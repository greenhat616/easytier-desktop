//! WinUI motion for the Fluent gallery controls: popup entrance and exit,
//! Expander open and close. Timings and curves come from the WinUI source
//! and are cited where used. Every animation goes through gpui-base's
//! [`Presence`], so it finishes at once when the system asks for reduced
//! motion (WinUI likewise skips them when animations are off,
//! `SharedHelpers::IsAnimationsEnabled`).

use std::time::Duration;

use gpui_kit::{
    AnyElement, App, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    RenderOnce, SharedString, Styled as _, Window,
    base::{Presence, PresencePhase, PresenceSample, Transition, animation::cubic_bezier},
    div, px, relative,
};

/// `ControlFasterAnimationDuration` (83 ms).
pub const FASTER: Duration = Duration::from_millis(83);
/// `ControlFastAnimationDuration` (167 ms).
pub const FAST: Duration = Duration::from_millis(167);
/// `ControlNormalAnimationDuration` (250 ms).
pub const NORMAL: Duration = Duration::from_millis(250);

/// `ControlFastOutSlowInKeySpline` (0,0,0,1).
pub fn fast_out_slow_in(t: f32) -> f32 {
    cubic_bezier(0., 0., 0., 1.)(t)
}

/// How a popup enters and leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopupKind {
    /// MenuFlyout (MenuPopupThemeTransition, LayoutTransition_partial.cpp;
    /// s_OpenDuration 250, s_OpacityChangeDuration 83 in
    /// MenuPopupThemeTransition_Partial.h): the menu slides down out of its
    /// own top edge from half its height (MenuFlyout_Partial.cpp
    /// closedRatioConstant 0.5) over 250 ms on cubic-bezier 0,0,0,1, clipped
    /// to its final bounds; it fades out over 83 ms.
    Menu,
    /// Flyout (FlyoutBase PopupThemeTransition): it comes in from 50 px above
    /// (FlyoutBase::g_entranceThemeOffset) and fades out. The timing is
    /// [`POPUP_IN`]'s.
    Flyout,
    /// A Popup with PopupThemeTransition at its default 40 px offset
    /// (DependencyProperty.cpp:687-689): it rises from 40 px below, with
    /// [`POPUP_IN`]'s timing.
    Popup,
    /// ContentDialog (ContentDialog_themeresources.xaml DialogShowing /
    /// DialogHidden): LayoutRoot, smoke included, fades in over 83 ms
    /// (ControlFasterAnimationDuration) and out over 83 ms. WinUI also
    /// scales the dialog 1.05→1 over 250 ms; GPUI cannot scale an element.
    Dialog,
}

/// PopupThemeTransition's timing. WinUI reads it from the Windows
/// animation tables at run time (ThemeGenerator.cpp:727-750, storyboards
/// TAS_SHOWPOPUP and TAS_HIDEPOPUP), so it is not in the source; these are
/// the values Windows 11 26300 returns. Showing, the popup moves into place
/// over 367 ms on (0.1,0.9,0.2,1) and fades in linearly over 83 ms after an
/// 83 ms wait; hiding, it fades out linearly over 83 ms.
pub const POPUP_IN: Duration = Duration::from_millis(367);

impl PopupKind {
    fn duration(self, open: bool) -> Duration {
        match (self, open) {
            (Self::Menu, true) => NORMAL,
            (Self::Flyout | Self::Popup, true) => POPUP_IN,
            (Self::Dialog, true) => FASTER,
            (_, false) => FASTER,
        }
    }
}

/// A popup's presence: whether it is open, and how it moves in and out.
#[derive(Clone)]
pub struct PopupMotion {
    id: SharedString,
    open: bool,
    kind: PopupKind,
}

impl PopupMotion {
    pub fn new(id: impl Into<SharedString>, open: bool, kind: PopupKind) -> Self {
        Self {
            id: id.into(),
            open,
            kind,
        }
    }

    pub fn open(&self) -> bool {
        self.open
    }

    /// Progress is linear time: 0→1 over the entrance, 1→0 over the exit.
    fn sample(&self, window: &mut Window, cx: &mut App) -> PresenceSample {
        Presence::new(
            SharedString::from(format!("{}-presence", self.id)),
            self.open,
        )
        .transition(Transition::new(self.kind.duration(self.open)).ease(|t| t))
        .sample(window, cx)
    }

    /// Renders `element` while the popup is open or leaving.
    pub fn gate(&self, element: AnyElement) -> AnyElement {
        Gate {
            motion: self.clone(),
            element,
            interactive_only: false,
        }
        .into_any_element()
    }

    /// Renders `element` only while the popup is open and not leaving: the
    /// light-dismiss layer, which must let presses through as it goes.
    pub fn interactive(&self, element: AnyElement) -> AnyElement {
        Gate {
            motion: self.clone(),
            element,
            interactive_only: true,
        }
        .into_any_element()
    }

    /// Moves the popup's surface as it enters and leaves.
    pub fn animate(&self, id: impl Into<ElementId>, surface: AnyElement) -> AnyElement {
        Animated {
            id: id.into(),
            motion: self.clone(),
            surface,
        }
        .into_any_element()
    }
}

#[derive(IntoElement)]
struct Gate {
    motion: PopupMotion,
    element: AnyElement,
    interactive_only: bool,
}

impl RenderOnce for Gate {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let sample = self.motion.sample(window, cx);
        let show = if self.interactive_only {
            self.motion.open && sample.should_render()
        } else {
            sample.should_render()
        };
        div().children(show.then_some(self.element))
    }
}

#[derive(IntoElement)]
struct Animated {
    id: ElementId,
    motion: PopupMotion,
    surface: AnyElement,
}

impl RenderOnce for Animated {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let sample = self.motion.sample(window, cx);
        let kind = self.motion.kind;
        let entrance = self.motion.kind.duration(true).as_secs_f32();
        match sample.phase {
            PresencePhase::Present | PresencePhase::Absent => div().id(self.id).child(self.surface),
            PresencePhase::Exiting => div()
                .id(self.id)
                .opacity(sample.progress)
                .child(self.surface),
            PresencePhase::Entering => {
                let t = sample.progress;
                let eased = fast_out_slow_in(t);
                match kind {
                    PopupKind::Menu => div().id(self.id).relative().overflow_hidden().child(
                        div()
                            .relative()
                            .top(relative(-0.5 * (1. - eased)))
                            .child(self.surface),
                    ),
                    PopupKind::Flyout | PopupKind::Popup => {
                        // A flyout drops in from 50 px above its anchor
                        // (FlyoutBase); a plain popup rises from its
                        // positive FromVerticalOffset, 40 px below.
                        let offset = if kind == PopupKind::Flyout { -50. } else { 40. };
                        let ms = t * entrance * 1000.;
                        let decel = cubic_bezier(0.1, 0.9, 0.2, 1.)(t);
                        let fade = ((ms - 83.) / 83.).clamp(0., 1.);
                        div()
                            .id(self.id)
                            .relative()
                            .top(px(offset * (1. - decel)))
                            .opacity(fade)
                            .child(self.surface)
                    }
                    // The dialog's whole entrance is the 83 ms fade.
                    PopupKind::Dialog => div().id(self.id).opacity(t).child(self.surface),
                }
            }
        }
    }
}

/// WinUI Expander content motion (Expander.xaml ExpandDown/CollapseUp):
/// opening, the content slides down from its full height above into its
/// place over 333 ms on KeySpline 0,0,0,1; closing, it slides back up over
/// 167 ms on KeySpline 1,1,0,1 and then collapses. It is clipped to its
/// final bounds throughout.
pub fn expander_content(
    id: impl Into<SharedString>,
    open: bool,
    content: AnyElement,
) -> AnyElement {
    ExpanderContent {
        id: id.into(),
        open,
        content,
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct ExpanderContent {
    id: SharedString,
    open: bool,
    content: AnyElement,
}

/// The last open state an Expander's content saw, and when it changed.
/// It starts settled, so content that is open when it first appears does
/// not slide in.
struct ExpanderState {
    open: bool,
    since: Option<std::time::Instant>,
}

impl RenderOnce for ExpanderContent {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let now = cx.background_executor().now();
        let open = self.open;
        let state = window.use_keyed_state(
            SharedString::from(format!("{}-state", self.id)),
            cx,
            |_, _| ExpanderState { open, since: None },
        );
        if state.read(cx).open != open {
            state.update(cx, |state, _| {
                state.open = open;
                state.since = Some(now);
            });
        }
        let duration = Duration::from_millis(if open { 333 } else { 167 });
        let progress = match state.read(cx).since {
            Some(since) if !cx.reduce_motion() => {
                (now.saturating_duration_since(since).as_secs_f32() / duration.as_secs_f32())
                    .min(1.)
            }
            _ => 1.,
        };
        if progress < 1. {
            window.request_animation_frame();
        }
        let offset = match (open, progress < 1.) {
            (false, false) => return div(),
            (true, false) => 0.,
            (true, true) => 1. - cubic_bezier(0., 0., 0., 1.)(progress),
            (false, true) => cubic_bezier(1., 1., 0., 1.)(progress),
        };
        if offset == 0. {
            return div().w_full().child(self.content);
        }
        div().w_full().relative().overflow_hidden().child(
            div()
                .w_full()
                .relative()
                .top(relative(-offset))
                .child(self.content),
        )
    }
}
