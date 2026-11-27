//! WinUI ProgressBar, an empty state, and selectable cards for the Fluent
//! gallery's simple-mode pieces. Values come from the WinUI source and
//! theme resources, cited where used.

use std::{rc::Rc, time::Duration};

use gpui_kit::{
    Animation, AnimationExt as _, AnyElement, App, Hsla, InteractiveElement as _, IntoElement,
    KeyDownEvent, ParentElement as _, Role, SharedString, StatefulInteractiveElement as _,
    Styled as _, TestSupportExt as _, Window,
    base::animation::cubic_bezier,
    component::{ActiveTheme as _, Icon, Sizable as _, Size, StyledExt as _},
    div, px, relative,
};

use crate::theme::{self, ControlState};
use crate::views::pseudo::t;
use crate::views::ui::keyboard_focus;

/// What a [`progress_bar`]'s indicator is showing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressState {
    Running,
    /// `ProgressBarPausedForegroundColor` = `SystemFillColorCaution`.
    Paused,
    /// `ProgressBarErrorForegroundColor` = `SystemFillColorCritical`.
    Error,
}

pub(crate) fn indicator_color(state: ProgressState, cx: &App) -> Hsla {
    match state {
        ProgressState::Running => theme::accent_fill(ControlState::Rest, cx),
        ProgressState::Paused => theme::winui_brush(cx, 0x9D5D00FF, 0xFCE100FF),
        ProgressState::Error => theme::winui_brush(cx, 0xC42B1CFF, 0xFF99A4FF),
    }
}

/// WinUI ProgressBar (ProgressBar.xaml, ProgressBar_themeresources.xaml):
/// 3 px tall (ProgressBarMinHeight) with a 1 px track
/// (ProgressBarTrackHeight) in `ControlStrongStrokeColorDefault`, 0.5 px
/// track corners and a 1.5 px-cornered indicator in
/// `AccentFillColorDefault` (or the paused/error colours).
///
/// `value` in 0..=1 draws a determinate bar. `None` is indeterminate: a
/// 40 % indicator runs from -100 % to 300 % of its width over 1.5 s, and a
/// 60 % one from -150 % to 166 % between 0.75 s and 2 s, both on
/// KeySpline 0.4,0,0.6,1, repeating every 2 s (ProgressBar.cpp
/// UpdateWidthBasedTemplateSettings). Under reduced motion, and while
/// paused or in error, the 60 % indicator rests at the start
/// (ContainerAnimationMidPosition 0).
pub fn progress_bar(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    value: Option<f32>,
    state: ProgressState,
    cx: &App,
) -> AnyElement {
    let id: SharedString = id.into();
    let color = indicator_color(state, cx);
    let track = div()
        .absolute()
        .left_0()
        .right_0()
        .top(px(1.))
        .h(px(1.))
        .rounded(px(0.5))
        .bg(theme::control_strong_stroke(cx));
    let bar = div()
        .id(id.clone())
        .test_support()
        .role(Role::ProgressIndicator)
        .aria_label(t(label))
        .relative()
        .w_full()
        .h(px(3.))
        .overflow_hidden()
        .child(track);
    let indicator = move |width: f32| {
        div()
            .absolute()
            .top_0()
            .h(px(3.))
            .w(relative(width))
            .rounded(px(1.5))
            .bg(color)
    };
    match value {
        Some(value) => {
            let value = value.clamp(0., 1.);
            bar.child(indicator(value).left_0()).into_any_element()
        }
        None if cx.reduce_motion() || state != ProgressState::Running => {
            bar.child(indicator(0.6).left_0()).into_any_element()
        }
        None => {
            let ease = cubic_bezier(0.4, 0., 0.6, 1.);
            bar.child(div().absolute().inset_0().with_animation(
                SharedString::from(format!("{id}-indeterminate")),
                Animation::new(Duration::from_secs(2)).repeat(),
                move |el, t| {
                    // Seconds into the 2 s loop.
                    let s = t * 2.;
                    let first = ease((s / 1.5).min(1.));
                    let second = ease(((s - 0.75) / 1.25).clamp(0., 1.));
                    el.child(indicator(0.4).left(relative(-0.4 + first * (1.2 + 0.4))))
                        .child(indicator(0.6).left(relative(-0.9 + second * (0.996 + 0.9))))
                },
            ))
            .into_any_element()
        }
    }
}

/// An empty state, for a list or page with nothing to show yet. WinUI has
/// no control for it; Fluent's pattern is an icon, one sentence and one
/// action. The icon is 48 px in `TextFillColorSecondary`, the title
/// BodyStrong (14/20 SemiBold), the message Body (14/20) in
/// `TextFillColorSecondary` (TextBlock type ramp), stacked 8 px apart with
/// 16 px before the action, centred, and wrapping rather than truncating.
pub fn empty_state(
    id: impl Into<SharedString>,
    icon: &'static str,
    title: impl Into<SharedString>,
    message: impl Into<SharedString>,
    action: Option<AnyElement>,
    cx: &App,
) -> AnyElement {
    let secondary = theme::text_secondary(cx);
    div()
        .id(id.into())
        .test_support()
        .role(Role::Status)
        .w_full()
        .py(px(24.))
        .flex()
        .flex_col()
        .items_center()
        .gap(px(8.))
        .text_size(px(14.))
        .line_height(px(20.))
        .text_center()
        .child(
            Icon::default()
                .path(icon)
                .with_size(Size::Size(px(48.)))
                .text_color(secondary),
        )
        .child(
            div()
                .font_semibold()
                .text_color(cx.theme().foreground)
                .child(t(title)),
        )
        .child(
            div()
                .max_w(px(360.))
                .text_color(secondary)
                .child(t(message)),
        )
        .children(action.map(|a| div().mt(px(8.)).child(a)))
        .into_any_element()
}

/// One choice in [`selection_cards`].
pub struct CardChoice {
    pub icon: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

/// Single-choice cards, such as the first-run mode choice. The cards are
/// `CardBackgroundFillColorDefault` with a 1 px `CardStrokeColorDefault`
/// border and 4 px corners (ItemContainer.xaml ControlCornerRadius); hover
/// and press lay `SubtleFillColorSecondary` / `Tertiary` over them
/// (ItemContainerPointerOverBackground, PressedBackground). The chosen card
/// gets ItemContainer's selection visual: a 3 px `AccentFillColorDefault`
/// border with a 1 px `ControlSolidFillColorDefault` line inside it
/// (ItemContainerSelectedInnerThickness). The group is one Tab stop that
/// behaves like RadioButtons: arrows move the choice, Space or a click
/// picks a card.
pub fn selection_cards(
    id: &'static str,
    label: impl Into<SharedString>,
    choices: &[CardChoice],
    selected: usize,
    on_select: SelectHandler,
    cx: &App,
) -> AnyElement {
    let count = choices.len();
    let fg = cx.theme().foreground;
    let secondary = theme::text_secondary(cx);
    let accent = theme::accent_fill(ControlState::Rest, cx);
    let inner = theme::winui_brush(cx, 0xFFFFFFFF, 0x454545FF);
    let stroke = theme::card_stroke(cx);
    let fill = theme::card_fill(cx);
    let hover = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let mut row = div().flex().flex_row().flex_wrap().gap(px(12.));
    for (ix, choice) in choices.iter().enumerate() {
        let chosen = ix == selected;
        let pick = on_select.clone();
        let card = div()
            .id(SharedString::from(format!("{id}-{ix}")))
            .test_support()
            .role(Role::RadioButton)
            .aria_label(t(choice.title))
            .aria_selected(chosen)
            .relative()
            .w(px(240.))
            .rounded(px(4.))
            .border_1()
            .border_color(stroke)
            .bg(fill)
            .on_click(move |_, window, cx| pick(ix, window, cx))
            .child(
                div()
                    .id("card-body")
                    .size_full()
                    .p(px(16.))
                    .rounded(px(4.))
                    .hover(move |s| s.bg(hover))
                    .active(move |s| s.bg(pressed))
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .child(
                        Icon::default()
                            .path(choice.icon)
                            .with_size(Size::Size(px(24.)))
                            .text_color(fg),
                    )
                    .child(
                        div()
                            .text_size(px(14.))
                            .line_height(px(20.))
                            .font_semibold()
                            .text_color(fg)
                            .child(t(choice.title)),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .line_height(px(16.))
                            .text_color(secondary)
                            .child(t(choice.description)),
                    ),
            )
            .children(chosen.then(|| {
                div()
                    .absolute()
                    .inset(px(-1.))
                    .rounded(px(4.))
                    .border(px(3.))
                    .border_color(accent)
                    .child(
                        div()
                            .absolute()
                            .inset_0()
                            .rounded(px(1.))
                            .border_1()
                            .border_color(inner),
                    )
            }));
        row = row.child(card);
    }
    let keys = on_select.clone();
    let group = div()
        .id(id)
        .test_support()
        .role(Role::RadioGroup)
        .aria_label(t(label))
        .on_key_down(move |event: &KeyDownEvent, window, cx| {
            let next = match event.keystroke.key.as_str() {
                "right" | "down" => (selected + 1) % count,
                "left" | "up" => (selected + count - 1) % count,
                _ => return,
            };
            keys(next, window, cx);
            cx.stop_propagation();
        })
        .child(row);
    keyboard_focus(SharedString::from(format!("{id}-focus")), move |focus| {
        group.track_focus(focus).into_any_element()
    })
}
