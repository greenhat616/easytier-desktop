//! WinUI page transitions (NavigationThemeTransition) for a frame whose
//! page changes: Entrance, DrillIn, Slide from left or right, and Suppress.
//! Timings and curves are microsoft-ui-xaml's
//! `dxaml/phone/lib/ThemeTransitions.cpp` and `.h`, cited per kind.
//!
//! [`page_frame`] keeps the outgoing page drawn while it leaves and the
//! incoming one arrives, so the product's navigation can use it as is: give
//! it the current page key and a builder for any key.

use std::time::{Duration, Instant};

use gpui_kit::{
    AnyElement, App, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    RenderOnce, SharedString, Styled as _, Window, base::animation::cubic_bezier, div, px,
};

/// How the next page comes in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PageTransition {
    /// The default (ThemeTransitions.cpp:228-234, :3141-3247): the old page
    /// fades out over 150 ms on (0.7,0,1,0.5); the new one appears at
    /// 150 ms and rises 140 px over 300 ms on (0.1,0.9,0.2,1). Going back,
    /// the old page drops 140 px as it leaves and the new one fades in.
    #[default]
    Entrance,
    /// Drill in (:2830-3031, ThemeTransitions.h:326-333): the new page
    /// fades in over 333 ms and the old one out over 100 ms, both on
    /// (0.17,0.17,0,1). WinUI also scales them (0.94→1 and 1→1.04, back
    /// 1.06→1 and 1→0.96); GPUI cannot scale an element, so that is a gap.
    DrillIn,
    /// Slide (:1515-1667): the old page moves 150 px away and the new one
    /// comes in from 200 px on the other side, with Entrance's timing.
    SlideFromLeft,
    SlideFromRight,
    /// No animation (:3075-3082).
    Suppress,
}

const OUT: Duration = Duration::from_millis(150);
const IN: Duration = Duration::from_millis(300);
const DRILL_IN: Duration = Duration::from_millis(333);
const DRILL_OUT: Duration = Duration::from_millis(100);

impl PageTransition {
    /// How long the whole change lasts.
    pub fn duration(self) -> Duration {
        match self {
            Self::Entrance | Self::SlideFromLeft | Self::SlideFromRight => OUT + IN,
            Self::DrillIn => DRILL_IN,
            Self::Suppress => Duration::ZERO,
        }
    }

    /// The outgoing and incoming pages' (opacity, x, y) `ms` into the
    /// change.
    fn layers(self, back: bool, ms: f32) -> (Layer, Layer) {
        let decel = cubic_bezier(0.1, 0.9, 0.2, 1.);
        let accel = cubic_bezier(0.7, 0., 1., 0.5);
        let out = OUT.as_secs_f32() * 1000.;
        let inn = IN.as_secs_f32() * 1000.;
        // Progress of the leaving phase and of the arriving phase.
        let leave = (ms / out).clamp(0., 1.);
        let arrive = ((ms - out) / inn).clamp(0., 1.);
        let shown = if ms >= out { 1. } else { 0. };
        match self {
            Self::Entrance if !back => (
                Layer::faded(1. - accel(leave)),
                Layer {
                    opacity: shown,
                    x: 0.,
                    y: 140. * (1. - decel(arrive)),
                },
            ),
            Self::Entrance => (
                Layer {
                    opacity: 1. - shown,
                    x: 0.,
                    y: 140. * accel(leave),
                },
                Layer::faded(if ms < out { 0. } else { decel(arrive) }),
            ),
            Self::SlideFromLeft | Self::SlideFromRight => {
                let f = if self == Self::SlideFromLeft { 1. } else { -1. };
                let (away, from) = if back {
                    (-200. * f, 150. * f)
                } else {
                    (150. * f, -200. * f)
                };
                (
                    Layer {
                        opacity: 1. - shown,
                        x: away * accel(leave),
                        y: 0.,
                    },
                    Layer {
                        opacity: shown,
                        x: from * (1. - decel(arrive)),
                        y: 0.,
                    },
                )
            }
            Self::DrillIn => {
                let curve = cubic_bezier(0.17, 0.17, 0., 1.);
                let fade_out = (ms / (DRILL_OUT.as_secs_f32() * 1000.)).clamp(0., 1.);
                let fade_in = (ms / (DRILL_IN.as_secs_f32() * 1000.)).clamp(0., 1.);
                (
                    Layer::faded(1. - curve(fade_out)),
                    Layer::faded(curve(fade_in)),
                )
            }
            Self::Suppress => (Layer::faded(0.), Layer::faded(1.)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Layer {
    opacity: f32,
    x: f32,
    y: f32,
}

impl Layer {
    fn faded(opacity: f32) -> Self {
        Self {
            opacity,
            x: 0.,
            y: 0.,
        }
    }
}

type Build = Box<dyn Fn(usize, &mut Window, &mut App) -> AnyElement>;

/// A frame showing page `page`, built by `build`. When `page` changes, the
/// old page leaves and the new one arrives with `transition`; `back` says
/// the change is a backward navigation. Under reduced motion the new page
/// shows at once.
pub fn page_frame(
    id: impl Into<SharedString>,
    page: usize,
    transition: PageTransition,
    back: bool,
    build: impl Fn(usize, &mut Window, &mut App) -> AnyElement + 'static,
) -> AnyElement {
    PageFrame {
        id: id.into(),
        page,
        transition,
        back,
        build: Box::new(build),
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct PageFrame {
    id: SharedString,
    page: usize,
    transition: PageTransition,
    back: bool,
    build: Build,
}

/// The page on show, and the change in progress.
struct FrameState {
    current: usize,
    change: Option<Change>,
}

#[derive(Clone, Copy)]
struct Change {
    from: usize,
    transition: PageTransition,
    back: bool,
    since: Instant,
}

impl RenderOnce for PageFrame {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let page = self.page;
        let state = window.use_keyed_state(
            SharedString::from(format!("{}-page-frame", self.id)),
            cx,
            |_, _| FrameState {
                current: page,
                change: None,
            },
        );
        let now = cx.background_executor().now();
        let animate = !cx.reduce_motion() && self.transition != PageTransition::Suppress;
        state.update(cx, |s, _| {
            if s.current != page {
                s.change = animate.then_some(Change {
                    from: s.current,
                    transition: self.transition,
                    back: self.back,
                    since: now,
                });
                s.current = page;
            }
        });
        let change = state.read(cx).change.and_then(|c| {
            let elapsed = now.saturating_duration_since(c.since);
            (elapsed < c.transition.duration()).then_some((c, elapsed))
        });
        let frame = div()
            .id(ElementId::Name(self.id.clone()))
            .relative()
            .size_full()
            .overflow_hidden();
        let Some((change, elapsed)) = change else {
            return frame.child(layer(Layer::faded(1.), (self.build)(page, window, cx)));
        };
        window.request_animation_frame();
        let ms = elapsed.as_secs_f32() * 1000.;
        let (old, new) = change.transition.layers(change.back, ms);
        frame
            .child(layer(new, (self.build)(page, window, cx)))
            .child(
                div()
                    .absolute()
                    .inset_0()
                    .child(layer(old, (self.build)(change.from, window, cx))),
            )
    }
}

fn layer(at: Layer, content: AnyElement) -> gpui_kit::Div {
    div()
        .relative()
        .size_full()
        .left(px(at.x))
        .top(px(at.y))
        .opacity(at.opacity)
        .child(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrance_hands_over_at_150_ms_and_settles_at_450() {
        let t = PageTransition::Entrance;
        let (old, new) = t.layers(false, 0.);
        assert_eq!((old.opacity, new.opacity, new.y), (1., 0., 140.));
        let (old, new) = t.layers(false, 149.);
        assert!(old.opacity < 0.2 && new.opacity == 0.);
        let (_, new) = t.layers(false, 150.);
        assert_eq!((new.opacity, new.y), (1., 140.));
        let (_, new) = t.layers(false, 450.);
        assert_eq!(new.y, 0.);
        assert_eq!(t.duration(), Duration::from_millis(450));
    }

    #[test]
    fn slides_leave_150_px_and_arrive_from_200_on_the_other_side() {
        let (old, new) = PageTransition::SlideFromRight.layers(false, 150.);
        assert_eq!((old.x, new.x), (-150., 200.));
        let (old, new) = PageTransition::SlideFromLeft.layers(false, 150.);
        assert_eq!((old.x, new.x), (150., -200.));
        // Back reverses the directions.
        let (old, new) = PageTransition::SlideFromRight.layers(true, 150.);
        assert_eq!((old.x, new.x), (200., -150.));
    }

    #[test]
    fn drill_in_fades_without_moving() {
        let (old, new) = PageTransition::DrillIn.layers(false, 100.);
        assert_eq!((old.opacity, old.x, old.y), (0., 0., 0.));
        assert!(new.opacity > 0.5 && new.opacity < 1.);
        let (_, new) = PageTransition::DrillIn.layers(false, 333.);
        assert_eq!(new.opacity, 1.);
    }
}
