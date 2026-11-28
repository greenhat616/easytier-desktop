//! WinUI theme transitions (LayoutTransition_partial.cpp) for elements
//! that appear, leave or move: Entrance, Content, Add/Delete and
//! Reposition. Which properties move, the offsets and the extra delays are
//! in the WinUI source; the durations, curves and stagger come from the
//! Windows animation tables at run time (ThemeGenerator.cpp:727-750), so
//! they are the values Windows 11 26300 returns, cited as "measured".
//! WinUI's Add/Delete also scales items between 0.9 and 1; GPUI cannot
//! scale an element, so that part is a gap.

use std::time::{Duration, Instant};

use gpui_kit::{
    AnyElement, App, Bounds, Entity, IntoElement, ParentElement as _, Pixels, Point, RenderOnce,
    SharedString, Styled as _, Window, base::animation::cubic_bezier, canvas, div, px,
};

/// The deceleration curve of the theme storyboards, (0.1,0.9,0.2,1).
fn decel(t: f32) -> f32 {
    cubic_bezier(0.1, 0.9, 0.2, 1.)(t)
}

/// How an element arrives when it first renders.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Arrival {
    /// EntranceThemeTransition: up from 28 px (DependencyProperty.cpp
    /// :691-699) and fading in, both over 667 ms on (0.1,0.9,0.2,1)
    /// (measured, TAS_ENTERPAGE). With staggering, item `order` waits
    /// (order + 1) × 35 ms (measured; StaggerFunctionBase_Partial.cpp:83-119).
    Entrance { order: usize, stagger: bool },
    /// ContentThemeTransition, incoming: up from 28 px over 500 ms on
    /// (0.1,0.9,0.2,1), fading in over 170 ms after 50 ms (measured,
    /// TAS_TRANSITIONCONTENT).
    Content,
    /// AddDeleteThemeTransition, added item: fades in linearly over 333 ms
    /// after 166 ms (measured, TAS_ADDTOGRID), plus the source's 300 ms
    /// wait for an add (LayoutTransition_partial.cpp:1563, 1603-1609).
    Added,
}

impl Arrival {
    /// Total time, and (opacity, y offset) `ms` after the first render.
    fn total(self) -> f32 {
        match self {
            Self::Entrance { order, stagger } => {
                667. + if stagger {
                    (order as f32 + 1.) * 35.
                } else {
                    0.
                }
            }
            Self::Content => 500.,
            Self::Added => 300. + 166. + 333.,
        }
    }

    fn at(self, ms: f32) -> (f32, f32) {
        match self {
            Self::Entrance { order, stagger } => {
                let wait = if stagger {
                    (order as f32 + 1.) * 35.
                } else {
                    0.
                };
                let p = decel(((ms - wait) / 667.).clamp(0., 1.));
                (p, 28. * (1. - p))
            }
            Self::Content => {
                let y = 28. * (1. - decel((ms / 500.).clamp(0., 1.)));
                (decel(((ms - 50.) / 170.).clamp(0., 1.)), y)
            }
            Self::Added => (((ms - 466.) / 333.).clamp(0., 1.), 0.),
        }
    }
}

/// `content` arriving with `arrival` the first time an element with `id`
/// renders. Under reduced motion it is simply there.
pub fn arrive(id: impl Into<SharedString>, arrival: Arrival, content: AnyElement) -> AnyElement {
    Arrive {
        id: id.into(),
        arrival,
        content,
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct Arrive {
    id: SharedString,
    arrival: Arrival,
    content: AnyElement,
}

struct Mounted(Instant);

impl RenderOnce for Arrive {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let now = cx.background_executor().now();
        let since = window
            .use_keyed_state(
                SharedString::from(format!("{}-arrive", self.id)),
                cx,
                move |_, _| Mounted(now),
            )
            .read(cx)
            .0;
        let ms = now.saturating_duration_since(since).as_secs_f32() * 1000.;
        let (opacity, y) = if cx.reduce_motion() || ms >= self.arrival.total() {
            (1., 0.)
        } else {
            window.request_animation_frame();
            self.arrival.at(ms)
        };
        div()
            .relative()
            .top(px(y))
            .opacity(opacity)
            .child(self.content)
    }
}

/// How far a leaving element has faded, `elapsed` after it started to
/// leave: AddDeleteThemeTransition's deleted item fades out linearly over
/// 100 ms (measured, TAS_DELETEFROMGRID), ContentThemeTransition's
/// outgoing content over 50 ms (measured). `None` once it has gone.
pub fn leaving_opacity(elapsed: Duration, over: Duration) -> Option<f32> {
    (elapsed < over).then(|| 1. - elapsed.as_secs_f32() / over.as_secs_f32())
}

/// AddDeleteThemeTransition's deleted-item fade (measured).
pub const DELETE_FADE: Duration = Duration::from_millis(100);
/// ContentThemeTransition's outgoing fade (measured).
pub const CONTENT_FADE: Duration = Duration::from_millis(50);

/// How an element moves to a new place after layout changes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Move {
    pub delay_ms: f32,
    pub duration_ms: f32,
}

impl Move {
    /// RepositionThemeTransition: 367 ms on (0.1,0.9,0.2,1), item `order`
    /// waiting order × 33 ms (measured, TAS_REPOSITION; staggering is
    /// forced on, LayoutTransition_partial.cpp:365-366).
    pub fn reposition(order: usize) -> Self {
        Self {
            delay_ms: order as f32 * 33.,
            duration_ms: 367.,
        }
    }

    /// AddDeleteThemeTransition: items making room for an added one move
    /// over 400 ms (measured, ADDTOGRID AFFECTED) at once; items closing a
    /// deleted one's gap move over 333 ms (DELETEFROMGRID REMAINING) after
    /// the source's 220 ms wait (LayoutTransition_partial.cpp:1892-1937).
    pub fn make_room() -> Self {
        Self {
            delay_ms: 0.,
            duration_ms: 400.,
        }
    }

    pub fn close_gap() -> Self {
        Self {
            delay_ms: 220.,
            duration_ms: 333.,
        }
    }
}

/// `content`, sliding from where it was drawn last to where layout now
/// puts it. GPUI only knows the new place after layout, so the slide
/// starts one frame after the move.
pub fn reposition(id: impl Into<SharedString>, motion: Move, content: AnyElement) -> AnyElement {
    Reposition {
        id: id.into(),
        motion,
        content,
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct Reposition {
    id: SharedString,
    motion: Move,
    content: AnyElement,
}

#[derive(Default)]
struct Placement {
    /// Where layout put the element last frame.
    laid_out: Option<Point<Pixels>>,
    /// The offset to slide away, and when the slide started.
    slide: Option<(Point<Pixels>, Instant)>,
}

impl Placement {
    fn offset(&self, now: Instant, motion: Move) -> Option<Point<Pixels>> {
        let (from, since) = self.slide?;
        let ms = now.saturating_duration_since(since).as_secs_f32() * 1000. - motion.delay_ms;
        if ms >= motion.duration_ms {
            return None;
        }
        let left = 1. - decel((ms / motion.duration_ms).clamp(0., 1.));
        Some(Point::new(from.x * left, from.y * left))
    }
}

impl RenderOnce for Reposition {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let state: Entity<Placement> = window.use_keyed_state(
            SharedString::from(format!("{}-reposition", self.id)),
            cx,
            |_, _| Placement::default(),
        );
        let now = cx.background_executor().now();
        let motion = self.motion;
        let offset = state.read(cx).offset(now, motion);
        if offset.is_some() {
            window.request_animation_frame();
        }
        let shown = offset.unwrap_or_default();
        let animate = !cx.reduce_motion();
        let probe = canvas(
            move |bounds: Bounds<Pixels>, window, cx| {
                let laid_out = bounds.origin - shown;
                state.update(cx, |s, _| {
                    // Pixel snapping moves the drawn origin by up to half a
                    // pixel; only a real layout change starts a slide.
                    let moved = s.laid_out.is_some_and(|before| {
                        (before.x - laid_out.x).abs() >= px(1.)
                            || (before.y - laid_out.y).abs() >= px(1.)
                    });
                    if let Some(before) = s.laid_out
                        && moved
                        && animate
                    {
                        // Start from where it was on screen.
                        s.slide = Some((before + shown - laid_out, now));
                        window.request_animation_frame();
                    }
                    if moved || s.laid_out.is_none() {
                        s.laid_out = Some(laid_out);
                    }
                });
            },
            |_, _, _, _| {},
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full();
        div()
            .relative()
            .left(shown.x)
            .top(shown.y)
            .child(self.content)
            .child(probe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrance_staggers_by_35_ms_and_lasts_667() {
        let first = Arrival::Entrance {
            order: 0,
            stagger: true,
        };
        assert_eq!(first.at(35.), (0., 28.));
        let (opacity, y) = first.at(35. + 667.);
        assert_eq!((opacity, y), (1., 0.));
        let third = Arrival::Entrance {
            order: 2,
            stagger: true,
        };
        assert_eq!(third.at(100.), (0., 28.));
    }

    #[test]
    fn content_fades_in_after_50_ms_and_added_items_after_466() {
        assert_eq!(Arrival::Content.at(50.).0, 0.);
        assert!(Arrival::Content.at(220.).0 >= 0.999);
        assert_eq!(Arrival::Added.at(466.).0, 0.);
        assert!((Arrival::Added.at(632.5).0 - 0.5).abs() < 0.01);
    }

    #[test]
    fn leaving_items_fade_linearly_then_go() {
        assert_eq!(
            leaving_opacity(Duration::from_millis(50), DELETE_FADE),
            Some(0.5)
        );
        assert_eq!(leaving_opacity(DELETE_FADE, DELETE_FADE), None);
    }
}
