//! WinUI connected animation (ConnectedAnimation.cpp and its
//! configurations): an element seems to fly from its place on one page to
//! its place on the next. WinUI flies a snapshot of the source; GPUI cannot
//! snapshot, so this flies a copy drawn from both elements' builders,
//! crossfading from the source's look to the destination's while its
//! position and size move between the two places. A colour block or image
//! looks right; text reflows as the box changes size, and the Gravity
//! configuration's 1.1 scale becomes a size bump.
//!
//! Wrap the element on both pages in [`connected`] with the same key, call
//! [`prepare`] just before the page changes, and the element on the new
//! page plays the flight when it first lays out.

use std::{collections::HashMap, rc::Rc, time::Instant};

use gpui_kit::{
    AnchoredPositionMode, AnyElement, App, Bounds, Global, InteractiveElement as _, IntoElement,
    ParentElement as _, Pixels, RenderOnce, SharedString, Styled as _, TestSupportExt as _, Window,
    anchored, base::animation::cubic_bezier, canvas, deferred, div, point, px, size,
};

/// ConnectedAnimationConfiguration. `None` in WinUI means Gravity unless a
/// runtime feature turns it off (ConnectedAnimationConfiguration_partial.cpp
/// :77-86), so the gallery's "Default" is [`Self::Gravity`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectedConfig {
    /// 300 ms on (0.8,0,0.2,1) (ConnectedAnimationService.cpp:26-28) with a
    /// dip: 80 px down at 66 % of the way on (0.35,0,0.55,1), back up on
    /// (0.45,0,0.55,1), scaling 1.1 at the dip when source and destination
    /// are the same size, with a shadow
    /// (GravityConnectedAnimationConfiguration_partial.cpp:10-17, 60-102).
    #[default]
    Gravity,
    /// 200 ms on (0.1,0.9,0.2,1), no dip or shadow
    /// (DirectConnectedAnimationConfiguration_partial.cpp:13-15; Learn says
    /// 150 ms, the source 200).
    Direct,
    /// 300 ms on (0.8,0,0.2,1), no dip or shadow.
    Basic,
}

impl ConnectedConfig {
    fn duration_ms(self) -> f32 {
        match self {
            Self::Direct => 200.,
            Self::Gravity | Self::Basic => 300.,
        }
    }

    fn ease(self, t: f32) -> f32 {
        match self {
            Self::Direct => cubic_bezier(0.1, 0.9, 0.2, 1.)(t),
            Self::Gravity | Self::Basic => cubic_bezier(0.8, 0., 0.2, 1.)(t),
        }
    }
}

/// A prepared animation is dropped if no destination picks it up within
/// 2 s (ConnectedAnimation.cpp:47 `s_timeout`; Learn says 3 s).
const TIMEOUT_MS: f32 = 2000.;

type Visual = Rc<dyn Fn(&mut Window, &mut App) -> AnyElement>;

#[derive(Default)]
struct Store {
    /// Where each keyed element was last drawn, and how to draw it.
    last: HashMap<SharedString, (Bounds<Pixels>, Visual)>,
    /// Flights waiting for their destination to lay out.
    pending: HashMap<SharedString, Pending>,
    /// Flights under way.
    active: HashMap<SharedString, Flight>,
}

impl Global for Store {}

struct Pending {
    from: Bounds<Pixels>,
    visual: Visual,
    config: ConnectedConfig,
    since: Instant,
}

#[derive(Clone)]
struct Flight {
    from: Bounds<Pixels>,
    to: Bounds<Pixels>,
    visual: Visual,
    config: ConnectedConfig,
    since: Instant,
}

/// Captures where the element with `key` is now, to fly from there to the
/// element with the same key on the next page. Does nothing under reduced
/// motion, or if the element has not been drawn.
pub fn prepare(key: impl Into<SharedString>, config: ConnectedConfig, cx: &mut App) {
    if cx.reduce_motion() {
        return;
    }
    let key = key.into();
    let now = cx.background_executor().now();
    let store = cx.default_global::<Store>();
    if let Some((from, visual)) = store.last.get(&key).cloned() {
        store.active.remove(&key);
        store.pending.insert(
            key,
            Pending {
                from,
                visual,
                config,
                since: now,
            },
        );
    }
}

/// An element taking part in connected animations under `key`, drawn by
/// `visual`, filling the box its caller gives it. When a flight to it is prepared, it stays hidden while a copy
/// flies in, then shows.
pub fn connected(
    key: impl Into<SharedString>,
    visual: impl Fn(&mut Window, &mut App) -> AnyElement + 'static,
) -> AnyElement {
    Connected {
        key: key.into(),
        visual: Rc::new(visual),
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct Connected {
    key: SharedString,
    visual: Visual,
}

impl RenderOnce for Connected {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let now = cx.background_executor().now();
        let key = self.key.clone();
        let store = cx.default_global::<Store>();
        let elapsed = |since: Instant| now.saturating_duration_since(since).as_secs_f32() * 1000.;
        store.pending.retain(|_, p| elapsed(p.since) < TIMEOUT_MS);
        let waiting = store.pending.contains_key(&key);
        let flight = store.active.get(&key).cloned();
        let flight = match flight {
            Some(f) if elapsed(f.since) < f.config.duration_ms() => Some(f),
            Some(_) => {
                store.active.remove(&key);
                None
            }
            None => None,
        };
        let hidden = waiting || flight.is_some();
        if hidden {
            window.request_animation_frame();
        }
        let visual = self.visual.clone();
        let probe = canvas(
            move |bounds: Bounds<Pixels>, window, cx| {
                let store = cx.default_global::<Store>();
                store.last.insert(key.clone(), (bounds, visual));
                if let Some(p) = store.pending.remove(&key) {
                    store.active.insert(
                        key,
                        Flight {
                            from: p.from,
                            to: bounds,
                            visual: p.visual,
                            config: p.config,
                            since: now,
                        },
                    );
                    window.request_animation_frame();
                }
            },
            |_, _, _, _| {},
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full();
        let own = (self.visual)(window, cx);
        let overlay = flight.map(|f| {
            let t = (elapsed(f.since) / f.config.duration_ms()).clamp(0., 1.);
            fly(&f, t, self.visual.clone(), window, cx)
        });
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .size_full()
                    .opacity(if hidden { 0. } else { 1. })
                    .child(own),
            )
            .child(probe)
            .children(overlay)
    }
}

/// The flying copy `t` of the way through, in window coordinates.
fn fly(f: &Flight, t: f32, destination: Visual, window: &mut Window, cx: &mut App) -> AnyElement {
    let e = f.config.ease(t);
    let lerp = |a: Pixels, b: Pixels| a + (b - a) * e;
    let mut origin = point(
        lerp(f.from.origin.x, f.to.origin.x),
        lerp(f.from.origin.y, f.to.origin.y),
    );
    let mut extent = size(
        lerp(f.from.size.width, f.to.size.width),
        lerp(f.from.size.height, f.to.size.height),
    );
    if f.config == ConnectedConfig::Gravity {
        // The dip: 0 → 1 → 0 with its two curves, peaking at 66 %.
        let dip = if t < 0.66 {
            cubic_bezier(0.35, 0., 0.55, 1.)(t / 0.66)
        } else {
            1. - cubic_bezier(0.45, 0., 0.55, 1.)((t - 0.66) / 0.34)
        };
        origin.y += px(80. * dip);
        if f.from.size == f.to.size {
            let grow = 1. + 0.1 * dip;
            let grown = size(extent.width * grow, extent.height * grow);
            origin.x -= (grown.width - extent.width) / 2.;
            origin.y -= (grown.height - extent.height) / 2.;
            extent = grown;
        }
    }
    let source = (f.visual)(window, cx);
    let target = destination(window, cx);
    let mut copy = div()
        .id("connected-flight")
        .test_support()
        .w(extent.width)
        .h(extent.height)
        .relative()
        .overflow_hidden()
        .child(div().absolute().inset_0().opacity(1. - e).child(source))
        .child(div().absolute().inset_0().opacity(e).child(target));
    if f.config == ConnectedConfig::Gravity {
        copy = copy.shadow_lg();
    }
    deferred(
        anchored()
            .position_mode(AnchoredPositionMode::Window)
            .position(origin)
            .child(copy),
    )
    .with_priority(2)
    .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configurations_use_the_source_timing() {
        assert_eq!(ConnectedConfig::default(), ConnectedConfig::Gravity);
        assert_eq!(ConnectedConfig::Gravity.duration_ms(), 300.);
        assert_eq!(ConnectedConfig::Direct.duration_ms(), 200.);
        assert_eq!(ConnectedConfig::Basic.ease(1.), 1.);
        // Direct decelerates: most of the way by a third of the time.
        assert!(ConnectedConfig::Direct.ease(0.33) > 0.8);
    }
}
