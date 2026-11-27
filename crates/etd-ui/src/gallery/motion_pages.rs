//! Gallery pages for WinUI Gallery's Motion group: easing functions and
//! page transitions so far. Each page follows its WinUI Gallery sample.

use std::time::Duration;

use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    Styled as _, TestSupportExt as _, Window,
    base::{Transition, transition},
    component::{ActiveTheme as _, Size, button::ButtonVariant},
    div, px,
};

use super::{Gallery, section};
use crate::views::{
    controls::fluent_radio_group,
    easing::{Easing, EasingMode},
    page_transition::{PageTransition, page_frame},
    pseudo::t,
    ui::{BtnStyle, action_button},
};

/// Motion pages' demo state.
pub(super) struct MotionDemo {
    /// Whether each easing example sits at its far end (200 px).
    pub(super) easing_far: [bool; 4],
    pub(super) easing_choice: usize,
    pub(super) easing_mode: usize,
    pub(super) page_kind: usize,
    pub(super) page: usize,
    pub(super) page_back: bool,
}

impl MotionDemo {
    pub(super) fn new() -> Self {
        Self {
            easing_far: [false; 4],
            easing_choice: 2,
            easing_mode: 0,
            page_kind: 0,
            page: 0,
            page_back: false,
        }
    }
}

/// The square's travel in the easing examples (EasingFunctionPage.xaml.cs).
const TRAVEL: f32 = 200.;

/// A 50×50 accent square that moves 0↔200 px with `easing`.
fn easing_example(
    view: &Gallery,
    ix: usize,
    easing: Easing,
    mode: EasingMode,
    duration: Duration,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> AnyElement {
    let far = view.motion.easing_far[ix];
    let x = transition(
        SharedString::from(format!("easing-square-{ix}")),
        if far { TRAVEL } else { 0. },
        Transition::new(duration).ease(move |t| easing.ease(mode, t)),
        window,
        cx,
    );
    let accent = crate::theme::accent_fill(crate::theme::ControlState::Rest, cx);
    let track = div().relative().w(px(TRAVEL + 50.)).h(px(50.)).child(
        div()
            .id(SharedString::from(format!("easing-square-{ix}")))
            .test_support()
            .absolute()
            .top_0()
            .left(px(x))
            .size(px(50.))
            .rounded(px(4.))
            .bg(accent),
    );
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(24.))
        .child(action_button(
            SharedString::from(format!("easing-animate-{ix}")),
            "Animate",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(move |this, _: &gpui_kit::ClickEvent, _, cx| {
                this.motion.easing_far[ix] = !this.motion.easing_far[ix];
                cx.notify();
            }),
        ))
        .child(track)
        .into_any_element()
}

/// The eased curve over 0..=1, drawn as dots in a 160×160 box, with room
/// above and below for overshoot.
fn easing_plot(easing: Easing, mode: EasingMode, cx: &Context<Gallery>) -> AnyElement {
    const SIZE: f32 = 160.;
    const PAD: f32 = 40.;
    let fg = crate::theme::accent_fill(crate::theme::ControlState::Rest, cx);
    let axis = crate::theme::control_strong_stroke(cx);
    let mut plot = div()
        .id("easing-plot")
        .test_support()
        .relative()
        .w(px(SIZE))
        .h(px(SIZE + 2. * PAD))
        .child(
            div()
                .absolute()
                .left_0()
                .top(px(PAD))
                .w(px(SIZE))
                .h(px(SIZE))
                .border_l_1()
                .border_b_1()
                .border_color(axis),
        );
    for i in 0..=80 {
        let t = i as f32 / 80.;
        let v = easing.ease(mode, t);
        plot = plot.child(
            div()
                .absolute()
                .left(px(t * SIZE - 1.5))
                .top(px(PAD + (1. - v) * SIZE - 1.5))
                .size(px(3.))
                .rounded_full()
                .bg(fg),
        );
    }
    plot.into_any_element()
}

pub(super) fn easing_page(
    view: &Gallery,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> Vec<AnyElement> {
    let caption = |text: &'static str, cx: &Context<Gallery>| {
        div()
            .text_size(px(12.))
            .line_height(px(16.))
            .text_color(crate::theme::text_secondary(cx))
            .child(t(text))
            .into_any_element()
    };
    let standard = easing_example(
        view,
        0,
        Easing::Circle,
        EasingMode::InOut,
        Duration::from_millis(500),
        window,
        cx,
    );
    let accelerate = easing_example(
        view,
        1,
        Easing::Exponential { exponent: 4.5 },
        EasingMode::In,
        Duration::from_millis(150),
        window,
        cx,
    );
    let decelerate = easing_example(
        view,
        2,
        Easing::Exponential { exponent: 7. },
        EasingMode::Out,
        Duration::from_millis(300),
        window,
        cx,
    );
    let (_, chosen) = Easing::ALL[view.motion.easing_choice];
    let mode = [EasingMode::Out, EasingMode::In, EasingMode::InOut][view.motion.easing_mode];
    let any = easing_example(
        view,
        3,
        chosen,
        mode,
        Duration::from_millis(500),
        window,
        cx,
    );
    const NAMES: [&str; 11] = [
        "BackEase",
        "BounceEase",
        "CircleEase",
        "CubicEase",
        "ElasticEase",
        "ExponentialEase",
        "PowerEase",
        "QuadraticEase",
        "QuarticEase",
        "QuinticEase",
        "SineEase",
    ];
    let picker = div()
        .flex()
        .flex_row()
        .gap(px(32.))
        .items_start()
        .child(fluent_radio_group(
            "easing-function",
            "Easing function",
            &NAMES,
            view.motion.easing_choice,
            false,
            cx.listener(|this, ix: &usize, _, cx| {
                this.motion.easing_choice = *ix;
                cx.notify();
            }),
            cx,
        ))
        .child(fluent_radio_group(
            "easing-mode",
            "Easing mode",
            &["EaseOut", "EaseIn", "EaseInOut"],
            view.motion.easing_mode,
            false,
            cx.listener(|this, ix: &usize, _, cx| {
                this.motion.easing_mode = *ix;
                cx.notify();
            }),
            cx,
        ))
        .child(easing_plot(chosen, mode, cx))
        .into_any_element();
    vec![
        section(
            "Standard: CircleEase, EaseInOut, 500 ms",
            [caption("Moves between two points on screen.", cx), standard],
            cx,
        ),
        section(
            "Accelerate: ExponentialEase, EaseIn, exponent 4.5, 150 ms",
            [caption("Leaves the screen.", cx), accelerate],
            cx,
        ),
        section(
            "Decelerate: ExponentialEase, EaseOut, exponent 7, 300 ms",
            [caption("Comes on screen.", cx), decelerate],
            cx,
        ),
        section("Easing functions, 500 ms", [picker, any], cx),
    ]
}

/// The kinds in the Gallery sample's order.
const PAGE_KINDS: [(&str, PageTransition); 5] = [
    ("Entrance", PageTransition::Entrance),
    ("Drill in", PageTransition::DrillIn),
    ("Suppress", PageTransition::Suppress),
    ("Slide from right", PageTransition::SlideFromRight),
    ("Slide from left", PageTransition::SlideFromLeft),
];

/// One of the two sample pages the frame alternates between.
fn sample_page(page: usize, cx: &gpui_kit::App) -> AnyElement {
    let (title, fill) = if page.is_multiple_of(2) {
        (
            "Sample page 1",
            crate::theme::accent_fill(crate::theme::ControlState::Rest, cx),
        )
    } else {
        ("Sample page 2", gpui_kit::rgb(0x8764B8).into())
    };
    div()
        .id(SharedString::from(format!("sample-page-{}", page % 2)))
        .test_support()
        .size_full()
        .p(px(24.))
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(
            div()
                .text_size(px(28.))
                .line_height(px(36.))
                .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                .text_color(cx.theme().foreground)
                .child(t(title)),
        )
        .child(div().w(px(240.)).h(px(140.)).rounded(px(8.)).bg(fill))
        .into_any_element()
}

pub(super) fn page_transitions_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    let names: Vec<&'static str> = PAGE_KINDS.iter().map(|(n, _)| *n).collect();
    let kind = PAGE_KINDS[view.motion.page_kind].1;
    let controls = div()
        .flex()
        .flex_row()
        .items_start()
        .gap(px(32.))
        .child(fluent_radio_group(
            "page-transition-kind",
            "Transition",
            &names,
            view.motion.page_kind,
            false,
            cx.listener(|this, ix: &usize, _, cx| {
                this.motion.page_kind = *ix;
                cx.notify();
            }),
            cx,
        ))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child(action_button(
                    "page-forward",
                    "Navigate forward",
                    BtnStyle::new(ButtonVariant::Primary, Size::Medium),
                    cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                        this.motion.page += 1;
                        this.motion.page_back = false;
                        cx.notify();
                    }),
                ))
                .child(action_button(
                    "page-back",
                    "Navigate backward",
                    BtnStyle::new(ButtonVariant::Default, Size::Medium),
                    cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                        if this.motion.page > 0 {
                            this.motion.page -= 1;
                            this.motion.page_back = true;
                            cx.notify();
                        }
                    }),
                )),
        )
        .into_any_element();
    let frame = div()
        .id("page-frame-box")
        .test_support()
        .w_full()
        .h(px(260.))
        .rounded(px(8.))
        .border_1()
        .border_color(crate::theme::card_stroke(cx))
        .bg(crate::theme::card_fill(cx))
        .child(page_frame(
            "page-frame",
            view.motion.page,
            kind,
            view.motion.page_back,
            |page, _, cx| sample_page(page, cx),
        ))
        .into_any_element();
    vec![section("Page transitions", [controls, frame], cx)]
}
