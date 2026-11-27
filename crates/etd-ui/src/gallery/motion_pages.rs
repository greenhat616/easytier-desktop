//! Gallery pages for WinUI Gallery's Motion group: page, theme and
//! implicit transitions, ParallaxView and easing functions. Each page follows its WinUI Gallery sample.

use std::time::Duration;

use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    base::{Transition, transition},
    component::{ActiveTheme as _, Sizable as _, Size, button::ButtonVariant},
    div, px,
};

use super::{Gallery, section};
use crate::views::{
    controls::fluent_radio_group,
    easing::{Easing, EasingMode},
    motion::{PopupKind, PopupMotion},
    page_transition::{PageTransition, page_frame},
    pseudo::t,
    theme_transition::{
        Arrival, CONTENT_FADE, DELETE_FADE, Move, arrive, leaving_opacity, reposition,
    },
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
    /// Entrance demo: (id, order within the batch it arrived in).
    pub(super) entrance_items: Vec<(u32, usize)>,
    pub(super) next_id: u32,
    pub(super) green_hidden: bool,
    /// Content demo: the data generation, and the previous one while it
    /// fades out.
    pub(super) content_gen: u32,
    pub(super) content_old: Option<(u32, std::time::Instant)>,
    /// Add/Delete demo: live items, items fading out (id, index, since),
    /// and whether the last change was an add.
    pub(super) list: Vec<u32>,
    pub(super) deleted: Vec<(u32, usize, std::time::Instant)>,
    pub(super) last_added: bool,
    pub(super) popup_open: bool,
    /// Implicit transitions: opacity, translation, brush, rotation, scale.
    pub(super) implicit: [bool; 5],
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
            entrance_items: Vec::new(),
            next_id: 100,
            green_hidden: false,
            content_gen: 0,
            content_old: None,
            list: (0..10).collect(),
            deleted: Vec::new(),
            last_added: true,
            popup_open: false,
            implicit: [false; 5],
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

fn button(
    id: &'static str,
    label: &'static str,
    cx: &mut Context<Gallery>,
    f: impl Fn(&mut Gallery, &mut Context<Gallery>) + 'static,
) -> AnyElement {
    // In a row of its own, so a lone button keeps its natural width.
    row()
        .child(action_button(
            id,
            label,
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(move |this, _: &gpui_kit::ClickEvent, _, cx| {
                f(this, cx);
                cx.notify();
            }),
        ))
        .into_any_element()
}

fn row() -> gpui_kit::Div {
    div()
        .flex()
        .flex_row()
        .flex_wrap()
        .items_center()
        .gap(px(8.))
}

fn square(id: SharedString, size: f32, fill: gpui_kit::Hsla) -> AnyElement {
    div()
        .id(id)
        .test_support()
        .size(px(size))
        .bg(fill)
        .into_any_element()
}

pub(super) fn theme_transitions_page(
    view: &Gallery,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> Vec<AnyElement> {
    let m = &view.motion;
    let now = cx.background_executor().now();
    let blue: gpui_kit::Hsla = gpui_kit::rgb(0xADD8E6).into();
    // EntranceThemeTransition: 50x50 light-blue squares, staggered.
    let mut entrance = row().min_h(px(60.));
    for (id, order) in &m.entrance_items {
        entrance = entrance.child(arrive(
            SharedString::from(format!("entrance-{id}")),
            Arrival::Entrance {
                order: *order,
                stagger: true,
            },
            square(SharedString::from(format!("entrance-item-{id}")), 50., blue),
        ));
    }
    let entrance_buttons = row()
        .child(button("entrance-add-one", "Add one", cx, |this, _| {
            let id = this.motion.next_id;
            this.motion.next_id += 1;
            this.motion.entrance_items.push((id, 0));
        }))
        .child(button("entrance-add-five", "Add five", cx, |this, _| {
            for order in 0..5 {
                let id = this.motion.next_id;
                this.motion.next_id += 1;
                this.motion.entrance_items.push((id, order));
            }
        }))
        .child(button("entrance-clear", "Clear all", cx, |this, _| {
            this.motion.entrance_items.clear();
        }));

    // RepositionThemeTransition: only the blue square has it.
    let reposition_row = div()
        .flex()
        .flex_row()
        .gap(px(10.))
        .child(square(
            "reposition-red".into(),
            75.,
            gpui_kit::rgb(0xE81123).into(),
        ))
        .children((!m.green_hidden).then(|| {
            square(
                "reposition-green".into(),
                75.,
                gpui_kit::rgb(0x107C10).into(),
            )
        }))
        .child(reposition(
            "reposition-blue-move",
            Move::reposition(0),
            square(
                "reposition-blue".into(),
                75.,
                gpui_kit::rgb(0x0078D4).into(),
            ),
        ));
    let reposition_button = button("reposition-toggle", "Reposition", cx, |this, _| {
        this.motion.green_hidden = !this.motion.green_hidden;
    });

    // ContentThemeTransition on a five-line list whose data is refreshed.
    let content_list = |generation: u32, incoming: bool| {
        let mut list = div().flex().flex_col();
        for i in 0..5 {
            let text = div()
                .id(SharedString::from(format!("content-item-{generation}-{i}")))
                .test_support()
                .h(px(32.))
                .flex()
                .items_center()
                .text_size(px(14.))
                .child(format!("Item {} (data set {})", i + 1, generation + 1))
                .into_any_element();
            list = list.child(if incoming {
                arrive(
                    SharedString::from(format!("content-{generation}-{i}")),
                    Arrival::Content,
                    text,
                )
            } else {
                text
            });
        }
        list
    };
    let mut content = div()
        .id("content-list")
        .test_support()
        .relative()
        .child(content_list(m.content_gen, true));
    if let Some((old, since)) = m.content_old
        && let Some(opacity) = leaving_opacity(now.saturating_duration_since(since), CONTENT_FADE)
    {
        window.request_animation_frame();
        content = content.child(
            content_list(old, false)
                .absolute()
                .top_0()
                .left_0()
                .opacity(opacity),
        );
    }
    let content_button = button("content-refresh", "Refresh data", cx, |this, cx| {
        let now = cx.background_executor().now();
        this.motion.content_old = Some((this.motion.content_gen, now));
        this.motion.content_gen += 1;
    });

    // AddDeleteThemeTransition on a list of items.
    let mut shown: Vec<(u32, Option<f32>)> = m.list.iter().map(|id| (*id, None)).collect();
    for (id, index, since) in &m.deleted {
        if let Some(opacity) = leaving_opacity(now.saturating_duration_since(*since), DELETE_FADE) {
            window.request_animation_frame();
            shown.insert((*index).min(shown.len()), (*id, Some(opacity)));
        }
    }
    let moving = if m.last_added {
        Move::make_room()
    } else {
        Move::close_gap()
    };
    let mut list = div().id("add-delete-list").test_support().flex().flex_col();
    for (id, leaving) in shown {
        let text = div()
            .id(SharedString::from(format!("add-delete-item-{id}")))
            .test_support()
            .h(px(32.))
            .flex()
            .items_center()
            .text_size(px(14.))
            .opacity(leaving.unwrap_or(1.))
            .child(format!("Item {id}"))
            .into_any_element();
        let item = if leaving.is_some() {
            text
        } else {
            arrive(
                SharedString::from(format!("add-delete-{id}")),
                Arrival::Added,
                text,
            )
        };
        list = list.child(reposition(
            SharedString::from(format!("add-delete-move-{id}")),
            moving,
            item,
        ));
    }
    let add_delete_buttons = row()
        .child(button("add-delete-add", "Add", cx, |this, _| {
            let id = this.motion.next_id;
            this.motion.next_id += 1;
            this.motion.list.push(id);
            this.motion.last_added = true;
        }))
        .child(button("add-delete-delete", "Delete", cx, |this, cx| {
            if !this.motion.list.is_empty() {
                let id = this.motion.list.remove(0);
                let now = cx.background_executor().now();
                this.motion
                    .deleted
                    .retain(|(_, _, since)| now.saturating_duration_since(*since) < DELETE_FADE);
                this.motion.deleted.push((id, 0, now));
                this.motion.last_added = false;
            }
        }));

    // PopupThemeTransition: a popup with a circle and a close button.
    let motion = PopupMotion::new("theme-popup", m.popup_open, PopupKind::Popup);
    let popup = motion.gate(
        motion.animate(
            "theme-popup-surface",
            div()
                .id("theme-popup")
                .test_support()
                .w(px(200.))
                .p(px(16.))
                .flex()
                .flex_col()
                .items_center()
                .gap(px(8.))
                .rounded(px(8.))
                .border_1()
                .border_color(crate::theme::flyout_stroke(cx))
                .bg(crate::views::popout::surface(cx))
                .child(
                    div()
                        .size(px(120.))
                        .rounded_full()
                        .bg(crate::theme::accent_fill(
                            crate::theme::ControlState::Rest,
                            cx,
                        )),
                )
                .child(div().text_size(px(14.)).child(t("A popup")))
                .child(button("theme-popup-close", "Close popup", cx, |this, _| {
                    this.motion.popup_open = false;
                }))
                .into_any_element(),
        ),
    );
    let popup_row = div()
        .relative()
        .min_h(px(280.))
        .flex()
        .flex_col()
        .gap(px(8.))
        .child(button("theme-popup-show", "Show popup", cx, |this, _| {
            this.motion.popup_open = true;
        }))
        .child(popup);

    vec![
        section(
            "EntranceThemeTransition",
            [
                entrance_buttons.into_any_element(),
                entrance.into_any_element(),
            ],
            cx,
        ),
        section(
            "RepositionThemeTransition",
            [reposition_button, reposition_row.into_any_element()],
            cx,
        ),
        section(
            "ContentThemeTransition",
            [content_button, content.into_any_element()],
            cx,
        ),
        section(
            "AddDeleteThemeTransition",
            [
                add_delete_buttons.into_any_element(),
                list.into_any_element(),
            ],
            cx,
        ),
        section("PopupThemeTransition", [popup_row.into_any_element()], cx),
    ]
}

/// ScalarTransition and Vector3Transition: 300 ms on (0.8,0,0.2,1)
/// (Microsoft.UI.Xaml.Motion.cs:47, 72; SharedTransitionAnimations.cpp:8-25).
fn implicit_curve(t: f32) -> f32 {
    gpui_kit::base::animation::cubic_bezier(0.8, 0., 0.2, 1.)(t)
}

pub(super) fn implicit_transitions_page(
    view: &Gallery,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> Vec<AnyElement> {
    let on = view.motion.implicit;
    let scalar = || Transition::new(Duration::from_millis(300)).ease(implicit_curve);
    let accent = crate::theme::accent_fill(crate::theme::ControlState::Rest, cx);
    let opacity = transition(
        "implicit-opacity",
        if on[0] { 0.2 } else { 1. },
        scalar(),
        window,
        cx,
    );
    let x = transition(
        "implicit-translate",
        if on[1] { 200. } else { 0. },
        scalar(),
        window,
        cx,
    );
    // BrushTransition: 150 ms, linear (Microsoft.UI.Xaml.Motion.cs:20).
    let mix = transition(
        "implicit-brush",
        if on[2] { 1. } else { 0. },
        Transition::new(Duration::from_millis(150)).ease(|t| t),
        window,
        cx,
    );
    let angle = transition(
        "implicit-rotate",
        if on[3] { 90. } else { 0. },
        scalar(),
        window,
        cx,
    );
    let scale = transition(
        "implicit-scale",
        if on[4] { 2. } else { 1. },
        scalar(),
        window,
        cx,
    );
    let brush = {
        let b = gpui_kit::Hsla::from(gpui_kit::rgb(0x0000FF)).to_rgb();
        let y = gpui_kit::Hsla::from(gpui_kit::rgb(0xFFFF00)).to_rgb();
        let lerp = |a: f32, b: f32| a + (b - a) * mix;
        gpui_kit::Hsla::from(gpui_kit::Rgba {
            r: lerp(b.r, y.r),
            g: lerp(b.g, y.g),
            b: lerp(b.b, y.b),
            a: 1.,
        })
    };
    let toggle = |ix: usize, id: &'static str, label: &'static str, cx: &mut Context<Gallery>| {
        button(id, label, cx, move |this, _| {
            this.motion.implicit[ix] = !this.motion.implicit[ix];
        })
    };
    let icon = |id: &'static str, transform: gpui_kit::Transformation| {
        div()
            .id(id)
            .test_support()
            .size(px(100.))
            .flex()
            .items_center()
            .justify_center()
            .child(
                gpui_kit::component::Icon::default()
                    .path("fluent/settings.svg")
                    .with_size(Size::Size(px(50.)))
                    .text_color(accent)
                    .transform(transform),
            )
            .into_any_element()
    };
    vec![
        section(
            "Opacity (ScalarTransition, 300 ms)",
            [
                toggle(0, "implicit-opacity-toggle", "Set opacity", cx),
                div()
                    .id("implicit-opacity")
                    .test_support()
                    .size(px(50.))
                    .bg(accent)
                    .opacity(opacity)
                    .into_any_element(),
            ],
            cx,
        ),
        section(
            "Translation (Vector3Transition, 300 ms)",
            [
                toggle(1, "implicit-translate-toggle", "Set translation", cx),
                div()
                    .relative()
                    .w(px(250.))
                    .h(px(50.))
                    .child(
                        div()
                            .id("implicit-translate")
                            .test_support()
                            .absolute()
                            .left(px(x))
                            .size(px(50.))
                            .bg(accent),
                    )
                    .into_any_element(),
            ],
            cx,
        ),
        section(
            "Background (BrushTransition, 150 ms)",
            [
                toggle(2, "implicit-brush-toggle", "Change background", cx),
                div()
                    .id("implicit-brush")
                    .test_support()
                    .size(px(50.))
                    .bg(brush)
                    .into_any_element(),
            ],
            cx,
        ),
        section(
            "Rotation and scale (icons only)",
            [
                div()
                    .text_size(px(12.))
                    .line_height(px(16.))
                    .text_color(crate::theme::text_secondary(cx))
                    .child(t(
                        "GPUI can rotate and scale only an SVG icon, not an element, so these run on an icon.",
                    ))
                    .into_any_element(),
                row()
                    .child(toggle(3, "implicit-rotate-toggle", "Rotate", cx))
                    .child(toggle(4, "implicit-scale-toggle", "Scale", cx))
                    .into_any_element(),
                row()
                    .child(icon(
                        "implicit-rotate",
                        gpui_kit::Transformation::rotate(gpui_kit::radians(angle.to_radians())),
                    ))
                    .child(icon(
                        "implicit-scale",
                        gpui_kit::Transformation::scale(gpui_kit::size(scale, scale)),
                    ))
                    .into_any_element(),
            ],
            cx,
        ),
    ]
}

/// ParallaxView: the background moves VerticalShift px over the whole
/// scroll range, clamped (ParallaxView.cpp:548-690; IsVerticalShiftClamped
/// and MaxVerticalShiftRatio 1 by default).
pub(super) fn parallax_page(window: &mut Window, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    const SHIFT: f32 = 500.;
    const HEIGHT: f32 = 400.;
    let handle = window
        .use_keyed_state("parallax-scroll", cx, |_, _| gpui_kit::ScrollHandle::new())
        .read(cx)
        .clone();
    let scrolled = -handle.offset().y;
    let range = handle.max_offset().y;
    let ratio = if range > px(0.) {
        (scrolled / range).clamp(0., 1.)
    } else {
        0.
    };
    let bands = [
        0x1B4F72, 0x21618C, 0x2874A6, 0x2E86C1, 0x3498DB, 0x5DADE2, 0x85C1E9,
    ];
    let mut background = div()
        .id("parallax-background")
        .test_support()
        .absolute()
        .left_0()
        .right_0()
        .top(px(-SHIFT * ratio))
        .h(px(HEIGHT + SHIFT))
        .flex()
        .flex_col();
    for band in bands {
        background = background.child(div().flex_1().bg(gpui_kit::rgb(band)));
    }
    let mut items = div().flex().flex_col().gap(px(4.)).p(px(16.));
    for i in 0..30 {
        items = items.child(
            div()
                .h(px(40.))
                .px(px(12.))
                .flex()
                .items_center()
                .rounded(px(4.))
                .bg(gpui_kit::hsla(0., 0., 1., 0.85))
                .text_color(gpui_kit::black())
                .child(format!("Item {}", i + 1)),
        );
    }
    let view = cx.entity().downgrade();
    let frame = div()
        .id("parallax-view")
        .test_support()
        .relative()
        .w(px(360.))
        .h(px(HEIGHT))
        .overflow_hidden()
        .rounded(px(8.))
        .child(background)
        .child(
            div()
                .id("parallax-list")
                .test_support()
                .absolute()
                .inset_0()
                .overflow_y_scroll()
                .track_scroll(&handle)
                .on_scroll(move |_, _, cx| {
                    view.update(cx, |_, cx| cx.notify()).ok();
                })
                .child(items),
        )
        .into_any_element();
    vec![section("ParallaxView, vertical shift 500", [frame], cx)]
}
