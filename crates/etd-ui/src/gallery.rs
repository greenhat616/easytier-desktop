//! Interactive, host-free specimen view of the same Fluent wrappers used
//! by the desktop. All activation is in-memory; no bridge, tray, services,
//! network profiles or production preferences are opened.
use crate::{
    assets::FluentAssets,
    preferences::ThemePreference,
    theme,
    views::ui::{
        BtnStyle, FluentInfoBar, FluentNavItem, InfoSeverity, action_button, fluent_switch,
        list_choice_button, list_selection_surface, password_input, progress_ring, text_field,
        theme_menu,
    },
};
use gpui_kit::{
    AnyElement, App, AppContext as _, Bounds, Context, Entity, InteractiveElement as _,
    IntoElement, ParentElement as _, QuitMode, Render, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, TitlebarOptions, Window,
    WindowBounds, WindowOptions,
    base::LogicalStyledExt as _,
    component::{
        ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant, input::InputState,
        sidebar::Sidebar,
    },
    div, px, size,
};

/// Starts a separate gallery window, with a session-only appearance choice.
/// Use --light or --dark to choose the initial mode.
pub fn run() {
    let preference = std::env::args()
        .skip(1)
        .find_map(|arg| match arg.as_str() {
            "--light" => Some(ThemePreference::Light),
            "--dark" => Some(ThemePreference::Dark),
            _ => None,
        })
        .unwrap_or_default();
    gpui_kit::application()
        .with_assets(FluentAssets)
        .with_quit_mode(QuitMode::LastWindowClosed)
        .run(move |cx| {
            gpui_kit::init(cx);
            theme::init_gallery(preference, cx);
            let (handle, _) = gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                        None,
                        size(px(1200.), px(1000.)),
                        cx,
                    ))),
                    titlebar: Some(TitlebarOptions {
                        title: Some("EasyTier · Fluent gallery".into()),
                        ..Default::default()
                    }),
                    window_background: theme::window_background(cx),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| Gallery::new(window, cx)),
            )
            .expect("open Fluent gallery");
            handle
                .update(cx, |_, window, cx| theme::bind_window(window, cx))
                .expect("bind gallery appearance");
        });
}

struct Gallery {
    toggles: [bool; 2],
    inputs: [Entity<InputState>; 3],
    nav_selected: usize,
    list_selected: usize,
    collapsed: bool,
    closed: [bool; 4],
    clicks: usize,
}

impl Gallery {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let normal = cx.new(|cx| InputState::new(window, cx).placeholder("Type here"));
        let filled = cx.new(|cx| InputState::new(window, cx).placeholder("Filled"));
        filled.update(cx, |input, cx| input.set_value("Example value", window, cx));
        let secret = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Demo only")
                .masked(true)
        });
        secret.update(cx, |input, cx| input.set_value("example", window, cx));
        Self {
            toggles: [false, true],
            inputs: [normal, filled, secret],
            nav_selected: 0,
            list_selected: 1,
            collapsed: false,
            closed: [false; 4],
            clicks: 0,
        }
    }
}

#[inline(never)]
fn gallery_sidebar(view: &Gallery, cx: &mut Context<Gallery>) -> AnyElement {
    let toggle = action_button(
        "gallery-collapse",
        if view.collapsed {
            "Expand gallery navigation"
        } else {
            "Collapse gallery navigation"
        },
        BtnStyle::new(ButtonVariant::Ghost, Size::Medium)
            .icon("fluent/navigation.svg")
            .icon_only(),
        cx.listener(|this, _, _, cx| {
            this.collapsed = !this.collapsed;
            cx.notify();
        }),
    );
    let header = div()
        .flex_row_dir(cx)
        .items_center()
        .gap_2()
        .h(px(40.))
        .child(toggle)
        .children((!view.collapsed).then(|| {
            div()
                .font_semibold()
                .text_size(px(14.))
                .child("Fluent gallery")
        }));
    let first = FluentNavItem::new(
        "gallery-nav-controls",
        "Controls",
        "fluent/globe.svg",
        "fluent/globe-filled.svg",
        view.nav_selected == 0,
        cx.listener(|this, _, _, cx| {
            this.nav_selected = 0;
            cx.notify();
        }),
    );
    let second = FluentNavItem::new(
        "gallery-nav-other",
        "Other item",
        "fluent/shield.svg",
        "fluent/shield-filled.svg",
        view.nav_selected == 1,
        cx.listener(|this, _, _, cx| {
            this.nav_selected = 1;
            cx.notify();
        }),
    );
    let mut sidebar = Sidebar::new("gallery-sidebar")
        .w(px(220.))
        .h_full()
        .bg(theme::chrome_fill(cx, cx.theme().sidebar))
        .border_0()
        .collapsed(view.collapsed)
        .header(header)
        .child(first)
        .child(second);
    if !view.collapsed {
        sidebar = sidebar.footer(div().w_full().child(theme_menu(cx)));
    }
    sidebar.into_any_element()
}

#[inline(never)]
fn section(
    title: &'static str,
    children: impl IntoIterator<Item = AnyElement>,
    cx: &App,
) -> AnyElement {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(div().font_semibold().text_size(px(20.)).child(title))
        .child(
            div()
                .flex()
                .flex_col()
                .gap_3()
                .p_3()
                .rounded(px(8.))
                .border_1()
                .border_color(theme::card_stroke(cx))
                .bg(theme::card_fill(cx))
                .children(children),
        )
        .into_any_element()
}

#[inline(never)]
fn gallery_buttons(cx: &mut Context<Gallery>) -> AnyElement {
    let variants = [
        ("accent", "Accent", ButtonVariant::Primary, None),
        ("standard", "Standard", ButtonVariant::Default, None),
        ("subtle", "Subtle", ButtonVariant::Ghost, None),
        ("hyperlink", "Hyperlink", ButtonVariant::Link, None),
        (
            "icon",
            "With icon",
            ButtonVariant::Default,
            Some("fluent/add.svg"),
        ),
    ];
    let mut columns = Vec::new();
    for (key, label, variant, icon) in variants {
        let mut cells = Vec::new();
        for (name, disabled, loading) in [
            ("Rest", false, false),
            ("Disabled", true, false),
            ("Loading", false, true),
        ] {
            let mut style = BtnStyle::new(variant, Size::Medium)
                .disabled(disabled)
                .loading(loading);
            if let Some(icon) = icon {
                style = style.icon(icon);
            }
            cells.push(action_button(
                SharedString::from(format!("gallery-{key}-{name}")),
                name,
                style,
                cx.listener(|this, _, _, cx| {
                    this.clicks += 1;
                    cx.notify();
                }),
            ));
        }
        columns.push(
            div()
                .flex()
                .flex_col()
                .items_start()
                .flex_1()
                .gap_2()
                .child(div().text_sm().font_semibold().child(label))
                .children(cells)
                .into_any_element(),
        );
    }
    section(
        "Buttons · live rest / hover / press / keyboard focus",
        [div()
            .flex_row_dir(cx)
            .flex_wrap()
            .gap_4()
            .children(columns)
            .into_any_element()],
        cx,
    )
}

#[inline(never)]
fn gallery_inputs(view: &Gallery, cx: &mut Context<Gallery>) -> AnyElement {
    let mut switches = Vec::new();
    for (index, label) in ["Off / interactive", "On / interactive"]
        .into_iter()
        .enumerate()
    {
        switches.push(fluent_switch(
            SharedString::from(format!("gallery-switch-{index}")),
            label,
            view.toggles[index],
            false,
            cx.listener(move |this, checked, _, cx| {
                this.toggles[index] = *checked;
                cx.notify();
            }),
        ));
    }
    switches.push(fluent_switch(
        "gallery-switch-disabled-off",
        "Disabled off",
        false,
        true,
        |_, _, _| {},
    ));
    switches.push(fluent_switch(
        "gallery-switch-disabled-on",
        "Disabled on",
        true,
        true,
        |_, _, _| {},
    ));
    let switch_panel = div()
        .flex()
        .flex_col()
        .gap_3()
        .flex_1()
        .child(div().font_semibold().child("Toggle switches"))
        .children(switches);
    let input_panel = div()
        .flex()
        .flex_col()
        .gap_2()
        .flex_1()
        .min_w_0()
        .child(text_field(
            "Text box",
            "gallery-input",
            "Editable text box",
            &view.inputs[0],
            false,
            cx,
        ))
        .child(text_field(
            "Disabled text box",
            "gallery-disabled-input",
            "Disabled text box",
            &view.inputs[1],
            true,
            cx,
        ))
        .child(div().text_sm().child("Masked input"))
        .child(password_input(
            "gallery-password",
            "Demo masked text box",
            &view.inputs[2],
            false,
        ));
    section(
        "Inputs",
        [div()
            .flex_row_dir(cx)
            .gap_4()
            .child(switch_panel)
            .child(input_panel)
            .into_any_element()],
        cx,
    )
}

#[inline(never)]
fn gallery_lists(view: &Gallery, cx: &mut Context<Gallery>) -> AnyElement {
    let mut rows = Vec::new();
    for (ix, title) in ["Example instance", "Selected instance"]
        .into_iter()
        .enumerate()
    {
        let selected = view.list_selected == ix;
        let (fill, border) = list_selection_surface(selected, cx);
        let btn = list_choice_button(
            SharedString::from(format!("gallery-list-{ix}")),
            title,
            selected,
            cx.listener(move |this, _, _, cx| {
                this.list_selected = ix;
                cx.notify();
            }),
        );
        rows.push(
            div()
                .id(("gallery-list-row", ix))
                .test_support()
                .flex_1()
                .p_2()
                .rounded(px(4.))
                .border_1()
                .border_color(border)
                .bg(fill)
                .aria_selected(selected)
                .child(btn)
                .into_any_element(),
        );
    }
    let rings = div()
        .flex_row_dir(cx)
        .items_center()
        .gap_3()
        .child(progress_ring(
            "gallery-progress-small",
            "Busy small",
            Size::Small,
        ))
        .child(progress_ring(
            "gallery-progress-medium",
            "Busy medium",
            Size::Medium,
        ))
        .child(progress_ring(
            "gallery-progress-large",
            "Busy large",
            Size::Large,
        ))
        .child(div().text_sm().child("Indeterminate · 12 / 16 / 20"));
    section(
        "List selection & progress",
        [
            div()
                .flex_row_dir(cx)
                .gap_3()
                .children(rows)
                .into_any_element(),
            rings.into_any_element(),
        ],
        cx,
    )
}

#[inline(never)]
fn gallery_notifications(view: &Gallery, cx: &mut Context<Gallery>) -> AnyElement {
    let mut rows = Vec::new();
    for (ix, (title, severity, message)) in [
        (
            "Information",
            InfoSeverity::Informational,
            "An update is available.",
        ),
        ("Success", InfoSeverity::Success, "Your changes were saved."),
        (
            "Warning",
            InfoSeverity::Warning,
            "A resource may be unavailable.",
        ),
        (
            "Error",
            InfoSeverity::Error,
            "An action could not complete.",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let plain = FluentInfoBar::new(
            SharedString::from(format!("gallery-info-plain-{ix}")),
            severity,
            message,
        )
        .title(title)
        .render(cx);
        let action = action_button(
            SharedString::from(format!("gallery-info-action-{ix}")),
            "Details",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(|this, _, _, cx| {
                this.clicks += 1;
                cx.notify();
            }),
        );
        let close = action_button(
            SharedString::from(format!("gallery-info-close-{ix}")),
            "Dismiss notification",
            BtnStyle::new(ButtonVariant::Ghost, Size::Size(px(38.)))
                .icon("fluent/dismiss.svg")
                .icon_only(),
            cx.listener(move |this, _, _, cx| {
                this.closed[ix] = true;
                cx.notify();
            }),
        );
        let decorated = if view.closed[ix] {
            action_button(
                SharedString::from(format!("gallery-info-reopen-{ix}")),
                "Restore InfoBar",
                BtnStyle::new(ButtonVariant::Default, Size::Medium),
                cx.listener(move |this, _, _, cx| {
                    this.closed[ix] = false;
                    cx.notify();
                }),
            )
        } else {
            FluentInfoBar::new(
                SharedString::from(format!("gallery-info-actionbar-{ix}")),
                severity,
                message,
            )
            .title(title)
            .actions([action])
            .close(close)
            .render(cx)
        };
        rows.push(
            div()
                .flex_row_dir(cx)
                .gap_3()
                .child(div().flex_1().min_w_0().child(plain))
                .child(div().flex_1().min_w_0().child(decorated))
                .into_any_element(),
        );
    }
    section("InfoBars · persistent / action + dismiss", rows, cx)
}

impl Render for Gallery {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let sidebar = gallery_sidebar(self, cx);
        let buttons = gallery_buttons(cx);
        let inputs = gallery_inputs(self, cx);
        let lists = gallery_lists(self, cx);
        let notifications = gallery_notifications(self, cx);
        div().id("gallery-root").test_support().size_full().flex_row_dir(cx)
            .bg(theme::chrome_fill(cx, cx.theme().background)).text_color(cx.theme().foreground)
            .child(sidebar)
            .child(div().flex_1().min_w_0().min_h_0().flex().flex_col()
                .child(div().h(px(52.)).flex_shrink_0().flex_row_dir(cx).items_center().justify_between().px(px(24.))
                    .child(div().font_semibold().text_size(px(24.)).child("Component gallery"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child(format!("Local actions: {}", self.clicks))))
                .child(div().id("gallery-scroll").test_support().flex_1().min_h_0().overflow_y_scroll()
                    .bg(theme::content_layer(cx)).rounded_tl(px(8.)).border_t_1().border_l_1().border_color(theme::card_stroke(cx)).px(px(24.)).py_4().flex().flex_col().gap_4()
                    .child(div().text_sm().text_color(cx.theme().muted_foreground)
                        .child("Hover or hold an enabled sample, or press Tab then Space/Enter. Appearance is session-only. No host is used."))
                    .child(buttons).child(inputs).child(lists).child(notifications)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{TestAppContext, test::TestWindowExt as _};

    #[gpui_kit::test]
    fn gallery_exercises_controls_without_host(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds {
                        origin: Default::default(),
                        size: size(px(1440.), px(1300.)),
                    })),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| Gallery::new(window, cx)),
            )
            .unwrap()
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("gallery-accent-Rest").bounds().size.height,
                px(32.)
            );
            assert_eq!(
                window.find("gallery-standard-Disabled").disabled(),
                Some(true)
            );
            window.click("gallery-accent-Rest", cx);
            assert_eq!(view.read(cx).clicks, 1);
            window.click("gallery-switch-0", cx);
            assert_eq!(window.find("gallery-switch-0").checked(), Some(true));
            window.click("theme-dark", cx);
            assert!(cx.theme().is_dark());
            window.click("theme-light", cx);
            assert!(!cx.theme().is_dark());
            assert!(window.find("gallery-info-actionbar-0").visible());
            window.click("gallery-info-close-0", cx);
            assert!(window.try_find("gallery-info-actionbar-0").is_none());
            window.click("gallery-info-reopen-0", cx);
            assert!(window.find("gallery-info-actionbar-0").visible());
        })
        .unwrap();
    }

    /// CI-only real offscreen renderer. No desktop/session interception.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    #[ignore = "requires a real offscreen renderer and GALLERY_SCREENSHOT_DIR"]
    fn capture_gallery_screenshots() {
        use gpui_kit::{
            HeadlessAppContext,
            platform::{current_headless_renderer, current_platform},
            test::{TestAppContextExt as _, TestEventExt as _},
        };
        use std::{path::PathBuf, sync::Arc, time::Duration};
        let output = PathBuf::from(
            std::env::var_os("GALLERY_SCREENSHOT_DIR").expect("GALLERY_SCREENSHOT_DIR"),
        );
        std::fs::create_dir_all(&output).unwrap();
        for (name, preference) in [
            ("light", ThemePreference::Light),
            ("dark", ThemePreference::Dark),
        ] {
            let mut cx = HeadlessAppContext::with_platform(
                current_platform(true).text_system(),
                Arc::new(FluentAssets),
                current_headless_renderer,
            );
            let (handle, _) = cx.update(|cx| {
                gpui_kit::init(cx);
                theme::install_palette(cx);
                gpui_kit::open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(Bounds {
                            origin: Default::default(),
                            size: size(px(1440.), px(1320.)),
                        })),
                        focus: false,
                        show: false,
                        ..Default::default()
                    },
                    cx,
                    |window, cx| cx.new(|cx| Gallery::new(window, cx)),
                )
                .unwrap()
            });
            cx.update_window(handle, |_, window, cx| {
                theme::set_preference(preference, window, cx);
                window.render_frame(cx);
            })
            .unwrap();
            cx.advance_clock(Duration::from_millis(350));
            cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-{name}.png")))
                .unwrap();
            cx.update_window(handle, |_, window, cx| {
                let center = window.find("gallery-accent-Rest").bounds().center();
                window.pointer_move(center, None, cx);
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-{name}-hover.png")))
                .unwrap();
            cx.update_window(handle, |_, window, cx| {
                let center = window.find("gallery-accent-Rest").bounds().center();
                window.pointer_down(center, gpui_kit::MouseButton::Left, cx);
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-{name}-pressed.png")))
                .unwrap();
            cx.update_window(handle, |_, window, cx| {
                let center = window.find("gallery-accent-Rest").bounds().center();
                window.pointer_up(center, gpui_kit::MouseButton::Left, cx);
                for _ in 0..12 {
                    window.press("tab", cx);
                    window.render_frame(cx);
                    if window.find("gallery-accent-Rest").focused() == Some(true) {
                        break;
                    }
                }
                assert!(window.find("fluent-focus-visual").visible());
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-{name}-focus.png")))
                .unwrap();
        }
    }
}
