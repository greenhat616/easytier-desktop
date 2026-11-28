//! Interactive, host-free specimen view of the same Fluent wrappers used
//! by the desktop. All activation is in-memory; no bridge, tray, services,
//! network profiles or production preferences are opened.
mod motion_pages;
mod pages;

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

/// Gallery pages, grouped like WinUI Gallery's navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Controls,
    Settings,
    BasicInput,
    Menus,
    Dialogs,
    Navigation,
    Layout,
    Feedback,
    Transitions,
    ThemeTransitions,
    Implicit,
    Parallax,
    Connected,
    Composition,
    Easing,
}

struct Gallery {
    toggles: [bool; 2],
    inputs: [Entity<InputState>; 3],
    page: Page,
    demo: pages::DemoState,
    list_selected: usize,
    collapsed: bool,
    closed: [bool; 4],
    clicks: usize,
    pseudo: bool,
    motion: motion_pages::MotionDemo,
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
            page: Page::Controls,
            demo: pages::DemoState::new(window, cx),
            list_selected: 1,
            collapsed: false,
            closed: [false; 4],
            clicks: 0,
            pseudo: false,
            motion: motion_pages::MotionDemo::new(cx),
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
    let nav = |page: Page,
               id: &'static str,
               label: &'static str,
               icon: &'static str,
               filled: &'static str,
               cx: &mut Context<Gallery>| {
        FluentNavItem::new(
            id,
            label,
            icon,
            filled,
            view.page == page,
            cx.listener(move |this, _, _, cx| {
                this.page = page;
                cx.notify();
            }),
        )
    };
    let first = nav(
        Page::Controls,
        "gallery-nav-controls",
        "Controls",
        "fluent/globe.svg",
        "fluent/globe-filled.svg",
        cx,
    );
    let settings = nav(
        Page::Settings,
        "gallery-nav-settings",
        "Settings",
        "fluent/settings.svg",
        "fluent/settings.svg",
        cx,
    );
    let basic = nav(
        Page::BasicInput,
        "gallery-nav-basic-input",
        "Basic input",
        "fluent/checkmark-circle.svg",
        "fluent/checkmark-circle-filled.svg",
        cx,
    );
    let menus = nav(
        Page::Menus,
        "gallery-nav-menus",
        "Menus & toolbars",
        "fluent/more-horizontal.svg",
        "fluent/more-horizontal.svg",
        cx,
    );
    let dialogs = nav(
        Page::Dialogs,
        "gallery-nav-dialogs",
        "Dialogs & flyouts",
        "fluent/chat.svg",
        "fluent/chat.svg",
        cx,
    );
    let navigation = nav(
        Page::Navigation,
        "gallery-nav-navigation",
        "Navigation",
        "fluent/navigation.svg",
        "fluent/navigation.svg",
        cx,
    );
    let layout = nav(
        Page::Layout,
        "gallery-nav-layout",
        "Layout",
        "fluent/grid.svg",
        "fluent/grid.svg",
        cx,
    );
    let feedback = nav(
        Page::Feedback,
        "gallery-nav-feedback",
        "Status & info",
        "fluent/info.svg",
        "fluent/info.svg",
        cx,
    );
    let page_transitions = nav(
        Page::Transitions,
        "gallery-nav-page-transitions",
        "Page transitions",
        "fluent/arrow-right.svg",
        "fluent/arrow-right.svg",
        cx,
    );
    let theme_transitions = nav(
        Page::ThemeTransitions,
        "gallery-nav-theme-transitions",
        "Theme transitions",
        "fluent/arrow-sync.svg",
        "fluent/arrow-sync.svg",
        cx,
    );
    let implicit = nav(
        Page::Implicit,
        "gallery-nav-implicit",
        "Implicit transitions",
        "fluent/arrow-clockwise.svg",
        "fluent/arrow-clockwise.svg",
        cx,
    );
    let parallax = nav(
        Page::Parallax,
        "gallery-nav-parallax",
        "ParallaxView",
        "fluent/grid.svg",
        "fluent/grid.svg",
        cx,
    );
    let connected = nav(
        Page::Connected,
        "gallery-nav-connected",
        "Connected animation",
        "fluent/link.svg",
        "fluent/link.svg",
        cx,
    );
    let composition = nav(
        Page::Composition,
        "gallery-nav-composition",
        "Composition",
        "fluent/color.svg",
        "fluent/color.svg",
        cx,
    );
    let easing = nav(
        Page::Easing,
        "gallery-nav-easing",
        "Easing functions",
        "fluent/play.svg",
        "fluent/play.svg",
        cx,
    );
    let mut sidebar = Sidebar::new("gallery-sidebar")
        .w(px(220.))
        .h_full()
        .bg(theme::chrome_fill(cx, cx.theme().sidebar))
        .border_0()
        .collapsed(view.collapsed)
        .header(header)
        .child(first)
        .child(basic)
        .child(menus)
        .child(dialogs)
        .child(navigation)
        .child(layout)
        .child(feedback)
        .child(page_transitions)
        .child(theme_transitions)
        .child(implicit)
        .child(parallax)
        .child(connected)
        .child(composition)
        .child(easing)
        .child(settings);
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
        .child(
            div()
                .font_semibold()
                .text_size(px(20.))
                .child(crate::views::pseudo::t(title)),
        )
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
                .child(
                    div()
                        .text_sm()
                        .font_semibold()
                        .child(crate::views::pseudo::t(label)),
                )
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
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let sidebar = gallery_sidebar(self, cx);
        let (title, body): (&str, Vec<AnyElement>) = match self.page {
            Page::Controls => (
                "Component gallery",
                vec![
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child("Hover or hold an enabled sample, or press Tab then Space/Enter. Appearance is session-only. No host is used.")
                        .into_any_element(),
                    gallery_buttons(cx),
                    gallery_inputs(self, cx),
                    gallery_lists(self, cx),
                    gallery_notifications(self, cx),
                ],
            ),
            Page::Settings => ("Settings", pages::settings_page(self, cx)),
            Page::BasicInput => ("Basic input", pages::basic_input_page(self, window, cx)),
            Page::Menus => ("Menus & toolbars", pages::menus_page(self, cx)),
            Page::Dialogs => ("Dialogs & flyouts", pages::dialogs_page(self, cx)),
            Page::Navigation => ("Navigation", pages::navigation_page(self, cx)),
            Page::Layout => ("Layout", pages::layout_page(self, window, cx)),
            Page::Feedback => ("Status & info", pages::feedback_page(self, cx)),
            Page::Transitions => (
                "Page transitions",
                motion_pages::page_transitions_page(self, cx),
            ),
            Page::ThemeTransitions => (
                "Theme transitions",
                motion_pages::theme_transitions_page(self, window, cx),
            ),
            Page::Implicit => (
                "Implicit transitions",
                motion_pages::implicit_transitions_page(self, window, cx),
            ),
            Page::Parallax => ("ParallaxView", motion_pages::parallax_page(window, cx)),
            Page::Connected => (
                "Connected animation",
                motion_pages::connected_page(self, cx),
            ),
            Page::Composition => (
                "Composition",
                motion_pages::composition_page(self, window, cx),
            ),
            Page::Easing => (
                "Easing functions",
                motion_pages::easing_page(self, window, cx),
            ),
        };
        div()
            .id("gallery-root")
            .test_support()
            .size_full()
            .flex_row_dir(cx)
            .bg(theme::chrome_fill(cx, cx.theme().background))
            .text_color(cx.theme().foreground)
            .child(sidebar)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .h(px(52.))
                            .flex_shrink_0()
                            .flex_row_dir(cx)
                            .items_center()
                            .justify_between()
                            .px(px(24.))
                            .child(
                                div()
                                    .font_semibold()
                                    .text_size(px(24.))
                                    .child(crate::views::pseudo::t(title)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap(px(24.))
                                    // Doc#24's +40 % pseudo-locale check.
                                    .child(crate::views::ui::fluent_switch(
                                        "gallery-pseudo",
                                        "Pseudo-locale",
                                        self.pseudo,
                                        false,
                                        cx.listener(|this, on: &bool, _, cx| {
                                            this.pseudo = *on;
                                            crate::views::pseudo::set(*on);
                                            cx.notify();
                                        }),
                                    ))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
                                            .child(format!("Local actions: {}", self.clicks)),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id("gallery-scroll")
                            .test_support()
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .bg(theme::content_layer(cx))
                            .rounded_tl(px(8.))
                            .border_t_1()
                            .border_l_1()
                            .border_color(theme::card_stroke(cx))
                            .px(px(24.))
                            .py_4()
                            .flex()
                            .flex_col()
                            .gap_4()
                            .children(body),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{TestAppContext, test::TestWindowExt as _};

    /// "Pop out" opens one always-on-top, resizable room window with its
    /// own title bar and a scrolling peer list; a second press brings the same one forward, and its close
    /// button closes it.
    #[gpui_kit::test]
    fn gallery_pops_out_one_room_window(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(true);
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
            window.click("gallery-nav-feedback", cx);
            window.render_frame(cx);
            window.click("popout-open", cx);
        })
        .unwrap();
        cx.run_until_parked();
        let popout = view
            .read_with(cx, |g, _| g.demo.popout)
            .expect("pop-out opened");
        assert_eq!(cx.windows().len(), 2);
        cx.update_window(popout, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("popout-title").bounds().size.height, px(32.));
            assert_eq!(
                window.find("popout-title-close").bounds().size.width,
                px(46.)
            );
            assert_eq!(window.find("popout-title-close").label(), Some("Close"));
            assert!(window.find("popout-badge").visible());
            // S3's peer list: 40 px rows inset 4,2 that scroll in the space
            // left under the header.
            let row = window.find("popout-peer-0").bounds();
            assert!(row.size.height >= px(40.));
            let list = window.find("popout-peers").bounds();
            let last = window.find("popout-peer-8").bounds();
            assert!(last.bottom() > list.bottom(), "nine peers overflow 520 px");
            window.scroll(
                "popout-peers-area",
                gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), px(-400.))),
                cx,
            );
            window.render_frame(cx);
            assert!(window.find("popout-peer-8").bounds().bottom() <= list.bottom() + px(1.));
        })
        .unwrap();
        // A second press brings the same window forward.
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("popout-open", cx);
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(cx.windows().len(), 2);
        assert_eq!(view.read_with(cx, |g, _| g.demo.popout), Some(popout));
        cx.update_window(popout, |_, window, cx| {
            window.click("popout-title-close", cx)
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(cx.windows().len(), 1);
        // With it closed, "Pop out" opens a new one.
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("popout-open", cx);
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(cx.windows().len(), 2);
    }

    /// The copy button writes to the clipboard and says "Copied" for two
    /// seconds, also from the keyboard; a status badge is 20 px tall and
    /// a narrow one truncates.
    #[gpui_kit::test]
    fn gallery_feedback_controls(cx: &mut TestAppContext) {
        use std::time::Duration;
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(true);
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
        let step = |cx: &mut TestAppContext, ms: u64| {
            cx.executor().advance_clock(Duration::from_millis(ms));
            cx.run_until_parked();
            cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                .unwrap();
        };
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("gallery-nav-feedback", cx);
            window.render_frame(cx);
            let badge = window.find("badge-success").bounds();
            assert_eq!(badge.size.height, px(20.));
            let narrow = window.find("badge-long").bounds();
            assert!(narrow.size.width <= px(140.));
            assert_eq!(window.find("copy-ip").label(), Some("Copy IP address"));
            window.click("copy-ip", cx);
            window.render_frame(cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|c| c.text()).as_deref(),
                Some("10.144.144.3")
            );
            assert!(window.find("copy-ip-copied").visible());
            assert_eq!(window.find("copy-ip").label(), Some("Copied"));
            // The note sits under the button, not over it.
            assert!(
                window.find("copy-ip-copied").bounds().top()
                    >= window.find("copy-ip").bounds().bottom()
            );
        })
        .unwrap();
        step(cx, 2100);
        cx.update_window(handle, |_, window, cx| {
            assert!(window.try_find("copy-ip-copied").is_none());
            // Enter on the focused button copies again.
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.find("copy-ip-copied").visible());
        })
        .unwrap();
        cx.update_window(handle, |_, window, cx| {
            // ProgressBar: 3 px tall; 40 % determinate.
            let bar = window.find("progress-determinate").bounds();
            assert_eq!(bar.size.height, px(3.));
            // Selection cards: one Tab stop; arrows and clicks choose.
            assert_eq!(view.read(cx).demo_mode(), 0);
            window.click("mode-cards-1", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_mode(), 1);
            assert_eq!(window.find("mode-cards-1").selected(), Some(true));
            window.press("left", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_mode(), 0);
            assert!(window.find("empty-networks").visible());
        })
        .unwrap();
    }

    /// With motion allowed, popups and expanders linger for WinUI's exit
    /// timings: a MenuFlyout fades for 83 ms, a ContentDialog for 83 ms and
    /// an Expander's content slides up for 167 ms. An Expander that is open
    /// when it first appears does not slide in.
    /// A connected animation flies a copy from the source's place to the
    /// destination's over 300 ms (Gravity), dipping on the way; the spring
    /// moves the button on hover.
    #[gpui_kit::test]
    fn gallery_connected_animation_flies_between_pages(cx: &mut TestAppContext) {
        use std::time::Duration;
        let (handle, _view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(false);
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
        let step = |cx: &mut TestAppContext, ms: u64| {
            for _ in 0..(ms / 25) {
                cx.executor().advance_clock(Duration::from_millis(25));
                cx.run_until_parked();
                cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                    .unwrap();
            }
        };
        let mut source = Bounds::default();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("gallery-nav-connected", cx);
            window.render_frame(cx);
            source = window.find("connected-source").bounds();
            window.click("connected-forward", cx);
            window.render_frame(cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 100);
        let mut destination = Bounds::default();
        cx.update_window(handle, |_, window, _| {
            destination = window.find("connected-destination").bounds();
            let flight = window.find("connected-flight").bounds();
            assert!(
                flight.size.width > source.size.width && flight.size.width < destination.size.width,
                "growing from 100 to 150 wide: {flight:?}"
            );
        })
        .unwrap();
        step(cx, 100);
        cx.update_window(handle, |_, window, _| {
            // About 66 % in, the Gravity dip puts it below the straight path.
            let flight = window.find("connected-flight").bounds();
            // The straight path runs from the source's top to the
            // destination's; the dip adds up to 80 px below it.
            let straight = source.top().max(destination.top());
            assert!(
                flight.top() > straight && flight.top() < straight + px(80.),
                "dipping: {flight:?}"
            );
        })
        .unwrap();
        step(cx, 200);
        cx.update_window(handle, |_, window, _| {
            assert!(window.try_find("connected-flight").is_none(), "landed");
        })
        .unwrap();

        // The spring lifts the button 20 px on hover.
        let mut rest = px(0.);
        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-composition", cx);
            window.render_frame(cx);
            rest = window.find("composition-spring").bounds().top();
            window.hover("composition-spring", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 500);
        cx.update_window(handle, |_, window, _| {
            let top = window.find("composition-spring").bounds().top();
            assert!(
                (top - (rest - px(20.))).abs() < px(1.),
                "lifted: {top:?} from {rest:?}"
            );
        })
        .unwrap();
    }

    /// Theme and implicit transitions and ParallaxView follow WinUI's
    /// timing: the measured theme storyboards, the source's offsets and
    /// delays, and the implicit transitions' 300 ms.
    #[gpui_kit::test]
    fn gallery_theme_transitions_follow_winui_timing(cx: &mut TestAppContext) {
        use std::time::Duration;
        let (handle, _view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(false);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds {
                        origin: Default::default(),
                        size: size(px(1440.), px(2400.)),
                    })),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| Gallery::new(window, cx)),
            )
            .unwrap()
        });
        let step = |cx: &mut TestAppContext, ms: u64| {
            for _ in 0..(ms / 50) {
                cx.executor().advance_clock(Duration::from_millis(50));
                cx.run_until_parked();
                cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                    .unwrap();
            }
        };
        let top = |cx: &mut TestAppContext, id: &'static str| {
            cx.update_window(handle, |_, window, _| window.find(id).bounds().top())
                .unwrap()
        };
        let left = |cx: &mut TestAppContext, id: &'static str| {
            cx.update_window(handle, |_, window, _| window.find(id).bounds().left())
                .unwrap()
        };
        // Entrance, five at once: the fifth waits 5 x 35 ms, 28 px down.
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("gallery-nav-theme-transitions", cx);
            window.render_frame(cx);
            window.click("entrance-add-five", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 150);
        let waiting = top(cx, "entrance-item-104");
        step(cx, 1000);
        assert_eq!(waiting - top(cx, "entrance-item-104"), px(28.));

        // Reposition: hiding green moves blue 85 px left over 367 ms.
        let before = left(cx, "reposition-blue");
        cx.update_window(handle, |_, window, cx| {
            window.click("reposition-toggle", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 100);
        let moving = left(cx, "reposition-blue");
        assert!(
            moving < before && moving > before - px(85.),
            "sliding: {moving:?} from {before:?}"
        );
        step(cx, 400);
        assert_eq!(left(cx, "reposition-blue"), before - px(85.));

        // Add/Delete: the deleted item fades for 100 ms; the rest close the
        // gap after 220 ms.
        let second = top(cx, "add-delete-item-1");
        cx.update_window(handle, |_, window, cx| {
            window.click("add-delete-delete", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 50);
        cx.update_window(handle, |_, window, _| {
            assert!(window.try_find("add-delete-item-0").is_some(), "fading");
        })
        .unwrap();
        step(cx, 150);
        cx.update_window(handle, |_, window, _| {
            assert!(window.try_find("add-delete-item-0").is_none(), "gone");
        })
        .unwrap();
        assert_eq!(top(cx, "add-delete-item-1"), second, "waits 220 ms");
        step(cx, 500);
        assert_eq!(top(cx, "add-delete-item-1"), second - px(32.));

        // Implicit translation: 300 ms on (0.8,0,0.2,1).
        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-implicit", cx);
            window.render_frame(cx);
        })
        .unwrap();
        let start = left(cx, "implicit-translate");
        cx.update_window(handle, |_, window, cx| {
            window.click("implicit-translate-toggle", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 150);
        let mid = left(cx, "implicit-translate") - start;
        assert!(mid > px(20.) && mid < px(180.), "halfway: {mid:?}");
        step(cx, 200);
        assert_eq!(left(cx, "implicit-translate") - start, px(200.));

        // ParallaxView: scrolling moves the background up.
        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-parallax", cx);
            window.render_frame(cx);
        })
        .unwrap();
        let resting = top(cx, "parallax-background");
        cx.update_window(handle, |_, window, cx| {
            window.scroll(
                "parallax-list",
                gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), px(-300.))),
                cx,
            );
            window.render_frame(cx);
            window.render_frame(cx);
        })
        .unwrap();
        assert!(
            top(cx, "parallax-background") < resting,
            "background moved up"
        );
    }

    /// Page transitions and easing functions run on WinUI's timing
    /// (ThemeTransitions.cpp, EasingFunctions.cpp).
    #[gpui_kit::test]
    fn gallery_page_transitions_and_easings_follow_winui_timing(cx: &mut TestAppContext) {
        use std::time::Duration;
        let (handle, _view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(false);
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
        let step = |cx: &mut TestAppContext, ms: u64| {
            cx.executor().advance_clock(Duration::from_millis(ms));
            cx.run_until_parked();
            cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                .unwrap();
        };
        // Entrance: the old page fades for 150 ms while the new one waits
        // 140 px down, then rises by 450 ms.
        let mut frame_top = px(0.);
        let mut frame_left = px(0.);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("gallery-nav-page-transitions", cx);
            window.render_frame(cx);
            frame_top = window.find("sample-page-0").bounds().top();
            window.click("page-forward", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 100);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("sample-page-0").is_some(),
                "old page leaving"
            );
            assert_eq!(
                window.find("sample-page-1").bounds().top(),
                frame_top + px(140.)
            );
        })
        .unwrap();
        step(cx, 200);
        cx.update_window(handle, |_, window, _| {
            let top = window.find("sample-page-1").bounds().top();
            assert!(
                top > frame_top && top < frame_top + px(140.),
                "rising: {top:?}"
            );
        })
        .unwrap();
        step(cx, 200);
        cx.update_window(handle, |_, window, cx| {
            assert!(window.try_find("sample-page-0").is_none(), "old page gone");
            assert_eq!(window.find("sample-page-1").bounds().top(), frame_top);
            frame_left = window.find("sample-page-1").bounds().left();
            // Slide from right: the new page waits 200 px to the right.
            window.click("page-transition-kind-3", cx);
            window.render_frame(cx);
            window.click("page-forward", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 100);
        cx.update_window(handle, |_, window, _| {
            let old = window.find("sample-page-1").bounds().left();
            let new = window.find("sample-page-0").bounds().left();
            assert_eq!(new, frame_left + px(200.), "new page waits 200 px right");
            assert!(
                old < frame_left && old > frame_left - px(150.),
                "old page leaving left"
            );
        })
        .unwrap();
        step(cx, 400);
        // Easing: CircleEase InOut over 500 ms is halfway at 250 ms.
        let mut start = px(0.);
        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-easing", cx);
            window.render_frame(cx);
            start = window.find("easing-square-0").bounds().left();
            window.click("easing-animate-0", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 250);
        cx.update_window(handle, |_, window, _| {
            let x = window.find("easing-square-0").bounds().left() - start;
            assert!((x - px(100.)).abs() < px(8.), "halfway at 250 ms: {x:?}");
        })
        .unwrap();
        step(cx, 300);
        cx.update_window(handle, |_, window, _| {
            let x = window.find("easing-square-0").bounds().left() - start;
            assert_eq!(x, px(200.));
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn gallery_motion_follows_winui_timing(cx: &mut TestAppContext) {
        use std::time::Duration;
        let (handle, _view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            cx.set_reduce_motion(false);
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
        let step = |cx: &mut TestAppContext, ms: u64| {
            cx.executor().advance_clock(Duration::from_millis(ms));
            cx.run_until_parked();
            cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                .unwrap();
        };
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("gallery-nav-menus", cx);
            window.render_frame(cx);
            window.click("menu-button", cx);
            window.render_frame(cx);
        })
        .unwrap();
        // The menu slides in over 250 ms.
        step(cx, 300);
        cx.update_window(handle, |_, window, cx| {
            assert!(window.find("menu-flyout").visible());
            window.press("escape", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 40);
        cx.update_window(handle, |_, window, _| {
            assert!(window.try_find("menu-flyout").is_some(), "menu fading out");
        })
        .unwrap();
        step(cx, 60);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("menu-flyout").is_none(),
                "menu gone after 83 ms"
            );
        })
        .unwrap();

        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-dialogs", cx);
            window.render_frame(cx);
            window.click("dialog-open", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 300);
        cx.update_window(handle, |_, window, cx| {
            window.click("dialog-secondary", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 40);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("dialog-smoke").is_some(),
                "dialog fading out"
            );
        })
        .unwrap();
        step(cx, 60);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("dialog-smoke").is_none(),
                "dialog gone after 83 ms"
            );
        })
        .unwrap();

        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-layout", cx);
            window.render_frame(cx);
            // Open on arrival, so already in place.
            let header = window.find("layout-expander-header").bounds();
            let content = window.find("layout-expander-content").bounds();
            assert_eq!(content.top(), header.bottom());
            window.click("layout-expander-header", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 100);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("layout-expander-content").is_some(),
                "content sliding up"
            );
        })
        .unwrap();
        step(cx, 100);
        cx.update_window(handle, |_, window, _| {
            assert!(
                window.try_find("layout-expander-content").is_none(),
                "content gone after 167 ms"
            );
        })
        .unwrap();
        // The NavigationView indicator stretches towards the new item for
        // 200 ms, then settles on it by 600 ms.
        cx.update_window(handle, |_, window, cx| {
            window.click("gallery-nav-navigation", cx);
            window.render_frame(cx);
            assert_eq!(window.find("nav-indicator").bounds().size.height, px(16.));
            window.click("nav-item-4", cx);
            window.render_frame(cx);
        })
        .unwrap();
        step(cx, 200);
        cx.update_window(handle, |_, window, _| {
            // Items 0 to 4 are 160 px apart: the pill spans both.
            assert!(window.find("nav-indicator").bounds().size.height > px(150.));
        })
        .unwrap();
        step(cx, 450);
        cx.update_window(handle, |_, window, _| {
            let pill = window.find("nav-indicator").bounds();
            let item = window.find("nav-item-4").bounds();
            assert_eq!(pill.size.height, px(16.));
            assert_eq!(pill.top(), item.top() + px(10.));
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn gallery_exercises_controls_without_host(cx: &mut TestAppContext) {
        fn tab_to(window: &mut gpui_kit::Window, id: &'static str, cx: &mut gpui_kit::App) {
            for _ in 0..60 {
                window.press("tab", cx);
                window.render_frame(cx);
                if window.find(id).focused() == Some(true) {
                    return;
                }
            }
            panic!("Tab never reached {id}");
        }
        let (handle, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            // Popups and expanders settle at once, as with Windows' animation
            // effects off; `gallery_motion_follows_winui_timing` covers motion.
            cx.set_reduce_motion(true);
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
            window.click("gallery-nav-settings", cx);
            window.render_frame(cx);
            assert!(window.find("settings-spatial").visible());
            // SettingsCardMinHeight 68; a title plus description is taller.
            assert!(window.find("settings-nav-style-card").bounds().size.height >= px(68.));
            window.click("settings-sound-chevron", cx);
            window.render_frame(cx);
            assert!(window.try_find("settings-spatial").is_none());
            window.click("settings-app-theme", cx);
            window.render_frame(cx);
            window.click("settings-app-theme-item-2", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_app_theme(), 2);
            assert!(window.try_find("settings-app-theme-popup").is_none());
            window.click("gallery-nav-basic-input", cx);
            window.render_frame(cx);
            assert_eq!(window.find("basic-check-two").checked(), Some(true));
            window.click("basic-check-two", cx);
            window.render_frame(cx);
            assert_eq!(window.find("basic-check-two").checked(), Some(false));
            assert_eq!(window.find("basic-check-d1").disabled(), Some(true));
            window.click("basic-radio-1", cx);
            window.render_frame(cx);
            assert_eq!(window.find("basic-radio-1").checked(), Some(true));
            window.click("basic-number-Increase", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_number(cx).as_ref(), "13");
            window.click("gallery-nav-menus", cx);
            window.render_frame(cx);
            window.click("menu-button", cx);
            window.render_frame(cx);
            assert_eq!(window.find("menu-hidden").checked(), Some(true));
            window.click("menu-sort", cx);
            window.render_frame(cx);
            window.click("menu-sort-2", cx);
            window.render_frame(cx);
            assert!(window.try_find("menu-flyout").is_none());
            assert_eq!(view.read(cx).demo_last().as_ref(), "Sort by Size");
            window.click("bar-preview", cx);
            window.render_frame(cx);
            assert_eq!(window.find("bar-preview").checked(), Some(true));
            window.click("command-bar-more", cx);
            window.render_frame(cx);
            window.click("bar-refresh", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_last().as_ref(), "Refresh");
        })
        .unwrap();
        // Closing the overflow menu gave focus back to its More button.
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("command-bar-more").focused(), Some(true));

            // Keyboard: every control is a Tab stop that Enter or Space
            // activates, and open flyouts take Up, Down and Escape.
            tab_to(window, "menu-button", cx);
            assert!(window.find("fluent-focus-visual").visible());
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.find("menu-flyout").visible());
        })
        .unwrap();
        // The open menu took focus; Down reaches its first item, Escape
        // closes it and focus goes back to the button.
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("down", cx);
            window.render_frame(cx);
            assert_eq!(window.find("menu-open").focused(), Some(true));
            window.press("escape", cx);
            window.render_frame(cx);
            assert!(window.try_find("menu-flyout").is_none());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("menu-button").focused(), Some(true));
            // Escape also closes a menu whose submenu is open.
            window.click("menu-button", cx);
            window.render_frame(cx);
            window.click("menu-sort", cx);
            window.render_frame(cx);
            assert!(window.find("menu-sort-submenu").visible());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("escape", cx);
            window.render_frame(cx);
            assert!(window.try_find("menu-flyout").is_none());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            tab_to(window, "bar-add", cx);
            window.press("space", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_last().as_ref(), "Add");

            window.click("gallery-nav-settings", cx);
            window.render_frame(cx);
            assert!(window.try_find("settings-spatial").is_none());
            tab_to(window, "settings-sound-header", cx);
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.find("settings-spatial").visible());
            // Pressing a control in the header leaves the expander alone.
            window.click("settings-sound-switch", cx);
            window.render_frame(cx);
            assert!(window.find("settings-spatial").visible());

            window.click("gallery-nav-basic-input", cx);
            window.render_frame(cx);
            tab_to(window, "basic-combo", cx);
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.find("basic-combo-popup").visible());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("escape", cx);
            window.render_frame(cx);
            assert!(window.try_find("basic-combo-popup").is_none());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("basic-combo").focused(), Some(true));
            tab_to(window, "basic-check-two", cx);
            window.press("space", cx);
            window.render_frame(cx);
            assert_eq!(window.find("basic-check-two").checked(), Some(true));
            window.click("basic-number", cx);
            window.render_frame(cx);
            window.press("up", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_number(cx).as_ref(), "14");

            // Dialogs & flyouts.
            window.click("gallery-nav-dialogs", cx);
            window.render_frame(cx);
            window.click("dialog-open", cx);
            window.render_frame(cx);
            assert!(window.find("dialog").visible());
            assert!(window.find("dialog").bounds().size.width >= px(320.));
            assert!(window.find("dialog").bounds().size.width <= px(548.));
            // The smoke layer takes presses outside the dialog.
            window.click("gallery-nav-controls", cx);
            window.render_frame(cx);
            assert!(window.find("dialog").visible());
            window.click("dialog-secondary", cx);
            window.render_frame(cx);
            assert!(window.try_find("dialog").is_none());
            assert_eq!(view.read(cx).demo_dialog_result().as_ref(), "Don't save");
            window.click("tip-target", cx);
            window.render_frame(cx);
            assert!(window.find("tip").visible());
            // The tip opens below its target, its tail in the 12 px gap.
            assert!(
                window.find("tip").bounds().top() >= window.find("tip-target").bounds().bottom()
            );
            // A TeachingTip is not light-dismissed.
            window.click("flyout-open", cx);
            window.render_frame(cx);
            assert!(window.find("tip").visible());
            assert!(window.find("flyout").visible());
            window.click("flyout-confirm", cx);
            window.render_frame(cx);
            assert!(window.try_find("flyout").is_none());
            window.click("tip-close", cx);
            window.render_frame(cx);
            assert!(window.try_find("tip").is_none());
            window.click("dialog-open", cx);
            window.render_frame(cx);
        })
        .unwrap();
        // The open dialog takes focus: Enter answers the default button.
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.try_find("dialog").is_none());
            assert_eq!(view.read(cx).demo_dialog_result().as_ref(), "Save");
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            tab_to(window, "dialog-open", cx);
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.find("dialog").visible());
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            // Tab stays inside the dialog.
            for _ in 0..8 {
                window.press("tab", cx);
                window.render_frame(cx);
                assert_ne!(window.find("dialog-open").focused(), Some(true));
            }
            window.press("escape", cx);
            window.render_frame(cx);
            assert!(window.try_find("dialog").is_none());
            assert_eq!(view.read(cx).demo_dialog_result().as_ref(), "Cancel");
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("dialog-open").focused(), Some(true));
            // The TeachingTip's close button answers Enter.
            window.click("tip-target", cx);
            window.render_frame(cx);
            tab_to(window, "tip-close", cx);
            window.press("enter", cx);
            window.render_frame(cx);
            assert!(window.try_find("tip").is_none());

            // Navigation.
            window.click("gallery-nav-navigation", cx);
            window.render_frame(cx);
            assert!(window.find("nav-item-2").visible());
            assert_eq!(window.find("nav-item-0").bounds().size.height, px(36.));
            // Children keep the pane's margins; their content indents 31 px.
            assert_eq!(
                window.find("nav-item-2").bounds().left()
                    - window.find("nav-item-0").bounds().left(),
                px(0.)
            );
            window.click("nav-item-3", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_nav().0, 3);
            window.click("nav-item-1", cx);
            window.render_frame(cx);
            assert!(window.try_find("nav-item-2").is_none());
            window.click("crumbs-1", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_nav().1, 2);
            assert!(window.try_find("crumbs-2").is_none());
            window.click("selector-2", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_nav().2, 2);
            assert_eq!(window.find("selector-2").selected(), Some(true));
            window.click("tabs-add", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_nav().3, 4);
            window.click("tabs-0-close", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_nav().3, 3);
            tab_to(window, "tabs-1", cx);
            window.press("space", cx);
            window.render_frame(cx);
            assert_eq!(window.find("tabs-1").selected(), Some(true));

            window.click("gallery-nav-dialogs", cx);
            window.render_frame(cx);
            window.click("flyout-open", cx);
            window.render_frame(cx);
        })
        .unwrap();
        // A popup opened while an older one closes keeps the focus it took.
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("escape", cx);
            window.render_frame(cx);
            window.click("dialog-open", cx);
            window.render_frame(cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update_window(handle, |_, window, cx| {
            window.press("escape", cx);
            window.render_frame(cx);
            assert!(window.try_find("dialog").is_none());

            // Layout: the Expander header toggles by click and by keyboard.
            window.click("gallery-nav-layout", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_layout(), [true, false]);
            assert!(window.find("layout-expander-content").visible());
            assert_eq!(
                window.find("layout-expander-header").bounds().size.height,
                px(48.)
            );
            window.click("layout-expander-header", cx);
            window.render_frame(cx);
            assert!(window.try_find("layout-expander-content").is_none());
            tab_to(window, "layout-expander-2-header", cx);
            window.press("enter", cx);
            window.render_frame(cx);
            assert_eq!(view.read(cx).demo_layout(), [false, true]);
            assert_eq!(
                window.find("layout-expander-2-header").expanded(),
                Some(true)
            );
            // StackPanel: 40 px squares 8 apart, then laid out in a row.
            let stack = window.find("layout-stack").bounds();
            assert_eq!(stack.size.height, px(4. * 40. + 3. * 8.));
            window.click("layout-orientation-0", cx);
            window.render_frame(cx);
            let stack = window.find("layout-stack").bounds();
            assert_eq!(stack.size.height, px(40.));
            // ScrollViewer: the area is 200 tall and its content overflows.
            assert_eq!(window.find("layout-scroll").bounds().size.height, px(200.));
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
                // Popups and expanders settle at once, as with Windows' animation
                // effects off; `gallery_motion_follows_winui_timing` covers motion.
                cx.set_reduce_motion(true);
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
            // A focused text box shows WinUI's 2 px accent bottom line.
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-input", cx);
                window.render_frame(cx);
                assert!(
                    window
                        .within("gallery-input-frame")
                        .find("fluent-textbox-underline")
                        .visible()
                );
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-{name}-textbox-focus.png")))
                .unwrap();
            for (page, nav) in [
                ("settings", "gallery-nav-settings"),
                ("basic-input", "gallery-nav-basic-input"),
            ] {
                cx.update_window(handle, |_, window, cx| {
                    window.click(nav, cx);
                    window.render_frame(cx);
                })
                .unwrap();
                cx.advance_clock(Duration::from_millis(350));
                cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                    .unwrap();
                cx.capture_screenshot(handle)
                    .unwrap()
                    .save(output.join(format!("gallery-{page}-{name}.png")))
                    .unwrap();
            }
            // Open drop-down and a hovered CheckBox on the Basic input page.
            cx.update_window(handle, |_, window, cx| {
                window.click("basic-combo", cx);
                window.render_frame(cx);
                assert!(window.find("basic-combo-popup").visible());
                let center = window.find("basic-check-two").bounds().center();
                window.pointer_move(center, None, cx);
                window.render_frame(cx);
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-basic-input-{name}-open.png")))
                .unwrap();
            // Menus page: the MenuFlyout with its submenu open, and the
            // Preview AppBarToggleButton checked.
            cx.update_window(handle, |_, window, cx| {
                window.click("basic-combo", cx);
                window.render_frame(cx);
                window.click("gallery-nav-menus", cx);
                window.render_frame(cx);
                window.click("bar-preview", cx);
                window.render_frame(cx);
                window.click("menu-button", cx);
                window.render_frame(cx);
                window.click("menu-sort", cx);
                window.render_frame(cx);
                assert!(window.find("menu-sort-submenu").visible());
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-menus-{name}.png")))
                .unwrap();
            // Keyboard focus on the Settings page: the first press outside
            // the open menu only light-dismisses it, the second navigates;
            // then Tab reaches the Sound expander header.
            for _ in 0..2 {
                cx.update_window(handle, |_, window, cx| {
                    window.click("gallery-nav-settings", cx);
                    window.render_frame(cx);
                })
                .unwrap();
                cx.run_until_parked();
            }
            cx.run_until_parked();
            cx.update_window(handle, |_, window, cx| {
                for _ in 0..60 {
                    window.press("tab", cx);
                    window.render_frame(cx);
                    if window.find("settings-sound-header").focused() == Some(true) {
                        break;
                    }
                }
                assert!(window.find("fluent-focus-visual").visible());
            })
            .unwrap();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-settings-{name}-focus.png")))
                .unwrap();
            // Dialogs page: a TeachingTip and a Flyout open together, then
            // the ContentDialog over its smoke layer.
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-nav-dialogs", cx);
                window.render_frame(cx);
                window.click("tip-target", cx);
                window.render_frame(cx);
                assert!(window.find("tip").visible());
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-dialogs-{name}.png")))
                .unwrap();
            cx.update_window(handle, |_, window, cx| {
                window.click("tip-close", cx);
                window.render_frame(cx);
                window.click("flyout-open", cx);
                window.render_frame(cx);
                assert!(window.find("flyout").visible());
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-dialogs-{name}-flyout.png")))
                .unwrap();
            cx.update_window(handle, |_, window, cx| {
                window.press("escape", cx);
                window.render_frame(cx);
                window.click("dialog-open", cx);
                window.render_frame(cx);
                assert!(window.find("dialog").visible());
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-dialogs-{name}-dialog.png")))
                .unwrap();
            // Layout page, once the dialog above is closed.
            cx.update_window(handle, |_, window, cx| {
                window.press("escape", cx);
                window.render_frame(cx);
                window.click("gallery-nav-layout", cx);
                window.render_frame(cx);
                assert!(window.find("layout-grid").visible());
                // Scroll the ScrollViewer so its scroll bar shows.
                window.scroll(
                    "layout-scroll-area",
                    gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), px(-60.))),
                    cx,
                );
                window.render_frame(cx);
                window.hover("layout-scroll", cx);
                window.render_frame(cx);
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-layout-{name}.png")))
                .unwrap();
            // Status & info page, with the copy confirmation showing.
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-nav-feedback", cx);
                window.render_frame(cx);
                window.click("copy-ip", cx);
                window.render_frame(cx);
                assert!(window.find("copy-ip-copied").visible());
                window.click("mode-cards-1", cx);
                window.render_frame(cx);
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-feedback-{name}.png")))
                .unwrap();
            // The room pop-out window on its own.
            cx.update_window(handle, |_, window, cx| window.click("popout-open", cx))
                .unwrap();
            cx.run_until_parked();
            let popout = cx
                .update(|cx| cx.windows())
                .into_iter()
                .find(|w| *w != handle)
                .expect("pop-out opened");
            cx.update_window(popout, |_, window, cx| window.render_frame(cx))
                .unwrap();
            cx.capture_screenshot(popout)
                .unwrap()
                .save(output.join(format!("gallery-popout-{name}.png")))
                .unwrap();
            cx.update_window(popout, |_, window, cx| {
                window.click("popout-title-close", cx)
            })
            .unwrap();
            cx.run_until_parked();
            // Motion pages, at rest.
            for page in [
                "page-transitions",
                "theme-transitions",
                "implicit",
                "parallax",
                "connected",
                "composition",
                "easing",
            ] {
                cx.update_window(handle, |_, window, cx| {
                    window.click(SharedString::from(format!("gallery-nav-{page}")), cx);
                    window.render_frame(cx);
                })
                .unwrap();
                cx.run_until_parked();
                cx.capture_screenshot(handle)
                    .unwrap()
                    .save(output.join(format!("gallery-{page}-{name}.png")))
                    .unwrap();
            }
            // Page transitions mid-flight, in the light theme: frames of
            // Entrance and Slide from right with motion on.
            if name == "light" {
                cx.update(|cx| cx.set_reduce_motion(false));
                for (kind, label) in [(0, "entrance"), (3, "slide")] {
                    cx.update_window(handle, |_, window, cx| {
                        window.click("gallery-nav-page-transitions", cx);
                        window.render_frame(cx);
                        window.click(
                            SharedString::from(format!("page-transition-kind-{kind}")),
                            cx,
                        );
                        window.render_frame(cx);
                        window.click("page-forward", cx);
                        window.render_frame(cx);
                    })
                    .unwrap();
                    let mut at = 0;
                    for ms in [100, 200, 300, 400] {
                        cx.advance_clock(Duration::from_millis(ms - at));
                        at = ms;
                        cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                            .unwrap();
                        cx.capture_screenshot(handle)
                            .unwrap()
                            .save(output.join(format!("gallery-motion-{label}-{ms}ms.png")))
                            .unwrap();
                    }
                    cx.advance_clock(Duration::from_millis(200));
                    cx.run_until_parked();
                }
                // Theme transitions: five squares arriving staggered, and
                // the popup coming in.
                cx.update_window(handle, |_, window, cx| {
                    window.click("gallery-nav-theme-transitions", cx);
                    window.render_frame(cx);
                    window.click("entrance-add-five", cx);
                    window.click("theme-popup-show", cx);
                    window.render_frame(cx);
                })
                .unwrap();
                let mut at = 0;
                for ms in [50, 150, 300, 600] {
                    cx.advance_clock(Duration::from_millis(ms - at));
                    at = ms;
                    cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                        .unwrap();
                    cx.capture_screenshot(handle)
                        .unwrap()
                        .save(output.join(format!("gallery-motion-theme-{ms}ms.png")))
                        .unwrap();
                }
                cx.advance_clock(Duration::from_millis(700));
                // Connected animation, Gravity: the card flying to page 2.
                cx.update_window(handle, |_, window, cx| {
                    window.click("gallery-nav-connected", cx);
                    window.render_frame(cx);
                    window.click("connected-forward", cx);
                    window.render_frame(cx);
                    window.render_frame(cx);
                })
                .unwrap();
                let mut at = 0;
                for ms in [60, 120, 200, 260] {
                    cx.advance_clock(Duration::from_millis(ms - at));
                    at = ms;
                    cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                        .unwrap();
                    cx.capture_screenshot(handle)
                        .unwrap()
                        .save(output.join(format!("gallery-motion-connected-{ms}ms.png")))
                        .unwrap();
                }
                cx.advance_clock(Duration::from_millis(300));
                cx.update_window(handle, |_, window, cx| {
                    window.click("connected-back", cx);
                    window.render_frame(cx);
                })
                .unwrap();
                cx.advance_clock(Duration::from_millis(400));
                cx.run_until_parked();
                cx.run_until_parked();
                cx.update(|cx| cx.set_reduce_motion(true));
            }
            // Navigation page.
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-nav-navigation", cx);
                window.render_frame(cx);
                window.click("nav-item-3", cx);
                window.render_frame(cx);
                window.click("selector-1", cx);
                window.render_frame(cx);
                assert!(window.find("tabs").visible());
            })
            .unwrap();
            cx.run_until_parked();
            cx.capture_screenshot(handle)
                .unwrap()
                .save(output.join(format!("gallery-navigation-{name}.png")))
                .unwrap();

            // Doc#24's pseudo-locale check: every page once with labels
            // 40 % longer, in the light theme.
            if name != "light" {
                continue;
            }
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-pseudo", cx);
                window.render_frame(cx);
            })
            .unwrap();
            for page in [
                "controls",
                "basic-input",
                "menus",
                "dialogs",
                "navigation",
                "layout",
                "feedback",
                "page-transitions",
                "theme-transitions",
                "implicit",
                "parallax",
                "connected",
                "composition",
                "easing",
                "settings",
            ] {
                cx.update_window(handle, |_, window, cx| {
                    window.click(SharedString::from(format!("gallery-nav-{page}")), cx);
                    window.render_frame(cx);
                })
                .unwrap();
                cx.run_until_parked();
                cx.capture_screenshot(handle)
                    .unwrap()
                    .save(output.join(format!("gallery-pseudo-{page}.png")))
                    .unwrap();
            }
            cx.update_window(handle, |_, window, cx| {
                window.click("gallery-pseudo", cx);
                window.render_frame(cx);
            })
            .unwrap();
        }
    }
}
