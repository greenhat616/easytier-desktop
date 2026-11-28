//! Gallery pages for the WinUI-style controls in [`crate::views::controls`]:
//! a Settings page laid out like WinUI Gallery's own, and Basic input.
//! All state is in memory; nothing reaches a host or the product's settings.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, SharedString, Styled as _, TestSupportExt as _, Window,
    base::CheckboxState,
    component::{
        ActiveTheme as _, Size, StyledExt as _,
        button::ButtonVariant,
        input::InputState,
        slider::{SliderState, SliderValue},
    },
    div, px,
};

use super::{Gallery, Page, section};
use crate::views::{
    controls::{
        combo_box, dropdown_button, fluent_checkbox, fluent_radio_group, fluent_slider, flyout,
        flyout_item, number_box, settings_card, settings_expander, settings_expander_item,
        split_button, toggle_button,
    },
    dialogs::{DialogButtons, DialogResult, content_dialog, flyout_panel, teaching_tip},
    feedback::{Status, TOOLTIP_SHOW_DELAY, copy_button, fluent_tooltip, status_badge},
    layout::{expander, scroll_viewer},
    menus::{BarCommand, MenuCheck, MenuEntry, MenuHandler, MenuItem, command_bar, menu_flyout},
    navigation::{
        IndexHandler, Tab, breadcrumb_bar, nav_selection_indicator, nav_view_item, selector_bar,
        tab_view,
    },
    progress::{CardChoice, ProgressState, empty_state, progress_bar, selection_cards},
    ui::{BtnStyle, action_button, settings_switch},
};

/// Which drop-down is open; WinUI keeps at most one light-dismiss popup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Popup {
    AppTheme,
    NavStyle,
    DropDown,
    Split,
    Combo,
    Menu,
    Context,
    Overflow,
    Flyout,
}

pub(super) struct DemoState {
    popup: Option<Popup>,
    app_theme: usize,
    nav_style: usize,
    sound: bool,
    spatial: bool,
    expanded: [bool; 2],
    checks: [CheckboxState; 2],
    radio: usize,
    toggled: bool,
    split_color: usize,
    combo: usize,
    slider: Entity<SliderState>,
    slider_disabled: Entity<SliderState>,
    number: Entity<InputState>,
    last: SharedString,
    context_at: Option<gpui_kit::Point<gpui_kit::Pixels>>,
    submenu: bool,
    show_hidden: bool,
    sort: usize,
    preview: bool,
    dialog_open: bool,
    dialog_result: SharedString,
    tip_open: bool,
    nav_selected: usize,
    nav_prev: usize,
    nav_expanded: bool,
    crumbs: usize,
    selector: usize,
    tabs: Vec<usize>,
    tab_selected: usize,
    next_tab: usize,
    layout_open: [bool; 2],
    mode_choice: usize,
    /// The room pop-out, while it is open; one at a time.
    pub(super) popout: Option<gpui_kit::AnyWindowHandle>,
    stack_horizontal: bool,
    stack_spacing: Entity<SliderState>,
    grid_columns: Entity<SliderState>,
    grid_rows: Entity<SliderState>,
}

impl DemoState {
    pub(super) fn new(window: &mut Window, cx: &mut Context<Gallery>) -> Self {
        let slider = cx.new(|_| {
            SliderState::new()
                .min(0.)
                .max(100.)
                .step(1.)
                .default_value(SliderValue::Single(40.))
        });
        cx.observe(&slider, |_, _, cx| cx.notify()).detach();
        let slider_disabled = cx.new(|_| {
            SliderState::new()
                .min(0.)
                .max(100.)
                .default_value(SliderValue::Single(60.))
        });
        let stack_spacing = spacing_slider(8., cx);
        let grid_columns = spacing_slider(8., cx);
        let grid_rows = spacing_slider(8., cx);
        let number = cx.new(|cx| InputState::new(window, cx).placeholder("0"));
        number.update(cx, |input, cx| input.set_value("12", window, cx));
        Self {
            popup: None,
            app_theme: 0,
            nav_style: 0,
            sound: false,
            spatial: true,
            expanded: [true, false],
            checks: [CheckboxState::Checked, CheckboxState::Indeterminate],
            radio: 0,
            toggled: false,
            split_color: 0,
            combo: 0,
            slider,
            slider_disabled,
            number,
            last: "None".into(),
            context_at: None,
            submenu: false,
            show_hidden: true,
            sort: 0,
            preview: false,
            dialog_open: false,
            dialog_result: "None".into(),
            tip_open: false,
            nav_selected: 0,
            nav_prev: 0,
            nav_expanded: true,
            crumbs: CRUMBS.len(),
            selector: 0,
            tabs: vec![0, 1, 2],
            tab_selected: 0,
            next_tab: 3,
            layout_open: [true, false],
            mode_choice: 0,
            popout: None,
            stack_horizontal: false,
            stack_spacing,
            grid_columns,
            grid_rows,
        }
    }
}

#[cfg(test)]
impl Gallery {
    pub(super) fn demo_app_theme(&self) -> usize {
        self.demo.app_theme
    }
    pub(super) fn demo_number(&self, cx: &App) -> SharedString {
        self.demo.number.read(cx).value()
    }
    pub(super) fn demo_last(&self) -> SharedString {
        self.demo.last.clone()
    }
    pub(super) fn demo_dialog_result(&self) -> SharedString {
        self.demo.dialog_result.clone()
    }
    pub(super) fn demo_mode(&self) -> usize {
        self.demo.mode_choice
    }
    pub(super) fn demo_layout(&self) -> [bool; 2] {
        self.demo.layout_open
    }
    pub(super) fn demo_nav(&self) -> (usize, usize, usize, usize) {
        (
            self.demo.nav_selected,
            self.demo.crumbs,
            self.demo.selector,
            self.demo.tabs.len(),
        )
    }
}

const APP_THEMES: &[&str] = &["Use system setting", "Light", "Dark"];
const NAV_STYLES: &[&str] = &["Left", "Top"];
const COLORS: &[&str] = &["Blue", "Green", "Red", "Yellow"];
const SPLIT_COLORS: &[&str] = &["Red", "Green", "Blue"];

/// BodyStrongTextBlockStyle (14/20 SemiBold) group header, spaced as WinUI
/// Gallery's settings page (margin 1,30,0,6); cards are 4 px apart.
fn group_header(text: &'static str, cx: &App) -> AnyElement {
    div()
        .mt(px(30.))
        .mb(px(6.))
        .ml(px(1.))
        .text_size(px(14.))
        .line_height(px(20.))
        .font_semibold()
        .text_color(cx.theme().foreground)
        .child(text)
        .into_any_element()
}

fn popup_toggle(
    popup: Popup,
    cx: &mut Context<Gallery>,
) -> impl Fn(&gpui_kit::ClickEvent, &mut Window, &mut App) + 'static {
    cx.listener(move |this, _, _, cx| {
        this.demo.popup = if this.demo.popup == Some(popup) {
            None
        } else {
            Some(popup)
        };
        cx.notify();
    })
}

fn dismiss(cx: &mut Context<Gallery>) -> impl Fn(&mut Window, &mut App) + 'static {
    let view = cx.entity().downgrade();
    move |_, cx| {
        view.update(cx, |this, cx| {
            this.demo.popup = None;
            this.demo.submenu = false;
            cx.notify();
        })
        .ok();
    }
}

fn select(
    cx: &mut Context<Gallery>,
    apply: impl Fn(&mut DemoState, usize) + 'static,
) -> impl Fn(usize, &mut Window, &mut App) + 'static {
    let view = cx.entity().downgrade();
    move |ix, _, cx| {
        view.update(cx, |this, cx| {
            apply(&mut this.demo, ix);
            this.demo.popup = None;
            cx.notify();
        })
        .ok();
    }
}

#[inline(never)]
pub(super) fn settings_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    let demo = &view.demo;
    let app_theme = combo_box(
        "settings-app-theme",
        None,
        APP_THEMES,
        demo.app_theme,
        demo.popup == Some(Popup::AppTheme),
        200.,
        popup_toggle(Popup::AppTheme, cx),
        select(cx, |d, ix| d.app_theme = ix),
        dismiss(cx),
        cx,
    );
    let nav_style = combo_box(
        "settings-nav-style",
        None,
        NAV_STYLES,
        demo.nav_style,
        demo.popup == Some(Popup::NavStyle),
        120.,
        popup_toggle(Popup::NavStyle, cx),
        select(cx, |d, ix| d.nav_style = ix),
        dismiss(cx),
        cx,
    );
    let sound_switch = settings_switch(
        "settings-sound-switch",
        if demo.sound { "On" } else { "Off" },
        demo.sound,
        false,
        cx.listener(|this, on: &bool, _, cx| {
            this.demo.sound = *on;
            cx.notify();
        }),
    );
    let spatial_switch = settings_switch(
        "settings-spatial-switch",
        if demo.spatial { "On" } else { "Off" },
        demo.spatial,
        !demo.sound,
        cx.listener(|this, on: &bool, _, cx| {
            this.demo.spatial = *on;
            cx.notify();
        }),
    );
    let sound = settings_expander(
        "settings-sound",
        Some("fluent/speaker-2.svg"),
        "Sound",
        Some("Controls provide audible feedback"),
        Some(sound_switch),
        demo.expanded[0],
        Rc::new(cx.listener(|this, _, _, cx| {
            this.demo.expanded[0] = !this.demo.expanded[0];
            cx.notify();
        })),
        vec![settings_expander_item(
            "settings-spatial",
            "Spatial audio",
            Some("Available when sound is on"),
            Some(spatial_switch),
            cx,
        )],
        cx,
    );
    let manage = div()
        .flex()
        .flex_row()
        .gap(px(8.))
        .child(action_button(
            "settings-clear-recents",
            "Clear recents",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(|this, _, _, cx| {
                this.clicks += 1;
                cx.notify();
            }),
        ))
        .child(action_button(
            "settings-remove-favorites",
            "Remove favorites",
            {
                let mut style = BtnStyle::new(ButtonVariant::Default, Size::Medium);
                style.disabled = true;
                style
            },
            |_, _, _| {},
        ))
        .into_any_element();
    let about = settings_expander(
        "settings-about",
        Some("fluent/info.svg"),
        "Fluent gallery",
        Some("EasyTier Desktop component specimens"),
        Some(
            div()
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(crate::theme::text_secondary(cx))
                .child(env!("CARGO_PKG_VERSION"))
                .into_any_element(),
        ),
        demo.expanded[1],
        Rc::new(cx.listener(|this, _, _, cx| {
            this.demo.expanded[1] = !this.demo.expanded[1];
            cx.notify();
        })),
        vec![
            settings_expander_item(
                "settings-about-renderer",
                "Renderer",
                Some("GPUI with gpui-kit 0.11"),
                None,
                cx,
            ),
            settings_expander_item(
                "settings-about-data",
                "Data",
                Some("Session only; no host, profile or preference file is opened"),
                None,
                cx,
            ),
        ],
        cx,
    );
    let open_basic = settings_card(
        "settings-open-basic-input",
        Some("fluent/grid.svg"),
        "Basic input",
        Some("A clickable SettingsCard: opens the Basic input page"),
        None,
        Some(Rc::new(cx.listener(|this, _, _, cx| {
            this.page = Page::BasicInput;
            cx.notify();
        }))),
        cx,
    );
    let cards = |items: Vec<AnyElement>| {
        div()
            .flex()
            .flex_col()
            .gap(px(4.))
            .children(items)
            .into_any_element()
    };
    vec![
        div()
            .max_w(px(1000.))
            .flex()
            .flex_col()
            .child(group_header("Appearance & behavior", cx))
            .child(cards(vec![
                settings_card(
                    "settings-app-theme-card",
                    Some("fluent/color.svg"),
                    "App theme",
                    Some("Select which app theme to display"),
                    Some(app_theme),
                    None,
                    cx,
                ),
                settings_card(
                    "settings-nav-style-card",
                    Some("fluent/panel-left.svg"),
                    "Navigation style",
                    None,
                    Some(nav_style),
                    None,
                    cx,
                ),
                sound,
                settings_card(
                    "settings-manage",
                    Some("fluent/grid.svg"),
                    "Manage samples",
                    Some("Clear your recent or favorite samples"),
                    Some(manage),
                    None,
                    cx,
                ),
            ]))
            .child(group_header("About", cx))
            .child(cards(vec![about, open_basic]))
            .into_any_element(),
    ]
}

#[inline(never)]
pub(super) fn basic_input_page(
    view: &Gallery,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> Vec<AnyElement> {
    let demo = &view.demo;
    let note = |text: SharedString, cx: &App| {
        div()
            .text_size(px(12.))
            .line_height(px(16.))
            .text_color(crate::theme::text_secondary(cx))
            .child(text)
            .into_any_element()
    };
    let row = |items: Vec<AnyElement>| {
        div()
            .flex()
            .flex_row()
            .flex_wrap()
            .items_start()
            .gap(px(16.))
            .children(items)
            .into_any_element()
    };

    // Buttons with a toggle or a drop-down.
    let toggle = toggle_button(
        "basic-toggle",
        if demo.toggled { "On" } else { "Off" },
        demo.toggled,
        false,
        cx.listener(|this, _, _, cx| {
            this.demo.toggled = !this.demo.toggled;
            cx.notify();
        }),
    );
    let toggle_disabled = toggle_button(
        "basic-toggle-disabled",
        "Disabled",
        true,
        true,
        |_, _, _| {},
    );
    let mail = ["Send", "Reply", "Reply all"];
    let dropdown_menu = Some({
        let pick = select(cx, |d, ix| {
            d.last = SharedString::from(["Send", "Reply", "Reply all"][ix])
        });
        let pick = Rc::new(pick);
        let items = mail
            .iter()
            .enumerate()
            .map(|(ix, label)| {
                let pick = pick.clone();
                flyout_item(
                    SharedString::from(format!("basic-dropdown-item-{ix}")),
                    *label,
                    false,
                    move |_, window, cx| pick(ix, window, cx),
                    cx,
                )
            })
            .collect();
        flyout(
            "basic-dropdown-menu",
            demo.popup == Some(Popup::DropDown),
            120.,
            items,
            dismiss(cx),
            cx,
        )
    });
    let dropdown = dropdown_button(
        "basic-dropdown",
        "Email",
        demo.popup == Some(Popup::DropDown),
        popup_toggle(Popup::DropDown, cx),
        dropdown_menu,
        cx,
    );
    let split_menu = Some({
        let pick = Rc::new(select(cx, |d, ix| d.split_color = ix));
        let items = SPLIT_COLORS
            .iter()
            .enumerate()
            .map(|(ix, label)| {
                let pick = pick.clone();
                flyout_item(
                    SharedString::from(format!("basic-split-item-{ix}")),
                    *label,
                    ix == demo.split_color,
                    move |_, window, cx| pick(ix, window, cx),
                    cx,
                )
            })
            .collect();
        flyout(
            "basic-split-menu",
            demo.popup == Some(Popup::Split),
            120.,
            items,
            dismiss(cx),
            cx,
        )
    });
    let split = split_button(
        "basic-split",
        "Apply color",
        demo.popup == Some(Popup::Split),
        cx.listener(|this, _, _, cx| {
            this.demo.last =
                SharedString::from(format!("Applied {}", SPLIT_COLORS[this.demo.split_color]));
            cx.notify();
        }),
        popup_toggle(Popup::Split, cx),
        split_menu,
        cx,
    );

    // CheckBox, two-state and three-state, plus disabled.
    let two_state = fluent_checkbox(
        "basic-check-two",
        "Two-state CheckBox",
        demo.checks[0],
        false,
        cx.listener(|this, next: &CheckboxState, _, cx| {
            this.demo.checks[0] = *next;
            cx.notify();
        }),
        cx,
    );
    let three_state = fluent_checkbox(
        "basic-check-three",
        "Three-state CheckBox",
        demo.checks[1],
        false,
        cx.listener(|this, _: &CheckboxState, _, cx| {
            this.demo.checks[1] = match this.demo.checks[1] {
                CheckboxState::Unchecked => CheckboxState::Checked,
                CheckboxState::Checked => CheckboxState::Indeterminate,
                CheckboxState::Indeterminate => CheckboxState::Unchecked,
            };
            cx.notify();
        }),
        cx,
    );
    let checks_disabled: Vec<AnyElement> = [
        (
            "basic-check-d0",
            "Disabled unchecked",
            CheckboxState::Unchecked,
        ),
        ("basic-check-d1", "Disabled checked", CheckboxState::Checked),
        (
            "basic-check-d2",
            "Disabled indeterminate",
            CheckboxState::Indeterminate,
        ),
    ]
    .into_iter()
    .map(|(id, label, state)| fluent_checkbox(id, label, state, true, |_, _, _| {}, cx))
    .collect();

    let radios = fluent_radio_group(
        "basic-radio",
        "Background",
        &["Green", "Yellow", "White"],
        demo.radio,
        false,
        cx.listener(|this, ix: &usize, _, cx| {
            this.demo.radio = *ix;
            cx.notify();
        }),
        cx,
    );
    let radios_disabled = fluent_radio_group(
        "basic-radio-disabled",
        "Disabled",
        &["Option 1", "Option 2"],
        0,
        true,
        |_, _, _| {},
        cx,
    );

    let combo = combo_box(
        "basic-combo",
        Some("Colors"),
        COLORS,
        demo.combo,
        demo.popup == Some(Popup::Combo),
        200.,
        popup_toggle(Popup::Combo, cx),
        select(cx, |d, ix| d.combo = ix),
        dismiss(cx),
        cx,
    );

    let slider_value = demo.slider.read(cx).value().end();
    let slider = fluent_slider("basic-slider", "Slider", &demo.slider, false, window, cx);
    let slider_disabled = fluent_slider(
        "basic-slider-disabled",
        "Disabled slider",
        &demo.slider_disabled,
        true,
        window,
        cx,
    );

    let number_state = demo.number.clone();
    let number = number_box(
        "basic-number",
        "Enter an integer",
        &demo.number,
        move |delta, window, cx| {
            let current = number_state
                .read(cx)
                .value()
                .trim()
                .parse::<f64>()
                .unwrap_or(0.);
            let next = SharedString::from(format!("{}", current + delta));
            number_state.update(cx, |input, cx| input.set_value(next, window, cx));
        },
        cx,
    );

    vec![
        section(
            "ToggleButton · DropDownButton · SplitButton",
            [
                row(vec![toggle, toggle_disabled, dropdown, split]),
                note(
                    SharedString::from(format!("Last command: {}", demo.last)),
                    cx,
                ),
            ],
            cx,
        ),
        section(
            "CheckBox",
            [row(vec![two_state, three_state]), row(checks_disabled)],
            cx,
        ),
        section("RadioButtons", [row(vec![radios, radios_disabled])], cx),
        section("ComboBox", [combo], cx),
        section(
            "Slider",
            [
                row(vec![
                    slider,
                    // Centred on the 32 px slider row.
                    div()
                        .h(px(32.))
                        .flex()
                        .items_center()
                        .child(note(SharedString::from(format!("{slider_value:.0}")), cx))
                        .into_any_element(),
                ]),
                slider_disabled,
            ],
            cx,
        ),
        section("NumberBox", [number], cx),
    ]
}

/// Records a command from a menu or the command bar and closes any popup.
fn command(label: &'static str, cx: &mut Context<Gallery>) -> MenuHandler {
    Rc::new(cx.listener(move |this, _: &gpui_kit::ClickEvent, _, cx| {
        this.demo.last = SharedString::from(label);
        this.demo.popup = None;
        this.demo.submenu = false;
        cx.notify();
    }))
}

const SORTS: [&str; 3] = ["Name", "Date modified", "Size"];

#[inline(never)]
pub(super) fn menus_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    let demo = &view.demo;
    let note = div()
        .text_size(px(12.))
        .line_height(px(16.))
        .text_color(crate::theme::text_secondary(cx))
        .child(SharedString::from(format!("Last command: {}", demo.last)))
        .into_any_element();

    // MenuFlyout from a button: icons, accelerators, a toggle item, a
    // submenu of radio items, separators and a disabled item.
    let menu = Some({
        let sort_items = SORTS
            .iter()
            .enumerate()
            .map(|(ix, label)| {
                MenuEntry::Item(
                    MenuItem::new(SharedString::from(format!("menu-sort-{ix}")), *label)
                        .check(MenuCheck::Radio(ix == demo.sort))
                        .on_click(cx.listener(move |this, _: &gpui_kit::ClickEvent, _, cx| {
                            this.demo.sort = ix;
                            this.demo.last = SharedString::from(format!("Sort by {}", SORTS[ix]));
                            this.demo.popup = None;
                            this.demo.submenu = false;
                            cx.notify();
                        })),
                )
            })
            .collect();
        let open = command("Open", cx);
        let save = command("Save", cx);
        let entries = vec![
            MenuEntry::Item(
                MenuItem::new("menu-open", "Open")
                    .icon("fluent/folder.svg")
                    .accelerator("Ctrl+O")
                    .on_click(move |e, w, cx| open(e, w, cx)),
            ),
            MenuEntry::Item(
                MenuItem::new("menu-save", "Save")
                    .icon("fluent/document.svg")
                    .accelerator("Ctrl+S")
                    .on_click(move |e, w, cx| save(e, w, cx)),
            ),
            MenuEntry::Separator,
            MenuEntry::Item(
                MenuItem::new("menu-hidden", "Show hidden items")
                    .check(MenuCheck::Toggle(demo.show_hidden))
                    .on_click(cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                        this.demo.show_hidden = !this.demo.show_hidden;
                        this.demo.last = "Toggle hidden items".into();
                        this.demo.popup = None;
                        cx.notify();
                    })),
            ),
            MenuEntry::Item(
                MenuItem::new("menu-sort", "Sort by")
                    .submenu(demo.submenu, sort_items)
                    .on_click(cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                        this.demo.submenu = !this.demo.submenu;
                        cx.notify();
                    })),
            ),
            MenuEntry::Separator,
            MenuEntry::Item(
                MenuItem::new("menu-delete", "Delete")
                    .icon("fluent/delete.svg")
                    .accelerator("Del")
                    .disabled(true),
            ),
        ];
        menu_flyout(
            "menu-flyout",
            demo.popup == Some(Popup::Menu),
            entries,
            None,
            dismiss(cx),
            cx,
        )
    });
    let menu_button = dropdown_button(
        "menu-button",
        "Options",
        demo.popup == Some(Popup::Menu),
        popup_toggle(Popup::Menu, cx),
        menu,
        cx,
    );

    // Context menu: the same MenuFlyout, opened at the pointer.
    let context = demo.context_at.map(|at| {
        let cut = command("Cut", cx);
        let copy = command("Copy", cx);
        let paste = command("Paste", cx);
        menu_flyout(
            "context-menu",
            demo.popup == Some(Popup::Context),
            vec![
                MenuEntry::Item(
                    MenuItem::new("context-cut", "Cut")
                        .accelerator("Ctrl+X")
                        .on_click(move |e, w, cx| cut(e, w, cx)),
                ),
                MenuEntry::Item(
                    MenuItem::new("context-copy", "Copy")
                        .icon("fluent/copy.svg")
                        .accelerator("Ctrl+C")
                        .on_click(move |e, w, cx| copy(e, w, cx)),
                ),
                MenuEntry::Item(
                    MenuItem::new("context-paste", "Paste")
                        .accelerator("Ctrl+V")
                        .on_click(move |e, w, cx| paste(e, w, cx)),
                ),
            ],
            Some(at),
            dismiss(cx),
            cx,
        )
    });
    let target = div()
        .id("context-target")
        .test_support()
        .h(px(96.))
        .w(px(320.))
        .rounded(px(4.))
        .border_1()
        .border_color(crate::theme::control_stroke(cx))
        .flex()
        .items_center()
        .justify_center()
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(crate::theme::text_secondary(cx))
        .child("Right-click here")
        .on_mouse_down(
            gpui_kit::MouseButton::Right,
            cx.listener(|this, e: &gpui_kit::MouseDownEvent, _, cx| {
                this.demo.context_at = Some(e.position);
                this.demo.popup = Some(Popup::Context);
                cx.notify();
            }),
        )
        .into_any_element();

    // CommandBar: primary commands, a toggle and the overflow menu.
    let overflow = Some({
        let settings = command("Settings", cx);
        let refresh = command("Refresh", cx);
        menu_flyout(
            "bar-overflow",
            demo.popup == Some(Popup::Overflow),
            vec![
                MenuEntry::Item(
                    MenuItem::new("bar-settings", "Settings")
                        .icon("fluent/settings.svg")
                        .on_click(move |e, w, cx| settings(e, w, cx)),
                ),
                MenuEntry::Item(
                    MenuItem::new("bar-refresh", "Refresh")
                        .icon("fluent/arrow-clockwise.svg")
                        .accelerator("F5")
                        .on_click(move |e, w, cx| refresh(e, w, cx)),
                ),
            ],
            None,
            dismiss(cx),
            cx,
        )
    });
    let button = |id, label, icon, cx: &mut Context<Gallery>| BarCommand::Button {
        id,
        label,
        icon,
        toggled: None,
        on_click: command(label, cx),
    };
    let primary = vec![
        button("bar-add", "Add", "fluent/add.svg", cx),
        button("bar-edit", "Edit", "fluent/edit.svg", cx),
        button("bar-copy", "Copy", "fluent/copy.svg", cx),
        BarCommand::Separator,
        BarCommand::Button {
            id: "bar-preview",
            label: "Preview",
            icon: "fluent/eye.svg",
            toggled: Some(demo.preview),
            on_click: Rc::new(cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                this.demo.preview = !this.demo.preview;
                this.demo.last = "Toggle preview".into();
                cx.notify();
            })),
        },
    ];
    let bar = command_bar(
        "command-bar",
        primary,
        demo.popup == Some(Popup::Overflow),
        popup_toggle(Popup::Overflow, cx),
        overflow,
        cx,
    );

    vec![
        section("MenuFlyout", [menu_button, note], cx),
        section("Context menu", std::iter::once(target).chain(context), cx),
        section("CommandBar", [bar], cx),
    ]
}

#[inline(never)]
pub(super) fn dialogs_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    let demo = &view.demo;
    let note = |text: SharedString, cx: &App| {
        div()
            .text_size(px(12.))
            .line_height(px(16.))
            .text_color(crate::theme::text_secondary(cx))
            .child(text)
            .into_any_element()
    };

    // ContentDialog: Save is the default button.
    let dialog = Some({
        let view = cx.entity().downgrade();
        content_dialog(
            "dialog",
            demo.dialog_open,
            "Save your work?",
            div()
                .child("You have unsaved changes to this profile. Save them before closing?")
                .into_any_element(),
            DialogButtons {
                primary: Some("Save"),
                secondary: Some("Don't save"),
                close: "Cancel",
                default: DialogResult::Primary,
            },
            Rc::new(move |result, _, cx| {
                view.update(cx, |this, cx| {
                    this.demo.dialog_open = false;
                    this.demo.dialog_result = SharedString::from(match result {
                        DialogResult::Primary => "Save",
                        DialogResult::Secondary => "Don't save",
                        DialogResult::None => "Cancel",
                    });
                    cx.notify();
                })
                .ok();
            }),
        )
    });
    let open_dialog = action_button(
        "dialog-open",
        "Show dialog",
        BtnStyle::new(ButtonVariant::Default, Size::Medium),
        cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
            this.demo.dialog_open = true;
            cx.notify();
        }),
    );
    let dialog_note = note(
        SharedString::from(format!("Dialog result: {}", demo.dialog_result)),
        cx,
    );

    // Flyout: arbitrary content in a light-dismiss popup.
    let flyout = Some({
        let confirm = cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
            this.demo.popup = None;
            this.demo.last = "Cleared recents".into();
            cx.notify();
        });
        flyout_panel(
            "flyout",
            demo.popup == Some(Popup::Flyout),
            div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .items_start()
                .child("Recent samples will be removed. Continue?")
                .child(action_button(
                    "flyout-confirm",
                    "Clear recents",
                    BtnStyle::new(ButtonVariant::Default, Size::Medium),
                    confirm,
                ))
                .into_any_element(),
            dismiss(cx),
            cx,
        )
    });
    let flyout_button = div()
        .flex()
        .flex_col()
        .items_start()
        .child(action_button(
            "flyout-open",
            "Clear recents…",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            popup_toggle(Popup::Flyout, cx),
        ))
        .children(flyout)
        .into_any_element();

    // TeachingTip below its target; it stays open until closed.
    let tip = demo.tip_open.then(|| {
        let view = cx.entity().downgrade();
        let got_it = cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
            this.demo.tip_open = false;
            cx.notify();
        });
        teaching_tip(
            "tip",
            "Pin your favorite samples",
            "Pinned samples appear first on the home page.",
            Some(action_button(
                "tip-action",
                "Got it",
                BtnStyle::new(ButtonVariant::Primary, Size::Medium),
                got_it,
            )),
            move |_, cx| {
                view.update(cx, |this, cx| {
                    this.demo.tip_open = false;
                    cx.notify();
                })
                .ok();
            },
            cx,
        )
    });
    let tip_target = div()
        .flex()
        .flex_col()
        .items_start()
        .child(action_button(
            "tip-target",
            "Show tip",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                this.demo.tip_open = !this.demo.tip_open;
                cx.notify();
            }),
        ))
        .children(tip)
        .into_any_element();

    vec![
        section(
            "ContentDialog",
            std::iter::once(div().flex().child(open_dialog).into_any_element())
                .chain(std::iter::once(dialog_note))
                .chain(dialog),
            cx,
        ),
        section("Flyout", [flyout_button], cx),
        section("TeachingTip", [tip_target], cx),
    ]
}

const NAV_ITEMS: [(&str, &str, Option<&str>, usize); 6] = [
    ("Home", "fluent/globe.svg", None, 0),
    ("Collections", "fluent/grid.svg", Some("group"), 0),
    ("Recent", "fluent/document.svg", Some("child"), 1),
    ("Favorites", "fluent/folder.svg", Some("child"), 1),
    ("People", "fluent/person.svg", None, 0),
    ("Settings", "fluent/settings.svg", None, 0),
];
const CRUMBS: [&str; 4] = ["Home", "Documents", "Design", "Specs"];
const SELECTOR: [&str; 3] = ["Recent", "Shared", "Favorites"];

#[inline(never)]
pub(super) fn navigation_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    let demo = &view.demo;

    // NavigationView pane with an expandable group.
    // Where an item sits among those shown; a hidden child's indicator
    // stays on its group, as in WinUI.
    let shown = |item: usize| {
        let hidden = |i: usize| NAV_ITEMS[i].2 == Some("child") && !demo.nav_expanded;
        if hidden(item) {
            1
        } else {
            (0..item).filter(|&i| !hidden(i)).count()
        }
    };
    let mut pane = div()
        .id("nav-pane")
        .relative()
        .w(px(320.))
        .py(px(4.))
        .flex()
        .flex_col();
    for (ix, (label, icon, kind, depth)) in NAV_ITEMS.iter().enumerate() {
        if kind == &Some("child") && !demo.nav_expanded {
            continue;
        }
        let is_group = kind == &Some("group");
        let on_click = {
            let view = cx.entity().downgrade();
            move |_: &mut Window, cx: &mut App| {
                view.update(cx, |this, cx| {
                    if is_group {
                        this.demo.nav_expanded = !this.demo.nav_expanded;
                    } else {
                        this.demo.nav_prev = this.demo.nav_selected;
                        this.demo.nav_selected = ix;
                    }
                    cx.notify();
                })
                .ok();
            }
        };
        pane = pane.child(nav_view_item(
            SharedString::from(format!("nav-item-{ix}")),
            Some(icon),
            label,
            *depth,
            !is_group && demo.nav_selected == ix,
            is_group.then_some(demo.nav_expanded),
            on_click,
            cx,
        ));
    }
    let pane = pane.child(nav_selection_indicator(
        "nav-indicator",
        4.,
        shown(demo.nav_prev),
        shown(demo.nav_selected),
        cx,
    ));
    let nav = div()
        .flex()
        .flex_row()
        .gap(px(16.))
        .child(pane)
        .child(
            div()
                .text_size(px(14.))
                .line_height(px(20.))
                .child(SharedString::from(format!(
                    "Selected: {}",
                    NAV_ITEMS[demo.nav_selected].0
                ))),
        )
        .into_any_element();

    let crumbs = breadcrumb_bar(
        "crumbs",
        &CRUMBS[..demo.crumbs],
        index_handler(cx, |this, ix| this.demo.crumbs = ix + 1),
        cx,
    );
    let reset_crumbs = action_button(
        "crumbs-reset",
        "Reset path",
        BtnStyle::new(ButtonVariant::Default, Size::Medium),
        cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
            this.demo.crumbs = CRUMBS.len();
            cx.notify();
        }),
    );

    let selector = selector_bar(
        "selector",
        &SELECTOR,
        demo.selector,
        index_handler(cx, |this, ix| this.demo.selector = ix),
        cx,
    );

    let tabs: Vec<Tab> = demo
        .tabs
        .iter()
        .map(|n| Tab {
            label: TAB_NAMES[n % TAB_NAMES.len()],
            icon: "fluent/document.svg",
        })
        .collect();
    let content = SharedString::from(match demo.tabs.get(demo.tab_selected) {
        Some(n) => format!("Contents of {}", TAB_NAMES[n % TAB_NAMES.len()]),
        None => "No open documents".to_owned(),
    });
    let tab_view = tab_view(
        "tabs",
        &tabs,
        demo.tab_selected,
        index_handler(cx, |this, ix| this.demo.tab_selected = ix),
        index_handler(cx, |this, ix| {
            if ix < this.demo.tabs.len() {
                this.demo.tabs.remove(ix);
            }
            let last = this.demo.tabs.len().saturating_sub(1);
            this.demo.tab_selected = this.demo.tab_selected.min(last);
        }),
        {
            let view = cx.entity().downgrade();
            move |_, cx| {
                view.update(cx, |this, cx| {
                    let next = this.demo.next_tab;
                    this.demo.next_tab += 1;
                    this.demo.tabs.push(next);
                    this.demo.tab_selected = this.demo.tabs.len() - 1;
                    cx.notify();
                })
                .ok();
            }
        },
        div().child(content).into_any_element(),
        cx,
    );

    vec![
        section("NavigationView", [nav], cx),
        section(
            "BreadcrumbBar",
            [crumbs, div().flex().child(reset_crumbs).into_any_element()],
            cx,
        ),
        section("SelectorBar", [selector], cx),
        section("TabView", [tab_view], cx),
    ]
}

const TAB_NAMES: [&str; 5] = ["Document 1", "Document 2", "Document 3", "Notes", "Draft"];

/// An index callback that updates the gallery's demo state and redraws.
fn index_handler(
    cx: &mut Context<Gallery>,
    update: impl Fn(&mut Gallery, usize) + 'static,
) -> IndexHandler {
    let view = cx.entity().downgrade();
    Rc::new(move |ix, _, cx| {
        view.update(cx, |this, cx| {
            update(this, ix);
            cx.notify();
        })
        .ok();
    })
}

/// The four squares of WinUI Gallery's StackPanel and Grid samples
/// (StackPanelPage.xaml, GridPage.xaml: Red, Blue, Green, Yellow).
const SAMPLE_FILLS: [u32; 4] = [0xFF0000, 0x0000FF, 0x008000, 0xFFFF00];

/// A WinUI Slider with its Header above it: 14/20 text, 4 px below
/// (SliderHeaderThemeMargin 0,0,0,4, Slider_themeresources.xaml).
fn headed(header: &'static str, slider: AnyElement) -> AnyElement {
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(div().text_size(px(14.)).line_height(px(20.)).child(header))
        .child(slider)
        .into_any_element()
}

fn spacing_slider(value: f32, cx: &mut Context<Gallery>) -> Entity<SliderState> {
    // WinUI Gallery's spacing sliders: 0–16 in steps of 1, starting at 8.
    let state = cx.new(|_| {
        SliderState::new()
            .min(0.)
            .max(16.)
            .step(1.)
            .default_value(SliderValue::Single(value))
    });
    cx.observe(&state, |_, _, cx| cx.notify()).detach();
    state
}

#[inline(never)]
pub(super) fn layout_page(
    view: &Gallery,
    window: &mut Window,
    cx: &mut Context<Gallery>,
) -> Vec<AnyElement> {
    let demo = &view.demo;
    let fg = cx.theme().foreground;
    let toggle = |ix: usize, cx: &mut Context<Gallery>| -> crate::views::controls::Handler {
        Rc::new(cx.listener(move |this, _, _, cx| {
            this.demo.layout_open[ix] = !this.demo.layout_open[ix];
            cx.notify();
        }))
    };
    let expanders = div()
        .flex()
        .flex_col()
        .gap(px(8.))
        .w(px(480.))
        .child(expander(
            "layout-expander",
            "This text is in the header",
            div().child("This is in the content").into_any_element(),
            demo.layout_open[0],
            toggle(0, cx),
            cx,
        ))
        .child(expander(
            "layout-expander-2",
            "Expander with a longer body",
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child("The content grows with what it holds.")
                .child("Closed, only the header shows.")
                .into_any_element(),
            demo.layout_open[1],
            toggle(1, cx),
            cx,
        ))
        .into_any_element();

    // StackPanelPage.xaml: 40x40 squares.
    let square = |fill: u32| div().size(px(40.)).flex_shrink_0().bg(gpui_kit::rgb(fill));
    let stack_spacing = demo.stack_spacing.read(cx).value().end();
    let mut stack = div()
        .id("layout-stack")
        .test_support()
        .flex()
        .gap(px(stack_spacing));
    stack = if demo.stack_horizontal {
        stack.flex_row()
    } else {
        stack.flex_col()
    };
    let stack = stack.children(SAMPLE_FILLS.map(square));
    let orientation = fluent_radio_group(
        "layout-orientation",
        "Orientation",
        &["Horizontal", "Vertical"],
        if demo.stack_horizontal { 0 } else { 1 },
        false,
        cx.listener(|this, ix: &usize, _, cx| {
            this.demo.stack_horizontal = *ix == 0;
            cx.notify();
        }),
        cx,
    );
    let stack_slider = fluent_slider(
        "layout-stack-spacing",
        "Spacing",
        &demo.stack_spacing,
        false,
        window,
        cx,
    );
    let stack_row = div()
        .flex()
        .flex_row()
        .gap(px(48.))
        .child(div().w(px(240.)).child(stack))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .w(px(240.))
                .child(orientation)
                .child(headed("Spacing", stack_slider))
                .child(
                    div()
                        .text_size(px(14.))
                        .line_height(px(20.))
                        .child(SharedString::from(format!("Spacing: {stack_spacing:.0}"))),
                ),
        )
        .into_any_element();

    let col = demo.grid_columns.read(cx).value().end();
    let row = demo.grid_rows.read(cx).value().end();
    // GridPage.xaml: a 240x160 grid of 3 columns and 3 rows with 50x50
    // squares in four of its cells.
    let cell = |fill: Option<u32>| {
        let c = div().h(px(50.)).w(px(50.));
        match fill {
            Some(f) => c.bg(gpui_kit::rgb(f)),
            None => c,
        }
    };
    let grid = div()
        .id("layout-grid")
        .test_support()
        .w(px(240.))
        .h(px(160.))
        .grid()
        .grid_cols(3)
        .gap_x(px(col))
        .gap_y(px(row))
        .child(cell(Some(SAMPLE_FILLS[0])))
        .child(cell(None))
        .child(cell(Some(SAMPLE_FILLS[1])))
        .child(cell(None))
        .child(cell(Some(SAMPLE_FILLS[2])))
        .child(cell(None))
        .child(cell(None))
        .child(cell(None))
        .child(cell(Some(SAMPLE_FILLS[3])));
    let col_slider = fluent_slider(
        "layout-grid-columns",
        "ColumnSpacing",
        &demo.grid_columns,
        false,
        window,
        cx,
    );
    let row_slider = fluent_slider(
        "layout-grid-rows",
        "RowSpacing",
        &demo.grid_rows,
        false,
        window,
        cx,
    );
    let grid_row = div()
        .flex()
        .flex_row()
        .gap(px(48.))
        .child(grid)
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .w(px(240.))
                .child(headed("ColumnSpacing", col_slider))
                .child(headed("RowSpacing", row_slider)),
        )
        .into_any_element();

    let lines = (1..=24).map(|n| {
        div()
            .py(px(6.))
            .text_size(px(14.))
            .line_height(px(20.))
            .text_color(fg)
            .child(SharedString::from(format!("Item {n}")))
    });
    let scroller = div()
        .w(px(320.))
        .rounded(px(4.))
        .border_1()
        .border_color(crate::theme::card_stroke(cx))
        .child(scroll_viewer(
            "layout-scroll",
            200.,
            div()
                .px(px(12.))
                .flex()
                .flex_col()
                .children(lines)
                .into_any_element(),
            window,
            cx,
        ))
        .into_any_element();

    vec![
        section("Expander", [expanders], cx),
        section("StackPanel", [stack_row], cx),
        section("Grid", [grid_row], cx),
        section("ScrollViewer", [scroller], cx),
    ]
}

#[inline(never)]
pub(super) fn feedback_page(view: &Gallery, cx: &mut Context<Gallery>) -> Vec<AnyElement> {
    use gpui_kit::{StatefulInteractiveElement as _, component::Sizable as _};
    let fg = cx.theme().foreground;
    let badges = div()
        .flex()
        .flex_row()
        .flex_wrap()
        .gap(px(8.))
        .child(status_badge(
            "badge-success",
            Status::Success,
            "18 ms · Direct",
            cx,
        ))
        .child(status_badge(
            "badge-caution",
            Status::Caution,
            "Relayed",
            cx,
        ))
        .child(status_badge(
            "badge-critical",
            Status::Critical,
            "Offline",
            cx,
        ))
        .child(status_badge(
            "badge-info",
            Status::Informational,
            "Connecting",
            cx,
        ))
        .child(status_badge(
            "badge-neutral",
            Status::Neutral,
            "Stopped",
            cx,
        ))
        .into_any_element();
    // A badge in a narrow column truncates and shows its text in a tooltip.
    let narrow = div()
        .w(px(140.))
        .flex()
        .child(status_badge(
            "badge-long",
            Status::Success,
            "42 ms · Direct via relay-eu-west-1",
            cx,
        ))
        .into_any_element();

    let ip_row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.))
        .child(
            div()
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(fg)
                .child("10.144.144.3"),
        )
        .child(copy_button(
            "copy-ip",
            "Copy IP address",
            "Copied",
            "10.144.144.3",
        ))
        .into_any_element();

    let hint = div()
        .id("tooltip-target")
        .test_support()
        .tooltip(fluent_tooltip(
            "Peers exchange traffic directly when they can, and through a relay when they cannot.",
        ))
        .tooltip_show_delay(TOOLTIP_SHOW_DELAY)
        .flex()
        .flex_row()
        .items_center()
        .gap(px(4.))
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(fg)
        .child("Connection type")
        .child(
            gpui_kit::component::Icon::default()
                .path("fluent/info.svg")
                .with_size(gpui_kit::component::Size::Size(px(16.)))
                .text_color(crate::theme::text_secondary(cx)),
        )
        .into_any_element();

    let caption = |text: &'static str, cx: &Context<Gallery>| {
        div()
            .text_size(px(12.))
            .line_height(px(16.))
            .text_color(crate::theme::text_secondary(cx))
            .child(crate::views::pseudo::t(text))
            .into_any_element()
    };
    let bars = div()
        .w(px(360.))
        .flex()
        .flex_col()
        .gap(px(8.))
        .child(caption("Creating virtual adapter (step 1 of 2)", cx))
        .child(progress_bar(
            "progress-determinate",
            "Creating virtual adapter",
            Some(0.4),
            ProgressState::Running,
            cx,
        ))
        .child(caption("Connecting", cx))
        .child(progress_bar(
            "progress-indeterminate",
            "Connecting",
            None,
            ProgressState::Running,
            cx,
        ))
        .child(caption("Paused", cx))
        .child(progress_bar(
            "progress-paused",
            "Paused",
            Some(0.6),
            ProgressState::Paused,
            cx,
        ))
        .child(caption("Failed", cx))
        .child(progress_bar(
            "progress-error",
            "Failed",
            Some(0.8),
            ProgressState::Error,
            cx,
        ))
        .into_any_element();

    let empty = empty_state(
        "empty-networks",
        "fluent/globe.svg",
        "No networks yet",
        "Create a network or join one with a share link.",
        Some(action_button(
            "empty-create",
            "Create network",
            BtnStyle::new(ButtonVariant::Primary, Size::Medium),
            cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| {
                this.demo.last = "Create network".into();
                cx.notify();
            }),
        )),
        cx,
    );

    let popout = div()
        .flex()
        .flex_col()
        .items_start()
        .gap(px(8.))
        .child(
            div()
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(fg)
                .child(crate::views::pseudo::t(
                    "Keeps one room's status above other windows, even while the main window is hidden.",
                )),
        )
        .child(action_button(
            "popout-open",
            "Pop out",
            BtnStyle::new(ButtonVariant::Default, Size::Medium),
            cx.listener(|this, _: &gpui_kit::ClickEvent, _, cx| this.open_popout(cx)),
        ))
        .into_any_element();

    let cards = selection_cards(
        "mode-cards",
        "How do you want to use EasyTier?",
        &[
            CardChoice {
                icon: "fluent/people-community.svg",
                title: "Simple",
                description: "Join or create a room with friends. Settings stay out of the way.",
            },
            CardChoice {
                icon: "fluent/developer-board.svg",
                title: "Professional",
                description: "Manage several networks, peers, routes and access rules.",
            },
        ],
        view.demo.mode_choice,
        {
            let view = cx.entity().downgrade();
            Rc::new(move |ix, _, cx| {
                view.update(cx, |this, cx| {
                    this.demo.mode_choice = ix;
                    cx.notify();
                })
                .ok();
            })
        },
        cx,
    );

    vec![
        section("Status badge", [badges, narrow], cx),
        section("Copy button", [ip_row], cx),
        section("ToolTip", [hint], cx),
        section("ProgressBar", [bars], cx),
        section("Empty state", [empty], cx),
        section("Selection cards", [cards], cx),
        section("Pop-out window", [popout], cx),
    ]
}

/// The room status pop-out (doc#23 S3): an always-on-top, resizable window
/// with its own title bar, the room's address, and a scrolling peer list.
pub(super) struct RoomPopOut;

/// Demo peers: name, virtual address, status, latency text.
const PEERS: [(&str, &str, Status, &str); 9] = [
    (
        "alice-desktop",
        "10.144.144.4",
        Status::Success,
        "12 ms · Direct",
    ),
    (
        "bob-laptop",
        "10.144.144.5",
        Status::Success,
        "18 ms · Direct",
    ),
    (
        "carol-nas",
        "10.144.144.6",
        Status::Caution,
        "64 ms · Relayed",
    ),
    (
        "dave-steamdeck",
        "10.144.144.7",
        Status::Success,
        "23 ms · Direct",
    ),
    (
        "erin-phone",
        "10.144.144.8",
        Status::Caution,
        "97 ms · Relayed",
    ),
    (
        "frank-server-in-the-basement",
        "10.144.144.9",
        Status::Success,
        "5 ms · Direct",
    ),
    (
        "grace-tablet",
        "10.144.144.10",
        Status::Informational,
        "Connecting",
    ),
    ("heidi-pc", "10.144.144.11", Status::Critical, "Offline"),
    (
        "ivan-mini",
        "10.144.144.12",
        Status::Success,
        "31 ms · Direct",
    ),
];

impl gpui_kit::Render for RoomPopOut {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        use crate::views::popout;
        let fg = cx.theme().foreground;
        let secondary = crate::theme::text_secondary(cx);
        let header = div()
            .flex_shrink_0()
            .px(px(16.))
            .pb(px(12.))
            .flex()
            .flex_col()
            .gap(px(4.))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(8.))
                    .child(
                        div()
                            .min_w_0()
                            .truncate()
                            .text_size(px(20.))
                            .line_height(px(28.))
                            .font_semibold()
                            .child(crate::views::pseudo::t("Weekend LAN")),
                    )
                    .child(status_badge(
                        "popout-badge",
                        Status::Success,
                        "Connected",
                        cx,
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(4.))
                    .child(
                        div()
                            .text_size(px(14.))
                            .line_height(px(20.))
                            .text_color(secondary)
                            .child("10.144.144.3"),
                    )
                    .child(copy_button(
                        "popout-copy",
                        "Copy IP address",
                        "Copied",
                        "10.144.144.3",
                    )),
            );
        let mut rows = div().flex().flex_col().pb(px(4.));
        for (ix, (name, ip, status, latency)) in PEERS.into_iter().enumerate() {
            let row = div()
                .w_full()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(12.))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(
                            div()
                                .truncate()
                                .text_size(px(14.))
                                .line_height(px(20.))
                                .child(crate::views::pseudo::t(name)),
                        )
                        .child(
                            div()
                                .truncate()
                                .text_size(px(12.))
                                .line_height(px(16.))
                                .text_color(secondary)
                                .child(ip),
                        ),
                )
                .child(div().flex_shrink_0().max_w(px(160.)).child(status_badge(
                    SharedString::from(format!("popout-peer-{ix}-badge")),
                    status,
                    latency,
                    cx,
                )))
                .into_any_element();
            rows = rows.child(popout::list_view_item(
                SharedString::from(format!("popout-peer-{ix}")),
                format!("{name}, {ip}, {latency}"),
                row,
                cx,
            ));
        }
        div()
            .id("popout-root")
            .test_support()
            .size_full()
            .flex()
            .flex_col()
            .bg(popout::surface(cx))
            .text_color(fg)
            .child(popout::title_bar(
                "popout-title",
                "fluent/people-community.svg",
                "Weekend LAN",
                "Close",
                Rc::new(|_, window, _| window.remove_window()),
                window,
                cx,
            ))
            .child(header)
            .child(
                div()
                    .flex_shrink_0()
                    .px(px(16.))
                    .pb(px(4.))
                    .text_size(px(14.))
                    .line_height(px(20.))
                    .font_semibold()
                    .child(crate::views::pseudo::t("Peers")),
            )
            .child(crate::views::layout::scroll_viewer_fill(
                "popout-peers",
                rows.into_any_element(),
                window,
                cx,
            ))
    }
}

impl Gallery {
    /// Opens the room pop-out, or brings the open one forward: one per room.
    pub(super) fn open_popout(&mut self, cx: &mut Context<Self>) {
        if let Some(handle) = self.demo.popout
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        let options = crate::views::popout::window_options(
            "Weekend LAN",
            px(420.),
            px(520.),
            gpui_kit::size(px(320.), px(240.)),
            cx,
        );
        self.demo.popout = gpui_kit::open_window(options, cx, |window, cx| {
            crate::views::popout::pin(window);
            cx.new(|_| RoomPopOut)
        })
        .ok()
        .map(|(handle, _)| handle);
    }
}
