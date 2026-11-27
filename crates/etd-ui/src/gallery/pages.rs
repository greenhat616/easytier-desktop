//! Gallery pages for the WinUI-style controls in [`crate::views::controls`]:
//! a Settings page laid out like WinUI Gallery's own, and Basic input.
//! All state is in memory; nothing reaches a host or the product's settings.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, AppContext as _, Context, Entity, IntoElement, ParentElement as _,
    SharedString, Styled as _, Window,
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
    ui::{BtnStyle, action_button, fluent_switch},
};

/// Which drop-down is open; WinUI keeps at most one light-dismiss popup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Popup {
    AppTheme,
    NavStyle,
    DropDown,
    Split,
    Combo,
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
    let sound_switch = fluent_switch(
        "settings-sound-switch",
        if demo.sound { "On" } else { "Off" },
        demo.sound,
        false,
        cx.listener(|this, on: &bool, _, cx| {
            this.demo.sound = *on;
            cx.notify();
        }),
    );
    let spatial_switch = fluent_switch(
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
    let dropdown_menu = (demo.popup == Some(Popup::DropDown)).then(|| {
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
        flyout("basic-dropdown-menu", 120., items, dismiss(cx), cx)
    });
    let dropdown = dropdown_button(
        "basic-dropdown",
        "Email",
        demo.popup == Some(Popup::DropDown),
        popup_toggle(Popup::DropDown, cx),
        dropdown_menu,
        cx,
    );
    let split_menu = (demo.popup == Some(Popup::Split)).then(|| {
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
        flyout("basic-split-menu", 120., items, dismiss(cx), cx)
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
                    note(SharedString::from(format!("{slider_value:.0}")), cx),
                ]),
                slider_disabled,
            ],
            cx,
        ),
        section("NumberBox", [number], cx),
    ]
}
