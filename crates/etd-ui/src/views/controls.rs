//! WinUI-style controls shown in the Fluent gallery: SettingsCard,
//! SettingsExpander, CheckBox, RadioButtons, ToggleButton, DropDownButton,
//! SplitButton, ComboBox, Slider and NumberBox.
//!
//! Every colour, size and spacing comes from the WinUI theme resources
//! (microsoft-ui-xaml `controls/dev/**/*_themeresources.xaml`) or from the
//! Windows Community Toolkit SettingsControls, cited where it is used. Like
//! [`super::ui`], each builder is `#[inline(never)]` and returns an
//! [`AnyElement`] so debug stack frames stay small.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, BoxShadow, ClickEvent, ElementId, Entity, Hsla, InteractiveElement as _,
    IntoElement, ParentElement as _, Role, SharedString, StatefulInteractiveElement as _,
    Styled as _, TestSupportExt as _, Toggled, Window, anchored,
    base::{
        Checkbox as BaseCheckbox, CheckboxState, LogicalStyledExt as _, Radio as BaseRadio,
        RadioGroup, Slider as BaseSlider, SliderIndicator, SliderThumb, SliderTrack,
    },
    component::{
        ActiveTheme as _, Icon, Sizable as _, Size, button::ButtonVariant, input::InputState,
        slider::SliderState,
    },
    deferred, div, point, px, relative,
};

use crate::theme::{self, ControlState};
use crate::views::ui::{BtnStyle, action_button};

type Handler = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

fn icon(path: &'static str, size: f32, color: Hsla) -> Icon {
    Icon::default()
        .path(path)
        .with_size(Size::Size(px(size)))
        .text_color(color)
}

/// BodyTextBlockStyle 14/20.
fn body(text: impl Into<SharedString>) -> gpui_kit::Div {
    div()
        .text_size(px(14.))
        .line_height(px(20.))
        .child(text.into())
}

/// CaptionTextBlockStyle 12/16 in `TextFillColorSecondary`.
fn caption(text: impl Into<SharedString>, cx: &App) -> gpui_kit::Div {
    div()
        .text_size(px(12.))
        .line_height(px(16.))
        .text_color(theme::text_secondary(cx))
        .child(text.into())
}

/// Header icon, title and description shared by SettingsCard and the
/// SettingsExpander header (SettingsCard.xaml: SettingsCardHeaderIconMaxSize
/// 20, SettingsCardHeaderIconMargin 2,0,20,0, header panel margin 0,0,24,0).
fn settings_header(
    icon_path: Option<&'static str>,
    header: SharedString,
    description: Option<SharedString>,
    cx: &App,
) -> gpui_kit::Div {
    let fg = cx.theme().foreground;
    div()
        .flex_1()
        .min_w_0()
        .flex()
        .flex_row()
        .items_center()
        .children(icon_path.map(|path| {
            div()
                .flex_shrink_0()
                .ms(px(2.), cx)
                .me(px(20.), cx)
                .child(icon(path, 20., fg))
        }))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .me(px(24.), cx)
                .flex()
                .flex_col()
                .child(body(header).text_color(fg))
                .children(description.map(|d| caption(d, cx))),
        )
}

/// Community Toolkit SettingsCard: MinHeight 68, padding 16, corner 4,
/// `CardBackgroundFillColorDefault` with `CardStrokeColorDefault`. A clickable
/// card turns `ControlFillColorSecondary` on hover and `ControlFillColorTertiary`
/// when pressed, and shows a 13 px chevron 14 px after the content
/// (SettingsCardActionIconMaxSize, SettingsCardActionIconMargin).
#[inline(never)]
pub fn settings_card(
    id: impl Into<ElementId>,
    icon_path: Option<&'static str>,
    header: impl Into<SharedString>,
    description: Option<&'static str>,
    content: Option<AnyElement>,
    on_click: Option<Handler>,
    cx: &App,
) -> AnyElement {
    let header = header.into();
    let hover = theme::control_fill(ControlState::Hover, cx);
    let pressed = theme::control_fill(ControlState::Pressed, cx);
    let mut card = div()
        .id(id)
        .test_support()
        .aria_label(header.clone())
        .w_full()
        .min_h(px(68.))
        .p(px(16.))
        .rounded(px(4.))
        .border_1()
        .border_color(theme::card_stroke(cx))
        .bg(theme::card_fill(cx))
        .flex()
        .flex_row()
        .items_center()
        .child(settings_header(
            icon_path,
            header,
            description.map(SharedString::from),
            cx,
        ))
        .children(content.map(|c| div().flex_shrink_0().child(c)));
    if let Some(handler) = on_click {
        card = card
            .role(Role::Button)
            .hover(move |s| s.bg(hover))
            .active(move |s| s.bg(pressed))
            .on_click(move |event, window, cx| handler(event, window, cx))
            .child(div().flex_shrink_0().ms(px(14.), cx).child(icon(
                "fluent/chevron-right.svg",
                13.,
                cx.theme().foreground,
            )));
    }
    card.into_any_element()
}

/// One row inside an open SettingsExpander (SettingsExpander.xaml item
/// style): MinHeight 52, padding 58,8,44,8, a 1 px top divider in
/// `CardStrokeColorDefault`, no corner radius.
#[inline(never)]
pub fn settings_expander_item(
    id: impl Into<ElementId>,
    header: impl Into<SharedString>,
    description: Option<&'static str>,
    content: Option<AnyElement>,
    cx: &App,
) -> AnyElement {
    let header = header.into();
    div()
        .id(id)
        .test_support()
        .aria_label(header.clone())
        .w_full()
        .min_h(px(52.))
        .ps(px(58.), cx)
        .pe(px(44.), cx)
        .py(px(8.))
        .border_t_1()
        .border_color(theme::card_stroke(cx))
        .flex()
        .flex_row()
        .items_center()
        .child(settings_header(
            None,
            header,
            description.map(SharedString::from),
            cx,
        ))
        .children(content.map(|c| div().flex_shrink_0().child(c)))
        .into_any_element()
}

/// Community Toolkit SettingsExpander: the header is a SettingsCard with
/// padding 16,16,4,16 and a 32×32 chevron button (SettingsExpanderHeaderPadding,
/// SettingsExpanderChevronButtonWidth/Height) whose fill follows
/// `ExpanderChevron*Background` (SubtleFill transparent / secondary /
/// tertiary). Open, the header keeps only its top corners and the items sit
/// on `ExpanderContentBackground` = `CardBackgroundFillColorSecondary`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn settings_expander(
    id: &'static str,
    icon_path: Option<&'static str>,
    header: impl Into<SharedString>,
    description: Option<&'static str>,
    content: Option<AnyElement>,
    expanded: bool,
    on_toggle: Handler,
    items: Vec<AnyElement>,
    cx: &App,
) -> AnyElement {
    let header = header.into();
    let stroke = theme::card_stroke(cx);
    let subtle = theme::subtle_fill_secondary(cx);
    let subtle_pressed = theme::subtle_fill_tertiary(cx);
    let chevron = div()
        .id(SharedString::from(format!("{id}-chevron")))
        .test_support()
        .role(Role::Button)
        .aria_label(SharedString::from(if expanded {
            format!("Collapse {header}")
        } else {
            format!("Expand {header}")
        }))
        .aria_expanded(expanded)
        .flex_shrink_0()
        .ms(px(8.), cx)
        .size(px(32.))
        .rounded(px(4.))
        .flex()
        .items_center()
        .justify_center()
        .hover(move |s| s.bg(subtle))
        .active(move |s| s.bg(subtle_pressed))
        .on_click(move |event, window, cx| on_toggle(event, window, cx))
        .child(icon(
            if expanded {
                "fluent/chevron-up.svg"
            } else {
                "fluent/chevron-down.svg"
            },
            12.,
            cx.theme().foreground,
        ));
    let mut head = div()
        .id(SharedString::from(format!("{id}-header")))
        .test_support()
        .w_full()
        .min_h(px(68.))
        .pt(px(16.))
        .pb(px(16.))
        .ps(px(16.), cx)
        .pe(px(4.), cx)
        .border_1()
        .border_color(stroke)
        .bg(theme::card_fill(cx))
        .flex()
        .flex_row()
        .items_center()
        .child(settings_header(
            icon_path,
            header.clone(),
            description.map(SharedString::from),
            cx,
        ))
        .children(content.map(|c| div().flex_shrink_0().child(c)))
        .child(chevron);
    head = if expanded {
        head.rounded_t(px(4.))
    } else {
        head.rounded(px(4.))
    };
    div()
        .id(id)
        .test_support()
        .aria_label(header)
        .w_full()
        .flex()
        .flex_col()
        .child(head)
        .children(expanded.then(|| {
            div()
                .id(SharedString::from(format!("{id}-content")))
                .test_support()
                .w_full()
                .rounded_b(px(4.))
                .border_1()
                .border_t_0()
                .border_color(stroke)
                .bg(theme::card_fill_secondary(cx))
                .flex()
                .flex_col()
                .children(items)
        }))
        .into_any_element()
}

/// WinUI CheckBox (CheckBox_themeresources.xaml): a 20 px box (CheckBoxSize)
/// with 4 px corners and a 1 px border, 12 px glyph (CheckBoxGlyphSize),
/// 32 px tall (CheckBoxHeight), label 8 px after the box (CheckBoxPadding
/// 8,5,0,0). Unchecked: `ControlAltFillColor*` fill and
/// `ControlStrongStrokeColorDefault` stroke; checked or indeterminate:
/// `AccentFillColor*` with a `TextOnAccentFillColorPrimary` glyph.
#[inline(never)]
pub fn fluent_checkbox(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    state: CheckboxState,
    disabled: bool,
    on_change: impl Fn(&CheckboxState, &mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let id = id.into();
    let label = label.into();
    let on = state != CheckboxState::Unchecked;
    let group = SharedString::from(format!("fluent-checkbox:{id:?}"));
    let (rest, hover, pressed) = if disabled {
        let d = ControlState::Disabled;
        if on {
            (
                theme::accent_fill(d, cx),
                theme::accent_fill(d, cx),
                theme::accent_fill(d, cx),
            )
        } else {
            (
                theme::control_alt_fill(d, cx),
                theme::control_alt_fill(d, cx),
                theme::control_alt_fill(d, cx),
            )
        }
    } else if on {
        (
            theme::accent_fill(ControlState::Rest, cx),
            theme::accent_fill(ControlState::Hover, cx),
            theme::accent_fill(ControlState::Pressed, cx),
        )
    } else {
        (
            theme::control_alt_fill(ControlState::Rest, cx),
            theme::control_alt_fill(ControlState::Hover, cx),
            theme::control_alt_fill(ControlState::Pressed, cx),
        )
    };
    let stroke = if disabled {
        theme::control_strong_stroke_disabled(cx)
    } else if on {
        rest
    } else {
        theme::control_strong_stroke(cx)
    };
    let glyph = match state {
        CheckboxState::Checked => Some("fluent/checkmark.svg"),
        CheckboxState::Indeterminate => Some("fluent/subtract.svg"),
        CheckboxState::Unchecked => None,
    };
    let glyph_color = theme::text_on_accent(cx);
    let mut boxed = div()
        .id("fluent-checkbox-box")
        .test_support()
        .flex_shrink_0()
        .size(px(20.))
        .rounded(px(4.))
        .border_1()
        .border_color(stroke)
        .bg(rest)
        .flex()
        .items_center()
        .justify_center()
        .children(glyph.map(|g| icon(g, 12., glyph_color)));
    if !disabled {
        let hover_stroke = if on { hover } else { stroke };
        let pressed_stroke = if on {
            pressed
        } else {
            theme::control_strong_stroke_disabled(cx)
        };
        boxed = boxed
            .group_hover(group.clone(), move |s| {
                s.bg(hover).border_color(hover_stroke)
            })
            .group_active(group.clone(), move |s| {
                s.bg(pressed).border_color(pressed_stroke)
            });
    }
    BaseCheckbox::new(id)
        .state(state)
        .disabled(disabled)
        .accessibility_label(label.clone())
        .on_change(move |next, _, window, cx| on_change(&next, window, cx))
        .group(group)
        .min_h(px(32.))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.))
        .child(boxed)
        .child(body(label).text_color(if disabled {
            theme::text_disabled(cx)
        } else {
            cx.theme().foreground
        }))
        .into_any_element()
}

/// WinUI RadioButton (RadioButton_themeresources.xaml): a 20 px ring with a
/// 1 px border. Unselected: `ControlAltFillColor*` fill with
/// `ControlStrongStrokeColorDefault`; selected: `AccentFillColor*` with a
/// `TextOnAccentFillColorPrimary` dot of 12 px, 14 px on hover and 10 px when
/// pressed (RadioButtonCheckGlyph{,PointerOver,PressedOver}Size).
#[inline(never)]
pub fn fluent_radio_group(
    id: &'static str,
    header: &'static str,
    options: &[&'static str],
    selected: usize,
    disabled: bool,
    on_select: impl Fn(&usize, &mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let on_select = Rc::new(on_select);
    let mut group = RadioGroup::new(id).flex().flex_col();
    for (ix, option) in options.iter().enumerate() {
        let checked = ix == selected;
        let hover_group = SharedString::from(format!("fluent-radio:{id}:{ix}"));
        let state = |s| {
            if disabled { ControlState::Disabled } else { s }
        };
        let (fill, fill_hover, fill_pressed) = if checked {
            (
                theme::accent_fill(state(ControlState::Rest), cx),
                theme::accent_fill(state(ControlState::Hover), cx),
                theme::accent_fill(state(ControlState::Pressed), cx),
            )
        } else {
            (
                theme::control_alt_fill(state(ControlState::Rest), cx),
                theme::control_alt_fill(state(ControlState::Hover), cx),
                theme::control_alt_fill(state(ControlState::Pressed), cx),
            )
        };
        let stroke = if checked {
            fill
        } else if disabled {
            theme::control_strong_stroke_disabled(cx)
        } else {
            theme::control_strong_stroke(cx)
        };
        let dot = div()
            .id("fluent-radio-dot")
            .test_support()
            .size(px(12.))
            .rounded_full()
            .bg(theme::text_on_accent(cx));
        let dot = if disabled {
            dot
        } else {
            dot.group_hover(hover_group.clone(), |s| s.size(px(14.)))
                .group_active(hover_group.clone(), |s| s.size(px(10.)))
        };
        let mut ring = div()
            .id("fluent-radio-ring")
            .flex_shrink_0()
            .size(px(20.))
            .rounded_full()
            .border_1()
            .border_color(stroke)
            .bg(fill)
            .flex()
            .items_center()
            .justify_center()
            .children(checked.then_some(dot));
        if !disabled {
            let pressed_stroke = if checked {
                fill_pressed
            } else {
                theme::control_strong_stroke_disabled(cx)
            };
            ring = ring
                .group_hover(hover_group.clone(), move |s| s.bg(fill_hover))
                .group_active(hover_group.clone(), move |s| {
                    s.bg(fill_pressed).border_color(pressed_stroke)
                });
        }
        let on_select = on_select.clone();
        group = group.child(
            BaseRadio::new(SharedString::from(format!("{id}-{ix}")))
                .checked(checked)
                .disabled(disabled)
                .accessibility_label(*option)
                .set_position(ix + 1, options.len())
                .on_change(move |_, _, window, cx| on_select(&ix, window, cx))
                .group(hover_group)
                .min_h(px(32.))
                .flex()
                .flex_row()
                .items_center()
                .gap(px(8.))
                .child(ring)
                .child(body(*option).text_color(if disabled {
                    theme::text_disabled(cx)
                } else {
                    cx.theme().foreground
                })),
        );
    }
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(body(header).text_color(cx.theme().foreground))
        .child(group)
        .into_any_element()
}

/// WinUI ToggleButton (ToggleButton_themeresources.xaml): off it is a
/// standard button (`ControlFillColor*`), on it takes the accent fill
/// (`ToggleButtonBackgroundChecked` = `AccentFillColorDefault`), exactly the
/// two button styles the gallery already has.
#[inline(never)]
pub fn toggle_button(
    id: &'static str,
    label: &'static str,
    checked: bool,
    disabled: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> AnyElement {
    let variant = if checked {
        ButtonVariant::Primary
    } else {
        ButtonVariant::Default
    };
    let mut style = BtnStyle::new(variant, Size::Medium);
    style.disabled = disabled;
    div()
        .id(SharedString::from(format!("{id}-toggle")))
        .test_support()
        .aria_toggled(if checked {
            Toggled::True
        } else {
            Toggled::False
        })
        .child(action_button(id, label, style, on_click))
        .into_any_element()
}

/// Drop-down chevron used by DropDownButton, SplitButton and ComboBox:
/// DropDownButton.xaml draws glyph E96E at 8 px in a 12 px box, 8 px after
/// the label.
fn chevron(cx: &App) -> AnyElement {
    div()
        .size(px(12.))
        .flex()
        .items_center()
        .justify_center()
        .child(icon("fluent/chevron-down.svg", 12., cx.theme().foreground))
        .into_any_element()
}

/// Flyout surface: `AcrylicInAppFillColorDefaultBrush` (its fallback colour),
/// `SurfaceStrokeColorFlyout` 1 px, OverlayCornerRadius 8, and Fluent 2's
/// shadow16 (0 0 2 and 0 8 16, 14 % / 28 % black).
pub(crate) fn flyout_surface(cx: &App) -> gpui_kit::Div {
    let dark = cx.theme().is_dark();
    let ambient = Hsla::from(gpui_kit::rgb(0)).opacity(if dark { 0.24 } else { 0.12 });
    let key = Hsla::from(gpui_kit::rgb(0)).opacity(if dark { 0.28 } else { 0.14 });
    div()
        .rounded(px(8.))
        .border_1()
        .border_color(theme::flyout_stroke(cx))
        .bg(theme::flyout_fill(cx))
        .shadow(vec![
            BoxShadow {
                color: ambient,
                offset: point(px(0.), px(0.)),
                blur_radius: px(2.),
                spread_radius: px(0.),
                inset: false,
            },
            BoxShadow {
                color: key,
                offset: point(px(0.), px(8.)),
                blur_radius: px(16.),
                spread_radius: px(0.),
                inset: false,
            },
        ])
}

/// A list item inside a flyout or ComboBox drop-down
/// (ComboBox_themeresources.xaml): ComboBoxItemThemePadding 11,5,11,7,
/// ComboBoxItemCornerRadius 3, `SubtleFillColorSecondary` on hover and when
/// selected, `SubtleFillColorTertiary` pressed, and a 3×16 accent pill with
/// 1.5 px corners (ComboBoxItemPillWidth/Height, ComboBoxItemPillCornerRadius)
/// on the selected item. Items sit 4 px inside the surface (margin 5,2).
#[inline(never)]
pub fn flyout_item(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    selected: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let label = label.into();
    let mut item = div()
        .id(id)
        .test_support()
        .role(Role::MenuItem)
        .aria_label(label.clone())
        .aria_selected(selected)
        .relative()
        .mx(px(4.))
        .my(px(2.))
        .ps(px(11.), cx)
        .pe(px(11.), cx)
        .pt(px(5.))
        .pb(px(7.))
        .rounded(px(3.))
        .hover(move |s| s.bg(subtle))
        .active(move |s| s.bg(pressed))
        .on_click(on_click)
        .child(body(label).text_color(cx.theme().foreground));
    if selected {
        item = item.bg(subtle).child(
            div()
                .absolute()
                .top(px(8.))
                .left_0()
                .w(px(3.))
                .h(px(16.))
                .rounded(px(1.5))
                .bg(theme::accent_fill(ControlState::Rest, cx)),
        );
    }
    item.into_any_element()
}

/// Opens `items` in a flyout under the element that precedes it in a
/// column. `on_dismiss` runs for a pointer press outside the flyout.
#[inline(never)]
pub fn flyout(
    id: impl Into<ElementId>,
    min_width: f32,
    items: Vec<AnyElement>,
    on_dismiss: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    deferred(
        anchored().snap_to_window_with_margin(px(8.)).child(
            flyout_surface(cx)
                .id(id)
                .test_support()
                .role(Role::Menu)
                .mt(px(4.))
                .min_w(px(min_width))
                .py(px(2.))
                .flex()
                .flex_col()
                .on_mouse_down_out(move |_, window, cx| on_dismiss(window, cx))
                .children(items),
        ),
    )
    .with_priority(1)
    .into_any_element()
}

/// WinUI DropDownButton: a standard button with the chevron 8 px after its
/// label (DropDownButton.xaml ChevronIcon margin 8,0,0,0), opening a flyout.
#[inline(never)]
pub fn dropdown_button(
    id: &'static str,
    label: &'static str,
    open: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    menu: Option<AnyElement>,
    cx: &App,
) -> AnyElement {
    let fill = theme::control_fill(ControlState::Rest, cx);
    let hover = theme::control_fill(ControlState::Hover, cx);
    let pressed = theme::control_fill(ControlState::Pressed, cx);
    div()
        .flex()
        .flex_col()
        .items_start()
        .child(
            div()
                .id(id)
                .test_support()
                .role(Role::Button)
                .aria_label(SharedString::from(label))
                .aria_expanded(open)
                .h(px(32.))
                .ps(px(11.), cx)
                .pe(px(11.), cx)
                .rounded(px(4.))
                .border_1()
                .border_color(cx.theme().input)
                .bg(fill)
                .hover(move |s| s.bg(hover))
                .active(move |s| s.bg(pressed))
                .flex()
                .flex_row()
                .items_center()
                .gap(px(8.))
                .on_click(on_click)
                .child(body(label).text_color(cx.theme().foreground))
                .child(chevron(cx)),
        )
        .children(menu)
        .into_any_element()
}

/// WinUI SplitButton (SplitButton_themeresources.xaml): a primary part and
/// a chevron part, each with the standard `ControlFillColor*` ramp, divided
/// by 1 px `ControlStrokeColorDefault` (SplitButtonBorderBrushDivider); the
/// secondary part is 35 px wide (SplitButtonSecondaryButtonSize).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn split_button(
    id: &'static str,
    label: &'static str,
    open: bool,
    on_primary: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_secondary: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    menu: Option<AnyElement>,
    cx: &App,
) -> AnyElement {
    let fill = theme::control_fill(ControlState::Rest, cx);
    let hover = theme::control_fill(ControlState::Hover, cx);
    let pressed = theme::control_fill(ControlState::Pressed, cx);
    let part = |part_id: SharedString| {
        div()
            .id(part_id)
            .test_support()
            .role(Role::Button)
            .h_full()
            .flex()
            .flex_row()
            .items_center()
            .justify_center()
            .hover(move |s| s.bg(hover))
            .active(move |s| s.bg(pressed))
    };
    div()
        .flex()
        .flex_col()
        .items_start()
        .child(
            div()
                .h(px(32.))
                .rounded(px(4.))
                .border_1()
                .border_color(cx.theme().input)
                .bg(fill)
                .overflow_hidden()
                .flex()
                .flex_row()
                .child(
                    part(SharedString::from(id))
                        .aria_label(SharedString::from(label))
                        .ps(px(11.), cx)
                        .pe(px(11.), cx)
                        .on_click(on_primary)
                        .child(body(label).text_color(cx.theme().foreground)),
                )
                .child(div().w(px(1.)).h_full().bg(theme::control_stroke(cx)))
                .child(
                    part(SharedString::from(format!("{id}-more")))
                        .aria_label(SharedString::from(format!("More {label} options")))
                        .aria_expanded(open)
                        .w(px(35.))
                        .on_click(on_secondary)
                        .child(chevron(cx)),
                ),
        )
        .children(menu)
        .into_any_element()
}

/// WinUI ComboBox (ComboBox_themeresources.xaml): MinHeight 32, padding
/// 12,5,0,7 (the chevron sits in a 38 px column, ComboBoxEditableTextPadding
/// right 38), `ControlFillColor*` fill, corner 4. The drop-down is a flyout
/// of [`flyout_item`]s with 4 px content margin (ComboBoxDropdownContentMargin 0,4).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn combo_box(
    id: &'static str,
    header: Option<&'static str>,
    options: &'static [&'static str],
    selected: usize,
    open: bool,
    width: f32,
    on_toggle: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_select: impl Fn(usize, &mut Window, &mut App) + 'static,
    on_dismiss: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let fill = theme::control_fill(ControlState::Rest, cx);
    let hover = theme::control_fill(ControlState::Hover, cx);
    let pressed = theme::control_fill(ControlState::Pressed, cx);
    let on_select = Rc::new(on_select);
    let menu = open.then(|| {
        let items = options
            .iter()
            .enumerate()
            .map(|(ix, option)| {
                let on_select = on_select.clone();
                flyout_item(
                    SharedString::from(format!("{id}-item-{ix}")),
                    *option,
                    ix == selected,
                    move |_, window, cx| on_select(ix, window, cx),
                    cx,
                )
            })
            .collect();
        flyout(
            SharedString::from(format!("{id}-popup")),
            width,
            items,
            on_dismiss,
            cx,
        )
    });
    div()
        .flex()
        .flex_col()
        .items_start()
        .gap(px(8.))
        .children(header.map(|h| body(h).text_color(cx.theme().foreground)))
        .child(
            div()
                .flex()
                .flex_col()
                .child(
                    div()
                        .id(id)
                        .test_support()
                        .role(Role::ComboBox)
                        .aria_label(SharedString::from(header.unwrap_or(id)))
                        .aria_expanded(open)
                        .w(px(width))
                        .h(px(32.))
                        .ps(px(12.), cx)
                        .rounded(px(4.))
                        .border_1()
                        .border_color(cx.theme().input)
                        .bg(fill)
                        .hover(move |s| s.bg(hover))
                        .active(move |s| s.bg(pressed))
                        .flex()
                        .flex_row()
                        .items_center()
                        .on_click(on_toggle)
                        .child(
                            body(options[selected])
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_color(cx.theme().foreground),
                        )
                        .child(div().w(px(38.)).flex().justify_center().child(chevron(cx))),
                )
                .children(menu),
        )
        .into_any_element()
}

/// WinUI Slider (Slider_themeresources.xaml): 32 px tall, a 4 px track
/// with 2 px corners in `ControlStrongFillColorDefault`, the value part in
/// `AccentFillColor*`, and an 18 px `ControlSolidFillColorDefault` thumb
/// (SliderHorizontalThumbWidth/Height, SliderThumbCornerRadius 10) holding a
/// 12 px accent dot (SliderInnerThumbWidth) that grows to 14 px on hover and
/// shrinks to 10 px pressed, as WinUI's thumb animation does.
#[inline(never)]
pub fn fluent_slider(
    id: &'static str,
    label: &'static str,
    state: &Entity<SliderState>,
    disabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> AnyElement {
    let focus = window
        .use_keyed_state((ElementId::from(id), "fluent-slider-focus"), cx, |_, cx| {
            cx.focus_handle()
        })
        .read(cx)
        .clone();
    let pct = state.read(cx).percentage();
    let value_state = |s| {
        if disabled { ControlState::Disabled } else { s }
    };
    let accent = theme::accent_fill(value_state(ControlState::Rest), cx);
    let accent_hover = theme::accent_fill(value_state(ControlState::Hover), cx);
    let accent_pressed = theme::accent_fill(value_state(ControlState::Pressed), cx);
    let group = SharedString::from(format!("fluent-slider:{id}"));
    let dot = div()
        .id("fluent-slider-dot")
        .test_support()
        .size(px(12.))
        .rounded_full()
        .bg(accent);
    let dot = if disabled {
        dot
    } else {
        dot.group_hover(group.clone(), move |s| s.size(px(14.)).bg(accent_hover))
            .group_active(group.clone(), move |s| s.size(px(10.)).bg(accent_pressed))
    };
    let thumb = SliderThumb::new(state)
        .disabled(disabled)
        .absolute()
        .top(px(-7.))
        .inset_s(relative(pct.end), cx)
        .ms(px(-9.), cx)
        .size(px(18.))
        .rounded_full()
        .border_1()
        .border_color(theme::control_stroke(cx))
        .bg(theme::control_solid_fill(cx))
        .flex()
        .items_center()
        .justify_center()
        .child(dot);
    let slider = BaseSlider::new(state)
        .disabled(disabled)
        .accessibility_label(label)
        .track_focus(&focus)
        .w(px(240.))
        .h(px(32.))
        .flex()
        .items_center()
        .child(
            SliderTrack::new(state)
                .disabled(disabled)
                .w_full()
                .h(px(32.))
                .flex()
                .items_center()
                .child(
                    SliderIndicator::new(state)
                        .relative()
                        .w_full()
                        .h(px(4.))
                        .rounded(px(2.))
                        .bg(theme::control_strong_fill(disabled, cx))
                        .child(
                            div()
                                .absolute()
                                .h_full()
                                .inset_s(relative(pct.start), cx)
                                .inset_e(relative(1. - pct.end), cx)
                                .rounded(px(2.))
                                .bg(accent),
                        )
                        .child(thumb),
                ),
        );
    div()
        .id(SharedString::from(format!("{id}-frame")))
        .group(group)
        .child(slider)
        .into_any_element()
}

/// WinUI NumberBox with inline spin buttons (NumberBox.xaml,
/// SpinButtonPlacementMode="Inline"): a TextBox (see [`super::ui::text_field`])
/// with two 32 px subtle buttons for −/+ inside its right edge.
#[inline(never)]
pub fn number_box(
    id: &'static str,
    header: &'static str,
    state: &Entity<InputState>,
    on_step: impl Fn(f64, &mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let on_step = Rc::new(on_step);
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let spin = |dir: f64, glyph: &'static str, label: &'static str| {
        let on_step = on_step.clone();
        div()
            .id(SharedString::from(format!("{id}-{label}")))
            .test_support()
            .role(Role::Button)
            .aria_label(SharedString::from(label))
            .size(px(28.))
            .rounded(px(4.))
            .flex()
            .items_center()
            .justify_center()
            .hover(move |s| s.bg(subtle))
            .active(move |s| s.bg(pressed))
            .on_click(move |_, window, cx| on_step(dir, window, cx))
            .child(icon(glyph, 12., theme::text_secondary(cx)))
    };
    div()
        .w(px(200.))
        .relative()
        .child(super::ui::text_field(header, id, header, state, false, cx))
        .child(
            div()
                .absolute()
                .bottom(px(2.))
                .right(px(2.))
                .flex()
                .flex_row()
                .child(spin(-1., "fluent/subtract.svg", "Decrease"))
                .child(spin(1., "fluent/add.svg", "Increase")),
        )
        .into_any_element()
}
