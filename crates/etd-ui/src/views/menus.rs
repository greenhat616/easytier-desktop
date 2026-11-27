//! WinUI MenuFlyout (also used as a context menu) and CommandBar with
//! AppBarButton, AppBarToggleButton, AppBarSeparator and its overflow menu,
//! shown in the Fluent gallery. Values come from MenuFlyout_themeresources,
//! AppBarButton_themeresources, AppBarSeparator_themeresources and
//! CommandBar_themeresources in microsoft-ui-xaml, cited where used.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, ClickEvent, ElementId, InteractiveElement as _, IntoElement, KeyDownEvent,
    ParentElement as _, Pixels, Point, Role, SharedString, StatefulInteractiveElement as _,
    Styled as _, TestSupportExt as _, Toggled, Window, anchored,
    base::LogicalStyledExt as _,
    component::{ActiveTheme as _, Icon, Sizable as _, Size},
    deferred, div, px,
};

use crate::theme::{self, ControlState};
use crate::views::controls::{
    DismissHandler, flyout_keys, flyout_surface, light_dismiss_layer, popup_focus,
};
use crate::views::motion::{PopupKind, PopupMotion};
use crate::views::ui::keyboard_focus;

pub type MenuHandler = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// The check column of a menu item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MenuCheck {
    None,
    /// ToggleMenuFlyoutItem: a check mark when on.
    Toggle(bool),
    /// RadioMenuFlyoutItem: a dot when chosen.
    Radio(bool),
}

pub enum MenuEntry {
    Item(MenuItem),
    /// MenuFlyoutSeparator.
    Separator,
}

pub struct MenuItem {
    pub id: SharedString,
    pub label: SharedString,
    pub icon: Option<&'static str>,
    pub accelerator: Option<&'static str>,
    pub check: MenuCheck,
    pub disabled: bool,
    /// MenuFlyoutSubItem: entries shown beside this item when it is open.
    pub submenu: Option<(bool, Vec<MenuEntry>)>,
    pub on_click: Option<MenuHandler>,
}

impl MenuItem {
    pub fn new(id: impl Into<SharedString>, label: impl Into<SharedString>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            icon: None,
            accelerator: None,
            check: MenuCheck::None,
            disabled: false,
            submenu: None,
            on_click: None,
        }
    }
    pub fn icon(mut self, icon: &'static str) -> Self {
        self.icon = Some(icon);
        self
    }
    pub fn accelerator(mut self, text: &'static str) -> Self {
        self.accelerator = Some(text);
        self
    }
    pub fn check(mut self, check: MenuCheck) -> Self {
        self.check = check;
        self
    }
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
    pub fn submenu(mut self, open: bool, entries: Vec<MenuEntry>) -> Self {
        self.submenu = Some((open, entries));
        self
    }
    pub fn on_click(
        mut self,
        handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        self.on_click = Some(Rc::new(handler));
        self
    }
}

fn glyph(path: &'static str, size: f32, color: gpui_kit::Hsla) -> Icon {
    Icon::default()
        .path(path)
        .with_size(Size::Size(px(size)))
        .text_color(color)
}

/// `DividerStrokeColorDefault` (#0F000000 / #15FFFFFF).
fn divider(cx: &App) -> gpui_kit::Hsla {
    let dark = cx.theme().is_dark();
    gpui_kit::rgba(if dark { 0xFFFFFF15 } else { 0x0000000F }).into()
}

/// MenuFlyoutPresenter content: padding 0,2,0,2 (MenuFlyoutPresenterThemePadding),
/// items with MenuFlyoutItemMargin 4,2,4,2, MenuFlyoutItemThemePaddingNarrow
/// 11,4,11,5 (the padding WinUI uses when the menu is opened by mouse, pen
/// or keyboard: MenuFlyoutItemBase::GetShouldBeNarrow) and
/// MenuFlyoutThemeMinHeight 32; `SubtleFillColorSecondary`
/// on hover and `SubtleFillColorTertiary` pressed. When any item has a check
/// or an icon the labels share a 28 px column (MenuFlyoutItemPlaceholderThemeThickness),
/// 56 px when the menu has both a checkable item and an item with an icon
/// (…DoublePlaceholderThemeThickness; MenuFlyoutItem::UpdateVisualState
/// picks CheckAndIconPlaceholder from the presenter-wide flags). Up and
/// Down move between items and Escape closes the menu.
/// Accelerator text is `TextFillColorSecondary`, 24 px after the label, and
/// a sub-item's chevron sits 24 px after it (MenuFlyoutItemChevronMargin).
/// Separators are 1 px `DividerStrokeColorDefault` with 1 px above and
/// below, running the menu's full width (MenuFlyoutSeparatorThemePadding -4,1,-4,1).
#[inline(never)]
pub fn menu_content(
    id: impl Into<ElementId>,
    entries: Vec<MenuEntry>,
    min_width: f32,
    cx: &App,
) -> AnyElement {
    let has_check = entries
        .iter()
        .any(|e| matches!(e, MenuEntry::Item(item) if item.check != MenuCheck::None));
    let has_icon = entries
        .iter()
        .any(|e| matches!(e, MenuEntry::Item(item) if item.icon.is_some()));
    let indent = match (has_check, has_icon) {
        (true, true) => 56.,
        (true, false) | (false, true) => 28.,
        (false, false) => 0.,
    };
    let fg = cx.theme().foreground;
    let secondary = theme::text_secondary(cx);
    let disabled_fg = theme::text_disabled(cx);
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let rows = entries.into_iter().map(|entry| match entry {
        MenuEntry::Separator => div()
            .my(px(1.))
            .h(px(1.))
            .w_full()
            .bg(divider(cx))
            .into_any_element(),
        MenuEntry::Item(item) => {
            let ink = if item.disabled { disabled_fg } else { fg };
            let check = match item.check {
                MenuCheck::Toggle(true) => {
                    Some(glyph("fluent/checkmark.svg", 12., ink).into_any_element())
                }
                MenuCheck::Radio(true) => {
                    Some(div().size(px(6.)).rounded_full().bg(ink).into_any_element())
                }
                _ => None,
            };
            let lead = div()
                .absolute()
                .top_0()
                .bottom_0()
                .left(px(11.))
                .flex()
                .flex_row()
                .items_center()
                .when_has_check(has_check, check)
                .children(item.icon.map(|i| {
                    div()
                        .w(px(28.))
                        .flex()
                        .items_center()
                        .child(glyph(i, 16., ink))
                }));
            let open = item.submenu.as_ref().is_some_and(|(open, _)| *open);
            let mut row = div()
                .id(item.id.clone())
                .test_support()
                .role(Role::MenuItem)
                .aria_label(item.label.clone())
                .relative()
                .mx(px(4.))
                .my(px(2.))
                .min_h(px(32.))
                .ps(px(11. + indent), cx)
                .pe(px(11.), cx)
                .pt(px(4.))
                .pb(px(5.))
                .rounded(px(4.))
                .flex()
                .flex_row()
                .items_center()
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(ink)
                .child(lead)
                .child(div().flex_1().min_w_0().child(item.label.clone()))
                .children(item.accelerator.map(|a| {
                    div()
                        .ms(px(24.), cx)
                        .text_color(if item.disabled {
                            disabled_fg
                        } else {
                            secondary
                        })
                        .child(a)
                }));
            match item.check {
                MenuCheck::Toggle(on) => {
                    row = row.role(Role::MenuItemCheckBox).aria_toggled(if on {
                        Toggled::True
                    } else {
                        Toggled::False
                    });
                }
                MenuCheck::Radio(on) => {
                    row = row.role(Role::MenuItemRadio).aria_toggled(if on {
                        Toggled::True
                    } else {
                        Toggled::False
                    });
                }
                MenuCheck::None => {}
            }
            if !item.disabled {
                row = row
                    .hover(move |s| s.bg(subtle))
                    .active(move |s| s.bg(pressed));
                if let Some(handler) = item.on_click.clone() {
                    row = row.on_click(move |e, w, cx| handler(e, w, cx));
                }
            }
            let mut wrapper = div().relative().flex().flex_col();
            if let Some((_, sub)) = item.submenu {
                row = row
                    .aria_expanded(open)
                    .child(div().ms(px(24.), cx).child(glyph(
                        "fluent/chevron-right.svg",
                        12.,
                        secondary,
                    )));
                if open {
                    row = row.bg(subtle);
                    let sub_id = SharedString::from(format!("{}-submenu", item.id));
                    wrapper = wrapper.child(
                        div().absolute().top(px(-4.)).right(px(-4.)).child(
                            deferred(
                                anchored().snap_to_window_with_margin(px(8.)).child(
                                    flyout_surface(cx)
                                        .id("menu-submenu-surface")
                                        .occlude()
                                        .on_key_down(|event: &KeyDownEvent, window, cx| {
                                            // Left returns to the parent menu.
                                            if event.keystroke.key == "left" {
                                                window.focus_prev(cx);
                                                cx.stop_propagation();
                                            }
                                        })
                                        .child(menu_content(sub_id, sub, 160., cx)),
                                ),
                            )
                            .with_priority(3),
                        ),
                    );
                }
            }
            let row = if item.disabled {
                row.into_any_element()
            } else {
                keyboard_focus(item.id.clone(), move |focus| {
                    row.track_focus(focus).into_any_element()
                })
            };
            wrapper.child(row).into_any_element()
        }
    });
    div()
        .id(id)
        .test_support()
        .role(Role::Menu)
        .min_w(px(min_width))
        .py(px(2.))
        .flex()
        .flex_col()
        .children(rows)
        .into_any_element()
}

trait WhenHasCheck {
    fn when_has_check(self, has_check: bool, check: Option<AnyElement>) -> Self;
}

impl WhenHasCheck for gpui_kit::Div {
    /// Reserves the 28 px check column, with the glyph centred in 16 px.
    fn when_has_check(self, has_check: bool, check: Option<AnyElement>) -> Self {
        if has_check {
            self.child(
                div()
                    .w(px(28.))
                    .h(px(16.))
                    .flex()
                    .items_center()
                    .children(check.map(|c| div().w(px(16.)).flex().justify_center().child(c))),
            )
        } else {
            self
        }
    }
}

/// A MenuFlyout in its light-dismiss popup. With `at`, the popup opens at
/// that window point (a context menu); otherwise under the element before
/// it in a column.
#[inline(never)]
pub fn menu_flyout(
    id: &'static str,
    open: bool,
    entries: Vec<MenuEntry>,
    at: Option<Point<Pixels>>,
    on_dismiss: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let mut anchor = anchored().snap_to_window_with_margin(px(8.));
    if let Some(at) = at {
        anchor = anchor.position(at);
    }
    let on_dismiss: DismissHandler = Rc::new(on_dismiss);
    let layer_dismiss = on_dismiss.clone();
    let motion = PopupMotion::new(id, open, PopupKind::Menu);
    let animate = motion.clone();
    let surface = flyout_surface(cx)
        .id("menu-surface")
        .occlude()
        .mt(px(4.))
        .child(menu_content(id, entries, 160., cx));
    motion.gate(
        div()
            .child(motion.interactive(light_dismiss_layer(move |window, cx| {
                layer_dismiss(window, cx)
            })))
            .child(
                deferred(anchor.child(popup_focus(id, move |focus| {
                    animate.animate(
                        SharedString::from(format!("{id}-motion")),
                        flyout_keys(surface.track_focus(focus), on_dismiss).into_any_element(),
                    )
                })))
                .with_priority(2),
            )
            .into_any_element(),
    )
}

/// One CommandBar command.
pub enum BarCommand {
    /// AppBarButton, or AppBarToggleButton when `toggled` is set.
    Button {
        id: &'static str,
        label: &'static str,
        icon: &'static str,
        toggled: Option<bool>,
        on_click: MenuHandler,
    },
    /// AppBarSeparator.
    Separator,
}

/// CommandBar with DefaultLabelPosition="Right" (CommandBar_themeresources,
/// AppBarButton_themeresources): 48 px tall (AppBarThemeCompactHeight) on
/// `CommandBarBackground` (transparent). Each AppBarButton draws its fill in
/// an inner border inset 2,6,2,6 (AppBarButtonInnerBorderMargin) with 4 px
/// corners: `SubtleFillColor{Transparent,Secondary,Tertiary}`; a checked
/// AppBarToggleButton is `AccentFillColor*` with `TextOnAccentFillColorPrimary`.
/// The 16 px icon starts 12 px in, the label is 8 px after it with 12 px
/// on the right (AppBarButtonContentViewboxMargin 12, AppBarButtonTextLabelOnRightMargin 8,…,12).
/// AppBarSeparator is 1 px wide with margin 2,8,2,8. The "More" button opens
/// the secondary commands in a MenuFlyout at least 160 px wide (CommandBarOverflowMinWidth).
#[inline(never)]
pub fn command_bar(
    id: &'static str,
    primary: Vec<BarCommand>,
    overflow_open: bool,
    on_more: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    overflow: Option<AnyElement>,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let button = |bid: SharedString,
                  label: Option<&'static str>,
                  icon: &'static str,
                  toggled: Option<bool>,
                  cx: &App| {
        let on = toggled == Some(true);
        let (fill, hover, down, ink) = if on {
            (
                theme::accent_fill(ControlState::Rest, cx),
                theme::accent_fill(ControlState::Hover, cx),
                theme::accent_fill(ControlState::Pressed, cx),
                theme::text_on_accent(cx),
            )
        } else {
            (cx.theme().transparent, subtle, pressed, fg)
        };
        let group = SharedString::from(format!("appbar:{bid}"));
        let mut el = div()
            .id(bid)
            .test_support()
            .role(Role::Button)
            .aria_label(SharedString::from(label.unwrap_or("More options")))
            .group(group.clone())
            .h(px(48.))
            .px(px(2.))
            .py(px(6.))
            .child(
                div()
                    .id("appbar-button-fill")
                    .h_full()
                    .rounded(px(4.))
                    .bg(fill)
                    .group_hover(group.clone(), move |s| s.bg(hover))
                    .group_active(group.clone(), move |s| s.bg(down))
                    .ps(px(10.), cx)
                    .pe(px(10.), cx)
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(8.))
                    .text_size(px(14.))
                    .line_height(px(20.))
                    .text_color(ink)
                    .child(glyph(icon, 16., ink))
                    .children(label),
            );
        if let Some(t) = toggled {
            el = el.aria_toggled(if t { Toggled::True } else { Toggled::False });
        }
        el
    };
    let mut bar = div()
        .id(id)
        .test_support()
        .role(Role::Toolbar)
        .h(px(48.))
        .flex()
        .flex_row()
        .items_center();
    for command in primary {
        bar = bar.child(match command {
            BarCommand::Separator => div()
                .mx(px(2.))
                .my(px(8.))
                .w(px(1.))
                .h(px(32.))
                .bg(divider(cx))
                .into_any_element(),
            BarCommand::Button {
                id,
                label,
                icon,
                toggled,
                on_click,
            } => {
                let el = button(SharedString::from(id), Some(label), icon, toggled, cx)
                    .on_click(move |e, w, cx| on_click(e, w, cx));
                keyboard_focus(id, move |focus| el.track_focus(focus).into_any_element())
            }
        });
    }
    let more_id = SharedString::from(format!("{id}-more"));
    let more = button(
        more_id.clone(),
        None,
        "fluent/more-horizontal.svg",
        None,
        cx,
    )
    .aria_expanded(overflow_open)
    .on_click(on_more);
    let more = keyboard_focus(more_id, move |focus| {
        more.track_focus(focus).into_any_element()
    });
    div()
        .flex()
        .flex_col()
        .items_start()
        .child(bar.child(more))
        .children(overflow)
        .into_any_element()
}
