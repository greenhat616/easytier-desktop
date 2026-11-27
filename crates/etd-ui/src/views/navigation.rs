//! WinUI NavigationView items with expandable groups, BreadcrumbBar,
//! SelectorBar and TabView, shown in the Fluent gallery. Values come from
//! the NavigationView, BreadcrumbBar, SelectorBar and TabView theme
//! resources and templates in microsoft-ui-xaml, cited where used.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, ElementId, Hsla, InteractiveElement as _, IntoElement, ParentElement as _,
    Role, SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    base::LogicalStyledExt as _,
    component::{ActiveTheme as _, Icon, Sizable as _, Size},
    div, px,
};

use crate::theme::{self, ControlState};
use crate::views::ui::keyboard_focus;

pub type IndexHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

fn glyph(path: &'static str, size: f32, color: Hsla) -> Icon {
    Icon::default()
        .path(path)
        .with_size(Size::Size(px(size)))
        .text_color(color)
}

/// `TextFillColorTertiary` (#72000000 / #87FFFFFF): pressed text in
/// BreadcrumbBar and SelectorBar.
fn text_tertiary(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0x00000072, 0xFFFFFF87)
}

/// `DividerStrokeColorDefault` (#0F000000 / #15FFFFFF).
fn divider(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0x0000000F, 0xFFFFFF15)
}

/// One NavigationView item in the left pane (NavigationView_themeresources):
/// at least 36 px tall (NavigationViewItemOnLeftMinHeight) with a 4,2 margin
/// (NavigationViewItemButtonMargin) and 4 px corners; the 16 px icon is
/// centred in the 40 px compact column and the label starts 4 px after it
/// (NavigationViewItemContentPresenterMargin 4,-1,8,-1). Each nesting level
/// indents 31 px (NavigationView.h c_itemIndentation). A group shows the
/// E70D chevron at 8 px (NavigationViewItemExpandedGlyph,
/// NavigationViewItemExpandedGlyphFontSize). Hover and pressed take
/// `SubtleFillColorSecondary` / `Tertiary`; the selected item keeps the
/// secondary fill with a 3×16 accent pill, 2 px corners
/// (NavigationViewSelectionIndicatorWidth/Height/Radius).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn nav_view_item(
    id: impl Into<ElementId>,
    icon: Option<&'static str>,
    label: &'static str,
    depth: usize,
    selected: bool,
    expanded: Option<bool>,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let id = id.into();
    let key = id.clone();
    let fg = cx.theme().foreground;
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let mut item = div()
        .id(id)
        .test_support()
        .role(Role::TreeItem)
        .aria_label(SharedString::from(label))
        .aria_selected(selected)
        .relative()
        .mx(px(4.))
        .my(px(2.))
        .min_h(px(36.))
        .rounded(px(4.))
        .flex()
        .flex_row()
        .items_center()
        .ps(px(31. * depth as f32), cx)
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(fg)
        .hover(move |s| s.bg(subtle))
        .active(move |s| s.bg(pressed))
        .on_click(move |_, window, cx| on_click(window, cx))
        .child(
            div()
                .flex_shrink_0()
                .w(px(40.))
                .flex()
                .justify_center()
                .children(icon.map(|i| glyph(i, 16., fg))),
        )
        .child(div().flex_1().min_w_0().ms(px(4.), cx).child(label));
    if let Some(open) = expanded {
        item = item
            .aria_expanded(open)
            .child(div().w(px(32.)).flex().justify_center().child(glyph(
                if open {
                    "fluent/chevron-up.svg"
                } else {
                    "fluent/chevron-down.svg"
                },
                8.,
                fg,
            )));
    }
    if selected {
        item = item.bg(subtle).child(
            div()
                .absolute()
                .left_0()
                .top(px(10.))
                .w(px(3.))
                .h(px(16.))
                .rounded(px(2.))
                .bg(theme::accent_fill(ControlState::Rest, cx)),
        );
    }
    keyboard_focus(key, move |focus| item.track_focus(focus).into_any_element())
}

/// WinUI BreadcrumbBar (BreadcrumbBar.xaml, BreadcrumbBar_themeresources):
/// 14 px items, line height 20, 1,3 padding, `TextFillColorPrimary` that
/// turns `TextFillColorSecondary` on hover and `TextFillColorTertiary`
/// pressed; each is followed by the E974 chevron at 12 px with 2,0 padding
/// (BreadcrumbBarChevronFontSize, BreadcrumbBarChevronPadding). The last
/// item is the current location and is not a button.
#[inline(never)]
pub fn breadcrumb_bar(
    id: &'static str,
    items: &[&'static str],
    on_click: IndexHandler,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let hover = theme::text_secondary(cx);
    let pressed = text_tertiary(cx);
    let last = items.len().saturating_sub(1);
    let mut bar = div()
        .id(id)
        .test_support()
        .role(Role::Navigation)
        .flex()
        .flex_row()
        .flex_wrap()
        .items_center()
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(fg);
    for (ix, label) in items.iter().enumerate() {
        let item_id = SharedString::from(format!("{id}-{ix}"));
        if ix == last {
            bar = bar.child(
                div()
                    .id(item_id)
                    .test_support()
                    .aria_label(SharedString::from(*label))
                    .px(px(1.))
                    .py(px(3.))
                    .child(*label),
            );
            continue;
        }
        let on_click = on_click.clone();
        let crumb = div()
            .id(item_id.clone())
            .test_support()
            .role(Role::Link)
            .aria_label(SharedString::from(*label))
            .px(px(1.))
            .py(px(3.))
            .rounded(px(4.))
            .hover(move |s| s.text_color(hover))
            .active(move |s| s.text_color(pressed))
            .on_click(move |_, window, cx| on_click(ix, window, cx))
            .child(*label);
        bar = bar
            .child(keyboard_focus(item_id, move |focus| {
                crumb.track_focus(focus).into_any_element()
            }))
            .child(div().px(px(2.)).flex().items_center().child(glyph(
                "fluent/chevron-right.svg",
                12.,
                fg,
            )));
    }
    bar.into_any_element()
}

/// WinUI SelectorBar (SelectorBar.xaml, SelectorBar_themeresources): 0,4
/// padding, items with 12,10,12,7 padding (SelectorBarItemPadding) and 4 px
/// corners, 14 px text that turns `TextFillColorSecondary` on hover and
/// `TextFillColorTertiary` pressed. The selected item shows the accent
/// pill at its bottom centre: 4×3 scaled ×4 to 16×3
/// (SelectorBarItemPillWidth/Height, PillTransform ScaleX 4).
#[inline(never)]
pub fn selector_bar(
    id: &'static str,
    items: &[&'static str],
    selected: usize,
    on_select: IndexHandler,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let hover = theme::text_secondary(cx);
    let pressed = text_tertiary(cx);
    let accent = theme::accent_fill(ControlState::Rest, cx);
    let mut bar = div()
        .id(id)
        .test_support()
        .role(Role::TabList)
        .py(px(4.))
        .flex()
        .flex_row()
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(fg);
    for (ix, label) in items.iter().enumerate() {
        let on_select = on_select.clone();
        let item_id = SharedString::from(format!("{id}-{ix}"));
        let is_selected = ix == selected;
        let item = div()
            .id(item_id.clone())
            .test_support()
            .role(Role::Tab)
            .aria_label(SharedString::from(*label))
            .aria_selected(is_selected)
            .relative()
            .pt(px(10.))
            .pb(px(7.))
            .px(px(12.))
            .rounded(px(4.))
            .hover(move |s| s.text_color(hover))
            .active(move |s| s.text_color(pressed))
            .on_click(move |_, window, cx| on_select(ix, window, cx))
            .child(*label)
            .children(is_selected.then(|| {
                div()
                    .absolute()
                    .bottom_0()
                    .left_0()
                    .right_0()
                    .flex()
                    .justify_center()
                    .child(div().w(px(16.)).h(px(3.)).rounded(px(1.)).bg(accent))
            }));
        bar = bar.child(keyboard_focus(item_id, move |focus| {
            item.track_focus(focus).into_any_element()
        }));
    }
    bar.into_any_element()
}

/// One tab of a [`tab_view`].
pub struct Tab {
    pub label: &'static str,
    pub icon: &'static str,
}

/// WinUI TabView (TabView.xaml, TabView_themeresources): the strip has 8 px
/// top padding (TabViewHeaderPadding); tabs are 100–240 px wide and at least
/// 32 tall (TabViewItemMinWidth/MaxWidth/MinHeight) with 8,3,4,3 padding, a
/// 16 px icon 10 px before 12 px text (TabViewItemHeaderIconSize,
/// HeaderIconMargin, HeaderFontSize) and a 32×24 close button with a 12 px
/// glyph (TabViewItemHeaderCloseButtonWidth/Height, CloseFontSize).
/// Unselected tabs are transparent, `LayerOnMicaBaseAltFillColorSecondary`
/// on hover and `…Default` pressed, divided by 1 px `DividerStrokeColorDefault`
/// lines with 8 px vertical margin (TabViewItemSeparatorMargin). The
/// selected tab is `SolidBackgroundFillColorTertiary` with
/// `CardStrokeColorDefault` on its top and sides, 8 px top corners
/// (OverlayCornerRadius), and joins the content below. The add button is
/// 32×24 with a 12 px glyph (TabViewItemAddButtonWidth/Height/FontSize).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn tab_view(
    id: &'static str,
    tabs: &[Tab],
    selected: usize,
    on_select: IndexHandler,
    on_close: IndexHandler,
    on_add: impl Fn(&mut Window, &mut App) + 'static,
    content: AnyElement,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let hover = theme::winui_brush(cx, 0x0000000A, 0xFFFFFF0F);
    let pressed = theme::winui_brush(cx, 0xFFFFFFB3, 0x3A3A3A73);
    let tertiary = crate::views::dialogs::solid_tertiary(cx);
    let stroke = theme::card_stroke(cx);
    let subtle = theme::subtle_fill_secondary(cx);
    let subtle_pressed = theme::subtle_fill_tertiary(cx);
    let small_button = |bid: SharedString, label: &'static str, glyph_path: &'static str| {
        div()
            .id(bid)
            .test_support()
            .role(Role::Button)
            .aria_label(SharedString::from(label))
            .flex_shrink_0()
            .w(px(32.))
            .h(px(24.))
            .rounded(px(4.))
            .flex()
            .items_center()
            .justify_center()
            .hover(move |s| s.bg(subtle))
            .active(move |s| s.bg(subtle_pressed))
            .child(glyph(glyph_path, 12., fg))
    };
    let mut strip = div()
        .id(SharedString::from(format!("{id}-strip")))
        .test_support()
        .role(Role::TabList)
        .pt(px(8.))
        .flex()
        .flex_row()
        .items_end();
    for (ix, tab) in tabs.iter().enumerate() {
        let is_selected = ix == selected;
        // The divider sits between two unselected tabs.
        if ix > 0 && !is_selected && ix - 1 != selected {
            strip = strip.child(
                div()
                    .border_b_1()
                    .border_color(stroke)
                    .child(div().my(px(8.)).w(px(1.)).h(px(16.)).bg(divider(cx))),
            );
        } else if ix > 0 {
            strip = strip.child(
                div()
                    .self_stretch()
                    .w(px(1.))
                    .border_b_1()
                    .border_color(stroke),
            );
        }
        let tab_id = SharedString::from(format!("{id}-{ix}"));
        let close_id = SharedString::from(format!("{id}-{ix}-close"));
        let on_select = on_select.clone();
        let on_close = on_close.clone();
        let close = small_button(close_id.clone(), "Close tab", "fluent/dismiss.svg").on_click(
            move |_, window, cx| {
                cx.stop_propagation();
                on_close(ix, window, cx)
            },
        );
        let mut header = div()
            .id(tab_id.clone())
            .test_support()
            .role(Role::Tab)
            .aria_label(SharedString::from(tab.label))
            .aria_selected(is_selected)
            .min_w(px(100.))
            .max_w(px(240.))
            .min_h(px(32.))
            .ps(px(8.), cx)
            .pe(px(4.), cx)
            .py(px(3.))
            .rounded_t(px(8.))
            .flex()
            .flex_row()
            .items_center()
            .text_size(px(12.))
            .line_height(px(16.))
            .text_color(fg)
            .on_click(move |_, window, cx| on_select(ix, window, cx))
            .child(div().me(px(10.), cx).child(glyph(tab.icon, 16., fg)))
            .child(div().flex_1().min_w_0().truncate().child(tab.label))
            .child(div().ms(px(4.), cx).child(close));
        header = if is_selected {
            header
                .bg(tertiary)
                .border_1()
                .border_b_0()
                .border_color(stroke)
        } else {
            header
                .border_b_1()
                .border_color(stroke)
                .hover(move |s| s.bg(hover))
                .active(move |s| s.bg(pressed))
        };
        strip = strip.child(keyboard_focus(tab_id, move |focus| {
            header.track_focus(focus).into_any_element()
        }));
    }
    let add_id = SharedString::from(format!("{id}-add"));
    let add = small_button(add_id.clone(), "Add tab", "fluent/add.svg")
        .on_click(move |_, window, cx| on_add(window, cx));
    strip = strip
        .child(
            div()
                .ps(px(3.), cx)
                .pb(px(3.))
                .border_b_1()
                .border_color(stroke)
                .child(keyboard_focus(add_id, move |focus| {
                    add.track_focus(focus).into_any_element()
                })),
        )
        // The strip's bottom line runs on to the right edge; only the selected
        // tab has none, so it joins the content.
        .child(
            div()
                .flex_1()
                .self_stretch()
                .border_b_1()
                .border_color(stroke),
        );
    div()
        .id(id)
        .test_support()
        .flex()
        .flex_col()
        .child(strip)
        .child(
            div()
                .id(SharedString::from(format!("{id}-content")))
                .test_support()
                .role(Role::TabPanel)
                .p(px(16.))
                .min_h(px(120.))
                .bg(tertiary)
                .border_1()
                .border_t_0()
                .border_color(stroke)
                .rounded_b(px(8.))
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(fg)
                .child(content),
        )
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use gpui_kit::{Hsla, TestAppContext, component::ActiveTheme as _};

    use crate::theme::{self, ControlState, contrast};
    use crate::views::dialogs;

    /// `top` composited over the opaque `bottom`, as 0xRRGGBB.
    fn over(top: Hsla, bottom: Hsla) -> u32 {
        let (t, b) = (top.to_rgb(), bottom.to_rgb());
        let mix = |a: f32, z: f32| ((a * t.a + z * (1. - t.a)).clamp(0., 1.) * 255.).round() as u32;
        mix(t.r, b.r) << 16 | mix(t.g, b.g) << 8 | mix(t.b, b.b)
    }

    /// Text in the FL5 gallery controls meets WCAG AA (4.5:1) on the fills
    /// it sits on, and the accent selection pills and the scroll bar thumb
    /// reach 3:1 against theirs.
    /// Pressed text (TextFillColorTertiary) is a momentary WinUI state and
    /// disabled text is exempt, so neither is checked.
    #[gpui_kit::test]
    fn fl5_text_and_fills_are_readable_in_both_themes(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            theme::install_palette(cx);
            for mode in [
                gpui_kit::component::ThemeMode::Light,
                gpui_kit::component::ThemeMode::Dark,
            ] {
                gpui_kit::component::Theme::change(mode, None, cx);
                let fg = cx.theme().foreground;
                let page = cx.theme().background;
                let card = cx.theme().popover;
                let base = dialogs::solid_base(cx);
                let tertiary = dialogs::solid_tertiary(cx);
                let layer = over(dialogs::layer_alt(cx), base);
                let accent = theme::accent_fill(ControlState::Rest, cx);
                for surface in [page, card] {
                    let selected = over(theme::subtle_fill_secondary(cx), surface);
                    let pairs = [
                        ("text on surface", over(fg, surface), over(surface, surface)),
                        (
                            "secondary text",
                            over(theme::text_secondary(cx), surface),
                            over(surface, surface),
                        ),
                        ("selected nav item", over(fg, surface), selected),
                        (
                            "Expander content",
                            over(fg, surface),
                            over(theme::card_fill_secondary(cx), surface),
                        ),
                        (
                            "Expander header",
                            over(fg, surface),
                            over(theme::card_fill(cx), surface),
                        ),
                    ];
                    for (what, text, fill) in pairs {
                        assert!(contrast(text, fill) >= 4.5, "{what} {mode:?}");
                    }
                    assert!(
                        contrast(over(accent, surface), selected) >= 3.,
                        "nav pill {mode:?}"
                    );
                    assert!(
                        contrast(over(accent, surface), over(surface, surface)) >= 3.,
                        "SelectorBar pill {mode:?}"
                    );
                    assert!(
                        contrast(
                            over(crate::views::layout::scroll_thumb(cx), surface),
                            over(surface, surface)
                        ) >= 3.,
                        "scroll bar thumb {mode:?}"
                    );
                }
                for (what, fill) in [
                    ("dialog body", layer),
                    ("dialog buttons", over(base, base)),
                    ("TabView / TeachingTip", over(tertiary, tertiary)),
                ] {
                    assert!(
                        contrast(over(fg, fill_hsla(fill)), fill) >= 4.5,
                        "{what} {mode:?}"
                    );
                }
            }
        });
    }

    fn fill_hsla(rgb: u32) -> Hsla {
        gpui_kit::rgb(rgb).into()
    }
}
