//! WinUI layout pieces shown in the Fluent gallery: Expander and a
//! ScrollViewer with the Fluent scroll bar. Values come from
//! `Expander_themeresources.xaml`, `Expander.xaml` and
//! `ScrollBar_themeresources.xaml` in microsoft-ui-xaml, cited where used.
//! StackPanel and Grid need no control of their own: the gallery lays them
//! out with flex and grid styles, the way WinUI Gallery demonstrates them.

use gpui_kit::{
    AnyElement, App, Hsla, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    ScrollHandle, SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    Window,
    base::LogicalStyledExt as _,
    component::{ActiveTheme as _, Icon, Sizable as _, Size, scroll::Scrollbar},
    div, px,
};

use crate::theme;
use crate::views::controls::Handler;
use crate::views::ui::keyboard_focus;

/// `ControlStrongFillColorDefault` (#72000000 / #8BFFFFFF): the scroll bar
/// thumb (ScrollBarThumbFill, ScrollBarPanningThumbBackground).
pub(crate) fn scroll_thumb(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0x00000072, 0xFFFFFF8B)
}

/// The fallback of `AcrylicInAppFillColorDefault` (#F9F9F9 / #2C2C2C,
/// Acrylic.xaml): the scroll bar track while it is expanded.
fn acrylic_in_app_fallback(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0xF9F9F9FF, 0x2C2C2CFF)
}

/// WinUI Expander (Expander.xaml, Expander_themeresources.xaml). The header
/// is one toggle button at least 48 tall (ExpanderMinHeight) with 16 px
/// start padding (ExpanderHeaderPadding 16,0,0,0) on
/// `CardBackgroundFillColorDefault` with a 1 px `CardStrokeColorDefault`
/// border and 4 px corners (ControlCornerRadius). At its end sits a 32×32
/// chevron button (ExpanderChevronButtonSize) with 20,0,8,0 margin
/// (ExpanderChevronMargin) and a 12 px E70D/E70E glyph
/// (ExpanderChevronGlyphSize); pointing at the header fills it with
/// `SubtleFillColorSecondary`, pressing with `…Tertiary`. Open, the header
/// keeps its top corners and the content hangs below on
/// `CardBackgroundFillColorSecondary` with a 1,0,1,1 border
/// (ExpanderContentDownBorderThickness), 16 px padding
/// (ExpanderContentPadding) and the bottom corners.
#[inline(never)]
pub fn expander(
    id: &'static str,
    header: impl Into<SharedString>,
    content: AnyElement,
    expanded: bool,
    on_toggle: Handler,
    cx: &App,
) -> AnyElement {
    let header = header.into();
    let stroke = theme::card_stroke(cx);
    let subtle = theme::subtle_fill_secondary(cx);
    let subtle_pressed = theme::subtle_fill_tertiary(cx);
    let fg = cx.theme().foreground;
    let group = SharedString::from(format!("fluent-expander:{id}"));
    let chevron = div()
        .id(SharedString::from(format!("{id}-chevron")))
        .flex_shrink_0()
        .ms(px(20.), cx)
        .me(px(8.), cx)
        .size(px(32.))
        .rounded(px(4.))
        .flex()
        .items_center()
        .justify_center()
        .group_hover(group.clone(), move |s| s.bg(subtle))
        .group_active(group.clone(), move |s| s.bg(subtle_pressed))
        .child(
            Icon::default()
                .path(if expanded {
                    "fluent/chevron-up.svg"
                } else {
                    "fluent/chevron-down.svg"
                })
                .with_size(Size::Size(px(12.)))
                .text_color(fg),
        );
    let head_id = SharedString::from(format!("{id}-header"));
    let mut head = div()
        .id(head_id.clone())
        .test_support()
        .role(Role::Button)
        .aria_label(header.clone())
        .aria_expanded(expanded)
        .group(group)
        .on_click(move |event, window, cx| on_toggle(event, window, cx))
        .w_full()
        .min_h(px(48.))
        .ps(px(16.), cx)
        .border_1()
        .border_color(stroke)
        .bg(theme::card_fill(cx))
        .flex()
        .flex_row()
        .items_center()
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(fg)
        .child(div().flex_1().min_w_0().child(header))
        .child(chevron);
    head = if expanded {
        head.rounded_t(px(4.))
    } else {
        head.rounded(px(4.))
    };
    let head = keyboard_focus(head_id, move |focus| {
        head.track_focus(focus).into_any_element()
    });
    div()
        .id(id)
        .test_support()
        .w_full()
        .min_w(px(96.))
        .flex()
        .flex_col()
        .child(head)
        .children(expanded.then(|| {
            div()
                .id(SharedString::from(format!("{id}-content")))
                .test_support()
                .w_full()
                .p(px(16.))
                .rounded_b(px(4.))
                .border_1()
                .border_t_0()
                .border_color(stroke)
                .bg(theme::card_fill_secondary(cx))
                .text_size(px(14.))
                .line_height(px(20.))
                .text_color(fg)
                .child(content)
        }))
        .into_any_element()
}

/// A vertical WinUI ScrollViewer with the Fluent scroll bar
/// (ScrollBar_themeresources.xaml). At rest the thumb is a 2 px line
/// (ScrollBarVerticalThumbMinWidth 8 less the 6 px
/// ScrollBarThumbStrokeThickness), 2 px in from the edge
/// (ScrollBarThumbOffset); pointing at the bar widens the track to 12 px
/// (ScrollBarSize) on `AcrylicInAppFillColorDefault` and the thumb to 6 px.
/// The thumb is `ControlStrongFillColorDefault`, 3 px corners
/// (ScrollBarCornerRadius) and at least 30 long
/// (ScrollBarVerticalThumbMinHeight).
#[inline(never)]
pub fn scroll_viewer(
    id: &'static str,
    height: f32,
    content: AnyElement,
    window: &mut Window,
    cx: &mut App,
) -> AnyElement {
    let handle = window
        .use_keyed_state(
            SharedString::from(format!("{id}-fluent-scroll")),
            cx,
            |_, _| ScrollHandle::default(),
        )
        .read(cx)
        .clone();
    let thumb = scroll_thumb(cx);
    let track = acrylic_in_app_fallback(cx);
    let transparent = gpui_kit::transparent_black();
    div()
        .id(id)
        .test_support()
        .relative()
        .h(px(height))
        .w_full()
        .child(
            div()
                .id(SharedString::from(format!("{id}-area")))
                .test_support()
                .size_full()
                .overflow_y_scroll()
                .track_scroll(&handle)
                .child(content),
        )
        .child(
            div().absolute().inset_0().child(
                Scrollbar::vertical(&handle)
                    .id(SharedString::from(format!("{id}-bar")))
                    .viewport_from_layout()
                    .styles(|s| {
                        s.track(|t| t.bg(transparent).width(px(12.)))
                            .track_hover(|t| t.bg(track).width(px(12.)))
                            .track_active(|t| t.bg(track).width(px(12.)))
                            .thumb(|t| {
                                t.bg(thumb)
                                    .width(px(2.))
                                    .inset(px(2.))
                                    .radius(px(3.))
                                    .min_length(px(30.))
                            })
                            .thumb_hover(|t| t.bg(thumb).width(px(6.)).inset(px(3.)))
                            .thumb_active(|t| t.bg(thumb).width(px(6.)).inset(px(3.)))
                    }),
            ),
        )
        .into_any_element()
}
