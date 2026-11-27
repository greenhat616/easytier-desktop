//! WinUI ContentDialog, Flyout and TeachingTip, shown in the Fluent gallery.
//! Values come from ContentDialog_themeresources, FlyoutPresenter_themeresources
//! and TeachingTip_themeresources in microsoft-ui-xaml, cited where used.

use std::rc::Rc;

use gpui_kit::{
    AnyElement, App, BoxShadow, Hsla, InteractiveElement as _, IntoElement, KeyDownEvent,
    ParentElement as _, PathBuilder, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, anchored,
    base::{FocusTrapElement as _, LogicalStyledExt as _},
    canvas,
    component::{
        ActiveTheme as _, Icon, Sizable as _, Size, StyledExt as _, button::ButtonVariant,
    },
    deferred, div, point, px, rgba,
};

use crate::theme;
use crate::views::controls::{
    DismissHandler, flyout_keys, flyout_surface, light_dismiss_layer, popup_focus,
};
use crate::views::ui::{BtnStyle, action_button, keyboard_focus};

/// Which ContentDialog button the user chose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogResult {
    Primary,
    Secondary,
    /// The close button, Escape, or the dialog being dismissed.
    None,
}

pub type DialogHandler = Rc<dyn Fn(DialogResult, &mut Window, &mut App)>;

/// `SolidBackgroundFillColorBase` (#F3F3F3 / #202020): ContentDialogBackground.
fn solid_base(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0xF3F3F3FF, 0x202020FF)
}

/// `SolidBackgroundFillColorTertiary` (#F9F9F9 / #282828): TeachingTipBackgroundBrush.
fn solid_tertiary(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0xF9F9F9FF, 0x282828FF)
}

/// `LayerFillColorAlt` (#FFFFFF / #0DFFFFFF): ContentDialogTopOverlay.
fn layer_alt(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0xFFFFFFFF, 0xFFFFFF0D)
}

/// `SurfaceStrokeColorDefault` (#66757575 in both themes): the border of
/// ContentDialog and TeachingTip.
fn surface_stroke() -> Hsla {
    rgba(0x75757566).into()
}

/// Fluent 2 shadow64 (0 0 8 and 0 32 64; 12 %/14 % black light, 24 %/28 %
/// dark), the depth WinUI gives dialogs.
fn shadow64(cx: &App) -> Vec<BoxShadow> {
    let dark = cx.theme().is_dark();
    let black = Hsla::from(gpui_kit::rgb(0));
    vec![
        BoxShadow {
            color: black.opacity(if dark { 0.24 } else { 0.12 }),
            offset: point(px(0.), px(0.)),
            blur_radius: px(8.),
            spread_radius: px(0.),
            inset: false,
        },
        BoxShadow {
            color: black.opacity(if dark { 0.28 } else { 0.14 }),
            offset: point(px(0.), px(32.)),
            blur_radius: px(64.),
            spread_radius: px(0.),
            inset: false,
        },
    ]
}

/// The buttons of a ContentDialog. `default` takes the accent style and
/// answers Enter (ContentDialog.DefaultButton).
pub struct DialogButtons {
    pub primary: Option<&'static str>,
    pub secondary: Option<&'static str>,
    pub close: &'static str,
    pub default: DialogResult,
}

/// WinUI ContentDialog (ContentDialog_themeresources.xaml) over a
/// `SmokeFillColorDefault` (#4D000000) layer that covers the window and
/// takes every press. The dialog is 320–548 px wide (ContentDialogMinWidth,
/// MaxWidth), at least 184 tall, with 8 px corners (OverlayCornerRadius)
/// and a 1 px `SurfaceStrokeColorDefault` border. The top part sits on
/// `LayerFillColorAlt` with 24 px padding (ContentDialogPadding) and a 1 px
/// `CardStrokeColorDefault` line below (ContentDialogSeparatorThickness);
/// the title is 20 px SemiBold, 12 px above the content
/// (ContentDialogTitleMargin). The button row has 24 px padding on
/// `SolidBackgroundFillColorBase` with equal-width buttons 8 px apart
/// (ContentDialogButtonSpacing). Tab stays inside the dialog, Escape
/// answers Close, Enter answers the default button, and focus goes back to
/// the opener when it closes.
#[inline(never)]
pub fn content_dialog(
    id: &'static str,
    title: &'static str,
    body: AnyElement,
    buttons: DialogButtons,
    on_result: DialogHandler,
) -> AnyElement {
    ContentDialog {
        id,
        title,
        body,
        buttons,
        on_result,
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct ContentDialog {
    id: &'static str,
    title: &'static str,
    body: AnyElement,
    buttons: DialogButtons,
    on_result: DialogHandler,
}

impl RenderOnce for ContentDialog {
    #[inline(never)]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let id = self.id;
        let viewport = window.viewport_size();
        let on_result = self.on_result;
        let default = self.buttons.default;
        let button = |bid: String, label: &'static str, result: DialogResult, cx: &App| {
            let on_result = on_result.clone();
            let variant = if result == default {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Default
            };
            let _ = cx;
            div().flex_1().min_w_0().child(action_button(
                SharedString::from(bid),
                label,
                BtnStyle::new(variant, Size::Medium).full_width(),
                move |_, window, cx| on_result(result, window, cx),
            ))
        };
        let mut row = div().flex().flex_row().gap(px(8.));
        if let Some(label) = self.buttons.primary {
            row = row.child(button(
                format!("{id}-primary"),
                label,
                DialogResult::Primary,
                cx,
            ));
        }
        if let Some(label) = self.buttons.secondary {
            row = row.child(button(
                format!("{id}-secondary"),
                label,
                DialogResult::Secondary,
                cx,
            ));
        }
        row = row.child(button(
            format!("{id}-close"),
            self.buttons.close,
            DialogResult::None,
            cx,
        ));
        let keys = on_result.clone();
        let dialog = div()
            .id(SharedString::from(format!("{id}-surface")))
            .test_support()
            .role(Role::Dialog)
            .aria_label(SharedString::from(self.title))
            .min_w(px(320.))
            .max_w(px(548.))
            .min_h(px(184.))
            .rounded(px(8.))
            .border_1()
            .border_color(surface_stroke())
            .bg(solid_base(cx))
            .shadow(shadow64(cx))
            .overflow_hidden()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex_1()
                    .p(px(24.))
                    .bg(layer_alt(cx))
                    .border_b_1()
                    .border_color(theme::card_stroke(cx))
                    .text_color(cx.theme().foreground)
                    .child(
                        div()
                            .mb(px(12.))
                            .text_size(px(20.))
                            .line_height(px(28.))
                            .font_semibold()
                            .child(self.title),
                    )
                    .child(
                        div()
                            .text_size(px(14.))
                            .line_height(px(20.))
                            .child(self.body),
                    ),
            )
            .child(div().p(px(24.)).child(row));
        let dialog = popup_focus(SharedString::from(format!("{id}-focus")), move |focus| {
            let own = focus.clone();
            let escape = keys.clone();
            div()
                // Escape answers Close wherever focus is in the dialog.
                .capture_key_down(move |event: &KeyDownEvent, window, cx| {
                    if event.keystroke.key == "escape" {
                        escape(DialogResult::None, window, cx);
                        cx.stop_propagation();
                    }
                })
                // Enter answers the default button unless a focused button
                // takes it itself.
                .on_key_down(move |event: &KeyDownEvent, window, cx| {
                    if event.keystroke.key == "enter" && own.is_focused(window) {
                        keys(default, window, cx);
                        cx.stop_propagation();
                    }
                })
                .child(dialog.focus_trap(id, focus))
                .into_any_element()
        });
        deferred(
            anchored().position(point(px(0.), px(0.))).child(
                div()
                    .id(SharedString::from(format!("{id}-smoke")))
                    .test_support()
                    .w(viewport.width)
                    .h(viewport.height)
                    .bg(gpui_kit::rgba(0x0000004D))
                    .occlude()
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(dialog),
            ),
        )
        .with_priority(4)
    }
}

/// WinUI Flyout (FlyoutPresenter_themeresources.xaml): the flyout surface
/// (Acrylic fallback, `SurfaceStrokeColorFlyout`, 8 px corners) with
/// FlyoutContentPadding 16,15,16,17, 96–456 px wide (FlyoutThemeMinWidth,
/// MaxWidth) and at least 40 tall. It light-dismisses, Escape closes it and
/// focus returns to the button that opened it.
#[inline(never)]
pub fn flyout_panel(
    id: &'static str,
    content: AnyElement,
    on_dismiss: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let on_dismiss: DismissHandler = Rc::new(on_dismiss);
    let layer = on_dismiss.clone();
    let surface = flyout_surface(cx)
        .id(id)
        .test_support()
        .role(Role::Dialog)
        .occlude()
        .mt(px(4.))
        .min_w(px(96.))
        .max_w(px(456.))
        .min_h(px(40.))
        .pt(px(15.))
        .pb(px(17.))
        .px(px(16.))
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(cx.theme().foreground)
        .child(content);
    div()
        .child(light_dismiss_layer(move |window, cx| layer(window, cx)))
        .child(
            deferred(
                anchored()
                    .snap_to_window_with_margin(px(8.))
                    .child(popup_focus(id, move |focus| {
                        flyout_keys(surface.track_focus(focus), on_dismiss).into_any_element()
                    })),
            )
            .with_priority(2),
        )
        .into_any_element()
}

/// WinUI TeachingTip (TeachingTip_themeresources.xaml) placed below its
/// target: `SolidBackgroundFillColorTertiary` with a 1 px
/// `SurfaceStrokeColorDefault` border and 8 px corners, 320–336 px wide
/// (TeachingTipMinWidth/MaxWidth), 12 px content margin. The tail is a
/// 16×8 triangle (TeachingTipTailShortSideLength 8) overlapping the border
/// by 1 px (TeachingTipTailPolygonMarginTop 0,-1,0,0). The title is 14 px
/// SemiBold and the subtitle 14 px, kept 28 px clear of the 40×40 close
/// button (TeachingTipTitleStackPanelMarginWithHeaderCloseButton,
/// TeachingTipAlternateCloseButtonSize, 16 px glyph, SubtleFill
/// transparent / secondary / tertiary). The action button follows 12 px
/// below (TeachingTipButtonPanelMargin). A tip is not light-dismissed:
/// it stays until closed by its button or Escape.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn teaching_tip(
    id: &'static str,
    title: &'static str,
    subtitle: &'static str,
    action: Option<AnyElement>,
    on_close: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let fill = solid_tertiary(cx);
    let stroke = surface_stroke();
    let on_close: DismissHandler = Rc::new(on_close);
    let close_click = on_close.clone();
    let subtle = theme::subtle_fill_secondary(cx);
    let pressed = theme::subtle_fill_tertiary(cx);
    let close_id = SharedString::from(format!("{id}-close"));
    let close = div()
        .id(close_id.clone())
        .test_support()
        .role(Role::Button)
        .aria_label(SharedString::from("Close"))
        .size(px(40.))
        .rounded(px(4.))
        .flex()
        .items_center()
        .justify_center()
        .hover(move |s| s.bg(subtle))
        .active(move |s| s.bg(pressed))
        .on_click(move |_, window, cx| close_click(window, cx))
        .child(
            Icon::default()
                .path("fluent/dismiss.svg")
                .with_size(Size::Size(px(16.)))
                .text_color(cx.theme().foreground),
        );
    let tail = canvas(
        |_, _, _| {},
        move |bounds, _, window, _| {
            let o = bounds.origin;
            // The fill reaches 1 px further down to cover the card's top
            // border under the tail; the stroked edges stop at the border.
            let mut fill_path = PathBuilder::fill();
            fill_path.move_to(point(o.x, o.y + px(10.)));
            fill_path.line_to(point(o.x, o.y + px(9.)));
            fill_path.line_to(point(o.x + px(8.), o.y + px(1.)));
            fill_path.line_to(point(o.x + px(16.), o.y + px(9.)));
            fill_path.line_to(point(o.x + px(16.), o.y + px(10.)));
            fill_path.close();
            if let Ok(path) = fill_path.build() {
                window.paint_path(path, fill);
            }
            let mut edge = PathBuilder::stroke(px(1.));
            edge.move_to(point(o.x, o.y + px(9.)));
            edge.line_to(point(o.x + px(8.), o.y + px(1.)));
            edge.line_to(point(o.x + px(16.), o.y + px(9.)));
            if let Ok(path) = edge.build() {
                window.paint_path(path, stroke);
            }
        },
    )
    .absolute()
    .top(px(-9.))
    .left(px(20.))
    .w(px(16.))
    .h(px(10.));
    let keys = on_close.clone();
    let tip = div()
        .id(id)
        .test_support()
        .role(Role::Dialog)
        .aria_label(SharedString::from(title))
        .relative()
        .mt(px(12.))
        .min_w(px(320.))
        .max_w(px(336.))
        .rounded(px(8.))
        .border_1()
        .border_color(stroke)
        .bg(fill)
        .shadow(shadow16(cx))
        .p(px(12.))
        .text_size(px(14.))
        .line_height(px(20.))
        .text_color(cx.theme().foreground)
        .on_key_down(move |event: &KeyDownEvent, window, cx| {
            if event.keystroke.key == "escape" {
                keys(window, cx);
                cx.stop_propagation();
            }
        })
        .child(tail)
        .child(
            div()
                .absolute()
                .top(px(0.))
                .right(px(0.))
                .child(keyboard_focus(close_id, move |focus| {
                    use gpui_kit::InteractiveElement as _;
                    close.track_focus(focus).into_any_element()
                })),
        )
        .child(
            div()
                .me(px(28.), cx)
                .flex()
                .flex_col()
                .child(div().font_semibold().child(title))
                .child(div().child(subtitle)),
        )
        .children(action.map(|a| div().mt(px(12.)).child(a)));
    // Wrapped like the flyouts so the popup anchors below its target.
    div()
        .child(deferred(anchored().snap_to_window_with_margin(px(8.)).child(tip)).with_priority(1))
        .into_any_element()
}

/// Fluent 2 shadow16, as on menus and flyouts.
fn shadow16(cx: &App) -> Vec<BoxShadow> {
    let dark = cx.theme().is_dark();
    let black = Hsla::from(gpui_kit::rgb(0));
    vec![
        BoxShadow {
            color: black.opacity(if dark { 0.24 } else { 0.12 }),
            offset: point(px(0.), px(0.)),
            blur_radius: px(2.),
            spread_radius: px(0.),
            inset: false,
        },
        BoxShadow {
            color: black.opacity(if dark { 0.28 } else { 0.14 }),
            offset: point(px(0.), px(8.)),
            blur_radius: px(16.),
            spread_radius: px(0.),
            inset: false,
        },
    ]
}
