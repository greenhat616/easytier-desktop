//! WinUI feedback pieces for the Fluent gallery: ToolTip, a status badge,
//! and a copy button that confirms the copy. Values come from the WinUI
//! source and theme resources, cited where used.

use std::time::Duration;

use gpui_kit::{
    AnyElement, AnyView, App, ClipboardItem, ElementId, Hsla, InteractiveElement as _, IntoElement,
    ParentElement as _, RenderOnce, Role, SharedString, StatefulInteractiveElement as _,
    Styled as _, TestSupportExt as _, Window, anchored,
    component::{ActiveTheme as _, Icon, Sizable as _, Size, tooltip::Tooltip},
    deferred, div, px,
};

use crate::theme;
use crate::views::ui::keyboard_focus;

/// How long the pointer rests before a ToolTip opens: twice
/// SPI_GETMOUSEHOVERTIME, whose default is 400 ms
/// (ToolTipService_Partial.cpp GetInitialShowDelay, mouse, first show).
pub const TOOLTIP_SHOW_DELAY: Duration = Duration::from_millis(800);

/// How long a copy button keeps saying "Copied".
const COPIED_FOR: Duration = Duration::from_secs(2);

/// The fallback of `AcrylicInAppFillColorDefault` (#F9F9F9 / #2C2C2C,
/// Acrylic.xaml).
fn acrylic_in_app(cx: &App) -> Hsla {
    theme::winui_brush(cx, 0xF9F9F9FF, 0x2C2C2CFF)
}

/// A WinUI ToolTip (ToolTip_themeresources.xaml): 12 px text
/// (ToolTipContentThemeFontSize) on `AcrylicInAppFillColorDefault` with a
/// 1 px `SurfaceStrokeColorFlyout` border, 4 px corners
/// (ControlCornerRadius), 9,6,9,8 padding (ToolTipBorderPadding) and at
/// most 320 px wide (ToolTipMaxWidth), wrapping longer text.
pub fn fluent_tooltip(
    text: impl Into<SharedString>,
) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text: SharedString = text.into();
    move |window, cx| {
        Tooltip::new(text.clone())
            .bg(acrylic_in_app(cx))
            .border_color(theme::flyout_stroke(cx))
            .text_color(cx.theme().foreground)
            .rounded(px(4.))
            .pt(px(6.))
            .pb(px(8.))
            .px(px(9.))
            .max_w(px(320.))
            .text_size(px(12.))
            .line_height(px(16.))
            .build(window, cx)
    }
}

/// The meaning a [`status_badge`] carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Success,
    Caution,
    Critical,
    Informational,
    Neutral,
}

/// The dot and background for each status, from InfoBar's severity tokens
/// (InfoBar_themeresources.xaml): `SystemFillColor{Success,Caution,
/// Critical}` for the dot on `SystemFillColor{…}Background`; Informational
/// uses `AccentFillColorDefault` on `SystemFillColorAttentionBackground`,
/// Neutral `SystemFillColorSolidNeutral` on
/// `SystemFillColorNeutralBackground` (Common_themeresources_any.xaml).
pub(crate) fn status_colors(status: Status, cx: &App) -> (Hsla, Hsla) {
    let brush = |light: u32, dark: u32| theme::winui_brush(cx, light, dark);
    match status {
        Status::Success => (brush(0x0F7B0FFF, 0x6CCB5FFF), brush(0xDFF6DDFF, 0x393D1BFF)),
        Status::Caution => (brush(0x9D5D00FF, 0xFCE100FF), brush(0xFFF4CEFF, 0x433519FF)),
        Status::Critical => (brush(0xC42B1CFF, 0xFF99A4FF), brush(0xFDE7E9FF, 0x442726FF)),
        Status::Informational => (
            theme::accent_fill(theme::ControlState::Rest, cx),
            brush(0xF6F6F680, 0xFFFFFF08),
        ),
        Status::Neutral => (brush(0x8A8A8AFF, 0x9D9D9DFF), brush(0x00000006, 0xFFFFFF08)),
    }
}

/// A status badge: an 8 px dot (InfoBadgeIconHeight 8) and Caption text
/// (12/16, TextFillColorPrimary) in a pill on the status background. The
/// text is whatever the caller passes, already translated, so compound
/// text such as "18 ms · Direct" stays one string; long text truncates
/// with an ellipsis and shows in full in a tooltip.
pub fn status_badge(
    id: impl Into<ElementId>,
    status: Status,
    text: impl Into<SharedString>,
    cx: &App,
) -> AnyElement {
    let text: SharedString = text.into();
    let (dot, fill) = status_colors(status, cx);
    div()
        .id(id)
        .test_support()
        .role(Role::Status)
        .aria_label(text.clone())
        .tooltip(fluent_tooltip(text.clone()))
        .tooltip_show_delay(TOOLTIP_SHOW_DELAY)
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.))
        .min_w_0()
        .max_w_full()
        .px(px(8.))
        .py(px(2.))
        .rounded_full()
        .bg(fill)
        .text_size(px(12.))
        .line_height(px(16.))
        .text_color(cx.theme().foreground)
        .child(div().flex_shrink_0().size(px(8.)).rounded_full().bg(dot))
        .child(div().min_w_0().truncate().child(text))
        .into_any_element()
}

/// A copy button: a 32×32 subtle button with the 16 px Copy glyph whose
/// translated `label` is both its accessible name and its tooltip. A press
/// or Enter/Space writes `value` to the clipboard, swaps the glyph to a
/// checkmark and shows a tooltip-styled "Copied" note under the button for
/// two seconds (WinUI Gallery's copy buttons confirm the same way).
pub fn copy_button(
    id: &'static str,
    label: impl Into<SharedString>,
    copied: impl Into<SharedString>,
    value: impl Into<SharedString>,
) -> AnyElement {
    CopyButton {
        id,
        label: label.into(),
        copied: copied.into(),
        value: value.into(),
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct CopyButton {
    id: &'static str,
    label: SharedString,
    copied: SharedString,
    value: SharedString,
}

/// When the button last copied; `None` once the note has gone.
struct CopyState {
    copied_at: Option<std::time::Instant>,
}

impl RenderOnce for CopyButton {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let id = self.id;
        let state = window.use_keyed_state(
            SharedString::from(format!("{id}-copy-state")),
            cx,
            |_, _| CopyState { copied_at: None },
        );
        let now = cx.background_executor().now();
        let showing = state
            .read(cx)
            .copied_at
            .is_some_and(|at| now.saturating_duration_since(at) < COPIED_FOR);
        let fg = cx.theme().foreground;
        let subtle = theme::subtle_fill_secondary(cx);
        let pressed = theme::subtle_fill_tertiary(cx);
        let value = self.value.clone();
        let on_copy = state.clone();
        let button = div()
            .id(id)
            .test_support()
            .role(Role::Button)
            .aria_label(if showing {
                self.copied.clone()
            } else {
                self.label.clone()
            })
            .tooltip(fluent_tooltip(self.label.clone()))
            .tooltip_show_delay(TOOLTIP_SHOW_DELAY)
            .size(px(32.))
            .rounded(px(4.))
            .flex()
            .items_center()
            .justify_center()
            .hover(move |s| s.bg(subtle))
            .active(move |s| s.bg(pressed))
            .on_click(move |_, window, cx| {
                cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
                let at = cx.background_executor().now();
                on_copy.update(cx, |s, _| s.copied_at = Some(at));
                let entity = on_copy.downgrade();
                let timer = cx.background_executor().timer(COPIED_FOR);
                window
                    .spawn(cx, async move |cx| {
                        timer.await;
                        entity
                            .update(cx, |s, cx| {
                                if s.copied_at == Some(at) {
                                    s.copied_at = None;
                                }
                                cx.notify();
                            })
                            .ok();
                    })
                    .detach();
            })
            .child(
                Icon::default()
                    .path(if showing {
                        "fluent/checkmark.svg"
                    } else {
                        "fluent/copy.svg"
                    })
                    .with_size(Size::Size(px(16.)))
                    .text_color(fg),
            );
        let note = showing.then(|| {
            deferred(
                anchored().child(
                    div()
                        .id(SharedString::from(format!("{id}-copied")))
                        .test_support()
                        .role(Role::Status)
                        .mt(px(4.))
                        .bg(acrylic_in_app(cx))
                        .border_1()
                        .border_color(theme::flyout_stroke(cx))
                        .rounded(px(4.))
                        .pt(px(6.))
                        .pb(px(8.))
                        .px(px(9.))
                        .text_size(px(12.))
                        .line_height(px(16.))
                        .text_color(fg)
                        .child(self.copied.clone()),
                ),
            )
            .with_priority(3)
        });
        div()
            .flex()
            .flex_col()
            .child(keyboard_focus(id, move |focus| {
                button.track_focus(focus).into_any_element()
            }))
            .children(note)
    }
}
