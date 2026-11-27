//! A small always-on-top pop-out window with its own Fluent title bar, for
//! keeping one room's status in view while the main window is hidden.
//! Values come from the WinUI TitleBar control (TitleBar_themeresources.xaml)
//! where it has them; the caption button follows Windows 11's own.

use gpui_kit::{
    AnyElement, App, Bounds, InteractiveElement as _, IntoElement, ParentElement as _, Pixels,
    Role, SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    TitlebarOptions, Window, WindowBackgroundAppearance, WindowBounds, WindowControlArea,
    WindowKind, WindowOptions,
    component::{ActiveTheme as _, Icon, Sizable as _, Size},
    div, px, size,
};

use crate::views::controls::Handler;
use crate::views::pseudo::t;

/// TitleBarCompactHeight.
pub const TITLE_BAR_HEIGHT: Pixels = px(32.);
/// Windows 11 caption buttons are 46 × 32.
const CAPTION_BUTTON_WIDTH: Pixels = px(46.);

/// Window options for a pop-out of `width` × `height`, placed near the top
/// right of the primary display.
///
/// On Windows it is a `WindowKind::PopUp`: WS_EX_TOPMOST keeps it above
/// other windows and WS_EX_TOOLWINDOW keeps it out of the taskbar and
/// Alt+Tab, so it lives apart from the main window and stays when that
/// hides. It has no system frame, so it draws [`title_bar`] and is a fixed
/// size. Elsewhere it is a `Floating` window, since X11 pop-ups are
/// override-redirect and could not be moved.
pub fn window_options(title: &str, width: Pixels, height: Pixels, cx: &App) -> WindowOptions {
    let display = cx.primary_display();
    let area = display
        .as_ref()
        .map(|d| d.visible_bounds())
        .unwrap_or_else(|| Bounds::new(Default::default(), size(px(1280.), px(800.))));
    let origin = gpui_kit::point(
        area.origin.x + area.size.width - width - px(24.),
        area.origin.y + px(24.),
    );
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::new(
            origin,
            size(width, height),
        ))),
        titlebar: Some(TitlebarOptions {
            title: Some(title.to_owned().into()),
            appears_transparent: true,
            ..Default::default()
        }),
        kind: if cfg!(target_os = "windows") {
            WindowKind::PopUp
        } else {
            WindowKind::Floating
        },
        is_resizable: false,
        is_minimizable: false,
        focus: true,
        show: true,
        window_background: WindowBackgroundAppearance::Opaque,
        ..Default::default()
    }
}

/// A compact WinUI TitleBar: 32 px (TitleBarCompactHeight), a 16 px icon
/// (TitleBarIconMaxWidth/Height) 16 px in (TitleBarLeftPaddingWidth 2 +
/// TitleBarLeftHeaderPaddingWidth 14) with 16 px after it
/// (TitleBarIconMargin), and the title in Caption 12/16
/// `TextFillColorPrimary` (TitleBarForegroundBrush), truncating. While the
/// window is inactive the icon and title drop to 50 %
/// (TitleBarDeactivatedOpacity). Everything but the close button drags the
/// window.
///
/// The close button is a Windows 11 caption button, 46 × 32 with a 10 px
/// glyph; it turns `#C42B1C` with a white glyph on hover and 90 % of that
/// when pressed. Those are the system's own values, not WinUI resources.
pub fn title_bar(
    id: &'static str,
    icon: &'static str,
    title: impl Into<SharedString>,
    close_label: impl Into<SharedString>,
    on_close: Handler,
    window: &Window,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let opacity = if window.is_window_active() { 1. } else { 0.5 };
    let close_red = gpui_kit::rgb(0xC42B1C);
    let close_pressed = gpui_kit::Hsla::from(close_red).opacity(0.9);
    let close = div()
        .id(SharedString::from(format!("{id}-close")))
        .test_support()
        .role(Role::Button)
        .aria_label(t(close_label))
        .window_control_area(WindowControlArea::Close)
        .flex_shrink_0()
        .w(CAPTION_BUTTON_WIDTH)
        .h_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(fg)
        .hover(move |s| s.bg(close_red).text_color(gpui_kit::white()))
        .active(move |s| s.bg(close_pressed).text_color(gpui_kit::white()))
        .on_click(move |event, window, cx| on_close(event, window, cx))
        .child(
            Icon::default()
                .path("fluent/dismiss.svg")
                .with_size(Size::Size(px(10.))),
        );
    div()
        .id(id)
        .test_support()
        .flex_shrink_0()
        .h(TITLE_BAR_HEIGHT)
        .w_full()
        .flex()
        .flex_row()
        .items_center()
        .child(
            div()
                .id(SharedString::from(format!("{id}-drag")))
                .window_control_area(WindowControlArea::Drag)
                .flex_1()
                .min_w_0()
                .h_full()
                .flex()
                .flex_row()
                .items_center()
                .pl(px(16.))
                .opacity(opacity)
                .child(
                    Icon::default()
                        .path(icon)
                        .with_size(Size::Size(px(16.)))
                        .text_color(fg)
                        .flex_shrink_0(),
                )
                .child(
                    div()
                        .ml(px(16.))
                        .min_w_0()
                        .truncate()
                        .text_size(px(12.))
                        .line_height(px(16.))
                        .text_color(fg)
                        .child(t(title)),
                ),
        )
        .child(close)
        .into_any_element()
}

/// The pop-out's surface: `SolidBackgroundFillColorBase`, as WinUI uses
/// for a window without Mica.
pub fn surface(cx: &App) -> gpui_kit::Hsla {
    crate::views::dialogs::solid_base(cx)
}
