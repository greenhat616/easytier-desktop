//! Small `#[inline(never)]` element constructors that isolate large GPUI component
//! builder temporaries (`Button`, `Input`, `Switch`) into short-lived stack frames
//! and return a 16-byte [`AnyElement`].
//!
//! Without this boundary, unoptimized debug builds (especially on Windows where the
//! main thread stack is 1 MiB) keep every chained component temporary alive for the
//! entire enclosing render function, causing stack frames of 500–700 KiB.

use gpui_kit::gpui;
use gpui_kit::{
    AnyElement, App, ClickEvent, ElementId, Entity, FocusHandle, Focusable as _, Hsla,
    InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    base::{
        Button as BaseButton, LayoutDirection, LogicalStyledExt as _, Switch as BaseSwitch,
        SwitchThumb, SwitchTrack, spring,
    },
    component::{
        ActiveTheme as _, Collapsible, Disableable as _, FocusableExt as _, Icon, Selectable as _,
        Sizable as _, Size, StyledExt as _,
        button::{Button, ButtonVariant, ButtonVariants as _},
        input::{Input, InputContentType, InputState},
        progress::ProgressCircle,
        sidebar::SidebarItem,
    },
    div, px, rgb,
};

#[derive(Clone, Copy)]
pub struct BtnStyle {
    pub variant: ButtonVariant,
    pub size: Size,
    pub outline: bool,
    pub disabled: bool,
    pub loading: bool,
    pub icon: Option<&'static str>,
    selected: bool,
}

impl BtnStyle {
    pub const fn new(variant: ButtonVariant, size: Size) -> Self {
        Self {
            variant,
            size,
            outline: false,
            disabled: false,
            loading: false,
            icon: None,
            selected: false,
        }
    }

    pub const fn icon(mut self, asset: &'static str) -> Self {
        self.icon = Some(asset);
        self
    }

    pub const fn outline(mut self) -> Self {
        self.outline = true;
        self
    }

    pub const fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    pub const fn selected(mut self, selected: bool) -> Self {
        self.selected = selected;
        self
    }

    pub const fn loading(mut self, loading: bool) -> Self {
        self.loading = loading;
        self
    }
}

type ClickHandler = Box<dyn Fn(&ClickEvent, &mut Window, &mut App) + 'static>;

/// Builds a single `gpui_component::Button` in its own stack frame and immediately
/// boxes it into an [`AnyElement`].
pub fn action_button(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    style: BtnStyle,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> AnyElement {
    action_button_inner(id.into(), label.into(), style, Box::new(on_click))
}

#[inline(never)]
fn action_button_inner(
    id: ElementId,
    label: SharedString,
    style: BtnStyle,
    on_click: ClickHandler,
) -> AnyElement {
    FluentButton {
        id,
        label,
        style,
        on_click,
    }
    .into_any_element()
}

/// App-owned, keyboard-only WinUI focus treatment. The outer 2px line
/// contrasts with the surface; the inner 1px reverses its polarity. Both
/// are overlays, so focus never changes layout or intercepts activation.
fn focus_visual(focused: bool, window: &Window, cx: &App) -> Option<AnyElement> {
    if !focused || !window.last_input_was_keyboard() {
        return None;
    }
    let (outer, inner) = focus_colors(cx.theme().is_dark());
    Some(
        div()
            .id("fluent-focus-visual")
            .test_support()
            .absolute()
            .top(-px(3.))
            .bottom(-px(3.))
            .left(-px(3.))
            .right(-px(3.))
            .rounded(px(7.))
            .border_2()
            .border_color(outer)
            .child(
                div()
                    .size_full()
                    .rounded(px(5.))
                    .border_1()
                    .border_color(inner),
            )
            .into_any_element(),
    )
}

fn focus_colors(dark: bool) -> (Hsla, Hsla) {
    if dark {
        (rgb(0xFFFFFF).into(), rgb(0x000000).into())
    } else {
        (rgb(0x000000).into(), rgb(0xFFFFFF).into())
    }
}

#[derive(IntoElement)]
struct FluentButton {
    id: ElementId,
    label: SharedString,
    style: BtnStyle,
    on_click: ClickHandler,
}

impl gpui::RenderOnce for FluentButton {
    #[inline(never)]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        // The Kit button still owns disabled, loading and keyboard behavior,
        // variant contrast, and the existing hover/press fills.
        let id = self.id;
        let style = self.style;
        let focus = focus_for(&id, window, cx);
        let group = SharedString::from(format!("fluent-button:{id:?}"));
        let mut btn = Button::new(id.clone())
            .with_size(style.size)
            .with_variant(style.variant)
            .accessibility_label(if style.selected {
                format!("{} (selected)", self.label).into()
            } else {
                self.label.clone()
            })
            .selected(style.selected)
            .track_focus(&focus)
            .focus_ring(false)
            .disabled(style.disabled || style.loading)
            .on_click(move |ev, window, cx| (self.on_click)(ev, window, cx));
        if style.outline {
            btn = btn.outline();
        }
        if style.loading {
            let (fill, ink) = loading_button_colors(style, cx);
            // Kit's disabled state normally fades the fill to 15%; a busy
            // button is non-activatable but should keep its readable fill.
            btn = btn
                .bg(fill)
                .border_color(fill)
                .text_color(ink)
                .child(progress_ring_colored(
                    "button-progress",
                    "Working",
                    Size::Small,
                    ink,
                ));
        } else if let Some(path) = style.icon {
            btn = btn.icon(Icon::default().path(path));
        }
        // The content fades slightly during a pointer press; the toolkit's
        // own active color remains the background feedback. Don't scale
        // layout or make disabled targets respond.
        btn = btn.child(
            div()
                .id("fluent-button-label")
                .min_w_0()
                .truncate()
                .group_active(group.clone(), move |s| {
                    s.opacity(if style.disabled || style.loading {
                        1.
                    } else {
                        0.86
                    })
                })
                .child(self.label),
        );
        let elevate = !style.disabled
            && !style.loading
            && !matches!(
                style.variant,
                ButtonVariant::Ghost | ButtonVariant::Link | ButtonVariant::Text
            );
        div()
            .relative()
            .group(group)
            .child(btn)
            .children(elevate.then(|| button_elevation_line(cx)))
            .children(focus_visual(focus.is_focused(window), window, cx))
    }
}

/// A one-pixel non-layout bevel: the bottom is darker in light mode,
/// while dark mode catches a subtle highlight along the top edge.
fn button_elevation_line(cx: &App) -> AnyElement {
    let dark = cx.theme().is_dark();
    let line = div()
        .absolute()
        .left(px(3.))
        .right(px(3.))
        .h(px(1.))
        .rounded_full()
        .bg(if dark {
            Hsla::from(rgb(0xFFFFFF)).opacity(0.10)
        } else {
            Hsla::from(rgb(0x000000)).opacity(0.16)
        });
    if dark {
        line.top_0().into_any_element()
    } else {
        line.bottom_0().into_any_element()
    }
}

fn loading_button_colors(style: BtnStyle, cx: &App) -> (Hsla, Hsla) {
    let t = cx.theme();
    if style.outline {
        let ink = match style.variant {
            ButtonVariant::Primary => t.primary,
            ButtonVariant::Danger => t.danger,
            ButtonVariant::Warning => t.warning,
            ButtonVariant::Success => t.success,
            ButtonVariant::Info => t.info,
            ButtonVariant::Secondary => t.secondary_foreground,
            _ => t.button_foreground,
        };
        return (t.popover, ink);
    }
    match style.variant {
        ButtonVariant::Primary => (t.button_primary, t.button_primary_foreground),
        ButtonVariant::Secondary => (t.button_secondary, t.button_secondary_foreground),
        ButtonVariant::Danger => (t.button_danger, t.button_danger_foreground),
        ButtonVariant::Warning => (t.button_warning, t.button_warning_foreground),
        ButtonVariant::Success => (t.button_success, t.button_success_foreground),
        ButtonVariant::Info => (t.button_info, t.button_info_foreground),
        ButtonVariant::Default => (t.button, t.button_foreground),
        ButtonVariant::Link => (t.popover, t.link),
        _ => (t.popover, t.foreground),
    }
}

fn focus_for(id: &ElementId, window: &mut Window, cx: &mut App) -> FocusHandle {
    window
        .use_keyed_state((id.clone(), "fluent-focus"), cx, |_, cx| cx.focus_handle())
        .read(cx)
        .clone()
}

/// Generic indeterminate Fluent progress ring (Kit owns animation and a11y).
#[inline(never)]
pub fn progress_ring(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    size: Size,
) -> AnyElement {
    ProgressCircle::new(id)
        .loading(true)
        .with_size(size)
        .accessibility_label(label)
        .into_any_element()
}

#[inline(never)]
pub fn progress_ring_colored(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    size: Size,
    color: Hsla,
) -> AnyElement {
    ProgressCircle::new(id)
        .loading(true)
        .with_size(size)
        .color(color)
        .accessibility_label(label)
        .into_any_element()
}

/// The appearance section of the sidebar menu, with all choices visible.
/// A checked button represents the saved choice, not the effective OS mode.
#[inline(never)]
pub fn theme_menu(cx: &App) -> AnyElement {
    use crate::{preferences::ThemePreference, theme};
    let current = theme::preference(cx);
    let mut menu = div()
        .mt_auto()
        .pt_3()
        .border_t_1()
        .border_color(cx.theme().border)
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child("Appearance"),
        );
    for (id, choice) in [
        ("theme-follow-system", ThemePreference::FollowSystem),
        ("theme-light", ThemePreference::Light),
        ("theme-dark", ThemePreference::Dark),
    ] {
        menu = menu.child(theme_choice_button(id, choice, current == choice));
    }
    if theme::preference_save_failed(cx) {
        menu = menu.child(
            div()
                .text_xs()
                .text_color(cx.theme().warning)
                .child("Theme not saved"),
        );
    }
    menu.into_any_element()
}

#[inline(never)]
fn theme_choice_button(
    id: &'static str,
    choice: crate::preferences::ThemePreference,
    selected: bool,
) -> AnyElement {
    let mut style = BtnStyle::new(ButtonVariant::Ghost, Size::Small).selected(selected);
    if selected {
        style = style.icon("fluent/checkmark.svg");
    }
    action_button(id, choice.label(), style, move |_, window, cx| {
        crate::theme::set_preference(choice, window, cx)
    })
}

/// Builds a labeled single-line [`Input`] in its own stack frame.
#[inline(never)]
pub fn text_field(
    label: &str,
    id: &'static str,
    aria_label: &'static str,
    state: &Entity<InputState>,
    disabled: bool,
    cx: &App,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let input = FluentInput {
        id,
        aria_label,
        state: state.clone(),
        disabled,
        password: false,
    }
    .into_any_element();
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_sm().text_color(fg).child(label.to_owned()))
        .child(input)
        .into_any_element()
}

/// Builds a masked password [`Input`] with mask toggle in its own stack frame.
#[inline(never)]
pub fn password_input(
    id: &'static str,
    aria_label: &'static str,
    state: &Entity<InputState>,
    disabled: bool,
) -> AnyElement {
    FluentInput {
        id,
        aria_label,
        state: state.clone(),
        disabled,
        password: true,
    }
    .into_any_element()
}

#[derive(IntoElement)]
struct FluentInput {
    id: &'static str,
    aria_label: &'static str,
    state: Entity<InputState>,
    disabled: bool,
    password: bool,
}

impl RenderOnce for FluentInput {
    #[inline(never)]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let focus = self.state.read(cx).focus_handle(cx);
        let mut input = Input::new(&self.state)
            .id(self.id)
            .aria_label(self.aria_label)
            .disabled(self.disabled)
            .focus_ring(false);
        if self.password {
            input = input.content_type(InputContentType::Password).mask_toggle();
        }
        div()
            .relative()
            .w_full()
            .child(input)
            .children(focus_visual(focus.is_focused(window), window, cx))
    }
}

/// Controlled Fluent switch: gpui-base retains keyboard activation, focus,
/// ARIA checked state and disabled behavior. The 40×20 track uses a spring
/// for thumb travel and renders from logical start to end in RTL.
#[inline(never)]
pub fn switch_control(
    id: &'static str,
    label: impl Into<SharedString>,
    checked: bool,
    on_change: impl Fn(&bool, &mut Window, &mut App) + 'static,
) -> AnyElement {
    fluent_switch(id, label, checked, false, on_change)
}

#[inline(never)]
pub fn fluent_switch(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    checked: bool,
    disabled: bool,
    on_change: impl Fn(&bool, &mut Window, &mut App) + 'static,
) -> AnyElement {
    FluentSwitch {
        id: id.into(),
        label: label.into(),
        checked,
        disabled,
        on_change: Box::new(on_change),
    }
    .into_any_element()
}

type SwitchHandler = Box<dyn Fn(&bool, &mut Window, &mut App)>;

#[derive(IntoElement)]
struct FluentSwitch {
    id: ElementId,
    label: SharedString,
    checked: bool,
    disabled: bool,
    on_change: SwitchHandler,
}

#[derive(Clone, Copy)]
struct SwitchPaint {
    track: Hsla,
    border: Hsla,
    thumb: Hsla,
}

fn switch_paint(checked: bool, disabled: bool, cx: &App) -> SwitchPaint {
    let t = cx.theme();
    if disabled {
        return SwitchPaint {
            track: t.secondary,
            border: t.border,
            thumb: t.muted_foreground,
        };
    }
    if checked {
        SwitchPaint {
            track: t.primary,
            border: t.primary,
            thumb: t.primary_foreground,
        }
    } else {
        SwitchPaint {
            track: t.transparent,
            border: t.muted_foreground,
            thumb: t.muted_foreground,
        }
    }
}

impl RenderOnce for FluentSwitch {
    #[inline(never)]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let id = self.id;
        let checked = self.checked;
        let disabled = self.disabled;
        let focus = focus_for(&id, window, cx);
        let paint = switch_paint(checked, disabled, cx);
        let thumb_size = px(12.);
        let thumb_x = spring(
            (id.clone(), "fluent-thumb"),
            if checked {
                px(40.) - thumb_size - px(6.)
            } else {
                px(0.)
            },
            cx.theme().motion_tokens().spring_move,
            window,
            cx,
        );
        let group = SharedString::from(format!("fluent-switch:{id:?}"));
        let rtl = LayoutDirection::global(cx).is_rtl();
        let mut thumb = div()
            .id("fluent-switch-thumb")
            .test_support()
            .relative()
            .rounded_full()
            .size(thumb_size)
            .bg(paint.thumb);
        if !disabled {
            thumb = thumb
                .group_hover(group.clone(), move |s| {
                    let s = s.size(thumb_size + px(2.));
                    if checked {
                        if rtl {
                            s.right(-px(2.))
                        } else {
                            s.left(-px(2.))
                        }
                    } else {
                        s
                    }
                })
                .group_active(group.clone(), move |s| {
                    let s = s.w(px(17.)).h(px(14.));
                    if checked {
                        if rtl {
                            s.right(-px(5.))
                        } else {
                            s.left(-px(5.))
                        }
                    } else {
                        s
                    }
                });
        }
        let track = SwitchTrack::new((id.clone(), "track"))
            .checked(checked)
            .disabled(disabled)
            .w(px(40.))
            .h(px(20.))
            .flex_shrink_0()
            .rounded_full()
            .border_1()
            .border_color(paint.border)
            .bg(paint.track)
            .p(px(2.))
            .flex_row_dir(cx)
            .items_center()
            .child(
                SwitchThumb::new(checked)
                    .disabled(disabled)
                    .inset_s(thumb_x, cx)
                    .child(thumb),
            );
        let label = self.label;
        let mut switch = BaseSwitch::new(id)
            .track_focus(&focus)
            .checked(checked)
            .disabled(disabled)
            .accessibility_label(label.clone())
            .group(group)
            .on_change(move |next, _, window, cx| (self.on_change)(&next, window, cx))
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .text_sm();
        if rtl {
            switch = switch.flex_row_reverse();
        }
        switch
            .child(
                div()
                    .id("fluent-switch-track")
                    .test_support()
                    .relative()
                    .flex_shrink_0()
                    .child(track)
                    .children(focus_visual(focus.is_focused(window), window, cx)),
            )
            .child(
                div()
                    .text_color(if disabled {
                        cx.theme().muted_foreground
                    } else {
                        cx.theme().foreground
                    })
                    .child(label),
            )
    }
}

type NavClickHandler = std::rc::Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// Navigation row used by the Kit Sidebar. It owns only the appearance;
/// Sidebar handles the expanded/icon-only transition, scrolling and layout.
#[derive(Clone)]
pub struct FluentNavItem {
    id: ElementId,
    label: SharedString,
    regular_icon: &'static str,
    filled_icon: &'static str,
    selected: bool,
    collapsed: bool,
    handler: NavClickHandler,
}

impl FluentNavItem {
    pub fn new(
        id: impl Into<ElementId>,
        label: impl Into<SharedString>,
        regular_icon: &'static str,
        filled_icon: &'static str,
        selected: bool,
        handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            regular_icon,
            filled_icon,
            selected,
            collapsed: false,
            handler: std::rc::Rc::new(handler),
        }
    }
}

impl Collapsible for FluentNavItem {
    fn is_collapsed(&self) -> bool {
        self.collapsed
    }
    fn collapsed(mut self, collapsed: bool) -> Self {
        self.collapsed = collapsed;
        self
    }
}

impl SidebarItem for FluentNavItem {
    #[inline(never)]
    fn render(
        self,
        _id: impl Into<ElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> impl IntoElement {
        let focus = focus_for(&self.id, window, cx);
        let t = cx.theme();
        let selected = self.selected;
        let collapsed = self.collapsed;
        let bg = if selected {
            t.secondary.opacity(0.55)
        } else {
            t.transparent
        };
        let icon = if selected {
            self.filled_icon
        } else {
            self.regular_icon
        };
        let handler = self.handler;
        let rtl = LayoutDirection::global(cx).is_rtl();
        let pill = div()
            .id("fluent-nav-pill")
            .test_support()
            .absolute()
            .top(px(8.))
            .w(px(3.))
            .h(px(16.))
            .rounded_full()
            .bg(t.primary);
        let pill = if rtl { pill.right_0() } else { pill.left_0() };
        let mut btn = BaseButton::new(self.id)
            .track_focus(&focus)
            .accessibility_label(self.label.clone())
            .selected(selected)
            .aria_selected(selected)
            .relative()
            .w_full()
            .h(px(32.))
            .rounded(px(4.))
            .bg(bg)
            .text_sm()
            .text_color(t.sidebar_foreground)
            .flex_row_dir(cx)
            .items_center()
            .gap_2()
            .hover(|s| s.bg(t.secondary.opacity(0.65)))
            .active(|s| s.bg(t.secondary_active))
            .on_click(move |event, window, cx| handler(event, window, cx));
        btn = if collapsed {
            btn.justify_center()
        } else {
            btn.px_3()
        };
        btn = btn.child(
            Icon::default()
                .path(icon)
                .with_size(Size::Medium)
                .text_color(if selected {
                    t.primary
                } else {
                    t.sidebar_foreground
                }),
        );
        if !collapsed {
            let label = div().min_w_0().truncate().child(self.label);
            btn = btn.child(if selected {
                label.font_semibold()
            } else {
                label
            });
        }
        if selected {
            btn = btn.child(pill);
        }
        div()
            .relative()
            .w_full()
            .my_0p5()
            .child(btn)
            .children(focus_visual(focus.is_focused(window), window, cx))
    }
}

/// Semantic InfoBar presentation, with neutral text on an opaque composited
/// tint. The badge's icon matches severity without relying on color alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfoSeverity {
    Informational,
    Success,
    Warning,
    Error,
}

fn info_colors(severity: InfoSeverity, cx: &App) -> (Hsla, Hsla) {
    let t = cx.theme();
    let color = match severity {
        InfoSeverity::Informational => t.info,
        InfoSeverity::Success => t.success,
        InfoSeverity::Warning => t.warning,
        InfoSeverity::Error => t.danger,
    };
    let bg = Hsla::from(t.popover.to_rgb().blend(color.opacity(0.10).to_rgb()));
    (bg, color)
}

pub struct FluentInfoBar {
    id: ElementId,
    message: SharedString,
    severity: InfoSeverity,
    role: Role,
    actions: Vec<AnyElement>,
    close: Option<AnyElement>,
}

impl FluentInfoBar {
    pub fn new(
        id: impl Into<ElementId>,
        severity: InfoSeverity,
        message: impl Into<SharedString>,
    ) -> Self {
        Self {
            id: id.into(),
            message: message.into(),
            severity,
            role: Role::Alert,
            actions: Vec::new(),
            close: None,
        }
    }
    pub fn status(mut self) -> Self {
        self.role = Role::Status;
        self
    }
    pub fn actions(mut self, actions: impl IntoIterator<Item = AnyElement>) -> Self {
        self.actions.extend(actions);
        self
    }
    pub fn close(mut self, close: AnyElement) -> Self {
        self.close = Some(close);
        self
    }

    #[inline(never)]
    pub fn render(self, cx: &App) -> AnyElement {
        let (bg, semantic) = info_colors(self.severity, cx);
        let icon = match self.severity {
            InfoSeverity::Informational => "fluent/info-filled.svg",
            InfoSeverity::Success => "fluent/checkmark-circle-filled.svg",
            InfoSeverity::Warning => "fluent/warning-filled.svg",
            InfoSeverity::Error => "fluent/error-circle-filled.svg",
        };
        let badge = div()
            .id("infobar-severity")
            .test_support()
            .size(px(20.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .child(
                Icon::default()
                    .path(icon)
                    .with_size(Size::Large)
                    .text_color(semantic),
            );
        let actions = (!self.actions.is_empty()).then(|| {
            div()
                .flex_row_dir(cx)
                .flex_shrink_0()
                .gap_2()
                .children(self.actions)
        });

        div()
            .id(self.id)
            .role(self.role)
            .test_support()
            .aria_label(self.message.clone())
            .mx_3()
            .my_0p5()
            .px_3()
            .py_1()
            .rounded(px(4.))
            .border_1()
            .border_color(cx.theme().border)
            .bg(bg)
            .text_sm()
            .text_color(cx.theme().foreground)
            .flex_row_dir(cx)
            .items_center()
            .gap_3()
            .child(badge)
            .child(div().min_w_0().flex_1().child(self.message))
            .children(actions)
            .children(self.close)
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{
        AppContext as _, Context, Render, TestAppContext, WindowOptions, size,
        test::{TestEventExt as _, TestWindowExt as _},
    };

    struct ControlDemo {
        checked: bool,
        activated: usize,
        closed: bool,
    }

    impl Render for ControlDemo {
        fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            let button = action_button(
                "demo-button",
                "Activate",
                BtnStyle::new(ButtonVariant::Primary, Size::Small),
                cx.listener(|this, _, _, cx| {
                    this.activated += 1;
                    cx.notify();
                }),
            );
            let switch = fluent_switch(
                "demo-switch",
                "Toggle",
                self.checked,
                false,
                cx.listener(|this, next, _, cx| {
                    this.checked = *next;
                    cx.notify();
                }),
            );
            let disabled = fluent_switch("demo-disabled", "Disabled", false, true, |_, _, _| {
                panic!("disabled switch activated")
            });
            let loading = action_button(
                "demo-loading",
                "Busy",
                BtnStyle::new(ButtonVariant::Primary, Size::Small).loading(true),
                |_, _, _| panic!("loading button activated"),
            );
            let close = action_button(
                "demo-close",
                "Dismiss",
                BtnStyle::new(ButtonVariant::Ghost, Size::Small),
                cx.listener(|this, _, _, cx| {
                    this.closed = true;
                    cx.notify();
                }),
            );
            div()
                .size_full()
                .tab_group()
                .flex()
                .flex_col()
                .items_start()
                .gap_3()
                .p_4()
                .child(button)
                .child(switch)
                .child(disabled)
                .child(loading)
                .children((!self.closed).then(|| {
                    FluentInfoBar::new("demo-info", InfoSeverity::Warning, "Warning body")
                        .close(close)
                        .render(cx)
                }))
        }
    }

    #[gpui_kit::test]
    fn fluent_controls_preserve_click_checked_focus_loading_and_close(cx: &mut TestAppContext) {
        let (window, view) = cx.update(|cx| {
            gpui_kit::init(cx);
            crate::theme::install_palette(cx);
            gpui_kit::open_window(WindowOptions::default(), cx, |_, cx| {
                cx.new(|_| ControlDemo {
                    checked: false,
                    activated: 0,
                    closed: false,
                })
            })
            .unwrap()
        });
        cx.update_window(window, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("demo-switch").role(), Some(Role::Switch));
            assert_eq!(window.find("demo-switch").checked(), Some(false));
            assert_eq!(
                window
                    .within("demo-switch")
                    .find("fluent-switch-track")
                    .bounds()
                    .size,
                size(px(40.), px(20.))
            );
            assert_eq!(window.find("demo-disabled").disabled(), Some(true));
            assert_eq!(window.find("demo-loading").disabled(), Some(true));
            let progress = window.find("button-progress");
            assert_eq!(progress.role(), Some(Role::ProgressIndicator));
            assert_eq!(progress.label(), Some("Working"));
            // Indeterminate progress omits aria_numeric_value; indeterminate() is checkbox metadata.
            assert!(progress.value().is_none());
            assert_eq!(progress.bounds().size.width, progress.bounds().size.height);
            assert!(progress.bounds().size.width >= px(10.));
            assert!(window.try_find("fluent-focus-visual").is_none());
            window.press("tab", cx);
            window.render_frame(cx);
            assert!(window.find("fluent-focus-visual").visible());
            window.click("demo-button", cx);
            assert_eq!(view.read(cx).activated, 1);
            assert!(window.try_find("fluent-focus-visual").is_none());
            let center = window
                .within("demo-switch")
                .find("fluent-switch-track")
                .bounds()
                .center();
            for expected in [true, false] {
                window.pointer_move(center, None, cx);
                let hovered = window
                    .within("demo-switch")
                    .find("fluent-switch-thumb")
                    .bounds()
                    .size;
                assert_eq!(hovered, size(px(14.), px(14.)));
                window.pointer_down(center, gpui_kit::MouseButton::Left, cx);
                let pressed = window
                    .within("demo-switch")
                    .find("fluent-switch-thumb")
                    .bounds()
                    .size;
                assert_eq!(pressed, size(px(17.), px(14.)));
                window.pointer_up(center, gpui_kit::MouseButton::Left, cx);
                assert_eq!(window.find("demo-switch").checked(), Some(expected));
            }
            window.click("demo-disabled", cx);
            assert_eq!(window.find("demo-disabled").checked(), Some(false));
            window.click("demo-loading", cx);
            assert_eq!(window.find("demo-info").role(), Some(Role::Alert));
            assert!(
                window
                    .within("demo-info")
                    .find("infobar-severity")
                    .visible()
            );
            window.click("demo-close", cx);
            assert!(window.try_find("demo-info").is_none());
        })
        .unwrap();
    }

    fn rgb24(color: Hsla) -> u32 {
        let c = color.to_rgb();
        let b = |v: f32| (v.clamp(0., 1.) * 255.).round() as u32;
        b(c.r) << 16 | b(c.g) << 8 | b(c.b)
    }

    #[gpui_kit::test]
    fn info_bar_and_switch_colors_are_readable_in_both_themes(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            crate::theme::install_palette(cx);
            for mode in [
                gpui_kit::component::ThemeMode::Light,
                gpui_kit::component::ThemeMode::Dark,
            ] {
                gpui_kit::component::Theme::change(mode, None, cx);
                let t = cx.theme();
                let contrast = |a, b| crate::theme::contrast(rgb24(a), rgb24(b));
                for severity in [
                    InfoSeverity::Informational,
                    InfoSeverity::Success,
                    InfoSeverity::Warning,
                    InfoSeverity::Error,
                ] {
                    let (bg, badge) = info_colors(severity, cx);
                    assert!(
                        contrast(t.foreground, bg) >= 4.5,
                        "InfoBar body {mode:?} {severity:?}"
                    );
                    assert!(
                        contrast(badge, bg) >= 3.,
                        "InfoBar badge {mode:?} {severity:?}"
                    );
                }
                for checked in [false, true] {
                    let paint = switch_paint(checked, false, cx);
                    assert!(
                        contrast(if checked { paint.track } else { t.popover }, paint.thumb) >= 3.,
                        "switch thumb {mode:?} {checked}"
                    );
                }
                for outline in [false, true] {
                    let mut style =
                        BtnStyle::new(ButtonVariant::Primary, Size::Small).loading(true);
                    style.outline = outline;
                    let (fill, ink) = loading_button_colors(style, cx);
                    assert!(
                        contrast(fill, ink) >= 4.5,
                        "loading ring {mode:?} outline={outline}"
                    );
                }
                let (outer, inner) = focus_colors(t.is_dark());
                assert!(contrast(outer, inner) >= 4.5);
                assert!(contrast(outer, t.background) >= 3.);
            }
        });
    }
}
