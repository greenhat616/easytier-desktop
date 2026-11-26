//! Small `#[inline(never)]` element constructors that isolate large GPUI component
//! builder temporaries (`Button`, `Input`, `Switch`) into short-lived stack frames
//! and return a 16-byte [`AnyElement`].
//!
//! Without this boundary, unoptimized debug builds (especially on Windows where the
//! main thread stack is 1 MiB) keep every chained component temporary alive for the
//! entire enclosing render function, causing stack frames of 500–700 KiB.

use gpui_kit::{
    AnyElement, App, ClickEvent, ElementId, Entity, IntoElement as _, ParentElement as _,
    SharedString, Styled as _, Window,
    component::{
        ActiveTheme as _, Disableable as _, Sizable as _, Size,
        button::{Button, ButtonVariant, ButtonVariants as _},
        input::{Input, InputContentType, InputState},
        switch::Switch,
    },
    div,
};

#[derive(Clone, Copy)]
pub struct BtnStyle {
    pub variant: ButtonVariant,
    pub size: Size,
    pub outline: bool,
    pub disabled: bool,
    pub loading: bool,
}

impl BtnStyle {
    pub const fn new(variant: ButtonVariant, size: Size) -> Self {
        Self {
            variant,
            size,
            outline: false,
            disabled: false,
            loading: false,
        }
    }

    pub const fn outline(mut self) -> Self {
        self.outline = true;
        self
    }

    pub const fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
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
    let mut btn = Button::new(id)
        .with_size(style.size)
        .with_variant(style.variant)
        .label(label)
        .disabled(style.disabled)
        .loading(style.loading)
        .on_click(move |ev, window, cx| on_click(ev, window, cx));
    if style.outline {
        btn = btn.outline();
    }
    btn.into_any_element()
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
    let input = Input::new(state)
        .id(id)
        .aria_label(aria_label)
        .disabled(disabled)
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
    Input::new(state)
        .id(id)
        .aria_label(aria_label)
        .content_type(InputContentType::Password)
        .mask_toggle()
        .disabled(disabled)
        .into_any_element()
}

/// Builds a [`Switch`] in its own stack frame.
#[inline(never)]
pub fn switch_control(
    id: &'static str,
    label: impl Into<SharedString>,
    checked: bool,
    on_change: impl Fn(&bool, &mut Window, &mut App) + 'static,
) -> AnyElement {
    Switch::new(id)
        .checked(checked)
        .label(label.into())
        .on_change(on_change)
        .into_any_element()
}
