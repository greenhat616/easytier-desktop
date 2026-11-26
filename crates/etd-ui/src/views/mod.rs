//! Root GPUI view (`MainView`) and sub-views bound strictly to [`etd_app::StateStore`].

pub mod banners;
pub mod instances;
pub mod reclaim;
pub mod ui;

use etd_app::UserCommand;
use etd_contract::{Desired, InstanceId, NetworkSpec, capability};
use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, Size, button::ButtonVariant},
    div, px,
};

use crate::{
    controller::UiController,
    editor::{NetworkEditorState, render_editor},
    model::Section,
    views::ui::{BtnStyle, action_button, theme_menu},
};

/// Main desktop window view.
pub struct MainView {
    pub controller: UiController,
    pub editor: NetworkEditorState,
}

impl MainView {
    pub fn new(controller: UiController, window: &mut Window, cx: &mut Context<Self>) -> Self {
        cx.observe(&controller.model, |_, _, cx| cx.notify())
            .detach();
        let editor = NetworkEditorState::new(window, cx);
        Self { controller, editor }
    }

    pub fn open_new_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tun_available = self
            .controller
            .model
            .read(cx)
            .store
            .has_capability(capability::TUN);
        self.editor.load_new(tun_available, window, cx);
        self.controller.select_section(Section::Editor, cx);
        cx.notify();
    }

    pub fn open_edit_editor(
        &mut self,
        instance_id: InstanceId,
        spec: &NetworkSpec,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.editor.load_existing(instance_id, spec, window, cx);
        self.controller.select_section(Section::Editor, cx);
        cx.notify();
    }

    pub fn cancel_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.editor.clear_secret(window, cx);
        self.editor.validation_error = None;
        self.controller.select_section(Section::Instances, cx);
        cx.notify();
    }

    pub fn submit_editor(&mut self, desired: Desired, window: &mut Window, cx: &mut Context<Self>) {
        match self.editor.build_draft(desired, window, cx) {
            Ok(draft) => {
                let id = draft.instance_id.clone();
                self.controller
                    .send_command(UserCommand::Apply(Box::new(draft)));
                self.controller.select_instance(Some(id), cx);
            }
            Err(error) => {
                self.editor.validation_error = Some(error);
                cx.notify();
            }
        }
    }
}

#[inline(never)]
fn render_sidebar(
    active_section: Section,
    instance_count: usize,
    reclaim_count: usize,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = cx.theme().border;
    let sidebar = crate::theme::chrome_fill(cx, cx.theme().sidebar);
    let reclaim_label = if reclaim_count > 0 {
        format!("Reclaim Report ({reclaim_count})")
    } else {
        "Reclaim Report".to_owned()
    };

    let new_btn = action_button(
        "btn-new-network",
        "+ New Network",
        BtnStyle::new(ButtonVariant::Primary, Size::Small),
        cx.listener(|this, _, window, cx| {
            this.open_new_editor(window, cx);
        }),
    );
    let instances_btn = action_button(
        "nav-instances",
        SharedString::from(format!("Instances ({instance_count})")),
        BtnStyle::new(
            if active_section == Section::Instances {
                ButtonVariant::Secondary
            } else {
                ButtonVariant::Ghost
            },
            Size::Small,
        )
        .icon("fluent/globe.svg"),
        cx.listener(|this, _, _, cx| {
            this.controller.select_section(Section::Instances, cx);
        }),
    );
    let reclaim_btn = action_button(
        "nav-reclaim",
        SharedString::from(reclaim_label),
        BtnStyle::new(
            if active_section == Section::Reclaim {
                ButtonVariant::Secondary
            } else {
                ButtonVariant::Ghost
            },
            Size::Small,
        )
        .icon("fluent/shield.svg"),
        cx.listener(|this, _, _, cx| {
            this.controller.select_section(Section::Reclaim, cx);
        }),
    );

    div()
        .id("sidebar-nav")
        .w(px(210.))
        .h_full()
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .border_r_1()
        .border_color(border)
        .bg(sidebar)
        .child(new_btn)
        .child(instances_btn)
        .child(reclaim_btn)
        .child(theme_menu(cx))
        .into_any_element()
}

#[inline(never)]
fn render_section_content(
    view: &MainView,
    section: Section,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let inner = match section {
        Section::Instances => instances::render_instances_workspace(view, cx),
        Section::Reclaim => reclaim::render_reclaim_view(view, cx),
        Section::Editor => render_editor(view, cx),
    };
    div()
        .flex_1()
        .h_full()
        .overflow_hidden()
        .bg(cx.theme().popover)
        .rounded_tl(px(8.))
        .child(inner)
        .into_any_element()
}

impl Render for MainView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let background = crate::theme::chrome_fill(cx, cx.theme().background);
        let foreground = cx.theme().foreground;
        let (active_section, instance_count, reclaim_count) = {
            let model = self.controller.model.read(cx);
            (
                model.active_section,
                model.store.instances.len(),
                model.reclaim_attention_count(),
            )
        };

        let header = banners::render_header(self, cx);
        let banners = banners::render_banners(self, cx);
        let nav = render_sidebar(active_section, instance_count, reclaim_count, cx);
        let content = render_section_content(self, active_section, cx);

        div()
            .id("etd-main-root")
            .test_support()
            .flex()
            .flex_col()
            .size_full()
            .bg(background)
            .text_color(foreground)
            .child(header)
            .child(banners)
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_row()
                    .min_h(px(0.))
                    .overflow_hidden()
                    .child(nav)
                    .child(content),
            )
    }
}
