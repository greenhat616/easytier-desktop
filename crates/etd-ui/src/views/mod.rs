//! Root GPUI view (`MainView`) and sub-views bound strictly to [`etd_app::StateStore`].

pub mod banners;
pub mod connected;
pub mod controls;
pub mod dialogs;
pub mod easing;
pub mod feedback;
pub mod instances;
pub mod layout;
pub mod menus;
pub mod motion;
pub mod navigation;
pub mod page_transition;
pub mod popout;
pub mod progress;
pub mod pseudo;
pub mod reclaim;
pub mod theme_transition;
pub mod ui;

use etd_app::UserCommand;
use etd_contract::{Desired, InstanceId, NetworkSpec, capability};
use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, TestSupportExt as _, Window,
    base::{LayoutDirection, LogicalStyledExt as _},
    component::{ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant, sidebar::Sidebar},
    div, px,
};

use crate::{
    controller::UiController,
    editor::{NetworkEditorState, render_editor},
    model::Section,
    views::ui::{BtnStyle, FluentNavItem, action_button, theme_menu},
};

/// Main desktop window view.
pub struct MainView {
    pub controller: UiController,
    pub editor: NetworkEditorState,
    sidebar_collapsed: bool,
}

impl MainView {
    pub fn new(controller: UiController, window: &mut Window, cx: &mut Context<Self>) -> Self {
        cx.observe(&controller.model, |_, _, cx| cx.notify())
            .detach();
        let editor = NetworkEditorState::new(window, cx);
        Self {
            controller,
            editor,
            sidebar_collapsed: false,
        }
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
    collapsed: bool,
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
    let instances = FluentNavItem::new(
        "nav-instances",
        SharedString::from(format!("Instances ({instance_count})")),
        "fluent/globe.svg",
        "fluent/globe-filled.svg",
        active_section == Section::Instances,
        cx.listener(|this, _, _, cx| this.controller.select_section(Section::Instances, cx)),
    );
    let reclaim = FluentNavItem::new(
        "nav-reclaim",
        SharedString::from(reclaim_label),
        "fluent/shield.svg",
        "fluent/shield-filled.svg",
        active_section == Section::Reclaim,
        cx.listener(|this, _, _, cx| this.controller.select_section(Section::Reclaim, cx)),
    );
    let toggle = action_button(
        "collapse",
        if collapsed {
            "Expand navigation"
        } else {
            "Collapse navigation"
        },
        BtnStyle::new(ButtonVariant::Ghost, Size::Medium)
            .icon("fluent/navigation.svg")
            .icon_only(),
        cx.listener(|this, _, _, cx| {
            this.sidebar_collapsed = !this.sidebar_collapsed;
            cx.notify();
        }),
    );
    let title_row = div()
        .id("pane-title")
        .test_support()
        .flex_row_dir(cx)
        .h(px(40.))
        .items_center()
        .gap_2()
        .child(toggle)
        .children((!collapsed).then(|| {
            div()
                .text_size(px(14.))
                .font_semibold()
                .child("EasyTier Desktop")
        }));
    let header = div()
        .flex()
        .flex_col()
        .w_full()
        .gap_2()
        .child(title_row)
        .children((!collapsed).then_some(new_btn));
    let mut sidebar = Sidebar::new("sidebar-nav")
        .w(px(240.))
        .h_full()
        .bg(sidebar)
        .border_color(border)
        .border_0()
        .collapsed(collapsed)
        .header(header)
        .child(instances)
        .child(reclaim);
    if !collapsed {
        sidebar = sidebar.footer(div().w_full().child(theme_menu(cx)));
    }
    sidebar.into_any_element()
}

#[inline(never)]
fn render_section_content(
    view: &MainView,
    section: Section,
    banners: AnyElement,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let inner = match section {
        Section::Instances => instances::render_instances_workspace(view, cx),
        Section::Reclaim => reclaim::render_reclaim_view(view, cx),
        Section::Editor => render_editor(view, cx),
    };
    let page = div()
        .id("page-content")
        .test_support()
        .flex_1()
        .min_h_0()
        .min_w_0()
        .flex()
        .flex_col()
        .overflow_hidden()
        .bg(crate::theme::content_layer(cx))
        .border_t_1()
        .border_color(crate::theme::card_stroke(cx))
        .child(banners)
        .child(div().flex_1().min_h_0().overflow_hidden().child(inner));
    if LayoutDirection::global(cx).is_rtl() {
        page.rounded_tr(px(8.)).border_r_1().into_any_element()
    } else {
        page.rounded_tl(px(8.)).border_l_1().into_any_element()
    }
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
        let nav = render_sidebar(
            active_section,
            instance_count,
            reclaim_count,
            self.sidebar_collapsed,
            cx,
        );
        let content = render_section_content(self, active_section, banners, cx);

        div()
            .id("etd-main-root")
            .test_support()
            .flex_row_dir(cx)
            .size_full()
            .bg(background)
            .text_color(foreground)
            .overflow_hidden()
            .child(nav)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .child(header)
                    .child(content),
            )
    }
}
