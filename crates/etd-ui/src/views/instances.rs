//! Instance list and selected-instance detail panel (Overview + capability-gated
//! Nodes, Routes, and Traffic pages).
//!
//! All controls are constructed via small `#[inline(never)]` helpers returning
//! [`AnyElement`] to keep Windows debug stack frames minimal.

use etd_app::{InstanceCondition, InstanceEntry, Profile, StateStore, UserCommand};
use etd_contract::{
    Desired, QueryKind, capability,
    v1::{ManagementAccess, Node, Route, TrafficStats},
};
use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant},
    div, px,
};

use crate::{
    model::{DetailTab, Section, UiModel},
    views::{
        MainView,
        ui::{BtnStyle, action_button},
    },
};

#[inline(never)]
pub fn render_instances_workspace(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let border = cx.theme().border;
    let list = render_instance_list(view, cx);
    let detail = render_instance_detail(view, cx);
    div()
        .flex()
        .flex_row()
        .size_full()
        .overflow_hidden()
        .child(
            div()
                .id("instance-list-pane")
                .w(px(340.))
                .h_full()
                .border_r_1()
                .border_color(border)
                .overflow_y_scroll()
                .p_3()
                .child(list),
        )
        .child(
            div()
                .id("instance-detail-pane")
                .flex_1()
                .h_full()
                .overflow_y_scroll()
                .p_4()
                .child(detail),
        )
        .into_any_element()
}

#[inline(never)]
fn render_instance_list(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let border = cx.theme().border;
    let muted_fg = cx.theme().muted_foreground;
    let (instances, unapplied_profiles, selected_id) = {
        let model = view.controller.model.read(cx);
        let store = &model.store;
        let instances: Vec<_> = store.instances.values().cloned().collect();
        let unapplied_profiles: Vec<_> = store
            .profiles
            .iter()
            .filter(|profile| !store.instances.contains_key(&profile.instance_id))
            .cloned()
            .collect();
        (
            instances,
            unapplied_profiles,
            model.selected_instance.clone(),
        )
    };

    let mut children: Vec<AnyElement> = Vec::new();
    if instances.is_empty() {
        children.push(
            div()
                .id("instance-list-empty")
                .test_support()
                .aria_label("No instances configured")
                .p_4()
                .rounded_md()
                .border_1()
                .border_color(border)
                .text_sm()
                .text_color(muted_fg)
                .child("No instances configured on this host yet. Click '+ New Network' to create one.")
                .into_any_element(),
        );
    } else {
        for entry in &instances {
            let is_selected = selected_id.as_ref() == Some(&entry.id);
            children.push(render_instance_card(entry, is_selected, cx));
        }
    }

    if !unapplied_profiles.is_empty() {
        children.push(render_saved_profiles(&unapplied_profiles, cx));
    }

    div()
        .id("instance-list")
        .test_support()
        .flex()
        .flex_col()
        .gap_2()
        .children(children)
        .into_any_element()
}

#[inline(never)]
fn render_saved_profiles(profiles: &[Profile], cx: &mut Context<MainView>) -> AnyElement {
    let muted_fg = cx.theme().muted_foreground;
    let rows: Vec<AnyElement> = profiles
        .iter()
        .map(|profile| render_profile_row(profile, cx))
        .collect();
    div()
        .id("saved-profiles-section")
        .flex()
        .flex_col()
        .gap_2()
        .mt_4()
        .child(
            div()
                .text_xs()
                .font_semibold()
                .text_color(muted_fg)
                .child("SAVED PROFILES (NOT ON HOST)"),
        )
        .children(rows)
        .into_any_element()
}

#[inline(never)]
fn render_profile_row(profile: &Profile, cx: &mut Context<MainView>) -> AnyElement {
    let border = cx.theme().border;
    let label = if !profile.spec.display_name.is_empty() {
        profile.spec.display_name.clone()
    } else if !profile.spec.network_name.is_empty() {
        profile.spec.network_name.clone()
    } else {
        profile.instance_id.0.clone()
    };
    let profile_id = profile.instance_id.clone();
    let profile_spec = profile.spec.clone();
    let delete_id = profile.instance_id.clone();

    let load_btn = action_button(
        SharedString::from(format!("btn-load-profile-{}", profile.instance_id.0)),
        "Edit / Apply",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
        cx.listener(move |this, _, window, cx| {
            this.open_edit_editor(profile_id.clone(), &profile_spec, window, cx);
        }),
    );
    let del_btn = action_button(
        SharedString::from(format!("btn-delete-profile-{}", profile.instance_id.0)),
        "Delete",
        BtnStyle::new(ButtonVariant::Ghost, Size::XSmall),
        cx.listener(move |this, _, _, _| {
            this.controller
                .send_command(UserCommand::DeleteProfile(delete_id.clone()));
        }),
    );

    div()
        .id(SharedString::from(format!(
            "profile-row-{}",
            profile.instance_id.0
        )))
        .test_support()
        .aria_label(SharedString::from(label.clone()))
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .p_2()
        .rounded_md()
        .border_1()
        .border_color(border)
        .child(div().text_sm().child(label))
        .child(
            div()
                .flex()
                .flex_row()
                .gap_1()
                .child(load_btn)
                .child(del_btn),
        )
        .into_any_element()
}

#[inline(never)]
fn render_instance_card(
    entry: &InstanceEntry,
    is_selected: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let (card_bg, card_border) = crate::views::ui::list_selection_surface(is_selected, cx);
    let secondary = cx.theme().secondary;
    let secondary_fg = cx.theme().secondary_foreground;
    let success = cx.theme().success;
    let danger = cx.theme().danger;
    let warning = cx.theme().warning;

    let condition = entry.condition();
    let cond_label = UiModel::condition_label(condition);
    let display_name = entry.display_name().to_owned();
    let id = entry.id.clone();
    let id_select = id.clone();

    let (badge_bg, badge_fg) = match condition {
        InstanceCondition::Running | InstanceCondition::RunningBasic => {
            (success.opacity(0.15), success)
        }
        InstanceCondition::GaveUp
        | InstanceCondition::Quarantined
        | InstanceCondition::CutUnconfirmed => (danger.opacity(0.15), danger),
        InstanceCondition::Waiting | InstanceCondition::Backoff | InstanceCondition::Unknown => {
            (warning.opacity(0.15), warning)
        }
        _ => (secondary, secondary_fg),
    };

    let state_badge_id = match condition {
        InstanceCondition::Waiting => format!("state-waiting-{}", id.0),
        InstanceCondition::GaveUp => format!("state-gave-up-{}", id.0),
        InstanceCondition::CutUnconfirmed => format!("state-cut-unconfirmed-{}", id.0),
        _ => format!("state-badge-{}", id.0),
    };

    let select_btn = crate::views::ui::list_choice_button(
        SharedString::from(format!("btn-select-instance-{}", id.0)),
        SharedString::from(display_name.clone()),
        is_selected,
        cx.listener(move |this, _, _, cx| {
            this.controller.select_instance(Some(id_select.clone()), cx);
        }),
    );

    let badge = div()
        .id(SharedString::from(state_badge_id))
        .role(Role::Status)
        .test_support()
        .aria_label(SharedString::from(cond_label))
        .flex_shrink_0()
        .px_2()
        .py_1()
        .rounded_sm()
        .bg(badge_bg)
        .text_xs()
        .font_semibold()
        .text_color(badge_fg)
        .child(cond_label);

    let mut card = div()
        .id(SharedString::from(format!("instance-row-{}", id.0)))
        .test_support()
        .aria_label(SharedString::from(format!("{display_name} ({cond_label})")))
        .flex()
        .flex_col()
        .gap_2()
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(card_border)
        .bg(card_bg)
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .child(select_btn)
                .child(badge),
        );

    if let Some(detail) = render_card_status_detail(entry, cx) {
        card = card.child(detail);
    }

    card.child(render_card_actions(entry, cx))
        .into_any_element()
}

#[inline(never)]
fn render_card_status_detail(entry: &InstanceEntry, cx: &Context<MainView>) -> Option<AnyElement> {
    let warning = cx.theme().warning;
    let danger = cx.theme().danger;
    let muted = cx.theme().muted_foreground;
    let id = &entry.id;

    match entry.condition() {
        InstanceCondition::Waiting => {
            let detail = entry
                .notice
                .as_ref()
                .map(|n| n.message.as_str())
                .filter(|m| !m.is_empty())
                .or_else(|| {
                    entry
                        .status
                        .as_ref()
                        .map(|s| s.message.as_str())
                        .filter(|m| !m.is_empty())
                })
                .unwrap_or("Start deferred while another instance holds a shared resource.");
            Some(
                div()
                    .id(SharedString::from(format!("waiting-detail-{}", id.0)))
                    .test_support()
                    .aria_label(SharedString::from(detail.to_owned()))
                    .text_xs()
                    .text_color(warning)
                    .child(detail.to_owned())
                    .into_any_element(),
            )
        }
        InstanceCondition::GaveUp => {
            let attempts = entry.status.as_ref().map_or(0, |s| s.restart_attempt);
            let detail = format!(
                "Circuit breaker tripped after {attempts} abnormal exits. Manual retry required."
            );
            Some(
                div()
                    .id(SharedString::from(format!("gave-up-detail-{}", id.0)))
                    .test_support()
                    .aria_label(SharedString::from(detail.clone()))
                    .text_xs()
                    .text_color(danger)
                    .child(detail)
                    .into_any_element(),
            )
        }
        InstanceCondition::CutUnconfirmed => Some(
            div()
                .text_xs()
                .text_color(danger)
                .child("Stop intent not durably recorded; retry confirm to prevent restart.")
                .into_any_element(),
        ),
        _ => entry
            .status
            .as_ref()
            .filter(|s| !s.message.is_empty())
            .map(|s| {
                div()
                    .text_xs()
                    .text_color(muted)
                    .child(s.message.clone())
                    .into_any_element()
            }),
    }
}

#[inline(never)]
fn render_card_actions(entry: &InstanceEntry, cx: &mut Context<MainView>) -> AnyElement {
    let id = entry.id.clone();
    let mut btns: Vec<AnyElement> = Vec::new();

    match entry.condition() {
        InstanceCondition::Stopped => {
            let start_id = id.clone();
            btns.push(action_button(
                SharedString::from(format!("btn-start-{}", id.0)),
                "Start",
                BtnStyle::new(ButtonVariant::Primary, Size::XSmall),
                cx.listener(move |this, _, _, _| {
                    this.controller.send_command(UserCommand::SetDesired {
                        instance: start_id.clone(),
                        desired: Desired::Running,
                    });
                }),
            ));
        }
        InstanceCondition::Starting
        | InstanceCondition::RunningBasic
        | InstanceCondition::Running
        | InstanceCondition::Backoff
        | InstanceCondition::Waiting => {
            let stop_id = id.clone();
            btns.push(action_button(
                SharedString::from(format!("btn-stop-{}", id.0)),
                "Stop",
                BtnStyle::new(ButtonVariant::Secondary, Size::XSmall),
                cx.listener(move |this, _, _, _| {
                    this.controller.send_command(UserCommand::SetDesired {
                        instance: stop_id.clone(),
                        desired: Desired::Stopped,
                    });
                }),
            ));
        }
        InstanceCondition::GaveUp => {
            let retry_id = id.clone();
            btns.push(action_button(
                SharedString::from(format!("btn-retry-start-{}", id.0)),
                "Retry Start",
                BtnStyle::new(ButtonVariant::Warning, Size::XSmall),
                cx.listener(move |this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::RetryStart(retry_id.clone()));
                }),
            ));
        }
        InstanceCondition::CutUnconfirmed => {
            let retry_id = id.clone();
            btns.push(action_button(
                SharedString::from(format!("btn-retry-confirm-{}", id.0)),
                "Retry Confirm",
                BtnStyle::new(ButtonVariant::Danger, Size::XSmall),
                cx.listener(move |this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::RetryConfirmStop(retry_id.clone()));
                }),
            ));
        }
        InstanceCondition::Quarantined => {
            let reclaim_id = id.clone();
            btns.push(action_button(
                SharedString::from(format!("btn-retry-reclaim-{}", id.0)),
                "Retry Cleanup",
                BtnStyle::new(ButtonVariant::Warning, Size::XSmall),
                cx.listener(move |this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::RetryReclaim(reclaim_id.clone()));
                }),
            ));
            btns.push(action_button(
                SharedString::from(format!("btn-open-reclaim-{}", id.0)),
                "View Report",
                BtnStyle::new(ButtonVariant::Ghost, Size::XSmall),
                cx.listener(|this, _, _, cx| {
                    this.controller.select_section(Section::Reclaim, cx);
                }),
            ));
        }
        _ => {}
    }

    if let Some(spec) = entry.desired.as_ref().and_then(|d| d.spec.clone()) {
        let edit_id = id.clone();
        btns.push(action_button(
            SharedString::from(format!("btn-edit-{}", id.0)),
            "Edit",
            BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
            cx.listener(move |this, _, window, cx| {
                this.open_edit_editor(edit_id.clone(), &spec, window, cx);
            }),
        ));
    }

    let remove_id = id.clone();
    btns.push(action_button(
        SharedString::from(format!("btn-remove-{}", id.0)),
        "Remove",
        BtnStyle::new(ButtonVariant::Ghost, Size::XSmall),
        cx.listener(move |this, _, _, _| {
            this.controller.send_command(UserCommand::Remove {
                instance: remove_id.clone(),
                forget_profile: true,
            });
        }),
    ));

    div()
        .flex()
        .flex_row()
        .flex_wrap()
        .gap_1()
        .children(btns)
        .into_any_element()
}

#[inline(never)]
fn render_instance_detail(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let muted_fg = cx.theme().muted_foreground;
    let (selected_entry, active_tab, has_nodes, has_routes, has_traffic) = {
        let model = view.controller.model.read(cx);
        let store = &model.store;
        let Some(selected_id) = &model.selected_instance else {
            return div()
                .id("detail-empty")
                .test_support()
                .aria_label("Select an instance to view details")
                .p_6()
                .text_sm()
                .text_color(muted_fg)
                .child("Select an instance on the left to inspect its status and network data.")
                .into_any_element();
        };
        let Some(entry) = store.instance(selected_id).cloned() else {
            return div()
                .id("detail-missing")
                .p_6()
                .text_sm()
                .text_color(muted_fg)
                .child("Selected instance is no longer present.")
                .into_any_element();
        };
        (
            entry,
            model.detail_tab,
            store.has_capability(capability::QUERY_NODES),
            store.has_capability(capability::QUERY_ROUTES),
            store.has_capability(capability::QUERY_TRAFFIC),
        )
    };

    let tabs = render_detail_tabs(active_tab, has_nodes, has_routes, has_traffic, cx);
    let store = &view.controller.model.read(cx).store;
    let body = match active_tab {
        DetailTab::Overview => render_overview(&selected_entry, cx),
        DetailTab::Nodes if has_nodes => render_nodes_page(store, &selected_entry, cx),
        DetailTab::Routes if has_routes => render_routes_page(store, &selected_entry, cx),
        DetailTab::Traffic if has_traffic => render_traffic_page(store, &selected_entry, cx),
        _ => render_overview(&selected_entry, cx),
    };

    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_lg()
                        .font_semibold()
                        .child(selected_entry.display_name().to_owned()),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(muted_fg)
                        .child(format!("ID: {}", selected_entry.id.0)),
                ),
        )
        .child(tabs)
        .child(body)
        .into_any_element()
}

#[inline(never)]
fn render_detail_tabs(
    active_tab: DetailTab,
    has_nodes: bool,
    has_routes: bool,
    has_traffic: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let variant_for = |tab: DetailTab| {
        if active_tab == tab {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        }
    };

    let mut btns = vec![action_button(
        "tab-overview",
        "Overview",
        BtnStyle::new(variant_for(DetailTab::Overview), Size::Small),
        cx.listener(|this, _, _, cx| {
            this.controller.select_detail_tab(DetailTab::Overview, cx);
        }),
    )];

    if has_nodes {
        btns.push(action_button(
            "tab-nodes",
            "Nodes",
            BtnStyle::new(variant_for(DetailTab::Nodes), Size::Small),
            cx.listener(|this, _, _, cx| {
                this.controller.select_detail_tab(DetailTab::Nodes, cx);
            }),
        ));
    }
    if has_routes {
        btns.push(action_button(
            "tab-routes",
            "Routes",
            BtnStyle::new(variant_for(DetailTab::Routes), Size::Small),
            cx.listener(|this, _, _, cx| {
                this.controller.select_detail_tab(DetailTab::Routes, cx);
            }),
        ));
    }
    if has_traffic {
        btns.push(action_button(
            "tab-traffic",
            "Traffic",
            BtnStyle::new(variant_for(DetailTab::Traffic), Size::Small),
            cx.listener(|this, _, _, cx| {
                this.controller.select_detail_tab(DetailTab::Traffic, cx);
            }),
        ));
    }

    div()
        .id("detail-tabs")
        .flex()
        .flex_row()
        .gap_2()
        .children(btns)
        .into_any_element()
}

#[inline(never)]
fn render_overview(entry: &InstanceEntry, cx: &Context<MainView>) -> AnyElement {
    let condition = UiModel::condition_label(entry.condition());
    let desired = format!("{:?}", entry.desired_state());
    let epoch = entry.status.as_ref().map_or(0, |s| s.epoch);
    let iface = entry
        .status
        .as_ref()
        .map(|s| s.interface_name.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("—");
    let addrs = entry
        .status
        .as_ref()
        .filter(|s| !s.addresses.is_empty())
        .map(|s| s.addresses.join(", "))
        .unwrap_or_else(|| "—".to_owned());
    let core_ver = entry
        .status
        .as_ref()
        .map(|s| s.core_version.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("—");
    let mgmt = entry
        .status
        .as_ref()
        .map(|s| match s.management() {
            ManagementAccess::Available => "Available",
            ManagementAccess::Pending => "Pending",
            ManagementAccess::DenyAll => "Unavailable (Deny-All Fence Fallback)",
            ManagementAccess::LifecycleOnly => "Unavailable (Lifecycle-Only Kernel)",
            _ => "Unspecified",
        })
        .unwrap_or("—");

    let mut rows = vec![
        kv_row("State", condition, cx),
        kv_row("Desired", &desired, cx),
        kv_row("Epoch", &epoch.to_string(), cx),
        kv_row("Interface", iface, cx),
        kv_row("Addresses", &addrs, cx),
        kv_row("Core Version", core_ver, cx),
        kv_row("Management Access", mgmt, cx),
    ];

    if let Some(spec) = entry.desired.as_ref().and_then(|d| d.spec.as_ref()) {
        rows.push(kv_row("Network Name", &spec.network_name, cx));
        rows.push(kv_row(
            "Network Secret",
            if spec.network_secret_set {
                "Configured on host (never stored in UI)"
            } else {
                "None"
            },
            cx,
        ));
        rows.push(kv_row(
            "Peers",
            &if spec.peers.is_empty() {
                "—".to_owned()
            } else {
                spec.peers.join(", ")
            },
            cx,
        ));
        rows.push(kv_row(
            "Listeners",
            &if spec.no_listener {
                "Disabled".to_owned()
            } else if spec.listeners.is_empty() {
                "Dial-out only".to_owned()
            } else {
                spec.listeners.join(", ")
            },
            cx,
        ));
    }

    if let Some(notice) = &entry.notice {
        rows.push(kv_row(
            "Latest Notice",
            &format!("[{}] {}", notice.code, notice.message),
            cx,
        ));
    }

    div()
        .id("page-overview")
        .test_support()
        .aria_label(SharedString::from(format!(
            "Overview: {condition}, desired {desired}"
        )))
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(crate::theme::card_stroke(cx))
        .bg(crate::theme::card_fill(cx))
        .children(rows)
        .into_any_element()
}

#[inline(never)]
fn render_management_unavailable(
    page_id: &'static str,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> AnyElement {
    let theme = cx.theme();
    let reason = entry
        .status
        .as_ref()
        .map(|s| match s.management() {
            ManagementAccess::DenyAll => {
                "Management RPC is disabled for this instance (verified deny-all fallback)."
            }
            ManagementAccess::LifecycleOnly => {
                "Management RPC is unavailable for unprofiled kernels (lifecycle-only mode)."
            }
            ManagementAccess::Pending => "Management RPC is pending verification.",
            _ => "Management data is currently unavailable for this instance.",
        })
        .unwrap_or("Management data is currently unavailable for this instance.");
    div()
        .id(page_id)
        .test_support()
        .aria_label(SharedString::from(reason))
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(theme.border)
        .text_sm()
        .text_color(theme.muted_foreground)
        .child(reason)
        .into_any_element()
}

fn query_error_for(
    store: &StateStore,
    id: &etd_contract::InstanceId,
    kind: QueryKind,
) -> Option<String> {
    store
        .watched
        .as_ref()
        .filter(|w| &w.id == id)
        .and_then(|w| {
            w.errors
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, failure)| failure.0.to_string())
        })
}

#[inline(never)]
fn render_nodes_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> AnyElement {
    if !entry.management_available() {
        return render_management_unavailable("page-nodes", entry, cx);
    }
    let theme = cx.theme();
    let nodes: Option<&[Node]> = store
        .watched
        .as_ref()
        .filter(|w| w.id == entry.id)
        .and_then(|w| w.nodes.as_deref());

    let mut box_el = div()
        .id("page-nodes")
        .test_support()
        .aria_label("Nodes page")
        .flex()
        .flex_col()
        .gap_2();

    if let Some(err) = query_error_for(store, &entry.id, QueryKind::Nodes) {
        box_el = box_el.child(
            div()
                .text_xs()
                .text_color(theme.danger)
                .child(format!("Nodes query error: {err}")),
        );
    }

    match nodes {
        None => {
            box_el = box_el.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("Waiting for node data..."),
            );
        }
        Some([]) => {
            box_el = box_el.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("No peer nodes reported."),
            );
        }
        Some(list) => {
            for node in list {
                let latency_ms = node.latency_us as f64 / 1000.0;
                let loss_pct = node.loss_rate * 100.0;
                let summary = format!(
                    "{}{} | {} | {:.1} ms | loss {:.1}% | NAT: {} | tunnels: {}",
                    node.hostname,
                    if node.is_self { " (self)" } else { "" },
                    node.ipv4_cidr,
                    latency_ms,
                    loss_pct,
                    node.nat_type,
                    node.tunnels.join(", "),
                );
                box_el = box_el.child(
                    div()
                        .id(SharedString::from(format!("node-row-{}", node.peer_id)))
                        .test_support()
                        .aria_label(SharedString::from(summary.clone()))
                        .p_3()
                        .rounded_md()
                        .border_1()
                        .border_color(crate::theme::card_stroke(cx))
                        .bg(crate::theme::card_fill(cx))
                        .text_sm()
                        .child(summary),
                );
            }
        }
    }

    box_el.into_any_element()
}

#[inline(never)]
fn render_routes_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> AnyElement {
    if !entry.management_available() {
        return render_management_unavailable("page-routes", entry, cx);
    }
    let theme = cx.theme();
    let routes: Option<&[Route]> = store
        .watched
        .as_ref()
        .filter(|w| w.id == entry.id)
        .and_then(|w| w.routes.as_deref());

    let mut box_el = div()
        .id("page-routes")
        .test_support()
        .aria_label("Routes page")
        .flex()
        .flex_col()
        .gap_2();

    if let Some(err) = query_error_for(store, &entry.id, QueryKind::Routes) {
        box_el = box_el.child(
            div()
                .text_xs()
                .text_color(theme.danger)
                .child(format!("Routes query error: {err}")),
        );
    }

    match routes {
        None => {
            box_el = box_el.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("Waiting for route table..."),
            );
        }
        Some([]) => {
            box_el = box_el.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("No routes reported."),
            );
        }
        Some(list) => {
            for route in list {
                let latency_ms = route.path_latency_us as f64 / 1000.0;
                let summary = format!(
                    "{} ({}) -> next hop #{} | cost {} | {:.1} ms | proxy: {}",
                    route.hostname,
                    route.ipv4_cidr,
                    route.next_hop_peer_id,
                    route.cost,
                    latency_ms,
                    if route.proxy_cidrs.is_empty() {
                        "—".to_owned()
                    } else {
                        route.proxy_cidrs.join(", ")
                    }
                );
                box_el = box_el.child(
                    div()
                        .id(SharedString::from(format!("route-row-{}", route.peer_id)))
                        .test_support()
                        .aria_label(SharedString::from(summary.clone()))
                        .p_3()
                        .rounded_md()
                        .border_1()
                        .border_color(crate::theme::card_stroke(cx))
                        .bg(crate::theme::card_fill(cx))
                        .text_sm()
                        .child(summary),
                );
            }
        }
    }

    box_el.into_any_element()
}

#[inline(never)]
fn render_traffic_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> AnyElement {
    if !entry.management_available() {
        return render_management_unavailable("page-traffic", entry, cx);
    }
    let theme = cx.theme();
    let traffic: Option<&TrafficStats> = store
        .watched
        .as_ref()
        .filter(|w| w.id == entry.id)
        .and_then(|w| w.traffic.as_ref());

    let mut box_el = div()
        .id("page-traffic")
        .test_support()
        .aria_label("Traffic page")
        .flex()
        .flex_col()
        .gap_2();

    if let Some(err) = query_error_for(store, &entry.id, QueryKind::Traffic) {
        box_el = box_el.child(
            div()
                .text_xs()
                .text_color(theme.danger)
                .child(format!("Traffic query error: {err}")),
        );
    }

    match traffic {
        None => {
            box_el = box_el.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("Waiting for traffic statistics..."),
            );
        }
        Some(stats) => {
            let totals = format!(
                "RX {} ({} pkts) | TX {} ({} pkts)",
                format_bytes(stats.rx_bytes),
                stats.rx_packets,
                format_bytes(stats.tx_bytes),
                stats.tx_packets,
            );
            box_el = box_el.child(
                div()
                    .id("traffic-totals")
                    .test_support()
                    .aria_label(SharedString::from(totals.clone()))
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(crate::theme::card_stroke(cx))
                    .bg(crate::theme::card_fill(cx))
                    .text_sm()
                    .font_medium()
                    .child(totals),
            );
            for peer in &stats.peers {
                let row = format!(
                    "Peer #{}: RX {} / TX {}",
                    peer.peer_id,
                    format_bytes(peer.rx_bytes),
                    format_bytes(peer.tx_bytes)
                );
                box_el = box_el.child(
                    div()
                        .id(SharedString::from(format!("traffic-peer-{}", peer.peer_id)))
                        .test_support()
                        .aria_label(SharedString::from(row.clone()))
                        .p_2()
                        .rounded_sm()
                        .border_1()
                        .border_color(theme.border)
                        .text_xs()
                        .child(row),
                );
            }
        }
    }

    box_el.into_any_element()
}

#[inline(never)]
fn kv_row(key: &str, value: &str, cx: &Context<MainView>) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    div()
        .flex()
        .flex_row()
        .gap_3()
        .text_sm()
        .child(div().w(px(160.)).text_color(muted).child(key.to_owned()))
        .child(div().flex_1().child(value.to_owned()))
        .into_any_element()
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}
