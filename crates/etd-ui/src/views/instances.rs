//! Instance list and selected-instance detail panel (Overview + capability-gated
//! Nodes, Routes, and Traffic pages).

use etd_app::{InstanceCondition, InstanceEntry, StateStore, UserCommand};
use etd_contract::{
    Desired, QueryKind, capability,
    v1::{ManagementAccess, Node, Route, TrafficStats},
};
use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{
        ActiveTheme as _, Sizable as _, StyledExt as _,
        button::{Button, ButtonVariant, ButtonVariants as _},
    },
    div, px,
};

use crate::{
    model::{DetailTab, Section, UiModel},
    views::MainView,
};

pub fn render_instances_workspace(view: &MainView, cx: &mut Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
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
                .border_color(theme.border)
                .overflow_y_scroll()
                .p_3()
                .child(render_instance_list(view, cx)),
        )
        .child(
            div()
                .id("instance-detail-pane")
                .flex_1()
                .h_full()
                .overflow_y_scroll()
                .p_4()
                .child(render_instance_detail(view, cx)),
        )
}

fn render_instance_list(view: &MainView, cx: &mut Context<MainView>) -> impl IntoElement {
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

    let mut list = div()
        .id("instance-list")
        .test_support()
        .flex()
        .flex_col()
        .gap_2();

    if instances.is_empty() {
        list = list.child(
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
                .child("No instances configured on this host yet. Click '+ New Network' to create one."),
        );
    } else {
        for entry in &instances {
            let is_selected = selected_id.as_ref() == Some(&entry.id);
            list = list.child(render_instance_card(entry, is_selected, cx));
        }
    }

    if !unapplied_profiles.is_empty() {
        let mut section = div()
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
            );
        for profile in &unapplied_profiles {
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
            section =
                section.child(
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
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "btn-load-profile-{}",
                                        profile.instance_id.0
                                    )))
                                    .xsmall()
                                    .outline()
                                    .label("Edit / Apply")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.open_edit_editor(
                                            profile_id.clone(),
                                            &profile_spec,
                                            window,
                                            cx,
                                        );
                                    })),
                                )
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "btn-delete-profile-{}",
                                        profile.instance_id.0
                                    )))
                                    .xsmall()
                                    .ghost()
                                    .label("Delete")
                                    .on_click(cx.listener(move |this, _, _, _| {
                                        this.controller.send_command(UserCommand::DeleteProfile(
                                            delete_id.clone(),
                                        ));
                                    })),
                                ),
                        ),
                );
        }
        list = list.child(section);
    }

    list
}

fn render_instance_card(
    entry: &InstanceEntry,
    is_selected: bool,
    cx: &mut Context<MainView>,
) -> impl IntoElement {
    let theme = cx.theme();
    let condition = entry.condition();
    let cond_label = UiModel::condition_label(condition);
    let display_name = entry.display_name().to_owned();
    let id = entry.id.clone();
    let id_select = id.clone();

    let (badge_bg, badge_fg) = match condition {
        InstanceCondition::Running | InstanceCondition::RunningBasic => {
            (theme.success.opacity(0.2), theme.success)
        }
        InstanceCondition::GaveUp
        | InstanceCondition::Quarantined
        | InstanceCondition::CutUnconfirmed => (theme.danger.opacity(0.2), theme.danger),
        InstanceCondition::Waiting | InstanceCondition::Backoff | InstanceCondition::Unknown => {
            (theme.warning.opacity(0.2), theme.warning)
        }
        _ => (theme.secondary, theme.secondary_foreground),
    };

    let state_badge_id = match condition {
        InstanceCondition::Waiting => format!("state-waiting-{}", id.0),
        InstanceCondition::GaveUp => format!("state-gave-up-{}", id.0),
        InstanceCondition::CutUnconfirmed => format!("state-cut-unconfirmed-{}", id.0),
        _ => format!("state-badge-{}", id.0),
    };

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
        .border_color(if is_selected {
            theme.primary
        } else {
            theme.border
        })
        .bg(if is_selected {
            theme.primary.opacity(0.08)
        } else {
            theme.secondary.opacity(0.25)
        })
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    Button::new(SharedString::from(format!("btn-select-instance-{}", id.0)))
                        .ghost()
                        .small()
                        .label(SharedString::from(display_name))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.controller.select_instance(Some(id_select.clone()), cx);
                        })),
                )
                .child(
                    div()
                        .id(SharedString::from(state_badge_id))
                        .role(Role::Status)
                        .test_support()
                        .aria_label(SharedString::from(cond_label))
                        .px_2()
                        .py_1()
                        .rounded_sm()
                        .bg(badge_bg)
                        .text_xs()
                        .font_semibold()
                        .text_color(badge_fg)
                        .child(cond_label),
                ),
        );

    // Extra state detail line (WAITING deferral notice, GAVE_UP circuit breaker, CutUnconfirmed, etc.)
    if condition == InstanceCondition::Waiting {
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
        card = card.child(
            div()
                .id(SharedString::from(format!("waiting-detail-{}", id.0)))
                .test_support()
                .aria_label(SharedString::from(detail.to_owned()))
                .text_xs()
                .text_color(theme.warning)
                .child(detail.to_owned()),
        );
    } else if condition == InstanceCondition::GaveUp {
        let attempts = entry.status.as_ref().map_or(0, |s| s.restart_attempt);
        let detail = format!(
            "Circuit breaker tripped after {attempts} abnormal exits. Manual retry required."
        );
        card = card.child(
            div()
                .id(SharedString::from(format!("gave-up-detail-{}", id.0)))
                .test_support()
                .aria_label(SharedString::from(detail.clone()))
                .text_xs()
                .text_color(theme.danger)
                .child(detail),
        );
    } else if condition == InstanceCondition::CutUnconfirmed {
        card = card.child(
            div()
                .text_xs()
                .text_color(theme.danger)
                .child("Stop intent not durably recorded; retry confirm to prevent restart."),
        );
    } else if let Some(status) = &entry.status
        && !status.message.is_empty()
    {
        card = card.child(
            div()
                .text_xs()
                .text_color(theme.muted_foreground)
                .child(status.message.clone()),
        );
    }

    // Per-instance action buttons
    let mut actions = div().flex().flex_row().flex_wrap().gap_1();

    match condition {
        InstanceCondition::Stopped => {
            let start_id = id.clone();
            actions = actions.child(
                Button::new(SharedString::from(format!("btn-start-{}", id.0)))
                    .xsmall()
                    .primary()
                    .label("Start")
                    .on_click(cx.listener(move |this, _, _, _| {
                        this.controller.send_command(UserCommand::SetDesired {
                            instance: start_id.clone(),
                            desired: Desired::Running,
                        });
                    })),
            );
        }
        InstanceCondition::Starting
        | InstanceCondition::RunningBasic
        | InstanceCondition::Running
        | InstanceCondition::Backoff
        | InstanceCondition::Waiting => {
            let stop_id = id.clone();
            actions = actions.child(
                Button::new(SharedString::from(format!("btn-stop-{}", id.0)))
                    .xsmall()
                    .secondary()
                    .label("Stop")
                    .on_click(cx.listener(move |this, _, _, _| {
                        this.controller.send_command(UserCommand::SetDesired {
                            instance: stop_id.clone(),
                            desired: Desired::Stopped,
                        });
                    })),
            );
        }
        InstanceCondition::GaveUp => {
            let retry_id = id.clone();
            actions = actions.child(
                Button::new(SharedString::from(format!("btn-retry-start-{}", id.0)))
                    .xsmall()
                    .warning()
                    .label("Retry Start")
                    .on_click(cx.listener(move |this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::RetryStart(retry_id.clone()));
                    })),
            );
        }
        InstanceCondition::CutUnconfirmed => {
            let retry_id = id.clone();
            actions = actions.child(
                Button::new(SharedString::from(format!("btn-retry-confirm-{}", id.0)))
                    .xsmall()
                    .danger()
                    .label("Retry Confirm")
                    .on_click(cx.listener(move |this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::RetryConfirmStop(retry_id.clone()));
                    })),
            );
        }
        InstanceCondition::Quarantined => {
            let reclaim_id = id.clone();
            actions = actions
                .child(
                    Button::new(SharedString::from(format!("btn-retry-reclaim-{}", id.0)))
                        .xsmall()
                        .warning()
                        .label("Retry Cleanup")
                        .on_click(cx.listener(move |this, _, _, _| {
                            this.controller
                                .send_command(UserCommand::RetryReclaim(reclaim_id.clone()));
                        })),
                )
                .child(
                    Button::new(SharedString::from(format!("btn-open-reclaim-{}", id.0)))
                        .xsmall()
                        .ghost()
                        .label("View Report")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.controller.select_section(Section::Reclaim, cx);
                        })),
                );
        }
        _ => {}
    }

    if let Some(spec) = entry.desired.as_ref().and_then(|d| d.spec.clone()) {
        let edit_id = id.clone();
        actions = actions.child(
            Button::new(SharedString::from(format!("btn-edit-{}", id.0)))
                .xsmall()
                .outline()
                .label("Edit")
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.open_edit_editor(edit_id.clone(), &spec, window, cx);
                })),
        );
    }

    let remove_id = id.clone();
    actions = actions.child(
        Button::new(SharedString::from(format!("btn-remove-{}", id.0)))
            .xsmall()
            .ghost()
            .label("Remove")
            .on_click(cx.listener(move |this, _, _, _| {
                this.controller.send_command(UserCommand::Remove {
                    instance: remove_id.clone(),
                    forget_profile: true,
                });
            })),
    );

    card.child(actions)
}

fn render_instance_detail(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let theme = cx.theme();
    let model = view.controller.model.read(cx);
    let store = &model.store;

    let Some(selected_id) = &model.selected_instance else {
        return div()
            .id("detail-empty")
            .test_support()
            .aria_label("Select an instance to view details")
            .p_6()
            .text_sm()
            .text_color(theme.muted_foreground)
            .child("Select an instance on the left to inspect its status and network data.")
            .into_any_element();
    };

    let Some(entry) = store.instance(selected_id) else {
        return div()
            .id("detail-missing")
            .p_6()
            .text_sm()
            .text_color(theme.muted_foreground)
            .child("Selected instance is no longer present.")
            .into_any_element();
    };

    let active_tab = model.detail_tab;
    let has_nodes = store.has_capability(capability::QUERY_NODES);
    let has_routes = store.has_capability(capability::QUERY_ROUTES);
    let has_traffic = store.has_capability(capability::QUERY_TRAFFIC);

    // Capability-gated tab bar: Nodes, Routes, and Traffic tabs are hidden when absent.
    let mut tabs = div().id("detail-tabs").flex().flex_row().gap_2().child(
        Button::new("tab-overview")
            .small()
            .with_variant(if active_tab == DetailTab::Overview {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            })
            .label("Overview")
            .on_click(cx.listener(|this, _, _, cx| {
                this.controller.select_detail_tab(DetailTab::Overview, cx);
            })),
    );

    if has_nodes {
        tabs = tabs.child(
            Button::new("tab-nodes")
                .small()
                .with_variant(if active_tab == DetailTab::Nodes {
                    ButtonVariant::Primary
                } else {
                    ButtonVariant::Secondary
                })
                .label("Nodes")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.controller.select_detail_tab(DetailTab::Nodes, cx);
                })),
        );
    }

    if has_routes {
        tabs = tabs.child(
            Button::new("tab-routes")
                .small()
                .with_variant(if active_tab == DetailTab::Routes {
                    ButtonVariant::Primary
                } else {
                    ButtonVariant::Secondary
                })
                .label("Routes")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.controller.select_detail_tab(DetailTab::Routes, cx);
                })),
        );
    }

    if has_traffic {
        tabs = tabs.child(
            Button::new("tab-traffic")
                .small()
                .with_variant(if active_tab == DetailTab::Traffic {
                    ButtonVariant::Primary
                } else {
                    ButtonVariant::Secondary
                })
                .label("Traffic")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.controller.select_detail_tab(DetailTab::Traffic, cx);
                })),
        );
    }

    let body = match active_tab {
        DetailTab::Overview => render_overview(entry, cx).into_any_element(),
        DetailTab::Nodes if has_nodes => render_nodes_page(store, entry, cx).into_any_element(),
        DetailTab::Routes if has_routes => render_routes_page(store, entry, cx).into_any_element(),
        DetailTab::Traffic if has_traffic => {
            render_traffic_page(store, entry, cx).into_any_element()
        }
        _ => render_overview(entry, cx).into_any_element(),
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
                        .child(entry.display_name().to_owned()),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format!("ID: {}", entry.id.0)),
                ),
        )
        .child(tabs)
        .child(body)
        .into_any_element()
}

fn render_overview(entry: &InstanceEntry, cx: &Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
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

    let mut panel = div()
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
        .border_color(theme.border)
        .bg(theme.secondary.opacity(0.2))
        .child(kv_row("State", condition, cx))
        .child(kv_row("Desired", &desired, cx))
        .child(kv_row("Epoch", &epoch.to_string(), cx))
        .child(kv_row("Interface", iface, cx))
        .child(kv_row("Addresses", &addrs, cx))
        .child(kv_row("Core Version", core_ver, cx))
        .child(kv_row("Management Access", mgmt, cx));

    if let Some(spec) = entry.desired.as_ref().and_then(|d| d.spec.as_ref()) {
        panel = panel
            .child(kv_row("Network Name", &spec.network_name, cx))
            .child(kv_row(
                "Network Secret",
                if spec.network_secret_set {
                    "Configured on host (never stored in UI)"
                } else {
                    "None"
                },
                cx,
            ))
            .child(kv_row(
                "Peers",
                &if spec.peers.is_empty() {
                    "—".to_owned()
                } else {
                    spec.peers.join(", ")
                },
                cx,
            ))
            .child(kv_row(
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
        panel = panel.child(kv_row(
            "Latest Notice",
            &format!("[{}] {}", notice.code, notice.message),
            cx,
        ));
    }

    panel
}

fn render_management_unavailable(
    page_id: &'static str,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> impl IntoElement {
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

fn render_nodes_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> impl IntoElement {
    if !entry.management_available() {
        return render_management_unavailable("page-nodes", entry, cx).into_any_element();
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
                        .border_color(theme.border)
                        .bg(theme.secondary.opacity(0.2))
                        .text_sm()
                        .child(summary),
                );
            }
        }
    }

    box_el.into_any_element()
}

fn render_routes_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> impl IntoElement {
    if !entry.management_available() {
        return render_management_unavailable("page-routes", entry, cx).into_any_element();
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
                        .border_color(theme.border)
                        .bg(theme.secondary.opacity(0.2))
                        .text_sm()
                        .child(summary),
                );
            }
        }
    }

    box_el.into_any_element()
}

fn render_traffic_page(
    store: &StateStore,
    entry: &InstanceEntry,
    cx: &Context<MainView>,
) -> impl IntoElement {
    if !entry.management_available() {
        return render_management_unavailable("page-traffic", entry, cx).into_any_element();
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
                    .border_color(theme.border)
                    .bg(theme.secondary.opacity(0.25))
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

fn kv_row(key: &str, value: &str, cx: &Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
    div()
        .flex()
        .flex_row()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(160.))
                .text_color(theme.muted_foreground)
                .child(key.to_owned()),
        )
        .child(div().flex_1().child(value.to_owned()))
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
