//! Header bar and global status/alert banners:
//! - Host reconnecting banner
//! - "Cut, unconfirmed · retry" banner with per-instance Retry Confirm action
//! - `NotInstalled` → offer service install
//! - Elevated user host refused → offer the service
//! - Upgrade required, unverified host, tray-unavailable keep-window notice, and operations bar

use etd_app::{HostLink, OperationStatus, UserCommand, window_tray::ExitReason};
use etd_contract::{HostMode, HostPhase};
use gpui_kit::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{
        ActiveTheme as _, Sizable as _, StyledExt as _,
        button::{Button, ButtonVariants as _},
    },
    div,
};

use crate::{model::InstallStatus, views::MainView};

pub fn render_header(view: &MainView, cx: &mut Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
    let model = view.controller.model.read(cx);
    let mode_label = match model.store.negotiated.as_ref().map(|n| n.host_mode) {
        Some(HostMode::Service) => "System Service",
        Some(HostMode::User) => "User Host",
        Some(HostMode::ElevatedSession) => "Elevated Session",
        _ => "Disconnected",
    };
    let phase_label = match model.store.phase {
        HostPhase::Serving => "Serving",
        HostPhase::SelfCheck => "Self-Check",
        HostPhase::DiagnosticOnly => "Diagnostic Only",
        HostPhase::ShuttingDown => "Shutting Down",
        _ => "Idle",
    };
    let link_label = match &model.store.link {
        HostLink::Idle => "Idle".to_owned(),
        HostLink::NoHost => "No Host".to_owned(),
        HostLink::Launching(mode) => format!("Launching {mode:?}"),
        HostLink::LaunchFailed(_) => "Launch Failed".to_owned(),
        HostLink::Connecting => "Connecting".to_owned(),
        HostLink::Connected => format!("Connected ({mode_label} · {phase_label})"),
        HostLink::Reconnecting { attempt } => format!("Reconnecting (#{attempt})"),
        HostLink::UpgradeRequired { .. } => "Upgrade Required".to_owned(),
        HostLink::Closed => "Closed".to_owned(),
    };

    let tray_note = if model.tray_available {
        None
    } else {
        Some("No system tray")
    };

    let mut left = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_3()
        .child(
            div()
                .text_base()
                .font_semibold()
                .text_color(theme.foreground)
                .child("EasyTier Desktop"),
        )
        .child(
            div()
                .id("header-host-status")
                .role(Role::Status)
                .test_support()
                .aria_label(SharedString::from(link_label.clone()))
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(theme.secondary)
                .text_xs()
                .text_color(theme.secondary_foreground)
                .child(link_label),
        );

    if let Some(note) = tray_note {
        left = left.child(
            div()
                .id("header-no-tray-badge")
                .test_support()
                .aria_label(SharedString::from(note))
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(theme.warning.opacity(0.2))
                .text_xs()
                .text_color(theme.warning)
                .child(note),
        );
    }

    let right = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            Button::new("btn-connect-service")
                .xsmall()
                .outline()
                .label("Service")
                .on_click(cx.listener(|this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::Connect(HostMode::Service));
                })),
        )
        .child(
            Button::new("btn-connect-user")
                .xsmall()
                .outline()
                .label("User Host")
                .on_click(cx.listener(|this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::Connect(HostMode::User));
                })),
        )
        .child(
            Button::new("btn-refresh")
                .xsmall()
                .ghost()
                .label("Refresh")
                .on_click(cx.listener(|this, _, _, _| {
                    this.controller.send_command(UserCommand::Refresh);
                })),
        )
        .child(
            Button::new("btn-app-exit")
                .xsmall()
                .danger()
                .label("Exit")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.controller.request_exit(ExitReason::AppMenu, cx);
                })),
        );

    div()
        .id("app-header")
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .px_4()
        .py_2()
        .border_b_1()
        .border_color(theme.border)
        .bg(theme.title_bar)
        .child(left)
        .child(right)
}

pub fn render_banners(view: &MainView, cx: &mut Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
    let model = view.controller.model.read(cx);
    let store = &model.store;

    let mut stack = div().id("banners-stack").flex().flex_col();

    // 1. Host reconnecting banner
    if let HostLink::Reconnecting { attempt } = store.link {
        let msg = format!(
            "Host reconnecting (attempt {attempt}) — displaying last known state until connection resumes"
        );
        stack = stack.child(
            div()
                .id("banner-reconnecting")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.warning)
                .bg(theme.warning.opacity(0.14))
                .text_sm()
                .text_color(theme.foreground)
                .child(msg)
                .child(
                    Button::new("btn-reconnecting-refresh")
                        .xsmall()
                        .outline()
                        .label("Retry Now")
                        .on_click(cx.listener(|this, _, _, _| {
                            this.controller.send_command(UserCommand::Refresh);
                        })),
                ),
        );
    }

    // 2. "Cut, unconfirmed · retry" banner for every instance whose stop is not yet durable
    let cut_instances = model.cut_unconfirmed_instances();
    if !cut_instances.is_empty() {
        let names = cut_instances
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let summary = format!(
            "Cut, unconfirmed · retry: {names} — process stopped but stop intent is not durably recorded and may restart after reboot."
        );
        let mut actions = div().flex().flex_row().gap_2();
        for (id, name) in cut_instances {
            let btn_id = format!("btn-banner-retry-confirm-{}", id.0);
            let retry_id = id.clone();
            actions = actions.child(
                Button::new(SharedString::from(btn_id))
                    .xsmall()
                    .warning()
                    .label(SharedString::from(format!("Retry Confirm ({name})")))
                    .on_click(cx.listener(move |this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::RetryConfirmStop(retry_id.clone()));
                    })),
            );
        }
        stack = stack.child(
            div()
                .id("banner-cut-unconfirmed")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(summary.clone()))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.14))
                .text_sm()
                .text_color(theme.foreground)
                .child(summary)
                .child(actions),
        );
    }

    // 3. Elevated user host refused → offer the service
    if model.is_elevated_user_host_refused() {
        let msg = "Elevated user host refused: an elevated process cannot operate a user host. Use or install the system service instead.";
        stack = stack.child(
            div()
                .id("banner-elevated-user-refused")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.warning)
                .bg(theme.warning.opacity(0.16))
                .text_sm()
                .text_color(theme.foreground)
                .child(msg)
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap_2()
                        .child(
                            Button::new("btn-offer-service-connect")
                                .xsmall()
                                .primary()
                                .label("Use System Service")
                                .on_click(cx.listener(|this, _, _, _| {
                                    this.controller
                                        .send_command(UserCommand::Connect(HostMode::Service));
                                })),
                        )
                        .child(
                            Button::new("btn-offer-service-install")
                                .xsmall()
                                .outline()
                                .label("Install System Service")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.controller.request_service_install(cx);
                                })),
                        ),
                ),
        );
    } else if model.is_service_not_installed() {
        // 4. NotInstalled → offer service install
        let preview = model.install_command_preview.clone();
        let msg = format!(
            "System service is not installed. Install the service for full TUN support ({preview})."
        );
        let installing = matches!(model.install_status, Some(InstallStatus::InProgress));
        let mut actions = div().flex().flex_row().gap_2().child(
            Button::new("btn-install-service")
                .xsmall()
                .primary()
                .loading(installing)
                .label(if installing {
                    "Installing Service..."
                } else {
                    "Install System Service"
                })
                .on_click(cx.listener(|this, _, _, cx| {
                    this.controller.request_service_install(cx);
                })),
        );
        if !model.is_elevated {
            actions = actions.child(
                Button::new("btn-fallback-user-host")
                    .xsmall()
                    .outline()
                    .label("Use User Host (No TUN)")
                    .on_click(cx.listener(|this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::Connect(HostMode::User));
                    })),
            );
        }
        stack = stack.child(
            div()
                .id("banner-not-installed")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.info)
                .bg(theme.info.opacity(0.14))
                .text_sm()
                .text_color(theme.foreground)
                .child(msg)
                .child(actions),
        );
    } else if let HostLink::LaunchFailed(failure) = &store.link {
        let msg = format!(
            "Host launch failed ({:?}): {}",
            failure.kind, failure.message
        );
        stack = stack.child(
            div()
                .id("banner-launch-failed")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.12))
                .text_sm()
                .text_color(theme.foreground)
                .child(msg)
                .child(
                    Button::new("btn-retry-autoconnect")
                        .xsmall()
                        .outline()
                        .label("Retry Auto-Connect")
                        .on_click(cx.listener(|this, _, _, _| {
                            this.controller.send_command(UserCommand::AutoConnect);
                        })),
                ),
        );
    } else if store.link == HostLink::NoHost {
        let msg = if model.is_elevated {
            "No host is running. Running elevated: install or connect to the system service."
        } else {
            "No host is running. Install the system service for TUN mode, or start a user host."
        };
        let mut actions = div()
            .flex()
            .flex_row()
            .gap_2()
            .child(
                Button::new("btn-nohost-install-service")
                    .xsmall()
                    .primary()
                    .label("Install System Service")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.controller.request_service_install(cx);
                    })),
            )
            .child(
                Button::new("btn-nohost-connect-service")
                    .xsmall()
                    .outline()
                    .label("Connect Service")
                    .on_click(cx.listener(|this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::Connect(HostMode::Service));
                    })),
            );
        if !model.is_elevated {
            actions = actions.child(
                Button::new("btn-nohost-start-user")
                    .xsmall()
                    .secondary()
                    .label("Start User Host")
                    .on_click(cx.listener(|this, _, _, _| {
                        this.controller
                            .send_command(UserCommand::Connect(HostMode::User));
                    })),
            );
        }
        stack = stack.child(
            div()
                .id("banner-no-host")
                .role(Role::Status)
                .test_support()
                .aria_label(SharedString::from(msg))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.border)
                .bg(theme.secondary.opacity(0.45))
                .text_sm()
                .text_color(theme.foreground)
                .child(msg)
                .child(actions),
        );
    }

    // 5. Service install result feedback
    if let Some(InstallStatus::Failed(err)) = &model.install_status {
        let msg = format!("Service installation failed: {err}");
        stack = stack.child(
            div()
                .id("banner-install-failed")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.12))
                .text_xs()
                .text_color(theme.danger)
                .child(msg),
        );
    }

    // 6. Upgrade required
    if let HostLink::UpgradeRequired {
        host_major,
        host_minor,
    } = store.link
    {
        let msg = format!(
            "Service upgrade required: host speaks contract v{host_major}.{host_minor}, incompatible with this client."
        );
        stack = stack.child(
            div()
                .id("banner-upgrade-required")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.16))
                .text_sm()
                .text_color(theme.danger)
                .child(msg),
        );
    }

    // 7. Unverified host security warning
    if let Some(reason) = &store.unverified_host {
        let msg = format!("Unverified host endpoint blocked (nothing sent): {reason}");
        stack = stack.child(
            div()
                .id("banner-unverified-host")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.16))
                .text_sm()
                .text_color(theme.danger)
                .child(msg),
        );
    }

    // 8. Wayland / trayless fallback notice when close was vetoed
    if model.keep_window_notice {
        let msg = "System tray is unavailable on this desktop; window kept open. Use the Exit button to quit.";
        stack = stack.child(
            div()
                .id("banner-keep-window")
                .role(Role::Status)
                .test_support()
                .aria_label(SharedString::from(msg))
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.info)
                .bg(theme.info.opacity(0.12))
                .text_xs()
                .text_color(theme.foreground)
                .child(msg)
                .child(
                    Button::new("btn-dismiss-keep-window")
                        .xsmall()
                        .ghost()
                        .label("Dismiss")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.controller.dismiss_keep_window_notice(cx);
                        })),
                ),
        );
    }

    // 9. Profile store error banner
    if let Some(err) = &store.profile_error {
        let msg = format!("Profile library error: {err}");
        stack = stack.child(
            div()
                .id("banner-profile-error")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(msg.clone()))
                .px_4()
                .py_1()
                .border_b_1()
                .border_color(theme.warning)
                .bg(theme.warning.opacity(0.12))
                .text_xs()
                .text_color(theme.foreground)
                .child(msg),
        );
    }

    // 10. Unconfirmed / failed mutations bar
    let actionable_ops: Vec<_> = store
        .operations
        .iter()
        .filter(|op| {
            matches!(
                op.status,
                OperationStatus::Unconfirmed(_) | OperationStatus::Failed(_)
            )
        })
        .collect();
    if !actionable_ops.is_empty() {
        let mut bar = div()
            .id("operations-bar")
            .flex()
            .flex_col()
            .gap_1()
            .px_4()
            .py_2()
            .border_b_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.35));
        for op in actionable_ops {
            let req_id = op.request_id.clone();
            let req_id_dismiss = op.request_id.clone();
            let (label, can_retry) = match &op.status {
                OperationStatus::Unconfirmed(failure) => {
                    (format!("{:?} unconfirmed: {}", op.kind, failure.0), true)
                }
                OperationStatus::Failed(failure) => {
                    (format!("{:?} failed: {}", op.kind, failure.0), false)
                }
                _ => continue,
            };
            let mut row = div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .text_xs()
                .child(label);
            let mut btns = div().flex().flex_row().gap_1();
            if can_retry {
                btns = btns.child(
                    Button::new(SharedString::from(format!("btn-op-retry-{}", req_id.0)))
                        .xsmall()
                        .warning()
                        .label("Retry")
                        .on_click(cx.listener(move |this, _, _, _| {
                            this.controller
                                .send_command(UserCommand::RetryOperation(req_id.clone()));
                        })),
                );
            }
            btns = btns.child(
                Button::new(SharedString::from(format!(
                    "btn-op-dismiss-{}",
                    req_id_dismiss.0
                )))
                .xsmall()
                .ghost()
                .label("Dismiss")
                .on_click(cx.listener(move |this, _, _, _| {
                    this.controller
                        .send_command(UserCommand::DismissOperation(req_id_dismiss.clone()));
                })),
            );
            row = row.child(btns);
            bar = bar.child(row);
        }
        stack = stack.child(bar);
    }

    stack
}
