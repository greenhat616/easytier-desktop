//! Header bar and global status/alert banners:
//! - Host reconnecting banner
//! - "Cut, unconfirmed · retry" banner with per-instance Retry Confirm action
//! - `NotInstalled` → offer service install
//! - Elevated user host refused → offer the service
//! - Upgrade required, unverified host, tray-unavailable keep-window notice, and operations bar
//!
//! Each banner is rendered in its own `#[inline(never)]` helper returning
//! [`AnyElement`] so debug stack frames remain small on Windows' 1 MiB main stack.

use etd_app::{
    HostLink, LaunchFailure, Operation, OperationStatus, UserCommand, window_tray::ExitReason,
};
use etd_contract::{HostMode, HostPhase, InstanceId};
use gpui_kit::{
    AnyElement, App, Context, Hsla, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant},
    div,
};

use crate::{
    model::InstallStatus,
    views::{
        MainView,
        ui::{BtnStyle, FluentInfoBar, InfoSeverity, action_button},
    },
};

#[inline(never)]
pub fn render_header(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let sec_bg = cx.theme().secondary;
    let sec_fg = cx.theme().secondary_foreground;
    let warn = cx.theme().warning;
    let border = cx.theme().border;
    let title_bar = crate::theme::chrome_fill(cx, cx.theme().title_bar);

    let (link_label, tray_available) = {
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
        (link_label, model.tray_available)
    };

    let mut left = div().flex().flex_row().items_center().gap_3().child(
        div()
            .id("header-host-status")
            .role(Role::Status)
            .test_support()
            .aria_label(SharedString::from(link_label.clone()))
            .px_2()
            .py_1()
            .rounded_sm()
            .bg(sec_bg)
            .text_xs()
            .text_color(sec_fg)
            .child(link_label),
    );

    if !tray_available {
        let note = "No system tray";
        left = left.child(
            div()
                .id("header-no-tray-badge")
                .test_support()
                .aria_label(SharedString::from(note))
                .px_2()
                .py_1()
                .rounded_sm()
                // Keep the warning pill readable even over native Mica.
                .bg(Hsla::from(
                    cx.theme()
                        .popover
                        .to_rgb()
                        .blend(warn.opacity(0.2).to_rgb()),
                ))
                .text_xs()
                .text_color(warn)
                .child(note),
        );
    }

    let svc_btn = action_button(
        "btn-connect-service",
        "Service",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall)
            .outline()
            .icon("fluent/server.svg"),
        cx.listener(|this, _, _, _| {
            this.controller
                .send_command(UserCommand::Connect(HostMode::Service));
        }),
    );
    let user_btn = action_button(
        "btn-connect-user",
        "User Host",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall)
            .outline()
            .icon("fluent/person.svg"),
        cx.listener(|this, _, _, _| {
            this.controller
                .send_command(UserCommand::Connect(HostMode::User));
        }),
    );
    let refresh_btn = action_button(
        "btn-refresh",
        "Refresh",
        BtnStyle::new(ButtonVariant::Ghost, Size::XSmall).icon("fluent/arrow-clockwise.svg"),
        cx.listener(|this, _, _, _| {
            this.controller.send_command(UserCommand::Refresh);
        }),
    );
    let exit_btn = action_button(
        "btn-app-exit",
        "Exit",
        BtnStyle::new(ButtonVariant::Danger, Size::XSmall).icon("fluent/sign-out.svg"),
        cx.listener(|this, _, _, cx| {
            this.controller.request_exit(ExitReason::AppMenu, cx);
        }),
    );

    let right = div()
        .flex_shrink_0()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .child(svc_btn)
        .child(user_btn)
        .child(refresh_btn)
        .child(exit_btn);

    div()
        .id("app-header")
        .test_support()
        .h(gpui_kit::px(52.))
        .flex_shrink_0()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .px_4()
        .py_2()
        .border_b_1()
        .border_color(border)
        .bg(title_bar)
        .child(left)
        .child(right)
        .into_any_element()
}

#[inline(never)]
pub fn render_banners(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let mut items: Vec<AnyElement> = Vec::new();

    let (
        reconnecting_attempt,
        cut_instances,
        elevated_refused,
        not_installed,
        launch_failure,
        no_host,
        is_elevated,
        install_status,
        install_preview,
        upgrade_required,
        unverified_host,
        keep_window_notice,
        profile_error,
        actionable_ops,
    ) = {
        let model = view.controller.model.read(cx);
        let store = &model.store;
        let reconnecting_attempt = match store.link {
            HostLink::Reconnecting { attempt } => Some(attempt),
            _ => None,
        };
        let launch_failure = match &store.link {
            HostLink::LaunchFailed(f) => Some(f.clone()),
            _ => None,
        };
        let upgrade_required = match store.link {
            HostLink::UpgradeRequired {
                host_major,
                host_minor,
            } => Some((host_major, host_minor)),
            _ => None,
        };
        let actionable_ops: Vec<Operation> = store
            .operations
            .iter()
            .filter(|op| {
                matches!(
                    op.status,
                    OperationStatus::Unconfirmed(_) | OperationStatus::Failed(_)
                )
            })
            .cloned()
            .collect();
        (
            reconnecting_attempt,
            model.cut_unconfirmed_instances(),
            model.is_elevated_user_host_refused(),
            model.is_service_not_installed(),
            launch_failure,
            store.link == HostLink::NoHost,
            model.is_elevated,
            model.install_status.clone(),
            model.install_command_preview.clone(),
            upgrade_required,
            store.unverified_host.clone(),
            model.keep_window_notice,
            store.profile_error.clone(),
            actionable_ops,
        )
    };

    if let Some(attempt) = reconnecting_attempt {
        items.push(render_reconnecting_banner(attempt, cx));
    }
    if !cut_instances.is_empty() {
        items.push(render_cut_unconfirmed_banner(cut_instances, cx));
    }
    if elevated_refused {
        items.push(render_elevated_refused_banner(cx));
    } else if not_installed {
        items.push(render_not_installed_banner(
            &install_preview,
            matches!(install_status, Some(InstallStatus::InProgress)),
            is_elevated,
            cx,
        ));
    } else if let Some(failure) = launch_failure {
        items.push(render_launch_failed_banner(&failure, cx));
    } else if no_host {
        items.push(render_no_host_banner(is_elevated, cx));
    }

    if let Some(InstallStatus::Failed(err)) = install_status {
        items.push(render_simple_alert(
            "banner-install-failed",
            format!("Service installation failed: {err}"),
            InfoSeverity::Error,
            cx,
        ));
    }
    if let Some((host_major, host_minor)) = upgrade_required {
        items.push(render_simple_alert(
            "banner-upgrade-required",
            format!(
                "Service upgrade required: host speaks contract v{host_major}.{host_minor}, incompatible with this client."
            ),
            InfoSeverity::Error,
            cx,
        ));
    }
    if let Some(reason) = unverified_host {
        items.push(render_simple_alert(
            "banner-unverified-host",
            format!("Unverified host endpoint blocked (nothing sent): {reason}"),
            InfoSeverity::Error,
            cx,
        ));
    }
    if keep_window_notice {
        items.push(render_keep_window_banner(cx));
    }
    if let Some(err) = profile_error {
        items.push(render_simple_alert(
            "banner-profile-error",
            format!("Profile library error: {err}"),
            InfoSeverity::Warning,
            cx,
        ));
    }
    if !actionable_ops.is_empty() {
        items.push(render_operations_bar(&actionable_ops, cx));
    }

    let has_items = !items.is_empty();
    let stack = div()
        .id("banners-stack")
        .test_support()
        .flex()
        .flex_col()
        .gap_2()
        .children(items);
    let stack = if has_items {
        stack.px(gpui_kit::px(24.)).pt_3().pb_2()
    } else {
        stack
    };
    stack.into_any_element()
}

#[inline(never)]
fn render_reconnecting_banner(attempt: u32, cx: &mut Context<MainView>) -> AnyElement {
    let msg = format!(
        "Host reconnecting (attempt {attempt}) — displaying last known state until connection resumes"
    );
    let btn = action_button(
        "btn-reconnecting-refresh",
        "Retry Now",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
        cx.listener(|this, _, _, _| {
            this.controller.send_command(UserCommand::Refresh);
        }),
    );
    FluentInfoBar::new("banner-reconnecting", InfoSeverity::Warning, msg)
        .title("Connection interrupted")
        .actions([btn])
        .render(cx)
}

#[inline(never)]
fn render_cut_unconfirmed_banner(
    cut_instances: Vec<(InstanceId, String)>,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let names = cut_instances
        .iter()
        .map(|(_, name)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!(
        "Cut, unconfirmed · retry: {names} — process stopped but stop intent is not durably recorded and may restart after reboot."
    );
    let mut action_btns: Vec<AnyElement> = Vec::with_capacity(cut_instances.len());
    for (id, name) in cut_instances {
        let btn_id = SharedString::from(format!("btn-banner-retry-confirm-{}", id.0));
        let retry_id = id.clone();
        action_btns.push(action_button(
            btn_id,
            SharedString::from(format!("Retry Confirm ({name})")),
            BtnStyle::new(ButtonVariant::Warning, Size::XSmall),
            cx.listener(move |this, _, _, _| {
                this.controller
                    .send_command(UserCommand::RetryConfirmStop(retry_id.clone()));
            }),
        ));
    }
    FluentInfoBar::new("banner-cut-unconfirmed", InfoSeverity::Error, summary)
        .title("Stop confirmation required")
        .actions(action_btns)
        .render(cx)
}

#[inline(never)]
fn render_elevated_refused_banner(cx: &mut Context<MainView>) -> AnyElement {
    let msg = "An elevated process cannot operate a user host. Use or install the system service instead.";
    let connect_btn = action_button(
        "btn-offer-service-connect",
        "Use System Service",
        BtnStyle::new(ButtonVariant::Primary, Size::XSmall),
        cx.listener(|this, _, _, _| {
            this.controller
                .send_command(UserCommand::Connect(HostMode::Service));
        }),
    );
    let install_btn = action_button(
        "btn-offer-service-install",
        "Install System Service",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
        cx.listener(|this, _, _, cx| {
            this.controller.request_service_install(cx);
        }),
    );
    FluentInfoBar::new("banner-elevated-user-refused", InfoSeverity::Warning, msg)
        .title("Elevated user host refused")
        .actions([connect_btn, install_btn])
        .render(cx)
}

#[inline(never)]
fn render_not_installed_banner(
    preview: &str,
    installing: bool,
    is_elevated: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let msg = format!("Install the service for full TUN support ({preview}).");
    let mut btns = vec![action_button(
        "btn-install-service",
        if installing {
            "Installing Service..."
        } else {
            "Install System Service"
        },
        BtnStyle::new(ButtonVariant::Primary, Size::XSmall).loading(installing),
        cx.listener(|this, _, _, cx| {
            this.controller.request_service_install(cx);
        }),
    )];
    if !is_elevated {
        btns.push(action_button(
            "btn-fallback-user-host",
            "Use User Host (No TUN)",
            BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
            cx.listener(|this, _, _, _| {
                this.controller
                    .send_command(UserCommand::Connect(HostMode::User));
            }),
        ));
    }
    FluentInfoBar::new("banner-not-installed", InfoSeverity::Informational, msg)
        .title("System service not installed")
        .actions(btns)
        .render(cx)
}

#[inline(never)]
fn render_launch_failed_banner(failure: &LaunchFailure, cx: &mut Context<MainView>) -> AnyElement {
    let msg = format!("{:?}: {}", failure.kind, failure.message);
    let btn = action_button(
        "btn-retry-autoconnect",
        "Retry Auto-Connect",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
        cx.listener(|this, _, _, _| {
            this.controller.send_command(UserCommand::AutoConnect);
        }),
    );
    FluentInfoBar::new("banner-launch-failed", InfoSeverity::Error, msg)
        .title("Host launch failed")
        .actions([btn])
        .render(cx)
}

#[inline(never)]
fn render_no_host_banner(is_elevated: bool, cx: &mut Context<MainView>) -> AnyElement {
    let msg = if is_elevated {
        "Running elevated: install or connect to the system service."
    } else {
        "Install the system service for TUN mode, or start a user host."
    };
    let mut btns = vec![
        action_button(
            "btn-nohost-install-service",
            "Install System Service",
            BtnStyle::new(ButtonVariant::Primary, Size::XSmall),
            cx.listener(|this, _, _, cx| {
                this.controller.request_service_install(cx);
            }),
        ),
        action_button(
            "btn-nohost-connect-service",
            "Connect Service",
            BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
            cx.listener(|this, _, _, _| {
                this.controller
                    .send_command(UserCommand::Connect(HostMode::Service));
            }),
        ),
    ];
    if !is_elevated {
        btns.push(action_button(
            "btn-nohost-start-user",
            "Start User Host",
            BtnStyle::new(ButtonVariant::Secondary, Size::XSmall),
            cx.listener(|this, _, _, _| {
                this.controller
                    .send_command(UserCommand::Connect(HostMode::User));
            }),
        ));
    }
    FluentInfoBar::new("banner-no-host", InfoSeverity::Informational, msg)
        .title("No host is running")
        .status()
        .actions(btns)
        .render(cx)
}

#[inline(never)]
fn render_keep_window_banner(cx: &mut Context<MainView>) -> AnyElement {
    let msg = "System tray is unavailable on this desktop; window kept open. Use the Exit button to quit.";
    let btn = action_button(
        "btn-dismiss-keep-window",
        "Dismiss",
        BtnStyle::new(ButtonVariant::Ghost, Size::Size(gpui_kit::px(38.)))
            .icon("fluent/dismiss.svg")
            .icon_only(),
        cx.listener(|this, _, _, cx| {
            this.controller.dismiss_keep_window_notice(cx);
        }),
    );
    FluentInfoBar::new("banner-keep-window", InfoSeverity::Informational, msg)
        .title("No system tray")
        .status()
        .close(btn)
        .render(cx)
}

#[inline(never)]
fn render_simple_alert(
    id: &'static str,
    msg: String,
    severity: InfoSeverity,
    cx: &App,
) -> AnyElement {
    FluentInfoBar::new(id, severity, msg)
        .title(if severity == InfoSeverity::Error {
            "Problem"
        } else {
            "Warning"
        })
        .render(cx)
}

#[inline(never)]
fn render_operations_bar(ops: &[Operation], cx: &mut Context<MainView>) -> AnyElement {
    let rows: Vec<AnyElement> = ops
        .iter()
        .filter_map(|op| render_operation_row(op, cx))
        .collect();
    div()
        .id("operations-bar")
        .flex()
        .flex_col()
        .gap_1()
        .children(rows)
        .into_any_element()
}

#[inline(never)]
fn render_operation_row(op: &Operation, cx: &mut Context<MainView>) -> Option<AnyElement> {
    let req_id = op.request_id.clone();
    let req_id_dismiss = op.request_id.clone();
    let (label, can_retry) = match &op.status {
        OperationStatus::Unconfirmed(failure) => {
            (format!("{:?} unconfirmed: {}", op.kind, failure.0), true)
        }
        OperationStatus::Failed(failure) => (format!("{:?} failed: {}", op.kind, failure.0), false),
        _ => return None,
    };
    let mut btns = Vec::new();
    if can_retry {
        btns.push(action_button(
            SharedString::from(format!("btn-op-retry-{}", req_id.0)),
            "Retry",
            BtnStyle::new(ButtonVariant::Warning, Size::XSmall),
            cx.listener(move |this, _, _, _| {
                this.controller
                    .send_command(UserCommand::RetryOperation(req_id.clone()));
            }),
        ));
    }
    btns.push(action_button(
        SharedString::from(format!("btn-op-dismiss-{}", req_id_dismiss.0)),
        "Dismiss",
        BtnStyle::new(ButtonVariant::Ghost, Size::Size(gpui_kit::px(38.)))
            .icon("fluent/dismiss.svg")
            .icon_only(),
        cx.listener(move |this, _, _, _| {
            this.controller
                .send_command(UserCommand::DismissOperation(req_id_dismiss.clone()));
        }),
    ));
    let close = btns.pop().expect("dismiss action is always present");
    Some(
        FluentInfoBar::new(
            SharedString::from(format!("operation-{}", op.request_id.0)),
            if can_retry {
                InfoSeverity::Warning
            } else {
                InfoSeverity::Error
            },
            label,
        )
        .actions(btns)
        .close(close)
        .render(cx),
    )
}
