//! Reclaim report view with per-item candidate confirmation (`Delete` / `Keep`),
//! conflict release (`Keep` only), quarantined instance retries, and reclaim notes.

use etd_app::UserCommand;
use etd_contract::{
    InstanceId, Role, capability,
    v1::{CandidateAction, CandidateOrigin, ReclaimStatus},
};
use gpui_kit::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{
        ActiveTheme as _, Disableable as _, Sizable as _, StyledExt as _,
        button::{Button, ButtonVariant, ButtonVariants as _},
    },
    div,
};

use crate::views::MainView;

pub fn render_reclaim_view(view: &MainView, cx: &mut Context<MainView>) -> impl IntoElement {
    let theme = cx.theme();
    let model = view.controller.model.read(cx);
    let report = &model.store.reclaim;
    let can_resolve = model.store.has_capability(capability::RECLAIM_CANDIDATES);
    let is_admin = model
        .store
        .negotiated
        .as_ref()
        .is_some_and(|n| n.role == Role::Admin);
    let decided_count = model.candidate_decisions.len();

    let mut page = div()
        .id("reclaim-report-view")
        .test_support()
        .aria_label("Reclaim Report")
        .flex()
        .flex_col()
        .gap_4()
        .p_5()
        .size_full()
        .overflow_y_scroll()
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
                        .child("System Side-Effect Reclaim Report"),
                )
                .child(
                    Button::new("btn-reclaim-refresh")
                        .small()
                        .outline()
                        .label("Refresh Snapshot")
                        .on_click(cx.listener(|this, _, _, _| {
                            this.controller.send_command(UserCommand::Refresh);
                        })),
                ),
        );

    let all_clean = report.instances.is_empty()
        && report.candidates.is_empty()
        && report.conflicts.is_empty()
        && report.notes.is_empty();

    if all_clean {
        return page.child(
            div()
                .id("reclaim-clean")
                .test_support()
                .aria_label("All system resources are clean")
                .p_4()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .text_sm()
                .text_color(theme.muted_foreground)
                .child("No pending residues, candidates, or conflicts reported by the host."),
        );
    }

    // 1. Instance reclaim records
    if !report.instances.is_empty() {
        let mut section = div().flex().flex_col().gap_2().child(
            div()
                .text_sm()
                .font_semibold()
                .child("Instance Reclaim Records"),
        );
        for item in &report.instances {
            let status_label = match item.status() {
                ReclaimStatus::Clean => "Clean",
                ReclaimStatus::InProgress => "In Progress",
                ReclaimStatus::Quarantined => "Quarantined",
                ReclaimStatus::AwaitingConfirmation => "Awaiting Confirmation",
                _ => "Unspecified",
            };
            let inst_id = InstanceId(item.instance_id.clone());
            let mut card = div()
                .id(SharedString::from(format!(
                    "reclaim-instance-{}",
                    item.instance_id
                )))
                .test_support()
                .aria_label(SharedString::from(format!(
                    "{} epoch {} ({status_label})",
                    item.instance_id, item.epoch
                )))
                .flex()
                .flex_col()
                .gap_2()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .bg(theme.secondary.opacity(0.2))
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .child(div().text_sm().font_medium().child(format!(
                            "{} · epoch {} ({status_label})",
                            item.instance_id, item.epoch
                        )))
                        .child(
                            Button::new(SharedString::from(format!(
                                "btn-reclaim-retry-{}",
                                item.instance_id
                            )))
                            .xsmall()
                            .warning()
                            .label("Retry Reclaim")
                            .on_click(cx.listener(
                                move |this, _, _, _| {
                                    this.controller
                                        .send_command(UserCommand::RetryReclaim(inst_id.clone()));
                                },
                            )),
                        ),
                );
            if !item.reason.is_empty() {
                card = card.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(item.reason.clone()),
                );
            }
            for residue in &item.residues {
                card = card.child(div().text_xs().text_color(theme.foreground).child(format!(
                    "• [{}] {} — failures: {}, error: {}",
                    residue.kind,
                    residue.identity,
                    residue.failures,
                    if residue.last_error.is_empty() {
                        "none"
                    } else {
                        &residue.last_error
                    }
                )));
            }
            section = section.child(card);
        }
        page = page.child(section);
    }

    // 2. Per-item candidate confirmation
    if !report.candidates.is_empty() {
        let mut section = div()
            .id("reclaim-candidates-section")
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_sm()
                    .font_semibold()
                    .child("Candidates Awaiting Per-Item Confirmation"),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child("Candidates are never deleted automatically. Review each item individually and mark Delete (ours) or Keep (not ours)."),
            );

        if !is_admin {
            section = section.child(div().text_xs().text_color(theme.warning).child(
                "Administrator role is required by the host to submit candidate resolutions.",
            ));
        }

        for candidate in &report.candidates {
            let cid = candidate.candidate_id.clone();
            let cid_del = cid.clone();
            let cid_keep = cid.clone();
            let chosen = model.candidate_decisions.get(&cid).copied();
            let origin = match candidate.origin() {
                CandidateOrigin::NoCredential => "No creation credential",
                CandidateOrigin::LedgerLost => "Ledger lost (repair index)",
                CandidateOrigin::PrefixMatch => "Prefix match only",
                _ => "Unknown origin",
            };
            let summary = format!(
                "[{}] {} ({origin}) — {}",
                candidate.kind, candidate.identity, candidate.detail
            );
            section = section.child(
                div()
                    .id(SharedString::from(format!("candidate-row-{cid}")))
                    .test_support()
                    .aria_label(SharedString::from(summary.clone()))
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.secondary.opacity(0.25))
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .font_medium()
                                    .child(format!("[{}] {}", candidate.kind, candidate.identity)),
                            )
                            .child(div().text_xs().text_color(theme.muted_foreground).child(
                                format!(
                                    "Origin: {origin} | Instance: {} (epoch {}) | {}",
                                    candidate.instance_id, candidate.epoch, candidate.detail
                                ),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap_2()
                            .child(
                                Button::new(SharedString::from(format!("candidate-delete-{cid}")))
                                    .xsmall()
                                    .with_variant(if chosen == Some(CandidateAction::Delete) {
                                        ButtonVariant::Danger
                                    } else {
                                        ButtonVariant::Secondary
                                    })
                                    .label("Delete (Ours)")
                                    .disabled(!can_resolve)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.controller.model.update(cx, |m, cx| {
                                            m.set_candidate_decision(
                                                cid_del.clone(),
                                                CandidateAction::Delete,
                                            );
                                            cx.notify();
                                        });
                                    })),
                            )
                            .child(
                                Button::new(SharedString::from(format!("candidate-keep-{cid}")))
                                    .xsmall()
                                    .with_variant(if chosen == Some(CandidateAction::Keep) {
                                        ButtonVariant::Primary
                                    } else {
                                        ButtonVariant::Secondary
                                    })
                                    .label("Keep (Not Ours)")
                                    .disabled(!can_resolve)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.controller.model.update(cx, |m, cx| {
                                            m.set_candidate_decision(
                                                cid_keep.clone(),
                                                CandidateAction::Keep,
                                            );
                                            cx.notify();
                                        });
                                    })),
                            ),
                    ),
            );
        }
        page = page.child(section);
    }

    // 3. Identity conflicts (KEEP / release only — never deleted)
    if !report.conflicts.is_empty() {
        let mut section = div()
            .id("reclaim-conflicts-section")
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_sm()
                    .font_semibold()
                    .child("Identity Conflicts (Never Deleted)"),
            );
        for conflict in &report.conflicts {
            let cid = conflict.conflict_id.clone();
            let cid_keep = cid.clone();
            let chosen = model.candidate_decisions.get(&cid).copied();
            let summary = format!(
                "[{}] {} — expected {}, found {}",
                conflict.kind, conflict.identity, conflict.expected, conflict.found
            );
            section = section.child(
                div()
                    .id(SharedString::from(format!("conflict-row-{cid}")))
                    .test_support()
                    .aria_label(SharedString::from(summary.clone()))
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.warning)
                    .bg(theme.warning.opacity(0.1))
                    .child(div().flex_1().text_xs().child(summary))
                    .child(
                        Button::new(SharedString::from(format!("conflict-keep-{cid}")))
                            .xsmall()
                            .with_variant(if chosen == Some(CandidateAction::Keep) {
                                ButtonVariant::Primary
                            } else {
                                ButtonVariant::Secondary
                            })
                            .label("Keep & Release Record")
                            .disabled(!can_resolve || cid.is_empty())
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.controller.model.update(cx, |m, cx| {
                                    m.set_candidate_decision(
                                        cid_keep.clone(),
                                        CandidateAction::Keep,
                                    );
                                    cx.notify();
                                });
                            })),
                    ),
            );
        }
        page = page.child(section);
    }

    // Submit bar for per-item candidate / conflict decisions
    if !report.candidates.is_empty() || !report.conflicts.is_empty() {
        page = page.child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_end()
                .gap_3()
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format!("{decided_count} item(s) marked for confirmation")),
                )
                .child(
                    Button::new("btn-submit-candidate-decisions")
                        .primary()
                        .small()
                        .disabled(!can_resolve || decided_count == 0)
                        .label(SharedString::from(format!(
                            "Confirm & Apply ({decided_count})"
                        )))
                        .on_click(cx.listener(|this, _, _, cx| {
                            let decisions = this.controller.model.update(cx, |m, cx| {
                                let out = m.take_candidate_decisions();
                                cx.notify();
                                out
                            });
                            if !decisions.is_empty() {
                                this.controller
                                    .send_command(UserCommand::ResolveCandidates(decisions));
                            }
                        })),
                ),
        );
    }

    // 4. Reclaim notes
    if !report.notes.is_empty() {
        let mut notes = div()
            .id("reclaim-notes-section")
            .flex()
            .flex_col()
            .gap_1()
            .child(div().text_sm().font_semibold().child("Notes"));
        for note in &report.notes {
            notes = notes.child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(format!("[{}] {}", note.code, note.message)),
            );
        }
        page = page.child(notes);
    }

    page
}
