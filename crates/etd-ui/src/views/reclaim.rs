//! Reclaim report view with per-item candidate confirmation (`Delete` / `Keep`),
//! conflict release (`Keep` only), quarantined instance retries, and reclaim notes.
//!
//! Each section and row uses `#[inline(never)]` helpers returning [`AnyElement`]
//! to keep Windows debug stack frames small.

use std::collections::BTreeMap;

use etd_app::UserCommand;
use etd_contract::{
    InstanceId, Role, capability,
    v1::{
        Candidate, CandidateAction, CandidateOrigin, Conflict, InstanceReclaim, Notice,
        ReclaimStatus,
    },
};
use gpui_kit::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant},
    div,
};

use crate::views::{
    MainView,
    ui::{BtnStyle, action_button},
};

#[inline(never)]
pub fn render_reclaim_view(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let (report, can_resolve, is_admin, decisions) = {
        let model = view.controller.model.read(cx);
        let can_resolve = model.store.has_capability(capability::RECLAIM_CANDIDATES);
        let is_admin = model
            .store
            .negotiated
            .as_ref()
            .is_some_and(|n| n.role == Role::Admin);
        (
            model.store.reclaim.clone(),
            can_resolve,
            is_admin,
            model.candidate_decisions.clone(),
        )
    };

    let refresh_btn = action_button(
        "btn-reclaim-refresh",
        "Refresh Snapshot",
        BtnStyle::new(ButtonVariant::Default, Size::Small).outline(),
        cx.listener(|this, _, _, _| {
            this.controller.send_command(UserCommand::Refresh);
        }),
    );

    let header = div()
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
        .child(refresh_btn);

    let mut sections: Vec<AnyElement> = Vec::new();
    let all_clean = report.instances.is_empty()
        && report.candidates.is_empty()
        && report.conflicts.is_empty()
        && report.notes.is_empty();

    if all_clean {
        let border = cx.theme().border;
        let muted = cx.theme().muted_foreground;
        sections.push(
            div()
                .id("reclaim-clean")
                .test_support()
                .aria_label("All system resources are clean")
                .p_4()
                .rounded_md()
                .border_1()
                .border_color(border)
                .text_sm()
                .text_color(muted)
                .child("No pending residues, candidates, or conflicts reported by the host.")
                .into_any_element(),
        );
    } else {
        if !report.instances.is_empty() {
            sections.push(render_reclaim_instances(&report.instances, cx));
        }
        if !report.candidates.is_empty() {
            sections.push(render_reclaim_candidates(
                &report.candidates,
                &decisions,
                can_resolve,
                is_admin,
                cx,
            ));
        }
        if !report.conflicts.is_empty() {
            sections.push(render_reclaim_conflicts(
                &report.conflicts,
                &decisions,
                can_resolve,
                cx,
            ));
        }
        if !report.candidates.is_empty() || !report.conflicts.is_empty() {
            sections.push(render_submit_bar(decisions.len(), can_resolve, cx));
        }
        if !report.notes.is_empty() {
            sections.push(render_notes_section(&report.notes, cx));
        }
    }

    div()
        .id("reclaim-report-view")
        .test_support()
        .aria_label("Reclaim Report")
        .flex()
        .flex_col()
        .gap_4()
        .p_5()
        .size_full()
        .overflow_y_scroll()
        .child(header)
        .children(sections)
        .into_any_element()
}

#[inline(never)]
fn render_reclaim_instances(
    instances: &[InstanceReclaim],
    cx: &mut Context<MainView>,
) -> AnyElement {
    let cards: Vec<AnyElement> = instances
        .iter()
        .map(|item| render_reclaim_instance_card(item, cx))
        .collect();
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .text_sm()
                .font_semibold()
                .child("Instance Reclaim Records"),
        )
        .children(cards)
        .into_any_element()
}

#[inline(never)]
fn render_reclaim_instance_card(item: &InstanceReclaim, cx: &mut Context<MainView>) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);
    let muted = cx.theme().muted_foreground;
    let fg = cx.theme().foreground;

    let status_label = match item.status() {
        ReclaimStatus::Clean => "Clean",
        ReclaimStatus::InProgress => "In Progress",
        ReclaimStatus::Quarantined => "Quarantined",
        ReclaimStatus::AwaitingConfirmation => "Awaiting Confirmation",
        _ => "Unspecified",
    };
    let inst_id = InstanceId(item.instance_id.clone());
    let retry_btn = action_button(
        SharedString::from(format!("btn-reclaim-retry-{}", item.instance_id)),
        "Retry Reclaim",
        BtnStyle::new(ButtonVariant::Warning, Size::XSmall),
        cx.listener(move |this, _, _, _| {
            this.controller
                .send_command(UserCommand::RetryReclaim(inst_id.clone()));
        }),
    );

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
        .border_color(border)
        .bg(card)
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
                .child(retry_btn),
        );

    if !item.reason.is_empty() {
        card = card.child(div().text_xs().text_color(muted).child(item.reason.clone()));
    }
    for residue in &item.residues {
        card = card.child(div().text_xs().text_color(fg).child(format!(
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
    card.into_any_element()
}

#[inline(never)]
fn render_reclaim_candidates(
    candidates: &[Candidate],
    decisions: &BTreeMap<String, CandidateAction>,
    can_resolve: bool,
    is_admin: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    let warning = cx.theme().warning;

    let rows: Vec<AnyElement> = candidates
        .iter()
        .map(|candidate| {
            let chosen = decisions.get(&candidate.candidate_id).copied();
            render_candidate_row(candidate, chosen, can_resolve, cx)
        })
        .collect();

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
                .text_color(muted)
                .child("Candidates are never deleted automatically. Review each item individually and mark Delete (ours) or Keep (not ours)."),
        );

    if !is_admin {
        section =
            section.child(div().text_xs().text_color(warning).child(
                "Administrator role is required by the host to submit candidate resolutions.",
            ));
    }

    section.children(rows).into_any_element()
}

#[inline(never)]
fn render_candidate_row(
    candidate: &Candidate,
    chosen: Option<CandidateAction>,
    can_resolve: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);
    let muted = cx.theme().muted_foreground;

    let cid = candidate.candidate_id.clone();
    let cid_del = cid.clone();
    let cid_keep = cid.clone();
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

    let del_btn = action_button(
        SharedString::from(format!("candidate-delete-{cid}")),
        "Delete (Ours)",
        BtnStyle::new(
            if chosen == Some(CandidateAction::Delete) {
                ButtonVariant::Danger
            } else {
                ButtonVariant::Secondary
            },
            Size::XSmall,
        )
        .disabled(!can_resolve),
        cx.listener(move |this, _, _, cx| {
            this.controller.model.update(cx, |m, cx| {
                m.set_candidate_decision(cid_del.clone(), CandidateAction::Delete);
                cx.notify();
            });
        }),
    );

    let keep_btn = action_button(
        SharedString::from(format!("candidate-keep-{cid}")),
        "Keep (Not Ours)",
        BtnStyle::new(
            if chosen == Some(CandidateAction::Keep) {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            },
            Size::XSmall,
        )
        .disabled(!can_resolve),
        cx.listener(move |this, _, _, cx| {
            this.controller.model.update(cx, |m, cx| {
                m.set_candidate_decision(cid_keep.clone(), CandidateAction::Keep);
                cx.notify();
            });
        }),
    );

    div()
        .id(SharedString::from(format!("candidate-row-{cid}")))
        .test_support()
        .aria_label(SharedString::from(summary))
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(border)
        .bg(card)
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
                .child(div().text_xs().text_color(muted).child(format!(
                    "Origin: {origin} | Instance: {} (epoch {}) | {}",
                    candidate.instance_id, candidate.epoch, candidate.detail
                ))),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(del_btn)
                .child(keep_btn),
        )
        .into_any_element()
}

#[inline(never)]
fn render_reclaim_conflicts(
    conflicts: &[Conflict],
    decisions: &BTreeMap<String, CandidateAction>,
    can_resolve: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let rows: Vec<AnyElement> = conflicts
        .iter()
        .map(|conflict| {
            let chosen = decisions.get(&conflict.conflict_id).copied();
            render_conflict_row(conflict, chosen, can_resolve, cx)
        })
        .collect();
    div()
        .id("reclaim-conflicts-section")
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .text_sm()
                .font_semibold()
                .child("Identity Conflicts (Never Deleted)"),
        )
        .children(rows)
        .into_any_element()
}

#[inline(never)]
fn render_conflict_row(
    conflict: &Conflict,
    chosen: Option<CandidateAction>,
    can_resolve: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let warning = cx.theme().warning;
    let cid = conflict.conflict_id.clone();
    let cid_keep = cid.clone();
    let summary = format!(
        "[{}] {} — expected {}, found {}",
        conflict.kind, conflict.identity, conflict.expected, conflict.found
    );
    let keep_btn = action_button(
        SharedString::from(format!("conflict-keep-{cid}")),
        "Keep & Release Record",
        BtnStyle::new(
            if chosen == Some(CandidateAction::Keep) {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            },
            Size::XSmall,
        )
        .disabled(!can_resolve || cid.is_empty()),
        cx.listener(move |this, _, _, cx| {
            this.controller.model.update(cx, |m, cx| {
                m.set_candidate_decision(cid_keep.clone(), CandidateAction::Keep);
                cx.notify();
            });
        }),
    );

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
        .border_color(warning)
        .bg(warning.opacity(0.1))
        .child(div().flex_1().text_xs().child(summary))
        .child(keep_btn)
        .into_any_element()
}

#[inline(never)]
fn render_submit_bar(
    decided_count: usize,
    can_resolve: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    let btn = action_button(
        "btn-submit-candidate-decisions",
        SharedString::from(format!("Confirm & Apply ({decided_count})")),
        BtnStyle::new(ButtonVariant::Primary, Size::Small)
            .disabled(!can_resolve || decided_count == 0),
        cx.listener(|this, _, _, cx| {
            let decisions = this.controller.model.update(cx, |m, cx| {
                let out = m.take_candidate_decisions();
                cx.notify();
                out
            });
            if !decisions.is_empty() {
                this.controller
                    .send_command(UserCommand::ResolveCandidates(decisions));
            }
        }),
    );
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_end()
        .gap_3()
        .child(
            div()
                .text_xs()
                .text_color(muted)
                .child(format!("{decided_count} item(s) marked for confirmation")),
        )
        .child(btn)
        .into_any_element()
}

#[inline(never)]
fn render_notes_section(notes: &[Notice], cx: &Context<MainView>) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    let rows: Vec<AnyElement> = notes
        .iter()
        .map(|note| {
            div()
                .text_xs()
                .text_color(muted)
                .child(format!("[{}] {}", note.code, note.message))
                .into_any_element()
        })
        .collect();
    div()
        .id("reclaim-notes-section")
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_sm().font_semibold().child("Notes"))
        .children(rows)
        .into_any_element()
}
