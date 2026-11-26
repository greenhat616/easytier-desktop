//! Reactive GPUI UI model wrapping [`etd_app::StateStore`] plus view-only
//! selection/navigation state. Never holds a network secret.

use std::collections::{BTreeMap, BTreeSet};

use etd_app::{HostLink, InstanceCondition, LaunchFailure, LaunchFailureKind, StateStore};
use etd_contract::{
    CandidateDecision, HostMode, InstanceId, QueryKind, capability,
    v1::{CandidateAction, ReclaimStatus},
};

/// Top-level workspace section shown in the main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    #[default]
    Instances,
    Reclaim,
    Editor,
}

/// Detail sub-tab for the selected instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailTab {
    #[default]
    Overview,
    Nodes,
    Routes,
    Traffic,
}

impl DetailTab {
    pub fn required_capability(self) -> Option<&'static str> {
        match self {
            Self::Overview => None,
            Self::Nodes => Some(capability::QUERY_NODES),
            Self::Routes => Some(capability::QUERY_ROUTES),
            Self::Traffic => Some(capability::QUERY_TRAFFIC),
        }
    }

    pub fn query_kind(self) -> Option<QueryKind> {
        match self {
            Self::Overview => None,
            Self::Nodes => Some(QueryKind::Nodes),
            Self::Routes => Some(QueryKind::Routes),
            Self::Traffic => Some(QueryKind::Traffic),
        }
    }
}

/// Progress of an in-app service installation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    InProgress,
    Succeeded,
    Failed(String),
}

/// Shared UI state owned as a GPUI [`gpui_kit::Entity`].
///
/// The window can close to the tray and re-open later bound to this exact entity
/// without losing selection or the latest [`StateStore`].
#[derive(Debug, Clone)]
pub struct UiModel {
    pub store: StateStore,
    pub is_elevated: bool,
    pub tray_available: bool,
    pub keep_window_notice: bool,
    pub active_section: Section,
    pub selected_instance: Option<InstanceId>,
    pub detail_tab: DetailTab,
    /// Per-item decisions keyed by `candidate_id` or `conflict_id`.
    pub candidate_decisions: BTreeMap<String, CandidateAction>,
    pub install_status: Option<InstallStatus>,
    pub install_command_preview: String,
}

impl UiModel {
    pub fn new(is_elevated: bool, install_command_preview: String) -> Self {
        Self {
            store: StateStore::default(),
            is_elevated,
            tray_available: false,
            keep_window_notice: false,
            active_section: Section::Instances,
            selected_instance: None,
            detail_tab: DetailTab::Overview,
            candidate_decisions: BTreeMap::new(),
            install_status: None,
            install_command_preview,
        }
    }

    /// Replaces the store snapshot and reconciles view-only pointers (selected
    /// instance, capability-gated tab, stale candidate decisions).
    pub fn apply_store(&mut self, store: StateStore) {
        self.store = store;

        // Keep selected instance valid; auto-select first instance if none selected.
        if let Some(selected) = &self.selected_instance
            && !self.store.instances.contains_key(selected)
        {
            self.selected_instance = None;
        }
        if self.selected_instance.is_none() {
            self.selected_instance = self.store.instances.keys().next().cloned();
        }

        // If the host no longer advertises the capability for the active detail tab,
        // fall back to Overview immediately.
        if let Some(cap) = self.detail_tab.required_capability()
            && !self.store.has_capability(cap)
        {
            self.detail_tab = DetailTab::Overview;
        }

        // Drop candidate decisions for items that are no longer in the report.
        let mut live_ids: BTreeSet<&str> = self
            .store
            .reclaim
            .candidates
            .iter()
            .map(|c| c.candidate_id.as_str())
            .collect();
        live_ids.extend(
            self.store
                .reclaim
                .conflicts
                .iter()
                .filter(|c| !c.conflict_id.is_empty())
                .map(|c| c.conflict_id.as_str()),
        );
        self.candidate_decisions
            .retain(|id, _| live_ids.contains(id.as_str()));
    }

    /// Instances currently in `CUT_UNCONFIRMED` (stop not yet durable).
    pub fn cut_unconfirmed_instances(&self) -> Vec<(InstanceId, String)> {
        self.store
            .instances
            .values()
            .filter(|entry| entry.needs_stop_confirm())
            .map(|entry| (entry.id.clone(), entry.display_name().to_owned()))
            .collect()
    }

    /// Whether the current launch failure indicates the system service is not installed.
    pub fn is_service_not_installed(&self) -> bool {
        matches!(
            &self.store.link,
            HostLink::LaunchFailed(LaunchFailure {
                kind: LaunchFailureKind::NotInstalled,
                ..
            })
        )
    }

    /// Whether a user-mode host launch was refused because the process is elevated.
    pub fn is_elevated_user_host_refused(&self) -> bool {
        let failure_is_elevated_refusal = |failure: &LaunchFailure| {
            let msg = failure.message.to_ascii_lowercase();
            let mentions_elevated = msg.contains("elevated")
                || msg.contains("administrator")
                || msg.contains("system service");
            failure.mode == Some(HostMode::User) && (self.is_elevated || mentions_elevated)
        };

        matches!(&self.store.link, HostLink::LaunchFailed(f) if failure_is_elevated_refusal(f))
            || self
                .store
                .relaunch_failure
                .as_ref()
                .is_some_and(failure_is_elevated_refusal)
    }

    /// Number of actionable items in the reclaim report (candidates + conflicts +
    /// quarantined/awaiting instances).
    pub fn reclaim_attention_count(&self) -> usize {
        let quarantined = self
            .store
            .reclaim
            .instances
            .iter()
            .filter(|item| {
                matches!(
                    item.status(),
                    ReclaimStatus::Quarantined | ReclaimStatus::AwaitingConfirmation
                )
            })
            .count();
        self.store.reclaim.candidates.len() + self.store.reclaim.conflicts.len() + quarantined
    }

    /// Records a per-item decision for a candidate (`Delete` or `Keep`).
    pub fn set_candidate_decision(&mut self, candidate_id: String, action: CandidateAction) {
        if self.candidate_decisions.get(&candidate_id) == Some(&action) {
            self.candidate_decisions.remove(&candidate_id);
        } else {
            self.candidate_decisions.insert(candidate_id, action);
        }
    }

    /// Builds the `ResolveCandidates` payload for all explicitly decided items.
    pub fn take_candidate_decisions(&mut self) -> Vec<CandidateDecision> {
        let mut decisions = Vec::new();
        for (id, action) in std::mem::take(&mut self.candidate_decisions) {
            decisions.push(CandidateDecision {
                candidate_id: id,
                action: action as i32,
            });
        }
        decisions
    }

    /// Human-readable label for an [`InstanceCondition`].
    pub fn condition_label(condition: InstanceCondition) -> &'static str {
        match condition {
            InstanceCondition::Unknown => "Unknown",
            InstanceCondition::Stopped => "Stopped",
            InstanceCondition::Starting => "Starting",
            InstanceCondition::RunningBasic => "Running (Basic)",
            InstanceCondition::Running => "Running",
            InstanceCondition::Stopping => "Stopping",
            InstanceCondition::Reclaiming => "Reclaiming",
            InstanceCondition::Backoff => "Backoff",
            InstanceCondition::GaveUp => "GAVE_UP",
            InstanceCondition::Quarantined => "Quarantined",
            InstanceCondition::CutUnconfirmed => "Cut, unconfirmed",
            InstanceCondition::Waiting => "WAITING",
        }
    }
}
