//! The orchestrator's published state: gap-free events plus the
//! [`HostView`] reflecting every event up to its `seq`, secret redaction,
//! and the conversion of reclaim reports into contract messages.
use crate::api::{HostEvent, HostView};
use etd_contract::v1::{
    self, CandidateOrigin, InstanceReclaim, InstanceView, NoticeLevel, ReclaimStatus, ResidueState,
    event,
};
use etd_contract::{DesiredInstance, HostPhase, InstanceStatus, NetworkSpec};
use etd_sysfx::{
    CandidateSource, FoundBy, GenerationOutcome, GenerationReport, ObjectKey, ReclaimReport,
    ResidueReason,
};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

/// Owns the sequence counter; the only writer of events and the view.
pub(crate) struct Publisher {
    seq: u64,
    view: HostView,
    events: broadcast::Sender<HostEvent>,
    watch: watch::Sender<Arc<HostView>>,
}

impl Publisher {
    pub(crate) fn new(
        events: broadcast::Sender<HostEvent>,
        watch: watch::Sender<Arc<HostView>>,
    ) -> Self {
        let view = (**watch.borrow()).clone();
        Self {
            seq: view.seq,
            view,
            events,
            watch,
        }
    }

    pub(crate) fn snapshot(&self) -> &etd_contract::HostSnapshot {
        &self.view.snapshot
    }

    /// Apply one state change to the view, then broadcast it. The view is
    /// replaced before the event is sent, so a reader that sees event `n`
    /// can always read a view with `seq >= n`.
    pub(crate) fn publish(
        &mut self,
        at_unix_ms: i64,
        payload: event::Payload,
        apply: impl FnOnce(&mut etd_contract::HostSnapshot),
    ) {
        self.seq += 1;
        apply(&mut self.view.snapshot);
        self.view.seq = self.seq;
        self.watch.send_replace(Arc::new(self.view.clone()));
        // No receiver is fine: H2 resyncs from the view.
        let _ = self.events.send(HostEvent {
            seq: self.seq,
            at_unix_ms,
            payload,
        });
    }

    pub(crate) fn phase(&mut self, at: i64, phase: HostPhase) {
        if self.view.snapshot.phase() == phase {
            return;
        }
        self.publish(
            at,
            event::Payload::HostPhase(v1::HostPhaseChanged {
                phase: phase as i32,
            }),
            |s| s.set_phase(phase),
        );
    }

    pub(crate) fn status(&mut self, at: i64, status: InstanceStatus) {
        let id = status.instance_id.clone();
        let copy = status.clone();
        self.publish(at, event::Payload::InstanceStatus(status), |s| {
            match s
                .instances
                .iter_mut()
                .find(|v| v.desired.as_ref().is_some_and(|d| d.instance_id == id))
            {
                Some(view) => view.status = Some(copy),
                None => insert_sorted(
                    &mut s.instances,
                    InstanceView {
                        desired: Some(DesiredInstance {
                            instance_id: id.clone(),
                            ..Default::default()
                        }),
                        status: Some(copy),
                    },
                ),
            }
        });
    }

    /// A committed desired state (already redacted by the caller).
    pub(crate) fn desired(
        &mut self,
        at: i64,
        revision: u64,
        instance: DesiredInstance,
        request_id: String,
        ticket: String,
    ) {
        let copy = instance.clone();
        self.publish(
            at,
            event::Payload::DesiredChanged(v1::DesiredChanged {
                revision,
                instance: Some(instance),
                request_id,
                ticket,
            }),
            |s| {
                s.revision = s.revision.max(revision);
                set_desired(s, copy);
            },
        );
    }

    /// Desired state learnt without an event of its own (host start).
    pub(crate) fn seed_desired(&mut self, revision: u64, instances: Vec<DesiredInstance>) {
        self.view.snapshot.revision = revision;
        for instance in instances {
            set_desired(&mut self.view.snapshot, redact(instance));
        }
        self.watch.send_replace(Arc::new(self.view.clone()));
    }

    pub(crate) fn removed(&mut self, at: i64, instance_id: String, revision: u64) {
        let id = instance_id.clone();
        self.publish(
            at,
            event::Payload::InstanceRemoved(v1::InstanceRemoved {
                instance_id,
                revision,
            }),
            |s| {
                s.revision = s.revision.max(revision);
                s.instances
                    .retain(|v| v.desired.as_ref().is_none_or(|d| d.instance_id != id));
            },
        );
    }

    pub(crate) fn exited(&mut self, at: i64, exited: v1::InstanceExited) {
        self.publish(at, event::Payload::InstanceExited(exited), |_| {});
    }

    pub(crate) fn notice(&mut self, at: i64, notice: v1::Notice) {
        self.publish(at, event::Payload::Notice(notice), |_| {});
    }

    pub(crate) fn reclaim(&mut self, at: i64, report: v1::ReclaimReport) {
        let copy = report.clone();
        self.publish(at, event::Payload::ReclaimReport(report), |s| {
            s.reclaim = Some(copy)
        });
    }

    pub(crate) fn default_core(&mut self, version: String) {
        if self.view.snapshot.default_core_version != version {
            self.view.snapshot.default_core_version = version;
            self.watch.send_replace(Arc::new(self.view.clone()));
        }
    }
}

fn instance_id_of(v: &InstanceView) -> &str {
    v.desired.as_ref().map_or("", |d| d.instance_id.as_str())
}

fn insert_sorted(list: &mut Vec<InstanceView>, view: InstanceView) {
    let at = list
        .iter()
        .position(|v| instance_id_of(v) > instance_id_of(&view))
        .unwrap_or(list.len());
    list.insert(at, view);
}

fn set_desired(s: &mut etd_contract::HostSnapshot, instance: DesiredInstance) {
    match s
        .instances
        .iter_mut()
        .find(|v| instance_id_of(v) == instance.instance_id)
    {
        Some(view) => view.desired = Some(instance),
        None => insert_sorted(
            &mut s.instances,
            InstanceView {
                desired: Some(instance),
                status: None,
            },
        ),
    }
}

/// The spec as clients may see it: the secret is never returned, only
/// whether one is set.
pub fn redact_spec(mut spec: NetworkSpec) -> NetworkSpec {
    spec.network_secret_set = spec
        .network_secret
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    spec.network_secret = None;
    spec
}

pub fn redact(mut instance: DesiredInstance) -> DesiredInstance {
    instance.spec = instance.spec.map(redact_spec);
    instance
}

pub(crate) fn notice(
    level: NoticeLevel,
    code: &str,
    message: impl Into<String>,
    instance: &str,
) -> v1::Notice {
    v1::Notice {
        level: level as i32,
        code: code.into(),
        message: message.into(),
        instance_id: instance.into(),
    }
}

/// Human-readable natural key for reports.
pub fn key_text(key: &ObjectKey) -> String {
    match key {
        ObjectKey::Process {
            exe,
            cmdline_marker,
        } => format!("process {} ({})", exe.display(), cmdline_marker.display()),
        ObjectKey::Path { path } => path.display().to_string(),
        ObjectKey::Interface { name, guid } => match (name, guid) {
            (Some(n), Some(g)) => format!("interface {n} {{{g}}}"),
            (Some(n), None) => format!("interface {n}"),
            (None, Some(g)) => format!("interface {{{g}}}"),
            (None, None) => "interface (unnamed)".into(),
        },
        ObjectKey::RoutesVia { interface } => format!(
            "routes via {}",
            interface.as_deref().unwrap_or("(unnamed interface)")
        ),
        ObjectKey::Rule { name, group } => match group {
            Some(g) => format!("rule {name} [{g}]"),
            None => format!("rule {name}"),
        },
        ObjectKey::Registry { key, value } => match value {
            Some(v) => format!("{key}\\{v}"),
            None => key.clone(),
        },
        ObjectKey::Fence {
            container,
            rule,
            port,
        } => format!("fence {container}/{rule} port {port}"),
        ObjectKey::ResolvedLink { interface } => format!("resolved link {interface}"),
        ObjectKey::PortMapping {
            protocol,
            internal_port,
            external_port,
            description,
        } => format!(
            "{protocol} mapping {internal_port}->{} {description}",
            external_port.map_or("?".into(), |p| p.to_string())
        ),
        ObjectKey::Service { name } => format!("service {name}"),
        other => format!("{other:?}"),
    }
}

fn generation_view(g: &GenerationReport, awaiting: bool) -> InstanceReclaim {
    let (status, reason) = match &g.outcome {
        GenerationOutcome::Closed => (ReclaimStatus::Clean, String::new()),
        GenerationOutcome::Pending => (ReclaimStatus::InProgress, String::new()),
        GenerationOutcome::Quarantined(r) if awaiting => {
            (ReclaimStatus::AwaitingConfirmation, r.clone())
        }
        GenerationOutcome::Quarantined(r) => (ReclaimStatus::Quarantined, r.clone()),
        other => (ReclaimStatus::InProgress, format!("{other:?}")),
    };
    InstanceReclaim {
        instance_id: g.instance.to_string(),
        epoch: g.epoch.0,
        status: status as i32,
        residues: g
            .residues
            .iter()
            .map(|r| {
                let (state, failures, last_error) = match &r.reason {
                    ResidueReason::Pending => (ResidueState::Pending, 0, String::new()),
                    ResidueReason::Failing {
                        failures,
                        last_error,
                    } => (ResidueState::Failing, *failures, last_error.clone()),
                    ResidueReason::Indeterminate(m) => (ResidueState::Indeterminate, 0, m.clone()),
                    other => (ResidueState::Pending, 0, format!("{other:?}")),
                };
                v1::Residue {
                    effect_id: r.effect.0.clone(),
                    kind: r.kind.as_str().into(),
                    identity: key_text(&r.key),
                    failures,
                    last_error,
                    state: state as i32,
                }
            })
            .collect(),
        reason,
    }
}

/// Contract form of a reclaim report.
pub fn reclaim_report(report: &ReclaimReport) -> v1::ReclaimReport {
    let candidate_instance = |c: &etd_sysfx::Candidate| -> Option<String> {
        c.scope
            .as_ref()
            .and_then(|s| s.generation())
            .map(|(i, _)| i.to_string())
    };
    v1::ReclaimReport {
        generated_unix_ms: report.generated_at.as_millisecond(),
        instances: report
            .generations
            .iter()
            .map(|g| {
                let awaiting = report
                    .candidates
                    .iter()
                    .any(|c| candidate_instance(c).as_deref() == Some(g.instance.as_str()));
                generation_view(g, awaiting)
            })
            .collect(),
        candidates: report
            .candidates
            .iter()
            .map(|c| {
                let (instance_id, epoch) = c
                    .scope
                    .as_ref()
                    .and_then(|s| s.generation())
                    .map_or((String::new(), 0), |(i, e)| (i.to_string(), e.0));
                let origin = match &c.source {
                    CandidateSource::PlannedRecord { .. } => CandidateOrigin::NoCredential,
                    CandidateSource::Swept(FoundBy::DerivedName { .. }) => {
                        CandidateOrigin::LedgerLost
                    }
                    CandidateSource::Swept(FoundBy::PrefixOnly) => CandidateOrigin::PrefixMatch,
                    _ => CandidateOrigin::Unspecified,
                };
                v1::Candidate {
                    candidate_id: c.id.clone(),
                    kind: c.kind.as_str().into(),
                    identity: key_text(&c.key),
                    origin: origin as i32,
                    instance_id,
                    epoch,
                    detail: c
                        .observation
                        .as_ref()
                        .and_then(|o| o.detail.clone())
                        .unwrap_or_default(),
                }
            })
            .collect(),
        conflicts: report
            .conflicts
            .iter()
            .map(|c| v1::Conflict {
                kind: c.kind.as_str().into(),
                identity: key_text(&c.key),
                expected: c
                    .expected
                    .as_ref()
                    .map(|x| format!("{x:?}"))
                    .unwrap_or_default(),
                found: c
                    .found
                    .as_ref()
                    .map(|x| format!("{x:?}"))
                    .unwrap_or_default(),
                effect_id: c.effect.0.clone(),
                conflict_id: c.id.clone(),
            })
            .collect(),
        notes: report
            .notes
            .iter()
            .map(|n| notice(NoticeLevel::Info, "reclaim.note", n.clone(), ""))
            .collect(),
    }
}

/// Merge one generation's outcome into the published report.
pub(crate) fn merge_generation(report: &mut v1::ReclaimReport, g: &GenerationReport, at: i64) {
    report.generated_unix_ms = at;
    let view = generation_view(g, false);
    report
        .instances
        .retain(|r| r.instance_id != view.instance_id);
    if view.status() != ReclaimStatus::Clean {
        report.instances.push(view);
    }
}
