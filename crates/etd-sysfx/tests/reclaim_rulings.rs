//! R1 audit round 1 rulings (msg#480): record-only leases, no key-type
//! exception to "delete needs proof", shared records wait for generations,
//! administrator decisions bind to the reported identity and respect the
//! gates, unreadable credentials are indeterminate, unsupported kinds
//! follow the record state machine, offline reports are cached.
mod reclaim_support;

use etd_contract::{CandidateDecision, InstanceId, v1::CandidateAction};
use etd_sysfx::*;
use etd_testkit::fakes::system::{FakeObject, Fault, ObjectId, Owner, Step};
use reclaim_support::{Fate, World, core_hex};

fn scope(id: &str, epoch: u64) -> EffectScope {
    EffectScope::Instance {
        instance: InstanceId::from(id),
        epoch: Epoch(epoch),
    }
}

fn upnp(id: &str, epoch: u64) -> EffectIntent {
    EffectIntent {
        scope: scope(id, epoch),
        kind: EffectKind::UpnpMapping,
        key: ObjectKey::PortMapping {
            protocol: "udp".into(),
            internal_port: 11010,
            external_port: None,
            description: "EasyTier udp hole punch".into(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Lease { seconds: 300 },
    }
}

fn delete(id: &str) -> CandidateDecision {
    CandidateDecision {
        candidate_id: id.into(),
        action: CandidateAction::Delete as i32,
    }
}

/// An object at `key` with no credential (as a probe that cannot read one
/// would report it).
fn bare(kind: EffectKind, key: ObjectKey, owner: Owner) -> FakeObject {
    FakeObject {
        id: ObjectId(0),
        kind,
        key,
        credential: None,
        owner,
        value: None,
        volatile: false,
        pid: None,
        addresses: Vec::new(),
        up: true,
        expires: None,
    }
}

#[tokio::test]
async fn lease_records_never_block_and_are_never_reclaimed() {
    let w = World::new();
    w.add_instance("a").await;
    let mut intents = w.windows_intents("a", 1);
    intents.push(upnp("a", 1));
    let effects = w.begin("a", intents).await;
    for e in &effects {
        w.settle(e, Fate::Applied).await;
    }
    // Even a failing UPnP reclaimer must not matter: it is never called.
    w.sys
        .inject(Fault::on(Step::Probe).kind(EffectKind::UpnpMapping));
    let engine = w.engine();
    let report = engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    assert!(
        !w.sys
            .ops()
            .iter()
            .any(|o| o.kind == Some(EffectKind::UpnpMapping))
    );
    // The router mapping is left to expire.
    let left: Vec<_> = w.sys.ours().iter().map(|o| o.kind).collect();
    assert_eq!(left, vec![EffectKind::UpnpMapping]);
    let all = engine.report().await.unwrap();
    // The process record closed in this run: the expiry is absolute.
    assert!(
        all.notes
            .iter()
            .any(|n| n.contains("recorded only") && n.contains("ended, at ")),
        "{:?}",
        all.notes
    );
    // The next generation may start.
    w.begin("a", w.windows_intents("a", 2)).await;
}

#[tokio::test]
async fn a_fence_key_alone_never_authorises_a_delete() {
    let w = World::new();
    w.add_instance("a").await;
    let fence = w
        .windows_intents("a", 1)
        .into_iter()
        .find(|i| i.kind == EffectKind::WinFenceFilter)
        .unwrap();
    w.begin("a", vec![fence.clone()]).await;
    // Something at the fence key that the probe does not report as inside
    // the exclusive container.
    w.sys.insert(FakeObject {
        credential: Some(Credential::Opaque {
            value: "not-ours".into(),
        }),
        ..bare(fence.kind, fence.key.clone(), Owner::Foreign)
    });
    let report = w
        .engine()
        .reclaim_all(ReclaimScope::Instances)
        .await
        .unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(report.candidates.len(), 1);
}

#[tokio::test]
async fn unreadable_credential_is_indeterminate_not_conflict() {
    let w = World::new();
    w.add_instance("a").await;
    let tun = w
        .windows_intents("a", 1)
        .into_iter()
        .find(|i| i.kind == EffectKind::WinTunAdapter)
        .unwrap();
    let effects = w.begin("a", vec![tun.clone()]).await;
    for e in &effects {
        w.settle(e, Fate::Applied).await;
    }
    let ours = w.sys.find(tun.kind, &tun.key).unwrap();
    w.sys.vanish(tun.kind, &tun.key);
    w.sys.insert(bare(tun.kind, ours.key.clone(), Owner::Ours));
    let report = w
        .engine()
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Pending);
    let residue = report
        .residues
        .iter()
        .find(|r| r.kind == EffectKind::WinTunAdapter)
        .unwrap();
    assert!(matches!(residue.reason, ResidueReason::Indeterminate(_)));
    assert!(w.engine().report().await.unwrap().conflicts.is_empty());
}

#[tokio::test]
async fn unsupported_kind_quarantines_through_reclaiming() {
    let w = World::new();
    w.running("a").await;
    let without_registry: Vec<_> = EffectKind::ALL
        .iter()
        .copied()
        .filter(|k| *k != EffectKind::WinRegistryValue)
        .collect();
    let engine = w.engine_with(w.sys.reclaimers_for(&without_registry));
    let a = InstanceId::from("a");
    let mut last = None;
    for _ in 0..QUARANTINE_AFTER {
        last = Some(engine.reclaim_generation(&a, Epoch(1)).await.unwrap());
    }
    let report = last.unwrap();
    assert!(
        matches!(report.outcome, GenerationOutcome::Quarantined(_)),
        "{report:?}"
    );
    let residue = report
        .residues
        .iter()
        .find(|r| r.kind == EffectKind::WinRegistryValue)
        .unwrap();
    assert!(
        matches!(&residue.reason, ResidueReason::Failing { failures, .. } if *failures == QUARANTINE_AFTER)
    );
}

#[tokio::test]
async fn purge_waits_for_generations_that_may_use_shared_records() {
    let w = World::new();
    w.running("a").await;
    let rule = EffectIntent {
        scope: EffectScope::CoreBinary { sha256: core_hex() },
        kind: EffectKind::WinProgramFirewallRule,
        key: ObjectKey::Rule {
            name: "EasyTier core.exe (in)".into(),
            group: Some("EasyTier".into()),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    };
    let driver = EffectIntent {
        scope: EffectScope::Product,
        kind: EffectKind::Driver,
        key: ObjectKey::Service {
            name: "wintun".into(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    };
    for intent in [rule, driver] {
        let e = w.memory.record(intent.clone()).await.unwrap();
        let obs = w.sys.apply_intent(&intent);
        w.memory
            .transition(&e.id, EffectState::Applied, Some(obs))
            .await
            .unwrap();
    }
    // The generation cannot close: its process is still running.
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::Process)
            .fail(ReclaimError::Busy("running".into())),
    );
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Everything).await.unwrap();
    assert!(!w.sys.reclaim_order().contains(&EffectKind::Driver));
    assert!(
        !w.sys
            .reclaim_order()
            .contains(&EffectKind::WinProgramFirewallRule)
    );
    assert_eq!(
        report
            .notes
            .iter()
            .filter(|n| n.contains("waiting"))
            .count(),
        2
    );

    w.sys.clear_faults();
    engine.reclaim_all(ReclaimScope::Everything).await.unwrap();
    w.assert_clean();
    assert!(w.open().await.is_empty());
}

#[tokio::test]
async fn delete_decision_binds_to_the_reported_object() {
    let w = World::new();
    w.add_instance("a").await;
    let tun = w
        .windows_intents("a", 1)
        .into_iter()
        .find(|i| i.kind == EffectKind::WinTunAdapter)
        .unwrap();
    w.begin("a", vec![tun.clone()]).await;
    w.sys.create_foreign(tun.kind, tun.key.clone());
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let id = report.candidates[0].id.clone();
    // After the report, the object was replaced by another one.
    w.sys.replace_with_foreign(tun.kind, &tun.key);
    let report = engine.resolve(&[delete(&id)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(report.candidates.len(), 1);
    assert!(report.notes.iter().any(|n| n.contains("delete refused")));
}

#[tokio::test]
async fn delete_decision_respects_rank_gates() {
    let w = World::new();
    w.add_instance("a").await;
    let intents: Vec<_> = w
        .windows_intents("a", 1)
        .into_iter()
        .filter(|i| {
            matches!(
                i.kind,
                EffectKind::WinTunAdapter | EffectKind::WinFirewallRule
            )
        })
        .collect();
    let effects = w.begin("a", intents.clone()).await;
    for e in &effects {
        if e.kind == EffectKind::WinFirewallRule {
            w.settle(e, Fate::Applied).await;
        }
    }
    let tun = intents
        .iter()
        .find(|i| i.kind == EffectKind::WinTunAdapter)
        .unwrap();
    w.sys.create_foreign(tun.kind, tun.key.clone());
    // Firewall rules (lower rank) fail: the interface candidate must wait.
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinFirewallRule)
            .fail(ReclaimError::Busy("x".into())),
    );
    let engine = w.engine();
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let tun_record = w
        .open()
        .await
        .into_iter()
        .find(|e| e.kind == EffectKind::WinTunAdapter)
        .unwrap();
    // Not reached yet (lower rank failing): make it a candidate by hand.
    w.memory
        .transition(&tun_record.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    let found = w.sys.find(tun.kind, &tun.key).unwrap();
    w.memory
        .transition(
            &tun_record.id,
            EffectState::Candidate,
            Some(Observation {
                credential: None,
                key: Some(found.key.clone()),
                observed_at: jiff::Timestamp::now(),
                detail: Some(format!(
                    "found credential: {}",
                    serde_json::to_string(&found.credential).unwrap()
                )),
            }),
        )
        .await
        .unwrap();
    let id = engine.report().await.unwrap().candidates[0].id.clone();
    let report = engine.resolve(&[delete(&id)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("lower-rank records")),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn offline_report_is_served_while_the_ledger_is_unavailable() {
    let (w, ledger) = World::crashing();
    w.add_instance("a").await;
    w.sys.create_foreign(
        EffectKind::WinTunAdapter,
        ObjectKey::Interface {
            name: Some(w.name("a")),
            guid: None,
        },
    );
    let engine = w.engine();
    ledger
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let diagnosed = engine.diagnose().await.unwrap();
    assert_eq!(diagnosed.candidates.len(), 1);
    assert_eq!(engine.report().await.unwrap(), diagnosed);
}

#[tokio::test]
async fn lease_expiry_is_relative_when_the_process_end_is_unknown() {
    let w = World::new();
    w.add_instance("a").await;
    // No process record closes in this run (it is planned and never
    // reached because a lower rank fails).
    let effects = w.begin("a", vec![upnp("a", 1)]).await;
    for e in &effects {
        if e.kind != EffectKind::Process {
            w.settle(e, Fate::Applied).await;
        }
    }
    let process = effects
        .iter()
        .find(|e| e.kind == EffectKind::Process)
        .unwrap();
    w.memory
        .transition(&process.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    w.sys
        .inject(Fault::on(Step::Probe).kind(EffectKind::Process));
    let engine = w.engine();
    engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    let notes = engine.report().await.unwrap().notes;
    assert!(
        notes.iter().any(
            |n| n.contains("expires 300s after the kernel process ended") && !n.contains(", at ")
        ),
        "{notes:?}"
    );
}

#[tokio::test]
async fn manual_delete_of_shared_records_waits_for_generations() {
    let w = World::new();
    w.running("a").await;
    let rule = EffectIntent {
        scope: EffectScope::CoreBinary { sha256: core_hex() },
        kind: EffectKind::WinProgramFirewallRule,
        key: ObjectKey::Rule {
            name: "EasyTier core.exe (in)".into(),
            group: Some("EasyTier".into()),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    };
    // Recorded, never read back; a foreign rule holds the name.
    w.memory.record(rule.clone()).await.unwrap();
    w.sys.create_foreign(rule.kind, rule.key.clone());
    // Process keeps the generation open.
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::Process)
            .fail(ReclaimError::Busy("running".into())),
    );
    let engine = w.engine();
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let shared = w
        .open()
        .await
        .into_iter()
        .find(|e| e.kind == EffectKind::WinProgramFirewallRule)
        .unwrap();
    // Make it a candidate as reclaim_core would once allowed.
    w.memory
        .transition(&shared.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    let found = w.sys.find(rule.kind, &rule.key).unwrap();
    w.memory
        .transition(
            &shared.id,
            EffectState::Candidate,
            Some(Observation {
                credential: None,
                key: Some(found.key.clone()),
                observed_at: jiff::Timestamp::now(),
                detail: Some(format!(
                    "found credential: {}",
                    serde_json::to_string(&found.credential).unwrap()
                )),
            }),
        )
        .await
        .unwrap();
    let id = engine
        .report()
        .await
        .unwrap()
        .candidates
        .into_iter()
        .find(|c| c.kind == EffectKind::WinProgramFirewallRule)
        .unwrap()
        .id;
    let report = engine.resolve(&[delete(&id)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("generations that may use it")),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn stale_decisions_do_not_carry_over() {
    let w = World::new();
    w.add_instance("a").await;
    let key = ObjectKey::Interface {
        name: Some("etd-0badf00d".into()),
        guid: None,
    };
    w.sys.create_foreign(EffectKind::WinTunAdapter, key.clone());
    let engine = w.engine();
    let first = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let old_id = first.candidates[0].id.clone();
    // The object is replaced by another one with the same name; the next
    // report lists it under a new id.
    w.sys.replace_with_foreign(EffectKind::WinTunAdapter, &key);
    let second = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert_ne!(second.candidates[0].id, old_id);
    let report = engine.resolve(&[delete(&old_id)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert!(report.notes.iter().any(|n| n.contains("unknown candidate")));
}

#[tokio::test]
async fn exclusive_sweep_waits_for_process_records() {
    let w = World::new();
    w.running("a").await;
    w.sys.create_ours(
        EffectKind::WinFenceFilter,
        ObjectKey::Fence {
            container: etd_testkit::fakes::system::FENCE_CONTAINER.into(),
            rule: "orphan".into(),
            port: 15999,
        },
    );
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::Process)
            .fail(ReclaimError::Busy("running".into())),
    );
    let engine = w.engine();
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    assert!(w.sys.ours().iter().any(|o| matches!(
        &o.key,
        ObjectKey::Fence { rule, .. } if rule == "orphan"
    )));
    w.sys.clear_faults();
    engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    w.assert_clean();
}

/// A record in conflict (adapter recreated by someone else with our name).
async fn conflict_world() -> (World, ObjectKey) {
    let w = World::new();
    w.add_instance("a").await;
    let tun = w
        .windows_intents("a", 1)
        .into_iter()
        .find(|i| i.kind == EffectKind::WinTunAdapter)
        .unwrap();
    let effects = w.begin("a", vec![tun.clone()]).await;
    for e in &effects {
        if e.kind == EffectKind::WinTunAdapter {
            w.settle(e, Fate::Applied).await;
        }
    }
    w.sys.replace_with_foreign(tun.kind, &tun.key);
    (w, tun.key)
}

#[tokio::test]
async fn conflict_reference_allows_keep_only() {
    let (w, _) = conflict_world().await;
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let conflict = report.conflicts[0].id.clone();
    let report = engine.resolve(&[delete(&conflict)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("a conflict can only be kept"))
    );
    assert_eq!(report.conflicts.len(), 1);
}

#[tokio::test]
async fn conflict_reference_never_acts_on_a_candidate() {
    let w = World::new();
    w.add_instance("a").await;
    let tun = w
        .windows_intents("a", 1)
        .into_iter()
        .find(|i| i.kind == EffectKind::WinTunAdapter)
        .unwrap();
    w.begin("a", vec![tun.clone()]).await;
    w.sys.create_foreign(tun.kind, tun.key.clone());
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let candidate = &report.candidates[0];
    let CandidateSource::PlannedRecord { effect } = &candidate.source else {
        panic!("{candidate:?}");
    };
    // A conflict-shaped reference to the candidate record: refused for
    // both actions, nothing changes.
    let forged = format!("conflict:{}", effect.0);
    for action in [CandidateAction::Keep, CandidateAction::Delete] {
        let report = engine
            .resolve(&[CandidateDecision {
                candidate_id: forged.clone(),
                action: action as i32,
            }])
            .await
            .unwrap();
        assert!(
            report.notes.iter().any(|n| n.contains("not a conflict")),
            "{:?}",
            report.notes
        );
        assert_eq!(report.candidates.len(), 1);
    }
    assert!(w.sys.foreign_deleted().is_empty());
    assert_eq!(w.sys.foreign().len(), 1);
}

#[tokio::test]
async fn candidate_reference_never_acts_on_a_conflict() {
    let (w, _) = conflict_world().await;
    let engine = w.engine();
    let report = engine.reclaim_all(ReclaimScope::Instances).await.unwrap();
    let conflict = &report.conflicts[0];
    // A candidate-shaped reference to the conflict record.
    let forged = format!("rec:{}@{}", conflict.effect.0, "0".repeat(24));
    let report = engine.resolve(&[delete(&forged)]).await.unwrap();
    assert!(w.sys.foreign_deleted().is_empty());
    assert!(report.notes.iter().any(|n| n.contains("stale decision")));
    assert_eq!(report.conflicts.len(), 1);
}

fn magic_dns_recovery(id: &str, epoch: u64) -> EffectIntent {
    EffectIntent {
        scope: scope(id, epoch),
        kind: EffectKind::WinMagicDnsRecovery,
        key: ObjectKey::Registry {
            key: r"HKLM\SOFTWARE\EasyTier\MagicDNS".into(),
            value: None,
        },
        undo: Undo::ReplayUpstreamRecovery,
        persistence: Persistence::Persistent,
    }
}

#[tokio::test]
async fn replay_upstream_recovery_is_authorised_by_its_reclaimer() {
    let w = World::new();
    w.add_instance("a").await;
    // Planned only (no credential): still handed to the reclaimer.
    let effects = w.begin("a", vec![magic_dns_recovery("a", 1)]).await;
    for e in &effects {
        if e.kind == EffectKind::WinMagicDnsRecovery {
            w.settle(e, Fate::PlannedPresent).await;
        }
    }
    let engine = w.engine();
    // The reclaimer refuses (another EasyTier process runs): retryable.
    w.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinMagicDnsRecovery)
            .once()
            .fail(ReclaimError::Busy("other EasyTier running".into())),
    );
    let a = InstanceId::from("a");
    let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Pending);
    assert_eq!(w.sys.ours().len(), 1);
    // Gate holds now: replayed, verified absent, closed.
    let report = engine.reclaim_generation(&a, Epoch(1)).await.unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Closed);
    w.assert_clean();
}

#[tokio::test]
async fn replay_upstream_recovery_must_leave_its_key_absent() {
    let w = World::new();
    w.add_instance("a").await;
    let effects = w.begin("a", vec![magic_dns_recovery("a", 1)]).await;
    for e in &effects {
        if e.kind == EffectKind::WinMagicDnsRecovery {
            w.settle(e, Fate::Applied).await;
        }
    }
    // The reclaimer reports success but the recovery key stays.
    let engine = w.engine_with(
        EffectKind::ALL
            .iter()
            .copied()
            .filter(|k| *k != EffectKind::WinMagicDnsRecovery)
            .map(|k| w.sys.reclaimer(k))
            .chain(std::iter::once(
                std::sync::Arc::new(NoopReclaimer) as std::sync::Arc<dyn Reclaimer>
            ))
            .collect(),
    );
    let report = engine
        .reclaim_generation(&InstanceId::from("a"), Epoch(1))
        .await
        .unwrap();
    assert_eq!(report.outcome, GenerationOutcome::Pending);
    let residue = &report.residues[0];
    assert!(
        matches!(&residue.reason, ResidueReason::Failing { last_error, .. } if last_error.contains("still present"))
    );
}

/// Claims success without touching anything; probes always find the key.
struct NoopReclaimer;

#[async_trait::async_trait]
impl Reclaimer for NoopReclaimer {
    fn kind(&self) -> EffectKind {
        EffectKind::WinMagicDnsRecovery
    }
    fn rank(&self) -> u8 {
        EffectKind::WinMagicDnsRecovery.default_rank()
    }
    async fn probe(&self, e: &Effect) -> Probe {
        Probe::Present(Observation {
            credential: None,
            key: Some(e.key.clone()),
            observed_at: jiff::Timestamp::now(),
            detail: None,
        })
    }
    async fn reclaim(&self, _: &Effect) -> Result<Reclaimed, ReclaimError> {
        Ok(Reclaimed::Removed)
    }
}
