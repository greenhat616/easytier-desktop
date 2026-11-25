//! Shared conformance suite for every Ledger implementation. Each case
//! receives a separate empty ledger; tests never inspect implementation internals.
use etd_contract::{Desired, DesiredInstance, InstanceId, NetworkSpec, Revision};
use etd_sysfx::*;

pub fn request(id: &str, digest: u8) -> RequestRecord {
    RequestRecord {
        request_id: id.into(),
        caller: "test".into(),
        digest: RequestDigest([digest; 32]),
    }
}

pub fn put(id: &str, desired: Desired, claims: &[&str]) -> Change {
    Change::PutInstance {
        instance: Box::new(DesiredInstance {
            instance_id: id.into(),
            desired: desired as i32,
            spec: Some(NetworkSpec {
                network_name: id.into(),
                ..Default::default()
            }),
        }),
        claims: claims.iter().map(|s| (*s).into()).collect(),
    }
}

pub fn plan(id: &str, epoch: u64, claims: &[&str]) -> GenerationPlan {
    let instance = InstanceId::from(id);
    GenerationPlan {
        instance: instance.clone(),
        epoch: Epoch(epoch),
        claims: claims.iter().map(|s| (*s).into()).collect(),
        inputs: LaunchInputs {
            spec: NetworkSpec {
                network_name: id.into(),
                ..Default::default()
            },
            spec_revision: 1,
            runtime_dir: format!("run/{id}/{epoch}").into(),
            interface_name: format!("etd-{id}"),
            management: "127.0.0.1:10001".parse().unwrap(),
            privilege: Privilege::User,
            guard: ManagementGuard::Unguarded,
            core: CoreRef {
                version: "test".into(),
                proto_revision: "test".into(),
                sha256: [0; 32],
                binary: "core".into(),
                profile: Some("test".into()),
            },
        },
        effects: vec![EffectIntent {
            scope: EffectScope::Instance {
                instance,
                epoch: Epoch(epoch),
            },
            kind: EffectKind::RuntimeDir,
            key: ObjectKey::Path {
                path: format!("run/{id}/{epoch}").into(),
            },
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
        }],
    }
}

pub fn changes(
    id: &str,
    digest: u8,
    changes: Vec<Change>,
    generations: Vec<GenerationPlan>,
) -> ChangeSet {
    ChangeSet {
        request: request(id, digest),
        changes,
        generations,
    }
}

async fn commit(ledger: &dyn Ledger, rev: Revision, change: ChangeSet) {
    assert_eq!(ledger.commit(rev, change).await.unwrap().revision, rev + 1);
}

pub async fn idempotency(ledger: &dyn Ledger) {
    let change = changes(
        "one",
        1,
        vec![put("a", Desired::Running, &[])],
        vec![plan("a", 1, &[])],
    );
    let receipt = ledger.commit(0, change.clone()).await.unwrap();
    let instance = InstanceId::from("a");
    assert_eq!(
        ledger.request_status(&change.request).await.unwrap(),
        RequestStatus::Done(receipt.clone())
    );
    assert_eq!(
        ledger.receipt(&change.request.request_id).await.unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(ledger.desired().await.unwrap().0, 1);
    assert_eq!(
        ledger.pending_tickets().await.unwrap()[0].generations,
        vec![(instance.clone(), Epoch(1))]
    );
    commit(
        ledger,
        1,
        changes(
            "two",
            2,
            vec![Change::SetDesired {
                instance: instance.clone(),
                desired: Desired::Stopped,
            }],
            vec![],
        ),
    )
    .await;
    ledger.complete_ticket(&receipt.ticket).await.unwrap();
    assert_eq!(ledger.commit(0, change.clone()).await.unwrap(), receipt);
    let mut reused = change;
    reused.request.digest = RequestDigest([2; 32]);
    assert_eq!(
        ledger.request_status(&reused.request).await.unwrap(),
        RequestStatus::Reused
    );
    assert!(matches!(
        ledger.commit(0, reused).await,
        Err(LedgerError::RequestReused(_))
    ));
    assert_eq!(ledger.pending_tickets().await.unwrap().len(), 1);
    assert_eq!(ledger.desired().await.unwrap().0, 2);
    assert_eq!(
        ledger.desired().await.unwrap().1[0].desired(),
        Desired::Stopped
    );
    assert_eq!(ledger.next_epoch(&instance).await.unwrap(), Epoch(2));
}

pub async fn revision_and_atomicity(ledger: &dyn Ledger) {
    commit(
        ledger,
        0,
        changes("one", 1, vec![put("a", Desired::Stopped, &[])], vec![]),
    )
    .await;
    let update = changes(
        "two",
        2,
        vec![put("a", Desired::Running, &[])],
        vec![plan("a", 2, &[])],
    );
    assert_eq!(
        ledger.commit(0, update.clone()).await,
        Err(LedgerError::Conflict { current: 1 })
    );
    assert!(matches!(
        ledger.commit(1, update.clone()).await,
        Err(LedgerError::EpochNotNext { .. })
    ));
    assert_eq!(
        ledger.request_status(&update.request).await.unwrap(),
        RequestStatus::New
    );
    assert_eq!(
        ledger.desired().await.unwrap().1[0].desired(),
        Desired::Stopped
    );
    assert_eq!(ledger.next_epoch(&"a".into()).await.unwrap(), Epoch(1));
    assert!(
        ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(ledger.pending_tickets().await.unwrap().len(), 1);
    let update = changes(
        "two",
        2,
        vec![put("a", Desired::Running, &[])],
        vec![plan("a", 1, &[])],
    );
    commit(ledger, 1, update).await;
    assert_eq!(
        ledger.desired().await.unwrap().1[0].desired(),
        Desired::Running
    );
    assert_eq!(
        ledger
            .generation(&"a".into(), Epoch(1))
            .await
            .unwrap()
            .unwrap()
            .inputs,
        plan("a", 1, &[]).inputs
    );
}

pub async fn claims_while_reclaiming(ledger: &dyn Ledger, replace: bool) {
    let a = InstanceId::from("a");
    let b = InstanceId::from("b");
    commit(
        ledger,
        0,
        changes(
            "one",
            1,
            vec![put("a", Desired::Running, &["X"])],
            vec![plan("a", 1, &["X"])],
        ),
    )
    .await;
    let effect = ledger
        .open_effects(&ScopeFilter::epoch(a.clone(), Epoch(1)))
        .await
        .unwrap()
        .remove(0);
    ledger
        .transition(&effect.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    let duplicate = changes("dup", 2, vec![put("b", Desired::Running, &["X"])], vec![]);
    assert!(matches!(
        ledger.commit(1, duplicate).await,
        Err(LedgerError::ExclusiveTaken { .. })
    ));
    let change = if replace {
        put("a", Desired::Running, &["Y"])
    } else {
        Change::SetDesired {
            instance: a.clone(),
            desired: Desired::Stopped,
        }
    };
    commit(ledger, 1, changes("two", 3, vec![change], vec![])).await;
    let conflicting = changes(
        "three",
        4,
        vec![put("b", Desired::Running, &["X"])],
        vec![plan("b", 1, &["X"])],
    );
    assert!(matches!(
        ledger.commit(2, conflicting).await,
        Err(LedgerError::ExclusiveTaken { .. })
    ));
    assert_eq!(ledger.desired().await.unwrap().0, 2);
    assert_eq!(
        ledger
            .claims()
            .await
            .unwrap()
            .iter()
            .filter(|c| c.resource == "X")
            .cloned()
            .collect::<Vec<_>>(),
        vec![ClaimHold {
            resource: "X".into(),
            instance: a.clone(),
            source: ClaimSource::Generation(Epoch(1))
        }]
    );
    commit(
        ledger,
        2,
        changes("three", 4, vec![put("b", Desired::Running, &["X"])], vec![]),
    )
    .await;
    assert!(matches!(
        ledger.begin_epoch(plan("b", 1, &["X"])).await,
        Err(LedgerError::ExclusiveTaken { .. })
    ));
    assert_eq!(ledger.next_epoch(&b).await.unwrap(), Epoch(1));
    ledger
        .transition(&effect.id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    assert!(
        ledger
            .generation(&a, Epoch(1))
            .await
            .unwrap()
            .unwrap()
            .closed
    );
    ledger.begin_epoch(plan("b", 1, &["X"])).await.unwrap();
    assert_eq!(ledger.next_epoch(&b).await.unwrap(), Epoch(2));
}

pub async fn epochs_and_compaction(ledger: &dyn Ledger) {
    let a = InstanceId::from("a");
    commit(
        ledger,
        0,
        changes(
            "one",
            1,
            vec![put("a", Desired::Running, &[])],
            vec![plan("a", 1, &[])],
        ),
    )
    .await;
    assert!(matches!(
        ledger.begin_epoch(plan("a", 2, &[])).await,
        Err(LedgerError::EpochOpen { .. })
    ));
    let effect = ledger
        .open_effects(&ScopeFilter::all())
        .await
        .unwrap()
        .remove(0);
    for n in 1..=5 {
        assert_eq!(
            ledger.record_failure(&effect.id, "failed").await.unwrap(),
            n
        );
    }
    ledger
        .transition(&effect.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    ledger
        .transition(&effect.id, EffectState::Quarantined, None)
        .await
        .unwrap();
    ledger
        .transition(&effect.id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    assert_eq!(
        ledger.open_effects(&ScopeFilter::all()).await.unwrap()[0].failures,
        0
    );
    ledger
        .transition(&effect.id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    assert!(matches!(
        ledger
            .transition(&effect.id, EffectState::Applied, None)
            .await,
        Err(LedgerError::InvalidTransition { .. })
    ));
    assert!(
        ledger
            .generation(&a, Epoch(1))
            .await
            .unwrap()
            .unwrap()
            .closed
    );
    assert_eq!(ledger.compact().await.unwrap(), 1);
    assert!(ledger.generation(&a, Epoch(1)).await.unwrap().is_none());
    assert_eq!(ledger.next_epoch(&a).await.unwrap(), Epoch(2));
    assert!(matches!(
        ledger.begin_epoch(plan("a", 1, &[])).await,
        Err(LedgerError::EpochNotNext { .. })
    ));
    ledger.begin_epoch(plan("a", 2, &[])).await.unwrap();
}

pub async fn concurrent_revision(ledger: &dyn Ledger) {
    let a = changes(
        "a",
        1,
        vec![put("a", Desired::Running, &["X"])],
        vec![plan("a", 1, &["X"])],
    );
    let b = changes(
        "b",
        2,
        vec![put("b", Desired::Running, &["X"])],
        vec![plan("b", 1, &["X"])],
    );
    let (a, b) = tokio::join!(ledger.commit(0, a), ledger.commit(0, b));
    assert_ne!(a.is_ok(), b.is_ok());
    assert!(matches!(
        a.err().or(b.err()),
        Some(LedgerError::Conflict { current: 1 })
    ));
    assert_eq!(ledger.desired().await.unwrap().1.len(), 1);
    assert_eq!(ledger.pending_tickets().await.unwrap().len(), 1);
    assert_eq!(
        ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .len(),
        1
    );
}
