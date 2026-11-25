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
    plan_at(id, epoch, claims, 1)
}

pub fn plan_at(id: &str, epoch: u64, claims: &[&str], revision: Revision) -> GenerationPlan {
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
            spec_revision: revision,
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
            kind: EffectKind::Process,
            key: ObjectKey::Process {
                exe: "core".into(),
                cmdline_marker: format!("run/{id}/{epoch}").into(),
            },
            undo: Undo::EnsureAbsent,
            persistence: Persistence::WithProcess,
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
        vec![plan_at("a", 2, &[], 2)],
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
        vec![plan_at("a", 1, &[], 2)],
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
        plan_at("a", 1, &[], 2).inputs
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
        vec![plan_at("b", 1, &["X"], 3)],
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
        ledger.begin_epoch(plan_at("b", 1, &["X"], 3)).await,
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
    ledger
        .begin_epoch(plan_at("b", 1, &["X"], 3))
        .await
        .unwrap();
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

/// Core and product intents are recorded once while open, but cannot keep
/// an instance generation open after its own records have closed.
pub async fn shared_effects(ledger: &dyn Ledger) {
    let mut a = plan("a", 1, &[]);
    let mut b = plan("b", 1, &[]);
    let product = EffectIntent {
        scope: EffectScope::Product,
        kind: EffectKind::Driver,
        key: ObjectKey::Service {
            name: "driver".into(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
    };
    a.effects.push(product.clone());
    b.effects.push(product);
    commit(
        ledger,
        0,
        changes(
            "a",
            1,
            vec![
                put("a", Desired::Running, &[]),
                put("b", Desired::Running, &[]),
            ],
            vec![a, b],
        ),
    )
    .await;
    let product_filter = ScopeFilter {
        product: true,
        kinds: vec![EffectKind::Driver],
        ..Default::default()
    };
    let products = ledger.open_effects(&product_filter).await.unwrap();
    assert_eq!(products.len(), 1);
    for name in ["a", "b"] {
        let id = InstanceId::from(name);
        let generation = ledger.generation(&id, Epoch(1)).await.unwrap().unwrap();
        assert_eq!(generation.effects.len(), 2);
        assert!(generation.effects.iter().any(|e| e.id == products[0].id));
        let effect = ledger
            .open_effects(&ScopeFilter::instance(id.clone()))
            .await
            .unwrap()
            .remove(0);
        ledger
            .transition(&effect.id, EffectState::Reclaimed, None)
            .await
            .unwrap();
        assert!(
            ledger
                .generation(&id, Epoch(1))
                .await
                .unwrap()
                .unwrap()
                .closed
        );
    }
    assert_eq!(ledger.compact().await.unwrap(), 2);
    assert_eq!(
        ledger.open_effects(&product_filter).await.unwrap(),
        products
    );
}

pub async fn remove_while_reclaiming(ledger: &dyn Ledger) {
    let id = InstanceId::from("a");
    let mut generation = plan("a", 1, &["X"]);
    let mut second = generation.effects[0].clone();
    second.kind = EffectKind::RuntimeDir;
    second.key = ObjectKey::Path {
        path: "second".into(),
    };
    generation.effects.push(second);
    commit(
        ledger,
        0,
        changes(
            "start",
            1,
            vec![put("a", Desired::Running, &["X"])],
            vec![generation],
        ),
    )
    .await;
    let records = ledger
        .open_effects(&ScopeFilter::instance(id.clone()))
        .await
        .unwrap();
    ledger
        .transition(&records[0].id, EffectState::Reclaiming, None)
        .await
        .unwrap();
    let remove = changes(
        "remove",
        2,
        vec![Change::RemoveInstance(id.clone())],
        vec![],
    );
    let receipt = ledger.commit(1, remove.clone()).await.unwrap();
    assert_eq!(
        ledger.desired().await.unwrap().1[0].desired(),
        Desired::Stopped
    );
    assert_eq!(
        ledger.claims().await.unwrap(),
        vec![ClaimHold {
            resource: "X".into(),
            instance: id.clone(),
            source: ClaimSource::Generation(Epoch(1))
        }]
    );
    let revive = changes(
        "revive",
        3,
        vec![put("a", Desired::Running, &["X"])],
        vec![],
    );
    assert!(matches!(
        ledger.commit(2, revive.clone()).await,
        Err(LedgerError::RemovalPending { .. })
    ));
    assert!(matches!(
        ledger
            .commit(
                2,
                changes(
                    "set",
                    4,
                    vec![Change::SetDesired {
                        instance: id.clone(),
                        desired: Desired::Running
                    }],
                    vec![]
                )
            )
            .await,
        Err(LedgerError::RemovalPending { .. })
    ));
    assert!(matches!(
        ledger.begin_epoch(plan("a", 2, &["X"])).await,
        Err(LedgerError::RemovalPending { .. })
    ));
    ledger
        .transition(&records[0].id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    assert_eq!(ledger.desired().await.unwrap().1.len(), 1);
    ledger
        .transition(&records[1].id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    assert_eq!(ledger.desired().await.unwrap(), (3, vec![]));
    assert!(ledger.claims().await.unwrap().is_empty());
    assert_eq!(ledger.next_epoch(&id).await.unwrap(), Epoch(2));
    assert_eq!(ledger.commit(1, remove).await.unwrap(), receipt);
    assert_eq!(
        ledger.commit(2, revive).await,
        Err(LedgerError::Conflict { current: 3 })
    );
    assert!(matches!(
        ledger
            .commit(
                3,
                changes(
                    "set",
                    4,
                    vec![Change::SetDesired {
                        instance: id,
                        desired: Desired::Running
                    }],
                    vec![]
                )
            )
            .await,
        Err(LedgerError::UnknownInstance(_))
    ));
}

pub async fn reservation_validation(ledger: &dyn Ledger) {
    let id = InstanceId::from("a");
    let stopped = changes(
        "stopped",
        1,
        vec![put("a", Desired::Stopped, &[])],
        vec![plan("a", 1, &[])],
    );
    assert!(matches!(
        ledger.commit(0, stopped).await,
        Err(LedgerError::InvalidPlan { .. })
    ));
    assert_eq!(ledger.desired().await.unwrap(), (0, vec![]));
    commit(
        ledger,
        0,
        changes("create", 1, vec![put("a", Desired::Stopped, &[])], vec![]),
    )
    .await;
    assert!(matches!(
        ledger.begin_epoch(plan("a", 1, &[])).await,
        Err(LedgerError::InvalidPlan { .. })
    ));
    let mut changed = put("a", Desired::Running, &[]);
    if let Change::PutInstance { instance, .. } = &mut changed {
        instance.spec.as_mut().unwrap().network_name = "changed".into();
    }
    let stale = plan_at("a", 1, &[], 2);
    assert!(matches!(
        ledger
            .commit(
                1,
                changes("update", 2, vec![changed.clone()], vec![stale.clone()])
            )
            .await,
        Err(LedgerError::InvalidPlan { .. })
    ));
    commit(ledger, 1, changes("update", 2, vec![changed], vec![])).await;
    assert!(matches!(
        ledger.begin_epoch(stale).await,
        Err(LedgerError::InvalidPlan { .. })
    ));
    let mut current = plan_at("a", 1, &[], 2);
    current.inputs.spec.network_name = "changed".into();
    let mut old = current.clone();
    old.inputs.spec_revision = 1;
    assert_eq!(
        ledger.begin_epoch(old).await,
        Err(LedgerError::Conflict { current: 2 })
    );
    let mut no_process = current.clone();
    no_process.effects.clear();
    assert!(matches!(
        ledger.begin_epoch(no_process).await,
        Err(LedgerError::InvalidPlan { .. })
    ));
    assert!(
        ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(ledger.next_epoch(&id).await.unwrap(), Epoch(1));
    ledger.begin_epoch(current).await.unwrap();
}

pub async fn caller_and_purge(ledger: &dyn Ledger) {
    let allow_list = vec![etd_contract::AllowEntry {
        principal: Some(etd_contract::OsPrincipal {
            id: Some(etd_contract::v1::os_principal::Id::UnixUid(0)),
        }),
        role: etd_contract::Role::Admin as i32,
        display_name: "installer".into(),
    }];
    let original = changes(
        "first",
        1,
        vec![
            put("a", Desired::Stopped, &[]),
            Change::SetAllowList(allow_list.clone()),
            Change::SelectCore(Some("test-core".into())),
        ],
        vec![],
    );
    let receipt = ledger.commit(0, original.clone()).await.unwrap();
    assert_eq!(
        ledger
            .receipt_for(&original.request.request_id, Some(&original.request.caller))
            .await
            .unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(
        ledger
            .receipt_for(&original.request.request_id, Some("different-caller"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        ledger
            .receipt_for(&original.request.request_id, None)
            .await
            .unwrap(),
        Some(receipt.clone())
    );
    let mut impersonated = original.clone();
    impersonated.request.caller = "different-caller".into();
    assert_eq!(
        ledger.request_status(&impersonated.request).await.unwrap(),
        RequestStatus::Reused
    );
    assert!(matches!(
        ledger.commit(0, impersonated).await,
        Err(LedgerError::RequestReused(_))
    ));
    ledger.complete_ticket(&receipt.ticket).await.unwrap();
    assert_eq!(ledger.commit(0, original.clone()).await.unwrap(), receipt);
    let purge = changes("purge", 2, vec![Change::PurgeAll], vec![]);
    let purge_receipt = ledger.commit(1, purge.clone()).await.unwrap();
    assert_eq!(ledger.desired().await.unwrap(), (2, vec![]));
    let settings = ledger.settings().await.unwrap();
    assert_eq!(settings.allow_list, allow_list);
    assert_eq!(settings.selected_core, None);
    assert_eq!(
        ledger.request_status(&original.request).await.unwrap(),
        RequestStatus::New
    );
    assert!(
        ledger
            .receipt(&original.request.request_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(ledger.pending_tickets().await.unwrap().len(), 1);
    assert_eq!(ledger.commit(0, purge).await.unwrap(), purge_receipt);
}

pub async fn per_instance_spec_revision(ledger: &dyn Ledger) {
    let id = InstanceId::from("a");
    commit(
        ledger,
        0,
        changes("one", 1, vec![put("a", Desired::Stopped, &[])], vec![]),
    )
    .await;
    commit(
        ledger,
        1,
        changes("two", 2, vec![put("b", Desired::Stopped, &[])], vec![]),
    )
    .await;
    assert_eq!(ledger.spec_revision(&id).await.unwrap(), 1);
    assert_eq!(ledger.spec_revision(&"b".into()).await.unwrap(), 2);
    commit(
        ledger,
        2,
        changes(
            "start",
            3,
            vec![Change::SetDesired {
                instance: id.clone(),
                desired: Desired::Running,
            }],
            vec![plan_at("a", 1, &[], 1)],
        ),
    )
    .await;
    assert_eq!(ledger.spec_revision(&id).await.unwrap(), 1);
    let effect = ledger
        .open_effects(&ScopeFilter::instance(id.clone()))
        .await
        .unwrap()
        .remove(0);
    ledger
        .transition(&effect.id, EffectState::Reclaimed, None)
        .await
        .unwrap();
    commit(
        ledger,
        3,
        changes(
            "unrelated",
            4,
            vec![Change::SelectCore(Some("next".into()))],
            vec![],
        ),
    )
    .await;
    ledger.begin_epoch(plan_at("a", 2, &[], 1)).await.unwrap();
    assert_eq!(ledger.spec_revision(&id).await.unwrap(), 1);
    commit(
        ledger,
        4,
        changes("replace", 5, vec![put("a", Desired::Running, &[])], vec![]),
    )
    .await;
    assert_eq!(ledger.spec_revision(&id).await.unwrap(), 5);
}
