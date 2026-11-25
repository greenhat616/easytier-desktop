mod common;
use common::*;
use etd_contract::v1::*;
use etd_host_core::stub::host_service_server::HostService;
use etd_sysfx::Ledger;
use std::sync::atomic::Ordering;
#[tokio::test]
async fn durable_retry_and_old_revision() {
    let mut f = Fixture::new().await;
    let plans = f.start_commands();
    let mut body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "one".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            network_secret: Some("test-only".into()),
            ..Default::default()
        }),
        desired: Desired::Stopped as i32,
    };
    // Treat the initial reply as lost. Retry must not replan or commit again.
    let first = f
        .service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    let retry = f
        .service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(first, retry);
    assert_eq!(plans.load(Ordering::SeqCst), 1);
    assert_eq!(f.ledger.desired().await.unwrap().0, 2);
    let recovered = f
        .service
        .get_receipt(request(
            GetReceiptRequest {
                request_id: "one".into(),
            },
            Role::Control,
        ))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(recovered, first);
    body.desired = Desired::Running as i32;
    assert_eq!(
        code(
            f.service
                .apply(request(body.clone(), Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::RequestIdReused
    );
    body.header.as_mut().unwrap().request_id = "two".into();
    assert_eq!(
        code(
            f.service
                .apply(request(body, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::RevisionConflict
    );
    assert_eq!(plans.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn remove_accepts_stop_before_open_generation_closes() {
    use etd_sysfx::{EffectState, ScopeFilter};
    use etd_testkit::conformance::ledger::{changes, plan_at, put};
    let f = Fixture::new().await;
    f.ledger
        .commit(
            1,
            changes(
                "seed-instance",
                2,
                vec![put(INSTANCE, Desired::Running, &[])],
                vec![plan_at(INSTANCE, 1, &[], 2)],
            ),
        )
        .await
        .unwrap();
    let body = RemoveInstanceRequest {
        header: Some(MutationHeader {
            request_id: "remove".into(),
            expected_revision: 2,
        }),
        instance_id: INSTANCE.into(),
    };
    let receipt = f
        .service
        .remove_instance(request(body.clone(), Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(
        f.ledger.desired().await.unwrap().1[0].desired(),
        Desired::Stopped
    );
    assert_eq!(
        f.service
            .remove_instance(request(body, Role::Control))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap(),
        receipt
    );
    let cannot_revive = SetDesiredRequest {
        header: Some(MutationHeader {
            request_id: "pending".into(),
            expected_revision: receipt.revision,
        }),
        instance_id: INSTANCE.into(),
        desired: Desired::Stopped as i32,
    };
    assert_eq!(
        code(
            f.service
                .set_desired(request(cannot_revive, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::InstanceBusy
    );
    let effects = f.ledger.open_effects(&ScopeFilter::all()).await.unwrap();
    for e in effects {
        f.ledger
            .transition(&e.id, EffectState::Reclaimed, None)
            .await
            .unwrap();
    }
    assert!(f.ledger.desired().await.unwrap().1.is_empty());
}

#[tokio::test]
async fn absent_secret_keeps_stored_value_clear_is_explicit() {
    let mut f = Fixture::new().await;
    f.start_commands();
    let mut body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "set".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            network_secret: Some("test-only".into()),
            ..Default::default()
        }),
        desired: Desired::Stopped as i32,
    };
    f.service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap();
    body.header = Some(MutationHeader {
        request_id: "keep".into(),
        expected_revision: 2,
    });
    body.spec.as_mut().unwrap().network_secret = None;
    f.service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap();
    assert_eq!(
        f.ledger.desired().await.unwrap().1[0]
            .spec
            .as_ref()
            .unwrap()
            .network_secret
            .as_deref(),
        Some("test-only")
    );
    body.header = Some(MutationHeader {
        request_id: "clear".into(),
        expected_revision: 3,
    });
    body.spec.as_mut().unwrap().network_secret = Some(String::new());
    f.service.apply(request(body, Role::Control)).await.unwrap();
    assert!(
        !f.ledger.desired().await.unwrap().1[0]
            .spec
            .as_ref()
            .unwrap()
            .network_secret_set
    );
}

#[tokio::test]
async fn cancellation_after_durable_commit_does_not_lose_notification_or_receipt() {
    use etd_host_core::{
        api::{ClientPresence, Command, HostView, orchestrator_channel},
        service::ContractService,
    };
    use etd_testkit::{
        conformance::ledger::{changes, put},
        fakes::store::FakeCoreStore,
    };
    use std::{sync::Arc, time::Duration};
    let f = Fixture::new().await;
    f.ledger
        .commit(
            1,
            changes(
                "seed-instance",
                2,
                vec![put(INSTANCE, Desired::Running, &[])],
                vec![],
            ),
        )
        .await
        .unwrap();
    let (handle, mut port) = orchestrator_channel(
        1,
        HostView {
            seq: 0,
            snapshot: HostSnapshot {
                phase: HostPhase::Serving as i32,
                ..Default::default()
            },
        },
    );
    handle
        .send(Command::Clients(ClientPresence::default()))
        .await
        .unwrap(); // Keep the queue full until the client disconnects.
    let service = ContractService::new(
        HostMode::Service,
        f.ledger.clone(),
        etd_sysfx::InstallKey([7; 32]),
        f.auth,
        Arc::new(FakeCoreStore::default()),
        handle,
        vec![],
        8,
    );
    let body = SetDesiredRequest {
        header: Some(MutationHeader {
            request_id: "lost-reply".into(),
            expected_revision: 2,
        }),
        instance_id: INSTANCE.into(),
        desired: Desired::Stopped as i32,
    };
    let call = tokio::spawn({
        let service = service.clone();
        let body = body.clone();
        async move { service.set_desired(request(body, Role::Control)).await }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.ledger.desired().await.unwrap().0 != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!call.is_finished());
    call.abort();
    let _ = call.await;
    assert!(matches!(
        port.commands.recv().await,
        Some(Command::Clients(_))
    ));
    let Some(Command::Committed { receipt }) =
        tokio::time::timeout(Duration::from_secs(5), port.commands.recv())
            .await
            .unwrap()
    else {
        panic!("durable operation must notify H1")
    };
    let retry = service
        .set_desired(request(body, Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(receipt, retry);
    assert_eq!(f.ledger.desired().await.unwrap().0, 3);
}

#[tokio::test]
async fn request_digest_binds_caller_revision_method_and_presence() {
    let mut f = Fixture::new().await;
    let plans = f.start_commands();
    let body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "digest".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            flags: Some(NetworkFlags::default()),
            ..Default::default()
        }),
        desired: Desired::Stopped as i32,
    };
    f.service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap();
    assert_eq!(
        code(
            f.service
                .apply(request(body.clone(), Role::Admin))
                .await
                .unwrap_err()
        ),
        ErrorCode::RequestIdReused
    );
    let mut changed = body.clone();
    changed.header.as_mut().unwrap().expected_revision = 2;
    assert_eq!(
        code(
            f.service
                .apply(request(changed, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::RequestIdReused
    );
    let mut changed = body.clone();
    changed
        .spec
        .as_mut()
        .unwrap()
        .flags
        .as_mut()
        .unwrap()
        .multi_thread = Some(false);
    assert_eq!(
        code(
            f.service
                .apply(request(changed, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::RequestIdReused
    );
    let changed = SetDesiredRequest {
        header: body.header,
        instance_id: INSTANCE.into(),
        desired: Desired::Stopped as i32,
    };
    assert_eq!(
        code(
            f.service
                .set_desired(request(changed, Role::Control))
                .await
                .unwrap_err()
        ),
        ErrorCode::RequestIdReused
    );
    assert_eq!(plans.load(Ordering::SeqCst), 1);
    assert_eq!(f.ledger.desired().await.unwrap().0, 2);
}

#[tokio::test]
async fn generation_is_committed_atomically_with_request_and_config_revision() {
    use etd_sysfx::{Epoch, ScopeFilter};
    let mut f = Fixture::new().await;
    let plans = f.start_commands();
    let body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "start".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            network_name: "network".into(),
            ..Default::default()
        }),
        desired: Desired::Running as i32,
    };
    let receipt = f
        .service
        .apply(request(body.clone(), Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(receipt.revision, 2);
    let generation = f
        .ledger
        .generation(&INSTANCE.into(), Epoch(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation.inputs.spec_revision, 2);
    assert_eq!(generation.inputs.spec, body.spec.clone().unwrap());
    assert_eq!(
        f.ledger
            .open_effects(&ScopeFilter::all())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        f.ledger
            .pending_tickets()
            .await
            .unwrap()
            .iter()
            .any(|t| t.receipt == receipt && t.generations == vec![(INSTANCE.into(), Epoch(1))])
    );
    assert_eq!(
        f.service
            .apply(request(body, Role::Control))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap(),
        receipt
    );
    assert_eq!(plans.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn receipt_is_visible_only_to_original_caller_or_admin() {
    let mut f = Fixture::new().await;
    f.start_commands();
    let body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "private-receipt".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec::default()),
        desired: Desired::Stopped as i32,
    };
    let receipt = f
        .service
        .apply(request(body, Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt;
    for (role, expected) in [
        (Role::Viewer, None),
        (Role::Control, receipt.clone()),
        (Role::Admin, receipt.clone()),
    ] {
        let actual = f
            .service
            .get_receipt(request(
                GetReceiptRequest {
                    request_id: "private-receipt".into(),
                },
                role,
            ))
            .await
            .unwrap()
            .into_inner()
            .receipt;
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn apply_with_secret_uses_h1_canonical_generation_spec() {
    use etd_sysfx::Epoch;
    let mut f = Fixture::new().await;
    f.start_commands();
    let body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "apply-secret-start".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            network_secret: Some("synthetic-fixture".into()),
            network_secret_set: true,
            ..Default::default()
        }),
        desired: Desired::Running as i32,
    };
    let receipt = f
        .service
        .apply(request(body, Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(receipt.revision, 2);
    let persisted = f.ledger.desired().await.unwrap().1.remove(0).spec.unwrap();
    assert!(!persisted.network_secret_set);
    assert_eq!(
        persisted.network_secret.as_deref(),
        Some("synthetic-fixture")
    );
    let generation = f
        .ledger
        .generation(&INSTANCE.into(), Epoch(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation.inputs.spec, persisted);
}

#[tokio::test]
async fn stopped_apply_then_set_desired_starts_from_exact_stored_spec() {
    use etd_sysfx::Epoch;
    let mut f = Fixture::new().await;
    f.start_commands();
    let body = ApplyRequest {
        header: Some(MutationHeader {
            request_id: "apply-secret-stopped".into(),
            expected_revision: 1,
        }),
        instance_id: INSTANCE.into(),
        spec: Some(NetworkSpec {
            network_secret: Some("synthetic-fixture".into()),
            network_secret_set: true,
            ..Default::default()
        }),
        desired: Desired::Stopped as i32,
    };
    f.service.apply(request(body, Role::Control)).await.unwrap();
    let persisted = f.ledger.desired().await.unwrap().1.remove(0).spec.unwrap();
    assert!(!persisted.network_secret_set);
    assert!(
        f.ledger
            .generation(&INSTANCE.into(), Epoch(1))
            .await
            .unwrap()
            .is_none()
    );
    let stop = SetDesiredRequest {
        header: Some(MutationHeader {
            request_id: "start-stored-secret".into(),
            expected_revision: 2,
        }),
        instance_id: INSTANCE.into(),
        desired: Desired::Running as i32,
    };
    let receipt = f
        .service
        .set_desired(request(stop, Role::Control))
        .await
        .unwrap()
        .into_inner()
        .receipt
        .unwrap();
    assert_eq!(receipt.revision, 3);
    let generation = f
        .ledger
        .generation(&INSTANCE.into(), Epoch(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation.inputs.spec_revision, 2);
    assert_eq!(generation.inputs.spec, persisted);
    assert_eq!(
        generation.inputs.spec.network_secret.as_deref(),
        Some("synthetic-fixture")
    );
}
