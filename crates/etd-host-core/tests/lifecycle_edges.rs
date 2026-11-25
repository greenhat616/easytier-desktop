//! Every edge of the instance state machine (`lifecycle::machine::EDGES`)
//! is taken by at least one scenario below, observed from the published
//! events; edges deliberately left out are listed with the reason.
mod lifecycle_common;

use etd_contract::{Desired, InstanceState as S};
use etd_core_api::CoreError;
use etd_host_core::lifecycle::machine::EDGES;
use etd_proc::{Exit, ExitCause, Liveness, ProcessEvent};
use etd_sysfx::{EffectKind, Ledger, ReclaimError};
use etd_testkit::fakes::system::{Fault, Step};
use lifecycle_common::*;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

type Edges = BTreeSet<(S, S)>;

/// Edges no scenario takes, and why they stay in the table.
const EXCLUDED: &[((S, S), &str)] = &[(
    (S::Unspecified, S::CutUnconfirmed),
    "a cut reaching a supervisor before its first drive: a scheduling race \
     between the actor spawning the supervisor and the next client command, \
     not reproducible deterministically; the edge must stay allowed",
)];

fn crash() -> Exit {
    Exit {
        code: Some(1),
        signal: None,
        cause: ExitCause::Exited,
    }
}

fn dns() -> etd_contract::NetworkSpec {
    etd_contract::NetworkSpec {
        magic_dns: true,
        ..spec("net")
    }
}

/// Crash the kernel each time it is ready, until the policy gives up.
async fn crash_until_gave_up(world: &World, h: &mut Host<'_>) {
    crash_id_until_gave_up(world, h, "a").await;
}

async fn crash_id_until_gave_up(world: &World, h: &mut Host<'_>, id: &str) {
    loop {
        h.until("ready or gave up", |h| {
            matches!(h.state(id), S::ReadyFull | S::GaveUp)
        })
        .await;
        if h.state(id) == S::GaveUp {
            return;
        }
        world.engine.exit(&world.kernel_of(id), crash());
        h.until_still("reclaimed", |h| {
            matches!(h.state(id), S::Backoff | S::GaveUp)
        })
        .await;
    }
}

fn plan_error() -> Option<CoreError> {
    Some(CoreError::Connect("kernel store broken".into()))
}

/// `c` holds the magic-DNS claim through a generation that cannot be
/// reclaimed for now (stopped; its NRPT rule is busy until `clear_faults`).
async fn stuck_holder(world: &World, h: &mut Host<'_>) {
    h.apply("c", dns(), Desired::Running).await;
    h.wait_state("c", S::ReadyFull).await;
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinNrptRule)
            .fail(ReclaimError::Busy("busy".into())),
    );
    h.set_desired("c", Desired::Stopped).await.unwrap();
    h.until_still("c reclaiming", |h| h.state("c") == S::Reclaiming)
        .await;
}

/// `w` waits for the claim `c` holds.
async fn waiter(world: &World) -> Host<'_> {
    let mut h = world.start();
    h.wait_serving().await;
    stuck_holder(world, &mut h).await;
    h.apply("w", dns(), Desired::Running).await;
    h.until_still("w waiting", |h| h.state("w") == S::Waiting)
        .await;
    h
}

/// Every way into `Waiting` while another instance holds the claim.
async fn claims(edges: &mut Edges) {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("x", spec("x"), Desired::Running).await;
    h.apply("y", spec("y"), Desired::Running).await;
    h.apply("g", spec("g"), Desired::Running).await;
    h.wait_state("x", S::ReadyFull).await;
    h.wait_state("y", S::ReadyFull).await;
    h.wait_state("g", S::ReadyFull).await;
    stuck_holder(&world, &mut h).await;

    // A new configuration needing the claim: reclaim, then wait.
    h.apply("x", dns(), Desired::Running).await;
    h.until_still("x waiting", |h| h.state("x") == S::Waiting)
        .await;
    h.cut("x").await.unwrap();
    h.wait_state("x", S::CutUnconfirmed).await;
    h.set_desired("x", Desired::Running).await.unwrap();
    h.until_still("x waiting", |h| h.state("x") == S::Waiting)
        .await;
    h.set_desired("x", Desired::Stopped).await.unwrap();
    h.wait_state("x", S::Stopped).await;

    // Crashed, then reconfigured during its backoff.
    let y = world.kernel_of("y");
    world.engine.exit(&y, crash());
    h.until_still("y backoff", |h| h.state("y") == S::Backoff)
        .await;
    h.apply("y", dns(), Desired::Running).await;
    h.until("y waiting", |h| h.state("y") == S::Waiting).await;
    h.set_desired("y", Desired::Stopped).await.unwrap();
    h.wait_state("y", S::Stopped).await;

    // Gave up, reconfigured, retried.
    crash_id_until_gave_up(&world, &mut h, "g").await;
    h.apply("g", dns(), Desired::Running).await;
    h.retry_start("g").await;
    h.until_still("g waiting", |h| h.state("g") == S::Waiting)
        .await;
    edges.extend(h.edges());

    // The claim comes free while the waiter cannot start.
    let world = World::new();
    let mut h = waiter(&world).await;
    world.ledger.fail_begin.store(1, Ordering::SeqCst);
    world.sys.clear_faults();
    h.until("w backoff", |h| h.state("w") == S::Backoff).await;
    h.until("w ready", |h| h.state("w") == S::ReadyFull).await;
    edges.extend(h.edges());

    let world = World::new();
    let mut h = waiter(&world).await;
    *world.ledger.fail_generation.lock().unwrap() = Some(("w".into(), 1));
    world.sys.clear_faults();
    h.until("w ready", |h| h.state("w") == S::ReadyFull).await;
    edges.extend(h.edges());

    let world = World::new();
    let mut h = waiter(&world).await;
    world.driver.set_plan_error(plan_error());
    world.sys.clear_faults();
    h.until("w gave up", |h| h.state("w") == S::GaveUp).await;
    edges.extend(h.edges());
}

/// Commits that reach a supervisor together with a ledger problem or a
/// later commit.
async fn interleavings(edges: &mut Edges) {
    // A launch whose generation is superseded by a stop committed with it.
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("a"), Desired::Stopped).await;
    h.wait_state("a", S::Stopped).await;
    h.hold();
    h.set_desired("a", Desired::Running).await.unwrap();
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.notify().await;
    h.wait_state("a", S::Stopped).await;
    // The launch generation cannot be read: retry later, then reclaim the
    // generation left open before starting a new one.
    h.hold();
    h.set_desired("a", Desired::Running).await.unwrap();
    *world.ledger.fail_generation.lock().unwrap() = Some(("a".into(), 1));
    h.notify().await;
    h.until("backoff", |h| h.state("a") == S::Backoff).await;
    h.until("ready", |h| h.state("a") == S::ReadyFull).await;
    // The launch generation was closed meanwhile and no new one can be
    // planned: give up.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    h.hold();
    h.set_desired("a", Desired::Running).await.unwrap();
    let epoch = world.ledger.inner.next_epoch(&"a".into()).await.unwrap().0 - 1;
    world
        .reclaim_engine()
        .reclaim_generation(&"a".into(), etd_sysfx::Epoch(epoch))
        .await
        .unwrap();
    world.driver.set_plan_error(plan_error());
    h.notify().await;
    h.until("gave up", |h| h.state("a") == S::GaveUp).await;
    // A retry superseded by a stop committed with it.
    world.driver.set_plan_error(None);
    h.hold();
    h.retry_start("a").await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.notify().await;
    h.wait_state("a", S::Stopped).await;
    edges.extend(h.edges());

    // A cut while the kernel ignores the graceful stop.
    let world = World::new();
    world
        .engine
        .push_spawn(Ok(etd_testkit::fakes::process::SpawnScript {
            graceful_exit: None,
            ..Default::default()
        }));
    let mut h = ready(&world, "a").await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopping).await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    edges.extend(h.edges());
}

/// Host start without an open generation: the first start fails.
async fn first_start(edges: &mut Edges) {
    let world = World::new();
    let h = ready(&world, "a").await;
    h.crash();
    world.ledger.fail_begin.store(1, Ordering::SeqCst);
    let mut h = world.start();
    h.until("backoff", |h| h.state("a") == S::Backoff).await;
    world.driver.set_plan_error(plan_error());
    h.until("gave up", |h| h.state("a") == S::GaveUp).await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    edges.extend(h.edges());
    h.crash();

    let mut h = world.start();
    h.until("gave up", |h| h.state("a") == S::GaveUp).await;
    edges.extend(h.edges());
}

async fn ready<'w>(world: &'w World, id: &str) -> Host<'w> {
    let mut h = world.start();
    h.wait_serving().await;
    h.apply(id, spec(id), Desired::Running).await;
    h.wait_state(id, S::ReadyFull).await;
    h
}

/// Start, stop, crash, back off, give up, retry, stop again.
async fn lifecycle(edges: &mut Edges) {
    let world = World::new();
    let mut h = ready(&world, "a").await;
    world.engine.exit(&world.last_kernel(), crash());
    h.until_still("backoff", |h| h.state("a") == S::Backoff)
        .await;
    // Stop during backoff.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    // Run again and crash until it gives up.
    h.set_desired("a", Desired::Running).await.unwrap();
    crash_until_gave_up(&world, &mut h).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("ready", |h| h.state("a") == S::ReadyFull).await;
    edges.extend(h.edges());
}

/// Give up, then a manual retry starts at once.
async fn retry_after_give_up(edges: &mut Edges) {
    let world = World::new();
    let mut h = ready(&world, "a").await;
    crash_until_gave_up(&world, &mut h).await;
    h.retry_start("a").await;
    h.until("ready", |h| h.state("a") == S::ReadyFull).await;
    edges.extend(h.edges());
}

/// Stop while starting, cut while live and while reclaiming.
async fn stops_and_cuts(edges: &mut Edges) {
    let world = World::new();
    world.behave(KernelBehaviour {
        address: false,
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("a"), Desired::Running).await;
    h.wait_state("a", S::Starting).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    // Cut while starting.
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::Starting).await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    h.set_desired("a", Desired::Running).await.unwrap();
    h.until("starting again", |h| h.state("a") == S::Starting)
        .await;
    edges.extend(h.edges());

    // Cut while ready (basic and full), then confirmed running again.
    let world = World::new();
    world
        .driver
        .set_attach_error(Some(CoreError::Connect("down".into())));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("a"), Desired::Running).await;
    h.wait_state("a", S::ReadyBasic).await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    // Cut while stopped.
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    world.driver.set_attach_error(None);
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::ReadyFull).await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    // A start committed while cut: reclaim, then start.
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::ReadyFull).await;
    edges.extend(h.edges());

    // Cut while reclaiming, during backoff and after giving up.
    let world = World::new();
    let mut h = ready(&world, "a").await;
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::LinuxTun)
            .times(2)
            .fail(ReclaimError::Busy("busy".into())),
    );
    world.engine.exit(&world.last_kernel(), crash());
    h.until_still("reclaiming", |h| h.state("a") == S::Reclaiming)
        .await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::ReadyFull).await;
    world.engine.exit(&world.last_kernel(), crash());
    h.until_still("backoff", |h| h.state("a") == S::Backoff)
        .await;
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    h.set_desired("a", Desired::Running).await.unwrap();
    h.wait_state("a", S::ReadyFull).await;
    edges.extend(h.edges());
}

/// Lost management session; never ready; fence failure.
async fn readiness(edges: &mut Edges) {
    let world = World::new();
    let mut h = ready(&world, "a").await;
    h.clients(1).await;
    world.driver.set_poll_error(Some(CoreError::SessionClosed));
    world
        .driver
        .set_attach_error(Some(CoreError::Connect("gone".into())));
    h.wait_state("a", S::ReadyBasic).await;
    // Crash while basic.
    world.engine.exit(&world.last_kernel(), crash());
    h.until_still("reclaimed", |h| h.state("a") == S::Backoff)
        .await;
    world.driver.set_poll_error(None);
    world.driver.set_attach_error(None);
    h.wait_state("a", S::ReadyFull).await;
    // Stop while basic.
    world
        .driver
        .set_attach_error(Some(CoreError::Connect("gone".into())));
    world.engine.exit(&world.last_kernel(), crash());
    h.wait_state("a", S::ReadyBasic).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    edges.extend(h.edges());

    let world = World::new();
    world.behave(KernelBehaviour {
        address: false,
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("a"), Desired::Running).await;
    h.until("timed out", |h| h.state("a") == S::Backoff).await;
    edges.extend(h.edges());
}

/// Waiting for a single-writer claim, and leaving it.
async fn waiting(edges: &mut Edges) {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", dns(), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.apply("b", dns(), Desired::Stopped).await;
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinNrptRule)
            .times(3)
            .fail(ReclaimError::Busy("busy".into())),
    );
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.until_still("a reclaiming", |h| h.state("a") == S::Reclaiming)
        .await;
    h.set_desired("b", Desired::Running).await.unwrap();
    h.until_still("b waiting", |h| h.state("b") == S::Waiting)
        .await;
    // Stop while waiting, run again: waits, then starts.
    h.set_desired("b", Desired::Stopped).await.unwrap();
    h.until_still("b stopped", |h| h.state("b") == S::Stopped)
        .await;
    h.set_desired("b", Desired::Running).await.unwrap();
    h.until("b ready", |h| h.state("b") == S::ReadyFull).await;
    edges.extend(h.edges());
}

/// Quarantine (uncertain process) and the way out.
async fn quarantine(edges: &mut Edges) {
    let world = World::new();
    let mut h = ready(&world, "a").await;
    let kernel = world.last_kernel();
    world.engine.exit(&kernel, crash());
    world
        .engine
        .set_liveness(&kernel, Some(Liveness::Uncertain));
    h.wait_state("a", S::Quarantined).await;
    world.engine.set_liveness(&kernel, None);
    h.retry_reclaim("a").await;
    h.wait_state("a", S::ReadyFull).await;
    // Cleanup uncertain while stopping.
    world.engine.emit(
        &world.last_kernel(),
        ProcessEvent::CleanupUncertain("job".into()),
    );
    h.wait_state("a", S::Quarantined).await;
    edges.extend(h.edges());
}

/// Host start: open generations (pending or quarantined), held starts.
async fn host_start(edges: &mut Edges) {
    let world = World::new();
    {
        let mut h = world.start();
        h.wait_serving().await;
        h.apply("a", spec("a"), Desired::Running).await;
        h.apply("b", dns(), Desired::Running).await;
        h.apply("c", spec("c"), Desired::Stopped).await;
        h.wait_state("a", S::ReadyFull).await;
        h.wait_state("b", S::ReadyFull).await;
        h.crash();
    }
    let kernels = world.spawned();
    world
        .engine
        .set_liveness(&kernels[0], Some(Liveness::Uncertain));
    // b's DNS rule cannot be removed for now: it starts reclaiming.
    world.sys.inject(
        Fault::on(Step::Reclaim)
            .kind(EffectKind::WinNrptRule)
            .times(1)
            .fail(ReclaimError::Busy("busy".into())),
    );
    let mut h = world.start();
    h.wait_state("a", S::Quarantined).await;
    h.until("b ready", |h| h.state("b") == S::ReadyFull).await;
    h.wait_state("c", S::Stopped).await;
    edges.extend(h.edges());
    h.crash();

    // Starts held by a failed sweep.
    world.engine.set_liveness(&kernels[0], None);
    for _ in 0..2 {
        world
            .engine
            .fail_next_enumeration(etd_proc::ProcessError::Enumeration("denied".into()));
    }
    let mut h = world.start();
    h.until("b ready", |h| h.state("b") == S::ReadyFull).await;
    edges.extend(h.edges());
}

#[tokio::test]
async fn every_edge_is_taken() {
    let mut edges = Edges::new();
    lifecycle(&mut edges).await;
    retry_after_give_up(&mut edges).await;
    stops_and_cuts(&mut edges).await;
    readiness(&mut edges).await;
    waiting(&mut edges).await;
    quarantine(&mut edges).await;
    host_start(&mut edges).await;
    claims(&mut edges).await;
    interleavings(&mut edges).await;
    first_start(&mut edges).await;

    let excluded: Edges = EXCLUDED.iter().map(|(e, _)| *e).collect();
    let table: Edges = EDGES.iter().copied().collect();
    let missing: Vec<_> = table
        .difference(&edges)
        .filter(|e| !excluded.contains(e))
        .collect();
    let unknown: Vec<_> = edges.difference(&table).collect();
    assert!(unknown.is_empty(), "edges outside the table: {unknown:?}");
    assert!(missing.is_empty(), "edges never taken: {missing:?}");
    let stale: Vec<_> = excluded.intersection(&edges).collect();
    assert!(stale.is_empty(), "excluded edges that are taken: {stale:?}");
}
