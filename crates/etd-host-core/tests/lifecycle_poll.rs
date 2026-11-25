//! Kernel polling: about once a second while a client subscribes to
//! events, a health check every 30 s otherwise.
mod lifecycle_common;

use etd_contract::v1::event::Payload;
use etd_contract::{Desired, InstanceState as S};
use etd_core_api::{CoreError, CoreEventKind};
use lifecycle_common::*;
use std::time::Duration;

async fn ready(world: &World) -> Host<'_> {
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h
}

#[tokio::test]
async fn thirty_seconds_without_subscribers() {
    let world = World::new();
    let mut h = ready(&world).await;
    let before = world.driver.polls();
    h.idle(Duration::from_millis(500), Duration::from_secs(120))
        .await;
    let polls = world.driver.polls() - before;
    assert!((3..=5).contains(&polls), "{polls} polls in 120 s");
}

#[tokio::test]
async fn about_one_second_with_subscribers() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.clients(1).await;
    h.settle().await;
    let before = world.driver.polls();
    h.idle(Duration::from_millis(100), Duration::from_secs(10))
        .await;
    let polls = world.driver.polls() - before;
    assert!((9..=11).contains(&polls), "{polls} polls in 10 s");

    // The last subscriber leaves: back to health checks.
    h.clients(0).await;
    h.settle().await;
    let before = world.driver.polls();
    h.idle(Duration::from_millis(500), Duration::from_secs(60))
        .await;
    let polls = world.driver.polls() - before;
    assert!((1..=3).contains(&polls), "{polls} polls in 60 s");
}

#[tokio::test]
async fn a_new_subscriber_is_served_within_a_second() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.idle(Duration::from_millis(500), Duration::from_secs(5))
        .await;
    let before = world.driver.polls();
    h.clients(1).await;
    h.idle(Duration::from_millis(100), Duration::from_millis(1100))
        .await;
    assert!(world.driver.polls() > before);
}

#[tokio::test]
async fn kernel_events_become_host_events() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.clients(1).await;
    world.driver.push_event(CoreEventKind::AddressChanged {
        ipv4_cidr: Some("10.144.0.7/24".into()),
    });
    h.until("address published", |h| {
        h.status("a")
            .is_some_and(|s| s.addresses == vec!["10.144.0.7/24".to_string()])
    })
    .await;
    // The same kernel event is not published twice.
    h.idle(Duration::from_millis(100), Duration::from_secs(3))
        .await;
    h.settle_sync();
    let n = h
        .log
        .iter()
        .filter(|e| {
            matches!(&e.payload, Payload::InstanceStatus(s)
                if s.addresses == vec!["10.144.0.7/24".to_string()] && s.state() == S::ReadyFull)
        })
        .count();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_failed_health_check_drops_to_basic_and_reattaches() {
    let world = World::new();
    let mut h = ready(&world).await;
    h.clients(1).await;
    world
        .driver
        .set_attach_error(Some(CoreError::Connect("gone".into())));
    world.driver.set_poll_error(Some(CoreError::SessionClosed));
    h.wait_state("a", S::ReadyBasic).await;
    assert_eq!(
        world.spawned().len(),
        1,
        "a lost session never kills the kernel"
    );
    world.driver.set_poll_error(None);
    world.driver.set_attach_error(None);
    h.wait_state("a", S::ReadyFull).await;
}
