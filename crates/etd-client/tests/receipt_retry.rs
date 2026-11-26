//! A mutation whose reply is lost recovers its receipt by request id and is
//! not executed again.
mod common;

use common::*;
use etd_client::{CallError, HostClient};
use etd_contract::RequestId;
use etd_testkit::scripted_server::ScriptedHost;
use std::time::Duration;

#[tokio::test]
async fn apply_with_a_lost_reply_returns_the_original_receipt() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.lose_next_reply("Apply");

    let receipt = within(client.apply(apply("request-1", 0))).await.unwrap();

    assert_eq!(receipt.request_id, "request-1");
    assert_eq!(receipt.revision, 1);
    assert_eq!(host.executed(), ["request-1"]);
    assert_eq!(host.count("Apply"), 1, "recovery only reads");
    assert!(host.count("GetReceipt") >= 1);
    assert!(
        host.dials().len() >= 2,
        "the reply was lost with its connection"
    );

    assert_eq!(
        client.receipt(RequestId("request-1".into())).await.unwrap(),
        Some(receipt.clone())
    );
    // The caller retrying the same request changes nothing either.
    assert_eq!(client.apply(apply("request-1", 0)).await.unwrap(), receipt);
    assert_eq!(host.executed(), ["request-1"]);
}

#[tokio::test]
async fn every_mutation_recovers_a_lost_reply() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    for (revision, method) in (0..).zip(MUTATIONS) {
        wait_connected(&client).await;
        host.lose_next_reply(method);
        let id = format!("id-{method}");
        let receipt = within(mutate(&client, method, &id, revision))
            .await
            .unwrap_or_else(|error| panic!("{method}: {error}"));
        assert_eq!(receipt.request_id, id);
        assert_eq!(host.count(method), 1, "{method}");
    }
    assert_eq!(host.executed().len(), MUTATIONS.len());
}

#[tokio::test]
async fn a_host_that_stays_away_leaves_the_outcome_open() {
    let host = ScriptedHost::start();
    let mut options = options();
    options.recovery_timeout = Duration::from_millis(200);
    let client = client_with(&host, options);
    wait_connected(&client).await;
    host.stay_down_after_loss();
    host.lose_next_reply("Apply");

    let error = within(client.apply(apply("request-1", 0)))
        .await
        .unwrap_err();
    assert!(matches!(error, CallError::Unavailable(_)), "{error:?}");

    host.set_refusing(false);
    wait_connected(&client).await;
    let receipt = client
        .receipt(RequestId("request-1".into()))
        .await
        .unwrap()
        .expect("the host had accepted it");
    assert_eq!(client.apply(apply("request-1", 0)).await.unwrap(), receipt);
    assert_eq!(host.executed(), ["request-1"]);
}

#[tokio::test]
async fn a_request_that_never_took_effect_is_not_sent_again_by_the_client() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.drop_next_request("Apply");

    let error = within(client.apply(apply("request-1", 0)))
        .await
        .unwrap_err();
    assert!(
        matches!(error, CallError::Unavailable(_) | CallError::Transport(_)),
        "{error:?}"
    );
    assert!(host.executed().is_empty());
    assert_eq!(host.count("Apply"), 1);
    assert_eq!(host.count("GetReceipt"), 1);

    wait_connected(&client).await;
    client.apply(apply("request-1", 0)).await.unwrap();
    assert_eq!(host.executed(), ["request-1"]);
}

#[tokio::test]
async fn recovery_survives_a_connection_that_breaks_again() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.lose_next_reply("Apply");
    host.drop_next_request("GetReceipt");
    let receipt = within(client.apply(apply("request-1", 0))).await.unwrap();
    assert_eq!(receipt.request_id, "request-1");
    assert_eq!(host.count("GetReceipt"), 2);
    assert_eq!(host.executed(), ["request-1"]);
}

#[tokio::test(start_paused = true)]
async fn a_reply_that_never_comes_is_looked_up_on_the_same_connection() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.hang_next("Apply");
    let error = within(client.apply(apply("request-1", 0)))
        .await
        .unwrap_err();
    assert!(matches!(error, CallError::Unavailable(_)), "{error:?}");
    assert_eq!(host.count("GetReceipt"), 1);
    assert_eq!(
        host.dials().len(),
        1,
        "a slow call does not cost the connection"
    );
}

#[tokio::test]
async fn a_definite_answer_needs_no_recovery() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    client.apply(apply("request-1", 0)).await.unwrap();

    assert!(matches!(
        client.apply(apply("request-2", 0)).await,
        Err(CallError::Conflict { current: 1 })
    ));
    assert!(matches!(
        client.apply(apply("request-1", 1)).await,
        Err(CallError::RequestIdReused)
    ));
    assert_eq!(host.count("GetReceipt"), 0);
    assert_eq!(host.executed(), ["request-1"]);
}

#[tokio::test]
async fn a_mutation_made_without_a_connection_is_never_looked_up() {
    let host = ScriptedHost::start();
    host.set_refusing(true);
    let client = client_with(&host, options());
    assert!(matches!(
        within(client.apply(apply("request-1", 0))).await,
        Err(CallError::Unavailable(_))
    ));
    assert!(host.calls().is_empty());
}
