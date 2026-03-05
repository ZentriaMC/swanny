use crate::{
    config,
    message::{
        num::TrafficSelectorType,
        traffic_selector::{self, TrafficSelector},
    },
    sa::*,
    state,
    tests::establish_sa,
};
use futures::stream::StreamExt;
use std::net::IpAddr;

/// From Established, the initiator acquires with TS (`192.168.2.x`) that don't
/// match the responder's configured selectors (`192.168.1.x`).  The responder
/// rejects with TS_UNACCEPTABLE and both sides stay Established.
#[tokio::test]
async fn test_ts_unacceptable() {
    let config_i = config::tests::create_config(b"initiator");
    let config_r = config::tests::create_config(b"responder");

    let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
    let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
    let ts_i = traffic_selector::tests::create_traffic_selector(initiator_addr);
    let ts_r = traffic_selector::tests::create_traffic_selector(responder_addr);

    let (initiator, mut messages_i, responder, mut messages_r) =
        establish_sa(&config_i, &config_r, ts_i, ts_r).await;

    // CREATE_CHILD_SA with non-matching TS
    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        let addr_i: IpAddr = "192.168.2.2".parse().unwrap();
        let addr_r: IpAddr = "192.168.2.3".parse().unwrap();
        let ts_i = traffic_selector::tests::create_traffic_selector(addr_i);
        let ts_r = traffic_selector::tests::create_traffic_selector(addr_r);
        initiator2
            .handle_acquire(ts_i, ts_r)
            .await
            .expect("unable to handle acquire");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::NewChildSaRequestSent {}).await);

    // Responder rejects
    let responder2 = responder.clone();
    let handle = tokio::spawn(async move {
        responder2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(responder.in_state(&state::Established {}).await);

    // Initiator processes the rejection
    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message.clone())
            .await
            .expect("unable to handle message");
    });
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::Established {}).await);
}

/// With `strict_ts` enabled on the responder, a /24 range that *overlaps* the
/// responder's host selector would pass narrowing but must fail exact match.
/// Both sides stay Established after the rejection.
#[tokio::test]
async fn test_strict_ts_unacceptable() {
    let config_i = config::tests::create_config(b"initiator");
    let config_r = config::tests::create_strict_config(b"responder");

    let ts_i = traffic_selector::tests::create_traffic_selector("192.168.1.2".parse().unwrap());
    let ts_r = traffic_selector::tests::create_traffic_selector("192.168.1.3".parse().unwrap());

    let (initiator, mut messages_i, responder, mut messages_r) =
        establish_sa(&config_i, &config_r, ts_i, ts_r).await;

    // CREATE_CHILD_SA with /24 range — overlaps but doesn't exactly match
    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        let ts_i = TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            0,
            "192.168.1.0".parse().unwrap(),
            "192.168.1.255".parse().unwrap(),
            0,
            65535,
        );
        let ts_r = TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            0,
            "192.168.1.0".parse().unwrap(),
            "192.168.1.255".parse().unwrap(),
            0,
            65535,
        );
        initiator2
            .handle_acquire(ts_i, ts_r)
            .await
            .expect("unable to handle acquire");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::NewChildSaRequestSent {}).await);

    // Responder rejects (strict match fails)
    let responder2 = responder.clone();
    let handle = tokio::spawn(async move {
        responder2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(responder.in_state(&state::Established {}).await);

    // Initiator processes the rejection
    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message.clone())
            .await
            .expect("unable to handle message");
    });
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::Established {}).await);
}
