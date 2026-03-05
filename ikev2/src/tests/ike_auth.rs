use crate::{
    config,
    message::{
        ProtectedMessage,
        num::{ExchangeType, NotifyType, TrafficSelectorType},
        serialize::Deserialize,
        traffic_selector::{self, TrafficSelector},
    },
    sa::*,
    state,
    tests::check_notify,
};
use futures::stream::StreamExt;
use std::net::IpAddr;

#[tokio::test]
async fn test_ts_unacceptable() {
    let config = config::tests::create_config(b"initiator");
    let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    // Initial exchange
    assert!(initiator.in_state(&state::Initial {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        let initiator_addr: IpAddr = "192.168.2.2".parse().unwrap();
        let responder_addr: IpAddr = "192.168.2.3".parse().unwrap();
        let ts_i = traffic_selector::tests::create_traffic_selector(initiator_addr);
        let ts_r = traffic_selector::tests::create_traffic_selector(responder_addr);
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

    assert!(initiator.in_state(&state::IkeSaInitRequestSent {}).await);

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

    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::IkeAuthRequestSent {}).await);

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

    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    let message =
        ProtectedMessage::deserialize(&mut &message[..]).expect("message should be deserialized");
    let message = initiator
        .unprotect_message(message)
        .await
        .expect("message should be unprotected");

    check_notify(
        &message,
        ExchangeType::IKE_AUTH,
        NotifyType::TS_UNACCEPTABLE,
    );
}

/// With strict_ts enabled, a TS that would pass narrowing but doesn't exactly
/// match the responder's configured selector must be rejected.
#[tokio::test]
async fn test_strict_ts_unacceptable() {
    // Initiator uses the default (non-strict) config — its TS config matches
    // 192.168.1.2 and 192.168.1.3 as single hosts (port range 0-65535).
    let config = config::tests::create_config(b"initiator");
    let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

    // Responder uses strict_ts — only exact TS equality is accepted.
    let config = config::tests::create_strict_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(initiator.in_state(&state::Initial {}).await);

    let initiator2 = initiator.clone();

    // The initiator acquires a /24 range that *overlaps* with the responder's
    // 192.168.1.2 host selector.  negotiate() would narrow it successfully,
    // but exact_match() must reject it.
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
    assert!(initiator.in_state(&state::IkeSaInitRequestSent {}).await);

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
    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::IkeAuthRequestSent {}).await);

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

    // Responder stays in IkeSaInitResponseSent (rejected the TS)
    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    let message =
        ProtectedMessage::deserialize(&mut &message[..]).expect("message should be deserialized");
    let message = initiator
        .unprotect_message(message)
        .await
        .expect("message should be unprotected");

    check_notify(
        &message,
        ExchangeType::IKE_AUTH,
        NotifyType::TS_UNACCEPTABLE,
    );
}
