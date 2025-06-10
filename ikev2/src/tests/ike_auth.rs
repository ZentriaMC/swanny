use crate::{
    config,
    message::{
        ProtectedMessage,
        num::{ExchangeType, NotifyType},
        serialize::Deserialize,
        traffic_selector,
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
