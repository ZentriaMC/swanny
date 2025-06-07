use crate::{
    config,
    message::{
        Message, ProtectedMessage,
        num::{ExchangeType, NotifyType, PayloadType},
        payload,
        serialize::Deserialize,
        traffic_selector,
    },
    sa::*,
    state,
};
use futures::stream::StreamExt;
use std::net::IpAddr;

fn check_notify(message: &Message, exchange: ExchangeType, ty: NotifyType) {
    match message.exchange().assigned() {
        Some(exchange_) if exchange_ == exchange => {}
        _ => unreachable!("exchange type doesn't match"),
    }
    assert_eq!(message.payloads().collect::<Vec<_>>().len(), 1);

    let notify: &payload::Notify = message
        .get(PayloadType::NOTIFY)
        .expect("notify payload should be included");
    match notify.ty().assigned() {
        Some(ty_) if ty_ == ty => {}
        _ => unreachable!("notify type doesn't match"),
    }
}

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
            .handle_acquire(ts_i, ts_r, 1)
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

    let message = ProtectedMessage::deserialize(&mut message.as_slice())
        .expect("message should be deserialized");
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
