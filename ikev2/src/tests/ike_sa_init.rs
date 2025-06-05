use crate::{
    config,
    crypto::{Group, Nonce},
    message::{
        Message, Spi,
        num::{DhId, ExchangeType, MessageFlags, NotifyType, PayloadType},
        payload::{self, Payload},
        proposal::Proposal,
        serialize::{Deserialize, Serialize},
        traffic_selector,
    },
    sa::*,
    state,
};
use bytes::BytesMut;
use futures::stream::StreamExt;
use std::net::IpAddr;

fn check_notify(message: &[u8], exchange: ExchangeType, ty: NotifyType) {
    let message = Message::deserialize(&mut &message[..]).expect("message should be deserialized");
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
async fn test_empty() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let responder2 = responder.clone();

    let handle = tokio::spawn(async move {
        responder2
            .handle_message(b"")
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Initial {}).await);
    check_notify(
        &message,
        ExchangeType::IKE_SA_INIT,
        NotifyType::INVALID_SYNTAX,
    );
}

#[tokio::test]
async fn test_request_is_response() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let response = Message::new(
        &Spi::default(),
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::R,
        0,
    );

    let len = response
        .size()
        .expect("unable to determine serialized size");
    let buf = BytesMut::with_capacity(len);

    let responder2 = responder.clone();

    let handle = tokio::spawn(async move {
        responder2
            .handle_message(&buf)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Initial {}).await);
    check_notify(
        &message,
        ExchangeType::IKE_SA_INIT,
        NotifyType::INVALID_SYNTAX,
    );
}

#[tokio::test]
async fn test_non_zero_message_id() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let request = Message::new(
        &Spi::default(),
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::I,
        100,
    );

    let len = request.size().expect("unable to determine serialized size");
    let mut buf = BytesMut::with_capacity(len);
    request
        .serialize(&mut buf)
        .expect("unable to serialize message");

    let responder2 = responder.clone();

    let handle = tokio::spawn(async move {
        responder2
            .handle_message(&buf)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Initial {}).await);
    check_notify(
        &message,
        ExchangeType::IKE_SA_INIT,
        NotifyType::INVALID_SYNTAX,
    );
}

#[tokio::test]
async fn test_no_proposal_chosen() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let mut request = Message::new(
        &Spi::default(),
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::I,
        0,
    );

    let nonce = Nonce::new().expect("nonce should be created");
    let group = Group::new(DhId::SECP256R1).expect("group should be created");
    let private_key = group
        .generate_key()
        .expect("group private key should be created");
    let public_key = private_key
        .public_key()
        .expect("group public key should be derived");

    request.add_payloads([
        Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(payload::Sa::new::<[Proposal; 0]>([])),
            true,
        ),
        Payload::new(
            PayloadType::NONCE.into(),
            payload::Content::Nonce(payload::Nonce::new(nonce.as_ref())),
            true,
        ),
        Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(payload::Ke::new(group.id().into(), &public_key)),
            true,
        ),
    ]);

    let len = request.size().expect("unable to determine serialized size");
    let mut buf = BytesMut::with_capacity(len);
    request
        .serialize(&mut buf)
        .expect("unable to serialize message");

    let responder2 = responder.clone();

    let handle = tokio::spawn(async move {
        responder2
            .handle_message(&buf)
            .await
            .expect("unable to handle message");
    });

    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Initial {}).await);
    check_notify(
        &message,
        ExchangeType::IKE_SA_INIT,
        NotifyType::NO_PROPOSAL_CHOSEN,
    );
}

#[tokio::test]
async fn test_mismatched_message_id() {
    let config = config::tests::create_config(b"initiator");
    let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    // Initial exchange
    assert!(initiator.in_state(&state::Initial {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
        let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
        let ts_i = traffic_selector::tests::create_traffic_selector(&initiator_addr);
        let ts_r = traffic_selector::tests::create_traffic_selector(&responder_addr);
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

    let mut message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    // Modify the message ID field to be an unrelated value
    message[23] = 2;

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Initial {}).await);
}

#[tokio::test]
async fn test_response_is_request() {
    let config = config::tests::create_config(b"initiator");
    let (initiator, mut messages_i) = IkeSa::new(&config).expect("unable to create IKE SA");

    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    // Initial exchange
    assert!(initiator.in_state(&state::Initial {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
        let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
        let ts_i = traffic_selector::tests::create_traffic_selector(&initiator_addr);
        let ts_r = traffic_selector::tests::create_traffic_selector(&responder_addr);
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

    let mut message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::IkeSaInitResponseSent {}).await);

    // Modify the flags field to be a request
    message[19] = MessageFlags::I.bits();

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Initial {}).await);
}
