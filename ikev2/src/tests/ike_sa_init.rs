use bytes::BytesMut;
use crate::{config, message::{Spi, Message, num::{MessageFlags, Num, ExchangeType}, serialize::{Deserialize, Serialize}}, sa::*, state};
use futures::stream::StreamExt;
use std::net::IpAddr;

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

    let message = Message::deserialize(&mut &message[..]).expect("message should be deserialized");
    assert_eq!(message.exchange().assigned(), Some(ExchangeType::IKE_SA_INIT));
    assert!(responder.in_state(&state::Initial {}).await);
    assert_eq!(message.payloads().collect::<Vec<_>>().len(), 1);
}

#[tokio::test]
async fn test_request_is_response() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let mut response = Message::new(
        &Spi::default(),
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::R,
        0,
    );

    let len = response.size().expect("unable to determine serialized size");
    let mut buf = BytesMut::with_capacity(len);
    let response = response.serialize(&mut buf).expect("response should be serializable");

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

    let message = Message::deserialize(&mut &message[..]).expect("message should be deserialized");
    assert_eq!(message.exchange().assigned(), Some(ExchangeType::IKE_SA_INIT));
    assert!(responder.in_state(&state::Initial {}).await);
}

#[tokio::test]
async fn test_non_zero_message_id() {
    let config = config::tests::create_config(b"responder");
    let (responder, mut messages_r) = IkeSa::new(&config).expect("unable to create IKE SA");

    assert!(responder.in_state(&state::Initial {}).await);

    let mut response = Message::new(
        &Spi::default(),
        &Spi::default(),
        ExchangeType::IKE_SA_INIT.into(),
        MessageFlags::I,
        100,
    );

    let len = response.size().expect("unable to determine serialized size");
    let mut buf = BytesMut::with_capacity(len);
    let response = response.serialize(&mut buf).expect("response should be serializable");

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

    let message = Message::deserialize(&mut &message[..]).expect("message should be deserialized");
    assert_eq!(message.exchange().assigned(), Some(ExchangeType::IKE_SA_INIT));
    assert!(responder.in_state(&state::Initial {}).await);
    assert_eq!(message.payloads().collect::<Vec<_>>().len(), 1);
}
