use crate::{config, message::traffic_selector, sa::*, state};
use futures::stream::StreamExt;
use std::net::IpAddr;

use super::establish_sa;

#[tokio::test]
async fn test_dpd() {
    let config_i = config::tests::create_config(b"initiator");
    let config_r = config::tests::create_config(b"responder");

    let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
    let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
    let ts_i = traffic_selector::tests::create_traffic_selector(initiator_addr);
    let ts_r = traffic_selector::tests::create_traffic_selector(responder_addr);

    let (initiator, mut messages_i, responder, mut messages_r) =
        establish_sa(&config_i, &config_r, ts_i, ts_r).await;

    // Initiator sends DPD probe
    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2.handle_dpd().await.expect("unable to handle DPD");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::DpdRequestSent {}).await);

    // Responder receives DPD probe and responds
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

    // Initiator processes DPD response
    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Established {}).await);
}

#[tokio::test]
async fn test_dpd_both_directions() {
    let config_i = config::tests::create_config(b"initiator");
    let config_r = config::tests::create_config(b"responder");

    let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
    let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
    let ts_i = traffic_selector::tests::create_traffic_selector(initiator_addr);
    let ts_r = traffic_selector::tests::create_traffic_selector(responder_addr);

    let (initiator, mut messages_i, responder, mut messages_r) =
        establish_sa(&config_i, &config_r, ts_i, ts_r).await;

    // Initiator DPD
    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        initiator2.handle_dpd().await.expect("unable to handle DPD");
    });
    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");

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

    let initiator2 = initiator.clone();
    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::Established {}).await);

    // Responder DPD
    let responder2 = responder.clone();
    let handle = tokio::spawn(async move {
        responder2.handle_dpd().await.expect("unable to handle DPD");
    });
    let message = match messages_r.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(responder.in_state(&state::DpdRequestSent {}).await);

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
    assert!(initiator.in_state(&state::Established {}).await);

    let responder2 = responder.clone();
    let handle = tokio::spawn(async move {
        responder2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });
    handle.await.expect("handle should be awaited");
    assert!(responder.in_state(&state::Established {}).await);
}
