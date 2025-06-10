use crate::{config, message::traffic_selector, sa::*, state};
use futures::stream::StreamExt;
use std::net::IpAddr;

#[tokio::test]
async fn test_all_good() {
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

    let child_sa = match messages_r.next().await {
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert_eq!(child_sa.mode(), ChildSaMode::Transport);
    assert!(responder.in_state(&state::Established {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let child_sa = match messages_i.next().await {
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert_eq!(child_sa.mode(), ChildSaMode::Transport);
    assert!(initiator.in_state(&state::Established {}).await);

    // Rekeying
    let spi = *child_sa.spi();

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_expire(spi, false)
            .await
            .expect("unable to handle expire");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::RekeyChildSaRequestSent {}).await);

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

    let _created_child_sa = match messages_r.next().await {
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    let _rekeyed_child_sa = match messages_r.next().await {
        Some(ControlMessage::DeleteChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Established {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let created_child_sa = match messages_i.next().await {
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    let _rekeyed_child_sa = match messages_i.next().await {
        Some(ControlMessage::DeleteChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Established {}).await);

    // Deleting
    let spi = *created_child_sa.spi();

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_expire(spi, true)
            .await
            .expect("unable to handle expire");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(
        initiator
            .in_state(&state::DeleteChildSaRequestSent {})
            .await
    );

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

    let _child_sa = match messages_r.next().await {
        Some(ControlMessage::DeleteChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(responder.in_state(&state::Established {}).await);

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Established {}).await);

    // Recreating
    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        let initiator_addr: IpAddr = "192.168.1.2".parse().unwrap();
        let responder_addr: IpAddr = "192.168.1.3".parse().unwrap();
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

    assert!(initiator.in_state(&state::NewChildSaRequestSent {}).await);

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

    let initiator2 = initiator.clone();

    let handle = tokio::spawn(async move {
        initiator2
            .handle_message(message)
            .await
            .expect("unable to handle message");
    });

    let _child_sa = match messages_i.next().await {
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };

    handle.await.expect("handle should be awaited");

    assert!(initiator.in_state(&state::Established {}).await);
}
