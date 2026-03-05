mod all_good;
mod create_child_sa;
mod dpd;
mod ike_auth;
mod ike_sa_init;

use crate::{
    config::Config,
    message::{
        Message,
        num::{ExchangeType, NotifyType, PayloadType},
        payload,
        traffic_selector::TrafficSelector,
    },
    sa::*,
    state,
};
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::StreamExt;

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

/// Run the full IKE_SA_INIT + IKE_AUTH handshake to reach Established on both
/// sides, consuming the initial `CreateChildSa` control messages.
///
/// Returns `(initiator, messages_i, responder, messages_r)` ready for further
/// CREATE_CHILD_SA exchanges.
pub(crate) async fn establish_sa(
    config_i: &Config,
    config_r: &Config,
    ts_i: TrafficSelector,
    ts_r: TrafficSelector,
) -> (
    IkeSa,
    UnboundedReceiver<ControlMessage>,
    IkeSa,
    UnboundedReceiver<ControlMessage>,
) {
    let (initiator, mut messages_i) = IkeSa::new(config_i).expect("unable to create IKE SA");
    let (responder, mut messages_r) = IkeSa::new(config_r).expect("unable to create IKE SA");

    assert!(initiator.in_state(&state::Initial {}).await);

    // IKE_SA_INIT request
    let initiator2 = initiator.clone();
    let ts_i2 = ts_i.clone();
    let ts_r2 = ts_r.clone();
    let handle = tokio::spawn(async move {
        initiator2
            .handle_acquire(ts_i2, ts_r2)
            .await
            .expect("unable to handle acquire");
    });

    let message = match messages_i.next().await {
        Some(ControlMessage::IkeMessage(message)) => message,
        _ => panic!("unexpected message"),
    };
    handle.await.expect("handle should be awaited");
    assert!(initiator.in_state(&state::IkeSaInitRequestSent {}).await);

    // IKE_SA_INIT response
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

    // IKE_AUTH request
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

    // IKE_AUTH response
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
        Some(ControlMessage::CreateChildSa(child_sa)) => child_sa,
        _ => panic!("unexpected message"),
    };
    match messages_r.next().await {
        Some(ControlMessage::InitialContact(_)) => {}
        _ => panic!("expected InitialContact"),
    };
    handle.await.expect("handle should be awaited");
    assert!(responder.in_state(&state::Established {}).await);

    // Initiator processes IKE_AUTH response
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

    (initiator, messages_i, responder, messages_r)
}
