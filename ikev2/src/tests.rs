mod all_good;
mod ike_auth;
mod ike_sa_init;

use crate::message::{
    Message,
    num::{ExchangeType, NotifyType, PayloadType},
    payload,
};

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
