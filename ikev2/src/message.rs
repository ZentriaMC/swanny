//! IKEv2 messages
//!
//! This module provides serialization and deserialization of IKEv2
//! messages, following [RFC 7296]. Each IKEv2 message contains a
//! header followed by one or payloads, represented as an array of
//! [`Payload`].
//!
//! [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296.html
//! [`Payload`]: crate::message::payload::Payload
//!
use anyhow::Result;
use bytes::{Buf, BufMut};

pub mod num;
use num::{ExchangeType, MessageFlags, Num, PayloadType};

pub mod payload;
use payload::Payload;

pub mod proposal;
pub mod serialize;
pub mod traffic_selector;
pub mod transform;

pub type Spi = [u8; 8];
pub type EspSpi = [u8; 4];

pub(crate) const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// IKEv2 message
#[derive(Debug)]
pub struct Message {
    spi_i: Spi,
    spi_r: Spi,
    exchange: Num<u8, ExchangeType>,
    flags: MessageFlags,
    id: u32,
    payloads: Vec<Payload>,
}

impl Message {
    /// Creates a new `Message` with required fields
    pub fn new(
        spi_i: &Spi,
        spi_r: &Spi,
        exchange: Num<u8, ExchangeType>,
        flags: MessageFlags,
        id: u32,
    ) -> Self {
        Self {
            spi_i: spi_i.to_owned(),
            spi_r: spi_r.to_owned(),
            exchange,
            flags,
            id,
            payloads: Default::default(),
        }
    }

    /// Returns the initiator SPI
    pub fn spi_i(&self) -> &Spi {
        &self.spi_i
    }

    /// Returns the responder SPI
    pub fn spi_r(&self) -> &Spi {
        &self.spi_r
    }

    /// Returns the exchange type
    pub fn exchange(&self) -> Num<u8, ExchangeType> {
        self.exchange
    }

    /// Returns the flags set in the current message
    pub fn flags(&self) -> &MessageFlags {
        &self.flags
    }

    /// Returns the message ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns an iterator over payloads inside this message
    pub fn payloads(&self) -> impl Iterator<Item = &Payload> {
        self.payloads.iter()
    }

    /// Appends new payloads into this message
    pub fn add_payloads<P>(&mut self, payloads: P)
    where
        P: IntoIterator,
        P::Item: Into<Payload>,
    {
        for p in payloads {
            self.payloads.push(p.into());
        }
    }

    /// Finds a payload in this message by `PayloadType`
    pub fn get<'a, C>(&'a self, ty: PayloadType) -> Option<C>
    where
        C: TryFrom<&'a Payload>,
    {
        if let Some(p) = self
            .payloads
            .iter()
            .find(|payload| matches!(payload.ty().assigned(), Some(other) if other == ty))
        {
            TryInto::<C>::try_into(p).ok()
        } else {
            None
        }
    }
}

const HEADER_SIZE: usize = 28;

impl serialize::Serialize for Message {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_slice(&self.spi_i[..]);
        buf.put_slice(&self.spi_r[..]);
        buf.put_u8(self.payloads.first().map(|p| p.ty().into()).unwrap_or(0));
        buf.put_u8(0x20);
        buf.put_u8(self.exchange.into());
        buf.put_u8(self.flags.bits());
        buf.put_u32(self.id);
        buf.put_u32(self.size()?.try_into()?);
        payload::serialize_payloads(&self.payloads, buf)?;
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        HEADER_SIZE
            .checked_add(payload::cumulative_size(&self.payloads)?)
            .ok_or_else(|| anyhow::anyhow!("overflow while calculating message size"))
    }
}

impl serialize::Deserialize for Message {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let mut spi_i: Spi = Default::default();
        buf.try_copy_to_slice(&mut spi_i[..])?;
        let mut spi_r: Spi = Default::default();
        buf.try_copy_to_slice(&mut spi_r[..])?;
        let next_payload_type: Num<u8, PayloadType> = buf.try_get_u8()?.into();
        let _version = buf.try_get_u8()?;
        let exchange: Num<u8, ExchangeType> = buf.try_get_u8()?.into();
        let flags = MessageFlags::from_bits(buf.try_get_u8()?)
            .ok_or_else(|| anyhow::anyhow!("unknown flags"))?;
        let id = buf.try_get_u32()?;
        let _length = buf.try_get_u32()?;
        let payloads = payload::deserialize_payloads(next_payload_type, buf)?;
        Ok(Self {
            spi_i,
            spi_r,
            exchange,
            flags,
            id,
            payloads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    const SPI_I: Spi = [1, 2, 3, 4, 5, 6, 7, 8];
    const SPI_R: Spi = [9, 10, 11, 12, 13, 14, 15, 16];

    fn create_empty() -> Message {
        Message::new(
            &SPI_I,
            &SPI_R,
            ExchangeType::IKE_SA_INIT.into(),
            MessageFlags::I,
            0,
        )
    }

    #[test]
    fn test_empty() {
        let message = create_empty();

        let len = message.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        message
            .serialize(&mut buf)
            .expect("unable to serialize message");

        let message2 = Message::deserialize(&mut &buf[..]).expect("unable to deserialize");
        assert_eq!(message2.spi_i(), message.spi_i());
        assert_eq!(message2.spi_r(), message.spi_r());
        assert_eq!(message2.exchange(), message.exchange());
        assert_eq!(message2.flags(), message.flags());
        assert_eq!(message2.id(), message.id());
        assert!(message2.payloads().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn test_sa_and_ke() {
        let mut message = create_empty();
        let sa = payload::tests::create_sa();
        let ke = payload::tests::create_ke();

        message.add_payloads(Some(Payload::new(
            PayloadType::SA.into(),
            payload::Content::Sa(sa),
            true,
        )));
        message.add_payloads(Some(Payload::new(
            PayloadType::KE.into(),
            payload::Content::Ke(ke),
            true,
        )));

        let len = message.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        message
            .serialize(&mut buf)
            .expect("unable to serialize message");

        let message2 = Message::deserialize(&mut &buf[..]).expect("unable to deserialize");
        assert_eq!(message2.spi_i(), message.spi_i());
        assert_eq!(message2.spi_r(), message.spi_r());
        assert_eq!(message2.exchange(), message.exchange());
        assert_eq!(message2.flags(), message.flags());
        assert_eq!(message2.id(), message.id());
        assert_eq!(message2.payloads().collect::<Vec<_>>().len(), 2);
    }
}
