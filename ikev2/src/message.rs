use anyhow::Result;
use bitflags::bitflags;
use bytes::{Buf, BufMut};

pub mod num;
use num::Num;

pub mod payload;
pub mod proposal;
pub mod serialize;
pub mod transform;

pub type SPI = [u8; 8];

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum Exchange {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37,
}

impl From<Exchange> for u8 {
    fn from(value: Exchange) -> Self {
        value as Self
    }
}

bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct Flags: u8 {
        const R = 1u8 << 5;
        const V = 1u8 << 4;
        const I = 1u8 << 3;
    }
}

pub struct Message {
    spi_i: SPI,
    spi_r: SPI,
    exchange: Num<u8, Exchange>,
    flags: Flags,
    id: u32,
    payloads: Vec<payload::Payload>,
}

impl Message {
    pub fn new(spi_i: SPI, spi_r: SPI, exchange: Num<u8, Exchange>, flags: Flags, id: u32) -> Self {
        Self {
            spi_i,
            spi_r,
            exchange,
            flags,
            id,
            payloads: Default::default(),
        }
    }

    pub fn spi_i(&self) -> &SPI {
        &self.spi_i
    }

    pub fn spi_r(&self) -> &SPI {
        &self.spi_r
    }

    pub fn exchange(&self) -> Num<u8, Exchange> {
        self.exchange
    }

    pub fn flags(&self) -> &Flags {
        &self.flags
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn payloads(&self) -> impl Iterator<Item = &payload::Payload> {
        self.payloads.iter()
    }

    pub fn add_payload(&mut self, payload: payload::Payload) {
        self.payloads.push(payload);
    }
}

const HEADER_SIZE: usize = 28;

impl serialize::Serialize for Message {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        let trailer: Vec<Num<u8, payload::ContentType>> = vec![Num::Unassigned(0); 1];
        let mut types_iter = self
            .payloads
            .iter()
            .map(|p| p.content_type())
            .chain(trailer.into_iter());

        buf.put_slice(&self.spi_i[..]);
        buf.put_slice(&self.spi_r[..]);
        buf.put_u8(types_iter.next().unwrap().into());
        buf.put_u8(0x20);
        buf.put_u8(self.exchange.into());
        buf.put_u8(self.flags.bits() as u8);
        buf.put_u32(self.id);
        buf.put_u32(self.size()?.try_into()?);

        for (payload, next_content_type) in self.payloads.iter().zip(types_iter) {
            payload.serialize(next_content_type, buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let sizes: Result<Vec<_>> = self.payloads.iter().map(|p| p.size()).collect();

        let sizes: Result<Vec<_>> = sizes?
            .iter()
            .map(|s| {
                payload::HEADER_SIZE
                    .checked_add(*s)
                    .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
            })
            .collect();

        sizes?
            .into_iter()
            .try_fold(HEADER_SIZE, |acc, x| acc.checked_add(x))
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum message size"))
    }
}

impl serialize::Deserialize for Message {
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let mut spi_i: SPI = Default::default();
        buf.try_copy_to_slice(&mut spi_i[..])?;
        let mut spi_r: SPI = Default::default();
        buf.try_copy_to_slice(&mut spi_r[..])?;
        let mut content_type: Num<u8, payload::ContentType> = buf.try_get_u8()?.into();
        let _version = buf.try_get_u8()?;
        let exchange: Num<u8, Exchange> = buf.try_get_u8()?.into();
        let flags =
            Flags::from_bits(buf.try_get_u8()?).ok_or_else(|| anyhow::anyhow!("unknown flags"))?;
        let id = buf.try_get_u32()?;
        let _length = buf.try_get_u32()?;
        let mut payloads = Vec::new();
        while buf.has_remaining() {
            let (payload, next_content_type) = payload::Payload::deserialize(content_type, buf)?;
            payloads.push(payload);
            content_type = next_content_type;
        }
        Ok(Box::new(Self {
            spi_i,
            spi_r,
            exchange,
            flags,
            id,
            payloads,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    const SPI_I: SPI = [1, 2, 3, 4, 5, 6, 7, 8];
    const SPI_R: SPI = [9, 10, 11, 12, 13, 14, 15, 16];

    fn create_empty() -> Message {
        Message::new(
            SPI_I.clone(),
            SPI_R.clone(),
            Num::Assigned(Exchange::IKE_SA_INIT),
            Flags::I,
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

        message.add_payload(payload::Payload::new(
            true,
            Num::Assigned(payload::ContentType::SA),
            Box::new(sa),
        ));
        message.add_payload(payload::Payload::new(
            true,
            Num::Assigned(payload::ContentType::KE),
            Box::new(ke),
        ));

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
