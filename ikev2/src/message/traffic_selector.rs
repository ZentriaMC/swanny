use crate::message::{
    num::{Num, TrafficSelectorType},
    serialize,
};
use anyhow::Result;
use bytes::{Buf, BufMut};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub struct TrafficSelector {
    ty: Num<u8, TrafficSelectorType>,
    ip_proto: u8,
    start_port: u16,
    end_port: u16,
    start_address: IpAddr,
    end_address: IpAddr,
}

impl TrafficSelector {
    pub fn new(
        ty: Num<u8, TrafficSelectorType>,
        ip_proto: u8,
        start_address: &IpAddr,
        end_address: &IpAddr,
        start_port: u16,
        end_port: u16,
    ) -> Self {
        Self {
            ty,
            ip_proto,
            start_port,
            end_port,
            start_address: start_address.to_owned(),
            end_address: end_address.to_owned(),
        }
    }

    pub fn ty(&self) -> Num<u8, TrafficSelectorType> {
        self.ty
    }

    pub fn ip_proto(&self) -> u8 {
        self.ip_proto
    }

    pub fn start_port(&self) -> u16 {
        self.start_port
    }

    pub fn end_port(&self) -> u16 {
        self.end_port
    }

    pub fn start_address(&self) -> &IpAddr {
        &self.start_address
    }

    pub fn end_address(&self) -> &IpAddr {
        &self.end_address
    }
}

impl serialize::Serialize for TrafficSelector {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.ty.into());
        buf.put_u8(self.ip_proto);
        buf.put_u16(self.size()?.try_into()?);
        buf.put_u16(self.start_port);
        buf.put_u16(self.end_port);

        let start_address = match self.start_address {
            IpAddr::V4(v4) => v4.to_bits().to_be_bytes().to_vec(),
            IpAddr::V6(v6) => v6.to_bits().to_be_bytes().to_vec(),
        };
        let end_address = match self.end_address {
            IpAddr::V4(v4) => v4.to_bits().to_be_bytes().to_vec(),
            IpAddr::V6(v6) => v6.to_bits().to_be_bytes().to_vec(),
        };

        buf.put_slice(&start_address);
        buf.put_slice(&end_address);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let address_size = match self.ty {
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE) => 4usize,
            Num::Assigned(TrafficSelectorType::TS_IPV6_ADDR_RANGE) => 16usize,
            _ => return Err(anyhow::anyhow!("unknown TS type")),
        };

        8usize
            .checked_add(address_size * 2)
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum TS size"))
    }
}

impl serialize::Deserialize for TrafficSelector {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let ty = buf.try_get_u8()?.into();
        let ip_proto = buf.try_get_u8()?;
        let size: usize = buf.try_get_u16()?.into();
        if size != buf.remaining() + 4usize {
            return Err(anyhow::anyhow!("invalid TS length: {}, {}", size, buf.remaining()));
        }

        let start_port = buf.try_get_u16()?;
        let end_port = buf.try_get_u16()?;
        let (start_address, end_address): (IpAddr, IpAddr) = match ty {
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE) => {
                let mut address = [0; 4];

                buf.try_copy_to_slice(&mut address)?;
                let start_address = address.into();
                buf.try_copy_to_slice(&mut address)?;
                let end_address = address.into();
                (start_address, end_address)
            }
            Num::Assigned(TrafficSelectorType::TS_IPV6_ADDR_RANGE) => {
                let mut address = [0; 16];

                buf.try_copy_to_slice(&mut address)?;
                let start_address = address.into();
                buf.try_copy_to_slice(&mut address)?;
                let end_address = address.into();
                (start_address, end_address)
            }
            _ => return Err(anyhow::anyhow!("unknown TS type")),
        };
        if buf.has_remaining() {
            return Err(anyhow::anyhow!("invalid TS length"));
        }

        Ok(Self {
            ty,
            ip_proto,
            start_port,
            end_port,
            start_address,
            end_address,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;
    use std::net::IpAddr;
    use std::str::FromStr;

    pub(crate) fn create_traffic_selector() -> TrafficSelector {
        let src_address = IpAddr::from_str("192.168.1.2").unwrap();
        TrafficSelector::new(
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE),
            0,
            &src_address,
            &src_address,
            0,
            0,
        )
    }

    #[test]
    fn test_traffic_selector() {
        let traffic_selector = create_traffic_selector();

        let len = traffic_selector
            .size()
            .expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        traffic_selector
            .serialize(&mut buf)
            .expect("unable to serialize traffic selector");

        let traffic_selector2 = TrafficSelector::deserialize(&mut &buf[..])
            .expect("unable to deserialize traffic selector");

        assert_eq!(traffic_selector, traffic_selector2);
    }
}
