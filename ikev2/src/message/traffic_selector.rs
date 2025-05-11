use crate::message::{
    num::{Num, TrafficSelectorType},
    serialize,
};
use anyhow::Result;
use bytes::{Buf, BufMut};

#[derive(Clone, Debug, PartialEq)]
pub struct TrafficSelector {
    type_: Num<u8, TrafficSelectorType>,
    ip_proto: u8,
    start_port: u16,
    end_port: u16,
    start_address: Vec<u8>,
    end_address: Vec<u8>,
}

impl TrafficSelector {
    pub fn r#type(&self) -> Num<u8, TrafficSelectorType> {
        self.type_
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

    pub fn start_address(&self) -> &[u8] {
        &self.start_address
    }

    pub fn end_address(&self) -> &[u8] {
        &self.end_address
    }
}

impl serialize::Serialize for TrafficSelector {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.type_.into());
        buf.put_u8(self.ip_proto);
        buf.put_u16(self.size()?.try_into()?);
        buf.put_u16(self.start_port);
        buf.put_u16(self.end_port);
        buf.put_slice(&self.start_address);
        buf.put_slice(&self.end_address);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        8usize
            .checked_add(self.start_address.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum TS size"))?
            .checked_add(self.end_address.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum TS size"))
    }
}

impl serialize::Deserialize for TrafficSelector {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let type_ = buf.try_get_u8()?.into();
        let ip_proto = buf.try_get_u8()?;
        let size: usize = buf.try_get_u16()?.into();
        let start_port = buf.try_get_u16()?;
        let end_port = buf.try_get_u16()?;
        let address_size = match type_ {
            Num::Assigned(TrafficSelectorType::TS_IPV4_ADDR_RANGE) => 4usize,
            Num::Assigned(TrafficSelectorType::TS_IPV6_ADDR_RANGE) => 16usize,
            _ => return Err(anyhow::anyhow!("unknown TS type")),
        };
        if size != 8usize + address_size * 2 {
            return Err(anyhow::anyhow!("invalid TS length"));
        }

        let mut start_address = vec![0; address_size];
        buf.try_copy_to_slice(&mut start_address)?;
        let mut end_address = vec![0; address_size];
        buf.try_copy_to_slice(&mut end_address)?;
        Ok(Self {
            type_,
            ip_proto,
            start_port,
            end_port,
            start_address,
            end_address,
        })
    }
}
