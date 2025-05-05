use crate::message::{
    num::{ContentType, DhId, IdType, Num},
    proposal,
    serialize::{self, Deserialize, Serialize},
};
use anyhow::Result;
use bytes::{Buf, BufMut};

pub const HEADER_SIZE: usize = 4;

impl From<ContentType> for u8 {
    fn from(value: ContentType) -> Self {
        value as Self
    }
}

pub trait Content: Serialize + Deserialize {}

pub struct Payload {
    critical: bool,
    content_type: Num<u8, ContentType>,
    content: Box<dyn Content>,
}

impl Payload {
    pub fn new(
        critical: bool,
        content_type: Num<u8, ContentType>,
        content: Box<dyn Content>,
    ) -> Self {
        Self {
            critical,
            content_type,
            content,
        }
    }

    pub fn content_type(&self) -> Num<u8, ContentType> {
        self.content_type
    }

    pub fn serialize(
        &self,
        next_content_type: Num<u8, ContentType>,
        buf: &mut dyn BufMut,
    ) -> Result<()> {
        buf.put_u8(next_content_type.into());
        buf.put_u8(u8::from(self.critical) * 0x80);
        buf.put_u16(self.size()?.try_into()?);
        self.content.serialize(buf)
    }

    pub fn size(&self) -> Result<usize> {
        4usize
            .checked_add(self.content.size()?)
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
    }

    pub fn deserialize(
        content_type: Num<u8, ContentType>,
        buf: &mut dyn Buf,
    ) -> Result<(Self, Num<u8, ContentType>)>
    where
        Self: Sized,
    {
        let next_content_type: Num<u8, ContentType> = buf.try_get_u8()?.into();
        let critical = (buf.try_get_u8()? & 0x80) != 0;
        let len: usize = buf.try_get_u16()?.try_into()?;
        let len = len
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| anyhow::anyhow!("invalid payload length"))?;

        let content = match content_type {
            Num::Assigned(ContentType::SA) => {
                SA::deserialize(&mut &buf.chunk()[..len])? as Box<dyn Content>
            }
            Num::Assigned(ContentType::KE) => {
                KE::deserialize(&mut &buf.chunk()[..len])? as Box<dyn Content>
            }
            Num::Assigned(ContentType::IDi) | Num::Assigned(ContentType::IDr) => {
                ID::deserialize(&mut &buf.chunk()[..len])? as Box<dyn Content>
            }
            ct => return Err(anyhow::anyhow!("unknown content type {:?}", ct)),
        };
        buf.advance(len);

        Ok((
            Self::new(critical, content_type, content),
            next_content_type,
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct SA {
    proposals: Vec<proposal::Proposal>,
}

impl SA {
    pub fn new(proposals: impl AsRef<[proposal::Proposal]>) -> Self {
        Self {
            proposals: proposals.as_ref().to_vec(),
        }
    }

    pub fn proposals(&self) -> impl Iterator<Item = &proposal::Proposal> {
        self.proposals.iter()
    }
}

impl Content for SA {}

impl serialize::Serialize for SA {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        for (i, proposal) in self.proposals.iter().enumerate() {
            if i == self.proposals.len() - 1 {
                buf.put_u8(0);
            } else {
                buf.put_u8(2);
            }
            buf.put_u8(0);
            let len = proposal::HEADER_SIZE
                .checked_add(proposal.size()?)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))?;
            buf.put_u16(len.try_into()?);
            proposal.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let mut len = 0usize;
        for proposal in &self.proposals {
            len = len
                .checked_add(proposal::HEADER_SIZE)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))?
                .checked_add(proposal.size()?)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))?;
        }
        Ok(len)
    }
}

impl serialize::Deserialize for SA {
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let mut proposals = Vec::new();
        while buf.has_remaining() {
            let _last_substruc = buf.try_get_u8()?;
            let _ = buf.try_get_u8()?;
            let len: usize = buf.try_get_u16()?.try_into()?;
            let len = len
                .checked_sub(proposal::HEADER_SIZE)
                .ok_or_else(|| anyhow::anyhow!("invalid proposal length"))?;
            proposals.push(*proposal::Proposal::deserialize(&mut &buf.chunk()[..len])?);
            buf.advance(len);
        }
        Ok(Box::new(Self::new(proposals)))
    }
}

#[derive(Debug, PartialEq)]
pub struct KE {
    dh_group: Num<u16, DhId>,
    ke_data: Vec<u8>,
}

impl KE {
    pub fn new(dh_group: Num<u16, DhId>, ke_data: impl AsRef<[u8]>) -> Self {
        Self {
            dh_group,
            ke_data: ke_data.as_ref().to_vec(),
        }
    }

    pub fn dh_group(&self) -> Num<u16, DhId> {
        self.dh_group
    }

    pub fn ke_data(&self) -> &[u8] {
        &self.ke_data
    }
}

impl Content for KE {}

impl serialize::Serialize for KE {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u16(self.dh_group.into());
        buf.put_u16(0);
        buf.put_slice(&self.ke_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        4usize
            .checked_add(self.ke_data.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
    }
}

impl serialize::Deserialize for KE {
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let dh_group = buf.try_get_u16()?;
        let _ = buf.try_get_u16()?;
        Ok(Box::new(Self::new(dh_group.into(), buf.chunk())))
    }
}

#[derive(Debug, PartialEq)]
pub struct ID {
    type_: Num<u8, IdType>,
    id_data: Vec<u8>,
}

impl ID {
    pub fn new(type_: Num<u8, IdType>, id_data: impl AsRef<[u8]>) -> Self {
        Self {
            type_,
            id_data: id_data.as_ref().to_vec(),
        }
    }

    pub fn r#type(&self) -> Num<u8, IdType> {
        self.type_
    }

    pub fn id_data(&self) -> &[u8] {
        &self.id_data
    }
}

impl Content for ID {}

impl serialize::Serialize for ID {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.type_.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.id_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        4usize
            .checked_add(self.id_data.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
    }
}

impl serialize::Deserialize for ID {
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let type_ = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Box::new(Self::new(type_.into(), buf.chunk())))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    pub(crate) fn create_sa() -> SA {
        let proposal = proposal::tests::create_proposal();
        SA::new(&[proposal])
    }

    pub(crate) fn create_ke() -> KE {
        const DATA: &'static [u8] = b"key exchange data";
        KE::new(Num::Assigned(DhId::MODP4096), DATA)
    }

    #[test]
    fn test_sa() {
        let sa = create_sa();

        let len = sa.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        sa.serialize(&mut buf).expect("unable to serialize SA");

        let sa2 = SA::deserialize(&mut &buf[..]).expect("unable to deserialize SA");

        assert_eq!(*sa2, sa);
    }

    #[test]
    fn test_ke() {
        let ke = create_ke();

        let len = ke.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        ke.serialize(&mut buf).expect("unable to serialize KE");

        let ke2 = KE::deserialize(&mut &buf[..]).expect("unable to deserialize KE");

        assert_eq!(*ke2, ke);
    }
}
