use crate::message::{
    num::{DhId, IdType, Num, PayloadType, AuthType},
    proposal,
    serialize::{self, Deserialize, Serialize},
};
use anyhow::Result;
use bytes::{Buf, BufMut};

pub const HEADER_SIZE: usize = 4;

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        value as Self
    }
}

#[derive(Debug)]
pub enum Content {
    SA(SA),
    KE(KE),
    ID(ID),
    Auth(Auth),
    Nonce(Nonce),
}

impl Serialize for Content {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        match self {
            Content::SA(sa) => sa.serialize(buf),
            Content::KE(ke) => ke.serialize(buf),
            Content::ID(id) => id.serialize(buf),
            Content::Auth(auth) => auth.serialize(buf),
            Content::Nonce(nonce) => nonce.serialize(buf),
        }
    }

    fn size(&self) -> Result<usize> {
        match self {
            Content::SA(sa) => sa.size(),
            Content::KE(ke) => ke.size(),
            Content::ID(id) => id.size(),
            Content::Auth(auth) => auth.size(),
            Content::Nonce(nonce) => nonce.size(),
        }
    }
}

pub struct Payload {
    critical: bool,
    type_: Num<u8, PayloadType>,
    content: Content,
}

impl Payload {
    pub fn new(type_: Num<u8, PayloadType>, content: Content, critical: bool) -> Self {
        Self {
            type_,
            content,
            critical,
        }
    }

    pub fn r#type(&self) -> Num<u8, PayloadType> {
        self.type_
    }

    pub fn serialize(
        &self,
        next_payload_type: Num<u8, PayloadType>,
        buf: &mut dyn BufMut,
    ) -> Result<()> {
        buf.put_u8(next_payload_type.into());
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
        payload_type: Num<u8, PayloadType>,
        buf: &mut dyn Buf,
    ) -> Result<(Self, Num<u8, PayloadType>)>
    where
        Self: Sized,
    {
        let next_payload_type: Num<u8, PayloadType> = buf.try_get_u8()?.into();
        let critical = (buf.try_get_u8()? & 0x80) != 0;
        let len: usize = buf.try_get_u16()?.into();
        let len = len
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| anyhow::anyhow!("invalid payload length"))?;

        let content = match payload_type {
            Num::Assigned(PayloadType::SA) => {
                Content::SA(SA::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::KE) => {
                Content::KE(KE::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::IDi) | Num::Assigned(PayloadType::IDr) => {
                Content::ID(ID::deserialize(&mut &buf.chunk()[..len])?)
            }
            ct => return Err(anyhow::anyhow!("unknown content type {:?}", ct)),
        };
        buf.advance(len);

        Ok((
            Self::new(payload_type, content, critical),
            next_payload_type,
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
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let mut proposals = Vec::new();
        while buf.has_remaining() {
            let _last_substruc = buf.try_get_u8()?;
            let _ = buf.try_get_u8()?;
            let len: usize = buf.try_get_u16()?.into();
            let len = len
                .checked_sub(proposal::HEADER_SIZE)
                .ok_or_else(|| anyhow::anyhow!("invalid proposal length"))?;
            proposals.push(proposal::Proposal::deserialize(&mut &buf.chunk()[..len])?);
            buf.advance(len);
        }
        Ok(Self::new(proposals))
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
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let dh_group = buf.try_get_u16()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(dh_group.into(), buf.chunk()))
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
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let type_ = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(type_.into(), buf.chunk()))
    }
}

#[derive(Debug, PartialEq)]
pub struct Auth {
    method: Num<u8, AuthType>,
    auth_data: Vec<u8>,
}

impl Auth {
    pub fn new(method: Num<u8, AuthType>, auth_data: impl AsRef<[u8]>) -> Self {
        Self {
            method,
            auth_data: auth_data.as_ref().to_vec(),
        }
    }

    pub fn method(&self) -> Num<u8, AuthType> {
        self.method
    }

    pub fn auth_data(&self) -> &[u8] {
        &self.auth_data
    }
}

impl serialize::Serialize for Auth {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.method.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.auth_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        4usize
            .checked_add(self.auth_data.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
    }
}

impl serialize::Deserialize for Auth {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let method = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(method.into(), buf.chunk()))
    }
}

#[derive(Debug, PartialEq)]
pub struct Nonce {
    nonce: Vec<u8>,
}

impl Nonce {
    pub fn new(nonce: impl AsRef<[u8]>) -> Self {
        Self {
            nonce: nonce.as_ref().to_vec(),
        }
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl serialize::Serialize for Nonce {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_slice(&self.nonce[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        Ok(self.nonce.len())
    }
}

impl serialize::Deserialize for Nonce {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::new(buf.chunk()))
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

        assert_eq!(sa2, sa);
    }

    #[test]
    fn test_ke() {
        let ke = create_ke();

        let len = ke.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        ke.serialize(&mut buf).expect("unable to serialize KE");

        let ke2 = KE::deserialize(&mut &buf[..]).expect("unable to deserialize KE");

        assert_eq!(ke2, ke);
    }
}
