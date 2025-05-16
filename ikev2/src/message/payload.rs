use crate::{
    crypto::Cipher,
    message::{
        num::{AuthType, DhId, IdType, NotifyType, Num, PayloadType, Protocol},
        proposal::{self, Proposal},
        serialize::{self, Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
};
use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

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
    Notify(Notify),
    TS(TS),
    SK(SK),
}

impl Serialize for Content {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        match self {
            Content::SA(sa) => sa.serialize(buf),
            Content::KE(ke) => ke.serialize(buf),
            Content::ID(id) => id.serialize(buf),
            Content::Auth(auth) => auth.serialize(buf),
            Content::Nonce(nonce) => nonce.serialize(buf),
            Content::Notify(notify) => notify.serialize(buf),
            Content::TS(ts) => ts.serialize(buf),
            Content::SK(sk) => sk.serialize(buf),
        }
    }

    fn size(&self) -> Result<usize> {
        match self {
            Content::SA(sa) => sa.size(),
            Content::KE(ke) => ke.size(),
            Content::ID(id) => id.size(),
            Content::Auth(auth) => auth.size(),
            Content::Nonce(nonce) => nonce.size(),
            Content::Notify(notify) => notify.size(),
            Content::TS(ts) => ts.size(),
            Content::SK(sk) => sk.size(),
        }
    }
}

#[derive(Debug)]
pub struct Payload {
    critical: bool,
    ty: Num<u8, PayloadType>,
    content: Content,
}

impl Payload {
    pub fn new(ty: Num<u8, PayloadType>, content: Content, critical: bool) -> Self {
        Self {
            ty,
            content,
            critical,
        }
    }

    pub fn ty(&self) -> Num<u8, PayloadType> {
        self.ty
    }

    pub fn content(&self) -> &Content {
        &self.content
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
            Num::Assigned(PayloadType::AUTH) => {
                Content::Auth(Auth::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::NONCE) => {
                Content::Nonce(Nonce::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::NOTIFY) => {
                Content::Notify(Notify::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::IDi | PayloadType::IDr) => {
                Content::ID(ID::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::TSi | PayloadType::TSr) => {
                Content::TS(TS::deserialize(&mut &buf.chunk()[..len])?)
            }
            Num::Assigned(PayloadType::SK) => {
                Content::SK(SK::deserialize(&mut &buf.chunk()[..len])?)
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

macro_rules! create_try_from {
    ( $pe:pat, $ce:ident ) => {
        impl<'a> TryFrom<&'a Payload> for &'a $ce {
            type Error = anyhow::Error;

            fn try_from(other: &'a Payload) -> std::result::Result<Self, Self::Error> {
                match (other.ty(), other.content()) {
                    (Num::Assigned($pe), Content::$ce(content)) => Ok(content),
                    _ => Err(anyhow::anyhow!("unable to convert payload")),
                }
            }
        }
    };
}

create_try_from!(PayloadType::SA, SA);
create_try_from!(PayloadType::KE, KE);
create_try_from!(PayloadType::IDi | PayloadType::IDr, ID);
create_try_from!(PayloadType::AUTH, Auth);
create_try_from!(PayloadType::NONCE, Nonce);
create_try_from!(PayloadType::NOTIFY, Notify);
create_try_from!(PayloadType::TSi | PayloadType::TSr, TS);
create_try_from!(PayloadType::SK, SK);

#[derive(Debug, PartialEq)]
pub struct SA {
    proposals: Vec<Proposal>,
}

impl SA {
    pub fn new<P>(proposals: P) -> Self
    where
        P: IntoIterator,
        P::Item: Into<Proposal>,
    {
        Self {
            proposals: proposals.into_iter().map(Into::into).collect(),
        }
    }

    pub fn proposals(&self) -> impl Iterator<Item = &Proposal> {
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
            proposals.push(Proposal::deserialize(&mut &buf.chunk()[..len])?);
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
    ty: Num<u8, IdType>,
    id_data: Vec<u8>,
}

impl ID {
    pub fn new(ty: Num<u8, IdType>, id_data: impl AsRef<[u8]>) -> Self {
        Self {
            ty,
            id_data: id_data.as_ref().to_vec(),
        }
    }

    pub fn ty(&self) -> Num<u8, IdType> {
        self.ty
    }

    pub fn id_data(&self) -> &[u8] {
        &self.id_data
    }
}

impl serialize::Serialize for ID {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.ty.into());
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
        let ty = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(ty.into(), buf.chunk()))
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

#[derive(Debug, PartialEq)]
pub struct Notify {
    protocol: Num<u8, Protocol>,
    spi: Option<Vec<u8>>,
    ty: Num<u16, NotifyType>,
    notify_data: Vec<u8>,
}

impl Notify {
    pub fn new(
        protocol: Num<u8, Protocol>,
        spi: Option<&[u8]>,
        ty: Num<u16, NotifyType>,
        notify_data: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            protocol,
            spi: spi.map(|spi| spi.as_ref().to_vec()),
            ty,
            notify_data: notify_data.as_ref().to_vec(),
        }
    }

    pub fn protocol(&self) -> Num<u8, Protocol> {
        self.protocol
    }

    pub fn spi(&self) -> Option<&[u8]> {
        self.spi.as_deref()
    }

    pub fn ty(&self) -> Num<u16, NotifyType> {
        self.ty
    }

    pub fn notify_data(&self) -> &[u8] {
        &self.notify_data
    }
}

impl serialize::Serialize for Notify {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.protocol.into());
        if let Some(ref spi) = self.spi {
            buf.put_u8(spi.len().try_into()?);
        } else {
            buf.put_u8(0);
        }
        buf.put_u16(self.ty.into());
        if let Some(ref spi) = self.spi {
            buf.put_slice(spi);
        }
        buf.put_slice(&self.notify_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        4usize
            .checked_add(self.spi.as_ref().map(|spi| spi.len()).unwrap_or(0))
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))?
            .checked_add(self.notify_data.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
    }
}

impl serialize::Deserialize for Notify {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let protocol = buf.try_get_u8()?;
        let spi_len: usize = buf.try_get_u8()?.into();
        let ty = buf.try_get_u16()?;
        let spi = if spi_len > 0 {
            Some(&buf.chunk()[..spi_len])
        } else {
            None
        };
        Ok(Self::new(
            protocol.into(),
            spi,
            ty.into(),
            &buf.chunk()[spi_len..],
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct TS {
    traffic_selectors: Vec<TrafficSelector>,
}

impl TS {
    pub fn new<T>(traffic_selectors: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<TrafficSelector>,
    {
        Self {
            traffic_selectors: traffic_selectors.into_iter().map(Into::into).collect(),
        }
    }

    pub fn traffic_selectors(&self) -> impl Iterator<Item = &TrafficSelector> {
        self.traffic_selectors.iter()
    }
}

impl serialize::Serialize for TS {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.traffic_selectors.len().try_into()?);
        buf.put_u8(0);
        buf.put_u16(0);
        for traffic_selector in &self.traffic_selectors {
            traffic_selector.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let mut len = 0usize;
        for traffic_selector in &self.traffic_selectors {
            len = len
                .checked_add(traffic_selector.size()?)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))?;
        }
        Ok(len)
    }
}

impl serialize::Deserialize for TS {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let count = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;

        let mut traffic_selectors = Vec::new();
        for _ in 0..count {
            let traffic_selector = TrafficSelector::deserialize(&mut buf.chunk())?;
            buf.advance(traffic_selector.size()?);
            traffic_selectors.push(traffic_selector);
        }
        if buf.has_remaining() {
            return Err(anyhow::anyhow!("payload with extra data"));
        }
        Ok(Self::new(traffic_selectors))
    }
}

#[derive(Debug, PartialEq)]
pub struct SK {
    ciphertext: Vec<u8>,
}

pub fn serialize_payloads<'a>(
    payloads: impl IntoIterator<Item = &'a Payload>,
    buf: &mut dyn BufMut,
) -> Result<()> {
    let payloads: Vec<_> = payloads.into_iter().collect();
    let trailer: Vec<Num<u8, PayloadType>> = vec![Num::Unassigned(0); 1];
    let mut next_types = payloads.iter().map(|p| p.ty()).chain(trailer);
    let _ = next_types.next();
    for (payload, next_type) in payloads.iter().zip(next_types) {
        payload.serialize(next_type, buf)?;
    }
    Ok(())
}

pub fn deserialize_payloads(
    mut payload_type: Num<u8, PayloadType>,
    buf: &mut dyn Buf,
) -> Result<Vec<Payload>> {
    let mut payloads = Vec::new();
    while buf.has_remaining() {
        let (payload, next_type) = Payload::deserialize(payload_type, buf)?;
        payloads.push(payload);
        payload_type = next_type;
    }
    Ok(payloads)
}

pub fn cumulative_size<'a>(payloads: impl IntoIterator<Item = &'a Payload>) -> Result<usize> {
    let sizes: Result<Vec<_>> = payloads.into_iter().map(|p| p.size()).collect();

    let sizes: Result<Vec<_>> = sizes?
        .iter()
        .map(|s| {
            HEADER_SIZE
                .checked_add(*s)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum payload size"))
        })
        .collect();

    sizes?
        .into_iter()
        .try_fold(HEADER_SIZE, |acc, x| acc.checked_add(x))
        .ok_or_else(|| anyhow::anyhow!("exceeded maximum message size"))
}

impl SK {
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Self {
        Self {
            ciphertext: ciphertext.as_ref().to_owned(),
        }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn encrypt<'a>(
        cipher: &Cipher,
        key: impl AsRef<[u8]>,
        payloads: impl IntoIterator<Item = &'a Payload>,
    ) -> Result<Self> {
        let payloads: Vec<_> = payloads.into_iter().collect();
        let mut plaintext = BytesMut::with_capacity(cumulative_size(payloads.clone())?);
        serialize_payloads(payloads, &mut plaintext)?;
        let ciphertext = cipher.encrypt(key, plaintext)?;
        Ok(Self { ciphertext })
    }

    pub fn decrypt(
        &self,
        cipher: &Cipher,
        key: impl AsRef<[u8]>,
        mut payload_type: Num<u8, PayloadType>,
    ) -> Result<Vec<Payload>> {
        let plaintext = cipher.decrypt(key, &self.ciphertext)?;
        let mut plaintext = plaintext.as_slice();
        let mut payloads = Vec::new();
        while plaintext.has_remaining() {
            let (payload, next_payload_type) = Payload::deserialize(payload_type, &mut plaintext)?;
            payloads.push(payload);
            payload_type = next_payload_type;
        }
        Ok(payloads)
    }
}

impl serialize::Serialize for SK {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_slice(&self.ciphertext[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        Ok(self.ciphertext.len())
    }
}

impl serialize::Deserialize for SK {
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
        SA::new(Some(proposal))
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
