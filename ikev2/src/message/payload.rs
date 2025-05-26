use crate::{
    crypto::{self, Cipher, Key, Prf},
    message::{
        num::{AuthType, DhId, IdType, NotifyType, Num, PayloadType, Protocol},
        proposal::{self, Proposal},
        serialize::{self, Deserialize, Serialize},
        traffic_selector::TrafficSelector,
    },
};
use bytes::{Buf, BufMut, BytesMut};

pub(crate) const HEADER_SIZE: usize = 4;

/// Content variants
#[derive(Debug)]
pub enum Content {
    Sa(Sa),
    Ke(Ke),
    Id(Id),
    Auth(Auth),
    Nonce(Nonce),
    Notify(Notify),
    Ts(Ts),
    Sk(Sk),
}

impl Serialize for Content {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        match self {
            Content::Sa(sa) => sa.serialize(buf),
            Content::Ke(ke) => ke.serialize(buf),
            Content::Id(id) => id.serialize(buf),
            Content::Auth(auth) => auth.serialize(buf),
            Content::Nonce(nonce) => nonce.serialize(buf),
            Content::Notify(notify) => notify.serialize(buf),
            Content::Ts(ts) => ts.serialize(buf),
            Content::Sk(sk) => sk.serialize(buf),
        }
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        match self {
            Content::Sa(sa) => sa.size(),
            Content::Ke(ke) => ke.size(),
            Content::Id(id) => id.size(),
            Content::Auth(auth) => auth.size(),
            Content::Nonce(nonce) => nonce.size(),
            Content::Notify(notify) => notify.size(),
            Content::Ts(ts) => ts.size(),
            Content::Sk(sk) => sk.size(),
        }
    }
}

/// Message payload
///
/// A message payload contains a generic payload headerr followed by a
/// [`Content`] variant.
///
/// [`Content`]: crate::message::payload::Content
///
#[derive(Debug)]
pub struct Payload {
    critical: bool,
    ty: Num<u8, PayloadType>,
    content: Content,
}

impl Payload {
    /// Creates a new `Payload` with given type and content variant
    pub fn new(ty: Num<u8, PayloadType>, content: Content, critical: bool) -> Self {
        Self {
            ty,
            content,
            critical,
        }
    }

    /// Returns the payload type
    pub fn ty(&self) -> Num<u8, PayloadType> {
        self.ty
    }

    /// Returns the content variant
    pub fn content(&self) -> &Content {
        &self.content
    }

    /// Serializes the payload, taking into account of the next payload type
    pub fn serialize(
        &self,
        next_payload_type: Num<u8, PayloadType>,
        buf: &mut dyn BufMut,
    ) -> Result<(), serialize::SerializeError> {
        buf.put_u8(next_payload_type.into());
        buf.put_u8(u8::from(self.critical) * 0x80);
        buf.put_u16(self.size()?.try_into()?);
        self.content.serialize(buf)
    }

    /// Returns the size of serialized payload
    pub fn size(&self) -> Result<usize, serialize::SerializeError> {
        HEADER_SIZE
            .checked_add(self.content.size()?)
            .ok_or(serialize::SerializeError::Overflow)
    }

    /// Deserializes `buf` as a payload with given type
    pub fn deserialize(
        payload_type: Num<u8, PayloadType>,
        buf: &mut dyn Buf,
    ) -> Result<(Self, Num<u8, PayloadType>), serialize::DeserializeError>
    where
        Self: Sized,
    {
        let next_payload_type: Num<u8, PayloadType> = buf.try_get_u8()?.into();
        let critical = (buf.try_get_u8()? & 0x80) != 0;
        let len: usize = buf.try_get_u16()?.into();
        let len = len
            .checked_sub(HEADER_SIZE)
            .ok_or(serialize::DeserializeError::Underflow)?;
        if len > buf.remaining() {
            return Err(serialize::DeserializeError::PrematureEof);
        }

        let content = match payload_type.assigned() {
            Some(PayloadType::SA) => Content::Sa(Sa::deserialize(&mut &buf.chunk()[..len])?),
            Some(PayloadType::KE) => Content::Ke(Ke::deserialize(&mut &buf.chunk()[..len])?),
            Some(PayloadType::AUTH) => Content::Auth(Auth::deserialize(&mut &buf.chunk()[..len])?),
            Some(PayloadType::NONCE) => {
                Content::Nonce(Nonce::deserialize(&mut &buf.chunk()[..len])?)
            }
            Some(PayloadType::NOTIFY) => {
                Content::Notify(Notify::deserialize(&mut &buf.chunk()[..len])?)
            }
            Some(PayloadType::IDi | PayloadType::IDr) => {
                Content::Id(Id::deserialize(&mut &buf.chunk()[..len])?)
            }
            Some(PayloadType::TSi | PayloadType::TSr) => {
                Content::Ts(Ts::deserialize(&mut &buf.chunk()[..len])?)
            }
            Some(PayloadType::SK) => Content::Sk(Sk::deserialize(
                next_payload_type,
                &mut &buf.chunk()[..len],
            )?),
            _ => {
                return Err(serialize::DeserializeError::UnknownPayloadType(
                    payload_type,
                ));
            }
        };
        buf.advance(len);

        Ok((
            Self::new(payload_type, content, critical),
            next_payload_type,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TryFromPayloadError {
    #[error("unknown payload type")]
    UnknownPayloadType(Num<u8, PayloadType>),
}

macro_rules! emit_try_from_payload {
    ( $pe:pat, $ce:ident ) => {
        impl<'a> TryFrom<&'a Payload> for &'a $ce {
            type Error = TryFromPayloadError;

            fn try_from(other: &'a Payload) -> Result<Self, Self::Error> {
                match (other.ty().assigned(), other.content()) {
                    (Some($pe), Content::$ce(content)) => Ok(content),
                    _ => Err(TryFromPayloadError::UnknownPayloadType(other.ty())),
                }
            }
        }
    };
}

emit_try_from_payload!(PayloadType::SA, Sa);
emit_try_from_payload!(PayloadType::KE, Ke);
emit_try_from_payload!(PayloadType::IDi | PayloadType::IDr, Id);
emit_try_from_payload!(PayloadType::AUTH, Auth);
emit_try_from_payload!(PayloadType::NONCE, Nonce);
emit_try_from_payload!(PayloadType::NOTIFY, Notify);
emit_try_from_payload!(PayloadType::TSi | PayloadType::TSr, Ts);
emit_try_from_payload!(PayloadType::SK, Sk);

/// Security Association content
#[derive(Debug, PartialEq)]
pub struct Sa {
    proposals: Vec<Proposal>,
}

impl Sa {
    /// Creates a new `Sa` content with given cryptographic proposals
    pub fn new<P>(proposals: P) -> Self
    where
        P: IntoIterator,
        P::Item: Into<Proposal>,
    {
        Self {
            proposals: proposals.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns an iterator over the cryptographic proposals in the `Sa` content
    pub fn proposals(&self) -> impl Iterator<Item = &Proposal> {
        self.proposals.iter()
    }
}

impl serialize::Serialize for Sa {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        for (i, proposal) in self.proposals.iter().enumerate() {
            if i == self.proposals.len() - 1 {
                buf.put_u8(0);
            } else {
                buf.put_u8(2);
            }
            buf.put_u8(0);
            let len = proposal::HEADER_SIZE
                .checked_add(proposal.size()?)
                .ok_or(serialize::SerializeError::Overflow)?;
            buf.put_u16(len.try_into()?);
            proposal.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        let mut len = 0usize;
        for proposal in &self.proposals {
            len = len
                .checked_add(proposal::HEADER_SIZE)
                .ok_or(serialize::SerializeError::Overflow)?
                .checked_add(proposal.size()?)
                .ok_or(serialize::SerializeError::Overflow)?;
        }
        Ok(len)
    }
}

impl serialize::Deserialize for Sa {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
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
                .ok_or(serialize::DeserializeError::Underflow)?;
            proposals.push(Proposal::deserialize(&mut &buf.chunk()[..len])?);
            buf.advance(len);
        }
        Ok(Self::new(proposals))
    }
}

/// Key Exchange content
#[derive(Debug, PartialEq)]
pub struct Ke {
    dh_group: Num<u16, DhId>,
    ke_data: Vec<u8>,
}

impl Ke {
    /// Creates a new `Ke` content, with a given group and associated data
    pub fn new(dh_group: Num<u16, DhId>, ke_data: impl AsRef<[u8]>) -> Self {
        Self {
            dh_group,
            ke_data: ke_data.as_ref().to_vec(),
        }
    }

    /// Returns the group ID of the `Ke` content
    pub fn dh_group(&self) -> Num<u16, DhId> {
        self.dh_group
    }

    /// Returns the data associated with the `Ke` content
    pub fn ke_data(&self) -> &[u8] {
        &self.ke_data
    }
}

impl serialize::Serialize for Ke {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_u16(self.dh_group.into());
        buf.put_u16(0);
        buf.put_slice(&self.ke_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        4usize
            .checked_add(self.ke_data.len())
            .ok_or(serialize::SerializeError::Overflow)
    }
}

impl serialize::Deserialize for Ke {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        let dh_group = buf.try_get_u16()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(dh_group.into(), buf.chunk()))
    }
}

/// Identification content
#[derive(Clone, Debug, PartialEq)]
pub struct Id {
    ty: Num<u8, IdType>,
    id_data: Vec<u8>,
}

impl Id {
    /// Creates a new `Id` content with given type and data
    pub fn new(ty: Num<u8, IdType>, id_data: impl AsRef<[u8]>) -> Self {
        Self {
            ty,
            id_data: id_data.as_ref().to_vec(),
        }
    }

    /// Returns the type of the `Id` content
    pub fn ty(&self) -> Num<u8, IdType> {
        self.ty
    }

    /// Returns the identification data associated with the `Id` content
    pub fn id_data(&self) -> &[u8] {
        &self.id_data
    }
}

impl serialize::Serialize for Id {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_u8(self.ty.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.id_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        4usize
            .checked_add(self.id_data.len())
            .ok_or(serialize::SerializeError::Overflow)
    }
}

impl serialize::Deserialize for Id {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        let ty = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(ty.into(), buf.chunk()))
    }
}

/// Authentication content
#[derive(Debug, PartialEq)]
pub struct Auth {
    method: Num<u8, AuthType>,
    auth_data: Vec<u8>,
}

impl Auth {
    const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

    /// Creats a new `Auth` content with given method and data
    pub fn new(method: Num<u8, AuthType>, auth_data: impl AsRef<[u8]>) -> Self {
        Self {
            method,
            auth_data: auth_data.as_ref().to_vec(),
        }
    }

    /// Returns the authentication method of the `Auth` content
    pub fn method(&self) -> Num<u8, AuthType> {
        self.method
    }

    /// Returns the authentication data associated with the `Auth` content
    pub fn auth_data(&self) -> &[u8] {
        &self.auth_data
    }

    /// Creates an `Auth` content by signing data with PSK
    pub fn sign_with_psk(
        prf: &Prf,
        psk: &Key,
        data: impl AsRef<[u8]>,
    ) -> Result<Self, crypto::CryptoError> {
        Ok(Self::new(
            AuthType::PSK.into(),
            prf.prf(&Key::new(prf.prf(psk, Self::KEY_PAD)?), data)?,
        ))
    }

    pub fn verify_with_psk(
        &self,
        prf: &Prf,
        psk: &Key,
        data: impl AsRef<[u8]>,
    ) -> Result<bool, crypto::CryptoError> {
        prf.verify(
            &Key::new(prf.prf(psk, Self::KEY_PAD)?),
            data,
            &self.auth_data,
        )
    }
}

impl serialize::Serialize for Auth {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_u8(self.method.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.auth_data[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        4usize
            .checked_add(self.auth_data.len())
            .ok_or(serialize::SerializeError::Overflow)
    }
}

impl serialize::Deserialize for Auth {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        let method = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;
        Ok(Self::new(method.into(), buf.chunk()))
    }
}

/// Nonce content
#[derive(Debug, PartialEq)]
pub struct Nonce {
    nonce: Vec<u8>,
}

impl Nonce {
    /// Creates a new `Nonce` content
    pub fn new(nonce: impl AsRef<[u8]>) -> Self {
        Self {
            nonce: nonce.as_ref().to_vec(),
        }
    }

    /// Returns the nonce value of the `Nonce` content
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl serialize::Serialize for Nonce {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_slice(&self.nonce[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        Ok(self.nonce.len())
    }
}

impl serialize::Deserialize for Nonce {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        Ok(Self::new(buf.chunk()))
    }
}

/// Notify content
#[derive(Debug, PartialEq)]
pub struct Notify {
    protocol: Num<u8, Protocol>,
    spi: Option<Vec<u8>>,
    ty: Num<u16, NotifyType>,
    notify_data: Vec<u8>,
}

impl Notify {
    /// Creates a new `Notify` content
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

    /// Returns the protocol of the `Notify` content
    pub fn protocol(&self) -> Num<u8, Protocol> {
        self.protocol
    }

    /// Returns the SPI of the `Notify` content
    pub fn spi(&self) -> Option<&[u8]> {
        self.spi.as_deref()
    }

    /// Returns the notification type of the `Notify` content
    pub fn ty(&self) -> Num<u16, NotifyType> {
        self.ty
    }

    /// Returns the notification data of the `Notify` content
    pub fn notify_data(&self) -> &[u8] {
        &self.notify_data
    }
}

impl serialize::Serialize for Notify {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
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

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        4usize
            .checked_add(self.spi.as_ref().map(|spi| spi.len()).unwrap_or(0))
            .ok_or(serialize::SerializeError::Overflow)?
            .checked_add(self.notify_data.len())
            .ok_or(serialize::SerializeError::Overflow)
    }
}

impl serialize::Deserialize for Notify {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
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

/// Traffic Selector content
#[derive(Debug, PartialEq)]
pub struct Ts {
    traffic_selectors: Vec<TrafficSelector>,
}

impl Ts {
    /// Creates a new `Ts` content with given traffic selectors
    pub fn new<T>(traffic_selectors: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<TrafficSelector>,
    {
        Self {
            traffic_selectors: traffic_selectors.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns the iterator over the traffic selectors in the `Ts` content
    pub fn traffic_selectors(&self) -> impl Iterator<Item = &TrafficSelector> {
        self.traffic_selectors.iter()
    }
}

impl serialize::Serialize for Ts {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_u8(self.traffic_selectors.len().try_into()?);
        buf.put_u8(0);
        buf.put_u16(0);
        for traffic_selector in &self.traffic_selectors {
            traffic_selector.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        let mut len = 4usize;
        for traffic_selector in &self.traffic_selectors {
            len = len
                .checked_add(traffic_selector.size()?)
                .ok_or(serialize::SerializeError::Overflow)?;
        }
        Ok(len)
    }
}

impl serialize::Deserialize for Ts {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        let count = buf.try_get_u8()?;
        let _ = buf.try_get_u8()?;
        let _ = buf.try_get_u16()?;

        let mut traffic_selectors = Vec::new();
        for _ in 0..count {
            let traffic_selector = TrafficSelector::deserialize(buf)?;
            traffic_selectors.push(traffic_selector);
        }
        if buf.has_remaining() {
            return Err(serialize::DeserializeError::Overlong);
        }
        Ok(Self::new(traffic_selectors))
    }
}

/// Encrypted content
#[derive(Debug, PartialEq)]
pub struct Sk {
    ciphertext: Vec<u8>,
    inner: Num<u8, PayloadType>,
}

impl Sk {
    /// Creates a new `Sk` content with given ciphertext and the type of the first inner payload
    pub fn new(ciphertext: impl AsRef<[u8]>, inner: Num<u8, PayloadType>) -> Self {
        Self {
            ciphertext: ciphertext.as_ref().to_owned(),
            inner,
        }
    }

    /// Returns the ciphertext of the `Sk` content
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encrypts payloads with given cipher and key, creates a new `Sk` content
    pub fn encrypt<'a>(
        cipher: &Cipher,
        key: &Key,
        payloads: impl IntoIterator<Item = &'a Payload>,
    ) -> Result<Self, serialize::SerializeError> {
        let payloads: Vec<_> = payloads.into_iter().collect();
        let inner = payloads.first().map(|p| p.ty()).unwrap_or(0.into());
        let mut plaintext = BytesMut::with_capacity(cumulative_size(payloads.clone())?);
        serialize_payloads(payloads, &mut plaintext)?;
        let ciphertext = cipher.encrypt(key, &plaintext)?;
        Ok(Self { ciphertext, inner })
    }

    /// Decrypts payloads from the ciphertext of the `Sk` content
    pub fn decrypt(
        &self,
        cipher: &Cipher,
        key: &Key,
    ) -> Result<Vec<Payload>, serialize::DeserializeError> {
        let plaintext = cipher.decrypt(key, &self.ciphertext)?;
        let mut payload_type: Num<u8, PayloadType> = self.inner;
        let mut plaintext = plaintext.as_slice();
        let mut payloads = Vec::new();
        while plaintext.has_remaining() {
            let (payload, next_payload_type) = Payload::deserialize(payload_type, &mut plaintext)?;
            payloads.push(payload);
            payload_type = next_payload_type;
        }
        Ok(payloads)
    }

    /// Deserializes `buf` as an `Sk` content with given type
    pub fn deserialize(
        payload_type: Num<u8, PayloadType>,
        buf: &mut dyn Buf,
    ) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        Ok(Self::new(buf.chunk(), payload_type))
    }
}

impl serialize::Serialize for Sk {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_slice(&self.ciphertext[..]);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        Ok(self.ciphertext.len())
    }
}

pub(crate) fn serialize_payloads<'a>(
    payloads: impl IntoIterator<Item = &'a Payload>,
    buf: &mut dyn BufMut,
) -> Result<(), serialize::SerializeError> {
    let payloads: Vec<_> = payloads.into_iter().collect();
    let last = payloads.last().map(|p| match p.ty().assigned() {
        Some(PayloadType::SK) => Some(p.content()),
        _ => None,
    });
    let trailer = if let Some(Some(Content::Sk(sk))) = last {
        sk.inner
    } else {
        0.into()
    };
    let trailer: Vec<Num<u8, PayloadType>> = vec![trailer; 1];
    let mut next_types = payloads.iter().map(|p| p.ty()).chain(trailer);
    let _ = next_types.next();
    for (payload, next_type) in payloads.iter().zip(next_types) {
        payload.serialize(next_type, buf)?;
    }
    Ok(())
}

pub(crate) fn deserialize_payloads(
    mut payload_type: Num<u8, PayloadType>,
    buf: &mut dyn Buf,
) -> Result<Vec<Payload>, serialize::DeserializeError> {
    let mut payloads = Vec::new();
    while buf.has_remaining() {
        let (payload, next_type) = Payload::deserialize(payload_type, buf)?;
        payloads.push(payload);
        if let Some(PayloadType::SK) = payload_type.assigned() {
            break;
        }
        payload_type = next_type;
    }
    Ok(payloads)
}

pub(crate) fn cumulative_size<'a>(
    payloads: impl IntoIterator<Item = &'a Payload>,
) -> Result<usize, serialize::SerializeError> {
    let sizes: Result<Vec<_>, _> = payloads.into_iter().map(|p| p.size()).collect();

    sizes?
        .into_iter()
        .try_fold(0usize, |acc, x| acc.checked_add(x))
        .ok_or(serialize::SerializeError::Overflow)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    pub(crate) fn create_sa() -> Sa {
        let proposal = proposal::tests::create_proposal();
        Sa::new(Some(proposal))
    }

    pub(crate) fn create_ke() -> Ke {
        const DATA: &'static [u8] = b"key exchange data";
        Ke::new(DhId::MODP4096.into(), DATA)
    }

    #[test]
    fn test_sa() {
        let sa = create_sa();

        let len = sa.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        sa.serialize(&mut buf).expect("unable to serialize SA");

        let sa2 = Sa::deserialize(&mut &buf[..]).expect("unable to deserialize SA");

        assert_eq!(sa2, sa);
    }

    #[test]
    fn test_ke() {
        let ke = create_ke();

        let len = ke.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        ke.serialize(&mut buf).expect("unable to serialize KE");

        let ke2 = Ke::deserialize(&mut &buf[..]).expect("unable to deserialize KE");

        assert_eq!(ke2, ke);
    }
}
