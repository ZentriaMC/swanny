#![allow(non_camel_case_types)]

use bitflags::bitflags;
use num_traits::FromPrimitive;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num<P, E>
where
    P: From<E>,
{
    Assigned(E),
    Unassigned(P),
}

struct Primitive<P>(P);

impl<P> Primitive<P> {
    pub fn into_inner(self) -> P {
        self.0
    }
}

impl<P, E> From<Num<P, E>> for Primitive<P>
where
    P: From<E>,
{
    fn from(value: Num<P, E>) -> Self {
        match value {
            Num::Assigned(e) => Primitive(e.into()),
            Num::Unassigned(p) => Primitive(p),
        }
    }
}

impl<E> From<Num<u8, E>> for u8
where
    u8: From<E>,
{
    fn from(value: Num<u8, E>) -> Self {
        Into::<Primitive<u8>>::into(value).into_inner()
    }
}

impl<E> From<Num<u16, E>> for u16
where
    u16: From<E>,
{
    fn from(value: Num<u16, E>) -> Self {
        Into::<Primitive<u16>>::into(value).into_inner()
    }
}

impl<P, E> From<P> for Num<P, E>
where
    E: FromPrimitive,
    P: Copy + From<E> + Into<u64>,
{
    fn from(value: P) -> Self {
        match E::from_u64(value.into()) {
            Some(n) => Num::Assigned(n),
            None => Num::Unassigned(value),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum ExchangeType {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37,
}

impl From<ExchangeType> for u8 {
    fn from(value: ExchangeType) -> Self {
        value as Self
    }
}

bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct MessageFlags: u8 {
        const R = 1u8 << 5;
        const V = 1u8 << 4;
        const I = 1u8 << 3;
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum PayloadType {
    SA = 33,
    KE = 34,
    IDi = 35,
    IDr = 36,
    CERT = 37,
    CERTREQ = 38,
    AUTH = 39,
    NONCE = 40,
    NOTIFY = 41,
    DELETE = 42,
    VENDOR = 43,
    TSi = 44,
    TSr = 45,
    SK = 46,
    CP = 47,
    EAP = 48,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum Protocol {
    IKE = 1,
    AH = 2,
    ESP = 3,
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self {
        value as Self
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum TransformType {
    ENCR = 1,
    PRF = 2,
    INTEG = 3,
    DH = 4,
    ESN = 5,
}

impl From<TransformType> for u8 {
    fn from(value: TransformType) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum EncrId {
    ENCR_DES_IV64 = 1,
    ENCR_DES = 2,
    ENCR_3DES = 3,
    ENCR_RC5 = 4,
    ENCR_IDEA = 5,
    ENCR_CAST = 6,
    ENCR_BLOWFISH = 7,
    ENCR_3IDEA = 8,
    ENCR_DES_IV32 = 9,
    ENCR_NULL = 11,
    ENCR_AES_CBC = 12,
    ENCR_AES_CTR = 13,
}

impl From<EncrId> for u16 {
    fn from(value: EncrId) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum PrfId {
    PRF_HMAC_MD5 = 1,
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_TIGER = 3,
}

impl From<PrfId> for u16 {
    fn from(value: PrfId) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum IntegId {
    NONE = 0,
    AUTH_HMAC_MD5_96 = 1,
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK_MD5 = 4,
    AUTH_AES_XCBC_96 = 5,
}

impl From<IntegId> for u16 {
    fn from(value: IntegId) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum DhId {
    NONE = 0,
    MODP768 = 1,
    MODP1024 = 2,
    MODP1536 = 5,
    MODP2048 = 14,
    MODP3072 = 15,
    MODP4096 = 16,
    MODP6144 = 17,
    MODP8192 = 18,
}

impl From<DhId> for u16 {
    fn from(value: DhId) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum EsnId {
    NoEsn = 0,
    Esn = 1,
}

impl From<EsnId> for u16 {
    fn from(value: EsnId) -> Self {
        value as Self
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum AttributeType {
    KeyLength = 14,
}

impl From<AttributeType> for u16 {
    fn from(value: AttributeType) -> Self {
        value as Self
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum IdType {
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
}

impl From<IdType> for u8 {
    fn from(value: IdType) -> Self {
        value as Self
    }
}
