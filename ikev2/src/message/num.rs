use bitflags::bitflags;
use num_traits::FromPrimitive;

/// A newtype used by `Num` to represent an IANA registered number.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Enum<E>(E);

impl<E> Enum<E> {
    pub fn into_inner(self) -> E {
        self.0
    }
}

impl<E> From<E> for Enum<E> {
    fn from(other: E) -> Self {
        Self(other)
    }
}

/// A newtype used by `Num` to represent a number not in the IANA registry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Primitive<P>(P);

impl<P> Primitive<P> {
    pub fn into_inner(self) -> P {
        self.0
    }
}

impl<P> From<P> for Primitive<P> {
    fn from(other: P) -> Self {
        Self(other)
    }
}

/// Protocol numbers
///
/// The `Num` data strucure is a thin wrapper around integrals used in
/// the IKEv2 wire protocol. Unlike `Option`, it provides a
/// distinction between IANA assigned or unassigned numbers.
///
/// The applications do not usually need to construct `Num`
/// manually. Use `Into` trait from the enum types such as `IdType`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num<P, E>
where
    P: From<E>,
{
    Assigned(Enum<E>),
    Unassigned(Primitive<P>),
}

impl<P, E> Num<P, E>
where
    P: From<E>,
{
    pub fn from_enum(e: E) -> Self {
        Self::Assigned(Enum(e))
    }

    pub fn from_primitive(p: P) -> Self {
        Self::Unassigned(Primitive(p))
    }

    pub fn assigned(self) -> Option<E> {
        match self {
            Self::Assigned(e) => Some(e.into_inner()),
            _ => None,
        }
    }
}

impl<P, E> From<Num<P, E>> for Primitive<P>
where
    P: From<E>,
{
    fn from(value: Num<P, E>) -> Self {
        match value {
            Num::Assigned(e) => Primitive(e.into_inner().into()),
            Num::Unassigned(p) => p,
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
            Some(n) => Num::Assigned(Enum(n)),
            None => Num::Unassigned(Primitive(value)),
        }
    }
}

#[allow(non_camel_case_types)]
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

impl From<ExchangeType> for Num<u8, ExchangeType> {
    fn from(value: ExchangeType) -> Self {
        Num::Assigned(Enum(value))
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq)]
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

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        value as Self
    }
}

impl From<PayloadType> for Num<u8, PayloadType> {
    fn from(value: PayloadType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, FromPrimitive)]
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

impl From<Protocol> for Num<u8, Protocol> {
    fn from(value: Protocol) -> Self {
        Num::Assigned(Enum(value))
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

impl From<TransformType> for Num<u8, TransformType> {
    fn from(value: TransformType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[allow(non_camel_case_types)]
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
    ENCR_AES_CCM_8 = 14,
    ENCR_AES_CCM_12 = 15,
    ENCR_AES_CCM_16 = 16,
    ENCR_AES_GCM_8 = 18,
    ENCR_AES_GCM_12 = 19,
    ENCR_AES_GCM_16 = 20,
}

impl From<EncrId> for u16 {
    fn from(value: EncrId) -> Self {
        value as Self
    }
}

impl From<EncrId> for Num<u16, EncrId> {
    fn from(value: EncrId) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum PrfId {
    PRF_HMAC_MD5 = 1,
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_TIGER = 3,
    PRF_AES128_XCBC = 4,
    PRF_HMAC_SHA2_256 = 5,
    PRF_HMAC_SHA2_384 = 6,
    PRF_HMAC_SHA2_512 = 7,
}

impl From<PrfId> for u16 {
    fn from(value: PrfId) -> Self {
        value as Self
    }
}

impl From<PrfId> for Num<u16, PrfId> {
    fn from(value: PrfId) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum IntegId {
    NONE = 0,
    AUTH_HMAC_MD5_96 = 1,
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK_MD5 = 4,
    AUTH_AES_XCBC_96 = 5,
    AUTH_HMAC_MD5_128 = 6,
    AUTH_HMAC_SHA1_160 = 7,
    AUTH_AES_CMAC_96 = 8,
    AUTH_AES_128_GMAC = 9,
    AUTH_AES_192_GMAC = 10,
    AUTH_AES_256_GMAC = 11,
    AUTH_HMAC_SHA2_256_128 = 12,
    AUTH_HMAC_SHA2_384_192 = 13,
    AUTH_HMAC_SHA2_512_256 = 14,
}

impl From<IntegId> for u16 {
    fn from(value: IntegId) -> Self {
        value as Self
    }
}

impl From<IntegId> for Num<u16, IntegId> {
    fn from(value: IntegId) -> Self {
        Num::Assigned(Enum(value))
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
    SECP256R1 = 19,
    SECP384R1 = 20,
    SECP521R1 = 21,
}

impl From<DhId> for u16 {
    fn from(value: DhId) -> Self {
        value as Self
    }
}

impl From<DhId> for Num<u16, DhId> {
    fn from(value: DhId) -> Self {
        Num::Assigned(Enum(value))
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

impl From<EsnId> for Num<u16, EsnId> {
    fn from(value: EsnId) -> Self {
        Num::Assigned(Enum(value))
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

impl From<AttributeType> for Num<u16, AttributeType> {
    fn from(value: AttributeType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AttributeFormat {
    TV,
    TLV,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransformId {
    Encr(Num<u16, EncrId>),
    Prf(Num<u16, PrfId>),
    Integ(Num<u16, IntegId>),
    Dh(Num<u16, DhId>),
    Esn(Num<u16, EsnId>),
}

impl From<TransformId> for u16 {
    fn from(value: TransformId) -> Self {
        match value {
            TransformId::Encr(id) => id.into(),
            TransformId::Prf(id) => id.into(),
            TransformId::Integ(id) => id.into(),
            TransformId::Dh(id) => id.into(),
            TransformId::Esn(id) => id.into(),
        }
    }
}

impl From<TransformId> for Num<u16, TransformId> {
    fn from(value: TransformId) -> Self {
        Num::Assigned(Enum(value))
    }
}

impl Num<u16, TransformId> {
    pub fn from_u16(ty: Num<u8, TransformType>, value: u16) -> Self {
        match ty.assigned() {
            Some(TransformType::ENCR) => Num::Assigned(TransformId::Encr(value.into()).into()),
            Some(TransformType::PRF) => Num::Assigned(TransformId::Prf(value.into()).into()),
            Some(TransformType::INTEG) => Num::Assigned(TransformId::Integ(value.into()).into()),
            Some(TransformType::DH) => Num::Assigned(TransformId::Dh(value.into()).into()),
            Some(TransformType::ESN) => Num::Assigned(TransformId::Esn(value.into()).into()),
            None => Num::Unassigned(value.into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TryFromTransformIdError {
    #[error("unknown transform ID")]
    UnknownTransformId(Num<u16, TransformId>),
}

macro_rules! emit_transform_id_conversions {
    ( $id:ident, $ce:ident ) => {
        impl TryFrom<TransformId> for $id {
            type Error = TryFromTransformIdError;

            fn try_from(other: TransformId) -> std::result::Result<Self, Self::Error> {
                match other {
                    TransformId::$ce(Num::Assigned(id)) => Ok(id.into_inner()),
                    _ => Err(TryFromTransformIdError::UnknownTransformId(other.into())),
                }
            }
        }

        impl TryFrom<Num<u16, TransformId>> for $id {
            type Error = TryFromTransformIdError;

            fn try_from(other: Num<u16, TransformId>) -> std::result::Result<Self, Self::Error> {
                match other.assigned() {
                    Some(TransformId::$ce(Num::Assigned(id))) => Ok(id.into_inner()),
                    _ => Err(TryFromTransformIdError::UnknownTransformId(other)),
                }
            }
        }

        impl From<$id> for Num<u16, TransformId> {
            fn from(value: $id) -> Self {
                Num::Assigned(Enum(TransformId::$ce(value.into())))
            }
        }
    };
}

emit_transform_id_conversions!(EncrId, Encr);
emit_transform_id_conversions!(PrfId, Prf);
emit_transform_id_conversions!(IntegId, Integ);
emit_transform_id_conversions!(DhId, Dh);
emit_transform_id_conversions!(EsnId, Esn);

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum IdType {
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
    ID_RFC822_ADDR = 3,
    ID_IPV6_ADDR = 5,
    ID_DER_ASN1_DN = 9,
    ID_DER_ASN1_GN = 10,
    ID_KEY_ID = 11,
}

impl From<IdType> for u8 {
    fn from(value: IdType) -> Self {
        value as Self
    }
}

impl From<IdType> for Num<u8, IdType> {
    fn from(value: IdType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum AuthType {
    RSA = 1,
    PSK = 2,
    DSS = 3,
}

impl From<AuthType> for u8 {
    fn from(value: AuthType) -> Self {
        value as Self
    }
}

impl From<AuthType> for Num<u8, AuthType> {
    fn from(value: AuthType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum NotifyType {
    UNSUPPORTED_CRITICAL_PAYLOAD = 1,
    INVALID_IKE_Spi = 4,
    INVALID_MAJOR_VERSION = 5,
    INVALID_SYNTAX = 7,
    INVALID_MESSAGE_ID = 9,
    INVALID_Spi = 11,
    NO_PROPOSAL_CHOSEN = 14,
    INVALID_KE_PAYLOAD = 17,
    AUTHENTICATION_FAILED = 24,
    SINGLE_PAIR_REQUIRED = 34,
    NO_ADDITIONAL_SAS = 35,
    INTERNAL_ADDRESS_FAILURE = 36,
    FAILED_CP_REQUIRED = 37,
    TS_UNACCEPTABLE = 38,
    INVALID_SELECTORS = 39,
    TEMPORARY_FAILURE = 43,
    CHILD_SA_NOT_FOUND = 44,
    INITIAL_CONTACT = 16384,
    SET_WINDOW_SIZE = 16385,
    ADDITIONAL_TS_POSSIBLE = 16386,
    IPCOMP_SUPPORTED = 16387,
    NAT_DETECTION_SOURCE_IP = 16388,
    NAT_DETECTION_DESTINATION_IP = 16389,
    COOKIE = 16390,
    USE_TRANSPORT_MODE = 16391,
    HTTP_CERT_LOOKUP_SUPPORTED = 16392,
    REKEY_SA = 16393,
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
    NON_FIRST_FRAGMENTS_ALSO = 16395,
}

impl From<NotifyType> for u16 {
    fn from(value: NotifyType) -> Self {
        value as Self
    }
}

impl From<NotifyType> for Num<u16, NotifyType> {
    fn from(value: NotifyType) -> Self {
        Num::Assigned(Enum(value))
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum TrafficSelectorType {
    TS_IPV4_ADDR_RANGE = 7,
    TS_IPV6_ADDR_RANGE = 8,
}

impl From<TrafficSelectorType> for u8 {
    fn from(value: TrafficSelectorType) -> Self {
        value as Self
    }
}

impl From<TrafficSelectorType> for Num<u8, TrafficSelectorType> {
    fn from(value: TrafficSelectorType) -> Self {
        Num::Assigned(Enum(value))
    }
}
