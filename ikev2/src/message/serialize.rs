use crate::{
    crypto,
    message::{Num, PayloadType, TrafficSelectorType, payload::TryFromPayloadError},
};
use bytes::{Buf, BufMut};

#[derive(Debug, thiserror::Error)]
pub enum SerializeError {
    #[error("integer conversion error")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("integer overflow")]
    Overflow,

    #[error("unknown traffic selector type")]
    UnknownTrafficSelectorType(Num<u8, TrafficSelectorType>),

    #[error("cryptographic error")]
    Crypto(#[from] crypto::CryptoError),
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    #[error("integer conversion error")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("the data is not available in the buffer")]
    TryGetError(#[from] bytes::TryGetError),

    #[error("slice to array conversion error")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("premature EOF")]
    PrematureEof,

    #[error("extra data after EOF")]
    Overlong,

    #[error("integer underflow")]
    Underflow,

    #[error("unknown payload type")]
    UnknownPayloadType(Num<u8, PayloadType>),

    #[error("unknown traffic selector type")]
    UnknownTrafficSelectorType(Num<u8, TrafficSelectorType>),

    #[error("invalid traffic selector range")]
    InvalidTrafficSelectorRange,

    #[error("unknown IKE version")]
    UnknownVersion(u8),

    #[error("unknown bits are set in message flags")]
    UnknownMessageFlags(u8),

    #[error("payload conversion error")]
    TryFromPayload(#[from] TryFromPayloadError),

    #[error("encrypted payload is expected but missing")]
    MissingEncryptedPayload,

    #[error("cryptographic error")]
    Crypto(#[from] crypto::CryptoError),
}

pub trait Serialize {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), SerializeError>;
    fn size(&self) -> Result<usize, SerializeError>;
}

pub trait Deserialize {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, DeserializeError>
    where
        Self: Sized;
}
