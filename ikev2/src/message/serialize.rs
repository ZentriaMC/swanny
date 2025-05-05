use anyhow::Result;
use bytes::{Buf, BufMut};

pub trait Serialize {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()>;
    fn size(&self) -> Result<usize>;
}

pub trait Deserialize {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized;
}
