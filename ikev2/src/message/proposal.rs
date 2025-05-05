use crate::message::{
    num::{Num, Protocol},
    serialize, transform,
};
use anyhow::Result;
use bytes::{Buf, BufMut};

pub const HEADER_SIZE: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    number: u8,
    protocol: Num<u8, Protocol>,
    spi: Vec<u8>,
    transforms: Vec<transform::Transform>,
}

impl Proposal {
    pub fn number(&self) -> u8 {
        self.number
    }

    pub fn protocol(&self) -> Num<u8, Protocol> {
        self.protocol
    }

    pub fn spi(&self) -> &[u8] {
        &self.spi
    }

    pub fn transforms(&self) -> impl Iterator<Item = &transform::Transform> {
        self.transforms.iter()
    }

    pub fn new(
        number: u8,
        protocol: Num<u8, Protocol>,
        spi: impl AsRef<[u8]>,
        transforms: impl AsRef<[transform::Transform]>,
    ) -> Self {
        Self {
            number,
            protocol,
            spi: spi.as_ref().to_vec(),
            transforms: transforms.as_ref().to_vec(),
        }
    }
}

impl serialize::Serialize for Proposal {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.number);
        buf.put_u8(self.protocol.into());
        buf.put_u8(self.spi.len().try_into()?);
        buf.put_u8(self.transforms.len().try_into()?);
        buf.put_slice(&self.spi);
        for (i, transform) in self.transforms.iter().enumerate() {
            if i == self.transforms.len() - 1 {
                buf.put_u8(0);
            } else {
                buf.put_u8(3);
            }
            buf.put_u8(0);
            let len = transform::HEADER_SIZE
                .checked_add(transform.size()?)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum proposal size"))?;
            buf.put_u16(len.try_into()?);
            transform.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let mut len = HEADER_SIZE
            .checked_add(self.spi.len())
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum proposal size"))?;
        for transform in &self.transforms {
            len = len
                .checked_add(transform::HEADER_SIZE)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum proposal size"))?
                .checked_add(transform.size()?)
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum proposal size"))?;
        }
        Ok(len)
    }
}

impl serialize::Deserialize for Proposal {
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let number = buf.try_get_u8()?;
        let protocol: Num<u8, Protocol> = buf.try_get_u8()?.into();
        let spi_size = buf.try_get_u8()?;
        let num_transforms = buf.try_get_u8()?;
        let mut spi = vec![0; spi_size as usize];
        buf.try_copy_to_slice(&mut spi)?;
        let mut transforms = Vec::new();
        for _ in 0..num_transforms {
            let _last_substruc = buf.try_get_u8()?;
            let _ = buf.try_get_u8()?;
            let len: usize = buf.try_get_u16()?.try_into()?;
            let len = len
                .checked_sub(transform::HEADER_SIZE)
                .ok_or_else(|| anyhow::anyhow!("invalid transform length"))?;
            transforms.push(*transform::Transform::deserialize(
                &mut &buf.chunk()[..len],
            )?);
            buf.advance(len);
        }
        if buf.has_remaining() {
            return Err(anyhow::anyhow!("proposal with extra data"));
        }
        Ok(Box::new(Self {
            number,
            protocol,
            spi,
            transforms,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    pub(crate) fn create_proposal() -> Proposal {
        let transform = transform::tests::create_transform();
        Proposal::new(
            1,
            Num::Assigned(Protocol::IKE),
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[transform],
        )
    }

    #[test]
    fn test_proposal() {
        let proposal = create_proposal();

        let len = proposal
            .size()
            .expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        proposal
            .serialize(&mut buf)
            .expect("unable to serialize proposal");

        let proposal2 =
            Proposal::deserialize(&mut &buf[..]).expect("unable to deserialize proposal");

        assert_eq!(proposal2.number(), 1);
        assert!(matches!(proposal2.protocol(), Num::Assigned(Protocol::IKE),));
        assert_eq!(proposal2.spi(), &[1, 2, 3, 4, 5, 6, 7, 8][..]);
        assert_eq!(
            proposal2
                .transforms()
                .collect::<Vec<&transform::Transform>>(),
            proposal
                .transforms()
                .collect::<Vec<&transform::Transform>>()
        );
    }
}
