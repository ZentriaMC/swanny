use crate::message::{
    num::{AttributeFormat, AttributeType, Num, TransformId, TransformType},
    serialize,
};
use anyhow::Result;
use bytes::{Buf, BufMut};

pub(crate) const HEADER_SIZE: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    ty: Num<u16, AttributeType>,
    value: Vec<u8>,
    format: AttributeFormat,
}

impl Attribute {
    pub fn ty(&self) -> Num<u16, AttributeType> {
        self.ty
    }

    pub fn value(&self) -> &[u8] {
        self.value.as_ref()
    }

    pub fn format(&self) -> AttributeFormat {
        self.format
    }

    pub fn new(
        ty: Num<u16, AttributeType>,
        value: impl AsRef<[u8]>,
        format: AttributeFormat,
    ) -> Self {
        Self {
            ty,
            value: value.as_ref().to_vec(),
            format,
        }
    }
}

impl serialize::Serialize for Attribute {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        let ty: u16 = self.ty.into();
        match self.format {
            AttributeFormat::TLV => {
                buf.put_u16(ty);
                buf.put_u16(self.value.len().try_into()?);
                buf.put_slice(&self.value);
            }
            AttributeFormat::TV => {
                buf.put_u16(ty | 0x8000);
                buf.put_u8(self.value[0]);
                buf.put_u8(self.value[1]);
            }
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        match self.format {
            AttributeFormat::TLV => 4usize
                .checked_add(self.value.len())
                .ok_or_else(|| anyhow::anyhow!("exceeded maximum attribute size")),
            AttributeFormat::TV => Ok(4),
        }
    }
}

impl serialize::Deserialize for Attribute {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let mut ty = buf.try_get_u16()?;
        let (format, len) = if (ty & 0x8000) != 0 {
            (AttributeFormat::TV, 2)
        } else {
            (AttributeFormat::TLV, buf.try_get_u16()?)
        };
        ty &= !0x8000;
        let ty: Num<u16, AttributeType> = ty.into();
        let mut value = vec![0; len as usize];
        buf.try_copy_to_slice(&mut value)?;
        Ok(Self { ty, value, format })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Transform {
    ty: Num<u8, TransformType>,
    id: Num<u16, TransformId>,
    attributes: Vec<Attribute>,
}

impl Transform {
    pub fn ty(&self) -> Num<u8, TransformType> {
        self.ty
    }

    pub fn id(&self) -> Num<u16, TransformId> {
        self.id
    }

    pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter()
    }

    pub fn new<A>(ty: Num<u8, TransformType>, id: Num<u16, TransformId>, attributes: A) -> Self
    where
        A: IntoIterator,
        A::Item: Into<Attribute>,
    {
        Self {
            ty,
            id,
            attributes: attributes.into_iter().map(Into::into).collect(),
        }
    }
}

impl serialize::Serialize for Transform {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.ty.into());
        buf.put_u8(0);
        buf.put_u16(self.id.into());
        for attribute in &self.attributes {
            attribute.serialize(buf)?;
        }
        Ok(())
    }

    fn size(&self) -> Result<usize> {
        let sizes: Result<Vec<_>> = self.attributes.iter().map(|a| a.size()).collect();
        sizes?
            .into_iter()
            .try_fold(4usize, |acc, x| acc.checked_add(x))
            .ok_or_else(|| anyhow::anyhow!("exceeded maximum transform size"))
    }
}

impl serialize::Deserialize for Transform {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let ty = buf.try_get_u8()?.into();
        let _ = buf.try_get_u8();
        let id = Num::<u16, TransformId>::from_u16(ty, buf.try_get_u16()?);
        let mut attributes = Vec::new();
        while buf.has_remaining() {
            attributes.push(Attribute::deserialize(buf)?);
        }
        Ok(Self { ty, id, attributes })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::{
        num::EncrId,
        serialize::{Deserialize, Serialize},
    };
    use bytes::BytesMut;

    fn create_attribute() -> Attribute {
        Attribute::new(
            AttributeType::KeyLength.into(),
            &128u16.to_be_bytes()[..],
            AttributeFormat::TV,
        )
    }

    pub(crate) fn create_transform() -> Transform {
        let attr = create_attribute();
        Transform::new(
            TransformType::ENCR.into(),
            EncrId::ENCR_AES_CTR.into(),
            Some(attr),
        )
    }

    #[test]
    fn test_attribute() {
        let attr = create_attribute();

        let len = attr.size().expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        attr.serialize(&mut buf)
            .expect("unable to serialize attribute");

        let attr2 = Attribute::deserialize(&mut &buf[..]).expect("unable to deserialize attribute");

        assert_eq!(attr2, attr);
    }

    #[test]
    fn test_transform() {
        let transform = create_transform();

        let len = transform
            .size()
            .expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        transform
            .serialize(&mut buf)
            .expect("unable to serialize transform");

        let transform2 =
            Transform::deserialize(&mut &buf[..]).expect("unable to deserialize transform");

        assert!(matches!(
            transform2.ty().assigned(),
            Some(TransformType::ENCR)
        ));
        assert!(matches!(
            transform2.id().assigned(),
            Some(TransformId::Encr(_))
        ));
        assert_eq!(
            transform2.attributes().collect::<Vec<&Attribute>>(),
            transform.attributes().collect::<Vec<&Attribute>>()
        );
    }
}
