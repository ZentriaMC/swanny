use crate::message::{
    num::{AttributeType, DhId, EncrId, EsnId, IntegId, Num, PrfId, TransformType},
    serialize,
};
use anyhow::Result;
use bytes::{Buf, BufMut};

pub const HEADER_SIZE: usize = 4;

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

impl Num<u16, TransformId> {
    pub fn from_u16(type_: Num<u8, TransformType>, value: u16) -> Self {
        match type_ {
            Num::Assigned(TransformType::ENCR) => Num::Assigned(TransformId::Encr(value.into())),
            Num::Assigned(TransformType::PRF) => Num::Assigned(TransformId::Prf(value.into())),
            Num::Assigned(TransformType::INTEG) => Num::Assigned(TransformId::Integ(value.into())),
            Num::Assigned(TransformType::DH) => Num::Assigned(TransformId::Dh(value.into())),
            Num::Assigned(TransformType::ESN) => Num::Assigned(TransformId::Esn(value.into())),
            Num::Unassigned(_) => Num::Unassigned(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AttributeFormat {
    TV = 0,
    TLV = 1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    type_: Num<u16, AttributeType>,
    value: Vec<u8>,
    format: AttributeFormat,
}

impl Attribute {
    pub fn r#type(&self) -> Num<u16, AttributeType> {
        self.type_
    }

    pub fn value(&self) -> &[u8] {
        self.value.as_ref()
    }

    pub fn format(&self) -> AttributeFormat {
        self.format
    }

    pub fn new(
        type_: Num<u16, AttributeType>,
        value: impl AsRef<[u8]>,
        format: AttributeFormat,
    ) -> Self {
        Self {
            type_,
            value: value.as_ref().to_vec(),
            format,
        }
    }
}

impl serialize::Serialize for Attribute {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        let type_: u16 = self.type_.into();
        match self.format {
            AttributeFormat::TLV => {
                buf.put_u16(type_ | 0x8000);
                buf.put_u16(self.value.len().try_into()?);
                buf.put_slice(&self.value);
            }
            AttributeFormat::TV => {
                buf.put_u16(type_);
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
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let mut type_ = buf.try_get_u16()?;
        let (format, len) = if (type_ & 0x8000) == 0 {
            (AttributeFormat::TV, 2)
        } else {
            (AttributeFormat::TLV, buf.try_get_u16()?)
        };
        type_ &= !0x8000;
        let type_: Num<u16, AttributeType> = type_.into();
        let mut value = vec![0; len as usize];
        buf.try_copy_to_slice(&mut value)?;
        Ok(Box::new(Self {
            type_,
            value,
            format,
        }))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Transform {
    type_: Num<u8, TransformType>,
    id: Num<u16, TransformId>,
    attributes: Vec<Attribute>,
}

impl Transform {
    pub fn r#type(&self) -> Num<u8, TransformType> {
        self.type_
    }

    pub fn id(&self) -> Num<u16, TransformId> {
        self.id
    }

    pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter()
    }

    pub fn new(
        type_: Num<u8, TransformType>,
        id: Num<u16, TransformId>,
        attributes: impl AsRef<[Attribute]>,
    ) -> Self {
        Self {
            type_,
            id,
            attributes: attributes.as_ref().to_vec(),
        }
    }
}

impl serialize::Serialize for Transform {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<()> {
        buf.put_u8(self.type_.into());
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
    fn deserialize(buf: &mut dyn Buf) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let type_ = buf.try_get_u8()?.into();
        let _ = buf.try_get_u8();
        let id = Num::<u16, TransformId>::from_u16(type_, buf.try_get_u16()?);
        let mut attributes = Vec::new();
        while buf.has_remaining() {
            attributes.push(*Attribute::deserialize(buf)?);
        }
        Ok(Box::new(Self {
            type_,
            id,
            attributes,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;

    fn create_attribute() -> Attribute {
        Attribute::new(
            Num::Assigned(AttributeType::KeyLength),
            &128u16.to_be_bytes()[..],
            AttributeFormat::TV,
        )
    }

    pub(crate) fn create_transform() -> Transform {
        let attr = create_attribute();
        Transform::new(
            Num::Assigned(TransformType::ENCR),
            Num::Assigned(TransformId::Encr(Num::Assigned(EncrId::ENCR_AES_CTR))),
            &[attr],
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

        assert_eq!(*attr2, attr);
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
            transform2.r#type(),
            Num::Assigned(TransformType::ENCR)
        ));
        assert!(matches!(
            transform2.id(),
            Num::Assigned(TransformId::Encr(Num::Assigned(EncrId::ENCR_AES_CTR)))
        ));
        assert_eq!(
            transform2.attributes().collect::<Vec<&Attribute>>(),
            transform.attributes().collect::<Vec<&Attribute>>()
        );
    }
}
