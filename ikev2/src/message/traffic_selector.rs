use crate::message::{
    num::{Num, TrafficSelectorType},
    serialize,
};
use bytes::{Buf, BufMut};
use std::net::IpAddr;
use tracing::debug;

/// Traffic Selector
#[derive(Clone, Debug, PartialEq)]
pub struct TrafficSelector {
    ty: Num<u8, TrafficSelectorType>,
    ip_proto: u8,
    start_port: u16,
    end_port: u16,
    start_address: IpAddr,
    end_address: IpAddr,
}

impl TrafficSelector {
    /// Creates a new `TrafficSelector`
    pub fn new(
        ty: Num<u8, TrafficSelectorType>,
        ip_proto: u8,
        start_address: IpAddr,
        end_address: IpAddr,
        start_port: u16,
        end_port: u16,
    ) -> Self {
        Self {
            ty,
            ip_proto,
            start_port,
            end_port,
            start_address,
            end_address,
        }
    }

    /// Returns the type of the `TrafficSelector`
    pub fn ty(&self) -> Num<u8, TrafficSelectorType> {
        self.ty
    }

    /// Returns the IP protocol of the `TrafficSelector`
    pub fn ip_proto(&self) -> u8 {
        self.ip_proto
    }

    /// Returns the starting address of the `TrafficSelector`
    pub fn start_address(&self) -> IpAddr {
        self.start_address
    }

    /// Returns the ending address of the `TrafficSelector`
    pub fn end_address(&self) -> IpAddr {
        self.end_address
    }

    /// Returns the starting port of the `TrafficSelector`
    pub fn start_port(&self) -> u16 {
        self.start_port
    }

    /// Returns the ending port of the `TrafficSelector`
    pub fn end_port(&self) -> u16 {
        self.end_port
    }

    /// Returns the first matching `TrafficSelector`
    pub fn negotiate<'a, 'b>(
        this: impl IntoIterator<Item = &'a TrafficSelector>,
        other: impl IntoIterator<Item = &'a TrafficSelector>,
    ) -> Option<Self> {
        let this: Vec<_> = this.into_iter().collect();
        let other: Vec<_> = other.into_iter().collect();
        debug!(this = ?this, other = ?other, "TrafficSelector::negotiate");
        this.iter()
            .find_map(|tx| other.iter().find_map(|ty| tx.intersection(ty)))
            .or_else(|| {
                other
                    .iter()
                    .find_map(|tx| this.iter().find_map(|ty| tx.intersection(ty)))
            })
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        if self.ty != other.ty {
            return false;
        }
        if other.ip_proto != 0 && self.ip_proto != other.ip_proto {
            return false;
        }
        if self.start_port < other.start_port || self.end_port > other.end_port {
            return false;
        }
        if self.start_address < other.start_address || self.end_address > other.end_address {
            return false;
        }
        true
    }

    fn narrow_to(&self, other: &Self) -> Option<Self> {
        if self.ty != other.ty {
            return None;
        }
        if self.ip_proto != 0 && self.ip_proto != other.ip_proto {
            return None;
        }
        if self.end_address < other.start_address || other.end_address < self.start_address {
            return None;
        }
        if self.end_port < other.start_port || other.end_port < self.start_port {
            return None;
        }
        Some(Self::new(
            self.ty,
            self.ip_proto.max(other.ip_proto),
            self.start_address.max(other.start_address),
            self.end_address.min(other.end_address),
            self.start_port.max(other.start_port),
            self.end_port.min(other.end_port),
        ))
    }

    fn intersection(&self, other: &Self) -> Option<Self> {
        if self.is_subset_of(other) {
            Some(self.clone())
        } else if other.is_subset_of(self) {
            Some(other.clone())
        } else {
            self.narrow_to(other).or_else(|| other.narrow_to(self))
        }
    }
}

impl serialize::Serialize for TrafficSelector {
    fn serialize(&self, buf: &mut dyn BufMut) -> Result<(), serialize::SerializeError> {
        buf.put_u8(self.ty.into());
        buf.put_u8(self.ip_proto);
        buf.put_u16(self.size()?.try_into()?);
        buf.put_u16(self.start_port);
        buf.put_u16(self.end_port);

        let start_address = match self.start_address {
            IpAddr::V4(v4) => v4.to_bits().to_be_bytes().to_vec(),
            IpAddr::V6(v6) => v6.to_bits().to_be_bytes().to_vec(),
        };
        let end_address = match self.end_address {
            IpAddr::V4(v4) => v4.to_bits().to_be_bytes().to_vec(),
            IpAddr::V6(v6) => v6.to_bits().to_be_bytes().to_vec(),
        };

        buf.put_slice(&start_address);
        buf.put_slice(&end_address);
        Ok(())
    }

    fn size(&self) -> Result<usize, serialize::SerializeError> {
        let address_size = match self.ty.assigned() {
            Some(TrafficSelectorType::TS_IPV4_ADDR_RANGE) => 4usize,
            Some(TrafficSelectorType::TS_IPV6_ADDR_RANGE) => 16usize,
            _ => {
                return Err(serialize::SerializeError::UnknownTrafficSelectorType(
                    self.ty,
                ));
            }
        };

        8usize
            .checked_add(address_size * 2)
            .ok_or(serialize::SerializeError::Overflow)
    }
}

impl serialize::Deserialize for TrafficSelector {
    fn deserialize(buf: &mut dyn Buf) -> Result<Self, serialize::DeserializeError>
    where
        Self: Sized,
    {
        let ty: Num<u8, TrafficSelectorType> = buf.try_get_u8()?.into();
        let ip_proto = buf.try_get_u8()?;
        let size: usize = buf.try_get_u16()?.into();
        if size < 4 || size - 4 > buf.remaining() {
            return Err(serialize::DeserializeError::PrematureEof);
        }

        let start_port = buf.try_get_u16()?;
        let end_port = buf.try_get_u16()?;

        let (start_address, end_address): (IpAddr, IpAddr) = match ty.assigned() {
            Some(TrafficSelectorType::TS_IPV4_ADDR_RANGE) => {
                let mut address = [0; 4];

                buf.try_copy_to_slice(&mut address)?;
                let start_address = address.into();
                buf.try_copy_to_slice(&mut address)?;
                let end_address = address.into();
                (start_address, end_address)
            }
            Some(TrafficSelectorType::TS_IPV6_ADDR_RANGE) => {
                let mut address = [0; 16];

                buf.try_copy_to_slice(&mut address)?;
                let start_address = address.into();
                buf.try_copy_to_slice(&mut address)?;
                let end_address = address.into();
                (start_address, end_address)
            }
            _ => return Err(serialize::DeserializeError::UnknownTrafficSelectorType(ty)),
        };

        if start_address > end_address || start_port > end_port {
            return Err(serialize::DeserializeError::InvalidTrafficSelectorRange);
        }

        Ok(Self {
            ty,
            ip_proto,
            start_port,
            end_port,
            start_address,
            end_address,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::serialize::{Deserialize, Serialize};
    use bytes::BytesMut;
    use std::net::IpAddr;

    pub(crate) fn create_traffic_selector(address: IpAddr) -> TrafficSelector {
        TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            0,
            address,
            address,
            0,
            0,
        )
    }

    #[test]
    fn test_traffic_selector() {
        let traffic_selector = create_traffic_selector("192.168.1.2".parse().unwrap());

        let len = traffic_selector
            .size()
            .expect("unable to determine serialized size");
        let mut buf = BytesMut::with_capacity(len);
        traffic_selector
            .serialize(&mut buf)
            .expect("unable to serialize traffic selector");

        let traffic_selector2 = TrafficSelector::deserialize(&mut &buf[..])
            .expect("unable to deserialize traffic selector");

        assert_eq!(traffic_selector, traffic_selector2);
    }

    #[test]
    fn test_intersection() {
        let this = TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            0,
            "192.168.1.1".parse().unwrap(),
            "192.168.1.255".parse().unwrap(),
            1000,
            2000,
        );
        let other = TrafficSelector::new(
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into(),
            0,
            "192.168.1.1".parse().unwrap(),
            "192.168.255.255".parse().unwrap(),
            500,
            1500,
        );
        let intersection = this
            .intersection(&other)
            .expect("intersection should be found");
        assert_eq!(
            intersection.ty(),
            TrafficSelectorType::TS_IPV4_ADDR_RANGE.into()
        );
        assert_eq!(intersection.ip_proto(), 0);
        assert_eq!(intersection.start_address(), this.start_address());
        assert_eq!(intersection.end_address(), this.end_address());
        assert_eq!(intersection.start_port(), 1000);
        assert_eq!(intersection.end_port(), 1500);
    }
}
