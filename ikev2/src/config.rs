//! IKE SA configuration
//!
//! This module provides functions and data structures to configure a
//! new IKE SA. The main entry point to this module is
//! [`ConfigBuilder`].
//!
//! [`ConfigBuilder`]: crate::config::ConfigBuilder
//!
use crate::{
    crypto::Key,
    message::{
        EspSpi, Spi,
        num::{
            AttributeFormat, AttributeType, DhId, EncrId, EsnId, IntegId, PrfId, Protocol,
            TrafficSelectorType, TransformType,
        },
        payload::Id,
        proposal::Proposal,
        traffic_selector::TrafficSelector,
        transform::{Attribute, Transform},
    },
};

use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no proposal to send")]
    NoProposalsSet,

    #[error("insufficient proposal")]
    InsufficientProposal,

    #[error("no PSK set")]
    NoPSK,

    #[error("inconsistent traffic selector")]
    InconsistentTrafficSelector,
}

/// Builder to create a cryptographic proposal
#[derive(Clone, Debug, Default)]
pub struct ProposalBuilder {
    encryption: Vec<(EncrId, Option<u16>)>,
    prf: Vec<PrfId>,
    integrity: Vec<IntegId>,
    dh: Vec<DhId>,
    esn: Vec<EsnId>,
}

impl ProposalBuilder {
    /// Sets the encryption algorithm and key size
    pub fn encryption(mut self, id: EncrId, key_size: Option<u16>) -> Self {
        self.encryption.push((id, key_size));
        self
    }

    /// Sets the PRF algorithm
    pub fn prf(mut self, id: PrfId) -> Self {
        self.prf.push(id);
        self
    }

    /// Sets the integrity checking algorithm
    pub fn integrity(mut self, id: IntegId) -> Self {
        self.integrity.push(id);
        self
    }

    /// Sets the Diffie-Hellman group
    pub fn dh(mut self, id: DhId) -> Self {
        self.dh.push(id);
        self
    }

    /// Sets the ESN option
    pub fn esn(mut self, id: EsnId) -> Self {
        self.esn.push(id);
        self
    }

    /// Turn this `ProposalBuilder` into an actual `Proposal`
    pub fn build(&self, number: u8, protocol: Protocol, spi: impl AsRef<[u8]>) -> Proposal {
        let mut transforms = Vec::new();

        let mut encryption = self
            .encryption
            .iter()
            .map(|(id, key_size)| {
                let mut attributes = Vec::new();
                if let Some(key_size) = key_size {
                    attributes.push(Attribute::new(
                        AttributeType::KeyLength.into(),
                        key_size.to_be_bytes(),
                        AttributeFormat::TV,
                    ));
                }
                Transform::new(TransformType::ENCR.into(), (*id).into(), attributes)
            })
            .collect();

        transforms.append(&mut encryption);

        let mut prf = self
            .prf
            .iter()
            .map(|id| Transform::new(TransformType::PRF.into(), (*id).into(), None::<Attribute>))
            .collect();

        transforms.append(&mut prf);

        let mut integrity = self
            .integrity
            .iter()
            .map(|id| Transform::new(TransformType::INTEG.into(), (*id).into(), None::<Attribute>))
            .collect();

        transforms.append(&mut integrity);

        let mut dh = self
            .dh
            .iter()
            .map(|id| Transform::new(TransformType::DH.into(), (*id).into(), None::<Attribute>))
            .collect();

        transforms.append(&mut dh);

        let mut esn = self
            .esn
            .iter()
            .map(|id| Transform::new(TransformType::ESN.into(), (*id).into(), None::<Attribute>))
            .collect();

        transforms.append(&mut esn);

        Proposal::new(number, protocol.into(), spi.as_ref(), transforms)
    }
}

/// Builder to create a traffic selector
#[derive(Clone, Debug, Default)]
pub struct TrafficSelectorBuilder {
    ip_proto: Option<u8>,
    start_address: Option<IpAddr>,
    end_address: Option<IpAddr>,
    start_port: Option<u16>,
    end_port: Option<u16>,
}

impl TrafficSelectorBuilder {
    /// Sets the IP protocol
    pub fn ip_proto(mut self, ip_proto: u8) -> Self {
        self.ip_proto = Some(ip_proto);
        self
    }

    /// Sets the starting address
    pub fn start_address(mut self, start_address: IpAddr) -> Self {
        self.start_address = Some(start_address);
        self
    }

    /// Sets the ending address
    pub fn end_address(mut self, end_address: IpAddr) -> Self {
        self.end_address = Some(end_address);
        self
    }

    /// Sets the starting port
    pub fn start_port(mut self, start_port: u16) -> Self {
        self.start_port = Some(start_port);
        self
    }

    /// Sets the ending port
    pub fn end_port(mut self, end_port: u16) -> Self {
        self.end_port = Some(end_port);
        self
    }

    /// Turn this `TrafficSelectorBuilder` into an actual `TrafficSelector`
    pub fn build(self) -> Result<TrafficSelector, ConfigError> {
        let (start_address, end_address) = match (self.start_address, self.end_address) {
            (Some(start_address @ IpAddr::V4(_)), Some(end_address @ IpAddr::V4(_)))
            | (Some(start_address @ IpAddr::V6(_)), Some(end_address @ IpAddr::V6(_))) => {
                (start_address, end_address)
            }
            (Some(start_address @ IpAddr::V4(_)), None) => (start_address, start_address),
            (Some(start_address @ IpAddr::V6(_)), None) => (start_address, start_address),
            _ => return Err(ConfigError::InconsistentTrafficSelector),
        };

        let (start_port, end_port) = match (self.start_port, self.end_port) {
            (Some(start_port), Some(end_port)) => (start_port, end_port),
            (Some(start_port), None) => (start_port, start_port),
            (None, None) => (u16::MIN, u16::MAX),
            (None, Some(_)) => return Err(ConfigError::InconsistentTrafficSelector),
        };

        if start_address > end_address || start_port > end_port {
            return Err(ConfigError::InconsistentTrafficSelector);
        }

        let ty = match start_address {
            IpAddr::V4(_) => TrafficSelectorType::TS_IPV4_ADDR_RANGE,
            IpAddr::V6(_) => TrafficSelectorType::TS_IPV6_ADDR_RANGE,
        };

        Ok(TrafficSelector::new(
            ty.into(),
            self.ip_proto.unwrap_or(0),
            &start_address,
            &end_address,
            start_port,
            end_port,
        ))
    }
}

/// Builder to create an IKE SA configuration
#[derive(Default)]
pub struct ConfigBuilder {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Option<Protocol>,
    inbound_traffic_selectors: Vec<TrafficSelectorBuilder>,
    outbound_traffic_selectors: Vec<TrafficSelectorBuilder>,
    psk: Option<Key>,
}

impl ConfigBuilder {
    /// Adds an IKE proposal
    pub fn ike_proposal<F>(mut self, func: F) -> Self
    where
        F: FnOnce(ProposalBuilder) -> ProposalBuilder,
    {
        self.ike_proposals.push(func(ProposalBuilder::default()));
        self
    }

    /// Sets the IPsec protocol (ESP or AH)
    pub fn ipsec_protocol(mut self, protocol: Protocol) -> Self {
        self.ipsec_protocol = Some(protocol);
        self
    }

    /// Adds an IPsec proposal
    pub fn ipsec_proposal<F>(mut self, func: F) -> Self
    where
        F: FnOnce(ProposalBuilder) -> ProposalBuilder,
    {
        self.ipsec_proposals.push(func(ProposalBuilder::default()));
        self
    }

    /// Sets the PSK for authentication
    pub fn psk(mut self, psk: impl AsRef<[u8]>) -> Self {
        self.psk = Some(Key::new(psk.as_ref().to_vec()));
        self
    }

    /// Adds an inbound traffic selector
    pub fn inbound_traffic_selector<F>(mut self, func: F) -> Self
    where
        F: FnOnce(TrafficSelectorBuilder) -> TrafficSelectorBuilder,
    {
        self.inbound_traffic_selectors
            .push(func(TrafficSelectorBuilder::default()));
        self
    }

    /// Adds an outbound traffic selector
    pub fn outbound_traffic_selector<F>(mut self, func: F) -> Self
    where
        F: FnOnce(TrafficSelectorBuilder) -> TrafficSelectorBuilder,
    {
        self.outbound_traffic_selectors
            .push(func(TrafficSelectorBuilder::default()));
        self
    }

    /// Turn this `ConfigBuilder` into an actual `Config`
    pub fn build(mut self, id: Id) -> Result<Config, ConfigError> {
        let inbound_traffic_selectors: Result<Vec<_>, _> = self
            .inbound_traffic_selectors
            .into_iter()
            .map(|tb| tb.build())
            .collect();
        let outbound_traffic_selectors: Result<Vec<_>, _> = self
            .outbound_traffic_selectors
            .into_iter()
            .map(|tb| tb.build())
            .collect();
        Ok(Config {
            ike_proposals: self.ike_proposals,
            ipsec_protocol: self.ipsec_protocol.take().unwrap_or(Protocol::ESP),
            ipsec_proposals: self.ipsec_proposals,
            inbound_traffic_selectors: inbound_traffic_selectors?,
            outbound_traffic_selectors: outbound_traffic_selectors?,
            psk: self.psk.take(),
            id,
        })
    }
}

/// IKE SA configuration
#[derive(Clone, Debug)]
pub struct Config {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Protocol,
    ipsec_proposals: Vec<ProposalBuilder>,
    inbound_traffic_selectors: Vec<TrafficSelector>,
    outbound_traffic_selectors: Vec<TrafficSelector>,
    psk: Option<Key>,
    id: Id,
}

impl Config {
    /// Returns an interator over configured IKE proposals
    pub fn ike_proposals<'a, 'b>(
        &'a self,
        spi: Option<&'b Spi>,
    ) -> impl Iterator<Item = Proposal> + use<'a, 'b> {
        let spi = spi.map(|spi| &spi[..]).unwrap_or_else(|| b"");
        self.ike_proposals
            .iter()
            .enumerate()
            .map(move |(i, pb)| pb.build(i as u8 + 1, Protocol::IKE, spi))
    }

    /// Returns the IPsec protocol (ESP or AH)
    pub fn ipsec_protocol(&self) -> Protocol {
        self.ipsec_protocol
    }

    /// Returns an interator over configured IPsec proposals
    pub fn ipsec_proposals<'a, 'b>(
        &'a self,
        spi: &'b EspSpi,
    ) -> impl Iterator<Item = Proposal> + use<'a, 'b> {
        self.ipsec_proposals
            .iter()
            .enumerate()
            .map(|(i, pb)| pb.build(i as u8 + 1, self.ipsec_protocol, spi.as_ref()))
    }

    /// Returns an interator over inbound traffic selectors
    pub fn inbound_traffic_selectors(&self) -> impl Iterator<Item = &TrafficSelector> {
        self.inbound_traffic_selectors.iter()
    }

    /// Returns an interator over inbound traffic selectors
    pub fn outbound_traffic_selectors(&self) -> impl Iterator<Item = &TrafficSelector> {
        self.outbound_traffic_selectors.iter()
    }

    /// Returns the PSK for authentication if set
    pub fn psk(&self) -> Option<&Key> {
        self.psk.as_ref()
    }

    /// Returns the identity of IKE SA
    pub fn id(&self) -> &Id {
        &self.id
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::message::{num::IdType, payload::Id};

    pub(crate) fn create_config(id: impl AsRef<[u8]>) -> Config {
        let builder = ConfigBuilder::default();
        builder
            .ike_proposal(|pc| {
                pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                    .encryption(EncrId::ENCR_AES_CBC, Some(256))
                    .prf(PrfId::PRF_HMAC_SHA1)
                    .integrity(IntegId::AUTH_HMAC_SHA1_96)
                    .dh(DhId::MODP2048)
                    .esn(EsnId::NoEsn)
                    .esn(EsnId::Esn)
            })
            .ike_proposal(|pc| {
                pc.encryption(EncrId::ENCR_AES_CTR, Some(128))
                    .encryption(EncrId::ENCR_AES_CTR, Some(256))
                    .prf(PrfId::PRF_HMAC_SHA1)
                    .integrity(IntegId::AUTH_HMAC_SHA1_96)
                    .dh(DhId::MODP2048)
            })
            .ipsec_protocol(Protocol::ESP)
            .ipsec_proposal(|pc| {
                pc.encryption(EncrId::ENCR_AES_CBC, Some(128))
                    .encryption(EncrId::ENCR_AES_CBC, Some(256))
                    .prf(PrfId::PRF_HMAC_SHA1)
                    .integrity(IntegId::AUTH_HMAC_SHA1_96)
                    .dh(DhId::MODP2048)
            })
            .inbound_traffic_selector(|tc| tc.start_address("192.168.1.2".parse().unwrap()))
            .inbound_traffic_selector(|tc| tc.start_address("192.168.1.3".parse().unwrap()))
            .outbound_traffic_selector(|tc| tc.start_address("192.168.1.3".parse().unwrap()))
            .outbound_traffic_selector(|tc| tc.start_address("192.168.1.2".parse().unwrap()))
            .psk(b"test test test")
            .build(Id::new(IdType::ID_KEY_ID.into(), id.as_ref()))
            .expect("building config should succeed")
    }

    #[test]
    fn test_config_builder() {
        let config = create_config(b"initiator");

        assert_eq!(
            config
                .ike_proposals(Some(&Spi::default()))
                .collect::<Vec<_>>()
                .len(),
            2
        );
        assert_eq!(config.ipsec_protocol(), Protocol::ESP);
        assert_eq!(
            config
                .ipsec_proposals(&EspSpi::default())
                .collect::<Vec<_>>()
                .len(),
            1
        );
    }
}
