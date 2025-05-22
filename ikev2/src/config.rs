//! IKE SA configuration
//!
//! This module provides functions and data structures to configure a
//! new IKE SA. The main entry point to this module is
//! [`ConfigBuilder`].
//!
//! [`ConfigBuilder`]: crate::config::ConfigBuilder
//!
use crate::message::{
    EspSpi, Spi,
    num::{
        AttributeFormat, AttributeType, DhId, EncrId, EsnId, IntegId, Num, PrfId, Protocol,
        TransformId, TransformType,
    },
    payload::Id,
    proposal::Proposal,
    transform::{Attribute, Transform},
};

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
                        Num::Assigned(AttributeType::KeyLength.into()),
                        key_size.to_be_bytes(),
                        AttributeFormat::TV,
                    ));
                }
                Transform::new(
                    Num::Assigned(TransformType::ENCR.into()),
                    Num::Assigned(TransformId::Encr(Num::Assigned((*id).into())).into()),
                    attributes,
                )
            })
            .collect();

        transforms.append(&mut encryption);

        let mut prf = self
            .prf
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::PRF.into()),
                    Num::Assigned(TransformId::Prf(Num::Assigned((*id).into())).into()),
                    None::<Attribute>,
                )
            })
            .collect();

        transforms.append(&mut prf);

        let mut integrity = self
            .integrity
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::INTEG.into()),
                    Num::Assigned(TransformId::Integ(Num::Assigned((*id).into())).into()),
                    None::<Attribute>,
                )
            })
            .collect();

        transforms.append(&mut integrity);

        let mut dh = self
            .dh
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::DH.into()),
                    Num::Assigned(TransformId::Dh(Num::Assigned((*id).into())).into()),
                    None::<Attribute>,
                )
            })
            .collect();

        transforms.append(&mut dh);

        let mut esn = self
            .esn
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::ESN.into()),
                    Num::Assigned(TransformId::Esn(Num::Assigned((*id).into())).into()),
                    None::<Attribute>,
                )
            })
            .collect();

        transforms.append(&mut esn);

        Proposal::new(
            number,
            Num::Assigned(protocol.into()),
            spi.as_ref(),
            transforms,
        )
    }
}

/// Builder to create an IKE SA configuration
#[derive(Default)]
pub struct ConfigBuilder {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Option<Protocol>,
    psk: Option<Vec<u8>>,
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
        self.psk = Some(psk.as_ref().to_vec());
        self
    }

    /// Turn this `ConfigBuilder` into an actual `Config`
    pub fn build(mut self, id: Id) -> Config {
        Config {
            ike_proposals: self.ike_proposals,
            ipsec_protocol: self.ipsec_protocol.take().unwrap_or(Protocol::ESP),
            ipsec_proposals: self.ipsec_proposals,
            id,
            psk: self.psk.take(),
        }
    }
}

/// IKE SA configuration
#[derive(Clone, Debug)]
pub struct Config {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Protocol,
    ipsec_proposals: Vec<ProposalBuilder>,
    id: Id,
    psk: Option<Vec<u8>>,
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

    /// Returns the identity of IKE SA
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Returns the PSK for authentication if set
    pub fn psk(&self) -> Option<&[u8]> {
        self.psk.as_deref()
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
            .psk(b"test test test")
            .build(Id::new(
                Num::Assigned(IdType::ID_KEY_ID.into()),
                id.as_ref(),
            ))
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
