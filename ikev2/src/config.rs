use crate::message::{
    num::{AttributeType, DhId, EncrId, EsnId, IntegId, Num, PrfId, Protocol, TransformType},
    proposal::Proposal,
    transform::{Attribute, AttributeFormat, Transform, TransformId},
};

#[derive(Clone, Debug, Default)]
pub struct ProposalBuilder {
    encryption: Vec<(EncrId, Option<u16>)>,
    prf: Vec<PrfId>,
    integrity: Vec<IntegId>,
    dh: Vec<DhId>,
    esn: Vec<EsnId>,
}

impl ProposalBuilder {
    pub fn encryption(mut self, id: EncrId, key_size: Option<u16>) -> Self {
        self.encryption.push((id, key_size));
        self
    }

    pub fn prf(mut self, id: PrfId) -> Self {
        self.prf.push(id);
        self
    }

    pub fn integrity(mut self, id: IntegId) -> Self {
        self.integrity.push(id);
        self
    }

    pub fn dh(mut self, id: DhId) -> Self {
        self.dh.push(id);
        self
    }

    pub fn esn(mut self, id: EsnId) -> Self {
        self.esn.push(id);
        self
    }

    pub fn build(&self, number: u8, protocol: Protocol, spi: impl AsRef<[u8]>) -> Proposal {
        let mut transforms = Vec::new();

        let mut encryption = self
            .encryption
            .iter()
            .map(|(id, key_size)| {
                let mut attributes = Vec::new();
                if let Some(key_size) = key_size {
                    attributes.push(Attribute::new(
                        Num::Assigned(AttributeType::KeyLength),
                        key_size.to_be_bytes(),
                        AttributeFormat::TV,
                    ));
                }
                Transform::new(
                    Num::Assigned(TransformType::ENCR),
                    Num::Assigned(TransformId::Encr(Num::Assigned(*id))),
                    &attributes,
                )
            })
            .collect();

        transforms.append(&mut encryption);

        let mut prf = self
            .prf
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::PRF),
                    Num::Assigned(TransformId::Prf(Num::Assigned(*id))),
                    &[],
                )
            })
            .collect();

        transforms.append(&mut prf);

        let mut integrity = self
            .integrity
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::INTEG),
                    Num::Assigned(TransformId::Integ(Num::Assigned(*id))),
                    &[],
                )
            })
            .collect();

        transforms.append(&mut integrity);

        let mut dh = self
            .dh
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::DH),
                    Num::Assigned(TransformId::Dh(Num::Assigned(*id))),
                    &[],
                )
            })
            .collect();

        transforms.append(&mut dh);

        let mut esn = self
            .esn
            .iter()
            .map(|id| {
                Transform::new(
                    Num::Assigned(TransformType::ESN),
                    Num::Assigned(TransformId::Esn(Num::Assigned(*id))),
                    &[],
                )
            })
            .collect();

        transforms.append(&mut esn);

        Proposal::new(number, Num::Assigned(protocol), spi, &transforms)
    }
}

#[derive(Default)]
pub struct ConfigBuilder {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Option<Protocol>,
}

impl ConfigBuilder {
    pub fn ike_proposal<F>(mut self, func: F) -> Self
    where
        F: FnOnce(ProposalBuilder) -> ProposalBuilder,
    {
        self.ike_proposals.push(func(ProposalBuilder::default()));
        self
    }

    pub fn ipsec_protocol(mut self, protocol: Protocol) -> Self {
        self.ipsec_protocol = Some(protocol);
        self
    }

    pub fn ipsec_proposal<F>(mut self, func: F) -> Self
    where
        F: FnOnce(ProposalBuilder) -> ProposalBuilder,
    {
        self.ipsec_proposals.push(func(ProposalBuilder::default()));
        self
    }

    pub fn build(mut self) -> Config {
        Config {
            ike_proposals: self.ike_proposals,
            ipsec_protocol: self.ipsec_protocol.take().unwrap_or(Protocol::ESP),
            ipsec_proposals: self.ipsec_proposals,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    ike_proposals: Vec<ProposalBuilder>,
    ipsec_protocol: Protocol,
    ipsec_proposals: Vec<ProposalBuilder>,
}

impl Config {
    pub fn ike_proposals(&self) -> impl Iterator<Item = &ProposalBuilder> {
        self.ike_proposals.iter()
    }

    pub fn ipsec_protocol(&self) -> Protocol {
        self.ipsec_protocol
    }

    pub fn ipsec_proposals(&self) -> impl Iterator<Item = &ProposalBuilder> {
        self.ipsec_proposals.iter()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn create_config() -> Config {
        let mut builder = ConfigBuilder::default();
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
            .build()
    }

    #[test]
    fn test_config_builder() {
        let config = create_config();

        assert_eq!(config.ike_proposals().collect::<Vec<_>>().len(), 2);
        assert_eq!(config.ipsec_protocol(), Protocol::ESP);
        assert_eq!(config.ipsec_proposals().collect::<Vec<_>>().len(), 1);
    }
}
