use crate::message::{
    num::{AttributeType, DhId, EncrId, IntegId, Num, PrfId, TransformType},
    transform::{Attribute, AttributeFormat, Transform, TransformId},
};
use anyhow::Result;
use bytes::{BufMut, BytesMut};

use openssl::{
    bn,
    derive::Deriver,
    dh, ec,
    hash::MessageDigest,
    memcmp,
    nid::Nid,
    pkey::{self, PKey},
    rand,
    sign::Signer,
    symm,
};

use std::sync::Arc;

pub(crate) fn rand_bytes(buf: &mut [u8]) -> Result<()> {
    Ok(rand::rand_bytes(buf)?)
}

#[derive(Clone)]
pub struct Prf {
    id: PrfId,
    md: MessageDigest,
}

impl std::fmt::Debug for Prf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prf").field("id", &self.id).finish()
    }
}

impl Prf {
    pub fn new(id: PrfId) -> Result<Self> {
        let md = match id {
            PrfId::PRF_HMAC_MD5 => MessageDigest::md5(),
            PrfId::PRF_HMAC_SHA1 => MessageDigest::sha1(),
            PrfId::PRF_HMAC_SHA2_256 => MessageDigest::sha256(),
            PrfId::PRF_HMAC_SHA2_384 => MessageDigest::sha384(),
            PrfId::PRF_HMAC_SHA2_512 => MessageDigest::sha512(),
            _ => return Err(anyhow::anyhow!("unsupported PRF")),
        };

        Ok(Self { id, md })
    }

    pub fn id(&self) -> PrfId {
        self.id
    }

    pub fn size(&self) -> usize {
        self.md.size()
    }

    pub fn verify(
        &self,
        key: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
        mac: impl AsRef<[u8]>,
    ) -> Result<bool> {
        Ok(memcmp::eq(&self.prf(key, data)?, mac.as_ref()))
    }

    pub fn prf(&self, key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let pkey = PKey::hmac(key.as_ref())?;
        let mut signer = Signer::new(self.md, &pkey)?;
        signer.update(data.as_ref())?;
        Ok(signer.sign_to_vec()?)
    }

    pub fn prfplus(
        &self,
        key: impl AsRef<[u8]>,
        seed: impl AsRef<[u8]>,
        size: usize,
    ) -> Result<Vec<u8>> {
        let pkey = PKey::hmac(key.as_ref())?;
        let mut signer = Signer::new(self.md, &pkey)?;
        let mut buf = BytesMut::with_capacity(size);
        let blocks = size.div_ceil(self.md.size());
        let mut block = vec![0; self.md.size()];
        for i in 0..blocks {
            signer.update(&block)?;
            signer.update(seed.as_ref())?;
            let counter: u8 = (i + 1).try_into()?;
            signer.update(&[counter])?;
            signer.sign(&mut block)?;
            buf.put_slice(&block[..buf.remaining_mut().min(block.len())]);
        }
        Ok(buf.to_vec())
    }
}

impl From<&Prf> for Transform {
    fn from(other: &Prf) -> Self {
        Transform::new(
            Num::Assigned(TransformType::PRF.into()),
            Num::Assigned(TransformId::Prf(Num::Assigned(other.id.into())).into()),
            None::<Attribute>,
        )
    }
}

#[derive(Clone)]
pub struct Integ {
    id: IntegId,
    md: MessageDigest,
    output_size: usize,
}

impl std::fmt::Debug for Integ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Integ")
            .field("id", &self.id)
            .field("output_size", &self.output_size)
            .finish()
    }
}

impl Integ {
    pub fn new(id: IntegId) -> Result<Self> {
        let (md, output_size) = match id {
            IntegId::AUTH_HMAC_MD5_96 => (MessageDigest::md5(), 12),
            IntegId::AUTH_HMAC_SHA1_96 => (MessageDigest::sha1(), 12),
            IntegId::AUTH_HMAC_SHA2_256_128 => (MessageDigest::sha256(), 16),
            IntegId::AUTH_HMAC_SHA2_384_192 => (MessageDigest::sha384(), 24),
            IntegId::AUTH_HMAC_SHA2_512_256 => (MessageDigest::sha512(), 32),
            _ => return Err(anyhow::anyhow!("unsupported integrity checking algorithm")),
        };

        Ok(Self {
            id,
            md,
            output_size,
        })
    }

    pub fn id(&self) -> IntegId {
        self.id
    }

    pub fn sign(&self, key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let pkey = PKey::hmac(key.as_ref())?;
        let mut signer = Signer::new(self.md, &pkey)?;
        signer.update(data.as_ref())?;
        let mut signature = signer.sign_to_vec()?;
        signature.truncate(self.output_size);
        Ok(signature)
    }

    pub fn verify(
        &self,
        key: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<bool> {
        Ok(memcmp::eq(&self.sign(key, data)?, signature.as_ref()))
    }

    pub fn key_size(&self) -> usize {
        self.md.size()
    }

    pub fn output_size(&self) -> usize {
        self.output_size
    }
}

impl From<&Integ> for Transform {
    fn from(other: &Integ) -> Self {
        Transform::new(
            Num::Assigned(TransformType::INTEG.into()),
            Num::Assigned(TransformId::Integ(Num::Assigned(other.id.into())).into()),
            None::<Attribute>,
        )
    }
}

enum GroupVariant {
    Ffdh(dh::Dh<pkey::Params>),
    Ecdh(ec::EcGroup),
}

impl GroupVariant {
    fn ffdh(id: DhId) -> Result<Self> {
        let (prime, generator) = match id {
            DhId::MODP768 => (
                bn::BigNum::get_rfc2409_prime_768().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP1024 => (
                bn::BigNum::get_rfc2409_prime_1024().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP1536 => (
                bn::BigNum::get_rfc3526_prime_1536().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP2048 => (
                bn::BigNum::get_rfc3526_prime_2048().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP3072 => (
                bn::BigNum::get_rfc3526_prime_3072().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP4096 => (
                bn::BigNum::get_rfc3526_prime_4096().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP6144 => (
                bn::BigNum::get_rfc3526_prime_6144().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            DhId::MODP8192 => (
                bn::BigNum::get_rfc3526_prime_8192().unwrap(),
                bn::BigNum::from_u32(2).unwrap(),
            ),
            _ => return Err(anyhow::anyhow!("unsupported MODP group")),
        };

        Ok(Self::Ffdh(dh::Dh::from_pqg(prime, None, generator)?))
    }

    fn ecdh(id: DhId) -> Result<Self> {
        let nid = match id {
            DhId::SECP256R1 => Nid::X9_62_PRIME256V1,
            _ => return Err(anyhow::anyhow!("unsupported ECDH group")),
        };
        Ok(Self::Ecdh(ec::EcGroup::from_curve_name(nid)?))
    }

    fn new(id: DhId) -> Result<Self> {
        match id {
            DhId::MODP768
            | DhId::MODP1024
            | DhId::MODP1536
            | DhId::MODP2048
            | DhId::MODP3072
            | DhId::MODP4096 => Self::ffdh(id),
            DhId::SECP256R1 => Self::ecdh(id),
            _ => Err(anyhow::anyhow!("unsupported MODP group")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupPrivateKey {
    group: Group,
    pkey: PKey<pkey::Private>,
}

impl GroupPrivateKey {
    pub fn group(&self) -> &Group {
        &self.group
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        match *self.group.variant {
            GroupVariant::Ffdh(_) => Ok(self.pkey.dh()?.public_key().to_vec()),
            GroupVariant::Ecdh(ref group) => {
                let mut bn_ctx = bn::BigNumContext::new()?;
                Ok(self.pkey.ec_key()?.public_key().to_bytes(
                    group,
                    ec::PointConversionForm::UNCOMPRESSED,
                    &mut bn_ctx,
                )?)
            }
        }
    }

    pub fn compute_key(&self, public_key: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let public_key = match *self.group.variant {
            GroupVariant::Ffdh(ref params) => {
                let public_key = bn::BigNum::from_slice(public_key.as_ref())?;
                let dh = dh::Dh::from_pqg(
                    params.prime_p().to_owned().unwrap(),
                    None,
                    params.generator().to_owned().unwrap(),
                )?;
                let dh = dh.set_public_key(public_key)?;
                PKey::<pkey::Public>::from_dh(dh)?
            }
            GroupVariant::Ecdh(ref group) => {
                let mut bn_ctx = bn::BigNumContext::new()?;
                let point = ec::EcPoint::from_bytes(group, public_key.as_ref(), &mut bn_ctx)?;
                let key = ec::EcKey::from_public_key(group, &point)?;
                PKey::<pkey::Public>::from_ec_key(key)?
            }
        };
        let mut deriver = Deriver::new(&self.pkey)?;
        deriver.set_peer(&public_key)?;
        Ok(deriver.derive_to_vec()?)
    }
}

#[derive(Clone)]
pub struct Group {
    id: DhId,
    variant: Arc<GroupVariant>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group").field("id", &self.id).finish()
    }
}

impl Group {
    pub fn new(id: DhId) -> Result<Self> {
        let variant = GroupVariant::new(id)?;
        Ok(Self {
            id,
            variant: Arc::new(variant),
        })
    }

    pub fn id(&self) -> DhId {
        self.id
    }

    pub fn generate_key(&self) -> Result<GroupPrivateKey> {
        Ok(GroupPrivateKey {
            group: self.clone(),
            pkey: Self::generate_pkey(&self.variant)?,
        })
    }

    fn generate_pkey(variant: &GroupVariant) -> Result<PKey<pkey::Private>> {
        match variant {
            GroupVariant::Ffdh(params) => {
                let dh = dh::Dh::from_pqg(
                    params.prime_p().to_owned().unwrap(),
                    None,
                    params.generator().to_owned().unwrap(),
                )?;
                let dh = dh.generate_key()?;
                Ok(PKey::<pkey::Private>::from_dh(dh)?)
            }
            GroupVariant::Ecdh(group) => {
                let ec = ec::EcKey::generate(group)?;
                Ok(PKey::<pkey::Private>::from_ec_key(ec)?)
            }
        }
    }
}

impl From<&Group> for Transform {
    fn from(other: &Group) -> Self {
        Transform::new(
            Num::Assigned(TransformType::DH.into()),
            Num::Assigned(TransformId::Dh(Num::Assigned(other.id.into())).into()),
            None::<Attribute>,
        )
    }
}

#[derive(Clone)]
pub struct Cipher {
    id: EncrId,
    cipher: symm::Cipher,
    is_aead: bool,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher").field("id", &self.id).finish()
    }
}

impl Cipher {
    pub fn new(id: EncrId, key_size: Option<u16>) -> Result<Self> {
        let (cipher, is_aead) = match (id, key_size) {
            (EncrId::ENCR_AES_CBC, Some(128)) => (symm::Cipher::aes_128_cbc(), false),
            (EncrId::ENCR_AES_CBC, Some(256)) => (symm::Cipher::aes_256_cbc(), false),
            e => return Err(anyhow::anyhow!("unsupported cipher {:?}", e)),
        };
        Ok(Self {
            id,
            cipher,
            is_aead,
        })
    }

    pub fn key_size(&self) -> usize {
        self.cipher.key_len()
    }

    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn iv_size(&self) -> Option<usize> {
        self.cipher.iv_len()
    }

    pub fn is_aead(&self) -> bool {
        self.is_aead
    }

    pub fn id(&self) -> EncrId {
        self.id
    }

    pub fn encrypt(&self, key: impl AsRef<[u8]>, plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut iv = vec![0; self.cipher.iv_len().unwrap()];
        rand::rand_bytes(&mut iv)?;
        let mut encrypter =
            symm::Crypter::new(self.cipher, symm::Mode::Encrypt, key.as_ref(), Some(&iv))?;
        encrypter.pad(false);
        let block_size = self.cipher.block_size();
        let blocks = (plaintext.as_ref().len() + 1).div_ceil(block_size);
        let padded_size = block_size
            .checked_mul(blocks)
            .ok_or_else(|| anyhow::anyhow!("overflow"))?;
        let mut ciphertext = vec![0; block_size * blocks + block_size];

        let mut count = encrypter.update(plaintext.as_ref(), &mut ciphertext)?;
        let padding = vec![0; padded_size - plaintext.as_ref().len() - 1];
        count += encrypter.update(&padding, &mut ciphertext[count..])?;
        count += encrypter.update(&[padding.len().try_into()?], &mut ciphertext[count..])?;
        count += encrypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);
        iv.append(&mut ciphertext);

        Ok(iv)
    }

    pub fn decrypt(&self, key: impl AsRef<[u8]>, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let (iv, ciphertext) = ciphertext.as_ref().split_at(self.cipher.iv_len().unwrap());
        let mut decrypter =
            symm::Crypter::new(self.cipher, symm::Mode::Decrypt, key.as_ref(), Some(iv))?;
        decrypter.pad(false);
        let block_size = self.cipher.block_size();
        let mut plaintext = vec![0; ciphertext.len() + block_size];

        let mut count = decrypter.update(ciphertext, &mut plaintext)?;
        count += decrypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);

        let pad_len: usize = plaintext[plaintext.len() - 1].into();
        if pad_len > block_size {
            return Err(anyhow::anyhow!("invalid padding length"));
        }
        plaintext.truncate(plaintext.len() - pad_len - 1);

        Ok(plaintext)
    }
}

impl From<&Cipher> for Transform {
    fn from(other: &Cipher) -> Self {
        Transform::new(
            Num::Assigned(TransformType::ENCR.into()),
            Num::Assigned(TransformId::Encr(Num::Assigned(other.id.into())).into()),
            [Attribute::new(
                Num::Assigned(AttributeType::KeyLength.into()),
                &((other.key_size() * 8) as u16).to_be_bytes()[..],
                AttributeFormat::TV,
            )],
        )
    }
}

pub fn generate_skeyseed(
    prf: &Prf,
    n_i: impl AsRef<[u8]>,
    n_r: impl AsRef<[u8]>,
    private_key: &GroupPrivateKey,
    peer_public_key: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let g_ir = private_key.compute_key(peer_public_key)?;
    let mut buf = n_i.as_ref().to_vec();
    buf.extend_from_slice(n_r.as_ref());
    prf.prf(buf, g_ir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf() {
        let prf = Prf::new(PrfId::PRF_HMAC_SHA1).expect("unable to create PRF");
        prf.prf(&vec![0u8; 20], b"foo")
            .expect("unable to calculate PRF");
    }

    fn test_shared_secret(id: DhId) {
        let group1 = Group::new(id).expect("unable to create group");
        let group2 = Group::new(id).expect("unable to create group");
        let private_key1 = group1
            .generate_key()
            .expect("unable to generate private key");
        let private_key2 = group2
            .generate_key()
            .expect("unable to generate private key");
        let public_key1 = private_key1
            .public_key()
            .expect("unable to extract public key");
        let public_key2 = private_key2
            .public_key()
            .expect("unable to extract public key");
        let secret1 = private_key1
            .compute_key(&public_key2)
            .expect("unable to compute shared secret");
        let secret2 = private_key2
            .compute_key(&public_key1)
            .expect("unable to compute shared secret");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_ffdh() {
        test_shared_secret(DhId::MODP4096);
    }

    #[test]
    fn test_ecdh() {
        test_shared_secret(DhId::SECP256R1);
    }

    #[test]
    fn test_cipher() {
        let cipher = Cipher::new(EncrId::ENCR_AES_CBC, Some(128)).expect("");

        let key = vec![1; 16];
        let plaintext = b"hello world";
        let ciphertext = cipher.encrypt(&key, &plaintext).expect("");
        assert_eq!(
            ciphertext.len(),
            cipher.iv_size().unwrap()
                + (plaintext.len() + 1).div_ceil(cipher.block_size()) * cipher.block_size()
        );

        let plaintext2 = cipher.decrypt(&key, &ciphertext).expect("");
        assert_eq!(plaintext2, plaintext);
    }
}
