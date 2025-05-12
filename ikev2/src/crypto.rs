use crate::message::num::{DhId, EncrId, PrfId};
use anyhow::Result;
use bytes::{BufMut, BytesMut};

use openssl::{
    bn,
    derive::Deriver,
    dh, ec,
    hash::{Hasher, MessageDigest, hash},
    nid::Nid,
    pkey::{self, PKey},
    pkey_ctx::PkeyCtx,
    rand,
    sign::Signer,
    symm,
};

pub(crate) fn rand_bytes(buf: &mut [u8]) -> Result<()> {
    Ok(rand::rand_bytes(buf)?)
}

pub struct Prf {
    md: MessageDigest,
}

impl Prf {
    pub fn new(id: PrfId) -> Result<Self> {
        let md = match id {
            PrfId::PRF_HMAC_MD5 => MessageDigest::md5(),
            PrfId::PRF_HMAC_SHA1 => MessageDigest::sha1(),
            _ => return Err(anyhow::anyhow!("unsupported PRF")),
        };

        Ok(Self { md })
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
        let blocks = (size + (self.md.size() - 1)) / self.md.size();
        let mut block = Vec::with_capacity(self.md.size());
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

enum GroupType {
    Ffdh(dh::Dh<pkey::Params>),
    Ecdh(ec::EcGroup),
}

impl GroupType {
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

pub struct Group {
    type_: GroupType,
    pkey: PKey<pkey::Private>,
}

impl Group {
    pub fn new(id: DhId) -> Result<Self> {
        let type_ = GroupType::new(id)?;
        let pkey = Self::generate_key(&type_)?;
        Ok(Self { type_, pkey })
    }

    fn generate_key(type_: &GroupType) -> Result<PKey<pkey::Private>> {
        match type_ {
            GroupType::Ffdh(params) => {
                let dh = dh::Dh::from_pqg(
                    params.prime_p().to_owned().unwrap(),
                    None,
                    params.generator().to_owned().unwrap(),
                )?;
                let dh = dh.generate_key()?;
                Ok(PKey::<pkey::Private>::from_dh(dh)?)
            }
            GroupType::Ecdh(group) => {
                let ec = ec::EcKey::generate(group)?;
                Ok(PKey::<pkey::Private>::from_ec_key(ec)?)
            }
        }
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        match self.type_ {
            GroupType::Ffdh(_) => Ok(self.pkey.dh()?.public_key().to_vec()),
            GroupType::Ecdh(ref group) => {
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
        let public_key = match self.type_ {
            GroupType::Ffdh(ref params) => {
                let public_key = bn::BigNum::from_slice(public_key.as_ref())?;
                let dh = dh::Dh::from_pqg(
                    params.prime_p().to_owned().unwrap(),
                    None,
                    params.generator().to_owned().unwrap(),
                )?;
                let dh = dh.set_public_key(public_key)?;
                PKey::<pkey::Public>::from_dh(dh)?
            }
            GroupType::Ecdh(ref group) => {
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

pub struct Cipher {
    cipher: symm::Cipher,
    iv: Vec<u8>,
}

impl Cipher {
    pub fn new(id: EncrId, key_size: Option<u16>) -> Result<Self> {
        let cipher = match (id, key_size) {
            (EncrId::ENCR_AES_CBC, Some(128)) => symm::Cipher::aes_128_cbc(),
            (EncrId::ENCR_AES_CBC, Some(256)) => symm::Cipher::aes_256_cbc(),
            _ => return Err(anyhow::anyhow!("unsupported cipher")),
        };
        let mut iv = vec![0; cipher.iv_len().unwrap()];
        rand::rand_bytes(&mut iv)?;
        Ok(Self { cipher, iv })
    }

    pub fn encrypt(&self, key: impl AsRef<[u8]>, plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut encrypter = symm::Crypter::new(
            self.cipher.clone(),
            symm::Mode::Encrypt,
            key.as_ref(),
            Some(&self.iv),
        )?;
        encrypter.pad(false);
        let block_size = self.cipher.block_size();
        let blocks = (plaintext.as_ref().len() + 1 + block_size - 1) / block_size;
        let mut ciphertext = vec![0; block_size * blocks + block_size];

        let mut count = encrypter.update(plaintext.as_ref(), &mut ciphertext)?;
        let buf = vec![0; block_size * blocks - plaintext.as_ref().len() - 1];
        count += encrypter.update(&buf, &mut ciphertext[count..])?;
        let pad_len: u8 = buf.len().try_into()?;
        count += encrypter.update(&[pad_len], &mut ciphertext[count..])?;
        count += encrypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);

        Ok(ciphertext)
    }

    pub fn decrypt(&self, key: impl AsRef<[u8]>, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut decrypter = symm::Crypter::new(
            self.cipher.clone(),
            symm::Mode::Decrypt,
            key.as_ref(),
            Some(&self.iv),
        )?;
        decrypter.pad(false);
        let block_size = self.cipher.block_size();
        let mut plaintext = vec![0; ciphertext.as_ref().len() + block_size];

        let mut count = decrypter.update(ciphertext.as_ref(), &mut plaintext)?;
        count += decrypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);

        let pad_len: usize = plaintext[plaintext.len() - 1].into();
        plaintext.truncate(plaintext.len() - pad_len - 1);

        Ok(plaintext)
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }
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

    #[test]
    fn test_ffdh() {
        let group1 = Group::new(DhId::MODP4096).expect("unable to create group");
        let group2 = Group::new(DhId::MODP4096).expect("unable to create group");
        let public_key1 = group1.public_key().expect("unable to extract public key");
        let public_key2 = group2.public_key().expect("unable to extract public key");
        let secret1 = group1
            .compute_key(&public_key2)
            .expect("unable to compute shared secret");
        let secret2 = group2
            .compute_key(&public_key1)
            .expect("unable to compute shared secret");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_ecdh() {
        let group1 = Group::new(DhId::SECP256R1).expect("unable to create group");
        let group2 = Group::new(DhId::SECP256R1).expect("unable to create group");
        let public_key1 = group1.public_key().expect("unable to extract public key");
        let public_key2 = group2.public_key().expect("unable to extract public key");
        let secret1 = group1
            .compute_key(&public_key2)
            .expect("unable to compute shared secret");
        let secret2 = group2
            .compute_key(&public_key1)
            .expect("unable to compute shared secret");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_cipher() {
        let cipher = Cipher::new(EncrId::ENCR_AES_CBC, Some(128)).expect("");
        assert_eq!(cipher.iv().len(), 16);

        let key = vec![1; 16];
        let plaintext = b"hello world";
        let ciphertext = cipher.encrypt(&key, &plaintext).expect("");
        assert_eq!(ciphertext.len(), ((plaintext.len() + 15) / 16) * 16);

        let plaintext2 = cipher.decrypt(&key, &ciphertext).expect("");
        assert_eq!(plaintext2, plaintext);
    }
}
