use crate::message::num::{DhId, EncrId, IntegId, PrfId};
use anyhow::Result;
use bytes::{BufMut, BytesMut};

use openssl::{
    bn,
    derive::Deriver,
    dh, ec,
    hash::MessageDigest,
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

pub struct Prf {
    id: PrfId,
    md: MessageDigest,
}

impl Prf {
    pub fn new(id: PrfId) -> Result<Self> {
        let md = match id {
            PrfId::PRF_HMAC_MD5 => MessageDigest::md5(),
            PrfId::PRF_HMAC_SHA1 => MessageDigest::sha1(),
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

pub struct Integ {
    md: MessageDigest,
    output_size: usize,
}

impl Integ {
    pub fn new(id: IntegId) -> Result<Self> {
        let (md, output_size) = match id {
            IntegId::AUTH_HMAC_MD5_96 => (MessageDigest::md5(), 12),
            IntegId::AUTH_HMAC_SHA1_96 => (MessageDigest::sha1(), 12),
            _ => return Err(anyhow::anyhow!("unsupported integrity checking")),
        };

        Ok(Self { md, output_size })
    }

    pub fn key_size(&self) -> usize {
        self.md.size()
    }

    pub fn output_size(&self) -> usize {
        self.output_size
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

#[derive(Clone)]
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

pub struct Cipher {
    cipher: symm::Cipher,
    iv: Vec<u8>,
    is_aead: bool,
}

impl Cipher {
    pub fn new(id: EncrId, key_size: Option<u16>) -> Result<Self> {
        let (cipher, is_aead) = match (id, key_size) {
            (EncrId::ENCR_AES_CBC, Some(128)) => (symm::Cipher::aes_128_cbc(), false),
            (EncrId::ENCR_AES_CBC, Some(256)) => (symm::Cipher::aes_256_cbc(), false),
            _ => return Err(anyhow::anyhow!("unsupported cipher")),
        };
        let mut iv = vec![0; cipher.iv_len().unwrap()];
        rand::rand_bytes(&mut iv)?;
        Ok(Self {
            cipher,
            iv,
            is_aead,
        })
    }

    pub fn key_size(&self) -> usize {
        self.cipher.key_len()
    }

    pub fn is_aead(&self) -> bool {
        self.is_aead
    }

    pub fn encrypt(&self, key: impl AsRef<[u8]>, plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut encrypter = symm::Crypter::new(
            self.cipher,
            symm::Mode::Encrypt,
            key.as_ref(),
            Some(&self.iv),
        )?;
        encrypter.pad(false);
        let block_size = self.cipher.block_size();
        let blocks = (plaintext.as_ref().len() + 1).div_ceil(block_size);
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
            self.cipher,
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

pub(crate) fn generate_skeyseed(
    prf: &Prf,
    n_i: impl AsRef<[u8]>,
    n_r: impl AsRef<[u8]>,
    private_key: &GroupPrivateKey,
    peer_public_key: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let g_ir = private_key.compute_key(peer_public_key)?;
    let mut n_i_n_r = n_i.as_ref().to_vec();
    n_i_n_r.extend_from_slice(n_r.as_ref());
    prf.prf(n_i_n_r, g_ir)
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
        assert_eq!(cipher.iv().len(), 16);

        let key = vec![1; 16];
        let plaintext = b"hello world";
        let ciphertext = cipher.encrypt(&key, &plaintext).expect("");
        assert_eq!(ciphertext.len(), ((plaintext.len() + 15) / 16) * 16);

        let plaintext2 = cipher.decrypt(&key, &ciphertext).expect("");
        assert_eq!(plaintext2, plaintext);
    }
}
