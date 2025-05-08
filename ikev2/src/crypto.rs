use crate::message::num::PrfId;
use anyhow::Result;
use bytes::{BufMut, BytesMut};

use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest, hash},
    md::Md,
    memcmp,
    nid::Nid,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};

fn prf_nid(id: PrfId) -> Result<Nid> {
    match id {
        PrfId::PRF_HMAC_MD5 => Ok(Nid::HMAC_MD5),
        PrfId::PRF_HMAC_SHA1 => Ok(Nid::HMAC_SHA1),
        _ => Err(anyhow::anyhow!("unsupported PRF")),
    }
}

pub fn prf(id: PrfId, key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let nid = prf_nid(id)?;
    let md = MessageDigest::from_nid(nid).ok_or_else(|| anyhow::anyhow!("unknown NID"))?;
    let mac_key = PKey::hmac(key.as_ref())?;
    let mut signer = Signer::new(md, &mac_key)?;
    signer.update(data.as_ref())?;
    signer.sign_to_vec().map_err(From::from)
}

pub fn prfplus(
    id: PrfId,
    key: impl AsRef<[u8]>,
    seed: impl AsRef<[u8]>,
    size: usize,
) -> Result<Vec<u8>> {
    let nid = prf_nid(id)?;
    let md = MessageDigest::from_nid(nid).ok_or_else(|| anyhow::anyhow!("unknown NID"))?;
    let mac_key = PKey::hmac(key.as_ref())?;
    let mut signer = Signer::new(md, &mac_key)?;
    let mut buf = BytesMut::with_capacity(size);
    let blocks = (size + (md.size() - 1)) / md.size();
    let mut block = Vec::with_capacity(md.size());
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
