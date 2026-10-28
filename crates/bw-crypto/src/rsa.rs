//! RSA-2048：keypair 生成、org key 包裝（RSA-OAEP）。
//! Hash 演算法查證：官方 rsa.rs `encrypt_rsa2048_oaep_sha1` 用 `Oaep::<Sha1>`；
//! 密文序列化為 `4.<b64>`（UnsignedSharedKey::Rsa2048_OaepSha1_B64，
//! device_key.rs 官方測試實證）。3/5/6 型別只辨識不支援運算。

use crate::{CryptoError, OrgKey, UserKey, b64, b64_decode, envelope};
use rand::thread_rng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use zeroize::Zeroizing;

/// RSA keypair（伺服器欄位形態）：public = base64 SPKI DER，
/// private = 以 user key type 2 信封保護的 PKCS#8 DER。
#[derive(Clone, Debug)]
pub struct RsaKeyPair {
    pub public_key_b64: String,
    pub encrypted_private_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OaepHash {
    Sha1,
    Sha256,
}

pub fn generate_rsa_keypair(protect_with: &UserKey) -> Result<RsaKeyPair, CryptoError> {
    let priv_key = RsaPrivateKey::new(&mut thread_rng(), 2048).map_err(|_| CryptoError::Rsa)?;
    let pub_key = RsaPublicKey::from(&priv_key);
    let spki = pub_key.to_public_key_der().map_err(|_| CryptoError::Rsa)?;
    let pkcs8 = priv_key.to_pkcs8_der().map_err(|_| CryptoError::Rsa)?;
    let private_enc = envelope::encrypt_bytes_key(protect_with.as_bytes(), pkcs8.as_bytes())?;
    Ok(RsaKeyPair {
        public_key_b64: b64(spki.as_bytes()),
        encrypted_private_key: private_enc,
    })
}

/// 解出 PKCS#8 私鑰 DER（呼叫端用完由 Zeroizing 清零）。
pub fn decrypt_private_key(
    user_key: &UserKey,
    encrypted_private_key: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let der = envelope::decrypt_bytes_with_key(user_key.as_bytes(), encrypted_private_key)?;
    // 先確認能 parse，失敗不洩漏位置資訊。
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| CryptoError::Rsa)?;
    Ok(Zeroizing::new(der))
}

fn parse_public_key(spki_b64: &str) -> Result<RsaPublicKey, CryptoError> {
    let der = b64_decode(spki_b64)?;
    RsaPublicKey::from_public_key_der(&der).map_err(|_| CryptoError::Rsa)
}

/// RSA-OAEP 包裝任意資料（典型：64-byte org key），輸出 `4.<b64>`／`3.<b64>`。
pub fn rsa_encrypt(pub_spki_b64: &str, hash: OaepHash, data: &[u8]) -> Result<String, CryptoError> {
    let key = parse_public_key(pub_spki_b64)?;
    let mut rng = thread_rng();
    let (ct, tag) = match hash {
        OaepHash::Sha1 => (
            key.encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), data)
                .map_err(|_| CryptoError::Rsa)?,
            4u8,
        ),
        OaepHash::Sha256 => (
            key.encrypt(&mut rng, rsa::Oaep::new::<sha2::Sha256>(), data)
                .map_err(|_| CryptoError::Rsa)?,
            3u8,
        ),
    };
    Ok(format!("{tag}.{}", b64(&ct)))
}

/// RSA-OAEP 解包 `4.`/`3.` 密文。
pub fn rsa_decrypt(private_pkcs8: &[u8], wrapped: &str) -> Result<Vec<u8>, CryptoError> {
    let (tag, body) = wrapped.split_once('.').ok_or(CryptoError::BadB64)?;
    let ct = b64_decode(body)?;
    let key = RsaPrivateKey::from_pkcs8_der(private_pkcs8).map_err(|_| CryptoError::Rsa)?;
    match tag {
        "4" => key
            .decrypt(rsa::Oaep::new::<sha1::Sha1>(), &ct)
            .map_err(|_| CryptoError::Rsa),
        "3" => key
            .decrypt(rsa::Oaep::new::<sha2::Sha256>(), &ct)
            .map_err(|_| CryptoError::Rsa),
        other => {
            let n = other.parse::<u8>().map_err(|_| CryptoError::BadB64)?;
            Err(CryptoError::UnknownCipherType(n))
        }
    }
}

/// 邀請/輪播流：用使用者 RSA 公鑰（OAEP-SHA1）包裝 org key。
pub fn wrap_org_key(user_public_b64: &str, org_key: &OrgKey) -> Result<String, CryptoError> {
    rsa_encrypt(user_public_b64, OaepHash::Sha1, org_key.as_bytes())
}

/// 對稱路徑：org key 在伺服器上以 user key type 2 信封保護。
pub fn unwrap_org_key(user_key: &UserKey, encrypted_org_key: &str) -> Result<OrgKey, CryptoError> {
    let raw = envelope::decrypt_bytes_with_key(user_key.as_bytes(), encrypted_org_key)?;
    OrgKey::from_bytes(raw)
}

/// 非對稱路徑：用剛解出的 PKCS#8 私鑰把 `4.` 包裝的 org key 還原。
pub fn unwrap_org_key_rsa(
    private_pkcs8: &[u8],
    wrapped_org_key: &str,
) -> Result<OrgKey, CryptoError> {
    let raw = rsa_decrypt(private_pkcs8, wrapped_org_key)?;
    OrgKey::from_bytes(raw)
}

impl OrgKey {
    /// 以 user key type 2 信封包裝（上傳 `organizations/{id}/crypto/keys` 的形態）。
    pub fn encrypt_with_user_key(&self, user_key: &UserKey) -> Result<String, CryptoError> {
        envelope::encrypt_bytes_key(user_key.as_bytes(), self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key64() -> UserKey {
        UserKey::from_bytes((0u8..64).collect()).unwrap()
    }

    #[test]
    fn keypair_and_org_key_wrap_roundtrip() {
        let uk = key64();
        let pair = generate_rsa_keypair(&uk).unwrap();
        assert!(pair.public_key_b64.len() > 300);
        assert!(pair.encrypted_private_key.starts_with("2."));

        let pkcs8 = decrypt_private_key(&uk, &pair.encrypted_private_key).unwrap();
        let org = OrgKey::from_bytes((100u8..164).collect()).unwrap();
        let wrapped = wrap_org_key(&pair.public_key_b64, &org).unwrap();
        assert!(wrapped.starts_with("4."));
        let unwrapped = unwrap_org_key_rsa(&pkcs8, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), org.as_bytes());

        // 對稱路徑（org key 以 user key 保護）。
        let enc = org.encrypt_with_user_key(&uk).unwrap();
        let back = unwrap_org_key(&uk, &enc).unwrap();
        assert_eq!(back.as_bytes(), org.as_bytes());
    }

    #[test]
    fn oaep_sha256_variant() {
        let uk = key64();
        let pair = generate_rsa_keypair(&uk).unwrap();
        let pkcs8 = decrypt_private_key(&uk, &pair.encrypted_private_key).unwrap();
        let w = rsa_encrypt(&pair.public_key_b64, OaepHash::Sha256, b"seed").unwrap();
        assert!(w.starts_with("3."));
        assert_eq!(rsa_decrypt(&pkcs8, &w).unwrap(), b"seed");
    }
}
