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

/// 解析 RSA 公開金鑰：接受 b64 DER(SPKI) 或 PEM 裝甲（伺服器上使用者/org
/// 公開金鑰的實際形態是 `-----BEGIN PUBLIC KEY-----` PEM；官方 client
/// `CryptoFunctionService.rsaDeserializePublicKey` 同样是去頭尾再 b64）。
fn parse_public_key(s: &str) -> Result<RsaPublicKey, CryptoError> {
    let body: String = s
        .lines()
        .filter(|l| !l.trim().starts_with("-----"))
        .collect::<String>();
    let der = b64_decode(body.trim())?;
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

    /// 互操作金標：密文由外部工具（LibreSSL `openssl rsautl -oaep`＝OAEP-SHA1）
    /// 產生、私鑰 PKCS#8——證明與官方 WebCrypto RSA-OAEP-SHA1 線格式互通，
    /// 非自家 real 環自我循環。
    #[test]
    fn interop_openssl_oaep_sha1_vector() {
        let pem_b64 = concat!(
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgTUV2PTzrACgI",
            "oURq0c3OnCKSqhWElDVBJDuktny3e1ra1O2nlAGN76bKOEaH0EJKjCGIM2cTW4TD",
            "S3Vw+H5kDvCG177lXVL+La1bWIwOSiW0SOwZuBVEfortk0n9eVdfwaW4vXfgfZbW",
            "B/YVtusDQHhpqq4vtnEk6Grectptzu+JcyCc/qasGV1EVGMMuQVCFRw2hcExgetj",
            "LPaDw4YpL7ZBFuZ328AG+lXRpj86GkZUo5kjGy3Ej+sZHJ9qUX6/0ZKQs9l1RF/y",
            "wWZFThBATLFXDek06wj5nmdEUy7POTZ+Ed7BxvsqwTEaA2Xs6ZBQeF8EwWUWpz6l",
            "zBJ66pblAgMBAAECggEBAJNxN9/pkUnI6IgDuj2dfHP8Hp3aQBrOcdNIRgyYCJNz",
            "+t0uaqplmD/88N6s73AHbgwi4UfuwirvVe4qhCCmuC59w45f85RCLHP5AqOxKR+b",
            "jf1ckha18wT7Scexskl0ogLIAG/X3B0tcSFwSksr2oBguMZ889NZUja4sMdZKExV",
            "J6BtasRMZCdDtYpTgMTkCiNTgqvvg/uigU0uqUepDl2YQBHa/NSbFcGvHHjQRnef",
            "jJr9h83SR+erRidt+VA9gB5Ak91XaffkUVOSrYtwcVU77/7z8N1OMmj98/BFdSox",
            "D72c57A43x6pfy+cC9zF11QsE8MnoxpSJhdi0A9plGECgYEA/ALcFUP7x3RXPBmK",
            "H2cQ9CDE3prpvhiCMVTMnGUBwcB5I6I3LWtUWfC/5anUj334SxP6/u2++LWFy5GV",
            "Z6wIphLeCJGdjUoacBF6V5G5IgvxPL+5Sa56YBJdc0srDAGHWR/DdnQwN/VaUFuo",
            "WF0pguIAiySB0GbC97y6zj7U6kcCgYEA49oiaTpab9vRXHXlcDyc/vlMl45JDmSw",
            "1FjrIPzY7kB0mhJga4O1+TFwgF3wNgjTX6QNCWIhRZdEzL9Ed8ohAZWzTPfXdFf0",
            "x9o3ymYCYrCkQTs5JXvkUzHLHvWhbKJlmZXB2Wqh19fvhOQJBtqFCBhal1zgassN",
            "lhofb8SDX3MCgYAJrMJuPpHn8lt2/zQCSJ6qAKgOM7xNg/tbkXnZdzc+DPmZmJyt",
            "rbUrTsbPNlnmuFtT5ox4RQBT5AQi8I/fzwb1+Tt08MIvrmydaM5dlkaZPAQi5Olk",
            "HsKr9YiI6JXafCSKE2IZphRD0bOJ6jroSYtSbwK+VMR3D7rkb+ZsDJV3+QKBgCmZ",
            "QKEPi0VSz5Ve3OWx20PdxfMBgisDjRknpr3eC8jrsZ4TbtESOd3l/dEh1WI4GEck",
            "z1CAPuzSojfzT4/DMmV0rEiIEyjligYWvArSturHryVNp7BFPzlFJP1hAPixaXUx",
            "1zNXeXbLsKoFa/R5XsJMl/V8emhk6/UUjdq8+PMrAoGBAK1dOUf6UXi9C2/cCjuI",
            "HEG5U4OC+zmp9yg7LsiH/IKputAUCZJCpt1qE0ESoZvXh6bcOsqBguqM+3seloKn",
            "hTc/dDRGdDOZF03piHzC4d6zR8T4c++crS3pOR585A94DmGDBm89sCXgHSEscnPX",
            "3NQuTbv3T7B1UysaMSX8yJNm",
        );
        let der = b64_decode(pem_b64).unwrap();
        let want = b64_decode("s9yr9SAsBQp/saBPX1JVBrzcftqHtUJ6pNKVXH1iFum45l+VtY2bj9kr+R37XqYnTLiKMPvXzwR4TpYJpHbtuw==").unwrap();
        let got = unwrap_org_key_rsa(&der, "4.xBMyA53zvoq1fDkl3JYTbkuevBjZvtrUHDHGZLlReEkfvfzjB6FRCfMnS+AOmkZEpNAfivBMBZjeBbkkKBGZcxnBvNw59k1yNIYIpneqXHKEtCNtIXbN2zDaR7FHKDUUnkx2kshxxSn0VlUyRhygsEallmLd9NXBFClZNHb0GHXtSGyZ0v6Qw+KN0sH7g2YZNsYWHhbOWgMm/tM3tOfSRCKu7AHUc4Qj5afvJNnCiIk7eenEx4qgI1p06F09C3GXgOBgh86MXkDqV39uFU6a5YlC2UN22zSjBouxMe6aV7qXXGHv6jT2ItM1jr2hunato+vmiuriQ7R3srdJ1Qq26w==").unwrap();
        assert_eq!(got.as_bytes(), want.as_slice());
    }

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

    #[test]
    fn public_key_accepts_pem_armor() {
        // 伺服器實際存的公開金鑰是 PEM 裝甲（GET /public-key/{email}）；
        // 同一把鑰的 b64 與 PEM 兩種形態必須都能包。
        let uk = key64();
        let pair = generate_rsa_keypair(&uk).unwrap();
        let der = b64_decode(&pair.public_key_b64).unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            b64(&der)
        );
        let org = OrgKey::from_bytes((100u8..164).collect()).unwrap();
        let from_pem = wrap_org_key(&pem, &org).unwrap();
        let pkcs8 = decrypt_private_key(&uk, &pair.encrypted_private_key).unwrap();
        assert_eq!(
            unwrap_org_key_rsa(&pkcs8, &from_pem).unwrap().as_bytes(),
            org.as_bytes()
        );
    }
}
