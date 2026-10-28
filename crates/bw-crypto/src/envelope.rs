//! Bitwarden 信封字串 `type.iv|ct|mac`：解析、生成、MAC-then-check。
//! type 2 = AES-256-CBC(PKCS#7) + HMAC-SHA256(mac_key, iv‖ct)（Encrypt-then-MAC）。
//! 佈局來源：bitwarden-crypto 4.0.0 `aes256_cbc_hmac_sha256_ae.rs`、
//! `enc_string/symmetric.rs`（見 NOTES.md URL）。

use crate::{CryptoError, UserKey, b64, b64_decode};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::Mac;
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherType {
    /// 0：AES-256-CBC，無認證（legacy，只解析不生成）。
    Aes256Cbc = 0,
    /// 1：AES-128-CBC + HMAC-SHA256（遠古 legacy，只解析）。
    Aes128CbcHmacSha256 = 1,
    /// 2：AES-256-CBC + HMAC-SHA256，現行唯一生成格式。
    Aes256CbcHmacSha256 = 2,
}

/// 已解析的信封 constituent（base64 段已解碼）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncParts {
    pub cipher_type: CipherType,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

pub fn parse_enc_str(s: &str) -> Result<EncParts, CryptoError> {
    let (head, rest) = s.split_once('.').ok_or(CryptoError::BadB64)?;
    let cipher_type = match head {
        "0" => CipherType::Aes256Cbc,
        "1" => CipherType::Aes128CbcHmacSha256,
        "2" => CipherType::Aes256CbcHmacSha256,
        other => {
            let n = other.parse::<u8>().map_err(|_| CryptoError::BadB64)?;
            return Err(CryptoError::UnknownCipherType(n));
        }
    };
    let parts: Vec<&str> = rest.split('|').collect();
    let (iv, ct, mac) = match (cipher_type, parts.len()) {
        (CipherType::Aes256Cbc, 2) => (b64_decode(parts[0])?, b64_decode(parts[1])?, None),
        (CipherType::Aes128CbcHmacSha256 | CipherType::Aes256CbcHmacSha256, 3) => (
            b64_decode(parts[0])?,
            b64_decode(parts[1])?,
            Some(b64_decode(parts[2])?),
        ),
        _ => return Err(CryptoError::BadB64),
    };
    Ok(EncParts {
        cipher_type,
        iv,
        ct,
        mac,
    })
}

fn format_parts(
    cipher_type: CipherType,
    iv: &[u8],
    ct: &[u8],
    mac: Option<&[u8]>,
) -> Result<String, CryptoError> {
    let mut s = format!("{}.{}|", cipher_type as u8, b64(iv));
    s.push_str(&b64(ct));
    if let Some(m) = mac {
        s.push('|');
        s.push_str(&b64(m));
    }
    Ok(s)
}

fn calculate_mac(mac_key: &[u8], iv: &[u8], ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hmac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac_key)
        .expect("mac key is always 32 bytes");
    hmac.update(iv);
    hmac.update(ct);
    Zeroizing::new(hmac.finalize().into_bytes().into())
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let pt = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| CryptoError::BadPadding)?;
    Ok(pt)
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .encrypt_padded_vec_mut::<Pkcs7>(pt))
}

/// 依密文型別把 composite key 拆成 (enc, mac)。
/// 64 bytes：enc=k[0..32]、mac=k[32..64]；32 bytes（legacy）：
/// type 0 enc=k[0..32]；type 1 enc=k[0..16]、mac=k[16..32]。
/// 64-byte key 配 type 0 一律拒絕——防「去掉 MAC 段」的降級攻擊
/// （官方 test_decrypt_downgrade_encstring_prevention）。
fn split_key(key: &[u8], t: CipherType) -> Result<(&[u8], Option<&[u8]>), CryptoError> {
    match (t, key.len()) {
        (CipherType::Aes256CbcHmacSha256, 64) => Ok((&key[0..32], Some(&key[32..64]))),
        (CipherType::Aes128CbcHmacSha256, 64) => Ok((&key[0..16], Some(&key[32..64]))),
        (CipherType::Aes128CbcHmacSha256, 32) => Ok((&key[0..16], Some(&key[16..32]))),
        (CipherType::Aes256Cbc, 32) => Ok((&key[0..32], None)),
        _ => Err(CryptoError::KeyTypeMismatch(key.len())),
    }
}

pub(crate) fn decrypt_bytes_with_key(key: &[u8], c: &str) -> Result<Vec<u8>, CryptoError> {
    let parsed = parse_enc_str(c)?;
    decrypt_with_raw_key(key, &parsed)
}

/// 以 composite key bytes（32 或 64）解密已解析信封；MAC 先驗、常數時間比對。
pub fn decrypt_with_raw_key(key: &[u8], p: &EncParts) -> Result<Vec<u8>, CryptoError> {
    let (enc_key, mac_key) = split_key(key, p.cipher_type)?;
    if let Some(mac) = &p.mac {
        let mac_key = mac_key.ok_or(CryptoError::KeyTypeMismatch(key.len()))?;
        // hmac::Mac::verify_slice 為常數時間比較。
        let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac_key)
            .expect("mac key is 32 bytes");
        m.update(&p.iv);
        m.update(&p.ct);
        m.verify_slice(mac).map_err(|_| CryptoError::MacMismatch)?;
    } else if mac_key.is_some() {
        // 有 mac 子鑰卻收到無 MAC 密文：降級攻擊。
        return Err(CryptoError::KeyTypeMismatch(key.len()));
    }
    if p.cipher_type == CipherType::Aes128CbcHmacSha256 {
        aes_cbc128_decrypt(enc_key, &p.iv, &p.ct)
    } else {
        aes_cbc_decrypt(enc_key, &p.iv, &p.ct)
    }
}

fn aes_cbc128_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pt = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| CryptoError::BadPadding)?;
    Ok(pt)
}

/// type 2 生成（key 必須是 64 bytes composite）。隨機 IV。
pub(crate) fn encrypt_bytes_key(key: &[u8], plaintext: &[u8]) -> Result<String, CryptoError> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    encrypt_with_iv(key, &iv, plaintext)
}

/// 指定 IV 的 type 2 生成（KAT/除錯用；出貨路徑用隨機 IV）。
pub fn encrypt_with_iv(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<String, CryptoError> {
    let (enc_key, mac_key) = split_key(key, CipherType::Aes256CbcHmacSha256)?;
    let mac_key = mac_key.expect("type 2 always has mac key");
    let ct = aes_cbc_encrypt(enc_key, iv, plaintext)?;
    let mac = calculate_mac(mac_key, iv, &ct);
    format_parts(CipherType::Aes256CbcHmacSha256, iv, &ct, Some(&mac[..]))
}

pub fn encrypt_bytes(k: &UserKey, plaintext: &[u8]) -> Result<String, CryptoError> {
    encrypt_bytes_key(k.as_bytes(), plaintext)
}

pub fn decrypt_bytes(k: &UserKey, c: &str) -> Result<Vec<u8>, CryptoError> {
    decrypt_bytes_with_key(k.as_bytes(), c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key64() -> UserKey {
        UserKey::from_bytes((0u8..64).collect::<Vec<u8>>()).unwrap()
    }

    #[test]
    fn roundtrip_and_mac_tamper() {
        let k = key64();
        let enc = encrypt_bytes(&k, b"hello bitward").unwrap();
        assert!(enc.starts_with("2."));
        assert_eq!(decrypt_bytes(&k, &enc).unwrap(), b"hello bitward");

        let mut parts: Vec<String> = enc
            .split('.')
            .nth(1)
            .unwrap()
            .split('|')
            .map(str::to_string)
            .collect();
        let mut mac = b64_decode(&parts[2]).unwrap();
        mac[0] ^= 1;
        parts[2] = b64(&mac);
        let tampered = format!("2.{}", parts.join("|"));
        assert!(matches!(
            decrypt_bytes(&k, &tampered),
            Err(CryptoError::MacMismatch)
        ));
    }

    #[test]
    fn rejects_bad_shapes() {
        assert!(parse_enc_str("9.iv|ct").is_err());
        assert!(parse_enc_str("junk").is_err());
        assert!(parse_enc_str("2.aGVhZA==|Y3Q=").is_err()); // type 2 缺 mac 段
        assert!(parse_enc_str("2.@@@@|Y3Q=|bWFj").is_err()); // 非法 base64
    }

    #[test]
    fn downgrade_prevention() {
        let k = key64();
        // 64-byte key 遇到 type 0 應拒絕（官方 WrongKeyType 語意）。
        let e = decrypt_bytes_with_key(
            k.as_bytes(),
            "0.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==",
        );
        assert!(matches!(e, Err(CryptoError::KeyTypeMismatch(64))));
    }
}
