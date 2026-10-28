//! 自寫 Bitwarden 金鑰派生與信封加解密（契約 §3.1、§0 授權列）。
//! 編排自寫、原語用 rustcrypto；本 crate 不得 use 任何網路/IO 型別（A10）。
//!
//! 互通性參數全部以官方實作原始碼為準（來源 URL 與版本對照見 NOTES.md）：
//! - KDF：PBKDF2-SHA256（salt=trim+lowercase(email)，預設 600,000）或
//!   Argon2id（BLAKE2b core，salt=SHA-256(email)，預設 m=32MiB, t=6, p=4）。
//! - master password hash：PBKDF2-SHA256(mk, password, 1 次, 32 bytes)。
//! - stretch：HKDF-SHA256 **Expand-only**（mk 直接作 PRK），info="enc"/"mac"。
//! - 信封：type 2 = AES-256-CBC(PKCS#7) + HMAC-SHA256(mac_key, iv‖ct)，
//!   Encrypt-then-MAC、驗證先於解密；type 0/1 為 legacy 只解析不生成。

mod envelope;
mod generator;
mod kdf;
mod rsa;
mod totp;

pub(crate) use kdf::{b64, b64_decode};

pub use envelope::{
    CipherType, EncParts, decrypt_bytes, decrypt_with_raw_key, encrypt_bytes, encrypt_with_iv,
    parse_enc_str,
};
pub use generator::{PasswordOptions, generate_password};
pub use kdf::{
    DEFAULT_ARGON2_M_MIB, DEFAULT_ARGON2_P, DEFAULT_ARGON2_T, DEFAULT_PBKDF2_ITERATIONS,
    MAX_PBKDF2_ITERATIONS, MIN_ARGON2_M_MIB, MIN_ARGON2_P, MIN_ARGON2_T, MIN_PBKDF2_ITERATIONS,
    argon2id_raw, pbkdf2_sha256_raw,
};
pub use rsa::{
    OaepHash, RsaKeyPair, decrypt_private_key, generate_rsa_keypair, rsa_decrypt, rsa_encrypt,
    unwrap_org_key, unwrap_org_key_rsa, wrap_org_key,
};
pub use totp::{
    Otpauth, TotpAlgorithm, TotpParams, generate_uri as totp_generate_uri, parse_otpauth,
    totp_code_with,
};

use bw_proto::EncStr;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("mac mismatch")]
    MacMismatch,
    #[error("unknown cipher type {0}")]
    UnknownCipherType(u8),
    #[error("bad base64")]
    BadB64,
    #[error("kdf unsupported")]
    KdfUnsupported,
    #[error("padding invalid")]
    BadPadding,
    #[error("key length {0} incompatible with cipher type")]
    KeyTypeMismatch(usize),
    #[error("insufficient kdf parameters")]
    InsufficientKdfParameters,
    #[error("invalid key material")]
    InvalidKey,
    #[error("rsa failure")]
    Rsa,
    #[error("invalid base32")]
    BadBase32,
    #[error("invalid otpauth uri")]
    BadOtpauthUri,
    #[error("invalid totp parameters")]
    BadTotpParams,
    #[error("no character set enabled")]
    NoCharacterSetEnabled,
    #[error("invalid password length")]
    InvalidLength,
    #[error("decrypted content is not utf-8")]
    NotUtf8,
}

/// KDF 輸出（32 bytes）。Debug 一律 REDACTED（契約 §2.7 型別紀律）。
#[derive(Clone)]
pub struct MasterKey(Vec<u8>);
/// HKDF stretch 後的 64 bytes（enc‖mac）。
#[derive(Clone)]
pub struct StretchedKey(Vec<u8>);
/// User key（64 bytes enc‖mac；legacy 帳號可能是 32 bytes）。
#[derive(Clone)]
pub struct UserKey(Vec<u8>);
/// 組織金鑰（與 user key 同形的 64 bytes 對稱金鑰）。
#[derive(Clone)]
pub struct OrgKey(Vec<u8>);
/// 送給伺服器的 master password hash（base64）。
#[derive(Clone)]
pub struct PasswordHash(String);

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterKey").finish_non_exhaustive()
    }
}
impl core::fmt::Debug for StretchedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StretchedKey").finish_non_exhaustive()
    }
}
impl core::fmt::Debug for UserKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserKey").finish_non_exhaustive()
    }
}
impl core::fmt::Debug for OrgKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OrgKey").finish_non_exhaustive()
    }
}
impl core::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordHash").finish_non_exhaustive()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for StretchedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for UserKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for OrgKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl MasterKey {
    /// 直接以已派生的 32 bytes 構造（Key Connector / 封存金鑰解包路徑）。
    pub fn from_bytes(b: Vec<u8>) -> Result<Self, CryptoError> {
        if b.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(b))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl StretchedKey {
    pub(crate) fn from_parts(enc: Vec<u8>, mac: Vec<u8>) -> Self {
        let mut v = enc;
        let mut mac = mac;
        v.append(&mut mac);
        Self(v)
    }
    /// 64 bytes：enc（前 32）‖ mac（後 32）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl UserKey {
    /// 32（legacy AES-CBC-only）或 64（AES-CBC+HMAC）bytes 的官方 legacy key 序列化。
    pub fn from_bytes(b: Vec<u8>) -> Result<Self, CryptoError> {
        if b.len() != 32 && b.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(b))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl OrgKey {
    pub fn from_bytes(b: Vec<u8>) -> Result<Self, CryptoError> {
        if b.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(b))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PasswordHash {
    /// base64（32 bytes HMAC-SHA256 輸出），送 identity 端點用。
    pub fn as_b64(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id { m: u32, t: u32, p: u32 },
}

/// 契約 §3.1（U3 實作；簽名凍結）。
pub fn master_key(pw: &str, email: &str, kdf: KdfParams) -> Result<MasterKey, CryptoError> {
    kdf::master_key(pw, email, kdf)
}

/// 客戶端層 master password hash：PBKDF2-SHA256(mk, password, 1, 32)。
/// ServerAuthorization=1 次；本函数即登入/prelogin 用的那一層。
pub fn master_password_hash(mk: &MasterKey, pw: &str) -> PasswordHash {
    kdf::master_password_hash(mk, pw)
}

/// 同 hash，但 LocalAuthorization 用途（iterations=2，解鎖本地鏡像比對用）。
pub fn master_password_hash_local(mk: &MasterKey, pw: &str) -> PasswordHash {
    kdf::hash_purpose(mk, pw, 2)
}

/// HKDF-SHA256 stretch：mk → 64 bytes（enc‖mac）。
pub fn stretch(mk: &MasterKey) -> StretchedKey {
    kdf::stretch(mk)
}

/// 解 Protected Symmetric Key（token 回應 `Key` 欄位，type 2）。
/// 金鑰輸入是 stretched master key（官方 `decrypt_user_key`）。
pub fn decrypt_user_key(sk: &StretchedKey, enc: &EncStr) -> Result<UserKey, CryptoError> {
    let raw = envelope::decrypt_bytes_with_key(&sk.0, enc)?;
    UserKey::from_bytes(raw)
}

/// 反向操作：改密碼 / 重解鎖時用 master key 重新包裝 user key。
pub fn encrypt_user_key(mk: &MasterKey, uk: &UserKey) -> Result<EncStr, CryptoError> {
    envelope::encrypt_bytes_key(stretch(mk).as_bytes(), uk.as_bytes())
}

/// legacy type 0 Protected Symmetric Key：AES-256-CBC 直接用**未 stretch** 的 master key。
pub fn decrypt_user_key_legacy(mk: &MasterKey, enc: &EncStr) -> Result<UserKey, CryptoError> {
    let parsed = envelope::parse_enc_str(enc)?;
    if parsed.cipher_type != CipherType::Aes256Cbc {
        return Err(CryptoError::UnknownCipherType(parsed.cipher_type as u8));
    }
    let raw = envelope::decrypt_with_raw_key(mk.as_bytes(), &parsed)?;
    UserKey::from_bytes(raw)
}

/// type 2 信封加密（vault 欄位預設格式）。
pub fn encrypt(k: &UserKey, plaintext: &str) -> Result<EncStr, CryptoError> {
    envelope::encrypt_bytes(k, plaintext.as_bytes())
}

/// type 2 信封解密，MAC 先驗（常數時間比對）。
pub fn decrypt(k: &UserKey, c: &EncStr) -> Result<String, CryptoError> {
    let raw = envelope::decrypt_bytes(k, c)?;
    String::from_utf8(raw).map_err(|_| CryptoError::NotUtf8)
}

/// RFC 6238 TOTP，預設 6 digits / 30s / SHA1。本地產生不問伺服器。
pub fn totp_code(seed_base32: &str, unix_secs: u64) -> Result<String, CryptoError> {
    totp::totp_code_with(seed_base32, unix_secs, &TotpParams::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let mk = MasterKey::from_bytes(vec![7u8; 32]).unwrap();
        assert!(!format!("{mk:?}").contains('7'));
        let uk = UserKey::from_bytes(vec![9u8; 64]).unwrap();
        assert!(!format!("{uk:?}").contains('9'));
        let ph = PasswordHash("abc".into());
        assert!(!format!("{ph:?}").contains("abc"));
    }

    #[test]
    fn key_length_discipline() {
        assert!(MasterKey::from_bytes(vec![0u8; 31]).is_err());
        assert!(UserKey::from_bytes(vec![0u8; 32]).is_ok());
        assert!(UserKey::from_bytes(vec![0u8; 64]).is_ok());
        assert!(UserKey::from_bytes(vec![0u8; 33]).is_err());
        assert!(OrgKey::from_bytes(vec![0u8; 32]).is_err());
    }
}
