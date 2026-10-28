//! 自寫 Bitwarden 金鑰派生與信封加解密（契約 §3.1、§0 授權列）。
//! 編排自寫、原語用 rustcrypto；本 crate 不得 use 任何網路/IO 型別（A10）。
//! 函數簽名是契約（ARCHITECTURE §3.1），實作由 U3 填入。

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
}

#[derive(Clone)]
pub struct MasterKey(Vec<u8>);
#[derive(Clone)]
pub struct StretchedKey(Vec<u8>);
#[derive(Clone)]
pub struct UserKey(Vec<u8>);
#[derive(Clone, Debug)]
pub struct PasswordHash(String);
#[derive(Clone, Copy, Debug)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id { m: u32, t: u32, p: u32 },
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

/// U3（U3 worker）實作；簽名凍結自契約 §3.1。
pub fn master_key(pw: &str, email: &str, kdf: KdfParams) -> Result<MasterKey, CryptoError> {
    let _ = (pw, email, kdf);
    todo!("U3: PBKDF2-SHA256(600k) | Argon2id(32M,6,4)，salt=email")
}

pub fn master_password_hash(mk: &MasterKey, pw: &str) -> PasswordHash {
    let _ = (mk, pw);
    todo!("U3: 以 master key 為輸入、pw 為 salt 的第二輪 PBKDF-SHA256")
}

pub fn stretch(mk: &MasterKey) -> StretchedKey {
    let _ = mk;
    todo!("U3: HKDF-SHA256 拉長")
}

pub fn decrypt_user_key(sk: &StretchedKey, enc: &EncStr) -> Result<UserKey, CryptoError> {
    let _ = (sk, enc);
    todo!("U3: 解 Protected Symmetric Key")
}

pub fn encrypt(k: &UserKey, plaintext: &str) -> Result<EncStr, CryptoError> {
    let _ = (k, plaintext);
    todo!("U3: type 2 AES-256-CBC+HMAC-SHA256 信封")
}

pub fn decrypt(k: &UserKey, c: &EncStr) -> Result<String, CryptoError> {
    let _ = (k, c);
    todo!("U3: 信封解密，MAC 先驗")
}

pub fn totp_code(seed_base32: &str, unix_secs: u64) -> Result<String, CryptoError> {
    let _ = (seed_base32, unix_secs);
    todo!("U3: RFC 6238，本地產生不問伺服器")
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // U3 以官方 KAT fixtures 取代（契約 §6 A1）
    }
}
