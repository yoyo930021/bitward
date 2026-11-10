//! Send（加密分享）金鑰鏈：16 bytes 隨機 seed → 拉伸後 64 bytes 內容金鑰。
//!
//! 線格式查證（2026-11-10，官方原始碼＋VW 1.37.2 dev 容器實測，對照表見 NOTES.md）：
//! - Send **不經 user key 直接加密**：每枚 send 一把隨機 seed（16 bytes）；
//!   內容欄位（name/notes/text.text/file.fileName）以**拉伸後的 64 bytes 金鑰**
//!   走 type-2 信封（同 item key 用法——enc=前 32、mac=後 32，`encrypt_bytes_key`
//!   直接吃）；wire `key` 欄＝seed 位元組以 **user key** 包成的信封（僅發送端可讀，
//!   接收端從 URL 片段拿 seed 原值，不問伺服器）。
//! - 拉伸＝HKDF-SHA256 **Expand-only**：PRK=HMAC-SHA256(key="bitwarden-send", seed)，
//!   info="send"，輸出 64 bytes——同 sdk-internal
//!   `derive_shareable_key(seed, "send", Some("send"))`
//!   （crates/bitwarden-crypto/src/keys/shareable_key.rs）與舊 jslib
//!   `makeSendKey`（PrfExtendedKdf send 參數）同源。
//! - 取用密碼：wire `password` 欄＝`b64(PBKDF2-HMAC-SHA256(password, salt=seed,
//!   100_000 輪, 32 bytes))`（sdk_send.rs `SEND_ITERATIONS`＋`pbkdf2(pw, k, …)`）。
//!   實測（VW 1.37.2）伺服器把此字串再走自家 PBKDF2 落庫、接收方原樣回傳比對，
//!   故 seed 不變則改密/往來互通；契約「bcrypt 伺服器側」的猜測已按實錄修正。

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, envelope};

/// 官方 seed 長度（sdk-internal `SEND_KEY_LEN`）。
pub const SEND_SEED_LEN: usize = 16;

/// Send 內容金鑰的 seed（16 bytes；除錯遮罩、Drop zeroize，同 OrgKey 紀律）。
#[derive(Clone)]
pub struct SendKey(Vec<u8>);

impl core::fmt::Debug for SendKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendKey").finish_non_exhaustive()
    }
}

impl Drop for SendKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl SendKey {
    /// 新 send：16 bytes 隨機 seed。
    pub fn generate() -> Self {
        let mut seed = vec![0u8; SEND_SEED_LEN];
        rand::thread_rng().fill_bytes(&mut seed);
        Self(seed)
    }

    /// 從 URL 片段／鏡像 `key` 信封解出的 seed 位元組構造。
    ///
    /// # Errors
    /// 長度非 16 時回 [`CryptoError::InvalidKey`]。
    pub fn from_bytes(b: Vec<u8>) -> Result<Self, CryptoError> {
        if b.len() != SEND_SEED_LEN {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(b))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// seed → 64 bytes 內容金鑰（enc‖mac），直接餵 `envelope::encrypt_bytes_key`。
    pub fn stretch(&self) -> Zeroizing<[u8; 64]> {
        Self::stretch_seed(&self.0)
    }

    pub(crate) fn stretch_seed(seed: &[u8]) -> Zeroizing<[u8; 64]> {
        // PRK = HMAC-SHA256(key="bitwarden-send", msg=seed)（1 輪 PBKDF2＝HMAC 本體）
        let prk = Hmac::<Sha256>::new_from_slice(b"bitwarden-send")
            .expect("static key")
            .chain_update(seed)
            .finalize()
            .into_bytes();
        let mut out = Zeroizing::new([0u8; 64]);
        hkdf::Hkdf::<Sha256>::from_prk(&prk)
            .expect("32 bytes = PRK size")
            .expand(b"send", out.as_mut())
            .expect("64 <= 255*32");
        out
    }

    /// 取用密碼的線格式雜湊（見模組頭查證；b64 標準字母）。
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &self.0, 100_000, &mut out);
        crate::b64(&out)
    }

    /// 以 user key 包 seed（wire `key` 欄；反向操作見 [`unwrap_seed`]）。
    pub fn wrap_with_user_key(
        &self,
        user_key: &crate::UserKey,
    ) -> Result<String, CryptoError> {
        envelope::encrypt_bytes_key(user_key.as_bytes(), &self.0)
    }
}

/// 解 wire `key` 信封（user key 包裝的 seed）→ [`SendKey`]。
///
/// # Errors
/// 信封損壞、MAC 不符或解出長度非 16 時回 [`CryptoError`]。
pub fn unwrap_seed(user_key: &crate::UserKey, wrapped: &str) -> Result<SendKey, CryptoError> {
    let raw = envelope::decrypt_bytes_with_key(user_key.as_bytes(), wrapped)?;
    SendKey::from_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UserKey, b64_decode, decrypt_bytes_with_key, encrypt_bytes_key};

    #[test]
    fn stretch_kat_against_official_derivation() {
        // 独立實作（python hmac/hashlib）算出的期望值，釘選與官方同形：
        // seed=001122…ff → PRK=HMAC("bitwarden-send",seed) → HKDF-Expand(info="send",64)
        let key = SendKey::from_bytes(
            (0..16u8)
                .flat_map(|i| [i * 0x11])
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        assert_eq!(
            hex(key.stretch().as_slice()),
            "9f48c08ee2b16be3db943552165b1f2f646000c481ffbdc2ffd09ddaa169fbee\
             700493a8b6e374873f992029f01600e26940b004fe16ec0a32996a1fb021ba5c"
        );
    }

    #[test]
    fn password_hash_kat() {
        let key = SendKey::from_bytes(
            (0..16u8).flat_map(|i| [i * 0x11]).collect::<Vec<u8>>(),
        )
        .unwrap();
        assert_eq!(
            key.password_hash("hunter2"),
            "IUfRQWngrzaQ9yDeP5jdidY+TbsIpwLrvaezPw/pemk="
        );
    }

    #[test]
    fn send_key_envelope_roundtrip() {
        // 官方語意閉環：內容欄用拉伸金鑰（同 item key 用法）、seed 用 user key 包。
        let uk = UserKey::from_bytes(vec![7u8; 64]).unwrap();
        let k = SendKey::generate();
        let ct = encrypt_bytes_key(k.stretch().as_slice(), "敏感文字".as_bytes()).unwrap();
        let pt = decrypt_bytes_with_key(k.stretch().as_slice(), &ct).unwrap();
        assert_eq!(pt, "敏感文字".as_bytes());
        let wrapped = k.wrap_with_user_key(&uk).unwrap();
        let back = unwrap_seed(&uk, &wrapped).unwrap();
        assert_eq!(back.as_bytes(), k.as_bytes());
        // 錯 user key 解不開（MAC 先驗）
        let uk2 = UserKey::from_bytes(vec![8u8; 64]).unwrap();
        assert!(unwrap_seed(&uk2, &wrapped).is_err());
        // seed 穩定：改密重算的 password_hash 與拉伸金鑰都不變（接收方舊連結可用）
        assert_eq!(
            hex(back.stretch().as_slice()),
            hex(k.stretch().as_slice())
        );
    }

    #[test]
    fn key_discipline() {
        assert!(SendKey::from_bytes(vec![0u8; 15]).is_err());
        assert!(SendKey::from_bytes(vec![0u8; 64]).is_err());
        assert!(SendKey::from_bytes(vec![0u8; 16]).is_ok());
        let k = SendKey::generate();
        assert!(!format!("{k:?}").contains('7')); // REDACTED
        // b64 往返（URL 片段用 b64url 屬呼叫端編碼，這裡鎖 b64 包裝可用）
        assert_eq!(b64_decode(&crate::b64(k.as_bytes())).unwrap(), k.as_bytes());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
