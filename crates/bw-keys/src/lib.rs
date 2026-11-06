//! 金鑰生命週期狀態機 + OS 級封存（契約 §2.2、§3.2）。
//! 金鑰只在 `with_keys` 閉包內存在；`KeyBundle` 不 Clone、Debug=REDACTED（不變量 3）。
//! 狀態機是 per-device：`LockEpoch` 與其廣播只覆蓋本裝置的中樞與它的 thin clients。

pub mod clock;
pub mod kernel;
pub mod keystore;
pub mod machine;

#[cfg(target_os = "macos")]
pub mod keychain;

use thiserror::Error;
use zeroize::Zeroizing;

pub use clock::{Clock, ManualClock, SystemClock};
pub use kernel::{AuthContext, BwCryptoKernel, UnlockKernel};
pub use keystore::{AccountLabel, FileKeyStore, KeyStore, SealedKey, WrapStrength};
pub use machine::{
    ChallengeId, ChallengeKind, KeyDrift, TimeoutPolicy, UnlockChallenge, UnlockEvent,
    UnlockMachine, UnlockMachineBuilder, UnlockReceipt,
};

#[cfg(target_os = "macos")]
pub use keychain::KeychainKeystore;

/// 單調遞增的全域鎖世代（per-device，§1.1；不變量 6）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockEpoch(pub u64);

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("locked")]
    Locked,
    #[error("stale keys: {0}")]
    Stale(String),
    #[error("stale epoch: seen {seen}, now {now}")]
    StaleEpoch { seen: u64, now: u64 },
    #[error("keystore: {0}")]
    KeyStore(String),
    #[error("not authenticated (no account bound yet)")]
    NotAuthenticated,
    #[error("unlock failed (wrong password / corrupt key material)")]
    AuthFailed,
    #[error("unlock challenge unknown or already resolved")]
    ChallengeUnknown,
}

/// 金鑰包：只活在 `with_keys` 閉包內。不實作 Clone（不變量 3），
/// 所有欄位型別 drop 即清零。
pub struct KeyBundle {
    user_key: bw_crypto::UserKey,
    /// 使用者 RSA 私鑰的信封字串（user key 加密）；RSA unwrap 屬 U3 後續介面，
    /// 這裡先原樣保存密文。
    enc_private_key: Option<Zeroizing<String>>,
    /// 伺服器 `profile.keys` 指紋；KeyDrift 比對基準（§2.2）。
    fingerprint: Option<String>,
}

impl KeyBundle {
    pub(crate) fn new(
        user_key: bw_crypto::UserKey,
        enc_private_key: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            user_key,
            enc_private_key: enc_private_key.map(Zeroizing::new),
            fingerprint,
        }
    }

    pub fn user_key(&self) -> &bw_crypto::UserKey {
        &self.user_key
    }

    pub fn encrypted_private_key(&self) -> Option<&str> {
        self.enc_private_key.as_deref().map(String::as_str)
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// 使用者 RSA 私鑰（PKCS#8 DER）：以 user 對稱金鑰解 `enc_private_key`。
    /// 成員路徑解 org akey（`4.` RSA 包裝）的前置步驟。
    ///
    /// # Errors
    /// 無私鑰材料 → `CryptoError::InvalidKey`；信封 MAC/解析失敗 → 對應变體。
    pub fn user_rsa_private(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, bw_crypto::CryptoError> {
        let enc = self
            .enc_private_key
            .as_deref()
            .ok_or(bw_crypto::CryptoError::InvalidKey)?;
        bw_crypto::decrypt_private_key(&self.user_key, enc)
    }

    /// 從 `/sync` organization 的 `key`（akey）派生 org 對稱金鑰。
    /// 兩條協定路徑（來源：clients 新金鑰模型；vaultwarden 1.37.2
    /// `Membership.akey` → `organizations[].key`）：
    /// - `2.` ＝ owner：org key 以使用者**對稱**金鑰包裝 → `unwrap_org_key`。
    /// - `3.`/`4.` ＝ 成員：org key 以使用者 **RSA 公鑰**包裝 →
    ///   先 `user_rsa_private()` 再 `unwrap_org_key_rsa`。
    ///
    /// 派生金鑰只活在呼叫端閉包內（不變量 3）；本層不落盤明文。
    ///
    /// # Errors
    /// 前綴不認得、信封損壞或 MAC 失敗時回 `CryptoError`。
    pub fn unwrap_org_key(
        &self,
        encrypted_org_key: &str,
    ) -> Result<bw_crypto::OrgKey, bw_crypto::CryptoError> {
        match encrypted_org_key.split_once('.').map(|(t, _)| t) {
            Some("2") => bw_crypto::unwrap_org_key(&self.user_key, encrypted_org_key),
            Some("3") | Some("4") => {
                let priv_der = self.user_rsa_private()?;
                bw_crypto::unwrap_org_key_rsa(&priv_der, encrypted_org_key)
            }
            _ => {
                let head = encrypted_org_key.split('.').next().unwrap_or_default();
                let n = head
                    .parse::<u8>()
                    .map_err(|_| bw_crypto::CryptoError::BadB64)?;
                Err(bw_crypto::CryptoError::UnknownCipherType(n))
            }
        }
    }

    /// 解 org RSA 私鑰（`organizations[].keys.encryptedPrivateKey`，
    /// 以 owner 的 user 對稱金鑰包裝）。只有 owner/admin 的材料解得開；
    /// 成員對 VW 上的 org 私鑰本來就無存取路徑（見 daemon 容忍邏輯）。
    ///
    /// # Errors
    /// 信封 MAC/解析失敗 → `CryptoError`。
    pub fn org_rsa_private(
        &self,
        encrypted_org_private_key: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, bw_crypto::CryptoError> {
        bw_crypto::decrypt_private_key(&self.user_key, encrypted_org_private_key)
    }
}

impl std::fmt::Debug for KeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBundle(REDACTED)")
    }
}

/// 解鎖材料。DeviceAssertion 走 OS 封存解包，不需網路（離線可解鎖，
/// 治 clients#19055）；MasterPassword 離線驗證走 protected symmetric key
/// 的 MAC，不打伺服器。
pub enum UnlockMaterial {
    MasterPassword(Zeroizing<String>),
    DeviceAssertion,
    /// login-with-device / TDE：非同步，submit 先进 Unlocking，等
    /// `resolve_challenge`。
    AuthRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockReason {
    User,
    Timeout,
    ServerLogout,
    KeyRotation,
    /// 撤銷：`Revoked { by }`（§2.2）；by 為執行撤銷的 session/裝置識別字串。
    Revoked {
        by: String,
    },
    Startup,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_key() -> bw_crypto::UserKey {
        bw_crypto::UserKey::from_bytes((0u8..64).collect()).unwrap()
    }

    /// P4b org 派生鏈全形勢回放：owner（`2.` 對稱）、成員（`4.` RSA 經
    /// 使用者 RSA 私鑰）、org RSA 私鑰解包 + bw-crypto 原語往返驗證。
    #[test]
    fn org_key_derivation_paths_and_roundtrip() {
        let uk = user_key();
        let user_pair = bw_crypto::generate_rsa_keypair(&uk).unwrap();
        let org_pair = bw_crypto::generate_rsa_keypair(&uk).unwrap();
        let org_key = bw_crypto::OrgKey::from_bytes((100u8..164).collect()).unwrap();

        // owner 路徑：akey = org key 以 user 對稱金鑰包裝（type 2）
        let akey_owner = org_key.encrypt_with_user_key(&uk).unwrap();
        // 成員路徑：akey = org key 以成員 RSA 公鑰包裝（type 4 OAEP-SHA1）
        let akey_member = bw_crypto::wrap_org_key(&user_pair.public_key_b64, &org_key).unwrap();
        assert!(akey_owner.starts_with("2."));
        assert!(akey_member.starts_with("4."));

        let bundle = KeyBundle::new(
            uk.clone(),
            Some(user_pair.encrypted_private_key.clone()),
            None,
        );
        assert_eq!(
            bundle.unwrap_org_key(&akey_owner).unwrap().as_bytes(),
            org_key.as_bytes()
        );
        assert_eq!(
            bundle.unwrap_org_key(&akey_member).unwrap().as_bytes(),
            org_key.as_bytes()
        );

        // org RSA 私鑰解包（owner 材料）＋ 往返驗證：以 org 公鑰包一枚 probe，
        // 用剛解出的私鑰必須原樣取回。
        let org_priv = bundle
            .org_rsa_private(&org_pair.encrypted_private_key)
            .unwrap();
        let probe = bw_crypto::rsa_encrypt(
            &org_pair.public_key_b64,
            bw_crypto::OaepHash::Sha1,
            b"p4b-probe",
        )
        .unwrap();
        assert_eq!(
            bw_crypto::rsa_decrypt(&org_priv, &probe).unwrap(),
            b"p4b-probe"
        );

        // 無使用者 RSA 私鑰材料時，成員路徑明確失敗（不靜默降級）
        let no_priv = KeyBundle::new(uk.clone(), None, None);
        assert!(no_priv.unwrap_org_key(&akey_member).is_err());
        // 不認得的前綴回 UnknownCipherType 語意錯誤
        assert!(no_priv.unwrap_org_key("9.abc").is_err());
        assert!(no_priv.unwrap_org_key("garbage").is_err());
    }
}
