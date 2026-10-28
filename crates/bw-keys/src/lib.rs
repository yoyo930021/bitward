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
