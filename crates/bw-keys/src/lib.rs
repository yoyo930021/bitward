//! 金鑰生命週期狀態機 + OS 級封存（契約 §2.2、§3.2）。
//! 金鑰只在 `with_keys` 閉包內存在；`KeyBundle` 不 Clone、Debug=REDACTED。實作由 U5 填入。

use bw_proto::UnlockStateView;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("locked")]
    Locked,
    #[error("stale epoch: seen {seen}, now {now}")]
    StaleEpoch { seen: u64, now: u64 },
    #[error("keystore: {0}")]
    KeyStore(String),
}

/// 單調遞增的全域鎖世代（per-device，§1.1）
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockEpoch(pub u64);

#[derive(Clone)]
pub struct KeyBundle {
    user_key: bw_crypto::UserKey,
    private_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for KeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBundle(REDACTED)")
    }
}

impl Drop for KeyBundle {
    fn drop(&mut self) {
        if let Some(k) = self.private_key.as_mut() {
            k.zeroize();
        }
    }
}

pub struct UnlockMachine {
    _private: (),
}

impl UnlockMachine {
    pub fn new() -> Self {
        todo!("U5: 初始 AuthLocked/SignedOut")
    }
    pub fn state(&self) -> UnlockStateView {
        todo!("U5: 不含金鑰本身的視窗")
    }
    pub fn epoch(&self) -> LockEpoch {
        todo!("U5")
    }
    pub fn submit(&self, _material: UnlockMaterial) -> Result<LockEpoch, KeyError> {
        todo!("U5: 冪等解鎖，重複不互毀（治 clients#6898）")
    }
    pub fn lock(&self, _reason: LockReason) -> LockEpoch {
        todo!("U5: epoch++ 並級聯撤銷（§2.2）")
    }
    pub fn with_keys<R>(&self, _f: impl FnOnce(&KeyBundle) -> R) -> Result<R, KeyError> {
        todo!("U5: 金鑰不離開閉包")
    }
}

#[derive(Clone)]
pub enum UnlockMaterial {
    MasterPassword(String),
    DeviceAssertion,
    AuthRequest,
}

#[derive(Clone, Copy, Debug)]
pub enum LockReason {
    User,
    Timeout,
    ServerLogout,
    KeyRotation,
    Revoked,
    Startup,
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // U5：狀態機轉移表逐條測試（§2.2 表格即測試清單）
    }
}
