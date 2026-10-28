//! `KeyStore`：OS 級金鑰封存邊界（契約 §3.2）。
//! `FileKeyStore` 是測試/開發用實作：wrapped user key 落 0600 檔、目錄 0700。
//! macOS 另有 `KeychainKeystore`（biometric ACL）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::KeyError;

/// 多帳號時分辨封存記錄（開放問題 Q2 未定案前，先以 email + 可選 account id 作鍵）。
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountLabel {
    pub email: String,
    pub account_id: Option<String>,
}

impl AccountLabel {
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            account_id: None,
        }
    }
    fn key(&self) -> String {
        match &self.account_id {
            Some(id) => format!("{}#{id}", self.email),
            None => self.email.clone(),
        }
    }
}

/// 封存的 user key：已 stretch 的金鑰本體（64B）+ 附帶的 RSA 私鑰信封。
/// 這是 `DeviceAssertion` 離線解鎖的載體。
#[derive(Clone, Debug)]
pub struct SealedKey {
    pub user_key: Zeroizing<Vec<u8>>,
    pub keys_fingerprint: Option<String>,
    pub enc_private_key: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapStrength {
    /// 僅檔案權限保護（開發/測試退路，等同無生物辨識）。
    FilePermissions,
    /// Keychain/Keystore 硬體綁定 + biometric ACL。
    BiometricBound,
}

pub trait KeyStore: Send + Sync {
    fn store_wrapped(&self, label: &AccountLabel, key: &SealedKey) -> Result<(), KeyError>;
    fn load_wrapped(&self, label: &AccountLabel) -> Result<Option<SealedKey>, KeyError>;
    fn clear(&self, label: &AccountLabel) -> Result<(), KeyError>;
    fn biometric_available(&self) -> bool {
        false
    }
    fn wrap_strength(&self) -> WrapStrength {
        WrapStrength::FilePermissions
    }
}

/// 測試/開發用：0600 檔封存。金鑰以 base64 存於 `<dir>/<hex(email)>.key`。
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, KeyError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| KeyError::KeyStore(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| KeyError::KeyStore(e.to_string()))?;
        }
        Ok(Self { dir })
    }

    fn path(&self, label: &AccountLabel) -> PathBuf {
        // email 可能含 @ 與 .，用 sha256 前 16 hex 作檔名避免路徑注入。
        let digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(label.key().as_bytes());
            h.finalize()
        };
        let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.key"))
    }
}

#[derive(Serialize, Deserialize)]
struct DiskRecord {
    v: u8,
    user_key: String,
    keys_fingerprint: Option<String>,
    enc_private_key: Option<String>,
}

impl KeyStore for FileKeyStore {
    fn store_wrapped(&self, label: &AccountLabel, key: &SealedKey) -> Result<(), KeyError> {
        use base64::Engine;
        let rec = DiskRecord {
            v: 1,
            user_key: base64::engine::general_purpose::STANDARD.encode(&key.user_key[..]),
            keys_fingerprint: key.keys_fingerprint.clone(),
            enc_private_key: key.enc_private_key.as_deref().map(|s| s.to_owned()),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|e| KeyError::KeyStore(e.to_string()))?;
        let path = self.path(label);
        write_0600(&path, &bytes)?;
        Ok(())
    }

    fn load_wrapped(&self, label: &AccountLabel) -> Result<Option<SealedKey>, KeyError> {
        use base64::Engine;
        let path = self.path(label);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(KeyError::KeyStore(e.to_string())),
        };
        let rec: DiskRecord =
            serde_json::from_slice(&bytes).map_err(|e| KeyError::KeyStore(e.to_string()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&rec.user_key)
            .map_err(|e| KeyError::KeyStore(e.to_string()))?;
        Ok(Some(SealedKey {
            user_key: Zeroizing::new(raw),
            keys_fingerprint: rec.keys_fingerprint,
            enc_private_key: rec.enc_private_key.map(Zeroizing::new),
        }))
    }

    fn clear(&self, label: &AccountLabel) -> Result<(), KeyError> {
        match std::fs::remove_file(self.path(label)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyError::KeyStore(e.to_string())),
        }
    }
}

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| KeyError::KeyStore(e.to_string()))?;
    f.write_all(bytes)
        .map_err(|e| KeyError::KeyStore(e.to_string()))?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
    std::fs::write(path, bytes).map_err(|e| KeyError::KeyStore(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_keystore_roundtrip_and_zero_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path()).unwrap();
        let label = AccountLabel::new("dev@bitward.test");
        let key = SealedKey {
            user_key: Zeroizing::new(vec![7u8; 64]),
            keys_fingerprint: Some("fp".into()),
            enc_private_key: Some(Zeroizing::new("2.iv|ct|mac".into())),
        };
        store.store_wrapped(&label, &key).unwrap();
        let got = store.load_wrapped(&label).unwrap().unwrap();
        assert_eq!(&got.user_key[..], &[7u8; 64]);
        assert_eq!(got.keys_fingerprint.as_deref(), Some("fp"));
        assert_eq!(
            got.enc_private_key.as_deref().map(|s| s.as_str()),
            Some("2.iv|ct|mac")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(store.path(&label))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "封存檔必须 0600");
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                dir_mode & 0o077,
                0,
                "封存目錄不可群組/他人可見: {dir_mode:o}"
            );
        }

        store.clear(&label).unwrap();
        assert!(store.load_wrapped(&label).unwrap().is_none());
        // 冪等清除
        store.clear(&label).unwrap();
    }

    #[test]
    fn distinct_labels_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path()).unwrap();
        let a = AccountLabel::new("a@x.io");
        let b = AccountLabel {
            email: "a@x.io".into(),
            account_id: Some("org1".into()),
        };
        store
            .store_wrapped(
                &a,
                &SealedKey {
                    user_key: Zeroizing::new(vec![1; 64]),
                    keys_fingerprint: None,
                    enc_private_key: None,
                },
            )
            .unwrap();
        assert!(store.load_wrapped(&b).unwrap().is_none());
    }
}
