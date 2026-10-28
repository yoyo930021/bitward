//! SQLite 鏡像 + overlay + outbox + audit（契約 §3.4）。
//! 只存 `Prot<T>` 的加密態與已索引 metadata；不知金鑰語意（§3 規則）。
//! 鏡像列存密文原樣；明文索引（name/uris）由解鎖後的 `set_plain_meta` 填入。

mod audit;
mod blobs;
mod ciphers;
mod outbox;
mod overlay;
mod query;
mod schema;
mod sessions;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;
use thiserror::Error;

pub use audit::{AuditFilter, AuditRecord};
pub use blobs::BlobRef;
pub use ciphers::CipherRow;
pub use outbox::{ConflictRecord, LEASE_MS, MutState, Mutation, MutationDraft, OutboxDepth};
pub use overlay::{Overlay, OverlayOp};
pub use sessions::{SessionRow, SessionState};

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("not found")]
    NotFound,
    #[error("unsupported schema version {0}")]
    SchemaVersion(i64),
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(String),
    #[error("audit chain broken at seq {seq}: expected {expected}, found {found}")]
    ChainBroken {
        seq: i64,
        expected: String,
        found: String,
    },
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Invalid(e.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

/// 本地持久層。`Connection` 包在 `Mutex` 裡：daemon 是唯一寫入者（不變量 11），
/// 讀取並發靠 WAL；API 全部 `&self`，不外洩事務邊界細節。
pub struct Store {
    conn: Mutex<Connection>,
    blobs_dir: PathBuf,
}

impl Store {
    /// 開庫並 migration。建立目錄 0700、db/`-wal`/`-shm` 檔 0600。
    pub fn open(path: &Path) -> StoreResult<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;",
        )?;
        let blobs_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Self {
            conn: Mutex::new(conn),
            blobs_dir,
        };
        store.migrate()?;
        // WAL/SHM 檔由 SQLite 在第一次寫入後建立，權限跟 umask 走，補 chmod。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let p = PathBuf::from(format!("{}{}", path.display(), suffix));
                if p.exists() {
                    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
        Ok(store)
    }

    fn migrate(&self) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > schema::SCHEMA_VERSION {
            return Err(StoreError::SchemaVersion(version));
        }
        conn.execute_batch(schema::V1)?;
        if version < schema::SCHEMA_VERSION {
            conn.execute_batch(&format!(
                "PRAGMA user_version = {};",
                schema::SCHEMA_VERSION
            ))?;
        }
        Ok(())
    }

    /// 上次 `apply_sync` 的游標（單調遞增）；尚未同步過為 0。
    pub fn cursor(&self) -> StoreResult<u64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(meta_u64(&conn, "cursor").unwrap_or(0))
    }

    /// 供測試與 e2e：確認檔案權限收斂（0600）。SQLite 可能在後續寫入時重建
    /// `-wal`，故每次交易提交後都呼叫一次。
    #[cfg(unix)]
    pub fn enforce_file_modes(&self, path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{}", path.display(), suffix));
            if p.exists() {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

pub(crate) fn meta_u64(conn: &Connection, key: &str) -> Option<u64> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()?
    .parse()
    .ok()
}

pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
