//! 內容定址 blob（附件落地；治 FR 4306 的本地佇列）。
//! 路徑 `<db 同目錄>/blobs/<hex[0..2]>/<hex[2..]>`，檔 0600、目錄 0700。
//! 分兩層目錄是借 git object store 的形態（來源：
//! https://git-scm.com/docs/gitrepository-layout ）。

use std::path::PathBuf;

use crate::{Store, StoreError, StoreResult, sha256_hex, unix_ms};

/// sha256 hex（64 字元）。
pub type BlobRef = String;

impl Store {
    /// 寫入前純函數：呼叫端可先算 ref 再決定是否上傳。
    pub fn blob_ref_of(bytes: &[u8]) -> BlobRef {
        sha256_hex(bytes)
    }

    pub fn blob_put(&self, bytes: &[u8]) -> StoreResult<BlobRef> {
        let r = Self::blob_ref_of(bytes);
        let path = self.blob_path(&r)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        if !path.exists() {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&path)?;
            std::io::Write::write_all(&mut f, bytes)?;
        }
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO blobs(ref, size, created_at) VALUES(?1,?2,?3)",
            rusqlite::params![r, bytes.len() as i64, unix_ms() as i64],
        )?;
        Ok(r)
    }

    pub fn blob_open(&self, r: &str) -> StoreResult<Vec<u8>> {
        let path = self.blob_path(r)?;
        match std::fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    /// 登記過但檔案遺漏的 ref（fsck／重傳佇列用）。
    pub fn blob_missing(&self) -> StoreResult<Vec<BlobRef>> {
        let refs: Vec<BlobRef> = {
            let conn = self.conn.lock().expect("store mutex poisoned");
            let mut stmt = conn.prepare("SELECT ref FROM blobs ORDER BY ref")?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?
        };
        let mut missing = Vec::new();
        for r in refs {
            if !self.blob_path(&r)?.exists() {
                missing.push(r);
            }
        }
        Ok(missing)
    }

    fn blob_path(&self, r: &str) -> StoreResult<PathBuf> {
        let bytes = r.as_bytes();
        if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(StoreError::Invalid(format!("bad blob ref {r}")));
        }
        Ok(self.blobs_dir.join(&r[0..2]).join(&r[2..64]))
    }
}
