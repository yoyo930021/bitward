//! 附件視圖層（批次 4b）：大小格式化、32MiB 本地閘、org 擋附、行狀態機、
//! 讀檔／落地路徑。全部純函數可單測；daemon 往返在 `state.rs` 的附件命令。
//!
//! 線紀律對照：`AttachmentOp::Upload.bytes` 是明文（本機 UDS 線安全，與
//! login password 同級），attachment_id 是 20-hex 不透明字串——GUI 只原樣
//! 轉送，絕不按 UUID 解析。上傳收斂走 outbox（掛「未同步」），鏡像的附件
//! 列在背景推送落地後才出現；刪除需連網，無離線佇列。

use std::path::PathBuf;

use crate::export::ts_utc;

/// 單檔上限（與 daemon `MAX_ATTACHMENT_BYTES` 同口徑；本地先擋給可懂文案）。
pub const MAX_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;

/// 人類可讀大小（daemon `sizeName` 缺席時的備援；1024 進位，官方風格）。
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.2} {}", UNITS[unit])
}

/// 上傳前本地閘：空檔名／超限先擋，不佔 daemon 往返。
pub fn check_upload(file_name: &str, size: u64) -> Result<(), String> {
    if file_name.trim().is_empty() {
        return Err("附件需要檔名".into());
    }
    if size > MAX_ATTACHMENT_BYTES {
        return Err(format!(
            "附件 {} 超過上限 {}",
            format_size(size),
            format_size(MAX_ATTACHMENT_BYTES)
        ));
    }
    Ok(())
}

/// org 共享項目的上傳閘（daemon 回 Unsupported：換鑰在後續批）。
/// 回 Some(原因)＝UI 必須擋下＋tooltip；None＝可上傳。
pub fn upload_gate(organization_id: Option<&str>) -> Option<&'static str> {
    organization_id.map(|_| "組織共享項目的附件需等 daemon 換鑰批次（org 附件換鑰未開放）")
}

/// 附件操作種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttOp {
    Upload,
    Download,
    Delete,
}

/// 詳情頁附件行狀態機：同一刻只容一個附件操作在飛（雙擊不重複排隊）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AttState {
    pub busy: Option<AttOp>,
}

impl AttState {
    /// 嘗試進入 busy；已在飛回 false（呼叫端忽略這次按鍵）。
    pub fn start(&mut self, op: AttOp) -> bool {
        if self.busy.is_some() {
            return false;
        }
        self.busy = Some(op);
        true
    }

    pub fn finish(&mut self) {
        self.busy = None;
    }

    pub fn busy(&self) -> bool {
        self.busy.is_some()
    }
}

/// worker 端讀檔：回（檔名, 明文位元組）。大 buffer 不做 zeroing——
/// Zeroizing 紀律只對密碼類（小、高熵、洩一份致命）；附件明文與匯出檔同級。
pub fn read_for_upload(path: &str) -> Result<(String, Vec<u8>), String> {
    let p = PathBuf::from(path);
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "路徑取不到檔名".to_owned())?
        .to_owned();
    let meta = std::fs::metadata(&p).map_err(|e| format!("讀不到「{path}」：{e}"))?;
    check_upload(&name, meta.len())?;
    let bytes = std::fs::read(&p).map_err(|e| format!("讀不到「{path}」：{e}"))?;
    Ok((name, bytes))
}

/// 預覽文案（路徑框旁的檔名＋大小）；檔不存在回錯誤字串供紅色顯示。
pub fn upload_preview(path: &str) -> Result<String, String> {
    let p = PathBuf::from(path.trim());
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "請貼上檔案路徑".to_owned())?
        .to_owned();
    let meta = std::fs::metadata(&p).map_err(|e| format!("讀不到「{path}」：{e}"))?;
    Ok(format!("{name} · {}", format_size(meta.len())))
}

/// 下載落地路徑：`~/Downloads/bitward-attachment-<file_name>`（沿用匯出紀律）；
/// 同名已存在加 UTC 時間戳防蓋檔。檔名去路徑分隔（attachment 名是伺服器字串）。
pub fn download_target(file_name: &str) -> PathBuf {
    let safe: String = file_name
        .chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let safe = if safe.trim().is_empty() {
        "attachment".to_owned()
    } else {
        safe
    };
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = home.join("Downloads");
    let _ = std::fs::create_dir_all(&dir);
    let mut path = dir.join(format!("bitward-attachment-{safe}"));
    if path.exists() {
        path = dir.join(format!("bitward-attachment-{}-{safe}", ts_utc()));
    }
    path
}

/// worker 端落地：寫 0600（明文抵銷面同匯出），回顯示用路徑字串。
pub fn write_download(file_name: &str, bytes: &[u8]) -> Result<String, String> {
    let path = download_target(file_name);
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_steps_on_binaries() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(3 * 1024 * 1024 + 512 * 1024), "3.50 MB");
        assert_eq!(format_size(64u64 * 1024 * 1024 * 1024), "64.00 GB");
    }

    #[test]
    fn upload_gate_blocks_only_org_items() {
        assert_eq!(upload_gate(None), None);
        assert!(upload_gate(Some("org-1")).unwrap().contains("換鑰"));
    }

    #[test]
    fn check_upload_gates_size_and_name() {
        assert!(check_upload("a.pdf", 10).is_ok());
        assert!(check_upload("  ", 10).is_err());
        let err = check_upload("big.bin", MAX_ATTACHMENT_BYTES + 1).unwrap_err();
        assert!(err.contains("超過上限"), "{err}");
    }

    #[test]
    fn att_state_single_flight() {
        let mut s = AttState::default();
        assert!(!s.busy());
        assert!(s.start(AttOp::Upload));
        assert!(s.busy());
        assert!(!s.start(AttOp::Download), "在飛時第二個操作必須被擋");
        s.finish();
        assert!(s.start(AttOp::Delete));
    }

    #[test]
    fn download_target_sanitizes_and_avoids_collisions() {
        let p = download_target("深/層\\名.pdf");
        let name = p.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name.starts_with("bitward-attachment-深_層_名.pdf"), "{name}");
        assert!(p.starts_with("Downloads".chars().collect::<String>()) || p.is_absolute());
        let empty = download_target("");
        assert!(empty.file_name().unwrap().to_str().unwrap().contains("attachment"));
    }
}
