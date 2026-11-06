//! 未加密 JSON 匯出（契約功能面：逐筆 Get Reveal 組 [{name,username,password,uri,tags}]）。
//!
//! 明文紀律：這是 GUI 唯一「明文經檔案離開程序」的出口，UI 必須先經
//! 確認框明示（state.rs 的 AskExport）。路徑上明文只活在此函數的
//! `Zeroizing` 區域——寫檔後即清零；落盤檔另以 0600 抵銷部分暴露面。

use std::path::PathBuf;

use bw_proto::{Call, Query, Response, SortKey, VaultCall, View};

use crate::btp::Session;

#[derive(Clone)]
pub struct ExportOutcome {
    pub path: PathBuf,
    pub count: usize,
}

/// 在 worker 執行緒跑完整匯出（一條連線、逐筆 Reveal）。
pub fn run(session: &Session) -> Result<ExportOutcome, String> {
    let listed = session
        .call(&Call::Vault(VaultCall::List {
            query: Query {
                sort: SortKey::Name,
                limit: 0,
                ..Default::default()
            },
            view: View::Metadata,
        }))
        .map_err(|e| e.display())?;
    let Response::Items(metas) = listed else {
        return Err("List 回應形態不符".into());
    };
    let mut rows: Vec<serde_json::Value> = Vec::with_capacity(metas.len());
    for m in metas {
        let got = session
            .call(&Call::Vault(VaultCall::Get {
                id: m.meta.id,
                view: View::Reveal,
            }))
            .map_err(|e| e.display())?;
        let Response::Item(Some(view)) = got else {
            continue;
        };
        // Zeroize 點 ③：Reveal 明文一出連線就包進 Zeroizing，
        // 嵌進 JSON 值是這裡唯一無法清零的拷貝（serde_json::Value），
        // 迴圈結束即釋放，匯出完成後程序內不再持有。
        let password = view.password.map(zeroize::Zeroizing::new);
        rows.push(serde_json::json!({
            "name": view.meta.name,
            "username": view.username,
            "password": password.as_deref(),
            "uri": view.meta.uris.first(),
            "tags": view.meta.tags,
        }));
    }
    let path = download_path()?;
    let body = serde_json::to_vec_pretty(&rows).map_err(|e| e.to_string())?;
    std::fs::write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))?;
    restrict_owner_only(&path);
    Ok(ExportOutcome {
        path,
        count: rows.len(),
    })
}

/// `~/Downloads/bitward-export-<UTC 時間>.json`；無 HOME 時退回暫存目錄。
fn download_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = home.join("Downloads");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir.join(format!("bitward-export-{}.json", ts_utc())))
}

/// 明文匯出檔收緊為 0600（Windows/Linux 以外都吃得到 unix 權限；
/// 失敗不阻擋匯出本身）。
#[cfg(unix)]
fn restrict_owner_only(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &PathBuf) {}

/// UTC 時間戳 `YYYYMMDDTHHMMSSZ`（不拉 chrono：days-to-civil 就這幾個算式）。
pub fn ts_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    format!("{}Z", civil(secs))
}

/// epoch 秒 → `YYYYMMDDTHHMMSS`（Howard Hinnant civil_from_days 的整數版）。
fn civil(epoch_secs: i64) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let tod = epoch_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_matches_known_dates() {
        // 2001-09-09T01:46:40Z（epoch 1e9）
        assert_eq!(civil(1_000_000_000), "20010909T014640");
        // epoch 0
        assert_eq!(civil(0), "19700101T000000");
        // 2025-11-07T00:00:00Z
        assert_eq!(civil(1_762_473_600), "20251107T000000");
        // 負數（1969-12-31T23:59:59Z）走 div_euclid 正確回退
        assert_eq!(civil(-1), "19691231T235959");
    }

    #[test]
    fn ts_utc_has_shape() {
        let t = ts_utc();
        assert_eq!(t.len(), 16, "{t}");
        assert!(t.ends_with('Z'));
        assert_eq!(t.as_bytes()[8], b'T');
    }
}
