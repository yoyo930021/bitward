//! 批次 B：網站圖示代理（favicon proxy）。
//!
//! GUI 要顯示網站圖示但 nsh 自己抓網/快取不便；daemon 代打 VW 的
//! `GET {base}/icons/{host}/icon.png`（root 路徑——查證見 bw-server
//! `fetch_icon`）並落盤快取。
//!
//! 隱私註記（Contract 2）：GetIcon 會向伺服器請求該 host——伺服器本來
//! 就存著含此 host 的項目（icon 請求無新增外洩面）。
//!
//! 快取紀律：`data_dir/icons/{host}.png`，TTL 7 天（mtime 判定，過期重取
//! 覆寫）；同 host 併發去重走單飛閘＋雙重檢查——第一個取網填_cache_，
//! 其餘在閘後直接命中，零重複外連。未啟用 icons 的 server（404）→
//! `NotFound`，GUI 退回字母磚；VW 對解析失敗的 host 回占位 PNG（實錄），
//! 故 200 不保證該站真有圖示——這是官方客戶端同款的寬容。

use std::time::{SystemTime, UNIX_EPOCH};

use bw_proto::{Response, WtpError};

/// 快取有效期：7 天（官方 web-vault 的 icon 快取同量級；圖示極少變動）。
pub const ICON_TTL_MS: u64 = 7 * 24 * 3600 * 1000;

/// host 白名單校驗：快取檔名直接拼 `icons/{host}.png`，不擋路徑穿越
/// （`..`、`/`）就等于讓呼叫端寫任意檔。官方域名形態＝萬用字元標籤字串。
fn valid_host(host: &str) -> bool {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    // 泛域名（萬用字元標籤）無圖可取，也防 `*.example.com` 進檔名
    ok && !host.starts_with('*')
}

impl crate::hub::Hub {
    /// 取圖：快取命中（未過 TTL）直接回；miss → 單飛閘內再檢查一次
    /// （併發同 host 只放一發外連）→ 打伺服器 → 落盤 → 回位元組。
    pub async fn get_icon(&self, host: &str) -> Result<Response, WtpError> {
        if !valid_host(host) {
            return Err(WtpError::Denied {
                grant_gap: format!("非法 host: {host:?}"),
            });
        }
        let dir = self.data_dir.join("icons");
        let file = dir.join(format!("{host}.png"));
        if fresh_cache(&file, ICON_TTL_MS, now_ms()) && let Ok(bytes) = std::fs::read(&file) {
            return Ok(Response::AttachmentBytes(bytes));
        }
        let _gate = self.icon_gate.lock().await;
        // 雙重檢查：排隊期間第一個呼叫已把快取填好
        if fresh_cache(&file, ICON_TTL_MS, now_ms()) && let Ok(bytes) = std::fs::read(&file) {
            return Ok(Response::AttachmentBytes(bytes));
        }
        let client = self.client().await?;
        let bytes = match client.fetch_icon(host).await {
            Ok(b) => b,
            Err(e) if e.status() == Some(404) => return Err(WtpError::NotFound),
            Err(e) => return Err(crate::hub::map_server_err(e)),
        };
        if bytes.is_empty() {
            return Err(WtpError::NotFound);
        }
        if std::fs::create_dir_all(&dir).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            // 原子落盤：先寫同目錄暫存再 rename，崩潰不留在半截快取
            let tmp = dir.join(format!("{host}.png.partial"));
            if std::fs::write(&tmp, &bytes).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                }
                let _ = std::fs::rename(&tmp, &file);
            }
        }
        Ok(Response::AttachmentBytes(bytes))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 快取新鮮度：檔存在且 mtime 距今 < ttl。讀不到 metadata 視為過期。
fn fresh_cache(path: &std::path::Path, ttl_ms: u64, now: u64) -> bool {
    path.metadata()
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(UNIX_EPOCH)
                .map(|d| now.saturating_sub(d.as_millis() as u64) < ttl_ms)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_whitelist_blocks_traversal_and_junk() {
        assert!(valid_host("github.com"));
        assert!(valid_host("1.1.1.1"));
        assert!(valid_host("xn--fiqs8s.example.cn"));
        assert!(valid_host("a-b.example_1.com"));
        assert!(!valid_host(""));
        assert!(!valid_host("../etc/passwd"));
        assert!(!valid_host("a/b"));
        assert!(!valid_host("a..b"));
        assert!(!valid_host(".leading"));
        assert!(!valid_host("trailing-"));
        assert!(!valid_host("*.example.com"));
        assert!(!valid_host("bad host"));
        assert!(!valid_host(&"a".repeat(300)));
    }

    #[test]
    fn freshness_window_is_pure() {
        let dir = std::env::temp_dir().join(format!("bw-icon-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.png");
        // 不存在 → 過期
        assert!(!fresh_cache(&f, 10_000, now_ms()));
        std::fs::write(&f, b"png").unwrap();
        // 剛寫入 → 新鮮（容 60s 時鐘粒度）
        assert!(fresh_cache(&f, 60_000, now_ms() + 1_000));
        // TTL 遠小於寫入年齡 → 過期
        assert!(!fresh_cache(&f, 1, now_ms() + 10_000));
        std::fs::remove_dir_all(&dir).ok();
    }
}
