//! 環境與 session 生命週期：`BITWARD_SOCK` 必要（shim 永不自行落地 daemon，§1.2）；
//! 配對 token 存 `<data_dir>/nm_session`。daemon 重啟（unknown session → 握手即斷線）
//! ⇒ 自動重配對一次，借鑒 CLI `open_session` 的教訓。

use std::path::{Path, PathBuf};

use uuid::Uuid;

use bw_proto::Auth;

use crate::bridge::Bridge;

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return d.into();
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitward")
}

pub fn token_file(data_dir: &Path) -> PathBuf {
    data_dir.join("nm_session")
}

/// 依凍結介面連線 daemon：有存檔 token ⇒ `Auth::Session` 續用；
/// 缺 ⇒ `Auth::Enroll`（pairing = 自製 uuid，握手成功才落盤）。
/// 第一次嘗試以任何理由失敗（典型：daemon 重啟、token 不認）⇒ 刪檔重配對一次。
pub async fn open_bridge() -> Result<Bridge, String> {
    let sock = std::env::var_os("BITWARD_SOCK")
        .map(PathBuf::from)
        .ok_or("BITWARD_SOCK not set (daemon UDS path required)")?;
    let dir = data_dir();
    let mut last = String::new();
    for attempt in 0..2u8 {
        match try_connect(&sock, &dir, attempt == 0).await {
            Ok(b) => return Ok(b),
            Err(e) => {
                let _ = std::fs::remove_file(token_file(&dir));
                last = e;
            }
        }
    }
    Err(format!(
        "cannot pair with daemon ({}): {last}",
        sock.display()
    ))
}

async fn try_connect(sock: &Path, dir: &Path, use_saved: bool) -> Result<Bridge, String> {
    let stream = tokio::net::UnixStream::connect(sock)
        .await
        .map_err(|e| format!("cannot connect to daemon ({}): {e}", sock.display()))?;
    let saved: Option<String> = if use_saved {
        tokio::fs::read_to_string(token_file(dir))
            .await
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    } else {
        None
    };
    let pairing = Uuid::new_v4().to_string();
    let enrolled = saved.is_none();
    let auth = match saved {
        Some(t) => Auth::Session { token: t },
        None => Auth::Enroll {
            pairing: pairing.clone(),
            display_name: format!("browser-nm:{}", std::process::id()),
            pair_code: None,
        },
    };
    let bridge = Bridge::connect(stream, auth).await?;
    if enrolled {
        if let Some(parent) = token_file(dir).parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        // 0600：token 是能力憑證，同 uid 之外不可讀。
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(token_file(dir))
                .map_err(|e| format!("token file: {e}"))?;
            f.write_all(pairing.as_bytes())
                .map_err(|e| format!("token file: {e}"))?;
        }
        #[cfg(not(unix))]
        tokio::fs::write(token_file(dir), &pairing)
            .await
            .map_err(|e| format!("token file: {e}"))?;
    }
    Ok(bridge)
}
