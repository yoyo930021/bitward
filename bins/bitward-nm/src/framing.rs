//! Chromium native messaging stdio 協定：4 bytes **little-endian** 長度前綴 + UTF-8 JSON。
//! 來源：<https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging>
//! （Chromium 以 native endian 寫入；macOS/Linux 皆 LE。BTP 線格式同為 LE 前綴，
//! 但那是 postcard/JSON 的協定型別化幀——本檔是 NM 面自用的 `serde_json::Value` 幀。）

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// host→extension 方向 Chrome 硬性上限 1 MiB；對稱套用。
pub const MAX_FRAME: usize = 1024 * 1024;

/// 讀一幀。回 `Ok(None)`＝輸入流乾淨 EOF（呼叫端應結束）；
/// 部分前綴（0 < n < 4 後 EOF）視同 EOF；截斷本體或超限是錯誤。
pub async fn read_nm<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Option<Value>, String> {
    let raw = read_raw(rd).await?;
    match raw {
        None => Ok(None),
        Some(b) => {
            let v = serde_json::from_slice(&b).map_err(|e| format!("nm json: {e}"))?;
            Ok(Some(v))
        }
    }
}

/// `Ok(None)`＝EOF（含部分前綴）；`Ok(Some)`＝本體完整讀取。
pub async fn read_raw<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut head = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match rd.read(&mut head[got..]).await {
            Ok(0) => return Ok(None),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("nm length prefix: {e}")),
        }
    }
    let len = u32::from_le_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(format!("nm frame too large: {len} > {MAX_FRAME}"));
    }
    let mut body = vec![0u8; len];
    rd.read_exact(&mut body)
        .await
        .map_err(|e| format!("nm body read: {e}"))?;
    Ok(Some(body))
}

/// 寫一幀（LE 前綴 + UTF-8 JSON）。
pub async fn write_nm<W: AsyncWrite + Unpin>(wr: &mut W, msg: &Value) -> Result<(), String> {
    write_nm_raw(wr, msg).await
}

pub(crate) async fn write_nm_raw<W: AsyncWrite + Unpin>(
    wr: &mut W,
    msg: &impl Serialize,
) -> Result<(), String> {
    let body = serde_json::to_vec(msg).map_err(|e| format!("nm json: {e}"))?;
    if body.len() > MAX_FRAME {
        return Err(format!("nm frame too large: {} > {MAX_FRAME}", body.len()));
    }
    wr.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .map_err(|e| format!("nm write prefix: {e}"))?;
    wr.write_all(&body).await.map_err(|e| format!("nm write body: {e}"))?;
    wr.flush().await.map_err(|e| format!("nm flush: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::duplex;

    #[tokio::test]
    async fn le_round_trip() {
        let (a, mut b) = duplex(1 << 16);
        let (mut w, mut r) = tokio::io::split(a);
        let msg = json!({"id": 7, "method": "ping", "params": {}});
        let t = tokio::spawn(async move { write_nm(&mut w, &msg).await });
        let got = read_nm(&mut r).await.unwrap().unwrap();
        assert_eq!(got, msg);
        t.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn prefix_is_little_endian() {
        let (mut w, mut r) = duplex(1 << 16);
        let msg = json!({"ok": true}); // 11 bytes
        write_nm(&mut w, &msg).await.unwrap();
        let mut head = [0u8; 4];
        r.read_exact(&mut head).await.unwrap();
        assert_eq!(head, 11u32.to_le_bytes());
        assert_eq!(&head, &[11, 0, 0, 0]);
        let mut body = vec![0u8; 11];
        r.read_exact(&mut body).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), msg);
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let (mut w, mut r) = duplex(64);
        drop(w);
        assert!(read_nm(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_prefix_is_eof() {
        let (mut w, mut r) = duplex(64);
        w.write_all(&[3, 0]).await.unwrap();
        w.flush().unwrap();
        drop(w);
        assert!(read_nm(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_body_is_error() {
        let (mut w, mut r) = duplex(64);
        w.write_all(&[9, 0, 0, 0, b'{']).await.unwrap();
        w.flush().unwrap();
        drop(w);
        assert!(read_nm(&mut r).await.is_err());
    }

    #[tokio::test]
    async fn oversized_frame_rejected_before_alloc() {
        let (mut w, mut r) = duplex(64);
        let fake = MAX_FRAME as u32 + 1;
        w.write_all(&fake.to_le_bytes()).await.unwrap();
        w.flush().unwrap();
        let e = read_nm(&mut r).await.unwrap_err();
        assert!(e.contains("too large"), "{e}");
    }
}
