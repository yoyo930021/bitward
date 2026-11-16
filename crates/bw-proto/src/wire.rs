//! BTP 幀編碼層（契約 §2.5；規格與 conformance vectors 見 `docs/research/btp-frames.md`）。
//!
//! 線形態：`u32 LE 長度前綴（不計自身）＋單一訊息體`。訊息體的編碼是**連線級**
//! 協商結果（`ClientMsg::Hello::formats` 宣告偏好、`ServerMsg::Welcome::format`
//! 選定），本模組只負責「一種格式 ↔ 一段位元組」的對稱映射；傳輸適配
//! （`bw-btp` 的 tokio 路徑、thin 端的 std `UnixStream` 路徑）各自只管讀寫迴圈。
//!
//! 為什麼碼在本 crate：Full 端與 thin 端必須對同一幀得出相同位元組。兩份
//! 實作（`bw-btp` 與 GUI `btp.rs`）曾各自抄寫 length-prefix JSON，格式要切換
//! 就得兩邊同步改——單一真相源放在雙方共同的依賴（協定型別）裡。

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// 幀上限要在解碼前擋住，不是解碼後（官方 IPC 框架 1MB 前綴教訓）。
/// 數值承自批次 4a：32 MiB 附件的 base64 體（≈43 MiB）要過得了本機線；
/// UDS/TLS 對端已經過 uid/簽章白名單（§1.4）。
pub const MAX_FRAME: u32 = 48 * 1024 * 1024;

/// 訊息體長度前綴的位元組數（u32 LE）。
pub const FRAME_HEADER: usize = 4;

/// 連線級訊息體編碼。
///
/// `Default`＝`Json`：不帶协商欄位的舊端只可能說 JSON，因此缺欄的語意就是 JSON
/// （§2.6 R3 寬容解析）。協商的偏好順序由宣告方（客戶端）決定，伺服器從中選
/// 自己支援的第一項。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireFormat {
    /// `serde_json`：自描述、人可讀；舊端與除錯位（`BW_BTP_JSON=1`）。
    #[default]
    Json,
    /// `postcard`：緊湊、非自描述；全型別化後的主線。
    Postcard,
}

impl WireFormat {
    /// 日誌與診斷用的穩定短名（幀層 content-type 標記）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Postcard => "postcard",
        }
    }
}

#[derive(Error, Debug)]
pub enum WireError {
    #[error("codec: {0}")]
    Codec(String),
    #[error("frame too large: {len} > {max}")]
    FrameTooLarge { len: u32, max: u32 },
    #[error("io: {0}")]
    Io(String),
    #[error("connection closed")]
    Closed,
}

/// 訊息體編碼（不含長度前綴）。
pub fn encode<T: Serialize>(fmt: WireFormat, msg: &T) -> Result<Vec<u8>, WireError> {
    let body = match fmt {
        WireFormat::Json => serde_json::to_vec(msg).map_err(|e| WireError::Codec(e.to_string()))?,
        WireFormat::Postcard => {
            postcard::to_allocvec(msg).map_err(|e| WireError::Codec(e.to_string()))?
        }
    };
    let len = u32::try_from(body.len()).map_err(|_| WireError::FrameTooLarge {
        len: u32::MAX,
        max: MAX_FRAME,
    })?;
    if len > MAX_FRAME {
        return Err(WireError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    Ok(body)
}

/// 訊息體解碼（不含長度前綴）。
pub fn decode<T: DeserializeOwned>(fmt: WireFormat, body: &[u8]) -> Result<T, WireError> {
    match fmt {
        WireFormat::Json => {
            serde_json::from_slice(body).map_err(|e| WireError::Codec(e.to_string()))
        }
        WireFormat::Postcard => {
            postcard::from_bytes(body).map_err(|e| WireError::Codec(e.to_string()))
        }
    }
}

/// std 傳輸寫幀：長度前綴 + 體，一次 `write_all`（前綴與體之間不插入他人寫入）。
pub fn write_frame<W: std::io::Write, T: Serialize>(
    w: &mut W,
    fmt: WireFormat,
    msg: &T,
) -> Result<(), WireError> {
    let body = encode(fmt, msg)?;
    let mut buf = Vec::with_capacity(FRAME_HEADER + body.len());
    buf.extend_from_slice(&frame_head(body.len()));
    buf.extend_from_slice(&body);
    w.write_all(&buf)
        .and_then(|()| w.flush())
        .map_err(|e| WireError::Io(e.to_string()))
}

/// 長度前綴（u32 LE）。`encode` 已擋過上限，這裡不再回錯。
#[must_use]
pub fn frame_head(body_len: usize) -> [u8; FRAME_HEADER] {
    u32::try_from(body_len).unwrap_or(u32::MAX).to_le_bytes()
}

/// std 傳輸讀幀：先讀前綴、擋上限、按實際長度分配讀體、再解碼。
pub fn read_frame<R: std::io::Read, T: DeserializeOwned>(
    r: &mut R,
    fmt: WireFormat,
) -> Result<T, WireError> {
    let mut head = [0u8; FRAME_HEADER];
    if r.read_exact(&mut head).is_err() {
        return Err(WireError::Closed);
    }
    let len = u32::from_le_bytes(head);
    if len > MAX_FRAME {
        return Err(WireError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)
        .map_err(|e| WireError::Io(e.to_string()))?;
    decode(fmt, &body)
}

/// 本進程能提供的格式清單（客戶端宣告、伺服器受理集合）。
///
/// 目前只列 JSON：協定型別裡還掛著 `serde_json::Value`
/// （`Response::Json`／`Audit`／`Sessions`／`Event::payload`），非自描述格式
/// 解不回來（`Value` 的反序列化要 `deserialize_any`）。型別化收尾批把
/// `Postcard` 放進清單頭部，逃生舷 `BW_BTP_JSON=1` 同批生效。
#[must_use]
pub fn supported_formats() -> Vec<WireFormat> {
    vec![WireFormat::Json]
}

/// 從客戶端宣告的偏好裡選出伺服器支援的格式；None＝無共同格式。
/// 偏好順序屬客戶端（例如只要 postcard 的嚴格端不得被降階成 JSON 後還被當成成功）。
/// 空偏好＝舊客戶端不宣告 formats，它只可能說 JSON。
#[must_use]
pub fn select_format(client_prefers: &[WireFormat]) -> Option<WireFormat> {
    select_format_in(client_prefers, &supported_formats())
}

/// `select_format` 的純函數本體（不讀程序狀態，混版本矩陣可直接測）。
#[must_use]
pub fn select_format_in(client_prefers: &[WireFormat], ours: &[WireFormat]) -> Option<WireFormat> {
    if client_prefers.is_empty() {
        return ours.contains(&WireFormat::Json).then_some(WireFormat::Json);
    }
    client_prefers.iter().find(|f| ours.contains(f)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Call, ClientMsg, Query, ServerMsg, VaultCall, View, WtpError};

    fn list_msg(rid: u64) -> ClientMsg {
        ClientMsg::Invoke {
            rid,
            call: Call::Vault(VaultCall::List {
                query: Query::default(),
                view: View::Metadata,
            }),
        }
    }

    /// 混版本协商矩陣（純函數側）：新客戶端偏好 postcard 但舊伺服器只支援 JSON
    /// 時必須降階；舊客戶端（空偏好）對新伺服器得 JSON；宣告了雙方無交集則誠實拒。
    #[test]
    fn selection_matrix_covers_mixed_versions() {
        let json_only = [WireFormat::Json];
        let both = [WireFormat::Postcard, WireFormat::Json];
        // 新客戶端 ↔ 舊伺服器（只支援 JSON）：降階。
        assert_eq!(select_format_in(&both, &json_only), Some(WireFormat::Json));
        // 舊客戶端（不帶 formats 欄）↔ 任何支援 JSON 的伺服器：JSON。
        assert_eq!(select_format_in(&[], &both), Some(WireFormat::Json));
        assert_eq!(select_format_in(&[], &json_only), Some(WireFormat::Json));
        // 嚴格 postcard 客戶端 ↔ 只支援 JSON 的伺服器：無交集（不得假成功降階）。
        assert_eq!(select_format_in(&[WireFormat::Postcard], &json_only), None);
        // 本進程現況：Value 未清完前不得宣告 postcard。
        assert_eq!(supported_formats(), vec![WireFormat::Json]);
        assert_eq!(select_format(&both), Some(WireFormat::Json));
    }

    #[test]
    fn json_body_is_byte_identical_to_serde_json() {
        // bw-btp/GUI 舊實作＝`serde_json::to_vec`；切到本模組不得改變一個位元組，
        // 否則混版本連線與既有 conformance 樣本全要重算。
        for msg in [
            serde_json::to_value(list_msg(3)).unwrap(),
            serde_json::to_value(ServerMsg::Error {
                message: "x".into(),
            })
            .unwrap(),
        ] {
            let raw = serde_json::to_vec(&msg).unwrap();
            assert_eq!(encode(WireFormat::Json, &msg).unwrap(), raw);
            let back: serde_json::Value = decode(WireFormat::Json, &raw).unwrap();
            assert_eq!(back, msg);
        }
    }

    #[test]
    fn postcard_body_is_smaller_than_json() {
        let msg = ClientMsg::Invoke {
            rid: 1,
            call: Call::Vault(VaultCall::List {
                query: Query {
                    text: Some("github.com/owner/repo".into()),
                    ..Default::default()
                },
                view: View::Reveal,
            }),
        };
        let j = encode(WireFormat::Json, &msg).unwrap();
        let p = encode(WireFormat::Postcard, &msg).unwrap();
        assert!(
            p.len() * 2 < j.len(),
            "postcard 應明顯小於 JSON（json={} postcard={}",
            j.len(),
            p.len()
        );
        let back: ClientMsg = decode(WireFormat::Postcard, &p).unwrap();
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&msg).unwrap()
        );
    }

    #[test]
    fn sync_frame_roundtrip_both_formats() {
        for fmt in [WireFormat::Json, WireFormat::Postcard] {
            let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
            let writer = std::thread::spawn(move || {
                let mut a = a;
                write_frame(&mut a, fmt, &list_msg(7)).unwrap();
                write_frame(
                    &mut a,
                    fmt,
                    &ServerMsg::Reply {
                        rid: 7,
                        outcome: Err(WtpError::Locked),
                    },
                )
                .unwrap();
            });
            let req: ClientMsg = read_frame(&mut b, fmt).unwrap();
            assert!(matches!(req, ClientMsg::Invoke { rid: 7, .. }));
            let rep: ServerMsg = read_frame(&mut b, fmt).unwrap();
            assert!(matches!(
                rep,
                ServerMsg::Reply {
                    outcome: Err(WtpError::Locked),
                    ..
                }
            ));
            writer.join().unwrap();
        }
    }

    #[test]
    fn closed_and_oversized_frames_are_honest_errors() {
        use std::io::Write as _;
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(a);
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut b, WireFormat::Json),
            Err(WireError::Closed)
        ));
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.write_all(&(MAX_FRAME + 1).to_le_bytes()).unwrap();
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut b, WireFormat::Postcard),
            Err(WireError::FrameTooLarge { .. })
        ));
    }
}
