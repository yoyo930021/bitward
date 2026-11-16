//! BTP 骨幹（契約 §2.5、§3.9）：4 bytes LE 長度前綴 + 协商選定的訊息體編碼。
//! 編碼層與上限在 `bw_proto::wire`（規格：`docs/research/btp-frames.md`）；
//! 本 crate 只加 tokio 適配與 Full 端傳輸綁定：UDS（本機）、XPC（macOS provider，
//! 平台層）、TLS（跨機，P5）。

pub mod tls;

use bw_proto::{
    ClientMsg, ServerMsg,
    wire::{self, WireError, WireFormat},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 幀上限與編碼層同源（`bw_proto::wire`）：Full/thin 兩側不得各抄一份數值。
pub use bw_proto::wire::MAX_FRAME;

#[derive(Error, Debug)]
pub enum BtpError {
    #[error("io: {0}")]
    Io(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("frame too large: {len} > {max}")]
    FrameTooLarge { len: u32, max: u32 },
    #[error("connection closed")]
    Closed,
}

/// fd 層變體：tokio listener 的 accept 結果直接可用。
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid_from_fd(fd: std::os::unix::io::RawFd) -> Result<u32, BtpError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
    } else {
        Err(BtpError::Io("getpeereid failed".into()))
    }
}

#[cfg(target_os = "linux")]
pub fn peer_uid_from_fd(fd: std::os::unix::io::RawFd) -> Result<u32, BtpError> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Ok(cred.uid)
    } else {
        Err(BtpError::Io("SO_PEERCRED failed".into()))
    }
}

impl From<tokio::io::Error> for BtpError {
    fn from(e: tokio::io::Error) -> Self {
        BtpError::Io(e.to_string())
    }
}

impl From<WireError> for BtpError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Codec(m) => BtpError::Codec(m),
            WireError::FrameTooLarge { len, max } => BtpError::FrameTooLarge { len, max },
            WireError::Io(m) => BtpError::Io(m),
            WireError::Closed => BtpError::Closed,
        }
    }
}

pub async fn write_client<W>(w: &mut W, fmt: WireFormat, msg: &ClientMsg) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, fmt, msg).await
}

pub async fn read_client<R>(r: &mut R, fmt: WireFormat) -> Result<ClientMsg, BtpError>
where
    R: AsyncRead + Unpin,
{
    read_frame(r, fmt).await
}

pub async fn write_server<W>(w: &mut W, fmt: WireFormat, msg: &ServerMsg) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, fmt, msg).await
}

pub async fn read_server<R>(r: &mut R, fmt: WireFormat) -> Result<ServerMsg, BtpError>
where
    R: AsyncRead + Unpin,
{
    read_frame(r, fmt).await
}

async fn write_frame<W, T>(w: &mut W, fmt: WireFormat, msg: &T) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    // 訊息體編碼由連線級协商決定（bw_proto::wire）；本層只管長度前綴與讀寫。
    let body = wire::encode(fmt, msg)?;
    w.write_all(&wire::frame_head(body.len())).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R, T>(r: &mut R, fmt: WireFormat) -> Result<T, BtpError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut head = [0u8; wire::FRAME_HEADER];
    if r.read_exact(&mut head).await.is_err() {
        return Err(BtpError::Closed);
    }
    let len = u32::from_le_bytes(head);
    if len > MAX_FRAME {
        return Err(BtpError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    wire::decode(fmt, &body).map_err(Into::into)
}

/// 同機對端驗證第一層：連線程序 uid。
/// uid 相等只是必要條件；執行檔路徑與代碼簽章白名單在 daemon 層疊加（§1.4）。
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32, BtpError> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
    } else {
        Err(BtpError::Io("getpeereid failed".into()))
    }
}

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32, BtpError> {
    use std::os::unix::io::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Ok(cred.uid)
    } else {
        Err(BtpError::Io("SO_PEERCRED failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::*;

    fn list_msg(rid: u64) -> ClientMsg {
        ClientMsg::Invoke {
            rid,
            call: Call::Vault(VaultCall::List {
                query: Query {
                    text: Some("git".into()),
                    ..Default::default()
                },
                view: View::Metadata,
            }),
        }
    }

    #[tokio::test]
    async fn frame_roundtrip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        write_client(&mut a, WireFormat::Json, &list_msg(1))
            .await
            .unwrap();
        let got = read_client(&mut b, WireFormat::Json).await.unwrap();
        assert_eq!(rid_of(&got), 1);
    }

    #[tokio::test]
    async fn server_msg_roundtrip_with_error() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let msg = ServerMsg::Reply {
            rid: 9,
            outcome: Err(WtpError::HubOffline {
                last_seen_epoch_ms: Some(123),
            }),
        };
        write_server(&mut a, WireFormat::Json, &msg).await.unwrap();
        let got = read_server(&mut b, WireFormat::Json).await.unwrap();
        match got {
            ServerMsg::Reply {
                rid,
                outcome: Err(WtpError::HubOffline { last_seen_epoch_ms }),
            } => {
                assert_eq!(rid, 9);
                assert_eq!(last_seen_epoch_ms, Some(123));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn oversized_header_rejected_before_alloc() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let bogus: u32 = MAX_FRAME + 1;
        tokio::spawn(async move {
            a.write_all(&bogus.to_le_bytes()).await.unwrap();
            a.write_all(b"junk").await.unwrap();
        });
        match read_client::<_>(&mut b, WireFormat::Json).await {
            Err(BtpError::FrameTooLarge { .. }) => {}
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closed_stream_is_not_panic() {
        let (a, mut b) = tokio::io::duplex(1024);
        drop(a);
        assert!(matches!(
            read_client(&mut b, WireFormat::Json).await,
            Err(BtpError::Closed)
        ));
    }

    /// 舊對端實錄幀（PR5 前建置：Hello 不帶 `formats`、Welcome 不帶 `format`）
    /// 必須照樣解得出來，且缺欄語意＝JSON——混版本連線降階的地基。
    /// 位元組直接寫死，不靠本 crate 的編碼器產生（否則測的是自己）。
    #[tokio::test]
    async fn legacy_handshake_frames_decode_as_json() {
        let legacy_hello: &[u8] = br#"{"Hello":{"version":1,"auth":{"Enroll":{"pairing":"p-1","display_name":"cli:1","pair_code":null}},"wants":[]}}"#;
        let legacy_welcome: &[u8] =
            br#"{"Welcome":{"proto":1,"epoch":0,"server":{"kind":"Unknown","version":null,"features":[]},"state":"SignedOut","events_from":0}}"#;
        for (raw, expect) in [(legacy_hello, "Hello"), (legacy_welcome, "Welcome")] {
            let (mut a, mut b) = tokio::io::duplex(4096);
            let frame = [&(raw.len() as u32).to_le_bytes()[..], raw].concat();
            a.write_all(&frame).await.unwrap();
            let got = if expect == "Hello" {
                serde_json::to_value(read_client(&mut b, WireFormat::Json).await.unwrap()).unwrap()
            } else {
                serde_json::to_value(read_server(&mut b, WireFormat::Json).await.unwrap()).unwrap()
            };
            let body = got
                .get(expect)
                .unwrap_or_else(|| panic!("非 {expect} 幀：{got}"));
            if expect == "Hello" {
                assert_eq!(
                    body.get("formats").unwrap(),
                    &serde_json::json!([]),
                    "舊 Hello 的缺欄必須補成空偏好（＝协商時落回 JSON）"
                );
            } else {
                assert_eq!(
                    body.get("format").unwrap(),
                    &serde_json::json!("Json"),
                    "舊 Welcome 的缺欄必須讀成 JSON"
                );
            }
        }
    }

    /// 混格式誤接的誠實錯誤：postcard 體被當 JSON 讀（反之亦然）不得靜默成功。
    #[tokio::test]
    async fn wrong_format_is_codec_error_not_silence() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let pcard = wire::encode(WireFormat::Postcard, &list_msg(5)).unwrap();
        a.write_all(&(pcard.len() as u32).to_le_bytes())
            .await
            .unwrap();
        a.write_all(&pcard).await.unwrap();
        assert!(matches!(
            read_client(&mut b, WireFormat::Json).await,
            Err(BtpError::Codec(_))
        ));
    }

    fn rid_of(m: &ClientMsg) -> u64 {
        match m {
            ClientMsg::Invoke { rid, .. } => *rid,
            _ => u64::MAX,
        }
    }
}
