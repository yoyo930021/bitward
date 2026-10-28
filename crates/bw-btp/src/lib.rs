//! BTP 骨幹：4 bytes LE 長度前綴 + postcard 幀（契約 §2.5、§3.9）。
//! 傳輸綁定：UDS（本機）、XPC（macOS provider，平台層）、TLS（跨機，P5）。

use bw_proto::{ClientMsg, ServerMsg};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 1 MiB 上限。官方 IPC 框架用 1MB 前綴教訓：幀上限要在解碼前擋住，不是解碼後。
pub const MAX_FRAME: u32 = 1024 * 1024;

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

impl From<tokio::io::Error> for BtpError {
    fn from(e: tokio::io::Error) -> Self {
        BtpError::Io(e.to_string())
    }
}

pub async fn write_client<W>(w: &mut W, msg: &ClientMsg) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, msg).await
}

pub async fn read_client<R>(r: &mut R) -> Result<ClientMsg, BtpError>
where
    R: AsyncRead + Unpin,
{
    read_frame(r).await
}

pub async fn write_server<W>(w: &mut W, msg: &ServerMsg) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, msg).await
}

pub async fn read_server<R>(r: &mut R) -> Result<ServerMsg, BtpError>
where
    R: AsyncRead + Unpin,
{
    read_frame(r).await
}

async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), BtpError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let body = postcard::to_allocvec(msg).map_err(|e| BtpError::Codec(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| BtpError::FrameTooLarge {
        len: u32::MAX,
        max: MAX_FRAME,
    })?;
    if len > MAX_FRAME {
        return Err(BtpError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R, T>(r: &mut R) -> Result<T, BtpError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut head = [0u8; 4];
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
    postcard::from_bytes(&body).map_err(|e| BtpError::Codec(e.to_string()))
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
        write_client(&mut a, &list_msg(1)).await.unwrap();
        let got = read_client(&mut b).await.unwrap();
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
        write_server(&mut a, &msg).await.unwrap();
        let got = read_server(&mut b).await.unwrap();
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
        match read_client::<_>(&mut b).await {
            Err(BtpError::FrameTooLarge { .. }) => {}
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closed_stream_is_not_panic() {
        let (a, mut b) = tokio::io::duplex(1024);
        drop(a);
        assert!(matches!(read_client(&mut b).await, Err(BtpError::Closed)));
    }

    fn rid_of(m: &ClientMsg) -> u64 {
        match m {
            ClientMsg::Invoke { rid, .. } => *rid,
            _ => u64::MAX,
        }
    }
}
