//! BTP 框架：長度前綴幀 + 對端驗證 + ClientMsg/ServerMsg 收發（契約 §2.5、§3.9）。
//! 傳輸綁定：UDS（本機）、XPC（macOS provider，U6 後）、TLS（跨機，P5）。實作由 U6 填入。

use bw_proto::{ClientMsg, ServerMsg};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BtpError {
    #[error("io: {0}")]
    Io(String),
    #[error("proto: version {peer} unsupported")]
    Version { peer: u16 },
    #[error("frame too large")]
    FrameTooLarge,
}

/// 4 bytes LE 長度前綴 + postcard 主體；上限 1 MiB（官方 IPC 同法，教訓取自其框架）
pub async fn write_msg<W>(w: &mut W, msg: &ClientMsg) -> Result<(), BtpError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let _ = (w, msg);
    todo!("U6")
}

pub async fn read_server_msg<R>(r: &mut R) -> Result<ServerMsg, BtpError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let _ = r;
    todo!("U6")
}

/// 同機對端驗證：LOCAL_PEERCRED uid + 執行檔路徑（+ macOS SecCode 白名單，U6/平台層）
#[cfg(unix)]
pub fn peer_uid(stream_fd: i32) -> Result<u32, BtpError> {
    let _ = stream_fd;
    todo!("U6")
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // U6：記憶體 transport 的 conformance vectors（§5.1 測試 3）
    }
}
