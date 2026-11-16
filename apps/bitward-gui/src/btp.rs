//! BTP 精簡同步 client（契約 §2.5；幀規格見 `docs/research/btp-frames.md`）。
//!
//! 編碼層不另起爐灶：length-prefix 與訊息體一律走 `bw_proto::wire`，與 daemon 的
//! `bw-btp` 同源（本 app 不吃 tokio，故用該模組的 std 路徑；握手照 CLI 慣例：
//! `Hello{Auth::Enroll{pair_code: None}}` → `Welcome` → `Invoke`/`Reply`，
//! 握手兩幀恆 JSON，Welcome 選定的格式套用到此後所有幀）。
//! 鎖撤銷（A6）會讓快取 session 作廢：偵測到就丟掉連線重 Enroll 一次。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bw_proto::{
    Auth, Call, ClientMsg, EventPayload, EventTopic, PROTO_VERSION, ProtoVersion, Response,
    ServerMsg, UnlockStateView, WtpError,
    wire::{self, WireFormat},
};

const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum BtpError {
    /// 傳輸層失敗（連不上、斷線、逾時、幀損壞）：重連可救。
    Transport(String),
    /// 協定層錯誤：daemon 給的明確裁決。
    Protocol(WtpError),
}

impl BtpError {
    /// UI 顯示用單行文案。
    pub fn display(&self) -> String {
        match self {
            BtpError::Transport(m) => m.clone(),
            BtpError::Protocol(e) => e.to_string(),
        }
    }

    /// 鎖世代不符或 session 已隨鎖撤銷：換新連線（重 Enroll）就有救。
    fn is_re_enrollable(&self) -> bool {
        match self {
            BtpError::Protocol(WtpError::StaleEpoch { .. }) => true,
            BtpError::Protocol(WtpError::Denied { grant_gap }) => grant_gap.contains("撤銷"),
            _ => false,
        }
    }
}

impl std::fmt::Display for BtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtpError::Transport(m) => write!(f, "{m}"),
            BtpError::Protocol(e) => write!(f, "{e}"),
        }
    }
}

impl From<WtpError> for BtpError {
    fn from(e: WtpError) -> Self {
        BtpError::Protocol(e)
    }
}

/// 一條可重連的 daemon 連線。`call` 內部序列化（Mutex），
/// worker 執行緒直接共用，不需額外排隊層。
pub struct Session {
    path: PathBuf,
    conn: Mutex<Option<Conn>>,
    rid: AtomicU64,
}

struct Conn {
    stream: std::os::unix::net::UnixStream,
    /// Welcome 帶回的鎖態（契約 §2.5：state 只有一份真相）。
    welcome_state: UnlockStateView,
    /// Welcome 選定的訊息體編碼（此後所有幀）。
    fmt: WireFormat,
}

impl Session {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Session {
            path: path.into(),
            conn: Mutex::new(None),
            rid: AtomicU64::new(1),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 丟掉目前連線（下次 ensure/call 重連重 Enroll）。
    pub fn drop_conn(&self) {
        if let Ok(mut guard) = self.conn.lock() {
            *guard = None;
        }
    }

    /// 確保有連線；回傳 Welcome 的鎖態（重連後是新的 Enroll，語意不變）。
    pub fn ensure(&self) -> Result<UnlockStateView, BtpError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| BtpError::Transport("conn mutex poisoned".into()))?;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.welcome_state.clone());
        }
        let conn = Conn::open(&self.path)?;
        let state = conn.welcome_state.clone();
        *guard = Some(conn);
        Ok(state)
    }

    /// 發一個呼叫並等 Reply。傳輸錯誤或「session 已隨鎖撤銷／世代過期」
    /// 時丟連線重連，再試一次（CLI `open_session` 的 re-enroll 語意）。
    pub fn call(&self, call: &Call) -> Result<Response, BtpError> {
        for attempt in 0..2u8 {
            if let Err(e) = self.ensure() {
                if attempt == 0 {
                    continue;
                }
                return Err(e);
            }
            let mut guard = self
                .conn
                .lock()
                .map_err(|_| BtpError::Transport("conn mutex poisoned".into()))?;
            let Some(conn) = guard.as_mut() else {
                continue;
            };
            let rid = self.rid.fetch_add(1, Ordering::Relaxed);
            match conn.round_trip(rid, call) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // 斷線或撤銷：丟掉連線；下一輪 attempt 會重連重 Enroll。
                    *guard = None;
                    drop(guard);
                    let recoverable = e.is_re_enrollable() || matches!(e, BtpError::Transport(_));
                    if attempt == 0 && recoverable {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(BtpError::Transport("連線反覆失敗".into()))
    }

    /// 事件監聽：自開一條訂閱連線（不佔用呼叫連線的 Mutex），阻塞收
    /// `Event` 幀並逐筆交 `on_event`；任何傳輸錯誤即回，由呼叫端重連。
    /// 監聽連線不發 Invoke，出現非 Event 幀即協定異常、回錯。
    pub fn listen(
        &self,
        wants: &[EventTopic],
        mut on_event: impl FnMut(EventTopic, EventPayload),
    ) -> Result<(), BtpError> {
        let mut conn = Conn::open_with(&self.path, wants.to_vec(), None)?;
        loop {
            match wire::read_frame::<_, ServerMsg>(&mut conn.stream, conn.fmt)
                .map_err(|e| BtpError::Transport(e.to_string()))?
            {
                ServerMsg::Event { topic, payload, .. } => on_event(topic, payload),
                other => {
                    return Err(BtpError::Transport(format!(
                        "監聽連線收到非事件幀：{other:?}"
                    )));
                }
            }
        }
    }
}

impl Conn {
    fn open(path: &Path) -> Result<Conn, BtpError> {
        // 呼叫連線不吃推播（wants 空）：事件走 `Session::listen` 專用連線，
        // 避免非 round_trip 時段的幀滯留互搶。
        Conn::open_with(path, Vec::new(), Some(IO_TIMEOUT))
    }

    fn open_with(
        path: &Path,
        wants: Vec<EventTopic>,
        read_timeout: Option<Duration>,
    ) -> Result<Conn, BtpError> {
        let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
            BtpError::Transport(format!("連不到 daemon（{}）：{e}", path.display()))
        })?;
        let _ = stream.set_read_timeout(read_timeout);
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut conn = Conn {
            stream,
            welcome_state: UnlockStateView::SignedOut,
            fmt: WireFormat::Json,
        };
        let pairing = uuid::Uuid::new_v4().to_string();
        wire::write_frame(
            &mut conn.stream,
            conn.fmt,
            &ClientMsg::Hello {
                version: ProtoVersion(PROTO_VERSION),
                auth: Auth::Enroll {
                    pairing,
                    display_name: format!("gui:{}", std::process::id()),
                    pair_code: None,
                },
                wants,
                formats: wire::supported_formats(),
            },
        )
        .map_err(|e| BtpError::Transport(e.to_string()))?;
        // Hello 之後第一幀必須是 Welcome（daemon 在 serve_conn 就回）；
        // 协商欄位缺省＝JSON，選定結果自此後的幀生效。
        match wire::read_frame::<_, ServerMsg>(&mut conn.stream, conn.fmt)
            .map_err(|e| BtpError::Transport(e.to_string()))?
        {
            ServerMsg::Welcome {
                proto,
                state,
                format,
                ..
            } => {
                if proto > PROTO_VERSION {
                    return Err(BtpError::Transport(format!(
                        "daemon proto {proto} > GUI {PROTO_VERSION}"
                    )));
                }
                conn.welcome_state = state;
                conn.fmt = format;
            }
            other => {
                return Err(BtpError::Transport(format!("預期 Welcome，收到 {other:?}")));
            }
        }
        Ok(conn)
    }

    fn round_trip(&mut self, rid: u64, call: &Call) -> Result<Response, BtpError> {
        wire::write_frame(
            &mut self.stream,
            self.fmt,
            &ClientMsg::Invoke {
                rid,
                call: call.clone(),
            },
        )
        .map_err(|e| BtpError::Transport(e.to_string()))?;
        loop {
            match wire::read_frame::<_, ServerMsg>(&mut self.stream, self.fmt)
                .map_err(|e| BtpError::Transport(e.to_string()))?
            {
                ServerMsg::Reply { rid: r, outcome } if r == rid => {
                    return outcome.map_err(BtpError::Protocol);
                }
                // wants 為空仍可能收到非訂閱事件；略過續等。
                ServerMsg::Event { .. } => continue,
                other => {
                    return Err(BtpError::Transport(format!("預期 Reply，收到 {other:?}")));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::wire::MAX_FRAME;
    use bw_proto::{Query, SortKey, VaultCall, View};
    use std::io::{Read as _, Write as _};

    fn list_msg(rid: u64) -> ClientMsg {
        ClientMsg::Invoke {
            rid,
            call: Call::Vault(VaultCall::List {
                query: Query {
                    text: Some("git".into()),
                    sort: SortKey::Name,
                    ..Default::default()
                },
                view: View::Metadata,
            }),
        }
    }

    #[test]
    fn frame_roundtrip_over_socketpair() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        wire::write_frame(&mut a, WireFormat::Json, &list_msg(7)).unwrap();
        let mut head = [0u8; 4];
        b.read_exact(&mut head).unwrap();
        let mut body = vec![0u8; u32::from_le_bytes(head) as usize];
        b.read_exact(&mut body).unwrap();
        let got: ClientMsg = serde_json::from_slice(&body).unwrap();
        match got {
            ClientMsg::Invoke { rid, .. } => assert_eq!(rid, 7),
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn oversized_frame_rejected_before_alloc() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let bogus = MAX_FRAME + 1;
        a.write_all(&bogus.to_le_bytes()).unwrap();
        a.write_all(b"junk").unwrap();
        assert!(matches!(
            wire::read_frame::<_, ServerMsg>(&mut b, WireFormat::Json),
            Err(wire::WireError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn missing_socket_is_transport_error() {
        let s = Session::new("/nonexistent/bitward-test.sock");
        match s.ensure() {
            Err(BtpError::Transport(m)) => assert!(m.contains("連不到 daemon")),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn listen_pump_delivers_subscribed_events() {
        use bw_proto::{ServerKind, ServerProfile};
        let dir = std::env::temp_dir().join(format!("btp-listen-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).unwrap();
            let mut body = vec![0u8; u32::from_le_bytes(head) as usize];
            stream.read_exact(&mut body).unwrap();
            let hello: ClientMsg = serde_json::from_slice(&body).unwrap();
            match hello {
                ClientMsg::Hello { wants, formats, .. } => {
                    assert!(wants.contains(&EventTopic::OutboxDrained));
                    assert_eq!(formats, wire::supported_formats(), "Hello 必須宣告格式偏好");
                }
                other => panic!("expected Hello, got {other:?}"),
            }
            wire::write_frame(
                &mut stream,
                WireFormat::Json,
                &ServerMsg::Welcome {
                    proto: PROTO_VERSION,
                    epoch: 1,
                    server: ServerProfile {
                        kind: ServerKind::Vaultwarden,
                        version: None,
                        features: vec![],
                    },
                    state: UnlockStateView::Unlocked {
                        epoch: 1,
                        deadline_epoch_ms: None,
                    },
                    events_from: 0,
                    format: WireFormat::Json,
                },
            )
            .unwrap();
            wire::write_frame(
                &mut stream,
                WireFormat::Json,
                &ServerMsg::Event {
                    topic: EventTopic::OutboxDrained,
                    seq: 1,
                    payload: bw_proto::EventPayload::OutboxDrained { pushed: 2 },
                },
            )
            .unwrap();
            // 保持連線一會，讓 client 有機會讀到 Event，再以 close 收尾。
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        let session = Session::new(&path);
        let mut got = Vec::new();
        let _ = session.listen(&[EventTopic::OutboxDrained], |t, p| got.push((t, p)));
        // 載荷必須原樣送到訂閱端（不是只給 topic）：pushed 值是 GUI 分岔的依據。
        assert_eq!(
            got,
            vec![(
                EventTopic::OutboxDrained,
                bw_proto::EventPayload::OutboxDrained { pushed: 2 }
            )]
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoked_session_marker_is_recoverable() {
        let denied = BtpError::Protocol(WtpError::Denied {
            grant_gap: "session 已隨鎖撤銷".into(),
        });
        assert!(denied.is_re_enrollable());
        let gap = BtpError::Protocol(WtpError::Denied {
            grant_gap: "授權不足".into(),
        });
        assert!(!gap.is_re_enrollable());
    }
}
