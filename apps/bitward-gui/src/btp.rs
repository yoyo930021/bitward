//! BTP 精簡同步 client（契約 §2.5 P1 線格式：u32 LE 長度前綴 + JSON 幀）。
//!
//! 與 `bw-btp` 的 `write_frame`/`read_frame` 同語意，但走 std `UnixStream`：
//! GUI 的呼叫全在 worker 執行緒上跑，不把 tokio 拉進 app 依賴樹
//! （spike FINDINGS：`nsh run` 剝 target 依賴，普通依賴也越少越穩）。
//! 握手照 CLI 慣例：`Hello{Auth::Enroll{pair_code: None}}` → `Welcome` →
//! `Invoke`/`Reply`；本機 UDS 的 Enroll 即 Interactive 全權 session。
//! 鎖撤銷（A6）會讓快取 session 作廢：偵測到就丟掉連線重 Enroll 一次。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bw_proto::{
    Auth, Call, ClientMsg, EventTopic, PROTO_VERSION, ProtoVersion, Response, ServerMsg,
    UnlockStateView, WtpError,
};

/// 與 `bw_btp::MAX_FRAME` 同值：幀上限要在解碼前擋住。批次 4a 起放寬到
/// 48MiB——32MiB 附件的 base64 幀（≈43MiB）要過得了本機線。
const MAX_FRAME: u32 = 48 * 1024 * 1024;
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
        mut on_event: impl FnMut(EventTopic),
    ) -> Result<(), BtpError> {
        let mut conn = Conn::open_with(&self.path, wants.to_vec(), None)?;
        loop {
            match read_frame(&mut conn.stream)? {
                ServerMsg::Event { topic, .. } => on_event(topic),
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
        };
        let pairing = uuid::Uuid::new_v4().to_string();
        write_frame(
            &mut conn.stream,
            &ClientMsg::Hello {
                version: ProtoVersion(PROTO_VERSION),
                auth: Auth::Enroll {
                    pairing,
                    display_name: format!("gui:{}", std::process::id()),
                    pair_code: None,
                },
                wants,
            },
        )?;
        // Hello 之後第一幀必須是 Welcome（daemon 在 serve_conn 就回）。
        match read_frame(&mut conn.stream)? {
            ServerMsg::Welcome { proto, state, .. } => {
                if proto > PROTO_VERSION {
                    return Err(BtpError::Transport(format!(
                        "daemon proto {proto} > GUI {PROTO_VERSION}"
                    )));
                }
                conn.welcome_state = state;
            }
            other => {
                return Err(BtpError::Transport(format!("預期 Welcome，收到 {other:?}")));
            }
        }
        Ok(conn)
    }

    fn round_trip(&mut self, rid: u64, call: &Call) -> Result<Response, BtpError> {
        write_frame(
            &mut self.stream,
            &ClientMsg::Invoke {
                rid,
                call: call.clone(),
            },
        )?;
        loop {
            match read_frame(&mut self.stream)? {
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

fn write_frame<W: Write>(w: &mut W, msg: &impl serde::Serialize) -> Result<(), BtpError> {
    let body =
        serde_json::to_vec(msg).map_err(|e| BtpError::Transport(format!("編碼失敗：{e}")))?;
    let len = u32::try_from(body.len()).map_err(|_| BtpError::Transport("幀過大".into()))?;
    if len > MAX_FRAME {
        return Err(BtpError::Transport(format!("幀過大：{len} > {MAX_FRAME}")));
    }
    w.write_all(&len.to_le_bytes())
        .and_then(|()| w.write_all(&body))
        .map_err(|e| BtpError::Transport(format!("寫入失敗：{e}")))
}

fn read_frame<R: Read>(r: &mut R) -> Result<ServerMsg, BtpError> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head)
        .map_err(|e| BtpError::Transport(format!("讀取失敗：{e}")))?;
    let len = u32::from_le_bytes(head);
    if len > MAX_FRAME {
        return Err(BtpError::Transport(format!("幀過大：{len} > {MAX_FRAME}")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)
        .map_err(|e| BtpError::Transport(format!("讀取失敗：{e}")))?;
    serde_json::from_slice(&body).map_err(|e| BtpError::Transport(format!("解碼失敗：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::{Query, SortKey, VaultCall, View};

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
        write_frame(&mut a, &list_msg(7)).unwrap();
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
        assert!(matches!(read_frame(&mut b), Err(BtpError::Transport(_))));
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
                ClientMsg::Hello { wants, .. } => {
                    assert!(wants.contains(&EventTopic::OutboxDrained));
                }
                other => panic!("expected Hello, got {other:?}"),
            }
            write_frame(
                &mut stream,
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
                },
            )
            .unwrap();
            write_frame(
                &mut stream,
                &ServerMsg::Event {
                    topic: EventTopic::OutboxDrained,
                    seq: 1,
                    payload: serde_json::json!({}),
                },
            )
            .unwrap();
            // 保持連線一會，讓 client 有機會讀到 Event，再以 close 收尾。
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        let session = Session::new(&path);
        let mut topics = Vec::new();
        let _ = session.listen(&[EventTopic::OutboxDrained], |t| topics.push(t));
        assert_eq!(topics, vec![EventTopic::OutboxDrained]);
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
