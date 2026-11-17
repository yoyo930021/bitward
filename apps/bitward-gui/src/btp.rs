//! BTP 精簡同步 client（契約 §2.5；幀規格見 `docs/research/btp-frames.md`）。
//!
//! 編碼層不另起爐灶：length-prefix 與訊息體一律走 `bw_proto::wire`，與 daemon 的
//! `bw-btp` 同源（本 app 不吃 tokio，故用該模組的 std 路徑；握手照 CLI 慣例：
//! `Hello{...}` → `Welcome` → `Invoke`/`Reply`，握手兩幀恆 JSON，Welcome 選定的
//! 格式套用到此後所有幀）。
//! 傳輸兩形態（PR6-E3b，§1.4）：本機 UDS 走 `Auth::Enroll`（peer uid 即身分）；
//! 跨機走同步 rustls＋SPKI pin（verifier 真相源在 `bw_btp::tls::client_config`）、
//! 以配對落檔的 token 發 `Auth::Session`（同 CLI `try_remote`）。
//! 鎖撤銷（A6）會讓快取 session 作廢：偵測到就丟掉連線重握手一次。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bw_proto::{
    Auth, Call, ClientMsg, EventPayload, EventTopic, PROTO_VERSION, ProtoVersion, Response,
    ServerMsg, UnlockStateView, WtpError,
    wire::{self, WireFormat},
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// 跨機 TLS 目標：由 `remotes/<profile>.json` 組出（編組在 `hub`）。
/// `url` 是落檔正規形態（`https://host:port`），僅供顯示；連線用 host/port。
#[derive(Clone, Debug)]
pub struct TlsTarget {
    pub profile: String,
    pub url: String,
    pub host: String,
    pub port: u16,
    /// base64(SHA-256(SPKI))：唯一信任錨點（無 CA 體系）。
    pub pin: String,
    /// 配對時落檔的 device token（`Auth::Session` 憑據）。
    pub token: String,
}

/// daemon 連線的傳輸層。本機＝UDS；跨機＝TLS＋pin＋配對 token。
#[derive(Clone, Debug)]
pub enum Transport {
    Unix(PathBuf),
    Tls(TlsTarget),
}

impl Transport {
    /// UI/錯誤畫面用單行目標描述。
    pub fn describe(&self) -> String {
        match self {
            Transport::Unix(p) => format!("本機 daemon（{}）", p.display()),
            Transport::Tls(t) => format!("hub「{}」（{}）", t.profile, t.url),
        }
    }

    fn unix_path(&self) -> Option<&Path> {
        match self {
            Transport::Unix(p) => Some(p),
            Transport::Tls(_) => None,
        }
    }
}

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
    transport: Arc<Mutex<Transport>>,
    /// E5 帳號槽（`accounts/<profile>`）。None＝交 daemon 的預設槽指標。
    /// 與 `transport` 正交：跨機 hub 是「連哪台中樞」，帳號槽是「那台中樞裡哪個帳號」。
    account: Arc<Mutex<Option<String>>>,
    /// 傳輸切換計數：快取 conn 記開連世代，世代不符即重開——切換恰好落在
    /// 開連中途時，舊目標連線不會永久霸佔快取。
    switch_gen: Arc<AtomicU64>,
    conn: Mutex<Option<Conn>>,
    /// 事件幫浦活連線的可關閉句柄：`set_transport` 用它 shutdown 阻塞中的
    /// read，幫浦立刻重連新目標（不等到下一筆事件才換軌）。
    listen_h: Mutex<Option<ListenHandle>>,
    rid: AtomicU64,
}

struct Conn {
    stream: Stream,
    /// 開連時的傳輸世代（見 `Session::switch_gen`）。
    switch_gen: u64,
    /// Welcome 帶回的鎖態（契約 §2.5：state 只有一份真相）。
    welcome_state: UnlockStateView,
    /// Welcome 選定的訊息體編碼（此後所有幀）。
    fmt: WireFormat,
}

/// 兩形態共用的雙向流：`wire` 只要求 Read+Write，UDS 與同步 rustls 都滿足。
enum Stream {
    Unix(std::os::unix::net::UnixStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

/// try_clone 出的第二描述符：獨立持有、可隨時 shutdown 中斷幫浦連線的 read。
enum ListenHandle {
    Unix(std::os::unix::net::UnixStream),
    Tcp(TcpStream),
}

impl ListenHandle {
    fn shutdown(&self) {
        use std::net::Shutdown::Both;
        match self {
            ListenHandle::Unix(s) => {
                let _ = s.shutdown(Both);
            }
            ListenHandle::Tcp(s) => {
                let _ = s.shutdown(Both);
            }
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Unix(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl Session {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Session::with_transport(Transport::Unix(path.into()))
    }

    /// 跨機連線只由 `set_transport` 熱切換而來（啟動恆為本機 sock）。
    fn with_transport(transport: Transport) -> Self {
        Session {
            transport: Arc::new(Mutex::new(transport)),
            account: Arc::new(Mutex::new(None)),
            switch_gen: Arc::new(AtomicU64::new(0)),
            conn: Mutex::new(None),
            listen_h: Mutex::new(None),
            rid: AtomicU64::new(1),
        }
    }

    /// 第二連線：共用傳輸槽（切換一起跟隨），各自持連線與請求計數。
    /// favicon 與事件幫浦都用它，避免 AppCore 持有可變 `Arc<Session>` 欄位。
    pub fn fork(&self) -> Session {
        Session {
            transport: self.transport.clone(),
            account: self.account.clone(),
            switch_gen: self.switch_gen.clone(),
            conn: Mutex::new(None),
            listen_h: Mutex::new(None),
            rid: AtomicU64::new(1),
        }
    }

    pub fn transport(&self) -> Transport {
        self.transport
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| Transport::Unix(PathBuf::new()))
    }

    /// UI/錯誤畫面用的目標描述。
    pub fn describe(&self) -> String {
        self.transport().describe()
    }

    /// 本機 UDS 路徑（跨機態＝None；e2e 截圖鏈 spawn 本機 CLI 用）。
    pub fn unix_path(&self) -> Option<PathBuf> {
        self.transport().unix_path().map(Path::to_path_buf)
    }

    /// 目前連線綁定的 hub profile 名（本機態＝None）。
    pub fn active_profile(&self) -> Option<String> {
        match self.transport() {
            Transport::Unix(_) => None,
            Transport::Tls(t) => Some(t.profile),
        }
    }

    /// 熱切換目標（設定頁「連線／本機」）：換槽、進世代、丟快取連線、
    /// 中斷事件幫浦讀——下一拍所有連線都走新目標。
    pub fn set_transport(&self, transport: Transport) {
        if let Ok(mut guard) = self.transport.lock() {
            *guard = transport;
        }
        self.switch_gen.fetch_add(1, Ordering::Relaxed);
        self.drop_conn();
        if let Ok(mut h) = self.listen_h.lock()
            && let Some(handle) = h.take()
        {
            handle.shutdown();
        }
    }

    /// 目前連線綁定的帳號槽（E5；None＝daemon 預設槽）。
    pub fn account(&self) -> Option<String> {
        self.account.lock().ok().and_then(|g| g.clone())
    }

    /// 切帳號槽（頂部帳號列的切換器）：換槽、進世代、丟快取連線、中斷事件幫浦
    /// ——下一拍所有連線都以新槽重新 Enroll。語意同 `set_transport`，兩者正交。
    pub fn set_account(&self, name: Option<String>) {
        if let Ok(mut guard) = self.account.lock() {
            *guard = name;
        }
        self.switch_gen.fetch_add(1, Ordering::Relaxed);
        self.drop_conn();
        if let Ok(mut h) = self.listen_h.lock()
            && let Some(handle) = h.take()
        {
            handle.shutdown();
        }
    }

    /// 丟掉目前連線（下次 ensure/call 重連重握手）。
    pub fn drop_conn(&self) {
        if let Ok(mut guard) = self.conn.lock() {
            *guard = None;
        }
    }

    /// 確保有連線；回傳 Welcome 的鎖態（重連後是新的握手，語意不變）。
    pub fn ensure(&self) -> Result<UnlockStateView, BtpError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| BtpError::Transport("conn mutex poisoned".into()))?;
        for _ in 0..2 {
            let sg = self.switch_gen.load(Ordering::Relaxed);
            if let Some(conn) = guard.as_ref()
                && conn.switch_gen == sg
            {
                return Ok(conn.welcome_state.clone());
            }
            *guard = None;
            let transport = self
                .transport
                .lock()
                .map_err(|_| BtpError::Transport("transport mutex poisoned".into()))?
                .clone();
            let conn = Conn::open(transport, sg, Vec::new(), Some(IO_TIMEOUT), self.account())?;
            // 開連期間被切換：舊目標連線直接丟棄，下一輪以新世代重開。
            if conn.switch_gen == self.switch_gen.load(Ordering::Relaxed) {
                let state = conn.welcome_state.clone();
                *guard = Some(conn);
                return Ok(state);
            }
        }
        Err(BtpError::Transport("連線反覆被切換中斷".into()))
    }

    /// 發一個呼叫並等 Reply。傳輸錯誤或「session 已隨鎖撤銷／世代過期」
    /// 時丟連線重連，再試一次（CLI `open_session` 的重握手語意）。
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
                    // 斷線或撤銷：丟掉連線；下一輪 attempt 會重連重握手。
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
    /// 傳輸切換（`set_transport`）會 shutdown 本連線＝即刻回錯讓幫浦換軌。
    pub fn listen(
        &self,
        wants: &[EventTopic],
        mut on_event: impl FnMut(EventTopic, EventPayload),
    ) -> Result<(), BtpError> {
        let transport = self
            .transport
            .lock()
            .map_err(|_| BtpError::Transport("transport mutex poisoned".into()))?
            .clone();
        let sg = self.switch_gen.load(Ordering::Relaxed);
        let mut conn = Conn::open(transport, sg, wants.to_vec(), None, self.account())?;
        // 註冊可關閉句柄後才進讀迴圈；離開（任何路徑）即摘除。
        if let Some(handle) = conn.stream_handle()
            && let Ok(mut slot) = self.listen_h.lock()
        {
            *slot = Some(handle);
        }
        let _slot = ListenSlot { session: self };
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

/// listen 期間的句柄佔位：離開即從 Session 摘除，避免切換時
/// shutdown 到已關閉的舊描述符。
struct ListenSlot<'a> {
    session: &'a Session,
}

impl Drop for ListenSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut h) = self.session.listen_h.lock() {
            let _ = h.take();
        }
    }
}

/// 同步 rustls 連線：StreamOwned 在首讀寫惰性完成握手，pin 不符即成 IO 錯。
/// 逾時設在內層 TcpStream（rustls 讀寫都經它）。
fn tls_connect(
    host: &str,
    port: u16,
    pin: &str,
    read_timeout: Option<Duration>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, BtpError> {
    let tcp = TcpStream::connect((host, port))
        .map_err(|e| BtpError::Transport(format!("連不到 hub（{host}:{port}）：{e}")))?;
    let _ = tcp.set_read_timeout(read_timeout);
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| BtpError::Transport(format!("TLS 目標名稱非法（{host}）：{e}")))?;
    let conn = ClientConnection::new(bw_btp::tls::client_config(pin), name)
        .map_err(|e| BtpError::Transport(format!("TLS 初始化失敗：{e}")))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Hello/Welcome 握手兩幀（恆 JSON）：回鎖態與 Welcome 選定的格式。
fn handshake(
    stream: &mut Stream,
    auth: Auth,
    wants: Vec<EventTopic>,
) -> Result<(UnlockStateView, WireFormat), BtpError> {
    wire::write_frame(
        stream,
        WireFormat::Json,
        &ClientMsg::Hello {
            version: ProtoVersion(PROTO_VERSION),
            auth,
            wants,
            formats: wire::supported_formats(),
        },
    )
    .map_err(|e| BtpError::Transport(e.to_string()))?;
    // Hello 之後第一幀必須是 Welcome（daemon 在 serve_conn 就回）。
    match wire::read_frame::<_, ServerMsg>(stream, WireFormat::Json)
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
            Ok((state, format))
        }
        // 握手被拒（unknown session／跨機需配對碼）：daemon 先發 Error 再 close，
        // 原因必須上車，才不會被歸因成單純斷線。
        ServerMsg::Error { message } => Err(BtpError::Transport(format!("握手被拒：{message}"))),
        other => Err(BtpError::Transport(format!("預期 Welcome，收到 {other:?}"))),
    }
}

/// 一次性配對握手（設定頁「配對碼加入」）：TLS＋pin 連上後以配對碼換
/// device token。回的就是要落檔 `remotes/<profile>.json` 的 token——
/// daemon 以 Hello.pairing 作 session id（同 CLI `pair join`）。
pub fn join_hub(
    host: &str,
    port: u16,
    pin: &str,
    code: &str,
    name: &str,
) -> Result<String, BtpError> {
    let mut stream = Stream::Tls(Box::new(tls_connect(host, port, pin, Some(IO_TIMEOUT))?));
    let pairing = uuid::Uuid::new_v4().to_string();
    handshake(
        &mut stream,
        Auth::Enroll {
            pairing: pairing.clone(),
            display_name: format!("gui:{name}"),
            pair_code: Some(code.to_owned()),
            profile: None,
        },
        Vec::new(),
    )?;
    Ok(pairing)
}

impl Conn {
    /// 開一條連線并完成握手。本機 UDS＝Enroll（peer uid 即身分）；
    /// 跨機＝TLS（pin 在握手中驗證）＋配對落檔 token 的 Session 認證。
    fn open(
        transport: Transport,
        switch_gen: u64,
        wants: Vec<EventTopic>,
        read_timeout: Option<Duration>,
        account: Option<String>,
    ) -> Result<Conn, BtpError> {
        let mut stream = match &transport {
            // 呼叫連線不吃推播（wants 空）：事件走 `Session::listen` 專用連線，
            // 避免非 round_trip 時段的幀滯留互搶。
            Transport::Unix(path) => {
                let s = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
                    BtpError::Transport(format!("連不到 daemon（{}）：{e}", path.display()))
                })?;
                let _ = s.set_read_timeout(read_timeout);
                let _ = s.set_write_timeout(Some(IO_TIMEOUT));
                Stream::Unix(s)
            }
            Transport::Tls(t) => Stream::Tls(Box::new(tls_connect(
                &t.host,
                t.port,
                &t.pin,
                read_timeout,
            )?)),
        };
        let auth = match &transport {
            Transport::Unix(_) => Auth::Enroll {
                pairing: uuid::Uuid::new_v4().to_string(),
                display_name: format!("gui:{}", std::process::id()),
                pair_code: None,
                profile: account,
            },
            Transport::Tls(t) => Auth::Session {
                token: t.token.clone(),
            },
        };
        let (welcome_state, fmt) = handshake(&mut stream, auth, wants)?;
        Ok(Conn {
            stream,
            switch_gen,
            welcome_state,
            fmt,
        })
    }

    /// 事件幫浦用的可關閉句柄（clone 失敗＝無法中斷，僅退化為等下一筆事件）。
    fn stream_handle(&self) -> Option<ListenHandle> {
        match &self.stream {
            Stream::Unix(s) => s.try_clone().ok().map(ListenHandle::Unix),
            Stream::Tls(s) => s.sock.try_clone().ok().map(ListenHandle::Tcp),
        }
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
                    profile: String::new(),
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

    fn welcome_msg() -> ServerMsg {
        use bw_proto::{ServerKind, ServerProfile};
        ServerMsg::Welcome {
            proto: PROTO_VERSION,
            epoch: 1,
            profile: String::new(),
            server: ServerProfile {
                kind: ServerKind::Vaultwarden,
                version: None,
                features: vec![],
            },
            state: UnlockStateView::Unlocked {
                epoch: 7,
                deadline_epoch_ms: None,
            },
            events_from: 0,
            format: WireFormat::Json,
        }
    }

    /// 同步 rustls 假 hub（真 `bw_btp::tls` 憑證＋server_config，pin 即其 SPKI）：
    /// accept 一筆，回 Hello 摘要（`enroll:<pairing>:<code>:<name>`／`session:<token>`），
    /// 再按 `reply_ok` 回 Welcome 或拒因 Error。讀不到 Hello（pin 不符）即靜默退。
    fn fake_tls_hub(tag: &str, reply_ok: bool) -> (u16, String, std::sync::mpsc::Receiver<String>) {
        let dir = std::env::temp_dir().join(format!("btp-tls-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = bw_btp::tls::load_or_create(&dir).unwrap();
        let cfg = bw_btp::tls::server_config(&id).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(cfg).unwrap();
            let mut s = rustls::StreamOwned::new(conn, tcp);
            let Ok(ClientMsg::Hello { auth, .. }) =
                wire::read_frame::<_, ClientMsg>(&mut s, WireFormat::Json)
            else {
                return; // pin 不符：TLS 層就斷，沒有 Hello 可看
            };
            let summary = match &auth {
                Auth::Session { token } => format!("session:{token}"),
                Auth::Enroll {
                    pairing,
                    pair_code,
                    display_name,
                    ..
                } => format!("enroll:{pairing}:{pair_code:?}:{display_name}"),
                other => format!("other:{other:?}"),
            };
            let _ = tx.send(summary);
            let msg = if reply_ok {
                welcome_msg()
            } else {
                ServerMsg::Error {
                    message: "配對碼無效或已過期".into(),
                }
            };
            let _ = wire::write_frame(&mut s, WireFormat::Json, &msg);
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = std::fs::remove_dir_all(&dir);
        });
        (port, id.spki_pin, rx)
    }

    fn tls_target(port: u16, pin: &str) -> TlsTarget {
        TlsTarget {
            profile: "desk".into(),
            url: format!("https://127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            pin: pin.into(),
            token: "tok-1".into(),
        }
    }

    /// Transport::Tls 主鏈：pin 正確→握手完成、認證幀是配對 token 的
    /// `Auth::Session`（同 CLI try_remote），Welcome 鎖態原樣上車。
    #[test]
    fn tls_transport_authenticates_with_paired_token() {
        let (port, pin, rx) = fake_tls_hub("ok", true);
        let s = Session::with_transport(Transport::Tls(tls_target(port, &pin)));
        let state = s.ensure().expect("pin 正確必須完成握手");
        assert!(matches!(state, UnlockStateView::Unlocked { epoch: 7, .. }));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "session:tok-1"
        );
        assert!(s.describe().contains("hub「desk」"));
        assert_eq!(s.active_profile().as_deref(), Some("desk"));
        assert!(s.unix_path().is_none());
    }

    /// 錯 pin 必須在 TLS 層擋死（自簽無 CA：pin 是唯一信任錨點），
    /// 且不得把 token 交出去（假 hub 讀不到任何 Hello）。
    #[test]
    fn tls_wrong_pin_fails_handshake() {
        let (port, _pin, rx) = fake_tls_hub("badpin", true);
        let bad = format!("{}B", "A".repeat(43));
        let s = Session::with_transport(Transport::Tls(tls_target(port, &bad)));
        match s.ensure() {
            Err(BtpError::Transport(m)) => {
                let lower = m.to_lowercase();
                assert!(
                    lower.contains("tls") || lower.contains("pin") || lower.contains("alert"),
                    "錯 pin 應給可懂 TLS 錯：{m}"
                );
            }
            other => panic!("expected Transport, got {other:?}"),
        }
        assert!(
            rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "pin 不符不該有 Hello 抵達 hub"
        );
    }

    /// 配對加入：`pair_code` 上車換 token，回值即落檔用的 device token
    /// （daemon 拿 Hello.pairing 當 session id——錯一個字元就永久配不上）。
    #[test]
    fn join_hub_trades_pair_code_for_token() {
        let (port, pin, rx) = fake_tls_hub("join", true);
        let token = join_hub("127.0.0.1", port, &pin, "CODE9AB", "laptop").unwrap();
        let seen = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen, format!("enroll:{token}:Some(\"CODE9AB\"):gui:laptop"));
    }

    /// daemon 拒因（Error 幀）必須進錯誤文案，不能糊成「連不上」。
    #[test]
    fn join_hub_rejection_surfaces_reason() {
        let (port, pin, _rx) = fake_tls_hub("reject", false);
        match join_hub("127.0.0.1", port, &pin, "WRONG99", "laptop") {
            Err(BtpError::Transport(m)) => assert!(m.contains("配對碼無效"), "got {m}"),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    /// 熱切換：fork 出的第二連線跟隨同一傳輸槽；切換後本機路徑即失。
    #[test]
    fn set_transport_propagates_to_forks() {
        let a = Session::new("/tmp/x.sock");
        let b = a.fork();
        assert!(a.unix_path().is_some());
        a.set_transport(Transport::Tls(tls_target(8443, "pin")));
        assert!(a.unix_path().is_none());
        assert_eq!(b.active_profile().as_deref(), Some("desk"));
    }
}
