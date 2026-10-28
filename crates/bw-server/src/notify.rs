//! notifications hub：一條 WS 連線、兩種協議形態（契约 §3.3）。
//!
//! - 官方雲走 ASP.NET Core SignalR 的 **json hub protocol**：文字握手
//!   `{"protocol":"json","version":1}` + `0x1e` 分隔符，之後每個文字 frame 是一條
//!   JSON 訊息（可再用 `0x1e` 分包）。
//! - Vaultwarden 走同一条 `/notifications/hub`，但只認 **messagepack 握手**，並用
//!   SignalR 的 binary message format（varint 長度前綴 + msgpack 內文）派送
//!   `[1, {}, null, "ReceiveMessage", [{ContextId,Type,Payload}]]`。
//!   來源：https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L614-L676
//!   （`RECORD_SEPARATOR`、`INITIAL_MESSAGE{protocol:"messagepack"}`、`create_update`）
//!   實測（本倉庫 fixtures/notifications_vw_msgpack_frame.bin，VW 1.37.2）：送 json 握手
//!   不會得到 `{}\u001e` 回應，只送 messagepack 握手才會。
//!
//! 因此這裡同時實作兩態，並讓解碼器對「形態與模式不符」的 frame 宽容：任何 frame
//! 先試 JSON 再試 msgpack，避免 server 升級時整條事件流失效。

use base64::Engine as _;
use bw_proto::ItemId;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http;

use crate::Client;
use crate::error::ServerError;
use crate::json::get;
use crate::profile::feature;

const RECORD_SEPARATOR: u8 = 0x1e;

/// 握手協議形態。由 [`Client::probe`] 的 server kind 決定，也可強制指定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationMode {
    /// 官方雲：json hub protocol（文字 frame + `0x1e` 分隔）。
    SignalRJson,
    /// Vaultwarden：messagepack 握手 + msgpack binary frame（純 WS，無 negotiate）。
    VaultwardenWs,
}

/// 更新型別；編號對齊 upstream `UpdateType`
/// （https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L678-L700
/// 註解指向 bitwarden/server `src/Core/Enums/PushType.cs`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UpdateType {
    SyncCipherUpdate,
    SyncCipherCreate,
    SyncLoginDelete,
    SyncFolderDelete,
    SyncCiphers,
    SyncVault,
    SyncOrgKeys,
    SyncFolderCreate,
    SyncFolderUpdate,
    SyncSettings,
    LogOut,
    SyncSendCreate,
    SyncSendUpdate,
    SyncSendDelete,
    AuthRequest,
    AuthRequestResponse,
    Other(i32),
}

impl UpdateType {
    pub fn from_i32(n: i32) -> Self {
        match n {
            0 => Self::SyncCipherUpdate,
            1 => Self::SyncCipherCreate,
            2 => Self::SyncLoginDelete,
            3 => Self::SyncFolderDelete,
            4 => Self::SyncCiphers,
            5 => Self::SyncVault,
            6 => Self::SyncOrgKeys,
            7 => Self::SyncFolderCreate,
            8 => Self::SyncFolderUpdate,
            10 => Self::SyncSettings,
            11 => Self::LogOut,
            12 => Self::SyncSendCreate,
            13 => Self::SyncSendUpdate,
            14 => Self::SyncSendDelete,
            15 => Self::AuthRequest,
            16 => Self::AuthRequestResponse,
            other => Self::Other(other),
        }
    }

    pub fn as_i32(self) -> i32 {
        match self {
            Self::SyncCipherUpdate => 0,
            Self::SyncCipherCreate => 1,
            Self::SyncLoginDelete => 2,
            Self::SyncFolderDelete => 3,
            Self::SyncCiphers => 4,
            Self::SyncVault => 5,
            Self::SyncOrgKeys => 6,
            Self::SyncFolderCreate => 7,
            Self::SyncFolderUpdate => 8,
            Self::SyncSettings => 10,
            Self::LogOut => 11,
            Self::SyncSendCreate => 12,
            Self::SyncSendUpdate => 13,
            Self::SyncSendDelete => 14,
            Self::AuthRequest => 15,
            Self::AuthRequestResponse => 16,
            Self::Other(n) => n,
        }
    }

    /// 事件承載的是 cipher（§1.1 的 targeted pull 依據）。
    pub fn is_cipher(self) -> bool {
        matches!(
            self,
            Self::SyncCipherUpdate | Self::SyncCipherCreate | Self::SyncLoginDelete
        )
    }
}

/// 一條已正規化的伺服器事件。`raw` 保留原樣載荷給上層查未建模欄位。
#[derive(Clone, Debug, PartialEq)]
pub struct ServerEvent {
    pub update: UpdateType,
    pub payload: Value,
    /// hub target 名稱（官方是 `ReceiveMessage`；auth-request 匿名 hub 有拼字錯誤的变體）。
    pub target: Option<String>,
    /// 發出動作的裝置 id；與本裝置相同代表是自己寫的，不用拉。
    pub context_id: Option<String>,
    pub raw: Value,
}

impl ServerEvent {
    /// payload 的 `Id`：cipher 類事件時是 ItemId（§1.1 targeted pull）。
    pub fn cipher_id(&self) -> Option<ItemId> {
        if !self.update.is_cipher() {
            return None;
        }
        self.id_field()
    }

    fn id_field(&self) -> Option<ItemId> {
        get(&self.payload, &["Id", "id", "CipherId", "cipherId"])
            .and_then(Value::as_str)
            .and_then(|s| ItemId::parse_str(s).ok())
    }

    /// 跨裝置提示用的 revisionDate（CAS 基準）；msgpack timestamp 已轉 RFC3339。
    pub fn revision_date(&self) -> Option<&str> {
        get(
            &self.payload,
            &["RevisionDate", "revisionDate", "Date", "date"],
        )
        .and_then(Value::as_str)
    }

    /// 自己裝置觸發的更新（context_id 等於本裝置 deviceIdentifier）。
    pub fn is_own_change(&self, device_identifier: &str) -> bool {
        self.context_id.as_deref() == Some(device_identifier)
    }
}

/// 由探測結果決定握手形態：Vaultwarden 只認 messagepack 握手，官方雲用 json。
pub fn mode_for(probe: &crate::profile::ServerProbe) -> NotificationMode {
    if probe.is_vaultwarden() {
        NotificationMode::VaultwardenWs
    } else {
        NotificationMode::SignalRJson
    }
}

/// 已開啟的 notifications 連線。
pub struct Notifications {
    ws: tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub mode: NotificationMode,
    closed: bool,
}

impl Notifications {
    /// 下一條事件；連線結束或中斷時回 `None`（一次呼叫可能吞掉多條 ping/控制 frame）。
    pub async fn next(&mut self) -> Option<ServerEvent> {
        loop {
            if self.closed {
                return None;
            }
            let msg = match self.ws.next().await {
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    tracing::debug!(error = %e, "notifications stream ended");
                    self.closed = true;
                    return None;
                }
                None => {
                    self.closed = true;
                    return None;
                }
            };
            match msg {
                Message::Text(text) => {
                    if let Some(ev) = decode_json_records(text.as_str()) {
                        return Some(ev);
                    }
                }
                Message::Binary(bytes) => {
                    if let Some(ev) = decode_binary_record(&bytes) {
                        return Some(ev);
                    }
                }
                Message::Close(_) => {
                    self.closed = true;
                    return None;
                }
                // Ping/Pong 由 tungstenite 自動應答；Frame 忽略。
                _ => {}
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), ServerError> {
        if !self.closed {
            let _ = self.ws.send(Message::Close(None)).await;
            self.closed = true;
        }
        Ok(())
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        // 非同步關閉交給 close()；drop 時至少別讓 server 端掛著幽靈訂閱。
        self.closed = true;
    }
}

impl Client {
    /// 依 ServerProfile 選協議形態開啟 notifications 連線。
    ///
    /// 探測失敗（沒打過 `/config`）時預設 `SignalRJson`，並在收不到握手回應時自動
    /// 改用 Vaultwarden 態重連一次：這樣對未知 server 也能工作。
    pub async fn notifications(&self) -> Result<Notifications, ServerError> {
        let profile = self.cached_probe().await;
        let mode = mode_for(&profile);
        match self.notifications_in(mode).await {
            Ok(n) => Ok(n),
            Err(first) if mode == NotificationMode::SignalRJson => {
                tracing::debug!(error = %first, "signalr json handshake failed, retrying as vaultwarden ws");
                self.notifications_in(NotificationMode::VaultwardenWs).await
            }
            Err(e) => Err(e),
        }
    }

    /// 指定協議形態連線。`user_id` 為 None 時從 access token 的 `sub` claim 推得
    /// （官方 hub 用 `Connect` 加入使用者群組）。
    pub async fn notifications_in(
        &self,
        mode: NotificationMode,
    ) -> Result<Notifications, ServerError> {
        self.notifications_as(mode, None).await
    }

    pub async fn notifications_as(
        &self,
        mode: NotificationMode,
        user_id: Option<&str>,
    ) -> Result<Notifications, ServerError> {
        if !self.signed_in().await {
            return Err(ServerError::Unauthenticated);
        }
        let probe = self.cached_probe().await;
        if !probe.has(feature::NOTIFICATIONS_WEBSOCKET) && probe.config.is_some() {
            // config 裡沒有 notifications 位址：仍嘗試 base/notifications，但先記下來
            tracing::debug!("notifications url missing from /config, guessing from base url");
        }
        let token = self
            .access_token()
            .await
            .ok_or(ServerError::Unauthenticated)?;
        let uid = user_id
            .map(str::to_owned)
            .or_else(|| crate::jwt_claim_str(&token, "sub"));

        // WS 端點從 http(s) base 推來，scheme 要換掉（tungstenite 只認 ws/wss）
        let mut url = match self.notifications_base(&probe).await {
            b if b.starts_with("https://") => format!("wss://{}", &b["https://".len()..]),
            b if b.starts_with("http://") => format!("ws://{}", &b["http://".len()..]),
            b => b,
        };
        url.push_str("/hub?access_token=");
        url.push_str(&urlencoded(&token));

        let mut request = url.as_str().into_client_request()?;
        if mode == NotificationMode::VaultwardenWs {
            // Vaultwarden 的 route 只认 access_token 查詢參數或 Authorization header 兩者之一，
            // 帶 header 讓只有 header 的路径也能走通。
            request.headers_mut().insert(
                "Authorization",
                http_header_value(&format!("Bearer {token}")),
            );
            // 不請求 Sec-WebSocket-Protocol：VW 不會回呼任何 subprotocol，
            // 而 tungstenite 對「要求了卻沒被回應」直接判定握手失敗
            //（實測：`SubProtocol error: Server sent no subprotocol`）。
            // 協議由握手訊息的 protocol 欄位決定，subprotocol 頭本來就是多餘的。
        }

        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;
        handshake(&mut ws, mode).await?;
        if mode == NotificationMode::SignalRJson {
            // 官方 hub 的 Connect(userId, version?)：少了這一步只會收到全域事件。
            // 沒有回應也要能繼續跑，所以不等待 ack（void Task 的 invocation 本來就不回話）。
            let invoke = json!({
                "type": 1,
                "invocationId": "1",
                "target": "Connect",
                "arguments": [uid.clone().unwrap_or_default()],
            });
            ws.send(Message::Text(record(invoke.to_string()))).await?;
        }
        Ok(Notifications {
            ws,
            mode,
            closed: false,
        })
    }
}

fn http_header_value(v: &str) -> http::HeaderValue {
    http::HeaderValue::from_str(v).unwrap_or_else(|_| http::HeaderValue::from_static(""))
}

fn record(payload: String) -> String {
    let mut out = payload;
    out.push(char::from(RECORD_SEPARATOR));
    out
}

/// 送出對應協議的握手並等待 `{}\u001e`。Vaultwarden 對不認識的握手不回話，
/// 所以這裡的逾時是「警告」不是錯誤。
async fn handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>,
    mode: NotificationMode,
) -> Result<(), ServerError> {
    let hello = match mode {
        NotificationMode::SignalRJson => r#"{"protocol":"json","version":1}"#,
        NotificationMode::VaultwardenWs => r#"{"protocol":"messagepack","version":1}"#,
    };
    ws.send(Message::Text(record(hello.to_owned()))).await?;
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                return Err(ServerError::Transport(match mode {
                    NotificationMode::SignalRJson => "signalr handshake timed out".to_owned(),
                    NotificationMode::VaultwardenWs => "vaultwarden handshake timed out".to_owned(),
                }));
            }
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    if is_handshake_response(t.as_str()) { return Ok(()); }
                }
                Some(Ok(Message::Binary(b))) => {
                    if is_handshake_response_bytes(&b) { return Ok(()); }
                    // 先來的是 notification/ping：握手回應缺但連線可用（舊 VW 行為）
                    return Ok(());
                }
                Some(Ok(Message::Ping(p))) => {
                    ws.send(Message::Pong(p)).await?;
                }
                Some(Ok(Message::Close(_))) | None => return Err(ServerError::Transport("handshake closed".to_owned())),
                Some(Err(e)) => return Err(ServerError::Transport(e.to_string())),
                Some(Ok(_)) => {}
            }
        }
    }
}

fn is_handshake_response(text: &str) -> bool {
    let trimmed = text.trim_matches(char::from(RECORD_SEPARATOR)).trim();
    trimmed == "{}" || trimmed.is_empty()
}

/// Vaultwarden 回的握手回應是裸 `{}\u001e`（`INITIAL_RESPONSE`，無長度前綴）；
/// 其他實作可能套上 SignalR 長度前綴，兩種都認。
fn is_handshake_response_bytes(bytes: &[u8]) -> bool {
    bytes == b"{}\x1e"
        || bytes == b"{}"
        || strip_length_prefix(bytes) == b"{}\x1e"
        || strip_length_prefix(bytes) == b"{}"
}

/// SignalR BinaryMessageFormat：7-bit 一段、最高位是續位元組的 varint 長度前綴。
/// 來源：https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Shared/src/BinaryMessageFormat.cs
/// （Vaultwarden 的 `serialize()` 註解即指向該檔）
pub(crate) fn strip_length_prefix(bytes: &[u8]) -> &[u8] {
    for (idx, byte) in bytes.iter().enumerate().take(9) {
        if byte & 0x80 == 0 {
            return &bytes[idx + 1..];
        }
    }
    bytes
}

/// 文字 frame：可能含多條以 `0x1e` 分隔的 JSON 訊息，取第一條可解讀的事件。
pub fn decode_json_records(text: &str) -> Option<ServerEvent> {
    for part in text.split(char::from(RECORD_SEPARATOR)) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(ev) = interpret(&value) {
            return Some(ev);
        }
    }
    None
}

/// 二元 frame：先剝長度前綴，再試 msgpack，不行再試 JSON（兩態宽容）。
pub fn decode_binary_record(bytes: &[u8]) -> Option<ServerEvent> {
    // 有無長度前綴都試：VW 的 `serialize()` 一定加，其他實作可能直接送裸 msgpack。
    for candidate in [bytes, strip_length_prefix(bytes)] {
        let parsed = parse_candidate(candidate);
        if parsed.is_some() {
            return parsed;
        }
    }
    None
}

/// 單一 buffer 先當 msgpack 試，再當 JSON 試。
fn parse_candidate(bytes: &[u8]) -> Option<ServerEvent> {
    if let Ok(value) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.to_vec())) {
        let from_msgpack = interpret(&json_from_msgpack(value));
        if from_msgpack.is_some() {
            return from_msgpack;
        }
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(decode_json_records)
}

/// 把 SignalR 訊息（json 形態的 `{type,target,arguments}` 或 msgpack 形態的
/// `[1, headers, invocationId, target, arguments]`）與裸通知物件都轉成事件。
pub fn interpret(value: &Value) -> Option<ServerEvent> {
    // msgpack invocation 陣列：[1, headers, invocationId, target, arguments]
    if let Value::Array(items) = value {
        let first = items.first().and_then(Value::as_i64);
        if first == Some(1) && items.len() >= 5 {
            let target = items[3].as_str().map(str::to_owned);
            return from_arguments(target, &items[4]);
        }
        return None; // [6] 是 keepalive ping，握手回應是物件
    }
    // 通知本體優先判別：VW 在 arguments 裡放 `{ContextId,Type,Payload}`，
    // 官方雲放 `{NotificationType,Payload}`，兩者都不帶 SignalR 的 `type` 外殼。
    if let Some(ev) = notification_from(value) {
        return Some(ev);
    }
    // SignalR json 外殼：type 1 = invocation，6 = keepalive，其他是控制 frame
    let ty = value.as_object()?.get("type").and_then(Value::as_i64)?;
    if ty != 1 {
        return None;
    }
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .map(str::to_owned);
    from_arguments(
        target.clone(),
        get(value, &["arguments"]).unwrap_or(&Value::Null),
    )
}

fn from_arguments(target: Option<String>, args: &Value) -> Option<ServerEvent> {
    let items: Vec<&Value> = match args {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    for arg in items {
        // 官方雲把通知再包一層 JSON 字串
        let candidate = match arg {
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(v) => v,
                Err(_) => continue,
            },
            v => v.clone(),
        };
        if let Some(mut ev) = notification_from(&candidate) {
            ev.target = target.clone();
            return Some(ev);
        }
    }
    None
}

/// 通知本體：`{Type|NotificationType, Payload}`，欄位大小寫兩態都吃。
fn notification_from(value: &Value) -> Option<ServerEvent> {
    let payload = get(value, &["Payload", "payload"])?;
    let raw_type = get(value, &["NotificationType", "notificationType", "Type"])?;
    let number = match raw_type {
        Value::Number(n) => n.as_i64().map(|i| i as i32),
        Value::String(s) => s.parse::<i32>().ok(),
        _ => None,
    }?;
    let context_id = get(value, &["ContextId", "contextId"])
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(ServerEvent {
        update: UpdateType::from_i32(number),
        payload: payload.clone(),
        target: None,
        context_id,
        raw: value.clone(),
    })
}

/// rmpv → serde_json。ext -1（msgpack timestamp，SignalR 用它送 DateTime）
/// 轉成 RFC3339，讓上層能直接跟 `revisionDate` 比。
pub fn json_from_msgpack(value: rmpv::Value) -> Value {
    use rmpv::Value as M;
    match value {
        M::Nil => Value::Null,
        M::Boolean(b) => Value::Bool(b),
        M::Integer(i) => i
            .as_i64()
            .map(|n| json!(n))
            .or_else(|| i.as_u64().map(|n| json!(n)))
            .unwrap_or(Value::Null),
        M::F32(f) => Value::from(f64::from(f)),
        M::F64(f) => Value::from(f),
        M::String(s) => Value::String(s.as_str().unwrap_or_default().to_owned()),
        M::Binary(b) => Value::String(base64::engine::general_purpose::STANDARD.encode(b)),
        M::Array(items) => Value::Array(items.into_iter().map(json_from_msgpack).collect()),
        M::Map(pairs) => {
            let mut map = Map::new();
            for (k, v) in pairs {
                let key = match k {
                    rmpv::Value::String(s) => s.as_str().unwrap_or_default().to_owned(),
                    other => json_from_msgpack(other).to_string(),
                };
                map.insert(key, json_from_msgpack(v));
            }
            Value::Object(map)
        }
        M::Ext(-1, bytes) if bytes.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes);
            let packed = u64::from_be_bytes(raw);
            let seconds = (packed & 0x3_FFFF_FFFF) as i64;
            let nanos = (packed >> 34) as u32;
            Value::String(format_rfc3339(seconds, nanos))
        }
        M::Ext(ty, bytes) => {
            json!({ "$ext": { "type": ty, "data": base64::engine::general_purpose::STANDARD.encode(bytes) } })
        }
    }
}

/// epoch seconds → `YYYY-MM-DDTHH:MM:SSZ`（Howard Hinnant civil_from_days，免引入 chrono）。
pub(crate) fn format_rfc3339(seconds: i64, _nanos: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let sec_of_day = seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sec_of_day / 3600,
        (sec_of_day % 3600) / 60,
        sec_of_day % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Vaultwarden 的 route 是 `/notifications/hub`；官方雲的 `/hub` 在 notifications 網域下。
/// 兩者只差 base，這裡只負責給 base。
impl Client {
    pub(crate) async fn notifications_base(&self, probe: &crate::profile::ServerProbe) -> String {
        if let Some(n) = &probe.urls.notifications {
            return n.trim_end_matches('/').to_owned();
        }
        self.url("notifications").await
    }
}
