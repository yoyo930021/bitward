//! notifications hub 位元組 → 事件（契约 §1.1 targeted pull 的入口）。
//!
//! 同一條 `/notifications/hub` WebSocket 上有兩種協議形態（來源全部見
//! `NOTES.md`）：
//!
//! - 官方雲：ASP.NET Core SignalR **json hub protocol**。文字 frame 內每條 JSON
//!   訊息以 `0x1e`（RECORD_SEPARATOR）分隔；通知是 invocation 訊息
//!   （`type:1`，`target:"ReceiveMessage"`），`arguments` 裡可能再包一層 JSON
//!   字串（官方雲的雙層包裹形態）。
//! - Vaultwarden：同一條 route 只認 **messagepack** 握手，派送 SignalR binary
//!   message format（varint 長度前綴 + msgpack 內文）的 invocation 陣列
//!   `[1, headers, invocationId, target, arguments]`，通知本體是
//!   `{ContextId, Type, Payload}`。
//!
//! 本解析器對「形態與 frame 類型不符」寬容：任何 frame 先試 msgpack（含剝長度
//!   前綴的變體）、再試 `0x1e` 分包 JSON——server 升級或混搭時事件流不會整條失效
//!   （行為對齊 `crates/bw-server/src/notify.rs` 的實錄結論，但自持、不依賴它）。

use bw_proto::ItemId;
use serde_json::Value;

/// SignalR 記錄分隔符。來源：Vaultwarden 1.37.2 `src/api/notifications.rs#L334`
/// （`RECORD_SEPARATOR`），並見 aspnetcore `MessageFrameTypes.cs`。
const RECORD_SEPARATOR: u8 = 0x1e;

/// cipher 級事件的 `UpdateType` 編號：SyncCipherUpdate=0、SyncCipherCreate=1、
/// SyncLoginDelete=2。來源：
/// https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L678-L700
/// （註解指向 https://github.com/bitwarden/server/blob/375af7c/src/Core/Enums/PushType.cs ）
const CIPHER_UPDATES: [i32; 3] = [0, 1, 2];

/// 解析後的通知事件。
#[derive(Clone, Debug, PartialEq)]
pub enum NotifyEvent {
    /// 單一 cipher 變更（`Id` 為 ItemId）。契约 §1.1：收到就 targeted
    /// `GET /ciphers/{id}`，不用全量 sync。
    CipherChanged(ItemId),
    /// 其他事件（SyncVault、SyncCiphers、LogOut、AuthRequest…）。值是通知本體
    /// （`{Type|NotificationType, Payload, …}` 的原始 JSON），daemon 自己分派。
    Other(Value),
}

/// 一個 WS frame（文字或二元）進、事件出；不是事件的 frame（握手回應 `{}\u001e`、
/// keepalive ping、ack）回空向量。無內部狀態：WS frame 邊界由傳輸層保證，
/// 不需要跨 frame 緩衝。
#[derive(Clone, Copy, Debug, Default)]
pub struct NotifyParser;

impl NotifyParser {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 解析一個完整的 WS 訊息（frame 載荷位元組）。
    #[must_use]
    pub fn feed(&self, frame: &[u8]) -> Vec<NotifyEvent> {
        // Binary shapes first: VW's serialize() always wraps with the SignalR
        // length prefix, but bare msgpack is tried too. Either shape may win.
        for candidate in [frame, strip_length_prefix(frame)] {
            if let Some(ev) = parse_msgpack(candidate) {
                return vec![ev];
            }
        }
        // Text shape: one frame may carry several `0x1e`-separated JSON records.
        let Ok(text) = std::str::from_utf8(frame) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for part in text.split(char::from(RECORD_SEPARATOR)) {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(trimmed)
                && let Some(ev) = interpret(&value)
            {
                out.push(ev);
            }
        }
        out
    }
}

/// 單一 buffer 當 msgpack 試：解出值 → 轉 JSON → 判讀。
fn parse_msgpack(bytes: &[u8]) -> Option<NotifyEvent> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.to_vec())).ok()?;
    interpret(&json_from_msgpack(value))
}

/// SignalR BinaryMessageFormat：長度是 7-bit 一組、最高位為續位元組的 varint。
/// 來源：https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Shared/src/BinaryMessageFormat.cs
/// （Vaultwarden 的 `serialize()` 註解即指向該檔；實錄前綴 `0xca 0x01` = 202，
/// 見 fixtures/README.md）
fn strip_length_prefix(bytes: &[u8]) -> &[u8] {
    for (idx, byte) in bytes.iter().enumerate().take(9) {
        if byte & 0x80 == 0 {
            return &bytes[idx + 1..];
        }
    }
    bytes
}

/// 把 SignalR 訊息（json 形態的 `{type,target,arguments}`、msgpack 形態的
/// `[1, headers, invocationId, target, arguments]`）與裸通知物件都判讀成事件。
fn interpret(value: &Value) -> Option<NotifyEvent> {
    // msgpack invocation array: [1, headers, invId, target, arguments].
    if let Value::Array(items) = value {
        if items.first().and_then(Value::as_i64) == Some(1) && items.len() >= 5 {
            return from_arguments(&items[4]);
        }
        // [6] is a keepalive ping; the handshake response is an object, not an array.
        return None;
    }
    // Notification body first: VW nests `{ContextId,Type,Payload}` inside
    // arguments, official cloud uses `{NotificationType,Payload}`; neither
    // carries the SignalR `type` envelope.
    if let Some(ev) = notification_from(value) {
        return Some(ev);
    }
    // SignalR json envelope: type 1 = invocation, 6 = keepalive, others are control frames.
    let ty = value.as_object()?.get("type").and_then(Value::as_i64)?;
    if ty != 1 {
        return None;
    }
    from_arguments(value.get("arguments").unwrap_or(&Value::Null))
}

fn from_arguments(args: &Value) -> Option<NotifyEvent> {
    let items: Vec<&Value> = match args {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    for arg in items {
        // Official cloud double-wraps the notification as a JSON string
        // (recorded shape; see NOTES.md).
        let candidate = match arg {
            Value::String(s) => serde_json::from_str::<Value>(s).ok()?,
            v => v.clone(),
        };
        if let Some(ev) = notification_from(&candidate) {
            return Some(ev);
        }
    }
    None
}

/// 通知本體：`{Type|NotificationType, Payload}`，欄位大小寫兩態都吃。
fn notification_from(value: &Value) -> Option<NotifyEvent> {
    let obj = value.as_object()?;
    let payload = get_any(obj, &["Payload", "payload"])?;
    let raw_type = get_any(obj, &["NotificationType", "notificationType", "Type"])?;
    let number = match raw_type {
        Value::Number(n) => n.as_i64().map(|i| i as i32),
        Value::String(s) => s.parse::<i32>().ok(),
        _ => None,
    }?;
    if CIPHER_UPDATES.contains(&number) {
        let id_str = get_any(payload.as_object()?, &["Id", "id"])?.as_str()?;
        // bw_proto does not re-export uuid; go through Uuid's serde impl (parse_str semantics).
        if let Ok(id) = serde_json::from_value::<ItemId>(Value::String(id_str.to_owned())) {
            return Some(NotifyEvent::CipherChanged(id));
        }
    }
    Some(NotifyEvent::Other(value.clone()))
}

fn get_any<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| obj.get(*k))
}

/// rmpv → serde_json。ext -1（msgpack timestamp，SignalR 用它送 DateTime）
/// 轉成 RFC3339，讓上層能直接跟 `revisionDate` 比。
/// 來源：https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
/// 與 https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L310-L322
/// （8 bytes big-endian = `(nanos << 34) | seconds`）。
fn json_from_msgpack(value: rmpv::Value) -> Value {
    use base64::Engine as _;
    use rmpv::Value as M;
    match value {
        M::Nil => Value::Null,
        M::Boolean(b) => Value::Bool(b),
        M::Integer(i) => i
            .as_i64()
            .map(Value::from)
            .or_else(|| i.as_u64().map(Value::from))
            .unwrap_or(Value::Null),
        M::F32(f) => Value::from(f64::from(f)),
        M::F64(f) => Value::from(f),
        M::String(s) => Value::String(s.as_str().unwrap_or_default().to_owned()),
        M::Binary(b) => Value::String(base64::engine::general_purpose::STANDARD.encode(b)),
        M::Array(items) => Value::Array(items.into_iter().map(json_from_msgpack).collect()),
        M::Map(pairs) => {
            let mut map = serde_json::Map::new();
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
            let seconds = i64::try_from(packed & 0x3_FFFF_FFFF).unwrap_or(i64::MAX);
            let nanos = (packed >> 34) as u32;
            Value::String(format_rfc3339(seconds, nanos))
        }
        M::Ext(ty, bytes) => {
            let mut map = serde_json::Map::new();
            let mut data = serde_json::Map::new();
            data.insert("type".to_owned(), Value::from(i64::from(ty)));
            data.insert(
                "data".to_owned(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
            map.insert("$ext".to_owned(), Value::Object(data));
            Value::Object(map)
        }
    }
}

/// epoch seconds → `YYYY-MM-DDTHH:MM:SSZ`（Howard Hinnant civil_from_days，
/// 免引入 chrono；演算法來源 http://howardhinnant.github.io/date_algorithms.html ）
fn format_rfc3339(seconds: i64, nanos: u32) -> String {
    let _ = nanos; // second precision; matches the recorded VW behaviour
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

#[cfg(test)]
mod tests;
