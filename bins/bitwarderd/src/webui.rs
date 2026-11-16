//! Send 接收頁（PR2）：loopback 靜態頁＋無 bearer 代理端點。
//!
//! 為什麼要代理（實測表態 2026-11-16，記錄於 bw-server `sends.rs` 模組頭）：
//! VW 1.37.2 對任意 Origin 不給 `Access-Control-Allow-Origin`，瀏覽器頁直打
//! server 的存取端點必被 CORS 擋——故頁打本模組，本模組轉發**密文**，
//! 解密全在頁內 WebCrypto（seed 留 URL 片段，瀏覽器不上送、不進本進程）。
//!
//! 攻擊面紀律（plan 附錄 C）：
//! - 僅 127.0.0.1、port 由 OS 隨機指派（Lane 8：外部介面拒連）。
//! - 代理 base 取**帳號 server 值**，不吃頁端傳來的 URL——SSRF 無入口。
//! - per-page nonce：`GET /` 每次發新 nonce 內嵌進頁；POST 缺有效 nonce 拒
//!   （自訂標頭觸發 preflight，本服務不表態 CORS，外人頁連讀回應都做不到）。
//! - 請求體上限 4 KiB（只該裝一個密碼哈希）；單連線單請求即關。
//! - 存取日誌只記 method/path/status：path 含 accessId（非密鑰材料），
//!   body（含密碼哈希）與片段 seed 永不進日誌（Lane 6 斷言軸）。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use bw_server::{Client, SendAccessOutcome};

use crate::hub::Hub;

/// 接收頁（inline WebCrypto，零外部資源；`__BW_NONCE__` 佔位每次發放時替換）。
const PAGE_HTML: &str = include_str!("../assets/send-receive.html");

/// nonce 使用期（拿到頁後 6 小時內完成收件；逾時重開頁即換發）。
const NONCE_TTL: Duration = Duration::from_secs(6 * 3600);
/// nonce 表上限（防有人刷 `GET /` 撐爆記憶體；超限先清過期再逐出最舊）。
const NONCE_CAP: usize = 256;
/// 請求體上限：一個 JSON 帶密碼哈希（44 bytes）用不了更多。
const MAX_BODY_BYTES: usize = 4096;
/// 單請求讀寫總閘（含代理往復）。
const REQ_TIMEOUT: Duration = Duration::from_secs(60);

/// 綁 127.0.0.1 隨機 port，記入 hub（webUrl 組裝讀同欄位）並交回 listener。
pub async fn bind(hub: Arc<Hub>) -> Result<(u16, TcpListener), String> {
    let tcp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("webui bind: {e}"))?;
    let port = tcp
        .local_addr()
        .map_err(|e| format!("webui addr: {e}"))?
        .port();
    hub.webui_port.store(port, Ordering::Relaxed);
    Ok((port, tcp))
}

/// 接受迴圈（常駐 task）。
pub async fn serve(hub: Arc<Hub>, tcp: TcpListener) {
    let nonces: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let Ok((stream, peer)) = tcp.accept().await else {
            continue;
        };
        let hub = hub.clone();
        let nonces = nonces.clone();
        tokio::spawn(async move {
            let done = tokio::time::timeout(REQ_TIMEOUT, async {
                if !peer.ip().is_loopback() {
                    let _ = respond(stream, 403, "application/json", b"{}".to_vec()).await;
                    return;
                }
                handle(stream, &hub, &nonces).await;
            })
            .await;
            if done.is_err() {
                tracing::debug!("webui conn timeout");
            }
        });
    }
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    hub: &Hub,
    nonces: &Mutex<HashMap<String, Instant>>,
) {
    let Some(req) = read_request(&mut stream).await else {
        return;
    };
    let (status, ctype, body) = route(hub, nonces, &req).await;
    tracing::info!(
        method = %req.method,
        path = %req.path,
        status,
        "webui"
    );
    let _ = respond(stream, status, &ctype, body).await;
}

struct Req {
    method: String,
    path: String,
    nonce: String,
    body: Vec<u8>,
    /// 宣告的 body 長度（超 cap 時不收 body 只記數，供 413 判定）。
    declared_len: usize,
}

/// 讀 HTTP/1.1 請求頭＋宣告的 body（cap 4 KiB）。形態不正回 None（連關）。
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 32 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut rl = lines.next()?.split_whitespace();
    let method = rl.next()?.to_owned();
    let path = rl.next()?.to_owned();
    let mut clen = 0usize;
    let mut nonce = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => clen = v.parse().unwrap_or(usize::MAX),
            "x-bw-nonce" => nonce = v.to_owned(),
            _ => {}
        }
    }
    if clen > MAX_BODY_BYTES {
        return Some(Req {
            method,
            path,
            nonce,
            body: Vec::new(),
            declared_len: clen,
        });
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < clen {
        let want = (clen - body.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..want]).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Req {
        method,
        path,
        nonce,
        body,
        declared_len: clen,
    })
}

async fn route(
    hub: &Hub,
    nonces: &Mutex<HashMap<String, Instant>>,
    req: &Req,
) -> (u16, String, Vec<u8>) {
    if req.method == "GET" && (req.path == "/" || req.path == "/index.html") {
        let nonce = issue_nonce(nonces).await;
        let html = PAGE_HTML.replace("__BW_NONCE__", &nonce);
        return (200, "text/html; charset=utf-8".into(), html.into_bytes());
    }
    if req.method != "POST" {
        return json_resp(405, json!({"error":"method-not-allowed"}));
    }
    if !check_nonce(nonces, &req.nonce).await {
        return json_resp(403, json!({"error":"bad-nonce"}));
    }
    if req.declared_len > MAX_BODY_BYTES {
        return json_resp(413, json!({"error":"body-too-large"}));
    }
    let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
        return json_resp(400, json!({"error":"bad-json"}));
    };
    let password = body.get("password").and_then(Value::as_str);
    if let Some(aid) = req.path.strip_prefix("/access/") {
        if !valid_id(aid) {
            return json_resp(400, json!({"error":"bad-access-id"}));
        }
        let (status, v) = hub.webui_access(aid, password).await;
        return json_resp(status, v);
    }
    if let Some(rest) = req.path.strip_prefix("/file/") {
        let Some((sid, fid)) = rest.split_once('/') else {
            return json_resp(400, json!({"error":"bad-path"}));
        };
        if !valid_uuid(sid) || !valid_id(fid) {
            return json_resp(400, json!({"error":"bad-path"}));
        }
        return hub.webui_file(sid, fid, password).await;
    }
    json_resp(404, json!({"error":"not-found"}))
}

async fn issue_nonce(nonces: &Mutex<HashMap<String, Instant>>) -> String {
    let mut n = nonces.lock().await;
    let now = Instant::now();
    n.retain(|_, t| now.duration_since(*t) < NONCE_TTL);
    if n.len() >= NONCE_CAP {
        let oldest = n.iter().min_by_key(|(_, t)| *t).map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            n.remove(&k);
        }
    }
    let nonce = bw_crypto::b64url(&rand::random::<[u8; 16]>());
    n.insert(nonce.clone(), now);
    nonce
}

async fn check_nonce(nonces: &Mutex<HashMap<String, Instant>>, nonce: &str) -> bool {
    let n = nonces.lock().await;
    let now = Instant::now();
    matches!(n.get(nonce), Some(t) if now.duration_since(*t) < NONCE_TTL)
}

/// accessId／fileId 字元集：b64url 與 hex 段（不給路徑注入留縫）。
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// send id 段：UUID 形態。
fn valid_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn json_resp(status: u16, v: Value) -> (u16, String, Vec<u8>) {
    (
        status,
        "application/json; charset=utf-8".into(),
        v.to_string().into_bytes(),
    )
}

async fn respond(
    mut stream: tokio::net::TcpStream,
    status: u16,
    ctype: &str,
    body: Vec<u8>,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

impl Hub {
    /// 代理存取：base 取帳號 server 值（頁端無從指定）；四態換成本頁文案鍵。
    pub(crate) async fn webui_access(&self, aid: &str, password: Option<&str>) -> (u16, Value) {
        let Some(base) = self.server_base().await else {
            return (503, json!({"error":"no-server"}));
        };
        let Ok(client) = Client::new(&base) else {
            return (503, json!({"error":"no-server"}));
        };
        match client.send_access(aid, password).await {
            Ok(SendAccessOutcome::Send(v)) => (200, v),
            Ok(SendAccessOutcome::PasswordRequired) => (401, json!({"error":"password-required"})),
            Ok(SendAccessOutcome::PasswordInvalid) => (400, json!({"error":"password-invalid"})),
            Ok(SendAccessOutcome::Inaccessible) => (404, json!({"error":"inaccessible"})),
            Err(e) => (502, json!({"error":"transport", "detail": e.to_string()})),
        }
    }

    /// 代理取檔：回密文檔身位元組（解密屬頁內 WebCrypto；本層不碰明文）。
    pub(crate) async fn webui_file(
        &self,
        sid: &str,
        fid: &str,
        password: Option<&str>,
    ) -> (u16, String, Vec<u8>) {
        let Some(base) = self.server_base().await else {
            return json_resp(503, json!({"error":"no-server"}));
        };
        let Ok(client) = Client::new(&base) else {
            return json_resp(503, json!({"error":"no-server"}));
        };
        let Ok(id) = bw_proto::ItemId::parse_str(sid) else {
            return json_resp(400, json!({"error":"bad-send-id"}));
        };
        match client.send_file_download(id, fid, password).await {
            Ok(bytes) => (200, "application/octet-stream".into(), bytes),
            Err(bw_server::ServerError::Http { status: 404, .. }) => {
                json_resp(404, json!({"error":"inaccessible"}))
            }
            Err(bw_server::ServerError::Http { status: 400, .. }) => {
                json_resp(400, json!({"error":"password-invalid"}))
            }
            Err(e) => json_resp(502, json!({"error":"transport", "detail": e.to_string()})),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::tests::unlocked_hub;
    use bw_proto::{Response, SendOp};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn one_shot(port: u16, request: &str) -> (u16, String, String) {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        let split = text.find("\r\n\r\n").unwrap();
        (
            status,
            text[..split].to_owned(),
            text[split + 2..].to_owned(),
        )
    }

    async fn live_webui(tag: &str) -> (Arc<Hub>, u16, String) {
        let (hub, _dir) = unlocked_hub(tag).await;
        let (port, tcp) = bind(hub.clone()).await.unwrap();
        tokio::spawn(serve(hub.clone(), tcp));
        let (status, _, html) = one_shot(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert_eq!(status, 200);
        let nonce = html
            .split("nonce: \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        (hub, port, nonce)
    }

    #[tokio::test]
    async fn page_serves_with_fresh_nonce_and_hardening_headers() {
        let (_hub, port, nonce) = live_webui("webui-page").await;
        let (status, head, html) = one_shot(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert_eq!(status, 200);
        assert!(
            head.contains("Content-Security-Policy: default-src 'none'"),
            "{head}"
        );
        assert!(head.contains("Cache-Control: no-store"));
        assert!(!html.contains("__BW_NONCE__"), "佔位必須被換發替換");
        // 每次發放是新值（不是固定字串）
        let nonce2 = html
            .split("nonce: \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert!(
            !nonce2.is_empty() && nonce2 != nonce,
            "第二次發放的 nonce 應不同"
        );
    }

    #[tokio::test]
    async fn proxy_gates_by_nonce_and_maps_states() {
        let (_hub, port, nonce) = live_webui("webui-gate").await;
        // 缺 nonce／錯 nonce → 403（外人頁打不進）
        let (s, _, b) = one_shot(
            port,
            "POST /access/ACC1 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert_eq!(s, 403, "{b}");
        let req = |nonce: &str, path: &str, body: &str| {
            format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
                 x-bw-nonce: {nonce}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let (s, _, b) = one_shot(port, &req("nope-nope-nope", "/access/ACC1", "{}")).await;
        assert_eq!(s, 403, "{b}");
        // 有效 nonce＋fixture server（port 9 拒連）→ 502 transport（可懂錯誤非白屏）
        let (s, _, b) = one_shot(port, &req(&nonce, "/access/ACC1", "{}")).await;
        assert_eq!(s, 502, "{b}");
        assert!(b.contains("transport"), "{b}");
        // 路徑形態守門：非法字元拒、亂路徑 404、GET 打資料端點 405
        let (s, _, _) = one_shot(port, &req(&nonce, "/access/..%2F..%2Fx", "{}")).await;
        assert_eq!(s, 400);
        let (s, _, _) = one_shot(port, &req(&nonce, "/nope", "{}")).await;
        assert_eq!(s, 404);
        let (s, _, _) = one_shot(port, "GET /access/ACC1 HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert_eq!(s, 405);
    }

    #[tokio::test]
    async fn send_projection_carries_weburl_when_bound() {
        use uuid::Uuid;
        let (hub, port, _nonce) = live_webui("webui-send").await;
        let id = Uuid::new_v4();
        let uk = bw_crypto::UserKey::from_bytes(vec![7u8; 64]).unwrap();
        let seed = bw_crypto::SendKey::from_bytes((0..16u8).collect()).unwrap();
        let ck = seed.stretch();
        let name_env = bw_crypto::encrypt_bytes_key(ck.as_slice(), "帳單分享".as_bytes()).unwrap();
        hub.store
            .send_put(&json!({
                "id": id.to_string(), "type": 0, "name": name_env,
                "key": seed.wrap_with_user_key(&uk).unwrap(),
                "accessId": "ACC-IDA", "accessCount": 0,
                "deletionDate": "2026-11-17T00:00:00Z", "object": "send",
            }))
            .unwrap();
        let Response::Sends(v) = hub.send_op(&SendOp::List).await.unwrap() else {
            panic!("expect Sends");
        };
        assert_eq!(
            v.items[0].web_url.as_deref().unwrap(),
            format!("http://127.0.0.1:{port}/#/send/ACC-IDA/AAECAwQFBgcICQoLDA0ODw")
        );
        // 官方 URL 照在（兩態並存，接收端選路是使用者的事）
        assert_eq!(
            v.items[0].url.as_deref().unwrap(),
            "http://127.0.0.1:9/#/send/ACC-IDA/AAECAwQFBgcICQoLDA0ODw"
        );
        // Get 同欄
        let Response::SendUrl(g) = hub.send_op(&SendOp::Get { id }).await.unwrap() else {
            panic!("expect SendUrl");
        };
        assert!(g.web_url.unwrap().contains(&port.to_string()));
    }

    #[tokio::test]
    async fn body_cap_enforced() {
        let (_hub, port, nonce) = live_webui("webui-cap").await;
        let big = format!(
            "POST /access/ACC1 HTTP/1.1\r\nHost: x\r\nx-bw-nonce: {nonce}\r\n\
             Content-Length: 9000\r\n\r\n{}",
            "a".repeat(100)
        );
        let (s, _, _) = one_shot(port, &big).await;
        assert_eq!(s, 413);
    }
}
