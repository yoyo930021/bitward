//! 4c access token 自動續期的單元面：以本地 mock HTTP server 驗證
//! 401 收口 → 單飛 refresh → 重試一次 → 持久化鉤子 的完整閉環，
//! 外加純閘函數與失效路徑。VW 實錄形態（2026-11-09 probe）：
//! 過期 token → 401（HTML 體）；死 refresh grant → 400 invalid_grant。

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use bw_server::Client;

type Resp = (u16, String);

/// path 前綴 → 應答 FIFO（取盡後重複最後一則）；hits 記錄每筆請求行。
struct Mock {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn spawn(script: Vec<(&str, Vec<Resp>)>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut queues: Vec<(String, VecDeque<Resp>)> = script
            .into_iter()
            .map(|(p, q)| (p.to_owned(), q.into_iter().collect()))
            .collect();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits_c = hits.clone();
        std::thread::spawn(move || {
            let mut seen: HashMap<String, usize> = HashMap::new();
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else { continue };
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.is_empty() {
                    continue;
                }
                let mut it = line.split_whitespace();
                let method = it.next().unwrap_or("").to_owned();
                let path = it.next().unwrap_or("").to_owned();
                let mut len = 0usize;
                let mut auths: Vec<String> = Vec::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(rest) = lower.strip_prefix("content-length:") {
                        len = rest.trim().parse().unwrap_or(0);
                    }
                    if let Some(rest) = lower.strip_prefix("authorization:") {
                        auths.push(rest.trim().to_owned());
                    }
                }
                let mut body = vec![0u8; len];
                if len > 0 {
                    let _ = reader.read_exact(&mut body);
                }
                let rec = format!("{method} {path} auths=[{}]", auths.join(" & "));
                *seen.entry(rec.clone()).or_default() += 1;
                hits_c.lock().unwrap().push(rec.clone());
                let (status, resp_body) = queues
                    .iter_mut()
                    .find(|(p, _)| path.starts_with(p.as_str()))
                    .and_then(|(_, q)| {
                        if q.len() > 1 {
                            q.pop_front()
                        } else {
                            q.front().cloned()
                        }
                    })
                    .unwrap_or((500, "{\"message\":\"unmatched\"}".to_owned()));
                // 鑒權語意補強：號稱 200 的 /api/sync 應答只認**單一**
                // 新 bearer——抓「重試時舊 Authorization 未被置換」的回歸
                // （reqwest builder .header 是 append，實錄教訓）。
                // auths 取自 lowercased 行，比對值同為小寫。
                let (status, resp_body) = if path.starts_with("/api/sync")
                    && status == 200
                    && auths != ["bearer new.token".to_owned()]
                {
                    (401, "{\"message\":\"stale or duplicated bearer\"}".to_owned())
                } else {
                    (status, resp_body)
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.flush();
            }
        });
        Mock { port, hits }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn count(&self, needle: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains(needle))
            .count()
    }
}

const OK_SYNC: &str =
    "{\"profile\":{},\"ciphers\":[],\"folders\":[],\"collections\":[],\"organizations\":[]}";
const TOKEN_NEW: &str =
    "{\"access_token\":\"NEW.TOKEN\",\"refresh_token\":\"R2\",\"expires_in\":7200,\"token_type\":\"Bearer\"}";

#[tokio::test]
async fn forty_one_renews_once_and_retries() {
    let mock = Mock::spawn(vec![
        (
            "/api/sync",
            vec![(401, "{\"message\":\"expired\"}".into()), (200, OK_SYNC.into())],
        ),
        (
            "/identity/connect/token",
            vec![(200, TOKEN_NEW.into())],
        ),
    ]);
    let client = Client::new(&mock.base()).unwrap();
    client.set_access_token("OLD.TOKEN").await;
    client.set_refresh_token(Some("R1")).await;
    let seen = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let seen2 = seen.clone();
    client.set_token_sink(Arc::new(move |a, r| {
        seen2.lock().unwrap().push((a.to_owned(), r.map(str::to_owned)));
    }));

    let sync = client.sync().await;
    assert!(
        sync.is_ok(),
        "401 後應自動續期並重試成功，got {sync:?} hits={:?}",
        mock.hits.lock().unwrap()
    );
    assert_eq!(mock.count("connect/token"), 1, "只跑一次 refresh grant");
    assert_eq!(mock.count("GET /api/sync"), 2, "原請求重試恰好一次");
    assert_eq!(client.access_token().await.as_deref(), Some("NEW.TOKEN"));
    assert_eq!(client.refresh_token().await.as_deref(), Some("R2"));
    assert!(!client.needs_relogin());
    let s = seen.lock().unwrap();
    assert_eq!(s.len(), 1, "sink 收到續期結果");
    assert_eq!(s[0].0, "NEW.TOKEN");
    assert_eq!(s[0].1.as_deref(), Some("R2"));
}

#[tokio::test]
async fn refresh_rejection_marks_needs_relogin() {
    let mock = Mock::spawn(vec![
        ("/api/sync", vec![(401, "{\"message\":\"expired\"}".into())]),
        (
            "/identity/connect/token",
            vec![(400, "{\"error\":\"invalid_grant\"}".into())],
        ),
    ]);
    let client = Client::new(&mock.base()).unwrap();
    client.set_access_token("OLD").await;
    client.set_refresh_token(Some("DEAD")).await;
    let err = client.sync().await.expect_err("續期失敗時原 401 應上拋");
    let s = format!("{err:?}");
    assert!(s.contains("401"), "surface original 401: {s}");
    assert!(client.needs_relogin(), "refresh 也遭拒 → needs_relogin");
    assert_eq!(mock.count("connect/token"), 1, "不重試轟炸 token 端點");
    assert_eq!(mock.count("GET /api/sync"), 1, "續期失敗不重試原請求");
}

#[tokio::test]
async fn concurrent_forty_ones_share_single_refresh() {
    let mock = Mock::spawn(vec![
        (
            "/api/sync",
            vec![
                (401, "{\"message\":\"expired\"}".into()),
                (401, "{\"message\":\"expired\"}".into()),
                (401, "{\"message\":\"expired\"}".into()),
                (200, OK_SYNC.into()),
                (200, OK_SYNC.into()),
                (200, OK_SYNC.into()),
            ],
        ),
        (
            "/identity/connect/token",
            vec![(200, TOKEN_NEW.into())],
        ),
    ]);
    let client = Arc::new(Client::new(&mock.base()).unwrap());
    client.set_access_token("OLD").await;
    client.set_refresh_token(Some("R1")).await;
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move { c.sync().await.is_ok() }));
    }
    let mut oks = 0;
    for t in tasks {
        oks += usize::from(t.await.unwrap());
    }
    assert_eq!(oks, 3, "三個請求都該經收口成功");
    assert_eq!(mock.count("connect/token"), 1, "單飛：只續一次");
}

#[tokio::test]
async fn no_refresh_token_passes_error_through() {
    let mock = Mock::spawn(vec![(
        "/api/sync",
        vec![(401, "{\"message\":\"expired\"}".into())],
    )]);
    let client = Client::new(&mock.base()).unwrap();
    client.set_access_token("OLD").await; // API key 形態：無 refresh 憑證
    assert!(client.sync().await.is_err());
    assert!(!client.needs_relogin(), "無憑證可續 ≠ 憑證失效");
    assert_eq!(mock.count("connect/token"), 0);
}

#[test]
fn ninety_minute_gate_is_pure_and_bounded() {
    use bw_server::{REFRESH_AFTER_MS, token_due_for_refresh};
    assert_eq!(REFRESH_AFTER_MS, 90 * 60 * 1000);
    assert!(!token_due_for_refresh(0, u64::MAX), "未記錄取得時刻不搶跑");
    assert!(!token_due_for_refresh(1_000, 1_000 + REFRESH_AFTER_MS - 1));
    assert!(token_due_for_refresh(1_000, 1_000 + REFRESH_AFTER_MS));
    assert!(
        !token_due_for_refresh(1_000, 500),
        "時鐘回撥 saturating 至 0：不搶跑續期"
    );
}
