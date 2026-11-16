//! PR4 EA 端點代理的請求形態與路徑探測：mock server 記錄 method/path/body，
//! 斷言 `emergency-access/*` 各端點的欄位名（源檔對照見 `bw_server::ea` 模組表），
//! 外加 ServerProfile 未定性時的**雙態路徑探測**（VW 佈局 vs 舊雲
//! `accounts/emergency-access` 佈局）。回應形態以 `fixtures/ea_*` 真錄 bytes
//! 回放（§2.6 釘選；雲態為推導樣本）。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use bw_proto::{EaAccessType, EaRole, EaStatus};
use bw_server::Client;
use bw_server::ea::parse_contacts;

struct Mock {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
}

/// 應答腳本：path 前綴 → (status, body)。
fn scripted(path: &str, queues: &[(String, (u16, String))]) -> (u16, String) {
    queues
        .iter()
        .find(|(p, _)| path.starts_with(p.as_str()))
        .map(|(_, r)| r.clone())
        .unwrap_or((404, "{\"message\":\"unmatched\"}".to_owned()))
}

impl Mock {
    fn spawn(script: Vec<(&str, (u16, String))>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let queues: Vec<(String, (u16, String))> =
            script.into_iter().map(|(p, r)| (p.to_owned(), r)).collect();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits_c = hits.clone();
        std::thread::spawn(move || {
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
                let mut bearer = false;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(rest) = lower.strip_prefix("content-length:") {
                        len = rest.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("authorization:") {
                        bearer = true;
                    }
                }
                let mut body = vec![0u8; len];
                if len > 0 {
                    let _ = reader.read_exact(&mut body);
                }
                hits_c.lock().unwrap().push(format!(
                    "{method} {path} bearer={} body={}",
                    bearer as u8,
                    String::from_utf8_lossy(&body)
                ));
                let (status, resp_body) = scripted(&path, &queues);
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

    fn hit(&self, needle: &str) -> String {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.contains(needle))
            .cloned()
            .unwrap_or_else(|| panic!("找不到 {needle}，實測={:?}", self.hits.lock().unwrap()))
    }

    fn json_body(&self, needle: &str) -> serde_json::Value {
        let line = self.hit(needle);
        let raw = line.split_once("body=").expect("hit 應含 body 段").1;
        serde_json::from_str(raw).unwrap_or_else(|e| panic!("{needle} 體非 JSON：{raw}（{e}）"))
    }
}

async fn client_with_token(mock: &Mock) -> Client {
    let client = Client::new(&mock.base()).unwrap();
    client.set_access_token("AT").await;
    client
}

const TRUSTED_VW: &str = include_str!("../fixtures/ea_trusted_vw_1.37.2.json");
const GRANTED_VW: &str = include_str!("../fixtures/ea_granted_vw_1.37.2.json");
const PUBKEY_VW: &str = include_str!("../fixtures/users_public_key_vw_1.37.2.json");
const GRANTED_CLOUD: &str = include_str!("../fixtures/ea_granted_cloud_derived.json");

/// VW 佈局全鏈形態：清單解析吃真錄 bytes、invite/confirm/revoke 的
/// path 與欄位名逐斷言（`{api}/emergency-access/*`、公鑰 `{api}/users/{id}/…`）。
#[tokio::test]
async fn vaultwarden_layout_full_grantor_chain() {
    let mock = Mock::spawn(vec![
        ("/api/emergency-access/trusted", (200, TRUSTED_VW.to_owned())),
        ("/api/emergency-access/granted", (200, GRANTED_VW.to_owned())),
        (
            "/api/emergency-access/20eb27d5-49a9-4543-8c3c-42b9adff99e5/confirm",
            (200, "{\"id\":\"20eb27d5-49a9-4543-8c3c-42b9adff99e5\",\"status\":2,\"type\":0,\"waitTimeDays\":7,\"object\":\"emergencyAccess\"}".to_owned()),
        ),
        (
            "/api/emergency-access/20eb27d5-49a9-4543-8c3c-42b9adff99e5",
            (200, "{\"id\":\"20eb27d5-49a9-4543-8c3c-42b9adff99e5\",\"status\":2,\"type\":0,\"waitTimeDays\":7,\"object\":\"emergencyAccess\"}".to_owned()),
        ),
        ("/api/emergency-access/invite", (200, "{}".to_owned())),
        ("/api/users/", (200, PUBKEY_VW.to_owned())),
    ]);
    let client = client_with_token(&mock).await;

    let rows = client.ea_list(EaRole::Grantee).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, EaStatus::Confirmed);
    assert_eq!(rows[0].access_type, EaAccessType::View);
    assert_eq!(rows[0].wait_time_days, 7);
    assert_eq!(
        rows[0].user_id.as_deref(),
        Some("4f474103-2fb9-4e47-a56c-50845ee86bfe")
    );

    let grantors = client.ea_list(EaRole::Grantor).await.unwrap();
    assert_eq!(
        grantors[0].email,
        rows[0].email.replace("grantee", "grantor")
    );

    client
        .ea_invite("someone@bitward.test", EaAccessType::Takeover, 2)
        .await
        .unwrap();
    let body = mock.json_body("POST /api/emergency-access/invite");
    assert_eq!(body["email"], "someone@bitward.test");
    assert_eq!(body["type"], 1);
    assert_eq!(body["waitTimeDays"], 2);

    let pk = client
        .ea_public_key("4f474103-2fb9-4e47-a56c-50845ee86bfe")
        .await
        .unwrap();
    assert!(pk.starts_with("-----BEGIN PUBLIC KEY-----"));

    client
        .ea_confirm("20eb27d5-49a9-4543-8c3c-42b9adff99e5", "4.fake|wrapped|b64")
        .await
        .unwrap();
    let body =
        mock.json_body("POST /api/emergency-access/20eb27d5-49a9-4543-8c3c-42b9adff99e5/confirm");
    assert_eq!(body["key"], "4.fake|wrapped|b64");

    client
        .ea_revoke("20eb27d5-49a9-4543-8c3c-42b9adff99e5")
        .await
        .unwrap();
    assert!(
        mock.hit("DELETE /api/emergency-access/20eb27d5-49a9-4543-8c3c-42b9adff99e5")
            .contains("bearer=1")
    );
}

/// 路徑探測雙態（§2.6）：`/config` 判不了家鄉（mock 全 404＝Unknown）時，
/// trusted 404 → 改探 `accounts/emergency-access` 命中 → 後續呼叫走雲舊佈局，
/// 並記 `EmergencyAccessUnderAccounts` quirk。
#[tokio::test]
async fn probe_falls_back_to_cloud_accounts_layout() {
    let mock = Mock::spawn(vec![
        (
            "/api/accounts/emergency-access",
            (200, GRANTED_CLOUD.to_owned()),
        ),
        (
            "/api/accounts/emergency-access/invite",
            (200, "{}".to_owned()),
        ),
    ]);
    let client = client_with_token(&mock).await;

    let rows = client.ea_list(EaRole::Grantor).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, EaStatus::RecoveryInitiated);
    assert_eq!(
        rows[0].recovery_initiated_at.as_deref(),
        Some("2026-11-16T12:00:00Z")
    );
    // 探測軌跡：先撞 VW 路徑 404，再命中雲路徑
    mock.hit("GET /api/emergency-access/trusted");
    assert!(
        client
            .cached_probe()
            .await
            .quirks
            .contains(&bw_server::profile::Quirk::EmergencyAccessUnderAccounts)
    );
    // 快取生效：後續呼叫直接走雲佈局（invite 命中 accounts 前綴）
    client
        .ea_invite("x@y.test", EaAccessType::View, 1)
        .await
        .unwrap();
    mock.hit("POST /api/accounts/emergency-access/invite");
}

/// 雙態清單解析共用同一純函數：雲推導樣本（帶 recoveryInitiatedDate）
/// 與 VW 真錄（不帶）都得收斂成型別形態。
#[test]
fn both_fixture_shapes_parse() {
    let vw: serde_json::Value = serde_json::from_str(TRUSTED_VW).unwrap();
    let cloud: serde_json::Value = serde_json::from_str(GRANTED_CLOUD).unwrap();
    let a = parse_contacts(&vw, EaRole::Grantee);
    let b = parse_contacts(&cloud, EaRole::Grantor);
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].recovery_initiated_at, None);
    assert!(b[0].recovery_initiated_at.is_some());
}
