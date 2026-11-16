//! PR3 管理面代理的請求形態：以本地 mock server 記錄 method/path/body，
//! 斷言 `/two-factor/*` 各端點的欄位名與 `PasswordOrOtpData` 驗證欄，
//! 外加 `retry_with` 三因子（YubiKey OTP／Duo 雙段／WebAuthn assertion）
//! 的表單形態。端點與欄位名對照 Vaultwarden 1.37.2 源檔
//! `src/api/core/two_factor/*.rs`（表見 two_factor 模組頭）。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use bw_server::Client;
use bw_server::auth::{PasswordLogin, TwoFactorChallenge, TwoFactorProviderType};

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

    /// 第一筆含 `needle` 的記錄行（method path bearer body 合成字串）。
    fn hit(&self, needle: &str) -> String {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.contains(needle))
            .cloned()
            .unwrap_or_else(|| panic!("找不到 {needle}，實測={:?}", self.hits.lock().unwrap()))
    }

    /// 該請求的 JSON 體（欄位序不敏感；`serde_json::Map` 預設排序）。
    fn json_body(&self, needle: &str) -> serde_json::Value {
        let line = self.hit(needle);
        let raw = line.split_once("body=").expect("hit 應含 body 段").1;
        serde_json::from_str(raw).unwrap_or_else(|e| panic!("{needle} 體非 JSON：{raw}（{e}）"))
    }

    /// 該請求的 form 體 → 鍵值對（token 重送路徑）。
    fn form_body(&self, needle: &str) -> Vec<(String, String)> {
        let line = self.hit(needle);
        let raw = line.split_once("body=").expect("hit 應含 body 段").1;
        serde_urlencoded_pairs(raw)
    }
}

fn serde_urlencoded_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn client_with_token(mock: &Mock) -> Client {
    let client = Client::new(&mock.base()).unwrap();
    // 管理面全部需要 bearer（`require_token` 閘）；token 內容由 mock 不驗。
    client.set_access_token("AT").await;
    client
}

#[tokio::test]
async fn list_reads_vaultwarden_list_response() {
    let mock = Mock::spawn(vec![(
        "/api/two-factor",
        (
            200,
            "{\"data\":[{\"enabled\":true,\"type\":0,\"object\":\"twoFactorProvider\"},\
             {\"enabled\":true,\"type\":8,\"object\":\"twoFactorProvider\"}],\
             \"object\":\"list\",\"continuationToken\":null}"
                .to_owned(),
        ),
    )]);
    let client = client_with_token(&mock).await;
    let states = client.two_factor_list().await.unwrap();
    assert_eq!(
        states
            .iter()
            .map(|s| (s.provider, s.enabled))
            .collect::<Vec<_>>(),
        vec![(0, true), (8, true)]
    );
    assert_eq!(
        mock.hit("GET /api/two-factor"),
        "GET /api/two-factor bearer=1 body="
    );
}

#[tokio::test]
async fn authenticator_key_enable_and_disable_wire_shapes() {
    let mock = Mock::spawn(vec![
        (
            "/api/two-factor/get-authenticator",
            (200, "{\"enabled\":false,\"key\":\"JBSWY3DPEHPK3PXP\",\"object\":\"twoFactorAuthenticator\"}".to_owned()),
        ),
        (
            "/api/two-factor/authenticator",
            (200, "{\"enabled\":true,\"object\":\"twoFactorProvider\"}".to_owned()),
        ),
        (
            "/api/two-factor/disable",
            (200, "{\"enabled\":false,\"type\":0,\"object\":\"twoFactorProvider\"}".to_owned()),
        ),
    ]);
    let client = client_with_token(&mock).await;

    let key = client
        .two_factor_authenticator_key("HASH==")
        .await
        .expect("get-authenticator");
    assert_eq!(key.key, "JBSWY3DPEHPK3PXP");
    assert!(!key.already_enabled);
    assert_eq!(
        mock.json_body("POST /api/two-factor/get-authenticator"),
        serde_json::json!({"masterPasswordHash": "HASH=="})
    );

    client
        .two_factor_enable_authenticator("HASH==", &key.key, "123456")
        .await
        .expect("enable");
    assert_eq!(
        mock.json_body("POST /api/two-factor/authenticator"),
        serde_json::json!({
            "masterPasswordHash": "HASH==",
            "key": "JBSWY3DPEHPK3PXP",
            "token": "123456"
        })
    );

    client
        .two_factor_disable("HASH==", 0)
        .await
        .expect("disable");
    assert_eq!(
        mock.json_body("POST /api/two-factor/disable"),
        serde_json::json!({"masterPasswordHash": "HASH==", "type": 0})
    );
}

#[tokio::test]
async fn email_yubikey_and_recovery_shapes() {
    let mock = Mock::spawn(vec![
        ("/api/two-factor/send-email", (200, "{}".to_owned())),
        (
            "/api/two-factor/email",
            (200, "{\"email\":\"a@b.test\",\"enabled\":true}".to_owned()),
        ),
        (
            "/api/two-factor/yubikey",
            (200, "{\"enabled\":true}".to_owned()),
        ),
        (
            "/api/two-factor/get-recover",
            (
                200,
                "{\"code\":\"y3xv4t6z7qbjkmnp2rtw3xyzabcd\",\"object\":\"twoFactorRecover\"}"
                    .to_owned(),
            ),
        ),
    ]);
    let client = client_with_token(&mock).await;

    client
        .two_factor_send_email_code("HASH==", "a@b.test")
        .await
        .expect("send-email");
    assert_eq!(
        mock.json_body("POST /api/two-factor/send-email"),
        serde_json::json!({"masterPasswordHash": "HASH==", "email": "a@b.test"})
    );

    client
        .two_factor_verify_email("HASH==", "a@b.test", "654321")
        .await
        .expect("verify email");
    assert_eq!(
        mock.json_body("PUT /api/two-factor/email"),
        serde_json::json!({
            "masterPasswordHash": "HASH==",
            "email": "a@b.test",
            "token": "654321"
        })
    );

    let otp = "c".to_owned() + &"b".repeat(43);
    client
        .two_factor_enable_yubikey("HASH==", &otp, false)
        .await
        .expect("enable yubikey");
    assert_eq!(
        mock.json_body("POST /api/two-factor/yubikey"),
        serde_json::json!({
            "masterPasswordHash": "HASH==",
            "key1": otp,
            "nfc": false
        })
    );

    let code = client
        .two_factor_recovery_code("HASH==")
        .await
        .expect("get-recover");
    assert_eq!(code.as_deref(), Some("y3xv4t6z7qbjkmnp2rtw3xyzabcd"));
}

#[tokio::test]
async fn recovery_code_absent_is_none_not_error() {
    let mock = Mock::spawn(vec![(
        "/api/two-factor/get-recover",
        (
            200,
            "{\"code\":null,\"object\":\"twoFactorRecover\"}".to_owned(),
        ),
    )]);
    let client = client_with_token(&mock).await;
    assert_eq!(
        client.two_factor_recovery_code("HASH==").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn unauthenticated_management_call_fails_fast() {
    let mock = Mock::spawn(vec![("/api/two-factor", (200, "{\"data\":[]}".to_owned()))]);
    let client = Client::new(&mock.base()).unwrap();
    let err = client
        .two_factor_list()
        .await
        .expect_err("無 bearer 應快速失敗");
    assert!(
        matches!(err, bw_server::ServerError::Unauthenticated),
        "{err:?}"
    );
    assert!(mock.hits.lock().unwrap().is_empty(), "不該打出請求");
}

/// 第二步表單：三因子（YubiKey OTP、Duo `AUTH…:APP…`、WebAuthn assertion JSON）
/// 都以 `twoFactorProvider` 編號＋原樣 token 送出（表單 urlencod 由 reqwest 做，
/// 這裡斷言的是欄位值本身）。源檔對照 `src/api/identity.rs:826-880`。
#[test]
fn retry_form_carries_three_factor_shapes() {
    use bw_proto::TwoFactorProviderInfo as P;

    let assertion = serde_json::json!({
        "id": "credA",
        "rawId": "credA",
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": "aHVzdG9y",
            "clientDataJson": "Y2xpZW50",
            "signature": "c2ln",
            "userHandle": null
        }
    })
    .to_string();
    let cases: [(TwoFactorProviderType, &str); 3] = [
        (
            TwoFactorProviderType::YubiKey,
            &(String::from("c") + &"b".repeat(43)),
        ),
        (
            TwoFactorProviderType::Duo,
            "AUTH|aGVsbG8=|sig1|AUTO|AUTO:APP|aGVsbG8=|sig2",
        ),
        (TwoFactorProviderType::Webauthn, &assertion),
    ];
    for (kind, token) in cases {
        let login = PasswordLogin::new("a@b.test", "HASH==", "dev").two_factor(kind, token, false);
        let form = bw_server::auth::build_form(&login, &bw_server::ClientOptions::default());
        let want_provider = kind.as_i32();
        assert!(
            P::is_supported(want_provider),
            "因子 {want_provider} 不在白名單，daemon 會先拒"
        );
        for (k, v) in &form {
            match k.as_str() {
                "twoFactorProvider" => assert_eq!(v, &want_provider.to_string()),
                "twoFactorToken" => assert_eq!(v, token),
                "twoFactorRemember" => assert_eq!(v, "0"),
                _ => {}
            }
        }
    }
}

/// `retry_with` 端到端：挑戰重送後伺服器收表單、回 token（含 Keys）。
#[tokio::test]
async fn retry_with_resends_password_grant_with_factor() {
    let mock = Mock::spawn(vec![
        (
            "/identity/connect/token",
            (
                200,
                "{\"access_token\":\"AT2\",\"refresh_token\":\"R2\",\"expires_in\":7200,\
                 \"token_type\":\"Bearer\",\"Key\":\"2.iv|ct|mac\",\"PrivateKey\":\"2.iv|ct|mac\"}"
                    .to_owned(),
            ),
        ),
        ("/api/", (200, "{}".to_owned())),
    ]);
    let client = Client::new(&mock.base()).unwrap();
    let login = PasswordLogin::new("a@b.test", "HASH==", "dev");
    let challenge = TwoFactorChallenge {
        login,
        providers: vec![bw_server::TwoFactorProvider {
            kind: TwoFactorProviderType::YubiKey,
            details: Some(serde_json::json!({ "Nfc": false })),
        }],
        raw: serde_json::json!({}),
        error: "Two factor required.".to_owned(),
    };
    let otp = "c".to_owned() + &"b".repeat(43);
    let bundle = challenge
        .retry_with(&client, TwoFactorProviderType::YubiKey, &otp, false)
        .await
        .expect("第二步應成功");
    assert_eq!(bundle.access_token, "AT2");
    let sent = mock.form_body("POST /identity/connect/token");
    let get = |k: &str| {
        sent.iter()
            .find(|(sk, _)| sk == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("grant_type"), "password");
    assert_eq!(get("twoFactorProvider"), "3");
    assert_eq!(get("twoFactorToken"), otp);
    assert_eq!(get("username"), "a@b.test");
}
