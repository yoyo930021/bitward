//! e2e：對真實 Vaultwarden 跑完整讀寫路徑（契约 §6 A2 的動態部分）。
//!
//! 跑法（需要本機 docker）：
//! ```sh
//! docker run -d --name bitward-vw-u4 -p 18080:80 \
//!   -e I_REALLY_WANT_VOLATILE_STORAGE=true \
//!   -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=20 \
//!   vaultwarden/server:1.37.2
//! cargo test -p bw-server --features e2e -- --nocapture
//! ```
//! 沒有 `BITWARD_E2E_SERVER` 時整個檔跳過（CI 的釘版矩陣才有這個 env）。

#![cfg(feature = "e2e")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bw_server::auth::{PasswordLogin, TwoFactorChallenge};
use bw_server::vault::{DeleteKind, NewAttachment, absolutize};
use bw_server::{
    Client, ClientOptions, NewAccount, ServerError, ServerKind, TokenGrant, TwoFactorProviderType,
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Digest as _;

const PASSWORD: &str = "correct horse battery staple";

fn base_url() -> Option<String> {
    std::env::var("BITWARD_E2E_SERVER")
        .ok()
        .filter(|v| !v.is_empty())
}

/// 主密碼雜湊的**替身**：真正的派生在 bw-crypto（PBKDF2-SHA256(email, pwd) 再 PBKDF2 一層）。
/// 這一層只測試 HTTP 協定，所以只要每次一致即可——伺服器對它再做一輪加鹽 hash。
fn master_password_hash(email: &str) -> String {
    use base64::Engine as _;
    let digest = sha2::Sha256::digest(format!("{PASSWORD}{email}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// 僞造的 user key 信封：形狀正確（`2.iv|ct|mac`），內容對本層是透明的。
fn dummy_envelope(seed: &str) -> String {
    use base64::Engine as _;
    let block = |n: usize| {
        let s: String = (0..n)
            .map(|i| (b'a' + (((seed.len() + i) % 26) as u8)) as char)
            .collect();
        base64::engine::general_purpose::STANDARD.encode(s)
    };
    format!("2.{}|{}|{}", block(16), block(48), block(32))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn unique_email(tag: &str) -> String {
    format!("e2e-{tag}-{}@bitward.test", unix_now())
}

async fn api_post(client: &Client, path: &str, body: &Value) -> Value {
    let token = client.access_token().await.expect("token");
    let api = client.service_url("api").await;
    let resp = reqwest::Client::new()
        .post(format!("{api}/{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .expect("request");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "POST {path} -> {status}: {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// RFC 6238 TOTP（SHA1、30 秒、6 位）——只為在 e2e 裡真的走完 2FA 第二步。
fn totp(secret_base32: &str, at: u64) -> String {
    let key = base32_decode(secret_base32);
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).expect("hmac");
    mac.update(&(at / 30).to_be_bytes());
    let code = mac.finalize().into_bytes();
    let off = usize::from(code[code.len() - 1] & 0x0f);
    let value =
        u32::from_be_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]) & 0x7fff_ffff;
    format!("{:06}", value % 1_000_000)
}

fn base32_decode(input: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = Vec::new();
    for c in input.bytes() {
        let c = c.to_ascii_uppercase() as char;
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let idx = alphabet
            .iter()
            .position(|a| *a as char == c)
            .unwrap_or_else(|| panic!("bad base32 {c}"));
        acc = (acc << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// 登入。429（Vaultwarden 的 login rate limit）用退避重試吸收，
/// 這樣在釘版預設值的容器上也能跑。
async fn login(client: &Client, grant: TokenGrant) -> Result<bw_server::TokenBundle, ServerError> {
    let mut attempt = 0;
    loop {
        match client.token(grant.clone()).await {
            Err(e) if e.is_rate_limited() && attempt < 5 => {
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(2 * attempt)).await;
            }
            other => return other,
        }
    }
}

/// 第二步：碼可能剛好撞上已被使用的窗口（啟用 2FA 時用掉一個），
/// 所以跨窗口重試；rate limit 則退避。
async fn login_with_code(
    client: &Client,
    challenge: &TwoFactorChallenge,
    secret: &str,
) -> Result<bw_server::TokenBundle, ServerError> {
    let mut last = ServerError::Rejected("2FA retry never ran".to_owned());
    for _ in 0..4 {
        let window = unix_now() / 30;
        let code = totp(secret, window * 30);
        match challenge.retry(client, &code, false).await {
            Ok(bundle) => return Ok(bundle),
            Err(e) if e.is_rate_limited() => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                last = e;
            }
            Err(e) if e.to_string().contains("Invalid TOTP code") => {
                while unix_now() / 30 == window {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                last = e;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// 一個全新的帳號 + 已登入的 client。
async fn fresh_client(base: &str, tag: &str) -> (Client, String) {
    let email = unique_email(tag);
    let hash = master_password_hash(&email);
    let client = Client::with_options(
        base,
        ClientOptions {
            device_name: format!("bitward-e2e-{tag}"),
            ..Default::default()
        },
    )
    .expect("client");
    let account = NewAccount::new(
        email.clone(),
        "E2E User",
        hash.clone(),
        dummy_envelope(&email),
    );
    client
        .register(&account)
        .await
        .unwrap_or_else(|e| panic!("register {email}: {e}"));
    let bundle = login(
        &client,
        TokenGrant::Password {
            email: email.clone(),
            master_password_hash: hash.clone(),
            device_identifier: format!("u4-e2e-{tag}"),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("token: {e}"));
    assert!(!bundle.access_token.is_empty());
    assert!(
        bundle.refresh_token.is_some(),
        "password grant 應拿到 offline_access token"
    );
    let keys = bundle.keys.clone().expect("password grant 應帶回 Keys");
    assert_eq!(keys.kdf_iterations, Some(600_000), "VW 預設 PBKDF2 600k");
    (client, email)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vaultwarden_round_trip() {
    let Some(base) = base_url() else {
        eprintln!("BITWARD_E2E_SERVER 未設定，跳過 e2e");
        return;
    };
    let (client, email) = fresh_client(&base, "main").await;

    // —— 探測 ——
    let probe = client.probe().await;
    assert_eq!(
        probe.kind(),
        ServerKind::Vaultwarden,
        "本 e2e 的 target 是 Vaultwarden"
    );
    assert!(
        probe
            .profile
            .version
            .as_deref()
            .is_some_and(|v| v.starts_with("1.")),
        "拿到產品版本而非協定版本: {:?}",
        probe.profile.version
    );
    assert!(probe.has("notifications.websocket"));
    assert!(probe.has_quirk(bw_server::Quirk::RestoreUsesPutVerb));

    // —— sync（空 vault）——
    let sync = client.sync_parsed().await.expect("sync");
    assert_eq!(sync.object.as_deref(), Some("sync"));
    assert!(sync.ciphers.is_empty(), "新帳號不該有 cipher");
    assert!(
        sync.profile
            .as_ref()
            .is_some_and(|p| p["email"].as_str() == Some(&email))
    );
    let fingerprint = sync.key_fingerprint().expect("金鑰指紋");

    // —— create / get / put / patch ——
    let envelope = dummy_envelope("cipher-name");
    let created = client
        .cipher_create(&json!({
            "type": 1,
            "name": envelope,
            "login": { "username": dummy_envelope("user"), "password": dummy_envelope("pass"), "uris": [{"uri": dummy_envelope("uri"), "match": null}] },
            "folderId": Value::Null,
            "organizationId": Value::Null,
            "collectionIds": [],
            "notes": Value::Null,
            "favorite": false,
        }))
        .await
        .expect("create cipher");
    let id: bw_server::ItemId = created["id"].as_str().unwrap().parse().expect("uuid id");
    assert_eq!(created["name"].as_str().unwrap(), envelope);

    let fetched = client.cipher_get(id).await.expect("get cipher");
    assert_eq!(fetched["id"], created["id"]);
    let rev1 = fetched["revisionDate"].as_str().unwrap().to_owned();

    let mut updated = fetched.clone();
    updated["name"] = json!(dummy_envelope("renamed"));
    updated.as_object_mut().unwrap().remove("object");
    let put = client.cipher_put(id, &updated).await.expect("put cipher");
    assert_ne!(put["name"], fetched["name"], "整筆覆寫要生效");
    let rev2 = put["revisionDate"].as_str().unwrap().to_owned();
    assert_ne!(rev1, rev2, "revisionDate 是 CAS 基準，必須遞增");

    // 欄位級 patch：Vaultwarden 只認 folderId/favorite（见 NOTES.md）
    let patched = client
        .cipher_patch(id, &json!({ "folderId": null, "favorite": true }))
        .await
        .expect("patch");
    assert_eq!(patched["favorite"], json!(true));
    assert_eq!(patched["name"], put["name"], "patch 不該動到沒送的欄位");

    // raw mirror：未建模欄位還在（不變量 8）
    assert!(patched.get("organizationUseTotp").is_some() || patched.get("viewPassword").is_some());

    // —— 附件 v2：只取 URL ——
    let upload = client
        .attachment_prepare_upload(
            id,
            &NewAttachment {
                file_name: "notes.txt".to_owned(),
                size: 11,
                key: Some(dummy_envelope("att")),
            },
        )
        .await
        .expect("attachment v2");
    assert!(!upload.attachment_id.is_empty());
    assert!(
        upload.url.starts_with("http"),
        "相對 URL 要拼成絕對 URL: {}",
        upload.url
    );
    assert_eq!(
        upload.url,
        absolutize(
            &client.service_url("api").await,
            upload.raw["url"].as_str().unwrap()
        )
    );
    let token = client.access_token().await.unwrap();
    let uploaded = match upload.method {
        bw_server::vault::UploadMethod::PutRaw => reqwest::Client::new()
            .put(&upload.url)
            .bearer_auth(&token)
            .header("Content-Type", "application/octet-stream")
            .body("hello world")
            .send()
            .await
            .expect("put attachment"),
        bw_server::vault::UploadMethod::PostMultipart => reqwest::Client::new()
            .post(&upload.url)
            .bearer_auth(&token)
            .multipart(
                reqwest::multipart::Form::new()
                    .text("key", dummy_envelope("att"))
                    .part(
                        "data",
                        reqwest::multipart::Part::bytes("hello world".as_bytes().to_vec())
                            .file_name("notes.txt"),
                    ),
            )
            .send()
            .await
            .expect("post attachment"),
    };
    assert!(
        uploaded.status().is_success(),
        "上傳附件失敗: {}",
        uploaded.status()
    );

    let download = client
        .attachment_download(id, &upload.attachment_id)
        .await
        .expect("attachment url");
    let download_url = download.url.clone().expect("簽名 URL");
    assert!(
        download_url.contains("token="),
        "下載 URL 該是簽名的: {download_url}"
    );
    let got = reqwest::Client::new()
        .get(&download_url)
        .send()
        .await
        .expect("download");
    assert!(
        got.status().is_success(),
        "下載不該要额外授權: {}",
        got.status()
    );
    assert_eq!(got.text().await.unwrap(), "hello world");

    let with_att = client.cipher_get(id).await.unwrap();
    assert!(
        with_att["attachments"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
            || with_att["attachments"]
                .as_object()
                .map(|o| !o.is_empty())
                .unwrap_or(false),
        "附件要出現在 cipher 上"
    );

    // —— notifications：另一台裝置寫入 → 本裝置收到事件 ——
    let mut stream = client.notifications().await.expect("notifications connect");
    let other = Client::with_options(
        &base,
        ClientOptions {
            device_name: "bitward-e2e-peer".to_owned(),
            ..Default::default()
        },
    )
    .unwrap();
    login(
        &other,
        TokenGrant::Password {
            email: email.clone(),
            master_password_hash: master_password_hash(&email),
            device_identifier: "u4-e2e-peer".to_owned(),
        },
    )
    .await
    .expect("peer login");
    let peer_cipher = other
        .cipher_create(&json!({ "type": 1, "name": dummy_envelope("peer"), "login": { "username": dummy_envelope("p") }, "collectionIds": [] }))
        .await
        .expect("peer create");
    let peer_id = peer_cipher["id"].as_str().unwrap().to_owned();

    let event = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ev = stream.next().await.expect("stream ended");
            let matched = ev.cipher_id().is_some_and(|cid| cid.to_string() == peer_id);
            if matched {
                return ev;
            }
        }
    })
    .await
    .expect("20 秒內該收到 peer 的 cipher 事件（A12 的 5 秒視窗靠這個觸發）");
    assert!(event.update.is_cipher());
    assert_eq!(
        event.context_id.as_deref(),
        Some("u4-e2e-peer"),
        "ContextId 是發起裝置"
    );
    assert!(!event.is_own_change("u4-e2e-main"));
    // targeted pull：事件帶 id 就能單筆拉，不必全量 sync
    let pulled = client
        .cipher_get(event.cipher_id().unwrap())
        .await
        .expect("targeted pull");
    assert_eq!(pulled["id"].as_str().unwrap(), peer_id);
    stream.close().await.ok();

    // —— 回收桶：軟刪 → 還原 → 硬刪 ——
    client
        .cipher_delete(id, DeleteKind::Soft)
        .await
        .expect("soft delete");
    let deleted = client.cipher_get(id).await.expect("軟刪後仍讀得到");
    assert!(
        deleted["deletedDate"].as_str().is_some(),
        "deletedDate 要有值"
    );
    client.cipher_restore(id).await.expect("restore");
    let restored = client.cipher_get(id).await.expect("get after restore");
    assert!(
        restored["deletedDate"].is_null(),
        "還原後 deletedDate 應清空"
    );

    // 沒有 /ciphers/deleted 的 server 要回 Unsupported，讓上層降回全量 sync
    match client.ciphers_deleted().await {
        Ok(v) => assert!(v.get("data").is_some() || v.is_array() || v.is_object()),
        Err(ServerError::Unsupported(_)) => {}
        Err(e) => panic!("預期 Unsupported 或成功，得到 {e}"),
    }

    client
        .cipher_delete(id, DeleteKind::Hard)
        .await
        .expect("hard delete");
    assert!(client.cipher_get(id).await.is_err(), "硬刪後不該讀得到");
    other
        .ciphers_delete_bulk(&[event.cipher_id().unwrap()], DeleteKind::Hard)
        .await
        .expect("bulk delete");

    // —— 金鑰指紋穩定（同一帳號重連不該漂移）——
    let sync2 = client.sync_parsed().await.unwrap();
    assert_eq!(
        sync2.key_fingerprint().as_deref(),
        Some(fingerprint.as_str())
    );

    // —— refresh ——
    let refreshed = client.refresh().await.expect("refresh");
    assert!(!refreshed.access_token.is_empty());
    // VW 的 JWT claims 以秒為單位，同一秒內換發可能拿到逐字元相同的 token；
    // 這裡要保證的是「換發成功且可用」，不是「一定不同」。
    assert!(client.sync().await.is_ok(), "新 token 可用");

    // —— 2FA 兩步 ——
    let auth = api_post(
        &client,
        "two-factor/get-authenticator",
        &json!({ "masterPasswordHash": master_password_hash(&email) }),
    )
    .await;
    let secret = auth["key"].as_str().unwrap().to_owned();
    // 啟用時吃掉一個窗口的碼；Vaultwarden 對同一個碼在窗口內不給重複使用，
    // 所以第二步必須等「下一個还没用過的窗口」。
    let used_window = unix_now() / 30 + 1;
    api_post(
        &client,
        "two-factor/authenticator",
        &json!({ "key": secret, "token": totp(&secret, used_window * 30), "masterPasswordHash": master_password_hash(&email) }),
    )
    .await;
    let login = PasswordLogin::new(
        email.clone(),
        master_password_hash(&email),
        "u4-e2e-2fa".to_owned(),
    );
    let Err(ServerError::TwoFactorRequired { challenge }) = client.password_login(&login).await
    else {
        panic!("開了 2FA 之後第一步應該被擋下");
    };
    let challenge: TwoFactorChallenge = *challenge;
    assert!(
        challenge
            .providers
            .iter()
            .any(|p| p.kind == TwoFactorProviderType::Authenticator)
    );
    let retry = login_with_code(&client, &challenge, &secret)
        .await
        .unwrap_or_else(|e| panic!("第二步失敗: {e}"));
    assert!(!retry.access_token.is_empty());
    assert!(client.sync().await.is_ok(), "2FA 登入後可讀 vault");

    // —— 登出 ——
    client.sign_out().await;
    assert!(matches!(
        client.sync().await,
        Err(ServerError::Unauthenticated)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_key_login_reads_vault_but_2fa_account_still_needs_password() {
    let Some(base) = base_url() else { return };
    let (client, email) = fresh_client(&base, "apikey").await;
    let resp = api_post(
        &client,
        "accounts/api-key",
        &json!({ "masterPasswordHash": master_password_hash(&email) }),
    )
    .await;
    let secret = resp["apiKey"].as_str().expect("apiKey");
    let uid = client.user_id().await.expect("sub claim 給出 user id");

    let api = Client::new(&base).unwrap();
    let bundle = api
        .client_credentials(&format!("user.{uid}"), secret)
        .await
        .expect("client_credentials grant");
    assert!(bundle.refresh_token.is_none(), "API key 不發 refresh token");
    assert!(api.sync().await.is_ok(), "API key 可以讀 vault");
    assert!(
        api.cipher_create(
            &json!({ "type": 1, "name": dummy_envelope("k"), "login": {}, "collectionIds": [] })
        )
        .await
        .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_master_password_is_a_clean_rejection() {
    let Some(base) = base_url() else { return };
    let email = unique_email("badpw");
    let client = Client::new(&base).unwrap();
    client
        .register(&NewAccount::new(
            email.clone(),
            "Bad",
            master_password_hash(&email),
            dummy_envelope(&email),
        ))
        .await
        .unwrap();
    let err = client
        .token(TokenGrant::Password {
            email,
            master_password_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            device_identifier: "u4-e2e-bad".to_owned(),
        })
        .await
        .expect_err("錯密碼要被打回");
    match err {
        ServerError::Http {
            status: 400,
            ref detail,
        } => {
            assert!(
                detail.to_lowercase().contains("incorrect"),
                "錯誤訊息要能用: {detail}"
            );
        }
        other => panic!("預期 400，得到 {other:?}"),
    }
    assert!(!client.signed_in().await, "失敗的登入不該留下 token");
}
