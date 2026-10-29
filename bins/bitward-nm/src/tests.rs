//! 整合測試：假 daemon（tokio UDS）跑五個 method 各一筆 + unknown-session 重配對路徑；
//! manifest 寫入以 tempdir 斷言。LE framing 單元測在 `framing.rs`。

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use serde_json::{Value, json};
use tokio::io::duplex;
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use bw_btp::{read_client, write_server};
use bw_proto::{
    AccountInfo, AdminCall, Auth, AuthCall, Call, ClientMsg, ItemKind, ItemMeta, ItemView,
    PROTO_VERSION, Response, ServerKind, ServerMsg, ServerProfile, UnlockStateView, VaultCall,
    View, WtpError,
};

use crate::bridge::Bridge;
use crate::framing::{read_nm, write_nm};
use crate::manifest::{Browser, HOST_NAME, chrome_origin, install, manifest_value};
use crate::serve;
use crate::session::{open_bridge, token_file};

const GITHUB: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
const GITLAB: &str = "11111111-2222-3333-4444-555555555555";
const GIST: &str = "22222222-3333-4444-5555-666666666666";

fn item(id: &str, name: &str, uris: &[&str]) -> ItemView {
    ItemView::metadata(ItemMeta {
        id: Uuid::parse_str(id).unwrap(),
        kind: ItemKind::Login,
        name: Some(name.into()),
        uris: uris.iter().map(|s| s.to_string()).collect(),
        folder_id: None,
        organization_id: None,
        favorite: false,
        tags: vec![],
        updated_at: None,
        pending: false,
    })
}

#[derive(Clone)]
struct Daemon {
    hellos: Arc<Mutex<Vec<Auth>>>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// true ⇒ `Auth::Session` 握手即斷線（模擬 daemon 重啟後的 unknown session）。
    kill_sessions: Arc<AtomicBool>,
    /// true ⇒ vault.list 收到後不回 Reply，等 `kill` 訊號再收線（測 pending 斷線）。
    hang_lists: Arc<AtomicBool>,
    kill: Arc<tokio::sync::Notify>,
}

async fn spawn_daemon(dir: &Path) -> Daemon {
    let listener = UnixListener::bind(dir.join("daemon.sock")).unwrap();
    let d = Daemon {
        hellos: Arc::new(Mutex::new(Vec::new())),
        calls: Arc::new(Mutex::new(Vec::new())),
        kill_sessions: Arc::new(AtomicBool::new(false)),
        hang_lists: Arc::new(AtomicBool::new(false)),
        kill: Arc::new(tokio::sync::Notify::new()),
    };
    let inner = d.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let d = inner.clone();
            tokio::spawn(async move { conn(stream, d).await });
        }
    });
    d
}

async fn conn(stream: UnixStream, d: Daemon) {
    let (mut rd, mut wr) = stream.into_split();
    let Ok(ClientMsg::Hello { auth, .. }) = read_client(&mut rd).await else {
        return;
    };
    if matches!(auth, Auth::Session { .. }) && d.kill_sessions.load(AtomicOrdering::SeqCst) {
        return; // 不送 Welcome，直接收線
    }
    d.hellos.lock().unwrap().push(auth);
    write_server(
        &mut wr,
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
    .await
    .unwrap();
    loop {
        let Ok(msg) = read_client(&mut rd).await else {
            return;
        };
        let ClientMsg::Invoke { rid, call } = msg else {
            continue;
        };
        let hung = d.hang_lists.load(AtomicOrdering::SeqCst)
            && matches!(call, Call::Vault(VaultCall::List { .. }));
        let outcome = reply(&call);
        d.calls.lock().unwrap().push(call);
        if hung {
            d.kill.notified().await;
            return; // 收線：對端讀到 EOF ⇒ 橋斷
        }
        if write_server(&mut wr, &ServerMsg::Reply { rid, outcome })
            .await
            .is_err()
        {
            return;
        }
    }
}

fn reply(call: &Call) -> Result<Response, WtpError> {
    match call {
        Call::Admin(AdminCall::Version) => Ok(Response::Version("0.0.1-test".into())),
        Call::Auth(AuthCall::WhoAmI) => Ok(Response::Account(Some(AccountInfo {
            email: "dev@bitward.test".into(),
            server: "http://127.0.0.1:8080".into(),
        }))),
        Call::Vault(VaultCall::List { query, view }) => {
            // 假 daemon 的 uri 過濾＝子串比對（真 daemon 是 LIKE，語意一致）：
            // "github.com" 同時命中 GitHub 與 Gist，逼 shim 做 host 精確過濾。
            let all = vec![
                item(GITHUB, "GitHub", &["https://github.com"]),
                item(GITLAB, "GitLab", &["https://gitlab.com"]),
                item(GIST, "Gist", &["https://gist.github.com"]),
            ];
            let items: Vec<ItemView> = match query.uri.as_deref() {
                Some(sub) => all
                    .into_iter()
                    .filter(|it| it.meta.uris.iter().any(|u| u.contains(sub)))
                    .collect(),
                None => all,
            };
            assert_eq!(*view, View::Metadata, "瀏覽器面 list 必須 Metadata");
            Ok(Response::Items(items))
        }
        Call::Vault(VaultCall::Get { id, view }) => {
            assert_eq!(*view, View::Reveal, "credential.reveal 必須 Reveal");
            Ok(Response::Item(Some(
                item(
                    &id.as_simple().to_string(),
                    "GitHub",
                    &["https://github.com"],
                )
                .revealed(Some("hunter2".into())),
            )))
        }
        other => Err(WtpError::Unsupported {
            feature: format!("fake: {other:?}"),
        }),
    }
}

/// 起一條假瀏覽器 stdin（UDS pair）＋記憶體 stdout，回 (寫請求端, 讀回應端, serve 任務)。
fn shim(
    bridge: Arc<Bridge>,
) -> (
    UnixStream,
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let (host_stdin, shim_stdin) = UnixStream::pair().unwrap();
    let (resp_tx, resp_rx) = duplex(1 << 20);
    // serve 吃 resp_tx 當 stdout；測試從 resp_rx 讀。
    let task = tokio::spawn(serve(bridge, shim_stdin, resp_tx));
    (host_stdin, resp_rx, task)
}

#[tokio::test]
async fn five_methods_over_fake_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_daemon(dir.path()).await;
    let stream = UnixStream::connect(dir.path().join("daemon.sock"))
        .await
        .unwrap();
    let bridge = Arc::new(
        Bridge::connect(
            stream,
            Auth::Session {
                token: "saved-token".into(),
            },
        )
        .await
        .unwrap(),
    );
    let (mut stdin, mut rx, task) = shim(bridge);

    let requests = vec![
        json!({"id": 1, "method": "ping", "params": {}}),
        json!({"id": 2, "method": "session.info", "params": {}}),
        json!({"id": 3, "method": "vault.list", "params": {}}),
        json!({"id": 4, "method": "credential.match", "params": {"uri": "https://github.com/settings/profile"}}),
        json!({"id": 5, "method": "credential.reveal", "params": {"id": GITHUB}}),
    ];
    for req in &requests {
        write_nm(&mut stdin, req).await.unwrap();
    }
    let mut by_id = serde_json::Map::new();
    for _ in 0..requests.len() {
        let resp = read_nm(&mut rx).await.unwrap().unwrap();
        let key = resp["id"].as_u64().unwrap().to_string();
        assert!(by_id.insert(key, resp).is_none(), "重複 id 回應");
    }

    assert_eq!(
        by_id["1"],
        json!({"id": 1, "ok": true, "result": {"Version": "0.0.1-test"}})
    );
    assert_eq!(
        by_id["2"],
        json!({"id": 2, "ok": true, "result": {"Account": {"email": "dev@bitward.test", "server": "http://127.0.0.1:8080"}}})
    );
    let items = by_id["3"]["result"]["Items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    // A3 語意：Metadata 輸出裡機密鍵根本不存在
    let list_raw = serde_json::to_string(&by_id["3"]).unwrap();
    assert!(!list_raw.contains("password") && !list_raw.contains("hunter2"));
    // credential.match：shim 以 host "github.com" 查，daemon 子串回 GitHub+Gist，
    // shim host 過濾後只剩 GitHub
    let matched = by_id["4"]["result"].as_array().unwrap();
    assert_eq!(matched.len(), 1, "{}", by_id["4"]);
    assert_eq!(matched[0]["id"], json!(GITHUB));
    assert_eq!(matched[0]["name"], json!("GitHub"));
    assert_eq!(matched[0]["uris"], json!(["https://github.com"]));
    assert!(matched[0].get("username_hint").is_some());
    assert_eq!(matched[0]["username_hint"], Value::Null);
    // credential.reveal：明文在此（政策邊界見 README）
    assert_eq!(by_id["5"]["result"]["Item"]["password"], json!("hunter2"));

    // 對映表守門：五個 method 各自落到正確的 BTP Call
    {
        let calls = daemon.calls.lock().unwrap();
        assert!(matches!(
            &calls[3],
            Call::Vault(VaultCall::List { query, view: View::Metadata })
                if query.uri.as_deref() == Some("github.com")
        ));
        assert!(matches!(
            &calls[4],
            Call::Vault(VaultCall::Get {
                view: View::Reveal,
                ..
            })
        ));
    }

    // 未知 method ⇒ 協定級 error，不斷管線
    write_nm(
        &mut stdin,
        &json!({"id": 6, "method": "nope", "params": {}}),
    )
    .await
    .unwrap();
    let resp = read_nm(&mut rx).await.unwrap().unwrap();
    assert_eq!(resp["id"], json!(6));
    assert_eq!(resp["ok"], json!(false));
    assert!(resp["error"].as_str().unwrap().contains("unknown method"));

    // stdin EOF ⇒ 乾淨結束（exit Ok）
    drop(stdin);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn btp_drop_fails_pending_and_exits() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_daemon(dir.path()).await;
    let stream = UnixStream::connect(dir.path().join("daemon.sock"))
        .await
        .unwrap();
    let bridge = Arc::new(
        Bridge::connect(stream, Auth::Session { token: "t".into() })
            .await
            .unwrap(),
    );
    // fake daemon 對 vault.list 卡住不回（hang_lists），再主動收線 ⇒ 請求仍在 pending。
    daemon.hang_lists.store(true, AtomicOrdering::SeqCst);
    let (mut host_stdin, mut rx, task) = shim(bridge);
    write_nm(
        &mut host_stdin,
        &json!({"id": 7, "method": "vault.list", "params": {}}),
    )
    .await
    .unwrap();
    // 等到 daemon 收到 call 再斷線
    while daemon.calls.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    daemon.kill.notify_waiters(); // daemon 收線 ⇒ 橋 dead ⇒ pending 必須被代答
    let resp = read_nm(&mut rx).await.unwrap().unwrap();
    assert_eq!(resp["id"], json!(7));
    assert_eq!(resp["ok"], json!(false));
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("daemon bridge closed")
    );
    let err = task.await.unwrap().unwrap_err();
    assert!(err.contains("btp bridge closed"), "{err}");
    drop(host_stdin);
}

#[tokio::test]
async fn unknown_session_re_enrolls_once() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let daemon = spawn_daemon(dir.path()).await;
    daemon.kill_sessions.store(true, AtomicOrdering::SeqCst);

    // 無存檔 token：直接 Enroll
    unsafe {
        std::env::set_var("BITWARD_SOCK", dir.path().join("daemon.sock"));
        std::env::set_var("BITWARD_DATA_DIR", &data);
    }
    let b1 = open_bridge().await.unwrap();
    drop(b1);
    let saved1 = std::fs::read_to_string(token_file(&data)).unwrap();
    assert!(!saved1.is_empty());
    {
        let hellos = daemon.hellos.lock().unwrap();
        assert_eq!(hellos.len(), 1);
        assert!(matches!(&hellos[0], Auth::Enroll { pairing, .. } if *pairing == saved1));
    }

    // daemon「重啟」：Session token 不認 ⇒ 自動重配對一次，換新 token
    daemon.kill_sessions.store(true, AtomicOrdering::SeqCst);
    let b2 = open_bridge().await.unwrap();
    drop(b2);
    let saved2 = std::fs::read_to_string(token_file(&data)).unwrap();
    assert_ne!(saved1, saved2, "重配對必須換 pairing");
    let hellos = daemon.hellos.lock().unwrap();
    // 被拒的 Session 不進 hellos（daemon 在註冊前收線）：兩次成功都是 Enroll。
    assert_eq!(hellos.len(), 2, "Enroll → (Session 拒) → Enroll");
    assert!(matches!(&hellos[1], Auth::Enroll { pairing, .. } if *pairing == saved2));
}

#[test]
fn manifest_chrome_content() {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::path::Path::new("/opt/bitward/bin/bitward-nm");
    let id = "mmlebeeagmflhgobbnpljgnhbncpffec";
    let path = install(Browser::Chrome, id, Some(dir.path()), exe).unwrap();
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        format!("{HOST_NAME}.json")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        v,
        json!({
            "name": "com.bitward.client",
            "description": "bitward bridge",
            "path": "/opt/bitward/bin/bitward-nm",
            "type": "stdio",
            "allowed_origins": ["chrome-extension://mmlebeeagmflhgobbnpljgnhbncpffec/"],
        })
    );
    assert_eq!(
        chrome_origin("chrome-extension://abc"),
        "chrome-extension://abc/"
    );
}

#[test]
fn manifest_firefox_content_and_bad_id() {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::path::Path::new("/usr/local/bin/bitward-nm");
    let v = manifest_value(Browser::Firefox, exe, "bitward@example.com");
    assert_eq!(v["allowed_extensions"], json!(["bitward@example.com"]));
    assert!(v.get("allowed_origins").is_none());
    let path = install(
        Browser::Firefox,
        "bitward@example.com",
        Some(dir.path()),
        exe,
    )
    .unwrap();
    assert!(path.exists());
    assert!(install(Browser::Chrome, " ", Some(dir.path()), exe).is_err());
}
