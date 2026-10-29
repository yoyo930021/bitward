//! 假 daemon 整合測試：tokio UDS pair 回固定 Welcome/Reply 向量，
//! 驗 JSON-RPC framing、七工具對映、錯誤轉譯、斷線以錯結束（契約出口要求）。

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use bw_btp::{read_client, write_server};
use bw_proto::{
    ApprovalId, Auth, Call, ClientMsg, ItemKind, ItemMeta, ItemView, PROTO_VERSION, Response,
    ServerKind, ServerMsg, ServerProfile, SortKey, UnlockStateView, VaultCall, View, WtpError,
};
use uuid::Uuid;

use super::{Bridge, serve};

const ITEM_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
const APPROVAL_ID: &str = "11111111-2222-3333-4444-555555555555";

fn welcome() -> ServerMsg {
    ServerMsg::Welcome {
        proto: PROTO_VERSION,
        epoch: 7,
        server: ServerProfile {
            kind: ServerKind::Vaultwarden,
            version: Some("1.37.2".into()),
            features: vec![],
        },
        state: UnlockStateView::Unlocked {
            epoch: 7,
            deadline_epoch_ms: None,
        },
        events_from: 0,
    }
}

fn sample_item() -> ItemView {
    ItemView::metadata(ItemMeta {
        id: Uuid::parse_str(ITEM_ID).unwrap(),
        kind: ItemKind::Login,
        name: Some("agent1".into()),
        uris: vec!["https://github.com".into()],
        folder_id: None,
        organization_id: None,
        favorite: false,
        tags: vec![],
        updated_at: None,
        pending: false,
    })
}

struct Fake {
    calls: mpsc::UnboundedReceiver<ClientMsg>,
    replies: mpsc::UnboundedSender<ServerMsg>,
}

/// 假 daemon：Echo 每一條 ClientMsg 進 `calls`，Hello 自動回固定 Welcome，
/// 其餘 Reply 由測試經 `replies` 餵。Drop Fake ⇒ daemon 端斷線。
async fn fake_daemon(auth: Auth) -> (Arc<Bridge>, Fake) {
    let (mcp, daemon) = UnixStream::pair().unwrap();
    let (mut dr, mut dw) = daemon.into_split();
    let (calls_tx, calls) = mpsc::unbounded_channel();
    let (replies_tx, mut replies_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                c = read_client(&mut dr) => match c {
                    Ok(msg) => {
                        let hello = matches!(msg, ClientMsg::Hello { .. });
                        if calls_tx.send(msg).is_err() {
                            break;
                        }
                        if hello && write_server(&mut dw, &welcome()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                r = replies_rx.recv() => match r {
                    Some(m) => {
                        if write_server(&mut dw, &m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    });
    let bridge = Bridge::connect(mcp, auth).await.expect("handshake");
    (
        Arc::new(bridge),
        Fake {
            calls,
            replies: replies_tx,
        },
    )
}

struct Harness {
    serve: tokio::task::JoinHandle<Result<(), String>>,
    stdin: Option<DuplexStream>,
    stdout: BufReader<DuplexStream>,
}

impl Harness {
    fn new(bridge: Arc<Bridge>) -> Harness {
        let (stdin_tx, stdin_rx) = duplex();
        let (stdout_tx, stdout_rx) = duplex();
        let handle = tokio::spawn(async move {
            serve(
                BufReader::new(stdin_rx),
                stdout_tx,
                &bridge,
                "bitward-mcp-test",
            )
            .await
        });
        Harness {
            serve: handle,
            stdin: Some(stdin_tx),
            stdout: BufReader::new(stdout_rx),
        }
    }

    async fn send(&mut self, line: &str) {
        self.stdin
            .as_mut()
            .unwrap()
            .write_all(line.as_bytes())
            .await
            .unwrap();
        self.stdin.as_mut().unwrap().write_all(b"\n").await.unwrap();
    }

    async fn json(&mut self) -> Value {
        let mut buf = Vec::new();
        self.stdout.read_until(b'\n', &mut buf).await.unwrap();
        assert!(
            buf.ends_with(b"\n"),
            "response line must be newline-terminated"
        );
        assert_eq!(
            buf.iter().filter(|b| **b == b'\n').count(),
            1,
            "exactly one frame per line"
        );
        serde_json::from_slice(&buf).expect("valid json line")
    }

    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }
}

fn duplex() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(1 << 16)
}

fn call_line(id: u64, name: &str, args: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{args}}}}}"
    )
}

async fn next_call(fake: &mut Fake) -> (u64, Call) {
    match timeout(Duration::from_secs(5), fake.calls.recv())
        .await
        .expect("daemon call timeout")
    {
        Some(ClientMsg::Invoke { rid, call }) => (rid, call),
        Some(other) => panic!("expected Invoke, got {other:?}"),
        None => panic!("daemon channel closed"),
    }
}

async fn hello_of(fake: &mut Fake) -> ClientMsg {
    timeout(Duration::from_secs(5), fake.calls.recv())
        .await
        .expect("hello timeout")
        .expect("hello present")
}

#[tokio::test]
async fn framing_and_protocol_surface() {
    let (bridge, mut fake) = fake_daemon(Auth::Session {
        token: "tok-1".into(),
    })
    .await;
    let mut h = Harness::new(bridge);

    h.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .await;
    let r = h.json().await;
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert!(r["result"]["capabilities"]["tools"].is_object());
    assert_eq!(r["result"]["serverInfo"]["name"], "bitward-mcp-test");
    assert_eq!(
        r["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );

    // 通知不回呼：下一行必須是 ping 的回應，而非 initialized 的殘影。
    h.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    h.send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#).await;
    let r = h.json().await;
    assert_eq!(r["id"], 2);
    assert_eq!(r["result"], serde_json::json!({}));

    h.send(r#"{"jsonrpc":"2.0","id":3,"method":"bad/method"}"#)
        .await;
    let r = h.json().await;
    assert_eq!(r["error"]["code"], -32601);

    h.send("not json at all").await;
    let r = h.json().await;
    assert_eq!(r["error"]["code"], -32700);
    assert!(r["id"].is_null());

    h.send(r#"{"id":5,"method":"ping"}"#).await; // 缺 jsonrpc
    let r = h.json().await;
    assert_eq!(r["error"]["code"], -32600);

    // 握手細節：Hello 帶 Session token、wants 為空、版本相符。
    match hello_of(&mut fake).await {
        ClientMsg::Hello {
            version,
            auth,
            wants,
        } => {
            assert_eq!(version.0, PROTO_VERSION);
            assert!(matches!(auth, Auth::Session { ref token } if token == "tok-1"));
            assert!(wants.is_empty());
        }
        other => panic!("expected Hello, got {other:?}"),
    }
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn tools_list_exposes_seven_frozen_tools() {
    let (bridge, fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge);
    h.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .await;
    let r = h.json().await;
    let tools = r["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "vault_list",
            "vault_get",
            "vault_reveal",
            "totp_code",
            "run",
            "audit_tail",
            "session_whoami"
        ]
    );
    for t in tools {
        assert_eq!(t["inputSchema"]["type"], "object");
        assert!(t["description"].as_str().unwrap().len() > 20);
    }
    // 描述必須交代預設輸出與 grant 條件（任務契約明定）。
    let find = |n: &str| {
        tools.iter().find(|t| t["name"] == n).unwrap()["description"]
            .as_str()
            .unwrap()
            .to_lowercase()
    };
    assert!(find("vault_list").contains("metadata"));
    assert!(find("vault_reveal").contains("grant"));
    assert!(find("vault_reveal").contains("reveal"));
    drop(fake);
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn vault_list_round_trip_is_metadata_only() {
    let (bridge, mut fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge);
    h.send(&call_line(1, "vault_list", r#"{"text":"git"}"#))
        .await;
    let _ = hello_of(&mut fake).await;
    let (rid, call) = next_call(&mut fake).await;
    assert_eq!(rid, 1);
    match call {
        Call::Vault(VaultCall::List { query, view }) => {
            assert_eq!(view, View::Metadata);
            assert_eq!(query.text.as_deref(), Some("git"));
            assert_eq!(query.limit, 100); // 預設與 CLI 一致
            assert_eq!(query.sort, SortKey::Name);
        }
        other => panic!("{other:?}"),
    }
    fake.replies
        .send(ServerMsg::Reply {
            rid: 1,
            outcome: Ok(Response::Items(vec![sample_item()])),
        })
        .unwrap();
    let r = h.json().await;
    assert_eq!(r["result"]["isError"], false);
    assert_eq!(r["result"]["content"][0]["type"], "text");
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("agent1"));
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["Items"][0]["meta"]["name"], "agent1");
    // A3 結構保證：Metadata 視窗裡 password 鍵根本不存在。
    assert!(parsed["Items"][0]["meta"].get("password").is_none());
    assert!(parsed["Items"][0].get("password").is_none());
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn daemon_denied_becomes_tool_error_text() {
    let (bridge, mut fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge);
    h.send(&call_line(
        1,
        "vault_reveal",
        &format!(r#"{{"id":"{ITEM_ID}"}}"#),
    ))
    .await;
    let _ = hello_of(&mut fake).await;
    let (rid, call) = next_call(&mut fake).await;
    match call {
        Call::Vault(VaultCall::Get { view, .. }) => assert_eq!(view, View::Reveal),
        other => panic!("{other:?}"),
    }
    fake.replies
        .send(ServerMsg::Reply {
            rid,
            outcome: Err(WtpError::Denied {
                grant_gap: "需要 reveal:secret item:<uuid>".into(),
            }),
        })
        .unwrap();
    let r = h.json().await;
    assert_eq!(r["result"]["isError"], true);
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("授權不足"), "got {text}");
    assert!(text.contains("reveal:secret"));
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn needs_approval_text_carries_approval_uuid() {
    let (bridge, mut fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge);
    h.send(&call_line(
        1,
        "vault_reveal",
        &format!(r#"{{"id":"{ITEM_ID}","field":"password"}}"#),
    ))
    .await;
    let _ = hello_of(&mut fake).await;
    let (rid, _) = next_call(&mut fake).await;
    fake.replies
        .send(ServerMsg::Reply {
            rid,
            outcome: Err(WtpError::NeedsApproval {
                id: ApprovalId(Uuid::parse_str(APPROVAL_ID).unwrap()),
            }),
        })
        .unwrap();
    let r = h.json().await;
    assert_eq!(r["result"]["isError"], true);
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains(APPROVAL_ID),
        "id must be extractable from text: {text}"
    );
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn totp_audit_whoami_mappings() {
    let (bridge, mut fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge);

    h.send(&call_line(
        1,
        "totp_code",
        &format!(r#"{{"id":"{ITEM_ID}"}}"#),
    ))
    .await;
    let _ = hello_of(&mut fake).await;
    let (rid, call) = next_call(&mut fake).await;
    match call {
        Call::Use(bw_proto::UseCall::TotpCode { id }) => {
            assert_eq!(id.to_string(), ITEM_ID);
        }
        other => panic!("{other:?}"),
    }
    fake.replies
        .send(ServerMsg::Reply {
            rid,
            outcome: Ok(Response::TotpCode {
                code: "123456".into(),
                valid_for_secs: 30,
            }),
        })
        .unwrap();
    let r = h.json().await;
    assert_eq!(r["result"]["isError"], false);
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("123456")
    );

    h.send(&call_line(2, "audit_tail", "{}")).await;
    let (rid, call) = next_call(&mut fake).await;
    assert_eq!(rid, 2);
    match call {
        Call::Agent(bw_proto::AgentCall::Audit { since, limit }) => {
            assert!(since.is_none());
            assert_eq!(limit, 50); // 契約預設
        }
        other => panic!("{other:?}"),
    }
    fake.replies
        .send(ServerMsg::Reply {
            rid,
            outcome: Ok(Response::Audit(vec![
                serde_json::json!({"action": "Vault.List"}),
            ])),
        })
        .unwrap();
    let r = h.json().await;
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Vault.List")
    );

    h.send(&call_line(3, "session_whoami", "{}")).await;
    let (rid, call) = next_call(&mut fake).await;
    assert_eq!(rid, 3);
    assert!(matches!(call, Call::Auth(bw_proto::AuthCall::WhoAmI)));
    fake.replies
        .send(ServerMsg::Reply {
            rid,
            outcome: Ok(Response::Account(Some(bw_proto::AccountInfo {
                email: "e@x.test".into(),
                server: "http://127.0.0.1:18085".into(),
            }))),
        })
        .unwrap();
    let r = h.json().await;
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("e@x.test")
    );
    h.close_stdin();
    assert!(
        timeout(Duration::from_secs(5), &mut h.serve)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn btp_drop_ends_serve_with_error() {
    let (bridge, fake) = fake_daemon(Auth::Session { token: "t".into() }).await;
    let mut h = Harness::new(bridge.clone());
    h.send(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).await;
    let _ = h.json().await;
    // daemon 端整個消失：reader EOF → bridge dead。
    drop(fake);
    timeout(Duration::from_secs(5), &mut h.serve)
        .await
        .expect("serve must exit on btp loss")
        .expect("no panic")
        .expect_err("btp loss is a fatal error, not clean exit");
    // 死橋上的 invoke 直接回錯，不再排隊等幽靈。
    assert!(
        bridge
            .invoke(Call::Auth(bw_proto::AuthCall::WhoAmI))
            .await
            .is_err()
    );
}

#[test]
fn server_identity_follows_frozen_env_contract() {
    // 有 token：Session 續用，正名。
    let (name, auth) = super::server_identity(Some("abc"), 42, "pair".into());
    assert_eq!(name, "bitward-mcp");
    assert!(matches!(auth, Auth::Session { ref token } if token == "abc"));
    // 無 token：本機全權 Enroll，name=mcp:pid（凍結介面）。
    let (name, auth) = super::server_identity(None, 42, "pair".into());
    assert_eq!(name, "mcp:42");
    match auth {
        Auth::Enroll {
            pairing,
            display_name,
        } => {
            assert_eq!(display_name, "mcp:42");
            assert_eq!(pairing, "pair");
        }
        other => panic!("{other:?}"),
    }
}
