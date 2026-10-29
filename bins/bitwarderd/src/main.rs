//! bitwarderd：每裝置唯一的中樞（契約 §1）。
//! main = 傳輸與 session 生命週期；業務分派在 hub.rs。

mod arena;
mod hub;
mod sync;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use clap::Parser;
use tokio::net::UnixListener;
use uuid::Uuid;

use bw_btp::{read_client, write_server};
use bw_keys::UnlockEvent;
use bw_proto::{
    Auth, ClientMsg, PROTO_VERSION, Response, ServerMsg, SessionId, SessionToken, WtpError,
};
use bw_store::SessionRow;
use hub::Hub;

#[derive(Parser)]
#[command(name = "bitwarderd", version, about = "bitward hub daemon")]
struct Args {
    /// 資料目錄（vault.db、keys/、account.json）
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// BTP unix socket 路徑（預設 <data_dir>/daemon.sock）
    #[arg(long)]
    sock: Option<PathBuf>,
}

fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return d.into();
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitward")
}

struct LiveSession {
    row: SessionRow,
    /// 只由 lock/漂移的 Revoked 事件翻轉（A6：unlock 的 epoch bump 不撤銷既有 session）
    revoked: bool,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let args = Args::parse();
    if !arena::init() {
        eprintln!("warning: secret arena inactive (mlock unavailable)");
    }
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    let sock = args.sock.unwrap_or_else(|| data_dir.join("daemon.sock"));
    std::fs::create_dir_all(data_dir.join("run")).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&sock);
    let hub = Hub::open(&data_dir).await?;
    let listener = UnixListener::bind(&sock).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    tracing::info!(sock = %sock.display(), "bitwarderd listening");

    let sessions: Arc<Mutex<HashMap<SessionToken, LiveSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // drain：觸發式 + 5 秒兜底輪（離線重試與租約過期回收）
    {
        let hub_a = hub.clone();
        tokio::spawn(async move {
            let mut rx = hub_a.drain_rx.lock().await.take().expect("drain rx once");
            while rx.recv().await.is_some() {
                hub_a.drain_until_idle().await;
            }
        });
        let hub2 = hub.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if hub2.store.depth().map(|d| d.total > 0).unwrap_or(false) {
                    hub2.drain_until_idle().await;
                }
            }
        });
    }
    // notifications：多中樞收斂（§1.1 targeted pull）
    {
        let hub = hub.clone();
        tokio::spawn(async move { hub.notify_loop().await });
    }

    // 級聯撤銷：鎖世代推進 ⇒ 綁舊 epoch 的 session 全滅（§2.2、A6）。
    {
        let hub = hub.clone();
        let sessions = sessions.clone();
        let mut watch = hub.machine.watch();
        tokio::spawn(async move {
            while let Ok(ev) = watch.recv().await {
                if let UnlockEvent::Revoked { epoch, .. } = ev {
                    // 鎖世代推進 ⇒ 事件之前存在的所有 session 撤銷；
                    // 之後 Enroll 的（含 AuthLocked 期間）不受影響。
                    let _ = hub.store.sessions_revoke_before(epoch.0);
                    for s in sessions.lock().unwrap().values_mut() {
                        if s.row.epoch < epoch.0 {
                            s.revoked = true;
                        }
                    }
                }
            }
        });
    }
    // vault timeout 心跳（idle + hard 雙軌，§2.2）。
    {
        let hub = hub.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if hub.machine.check_timeout() {
                    let _ = hub.store.sessions_revoke_before(hub.machine.epoch().0);
                }
            }
        });
    }

    loop {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let hub = hub.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, hub, sessions).await {
                tracing::debug!(err = %e, "conn ended");
            }
        });
    }
}

async fn serve_conn(
    stream: tokio::net::UnixStream,
    hub: Arc<Hub>,
    sessions: Arc<Mutex<HashMap<SessionToken, LiveSession>>>,
) -> Result<(), WtpError> {
    let peer_uid = bw_btp::peer_uid_from_fd(stream.as_raw_fd()).map_err(|_| WtpError::Denied {
        grant_gap: "peer uid unavailable".into(),
    })?;
    if peer_uid != unsafe { libc::geteuid() } {
        return Err(WtpError::Denied {
            grant_gap: "peer uid != daemon uid".into(),
        });
    }
    let (mut rd, mut wr) = stream.into_split();
    let hello = tokio::time::timeout(std::time::Duration::from_secs(10), read_client(&mut rd))
        .await
        .map_err(|_| WtpError::RetryAfter { ms: 0 })?
        .map_err(|_| WtpError::Denied {
            grant_gap: "hello unreadable".into(),
        })?;
    let ClientMsg::Hello {
        version,
        auth,
        wants,
    } = hello
    else {
        return Err(WtpError::Denied {
            grant_gap: "first message must be Hello".into(),
        });
    };
    if version.0 > PROTO_VERSION {
        return Err(WtpError::Unsupported {
            feature: format!("peer proto {} > daemon {PROTO_VERSION}", version.0),
        });
    }
    let token = match auth {
        Auth::Enroll {
            display_name,
            pairing,
        } => {
            let sid = SessionId(Uuid::new_v4());
            let row = SessionRow {
                id: sid.0.to_string(),
                principal: serde_json::json!({"kind": "local", "uid": peer_uid, "name": display_name}),
                grants: serde_json::json!(["*"]), // P1 全權佔位（§5.4）
                epoch: hub.machine.epoch().0,
                state: bw_store::SessionState::Active,
                created_at: hub.store.now_ms(),
                expires_at: None,
            };
            let token = if pairing.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                pairing.clone()
            };
            sessions.lock().unwrap().insert(
                token.clone(),
                LiveSession {
                    row: row.clone(),
                    revoked: false,
                },
            );
            let _ = hub.store.session_put(&row);
            token
        }
        Auth::Session { token } => {
            if !sessions.lock().unwrap().contains_key(&token) {
                return Err(WtpError::Denied {
                    grant_gap: "unknown session".into(),
                });
            }
            token
        }
        Auth::Resume { .. } => {
            return Err(WtpError::Unsupported {
                feature: "Resume 在 P2".into(),
            });
        }
    };

    write_server(
        &mut wr,
        &ServerMsg::Welcome {
            proto: PROTO_VERSION,
            epoch: hub.machine.epoch().0,
            server: hub.server_profile().await,
            state: hub.machine.state(),
            events_from: hub.store.cursor().unwrap_or(0),
        },
    )
    .await
    .map_err(|_| WtpError::Denied {
        grant_gap: "write".into(),
    })?;

    let mut ev_rx = if wants.is_empty() {
        None
    } else {
        Some(hub.events.subscribe())
    };

    loop {
        let recv = read_client(&mut rd);
        tokio::pin!(recv);
        tokio::select! {
            msg = &mut recv => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                };
                match msg {
                    ClientMsg::Invoke { rid, call } => {
                        // 撤銷只看 lock 事件（A6）；unlock 的 epoch bump 不殺既有 session
                        let (revoked, bound) = sessions
                            .lock()
                            .unwrap()
                            .get(&token)
                            .map(|s| (s.revoked, s.row.epoch))
                            .ok_or(WtpError::Denied {
                                grant_gap: "session dropped".into(),
                            })?;
                        let now = hub.machine.epoch();
                        let outcome = if revoked {
                            Err(WtpError::StaleEpoch {
                                seen: bound,
                                now: now.0,
                            })
                        } else {
                            hub.dispatch(&token, &call).await
                        };
                        if write_server(&mut wr, &ServerMsg::Reply { rid, outcome })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    ClientMsg::Pull { cursor } => {
                        // P2：事件歷史重播在 P3 補（目前 Pull 回游標確認）
                        let _seq = hub.store.cursor().unwrap_or(cursor);
                        if write_server(&mut wr, &ServerMsg::Reply { rid: 0, outcome: Ok(Response::Status(hub.status_info().await)) }).await.is_err() {
                            return Ok(());
                        }
                    }
                    ClientMsg::Cancel { .. } | ClientMsg::Hello { .. } => {}
                }
            }
            ev = async {
                match ev_rx.as_mut() {
                    Some(r) => r.recv().await.ok(),
                    None => std::future::pending::<Option<_>>().await,
                }
            } => {
                if let Some((topic, payload)) = ev {
                    let seq = hub.store.cursor().unwrap_or(0);
                    if write_server(
                        &mut wr,
                        &ServerMsg::Event {
                            topic,
                            seq,
                            payload,
                        },
                    )
                    .await
                    .is_err()
                    {
                        return Ok(());
                    }
                }
            }
        }
    }
}

impl Hub {
    /// Welcome 用：回 cache 的 profile，不觸發網路探測。
    async fn server_profile(&self) -> bw_proto::ServerProfile {
        let g = self.server.read().await;
        match g.as_ref() {
            Some(h) => h.client.cached_probe().await.profile,
            None => bw_proto::ServerProfile {
                kind: bw_proto::ServerKind::Unknown,
                version: None,
                features: vec![],
            },
        }
    }
}
