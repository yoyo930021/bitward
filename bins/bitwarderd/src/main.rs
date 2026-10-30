//! bitwarderd：每裝置唯一的中樞（契約 §1）。
//! main = 傳輸與 session 生命週期；業務分派在 hub.rs。

mod agent;
mod arena;
mod datamanage;
mod hub;
mod sync;

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use clap::Parser;
use tokio::net::UnixListener;
use uuid::Uuid;

use bw_btp::{read_client, write_server};
use bw_keys::UnlockEvent;
use bw_proto::{Auth, ClientMsg, PROTO_VERSION, Response, ServerMsg, WtpError};
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
    /// 跨機 BTP over TLS 監聽位址（self-signed，pin 由 pair start 顯示）
    #[arg(long)]
    listen: Option<String>,
    /// ntfy 信令 URL（核准/喚醒通知；只傳不透明信令）
    #[arg(long)]
    ntfy: Option<String>,
    /// macOS：在 app group 容器內多綁一個 BTP socket（provider extension 用）
    #[arg(long)]
    push_app_group: Option<String>,
}

fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return d.into();
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitward")
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
    let hub = Hub::open(&data_dir, args.ntfy.clone()).await?;
    let listener = UnixListener::bind(&sock).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    tracing::info!(sock = %sock.display(), "bitwarderd listening");

    // 跨機 TLS listener（§1.2）：身分持久化 ⇒ pin 穩定
    if let Some(addr) = args.listen.clone() {
        let id = bw_btp::tls::load_or_create(&data_dir).map_err(|e| e.to_string())?;
        let _ = hub.tls_pin.set(id.spki_pin.clone());
        let acceptor = tokio_rustls::TlsAcceptor::from(bw_btp::tls::server_config(&id).unwrap());
        let tcp = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(%addr, pin = %id.spki_pin, "bitwarderd TLS listening");
        let hub = hub.clone();
        tokio::spawn(async move {
            loop {
                match tcp.accept().await {
                    Ok((sock, _)) => {
                        let hub = hub.clone();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            match bw_btp::tls::accept(&acceptor, sock).await {
                                Ok(tls) => {
                                    let (rd, wr) = tokio::io::split(tls);
                                    if let Err(e) = serve_conn(rd, wr, hub, None).await {
                                        tracing::debug!(err = %e, "tls conn ended");
                                    }
                                }
                                Err(e) => tracing::warn!(err = %e, "TLS handshake failed"),
                            }
                        });
                    }
                    Err(e) => tracing::warn!(err = %e, "tcp accept"),
                }
            }
        });
    }

    // macOS provider：app group 容器內多綁一條 UDS（§1.4，Xcode worker 依賴）
    #[cfg(target_os = "macos")]
    if let Some(group) = args.push_app_group.clone() {
        let base = dirs::home_dir().unwrap_or_default();
        let group_dir = base.join("Library/Group Containers").join(&group);
        if std::fs::create_dir_all(&group_dir).is_ok() {
            let gsock = group_dir.join("daemon.sock");
            let _ = std::fs::remove_file(&gsock);
            match UnixListener::bind(&gsock) {
                Ok(gl) => {
                    tracing::info!(sock = %gsock.display(), "bitwarderd app-group socket listening");
                    let hub = hub.clone();
                    tokio::spawn(async move {
                        loop {
                            if let Ok((stream, _)) = gl.accept().await {
                                let hub = hub.clone();
                                tokio::spawn(async move {
                                    let uid = bw_btp::peer_uid_from_fd(stream.as_raw_fd()).ok();
                                    let (rd, wr) = stream.into_split();
                                    if let Err(e) = serve_conn(rd, wr, hub, uid).await {
                                        tracing::debug!(err = %e, "group conn ended");
                                    }
                                });
                            }
                        }
                    });
                }
                Err(e) => tracing::warn!(err = %e, "app-group socket bind failed"),
            }
        }
    }

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
                // 通知是 fire-and-forget：斷線期間的事件永久錯過，30 秒週期 sync 兜底
                if hub2.machine.is_unlocked()
                    && hub2.machine.egress_online()
                    && hub2.store.now_ms()
                        - hub2.last_sync_ms.load(std::sync::atomic::Ordering::Relaxed)
                        > 30_000
                {
                    let _ = hub2.sync_now().await;
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
        let mut watch = hub.machine.watch();
        tokio::spawn(async move {
            while let Ok(ev) = watch.recv().await {
                if let UnlockEvent::Revoked { epoch, .. } = ev {
                    // 鎖世代推進 ⇒ 事件之前存在的所有 session 撤銷；
                    // 之後 Enroll 的（含 AuthLocked 期間）不受影響。
                    let _ = hub.store.sessions_revoke_before(epoch.0);
                    for s in hub.sessions.lock().unwrap().values_mut() {
                        if s.row.epoch < epoch.0 {
                            s.revoked.store(true, std::sync::atomic::Ordering::Relaxed);
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
        tokio::spawn(async move {
            let uid = bw_btp::peer_uid_from_fd(stream.as_raw_fd()).ok();
            let (rd, wr) = stream.into_split();
            if let Err(e) = serve_conn(rd, wr, hub, uid).await {
                tracing::debug!(err = %e, "conn ended");
            }
        });
    }
}

type BoxRd = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxWr = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

async fn serve_conn<R, W>(
    rd: R,
    wr: W,
    hub: Arc<Hub>,
    local_uid: Option<u32>,
) -> Result<(), WtpError>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut rd: BoxRd = Box::new(rd);
    let mut wr: BoxWr = Box::new(wr);
    if let Some(uid) = local_uid
        && uid != unsafe { libc::geteuid() }
    {
        return Err(WtpError::Denied {
            grant_gap: "peer uid != daemon uid".into(),
        });
    }
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
    let sess = match auth {
        Auth::Enroll {
            display_name,
            pairing,
            pair_code,
        } => {
            // 本機 UDS 的 Enroll = Interactive 全權；TLS 連線必須帶配對碼（§1.2）
            let token = if pairing.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                pairing.clone()
            };
            match pair_code {
                None => {
                    if local_uid.is_none() {
                        return Err(WtpError::Denied {
                            grant_gap: "跨機連線需要配對碼".into(),
                        });
                    }
                    hub.new_session(
                        token,
                        crate::agent::SessionKind::Interactive,
                        bw_agent::GrantSet::default_full(),
                        None,
                        serde_json::json!({"kind": "local", "uid": local_uid, "name": display_name}),
                    )
                }
                Some(code) => match hub.consume_pairing(&code) {
                    Some(spec) => {
                        let expires = hub.store.now_ms() + spec.ttl_secs * 1000;
                        hub.new_session(
                            token,
                            crate::agent::SessionKind::Device,
                            spec.grants,
                            Some(expires),
                            serde_json::json!({"kind": "device", "name": spec.name}),
                        )
                    }
                    None => {
                        return Err(WtpError::Denied {
                            grant_gap: "配對碼無效或已過期".into(),
                        });
                    }
                },
            }
        }
        Auth::Session { token } => {
            hub.sessions
                .lock()
                .unwrap()
                .get(&token)
                .cloned()
                .ok_or(WtpError::Denied {
                    grant_gap: "unknown session".into(),
                })?
        }
        Auth::Resume { .. } => {
            return Err(WtpError::Unsupported {
                feature: "Resume 在 P4".into(),
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
                        let revoked = sess.revoked.load(std::sync::atomic::Ordering::Relaxed);
                        let now = hub.machine.epoch();
                        let outcome = if revoked {
                            Err(WtpError::StaleEpoch {
                                seen: sess.row.epoch,
                                now: now.0,
                            })
                        } else {
                            hub.dispatch(&sess, &call).await
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
