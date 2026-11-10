//! bitwarderd：每裝置唯一的中樞（契約 §1）。
//! main = 傳輸與 session 生命週期；業務分派在 hub.rs。

mod agent;
mod apns;
mod arena;
mod attach;
mod datamanage;
mod hub;
mod passkey;
mod sync;

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use clap::Parser;
use uuid::Uuid;

use bw_btp::{read_client, write_server};
use bw_keys::UnlockEvent;
use bw_proto::{Auth, ClientMsg, PROTO_VERSION, Response, ServerMsg, WtpError};
use hub::Hub;
mod service;

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
    /// APNs .p8 私鑰路徑（推播；需與 key/team/bundle 四者齊備才啟用）
    #[arg(long)]
    apns_p8: Option<PathBuf>,
    /// APNs Auth Key ID（.p8 對應的 Apple 金鑰 id）
    #[arg(long)]
    apns_key_id: Option<String>,
    /// APNs Team ID（開發者團隊）
    #[arg(long)]
    apns_team_id: Option<String>,
    /// APNs Bundle ID（apns-topic）
    #[arg(long)]
    apns_bundle_id: Option<String>,
    /// 用 sandbox（api.sandbox.push.apple.com）端點
    #[arg(long)]
    apns_staging: bool,
    /// macOS：在 app group 容器內多綁一個 BTP socket（provider extension 用）
    #[arg(long)]
    push_app_group: Option<String>,
    /// macOS：LaunchAgent 自管（非沙盒進程才有權限寫 LaunchAgents + launchctl）
    #[arg(long, value_enum)]
    service: Option<service::ServiceAction>,
}

pub(crate) fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return d.into();
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitward")
}

/// 真使用者 home：沙盒進程的 `$HOME` 被改寫進容器深路徑（UDS SUN_LEN 會爆），
/// getpwuid 不受影響。取不到就退回 `dirs::home_dir()`。
#[cfg(target_os = "macos")]
fn real_user_home() -> PathBuf {
    // SAFETY: pw 為 NULL 時跳過；非 NULL 時 pw_dir 為 NUL-terminated C 字串。
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() && !(*pw).pw_dir.is_null() {
            let s = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy();
            if !s.is_empty() {
                return PathBuf::from(s.into_owned());
            }
        }
    }
    dirs::home_dir().unwrap_or_default()
}

/// socket 綁定 + 單實例守衛（flock）。崩潰／kill -9 留下的屍体 sock 檔案必須
/// 清掉重綁（Make Operations Idempotent），但「先 unlink 再 bind」只有在
/// **沒有別的 live 實例**時才安全——否則第二個實例會把第一個的位址蓋掉，
/// 第二個退出後所有人拿到 ECONNREFUSED（真機實測：手工前台測試打掛 launchd
/// daemon）。故每個 socket 配一個 `.lock` 檔持有非阻塞 LOCK_EX 到程序結束。
/// flock 只擋得住有合作（會拿同一把鎖）的實例；未拿鎖的活聽者（舊版 daemon、
/// 手工起的一次性實例）由 `sock_has_live_listener` 探測補盲：連得上＝讓步不搶，
/// 連不到（ECONNREFUSED/ENOENT）＝殭屍檔 → unlink 重綁。
pub(crate) struct HeldSock {
    pub listener: tokio::net::UnixListener,
    _lock: std::fs::File,
}

/// 100ms 非阻塞 connect 探測 path 上有無活聽者。保守語意：只有明確的
/// 「無聽者」訊號（ECONNREFUSED/ENOENT/ENOTSOCK）算死；其餘（權限、逾時、
/// backlog 塞死）視為活，寧可讓步不可誤殺。
fn sock_has_live_listener(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: fd 各分支皆 close；sockaddr_un 零初始化後填 sun_path。
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return true;
        }
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            libc::close(fd);
            return false; // 超長路徑 connect 必敗；留給 bind 報原始錯誤
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let path_off = addr.sun_path.as_ptr() as usize - &addr as *const _ as usize;
        let addrlen = (path_off + bytes.len() + 1) as libc::socklen_t;
        let rc = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addrlen,
        );
        if rc == 0 {
            libc::close(fd);
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let alive = match errno {
            libc::ECONNREFUSED | libc::ENOENT | libc::ENOTSOCK => false,
            libc::EAGAIN | libc::EINPROGRESS => {
                // unix 上 EWOULDBLOCK == EAGAIN
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let n = libc::poll(&mut pfd, 1, 100);
                if n <= 0 {
                    true // 逾時/中斷：聽者可能存在只是慢，保守讓步
                } else {
                    let mut so_err: libc::c_int = 0;
                    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut so_err as *mut _ as *mut libc::c_void,
                        &mut len,
                    );
                    so_err == 0
                }
            }
            _ => true,
        };
        libc::close(fd);
        alive
    }
}

/// launchd（SMAppService）形態沒有 StandardErrorPath，stderr 日誌進不了任何
/// 檔案；綁定失敗落地 `<data_dir>/bind-error.log`（每輪覆寫＝永遠是最新現況，
/// 成功即刪除），讓「靜默沒綁上」可事後診斷（2026-11-10 實錄：group sock
/// 未建、GUI 連不上，三天無從查起）。
pub(crate) fn record_bind_error(
    data_dir: &std::path::Path,
    kind: &str,
    path: &std::path::Path,
    err: &str,
) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = std::fs::write(
        data_dir.join("bind-error.log"),
        format!("{ts} {kind} bind {} failed: {err}\n", path.display()),
    );
}

fn clear_bind_error(data_dir: &std::path::Path) {
    let _ = std::fs::remove_file(data_dir.join("bind-error.log"));
}

pub(crate) fn bind_sock(
    path: &std::path::Path,
    lock_dir: &std::path::Path,
) -> Result<HeldSock, String> {
    use std::os::unix::io::AsRawFd;
    // lock 檔放 daemon 自有目錄：group container 的策略只准 entitlement 成員建
    // 普通檔（daemon 非成員，開 lock 會 EPERM），socket 檔是例外能綁。
    std::fs::create_dir_all(lock_dir).map_err(|e| format!("lock dir: {e}"))?;
    let lock_path = lock_dir.join(
        path.file_name()
            .map(|n| format!("{}.lock", n.to_string_lossy()))
            .unwrap_or_else(|| "daemon.sock.lock".into()),
    );
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("lock open: {e}"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!("{} 已被運行中的實例佔用", path.display()));
    }
    if path.exists() {
        if sock_has_live_listener(path) {
            // 活聽者但沒拿我們的 flock（非合作實例）：讓步不搶，
            // 語意同 flock _busy_ 分支——放棄綁定＋讓呼叫端 warn。
            return Err(format!("{} 已被運行中的實例佔用", path.display()));
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // 不吞錯：EPERM（如 launchd Spawned 非成員進程碰 group container）
            // 若靜默放行，下一步就是讓人誤診的 EADDRINUSE。
            Err(e) => return Err(format!("unlink stale {}: {e}", path.display())),
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("sock dir: {e}"))?;
        // 世界可寫目錄下的 sock 要防搶佔：目錄 0700（僅本使用者可進）＋
        // sock 0600；同 uid 已是信任邊界，peer_uid 驗證兜底。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let listener = tokio::net::UnixListener::bind(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok(HeldSock {
        listener,
        _lock: lock,
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let args = Args::parse();
    if let Some(action) = args.service {
        let msg = service::run(
            action,
            std::env::current_exe().map_err(|e| e.to_string())?,
            args.push_app_group.as_deref(),
        )?;
        println!("{msg}");
        return Ok(());
    }
    if !arena::init() {
        eprintln!("warning: secret arena inactive (mlock unavailable)");
    }
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    let sock = args.sock.unwrap_or_else(|| data_dir.join("daemon.sock"));
    std::fs::create_dir_all(data_dir.join("run")).map_err(|e| e.to_string())?;
    // APNs：四參齊備才啟用；給部分 → 警告降級 None（ntfy 通道不受影響）。
    // BW_APNS_ENDPOINT 覆蓋 host（e2e mock 注入用，生產不設）。
    let apns = match (
        args.apns_p8,
        args.apns_key_id,
        args.apns_team_id,
        args.apns_bundle_id,
    ) {
        (Some(p8), Some(key_id), Some(team_id), Some(bundle_id)) => {
            let mut cfg =
                apns::ApnsConfig::load(&p8, &key_id, &team_id, &bundle_id, args.apns_staging)
                    .map_err(|e| format!("APNs: {e}"))?;
            if let Ok(ep) = std::env::var("BW_APNS_ENDPOINT") {
                cfg.endpoint = ep.trim_end_matches('/').to_owned();
                tracing::info!(endpoint = %cfg.endpoint, "APNs endpoint 由環境變數覆蓋");
            }
            Some(Arc::new(cfg))
        }
        (None, None, None, None) => None,
        _ => {
            eprintln!(
                "warning: APNs 參數不完整（--apns-p8 --apns-key-id --apns-team-id --apns-bundle-id \
                 需齊備），推播停用"
            );
            None
        }
    };
    let hub = Hub::open(&data_dir, args.ntfy.clone(), apns).await?;
    let held = match bind_sock(&sock, &data_dir) {
        Ok(h) => h,
        Err(e) => {
            record_bind_error(&data_dir, "sock", &sock, &e);
            return Err(e);
        }
    };
    let listener = held.listener;
    let _sock_guard = held._lock;
    clear_bind_error(&data_dir);
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
        // 沙盒形態（BitwardDaemon.app via SMAppService）下 $HOME 落在容器深路徑，
        // 拼出的 group sock 超過 UDS SUN_LEN(104) → bind 必掛（2026-11-08 實測
        // 「path must be shorter than SUN_LEN」）。getpwuid 回真 home，
        // 沙盒內外同值且 Group Containers 路由 app-group entitlement 放行。
        let base = real_user_home();
        let group_dir = base.join("Library/Group Containers").join(&group);
        let gsock = group_dir.join("daemon.sock");
        let data_dir_g = data_dir.clone();
        let hub_g = hub.clone();
        // 綁定失敗（如暫態 EPERM/EACCES、前實例殭屍檔擋路）不再靜默放棄：
        // 背景每 30 秒重試直到成功或 daemon 退出，並落地 bind-error.log 供
        // launchd 形態事後診斷（其 stderr 無處可去）。一行一輪，不刷屏。
        tokio::spawn(async move {
            let mut first = true;
            loop {
                let attempt = std::fs::create_dir_all(&group_dir)
                    .map_err(|e| format!("mkdir {}: {e}", group_dir.display()))
                    .and_then(|()| bind_sock(&gsock, &data_dir_g.join("run")));
                match attempt {
                    Ok(held) => {
                        let gl = held.listener;
                        let _flock_guard = held._lock; // flock 隨循環存活：第二實例無法搶佔此位址
                        clear_bind_error(&data_dir_g);
                        tracing::info!(sock = %gsock.display(), "bitwarderd app-group socket listening");
                        loop {
                            match gl.accept().await {
                                Ok((stream, _)) => {
                                    let hub = hub_g.clone();
                                    tokio::spawn(async move {
                                        let uid = bw_btp::peer_uid_from_fd(stream.as_raw_fd()).ok();
                                        let (rd, wr) = stream.into_split();
                                        if let Err(e) = serve_conn(rd, wr, hub, uid).await {
                                            tracing::debug!(err = %e, "group conn ended");
                                        }
                                    });
                                }
                                Err(e) => tracing::debug!(err = %e, "group accept"),
                            }
                        }
                    }
                    Err(e) => {
                        record_bind_error(&data_dir_g, "app-group", &gsock, &e);
                        if first {
                            tracing::warn!(err = %e, sock = %gsock.display(), "app-group socket bind failed; 30 秒後起每輪重試");
                            first = false;
                        } else {
                            tracing::info!(err = %e, "app-group socket bind 仍未成功，續重試");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                }
            }
        });
    }

    // drain：寫入即推（mpsc 觸發）＋ 背景自動推送常駐輪（退避、收斂發
    // OutboxDrained，見 sync.rs auto_drain_loop）＋ 30 秒週期 sync 兜底。
    {
        let hub_a = hub.clone();
        tokio::spawn(async move {
            let mut rx = hub_a.drain_rx.lock().await.take().expect("drain rx once");
            while rx.recv().await.is_some() {
                hub_a.drain_until_idle().await;
            }
        });
        let hub2 = hub.clone();
        tokio::spawn(async move { hub2.auto_drain_loop().await });
        let hub3 = hub.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                // 通知是 fire-and-forget：斷線期間的事件永久錯過，30 秒週期 sync 兜底
                if hub3.machine.is_unlocked()
                    && hub3.machine.egress_online()
                    && hub3.store.now_ms()
                        - hub3.last_sync_ms.load(std::sync::atomic::Ordering::Relaxed)
                        > 30_000
                {
                    let _ = hub3.sync_now().await;
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
    let auth_out: Result<_, WtpError> = 'auth: {
        let ClientMsg::Hello {
            version,
            auth,
            wants,
        } = hello
        else {
            break 'auth Err(WtpError::Denied {
                grant_gap: "first message must be Hello".into(),
            });
        };
        if version.0 > PROTO_VERSION {
            break 'auth Err(WtpError::Unsupported {
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
                            break 'auth Err(WtpError::Denied {
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
                            break 'auth Err(WtpError::Denied {
                                grant_gap: "配對碼無效或已過期".into(),
                            });
                        }
                    },
                }
            }
            Auth::Session { token } => {
                let Some(sess) = hub.sessions.lock().unwrap().get(&token).cloned() else {
                    break 'auth Err(WtpError::Denied {
                        grant_gap: "unknown session".into(),
                    });
                };
                // lock 撤銷的 session 在 Hello 就拒（A6），讓 thin 端的「重 Enroll 一次」
                // 路徑接住；拖到 Invoke 才回 StaleEpoch 会让 client 快取殭屍 token 永世復活失敗。
                if sess.revoked.load(std::sync::atomic::Ordering::Relaxed) {
                    break 'auth Err(WtpError::Denied {
                        grant_gap: "session 已隨鎖撤銷".into(),
                    });
                }
                sess
            }
            Auth::Resume { .. } => {
                break 'auth Err(WtpError::Unsupported {
                    feature: "Resume 在 P4".into(),
                });
            }
        };
        Ok((sess, wants))
    };
    let (sess, wants) = match auth_out {
        Ok(v) => v,
        // 拒絕原因必須上車（readpath A6 raw 重放的依據）：只 close 不回應，
        // thin 端會把「撤銷」誤歸因成「daemon 重啟」。
        Err(e) => {
            let _ = write_server(
                &mut wr,
                &ServerMsg::Error {
                    message: e.to_string(),
                },
            )
            .await;
            return Err(e);
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

#[cfg(test)]
mod sock_tests {
    use super::bind_sock;

    fn tmp_tagged(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bw-sock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn zombie_sock_file_self_heals_without_external_rm() {
        // kill -9 殘留：檔在（socket inode）但無聽者 → 應 unlink 重綁並可連。
        let d = tmp_tagged("zombie");
        let sock = d.join("daemon.sock");
        let stale = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        drop(stale); // std 不刪檔 → 殭屍檔
        assert!(sock.exists(), "前提：殭屍檔留下");
        let held = bind_sock(&sock, &d).expect("殭屍檔應自愈重綁");
        let _c = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::UnixStream::connect(&sock),
        )
        .await
        .expect("新聽者可連")
        .expect("connect ok");
        drop(held);
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn live_listener_without_flock_is_not_stolen() {
        // 非合作式活聽者（沒拿 flock，如舊版 daemon）：讓步不搶、原檔原位續服務。
        let d = tmp_tagged("live");
        let sock = d.join("daemon.sock");
        let foreign = tokio::net::UnixListener::bind(&sock).unwrap();
        let err = match bind_sock(&sock, &d) {
            Ok(_) => panic!("活聽者在場時不應綁成功"),
            Err(e) => e,
        };
        assert!(err.contains("佔用"), "應回報佔用而非綁定成功: {err}");
        let c = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::UnixStream::connect(&sock),
        )
        .await
        .expect("舊聽者仍佔位可連")
        .expect("connect ok");
        let (accepted, _) = tokio::time::timeout(std::time::Duration::from_millis(500), foreign.accept())
            .await
            .expect("accept 逾時")
            .expect("連線落在舊聽者而非被搶走");
        drop((c, accepted, foreign));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn probe_treats_absent_path_as_dead() {
        assert!(!super::sock_has_live_listener(std::path::Path::new(
            "/nonexistent-bw-probe/x.sock"
        )));
    }
}
