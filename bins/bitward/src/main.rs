//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! 輸出契約：`--json` 的 metadata 路徑結構上不含機密鍵（A3）；
//! 密碼輸入走 stdin/旗標轉 stdin，不進 argv（A11）。

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use uuid::Uuid;

use bw_btp::{read_server, write_client};
use bw_proto::{
    AdminCall, AgentCall, Auth, AuthCall, Call, CipherDraft, CipherField, ClientMsg, FieldEdit,
    FillCall, ItemId, ItemKind, ItemView, MutationId, OverlayOpWire, PROTO_VERSION, PasskeyCall,
    ProtoVersion, Query, Resolution, Response, ServerMsg, SessionToken, SortKey, SyncCall, UseCall,
    VaultCall, View, WtpError,
};

#[derive(Parser)]
#[command(name = "bitward", version, about = "bitward thin client CLI")]
struct Args {
    #[arg(long, global = true)]
    sock: Option<PathBuf>,
    /// 輸出 JSON（機器可讀契約；ls 的 metadata 永不含 password/username 鍵）
    #[arg(long, global = true)]
    json: bool,
    /// 以跨機 device profile 連線（`pair join` 建立），值為 profile 名稱
    #[arg(long, global = true)]
    remote: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        /// "-" 或 unset ＝從 stdin 讀主密碼（pinentry 式）
        #[arg(long)]
        password_stdin: bool,
    },
    Unlock,
    Lock,
    /// 改主密碼：stdin 依序讀入現有、新主密碼兩行（A11：密碼不進 argv）
    ChangePassword,
    Status,
    Sync,
    Ls {
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        uri: Option<String>,
        /// 以密碼/帳號值精確搜尋（需曾解鎖回填索引）
        #[arg(long)]
        value: Option<String>,
        /// 只列該 collection（org 共享集合）的項目（P4b）
        #[arg(long)]
        collection: Option<String>,
        /// 只列該資料夾（UUID）；空字串＝個人未歸屬
        #[arg(long)]
        folder: Option<String>,
        /// 列垃圾桶（帶 deleted_at；默認只列未刪）
        #[arg(long)]
        trash: bool,
        #[arg(long, default_value = "name")]
        sort: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Get {
        id: String,
        #[arg(long, default_value = "metadata")]
        view: String,
    },
    Reveal {
        id: String,
    },
    Totp {
        id: String,
    },
    /// AutoType：daemon 解密後倒數 3 秒注入按鍵（明文不回程）
    Autotype {
        id: String,
        /// 模板，預設 {username}{TAB}{password}{TAB}{enter}
        #[arg(long)]
        template: Option<String>,
    },
    /// WebAuthn passkey（macOS autofill 的 daemon 端核心）
    Passkey {
        #[command(subcommand)]
        cmd: PasskeyCmd,
    },
    Audit {
        #[arg(long, default_value_t = 50)]
        tail: u32,
        #[arg(long)]
        verify: bool,
    },
    Version,
    New {
        #[arg(long)]
        name: String,
        /// 項目型別：login|note（SecureNote；card/identity 留後續批次）
        #[arg(long = "type", default_value = "login")]
        type_: String,
        #[arg(long)]
        username: Option<String>,
        /// 從 stdin 讀一行作為密碼（不進 argv，A11）
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        uri: Option<String>,
        #[arg(long)]
        totp: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// 建立時歸屬的資料夾（UUID；`bitward folder ls` 取 id）
        #[arg(long)]
        folder: Option<String>,
        /// 自訂文字欄 `k=v`，可重複
        #[arg(long = "field")]
        fields: Vec<String>,
        /// 自訂 hidden 欄 `k=v`，可重複（回程值以 ••• 代，reveal 才出）
        #[arg(long = "field!")]
        hidden_fields: Vec<String>,
    },
    /// 資料夾（官方 folders 語意：名稱 user key 加密）
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// 硬刪垃圾桶項目：本機鏡像永久移除＋伺服器 DELETE（離線拒）
    Purge {
        id: String,
    },
    Edit {
        id: String,
        /// `path=value`，可重複。path ∈ name|notes|username|password|totp|uri.<n>|favorite|folderId|field.<n>.name|field.<n>.value
        #[arg(long = "set")]
        sets: Vec<String>,
        /// 清除欄位，可重複
        #[arg(long = "clear")]
        clears: Vec<String>,
        /// 密碼類新值改由 stdin 讀（搭配 --secret-stdin）
        #[arg(long)]
        secret_stdin: bool,
    },
    Rm {
        id: String,
    },
    Restore {
        id: String,
    },
    Outbox,
    Conflicts,
    Resolve {
        id: u64,
        #[arg(long)]
        ours: bool,
        #[arg(long)]
        theirs: bool,
        #[arg(long)]
        keep_both: bool,
    },
    SignOut,
    /// 本地 overlay 標籤（FR 132）
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    /// 去重報告（同 host+username 群集）
    Dupes,
    /// 合併重複項：保留 KEEP，軟刪其餘，tags 聯集
    Merge {
        keep: String,
        dupes: Vec<String>,
    },
    /// unshare：把 org 項目移回個人 vault（FR 604）
    Unshare {
        id: String,
    },
    /// agent session 治理（人在這台機器上簽發/管理）
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// 注入 vault 機密執行命令（出口經 Redactor 淨化）
    Run {
        /// `K=btw://<uuid>/<field>` 或 `K=literal`，可重複
        #[arg(long = "env")]
        env: Vec<String>,
        #[arg(long, default_value = "")]
        cwd: String,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// 核准一個待批請求（human-in-the-loop）
    Approve {
        id: String,
        /// 追加常駐 grant（DSL），可重複
        #[arg(long = "grant")]
        grants: Vec<String>,
    },
    /// 拒絕一個待批請求：請求端立刻收到 Denied，不必等 120s 逾時
    Deny {
        id: String,
    },
    /// 跨機配對（§1.2）
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// e2e/開發用：向（自架）server 註冊新帳號，不寫入 daemon 狀態
    #[command(hide = true)]
    DevRegister {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// e2e/開發用：直接經 API 塞一筆 login cipher（繞過 P2 才有的 outbox）
    #[command(hide = true)]
    DevSeed {
        #[arg(long)]
        name: String,
        #[arg(long)]
        uri: String,
        #[arg(long)]
        password: String,
    },
}

fn session_file(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("cli_session")
}

#[derive(Subcommand)]
enum TagCmd {
    Add {
        id: String,
        tag: String,
    },
    Rm {
        id: String,
        tag: String,
    },
    Pin {
        id: String,
        #[arg(default_value = "true")]
        on: String,
    },
}

#[derive(Subcommand)]
enum FolderCmd {
    /// 列資料夾（鎖定態 name 為 null——名稱是信封字串）
    Ls,
    Create {
        name: String,
    },
    /// 刪除：夾內項目 folderId 先清 NULL（官方語意同序）
    Delete {
        id: String,
    },
}

#[derive(Subcommand)]
enum PasskeyCmd {
    /// 列 passkey（Metadata 級：只含識別欄，無密鑰材料）
    List {
        #[arg(long)]
        rp: Option<String>,
    },
    /// 註冊 passkey：預設 daemon 生成 P-256 私鑰（純軟體流）；
    /// 帶 --public-key = SE 公鑰單步流（keyValue 存 SPKI）。輸出 attestation（JSON）
    Register {
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        /// b64url challenge
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        /// 附加到既有 item（預設新建 login item）
        #[arg(long)]
        item: Option<String>,
        /// b64url DER SubjectPublicKeyInfo（Swift/SE 匯出的公鑰）
        #[arg(long)]
        public_key: Option<String>,
    },
    /// 兩步註冊·第一步：daemon 簽發 credential_id（b64url 32B，SecKey tag 用）
    BeginRegister {
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
    /// 兩步註冊·第二步：以 BeginRegister 的 id + SPKI 公鑰完成註冊（輸出 attestation JSON）
    FinishRegister {
        /// BeginRegister 回傳的 b64url credential id
        #[arg(long)]
        credential: String,
        /// b64url DER SubjectPublicKeyInfo
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
    /// 簽發 assertion（counter++ 進 outbox）。純軟體流由 daemon 自簽；
    /// 帶 --signature = 簽名校驗流（Swift 已簽，驗過才提交 counter）。
    Assert {
        #[arg(long)]
        credential: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        rp: String,
        /// b64url(32B)：Apple provider 流的 clientDataHash
        #[arg(long)]
        hash: Option<String>,
        /// b64url DER ECDSA 簽名（對 authData‖hash）
        #[arg(long)]
        signature: Option<String>,
        /// Swift 側 keychain item 標籤（不透明，隨 audit 記錄）
        #[arg(long)]
        key_id: Option<String>,
    },
    /// 兩步斷言·第一步：取本次 authData（含新 counter；不持久化）
    Begin {
        #[arg(long)]
        credential: String,
        /// b64url(32B) clientDataHash
        #[arg(long)]
        hash: String,
    },
    /// 兩步斷言·第二步：交回 DER 簽名（b64url），驗過才持久化 counter
    Finish {
        #[arg(long)]
        credential: String,
        #[arg(long)]
        signature: String,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// 全端：產生一次性配對碼
    Start {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "see:identity all")]
        grant: String,
        #[arg(long, default_value_t = 30 * 24 * 3600)]
        ttl: u64,
    },
    /// thin 端：用配對碼換長期 device token
    Join {
        /// https://host:port
        #[arg(long)]
        url: String,
        #[arg(long)]
        pin: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        name: String,
        /// ntfy 喚醒 endpoint（能力憑證，選填）
        #[arg(long)]
        wake: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    List,
    Revoke {
        code: String,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    Open {
        #[arg(long)]
        name: String,
        /// grant DSL（見 bw-agent 文件）
        #[arg(long)]
        grant: String,
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    List,
    /// 待核准佇列（回 [{"id","summary"}]）
    Pending,
    Revoke {
        id: String,
    },
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
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn open_session(
    sock: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<
    (
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
    ),
    String,
> {
    // 一次 Session 續用；被拒（daemon 重啟過）則刪檔重 Enroll 一次。
    for attempt in 0..2u8 {
        let stream = tokio::net::UnixStream::connect(sock)
            .await
            .map_err(|_| format!("連不到 daemon（{}）；先啟動 bitwarderd", sock.display()))?;
        let (mut rd, mut wr) = stream.into_split();
        let saved: Option<SessionToken> = if attempt == 0 {
            std::fs::read_to_string(session_file(data_dir))
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        let fresh = Uuid::new_v4().to_string();
        let auth = match saved {
            Some(t) => Auth::Session { token: t },
            None => Auth::Enroll {
                pairing: fresh.clone(),
                display_name: format!("cli:{}", std::process::id()),
                pair_code: None,
            },
        };
        write_client(
            &mut wr,
            &ClientMsg::Hello {
                version: ProtoVersion(PROTO_VERSION),
                auth: auth.clone(),
                wants: vec![],
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        match read_server(&mut rd).await {
            Ok(ServerMsg::Welcome { proto, .. }) => {
                if let Some(s) = proto_mismatch(proto) {
                    return Err(s);
                }
                if matches!(auth, Auth::Enroll { .. }) {
                    let _ = std::fs::write(session_file(data_dir), &fresh);
                }
                return Ok((rd, wr));
            }
            Ok(ServerMsg::Error { message }) if attempt == 0 => {
                // daemon 明確拒絕（重啟過/隨鎖撤銷）：刪檔重 Enroll 續跑，但必須留痕
                // （readpath A6 的可觀察性）——靜默癒合會把「lock＝撤銷」洗成無感成功。
                eprintln!("warning: session 失效（{message}）；已重入會（enroll）並續跑指令");
                let _ = std::fs::remove_file(session_file(data_dir));
            }
            Ok(ServerMsg::Error { message }) => return Err(message),
            Ok(other) => return Err(format!("expected Welcome, got {other:?}")),
            Err(e) if attempt == 0 => {
                // 撤銷/失效必須留痕（readpath A6 的可觀察性）：靜默重 Enroll 會把
                // 「lock 級聯撤銷」這個安全語意洗成無感成功。
                eprintln!("warning: session 失效（{e}）；已重入會（enroll）並續跑指令");
                let _ = std::fs::remove_file(session_file(data_dir));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    unreachable!()
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    match &args.cmd {
        Cmd::DevRegister {
            server,
            email,
            password_stdin,
        } => return dev_register(server, email, *password_stdin).await,
        Cmd::DevSeed {
            name,
            uri,
            password,
        } => {
            let (server, email) = seed_target(&args)?;
            return dev_seed(&server, &email, name, uri, password).await;
        }
        _ => {}
    }
    let data_dir = default_data_dir();
    if let Cmd::Pair {
        cmd: PairCmd::Join { .. },
    } = &args.cmd
    {
        return pair_join(&args, &data_dir).await;
    }
    let sock = args
        .sock
        .clone()
        .unwrap_or_else(|| data_dir.join("daemon.sock"));
    let (mut rd, mut wr): (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) = match &args.remote {
        None => {
            let (r, w) = open_session(&sock, &data_dir).await?;
            (Box::new(r), Box::new(w))
        }
        Some(profile) => open_remote(profile, &data_dir).await?,
    };

    let call = build_call(&args.cmd)?;
    if matches!(args.cmd, Cmd::Autotype { .. }) {
        // 倒數在 daemon 端跑，stderr 提示讓使用者抓時機切視窗
        eprintln!("AutoType: 準備倒數 3 秒後注入按鍵，請切到目標視窗");
    }
    let rid = 1u64;
    write_client(&mut wr, &ClientMsg::Invoke { rid, call })
        .await
        .map_err(|e| e.to_string())?;
    let reply = loop {
        match read_server(&mut rd).await.map_err(|e| e.to_string())? {
            ServerMsg::Reply { rid: r, outcome } if r == rid => break outcome,
            ServerMsg::Event { .. } => continue,
            other => return Err(format!("unexpected {other:?}")),
        }
    };
    match reply {
        Ok(resp) => {
            if matches!(args.cmd, Cmd::ChangePassword)
                && matches!(resp, Response::Ok)
                && !args.json
            {
                println!("主密碼已變更");
            } else {
                print_response(&resp, args.json);
            }
            Ok(())
        }
        Err(e) => Err(wtp_to_string(&e)),
    }
}

fn proto_mismatch(peer: u16) -> Option<String> {
    if peer > PROTO_VERSION {
        Some(format!("daemon proto {peer} > CLI {PROTO_VERSION}"))
    } else {
        None
    }
}

/// `pair join` 後的跨機身分檔：remotes/<profile>.json
#[derive(serde::Serialize, serde::Deserialize)]
struct RemoteProfile {
    url: String,
    pin: String,
    token: SessionToken,
    #[serde(default)]
    wake: Option<String>,
}

fn split_url(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "需要 https://".to_string())?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| "需要 :port".to_string())?;
    Ok((
        host.to_string(),
        port.parse::<u16>()
            .map_err(|e: std::num::ParseIntError| e.to_string())?,
    ))
}

async fn pair_join(args: &Args, data_dir: &Path) -> Result<(), String> {
    let PairCmd::Join {
        url,
        pin,
        code,
        name,
        wake,
        profile,
    } = (match &args.cmd {
        Cmd::Pair { cmd } => cmd,
        _ => unreachable!(),
    })
    else {
        unreachable!()
    };
    let (host, port) = split_url(url)?;
    let stream = bw_btp::tls::connect(&host, port, pin)
        .await
        .map_err(|e| format!("TLS 連線失敗（pin 正確？）：{e}"))?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let fresh = Uuid::new_v4().to_string();
    write_client(
        &mut wr,
        &ClientMsg::Hello {
            version: ProtoVersion(PROTO_VERSION),
            auth: Auth::Enroll {
                pairing: fresh.clone(),
                display_name: format!("remote:{name}"),
                pair_code: Some(code.clone()),
            },
            wants: vec![],
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match read_server(&mut rd).await.map_err(|e| e.to_string())? {
        ServerMsg::Welcome { .. } => {}
        ServerMsg::Reply {
            outcome: Err(e), ..
        } => return Err(format!("join 被拒：{e}")),
        other => return Err(format!("預期 Welcome，got {other:?}")),
    }
    let dir = data_dir.join("remotes");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let prof = RemoteProfile {
        url: url.clone(),
        pin: pin.clone(),
        token: fresh,
        wake: wake.clone(),
    };
    let path = dir.join(format!("{profile}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&prof).unwrap()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    println!("paired → --remote {profile} ({})", path.display());
    Ok(())
}

/// 跨機連線：HubOffline 快速失敗 + 可選 wake 信令後重試一次（§1.2）
async fn open_remote(
    profile: &str,
    data_dir: &Path,
) -> Result<
    (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ),
    String,
> {
    let path = data_dir.join("remotes").join(format!("{profile}.json"));
    let prof: RemoteProfile =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let (host, port) = split_url(&prof.url)?;
    let last_ok_path = data_dir.join(format!("remote_{profile}_last_ok"));

    for attempt in 0..2u8 {
        match try_remote(&host, port, &prof).await {
            Ok(pair) => {
                let _ = std::fs::write(&last_ok_path, chrono_now_ms().to_string());
                return Ok(pair);
            }
            Err(e) => {
                // 第一次失敗：發喚醒信令（endpoint 即能力憑證），稍後重試一次
                if attempt == 0
                    && let Some(wake) = &prof.wake
                {
                    let body = "bitward wake".to_string();
                    let url = wake.clone();
                    tokio::spawn(async move {
                        let _ = reqwest::Client::new().post(url).body(body).send().await;
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    continue;
                }
                let seen = std::fs::read_to_string(&last_ok_path).unwrap_or_default();
                return Err(format!(
                    "HubOffline（last_seen={}）：{e}",
                    if seen.is_empty() { "never" } else { &seen }
                ));
            }
        }
    }
    unreachable!()
}

async fn try_remote(
    host: &str,
    port: u16,
    prof: &RemoteProfile,
) -> Result<
    (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ),
    String,
> {
    let stream = bw_btp::tls::connect(host, port, &prof.pin)
        .await
        .map_err(|e| e.to_string())?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    write_client(
        &mut wr,
        &ClientMsg::Hello {
            version: ProtoVersion(PROTO_VERSION),
            auth: Auth::Session {
                token: prof.token.clone(),
            },
            wants: vec![],
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match read_server(&mut rd).await.map_err(|e| e.to_string())? {
        ServerMsg::Welcome { proto, .. } => {
            if let Some(s) = proto_mismatch(proto) {
                return Err(s);
            }
            Ok((Box::new(rd), Box::new(wr)))
        }
        other => Err(format!("expected Welcome, got {other:?}")),
    }
}

fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn build_call(cmd: &Cmd) -> Result<Call, String> {
    Ok(match cmd {
        Cmd::Login {
            server,
            email,
            password_stdin,
        } => {
            let pw = if *password_stdin {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                Some(s.trim_end_matches('\n').to_owned())
            } else {
                None
            };
            Call::Auth(AuthCall::Login {
                server: server.clone(),
                email: email.clone(),
                password: pw,
                api_key: None,
            })
        }
        Cmd::Unlock => Call::Auth(AuthCall::Unlock { biometric: false }),
        Cmd::Lock => Call::Auth(AuthCall::Lock),
        Cmd::ChangePassword => {
            // 提示與警告走 stderr，stdout 留給結果行（機器可讀慣例）。
            // 強度閘不在此重複實作——daemon（hub::MIN_MASTER_PASSWORD）是唯一
            // 真相源，短碼由它拒絕、錯誤原文經 Reply 回程顯示。
            eprintln!("請依序輸入現有主密碼、新主密碼（至少 12 字元）；注意：改密後其他裝置需重新登入");
            let current = read_line_stdin()?;
            let new = read_line_stdin()?;
            Call::Auth(AuthCall::ChangePassword {
                current: Some(current),
                new: Some(new),
            })
        }
        Cmd::Status => Call::Admin(AdminCall::Diagnostics),
        Cmd::Sync => Call::Sync(SyncCall::Trigger { force: true }),
        Cmd::Ls {
            text,
            tag,
            uri,
            value,
            collection,
            folder,
            trash,
            sort,
            limit,
        } => Call::Vault(VaultCall::List {
            query: Query {
                text: text.clone(),
                tag: tag.clone(),
                uri: uri.clone(),
                value: value.clone(),
                kind: None,
                sort: match sort.as_str() {
                    "updated" => SortKey::Updated,
                    "created" => SortKey::Created,
                    "used" => SortKey::Used,
                    _ => SortKey::Name,
                },
                limit: *limit,
                collection: collection.as_deref().map(parse_id).transpose()?,
                folder: folder.clone(),
                deleted: trash.then_some(true),
            },
            view: View::Metadata,
        }),
        Cmd::Get { id, view } => Call::Vault(VaultCall::Get {
            id: parse_id(id)?,
            view: match view.as_str() {
                "masked" => View::Masked,
                "reveal" => View::Reveal,
                _ => View::Metadata,
            },
        }),
        Cmd::Reveal { id } => Call::Vault(VaultCall::Get {
            id: parse_id(id)?,
            view: View::Reveal,
        }),
        Cmd::Totp { id } => Call::Use(UseCall::TotpCode { id: parse_id(id)? }),
        Cmd::Autotype { id, template } => Call::Fill(FillCall::AutoType {
            id: parse_id(id)?,
            template: template.clone(),
        }),
        Cmd::Passkey { cmd } => match cmd {
            PasskeyCmd::List { rp } => {
                Call::Passkey(PasskeyCall::GetPasskeys { rp_id: rp.clone() })
            }
            PasskeyCmd::Register {
                rp,
                user,
                challenge,
                handle,
                display,
                item,
                public_key,
            } => Call::Passkey(PasskeyCall::RegisterPasskey {
                rp_id: rp.clone(),
                challenge: challenge.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
                credential_public_key: public_key.clone(),
            }),
            PasskeyCmd::BeginRegister {
                rp,
                user,
                handle,
                display,
                item,
            } => Call::Passkey(PasskeyCall::BeginRegister {
                rp_id: rp.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
            }),
            PasskeyCmd::FinishRegister {
                credential,
                public_key,
                rp,
                user,
                challenge,
                handle,
                display,
                item,
            } => Call::Passkey(PasskeyCall::FinishRegister {
                credential_id: credential.clone(),
                credential_public_key: public_key.clone(),
                rp_id: rp.clone(),
                challenge: challenge.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
            }),
            PasskeyCmd::Assert {
                credential,
                challenge,
                rp,
                hash,
                signature,
                key_id,
            } => Call::Passkey(PasskeyCall::AssertPasskey {
                credential_id: credential.clone(),
                challenge: challenge.clone(),
                rp_id: rp.clone(),
                // CLI 走標準流（自組 JSON）；Apple provider 流由 Swift 端帶 hash。
                client_data_hash: hash.clone(),
                // Some = 簽名已在呼叫端（模擬 Swift SE 簽名路徑）
                signature: signature.clone(),
                key_id: key_id.clone(),
            }),
            PasskeyCmd::Begin { credential, hash } => Call::Passkey(PasskeyCall::BeginAssert {
                credential_id: credential.clone(),
                client_data_hash: hash.clone(),
            }),
            PasskeyCmd::Finish {
                credential,
                signature,
            } => Call::Passkey(PasskeyCall::FinishAssert {
                credential_id: credential.clone(),
                signature: signature.clone(),
            }),
        },
        Cmd::Audit { tail, verify } => {
            if *verify {
                Call::Agent(AgentCall::AuditVerify)
            } else {
                Call::Agent(AgentCall::Audit {
                    since: None,
                    limit: *tail,
                })
            }
        }
        Cmd::Version => Call::Admin(AdminCall::Version),
        Cmd::New {
            name,
            type_,
            username,
            password_stdin,
            uri,
            totp,
            notes,
            folder,
            fields,
            hidden_fields,
        } => {
            let password = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            let kind = match type_.as_str() {
                "login" => ItemKind::Login,
                "note" => ItemKind::SecureNote,
                other => {
                    return Err(format!(
                        "--type 僅支援 login|note（card/identity 留後續批次），got {other}"
                    ));
                }
            };
            let mut draft_fields = parse_field_pairs(fields, false)?;
            draft_fields.extend(parse_field_pairs(hidden_fields, true)?);
            Call::Vault(VaultCall::Create {
                draft: CipherDraft {
                    kind,
                    name: name.clone(),
                    username: username.clone(),
                    password,
                    totp: totp.clone(),
                    uris: uri.clone().into_iter().collect(),
                    notes: notes.clone(),
                    favorite: false,
                    folder_id: folder.clone(),
                    fields: draft_fields,
                },
            })
        }
        Cmd::Folder { cmd } => match cmd {
            FolderCmd::Ls => Call::Vault(VaultCall::ListFolders),
            FolderCmd::Create { name } => Call::Vault(VaultCall::CreateFolder {
                name: name.clone(),
            }),
            FolderCmd::Delete { id } => Call::Vault(VaultCall::DeleteFolder { id: parse_id(id)? }),
        },
        Cmd::Purge { id } => Call::Vault(VaultCall::Purge { id: parse_id(id)? }),
        Cmd::Edit {
            id,
            sets,
            clears,
            secret_stdin,
        } => {
            let mut edits = Vec::new();
            for s in sets {
                let (path, value) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set 需要 path=value， got {s}"))?;
                let value = if value == "-" || *secret_stdin {
                    read_line_stdin()?
                } else {
                    value.to_owned()
                };
                edits.push(FieldEdit {
                    path: path.to_owned(),
                    value: Some(value),
                });
            }
            for c in clears {
                edits.push(FieldEdit {
                    path: c.clone(),
                    value: None,
                });
            }
            Call::Vault(VaultCall::Patch {
                id: parse_id(id)?,
                edits,
            })
        }
        Cmd::Rm { id } => Call::Vault(VaultCall::Delete {
            ids: vec![parse_id(id)?],
        }),
        Cmd::Restore { id } => Call::Vault(VaultCall::Restore { id: parse_id(id)? }),
        Cmd::Outbox => Call::Sync(SyncCall::Status),
        Cmd::Conflicts => Call::Sync(SyncCall::ListConflicts),
        Cmd::Resolve {
            id,
            ours,
            theirs,
            keep_both,
        } => {
            let pick = if *ours {
                Resolution::Ours
            } else if *theirs {
                Resolution::Theirs
            } else if *keep_both {
                Resolution::KeepBoth
            } else {
                return Err("需要 --ours/--theirs/--keep-both".into());
            };
            Call::Sync(SyncCall::ResolveConflict {
                id: MutationId(*id),
                pick,
            })
        }
        Cmd::Pair { cmd } => match cmd {
            PairCmd::Start { name, grant, ttl } => Call::Auth(AuthCall::PairStart {
                name: name.clone(),
                grant: grant.clone(),
                ttl_secs: *ttl,
            }),
            PairCmd::List => Call::Auth(AuthCall::PairList),
            PairCmd::Revoke { code } => Call::Auth(AuthCall::PairRevoke { code: code.clone() }),
            PairCmd::Join { .. } => unreachable!("join 不經 daemon 分派"),
        },
        Cmd::SignOut => Call::Auth(AuthCall::SignOut),
        Cmd::Tag { cmd } => Call::Vault(VaultCall::Overlay {
            id: parse_id(match cmd {
                TagCmd::Add { id, .. } | TagCmd::Rm { id, .. } | TagCmd::Pin { id, .. } => id,
            })?,
            op: match cmd {
                TagCmd::Add { tag, .. } => OverlayOpWire::AddTag(tag.clone()),
                TagCmd::Rm { tag, .. } => OverlayOpWire::RemoveTag(tag.clone()),
                TagCmd::Pin { on, .. } => OverlayOpWire::SetPinned(on == "true"),
            },
        }),
        Cmd::Dupes => Call::Vault(VaultCall::FindDuplicates),
        Cmd::Merge { keep, dupes } => Call::Vault(VaultCall::Merge {
            keep: parse_id(keep)?,
            dupes: dupes
                .iter()
                .map(|d| parse_id(d))
                .collect::<Result<_, _>>()?,
        }),
        Cmd::Unshare { id } => Call::Vault(VaultCall::MoveToOrg {
            item: parse_id(id)?,
            org: None,
            collections: vec![],
        }),
        Cmd::Run {
            env,
            cwd,
            timeout_ms,
            argv,
        } => {
            if argv.is_empty() {
                return Err("用法：bitward run -- cmd args...".into());
            }
            Call::Use(UseCall::Run {
                plan: bw_proto::RunPlan {
                    argv: argv.clone(),
                    env: env
                        .iter()
                        .map(|e| {
                            let (k, v) = e.split_once('=').unwrap_or((e.as_str(), ""));
                            (k.to_string(), v.to_string())
                        })
                        .collect(),
                    cwd: cwd.clone(),
                    timeout_ms: *timeout_ms,
                },
            })
        }
        Cmd::Approve { id, grants } => Call::Agent(AgentCall::Approve {
            id: bw_proto::ApprovalId(parse_approval(id)?),
            grants: (!grants.is_empty()).then(|| grants.clone()),
        }),
        Cmd::Deny { id } => Call::Agent(AgentCall::Deny {
            id: bw_proto::ApprovalId(parse_approval(id)?),
        }),
        Cmd::Agent { cmd } => match cmd {
            AgentCmd::Open { name, grant, ttl } => Call::Agent(AgentCall::OpenSession {
                scopes: vec![grant.clone()],
                ttl_secs: *ttl,
                name: name.clone(),
            }),
            AgentCmd::List => Call::Agent(AgentCall::ListSessions),
            AgentCmd::Pending => Call::Agent(AgentCall::ListPending),
            AgentCmd::Revoke { id } => Call::Agent(AgentCall::Revoke {
                session: bw_proto::SessionId(parse_approval(id)?),
            }),
        },
        Cmd::DevRegister { .. } | Cmd::DevSeed { .. } => {
            unreachable!("dev 命令在連 daemon 前攔截")
        }
    })
}

fn parse_id(s: &str) -> Result<ItemId, String> {
    Uuid::parse_str(s).map_err(|e| format!("item id: {e}"))
}

/// `--field k=v` / `--field! k=v`：官方自訂欄（hidden 走 type 1 線格式）。
fn parse_field_pairs(pairs: &[String], hidden: bool) -> Result<Vec<CipherField>, String> {
    pairs
        .iter()
        .map(|s| {
            let (k, v) = s
                .split_once('=')
                .ok_or_else(|| format!("--field 需要 k=v，got {s}"))?;
            Ok(CipherField {
                name: k.to_owned(),
                value: Some(v.to_owned()),
                hidden,
            })
        })
        .collect()
}

fn parse_approval(s: &str) -> Result<Uuid, String> {
    Uuid::parse_str(s).map_err(|e| format!("approval/session id: {e}"))
}

fn print_response(resp: &Response, json: bool) {
    use serde_json::json;
    match resp {
        Response::Items(rows) => {
            if json {
                println!("{}", serde_json::to_string(rows).unwrap());
            } else {
                for r in rows {
                    let tags = if r.meta.tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", r.meta.tags.join(","))
                    };
                    let pending = if r.meta.pending { " (pending)" } else { "" };
                    println!(
                        "{}  {}{}{}",
                        r.meta.id,
                        r.meta.name.clone().unwrap_or_else(|| "…".into()),
                        tags,
                        pending
                    );
                }
            }
        }
        Response::Item(Some(v)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(v).unwrap());
            } else {
                println!("{}", format_item(v));
            }
        }
        Response::Item(None) => println!("(not found)"),
        Response::Secret(s) => println!("{s}"),
        Response::TotpCode {
            code,
            valid_for_secs,
        } => {
            if json {
                println!(
                    "{}",
                    json!({"code": code, "valid_for_secs": valid_for_secs})
                );
            } else {
                println!("{code}  ({valid_for_secs}s)");
            }
        }
        Response::Audit(rows) => {
            println!("{}", serde_json::to_string_pretty(rows).unwrap());
        }
        // AutoType 等計數類結果：扁平 JSON，無外殼（jq 直接命中 .typed）
        Response::Json(v) => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        // passkey：恆為扁平 JSON（Swift/測試端直接解析，無 --json 分支）
        Response::Passkeys(v) => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        Response::PasskeyAttestation {
            credential_id,
            attestation_object,
        } => println!(
            "{}",
            json!({"credential_id": credential_id, "attestation_object": attestation_object})
        ),
        Response::PasskeyAssertion {
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
        } => println!(
            "{}",
            json!({
                "credential_id": credential_id,
                "authenticator_data": authenticator_data,
                "client_data_json": client_data_json,
                "signature": signature,
            })
        ),
        Response::AssertBegin {
            credential_id,
            rp_id,
            authenticator_data,
            client_data_hash,
            signing_input_note,
            counter,
        } => println!(
            "{}",
            json!({
                "credential_id": credential_id,
                "rp_id": rp_id,
                "authenticator_data": authenticator_data,
                "client_data_hash": client_data_hash,
                "signing_input_note": signing_input_note,
                "counter": counter,
            })
        ),
        Response::RegisterBegin { credential_id } => {
            println!("{}", json!({"credential_id": credential_id}));
        }
        Response::Version(s) => println!("{s}"),
        Response::Profile(p) => println!("{}", json!(p)),
        Response::Ok => println!("ok"),
        // 展開 newtype variant，jq 路徑直接命中欄位（避免 {"Status":{...}} 外殼）
        Response::Status(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
        Response::Account(a) => println!("{}", serde_json::to_string_pretty(&a).unwrap()),
        Response::AuditChain(c) => println!("{}", serde_json::to_string_pretty(&c).unwrap()),
        Response::Conflicts(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Response::Sessions(v) => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        Response::DupGroups(g) => println!("{}", serde_json::to_string_pretty(g).unwrap()),
        Response::PairInfo(p) => println!("{}", serde_json::to_string_pretty(p).unwrap()),
        // agentpath.sh 依賴的扁平形狀：{"token","session","expires_at_ms"}
        Response::AgentSession {
            token,
            expires_epoch_ms,
        } => println!(
            "{}",
            serde_json::json!({"token": token, "session": token, "expires_at_ms": expires_epoch_ms})
        ),
        other => println!("{}", serde_json::to_string_pretty(other).unwrap()),
    }
}

/// 詳情頁人類可讀排版：筆記／資料夾／自訂欄（三件套）。
/// hidden 欄值缺席時以 ••• 代（daemon 未在該視窗返回值＝金鑰不可見）。
fn format_item(v: &ItemView) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}  {}\n", v.meta.id, v.meta.name.clone().unwrap_or_default()));
    out.push_str(&format!("type: {:?}\n", v.meta.kind));
    if let Some(f) = &v.meta.folder_id {
        out.push_str(&format!("folder: {f}\n"));
    }
    for u in &v.meta.uris {
        out.push_str(&format!("uri: {u}\n"));
    }
    if let Some(u) = &v.username {
        out.push_str(&format!("username: {u}\n"));
    }
    if let Some(p) = &v.password_masked {
        out.push_str(&format!("password: {p}\n"));
    }
    if let Some(p) = &v.password {
        out.push_str(&format!("password: {p}\n"));
    }
    if let Some(n) = &v.notes {
        out.push_str(&format!("notes: {n}\n"));
    }
    for f in &v.fields {
        let val = f.value.clone().unwrap_or_else(|| "•••".into());
        let tag = if f.hidden { "hidden" } else { "text" };
        out.push_str(&format!("field[{}]: {} = {val}\n", tag, f.name));
    }
    if let Some(t) = &v.meta.updated_at {
        out.push_str(&format!("updated: {t}\n"));
    }
    if v.meta.pending {
        out.push_str("(pending)\n");
    }
    out.trim_end().to_owned()
}

fn wtp_to_string(e: &WtpError) -> String {
    match e {
        WtpError::Locked => "vault 未解鎖：bitward unlock".into(),
        WtpError::StaleEpoch { seen, now } => {
            format!("session 已隨鎖世代失效（seen {seen}, now {now}）：重新執行指令即可")
        }
        other => format!("{other:?}"),
    }
}

fn read_line_stdin() -> Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    if s.is_empty() {
        return Err("stdin 為空".into());
    }
    Ok(s.trim_end_matches(['\n', '\r']).to_owned())
}

fn kdf_from_prelogin(v: &serde_json::Value) -> bw_crypto::KdfParams {
    let iterations = v
        .get("kdfIterations")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(600_000);
    if v.get("kdf").and_then(serde_json::Value::as_i64) == Some(1) {
        bw_crypto::KdfParams::Argon2id {
            m: v.get("kdfMemory")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(64) as u32,
            t: iterations as u32,
            p: v.get("kdfParallelism")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(4) as u32,
        }
    } else {
        bw_crypto::KdfParams::Pbkdf2 {
            iterations: iterations as u32,
        }
    }
}

async fn dev_register(server: &str, email: &str, _stdin: bool) -> Result<(), String> {
    use bw_server::NewAccount;
    let pw = read_line_stdin()?;
    let client = bw_server::Client::new(server).map_err(|e| e.to_string())?;
    let pre = client.prelogin(email).await.map_err(|e| e.to_string())?;
    let kdf = kdf_from_prelogin(&pre);
    let mk = bw_crypto::master_key(&pw, email, kdf).map_err(|e| e.to_string())?;
    let mph = bw_crypto::master_password_hash(&mk, &pw)
        .as_b64()
        .to_owned();
    let mut raw = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    let uk = bw_crypto::UserKey::from_bytes(raw.to_vec()).map_err(|e| e.to_string())?;
    let key = bw_crypto::encrypt_user_key(&mk, &uk).map_err(|e| e.to_string())?;
    let acc = NewAccount::new(email, "e2e dev", mph, key);
    client.register(&acc).await.map_err(|e| e.to_string())?;
    println!("registered {email}");
    Ok(())
}

fn seed_target(args: &Args) -> Result<(String, String), String> {
    let _ = args;
    let path = default_data_dir().join("account.json");
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    Ok((
        v["server"].as_str().unwrap_or_default().to_owned(),
        v["email"].as_str().unwrap_or_default().to_owned(),
    ))
}

async fn dev_seed(
    server: &str,
    email: &str,
    name: &str,
    uri: &str,
    secret: &str,
) -> Result<(), String> {
    use bw_server::PasswordLogin;
    let pw = read_line_stdin()?;
    let client = bw_server::Client::new(server).map_err(|e| e.to_string())?;
    let pre = client.prelogin(email).await.map_err(|e| e.to_string())?;
    let kdf = kdf_from_prelogin(&pre);
    let mk = bw_crypto::master_key(&pw, email, kdf).map_err(|e| e.to_string())?;
    let mph = bw_crypto::master_password_hash(&mk, &pw)
        .as_b64()
        .to_owned();
    let login = PasswordLogin::new(email, mph, "dev-seed");
    let bundle = client
        .password_login(&login)
        .await
        .map_err(|e| e.to_string())?;
    let puk = bundle.keys.and_then(|k| k.key).ok_or("token 無 Keys")?;
    let sk = bw_crypto::stretch(&mk);
    let uk = bw_crypto::decrypt_user_key(&sk, &puk).map_err(|e| e.to_string())?;
    let enc = |s: &str| {
        bw_crypto::encrypt(&uk, s)
            .map(|e| e.to_string())
            .map_err(|e| e.to_string())
    };
    let body = serde_json::json!({
        "type": 1,
        "name": enc(name)?,
        "login": {
            "username": enc("e2e-user")?,
            "password": enc(secret)?,
            "uris": [{"uri": enc(uri)?, "match": null}]
        }
    });
    let created = client
        .cipher_create(&body)
        .await
        .map_err(|e| e.to_string())?;
    println!("seeded {}", created["id"].as_str().unwrap_or("?"));
    Ok(())
}
