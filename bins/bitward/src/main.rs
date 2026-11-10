//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! 輸出契約：`--json` 的 metadata 路徑結構上不含機密鍵（A3）；
//! 密碼輸入走 stdin/旗標轉 stdin，不進 argv（A11）。

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use uuid::Uuid;

use bw_btp::{read_server, write_client};
use bw_proto::{
    AdminCall, AgentCall, Auth, AuthCall, Call, CipherDraft, CipherField, CipherFieldKind,
    ClientMsg, FieldEdit, FillCall, ImportItem, ItemId, ItemKind, ItemView, MutationId,
    OverlayOpWire, PROTO_VERSION, PasskeyCall, ProtoVersion, Query, Resolution, Response,
    ServerMsg, SessionToken, Settings, SortKey, SyncCall, TwoFactorInput, TwoFactorProviderInfo,
    UseCall, VaultCall, View, WtpError,
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
        /// 從 stdin 讀主密碼（第一行；pinentry 式）。帳號開 2FA 時，
        /// 同一流依序再收「因子編號、6 位驗證碼」兩行（提示走 stderr）。
        #[arg(long)]
        password_stdin: bool,
    },
    Unlock,
    Lock,
    /// 改主密碼：stdin 依序讀入現有、新主密碼兩行（A11：密碼不進 argv）
    ChangePassword,
    Status,
    /// 本機設定（macOS 設定面）：自動鎖定／剪貼簿清除／重啟鎖定／鎖定清搜尋
    Settings {
        #[command(subcommand)]
        cmd: SettingsCmd,
    },
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
        /// 只列已封存項目（默認排除封存；官方 archivedDate 語意）
        #[arg(long)]
        archived: bool,
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
        /// 自訂 boolean 欄 `k=v`（v ∈ true|false），可重複
        #[arg(long = "field?")]
        bool_fields: Vec<String>,
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
        /// `path=value`，可重複。path ∈ name|notes|username|password|totp|uri.<n>|favorite|folderId|field.<n>.name|field.<n>.value|field.<n>.type
        #[arg(long = "set")]
        sets: Vec<String>,
        /// 改自訂欄型別 `<index>=<text|hidden|boolean>`，可重複。
        /// 官方語意 type 改動連帶整欄重加密：與另一端同欄的值改動判同欄衝突。
        #[arg(long = "set-type")]
        set_types: Vec<String>,
        /// 附加自訂文字欄 `k=v`，可重複
        #[arg(long = "append-field")]
        appends: Vec<String>,
        /// 附加 hidden 欄 `k=v`，可重複
        #[arg(long = "append-field!")]
        appends_hidden: Vec<String>,
        /// 附加自訂欄 `k=true|false`，可重複
        #[arg(long = "append-field?")]
        appends_bool: Vec<String>,
        /// 移除自訂欄（0 起 index），可重複
        #[arg(long = "remove-field")]
        removes: Vec<u32>,
        /// 附加網址列（官方形態新列 match=null），可重複
        #[arg(long = "append-uri")]
        append_uris: Vec<String>,
        /// 移除網址列（0 起 index），可重複
        #[arg(long = "remove-uri")]
        remove_uris: Vec<u32>,
        /// 改網址列判定 `<index>=<null|0..5>`，可重複（官方 `login.uris[].match`：
        /// null=預設、0=網域、1=網域＋子域、2=開頭符合、3=精確、4=正規表達式、5=永不）
        #[arg(long = "set-uri-match")]
        set_uri_matches: Vec<String>,
        /// 清除欄位，可重複
        #[arg(long = "clear")]
        clears: Vec<String>,
        /// 密碼類新值改由 stdin 讀（搭配 --secret-stdin）
        #[arg(long)]
        secret_stdin: bool,
    },
    /// 批次匯入未加密 JSON（官方匯出形態或本 CLI 欄位形態；單交易全收或全拒）
    Import {
        /// 檔案路徑或 `-`＝stdin。明文欄位走 UDS/TLS 本機線（A11：不落 argv）
        file: String,
        /// 官方 `bw import` 格式參數佔位（本批 true/false 語意相同）
        #[arg(long)]
        format: bool,
    },
    /// 封存／取消封存（官方 archivedDate 語意：主列表預設排除已封存）
    Archive {
        id: String,
        /// true＝封存（預設）、false＝取消封存
        #[arg(default_value = "true")]
        on: String,
    },
    /// 取網站圖示（daemon 代理＋7 天快取；`-`＝stdout。404＝server 無 icons）
    Icon {
        host: String,
        out: String,
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
    /// 附件（VW 免費開放；內容加密以附件金鑰、元資料鏡像隨 /sync）
    Attach {
        #[command(subcommand)]
        cmd: AttachCmd,
    },
    /// 本地 overlay 標籤（FR 132）
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    /// 去重報告（同 host+username 群集）
    Dupes,
    /// 報告儀表板（重用密碼／弱密碼／項目歷史）
    Reports {
        /// reuse | weak | history
        what: String,
        /// history 的項目 id（其餘子命令忽略）
        #[arg(long)]
        id: Option<String>,
    },
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
enum AttachCmd {
    /// 上傳檔案（≤32MiB；離線自動入佇列收斂）
    Add {
        item: String,
        path: String,
    },
    /// 列附件（元資料；需解鎖——檔名是信封字串）
    Ls {
        item: String,
    },
    /// 下載到檔案（`-`＝stdout）
    Get {
        item: String,
        #[arg(name = "ATT_ID")]
        att_id: String,
        out: String,
    },
    /// 刪除附件（需線上；見 daemon 語意）
    Rm {
        item: String,
        #[arg(name = "ATT_ID")]
        att_id: String,
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
enum SettingsCmd {
    /// 讀取現行設定（輸出 Settings JSON）
    Show,
    /// 寫入設定：`<payload>` 為 Settings 形態 JSON，缺欄＝官方預設
    Set { payload: String },
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
    /// 刪除單條憑證（鏡像＋伺服器 fido2Credentials 同步收斂）
    Rm {
        /// 憑證所在項目 id（`bitward passkey ls --json` 的 item 歸屬）
        item: String,
        /// b64url credentialId
        credential: String,
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
    write_client(&mut wr, &ClientMsg::Invoke { rid, call: call.clone() })
        .await
        .map_err(|e| e.to_string())?;
    let mut reply = await_reply(&mut rd, rid).await?;
    if matches!(args.cmd, Cmd::Login { .. }) {
        reply = login_2fa_rounds(&mut rd, &mut wr, &call, reply, rid).await?;
    }
    match reply {
        Ok(resp) => {
            // 二進位出口統一落檔：附件下載與圖示代理同形（AttachmentBytes）
            let bin_out = match &args.cmd {
                Cmd::Attach {
                    cmd: AttachCmd::Get { out, .. },
                }
                | Cmd::Icon { out, .. } => Some(out.clone()),
                _ => None,
            };
            if let (Some(out), Response::AttachmentBytes(bytes)) = (&bin_out, &resp) {
                // 附件內容寫檔不走 stdout（二進位；`-`＝stdout 供管線）
                if out == "-" {
                    use std::io::Write as _;
                    std::io::stdout().write_all(bytes).map_err(|e| e.to_string())?;
                } else {
                    std::fs::write(out, bytes).map_err(|e| format!("寫檔失敗：{e}"))?;
                    println!("ok ({} bytes)", bytes.len());
                }
                return Ok(());
            }
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

type BoxRd = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxWr = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
type Reply = Result<Response, WtpError>;

async fn await_reply(rd: &mut BoxRd, rid: u64) -> Result<Reply, String> {
    loop {
        match read_server(rd).await.map_err(|e| e.to_string())? {
            ServerMsg::Reply { rid: r, outcome } if r == rid => return Ok(outcome),
            ServerMsg::Event { .. } => continue,
            other => return Err(format!("unexpected {other:?}")),
        }
    }
}

/// 登入 2FA 回合：daemon 回 TwoFactorRequest → stderr 列因子、stdin 收
/// 「因子編號＋6 位碼」→ 原樣重發 Login（password 再送一次，hash 由 daemon
/// 重算；本機線明文紀律同第一步）。碼錯時 VW 回「Invalid TOTP code」錯誤
/// （非新挑戰）→ 原樣返回讓末段顯示原文，使用者重跑 login 即可。
async fn login_2fa_rounds(
    rd: &mut BoxRd,
    wr: &mut BoxWr,
    first: &Call,
    reply: Reply,
    mut rid: u64,
) -> Result<Reply, String> {
    let mut reply = reply;
    let Call::Auth(AuthCall::Login {
        server,
        email,
        password,
        api_key,
        ..
    }) = first
    else {
        unreachable!("login_2fa_rounds 只接 Login call");
    };
    for _ in 0..5 {
        let providers = match &reply {
            Ok(Response::TwoFactorRequest { providers }) if !providers.is_empty() => {
                providers.clone()
            }
            _ => return Ok(reply),
        };
        eprintln!("此帳號需要第二因子驗證。可用因子：");
        for p in &providers {
            let gate = if TwoFactorProviderInfo::is_supported(p.provider) {
                String::new()
            } else {
                "（此因子尚未支援）".to_owned()
            };
            let hint = p
                .hint
                .as_deref()
                .map(|h| format!("：{h}"))
                .unwrap_or_default();
            eprintln!(
                "  [{}] {}{hint}{gate}",
                p.provider,
                TwoFactorProviderInfo::label(p.provider)
            );
        }
        let default = providers
            .iter()
            .find(|p| TwoFactorProviderInfo::is_supported(p.provider))
            .map(|p| p.provider);
        match default {
            Some(d) => eprintln!("選擇因子編號（預設 {d}）："),
            None => eprintln!("選擇因子編號："),
        }
        let pick_line = read_line_stdin()?;
        let pick = match pick_line.trim() {
            "" => default,
            s => s
                .parse::<i32>()
                .ok()
                .filter(|n| providers.iter().any(|p| p.provider == *n)),
        };
        let Some(pick) = pick else {
            eprintln!("輸入無效：請輸入上面列出的因子編號");
            reply = Ok(Response::TwoFactorRequest {
                providers: providers.clone(),
            });
            continue;
        };
        if !TwoFactorProviderInfo::is_supported(pick) {
            eprintln!(
                "此因子尚未支援：{}（請改選手機驗證器或 Email）",
                TwoFactorProviderInfo::label(pick)
            );
            reply = Ok(Response::TwoFactorRequest {
                providers: providers.clone(),
            });
            continue;
        }
        eprintln!("輸入 6 位驗證碼：");
        let code = read_line_stdin()?;
        let code = code.trim().to_owned();
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            eprintln!("驗證碼格式不對：需要 6 位數字");
            reply = Ok(Response::TwoFactorRequest {
                providers: providers.clone(),
            });
            continue;
        }
        rid += 1;
        let next = Call::Auth(AuthCall::Login {
            server: server.clone(),
            email: email.clone(),
            password: password.clone(),
            api_key: api_key.clone(),
            two_factor: Some(TwoFactorInput {
                provider: pick,
                token: code,
                remember: false,
            }),
        });
        write_client(wr, &ClientMsg::Invoke { rid, call: next })
            .await
            .map_err(|e| e.to_string())?;
        reply = await_reply(rd, rid).await?;
    }
    Err("第二因子嘗試次數過多（5 次）；請重試 login".into())
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
            // 只取第一行＝主密碼；後續行留給 2FA 回合（選因子、驗證碼）。
            let pw = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            Call::Auth(AuthCall::Login {
                server: server.clone(),
                email: email.clone(),
                password: pw,
                api_key: None,
                two_factor: None,
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
        Cmd::Settings { cmd } => match cmd {
            SettingsCmd::Show => Call::Admin(AdminCall::GetSettings),
            SettingsCmd::Set { payload } => {
                let s: Settings = serde_json::from_str(payload)
                    .map_err(|e| format!("settings JSON 不通：{e}"))?;
                Call::Admin(AdminCall::SetSettings(s))
            }
        },
        Cmd::Sync => Call::Sync(SyncCall::Trigger { force: true }),
        Cmd::Ls {
            text,
            tag,
            uri,
            value,
            collection,
            folder,
            trash,
            archived,
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
                archived: archived.then_some(true),
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
            PasskeyCmd::Rm { item, credential } => Call::Passkey(PasskeyCall::DeletePasskey {
                item_id: parse_id(item)?,
                credential_id: credential.clone(),
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
            bool_fields,
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
            let mut draft_fields = parse_field_pairs(fields, CipherFieldKind::Text)?;
            draft_fields.extend(parse_field_pairs(hidden_fields, CipherFieldKind::Hidden)?);
            draft_fields.extend(parse_field_pairs(bool_fields, CipherFieldKind::Boolean)?);
            Call::Vault(VaultCall::Create {
                draft: CipherDraft {
                    kind,
                    name: name.clone(),
                    username: username.clone(),
                    password,
                    totp: totp.clone(),
                    uris: uri.clone().into_iter().collect(),
                    // CLI new 不帶判定下拉（官方新建預設 null）；GUI 建立面走 draft.uri_matches
                    uri_matches: Vec::new(),
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
        Cmd::Archive { id, on } => Call::Vault(VaultCall::SetArchived {
            id: parse_id(id)?,
            archived: match on.as_str() {
                "true" => true,
                "false" => false,
                other => return Err(format!("archive 值需 true|false，got {other}")),
            },
        }),
        Cmd::Icon { host, .. } => Call::Vault(VaultCall::GetIcon { host: host.clone() }),
        Cmd::Purge { id } => Call::Vault(VaultCall::Purge { id: parse_id(id)? }),
        Cmd::Edit {
            id,
            sets,
            set_types,
            appends,
            appends_hidden,
            appends_bool,
            removes,
            append_uris,
            remove_uris,
            set_uri_matches,
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
                edits.push(FieldEdit::Set {
                    path: path.to_owned(),
                    value: Some(value),
                });
            }
            for s in set_types {
                let (idx, kind) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set-type 需要 index=kind， got {s}"))?;
                let index = idx
                    .parse::<u32>()
                    .map_err(|_| format!("--set-type index 需為數字，got {idx}"))?;
                let kind = match kind {
                    "text" => CipherFieldKind::Text,
                    "hidden" => CipherFieldKind::Hidden,
                    "boolean" => CipherFieldKind::Boolean,
                    other => return Err(format!("--set-type 值域 text|hidden|boolean，got {other}")),
                };
                edits.push(FieldEdit::SetType { index, kind });
            }
            for (pairs, kind) in [
                (appends, CipherFieldKind::Text),
                (appends_hidden, CipherFieldKind::Hidden),
                (appends_bool, CipherFieldKind::Boolean),
            ] {
                for f in parse_field_pairs(pairs, kind)? {
                    edits.push(FieldEdit::AppendField { field: f });
                }
            }
            for r in removes {
                edits.push(FieldEdit::RemoveField { index: *r });
            }
            for u in append_uris {
                edits.push(FieldEdit::AppendUri { uri: u.clone() });
            }
            for r in remove_uris {
                edits.push(FieldEdit::RemoveUri { index: *r });
            }
            for s in set_uri_matches {
                let (idx, val) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set-uri-match 需要 index=match， got {s}"))?;
                let index = idx
                    .parse::<u32>()
                    .map_err(|_| format!("--set-uri-match index 需為數字，got {idx}"))?;
                let match_type = match val {
                    "null" => None,
                    v => Some(
                        v.parse::<u8>()
                            .map_err(|_| format!("--set-uri-match 值域 null|0..5，got {val}"))?,
                    ),
                };
                edits.push(FieldEdit::SetUriMatch { index, match_type });
            }
            for c in clears {
                edits.push(FieldEdit::Set {
                    path: c.clone(),
                    value: None,
                });
            }
            Call::Vault(VaultCall::Patch {
                id: parse_id(id)?,
                edits,
            })
        }
        Cmd::Import { file, format } => {
            let raw = if file == "-" {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            } else {
                std::fs::read_to_string(file).map_err(|e| format!("讀不到匯入檔：{e}"))?
            };
            let items = parse_import_items(&serde_json::from_str(&raw).map_err(|e| {
                format!("匯入檔需為 JSON（官方未加密匯出或本 CLI 欄位形態）：{e}")
            })?)?;
            Call::Vault(VaultCall::Import {
                items,
                format: *format,
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
        Cmd::Attach { cmd } => match cmd {
            AttachCmd::Add { item, path } => {
                let bytes = std::fs::read(path).map_err(|e| format!("讀不到附件檔：{e}"))?;
                let file_name = Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "attachment".to_owned());
                Call::Vault(VaultCall::Attachment {
                    sub: bw_proto::AttachmentOp::Upload {
                        item_id: parse_id(item)?,
                        file_name,
                        bytes,
                    },
                })
            }
            AttachCmd::Ls { item } => Call::Vault(VaultCall::Get {
                id: parse_id(item)?,
                view: View::Masked,
            }),
            AttachCmd::Get { item, att_id, .. } => Call::Vault(VaultCall::Attachment {
                sub: bw_proto::AttachmentOp::Download {
                    item_id: parse_id(item)?,
                    attachment_id: att_id.clone(),
                },
            }),
            AttachCmd::Rm { item, att_id } => Call::Vault(VaultCall::Attachment {
                sub: bw_proto::AttachmentOp::Delete {
                    item_id: parse_id(item)?,
                    attachment_id: att_id.clone(),
                },
            }),
        },
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
        Cmd::Reports { what, id } => {
            let sub = match (what.as_str(), id.as_deref()) {
                ("reuse", _) => bw_proto::Reports::PasswordReuse,
                ("weak", _) => bw_proto::Reports::WeakPasswords,
                ("history", Some(i)) => bw_proto::Reports::CipherHistory { id: parse_id(i)? },
                ("history", None) => return Err("reports history 需要 --id".into()),
                other => {
                    return Err(format!("reports 子命令值域 reuse|weak|history，got {other:?}"));
                }
            };
            Call::Vault(VaultCall::Reports { sub })
        }
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

/// `--field k=v` / `--field! k=v` / `--field? k=v`：官方自訂欄。
/// boolean 欄值域 true|false（與 jslib 同形存字串）。
fn parse_field_pairs(
    pairs: &[String],
    kind: CipherFieldKind,
) -> Result<Vec<CipherField>, String> {
    pairs
        .iter()
        .map(|s| {
            let (k, v) = s
                .split_once('=')
                .ok_or_else(|| format!("--field 需要 k=v，got {s}"))?;
            if kind == CipherFieldKind::Boolean && !matches!(v, "true" | "false") {
                return Err(format!("boolean 欄值需 true|false，got {v:?}"));
            }
            Ok(CipherField {
                name: k.to_owned(),
                value: Some(v.to_owned()),
                kind,
            })
        })
        .collect()
}

/// 匯入檔 → ImportItem 集。吃兩形態：官方未加密匯出（`{"items":[...]}`，
/// login 子物件、type 整數、uris[{uri,match}]、fields[{name,value,type}]）
/// 或本 CLI 扁平欄位形態。加密匯出（`{"encrypted":true}`）擋下。
fn parse_import_items(v: &serde_json::Value) -> Result<Vec<ImportItem>, String> {
    if v.get("encrypted").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err("加密匯出檔不支援（需先用官方 App 解出未加密 JSON）".into());
    }
    let arr = v
        .as_array()
        .cloned()
        .or_else(|| v.get("items").and_then(serde_json::Value::as_array).cloned())
        .ok_or_else(|| "需要 JSON 陣列或 {\"items\":[...]}".to_string())?;
    arr.iter().map(parse_import_item).collect()
}

fn parse_import_item(c: &serde_json::Value) -> Result<ImportItem, String> {
    let name = c
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if name.is_empty() {
        return Err("匯入項缺 name".into());
    }
    let kind = match c.get("type") {
        Some(serde_json::Value::Number(n)) => match n.as_i64().unwrap_or(1) {
            2 => ItemKind::SecureNote,
            3 | 4 => return Err(format!("Card/Identity 型別本批不支援（type {}）", n)),
            _ => ItemKind::Login,
        },
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "note" | "securenote" => ItemKind::SecureNote,
            other => return Err(format!("未知 type {other:?}")),
        },
        _ => ItemKind::Login,
    };
    // 官方匯出把帳密放 login 子物件；扁平形態直接讀頂層欄
    let login = c.get("login").cloned().unwrap_or_else(|| serde_json::json!({}));
    let pick = |key: &str| -> Option<String> {
        c.get(key)
            .or_else(|| login.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let uris = c
        .get("uris")
        .or(login.get("uris"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|u| match u {
                    serde_json::Value::String(s) => Some(s.clone()),
                    obj => obj
                        .get("uri")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default();
    // 官方匯出 uris[].match（明文整數/null）：隨列序平行帶入 draft，缺位＝None 預設
    let uri_matches: Vec<Option<u8>> = c
        .get("uris")
        .or(login.get("uris"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|u| {
                    u.get("match")
                        .and_then(serde_json::Value::as_u64)
                        .map(|m| m as u8)
                })
                .collect()
        })
        .unwrap_or_default();
    let fields = c
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let name = f.get("name").and_then(serde_json::Value::as_str)?;
                    Some(CipherField {
                        name: name.to_owned(),
                        value: f.get("value").and_then(serde_json::Value::as_str).map(str::to_owned),
                        kind: CipherFieldKind::from_wire(
                            f.get("type").and_then(serde_json::Value::as_i64).unwrap_or(0),
                        ),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let tags = c
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(ImportItem {
        draft: CipherDraft {
            kind,
            name,
            username: pick("username"),
            password: pick("password"),
            totp: pick("totp"),
            uris,
            notes: pick("notes"),
            favorite: c
                .get("favorite")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            folder_id: c
                .get("folderId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            fields,
            uri_matches,
        },
        tags,
    })
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
        // 附件位元組直出口（attach get 在 run() 已攔截寫檔；這裡是旁路觀測形態）
        Response::AttachmentBytes(v) => {
            println!("{}", json!({"bytes": v.len()}))
        }
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
        // 本機設定：扁平 Settings JSON（e2e/GUI 直讀，無外殼）
        Response::Settings(s) => {
            println!("{}", serde_json::to_string_pretty(s).unwrap());
        }
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
        let val = match (&f.value, f.kind) {
            (Some(x), _) => x.clone(),
            (None, CipherFieldKind::Hidden) => "•••".into(),
            (None, _) => String::new(),
        };
        let tag = match f.kind {
            CipherFieldKind::Text => "text",
            CipherFieldKind::Hidden => "hidden",
            CipherFieldKind::Boolean => "boolean",
        };
        out.push_str(&format!("field[{}]: {} = {val}\n", tag, f.name));
    }
    for a in &v.attachments {
        let size = match (&a.size, &a.size_name) {
            (Some(s), _) => format!("{s} B"),
            (None, Some(n)) => n.clone(),
            (None, None) => "?".into(),
        };
        out.push_str(&format!("attach: {}  {}  ({size})\n", a.id, a.file_name));
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
