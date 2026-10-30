//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! 輸出契約：`--json` 的 metadata 路徑結構上不含機密鍵（A3）；
//! 密碼輸入走 stdin/旗標轉 stdin，不進 argv（A11）。

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use uuid::Uuid;

use bw_btp::{read_server, write_client};
use bw_proto::{
    AdminCall, AgentCall, Auth, AuthCall, Call, CipherDraft, ClientMsg, FieldEdit, FillCall,
    ItemId, ItemKind, MutationId, OverlayOpWire, PROTO_VERSION, ProtoVersion, Query, Resolution,
    Response, ServerMsg, SessionToken, SortKey, SyncCall, UseCall, VaultCall, View, WtpError,
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
    },
    Edit {
        id: String,
        /// `path=value`，可重複。path ∈ name|notes|username|password|totp|uri.<n>|favorite
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
            Ok(other) => return Err(format!("expected Welcome, got {other:?}")),
            Err(e) if attempt == 0 => {
                let _ = e;
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
            print_response(&resp, args.json);
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
        Cmd::Status => Call::Admin(AdminCall::Diagnostics),
        Cmd::Sync => Call::Sync(SyncCall::Trigger { force: true }),
        Cmd::Ls {
            text,
            tag,
            uri,
            value,
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
            username,
            password_stdin,
            uri,
            totp,
            notes,
        } => {
            let password = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            Call::Vault(VaultCall::Create {
                draft: CipherDraft {
                    kind: ItemKind::Login,
                    name: name.clone(),
                    username: username.clone(),
                    password,
                    totp: totp.clone(),
                    uris: uri.clone().into_iter().collect(),
                    notes: notes.clone(),
                    favorite: false,
                },
            })
        }
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
            println!(
                "{}",
                if json {
                    serde_json::to_string_pretty(v).unwrap()
                } else {
                    format!("{v:?}")
                }
            );
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
