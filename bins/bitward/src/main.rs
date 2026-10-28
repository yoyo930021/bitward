//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! 輸出契約：`--json` 的 metadata 路徑結構上不含機密鍵（A3）；
//! 密碼輸入走 stdin/旗標轉 stdin，不進 argv（A11）。

use std::io::Read as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use uuid::Uuid;

use bw_btp::{read_server, write_client};
use bw_proto::{
    AdminCall, AgentCall, Auth, AuthCall, Call, ClientMsg, ItemId, PROTO_VERSION, ProtoVersion,
    Query, Response, ServerMsg, SessionToken, SortKey, SyncCall, UseCall, VaultCall, View,
    WtpError,
};

#[derive(Parser)]
#[command(name = "bitward", version, about = "bitward thin client CLI")]
struct Args {
    #[arg(long, global = true)]
    sock: Option<PathBuf>,
    /// 輸出 JSON（機器可讀契約；ls 的 metadata 永不含 password/username 鍵）
    #[arg(long, global = true)]
    json: bool,
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
    Audit {
        #[arg(long, default_value_t = 50)]
        tail: u32,
        #[arg(long)]
        verify: bool,
    },
    Version,
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
    let sock = args
        .sock
        .clone()
        .unwrap_or_else(|| data_dir.join("daemon.sock"));
    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .map_err(|_| format!("連不到 daemon（{}）；先啟動 bitwarderd", sock.display()))?;
    let (mut rd, mut wr) = stream.into_split();

    let saved: Option<SessionToken> = std::fs::read_to_string(session_file(&data_dir))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let fresh = Uuid::new_v4().to_string();
    let auth = match saved {
        Some(t) => Auth::Session { token: t },
        None => Auth::Enroll {
            // P1：token 由 CLI 生成、經配對欄位帶入，daemon 以它作 session key。
            pairing: fresh.clone(),
            display_name: format!("cli:{}", std::process::id()),
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
    match read_server(&mut rd).await.map_err(|e| e.to_string())? {
        ServerMsg::Welcome { proto, .. } => {
            if let Some(s) = proto_mismatch(proto) {
                return Err(s);
            }
        }
        other => return Err(format!("expected Welcome, got {other:?}")),
    };
    if matches!(auth, Auth::Enroll { .. }) {
        let _ = std::fs::write(session_file(&data_dir), &fresh);
    }

    let call = build_call(&args.cmd)?;
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
            sort,
            limit,
        } => Call::Vault(VaultCall::List {
            query: Query {
                text: text.clone(),
                tag: tag.clone(),
                uri: uri.clone(),
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
        Cmd::DevRegister { .. } | Cmd::DevSeed { .. } => {
            unreachable!("dev 命令在連 daemon 前攔截")
        }
    })
}

fn parse_id(s: &str) -> Result<ItemId, String> {
    Uuid::parse_str(s).map_err(|e| format!("item id: {e}"))
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
        Response::Json(v) => println!(
            "{}",
            if json {
                v.to_string()
            } else {
                serde_json::to_string_pretty(v).unwrap()
            }
        ),
        Response::Audit(rows) => {
            println!("{}", serde_json::to_string_pretty(rows).unwrap());
        }
        Response::Version(s) => println!("{s}"),
        Response::Profile(p) => println!("{}", json!(p)),
        Response::Ok => println!("ok"),
        _ => println!("{resp:?}"),
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
