//! bitward-nm：瀏覽器 native messaging ↔ BTP 純管道（契約 §1 進程拓撲）。
//! 零政策邏輯：授權、budget、核准、審計全在 daemon（§2.3 唯一 thin 入口 `call()`）。
//! stdin EOF ⇒ 乾淨結束；BTP 斷線 ⇒ 對所有 pending 請求回 error 後結束。

mod bridge;
mod dispatch;
mod framing;
mod manifest;
mod session;

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

use crate::bridge::Bridge;
use crate::framing::{read_nm, write_nm};

#[derive(Parser)]
#[command(
    name = "bitward-nm",
    version,
    about = "bitward browser native messaging shim"
)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 寫 native messaging manifest，印安裝路徑
    InstallManifest {
        #[arg(long, value_enum)]
        browser: manifest::Browser,
        /// Chrome: 32 位 id；Firefox: addon id（email/uuid）
        #[arg(long)]
        extension_id: String,
        /// 覆寫安裝目錄（預設依瀏覽器找本機目錄）
        #[arg(long)]
        dest: Option<std::path::PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    if let Some(Cmd::InstallManifest {
        browser,
        extension_id,
        dest,
    }) = &args.cmd
    {
        let exe = std::env::current_exe().expect("current_exe");
        return match manifest::install(*browser, extension_id, dest.as_deref(), &exe) {
            Ok(p) => {
                println!("{}", p.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("bitward-nm: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let bridge = match session::open_bridge().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("bitward-nm: {e}");
            return ExitCode::FAILURE;
        }
    };
    match serve(bridge, tokio::io::stdin(), tokio::io::stdout()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bitward-nm: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 主迴程：幀化讀請求、每請求一任務（BTP 以 rid 配對，支援併發）、stdout 寫入序列化。
pub async fn serve<R, W>(bridge: Arc<Bridge>, mut stdin: R, stdout: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let out = Arc::new(AsyncMutex::new(stdout));
    // ticket → 請求 id：斷線時據此對所有 pending 回 error（不遺漏、不重複）。
    let pending: Arc<Mutex<HashMap<u64, Value>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_ticket = Arc::new(AtomicU64::new(1));
    loop {
        let frame = tokio::select! {
            r = read_nm(&mut stdin) => r?,
            _ = bridge.dead() => {
                fail_pending(&out, &pending).await;
                return Err("btp bridge closed".into());
            }
        };
        let Some(req) = frame else {
            return Ok(()); // stdin EOF → 乾淨結束
        };
        let id = match req.get("id") {
            Some(v @ (Value::Number(_) | Value::String(_))) => v.clone(),
            _ => {
                // 無 id 無法歸屬回應；協定要求 id 必填。
                let _ = write_nm(
                    &mut *out.lock().await,
                    &err_resp(Value::Null, "request id required"),
                )
                .await;
                continue;
            }
        };
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        let ticket = next_ticket.fetch_add(1, Ordering::Relaxed);
        pending
            .lock()
            .expect("pending mutex poisoned")
            .insert(ticket, id.clone());
        let (b, out, pending) = (bridge.clone(), out.clone(), pending.clone());
        tokio::spawn(async move {
            let resp = match dispatch::dispatch(&b, &method, &params).await {
                Ok(result) => json!({"id": id, "ok": true, "result": result}),
                Err(e) => err_resp(id.clone(), &e),
            };
            // 死訊號路徑可能已代答；誰抢到 remove 誰寫。
            if pending
                .lock()
                .expect("pending mutex poisoned")
                .remove(&ticket)
                .is_some()
            {
                let _ = write_nm(&mut *out.lock().await, &resp).await;
            }
        });
    }
}

fn err_resp(id: Value, error: &str) -> Value {
    json!({"id": id, "ok": false, "error": error})
}

/// BTP 斷線：對所有尚未回答的 pending 請求補 error 回應。
async fn fail_pending<W: AsyncWrite + Unpin>(
    out: &AsyncMutex<W>,
    pending: &Mutex<HashMap<u64, Value>>,
) {
    let drained: Vec<Value> = pending
        .lock()
        .expect("pending mutex poisoned")
        .drain()
        .map(|(_, id)| id)
        .collect();
    let mut w = out.lock().await;
    for id in drained {
        let _ = write_nm(&mut *w, &err_resp(id, "daemon bridge closed")).await;
    }
}

#[cfg(test)]
mod tests;
