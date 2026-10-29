//! bitward-mcp：MCP ↔ BTP 純轉譯 shim（契約 §1 進程拓撲、§2.3 唯一 thin 入口、§2.5 BTP）。
//! 一個程序只服務一條 stdio 連線；零政策邏輯——授權、budget、核准、淨化全在 daemon。
//! BTP 連線斷了 ⇒ 以錯結束（不重連；重新 spawn 是 agent host 的事）。

mod bridge;
mod tools;

use std::process::ExitCode;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use bridge::Bridge;
use bw_proto::{Auth, Response};

/// MCP stdio 傳輸 = newline-delimited JSON-RPC 2.0（無 Content-Length header）。
/// 來源：https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
const PROTOCOL_VERSION: &str = "2025-06-18";

// JSON-RPC 2.0 標準錯誤碼。來源：https://www.jsonrpc.org/specification#error_object
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bitward-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    // BITWARD_SOCK 必要：shim 永不自行落地 daemon（§1.2 可用性語意）。
    let sock = std::env::var_os("BITWARD_SOCK")
        .ok_or("BITWARD_SOCK not set (daemon UDS path required)")?;
    let token = std::env::var("BITWARD_AGENT_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .map_err(|e| format!("cannot connect to daemon ({}): {e}", sock.to_string_lossy()))?;
    let (server_name, auth) = server_identity(
        token.as_deref(),
        std::process::id(),
        uuid::Uuid::new_v4().to_string(),
    );
    let bridge = Bridge::connect(stream, auth).await?;
    serve(
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
        &bridge,
        &server_name,
    )
    .await
}

/// 凍結介面：有 token ⇒ Auth::Session 續用（serverInfo 掛正名）；
/// 無 token ⇒ 本機全權 Enroll，serverInfo 與 display_name 都標 `mcp:<pid>`，
/// 讓人在 `agent list` 看得到是誰開的（契約 §2.3 Enrollment）。
fn server_identity(token: Option<&str>, pid: u32, pairing: String) -> (String, Auth) {
    match token {
        Some(t) => (
            "bitward-mcp".to_owned(),
            Auth::Session {
                token: t.to_owned(),
            },
        ),
        None => {
            let name = format!("mcp:{pid}");
            (
                name.clone(),
                Auth::Enroll {
                    pairing,
                    display_name: name,
                },
            )
        }
    }
}

/// 主迴程：逐行讀 stdio、逐行寫回應。請求採串行處理（單連線 shim，
/// 併發價值低且讓 stderr/audit 時序難讀），但 BTP 層是 rid 配對的，
/// 日後要併發只需把 handle_line 丟進任務池。
async fn serve<R, W>(
    reader: R,
    mut writer: W,
    bridge: &Bridge,
    server_name: &str,
) -> Result<(), String>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = reader.lines();
    let mut dead_rx = bridge.dead_watch();
    let mut out: Vec<u8> = Vec::with_capacity(8192);
    loop {
        // 每輪先收斂死亡檢查：kill 可能發生在處理上一行之間，changed() 不會重播。
        if let Some(reason) = dead_rx.borrow_and_update().clone() {
            return Err(format!("daemon connection terminated: {reason}"));
        }
        let response = tokio::select! {
            biased;
            line = lines.next_line() => {
                match line.map_err(|e| format!("stdio read: {e}"))? {
                    None => break, // stdin EOF＝host 關連線，正常收工
                    Some(l) if l.trim().is_empty() => continue,
                    Some(l) => handle_line(&l, bridge, server_name).await,
                }
            }
            r = dead_rx.changed() => {
                let _ = r;
                let reason = dead_rx.borrow().clone().unwrap_or_else(|| "btp connection lost".to_owned());
                return Err(format!("daemon connection terminated: {reason}"));
            }
        };
        if let Some(resp) = response {
            serde_json::to_writer(&mut out, &resp).map_err(|e| format!("response encode: {e}"))?;
            out.push(b'\n');
            writer
                .write_all(&out)
                .await
                .map_err(|e| format!("stdio write: {e}"))?;
            writer
                .flush()
                .await
                .map_err(|e| format!("stdio flush: {e}"))?;
            out.clear();
        }
    }
    Ok(())
}

async fn handle_line(line: &str, bridge: &Bridge, server_name: &str) -> Option<Value> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(rpc_error(
                Value::Null,
                PARSE_ERROR,
                &format!("parse error: {e}"),
            ));
        }
    };
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str);
    if req.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || method.is_none() {
        return id.map(|id| {
            rpc_error(
                id,
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\" and method required",
            )
        });
    }
    let method = method.unwrap_or_default();
    // 通知永不回呼（JSON-RPC 2.0）；initialize 之後 host 必發 notifications/initialized。
    id.as_ref()?;
    let id = id.unwrap_or(Value::Null);
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": server_name, "version": env!("CARGO_PKG_VERSION")},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools::defs()})),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match tools::map_call(name, &args) {
                Err(e) => Err((e.code, e.message)),
                Ok(call) => match bridge.invoke(call).await {
                    Err(dead) => Err((INTERNAL_ERROR, dead)),
                    Ok(Ok(resp)) => Ok(tool_text(response_text(&resp), false)),
                    // daemon 的協定級錯誤＝工具層失敗（isError），不是協議失敗。
                    Ok(Err(wtp)) => Ok(tool_text(wtp.to_string(), true)),
                },
            }
        }
        other => Err((METHOD_NOT_FOUND, format!("unknown method: {other}"))),
    };
    Some(match result {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err((code, msg)) => rpc_error(id, code, &msg),
    })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_text(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

/// 回應 → 單一 text 欄位。Response 的 externally-tagged JSON 已足以描述結果
/// （{"Items":[..]} / {"Item":{..}} / {"TotpCode":{..}}...），不另發明智格式。
fn response_text(resp: &Response) -> String {
    match serde_json::to_string(resp) {
        Ok(s) => s,
        Err(e) => format!("{{\"serializeError\": \"{e}\"}}"),
    }
}

#[cfg(test)]
mod tests;
