//! 七個工具的宣告與「MCP 參數 → BTP Call」對映。
//! 這裡只有轉譯、沒有政策：授權判定唯一在 daemon `call()`（契約 §2.3），
//! 所以 view 等級是寫死的（list=Metadata、get=Masked、reveal=Reveal），
//! agent 無法從參數裡把自己看到的視窗調高。

use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug)]
pub struct ToolError {
    pub code: i64,
    pub message: String,
}

fn invalid(msg: impl Into<String>) -> ToolError {
    ToolError {
        code: -32602,
        message: msg.into(),
    }
}

pub fn defs() -> Value {
    json!([
        {
            "name": "vault_list",
            "description": "List vault items. Output is metadata only (id/name/uris/tags); secret fields do not exist in this view. Default limit 100.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "full-text search term"},
                    "tag": {"type": "string", "description": "filter by local tag"},
                    "uri": {"type": "string", "description": "filter by uri host"},
                    "limit": {"type": "integer", "description": "max items (default 100)"}
                }
            }
        },
        {
            "name": "vault_get",
            "description": "Read one item with masked secrets (password as tail-mask). Revealing plaintext requires vault_reveal and a grant.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "description": "item uuid"}},
                "required": ["id"]
            }
        },
        {
            "name": "vault_reveal",
            "description": "Reveal a plaintext secret field (default: password) into LLM context. Requires a Reveal grant on this session; without it the daemon denies or blocks on human approval. Every reveal is audited.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "item uuid"},
                    "field": {"type": "string", "description": "secret field to reveal (default \"password\")"}
                },
                "required": ["id"]
            }
        },
        {
            "name": "totp_code",
            "description": "Compute the current TOTP code for an item. Requires a use:totp grant.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "description": "item uuid"}},
                "required": ["id"]
            }
        },
        {
            "name": "run",
            "description": "Run a command via the daemon. env values may be btw://<item>/<field> secret refs injected into the child only; stdout/stderr are redacted before they reach context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}, "description": "program and args, no shell"},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "K=V; V may be a btw:// secret ref"},
                    "cwd": {"type": "string", "description": "working directory"},
                    "timeout_ms": {"type": "integer", "description": "kill child after this many ms (default 30000)"}
                },
                "required": ["argv"]
            }
        },
        {
            "name": "audit_tail",
            "description": "Tail the audit log: one JSON row per call (action, item, sensitivity, outcome, bytes_out). Values are never included, only fingerprints and byte counts.",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "description": "max rows (default 50)"}}
            }
        },
        {
            "name": "session_whoami",
            "description": "Report the account this session reads through (email, server). Opaque/Identity level only; no secrets.",
            "inputSchema": {"type": "object", "properties": {}}
        }
    ])
}

fn get_id(args: &Value) -> Result<Uuid, ToolError> {
    let raw = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("id (item uuid) required"))?;
    Uuid::parse_str(raw).map_err(|e| invalid(format!("id: {e}")))
}

fn get_limit(args: &Value, default: u32) -> Result<u32, ToolError> {
    match args.get("limit") {
        None => Ok(default),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| invalid("limit must be an integer"))?;
            u32::try_from(n).map_err(|_| invalid("limit out of range"))
        }
    }
}

/// 凍結對映表（任務契約）：
/// vault_list→Vault(List,Metadata) vault_get→Vault(Get,Masked)
/// vault_reveal→Vault(Get,Reveal) totp_code→Use(TotpCode)
/// run→Use(Run) audit_tail→Agent(Audit) session_whoami→Auth(WhoAmI)
pub fn map_call(name: &str, args: &Value) -> Result<bw_proto::Call, ToolError> {
    use bw_proto::{AgentCall, AuthCall, Call, Query, RunPlan, SortKey, UseCall, VaultCall, View};
    if !args.is_object() {
        return Err(invalid("arguments must be an object"));
    }
    Ok(match name {
        "vault_list" => Call::Vault(VaultCall::List {
            query: Query {
                text: opt_str(args, "text")?,
                tag: opt_str(args, "tag")?,
                uri: opt_str(args, "uri")?,
                kind: None,
                sort: SortKey::default(),
                limit: get_limit(args, 100)?,
            },
            view: View::Metadata,
        }),
        "vault_get" => Call::Vault(VaultCall::Get {
            id: get_id(args)?,
            view: View::Masked,
        }),
        "vault_reveal" => {
            // field 是 context 面參數；本輪 daemon 的 Get{Reveal} 回完整視窗，
            // 不另做過濾（政策唯一入口在 daemon，§2.3）。
            opt_str(args, "field")?;
            Call::Vault(VaultCall::Get {
                id: get_id(args)?,
                view: View::Reveal,
            })
        }
        "totp_code" => Call::Use(UseCall::TotpCode { id: get_id(args)? }),
        "run" => {
            let argv_v = args.get("argv").ok_or_else(|| invalid("argv required"))?;
            let argv = argv_v
                .as_array()
                .ok_or_else(|| invalid("argv must be an array of strings"))?;
            if argv.is_empty() {
                return Err(invalid("argv must not be empty"));
            }
            let argv: Result<Vec<String>, _> = argv
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| invalid("argv items must be strings"))
                })
                .collect();
            let mut env: Vec<(String, String)> = Vec::new();
            if let Some(e) = args.get("env") {
                let map = e
                    .as_object()
                    .ok_or_else(|| invalid("env must be an object of string values"))?;
                for (k, v) in map {
                    let v = v
                        .as_str()
                        .ok_or_else(|| invalid(format!("env.{k} must be a string")))?;
                    env.push((k.clone(), v.to_owned()));
                }
                env.sort(); // 決定性：map 迭代序不進協議
            }
            let cwd = match args.get("cwd") {
                Some(v) => v
                    .as_str()
                    .ok_or_else(|| invalid("cwd must be a string"))?
                    .to_owned(),
                None => String::new(),
            };
            let timeout_ms = match args.get("timeout_ms") {
                Some(v) => v
                    .as_u64()
                    .ok_or_else(|| invalid("timeout_ms must be an integer"))?,
                None => 30_000,
            };
            Call::Use(UseCall::Run {
                plan: RunPlan {
                    argv: argv?,
                    env,
                    cwd,
                    timeout_ms,
                },
            })
        }
        "audit_tail" => Call::Agent(AgentCall::Audit {
            since: None,
            limit: get_limit(args, 50)?,
        }),
        "session_whoami" => Call::Auth(AuthCall::WhoAmI),
        other => return Err(invalid(format!("unknown tool: {other}"))),
    })
}

fn opt_str(args: &Value, key: &str) -> Result<Option<String>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| invalid(format!("{key} must be a string"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::{Call, View};

    #[test]
    fn defs_have_seven_frozen_names() {
        let d = defs();
        let names: Vec<&str> = d
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
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
        for t in d.as_array().unwrap() {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    fn id() -> String {
        "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned()
    }

    #[test]
    fn vault_list_maps_to_metadata_view() {
        let call = map_call("vault_list", &json!({"text": "git", "limit": 5})).unwrap();
        match call {
            Call::Vault(bw_proto::VaultCall::List { query, view }) => {
                assert_eq!(view, View::Metadata);
                assert_eq!(query.text.as_deref(), Some("git"));
                assert_eq!(query.limit, 5);
            }
            other => panic!("{other:?}"),
        }
        // limit 預設 100（與 CLI 一致）
        let call = map_call("vault_list", &json!({})).unwrap();
        match call {
            Call::Vault(bw_proto::VaultCall::List { query, .. }) => assert_eq!(query.limit, 100),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn view_levels_are_hardcoded() {
        let a = id();
        match map_call("vault_get", &json!({"id": a})).unwrap() {
            Call::Vault(bw_proto::VaultCall::Get { view, .. }) => assert_eq!(view, View::Masked),
            other => panic!("{other:?}"),
        }
        match map_call("vault_reveal", &json!({"id": a, "field": "password"})).unwrap() {
            Call::Vault(bw_proto::VaultCall::Get { view, .. }) => assert_eq!(view, View::Reveal),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn run_plan_translation() {
        let call = map_call(
            "run",
            &json!({
                "argv": ["/bin/sh", "-c", "echo hi"],
                "env": {"TOKEN": "btw://67e55044-10b1-426f-9247-bb680e5fe0c8/password", "B": "lit"},
                "timeout_ms": 5000
            }),
        )
        .unwrap();
        match call {
            Call::Use(bw_proto::UseCall::Run { plan }) => {
                assert_eq!(plan.argv, ["/bin/sh", "-c", "echo hi"]);
                assert_eq!(plan.env[0].0, "B");
                assert_eq!(plan.env[1].0, "TOKEN");
                assert!(plan.env[1].1.starts_with("btw://"));
                assert_eq!(plan.timeout_ms, 5000);
                assert_eq!(plan.cwd, "");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bad_params() {
        assert!(map_call("vault_get", &json!({"id": "not-a-uuid"})).is_err());
        assert!(map_call("vault_get", &json!({})).is_err());
        assert!(map_call("run", &json!({"argv": []})).is_err());
        assert!(map_call("nope", &json!({})).is_err());
        assert!(map_call("vault_list", &json!({"limit": "x"})).is_err());
        assert!(map_call("audit_tail", &json!({})).is_ok());
        assert!(map_call("session_whoami", &json!({})).is_ok());
    }
}
