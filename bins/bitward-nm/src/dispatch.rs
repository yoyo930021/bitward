//! 五個凍結 method → BTP Call 的對映與回應塑形。
//! 零政策邏輯：view 等級寫死（list/match=Metadata、reveal=Reveal），
//! 瀏覽器無法從參數裡把自己看到的視窗調高。

use serde_json::{Value, json};
use uuid::Uuid;

use bw_proto::{AdminCall, AuthCall, Call, Query, VaultCall, View};

use crate::bridge::Bridge;

/// credential.match 的候選上限（daemon 端 `Query.limit` 為硬上限）。
const MATCH_LIMIT: u32 = 512;

/// 回 `Err`＝協定級失敗（呼叫端包成 `{"ok":false,"error":...}`）。
pub async fn dispatch(bridge: &Bridge, method: &str, params: &Value) -> Result<Value, String> {
    let (call, shape) = match method {
        "ping" => (Call::Admin(AdminCall::Version), Shape::Raw),
        "session.info" => (Call::Auth(AuthCall::WhoAmI), Shape::Raw),
        "vault.list" => {
            let limit = match params.get("limit").and_then(Value::as_u64) {
                Some(l) if (1..=10_000).contains(&l) => l as u32,
                Some(_) => return Err("params.limit out of range".into()),
                None => MATCH_LIMIT,
            };
            (
                Call::Vault(VaultCall::List {
                    query: Query {
                        limit,
                        ..Default::default()
                    },
                    view: View::Metadata,
                }),
                Shape::Raw,
            )
        }
        "credential.match" => {
            let uri = params
                .get("uri")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or("params.uri required")?
                .to_owned();
            // daemon 的 `Query.uri` 是「存儲值 ⊇ 查詢值」的子串比對：拿整頁 URL 去查
            // 永遠空集合（存儲的 site uri 較短）。故先歸一到 host 再查，
            // host 精確過濾在回應端做（見 FINDINGS）。
            let want = host_of(&uri).unwrap_or_else(|| uri.to_ascii_lowercase());
            (
                Call::Vault(VaultCall::List {
                    query: Query {
                        uri: Some(want.clone()),
                        limit: MATCH_LIMIT,
                        ..Default::default()
                    },
                    view: View::Metadata,
                }),
                Shape::Match(want),
            )
        }
        "credential.reveal" => {
            let raw = params
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "params.id (item uuid) required".to_owned())?;
            let id = Uuid::parse_str(raw).map_err(|e| format!("params.id: {e}"))?;
            (
                Call::Vault(VaultCall::Get {
                    id,
                    view: View::Reveal,
                }),
                Shape::Raw,
            )
        }
        _ => return Err(format!("unknown method: {method}")),
    };
    let outcome = bridge
        .invoke(call)
        .await
        .map_err(|dead| format!("daemon bridge closed: {dead}"))?;
    let resp = outcome.map_err(|e| e.to_string())?;
    match shape {
        Shape::Raw => serde_json::to_value(&resp).map_err(|e| e.to_string()),
        Shape::Match(want) => {
            let items = match resp {
                bw_proto::Response::Items(v) => v,
                other => return Err(format!("unexpected daemon response: {other:?}")),
            };
            let matched: Vec<Value> = items
                .into_iter()
                // daemon 的 uri 過濾是子串 LIKE；這裡歸一到 host 精確比對，
                // 擋掉 "github.com" 命中 "gist.github.com" 這類誤配。
                .filter(|it| {
                    it.meta
                        .uris
                        .iter()
                        .any(|u| host_of(u).as_deref() == Some(want.as_str()))
                })
                .map(|it| {
                    json!({
                        "id": it.meta.id,
                        "name": it.meta.name,
                        "uris": it.meta.uris,
                        // P4 不回 username：hint 恆 null（型別佔位，政策見 README）
                        "username_hint": Value::Null,
                    })
                })
                .collect();
            Ok(Value::Array(matched))
        }
    }
}

#[derive(Clone)]
enum Shape {
    /// daemon Response 原樣（serde externally-tagged）。
    Raw,
    /// host 精確過濾 + 塑形為 [{id,name,uris,username_hint}]。
    Match(String),
}

/// URI → 小寫 host（去 scheme/userinfo/port/path/trailing dot）。無 `url` crate：
/// native messaging 面只需 host 比對，這裡是刻意最小的解析。
pub fn host_of(uri: &str) -> Option<String> {
    let s = uri.trim();
    if s.is_empty() {
        return None;
    }
    let s = match s.split_once("://") {
        Some((_, rest)) => rest,
        None => s,
    };
    let s = s.split(['/', '?', '#']).next().unwrap_or_default();
    let s = match s.rsplit_once('@') {
        Some((_, hostport)) => hostport,
        None => s,
    };
    let host = if let Some(rest) = s.strip_prefix('[') {
        // IPv6：[::1]:8080 → [::1]（含括號，比對兩側形態一致）
        let end = rest.find(']')?;
        format!("[{}]", &rest[..end])
    } else {
        s.split(':').next().unwrap_or(s).to_owned()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction_basics() {
        assert_eq!(
            host_of("https://GitHub.com/path?x=1#f").as_deref(),
            Some("github.com")
        );
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(host_of("github.com.").as_deref(), Some("github.com"));
        assert_eq!(
            host_of("http://user:pw@sub.example.com:8080/a").as_deref(),
            Some("sub.example.com")
        );
        assert_eq!(host_of("https://[::1]:8080/x").as_deref(), Some("[::1]"));
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https:///path"), None);
        assert_eq!(
            host_of("app.example.com/privacy").as_deref(),
            Some("app.example.com")
        );
    }
}
