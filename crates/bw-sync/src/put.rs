//! PUT body 合成：`theirs` 深拷貝 + 欄位級合併結果（契约 §2.4、§2.6）。
//!
//! 路徑文法三處共用（`bw_proto::FieldEdit` 的文件即權威定義；bw-vault 的
//! `three_way` 輸出、daemon 的 flatten、這裡的套用都用同一套字串）：
//!
//! | 路徑 | 落點（cipher JSON） | 備註 |
//! |---|---|---|
//! | `name` | `$.name` | 伺服器上是信封字串 |
//! | `notes` | `$.notes` | 同上 |
//! | `username` | `$.login.username` | 同上 |
//! | `password` | `$.login.password` | 同上 |
//! | `totp` | `$.login.totp` | 同上 |
//! | `favorite` | `$.favorite` | 明碼布林，值域 `"true"`/`"false"`；`None` → `false` |
//! | `uri.<n>` | `$.login.uris[<n>].uri` | `<n>` 為 0 起索引；**越界回錯**（增刪 uri 是整陣列替換的 ops，不在此路徑） |
//! | `field.<id>.name` | `$.fields[id==<id>].name` | `<id>` 比對 `fields[].id`（字串或數字都接受，轉字串比） |
//! | `field.<id>.value` | `$.fields[id==<id>].value` | 找不到該 id → 回錯 |
//!
//! 為什麼放佔位字串而不是明文：本層不做加密（不持金鑰，不變量 1）。呼叫端
//! daemon 在 `with_keys` 閉包內把 `placeholder_for(path)` 換成信封
//! `2.iv|ct|mac` 後才 PUT。佔位字串內嵌路徑，同一 body 的多個待換欄位不會互相
//! 混淆。`None`（清空）直接落 `null`，不需要加密替換。
//!
//! 未列於 `merged` 的路徑絕不被碰——這是 raw mirror 無損往返（不变量 8）的
//! 寫入端：我們未建模的欄位（`object`、`passwordHistory`、任何未來新增欄位）
//! 原樣留在深拷貝裡送回伺服器。

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// 佔位字串前綴。daemon 以 `starts_with` 辨認待換欄位。
pub const PLACEHOLDER_PREFIX: &str = "__bw_sync_pending__:";

/// 某路徑的佔位值：`__bw_sync_pending__:<path>`。
#[must_use]
pub fn placeholder_for(path: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{path}")
}

/// 欄位路徑的內部表示（文法見模組文件表）。
enum Path<'a> {
    Name,
    Notes,
    Username,
    Password,
    Totp,
    Favorite,
    Uri(u32),
    FieldName(&'a str),
    FieldValue(&'a str),
}

fn parse_path(raw: &str) -> Result<Path<'_>, String> {
    match raw {
        "name" => return Ok(Path::Name),
        "notes" => return Ok(Path::Notes),
        "username" => return Ok(Path::Username),
        "password" => return Ok(Path::Password),
        "totp" => return Ok(Path::Totp),
        "favorite" => return Ok(Path::Favorite),
        _ => {}
    }
    if let Some(rest) = raw.strip_prefix("uri.") {
        let n = rest
            .parse::<u32>()
            .map_err(|_| format!("uri index is not a u32: {rest:?}"))?;
        return Ok(Path::Uri(n));
    }
    // field ids may contain dots; peel the known leaf from the right.
    if let Some(rest) = raw.strip_prefix("field.") {
        let (id, leaf) = rest
            .rsplit_once('.')
            .ok_or_else(|| format!("field path needs a .name/.value leaf: {raw:?}"))?;
        if id.is_empty() {
            return Err(format!("field path has an empty id: {raw:?}"));
        }
        return match leaf {
            "name" => Ok(Path::FieldName(id)),
            "value" => Ok(Path::FieldValue(id)),
            other => Err(format!("unknown field leaf {other:?} in {raw:?}")),
        };
    }
    Err(format!("unknown field path: {raw:?}"))
}

fn json_err(msg: String) -> serde_json::Error {
    <serde_json::Error as serde::ser::Error>::custom(msg)
}

fn err<T>(msg: String) -> serde_json::Result<T> {
    Err(json_err(msg))
}

/// 由 `theirs`（伺服器原樣 cipher JSON）合成 `PUT /ciphers/{id}` 的 body：
/// 深拷貝後套用 `merged`（欄位路徑 → 新明文值；`None` ＝ 清空該欄）。
///
/// 值以 [`placeholder_for`] 的佔位字串放入，加密與最終替換是呼叫端的事；
/// 本函數是純函數，不驗證信封、不碰金鑰。
///
/// # Errors
/// 路徑文法不合法、`uri.<n>` 越界、`field.<id>` 不存在、`favorite` 值不是
/// `"true"`/`"false"`、`theirs` 不是 JSON 物件時回 `Err`（`serde_json::Error`，
/// message 為上面這些原因）。
pub fn build_put_body(
    theirs: &Value,
    merged: &BTreeMap<String, Option<String>>,
) -> serde_json::Result<Value> {
    let mut out = theirs.clone(); // deep copy; every nested container is owned anew
    let root = match &mut out {
        Value::Object(m) => m,
        _ => return err("theirs must be a JSON object (cipher response)".to_owned()),
    };
    // BTreeMap iteration order is deterministic (sorted paths).
    for (path, value) in merged {
        let p = parse_path(path).map_err(json_err)?;
        let slot = placeholder_for(path);
        match p {
            Path::Name => {
                root.insert("name".to_owned(), opt_value(value, &slot));
            }
            Path::Notes => {
                root.insert("notes".to_owned(), opt_value(value, &slot));
            }
            Path::Favorite => {
                // favorite is a plain bool server-side: apply the real value,
                // no envelope placeholder needed. Clearing means off.
                let b = match value {
                    Some(v) => match v.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => {
                            return err(format!("favorite expects \"true\"/\"false\", got {v:?}"));
                        }
                    },
                    None => false,
                };
                root.insert("favorite".to_owned(), Value::Bool(b));
            }
            Path::Username | Path::Password | Path::Totp => {
                let key = match p {
                    Path::Username => "username",
                    Path::Password => "password",
                    _ => "totp",
                };
                let login = ensure_object(root, "login")?;
                login.insert(key.to_owned(), opt_value(value, &slot));
            }
            Path::Uri(n) => {
                let uris = root
                    .get_mut("login")
                    .and_then(Value::as_object_mut)
                    .and_then(|l| l.get_mut("uris"))
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| {
                        json_err(format!("uri.{n}: login.uris is missing or not an array"))
                    })?;
                let Some(entry) = uris.get_mut(n as usize) else {
                    return err(format!(
                        "uri.{n} out of range: login.uris has {} entries",
                        uris.len()
                    ));
                };
                let e = entry
                    .as_object_mut()
                    .ok_or_else(|| json_err(format!("uri.{n}: entry is not an object")))?;
                e.insert("uri".to_owned(), opt_value(value, &slot));
            }
            Path::FieldName(id) | Path::FieldValue(id) => {
                let key = if matches!(p, Path::FieldName(_)) {
                    "name"
                } else {
                    "value"
                };
                let fields = root
                    .get_mut("fields")
                    .ok_or_else(|| json_err(format!("field.{id}: no fields array in theirs")))?;
                let arr = fields
                    .as_array_mut()
                    .ok_or_else(|| json_err(format!("field.{id}: fields is not an array")))?;
                let entry = arr
                    .iter_mut()
                    .find(|f| f.get("id").is_some_and(|i| id_of(i).as_deref() == Some(id)))
                    .ok_or_else(|| {
                        json_err(format!("field.{id}: no field with id {id:?} in theirs"))
                    })?;
                let e = entry
                    .as_object_mut()
                    .ok_or_else(|| json_err(format!("field.{id}: entry is not an object")))?;
                e.insert(key.to_owned(), opt_value(value, &slot));
            }
        }
    }
    Ok(out)
}

/// `Some(v)` → 佔位字串（daemon 之後換信封）；`None` → `null`（清空）。
fn opt_value(value: &Option<String>, slot: &str) -> Value {
    match value {
        Some(_) => Value::String(slot.to_owned()),
        None => Value::Null,
    }
}

/// 取得（或建立）root 下的子物件；原本不是物件（含 `null`）時整個換掉。
fn ensure_object<'a>(
    root: &'a mut Map<String, Value>,
    key: &str,
) -> serde_json::Result<&'a mut Map<String, Value>> {
    let slot = root
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    match slot {
        Value::Object(m) => Ok(m),
        _ => {
            *slot = Value::Object(Map::new());
            match slot {
                Value::Object(m) => Ok(m),
                _ => unreachable!("just assigned an object"),
            }
        }
    }
}

/// `fields[].id` 在 upstream 是字串、部分實作可能給數字；統一轉字串比對。
fn id_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn theirs() -> Value {
        json!({
            "object": "cipher",
            "id": "66b31944-ec07-485e-9716-2b0632299dd7",
            "name": "2.old|old|old",
            "notes": "2.note|note|note",
            "favorite": false,
            "reprompt": 0,
            "revisionDate": "2026-10-28T18:15:44.9261315Z",
            "login": {
                "username": "2.user|u|u",
                "password": "2.pass|p|p",
                "totp": null,
                "uris": [
                    { "uri": "2.uri0|u0|u0", "match": null },
                    { "uri": "2.uri1|u1|u1", "match": 0 }
                ],
                "passwordHistory": [{ "password": "2.h|h|h", "lastUsedDate": "x" }]
            },
            "fields": [
                { "id": "1633806829", "name": "2.fn|fn|fn", "value": "2.fv|fv|fv", "type": 0 },
                { "id": "member", "name": "2.mn|mn|mn", "value": null, "type": 1 }
            ],
            "attachments": null,
            "folderId": null
        })
    }

    fn merged(pairs: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(p, v)| (p.to_string(), v.map(str::to_string)))
            .collect()
    }

    #[test]
    fn replaces_nested_paths_with_placeholders() {
        let m = merged(&[
            ("name", Some("new name")),
            ("username", Some("u2")),
            ("password", Some("p2")),
            ("totp", Some("jwt")),
            ("uri.1", Some("https://example.test")),
            ("field.1633806829.value", Some("secret field")),
            ("field.member.name", Some("renamed")),
        ]);
        let out = build_put_body(&theirs(), &m).unwrap();
        assert_eq!(out["name"], json!(placeholder_for("name")));
        assert_eq!(out["login"]["username"], json!(placeholder_for("username")));
        assert_eq!(out["login"]["password"], json!(placeholder_for("password")));
        assert_eq!(out["login"]["totp"], json!(placeholder_for("totp")));
        assert_eq!(
            out["login"]["uris"][1]["uri"],
            json!(placeholder_for("uri.1"))
        );
        assert_eq!(
            out["fields"][0]["value"],
            json!(placeholder_for("field.1633806829.value"))
        );
        assert_eq!(
            out["fields"][1]["name"],
            json!(placeholder_for("field.member.name"))
        );
    }

    #[test]
    fn placeholders_carry_their_own_path() {
        // Two changed fields must not collide into one indistinguishable token.
        let m = merged(&[("username", Some("a")), ("password", Some("b"))]);
        let out = build_put_body(&theirs(), &m).unwrap();
        let u = out["login"]["username"].as_str().unwrap();
        let p = out["login"]["password"].as_str().unwrap();
        assert!(u.starts_with(PLACEHOLDER_PREFIX) && p.starts_with(PLACEHOLDER_PREFIX));
        assert_ne!(u, p);
        assert!(u.ends_with("username") && p.ends_with("password"));
    }

    #[test]
    fn none_clears_the_field_to_null() {
        let m = merged(&[
            ("notes", None),
            ("uri.0", None),
            ("field.1633806829.value", None),
        ]);
        let out = build_put_body(&theirs(), &m).unwrap();
        assert_eq!(out["notes"], Value::Null);
        assert_eq!(out["login"]["uris"][0]["uri"], Value::Null);
        assert_eq!(out["fields"][0]["value"], Value::Null);
    }

    #[test]
    fn favorite_is_applied_as_plain_bool() {
        // favorite is not encrypted server-side, so it gets the real value.
        let on = build_put_body(&theirs(), &merged(&[("favorite", Some("true"))])).unwrap();
        assert_eq!(on["favorite"], json!(true));
        let off = build_put_body(&theirs(), &merged(&[("favorite", Some("false"))])).unwrap();
        assert_eq!(off["favorite"], json!(false));
        let clear = build_put_body(&theirs(), &merged(&[("favorite", None)])).unwrap();
        assert_eq!(clear["favorite"], json!(false));
        let bad = build_put_body(&theirs(), &merged(&[("favorite", Some("yes"))]));
        assert!(bad.is_err());
    }

    #[test]
    fn untouched_paths_survive_verbatim() {
        let m = merged(&[("name", Some("only name changed"))]);
        let out = build_put_body(&theirs(), &m).unwrap();
        assert_eq!(out["notes"], theirs()["notes"]);
        assert_eq!(out["login"]["uris"], theirs()["login"]["uris"]);
        assert_eq!(out["fields"], theirs()["fields"]);
        // unmodelled fields for the raw-mirror invariant (§2.6, invariant 8)
        for key in ["object", "id", "revisionDate", "reprompt"] {
            assert_eq!(out[key], theirs()[key]);
        }
        assert_eq!(
            out["login"]["passwordHistory"],
            theirs()["login"]["passwordHistory"]
        );
    }

    #[test]
    fn empty_merge_is_a_pure_deep_copy() {
        let out = build_put_body(&theirs(), &BTreeMap::new()).unwrap();
        assert_eq!(out, theirs());
    }

    #[test]
    fn deep_copy_does_not_alias_theirs() {
        let mut base = theirs();
        let before = base.clone();
        let m = merged(&[("uri.0", Some("changed"))]);
        let _ = build_put_body(&base, &m).unwrap();
        assert_eq!(base, before, "theirs must not be mutated");
        base["name"] = json!("mutating the copy source afterwards is fine");
    }

    #[test]
    fn uri_index_out_of_range_is_an_error() {
        let m = merged(&[("uri.2", Some("nope"))]);
        let e = build_put_body(&theirs(), &m).unwrap_err().to_string();
        assert!(e.contains("out of range"), "{e}");
        // index exactly at len is still out of range: appending is not this path's job
        let m = merged(&[("uri.2", None)]);
        assert!(build_put_body(&theirs(), &m).is_err());
    }

    #[test]
    fn missing_field_id_is_an_error() {
        let m = merged(&[("field.does-not-exist.value", Some("x"))]);
        let e = build_put_body(&theirs(), &m).unwrap_err().to_string();
        assert!(e.contains("no field with id"), "{e}");
    }

    #[test]
    fn unknown_path_grammar_is_an_error() {
        for p in [
            "",
            "urI.0",
            "uri",
            "uri.x",
            "field.",
            "field.id",
            "field.id.other",
            "cardNumber",
        ] {
            let m = merged(&[(p, Some("v"))]);
            assert!(
                build_put_body(&theirs(), &m).is_err(),
                "{p:?} should be rejected"
            );
        }
    }

    #[test]
    fn login_container_is_created_when_absent() {
        // a secure-note cipher has no login; setting username must materialise it
        let note = json!({ "object": "cipher", "type": 2, "name": "2.n|n|n", "fields": [] });
        let m = merged(&[("username", Some("someone"))]);
        let out = build_put_body(&note, &m).unwrap();
        assert_eq!(out["login"]["username"], json!(placeholder_for("username")));
        assert_eq!(out["type"], json!(2), "nothing else touched");
    }

    #[test]
    fn uri_on_cipher_without_uris_array_errors() {
        let note = json!({ "object": "cipher", "name": "2.n|n|n" });
        let m = merged(&[("uri.0", Some("x"))]);
        let e = build_put_body(&note, &m).unwrap_err().to_string();
        assert!(e.contains("login.uris is missing"), "{e}");
    }

    #[test]
    fn theirs_must_be_an_object() {
        assert!(build_put_body(&json!([]), &BTreeMap::new()).is_err());
        assert!(build_put_body(&json!("x"), &BTreeMap::new()).is_err());
    }

    #[test]
    fn real_recorded_request_shape_roundtrips() {
        // Fixture-shaped PUT body (bw-server recordings) with one nested field edit.
        let t = json!({
            "collectionIds": [], "favorite": false, "fields": [], "folderId": null,
            "login": { "password": "2.a|b|c", "totp": null,
                       "uris": [{ "match": null, "uri": "2.a|b|c" }],
                       "username": "2.a|b|c" },
            "name": "2.a|b|c", "notes": null, "organizationId": null,
            "reprompt": 0, "type": 1
        });
        let m = merged(&[("notes", Some("hello")), ("uri.0", Some("https://x.test"))]);
        let out = build_put_body(&t, &m).unwrap();
        assert_eq!(out["notes"], json!(placeholder_for("notes")));
        assert_eq!(
            out["login"]["uris"][0]["uri"],
            json!(placeholder_for("uri.0"))
        );
        assert_eq!(out["login"]["username"], "2.a|b|c");
    }
}
