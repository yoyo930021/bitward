//! 欄位級三方合併（契約 §2.4）：純函數，不做加解密、不碰 IO。
//!
//! 座標系是**欄位路徑字串**（文法見 bw_proto::FieldEdit 文件）：
//! daemon 先用 user key 把三個密文形態（base/ours/theirs）攤平成
//! `FieldMap`（明文），這裡只比較與合併明文；回傳「哪些路徑要推什麼值」。
//!
//! 為什麼不用密文比較：信封 IV 隨機，同一明文每次加密都不同，
//! 密文相等 ⇏ 內容相等；必須在明文域判定（來源：bitwarden 信封格式，
//! https://bitwarden.com/help/what-encryption-is-used ）。

use std::collections::BTreeMap;

/// 明文欄位表。None ＝ 該欄為空/清除。favorite 以 "true"/"false" 進入。
pub type FieldMap = BTreeMap<String, Option<String>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Merge {
    /// 把這些欄位推回伺服器（基準：theirs）。空 map 表示無需 PUT。
    Push(FieldMap),
    /// 我們的變更已被伺服器狀態涵蓋（例如兩邊改成同一值）。
    Noop,
    /// 同欄位双方都改且不同值；`fields` 為相撞路徑，交收件匣。
    Conflict { fields: Vec<String> },
}

/// 欄位級 3-way：ours vs base 的差異 × theirs vs base 的差異。
/// 不相交自動合併（ ours 的改動套到 theirs 上 ）；相交且值不同 → 衝突。
pub fn three_way(base: &FieldMap, ours: &FieldMap, theirs: &FieldMap) -> Merge {
    let mut push = FieldMap::new();
    let mut clashes = Vec::new();
    let keys: BTreeMap<&String, ()> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .map(|k| (k, ()))
        .collect();
    for key in keys.keys() {
        let b = base.get(*key).cloned().flatten();
        let o = ours.get(*key).cloned().flatten();
        let t = theirs.get(*key).cloned().flatten();
        let ours_changed = o != b;
        let theirs_changed = t != b;
        match (ours_changed, theirs_changed) {
            (false, _) => {}
            (true, false) => {
                push.insert((*key).clone(), o.clone());
            }
            (true, true) if o == t => {}
            // 雙方都改且不同值。值相同才算涵蓋；否則衝突（永不靜默覆蓋，§2.4）。
            (true, true) => {
                clashes.push((*key).clone());
            }
        }
    }
    if !clashes.is_empty() {
        return Merge::Conflict { fields: clashes };
    }
    if push.is_empty() {
        Merge::Noop
    } else {
        Merge::Push(push)
    }
}

/// 把（信封形態的）cipher JSON 攤平成明文 `FieldMap`。
/// `dec` 由 daemon 在 `with_keys` 閉包內提供（信封字串 → 明文；失敗回 None 視為讀不到）。
/// 未加密欄位（favorite）直接轉字串。uri 只取 `uri` 子欄。
pub fn flatten(cipher: &serde_json::Value, dec: &dyn Fn(&str) -> Option<String>) -> FieldMap {
    let mut m = FieldMap::new();
    let mut put_enc = |path: &str, val: Option<&str>| {
        if let Some(v) = val {
            m.insert(path.to_string(), dec(v));
        }
    };
    put_enc(
        "name",
        cipher.get("name").and_then(serde_json::Value::as_str),
    );
    put_enc(
        "notes",
        cipher.get("notes").and_then(serde_json::Value::as_str),
    );
    let login = cipher.get("login");
    put_enc(
        "username",
        login
            .and_then(|l| l.get("username"))
            .and_then(serde_json::Value::as_str),
    );
    put_enc(
        "password",
        login
            .and_then(|l| l.get("password"))
            .and_then(serde_json::Value::as_str),
    );
    put_enc(
        "totp",
        login
            .and_then(|l| l.get("totp"))
            .and_then(serde_json::Value::as_str),
    );
    if let Some(uris) = login
        .and_then(|l| l.get("uris"))
        .and_then(serde_json::Value::as_array)
    {
        for (i, u) in uris.iter().enumerate() {
            put_enc(
                &format!("uri.{i}"),
                u.get("uri").and_then(serde_json::Value::as_str),
            );
        }
    }
    if let Some(fav) = cipher.get("favorite").and_then(serde_json::Value::as_bool) {
        m.insert("favorite".into(), Some(fav.to_string()));
    }
    m
}

/// 把合併結果寫回 theirs 的副本：`enc_of` 把明文值加密成信封字串（同樣在
/// `with_keys` 閉包內由 daemon 提供）。None 值＝清除該欄。回傳新 cipher 主體。
pub fn apply_merged(
    theirs: &serde_json::Value,
    merged: &FieldMap,
    enc_of: &dyn Fn(&str) -> String,
) -> serde_json::Value {
    let mut out = theirs.clone();
    {
        let obj = out.as_object_mut().expect("cipher must be object");
        for (path, value) in merged {
            match path.as_str() {
                "name" => set_enc(obj, "name", value.as_deref(), enc_of),
                "notes" => set_enc(obj, "notes", value.as_deref(), enc_of),
                "username" => login_set(obj, "username", value.as_deref(), enc_of),
                "password" => login_set(obj, "password", value.as_deref(), enc_of),
                "totp" => login_set(obj, "totp", value.as_deref(), enc_of),
                "favorite" => {
                    obj.insert(
                        "favorite".into(),
                        serde_json::json!(value.as_deref() == Some("true")),
                    );
                }
                p => {
                    if let Some(rest) = p.strip_prefix("uri.")
                        && let Some(idx) = rest.parse::<usize>().ok()
                    {
                        let login =
                            obj_of(obj.entry("login").or_insert_with(|| serde_json::json!({})));
                        let uris = login.entry("uris").or_insert_with(|| serde_json::json!([]));
                        if !uris.is_array() {
                            *uris = serde_json::json!([]);
                        }
                        let uris = uris.as_array_mut().expect("uris must be array");
                        while uris.len() <= idx {
                            uris.push(serde_json::json!({ "match": null }));
                        }
                        match value {
                            Some(v) => {
                                uris[idx]
                                    .as_object_mut()
                                    .unwrap()
                                    .insert("uri".into(), serde_json::json!(enc_of(v)));
                            }
                            None => {
                                uris[idx]
                                    .as_object_mut()
                                    .unwrap()
                                    .insert("uri".into(), serde_json::Value::Null);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn set_enc(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
    enc_of: &dyn Fn(&str) -> String,
) {
    match value {
        Some(v) => {
            obj.insert(key.into(), serde_json::json!(enc_of(v)));
        }
        None => {
            obj.insert(key.into(), serde_json::Value::Null);
        }
    }
}

fn login_set(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&str>,
    enc_of: &dyn Fn(&str) -> String,
) {
    let login = obj_of(obj.entry("login").or_insert_with(|| serde_json::json!({})));
    set_enc(login, key, value, enc_of);
}

/// null/錯形態的節點一律改寫成 object，讓寫回路徑不因伺服器雜訊炸掉。
fn obj_of(v: &mut serde_json::Value) -> &mut serde_json::Map<String, serde_json::Value> {
    if !v.is_object() {
        *v = serde_json::json!({});
    }
    v.as_object_mut().expect("just set object")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, Option<&str>)]) -> FieldMap {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
            .collect()
    }

    #[test]
    fn disjoint_fields_auto_merge() {
        let base = map(&[
            ("name", Some("n")),
            ("username", Some("u")),
            ("password", Some("p")),
        ]);
        let ours = map(&[
            ("name", Some("n")),
            ("username", Some("U!")),
            ("password", Some("p")),
        ]);
        let theirs = map(&[
            ("name", Some("n")),
            ("username", Some("u")),
            ("password", Some("P!")),
        ]);
        match three_way(&base, &ours, &theirs) {
            Merge::Push(m) => {
                // 只推 ours 的改動；theirs 改的 password 已是伺服器事實，不進 push
                assert_eq!(m.len(), 1);
                assert_eq!(m["username"].as_deref(), Some("U!"));
            }
            other => panic!("expected Push, got {other:?}"),
        }
    }

    #[test]
    fn same_field_both_changed_conflicts() {
        let base = map(&[("name", Some("old"))]);
        let ours = map(&[("name", Some("a"))]);
        let theirs = map(&[("name", Some("b"))]);
        match three_way(&base, &ours, &theirs) {
            Merge::Conflict { fields } => assert_eq!(fields, vec!["name".to_string()]),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn both_changed_to_same_value_is_noop() {
        let base = map(&[("name", Some("old"))]);
        let ours = map(&[("name", Some("new"))]);
        let theirs = map(&[("name", Some("new"))]);
        assert_eq!(three_way(&base, &ours, &theirs), Merge::Noop);
    }

    #[test]
    fn clearing_a_field_pushes_none() {
        let base = map(&[("notes", Some("x"))]);
        let ours = map(&[("notes", None)]);
        let theirs = map(&[("notes", Some("x"))]);
        match three_way(&base, &ours, &theirs) {
            Merge::Push(m) => assert_eq!(m["notes"], None),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn theirs_only_change_needs_no_push() {
        let base = map(&[("name", Some("a"))]);
        let ours = map(&[("name", Some("a"))]);
        let theirs = map(&[("name", Some("b"))]);
        assert_eq!(three_way(&base, &ours, &theirs), Merge::Noop);
    }

    /// 不變量：ours == base 時永不推送、永不衝突。
    #[test]
    fn ours_unchanged_never_pushes() {
        use proptest::prelude::*;
        let base = map(&[("name", Some("n")), ("password", Some("p"))]);
        proptest!(|(seed in 0u8..255u8)| {
            let theirs = map(&[
                ("name", if seed % 2 == 0 { Some("n2") } else { Some("n") }),
                ("password", if seed % 3 == 0 { Some("p2") } else { Some("p") }),
            ]);
            prop_assert_eq!(three_way(&base, &base, &theirs), Merge::Noop);
        });
    }

    fn fake_dec(s: &str) -> Option<String> {
        // 測試用信封：`x:<plain>`；不合格式者回 None
        s.strip_prefix("x:").map(str::to_string)
    }
    fn fake_enc(s: &str) -> String {
        format!("x:{s}")
    }

    #[test]
    fn flatten_reads_known_paths_only() {
        let cipher = serde_json::json!({
            "name": "x:github",
            "notes": "x:note",
            "favorite": true,
            "login": {
                "username": "x:user",
                "password": "x:pw",
                "totp": "x:seed",
                "uris": [{"uri": "x:https://a.test", "match": null}]
            },
            "card": { "number": "x:4111" }
        });
        let m = flatten(&cipher, &fake_dec);
        assert_eq!(m["name"].as_deref(), Some("github"));
        assert_eq!(m["username"].as_deref(), Some("user"));
        assert_eq!(m["uri.0"].as_deref(), Some("https://a.test"));
        assert_eq!(m["favorite"].as_deref(), Some("true"));
        // card.* 不在 P2 路徑文法內
        assert!(!m.contains_key("card.number"));
        assert!(!m.contains_key("number"));
    }

    #[test]
    fn apply_merged_writes_back_with_fake_envelope() {
        let theirs = serde_json::json!({
            "type": 1,
            "name": "x:old",
            "login": {"username": "x:u", "uris": []}
        });
        let merged = map(&[
            ("name", Some("new")),
            ("password", Some("p1")),
            ("uri.0", Some("https://z")),
        ]);
        let out = apply_merged(&theirs, &merged, &fake_enc);
        assert_eq!(out["name"], "x:new");
        assert_eq!(out["login"]["password"], "x:p1");
        assert_eq!(out["login"]["uris"][0]["uri"], "x:https://z");
        assert_eq!(out["login"]["username"], "x:u"); // untouched
        assert_eq!(out["type"], 1);
    }

    #[test]
    fn apply_merged_clears_none() {
        let theirs = serde_json::json!({"name": "x:a", "login": {"totp": "x:s"}});
        let merged = map(&[("name", None), ("totp", None)]);
        let out = apply_merged(&theirs, &merged, &fake_enc);
        assert!(out["name"].is_null());
        assert!(out["login"]["totp"].is_null());
    }
}
