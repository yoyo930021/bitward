//! 欄位級三方合併（契約 §2.4）：純函數，不做加解密、不碰 IO。
//!
//! 座標系是**欄位路徑字串**（文法見 bw_proto::FieldEdit 文件）：
//! daemon 先按 cipher 歸屬與 item key 選鑰（官方形態＝`cipher.key` 解包出的
//! item key；舊形態＝個人 user key、共享 org 對稱金鑰，
//! 見 bitwarderd `Hub::cipher_decrypt_key`）把三個密文形態（base/ours/theirs）
//! 攤平成 `FieldMap`（明文），這裡只比較與合併明文；回傳「哪些路徑要推什麼值」。
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

/// `field.<n>.type` 欄的詞彙表（merge 座標系的明文值域）：線格式 type 整數
/// → 詞。未知整數回 None（值缺席＝讀不到，容忍漂移同信封解不開）。
#[must_use]
pub fn type_word(wire: i64) -> Option<&'static str> {
    match wire {
        0 => Some("text"),
        1 => Some("hidden"),
        2 => Some("boolean"),
        _ => None,
    }
}

/// 詞 → 線格式整數（apply_merged 寫回用）；未知詞回 None。
#[must_use]
pub fn wire_of_type_word(word: &str) -> Option<u8> {
    match word {
        "text" => Some(0),
        "hidden" => Some(1),
        "boolean" => Some(2),
        _ => None,
    }
}

/// 欄位級 3-way：ours vs base 的差異 × theirs vs base 的差異。
/// 不相交自動合併（ ours 的改動套到 theirs 上 ）；相交且值不同 → 衝突。
pub fn three_way(base: &FieldMap, ours: &FieldMap, theirs: &FieldMap) -> Merge {
    let mut push = FieldMap::new();
    let mut clashes = Vec::new();
    let mut ours_changed: Vec<&String> = Vec::new();
    let mut theirs_changed: Vec<&String> = Vec::new();
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
        let ours_changed_flag = o != b;
        let theirs_changed_flag = t != b;
        if ours_changed_flag {
            ours_changed.push(key);
        }
        if theirs_changed_flag {
            theirs_changed.push(key);
        }
        match (ours_changed_flag, theirs_changed_flag) {
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
    // 同欄 type×值撞車（批次 3 裁定）：官方改 fields[].type 連帶整欄重加密，
    // 「一端改 field.<n>.type、另一端改同欄 name/value」物理上同欄相撞——
    // 判同欄衝突進收件匣，不靜默合併。
    if clashes.is_empty() {
        for ko in &ours_changed {
            for kt in &theirs_changed {
                if let (Some((io, ty_o)), Some((it, ty_t))) = (field_slot(ko), field_slot(kt))
                    && io == it
                    && ty_o != ty_t
                {
                    clashes.push(format!("field.{io}.type"));
                }
            }
        }
        clashes.sort();
        clashes.dedup();
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

/// `field.<n>.<leaf>` 路徑的欄槽解析：回 (index, 是否 type 欄)。
fn field_slot(k: &str) -> Option<(u32, bool)> {
    let rest = k.strip_prefix("field.")?;
    let (id_s, leaf) = rest.rsplit_once('.')?;
    Some((id_s.parse::<u32>().ok()?, leaf == "type"))
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
    // 自訂欄位（v5 三件套）：`field.<n>.name`／`field.<n>.value` 以 0 起索引
    // 定址（官方 fields[] 無 id；同 uri.<n> 紀律，陣列位移視為不同欄）。
    // `field.<n>.type` 為明文詞（text|hidden|boolean）：官方改 type 连带整欄
    // 重加密，three_way 據此把同欄 type×值改動判同欄衝突（批次 3 裁定）。
    if let Some(fields) = cipher.get("fields").and_then(serde_json::Value::as_array) {
        let mut type_keys: Vec<(String, Option<String>)> = Vec::new();
        for (i, f) in fields.iter().enumerate() {
            put_enc(
                &format!("field.{i}.name"),
                f.get("name").and_then(serde_json::Value::as_str),
            );
            put_enc(
                &format!("field.{i}.value"),
                f.get("value").and_then(serde_json::Value::as_str),
            );
            if let Some(t) = f.get("type").and_then(serde_json::Value::as_i64) {
                type_keys.push((
                    format!("field.{i}.type"),
                    type_word(t).map(str::to_owned),
                ));
            }
        }
        for (k, v) in type_keys {
            m.insert(k, v);
        }
    }
    // folderId 是明文欄（同 favorite 直接轉字串）；null/缺欄＝未歸屬（鍵缺席）。
    if let Some(fid) = cipher.get("folderId").and_then(serde_json::Value::as_str) {
        m.insert("folderId".into(), Some(fid.to_string()));
    }
    if let Some(fav) = cipher.get("favorite").and_then(serde_json::Value::as_bool) {
        m.insert("favorite".into(), Some(fav.to_string()));
    }
    m
}

/// 明文索引回填的欄位組（`apply_sync` 落盤後經 `Store::set_plain_meta`／
/// `set_plain_secrets` 寫回）。欄位路徑與 [`flatten`] 同一個座標系。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlainIndex {
    pub name: Option<String>,
    pub uris: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// 自訂欄**欄名**（v5 三件套）。欄值是 Secret（§2.1 分級表
    /// `FieldValue`），hidden 欄值更不得落明文檔——這裡只收 name。
    pub field_names: Vec<String>,
}

/// 鏡像密文 → 明文索引欄。`dec` 形態同 [`flatten`]（信封字串 → 明文；
/// None＝讀不到，容忍跳過）。daemon `Hub::reindex_many` 與 Android
/// `Hub::reindex_plain` 共用這裡，欄位路徑只寫一份。
pub fn plain_index(
    cipher: &serde_json::Value,
    dec: &dyn Fn(&str) -> Option<String>,
) -> PlainIndex {
    let field = |v: Option<&serde_json::Value>| {
        v.and_then(serde_json::Value::as_str)
            .and_then(dec)
    };
    let login = cipher.get("login");
    let uris = login
        .and_then(|l| l.get("uris"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|u| u.get("uri").and_then(serde_json::Value::as_str))
                .filter_map(dec)
                .collect()
        })
        .unwrap_or_default();
    // 自訂欄：只收欄名（FieldName=Identity）；欄值是 Secret，不入明文索引。
    let field_names = cipher
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|f| f.get("name").and_then(serde_json::Value::as_str))
                .filter_map(dec)
                .collect()
        })
        .unwrap_or_default();
    PlainIndex {
        name: field(cipher.get("name")),
        uris,
        username: field(login.and_then(|l| l.get("username"))),
        password: field(login.and_then(|l| l.get("password"))),
        field_names,
    }
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
                // folderId 明文欄：Some＝UUID 字串原樣落欄、None＝清 NULL（移出資料夾）。
                "folderId" => {
                    match value {
                        Some(v) => obj.insert("folderId".into(), serde_json::json!(v)),
                        None => obj.insert("folderId".into(), serde_json::Value::Null),
                    };
                }
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
                    } else if let Some(rest) = p.strip_prefix("field.")
                        && let Some((id_s, leaf)) = rest.rsplit_once('.')
                        && let Some(idx) = id_s.parse::<usize>().ok()
                        && matches!(leaf, "name" | "value" | "type")
                    {
                        // fields[] 無 id（官方形態）：索引定址。索引越界＝跳過
                        // （陣列已被他端收縮，強插會造出缺 type/linkedId 的半套欄位；
                        // 寫入端 write_patch 在入列前就擋越界）。
                        let Some(entry) = obj
                            .get_mut("fields")
                            .and_then(serde_json::Value::as_array_mut)
                            .and_then(|arr| arr.get_mut(idx))
                            .and_then(|e| {
                                if !e.is_object() {
                                    *e = serde_json::json!({});
                                }
                                e.as_object_mut()
                            })
                        else {
                            continue;
                        };
                        if leaf == "type" {
                            // 明文詞 → 線格式整數；未知詞/清空不動現態
                            // （type 無「空」語意，None 收斂為 text）。
                            let wire = value
                                .as_deref()
                                .and_then(wire_of_type_word)
                                .unwrap_or(0);
                            entry.insert(leaf.into(), serde_json::json!(wire));
                        } else {
                            match value {
                                Some(v) => {
                                    entry.insert(leaf.into(), serde_json::json!(enc_of(v)));
                                }
                                None => {
                                    entry.insert(leaf.into(), serde_json::Value::Null);
                                }
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
    use serde_json::{Value, json};

    fn map(pairs: &[(&str, Option<&str>)]) -> FieldMap {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
            .collect()
    }

    #[test]
    fn plain_index_extracts_four_fields_and_tolerates_drift() {
        // dec 形態：`E.` 前綴＝解得開的信封、其他＝解不開（欄位漂移）。
        let dec = |s: &str| s.strip_prefix("E.").map(str::to_owned);
        let cipher = serde_json::json!({
            "name": "E.GitHub",
            "login": {
                "username": "E.alice",
                "password": "bad-mac",
                "totp": "E.seed",
                "uris": [
                    {"uri": "E.https://github.com"},
                    {"uri": "bad-mac"},
                    {"match": null}
                ]
            }
        });
        let idx = plain_index(&cipher, &dec);
        assert_eq!(idx.name.as_deref(), Some("GitHub"));
        assert_eq!(idx.username.as_deref(), Some("alice"));
        assert_eq!(idx.password, None);
        assert_eq!(idx.uris, vec!["https://github.com".to_string()]);
    }

    #[test]
    fn plain_index_without_login_is_empty() {
        let dec = |s: &str| Some(s.to_owned());
        let idx = plain_index(&serde_json::json!({"type": 2}), &dec);
        assert_eq!(idx, PlainIndex::default());
    }

    #[test]
    fn plain_index_collects_field_names_only() {
        let dec = |s: &str| s.strip_prefix("E.").map(str::to_owned);
        let cipher = serde_json::json!({
            "name": "E.GitHub",
            "fields": [
                {"name": "E.PIN", "value": "E.1234", "type": 1},
                {"name": "E.會員", "value": null, "type": 0},
                {"name": "bad-mac", "value": "E.v", "type": 0}
            ]
        });
        let idx = plain_index(&cipher, &dec);
        assert_eq!(idx.field_names, vec!["PIN".to_string(), "會員".to_string()]);
    }

    #[test]
    fn flatten_includes_field_paths_and_folder_id() {
        let dec = |s: &str| s.strip_prefix("E.").map(str::to_owned);
        let cipher = serde_json::json!({
            "name": "E.GitHub",
            "folderId": "6f1a-1",
            "fields": [
                {"name": "E.PIN", "value": "E.1234", "type": 1},
                {"name": "E.網站", "value": null, "type": 0}
            ]
        });
        let m = flatten(&cipher, &dec);
        assert_eq!(m.get("field.0.name").unwrap().as_deref(), Some("PIN"));
        assert_eq!(m.get("field.0.value").unwrap().as_deref(), Some("1234"));
        // value null → 鍵缺席（未設值不與「清空」混淆）
        assert!(!m.contains_key("field.1.value"));
        assert_eq!(m.get("field.1.name").unwrap().as_deref(), Some("網站"));
        // folderId 明文入欄；null/缺欄時鍵不存在
        assert_eq!(m.get("folderId").unwrap().as_deref(), Some("6f1a-1"));
        let nofolder = flatten(&serde_json::json!({"name": "E.x"}), &dec);
        assert!(!nofolder.contains_key("folderId"));
    }

    #[test]
    fn three_way_merges_disjoint_field_and_folder_edits() {
        // 雙裝置：A 改 field.0.value、B 改 folderId → 不同鍵自動合併（三件套
        // 的欄位級併發語意，e2e writepath 手法的單元層對應）。
        let base = map(&[("name", Some("n")), ("field.0.value", Some("v0"))]);
        let ours = map(&[("name", Some("n")), ("field.0.value", Some("v1"))]);
        let theirs = map(&[
            ("name", Some("n")),
            ("field.0.value", Some("v0")),
            ("folderId", Some("folder-A")),
        ]);
        match three_way(&base, &ours, &theirs) {
            Merge::Push(push) => {
                assert_eq!(push.get("field.0.value").unwrap().as_deref(), Some("v1"));
                assert!(!push.contains_key("folderId"), "theirs 已有的不動");
            }
            other => panic!("expect Push, got {other:?}"),
        }
        // 同欄相撞：兩端都改 field.0.value 且不同值 → 衝突（永不靜默覆蓋）。
        let theirs2 = map(&[("name", Some("n")), ("field.0.value", Some("other"))]);
        match three_way(&base, &ours, &theirs2) {
            Merge::Conflict { fields } => assert_eq!(fields, vec!["field.0.value".to_string()]),
            other => panic!("expect Conflict, got {other:?}"),
        }
    }

    #[test]
    fn apply_merged_writes_field_and_folder_paths() {
        let enc = |s: &str| format!("E.{s}");
        let theirs = serde_json::json!({
            "name": "E.old",
            "folderId": null,
            "fields": [{"name": "E.PIN", "value": "E.1", "linkedId": null, "type": 1}]
        });
        let mut merged = FieldMap::new();
        merged.insert("field.0.value".into(), Some("9999".into()));
        merged.insert("folderId".into(), Some("fid-1".into()));
        let out = apply_merged(&theirs, &merged, &enc);
        assert_eq!(out["fields"][0]["value"], json!("E.9999"));
        assert_eq!(out["fields"][0]["type"], json!(1), "type 不動");
        assert_eq!(out["folderId"], json!("fid-1"));
        // 越界索引跳過（不造半套欄位）
        let mut oob = FieldMap::new();
        oob.insert("field.7.value".into(), Some("x".into()));
        let out = apply_merged(&theirs, &oob, &enc);
        assert_eq!(out["fields"].as_array().unwrap().len(), 1);
        // None 清空：folderId→null、value→null
        let mut cleared = FieldMap::new();
        cleared.insert("folderId".into(), None);
        cleared.insert("field.0.value".into(), None);
        let out = apply_merged(&theirs, &cleared, &enc);
        assert_eq!(out["folderId"], Value::Null);
        assert_eq!(out["fields"][0]["value"], Value::Null);
    }

    #[test]
    fn field_type_edits_and_same_field_clash() {
        let dec = |s: &str| s.strip_prefix("E.").map(str::to_owned);
        let cipher = serde_json::json!({
            "name": "E.n",
            "fields": [{"name": "E.site", "value": "E.acme", "linkedId": null, "type": 0}]
        });
        let base = flatten(&cipher, &dec);
        assert_eq!(base.get("field.0.type").unwrap().as_deref(), Some("text"));

        // 一端改 type、另一端改同欄 value → 同欄衝突（type 改動連帶整欄重加密）
        let mut ours = base.clone();
        ours.insert("field.0.type".into(), Some("hidden".into()));
        let mut theirs = base.clone();
        theirs.insert("field.0.value".into(), Some("other".into()));
        match three_way(&base, &ours, &theirs) {
            Merge::Conflict { fields } => assert_eq!(fields, vec!["field.0.type".to_string()]),
            other => panic!("expect same-field Conflict, got {other:?}"),
        }
        // 另一端改**別欄**的 type（同槽位但不同 index）→ 不相交可合併
        let mut theirs2 = base.clone();
        theirs2.insert("field.1.type".into(), Some("boolean".into()));
        let mut ours2 = base.clone();
        ours2.insert("field.0.type".into(), Some("hidden".into()));
        assert!(matches!(three_way(&base, &ours2, &theirs2), Merge::Push(_)));
        // 雙方把 type 改成同值 → 涵蓋不衝突
        let mut theirs3 = base.clone();
        theirs3.insert("field.0.type".into(), Some("hidden".into()));
        match three_way(&base, &ours, &theirs3) {
            Merge::Noop => {}
            other => panic!("expect Noop, got {other:?}"),
        }

        // apply_merged 寫回線格式整數（明文詞不落盤）
        let mut m = FieldMap::new();
        m.insert("field.0.type".into(), Some("boolean".into()));
        let out = apply_merged(&cipher, &m, &dec_and_reenc);
        assert_eq!(out["fields"][0]["type"], json!(2));
        assert_eq!(out["fields"][0]["name"], "E.site", "type 改動不碰信封欄");
        // 未知詞收斂 text（0），不產生官方沒有的 type 值
        let mut bad = FieldMap::new();
        bad.insert("field.0.type".into(), Some("nope".into()));
        let out = apply_merged(&cipher, &bad, &dec_and_reenc);
        assert_eq!(out["fields"][0]["type"], json!(0));
    }

    fn dec_and_reenc(s: &str) -> String {
        format!("E.{s}")
    }

    #[test]
    fn type_word_vocabulary_roundtrips_wire() {
        assert_eq!(type_word(0), Some("text"));
        assert_eq!(type_word(1), Some("hidden"));
        assert_eq!(type_word(2), Some("boolean"));
        assert_eq!(type_word(3), None);
        assert_eq!(wire_of_type_word("hidden"), Some(1));
        assert_eq!(wire_of_type_word("weird"), None);
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
