//! 官方 JSON 匯入器（本地兜底：daemon 目前沒有 import 呼叫面，2b 實查）。
//! 吃兩種形態——本 App 匯出（陣列 `[{name,username,password,uri,tags}]`）
//! 與官方 Bitwarden 未加密匯出（`{encrypted:false, items:[{type,name,login,
//! notes,folderId,fields,...}]}`）。解析與計數全在本地純函數；落地走既有
//! `Vault:Create`（＋tags overlay），零新 daemon 依賴。
//!
//! 明文紀律：匯入是匯出的鏡像入口——明文只在 worker 區域與 `Zeroizing`
//! 副本短暫存在，進 Outgoing 幀即出棧；預覽只回計數，不回明文。

use bw_proto::{
    Call, CipherDraft, CipherField, ImportItem, ItemKind, Response, VaultCall,
};

use crate::btp::Session;

/// 單次匯入上限（防呆：誤指大檔不炸 daemon）。
pub const MAX_ROWS: usize = 5000;

/// 一筆待建立項目（兩來源格式歸一後的內部形）。
#[derive(Clone, Debug, PartialEq)]
pub struct ImportRow {
    pub kind: ItemKind,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub fields: Vec<CipherField>,
}

/// 解析結果：可匯入列＋因缺名等跳過的筆數。
#[derive(Debug, PartialEq)]
pub struct Parsed {
    pub rows: Vec<ImportRow>,
    pub skipped: usize,
}

/// 純解析（可單測）：偵測形態、型別映射、加密匯出擋下。
pub fn parse(text: &str) -> Result<Parsed, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("不是有效的 JSON：{e}"))?;
    let items: &Vec<serde_json::Value> = match &v {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(obj) => {
            if obj.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
                return Err("此檔是加密匯出（encrypted:true），請選「未加密 JSON」匯出檔".into());
            }
            obj.get("items")
                .and_then(|i| i.as_array())
                .ok_or_else(|| "找不到 items 陣列（非 Bitwarden JSON 匯出？）".to_owned())?
        }
        _ => return Err("JSON 頂層需為陣列或含 items 的物件".into()),
    };
    if items.len() > MAX_ROWS {
        return Err(format!("單次匯入上限 {MAX_ROWS} 筆（本檔 {} 筆）", items.len()));
    }
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for it in items {
        match row_from(it) {
            Some(r) => rows.push(r),
            None => skipped += 1,
        }
    }
    Ok(Parsed { rows, skipped })
}

/// 單列解析：無名字即跳過（官方匯入器同為跳過語意，不中止整批）。
fn row_from(it: &serde_json::Value) -> Option<ImportRow> {
    let name = it.get("name").and_then(|n| n.as_str())?.trim().to_owned();
    if name.is_empty() {
        return None;
    }
    let kind = match it.get("type").and_then(|t| t.as_i64()) {
        Some(2) => ItemKind::SecureNote,
        Some(3) => ItemKind::Card,
        Some(4) => ItemKind::Identity,
        _ => ItemKind::Login,
    };
    let s = |key: &str| {
        it.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .filter(|t| !t.is_empty())
    };
    // 本 App 匯出：flat username/password/uri；官方：login 子物件。
    let login = it.get("login");
    let username = s("username").or_else(|| {
        login
            .and_then(|l| l.get("username"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    });
    let password = s("password").or_else(|| {
        login
            .and_then(|l| l.get("password"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    });
    let mut uris: Vec<String> = Vec::new();
    if let Some(u) = s("uri") {
        uris.push(u);
    }
    if let Some(list) = login.and_then(|l| l.get("uris")).and_then(|u| u.as_array()) {
        for u in list {
            if let Some(s) = u.get("uri").and_then(|x| x.as_str()) {
                uris.push(s.to_owned());
            }
        }
    }
    let tags: Vec<String> = it
        .get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let fields: Vec<CipherField> = it
        .get("fields")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    let fname = f.get("name").and_then(|n| n.as_str())?.to_owned();
                    let kind = bw_proto::CipherFieldKind::from_wire(
                        f.get("type").and_then(|t| t.as_i64()).unwrap_or(0),
                    );
                    Some(CipherField {
                        name: fname,
                        value: f
                            .get("value")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                        kind,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ImportRow {
        kind,
        name,
        username,
        password,
        uris,
        notes: s("notes"),
        folder_id: s("folderId"),
        favorite: it
            .get("favorite")
            .and_then(|f| f.as_bool())
            .unwrap_or(false),
        tags,
        fields,
    })
}

/// 讀檔（worker 執行緒）：路徑不存在/無權限時回繁中錯誤供模態顯示。
pub fn read_text(path: &str) -> Result<String, String> {
    if path.trim().is_empty() {
        return Err("請先貼上檔案路徑".into());
    }
    std::fs::read_to_string(path).map_err(|e| format!("讀不到「{path}」：{e}"))
}

/// 匯入結果（結果列文案來源）。語意：跳過＝本地過濾（缺名）不進 items；
/// 失敗＝daemon 整批拒收（單交易全收或全拒），此時 created=0、failed=送件數。
#[derive(Clone, Debug, Default)]
pub struct ImportOutcome {
    pub created: usize,
    pub failed: usize,
    pub skipped: usize,
    pub reason: Option<String>,
}

/// 解析列 → `VaultCall::Import` 的 items（純函數，可單測）。
/// 明文紀律：password 在此原樣搬進 draft，序列化進 Outgoing 幀即出棧。
pub fn to_items(rows: &[ImportRow]) -> Vec<ImportItem> {
    rows.iter()
        .map(|r| ImportItem {
            draft: CipherDraft {
                kind: r.kind,
                name: r.name.clone(),
                username: r.username.clone(),
                password: r.password.clone(),
                totp: None,
                uris: r.uris.clone(),
                notes: r.notes.clone(),
                favorite: r.favorite,
                folder_id: r.folder_id.clone(),
                fields: r.fields.clone(),
            },
            tags: r.tags.clone(),
        })
        .collect()
}

/// 在 worker 執行緒跑匯入：本地解析（預覽同源）→ 單交易 `VaultCall::Import`。
/// 大檔不再非原子；drain 推 VW 失敗走 daemon 既有 outbox 重試，不影響此處計數。
pub fn run(session: &Session, text: &str) -> Result<ImportOutcome, String> {
    let Parsed { rows, skipped } = parse(text)?;
    if rows.is_empty() {
        return Ok(ImportOutcome {
            created: 0,
            failed: 0,
            skipped,
            reason: None,
        });
    }
    let items = to_items(&rows);
    match session.call(&Call::Vault(VaultCall::Import { items, format: false })) {
        Ok(Response::Json(v)) => Ok(ImportOutcome {
            created: v.get("imported").and_then(|n| n.as_u64()).unwrap_or(0) as usize,
            failed: 0,
            skipped,
            reason: None,
        }),
        Ok(other) => Ok(ImportOutcome {
            created: 0,
            failed: rows.len(),
            skipped,
            reason: Some(format!("Import 回應形態不符：{other:?}")),
        }),
        Err(e) => Ok(ImportOutcome {
            created: 0,
            failed: rows.len(),
            skipped,
            reason: Some(e.display()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_own_export_shape() {
        let text = r#"[
            {"name":"A","username":"u","password":"p","uri":"https://a","tags":["t1","t2"]},
            {"name":"B","username":null,"password":null,"uri":null,"tags":[]},
            {"name":"  ","username":"x"}
        ]"#;
        let p = parse(text).unwrap();
        assert_eq!(p.rows.len(), 2, "空名應跳過");
        assert_eq!(p.skipped, 1);
        assert_eq!(p.rows[0].tags, vec!["t1".to_owned(), "t2".to_owned()]);
        assert_eq!(p.rows[0].uris, vec!["https://a".to_owned()]);
        assert_eq!(p.rows[1].name, "B");
    }

    #[test]
    fn parses_official_items_shape() {
        let text = r#"{
            "encrypted": false,
            "items": [
                {"type":1,"name":"Google","favorite":true,"notes":"hi","folderId":"f-1",
                 "login":{"username":"g","password":"pw","uris":[{"uri":"https://g","match":null}]},
                 "fields":[{"name":"pin","value":"1234","type":1},{"name":"web","value":"x","type":0}]},
                {"type":2,"name":"筆記","login":null,"notes":"內容"}
            ]
        }"#;
        let p = parse(text).unwrap();
        assert_eq!(p.rows.len(), 2);
        let g = &p.rows[0];
        assert_eq!(g.kind, ItemKind::Login);
        assert!(g.favorite);
        assert_eq!(g.folder_id.as_deref(), Some("f-1"));
        assert_eq!(g.uris, vec!["https://g".to_owned()]);
        assert_eq!(g.fields.len(), 2);
        assert_eq!(g.fields[0].kind, bw_proto::CipherFieldKind::Hidden);
        assert_eq!(g.fields[1].kind, bw_proto::CipherFieldKind::Text);
        assert_eq!(p.rows[1].kind, ItemKind::SecureNote);
    }

    #[test]
    fn rejects_encrypted_and_junk() {
        assert!(parse(r#"{"encrypted":true,"items":[]}"#).is_err());
        assert!(parse(r#"{"nope":1}"#).is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn empty_name_counts_as_skipped_not_row() {
        let p = parse(r#"[{"name":""},{"name":null}]"#).unwrap();
        assert!(p.rows.is_empty());
        assert_eq!(p.skipped, 2);
    }

    #[test]
    fn to_items_builds_atomic_import_request() {
        let p = parse(
            r#"{"encrypted":false,"items":[
                {"type":1,"name":"A","login":{"username":"u","password":"p"},
                 "fields":[{"name":"vip","value":"true","type":2}]},
                {"type":2,"name":"N","notes":"x"}
            ]}"#,
        )
        .unwrap();
        let items = to_items(&p.rows);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].draft.name, "A");
        assert_eq!(items[0].draft.password.as_deref(), Some("p"));
        assert_eq!(items[0].draft.fields[0].kind, bw_proto::CipherFieldKind::Boolean);
        assert_eq!(items[1].draft.kind, ItemKind::SecureNote);
        assert_eq!(items[1].draft.notes.as_deref(), Some("x"));
    }
}
