//! 讀路徑：只回 `ItemMeta`（Opaque+Identity），永不含 Secret。

use bw_proto::{ItemKind, ItemMeta, Query, SortKey};
use rusqlite::{Connection, Row};
use uuid::Uuid;

use crate::{Store, StoreError, StoreResult};

impl Store {
    pub fn query(&self, q: &Query) -> StoreResult<Vec<ItemMeta>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut sql = String::from(
            "SELECT m.id, m.name, m.uris, m.kind, m.folder, m.org, m.favorite,
                    m.updated_at, m.pending, COALESCE(o.tags, '[]'),
                    COALESCE(cc.cols, '[]'), m.deleted_at, m.archived_at
             FROM meta_plain m
             JOIN ciphers c ON c.id = m.id
             LEFT JOIN overlay o ON o.id = m.id
             LEFT JOIN (SELECT cipher, json_group_array(collection) AS cols
                        FROM cipher_collections GROUP BY cipher) cc ON cc.cipher = m.id
             WHERE 1=1",
        );
        let mut args: Vec<String> = Vec::new();
        let mut like_fallback: Option<String> = None;
        let mut uri_host: Option<String> = None;

        // 垃圾桶三態（語意見 bw_proto::Query::deleted）：預設只列未刪。
        match q.deleted {
            Some(true) => sql.push_str(" AND c.deleted = 1"),
            Some(false) | None => sql.push_str(" AND c.deleted = 0"),
        }
        // 封存三態（語意見 bw_proto::Query::archived）：主列表預設排除已封存，
        // 與 deleted 正交合成（封存＋軟刪的列只同時命中各自 true 態的查詢）。
        match q.archived {
            Some(true) => sql.push_str(" AND m.archived_at IS NOT NULL"),
            Some(false) | None => sql.push_str(" AND m.archived_at IS NULL"),
        }
        if let Some(text) = q.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            match fts_match(text) {
                Some(m) => {
                    sql.push_str(
                        " AND m.rowid IN (SELECT rowid FROM meta_fts WHERE meta_fts MATCH ?",
                    );
                    args.push(m);
                    sql.push(')');
                }
                None => {
                    let esc = escape_like(text);
                    like_fallback = Some(esc);
                }
            }
        }
        if let Some(esc) = &like_fallback {
            sql.push_str(
                " AND (m.name LIKE ?1 ESCAPE '\\' OR m.uris LIKE ?1 ESCAPE '\\'
                       OR m.fields_plain LIKE ?1 ESCAPE '\\')",
            );
            args.push(format!("%{esc}%"));
        }
        if let Some(tag) = q.tag.as_deref().filter(|t| !t.is_empty()) {
            sql.push_str(
                " AND EXISTS(SELECT 1 FROM json_each(COALESCE(o.tags,'[]')) WHERE value = ?)",
            );
            args.push(tag.to_string());
        }
        if let Some(uri) = q.uri.as_deref().filter(|t| !t.is_empty()) {
            // host 錨定（P5-b3）：查詢可帶整頁 URL，比對 host 相等或子網域後綴。
            // SQL LIKE 用 host 做預篩，真實判定在 Rust 端對存儲 uris 逐筆比。
            let want = host_of(uri).unwrap_or_else(|| uri.to_ascii_lowercase());
            sql.push_str(" AND m.uris LIKE ?");
            args.push(format!("%{want}%"));
            uri_host = Some(want);
        }
        if let Some(val) = q.value.as_deref().filter(|t| !t.is_empty()) {
            // 值搜尋走明文索引欄（解鎖回填後才有資料）；大小寫敏感＝精確比對語意
            sql.push_str(" AND (m.username_plain = ? OR m.password_plain = ?)");
            args.push(val.to_string());
            args.push(val.to_string());
        }
        if let Some(kind) = q.kind {
            sql.push_str(" AND m.kind = ?");
            args.push(kind_index(kind).to_string());
        }
        if let Some(col) = q.collection {
            // 集合過濾走歸屬關聯表（apply_sync / put_mirror 落庫時重建）
            sql.push_str(
                " AND EXISTS(SELECT 1 FROM cipher_collections cx
                                      WHERE cx.cipher = m.id AND cx.collection = ?)",
            );
            args.push(col.to_string());
        }
        if let Some(folder) = q.folder.as_deref() {
            // 三態（語意見 bw_proto::Query::folder）：空字串＝未歸屬。
            // 鏡像 `folderId` 由 write_cipher 直存原字串，比對不走 UUID 解析。
            if folder.is_empty() {
                sql.push_str(" AND m.folder IS NULL");
            } else {
                sql.push_str(" AND m.folder = ?");
                args.push(folder.to_string());
            }
        }
        sql.push_str(" ORDER BY ");
        sql.push_str(match q.sort {
            SortKey::Name => "m.name COLLATE NOCASE ASC",
            SortKey::Updated => "m.updated_at DESC",
            // creationDate 不是 meta_plain 欄位：直接從 raw 鏡像抽（JSON1）。
            SortKey::Created => "json_extract(c.raw, '$.creationDate') DESC",
            SortKey::Used => "COALESCE(o.last_used, 0) DESC",
        });
        sql.push_str(", m.id ASC");
        if q.limit > 0 {
            sql.push_str(" LIMIT ?");
            args.push(q.limit.to_string());
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), row_to_meta)?;
        let mut out = rows.collect::<Result<Vec<_>, _>>()?;
        if let Some(want) = uri_host {
            out.retain(|m| {
                m.uris.iter().any(|u| {
                    host_of(u).is_some_and(|h| h == want || h.ends_with(&format!(".{want}")))
                })
            });
        }
        Ok(out)
    }

    /// 鏡像全 id（不分 deleted／archived 三態）：給「每列都要處理一次」的
    /// 回填／稽核路徑用。列表三態過濾是讀路徑語意，拿它圈定回填範圍會漏列
    /// （2026-11-11 實錄：預設＋垃圾桶兩條查詢圈定的 reindex 永遠跳過已封存列）。
    pub fn all_ids(&self) -> StoreResult<Vec<bw_proto::ItemId>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id FROM meta_plain ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| {
            let s = r?;
            Uuid::parse_str(&s).map_err(|e| StoreError::Invalid(format!("meta_plain id {s}: {e}")))
        })
        .collect()
    }

    /// 單筆取回（含 tombstone 判定交給呼叫端的 `CipherRow.deleted`）。
    pub fn meta(&self, id: bw_proto::ItemId) -> StoreResult<Option<ItemMeta>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        meta_by_id(&conn, id)
    }
}

pub(crate) fn meta_by_id(conn: &Connection, id: bw_proto::ItemId) -> StoreResult<Option<ItemMeta>> {
    use rusqlite::OptionalExtension;
    let mut stmt = conn.prepare(
        "SELECT m.id, m.name, m.uris, m.kind, m.folder, m.org, m.favorite,
                m.updated_at, m.pending, COALESCE(o.tags, '[]'),
                COALESCE((SELECT json_group_array(cx.collection)
                          FROM cipher_collections cx WHERE cx.cipher = m.id), '[]'),
                m.deleted_at, m.archived_at
         FROM meta_plain m LEFT JOIN overlay o ON o.id = m.id WHERE m.id = ?1",
    )?;
    stmt.query_row([id.to_string()], row_to_meta)
        .optional()
        .map_err(Into::into)
}

fn row_to_meta(row: &Row<'_>) -> Result<ItemMeta, rusqlite::Error> {
    let id = Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default();
    let uris_raw = row.get::<_, String>(2)?;
    let uris = parse_string_array(&uris_raw);
    let tags = parse_string_array(&row.get::<_, String>(9)?);
    let collections = parse_string_array(&row.get::<_, String>(10)?)
        .into_iter()
        .filter_map(|s| Uuid::parse_str(&s).ok())
        .collect();
    let kind = match row.get::<_, Option<i64>>(3)? {
        Some(v) => index_kind(v),
        None => ItemKind::Login,
    };
    Ok(ItemMeta {
        id,
        kind,
        name: row.get::<_, Option<String>>(1)?,
        uris,
        folder_id: row
            .get::<_, Option<String>>(4)?
            .and_then(|s| Uuid::parse_str(&s).ok()),
        organization_id: row
            .get::<_, Option<String>>(5)?
            .and_then(|s| Uuid::parse_str(&s).ok()),
        collections,
        favorite: row.get::<_, i64>(6)? != 0,
        tags,
        updated_at: row.get::<_, Option<String>>(7)?,
        pending: row.get::<_, i64>(8)? != 0,
        deleted_at: row.get::<_, Option<String>>(11)?,
        archived_at: row.get::<_, Option<String>>(12)?,
        // match 判定存鏡像不在 meta_plain：列表（Metadata 視窗）恆空，
        // 編輯基準由 project_one 的 Masked/Reveal 路徑回填。
        uri_matches: Vec::new(),
    })
}

fn parse_string_array(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// `https://host[:port]/path` → `host`（小寫）。無 scheme 時整串當 host。
fn host_of(uri: &str) -> Option<String> {
    let after = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri);
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn kind_index(k: ItemKind) -> i64 {
    // 與 wire type 對齊（見 ciphers::cipher_kind 出處）
    match k {
        ItemKind::Login => 1,
        ItemKind::SecureNote => 2,
        ItemKind::Card => 3,
        ItemKind::Identity => 4,
    }
}

fn index_kind(v: i64) -> ItemKind {
    match v {
        2 => ItemKind::SecureNote,
        3 => ItemKind::Card,
        4 => ItemKind::Identity,
        _ => ItemKind::Login,
    }
}

/// 使用者文字 → FTS5 MATCH 字串：逐 token 加引號並做前綴匹配。
/// token 切分規則對齊 fts5 unicode61 的分詞邊界（§4 缺口「值搜尋」v1 只索引 name/uris）。
fn fts_match(text: &str) -> Option<String> {
    let toks: Vec<String> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect();
    if toks.is_empty() {
        None
    } else {
        Some(toks.join(" AND "))
    }
}

pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts_match_quotes_and_prefixes() {
        assert_eq!(fts_match("git hub").unwrap(), "\"git\"* AND \"hub\"*");
        // 引號是分詞邊界：只留下內層 token
        assert_eq!(fts_match("\"quoted\"").unwrap(), "\"quoted\"*");
        assert!(fts_match("///").is_none());
    }

    #[test]
    fn escape_like_masks_wildcards() {
        assert_eq!(escape_like("50%_a\\b"), "50\\%\\_a\\\\b");
    }

    #[test]
    fn meta_columns_contain_no_secret_fields() {
        // 防呆：query 選擇的欄位都是 Opaque/Identity 級（§2.1 分級表）。
        let cols = [
            "id",
            "name",
            "uris",
            "kind",
            "folder",
            "org",
            "collections",
            "favorite",
            "updated_at",
            "pending",
            "tags",
            "deleted_at",
            "archived_at",
        ];
        for c in cols {
            assert!(
                !matches!(
                    c,
                    "password" | "notes" | "totp" | "username" | "enc_cipher" | "raw"
                ),
                "secret-bearing column {c} leaked into query surface"
            );
        }
    }
}
