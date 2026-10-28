//! 鏡像寫入：密文原樣落盤 + raw 保留 + meta_plain 重建（同交易）。

use bw_proto::ItemId;
use rusqlite::OptionalExtension;
use serde_json::Value;
use uuid::Uuid;

use crate::{Store, StoreError, StoreResult, unix_ms};

pub struct CipherRow {
    pub id: ItemId,
    /// 伺服器 cipher JSON，剝掉 revisionDate/deletedDate 後的形态（信封不改寫）。
    pub enc_cipher: Value,
    /// 伺服器 cipher JSON 原樣。
    pub raw: Value,
    pub rev: Option<String>,
    pub deleted: bool,
}

impl Store {
    /// 全量 `/sync` 回應落盤：整批在同一個 transaction 內完成，
    /// 任何一列解析失敗即全批回滾（崩壞 halfway 不留在半套鏡像）。
    /// 回傳新游標。
    pub fn apply_sync(&self, sync: &Value) -> StoreResult<u64> {
        let ciphers = sync
            .get("ciphers")
            .and_then(Value::as_array)
            .or_else(|| sync.pointer("/data/ciphers").and_then(Value::as_array))
            .ok_or_else(|| {
                StoreError::Invalid("sync response has no `ciphers` array".to_string())
            })?;
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch("DELETE FROM meta_plain; DELETE FROM ciphers;")?;
        for c in ciphers {
            let id_s = c
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("cipher missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("cipher id {id_s}: {e}")))?;
            write_cipher(&tx, id, c)?;
        }
        if let Some(sd) = sync.get("serverDate").and_then(Value::as_str) {
            tx.execute(
                "INSERT INTO meta(key, value) VALUES('server_date', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [sd],
            )?;
        }
        let cursor = crate::meta_u64(&tx, "cursor").unwrap_or(0) + 1;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES('cursor', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [cursor.to_string()],
        )?;
        refresh_pending(&tx, None)?;
        tx.commit()?;
        drop(conn);
        tracing::debug!(cursor, ciphers = ciphers.len(), "apply_sync done");
        Ok(cursor)
    }

    /// 解鎖路徑專用的明文索引回填：呼叫端（daemon）在 `with_keys` 內解密
    /// name/uris 後送進來；bw-store 不碰金鑰。
    pub fn set_plain_meta(
        &self,
        id: ItemId,
        name: Option<&str>,
        uris: &[String],
    ) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n = conn.execute(
            "UPDATE meta_plain SET name = ?2, uris = ?3 WHERE id = ?1",
            rusqlite::params![id.to_string(), name, serde_json::to_string(uris)?],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn item(&self, id: ItemId) -> StoreResult<Option<CipherRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let row = conn
            .query_row(
                "SELECT enc_cipher, raw, rev, deleted FROM ciphers WHERE id = ?1",
                [id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((enc, raw, rev, deleted)) = row else {
            return Ok(None);
        };
        Ok(Some(CipherRow {
            id,
            enc_cipher: serde_json::from_slice(&enc)?,
            raw: serde_json::from_slice(&raw)?,
            rev,
            deleted: deleted != 0,
        }))
    }

    /// raw 鏡像（未建模欄位的真相源）。
    pub fn raw(&self, id: ItemId) -> StoreResult<Value> {
        self.item(id)?.map(|r| r.raw).ok_or(StoreError::NotFound)
    }

    /// 目前鏡像列數（含 tombstone），餵 `UnlockStateView::AuthLocked { items }`。
    pub fn cipher_count(&self) -> StoreResult<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM ciphers", [], |r| r.get(0))?;
        Ok(n as u32)
    }

    /// 本地新增（draft）的鏡像列寫入：P2 前的最小入口，與 outbox 同交易見
    /// `enqueue`（帶 `mirror` 時）。
    pub fn put_mirror(&self, id: ItemId, cipher: &Value) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        write_cipher(&conn, id, cipher)?;
        refresh_pending(&conn, Some(id))?;
        Ok(())
    }

    /// 附件/blob 落地排程用的時間戳（unix ms），提供給呼叫端避免各自取時鐘。
    pub fn now_ms(&self) -> u64 {
        unix_ms()
    }
}

pub(crate) fn write_cipher(conn: &rusqlite::Connection, id: ItemId, c: &Value) -> StoreResult<()> {
    let deleted = c.get("deletedDate").and_then(Value::as_str).is_some();
    let rev = c.get("revisionDate").and_then(Value::as_str);
    let raw = serde_json::to_vec(c)?;
    let mut enc = c.clone();
    if let Some(o) = enc.as_object_mut() {
        o.remove("revisionDate");
        o.remove("deletedDate");
    }
    let enc_blob = serde_json::to_vec(&enc)?;
    conn.execute(
        "INSERT OR REPLACE INTO ciphers(id, enc_cipher, raw, rev, deleted) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![id.to_string(), enc_blob, raw, rev, deleted as i64],
    )?;
    if deleted {
        conn.execute("DELETE FROM meta_plain WHERE id = ?1", [id.to_string()])?;
    } else {
        conn.execute(
            "INSERT OR REPLACE INTO meta_plain(id, name, uris, kind, folder, org, favorite, updated_at, pending)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)",
            rusqlite::params![
                id.to_string(),
                c.get("name").and_then(Value::as_str),
                uris_json(c),
                cipher_kind(c),
                c.get("folderId").and_then(Value::as_str),
                c.get("organizationId").and_then(Value::as_str),
                c.get("favorite").and_then(Value::as_bool).unwrap_or(false) as i64,
                rev,
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn refresh_pending(tx: &rusqlite::Connection, item: Option<ItemId>) -> StoreResult<()> {
    let sql = match item {
        Some(_) => {
            "UPDATE meta_plain SET pending = EXISTS(
                        SELECT 1 FROM outbox o WHERE o.item = ?1
                          AND o.state IN ('queued','in_flight','awaiting'))
                    WHERE id = ?1"
        }
        None => {
            "UPDATE meta_plain SET pending = EXISTS(
                        SELECT 1 FROM outbox o WHERE o.item = meta_plain.id
                          AND o.state IN ('queued','in_flight','awaiting'))"
        }
    };
    match item {
        Some(id) => {
            tx.execute(sql, [id.to_string()])?;
        }
        None => {
            tx.execute_batch(sql)?;
        }
    }
    Ok(())
}

fn cipher_kind(c: &Value) -> Option<i64> {
    match c.get("type").and_then(Value::as_u64) {
        Some(v @ 0..=3) => Some(v as i64),
        _ => None,
    }
}

fn uris_json(c: &Value) -> String {
    let uris: Vec<String> = c
        .pointer("/login/uris")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|u| u.get("uri").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_string(&uris).unwrap_or_else(|_| "[]".to_string())
}
