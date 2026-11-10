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

/// `orgs` 表的一列（P4b）：金鑰材料全部是伺服器原樣信封，本層不做金鑰語意。
#[derive(Clone, Debug)]
pub struct OrgRow {
    pub id: ItemId,
    pub raw: Value,
    /// 信封字串（org key 加密的組織名）。
    pub name: Option<String>,
    /// akey：org 對稱金鑰的包裝。`2.` = owner 對稱路徑、`4.` = 成員 RSA 路徑。
    pub key: Option<String>,
    pub public_key: Option<String>,
    pub enc_private_key: Option<String>,
    pub key_verified: bool,
    pub status: Option<i64>,
    pub atype: Option<i64>,
}

/// `collections` 表的一列。
#[derive(Clone, Debug)]
pub struct CollectionRow {
    pub id: ItemId,
    pub org: ItemId,
    /// 信封字串（org key 加密的集合名）。
    pub name: Option<String>,
}

impl Store {
    /// 全量 `/sync` 回應落盤：整批在同一個 transaction 內完成，
    /// 任何一列解析失敗即全批回滾（崩壞 halfway 不留在半套鏡像）。
    /// ciphers、organizations、collections 都是全量替換語意。
    /// 回傳新游標。
    pub fn apply_sync(&self, sync: &Value) -> StoreResult<u64> {
        let ciphers = sync
            .get("ciphers")
            .and_then(Value::as_array)
            .or_else(|| sync.pointer("/objects/ciphers").and_then(Value::as_array))
            .or_else(|| sync.pointer("/data/ciphers").and_then(Value::as_array))
            .ok_or_else(|| {
                StoreError::Invalid("sync response has no `ciphers` array".to_string())
            })?;
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        // 全量重建前先快照 daemon 補寫過的 org 金鑰材料（VW 的 /sync 不含
        // encryptedPrivateKey；補齊結果要能活過每次 rebuild）。
        let preserved = snapshot_org_key_state(&tx)?;
        tx.execute_batch(
            "DELETE FROM meta_plain; DELETE FROM ciphers;
             DELETE FROM orgs; DELETE FROM collections; DELETE FROM cipher_collections;
             DELETE FROM folders; DELETE FROM attachments; DELETE FROM sends;",
        )?;
        for c in ciphers {
            let id_s = c
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("cipher missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("cipher id {id_s}: {e}")))?;
            write_cipher(&tx, id, c)?;
        }
        for o in sync_array(
            sync,
            &[
                "organizations",
                "profile.organizations",
                "objects.organizations",
            ],
        ) {
            let id_s = o
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("organization missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("organization id {id_s}: {e}")))?;
            write_org(&tx, id, o, &preserved)?;
        }
        for c in sync_array(sync, &["collections", "objects.collections"]) {
            let id_s = c
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("collection missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("collection id {id_s}: {e}")))?;
            write_collection(&tx, id, c)?;
        }
        // v5（三件套）：folders[] 全量替換（同 collections 語意）。
        for f in sync_array(sync, &["folders", "objects.folders"]) {
            let id_s = f
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("folder missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("folder id {id_s}: {e}")))?;
            write_folder(&tx, id, f)?;
        }
        // v8（Send 面）：sends[] 全量替換（VW 1.37.2 實錄 /sync 帶 sends 欄；
        // 缺欄＝空集合，語意同 collections 的寬容解析）。
        for s in sync_array(sync, &["sends", "objects.sends"]) {
            let id_s = s
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("send missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("send id {id_s}: {e}")))?;
            write_send(&tx, id, s)?;
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
    /// name/uris/自訂欄欄名後送進來；bw-store 不碰金鑰。
    /// `fields` 只含欄**名**（hidden 欄值是 Secret，不入明文索引，§2.1）。
    pub fn set_plain_meta(
        &self,
        id: ItemId,
        name: Option<&str>,
        uris: &[String],
        fields: &[String],
    ) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n = conn.execute(
            "UPDATE meta_plain SET name = ?2, uris = ?3, fields_plain = ?4 WHERE id = ?1",
            rusqlite::params![
                id.to_string(),
                name,
                serde_json::to_string(uris)?,
                serde_json::to_string(fields)?
            ],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// 值搜尋明文索引（FR 11941）。僅解鎖回填時呼叫；0600 檔承載（§2.7 R3）。
    pub fn set_plain_secrets(
        &self,
        id: ItemId,
        username: Option<&str>,
        password: Option<&str>,
    ) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE meta_plain SET username_plain = ?2, password_plain = ?3 WHERE id = ?1",
            rusqlite::params![id.to_string(), username, password],
        )?;
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

    // —— org / collection 鏡像（P4b 讀側）——

    pub fn org_count(&self) -> StoreResult<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM orgs", [], |r| r.get(0))?;
        Ok(n as u32)
    }

    pub fn org_list(&self) -> StoreResult<Vec<OrgRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(ORG_SELECT)?;
        let rows = stmt.query_map([], org_row_from)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn org(&self, id: ItemId) -> StoreResult<Option<OrgRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(&format!("{ORG_SELECT} WHERE o.id = ?1"))?;
        stmt.query_row([id.to_string()], org_row_from)
            .optional()
            .map_err(Into::into)
    }

    /// 補寫 org RSA 公開/私鑰信封（daemon 自 `GET /organizations/{id}/crypto/keys`
    /// 之類的端點撈回；`None` 欄位不動）。
    pub fn org_set_keys(
        &self,
        id: ItemId,
        public_key: Option<&str>,
        enc_private_key: Option<&str>,
    ) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE orgs SET
               public_key = COALESCE(?2, public_key),
               enc_private_key = COALESCE(?3, enc_private_key)
             WHERE id = ?1",
            rusqlite::params![id.to_string(), public_key, enc_private_key],
        )?;
        Ok(())
    }

    /// 私鑰往返驗證結果（daemon 在 `with_keys` 內用 bw-crypto 原語驗完落庫）。
    pub fn org_mark_verified(&self, id: ItemId, verified: bool) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE orgs SET key_verified = ?2 WHERE id = ?1",
            rusqlite::params![id.to_string(), verified as i64],
        )?;
        Ok(())
    }

    pub fn collection_list(&self) -> StoreResult<Vec<CollectionRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT id, org, name FROM collections ORDER BY name COLLATE NOCASE ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok(CollectionRow {
                id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                org: Uuid::parse_str(&r.get::<_, String>(1)?).unwrap_or_default(),
                name: r.get::<_, Option<String>>(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // —— 資料夾鏡像（v5 三件套）——

    /// 全量鏡像清單（name 為信封字串，解密是 daemon 的事）。
    pub fn folder_list(&self) -> StoreResult<Vec<FolderRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id, name, rev FROM folders ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(FolderRow {
                id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                name: r.get::<_, Option<String>>(1)?,
                rev: r.get::<_, Option<String>>(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// 即時落地（`POST /folders` 回包或本地補寫）：單列 upsert，不動全量語意。
    pub fn folder_put(&self, id: ItemId, folder: &Value) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        write_folder(&conn, id, folder)?;
        Ok(())
    }

    /// 刪除收斂（server `DELETE /folders/{id}` 成功後摘鏡像列）。
    pub fn folder_remove(&self, id: ItemId) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("DELETE FROM folders WHERE id = ?1", [id.to_string()])?;
        Ok(())
    }

    // —— Send 鏡像（v8）——

    /// 全量鏡像清單（伺服器 JSON 原樣；deletionDate 升序＝最快到期排前）。
    pub fn send_list(&self) -> StoreResult<Vec<Value>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT raw FROM sends ORDER BY deletion_date ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| serde_json::from_slice(&r?).map_err(Into::into))
            .collect()
    }

    /// 單列鏡像（伺服器 JSON 原樣；缺列＝None）。
    pub fn send(&self, id: ItemId) -> StoreResult<Option<Value>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let raw = conn
            .query_row("SELECT raw FROM sends WHERE id = ?1", [id.to_string()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?;
        raw.map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }

    /// 即時落地（建立/更新回包）：單列 upsert，不動全量語意（同 folder_put 紀律）。
    pub fn send_put(&self, send: &Value) -> StoreResult<()> {
        let id_s = send
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| StoreError::Invalid("send missing `id`".to_string()))?;
        let id = Uuid::parse_str(id_s)
            .map_err(|e| StoreError::Invalid(format!("send id {id_s}: {e}")))?;
        let conn = self.conn.lock().expect("store mutex poisoned");
        write_send(&conn, id, send)
    }

    /// 刪除收斂（server `DELETE /sends/{id}` 成功或 404 後摘鏡像列）。
    pub fn send_remove(&self, id: ItemId) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("DELETE FROM sends WHERE id = ?1", [id.to_string()])?;
        Ok(())
    }

    /// 線上刷新（`GET /sends` 的 `{data:[...]}` 陣列）：全量替換鏡像表
    /// （同 apply_sync 的 sends 分支語意——伺服器是真相源，本地不留孤列）。
    pub fn sends_replace(&self, items: &[Value]) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sends", [])?;
        for s in items {
            let id_s = s
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StoreError::Invalid("send missing `id`".to_string()))?;
            let id = Uuid::parse_str(id_s)
                .map_err(|e| StoreError::Invalid(format!("send id {id_s}: {e}")))?;
            write_send(&tx, id, s)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 硬刪收斂（`VaultCall::Purge` 的儲存端）：**本機鏡像永久移除**——
    /// cipher 列、明文索引、collection 歸屬、該 item 的全部 outbox 未推列、
    /// overlay 殭屍列一併清除；不發伺服器請求（调用端已判定伺服器端現態）。
    /// 回傳 actual-removed 的鏡像列數（0＝本地本來就沒有）。
    pub fn purge(&self, id: ItemId) -> StoreResult<u64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute("DELETE FROM ciphers WHERE id = ?1", [id.to_string()])?;
        tx.execute("DELETE FROM meta_plain WHERE id = ?1", [id.to_string()])?;
        tx.execute(
            "DELETE FROM cipher_collections WHERE cipher = ?1",
            [id.to_string()],
        )?;
        tx.execute(
            "DELETE FROM attachments WHERE cipher = ?1",
            [id.to_string()],
        )?;
        tx.execute("DELETE FROM outbox WHERE item = ?1", [id.to_string()])?;
        tx.execute("DELETE FROM overlay WHERE id = ?1", [id.to_string()])?;
        tx.commit()?;
        Ok(n as u64)
    }

    /// 單個 cipher 的附件鏡像列（批次 4a；欄位值為伺服器原樣）。
    pub fn attachment_list(&self, cipher: ItemId) -> StoreResult<Vec<AttachmentRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, file_name, size, size_name, key, url
             FROM attachments WHERE cipher = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([cipher.to_string()], |r| {
            Ok(AttachmentRow {
                id: r.get(0)?,
                file_name: r.get(1)?,
                size: r.get(2)?,
                size_name: r.get(3)?,
                key: r.get(4)?,
                url: r.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

/// `attachments` 表的一列（批次 4a）。
#[derive(Clone, Debug)]
pub struct AttachmentRow {
    pub id: String,
    pub file_name: Option<String>,
    pub size: Option<i64>,
    pub size_name: Option<String>,
    pub key: Option<String>,
    pub url: Option<String>,
}

/// `folders` 表的一列（v5）：名稱是伺服器原樣信封，本層不做金鑰語意。
#[derive(Clone, Debug)]
pub struct FolderRow {
    pub id: ItemId,
    pub name: Option<String>,
    pub rev: Option<String>,
}

fn write_folder(conn: &rusqlite::Connection, id: ItemId, f: &Value) -> StoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO folders(id, name, rev, raw) VALUES(?1,?2,?3,?4)",
        rusqlite::params![
            id.to_string(),
            f.get("name").and_then(Value::as_str),
            f.get("revisionDate").and_then(Value::as_str),
            serde_json::to_vec(f)?,
        ],
    )?;
    Ok(())
}

/// v8（Send 面）：單列 upsert。信封欄原樣入列（本層不判斷金鑰語意）；
/// `file.size` 在 VW 回包是**字串**（mobile 兼容形態，實錄），兩態都收。
fn write_send(conn: &rusqlite::Connection, id: ItemId, s: &Value) -> StoreResult<()> {
    let file_size = s.pointer("/file/size").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|x| x.parse().ok()))
    });
    conn.execute(
        "INSERT OR REPLACE INTO sends(id, stype, name, key, access_id, deletion_date,
            expiration_date, max_access_count, access_count, hide_email,
            file_id, file_name, file_size, rev, raw)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        rusqlite::params![
            id.to_string(),
            s.get("type").and_then(Value::as_i64).unwrap_or(0),
            s.get("name").and_then(Value::as_str),
            s.get("key").and_then(Value::as_str),
            s.get("accessId").and_then(Value::as_str),
            s.get("deletionDate").and_then(Value::as_str),
            s.get("expirationDate").and_then(Value::as_str),
            s.get("maxAccessCount").and_then(Value::as_i64),
            s.get("accessCount").and_then(Value::as_i64).unwrap_or(0),
            s.get("hideEmail").and_then(Value::as_bool).unwrap_or(false) as i64,
            s.pointer("/file/id").and_then(Value::as_str),
            s.pointer("/file/fileName").and_then(Value::as_str),
            file_size,
            s.get("revisionDate").and_then(Value::as_str),
            serde_json::to_vec(s)?,
        ],
    )?;
    Ok(())
}

const ORG_SELECT: &str = "SELECT id, raw, name, key, public_key, enc_private_key,
                                 key_verified, status, atype
                          FROM orgs o";

fn org_row_from(r: &rusqlite::Row<'_>) -> Result<OrgRow, rusqlite::Error> {
    Ok(OrgRow {
        id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
        raw: serde_json::from_slice(&r.get::<_, Vec<u8>>(1)?).unwrap_or(Value::Null),
        name: r.get::<_, Option<String>>(2)?,
        key: r.get::<_, Option<String>>(3)?,
        public_key: r.get::<_, Option<String>>(4)?,
        enc_private_key: r.get::<_, Option<String>>(5)?,
        key_verified: r.get::<_, i64>(6)? != 0,
        status: r.get::<_, Option<i64>>(7)?,
        atype: r.get::<_, Option<i64>>(8)?,
    })
}

pub(crate) fn write_cipher(conn: &rusqlite::Connection, id: ItemId, c: &Value) -> StoreResult<()> {
    let deleted_at = c.get("deletedDate").and_then(Value::as_str);
    let deleted = deleted_at.is_some();
    // v7（封存三態）：archivedDate 有值＝已封存；協定欄位原樣投影（同 deleted）
    let archived_at = c.get("archivedDate").and_then(Value::as_str);
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
    write_cipher_collections(conn, id, c)?;
    write_cipher_attachments(conn, id, c)?;
    // v5（垃圾桶三態）：軟刪列保留在 meta_plain（帶 deleted_at），由 query 的
    // `deleted` 過濾——垃圾桶列表要讀得到；硬刪走 `Store::purge` 摘列。
    conn.execute(
        "INSERT OR REPLACE INTO meta_plain(id, name, uris, kind, folder, org, favorite, updated_at, pending, deleted_at, archived_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,?9,?10)",
        rusqlite::params![
            id.to_string(),
            c.get("name").and_then(Value::as_str),
            uris_json(c),
            cipher_kind(c),
            c.get("folderId").and_then(Value::as_str),
            c.get("organizationId").and_then(Value::as_str),
            c.get("favorite").and_then(Value::as_bool).unwrap_or(false) as i64,
            rev,
            deleted_at,
            archived_at,
        ],
    )?;
    Ok(())
}

/// cipher `collectionIds[]` → 歸屬關聯（P4b）。全量替換語意：先刪後插。
/// 非 UUID 元素寬容跳過（伺服器未來可能塞非 uuid 字串，鏡像 raw 才是真相源）。
fn write_cipher_collections(conn: &rusqlite::Connection, id: ItemId, c: &Value) -> StoreResult<()> {
    conn.execute(
        "DELETE FROM cipher_collections WHERE cipher = ?1",
        [id.to_string()],
    )?;
    let Some(list) = c.get("collectionIds").and_then(Value::as_array) else {
        return Ok(());
    };
    for col in list {
        let Some(col_id) = col.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            continue;
        };
        conn.execute(
            "INSERT OR IGNORE INTO cipher_collections(cipher, collection) VALUES(?1,?2)",
            rusqlite::params![id.to_string(), col_id.to_string()],
        )?;
    }
    Ok(())
}

/// cipher `attachments{}` → 鏡像列（批次 4a）。全量替換語意同 collectionIds：
/// 先刪該 cipher 的舊列再依伺服器原樣插入。官方形態是 map（key=id）；
/// 寬容 array 形態（部分 server 變體）。欄位值一律原樣存（信封/明文不判斷）。
fn write_cipher_attachments(conn: &rusqlite::Connection, id: ItemId, c: &Value) -> StoreResult<()> {
    conn.execute("DELETE FROM attachments WHERE cipher = ?1", [id.to_string()])?;
    let empty = Vec::new();
    let list: Vec<&Value> = match c.get("attachments") {
        Some(Value::Object(m)) => m.values().collect(),
        Some(Value::Array(a)) => a.iter().collect(),
        _ => empty,
    };
    for a in list {
        let Some(aid) = a.get("id").and_then(Value::as_str) else {
            continue;
        };
        // size 官方線上是字串（"1024"），寬容數字形態
        let size = a.get("size").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        conn.execute(
            "INSERT OR REPLACE INTO attachments(id, cipher, file_name, size, size_name, key, url)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                aid,
                id.to_string(),
                a.get("fileName").and_then(Value::as_str),
                size,
                a.get("sizeName").and_then(Value::as_str),
                a.get("key").and_then(Value::as_str),
                a.get("url").and_then(Value::as_str),
            ],
        )?;
    }
    Ok(())
}

/// rebuild 前快照：org id →（public_key, enc_private_key, key_verified）。
type OrgKeyState = std::collections::HashMap<String, (Option<String>, Option<String>, i64)>;

fn snapshot_org_key_state(conn: &rusqlite::Connection) -> StoreResult<OrgKeyState> {
    let mut stmt =
        conn.prepare("SELECT id, public_key, enc_private_key, key_verified FROM orgs")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            (
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
            ),
        ))
    })?;
    rows.collect::<Result<OrgKeyState, _>>().map_err(Into::into)
}

fn write_org(
    tx: &rusqlite::Connection,
    id: ItemId,
    o: &Value,
    preserved: &OrgKeyState,
) -> StoreResult<()> {
    let raw = serde_json::to_vec(o)?;
    let keep = preserved.get(&id.to_string());
    let public_key = o
        .pointer("/keys/publicKey")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| keep.and_then(|k| k.0.clone()));
    let enc_private_key = o
        .pointer("/keys/encryptedPrivateKey")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| keep.and_then(|k| k.1.clone()));
    let key_verified = keep.map(|k| k.2).unwrap_or(0);
    tx.execute(
        "INSERT OR REPLACE INTO orgs(id, raw, name, key, public_key, enc_private_key, key_verified, status, atype)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            id.to_string(),
            raw,
            o.get("name").and_then(Value::as_str),
            o.get("key").and_then(Value::as_str),
            public_key,
            enc_private_key,
            key_verified,
            o.get("status").and_then(Value::as_i64),
            o.get("type").and_then(Value::as_i64),
        ],
    )?;
    Ok(())
}

fn write_collection(tx: &rusqlite::Connection, id: ItemId, c: &Value) -> StoreResult<()> {
    let raw = serde_json::to_vec(c)?;
    tx.execute(
        "INSERT OR REPLACE INTO collections(id, org, name, raw) VALUES(?1,?2,?3,?4)",
        rusqlite::params![
            id.to_string(),
            c.get("organizationId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            c.get("name").and_then(Value::as_str),
            raw,
        ],
    )?;
    Ok(())
}

/// 依序嘗試多個 JSON pointer 路徑，回第一個存在的陣列；全缺 → 空。
fn sync_array<'a>(sync: &'a Value, pointers: &[&str]) -> Vec<&'a Value> {
    for p in pointers {
        let path = format!("/{p}").replace('.', "/");
        if let Some(arr) = sync.pointer(&path).and_then(Value::as_array) {
            return arr.iter().collect();
        }
    }
    Vec::new()
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
    // 伺服器 wire type 原樣入索引：1 Login | 2 SecureNote | 3 Card | 4 Identity。
    // 證據：crates/bw-server/fixtures/（VW 1.37.2 實錄，type:1 == e2e 建立的 Login）
    // 與 jslib 歷史列舉 libs/common/src/enums/cipher-type.enum.ts。
    match c.get("type").and_then(Value::as_u64) {
        Some(v @ 1..=4) => Some(v as i64),
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
