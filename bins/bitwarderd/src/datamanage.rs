//! P4 資料管理：overlay tags/pin、去重、合併、unshare/move（契約 §4 缺口表第 2 列）。
//! 全部寫路徑複用 outbox（§2.4）：本地交易先行 → drain push。

use serde_json::{Value, json};
use uuid::Uuid;

use bw_proto::{DupGroup, ItemId, OverlayOpWire, Response, WtpError};
use bw_store::{MutationDraft, Overlay, OverlayOp};

use crate::hub::Hub;

fn denied(e: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: e.to_string(),
    }
}

impl Hub {
    pub fn overlay_op(
        &self,
        session: &str,
        id: ItemId,
        op: &OverlayOpWire,
    ) -> Result<Response, WtpError> {
        let _ = session;
        // overlay 列是 lazy upsert：沒讀過視為預設（預設值由 store 的 Default 定義）
        let cur: Overlay = self.store.overlay_get(id).unwrap_or_default();
        let next = match op {
            OverlayOpWire::AddTag(t) => {
                let mut tags = cur.tags.clone();
                if !tags.iter().any(|x| x == t) {
                    tags.push(t.clone());
                }
                OverlayOp::SetTags(tags)
            }
            OverlayOpWire::RemoveTag(t) => {
                OverlayOp::SetTags(cur.tags.iter().filter(|x| *x != t).cloned().collect())
            }
            OverlayOpWire::SetPinned(p) => OverlayOp::SetPinned(*p),
            OverlayOpWire::Touch => OverlayOp::TouchUsed {
                at_ms: self.store.now_ms(),
            },
        };
        self.store.overlay(id, next).map_err(denied)?;
        Ok(Response::Ok)
    }

    /// 去重：同 (uri host, username) 群集。解密掃描在 with_keys 內，只回 id。
    pub fn duplicates(&self) -> Result<Response, WtpError> {
        let metas = self
            .store
            .query(&bw_proto::Query {
                kind: Some(bw_proto::ItemKind::Login),
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(denied)?;
        let mut clusters: std::collections::BTreeMap<(String, String), Vec<ItemId>> =
            Default::default();
        for m in metas {
            let row = match self.store.item(m.id) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let key = self
                .machine
                .with_keys(|kb| {
                    let uk = kb.user_key();
                    let dec = |s: &str| bw_crypto::decrypt(uk, &s.to_string()).ok();
                    let user = row
                        .enc_cipher
                        .pointer("/login/username")
                        .and_then(Value::as_str)
                        .and_then(dec)
                        .unwrap_or_default();
                    let host = row
                        .enc_cipher
                        .pointer("/login/uris")
                        .and_then(Value::as_array)
                        .and_then(|a| a.iter().find_map(|u| u.get("uri").and_then(Value::as_str)))
                        .and_then(dec)
                        .and_then(|raw| {
                            let after = raw.split("://").nth(1).unwrap_or(raw.as_str());
                            after.split(['/']).next().map(str::to_lowercase)
                        })
                        .unwrap_or_default();
                    (host, user)
                })
                .map_err(denied)?;
            if key.0.is_empty() && key.1.is_empty() {
                continue;
            }
            clusters.entry(key).or_default().push(m.id);
        }
        let groups: Vec<DupGroup> = clusters
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .map(|((domain, _), mut ids)| {
                ids.sort_by_key(|i| i.to_string());
                DupGroup { domain, ids }
            })
            .collect();
        Ok(Response::DupGroups(groups))
    }

    /// 合併：tags 聯集進 keep（本地），dupes 走 outbox 軟刪（§2.4 唯一寫路徑）。
    pub async fn merge_dupes(
        &self,
        session: &str,
        keep: ItemId,
        dupes: &[ItemId],
    ) -> Result<Response, WtpError> {
        if dupes.is_empty() {
            return Err(denied("merge 需要至少一個 dup"));
        }
        let mut tags: Vec<String> = self.store.overlay_get(keep).unwrap_or_default().tags;
        for d in dupes {
            if let Ok(o) = self.store.overlay_get(*d) {
                for t in o.tags {
                    if !tags.contains(&t) {
                        tags.push(t);
                    }
                }
            }
        }
        self.store
            .overlay(keep, OverlayOp::SetTags(tags))
            .map_err(denied)?;
        self.write_delete(session, dupes).await
    }

    /// move / unshare：org None = unshare。鏡像先改（pending 語意正確），
    /// payload 帶目標歸屬，drain 端 PUT 時以即時 theirs 為基底改寫欄位。
    pub async fn write_move(
        &self,
        session: &str,
        item: ItemId,
        org: Option<String>,
        collections: Vec<String>,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let row = self.store.item(item).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let mut mirror = base.clone();
        if let Some(o) = mirror.as_object_mut() {
            match &org {
                Some(id) => o.insert("organizationId".into(), json!(id)),
                None => o.insert("organizationId".into(), Value::Null),
            };
            o.insert(
                "collectionIds".into(),
                Value::Array(collections.iter().map(|c| json!(c)).collect()),
            );
        }
        let raw = self.store.raw(item).map_err(denied)?;
        let rev = crate::sync::row_rev_of(&raw);
        let payload = json!({
            "op": "move",
            "org": org,
            "collections": collections,
        });
        self.store
            .enqueue(&MutationDraft {
                item,
                payload,
                base_rev: rev.as_deref(),
                origin: Some(session),
                mirror: Some(&mirror),
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    // —— 資料夾與硬刪（v5 三件套；垃圾桶三態為 Main 裁定追加）——

    /// 新建資料夾：名稱以 user key 加密後 `POST /folders`（官方客戶端語意：
    /// 資料夾屬個人 vault，不走 org key）。同步呼叫不入列——資料夾非 outbox
    /// 載體，離線時快速失敗（批次 2 GUI 再評估佇列化）。
    pub async fn create_folder(&self, name: &str) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let enc_name = self
            .machine
            .with_keys(|kb| bw_crypto::encrypt(kb.user_key(), name).map(|e| e.to_string()))
            .map_err(|_| WtpError::Locked)?
            .map_err(denied)?;
        let client = self.client().await?;
        let created = client.folder_create(&enc_name).await.map_err(crate::hub::map_server_err)?;
        let id_s = created
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::hub::drift("folders 回包缺 id"))?;
        let id = Uuid::parse_str(id_s).map_err(|_| crate::hub::drift(format!("folder id {id_s}")))?;
        self.store.folder_put(id, &created).map_err(denied)?;
        Ok(Response::Json(json!({"id": id.to_string(), "name": name})))
    }

    /// 資料夾清單：id 恆出；名稱是信封字串，解鎖態解明文、鎖定態 null
    /// （金鑰不在時不猜）。排序：明文名稱不分大小寫，未解名排後。
    pub fn list_folders(&self) -> Result<Response, WtpError> {
        let rows = self.store.folder_list().map_err(denied)?;
        let names: Option<Vec<Option<String>>> = self
            .machine
            .with_keys(|kb| {
                let key = kb.user_key().as_bytes().to_vec();
                rows.iter()
                    .map(|r| {
                        r.name.as_deref().and_then(|n| {
                            bw_crypto::decrypt_bytes_with_key(&key, n)
                                .ok()
                                .and_then(|b| String::from_utf8(b).ok())
                        })
                    })
                    .collect()
            })
            .ok();
        let mut out: Vec<Value> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({
                    "id": r.id.to_string(),
                    "name": names.as_ref().and_then(|ns| ns[i].clone()),
                })
            })
            .collect();
        out.sort_by(|a, b| {
            let name = |v: &Value| match v["name"].as_str() {
                Some(s) => (0u8, s.to_lowercase()),
                None => (1u8, String::new()),
            };
            name(a)
                .cmp(&name(b))
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
        Ok(Response::Json(Value::Array(out)))
    }

    /// 刪除資料夾（官方語意同序）：先把夾內項目 `folderId` 清 NULL
    /// （逐筆走 outbox patch，離線可收斂），再 `DELETE /folders/{id}`
    /// （404＝已不存在，冪等收斂），最後摘除鏡像列。
    /// 伺服器刪除失敗（離線）→ 回錯但項目 patch 已入列；重試收斂。
    pub async fn delete_folder(&self, session: &str, id: ItemId) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let items = self
            .store
            .query(&bw_proto::Query {
                folder: Some(id.to_string()),
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(denied)?;
        for m in items {
            self.write_patch(
                session,
                m.id,
                &[bw_proto::FieldEdit::Set {
                    path: "folderId".into(),
                    value: None,
                }],
            )
            .await?;
        }
        let client = self.client().await?;
        match client.folder_delete(id).await {
            Ok(()) => {}
            Err(e) if e.status() == Some(404) => {}
            Err(e) => return Err(crate::hub::map_server_err(e)),
        }
        self.store.folder_remove(id).map_err(denied)?;
        self.emit(
            bw_proto::EventTopic::VaultChanged,
            json!({"folder": id.to_string(), "op": "folder-delete"}),
        );
        Ok(Response::Ok)
    }

    /// 硬刪：**本機鏡像永久移除**（鏡像行＋明文索引＋關聯＋outbox＋overlay，
    /// 見 `Store::purge`）。僅開放垃圾桶項目（鏡像帶軟刪標記）；伺服器端
    /// 已被既有 DELETE 路徑軟刪，上線時補打 `DELETE /ciphers/{id}`（硬刪）
    /// 防下次 `/sync` 復活——離線則拒（純本地摘列會復活，語意不收斂）。
    pub async fn purge_item(&self, id: ItemId) -> Result<Response, WtpError> {
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        if !row.deleted {
            return Err(denied("Purge 僅開放垃圾桶項目（先 rm 軟刪）"));
        }
        let client = self.client().await?;
        match client.cipher_delete(id, bw_server::DeleteKind::Hard).await {
            Ok(()) => {}
            Err(e) if e.status() == Some(404) => {}
            Err(e) => return Err(crate::hub::map_server_err(e)),
        }
        let n = self.store.purge(id).map_err(denied)?;
        self.emit(
            bw_proto::EventTopic::VaultChanged,
            json!({"id": id.to_string(), "op": "purge"}),
        );
        Ok(Response::Json(json!({"purged": id.to_string(), "mirror_rows": n})))
    }

    /// 原子批次匯入（`VaultCall::Import`；語意見 proto 端註解）：
    /// 驗證全部条目（上限 500、名稱非空、folder_id 為 UUID）→ 全部加密
    /// （`with_keys` 單閉包）→ **單交易**鏡像＋outbox 全收或全拒 →
    /// 逐筆落本地明文索引＋overlay 標籤 → 觸發一次 drain（逐筆推 VW，
    /// 失敗走既有 outbox 重試/衝突佇列，非分散式事務）。
    /// `format` 為官方 import 格式參數佔位，本批不分支。
    pub async fn write_import(
        &self,
        session: &str,
        items: &[bw_proto::ImportItem],
        _format: bool,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        if items.is_empty() {
            return Ok(Response::Json(json!({"imported": 0, "ids": []})));
        }
        if items.len() > 500 {
            return Err(denied(format!(
                "單批上限 500 筆（got {}），請分批",
                items.len()
            )));
        }
        for (i, it) in items.iter().enumerate() {
            if it.draft.name.trim().is_empty() {
                return Err(denied(format!("第 {i} 筆缺名稱")));
            }
            if let Some(f) = &it.draft.folder_id {
                Uuid::parse_str(f)
                    .map_err(|_| denied(format!("第 {i} 筆 folder_id 需為 UUID，got {f:?}")))?;
            }
        }
        // 全批加密（encrypt_draft 自持 with_keys 閉包，金鑰不出閉包）
        let ids: Vec<Uuid> = items.iter().map(|_| Uuid::new_v4()).collect();
        let mut ciphers = Vec::with_capacity(items.len());
        for (id, it) in ids.iter().zip(items) {
            ciphers.push(self.encrypt_draft(&it.draft, Some(*id))?);
        }
        let drafts: Vec<bw_store::MutationDraft<'_>> = ciphers
            .iter()
            .zip(&ids)
            .map(|(cipher, id)| {
                let mut body = cipher.clone();
                if let Some(o) = body.as_object_mut() {
                    o.remove("id");
                }
                bw_store::MutationDraft {
                    item: *id,
                    payload: json!({"op": "create", "cipher": body}),
                    base_rev: None,
                    origin: Some(session),
                    mirror: Some(cipher),
                }
            })
            .collect();
        let mids = self.store.enqueue_batch(&drafts).map_err(denied)?;
        for (i, it) in items.iter().enumerate() {
            if !it.tags.is_empty() {
                let mut tags = self.store.overlay_get(ids[i]).unwrap_or_default().tags;
                for t in &it.tags {
                    if !tags.contains(t) {
                        tags.push(t.clone());
                    }
                }
                let _ = self.store.overlay(ids[i], bw_store::OverlayOp::SetTags(tags));
            }
        }
        self.reindex_many(&ids)?;
        self.trigger_drain();
        Ok(Response::Json(json!({
            "imported": mids.len(),
            "ids": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        })))
    }
}
