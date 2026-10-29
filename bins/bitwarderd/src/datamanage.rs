//! P4 資料管理：overlay tags/pin、去重、合併、unshare/move（契約 §4 缺口表第 2 列）。
//! 全部寫路徑複用 outbox（§2.4）：本地交易先行 → drain push。

use serde_json::{Value, json};

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
}
