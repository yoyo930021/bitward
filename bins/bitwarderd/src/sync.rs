//! P2 寫入路徑：enqueue（入列即加密）→ drain（base_rev CAS + 欄位級三方合併）
//! → notifications targeted pull（多中樞收斂，§1.1、§2.4）。
//!
//! outbox payload 契約（JSON）：
//! - create: `{"op":"create","cipher":<無 id 的加密 cipher>}`
//! - patch:  `{"op":"patch","base":<变更前加密 cipher>,"ours":<变更后加密 cipher>,"touched":[paths]}`
//! - delete: `{"op":"delete"}` ／ restore: `{"op":"restore"}`
//!
//! 協議限制：Bitwarden 的 PUT 沒有伺服器端 CAS（revisionDate 只用於比對，
//! -push 一律覆寫）。本實作在 push 前 GET 比較縮小窗口，最終一致由 FIFO +
//! 收件匣保證；真正的併發競態（比較後、推送前被改）留給跨裝置 e2e 量化。

use serde_json::{Value, json};
use uuid::Uuid;

use bw_proto::{
    CipherDraft, ConflictEntry, EventTopic, FieldEdit, ItemId, MutationId, Resolution, Response,
    WtpError,
};
use bw_server::DeleteKind;
use bw_store::{MutState, Mutation, MutationDraft};

use crate::hub::Hub;

/// 409/412 之外的「服務器上該 cipher 不存在」判定
fn is_not_found(e: &bw_server::ServerError) -> bool {
    e.status() == Some(404)
}

impl Hub {
    pub fn trigger_drain(&self) {
        let _ = self.drain_tx.send(());
    }

    pub fn emit(&self, topic: EventTopic, payload: Value) {
        let _ = self.events.send((topic, payload));
    }

    pub(crate) fn require_unlocked(&self) -> Result<(), WtpError> {
        if self.machine.is_unlocked() {
            Ok(())
        } else {
            Err(WtpError::Locked)
        }
    }

    /// 同步路徑的 client：8 秒 timeout。離線時快速失敗回 Queued 等下次觸發，
    /// 不能讓 drain_lock 掛在 OS 代理的半開連線上有幾十秒（writepath 實測教訓）。
    pub fn sync_options() -> bw_server::ClientOptions {
        bw_server::ClientOptions {
            request_timeout: std::time::Duration::from_secs(8),
            ..Default::default()
        }
    }

    async fn client(&self) -> Result<std::sync::Arc<bw_server::Client>, WtpError> {
        let g = self.server.read().await;
        g.as_ref()
            .map(|h| h.client.clone())
            .ok_or(WtpError::NotFound)
    }

    // —— enqueue 側 ——

    pub async fn write_create(
        &self,
        session: &str,
        draft: &CipherDraft,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let id = Uuid::new_v4();
        let cipher = self.encrypt_draft(draft, Some(id))?;
        let body = {
            let mut b = cipher.clone();
            b.as_object_mut().unwrap().remove("id");
            b
        };
        self.store.put_mirror(id, &cipher).map_err(denied)?;
        self.reindex_one(id)?;
        let payload = json!({"op": "create", "cipher": body});
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload,
                base_rev: None,
                origin: Some(session),
                mirror: None,
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    pub async fn write_patch(
        &self,
        session: &str,
        id: ItemId,
        edits: &[FieldEdit],
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let row = self.store.item(id).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let map: bw_vault::FieldMap = edits
            .iter()
            .map(|e| (e.path.clone(), e.value.clone()))
            .collect();
        let ours = self
            .machine
            .with_keys(|kb| {
                bw_vault::apply_merged(&base, &map, &|v| {
                    bw_crypto::encrypt(kb.user_key(), v)
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                })
            })
            .map_err(denied)?;
        let touched: Vec<&str> = edits.iter().map(|e| e.path.as_str()).collect();
        let payload = json!({"op": "patch", "base": base, "ours": ours, "touched": touched});
        let raw = self.store.raw(id).map_err(denied)?;
        let rev = row_rev_of(&raw);
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload,
                base_rev: rev.as_deref(),
                origin: Some(session),
                mirror: Some(&ours),
            })
            .map_err(denied)?;
        self.reindex_one(id)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    pub async fn write_delete(&self, session: &str, ids: &[ItemId]) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        for id in ids {
            let mut mirror = {
                let row = self.store.item(*id).map_err(denied)?;
                row.ok_or(WtpError::NotFound)?.enc_cipher
            };
            let raw = self.store.raw(*id).map_err(denied)?;
            let rev = row_rev_of(&raw);
            let now = chrono_now();
            if let Some(o) = mirror.as_object_mut() {
                o.insert("deletedDate".into(), json!(now));
            }
            self.store
                .enqueue(&MutationDraft {
                    item: *id,
                    payload: json!({"op": "delete"}),
                    base_rev: rev.as_deref(),
                    origin: Some(session),
                    mirror: Some(&mirror),
                })
                .map_err(denied)?;
        }
        self.trigger_drain();
        Ok(Response::Ok)
    }

    pub async fn write_restore(&self, session: &str, id: ItemId) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let mut mirror = {
            let row = self.store.item(id).map_err(denied)?;
            row.ok_or(WtpError::NotFound)?.enc_cipher
        };
        let raw = self.store.raw(id).map_err(denied)?;
        let rev = row_rev_of(&raw);
        if let Some(o) = mirror.as_object_mut() {
            o.insert("deletedDate".into(), Value::Null);
        }
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "restore"}),
                base_rev: rev.as_deref(),
                origin: Some(session),
                mirror: Some(&mirror),
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    fn encrypt_draft(&self, draft: &CipherDraft, id: Option<Uuid>) -> Result<Value, WtpError> {
        self.machine
            .with_keys(|kb| {
                let uk = kb.user_key();
                let enc = |s: &str| -> String {
                    bw_crypto::encrypt(uk, s)
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                };
                let mut c = json!({
                    "type": kind_wire(draft.kind),
                    "name": enc(&draft.name),
                    "favorite": draft.favorite,
                });
                if let Some(i) = id {
                    c["id"] = json!(i.to_string());
                }
                if let Some(n) = &draft.notes {
                    c["notes"] = json!(enc(n));
                }
                let mut login = serde_json::Map::new();
                if let Some(u) = &draft.username {
                    login.insert("username".into(), json!(enc(u)));
                }
                if let Some(p) = &draft.password {
                    login.insert("password".into(), json!(enc(p)));
                }
                if let Some(t) = &draft.totp {
                    login.insert("totp".into(), json!(enc(t)));
                }
                if !draft.uris.is_empty() {
                    let uris: Vec<Value> = draft
                        .uris
                        .iter()
                        .map(|u| json!({"uri": enc(u), "match": null}))
                        .collect();
                    login.insert("uris".into(), json!(uris));
                }
                if !login.is_empty() {
                    c["login"] = Value::Object(login);
                }
                c
            })
            .map_err(denied)
    }

    // —— drain 側 ——

    pub async fn drain_until_idle(self: &std::sync::Arc<Self>) {
        let _g = self.drain_lock.lock().await;
        loop {
            if !self.machine.is_unlocked() {
                return;
            }
            let due = match self.store.take_due(16) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(err = %e, "take_due failed");
                    return;
                }
            };
            if due.is_empty() {
                return;
            }
            for m in due {
                match self.push_one(&m).await {
                    Ok(()) => {}
                    Err(retry_later) => {
                        if retry_later {
                            let _ = self.store.settle(m.id, MutState::Queued);
                            return;
                        }
                        // false：push_one 已自行結算（dead/conflict），drain 不能再動它，
                        // 否則衝突列會被改回 queued 造成 conflict↔queued 無限振盪。
                    }
                }
            }
        }
    }

    /// Ok(()) = 已結算；Err(true) = 可重試（離線/限流）；Err(false) = 已標 Dead。
    async fn push_one(&self, m: &Mutation) -> Result<(), bool> {
        let client = match self.client().await {
            Ok(c) => c,
            Err(_) => return Err(true),
        };
        let op = m
            .payload
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = match op {
            "create" => self.push_create(&client, m).await,
            "patch" => self.push_patch(&client, m).await,
            "delete" => client
                .cipher_delete(m.item, DeleteKind::Soft)
                .await
                .map(|_| ())
                .map_err(|e| (e, false)),
            "restore" => client
                .cipher_restore(m.item)
                .await
                .map(|_| ())
                .map_err(|e| (e, false)),
            "move" => self.push_move(&client, m).await,
            other => {
                tracing::error!(op = other, "unknown outbox op");
                let _ = self.store.settle(m.id, MutState::Dead);
                return Err(false);
            }
        };
        match result {
            Ok(()) => {
                if op != "create" && op != "patch" {
                    self.emit(
                        EventTopic::VaultChanged,
                        json!({"id": m.item.to_string(), "op": op}),
                    );
                }
                Ok(())
            }
            Err((e, is_merge_path)) => {
                if is_merge_path {
                    return Err(false); // push_* 已自行結算
                }
                if e.is_rate_limited() || e.status().is_none() {
                    self.machine.set_egress(e.status().is_some());
                    return Err(true);
                }
                if e.is_auth_rejected() {
                    self.machine.note_token_rejected();
                    return Err(true);
                }
                tracing::error!(err = %e, id = m.id.0, "push failed permanently");
                let _ = self.store.settle(m.id, MutState::Dead);
                Err(false)
            }
        }
    }

    async fn push_create(
        &self,
        client: &bw_server::Client,
        m: &Mutation,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        let body = m.payload.get("cipher").cloned().unwrap_or(json!({}));
        let created = client.cipher_create(&body).await.map_err(|e| (e, false))?;
        let new_id = cipher_id(&created).ok_or_else(|| {
            (
                bw_server::ServerError::Malformed("create resp without id".into()),
                false,
            )
        })?;
        if new_id != m.item {
            let _ = self.store.remap_item(m.item, new_id);
        }
        let _ = self.store.put_mirror(new_id, &created);
        let _ = self.reindex_one(new_id);
        self.store
            .settle(m.id, MutState::Applied)
            .map_err(|_| (bw_server::ServerError::Rejected("settle".into()), true))?;
        self.emit(
            EventTopic::VaultChanged,
            json!({"id": new_id.to_string(), "op": "create"}),
        );
        Ok(())
    }

    async fn push_patch(
        &self,
        client: &bw_server::Client,
        m: &Mutation,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        let theirs = match client.cipher_get(m.item).await {
            Ok(t) => t,
            Err(e) if is_not_found(&e) => {
                // 本端要改的項目已被他端刪除 → 衝突收件匣
                let _ = self.store.settle(m.id, MutState::Conflict);
                self.emit(
                    EventTopic::ConflictDetected,
                    json!({"id": m.id.0, "item": m.item.to_string(), "why": "deleted-remotely"}),
                );
                return Err((e, true));
            }
            Err(e) => return Err((e, false)),
        };
        let their_rev = theirs
            .get("revisionDate")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let base_enc = m.payload.get("base").cloned().unwrap_or(json!({}));
        let ours_enc = m
            .payload
            .get("ours")
            .cloned()
            .unwrap_or_else(|| base_enc.clone());

        if m.base_rev.is_some() && their_rev == m.base_rev {
            // CAS 命中：直接推 ours
            let mut body = ours_enc.clone();
            if let Some(o) = body.as_object_mut() {
                o.insert("id".into(), json!(m.item.to_string()));
            }
            let resp = client
                .cipher_put(m.item, &body)
                .await
                .map_err(|e| (e, false))?;
            self.finish_applied(m.id, &resp)?;
            return Ok(());
        }

        // 漂移：欄位級三方合併。明文域比較（IV 隨機，密文不可比）。
        let merged = self
            .machine
            .with_keys(|kb| {
                let uk = kb.user_key();
                let dec =
                    |s: &str| -> Option<String> { bw_crypto::decrypt(uk, &s.to_string()).ok() };
                let base = bw_vault::flatten(&base_enc, &dec);
                let ours = bw_vault::flatten(&ours_enc, &dec);
                let theirs_m = bw_vault::flatten(&theirs, &dec);
                match bw_vault::three_way(&base, &ours, &theirs_m) {
                    bw_vault::Merge::Push(map) => {
                        Ok(Some(bw_vault::apply_merged(&theirs, &map, &|v| {
                            bw_crypto::encrypt(uk, v)
                                .map(|e| e.to_string())
                                .unwrap_or_default()
                        })))
                    }
                    bw_vault::Merge::Noop => Ok(None),
                    bw_vault::Merge::Conflict { fields } => Err(fields),
                }
            })
            .map_err(|e| (bw_server::ServerError::Rejected(e.to_string()), true))?;
        match merged {
            Ok(Some(body)) => {
                let resp = client
                    .cipher_put(m.item, &body)
                    .await
                    .map_err(|e| (e, false))?;
                self.finish_applied(m.id, &resp)?;
                Ok(())
            }
            Ok(None) => {
                let _ = self.store.put_mirror(m.item, &theirs);
                let _ = self.reindex_one(m.item);
                let _ = self.store.settle(m.id, MutState::Applied);
                self.emit(
                    EventTopic::OutboxDrained,
                    json!({"id": m.id.0, "noop": true}),
                );
                Ok(())
            }
            Err(fields) => {
                let _ = self.store.settle(m.id, MutState::Conflict);
                self.emit(
                    EventTopic::ConflictDetected,
                    json!({"id": m.id.0, "item": m.item.to_string(), "fields": fields}),
                );
                Err((bw_server::ServerError::Rejected("conflict".into()), true))
            }
        }
    }

    async fn push_move(
        &self,
        client: &bw_server::Client,
        m: &Mutation,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        let theirs = client.cipher_get(m.item).await.map_err(|e| (e, false))?;
        let mut body = theirs;
        if let Some(o) = body.as_object_mut() {
            o.insert(
                "organizationId".into(),
                m.payload.get("org").cloned().unwrap_or(Value::Null),
            );
            o.insert(
                "collectionIds".into(),
                m.payload.get("collections").cloned().unwrap_or(json!([])),
            );
        }
        let resp = client
            .cipher_put(m.item, &body)
            .await
            .map_err(|e| (e, false))?;
        self.finish_applied(m.id, &resp)
    }

    fn finish_applied(
        &self,
        id: MutationId,
        resp: &Value,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        if let Some(nid) = cipher_id(resp) {
            let _ = self.store.put_mirror(nid, resp);
            let _ = self.reindex_one(nid);
        }
        self.store
            .settle(id, MutState::Applied)
            .map_err(|_| (bw_server::ServerError::Rejected("settle".into()), true))?;
        self.emit(
            EventTopic::VaultChanged,
            json!({"id": id.0, "op": "applied"}),
        );
        Ok(())
    }

    /// 單筆鏡像的明文索引回填（with_keys 閉包內解密）。
    pub fn reindex_one(&self, id: ItemId) -> Result<(), WtpError> {
        let row = self.store.item(id).map_err(denied)?;
        let Some(row) = row else { return Ok(()) };
        let (name, uris, username, password) = self
            .machine
            .with_keys(|kb| {
                let uk = kb.user_key();
                let name = row
                    .enc_cipher
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|e| bw_crypto::decrypt(uk, &e.to_string()).ok());
                let username = row
                    .enc_cipher
                    .pointer("/login/username")
                    .and_then(Value::as_str)
                    .and_then(|e| bw_crypto::decrypt(uk, &e.to_string()).ok());
                let password = row
                    .enc_cipher
                    .pointer("/login/password")
                    .and_then(Value::as_str)
                    .and_then(|e| bw_crypto::decrypt(uk, &e.to_string()).ok());
                let uris: Vec<String> = row
                    .enc_cipher
                    .pointer("/login/uris")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|u| u.get("uri").and_then(Value::as_str))
                            .filter_map(|e| bw_crypto::decrypt(uk, &e.to_string()).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                (name, uris, username, password)
            })
            .map_err(denied)?;
        let _ = self.store.set_plain_meta(id, name.as_deref(), &uris);
        let _ = self
            .store
            .set_plain_secrets(id, username.as_deref(), password.as_deref());
        Ok(())
    }

    // —— notifications：多中樞收斂 ——

    pub async fn apply_theirs(&self, id: ItemId) {
        let Ok(client) = self.client().await else {
            return;
        };
        // 有未推的本地變更 → 交給 drain 的 merge，這裡不覆蓋鏡像（§2.4 規則 2）
        if self.store.has_pending(id).unwrap_or(true) {
            return;
        }
        match client.cipher_get(id).await {
            Ok(theirs) => {
                let _ = self.store.put_mirror(id, &theirs);
                let _ = self.reindex_one(id);
                self.emit(
                    EventTopic::VaultChanged,
                    json!({"id": id.to_string(), "op": "remote"}),
                );
            }
            Err(e) => tracing::warn!(err = %e, %id, "targeted pull failed"),
        }
    }

    pub async fn notify_loop(self: &std::sync::Arc<Self>) {
        loop {
            let client = match self.client().await {
                Ok(c) => c,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };
            match client.notifications().await {
                Ok(mut stream) => {
                    self.machine.set_egress(true);
                    loop {
                        // 60 秒讀取逾時：docker stop / 網路中斷常留半開 TCP，
                        // tungstenite 不會自己發現死了；逾時強制走重連路徑。
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(20),
                            stream.next(),
                        )
                        .await
                        {
                            Ok(Some(ev)) => {
                                if ev.is_own_change(&self.device) {
                                    continue;
                                }
                                if let Some(id) = ev.cipher_id() {
                                    self.apply_theirs(id).await;
                                }
                            }
                            Ok(None) => break,
                            Err(_) => {
                                tracing::debug!("notifications idle 60s; recycling connection");
                                break;
                            }
                        }
                    }
                    let _ = stream.close().await;
                    tracing::info!("notifications stream ended; reconnect in 2s");
                }
                Err(e) => {
                    tracing::warn!(err = %e, "notifications connect failed; retry in 5s");
                    self.machine.set_egress(false);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    // —— 衝突收件匣 ——

    pub async fn list_conflicts(&self) -> Result<Response, WtpError> {
        let rows = self.store.conflicts().map_err(denied)?;
        let client = self.client().await.ok();
        let mut out = Vec::new();
        for r in rows {
            let fields = match (&client, r.ours.get("base"), r.ours.get("ours")) {
                (Some(c), Some(base), Some(ours)) => match c.cipher_get(r.item).await {
                    Ok(theirs) => self
                        .machine
                        .with_keys(|kb| {
                            let uk = kb.user_key();
                            let dec = |s: &str| bw_crypto::decrypt(uk, &s.to_string()).ok();
                            let b = bw_vault::flatten(base, &dec);
                            let o = bw_vault::flatten(ours, &dec);
                            let t = bw_vault::flatten(&theirs, &dec);
                            match bw_vault::three_way(&b, &o, &t) {
                                bw_vault::Merge::Conflict { fields } => fields,
                                _ => vec![],
                            }
                        })
                        .unwrap_or_default(),
                    Err(_) => vec![],
                },
                _ => vec![],
            };
            out.push(ConflictEntry {
                id: r.id,
                item: r.item,
                base_rev: r.base_rev,
                origin: r.origin,
                created_at: r.created_at,
                fields,
            });
        }
        Ok(Response::Conflicts(out))
    }

    pub async fn resolve_conflict(
        &self,
        id: MutationId,
        pick: Resolution,
    ) -> Result<Response, WtpError> {
        let rows = self.store.conflicts().map_err(denied)?;
        let rec = rows
            .into_iter()
            .find(|r| r.id == id)
            .ok_or(WtpError::NotFound)?;
        let client = self.client().await?;
        let theirs = client.cipher_get(rec.item).await.map_err(denied)?;
        match pick {
            Resolution::Ours => {
                let ours = rec.ours.get("ours").cloned().ok_or(WtpError::NotFound)?;
                let mut body = ours.clone();
                if let Some(o) = body.as_object_mut() {
                    o.insert("id".into(), json!(rec.item.to_string()));
                    o.insert("revisionDate".into(), Value::Null);
                }
                let resp = client.cipher_put(rec.item, &body).await.map_err(denied)?;
                let _ = self.store.put_mirror(rec.item, &resp);
                let _ = self.reindex_one(rec.item);
            }
            Resolution::Theirs => {
                let _ = self.store.put_mirror(rec.item, &theirs);
                let _ = self.reindex_one(rec.item);
            }
            Resolution::KeepBoth => {
                let ours = rec.ours.get("ours").cloned().ok_or(WtpError::NotFound)?;
                let mut body = ours.clone();
                if let Some(o) = body.as_object_mut() {
                    o.remove("id");
                    o.remove("revisionDate");
                }
                let _created = client.cipher_create(&body).await.map_err(denied)?;
            }
            Resolution::Merge => {
                return Err(WtpError::Unsupported {
                    feature: "欄位級人工合併在 P4 GUI".into(),
                });
            }
        }
        self.store.settle(id, MutState::Applied).map_err(denied)?;
        self.emit(
            EventTopic::ConflictDetected,
            json!({"id": id.0, "resolved": format!("{pick:?}")}),
        );
        Ok(Response::Ok)
    }
}

fn kind_wire(k: bw_proto::ItemKind) -> u8 {
    use bw_proto::ItemKind::*;
    match k {
        Login => 1,
        SecureNote => 2,
        Card => 3,
        Identity => 4,
    }
}

fn cipher_id(c: &Value) -> Option<ItemId> {
    c.get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

pub(crate) fn row_rev_of(raw: &Value) -> Option<String> {
    raw.get("rev")
        .and_then(Value::as_str)
        .or_else(|| raw.get("revisionDate").and_then(Value::as_str))
        .or_else(|| raw.pointer("/cipher/revisionDate").and_then(Value::as_str))
        .map(str::to_owned)
}

fn denied(e: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: e.to_string(),
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // ISO-8601 without deps: seconds since epoch → RFC3339 由呼叫端容忍；VW 接受任何可解析日期字串
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, mo, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// 日期演算法：Howard Hinnant civil_from_days（Public Domain）
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
