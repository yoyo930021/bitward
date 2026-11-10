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
//!
//! drain 觸發三源（共用 `drain_lock` 單飛序列化）：寫路徑入列即推（mpsc）、
//! 背景自動推送常駐輪 `auto_drain_loop`（失敗指數退避，見 `drain_backoff`）、
//! 手動刷新；notifications 重新連上也喚醒 drain（`notify_loop` 內 trigger）。

use std::collections::HashMap;

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

/// 背景自動推送的空轉節拍：無失敗史時每 5 秒探一次 outbox
/// （同時代償過期 lease 的 in_flight 列）。
pub(crate) const DRAIN_IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// 背景自動推送退避（純函數）：連續失敗第 n 次 → 30s·2^(n-1)，上限 10 分鐘。
/// n=0 回 0（呼叫端用 `drain_tick` 取空轉節拍）。
pub(crate) fn drain_backoff(failures: u32) -> std::time::Duration {
    if failures == 0 {
        return std::time::Duration::ZERO;
    }
    let secs = 30u64
        .saturating_mul(1u64 << (failures - 1).min(16))
        .min(600);
    std::time::Duration::from_secs(secs)
}

/// 背景自動推送節拍決策（純函數）：無失敗史 → 5 秒空轉；有 → 退避表。
pub(crate) fn drain_tick(failures: u32) -> std::time::Duration {
    if failures == 0 {
        DRAIN_IDLE_TICK
    } else {
        drain_backoff(failures)
    }
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

    pub(crate) async fn client(&self) -> Result<std::sync::Arc<bw_server::Client>, WtpError> {
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
        if let Some(f) = &draft.folder_id {
            Uuid::parse_str(f)
                .map_err(|_| denied(format!("folder_id 需為 UUID，got {f:?}")))?;
        }
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
        // 三件套路徑預驗（入列前擋，不讓越界編輯靜默蒸發）：
        // field.<n>.<leaf> 的 n 必須落在現有 fields[] 內；folderId 值為 UUID；
        // SetType/RemoveField 按 index 定位同紀律，AppendField 要欄名。
        let n_fields = base
            .get("fields")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        for e in edits {
            match e {
                FieldEdit::SetType { index, .. } | FieldEdit::RemoveField { index } => {
                    if (*index as usize) >= n_fields {
                        return Err(denied(format!(
                            "field.{index} 越界：本項目只有 {n_fields} 個自訂欄位"
                        )));
                    }
                }
                FieldEdit::AppendField { field } => {
                    if field.name.is_empty() {
                        return Err(denied("AppendField 需要欄名"));
                    }
                }
                FieldEdit::Set { path, value } => {
                    if let Some(rest) = path.strip_prefix("field.") {
                        let (id_s, leaf) = rest.rsplit_once('.').unwrap_or((rest, ""));
                        if !matches!(leaf, "name" | "value" | "type") {
                            return Err(denied(format!(
                                "欄位路徑需 field.<n>.name|value|type，got {path:?}"
                            )));
                        }
                        let n = id_s
                            .parse::<usize>()
                            .map_err(|_| denied(format!("field 索引需為數字，got {id_s:?}")))?;
                        if n >= n_fields {
                            return Err(denied(format!(
                                "field.{n} 越界：本項目只有 {n_fields} 個自訂欄位"
                            )));
                        }
                        if leaf == "type"
                            && let Some(v) = value.as_deref()
                            && bw_vault::wire_of_type_word(v).is_none()
                        {
                            return Err(denied(format!(
                                "field type 值域 text|hidden|boolean，got {v:?}"
                            )));
                        }
                    }
                    if path == "folderId"
                        && let Some(v) = value.as_deref()
                        && Uuid::parse_str(v).is_err()
                    {
                        return Err(denied(format!("folderId 需為 UUID 字串，got {v:?}")));
                    }
                }
            }
        }
        let map: bw_vault::FieldMap = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::Set { path, value } => Some((path.clone(), value.clone())),
                FieldEdit::SetType { index, kind } => Some((
                    format!("field.{index}.type"),
                    Some(bw_vault::type_word(kind.wire() as i64)?.to_string()),
                )),
                _ => None,
            })
            .collect();
        // 寫側金鑰＝cipher 歸屬走解析器（見 `Hub::cipher_decrypt_key`）：帶
        // item key 的項目讀改寫回全用 item key、`key` 欄原樣保留；共享項目
        // 以 org 對稱金鑰重新加密；org key 未派生/item key 解不開時拒絕，
        // 不產生壞密文。
        let org_keys = self.org_key_map();
        let ours = self
            .machine
            .with_keys(|kb| -> Option<Value> {
                let key = self.cipher_decrypt_key(kb, &base, &org_keys)?;
                let enc = |v: &str| {
                    bw_crypto::encrypt_bytes_key(&key, v.as_bytes()).unwrap_or_default()
                };
                let ours = bw_vault::apply_merged(&base, &map, &enc);
                // 陣列形態操作（Set 型 leaf 做不到的增刪）：先刪（索引由大而小，
                // 免位移）後附加，全部落在 ours 副本上。
                Some(apply_field_ops(
                    ours,
                    &edits
                        .iter()
                        .filter_map(|e| match e {
                            FieldEdit::RemoveField { index } => Some(*index as usize),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    &edits
                        .iter()
                        .filter_map(|e| match e {
                            FieldEdit::AppendField { field } => Some(field),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    &enc,
                ))
            })
            .map_err(denied)?
            .ok_or_else(|| WtpError::Denied {
                grant_gap: "項目寫入金鑰不可用（共享需所屬 org 對稱金鑰 akey 解出；\
                            帶 key 欄的項目需能以 user/org 鑰 unwrapped 出 item key，\
                            請 sync/重解鎖）"
                    .to_owned(),
            })?;
        let touched: Vec<String> = edits
            .iter()
            .map(|e| match e {
                FieldEdit::Set { path, .. } => path.clone(),
                FieldEdit::SetType { index, .. } => format!("field.{index}.type"),
                FieldEdit::AppendField { .. } => "field.append".to_string(),
                FieldEdit::RemoveField { index } => format!("field.remove.{index}"),
            })
            .collect();
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

    /// 封存／取消封存（批次 B）。語意照 delete/restore 先例：鏡像立即改
    /// `archivedDate`（列表即刻反映＋pending 徽章），drain 端以即時 theirs
    /// 為基底全量 PUT（partial 端點不收 archivedDate——VW 1.37.2 實錄 422；
    /// 見 proto 變體註解）。離線＝入列待推。
    pub async fn write_set_archived(
        &self,
        session: &str,
        id: ItemId,
        archived: bool,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        if row.deleted {
            // 垃圾桶項目先還原再談封存：enc_cipher 鏡像不含 deletedDate
            // （write_cipher 剝除紀律），直接蓋 archivedDate 會把 deleted
            // 標記洗掉＝軟刪復活，語意不正確。
            return Err(denied("垃圾桶項目需先 restore 才能改封存狀態"));
        }
        let mut mirror = row.enc_cipher;
        if let Some(o) = mirror.as_object_mut() {
            if archived {
                o.insert("archivedDate".into(), json!(chrono_now()));
            } else {
                o.insert("archivedDate".into(), Value::Null);
            }
        }
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "archive", "archived": archived}),
                base_rev: None,
                origin: Some(session),
                mirror: Some(&mirror),
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    /// drain 端 archive：GET 即時 theirs → 蓋/清 archivedDate → 全量 PUT。
    /// 鏡像與金鑰欄原樣隨 theirs 帶回（item key 層不動，同 push_move 紀律）。
    async fn push_archive(
        &self,
        client: &bw_server::Client,
        m: &Mutation,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        let mut body = client.cipher_get(m.item).await.map_err(|e| (e, false))?;
        let archived = m
            .payload
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if let Some(o) = body.as_object_mut() {
            if archived {
                o.insert("archivedDate".into(), json!(chrono_now()));
            } else {
                o.insert("archivedDate".into(), Value::Null);
            }
        }
        let resp = client
            .cipher_put(m.item, &body)
            .await
            .map_err(|e| (e, false))?;
        self.finish_applied(m.id, &resp)
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

    pub(crate) fn encrypt_draft(
        &self,
        draft: &CipherDraft,
        id: Option<Uuid>,
    ) -> Result<Value, WtpError> {
        self.machine
            .with_keys(|kb| {
                let uk = kb.user_key();
                // 官方新建形態（jslib create 同形）：每筆一枚隨機 64B item key
                // （enc‖mac），`key` 欄存它以 user key 包的信封、內容欄全用
                // item key 加密——新建項目對官方與我們都原生。draft 無歸屬
                // 欄位（新建恆個人項目），包裝鑰即 user key。
                let mut ik = vec![0u8; 64];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ik);
                let enc = |s: &str| -> String {
                    bw_crypto::encrypt_bytes_key(&ik, s.as_bytes()).unwrap_or_default()
                };
                let mut c = json!({
                    "type": kind_wire(draft.kind),
                    "name": enc(&draft.name),
                    "favorite": draft.favorite,
                    "key": bw_crypto::encrypt_bytes_key(uk.as_bytes(), &ik)
                        .unwrap_or_default(),
                });
                if let Some(i) = id {
                    c["id"] = json!(i.to_string());
                }
                // folderId 明文 UUID 欄（官方線格式）；非 UUID 已在 write_create 擋下。
                if let Some(f) = &draft.folder_id {
                    c["folderId"] = json!(f);
                }
                if let Some(n) = &draft.notes {
                    c["notes"] = json!(enc(n));
                }
                // 自訂欄：官方 fields[] 形態 {name(信封), value(信封|null),
                // linkedId, type}。type 0=text、1=hidden、2=boolean——boolean
                // 值存 "true"/"false" 字串（jslib 同形，批次 3 落地）。
                if !draft.fields.is_empty() {
                    let fields: Vec<Value> = draft
                        .fields
                        .iter()
                        .map(|f| {
                            json!({
                                "name": enc(&f.name),
                                "value": f.value.as_deref().map(enc),
                                "linkedId": null,
                                "type": f.kind.wire(),
                            })
                        })
                        .collect();
                    c["fields"] = Value::Array(fields);
                }
                // SecureNote（type 2）官方線格式不帶 login 物件：整塊跳過，
                // 改掛 secureNote 子物件（jslib 同形；VW 缺它回 400 "Data missing"，
                // 2026-11-08 實錄：curl POST /api/ciphers 三態 probe）。
                if draft.kind == bw_proto::ItemKind::SecureNote {
                    c["secureNote"] = json!({"type": 0});
                }
                let mut login = serde_json::Map::new();
                if draft.kind != bw_proto::ItemKind::SecureNote {
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
                }
                if !login.is_empty() || draft.kind != bw_proto::ItemKind::SecureNote {
                    // 純名稱 Login 也恆帶 "login":{}——VW 對 type 1 缺 login 物件回
                    // 400 "Data missing"（2026-11-09 實錄：drain 建無密碼項目 dead；
                    // jslib create 同形）。
                    c["login"] = Value::Object(login);
                }
                c
            })
            .map_err(denied)
    }

    // —— drain 側 ——

    pub async fn drain_until_idle(self: &std::sync::Arc<Self>) {
        let _g = self.drain_lock.lock().await;
        let mut pushed = 0u32;
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
                break;
            }
            for m in due {
                match self.push_one(&m).await {
                    Ok(()) => pushed += 1,
                    Err(retry_later) => {
                        if retry_later {
                            // 按認領前原態回置（awaiting 的附件佇列不得降成 queued）
                            let _ = self.store.settle(m.id, m.state);
                            return;
                        }
                        // false：push_one 已自行結算（dead/conflict），drain 不能再動它，
                        // 否則衝突列會被改回 queued 造成 conflict↔queued 無限振盪。
                    }
                }
            }
        }
        // 推送收斂事件（契約 §2.4）：只在本輪實際推過且可推數歸零時發，
        // 空轉 drain 不常發事件；衝突/死信屬人工介入態、非收斂，不發。
        // 訂閱端據此刷新「待推送」徽章投影。
        if pushed > 0 && self.outbox_pushable().unwrap_or(1) == 0 {
            self.emit(
                EventTopic::OutboxDrained,
                json!({"pending": 0, "pushed": pushed}),
            );
        }
    }

    /// 可推送列數：queued+in_flight+awaiting，與「待推送」徽章投影同口徑
    /// （`refresh_pending` 的 EXISTS 集合）。conflict/dead 屬人工介入態，
    /// 不計入自動收斂判準。
    pub(crate) fn outbox_pushable(&self) -> Option<u32> {
        self.store
            .depth()
            .map(|d| d.queued + d.in_flight + d.awaiting)
            .ok()
    }

    /// 背景自動推送單輪（`auto_drain_loop` 本體；拆出便於單元測）：
    /// 鎖著、未登入（無 server handle）或 outbox 空 → 不推，原數回傳（空
    /// 則歸零）；推後可推數歸零 → backoff 歸零；未歸零 → failures+1，
    /// 首敗 warn 一輪、續敗降 debug（VW 掛掉不刷錯誤日誌洪流）。
    /// 重入紀律：與寫路徑即推、手動刷新共用 `drain_lock` 單飛序列化，不另建鎖。
    pub(crate) async fn auto_drain_round(self: &std::sync::Arc<Self>, failures: u32) -> u32 {
        if !self.machine.is_unlocked() || self.server.read().await.is_none() {
            return failures;
        }
        let Some(pending) = self.outbox_pushable() else {
            return failures;
        };
        if pending == 0 {
            return 0;
        }
        self.drain_until_idle().await;
        if self.outbox_pushable().unwrap_or(pending) == 0 {
            tracing::info!(deferred = failures, "background drain converged");
            0
        } else {
            let next = failures + 1;
            if next == 1 {
                tracing::warn!(
                    pending,
                    "background drain deferred; further failures at debug"
                );
            } else {
                tracing::debug!(pending, failures = next, "background drain deferred");
            }
            next
        }
    }

    /// 背景自動推送常駐迴路：VW 恢復後「待推送」無感自動收斂。節拍由
    /// `drain_tick` 決定（無失敗史 5 秒空轉含租約過期回收；失敗依
    /// 30s→60s→120s→上限 10 分鐘指數退避）；收斂事件由 `drain_until_idle`
    /// 於實際推空時發 `OutboxDrained`。
    pub async fn auto_drain_loop(self: &std::sync::Arc<Self>) {
        let mut failures = 0u32;
        loop {
            tokio::time::sleep(drain_tick(failures)).await;
            failures = self.auto_drain_round(failures).await;
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
            "archive" => self.push_archive(&client, m).await,
            "attach_upload" => self.push_attach_upload(&client, m).await,
            "move" => self.push_move(&client, m).await,
            other => {
                tracing::error!(op = other, "unknown outbox op");
                let _ = self.store.settle(m.id, MutState::Dead);
                return Err(false);
            }
        };
        match result {
            Ok(()) => {
                // create/patch/move 的 push_* 已自行結算（冪等重設 Applied）；
                // delete/restore 無內部結算點——不在這裡補 settle，列會永留
                // in_flight，租約到期反覆重推（writepath 未斷言收斂計數、
                // vaulttypes.sh 實測抓出）。
                let _ = self.store.settle(m.id, MutState::Applied);
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
        // 金鑰按 theirs（伺服器現態）的 cipher 歸屬走解析器（`Hub::cipher_decrypt_key`）：
        // 帶 item key 者以 item key 攤平與重加密（`key` 欄不動）、共享無 key 者以
        // org 對稱金鑰。org key 未派生/item key 解不開 → 結算回 Queued 等 sync
        // 補齊後重試，絕不以 user key 強解強加密（那會把解不開的密文推回伺服器）。
        let org_keys = self.org_key_map();
        let merged = self
            .machine
            .with_keys(|kb| -> Option<Result<Option<Value>, Vec<String>>> {
                let key = self.cipher_decrypt_key(kb, &theirs, &org_keys)?;
                let dec = |s: &str| -> Option<String> {
                    bw_crypto::decrypt_bytes_with_key(&key, s)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                };
                let base = bw_vault::flatten(&base_enc, &dec);
                let ours = bw_vault::flatten(&ours_enc, &dec);
                let theirs_m = bw_vault::flatten(&theirs, &dec);
                Some(match bw_vault::three_way(&base, &ours, &theirs_m) {
                    bw_vault::Merge::Push(map) => {
                        Ok(Some(bw_vault::apply_merged(&theirs, &map, &|v| {
                            bw_crypto::encrypt_bytes_key(&key, v.as_bytes()).unwrap_or_default()
                        })))
                    }
                    bw_vault::Merge::Noop => Ok(None),
                    bw_vault::Merge::Conflict { fields } => Err(fields),
                })
            })
            .map_err(|e| (bw_server::ServerError::Rejected(e.to_string()), true))?;
        let merged = match merged {
            None => {
                let _ = self.store.settle(m.id, MutState::Queued);
                return Err((
                    bw_server::ServerError::Rejected(
                        "cipher write key unavailable (org key not derived or item key unwrap failed)".into(),
                    ),
                    true,
                ));
            }
            Some(v) => v,
        };
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
        let target_org = m
            .payload
            .get("org")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        let mut body = theirs.clone();
        // 歸屬轉移的官方語意：item key 以新歸屬鑰重包後才 PUT（見
        // `Self::rewrap_moved_key`）；解不開/目標 org key 未派生 → 結算回
        // Queued 等 sync 補齊重試，不推「成員解不開 key」的半成品。
        match self.rewrap_moved_key(&theirs, target_org, &self.org_key_map()) {
            Ok(Some(env)) => {
                if let Some(o) = body.as_object_mut() {
                    o.insert("key".into(), json!(env));
                }
            }
            Ok(None) => {}
            Err(()) => {
                let _ = self.store.settle(m.id, MutState::Queued);
                return Err((
                    bw_server::ServerError::Rejected(
                        "move re-wrap item key unavailable (org key not derived or unwrap failed)".into(),
                    ),
                    true,
                ));
            }
        }
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

    /// move 換主時的 item key 重包：以現歸屬解出 item key（解析器口徑，
    /// 含舊包法容錯），再以目標歸屬鑰包回。回 `Ok(None)`＝本項目是無 key
    /// 舊形態，不憑空造 key 欄（維持既有 fallback 語意）；`Err(())`＝
    /// 舊 item key 解不開或目標 org key 未派生（呼叫端延後重試）。
    fn rewrap_moved_key(
        &self,
        theirs: &Value,
        target_org: Option<Uuid>,
        org_keys: &HashMap<Uuid, bw_crypto::OrgKey>,
    ) -> Result<Option<String>, ()> {
        if theirs.get("key").and_then(Value::as_str).is_none() {
            return Ok(None);
        }
        self.machine
            .with_keys(|kb| -> Option<String> {
                let item = self.cipher_decrypt_key(kb, theirs, org_keys)?;
                let wrap: &[u8] = match target_org {
                    None => kb.user_key().as_bytes(),
                    Some(o) => org_keys.get(&o).map(|k| k.as_bytes())?,
                };
                bw_crypto::encrypt_bytes_key(wrap, item.as_slice()).ok()
            })
            .map_err(|_| ())?
            .ok_or(())
            .map(Some)
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

    /// 單筆鏡像的明文索引回填（金鑰選擇與批量路徑同源，見 `Hub::reindex_many`）。
    pub fn reindex_one(&self, id: ItemId) -> Result<(), WtpError> {
        self.reindex_many(&[id])
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
            // 4c 主動續期：過 90 分鐘閘就在這順手換 token，避開
            // 「第一個使用者請求撞 401」的尾巴延遲。失敗不擋連線嘗試
            // （renew 內部已標 needs_relogin，下次 401 收口會再試並上拋）。
            client.renew_if_stale().await;
            match client.notifications().await {
                Ok(mut stream) => {
                    self.machine.set_egress(true);
                    // 共存快路：伺服器重新可達即喚醒 drain（VW 剛回來不必等
                    // 背景退避輪）。重入由 drain_lock 單飛序列化，空轉成本
                    // 僅一次 take_due 查詢；pull 路徑（下方 apply_theirs）不動。
                    self.trigger_drain();
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
                    Ok(theirs) => {
                        let org_keys = self.org_key_map();
                        self.machine
                            .with_keys(|kb| {
                                // 衝突欄位顯示同讀寫口徑：按 cipher 歸屬走解析器
                                // 攤平（含 item key 兩段鏈）。無鑰 → 空欄位清單
                                // （純顯示路徑，最壞不報欄，不硬用 user key 誤解）。
                                let Some(key) = self.cipher_decrypt_key(kb, ours, &org_keys) else {
                                    return Vec::new();
                                };
                                let dec = |s: &str| -> Option<String> {
                                    bw_crypto::decrypt_bytes_with_key(&key, s)
                                        .ok()
                                        .and_then(|b| String::from_utf8(b).ok())
                                };
                                let b = bw_vault::flatten(base, &dec);
                                let o = bw_vault::flatten(ours, &dec);
                                let t = bw_vault::flatten(&theirs, &dec);
                                match bw_vault::three_way(&b, &o, &t) {
                                    bw_vault::Merge::Conflict { fields } => fields,
                                    _ => vec![],
                                }
                            })
                            .unwrap_or_default()
                    }
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

/// fields[] 陣列操作落點（write_patch 的 ours 構造端）：removes 索引由大而小
/// 先刪（免位移），appends 再依序附加（官方 fields[] 形態：name/value 信封、
/// linkedId null、type 整數）。兩組皆空＝原值不動（不憑空造 fields 鍵）。
fn apply_field_ops(
    mut ours: Value,
    removes: &[usize],
    appends: &[&bw_proto::CipherField],
    enc: &dyn Fn(&str) -> String,
) -> Value {
    if removes.is_empty() && appends.is_empty() {
        return ours;
    }
    let obj = ours.as_object_mut().expect("cipher must be object");
    let fields = obj
        .entry("fields")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !fields.is_array() {
        *fields = Value::Array(Vec::new());
    }
    let arr = fields.as_array_mut().expect("fields must be array");
    let mut dels: Vec<usize> = removes.iter().copied().filter(|i| *i < arr.len()).collect();
    dels.sort_unstable_by(|a, b| b.cmp(a));
    for i in dels {
        arr.remove(i);
    }
    for f in appends {
        arr.push(json!({
            "name": enc(&f.name),
            "value": f.value.as_deref().map(enc),
            "linkedId": null,
            "type": f.kind.wire(),
        }));
    }
    ours
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::tests::unlocked_hub;
    use bw_proto::Query;

    fn enc(key: &[u8], pt: &str) -> String {
        bw_crypto::encrypt_bytes_key(key, pt.as_bytes()).unwrap()
    }
    fn dec(key: &[u8], ct: &str) -> Option<String> {
        bw_crypto::decrypt_bytes_with_key(key, ct)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    }
    fn dec_bytes(key: &[u8], ct: &str) -> Option<Vec<u8>> {
        bw_crypto::decrypt_bytes_with_key(key, ct).ok()
    }

    /// 共享寫側鏡像 fixture：org（owner `2.` akey 可解）＋ collection ＋
    /// org key 加密的共享 cipher。`with_akey=false` 模擬 akey 解不出的 org。
    /// 回 (hub, dir, shared id, coll id, org key bytes, user key bytes)。
    async fn fixture(
        tag: &str,
        with_akey: bool,
    ) -> (
        std::sync::Arc<Hub>,
        std::path::PathBuf,
        Uuid,
        Uuid,
        Vec<u8>,
        Vec<u8>,
    ) {
        let (hub, dir) = unlocked_hub(tag).await;
        let org_key = bw_crypto::OrgKey::from_bytes((100u8..164).collect()).unwrap();
        let org_bytes = org_key.as_bytes().to_vec();
        let user_bytes = hub
            .machine
            .with_keys(|kb| kb.user_key().as_bytes().to_vec())
            .unwrap();
        let akey = if with_akey {
            Some(
                hub.machine
                    .with_keys(|kb| org_key.encrypt_with_user_key(kb.user_key()))
                    .unwrap()
                    .unwrap(),
            )
        } else {
            None
        };
        let org = Uuid::new_v4();
        let coll = Uuid::new_v4();
        let shared = Uuid::new_v4();
        hub.store
            .apply_sync(&json!({
                "ciphers": [{
                    "id": shared.to_string(),
                    "type": 1,
                    "organizationId": org.to_string(),
                    "collectionIds": [coll.to_string()],
                    "name": enc(&org_bytes, "Shared Name"),
                    "login": {
                        "username": enc(&org_bytes, "shared-user"),
                        "password": enc(&org_bytes, "shared-pw"),
                    },
                    "revisionDate": "2026-11-07T00:00:00.000Z",
                }],
                "organizations": [{
                    "id": org.to_string(), "name": "2.x|y|z", "key": akey,
                    "status": 0, "type": 0,
                }],
                "collections": [{
                    "id": coll.to_string(),
                    "organizationId": org.to_string(),
                    "name": enc(&org_bytes, "Coll"),
                }],
            }))
            .unwrap();
        (hub, dir, shared, coll, org_bytes, user_bytes)
    }

    /// 共享項目 patch：重加密必須用所屬 org 對稱金鑰，未觸及欄位原樣保留。
    #[tokio::test]
    async fn patch_shared_cipher_reencrypts_with_org_key() {
        let (hub, _d, shared, _c, org_bytes, user_bytes) = fixture("w1", true).await;
        hub.write_patch(
            "s",
            shared,
            &[FieldEdit::Set {
                path: "password".into(),
                value: Some("new-pw".into()),
            }],
        )
        .await
        .unwrap();
        let mirror = hub.store.item(shared).unwrap().unwrap().enc_cipher;
        let ct = mirror["login"]["password"].as_str().unwrap();
        assert_eq!(
            dec(&org_bytes, ct).as_deref(),
            Some("new-pw"),
            "共享項目欄位必須以 org 金鑰加密"
        );
        assert_eq!(
            dec(&user_bytes, ct),
            None,
            "防回歸：不可再以 user key 加密（舊寫側行為）"
        );
        assert_eq!(
            dec(&org_bytes, mirror["login"]["username"].as_str().unwrap()).as_deref(),
            Some("shared-user"),
            "未觸及欄位的 org 密文必須原樣保留"
        );
    }

    /// 歸屬判定：organizationId 缺席時，collectionIds 非空 → 仍按集合反查所屬 org。
    #[tokio::test]
    async fn collection_ids_without_org_id_still_uses_org_key() {
        let (hub, _d, shared, coll, org_bytes, user_bytes) = fixture("w2", true).await;
        hub.store
            .put_mirror(
                shared,
                &json!({
                    "id": shared.to_string(),
                    "type": 1,
                    "organizationId": Value::Null,
                    "collectionIds": [coll.to_string()],
                    "name": enc(&org_bytes, "Shared Name"),
                    "login": {"password": enc(&org_bytes, "shared-pw")},
                }),
            )
            .unwrap();
        hub.write_patch(
            "s",
            shared,
            &[FieldEdit::Set {
                path: "notes".into(),
                value: Some("note-me".into()),
            }],
        )
        .await
        .unwrap();
        let mirror = hub.store.item(shared).unwrap().unwrap().enc_cipher;
        let ct = mirror["notes"].as_str().unwrap();
        assert_eq!(dec(&org_bytes, ct).as_deref(), Some("note-me"));
        assert_eq!(dec(&user_bytes, ct), None);
    }

    /// akey 解不出（org key 未派生）時共享項目寫入必須被拒，而非退回
    /// user key 產生其他裝置解不開的密文。
    #[tokio::test]
    async fn patch_shared_cipher_without_org_key_is_denied() {
        let (hub, _d, shared, _c, org_bytes, _u) = fixture("w3", false).await;
        let e = hub
            .write_patch(
                "s",
                shared,
                &[FieldEdit::Set {
                    path: "password".into(),
                    value: Some("x".into()),
                }],
            )
            .await
            .unwrap_err();
        assert!(
            matches!(e, WtpError::Denied { .. }),
            "org key 未派生應拒絕寫入，got {e:?}"
        );
        let mirror = hub.store.item(shared).unwrap().unwrap().enc_cipher;
        assert_eq!(
            dec(&org_bytes, mirror["login"]["password"].as_str().unwrap()).as_deref(),
            Some("shared-pw"),
            "拒絕後鏡像不得被污染"
        );
        assert_eq!(
            hub.store
                .take_due(16)
                .unwrap()
                .iter()
                .filter(|m| m.item == shared)
                .count(),
            0,
            "拒絕後不得有 mutation 入列"
        );
    }

    /// 帶 item key 的 cipher 編輯：讀改寫回全用 item key、`key` 欄原樣
    /// 保留、未觸及欄位的原密文不動（官方端不受我們編輯影響）。
    #[tokio::test]
    async fn patch_item_key_cipher_keeps_key_and_uses_item_key() {
        let (hub, _d, shared, _c, org_bytes, user_bytes) = fixture("w5", true).await;
        let item: Vec<u8> = (150u8..214).collect();
        let key_env = bw_crypto::encrypt_bytes_key(&org_bytes, &item).unwrap();
        let mut cipher = hub.store.item(shared).unwrap().unwrap().enc_cipher;
        cipher["key"] = json!(key_env);
        cipher["name"] = json!(bw_crypto::encrypt_bytes_key(&item, b"Shared Name").unwrap());
        cipher["login"]["password"] =
            json!(bw_crypto::encrypt_bytes_key(&item, b"shared-pw").unwrap());
        hub.store.put_mirror(shared, &cipher).unwrap();
        hub.write_patch(
            "s",
            shared,
            &[FieldEdit::Set {
                path: "password".into(),
                value: Some("ik-new-pw".into()),
            }],
        )
        .await
        .unwrap();
        let mirror = hub.store.item(shared).unwrap().unwrap().enc_cipher;
        assert_eq!(
            mirror["key"].as_str(),
            Some(key_env.as_str()),
            "編輯必須原樣保留 key 欄（不得改包法或遺失）"
        );
        let pw = mirror["login"]["password"].as_str().unwrap();
        assert_eq!(
            dec(&item, pw).as_deref(),
            Some("ik-new-pw"),
            "改寫欄位以 item key 重新加密"
        );
        assert_eq!(dec(&org_bytes, pw), None, "新密文不得是 org key 直解形態");
        assert_eq!(dec(&user_bytes, pw), None, "新密文不得是 user key 直解形態");
        assert_eq!(
            mirror["login"]["username"].as_str().unwrap(),
            cipher["login"]["username"].as_str().unwrap(),
            "未觸及欄位原密文不動（org key 舊形態照存活）"
        );
    }

    /// move 換主重包：item key 解出後以目標歸屬鑰包回（個人→org、
    /// org→個人雙向）；無 key 舊項目 Ok(None) 不憑空造欄；目標 org key
    /// 未派生 → Err（呼叫端延後重試，不推成員解不開的 key）。
    #[tokio::test]
    async fn move_rewraps_item_key_for_new_owner() {
        let (hub, _d, shared, _c, org_bytes, user_bytes) = fixture("mv1", true).await;
        let org_id = hub.store.collection_list().unwrap()[0].org;
        let org_keys = hub.org_key_map();
        let item: Vec<u8> = (150u8..214).collect();
        let personal = json!({
            "id": shared.to_string(), "type": 1, "organizationId": Value::Null,
            "collectionIds": [], "name": "2.a|b|c",
            "key": bw_crypto::encrypt_bytes_key(&user_bytes, &item).unwrap(),
        });
        let env = hub
            .rewrap_moved_key(&personal, Some(org_id), &org_keys)
            .unwrap()
            .expect("帶 key 項目必有新信封");
        assert_eq!(dec_bytes(&org_bytes, &env).as_deref(), Some(item.as_slice()),
            "個人→共享：item key 改由 org key 包");
        let shared_cipher = json!({
            "id": shared.to_string(), "type": 1, "organizationId": org_id.to_string(),
            "collectionIds": [], "name": "2.a|b|c",
            "key": bw_crypto::encrypt_bytes_key(&org_bytes, &item).unwrap(),
        });
        let env2 = hub
            .rewrap_moved_key(&shared_cipher, None, &org_keys)
            .unwrap()
            .expect("帶 key 項目必有新信封");
        assert_eq!(dec_bytes(&user_bytes, &env2).as_deref(), Some(item.as_slice()),
            "共享→個人：item key 改由 user key 包");
        assert_eq!(
            hub.rewrap_moved_key(&json!({"type": 1, "name": "2.a|b|c"}), None, &org_keys)
                .unwrap(),
            None,
            "無 key 舊項目維持現狀（不憑空造 key 欄）"
        );
        assert!(
            hub.rewrap_moved_key(&personal, Some(Uuid::new_v4()), &org_keys).is_err(),
            "目標 org key 未派生 → Err 延後重試"
        );
    }

    /// 個人項目不受影響：仍走 user key。
    #[tokio::test]
    async fn patch_personal_cipher_still_uses_user_key() {
        let (hub, _d, shared, _c, _o, user_bytes) = fixture("w4", true).await;
        let personal = Uuid::new_v4();
        hub.store
            .put_mirror(
                personal,
                &json!({
                    "id": personal.to_string(), "type": 1,
                    "organizationId": Value::Null, "collectionIds": [],
                    "name": enc(&user_bytes, "Mine"),
                    "revisionDate": "2026-11-07T00:00:00.000Z",
                }),
            )
            .unwrap();
        hub.write_patch(
            "s",
            personal,
            &[FieldEdit::Set {
                path: "notes".into(),
                value: Some("p-note".into()),
            }],
        )
        .await
        .unwrap();
        let mirror = hub.store.item(personal).unwrap().unwrap().enc_cipher;
        assert_eq!(
            dec(&user_bytes, mirror["notes"].as_str().unwrap()).as_deref(),
            Some("p-note")
        );
        let _ = shared;
    }

    /// 退避序列：30→60→120→240→480→600 秒封頂；無失敗史走 5 秒空轉節拍。
    #[test]
    fn drain_backoff_sequence_caps_at_ten_minutes() {
        use std::time::Duration;
        assert_eq!(drain_backoff(0), Duration::ZERO);
        for (n, secs) in [
            (1u32, 30u64),
            (2, 60),
            (3, 120),
            (4, 240),
            (5, 480),
            (6, 600),
            (7, 600),
            (u32::MAX, 600),
        ] {
            assert_eq!(drain_backoff(n), Duration::from_secs(secs), "n={n}");
        }
        assert_eq!(drain_tick(0), Duration::from_secs(5));
        assert_eq!(drain_tick(3), Duration::from_secs(120));
    }

    /// 背景輪紀律：未登入（無 server handle）不動 outbox；server 不可達
    /// （fixture 的 discard port）逐輪累計失敗、列回 queued 不成死信。
    #[tokio::test]
    async fn auto_drain_round_backs_off_without_killing_rows() {
        let (hub, _d) = unlocked_hub("ad1").await;
        let item = Uuid::new_v4();
        hub.store
            .enqueue(&MutationDraft {
                item,
                payload: json!({"op": "delete"}),
                base_rev: None,
                origin: None,
                mirror: None,
            })
            .unwrap();
        // 未登入：單輪空轉，列不動。
        let srv = hub
            .server
            .write()
            .await
            .take()
            .expect("fixture server handle");
        assert_eq!(hub.auto_drain_round(0).await, 0);
        assert_eq!(hub.outbox_pushable(), Some(1));
        // 已登入但伺服器不可達：逐輪 failures+1，列留 queued（非 Dead）。
        hub.server.write().await.replace(srv);
        assert_eq!(hub.auto_drain_round(0).await, 1);
        assert_eq!(hub.auto_drain_round(1).await, 2);
        assert_eq!(hub.outbox_pushable(), Some(1));
        assert_eq!(hub.store.depth().unwrap().dead, 0, "退避不得產生死信");
    }

    /// outbox 空 → 背景輪把失敗計數歸零（下個 episode 從空轉節拍重新起算）。
    #[tokio::test]
    async fn auto_drain_round_resets_when_idle() {
        let (hub, _d) = unlocked_hub("ad2").await;
        assert_eq!(hub.auto_drain_round(5).await, 0);
    }

    /// 三件套 create 線格式（官方兼容硬證據的單元層）：SecureNote（type 2）
    /// 不帶 login、folderId 明文 UUID 入鏡像、fields[] 帶 type/linkedId；
    /// hidden→type 1。新建＝官方形態：自帶 `key` 欄（item key 被 user key
    /// 包）、欄值以 **item key** 信封往復。
    #[tokio::test]
    async fn encrypt_draft_emits_official_wire_shape() {
        let (hub, _d) = unlocked_hub("wire").await;
        let folder = Uuid::new_v4().to_string();
        let draft = CipherDraft {
            kind: bw_proto::ItemKind::SecureNote,
            name: "筆記".into(),
            notes: Some("內文".into()),
            folder_id: Some(folder.clone()),
            fields: vec![
                bw_proto::CipherField {
                    name: "PIN".into(),
                    value: Some("1234".into()),
                    kind: bw_proto::CipherFieldKind::Hidden,
                },
                bw_proto::CipherField {
                    name: "網站".into(),
                    value: None,
                    kind: bw_proto::CipherFieldKind::Text,
                },
            ],
            username: Some("note 不該有 login".into()),
            ..Default::default()
        };
        let cipher = hub.encrypt_draft(&draft, None).unwrap();
        assert_eq!(cipher["type"], json!(2));
        assert!(cipher.get("login").is_none(), "type 2 官方線格式不帶 login");
        assert_eq!(cipher["secureNote"]["type"], json!(0), "VW 必要子物件");
        assert_eq!(cipher["folderId"], json!(&folder));
        let f0 = &cipher["fields"][0];
        assert_eq!(f0["type"], json!(1), "hidden→type 1");
        assert!(f0["linkedId"].is_null());
        let user = hub
            .machine
            .with_keys(|kb| kb.user_key().as_bytes().to_vec())
            .unwrap();
        // 官方形態：key 欄存在且＝user key 包的 64B item key。
        let item = dec_bytes(&user, cipher["key"].as_str().unwrap()).expect("key 欄可解");
        assert_eq!(item.len(), 64, "item key 64B（enc‖mac）");
        assert_eq!(
            dec(&item, f0["name"].as_str().unwrap()).as_deref(),
            Some("PIN"),
            "欄位以 item key 加密（官方同形）"
        );
        assert_eq!(
            dec(&item, f0["value"].as_str().unwrap()).as_deref(),
            Some("1234")
        );
        assert_eq!(
            dec(&item, cipher["name"].as_str().unwrap()).as_deref(),
            Some("筆記")
        );
        assert_eq!(
            dec(&item, cipher["notes"].as_str().unwrap()).as_deref(),
            Some("內文")
        );
        assert_eq!(
            dec(&user, f0["name"].as_str().unwrap()),
            None,
            "防回歸：欄位不得再以 user key 直解（舊新建形態）"
        );
        assert!(cipher["fields"][1]["value"].is_null(), "空值欄 value=null");

        // 純名稱 Login（無帳密/uris）：VW 仍要求 login 物件，缺它 POST 回
        // 400 "Data missing"（2026-11-09 實錄）——恆帶空 {}。
        let bare = CipherDraft {
            name: "只有名字".into(),
            ..Default::default()
        };
        let cipher2 = hub.encrypt_draft(&bare, None).unwrap();
        assert_eq!(cipher2["type"], json!(1));
        assert!(
            cipher2["login"].is_object(),
            "type 1 恆帶 login 物件（可為空 {{}}）"
        );
        assert!(cipher2.get("key").is_some(), "新建恆自帶 item key 欄");
    }

    /// 非 UUID 的 folder_id 在入列前擋下（鏡像 folderId 只收合法 UUID 字串）。
    #[tokio::test]
    async fn create_rejects_non_uuid_folder() {
        let (hub, _d) = unlocked_hub("badfolder").await;
        let draft = CipherDraft {
            name: "x".into(),
            folder_id: Some("not-a-uuid".into()),
            ..Default::default()
        };
        let err = hub.write_create("s", &draft).await.unwrap_err();
        assert!(matches!(err, WtpError::Denied { .. }), "{err:?}");
    }

    /// 批次 3 的陣列/型別操作：SetType 原位改 type 整數（不碰值信封）、
    /// AppendField 尾附加（官方 fields[] 形態）、RemoveField 先刪免位移；
    /// 越界 index 與空欄名在入列前拒。
    #[tokio::test]
    async fn patch_field_type_append_remove_ops() {
        let (hub, _d) = unlocked_hub("fldops").await;
        let user = hub
            .machine
            .with_keys(|kb| kb.user_key().as_bytes().to_vec())
            .unwrap();
        let id = Uuid::new_v4();
        hub.store
            .put_mirror(
                id,
                &json!({
                    "id": id.to_string(), "type": 1, "name": enc(&user, "n"),
                    "fields": [
                        {"name": enc(&user, "a"), "value": enc(&user, "1"), "linkedId": null, "type": 0},
                        {"name": enc(&user, "b"), "value": null, "linkedId": null, "type": 1}
                    ]
                }),
            )
            .unwrap();
        hub.write_patch(
            "s",
            id,
            &[
                FieldEdit::SetType {
                    index: 0,
                    kind: bw_proto::CipherFieldKind::Hidden,
                },
                FieldEdit::AppendField {
                    field: bw_proto::CipherField {
                        name: "flag".into(),
                        value: Some("true".into()),
                        kind: bw_proto::CipherFieldKind::Boolean,
                    },
                },
                FieldEdit::RemoveField { index: 1 },
            ],
        )
        .await
        .unwrap();
        let m = hub.store.item(id).unwrap().unwrap().enc_cipher;
        let fields = m["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2, "刪 b 附加 flag");
        assert_eq!(fields[0]["type"], json!(1), "SetType 原位改 type");
        assert_eq!(
            dec(&user, fields[0]["value"].as_str().unwrap()).as_deref(),
            Some("1"),
            "type 改動不碰值信封"
        );
        assert_eq!(fields[1]["type"], json!(2));
        assert_eq!(
            dec(&user, fields[1]["name"].as_str().unwrap()).as_deref(),
            Some("flag")
        );
        assert_eq!(
            dec(&user, fields[1]["value"].as_str().unwrap()).as_deref(),
            Some("true"),
            "boolean 值存 true/false 字串（jslib 同形）"
        );
        assert!(fields[1]["linkedId"].is_null());
        // 預驗：越界 index 與空欄名擋在入列前
        assert!(
            hub.write_patch("s", id, &[FieldEdit::RemoveField { index: 9 }])
                .await
                .is_err()
        );
        assert!(
            hub.write_patch(
                "s",
                id,
                &[FieldEdit::AppendField {
                    field: bw_proto::CipherField::default()
                }]
            )
            .await
            .is_err()
        );
    }

    /// Import：單交易全收（鏡像＋outbox＋tags 落本地 overlay）；
    /// 壞件整批拒（鏡像與 outbox 不留半套）；>500 拒。
    #[tokio::test]
    async fn import_is_atomic_batch() {
        let (hub, _d) = unlocked_hub("imp").await;
        let items = vec![
            bw_proto::ImportItem {
                draft: CipherDraft {
                    name: "i1".into(),
                    ..Default::default()
                },
                tags: vec!["t".into()],
            },
            bw_proto::ImportItem {
                draft: CipherDraft {
                    kind: bw_proto::ItemKind::SecureNote,
                    name: "i2".into(),
                    notes: Some("n".into()),
                    ..Default::default()
                },
                tags: vec![],
            },
        ];
        let resp = hub.write_import("s", &items, false).await.unwrap();
        let Response::Json(v) = resp else {
            panic!("Import 應回 Json，got {resp:?}")
        };
        assert_eq!(v["imported"], json!(2));
        assert_eq!(hub.store.query(&Query::default()).unwrap().len(), 2);
        assert_eq!(hub.store.depth().unwrap().queued, 2);
        let id0 = Uuid::parse_str(v["ids"][0].as_str().unwrap()).unwrap();
        assert_eq!(hub.store.overlay_get(id0).unwrap().tags, vec!["t".to_string()]);
        let id1 = Uuid::parse_str(v["ids"][1].as_str().unwrap()).unwrap();
        let note1 = hub.store.item(id1).unwrap().unwrap().enc_cipher;
        assert_eq!(note1["type"], json!(2), "SecureNote 走官方線格式");
        assert!(note1.get("secureNote").is_some());
        assert!(note1.get("login").is_none(), "type 2 不帶 login");

        // 壞件（非 UUID folder）→ 全批拒，不留第一筆
        let bad = vec![
            bw_proto::ImportItem {
                draft: CipherDraft {
                    name: "ok".into(),
                    ..Default::default()
                },
                tags: vec![],
            },
            bw_proto::ImportItem {
                draft: CipherDraft {
                    name: "bad".into(),
                    folder_id: Some("nope".into()),
                    ..Default::default()
                },
                tags: vec![],
            },
        ];
        assert!(hub.write_import("s", &bad, false).await.is_err());
        assert_eq!(hub.store.query(&Query::default()).unwrap().len(), 2);
        assert_eq!(hub.store.depth().unwrap().queued, 2);

        // 上限 500 防呆
        let many = vec![bw_proto::ImportItem::default(); 501];
        assert!(hub.write_import("s", &many, false).await.is_err());
    }

    /// 批次 B 封存：鏡像立即帶 archivedDate（列表即時反映）、outbox 入列
    /// archive op；取消封存清欄。推送端全量 PUT 形態由 archicon.sh 實錄。
    #[tokio::test]
    async fn set_archived_flips_mirror_and_queues_op() {
        let (hub, _d) = unlocked_hub("arch").await;
        let id = Uuid::new_v4();
        hub.store
            .put_mirror(
                id,
                &json!({"id": id.to_string(), "type": 1, "name": "2.n|x|y"}),
            )
            .unwrap();
        hub.write_set_archived("s", id, true).await.unwrap();
        let m = hub.store.meta(id).unwrap().unwrap();
        assert!(m.archived_at.is_some(), "鏡像即刻投影 archived_at");
        let due = hub.store.take_due(8).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].payload["op"], json!("archive"));
        assert_eq!(due[0].payload["archived"], json!(true));
        // 主列表預設排除已封存（三態過濾的 store 層專測在 tests/store.rs）
        assert!(
            hub.store
                .query(&Query::default())
                .unwrap()
                .iter()
                .all(|x| x.id != id)
        );
        hub.write_set_archived("s2", id, false).await.unwrap();
        let m = hub.store.meta(id).unwrap().unwrap();
        assert_eq!(m.archived_at, None, "取消封存清欄");
        // 垃圾桶閘：軟刪項目改封存會洗掉 deleted 標記（鏡像不含
        // deletedDate），必須擋下語意才正確
        hub.write_delete("s3", &[id]).await.unwrap();
        let err = hub.write_set_archived("s4", id, true).await.unwrap_err();
        assert!(matches!(&err, WtpError::Denied { grant_gap } if grant_gap.contains("restore")),
            "{err:?}");
    }
}
