//! agent 治理接線（契約 §2.3）：把 bw-agent 的純判定套在唯一入口上。
//! Interactive（本機 CLI/GUI）全權；Agent session 逐 Call 過 grant + budget + approval。

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use uuid::Uuid;

use bw_agent::{
    Access, CallReq, Decision, GrantSet, Ledger, MutateOp, ParseError, Redactor, UseKind,
    parse_grants, parse_ref,
};
use bw_proto::{
    AgentCall, ApprovalId, AuthCall, Call, EventTopic, PasskeyCall, PushCall, Response, RunPlan,
    SessionId, SyncCall, UseCall, VaultCall, View, WtpError,
};
use bw_store::{SessionRow, SessionState};

use crate::hub::Hub;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Interactive,
    Agent,
    /// 跨機配對裝置（§1.2）：授權走同一張判定表
    Device,
}

/// 一次性配對碼（`bitward pair start` 產生，join 時消耗）
#[derive(Clone, Debug)]
pub struct PairingSpec {
    pub name: String,
    pub grants: GrantSet,
    pub expires_at_ms: u64,
    pub ttl_secs: u64,
}

pub struct LiveSession {
    pub row: SessionRow,
    pub revoked: std::sync::atomic::AtomicBool,
    pub kind: SessionKind,
    /// 常駐 grants（open 時解析）；Approve 可追加
    pub grants: std::sync::RwLock<GrantSet>,
    pub ledger: Mutex<Ledger>,
    /// unix ms；None = 跟隨鎖世代
    pub expires_at_ms: Option<u64>,
}

pub struct PendingApproval {
    pub target: String,
    pub summary: String,
    /// 請求進佇列的 unix ms（記憶體態；ListPending 投影給 GUI 顯示等待時長）
    pub requested_at_ms: u64,
    pub tx: tokio::sync::oneshot::Sender<ApprovalDecision>,
}

/// 拒絕標記：`deny()` 送出後，等待端映射為 `WtpError::Denied`（非 ApprovalExpired）。
#[derive(Clone, Copy, Debug)]
pub struct DeniedMarker;

/// 人工裁決：Ok = 批准（Option = 追加的常駐 grant）；Err = 拒絕。
pub type ApprovalDecision = Result<Option<GrantSet>, DeniedMarker>;

fn denied(gap: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: gap.to_string(),
    }
}

impl Hub {
    pub fn new_session(
        &self,
        token: String,
        kind: SessionKind,
        grants: GrantSet,
        expires_at_ms: Option<u64>,
        principal: Value,
    ) -> Arc<LiveSession> {
        let sess = Arc::new(LiveSession {
            row: SessionRow {
                id: token,
                principal,
                grants: serde_json::to_value(&grants).unwrap_or(json!([])),
                epoch: self.machine.epoch().0,
                state: SessionState::Active,
                created_at: self.store.now_ms(),
                expires_at: expires_at_ms,
            },
            revoked: std::sync::atomic::AtomicBool::new(false),
            kind,
            grants: std::sync::RwLock::new(grants),
            ledger: Mutex::new(Ledger::default()),
            expires_at_ms,
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(sess.row.id.clone(), sess.clone());
        let _ = self.store.session_put(&sess.row);
        sess
    }

    /// 唯一入口的治理前置。回傳命中的 grant 索引（Interactive 回 None＝全權）。
    pub async fn authorize(
        &self,
        sess: &Arc<LiveSession>,
        call: &Call,
    ) -> Result<Option<usize>, WtpError> {
        if sess.kind == SessionKind::Interactive {
            return Ok(None);
        }
        if let Some(exp) = sess.expires_at_ms
            && self.store.now_ms() > exp
        {
            return Err(denied("agent session ttl 已到期"));
        }
        let req = self.call_req(call)?;
        let grants = sess.grants.read().unwrap().clone();
        let decision = bw_agent::check(&grants, &req).map_err(denied)?;
        match decision {
            Decision::Allow(idx) => {
                self.budget_ok(sess, &grants, idx, &req)?;
                Ok(Some(idx))
            }
            Decision::NeedApproval(idx) => {
                self.budget_ok(sess, &grants, idx, &req)?;
                // 人工核准迴路：事件推給互動端，請求端阻塞至批准或逾時
                let id = ApprovalId(Uuid::new_v4());
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.pending.lock().unwrap().insert(
                    id,
                    PendingApproval {
                        target: sess.row.id.clone(),
                        summary: summarize(call),
                        requested_at_ms: self.store.now_ms(),
                        tx,
                    },
                );
                self.emit(
                    EventTopic::ApprovalRequired,
                    json!({"id": id.0.to_string(), "summary": summarize(call)}),
                );
                self.publish_signal(&format!("bitward: approval {} {}", id.0, summarize(call)));
                let waited = tokio::time::timeout(std::time::Duration::from_secs(120), rx).await;
                self.pending.lock().unwrap().remove(&id);
                match waited {
                    // 批准（含追加 grant）：語意不變
                    Ok(Ok(Ok(extra))) => {
                        if let Some(extra) = extra {
                            let mut g = sess.grants.write().unwrap();
                            g.0.extend(extra.0);
                        }
                        let g = sess.grants.read().unwrap().clone();
                        let mut row = sess.row.clone();
                        row.grants = serde_json::to_value(&g).unwrap_or(json!([]));
                        let _ = self.store.session_put(&row);
                        Ok(Some(idx))
                    }
                    // 拒絕：立刻回 Denied，不再等 120s 逾時
                    Ok(Ok(Err(_))) => {
                        tracing::info!(approval = %id.0, target = %sess.row.id, "approval denied");
                        Err(denied("核准被使用者拒絕"))
                    }
                    // 逾時或通道斷（核准端消失）：維持 ApprovalExpired 語意
                    _ => Err(WtpError::ApprovalExpired),
                }
            }
        }
    }

    fn budget_ok(
        &self,
        sess: &Arc<LiveSession>,
        grants: &GrantSet,
        idx: usize,
        req: &CallReq,
    ) -> Result<(), WtpError> {
        let g = &grants.0[idx];
        if !sess
            .ledger
            .lock()
            .unwrap()
            .budget_ok(g, idx, req.item, req.est_bytes)
        {
            return Err(denied("grant budget 已耗盡"));
        }
        Ok(())
    }

    /// Call → 判定輸入。item 的 tags/uris 從鏡像 metadata 取（≤Identity 級）。
    fn call_req(&self, call: &Call) -> Result<CallReq, WtpError> {
        let (access, item) = match call {
            Call::Vault(VaultCall::List { view, .. }) => (
                Access::See(match view {
                    View::Metadata => bw_proto::Sensitivity::Identity,
                    _ => bw_proto::Sensitivity::Secret,
                }),
                None,
            ),
            Call::Vault(VaultCall::Get { id, view }) => (
                match view {
                    View::Metadata => Access::See(bw_proto::Sensitivity::Identity),
                    // Masked 露出 username 與密碼尾碼：仍是「看到 secret 級欄位」
                    View::Masked => Access::See(bw_proto::Sensitivity::Secret),
                    View::Reveal => Access::Reveal(bw_proto::Sensitivity::Secret),
                },
                Some(*id),
            ),
            Call::Vault(VaultCall::Create { .. }) => (Access::Mutate(MutateOp::Create), None),
            Call::Vault(VaultCall::Patch { id, .. }) => {
                (Access::Mutate(MutateOp::Patch), Some(*id))
            }
            Call::Vault(VaultCall::Delete { ids }) => {
                (Access::Mutate(MutateOp::Delete), ids.first().copied())
            }
            Call::Vault(VaultCall::Restore { id }) => (Access::Mutate(MutateOp::Move), Some(*id)),
            Call::Vault(VaultCall::Overlay { id, .. }) => {
                (Access::Mutate(MutateOp::Patch), Some(*id))
            }
            Call::Vault(VaultCall::FindDuplicates) => {
                (Access::See(bw_proto::Sensitivity::Identity), None)
            }
            Call::Vault(VaultCall::Merge { keep, .. }) => {
                (Access::Mutate(MutateOp::Delete), Some(*keep))
            }
            Call::Vault(VaultCall::MoveToOrg { item, .. }) => {
                (Access::Mutate(MutateOp::Move), Some(*item))
            }
            // 資料夾與硬刪比照 cipher 的 create/delete 級（無獨立 MutateOp：
            // Target 判定走 item/folder 歸屬，folder 級 grant 對 CreateFolder
            // （item None）只由 Target::All 命中——新建資料夾無歸屬可判定）。
            Call::Vault(VaultCall::CreateFolder { .. }) => {
                (Access::Mutate(MutateOp::Create), None)
            }
            Call::Vault(VaultCall::ListFolders) => (
                Access::See(bw_proto::Sensitivity::Identity),
                None,
            ),
            Call::Vault(VaultCall::DeleteFolder { .. }) => {
                (Access::Mutate(MutateOp::Delete), None)
            }
            Call::Vault(VaultCall::Purge { id }) => {
                (Access::Mutate(MutateOp::Delete), Some(*id))
            }
            // 批次匯入＝多筆 Create；item None（Target::All 級授權）
            Call::Vault(VaultCall::Import { .. }) => {
                (Access::Mutate(MutateOp::Create), None)
            }
            // 附件：上傳改的是 cipher（Patch 級）、下載出口是內容（See secret）、
            // 刪除比照 Delete；item 錨定便於 item:/folder: grant 判定
            Call::Vault(VaultCall::Attachment { sub }) => match sub {
                bw_proto::AttachmentOp::Upload { item_id, .. } => {
                    (Access::Mutate(MutateOp::Patch), Some(*item_id))
                }
                bw_proto::AttachmentOp::Download { item_id, .. } => (
                    Access::See(bw_proto::Sensitivity::Secret),
                    Some(*item_id),
                ),
                bw_proto::AttachmentOp::Delete { item_id, .. } => {
                    (Access::Mutate(MutateOp::Delete), Some(*item_id))
                }
            },
            // 封存＝項目元資料改動（Patch 級）；圖示是 host 級讀取，
            // 無 item 錨點（Target::All 級授權命中；item 級 grant 不覆蓋）
            Call::Vault(VaultCall::SetArchived { id, .. }) => {
                (Access::Mutate(MutateOp::Patch), Some(*id))
            }
            Call::Vault(VaultCall::GetIcon { .. }) => {
                (Access::See(bw_proto::Sensitivity::Identity), None)
            }
            // passkey 分級（契約 §4）：列表＝Metadata（Identity floor）；
            // Register/Assert 取用私鑰＝Use(UseKind::Passkey)（用而不讀，同 totp 級）
            Call::Passkey(PasskeyCall::GetPasskeys { .. }) => {
                (Access::See(bw_proto::Sensitivity::Identity), None)
            }
            Call::Passkey(PasskeyCall::RegisterPasskey { item_id, .. }) => {
                (Access::Use(UseKind::Passkey), *item_id)
            }
            Call::Passkey(PasskeyCall::AssertPasskey { .. }) => {
                (Access::Use(UseKind::Passkey), None)
            }
            Call::Passkey(PasskeyCall::BeginAssert { .. } | PasskeyCall::FinishAssert { .. }) => {
                (Access::Use(UseKind::Passkey), None)
            }
            Call::Passkey(PasskeyCall::BeginRegister { item_id, .. }) => {
                (Access::Use(UseKind::Passkey), *item_id)
            }
            Call::Passkey(PasskeyCall::FinishRegister { item_id, .. }) => {
                (Access::Use(UseKind::Passkey), *item_id)
            }
            // 推播 token 是不透明識別子、非機密（只有持有 daemon 連線者能用它收信令），
            // 註冊/退註取最松級 see:opaque：任何已配對 session 的 see grant 都涵蓋，
            // 裝置不必為裝推播申請 vault 級授權。清單列全部裝置登記，比照 Audit 級。
            Call::Push(PushCall::RegisterPush { .. } | PushCall::UnregisterPush { .. }) => {
                (Access::See(bw_proto::Sensitivity::Opaque), None)
            }
            Call::Push(PushCall::ListPush) => (Access::See(bw_proto::Sensitivity::Identity), None),
            Call::Use(UseCall::TotpCode { id }) => (Access::Use(UseKind::TotpCode), Some(*id)),
            Call::Use(UseCall::ResolveRef { .. }) => {
                (Access::Reveal(bw_proto::Sensitivity::Secret), None)
            }
            Call::Use(UseCall::Run { .. }) => (Access::Use(UseKind::Run), None),
            Call::Use(UseCall::GeneratePassword { .. }) => {
                (Access::See(bw_proto::Sensitivity::Opaque), None)
            }
            Call::Agent(AgentCall::Audit { .. }) => {
                (Access::See(bw_proto::Sensitivity::Identity), None)
            }
            Call::Auth(_) | Call::Admin(_) | Call::Sync(_) => {
                (Access::See(bw_proto::Sensitivity::Opaque), None)
            }
            Call::Agent(_) => (Access::See(bw_proto::Sensitivity::Opaque), None),
            Call::Fill(_) => (Access::Use(UseKind::Run), None),
        };
        if matches!(call, Call::Auth(AuthCall::Lock)) {
            return Err(denied("agent 不能鎖 vault（人在場原則）"));
        }
        if matches!(call, Call::Sync(SyncCall::Trigger { .. })) {
            return Err(denied("agent 不能手動 trigger sync（由 daemon 排程）"));
        }
        let mut tags = vec![];
        let mut uris = vec![];
        let mut folder = None;
        let mut collections = vec![];
        if let Some(id) = item
            && let Ok(Some(m)) = self.store.meta(id)
        {
            tags = m.tags;
            uris = m.uris;
            folder = m.folder_id;
            collections = m.collections;
        }
        Ok(CallReq {
            access,
            item,
            tags,
            uris,
            folder,
            collections,
            est_bytes: 64,
        })
    }

    pub fn record_usage(
        &self,
        sess: &Arc<LiveSession>,
        idx: Option<usize>,
        call: &Call,
        resp: &Result<Response, WtpError>,
    ) {
        let Some(idx) = idx else { return };
        let item = item_of(call);
        let bytes = resp
            .as_ref()
            .map(|r| {
                serde_json::to_string(r)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        sess.ledger.lock().unwrap().record(idx, item, bytes);
    }

    // —— AgentCall 治理面 ——

    pub fn open_session(
        &self,
        caller: &Arc<LiveSession>,
        scopes: &[String],
        ttl_secs: u64,
        name: &str,
    ) -> Result<Response, WtpError> {
        if caller.kind != SessionKind::Interactive {
            return Err(denied("只有互動 session 能签发 agent session"));
        }
        let dsl = scopes.join("; ");
        let grants: GrantSet = parse_grants(&dsl).map_err(parse_err)?;
        let token = Uuid::new_v4().to_string();
        let expires = self.store.now_ms() + ttl_secs * 1000;
        self.new_session(
            token.clone(),
            SessionKind::Agent,
            grants,
            Some(expires),
            json!({"kind": "agent", "name": name}),
        );
        Ok(Response::AgentSession {
            token,
            expires_epoch_ms: expires,
        })
    }

    pub fn approve(
        &self,
        caller: &Arc<LiveSession>,
        id: ApprovalId,
        grants: Option<&Vec<String>>,
    ) -> Result<Response, WtpError> {
        if caller.kind != SessionKind::Interactive {
            return Err(denied("只有互動端能核准"));
        }
        let pending = self.pending.lock().unwrap().remove(&id);
        let Some(p) = pending else {
            return Err(WtpError::NotFound);
        };
        let extra = match grants {
            Some(segs) => Some(parse_grants(&segs.join("; ")).map_err(parse_err)?),
            None => None,
        };
        let _ = p.tx.send(Ok(extra));
        tracing::info!(approval = %id.0, target = %p.target, "approval granted");
        Ok(Response::Ok)
    }

    /// 拒絕一個待批請求：語意比照 approve（僅互動端可拒；無此 pending → NotFound）。
    /// 請求端立刻收到 `Denied`，不必等 120s 逾時。
    pub fn deny(&self, caller: &Arc<LiveSession>, id: ApprovalId) -> Result<Response, WtpError> {
        if caller.kind != SessionKind::Interactive {
            return Err(denied("只有互動端能拒絕核准"));
        }
        let pending = self.pending.lock().unwrap().remove(&id);
        let Some(p) = pending else {
            return Err(WtpError::NotFound);
        };
        let _ = p.tx.send(Err(DeniedMarker));
        tracing::info!(approval = %id.0, target = %p.target, "approval denied");
        Ok(Response::Ok)
    }

    pub fn revoke(
        &self,
        caller: &Arc<LiveSession>,
        session: SessionId,
    ) -> Result<Response, WtpError> {
        if caller.kind != SessionKind::Interactive {
            return Err(denied("只有互動端能撤銷"));
        }
        let key = session.0.to_string();
        if let Some(s) = self.sessions.lock().unwrap().get(&key) {
            s.revoked.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = self.store.session_set_state(&key, SessionState::Revoked);
            Ok(Response::Ok)
        } else {
            Err(WtpError::NotFound)
        }
    }

    pub fn list_sessions(&self, caller: &Arc<LiveSession>) -> Result<Response, WtpError> {
        if caller.kind != SessionKind::Interactive {
            return Err(denied("只有互動端能列 session"));
        }
        let rows: Vec<Value> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| {
                json!({
                    "id": s.row.id,
                    "kind": format!("{:?}", s.kind),
                    "name": s.row.principal.get("name").cloned().unwrap_or(Value::Null),
                    "epoch": s.row.epoch,
                    "revoked": s.revoked.load(std::sync::atomic::Ordering::Relaxed),
                    "expires_at_ms": s.expires_at_ms,
                    "grants": serde_json::to_value(s.grants.read().unwrap().clone()).unwrap_or(json!([])),
                    "usage": s
                        .ledger
                        .lock()
                        .unwrap()
                        .snapshot()
                        .values()
                        .map(|u| u.total)
                        .sum::<u32>(),
                })
            })
            .collect();
        Ok(Response::Sessions(rows))
    }

    pub fn pending_list(&self) -> Vec<(String, String, u64)> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| (id.0.to_string(), p.summary.clone(), p.requested_at_ms))
            .collect()
    }

    // —— 跨機配對（§1.2）——

    pub fn restore_session(
        &self,
        row: SessionRow,
        kind: crate::agent::SessionKind,
        grants: bw_agent::GrantSet,
    ) -> Arc<crate::agent::LiveSession> {
        let sess = Arc::new(crate::agent::LiveSession {
            expires_at_ms: row.expires_at,
            revoked: std::sync::atomic::AtomicBool::new(false),
            row,
            kind,
            grants: std::sync::RwLock::new(grants),
            ledger: std::sync::Mutex::new(bw_agent::Ledger::default()),
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(sess.row.id.clone(), sess.clone());
        sess
    }

    /// 顯示給配對端的信任錨點：TLS 啟動時注入；未啟動 TLS 時即時從身分檔算。
    pub fn tls_pin(&self) -> String {
        if let Some(p) = self.tls_pin.get() {
            return p.clone();
        }
        bw_btp::tls::load_or_create(&self.data_dir)
            .map(|id| id.spki_pin)
            .unwrap_or_default()
    }

    pub fn pair_start(&self, name: &str, dsl: &str, ttl_secs: u64) -> Result<Response, WtpError> {
        let grants = parse_grants(dsl).map_err(parse_err)?;
        let code: String = {
            use rand::Rng;
            let alphabet: Vec<char> = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".chars().collect();
            let mut rng = rand::thread_rng();
            (0..9)
                .map(|_| alphabet[rng.gen_range(0..alphabet.len())])
                .collect()
        };
        let expires = self.store.now_ms() + 120_000;
        self.pairings.lock().unwrap().insert(
            code.clone(),
            PairingSpec {
                name: name.to_string(),
                grants,
                expires_at_ms: expires,
                ttl_secs: ttl_secs.max(60),
            },
        );
        Ok(Response::PairInfo(bw_proto::PairInfo {
            code,
            pin: self.tls_pin(),
            expires_in_secs: 120,
        }))
    }

    pub fn pair_list(&self) -> Response {
        let now = self.store.now_ms();
        let rows: Vec<Value> = self
            .pairings
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.expires_at_ms > now)
            .map(
                |(code, s)| json!({"code": code, "name": s.name, "expires_at_ms": s.expires_at_ms}),
            )
            .collect();
        Response::Sessions(rows)
    }

    pub fn pair_revoke_code(&self, code: &str) -> Result<Response, WtpError> {
        self.pairings
            .lock()
            .unwrap()
            .remove(code)
            .map(|_| Response::Ok)
            .ok_or(WtpError::NotFound)
    }

    /// join 時消耗：過期/不存在 → None。
    pub fn consume_pairing(&self, code: &str) -> Option<PairingSpec> {
        let spec = self.pairings.lock().unwrap().remove(code)?;
        if spec.expires_at_ms < self.store.now_ms() {
            return None;
        }
        Some(spec)
    }

    /// 信令副發（§1.2 推播路徑）：ntfy（自架形態）與 APNs（正式分發形態）同源同時機，
    /// 只傳不透明信令，明文永不上通道。fire-and-forget：推播是加速器不是正確性依賴
    /// （ntfy/輪詢仍在），失敗僅記日誌。
    pub fn publish_signal(&self, text: &str) {
        if let Some(url) = self.ntfy_url.clone() {
            let body = text.to_string();
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap_or_default();
                if let Err(e) = client
                    .post(&url)
                    .header("Title", "bitward approval")
                    .header("Priority", "high")
                    .body(body)
                    .send()
                    .await
                {
                    tracing::warn!(err = %e, "ntfy signal publish failed");
                }
            });
        }
        if let Some(apns) = self.apns.clone() {
            let text = text.to_string();
            let store = self.store.clone();
            tokio::spawn(async move {
                let Ok(tokens) = store.push_token_list() else {
                    tracing::warn!("apns fan-out skipped: push_token_list failed");
                    return;
                };
                for (token, _platform) in tokens {
                    match apns.send(&token, &text).await {
                        // 410 = 裝置已卸載：立即移除，不再對死 token 發推（收斂語意見 apns::send）
                        Ok(true) => {
                            let _ = store.push_token_remove(&token);
                        }
                        Ok(false) => {}
                        Err(e) => tracing::warn!(err = %e, "apns signal push failed"),
                    }
                }
            });
        }
    }

    /// `use:env` 逐 item 檢查後取明文值；回傳 (注入環境變數, 已知明文集合)。
    async fn resolve_env(
        &self,
        sess: &Arc<LiveSession>,
        plan: &RunPlan,
    ) -> Result<(Vec<(String, String)>, Vec<String>), WtpError> {
        let mut out = Vec::new();
        let mut known = Vec::new();
        for (k, v) in &plan.env {
            if let Some(r) = v.strip_prefix("btw://") {
                let _ = r;
                let reference = parse_ref(v).map_err(denied)?;
                let meta = self.store.meta(reference.item).ok().flatten();
                let req = CallReq {
                    access: Access::Use(UseKind::InjectEnv),
                    item: Some(reference.item),
                    tags: meta.as_ref().map(|m| m.tags.clone()).unwrap_or_default(),
                    uris: meta.as_ref().map(|m| m.uris.clone()).unwrap_or_default(),
                    folder: meta.as_ref().and_then(|m| m.folder_id),
                    collections: meta
                        .as_ref()
                        .map(|m| m.collections.clone())
                        .unwrap_or_default(),
                    est_bytes: 64,
                };
                let grants = sess.grants.read().unwrap().clone();
                if sess.kind == SessionKind::Agent {
                    let decision = bw_agent::check(&grants, &req).map_err(denied)?;
                    match decision {
                        Decision::Allow(idx) | Decision::NeedApproval(idx) => {
                            self.budget_ok(sess, &grants, idx, &req)?
                        }
                    }
                }
                let value = self.secret_plaintext(reference.item, &reference.field)?;
                known.push(value.clone());
                out.push((k.clone(), value));
            } else {
                out.push((k.clone(), v.clone()));
            }
        }
        Ok((out, known))
    }

    /// 鏡像欄位 → 明文（with_keys 閉包內解密）。field ∈ password|username|totp|notes。
    /// 共享項目走 org 對稱金鑰（P4b；金鑰選擇同 project_one）。
    fn secret_plaintext(&self, id: bw_proto::ItemId, field: &str) -> Result<String, WtpError> {
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        let path = match field {
            "password" | "username" | "totp" => format!("/login/{field}"),
            "notes" => "/notes".to_string(),
            _ => return Err(denied("P3：僅 password/username/totp/notes 可解析")),
        };
        let org_keys = self.org_key_map();
        self.machine
            .with_keys(|kb| {
                let d = self.cipher_field_decryptor(kb, &row.enc_cipher, &org_keys);
                row.enc_cipher
                    .pointer(&path)
                    .and_then(Value::as_str)
                    .and_then(d)
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or(WtpError::NotFound)
    }

    /// use:run：子行程注入解析後的環境，出口經 Redactor 淨化（arXiv 2604.03070 的 73.5% 路徑）。
    pub async fn run_plan(
        &self,
        sess: &Arc<LiveSession>,
        plan: &RunPlan,
    ) -> Result<Response, WtpError> {
        let (env, known) = self.resolve_env(sess, plan).await?;
        let mut cmd =
            tokio::process::Command::new(plan.argv.first().ok_or_else(|| denied("argv 為空"))?);
        cmd.args(&plan.argv[1..])
            .env_clear()
            .env(
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            )
            .env_remove("BITWARD_AGENT_TOKEN");
        for (k, v) in &env {
            cmd.env(k, v);
        }
        if !plan.cwd.is_empty() {
            cmd.current_dir(&plan.cwd);
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let output = tokio::time::timeout(
            std::time::Duration::from_millis(plan.timeout_ms.clamp(1000, 120_000)),
            cmd.output(),
        )
        .await
        .map_err(|_| denied("run timeout"))?
        .map_err(denied)?;
        let redactor = Redactor::new(known);
        let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let scrubbed = redactor.scrub(&mut stdout) + redactor.scrub(&mut stderr);
        tracing::info!(scrubbed, "run egress redacted");
        Ok(Response::RunOutput {
            exit: output.status.code(),
            stdout,
            stderr,
        })
    }

    /// btw:// 直接解析（回明文，屬 Reveal 級；已在 authorize 過關）。
    pub fn resolve_ref_value(&self, uri: &str) -> Result<Response, WtpError> {
        let reference = parse_ref(uri).map_err(denied)?;
        let value = self.secret_plaintext(reference.item, &reference.field)?;
        Ok(Response::Secret(value))
    }
}

fn parse_err(e: ParseError) -> WtpError {
    denied(e)
}

pub fn item_of(call: &Call) -> Option<uuid::Uuid> {
    match call {
        Call::Vault(VaultCall::Get { id, .. })
        | Call::Vault(VaultCall::Patch { id, .. })
        | Call::Vault(VaultCall::Restore { id })
        | Call::Use(UseCall::TotpCode { id }) => Some(*id),
        Call::Vault(VaultCall::Attachment { sub }) => Some(match sub {
            bw_proto::AttachmentOp::Upload { item_id, .. }
            | bw_proto::AttachmentOp::Download { item_id, .. }
            | bw_proto::AttachmentOp::Delete { item_id, .. } => *item_id,
        }),
        Call::Vault(VaultCall::SetArchived { id, .. }) => Some(*id),
        Call::Vault(VaultCall::Delete { ids }) => ids.first().copied(),
        Call::Passkey(PasskeyCall::RegisterPasskey {
            item_id: Some(id), ..
        })
        | Call::Passkey(PasskeyCall::BeginRegister {
            item_id: Some(id), ..
        })
        | Call::Passkey(PasskeyCall::FinishRegister {
            item_id: Some(id), ..
        }) => Some(*id),
        _ => None,
    }
}

fn summarize(call: &Call) -> String {
    match call {
        Call::Vault(VaultCall::Get { id, view }) => format!("vault get {id} view={view:?}"),
        Call::Use(UseCall::ResolveRef { uri }) => format!("resolve {uri}"),
        Call::Use(UseCall::Run { plan }) => {
            format!("run {:?}", plan.argv.first().cloned().unwrap_or_default())
        }
        // 附件 Upload 帶整檔位元組：Debug dump 會把內容潑進審計/核准文字
        Call::Vault(VaultCall::Attachment { sub }) => crate::attach::op_summary(sub),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn bare_hub() -> Arc<Hub> {
        let dir = std::env::temp_dir().join(format!("bw-agent-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Hub::open(&dir, None, None).await.unwrap()
    }

    /// (requester, human)：requester 帶 `approve` 標記的 grant，任何命中都排隊。
    fn gated_sessions(hub: &Arc<Hub>) -> (Arc<LiveSession>, Arc<LiveSession>) {
        let requester = hub.new_session(
            Uuid::new_v4().to_string(),
            SessionKind::Agent,
            parse_grants("use:totp all approve").unwrap(),
            None,
            json!({"kind": "agent", "name": "gated"}),
        );
        let human = hub.new_session(
            Uuid::new_v4().to_string(),
            SessionKind::Interactive,
            GrantSet::default_full(),
            None,
            json!({"kind": "interactive"}),
        );
        (requester, human)
    }

    /// 背景發起一個必然 NeedApproval 的 dispatch，等它進佇列後回 (任務, 核准 id)。
    async fn spawn_gated(
        hub: &Arc<Hub>,
        requester: &Arc<LiveSession>,
    ) -> (
        tokio::task::JoinHandle<Result<Response, WtpError>>,
        ApprovalId,
    ) {
        let hub2 = hub.clone();
        let sess2 = requester.clone();
        let h = tokio::spawn(async move {
            hub2.dispatch(&sess2, &Call::Use(UseCall::TotpCode { id: Uuid::new_v4() }))
                .await
        });
        let id = loop {
            if let Some((s, _, at_ms)) = hub.pending_list().first() {
                // 弱斷言：請求時間欄必須存在且落在 daemon 時鐘的近期視窗
                // （±2s 容忍排程抖動）——GUI 批准佇列的等待時長資料源。
                let now = hub.store.now_ms();
                assert!(
                    at_ms.abs_diff(now) <= 2_000,
                    "requested_at_ms 應在近期視窗內：at={at_ms} now={now}"
                );
                break ApprovalId(Uuid::parse_str(s).unwrap());
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        (h, id)
    }

    #[tokio::test]
    async fn deny_releases_requester_with_denied_not_timeout() {
        let hub = bare_hub().await;
        let (requester, human) = gated_sessions(&hub);
        let (h, id) = spawn_gated(&hub, &requester).await;
        // 治理比照 approve：非互動端不能拒；未知 id → NotFound
        assert!(matches!(
            hub.deny(&requester, id),
            Err(WtpError::Denied { .. })
        ));
        assert!(matches!(
            hub.deny(&human, ApprovalId(Uuid::new_v4())),
            Err(WtpError::NotFound)
        ));
        assert!(matches!(hub.deny(&human, id), Ok(Response::Ok)));
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("deny 後請求端必須立刻放行（非等 120s 逾時）")
            .unwrap();
        match outcome {
            Err(WtpError::Denied { grant_gap }) => {
                assert!(grant_gap.contains("拒絕"), "grant_gap: {grant_gap}")
            }
            other => panic!("expect Denied, got {other:?}"),
        }
        assert!(hub.pending_list().is_empty(), "拒絕後佇列必須清空");
    }

    #[tokio::test]
    async fn approve_path_still_passes_authorize() {
        let hub = bare_hub().await;
        let (requester, human) = gated_sessions(&hub);
        let (h, id) = spawn_gated(&hub, &requester).await;
        hub.approve(&human, id, Some(&vec!["see:identity all".to_string()]))
            .unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("approve 後請求端必須放行")
            .unwrap();
        // authorize 放行 → dispatch_inner 的 totp 因 item 不存在回 NotFound（非 Denied/Expired）
        assert!(matches!(outcome, Err(WtpError::NotFound)), "{outcome:?}");
        // approve 的追加 grant 語意不變：持久化進 session grants
        let g = requester.grants.read().unwrap();
        assert!(
            g.0.iter()
                .any(|x| x.access == Access::See(bw_proto::Sensitivity::Identity)),
            "追加 grant 必須生效"
        );
    }
}
