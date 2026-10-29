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
    AgentCall, ApprovalId, AuthCall, Call, EventTopic, Response, RunPlan, SessionId, SyncCall,
    UseCall, VaultCall, View, WtpError,
};
use bw_store::{SessionRow, SessionState};

use crate::hub::Hub;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Interactive,
    Agent,
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
    pub tx: tokio::sync::oneshot::Sender<ApprovalDecision>,
}

pub type ApprovalDecision = Option<GrantSet>;

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
                        tx,
                    },
                );
                self.emit(
                    EventTopic::ApprovalRequired,
                    json!({"id": id.0.to_string(), "summary": summarize(call)}),
                );
                let waited = tokio::time::timeout(std::time::Duration::from_secs(120), rx).await;
                self.pending.lock().unwrap().remove(&id);
                match waited {
                    Ok(Ok(extra)) => {
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
        if let Some(id) = item
            && let Ok(Some(m)) = self.store.meta(id)
        {
            tags = m.tags;
            uris = m.uris;
        }
        Ok(CallReq {
            access,
            item,
            tags,
            uris,
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
        let _ = p.tx.send(extra);
        tracing::info!(approval = %id.0, target = %p.target, "approval granted");
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

    pub fn pending_list(&self) -> Vec<(String, String)> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| (id.0.to_string(), p.summary.clone()))
            .collect()
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
                let req = CallReq {
                    access: Access::Use(UseKind::InjectEnv),
                    item: Some(reference.item),
                    tags: self.item_tags_uris(reference.item).0,
                    uris: self.item_tags_uris(reference.item).1,
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

    fn item_tags_uris(&self, id: bw_proto::ItemId) -> (Vec<String>, Vec<String>) {
        self.store
            .meta(id)
            .ok()
            .flatten()
            .map(|m| (m.tags, m.uris))
            .unwrap_or_default()
    }

    /// 鏡像欄位 → 明文（with_keys 閉包內解密）。field ∈ password|username|totp|notes。
    fn secret_plaintext(&self, id: bw_proto::ItemId, field: &str) -> Result<String, WtpError> {
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        let path = match field {
            "password" | "username" | "totp" => format!("/login/{field}"),
            "notes" => "/notes".to_string(),
            _ => return Err(denied("P3：僅 password/username/totp/notes 可解析")),
        };
        self.machine
            .with_keys(|kb| {
                row.enc_cipher
                    .pointer(&path)
                    .and_then(Value::as_str)
                    .and_then(|e| bw_crypto::decrypt(kb.user_key(), &e.to_string()).ok())
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
        Call::Vault(VaultCall::Delete { ids }) => ids.first().copied(),
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
        other => format!("{other:?}"),
    }
}
