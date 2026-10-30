//! Hub：daemon 的業務核心。持有 store/狀態機/伺服器連線，
//! 實作 P1 的 Call 分派（契約 §5.1 最小集）。金鑰只經 `with_keys` 流通。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use bw_keys::{
    AccountLabel, AuthContext, BwCryptoKernel, FileKeyStore, LockReason, UnlockMachine,
    UnlockMaterial, UnlockReceipt,
};
use bw_proto::{
    AccountInfo, AdminCall, AgentCall, AuditChainInfo, AuthCall, Call, FillCall, ItemId, ItemView,
    OutboxCounts, PROTO_VERSION, Query, Response, StatusInfo, SyncCall, UseCall, VaultCall, View,
    WtpError,
};
use bw_server::{Client, PasswordLogin, ServerError};
use bw_store::{AuditFilter, AuditRecord, Store};

pub struct ServerHandle {
    pub client: std::sync::Arc<Client>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub server: String,
    pub email: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    /// §2.1 的 KdfParams 持久化形態
    pub kdf: i64,
    pub kdf_iterations: u64,
    pub kdf_memory: Option<u64>,
    pub kdf_parallelism: Option<u64>,
    pub protected_user_key: String,
    pub keys_fingerprint: Option<String>,
}

pub struct Hub {
    pub data_dir: PathBuf,
    pub store: Store,
    pub machine: UnlockMachine,
    pub server: RwLock<Option<ServerHandle>>,
    account: RwLock<Option<AccountRecord>>,
    /// 穩定裝置 id：notifications is_own_change 與 login deviceIdentifier 同源
    pub device: String,
    pub drain_tx: tokio::sync::mpsc::UnboundedSender<()>,
    pub drain_rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<()>>>,
    /// drain 單飛：併發觸發只跑一轮實際推送（§3.5 trigger 去重語意）
    pub drain_lock: tokio::sync::Mutex<()>,
    /// BTP 事件匯流（EventTopic, payload ≤ Identity 級）
    pub events: tokio::sync::broadcast::Sender<(bw_proto::EventTopic, Value)>,
    /// 上次全量 sync 的 unix ms；通知是 fire-and-forget，半開連線期間的事件會永久錯過，
    /// 由 30 秒週期 sync 兜底（官方客戶端同為 notifications+定期 sync 雙軌）。
    pub last_sync_ms: std::sync::atomic::AtomicU64,
    /// token → 活 session（§2.3）。Enroll 與 Agent OpenSession 皆註冊於此。
    pub sessions: Arc<Mutex<HashMap<String, Arc<crate::agent::LiveSession>>>>,
    /// 等待人工核准的請求（§2.3 Enrollment/Approval）
    pub pending: Mutex<HashMap<bw_proto::ApprovalId, crate::agent::PendingApproval>>,
    /// 未消耗的一次性配對碼（§1.2）
    pub pairings: Mutex<HashMap<String, crate::agent::PairingSpec>>,
    /// ntfy 信令 URL（None = 不發）；只傳不透明信令，明文永不上通道
    pub ntfy_url: Option<String>,
    /// TLS listener 啟動後快取的 SPKI pin（pair start 顯示用）
    pub tls_pin: std::sync::OnceLock<String>,
}

pub type DispatchResult = Result<Response, WtpError>;

fn denied(detail: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: detail.to_string(),
    }
}

fn drift(detail: impl std::fmt::Display) -> WtpError {
    WtpError::ServerDrift {
        detail: detail.to_string(),
    }
}

impl Hub {
    pub async fn open(data_dir: &Path, ntfy_url: Option<String>) -> Result<Arc<Hub>, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let store = Store::open(&data_dir.join("vault.db")).map_err(|e| e.to_string())?;
        let account: Option<AccountRecord> = Self::read_json(&data_dir.join("account.json"));
        let keystore =
            FileKeyStore::new(data_dir.join("keys")).map_err(|e| format!("keystore: {e}"))?;
        // 固定 label：首次登入時 account.json 還不存在，若用 email 作 label
        // 會造成封存與載入路徑不一致（A7b 實測教訓）。多帳號（P6）再拆 per-account。
        let label = AccountLabel::new("default");
        let builder = UnlockMachine::builder()
            .label(label)
            .kernel(Arc::new(BwCryptoKernel))
            .keystore(Arc::new(keystore));
        let builder = match &account {
            Some(_) => builder.signed_out(false),
            None => builder.signed_out(true),
        };
        let machine = builder.build();
        if let Some(a) = &account {
            machine.set_auth_context(AuthContext {
                email: a.email.clone(),
                kdf: kdf_params(a),
                protected_user_key: a.protected_user_key.clone(),
                keys_fingerprint: a.keys_fingerprint.clone(),
            });
        }
        let (drain_tx, drain_rx) = tokio::sync::mpsc::unbounded_channel();
        let hub = Arc::new(Hub {
            data_dir: data_dir.to_path_buf(),
            store,
            machine,
            server: RwLock::new(None),
            account: RwLock::new(account.clone()),
            device: Self::device_id_static(data_dir),
            drain_tx,
            drain_rx: tokio::sync::Mutex::new(Some(drain_rx)),
            drain_lock: tokio::sync::Mutex::new(()),
            events: tokio::sync::broadcast::channel(128).0,
            last_sync_ms: std::sync::atomic::AtomicU64::new(0),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending: Mutex::new(HashMap::new()),
            pairings: Mutex::new(HashMap::new()),
            ntfy_url,
            tls_pin: std::sync::OnceLock::new(),
        });
        if let Some(a) = account {
            let client = std::sync::Arc::new(
                Client::with_options(&a.server, Hub::sync_options()).map_err(|e| e.to_string())?,
            );
            if let Some(t) = a.access_token.clone() {
                client.set_access_token(&t).await;
            }
            hub.server.write().await.replace(ServerHandle { client });
        }
        // 重啟不踢已配對裝置：從持久層重建活 session（§2.3，token 即 id）
        for row in hub.store.session_list().unwrap_or_default() {
            if row.state != bw_store::SessionState::Active {
                continue;
            }
            let kind = match row.principal.get("kind").and_then(Value::as_str) {
                Some("agent") => crate::agent::SessionKind::Agent,
                Some("device") => crate::agent::SessionKind::Device,
                _ => crate::agent::SessionKind::Interactive,
            };
            let parsed: bw_agent::GrantSet =
                serde_json::from_value(row.grants.clone()).unwrap_or_default();
            let grants = if parsed.0.is_empty() && kind == crate::agent::SessionKind::Interactive {
                bw_agent::GrantSet::default_full()
            } else {
                parsed
            };
            hub.restore_session(row, kind, grants);
        }
        Ok(hub)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    async fn persist_account(&self) -> Result<(), WtpError> {
        let acc = self
            .account
            .read()
            .await
            .clone()
            .ok_or(WtpError::NotFound)?;
        let bytes = serde_json::to_vec_pretty(&acc).map_err(denied)?;
        let path = self.data_dir.join("account.json");
        std::fs::write(&path, bytes).map_err(denied)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn device_id_static(dir: &Path) -> String {
        let path = dir.join("device.id");
        if let Ok(s) = std::fs::read_to_string(&path) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_owned();
            }
        }
        let id = Uuid::new_v4().to_string();
        let _ = std::fs::write(&path, &id);
        id
    }

    pub async fn status_info(&self) -> StatusInfo {
        let d = self.store.depth().unwrap_or_default();
        StatusInfo {
            state: self.machine.state(),
            epoch: self.machine.epoch().0,
            items: self.store.cipher_count().unwrap_or(0),
            outbox: OutboxCounts {
                queued: d.queued,
                in_flight: d.in_flight,
                awaiting: d.awaiting,
                conflict: d.conflict,
                dead: d.dead,
                total: d.total,
            },
            needs_reauth: self.machine.needs_reauth(),
            proto: PROTO_VERSION,
        }
    }

    /// 唯一 thin 入口：治理前置（grant/budget/approval）→ 分派 → 用量記帳 + 全量審計（A8）。
    pub async fn dispatch(
        self: &Arc<Self>,
        sess: &Arc<crate::agent::LiveSession>,
        call: &Call,
    ) -> DispatchResult {
        self.machine.record_activity();
        let granted = match self.authorize(sess, call).await {
            Ok(idx) => idx,
            Err(e) => {
                self.audit_call(
                    sess,
                    call,
                    &Err(WtpError::Denied {
                        grant_gap: e.to_string(),
                    }),
                    0,
                );
                return Err(e);
            }
        };
        let outcome = self.dispatch_inner(sess, call).await;
        self.record_usage(sess, granted, call, &outcome);
        let bytes = outcome
            .as_ref()
            .map(|r| {
                serde_json::to_string(r)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        self.audit_call(sess, call, &outcome, bytes);
        outcome
    }

    fn audit_call(
        &self,
        sess: &Arc<crate::agent::LiveSession>,
        call: &Call,
        outcome: &DispatchResult,
        bytes_out: u64,
    ) {
        let (outcome_s, sens) = match outcome {
            Ok(resp) => ("ok".to_string(), sensitivity_of_call(call, Some(resp))),
            Err(e) => (format!("err:{e}"), sensitivity_of_call(call, None)),
        };
        let _ = self.store.audit_append(&AuditRecord {
            ts: self.store.now_ms().to_string(),
            session: Some(sess.row.id.clone()),
            action: action_tag(call),
            item: crate::agent::item_of(call).map(|i| i.to_string()),
            field: None,
            sens,
            outcome: outcome_s,
            bytes_out,
            approval: None,
            epoch: self.machine.epoch().0,
        });
    }

    async fn dispatch_inner(
        &self,
        sess: &Arc<crate::agent::LiveSession>,
        call: &Call,
    ) -> DispatchResult {
        let session = sess.row.id.as_str();
        match call {
            Call::Auth(AuthCall::Login {
                server,
                email,
                password: Some(pw),
                api_key: None,
            }) => self.login(server, email, pw).await,
            Call::Auth(AuthCall::Login { .. }) => Err(denied(
                "P1: daemon-side password challenge 未実装；請由 CLI 傳入密碼",
            )),
            Call::Auth(AuthCall::Unlock { biometric }) => {
                if *biometric {
                    return Err(denied("P1: biometric assertion 尚未接 KeychainKeystore"));
                }
                match self.machine.submit(UnlockMaterial::DeviceAssertion) {
                    Ok(UnlockReceipt::Unlocked { .. } | UnlockReceipt::AlreadyUnlocked { .. }) => {
                        Ok(Response::Status(self.status_info().await))
                    }
                    Ok(UnlockReceipt::Pending { .. }) => Err(denied("unlock pending")),
                    Err(e) => Err(WtpError::Denied {
                        grant_gap: e.to_string(),
                    }),
                }
            }
            Call::Auth(AuthCall::SignOut) => {
                if let Some(h) = self.server.read().await.as_ref() {
                    h.client.sign_out().await;
                }
                self.machine.sign_out();
                *self.account.write().await = None;
                let _ = std::fs::remove_file(self.data_dir.join("account.json"));
                Ok(Response::Status(self.status_info().await))
            }
            Call::Auth(AuthCall::PairStart {
                name,
                grant,
                ttl_secs,
            }) => self.pair_start(name, grant, *ttl_secs),
            Call::Auth(AuthCall::PairList) => Ok(self.pair_list()),
            Call::Auth(AuthCall::PairRevoke { code }) => self.pair_revoke_code(code),
            Call::Auth(AuthCall::Lock) => {
                let epoch = self.machine.lock(LockReason::User);
                let n = self.store.sessions_revoke_before(epoch.0).unwrap_or(0);
                tracing::info!(epoch = epoch.0, revoked = n, "locked");
                Ok(Response::Ok)
            }
            Call::Auth(AuthCall::WhoAmI) => {
                let acc = self.account.read().await;
                Ok(Response::Account(acc.as_ref().map(|a| AccountInfo {
                    email: a.email.clone(),
                    server: a.server.clone(),
                })))
            }
            Call::Vault(VaultCall::List { query, view }) => {
                if *view > View::Metadata && !self.machine.is_unlocked() {
                    return Err(WtpError::Locked);
                }
                let metas = self.store.query(query).map_err(denied)?;
                let mut rows = Vec::with_capacity(metas.len());
                for m in metas {
                    if *view == View::Metadata {
                        rows.push(ItemView::metadata(m));
                    } else {
                        rows.push(
                            self.project_one(m.id, *view)?
                                .unwrap_or(ItemView::metadata(m)),
                        );
                    }
                }
                Ok(Response::Items(rows))
            }
            Call::Vault(VaultCall::Get { id, view }) => {
                if *view == View::Reveal {
                    self.audit_reveal(*id, "Reveal.Get")?;
                }
                let v = self.project_one(*id, *view)?;
                Ok(Response::Item(v))
            }
            Call::Vault(VaultCall::Create { draft }) => self.write_create(session, draft).await,
            Call::Vault(VaultCall::Patch { id, edits }) => {
                self.write_patch(session, *id, edits).await
            }
            Call::Vault(VaultCall::Delete { ids }) => self.write_delete(session, ids).await,
            Call::Vault(VaultCall::Restore { id }) => self.write_restore(session, *id).await,
            Call::Vault(VaultCall::Overlay { id, op }) => self.overlay_op(session, *id, op),
            Call::Vault(VaultCall::FindDuplicates) => self.duplicates(),
            Call::Vault(VaultCall::Merge { keep, dupes }) => {
                self.merge_dupes(session, *keep, dupes).await
            }
            Call::Vault(VaultCall::MoveToOrg {
                item,
                org,
                collections,
            }) => {
                self.write_move(session, *item, org.clone(), collections.clone())
                    .await
            }
            Call::Use(UseCall::TotpCode { id }) => self.totp(*id),
            Call::Use(UseCall::GeneratePassword { policy }) => {
                let opts = bw_crypto::PasswordOptions {
                    length: policy.get("length").and_then(Value::as_u64).unwrap_or(20) as usize,
                    lowercase: flag(policy, "lowercase"),
                    uppercase: flag(policy, "uppercase"),
                    numbers: flag(policy, "numbers"),
                    special: flag(policy, "special"),
                    avoid_ambiguous: flag(policy, "avoidAmbiguous"),
                };
                let pw = bw_crypto::generate_password(&opts).map_err(denied)?;
                Ok(Response::Secret(pw))
            }
            Call::Use(UseCall::ResolveRef { uri }) => {
                let resp = self.resolve_ref_value(uri)?;
                // Reveal 級出口：明文進入呼叫端 context，記帳已在 audit_call
                self.audit_reveal_ref(session, uri, &resp)?;
                Ok(resp)
            }
            Call::Use(UseCall::Run { plan }) => self.run_plan(sess, plan).await,
            Call::Fill(FillCall::AutoType { id, template }) => {
                self.autotype(*id, template.as_deref()).await
            }
            Call::Fill(_) => Err(WtpError::Unsupported {
                feature: "P1：fill 在 P4".into(),
            }),
            Call::Sync(SyncCall::Trigger { force }) => {
                if *force {
                    self.sync_now().await?;
                }
                self.trigger_drain();
                Ok(Response::Status(self.status_info().await))
            }
            Call::Sync(SyncCall::Status) => Ok(Response::Status(self.status_info().await)),
            Call::Sync(SyncCall::ListConflicts) => self.list_conflicts().await,
            Call::Sync(SyncCall::ResolveConflict { id, pick }) => {
                self.resolve_conflict(*id, *pick).await
            }
            Call::Agent(AgentCall::Audit { since, limit }) => {
                let rows = self
                    .store
                    .audit_query(&AuditFilter {
                        since_ts: since.clone(),
                        limit: *limit,
                        ..Default::default()
                    })
                    .map_err(denied)?;
                Ok(Response::Audit(
                    rows.iter()
                        .filter_map(|r| serde_json::to_value(r).ok())
                        .collect(),
                ))
            }
            Call::Agent(AgentCall::AuditVerify) => {
                let (count, head) = self.store.audit_verify().map_err(denied)?;
                Ok(Response::AuditChain(AuditChainInfo {
                    ok: true,
                    count,
                    head,
                }))
            }
            Call::Agent(AgentCall::OpenSession {
                scopes,
                ttl_secs,
                name,
            }) => self.open_session(sess, scopes, *ttl_secs, name),
            Call::Agent(AgentCall::Approve { id, grants }) => {
                self.approve(sess, *id, grants.as_ref())
            }
            Call::Agent(AgentCall::Revoke { session: sid }) => self.revoke(sess, *sid),
            Call::Agent(AgentCall::ListSessions) => self.list_sessions(sess),
            Call::Agent(AgentCall::ListPending) => Ok(Response::Sessions(
                self.pending_list()
                    .into_iter()
                    .map(|(id, summary)| json!({"id": id, "summary": summary}))
                    .collect(),
            )),
            Call::Admin(AdminCall::Version) => Ok(Response::Version(format!(
                "bitwarderd {} proto v{PROTO_VERSION}",
                env!("CARGO_PKG_VERSION")
            ))),
            Call::Admin(AdminCall::ServerProfile) => {
                let g = self.server.read().await;
                let h = g.as_ref().ok_or(WtpError::NotFound)?;
                let p = h.client.cached_probe().await;
                Ok(Response::Profile(p.profile))
            }
            Call::Admin(AdminCall::Diagnostics) => Ok(Response::Status(self.status_info().await)),
        }
    }

    async fn login(&self, server: &str, email: &str, pw: &str) -> DispatchResult {
        let client =
            std::sync::Arc::new(Client::with_options(server, Hub::sync_options()).map_err(denied)?);
        let pre = client.prelogin(email).await.map_err(map_server_err)?;
        let kdf = KdfWire::from_prelogin(&pre).ok_or_else(|| drift("prelogin 缺 KDF 欄位"))?;
        let mk = bw_crypto::master_key(pw, email, kdf.to_params()).map_err(denied)?;
        let hash = bw_crypto::master_password_hash(&mk, pw).as_b64().to_owned();
        let login = PasswordLogin::new(email, hash, self.device.clone());
        let bundle = client
            .password_login(&login)
            .await
            .map_err(map_server_err)?;
        let keys = bundle
            .keys
            .clone()
            .filter(|k| k.key.is_some())
            .ok_or_else(|| drift("token 回應沒有可用 Keys（client_credentials 不解 vault）"))?;
        let fingerprint = sha256_hex(&keys.raw.to_string());
        let acc = AccountRecord {
            server: server.to_owned(),
            email: email.to_owned(),
            access_token: Some(bundle.access_token.clone()),
            refresh_token: bundle.refresh_token.clone(),
            kdf: kdf.kind,
            kdf_iterations: kdf.iterations,
            kdf_memory: kdf.memory,
            kdf_parallelism: kdf.parallelism,
            protected_user_key: keys.key.clone().unwrap(),
            keys_fingerprint: Some(fingerprint.clone()),
        };
        if let Some(t) = acc.access_token.clone() {
            client.set_access_token(&t).await;
        }
        *self.account.write().await = Some(acc.clone());
        self.persist_account().await?;

        self.machine.set_auth_context(AuthContext {
            email: email.to_owned(),
            kdf: kdf.to_params(),
            protected_user_key: acc.protected_user_key.clone(),
            keys_fingerprint: acc.keys_fingerprint.clone(),
        });
        self.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                pw.to_owned(),
            )))
            .map_err(denied)?;
        self.server.write().await.replace(ServerHandle { client });
        self.sync_now().await?;
        Ok(Response::Status(self.status_info().await))
    }

    pub async fn sync_now(&self) -> Result<(), WtpError> {
        let g = self.server.read().await;
        let h = g.as_ref().ok_or(WtpError::NotFound)?;
        let raw = h.client.sync().await.map_err(map_server_err)?;
        self.last_sync_ms
            .store(self.store.now_ms(), std::sync::atomic::Ordering::Relaxed);
        self.store.apply_sync(&raw).map_err(denied)?;
        if let Some(keys) = raw.pointer("/profile/keys") {
            let fp = sha256_hex(&keys.to_string());
            if self.machine.note_key_drift(Some(&fp)) {
                tracing::warn!("key drift detected");
            }
        }
        self.reindex_plain().map_err(denied)?;
        let count = self.store.cipher_count().map_err(denied)?;
        self.machine.set_mirror(count);
        Ok(())
    }

    /// 鏡像落盤後的名字索引回填：解密只發生在 `with_keys` 閉包內。
    /// 單欄位解密失敗容忍跳過（漂移防御），不阻塞整批。
    fn reindex_plain(&self) -> Result<(), String> {
        let metas = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;
        for m in metas {
            let Some(row) = self.store.item(m.id).map_err(|e| e.to_string())? else {
                continue;
            };
            let decrypted = self.machine.with_keys(|kb| {
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
            });
            let (name, uris, username, password) = match decrypted {
                Ok(v) => v,
                Err(_) => continue,
            };
            let _ = self.store.set_plain_meta(m.id, name.as_deref(), &uris);
            let _ = self
                .store
                .set_plain_secrets(m.id, username.as_deref(), password.as_deref());
        }
        Ok(())
    }

    fn project_one(&self, id: ItemId, view: View) -> Result<Option<ItemView>, WtpError> {
        let meta = self.store.meta(id).map_err(denied)?;
        let base = match meta {
            Some(m) => m,
            None => return Ok(None),
        };
        // 請求 secret 級視窗但未解鎖：明確回 Locked，不靜默降級成 metadata
        if view != View::Metadata && !self.machine.is_unlocked() {
            return Err(WtpError::Locked);
        }
        if view == View::Metadata {
            return Ok(Some(ItemView::metadata(base)));
        }
        let row = self.store.item(id).map_err(denied)?;
        let Some(row) = row else {
            return Ok(Some(ItemView::metadata(base)));
        };
        let dec = self.machine.with_keys(|kb| {
            let uk = kb.user_key();
            let login = row.enc_cipher.get("login");
            let username = login
                .and_then(|l| l.get("username"))
                .and_then(Value::as_str)
                .and_then(|e| bw_crypto::decrypt(uk, &e.to_string()).ok());
            let password = login
                .and_then(|l| l.get("password"))
                .and_then(Value::as_str)
                .and_then(|e| bw_crypto::decrypt(uk, &e.to_string()).ok());
            (username, password)
        });
        let (username, password) = dec.map_err(denied)?;
        let v = match view {
            View::Masked => {
                ItemView::metadata(base).masked(username, password.as_deref().map(mask_tail), false)
            }
            View::Reveal => ItemView::metadata(base)
                .masked(username, None, false)
                .revealed(password),
            View::Metadata => ItemView::metadata(base),
        };
        Ok(Some(v))
    }

    /// AutoType：明文只進 blocking 執行緒化作按鍵事件，回應僅含計數（§2.1 出口紀律）。
    /// 倒數 + 鍵距全程 ~3s，放 `spawn_blocking` 餵養事件迴圈不被餓死。
    async fn autotype(&self, id: ItemId, template: Option<&str>) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(WtpError::Locked);
        }
        // 未授權先觸發系統彈窗（會把 bitwarderd 登記進輔助使用清單）；
        // 不查就直接打字的話 CGEventPost 會靜默丟事件，使用者看到「成功但沒發生事」
        #[cfg(target_os = "macos")]
        if !bw_autotype::accessibility_trusted(true) {
            return Err(denied(
                "輔助使用權限未授予：系統已彈出授權窗（或到 設定→隱私與安全性→輔助使用 允許 bitwarderd），完成後重試",
            ));
        }
        let tpl =
            bw_autotype::TypeTemplate::parse(template.unwrap_or(bw_autotype::DEFAULT_TEMPLATE))
                .map_err(denied)?;
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        let (username, password) = self
            .machine
            .with_keys(|kb| {
                let dec = |field: &str| {
                    row.enc_cipher
                        .pointer(&format!("/login/{field}"))
                        .and_then(Value::as_str)
                        .and_then(|e| bw_crypto::decrypt(kb.user_key(), &e.to_string()).ok())
                };
                (
                    Zeroizing::new(dec("username").unwrap_or_default()),
                    Zeroizing::new(dec("password").unwrap_or_default()),
                )
            })
            // 先過 is_unlocked 後仍失敗＝中途被鎖：語意同 Locked（totp 同款處理）
            .map_err(|_| WtpError::Locked)?;
        if username.is_empty() && password.is_empty() {
            return Err(denied("item 無 username/password 可打字"));
        }
        let stats = tokio::task::spawn_blocking(move || -> Result<_, WtpError> {
            let mut sink = bw_autotype::MacSink::new().ok_or_else(|| WtpError::Unsupported {
                feature: "按鍵注入不可用（非 macOS 或 CGEventSource 建立失敗）".into(),
            })?;
            bw_autotype::countdown(
                |rem| {
                    tracing::info!(remaining_secs = rem, "AutoType 倒數：請切到目標視窗");
                    eprintln!("autotype: {rem} 秒後開始打字，請切到目標視窗");
                },
                std::thread::sleep,
            );
            Ok(bw_autotype::emit(&mut sink, &tpl, &username, &password))
        })
        .await
        // 外層是 JoinError（任務掛掉）→ Denied；內層已是 WtpError（如 sink 不可用）原樣上拋
        .map_err(denied)??;
        Ok(Response::Json(json!({
            "typed": stats.typed,
            "fields": stats.fields,
        })))
    }

    fn totp(&self, id: ItemId) -> DispatchResult {
        let row = self.store.item(id).map_err(denied)?;
        let row = row.ok_or(WtpError::NotFound)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = self
            .machine
            .with_keys(|kb| {
                row.enc_cipher
                    .pointer("/login/totp")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "no totp seed".to_string())
                    .and_then(|e| {
                        bw_crypto::decrypt(kb.user_key(), &e.to_string()).map_err(|d| d.to_string())
                    })
                    .and_then(|seed| {
                        bw_crypto::totp_code(seed.trim(), now).map_err(|t| t.to_string())
                    })
            })
            .map_err(|_| WtpError::Locked)?
            .map_err(denied)?;
        Ok(Response::TotpCode {
            code,
            valid_for_secs: (30 - now % 30) as u32,
        })
    }

    fn audit_reveal(&self, id: ItemId, action: &str) -> Result<(), WtpError> {
        self.audit_reveal_line(None, id, action)
    }

    fn audit_reveal_ref(&self, session: &str, uri: &str, resp: &Response) -> Result<(), WtpError> {
        let item = match resp {
            Response::Secret(_) => bw_agent::parse_ref(uri).ok().map(|r| r.item.to_string()),
            _ => None,
        };
        let _ = session;
        let _ = item;
        Ok(()) // 主審計由 audit_call（Secret 級、bytes_out）覆蓋
    }

    fn audit_reveal_line(
        &self,
        _s: Option<&str>,
        id: ItemId,
        action: &str,
    ) -> Result<(), WtpError> {
        let _ = self.store.audit_append(&AuditRecord {
            ts: self.store.now_ms().to_string(),
            session: None,
            action: action.to_owned(),
            item: Some(id.to_string()),
            field: Some(json!("Password")),
            sens: bw_proto::Sensitivity::Secret,
            outcome: "ok".into(),
            bytes_out: 0,
            approval: None,
            epoch: self.machine.epoch().0,
        });
        Ok(())
    }
}

fn mask_tail(pw: &str) -> String {
    let tail: String = pw
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("••••{tail}")
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(true)
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// KDF 欄位的持久化/傳輸中介（bw-crypto 的 KdfParams 不實作 serde，邊界在這裡轉）。
#[derive(Clone, Copy)]
struct KdfWire {
    kind: i64,
    iterations: u64,
    memory: Option<u64>,
    parallelism: Option<u64>,
}

impl KdfWire {
    fn from_prelogin(v: &Value) -> Option<Self> {
        let kind = v.get("kdf").and_then(Value::as_i64).unwrap_or(0);
        let iterations = v
            .get("kdfIterations")
            .and_then(Value::as_u64)
            .unwrap_or(600_000);
        Some(Self {
            kind,
            iterations,
            memory: v.get("kdfMemory").and_then(Value::as_u64),
            parallelism: v.get("kdfParallelism").and_then(Value::as_u64),
        })
    }
    fn to_params(self) -> bw_crypto::KdfParams {
        if self.kind == 1 {
            bw_crypto::KdfParams::Argon2id {
                m: self.memory.unwrap_or(64) as u32,
                t: self.iterations as u32,
                p: self.parallelism.unwrap_or(4) as u32,
            }
        } else {
            bw_crypto::KdfParams::Pbkdf2 {
                iterations: self.iterations as u32,
            }
        }
    }
}

fn kdf_params(a: &AccountRecord) -> bw_crypto::KdfParams {
    KdfWire {
        kind: a.kdf,
        iterations: a.kdf_iterations,
        memory: a.kdf_memory,
        parallelism: a.kdf_parallelism,
    }
    .to_params()
}

fn map_server_err(e: ServerError) -> WtpError {
    match e {
        ServerError::TwoFactorRequired { challenge } => WtpError::Denied {
            grant_gap: format!(
                "需要第二因子（providers: {:?}），請以 --otp 重試",
                challenge.providers
            ),
        },
        ServerError::Http { status, detail } => WtpError::ServerDrift {
            detail: format!("http {status}: {detail}"),
        },
        other => WtpError::Denied {
            grant_gap: other.to_string(),
        },
    }
}

fn action_tag(c: &Call) -> String {
    match c {
        Call::Auth(AuthCall::Login { .. }) => "Auth.Login",
        Call::Auth(AuthCall::Unlock { .. }) => "Auth.Unlock",
        Call::Auth(AuthCall::Lock) => "Auth.Lock",
        Call::Auth(AuthCall::SignOut) => "Auth.SignOut",
        Call::Auth(AuthCall::PairStart { .. }) => "Auth.PairStart",
        Call::Auth(AuthCall::PairList) => "Auth.PairList",
        Call::Auth(AuthCall::PairRevoke { .. }) => "Auth.PairRevoke",
        Call::Auth(AuthCall::WhoAmI) => "Auth.WhoAmI",
        Call::Vault(VaultCall::List { view, .. }) => return format!("Vault.List.{view:?}"),
        Call::Vault(VaultCall::Get { view, .. }) => return format!("Vault.Get.{view:?}"),
        Call::Vault(VaultCall::Create { .. }) => "Vault.Create",
        Call::Vault(VaultCall::Patch { .. }) => "Vault.Patch",
        Call::Vault(VaultCall::Delete { .. }) => "Vault.Delete",
        Call::Vault(VaultCall::Restore { .. }) => "Vault.Restore",
        Call::Vault(VaultCall::Overlay { .. }) => "Vault.Overlay",
        Call::Vault(VaultCall::FindDuplicates) => "Vault.FindDuplicates",
        Call::Vault(VaultCall::Merge { .. }) => "Vault.Merge",
        Call::Vault(VaultCall::MoveToOrg { .. }) => "Vault.MoveToOrg",
        Call::Use(UseCall::TotpCode { .. }) => "Use.TotpCode",
        Call::Use(UseCall::GeneratePassword { .. }) => "Use.GeneratePassword",
        Call::Use(UseCall::ResolveRef { .. }) => "Use.ResolveRef",
        Call::Use(UseCall::Run { .. }) => "Use.Run",
        Call::Fill(FillCall::Request { .. }) => "Fill.Request",
        Call::Fill(FillCall::Claim { .. }) => "Fill.Claim",
        Call::Fill(FillCall::AutoType { .. }) => "Fill.AutoType",
        Call::Sync(SyncCall::Trigger { .. }) => "Sync.Trigger",
        Call::Sync(SyncCall::Status) => "Sync.Status",
        Call::Sync(SyncCall::ListConflicts) => "Sync.ListConflicts",
        Call::Sync(SyncCall::ResolveConflict { .. }) => "Sync.ResolveConflict",
        Call::Agent(AgentCall::OpenSession { .. }) => "Agent.OpenSession",
        Call::Agent(AgentCall::Approve { .. }) => "Agent.Approve",
        Call::Agent(AgentCall::Revoke { .. }) => "Agent.Revoke",
        Call::Agent(AgentCall::ListSessions) => "Agent.ListSessions",
        Call::Agent(AgentCall::ListPending) => "Agent.ListPending",
        Call::Agent(AgentCall::Audit { .. }) => "Agent.Audit",
        Call::Agent(AgentCall::AuditVerify) => "Agent.AuditVerify",
        Call::Admin(AdminCall::ServerProfile) => "Admin.ServerProfile",
        Call::Admin(AdminCall::Diagnostics) => "Admin.Diagnostics",
        Call::Admin(AdminCall::Version) => "Admin.Version",
    }
    .to_owned()
}

fn sensitivity_of_call(c: &Call, resp: Option<&Response>) -> bw_proto::Sensitivity {
    use bw_proto::Sensitivity::*;
    // 回應帶明文（Secret/Reveal 出口）一律 Secret 級，優先於呼叫形態
    if matches!(
        resp,
        Some(Response::Secret(_))
            | Some(Response::Item(Some(bw_proto::ItemView {
                password: Some(_),
                ..
            })))
    ) {
        return Secret;
    }
    match c {
        Call::Vault(VaultCall::Get { view, .. }) => match view {
            View::Reveal => Secret,
            _ => Identity,
        },
        Call::Vault(VaultCall::List { .. }) => Identity,
        Call::Vault(VaultCall::Create { .. })
        | Call::Vault(VaultCall::Patch { .. })
        | Call::Vault(VaultCall::Delete { .. })
        | Call::Vault(VaultCall::Restore { .. })
        | Call::Vault(VaultCall::Overlay { .. })
        | Call::Vault(VaultCall::FindDuplicates)
        | Call::Vault(VaultCall::Merge { .. })
        | Call::Vault(VaultCall::MoveToOrg { .. }) => Identity,
        Call::Use(UseCall::TotpCode { .. })
        | Call::Use(UseCall::Run { .. })
        | Call::Use(UseCall::ResolveRef { .. })
        | Call::Use(UseCall::GeneratePassword { .. }) => Secret,
        Call::Auth(_) | Call::Admin(_) | Call::Sync(_) | Call::Agent(_) | Call::Fill(_) => Opaque,
    }
}
