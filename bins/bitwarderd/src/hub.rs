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
    OutboxCounts, PROTO_VERSION, PasskeyCall, PushCall, Query, Response, StatusInfo, SyncCall,
    TwoFactorInput, TwoFactorProviderInfo, UseCall, VaultCall, View, WtpError,
};
use bw_server::{Client, PasswordLogin, ServerError, TwoFactorProviderType};
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
    /// 使用者 RSA 私鑰信封（token 回應 `PrivateKey`，原樣保存；P4b 成員
    /// 路徑解 org akey 用）。舊檔缺欄 → None。
    #[serde(default)]
    pub enc_private_key: Option<String>,
}

pub struct Hub {
    pub data_dir: PathBuf,
    /// Arc：publish_signal 的 APNs 副發 task 需要跨 spawn 持有 store。
    pub store: Arc<Store>,
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
    /// BeginAssert→FinishAssert 事務的暫存 authData/hash/counter（鍵=規範化 credentialId）。
    /// 記憶體態：daemon 重啟即失，Swift 端須重跑 Begin（冪等）。
    pub pending_asserts: Mutex<HashMap<String, crate::passkey::PendingAssert>>,
    /// 未消耗的一次性配對碼（§1.2）
    pub pairings: Mutex<HashMap<String, crate::agent::PairingSpec>>,
    /// ntfy 信令 URL（None = 不發）；只傳不透明信令，明文永不上通道
    pub ntfy_url: Option<String>,
    /// APNs 推播（None = 不發）；與 ntfy 同源時機副發同一條不透明信令
    pub apns: Option<Arc<crate::apns::ApnsConfig>>,
    /// TLS listener 啟動後快取的 SPKI pin（pair start 顯示用）
    pub tls_pin: std::sync::OnceLock<String>,
}

pub type DispatchResult = Result<Response, WtpError>;

fn denied(detail: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: detail.to_string(),
    }
}

pub(crate) fn drift(detail: impl std::fmt::Display) -> WtpError {
    WtpError::ServerDrift {
        detail: detail.to_string(),
    }
}

/// 主密碼強度閘（契約 2c：與註冊閘值一致；dev-register/VW 無本地閘，
/// 此常数是本專案的唯一真相源，daemon 拒短碼、CLI/GUI 前置提示同值）。
const MIN_MASTER_PASSWORD: usize = 12;

impl Hub {
    pub async fn open(
        data_dir: &Path,
        ntfy_url: Option<String>,
        apns: Option<Arc<crate::apns::ApnsConfig>>,
    ) -> Result<Arc<Hub>, String> {
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
                enc_private_key: a.enc_private_key.clone(),
            });
        }
        let (drain_tx, drain_rx) = tokio::sync::mpsc::unbounded_channel();
        let hub = Arc::new(Hub {
            data_dir: data_dir.to_path_buf(),
            store: Arc::new(store),
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
            pending_asserts: Mutex::new(HashMap::new()),
            pairings: Mutex::new(HashMap::new()),
            ntfy_url,
            apns,
            tls_pin: std::sync::OnceLock::new(),
        });
        if let Some(a) = account {
            let client = std::sync::Arc::new(
                Client::with_options(&a.server, Hub::sync_options()).map_err(|e| e.to_string())?,
            );
            if let Some(t) = a.access_token.clone() {
                client.set_access_token(&t).await;
            }
            // 4c：重啟還原也要帶續期憑證，否則 401 收口只能拋錯
            client.set_refresh_token(a.refresh_token.as_deref()).await;
            // 續期成功 → account.json 就地讀改寫（真態在磁碟；記憶體
            // AccountRecord 的 token 欄僅供展示，容許短暫落後）＋解除
            // needs_reauth。Weak 中樞引用：sink 掛在 client、client 住在 hub，
            // 強引用會成環。
            let weak = Arc::downgrade(&hub);
            client.set_token_sink(std::sync::Arc::new(move |access, refresh| {
                let Some(h) = weak.upgrade() else { return };
                let path = h.data_dir.join("account.json");
                if let Ok(bytes) = std::fs::read(&path)
                    && let Ok(mut v) = serde_json::from_slice::<Value>(&bytes)
                {
                    v["access_token"] = json!(access);
                    v["refresh_token"] = match refresh {
                        Some(r) => json!(r),
                        None => Value::Null,
                    };
                    if std::fs::write(&path, v.to_string()).is_ok() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &path,
                                std::fs::Permissions::from_mode(0o600),
                            );
                        }
                    }
                }
                h.machine.note_token_renewed();
            }));
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
        let acc = self.account.read().await;
        let email = acc.as_ref().map(|a| a.email.clone());
        let server = acc.as_ref().map(|a| a.server.clone());
        drop(acc);
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
            needs_reauth: {
                let server = self.server.read().await;
                self.machine.needs_reauth()
                    || server
                        .as_ref()
                        .is_some_and(|h| h.client.needs_relogin())
            },
            proto: PROTO_VERSION,
            orgs: self.store.org_count().unwrap_or(0),
            email,
            server,
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
                two_factor,
            }) => self.login(server, email, pw, two_factor.as_ref()).await,
            Call::Auth(AuthCall::Login { .. }) => Err(denied(
                "P1: daemon-side password challenge 未実装；請由 CLI 傳入密碼",
            )),
            Call::Auth(AuthCall::Unlock { biometric }) => {
                if *biometric {
                    return Err(denied("P1: biometric assertion 尚未接 KeychainKeystore"));
                }
                match self.machine.submit(UnlockMaterial::DeviceAssertion) {
                    Ok(UnlockReceipt::Unlocked { .. }) => {
                        // 解鎖完成處回填明文索引（2026-11-07 macOS demo 實測：
                        // 重啟後鎖定態 sync 把 meta_plain 蓋回信封形態，
                        // unlock 不重解就整頁-envelope）。AlreadyUnlocked 不重跑。
                        self.reindex_all()?;
                        Ok(Response::Status(self.status_info().await))
                    }
                    Ok(UnlockReceipt::AlreadyUnlocked { .. }) => {
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
            Call::Auth(AuthCall::ChangePassword {
                current: Some(cur),
                new: Some(nw),
            }) => self.change_password(cur, nw).await,
            Call::Auth(AuthCall::ChangePassword { .. }) => Err(denied(
                "P1: daemon 端收密码未実装；請由 CLI/GUI 經本機通道傳入",
            )),
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
                Ok(Response::Item(v.map(Box::new)))
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
            // 三件套（v5）：資料夾與硬刪的業務在 datamanage.rs。
            Call::Vault(VaultCall::CreateFolder { name }) => self.create_folder(name).await,
            Call::Vault(VaultCall::ListFolders) => self.list_folders(),
            Call::Vault(VaultCall::DeleteFolder { id }) => {
                self.delete_folder(session, *id).await
            }
            Call::Vault(VaultCall::Purge { id }) => self.purge_item(*id).await,
            Call::Vault(VaultCall::Import { items, format }) => {
                self.write_import(session, items, *format).await
            }
            Call::Vault(VaultCall::Attachment { sub }) => match sub {
                bw_proto::AttachmentOp::Upload {
                    item_id,
                    file_name,
                    bytes,
                } => self.attach_upload(session, *item_id, file_name, bytes).await,
                bw_proto::AttachmentOp::Download {
                    item_id,
                    attachment_id,
                } => self.attach_download(*item_id, attachment_id).await,
                bw_proto::AttachmentOp::Delete {
                    item_id,
                    attachment_id,
                } => self.attach_delete(*item_id, attachment_id).await,
            },
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
            Call::Passkey(pc) => match pc {
                PasskeyCall::GetPasskeys { rp_id } => self.passkey_list(rp_id.as_deref()),
                PasskeyCall::RegisterPasskey { .. } => self.passkey_register(session, pc).await,
                PasskeyCall::AssertPasskey { .. } => self.passkey_assert(session, pc).await,
                PasskeyCall::BeginAssert {
                    credential_id,
                    client_data_hash,
                } => self.passkey_begin_assert(credential_id, client_data_hash),
                PasskeyCall::FinishAssert {
                    credential_id,
                    signature,
                } => {
                    self.passkey_finish_assert(session, credential_id, signature)
                        .await
                }
                PasskeyCall::BeginRegister { .. } => self.passkey_begin_register(),
                PasskeyCall::FinishRegister { .. } => {
                    self.passkey_finish_register(session, pc).await
                }
            },
            Call::Push(pc) => match pc {
                PushCall::RegisterPush { token, platform } => {
                    self.store.push_token_put(token, platform).map_err(denied)?;
                    Ok(Response::Ok)
                }
                PushCall::UnregisterPush { token } => {
                    self.store.push_token_remove(token).map_err(denied)?;
                    Ok(Response::Ok)
                }
                PushCall::ListPush => {
                    let rows = self.store.push_token_list().map_err(denied)?;
                    let list = rows
                        .iter()
                        .map(|(token, platform)| {
                            json!({"token": mask_push_token(token), "platform": platform})
                        })
                        .collect::<Vec<_>>();
                    Ok(Response::Json(Value::Array(list)))
                }
            },
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
            Call::Agent(AgentCall::Deny { id }) => self.deny(sess, *id),
            Call::Agent(AgentCall::Revoke { session: sid }) => self.revoke(sess, *sid),
            Call::Agent(AgentCall::ListSessions) => self.list_sessions(sess),
            Call::Agent(AgentCall::ListPending) => Ok(Response::Sessions(
                self.pending_list()
                    .into_iter()
                    .map(|(id, summary, requested_at_ms)| {
                        json!({"id": id, "summary": summary, "requested_at_ms": requested_at_ms})
                    })
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

    /// 登入（含 2FA 第二步回合）。挑戰**不跨呼叫保存**：`TwoFactorChallenge`
    /// 只是「原 login 參數＋伺服器列出的因子」的 client 端包裝，master password
    /// hash 可由 (pw, prelogin KDF) 決定性重算，故第二步由呼叫端原樣重發
    /// Login{password, two_factor}（daemon 端 pinentry 收碼未實現——Login 的
    /// password None 直接拒——無既有互動通道可複用；重發方案讓 daemon 保持
    /// 無狀態、重啟不影響回合，密碼明文只在既有本機線多走一次，不新增洩密面）。
    async fn login(
        &self,
        server: &str,
        email: &str,
        pw: &str,
        two_factor: Option<&TwoFactorInput>,
    ) -> DispatchResult {
        let client =
            std::sync::Arc::new(Client::with_options(server, Hub::sync_options()).map_err(denied)?);
        let pre = client.prelogin(email).await.map_err(map_server_err)?;
        let kdf = KdfWire::from_prelogin(&pre).ok_or_else(|| drift("prelogin 缺 KDF 欄位"))?;
        let mk = bw_crypto::master_key(pw, email, kdf.to_params()).map_err(denied)?;
        let hash = bw_crypto::master_password_hash(&mk, pw).as_b64().to_owned();
        let mut login = PasswordLogin::new(email, hash, self.device.clone());
        if let Some(tf) = two_factor {
            if !TwoFactorProviderInfo::is_supported(tf.provider) {
                return Err(denied(format!(
                    "此因子尚未支援：{}（請選手機驗證器或 Email）",
                    TwoFactorProviderInfo::label(tf.provider)
                )));
            }
            login = login.two_factor(
                TwoFactorProviderType::from_i32(tf.provider),
                tf.token.clone(),
                tf.remember,
            );
        }
        let bundle = match client.password_login(&login).await {
            Ok(b) => b,
            // 不吞挑戰：映射成 TwoFactorRequest 讓 GUI/CLI 原地進第二步。
            Err(ServerError::TwoFactorRequired { challenge }) => {
                return Ok(Response::TwoFactorRequest {
                    providers: challenge
                        .providers
                        .iter()
                        .map(|p| TwoFactorProviderInfo {
                            provider: p.kind.as_i32(),
                            hint: p
                                .details
                                .as_ref()
                                .and_then(|d| {
                                    d.get("Email").or_else(|| d.get("email")).map(Value::as_str)
                                })
                                .flatten()
                                .map(str::to_owned),
                        })
                        .collect(),
                });
            }
            Err(other) => return Err(map_server_err(other)),
        };
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
            enc_private_key: keys.private_key.clone(),
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
            enc_private_key: acc.enc_private_key.clone(),
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

    /// 改主密碼（切片 A 契約 2）。順序即收斂策略：
    ///
    /// 1. 解鎖態閘（改密要拿 user key 驗私鑰鏈）；強度閘 12 字（契約 2c）。
    /// 2. 驗 current：本地信封比對是快速通道，最終裁判是伺服器
    ///    （`POST /accounts/password` 先比對舊 hash，400＝密碼錯；殘留死
    ///    token 401 時以 password grant 重登入代替裁決）。
    /// 3. 先遠端成功再落地：POST 失敗＝本地零變更（契約 2e）。
    /// 4. 成功後 VW reset security stamp 並輪換全部 refresh token：必須以
    ///    新密碼完整重登入換新 token（`refresh()` 此時已死），伺服器回顯
    ///    akey == 新信封才落地 account.json 與 AuthContext。
    ///
    /// 冪等語意：current == new 為 no-op（OK，不碰遠端、不踢其他裝置）；
    /// 崩潰後重跑（current 帶新密碼）經步驟 2 的伺服器裁判收斂。
    /// 金鑰模型注記：user key 不輪換（VW 的 `key` 欄位直接寫進 `user.akey`），
    /// 故 FileKeyStore 封存內容（user key 位元組）不變、無需重封；
    /// 真正輪換 user key 是 rotate-user-account-keys 的範圍（本切片外）。
    async fn change_password(&self, current: &str, new: &str) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(denied("改主密碼需要解鎖態（舊 user key 要驗證金鑰鏈）"));
        }
        let Some(mut acc) = self.account.read().await.clone() else {
            return Err(WtpError::NotFound);
        };
        if new.chars().count() < MIN_MASTER_PASSWORD {
            return Err(denied(format!(
                "新主密碼太短（至少 {MIN_MASTER_PASSWORD} 字元）"
            )));
        }
        if current == new {
            return Ok(Response::Ok);
        }
        let kdf = kdf_params(&acc);
        let mk_old = bw_crypto::master_key(current, &acc.email, kdf)
            .map_err(|_| denied("現有密碼不正確"))?;
        let hash_old = bw_crypto::master_password_hash(&mk_old, current)
            .as_b64()
            .to_owned();
        // 私鑰鏈硬閘（契約 2b）：解封態 KeyBundle 的 user key 必須解得開
        // 封存私鑰信封，否則本地金鑰鏈已斷，改密只會把斷鏈帶進新信封。
        let chain_ok = self
            .machine
            .with_keys(|kb| match kb.encrypted_private_key() {
                Some(enc) => bw_crypto::decrypt_private_key(kb.user_key(), enc).is_ok(),
                None => true,
            })
            .unwrap_or(false);
        if !chain_ok {
            return Err(denied("金鑰鏈不完整（封存私鑰解不開），請先鎖庫以現有密碼重新解鎖"));
        }
        // 驗 current：先本地（舊 master key 解 protected user key 信封並與
        // 解封態金鑰包一致）；本地不過**不直接拒**——信封可能過期（上次改密
        // VW 已成功、落地前崩潰），正確與否由伺服器在 POST 裡裁判。
        let local_ok =
            bw_crypto::decrypt_user_key(&bw_crypto::stretch(&mk_old), &acc.protected_user_key)
                .map(|uk| {
                    self.machine
                        .with_keys(|kb| kb.user_key().as_bytes() == uk.as_bytes())
                        .unwrap_or(false)
                })
                .unwrap_or(false);
        let server = self.server.read().await;
        let h = server.as_ref().ok_or(WtpError::NotFound)?;
        let mk_new = bw_crypto::master_key(new, &acc.email, kdf)
            .map_err(|_| denied("新密碼無法派生金鑰"))?;
        let hash_new = bw_crypto::master_password_hash(&mk_new, new)
            .as_b64()
            .to_owned();
        let wrapped_new = self
            .machine
            .with_keys(|kb| bw_crypto::encrypt_user_key(&mk_new, kb.user_key()))
            .map_err(|_| denied("vault 未解鎖"))?
            .map_err(denied)?;
        let post = h
            .client
            .change_password(&hash_old, &hash_new, &wrapped_new)
            .await;
        // 401＝崩潰遺留的死 token（上次成功已 reset stamp）：以 current 重打
        // password grant 換新 token——這一步就是伺服器對 current 的裁判，
        // 拒絕（invalid_grant）即現有密碼不正確。
        let post = match post {
            Err(ServerError::Http { status: 401, .. }) => {
                h.client
                    .password_login(&PasswordLogin::new(
                        &acc.email,
                        hash_old.clone(),
                        self.device.clone(),
                    ))
                    .await
                    .map_err(|e| match e {
                        ServerError::Http { status: 400, .. }
                        | ServerError::Rejected(_) => {
                            denied("現有密碼不正確（伺服器拒絕重登入）")
                        }
                        other => map_server_err(other),
                    })?;
                h.client
                    .change_password(&hash_old, &hash_new, &wrapped_new)
                    .await
            }
            other => other,
        };
        if !local_ok {
            // 本地已判不了，伺服器的 400 原文就是最終答案。
            post.map_err(|e| match e {
                ServerError::Http { status: 400, detail } => {
                    denied(format!("現有密碼不正確（伺服器拒絕：{detail}）"))
                }
                other => map_server_err(other),
            })?;
        } else {
            post.map_err(map_server_err)?;
        }
        // 遠端已改：VW 把 security stamp reset 且**輪換了全部 refresh token**
        // （`reset_security_stamp` → `rotate_refresh_tokens_by_user`），`refresh()`
        // 已不可用——以新密碼完整重登入換新 token，並順帶收伺服器回顯的
        // 新信封做收斂證據。中途崩潰重跑同一指令收斂（見函數註解）。
        let bundle = h
            .client
            .password_login(&PasswordLogin::new(
                &acc.email,
                hash_new.clone(),
                self.device.clone(),
            ))
            .await
            .map_err(|e| drift(format!(
                "遠端密碼已改，但新密碼重登入失敗（{e}）；請以新密碼重跑 change-password 收斂"
            )))?;
        drop(server);
        if bundle.keys.as_ref().and_then(|k| k.key.as_deref()) != Some(wrapped_new.as_str()) {
            return Err(drift(
                "遠端密碼已改，但 token 回顯的 akey 與新信封不符；請重跑 change-password 收斂",
            ));
        }
        self.machine.set_auth_context(AuthContext {
            email: acc.email.clone(),
            kdf,
            protected_user_key: wrapped_new.clone(),
            keys_fingerprint: acc.keys_fingerprint.clone(),
            enc_private_key: acc.enc_private_key.clone(),
        });
        // 新密碼 self-check：submit 在解鎖態仍驗證材料（AlreadyUnlocked 路徑）。
        // 失败時遠端已改、本地未落地——回錯讓呼叫端重跑收斂，不硬落地。
        self.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                new.to_owned(),
            )))
            .map_err(|e| drift(format!(
                "遠端密碼已改，但新密碼本地自查失敗（{e}）；請重跑 change-password 收斂"
            )))?;
        acc.protected_user_key = wrapped_new;
        acc.access_token = Some(bundle.access_token.clone());
        if let Some(r) = bundle.refresh_token.clone() {
            acc.refresh_token = Some(r);
        }
        *self.account.write().await = Some(acc);
        self.persist_account().await?;
        Ok(Response::Ok)
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
        self.backfill_org_keys(&h.client).await;
        drop(g);
        self.reindex_all()?;
        let count = self.store.cipher_count().map_err(denied)?;
        self.machine.set_mirror(count);
        Ok(())
    }

    /// org RSA 公開金鑰信封缺漏時向伺服器補齊（P4b 讀側）：官方雲
    /// `GET /organizations/{id}/crypto/keys` 回 publicKey+encryptedPrivateKey，
    /// Vaultwarden 1.37.2 只回 publicKey（私鑰信封對成員本就不開放）。
    /// 任何失敗容忍跳過，不阻塞 sync。
    async fn backfill_org_keys(&self, client: &Client) {
        let Ok(orgs) = self.store.org_list() else {
            return;
        };
        for o in orgs {
            if o.public_key.is_some() {
                continue;
            }
            match client.org_keys(o.id).await {
                Ok(v) => {
                    let pubk = v.get("publicKey").and_then(Value::as_str);
                    let enck = v.get("encryptedPrivateKey").and_then(Value::as_str);
                    if pubk.is_some() || enck.is_some() {
                        let _ = self.store.org_set_keys(o.id, pubk, enck);
                    }
                }
                Err(e) => tracing::debug!(org = %o.id, err = %e, "org keys endpoint unavailable"),
            }
        }
    }

    /// 自 org 鏡像派生 org 對稱金鑰集合（`with_keys` 閉包內；金鑰值型別
    /// `OrgKey` drop 即清零，不變量 3）。解不開的 akey 只讓該 org 缺席。
    /// 順帶：私鑰信封齊全時以 bw-crypto 原語做往返驗證並落庫
    /// （`orgs.key_verified`，P4b 解密鏈驗收點）。
    pub(crate) fn org_key_map(&self) -> HashMap<Uuid, bw_crypto::OrgKey> {
        let Ok(orgs) = self.store.org_list() else {
            return HashMap::new();
        };
        self.machine
            .with_keys(|kb| {
                let mut out = HashMap::new();
                for o in &orgs {
                    if let Some(akey) = o.key.as_deref() {
                        match kb.unwrap_org_key(akey) {
                            Ok(k) => {
                                out.insert(o.id, k);
                            }
                            Err(e) => {
                                tracing::debug!(org = %o.id, err = %e, "org akey unwrap failed");
                            }
                        }
                    }
                    if !o.key_verified
                        && let (Some(pubk), Some(encp)) =
                            (o.public_key.as_deref(), o.enc_private_key.as_deref())
                        && verify_org_private_key(kb, pubk, encp).is_ok()
                    {
                        let _ = self.store.org_mark_verified(o.id, true);
                    }
                }
                out
            })
            .unwrap_or_default()
    }

    /// cipher 的歸屬 org（共享寫側契約：`collectionIds` 非空 → 所屬 org）。
    /// `organizationId` 是直接證據（VW `/sync` 與 `GET /ciphers/{id}` 都帶，
    /// 見 `crates/bw-sync/fixtures/sync_org_owner_vw.json`）；缺該欄但
    /// `collectionIds` 非空時，以 collections 鏡像反查所屬 org。
    /// 個人項目（兩皆空）→ `None`。
    pub(crate) fn cipher_owner_org(&self, cipher: &Value) -> Option<Uuid> {
        if let Some(o) = cipher
            .get("organizationId")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            return Some(o);
        }
        let cols = cipher.get("collectionIds").and_then(Value::as_array)?;
        if cols.is_empty() {
            return None;
        }
        let listed: Vec<Uuid> = cols
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        self.store
            .collection_list()
            .ok()?
            .into_iter()
            .find(|c| listed.contains(&c.id))
            .map(|c| c.org)
    }

    /// 寫路徑欄位金鑰（base/ours/theirs 攤平與重新加密共用一把）：個人項目
    /// 用 user key；共享項目（[`Self::cipher_owner_org`]）必須用所屬 org 的
    /// 對稱金鑰——該 key 尚未派生（akey 解不出）時回 `None`，呼叫端**不得**
    /// 退回 user key（那會把其他裝置解不開的密文推回伺服器，比不寫更糟）。
    /// 讀路徑的同口徑容錯版見 [`cipher_field_decryptor`]。
    pub(crate) fn cipher_write_key<'k>(
        &self,
        kb: &'k bw_keys::KeyBundle,
        cipher: &Value,
        org_keys: &'k HashMap<Uuid, bw_crypto::OrgKey>,
    ) -> Option<&'k [u8]> {
        match self.cipher_owner_org(cipher) {
            None => Some(kb.user_key().as_bytes()),
            Some(org) => org_keys.get(&org).map(|k| k.as_bytes()),
        }
    }

    /// 明文索引回填（全鏡像，含垃圾桶——官方回收桶列表要顯示解密名稱）。
    fn reindex_all(&self) -> Result<(), WtpError> {
        let mut ids: Vec<ItemId> = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(denied)?
            .into_iter()
            .map(|m| m.id)
            .collect();
        ids.extend(
            self.store
                .query(&Query {
                    limit: u32::MAX,
                    deleted: Some(true),
                    ..Default::default()
                })
                .map_err(denied)?
                .into_iter()
                .map(|m| m.id),
        );
        self.reindex_many(&ids)
    }

    /// 鏡像落盤後的明文索引回填：解密只發生在 `with_keys` 閉包內。
    /// 單欄位解密失敗容忍跳過（漂移防御），不阻塞整批。共享項目改以
    /// org 對稱金鑰解密（金鑰選擇見 [`cipher_field_decryptor`]）。
    pub fn reindex_many(&self, ids: &[ItemId]) -> Result<(), WtpError> {
        let org_keys = self.org_key_map();
        for id in ids {
            let Some(row) = self.store.item(*id).map_err(denied)? else {
                continue;
            };
            let decrypted = self.machine.with_keys(|kb| {
                let dec = cipher_field_decryptor(kb, &row.enc_cipher, &org_keys);
                bw_vault::plain_index(&row.enc_cipher, &dec)
            });
            let idx = match decrypted {
                Ok(v) => v,
                Err(_) => continue,
            };
            let _ = self
                .store
                .set_plain_meta(*id, idx.name.as_deref(), &idx.uris, &idx.field_names);
            let _ = self
                .store
                .set_plain_secrets(*id, idx.username.as_deref(), idx.password.as_deref());
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
        // 共享項目（organizationId 命中已派生 org key）以 org 對稱金鑰解密；
        // 敏感度分級（§2.1）不因 org 放寬——這裡只換鑰，不換視窗。
        let org_keys = self.org_key_map();
        let reveal = view == View::Reveal;
        let dec = self.machine.with_keys(|kb| {
            let d = cipher_field_decryptor(kb, &row.enc_cipher, &org_keys);
            let (username, password, notes, fields) = {
                let login = row.enc_cipher.get("login");
                let username = login
                    .and_then(|l| l.get("username"))
                    .and_then(Value::as_str)
                    .and_then(&d);
                let password = login
                    .and_then(|l| l.get("password"))
                    .and_then(Value::as_str)
                    .and_then(&d);
                let notes = row
                    .enc_cipher
                    .get("notes")
                    .and_then(Value::as_str)
                    .and_then(&d);
                let fields = match row.enc_cipher.get("fields").and_then(Value::as_array) {
                    Some(arr) => arr
                        .iter()
                        .map(|f| {
                            let kind = bw_proto::CipherFieldKind::from_wire(
                                f.get("type").and_then(Value::as_i64).unwrap_or(0),
                            );
                            let value_ok = kind != bw_proto::CipherFieldKind::Hidden || reveal;
                            bw_proto::CipherField {
                                name: f
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .and_then(&d)
                                    .unwrap_or_default(),
                                value: if value_ok {
                                    f.get("value").and_then(Value::as_str).and_then(&d)
                                } else {
                                    None
                                },
                                kind,
                            }
                        })
                        .collect(),
                    None => Vec::new(),
                };
                (username, password, notes, fields)
            };
            // 附件元資料（批次 4a）：鏡像列＋檔名解密走同一個 dec 座標系
            let attachments = self.attachment_projection(id, &d);
            (username, password, notes, fields, attachments)
        });
        let (username, password, notes, fields, attachments) = dec.map_err(denied)?;
        let v = match view {
            View::Masked => ItemView::metadata(base)
                .masked(username, password.as_deref().map(mask_tail), false)
                .with_details(notes, fields, attachments),
            View::Reveal => ItemView::metadata(base)
                .masked(username, None, false)
                .revealed(password)
                .with_details(notes, fields, attachments),
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
        let (username, password) = {
            let org_keys = self.org_key_map();
            self.machine
                .with_keys(|kb| {
                    let d = cipher_field_decryptor(kb, &row.enc_cipher, &org_keys);
                    let dec = |field: &str| {
                        row.enc_cipher
                            .pointer(&format!("/login/{field}"))
                            .and_then(Value::as_str)
                            .and_then(&d)
                    };
                    (
                        Zeroizing::new(dec("username").unwrap_or_default()),
                        Zeroizing::new(dec("password").unwrap_or_default()),
                    )
                })
                // 先過 is_unlocked 後仍失敗＝中途被鎖：語意同 Locked（totp 同款處理）
                .map_err(|_| WtpError::Locked)?
        };
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
        // seed 存在性不需金鑰：先擋「無 seed」，別讓它折進下面的 Locked 映射。
        if row
            .enc_cipher
            .pointer("/login/totp")
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(denied("此項目沒有 TOTP seed"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = {
            let org_keys = self.org_key_map();
            self.machine
                .with_keys(|kb| {
                    let d = cipher_field_decryptor(kb, &row.enc_cipher, &org_keys);
                    row.enc_cipher
                        .pointer("/login/totp")
                        .and_then(Value::as_str)
                        .and_then(d)
                        .ok_or_else(|| "no totp seed".to_string())
                        .and_then(|seed| {
                            bw_crypto::totp_code(seed.trim(), now).map_err(|t| t.to_string())
                        })
                })
                .map_err(|_| WtpError::Locked)?
                .map_err(denied)?
        };
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

/// ListPush 出口的 token 去敏：前 8 字元 + sha256 前 12 碼。
/// 比照 keys_fingerprint 先例（指紋代原值）：清單讀取者能比對「是不是同一台」，
/// 但拿不到完整 token，無法離線冒充裝置收推播。
fn mask_push_token(t: &str) -> String {
    let prefix: String = t.chars().take(8).collect();
    format!("{prefix}…{}", &sha256_hex(t)[..12])
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

pub(crate) fn map_server_err(e: ServerError) -> WtpError {
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
        Call::Auth(AuthCall::ChangePassword { .. }) => "Auth.ChangePassword",
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
        Call::Vault(VaultCall::CreateFolder { .. }) => "Vault.CreateFolder",
        Call::Vault(VaultCall::ListFolders) => "Vault.ListFolders",
        Call::Vault(VaultCall::DeleteFolder { .. }) => "Vault.DeleteFolder",
        Call::Vault(VaultCall::Purge { .. }) => "Vault.Purge",
        Call::Vault(VaultCall::Import { .. }) => "Vault.Import",
        Call::Vault(VaultCall::Attachment {
            sub: bw_proto::AttachmentOp::Upload { .. },
        }) => "Vault.Attachment.Upload",
        Call::Vault(VaultCall::Attachment {
            sub: bw_proto::AttachmentOp::Download { .. },
        }) => "Vault.Attachment.Download",
        Call::Vault(VaultCall::Attachment {
            sub: bw_proto::AttachmentOp::Delete { .. },
        }) => "Vault.Attachment.Delete",
        Call::Passkey(PasskeyCall::GetPasskeys { .. }) => "Passkey.GetPasskeys",
        Call::Passkey(PasskeyCall::RegisterPasskey { .. }) => "Passkey.RegisterPasskey",
        Call::Passkey(PasskeyCall::AssertPasskey { .. }) => "Passkey.AssertPasskey",
        Call::Passkey(PasskeyCall::BeginAssert { .. }) => "Passkey.BeginAssert",
        Call::Passkey(PasskeyCall::FinishAssert { .. }) => "Passkey.FinishAssert",
        Call::Passkey(PasskeyCall::BeginRegister { .. }) => "Passkey.BeginRegister",
        Call::Passkey(PasskeyCall::FinishRegister { .. }) => "Passkey.FinishRegister",
        Call::Push(PushCall::RegisterPush { .. }) => "Push.RegisterPush",
        Call::Push(PushCall::UnregisterPush { .. }) => "Push.UnregisterPush",
        Call::Push(PushCall::ListPush) => "Push.ListPush",
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
        Call::Agent(AgentCall::Deny { .. }) => "Agent.Deny",
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
    let secret_out = match resp {
        Some(Response::Secret(_)) | Some(Response::AttachmentBytes(_)) => true,
        Some(Response::Item(Some(v))) => {
            v.password.is_some()
                || v.notes.is_some()
                || v.fields.iter().any(|f| f.value.is_some())
        }
        _ => false,
    };
    if secret_out {
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
        | Call::Vault(VaultCall::MoveToOrg { .. })
        | Call::Vault(VaultCall::CreateFolder { .. })
        | Call::Vault(VaultCall::ListFolders)
        | Call::Vault(VaultCall::DeleteFolder { .. })
        | Call::Vault(VaultCall::Purge { .. })
        | Call::Vault(VaultCall::Import { .. }) => Identity,
        // 附件內容是 Secret 級出口（Download 明文回程、Upload 明文入程計 bytes）；
        // Delete 只動元資料列，比照 Patch 級
        Call::Vault(VaultCall::Attachment {
            sub: bw_proto::AttachmentOp::Upload { .. } | bw_proto::AttachmentOp::Download { .. },
        }) => Secret,
        Call::Vault(VaultCall::Attachment {
            sub: bw_proto::AttachmentOp::Delete { .. },
        }) => Identity,
        Call::Use(UseCall::TotpCode { .. })
        | Call::Use(UseCall::Run { .. })
        | Call::Use(UseCall::ResolveRef { .. })
        | Call::Use(UseCall::GeneratePassword { .. }) => Secret,
        // 列表只投影 Metadata 級識別欄；Register/Assert 出口由私鑰簽出，比照 Use 級
        Call::Passkey(PasskeyCall::GetPasskeys { .. }) => Identity,
        Call::Passkey(_) => Secret,
        // 推播：清單出口帶去敏 token 與 platform（Identity 級，同 Audit）；
        // 註冊/退註出口為 Ok，token 本體是呼叫端自帶的不透明識別子
        Call::Push(PushCall::ListPush) => Identity,
        Call::Push(_) => Opaque,
        Call::Auth(_) | Call::Admin(_) | Call::Sync(_) | Call::Agent(_) | Call::Fill(_) => Opaque,
    }
}

/// 讀路徑欄位解密器：cipher 帶 `organizationId` 且該 org 的對稱金鑰已派生
/// （`org_key_map`）→ 用 org key；否則使用者金鑰。回傳閉包只在 `with_keys`
/// 閉包內存活（不變量 3）。解密失敗回 None（容忍漂移，同 reindex 舊行為）。
/// 出處：org 項目欄位以 org 對稱金鑰加密（clients 新金鑰模型；
/// `Membership.akey` → `organizations[].key` 的包裝金鑰見 bw-keys `unwrap_org_key`）。
pub(crate) fn cipher_field_decryptor<'k>(
    kb: &'k bw_keys::KeyBundle,
    enc_cipher: &Value,
    org_keys: &'k HashMap<Uuid, bw_crypto::OrgKey>,
) -> impl Fn(&str) -> Option<String> + 'k {
    let user_bytes: &'k [u8] = kb.user_key().as_bytes();
    let org_bytes = enc_cipher
        .get("organizationId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .and_then(|o| org_keys.get(&o))
        .map(|k| k.as_bytes());
    let key: &'k [u8] = org_bytes.unwrap_or(user_bytes);
    move |e: &str| {
        bw_crypto::decrypt_bytes_with_key(key, e)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    }
}

/// org RSA 私鑰解密鏈驗證：user 對稱金鑰解 `encryptedPrivateKey` 得 PKCS#8
/// → 以 org 公開金鑰 RSA-OAEP 包一枚 probe → 私鑰解回原值。全用既有
/// bw-crypto 原語（P4b 契約交付 1 的「至少」門檻）。
fn verify_org_private_key(
    kb: &bw_keys::KeyBundle,
    public_key_b64: &str,
    enc_private_key: &str,
) -> Result<(), bw_crypto::CryptoError> {
    const PROBE: &[u8] = b"bitward:org-key-roundtrip";
    let der = kb.org_rsa_private(enc_private_key)?;
    let wrapped = bw_crypto::rsa_encrypt(public_key_b64, bw_crypto::OaepHash::Sha1, PROBE)?;
    let back = bw_crypto::rsa_decrypt(&der, &wrapped)?;
    if back == PROBE {
        Ok(())
    } else {
        Err(bw_crypto::CryptoError::Rsa)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::SessionKind;

    async fn bare_hub() -> Arc<Hub> {
        let dir = std::env::temp_dir().join(format!("bw-hub-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Hub::open(&dir, None, None).await.unwrap()
    }

    #[test]
    fn mask_push_token_keeps_prefix_and_hash_only() {
        let token = "0123456789ABCDEF0123456789ABCDEF";
        let m = mask_push_token(token);
        assert!(m.starts_with("01234567…"), "前 8 字元保留：{m}");
        assert!(m.ends_with(&sha256_hex(token)[..12]), "尾段為 sha256 前 12 碼：{m}");
        assert!(!m.contains(token), "完整 token 不得外洩進清單出口");
    }

    #[tokio::test]
    async fn change_password_requires_unlock_and_some_passwords() {
        let hub = bare_hub().await;
        let sess = hub.new_session(
            "pw-test".into(),
            SessionKind::Interactive,
            bw_agent::GrantSet::default_full(),
            None,
            json!({"kind": "local"}),
        );
        // 未解鎖（bare hub＝SignedOut）：改密必須被閘下並帶原因（契約 2a）。
        let err = hub
            .dispatch(
                &sess,
                &Call::Auth(AuthCall::ChangePassword {
                    current: Some("old-password-1".into()),
                    new: Some("new-password-123".into()),
                }),
            )
            .await
            .unwrap_err();
        let WtpError::Denied { grant_gap } = err else {
            panic!("未解鎖改密應 Denied，got {err:?}");
        };
        assert!(grant_gap.contains("解鎖"), "原因需指向解鎖態：{grant_gap}");
        // None＝daemon 端向人收（同 Login 語意）：P1 明示未接。
        let err = hub
            .dispatch(
                &sess,
                &Call::Auth(AuthCall::ChangePassword {
                    current: None,
                    new: None,
                }),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WtpError::Denied { grant_gap } if grant_gap.contains("P1")),
            "None 形態應回 P1 拒接，got {err:?}"
        );
    }

    #[tokio::test]
    async fn push_register_list_unregister_converge_through_dispatch() {
        let hub = bare_hub().await;
        let sess = hub.new_session(
            "push-test".into(),
            SessionKind::Interactive,
            bw_agent::GrantSet::default_full(),
            None,
            json!({"kind": "local"}),
        );
        let reg = hub
            .dispatch(
                &sess,
                &Call::Push(PushCall::RegisterPush {
                    token: "AABBCCDDEEFF00112233".into(),
                    platform: "ios".into(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(reg, Response::Ok));
        let resp = hub
            .dispatch(&sess, &Call::Push(PushCall::ListPush))
            .await
            .unwrap();
        let Response::Json(v) = resp else {
            panic!("ListPush 應回 Json，got {resp:?}");
        };
        assert_eq!(v.as_array().map(Vec::len), Some(1));
        assert_eq!(v[0]["platform"], "ios");
        let masked = v[0]["token"].as_str().unwrap();
        assert!(masked.starts_with("AABBCCDD…") && !masked.contains("EEFF00112233"));
        hub.dispatch(
            &sess,
            &Call::Push(PushCall::UnregisterPush {
                token: "AABBCCDDEEFF00112233".into(),
            }),
        )
        .await
        .unwrap();
        let resp = hub
            .dispatch(&sess, &Call::Push(PushCall::ListPush))
            .await
            .unwrap();
        let Response::Json(v) = resp else { panic!("expect Json") };
        assert_eq!(v.as_array().map(Vec::len), Some(0));
    }
}
