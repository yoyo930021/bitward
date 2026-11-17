//! 帳號槽（E5 單 daemon 多 profile）：`Hub` 的 per-account 狀態容器。
//!
//! 一個槽＝一套 `vault.db`／`UnlockMachine`／server handle／`device.id`／事件匯流／
//! drain 佇列／設定鏡／核准佇列／passkey 事務暫存，各自獨立 LockEpoch。共享面
//! （socket、session token 表、一次性配對碼、推播通道、圖示快取、keystore 后端）
//! 留在 `Hub`。槽與槽之間沒有共享可變狀態 ⇒「A 鎖 B 解互不干擾」是結構性質，
//! 不是靠約定不碰彼此。
//!
//! 目錄形態：`<data_dir>/accounts/<profile>/`（遷移前舊單帳號庫在此批首啟搬入
//! `accounts/default/`，使用者無感）。預設槽指標 `<data_dir>/accounts/.default`
//! 是 dotfile，天然不進槽清單——慣例同 CLI hub registry 的 `remotes/.default`。
//! 封存 label 取槽名（`AccountLabel::new(name)`）：Keychain 與 FileKeyStore 因此
//! 逐槽分條目，而遷移後的 `default` 槽沿用既有條目，Touch ID 封存不必重封。

use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;

use bw_keys::{AccountLabel, AuthContext, UnlockMachine};
use bw_proto::{AccountSummary, ApprovalId, EventPayload, Response, WtpError};
use bw_store::Store;

use crate::agent::PendingApproval;
use crate::hub::{AccountRecord, Hub, ServerHandle, kdf_params};

/// 槽根目錄名（`<data_dir>/accounts/`）。
pub(crate) const ACCOUNTS_DIR: &str = "accounts";
/// 既有單帳號庫遷移後的槽名，也是新 daemon 的第一個槽。
pub(crate) const DEFAULT_PROFILE: &str = "default";
/// 預設槽指標檔名（dotfile，見模組頭）。
pub(crate) const DEFAULT_FILE: &str = ".default";
/// 槽名長度上限（欄位值同時是目錄名與 keychain 條目名的一節）。
const MAX_PROFILE_LEN: usize = 40;

/// 槽名校驗：檔名安全字元集＋首字元必須是字母數字（拒 `.default` 指標檔同名、
/// 拒 `-x` 這類會被 argv 解析誤讀的名）＋至少一個字母數字。大寫放行：槽名常由
/// email 前綴派生，強迫小寫會在比對處製造第二套規範化。
pub(crate) fn valid_profile_name(name: &str) -> bool {
    name.len() <= MAX_PROFILE_LEN
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub(crate) fn accounts_root(data_dir: &Path) -> PathBuf {
    data_dir.join(ACCOUNTS_DIR)
}

pub(crate) fn profile_dir(data_dir: &Path, name: &str) -> PathBuf {
    accounts_root(data_dir).join(name)
}

fn default_pointer(data_dir: &Path) -> PathBuf {
    accounts_root(data_dir).join(DEFAULT_FILE)
}

/// 讀預設槽指標；缺檔或內容不是已知槽時退回 `default`。
pub(crate) fn read_default_pointer(data_dir: &Path, known: &[String]) -> String {
    let raw = std::fs::read_to_string(default_pointer(data_dir)).unwrap_or_default();
    let name = raw.trim().to_owned();
    if known.contains(&name) {
        name
    } else {
        DEFAULT_PROFILE.to_owned()
    }
}

/// 盤上已有的槽目錄（合法名、含 vault.db 或 account.json 才算數——空目錄是
/// 上次建立失敗的殘骸，由 `open_profile` 重新收斂）。回排序後的名字。
pub(crate) fn list_profile_dirs(data_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(accounts_root(data_dir))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !valid_profile_name(&name) || !e.path().is_dir() {
                return None;
            }
            let has_state =
                e.path().join("vault.db").exists() || e.path().join("account.json").exists();
            has_state.then_some(name)
        })
        .collect();
    v.sort();
    v
}

/// 舊單帳號佈局（`<data_dir>/{vault.db,account.json,device.id}`）搬入
/// `accounts/default/`。冪等：搬完即無舊檔，崩在中間重跑收斂到同一終態
/// （Make Operations Idempotent）。回 `true` 只在真的搬動過時。
///
/// 只搬 per-account 檔：`keys/`（封存，按 label 分條目）、`icons/`、`remotes/`、
/// `cli_session`、`daemon.sock`、`run/` 是裝置級，留在原地。
pub(crate) fn migrate_legacy_layout(data_dir: &Path) -> bool {
    let target = profile_dir(data_dir, DEFAULT_PROFILE);
    let moved_files = [
        "vault.db",
        "vault.db-wal",
        "vault.db-shm",
        "account.json",
        "device.id",
    ];
    if target.join("vault.db").exists() || !data_dir.join("vault.db").exists() {
        return false;
    }
    if std::fs::create_dir_all(&target).is_err() {
        return false;
    }
    let mut moved = false;
    for name in moved_files {
        let from = data_dir.join(name);
        if !from.exists() {
            continue;
        }
        if std::fs::rename(&from, target.join(name)).is_ok() {
            moved = true;
        }
    }
    moved
}

/// 一個帳號槽。欄位即隔離邊界：本槽的鑰、庫、網路、事件、佇列都從這裡走。
pub struct Profile {
    pub name: String,
    /// 裝置級共享面。槽↔hub 互為強引用（hub 持槽表、槽持此回鏈）：daemon 生命週期
    /// 內名額固定，不回收是刻意的，比 `Weak`＋每處 upgrade 好讀。
    pub hub: Arc<Hub>,
    pub store: Arc<Store>,
    pub machine: UnlockMachine,
    pub server: RwLock<Option<ServerHandle>>,
    pub(crate) account: RwLock<Option<AccountRecord>>,
    /// 穩定裝置 id：notifications is_own_change 與 login deviceIdentifier 同源。
    /// 逐槽一套 ⇒ 同一台機器上兩個帳號在伺服器端是兩台裝置。
    pub device: String,
    /// 本槽 BTP 事件匯流（EventTopic, payload ≤ Identity 級）。連線只收自己槽的事件
    /// ——跨槽的鎖態/鏡像變更對本槽訂閱者是噪音，且會誤導鎖態顯示。
    pub(crate) events: tokio::sync::broadcast::Sender<EventPayload>,
    pub(crate) drain_tx: tokio::sync::mpsc::UnboundedSender<()>,
    pub(crate) drain_rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<()>>>,
    /// drain 單飛：併發觸發只跑一輪實際推送（§3.5 trigger 去重語意）
    pub(crate) drain_lock: tokio::sync::Mutex<()>,
    /// token → 活 session 的治理佇列（§2.3 核准）：逐槽一套，A 的核准請求
    /// 不出現在 B 的佇列裡。
    pub(crate) pending: Mutex<HashMap<ApprovalId, PendingApproval>>,
    /// BeginAssert→FinishAssert 事務暫存（credentialId 屬本槽的 vault）。
    pub(crate) pending_asserts: Mutex<HashMap<String, crate::passkey::PendingAssert>>,
    /// 上次全量 sync 的 unix ms；通知 fire-and-forget，30 秒週期 sync 兜底。
    pub last_sync_ms: std::sync::atomic::AtomicU64,
    /// 本槽設定鏡（真態在本槽庫的 meta 表；政策接線見 settings.rs）。
    pub settings: Mutex<bw_proto::Settings>,
    /// PR4 C2：grantee 緊急檢視快取（ea_id →（LockEpoch，Reveal 投影））。
    pub(crate) ea_view_cache: Mutex<HashMap<String, (u64, Vec<bw_proto::ItemView>)>>,
}

/// 裝置級欄位（socket 共享面）經此取得：槽內程式碼寫 `self.data_dir`、
/// `self.keystore`、`self.ntfy_url` 與 Hub 方法時不必先解引用，讀起來與
/// 單帳號時期一致。
impl Deref for Profile {
    type Target = Hub;

    fn deref(&self) -> &Self::Target {
        &self.hub
    }
}

impl Profile {
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<EventPayload> {
        self.events.subscribe()
    }

    /// 本槽是否已落帳號（改綁閘用，見 `Hub::login`）。
    pub(crate) async fn has_account(&self) -> bool {
        self.account.read().await.is_some()
    }

    /// 槽投影（`AuthCall::AccountList` 回包的一列）。
    pub(crate) async fn summary(&self, is_default: bool) -> AccountSummary {
        let acc = self.account.read().await;
        AccountSummary {
            profile: self.name.clone(),
            email: acc.as_ref().map(|a| a.email.clone()),
            server: acc.as_ref().map(|a| a.server.clone()),
            state: self.machine.state(),
            epoch: self.machine.epoch().0,
            items: self.store.cipher_count().unwrap_or(0),
            is_default,
            has_vault: self.dir().join("vault.db").exists(),
        }
    }

    pub(crate) fn dir(&self) -> PathBuf {
        profile_dir(&self.data_dir, &self.name)
    }

    /// 落盤本槽帳號（`accounts/<profile>/account.json`，0600）。
    pub(crate) async fn persist_account(&self) -> Result<(), WtpError> {
        let acc = self
            .account
            .read()
            .await
            .clone()
            .ok_or(WtpError::NotFound)?;
        let bytes = serde_json::to_vec_pretty(&acc).map_err(crate::hub::denied)?;
        let path = self.dir().join("account.json");
        std::fs::write(&path, bytes).map_err(crate::hub::denied)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// 續期回寫：token 真態在盤上，記憶體 `AccountRecord` 僅供展示，容許短暫落後。
    /// Weak 中樞引用：sink 掛在 client、client 住在槽裡，強引用會成環。
    fn install_token_sink(self: &Arc<Self>, client: &std::sync::Arc<bw_server::Client>) {
        let weak = Arc::downgrade(self);
        client.set_token_sink(std::sync::Arc::new(move |access, refresh| {
            let Some(p) = weak.upgrade() else { return };
            let path = p.dir().join("account.json");
            if let Ok(bytes) = std::fs::read(&path)
                && let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            {
                v["access_token"] = serde_json::json!(access);
                v["refresh_token"] = match refresh {
                    Some(r) => serde_json::json!(r),
                    None => serde_json::Value::Null,
                };
                if std::fs::write(&path, v.to_string()).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    }
                }
            }
            p.machine.note_token_renewed();
        }));
    }

    /// 本槽常駐迴路：drain 即推、背景自動推送、30 秒週期 sync、鎖世代級聯撤銷、
    /// vault timeout 心跳。槽建立時起（含執行期新登入的槽），因此每個槽的節拍與
    /// 自己的鎖態綁，不受別的帳號影響。
    pub(crate) fn spawn_tasks(self: &Arc<Self>) {
        let p = self.clone();
        tokio::spawn(async move {
            let Some(mut rx) = p.drain_rx.lock().await.take() else {
                return;
            };
            while rx.recv().await.is_some() {
                p.drain_until_idle().await;
            }
        });
        let p = self.clone();
        tokio::spawn(async move { p.auto_drain_loop().await });
        let p = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                // 通知是 fire-and-forget：斷線期間的事件永久錯過，30 秒週期 sync 兜底
                if p.machine.is_unlocked()
                    && p.machine.egress_online()
                    && p.store.now_ms() - p.last_sync_ms.load(std::sync::atomic::Ordering::Relaxed)
                        > 30_000
                {
                    let _ = p.sync_now().await;
                }
            }
        });
        let p = self.clone();
        tokio::spawn(async move { p.notify_loop().await });
        let p = self.clone();
        // 訂閱必須在 spawn 前完成：丢進 task 裡訂閱會漏掉「spawn 後、首次 poll 前」
        // 的事件（單測與快速重啟都撞得到）。
        let mut watch = p.machine.watch();
        tokio::spawn(async move {
            while let Ok(ev) = watch.recv().await {
                match &ev {
                    bw_keys::UnlockEvent::Revoked { epoch, .. } => {
                        // 鎖世代推進 ⇒ 本槽綁舊 epoch 的 session 全滅（§2.2、A6）；
                        // 別的槽的 session 與別的 epoch 無關，一律不動。
                        let _ = p.store.sessions_revoke_before(epoch.0);
                        // D1：任何路徑的鎖定（含閒置 timeout、with_keys 惰性
                        // 鎖）都截斷 WAL，治「舊頁留殘值」。
                        let _ = p.store.checkpoint_wal_truncate();
                        for s in p.hub.sessions.lock().unwrap().values_mut() {
                            let sp = s.profile.read().unwrap().clone();
                            if sp.name == p.name && s.row.epoch < epoch.0 {
                                s.revoked.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    // 鎖態轉換廣播（FR 1635 thin 共享解鎖態）：只發本槽匯流——
                    // 自動鎖定不是使用者按出來的，沒有這條事件界面會停在過期鎖態。
                    bw_keys::UnlockEvent::State { view, epoch } => {
                        p.emit(EventPayload::LockState {
                            state: view.clone(),
                            epoch: epoch.0,
                        });
                    }
                    _ => {}
                }
            }
        });
        let p = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if p.machine.check_timeout() {
                    let _ = p.store.sessions_revoke_before(p.machine.epoch().0);
                }
            }
        });
    }
}

impl Hub {
    pub(crate) fn profile(&self, name: &str) -> Option<Arc<Profile>> {
        self.profiles.lock().unwrap().get(name).cloned()
    }

    pub(crate) fn profiles(&self) -> Vec<Arc<Profile>> {
        let g = self.profiles.lock().unwrap();
        let mut v: Vec<Arc<Profile>> = g.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub(crate) fn default_profile_name(&self) -> String {
        self.default_profile.lock().unwrap().clone()
    }

    /// 設預設槽：寫指標檔＋更新記憶體鏡（不碰任何 vault）。
    pub(crate) fn set_default_profile(&self, name: &str) -> Result<(), WtpError> {
        if !valid_profile_name(name) {
            return Err(crate::hub::denied(format!("非法帳號槽名：{name:?}")));
        }
        if self.profile(name).is_none() {
            return Err(WtpError::NotFound);
        }
        let path = default_pointer(&self.data_dir);
        std::fs::write(&path, format!("{name}\n")).map_err(crate::hub::denied)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        *self.default_profile.lock().unwrap() = name.to_owned();
        Ok(())
    }

    /// 取槽；不存在的合法名字＝就地開新槽（空庫、signed-out，等第一次登入落帳號）。
    /// None＝呼叫端沒表態，用預設槽。
    pub(crate) async fn resolve_profile(
        self: &Arc<Self>,
        requested: Option<&str>,
    ) -> Result<Arc<Profile>, WtpError> {
        let name = match requested {
            Some(n) if !n.is_empty() => n.to_owned(),
            _ => self.default_profile_name(),
        };
        if !valid_profile_name(&name) {
            return Err(crate::hub::denied(format!(
                "非法帳號槽名：{name:?}（限字母數字與 -_. ，不得以 . 起頭）"
            )));
        }
        if let Some(p) = self.profile(&name) {
            return Ok(p);
        }
        let p = self.open_profile(&name).await.map_err(crate::hub::denied)?;
        self.profiles
            .lock()
            .unwrap()
            .insert(name.clone(), p.clone());
        tracing::info!(profile = %name, "新增帳號槽");
        Ok(p)
    }

    /// 開一個槽：建目錄、開庫、按槽名建封存 label 的狀態機、載入帳號、起常駐迴路。
    pub(crate) async fn open_profile(self: &Arc<Self>, name: &str) -> Result<Arc<Profile>, String> {
        let dir = profile_dir(&self.data_dir, name);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let store = Arc::new(Store::open(&dir.join("vault.db")).map_err(|e| e.to_string())?);
        let account: Option<AccountRecord> = Hub::read_json(&dir.join("account.json"));
        let label = AccountLabel::new(name);
        // D2（稽核 2026-11-16）strict 封存閘：逐槽判定——自動解鎖是各槽 meta 表裡
        // 的設定，A 開 auto-unlock 不會把 B 的封存檔一起放行。
        let initial_settings = Profile::read_settings(&store);
        let sealing = self.keystore.wrap_strength() == bw_keys::WrapStrength::BiometricBound
            || !initial_settings.lock_on_sleep_restart;
        if !sealing {
            let _ = self.keystore.clear(&label);
        }
        let builder = UnlockMachine::builder()
            .label(label)
            .kernel(Arc::new(bw_keys::BwCryptoKernel))
            .keystore(self.keystore.clone())
            .sealing(sealing);
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
        let p = Arc::new(Profile {
            name: name.to_owned(),
            hub: self.clone(),
            store: store.clone(),
            machine,
            server: RwLock::new(None),
            account: RwLock::new(account.clone()),
            device: Hub::device_id_static(&dir),
            events: tokio::sync::broadcast::channel(128).0,
            drain_tx,
            drain_rx: tokio::sync::Mutex::new(Some(drain_rx)),
            drain_lock: tokio::sync::Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
            pending_asserts: Mutex::new(HashMap::new()),
            last_sync_ms: std::sync::atomic::AtomicU64::new(0),
            settings: Mutex::new(initial_settings),
            ea_view_cache: Mutex::new(HashMap::new()),
        });
        if let Some(a) = &account {
            let client = std::sync::Arc::new(
                bw_server::Client::with_options(&a.server, Profile::sync_options())
                    .map_err(|e| e.to_string())?,
            );
            if let Some(t) = a.access_token.clone() {
                client.set_access_token(&t).await;
            }
            // 4c：重啟還原也要帶續期憑證，否則 401 收口只能拋錯
            client.set_refresh_token(a.refresh_token.as_deref()).await;
            p.install_token_sink(&client);
            p.server.write().await.replace(ServerHandle { client });
        }
        // 重啟不踢已配對裝置：從本槽的持久層重建活 session（§2.3，token 即 id）
        for row in p.store.session_list().unwrap_or_default() {
            if row.state != bw_store::SessionState::Active {
                continue;
            }
            let kind = match row
                .principal
                .get("kind")
                .and_then(serde_json::Value::as_str)
            {
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
            p.restore_session(row, kind, grants);
        }
        // 自動鎖定政策接線（settings.rs）：解鎖時的 idle deadline 由本槽設定決定。
        p.apply_timeout_policy();
        p.spawn_tasks();
        Ok(p)
    }

    /// `AuthCall::AccountList`：全槽投影（預設槽帶標記）。
    pub(crate) async fn account_list(&self) -> Response {
        let default = self.default_profile_name();
        let mut rows: Vec<AccountSummary> = Vec::new();
        for p in self.profiles() {
            rows.push(p.summary(p.name == default).await);
        }
        sort_accounts_first(&mut rows);
        Response::Accounts(rows)
    }
}

/// 槽清單的決定性排序（純函數測點）：預設槽恆列首，其餘按名。
pub(crate) fn sort_accounts_first(rows: &mut [AccountSummary]) {
    rows.sort_by(|a, b| (b.is_default, &a.profile).cmp(&(a.is_default, &b.profile)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_crypto::MIN_PBKDF2_ITERATIONS;
    use bw_keys::LockReason;
    use bw_proto::{AuthCall, Call, UnlockStateView};
    use serde_json::json;
    use uuid::Uuid;

    /// 合成一個帳號槽的 `account.json`（PBKDF2 iter=1、自訂 user key 位元組）。
    fn seed_slot(data_dir: &Path, name: &str, email: &str, pw: &str, user_key: u8) -> String {
        let mk = bw_crypto::master_key(
            pw,
            email,
            bw_crypto::KdfParams::Pbkdf2 {
                iterations: MIN_PBKDF2_ITERATIONS,
            },
        )
        .unwrap();
        let uk = bw_crypto::UserKey::from_bytes(vec![user_key; 64]).unwrap();
        let puk = bw_crypto::encrypt_user_key(&mk, &uk).unwrap().to_string();
        let dir = profile_dir(data_dir, name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("account.json"),
            json!({
                "server": "http://127.0.0.1:9",
                "email": email,
                "access_token": null, "refresh_token": null,
                "kdf": 0, "kdf_iterations": MIN_PBKDF2_ITERATIONS as u64,
                "kdf_memory": null, "kdf_parallelism": null,
                "protected_user_key": puk, "keys_fingerprint": null,
            })
            .to_string(),
        )
        .unwrap();
        pw.to_owned()
    }

    async fn open_hub(tag: &str) -> (Arc<Hub>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("bw-e5-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hub = Hub::open(&dir, None, None).await.unwrap();
        (hub, dir)
    }

    fn unlock(p: &Profile, pw: &str) {
        use bw_keys::{UnlockMaterial, UnlockReceipt};
        use zeroize::Zeroizing;
        let boxed = Zeroizing::new(pw.to_owned());
        assert!(matches!(
            p.machine.submit(UnlockMaterial::MasterPassword(boxed)),
            Ok(UnlockReceipt::Unlocked { .. }) | Ok(UnlockReceipt::AlreadyUnlocked { .. })
        ));
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    #[test]
    fn profile_name_table() {
        for ok in ["default", "work", "a.b-c_1", "Work"] {
            assert!(valid_profile_name(ok), "{ok} 應合法");
        }
        for bad in ["", ".", "..", ".default", "-x", "a/b", "a\\b", "a b"] {
            assert!(!valid_profile_name(bad), "{bad:?} 應非法");
        }
        let too_long = "x".repeat(MAX_PROFILE_LEN + 1);
        assert!(!valid_profile_name(&too_long), "超長名應非法");
    }

    #[tokio::test]
    async fn legacy_single_account_layout_migrates_into_default_slot() {
        let dir = std::env::temp_dir().join(format!("bw-e5-mig-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // 舊形態：vault.db／account.json／device.id 直接躺在 data_dir 根
        let pw = "test-master-pw";
        let email = "legacy@bitward.test";
        let mk = bw_crypto::master_key(
            pw,
            email,
            bw_crypto::KdfParams::Pbkdf2 {
                iterations: MIN_PBKDF2_ITERATIONS,
            },
        )
        .unwrap();
        let uk = bw_crypto::UserKey::from_bytes(vec![9u8; 64]).unwrap();
        std::fs::write(
            dir.join("account.json"),
            json!({
                "server": "http://127.0.0.1:9", "email": email,
                "access_token": null, "refresh_token": null,
                "kdf": 0, "kdf_iterations": MIN_PBKDF2_ITERATIONS as u64,
                "kdf_memory": null, "kdf_parallelism": null,
                "protected_user_key": bw_crypto::encrypt_user_key(&mk, &uk).unwrap().to_string(),
                "keys_fingerprint": null,
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(dir.join("device.id"), "legacy-device").unwrap();
        let device_file = dir.join("device.id");
        let legacy_db = dir.join("vault.db");
        {
            let s = Store::open(&legacy_db).unwrap();
            s.apply_sync(
                &json!({"ciphers": [{"id": Uuid::new_v4().to_string(), "type": 1,
                "revisionDate": "2026-11-17T00:00:00.000Z", "name": "x"}]}),
            )
            .unwrap();
        }
        let legacy_items_dir = legacy_db.clone();

        let hub = Hub::open(&dir, None, None).await.unwrap();
        let p = hub.profile(DEFAULT_PROFILE).expect("遷移後必有 default 槽");
        assert_eq!(
            p.account.read().await.as_ref().map(|a| a.email.as_str()),
            Some(email),
            "舊帳號必須落進 default 槽"
        );
        assert_eq!(p.device, "legacy-device", "device.id 同槽搬移");
        assert_eq!(p.store.cipher_count().unwrap(), 1, "鏡像庫內容不動");
        assert!(!dir.join("account.json").exists(), "舊路徑必須清空");
        assert!(
            !device_file.exists(),
            "舊 device.id 不得留下（否则下次開庫又搬一次）"
        );
        assert!(!legacy_items_dir.exists(), "舊 vault.db 不得留下");
        assert!(
            !dir.join("keys").exists() || dir.join("keys").is_dir(),
            "keys/ 是裝置級，原地保留"
        );

        // 冪等：重開一次不得再動任何东西（崩在中間收斂到同一終態）
        drop(hub);
        let hub2 = Hub::open(&dir, None, None).await.unwrap();
        let p2 = hub2.profile(DEFAULT_PROFILE).unwrap();
        assert_eq!(p2.store.cipher_count().unwrap(), 1);
        assert_eq!(
            p2.account.read().await.as_ref().map(|a| a.email.as_str()),
            Some(email)
        );
        assert!(
            profile_dir(&dir, DEFAULT_PROFILE)
                .join("account.json")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn two_slots_isolate_lock_state_epochs_and_stores() {
        let (hub, dir) = open_hub("isolate").await;
        let pw_a = seed_slot(&dir, DEFAULT_PROFILE, "a@bitward.test", "pw-a-12345678", 11);
        let pw_b = seed_slot(&dir, "work", "b@bitward.test", "pw-b-12345678", 22);
        // 槽是開庫時掃出來的：重開一次讓兩個槽都進表
        drop(hub);
        let (hub, dir) = {
            let h = Hub::open(&dir, None, None).await.unwrap();
            (h, dir)
        };
        let a = hub.profile(DEFAULT_PROFILE).unwrap();
        let b = hub.profile("work").unwrap();
        unlock(&a, &pw_a);
        unlock(&b, &pw_b);
        let sess_a = a.new_session(
            "sa".into(),
            crate::agent::SessionKind::Interactive,
            bw_agent::GrantSet::default_full(),
            None,
            json!({"kind": "local"}),
        );
        let sess_b = b.new_session(
            "sb".into(),
            crate::agent::SessionKind::Interactive,
            bw_agent::GrantSet::default_full(),
            None,
            json!({"kind": "local"}),
        );

        // 兩庫互不污染：A 的 sync 內容不進 B
        a.store
            .apply_sync(
                &json!({"ciphers": [{"id": Uuid::new_v4().to_string(), "type": 1,
                "revisionDate": "2026-11-17T00:00:00.000Z", "name": "n"}]}),
            )
            .unwrap();
        assert_eq!(a.store.cipher_count().unwrap(), 1);
        assert_eq!(b.store.cipher_count().unwrap(), 0, "B 的鏡像庫必須乾净");

        // A 鎖 B 解：鎖態與世代各自獨立
        let epoch_a_before = a.machine.epoch().0;
        let epoch_b_before = b.machine.epoch().0;
        a.machine.lock(LockReason::User);
        assert!(!a.machine.is_unlocked(), "A 鎖上");
        assert!(b.machine.is_unlocked(), "B 不受影響");
        assert_eq!(b.machine.epoch().0, epoch_b_before, "B 的世代不動");
        assert!(a.machine.epoch().0 > epoch_a_before, "A 的世代推進");

        // 級聯撤銷只殺本槽 session（常駐 watch task 非同步收斂）
        let revoked_a = {
            let (s, h) = (sess_a.clone(), sess_b.clone());
            wait_until(move || {
                s.revoked.load(std::sync::atomic::Ordering::Relaxed)
                    && !h.revoked.load(std::sync::atomic::Ordering::Relaxed)
            })
            .await
        };
        assert!(
            revoked_a,
            "A 的 session 随 A 的世代撤銷、B 的存活（a={} b={} row_a={} row_b={} epoch_a={}）",
            sess_a.revoked.load(std::sync::atomic::Ordering::Relaxed),
            sess_b.revoked.load(std::sync::atomic::Ordering::Relaxed),
            sess_a.row.epoch,
            sess_b.row.epoch,
            a.machine.epoch().0
        );
        assert!(
            b.store.session_list().unwrap().iter().all(|r| r.id != "sa"),
            "session 表逐槽落庫：sa 不得出現在 B 的庫"
        );

        // 事件匯流隔離：B 的訂閱者收不到 A 的鎖態
        let mut rx_b = b.subscribe();
        a.emit(EventPayload::LockState {
            state: UnlockStateView::SignedOut,
            epoch: 999,
        });
        assert!(rx_b.try_recv().is_err(), "A 的事件不得漏進 B 的訂閱佇列");

        // 自動鎖定政策 per-profile：A 改設定不動 B
        let want = bw_proto::Settings {
            auto_lock_minutes: 1,
            ..Default::default()
        };
        a.store_settings(want).unwrap();
        assert_eq!(a.current_settings().auto_lock_minutes, 1);
        assert_eq!(
            b.current_settings().auto_lock_minutes,
            bw_proto::Settings::default().auto_lock_minutes,
            "B 的設定鏡不受 A 影響（真態在各自的 meta 表）"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn account_use_moves_default_pointer_and_resolves_slots() {
        let (hub, dir) = open_hub("use").await;
        // 不帶 profile 的連線落在 default；指定名字就地開新槽
        let d1 = hub.resolve_profile(None).await.unwrap();
        assert_eq!(d1.name, DEFAULT_PROFILE);
        let work = hub.resolve_profile(Some("work")).await.unwrap();
        assert_eq!(work.name, "work");
        assert!(
            profile_dir(&dir, "work").join("vault.db").exists(),
            "新槽就地開庫"
        );
        assert_eq!(
            hub.resolve_profile(Some("work")).await.unwrap().name,
            "work",
            "同槽複用"
        );

        // 設預設：不帶 profile 的新連線改綁 work，既有 default 槽不動
        hub.set_default_profile("work").unwrap();
        assert_eq!(hub.default_profile_name(), "work");
        assert_eq!(hub.resolve_profile(None).await.unwrap().name, "work");
        assert_eq!(read_default_pointer(&dir, &["work".to_owned()]), "work");

        // 非法名與未知槽都拒（不得拿 ../../etc 開槽）
        assert!(hub.set_default_profile("nope").is_err());
        assert!(matches!(
            hub.resolve_profile(Some("../escape")).await,
            Err(WtpError::Denied { .. })
        ));

        // AccountList 投影：default-first、is_default 標記、空槽 email None
        let Response::Accounts(rows) = hub.account_list().await else {
            panic!("AccountList 必回 Accounts")
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].profile, "work");
        assert!(rows[0].is_default && !rows[1].is_default);
        assert_eq!(rows[1].profile, DEFAULT_PROFILE);
        assert_eq!(rows[0].email, None, "未落帳號的槽 email 缺席");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pairing_codes_are_scoped_to_the_issuing_slot() {
        let (hub, dir) = open_hub("pair").await;
        let a = hub.resolve_profile(Some("personal")).await.unwrap();
        let b = hub.resolve_profile(Some("work")).await.unwrap();
        let Response::PairInfo(info) = a.pair_start("laptop", "see:identity all", 3600).unwrap()
        else {
            panic!("pair_start 必回 PairInfo")
        };
        // A 看得到、B 看不到，也撤不掉
        let Response::Pairings(mine) = a.pair_list() else {
            panic!("pair_list 必回 Pairings")
        };
        assert_eq!(mine.len(), 1);
        let Response::Pairings(theirs) = b.pair_list() else {
            panic!("pair_list 必回 Pairings")
        };
        assert!(theirs.is_empty(), "B 的清單不得出現 A 的碼");
        assert!(matches!(
            b.pair_revoke_code(&info.code),
            Err(WtpError::NotFound)
        ));
        // 消耗後落回簽發槽：預設指標被別人改過也不跑錯帳號
        hub.set_default_profile("work").unwrap();
        let spec = hub.consume_pairing(&info.code).expect("碼可消耗");
        assert_eq!(spec.profile, "personal");
        let p = hub.resolve_profile(Some(&spec.profile)).await.unwrap();
        assert_eq!(p.name, "personal", "配對 session 落回簽發槽");
        assert!(matches!(
            a.pair_revoke_code(&info.code),
            Err(WtpError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn login_with_other_profile_never_overwrites_a_used_slot() {
        let (hub, dir) = open_hub("rebind").await;
        let pw = seed_slot(&dir, DEFAULT_PROFILE, "a@bitward.test", "pw-a-12345678", 33);
        drop(hub);
        let hub = Hub::open(&dir, None, None).await.unwrap();
        let a = hub.profile(DEFAULT_PROFILE).unwrap();
        unlock(&a, &pw);
        let sess = a.new_session(
            "s".into(),
            crate::agent::SessionKind::Interactive,
            bw_agent::GrantSet::default_full(),
            None,
            json!({"kind": "local"}),
        );
        // 已落帳號的連線指定別的槽：拒，且不動原槽帳號
        let err = a
            .dispatch(
                &sess,
                &Call::Auth(AuthCall::Login {
                    server: "http://127.0.0.1:9".into(),
                    email: "b@bitward.test".into(),
                    password: Some("x".into()),
                    api_key: None,
                    two_factor: None,
                    profile: Some("work".into()),
                }),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("已綁定帳號槽"),
            "改綁閘必須給可懂原因：{err}"
        );
        assert_eq!(
            sess.profile_arc().name,
            DEFAULT_PROFILE,
            "拒改綁後連線仍綁原槽"
        );
        assert!(
            hub.profile("work").is_none(),
            "拒改綁不得順手把槽建出來（網路都沒打出去）"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
