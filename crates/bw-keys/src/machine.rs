//! 解鎖狀態機（契約 §2.2）。金鑰只活在 `with_keys` 閉包內；任何轉換都
//! 經 `watch()` 廣播，讓本裝置的 thin client 同時看到 FR 1635 的共享解鎖態。
//!
//! 轉移表逐條（對照 ARCHITECTURE §2.2）：
//! - `submit(material)`：AuthLocked/Stale/SignedOut → Unlocking → Unlocked，`epoch++`；
//!   已解鎖時冪等（重複 unlock 不 bump epoch、不互毀 session，治 clients#6898）。
//! - `lock(reason)` / timeout：→ AuthLocked，`epoch++`，廣播 `Revoked`（級聯撤銷
//!   全部 agent session、lease、identity store，治 #22773、實作 FR 1635）。
//! - `set_egress(false)`：**狀態不變**，僅廣播 `Egress`（離線不降為鎖定）。
//! - `note_token_rejected()`：Unlocked 降級保留金鑰、要求重認證，不鎖（治 #12270）。
//! - `note_key_drift()`：Keys 指紋變動 → Stale，拒用舊鑰。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use bw_proto::UnlockStateView;
use tokio::sync::broadcast;

use crate::clock::Clock;
use crate::kernel::{AuthContext, UnlockKernel};
use crate::keystore::{AccountLabel, KeyStore};
use crate::{KeyBundle, KeyError, LockEpoch, LockReason, UnlockMaterial};

/// vault timeout 政策（§2.2 `Unlocked { deadline }`）。idle 由 `record_activity`
/// 重置；hard 為絕對上線，不受活動影響。
#[derive(Clone, Copy, Debug, Default)]
pub struct TimeoutPolicy {
    pub idle: Option<Duration>,
    pub hard: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeKind {
    AuthRequest { request_id: String },
    Biometric,
}

/// 進行中的解鎖挑戰（`Unlocking` 態的載體；login-with-device / TDE 用）。
#[derive(Clone, Debug, PartialEq)]
pub struct UnlockChallenge {
    pub kind: ChallengeKind,
    pub nonce: [u8; 32],
    pub deadline_ms: u64,
}

pub type ChallengeId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDrift {
    /// 他台改主密碼 → 伺服器 `profile.keys` 指紋變動。
    Fingerprint {
        was: String,
        now: String,
    },
    /// 金鑰被輪替但無新指紋可比對。
    Rotated,
    Other(String),
}

impl KeyDrift {
    pub fn reason(&self) -> String {
        match self {
            KeyDrift::Fingerprint { was, now } => {
                format!("server keys fingerprint changed {was} -> {now}")
            }
            KeyDrift::Rotated => "keys rotated".to_string(),
            KeyDrift::Other(s) => s.clone(),
        }
    }
}

enum VaultState {
    SignedOut,
    AuthLocked {
        has_mirror: bool,
    },
    Unlocking {
        challenge: UnlockChallenge,
    },
    Unlocked {
        keys: KeyBundle,
        idle_deadline_ms: Option<u64>,
        hard_deadline_ms: Option<u64>,
    },
    Stale {
        why: KeyDrift,
    },
}

/// 一次 `submit` 的結果。
#[derive(Clone, Debug, PartialEq)]
pub enum UnlockReceipt {
    Unlocked {
        epoch: LockEpoch,
    },
    /// 冪等：呼叫時已解鎖，回傳既有 epoch，不 bump、不撤銷（治 #6898）。
    AlreadyUnlocked {
        epoch: LockEpoch,
    },
    /// 非同步材料（AuthRequest）：進入 Unlocking，待 `complete_unlock`。
    Pending {
        challenge: UnlockChallenge,
    },
}

/// 訂閱 `watch()` 的廣播。任何鎖態轉換、淨變、降級都发一條。
#[derive(Clone, Debug, PartialEq)]
pub enum UnlockEvent {
    State {
        view: UnlockStateView,
        epoch: LockEpoch,
    },
    Egress {
        online: bool,
    },
    /// 級聯撤銷訊號：收到即代表 `epoch` 世代作廢，所有 session/lease 須失效。
    Revoked {
        epoch: LockEpoch,
        reason: LockReason,
    },
    NeedsReauth,
}

pub struct UnlockMachine {
    state: Mutex<VaultState>,
    epoch: AtomicU64,
    has_mirror: AtomicBool,
    egress: AtomicBool,
    needs_reauth: AtomicBool,
    mirror_items: AtomicU64,
    clock: std::sync::Arc<dyn Clock>,
    kernel: std::sync::Arc<dyn UnlockKernel>,
    keystore: Option<std::sync::Arc<dyn KeyStore>>,
    label: AccountLabel,
    auth_context: Mutex<Option<AuthContext>>,
    policy: Mutex<TimeoutPolicy>,
    tx: OnceLock<broadcast::Sender<UnlockEvent>>,
}

impl Default for UnlockMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl UnlockMachine {
    /// 預設：無 keystore、無內核（`submit` 需另注入）、初始 SignedOut。
    pub fn new() -> Self {
        Self::builder().signed_out(true).build()
    }

    pub fn builder() -> UnlockMachineBuilder {
        UnlockMachineBuilder::default()
    }

    fn sender(&self) -> &broadcast::Sender<UnlockEvent> {
        self.tx.get_or_init(|| broadcast::channel(EVENT_CAP).0)
    }

    /// 訂閱鎖態流。回傳的 Receiver 從訂閱後的下一條事件開始收。
    pub fn watch(&self) -> broadcast::Receiver<UnlockEvent> {
        self.sender().subscribe()
    }

    fn broadcast(&self, ev: UnlockEvent) {
        // 無訂閱者時 send 回 Err，忽略即可（daemon 可能尚無 thin client）。
        let _ = self.sender().send(ev);
    }

    fn next_epoch(&self) -> LockEpoch {
        LockEpoch(self.epoch.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn view_of(&self, st: &VaultState) -> UnlockStateView {
        match st {
            VaultState::SignedOut => UnlockStateView::SignedOut,
            VaultState::AuthLocked { .. } => UnlockStateView::AuthLocked {
                items: self.mirror_items.load(Ordering::Relaxed) as u32,
            },
            VaultState::Unlocking { .. } => UnlockStateView::Unlocking,
            VaultState::Unlocked {
                idle_deadline_ms,
                hard_deadline_ms,
                ..
            } => {
                let deadline = match (idle_deadline_ms, hard_deadline_ms) {
                    (Some(i), Some(h)) => Some(*i.min(h)),
                    (Some(i), None) => Some(*i),
                    (None, Some(h)) => Some(*h),
                    (None, None) => None,
                };
                UnlockStateView::Unlocked {
                    epoch: self.epoch().0,
                    deadline_epoch_ms: deadline,
                }
            }
            VaultState::Stale { why } => UnlockStateView::Stale { why: why.reason() },
        }
    }

    fn publish(&self, st: &VaultState) {
        self.broadcast(UnlockEvent::State {
            view: self.view_of(st),
            epoch: self.epoch(),
        });
    }

    pub fn state(&self) -> UnlockStateView {
        let st = self.state.lock().unwrap();
        self.view_of(&st)
    }

    pub fn epoch(&self) -> LockEpoch {
        LockEpoch(self.epoch.load(Ordering::SeqCst))
    }

    /// 檢查 session 綁定的 epoch 是否仍有效；不符 ⇒ StaleEpoch（不變量 6）。
    pub fn check_epoch(&self, seen: LockEpoch) -> Result<(), KeyError> {
        let now = self.epoch();
        if seen == now {
            Ok(())
        } else {
            Err(KeyError::StaleEpoch {
                seen: seen.0,
                now: now.0,
            })
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(&*self.state.lock().unwrap(), VaultState::Unlocked { .. })
    }

    /// AuthLocked 態下是否仍有本地鏡像（決定離線唯讀體驗，§2.2）。
    pub fn has_mirror(&self) -> bool {
        matches!(
            &*self.state.lock().unwrap(),
            VaultState::AuthLocked { has_mirror: true }
        )
    }

    pub fn needs_reauth(&self) -> bool {
        self.needs_reauth.load(Ordering::SeqCst)
    }

    pub fn egress_online(&self) -> bool {
        self.egress.load(Ordering::SeqCst)
    }

    /// 登入取得 KDF/Protected Key 後設定；之後 MasterPassword 解鎖才有意義。
    /// SignedOut → AuthLocked（有鏡像材料可解鎖）並廣播。
    pub fn set_auth_context(&self, ctx: AuthContext) {
        *self.auth_context.lock().unwrap() = Some(ctx);
        let mut st = self.state.lock().unwrap();
        if matches!(*st, VaultState::SignedOut) {
            *st = VaultState::AuthLocked {
                has_mirror: self.has_mirror.load(Ordering::SeqCst),
            };
            self.publish(&st);
        }
    }

    /// sync 完成後更新鏡像狀態（AuthLocked 顯示 items、決定 has_mirror）。
    pub fn set_mirror(&self, items: u32) {
        self.mirror_items.store(items as u64, Ordering::SeqCst);
        self.has_mirror.store(items > 0, Ordering::SeqCst);
        let mut st = self.state.lock().unwrap();
        if matches!(*st, VaultState::SignedOut) {
            *st = VaultState::AuthLocked {
                has_mirror: items > 0,
            };
            self.publish(&st);
        }
    }

    pub fn set_policy(&self, p: TimeoutPolicy) {
        *self.policy.lock().unwrap() = p;
        // 若已解鎖，立刻依新政策重算 idle/hard 上限（hard 不向後延）。
        let now = self.clock.unix_ms();
        let mut st = self.state.lock().unwrap();
        if let VaultState::Unlocked {
            idle_deadline_ms,
            hard_deadline_ms,
            ..
        } = &mut *st
        {
            *idle_deadline_ms = p.idle.map(|d| now + d.as_millis() as u64);
            *hard_deadline_ms = p.hard.map(|d| now + d.as_millis() as u64);
        }
    }

    /// 主解鎖入口。冪等（見模組級註解）：已解鎖時仍驗證材料（重認證路徑），
    /// 通過則回 `AlreadyUnlocked`（不 bump epoch、不撤銷，治 #6898）。
    pub fn submit(&self, material: UnlockMaterial) -> Result<UnlockReceipt, KeyError> {
        let mut st = self.state.lock().unwrap();
        if matches!(*st, VaultState::SignedOut) {
            return Err(KeyError::NotAuthenticated);
        }
        if matches!(material, UnlockMaterial::AuthRequest) {
            return match &*st {
                VaultState::Unlocked { .. } => Ok(UnlockReceipt::AlreadyUnlocked {
                    epoch: self.epoch(),
                }),
                VaultState::Unlocking { challenge } => Ok(UnlockReceipt::Pending {
                    challenge: challenge.clone(),
                }),
                _ => {
                    let challenge = UnlockChallenge {
                        kind: ChallengeKind::AuthRequest {
                            request_id: uuid_request_id(),
                        },
                        nonce: [0u8; 32],
                        deadline_ms: self.clock.unix_ms() + DEFAULT_CHALLENGE_TTL_MS,
                    };
                    *st = VaultState::Unlocking {
                        challenge: challenge.clone(),
                    };
                    self.publish(&st);
                    Ok(UnlockReceipt::Pending { challenge })
                }
            };
        }
        let bundle = match &material {
            UnlockMaterial::MasterPassword(pw) => {
                let ctx = self
                    .auth_context
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or(KeyError::NotAuthenticated)?;
                self.kernel.unlock_password(pw, &ctx)?
            }
            UnlockMaterial::DeviceAssertion => {
                self.assertion_bundle().ok_or(KeyError::NotAuthenticated)?
            }
            UnlockMaterial::AuthRequest => unreachable!("handled above"),
        };
        if matches!(*st, VaultState::Unlocked { .. }) {
            self.needs_reauth.store(false, Ordering::SeqCst);
            return Ok(UnlockReceipt::AlreadyUnlocked {
                epoch: self.epoch(),
            });
        }
        Ok(self.finish_unlock(&mut st, bundle))
    }

    /// 非同步挑戰完成（AuthRequest 拿到答案後）。
    pub fn complete_unlock(&self, bundle: KeyBundle) -> UnlockReceipt {
        let mut st = self.state.lock().unwrap();
        self.finish_unlock(&mut st, bundle)
    }

    fn finish_unlock(&self, st: &mut VaultState, bundle: KeyBundle) -> UnlockReceipt {
        let now = self.clock.unix_ms();
        let policy = *self.policy.lock().unwrap();
        let idle_deadline_ms = policy.idle.map(|d| now + d.as_millis() as u64);
        let hard_deadline_ms = policy.hard.map(|d| now + d.as_millis() as u64);
        *st = VaultState::Unlocked {
            keys: bundle,
            idle_deadline_ms,
            hard_deadline_ms,
        };
        // enrollment：成功解鎖後把金鑰封存給離線解鎖用（若有 keystore）。
        if let (Some(ks), VaultState::Unlocked { keys, .. }) = (&self.keystore, &*st) {
            let sealed = crate::keystore::SealedKey::from_bundle(keys);
            let _ = ks.store_wrapped(&self.label, &sealed);
        }
        let epoch = self.next_epoch();
        self.needs_reauth.store(false, Ordering::SeqCst);
        self.publish(st);
        UnlockReceipt::Unlocked { epoch }
    }

    fn assertion_bundle(&self) -> Option<KeyBundle> {
        let ks = self.keystore.as_ref()?;
        let sealed = ks.load_wrapped(&self.label).ok()??;
        self.kernel.unlock_assertion(&sealed).ok()
    }

    /// 使用者/伺服器主動上鎖。回傳新 epoch；廣播 `Revoked` 觸發級聯撤銷。
    pub fn lock(&self, reason: LockReason) -> LockEpoch {
        let mut st = self.state.lock().unwrap();
        let new = self.next_epoch();
        *st = VaultState::AuthLocked {
            has_mirror: self.has_mirror.load(Ordering::SeqCst),
        };
        self.needs_reauth.store(false, Ordering::SeqCst);
        self.broadcast(UnlockEvent::Revoked { epoch: new, reason });
        self.publish(&st);
        new
    }

    /// 登出：清空封存與認證情境，回 SignedOut，epoch++（撤銷一切）。
    pub fn sign_out(&self) -> LockEpoch {
        let mut st = self.state.lock().unwrap();
        let new = self.next_epoch();
        *st = VaultState::SignedOut;
        *self.auth_context.lock().unwrap() = None;
        if let Some(ks) = &self.keystore {
            let _ = ks.clear(&self.label);
        }
        self.broadcast(UnlockEvent::Revoked {
            epoch: new,
            reason: LockReason::ServerLogout,
        });
        self.publish(&st);
        new
    }

    /// 斷網/回網：**不改鎖態**，僅廣播（§2.2：離線僅 read-only 是誤把 sync
    /// 失敗當鎖定）。
    pub fn set_egress(&self, online: bool) {
        self.egress.store(online, Ordering::SeqCst);
        self.broadcast(UnlockEvent::Egress { online });
    }

    /// token 遭拒：保留金鑰、要求重認證、暫停 push，**不鎖**（治 #12270）。
    pub fn note_token_rejected(&self) {
        self.needs_reauth.store(true, Ordering::SeqCst);
        self.broadcast(UnlockEvent::NeedsReauth);
    }

    /// 使用者活動：重置 idle deadline（hard deadline 不動）。
    pub fn record_activity(&self) {
        let policy = *self.policy.lock().unwrap();
        let Some(d) = policy.idle else { return };
        let mut st = self.state.lock().unwrap();
        if let VaultState::Unlocked {
            idle_deadline_ms, ..
        } = &mut *st
        {
            *idle_deadline_ms = Some(self.clock.deadline_ms(d));
        }
    }

    /// 時脈推進後檢查是否逾時；逾時則 `lock(Timeout)`。回傳是否發生鎖定。
    /// 由 daemon 的計時器週期呼叫，或於 `with_keys` 內惰性檢查。
    pub fn check_timeout(&self) -> bool {
        let expired = {
            let st = self.state.lock().unwrap();
            match &*st {
                VaultState::Unlocked {
                    idle_deadline_ms,
                    hard_deadline_ms,
                    ..
                } => self.deadline_expired(*idle_deadline_ms, *hard_deadline_ms),
                VaultState::Unlocking { challenge } => {
                    self.clock.unix_ms() >= challenge.deadline_ms
                }
                _ => false,
            }
        };
        if expired {
            self.lock(LockReason::Timeout);
        }
        expired
    }

    fn deadline_expired(&self, idle: Option<u64>, hard: Option<u64>) -> bool {
        let now = self.clock.unix_ms();
        idle.map(|d| now >= d).unwrap_or(false) || hard.map(|d| now >= d).unwrap_or(false)
    }

    /// sync 發現金鑰指紋變動 → Stale（拒絕拿舊鑰硬解）。回傳是否進入 Stale。
    pub fn note_key_drift(&self, server_fp: Option<&str>) -> bool {
        let drift = {
            let st = self.state.lock().unwrap();
            match &*st {
                VaultState::Unlocked { keys, .. } => match (keys.fingerprint(), server_fp) {
                    (Some(was), Some(now)) if was != now => Some(KeyDrift::Fingerprint {
                        was: was.to_string(),
                        now: now.to_string(),
                    }),
                    (Some(_), None) => Some(KeyDrift::Rotated),
                    _ => None,
                },
                _ => None,
            }
        };
        let Some(why) = drift else { return false };
        let mut st = self.state.lock().unwrap();
        *st = VaultState::Stale { why };
        let e = self.next_epoch();
        self.broadcast(UnlockEvent::Revoked {
            epoch: e,
            reason: LockReason::KeyRotation,
        });
        self.publish(&st);
        true
    }

    /// 金鑰邊界：其他模組永遠拿不到 `KeyBundle` 實值，只能在閉包內用。
    /// 惰性檢查 timeout。
    pub fn with_keys<R>(&self, f: impl FnOnce(&KeyBundle) -> R) -> Result<R, KeyError> {
        let st = self.state.lock().unwrap();
        match &*st {
            VaultState::Unlocked {
                keys,
                idle_deadline_ms,
                hard_deadline_ms,
            } => {
                if self.deadline_expired(*idle_deadline_ms, *hard_deadline_ms) {
                    drop(st);
                    self.lock(LockReason::Timeout);
                    return Err(KeyError::Locked);
                }
                Ok(f(keys))
            }
            VaultState::Stale { why } => Err(KeyError::Stale(why.reason())),
            _ => Err(KeyError::Locked),
        }
    }

    /// 目前進行中的挑戰（若有）。
    pub fn pending_challenge(&self) -> Option<UnlockChallenge> {
        match &*self.state.lock().unwrap() {
            VaultState::Unlocking { challenge } => Some(challenge.clone()),
            _ => None,
        }
    }
}

/// 事件緩衝深度：daemon 可能短暂无訂閱者（thin client 重連期間）。
/// 取 256 對單裝置鎖態事件足夠（來源：本專案自訂，§2.2 事件量極低）。
const EVENT_CAP: usize = 256;
/// AuthRequest 挑戰預設存活的毫秒數（來源：本專案自訂；Bitwarden auth-request
/// TTL 由伺服器決定，這裡僅為離線挑戰的安全上界）。
const DEFAULT_CHALLENGE_TTL_MS: u64 = 60_000;

fn uuid_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Default)]
pub struct UnlockMachineBuilder {
    label: Option<AccountLabel>,
    clock: Option<std::sync::Arc<dyn Clock>>,
    kernel: Option<std::sync::Arc<dyn UnlockKernel>>,
    keystore: Option<std::sync::Arc<dyn KeyStore>>,
    policy: TimeoutPolicy,
    signed_out: bool,
}

impl UnlockMachineBuilder {
    pub fn label(mut self, l: AccountLabel) -> Self {
        self.label = Some(l);
        self
    }
    pub fn clock(mut self, c: std::sync::Arc<dyn Clock>) -> Self {
        self.clock = Some(c);
        self
    }
    pub fn kernel(mut self, k: std::sync::Arc<dyn UnlockKernel>) -> Self {
        self.kernel = Some(k);
        self
    }
    pub fn keystore(mut self, ks: std::sync::Arc<dyn KeyStore>) -> Self {
        self.keystore = Some(ks);
        self
    }
    pub fn policy(mut self, p: TimeoutPolicy) -> Self {
        self.policy = p;
        self
    }
    pub fn signed_out(mut self, v: bool) -> Self {
        self.signed_out = v;
        self
    }

    pub fn build(self) -> UnlockMachine {
        UnlockMachine {
            state: Mutex::new(if self.signed_out {
                VaultState::SignedOut
            } else {
                VaultState::AuthLocked { has_mirror: false }
            }),
            epoch: AtomicU64::new(0),
            has_mirror: AtomicBool::new(false),
            egress: AtomicBool::new(true),
            needs_reauth: AtomicBool::new(false),
            mirror_items: AtomicU64::new(0),
            clock: self
                .clock
                .unwrap_or_else(|| std::sync::Arc::new(crate::clock::SystemClock)),
            kernel: self
                .kernel
                .unwrap_or_else(|| std::sync::Arc::new(crate::kernel::BwCryptoKernel)),
            keystore: self.keystore,
            label: self
                .label
                .unwrap_or_else(|| AccountLabel::new(String::new())),
            auth_context: Mutex::new(None),
            policy: Mutex::new(self.policy),
            tx: OnceLock::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::keystore::{AccountLabel, FileKeyStore, SealedKey};
    use crate::{LockEpoch, LockReason, UnlockMaterial};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    /// 假內核：只認 "correct"；不碰 bw-crypto 實作（U3 併發進行中）。
    struct TestKernel;

    impl UnlockKernel for TestKernel {
        fn unlock_password(&self, pw: &str, ctx: &AuthContext) -> Result<KeyBundle, KeyError> {
            if pw == "correct" {
                Ok(KeyBundle::new(
                    bw_crypto::UserKey::from_bytes(vec![1u8; 64]).unwrap(),
                    None,
                    ctx.keys_fingerprint.clone(),
                ))
            } else {
                Err(KeyError::AuthFailed)
            }
        }
        fn unlock_assertion(&self, sealed: &SealedKey) -> Result<KeyBundle, KeyError> {
            Ok(KeyBundle::new(
                bw_crypto::UserKey::from_bytes(sealed.user_key.to_vec()).unwrap(),
                None,
                sealed.keys_fingerprint.clone(),
            ))
        }
    }

    fn ctx(fp: Option<&str>) -> AuthContext {
        AuthContext {
            email: "dev@bitward.test".into(),
            kdf: bw_crypto::KdfParams::Pbkdf2 {
                iterations: 600_000,
            },
            protected_user_key: "2.iv|ct|mac".into(),
            keys_fingerprint: fp.map(str::to_owned),
        }
    }

    struct Fix {
        clock: Arc<ManualClock>,
        machine: UnlockMachine,
    }

    fn fixture(policy: TimeoutPolicy) -> Fix {
        let clock = Arc::new(ManualClock::new());
        let machine = UnlockMachine::builder()
            .label(AccountLabel::new("dev@bitward.test"))
            .clock(clock.clone())
            .kernel(Arc::new(TestKernel))
            .policy(policy)
            .build();
        machine.set_auth_context(ctx(Some("fp-a")));
        Fix { clock, machine }
    }

    fn drain(rx: &mut tokio::sync::broadcast::Receiver<UnlockEvent>) -> Vec<UnlockEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn t01_signed_out_rejects_unlock() {
        let m = UnlockMachine::new();
        assert_eq!(m.state(), UnlockStateView::SignedOut);
        assert!(matches!(
            m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into()
            ))),
            Err(KeyError::NotAuthenticated)
        ));
    }

    #[test]
    fn t02_login_then_unlock_bumps_epoch_and_broadcasts() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        assert_eq!(f.machine.state(), UnlockStateView::AuthLocked { items: 0 });
        drain(&mut rx);
        let r = f
            .machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        let UnlockReceipt::Unlocked { epoch } = r else {
            panic!("expected Unlocked, got {r:?}")
        };
        assert_eq!(epoch, LockEpoch(1));
        assert!(f.machine.is_unlocked());
        let evs = drain(&mut rx);
        assert!(matches!(
            evs.last(),
            Some(UnlockEvent::State {
                view: UnlockStateView::Unlocked { epoch: 1, .. },
                ..
            })
        ));
    }

    #[test]
    fn t03_wrong_password_keeps_state_and_epoch() {
        let f = fixture(TimeoutPolicy::default());
        let e = f
            .machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "nope".into(),
            )))
            .unwrap_err();
        assert!(matches!(e, KeyError::AuthFailed));
        assert!(!f.machine.is_unlocked());
        assert_eq!(f.machine.epoch(), LockEpoch(0));
    }

    #[test]
    fn t04_idempotent_unlock_no_epoch_bump_and_sessions_survive() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        let UnlockReceipt::Unlocked { epoch: e1 } = f
            .machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap()
        else {
            panic!()
        };
        drain(&mut rx);
        // 重複 unlock：冪等、不 bump、不發 Revoked（治 clients#6898 的互毀）
        let r2 = f
            .machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        assert_eq!(r2, UnlockReceipt::AlreadyUnlocked { epoch: e1 });
        assert!(
            !drain(&mut rx)
                .iter()
                .any(|e| matches!(e, UnlockEvent::Revoked { .. }))
        );
        assert!(f.machine.with_keys(|_| ()).is_ok());
    }

    #[test]
    fn t05_concurrent_double_unlock_same_epoch() {
        let f = fixture(TimeoutPolicy::default());
        let m = &f.machine;
        std::thread::scope(|s| {
            let a = s.spawn(|| {
                m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                    "correct".into(),
                )))
            });
            let b = s.spawn(|| {
                m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                    "correct".into(),
                )))
            });
            let (ra, rb) = (
                a.join().unwrap().expect("unlock a"),
                b.join().unwrap().expect("unlock b"),
            );
            let epoch = |r: &UnlockReceipt| match r {
                UnlockReceipt::Unlocked { epoch } | UnlockReceipt::AlreadyUnlocked { epoch } => {
                    *epoch
                }
                UnlockReceipt::Pending { .. } => panic!("unexpected pending"),
            };
            assert_eq!(epoch(&ra), epoch(&rb), "併發雙 unlock 必須收斂到同一 epoch");
            assert_eq!(epoch(&ra), LockEpoch(1));
        });
        assert!(m.with_keys(|_| ()).is_ok());
    }

    #[test]
    fn t06_lock_bumps_epoch_revokes_and_locks_keys() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        drain(&mut rx);
        let new = f.machine.lock(LockReason::User);
        assert_eq!(new, LockEpoch(2));
        assert!(matches!(
            f.machine.state(),
            UnlockStateView::AuthLocked { .. }
        ));
        assert!(matches!(f.machine.with_keys(|_| ()), Err(KeyError::Locked)));
        let evs = drain(&mut rx);
        assert!(evs
            .iter()
            .any(|e| matches!(e, UnlockEvent::Revoked { epoch, reason: LockReason::User } if *epoch == LockEpoch(2))));
        // 級聯語意：綁舊 epoch 的 session 一律 StaleEpoch
        assert!(matches!(
            f.machine.check_epoch(LockEpoch(1)),
            Err(KeyError::StaleEpoch { seen: 1, now: 2 })
        ));
        // 再解鎖：epoch 再 ++
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        assert_eq!(f.machine.epoch(), LockEpoch(3));
    }

    #[test]
    fn t07_egress_change_does_not_touch_lock_state() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        drain(&mut rx);
        f.machine.set_egress(false);
        assert!(f.machine.is_unlocked(), "斷網不降級為鎖定（§2.2）");
        assert!(!f.machine.egress_online());
        let evs = drain(&mut rx);
        assert_eq!(evs, vec![UnlockEvent::Egress { online: false }]);
        assert!(f.machine.with_keys(|_| ()).is_ok());
    }

    #[test]
    fn t08_token_rejected_downgrade_not_lock() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        f.machine.note_token_rejected();
        // 保留金鑰：with_keys 仍可用（治 #12270 的直接壞掉）
        assert!(f.machine.with_keys(|_| ()).is_ok());
        assert!(f.machine.needs_reauth());
        assert!(drain(&mut rx).contains(&UnlockEvent::NeedsReauth));
        // 重新認證（再 submit 驗證通過）→ 解除旗標，epoch 不變
        let e_before = f.machine.epoch();
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        assert!(!f.machine.needs_reauth());
        assert_eq!(f.machine.epoch(), e_before);
    }

    #[test]
    fn t09_key_drift_to_stale_and_reunlock() {
        let f = fixture(TimeoutPolicy::default());
        let mut rx = f.machine.watch();
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        drain(&mut rx);
        // 同指紋：no-op
        assert!(!f.machine.note_key_drift(Some("fp-a")));
        // 他台改主密碼 → 指紋變動
        assert!(f.machine.note_key_drift(Some("fp-b")));
        match f.machine.state() {
            UnlockStateView::Stale { why } => assert!(why.contains("fp-a") && why.contains("fp-b")),
            other => panic!("expected Stale, got {other:?}"),
        }
        assert!(matches!(
            f.machine.with_keys(|_| ()),
            Err(KeyError::Stale(_))
        ));
        assert!(f.machine.epoch() > LockEpoch(1));
        assert!(drain(&mut rx).iter().any(|e| matches!(
            e,
            UnlockEvent::Revoked {
                reason: LockReason::KeyRotation,
                ..
            }
        )));
        // 重新認證：新 ctx 指紋 → 解鎖成功、離開 Stale
        f.machine.set_auth_context(ctx(Some("fp-b")));
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        assert!(f.machine.is_unlocked());
    }

    #[test]
    fn t10_idle_timeout_locks() {
        let f = fixture(TimeoutPolicy {
            idle: Some(Duration::from_secs(10)),
            hard: None,
        });
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        f.clock.advance(Duration::from_secs(9));
        assert!(!f.machine.check_timeout());
        f.clock.advance(Duration::from_secs(2));
        assert!(f.machine.check_timeout());
        assert!(matches!(
            f.machine.state(),
            UnlockStateView::AuthLocked { .. }
        ));
        assert_eq!(f.machine.epoch(), LockEpoch(2));
    }

    #[test]
    fn t11_activity_extends_idle_but_not_hard_deadline() {
        let f = fixture(TimeoutPolicy {
            idle: Some(Duration::from_secs(10)),
            hard: Some(Duration::from_secs(20)),
        });
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        f.clock.advance(Duration::from_secs(8));
        f.machine.record_activity(); // idle deadline → t=18
        f.clock.advance(Duration::from_secs(8)); // t=16：idle 未過
        assert!(!f.machine.check_timeout());
        f.clock.advance(Duration::from_secs(5)); // t=21：hard(t=20) 過，活動無效
        assert!(f.machine.check_timeout());
        assert_eq!(f.machine.epoch(), LockEpoch(2));
    }

    #[test]
    fn t12_with_keys_lazily_enforces_deadline() {
        let f = fixture(TimeoutPolicy {
            idle: Some(Duration::from_secs(10)),
            hard: None,
        });
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        f.clock.advance(Duration::from_secs(11));
        assert!(matches!(f.machine.with_keys(|_| ()), Err(KeyError::Locked)));
        assert!(matches!(
            f.machine.state(),
            UnlockStateView::AuthLocked { .. }
        ));
    }

    #[test]
    fn t13_device_assertion_offline_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeyStore::new(dir.path()).unwrap());
        let clock = Arc::new(ManualClock::new());
        let label = AccountLabel::new("dev@bitward.test");
        // 第一台機器：密碼解鎖順帶 enrollment
        let m1 = UnlockMachine::builder()
            .label(label.clone())
            .clock(clock.clone())
            .kernel(Arc::new(TestKernel))
            .keystore(ks.clone())
            .build();
        m1.set_auth_context(ctx(None));
        m1.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
            "correct".into(),
        )))
        .unwrap();
        assert!(
            ks.load_wrapped(&label).unwrap().is_some(),
            "成功解鎖應封存金鑰"
        );
        // 第二台機器（模擬重啟 daemon）：沒有 auth context（無網路情境），
        // DeviceAssertion 照樣解鎖 → 離線可解鎖（治 #19055）
        let m2 = UnlockMachine::builder()
            .label(label.clone())
            .clock(clock)
            .kernel(Arc::new(TestKernel))
            .keystore(ks.clone())
            .build();
        m2.submit(UnlockMaterial::DeviceAssertion).unwrap();
        assert!(m2.is_unlocked());
        assert_eq!(m2.epoch(), LockEpoch(1));
        // sign out 清空封存後不可離線解鎖
        m2.sign_out();
        assert!(matches!(
            m2.submit(UnlockMaterial::DeviceAssertion),
            Err(KeyError::NotAuthenticated)
        ));
        assert!(ks.load_wrapped(&label).unwrap().is_none());
    }

    #[test]
    fn t14_auth_request_pending_idempotent_and_resolves() {
        let f = fixture(TimeoutPolicy::default());
        let r = f.machine.submit(UnlockMaterial::AuthRequest).unwrap();
        let UnlockReceipt::Pending { challenge } = r else {
            panic!("{r:?}")
        };
        assert!(matches!(f.machine.state(), UnlockStateView::Unlocking));
        // 重複 submit 回同一挑戰（冪等）
        let r2 = f.machine.submit(UnlockMaterial::AuthRequest).unwrap();
        assert_eq!(
            r2,
            UnlockReceipt::Pending {
                challenge: challenge.clone()
            }
        );
        // 完成 → Unlocked
        let bundle = KeyBundle::new(
            bw_crypto::UserKey::from_bytes(vec![2u8; 64]).unwrap(),
            None,
            None,
        );
        let r3 = f.machine.complete_unlock(bundle);
        assert!(matches!(
            r3,
            UnlockReceipt::Unlocked {
                epoch: LockEpoch(1)
            }
        ));
        assert!(f.machine.is_unlocked());
        // 已解鎖後再 AuthRequest → AlreadyUnlocked
        let r4 = f.machine.submit(UnlockMaterial::AuthRequest).unwrap();
        assert_eq!(
            r4,
            UnlockReceipt::AlreadyUnlocked {
                epoch: LockEpoch(1)
            }
        );
    }

    #[test]
    fn t15_challenge_deadline_expires_to_authlocked() {
        let f = fixture(TimeoutPolicy::default());
        f.machine.submit(UnlockMaterial::AuthRequest).unwrap();
        f.clock
            .advance(Duration::from_secs(DEFAULT_CHALLENGE_TTL_MS / 1000 + 1));
        assert!(f.machine.check_timeout());
        assert!(matches!(
            f.machine.state(),
            UnlockStateView::AuthLocked { .. }
        ));
        assert_eq!(f.machine.epoch(), LockEpoch(1), "逾時鎖定也 bump epoch");
    }

    #[test]
    fn t16_epoch_monotonic_across_full_lifecycle() {
        type Step = Box<dyn Fn(&UnlockMachine)>;
        let f = fixture(TimeoutPolicy::default());
        let mut last = f.machine.epoch();
        let steps: Vec<Step> = vec![
            Box::new(|m| {
                m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                    "correct".into(),
                )))
                .unwrap();
            }),
            Box::new(|m| {
                m.lock(LockReason::User);
            }),
            Box::new(|m| {
                m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                    "correct".into(),
                )))
                .unwrap();
            }),
            Box::new(|m| {
                assert!(m.note_key_drift(Some("fp-changed")));
            }),
            Box::new(|m| {
                m.submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                    "correct".into(),
                )))
                .unwrap();
            }),
            Box::new(|m| {
                m.sign_out();
            }),
        ];
        for step in steps {
            step(&f.machine);
            let now = f.machine.epoch();
            assert!(
                now > last,
                "epoch 必須單調遞增（不變量 6）: {last:?} -> {now:?}"
            );
            last = now;
        }
    }

    #[test]
    fn t17_keybundle_debug_redacted_and_no_leak() {
        let f = fixture(TimeoutPolicy::default());
        f.machine
            .submit(UnlockMaterial::MasterPassword(Zeroizing::new(
                "correct".into(),
            )))
            .unwrap();
        let dbg = f.machine.with_keys(|k| format!("{k:?}")).unwrap();
        assert_eq!(dbg, "KeyBundle(REDACTED)");
        // with_keys 閉包只給 &KeyBundle：值不離開閉包（編譯期邊界，§3.2）
        let len = f
            .machine
            .with_keys(|k| k.user_key().as_bytes().len())
            .unwrap();
        assert_eq!(len, 64);
    }

    #[test]
    fn t18_set_mirror_view_items() {
        let m = UnlockMachine::new();
        m.set_auth_context(ctx(None));
        m.set_mirror(42);
        assert_eq!(m.state(), UnlockStateView::AuthLocked { items: 42 });
        assert!(matches!(
            m.state(),
            UnlockStateView::AuthLocked { items: 42 }
        ));
    }
}
