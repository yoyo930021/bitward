//! 本機設定（macOS 設定面補齊）：meta 表 JSON 行＋自動鎖定政策接線＋重啟行為。
//!
//! 自動鎖定的「活動」定義：任何 BTP `Invoke` 都算使用者活動（reveal／autofill／
//! 解鎖／同步觸發一律重計 idle deadline）；**純狀態輪詢不算**——GUI 的批准佇列
//! 1.5s 節拍、status 刷新、事件幫浦重連若不豁免，閒置計時器永不到期，等於沒有
//! 自動鎖定（豁免清單見 `hub::is_poll_call`）。執行側沿用狀態機既有的 idle＋hard
//! 雙軌心跳（main.rs），本模組只負責把 `Settings.auto_lock_minutes` 餵進
//! `TimeoutPolicy`；已解鎖時 `set_policy` 即刻重算上限，改設定不用等下次解鎖。

use bw_keys::{TimeoutPolicy, UnlockMaterial, UnlockReceipt};
use bw_proto::{Response, Settings, UnlockStateView};

use crate::hub::{DispatchResult, Hub};

/// meta 表落點鍵（本機設定的唯一真相源；JSON 形態＝`Settings` serde 預設）。
pub(crate) const META_KEY: &str = "settings";

/// 官方自動鎖定層級（分鐘）；0＝從不、255（`AUTO_LOCK_IMMEDIATE`）＝立即另判。
const AUTO_LOCK_TIERS: &[u8] = &[1, 5, 15, 30, 60, 240];
/// 官方剪貼簿清除層級（秒）；0＝從不。
const CLIPBOARD_TIERS: &[u8] = &[10, 20, 40, 60];

impl Hub {
    /// 從 meta 表讀設定；缺行或破損＝官方預設（相容性：舊庫沒有這行）。
    pub(crate) fn read_settings(store: &bw_store::Store) -> Settings {
        store
            .meta_str(META_KEY)
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub(crate) fn current_settings(&self) -> Settings {
        *self.settings.lock().expect("settings mutex poisoned")
    }

    /// 把現行設定餵進狀態機（idle 政策；hard 上限不開放＝None）。
    pub(crate) fn apply_timeout_policy(&self) {
        let s = self.current_settings();
        self.machine.set_policy(TimeoutPolicy {
            idle: s.idle_timeout(),
            hard: None,
        });
    }

    /// `Admin:SetSettings`：值域驗證（官方層級外拒收，不靜默存怪值）→
    /// 落庫 → 更新記憶體態 → 即時重套 idle 政策。
    pub(crate) fn store_settings(&self, s: Settings) -> DispatchResult {
        let valid = (s.auto_lock_minutes == 0
            || s.auto_lock_minutes == bw_proto::AUTO_LOCK_IMMEDIATE
            || AUTO_LOCK_TIERS.contains(&s.auto_lock_minutes))
            && (s.clipboard_clear_secs == 0 || CLIPBOARD_TIERS.contains(&s.clipboard_clear_secs));
        if !valid {
            return Err(crate::hub::denied(format!(
                "設定值不在官方層級：auto_lock_minutes={:?}（合法 0|255|{AUTO_LOCK_TIERS:?}）、\
                 clipboard_clear_secs={:?}（合法 0|{CLIPBOARD_TIERS:?}）",
                s.auto_lock_minutes, s.clipboard_clear_secs
            )));
        }
        let bytes = serde_json::to_string(&s).map_err(crate::hub::denied)?;
        self.store
            .meta_set(META_KEY, &bytes)
            .map_err(crate::hub::denied)?;
        *self.settings.lock().expect("settings mutex poisoned") = s;
        self.apply_timeout_policy();
        Ok(Response::Ok)
    }

    pub(crate) fn get_settings(&self) -> Response {
        Response::Settings(self.current_settings())
    }

    /// 重啟行為（`lock_on_sleep_restart=false`＝重新啟動後**不**鎖）：daemon
    /// 啟動即以封存裝置金鑰自動解鎖，跳過手動按「解鎖」。預設 true 時整個
    /// 函數直接回——重啟一律從鎖態起（官方預設語意）。封存金鑰不存在／解不開
    /// 時維持鎖態並記 log，不阻塞啟動。
    pub(crate) fn auto_unlock_on_start(&self) {
        if self.current_settings().lock_on_sleep_restart {
            return;
        }
        if !matches!(self.machine.state(), UnlockStateView::AuthLocked { .. }) {
            return;
        }
        match self.machine.submit(UnlockMaterial::DeviceAssertion) {
            Ok(UnlockReceipt::Unlocked { .. }) => {
                if let Err(e) = self.reindex_all() {
                    tracing::warn!(err = %e, "settings: 重啟自動解鎖後索引回填失敗");
                }
                tracing::info!("settings: lock_on_sleep_restart=false，重啟已自動解鎖");
            }
            Ok(other) => tracing::info!(?other, "settings: 重啟自動解鎖未落地"),
            Err(e) => tracing::info!(err = %e, "settings: 重啟自動解鎖失敗，維持鎖態"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::tests::unlocked_hub;
    use bw_proto::AUTO_LOCK_IMMEDIATE;

    #[tokio::test]
    async fn missing_settings_row_yields_official_defaults() {
        let (hub, dir) = unlocked_hub("set-default").await;
        let s = hub.current_settings();
        assert_eq!(s, Settings::default());
        assert_eq!(s.auto_lock_minutes, 15);
        assert_eq!(s.clipboard_clear_secs, 20);
        assert_eq!(s.idle_timeout(), Some(std::time::Duration::from_secs(900)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn set_settings_persists_and_survives_restart() {
        let (hub, dir) = unlocked_hub("set-persist").await;
        let want = Settings {
            auto_lock_minutes: 5,
            clipboard_clear_secs: 40,
            lock_on_sleep_restart: false,
            clear_search_on_lock: false,
        };
        hub.store_settings(want).unwrap();
        drop(hub);
        let hub2 = crate::hub::Hub::open(&dir, None, None).await.unwrap();
        assert_eq!(hub2.current_settings(), want);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn tier_validation_rejects_off_ladder_values() {
        let (hub, dir) = unlocked_hub("set-tiers").await;
        let bad = Settings {
            auto_lock_minutes: 7,
            ..Default::default()
        };
        assert!(hub.store_settings(bad).is_err());
        assert_eq!(hub.current_settings(), Settings::default());
        let ok = Settings {
            auto_lock_minutes: AUTO_LOCK_IMMEDIATE,
            clipboard_clear_secs: 0,
            ..Default::default()
        };
        assert!(hub.store_settings(ok).is_ok());
        assert_eq!(ok.idle_timeout(), Some(std::time::Duration::ZERO));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn immediate_auto_lock_applies_to_unlocked_machine() {
        let (hub, dir) = unlocked_hub("set-lock").await;
        assert!(hub.machine.is_unlocked());
        hub.store_settings(Settings {
            auto_lock_minutes: AUTO_LOCK_IMMEDIATE,
            ..Default::default()
        })
        .unwrap();
        // set_policy 已按新政策重算 idle deadline（零寬）→ 下一拍心跳即鎖
        assert!(hub.machine.check_timeout());
        assert!(!hub.machine.is_unlocked());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restart_auto_unlock_respects_toggle() {
        let (hub, dir) = unlocked_hub("set-restart").await;
        hub.store_settings(Settings {
            auto_lock_minutes: 0,
            lock_on_sleep_restart: false,
            ..Default::default()
        })
        .unwrap();
        // 手動鎖上 → 模擬重啟：開新 Hub 走啟動自動解鎖（封存金鑰在 disk）
        hub.machine.lock(bw_keys::LockReason::User);
        drop(hub);
        let hub2 = crate::hub::Hub::open(&dir, None, None).await.unwrap();
        assert!(!hub2.machine.is_unlocked());
        hub2.auto_unlock_on_start();
        assert!(hub2.machine.is_unlocked());
        // 預設（true）路徑：鎖態重啟不自動解
        hub2.store_settings(Settings {
            lock_on_sleep_restart: true,
            ..Default::default()
        })
        .unwrap();
        hub2.machine.lock(bw_keys::LockReason::User);
        drop(hub2);
        let hub3 = crate::hub::Hub::open(&dir, None, None).await.unwrap();
        hub3.auto_unlock_on_start();
        assert!(!hub3.machine.is_unlocked());
        let _ = std::fs::remove_dir_all(dir);
    }
}
