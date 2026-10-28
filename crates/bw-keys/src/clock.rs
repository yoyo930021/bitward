//! 可注入時鐘：vault timeout 的 idle/hard deadline 與 challenge 過期全部
//! 經此取時，測試用 `ManualClock` 推進，不需要 `tokio::time::pause`。

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// 單調時鐘，用於 deadline 比較。
    fn now(&self) -> Instant;
    /// unix epoch 毫秒，用於跨進程可見的 deadline 表示（UnlockStateView）。
    fn unix_ms(&self) -> u64;
    /// deadline 算術統一用毫秒（u64），避免 Instant 無法序列化。
    fn deadline_ms(&self, d: Duration) -> u64 {
        self.unix_ms().saturating_add(d.as_millis() as u64)
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// 測試用：時間只隨 `advance` 前進（共用時以 `Arc` 包裝）。
pub struct ManualClock {
    base: Instant,
    epoch_base_ms: u64,
    offset: Mutex<Duration>,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ManualClock {
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            epoch_base_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    pub fn advance(&self, d: Duration) {
        *self.offset.lock().unwrap() += d;
    }

    pub fn offset(&self) -> Duration {
        *self.offset.lock().unwrap()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap()
    }
    fn unix_ms(&self) -> u64 {
        self.epoch_base_ms + self.offset().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_both_scales() {
        let c = ManualClock::new();
        let m0 = c.unix_ms();
        let i0 = c.now();
        c.advance(Duration::from_secs(3));
        assert_eq!(c.unix_ms(), m0 + 3000);
        assert!(c.now() > i0);
        assert_eq!(c.deadline_ms(Duration::from_secs(1)), m0 + 4000);
    }

    #[test]
    fn system_clock_moves() {
        let c = SystemClock;
        assert!(c.unix_ms() > 1_700_000_000_000);
    }
}
