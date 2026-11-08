//! 密碼產生器：面板狀態機與 daemon policy JSON（純函數，可單測）。
//! 隨機數與字集組裝全在 daemon（`Use:GeneratePassword` → hub 翻成
//! `bw_crypto::PasswordOptions`），GUI 只收參數、夾取、序列化——
//! 零業務邏輯紀律不破。

use serde_json::{Value, json};

/// 滑桿範圍與預設（規格：8–64、預設 20；bw-crypto 下限同 8）。
pub const LENGTH_MIN: usize = 8;
pub const LENGTH_MAX: usize = 64;
pub const LENGTH_DEFAULT: usize = 20;

/// 產生器面板狀態：開合、長度、三個字元集開關。
/// 「大小寫」一鍵同控 lowercase＋uppercase（daemon policy 是兩欄）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GenState {
    pub open: bool,
    pub length: usize,
    pub letters: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenState {
    fn default() -> Self {
        Self {
            open: false,
            length: LENGTH_DEFAULT,
            letters: true,
            digits: true,
            symbols: true,
        }
    }
}

impl GenState {
    /// 滑桿比例 [0,1] → 長度；越界夾取，非有限值（除零 NaN）回預設。
    pub fn length_from_ratio(ratio: f32) -> usize {
        if !ratio.is_finite() {
            return LENGTH_DEFAULT;
        }
        let raw = LENGTH_MIN as f32 + ratio.clamp(0.0, 1.0) * (LENGTH_MAX - LENGTH_MIN) as f32;
        (raw.round() as usize).clamp(LENGTH_MIN, LENGTH_MAX)
    }

    /// 目前長度反算滑桿比例（顯示 knob/fill 用），先夾回合法區間。
    pub fn length_ratio(&self) -> f32 {
        let len = self.length.clamp(LENGTH_MIN, LENGTH_MAX);
        (len - LENGTH_MIN) as f32 / (LENGTH_MAX - LENGTH_MIN) as f32
    }

    pub fn set_length(&mut self, length: usize) {
        self.length = length.clamp(LENGTH_MIN, LENGTH_MAX);
    }

    /// 至少留一個字元集：全關時 daemon 端 classes 空集必錯，前端先擋。
    pub fn has_charset(&self) -> bool {
        self.letters || self.digits || self.symbols
    }

    /// `Use:GeneratePassword` 的 policy；欄名與 hub 讀取端一致
    /// （length/lowercase/uppercase/numbers/special/avoidAmbiguous）。
    pub fn policy(&self) -> Value {
        json!({
            "length": self.length.clamp(LENGTH_MIN, LENGTH_MAX) as u64,
            "lowercase": self.letters,
            "uppercase": self.letters,
            "numbers": self.digits,
            "special": self.symbols,
            "avoidAmbiguous": false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_panel_state() {
        let g = GenState::default();
        assert!(!g.open);
        assert_eq!(g.length, LENGTH_DEFAULT);
        assert!(g.has_charset());
    }

    #[test]
    fn length_ratio_round_trips_through_endpoints() {
        assert_eq!(GenState::length_from_ratio(0.0), LENGTH_MIN);
        assert_eq!(GenState::length_from_ratio(1.0), LENGTH_MAX);
        assert_eq!(GenState::length_from_ratio(0.5), (LENGTH_MIN + LENGTH_MAX) / 2);
        // 越界與 NaN：夾取／回預設，不 panic。
        assert_eq!(GenState::length_from_ratio(-0.4), LENGTH_MIN);
        assert_eq!(GenState::length_from_ratio(1.6), LENGTH_MAX);
        assert_eq!(GenState::length_from_ratio(f32::NAN), LENGTH_DEFAULT);
        let mut g = GenState::default();
        g.set_length(LENGTH_MAX);
        assert_eq!(GenState::length_from_ratio(g.length_ratio()), LENGTH_MAX);
    }

    #[test]
    fn set_length_clamps() {
        let mut g = GenState::default();
        g.set_length(3);
        assert_eq!(g.length, LENGTH_MIN);
        g.set_length(99);
        assert_eq!(g.length, LENGTH_MAX);
    }

    #[test]
    fn policy_maps_letters_switch_to_both_cases() {
        let g = GenState {
            open: true,
            length: 24,
            letters: true,
            digits: false,
            symbols: true,
        };
        let p = g.policy();
        assert_eq!(p["length"], 24);
        assert_eq!(p["lowercase"], true);
        assert_eq!(p["uppercase"], true);
        assert_eq!(p["numbers"], false);
        assert_eq!(p["special"], true);
    }

    #[test]
    fn charset_guard_only_false_when_all_off() {
        let g = GenState {
            open: true,
            length: 12,
            letters: false,
            digits: false,
            symbols: false,
        };
        assert!(!g.has_charset());
    }
}
