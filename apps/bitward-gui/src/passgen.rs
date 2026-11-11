//! 密碼產生器：面板狀態機與 daemon policy JSON（純函數，可單測）。
//! 隨機數與字集組裝全在 daemon（`Use:GeneratePassword` → hub 翻成
//! `bw_crypto::PasswordOptions`），GUI 只收參數、夾取、序列化——
//! 零業務邏輯紀律不破。
//! 批次 9：開關拆成官方六旗（大寫/小寫/數字/符號/易讀排除 0OlI1/
//! 避免相似），長度界面對齊官方 5–128。

use serde_json::{Value, json};

/// 滑桿範圍（官方 sdk-internal 界 5..=128）；預設 20（GUI 既有口徑）。
pub const LENGTH_MIN: usize = 5;
pub const LENGTH_MAX: usize = 128;
pub const LENGTH_DEFAULT: usize = 20;

/// 產生器狀態：開合、長度、六旗。表單面板與獨立產生器頁共用此狀態機
/// （零複製；兩頁各持一份訊號实例）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GenState {
    pub open: bool,
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// 官方 avoid_ambiguous：排除易混淆字元 `I O l 0 1`。
    pub avoid_ambiguous: bool,
}

impl Default for GenState {
    fn default() -> Self {
        Self {
            open: false,
            length: LENGTH_DEFAULT,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
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
        self.uppercase || self.lowercase || self.digits || self.symbols
    }

    /// `Use:GeneratePassword` 的 policy；欄名與 hub 讀取端一致
    /// （length/lowercase/uppercase/numbers/special/avoidAmbiguous）。
    pub fn policy(&self) -> Value {
        json!({
            "length": self.length.clamp(LENGTH_MIN, LENGTH_MAX) as u64,
            "lowercase": self.lowercase,
            "uppercase": self.uppercase,
            "numbers": self.digits,
            "special": self.symbols,
            "avoidAmbiguous": self.avoid_ambiguous,
        })
    }
}

/// 強度條填格（純函數，單測點；分級色另走 `reports::score_dot_color`
/// 同一真相源）：score 0–4 → 4 格條的填色數（0＝不填色，框線仍在）。
pub fn strength_segments(score: i64) -> usize {
    score.clamp(0, 4) as usize
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
        assert!(!g.avoid_ambiguous);
    }

    #[test]
    fn length_ratio_round_trips_through_endpoints() {
        assert_eq!(GenState::length_from_ratio(0.0), LENGTH_MIN);
        assert_eq!(GenState::length_from_ratio(1.0), LENGTH_MAX);
        assert_eq!(GenState::length_from_ratio(0.5), 67); // 5 + 0.5×123 = 66.5 → round 67
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
        g.set_length(200);
        assert_eq!(g.length, LENGTH_MAX);
    }

    #[test]
    fn policy_maps_six_flags() {
        let g = GenState {
            open: true,
            length: 24,
            uppercase: true,
            lowercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: true,
        };
        let p = g.policy();
        assert_eq!(p["length"], 24);
        assert_eq!(p["uppercase"], true);
        assert_eq!(p["lowercase"], false);
        assert_eq!(p["numbers"], true);
        assert_eq!(p["special"], false);
        assert_eq!(p["avoidAmbiguous"], true);
    }

    #[test]
    fn charset_guard_only_false_when_all_off() {
        let g = GenState {
            open: true,
            length: 12,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: true,
        };
        assert!(!g.has_charset(), "易讀旗不撐字元集");
    }

    #[test]
    fn strength_segments_clamp_to_four() {
        assert_eq!(strength_segments(-1), 0);
        assert_eq!(strength_segments(0), 0);
        assert_eq!(strength_segments(2), 2);
        assert_eq!(strength_segments(4), 4);
        assert_eq!(strength_segments(9), 4);
    }
}
