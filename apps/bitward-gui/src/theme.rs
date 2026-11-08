//! 設計 tokens：視圖層唯一的顏色與尺寸真相源。所有新外觀只从这里取值，
//! 散落 hex 視為代碼壞味道。語意命名（base/surface/elevated…），
//! 不跟 nsh theme() 的 shadcn 語意混用——本 app 強制定位暗色，
//! 每個 token 的 light/dark 兩槽同值，系統外觀切換不影響截圖一致性。

use nsh_core::prelude::AdaptiveColor;

/// 兩槽同值的常色（暗色調是設計目標，不是 appearance 的附屬品）。
const fn solid(hex: u32) -> AdaptiveColor {
    AdaptiveColor::rgb(hex, hex)
}

/// 兩槽同值的半透明白（分隔線、高光線）。
const fn white_alpha(a: f32) -> AdaptiveColor {
    AdaptiveColor {
        light: nsh_core::prelude::hsla(0.0, 0.0, 1.0, a),
        dark: nsh_core::prelude::hsla(0.0, 0.0, 1.0, a),
    }
}

// —— 背景三層 ——

/// 視窗底（近黑帶藍）。
pub const BASE: AdaptiveColor = solid(0x0E1116);
/// 列表列、輸入框、卡片以外的內層底。
pub const SURFACE: AdaptiveColor = solid(0x161B22);
/// 選中／hover 提亮一階。
pub const SURFACE_RAISED: AdaptiveColor = solid(0x1D242E);
/// 模態、下拉面板等浮層。
pub const ELEVATED: AdaptiveColor = solid(0x1C2330);
/// 1px 分隔線／描邊（surface 上 8% 白）。
pub const HAIRLINE: AdaptiveColor = white_alpha(0.08);
/// 浮層頂部 1px 高光線（模拟陰影的上緣）。
pub const HIGHLIGHT: AdaptiveColor = white_alpha(0.10);
/// 模態背板壓暗。
pub const SCRIM: AdaptiveColor = AdaptiveColor {
    light: nsh_core::prelude::hsla(0.0, 0.0, 0.0, 0.60),
    dark: nsh_core::prelude::hsla(0.0, 0.0, 0.0, 0.60),
};

// —— 語意色 ——

/// 主色（漸變起點，也用作聚焦/選中/連結的實色）。
pub const ACCENT: AdaptiveColor = solid(0x5B6CF9);
/// 漸變起點。
pub const ACCENT_FROM: AdaptiveColor = solid(0x5B6CF9);
/// 漸變終點。
pub const ACCENT_TO: AdaptiveColor = solid(0x8A5CF6);
/// 成功（複製完成、提示列）。
pub const SUCCESS: AdaptiveColor = solid(0x2EA36B);
/// 警告（待推送）。
pub const WARNING: AdaptiveColor = solid(0xD9831A);
/// 危險（刪除）。
pub const DESTRUCTIVE: AdaptiveColor = solid(0xE5484D);

// —— 文字三級 ——

/// 主文字（92% 白）。
pub const TEXT_PRIMARY: AdaptiveColor = white_alpha(0.92);
/// 次級文字（62% 白）。
pub const TEXT_SECONDARY: AdaptiveColor = white_alpha(0.62);
/// 弱化文字／節標題（40% 白）。
pub const TEXT_MUTED: AdaptiveColor = white_alpha(0.40);

// —— 密度 tokens（緊湊規格：尺寸與字級的唯一出處，禁散落魔數） ——

/// 列表列高（雙行 13.5＋11.5 加 2px 行距仍容納）。
pub const ROW_H: f32 = 38.0;
/// 列表 monogram：邊長／圓角／字級。
pub const MONOGRAM_ROW: f32 = 26.0;
pub const MONOGRAM_ROW_RADIUS: f32 = 8.0;
pub const MONOGRAM_ROW_TEXT: f32 = 11.0;
/// 詳情 identity monogram：邊長／圓角／字級（佔位卡圖示同尺等比）。
pub const MONOGRAM_ID: f32 = 44.0;
pub const MONOGRAM_ID_RADIUS: f32 = 12.0;
pub const MONOGRAM_ID_TEXT: f32 = 16.0;
/// 列表主行／副行字級（15→13.5、12.5→11.5）。
pub const TEXT_ROW: f32 = 13.5;
pub const TEXT_ROW_SUB: f32 = 11.5;
/// 頁面大標題與副行字級（28→22、13→12）。
pub const TEXT_PAGE_TITLE: f32 = 22.0;
pub const TEXT_PAGE_SUB: f32 = 12.0;
/// 詳情 identity 名稱字級（22→17）。
pub const TEXT_IDENTITY: f32 = 17.0;
/// 詳情欄位列同行制：label／value 字級與 label 欄寬。
pub const TEXT_FIELD_LABEL: f32 = 12.0;
pub const TEXT_FIELD_VALUE: f32 = 13.5;
pub const FIELD_LABEL_W: f32 = 120.0;
/// 詳情欄位列高（1Password 式緊湊行）。
pub const FIELD_H: f32 = 34.0;
/// 複製鈕邊長（26→20）。
pub const COPY_BTN: f32 = 20.0;
/// 輸入框族高度：搜尋框／模態欄位／下拉鈕（44→34）。
pub const INPUT_H: f32 = 34.0;
/// 標籤 chips 列高（28 減 20%）。
pub const CHIP_H: f32 = 22.0;
/// 小號狀態膠囊（待推送）：高與字級。
pub const BADGE_H: f32 = 16.0;
pub const TEXT_BADGE: f32 = 11.0;
/// 模態欄距（16 減 25%）。
pub const FORM_GAP: f32 = 12.0;
/// 標題區頂部／底部留白（20、16 各減 1/3）。
pub const HEADER_PT: f32 = 13.0;
pub const HEADER_PB: f32 = 11.0;
/// 置中卡（鎖態／佔位／連線失敗）標題字級與 glyph 尺寸（等比縮小）。
pub const TEXT_CARD_TITLE: f32 = 15.0;
pub const GLYPH_LOCK: f32 = 28.0;
pub const GLYPH_KEY: f32 = 20.0;

// —— monogram 派生色 ——

/// 頭像色盤（1Password 式：名字穩定派生，不隨列表變動）。
pub const MONOGRAM_PALETTE: [AdaptiveColor; 8] = [
    solid(0xE5484D),
    solid(0xF76B15),
    solid(0xFFB224),
    solid(0x46A758),
    solid(0x12A594),
    solid(0x0091FF),
    solid(0x5B6CF9),
    solid(0x8E4EC6),
];

/// 名字 → 色盤索引（FNV-1a；同一名字永遠同色）。
pub fn palette_index(name: &str) -> usize {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    (hash % MONOGRAM_PALETTE.len() as u64) as usize
}

/// 頭像底色；沒有名字的項目走「?」的固定灰。
pub fn monogram_color(name: Option<&str>) -> AdaptiveColor {
    match name {
        Some(n) if !n.is_empty() => MONOGRAM_PALETTE[palette_index(n)],
        _ => SURFACE_RAISED,
    }
}

/// 頭像字元：首字大寫（中文原樣）；空名退回「?」。
pub fn monogram_char(name: Option<&str>) -> String {
    name.filter(|n| !n.is_empty())
        .and_then(|n| n.chars().next())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_index_is_stable_and_in_range() {
        let a = palette_index("GitHub 測試");
        let b = palette_index("GitHub 測試");
        assert_eq!(a, b);
        assert!(a < MONOGRAM_PALETTE.len());
        // 不同名字不该全撞同一格（8 色盤、幾個名字至少兩格）。
        let idx: Vec<usize> = ["GitHub", "webeauth.io", "E2E 驗證項目", "銀行", "mail"]
            .iter()
            .map(|n| palette_index(n))
            .collect();
        assert!(idx.iter().collect::<std::collections::HashSet<_>>().len() > 1, "{idx:?}");
    }

    #[test]
    fn monogram_char_uppercases_first_and_falls_back() {
        assert_eq!(monogram_char(Some("github")), "G");
        assert_eq!(monogram_char(Some("銀行")), "銀");
        assert_eq!(monogram_char(Some("")), "?");
        assert_eq!(monogram_char(None), "?");
    }

    #[test]
    fn unnamed_items_get_the_neutral_tile() {
        assert_eq!(monogram_color(None), SURFACE_RAISED);
        assert_eq!(monogram_color(Some("")), SURFACE_RAISED);
        assert_eq!(monogram_color(Some("GitHub")), MONOGRAM_PALETTE[palette_index("GitHub")]);
    }
}
