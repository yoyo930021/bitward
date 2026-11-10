//! 設計 tokens（手機適配）：視圖層唯一的顏色與尺寸真相源，語意借鑑
//! `apps/bitward-gui/src/theme.rs`（官方淺色皮＋Bitwarden 藍、雙槽色板），
//! 密度按觸控改寫。散落 hex 視為代碼壞味道；新外觀只從這裡取值。
//!
//! 暗色跟隨系統：nsh Android host 把裝置 night 態推進 `Environment`
//! （查證 nsh-platform-android host.rs：`color_scheme` 由 Java 側 `dark`
//! 布林驅動），`Appearance::System` 是預設值，所以**不需要任何設定程式碼**
//! ——AdaptiveColor 雙槽在繪製期即時翻轉，切主題不重建畫面。
//!
//! 手機適配的取捨（為什麼不是桌面三欄的直接縮小）：
//! - 三欄（側欄＋列表＋詳情）在手機沒有橫向空間 → 單欄 push 導航
//!   （既有 nav_stack 路線，返回鍵語意免費）；側欄的資料夾節點改成
//!   列表頂部的 **chip 行**（手機無側欄空間，抽屜要多一层手勢與指示器，
//!   而 vault 的資料夾通常 <5 個，一橫排 chip 的到達成本最低）。
//! - hover 態不存在 → 選中/按下的回饋走 `active`（壓暗）與選中底色。
//! - 觸控命中區下限 ~44pt：列高 44 保持官方節奏，鈕高 44、FAB 56。

use nsh_core::prelude::AdaptiveColor;

/// 兩槽各自定色（light, dark）。
const fn solid2(light: u32, dark: u32) -> AdaptiveColor {
    AdaptiveColor::rgb(light, dark)
}

/// 兩槽半透明黑。
const fn black2(la: f32, da: f32) -> AdaptiveColor {
    AdaptiveColor {
        light: nsh_core::prelude::hsla(0.0, 0.0, 0.0, la),
        dark: nsh_core::prelude::hsla(0.0, 0.0, 0.0, da),
    }
}

// —— 背景層（同 macOS 語意命名）——

/// 頁面底。
pub const BASE: AdaptiveColor = solid2(0xFFFFFF, 0x0E1116);
/// 頂部列／導航列底。
pub const BAR: AdaptiveColor = solid2(0xFFFFFF, 0x12171F);
/// 值塊、輸入框、型別磚的內層底。
pub const SURFACE: AdaptiveColor = solid2(0xF7F8F9, 0x161B22);
/// 按下／中性選中提亮一階。
pub const SURFACE_RAISED: AdaptiveColor = solid2(0xEFF1F4, 0x1D242E);
/// FAB、浮層面板。
pub const ELEVATED: AdaptiveColor = solid2(0xFFFFFF, 0x1C2330);
/// 1px 分隔線／描邊。
pub const HAIRLINE: AdaptiveColor = black2(0.10, 0.08);
/// chip 的描邊底（未選中）。
pub const CHIP_BG: AdaptiveColor = solid2(0xF1F3F5, 0x1D242E);

// —— 語意色 ——

/// 主色（淺槽 Bitwarden 藍 #175DDC、暗槽藍紫；FAB／選中／連結同色）。
pub const ACCENT: AdaptiveColor = solid2(0x175DDC, 0x5B6CF9);
/// accent 底上的文字。
pub const TEXT_ON_ACCENT: AdaptiveColor = solid2(0xFFFFFF, 0xFFFFFF);
/// 成功（複製完成）。
pub const SUCCESS: AdaptiveColor = solid2(0x118846, 0x2EA36B);
/// 警告（TOTP 到期前 ≤5 秒）。
pub const WARNING: AdaptiveColor = solid2(0xB45309, 0xD9831A);
/// 危險（刪除）。
pub const DESTRUCTIVE: AdaptiveColor = solid2(0xC0392B, 0xE5484D);

// —— 文字三級 ——

/// 主文字。
pub const TEXT_PRIMARY: AdaptiveColor = solid2(0x1F242C, 0xE9ECF1);
/// 次級文字（副行、label）。
pub const TEXT_SECONDARY: AdaptiveColor = solid2(0x6B7280, 0x9AA4B2);
/// 弱化文字（占位、節輔助）。
pub const TEXT_MUTED: AdaptiveColor = solid2(0x9CA3AF, 0x6E7784);

// —— 圓角（官方小圓角語彙，同 macOS 尺度）——

/// 按鈕／輸入框／chip。
pub const RADIUS_CONTROL: f32 = 6.0;
/// 值塊／型別磚。
pub const RADIUS_BLOCK: f32 = 8.0;
/// FAB（Material 圓形鈕）。
pub const RADIUS_FAB: f32 = 16.0;

// —— 密度 tokens（觸控下限 44；官方列表節奏 44）——

/// 頂部列高（列內含帳號摘要＋動作）。
pub const TOPBAR_H: f32 = 56.0;
/// 列表列高（雙行 15＋12＋磚 32）。
pub const ROW_H: f32 = 44.0;
/// 列表型別磚：邊長／字級（favicon 實圖同尺）。
pub const TILE_ROW: f32 = 32.0;
pub const TILE_ROW_GLYPH: f32 = 15.0;
/// 詳情 identity 型別磚：邊長／字級。
pub const TILE_ID: f32 = 44.0;
pub const TILE_ID_GLYPH: f32 = 19.0;
/// 列表主行／副行字級。
pub const TEXT_ROW: f32 = 15.0;
pub const TEXT_ROW_SUB: f32 = 12.0;
/// 頁面／表單標題字級。
pub const TEXT_PAGE_TITLE: f32 = 20.0;
pub const TEXT_PAGE_SUB: f32 = 12.5;
/// 詳情大名稱字級（官方編輯項目頁語感）。
pub const TEXT_IDENTITY: f32 = 22.0;
/// 詳情欄位：塊上 label（12 粗灰）與塊內 value（14）。
pub const TEXT_FIELD_LABEL: f32 = 12.0;
pub const TEXT_FIELD_VALUE: f32 = 14.0;
/// 節標題字級。
pub const TEXT_SECTION: f32 = 13.0;
/// 搜尋框／表單欄高度（觸控下限之上）。
pub const INPUT_H: f32 = 44.0;
/// 一般鈕高。
pub const BTN_H: f32 = 44.0;
/// FAB 邊長。
pub const FAB: f32 = 56.0;
/// 資料夾 chip 列高／字級。
pub const CHIP_H: f32 = 30.0;
pub const TEXT_CHIP: f32 = 12.5;
/// 「待推送」小膠囊：高與字級。
pub const BADGE_H: f32 = 16.0;
pub const TEXT_BADGE: f32 = 11.0;
/// 複製鈕邊長（列內熱區放大到 36 靠 padding）。
pub const COPY_BTN: f32 = 20.0;
/// 表單欄距。
pub const FORM_GAP: f32 = 12.0;
/// TOTP 倒數細進度條：高。
pub const TOTP_BAR_H: f32 = 4.0;
/// 型別磚的字母底（無 favicon 退路；藍灰單色系，不派生彩虹色）。
pub const TILE_LETTER: AdaptiveColor = solid2(0x2F5A9E, 0x4D6296);

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb255(c: AdaptiveColor) -> (u32, u32, u32) {
        let rgb = c.light.to_rgb();
        (
            (rgb.r * 255.0).round() as u32,
            (rgb.g * 255.0).round() as u32,
            (rgb.b * 255.0).round() as u32,
        )
    }

    fn rgb255_dark(c: AdaptiveColor) -> (u32, u32, u32) {
        let rgb = c.dark.to_rgb();
        (
            (rgb.r * 255.0).round() as u32,
            (rgb.g * 255.0).round() as u32,
            (rgb.b * 255.0).round() as u32,
        )
    }

    #[test]
    fn light_palette_is_official_light() {
        // 白底近黑字、Bitwarden 藍實色（與 macOS 皮同一個設計錨點）。
        assert_eq!(rgb255(BASE), (255, 255, 255));
        assert_eq!(rgb255(TEXT_PRIMARY), (0x1F, 0x24, 0x2C));
        assert_eq!(rgb255(ACCENT), (0x17, 0x5D, 0xDC));
    }

    #[test]
    fn dark_slots_carry_the_night_skin() {
        // 雙槽：暗色跟隨系統時由平台推 appearance，樣式閉包即時翻轉。
        assert_eq!(rgb255_dark(BASE), (0x0E, 0x11, 0x16));
        assert_eq!(rgb255_dark(ACCENT), (0x5B, 0x6C, 0xF9));
        assert_eq!(rgb255_dark(TEXT_PRIMARY), (0xE9, 0xEC, 0xF1));
    }

    #[test]
    fn touch_targets_respect_the_minimum() {
        // 觸控下限：列高/鈕高/欄高 ≥44，FAB 56（Material 標準）。
        assert!(ROW_H >= 44.0 && BTN_H >= 44.0 && INPUT_H >= 44.0);
        assert_eq!(FAB, 56.0);
        // 圓角尺度與 macOS 皮同源（官方小圓角語彙）。
        assert_eq!((RADIUS_CONTROL, RADIUS_BLOCK), (6.0, 8.0));
    }
}
