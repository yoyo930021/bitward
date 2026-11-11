//! 設計 tokens：視圖層唯一的顏色與尺寸真相源。所有新外觀只从这里取值，
//! 散落 hex 視為代碼壞味道。語意命名（base/surface/elevated…），
//! 不跟 nsh theme() 的 shadcn 語意混用。**雙槽色板**（批次 5）：
//! light 槽＝官方淺色皮（白底、#175DDC 藍、小圓角），dark 槽＝保留的
//! 暗色皮；外觀由 `set_color_scheme`（跟隨系統／淺／暗三態）驅動，
//! 樣式閉包讀取時即時翻轉，不重建視窗。

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

// —— 背景層 ——

/// 視窗／列表中柱底。
pub const BASE: AdaptiveColor = solid2(0xFFFFFF, 0x0E1116);
/// 左側欄底。
pub const SIDEBAR: AdaptiveColor = solid2(0xF4F6F8, 0x12171F);
/// 值塊、輸入框、型別磚的內層底。
pub const SURFACE: AdaptiveColor = solid2(0xF7F8F9, 0x161B22);
/// hover／中性選中提亮一階。
pub const SURFACE_RAISED: AdaptiveColor = solid2(0xEFF1F4, 0x1D242E);
/// 模態、下拉面板等浮層。
pub const ELEVATED: AdaptiveColor = solid2(0xFFFFFF, 0x1C2330);
/// 1px 分隔線／描邊（淺底黑 10%、暗底白 8%）。
pub const HAIRLINE: AdaptiveColor = black2(0.10, 0.08);
/// 浮層頂部 1px 線。
pub const HIGHLIGHT: AdaptiveColor = black2(0.04, 0.10);
/// 模態背板壓暗。
pub const SCRIM: AdaptiveColor = black2(0.45, 0.60);

// —— 語意色 ——

/// 主色（淺槽 Bitwarden 藍、暗槽保留藍紫；聚焦／選中／連結同色）。
pub const ACCENT: AdaptiveColor = solid2(0x175DDC, 0x5B6CF9);
/// 主按鈕 hover（淺色壓深、暗色提亮）。
pub const ACCENT_HOVER: AdaptiveColor = solid2(0x124CB4, 0x7B8AFF);
/// accent 底上的文字。
pub const TEXT_ON_ACCENT: AdaptiveColor = solid2(0xFFFFFF, 0xFFFFFF);
/// 成功（複製完成、提示列）。
pub const SUCCESS: AdaptiveColor = solid2(0x118846, 0x2EA36B);
/// 警告（TOTP 到期前）。
pub const WARNING: AdaptiveColor = solid2(0xB45309, 0xD9831A);
/// 危險（刪除）。
pub const DESTRUCTIVE: AdaptiveColor = solid2(0xC0392B, 0xE5484D);

// —— 文字三級 ——

/// 主文字。
pub const TEXT_PRIMARY: AdaptiveColor = solid2(0x1F242C, 0xE9ECF1);
/// 次級文字。
pub const TEXT_SECONDARY: AdaptiveColor = solid2(0x6B7280, 0x9AA4B2);
/// 弱化文字／節標題辅助。
pub const TEXT_MUTED: AdaptiveColor = solid2(0x9CA3AF, 0x6E7784);

// —— 圓角（官方小圓角語彙） ——

/// 按鈕／輸入框／下拉。
pub const RADIUS_CONTROL: f32 = 6.0;
/// 值塊／型別磚／面板。
pub const RADIUS_BLOCK: f32 = 8.0;
/// 模態與置中卡。
pub const RADIUS_CARD: f32 = 12.0;

// —— 密度 tokens（官方節奏：列表 44、名稱 14／URL 13） ——

/// 頂部列高（置中搜尋＋右側新增）。
pub const TOPBAR_H: f32 = 48.0;
/// 左側欄寬／條目高／選中指示條寬。
pub const SIDEBAR_W: f32 = 220.0;
pub const SIDE_ITEM_H: f32 = 32.0;
pub const SIDE_BAR_W: f32 = 3.0;
/// 中列表欄寬。
pub const LIST_W: f32 = 300.0;
/// 列表列高（雙行 14＋13）。
pub const ROW_H: f32 = 44.0;
/// 列表型別磚：邊長／字級（取代 monogram 派生色磚）。
pub const TILE_ROW: f32 = 32.0;
pub const TILE_ROW_GLYPH: f32 = 15.0;
/// 詳情 identity 型別磚：邊長／字級（佔位卡圖示同尺）。
pub const TILE_ID: f32 = 44.0;
pub const TILE_ID_GLYPH: f32 = 19.0;
/// 列表主行／副行字級。
pub const TEXT_ROW: f32 = 14.0;
pub const TEXT_ROW_SUB: f32 = 13.0;
/// 頂部列產品名與副行字級。
pub const TEXT_PAGE_TITLE: f32 = 15.0;
pub const TEXT_PAGE_SUB: f32 = 12.0;
/// 詳情大名稱字級（官方編輯項目頁語感）。
pub const TEXT_IDENTITY: f32 = 22.0;
/// 詳情欄位：塊上 label（12 粗灰）與塊內 value（14）。
pub const TEXT_FIELD_LABEL: f32 = 12.0;
pub const TEXT_FIELD_VALUE: f32 = 14.0;
/// 複製鈕邊長。
pub const COPY_BTN: f32 = 20.0;
/// 輸入框族高度：搜尋框／模態欄位／下拉鈕。
pub const INPUT_H: f32 = 34.0;
/// 搜尋框寬（置中）。
pub const SEARCH_W: f32 = 420.0;
/// 標籤 chips 列高。
pub const CHIP_H: f32 = 22.0;
/// 小號狀態膠囊（未同步）：高與字級。
pub const BADGE_H: f32 = 16.0;
pub const TEXT_BADGE: f32 = 11.0;
/// 側欄組標題（批次 12：11px uppercase muted）。
pub const TEXT_SECTION: f32 = 11.0;
/// 模態欄距。
pub const FORM_GAP: f32 = 12.0;
/// 置中卡（鎖態／佔位／連線失敗）標題字級與 glyph 尺寸。
pub const TEXT_CARD_TITLE: f32 = 15.0;
pub const GLYPH_LOCK: f32 = 28.0;
pub const GLYPH_KEY: f32 = 20.0;
/// 產生器面板：滑桿軌道寬／高、命中區高、knob 直徑。
pub const GEN_TRACK_W: f32 = 240.0;
pub const GEN_TRACK_H: f32 = 6.0;
pub const GEN_TRACK_HIT_H: f32 = 18.0;
pub const GEN_KNOB: f32 = 14.0;
/// TOTP 倒數細进度條：軌道寬／高。
pub const TOTP_BAR_W: f32 = 120.0;
pub const TOTP_BAR_H: f32 = 4.0;
/// 布林開關（編輯列與詳情共用幾何）：軌道寬／高、knob 直徑。
pub const TOGGLE_W: f32 = 28.0;
pub const TOGGLE_H: f32 = 16.0;
pub const TOGGLE_KNOB: f32 = 12.0;
/// 欄位型別選單寬。
pub const KIND_MENU_W: f32 = 120.0;

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
        // 白底近黑字、Bitwarden 藍實色（設計語言的錨點）。
        assert_eq!(rgb255(BASE), (255, 255, 255));
        assert_eq!(rgb255(TEXT_PRIMARY), (0x1F, 0x24, 0x2C));
        assert_eq!(rgb255(ACCENT), (0x17, 0x5D, 0xDC));
        // hover 壓深一階（同色相、更低明度）。
        assert!(rgb255(ACCENT_HOVER).2 < rgb255(ACCENT).2);
    }

    #[test]
    fn dark_slots_carry_the_retained_night_skin() {
        // 雙槽：dark 槽仍是舊暗色系，set_color_scheme(Dark) 即翻轉。
        assert_eq!(rgb255_dark(BASE), (0x0E, 0x11, 0x16));
        assert_eq!(rgb255_dark(ACCENT), (0x5B, 0x6C, 0xF9));
        assert_eq!(rgb255_dark(TEXT_PRIMARY), (0xE9, 0xEC, 0xF1));
        // 暗槽 hover 反向提亮。
        assert!(rgb255_dark(ACCENT_HOVER).2 > rgb255_dark(ACCENT).2);
    }

    #[test]
    fn radius_scale_is_official_small() {
        assert_eq!(
            (RADIUS_CONTROL, RADIUS_BLOCK, RADIUS_CARD),
            (6.0, 8.0, 12.0)
        );
    }
}
