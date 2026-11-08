//! 設計 tokens：視圖層唯一的顏色與尺寸真相源。所有新外觀只从这里取值，
//! 散落 hex 視為代碼壞味道。語意命名（base/surface/elevated…），
//! 不跟 nsh theme() 的 shadcn 語意混用。本批發官方桌面版**淺色**皮
//! （白底、#175DDC 藍、小圓角）；dark 色板保留為 `DARK_*` 常量，
//! 外觀切換能力留給下批。每個 token 的 light/dark 兩槽同值，
//! 系統外觀切換不影響截圖一致性。

use nsh_core::prelude::AdaptiveColor;

/// 兩槽同值的常色（皮是設計目標，不是 appearance 的附屬品）。
const fn solid(hex: u32) -> AdaptiveColor {
    AdaptiveColor::rgb(hex, hex)
}

/// 兩槽同值的半透明黑（淺色皮的分隔線、背板）。
const fn black_alpha(a: f32) -> AdaptiveColor {
    AdaptiveColor {
        light: nsh_core::prelude::hsla(0.0, 0.0, 0.0, a),
        dark: nsh_core::prelude::hsla(0.0, 0.0, 0.0, a),
    }
}

// —— 背景層（官方淺色骨架） ——

/// 視窗／列表中柱底（純白）。
pub const BASE: AdaptiveColor = solid(0xFFFFFF);
/// 左側欄底（官方 sidebar 淡灰白）。
pub const SIDEBAR: AdaptiveColor = solid(0xF4F6F8);
/// 值塊、輸入框、型別磚的內層底。
pub const SURFACE: AdaptiveColor = solid(0xF7F8F9);
/// hover／中性選中提亮一階。
pub const SURFACE_RAISED: AdaptiveColor = solid(0xEFF1F4);
/// 模態、下拉面板等浮層（白卡＋hairline 描邊）。
pub const ELEVATED: AdaptiveColor = solid(0xFFFFFF);
/// 1px 分隔線／描邊。
pub const HAIRLINE: AdaptiveColor = black_alpha(0.10);
/// 浮層頂部 1px 線（淺色皮的高光改成極淡陰影線）。
pub const HIGHLIGHT: AdaptiveColor = black_alpha(0.04);
/// 模態背板壓暗。
pub const SCRIM: AdaptiveColor = black_alpha(0.45);

// —— 語意色 ——

/// 主色（Bitwarden 藍；按鈕實色不漸變、聚焦／選中／連結同色）。
pub const ACCENT: AdaptiveColor = solid(0x175DDC);
/// 主按鈕 hover（壓深一階）。
pub const ACCENT_HOVER: AdaptiveColor = solid(0x124CB4);
/// accent 底上的文字。
pub const TEXT_ON_ACCENT: AdaptiveColor = solid(0xFFFFFF);
/// 成功（複製完成、提示列）。
pub const SUCCESS: AdaptiveColor = solid(0x118846);
/// 警告（TOTP 到期前）。
pub const WARNING: AdaptiveColor = solid(0xB45309);
/// 危險（刪除）。
pub const DESTRUCTIVE: AdaptiveColor = solid(0xC0392B);

// —— 文字三級 ——

/// 主文字（近黑）。
pub const TEXT_PRIMARY: AdaptiveColor = solid(0x1F242C);
/// 次級文字。
pub const TEXT_SECONDARY: AdaptiveColor = solid(0x6B7280);
/// 弱化文字／節標題／欄位 label。
pub const TEXT_MUTED: AdaptiveColor = solid(0x9CA3AF);

// —— dark 色板（保留給下批外觀切換；本批不發） ——

/// 舊暗色皮：值不動，下批接 appearance 切換。
#[allow(dead_code)]
pub mod dark {
    use super::AdaptiveColor;

    const fn solid(hex: u32) -> AdaptiveColor {
        super::solid(hex)
    }

    pub const BASE: AdaptiveColor = solid(0x0E1116);
    pub const SURFACE: AdaptiveColor = solid(0x161B22);
    pub const SURFACE_RAISED: AdaptiveColor = solid(0x1D242E);
    pub const ELEVATED: AdaptiveColor = solid(0x1C2330);
    pub const ACCENT: AdaptiveColor = solid(0x5B6CF9);
    pub const SUCCESS: AdaptiveColor = solid(0x2EA36B);
    pub const WARNING: AdaptiveColor = solid(0xD9831A);
    pub const DESTRUCTIVE: AdaptiveColor = solid(0xE5484D);
}

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

    #[test]
    fn light_palette_is_official_light() {
        // 白底近黑字、Bitwarden 藍實色（本批設計語言的錨點）。
        assert_eq!(rgb255(BASE), (255, 255, 255));
        assert_eq!(rgb255(TEXT_PRIMARY), (0x1F, 0x24, 0x2C));
        assert_eq!(rgb255(ACCENT), (0x17, 0x5D, 0xDC));
        // hover 壓深一階（同色相、更低明度）。
        assert!(rgb255(ACCENT_HOVER).2 < rgb255(ACCENT).2);
    }

    #[test]
    fn dark_palette_reserved_for_next_batch() {
        // dark 色板保留：值仍是舊暗色系，切換能力不丟。
        assert_eq!(rgb255(dark::BASE), (0x0E, 0x11, 0x16));
        assert_eq!(rgb255(dark::ACCENT), (0x5B, 0x6C, 0xF9));
    }

    #[test]
    fn radius_scale_is_official_small() {
        assert_eq!(
            (RADIUS_CONTROL, RADIUS_BLOCK, RADIUS_CARD),
            (6.0, 8.0, 12.0)
        );
    }
}
