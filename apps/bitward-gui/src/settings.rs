//! 本機設定檢視（macOS 設定面補齊）：右欄視角，側欄「設定」進入。
//! 四組控件（自動鎖定／剪貼簿清除下拉 ＋ 重啟鎖定／鎖定清搜尋開關）＋「立即鎖定」鈕。
//! 改即存：任一控件變動即組整包 `Settings` 送 `Admin:SetSettings`，成功回 toast；
//! 值域與政策套用在 daemon（settings.rs），界面只列官方層級不重述判定。

use bw_proto::{AUTO_LOCK_IMMEDIATE, Settings};
use nsh_core::prelude::*;

use crate::state;
use crate::state::{AppCore, Cmd};
use crate::theme;
use crate::ui;

/// 自動鎖定層級（官方 web vault 選單）：(分鐘值, 繁中標籤)。0=從不、255=立即。
const AUTO_LOCK_LADDER: [(u8, &str); 8] = [
    (AUTO_LOCK_IMMEDIATE, "立即"),
    (1, "1 分鐘"),
    (5, "5 分鐘"),
    (15, "15 分鐘"),
    (30, "30 分鐘"),
    (60, "1 小時"),
    (240, "4 小時"),
    (0, "從不"),
];

/// 剪貼簿清除層級（官方選單）：(秒, 標籤)。0=從不。
const CLIPBOARD_LADDER: [(u8, &str); 5] = [
    (10, "10 秒"),
    (20, "20 秒"),
    (40, "40 秒"),
    (60, "60 秒"),
    (0, "從不"),
];

/// 設定頁視角（右欄整塊）。
pub fn pane(core: AppCore) -> View {
    let lock_core = core.clone();
    let auto_core = core.clone();
    let clip_core = core.clone();
    let restart_core = core.clone();
    let search_core = core.clone();
    let export_core = core.clone();
    let import_core = core.clone();
    let pw_cond = core.clone();
    let pw_build = core.clone();
    let theme_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .px_8()
        .py_5()
        .gap_4()
        .child(
            text("設定")
                .text_size(px(theme::TEXT_IDENTITY))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_5()
                .w_full()
                .max_w(px(560.0))
                .child(setting_row(
                    "自動鎖定",
                    "閒置多久後自動鎖庫（純狀態輪詢不計入活動）。",
                    dropdown(
                        core.settings,
                        auto_core,
                        |s| s.auto_lock_minutes,
                        |mut s, v| {
                            s.auto_lock_minutes = v;
                            s
                        },
                        &AUTO_LOCK_LADDER,
                    ),
                ))
                .child(setting_row(
                    "剪貼簿清除",
                    "複製敏感值後幾秒清空（中途另複製則讓位）。",
                    dropdown(
                        core.settings,
                        clip_core,
                        |s| s.clipboard_clear_secs,
                        |mut s, v| {
                            s.clipboard_clear_secs = v;
                            s
                        },
                        &CLIPBOARD_LADDER,
                    ),
                ))
                .child(setting_row(
                    "重新啟動後鎖定",
                    "開啟＝重啟一律從鎖態起；關閉＝daemon 啟動自動解鎖。",
                    toggle(core.settings, restart_core, |s| s.lock_on_sleep_restart, |mut s, v| {
                        s.lock_on_sleep_restart = v;
                        s
                    }),
                ))
                .child(setting_row(
                    "鎖定時清除最近搜尋",
                    "開啟＝進入鎖態即清掉搜尋框字串。",
                    toggle(core.settings, search_core, |s| s.clear_search_on_lock, |mut s, v| {
                        s.clear_search_on_lock = v;
                        s
                    }),
                ))
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .pt_2()
                        .child(ui::button("立即鎖定", ui::Btn::Ghost, move || {
                            lock_core.send(Cmd::RequestLock)
                        }))
                        .child(
                            text("立即上鎖 vault（解鎖需裝置金鑰）")
                                .text_size(px(theme::TEXT_PAGE_SUB))
                                .text_color(theme::TEXT_MUTED),
                        ),
                )
                // 批次 11：側欄收合後，庫工具與外觀搬進設定頁分節。
                .child(
                    view()
                        .flex_col()
                        .gap_2()
                        .child(ui::section_title("庫工具"))
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_2()
                                .child(ui::button("匯出", ui::Btn::Ghost, move || {
                                    export_core.send(Cmd::AskExport)
                                }))
                                .child(ui::button("匯入", ui::Btn::Ghost, move || {
                                    import_core.send(Cmd::OpenImport)
                                }))
                                .child(when(
                                    move || state::can_change_password(&pw_cond.vault.get()),
                                    move || {
                                        let c = pw_build.clone();
                                        ui::button("變更主密碼", ui::Btn::Ghost, move || {
                                            c.send(Cmd::OpenChangePassword)
                                        })
                                    },
                                )),
                        ),
                )
                .child(
                    view()
                        .flex_col()
                        .gap_2()
                        .child(ui::section_title("外觀"))
                        .child(crate::theme_picker(theme_core.clone())),
                ),
        ))
}

/// 設定列：左標題＋說明、右控件（官方設定頁行版式）。
fn setting_row(title: &'static str, desc: &'static str, control: View) -> View {
    view()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_4()
        .px_4()
        .py_3()
        .rounded(px(theme::RADIUS_CARD))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .child(
            view()
                .flex_col()
                .gap_1()
                .flex_1()
                .child(
                    text(title)
                        .text_size(px(14.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(
                    text(desc)
                        .text_size(px(theme::TEXT_PAGE_SUB))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
        .child(control)
}

/// 數值下拉：膠囊現值＋面板；選定即就地更新訊號並送整包存（改即存）。
fn dropdown(
    settings: Signal<Settings>,
    core: AppCore,
    get: impl Fn(Settings) -> u8 + 'static,
    set: impl Fn(Settings, u8) -> Settings + 'static,
    ladder: &'static [(u8, &'static str)],
) -> View {
    let get = std::rc::Rc::new(get);
    let set = std::rc::Rc::new(set);
    let open = signal(false);
    let label_get = get.clone();
    let panel_open = open;
    let panel_get = get.clone();
    let panel_set = set.clone();
    let pick_core = core.clone();
    view()
        .relative()
        .child(
            view()
                .h(px(theme::CHIP_H + 8.0))
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .flex_row()
                .items_center()
                .gap_2()
                .cursor_pointer()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .on_press(move || open.update(|o| *o = !*o))
                .child(
                    text(move || {
                        let cur = label_get(settings.get());
                        ladder
                            .iter()
                            .find(|(v, _)| *v == cur)
                            .map(|(_, l)| *l)
                            .unwrap_or("—")
                            .to_owned()
                    })
                    .text_size(px(13.0))
                    .text_color(theme::TEXT_PRIMARY),
                )
                .child(text("▾").text_size(px(9.0)).text_color(theme::TEXT_MUTED)),
        )
        .child(when(
            move || panel_open.get(),
            move || {
                let rows: Vec<View> = ladder
                    .iter()
                    .map(|(val, label)| {
                        let pick_settings = settings;
                        let pick_get = panel_get.clone();
                        let pick_set = panel_set.clone();
                        let pick = pick_core.clone();
                        let close = panel_open;
                        let (want, text_label) = (*val, *label);
                        let selected = pick_get(pick_settings.get()) == want;
                        ui::menu_row(text_label.to_owned(), selected, move || {
                            let next = pick_set(pick_settings.get(), want);
                            pick_settings.set(next);
                            close.set(false);
                            pick.send(Cmd::ApplySettings(next));
                        })
                    })
                    .collect();
                view()
                    .absolute()
                    .top(px(theme::CHIP_H + 12.0))
                    .right_0()
                    .z_index(10)
                    .child(ui::card(rows).w(px(140.0)))
            },
        ))
}

/// 布林開關：點擊翻值即就地更新＋送存（沿用詳情頁 `bool_switch` 幾何）。
fn toggle(
    settings: Signal<Settings>,
    core: AppCore,
    get: impl Fn(Settings) -> bool + 'static,
    set: impl Fn(Settings, bool) -> Settings + 'static,
) -> View {
    let get = std::rc::Rc::new(get);
    let set = std::rc::Rc::new(set);
    let press_get = get.clone();
    let switch_get = get.clone();
    let text_get = get;
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .cursor_pointer()
        .on_press(move || {
            let now = press_get(settings.get());
            let next = set(settings.get(), !now);
            settings.set(next);
            core.send(Cmd::ApplySettings(next));
        })
        .child(ui::bool_switch(move || switch_get(settings.get())))
        .child(
            text(move || if text_get(settings.get()) { "開" } else { "關" })
                .text_size(px(12.5))
                .text_color(theme::TEXT_SECONDARY),
        )
}
