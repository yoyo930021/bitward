//! Bitward vault GUI（NSH，契約 §0.2）：macOS 密碼管理主體。
//!
//! 架構：所有狀態收在 `state::AppCore`（訊號 + 命令佇列）；UI handler 只
//! 投遞 `Cmd`，`set_interval` 幫浦在引擎執行緒上 `reduce`；需要 daemon 的
//! 動作派到 worker 執行緒（`btp::Session` 同步 UDS client），worker 只準
//! 回傳 `Cmd`、不碰訊號。分級、過濾、排序語意全在 daemon（零業務邏輯在
//! GUI）；導航是 `Route` 狀態機＋官方三欄骨架（左側欄｜中列表欄｜右詳情欄，
//! 新增/編輯與確認走模態；nav_stack 在 macOS dev host 不渲染，spike
//! FINDINGS 卡點 4）。外觀代幣全在 `theme`（本批發官方淺色皮）。

mod attach;
mod approvals;
mod btp;
mod detail;
mod export;
mod form;
mod genpage;
mod import;
mod list;
mod passgen;
mod reports;
mod send;
mod settings;
mod shots;
mod state;
mod theme;
mod ui;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use nsh_core::prelude::*;

use bw_proto::UnlockStateView;
use state::{AppCore, Cmd, FolderEntry, Phase, Route};

/// 連線參數解析順序：`--sock <path>` > `BITWARD_GUI_SOCK` >
/// `$BITWARD_DATA_DIR/daemon.sock` > 平台資料目錄（`<datadir>/bitward/daemon.sock`）。
pub fn sock_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--sock")
        && let Some(p) = args.get(i + 1)
    {
        return p.into();
    }
    if let Ok(p) = std::env::var("BITWARD_GUI_SOCK") {
        return p.into();
    }
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return PathBuf::from(d).join("daemon.sock");
    }
    platform_data_dir().join("bitward").join("daemon.sock")
}

#[cfg(target_os = "macos")]
fn platform_data_dir() -> PathBuf {
    home_dir().join("Library/Application Support")
}

#[cfg(target_os = "linux")]
fn platform_data_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".local/share"))
}

#[cfg(target_os = "windows")]
fn platform_data_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("APPDATA").unwrap_or_else(|| "C:\\AppData".into()))
}

#[cfg(not(windows))]
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[native_module("bitward-gui/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// 主題持久化：`<平台資料目錄>/bitward/theme.txt`（GUI 側小檔，重啟記住）。
/// 取捨：nsh 沒暴露 UserDefaults 綁定，小檔最貼近 `sock_path` 的既有慣例；
/// 跟隨系統不需要輪詢——nsh 的 `dark()` env 由平台推送，`Appearance::System`
/// 即官方「自動」語意（查證 nsh-core ambient.rs：set_color_scheme/dark）。
pub(crate) fn theme_file() -> PathBuf {
    platform_data_dir().join("bitward").join("theme.txt")
}

pub(crate) fn load_theme_mode() -> Appearance {
    match std::fs::read_to_string(theme_file()) {
        Ok(s) => match s.trim() {
            "light" => Appearance::Light,
            "dark" => Appearance::Dark,
            _ => Appearance::System,
        },
        Err(_) => Appearance::System,
    }
}

pub(crate) fn save_theme_mode(mode: Appearance) {
    let name = match mode {
        Appearance::System => "system",
        Appearance::Light => "light",
        Appearance::Dark => "dark",
    };
    let path = theme_file();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, name);
}

/// 根元件：建立 AppCore、掛命令幫浦、分派主從式畫面與模態。
#[component]
pub fn App() -> impl IntoElement {
    let (core, rx) = AppCore::boot(Arc::new(btp::Session::new(sock_path())));
    let rx = Rc::new(RefCell::new(rx));
    set_interval(Duration::from_millis(50), {
        let core = core.clone();
        move || {
            let mut drained: Vec<Cmd> = Vec::new();
            while let Ok(cmd) = rx.borrow().try_recv() {
                drained.push(cmd);
            }
            if drained.is_empty() {
                return;
            }
            batch(|| {
                for cmd in drained {
                    state::reduce(&core, cmd);
                }
            });
        }
    });
    core.send(Cmd::Boot);
    core.watch_events();
    // 外觀套用：effect 讀 theme_mode → set_color_scheme。effect 跑在
    // App 的元件上下文（act 合法），且跟隨系統時由平台 env 自動翻轉，
    // 不需任何輪詢；切主題只翻樣式閉包，不重建視窗。
    core.theme_mode.set(load_theme_mode());
    let theme_watch = core.clone();
    effect(move || {
        set_color_scheme(theme_watch.theme_mode.get());
    });
    // 批次 11 直跳捷徑（nsh keymap 支援 cmd 修飾，查證 keymap.rs 519）：
    // cmd+1 全部項目、cmd+2 垃圾桶、cmd+3 產生密碼、cmd+4 設定。
    for (key, cmd) in [
        ("cmd+1", Cmd::ChooseFolder(None)),
        ("cmd+2", Cmd::ToggleTrash),
        ("cmd+3", Cmd::OpenGenerator),
        ("cmd+4", Cmd::OpenSettings),
    ] {
        let core = core.clone();
        let cmd = cmd.clone();
        on_key(key, move |_| core.send(cmd.clone()));
    }
    on_key("escape", {
        let core = core.clone();
        move |_| core.send(Cmd::RequestCloseForm)
    });
    // TOTP 倒數心跳：引擎計時器（非背景任務）。只在詳情有碼時重繪 tick，
    // 視窗過期即重發既有取碼命令，週期沿用 daemon 的 valid_for_secs。
    let totp_core = core.clone();
    set_interval(Duration::from_secs(1), move || {
        if totp_core.totp.get().is_some() {
            let expired = totp_core
                .totp_issued
                .get()
                .is_some_and(|i| i.elapsed().as_secs() >= totp_core.totp_valid_for.get() as u64);
            if expired {
                totp_core.send(Cmd::RequestTotp);
            }
            totp_core.totp_tick.set(totp_core.totp_tick.get() + 1);
        }
    });
    // 批准佇列節拍：照殼批准中心的 1.5s 輪詢（Ready 才拉；事件幫浦另路即時推）。
    let pending_core = core.clone();
    set_interval(Duration::from_millis(1500), move || {
        if matches!(pending_core.phase.get(), Phase::Ready) {
            pending_core.send(Cmd::FetchPending);
        }
    });
    if let Some(dir) = std::env::var_os("NSH_GUI_SHOTS").map(PathBuf::from) {
        if std::env::var_os("NSH_GUI_SHOTS_DRAIN").is_some() {
            shots::script_drain(dir, core.clone());
        } else if std::env::var_os("NSH_GUI_SHOTS_LOGIN").is_some() {
            shots::script_login(dir, core.clone());
        } else if std::env::var_os("NSH_GUI_SHOTS_LOGIN2FA").is_some() {
            shots::script_login2fa(dir, core.clone());
        } else if std::env::var_os("NSH_GUI_SHOTS_CANDID").is_some() {
            shots::script_cand(dir, core.clone());
        } else {
            shots::script(dir, core.clone());
        }
    }

    let conn_cond = core.clone();
    let conn_build = core.clone();
    let fail_cond = core.clone();
    let fail_build = core.clone();
    let ready_cond = core.clone();
    let ready_build = core.clone();
    let modal_cond = core.clone();
    let modal_build = core.clone();
    let pw_modal_cond = core.clone();
    let pw_modal_build = core.clone();
    let import_cond = core.clone();
    let import_build = core.clone();
    view()
        .flex_col()
        .flex_1()
        .relative()
        .bg(theme::BASE)
        .child(topbar(core.clone()))
        .child(banner(core.clone()))
        .child(reauth_banner(core.clone()))
        .child(when(
            move || conn_cond.phase.get() == Phase::Connecting,
            move || centered_hint(conn_build.clone(), "連線中…"),
        ))
        .child(when(
            move || fail_cond.phase.get() == Phase::Failed,
            move || failed_card(fail_build.clone()),
        ))
        .child(when(
            move || ready_cond.phase.get() == Phase::Ready,
            move || router(ready_build.clone()),
        ))
        .child(when(
            move || modal_cond.confirm.get().is_some(),
            move || match modal_build.confirm.get() {
                Some(c) => ui::confirm_modal(modal_build.clone(), &c),
                None => view().flex_1(),
            },
        ))
        .child(when(
            move || pw_modal_cond.pw_modal.get(),
            move || ui::change_password_modal(pw_modal_build.clone()),
        ))
        .child(when(
            move || import_cond.import_modal.get(),
            move || ui::import_modal(import_build.clone()),
        ))
}

/// 頂部列：產品名＋狀態副行（左）、置中搜尋（官方特徵）、右側藍實色新增。
/// 舊標題列的匯出/改密移入左側欄；鎖態指示、提示列收在副行/右側。
fn topbar(core: AppCore) -> View {
    let sub_core = core.clone();
    let busy_cond = core.clone();
    let busy_build = core.clone();
    let notice_cond = core.clone();
    let notice_build = core.clone();
    let new_core = core.clone();
    let add_cond = core.clone();
    let search_cond = core.clone();
    let search_build = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_4()
        .h(px(theme::TOPBAR_H))
        .bg(theme::BASE)
        .border_b(px(1.0))
        .border_color(theme::HAIRLINE)
        .child(
            view()
                .flex_col()
                .flex_1()
                .gap_0p5()
                .child(
                    text("Bitward 密碼庫")
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(
                            text(move || {
                                let n = sub_core.items.get().len();
                                match sub_core.vault.get() {
                                    Some(UnlockStateView::Unlocked { .. }) => {
                                        format!("{n} 筆項目 · 已同步")
                                    }
                                    Some(s) => {
                                        format!("{n} 筆項目 · {}", state::vault_label(&s))
                                    }
                                    None => format!("{n} 筆項目 · 連線中"),
                                }
                            })
                            .text_size(px(theme::TEXT_PAGE_SUB))
                            .text_color(theme::TEXT_SECONDARY),
                        )
                        .child(when(
                            move || busy_build.busy.get() > 0,
                            move || {
                                let _ = busy_cond.clone();
                                text("處理中…")
                                    .text_size(px(12.0))
                                    .text_color(theme::TEXT_MUTED)
                                    .animate_pulse()
                            },
                        )),
                ),
        )
        .child(when(
            move || state::is_unlocked(&search_cond.vault.get()),
            move || list::search(search_build.clone()),
        ))
        .child(
            view()
                .flex_1()
                .flex_row()
                .items_center()
                .justify_end()
                .gap_2()
                .child(when(
                    move || notice_cond.notice.get().is_some(),
                    move || {
                        let c = notice_build.clone();
                        view().max_w(px(260.0)).child(
                            text(move || c.notice.get().unwrap_or_default())
                                .text_size(px(11.5))
                                .line_height(px(16.0))
                                .number_of_lines(2)
                                .text_color(theme::SUCCESS),
                        )
                    },
                ))
                .child(when(
                    move || state::is_unlocked(&add_cond.vault.get()),
                    move || {
                        let n = new_core.clone();
                        ui::button("＋ 新增項目", ui::Btn::PrimaryWide, move || {
                            n.send(Cmd::OpenCreate)
                        })
                    },
                )),
        )
}

/// 左側欄（官方三欄骨架）：我的密碼庫（資料夾樹）／已共享／垃圾桶＋
/// 底部同步狀態與其他動作。資料夾與垃圾桶互斥（`VaultFilter`）。
fn sidebar(core: AppCore) -> View {
    // 驗收不變量：檯面常駐 ≤8（清單單源 `state::sidebar_rail`）。
    debug_assert!(state::sidebar_rail().len() <= 8);
    let all_sel = core.clone();
    let all_press = core.clone();
    let uncat_sel = core.clone();
    let uncat_press = core.clone();
    let tree_data = core.clone();
    let tree_row = core.clone();
    let trash_sel = core.clone();
    let trash_press = core.clone();
    let arch_sel = core.clone();
    let arch_press = core.clone();
    let app_sel = core.clone();
    let app_press = core.clone();
    let app_cnt = core.clone();
    let set_sel = core.clone();
    let set_press = core.clone();
    let gen_sel = core.clone();
    let gen_press = core.clone();
    let rep_sel = core.clone();
    let rep_press = core.clone();
    let send_sel = core.clone();
    let send_press = core.clone();
    let sync_core = core.clone();
    let more_cond = core.clone();
    view()
        .w(px(theme::SIDEBAR_W))
        .flex_col()
        .gap_0p5()
        .bg(theme::SIDEBAR)
        .border_r(px(1.0))
        .border_color(theme::HAIRLINE)
        .px_2()
        .pt_3()
        .child(side_label("我的密碼庫"))
        .child(side_item(
            "全部項目".to_owned(),
            move || {
                let f = all_sel.filter.get();
                !f.trash && f.folder.is_none()
            },
            move || all_press.send(Cmd::ChooseFolder(None)),
            false,
            None,
            || 0,
        ))
        .child(side_item(
            "（未分類）".to_owned(),
            move || {
                let f = uncat_sel.filter.get();
                !f.trash && f.folder.as_deref() == Some("")
            },
            move || uncat_press.send(Cmd::ChooseFolder(Some(String::new()))),
            false,
            None,
            || 0,
        ))
        .child(each(
            move || {
                tree_data
                    .folders
                    .get()
                    .iter()
                    .filter(|f| f.name.is_some())
                    .cloned()
                    .collect::<Vec<_>>()
            },
            |f: &FolderEntry| f.id.clone(),
            move |item: ReadSignal<FolderEntry>, _| {
                let id = item.get().id;
                let sel_core = tree_row.clone();
                let press_core = tree_row.clone();
                let press_id = id.clone();
                let shown = item.get().name.unwrap_or_default();
                side_item(
                    shown,
                    move || {
                        let f = sel_core.filter.get();
                        !f.trash && f.folder.as_deref() == Some(id.as_str())
                    },
                    move || press_core.send(Cmd::ChooseFolder(Some(press_id.clone()))),
                    false,
                    None,
                    || 0,
                )
            },
        ))
        .child(side_item(
            "待批准".to_owned(),
            move || app_sel.route.get() == Route::Approvals,
            move || app_press.send(Cmd::OpenApprovals),
            false,
            None,
            move || app_cnt.pending.get().len(),
        ))
        .child(side_item(
            "垃圾桶".to_owned(),
            move || trash_sel.filter.get().trash,
            move || trash_press.send(Cmd::ToggleTrash),
            false,
            None,
            || 0,
        ))
        .child(side_item(
            "產生密碼".to_owned(),
            move || gen_sel.route.get() == Route::Generator,
            move || gen_press.send(Cmd::OpenGenerator),
            false,
            None,
            || 0,
        ))
        // 批次 11 漸進揭露：低頻節點收進「更多」（本 session 記憶）。
        .child(side_disclosure(core.clone()))
        .child(when(
            move || more_cond.sidebar_more.get(),
            move || {
                let arch_sel = arch_sel.clone();
                let arch_press = arch_press.clone();
                let rep_sel = rep_sel.clone();
                let rep_press = rep_press.clone();
                let send_sel = send_sel.clone();
                let send_press = send_press.clone();
                let set_sel = set_sel.clone();
                let set_press = set_press.clone();
                view()
                    .flex_col()
                    .gap_0p5()
                    .pl_3()
                    .child(side_item(
                        "已封存".to_owned(),
                        move || arch_sel.filter.get().archived,
                        move || arch_press.send(Cmd::ToggleArchived),
                        false,
                        None,
                        || 0,
                    ))
                    .child(side_item(
                        "已共享".to_owned(),
                        || false,
                        || {},
                        true,
                        Some("組織共享：待 daemon 資料源就緒後開放"),
                        || 0,
                    ))
                    .child(side_item(
                        "報告".to_owned(),
                        move || rep_sel.route.get() == Route::Reports,
                        move || rep_press.send(Cmd::OpenReports),
                        false,
                        None,
                        || 0,
                    ))
                    .child(side_item(
                        "Send".to_owned(),
                        move || send_sel.route.get() == Route::Send,
                        move || send_press.send(Cmd::OpenSend),
                        false,
                        None,
                        || 0,
                    ))
                    .child(side_item(
                        "設定".to_owned(),
                        move || set_sel.route.get() == Route::Settings,
                        move || set_press.send(Cmd::OpenSettings),
                        false,
                        None,
                        || 0,
                    ))
            },
        ))
        .child(view().flex_1())
        .child(
            view()
                .flex_col()
                .gap_1()
                .px_1()
                .pb_3()
                .child(account_row(sync_core.clone()))
                .child(side_text_button("立即同步", move || {
                    sync_core.send(Cmd::TriggerSync)
                })),
        )
}

/// 「更多」disclosure 列：▸/▾ 動詞前綴＋翻轉命令（批次 11）。
fn side_disclosure(core: AppCore) -> View {
    let press = core.clone();
    let arrow = core.clone();
    view()
        .h(px(theme::SIDE_ITEM_H))
        .w_full()
        .px_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || press.send(Cmd::ToggleSidebarMore))
        .child(
            text(move || {
                if arrow.sidebar_more.get() {
                    "▾ 更多".to_owned()
                } else {
                    "▸ 更多".to_owned()
                }
            })
            .text_size(px(13.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(theme::TEXT_SECONDARY),
        )
}

/// 側欄分節標籤（不可點）。
fn side_label(label: &'static str) -> View {
    view()
        .px_3()
        .pt_1p5()
        .pb_0p5()
        .child(
            text(label)
                .text_size(px(11.5))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_MUTED),
        )
}

/// 側欄條目：32px 行；選中＝淡藍底＋左 3px 藍條；停用＝灰字＋tooltip；
/// `count` > 0 時右側掛筆數徽章（待批准用，0 不顯示）。
fn side_item(
    label: String,
    selected: impl Fn() -> bool + 'static,
    on_press: impl Fn() + 'static,
    disabled: bool,
    tip: Option<&'static str>,
    count: impl Fn() -> usize + 'static,
) -> View {
    let selected = Rc::new(selected);
    let sel_bg = selected.clone();
    let sel_bar = selected.clone();
    let sel_text = selected;
    let row = view()
        .relative()
        .h(px(theme::SIDE_ITEM_H))
        .px_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .bg(move || {
            if sel_bg() {
                theme::ACCENT.opacity(0.10)
            } else {
                AdaptiveColor::TRANSPARENT
            }
        });
    let row = if disabled {
        row.tooltip(ui::tooltip_card(tip.unwrap_or("即將推出")))
    } else {
        row.on_press(on_press).hover(|s| s.bg(theme::SURFACE_RAISED))
    };
    row.child(
        view()
            .absolute()
            .top_0()
            .bottom_0()
            .left_0()
            .w(px(theme::SIDE_BAR_W))
            .rounded_full()
            .bg(move || {
                if sel_bar() {
                    theme::ACCENT
                } else {
                    AdaptiveColor::TRANSPARENT
                }
            }),
    )
    .child(
        text(label)
            .text_size(px(13.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(move || {
                if sel_text() {
                    theme::TEXT_PRIMARY
                } else if disabled {
                    theme::TEXT_MUTED
                } else {
                    theme::TEXT_SECONDARY
                }
            }),
    )
    .child(view().flex_1())
    .child(dynamic(move || {
        let n = count();
        if n == 0 {
            return view();
        }
        view()
            .h(px(theme::BADGE_H))
            .px_1p5()
            .rounded_full()
            .flex_row()
            .items_center()
            .justify_center()
            .bg(theme::WARNING.opacity(0.16))
            .child(
                text(format!("{n}"))
                    .text_size(px(theme::TEXT_BADGE))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::WARNING),
            )
    }))
}

/// 側欄底部文字鈕（匯出/改密/立即同步）。
fn side_text_button(label: &'static str, on_press: impl Fn() + 'static) -> View {
    view()
        .h(px(theme::SIDE_ITEM_H))
        .w_full()
        .px_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(13.0))
                .text_color(theme::TEXT_SECONDARY),
        )
}

/// 主題三態選擇（官方桌面同款；預設跟隨系統）。
pub(crate) fn theme_picker(core: AppCore) -> View {
    let sys = core.clone();
    let light = core.clone();
    let dark = core.clone();
    view()
        .flex_col()
        .gap_1()
        .px_2()
        .pt_1p5()
        .child(
            text("主題")
                .text_size(px(11.5))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_MUTED),
        )
        .child(
            view()
                .flex_row()
                .gap_1p5()
                .child(theme_chip("跟隨系統", Appearance::System, sys))
                .child(theme_chip("淺色", Appearance::Light, light))
                .child(theme_chip("暗色", Appearance::Dark, dark)),
        )
}

fn theme_chip(label: &'static str, want: Appearance, core: AppCore) -> View {
    let mode = core.theme_mode;
    view()
        .h(px(theme::CHIP_H - 4.0))
        .px_2()
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .border(px(1.0))
        .border_color(move || {
            if mode.get() == want {
                theme::ACCENT
            } else {
                theme::HAIRLINE
            }
        })
        .bg(move || {
            if mode.get() == want {
                theme::ACCENT.opacity(0.12)
            } else {
                theme::BASE
            }
        })
        .active(|s| s.opacity(0.7))
        .on_press(move || core.send(Cmd::SetTheme(want)))
        .child(
            text(label)
                .text_size(px(11.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if mode.get() == want {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_SECONDARY
                    }
                }),
        )
}

/// Ready 後的內容區：登入卡／鎖態整頁取代主從式版面（Route 仍是導航真相）。
fn router(core: AppCore) -> impl IntoElement {
    let login_cond = core.clone();
    let login_build = core.clone();
    let lock_cond = core.clone();
    let lock_build0 = core.clone();
    let split_build0 = core.clone();
    when(
        move || {
            login_cond.show_login.get()
                || matches!(login_cond.vault.get(), Some(UnlockStateView::SignedOut))
        },
        move || login_page(login_build.clone()),
    )
    .otherwise(move || {
        let lock_build = lock_build0.clone();
        let split_build = split_build0.clone();
        when(
            move || !matches!(lock_cond.vault.get(), Some(UnlockStateView::Unlocked { .. })),
            move || lock_page(lock_build.clone()),
        )
        .otherwise(move || split(split_build.clone()))
    })
}

/// 主從式版面（官方三欄骨架）：左側欄｜中列表欄｜右詳情欄。
fn split(core: AppCore) -> View {
    let detail_cond = core.clone();
    let detail_build = core.clone();
    let route_cond = core.clone();
    let approvals_build = core.clone();
    let settings_build = core.clone();
    let reports_build = core.clone();
    let gen_build = core.clone();
    let send_build = core.clone();
    let form_build = core.clone();
    view()
        .flex_row()
        .flex_1()
        .overflow_hidden()
        .child(sidebar(core.clone()))
        .child(
            view()
                .w(px(theme::LIST_W))
                .flex_col()
                .border_r(px(1.0))
                .border_color(theme::HAIRLINE)
                .pb_2()
                .child(list::toolbar(core.clone()))
                .child(list::panel(core.clone())),
        )
        .child(
            view()
                .flex_1()
                .bg(theme::BASE)
                .child(dynamic(move || {
                    match route_cond.route.get() {
                        Route::Approvals => approvals::pane(approvals_build.clone()),
                        Route::Settings => settings::pane(settings_build.clone()),
                        Route::Reports => reports::pane(reports_build.clone()),
                        Route::Generator => genpage::pane(gen_build.clone()),
                        Route::Send => send::pane(send_build.clone()),
                        Route::Create => form::pane(form_build.clone()),
                        Route::Edit(_) | Route::Detail(_) => {
                            if detail_cond.detail.get().is_some() {
                                detail::pane(detail_build.clone())
                            } else {
                                detail::loading()
                            }
                        }
                        _ => detail::placeholder(),
                    }
                })),
        )
}

/// 鎖態頁：置中 lock glyph＋狀態字＋accent 解鎖卡（協定走金鑰鏈，
/// 無密碼輸入框：`Auth:Unlock{biometric:false}` 不帶參數）。
fn lock_page(core: AppCore) -> View {
    let label_core = core.clone();
    let unlock_cond = core.clone();
    let unlock_build = core.clone();
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .child(
            view()
                .w(px(320.0))
                .flex_col()
                .items_center()
                .gap_2()
                .p_6()
                .rounded(px(theme::RADIUS_CARD))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(12.0),
                    blur: px(32.0),
                    spread: px(-8.0),
                    color: black().opacity(0.18).into(),
                    inset: false,
                }])
                .child(
                    text("🔒")
                        .text_size(px(theme::GLYPH_LOCK))
                        .line_height(px(34.0)),
                )
                .child(
                    text(move || {
                        label_core
                            .vault
                            .get()
                            .map(|s| state::vault_label(&s).to_owned())
                            .unwrap_or_else(|| "連線中".to_owned())
                    })
                    .text_size(px(theme::TEXT_CARD_TITLE))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
                )
                .child(when(
                    move || state::can_unlock(&unlock_cond.vault.get()),
                    move || {
                        let c = unlock_build.clone();
                        view().w_full().pt_1().child(
                            ui::button("解鎖", ui::Btn::PrimaryWide, move || {
                                c.send(Cmd::RequestUnlock)
                            })
                            .w_full(),
                        )
                    },
                )),
        )
}

/// 登入卡（批次 8，鎖態卡姊妹款）：SignedOut 主畫面。置中 elevated 卡——
/// 伺服器 URL（預填 status.server）、email、密碼（secure）、`登入` primary；
/// 送 `Auth:Login{password:Some}`（本機 UDS 明文合法，同 CLI 紀律）；
/// 失敗顯示 daemon 錯誤原文＋可懂化；成功→hub 登入即解鎖→StateUpdated 進庫。
fn login_page(core: AppCore) -> View {
    // 預填：server 取 status 上次值（空則留佔位提示）；email 取帳號列值。
    if core.login.server.get().is_empty() && let Some(s) = core.acct_server.get() {
        core.login.server.set(s);
    }
    if core.login.email.get().is_empty() && let Some(e) = core.acct_email.get() {
        core.login.email.set(e);
    }
    let server = core.login.server;
    let email = core.login.email;
    let password = core.login.password;
    let code = core.login.code;
    let submit = core.clone();
    let err_core = core.clone();
    let busy_cond = core.clone();
    // 第一步（三欄）／第二步（因子單選＋碼）以 providers 訊號切換於同卡。
    let step1_core = core.clone();
    let step2_core = core.clone();
    let resend_core = core.clone();
    let factors_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .child(
            view()
                .w(px(380.0))
                .flex_col()
                .gap(px(theme::FORM_GAP))
                .p_6()
                .rounded(px(theme::RADIUS_CARD))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(12.0),
                    blur: px(32.0),
                    spread: px(-8.0),
                    color: black().opacity(0.18).into(),
                    inset: false,
                }])
                .child(
                    view()
                        .flex_col()
                        .items_center()
                        .gap_2()
                        .pb_1()
                        .w_full()
                        .child(
                            text("🔑")
                                .text_size(px(theme::GLYPH_LOCK))
                                .line_height(px(34.0)),
                        )
                        .child(
                            text(move || {
                                if step2_core.login.providers.get().is_some() {
                                    "第二因子驗證"
                                } else {
                                    "登入密碼庫"
                                }
                            })
                            .text_size(px(theme::TEXT_CARD_TITLE))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme::TEXT_PRIMARY),
                        ),
                )
                .child(when(
                    move || step1_core.login.providers.get().is_none(),
                    move || {
                        view()
                            .flex_col()
                            .gap(px(theme::FORM_GAP))
                            .child(ui::form_field(
                                "伺服器",
                                "https://vault.example.com",
                                server,
                                false,
                                move |v| server.set(v),
                            ))
                            .child(ui::form_field(
                                "Email",
                                "you@example.com",
                                email,
                                false,
                                move |v| email.set(v),
                            ))
                            .child(ui::form_field(
                                "主密碼",
                                "（登入後即解鎖金鑰鏈）",
                                password,
                                true,
                                move |v| password.set(v),
                            ))
                    },
                ))
                .child(when(
                    move || step2_core.login.providers.get().is_some(),
                    move || {
                        let list_core = factors_core.clone();
                        let pick_core = factors_core.clone();
                        view()
                            .flex_col()
                            .gap(px(theme::FORM_GAP))
                            .child(
                                text("此帳號需要第二因子驗證，請選擇因子並輸入驗證碼。")
                                    .text_size(px(12.5))
                                    .line_height(px(18.0))
                                    .text_color(theme::TEXT_SECONDARY),
                            )
                            .child(dynamic(move || {
                                let mut col = view().flex_col().gap_0p5();
                                if let Some(infos) = list_core.login.providers.get() {
                                    for p in infos.iter() {
                                        let label = format!(
                                            "{}{}",
                                            bw_proto::TwoFactorProviderInfo::label(p.provider),
                                            match &p.hint {
                                                Some(h) => format!("：{h}"),
                                                None => String::new(),
                                            }
                                        );
                                        let n = p.provider;
                                        let sel = list_core.login.provider.get() == n;
                                        let c = pick_core.clone();
                                        col = col.child(ui::menu_row(label, sel, move || {
                                            c.login.provider.set(n)
                                        }));
                                    }
                                }
                                col
                            }))
                            .child(ui::form_field(
                                "驗證碼",
                                "6 位數字",
                                code,
                                false,
                                move |v| code.set(v),
                            ))
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .cursor_pointer()
                                    .on_press({
                                        let c = factors_core.clone();
                                        move || {
                                            let v = c.login.remember.get();
                                            c.login.remember.set(!v);
                                        }
                                    })
                                    .child(ui::bool_switch(move || {
                                        factors_core.login.remember.get()
                                    }))
                                    .child(
                                        text("記住此裝置（下次登入免第二因子）")
                                            .text_size(px(12.5))
                                            .text_color(theme::TEXT_SECONDARY),
                                    ),
                            )
                    },
                ))
                .child(
                    text(move || err_core.login.error.get().unwrap_or_default())
                        .text_size(px(12.5))
                        .line_height(px(18.0))
                        .text_color(theme::DESTRUCTIVE),
                )
                .child(when(
                    move || !busy_cond.login.busy.get(),
                    move || {
                        let step2 = step2_core.login.providers.get().is_some();
                        let c = submit.clone();
                        let r = resend_core.clone();
                        let mut col = view().flex_col().gap(px(theme::FORM_GAP)).w_full();
                        col = col.child(
                            ui::button(
                                if step2 { "完成登入" } else { "登入" },
                                ui::Btn::PrimaryWide,
                                move || {
                                    c.send(if step2 {
                                        Cmd::SubmitLogin2fa
                                    } else {
                                        Cmd::SubmitLogin
                                    })
                                },
                            )
                            .w_full(),
                        );
                        if step2 {
                            // Email 因子補發：重送第一步（無 two_factor）讓伺服器
                            // 再跑挑戰並重發驗證信；Authenticator 時無害。
                            col = col.child(ui::text_button_dyn(
                                || "重新取得驗證碼".to_owned(),
                                move || r.send(Cmd::SubmitLogin),
                            ));
                        }
                        col
                    },
                ))
                .child(when(
                    move || busy_cond.login.busy.get(),
                    move || {
                        text(move || {
                            if busy_cond.login.providers.get().is_some() {
                                "驗證中…"
                            } else {
                                "登入中…"
                            }
                        })
                        .text_size(px(12.5))
                        .text_color(theme::TEXT_SECONDARY)
                        .animate_pulse()
                    },
                ))
                .child(
                    text("想改用 API key 登入？目前僅支援主密碼（CLI 亦提供 API key）。")
                        .text_size(px(11.0))
                        .line_height(px(15.0))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
}

/// needs_reauth 橫幅：憑證失效時置頂（既有橫條樣式、warning 色）；
/// 點擊主體直接進登入卡。
fn reauth_banner(core: AppCore) -> impl IntoElement {
    let cond = core.clone();
    let build = core.clone();
    when(
        move || cond.needs_reauth.get() && !cond.show_login.get(),
        move || {
            let c = build.clone();
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_6()
                .py_2()
                .cursor_pointer()
                .on_press(move || c.send(Cmd::OpenLogin))
                .bg(theme::WARNING.opacity(0.14))
                .child(
                    text("憑證失效，請重新登入")
                        .text_size(px(12.5))
                        .line_height(px(18.0))
                        .text_color(theme::WARNING)
                        .flex_1(),
                )
        },
    )
}

/// 側欄帳號列：依 `account_row` 映射三態（失效／未登入／已登入）。
/// 前兩者點擊＝主畫面切登入卡；已登入顯示 email（可知時）＋上次同步。
fn account_row(core: AppCore) -> impl IntoElement {
    let press0 = core.clone();
    let reauth0 = core.clone();
    let cond = core.clone();
    let sync0 = core.clone();
    dynamic(move || {
        let press = press0.clone();
        let reauth = reauth0.clone();
        let sync_email = sync0.clone();
        let col = view().flex_col().gap_0p5();
        match state::account_row(
            cond.vault.get().as_ref(),
            cond.needs_reauth.get(),
            cond.acct_email.get().as_deref(),
        ) {
            state::AcctRow::Reauth => col
                .cursor_pointer()
                .on_press(move || reauth.send(Cmd::OpenLogin))
                .child(
                    text("憑證失效，請重新登入")
                        .text_size(px(11.5))
                        .text_color(theme::WARNING),
                )
                .child(sync_line(sync_email.clone())),
            state::AcctRow::SignedOut => col
                .cursor_pointer()
                .on_press(move || press.send(Cmd::OpenLogin))
                .child(
                    text("未登入")
                        .text_size(px(11.5))
                        .text_color(theme::TEXT_SECONDARY),
                ),
            state::AcctRow::Signed(email) => {
                let mut c = col;
                if let Some(e) = email {
                    c = c.child(
                        text(e)
                            .text_size(px(11.5))
                            .text_color(theme::TEXT_SECONDARY)
                            .number_of_lines(1),
                    );
                }
                c.child(sync_line(sync_email.clone()))
            }
        }
    })
}

/// 「上次同步：…」一行（本視窗最近 Sync:Trigger 成功時刻；從未觸發如實說）。
fn sync_line(core: AppCore) -> Text {
    text(move || match core.last_sync.get() {
        Some(at) => {
            let s = at.elapsed().as_secs();
            if s < 60 {
                "上次同步：剛剛".to_owned()
            } else if s < 3600 {
                format!("上次同步：{} 分前", s / 60)
            } else {
                format!("上次同步：{} 小時前", s / 3600)
            }
        }
        None => "上次同步：本視窗尚未觸發".to_owned(),
    })
    .text_size(px(11.5))
    .text_color(theme::TEXT_MUTED)
}

/// 錯誤橫條：協定/傳輸錯誤與匯出失敗；點擊 ✕ 收合。
fn banner(core: AppCore) -> impl IntoElement {
    let cond = core.clone();
    let build = core.clone();
    when(
        move || cond.error_text.get().is_some(),
        move || {
            let c = build.clone();
            let dismiss = build.clone();
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_6()
                .py_2()
                .bg(theme::DESTRUCTIVE.opacity(0.12))
                .child(
                    text(move || c.error_text.get().unwrap_or_default())
                        .text_size(px(12.5))
                        .line_height(px(18.0))
                        .text_color(theme::DESTRUCTIVE)
                        .flex_1(),
                )
                .child(
                    view()
                        .cursor_pointer()
                        .on_press(move || dismiss.error_text.set(None))
                        .child(
                            text("✕")
                                .text_size(px(12.0))
                                .text_color(theme::TEXT_MUTED),
                        ),
                )
        },
    )
}

fn centered_hint(core: AppCore, label: &'static str) -> View {
    let _ = core;
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .child(
            text(label)
                .text_size(px(13.0))
                .text_color(theme::TEXT_MUTED)
                .animate_pulse(),
        )
}

/// daemon 不在：明確錯誤畫面（契約：落 not found 時報錯畫面）。
fn failed_card(core: AppCore) -> View {
    let retry = core.clone();
    let path = core.session.path().display().to_string();
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .child(
            view()
                .w(px(420.0))
                .flex_col()
                .items_center()
                .gap_2()
                .p_6()
                .rounded(px(theme::RADIUS_CARD))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(12.0),
                    blur: px(32.0),
                    spread: px(-8.0),
                    color: black().opacity(0.18).into(),
                    inset: false,
                }])
                .child(
                    text("無法連線 daemon")
                        .text_size(px(theme::TEXT_CARD_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(
                    text(format!("路徑：{path}"))
                        .text_size(px(12.5))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_MUTED),
                )
                .child(
                    text("先啟動 bitwarderd（--data-dir … --sock …），或以 --sock <path>／BITWARD_GUI_SOCK 指向正確位置。")
                        .text_size(px(12.5))
                        .line_height(px(19.0))
                        .text_center()
                        .text_color(theme::TEXT_SECONDARY),
                )
                .child(ui::button("重新連線", ui::Btn::PrimaryWide, move || {
                    retry.send(Cmd::Boot)
                })),
        )
}
