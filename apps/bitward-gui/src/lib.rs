//! Bitward vault GUI（NSH，契約 §0.2）：macOS 密碼管理主體。
//!
//! 架構：所有狀態收在 `state::AppCore`（訊號 + 命令佇列）；UI handler 只
//! 投遞 `Cmd`，`set_interval` 幫浦在引擎執行緒上 `reduce`；需要 daemon 的
//! 動作派到 worker 執行緒（`btp::Session` 同步 UDS client），worker 只準
//! 回傳 `Cmd`、不碰訊號。分級、過濾、排序語意全在 daemon（零業務邏輯在
//! GUI）；導航是 `Route` 狀態機＋主從式版面（列表常駐左欄、詳情走右欄、
//! 新增/編輯與確認走模態；nav_stack 在 macOS dev host 不渲染，spike
//! FINDINGS 卡點 4）。外觀代幣全在 `theme`。

mod btp;
mod detail;
mod export;
mod form;
mod list;
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
use state::{AppCore, Cmd, Phase, Route};

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
    on_key("escape", {
        let core = core.clone();
        move |_| core.send(Cmd::OpenList)
    });
    if let Some(dir) = std::env::var_os("NSH_GUI_SHOTS").map(PathBuf::from) {
        shots::script(dir, core.clone());
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
    let form_cond = core.clone();
    let form_build = core.clone();
    view()
        .flex_col()
        .flex_1()
        .relative()
        .bg(theme::BASE)
        .child(header(core.clone()))
        .child(banner(core.clone()))
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
            move || matches!(form_cond.route.get(), Route::Create | Route::Edit(_)),
            move || form::overlay(form_build.clone()),
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
}

/// 大標題列：產品名＋「N 筆項目 · 狀態」副行＋右側動作群。
/// 舊標題列的鎖態指示、匯出提示收進這裡（副行跟 vault_label 走）。
fn header(core: AppCore) -> View {
    let sub_core = core.clone();
    let busy_cond = core.clone();
    let busy_build = core.clone();
    let notice_cond = core.clone();
    let notice_build = core.clone();
    let export_core = core.clone();
    let new_core = core.clone();
    let pw_cond = core.clone();
    let pw_build = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_6()
        .pt(px(theme::HEADER_PT))
        .pb(px(theme::HEADER_PB))
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .child(
                    text("密碼庫")
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .letter_spacing(px(0.5))
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
        .child(view().flex_1())
        .child(when(
            move || notice_cond.notice.get().is_some(),
            move || {
                let c = notice_build.clone();
                view().max_w(px(360.0)).child(
                    text(move || c.notice.get().unwrap_or_default())
                        .text_size(px(11.5))
                        .line_height(px(16.0))
                        .number_of_lines(2)
                        .text_color(theme::SUCCESS),
                )
            },
        ))
        .child(ui::button("匯出", ui::Btn::Ghost, move || {
            export_core.send(Cmd::AskExport)
        }))
        .child(when(
            move || state::can_change_password(&pw_cond.vault.get()),
            move || {
                let c = pw_build.clone();
                ui::button("變更主密碼", ui::Btn::Ghost, move || {
                    c.send(Cmd::OpenChangePassword)
                })
            },
        ))
        .child(ui::button("＋ 新增", ui::Btn::PrimaryCapsule, move || {
            new_core.send(Cmd::OpenCreate)
        }))
}

/// Ready 後的內容區：鎖態整頁取代主從式版面（Route 仍是導航真相）。
fn router(core: AppCore) -> impl IntoElement {
    let lock_cond = core.clone();
    let lock_build = core.clone();
    let split_build = core.clone();
    when(
        move || !matches!(lock_cond.vault.get(), Some(UnlockStateView::Unlocked { .. })),
        move || lock_page(lock_build.clone()),
    )
    .otherwise(move || split(split_build.clone()))
}

/// 主從式版面：全寬工具列＋（左列表欄｜右詳情欄）。
fn split(core: AppCore) -> View {
    let detail_cond = core.clone();
    let detail_build = core.clone();
    let loading_cond = core.clone();
    view()
        .flex_col()
        .flex_1()
        .overflow_hidden()
        .child(list::toolbar(core.clone()))
        .child(
            view()
                .flex_row()
                .flex_1()
                .overflow_hidden()
                .child(
                    view()
                        .w(px(400.0))
                        .flex_col()
                        .border_r(px(1.0))
                        .border_color(theme::HAIRLINE)
                        .pt_2()
                        .child(list::panel(core.clone())),
                )
                .child(
                    view()
                        .flex_1()
                        .child(when(
                            move || detail_cond.detail.get().is_some(),
                            move || detail::pane(detail_build.clone()),
                        ).otherwise(move || {
                            if matches!(loading_cond.route.get(), Route::Detail(_)) {
                                detail::loading()
                            } else {
                                detail::placeholder()
                            }
                        })),
                ),
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
                .w(px(360.0))
                .flex_col()
                .items_center()
                .gap_3()
                .p_8()
                .rounded_2xl()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(18.0),
                    blur: px(48.0),
                    spread: px(-10.0),
                    color: black().opacity(0.55).into(),
                    inset: false,
                }])
                .child(
                    text("🔒")
                        .text_size(px(36.0))
                        .line_height(px(44.0)),
                )
                .child(
                    text(move || {
                        label_core
                            .vault
                            .get()
                            .map(|s| state::vault_label(&s).to_owned())
                            .unwrap_or_else(|| "連線中".to_owned())
                    })
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
                )
                .child(when(
                    move || state::can_unlock(&unlock_cond.vault.get()),
                    move || {
                        let c = unlock_build.clone();
                        view().w_full().pt_1().child(
                            ui::button("解鎖", ui::Btn::PrimaryCapsule, move || {
                                c.send(Cmd::RequestUnlock)
                            })
                            .w_full(),
                        )
                    },
                )),
        )
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
                .w(px(460.0))
                .flex_col()
                .items_center()
                .gap_3()
                .p_6()
                .rounded_2xl()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(18.0),
                    blur: px(48.0),
                    spread: px(-10.0),
                    color: black().opacity(0.55).into(),
                    inset: false,
                }])
                .child(
                    text("無法連線 daemon")
                        .text_size(px(17.0))
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
                .child(ui::button("重新連線", ui::Btn::PrimaryCapsule, move || {
                    retry.send(Cmd::Boot)
                })),
        )
}
