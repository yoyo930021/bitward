//! 詳情面板（右欄）：官方「編輯項目」表單感——頂部大名稱＋型別圖示，
//! 欄位為淺灰圓角值塊（label 12 粗灰在上、值在塊內 14），複製鈕在塊右側。
//! 分節與官方同序：帳密 → 驗證碼 → 備註 → 自訂欄位 → 資訊。
//! 密碼預設遮罩，「顯示密碼」才發 Get(Reveal)，明文只存在
//! `core.revealed` 這個詳情層訊號，離開視圖即清（契約驗收 3）。
//! 垃圾桶條目（`meta.deleted_at` 有值）動作群改「還原／永久刪除」；
//! TOTP 有碼時行內附倒數細进度條（App 1s 心跳驅動，≤5 秒轉 warning）。

use std::rc::Rc;

use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Route};
use crate::theme;
use crate::ui;

/// 顯示值：detail 訊號的派生閉包（欄位塊與複製鈕共用同一份）。
type Disp = Rc<dyn Fn() -> String>;

pub fn pane(core: AppCore) -> View {
    let copied = signal::<Option<&'static str>>(None);
    view()
        .flex_col()
        .flex_1()
        .child(identity_header(core.clone()))
        .child(view().h(px(1.0)).mx_8().bg(theme::HAIRLINE))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_5()
                .px_8()
                .py_4()
                .w_full()
                .max_w(px(680.0))
                .child(section("帳密", credentials_section(core.clone(), copied)))
                .child(section("驗證碼", totp_section(core.clone(), copied)))
                .child(section("備註", notes_section(core.clone(), copied)))
                .child(section("自訂欄位", custom_fields_section(core.clone(), copied)))
                .child(section("資訊", info_section(core.clone(), copied))),
        ))
}

/// 詳情載入中（右欄尚未收到 Get 回包）。
pub fn loading() -> View {
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .child(
            text("載入中…")
                .text_size(px(13.0))
                .text_color(theme::TEXT_MUTED)
                .animate_pulse(),
        )
}

/// 右欄未選取時的佔位：淡型別磚圖示＋置中大字＋次要說明。
pub fn placeholder() -> View {
    view()
        .flex_1()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_2()
        .child(
            view()
                .w(px(theme::TILE_ID))
                .h(px(theme::TILE_ID))
                .rounded(px(theme::RADIUS_BLOCK))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .flex_row()
                .items_center()
                .justify_center()
                .child(text("🔑\u{fe0e}").text_size(px(theme::GLYPH_KEY)).text_color(theme::TEXT_SECONDARY)),
        )
        .child(
            text("選取一個項目")
                .text_size(px(17.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_MUTED),
        )
        .child(
            text("或按＋新增項目建立新項目")
                .text_size(px(theme::TEXT_PAGE_SUB))
                .text_color(theme::TEXT_MUTED),
        )
}

/// 分節：粗灰小標題＋值塊列（無外框，官方詳情語感）。
fn section(title: &'static str, rows: Vec<View>) -> View {
    let mut body = view().flex_col().gap_2();
    for row in rows {
        body = body.child(row);
    }
    view()
        .flex_col()
        .gap_2()
        .child(ui::section_title(title))
        .child(body)
}

/// 頂部 identity：大 monogram 退役，改型別磚＋大名稱＋網址連結＋動作群。
fn identity_header(core: AppCore) -> View {
    let name_core = core.clone();
    let uri_core = core.clone();
    let uri_open = core.clone();
    let actions_core = core.clone();
    let close_core = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_8()
        .py_4()
        .child(ui::type_tile(
            move || {
                name_core
                    .detail
                    .get()
                    .map(|d| d.meta.kind)
                    .unwrap_or_default()
            },
            theme::TILE_ID,
            theme::TILE_ID_GLYPH,
        ))
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .overflow_hidden()
                .child(
                    text(move || {
                        uri_core
                            .detail
                            .get()
                            .and_then(|d| d.meta.name.clone())
                            .unwrap_or_else(|| "(未命名)".to_owned())
                    })
                    .text_size(px(theme::TEXT_IDENTITY))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY)
                    .number_of_lines(1),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_1p5()
                        .cursor_pointer()
                        .on_press(move || {
                            if let Some(uri) =
                                uri_open.detail.get().and_then(|d| d.meta.uris.first().cloned())
                            {
                                drop(open_url(uri));
                            }
                        })
                        .child(
                            text(move || {
                                uri_core
                                    .detail
                                    .get()
                                    .and_then(|d| d.meta.uris.first().cloned())
                                    .unwrap_or_else(|| "—".to_owned())
                            })
                            .text_size(px(13.0))
                            .text_color(theme::ACCENT)
                            .number_of_lines(1),
                        ),
                ),
        )
        .child(dynamic(move || {
            let trashed = actions_core
                .detail
                .get()
                .is_some_and(|d| d.meta.deleted_at.is_some());
            let edit = actions_core.clone();
            let del = actions_core.clone();
            if trashed {
                let restore = actions_core.clone();
                let purge = actions_core.clone();
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(ui::button("還原", ui::Btn::Ghost, move || {
                        if let Route::Detail(id) = restore.route.get() {
                            restore.send(Cmd::RestoreItem(id));
                        }
                    }))
                    .child(ui::button("永久刪除", ui::Btn::Destructive, move || {
                        if let Route::Detail(id) = purge.route.get() {
                            purge.send(Cmd::AskPurge(id));
                        }
                    }))
            } else {
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(ui::button("編輯", ui::Btn::Ghost, move || {
                        if let Route::Detail(id) = edit.route.get() {
                            edit.send(Cmd::OpenEdit(id));
                        }
                    }))
                    .child(ui::button("刪除", ui::Btn::Ghost, move || {
                        if let Route::Detail(id) = del.route.get() {
                            del.send(Cmd::AskDelete(id));
                        }
                    }))
            }
        }))
        .child(
            view()
                .w(px(26.0))
                .h(px(26.0))
                .rounded(px(theme::RADIUS_CONTROL))
                .flex_row()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .hover(|s| s.bg(theme::SURFACE_RAISED))
                .on_press(move || close_core.send(Cmd::OpenList))
                .child(
                    text("✕")
                        .text_size(px(12.0))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
}

/// 通用：從 detail 訊號取一個顯示閉包。
fn detail_disp(core: &AppCore, f: impl Fn(&bw_proto::ItemView) -> String + 'static) -> Disp {
    let c = core.clone();
    Rc::new(move || c.detail.get().map(|d| f(&d)).unwrap_or_default())
}

/// 帳密節（官方 Login credentials＋Autofill options 合併）：帳號/密碼/網址/標籤。
fn credentials_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let username = detail_disp(&core, |d| d.username.clone().unwrap_or_else(|| "—".into()));
    let uris = detail_disp(&core, |d| {
        if d.meta.uris.is_empty() {
            "—".into()
        } else {
            d.meta.uris.join(" · ")
        }
    });
    let tags = detail_disp(&core, |d| {
        if d.meta.tags.is_empty() {
            "—".into()
        } else {
            d.meta.tags.join(" · ")
        }
    });
    vec![
        field("帳號", username.clone(), vec![ui::copy_button(username, "帳號", copied)]),
        password_field(core.clone(), copied),
        field("網址", uris.clone(), vec![ui::copy_button(uris, "網址", copied)]),
        field("標籤", tags, Vec::new()),
    ]
}

/// 資訊節：類型/更新時間／同步狀態/識別碼（官方 Item history 对应物）。
fn info_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let kind = detail_disp(&core, |d| ui::kind_label(d.meta.kind).to_owned());
    let updated = detail_disp(&core, |d| {
        match (d.meta.updated_at.as_deref(), d.meta.pending) {
            (Some(t), true) => format!("{t} · 未同步"),
            (Some(t), false) => t.to_owned(),
            (None, true) => "尚未推送（outbox 待推）".to_owned(),
            (None, false) => "—".to_owned(),
        }
    });
    let id_disp = detail_disp(&core, |d| d.meta.id.to_string());
    vec![
        field("類型", kind, Vec::new()),
        field("更新時間／同步狀態", updated, Vec::new()),
        field(
            "識別碼",
            id_disp.clone(),
            vec![ui::copy_button(id_disp, "識別碼", copied)],
        ),
    ]
}

/// 備註節：notes 明文（Masked 視窗即帶全文；Metadata 下鍵不存在）。
fn notes_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let notes = detail_disp(&core, |d| d.notes.clone().unwrap_or_else(|| "—".into()));
    let copy = notes.clone();
    vec![block(
        move || notes(),
        true,
        vec![ui::copy_button(copy, "備註", copied)],
    )]
}

/// 自訂欄位節：pane 每次 detail 重建時快照（Reveal 不改欄集）。
fn custom_fields_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let Some(d) = core.detail.get() else {
        return Vec::new();
    };
    if d.fields.is_empty() {
        return vec![block(
            || "（無自訂欄位）".to_owned(),
            false,
            Vec::new(),
        )];
    }
    d.fields
        .iter()
        .map(|f| {
            let shown = f
                .value
                .clone()
                .unwrap_or_else(|| "••••••••".to_owned());
            let mut trailing = Vec::new();
            if !f.hidden {
                let v = f.value.clone().unwrap_or_default();
                trailing.push(ui::copy_button(
                    Rc::new(move || v.clone()),
                    "自訂欄位",
                    copied,
                ));
            }
            field_static(f.name.clone(), shown, trailing)
        })
        .collect()
}

/// 密碼欄：預設遮罩（Masked 投影的 `password_masked`，無則純點號）；
/// revealed 時改 mono 字體、附複製鈕。toggle 走既有 RequestReveal 語意。
fn password_field(core: AppCore, copied: Signal<Option<&'static str>>) -> View {
    let mask_core = core.clone();
    let reveal_core = core.clone();
    let shown_cond = core.clone();
    let shown_build = core.clone();
    let copy_cond = core.clone();
    let copy_build = core.clone();
    let toggle = core.clone();
    view()
        .flex_col()
        .gap_1()
        .child(label("密碼"))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .flex_1()
                        .px_3()
                        .py_2()
                        .rounded(px(theme::RADIUS_BLOCK))
                        .bg(theme::SURFACE)
                        .child(
                            when(
                                move || shown_cond.revealed.get().is_some(),
                                move || {
                                    let c = shown_build.clone();
                                    text(move || match c.revealed.get() {
                                        Some(pw) if pw.is_empty() => "（此項目沒有密碼）".to_owned(),
                                        Some(pw) => pw,
                                        None => String::new(),
                                    })
                                    .text_size(px(theme::TEXT_FIELD_VALUE))
                                    .font_family(ui::mono_font())
                                    .text_color(theme::TEXT_PRIMARY)
                                    .number_of_lines(1)
                                                                    },
                            )
                            .otherwise(move || {
                                let c = mask_core.clone();
                                text(move || {
                                    c.detail
                                        .get()
                                        .and_then(|d| d.password_masked.clone())
                                        .unwrap_or_else(|| "••••••••".to_owned())
                                })
                                .text_size(px(theme::TEXT_FIELD_VALUE))
                                .text_color(theme::TEXT_PRIMARY)
                                .number_of_lines(1)
                                                            }),
                        ),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_1()
                        .child(ui::text_button_dyn(
                            move || {
                                if reveal_core.revealed.get().is_some() {
                                    "隱藏密碼".to_owned()
                                } else {
                                    "顯示密碼".to_owned()
                                }
                            },
                            move || toggle.send(Cmd::RequestReveal),
                        ))
                        .child(when(
                            move || copy_cond.revealed.get().is_some(),
                            move || {
                                let c = copy_build.clone();
                                ui::copy_button(
                                    Rc::new(move || c.revealed.get().unwrap_or_default()),
                                    "密碼",
                                    copied,
                                )
                                                            },
                        )),
                ),
        )
}

fn label(text_label: &'static str) -> Text {
    text(text_label)
        .text_size(px(theme::TEXT_FIELD_LABEL))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(theme::TEXT_SECONDARY)
}

/// 值塊（無欄位名）：單欄分節（驗證碼/備註）由節標題承擔命名，不重複標。
fn block(value: impl Fn() -> String + 'static, multiline: bool, trailing: Vec<View>) -> View {
    let mut actions = view().flex_row().items_center().gap_1();
    for t in trailing {
        actions = actions.child(t);
    }
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            view()
                .flex_1()
                .px_3()
                .py_2()
                .rounded(px(theme::RADIUS_BLOCK))
                .bg(theme::SURFACE)
                .child(
                    text(value)
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .text_color(theme::TEXT_PRIMARY)
                        .number_of_lines(if multiline { 4 } else { 1 }),
                ),
        )
        .child(actions)
}

/// 值塊（trailing 鈕群由閉包現算：跟著訊號變動重建）。
fn block_dyn(
    value: impl Fn() -> String + 'static,
    multiline: bool,
    trailing: impl Fn() -> View + 'static,
) -> View {
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            view()
                .flex_1()
                .px_3()
                .py_2()
                .rounded(px(theme::RADIUS_BLOCK))
                .bg(theme::SURFACE)
                .child(
                    text(value)
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .text_color(theme::TEXT_PRIMARY)
                        .number_of_lines(if multiline { 4 } else { 1 }),
                ),
        )
        .child(dynamic(trailing))
}

fn label_str(text_label: String) -> Text {
    text(move || text_label.clone())
        .text_size(px(theme::TEXT_FIELD_LABEL))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(theme::TEXT_SECONDARY)
}

/// 欄位值塊：label 12 粗灰在上、value 14 在淺灰圓角塊內、按鈕群靠塊右側。
fn field(label_text: &'static str, value: Disp, trailing: Vec<View>) -> View {
    let v1 = value.clone();
    let mut actions = view().flex_row().items_center().gap_1();
    for t in trailing {
        actions = actions.child(t);
    }
    view()
        .flex_col()
        .gap_1()
        .child(label(label_text))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .flex_1()
                        .px_3()
                        .py_2()
                        .rounded(px(theme::RADIUS_BLOCK))
                        .bg(theme::SURFACE)
                        .child(
                            text(move || v1())
                                .text_size(px(theme::TEXT_FIELD_VALUE))
                                .text_color(theme::TEXT_PRIMARY)
                                .number_of_lines(1),
                        ),
                )
                .child(actions),
        )
}

/// 欄位值塊（build 時快照值；自訂欄位用，欄名是動態字串）。
fn field_static(label_text: String, value: String, trailing: Vec<View>) -> View {
    let mut actions = view().flex_row().items_center().gap_1();
    for t in trailing {
        actions = actions.child(t);
    }
    view()
        .flex_col()
        .gap_1()
        .child(label_str(label_text))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .flex_1()
                        .px_3()
                        .py_2()
                        .rounded(px(theme::RADIUS_BLOCK))
                        .bg(theme::SURFACE)
                        .child(
                            text(value)
                                .text_size(px(theme::TEXT_FIELD_VALUE))
                                .text_color(theme::TEXT_PRIMARY)
                                .number_of_lines(1),
                        ),
                )
                .child(actions),
        )
}

/// TOTP 節：代碼塊（取碼鈕＋倒數＋複製）；有無 seed 由 daemon 裁決
/// （Masked 投影的 totp_available 恆 false，不可用作開關）。
fn totp_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let hint_core = core.clone();
    let shown_core = core.clone();
    let btn_core = core.clone();
    let copy_core = core.clone();
    vec![block_dyn(
        move || {
            hint_core.totp.get().unwrap_or_else(|| {
                "（按右側「驗證碼」向 daemon 取現算代碼）".to_owned()
            })
        },
        false,
        move || {
            let btn = btn_core.clone();
            let shown = shown_core.clone();
            let copy = copy_core.clone();
            let bar_build = shown.clone();
            let mut actions = view().flex_row().items_center().gap_1p5();
            actions = actions.child(when(
                move || shown.totp.get().is_some(),
                move || countdown(bar_build.clone()),
            ));
            actions = actions.child(ui::text_button_dyn(
                || "驗證碼".to_owned(),
                move || btn.send(Cmd::RequestTotp),
            ));
            actions = actions.child(when(
                move || shown.totp.get().is_some(),
                move || {
                    ui::copy_button(
                        Rc::new(move || copy.totp.get().unwrap_or_default()),
                        "TOTP",
                        copied,
                    )
                },
            ));
            actions
        },
    )]
}

/// TOTP 視窗週期秒數（與 daemon `hub::totp` 的 `30 - now % 30` 同值）。
pub const TOTP_PERIOD_SECS: u32 = 30;
/// 剩餘低於此秒數轉 warning 色。
pub const TOTP_WARN_SECS: u32 = 5;

/// 剩餘秒數：取碼時的 valid_for_secs 減去經過秒數（純函數，可單測）。
pub fn totp_remaining(valid_for_secs: u32, elapsed_secs: u64) -> u32 {
    valid_for_secs.saturating_sub(elapsed_secs as u32)
}

/// 目前剩餘秒數；讀 `totp_tick`（App 1s 心跳）建立重繪依賴。
fn countdown_remaining(core: &AppCore) -> u32 {
    let _ = core.totp_tick.get();
    match (core.totp_issued.get(), core.totp_valid_for.get()) {
        (Some(issued), valid) => totp_remaining(valid, issued.elapsed().as_secs()),
        _ => 0,
    }
}

/// 倒數條：accent 實色細軌＋「剩餘 N 秒」12px；≤5 秒轉 warning 色。
fn countdown(core: AppCore) -> View {
    let w_core = core.clone();
    let c_core = core.clone();
    let t_core = core.clone();
    let n_core = core;
    view()
        .flex_row()
        .items_center()
        .gap_1p5()
        .child(
            view()
                .w(px(theme::TOTP_BAR_W))
                .h(px(theme::TOTP_BAR_H))
                .rounded_full()
                .bg(theme::SURFACE_RAISED)
                .child(
                    view()
                        .h_full()
                        .rounded_full()
                        .w(move || {
                            let left = countdown_remaining(&w_core) as f32
                                / TOTP_PERIOD_SECS as f32;
                            px(theme::TOTP_BAR_W * left)
                        })
                        .bg(move || {
                            if countdown_remaining(&c_core) <= TOTP_WARN_SECS {
                                theme::WARNING
                            } else {
                                theme::ACCENT
                            }
                        }),
                ),
        )
        .child(
            text(move || format!("剩餘 {} 秒", countdown_remaining(&t_core)))
                .text_size(px(theme::TEXT_PAGE_SUB))
                .text_color(move || {
                    if countdown_remaining(&n_core) <= TOTP_WARN_SECS {
                        theme::WARNING
                    } else {
                        theme::TEXT_MUTED
                    }
                }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_remaining_counts_down_and_floors_at_zero() {
        assert_eq!(totp_remaining(30, 0), 30);
        assert_eq!(totp_remaining(30, 20), 10);
        assert_eq!(totp_remaining(12, 7), 5);
        assert_eq!(totp_remaining(12, 12), 0);
        assert_eq!(totp_remaining(12, 99), 0);
    }

    #[test]
    fn warn_threshold_is_five_seconds() {
        assert_eq!(TOTP_WARN_SECS, 5);
        assert_eq!(TOTP_PERIOD_SECS, 30);
    }
}
