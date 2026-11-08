//! 詳情面板（右欄）：identity 卡＋分節欄位（帳密／一次性密碼）。
//! 密碼預設遮罩，「顯示密碼」才發 Get(Reveal)，明文只存在
//! `core.revealed` 這個詳情層訊號，離開視圖即清（契約驗收 3）。
//! 欄位右側複製鈕寫系統剪貼簿並轉 success 勾 1 秒（純視圖行為）。

use std::rc::Rc;

use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Route};
use crate::theme;
use crate::ui;

/// 顯示值：detail 訊號的派生閉包（欄位列與複製鈕共用同一份）。
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
                .gap_6()
                .px_8()
                .py_6()
                .w_full()
                .max_w(px(680.0))
                .child(section("帳密", accounts_section(core.clone(), copied)))
                .child(
                    section(
                        "一次性密碼（TOTP）",
                        totp_section(core.clone(), copied),
                    ),
                ),
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

fn section(title: &'static str, rows: Vec<View>) -> View {
    let mut rows_box = view()
        .flex_col()
        .overflow_hidden()
        .rounded_xl()
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::SURFACE);
    let count = rows.len();
    for (i, row) in rows.into_iter().enumerate() {
        rows_box = rows_box.child(row);
        if i + 1 < count {
            rows_box = rows_box.child(view().h(px(1.0)).ml_4().mr_4().bg(theme::HAIRLINE));
        }
    }
    view()
        .flex_col()
        .gap_2()
        .child(ui::section_title(title))
        .child(rows_box)
}

/// 頂部 identity 卡：大 monogram＋名稱＋網址連結＋編輯/刪除。
fn identity_header(core: AppCore) -> View {
    let name_core = core.clone();
    let uri_core = core.clone();
    let uri_open = core.clone();
    let edit_core = core.clone();
    let del_core = core.clone();
    let close_core = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_4()
        .px_8()
        .py_5()
        .child(ui::monogram(
            move || name_core.detail.get().and_then(|d| d.meta.name.clone()),
            64.0,
            16.0,
            24.0,
        ))
        .child(
            view()
                .flex_col()
                .flex_1()
                .gap_0p5()
                .child(
                    text(move || {
                        uri_core
                            .detail
                            .get()
                            .and_then(|d| d.meta.name.clone())
                            .unwrap_or_else(|| "(未命名)".to_owned())
                    })
                    .text_size(px(22.0))
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
        .child(ui::button("編輯", ui::Btn::PrimaryCapsule, move || {
            if let Route::Detail(id) = edit_core.route.get() {
                edit_core.send(Cmd::OpenEdit(id));
            }
        }))
        .child(ui::button("刪除", ui::Btn::Ghost, move || {
            if let Route::Detail(id) = del_core.route.get() {
                del_core.send(Cmd::AskDelete(id));
            }
        }))
        .child(
            view()
                .w(px(26.0))
                .h(px(26.0))
                .rounded_md()
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

/// 帳密節：類型/帳號/密碼/網址/標籤/更新時間／同步狀態/識別碼。
fn accounts_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let kind = detail_disp(&core, |d| ui::kind_label(d.meta.kind).to_owned());
    let username = detail_disp(&core, |d| d.username.clone().unwrap_or_else(|| "—".into()));
    let uris = detail_disp(&core, |d| {
        if d.meta.uris.is_empty() {
            "—".into()
        } else {
            d.meta.uris.join("\n")
        }
    });
    let tags = detail_disp(&core, |d| {
        if d.meta.tags.is_empty() {
            "—".into()
        } else {
            d.meta.tags.join(" · ")
        }
    });
    let updated = detail_disp(&core, |d| {
        match (d.meta.updated_at.as_deref(), d.meta.pending) {
            (Some(t), true) => format!("{t} · 待推送"),
            (Some(t), false) => t.to_owned(),
            (None, true) => "尚未推送（outbox 待推）".to_owned(),
            (None, false) => "—".to_owned(),
        }
    });
    let id_disp = detail_disp(&core, |d| d.meta.id.to_string());
    vec![
        field("類型", kind, Vec::new()),
        field("帳號", username.clone(), vec![ui::copy_button(username, "帳號", copied)]),
        password_field(core.clone(), copied),
        field("網址", uris.clone(), vec![ui::copy_button(uris, "網址", copied)]),
        field("標籤", tags, Vec::new()),
        field("更新時間／同步狀態", updated, Vec::new()),
        field(
            "識別碼",
            id_disp.clone(),
            vec![ui::copy_button(id_disp, "識別碼", copied)],
        ),
    ]
}

/// 密碼列：預設遮罩（Masked 投影的 `password_masked`，無則純點號）；
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
        .px_4()
        .py_3()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .child(label("密碼"))
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
                            .text_size(px(15.0))
                            .line_height(px(21.0))
                            .font_family(ui::mono_font())
                            .text_color(theme::TEXT_PRIMARY)
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
                        .text_size(px(15.0))
                        .line_height(px(21.0))
                        .text_color(theme::TEXT_PRIMARY)
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
        )
}

fn label(text_label: &'static str) -> Text {
    text(text_label)
        .text_size(px(12.0))
        .font_weight(FontWeight::MEDIUM)
        .letter_spacing(px(0.3))
        .text_color(theme::TEXT_SECONDARY)
}

/// 欄位列：label(12 secondary)／value(15 primary) 兩行＋右側按鈕群。
fn field(label_text: &'static str, value: Disp, trailing: Vec<View>) -> View {
    let v1 = value.clone();
    let mut actions = view().flex_row().items_center().gap_1();
    for t in trailing {
        actions = actions.child(t);
    }
    view()
        .px_4()
        .py_3()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .child(label(label_text))
                .child(
                    text(move || v1())
                        .text_size(px(15.0))
                        .line_height(px(21.0))
                        .text_color(theme::TEXT_PRIMARY)
                        .number_of_lines(2),
                ),
        )
        .child(actions)
}

/// TOTP 節：代碼列（取碼鈕＋複製）；有無 seed 由 daemon 裁決
/// （Masked 投影不含 totp 存在性，hub.rs project_one 恆 false）。
fn totp_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let hint_core = core.clone();
    let shown_core = core.clone();
    let btn_core = core.clone();
    let copy_core = core.clone();
    vec![field_dyn(
        "一次性密碼",
        move || {
            hint_core.totp.get().unwrap_or_else(|| {
                "（按右側「一次性密碼」向 daemon 取現算代碼）".to_owned()
            })
        },
        move || {
            let btn = btn_core.clone();
            let shown = shown_core.clone();
            let copy = copy_core.clone();
            let mut actions = view().flex_row().items_center().gap_1();
            actions = actions.child(ui::text_button_dyn(
                || "一次性密碼".to_owned(),
                move || btn.send(Cmd::RequestTotp),
            ));
            actions = actions.child(when(
                move || shown.totp.get().is_some(),
                move || {
                    ui::copy_button(
                        Rc::new(move || {
                            let raw = copy.totp.get().unwrap_or_default();
                            raw.split('（').next().unwrap_or(&raw).to_owned()
                        }),
                        "TOTP",
                        copied,
                    )
                },
            ));
            actions
        },
    )]
}

/// 欄位列（trailing 鈕群由閉包現算：跟著的訊號變動重建）。
fn field_dyn(
    label_text: &'static str,
    value: impl Fn() -> String + 'static,
    trailing: impl Fn() -> View + 'static,
) -> View {
    view()
        .px_4()
        .py_3()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .child(label(label_text))
                .child(
                    text(value)
                        .text_size(px(15.0))
                        .line_height(px(21.0))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_PRIMARY),
                ),
        )
        .child(dynamic(trailing))
}
