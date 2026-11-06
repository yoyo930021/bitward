//! 詳情頁：metadata 全欄位；密碼預設遮罩，「顯示」才發 Get(Reveal)，
//! 明文只存在 `core.revealed` 這個詳情層訊號，離開視圖即清（契約驗收 3）。

use bw_proto::{ItemId, ItemView};
use nsh_base::theme;
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Route};
use crate::ui;

pub fn page(core: AppCore, id: ItemId) -> View {
    let back_core = core.clone();
    let title_core = core.clone();
    let loading_cond = core.clone();
    let body_cond = core.clone();
    let body_build = core.clone();
    let _ = id; // 資料載入由 reduce 保證；這裡只渲染 detail 訊號。
    view()
        .flex_col()
        .flex_1()
        .child(ui::page_header("項目詳情".to_owned(), move || {
            back_core.send(Cmd::OpenList)
        }))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_6()
                .py_3()
                .child(
                    text(move || {
                        title_core
                            .detail
                            .get()
                            .and_then(|d| d.meta.name.clone())
                            .unwrap_or_else(|| "載入中…".to_owned())
                    })
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(move || theme().foreground),
                )
                .child(action_row(core.clone())),
        )
        .child(when(
            move || loading_cond.detail.get().is_none(),
            move || {
                view().flex_1().child(
                    text("載入中…")
                        .text_size(px(13.0))
                        .text_color(move || theme().muted_foreground)
                        .px_6()
                        .py_5(),
                )
            },
        ))
        .child(when(
            move || body_cond.detail.get().is_some(),
            move || body(body_build.clone()),
        ))
}

fn action_row(core: AppCore) -> View {
    let reveal_label = core.clone();
    let reveal_press = core.clone();
    let totp_core = core.clone();
    let edit_core = core.clone();
    let del_core = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(ui::button_dyn(
            move || {
                if reveal_label.revealed.get().is_some() {
                    "隱藏密碼".to_owned()
                } else {
                    "顯示密碼".to_owned()
                }
            },
            ui::Btn::Muted,
            move || reveal_press.send(Cmd::RequestReveal),
        ))
        .child(ui::button("一次性密碼", ui::Btn::Muted, move || {
            totp_core.send(Cmd::RequestTotp)
        }))
        .child(ui::button("編輯", ui::Btn::Primary, move || {
            if let Route::Detail(id) = edit_core.route.get() {
                edit_core.send(Cmd::OpenEdit(id));
            }
        }))
        .child(ui::button("刪除", ui::Btn::Destructive, move || {
            if let Route::Detail(id) = del_core.route.get() {
                del_core.send(Cmd::AskDelete(id));
            }
        }))
}

fn body(core: AppCore) -> View {
    view().flex_1().child(
        scroll().flex_1().child(
            view()
                .flex_col()
                .gap_4()
                .px_6()
                .py_5()
                .max_w(px(560.0))
                .child(type_row(core.clone()))
                .child(username_row(core.clone()))
                .child(password_row(core.clone()))
                .child(totp_row(core.clone()))
                .child(uris_row(core.clone()))
                .child(tags_row(core.clone()))
                .child(updated_row(core.clone()))
                .child(id_row(core)),
        ),
    )
}

fn labeled(label: &'static str, value: impl IntoElement) -> View {
    view()
        .flex_col()
        .gap_0p5()
        .child(
            text(label)
                .text_size(px(11.5))
                .uppercase()
                .text_color(move || theme().muted_foreground),
        )
        .child(value)
}

/// 通用：從 detail 訊號取一個顯示字串。
fn detail_text(core: &AppCore, f: impl Fn(&ItemView) -> String + 'static) -> impl IntoElement {
    let c = core.clone();
    text(move || c.detail.get().map(|d| f(&d)).unwrap_or_default())
        .text_size(px(13.5))
        .line_height(px(20.0))
        .text_color(move || theme().foreground)
}

fn type_row(core: AppCore) -> View {
    labeled(
        "類型",
        detail_text(&core, |d| ui::kind_label(d.meta.kind).to_owned()),
    )
}

fn username_row(core: AppCore) -> View {
    labeled(
        "帳號",
        detail_text(&core, |d| d.username.clone().unwrap_or_else(|| "—".into())),
    )
}

/// 密碼列：預設遮罩（Masked 投影的 `password_masked`，無則純點號）；
/// 「顯示密碼」按下去後 `revealed` 才有值——那是 Reveal 回來的明文，
/// 存在詳情層訊號、離開詳情由 `leave_detail` 清空。
fn password_row(core: AppCore) -> View {
    let c = core.clone();
    labeled(
        "密碼",
        text(move || match c.revealed.get() {
            Some(pw) if pw.is_empty() => "（此項目沒有密碼）".to_owned(),
            Some(pw) => pw,
            None => c
                .detail
                .get()
                .and_then(|d| d.password_masked.clone())
                .unwrap_or_else(|| "••••••••".to_owned()),
        })
        .text_size(px(13.5))
        .line_height(px(20.0))
        .text_color(move || theme().foreground),
    )
}

fn totp_row(core: AppCore) -> View {
    let c = core.clone();
    // daemon 的 Masked 投影不含 totp 存在性（hub.rs project_one 恆 false），
    // 所以按鈕常駐、有無 seed 由 daemon 裁決並回報錯誤。
    labeled(
        "一次性密碼（TOTP）",
        text(move || {
            c.totp
                .get()
                .unwrap_or_else(|| "（按上方「一次性密碼」向 daemon 取現算代碼）".to_owned())
        })
        .text_size(px(13.5))
        .line_height(px(20.0))
        .text_color(move || theme().foreground),
    )
}

fn uris_row(core: AppCore) -> View {
    labeled(
        "網址",
        detail_text(&core, |d| {
            if d.meta.uris.is_empty() {
                "—".into()
            } else {
                d.meta.uris.join("\n")
            }
        }),
    )
}

fn tags_row(core: AppCore) -> View {
    labeled(
        "標籤",
        detail_text(&core, |d| {
            if d.meta.tags.is_empty() {
                "—".into()
            } else {
                d.meta.tags.join(" · ")
            }
        }),
    )
}

fn updated_row(core: AppCore) -> View {
    labeled(
        "更新時間／同步狀態",
        detail_text(&core, |d| {
            match (d.meta.updated_at.as_deref(), d.meta.pending) {
                (Some(t), true) => format!("{t} · 待推送"),
                (Some(t), false) => t.to_owned(),
                (None, true) => "尚未推送（outbox 待推）".to_owned(),
                (None, false) => "—".to_owned(),
            }
        }),
    )
}

fn id_row(core: AppCore) -> View {
    labeled("識別碼", detail_text(&core, |d| d.meta.id.to_string()))
}
