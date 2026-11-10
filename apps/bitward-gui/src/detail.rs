//! 詳情面板（右欄）：官方「編輯項目」表單感——頂部大名稱＋型別圖示，
//! 欄位為淺灰圓角值塊（label 12 粗灰在上、值在塊內 14），複製鈕在塊右側。
//! 分節與官方同序：帳密 → 驗證碼 → 備註 → 自訂欄位 → 資訊。
//! 密碼預設遮罩，「顯示密碼」才發 Get(Reveal)，明文只存在
//! `core.revealed` 這個詳情層訊號，離開視圖即清（契約驗收 3）。
//! 垃圾桶條目（`meta.deleted_at` 有值）動作群改「還原／永久刪除」；
//! TOTP 有碼時行內附倒數細进度條（App 1s 心跳驅動，≤5 秒轉 warning）。

use std::rc::Rc;

use bw_proto::CipherFieldKind;
use nsh_base::input;
use nsh_core::prelude::*;

use crate::form;
use crate::state;
use crate::state::{AppCore, Cmd, Route};
use crate::theme;
use crate::ui;

/// 顯示值：detail 訊號的派生閉包（欄位塊與複製鈕共用同一份）。
type Disp = Rc<dyn Fn() -> String>;

pub fn pane(core: AppCore) -> View {
    let copied = signal::<Option<&'static str>>(None);
    // 批次 A＃2：同骨架原地變形——Route::Edit 時欄位換輸入框（綁 form 訊號），
    // 節次序／標題／幾何全部沿用查看態，切換零跳動。
    let editing = matches!(core.route.get(), Route::Edit(_));
    let totp_cond = core.clone();
    let pk_cond = core.clone();
    view()
        .flex_col()
        .flex_1()
        .child(identity_header(core.clone(), editing))
        .child(view().h(px(1.0)).mx_8().bg(theme::HAIRLINE))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_5()
                .px_8()
                .py_4()
                .w_full()
                .max_w(px(680.0))
                .child(section("帳密", credentials_section(core.clone(), copied, editing)))
                .child(when(
                    move || {
                        state::totp_section_shown(
                            totp_cond.totp.get().as_deref(),
                            totp_cond.totp_error.get().as_deref(),
                        )
                    },
                    {
                        let totp_build = core.clone();
                        move || section("驗證碼", totp_section(totp_build.clone(), copied))
                    },
                ))
                .child(section("備註", notes_section(core.clone(), copied, editing)))
                .child(section("自訂欄位", custom_fields_section(core.clone(), copied, editing)))
                .child(section_dyn("附件", {
                    let ac = core.clone();
                    move || attachments_rows(ac.clone())
                }))
                .child(when(
                    // 「有才渲染」：無 passkey 的項目整節缺席（不像附件恆帶上傳器）。
                    move || !pk_cond.passkeys.get().is_empty(),
                    {
                        let pk_build = core.clone();
                        move || section("Passkeys", passkey_rows(pk_build.clone()))
                    },
                ))
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
                .child(
                    text("⚷\u{fe0e}")
                        .text_size(px(theme::GLYPH_KEY))
                        .text_color(theme::TEXT_SECONDARY),
                ),
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

/// 動態分節：列内容由閉包現算——`detail` 訊號變動即重建。事件幫浦的
/// `DetailRefreshed` 是 Some→Some 更新（不翻 `when`），附件列這種
/// 「收斂後才出現」的資料必須走這條，不會卡在首次快照。
fn section_dyn(title: &'static str, build: impl Fn() -> Vec<View> + 'static) -> AnyElement {
    dynamic(move || section(title, build()))
}

/// 頂部 identity：大 monogram 退役，改型別磚＋大名稱＋網址連結＋動作群。
fn identity_header(core: AppCore, editing: bool) -> View {
    let name_core = core.clone();
    let icon_core = core.clone();
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
        .child(ui::icon_tile(
            icon_core.clone(),
            move || {
                icon_core
                    .detail
                    .get()
                    .and_then(|d| d.meta.uris.first().cloned())
                    .and_then(|u| state::host_of(&u))
            },
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
                .child(if editing {
                    // 名稱就地變輸入框：同字級同位置，零跳動。
                    let name_sig = name_core.form.name;
                    view().w_full().child(
                        input()
                            .value(move || name_sig.get())
                            .placeholder("名稱".to_owned())
                            .placeholder_color(move || color(theme::TEXT_MUTED))
                            .on_change(move |t: &str| name_sig.set(t.to_owned()))
                            .text_size(px(theme::TEXT_IDENTITY))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme::TEXT_PRIMARY)
                            .bg(theme::SURFACE)
                            .px_3()
                            .h(px(34.0))
                            .rounded(px(theme::RADIUS_BLOCK))
                            .border(px(1.0))
                            .border_color(theme::HAIRLINE)
                            .focus(|s| s.border_color(theme::ACCENT)),
                    )
                } else {
                    view().w_full().child(
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
                })
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
            let d = actions_core.detail.get();
            let trashed = d.as_ref().is_some_and(|d| d.meta.deleted_at.is_some());
            let archived = d.as_ref().is_some_and(|d| d.meta.archived_at.is_some());
            let item_id = d.as_ref().map(|d| d.meta.id);
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
                    .child(
                        // daemon 語意：垃圾桶內禁直接封存（422）→ UI 前置擋下。
                        ui::button("封存", ui::Btn::Ghost, || {})
                            .opacity(0.45)
                            .tooltip(ui::tooltip_card("先還原再封存")),
                    )
            } else if editing {
                // 編輯態頂部鈕：取消（髒走確認框）／儲存（diff 送出）。
                let cancel = actions_core.clone();
                let save = actions_core.clone();
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(ui::button("取消", ui::Btn::Ghost, move || {
                        cancel.send(Cmd::RequestCloseForm)
                    }))
                    .child(ui::button("儲存", ui::Btn::Primary, move || {
                        save.send(Cmd::SubmitForm)
                    }))
            } else {
                let arch = actions_core.clone();
                let unarch = actions_core.clone();
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(ui::button("編輯", ui::Btn::Ghost, move || {
                        if let Route::Detail(id) = edit.route.get() {
                            edit.send(Cmd::OpenEdit(id));
                        }
                    }))
                    .child(
                        // 已封存項目改「取消封存」；其餘給「封存」入口（批次 C）。
                        if archived {
                            ui::button("取消封存", ui::Btn::Ghost, move || {
                                if let (Some(id), Route::Detail(_)) = (item_id, unarch.route.get()) {
                                    unarch.send(Cmd::SetArchived { id, archived: false });
                                }
                            })
                        } else {
                            ui::button("封存", ui::Btn::Ghost, move || {
                                if let (Some(id), Route::Detail(_)) = (item_id, arch.route.get()) {
                                    arch.send(Cmd::SetArchived { id, archived: true });
                                }
                            })
                        },
                    )
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
/// 編輯態＝同節同序、值塊就地變輸入框（`edit_field`／`uris_editor`）。
fn credentials_section(core: AppCore, copied: Signal<Option<&'static str>>, editing: bool) -> Vec<View> {
    if editing {
        return vec![
            edit_field("帳號", "使用者名稱或電子信箱", core.form.username, false),
            edit_field("密碼", "（不變更；輸入新值以替換）", core.form.password, true),
            form::uris_editor(core.clone()),
            edit_field("標籤", "逗號分隔，例：dev, 工作", core.form.tags, false),
            form::folder_dropdown(core.clone()),
        ];
    }
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
        field("帳號", username.clone(), vec![ui::copy_button(username, "帳號", copied, core.settings)]),
        password_field(core.clone(), copied),
        field("網址", uris.clone(), vec![ui::copy_button(uris, "網址", copied, core.settings)]),
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
            vec![ui::copy_button(id_disp, "識別碼", copied, core.settings)],
        ),
    ]
}

/// 備註節：notes 明文（Masked 視窗即帶全文；Metadata 下鍵不存在）。
fn notes_section(core: AppCore, copied: Signal<Option<&'static str>>, editing: bool) -> Vec<View> {
    if editing {
        return vec![edit_field("備註", "筆記內容（明文進入 Outgoing 幀）", core.form.notes, false)];
    }
    let notes = detail_disp(&core, |d| d.notes.clone().unwrap_or_else(|| "—".into()));
    let copy = notes.clone();
    vec![block(
        move || notes(),
        true,
        vec![ui::copy_button(copy, "備註", copied, core.settings)],
    )]
}

/// 自訂欄位節：pane 每次 detail 重建時快照（Reveal 不改欄集）。
/// 布爾欄渲染成開關樣（非純文字）；hidden 欄值僅 Reveal 出、Masked 下
/// 顯示點號佔位且不給複製鈕。
fn custom_fields_section(core: AppCore, copied: Signal<Option<&'static str>>, editing: bool) -> Vec<View> {
    if editing {
        return vec![form::custom_fields_editor(core)];
    }
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
            let mut trailing = Vec::new();
            let value_view = match f.kind {
                CipherFieldKind::Boolean => {
                    let on = f.value.as_deref() == Some("true");
                    let v = f.value.clone().unwrap_or_else(|| "false".into());
                    trailing.push(ui::copy_button(
                        Rc::new(move || v.clone()),
                        "自訂欄位",
                        copied,
                        core.settings,
                    ));
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ui::bool_switch(move || on))
                        .child(
                            text(if on { "是" } else { "否" })
                                .text_size(px(theme::TEXT_FIELD_VALUE))
                                .text_color(theme::TEXT_SECONDARY),
                        )
                }
                CipherFieldKind::Hidden => view().child(
                    text("••••••••")
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .text_color(theme::TEXT_PRIMARY),
                ),
                CipherFieldKind::Text => {
                    let v = f.value.clone().unwrap_or_else(|| "—".into());
                    let vc = v.clone();
                    trailing.push(ui::copy_button(
                        Rc::new(move || vc.clone()),
                        "自訂欄位",
                        copied,
                        core.settings,
                    ));
                    view().child(
                        text(v)
                            .text_size(px(theme::TEXT_FIELD_VALUE))
                            .text_color(theme::TEXT_PRIMARY)
                            .number_of_lines(1),
                    )
                }
            };
            field_static_view(f.name.clone(), value_view, trailing)
        })
        .collect()
}

/// 附件節（官方同序：自訂欄位後、資訊前）。每筆一列＝檔名＋大小＋下載／刪除；
/// 節尾內聯「附加檔案」編輯器（路徑框＋檔名/大小預覽＋上傳確認）。
/// 投影來源：Get(Masked) 的 `attachments`（空時鍵缺席）；上傳後附件列要等
/// 背景推送收斂才出現（事件幫浦自動重取詳情），UI 不假裝立即完成。
fn attachments_rows(core: AppCore) -> Vec<View> {
    let Some(d) = core.detail.get() else {
        return Vec::new();
    };
    let item_id = d.meta.id;
    let mut rows: Vec<View> = d
        .attachments
        .iter()
        .map(|a| att_row(core.clone(), item_id, a))
        .collect();
    rows.push(upload_editor(core.clone(), item_id, d.meta.organization_id.is_some()));
    rows
}

/// Passkeys 節（macOS 設定面）：每筆一列＝ relying party＋使用者名＋刪除鈕。
/// 資料源 `Passkey:GetPasskeys`（Metadata 級，按 item 過濾快取於 `core.passkeys`）；
/// 刪除走確認模態（`AskDeletePasskey`）。RP/使用者名是協定明文識別欄，不需 Reveal。
fn passkey_rows(core: AppCore) -> Vec<View> {
    let Some(d) = core.detail.get() else {
        return Vec::new();
    };
    let item_id = d.meta.id;
    core.passkeys
        .get()
        .iter()
        .map(|e| {
            let del = core.clone();
            let credential = e.credential_id.clone();
            let rp = e.rp_id.clone();
            let user = e.user_name.clone();
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .flex_1()
                        .flex_col()
                        .gap_1()
                        .px_3()
                        .py_2()
                        .rounded(px(theme::RADIUS_BLOCK))
                        .bg(theme::SURFACE)
                        .overflow_hidden()
                        .child(
                            text(e.rp_id.clone())
                                .text_size(px(theme::TEXT_FIELD_VALUE))
                                .text_color(theme::TEXT_PRIMARY)
                                .number_of_lines(1),
                        )
                        .child(
                            text(e.user_name.clone())
                                .text_size(px(theme::TEXT_PAGE_SUB))
                                .text_color(theme::TEXT_MUTED)
                                .number_of_lines(1),
                        ),
                )
                .child(ui::button("刪除", ui::Btn::Ghost, {
                    let credential = credential.clone();
                    let rp = rp.clone();
                    let user = user.clone();
                    move || {
                        del.send(Cmd::AskDeletePasskey {
                            item: item_id,
                            credential: credential.clone(),
                            rp: rp.clone(),
                            user: user.clone(),
                        })
                    }
                }))
        })
        .collect()
}

/// 單筆附件列。
fn att_row(core: AppCore, item_id: bw_proto::ItemId, meta: &bw_proto::AttachmentMeta) -> View {
    let dl = core.clone();
    let dl_id = meta.id.clone();
    let dl_name = meta.file_name.clone();
    let del = core.clone();
    let del_id = meta.id.clone();
    let del_name = meta.file_name.clone();
    let size_label = meta
        .size_name
        .clone()
        .unwrap_or_else(|| crate::attach::format_size(meta.size.unwrap_or_default()));
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            view()
                .flex_1()
                .flex_row()
                .items_center()
                .gap_3()
                .px_3()
                .py_2()
                .rounded(px(theme::RADIUS_BLOCK))
                .bg(theme::SURFACE)
                .overflow_hidden()
                .child(
                    text(meta.file_name.clone())
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .text_color(theme::TEXT_PRIMARY)
                        .number_of_lines(1)
                        .flex_1(),
                )
                .child(
                    text(size_label)
                        .text_size(px(theme::TEXT_PAGE_SUB))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
        .child(ui::button("下載", ui::Btn::Ghost, move || {
            dl.send(Cmd::DownloadAttachment {
                item_id,
                attachment_id: dl_id.clone(),
                file_name: dl_name.clone(),
            })
        }))
        .child(ui::button("刪除", ui::Btn::Ghost, move || {
            del.send(Cmd::AskDeleteAttachment {
                item_id,
                attachment_id: del_id.clone(),
                file_name: del_name.clone(),
            })
        }))
}

/// 上傳內聯編輯器：「附加檔案」→ 路徑框＋預覽＋上傳確認。
/// org 共享項目擋下（daemon 換鑰批次未開放），disabled＋tooltip。
fn upload_editor(core: AppCore, item_id: bw_proto::ItemId, is_org: bool) -> View {
    let open = core.att_upload_open;
    let preview_core = core.clone();
    let gate = crate::attach::upload_gate(if is_org { Some("org") } else { None });
    view()
        .flex_col()
        .gap_1p5()
        .child(when(
            move || !open.get() && gate.is_none(),
            move || {
                let o = open;
                view().flex_row().child(ui::button(
                    "附加檔案",
                    ui::Btn::Ghost,
                    move || o.update(|v| *v = true),
                ))
            },
        ))
        .child(when(
            move || !open.get() && gate.is_some(),
            move || {
                view()
                    .flex_row()
                    .child(ui::button("附加檔案", ui::Btn::Ghost, move || {}).tooltip(
                        ui::tooltip_card(gate.unwrap_or("即將推出")),
                    ))
            },
        ))
        .child(when(
            move || open.get() && gate.is_none(),
            move || {
                let p = preview_core.att_upload_path;
                let press = preview_core.clone();
                view()
                    .flex_col()
                    .gap_1p5()
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .child(
                                input()
                                    .value(move || p.get())
                                    .placeholder("貼上檔案路徑，例：~/Downloads/bill.pdf")
                                    .placeholder_color(move || color(theme::TEXT_MUTED))
                                    .on_change(move |t: &str| p.set(t.to_owned()))
                                    .h(px(theme::INPUT_H))
                                    .px_3()
                                    .rounded(px(theme::RADIUS_CONTROL))
                                    .border(px(1.0))
                                    .border_color(theme::HAIRLINE)
                                    .bg(theme::BASE)
                                    .text_color(theme::TEXT_PRIMARY)
                                    .font_family(ui::mono_font())
                                    .flex_1(),
                            )
                            .child(ui::button("上傳", ui::Btn::Primary, move || {
                                let path = press.att_upload_path.get();
                                press.send(Cmd::UploadAttachment { item_id, path })
                            })),
                    )
                    .child(dynamic(move || {
                        let cur = preview_core.att_upload_path.get();
                        if cur.trim().is_empty() {
                            return view().child(
                                text("nsh 選檔面板僅支援圖片副檔名，請直接貼路徑（≤32 MiB）。")
                                    .text_size(px(12.0))
                                    .text_color(theme::TEXT_MUTED),
                            );
                        }
                        match crate::attach::upload_preview(&cur) {
                            Ok(s) => {
                                view().child(text(s).text_size(px(12.0)).text_color(theme::SUCCESS))
                            }
                            Err(e) => view().child(
                                text(e)
                                    .text_size(px(12.0))
                                    .text_color(theme::DESTRUCTIVE),
                            ),
                        }
                    }))
            },
        ))
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
                                    c.settings,
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

/// 編輯態欄位：與 `field()` 同幾何（label 同位、圓角塊同寬同高），
/// 塊內從文字換輸入框——morph 零跳動的欄位級實作。
fn edit_field(label_text: &'static str, placeholder: &'static str, value: Signal<String>, secure: bool) -> View {
    view()
        .flex_col()
        .gap_1()
        .child(label(label_text))
        .child(
            input()
                .value(move || value.get())
                .placeholder(placeholder.to_owned())
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .masked(secure)
                .on_change(move |t: &str| value.set(t.to_owned()))
                .px_3()
                .h(px(34.0))
                .w_full()
                .rounded(px(theme::RADIUS_BLOCK))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .text_color(theme::TEXT_PRIMARY)
                .text_size(px(theme::TEXT_FIELD_VALUE))
                .focus(|s| s.border_color(theme::ACCENT)),
        )
}

/// 欄位值塊（build 時快照；自訂欄位用，欄名是動態字串、值塊内容由呼叫端
/// 依型別構造——text/hidden 是文字、boolean 是開關樣）。
fn field_static_view(label_text: String, value: View, trailing: Vec<View>) -> View {
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
                        .child(value),
                )
                .child(actions),
        )
}

/// TOTP 節（批次 A＃3）：渲染閘在 pane 層（`totp_section_shown`）——無 seed
/// 的項目取碼回「沒有 TOTP seed」→ 整節不出現；有 seed 進詳情自動取碼，
/// 6 位碼＋倒數條＋複製鈕，不需按任何鈕；真失敗顯示可懂一行（不彈窗）。
fn totp_section(core: AppCore, copied: Signal<Option<&'static str>>) -> Vec<View> {
    let shown_core = core.clone();
    let err_core = core.clone();
    let btn_block = core.clone();
    vec![block_dyn(
        move || {
            shown_core.totp.get().unwrap_or_else(|| {
                err_core.totp_error.get().unwrap_or_default()
            })
        },
        false,
        move || {
            let bar_core = btn_block.clone();
            let cond_bar = btn_block.clone();
            let cond_copy = btn_block.clone();
            let build_copy = btn_block.clone();
            let mut actions = view().flex_row().items_center().gap_1p5();
            actions = actions.child(when(
                move || cond_bar.totp.get().is_some(),
                move || countdown(bar_core.clone()),
            ));
            actions = actions.child(when(
                move || cond_copy.totp.get().is_some(),
                move || {
                    ui::copy_button(
                        Rc::new(move || build_copy.totp.get().unwrap_or_default()),
                        "TOTP",
                        copied,
                        build_copy.settings,
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
