//! 新增/編輯右欄 inline 表單：name/username/password/uri/tags → Vault:Create / Vault:Patch。
//! 表單明文（密碼欄）只進訊號與送出時的 `Zeroizing` 副本，加密前不落盤；
//! 送出與差異計算在 `state::submit_form`，髒退出閘在 `state::form_dirty`（確認框攔截）。
//! 密碼欄附產生器：「產生」展開面板，隨機數走 daemon `Use:GeneratePassword`。

use std::rc::Rc;
use std::sync::Arc;

use bw_proto::{CipherFieldKind, ItemKind};
use nsh_base::input;
use nsh_core::prelude::*;

use crate::passgen::GenState;
use crate::state::{AppCore, Cmd, FieldDraft, Route, UriDraft};
use crate::theme;
use crate::ui;

/// 欄位可見性（純函數，單測點）：帳密三欄（帳號/密碼/產生器/網址）僅
/// 非 SecureNote 顯示；備註/標籤/自訂欄位/資料夾兩型別皆顯示。
pub fn shows_credentials(kind: ItemKind) -> bool {
    kind != ItemKind::SecureNote
}

/// 右欄 inline 編輯器（新增／編輯共用，詳情 view↔edit 態翻轉）：
/// 標題列＋取消/儲存、本體滾動表單；刪除/改密/匯入維持模態（紀律 2）。
pub fn pane(core: AppCore) -> View {
    let (title, is_create) = match core.route.get() {
        Route::Create => ("新增項目", true),
        Route::Edit(_) => ("編輯項目", false),
        _ => return view().flex_1(),
    };
    let cancel = core.clone();
    let save = core.clone();
    let err_core = core.clone();
    let name = core.form.name;
    let tags = core.form.tags;
    let cred_cond = core.clone();
    let cred_build = core.clone();
    let note_cond = core.clone();
    let note_build = core.clone();
    view()
        .flex_col()
        .flex_1()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .px_8()
                .py_4()
                .child(
                    text(title)
                        .text_size(px(theme::TEXT_IDENTITY))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ui::button("取消", ui::Btn::Ghost, move || {
                            cancel.send(Cmd::RequestCloseForm)
                        }))
                        .child(ui::button("儲存", ui::Btn::Primary, move || {
                            save.send(Cmd::SubmitForm)
                        })),
                ),
        )
        .child(view().h(px(1.0)).mx_8().bg(theme::HAIRLINE))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap(px(theme::FORM_GAP))
                .px_8()
                .py_4()
                .w_full()
                .max_w(px(680.0))
                .child(type_switcher(core.clone(), is_create))
                .child(ui::form_field("名稱", "例：GitHub", name, false, move |v| {
                    name.set(v)
                }))
                .child(folder_dropdown(core.clone()))
                .child(when(
                    move || shows_credentials(cred_cond.form.kind.get()),
                    move || credentials_block(cred_build.clone()),
                ))
                .child(when(
                    move || !shows_credentials(note_cond.form.kind.get()),
                    move || {
                        let notes = note_build.form.notes;
                        ui::form_field(
                            "備註",
                            "筆記內容（明文進入 Outgoing 幀）",
                            notes,
                            false,
                            move |v| notes.set(v),
                        )
                    },
                ))
                .child(custom_fields_editor(core.clone()))
                .child(ui::form_field(
                    "標籤",
                    "逗號分隔，例：dev, 工作",
                    tags,
                    false,
                    move |v| tags.set(v),
                ))
                .child(
                    text(move || err_core.form.error.get().unwrap_or_default())
                        .text_size(px(12.5))
                        .line_height(px(18.0))
                        .text_color(theme::DESTRUCTIVE),
                ),
        ))
}

/// 密碼欄提示（依 Route）；抽出以保持 `when` 閉包單純。
fn password_hint(route: Route) -> &'static str {
    match route {
        Route::Edit(_) => "（不變更；輸入新值以替換）",
        _ => "（可留空）",
    }
}

/// 帳密區塊（僅 Login 型別）：帳號、密碼＋產生器、網址。
fn credentials_block(core: AppCore) -> View {
    let username = core.form.username;
    view()
        .flex_col()
        .gap(px(theme::FORM_GAP))
        .child(ui::form_field(
            "帳號",
            "使用者名稱或電子信箱",
            username,
            false,
            move |v| username.set(v),
        ))
        .child(password_with_generator(core.clone()))
        .child(uris_editor(core.clone()))
}

/// 密碼列＋產生器摺疊面板（批次 9 抽共用：新增表單與詳情 inline 編輯態
/// 同一份，零複製）。提示依 Route（編輯＝不變更語意）。
pub(crate) fn password_with_generator(core: AppCore) -> View {
    let password = core.form.password;
    let gen_panel = core.form.gen_panel;
    let gen_cond = core.clone();
    let gen_build = core.clone();
    let pw_hint = password_hint(core.route.get());
    view()
        .flex_col()
        .gap_2()
        .child(
            view()
                .flex_row()
                .items_end()
                .gap_2()
                .child(
                    ui::form_field("密碼", pw_hint, password, true, move |v| password.set(v))
                        .flex_1(),
                )
                .child(ui::button_dyn(
                    move || if gen_panel.get().open { "收起" } else { "產生" }.to_owned(),
                    ui::Btn::Ghost,
                    move || gen_panel.update(|g| g.open = !g.open),
                )),
        )
        .child(when(
            move || gen_cond.form.gen_panel.get().open,
            move || generator(gen_build.clone()),
        ))
}

/// 網址多列編輯器（批次 A＃1＋C）：每列＝uri 輸入框＋✕刪列、＋ 新增網址。
/// 列身份走 `UriDraft.key`（編輯 prefilled 列＝基準索引、新增列＝亂數哨兵），
/// diff 按 key 對齊不錯位（`uri_edits`：值改 Set、刪列 RemoveUri 遞減、
/// 新列 AppendUri 落尾——daemon 892c15b 面）。
pub fn uris_editor(core: AppCore) -> View {
    let rows = core.form.uris;
    let add_rows = rows;
    let row_rows = rows;
    let label = view()
        .flex_row()
        .items_center()
        .justify_between()
        .child(
            text("網址")
                .text_size(px(theme::TEXT_FIELD_LABEL))
                .font_weight(FontWeight::MEDIUM)
                .letter_spacing(px(0.4))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(ui::text_button_dyn(
            || "＋ 新增網址".to_owned(),
            move || add_rows.update(|v| Arc::make_mut(v).push(UriDraft::default())),
        ));
    view()
        .flex_col()
        .gap_1p5()
        .child(label)
        .child(each(
            move || (*rows.get()).clone(),
            |u: &UriDraft| u.key,
            move |_item: ReadSignal<UriDraft>, _i: ReadSignal<usize>| {
                uri_row(row_rows, _item.get().key)
            },
        ))
}

/// 單列網址：輸入框（按 key 回寫）＋✕刪列。
fn uri_row(rows: Signal<Arc<Vec<UriDraft>>>, key: u32) -> View {
    let edit = rows;
    let del = rows;
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            input()
                .value(move || {
                    rows.get()
                        .iter()
                        .find(|u| u.key == key)
                        .map(|u| u.uri.clone())
                        .unwrap_or_default()
                })
                .placeholder("https://example.com".to_owned())
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .on_change(move |t: &str| {
                    edit.update(|v| {
                        if let Some(u) = Arc::make_mut(v).iter_mut().find(|u| u.key == key) {
                            u.uri = t.to_owned();
                        }
                    });
                })
                .h(px(theme::INPUT_H))
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::BASE)
                .text_color(theme::TEXT_PRIMARY)
                .focus(|s| s.border_color(theme::ACCENT))
                .flex_1(),
        )
        .child(uri_match_menu(rows, key))
        .child(
            view()
                .w(px(theme::COPY_BTN))
                .h(px(theme::COPY_BTN))
                .rounded(px(theme::RADIUS_CONTROL))
                .flex_row()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .hover(|s| s.bg(theme::SURFACE_RAISED))
                .on_press(move || {
                    del.update(|v| Arc::make_mut(v).retain(|u| u.key != key));
                })
                .child(text("✕").text_size(px(11.0)).text_color(theme::TEXT_MUTED)),
        )
}

/// 網址判定下拉（macOS 設定面：官方六態 match）：膠囊顯示現值＋▾，
/// 選定即關面板（手法同 `kind_menu`）。值落 `UriDraft.match_type`，diff 走
/// `SetUriMatch`（既有列 leaf 批、新列結構批後第三發，見 `uri_edits`）。
fn uri_match_menu(rows: Signal<Arc<Vec<UriDraft>>>, key: u32) -> View {
    let open = signal(false);
    let label_sig = rows;
    let panel_open = open;
    let panel_rows = rows;
    view()
        .relative()
        .child(
            view()
                .h(px(theme::CHIP_H))
                .px_2p5()
                .rounded_full()
                .flex_row()
                .items_center()
                .gap_1()
                .cursor_pointer()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .on_press(move || open.update(|o| *o = !*o))
                .child(
                    text(move || {
                        crate::state::uri_match_label(
                            label_sig
                                .get()
                                .iter()
                                .find(|u| u.key == key)
                                .and_then(|u| u.match_type),
                        )
                        .to_owned()
                    })
                    .text_size(px(12.0))
                    .text_color(theme::TEXT_SECONDARY),
                )
                .child(text("▾").text_size(px(9.0)).text_color(theme::TEXT_MUTED)),
        )
        .child(when(
            move || panel_open.get(),
            move || uri_match_panel(panel_rows, key, panel_open),
        ))
}

fn uri_match_panel(
    rows: Signal<Arc<Vec<UriDraft>>>,
    key: u32,
    open: Signal<bool>,
) -> View {
    let cur = rows
        .get()
        .iter()
        .find(|u| u.key == key)
        .and_then(|u| u.match_type);
    let rows: Vec<View> = crate::state::URI_MATCH_OPTIONS
        .iter()
        .map(|(val, label)| {
            let pick = rows;
            let close = open;
            let (want, text_label) = (*val, *label);
            ui::menu_row(text_label.to_owned(), cur == want, move || {
                pick.update(|v| {
                    if let Some(u) = Arc::make_mut(v).iter_mut().find(|u| u.key == key) {
                        u.match_type = want;
                    }
                });
                close.set(false);
            })
        })
        .collect();
    view()
        .absolute()
        .top(px(theme::CHIP_H + 4.0))
        .left_0()
        .z_index(10)
        .child(ui::card(rows).w(px(theme::KIND_MENU_W)))
}

/// 型別切換列：建立時可選 登入／加密筆記；Card/Identity 佔位 disabled
/// （daemon 未支援）。編輯模式型別不可改（FieldEdit 無 type 路徑）。
pub(crate) fn type_switcher(core: AppCore, is_create: bool) -> View {
    let kind = core.form.kind;
    let l_core = core.clone();
    let n_core = core.clone();
    let c_core = core.clone();
    let i_core = core.clone();
    view()
        .flex_col()
        .gap_1()
        .child(
            text("型別")
                .text_size(px(theme::TEXT_FIELD_LABEL))
                .font_weight(FontWeight::MEDIUM)
                .letter_spacing(px(0.4))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(type_chip(
                    "登入",
                    move || kind.get() == ItemKind::Login,
                    is_create,
                    if is_create { None } else { Some("型別於建立後不可更改") },
                    move || l_core.form.kind.set(ItemKind::Login),
                ))
                .child(type_chip(
                    "加密筆記",
                    move || kind.get() == ItemKind::SecureNote,
                    is_create,
                    if is_create { None } else { Some("型別於建立後不可更改") },
                    move || n_core.form.kind.set(ItemKind::SecureNote),
                ))
                .child(type_chip(
                    "卡片",
                    || false,
                    false,
                    Some("daemon 尚未支援卡片型別"),
                    move || c_core.form.kind.set(ItemKind::Card),
                ))
                .child(type_chip(
                    "身分",
                    || false,
                    false,
                    Some("daemon 尚未支援身分別"),
                    move || i_core.form.kind.set(ItemKind::Identity),
                )),
        )
}

/// 型別膠囊：disabled 時灰字＋tooltip，不接 onPressed。
fn type_chip(
    label: &'static str,
    selected: impl Fn() -> bool + 'static,
    enabled: bool,
    tip: Option<&'static str>,
    on_press: impl Fn() + 'static,
) -> View {
    let selected = Rc::new(selected);
    let sel_bg = selected.clone();
    let sel_border = selected;
    let base = view()
        .h(px(theme::CHIP_H))
        .px_2p5()
        .rounded_full()
        .flex_row()
        .items_center()
        .border(px(1.0))
        .transition_colors()
        .duration(150.0)
        .bg(move || {
            if sel_bg() {
                theme::ACCENT.opacity(0.14)
            } else {
                theme::SURFACE
            }
        })
        .border_color(move || {
            if sel_border() {
                theme::ACCENT
            } else {
                theme::HAIRLINE
            }
        });
    let base = if enabled {
        base.cursor_pointer()
            .active(|s| s.opacity(0.7))
            .on_press(on_press)
    } else {
        base.tooltip(ui::tooltip_card(tip.unwrap_or("即將推出")))
    };
    base.child(
        text(label)
            .text_size(px(12.5))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if enabled {
                theme::TEXT_SECONDARY
            } else {
                theme::TEXT_MUTED
            }),
    )
}

/// 資料夾下拉（ListFolders 鏡像來源）：無資料夾／各夾。選定即關面板。
pub(crate) fn folder_dropdown(core: AppCore) -> View {
    let open = signal(false);
    let folder = core.form.folder_id;
    let label_core = core.clone();
    let panel_open = open;
    let panel_core = core.clone();
    let trigger = view()
        .h(px(theme::INPUT_H))
        .px_3()
        .w_full()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::BASE)
        .flex_row()
        .items_center()
        .justify_between()
        .cursor_pointer()
        .on_press(move || open.update(|o| *o = !*o))
        .child(
            text(move || {
                let cur = folder.get();
                if cur.is_empty() {
                    "無資料夾".to_owned()
                } else {
                    label_core
                        .folders
                        .get()
                        .iter()
                        .find(|f| f.id == cur)
                        .and_then(|f| f.name.clone())
                        .unwrap_or_else(|| "（已刪除的資料夾）".to_owned())
                }
            })
            .text_size(px(13.0))
            .text_color(theme::TEXT_PRIMARY),
        )
        .child(text("▾").text_size(px(10.0)).text_color(theme::TEXT_MUTED));
    view()
        .flex_col()
        .gap_1()
        .child(
            text("資料夾")
                .text_size(px(theme::TEXT_FIELD_LABEL))
                .font_weight(FontWeight::MEDIUM)
                .letter_spacing(px(0.4))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(trigger)
        .child(when(
            move || panel_open.get(),
            move || folder_panel(panel_core.clone(), panel_open),
        ))
}

/// 下拉面板：選資料夾＝寫 folder_id 並關面板（"" ＝無資料夾）。
fn folder_panel(core: AppCore, open: Signal<bool>) -> View {
    let folder = core.form.folder_id;
    let mut rows: Vec<View> = Vec::new();
    let none_pick = folder;
    let none_close = open;
    rows.push(ui::menu_row("無資料夾".to_owned(), folder.get().is_empty(), move || {
        none_pick.set(String::new());
        none_close.set(false);
    }));
    let list = core.folders.get();
    for f in list.iter().filter(|f| f.name.is_some()) {
        let name = f.name.clone().unwrap_or_default();
        let id = f.id.clone();
        let pick = folder;
        let close = open;
        let selected = folder.get() == id;
        rows.push(ui::menu_row(name, selected, move || {
            pick.set(id.clone());
            close.set(false);
        }));
    }
    ui::card(rows).w(px(260.0))
}

/// 自訂欄位編輯列：name＋（值或布林開關）＋三態型別選單＋增刪。
/// 建立與編輯模式都可增刪改型（daemon 批次 3 的 SetType/Append/Remove）。
pub(crate) fn custom_fields_editor(core: AppCore) -> View {
    let fields = core.form.fields;
    let add_fields = fields;
    let row_fields = fields;
    view()
        .flex_col()
        .gap_1p5()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    text("自訂欄位")
                        .text_size(px(theme::TEXT_FIELD_LABEL))
                        .font_weight(FontWeight::MEDIUM)
                        .letter_spacing(px(0.4))
                        .text_color(theme::TEXT_SECONDARY),
                )
                .child(ui::text_button_dyn(
                    || "＋ 新增欄位".to_owned(),
                    move || {
                        add_fields.update(|v| Arc::make_mut(v).push(FieldDraft::default()));
                    },
                )),
        )
        .child(each(
            move || (*fields.get()).clone(),
            |f: &FieldDraft| f.key,
            move |item: ReadSignal<FieldDraft>, _i: ReadSignal<usize>| {
                field_row(row_fields, item.get().key)
            },
        ))
}

/// 單列編輯器：欄名＋（值輸入或布林開關，依型別）＋三態型別選單＋刪列。
/// 全部控制回寫 `fields` 訊號中 key 相符的那筆；增刪改型在編輯模式
/// 同樣開放（daemon 批次 3 的 SetType/Append/Remove）。
fn field_row(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32) -> View {
    let name_sig = fields;
    let val_cond = fields;
    let val_build = fields;
    let bool_cond = fields;
    let bool_build = fields;
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            input()
                .value(move || {
                    fields
                        .get()
                        .iter()
                        .find(|f| f.key == key)
                        .map(|f| f.name.clone())
                        .unwrap_or_default()
                })
                .placeholder("欄名")
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .on_change(move |t: &str| {
                    name_sig.update(|v| {
                        if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key) {
                            f.name = t.to_owned();
                        }
                    });
                })
                .h(px(theme::INPUT_H))
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::BASE)
                .text_color(theme::TEXT_PRIMARY)
                .flex_1(),
        )
        .child(when(
            move || !is_bool_row(row_kind(val_cond, key)),
            move || {
                let edit = val_build;
                input()
                    .value(move || {
                        edit.get().iter().find(|f| f.key == key).map(|f| f.value.clone()).unwrap_or_default()
                    })
                    .placeholder("值")
                    .placeholder_color(move || color(theme::TEXT_MUTED))
                    .on_change(move |t: &str| {
                        edit.update(|v| {
                            if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key) {
                                f.value = t.to_owned();
                            }
                        });
                    })
                    .h(px(theme::INPUT_H))
                    .px_3()
                    .rounded(px(theme::RADIUS_CONTROL))
                    .border(px(1.0))
                    .border_color(theme::HAIRLINE)
                    .bg(theme::BASE)
                    .text_color(theme::TEXT_PRIMARY)
                    .flex_1()
            },
        ))
        .child(when(
            move || is_bool_row(row_kind(bool_cond, key)),
            move || bool_toggle(bool_build, key),
        ))
        .child(kind_menu(fields, key))
        .child(
            view()
                .w(px(theme::COPY_BTN))
                .h(px(theme::COPY_BTN))
                .rounded(px(theme::RADIUS_CONTROL))
                .flex_row()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .hover(|s| s.bg(theme::SURFACE_RAISED))
                .on_press(move || {
                    fields.update(|v| Arc::make_mut(v).retain(|f| f.key != key));
                })
                .child(text("✕").text_size(px(11.0)).text_color(theme::TEXT_MUTED)),
        )
}

/// 取該列目前型別（列不存在退回 Text）。
fn row_kind(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32) -> CipherFieldKind {
    fields
        .get()
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.kind)
        .unwrap_or_default()
}

fn is_bool_row(kind: CipherFieldKind) -> bool {
    kind == CipherFieldKind::Boolean
}

/// 布林欄的值控制：開關＋是/否（值 "true"/"false" 由 set 端正規化）。
fn bool_toggle(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32) -> View {
    let press = fields;
    let read = fields;
    let label_read = fields;
    let is_on = move || {
        read.get()
            .iter()
            .find(|f| f.key == key)
            .is_some_and(|f| f.bool_value())
    };
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .flex_1()
        .cursor_pointer()
        .on_press(move || {
            press.update(|v| {
                if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key) {
                    f.value = if f.bool_value() { "false" } else { "true" }.to_owned();
                }
            });
        })
        .child(ui::bool_switch(move || {
            label_read
                .get()
                .iter()
                .find(|f| f.key == key)
                .is_some_and(|f| f.bool_value())
        }))
        .child(
            text(move || if is_on() { "是" } else { "否" })
                .text_size(px(12.5))
                .text_color(theme::TEXT_SECONDARY),
        )
}

/// 三態型別選單膠囊：文字／隱藏／布林；選定即關面板。
fn kind_menu(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32) -> View {
    let open = signal(false);
    let label_sig = fields;
    let panel_open = open;
    let panel_fields = fields;
    view()
        .relative()
        .child(
            view()
                .h(px(theme::CHIP_H))
                .px_2p5()
                .rounded_full()
                .flex_row()
                .items_center()
                .gap_1()
                .cursor_pointer()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .on_press(move || open.update(|o| *o = !*o))
                .child(
                    text(move || {
                        ui::field_kind_label(
                            label_sig
                                .get()
                                .iter()
                                .find(|f| f.key == key)
                                .map(|f| f.kind)
                                .unwrap_or_default(),
                        )
                    })
                    .text_size(px(12.0))
                    .text_color(theme::TEXT_SECONDARY),
                )
                .child(text("▾").text_size(px(9.0)).text_color(theme::TEXT_MUTED)),
        )
        .child(when(
            move || panel_open.get(),
            move || kind_panel(panel_fields, key, panel_open),
        ))
}

fn kind_panel(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32, open: Signal<bool>) -> View {
    let cur = fields
        .get()
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.kind)
        .unwrap_or_default();
    let rows: Vec<View> = [
        CipherFieldKind::Text,
        CipherFieldKind::Hidden,
        CipherFieldKind::Boolean,
    ]
    .into_iter()
    .map(|k| {
        let pick = fields;
        let close = open;
        ui::menu_row(ui::field_kind_label(k).to_owned(), cur == k, move || {
            pick.update(|v| {
                if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key) {
                    f.set_kind(k);
                }
            });
            close.set(false);
        })
    })
    .collect();
    view()
        .absolute()
        .top(px(theme::CHIP_H + 4.0))
        .left_0()
        .z_index(10)
        .child(ui::card(rows).w(px(theme::KIND_MENU_W)))
}

/// 產生器面板：長度滑桿（8–64）、三個字元集開關、草稿與套用。
/// 「產生」＝送既有 `Cmd::GeneratePassword`，隨機數在 daemon。
fn generator(core: AppCore) -> View {
    let gen_panel = core.form.gen_panel;
    let draft = core.form.gen_draft;
    let draft_build = draft;
    let draft_apply = draft;
    let pw_apply = core.form.password;
    let hint_err = core.form.error;
    let regen_core = core.clone();
    view()
        .flex_col()
        .gap_2p5()
        .p_4()
        .rounded_lg()
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::SURFACE)
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(
                    text("長度")
                        .text_size(px(theme::TEXT_FIELD_LABEL))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(theme::TEXT_MUTED),
                )
                .child(slider_on(gen_panel))
                .child(
                    text(move || format!("{}", gen_panel.get().length))
                        .text_size(px(theme::TEXT_ROW))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_PRIMARY),
                ),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(switch_chip(
                    "大寫",
                    move || gen_panel.get().uppercase,
                    move || gen_panel.update(|g| g.uppercase = !g.uppercase),
                ))
                .child(switch_chip(
                    "小寫",
                    move || gen_panel.get().lowercase,
                    move || gen_panel.update(|g| g.lowercase = !g.lowercase),
                ))
                .child(switch_chip(
                    "數字",
                    move || gen_panel.get().digits,
                    move || gen_panel.update(|g| g.digits = !g.digits),
                ))
                .child(switch_chip(
                    "符號",
                    move || gen_panel.get().symbols,
                    move || gen_panel.update(|g| g.symbols = !g.symbols),
                ))
                .child(switch_chip(
                    "易讀",
                    move || gen_panel.get().avoid_ambiguous,
                    move || {
                        gen_panel.update(|g| g.avoid_ambiguous = !g.avoid_ambiguous)
                    },
                )),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .child(dynamic(move || match draft.get() {
                    Some(pw) => view().flex_1().child(
                        text(pw)
                            .text_size(px(theme::TEXT_FIELD_VALUE))
                            .font_family(ui::mono_font())
                            .text_color(theme::TEXT_PRIMARY)
                            .number_of_lines(1),
                    ),
                    None => view().flex_1().child(
                        text("按「重新產生」生成草稿")
                            .text_size(px(theme::TEXT_ROW_SUB))
                            .text_color(theme::TEXT_MUTED),
                    ),
                }))
                .child(ui::button("重新產生", ui::Btn::Ghost, move || {
                    if !gen_panel.get().has_charset() {
                        hint_err.set(Some("請至少保留一個字元集".into()));
                        return;
                    }
                    hint_err.set(None);
                    regen_core.send(Cmd::GeneratePassword);
                }))
                .child(when(
                    move || draft_build.get().is_some(),
                    move || {
                        ui::button("套用", ui::Btn::Primary, move || {
                            if let Some(pw) = draft_apply.get() {
                                pw_apply.set(pw);
                            }
                        })
                    },
                )),
        )
}

/// 長度滑桿：點擊定位、按住拖動連動；比例→長度由 `GenState` 純函數夾取。
/// 綁定傳入的 `GenState` 訊號（表單面板與獨立產生器頁共用，零複製）。
pub(crate) fn slider_on(gen_panel: Signal<GenState>) -> View {
    let knob_gen = gen_panel;
    let pressed = signal(false);
    let hover_x = signal(0.0f32);
    view()
        .w(px(theme::GEN_TRACK_W))
        .h(px(theme::GEN_TRACK_HIT_H))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .on_press_down(move || pressed.set(true))
        .on_press_up(move || pressed.set(false))
        .on_press(move || {
            let x = hover_x.get();
            gen_panel.update(|g| {
                g.set_length(GenState::length_from_ratio(x / theme::GEN_TRACK_W));
            });
        })
        .on_hover_move(move |ev: &HoverEvent| {
            let x = ev.position.x.0.clamp(0.0, theme::GEN_TRACK_W);
            hover_x.set(x);
            if pressed.get() {
                gen_panel.update(|g| {
                    g.set_length(GenState::length_from_ratio(x / theme::GEN_TRACK_W));
                });
            }
        })
        .child(
            view()
                .w_full()
                .h(px(theme::GEN_TRACK_H))
                .relative()
                .rounded_full()
                .bg(theme::SURFACE_RAISED)
                .child(
                    view()
                        .h_full()
                        .rounded_full()
                        .w(move || px(theme::GEN_TRACK_W * knob_gen.get().length_ratio()))
                        .bg(theme::ACCENT),
                )
                .child(
                    view()
                        .absolute()
                        .top(px((theme::GEN_TRACK_H - theme::GEN_KNOB) / 2.0))
                        .w(px(theme::GEN_KNOB))
                        .h(px(theme::GEN_KNOB))
                        .rounded_full()
                        .bg(theme::ELEVATED)
                        .border(px(1.0))
                        .border_color(theme::HAIRLINE)
                        .left(move || {
                            px(
                                theme::GEN_TRACK_W * knob_gen.get().length_ratio()
                                    - theme::GEN_KNOB / 2.0,
                            )
                        }),
                ),
        )
}

/// 字元集開關膠囊（選中＝accent 描邊提亮，同 chips 語彙）。
pub(crate) fn switch_chip(
    label: &'static str,
    on: impl Fn() -> bool + 'static,
    on_press: impl Fn() + 'static,
) -> View {
    let on = Rc::new(on);
    let on_bg = on.clone();
    let on_border = on.clone();
    let on_text = on;
    view()
        .h(px(theme::CHIP_H))
        .px_2p5()
        .rounded_full()
        .flex_row()
        .items_center()
        .cursor_pointer()
        .border(px(1.0))
        .transition_colors()
        .duration(150.0)
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .bg(move || {
            if on_bg() {
                theme::ACCENT.opacity(0.14)
            } else {
                theme::SURFACE
            }
        })
        .border_color(move || {
            if on_border() {
                theme::ACCENT
            } else {
                theme::HAIRLINE
            }
        })
        .child(
            text(label)
                .text_size(px(12.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if on_text() {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_SECONDARY
                    }
                }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_note_hides_credential_fields() {
        assert!(shows_credentials(ItemKind::Login));
        assert!(!shows_credentials(ItemKind::SecureNote));
        // 佔位型別走登入形態（尚未開放，但可見性預設與登入同）。
        assert!(shows_credentials(ItemKind::Card));
        assert!(shows_credentials(ItemKind::Identity));
    }
}
