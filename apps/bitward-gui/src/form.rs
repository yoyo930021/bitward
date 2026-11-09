//! 新增/編輯模態：name/username/password/uri/tags → Vault:Create / Vault:Patch。
//! 表單明文（密碼欄）只進訊號與送出時的 `Zeroizing` 副本，加密前不落盤；
//! 送出與差異計算在 `state::submit_form`。背板點擊＝取消（回列表）。
//! 密碼欄附產生器：「產生」展開面板，隨機數走 daemon `Use:GeneratePassword`。

use std::rc::Rc;
use std::sync::Arc;

use bw_proto::ItemKind;
use nsh_base::input;
use nsh_core::prelude::*;

use crate::passgen::GenState;
use crate::state::{AppCore, Cmd, FieldDraft, Route};
use crate::theme;
use crate::ui;

/// 欄位可見性（純函數，單測點）：帳密三欄（帳號/密碼/產生器/網址）僅
/// 非 SecureNote 顯示；備註/標籤/自訂欄位/資料夾兩型別皆顯示。
pub fn shows_credentials(kind: ItemKind) -> bool {
    kind != ItemKind::SecureNote
}

pub fn overlay(core: AppCore) -> View {
    let (title, is_create) = match core.route.get() {
        Route::Create => ("新增項目", true),
        Route::Edit(_) => ("編輯項目", false),
        _ => return view().flex_1(),
    };
    let back = core.clone();
    let back2 = core.clone();
    let save = core.clone();
    let err_core = core.clone();
    let name = core.form.name;
    let tags = core.form.tags;
    let cred_cond = core.clone();
    let cred_build = core.clone();
    let note_cond = core.clone();
    let note_build = core.clone();
    ui::modal_shell(
        520.0,
        move || back.send(Cmd::OpenList),
        view()
            .flex_col()
            .gap(px(theme::FORM_GAP))
            .child(
                text(title)
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
            )
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
            .child(custom_fields_editor(core.clone(), is_create))
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
            )
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .justify_end()
                    .gap_2()
                    .child(ui::button("取消", ui::Btn::Ghost, move || {
                        back2.send(Cmd::OpenList)
                    }))
                    .child(ui::button("儲存", ui::Btn::Primary, move || {
                        save.send(Cmd::SubmitForm)
                    })),
            ),
    )
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
    let password = core.form.password;
    let uri = core.form.uri;
    let gen_panel = core.form.gen_panel;
    let gen_cond = core.clone();
    let gen_build = core.clone();
    let pw_hint = password_hint(core.route.get());
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
        .child(ui::form_field(
            "網址",
            "https://example.com",
            uri,
            false,
            move |v| uri.set(v),
        ))
}

/// 型別切換列：建立時可選 登入／加密筆記；Card/Identity 佔位 disabled
/// （daemon 未支援）。編輯模式型別不可改（FieldEdit 無 type 路徑）。
fn type_switcher(core: AppCore, is_create: bool) -> View {
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
fn folder_dropdown(core: AppCore) -> View {
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

/// 自訂欄位編輯列：name＋value＋隱藏開關（建立模式）＋增刪。
/// 編輯模式只改 name/value——daemon 的 FieldEdit 無整陣列增刪路徑。
fn custom_fields_editor(core: AppCore, is_create: bool) -> View {
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
                .child(when(
                    move || is_create,
                    move || {
                        ui::text_button_dyn(
                            || "＋ 新增欄位".to_owned(),
                            move || {
                                add_fields.update(|v| Arc::make_mut(v).push(FieldDraft::default()));
                            },
                        )
                    },
                )),
        )
        .child(each(
            move || (*fields.get()).clone(),
            |f: &FieldDraft| f.key,
            move |item: ReadSignal<FieldDraft>, _i: ReadSignal<usize>| {
                field_row(row_fields, item.get().key, is_create)
            },
        ))
}

/// 單列編輯器：三個控制都回寫 `fields` 訊號中 key 相符的那筆。
fn field_row(fields: Signal<Arc<Vec<FieldDraft>>>, key: u32, is_create: bool) -> View {
    let name_sig = fields;
    let value_sig = fields;
    let row = view()
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
                .placeholder_color(move || theme::TEXT_MUTED.light)
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
        .child(
            input()
                .value(move || {
                    fields
                        .get()
                        .iter()
                        .find(|f| f.key == key)
                        .map(|f| f.value.clone())
                        .unwrap_or_default()
                })
                .placeholder("值")
                .placeholder_color(move || theme::TEXT_MUTED.light)
                .on_change(move |t: &str| {
                    value_sig.update(|v| {
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
                .flex_1(),
        );
    let del_sig = fields;
    if is_create {
        let hid_sig = fields;
        row.child(
            view()
                .h(px(theme::CHIP_H))
                .px_2p5()
                .rounded_full()
                .flex_row()
                .items_center()
                .cursor_pointer()
                .border(px(1.0))
                .border_color(move || {
                    let on = hid_sig
                        .get()
                        .iter()
                        .any(|f| f.key == key && f.hidden);
                    if on {
                        theme::ACCENT
                    } else {
                        theme::HAIRLINE
                    }
                })
                .bg(theme::SURFACE)
                .on_press(move || {
                    hid_sig.update(|v| {
                        if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key) {
                            f.hidden = !f.hidden;
                        }
                    });
                })
                .child(
                    text("隱藏")
                        .text_size(px(12.0))
                        .text_color(theme::TEXT_SECONDARY),
                ),
        )
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
                    del_sig.update(|v| Arc::make_mut(v).retain(|f| f.key != key));
                })
                .child(text("✕").text_size(px(11.0)).text_color(theme::TEXT_MUTED)),
        )
    } else {
        row.child(
            text("隱藏欄")
                .text_size(px(12.0))
                .text_color(theme::TEXT_MUTED)
                .tooltip(ui::tooltip_card("型別旗標建立後不可更改")),
        )
    }
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
                .child(slider(core.clone()))
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
                    "大小寫",
                    move || gen_panel.get().letters,
                    move || gen_panel.update(|g| g.letters = !g.letters),
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
fn slider(core: AppCore) -> View {
    let gen_panel = core.form.gen_panel;
    let knob_gen = core.form.gen_panel;
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
fn switch_chip(
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
