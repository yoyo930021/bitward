//! 畫面：登入頁、金庫列表、詳情頁。
//!
//! 這裡零業務語意：KDF、信封、鏡像、搜尋都在 `hub`（＝根 workspace 的核心
//! crate）。UI 只做訊號與排版。明文紀律（契約 §2.7）：
//! - 主密碼欄位是 nsh 的 `String`（不可清零），`Hub::login` 收到後立刻放進
//!   `Zeroizing` 派生，完成時把欄位清空（見 `login_page` 的回呼）。
//! - 詳情頁的明文只存在 `plain` 訊號；`on_dismiss`（含系統返回鍵）即歸零。

use std::sync::Arc;

use bw_proto::{CipherDraft, FieldEdit, ItemId, ItemKind, ItemMeta};
use nsh_base::{input, nav_page, theme};
use nsh_core::EllipsizeMode;
use nsh_core::element::Screen;
use nsh_core::prelude::*;

use crate::Phase;
use crate::hub::{Hub, Revealed};

/// 編輯模態的目標：新增一筆，或編輯既有的某筆（預填走 `Hub::reveal`）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Editor {
    New,
    Edit(ItemId),
}

/// 中樞開不起來（資料目錄不可寫等）：明確失敗畫面，不靜默降格。
pub fn broken_page(err: String) -> View {
    view()
        .flex_1()
        .items_center()
        .justify_center()
        .p_safe_area()
        .child(
            view()
                .flex_col()
                .items_center()
                .gap_3()
                .child(
                    text("無法啟動本機中樞")
                        .text_size(px(18.0))
                        .font_weight(FontWeight::SEMIBOLD),
                )
                .child(
                    text(err)
                        .text_size(px(13.0))
                        .text_color(move || theme().muted_foreground),
                ),
        )
}

/// 登入頁：服務器 + 信箱 + 主密碼。解鎖成功後根頁換成金庫列表。
pub fn login_page(hub: Arc<Hub>, phase: Signal<Phase>, status: Signal<String>) -> View {
    // 每次這個區域建立時重讀：鎖定後回登入頁也預填剛用過的帳號。
    let account = hub.account();
    let server = signal(
        account
            .as_ref()
            .map(|a| a.server.clone())
            .unwrap_or_else(|| "http://10.0.2.2:18095".to_owned()),
    );
    let email = signal(
        account
            .as_ref()
            .map(|a| a.email.clone())
            .unwrap_or_default(),
    );
    let password = signal(String::new());

    let do_server = server;
    let do_email = email;
    let do_password = password;
    let hub_login = hub.clone();

    view()
        .flex_1()
        .flex_col()
        .child(page_header(
            "登入你的密碼庫",
            "本機中樞（in-process）：金鑰派生、同步與鏡像都在這個進程內完成",
        ))
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_5()
                    .px_6()
                    .py_5()
                    .child(form_field("服務器", "https://vault.example.com", server, false))
                    .child(form_field("電子信箱", "me@example.com", email, false))
                    .child(form_field("主密碼", "只用於派生金鑰，不落地", password, true))
                    .child(primary_button(
                        move || {
                            if phase.get() == Phase::Busy {
                                "登入中…".to_owned()
                            } else {
                                "登入".to_owned()
                            }
                        },
                        move || {
                            if do_server.get().trim().is_empty() || do_email.get().trim().is_empty()
                            {
                                status.set("服務器與電子信箱皆為必填".to_owned());
                                return;
                            }
                            if phase.get() == Phase::Busy {
                                return;
                            }
                            let (s, e, p) = (do_server.get(), do_email.get(), do_password.get());
                            status.set(String::new());
                            phase.set(Phase::Busy);
                            let hub = hub_login.clone();
                            spawn(async move {
                                let out = hub.login(&s, &e, &p).await;
                                // 欄位殘留的明文立刻抹掉（金鑰已在 Zeroizing 裡）。
                                do_password.set(String::new());
                                match out {
                                    Ok(snap) => {
                                        log::info!("已登入：{} 筆鏡像", snap.items);
                                        phase.set(Phase::Vault(snap));
                                    }
                                    Err(msg) => {
                                        log::warn!("登入失敗：{msg}");
                                        status.set(msg);
                                        phase.set(Phase::SignedOut);
                                    }
                                }
                            });
                        },
                    ))
                    .child(
                        text(move || status.get())
                            .text_size(px(12.5))
                            .line_height(px(18.0))
                            .text_color(move || theme().destructive),
                    )
                    .child(
                        text(
                            "示範帳號：以 CLI 現成建立\nbitward dev register --server <網址> --email <信箱>",
                        )
                        .text_size(px(11.5))
                        .line_height(px(17.0))
                        .text_color(move || theme().muted_foreground),
                    ),
            ),
        )
}

/// 金庫列表：搜尋 + 原生虛擬列表；點列 push 詳情頁。
/// `rev` 由寫入路徑（模態／刪除）遞增，驅動列表重算；`editor` 開編輯模態。
pub fn vault_page(
    hub: Arc<Hub>,
    phase: Signal<Phase>,
    status: Signal<String>,
    selected: Signal<Option<ItemId>>,
    editor: Signal<Option<Editor>>,
    rev: Signal<u64>,
) -> View {
    let query = signal(String::new());
    let filtered = computed({
        let hub = hub.clone();
        let count_phase = phase;
        move || {
            // 同步/鎖定/寫入改動訊號時才重算：訊號驅動，不另設輪詢。
            let _ = count_phase.get();
            let _ = rev.get();
            Arc::new(hub.list(&query.get()))
        }
    });

    let refresh_hub = hub.clone();
    let lock_hub = hub.clone();

    view()
        .flex_1()
        .flex_col()
        .child(
            view()
                .flex_col()
                .gap_2()
                .px_6()
                .pt_4()
                .pb_2()
                .child(
                    text(move || match phase.get() {
                        Phase::Vault(s) => format!("{} · {}", s.email, s.server),
                        _ => String::new(),
                    })
                    .text_size(px(12.0))
                    .text_color(move || theme().muted_foreground)
                    .number_of_lines(1)
                    .ellipsize_mode(EllipsizeMode::Tail),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .child(
                            text(move || match phase.get() {
                                Phase::Vault(s) => format!("鏡像 {} 筆", s.items),
                                Phase::Busy => "同步中…".to_owned(),
                                Phase::SignedOut => String::new(),
                            })
                            .text_size(px(13.0))
                            .font_weight(FontWeight::SEMIBOLD),
                        )
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_2()
                                .child(ghost_button("新增", move || {
                                    editor.set(Some(Editor::New));
                                }))
                                .child(ghost_button("重新同步", move || {
                                    if phase.get() == Phase::Busy {
                                        return;
                                    }
                                    status.set(String::new());
                                    phase.set(Phase::Busy);
                                    let hub = refresh_hub.clone();
                                    spawn(async move {
                                        match hub.sync_now().await {
                                            Ok(n) => {
                                                if let Phase::Vault(mut s) = phase.get() {
                                                    s.items = n;
                                                    s.last_sync_ms = hub.now_ms();
                                                    phase.set(Phase::Vault(s));
                                                }
                                            }
                                            Err(msg) => {
                                                status.set(msg);
                                                phase.set(Phase::SignedOut);
                                            }
                                        }
                                    });
                                }))
                                .child(ghost_button("鎖定", move || {
                                    // 金鑰在這裡歸零（Hub::sign_out 丟棄 UserKey）。
                                    lock_hub.sign_out();
                                    status.set(String::new());
                                    phase.set(Phase::SignedOut);
                                })),
                        ),
                )
                .child(
                    input()
                        .value(move || query.get())
                        .placeholder("搜尋名稱或網址".to_owned())
                        .on_change(move |text: &str| query.set(text.to_owned()))
                        .h_11()
                        .px_3()
                        .rounded_lg()
                        .border(px(1.0))
                        .border_color(move || theme().border)
                        .text_color(move || theme().foreground)
                        .text_size(px(15.0)),
                ),
        )
        .child(
            text(move || status.get())
                .text_size(px(12.0))
                .line_height(px(17.0))
                .px_6()
                .text_color(move || theme().destructive),
        )
        .child(
            virtual_list(
                move || filtered.get().len(),
                move |at| {
                    let tap = selected;
                    view()
                        .h_16()
                        .px_6()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .cursor_pointer()
                        .active(|s| s.bg(theme().accent))
                        .on_press(move || {
                            let items = filtered.get();
                            if let Some(it) = items.get(at.index()) {
                                tap.set(Some(it.id));
                            }
                        })
                        .child(
                            view()
                                .w_9()
                                .h_9()
                                .rounded(px(18.0))
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .bg(move || theme().muted)
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        items
                                            .get(at.index())
                                            .and_then(|it| it.name.clone())
                                            .and_then(|n| {
                                                n.chars()
                                                    .next()
                                                    .map(|c| c.to_uppercase().to_string())
                                            })
                                            .unwrap_or_else(|| "?".to_owned())
                                    })
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::SEMIBOLD),
                                ),
                        )
                        .child(
                            view()
                                .flex_col()
                                .flex_1()
                                .gap_0p5()
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        items
                                            .get(at.index())
                                            .and_then(|it| it.name.clone())
                                            .unwrap_or_else(|| "(未命名)".to_owned())
                                    })
                                    .text_size(px(15.0))
                                    .line_height(px(20.0))
                                    .font_weight(FontWeight::MEDIUM)
                                    .number_of_lines(1)
                                    .ellipsize_mode(EllipsizeMode::Tail),
                                )
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        items.get(at.index()).map(subtitle).unwrap_or_default()
                                    })
                                    .text_size(px(12.0))
                                    .line_height(px(16.0))
                                    .text_color(move || theme().muted_foreground)
                                    .number_of_lines(1)
                                    .ellipsize_mode(EllipsizeMode::Tail),
                                ),
                        )
                        .child(
                            text(move || {
                                let items = filtered.get();
                                match items.get(at.index()) {
                                    Some(it) if it.pending => "待推送".to_owned(),
                                    _ => String::new(),
                                }
                            })
                            .text_size(px(11.0))
                            .text_color(move || theme().primary),
                        )
                },
            )
            .flex_1()
            .keys(move || filtered.get().iter().map(|it| it.id).collect::<Vec<_>>())
            .separator(|| {
                view()
                    .h(px(1.0))
                    .ml(px(72.0))
                    .mr_6()
                    .bg(move || theme().border)
            })
            .empty(
                view()
                    .h_24()
                    .flex_row()
                    .items_center()
                    .justify_center()
                    .child(
                        text("還沒有任何項目")
                            .text_size(px(13.0))
                            .text_color(move || theme().muted_foreground),
                    ),
            ),
        )
}

/// 詳情頁（push 在棧上）：metadata 全欄位；密碼預設遮罩，按「顯示」才解密。
/// 「編輯」開預填模態；「刪除」走二次確認後軟刪（`Hub::delete`，待推送語意
/// 同列表的 pending 標記——tombstone 即刻離列，伺服器標記等同步收斂）。
pub fn detail_page(
    hub: Arc<Hub>,
    id: ItemId,
    selected: Signal<Option<ItemId>>,
    plain: Signal<Option<Revealed>>,
    editor: Signal<Option<Editor>>,
    phase: Signal<Phase>,
    rev: Signal<u64>,
) -> Screen {
    let title = hub
        .meta(id)
        .ok()
        .flatten()
        .and_then(|m| m.name)
        .unwrap_or_else(|| "項目詳情".to_owned());

    let show_hub = hub.clone();
    let show_status = signal(String::new());
    let confirm_del = signal(false);

    let content = view().flex_1().flex_col().child(
        scroll().flex_1().child(
            view()
                .flex_col()
                .gap_4()
                .px_6()
                .py_5()
                .child(meta_rows(hub.clone(), id))
                .child(divider())
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .child(
                            text(move || {
                                if plain.get().is_some() {
                                    "密碼（已顯示）".to_owned()
                                } else {
                                    "密碼".to_owned()
                                }
                            })
                            .text_size(px(13.0))
                            .font_weight(FontWeight::MEDIUM),
                        )
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_2()
                                .child(ghost_button(
                                    move || {
                                        if plain.get().is_some() {
                                            "隱藏".to_owned()
                                        } else {
                                            "顯示".to_owned()
                                        }
                                    },
                                    move || {
                                        if plain.get().is_some() {
                                            // 隱藏即歸零：Revealed Drop → Zeroizing 清零。
                                            plain.set(None);
                                            return;
                                        }
                                        match show_hub.reveal(id) {
                                            Ok(r) => plain.set(Some(r)),
                                            Err(e) => show_status.set(e),
                                        }
                                    },
                                ))
                                .child(ghost_button("複製帳號", move || {
                                    if let Some(u) = plain.get().and_then(|r| r.username.clone()) {
                                        set_clipboard(u);
                                    }
                                })),
                        ),
                )
                .child(
                    text(move || match plain.get() {
                        Some(r) => r
                            .password
                            .as_ref()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "（無密碼欄位）".to_owned()),
                        None => "••••••••".to_owned(),
                    })
                    .text_size(px(15.0))
                    .line_height(px(22.0)),
                )
                .child(
                    text(move || match plain.get().and_then(|r| r.username.clone()) {
                        Some(u) => u,
                        None => "（按「顯示」取用帳號與一次性密碼）".to_owned(),
                    })
                    .text_size(px(13.0))
                    .line_height(px(19.0))
                    .text_color(move || theme().muted_foreground),
                )
                .child(
                    text(move || match plain.get().and_then(|r| r.totp.clone()) {
                        Some(c) => format!("一次性密碼：{c}"),
                        None => String::new(),
                    })
                    .text_size(px(13.0))
                    .line_height(px(19.0))
                    .text_color(move || theme().muted_foreground),
                )
                .child(
                    text(move || show_status.get())
                        .text_size(px(12.0))
                        .line_height(px(17.0))
                        .text_color(move || theme().destructive),
                )
                .child(divider())
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ghost_button("編輯", move || {
                            editor.set(Some(Editor::Edit(id)));
                        }))
                        .child(ghost_button("刪除", move || {
                            confirm_del.set(true);
                        })),
                )
                .child(when(
                    move || confirm_del.get(),
                    move || {
                        let ok_hub = hub.clone();
                        let ok_phase = phase;
                        view()
                            .flex_col()
                            .gap_3()
                            .p_4()
                            .rounded_lg()
                            .border(px(1.0))
                            .border_color(move || theme().destructive)
                            .child(
                                text("確定刪除這筆？（軟刪：即刻從列表消失，同步後伺服器才標記刪除）")
                                    .text_size(px(13.0))
                                    .line_height(px(19.0)),
                            )
                            .child(
                                view()
                                    .flex_row()
                                    .gap_2()
                                    .child(ghost_button("取消刪除", move || {
                                        confirm_del.set(false);
                                    }))
                                    .child(primary_button("確定刪除", move || {
                                        match ok_hub.delete(id) {
                                            Ok(()) => {
                                                log::info!("ui: 已軟刪 {id}（待推送）");
                                                confirm_del.set(false);
                                                // 返回列表並清明文；計數與列舉同步刷新。
                                                plain.set(None);
                                                selected.set(None);
                                                if let Phase::Vault(mut s) = ok_phase.get() {
                                                    s.items = ok_hub.list("").len();
                                                    ok_phase.set(Phase::Vault(s));
                                                }
                                                rev.set(rev.get() + 1);
                                            }
                                            Err(e) => show_status.set(e),
                                        }
                                    })),
                            )
                    },
                )),
        ),
    );

    nav_page()
        .key(format!("detail-{id}"))
        .title(title)
        .on_dismiss(move || {
            // 離開視圖即清明文（系統返回鍵走同一條）。
            plain.set(None);
            selected.set(None);
        })
        .child(content)
}

/// 編輯模態（掛在根上的 `dialog()` 覆蓋層，navprobe 實測返回鍵不誤傷棧）：
/// 名稱／帳號／密碼／網址四欄＋存/取消。編輯預填走 `Hub::reveal`（明文只活在
/// 欄位訊號，關閉即清空）；送出去的是**對預填基線的差量**——沒動的欄位不進
/// patch，欄位級存活由 `bw_vault::apply_merged` 保證。寫入走 `Hub` 本地交易
/// （outbox），推送收斂由「重新同步」的 drain 負責（背景同步是下一批）。
pub fn editor_modal(
    hub: Arc<Hub>,
    editor: Signal<Option<Editor>>,
    phase: Signal<Phase>,
    selected: Signal<Option<ItemId>>,
    plain: Signal<Option<Revealed>>,
    rev: Signal<u64>,
) -> View {
    let target = editor.get().unwrap_or(Editor::New);
    let (title, pre) = match target {
        Editor::New => ("新增項目", None),
        Editor::Edit(id) => ("編輯項目", hub.reveal(id).ok()),
    };
    // 基線（比對差量用）與欄位訊號同源初始化；密碼副本在關閉時一併清掉。
    let base_name = pre.as_ref().map(|r| r.name.clone()).unwrap_or_default();
    let base_user = pre.as_ref().and_then(|r| r.username.clone());
    let base_pass = pre
        .as_ref()
        .and_then(|r| r.password.as_ref().map(|p| p.to_string()));
    let base_uri = pre.as_ref().and_then(|r| r.uris.first().cloned());

    let name = signal(base_name.clone());
    let user = signal(base_user.clone().unwrap_or_default());
    let pass = signal(base_pass.clone().unwrap_or_default());
    let uri = signal(base_uri.clone().unwrap_or_default());
    let err = signal(String::new());

    let close = {
        let (c_name, c_user, c_pass, c_uri, c_editor) = (name, user, pass, uri, editor);
        move || {
            // 明文紀律：欄位殘留（含密碼）先歸零再收模態。
            c_name.set(String::new());
            c_user.set(String::new());
            c_pass.set(String::new());
            c_uri.set(String::new());
            c_editor.set(None);
        }
    };

    let save_close = close;
    let save_hub = hub.clone();
    let save = move || {
        let n = name.get().trim().to_owned();
        if n.is_empty() {
            err.set("名稱為必填".to_owned());
            return;
        }
        let user_v = nonblank(&user.get());
        let pass_v = nonblank(&pass.get());
        let uri_v = nonblank(&uri.get());
        let out: Result<(), String> = match target {
            Editor::New => save_hub
                .create(&CipherDraft {
                    kind: ItemKind::Login,
                    name: n,
                    username: user_v,
                    password: pass_v,
                    totp: None,
                    uris: uri_v.map(|u| vec![u]).unwrap_or_default(),
                    notes: None,
                    favorite: false,
                })
                .map(|_| ()),
            Editor::Edit(id) => {
                let mut edits: Vec<FieldEdit> = Vec::new();
                if n != base_name {
                    edits.push(FieldEdit {
                        path: "name".into(),
                        value: Some(n),
                    });
                }
                if user_v != base_user {
                    edits.push(FieldEdit {
                        path: "username".into(),
                        value: user_v,
                    });
                }
                if pass_v != base_pass {
                    edits.push(FieldEdit {
                        path: "password".into(),
                        value: pass_v,
                    });
                }
                if uri_v != base_uri {
                    edits.push(FieldEdit {
                        path: "uri.0".into(),
                        value: uri_v,
                    });
                }
                if edits.is_empty() {
                    Ok(()) // 沒動任何欄：no-op 收工，不產生空 patch。
                } else {
                    save_hub.patch(id, &edits)
                }
            }
        };
        match out {
            Ok(()) => {
                let was_edit = matches!(target, Editor::Edit(_));
                save_close();
                if was_edit {
                    // 編輯來自詳情頁：靜態欄位不會自我重繪，回列表看新態。
                    plain.set(None);
                    selected.set(None);
                }
                if let Phase::Vault(mut s) = phase.get() {
                    s.items = save_hub.list("").len();
                    phase.set(Phase::Vault(s));
                }
                rev.set(rev.get() + 1);
            }
            // 錯誤原文顯示（閘金鑰、服務器拒絕都不改寫）。
            Err(msg) => err.set(msg),
        }
    };

    view().flex_1().items_center().justify_center().child(
        view()
            .w_full()
            .max_w(px(360.0))
            .flex_col()
            .gap_4()
            .p_6()
            .rounded(px(14.0))
            .bg(move || theme().background)
            .child(
                text(title)
                    .text_size(px(18.0))
                    .font_weight(FontWeight::SEMIBOLD),
            )
            .child(form_field("名稱", "項目名稱（必填）", name, false))
            .child(form_field("帳號", "帳號（可留空）", user, false))
            .child(form_field("密碼", "密碼（可留空）", pass, true))
            .child(form_field("網址", "網址（可留空）", uri, false))
            .child(
                text(move || err.get())
                    .text_size(px(12.0))
                    .line_height(px(17.0))
                    .text_color(move || theme().destructive),
            )
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(primary_button("儲存", save))
                    .child(ghost_button("取消", close)),
            ),
    )
}

/// 欄位值 → `Option`：全空視同未填（None＝清空語意，patch 差量的基準）。
fn nonblank(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

fn meta_rows(hub: Arc<Hub>, id: ItemId) -> View {
    let empty = view().flex_col().gap_2();
    let Ok(Some(meta)) = hub.meta(id) else {
        return empty.child(text("讀不到這筆項目的中繼資料").text_size(px(13.0)));
    };
    let mut rows = empty
        .child(labeled(
            "名稱",
            meta.name.unwrap_or_else(|| "(未命名)".to_owned()),
        ))
        .child(labeled("類型", kind_label(meta.kind)))
        .child(labeled(
            "網址",
            if meta.uris.is_empty() {
                "—".to_owned()
            } else {
                meta.uris.join("\n")
            },
        ))
        .child(labeled(
            "標籤",
            if meta.tags.is_empty() {
                "—".to_owned()
            } else {
                meta.tags.join("、")
            },
        ))
        .child(labeled(
            "更新",
            meta.updated_at.unwrap_or_else(|| "—".to_owned()),
        ))
        .child(labeled("待推送", if meta.pending { "是" } else { "否" }));
    if meta.favorite {
        rows = rows.child(labeled("收藏", "★"));
    }
    rows
}

fn labeled(label: &'static str, value: impl Into<String>) -> View {
    let value = value.into();
    view()
        .flex_col()
        .gap_0p5()
        .child(
            text(label)
                .text_size(px(11.5))
                .text_color(move || theme().muted_foreground),
        )
        .child(
            text(value)
                .text_size(px(14.0))
                .line_height(px(20.0))
                .text_color(move || theme().foreground),
        )
}

fn page_header(title: &'static str, subtitle: &'static str) -> View {
    view()
        .flex_col()
        .gap_1()
        .px_6()
        .pt_6()
        .pb_2()
        .child(
            text(title)
                .text_size(px(22.0))
                .font_weight(FontWeight::BOLD),
        )
        .child(
            text(subtitle)
                .text_size(px(12.5))
                .line_height(px(18.0))
                .text_color(move || theme().muted_foreground),
        )
}

fn form_field(
    label: &'static str,
    placeholder: &'static str,
    value: Signal<String>,
    secure: bool,
) -> View {
    view()
        .flex_col()
        .gap_1p5()
        .child(
            text(label)
                .text_size(px(13.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || theme().foreground),
        )
        .child(
            input()
                .value(move || value.get())
                .placeholder(placeholder.to_owned())
                .masked(secure)
                .on_change(move |text: &str| value.set(text.to_owned()))
                .h_11()
                .px_3()
                .rounded_lg()
                .border(px(1.0))
                .border_color(move || theme().border)
                .text_color(move || theme().foreground)
                .text_size(px(15.0)),
        )
}

fn primary_button(label: impl IntoReactive<SharedString>, on_press: impl Fn() + 'static) -> View {
    view()
        .px_6()
        .py_3()
        .rounded_lg()
        .flex_row()
        .items_center()
        .cursor_pointer()
        .bg(move || theme().primary)
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(16.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(move || theme().primary_foreground),
        )
}

fn ghost_button(label: impl IntoReactive<SharedString>, on_press: impl Fn() + 'static) -> View {
    view()
        .px_4()
        .py_2()
        .rounded_lg()
        .border(px(1.0))
        .border_color(move || theme().border)
        .flex_row()
        .items_center()
        .cursor_pointer()
        .bg(move || theme().muted)
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(13.0))
                .text_color(move || theme().foreground),
        )
}

fn divider() -> View {
    view().h(px(1.0)).w_full().bg(move || theme().border)
}

fn subtitle(item: &ItemMeta) -> String {
    if let Some(uri) = item.uris.first() {
        return uri.clone();
    }
    if item.tags.is_empty() {
        "—".to_owned()
    } else {
        item.tags.join("、")
    }
}

fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "登入",
        ItemKind::Card => "卡片",
        ItemKind::Identity => "身份",
        ItemKind::SecureNote => "安全備忘",
    }
}
