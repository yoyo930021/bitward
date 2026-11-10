//! Send 加密分享（路線 5）：右欄視角，側欄「Send」進入。
//! 清單（型別章＋名稱／到期／存取計數／已檢視＋複製連結／移除）↔ 新增表單
//! （文字/檔案二選一、內容/路徑、取用密碼選填、到期天數、次數上限）
//! → 成功卡（URL＋複製鈕，官方 send-success 流）。
//! **接收端不做**（開網頁的人用的，不是本客戶端職責）；建立需連網
//! （daemon 無 outbox，離線錯誤走表單紅字誠實標註）。
//! 清單資料源＝daemon 鏡像（連網時現刷）；名稱與 URL 鎖態為 null。

use std::sync::Arc;

use bw_proto::ItemId;
use nsh_core::prelude::*;
use serde_json::Value;

use crate::state::{AppCore, Cmd, SendKind, SendTab};
use crate::theme;
use crate::ui;

/// 清單列（`SendOp::List` 回包投影；欄位缺失走預設而非跳列——
/// 鏡像欄由 daemon 從伺服器 JSON 直抄，形態以實錄為準）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRow {
    pub id: ItemId,
    pub is_file: bool,
    pub name: Option<String>,
    pub url: Option<String>,
    pub deletion_date: String,
    pub access_count: i64,
    pub max_access: Option<i64>,
    pub viewed: bool,
}

/// `{"items":[...]}` → 列（id 解析失敗跳列：幽靈列不如不顯示）。
pub fn send_rows(v: &Value) -> Vec<SendRow> {
    v.get("items")
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let id = ItemId::parse_str(r.get("id")?.as_str()?).ok()?;
                    Some(SendRow {
                        id,
                        is_file: r.get("type").and_then(Value::as_i64) == Some(1),
                        name: r.get("name").and_then(Value::as_str).map(str::to_owned),
                        url: r.get("url").and_then(Value::as_str).map(str::to_owned),
                        deletion_date: r
                            .get("deletionDate")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        access_count: r.get("accessCount").and_then(Value::as_i64).unwrap_or(0),
                        max_access: r.get("maxAccessCount").and_then(Value::as_i64),
                        viewed: r.get("viewed").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// ISO `2026-11-11T14:23:53…Z` → `11-11 14:23`（UTC；解析失敗原樣截斷，
/// 顯示用欄不藏錯誤）。
pub fn fmt_expiry(iso: &str) -> String {
    let bytes = iso.as_bytes();
    if bytes.len() >= 16 && bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b'T' {
        format!("{} {}", &iso[5..10], &iso[11..16])
    } else if iso.is_empty() {
        "—".to_owned()
    } else {
        iso.chars().take(16).collect()
    }
}

/// Send 頁視角（右欄整塊）：tab 訊號切清單／表單，成功卡掛表單態之上。
pub fn pane(core: AppCore) -> View {
    let tab_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .px_8()
        .py_5()
        .gap_4()
        .child(dynamic(move || match tab_core.send_tab.get() {
            SendTab::List => list_view(core.clone()),
            SendTab::Create => match core.send_created.get() {
                Some(created) => created_view(core.clone(), created),
                None => form_view(core.clone()),
            },
        }))
}

/// 清單：標題＋新增鈕＋列表；鎖態提示（名稱/URL 需金鑰）。
fn list_view(core: AppCore) -> View {
    let add_core = core.clone();
    let each_core = core.clone();
    let copied: Signal<Option<&'static str>> = signal(None);
    view()
        .flex_1()
        .flex_col()
        .gap_4()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(
                    text("Send")
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(view().flex_1())
                .child(ui::button("+ 新增 Send", ui::Btn::Primary, move || {
                    add_core.send(Cmd::ShowSendsTab(SendTab::Create))
                })),
        )
        .child(when(
            move || !crate::state::is_unlocked(&core.vault.get()),
            || {
                text("解鎖後重進本頁可查看名稱與複製連結（seed 是金鑰信封，鎖態解不開）")
                    .text_size(px(theme::TEXT_PAGE_SUB))
                    .text_color(theme::TEXT_MUTED)
            },
        ))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_2()
                .w_full()
                .max_w(px(680.0))
                .child(each(
                    move || send_rows(&core.sends.get()),
                    |r: &SendRow| r.id,
                    move |row: ReadSignal<SendRow>, _| {
                        send_row(row.get(), each_core.clone(), copied)
                    },
                ))
                .child(when(move || send_rows(&core.sends.get()).is_empty(), || {
                    view()
                        .flex_col()
                        .gap_1()
                        .child(row_note("還沒有分享。文字或檔案都能加密成一條連結。"))
                        .child(row_note("建立需要連網：Send 不走離線佇列（交連結即存在）。"))
                })),
        ))
}

/// 單列：型別章＋名稱＋到期＋存取計數＋已檢視點＋複製連結＋移除。
fn send_row(row: SendRow, core: AppCore, copied: Signal<Option<&'static str>>) -> View {
    let name = row.name.clone().unwrap_or_else(|| "—".into());
    let url_for_copy = row.url.clone().unwrap_or_default();
    let rm_core = core.clone();
    let (ask_id, ask_name) = (row.id, row.name.clone().unwrap_or_else(|| "未命名".into()));
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .min_h(px(theme::ROW_H))
        .px_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .child(ui::badge(
            if row.is_file { "檔案" } else { "文字" },
            theme::ACCENT,
            theme::SURFACE,
        ))
        .child(
            text(name)
                .text_size(px(theme::TEXT_ROW))
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(view().flex_1())
        .child(row_note(format!("到期 {}", fmt_expiry(&row.deletion_date))))
        .child(row_note(format!(
            "存取 {}/{}",
            row.access_count,
            row.max_access.map(|m| m.to_string()).unwrap_or_else(|| "∞".into())
        )))
        .child(when(move || row.viewed, || {
            view()
                .flex_row()
                .items_center()
                .gap_1()
                .child(
                    view()
                        .w(px(8.0))
                        .h(px(8.0))
                        .rounded(px(4.0))
                        .bg(theme::SUCCESS),
                )
                .child(row_note("已檢視"))
        }))
        .child(ui::copy_button(
            std::rc::Rc::new(move || url_for_copy.clone()),
            "Send 連結",
            copied,
            core.settings,
        ))
        .child(ui::button("移除", ui::Btn::Ghost, move || {
            rm_core.send(Cmd::AskDeleteSend {
                id: ask_id,
                name: ask_name.clone(),
            })
        }))
}

/// 新增表單：型別二選一→內容欄→選填項。送出成功即換成功卡。
fn form_view(core: AppCore) -> View {
    let back_core = core.clone();
    let submit_core = core.clone();
    let text_core = core.clone();
    let path_core = core.clone();
    let days_core = core.clone();
    let pw_core = core.clone();
    let max_core = core.clone();
    let hide_core = core.clone();
    let kind_text = core.clone();
    let kind_file = core.clone();
    view()
        .flex_1()
        .flex_col()
        .gap_4()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(ui::button("返回", ui::Btn::Ghost, move || {
                    back_core.send(Cmd::ShowSendsTab(SendTab::List));
                    back_core.send(Cmd::FetchSends);
                }))
                .child(
                    text("新增 Send")
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                ),
        )
        .child(
            view()
                .flex_row()
                .gap_2()
                .child(crate::list::chip(
                    "文字".to_owned(),
                    move || kind_text.send_form.kind.get() == SendKind::Text,
                    move || kind_text.send_form.kind.set(SendKind::Text),
                ))
                .child(crate::list::chip(
                    "檔案".to_owned(),
                    move || kind_file.send_form.kind.get() == SendKind::File,
                    move || kind_file.send_form.kind.set(SendKind::File),
                )),
        )
        .child(dynamic(move || match core.send_form.kind.get() {
            SendKind::Text => view().child(ui::form_field(
                "內容",
                "要分享的文字",
                text_core.send_form.text,
                false,
                move |t| text_core.send_form.text.set(t),
            )),
            SendKind::File => view().child(ui::form_field(
                "檔案路徑",
                "/Users/you/file.pdf",
                path_core.send_form.path,
                false,
                move |t| path_core.send_form.path.set(t),
            )),
        }))
        .child(ui::form_field(
            "取用密碼（選填）",
            "留空＝不設",
            pw_core.send_form.password,
            true,
            move |t| pw_core.send_form.password.set(t),
        ))
        .child(
            view()
                .flex_col()
                .gap_2()
                .child(row_note("到期刪除"))
                .child(
                    view()
                        .flex_row()
                        .gap_2()
                        .child(crate::list::chip(
                            "1 天".to_owned(),
                            move || days_core.send_form.days.get() == 1,
                            {
                                let c = days_core.clone();
                                move || c.send_form.days.set(1)
                            },
                        ))
                        .child(crate::list::chip(
                            "7 天".to_owned(),
                            move || days_core.send_form.days.get() == 7,
                            {
                                let c = days_core.clone();
                                move || c.send_form.days.set(7)
                            },
                        ))
                        .child(crate::list::chip(
                            "30 天".to_owned(),
                            move || days_core.send_form.days.get() == 30,
                            {
                                let c = days_core.clone();
                                move || c.send_form.days.set(30)
                            },
                        )),
                ),
        )
        .child(ui::form_field(
            "存取上限（選填）",
            "留空＝不限",
            max_core.send_form.max,
            false,
            move |t| max_core.send_form.max.set(t),
        ))
        .child({
            let lbl_core = hide_core.clone();
            let sel_core = hide_core.clone();
            let press_core = hide_core.clone();
            crate::list::chip_dyn(
                move || {
                    if lbl_core.send_form.hide_email.get() {
                        "✓ 對接收方隱藏我的 Email".to_owned()
                    } else {
                        "對接收方隱藏我的 Email".to_owned()
                    }
                },
                move || sel_core.send_form.hide_email.get(),
                move || press_core.send_form.hide_email.update(|v| *v = !*v),
            )
        })
        .child(dynamic(move || match core.send_form.error.get() {
            Some(e) => view().child(
                text(e)
                    .text_size(px(theme::TEXT_ROW_SUB))
                    .text_color(theme::DESTRUCTIVE),
            ),
            None => view(),
        }))
        .child(
            view()
                .flex_row()
                .gap_3()
                .child(ui::button("建立連結", ui::Btn::Primary, move || {
                    submit_core.send(Cmd::SubmitSend)
                })),
        )
        .child(row_note(
            "建立需要連網與解鎖（Send 無離線佇列）；連結含金鑰片段，伺服器看不到內容。",
        ))
}

/// 成功卡：URL＋複製鈕（官方 send-success 流）。
fn created_view(core: AppCore, created: Arc<Value>) -> View {
    let url = created
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let done_core = core.clone();
    let again_core = core.clone();
    let copied: Signal<Option<&'static str>> = signal(None);
    let name = created
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("Send")
        .to_owned();
    view()
        .flex_col()
        .gap_4()
        .max_w(px(680.0))
        .child(
            text("分享已建立")
                .text_size(px(theme::TEXT_PAGE_TITLE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(row_note(format!("「{name}」— 把連結交給對方，開網頁即可收（本站不需接收端）。")))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .p_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .child(
                    text(url.clone())
                        .text_size(px(theme::TEXT_ROW_SUB))
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(ui::copy_button(
                    std::rc::Rc::new(move || url.clone()),
                    "Send 連結",
                    copied,
                    core.settings,
                )),
        )
        .child(
            view()
                .flex_row()
                .gap_3()
                .child(ui::button("再分享一個", ui::Btn::Ghost, move || {
                    again_core.send(Cmd::ShowSendsTab(SendTab::Create))
                }))
                .child(ui::button("完成", ui::Btn::Primary, move || {
                    done_core.send(Cmd::ShowSendsTab(SendTab::List));
                    done_core.send(Cmd::FetchSends);
                })),
        )
}

/// 次要說明列（清單列內欄位、提示共用）。
fn row_note(msg: impl Into<String>) -> View {
    view().child(
        text(msg.into())
            .text_size(px(theme::TEXT_ROW_SUB))
            .text_color(theme::TEXT_MUTED),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_parse_tolerantly() {
        let v = serde_json::json!({"items": [
            {"id": "6fe8bae0-e019-48fb-a651-f9e3514d156e", "type": 1, "name": null,
             "url": null, "deletionDate": "2026-11-17T13:49:27.000000Z",
             "accessCount": 3, "maxAccessCount": null, "viewed": true},
            {"id": "not-a-uuid", "type": 0},
        ]});
        let rows = send_rows(&v);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_file);
        assert_eq!(rows[0].access_count, 3);
        assert_eq!(rows[0].max_access, None);
        assert!(rows[0].viewed);
        assert!(rows[0].name.is_none());
        assert!(send_rows(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn expiry_formats_iso_only() {
        assert_eq!(fmt_expiry("2026-11-11T14:23:53.000000Z"), "11-11 14:23");
        assert_eq!(fmt_expiry(""), "—");
        assert_eq!(fmt_expiry("garbage"), "garbage");
    }
}
