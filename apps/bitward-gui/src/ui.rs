//! 共用小元件：按鈕、徽章、欄位列、下拉面板、確認模態。
//! 樣式 setter 只在建立時求值（spike FINDINGS 卡點 1），所以反應式樣式
//! 一律在閉包內讀 theme()/訊號；固定外觀直接給值。

use bw_proto::ItemKind;
use nsh_base::{input, theme};
use nsh_core::prelude::*;

use crate::state::{AppCore, Confirm};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    Primary,
    Muted,
    Destructive,
}

pub fn button(label: &str, kind: Btn, on_press: impl Fn() + 'static) -> View {
    let label = label.to_owned();
    button_dyn(move || label.clone(), kind, on_press)
}

/// 標籤會隨狀態變動的按鈕（顯示/隱藏密碼）。
pub fn button_dyn(
    label: impl Fn() -> String + 'static,
    kind: Btn,
    on_press: impl Fn() + 'static,
) -> View {
    let text_color = match kind {
        Btn::Primary => theme().primary_foreground,
        Btn::Muted => theme().foreground,
        Btn::Destructive => theme().background,
    };
    view()
        .h_9()
        .px_4()
        .rounded_lg()
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .active(|s| s.opacity(0.7))
        .bg(move || match kind {
            Btn::Primary => theme().primary,
            Btn::Muted => theme().muted,
            Btn::Destructive => theme().destructive,
        })
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(13.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || text_color),
        )
}

/// 表單欄位：`value` 由呼叫端直接 set（輸入回聲不等命令佇列）。
pub fn form_field(
    label: &'static str,
    placeholder: &'static str,
    value: Signal<String>,
    secure: bool,
    on_change: impl Fn(String) + 'static,
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
                .on_change(move |t: &str| on_change(t.to_owned()))
                .h_10()
                .px_3()
                .rounded_lg()
                .border(px(1.0))
                .border_color(move || theme().border)
                .text_color(move || theme().foreground),
        )
}

/// 下拉面板的一列（標籤選項、排序選項共用）。
pub fn menu_row(label: String, selected: bool, on_press: impl Fn() + 'static) -> View {
    view()
        .h_9()
        .px_3()
        .flex_row()
        .items_center()
        .justify_between()
        .cursor_pointer()
        .hover(|s| s.bg(theme().accent))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(13.0))
                .text_color(move || theme().popover_foreground),
        )
        .child(
            text(if selected { "✓" } else { "" }.to_owned())
                .text_size(px(12.0))
                .text_color(move || theme().primary),
        )
}

/// 面板容器：下拉選單與確認框共用的卡殼。
pub fn card(children: Vec<View>) -> View {
    let mut c = view()
        .flex_col()
        .rounded_lg()
        .border(px(1.0))
        .border_color(move || theme().border)
        .bg(move || theme().popover)
        .py_1();
    for child in children {
        c = c.child(child);
    }
    c
}

/// 確認模態：absolute 鋪滿 + 置中卡（不用 QuickJS、不用 alert，
/// 純 Rust 元件層；背景壓暗但不吃點擊以外的互動）。
pub fn confirm_modal(core: AppCore, confirm: &Confirm) -> View {
    let title = confirm.title.clone();
    let desc = confirm.description.clone();
    let label = confirm.confirm_label.clone();
    let destructive = confirm.destructive;
    let no = core.clone();
    let no2 = core.clone();
    let yes = core.clone();
    view()
        .absolute()
        .inset(px(0.0))
        .z_index(50)
        .flex_col()
        .items_center()
        .justify_center()
        .bg(move || theme().background.opacity(0.55))
        .on_press(move || no.send(crate::state::Cmd::ConfirmNo))
        .child(
            view()
                .w(px(420.0))
                .flex_col()
                .gap_3()
                .p_5()
                .rounded_xl()
                .border(px(1.0))
                .border_color(move || theme().border)
                .bg(move || theme().popover)
                // 卡內點擊不穿透到背板（背板 on_press 會誤關）。
                .on_press(|| {})
                .child(
                    text(title)
                        .text_size(px(16.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || theme().popover_foreground),
                )
                .child(
                    text(desc)
                        .text_size(px(13.0))
                        .line_height(px(19.0))
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_end()
                        .gap_2()
                        .child(button("取消", Btn::Muted, move || {
                            no2.send(crate::state::Cmd::ConfirmNo);
                        }))
                        .child(button(
                            &label,
                            {
                                if destructive {
                                    Btn::Destructive
                                } else {
                                    Btn::Primary
                                }
                            },
                            move || yes.send(crate::state::Cmd::ConfirmYes),
                        )),
                ),
        )
}

/// 改主密碼模態：三欄 secure input（現有/新/確認）+ 繁中錯誤行 +
/// 變更/取消。背板與點擊穿透語意同 confirm_modal。
pub fn change_password_modal(core: AppCore) -> View {
    let close = core.clone();
    let close2 = core.clone();
    let submit = core.clone();
    let current = core.pw.current;
    let new = core.pw.new;
    let confirm = core.pw.confirm;
    let err_core = core.clone();
    view()
        .absolute()
        .inset(px(0.0))
        .z_index(50)
        .flex_col()
        .items_center()
        .justify_center()
        .bg(move || theme().background.opacity(0.55))
        .on_press(move || close.send(crate::state::Cmd::CloseChangePassword))
        .child(
            view()
                .w(px(420.0))
                .flex_col()
                .gap_4()
                .p_5()
                .rounded_xl()
                .border(px(1.0))
                .border_color(move || theme().border)
                .bg(move || theme().popover)
                // 卡內點擊不穿透到背板（背板 on_press 會誤關）。
                .on_press(|| {})
                .child(
                    text("變更主密碼")
                        .text_size(px(16.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || theme().popover_foreground),
                )
                .child(
                    text("改密後其他裝置需重新登入；本機鏡像與金鑰鏈保持不變。")
                        .text_size(px(12.5))
                        .line_height(px(19.0))
                        .text_color(move || theme().muted_foreground),
                )
                .child(form_field(
                    "現有主密碼",
                    "輸入目前的主密碼",
                    current,
                    true,
                    move |v| current.set(v),
                ))
                .child(form_field(
                    "新主密碼",
                    "至少 12 字元",
                    new,
                    true,
                    move |v| new.set(v),
                ))
                .child(form_field(
                    "確認新密碼",
                    "再輸入一次新主密碼",
                    confirm,
                    true,
                    move |v| confirm.set(v),
                ))
                .child(
                    text(move || err_core.pw.error.get().unwrap_or_default())
                        .text_size(px(12.5))
                        .line_height(px(18.0))
                        .text_color(move || theme().destructive),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_end()
                        .gap_2()
                        .child(button("取消", Btn::Muted, move || {
                            close2.send(crate::state::Cmd::CloseChangePassword);
                        }))
                        .child(button("變更", Btn::Primary, move || {
                            submit.send(crate::state::Cmd::SubmitChangePassword);
                        })),
                ),
        )
}

/// 頁面標題列（詳情/表單共用的返回列）。
pub fn page_header(title: String, on_back: impl Fn() + 'static) -> View {
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_6()
        .py_4()
        .border_b(px(1.0))
        .border_color(move || theme().border)
        .child(
            view()
                .h_8()
                .px_3()
                .rounded_lg()
                .flex_row()
                .items_center()
                .cursor_pointer()
                .active(|s| s.opacity(0.7))
                .bg(move || theme().muted)
                .on_press(on_back)
                .child(text("← 返回").text_size(px(13.0))),
        )
        .child(
            text(title)
                .text_size(px(17.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(move || theme().foreground),
        )
}

pub fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "登入",
        ItemKind::SecureNote => "安全備註",
        ItemKind::Card => "卡片",
        ItemKind::Identity => "身分",
    }
}

/// 只取日期部分；updated_at 是 ISO-8601 字串（契約 §2 原樣保存）。
pub fn short_date(updated_at: Option<&str>) -> String {
    updated_at
        .map(|d| d.get(..10).unwrap_or(d).to_owned())
        .unwrap_or_else(|| "—".to_owned())
}
