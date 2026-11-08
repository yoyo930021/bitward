//! 共用小元件：按鈕、徽章、monogram、欄位列、下拉面板、模態殼。
//! 樣式 setter 只在建立時求值（spike FINDINGS 卡點 1），所以反應式樣式
//! 一律在閉包內讀 theme()/訊號；固定外觀直接給值。顏色全部出自
//! `crate::theme` tokens，本檔不寫 hex。

use std::rc::Rc;
use std::time::Duration;

use bw_proto::ItemKind;
use nsh_base::{input, theme};
use nsh_core::prelude::*;

use crate::state::{AppCore, Confirm};
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    /// 藍紫漸變主按鈕。
    Primary,
    /// 漸變膠囊（標題列「＋ 新增」）。
    PrimaryCapsule,
    /// 透明描邊次按鈕（取消等）。
    Ghost,
    /// 危險實色（刪除確認）。
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
    let capsule = kind == Btn::PrimaryCapsule;
    let base = view()
        .h_9()
        .px(px(if capsule { 20.0 } else { 16.0 }))
        .rounded(px(if capsule { 18.0 } else { 9.0 }))
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .transition_colors()
        .duration(150.0)
        .active(|s| s.opacity(0.7))
        .on_press(on_press);
    let styled = match kind {
        Btn::Primary | Btn::PrimaryCapsule => base
            .bg_linear_to_r()
            .gradient_from(theme::ACCENT_FROM)
            .gradient_to(theme::ACCENT_TO),
        Btn::Ghost => base
            .border(px(1.0))
            .border_color(theme::HAIRLINE)
            .hover(|s| s.bg(theme::SURFACE_RAISED)),
        Btn::Destructive => base.bg(theme::DESTRUCTIVE),
    };
    styled.child(
        text(label)
            .text_size(px(13.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(match kind {
                Btn::Ghost => theme::TEXT_SECONDARY,
                _ => theme::TEXT_PRIMARY,
            }),
    )
}

/// 表單欄位：`value` 由呼叫端直接 set（輸入回聲不等命令佇列）。
/// focus 時描邊轉 accent（transition_colors 過渡）。
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
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .letter_spacing(px(0.4))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(
            input()
                .value(move || value.get())
                .placeholder(placeholder.to_owned())
                .placeholder_color(move || theme::TEXT_MUTED.light)
                .masked(secure)
                .on_change(move |t: &str| on_change(t.to_owned()))
                .h_10()
                .px_3()
                .rounded_lg()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .text_color(theme::TEXT_PRIMARY)
                .transition_colors()
                .duration(150.0)
                .focus(|s| s.border_color(theme::ACCENT)),
        )
}

/// 下拉面板的一列（排序選項用；標籤已改 chips）。
pub fn menu_row(label: String, selected: bool, on_press: impl Fn() + 'static) -> View {
    view()
        .h_9()
        .px_3()
        .flex_row()
        .items_center()
        .justify_between()
        .cursor_pointer()
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(13.0))
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(
            text(if selected { "✓" } else { "" }.to_owned())
                .text_size(px(12.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::ACCENT),
        )
}

/// 浮層卡殼：下拉選單共用（模態走 `modal_shell`）。
pub fn card(children: Vec<View>) -> View {
    let mut c = view()
        .flex_col()
        .rounded_xl()
        .overflow_hidden()
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .py_1()
        .child(view().h(px(1.0)).mx_3().bg(theme::HIGHLIGHT));
    for child in children {
        c = c.child(child);
    }
    c
}

/// 模態殼：absolute 鋪滿背板（點擊即 `on_close`）＋置中 elevated 卡。
/// 卡自帶大圓角、1px 描邊、頂部高光線與投影，按鈕群归呼叫端。
/// 卡內點擊以空 `on_press` 擋穿透（背板 on_press 會誤關）。
pub fn modal_shell(width: f32, on_close: impl Fn() + 'static, card: View) -> View {
    view()
        .absolute()
        .inset(px(0.0))
        .z_index(50)
        .flex_col()
        .items_center()
        .justify_center()
        .bg(theme::SCRIM)
        .on_press(on_close)
        .child(
            view()
                .w(px(width))
                .flex_col()
                .gap_4()
                .p_6()
                .rounded_2xl()
                .overflow_hidden()
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
                .on_press(|| {})
                .child(
                    view()
                        .absolute()
                        .top_0()
                        .left_0()
                        .right_0()
                        .h(px(1.0))
                        .bg(theme::HIGHLIGHT),
                )
                .child(card),
        )
}

/// 確認模態：刪除/匯出共用；背景壓暗不吃卡外互動以外的語意同舊版。
pub fn confirm_modal(core: AppCore, confirm: &Confirm) -> View {
    let title = confirm.title.clone();
    let desc = confirm.description.clone();
    let label = confirm.confirm_label.clone();
    let destructive = confirm.destructive;
    let no = core.clone();
    let no2 = core.clone();
    let yes = core.clone();
    modal_shell(
        440.0,
        move || no.send(crate::state::Cmd::ConfirmNo),
        view()
            .flex_col()
            .gap_3()
            .child(
                text(title)
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
            )
            .child(
                text(desc)
                    .text_size(px(13.0))
                    .line_height(px(20.0))
                    .text_color(theme::TEXT_SECONDARY),
            )
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .justify_end()
                    .gap_2()
                    .child(button("取消", Btn::Ghost, move || {
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
    modal_shell(
        440.0,
        move || close.send(crate::state::Cmd::CloseChangePassword),
        view()
            .flex_col()
            .gap_4()
            .child(
                text("變更主密碼")
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
            )
            .child(
                text("改密後其他裝置需重新登入；本機鏡像與金鑰鏈保持不變。")
                    .text_size(px(12.5))
                    .line_height(px(19.0))
                    .text_color(theme::TEXT_MUTED),
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
                    .text_color(theme::DESTRUCTIVE),
            )
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .justify_end()
                    .gap_2()
                    .child(button("取消", Btn::Ghost, move || {
                        close2.send(crate::state::Cmd::CloseChangePassword);
                    }))
                    .child(button("變更", Btn::Primary, move || {
                        submit.send(crate::state::Cmd::SubmitChangePassword);
                    })),
            ),
    )
}

/// monogram 色塊：名字首字＋穩定派生底色（列表 36/詳情 64 共用）。
pub fn monogram(
    name: impl Fn() -> Option<String> + 'static,
    size: f32,
    radius: f32,
    letter: f32,
) -> View {
    let name = Rc::new(name);
    let name_bg = name.clone();
    let name_char = name;
    view()
        .w(px(size))
        .h(px(size))
        .rounded(px(radius))
        .flex_row()
        .items_center()
        .justify_center()
        .overflow_hidden()
        .bg(move || theme::monogram_color(name_bg().as_deref()))
        .child(
            text(move || theme::monogram_char(name_char().as_deref()))
                .text_size(px(letter))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
}

/// 小膠囊徽章（待推送/提示）；前景背景色由呼叫端給 tokens。
pub fn badge(label: &'static str, fg: AdaptiveColor, bg: AdaptiveColor) -> View {
    view()
        .h(px(20.0))
        .px_2()
        .rounded_full()
        .flex_row()
        .items_center()
        .bg(bg)
        .child(
            text(label)
                .text_size(px(11.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(fg),
        )
}

/// 節標題：12px 大寫、字距拉開、muted（詳情分節用）。
pub fn section_title(label: &'static str) -> Text {
    text(label)
        .text_size(px(12.0))
        .font_weight(FontWeight::SEMIBOLD)
        .uppercase()
        .letter_spacing(px(1.2))
        .text_color(theme::TEXT_MUTED)
}

/// 複製鈕：按下寫系統剪貼簿、圖示轉 success 勾 1 秒後復原。
/// `value` 在按下當下求值（跟著 detail/revealed 訊號走）。
pub fn copy_button(
    value: Rc<dyn Fn() -> String>,
    token: &'static str,
    copied: Signal<Option<&'static str>>,
) -> View {
    let press = value;
    view()
        .w(px(26.0))
        .h(px(26.0))
        .rounded_md()
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || {
            let v = press();
            if !v.is_empty() && v != "—" {
                set_clipboard(v);
            }
            copied.set(Some(token));
            set_timeout(Duration::from_millis(1000), move || {
                if copied.get() == Some(token) {
                    copied.set(None);
                }
            });
        })
        .child(
            text(move || if copied.get() == Some(token) { "✓" } else { "⧉" }.to_owned())
                .text_size(px(13.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(move || {
                    if copied.get() == Some(token) {
                        theme::SUCCESS
                    } else {
                        theme::TEXT_MUTED
                    }
                }),
        )
}

/// 「顯示/隱藏」文字鈕（密碼列內聯，取代舊實色按鈕）。
pub fn text_button_dyn(
    label: impl Fn() -> String + 'static,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .h_7()
        .px_2()
        .rounded_md()
        .flex_row()
        .items_center()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(12.5))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::ACCENT),
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

/// 詳情頁讀 theme() 的 mono 字體（revealed 密碼用）；缺字體退回平台等宽。
pub fn mono_font() -> SharedString {
    if let Some(mono) = theme().font_mono.clone() {
        return mono;
    }
    #[cfg(target_os = "macos")]
    {
        "Menlo".into()
    }
    #[cfg(not(target_os = "macos"))]
    {
        "monospace".into()
    }
}
