//! 共用小元件：按鈕（藍實色）、徽章、型別磚、值塊欄位、下拉面板、模態殼。
//! 樣式 setter 只在建立時求值（spike FINDINGS 卡點 1），所以反應式樣式
//! 一律在閉包內讀 theme()/訊號；固定外觀直接給值。顏色全部出自
//! `crate::theme` tokens，本檔不寫 hex。

use std::rc::Rc;
use std::time::Duration;

use bw_proto::ItemKind;
use nsh_base::{input, theme};
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Confirm};
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    /// 藍實色主按鈕（官方不漸變）。
    Primary,
    /// 藍實色寬鈕（頂部列「＋ 新增項目」、解鎖）。
    PrimaryWide,
    /// 白底描邊次按鈕（取消等）。
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
    let wide = kind == Btn::PrimaryWide;
    let base = view()
        .h(px(theme::INPUT_H))
        .px(px(if wide { 20.0 } else { 16.0 }))
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .transition_colors()
        .duration(150.0)
        .active(|s| s.opacity(0.7))
        .on_press(on_press);
    let styled = match kind {
        Btn::Primary | Btn::PrimaryWide => base
            .bg(theme::ACCENT)
            .hover(|s| s.bg(theme::ACCENT_HOVER)),
        Btn::Ghost => base
            .bg(theme::BASE)
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
                _ => theme::TEXT_ON_ACCENT,
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
        .gap_1()
        .child(
            text(label)
                .text_size(px(theme::TEXT_FIELD_LABEL))
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
                .h(px(theme::INPUT_H))
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::BASE)
                .text_color(theme::TEXT_PRIMARY)
                .transition_colors()
                .duration(150.0)
                .focus(|s| s.border_color(theme::ACCENT)),
        )
}

/// 下拉面板的一列（排序選項用；標籤已改 chips）。
pub fn menu_row(label: String, selected: bool, on_press: impl Fn() + 'static) -> View {
    view()
        .h(px(theme::INPUT_H))
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
        .rounded(px(theme::RADIUS_BLOCK))
        .overflow_hidden()
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .py_1()
        .shadow(vec![BoxShadow {
            offset_x: px(0.0),
            offset_y: px(6.0),
            blur: px(20.0),
            spread: px(-4.0),
            color: black().opacity(0.14).into(),
            inset: false,
        }])
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
                .gap(px(theme::FORM_GAP))
                .p_6()
                .rounded(px(theme::RADIUS_CARD))
                .overflow_hidden()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::ELEVATED)
                .shadow(vec![BoxShadow {
                    offset_x: px(0.0),
                    offset_y: px(12.0),
                    blur: px(32.0),
                    spread: px(-8.0),
                    color: black().opacity(0.18).into(),
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

/// 匯入模態：路徑輸入（nsh 選檔面板僅支援圖片→貼路徑兜底）→ 預覽計數
/// （本地解析，不回明文）→ 確認匯入（逐筆既有 Create 路徑）。
pub fn import_modal(core: AppCore) -> View {
    let close = core.clone();
    let close2 = core.clone();
    let path = core.import_path;
    let preview = core.clone();
    let line_cond = core.clone();
    let line_build = core.clone();
    let run_cond = core.clone();
    let run_build = core.clone();
    modal_shell(
        480.0,
        move || close.send(Cmd::CloseImport),
        view()
            .flex_col()
            .gap(px(theme::FORM_GAP))
            .child(
                text("匯入")
                    .text_size(px(17.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
            )
            .child(
                text("支援官方 Bitwarden「未加密 JSON」匯出檔與本 App 匯出檔。桌面選檔面板目前僅支援圖片，請直接貼上檔案路徑。")
                    .text_size(px(12.5))
                    .line_height(px(19.0))
                    .text_color(theme::TEXT_MUTED),
            )
            .child(
                input()
                    .value(move || path.get())
                    .placeholder("例：~/Downloads/bitward-export-….json")
                    .placeholder_color(move || theme::TEXT_MUTED.light)
                    .on_change(move |t: &str| path.set(t.to_owned()))
                    .h(px(theme::INPUT_H))
                    .px_3()
                    .rounded(px(theme::RADIUS_CONTROL))
                    .border(px(1.0))
                    .border_color(theme::HAIRLINE)
                    .bg(theme::BASE)
                    .text_color(theme::TEXT_PRIMARY)
                    .font_family(mono_font())
                    .transition_colors()
                    .duration(150.0)
                    .focus(|s| s.border_color(theme::ACCENT)),
            )
            .child(when(
                move || line_cond.import_preview.get().is_some(),
                move || {
                    let c = line_build.clone();
                    text(move || match c.import_preview.get() {
                        Some(Ok((n, skipped))) => format!("偵測到 {n} 筆可匯入（跳過 {skipped} 筆）"),
                        Some(Err(e)) => e.clone(),
                        None => String::new(),
                    })
                    .text_size(px(12.5))
                    .line_height(px(18.0))
                    .text_color(move || {
                        match line_build.import_preview.get() {
                            Some(Ok(_)) => theme::SUCCESS,
                            _ => theme::DESTRUCTIVE,
                        }
                    })
                },
            ))
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .justify_end()
                    .gap_2()
                    .child(button("取消", Btn::Ghost, move || {
                        close2.send(Cmd::CloseImport)
                    }))
                    .child(button("預覽", Btn::Ghost, move || {
                        preview.send(Cmd::ImportPreview)
                    }))
                    .child(when(
                        move || matches!(run_cond.import_preview.get(), Some(Ok(_))),
                        move || {
                            let c = run_build.clone();
                            button("匯入", Btn::Primary, move || c.send(Cmd::ImportRun))
                        },
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
            .gap(px(theme::FORM_GAP))
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

/// 型別字形：官方用單色 icon；nsh 無 icon 系統，以 Unicode 字形＋
/// U+FE0E（text presentation）強制單色、跟文字色走。Card 的 💳 在
/// macOS 仍可能落到彩色 emoji（無單色 dingbat 對等字），屬已知取捨。
pub fn type_glyph(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "🌐\u{fe0e}",
        ItemKind::Card => "💳\u{fe0e}",
        ItemKind::Identity => "⚷\u{fe0e}",
        ItemKind::SecureNote => "✎\u{fe0e}",
    }
}

/// 型別磚：淡灰圓角方磚＋單色型別字形（取代 monogram 派生色磚；
/// 列表 32／詳情 44 共用）。
pub fn type_tile(kind: impl Fn() -> ItemKind + 'static, size: f32, glyph: f32) -> View {
    view()
        .w(px(size))
        .h(px(size))
        .rounded(px(theme::RADIUS_BLOCK))
        .flex_row()
        .items_center()
        .justify_center()
        .bg(theme::SURFACE_RAISED)
        .child(
            text(move || type_glyph(kind()))
                .text_size(px(glyph))
                .text_color(theme::TEXT_SECONDARY),
        )
}

/// 小號膠囊徽章（待推送/提示）；前景背景色由呼叫端給 tokens。
pub fn badge(label: &'static str, fg: AdaptiveColor, bg: AdaptiveColor) -> View {
    view()
        .h(px(theme::BADGE_H))
        .px_1p5()
        .rounded_full()
        .flex_row()
        .items_center()
        .bg(bg)
        .child(
            text(label)
                .text_size(px(theme::TEXT_BADGE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(fg),
        )
}

/// tooltip 內容卡（nsh 的 tooltip 收元素，浮層自帶底與描邊）。
pub fn tooltip_card(msg: &str) -> View {
    view()
        .px_2p5()
        .py_1p5()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .shadow(vec![BoxShadow {
            offset_x: px(0.0),
            offset_y: px(4.0),
            blur: px(12.0),
            spread: px(-2.0),
            color: black().opacity(0.18).into(),
            inset: false,
        }])
        .child(
            text(msg.to_owned())
                .text_size(px(12.0))
                .text_color(theme::TEXT_SECONDARY),
        )
}

/// 節標題：12px 粗灰（官方詳情分節）。
pub fn section_title(label: &'static str) -> Text {
    text(label)
        .text_size(px(theme::TEXT_FIELD_LABEL))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(theme::TEXT_SECONDARY)
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
        .w(px(theme::COPY_BTN))
        .h(px(theme::COPY_BTN))
        .rounded(px(5.0))
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
                .text_size(px(11.0))
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

/// 布林開關幾何（編輯列與詳情共用）：on＝accent 軌＋knob 右，
/// off＝淡灰軌＋knob 左。`on` 為反應式取值；純視覺，點擊語意由呼叫端包。
pub fn bool_switch(on: impl Fn() -> bool + 'static) -> View {
    let pad = (theme::TOGGLE_H - theme::TOGGLE_KNOB) / 2.0;
    let on = std::rc::Rc::new(on);
    let on_bg = on.clone();
    let on_knob = on;
    view()
        .w(px(theme::TOGGLE_W))
        .h(px(theme::TOGGLE_H))
        .rounded_full()
        .relative()
        .bg(move || {
            if on_bg() {
                theme::ACCENT
            } else {
                theme::SURFACE_RAISED
            }
        })
        .child(
            view()
                .absolute()
                .top(px(pad))
                .left(move || {
                    if on_knob() {
                        px(theme::TOGGLE_W - theme::TOGGLE_KNOB - pad)
                    } else {
                        px(pad)
                    }
                })
                .w(px(theme::TOGGLE_KNOB))
                .h(px(theme::TOGGLE_KNOB))
                .rounded_full()
                .bg(theme::ELEVATED)
                .border(px(1.0))
                .border_color(theme::HAIRLINE),
        )
}

/// 自訂欄型別的顯示名（選單與膠囊共用）。
pub fn field_kind_label(kind: bw_proto::CipherFieldKind) -> &'static str {
    match kind {
        bw_proto::CipherFieldKind::Text => "文字",
        bw_proto::CipherFieldKind::Hidden => "隱藏",
        bw_proto::CipherFieldKind::Boolean => "布林",
    }
}
