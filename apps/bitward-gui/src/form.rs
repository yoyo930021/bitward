//! 新增/編輯模態：name/username/password/uri/tags → Vault:Create / Vault:Patch。
//! 表單明文（密碼欄）只進訊號與送出時的 `Zeroizing` 副本，加密前不落盤；
//! 送出與差異計算在 `state::submit_form`。背板點擊＝取消（回列表）。
//! 密碼欄附產生器：「產生」展開面板，隨機數走 daemon `Use:GeneratePassword`。

use std::rc::Rc;

use nsh_core::prelude::*;

use crate::passgen::GenState;
use crate::state::{AppCore, Cmd, Route};
use crate::theme;
use crate::ui;

pub fn overlay(core: AppCore) -> View {
    let (title, pw_hint) = match core.route.get() {
        Route::Create => ("新增項目", "（可留空）"),
        Route::Edit(_) => ("編輯項目", "（不變更；輸入新值以替換）"),
        _ => return view().flex_1(),
    };
    let back = core.clone();
    let back2 = core.clone();
    let save = core.clone();
    let err_core = core.clone();
    let name = core.form.name;
    let username = core.form.username;
    let password = core.form.password;
    let uri = core.form.uri;
    let tags = core.form.tags;
    let gen_panel = core.form.gen_panel;
    let gen_panel_cond = core.clone();
    let gen_panel_build = core.clone();
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
            .child(ui::form_field("名稱", "例：GitHub", name, false, move |v| {
                name.set(v)
            }))
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
                        ui::form_field(
                            "密碼",
                            pw_hint,
                            password,
                            true,
                            move |v| password.set(v),
                        )
                        .flex_1(),
                    )
                    .child(ui::button_dyn(
                        move || if gen_panel.get().open { "收起" } else { "產生" }.to_owned(),
                        ui::Btn::Ghost,
                        move || gen_panel.update(|g| g.open = !g.open),
                    )),
            )
            .child(when(
                move || gen_panel_cond.form.gen_panel.get().open,
                move || generator(gen_panel_build.clone()),
            ))
            .child(ui::form_field(
                "網址",
                "https://example.com",
                uri,
                false,
                move |v| uri.set(v),
            ))
            .child(ui::form_field(
                "標籤",
                "逗號分隔，例：dev, 工作",
                tags,
                false,
                move |v| tags.set(v),
            ))
            .child(
                text("密碼以明文進入加密前的 Outgoing 幀；本介面不落盤、不緩存任何明文。")
                    .text_size(px(12.0))
                    .line_height(px(18.0))
                    .text_color(theme::TEXT_MUTED),
            )
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
