//! 獨立密碼產生器頁（批次 9：官方客戶端同款工具）。
//! 右欄視角，側欄「產生密碼」進入：大字等寬現值＋強度條＋長度滑桿＋
//! 六開關＋重新產生／複製。隨機數走 daemon `Use:GeneratePassword`
//! （與表單產生器同源）；滑桿與開關膠囊沿用 `form` 的共用元件（零複製），
//! 狀態機是 `passgen::GenState` 的第二实例。

use std::rc::Rc;

use nsh_core::prelude::*;

use crate::form;
use crate::passgen;
use crate::reports;
use crate::state::{AppCore, Cmd};
use crate::theme;
use crate::ui;

pub fn pane(core: AppCore) -> View {
    let gstate = core.gen_tool;
    let pw = core.gen_tool_pw;
    let regen = core.clone();
    let copied = signal::<Option<&'static str>>(None);
    let disp: Rc<dyn Fn() -> String> = {
        let c = core.clone();
        Rc::new(move || c.gen_tool_pw.get().unwrap_or_default())
    };
    view()
        .flex_col()
        .flex_1()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_8()
                .py_4()
                .child(
                    text("產生密碼")
                        .text_size(px(theme::TEXT_IDENTITY))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                ),
        )
        .child(view().h(px(1.0)).mx_8().bg(theme::HAIRLINE))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_5()
                .px_8()
                .py_4()
                .w_full()
                .max_w(px(680.0))
                // 現值＋強度條
                .child(
                    view()
                        .flex_col()
                        .gap_2()
                        .p_4()
                        .rounded_lg()
                        .border(px(1.0))
                        .border_color(theme::HAIRLINE)
                        .bg(theme::SURFACE)
                        .child(
                            text(move || pw.get().unwrap_or_else(|| "—".into()))
                                .text_size(px(24.0))
                                .font_family(ui::mono_font())
                                .text_color(theme::TEXT_PRIMARY)
                                .line_height(px(32.0)),
                        )
                        .child(strength_bar(core.clone())),
                )
                // 長度滑桿
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .child(
                            text("長度")
                                .text_size(px(theme::TEXT_FIELD_LABEL))
                                .font_weight(FontWeight::MEDIUM)
                                .letter_spacing(px(0.4))
                                .text_color(theme::TEXT_SECONDARY),
                        )
                        .child(form::slider_on(gstate))
                        .child(
                            text(move || format!("{}", gstate.get().length))
                                .text_size(px(theme::TEXT_ROW))
                                .font_family(ui::mono_font())
                                .text_color(theme::TEXT_PRIMARY),
                        ),
                )
                // 六開關
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                                                .child(form::switch_chip(
                            "大寫",
                            move || gstate.get().uppercase,
                            move || gstate.update(|g| g.uppercase = !g.uppercase),
                        ))
                        .child(form::switch_chip(
                            "小寫",
                            move || gstate.get().lowercase,
                            move || gstate.update(|g| g.lowercase = !g.lowercase),
                        ))
                        .child(form::switch_chip(
                            "數字",
                            move || gstate.get().digits,
                            move || gstate.update(|g| g.digits = !g.digits),
                        ))
                        .child(form::switch_chip(
                            "符號",
                            move || gstate.get().symbols,
                            move || gstate.update(|g| g.symbols = !g.symbols),
                        ))
                        .child(form::switch_chip(
                            "易讀",
                            move || gstate.get().avoid_ambiguous,
                            move || {
                                gstate.update(|g| g.avoid_ambiguous = !g.avoid_ambiguous)
                            },
                        )),
                )
                // 動作
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ui::button("重新產生", ui::Btn::Primary, move || {
                            regen.send(Cmd::GenerateTool)
                        }))
                        .child(when(
                            move || core.gen_tool_pw.get().is_some(),
                            move || {
                                ui::copy_button(disp.clone(), "產生器", copied, core.settings)
                            },
                        )),
                ),
        ))
}

/// 強度條：4 格填色，分級色借 `reports::score_dot_color`（與報告同一
/// 真相源）；無碼時全空框。
fn strength_bar(core: AppCore) -> View {
    let mut row = view().flex_row().items_center().gap_1p5();
    for i in 0..4 {
        row = row.child(
            view()
                .h(px(6.0))
                .flex_1()
                .rounded_full()
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(move || {
                    let Some(pw) = core.gen_tool_pw.get() else {
                        return AdaptiveColor::TRANSPARENT;
                    };
                    let score = bw_crypto::password_score(&pw) as i64;
                    if (i as usize) < passgen::strength_segments(score) {
                        reports::score_dot_color(score)
                    } else {
                        AdaptiveColor::TRANSPARENT
                    }
                }),
        );
    }
    row
}
