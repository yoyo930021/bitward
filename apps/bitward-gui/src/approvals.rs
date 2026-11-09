//! 批准佇列（右欄視角，批次 6 自殼批准中心併入）：每筆＝daemon 去敏後的
//! summary ＋ 請求時間（daemon 補 `requested_at_ms` 後自動顯示）＋ 批准/拒絕。
//! 官方語意為單鍵直決——**不做二次確認**；按錯可用「拒絕」補救手動 deny 的
//! 对面（批准後該 agent 呼叫即放行，無法回收）。資料源 `Agent/ListPending`
//! 1.5s 輪詢（照殼節拍）＋ `ApprovalRequired` 事件搭車。

use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, PendingRow};
use crate::theme;
use crate::ui;

/// epoch 毫秒 → `HH:MM`（UTC，不拉 chrono；與 export 的 civil 同一套算式）。
/// None 回空字串（daemon 尚未帶時間欄時不佔位瞎編）。
pub fn format_epoch_ms(ms: Option<u64>) -> String {
    let Some(ms) = ms else { return String::new() };
    let secs = ms / 1000;
    let tod = secs % 86_400;
    format!("{:02}:{:02}", tod / 3600, (tod % 3600) / 60)
}

/// 佇列視角（右欄整塊）。
pub fn pane(core: AppCore) -> View {
    let list_core = core.clone();
    let each_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .px_8()
        .py_5()
        .gap_4()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(
                    text("待批准")
                        .text_size(px(theme::TEXT_IDENTITY))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(
                    text(move || {
                        let n = list_core.pending.get().len();
                        if n == 0 { "目前沒有待批准的請求".to_owned() } else { format!("{n} 筆待决") }
                    })
                    .text_size(px(theme::TEXT_PAGE_SUB))
                    .text_color(theme::TEXT_MUTED),
                ),
        )
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_2()
                .w_full()
                .max_w(px(680.0))
                .child(each(
                    move || (*core.pending.get()).clone(),
                    |p: &PendingRow| p.id.clone(),
                    move |item: ReadSignal<PendingRow>, _| {
                        pending_row(each_core.clone(), item.get())
                    },
                ))
                .child(when(move || core.pending.get().is_empty(), empty_card)),
        ))
}

/// 單筆佇列列：summary（mono）＋時間＋批准/拒絕。
fn pending_row(core: AppCore, row: PendingRow) -> View {
    let approve = core.clone();
    let deny = core.clone();
    let aid_a = row.id.clone();
    let aid_d = row.id.clone();
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_2()
        .rounded(px(theme::RADIUS_BLOCK))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::SURFACE)
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .overflow_hidden()
                .child(
                    text(row.summary.clone())
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_PRIMARY)
                        .number_of_lines(2),
                )
                .child(
                    text(format_epoch_ms(row.requested_at_ms))
                        .text_size(px(theme::TEXT_PAGE_SUB))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
        .child(ui::button("批准", ui::Btn::Primary, move || {
            approve.send(Cmd::ApprovePending(aid_a.clone()))
        }))
        .child(ui::button("拒絕", ui::Btn::Ghost, move || {
            deny.send(Cmd::DenyPending(aid_d.clone()))
        }))
}

/// 空佇列佔位卡（沿用殼批准中心文案）。
fn empty_card() -> View {
    view()
        .h_40()
        .flex_col()
        .items_center()
        .justify_center()
        .rounded(px(theme::RADIUS_BLOCK))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::SURFACE)
        .child(
            text("目前沒有待批准的請求")
                .text_size(px(theme::TEXT_ROW))
                .text_color(theme::TEXT_SECONDARY),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ms_formats_to_utc_clock_and_absent_is_blank() {
        // 1794000000123ms = 2026-11-06T21:20:00Z
        assert_eq!(format_epoch_ms(Some(1_794_000_000_123)), "21:20");
        assert_eq!(format_epoch_ms(Some(0)), "00:00");
        assert_eq!(format_epoch_ms(None), "");
    }
}
