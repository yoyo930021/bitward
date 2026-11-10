//! 報告儀表板（路線 4）：右欄視角，側欄「報告」進入。
//! 兩層同訊號切換：卡面（重用 N 組｜弱密碼 N 筆）→ 清單
//! （列項目＋共用計數／分級色點，點選跳詳情）。資料每次進入現取（daemon
//! 不落盤報告結果——弱密碼明文只在打分閉包內，落盤即殘留面）。
//! 分級色點口徑：0/1 紅（太易猜）、2 橘（尚可猜）、3/4 綠（難猜）；
//! 列管門檻 `WEAK_PASSWORD_THRESHOLD`（daemon 已過濾，此處只著色）。

use bw_proto::{ItemId, WEAK_PASSWORD_THRESHOLD};
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, ReportsTab, is_unlocked};
use crate::theme;
use crate::ui;

/// 報告頁視角（右欄整塊）：tab 訊號切卡面／清單，零路由跳動。
pub fn pane(core: AppCore) -> View {
    let tab_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .px_8()
        .py_5()
        .gap_4()
        .child(dynamic(move || match tab_core.reports_tab.get() {
            ReportsTab::Cards => cards(core.clone()),
            ReportsTab::Reuse => reuse_list(core.clone()),
            ReportsTab::Weak => weak_list(core.clone()),
        }))
}

/// 儀表板卡面：兩張可點卡；掃描需金鑰，鎖態顯示提示並重取。
fn cards(core: AppCore) -> View {
    let reuse_core = core.clone();
    let weak_core = core.clone();
    let reuse_cnt_core = core.clone();
    view()
        .flex_col()
        .gap_4()
        .child(
            text("報告")
                .text_size(px(theme::TEXT_IDENTITY))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(
            view()
                .flex_row()
                .gap_4()
                .child(report_card(
                    "重用密碼",
                    move || format!("{} 組", reuse_cnt_core.reports_reuse.get().len()),
                    "同網站同帳號的多筆項目".into(),
                    move || reuse_core.send(Cmd::ShowReportsTab(ReportsTab::Reuse)),
                ))
                .child(report_card(
                    "弱密碼",
                    move || format!("{} 筆", weak_score_items(&core.reports_weak.get()).len()),
                    format!("分級 <{WEAK_PASSWORD_THRESHOLD} 列管（規則近似，非 zxcvbn 本體）"),
                    move || weak_core.send(Cmd::ShowReportsTab(ReportsTab::Weak)),
                )),
        )
        .child(when(
            move || !is_unlocked(&core.vault.get()),
            || {
                text("解鎖後重進本頁以取得掃描結果（兩份報告都只在解鎖態現算）")
                    .text_size(px(theme::TEXT_PAGE_SUB))
                    .text_color(theme::TEXT_MUTED)
            },
        ))
}

/// 儀表板卡：標題＋大數字＋說明；整卡可點進清單。
fn report_card(
    title: &'static str,
    count: impl Fn() -> String + 'static,
    desc: String,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .flex_1()
        .flex_col()
        .gap_2()
        .p_4()
        .rounded(px(theme::RADIUS_CARD))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .cursor_pointer()
        .on_press(on_press)
        .child(
            text(title)
                .text_size(px(theme::TEXT_CARD_TITLE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(
            text(count)
                .text_size(px(28.0))
                .font_weight(FontWeight::BOLD)
                .text_color(theme::ACCENT),
        )
        .child(
            text(desc)
                .text_size(px(theme::TEXT_PAGE_SUB))
                .text_color(theme::TEXT_MUTED),
        )
}

/// 清單列頭：返回卡面鈕＋標題。
fn list_header(title: &'static str, core: AppCore) -> View {
    let back_core = core;
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .child(ui::button("返回", ui::Btn::Ghost, move || {
            back_core.send(Cmd::ShowReportsTab(ReportsTab::Cards))
        }))
        .child(
            text(title)
                .text_size(px(theme::TEXT_PAGE_TITLE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
}

/// 重用密碼清單：每群＝域名＋共用計數徽章，群內每筆項目可點進詳情。
fn reuse_list(core: AppCore) -> View {
    let head_core = core.clone();
    let each_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .gap_4()
        .child(list_header("重用密碼", head_core))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_3()
                .w_full()
                .max_w(px(680.0))
                .child(each(
                    move || (*core.reports_reuse.get()).clone(),
                    |g: &bw_proto::DupGroup| g.domain.clone(),
                    move |group: ReadSignal<bw_proto::DupGroup>, _| {
                        let mut body = view().flex_col().gap_1();
                        for id in group.get().ids {
                            body = body.child(item_row(id, each_core.clone(), None));
                        }
                        view()
                            .flex_col()
                            .gap_2()
                            .p_4()
                            .rounded(px(theme::RADIUS_BLOCK))
                            .border(px(1.0))
                            .border_color(theme::HAIRLINE)
                            .bg(theme::ELEVATED)
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        text(group.get().domain.clone())
                                            .text_size(px(theme::TEXT_ROW))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(theme::TEXT_PRIMARY),
                                    )
                                    .child(text(format!("共用 {} 筆", group.get().ids.len()))
                                        .text_size(px(theme::TEXT_BADGE))
                                        .text_color(theme::TEXT_MUTED)),
                            )
                            .child(body)
                    },
                ))
                .child(when(move || core.reports_reuse.get().is_empty(), || {
                    empty_note("目前沒有同網站同帳號的重複項目（需解鎖後掃描）")
                })),
        ))
}

/// 弱密碼清單：name＋分級色點＋分數；點列進詳情。
fn weak_list(core: AppCore) -> View {
    let head_core = core.clone();
    let each_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .gap_4()
        .child(list_header("弱密碼", head_core))
        .child(scroll().flex_1().child(
            view()
                .flex_col()
                .gap_2()
                .w_full()
                .max_w(px(680.0))
                .child(each(
                    move || weak_score_items(&core.reports_weak.get()),
                    |it: &(ItemId, i64)| it.0,
                    move |it: ReadSignal<(ItemId, i64)>, _| {
                        let (id, score) = it.get();
                        item_row(id, each_core.clone(), Some(score))
                    },
                ))
                .child(when(
                    move || weak_score_items(&core.reports_weak.get()).is_empty(),
                    || empty_note("目前沒有低於門檻的密碼（需解鎖後掃描）"),
                )),
        ))
}

/// 歷史回包的 `versions` 陣形（不支援態恆空；詳情頁渲染閘與列構造共用）。
pub fn history_versions(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v.get("versions")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default()
}

/// `{"items":[{"id","name","score"}]}` → (id, score) 對（id 解析失敗跳列）。
pub fn weak_score_items(v: &serde_json::Value) -> Vec<(ItemId, i64)> {
    v.get("items")
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let id = ItemId::parse_str(r.get("id")?.as_str()?).ok()?;
                    Some((id, r.get("score")?.as_i64()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 分級色點顏色（0/1 紅、2 橘、其餘綠）——詳情頁歷史節共用。
pub fn score_dot_color(score: i64) -> AdaptiveColor {
    match score {
        0..=1 => theme::DESTRUCTIVE,
        2 => theme::WARNING,
        _ => theme::SUCCESS,
    }
}

/// 報告清單列：名稱（鏡像投影，不另發請求）＋可選分級色點；點擊進詳情。
fn item_row(id: ItemId, core: AppCore, score: Option<i64>) -> View {
    let name_core = core.clone();
    let press_core = core.clone();
    let tail = match score {
        Some(s) => view()
            .flex_row()
            .items_center()
            .gap_2()
            .child(
                view()
                    .w(px(8.0))
                    .h(px(8.0))
                    .rounded(px(4.0))
                    .bg(score_dot_color(s)),
            )
            .child(
                text(format!("分數 {s}"))
                    .text_size(px(theme::TEXT_PAGE_SUB))
                    .text_color(theme::TEXT_MUTED),
            ),
        None => view().child(
            text("共用")
                .text_size(px(theme::TEXT_BADGE))
                .text_color(theme::TEXT_MUTED),
        ),
    };
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(theme::ROW_H))
        .px_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .cursor_pointer()
        .on_press(move || press_core.send(Cmd::OpenDetail(id)))
        .child(dynamic(move || {
            let name = name_core
                .items
                .get()
                .iter()
                .find(|r| r.meta.id == id)
                .and_then(|r| r.meta.name.clone())
                .unwrap_or_else(|| "…".into());
            text(name)
                .text_size(px(theme::TEXT_ROW))
                .text_color(theme::TEXT_PRIMARY)
        }))
        .child(view().flex_1())
        .child(tail)
}

/// 空清單說明列。
fn empty_note(msg: &'static str) -> View {
    view().child(
        text(msg)
            .text_size(px(theme::TEXT_ROW_SUB))
            .text_color(theme::TEXT_MUTED),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_items_parse_tolerant() {
        let v = serde_json::json!({"threshold": 3, "items": [
            {"id": "6fe8bae0-e019-48fb-a651-f9e3514d156e", "name": "weakone", "score": 0},
            {"id": "not-a-uuid", "name": "ghost", "score": 1},
        ]});
        let rows = weak_score_items(&v);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, 0);
        assert!(weak_score_items(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn score_dot_colors_follow_grade() {
        assert_eq!(score_dot_color(0), theme::DESTRUCTIVE);
        assert_eq!(score_dot_color(1), theme::DESTRUCTIVE);
        assert_eq!(score_dot_color(2), theme::WARNING);
        assert_eq!(score_dot_color(3), theme::SUCCESS);
        assert_eq!(score_dot_color(4), theme::SUCCESS);
    }
}
