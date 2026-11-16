//! 緊急存取 GUI 面（PR4）：側欄「工具→緊急联系人」進入的右欄視角。
//!
//! 兩塊清單＋邀請表單：
//! - 「我授權的」：grantee 列＋狀態徽章；Accepted 列給「確認派發金鑰」鈕
//!   （daemon 需解鎖態，鎖態時鈕位置給可懂文案）、任何狀態可「撤銷」。
//! - 「授權給我的」：grantor 列；C2 起在 Confirmed/恢復態給「檢視」入口，
//!   Takeover 型別在批准態給「接管」入口。
//!
//! 水印唯讀視圖（grantee 讀 grantor 帳密）在 `view_pane`；本檔只做視圖與
//! 純解析（徽章色、接管可用性的純判別函數零 nsh 依賴、單測直打）。

use std::sync::Arc;

use bw_proto::{EaContact, EaRole, EaStatus};
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd};
use crate::theme;
use crate::ui;

/// 狀態徽章配色（純函數，單測點）：待辦＝accent、進行中＝警示、安定＝success。
pub fn status_colors(status: EaStatus) -> (AdaptiveColor, AdaptiveColor) {
    match status {
        EaStatus::Invited | EaStatus::Accepted => (theme::ACCENT, theme::SURFACE),
        EaStatus::Confirmed => (theme::SUCCESS, theme::SURFACE),
        EaStatus::RecoveryInitiated | EaStatus::RecoveryApproved => {
            (theme::WARNING, theme::SURFACE)
        }
        EaStatus::Other(_) => (theme::TEXT_MUTED, theme::SURFACE),
    }
}

/// grantor 確認鈕可用性：只有 Accepted（已接受未派鑰）該出現。
/// Confirmed 再點是重派（PUT 語意），本波不提供——避免誤按覆蓋金鑰。
pub fn can_confirm(c: &EaContact) -> bool {
    c.role == EaRole::Grantee && c.status == EaStatus::Accepted
}

/// 發起恢復入口（C2，我在他人的 grantee 清單＝role Grantor）：Confirmed 起跳；
/// RecoveryInitiated 顯示進行中不重發。
pub fn can_initiate(c: &EaContact) -> bool {
    c.role == EaRole::Grantor && c.status == EaStatus::Confirmed
}

/// grantor 批准/拒絕鈕（C2）：對方已發起恢復，等我表態。
pub fn can_adjudicate(c: &EaContact) -> bool {
    c.role == EaRole::Grantee && c.status == EaStatus::RecoveryInitiated
}

/// 檢視入口（C2）：恢復已批准且型別是 View（Takeover 型別走接管，C3）。
pub fn can_view(c: &EaContact) -> bool {
    c.role == EaRole::Grantor
        && c.status == EaStatus::RecoveryApproved
        && c.access_type == bw_proto::EaAccessType::View
}

/// 接管入口（C3）：Takeover 型別且恢復已批准——改 grantor 主密碼閉環。
pub fn can_takeover(c: &EaContact) -> bool {
    c.role == EaRole::Grantor
        && c.status == EaStatus::RecoveryApproved
        && c.access_type == bw_proto::EaAccessType::Takeover
}

/// 緊急联系人頁視角（右欄整塊）：清單態 ↔ 水印唯讀檢視態同訊號切換。
pub fn pane(core: AppCore) -> View {
    let invite_core = core.clone();
    view()
        .flex_1()
        .flex_col()
        .px_8()
        .py_5()
        .gap_4()
        .child(dynamic(move || {
            if core.ea_view_items.get().is_some() {
                view_pane(core.clone())
            } else {
                contacts_body(core.clone(), invite_core.clone())
            }
        }))
}

/// 清單態：標題＋重新整理＋兩側清單＋邀請表單。
fn contacts_body(core: AppCore, invite_core: AppCore) -> View {
    let empty_cond = core.clone();
    let err_cond = core.clone();
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
                    text("緊急联系人")
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(view().flex_1())
                .child(ui::button("重新整理", ui::Btn::Ghost, move || {
                    invite_core.send(Cmd::EaFetch)
                })),
        )
        .child(when(
            move || empty_cond.ea_loaded.get() && empty_cond.ea_grantees.get().is_empty(),
            || {
                view()
                    .flex_col()
                    .gap_1()
                    .child(row_note(
                        "還沒有緊急联系人。邀請值得信任的對象，在意外發生時檢視或接管你的密碼庫。",
                    ))
                    .child(row_note(
                        "「檢視」＝唯讀帳密；「接管」＝可重設主密碼取得帳號。",
                    ))
            },
        ))
        .child(when(move || err_cond.ea_error.get().is_some(), {
            let err_build = core.clone();
            move || {
                text(move || err_build.ea_error.get().unwrap_or_default())
                    .text_size(px(theme::TEXT_ROW))
                    .text_color(theme::DESTRUCTIVE)
            }
        }))
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_4()
                    .w_full()
                    .max_w(px(720.0))
                    .child(contact_section(core.clone(), "我授權的", core.ea_grantees))
                    .child(contact_section(
                        core.clone(),
                        "授權給我的",
                        core.ea_grantors,
                    ))
                    .child(dynamic({
                        let tk_core = core.clone();
                        move || match tk_core.ea_tk_for.get() {
                            Some(_) => takeover_panel(tk_core.clone()),
                            None => view(),
                        }
                    }))
                    .child(invite_form(core.clone())),
            ),
        )
}

/// 一塊清單：標題＋逐列。
fn contact_section(core: AppCore, title: &'static str, rows: Signal<Arc<Vec<EaContact>>>) -> View {
    let each_core = core.clone();
    view()
        .flex_col()
        .gap_2()
        .w_full()
        .child(ui::section_title(title))
        .child(each(
            move || rows.get().as_ref().clone(),
            |c: &EaContact| c.id.clone(),
            move |row: ReadSignal<EaContact>, _| contact_row(row.get(), each_core.clone()),
        ))
        .child(when(
            move || rows.get().is_empty(),
            move || {
                row_note(if title == "我授權的" {
                    "（尚未邀請任何人）".to_owned()
                } else {
                    "（沒有人授權你）".to_owned()
                })
            },
        ))
}

/// 單列兩行式（尾修 1）：出廠窗 1120×760 下右欄只有 ~536px，單行塞名稱＋
/// 兩章＋天數＋動作群會把按鈕挤出可達區（nsh `press("檢視")` 實錄 no
/// pressable view）。上行＝名稱＋型別章＋狀態章；下行＝等待天數＋動作群。
fn contact_row(c: EaContact, core: AppCore) -> View {
    let (fg, bg) = status_colors(c.status);
    let id = c.id.clone();
    let display_name = if c.name.is_empty() {
        c.email.clone()
    } else {
        format!("{}（{}）", c.name, c.email)
    };
    let show_confirm = can_confirm(&c);
    view()
        .flex_col()
        .gap_1()
        .px_3()
        .py_2()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .min_h(px(28.0))
                .child(
                    text(display_name)
                        .text_size(px(theme::TEXT_ROW))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(view().flex_1())
                .child(ui::badge(
                    c.access_type.label(),
                    theme::ACCENT,
                    theme::SURFACE,
                ))
                .child(ui::badge(c.status.label(), fg, bg)),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(row_note(format!("等待 {} 天", c.wait_time_days)))
                .child(when(move || show_confirm, {
                    let show_core = core.clone();
                    let show_id = id.clone();
                    move || {
                        if crate::state::is_unlocked(&show_core.vault.get()) {
                            let confirm_core = show_core.clone();
                            let confirm_id = show_id.clone();
                            ui::button("確認派鑰", ui::Btn::Primary, move || {
                                confirm_core.send(Cmd::EaConfirm(confirm_id.clone()))
                            })
                        } else {
                            row_note("解鎖後可確認派鑰")
                        }
                    }
                }))
                .child(recovery_actions(&c, &id, &core))
                .child(ui::button("撤銷", ui::Btn::Ghost, {
                    let revoke_core = core.clone();
                    let revoke_id = id.clone();
                    move || revoke_core.send(Cmd::EaRevoke(revoke_id.clone()))
                })),
        )
}

/// 恢復流動作列（C2）：依純判別閘現算——我在 grantor 側給「發起恢復」與
/// 「檢視」；我在 grantee 側遇對方請求中給「批准／拒絕」。
fn recovery_actions(c: &EaContact, id: &str, core: &AppCore) -> View {
    let mut row = view().flex_row().items_center().gap_2();
    if can_initiate(c) {
        let ic = core.clone();
        let iid = id.to_owned();
        row = row.child(ui::button("發起恢復", ui::Btn::Ghost, move || {
            ic.send(Cmd::EaInitiate(iid.clone()))
        }));
    }
    if can_adjudicate(c) {
        let ac = core.clone();
        let aid = id.to_owned();
        row = row.child(ui::button("批准", ui::Btn::Primary, move || {
            ac.send(Cmd::EaApprove(aid.clone()))
        }));
        let rc = core.clone();
        let rid = id.to_owned();
        row = row.child(ui::button("拒絕", ui::Btn::Ghost, move || {
            rc.send(Cmd::EaReject(rid.clone()))
        }));
    }
    if can_view(c) {
        let vc = core.clone();
        let vid = id.to_owned();
        row = row.child(ui::button("檢視", ui::Btn::Primary, move || {
            vc.send(Cmd::EaView(vid.clone()))
        }));
    }
    if can_takeover(c) {
        let tc = core.clone();
        let tid = id.to_owned();
        row = row.child(ui::button("接管", ui::Btn::Destructive, move || {
            tc.send(Cmd::EaTakeoverOpen(tid.clone()))
        }));
    }
    row
}

/// 水印唯讀檢視態（C2）：標題＋返回＋水印帶＋grantor 項目明文列。
fn view_pane(core: AppCore) -> View {
    let back_core = core.clone();
    let items_sig = core.ea_view_items;
    let each_core = core.clone();
    let who = core
        .ea_view_for
        .get()
        .unwrap_or_else(|| "緊急檢視".to_owned());
    view()
        .flex_1()
        .flex_col()
        .gap_3()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(ui::button("返回", ui::Btn::Ghost, move || {
                    back_core.send(Cmd::EaViewLoaded(None))
                }))
                .child(
                    text(format!("{who} 的密碼庫（唯讀）"))
                        .text_size(px(theme::TEXT_PAGE_TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(ui::badge("唯讀", theme::WARNING, theme::SURFACE)),
        )
        .child(watermark_band())
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_2()
                    .w_full()
                    .max_w(px(720.0))
                    .child(each(
                        move || {
                            items_sig
                                .get()
                                .map(|a| a.as_ref().clone())
                                .unwrap_or_default()
                        },
                        |v: &bw_proto::ItemView| v.meta.id,
                        move |row: ReadSignal<bw_proto::ItemView>, _| {
                            view_row(row.get(), each_core.clone())
                        },
                    ))
                    .child(when(
                        move || items_sig.get().map(|a| a.is_empty()).unwrap_or(false),
                        || row_note("對方的密碼庫是空的（或項目都無法解密）。"),
                    )),
            ),
        )
}

/// 水印帶：三條低透明度重複字樣橫幅（截圖可證「水印在場」；只讀態全程在頂部）。
fn watermark_band() -> View {
    view()
        .flex_row()
        .gap_8()
        .child(wm_text())
        .child(wm_text())
        .child(wm_text())
}

fn wm_text() -> View {
    view().child(
        text("bitward 緊急檢視 · 唯讀")
            .text_size(px(theme::TEXT_PAGE_SUB))
            .font_weight(FontWeight::BOLD)
            .text_color(theme::TEXT_MUTED)
            .opacity(0.35),
    )
}

/// 檢視單列：名稱＋帳號＋密碼明文＋型別章（無編輯入口——唯讀語意）。
fn view_row(v: bw_proto::ItemView, _core: AppCore) -> View {
    let pw = v
        .password
        .clone()
        .or(v.password_masked.clone())
        .unwrap_or_else(|| "—".into());
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
        .child(
            text(v.meta.name.clone().unwrap_or_else(|| "（無名）".into()))
                .text_size(px(theme::TEXT_ROW))
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(view().flex_1())
        .child(row_note(v.username.clone().unwrap_or_default()))
        .child(row_note(format!("密碼 {pw}")))
}

/// 接管面板（C3）：新主密碼欄＋確認/取消。語意註記在欄位說明：
/// 改寫對方主密碼、其 2FA 因子全清、各裝置需重登入。
fn takeover_panel(core: AppCore) -> View {
    let cancel_core = core.clone();
    let submit_core = core.clone();
    let pw_core = core.clone();
    view()
        .flex_col()
        .gap_2()
        .w_full()
        .p_3()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::WARNING)
        .bg(theme::ELEVATED)
        .child(ui::section_title("接管這個帳號"))
        .child(row_note(
            "將以新主密碼接管：對方密碼改寫、雙重驗證因子全清、所有裝置需重新登入。",
        ))
        .child(ui::form_field(
            "新主密碼",
            "至少 12 字元",
            core.ea_tk_pw,
            true,
            move |t| pw_core.ea_tk_pw.set(t),
        ))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(ui::button(
                    "確認接管",
                    ui::Btn::Destructive,
                    move || submit_core.send(Cmd::EaTakeoverSubmit),
                ))
                .child(ui::button("取消", ui::Btn::Ghost, move || {
                    cancel_core.ea_tk_for.set(None);
                    cancel_core.ea_tk_pw.set(String::new());
                }))
                .child(when(move || core.ea_busy.get(), || row_note("執行中…"))),
        )
}

/// 邀請表單：email＋型別 chips＋等待天數＋送出。
fn invite_form(core: AppCore) -> View {
    let submit_core = core.clone();
    let email_core = core.clone();
    let view_sel = core.clone();
    let take_sel = core.clone();
    let days_core = core.clone();
    view()
        .flex_col()
        .gap_2()
        .w_full()
        .child(ui::section_title("邀請緊急联系人"))
        .child(ui::form_field(
            "Email",
            "family@example.com",
            core.ea_email,
            false,
            move |t| email_core.ea_email.set(t),
        ))
        .child(
            view()
                .flex_row()
                .gap_2()
                .child(crate::list::chip(
                    "檢視（唯讀）".to_owned(),
                    move || !view_sel.ea_takeover.get(),
                    move || take_sel.ea_takeover.set(false),
                ))
                .child(crate::list::chip(
                    "接管（可改密碼）".to_owned(),
                    move || take_sel.ea_takeover.get(),
                    move || view_sel.ea_takeover.set(true),
                )),
        )
        .child(ui::form_field(
            "恢復等待天數",
            "7",
            core.ea_days,
            false,
            move |t| days_core.ea_days.set(t),
        ))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(ui::button("邀請", ui::Btn::Primary, move || {
                    submit_core.send(Cmd::EaInvite)
                }))
                .child(when(move || core.ea_busy.get(), || row_note("執行中…"))),
        )
}

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
    use bw_proto::{EaAccessType, EaRole, EaStatus};

    fn contact(role: EaRole, status: EaStatus, atype: EaAccessType) -> EaContact {
        EaContact {
            id: "ea-1".into(),
            user_id: Some("u".into()),
            email: "a@b.test".into(),
            name: String::new(),
            status,
            access_type: atype,
            wait_time_days: 7,
            recovery_initiated_at: None,
            role,
        }
    }

    #[test]
    fn confirm_button_only_for_pending_acceptance() {
        assert!(can_confirm(&contact(
            EaRole::Grantee,
            EaStatus::Accepted,
            EaAccessType::View
        )));
        assert!(!can_confirm(&contact(
            EaRole::Grantee,
            EaStatus::Confirmed,
            EaAccessType::View
        )));
        assert!(!can_confirm(&contact(
            EaRole::Grantee,
            EaStatus::Invited,
            EaAccessType::View
        )));
        // 對方側沒有「我替他確認」這回事
        assert!(!can_confirm(&contact(
            EaRole::Grantor,
            EaStatus::Accepted,
            EaAccessType::View
        )));
    }

    #[test]
    fn recovery_gates_split_by_role_and_state() {
        // 我在 grantee 側（role Grantor）：Confirmed 可發起、批准後可檢視
        let confirmed = contact(EaRole::Grantor, EaStatus::Confirmed, EaAccessType::View);
        let approved_view = contact(
            EaRole::Grantor,
            EaStatus::RecoveryApproved,
            EaAccessType::View,
        );
        let approved_take = contact(
            EaRole::Grantor,
            EaStatus::RecoveryApproved,
            EaAccessType::Takeover,
        );
        assert!(can_initiate(&confirmed));
        assert!(!can_view(&confirmed));
        assert!(can_view(&approved_view) && !can_initiate(&approved_view));
        // 接管型別批准後不出檢視入口，改出接管鈕（C3）
        assert!(!can_view(&approved_take));
        assert!(can_takeover(&approved_take));
        assert!(!can_takeover(&approved_view));
        assert!(!can_takeover(&confirmed));
        // 我在 grantor 側（role Grantee）：對方請求中才出批准/拒絕
        let pending = contact(
            EaRole::Grantee,
            EaStatus::RecoveryInitiated,
            EaAccessType::View,
        );
        assert!(can_adjudicate(&pending));
        assert!(!can_adjudicate(&contact(
            EaRole::Grantee,
            EaStatus::Confirmed,
            EaAccessType::View
        )));
        assert!(!can_initiate(&pending), "grantee 側不该看到發起恢復");
    }

    #[test]
    fn status_badges_are_distinct_per_state() {
        let mut seen = Vec::new();
        for s in [
            EaStatus::Invited,
            EaStatus::Accepted,
            EaStatus::Confirmed,
            EaStatus::RecoveryInitiated,
            EaStatus::RecoveryApproved,
            EaStatus::Other(9),
        ] {
            let (fg, _) = status_colors(s);
            let label = s.label();
            assert!(!label.is_empty());
            seen.push(label);
            let _ = fg;
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 6, "六態文案不得重複");
    }
}
