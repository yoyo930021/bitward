//! 雙重驗證（PR3 GUI 面）：設定頁「雙重驗證」管理分節＋登入第二步的
//! Duo webview 島。管理面全部走 daemon `TwoFactor:*`（主密碼經本機線、
//! 語意同 CLI stdin）；本檔只做視圖與**純解析**（Duo 回捕 token 判別、
//! 因子材料取用），解析函數零 nsh 依賴、單測直打。
//!
//! Duo 兩態（源檔對照 Vaultwarden `duo.rs`／官方 desktop 收碼鏈）：
//! - iframe 態：`DuoIframe{host, signature}` → 本機殼頁嵌
//!   `https://{host}/frame/web/v1/auth?parent=..&tx={signature}&frame=b`，
//!   成功後 Duo 父窗收 postMessage `AUTH|…:APP|…`（nsh 已注入
//!   `window.nsh.postMessage` 橋，殼頁 script 轉渡）；
//! - redirect 態：`DuoRedirect{auth_url}` → webview 直載完整授權 URL，
//!   導航回 `…?code=..&state=..` 時從 URL 捕獲，token＝`code|state`。

use std::rc::Rc;

use bw_proto::{FactorMode, TwoFactorDetails, TwoFactorProviderInfo, TwoFactorProviderState};
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd};
use crate::theme;
use crate::ui;

/// Duo 承載頁形態（webview 二選一的純判別，單測點）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DuoPage {
    /// 殼頁 HTML（嵌 Duo iframe＋轉渡 postMessage）。
    Iframe(String),
    /// 直接導航的完整授權 URL。
    Url(String),
}

/// 因子材料 → Duo 承載頁；None＝伺服器沒給材料（舊幀/未知形態），
/// UI 必須給可懂缺席文案而不是開空窗。
pub fn duo_page(info: &TwoFactorProviderInfo) -> Option<DuoPage> {
    match info.details.as_ref()? {
        TwoFactorDetails::DuoIframe { host, signature } => {
            Some(DuoPage::Iframe(duo_shell_html(host, signature)))
        }
        TwoFactorDetails::DuoRedirect { auth_url } if auth_url.starts_with("https://") => {
            Some(DuoPage::Url(auth_url.clone()))
        }
        TwoFactorDetails::DuoRedirect { .. } => None,
        _ => None,
    }
}

/// Duo iframe 殼頁：`parent` 用 Duo 慣例的佔位回調頁（我們不靠真實回調，
/// 捕獲走 postMessage 橋）；`frame=b` 是 Duo 嵌入式表單參數。
fn duo_shell_html(host: &str, signature: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><style>html,body{{margin:0;height:100%;background:#fff}}iframe{{width:100%;height:100%;border:0}}</style></head><body><iframe src="https://{host}/frame/web/v1/auth?parent=https%3A%2F%2F{host}%2Fframe%2Fparent&tx={signature}&frame=b"></iframe><script>window.addEventListener("message",function(e){{if(typeof e.data==="string"&&e.data.indexOf("AUTH|")===0&&window.nsh){{window.nsh.postMessage(e.data);}}}});</script></body></html>"#
    )
}

/// webview `on_message` 字串 → Duo iframe 態 token（`AUTH|…:APP|…`）。
/// 非 AUTH 開頭（Duo 內部雜訊 postMessage）回 None 忽略。
pub fn duo_token_from_message(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.starts_with("AUTH|") && s.contains(":APP|") {
        Some(s.to_owned())
    } else {
        None
    }
}

/// redirect 態導航 URL → `code|state` token（兩參數齊全才算完成）。
pub fn duo_token_from_redirect(url: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let mut code = None;
    let mut state = None;
    for kv in query.split('&') {
        match kv.split_once('=') {
            Some(("code", v)) if !v.is_empty() => code = Some(v),
            Some(("state", v)) if !v.is_empty() => state = Some(v),
            _ => {}
        }
    }
    Some(format!("{}|{}", code?, state?))
}

/// 選中因子對 webview 島的可用性：需要的材料在不在。
/// 回 Ok(mode)＝可開島；Err(文案)＝欄位路因子或材料缺席。
pub fn island_gate(info: Option<&TwoFactorProviderInfo>) -> Result<FactorMode, &'static str> {
    let info = info.ok_or("尚未選取因子")?;
    let mode = TwoFactorProviderInfo::factor_mode(info.provider).ok_or("本產品不受理此因子")?;
    if !mode.needs_island() {
        return Err("此因子直接輸入驗證碼即可");
    }
    let has = matches!(
        (mode, info.details.as_ref()),
        (
            FactorMode::DuoHandoff,
            Some(TwoFactorDetails::DuoIframe { .. } | TwoFactorDetails::DuoRedirect { .. })
        ) | (
            FactorMode::WebauthnAssertion,
            Some(TwoFactorDetails::Webauthn { .. })
        )
    );
    if has {
        Ok(mode)
    } else {
        Err("伺服器未提供該因子的交涉材料（請改用其他因子或 web vault）")
    }
}

/// 已啟用清單裡某因子是否在场（管理列狀態徽章用，純查表）。
pub fn enabled_of(states: &[TwoFactorProviderState], provider: i32) -> bool {
    states.iter().any(|s| s.provider == provider && s.enabled)
}

// ── 設定頁「雙重驗證」分節 ────────────────────────────────────

/// 管理分節：主密碼欄＋已啟用清單＋各因子開停控件＋救援碼。
/// 進入設定頁由 `Cmd::OpenSettings` 觸發一次 `Cmd::TfFetch`。
pub fn section(core: AppCore) -> View {
    let fetch_lbl = core.clone();
    let fetch_press = core.clone();
    let clear_core = core.clone();
    let pw_core = core.clone();
    let rows_core = core.clone();
    let err_cond = core.clone();
    let err_build = core.clone();
    view()
        .flex_col()
        .gap_2()
        .child(ui::section_title("雙重驗證"))
        .child(
            text("登入時要求第二因子；開停直接生效於伺服器（主密碼只在送作時經本機線使用）。")
                .text_size(px(theme::TEXT_PAGE_SUB))
                .line_height(px(17.0))
                .text_color(theme::TEXT_MUTED),
        )
        .child(ui::form_field(
            "主密碼",
            "執行開停／取碼前填入（用後可清）",
            core.tf_pw,
            true,
            move |v| pw_core.tf_pw.set(v),
        ))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(ui::button_dyn(
                    move || {
                        if fetch_lbl.tf_busy.get() {
                            "載入中…".to_owned()
                        } else {
                            "重新載入清單".to_owned()
                        }
                    },
                    ui::Btn::Ghost,
                    move || fetch_press.send(Cmd::TfFetch),
                ))
                .child(ui::text_button_dyn(
                    || "清空主密碼".to_owned(),
                    move || clear_core.tf_pw.set(String::new()),
                )),
        )
        .child(dynamic(move || factor_rows(rows_core.clone())))
        .child(when(
            move || err_cond.tf_error.get().is_some(),
            move || {
                text(move || err_build.tf_error.get().unwrap_or_default())
                    .text_size(px(12.5))
                    .line_height(px(18.0))
                    .text_color(theme::DESTRUCTIVE)
            },
        ))
}

/// 現取清單（閉包內不擷快照,訊號是唯一真相源）。
fn states_now(core: &AppCore) -> Vec<TwoFactorProviderState> {
    core.tf_states
        .get()
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default()
}

/// YubiKey 啟用面板：貼上欄常駐於未啟用的行下（44 字元校驗在 daemon 前本地擋）。
fn yubi_panel(core: AppCore) -> View {
    let c = core.clone();
    view()
        .flex_col()
        .gap_1p5()
        .p_3()
        .rounded(px(theme::RADIUS_BLOCK))
        .bg(theme::SURFACE)
        .child(
            text("插入/觸碰 YubiKey 後按金鑰產生 OTP,貼入下方再按「啟用」。")
                .text_size(px(11.5))
                .line_height(px(17.0))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(ui::form_field(
            "YubiKey OTP",
            "44 字元",
            core.tf_yubi,
            false,
            move |v| c.tf_yubi.set(v),
        ))
}

/// 因子行＋各子流程面板（TOTP 設定、Email 兩步、YubiKey、救援碼）。
fn factor_rows(core: AppCore) -> View {
    let mut col = view().flex_col().gap_1p5().w_full();
    let states: Vec<TwoFactorProviderState> = states_now(&core);
    let has_list = core.tf_states.get().is_some();
    for provider in [0i32, 1, 2, 3, 7, 8] {
        let on = enabled_of(&states, provider);
        let title = TwoFactorProviderInfo::label(provider);
        let state_label = if !has_list {
            "未載入"
        } else if on {
            "已啟用"
        } else {
            "未啟用"
        };
        let c = core.clone();
        col = col.child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .min_h(px(theme::TILE_ROW))
                .child(
                    text(title)
                        .text_size(px(13.5))
                        .text_color(theme::TEXT_PRIMARY)
                        .flex_1(),
                )
                .child(text(state_label).text_size(px(11.5)).text_color(if on {
                    theme::SUCCESS
                } else {
                    theme::TEXT_MUTED
                }))
                .child(action_cell(c, provider, on)),
        );
        // 子流程面板緊接在觸發列下方。
        let ct = core.clone();
        let cb = core.clone();
        col = col.child(when(
            move || provider == 0 && ct.tf_totp.get().is_some(),
            move || totp_panel(cb.clone()),
        ));
        let et = core.clone();
        let eb = core.clone();
        col = col.child(when(
            move || provider == 1 && et.tf_email_stage.get().is_some(),
            move || email_panel(eb.clone()),
        ));
        let yt = core.clone();
        let yb = core.clone();
        col = col.child(when(
            move || provider == 3 && !enabled_of(&states_now(&yt), 3),
            move || yubi_panel(yb.clone()),
        ));
    }
    col = col.child(recovery_block(core));
    col
}

/// 每因子的操作控件（未啟用→啟用路徑；已啟用→停用）。
fn action_cell(core: AppCore, provider: i32, on: bool) -> View {
    let c = core.clone();
    if on && provider != 8 {
        return ui::button_dyn(
            move || {
                if c.tf_busy.get() {
                    "處理中…".to_owned()
                } else {
                    "停用".to_owned()
                }
            },
            ui::Btn::Ghost,
            move || c.send(Cmd::TfDisable(provider)),
        );
    }
    match provider {
        0 => {
            let cl = core.clone();
            let cp = core.clone();
            ui::button_dyn(
                move || {
                    if cl.tf_totp.get().is_some() {
                        "啟用".to_owned()
                    } else {
                        "取得設定碼".to_owned()
                    }
                },
                ui::Btn::Ghost,
                move || {
                    if cp.tf_totp.get().is_some() {
                        cp.send(Cmd::TfEnableTotp)
                    } else {
                        cp.send(Cmd::TfGetTotpKey)
                    }
                },
            )
        }
        1 => {
            let cl = core.clone();
            let cp = core.clone();
            ui::button_dyn(
                move || {
                    if cl.tf_email_stage.get().is_some() {
                        "確認".to_owned()
                    } else {
                        "寄驗證碼".to_owned()
                    }
                },
                ui::Btn::Ghost,
                move || {
                    if cp.tf_email_stage.get().is_some() {
                        cp.send(Cmd::TfEmailVerify)
                    } else {
                        cp.send(Cmd::TfEmailSend)
                    }
                },
            )
        }
        2 | 7 => {
            // 啟用 Duo/WebAuthn 需要對各自雲端的帳務與 attestation，本批只讀狀態。
            view().child(
                text("開停請用 web vault；本客戶端支援登入時完成")
                    .text_size(px(11.5))
                    .text_color(theme::TEXT_MUTED),
            )
        }
        3 => {
            let c = core.clone();
            ui::button_dyn(
                move || {
                    if c.tf_busy.get() {
                        "處理中…".to_owned()
                    } else {
                        "啟用".to_owned()
                    }
                },
                ui::Btn::Ghost,
                move || c.send(Cmd::TfYubikeyAdd),
            )
        }
        8 => {
            let c = core.clone();
            ui::button_dyn(
                move || {
                    if c.tf_busy.get() {
                        "處理中…".to_owned()
                    } else {
                        "取救援碼".to_owned()
                    }
                },
                ui::Btn::Ghost,
                move || c.send(Cmd::TfGetRecovery),
            )
        }
        _ => view().w(px(1.0)),
    }
}

/// TOTP 設定面板：otpauth URI（可複製）＋ secret ＋驗證器現碼輸入。
fn totp_panel(core: AppCore) -> View {
    let copied = signal::<Option<&'static str>>(None);
    let Some(arc) = core.tf_totp.get() else {
        return view().flex_1();
    };
    let (secret, key_uri) = (*arc).clone();
    let uri = key_uri.unwrap_or_else(|| format!("otpauth://totp/bitward:{secret}"));
    let c = core.clone();
    view()
        .flex_col()
        .gap_1p5()
        .p_3()
        .rounded(px(theme::RADIUS_BLOCK))
        .bg(theme::SURFACE)
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    text(uri.clone())
                        .text_size(px(11.5))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_SECONDARY)
                        .flex_1()
                        .selectable(true),
                )
                .child(ui::copy_button(
                    Rc::new(move || uri.clone()),
                    "otpauth",
                    copied,
                    core.settings,
                )),
        )
        .child(ui::form_field(
            "驗證器現碼",
            "6 位數字",
            core.tf_otp,
            false,
            move |v| c.tf_otp.set(v),
        ))
}

/// Email 兩步面板：寄出後收信中 6 碼。
fn email_panel(core: AppCore) -> View {
    let c = core.clone();
    view()
        .flex_col()
        .gap_1p5()
        .p_3()
        .rounded(px(theme::RADIUS_BLOCK))
        .bg(theme::SURFACE)
        .child(
            text(move || match core.tf_email_stage.get().as_deref() {
                Some(addr) => format!("驗證碼已寄往 {addr}，收信中輸入 6 位碼後按「確認」。"),
                None => String::new(),
            })
            .text_size(px(11.5))
            .line_height(px(17.0))
            .text_color(theme::TEXT_SECONDARY),
        )
        .child(ui::form_field(
            "信中驗證碼",
            "6 位數字",
            core.tf_email_code,
            false,
            move |v| c.tf_email_code.set(v),
        ))
}

/// 救援碼區塊：取回後常駐顯示（用後 2FA 全清的警告同 CLI 語意）。
fn recovery_block(core: AppCore) -> View {
    let copied = signal::<Option<&'static str>>(None);
    let rc = core.clone();
    let rb = core.clone();
    view().child(when(
        move || rc.tf_recovery.get().is_some(),
        move || {
            let code = rb.tf_recovery.get().unwrap_or_default();
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .p_3()
                .rounded(px(theme::RADIUS_BLOCK))
                .bg(theme::SURFACE)
                .child(
                    text(code.clone())
                        .text_size(px(12.5))
                        .font_family(ui::mono_font())
                        .text_color(theme::TEXT_PRIMARY)
                        .flex_1()
                        .selectable(true),
                )
                .child(ui::copy_button(
                    Rc::new(move || code.clone()),
                    "recovery",
                    copied,
                    core.settings,
                ))
        },
    ))
}

// ── 登入第二步：Duo webview 模態 ──────────────────────────────

/// Duo 島模態：iframe 態走 `web_view_html`（殼頁轉渡 postMessage），
/// redirect 態走 `web_view(url)` 直載授權頁並從導航捕 `code|state`。
/// 捕獲即 `Cmd::DuoCaptured`（回填驗證碼欄＋關窗）。
pub fn duo_modal(core: AppCore) -> View {
    let close = core.clone();
    let info = core.login.selected_provider();
    let page = info.as_deref().and_then(duo_page);
    let body: View = match page {
        Some(DuoPage::Iframe(html)) => {
            let msg_core = core.clone();
            let wv = web_view_html(html, None).on_message(move |data: &str| {
                if let Some(tok) = duo_token_from_message(data) {
                    let c = msg_core.clone();
                    c.send(Cmd::DuoCaptured(tok));
                }
            });
            view().flex_1().child(wv)
        }
        Some(DuoPage::Url(url)) => {
            let nav_core = core.clone();
            let wv = web_view(url).on_navigation_state_change(move |nav: &WebNavigation| {
                if let Some(tok) = duo_token_from_redirect(&nav.url) {
                    let c = nav_core.clone();
                    c.send(Cmd::DuoCaptured(tok));
                }
            });
            view().flex_1().child(wv)
        }
        None => view().flex_1().items_center().justify_center().child(
            text("伺服器未提供 Duo 交涉材料，無法開啟驗證頁。")
                .text_size(px(12.5))
                .text_color(theme::TEXT_SECONDARY),
        ),
    };
    ui::modal_shell(
        460.0,
        move || close.send(Cmd::CloseDuo),
        view()
            .flex_col()
            .gap_2()
            .w_full()
            .h_full()
            .child(
                text("Duo 驗證")
                    .text_size(px(theme::TEXT_FIELD_LABEL))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::TEXT_PRIMARY),
            )
            .child(
                text("完成 Duo 頁面操作後，本窗會自動取回憑證並填入驗證碼欄。")
                    .text_size(px(11.5))
                    .text_color(theme::TEXT_MUTED),
            )
            .child(body),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::TwoFactorProviderInfo;

    fn info(details: Option<TwoFactorDetails>) -> TwoFactorProviderInfo {
        TwoFactorProviderInfo {
            provider: 2,
            hint: None,
            details,
        }
    }

    #[test]
    fn duo_message_token_two_state() {
        // iframe 態雙段水漬全收；非 AUTH 前綴（Duo 內部訊息）與缺段拒絕。
        assert_eq!(
            duo_token_from_message("AUTH|abc.def:APP|ghi.jkl").as_deref(),
            Some("AUTH|abc.def:APP|ghi.jkl")
        );
        assert_eq!(duo_token_from_message("TX|ping"), None);
        assert_eq!(duo_token_from_message("AUTH|only-one-seg"), None);
        assert_eq!(
            duo_token_from_message("  AUTH|a:APP|b  ").as_deref(),
            Some("AUTH|a:APP|b")
        );
    }

    #[test]
    fn duo_redirect_token_requires_both_params() {
        // redirect 態：code+state 齊全才成型；缺任一或空值不算完成。
        assert_eq!(
            duo_token_from_redirect("https://vw.example/duo/callback?code=C1&state=S2").as_deref(),
            Some("C1|S2")
        );
        assert_eq!(duo_token_from_redirect("https://x/y?code=C1"), None);
        assert_eq!(duo_token_from_redirect("https://x/y?code=&state=S2"), None);
        assert_eq!(duo_token_from_redirect("https://x/y"), None);
    }

    #[test]
    fn duo_page_dispatches_by_details() {
        let iframe = info(Some(TwoFactorDetails::DuoIframe {
            host: "api-example.duosecurity.com".into(),
            signature: "SIG123".into(),
        }));
        match duo_page(&iframe) {
            Some(DuoPage::Iframe(html)) => {
                assert!(html.contains("api-example.duosecurity.com/frame/web/v1/auth"));
                assert!(html.contains("tx=SIG123"));
                assert!(html.contains("window.nsh.postMessage"));
            }
            other => panic!("iframe 態形態錯：{other:?}"),
        }
        let redirect = info(Some(TwoFactorDetails::DuoRedirect {
            auth_url: "https://example.duo/auth?x=1".into(),
        }));
        assert_eq!(
            duo_page(&redirect),
            Some(DuoPage::Url("https://example.duo/auth?x=1".into()))
        );
        // 非 https 授權 URL 與缺材料一律 None（不開空窗）。
        assert_eq!(
            duo_page(&info(Some(TwoFactorDetails::DuoRedirect {
                auth_url: "http://insecure".into(),
            }))),
            None
        );
        assert_eq!(duo_page(&info(None)), None);
    }

    #[test]
    fn island_gate_requires_matching_materials() {
        // Duo 有材料＝可開島；材料錯型＝可懂拒絕。
        let ok = info(Some(TwoFactorDetails::DuoIframe {
            host: "h".into(),
            signature: "s".into(),
        }));
        assert_eq!(island_gate(Some(&ok)), Ok(FactorMode::DuoHandoff));
        let mismatch = info(Some(TwoFactorDetails::Yubikey { nfc: false }));
        assert!(island_gate(Some(&mismatch)).is_err());
        // 純欄位因子不該開島。
        let mut otp = ok.clone();
        otp.provider = 0;
        assert!(island_gate(Some(&otp)).is_err());
        assert!(island_gate(None).is_err());
    }

    #[test]
    fn enabled_of_hits_only_enabled_rows() {
        let states = vec![
            TwoFactorProviderState {
                provider: 0,
                enabled: true,
            },
            TwoFactorProviderState {
                provider: 1,
                enabled: false,
            },
        ];
        assert!(enabled_of(&states, 0));
        assert!(!enabled_of(&states, 1));
        assert!(!enabled_of(&states, 6));
    }
}
