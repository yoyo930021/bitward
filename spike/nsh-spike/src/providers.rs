//! Provider 設定頁：表單欄位、開關、儲存按鈕（契約 §0.2 的兩個真實畫面之一）。

use std::path::PathBuf;

use nsh_base::{input, switch, theme};
use nsh_core::element::{Style, StyleRefinement};
use nsh_core::prelude::*;

use crate::data::ProviderSettings;

pub fn settings_page(dir: PathBuf) -> View {
    let saved = ProviderSettings::load(&dir);
    let server_url = signal(saved.server_url.clone());
    let email = signal(saved.email.clone());
    let master = signal(String::new());
    let launch_at_login = signal(saved.launch_at_login);
    let auto_lock = signal(saved.auto_lock);
    let use_keychain = signal(saved.use_system_keychain);
    let status = signal(None::<String>);

    let save_server = server_url;
    let save_email = email;
    let save_launch = launch_at_login;
    let save_lock = auto_lock;
    let save_keychain = use_keychain;
    let save_status = status;
    let save_dir = dir.clone();

    view()
        .flex_1()
        .flex_col()
        .child(page_header(
            "Provider 設定",
            "連線與鑰匙圈偏好（spike 存檔：本地 JSON，非正式路徑）",
        ))
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_5()
                    .px_6()
                    .py_5()
                    .max_w(px(520.0))
                    .child(form_field(
                        "伺服器網址",
                        "https://vault.example.com",
                        server_url,
                        false,
                    ))
                    .child(form_field("電子信箱", "me@example.com", email, false))
                    .child(form_field("主密碼", "解鎖此裝置的金鑰來源", master, true))
                    .child(
                        view()
                            .flex_col()
                            .rounded_lg()
                            .border(px(1.0))
                            .border_color(move || theme().border)
                            .child(toggle(
                                "開機自動啟動",
                                "登入 macOS 後拉起常駐中樞",
                                &launch_at_login,
                            ))
                            .child(divider())
                            .child(toggle(
                                "閒置後自動鎖定",
                                "5 分鐘無操作即鎖定並清零記憶體",
                                &auto_lock,
                            ))
                            .child(divider())
                            .child(toggle(
                                "使用系統鑰匙圈",
                                "解鎖金鑰封存於 Keychain",
                                &use_keychain,
                            )),
                    )
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_3()
                            .child(button::save_button("儲存設定", move || {
                                let settings = ProviderSettings {
                                    server_url: save_server.get(),
                                    email: save_email.get(),
                                    launch_at_login: save_launch.get(),
                                    auto_lock: save_lock.get(),
                                    use_system_keychain: save_keychain.get(),
                                };
                                if settings.server_url.is_empty() {
                                    save_status.set(Some("錯誤：伺服器網址不可為空".into()));
                                    return;
                                }
                                match settings.save(&save_dir) {
                                    Ok(path) => save_status
                                        .set(Some(format!("已儲存 → {}", path.display()))),
                                    Err(e) => {
                                        save_status.set(Some(format!("儲存失敗：{e}")));
                                    }
                                }
                            }))
                            .child(
                                text(move || status.get().unwrap_or_default())
                                    .text_size(px(12.0))
                                    .text_color(move || theme().muted_foreground),
                            ),
                    ),
            ),
        )
}

fn page_header(title: &'static str, subtitle: &'static str) -> View {
    view()
        .flex_col()
        .gap_1()
        .px_6()
        .pt_6()
        .pb_2()
        .child(
            text(title)
                .text_size(px(22.0))
                .font_weight(FontWeight::BOLD),
        )
        .child(
            text(subtitle)
                .text_size(px(12.5))
                .text_color(move || theme().muted_foreground),
        )
}

fn form_field(
    label: &'static str,
    placeholder: &'static str,
    value: Signal<String>,
    secure: bool,
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
                .on_change(move |text: &str| value.set(text.to_owned()))
                .h_10()
                .px_3()
                .rounded_lg()
                .border(px(1.0))
                .border_color(move || theme().border)
                .text_color(move || theme().foreground),
        )
}

fn toggle(label: &'static str, desc: &'static str, value: &Signal<bool>) -> View {
    view()
        .flex_row()
        .items_center()
        .justify_between()
        .px_4()
        .py_3()
        .child(
            view()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .child(
                    text(label)
                        .text_size(px(13.5))
                        .font_weight(FontWeight::MEDIUM),
                )
                .child(
                    text(desc)
                        .text_size(px(12.0))
                        .text_color(move || theme().muted_foreground),
                ),
        )
        .child(
            switch()
                .checked({
                    let value = *value;
                    move || value.get()
                })
                .on_change({
                    let value = *value;
                    move |on: &bool| value.set(*on)
                })
                .accessibility_label(label.to_owned())
                .track_style({
                    let value = *value;
                    move |s| {
                        s.w(px(40.0)).h(px(24.0)).rounded(px(12.0)).bg(move || {
                            if value.get() {
                                theme().primary
                            } else {
                                theme().muted
                            }
                        })
                    }
                })
                .thumb_style(move |s| {
                    s.w(px(18.0))
                        .h(px(18.0))
                        .rounded(px(9.0))
                        .bg(theme().background)
                        .translate_x({
                            let value = *value;
                            move || {
                                if value.get() { px(19.0) } else { px(3.0) }
                            }
                        })
                }),
        )
}

fn divider() -> View {
    view().h(px(1.0)).w_full().bg(move || theme().border)
}

/// 主要按鈕：nsh-base 的 `button()` 無外觀，樣式由 app 給（spike 驗證點）。
mod button {
    use super::*;

    pub fn save_button(label: &'static str, on_save: impl Fn() + 'static) -> View {
        view()
            .h_10()
            .px_5()
            .rounded_lg()
            .flex_row()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .active(|s| s.opacity(0.7))
            .inline_style(move || Style::from(StyleRefinement::default().bg(theme().primary)))
            .on_press(on_save)
            .child(
                text(label)
                    .text_size(px(13.5))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(move || theme().primary_foreground),
            )
    }
}
