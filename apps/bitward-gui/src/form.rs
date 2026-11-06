//! 新增/編輯表單：name/username/password/uri/tags → Vault:Create / Vault:Patch。
//! 表單明文（密碼欄）只進訊號與送出時的 `Zeroizing` 副本，加密前不落盤；
//! 送出與差異計算在 `state::submit_form`。

use nsh_base::theme;
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Route};
use crate::ui;

pub fn page(core: AppCore) -> View {
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
    view()
        .flex_col()
        .flex_1()
        .child(ui::page_header(title.to_owned(), move || {
            back.send(Cmd::OpenList)
        }))
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_5()
                    .px_6()
                    .py_5()
                    .max_w(px(560.0))
                    .child(ui::form_field(
                        "名稱",
                        "例：GitHub",
                        name,
                        false,
                        move |v| name.set(v),
                    ))
                    .child(ui::form_field(
                        "帳號",
                        "使用者名稱或電子信箱",
                        username,
                        false,
                        move |v| username.set(v),
                    ))
                    .child(ui::form_field(
                        "密碼",
                        pw_hint,
                        password,
                        true,
                        move |v| password.set(v),
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
                            .text_color(move || theme().muted_foreground),
                    )
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_3()
                            .child(ui::button("儲存", ui::Btn::Primary, move || {
                                save.send(Cmd::SubmitForm)
                            }))
                            .child(ui::button("取消", ui::Btn::Muted, move || {
                                back2.send(Cmd::OpenList)
                            }))
                            .child(
                                text(move || err_core.form.error.get().unwrap_or_default())
                                    .text_size(px(12.5))
                                    .text_color(move || theme().destructive),
                            ),
                    ),
            ),
        )
}
