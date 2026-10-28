//! NSH GUI spike（契約 §0.2）：provider 設定頁 + vault 列表，純 Rust 元件。
//!
//! 桌面（`is_desktop()`）走 sidebar 配置；窄螢幕退回頂部頁籤。
//! `mod+1` / `mod+2` 切頁、`mod+3` 開第一筆詳情、`escape` 返回——除了給
//! 使用者按，也是截圖自動化（osascript 送鍵）的操作面。

mod data;
mod providers;
mod shots;
mod vault;

use nsh_base::theme;
use nsh_core::prelude::*;

pub use data::VaultData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Providers,
    Vault,
}

/// 初始畫面：`NSH_SPIKE_SCREEN=vault` 讓截圖腳本直接落在目標頁，
/// 不依賴視窗能否被自動化操作。
fn initial_screen() -> Screen {
    match std::env::var("NSH_SPIKE_SCREEN").as_deref() {
        Ok("vault") => Screen::Vault,
        _ => Screen::Providers,
    }
}

#[native_module("nsh-spike/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// 根元件：持有畫面狀態，分派兩個子畫面。
#[component]
pub fn App() -> impl IntoElement {
    let data = data::load_vault();
    let screen = signal(initial_screen());
    let selected = signal(None::<bw_proto::ItemId>);

    on_key("mod+1", move |_| screen.set(Screen::Providers));
    on_key("mod+2", move |_| screen.set(Screen::Vault));
    on_key("mod+3", {
        let data_first = data.items.first().map(|i| i.id);
        move |_| {
            screen.set(Screen::Vault);
            if let Some(id) = data_first {
                selected.set(Some(id));
            }
        }
    });
    on_key("escape", move |_| selected.set(None));

    if let Some(dir) = std::env::var_os("NSH_SPIKE_SHOTS").map(std::path::PathBuf::from) {
        shots::script(dir, screen, selected, data.items.first().map(|i| i.id));
    }

    let body = if is_desktop() {
        desktop_shell(screen, data, selected)
    } else {
        mobile_shell(screen, data, selected)
    };

    body.flex_1().bg(move || theme().background)
}

fn desktop_shell(
    screen: Signal<Screen>,
    data: VaultData,
    selected: Signal<Option<bw_proto::ItemId>>,
) -> View {
    view()
        .flex_row()
        .flex_1()
        .child(sidebar(screen))
        .child(
            view()
                .w(px(1.0))
                .self_stretch()
                .bg(move || theme().sidebar_border),
        )
        .child(content(screen, data, selected))
}

fn sidebar(screen: Signal<Screen>) -> View {
    view()
        .w_60()
        .flex_col()
        .bg(move || theme().sidebar)
        .text_color(move || theme().sidebar_foreground)
        .child(
            view().h_14().px_4().flex_row().items_center().child(
                text("Bitward spike")
                    .text_size(px(15.0))
                    .font_weight(FontWeight::SEMIBOLD),
            ),
        )
        .child(nav_item(screen, Screen::Providers, "Provider 設定"))
        .child(nav_item(screen, Screen::Vault, "Vault 列表"))
        .child(view().flex_1())
        .child(
            view().px_4().pb_3().child(
                text("nsh spike · §0.2 · v0.3.0")
                    .text_size(px(11.0))
                    .opacity(0.6),
            ),
        )
}

fn nav_item(screen: Signal<Screen>, target: Screen, label: &'static str) -> View {
    view()
        .h_10()
        .mx_2()
        .rounded_lg()
        .px_3()
        .flex_row()
        .items_center()
        .bg(move || {
            if screen.get() == target {
                theme().sidebar_accent
            } else {
                theme().sidebar
            }
        })
        .hover(|s| s.bg(theme().sidebar_accent))
        .cursor_pointer()
        .on_press(move || screen.set(target))
        .child(
            text(label)
                .text_size(px(13.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if screen.get() == target {
                        theme().sidebar_primary_foreground
                    } else {
                        theme().sidebar_foreground
                    }
                }),
        )
}

fn mobile_shell(
    screen: Signal<Screen>,
    data: VaultData,
    selected: Signal<Option<bw_proto::ItemId>>,
) -> View {
    let tab = |target: Screen, label: &'static str| {
        let press = screen;
        let tint = screen;
        view()
            .flex_1()
            .h_11()
            .flex_row()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .on_press(move || press.set(target))
            .child(text(label).text_size(px(14.0)).text_color(move || {
                if tint.get() == target {
                    theme().foreground
                } else {
                    theme().muted_foreground
                }
            }))
    };
    view()
        .flex_col()
        .flex_1()
        .child(
            view()
                .flex_row()
                .h_11()
                .border_b(px(1.0))
                .border_color(move || theme().border)
                .child(tab(Screen::Providers, "Providers"))
                .child(tab(Screen::Vault, "Vault")),
        )
        .child(content(screen, data, selected))
}

fn content(
    screen: Signal<Screen>,
    data: VaultData,
    selected: Signal<Option<bw_proto::ItemId>>,
) -> View {
    let dir = data.dir.clone();
    let items = std::rc::Rc::new(data.items);
    let nav = screen;
    let list = screen;
    view()
        .flex_1()
        .flex_col()
        .child(when(
            move || nav.get() == Screen::Providers,
            move || providers::settings_page(dir.clone()),
        ))
        .child(when(
            move || list.get() == Screen::Vault,
            move || vault::vault_page(items.clone(), selected),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_screen_follows_env_with_providers_default() {
        // edition 2024：env 寫入是 unsafe；本測試是本 crate 唯一動 env 的。
        unsafe {
            std::env::remove_var("NSH_SPIKE_SCREEN");
            assert_eq!(initial_screen(), Screen::Providers);
            std::env::set_var("NSH_SPIKE_SCREEN", "vault");
            assert_eq!(initial_screen(), Screen::Vault);
            std::env::remove_var("NSH_SPIKE_SCREEN");
        }
    }
}
