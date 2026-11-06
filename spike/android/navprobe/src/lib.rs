//! Android 導航容器探針（契約 §0.2 起押注前的確認項）。
//!
//! 假設：nsh 0.3.0 的 `nav_stack`/`nav_page` 在 Android views 後端會渲染內容
//! （macOS dev host 上卡點 4 是「掛得上但內容區整塊不渲染」）。同時測 `dialog`
//! 是否呈現，因為刪除確認框要用它。
//!
//! 起點是 B 頁已在棧上（靜態兩頁）；按鈕做 push/pop，`when` 區域讓棧的
//! 子頁隨訊號增減（`.children(cond.then(...))` 只在建立時求值，不是反應式的）。
//!
//! 證據取法：`adb exec-out screencap` 看像素、`uiautomator dump` 看 view 層級、
//! logcat 看 `probe:` 開頭的日誌。

use nsh_base::{dialog, nav_page, nav_stack, theme};
use nsh_core::prelude::*;

#[native_module("bitward-navprobe/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// The application's root component.
#[component]
pub fn App() -> impl IntoElement {
    // 1 = B 在棧上（起點即靜態兩頁）。
    let pushed = signal(1_u32);
    let modal = signal(0_u32);

    view()
        .flex_1()
        .bg(move || theme().background)
        .text_color(move || theme().foreground)
        .child(
            nav_stack()
                .flex_1()
                .child(
                    nav_page()
                        .key("probe-a")
                        .title("Probe A")
                        .child(page_a(modal)),
                )
                .child(when(
                    move || pushed.get() > 0,
                    move || {
                        nav_page()
                            .key("probe-b")
                            .title("Probe B")
                            .on_dismiss(move || {
                                log::info!("probe: dismissed b");
                                pushed.set(0);
                            })
                            .child(page_b(pushed))
                    },
                )),
        )
        .child(when(
            move || modal.get() > 0,
            move || dialog().child(page_dialog(modal)),
        ))
}

fn page_a(modal: Signal<u32>) -> View {
    view().flex_1().flex_col().p_safe_area().child(
        scroll().flex_1().child(
            view()
                .flex_col()
                .gap_4()
                .items_start()
                .child(text("PROBE-A-ROOT").text_size(px(28.0)))
                .child(button("SHOW-DIALOG", move || {
                    log::info!("probe: A1 plain in scroll");
                }))
                .child(when(
                    move || modal.get() < 9,
                    move || {
                        button("IF-BUTTON", move || {
                            log::info!("probe: A2 inside If region");
                        })
                    },
                ))
                .child(
                    nsh_base::input()
                        .value(String::new())
                        .placeholder("type here".to_owned())
                        .on_change(|t: &str| log::info!("probe: A3 input change {}", t))
                        .h_12()
                        .w(px(420.0))
                        .px_3()
                        .border(px(1.0)),
                )
                .child(button("AFTER-INPUT", move || {
                    log::info!("probe: A4 after input in scroll");
                })),
        ),
    )
}

fn page_b(pushed: Signal<u32>) -> View {
    view()
        .flex_1()
        .flex_col()
        .p_safe_area()
        .gap_4()
        .items_start()
        .child(text("PROBE-B-TOP").text_size(px(28.0)))
        .child(button("POP-VIA-STATE", move || {
            log::info!("probe: pop via state");
            pushed.set(0);
        }))
        .child(button("SHOW-DIALOG-B", move || {
            log::info!("probe: show dialog from b");
            pushed.set(1);
        }))
}

fn page_dialog(modal: Signal<u32>) -> View {
    view().flex_1().items_center().justify_center().child(
        view()
            .gap_4()
            .p_8()
            .rounded(px(12.0))
            .bg(move || theme().background)
            .child(text("PROBE-DIALOG").text_size(px(24.0)))
            .child(button("CLOSE-DIALOG", move || {
                log::info!("probe: close dialog");
                modal.set(0);
            })),
    )
}

fn button(label: &'static str, on_press: impl Fn() + 'static) -> View {
    view()
        .px_5()
        .py_3()
        .rounded(px(10.0))
        .bg(move || theme().primary)
        .active(|s| s.opacity(0.6))
        .on_press(move || on_press())
        .child(
            text(label)
                .text_size(px(17.0))
                .text_color(move || theme().primary_foreground),
        )
}
