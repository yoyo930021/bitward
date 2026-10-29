//! The app's Rust UI: its root component, which `nsh run`, `nsh package`
//! and `cargo run` mount.

use bw_proto::{ItemKind, ItemMeta, ItemView};
use nsh_core::prelude::*;
use nsh_base::theme;

/// 假設 2 的證據：一筆 `bw_proto::ItemMeta` 經 serde_json 序列化/反序列化
/// round-trip。Android 上跑的程式碼路徑與桌面相同（純 Rust crate）。
pub fn sample_item_json() -> String {
    let meta = ItemMeta {
        id: bw_proto::ItemId::new_v4(),
        kind: ItemKind::Login,
        name: Some("github".into()),
        uris: vec!["https://github.com".into()],
        folder_id: None,
        organization_id: None,
        favorite: false,
        tags: vec!["dev".into()],
        updated_at: None,
        pending: false,
    };
    let json = serde_json::to_string(&ItemView::metadata(meta)).unwrap();
    // round-trip 驗形：Metadata 輸出不得含機密欄位鍵。
    let back: ItemView = serde_json::from_str(&json).unwrap();
    assert!(back.username.is_none() && back.password.is_none());
    assert!(!json.contains("\"password\""));
    json
}

/// The app's UI set (`nsh.json` `"rust"`): what a TSX entry may import from
/// `bitward-android-spike/native` (`README.md`, "Adding a TSX entry").
#[native_module("bitward-android-spike/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// The application's root component.
#[component]
pub fn App() -> impl IntoElement {
    let count = signal(0_u32);
    view()
        .flex_1()
        .bg(move || theme().background)
        .text_color(move || theme().foreground)
        .child(
            view()
                .flex_1()
                .p_safe_area()
                .child(
                    view()
                        .flex_1()
                        .items_center()
                        .justify_center()
                        .gap_4()
                        .child(text(move || format!("Count: {}", count.get())).text_size(px(28.0)))
                        .child(
                            // 掛載即執行 bw-proto 序列化路徑（假設 2 的執行期證據）。
                            text(move || {
                                format!("ItemMeta json {}B", sample_item_json().len())
                            })
                            .text_size(px(14.0)),
                        )
                        .child(
                            view()
                                .px_5()
                                .py_3()
                                .rounded(px(10.0))
                                .bg(move || theme().primary)
                                .active(|s| s.opacity(0.6))
                                .on_press(move || count.update(|value| *value += 1))
                                .child(
                                    text("Tap")
                                        .text_size(px(17.0))
                                        .text_color(move || theme().primary_foreground),
                                ),
                        ),
                ),
        )
}

#[cfg(test)]
mod tests {
    #[test]
    fn item_meta_roundtrips() {
        let j = super::sample_item_json();
        assert!(j.contains("github") && j.contains("\"uris\""));
    }
}
