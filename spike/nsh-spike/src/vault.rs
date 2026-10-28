//! Vault 列表頁：搜尋框 + `virtual_list` + 點擊進詳情（契約 §0.2 的兩個真實畫面之一）。
//! 資料是 `bw_proto::ItemMeta`（fixtures/items.json），型別來源即正式核心。
//! 詳情用 `nav_stack`/`nav_page`：原生 push/pop，列表在詳情後維持滾動狀態。

use std::rc::Rc;

use bw_proto::{ItemId, ItemKind, ItemMeta};
use nsh_base::{input, theme};
use nsh_core::EllipsizeMode;
use nsh_core::prelude::*;

pub fn vault_page(items: Rc<Vec<ItemMeta>>, selected: Signal<Option<ItemId>>) -> View {
    let query = signal(String::new());

    let filtered = computed({
        let items = items.clone();
        move || {
            let q = query.get().to_lowercase();
            items
                .iter()
                .filter(|it| q.is_empty() || matches(it, &q))
                .cloned()
                .collect::<Vec<_>>()
        }
    });

    let total = items.len();
    view()
        .flex_1()
        .flex_col()
        .child(when(
            move || selected.get().is_some(),
            move || {
                let id = selected.get().unwrap_or_default();
                let back = selected;
                view()
                    .flex_col()
                    .flex_1()
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_3()
                            .px_6()
                            .py_4()
                            .border_b(px(1.0))
                            .border_color(move || theme().border)
                            .child(
                                view()
                                    .h_8()
                                    .px_3()
                                    .rounded_lg()
                                    .flex_row()
                                    .items_center()
                                    .cursor_pointer()
                                    .active(|s| s.opacity(0.7))
                                    .bg(move || theme().muted)
                                    .on_press(move || back.set(None))
                                    .child(text("← 返回").text_size(px(13.0))),
                            )
                            .child(
                                text({
                                    let items = items.clone();
                                    move || {
                                        let id = selected.get().unwrap_or_default();
                                        items
                                            .iter()
                                            .find(|it| it.id == id)
                                            .and_then(|it| it.name.clone())
                                            .unwrap_or_else(|| "(未命名)".to_owned())
                                    }
                                })
                                .text_size(px(17.0))
                                .font_weight(FontWeight::SEMIBOLD),
                            ),
                    )
                    .child(detail_content(id, items.clone()))
            },
        ))
        .child(when(
            move || selected.get().is_none(),
            move || list_page(filtered, query, selected, total),
        ))
}

fn matches(item: &ItemMeta, q: &str) -> bool {
    item.name
        .as_deref()
        .is_some_and(|n| n.to_lowercase().contains(q))
        || item.uris.iter().any(|u| u.to_lowercase().contains(q))
        || item.tags.iter().any(|t| t.to_lowercase().contains(q))
}

fn list_page(
    filtered: Memo<Vec<ItemMeta>>,
    query: Signal<String>,
    selected: Signal<Option<ItemId>>,
    total: usize,
) -> View {
    view()
        .flex_col()
        .flex_1()
        .child(
            view()
                .flex_col()
                .gap_2()
                .px_6()
                .pb_3()
                .child(
                    text(move || format!("共 {total} 筆 · 顯示 {} 筆", filtered.get().len()))
                        .text_size(px(12.0))
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    input()
                        .value(move || query.get())
                        .placeholder("搜尋名稱、網址或標籤".to_owned())
                        .on_change(move |text: &str| query.set(text.to_owned()))
                        .h_10()
                        .px_3()
                        .rounded_lg()
                        .border(px(1.0))
                        .border_color(move || theme().border)
                        .text_color(move || theme().foreground),
                ),
        )
        .child(
            virtual_list(
                move || filtered.get().len(),
                move |at| {
                    view()
                        .h_16()
                        .px_6()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .cursor_pointer()
                        .hover(|s| s.bg(theme().accent))
                        .bg(move || {
                            let cur = selected.get();
                            let items = filtered.get();
                            if cur.is_some()
                                && items.get(at.index()).is_some_and(|it| Some(it.id) == cur)
                            {
                                theme().accent
                            } else {
                                theme().background
                            }
                        })
                        .on_press(move || {
                            let items = filtered.get();
                            if let Some(it) = items.get(at.index()) {
                                selected.set(Some(it.id));
                            }
                        })
                        .child(
                            view()
                                .w_9()
                                .h_9()
                                .rounded(px(18.0))
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .bg(move || theme().muted)
                                .child(
                                    text(move || {
                                        // 頭像字元讀位置訊號：单元格回收後才跟著換列。
                                        let items = filtered.get();
                                        items
                                            .get(at.index())
                                            .and_then(|it| it.name.clone())
                                            .and_then(|n| {
                                                n.chars()
                                                    .next()
                                                    .map(|c| c.to_uppercase().to_string())
                                            })
                                            .unwrap_or_else(|| "?".to_owned())
                                    })
                                    .text_size(px(13.0))
                                    .font_weight(FontWeight::SEMIBOLD),
                                ),
                        )
                        .child(
                            view()
                                .flex_col()
                                .flex_1()
                                .gap_0p5()
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        items
                                            .get(at.index())
                                            .and_then(|it| it.name.clone())
                                            .unwrap_or_else(|| "(未命名)".to_owned())
                                    })
                                    .text_size(px(14.0))
                                    .font_weight(FontWeight::MEDIUM)
                                    .number_of_lines(1)
                                    .ellipsize_mode(EllipsizeMode::Tail),
                                )
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        items.get(at.index()).map(subtitle).unwrap_or_default()
                                    })
                                    .text_size(px(12.0))
                                    .text_color(move || theme().muted_foreground)
                                    .number_of_lines(1)
                                    .ellipsize_mode(EllipsizeMode::Tail),
                                ),
                        )
                        .child(
                            view()
                                .flex_col()
                                .items_end()
                                .gap_0p5()
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        match items.get(at.index()) {
                                            Some(it) if it.pending => "待推送".to_owned(),
                                            Some(it) => short_date(it.updated_at.as_deref()),
                                            None => String::new(),
                                        }
                                    })
                                    .text_size(px(11.0))
                                    .text_color(move || theme().muted_foreground),
                                )
                                .child(
                                    text(move || {
                                        let items = filtered.get();
                                        if items.get(at.index()).is_some_and(|it| it.favorite) {
                                            "★"
                                        } else {
                                            ""
                                        }
                                        .to_owned()
                                    })
                                    .text_size(px(12.0))
                                    .text_color(move || theme().primary),
                                ),
                        )
                },
            )
            .flex_1()
            .keys(move || filtered.get().iter().map(|it| it.id).collect::<Vec<_>>())
            .separator(|| {
                view()
                    .h(px(1.0))
                    .ml(px(56.0))
                    .mr_6()
                    .bg(move || theme().border)
            })
            .empty(
                view()
                    .h_24()
                    .flex_row()
                    .items_center()
                    .justify_center()
                    .child(
                        text("找不到符合的項目")
                            .text_size(px(13.0))
                            .text_color(move || theme().muted_foreground),
                    ),
            ),
        )
}

fn subtitle(item: &ItemMeta) -> String {
    let kind = kind_label(item.kind);
    match item.uris.first() {
        Some(uri) => format!("{kind} · {uri}"),
        None => format!("{kind} · {}", item.tags.join(", ")),
    }
}

fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "登入",
        ItemKind::SecureNote => "安全備註",
        ItemKind::Card => "卡片",
        ItemKind::Identity => "身分",
    }
}

/// 列高 64pt：Apple HIG 可點列表列最小 44pt 之上留雙行空間，
/// <https://developer.apple.com/design/human-interface-guidelines/lists-and-tables>
/// 只取日期部分；updated_at 是 ISO-8601 字串（契約 §2 原樣保存）。
fn short_date(updated_at: Option<&str>) -> String {
    updated_at
        .map(|d| d.get(..10).unwrap_or(d).to_owned())
        .unwrap_or_else(|| "—".to_owned())
}

fn detail_content(id: ItemId, items: Rc<Vec<ItemMeta>>) -> View {
    let Some(item) = items.iter().find(|it| it.id == id).cloned() else {
        return view().flex_1();
    };
    view().flex_1().child(
        scroll().flex_1().child(
            view()
                .flex_col()
                .gap_4()
                .px_6()
                .py_5()
                .max_w(px(520.0))
                .child(meta_row("類型", kind_label(item.kind).to_owned()))
                .child(meta_row(
                    "網址",
                    if item.uris.is_empty() {
                        "—".to_owned()
                    } else {
                        item.uris.join("\n")
                    },
                ))
                .child(meta_row(
                    "標籤",
                    if item.tags.is_empty() {
                        "—".to_owned()
                    } else {
                        item.tags.join(" · ")
                    },
                ))
                .child(meta_row(
                    "常用",
                    if item.favorite { "★" } else { "—" }.to_owned(),
                ))
                .child(meta_row(
                    "待推送",
                    if item.pending {
                        "outbox 有未推變更".to_owned()
                    } else {
                        "—".to_owned()
                    },
                ))
                .child(meta_row(
                    "更新時間",
                    item.updated_at.unwrap_or_else(|| "—".to_owned()),
                ))
                .child(meta_row("id", item.id.to_string())),
        ),
    )
}

fn meta_row(label: &'static str, value: String) -> View {
    view()
        .flex_col()
        .gap_0p5()
        .child(
            text(label)
                .text_size(px(11.5))
                .uppercase()
                .text_color(move || theme().muted_foreground),
        )
        .child(text(value).text_size(px(13.5)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str, uris: Vec<String>, tags: Vec<String>) -> ItemMeta {
        ItemMeta {
            id: ItemId::default(),
            kind: ItemKind::Login,
            name: Some(name.into()),
            uris,
            folder_id: None,
            organization_id: None,
            favorite: false,
            tags,
            updated_at: None,
            pending: false,
        }
    }

    #[test]
    fn search_matches_name_uri_and_tag() {
        let it = item(
            "GitHub",
            vec!["https://github.com".into()],
            vec!["dev".into()],
        );
        assert!(matches(&it, "git"));
        assert!(matches(&it, "com"));
        assert!(matches(&it, "dev"));
        assert!(!matches(&it, "nope"));
    }

    #[test]
    fn short_date_truncates_to_day() {
        assert_eq!(short_date(Some("2026-10-28T09:12:00Z")), "2026-10-28");
        assert_eq!(short_date(None), "—");
    }
}
