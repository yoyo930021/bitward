//! Vault 列表頁：搜尋（Query.text 交 daemon FTS）、tag 過濾（本地下拉、
//! 比對在 daemon）、排序選單、pending 徽章。鎖態指示在標題列（lib.rs）。

use bw_proto::{ItemView, SortKey};
use nsh_base::{input, theme};
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd};
use crate::ui;

pub fn page(core: AppCore) -> View {
    let search_core = core.clone();
    let query = core.query;
    let tag_btn = core.clone();
    let tag_open = core.clone();
    let sort_btn = core.clone();
    let sort_open = core.clone();
    let refresh = core.clone();
    let count_core = core.clone();
    let tag_cond = core.clone();
    let tag_build = core.clone();
    let sort_cond = core.clone();
    let sort_build = core.clone();
    let list_core = core.clone();
    view()
        .flex_col()
        .flex_1()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .px_6()
                .pt_4()
                .pb_2()
                .child(
                    input()
                        .value(move || query.get())
                        .placeholder("搜尋名稱、網址或標籤")
                        .on_change(move |text: &str| {
                            // 輸入回聲直接寫訊號；重抓走命令佇列（下一個
                            // tick 合批，連續打字只發一次 List）。
                            search_core.query.set(text.to_owned());
                            search_core.send(Cmd::RefetchList);
                        })
                        .h_9()
                        .px_3()
                        .rounded_lg()
                        .border(px(1.0))
                        .border_color(move || theme().border)
                        .text_color(move || theme().foreground)
                        .flex_1(),
                )
                .child(filter_button(
                    "標籤",
                    move || tag_btn.tag.get().unwrap_or_else(|| "全部".to_owned()),
                    move || tag_open.send(Cmd::ToggleTagMenu),
                ))
                .child(filter_button(
                    "排序",
                    move || sort_label(sort_btn.sort.get()),
                    move || sort_open.send(Cmd::ToggleSortMenu),
                ))
                .child(ui::button("重新整理", ui::Btn::Muted, move || {
                    refresh.send(Cmd::RefetchList)
                })),
        )
        .child(when(
            move || tag_cond.tag_menu.get(),
            move || tag_panel(tag_build.clone()),
        ))
        .child(when(
            move || sort_cond.sort_menu.get(),
            move || sort_panel(sort_build.clone()),
        ))
        .child(
            text(move || format!("共 {} 筆", count_core.items.get().len()))
                .text_size(px(12.0))
                .text_color(move || theme().muted_foreground)
                .px_6()
                .pb_2(),
        )
        .child(list_body(list_core))
}

/// 下拉觸發鈕：標籤/排序共用。
fn filter_button(
    prefix: &'static str,
    value: impl Fn() -> String + 'static,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .h_9()
        .px_3()
        .rounded_lg()
        .flex_row()
        .items_center()
        .gap_1p5()
        .cursor_pointer()
        .active(|s| s.opacity(0.7))
        .border(px(1.0))
        .border_color(move || theme().border)
        .bg(move || theme().muted)
        .on_press(on_press)
        .child(
            text(move || format!("{prefix}：{}", value()))
                .text_size(px(12.5))
                .text_color(move || theme().foreground),
        )
        .child(
            text("▾")
                .text_size(px(10.0))
                .text_color(move || theme().muted_foreground),
        )
}

fn sort_label(sort: SortKey) -> String {
    match sort {
        SortKey::Name => "名稱".to_owned(),
        SortKey::Used => "最近使用".to_owned(),
        SortKey::Updated => "最近更新".to_owned(),
        SortKey::Created => "建立時間".to_owned(),
    }
}

/// 標籤選項取自目前載入的清單（本地下拉；過濾仍由 daemon 執行）。
/// 面板開啟期間清單若變動，下次開面板才會更新——可接受的快取語意。
fn tag_panel(core: AppCore) -> View {
    let current = core.tag.get();
    let mut tags: Vec<String> = Vec::new();
    for v in core.items.get().iter() {
        for t in &v.meta.tags {
            if !tags.iter().any(|x| x == t) {
                tags.push(t.clone());
            }
        }
    }
    tags.sort();
    let mut rows: Vec<View> = Vec::new();
    {
        let c = core.clone();
        rows.push(ui::menu_row(
            "全部標籤".into(),
            current.is_none(),
            move || c.send(Cmd::ChooseTag(None)),
        ));
    }
    for t in tags {
        let c = core.clone();
        let chosen = current.as_deref() == Some(t.as_str());
        let label = t.clone();
        rows.push(ui::menu_row(label, chosen, move || {
            c.send(Cmd::ChooseTag(Some(t.clone())))
        }));
    }
    view()
        .px_6()
        .pb_2()
        .child(scroll().max_h(px(240.)).child(ui::card(rows).w(px(240.0))))
}

fn sort_panel(core: AppCore) -> View {
    let current = core.sort.get();
    let rows = [SortKey::Name, SortKey::Used, SortKey::Updated]
        .iter()
        .map(|k| {
            let c = core.clone();
            let key = *k;
            ui::menu_row(sort_label(key), current == key, move || {
                c.send(Cmd::ChooseSort(key))
            })
        })
        .collect();
    ui::card(rows).mx_6()
}

fn list_body(core: AppCore) -> impl IntoElement {
    let count_core = core.clone();
    let keys_core = core.clone();
    let row_core = core.clone();
    virtual_list(
        move || count_core.items.get().len(),
        move |at| row(row_core.clone(), at),
    )
    .flex_1()
    .keys(move || {
        keys_core
            .items
            .get()
            .iter()
            .map(|v| v.meta.id)
            .collect::<Vec<_>>()
    })
    .separator(move || {
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
    )
}

/// 列高 72pt：Apple HIG 44pt 最小可點高度之上留三行空間（spike NOTES 來源同）。
fn row(core: AppCore, at: Position) -> View {
    let press_core = core.clone();
    let avatar_core = core.clone();
    let name_core = core.clone();
    let sub_core = core.clone();
    let right_core = core.clone();
    let fav_core = core.clone();
    view()
        .h(px(72.0))
        .px_6()
        .flex_row()
        .items_center()
        .gap_3()
        .cursor_pointer()
        .hover(|s| s.bg(theme().accent))
        .on_press(move || {
            if let Some(v) = press_core.items.get().get(at.index()) {
                press_core.send(Cmd::OpenDetail(v.meta.id));
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
                        // 頭像字元讀位置訊號：cell 回收後才跟著換列（spike 同款）。
                        avatar_core
                            .items
                            .get()
                            .get(at.index())
                            .and_then(|v| v.meta.name.clone())
                            .and_then(|n| n.chars().next().map(|c| c.to_uppercase().to_string()))
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
                        name_core
                            .items
                            .get()
                            .get(at.index())
                            .map(|v| v.meta.name.clone().unwrap_or_else(|| "(未命名)".to_owned()))
                            .unwrap_or_default()
                    })
                    .text_size(px(14.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(move || theme().foreground)
                    .number_of_lines(1),
                )
                .child(
                    text(move || {
                        sub_core
                            .items
                            .get()
                            .get(at.index())
                            .map(subtitle)
                            .unwrap_or_default()
                    })
                    .text_size(px(12.0))
                    .text_color(move || theme().muted_foreground)
                    .number_of_lines(1),
                ),
        )
        .child(
            view()
                .flex_col()
                .items_end()
                .gap_0p5()
                .child(
                    text(move || match right_core.items.get().get(at.index()) {
                        Some(v) if v.meta.pending => "待推送".to_owned(),
                        Some(v) => ui::short_date(v.meta.updated_at.as_deref()),
                        None => String::new(),
                    })
                    .text_size(px(11.0))
                    .text_color(move || theme().muted_foreground),
                )
                .child(
                    text(move || {
                        if fav_core
                            .items
                            .get()
                            .get(at.index())
                            .is_some_and(|v| v.meta.favorite)
                        {
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
}

/// 副標：uri 首條；沒有 uri 才退到標籤列（不顯示任何 Secret 級欄位）。
fn subtitle(item: &ItemView) -> String {
    match item.meta.uris.first() {
        Some(uri) => uri.clone(),
        None if item.meta.tags.is_empty() => String::new(),
        None => item.meta.tags.join(" · "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::{ItemId, ItemKind, ItemMeta};

    fn view_of(uris: Vec<&str>, tags: Vec<&str>) -> ItemView {
        ItemView::metadata(ItemMeta {
            id: ItemId::new_v4(),
            kind: ItemKind::Login,
            name: Some("x".into()),
            uris: uris.into_iter().map(str::to_owned).collect(),
            folder_id: None,
            organization_id: None,
            collections: Vec::new(),
            favorite: false,
            tags: tags.into_iter().map(str::to_owned).collect(),
            updated_at: None,
            pending: false,
        })
    }

    #[test]
    fn subtitle_prefers_uri_then_tags() {
        assert_eq!(
            subtitle(&view_of(vec!["https://a.com"], vec![])),
            "https://a.com"
        );
        assert_eq!(
            subtitle(&view_of(vec![], vec!["dev", "工作"])),
            "dev · 工作"
        );
        assert_eq!(subtitle(&view_of(vec![], vec![])), "");
    }
}
