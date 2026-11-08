//! Vault 列表（左欄＋全寬工具列）：搜尋（Query.text 交 daemon FTS）、
//! tag 過濾（chips 行，比對在 daemon）、排序選單、pending 徽章、
//! 選中列（Route::Detail 對應項）accent 指示條。鎖態/標題在 lib.rs。

use std::rc::Rc;

use bw_proto::{ItemView, SortKey};
use nsh_base::input;
use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, Route};
use crate::theme;
use crate::ui;

/// 工具列：全寬圓角搜尋框＋排序/重新整理＋標籤 chips 行＋排序下拉。
pub fn toolbar(core: AppCore) -> View {
    let search_core = core.clone();
    let query = core.query;
    let sort_btn = core.clone();
    let sort_open = core.clone();
    let refresh = core.clone();
    let chip_core = core.clone();
    let sort_cond = core.clone();
    let sort_build = core.clone();
    view()
        .flex_col()
        .gap_1p5()
        .px_6()
        .pt_2p5()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .flex_1()
                        .relative()
                        .child(
                            input()
                                .value(move || query.get())
                                .placeholder("搜尋名稱、網址或標籤")
                                .placeholder_color(move || theme::TEXT_MUTED.light)
                                .on_change(move |text: &str| {
                                    // 輸入回聲直接寫訊號；重抓走命令佇列（下一個
                                    // tick 合批，連續打字只發一次 List）。
                                    search_core.query.set(text.to_owned());
                                    search_core.send(Cmd::RefetchList);
                                })
                                .h(px(theme::INPUT_H))
                                .pl(px(34.0))
                                .pr_3()
                                .rounded_xl()
                                .border(px(1.0))
                                .border_color(theme::HAIRLINE)
                                .bg(theme::SURFACE)
                                .text_color(theme::TEXT_PRIMARY)
                                .transition_colors()
                                .duration(150.0)
                                .focus(|s| s.border_color(theme::ACCENT)),
                        )
                        .child(
                            view()
                                .absolute()
                                .top_0()
                                .bottom_0()
                                .left_0()
                                .w(px(34.0))
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .child(
                                    text("⌕")
                                        .text_size(px(15.0))
                                        .text_color(theme::TEXT_MUTED),
                                ),
                        ),
                )
                .child(filter_button(
                    "排序",
                    move || sort_label(sort_btn.sort.get()),
                    move || sort_open.send(Cmd::ToggleSortMenu),
                ))
                .child(ui::button("重新整理", ui::Btn::Ghost, move || {
                    refresh.send(Cmd::RefetchList)
                })),
        )
        .child(chip_row(chip_core))
        .child(when(
            move || sort_cond.sort_menu.get(),
            move || sort_panel(sort_build.clone()),
        ))
}

/// 標籤 chips 行：選項取自目前載入的清單（過濾仍由 daemon 執行）；
/// 選中描邊轉 accent，再點一次選中的 chip ＝回到全部。
fn chip_row(core: AppCore) -> View {
    let all_sel = core.clone();
    let all_press = core.clone();
    let items = core.items;
    let row_core = core.clone();
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .overflow_hidden()
        .child(chip(
            "全部標籤".to_owned(),
            move || all_sel.tag.get().is_none(),
            move || all_press.send(Cmd::ChooseTag(None)),
        ))
        .child(each(
            move || collect_tags(&items.get()),
            |t: &String| t.clone(),
            move |item: ReadSignal<String>, _| {
                let sel_core = row_core.clone();
                let press_core = row_core.clone();
                chip_dyn(
                    move || item.get(),
                    move || item.with(|t| sel_core.tag.get().as_deref() == Some(t.as_str())),
                    move || {
                        let t = item.get();
                        let clear = press_core.tag.get().as_deref() == Some(t.as_str());
                        press_core.send(Cmd::ChooseTag(if clear { None } else { Some(t) }));
                    },
                )
            },
        ))
}

/// 目前清單裡出現过的標籤（去重、字典序）。
fn collect_tags(items: &[ItemView]) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for v in items {
        for t in &v.meta.tags {
            if !tags.iter().any(|x| x == t) {
                tags.push(t.clone());
            }
        }
    }
    tags.sort();
    tags
}

fn chip(label: String, selected: impl Fn() -> bool + 'static, on_press: impl Fn() + 'static) -> View {
    chip_dyn(move || label.clone(), selected, on_press)
}

fn chip_dyn(
    label: impl Fn() -> String + 'static,
    selected: impl Fn() -> bool + 'static,
    on_press: impl Fn() + 'static,
) -> View {
    let selected = Rc::new(selected);
    let sel_bg = selected.clone();
    let sel_border = selected.clone();
    let sel_text = selected;
    view()
        .h(px(theme::CHIP_H))
        .px_2p5()
        .rounded_full()
        .flex_row()
        .items_center()
        .cursor_pointer()
        .border(px(1.0))
        .transition_colors()
        .duration(150.0)
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .bg(move || {
            if sel_bg() {
                theme::ACCENT.opacity(0.14)
            } else {
                theme::SURFACE
            }
        })
        .border_color(move || {
            if sel_border() {
                theme::ACCENT
            } else {
                theme::HAIRLINE
            }
        })
        .child(
            text(label)
                .text_size(px(12.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if sel_text() {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_SECONDARY
                    }
                }),
        )
}

/// 下拉觸發鈕（排序）。
fn filter_button(
    prefix: &'static str,
    value: impl Fn() -> String + 'static,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .h(px(theme::INPUT_H))
        .px_3()
        .rounded_full()
        .flex_row()
        .items_center()
        .gap_1p5()
        .cursor_pointer()
        .active(|s| s.opacity(0.7))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::SURFACE)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(on_press)
        .child(
            text(move || format!("{prefix}：{}", value()))
                .text_size(px(12.5))
                .text_color(theme::TEXT_SECONDARY),
        )
        .child(
            text("▾")
                .text_size(px(10.0))
                .text_color(theme::TEXT_MUTED),
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
    view().child(ui::card(rows).w(px(220.0)))
}

/// 列表本體（左欄）：38px 緊湊列、選中列提亮＋左 3px accent 條。
pub fn panel(core: AppCore) -> impl IntoElement {
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
            .ml(px(65.0))
            .mr_4()
            .bg(theme::HAIRLINE)
    })
    .empty(
        view()
            .h_40()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_1()
            .child(
                text("找不到符合的項目")
                    .text_size(px(14.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme::TEXT_SECONDARY),
            ),
    )
}

/// 列高 38：monogram 26＋雙行緊湊文字；右側只放狀態膠囊（待推送）與星。
fn row(core: AppCore, at: Position) -> View {
    let press_core = core.clone();
    let name_core = core.clone();
    let sub_core = core.clone();
    let right_core = core.clone();
    let fav_core = core.clone();
    let sel_bg = core.clone();
    let sel_bar = core.clone();
    view()
        .relative()
        .h(px(theme::ROW_H))
        .pl_6()
        .pr_4()
        .flex_row()
        .items_center()
        .gap_3()
        .cursor_pointer()
        .transition_colors()
        .duration(120.0)
        .hover(|s| s.bg(theme::SURFACE_RAISED))
        .bg(move || {
            if is_selected(&sel_bg, at) {
                theme::SURFACE_RAISED
            } else {
                AdaptiveColor::TRANSPARENT
            }
        })
        .on_press(move || {
            if let Some(v) = press_core.items.get().get(at.index()) {
                press_core.send(Cmd::OpenDetail(v.meta.id));
            }
        })
        .child(
            view()
                .absolute()
                .top_0()
                .bottom_0()
                .left_0()
                .w(px(3.0))
                .bg(move || {
                    if is_selected(&sel_bar, at) {
                        theme::ACCENT
                    } else {
                        AdaptiveColor::TRANSPARENT
                    }
                }),
        )
        .child(ui::monogram(
            move || {
                name_core
                    .items
                    .get()
                    .get(at.index())
                    .and_then(|v| v.meta.name.clone())
            },
            theme::MONOGRAM_ROW,
            theme::MONOGRAM_ROW_RADIUS,
            theme::MONOGRAM_ROW_TEXT,
        ))
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
                    .text_size(px(theme::TEXT_ROW))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme::TEXT_PRIMARY)
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
                    .text_size(px(theme::TEXT_ROW_SUB))
                    .text_color(theme::TEXT_SECONDARY)
                    .number_of_lines(1),
                ),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_1p5()
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
                    .text_color(theme::ACCENT),
                )
                .child(when(
                    move || right_core.items.get().get(at.index()).is_some_and(|v| v.meta.pending),
                    || ui::badge("待推送", theme::WARNING, theme::WARNING.opacity(0.16)),
                )),
        )
}

/// 該列是否為目前詳情頁展示的項目（Route 是唯一導航真相）。
fn is_selected(core: &AppCore, at: Position) -> bool {
    match core.route.get() {
        Route::Detail(id) => core
            .items
            .get()
            .get(at.index())
            .is_some_and(|v| v.meta.id == id),
        _ => false,
    }
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

    #[test]
    fn collect_tags_dedups_and_sorts() {
        let a = view_of(vec![], vec!["工作", "dev"]);
        let b = view_of(vec![], vec!["dev"]);
        assert_eq!(collect_tags(&[a, b]), vec!["dev".to_owned(), "工作".to_owned()]);
    }
}
