//! 畫面：登入頁、金庫列表（chip 列＋FAB）、詳情頁（分節值塊＋TOTP 自動碼）、
//! 全頁表單（新增／編輯）。
//!
//! 這裡零業務語意：KDF、信封、鏡像、搜尋都在 `hub`（＝根 workspace 的核心
//! crate）。UI 只做訊號與排版，顏色尺寸一律取自 [`crate::theme`]（觸控密度
//! 44/44/56，官方淺色皮＋Bitwarden 藍，暗槽跟隨系統）。明文紀律（契約 §2.7）：
//! - 主密碼欄位是 nsh 的 `String`（不可清零），`Hub::login` 收到後立刻放進
//!   `Zeroizing` 派生，完成時把欄位清空（見 `login_page` 的回呼）。
//! - 詳情頁的明文只存在 `plain` 訊號；`on_dismiss`（含系統返回鍵）即歸零。
//! - 表單預填的明文副本收頁時連同訊號一起丟棄。
//!
//! 導航形態（手機適配，取捨記錄在 `theme` 模組文件）：列表是棧底頁，詳情與
//! 表單都是 `nav_stack` push 上去的一頁（返回鍵語意免費）；新增走右下角 FAB。
//! favicon 快取在 [`Icons`]（App 根建立、列表頁 `effect` 發起請求，形態同
//! macOS `state::icons`；缺圖一律退字母磚，不空白不閃爍）。

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bw_proto::{CipherDraft, CipherField, CipherFieldKind, FieldEdit, ItemId, ItemKind, ItemMeta};
use nsh_base::{input, nav_page};
use nsh_core::EllipsizeMode;
use nsh_core::element::Screen;
use nsh_core::prelude::*;

use crate::Phase;
use crate::hub::{Hub, IconState, Revealed, Snapshot, host_of};
use crate::theme;

/// 編輯頁的目標：新增一筆，或編輯既有的某筆（預填走 `Hub::reveal`）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Editor {
    New,
    Edit(ItemId),
}

/// 中樞開不起來（資料目錄不可寫等）：明確失敗畫面，不靜默降格。
pub fn broken_page(err: String) -> View {
    view()
        .flex_1()
        .items_center()
        .justify_center()
        .bg(theme::BASE)
        .text_color(theme::TEXT_PRIMARY)
        .p_safe_area()
        .child(
            view()
                .flex_col()
                .items_center()
                .gap_3()
                .child(
                    text("無法啟動本機中樞")
                        .text_size(px(18.0))
                        .font_weight(FontWeight::SEMIBOLD),
                )
                .child(text(err).text_size(px(13.0)).text_color(theme::TEXT_SECONDARY)),
        )
}

// —— favicon 快取（形態同 macOS `state::icons`：Signal<Arc<HashMap>>）——

/// host → 取圖態。單飛＝請求前先插 `Loading`；`Ready` 存 data: URI。
/// 放 UI 側訊號（不是 Hub 的 Mutex）：渲染訂閱與結算回寫同一條反應鏈。
#[derive(Clone)]
pub struct Icons {
    map: Signal<Arc<HashMap<String, IconState>>>,
}

impl Icons {
    pub fn new() -> Self {
        Self { map: signal(Arc::new(HashMap::new())) }
    }

    /// 渲染期查閱（讀訊號＝建立重繪依賴；結算後磚自動換實圖）。
    fn ready(&self, host: &str) -> Option<String> {
        match self.map.get().get(host) {
            Some(IconState::Ready(uri)) => Some(uri.clone()),
            _ => None,
        }
    }

    /// 對缺態 host 發起取圖：標 `Loading` 擋重複，回包後結算。
    /// Hub 的 `icon_data_uri` 自帶單飛閘＋磁碟快取，這裡只管渲染態。
    fn request(&self, hub: &Arc<Hub>, hosts: &[String]) {
        let mut missing: Vec<String> = Vec::new();
        self.map.update(|m| {
            let map = Arc::make_mut(m);
            for h in hosts {
                if !map.contains_key(h) {
                    map.insert(h.clone(), IconState::Loading);
                    missing.push(h.clone());
                }
            }
        });
        for host in missing {
            let hub = hub.clone();
            let icons = self.clone();
            spawn(async move {
                let uri = hub.icon_data_uri(&host).await;
                icons.map.update(|m| {
                    let map = Arc::make_mut(m);
                    map.insert(
                        host,
                        match uri {
                            Some(u) => IconState::Ready(u),
                            None => IconState::Failed,
                        },
                    );
                });
            });
        }
    }
}

// —— 登入頁 ——

/// 登入頁：服務器 + 信箱 + 主密碼。解鎖成功後根頁換成金庫列表。
pub fn login_page(hub: Arc<Hub>, phase: Signal<Phase>, status: Signal<String>) -> View {
    // 每次這個區域建立時重讀：鎖定後回登入頁也預填剛用過的帳號。
    let account = hub.account();
    let server = signal(
        account
            .as_ref()
            .map(|a| a.server.clone())
            .unwrap_or_else(|| "http://10.0.2.2:18095".to_owned()),
    );
    let email = signal(account.as_ref().map(|a| a.email.clone()).unwrap_or_default());
    let password = signal(String::new());

    let do_server = server;
    let do_email = email;
    let do_password = password;
    let hub_login = hub.clone();
    // Keystore 封存存在＝有免重派生路（第五批）。本頁每次從鎖定態重建時
    // 重讀（封存的落地/作廢都發生在解鎖流之後，不需要渲染期訂閱）。
    let sealed_present = hub.has_sealed();
    let hub_bio = hub.clone();

    view()
        .flex_1()
        .flex_col()
        .bg(theme::BASE)
        .text_color(theme::TEXT_PRIMARY)
        .child(page_header(
            "登入你的密碼庫",
            "本機中樞（in-process）：金鑰派生、同步與鏡像都在這個進程內完成",
        ))
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap_4()
                    .px_5()
                    .py_4()
                    .child(form_field("服務器", "https://vault.example.com", server, false))
                    .child(form_field("電子信箱", "me@example.com", email, false))
                    .child(form_field("主密碼", "只用於派生金鑰，不落地", password, true))
                    .child(primary_button(
                        move || {
                            if phase.get() == Phase::Busy {
                                "登入中…"
                            } else {
                                "登入"
                            }
                        },
                        move || {
                            if do_server.get().trim().is_empty() || do_email.get().trim().is_empty()
                            {
                                status.set("服務器與電子信箱皆為必填".to_owned());
                                return;
                            }
                            if phase.get() == Phase::Busy {
                                return;
                            }
                            let (s, e, p) = (do_server.get(), do_email.get(), do_password.get());
                            status.set(String::new());
                            phase.set(Phase::Busy);
                            let hub = hub_login.clone();
                            spawn(async move {
                                let out = hub.login(&s, &e, &p).await;
                                // 欄位殘留的明文立刻抹掉（金鑰已在 Zeroizing 裡）。
                                do_password.set(String::new());
                                match out {
                                    Ok(snap) => {
                                        log::info!("已登入：{} 筆鏡像", snap.items);
                                        phase.set(Phase::Vault(snap));
                                    }
                                    Err(msg) => {
                                        log::warn!("登入失敗：{msg}");
                                        status.set(msg);
                                        phase.set(Phase::SignedOut);
                                    }
                                }
                            });
                        },
                    ))
                    .child(when(
                        move || sealed_present,
                        move || {
                            let hub = hub_bio.clone();
                            ghost_button(
                                "生物辨識直接解鎖",
                                move || {
                                    if phase.get() == Phase::Busy {
                                        return;
                                    }
                                    phase.set(Phase::Busy);
                                    status.set(String::new());
                                    let hub = hub.clone();
                                    spawn(async move {
                                        // 彈窗路（指紋 STRONG／裝置憑證）：通過
                                        // 即免 KDF 解鎖；拒絕／逾時誠實回表單。
                                        match hub.unseal(true).await {
                                            Ok(snap) => {
                                                log::info!(
                                                    "生物辨識解鎖完成：{} 筆鏡像",
                                                    snap.items
                                                );
                                                phase.set(Phase::Vault(snap));
                                            }
                                            Err(msg) => {
                                                log::warn!("生物辨識解鎖未成功：{msg}");
                                                status.set(format!("{msg}（請輸入主密碼）"));
                                                phase.set(Phase::SignedOut);
                                            }
                                        }
                                    });
                                },
                            )
                        },
                    ))
                    .child(
                        text(move || status.get())
                            .text_size(px(12.5))
                            .line_height(px(18.0))
                            .text_color(theme::DESTRUCTIVE),
                    )
                    .child(
                        text(
                            "示範帳號：以 CLI 現成建立\nbitward dev register --server <網址> --email <信箱>",
                        )
                        .text_size(px(11.5))
                        .line_height(px(17.0))
                        .text_color(theme::TEXT_MUTED),
                    ),
            ),
        )
}

// —— 金庫列表 ——

/// 金庫列表：頂部列（帳號＋計數＋動作）→ 搜尋 → 資料夾 chip 列 →
/// 虛擬列表（44 列高、favicon/字母磚、待推送膠囊）→ 右下 FAB。
/// `rev` 由寫入路徑（表單／刪除）遞增，驅動列表與 chip 重算。
pub fn vault_page(
    hub: Arc<Hub>,
    phase: Signal<Phase>,
    status: Signal<String>,
    selected: Signal<Option<ItemId>>,
    editor: Signal<Option<Editor>>,
    rev: Signal<u64>,
    icons: Icons,
) -> View {
    let query = signal(String::new());
    // 資料夾三態（口徑同 `Query.folder`）：None 全部、Some("") 未歸屬、
    // Some(id) 該夾。chip 列即側欄的手機替身。
    let folder: Signal<Option<String>> = signal(None);
    let filtered = computed({
        let hub = hub.clone();
        let (q, f) = (query, folder);
        move || {
            // 同步/鎖定/寫入改動訊號時才重算：訊號驅動，不另設輪詢。
            let _ = phase.get();
            let _ = rev.get();
            Arc::new(hub.list_in(&q.get(), f.get().as_deref()))
        }
    });

    // 列表換算 → 缺圖 host 發起取圖（effect 訂閱 filtered；request 以
    // Loading 標記冪等，重複喚起零外連）。
    effect({
        let hub = hub.clone();
        let icons = icons.clone();
        move || {
            let items = filtered.get();
            let hosts: Vec<String> =
                items.iter().filter_map(|m| m.uris.first()).filter_map(|u| host_of(u)).collect();
            icons.request(&hub, &hosts);
        }
    });

    let refresh_hub = hub.clone();
    let lock_hub = hub.clone();
    let fab_editor = editor;

    view()
        .flex_1()
        .flex_col()
        .bg(theme::BASE)
        .text_color(theme::TEXT_PRIMARY)
        .child(
            view()
                .h(px(theme::TOPBAR_H))
                .px_4()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .bg(theme::BAR)
                .child(
                    view()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.0))
                        .gap_0p5()
                        .child(
                            text("金庫")
                                .text_size(px(theme::TEXT_PAGE_TITLE))
                                .font_weight(FontWeight::SEMIBOLD),
                        )
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_2()
                                .child(
                                    text(move || match phase.get() {
                                        Phase::Vault(s) => format!("鏡像 {} 筆", s.items),
                                        Phase::Busy => "同步中…".to_owned(),
                                        Phase::SignedOut => String::new(),
                                    })
                                    .text_size(px(theme::TEXT_ROW_SUB))
                                    .text_color(theme::TEXT_SECONDARY)
                                    .flex_shrink_0(),
                                )
                                .child(
                                    text(move || match phase.get() {
                                        Phase::Vault(s) => format!("{} · {}", s.email, s.server),
                                        _ => String::new(),
                                    })
                                    .text_size(px(11.5))
                                    .text_color(theme::TEXT_MUTED)
                                    .number_of_lines(1)
                                    .ellipsize_mode(EllipsizeMode::Tail)
                                    .flex_1(),
                                ),
                        ),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .flex_shrink_0()
                        .child(ghost_button("重新同步", move || {
                            if phase.get() == Phase::Busy {
                                return;
                            }
                            status.set(String::new());
                            phase.set(Phase::Busy);
                            let hub = refresh_hub.clone();
                            spawn(async move {
                                match hub.sync_now().await {
                                    Ok(n) => {
                                        // Busy 蓋掉了快照（既有形態），完成後由帳號檔
                                        // 重建 Snapshot——舊寫法在 Busy 態讀 phase 永遠
                                        // 不匹配 Vault，界面卡死在「同步中」。
                                        if let Some(a) = hub.account() {
                                            phase.set(Phase::Vault(Snapshot {
                                                email: a.email,
                                                server: a.server,
                                                items: n,
                                                last_sync_ms: hub.now_ms(),
                                            }));
                                        }
                                    }
                                    Err(msg) => {
                                        status.set(msg);
                                        phase.set(Phase::SignedOut);
                                    }
                                }
                            });
                        }))
                        .child(ghost_button("鎖定", move || {
                            // 金鑰在這裡歸零（Hub::sign_out 丟棄 UserKey）。
                            lock_hub.sign_out();
                            status.set(String::new());
                            phase.set(Phase::SignedOut);
                        })),
                ),
        )
        .child(
            input()
                .value(move || query.get())
                .placeholder("搜尋名稱或網址".to_owned())
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .on_change(move |text: &str| query.set(text.to_owned()))
                .h(px(theme::INPUT_H))
                .mx_4()
                .mt_2()
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .text_color(theme::TEXT_PRIMARY)
                .text_size(px(theme::TEXT_ROW))
                .focus(|s| s.border_color(theme::ACCENT)),
        )
        .child(chip_row(hub.clone(), folder, phase, rev))
        .child(
            text(move || status.get())
                .text_size(px(12.0))
                .line_height(px(17.0))
                .px_4()
                .text_color(theme::DESTRUCTIVE),
        )
        .child(
            view()
                .flex_1()
                .relative()
                .child(
                    virtual_list(
                        move || filtered.get().len(),
                        move |at| {
                            let tap = selected;
                            view()
                                .relative()
                                .h(px(theme::ROW_H))
                                .pl_4()
                                .pr_3()
                                .flex_row()
                                .items_center()
                                .gap_3()
                                .cursor_pointer()
                                .active(|s| s.bg(theme::SURFACE_RAISED))
                                .on_press(move || {
                                    let items = filtered.get();
                                    if let Some(it) = items.get(at.index()) {
                                        tap.set(Some(it.id));
                                    }
                                })
                                .child(list_tile(icons.clone(), filtered, at.index()))
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
                                            .text_size(px(theme::TEXT_ROW))
                                            .line_height(px(20.0))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(theme::TEXT_PRIMARY)
                                            .number_of_lines(1)
                                            .ellipsize_mode(EllipsizeMode::Tail),
                                        )
                                        .child(
                                            text(move || {
                                                let items = filtered.get();
                                                items
                                                    .get(at.index())
                                                    .map(subtitle)
                                                    .unwrap_or_default()
                                            })
                                            .text_size(px(theme::TEXT_ROW_SUB))
                                            .line_height(px(16.0))
                                            .text_color(theme::TEXT_SECONDARY)
                                            .number_of_lines(1)
                                            .ellipsize_mode(EllipsizeMode::Tail),
                                        ),
                                )
                                .child(dynamic(move || {
                                    let items = filtered.get();
                                    let mut right = view().flex_row().items_center().gap_1p5();
                                    if let Some(it) = items.get(at.index()) {
                                        if it.favorite {
                                            right = right.child(
                                                text("★")
                                                    .text_size(px(14.0))
                                                    .text_color(theme::ACCENT),
                                            );
                                        }
                                        if it.pending {
                                            right = right.child(badge("待推送", theme::ACCENT));
                                        }
                                    }
                                    right
                                }))
                        },
                    )
                    .flex_1()
                    .keys(move || filtered.get().iter().map(|it| it.id).collect::<Vec<_>>())
                    .separator(|| {
                        view().h(px(1.0)).ml(px(72.0)).mr_4().bg(theme::HAIRLINE)
                    })
                    .empty(
                        dynamic(move || {
                            let searching =
                                !query.get().trim().is_empty() || folder.get().is_some();
                            view()
                                .h_24()
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .child(
                                    text(if searching {
                                        "找不到符合的項目"
                                    } else {
                                        "還沒有任何項目"
                                    })
                                    .text_size(px(13.0))
                                    .text_color(theme::TEXT_SECONDARY),
                                )
                        }),
                    ),
                )
                .child(
                    view()
                        .absolute()
                        .right(px(20.0))
                        .bottom(px(24.0))
                        .h(px(theme::FAB))
                        .px_5()
                        .flex_row()
                        .items_center()
                        .justify_center()
                        .gap_2()
                        .rounded(px(theme::RADIUS_FAB))
                        .bg(theme::ACCENT)
                        .cursor_pointer()
                        .active(|s| s.opacity(0.85))
                        .on_press(move || fab_editor.set(Some(Editor::New)))
                        .child(
                            text("+")
                                .text_size(px(22.0))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme::TEXT_ON_ACCENT),
                        )
                        .child(
                            text("新增")
                                .text_size(px(15.0))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme::TEXT_ON_ACCENT),
                        ),
                ),
        )
}

/// 資料夾 chip 列（側欄的手機替身）：全部／未歸屬／各資料夾。
/// 資料夾名稱只在解鎖態解密，列表頁恆解鎖；寫入後 `rev` 扳重算。
fn chip_row(hub: Arc<Hub>, folder: Signal<Option<String>>, phase: Signal<Phase>, rev: Signal<u64>) -> View {
    view()
        .flex_row()
        .pt_2()
        .pb_1()
        .child(dynamic(move || {
            let _ = (phase.get(), rev.get());
            let mut row = view().flex_row().items_center().gap_2().px_4();
            row = row.child(chip(folder, None, "全部"));
            row = row.child(chip(folder, Some(String::new()), "未歸屬"));
            for f in hub.folders() {
                let label = f.name.unwrap_or_else(|| "(資料夾)".to_owned());
                row = row.child(chip(folder, Some(f.id), label));
            }
            // 超出屏寬時橫向滾動（資料夾通常 <5，滾動條多數時候不出現）。
            scroll().horizontal().scrollbar(false).child(row)
        }))
}

fn chip(folder: Signal<Option<String>>, value: Option<String>, label: impl Into<String>) -> View {
    let label = label.into();
    let pick = folder;
    let press_value = value.clone();
    let bg_value = value.clone();
    let fg_value = value;
    view()
        .h(px(theme::CHIP_H))
        .px_3()
        .rounded(px(theme::CHIP_H / 2.0))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .active(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || pick.set(press_value.clone()))
        .bg(move || {
            if folder.get() == bg_value {
                theme::ACCENT
            } else {
                theme::CHIP_BG
            }
        })
        .child(
            text(move || label.clone())
                .text_size(px(theme::TEXT_CHIP))
                .text_color(move || {
                    if folder.get() == fg_value {
                        theme::TEXT_ON_ACCENT
                    } else {
                        theme::TEXT_SECONDARY
                    }
                }),
        )
}

/// 列表磚（32）：Login 有 host 且取圖 Ready → favicon 實圖；缺 → 字母磚；
/// 非 Login → 型別字形磚。取圖請求由列表頁的 effect 統一發起。
fn list_tile(icons: Icons, items: Memo<Arc<Vec<ItemMeta>>>, index: usize) -> AnyElement {
    dynamic(move || {
        let items = items.get();
        let Some(it) = items.get(index) else {
            return type_tile(ItemKind::Login, theme::TILE_ROW, theme::TILE_ROW_GLYPH);
        };
        let host = it.uris.first().and_then(|u| host_of(u));
        if let Some(uri) = host.as_deref().and_then(|h| icons.ready(h)) {
            return view()
                .w(px(theme::TILE_ROW))
                .h(px(theme::TILE_ROW))
                .rounded(px(theme::TILE_ROW * 0.28))
                .overflow_hidden()
                .flex_row()
                .items_center()
                .justify_center()
                .child(image(uri).w(px(theme::TILE_ROW)).h(px(theme::TILE_ROW)));
        }
        if it.kind == ItemKind::Login {
            letter_tile(it.name.clone(), theme::TILE_ROW, theme::TILE_ROW_GLYPH)
        } else {
            type_tile(it.kind, theme::TILE_ROW, theme::TILE_ROW_GLYPH)
        }
    })
}

/// 型別字形：官方用單色 icon；nsh 無 icon 系統，以 Unicode 字形＋
/// U+FE0E（text presentation）強制單色、跟文字色走（同 macOS 紀律）。
fn type_glyph(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "🌐\u{fe0e}",
        ItemKind::Card => "💳\u{fe0e}",
        ItemKind::Identity => "⚷\u{fe0e}",
        ItemKind::SecureNote => "✎\u{fe0e}",
    }
}

fn type_tile(kind: ItemKind, size: f32, glyph: f32) -> View {
    view()
        .w(px(size))
        .h(px(size))
        .rounded(px(theme::RADIUS_BLOCK))
        .flex_row()
        .items_center()
        .justify_center()
        .bg(theme::SURFACE_RAISED)
        .child(
            text(type_glyph(kind))
                .text_size(px(glyph))
                .text_color(theme::TEXT_SECONDARY),
        )
}

/// 字母磚（favicon 缺位退路）：藍灰單色系底＋首字大寫，不派生彩虹色。
fn letter_tile(name: Option<String>, size: f32, glyph: f32) -> View {
    let letter = name
        .and_then(|n| n.chars().next().map(|c| c.to_uppercase().to_string()))
        .unwrap_or_else(|| "?".to_owned());
    view()
        .w(px(size))
        .h(px(size))
        .rounded(px(size * 0.28))
        .flex_row()
        .items_center()
        .justify_center()
        .bg(theme::TILE_LETTER)
        .child(
            text(letter)
                .text_size(px(glyph))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_ON_ACCENT),
        )
}

// —— 詳情頁 ——

/// 詳情頁（push 在棧上）：分節值塊（帳密→驗證碼→網址→自訂欄→備註→其他），
/// TOTP 有 seed 即自動取碼＋倒數條，不需按鈕。密碼預設遮罩，按「顯示」才
/// 解密；「編輯」push 全頁表單；「刪除」二次確認後軟刪（`Hub::delete`，
/// 待推送語意同列表——tombstone 即刻離列，伺服器標記等同步收斂）。
#[allow(clippy::too_many_arguments)]
pub fn detail_page(
    hub: Arc<Hub>,
    id: ItemId,
    selected: Signal<Option<ItemId>>,
    plain: Signal<Option<Revealed>>,
    editor: Signal<Option<Editor>>,
    phase: Signal<Phase>,
    rev: Signal<u64>,
    icons: Icons,
) -> Screen {
    let meta = hub.meta(id).ok().flatten();
    let title =
        meta.as_ref().and_then(|m| m.name.clone()).unwrap_or_else(|| "項目詳情".to_owned());
    let kind = meta.as_ref().map(|m| m.kind).unwrap_or_default();

    let show_hub = hub.clone();
    let show_status = signal(String::new());
    let confirm_del = signal(false);
    let copied = signal::<Option<String>>(None);

    // TOTP 自動碼：進頁即取（無 seed＝靜默收合節）；1s 心跳驅動倒數條，
    // 視窗歸零自動重取（形態同 macOS `totp_section`）。
    let totp = signal(None::<String>);
    let totp_err = signal(None::<String>);
    let totp_valid_for = signal(0_u32);
    let totp_issued = signal(None::<Instant>);
    let totp_tick = signal(0_u64);
    fetch_totp(hub.clone(), id, totp, totp_err, totp_valid_for, totp_issued);
    set_interval(Duration::from_secs(1), move || totp_tick.set(totp_tick.get() + 1));
    effect({
        let hub = hub.clone();
        move || {
            let _ = totp_tick.get();
            if totp.get().is_some()
                && countdown_remaining(totp_valid_for, totp_issued, totp_tick) == 0
            {
                fetch_totp(hub.clone(), id, totp, totp_err, totp_valid_for, totp_issued);
            }
        }
    });

    // 收藏星：metadata 級現態＋本地覆蓋（patch 成功才翻，失敗回錯行）。
    let fav = signal(meta.as_ref().is_some_and(|m| m.favorite));
    let fav_hub = hub.clone();

    let tile_hub = hub.clone();
    let other_hub = hub.clone();
    let uri_meta = meta.clone();
    let ident_meta = meta.clone();
    let plain_fields = plain;

    let content = view().flex_1().flex_col().text_color(theme::TEXT_PRIMARY).child(
        scroll().flex_1().child(
            view()
                .flex_col()
                .gap_4()
                .px_4()
                .py_4()
                // identity：44 磚＋大名稱＋星＋待推送膠囊
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .child(dynamic({
                            let ident_meta = ident_meta.clone();
                            move || {
                                let host = ident_meta
                                    .as_ref()
                                    .and_then(|m| m.uris.first())
                                    .and_then(|u| host_of(u));
                                if let Some(uri) =
                                    host.as_deref().and_then(|h| icons.ready(h))
                                {
                                    return view()
                                        .w(px(theme::TILE_ID))
                                        .h(px(theme::TILE_ID))
                                        .rounded(px(theme::TILE_ID * 0.28))
                                        .overflow_hidden()
                                        .flex_row()
                                        .items_center()
                                        .justify_center()
                                        .child(
                                            image(uri)
                                                .w(px(theme::TILE_ID))
                                                .h(px(theme::TILE_ID)),
                                        );
                                }
                                match ident_meta.as_ref() {
                                    Some(m) if m.kind == ItemKind::Login => letter_tile(
                                        m.name.clone(),
                                        theme::TILE_ID,
                                        theme::TILE_ID_GLYPH,
                                    ),
                                    _ => {
                                        type_tile(kind, theme::TILE_ID, theme::TILE_ID_GLYPH)
                                    }
                                }
                            }
                        }))
                        .child(
                            view()
                                .flex_col()
                                .flex_1()
                                .gap_0p5()
                                .child(
                                    text(title.clone())
                                        .text_size(px(theme::TEXT_IDENTITY))
                                        .line_height(px(28.0))
                                        .font_weight(FontWeight::SEMIBOLD),
                                )
                                .child(
                                    text(move || {
                                        let mut s = kind_label(kind).to_owned();
                                        if let Some(u) =
                                            ident_meta.as_ref().and_then(|m| m.updated_at.clone())
                                        {
                                            s.push_str(" · 更新 ");
                                            s.push_str(&u);
                                        }
                                        s
                                    })
                                    .text_size(px(theme::TEXT_PAGE_SUB))
                                    .text_color(theme::TEXT_MUTED),
                                ),
                        )
                        .child(
                            view()
                                .w(px(36.0))
                                .h(px(36.0))
                                .rounded(px(theme::RADIUS_CONTROL))
                                .flex_row()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .active(|s| s.bg(theme::SURFACE_RAISED))
                                .on_press(move || {
                                    let want = !fav.get();
                                    match fav_hub.patch(
                                        id,
                                        &[FieldEdit::Set {
                                            path: "favorite".into(),
                                            value: Some(want.to_string()),
                                        }],
                                    ) {
                                        Ok(()) => {
                                            fav.set(want);
                                            rev.set(rev.get() + 1);
                                        }
                                        Err(e) => show_status.set(e),
                                    }
                                })
                                .child(
                                    text(move || if fav.get() { "★" } else { "☆" })
                                        .text_size(px(20.0))
                                        .text_color(move || {
                                            if fav.get() {
                                                theme::ACCENT
                                            } else {
                                                theme::TEXT_SECONDARY
                                            }
                                        }),
                                ),
                        ),
                )
                .child(dynamic(move || {
                    let _ = rev.get();
                    if hub_pending(&tile_hub, id) {
                        badge("待推送", theme::ACCENT)
                    } else {
                        view()
                    }
                }))
                // 登入：帳號＋密碼（遮罩預設，「顯示」才解密）
                .child(section(
                    "登入",
                    vec![
                        field_block(
                            "帳號",
                            move || match plain.get() {
                                Some(r) => r.username.unwrap_or_default(),
                                None => "••••••••".to_owned(),
                            },
                            vec![copy_revealed(plain, "username", copied)],
                        ),
                        field_block(
                            "密碼",
                            move || match plain.get() {
                                Some(r) => {
                                    r.password.as_ref().map(|p| p.to_string()).unwrap_or_default()
                                }
                                None => "••••••••".to_owned(),
                            },
                            vec![
                                reveal_toggle(show_hub.clone(), id, plain, show_status),
                                copy_revealed(plain, "password", copied),
                            ],
                        ),
                    ],
                ))
                // 驗證碼：有 seed 才渲染整節（自動取碼，免按鈕）
                .child(when(
                    move || totp.get().is_some(),
                    move || {
                        section(
                            "驗證碼",
                            vec![block_dyn(
                                move || totp.get().unwrap_or_default(),
                                false,
                                vec![copy_static(move || totp.get().unwrap_or_default(), copied)],
                                Some(countdown(totp_valid_for, totp_issued, totp_tick)),
                            )],
                        )
                    },
                ))
                .child(when(
                    move || totp_err.get().is_some(),
                    move || {
                        view().child(
                            text(move || totp_err.get().unwrap_or_default())
                                .text_size(px(12.5))
                                .text_color(theme::WARNING),
                        )
                    },
                ))
                // 網址：每列值塊＋複製（metadata 級明文，不用解鎖顯示）
                .child(dynamic(move || {
                    let mut sec = view().flex_col().gap_1p5();
                    if let Some(m) = &uri_meta {
                        if !m.uris.is_empty() {
                            sec = sec.child(section_label("網址"));
                            for u in &m.uris {
                                sec = sec.child(block(
                                    u.clone(),
                                    false,
                                    vec![copy_value(u.clone(), copied)],
                                ));
                            }
                        }
                    }
                    sec
                }))
                // 自訂欄位／備註：明文欄，「顯示」後才出現
                .child(dynamic(move || {
                    let mut col = view().flex_col().gap_4();
                    let Some(r) = plain_fields.get() else { return col };
                    if !r.fields.is_empty() {
                        let mut rows: Vec<View> = Vec::new();
                        for f in &r.fields {
                            let shown: String = match f.kind {
                                CipherFieldKind::Boolean => match f.value.as_deref() {
                                    Some("false") => "否".to_owned(),
                                    _ => "是".to_owned(),
                                },
                                _ => f.value.clone().unwrap_or_default(),
                            };
                            rows.push(block_dyn(
                                {
                                    let shown = shown.clone();
                                    move || shown.clone()
                                },
                                false,
                                vec![copy_static(
                                    move || shown.clone(),
                                    copied,
                                )],
                                None,
                            ));
                        }
                        col = col.child(section("自訂欄位", rows));
                    }
                    if let Some(n) = r.notes.clone() {
                        col = col.child(section("備註", vec![block(n, true, vec![])]));
                    }
                    col
                }))
                // 資料夾＋標籤＋同步態（其他資訊節）
                .child(dynamic(move || {
                    let _ = rev.get();
                    let mut rows: Vec<View> = Vec::new();
                    if let Some(fid) = other_meta_folder(&other_hub, id) {
                        let name = other_hub
                            .folders()
                            .into_iter()
                            .find(|f| f.id == fid)
                            .and_then(|f| f.name)
                            .unwrap_or_else(|| "(已刪除的資料夾)".to_owned());
                        rows.push(block(name, false, vec![]));
                    }
                    if let Some(m) = other_hub.meta(id).ok().flatten()
                        && !m.tags.is_empty()
                    {
                        rows.push(block(m.tags.join("、"), false, vec![]));
                    }
                    let status_line = if hub_pending(&other_hub, id) { "待推送" } else { "已同步" };
                    let status_hub = other_hub.clone();
                    rows.push(
                        view()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .child(
                                text(status_line)
                                    .text_size(px(theme::TEXT_FIELD_VALUE))
                                    .text_color(move || {
                                        if hub_pending(&status_hub, id) {
                                            theme::ACCENT
                                        } else {
                                            theme::TEXT_SECONDARY
                                        }
                                    }),
                            )
                            .rounded(px(theme::RADIUS_BLOCK))
                            .bg(theme::SURFACE)
                            .px_3()
                            .py_2(),
                    );
                    if rows.is_empty() {
                        return view();
                    }
                    section("其他資訊", rows)
                }))
                .child(divider())
                .child(
                    text(move || show_status.get())
                        .text_size(px(12.0))
                        .line_height(px(17.0))
                        .text_color(theme::DESTRUCTIVE),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ghost_button("編輯", move || {
                            editor.set(Some(Editor::Edit(id)));
                        }))
                        .child(destructive_button("刪除", move || {
                            confirm_del.set(true);
                        })),
                )
                .child(when(
                    move || confirm_del.get(),
                    move || {
                        let ok_hub = hub.clone();
                        let ok_phase = phase;
                        view()
                            .flex_col()
                            .gap_3()
                            .p_4()
                            .rounded(px(theme::RADIUS_BLOCK))
                            .border(px(1.0))
                            .border_color(theme::DESTRUCTIVE)
                            .child(
                                text("確定刪除這筆？（軟刪：即刻從列表消失，同步後伺服器才標記刪除）")
                                    .text_size(px(13.0))
                                    .line_height(px(19.0)),
                            )
                            .child(
                                view()
                                    .flex_row()
                                    .gap_2()
                                    .child(ghost_button("取消刪除", move || {
                                        confirm_del.set(false);
                                    }))
                                    .child(primary_button("確定刪除", move || {
                                        match ok_hub.delete(id) {
                                            Ok(()) => {
                                                log::info!("ui: 已軟刪 {id}（待推送）");
                                                confirm_del.set(false);
                                                // 返回列表並清明文；計數與列舉同步刷新。
                                                plain.set(None);
                                                selected.set(None);
                                                if let Phase::Vault(mut s) = ok_phase.get() {
                                                    s.items = ok_hub.list("").len();
                                                    ok_phase.set(Phase::Vault(s));
                                                }
                                                rev.set(rev.get() + 1);
                                            }
                                            Err(e) => show_status.set(e),
                                        }
                                    })),
                            )
                    },
                )),
        ),
    );

    nav_page()
        .key(format!("detail-{id}"))
        .title(title)
        .on_dismiss(move || {
            // 離開視圖即清明文（系統返回鍵走同一條）。
            plain.set(None);
            selected.set(None);
        })
        .child(content)
}

fn hub_pending(hub: &Hub, id: ItemId) -> bool {
    hub.meta(id).ok().flatten().is_some_and(|m| m.pending)
}

fn other_meta_folder(hub: &Hub, id: ItemId) -> Option<String> {
    hub.meta(id).ok().flatten().and_then(|m| m.folder_id.map(|f| f.to_string()))
}

// —— TOTP（純函數可單測；心跳形態同 macOS detail）——

/// TOTP 視窗週期秒數（與 `Hub::totp_code` 的 `30 - now % 30` 同值）。
pub const TOTP_PERIOD_SECS: u32 = 30;
/// 剩餘低於此秒數轉 warning 色。
pub const TOTP_WARN_SECS: u32 = 5;

/// 剩餘秒數：取碼時的 valid_for_secs 減去經過秒數（純函數，可單測）。
pub fn totp_remaining(valid_for_secs: u32, elapsed_secs: u64) -> u32 {
    valid_for_secs.saturating_sub(elapsed_secs as u32)
}

fn fetch_totp(
    hub: Arc<Hub>,
    id: ItemId,
    totp: Signal<Option<String>>,
    totp_err: Signal<Option<String>>,
    valid_for: Signal<u32>,
    issued: Signal<Option<Instant>>,
) {
    spawn(async move {
        match hub.totp_code(id) {
            Ok(Some((code, secs))) => {
                totp.set(Some(code));
                valid_for.set(secs);
                issued.set(Some(Instant::now()));
                totp_err.set(None);
            }
            Ok(None) => totp.set(None),
            Err(e) => {
                totp.set(None);
                totp_err.set(Some(e));
            }
        }
    });
}

/// 目前剩餘秒數；讀 tick 建立重繪依賴。
fn countdown_remaining(
    valid_for: Signal<u32>,
    issued: Signal<Option<Instant>>,
    tick: Signal<u64>,
) -> u32 {
    let _ = tick.get();
    match issued.get() {
        Some(at) => totp_remaining(valid_for.get(), at.elapsed().as_secs()),
        None => 0,
    }
}

/// 倒數條：accent 實色細軌＋「剩餘 N 秒」；≤5 秒轉 warning 色。
fn countdown(
    valid_for: Signal<u32>,
    issued: Signal<Option<Instant>>,
    tick: Signal<u64>,
) -> View {
    view()
        .flex_row()
        .items_center()
        .gap_1p5()
        .child(
            view()
                .w(px(96.0))
                .h(px(theme::TOTP_BAR_H))
                .rounded_full()
                .bg(theme::SURFACE_RAISED)
                .child(
                    view()
                        .h_full()
                        .rounded_full()
                        .w(move || {
                            let left = countdown_remaining(valid_for, issued, tick) as f32
                                / TOTP_PERIOD_SECS as f32;
                            px(96.0 * left)
                        })
                        .bg(move || {
                            if countdown_remaining(valid_for, issued, tick) <= TOTP_WARN_SECS {
                                theme::WARNING
                            } else {
                                theme::ACCENT
                            }
                        }),
                ),
        )
        .child(
            text(move || format!("剩餘 {} 秒", countdown_remaining(valid_for, issued, tick)))
                .text_size(px(theme::TEXT_PAGE_SUB))
                .text_color(move || {
                    if countdown_remaining(valid_for, issued, tick) <= TOTP_WARN_SECS {
                        theme::WARNING
                    } else {
                        theme::TEXT_MUTED
                    }
                }),
        )
}

// —— 全頁表單（新增／編輯）——

/// 表單網址列：key＝基準索引（既有列）或大於基準長度的遞增號（新列），
/// 差量以身分對齊而非位置（同 macOS `UriDraft` 紀律）。
#[derive(Clone, PartialEq)]
struct UriRow {
    key: u32,
    uri: String,
    match_type: Option<u8>,
}

/// 表單自訂欄列（boolean 值正規化 "true"/"false"，同 daemon wire 形態）。
#[derive(Clone, PartialEq)]
struct FieldRow {
    key: u32,
    name: String,
    value: String,
    kind: CipherFieldKind,
}

impl FieldRow {
    fn set_kind(&mut self, kind: CipherFieldKind) {
        self.kind = kind;
        if kind == CipherFieldKind::Boolean {
            self.value = if self.value == "true" { "true" } else { "false" }.to_owned();
        }
    }
}

/// 新列身份號：單調遞增且恆大於基準長度（實際資料夾規模遠小於 1000）。
fn rand_key() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// 官方六態 match（同 macOS `URI_MATCH_OPTIONS`；5=Never 僅值域，UI 不列）。
const URI_MATCH_OPTIONS: [(Option<u8>, &str); 6] = [
    (None, "預設"),
    (Some(0), "網域"),
    (Some(1), "網域＋子域"),
    (Some(3), "精確符合"),
    (Some(2), "開頭符合"),
    (Some(4), "正規表達式"),
];

fn uri_match_label(m: Option<u8>) -> &'static str {
    URI_MATCH_OPTIONS.iter().find(|(v, _)| *v == m).map(|(_, l)| *l).unwrap_or("預設")
}

/// 網址差量三批（口徑同 macOS `uri_edits`）：既有列 leaf 批（值＋判定）、
/// 結構批（刪列降序→附加）、新列判定尾批（落地索引＝基準−刪＋附加序）。
fn uri_edits(
    orig: &[String],
    orig_matches: &[Option<u8>],
    rows: &[UriRow],
) -> (Vec<FieldEdit>, Vec<FieldEdit>, Vec<FieldEdit>) {
    let present: HashSet<u32> =
        rows.iter().map(|r| r.key).filter(|k| (*k as usize) < orig.len()).collect();
    let mut sets = Vec::new();
    let mut appends = Vec::new();
    let mut match_tail = Vec::new();
    for r in rows {
        let now = nonblank(r.uri.trim());
        if let Some(base) = orig.get(r.key as usize).filter(|_| (r.key as usize) < orig.len()) {
            if now.as_deref() != Some(base.as_str()) {
                sets.push(FieldEdit::Set { path: format!("uri.{}", r.key), value: now });
            }
            if r.match_type != orig_matches.get(r.key as usize).copied().flatten() {
                sets.push(FieldEdit::SetUriMatch { index: r.key, match_type: r.match_type });
            }
        } else if now.is_some() {
            appends.push(FieldEdit::AppendUri { uri: r.uri.trim().to_owned() });
        }
    }
    let mut removes: Vec<u32> =
        (0..orig.len() as u32).filter(|i| !present.contains(i)).collect();
    removes.sort_by(|a, b| b.cmp(a));
    let mut structural: Vec<FieldEdit> =
        removes.iter().map(|index| FieldEdit::RemoveUri { index: *index }).collect();
    // 新列判定尾批：附加序 k 的落地索引＝基準數−刪除數＋k（AppendUri 依序落尾）。
    let mut append_i = 0usize;
    for r in rows {
        if nonblank(r.uri.trim()).is_some() && (r.key as usize) >= orig.len() {
            if let Some(m) = r.match_type {
                match_tail.push(FieldEdit::SetUriMatch {
                    index: (orig.len() - removes.len() + append_i) as u32,
                    match_type: Some(m),
                });
            }
            append_i += 1;
        }
    }
    structural.extend(appends);
    (sets, structural, match_tail)
}

/// 自訂欄差量（口徑同 macOS `field_edits`）：按 key 對齊基準索引；
/// 刪列降序、附加列依表單順序；空名空值的新列不送出。
fn field_edits(orig: &[CipherField], rows: &[FieldRow]) -> Vec<FieldEdit> {
    let mut edits: Vec<FieldEdit> = Vec::new();
    let mut removes: Vec<u32> = Vec::new();
    for (i, base) in orig.iter().enumerate() {
        match rows.iter().find(|c| c.key == i as u32) {
            Some(c) => {
                if c.name != base.name {
                    edits.push(FieldEdit::Set {
                        path: format!("field.{i}.name"),
                        value: Some(c.name.clone()),
                    });
                }
                if c.value != base.value.clone().unwrap_or_default() {
                    edits.push(FieldEdit::Set {
                        path: format!("field.{i}.value"),
                        value: nonblank(&c.value),
                    });
                }
                if c.kind != base.kind {
                    edits.push(FieldEdit::SetType { index: i as u32, kind: c.kind });
                }
            }
            None => removes.push(i as u32),
        }
    }
    removes.sort_by(|a, b| b.cmp(a));
    edits.extend(removes.into_iter().map(|index| FieldEdit::RemoveField { index }));
    edits.extend(
        rows.iter()
            .filter(|c| (c.key as usize) >= orig.len())
            .filter(|c| !c.name.trim().is_empty() || !c.value.trim().is_empty())
            .map(|c| FieldEdit::AppendField {
                field: CipherField {
                    name: c.name.trim().to_owned(),
                    value: nonblank(&c.value),
                    kind: c.kind,
                },
            }),
    );
    edits
}

/// 全頁表單：名稱／帳號／密碼（可顯示）／TOTP seed／多網址（含 match 六態）
/// ／資料夾 chip／收藏／自訂欄（型別輪轉）／備註。支援面全露出；型別限
/// Login、標籤寫入未接＝註記（缺角清單同 README）。送出去的是**對預填
/// 基線的差量**（沒動的欄不進 patch；欄位級存活由 `bw_vault::apply_merged`
/// 保證）。寫入走 `Hub` 本地交易（outbox），推送收斂由「重新同步」drain 負責。
pub fn editor_page(
    hub: Arc<Hub>,
    editor: Signal<Option<Editor>>,
    phase: Signal<Phase>,
    selected: Signal<Option<ItemId>>,
    plain: Signal<Option<Revealed>>,
    rev: Signal<u64>,
) -> Screen {
    let target = editor.get().unwrap_or(Editor::New);
    let (title, pre) = match target {
        Editor::New => ("新增項目", None),
        Editor::Edit(id) => ("編輯項目", hub.reveal(id).ok()),
    };
    // 基線（比對差量用）與欄位訊號同源初始化；明文副本隨訊號在收頁丟棄。
    let base_name = pre.as_ref().map(|r| r.name.clone()).unwrap_or_default();
    let base_user = pre.as_ref().and_then(|r| r.username.clone());
    let base_pass = pre.as_ref().and_then(|r| r.password.as_ref().map(|p| p.to_string()));
    let base_uris: Vec<String> = pre.as_ref().map(|r| r.uris.clone()).unwrap_or_default();
    let base_matches: Vec<Option<u8>> =
        pre.as_ref().map(|r| r.uri_matches.clone()).unwrap_or_default();
    let base_fields: Vec<CipherField> = pre.as_ref().map(|r| r.fields.clone()).unwrap_or_default();
    let base_notes = pre.as_ref().and_then(|r| r.notes.clone());
    let base_folder = pre.as_ref().and_then(|r| r.folder_id.clone());
    let base_fav = pre.as_ref().is_some_and(|r| r.favorite);

    let name = signal(base_name.clone());
    let user = signal(base_user.clone().unwrap_or_default());
    let pass = signal(base_pass.clone().unwrap_or_default());
    let pass_shown = signal(false);
    let totp_seed = signal(String::new());
    let notes = signal(base_notes.clone().unwrap_or_default());
    let folder = signal::<Option<String>>(base_folder.clone());
    let fav = signal(base_fav);
    let err = signal(String::new());
    let uris = signal(Arc::new(if base_uris.is_empty() {
        vec![UriRow { key: rand_key(), uri: String::new(), match_type: None }]
    } else {
        base_uris
            .iter()
            .enumerate()
            .map(|(i, u)| UriRow {
                key: i as u32,
                uri: u.clone(),
                match_type: base_matches.get(i).copied().flatten(),
            })
            .collect::<Vec<_>>()
    }));
    let fields = signal(Arc::new(
        base_fields
            .iter()
            .enumerate()
            .map(|(i, f)| FieldRow {
                key: i as u32,
                name: f.name.clone(),
                value: f.value.clone().unwrap_or_default(),
                kind: f.kind,
            })
            .collect::<Vec<_>>(),
    ));

    let close_hub = hub.clone();
    let save_hub = hub.clone();
    let dismiss_editor = editor;
    let cancel_editor = editor;
    let save_close = editor;
    let folders_for_form = hub.clone();

    let save = move || {
        let n = name.get().trim().to_owned();
        if n.is_empty() {
            err.set("名稱為必填".to_owned());
            return;
        }
        let user_v = nonblank(&user.get());
        let pass_v = nonblank(&pass.get());
        let seed_v = nonblank(&totp_seed.get());
        let notes_v = nonblank(&notes.get());
        let uri_rows: Vec<UriRow> =
            uris.get().iter().filter(|r| !r.uri.trim().is_empty()).cloned().collect();
        let field_rows: Vec<FieldRow> = fields
            .get()
            .iter()
            .filter(|f| !f.name.trim().is_empty() || !f.value.trim().is_empty())
            .cloned()
            .collect();
        let out: Result<(), String> = match target {
            Editor::New => {
                let (uris_v, matches_v): (Vec<String>, Vec<Option<u8>>) = uri_rows
                    .into_iter()
                    .map(|r| (r.uri.trim().to_owned(), r.match_type))
                    .unzip();
                save_hub
                    .create(&CipherDraft {
                        kind: ItemKind::Login,
                        name: n,
                        username: user_v,
                        password: pass_v,
                        totp: seed_v,
                        uris: uris_v,
                        notes: notes_v,
                        favorite: fav.get(),
                        folder_id: folder.get(),
                        fields: field_rows
                            .into_iter()
                            .map(|f| CipherField {
                                name: f.name.trim().to_owned(),
                                value: if f.kind == CipherFieldKind::Boolean {
                                    Some(f.value)
                                } else {
                                    nonblank(&f.value)
                                },
                                kind: f.kind,
                            })
                            .collect(),
                        uri_matches: matches_v,
                    })
                    .map(|_| ())
            }
            Editor::Edit(id) => {
                let mut edits: Vec<FieldEdit> = Vec::new();
                if n != base_name {
                    edits.push(FieldEdit::Set { path: "name".into(), value: Some(n) });
                }
                if user_v != base_user {
                    edits.push(FieldEdit::Set {
                        path: "username".into(),
                        value: user_v.clone(),
                    });
                }
                if pass_v != base_pass {
                    edits.push(FieldEdit::Set {
                        path: "password".into(),
                        value: pass_v.clone(),
                    });
                }
                if let Some(s) = seed_v {
                    edits.push(FieldEdit::Set { path: "totp".into(), value: Some(s) });
                }
                if notes_v != base_notes {
                    edits.push(FieldEdit::Set { path: "notes".into(), value: notes_v.clone() });
                }
                if fav.get() != base_fav {
                    edits.push(FieldEdit::Set {
                        path: "favorite".into(),
                        value: Some(fav.get().to_string()),
                    });
                }
                if folder.get() != base_folder {
                    edits.push(FieldEdit::Set {
                        path: "folderId".into(),
                        value: folder.get().clone(),
                    });
                }
                edits.extend(field_edits(&base_fields, &fields.get()));
                let (sets, structural, tail) = uri_edits(&base_uris, &base_matches, &uris.get());
                edits.extend(sets);
                edits.extend(structural);
                if edits.is_empty() {
                    Ok(()) // 沒動任何欄：no-op 收工，不產生空 patch。
                } else {
                    save_hub.patch(id, &edits).and_then(|()| {
                        // 新列判定尾批：結構批落地後補發（索引＝基準−刪＋附加序）。
                        if tail.is_empty() {
                            Ok(())
                        } else {
                            save_hub.patch(id, &tail)
                        }
                    })
                }
            }
        };
        match out {
            Ok(()) => {
                let was_edit = matches!(target, Editor::Edit(_));
                save_close.set(None);
                if was_edit {
                    // 編輯來自詳情頁：靜態欄位不會自我重繪，回列表看新態。
                    plain.set(None);
                    selected.set(None);
                }
                if let Phase::Vault(mut s) = phase.get() {
                    s.items = save_hub.list("").len();
                    phase.set(Phase::Vault(s));
                }
                rev.set(rev.get() + 1);
            }
            // 錯誤原文顯示（閘金鑰、服務器拒絕都不改寫）。
            Err(msg) => err.set(msg),
        }
    };

    let content = view()
        .flex_1()
        .flex_col()
        .bg(theme::BASE)
        .text_color(theme::TEXT_PRIMARY)
        .child(
            scroll().flex_1().child(
                view()
                    .flex_col()
                    .gap(px(theme::FORM_GAP))
                    .px_4()
                    .py_4()
                    .child(form_field("名稱", "項目名稱（必填）", name, false))
                    .child(form_field("帳號", "帳號（可留空）", user, false))
                    .child(
                        view()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("密碼"))
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        input()
                                            .value(move || pass.get())
                                            .placeholder("密碼（可留空）".to_owned())
                                            .placeholder_color(move || color(theme::TEXT_MUTED))
                                            .masked(move || !pass_shown.get())
                                            .on_change(move |t: &str| pass.set(t.to_owned()))
                                            .h(px(theme::INPUT_H))
                                            .px_3()
                                            .flex_1()
                                            .rounded(px(theme::RADIUS_CONTROL))
                                            .border(px(1.0))
                                            .border_color(theme::HAIRLINE)
                                            .bg(theme::SURFACE)
                                            .text_color(theme::TEXT_PRIMARY)
                                            .text_size(px(theme::TEXT_FIELD_VALUE))
                                            .focus(|s| s.border_color(theme::ACCENT)),
                                    )
                                    .child(ghost_button(
                                        move || {
                                            if pass_shown.get() {
                                                "隱藏"
                                            } else {
                                                "顯示"
                                            }
                                        },
                                        move || pass_shown.set(!pass_shown.get()),
                                    )),
                            ),
                    )
                    .child(form_field(
                        "驗證碼 seed",
                        "驗證碼 seed（可留空；編輯不改動＝保留原 seed）",
                        totp_seed,
                        false,
                    ))
                    .child(uris_editor(uris))
                    .child(folder_picker(folders_for_form.clone(), folder))
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .child(field_label("收藏"))
                            .child(
                                view()
                                    .h(px(theme::BTN_H))
                                    .w(px(theme::BTN_H))
                                    .rounded(px(theme::RADIUS_CONTROL))
                                    .flex_row()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .bg(theme::SURFACE)
                                    .border(px(1.0))
                                    .border_color(theme::HAIRLINE)
                                    .active(|s| s.bg(theme::SURFACE_RAISED))
                                    .on_press(move || fav.set(!fav.get()))
                                    .child(
                                        text(move || if fav.get() { "★" } else { "☆" })
                                            .text_size(px(20.0))
                                            .text_color(move || {
                                                if fav.get() {
                                                    theme::ACCENT
                                                } else {
                                                    theme::TEXT_MUTED
                                                }
                                            }),
                                    ),
                            ),
                    )
                    .child(fields_editor(fields))
                    .child(
                        view()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("備註"))
                            .child(
                                input()
                                    .value(move || notes.get())
                                    .placeholder("備註（可留空）".to_owned())
                                    .placeholder_color(move || color(theme::TEXT_MUTED))
                                    .multiline(true)
                                    .on_change(move |t: &str| notes.set(t.to_owned()))
                                    .h(px(84.0))
                                    .p_3()
                                    .rounded(px(theme::RADIUS_CONTROL))
                                    .border(px(1.0))
                                    .border_color(theme::HAIRLINE)
                                    .bg(theme::SURFACE)
                                    .text_color(theme::TEXT_PRIMARY)
                                    .text_size(px(theme::TEXT_FIELD_VALUE))
                                    .focus(|s| s.border_color(theme::ACCENT)),
                            ),
                    )
                    // 支援面邊界：說清楚哪些官方欄位本批不接（缺角清單）。
                    .child(
                        view()
                            .flex_col()
                            .gap_1()
                            .child(field_label("類型"))
                            .child(
                                text("登入（卡片／身份／安全備忘尚未支援）")
                                    .text_size(px(12.5))
                                    .text_color(theme::TEXT_MUTED),
                            )
                            .child(
                                text("標籤寫入尚未接（本機中樞缺 AddTag/RemoveTag 面）")
                                    .text_size(px(12.5))
                                    .text_color(theme::TEXT_MUTED),
                            ),
                    )
                    .child(
                        text(move || err.get())
                            .text_size(px(12.5))
                            .line_height(px(17.0))
                            .text_color(theme::DESTRUCTIVE),
                    ),
            ),
        )
        .child(
            view()
                .h(px(theme::TOPBAR_H))
                .px_4()
                .flex_row()
                .items_center()
                .gap_2()
                .bg(theme::BAR)
                .child(primary_button("儲存", save).flex_1())
                .child(ghost_button("取消", move || {
                    // 取消＝原樣收頁（不寫出差量；明文隨訊號丟棄）。
                    let _ = &close_hub;
                    cancel_editor.set(None);
                })),
        );

    nav_page()
        .key(match target {
            Editor::New => "editor-new".to_owned(),
            Editor::Edit(id) => format!("editor-{id}"),
        })
        .title(title)
        .on_dismiss(move || {
            // 返回鍵收頁：只撤訊號（明文副本在頁區域重建時自然歸零）。
            dismiss_editor.set(None);
        })
        .child(content)
}

/// 網址列編輯器：每列＝輸入框＋match 輪轉膠囊＋✕；「新增網址」落尾。
fn uris_editor(uris: Signal<Arc<Vec<UriRow>>>) -> View {
    let add = uris;
    let row_src = uris;
    view()
        .flex_col()
        .gap_1p5()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .child(field_label("網址"))
                .child(ghost_button("新增網址", move || {
                    add.update(|v| {
                        Arc::make_mut(v).push(UriRow {
                            key: rand_key(),
                            uri: String::new(),
                            match_type: None,
                        })
                    });
                })),
        )
        .child(each(
            move || (*uris.get()).clone(),
            |r: &UriRow| r.key,
            move |item: ReadSignal<UriRow>, _i: ReadSignal<usize>| {
                uri_row(row_src, item.get().key)
            },
        ))
}

fn uri_row(uris: Signal<Arc<Vec<UriRow>>>, key: u32) -> View {
    let edit = uris;
    let del = uris;
    let cyc = uris;
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .child(
            input()
                .value(move || {
                    uris.get()
                        .iter()
                        .find(|u| u.key == key)
                        .map(|u| u.uri.clone())
                        .unwrap_or_default()
                })
                .placeholder("網址（可留空）".to_owned())
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .on_change(move |t: &str| {
                    edit.update(|v| {
                        if let Some(u) = Arc::make_mut(v).iter_mut().find(|u| u.key == key) {
                            u.uri = t.to_owned();
                        }
                    });
                })
                .h(px(theme::INPUT_H))
                .px_3()
                .flex_1()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .text_color(theme::TEXT_PRIMARY)
                .text_size(px(theme::TEXT_FIELD_VALUE))
                .focus(|s| s.border_color(theme::ACCENT)),
        )
        .child(
            view()
                .h(px(theme::CHIP_H))
                .px_2()
                .rounded(px(theme::CHIP_H / 2.0))
                .flex_row()
                .items_center()
                .cursor_pointer()
                .bg(theme::CHIP_BG)
                .active(|s| s.bg(theme::SURFACE_RAISED))
                .on_press(move || {
                    // 輪轉官方六態（預設→網域→精確→開頭→子域→正則→預設）。
                    let order: [Option<u8>; 6] =
                        [None, Some(0), Some(3), Some(2), Some(1), Some(4)];
                    cyc.update(|v| {
                        if let Some(u) = Arc::make_mut(v).iter_mut().find(|u| u.key == key) {
                            let at = order.iter().position(|m| *m == u.match_type).unwrap_or(0);
                            u.match_type = order[(at + 1) % order.len()];
                        }
                    });
                })
                .child(dynamic(move || {
                    let cur = uris
                        .get()
                        .iter()
                        .find(|u| u.key == key)
                        .and_then(|u| u.match_type);
                    text(format!("符合：{}", uri_match_label(cur)))
                        .text_size(px(theme::TEXT_CHIP))
                        .text_color(theme::TEXT_SECONDARY)
                })),
        )
        .child(
            view()
                .w(px(theme::COPY_BTN))
                .h(px(theme::COPY_BTN))
                .flex_row()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .active(|s| s.opacity(0.6))
                .on_press(move || {
                    del.update(|v| Arc::make_mut(v).retain(|u| u.key != key));
                })
                .child(text("✕").text_size(px(13.0)).text_color(theme::TEXT_MUTED)),
        )
}

/// 資料夾選擇（chip 列＝官方下拉的手機替身）：「無資料夾」＝None（移出）。
fn folder_picker(hub: Arc<Hub>, folder: Signal<Option<String>>) -> View {
    view()
        .flex_col()
        .gap_1p5()
        .child(field_label("資料夾"))
        .child(dynamic(move || {
            let mut row = view().flex_row().items_center().gap_2();
            row = row.child(pick_chip(folder, None, "無資料夾"));
            for f in hub.folders() {
                let label = f.name.unwrap_or_else(|| "(資料夾)".to_owned());
                row = row.child(pick_chip(folder, Some(f.id), label));
            }
            scroll().horizontal().scrollbar(false).child(row)
        }))
}

fn pick_chip(sel: Signal<Option<String>>, value: Option<String>, label: impl Into<String>) -> View {
    let label = label.into();
    let pick = sel;
    let press_value = value.clone();
    let bg_value = value.clone();
    let fg_value = value;
    view()
        .h(px(theme::CHIP_H))
        .px_3()
        .rounded(px(theme::CHIP_H / 2.0))
        .flex_row()
        .items_center()
        .cursor_pointer()
        .active(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || pick.set(press_value.clone()))
        .bg(move || {
            if sel.get() == bg_value {
                theme::ACCENT
            } else {
                theme::CHIP_BG
            }
        })
        .child(
            text(move || label.clone())
                .text_size(px(theme::TEXT_CHIP))
                .text_color(move || {
                    if sel.get() == fg_value {
                        theme::TEXT_ON_ACCENT
                    } else {
                        theme::TEXT_SECONDARY
                    }
                }),
        )
}

/// 自訂欄位編輯器：列＝欄名＋值＋型別輪轉膠囊＋✕；「新增自訂欄」落尾。
fn fields_editor(fields: Signal<Arc<Vec<FieldRow>>>) -> View {
    let add = fields;
    let row_src = fields;
    view()
        .flex_col()
        .gap_1p5()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .child(field_label("自訂欄位"))
                .child(ghost_button("新增自訂欄", move || {
                    add.update(|v| {
                        Arc::make_mut(v).push(FieldRow {
                            key: rand_key(),
                            name: String::new(),
                            value: String::new(),
                            kind: CipherFieldKind::Text,
                        })
                    });
                })),
        )
        .child(each(
            move || (*fields.get()).clone(),
            |r: &FieldRow| r.key,
            move |item: ReadSignal<FieldRow>, _i: ReadSignal<usize>| {
                field_row(row_src, item.get().key)
            },
        ))
}

fn field_row(fields: Signal<Arc<Vec<FieldRow>>>, key: u32) -> View {
    let name_edit = fields;
    let value_edit = fields;
    let del = fields;
    let cyc = fields;
    view()
        .flex_col()
        .gap_1()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    input()
                        .value(move || {
                            fields
                                .get()
                                .iter()
                                .find(|f| f.key == key)
                                .map(|f| f.name.clone())
                                .unwrap_or_default()
                        })
                        .placeholder("欄名".to_owned())
                        .placeholder_color(move || color(theme::TEXT_MUTED))
                        .on_change(move |t: &str| {
                            name_edit.update(|v| {
                                if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key)
                                {
                                    f.name = t.to_owned();
                                }
                            });
                        })
                        .h(px(theme::INPUT_H))
                        .px_3()
                        .flex_1()
                        .rounded(px(theme::RADIUS_CONTROL))
                        .border(px(1.0))
                        .border_color(theme::HAIRLINE)
                        .bg(theme::SURFACE)
                        .text_color(theme::TEXT_PRIMARY)
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .focus(|s| s.border_color(theme::ACCENT)),
                )
                .child(
                    view()
                        .w(px(theme::COPY_BTN))
                        .h(px(theme::COPY_BTN))
                        .flex_row()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .active(|s| s.opacity(0.6))
                        .on_press(move || {
                            del.update(|v| Arc::make_mut(v).retain(|f| f.key != key));
                        })
                        .child(text("✕").text_size(px(13.0)).text_color(theme::TEXT_MUTED)),
                ),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    input()
                        .value(move || {
                            fields
                                .get()
                                .iter()
                                .find(|f| f.key == key)
                                .map(|f| f.value.clone())
                                .unwrap_or_default()
                        })
                        .placeholder("值".to_owned())
                        .placeholder_color(move || color(theme::TEXT_MUTED))
                        .on_change(move |t: &str| {
                            value_edit.update(|v| {
                                if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key)
                                {
                                    f.value = t.to_owned();
                                }
                            });
                        })
                        .h(px(theme::INPUT_H))
                        .px_3()
                        .flex_1()
                        .rounded(px(theme::RADIUS_CONTROL))
                        .border(px(1.0))
                        .border_color(theme::HAIRLINE)
                        .bg(theme::SURFACE)
                        .text_color(theme::TEXT_PRIMARY)
                        .text_size(px(theme::TEXT_FIELD_VALUE))
                        .focus(|s| s.border_color(theme::ACCENT)),
                )
                .child(
                    view()
                        .h(px(theme::CHIP_H))
                        .px_2()
                        .rounded(px(theme::CHIP_H / 2.0))
                        .flex_row()
                        .items_center()
                        .cursor_pointer()
                        .bg(theme::CHIP_BG)
                        .active(|s| s.bg(theme::SURFACE_RAISED))
                        .on_press(move || {
                            cyc.update(|v| {
                                if let Some(f) = Arc::make_mut(v).iter_mut().find(|f| f.key == key)
                                {
                                    let next = match f.kind {
                                        CipherFieldKind::Text => CipherFieldKind::Hidden,
                                        CipherFieldKind::Hidden => CipherFieldKind::Boolean,
                                        CipherFieldKind::Boolean => CipherFieldKind::Text,
                                    };
                                    f.set_kind(next);
                                }
                            });
                        })
                        .child(dynamic(move || {
                            let kind = fields
                                .get()
                                .iter()
                                .find(|f| f.key == key)
                                .map(|f| f.kind)
                                .unwrap_or_default();
                            text(field_kind_label(kind))
                                .text_size(px(theme::TEXT_CHIP))
                                .text_color(theme::TEXT_SECONDARY)
                        })),
                ),
        )
}

fn field_kind_label(kind: CipherFieldKind) -> &'static str {
    match kind {
        CipherFieldKind::Text => "文字",
        CipherFieldKind::Hidden => "隱藏",
        CipherFieldKind::Boolean => "布林",
    }
}

// —— 共用零件 ——

fn section(title: &'static str, rows: Vec<View>) -> View {
    let mut body = view().flex_col().gap_1p5();
    for row in rows {
        body = body.child(row);
    }
    view().flex_col().gap_1p5().child(section_label(title)).child(body)
}

fn section_label(text_label: &'static str) -> Text {
    text(text_label)
        .text_size(px(theme::TEXT_SECTION))
        .font_weight(FontWeight::SEMIBOLD)
        .letter_spacing(px(0.4))
        .text_color(theme::TEXT_SECONDARY)
}

fn field_label(text_label: &'static str) -> Text {
    text(text_label)
        .text_size(px(theme::TEXT_FIELD_LABEL))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(theme::TEXT_SECONDARY)
}

/// 值塊：value 14 在淺灰圓角塊內，trailing 鈕群靠右，可附進度條行。
fn block(value: impl Into<String>, multiline: bool, trailing: Vec<View>) -> View {
    let value = value.into();
    block_dyn(move || value.clone(), multiline, trailing, None)
}

fn block_dyn(
    value: impl Fn() -> String + 'static,
    multiline: bool,
    trailing: Vec<View>,
    below: Option<View>,
) -> View {
    let mut actions = view().flex_row().items_center().gap_1();
    for t in trailing {
        actions = actions.child(t);
    }
    let mut body = view()
        .flex_1()
        .px_3()
        .py_2()
        .rounded(px(theme::RADIUS_BLOCK))
        .bg(theme::SURFACE)
        .child(
            text(value)
                .text_size(px(theme::TEXT_FIELD_VALUE))
                .line_height(px(20.0))
                .text_color(theme::TEXT_PRIMARY)
                .number_of_lines(if multiline { 4 } else { 1 })
                .ellipsize_mode(if multiline {
                    EllipsizeMode::Clip
                } else {
                    EllipsizeMode::Tail
                }),
        );
    if let Some(extra) = below {
        body = body.child(extra);
    }
    view().flex_row().items_center().gap_2().child(body).child(actions)
}

/// 欄位值塊：label 在上、值塊在下（詳情分節的最小單位）。
fn field_block(
    label_text: &'static str,
    value: impl Fn() -> String + 'static,
    trailing: Vec<View>,
) -> View {
    view()
        .flex_col()
        .gap_1()
        .child(field_label(label_text))
        .child(block_dyn(value, false, trailing, None))
}

fn badge(label: &'static str, fg: AdaptiveColor) -> View {
    view()
        .h(px(theme::BADGE_H))
        .px_2()
        .rounded(px(theme::BADGE_H / 2.0))
        .flex_row()
        .items_center()
        .justify_center()
        .bg(theme::SURFACE_RAISED)
        .child(
            text(label)
                .text_size(px(theme::TEXT_BADGE))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(fg),
        )
}

/// 複製鈕（⧉→✓ 1 秒回饋；Android 無剪貼簿定時清除面，見缺角清單）。
fn copy_revealed(
    plain: Signal<Option<Revealed>>,
    which: &'static str,
    copied: Signal<Option<String>>,
) -> View {
    let press: Rc<dyn Fn() -> Option<String>> = Rc::new(move || {
        let r = plain.get()?;
        match which {
            "username" => r.username,
            "password" => r.password.as_ref().map(|p| p.to_string()),
            _ => None,
        }
    });
    mini_copy(press, which.to_owned(), copied)
}

fn copy_value(value: String, copied: Signal<Option<String>>) -> View {
    mini_copy(Rc::new(move || Some(value.clone())), "uri".to_owned(), copied)
}

fn copy_static(value: impl Fn() -> String + 'static, copied: Signal<Option<String>>) -> View {
    mini_copy(Rc::new(move || Some(value())), "totp".to_owned(), copied)
}

fn mini_copy(
    value: Rc<dyn Fn() -> Option<String>>,
    token: String,
    copied: Signal<Option<String>>,
) -> View {
    let press = value.clone();
    let mark = token.clone();
    view()
        .w(px(theme::COPY_BTN + 12.0))
        .h(px(theme::COPY_BTN + 12.0))
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .active(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || {
            if let Some(v) = press()
                && !v.is_empty()
            {
                set_clipboard(v);
            }
            copied.set(Some(mark.clone()));
            let t = mark.clone();
            set_timeout(Duration::from_millis(1000), move || {
                if copied.get().as_deref() == Some(t.as_str()) {
                    copied.set(None);
                }
            });
        })
        .child(
            text(move || {
                if copied.get().as_deref() == Some(token.as_str()) { "✓" } else { "⧉" }
            })
            .text_size(px(14.0))
            .text_color(theme::TEXT_SECONDARY),
        )
}

/// 顯示／隱藏切換：顯示發 Reveal，隱藏即歸零（Revealed Drop → Zeroizing）。
fn reveal_toggle(
    hub: Arc<Hub>,
    id: ItemId,
    plain: Signal<Option<Revealed>>,
    status: Signal<String>,
) -> View {
    let press_hub = hub;
    view()
        .h(px(theme::CHIP_H))
        .px_2()
        .rounded(px(theme::CHIP_H / 2.0))
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .bg(theme::CHIP_BG)
        .active(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(move || {
            if plain.get().is_some() {
                plain.set(None);
                return;
            }
            match press_hub.reveal(id) {
                Ok(r) => plain.set(Some(r)),
                Err(e) => status.set(e),
            }
        })
        .child(
            text(move || if plain.get().is_some() { "隱藏" } else { "顯示" })
                .text_size(px(theme::TEXT_CHIP))
                .text_color(theme::TEXT_SECONDARY),
        )
}

fn page_header(title: &'static str, subtitle: &'static str) -> View {
    view()
        .flex_col()
        .gap_1()
        .px_5()
        .pt_6()
        .pb_2()
        .child(
            text(title)
                .text_size(px(theme::TEXT_PAGE_TITLE))
                .font_weight(FontWeight::BOLD)
                .text_color(theme::TEXT_PRIMARY),
        )
        .child(
            text(subtitle)
                .text_size(px(theme::TEXT_PAGE_SUB))
                .line_height(px(18.0))
                .text_color(theme::TEXT_SECONDARY),
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
        .child(field_label(label))
        .child(
            input()
                .value(move || value.get())
                .placeholder(placeholder.to_owned())
                .placeholder_color(move || color(theme::TEXT_MUTED))
                .masked(secure)
                .on_change(move |text: &str| value.set(text.to_owned()))
                .h(px(theme::INPUT_H))
                .px_3()
                .rounded(px(theme::RADIUS_CONTROL))
                .border(px(1.0))
                .border_color(theme::HAIRLINE)
                .bg(theme::SURFACE)
                .text_color(theme::TEXT_PRIMARY)
                .text_size(px(theme::TEXT_ROW))
                .focus(|s| s.border_color(theme::ACCENT)),
        )
}

fn primary_button(
    label: impl IntoReactive<SharedString>,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .h(px(theme::BTN_H))
        .px_6()
        .rounded(px(theme::RADIUS_CONTROL))
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .bg(theme::ACCENT)
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(16.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::TEXT_ON_ACCENT),
        )
}

fn ghost_button(
    label: impl IntoReactive<SharedString>,
    on_press: impl Fn() + 'static,
) -> View {
    view()
        .h(px(theme::BTN_H))
        .px_4()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .bg(theme::SURFACE)
        .active(|s| s.bg(theme::SURFACE_RAISED))
        .on_press(on_press)
        .child(text(label).text_size(px(14.0)).text_color(theme::TEXT_PRIMARY))
}

fn destructive_button(label: &'static str, on_press: impl Fn() + 'static) -> View {
    view()
        .h(px(theme::BTN_H))
        .px_4()
        .rounded(px(theme::RADIUS_CONTROL))
        .border(px(1.0))
        .border_color(theme::DESTRUCTIVE)
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .active(|s| s.opacity(0.7))
        .on_press(on_press)
        .child(
            text(label)
                .text_size(px(14.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme::DESTRUCTIVE),
        )
}

fn divider() -> View {
    view().h(px(1.0)).w_full().bg(theme::HAIRLINE)
}

/// 欄位值 → `Option`：全空視同未填（None＝清空語意，patch 差量的基準）。
fn nonblank(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

fn subtitle(item: &ItemMeta) -> String {
    if let Some(uri) = item.uris.first() {
        return uri.clone();
    }
    if item.tags.is_empty() {
        "—".to_owned()
    } else {
        item.tags.join("、")
    }
}

fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "登入",
        ItemKind::Card => "卡片",
        ItemKind::Identity => "身份",
        ItemKind::SecureNote => "安全備忘",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_remaining_counts_down_and_floors_at_zero() {
        assert_eq!(totp_remaining(30, 0), 30);
        assert_eq!(totp_remaining(30, 12), 18);
        assert_eq!(totp_remaining(30, 31), 0);
    }

    #[test]
    fn warn_threshold_within_period() {
        assert!(TOTP_WARN_SECS < TOTP_PERIOD_SECS);
        assert!(totp_remaining(5, 0) <= TOTP_WARN_SECS);
    }

    fn row(key: u32, uri: &str, m: Option<u8>) -> UriRow {
        UriRow { key, uri: uri.to_owned(), match_type: m }
    }

    #[test]
    fn uri_edits_key_alignment_and_structural_batches() {
        let orig = vec!["https://a.test".to_owned(), "https://b.test".to_owned()];
        let no_match: [Option<u8>; 2] = [None, None];
        // 全等基準＝三批皆空。
        let same = [row(0, "https://a.test", None), row(1, "https://b.test", None)];
        let (s, t, tail) = uri_edits(&orig, &no_match, &same);
        assert!(s.is_empty() && t.is_empty() && tail.is_empty());
        // 倒置排列但 key 對齊→只有真改動的列產 Set。
        let swapped = [row(1, "https://b.test", None), row(0, "https://a.test", None)];
        let (s, t, tail) = uri_edits(&orig, &no_match, &swapped);
        assert!(s.is_empty() && t.is_empty() && tail.is_empty());
        // 改值＋改判定走 leaf 批；新列附加落尾；刪列降序進結構批。
        let mixed = [row(0, "https://a2.test", Some(3)), row(1_001, "https://c.test", Some(0))];
        let (s, t, tail) = uri_edits(&orig, &no_match, &mixed);
        let dbg = |v: &[FieldEdit]| -> Vec<String> {
            v.iter().map(|e| format!("{e:?}")).collect()
        };
        assert_eq!(
            dbg(&s),
            dbg(&[
                FieldEdit::Set {
                    path: "uri.0".into(),
                    value: Some("https://a2.test".into()),
                },
                FieldEdit::SetUriMatch { index: 0, match_type: Some(3) },
            ])
        );
        assert_eq!(
            dbg(&t),
            dbg(&[
                FieldEdit::RemoveUri { index: 1 },
                FieldEdit::AppendUri { uri: "https://c.test".into() },
            ])
        );
        // 新列判定尾批：落地索引＝基準 2−刪 1＋附加序 0＝1。
        assert_eq!(dbg(&tail), dbg(&[FieldEdit::SetUriMatch { index: 1, match_type: Some(0) }]));
    }

    fn frow(key: u32, name: &str, value: &str, kind: CipherFieldKind) -> FieldRow {
        FieldRow { key, name: name.to_owned(), value: value.to_owned(), kind }
    }

    #[test]
    fn field_edits_align_by_identity_not_position() {
        let orig = vec![
            CipherField { name: "a".into(), value: Some("1".into()), kind: CipherFieldKind::Text },
            CipherField { name: "b".into(), value: None, kind: CipherFieldKind::Text },
        ];
        // 中段刪 a：b 的基準索引仍是 1（key 對齊），新列 c 落尾。
        let cur = [
            frow(1, "b", "x", CipherFieldKind::Text),
            frow(501, "c", "v", CipherFieldKind::Text),
        ];
        let edits = field_edits(&orig, &cur);
        assert!(
            edits
                .iter()
                .any(|e| matches!(e, FieldEdit::Set { path, value } if path == "field.1.value" && value.as_deref() == Some("x"))),
            "b 列值改動應按基準索引 1 送出：{edits:?}"
        );
        assert!(
            edits.iter().any(|e| matches!(e, FieldEdit::RemoveField { index: 0 })),
            "a 列刪除應以基準索引 0 送出：{edits:?}"
        );
        assert!(
            edits
                .iter()
                .any(|e| matches!(e, FieldEdit::AppendField { field } if field.name == "c")),
            "新列 c 應附加：{edits:?}"
        );
        // 全空新列不送。
        let cur2 = [frow(0, "a", "1", CipherFieldKind::Text), frow(777, "", "", CipherFieldKind::Text)];
        assert!(
            field_edits(&orig, &cur2)
                .iter()
                .all(|e| !matches!(e, FieldEdit::AppendField { .. })),
            "全空新列不產生 AppendField"
        );
    }

    #[test]
    fn boolean_kind_normalizes_value() {
        let mut r = frow(0, "t", "anything", CipherFieldKind::Text);
        r.set_kind(CipherFieldKind::Boolean);
        assert_eq!(r.value, "false");
        r.value = "true".to_owned();
        r.set_kind(CipherFieldKind::Boolean);
        assert_eq!(r.value, "true");
    }

    #[test]
    fn match_labels_cover_six_states() {
        assert_eq!(uri_match_label(None), "預設");
        assert_eq!(uri_match_label(Some(3)), "精確符合");
        // 5=Never 不在六態表：寬容顯示「預設」不亂併名。
        assert_eq!(uri_match_label(Some(5)), "預設");
        assert_eq!(URI_MATCH_OPTIONS.len(), 6);
    }
}
