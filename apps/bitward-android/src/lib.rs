//! bitward Android（P4b 第一批）：NSH 純 Rust app，in-process 載入中樞核心。
//!
//! 架構位置（契約 §0.1、§1）：Android 的 Full 形態沒有獨立 daemon 進程，
//! `bw-crypto`/`bw-server`/`bw-store` 直接鏈進 `libnsh.so`；UI 與核心同進程，
//! 所以這一軌沒有 FFI 綁定面。平台整合（AutofillService、Keystore、
//! CredentialProviderService）是 Kotlin 孤島，見 `android-shell/README.md`。
//!
//! 導航用 nsh 原生 `nav_stack`/`nav_page`：Android views 後端實測會渲染
//! （macOS dev host 的卡點 4 不適用），系統返回鍵會 pop 並觸發 `on_dismiss`。
//! 證據見 `docs/design/android-findings.md` 與 `spike/android/navprobe/`。

pub mod hub;
#[cfg(target_os = "android")]
mod jni;
pub mod theme;
pub mod ui;

use std::sync::{Arc, LazyLock};

use bw_proto::ItemId;
use hub::{Hub, Revealed, Snapshot, data_dir};
use nsh_base::{nav_page, nav_stack};
use nsh_core::prelude::*;
use ui::Icons;

/// 進程內的中樞（開不起來時把錯誤留給 UI 顯示；JNI 橋同享這個實例）。
pub(crate) static HUB: LazyLock<Result<Arc<Hub>, String>> = LazyLock::new(|| Hub::open(data_dir()));

/// 畫面狀態機：登入 → 同步 → 金庫。金鑰在不在記憶體是唯一的分支依據。
#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    /// 未解鎖：登入表單。
    SignedOut,
    /// 登入或同步中（挡住重複按下）。
    Busy,
    /// 已解鎖且有鏡像：列表。
    Vault(Snapshot),
}

#[native_module("bitward-android/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// 根元件：棧底一頁在「登入／金庫列表」兩態間切換，詳情與表單是 push
/// 上去的頁（手機單欄 push 導航；返回鍵語意見 navprobe 實錄）。
#[component]
pub fn App() -> impl IntoElement {
    let hub = match HUB.as_ref() {
        Ok(h) => h.clone(),
        Err(e) => return ui::broken_page(e.clone()),
    };
    let phase = signal(Phase::SignedOut);
    let status = signal(String::new());
    let selected = signal(None::<ItemId>);
    // 編輯頁的目標（None＝沒開）；`rev` 是寫入後的重算訊號：patch 不改
    // 計數、phase 值不動，列表 computed 需要這個獨立扳機。
    let editor = signal(None::<ui::Editor>);
    let rev = signal(0_u64);
    // 明文只存活在這個訊號：詳情頁離開時 set(None) → Zeroizing 歸零。
    // 用 SignalEquals::Never，寫回同值也照樣通知（不讓「值相等」吞掉清零）。
    let plain = signal_with(None::<Revealed>, SignalEquals::Never);
    // favicon 快取掛根上：列表頁的 effect 寫、詳情磚讀，換頁不丟實圖。
    let icons = Icons::new();

    let hub_vault = hub.clone();
    let hub_login = hub.clone();
    let hub_detail = hub.clone();
    let hub_edit = hub.clone();
    let icons_vault = icons.clone();
    let icons_detail = icons;

    view()
        .flex_1()
        .bg(crate::theme::BASE)
        .text_color(crate::theme::TEXT_PRIMARY)
        .child(
            nav_stack()
                .flex_1()
                .child(
                    nav_page().key("root").title("bitward").child(
                        when(
                            move || matches!(phase.get(), Phase::Vault(_)),
                            move || {
                                ui::vault_page(
                                    hub_vault.clone(),
                                    phase,
                                    status,
                                    selected,
                                    editor,
                                    rev,
                                    icons_vault.clone(),
                                )
                            },
                        )
                        .otherwise(move || ui::login_page(hub_login.clone(), phase, status)),
                    ),
                )
                .child(when(
                    move || selected.get().is_some(),
                    move || {
                        let id = selected.get().unwrap_or_default();
                        ui::detail_page(
                            hub_detail.clone(),
                            id,
                            selected,
                            plain,
                            editor,
                            phase,
                            rev,
                            icons_detail.clone(),
                        )
                    },
                ))
                // 編輯＝全頁表單（push 在棧上；FAB／詳情「編輯」都走這條）。
                .child(when(
                    move || editor.get().is_some(),
                    move || {
                        ui::editor_page(hub_edit.clone(), editor, phase, selected, plain, rev)
                    },
                )),
        )
}
