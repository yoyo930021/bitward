//! bitward Android（P4b 第一批）：NSH 純 Rust app，in-process 載入中樞核心。
//!
//! 架構位置（契約 §0.1、§1）：Android 的 Full 形態沒有獨立 daemon 進程，
//! `bw-crypto`/`bw-server`/`bw-store` 直接鏈進 `libnsh.so`；UI 與核心同進程，
//! 所以這一軌沒有 FFI 綁定面。平台整合（AutofillService、Keystore、
//! CredentialProviderService）是 Kotlin 孤島，見 `android/README.md`。
//!
//! 導航用 nsh 原生 `nav_stack`/`nav_page`：Android views 後端實測會渲染
//! （macOS dev host 的卡點 4 不適用），系統返回鍵會 pop 並觸發 `on_dismiss`。
//! 證據見 `docs/design/android-findings.md` 與 `spike/android/navprobe/`。

pub mod hub;
pub mod ui;

use std::sync::{Arc, LazyLock};

use bw_proto::ItemId;
use hub::{Hub, Revealed, Snapshot, data_dir};
use nsh_base::{nav_page, nav_stack, theme};
use nsh_core::prelude::*;

/// 進程內的中樞（開不起來時把錯誤留給 UI 顯示）。
static HUB: LazyLock<Result<Arc<Hub>, String>> = LazyLock::new(|| Hub::open(data_dir()));

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

/// 根元件：棧底一頁在「登入／金庫列表」兩態間切換，詳情是 push 上去的一頁。
#[component]
pub fn App() -> impl IntoElement {
    let hub = match HUB.as_ref() {
        Ok(h) => h.clone(),
        Err(e) => return ui::broken_page(e.clone()),
    };
    let phase = signal(Phase::SignedOut);
    let status = signal(String::new());
    let selected = signal(None::<ItemId>);
    // 明文只存活在這個訊號：詳情頁離開時 set(None) → Zeroizing 歸零。
    // 用 SignalEquals::Never，寫回同值也照樣通知（不讓「值相等」吞掉清零）。
    let plain = signal_with(None::<Revealed>, SignalEquals::Never);

    let hub_vault = hub.clone();
    let hub_login = hub.clone();
    let hub_detail = hub.clone();

    view()
        .flex_1()
        .bg(move || theme().background)
        .text_color(move || theme().foreground)
        .child(
            nav_stack()
                .flex_1()
                .child(
                    nav_page().key("root").title("bitward").child(
                        when(
                            move || matches!(phase.get(), Phase::Vault(_)),
                            move || ui::vault_page(hub_vault.clone(), phase, status, selected),
                        )
                        .otherwise(move || ui::login_page(hub_login.clone(), phase, status)),
                    ),
                )
                .child(when(
                    move || selected.get().is_some(),
                    move || {
                        let id = selected.get().unwrap_or_default();
                        ui::detail_page(hub_detail.clone(), id, selected, plain)
                    },
                )),
        )
}
