# NOTES — 魔術常數與外部依據

- nsh CLI／crate 版本：`nsh 0.3.0 (76fa8a7)`，來自 <https://github.com/longbridge/nsh/releases/tag/v0.3.0>（install.sh 裝到 `~/.nsh`，`~/.local/bin/nsh`）。brew formula 停在 0.1.1。
- 列表列高 64pt（`h_16`）、頭像 36pt：Apple HIG 可點擊列最小 44pt 加雙行空間，<https://developer.apple.com/design/human-interface-guidelines/lists-and-tables>。
- 鍵盤切頁 `mod+1/2/3`、`escape`：NSH `on_key` keystroke 語法（`mod` = Command on Apple），<https://docs.rs/nsh-core/0.3.0/nsh_core/element/fn.on_key.html>。
- 截圖常數：`kCGWindowListOptionIncludingWindow = 8`、`kCGWindowImageBoundsIgnoreFraming = 1`，<https://developer.apple.com/documentation/coregraphics/cgwindowlistoption/cgwindowlistoptionincludingwindow>。
- `_dispatch_main_q`（main queue 全域符號）：對齊 dispatch2 0.3.1 的 `queue.rs` 做法，<https://docs.rs/dispatch2/0.3.1/src/dispatch2/queue.rs.html>。
- 時序：2.2s 首幀截圖、0.6s 切頁間隔——launchd Background session 下無 vsync 事件可等，用固定 sleep 裕量（見 FINDINGS「截圖鏈」）。
- fixture 欄位＝`bw_proto::ItemMeta` 的 serde 表示（`crates/bw-proto/src/lib.rs:78`），`Option` 欄位缺席時 serde 視為 None，故 `folder_id/organization_id/updated_at` 可省略；`pending` 為必填 bool。
