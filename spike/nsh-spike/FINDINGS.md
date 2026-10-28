# NSH GUI spike FINDINGS（契約 §0.2 校準）

## 版本
- 起點 `brew` formula：nsh 0.1.1（tap 已落後）。`brew upgrade` 無效；`install.sh` 裝到 **0.3.0 (76fa8a7)**（`~/.nsh` + `~/.local/bin/nsh`，PATH 順序蓋過 brew）。文件 §0.2 寫的「v0.2.x」應改釘 **0.3.0**，且 CI/本機安裝走 install.sh，不走 brew tap。

## 兩個畫面（spike/nsh-spike）
- provider 設定頁：3 個輸入欄（其中一個 masked）、3 個開關（`nsh_base::switch()`）、儲存按鈕 → `fixtures/settings.json`（serde round-trip 有測試）。
- vault 列表：`fixtures/items.json`（20 筆，直接反序列化成 `Vec<bw_proto::ItemMeta>`，path 依賴零修改）→ 搜尋框（name/uri/tag）+ `virtual_list`（keys/separator/empty）+ 點擊進詳情。桌面 `is_desktop()` 走 sidebar（theme 自帶 sidebar tokens），窄螢幕走頂部頁籤。
- 出口：`cargo test` 5/5 綠、`cargo clippy --all-targets -D warnings` 乾淨、`cargo fmt` 已跑。
- 截圖：`shot-1.png`（providers）、`shot-2.png`（vault 列表）、`shot-3.png`（詳情）。`nsh run --target macos` 啟動成功、無 crash、6 秒自我結束。

## API 順手度
- 好的：元件 run-once + 訊號模型清楚；`view/text/input/virtual_list` 流式 API 一氣呵成；Tailwind 步驟方法（`px_4`）省去手算；theme tokens（含 sidebar 組）齊全；`on_key` 一行綁定全域快捷鍵；bw-proto 零摩擦接入。
- 卡點 1：`Prop<Style>` 的 setter 是 `FnOnce(StyleRefinement) -> StyleRefinement` 且**只在建立時求值**；反應式要靠在 refinement 內傳 closure（`.bg(move || ...)`），文件沒寫清楚，試錯成本高。
- 卡點 2：`font_weight`/`number_of_lines` 等部分文字樣式不收 `IntoReactive`，切換 active 字重無法反應式，得改顏色。
- 卡點 3：`Signal` 是 `Copy`，但 `signal.clone()` 不會報錯、clippy 才唸；範本 codegen 因此產生一堆 `let x = x;`。
- 卡點 4：`nav_stack`/`nav_page` 在 macOS dev host 掛得上但內容區整塊不渲染（詳情改用 `when` 區域後正常）——原生導航棧列為**待觀察項**，正式 GUI 前先別依賴。
- 卡點 5：文字列高偏緊，詳情/列表的 value 行在截圖中有裁切感；需要显式 `line_height` 規範（P1 建 UI tokens 時處理）。

## 截圖鏈（環境限制，非 nsh 缺陷）
- 本機 agent 在 launchd `Background` session：`screencapture -x` 回 "could not create image from display"；`launchctl asuser` 亦被 TCC 擋。`CGWindowListCreateImage` 抓到純白（window 未被合成）。
- 解法：app 內 `cacheDisplayInRect_toBitmapImageRep` → PNG（不需 TCC，能捕 AppKit 重繪內容），由 `NSH_SPIKE_SHOTS` 環境變數驅動依序截三頁。正式 CI（macOS runner 有 GUI session）直接用 `screencapture -x` 即可，不需要這層。
- 鍵盤切頁（osascript System Events keystroke）送得進去、無權限錯誤，但无法從背景驗證結果，故截圖以環境變數固定腳本為準。

## nsh 打包鏈問題
- `nsh run` 組 app lib 時會**剝掉 Cargo.toml 的 `[target.'cfg(...)'.dependencies]`**：直接依賴 objc2 會 `unresolved import`，必須經 `nsh_platform_macos::{objc2, objc2_app_kit, objc2_foundation}` 再匯取；跨平台 dev 迴圈裡這是隱形規則，要寫進專案 README/CI。
- `nsh init --template rust` 附帶的 `App.test.tsx`/`tsconfig.json` 對純 Rust app 是多餘的（已刪）。
- 路徑依賴 `crates/bw-proto`（workspace 成員）被獨立 workspace（spike 有自己的 `[workspace]`）引用時正常。

## 對 §0.2 成本估計的校準建議
- 「GUI 開發成本兩套半→一套」方向成立：本 spike 兩個真實畫面 + 狀態管理 ≈ 900 行 Rust（含截圖器 190 行）、零平台碼；列表/表單/開關的組件coverage 足夠。
- 但 v0.3 仍嫩：style prop 語意、反應式覆蓋不全、nav_stack 不穩、target 依賴被剝——建議 §0.2 的「鎖版本 + vendor 補丁」加一條：**P1 起在 CI 跑 `nsh run --target macos` 冒煙 + 截圖 diff**，把框架抖動變成紅燈而不是意外。
- 「明文只進 Rust 元件」紀律在純 Rust 模板下天然成立（本 app 無 QuickJS）；TSX 混用時再驗 §2.7 規則 6。
- 裁決維持：採用。macOS track 可全棧押上；Android track 起押注前先確認 nav 容器在 Android views 後端的行為。
