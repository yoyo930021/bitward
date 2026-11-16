# nsh-platform-linux spike 記錄（PR6-E2，2026-11-16）

結論：**通過**。nsh 0.3.0 的 GTK4 後端在本 repo GUI（Rust root app）上可開窗、可渲染、
可互動，四屏證據在 `/tmp/swarm-pr6/worker-1/p6-linux-gui-{1-list,2-detail,3-locked,4-unlocked}.png`。
「Linux GUI 緩議」降級不需要啟動。

環境：OrbStack ubuntu 24.04（arm64，17c/15G）、`libgtk-4-dev`（GTK 4.14.5）＋`xvfb`＋
`imagemagick`＋`xdotool`；`cargo build --release` 於 `apps/bitward-gui` 87 秒；
執行 `DISPLAY=:99 BITWARD_GUI_SOCK=<demo sock> nsh-app-bitward-gui`。

驗證面（對 demo 40 筆庫）：主列表（名稱/URI/favicon/側欄群組全渲染）、詳情
（遮罩密碼＋顯示密碼＋備註＋自訂欄位）、daemon `lock` 後 GUI 即時轉鎖屏（epoch
廣播有效）、鎖屏輸入主密碼回列表（互動閉環）。無崩潰、無白屏。

觀察與坑：
- `libEGL warning: DRI3`＝Xvfb 無加速，GSK 退軟件渲染，畫面正確；真機桌面无此項。
- a11y bus 缺失只警告；無障礙環境設 `GTK_A11Y=none` 消音。
- xdotool 輸入前必須先點落輸入元件取得焦點（鎖屏直打無效＝第一次截圖失敗根因，
  非框架問題）。
- 未覆盖面：拖窗、HiDPI 縮放、Wayland 後端（本 spike 全走 X11/Xvfb）；
  auto-type 在 Linux 恆 Unsupported（`bw-autotype` 邊界，另立 xdg 後端才談）。
- 常駐面 Linux 走 systemd user（`bitwarderd --service install`，PR6-E1），
  GUI 裝機形態（tarball 內含 or 獨立）屬 P6-E2 後續打包決策，未在本 spike 範圍。
