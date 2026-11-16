# PR2 Send 接收端 — 剩餘 live lanes 收據（verifier: PR2Verify, 2026-11-16）

Head 與環境
- 乾淨 worktree：/tmp/swarm-pr2/head @ a136506（無其他軌半成品）
- release 二進位：cargo build --release --bins（target/release/bitward、bitwarderd）
- 隔離鏈：VW 容器 bitward-vw-pr2v（127.0.0.1:18195，VOLATILE）＋ daemon
  ./target/release/bitwarderd --data-dir /private/tmp/swarm-pr2/head/dev/e2e/demo
  --sock dev/e2e/demo/s（pid 35362，webui 127.0.0.1:62428）
- 常駐 launchd 域（/private/tmp/io.bitward.dev/daemon.sock、pid 80521）全程只讀探測，零寫入。

逐車道
- Lane 2 文字 Send 網頁閉環：PASS。send-text-web.png（頁內標題「Lane2 text」＋明文「…XYZ-7781」）
- Lane 3 密碼 Send：PASS。錯密＝紅字「取用密碼不正確」（send-pw-wrong.png，實測 err 色 rgb(242,139,130)）；
  對密＝明文「TOPSECRET-3」（send-pw-ok.png）
- Lane 4 檔案 Send 網頁下載：PASS。瀏覽器實際落檔 lane4-downloaded.bin
  sha256=8a9d28647a643f4fb6ab6d2d6eb1f865729c2758d3a532f15ea7df0abb24eb33 ＝ 原檔；
  頁內「已解密 20000 bytes → lane4.bin」（send-file-dl.png）
- Lane 7 不可用態：PASS（三態實測，文案命中「Send 不可用：已過期、存取次數耗盡或已被刪除。」，非白屏）
  - 真過期：PUT /api/sends/{id} 把 deletionDate 改到過去 → send-expired.png
  - 耗盡：--max 1 已被 CLI 用掉 → send-exhausted.png
  - 已刪除：send rm 後 → send-deleted.png
  - CLI 側同態：error: Send 不可用（已過期、存取次數耗盡或已被刪除）
- Lane 9／shot-61：PASS（修測流後）。nsh run --release --target macos，EXIT 0，
  主流 53 幀全出（1..23、26..43、50..61，README 集合），shot-61-send-link.png 帶
  「分享已建立」＋「在瀏覽器開連結」鈕＋成功卡斷言 webUrl 指 127.0.0.1。
  加分閉環：GUI 建的那筆 Send（「E2E 接收頁範例」）在瀏覽器用 webUrl 讀出明文
  （send-gui-created-web.png）。
- Lane 10 裝機真機：SKIP（記錄）。見 lane10-resident-probe.txt：/Applications 版 daemon
  無 127.0.0.1 監聽、binary 無 webui 字串（head 版 3 命中），webui 尚未隨裝機落地；
  順帶記錄舊 daemon 對新 CLI 回包正常（status=AuthLocked、send ls items=[]，無 webUrl 欄＝零誤按）。

缺陷（已找＋已修，測流層）
- apps/bitward-gui/src/shots.rs 的 shot-61 步在 dd48e36 是紅的（實錄 panic「Send 建立應成功…」
  /tmp/swarm-pr2/shots-main.log）。根因鏈：同 tick 內 c.send(Cmd::ShowSendsTab(Create)) 只是丟 channel
  （state.rs:1158），而 c.send_form.text.set(...) 同步生效；reducer 隨後跑 ShowSendsTab →
  send_form.reset()（state.rs:2313-2319）把 text 清空 → SubmitSend 走「請輸入要分享的文字」
  早回（state.rs:2362-2366），send_created 永遠 None。修法＝照既有慣例拆兩步（對齊 448/452 行形態），
  並在斷言訊息帶出表單錯誤。

Perf（10MB 檔案 Send，交錯 5 輪，ambient load avg 2.9）
- CLI access（含程序啟動，不经 daemon）：172 / 176 / 176 / 176 / 175 ms，peak RSS 67.3–68.7 MB
- 頁內點擊→落檔完成（WebCrypto 解密＋blob 下載）：103 / 121 / 124 / 118 / 112 ms（第 6 抽 115、121 ms）
- 含導覽的頁側全程：80 ms（開頁到按鈕就緒）＋ 121 ms（點擊到完成）＝ 201 ms；harness 全程 231 ms
- 規則：頁 ≤ CLI 2× → 0.67×（含導覽 1.14×）PASS；10MB ≤ 30s → 0.12–0.20 s PASS
- 記憶體峰值（抽樣）：daemon 50.7 MB → 頁側單輪峰值 81.6 MB（+31 MB＝代理-held 13.4 MB base64 信封），
  輪後仍停 81.6 MB＝allocator 高水位 [推論，單輪不能證明無洩漏]；瀏覽器端 RSS 未隔離（共用 Chrome）故不列。
- 為什麼頁比 CLI 快（推論，部分實證）：CLI 每輪付程序啟動＋新 HTTP client 建池；頁側沿用熱 daemon
  （VW client 常駐）＋Chrome 硬體 AES-CBC/HMAC。兩側同機同負載交錯。

入帳前測（Main 指定）
- 主工作樹 `cargo test`（apps/bitward-gui 為獨立 cargo workspace）跑不動，與本 patch 無關：TwoFA 在途
  ——未提交的 state.rs（+395 行）import `crate::twofa`／`crate::webauthn`，而 lib.rs 尚未宣告兩模組
  （E0432／E0433 實錄）。
- 同 patch 的乾淨基線綠：/tmp/swarm-pr2/head（a136506 ＋ 僅 shots.rs 修正）`cargo test` →
  69 passed; 0 failed（含 send_rows 的 webUrl 欄解析與缺欄容錯測）；主流 e2e EXIT 0 見上。

拆帳後存留
- 證據目錄 /tmp/swarm-pr2/worker-1/（截圖、lane4-downloaded.bin、perf-rounds.tsv、
  lane10-resident-probe.txt、本檔母本 RECEIPT.md）不隨隔離環境拆除消失；worktree 內 53 幀
  （含 shot-61-send-link.png）拆前已複製至該目錄。

拆除
- kill 35362; docker rm -f bitward-vw-pr2v; git -C /Users/yoyo930021/git/bitward worktree remove --force /tmp/swarm-pr2/head
