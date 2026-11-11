# bitward-gui

macOS 密碼管理 GUI 主體（契約 §0.2 NSH 裁決的 P1 落地）：瀏覽/搜尋/詳情/
Reveal/TOTP/新增/編輯/刪除/匯出/鎖態+解鎖，全部經 BTP 真連本機 daemon。
零業務邏輯在 GUI：分級、過濾、排序語意全在 `bitwarderd`。

## 執行

```sh
# 前提：daemon 已在跑（Full 套件註冊，或 dev 起 demo）
cargo run -- --sock <path>          # 或 nsh run --target macos
```

### 正式形態（巢狀進 Bitward.app）

`scripts/gui-bundle.sh` 以 cargo release 產物組最小 `BitwardGUI.app`
（id `io.bitward.dev.gui`、名「Bitward 密碼庫」、零 entitlements——hardened
runtime 實測不擋 group sock 與 ~/Downloads），由 `scripts/pkg-build.sh`／
`scripts/dev-install.sh` 放進 `Bitward.app/Contents/Applications/` 並納入深簽鏈。
LSUIElement 背景殼啟動時轉發開啟本 app（帶 `--sock`，預設 group container
路徑，`defaults write io.bitward.dev DaemonSockPath <path>` 覆寫）；
判定鏈見 `platforms/macos/FINDINGS.md` §12。開發形態（cargo run／nsh run）不受影響。

連線參數解析順序：`--sock <path>` > `BITWARD_GUI_SOCK` >
`$BITWARD_DATA_DIR/daemon.sock` > 平台資料目錄下的 `bitward/daemon.sock`。
daemon 不在 → 錯誤畫面（含路徑與重連鈕）。`nsh run` 沒有 argv 透傳，
開發時用 `BITWARD_GUI_SOCK=...` 指 sock。

## 主題切換（批次 5）

側欄底部「主題」三態：**跟隨系統（預設）／淺色／暗色**。實作口徑：

- nsh-core 自帶 appearance 環境（`ambient.rs`：`dark()` 反應式 env、
  `set_color_scheme(Appearance)`、`Appearance::{System,Light,Dark}`），
  「跟隨系統」由平台推送到 env、樣式閉包即時翻轉——**不需要** Mach 層
  `defaults read -g AppleInterfaceStyle` 輪詢（該兜底路徑查證後未用上，
  留此註記）。
- `theme.rs` 是雙槽色板（`AdaptiveColor{light, dark}`），所有元件經
  `theme::` token 取色即自動翻轉；切換不重建視窗。
- 選擇持久化在 `<平台資料目錄>/bitward/theme.txt`（`system|light|dark`）；
  nsh 未暴露 UserDefaults 綁定，小檔最貼近 `sock_path` 既有慣例。

## 驗證截圖（背景 session 自我截圖模式，照 spike 慣例）

```sh
cd apps/bitward-gui
BITWARD_GUI_SOCK=<repo>/dev/e2e/demo/s NSH_GUI_SHOTS=$PWD nsh run --target macos
```

依指令序列跑完整驗收流並寫 `shot-1..23、26..43、50..57-*.png`（24/25 徽章流、44..47 登入流、48/49 2FA 流見下）後退出：列表全量（三欄骨架、
型別磚、未同步膠囊，右欄空態為「選取一個項目」佔位）→ 搜尋 "GitHub" →
詳情遮罩 → 詳情 revealed → 新增編輯器（右欄 inline）→ 真送新增（Create+AddTag）
→ TOTP 缺席路徑（無 seed → 自動取碼靜默收合，驗證碼節不渲染，shot-6-totp-absent）→ 排序下拉 → 標籤 chips 選取 →
編輯改名（Patch）→ 刪除確認框 → 取消不刪斷言 → 刪除後空列表 →
鎖態頁（已鎖定+解鎖鈕）→ 解鎖 → 匯出確認框（未加密提醒）→ 匯出完成提示列 →
選取態（清搜尋、開詳情；選中列淡藍底＋左 3px 藍條）→
垃圾桶（軟刪條目＋刪除時間）→ 垃圾桶詳情（還原／永久刪除動作）→ 還原後回列表 →
產生器面板展開（真送 Use:GeneratePassword 取草稿）→
TOTP 倒數三段（真取碼後偽造時間源示 30/10/5 秒比例，5 秒段轉 warning 色）→
編輯改名前的同骨架對比兩張（查看態 shot-50-morph-view／編輯態 shot-51-morph-edit：
同項目、同節序、名稱就地變輸入框、值塊就地變輸入框、頂部鈕「編輯/刪除」變「取消/儲存」，
切換零跳動；網址為多列編輯器，列數＝基準列、增刪留 daemon 面）→
資料夾樹（把「GitHub 測試」歸入工作資料夾後過濾，側欄節點選中態）→
SecureNote 編輯器（帳密收合、備註大欄、Card/Identity 佔位灰）→
自訂欄位編輯列（文字＋隱藏兩列）→ 匯入模態（貼路徑→預覽計數）→
編輯模式欄位解鎖（text→boolean 開關拍板 shot-31、增／刪列 shot-32、
存檔後詳情頁布爾欄開關樣 shot-33）→ 匯入執行後結果列
（已匯入 N／跳過 M，走單交易 `VaultCall:Import`，列內含匯入產物）→
附件生命週期：上傳編輯器預覽（shot-34）→ 背景推送收斂後附件列在列（shot-35，
靠 `VaultChanged` 事件自動重取詳情）→ 下載落地結果列（shot-36）→ 刪除確認模態（shot-37）→
批准佇列：gated device session（`agent open --grant 'reveal:secret all approve'`）造一筆
真 pending，右欄佇列有筆＋側欄計數徽章（shot-41，並斷言 `requested_at_ms` 為近 5 分鐘
合理 epoch）→ 單鍵批准後佇列清空、徽章消失（shot-42）→
批准髒退出閘：編輯器弄髒後導航被確認框攔下（shot-43），拒絕留 edit、放棄完成重投導航 →
已封存視角（批次 C：SetArchived 封存→主列表消失→切「已封存」節點該項在列且副行顯示
封存時間（shot-52）→取消封存回主列表，斷言鏈全程校驗四態互斥）→
favicon 實圖（批次 C：開「GitHub 測試」詳情，主 uri host 經 `GetIcon` 取回 → magic 嗅探
定 MIME → 詳情 44px／列表 16px 圖示磚，先字母後換圖；demo VW 對 github.com 回真圖、
對解不了的 host 回 19×19 佔位 PNG＝照顯示，shot-53）→
暗色皮自查三張（shot-38 列表／39 詳情／40 新增器：`SetTheme(Dark)` 即時翻轉不重建視窗，
收尾復原跟隨系統預設）。

### 徽章無感收斂證據（`NSH_GUI_SHOTS_DRAIN`）

另跑一條獨立時間軸，證明 `OutboxDrained` 事件讓「未同步」徽章在 VW
恢復後自動消失（不點任何鈕）。指令由 `dev/e2e/autodrain.sh` 的停啟模式
驅動：VW 停機下建項目 → `shot-24-badge-pending.png`（徽章在列）→
背景重啟 VW → 事件幫浦收 `OutboxDrained` 自動重抓 →
`shot-25-badge-cleared.png`（徽章歸零）。90 秒未收斂即斷言失敗。

```sh
cd apps/bitward-gui
BITWARD_GUI_SOCK=<drain-daemon.sock> NSH_GUI_SHOTS=$PWD NSH_GUI_SHOTS_DRAIN=1 \
  nsh run --target macos
```

### 登入卡與憑證失效證據（`NSH_GUI_SHOTS_LOGIN`）

批次 8 補上 SignedOut 的登入入口（使用者實測回報：「打開顯示未登入，卻沒有登入的地方」）。
`dev/e2e/gui-login.sh` 一鍵起獨立環境：自起 VOLATILE VW 容器（`bitward-vw-login`，:18096）＋
全新 data-dir daemon（真 SignedOut 世界）＋`dev-register` 只在 server 端建帳（不寫 daemon 狀態），
再由 GUI 卡上完成一輪**真登入**：`shot-44-login-card.png`（空卡：伺服器 URL 佔位、email、主密碼
secure 欄、API key 小字提示）→ 填入 → `shot-45-login-filled.png` → `Auth:Login{password:Some}` →
hub 登入即解鎖 → `shot-46-vault-after-login.png`（進庫＋帳號列回填 email）→ 偽造 `needs_reauth`
→ `shot-47-reauth-banner.png`（頂部 warning 橫幅＋側欄帳號列警告色，點擊進登入卡）。
demo daemon／`bitward-vw-demo` 不受影響。

```sh
dev/e2e/gui-login.sh   # 產 apps/bitward-gui/shot-44..47-*.png，全綠印 GUI-LOGIN: ALL PASS
```

### 登入第二因子證據（`NSH_GUI_SHOTS_LOGIN2FA`）

批次 8b：帳號開 Authenticator(TOTP) 2FA 後，daemon 把伺服器挑戰映射成
`Response::TwoFactorRequest{providers}`（不吞成死字串），GUI 登入卡**原地**進第二步：
因子單選＋6 位碼欄＋記住此裝置＋「完成登入」。`dev/e2e/login2fa.sh` 一鍵跑全鏈：
真 VW（`bitward-vw-2fa`，:18097）經 API 開 2FA → **CLI** 兩步登入（stdin 依序收
密碼／因子／碼）→ 錯碼被拒且錯誤可懂 → **GUI** 兩步登入：`shot-48-login-2fa-step.png`
（因子清單＋驗證碼欄）→ 碼於填入時刻現算（shots 內建 TOTP，免預計算撞邊界）→
`shot-49-vault-after-2fa.png`（進庫＋鏡像非空）。兩段皆斷言 `status` Unlocked＋items≥1。
挑戰不在 daemon 跨呼叫快取：第二步由呼叫端重發 `Login{password+two_factor}`
（hash 可決定性重算，daemon 保持無狀態；理由見 `hub::login` 註解）。

```sh
dev/e2e/login2fa.sh    # 產 shot-48/49，全綠印 LOGIN2FA: ALL PASS（需 docker＋python3＋jq）
```

注意：垃圾桶與資料夾需要 daemon 支援 `Query.deleted`／`Query.folder` 三態與
`ListFolders`／`Vault:Restore`／`Vault:Purge`（主線三件套已落地）；批次 2c 的
編輯欄位增刪改型與原子匯入需要 `FieldEdit::SetType/AppendField/RemoveField`
與 `VaultCall:Import`（daemon 批次 3，e32e1d6 起）。產生器的 `Use:GeneratePassword`
為既有呼叫面。匯入執行走單交易 `VaultCall:Import`（全收或全拒），本地解析只做
預覽計數與擋加密檔。跑前把 demo daemon 重啟為新構成品並 `bitward unlock`，
且側欄「工作資料夾」需已存在（`bitward folder create 工作資料夾`）。VW 的
access token 壽命約 2 小時；daemon 自 4c 起**自動續期**（401 出口收口單飛續期
＋90 分鐘主動閘，新 token/refresh 對落盤 `account.json`）——久放後直接跑 e2e
即可，零人工。僅當 refresh 憑證也被拒（`status` 的 `needs_reauth=true`）才需
重新登入。

注意：流裡會真寫 demo vault——每跑一次淨留：一筆 "E2E 驗證項目改名"
（結尾已還原回庫）、一筆「2b 筆記範例」（含自訂欄位，附件在結尾刪除）、
兩筆「匯入示範 A/B」；「GitHub 測試」每輪被歸入「工作資料夾」（冪等）。
主流截圖開場釘選淺色主題（38–40 明確切暗色自查，收尾復原跟隨系統），
證據集不隨機器外觀漂移。跑前用 `bitward new` 塞幾筆明文名項目可讓截圖
不全是信封字串——daemon 的明文名字索引只在 sync/reindex 後回填。

## 架構（src/）

| 檔 | 職責 |
|---|---|
| `btp.rs` | BTP 精簡同步 client：u32 LE 長度前綴 + JSON 幀、`Hello{Enroll pair_code:null}`→`Welcome`→`Invoke`/`Reply`；鎖撤銷（A6）自動重連重 Enroll 一次；`listen` 事件監聽連線（wants 訂閱，OutboxDrained/VaultChanged 交 state 幫浦） |
| `state.rs` | 應用狀態機：`AppCore`（訊號集）+ `Cmd` 命令佇列 + 唯一 `reduce`；UI handler 只投遞命令，worker 執行緒只回傳命令，訊號全在引擎執行緒寫入；`watch_events` 事件幫浦（斷線 1s 重連；`EventsRefresh` 連詳情一起重取） |
| `lib.rs` | 根元件 `App`：命令幫浦（`set_interval` 50ms + `batch`）、TOTP 心跳（1s 引擎計時器）、批准佇列節拍（1.5s 輪詢，照殼節奏）、主題 effect（`theme_mode`→`set_color_scheme`，即時翻轉不重建視窗；`theme.txt` 持久化）、頂部列（置中搜尋＋新增項目）、左側欄（批次 11 漸進揭露：檯面常駐＝全部項目／(未分類)／資料夾樹／待批准＋計數徽章／垃圾桶／產生密碼／「更多」disclosure，收合組＝已封存／已共享／報告／Send／設定；底部僅帳號列（email＋上次同步／未登入／憑證失效三態）＋立即同步；快捷 cmd+1..4 直跳全部/垃圾桶/產生密碼/設定）、錯誤橫條、needs_reauth 橫幅（warning 色、點擊進登入卡）、Phase×Route 三欄版面與鎖態頁、SignedOut 登入卡（server/email/主密碼＋登入即解鎖）與側欄帳號列三態 |
| `approvals.rs` | 批准佇列右欄視角（自殼批准中心併入）：每筆＝去敏 summary＋請求時間（`requested_at_ms`，daemon 補欄即顯示）＋單鍵批准/拒絕（官方語意無二次確認，按錯以拒絕補救）；空佇列佔位卡；epoch→UTC 時分純函數 |
| `list.rs` | 置中搜尋框（Query.text 交 daemon FTS；掛頂部列）、標籤 chips 行＋排序/重新整理（中欄工具列）、排序選單、44px 列（favicon 磚（有 host 走 `ui::icon_tile` 實圖、否則字母型別磚）、選中列淡藍底＋藍指示條）、未同步膠囊、垃圾桶條目顯示刪除時間、已封存條目顯示封存時間、`virtual_list` |
| `detail.rs` | 右欄詳情面板：官方表單感——大名稱＋型別磚，分節與官方同序（帳密／驗證碼／備註／自訂欄位／附件／資訊），欄位為淺灰圓角值塊（label 12 粗灰在上、值 14 塊內、複製鈕塊右側），布爾欄渲染開關樣；垃圾桶條目動作改還原／永久刪除；密碼遮罩 →「顯示密碼」發 Get(Reveal)，明文只存 `revealed` 訊號、離開詳情即清；**編輯態＝同骨架原地變形**（`Route::Edit` 時名稱/帳號/密碼/標籤/備註值塊就地變同幾何輸入框、網址走多列編輯器、自訂欄位換編輯列、頂部鈕變取消/儲存，切換零跳動）；TOTP 進詳情自動取碼（無 seed 整節不渲染、真錯顯示可懂一行）＋倒數細进度條（≤5 秒轉 warning）；附件列＝檔名＋大小＋下載／刪除，節尾內聯上傳編輯器 |
| `attach.rs` | 附件視圖層純函數：大小格式化、32MiB 本地閘、org 上傳擋附、單飛行狀態機、上傳讀檔／下載落地路徑（`~/Downloads/bitward-attachment-*`，0600 防蓋檔）；往返在 `state.rs` 附件命令，收斂靠事件幫浦 |
| `form.rs` | 新增右欄 inline 編輯器（Create 專用；編輯態已併入 detail 同骨架 morph）：型別切換（登入/加密筆記可選，Card/Identity 佔位；項目型別建立後不可更改——與官方一致，community FR 1148 十年未開）、資料夾下拉（ListFolders）、name/username/password/**uris 多列編輯器（＋新增列／✕刪列，列身份 key 對齊）**/tags/notes/自訂欄位編輯列；密碼欄附產生器面板。`uris_editor`/`custom_fields_editor`/`folder_dropdown` 為 pub(crate) 供 detail morph 沿用（零複製） |
| `passgen.rs` | 產生器純狀態機：長度夾取（8–64、預設 20）、字元集開關、policy JSON（`Use:GeneratePassword` 欄名契約）；隨機數在 daemon |
| `import.rs` | 官方 JSON 匯入器：本地解析吃官方未加密匯出與本 App 匯出兩形態（預覽計數純函數、加密檔擋下），執行走單交易 `VaultCall:Import`（全收或全拒，上限 500） |
| `export.rs` | 未加密 JSON 匯出：逐筆 Get(Reveal) → `~/Downloads/bitward-export-<UTC>.json`（0600） |
| `theme.rs` | 設計 tokens：視圖層唯一顏色與尺寸真相源，禁散落 hex／魔數。**雙槽色板**（light＝官方淺色皮：白底、#175DDC 藍、6px 小圓角；dark＝藍紫暗色皮），語意色、文字三級、密度常量（三欄寬/列高/字級/留白/開關幾何）；外觀由 `set_color_scheme` 三態驅動、樣式閉包即時翻轉 |
| `ui.rs` | 共用小元件：按鈕（primary 藍實色/ghost/destructive）、型別磚（單色字形，monogram 退役）、`icon_tile`（favicon 實圖磚，先字母後換圖不閃）、徽章、表單欄、下拉列、模態殼（absolute 鋪滿 + 置中白卡）、確認/改密模態、複製鈕 |
| `shots.rs` | `NSH_GUI_SHOTS` 自我截圖器（AppKit `cacheDisplayInRect` 路徑，不需 TCC；objc2 經 `nsh_platform_macos` 再匯取）；`NSH_GUI_SHOTS_DRAIN` 徽章收斂時間軸；`NSH_GUI_SHOTS_LOGIN` 登入卡時間軸（gui-login.sh 驅動）；`NSH_GUI_SHOTS_LOGIN2FA` 登入第二步時間軸（login2fa.sh 驅動，碼填入時刻現算） |

導航是 `Route` 狀態機 + `when` 區塊——不用 `nav_stack`（spike FINDINGS
卡點 4：macOS dev host 不渲染）。

## 明文紀律（契約 §2.7 規則 6）

- 純 Rust 元件、無 QuickJS/TSX：明文天然不進 JS 堆。
- Reveal 明文只存詳情層 `revealed` 訊號；`leave_detail` 清空。
- 表單密碼走 `Zeroizing`（`state.rs` Zeroize 點 ①②）；GUI 不落地。
- 匯出是唯一明文檔案出口：確認框先示警（「未加密匯出」），落盤檔 0600，
  迴圈內密碼以 `Zeroizing` 持有（`export.rs` Zeroize 點 ③）。

## BTP 呼叫面

`Sync`：無（初始鎖態讀 `Welcome.state`）。`Auth`：`Unlock`（解鎖鈕）、
`Lock`（僅 dev 驗證流）。`Vault`：`List{Metadata}`、`Get{Masked}`、
`Get{Reveal}`、`Create`、`Patch`、`Delete`、`Overlay{AddTag,RemoveTag}`。
`Use`：`TotpCode`。

已知協議縫隙：`Vault:Create` 回應不含新 id（`Response::Ok`），標籤要
落在新項目上只能以明文名稱查回（`state.rs find_created`，名字完全相符
且 `updated_at` 為 None 的唯一候選）；歧義時放棄套標籤並提示。
