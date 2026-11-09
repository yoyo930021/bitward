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

## 驗證截圖（背景 session 自我截圖模式，照 spike 慣例）

```sh
cd apps/bitward-gui
BITWARD_GUI_SOCK=<repo>/dev/e2e/demo/s NSH_GUI_SHOTS=$PWD nsh run --target macos
```

依指令序列跑完整驗收流並寫 `shot-1..23、26..37-*.png`（24/25 見下）後退出：列表全量（三欄骨架、
型別磚、未同步膠囊，右欄空態為「選取一個項目」佔位）→ 搜尋 "GitHub" →
詳情遮罩 → 詳情 revealed → 新增表單模態 → 真送新增（Create+AddTag）
→ TOTP 拒絕路徑（無 seed → 錯誤橫條）→ 排序下拉 → 標籤 chips 選取 →
編輯改名（Patch）→ 刪除確認框 → 取消不刪斷言 → 刪除後空列表 →
鎖態頁（已鎖定+解鎖鈕）→ 解鎖 → 匯出確認框（未加密提醒）→ 匯出完成提示列 →
選取態（清搜尋、開詳情；選中列淡藍底＋左 3px 藍條）→
垃圾桶（軟刪條目＋刪除時間）→ 垃圾桶詳情（還原／永久刪除動作）→ 還原後回列表 →
產生器面板展開（真送 Use:GeneratePassword 取草稿）→
TOTP 倒數三段（真取碼後偽造時間源示 30/10/5 秒比例，5 秒段轉 warning 色）→
資料夾樹（把「GitHub 測試」歸入工作資料夾後過濾，側欄節點選中態）→
SecureNote 模態（帳密收合、備註大欄、Card/Identity 佔位灰）→
自訂欄位編輯列（文字＋隱藏兩列）→ 匯入模態（貼路徑→預覽計數）→
編輯模式欄位解鎖（text→boolean 開關拍板 shot-31、增／刪列 shot-32、
存檔後詳情頁布爾欄開關樣 shot-33）→ 匯入執行後結果列
（已匯入 N／跳過 M，走單交易 `VaultCall:Import`，列內含匯入產物）→
附件生命週期：上傳編輯器預覽（shot-34）→ 背景推送收斂後附件列在列（shot-35，
靠 `VaultChanged` 事件自動重取詳情）→ 下載落地結果列（shot-36）→ 刪除確認模態（shot-37）。

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

注意：流裡會真寫 demo vault（建一筆 "E2E 驗證項目"、改名、軟刪；
詳情目標是種子項目「GitHub 測試」，找不到退回第一筆）。跑前用
`bitward new` 塞幾筆明文名項目可讓截圖不全是信封字串——daemon 的明文
名字索引只在 sync/reindex 後回填，離線 Unlocked 的舊鏡像會顯示密文名。

## 架構（src/）

| 檔 | 職責 |
|---|---|
| `btp.rs` | BTP 精簡同步 client：u32 LE 長度前綴 + JSON 幀、`Hello{Enroll pair_code:null}`→`Welcome`→`Invoke`/`Reply`；鎖撤銷（A6）自動重連重 Enroll 一次；`listen` 事件監聽連線（wants 訂閱，OutboxDrained/VaultChanged 交 state 幫浦） |
| `state.rs` | 應用狀態機：`AppCore`（訊號集）+ `Cmd` 命令佇列 + 唯一 `reduce`；UI handler 只投遞命令，worker 執行緒只回傳命令，訊號全在引擎執行緒寫入；`watch_events` 事件幫浦（斷線 1s 重連；`EventsRefresh` 連詳情一起重取） |
| `lib.rs` | 根元件 `App`：命令幫浦（`set_interval` 50ms + `batch`）、TOTP 心跳（1s 引擎計時器）、頂部列（置中搜尋＋新增項目）、左側欄（我的密碼庫＋資料夾樹／已共享佔位／垃圾桶／同步列／匯出/匯入/改密）、錯誤橫條、Phase×Route 三欄版面與鎖態頁 |
| `list.rs` | 置中搜尋框（Query.text 交 daemon FTS；掛頂部列）、標籤 chips 行＋排序/重新整理（中欄工具列）、排序選單、44px 列（型別磚單色字形、選中列淡藍底＋藍指示條）、未同步膠囊、垃圾桶條目顯示刪除時間、`virtual_list` |
| `detail.rs` | 右欄詳情面板：官方表單感——大名稱＋型別磚，分節與官方同序（帳密／驗證碼／備註／自訂欄位／附件／資訊），欄位為淺灰圓角值塊（label 12 粗灰在上、值 14 塊內、複製鈕塊右側），布爾欄渲染開關樣；垃圾桶條目動作改還原／永久刪除；密碼遮罩 →「顯示密碼」發 Get(Reveal)，明文只存 `revealed` 訊號、離開詳情即清；TOTP 按鈕發 Use:TotpCode＋倒數細进度條（≤5 秒轉 warning）；附件列＝檔名＋大小＋下載／刪除，節尾內聯上傳編輯器 |
| `attach.rs` | 附件視圖層純函數：大小格式化、32MiB 本地閘、org 上傳擋附、單飛行狀態機、上傳讀檔／下載落地路徑（`~/Downloads/bitward-attachment-*`，0600 防蓋檔）；往返在 `state.rs` 附件命令，收斂靠事件幫浦 |
| `form.rs` | 新增/編輯模態（elevated 卡＋背板點擊取消）：型別切換（登入/加密筆記可選，Card/Identity 佔位；項目型別建立後不可更改——與官方一致，community FR 1148 十年未開）、資料夾下拉（ListFolders）、name/username/password/uri/tags/notes/自訂欄位編輯列；密碼欄附產生器面板 |
| `passgen.rs` | 產生器純狀態機：長度夾取（8–64、預設 20）、字元集開關、policy JSON（`Use:GeneratePassword` 欄名契約）；隨機數在 daemon |
| `import.rs` | 官方 JSON 匯入器：本地解析吃官方未加密匯出與本 App 匯出兩形態（預覽計數純函數、加密檔擋下），執行走單交易 `VaultCall:Import`（全收或全拒，上限 500） |
| `export.rs` | 未加密 JSON 匯出：逐筆 Get(Reveal) → `~/Downloads/bitward-export-<UTC>.json`（0600） |
| `theme.rs` | 設計 tokens：官方淺色皮（白底、#175DDC 藍、6px 小圓角）、語意色、文字三級、密度常量（三欄寬/列高/字級/留白）、dark 色板保留（`dark` 子模組，下批切換）；視圖層唯一顏色與尺寸真相源，禁散落 hex／魔數 |
| `ui.rs` | 共用小元件：按鈕（primary 藍實色/ghost/destructive）、型別磚（單色字形，monogram 退役）、徽章、表單欄、下拉列、模態殼（absolute 鋪滿 + 置中白卡）、確認/改密模態、複製鈕 |
| `shots.rs` | `NSH_GUI_SHOTS` 自我截圖器（AppKit `cacheDisplayInRect` 路徑，不需 TCC；objc2 經 `nsh_platform_macos` 再匯取）；`NSH_GUI_SHOTS_DRAIN` 徽章收斂時間軸 |

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
