# bitward-gui

macOS 密碼管理 GUI 主體（契約 §0.2 NSH 裁決的 P1 落地）：瀏覽/搜尋/詳情/
Reveal/TOTP/新增/編輯/刪除/匯出/鎖態+解鎖，全部經 BTP 真連本機 daemon。
零業務邏輯在 GUI：分級、過濾、排序語意全在 `bitwarderd`。

## 執行

```sh
# 前提：daemon 已在跑（Full 套件註冊，或 dev 起 demo）
cargo run -- --sock <path>          # 或 nsh run --target macos
```

連線參數解析順序：`--sock <path>` > `BITWARD_GUI_SOCK` >
`$BITWARD_DATA_DIR/daemon.sock` > 平台資料目錄下的 `bitward/daemon.sock`。
daemon 不在 → 錯誤畫面（含路徑與重連鈕）。`nsh run` 沒有 argv 透傳，
開發時用 `BITWARD_GUI_SOCK=...` 指 sock。

## 驗證截圖（背景 session 自我截圖模式，照 spike 慣例）

```sh
cd apps/bitward-gui
BITWARD_GUI_SOCK=<repo>/dev/e2e/demo/s NSH_GUI_SHOTS=$PWD nsh run --target macos
```

依指令序列跑完整驗收流並寫 `shot-1..15-*.png` 後退出：列表（搜尋
"GitHub"）→ 詳情遮罩 → 詳情 revealed → 新增表單 → 真送新增（Create+AddTag）
→ TOTP 拒絕路徑（無 seed → 錯誤橫條）→ 排序下拉 → 標籤下拉 → 編輯改名
（Patch）→ 刪除確認框 → 刪除後空列表 → 鎖態（已鎖定+解鎖鈕）→ 解鎖 →
匯出確認框（未加密提醒）→ 匯出完成提示列。

注意：流裡會真寫 demo vault（建一筆 "E2E 驗證項目"、改名、軟刪；
詳情目標是種子項目「GitHub 測試」，找不到退回第一筆）。跑前用
`bitward new` 塞幾筆明文名項目可讓截圖不全是信封字串——daemon 的明文
名字索引只在 sync/reindex 後回填，離線 Unlocked 的舊鏡像會顯示密文名。

## 架構（src/）

| 檔 | 職責 |
|---|---|
| `btp.rs` | BTP 精簡同步 client：u32 LE 長度前綴 + JSON 幀、`Hello{Enroll pair_code:null}`→`Welcome`→`Invoke`/`Reply`；鎖撤銷（A6）自動重連重 Enroll 一次 |
| `state.rs` | 應用狀態機：`AppCore`（訊號集）+ `Cmd` 命令佇列 + 唯一 `reduce`；UI handler 只投遞命令，worker 執行緒只回傳命令，訊號全在引擎執行緒寫入 |
| `lib.rs` | 根元件 `App`：命令幫浦（`set_interval` 50ms + `batch`）、標題列（鎖態/解鎖/匯出/新增/提示列）、錯誤橫條、Phase×Route 路由 |
| `list.rs` | 搜尋框（Query.text 交 daemon FTS）、標籤下拉（選項取自本地載入清單、比對交 daemon）、排序選單、pending 徽章、`virtual_list` |
| `detail.rs` | metadata 全欄位；密碼遮罩 →「顯示密碼」發 Get(Reveal)，明文只存 `revealed` 訊號、離開詳情即清；TOTP 按鈕發 Use:TotpCode |
| `form.rs` | 新增/編輯表單（name/username/password/uri/tags） |
| `export.rs` | 未加密 JSON 匯出：逐筆 Get(Reveal) → `~/Downloads/bitward-export-<UTC>.json`（0600） |
| `ui.rs` | 按鈕/徽章/表單欄/下拉列/確認模態（absolute 鋪滿 + 置中卡） |
| `shots.rs` | `NSH_GUI_SHOTS` 自我截圖器（AppKit `cacheDisplayInRect` 路徑，不需 TCC；objc2 經 `nsh_platform_macos` 再匯取） |

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
