# bitward Android（P4b 第一批）

NSH（`longbridge/nsh` 0.3.0，契約 §0.2）的純 Rust app，以 **in-process** 形態
載入中樞核心：`bw-crypto`（KDF 與信封）、`bw-server`（Bitwarden Client API）、
`bw-store`（SQLite 鏡像＋明文索引）直接鏈進 `libnsh.so`，所以這一軌沒有 FFI
綁定面，也沒有「GUI 內嵌第二份金鑰」之外的信任邊界（契約 §1：Android 的
Full 形態＝app 內等位物）。

這批交付的是**能用的登入路徑**，不是完整 UI：

| 有 | 還沒有 |
|---|---|
| 登入頁（伺服器／信箱／主密碼，預填上次帳號） | 新增／編輯／刪除（寫入路徑要 outbox＋衝突 UI） |
| prelogin → 派生 → password grant → user key 解封 | Keystore 封存（現在每次冷啟都要主密碼；見 `android/README.md`） |
| 全量 sync → 鏡像落地 → 明文索引回填 | AutofillService／CredentialProviderService（Kotlin 孤島佔位） |
| 列表（搜尋走 bw-store 的 FTS5／LIKE）、詳情 Reveal、TOTP 現算 | 附件、org 共享、衝突收件匣 |
| 鎖定＝丟棄 user key（Drop 歸零）、重新同步 | 背景同步（foreground service 尚未進 APK） |

## 建與跑

```sh
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH="$HOME/.local/bin:$PATH"          # nsh
cd apps/bitward-android

nsh check                                     # cargo check（本機目標）
nsh package --target android                  # 三 ABI 的簽章 APK → .nsh/out/bitward.apk
nsh package --target android --run            # 順帶 adb install + 啟動（要已開的 emulator）
cargo run                                     # 桌機 dev 迴圈（AppKit 後端，同一套 UI 碼）
```

純 cargo 交叉編譯（不走 nsh 鏈）要自己給 C 工具鏈，因為 `rusqlite`（bundled
SQLite）與 `ring` 有 C/asm 要編：

```sh
NDK=$HOME/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin
CC_aarch64_linux_android=$NDK/aarch64-linux-android21-clang \
AR_aarch64_linux_android=$NDK/llvm-ar \
  cargo check --target aarch64-linux-android --lib
```

`nsh package` 不需要這三個變數（它自繪 SDK 內 NDK 並注入 linker/cc）。

## 驗收腳本

```sh
dev/e2e/android-app.sh
```

它-register-一個示範帳號、播幾筆項目、開 emulator（若沒開）、組 APK、安裝、
啟動，然後用 `adb` 驅動真實 UI（填欄位→按登入），把截圖與 uiautomator 層級
留檔在 `apps/bitward-android/shots/`。 emulator 到 host 的 Vaultwarden 用
`http://10.0.2.2:18095`（10.0.2.2＝alias 到 host loopback）。

## 檔案

| 檔 | 內容 |
|---|---|
| `src/lib.rs` | 根元件：`nav_stack` + 狀態機（SignedOut → Busy → Vault），詳情是 push 上去的一頁 |
| `src/ui.rs` | 登入頁、列表、詳情頁；純排版與訊號，零業務語意 |
| `src/hub.rs` | in-process 中樞編排（KDF/登入/sync/索引/Reveal/鎖定）＋ 3 個單元測 |
| `android/` | Kotlin 孤島佔位與「為什麼還沒進 APK」的實測記錄 |
| `nsh.json` | app 中繼資料；`"root": "App"` 指到 Rust 根元件 |

## 明文紀律（契約 §2.7）

- 主密碼：`Hub::login` 內 `Zeroizing<String>` 承載，派生完 `MasterKey` Drop 歸零；
  登入回呼裡把欄位 `set(String::new())` 清掉殘留（nsh 的 `String` 不能清零，
  這是 UI 層唯一殘留的拷貝，與 macOS GUI 送 BTP 前的形態相同）。
- user key：`bw_crypto::UserKey`（其 `Drop` 清零 enc‖mac），只存活在
  `Hub::unlocked`；`sign_out()` 丟棄即歸零。
- Reveal：詳情頁的 `plain` 訊號用 `SignalEquals::Never`（寫回同值也照樣通知，
  不讓「值相等」吞掉清零）；`on_dismiss`（含系統返回鍵）即 `set(None)`。
- 明文不進日誌、不進帳號檔；帳號檔只存 `protected_user_key`（未解封形態）。

## 協作紀律（多 worker 並行時）

清理只准 `git clean -fdX`（僅 ignored 產物）或 `git clean -fd <自己的目錄>`。
**不要**在 repo 根跑無範圍的 `git clean -fd`：本 repo 的 worker 各自留下尚未
commit 的**未追蹤**原始檔（例：`apps/bitward-gui/src/*.rs` 曾被這樣掃掉過一次，
見 2026-11-07 Main 的協作記錄）。同一理由，`rm -rf` 也要帶明確路徑。
本 app 的產物目錄 `apps/**/target/` 與 `apps/**/.nsh/` 已進 `.gitignore`，
`git clean -fdX` 就足以清乾淨。

## 已知的下一步（P4b 第二批）

1. Keystore Class 3 封存 user key（冷啟免主密碼），並把 `bins/bitwarderd` 的
   `UnlockMachine` 接進來（現在 `hub.rs` 自己派生，還沒走封存路徑）。
2. 寫入路徑（`Vault:Create/Patch/Delete` 的等位物＝`bw-sync` 直接呼叫）＋衝突 UI。
3. Gradle 外殼讓 Kotlin 孤島真的進 APK（缺口記錄在 `android/README.md`）。
4. 匯出（未加密提醒）與 UnifiedPush distributor 接單。
