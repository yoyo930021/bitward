# bitward Android（P4b）

NSH（`longbridge/nsh` 0.3.0，契約 §0.2）的純 Rust app，以 **in-process** 形態
載入中樞核心：`bw-crypto`（KDF 與信封）、`bw-server`（Bitwarden Client API）、
`bw-store`（SQLite 鏡像＋明文索引）直接鏈進 `libnsh.so`，所以這一軌沒有 FFI
綁定面，也沒有「GUI 內嵌第二份金鑰」之外的信任邊界（契約 §1：Android 的
Full 形態＝app 內等位物）。

已交付的是**能用的登入路徑＋autofill 真候選**，不是完整 UI：

| 有 | 還沒有 |
|---|---|
| 登入頁（伺服器／信箱／主密碼，預填上次帳號） | 新增／編輯／刪除（寫入路徑要 outbox＋衝突 UI） |
| prelogin → 派生 → password grant → user key 解封 | Keystore 封存本體（Class 3 生成路徑已通，wrap/unwrap 接 `UnlockMachine` 在下一批） |
| 全量 sync → 鏡像落地 → 明文索引回填 | 背景同步（`HubService` 已宣告，`startForeground` 尚未接） |
| AutofillService 解鎖態真候選填充（JNI 橋接同程序中樞；鎖定態面板列「尚未解鎖」，點它拉開 app 解鎖＝解鎖引導） | 附件、org 共享、衝突收件匣 |
| 列表（搜尋走 bw-store 的 FTS5／LIKE）、詳情 Reveal、TOTP 現算 | Autofill save 回填（`HubBridge.save` 界面就緒，落地等寫入路徑） |
| 鎖定＝丟棄 user key（Drop 歸零）、重新同步 | |

## 建與跑

```sh
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH="$HOME/.local/bin:$PATH"          # nsh
cd apps/bitward-android

nsh check                                     # cargo check（本機目標）
nsh package --target android                  # 三 ABI 的簽章 APK → .nsh/out/bitward.apk
android-shell/build.sh                        # 孤島外殼合併 → .nsh/out/bitward-islands.apk
nsh package --target android --run            # 順帶 adb install + 啟動（要已開的 emulator）
cargo run                                     # 桌機 dev 迴圈（AppKit 後端，同一套 UI 碼）
```

日常裝機走 `dev/e2e/android-app.sh`（它裝的是合併包）。純 nsh 包（無孤島）
仍可單獨 `nsh package --run` 使用；兩包同鑰，`install -r` 互換。

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

它 register 一個示範帳號、播幾筆項目、開 emulator（若沒開）、組 APK（含孤島
外殼）、安裝、啟動，然後用 `adb` 驅動真實 UI（填欄位→按登入），把截圖與
uiautomator 層級留檔在 `apps/bitward-android/shots/`。emulator 到 host 的
Vaultwarden 用 `http://10.0.2.2:18095`（10.0.2.2＝alias 到 host loopback）。
A8–A11 驗孤島：系統列舉 AutofillService（注意 Android 15+ 的 key 是
`autofill_service`）、fill 請求送達＋「尚未解鎖」面板截圖、Keystore Class 3
EC 金鑰生成（需要鎖屏 PIN，腳本自備）、解鎖態真候選（面板列真項目、
commit 後欄位出現真 username）。

## 檔案

| 檔 | 內容 |
|---|---|
| `src/lib.rs` | 根元件：`nav_stack` + 狀態機（SignedOut → Busy → Vault），詳情是 push 上去的一頁 |
| `src/ui.rs` | 登入頁、列表、詳情頁；純排版與訊號，零業務語意 |
| `src/hub.rs` | in-process 中樞編排（KDF/登入/sync/索引/Reveal/候選/鎖定）＋ 3 個單元測 |
| `src/jni.rs` | 孤島↔中樞的 JNI 橋（`NativeHub` 的四支符號；panic 擋在邊界內） |
| `android-shell/` | Kotlin 孤島的 Gradle 外殼（AutofillService／CredentialProviderService／Keystore／HubService＋`build.sh` 組裝鏈；說明見其 README） |
| `nsh.json` | app 中繼資料；`"root": "App"` 指到 Rust 根元件 |

## 明文紀律（契約 §2.7）

- 主密碼：`Hub::login` 內 `Zeroizing<String>` 承載，派生完 `MasterKey` Drop 歸零；
  登入回呼裡把欄位 `set(String::new())` 清掉殘留（nsh 的 `String` 不能清零，
  這是 UI 層唯一殘留的拷貝，與 macOS GUI 送 BTP 前的形態相同）。
- user key：`bw_crypto::UserKey`（其 `Drop` 清零 enc‖mac），只存活在
  `Hub::unlocked`；`sign_out()` 丟棄即歸零。
- Reveal：詳情頁的 `plain` 訊號用 `SignalEquals::Never`（寫回同值也照樣通知，
  不讓「值相等」吞掉清零）；`on_dismiss`（含系統返回鍵）即 `set(None)`。
- Autofill：填充明文只活在單次 `onFillRequest` 的 `Dataset` 裡（Kotlin 端
  不快取、不落地，見 `android-shell/README.md` 紀律）；logcat 只記 id 與計數。
- 明文不進日誌、不進帳號檔；帳號檔只存 `protected_user_key`（未解封形態）。
- 鏡像與明文索引落在 `noBackupFilesDir/bitward`（`BitwardApplication` 於進程
  最早期用 `BITWARD_ANDROID_DATA` 傳入）：系統不會連 cache 一起清、Auto
  Backup 也不會把明文索引欄備份出裝置（2026-11-07 缺陷修，見
  `docs/design/android-findings.md` 假設 7 結局）。

## 協作紀律（多 worker 並行時）

清理只准 `git clean -fdX`（僅 ignored 產物）或 `git clean -fd <自己的目錄>`。
**不要**在 repo 根跑無範圍的 `git clean -fd`：本 repo 的 worker 各自留下尚未
commit 的**未追蹤**原始檔（例：`apps/bitward-gui/src/*.rs` 曾被這樣掃掉過一次，
見 2026-11-07 Main 的協作記錄）。同一理由，`rm -rf` 也要帶明確路徑。
本 app 的產物目錄 `apps/**/target/` 與 `apps/**/.nsh/` 已進 `.gitignore`，
`git clean -fdX` 就足以清乾淨。

## 已知的下一步（P4b 第三批）

1. Keystore Class 3 封存 user key（冷啟免主密碼）：`BitwardKeyStore` 補
   wrap/unwrap，接 `bins/bitwarderd` 的 `UnlockMachine`（現在 `hub.rs` 自己
   派生，還沒走封存路徑）。封好後 service 冷啟也能解鎖，autofill 不再
   依賴 UI 進程活著。
2. 寫入路徑（`Vault:Create/Patch/Delete` 的等位物＝`bw-sync` 直接呼叫）＋衝突 UI；
   接好後把 `HubBridge.save`（autofill 存密碼）落地。
3. `HubService.startForeground`（含通知權限）＋背景同步／UnifiedPush 喚醒。
   （`HubHolder.bridge` 的 JNI 裝載與 autofill 真候選已完成：2026-11-07，
   惰性裝載在 `HubHolder.ensureBridge()`，驗收 A11。）
4. 匯出（未加密提醒）與 UnifiedPush distributor 接單。
