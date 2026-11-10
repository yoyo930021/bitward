# Android 軌道風險探險 findings

日期：2026-10-30。環境：macOS arm64、rustc 1.99.1、nsh 0.3.0、Android SDK（platforms 34–36.1、
build-tools 33–37、NDK 27/28.2/30）、JDK 21 Temurin、`ANDROID_HOME=~/Library/Android/sdk`。
實驗碼：`spike/android/spk`（nsh rust 模板 app）、`spike/android/linkprobe`（cdylib 連結探針）。
均未動根 Cargo.toml（spk 自帶空 `[workspace]`；linkprobe 亦獨立）。

## 假設 1：NSH Android 打包鏈可用 — 通過

`nsh init spike/android/spk --template rust` → `nsh package --target android`（build 無 `--target`
選項，APK 產出路徑是 package）：

    ✓ built the Rust crate nsh-app-bitward-android-spike (19.9s)
    ✓ built libnsh.so ... armeabi-v7a (39.2s) / arm64-v8a (38.1s) / x86_64 (37.9s)
    ✓ packaged .nsh/out/bitward android spike.apk
    APK: classes.dex + lib/<3 ABI>/libnsh.so（debug 簽章，72MB）

不需 `ANDROID_NDK_HOME`（未設仍成功）：nsh 自繪 SDK 內 NDK 並注入 linker；prebuilt
runtime（`~/.nsh/runtime/android`）負責 Java 層，全程免 Gradle。未跑 emulator（不在驗收內）。
小坑：從 repo 根執行 `nsh package spike/android/spk` 時 `.nsh/out` 落在 cwd（repo 根），
須在 app 目錄內執行才寫進 app 自己的 `.nsh/out/`。

## 假設 2：spike path 依賴 bw-proto、序列化 ItemMeta — 通過

`spk/Cargo.toml`：`bw-proto = { path = "../../../crates/bw-proto" }`（同 nsh-spike 模式，
獨立 workspace 吸納根 crate 無衝突）。`src/lib.rs` 的 `sample_item_json()` 對
`ItemView::metadata(ItemMeta)` 做 serde_json round-trip＋「Metadata 無密碼鍵」斷言，
並掛進 App UI（Android 掛載即執行）。證據：

    test tests::item_meta_roundtrips ... ok
    （且假設 1 的三 ABI 交叉編譯已含此碼 → Android 目標下同樣編得過）

## 假設 3：aarch64-linux-android 可編 bw-crypto — 通過

`cargo check -p bw-crypto --target aarch64-linux-android`（先 `rustup target add`）：

    Checking rsa v0.9.10 → Checking bw-crypto → Finished in 4.03s

依賴圖（rsa/argon2/pbkdf2/aes…）純 Rust，零 C 編譯。cdylib 全連結探針（linkprobe）：
- 裸 `cargo build --target aarch64-linux-android` 在 link 階段才掛：macOS 的 clang/ld 不認
  GNU linker 選項（`ld: unknown options: --version-script=... --no-undefined-version`）。
- 指定 NDK linker 即過：

      CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang
      → Finished；liblinkprobe.so: ELF 64-bit ARM aarch64

教訓：**check 免 C 工具鏈；要產 .so/.apk 才需 NDK clang linker**（上述 env 或
`.cargo/config.toml` 的 `target.aarch64-linux-android.linker` 一行即可）。nsh 鏈已自動處理。

## 假設 4：UniFFI 綁 bw-btp client — 可行但有巨坑（評估，未實接）

最新穩定版 **uniffi 0.32.2**（2026-09-23；main 上 0.33-dev）。坑清單：
1. **serde 型別不自動過去**：`ClientMsg/ServerMsg/ItemMeta` 得在 UDL/proc-macro 重宣告一遍
   （雙份維護），或走「FFI 只傳 `Vec<u8>` postcard 幀／JSON字串、serde 留在 Rust 內」的薄外殼。
2. **泛型 trait 參數不能綁**：`write_client<W: AsyncWrite>` 這種簽名必須收斂成具象物件
   （如 `BtpClient::connect(sock_path)` 內部持流）。
3. async 支援穩定（Kotlin `suspend fun`、有 `tokio` feature），但**無取消機制**——BTP 長讀迴圈
   要自備 `cancel()` flag；且 `UnixStream` peer-UID 鑑權在 Android 跨 app 場景的有效性未驗。
4. Kotlin 綁定走 JNA（≥5.7）；ARM32 u8/u16 direct-mapping bug 至 0.31.2 才修，**鎖 ≥0.31.2**。
   main 有新 `uniffi-bindgen-kotlin-jni`（JNI、號稱大提速）但「very fresh」，P4 勿押。

建議採薄外殼（坑 1+2 一起解）：uniffi 面只暴露 6 個方法（對應 NM shim 的 method 集），
進出 postcard bytes；綁定面穩定後才考慮細化型別。

## 對 P4-Android 排程的建議

- 打包鏈零風險：nsh package 即出三 ABI 簽章 APK，NDK/Gradle 皆免。
- bw-crypto/bw-proto 交叉編譯零風險；唯一必要設定是 linker 一行（非 nsh 管線時）。
- 真正的工作量在 FFI 層：按薄外殼估 1–2 天（含 uniffi 骨架＋postcard 幀），排 P4 前先拍板
  「Android 端 BTP 傳輸」——daemon 在桌面、app 在手機，unix socket 跨不過去，
  需 LAN/TCP 或中繼（此為架構問題，非工具鏈問題，建議列 P4 開工前決策）。
- emulator 未裝亦未測（假設明文：編出 APK 即算過）；`nsh run --target android` 需 emulator/
  device，建議驗收放真機。
## P4b 第一批（2026-11-07）：nav 容器在 Android 的實測＋in-process 中樞進 APK

環境同上（nsh 0.3.0 76fa8a7、NDK 27/28.2/30、AVD `Pixel_10_Pro_XL`：android-36.1
google_apis_playstore arm64-v8a、4G RAM）。实验码：`spike/android/navprobe`
（導航探針）、`apps/bitward-android`（正式 app 本體）、`dev/e2e/android-app.sh`（驗收）。

### 假設 5：nsh 0.3.0 的導航容器在 Android views 後端可用 — 通過（macOS 卡點 4 不適用）

§0.2 的裁決寫「Android track 起押注前先確認 nav 容器行為」，實測四件事全過：

| 項目 | 證據 |
|---|---|
| `nav_stack`/`nav_page` 渲染內容 | uiautomator 層級有 `Probe A` 標題與 `PROBE-A-ROOT` 內容；兩頁棧時頂頁 `Probe B`/`PROBE-B-TOP` 渲染，原生 toolbar 跟著換標題 |
| `when` 區域增減頁面＝原生 push/pop | 起點 B 在棧上，按 `POP-VIA-STATE` 後層級只剩 Probe A（訊號驅動，無手動導航器） |
| 系統返回鍵 | `input keyevent 4` 會 pop 頂頁**並**觸發 `nav_page().on_dismiss`（logcat `probe: dismissed b`），只剩一頁時才退出 app |
| `dialog()`（Modal） | 按 `SHOW-DIALOG` 後層級出現 `PROBE-DIALOG`/`CLOSE-DIALOG`，蓋住棧與 header |

教訓：**Android 這軌可以直接押原生 `nav_stack`**（返回鍵語意免費），macOS dev host
仍按卡點 4 用 `when` 自製切頁。另外 `.children(cond.then(...))` 只在建立時求值
（卡點 1 的同一條），條件頁/條件內容一律走 `when(...)`，否則按了沒反應——這是
探針第一輪「push 沒渲染」的真正原因，不是框架缺陷。

### 假設 6：in-process 核心（bw-crypto/bw-server/bw-store）進得了 Android APK — 通過

把三個 crate 加進 nsh app 的依賴後 `nsh package --target android`：

    ✓ built libnsh.so ... armeabi-v7a (1m 4s) / arm64-v8a (1m 3s) / x86_64 (1m 2s)
    ✓ packaged .nsh/out/bitward.apk

`rusqlite`（bundled SQLite，要編 C）與 `ring`（asm）都在 nsh 自繪的 NDK 工具鏈下
编譯＋連結成功，**不需要**任何額外 env。但純 cargo 交叉編譯要自己給 C 工具鏈：
NDK 28 已移除裸 `aarch64-linux-android-clang` 符號連結，cc-rs 找不到會直接掛，
得明確指定：

    CC_aarch64_linux_android=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang
    AR_aarch64_linux_android=$NDK/.../llvm-ar
    cargo check --target aarch64-linux-android --lib

（`--all-targets` 在 Android 目標會連 bin target 一起編，而 nsh 模板的 `src/main.rs`
在非桌機目標是 `compile_error!`；Android 的 gate 用 `--lib`，桌機用 `--all-targets`。）

執行期證據（emulator，非 mock）：登入頁填表按「登入」後 logcat

    nsh_app_bitward_android::ui: 已登入：3 筆鏡像
    nsh_app_bitward_android::hub: hub: signed out（金鑰已歸零）

代表 prelogin→PBKDF2 600k 派生→password grant→user key 解封→`GET /sync`→
SQLite 鏡像＋明文索引回填在 arm64 模擬器上跑通（派生＋sync 不到 1 秒），
列表/搜尋/Reveal/遮罩重置都在真 UI 上驗過。到 host Vaultwarden 走
`http://10.0.2.2:18095`（10.0.2.2＝emulator 視角的 host loopback）。

### 假設 7：純 Rust app 拿得到可寫的 app 私有目錄 — 有缺口，可用 TMPDIR 抵

nsh 0.3.0 的 Android host 把 Java 層的 `filesDir` 只放進 JS runtime 的
`System.data_dir`（`nsh-core::element::System`），**純 Rust 根元件沒有對應存取面**
（`Environment` 裡沒有路徑欄位）。實測 app 進程的環境有 zygote 給的
`TMPDIR=/data/user/0/io.bitward.android/cache`（app 私有、可寫），本輪用它落地
`vault.db`/`account.json`，並留 `BITWARD_ANDROID_DATA` 覆寫：

    nsh_app_bitward_android::hub: bitward-android hub: dir=/data/user/0/io.bitward.android/cache/bitward

代價：cache 目錄理論上可被系統在空間壓力時清除（鏡像可重 sync，但帳號檔會不見）。
正式解要嘛上游開一個 Rust 側 data dir API，要嘛 Kotlin 外殼自己傳 `filesDir` 進來
（外殼已就位＝`android-shell/`，傳路徑的 JNI 通道列第二批）。

**結局（2026-11-07 第二批）**：走外殼傳路徑，不碰 nsh 上游。`BitwardApplication`
在任何進程入口前把 `BITWARD_ANDROID_DATA` 指向 `noBackupFilesDir/bitward`。
選 noBackupFilesDir 而非 filesDir：`vault.db` 帶明文索引欄（name/uris/
username/password），filesDir 會進 Auto Backup＝明文出裝置（破契約 §2.7 R3
的「0600 不離裝置」承受前提）；noBackup 不被自動清、不進備份，鏡像真丟了
重 sync 即癒。

### 假設 8：Kotlin 孤島能進 nsh 產的 APK — 不通（nsh 內）→ 由 Gradle 外殼解決（P4b 第二批，2026-11-07）

`nsh package --help` 的 Android 旗標只有 `--name/--id/--app-version/--build/--icon/
--keystore/--key-alias/--keystore-password/--run`；APK 的 dex 一律取自
`~/.nsh/runtime/android/{dev,release}/classes.dex`，**沒有** app 自帶 Kotlin/Java
來源、資源或 manifest 的掛鉤（`nsh.json` 也無對應欄位）。所以 `AutofillService`、
`CredentialProviderService`、Keystore、foreground service 這幾個孤島，在 0.3.0 的
管線下進不了 APK；第一批把孤島寫成佔位放在 `apps/bitward-android/android/`。

**結局（路線 A：Gradle 外殼，已落地）**：`apps/bitward-android/android-shell/`
是 app module 吃 nsh 產物的最小 Gradle 專案（Gradle 8.14＋快取 AGP 8.13.1＋
Kotlin 2.2.21，離線可建）：jniLibs/assets 直接從 `.nsh/out/bitward.apk` 解壓餵入，
孤島 Kotlin＋manifest 由 AGP 編譯，runtime 的 `classes.dex` 事後追加為
`classesN.dex`（ART minSdk≥21 原生載入多 dex；兩套碼零符號重疊），zipalign＋
`~/.android/debug.keystore` 重簽（與 nsh 產物同憑證，`install -r` 互換）。
最終包 `.nsh/out/bitward-islands.apk` 在 emulator 實測：

- 系統 bind 到 `io.bitward.android/.BitwardAutofillService`，logcat
  `bitward-island: autofill service bound by system` 與 `onFillRequest unlocked=false`，
  面板截圖列出「Bitward：尚未解鎖」（驗收 A8/A9）。
- Keystore Class 3 EC 金鑰在 service 內生成成功，logcat 回顯
  `keystore EC class3 key ready alias=bitward-class3-ec-probe strongbox=false`
  （emulator 無 StrongBox，降級路徑即正式行為；驗收 A10）。
- 原 A1–A7 不回歸（合併包裝回 emulator，登入/sync/搜尋/Reveal/返回/鎖定全過）。

三個 Android 16 實測坑（驗收腳本已照此寫）：

1. **autofill 服務的 settings key 換了**：`settings put secure
   current_autofill_service` 寫進去後 observer 完全無反應（dumpsys 仍認
   Google）；生效的是 `Settings.Secure` 的 **`autofill_service`**——
   `dumpsys autofill` 自報 `SecureSettingsServiceNamer: prop=autofill_service`。
2. **空 `Dataset` 不能 `build()`**：presentation-only 的鎖定列會丟
   `IllegalStateException: at least one of field or datatype must be set`；
   正統解是 response 級 `FillResponse.Builder.setAuthentication(focusedId,
   intentSender, RemoteViews)`。`PendingIntent.intentSender` 要 API 31+。
3. **Class 3 金鑰生成要求安全鎖屏**：無 PIN 時 `KeyGenParameterSpec` 帶
   `setUserAuthenticationRequired(true)` 直接丟 `IllegalStateException`
   （「Secure lock screen must be enabled」）；emulator 驗收前先
   `locksettings set-pin`。

教訓：孤島進 APK 不需要等上游掛鉤；外殼只承擔「編 Kotlin＋併 dex」，
nsh 管線（三 ABI 交叉編譯、NDK 注入、debug 簽章）全部照用。佔位目錄
`android/` 已刪除，檔位移入 `android-shell/app/src/main/`。

### adb 驅動陷阱（背景驗收必讀）

軟鍵盤開著時，第一個 `adb shell input type tap` 常被系統用來收 IME
（logcat 出現 `ImeTracker: ... HIDE_SOFT_INPUT fromUser true`），**送不到 app 的
`on_press`**；表單自動化要在按按鈕前先 `input keyevent 111`（ESCAPE，比 KEYCODE_BACK
安全——back 在單頁棧上會直接退出 app）。另外 `adb shell ...` 會吃 stdin，腳本裡
要加 `</dev/null`，否則迴圈的讀取會被它攔走。

### 對 P4b 排程的更新

- 導航：Android 可押原生 `nav_stack`（本輪已押，返回鍵＋`on_dismiss` 實測可用）。
- 打包：in-process 核心零風險；**唯一**必要設定是純 cargo 路徑的 `CC_*`/`AR_*` 兩行。
- 缺口兩項：(1) 純 Rust app 的 data dir API（否則鏡像放 cache）——**已解**
  （外殼 `BitwardApplication` 傳 `BITWARD_ANDROID_DATA`＝noBackupFilesDir，
  見假設 7 結局）；(2) Kotlin 孤島進 APK 的管道——**已解**（Gradle 外殼
  `android-shell/`，見假設 8 結局與 A8–A10）。
- 驗收入口：`dev/e2e/android-app.sh`（A1..A11：三 ABI＋孤島 dex 合併 APK、啟動到
  登入畫面、真實 UI 登入＋sync、搜尋、詳情遮罩→Reveal、返回清明文、鎖定＋預填、
  系統列舉 autofill 服務、fill 請求送達＋面板截圖、Keystore Class 3 EC 生成、
  解鎖態真候選＋commit 回真 username），截圖留 `apps/bitward-android/shots/`。

### P4b 第二批（2026-11-07）：autofill 真候選接線＋兩項缺陷收斂

- **bridge 接線**：`HubHolder.ensureBridge()` 惰性裝載（fill/save 請求到了才
  `System.loadLibrary("nsh")`＋探 `nshIsReady`），實作 `NativeHubBridge` 走
  `src/jni.rs` 的四支符號（ready/unlocked/candidates/reveal）。Rust panic 擋在
  邊界內（`catch_unwind`→回 null，Kotlin 視同空）。user key 不過橋；填充明文
  只在單次 `onFillRequest` 生命週期。A11 實測：解鎖後面板列真項目、commit 後
  欄位出現真 username（`dev/e2e/android-app.sh` 第 11 節）。
- **鏡像目錄**：cache（TMPDIR）→ `noBackupFilesDir/bitward`，理由見假設 7 結局。
  副作用：換目錄＝舊装机資料留在 cache（e2e 有 `pm clear`，正式機一次性重登）。
- **reindex 雙份收斂**：Android `reindex_plain`、daemon `reindex_many` 與
  `reveal` 的 40 行欄位提取改成共用 `bw_vault::plain_index`（欄位路徑與
  `flatten` 同座標系，單元測 2 條）。同一批把 **unlock 成功→回填**接到
  daemon `AuthCall::Unlock` 完成處（`reindex_all`）：macOS demo 實測重啟＋
  鎖定態 sync 後 `ls` 名字停在信封形態，Android 登入路徑本來就接了回填，
  兩平台現在同一支函數、同一個時點。回歸罩：`dev/e2e/readpath.sh` A12
  （重啟→sync→unlock→ls 無 `(pending)`、名字解密）。
- **本地 stub jar 缺件**：android-35 jar 沒有 `ViewHints`／`Presentation`／
  `addDataset(AutofillId, Dataset)`，編譯直接紅；以字串常數＋
  `setValue(field, value, presentation)` 規避（`android-shell/README.md`）。
- **autofill 服務開著時 app 自我干擾**：本 app 欄位 focus 會彈自家面板並搶
  焦點，`input text`／按鈕點擊送不到（實測 logcat 無第二次 Auth.Success）。
  A11 先關服務打字、再開服務驗真候選。

## P4b 第三批（2026-11-08）：vault 寫入 UI（新增／編輯／刪除）＋一個既有狀態機缺陷

- **寫入路徑接法**：UI 寫入走 in-process `Hub::create/patch/delete`，語意與
  daemon P2 同源（鏡像＋outbox 同交易、同 item FIFO、base_rev CAS＋欄位級
  三方合併，全部沿用 `bw_store`／`bw_vault` 原語，零新抽象）。本批 drain
  只在「重新同步」與登入 pull 前觸發（背景同步未接，自動 push 反而讓
  「待推送」斷言變成競態）；pull 前先推、outbox 未結算時跳過全量重建，
  「待推送」列不會被鏡像重建吞掉。org 共享項目寫入直接拒絕（本批無 akey
  解封路徑，絕不產生解不開的密文）。
- **既有缺陷：「重新同步」成功後永卡 Busy**。handler 先 `phase.set(Busy)`
  蓋掉快照，完成時再 `if let Phase::Vault(s) = phase.get()` 永遠不匹配，
  UI 停在登入頁（Busy 分支）不動。A1–A11 從未斷言同步後的列表態所以沒被
  發現；A12 首次踩中（實測：VW 端已收 create、logcat 無錯誤、按鈕標籤停在
  「登入中…」）。修法：完成後由帳號檔重建 Snapshot。教訓：**凡「按下去
  設 Busy、回來改 phase」的按鈕，成功分支不能假設 phase 還是原樣**。
- **模態表單自動化**：編輯模態四欄以 placeholder 文字定位（與登入頁
  「me@example.com」同法）；改欄位現值用 MOVE_END＋30×DEL 再打新值。
  欄位間切換**必隱鍵盤**（`input keyevent 111`）：模態總高度超過 IME 抬昇
  後的可視區時，下一欄的 tap 落在鍵盤上，文字接進前一欄（A12 首輪實錄：
  uri 字串接到密碼欄變成 `e2epasshttps://…`，VW reveal 斷言當場抓到）。

## P4b 第四批（2026-11-10）：手機皮（ui.rs 重寫）＋autofill save 真寫入（A15–A17）

### 新皮結構（tokens 落地形態）

- 列表頁：頂部列 56（標題＋計數＋帳號列＋「重新同步／鎖定」）→ 搜尋框 44 →
  資料夾 chip 列（全部／未歸屬／各夾，`Query.folder` 三態口徑）→ 44px 虛擬列表
  → 右下 FAB（56、accent、extended「＋新增」）。詳情與表單都是 `nav_stack`
  push 頁（編輯模態退役：全頁表單才有空間露出多網址／自訂欄／備註等支援面）。
- 詳情頁：44 大磚＋大名稱＋收藏星（真寫入 `favorite` leaf）→ 分節值塊
  （帳號／密碼→驗證碼→網址→自訂欄→備註→其他資訊）。TOTP **自動碼**：
  進頁即 `Hub::totp_code`（無 seed＝`Ok(None)` 合法態、整節靜默收合），
  `set_interval` 1s 心跳驅動倒數條（≤5s 轉 warning），視窗歸零 effect 自動重取。
- 表單差量紀律同 macOS：網址列 key＝基準索引、新列隨機號；三批送
  （既有列 leaf 批 → 結構批（刪列降序→附加）→ 新列 match 尾批走第二次
  patch）。自訂欄按 key 對齊基準索引（中段刪列不動旁列）。單測 6 條罩住
  （`uri_edits`／`field_edits`／boolean 正規化／六態表／totp 純函數）。

### favicon 快取放 UI 訊號，不放 Hub Mutex

前一手在 Hub 掛 `Mutex<HashMap>` 供渲染期查閱——斷流丟失，重寫時改判：
渲染訂閱與結算回寫必須走同一條反應鏈，所以快取是 `Icons`（App 根
`Signal<Arc<HashMap<..>>>`，同 macOS `state::icons`）；Hub 只留
`icon_data_uri`（單飛閘＋磁碟快取，已提交面）。列表頁 `effect` 訂閱
filtered 換算、對缺態 host 標 Loading＋spawn；字母磚是永久退路。

### autofill save 鏈（onFillRequest→SaveInfo→onSaveRequest→Hub）

- 判準：帳號欄現值非空且等於某候選帳號＝已儲存；否則（含空欄）掛
  `SaveInfo(USERNAME|PASSWORD, [userField, passField])`＋描述「儲存到 Bitward」。
  鎖態走既有 lockedResponse（無 SaveInfo＝框架不會發存檔請求）。
- `onSaveRequest` 從 `request.fillContexts` 末個結構取帳密現值＋查詢鍵
  （webDomain 優先、原生退 package）→ `nshSave` JNI（第五支符號，回
  `[id, action]`，明文不落 log）→ `Hub::save_from_autofill`（冪等：同組合
  unchanged 零寫入；同帳號新密碼＝patch 只動 password 欄）。本地交易進
  outbox＝列表「待推送」，drain 照「重新同步／登入 pull 前」收斂。
- **stub jar 實錄（第二批坑清單延續）**：`AssistStructure$ViewNode` 的取值面是
  `getAutofillValue()`（不是文檔常見的 `getValue()`），`AutofillValue` 無
  `isNull()`——判文字用 `isText()`。本地 android-35 stub jar 與真 API 36 jar
  皆如此（javap 實查）。
- **e2e 探針頁**（`AutofillProbeActivity`）：系統只在提交時發 onSaveRequest，
  真 app 提交時機各家不同 → 探針頁＝hint 帳密欄＋`AutofillManager.commit()`
  鈕（文件化「收集完畢」訊號）。欄位間距 260/140dp：autofill 面板錨在 focus
  欄下方，緊貼的下一欄／鈕會被蓋住，tap 誤命中候選列（設計期避開，未踩坑）。

### 首輪實錄：頂部列把「鎖定」推出屏（A7 FAIL→修）

Pixel 10 Pro XL（1440px 寬）實測：email·server 列（43 字元）把頂部列左欄撐到
x=1188，「重新同步」文字截斷、「鎖定」整個出屏，uiautomator 層級查無節點。
修法＝左欄 `flex_1().min_w(0)`、帳號列 `flex_1()`＋ellipsize、計數與按鈕群
`flex_shrink_0`。教訓：**單欄手機皮裡任何「文字＋按鈕同列」的列，文字側必須
帶收斂約束，否則長帳號（email·https://host）直接擠掉動作鈕**。

### 缺角清單（daemon 面 vs Android in-process 中樞；交回 Main，不改 crates/bins）

對照 `crates/bw-proto` 的 Call 列舉與 `apps/bitward-android/src/hub.rs` 現面
（Login/List/Get/Create/Patch/Delete/ListFolders/GetIcon/TotpCode/Sync/存檔已覆盖；
垃圾桶與封存**排除**由共用 `Store::query` 預設免费得）。缺：

| daemon 面 | Android 缺什麼 | 影響 |
|---|---|---|
| `Vault:Restore`／`Vault:Purge` | 軟刪復原、永久刪除（Hub 語意在 daemon） | 刪除後只能等伺服器端收斂，無垃圾桶視角 |
| `Vault:SetArchived` | 封存／解封存寫入 | 列表已隱封存項，但 app 內無法操作 |
| `Vault:Overlay`（AddTag/RemoveTag） | 標籤寫入 | 表單標籤欄 disabled＋註記；詳情唯讀顯示 |
| `Vault:CreateFolder`／`DeleteFolder` | 資料夾管理 | chip 列／表單只選既有夾 |
| `Vault:MoveToOrg`＋akey 解封 | org 共享項目寫入 | `patch` 直接拒絕共享項（不產生壞密文） |
| `Vault:Import`／`Vault:Send` | 匯入、Send 面 | app 無入口 |
| `Vault:Attachment` | 附件上傳／下載／刪除 | 詳情無附件節 |
| `Vault:FindDuplicates`／`Merge` | 查重與合併 | — |
| `Passkey:*` 全面 | GetPasskeys/DeletePasskey/Register/Assert；CredentialProviderService 只骨架 | 詳情無 passkey 節；孤島 passkey 未接線 |
| `Use:GeneratePassword` | 密碼產生器 | 表單無產生器面板（macOS 有） |
| `Sync:ListConflicts`／`ResolveConflict` | 衝突收件匣 | outbox 衝突進 bw-store 表，app 無 UI 入口 |
| `Admin:GetSettings`／`SetSettings` | 本機設定面（自動鎖定／剪貼簿清除／重啟鎖定／鎖定清搜尋） | app 無設定頁；複製鈕無定時清除；**無自動鎖定**（金鑰長駐記憶體至手動「鎖定」） |
| `Auth:ChangePassword` | 改主密碼 | — |
| `Auth:Unlock`（封存金鑰重入） | 冷啟免主密碼解鎖 | 見已知的下一步 1 |
| `Push:*` | UnifiedPush 註冊 | 背景同步未接（同第三批） |
| `Vault:Reports` | 密碼健康度 | R4 進行中，落地後需同步評估接面 |

### A16 實錄二：探針頁被 edge-to-edge 埋進狀態欄（FAIL→修）

r1/r2 兩輪 A16 同點掛：探針頁渲染成功、`tap_text` 也點了出去，但
`onFillRequest` 完全沒進孤島。實測根因＝**targetSdk 35 的 edge-to-edge 強制**：
探針 activity 沒吃 insets，第一欄 bounds 落在 [48,48]（狀態欄底下），tap 打在
系統欄上，EditText 永遠 `focused=false`、IME 不起、fill 請求自然不发
（nsh AppActivity 沒事是因為它自己處理 safe-area）。修＝`fitsSystemWindows=true`。
教訓：**外殼新增原生頁要嘛吃 insets、要嘛別把可交互欄位排在屏頂 90px 內**；
uiautomator 節點存在≠可點中，focus 斷言要看 `focused="true"` 而不是只認節點。

### A16 實錄三：存檔提示是 zh 語系（「保存」鈕，描述列不可點）

insets 修好後 fill→commit 全通，但 `onSaveRequest` 仍不來：emulator 語系為
zh，系統存檔提示實錄節點＝標題「要将密码和用户名保存到bitward吗？」＋
自訂描述列「儲存到 Bitward」（**純文字，點了沒反應**）＋「不用了」＋
「保存」（真鈕）。腳本原本認英文「Save」落空。教訓：**框架彈窗文案按語系
變，自動化要嘛固定 emulator 語系、要嘛按钮角色（非描述列）定位**；本腳本
改認「保存」優先、英文「Save」退路。修後實測鏈：`probe commit requested →
onSaveRequest → jni: save q=io.bitward.android action=created → save ok`。
