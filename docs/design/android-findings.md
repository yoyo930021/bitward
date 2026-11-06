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
（與下面的 Gradle 缺口一起做）。

### 假設 8：Kotlin 孤島能進 nsh 產的 APK — 不通（需要 Gradle 外殼）

`nsh package --help` 的 Android 旗標只有 `--name/--id/--app-version/--build/--icon/
--keystore/--key-alias/--keystore-password/--run`；APK 的 dex 一律取自
`~/.nsh/runtime/android/{dev,release}/classes.dex`，**沒有** app 自帶 Kotlin/Java
來源、資源或 manifest 的掛鉤（`nsh.json` 也無對應欄位）。所以 `AutofillService`、
`CredentialProviderService`、Keystore、foreground service 這幾個孤島，在 0.3.0 的
管線下進不了 APK；本輪把孤島寫成佔位（簽名與分層真實、方法體留白）放在
`apps/bitward-android/android/`，並在那邊 README 記錄缺口。下一批的形：
一個 Gradle app module 吃 nsh 的 `classes.dex` + `lib/<ABI>/libnsh.so`，
或由 nsh 提供 app 自帶 Android 來源的支援。

### adb 驅動陷阱（背景驗收必讀）

軟鍵盤開著時，第一個 `adb shell input type tap` 常被系統用來收 IME
（logcat 出現 `ImeTracker: ... HIDE_SOFT_INPUT fromUser true`），**送不到 app 的
`on_press`**；表單自動化要在按按鈕前先 `input keyevent 111`（ESCAPE，比 KEYCODE_BACK
安全——back 在單頁棧上會直接退出 app）。另外 `adb shell ...` 會吃 stdin，腳本裡
要加 `</dev/null`，否則迴圈的讀取會被它攔走。

### 對 P4b 排程的更新

- 導航：Android 可押原生 `nav_stack`（本輪已押，返回鍵＋`on_dismiss` 實測可用）。
- 打包：in-process 核心零風險；**唯一**必要設定是純 cargo 路徑的 `CC_*`/`AR_*` 兩行。
- 缺口兩項，都要在第二批前拍板：(1) 純 Rust app 的 data dir API（否則鏡像放 cache）；
  (2) Kotlin 孤島進 APK 的管道（Gradle 外殼 vs 上游支援）。
- 驗收入口：`dev/e2e/android-app.sh`（A1..A7：三 ABI APK、啟動到登入畫面、真實 UI
  登入＋sync、搜尋、詳情遮罩→Reveal、返回清明文、鎖定＋預填），截圖留
  `apps/bitward-android/shots/`。
