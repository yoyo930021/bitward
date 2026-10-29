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
