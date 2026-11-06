# Kotlin 孤島（骨架，尚未編進 APK）

契約 §0.1 的 Android 列寫的是「NSH UI（Android views 後端）+ Kotlin 整合孤島：
`AutofillService`、`androidx.credentials`（API 34）、Keystore、UnifiedPush」。
這個目錄是那四個孤島的**佔位**：簽名與分層寫實，方法體刻意留白。

## 為什麼只是佔位（實測）

`nsh` 0.3.0 的 Android 打包鏈是「prebuilt runtime + app 的 `libnsh.so`」：

```
$ nsh package --target android
✓ built libnsh.so ... armeabi-v7a / arm64-v8a / x86_64
✓ packaged .nsh/out/bitward android.apk
```

產物內容是 `classes.dex`（來自 `~/.nsh/runtime/android/{dev,release}/classes.dex`）
加 `lib/<3 ABI>/libnsh.so`，簽章用 debug key，全程免 Gradle。但 `nsh package --help`
的旗標只有 `--name/--id/--app-version/--build/--icon/--keystore/...`，
**沒有**讓 app 帶自己的 Kotlin/Java 來源、資源或 manifest 的掛鉤；
`nsh.json` 也沒有對應欄位。所以：

- 這批（P4b 第一批）驗收的是 NSH Rust app 本體：APK 出得來、裝得上、
  跑到登入畫面、in-process 核心真的完成 prelogin→派生→登入→sync→鏡像落地。
- 孤島要真的進 APK，下一批需要一個 Gradle 外殼模組（app module 把 nsh 的
  dex 與 `libnsh.so` 當成依賴，並 merge 這裡的 manifest），或上游支援
  app 自帶 Android 來源。這是**工具鏈缺口**，不是這裡的程式碼沒寫。

## 檔位

| 檔 | 角色 | 契約依據 |
|---|---|---|
| `src/main/AndroidManifest.snippet.xml` | 三個 service 宣告（autofill、credential provider、foreground hub） | §1 進程拓撲表 Android 列 |
| `src/main/kotlin/io/bitward/android/BitwardAutofillService.kt` | 填充服務 + `HubBridge` 程序內介面（3 個动作） | §2 不變量 5（孤島零業務語意） |
| `src/main/kotlin/io/bitward/android/BitwardCredentialProviderService.kt` | API 34 `androidx.credentials` 轉接 | §0.1 Android 列 |
| `src/main/kotlin/io/bitward/android/BitwardKeyStore.kt` | Keystore Class 3 / StrongBox 封裝 user key | §1 落盤形態、§2.2 |
| `src/main/kotlin/io/bitward/android/HubService.kt` | foreground service 保命 + 註冊 `HubHolder.bridge` | §1（Android 的 in-process 中樞） |

## 接上去時的紀律（別在 Kotlin 端破）

1. **金鑰不進 Kotlin String**：`unwrap` 回 `byte[]`，立刻交回 Rust 側的
   `UnlockMachine`；Kotlin 端不快取（契約 §2.7 規則 1）。
2. **孤島不做比對**：`candidatesFor` 只拿 metadata 級候選；分級、去重、
   衝突語意全在 Rust（`bw-vault`/`bw-store`）。
3. **中樞不在就快速失敗**：`HubHolder.bridge == null` 時回空回應，
   不自己降格持鑰（契約 §1.2）。
