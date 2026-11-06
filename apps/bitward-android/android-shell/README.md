# android-shell：Kotlin 孤島的 Gradle 外殼（路線 A）

契約 §0.1 的 Android 列有四個「整合孤島」：`AutofillService`、
`androidx.credentials`（API 34）、Keystore、UnifiedPush。nsh 0.3.0 的
`nsh package` 沒有 app 自帶 dex/資源/manifest 的掛鉤（實測記錄在
`docs/design/android-findings.md` 假設 8），所以孤島由這個 Gradle 外殼承載，
再把 nsh 產物併回來。**孤島現在真的在 APK 裡，系統會 bind、會送 fill 請求**
（驗收 A8–A10 在 `dev/e2e/android-app.sh`）。

## 組裝流程（`build.sh`，可重來）

```
nsh package --target android        # .nsh/out/bitward.apk（三 ABI libnsh.so＋runtime dex＋assets）
        │  解出 lib/、assets/、classes.dex → build/nsh-stage/
        ▼
gradle --offline assembleDebug      # 孤島 Kotlin＋資源＋manifest＋jniLibs＋assets
        │  app/build/outputs/apk/debug/app-debug.apk
        ▼
追加 runtime classes.dex 為 classesN.dex → zipalign → apksigner（debug 鑰）
        │
        ▼
.nsh/out/bitward-islands.apk        # 最終包；簽章與 nsh 產物同鑰（install -r 互換）
```

```sh
cd apps/bitward-android && android-shell/build.sh
```

- 外殼只依賴本機 Gradle（8.14）＋快取的 AGP 8.13.1/Kotlin 2.2.21，離線可建；
  快取缺件時 `build.sh` 自動退回線上解析。
- `~/.android/debug.keystore` 就是 `nsh package` 用的鑰（憑證 SHA-256
  `90AE7F…` 比對過），所以合併包與純 nsh 包在同一台 emulator 上可互換重裝。
- dex 併入用「追加 classesN.dex」而非 d8 重編：ART 對 minSdk≥21 原生支援多
  dex，順序不影響正確性；兩套碼（`com.longbridge.nsh.*` runtime 與
  `io.bitward.android.*` 孤島）零符號重疊。

## manifest 的兩個實測坑（Android 16 emulator）

1. **autofill 服務的 settings key 換了**：`current_autofill_service` 在此
   image 上寫了沒人聽（observer 不觸發、dumpsys 不動）；真正生效的是
   `Settings.Secure` 的 **`autofill_service`**（dumpsys autofill 自己報
   `prop=autofill_service`）。驗收腳本兩個 key 都寫，未來真機也兼容。
2. **`Dataset` 沒綁任何欄位就 `build()` 會丟** `IllegalStateException`
   （「at least one of field or datatype must be set」）。鎖定態的正統形態是
   response 級 `FillResponse.Builder.setAuthentication(focusedId, intentSender,
   RemoteViews)`，面板就會列出「Bitward：尚未解鎖」列，點它拉開 app。
   `PendingIntent.intentSender` 要 API 31+，28–30 回空回應。

另外 Keystore Class 3（`setUserAuthenticationRequired(true)`）生成金鑰要求
裝置有**安全鎖屏**，emulator 要先 `locksettings set-pin`（驗收腳本已做）。

## 檔位

| 檔 | 角色 |
|---|---|
| `app/src/main/AndroidManifest.xml` | 孤島三 service＋复刻 nsh 的 application/activity 節 |
| `app/src/main/kotlin/io/bitward/android/BitwardAutofillService.kt` | 填充服務＋`HubBridge` 程序內介面（3 個动作）＋`HubHolder` |
| `app/src/main/kotlin/io/bitward/android/BitwardCredentialProviderService.kt` | API 34 `android.service.credentials.CredentialProviderService` 轉接 |
| `app/src/main/kotlin/io/bitward/android/BitwardKeyStore.kt` | Keystore Class 3（AES wrap 金鑰＋EC 探針，StrongBox 降級路） |
| `app/src/main/kotlin/io/bitward/android/HubService.kt` | foreground service 保命＋註冊 `HubHolder.bridge`（第二批接） |
| `app/src/main/res/` | app_name、「尚未解鎖」列版面 |
| `build.sh` | 上面整條組裝鏈 |

## 孤島↔in-process 中樞的銜接（本批到此、第二批照做）

孤島與 `libnsh.so` **同程序**（service 不宣告 `android:process`）：系統因
autofill 拉起進程時只跑 Kotlin（`HubHolder.bridge == null` → 快速失敗）；
UI 起來後 `libnsh.so` 才載入。銜接方案：

1. `AppActivity` 的 Rust 中樞就緒時經 JNI 回呼 Java 側，把實作放進
   `HubHolder.bridge`（實作直接在 JNI 橋封 `Hub` 的候選/解封/save）；
2. 金鑰只走 `byte[]`（契約 §2.7 規則 1），Kotlin 端不快取、不落地；
3. 純 service 拉起（沒有 UI）時要開 Store：bw-store 是純 Rust SQLite，可在
   service 執行緒直接 `nsh` 之外的第二入口載 `libnsh.so` 開 `vault.db`——
   但**鏡像目錄**得先解決假設 7 的 data dir 缺口（外殼把 `filesDir` 傳進去）；
4. 背景同步/UnifiedPush 走 `HubService.startForeground`（第二批，含通知權限）。

## 接上去的紀律（別在 Kotlin 端破）

1. **金鑰不進 Kotlin String**：`unwrap` 回 `byte[]`，立刻交回 Rust 側的
   `UnlockMachine`；Kotlin 端不快取（契約 §2.7 規則 1）。
2. **孤島不做比對**：`candidatesFor` 只拿 metadata 級候選；分級、去重、
   衝突語意全在 Rust（`bw-vault`/`bw-store`）。
3. **中樞不在就快速失敗**：`HubHolder.bridge == null` 時回空回應／錯誤，
   不自己降格持鑰（契約 §1.2）。
