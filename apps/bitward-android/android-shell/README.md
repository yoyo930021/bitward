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
| `app/src/main/AndroidManifest.xml` | 孤島三 service＋复刻 nsh 的 application/activity 節（application 加 `android:name=".BitwardApplication"`） |
| `app/src/main/kotlin/io/bitward/android/BitwardApplication.kt` | 進程最早期把 `BITWARD_ANDROID_DATA` 指向 `noBackupFilesDir/bitward`（鏡像目錄缺陷修） |
| `app/src/main/kotlin/io/bitward/android/BitwardAutofillService.kt` | 填充服務＋`HubBridge` 程序內介面（unlocked/candidates/reveal/save）＋`HubHolder.ensureBridge()` |
| `app/src/main/kotlin/io/bitward/android/NativeHub.kt` | Rust 中樞的 JNI 面（`src/jni.rs` 五支符號：ready/unlocked/candidates/reveal/save）＋`HubBridge` 的 in-process 實作 |
| `app/src/main/kotlin/io/bitward/android/AutofillProbeActivity.kt` | e2e A16 探針頁：hint 帳密欄＋`AutofillManager.commit()`（確定性觸發存檔流；零業務語意） |
| `app/src/main/kotlin/io/bitward/android/BitwardCredentialProviderService.kt` | API 34 `android.service.credentials.CredentialProviderService` 轉接（骨架，bridge 已預留） |
| `app/src/main/kotlin/io/bitward/android/BitwardKeyStore.kt` | Keystore Class 3（AES wrap 金鑰＋EC 探針，StrongBox 降級路） |
| `app/src/main/kotlin/io/bitward/android/HubService.kt` | foreground service 保命（`startForeground` 尚未接，見下） |
| `app/src/main/res/` | app_name、「尚未解鎖」列與真候選列版面（`autofill_locked.xml`／`autofill_dataset.xml`） |
| `build.sh` | 上面整條組裝鏈 |

本地 `android-35` stub jar 沒打包 `android.view.ViewHints`、
`android.service.autofill.Presentation` 與 `addDataset(AutofillId, Dataset)`
（缺件見實測編譯錯誤）：hint 字串寫成常數、候選列呈現改掛在 username 的
`setValue(field, value, presentation)` 第三參上，語意不變。

## 孤島↔in-process 中樞的銜接（2026-11-07 第二批：1–3 已落地）

孤島與 `libnsh.so` **同程序**（service 不宣告 `android:process`）。落地形態：

1. bridge 裝載是**惰性**的：孤島第一次被系統叫醒（fill/save 請求）時
   `HubHolder.ensureBridge()` 探 `NativeHub`——UI 已起（libnsh.so 在記憶體）
   或 service 冷啟（`System.loadLibrary("nsh")` 拉同一顆 .so，Rust 側 `HUB`
   的 LazyLock 直接開 Store）。不需要 AppActivity 主動回呼。
2. 金鑰只走 Rust 側：本批 user key 從不過橋（Keystore 封存在下一批）；
   過橋的只有 metadata 級候選與填充用明文欄位（Dataset 必需形态）。
3. 純 service 拉起（沒有 UI）時開 Store 的前提＝資料目錄：由
   `BitwardApplication` 把 `BITWARD_ANDROID_DATA` 指到
   `noBackupFilesDir/bitward`（鏡像目錄缺陷修：cache 可被系統清、filesDir
   會進 Auto Backup 把明文索引欄帶出裝置，noBackup 兩者皆免）。
   但本批**未解鎖的冷啟 service 仍回鎖定態**——金鑰只活在已登入的 UI
   進程記憶體，這是 Keystore 批之前刻意保留的邊界。
4. 背景同步/UnifiedPush 走 `HubService.startForeground`（尚未接，含通知權限）。
5. save 真寫入（2026-11-10 第四批）：未儲存組合的 fill 回應掛 `SaveInfo`
   （USERNAME|PASSWORD，帳號欄現值對上候選＝已儲存不掛）；onSaveRequest 從
   fillContexts 結構取帳密與查詢鍵（webDomain 優先、原生退 package）過
   `nshSave` → `Hub::save_from_autofill`（同帳號改密＝patch 密碼欄；查無＝
   create；同組合＝unchanged 零寫入）。鎖態 save 回失敗不假裝存（驗收 A16）。

解鎖引導：鎖定態面板列「Bitward：尚未解鎖」，點它拉開 app 走登入；
解鎖後的下一次 fill 請求就是真候選列（驗收 A11 走的就是這條路）。

## 接上去的紀律（別在 Kotlin 端破）

1. **金鑰不進 Kotlin**：user key 留在 Rust 的 `UnlockMachine`／`Hub.unlocked`
   （契約 §2.7 規則 1 的 `byte[]` 限制指的是金鑰；填充用的 username/password
   明文是 Dataset 的必需形態，只活在單次 fill 回應的生命週期，不快取）。
2. **孤島不做比對**：`candidatesFor` 只拿 metadata 級候選；分級、去重、
   衝突語意全在 Rust（`bw-vault`/`bw-store`）。
3. **中樞不在就快速失敗**：`HubHolder.bridge == null` 時回空回應／錯誤，
   不自己降格持鑰（契約 §1.2）。
