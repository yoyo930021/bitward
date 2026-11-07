package io.bitward.android

import android.app.Application
import android.system.Os
import java.io.File

/**
 * 進程外殼：在**任何進程入口**（AppActivity 的 Rust 中樞、service 冷啟的
 * JNI 橋）之前把 `BITWARD_ANDROID_DATA` 指向 `noBackupFilesDir/bitward`。
 *
 * 為什麼是 noBackupFilesDir（2026-11-07 缺陷修，見 docs/design/android-findings.md
 * 假設 7）：
 * - 舊退路 `TMPDIR`（cacheDir）：系統可在空間壓力時清掉，帳號檔跟著沒。
 * - filesDir：預設進 Auto Backup，而 `vault.db` 帶明文索引欄
 *   （name/uris/username/password，契約 §2.7 R3 只以「0600 不離裝置」承受），
 *   備份出裝置＝明文外洩。
 * - noBackupFilesDir：不被自動清、不進備份。鏡像本身是伺服器資料的快取，
 *   真丟了重 sync 即癒，只是慢。
 *
 * Rust 側讀法見 `src/hub.rs::data_dir()`（env 覆寫 → TMPDIR 退路）。
 */
class BitwardApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Os.setenv("BITWARD_ANDROID_DATA", File(getNoBackupFilesDir(), "bitward").absolutePath, true)
    }
}
