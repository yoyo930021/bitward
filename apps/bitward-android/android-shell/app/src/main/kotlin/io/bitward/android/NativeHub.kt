package io.bitward.android

import android.util.Log

/**
 * in-process Rust 中樞的 JNI 面（實作：`apps/bitward-android/src/jni.rs`，
 * 符號 `Java_io_bitward_android_NativeHub_*`，隨 `libnsh.so` 載入）。
 *
 * 同程序前提：孤島 service 不宣告 `android:process`，UI 起來時 libnsh.so
 * 已在記憶體（nsh 自己 load 的同一份，classloader 相同）；service 冷啟
 * （沒有 UI）時由這裡 `loadLibrary` 拉同一顆 .so，`HUB` 的 LazyLock 直接
 * 開 `vault.db`（bw-store 是純 Rust SQLite，不需要 nsh runtime 起來）。
 * 資料目錄由 [BitwardApplication] 在進程最早期塞進環境變數。
 *
 * 紀律（本檔所屬 README「接上去的紀律」）：這裡只做符號透傳，零業務語意；
 * user key 不過橋；中樞開不起來＝快速失敗（回 null／空，不自行降格持鑰）。
 */
object NativeHub {

    @Volatile
    private var probed = false

    @Volatile
    private var available = false

    /** 載入 libnsh.so 並確認中樞 Store 開得起來；冪等，失敗不重試到煩（每次 fill 問一次可接受）。 */
    @Synchronized
    fun available(): Boolean {
        if (!probed) {
            runCatching { System.loadLibrary("nsh") }
                .onFailure { Log.w(ISLAND_TAG, "load libnsh.so failed: ${it.javaClass.simpleName}: ${it.message}") }
            available = runCatching { nshIsReady() }.getOrDefault(false)
            probed = true
            Log.i(ISLAND_TAG, "native hub available=$available")
        }
        return available
    }

    @JvmStatic
    private external fun nshIsReady(): Boolean

    @JvmStatic
    external fun nshIsUnlocked(): Boolean

    /** 回 `[id, label, ...]` 扁平陣列；null＝橋內錯（視同空）。 */
    @JvmStatic
    external fun nshCandidates(query: String): Array<String>?

    /** 回 `[username, password]`；null＝找不到或未解鎖。 */
    @JvmStatic
    external fun nshReveal(itemId: String): Array<String>?
}

/**
 * [BitwardAutofillService.HubBridge] 的 in-process JNI 實作。
 *
 * 明文欄位（username/password）以 Kotlin String 過橋是 Dataset 組裝的必需
 * 形態，用完即隨 FillResponse 生命週期丟棄；真正的金鑰（user key）從頭到尾
 * 留在 Rust 側（契約 §2.7 規則 1）。
 */
class NativeHubBridge : BitwardAutofillService.HubBridge {

    override fun unlocked(): Boolean = NativeHub.nshIsUnlocked()

    override fun candidatesFor(query: String): List<BitwardAutofillService.FillCandidate> =
        NativeHub.nshCandidates(query)?.toList()?.chunked(2)?.mapNotNull { pair ->
            if (pair.size == 2) BitwardAutofillService.FillCandidate(pair[0], pair[1]) else null
        } ?: emptyList()

    override fun revealFor(itemId: String): BitwardAutofillService.SecretBundle {
        val v = NativeHub.nshReveal(itemId) ?: error("中樞取不到 $itemId")
        return BitwardAutofillService.SecretBundle(
            v.getOrElse(0) { "" },
            v.getOrElse(1) { "" },
        )
    }

    override fun save(itemId: String?, username: String, password: String) {
        // 寫入路徑（outbox＋衝突收斂）是 P4b 下一批；這裡不假裝存了。
        Log.i(ISLAND_TAG, "bridge save 尚未接寫入路徑（下一批）")
    }
}
