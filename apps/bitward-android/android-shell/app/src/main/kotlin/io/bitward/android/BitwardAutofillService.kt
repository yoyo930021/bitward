package io.bitward.android

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.widget.RemoteViews

/** 孤島共同 log tag：驗收 A9/A10 靠它在 logcat 裡認出我們。 */
internal const val ISLAND_TAG = "bitward-island"

/**
 * 填充孤島（契約 §0.1 Android 列、§1「Android app＝Full（in-process 中樞）」）。
 *
 * 已進 APK（`android-shell/`，2026-11-07 起）：把 autofill 服務設為本服務
 * （Android 15+：`settings put secure autofill_service`；舊 image 為
 * `current_autofill_service`）後，系統 bind 到我們（onCreate/onFillRequest
 * 的 logcat 標記＝驗收 A9）。
 *
 * 分層紀律（契約 §2 不變量 5：孤島零業務語意）：比對、分級、去重都在
 * Rust 端（bw-vault/bw-store）；這裡只把欄位結構交出去、把回來的東西包成
 * Dataset。中樞與本服務同程序（`HubService`），走程序內介面，不經 BTP。
 */
class BitwardAutofillService : AutofillService() {

    /** 中樞的孤島視角：三個动作，回傳值只在當次呼叫的存活期內是明文。 */
    interface HubBridge {
        /** 依欄位結構問候選：只回 id 與顯示標籤（metadata 級，不含秘密）。 */
        fun candidatesFor(activity: String): List<FillCandidate>

        /** 取用一筆：填充用的明文（填完即歸零，不進 Kotlin String 常駐快取）。 */
        fun revealFor(itemId: String): SecretBundle

        /** 儲存新密碼：進 outbox（離線也可記，收斂靠伺服器）。 */
        fun save(itemId: String?, username: String, password: String)
    }

    data class FillCandidate(val id: String, val label: String)
    data class SecretBundle(val username: String, val password: String)

    override fun onCreate() {
        super.onCreate()
        // A9 的綁定標記：系統把本服務 bind 起來時必然經過這裡。
        Log.i(ISLAND_TAG, "autofill service bound by system")
        // Class 3 Keystore 探針（A10）：冪等；第一次綁定時生成 EC 金鑰並回顯 alias。
        runCatching { BitwardKeyStore().ensureClass3ProbeKey() }
            .onSuccess { Log.i(ISLAND_TAG, it) }
            .onFailure { Log.w(ISLAND_TAG, "keystore probe failed: ${it.message}") }
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val unlocked = HubHolder.bridge != null
        Log.i(ISLAND_TAG, "onFillRequest unlocked=$unlocked")
        if (!unlocked) {
            // 中樞不在（未登入或程序被回收）：回「尚未解鎖」列，不自行降格持鑰（契約 §1.2）。
            callback.onSuccess(lockedResponse(request))
            return
        }
        // TODO(P4b 第二批): 由 request.fillContexts 取 assured structure，
        // 經 bridge 拿候選，再用 Dataset.Builder 綁 username/password 欄位 id。
        callback.onSuccess(lockedResponse(request))
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Log.i(ISLAND_TAG, "onSaveRequest")
        val bridge = HubHolder.bridge
        if (bridge == null) {
            callback.onFailure("Bitward 本機中樞尚未啟動")
            return
        }
        // TODO(P4b 第二批): 從 request.fillContexts 的 fillable values 取值後 save()。
        callback.onSuccess()
    }

    /**
     * 鎖定態回應：response 級 setAuthentication 列「尚未解鎖」，點它開 app 解鎖
     * （Dataset 沒欄位值會被 `build()` 擋：「at least one of field or datatype
     * must be set」，實測 Android 16；response 級 auth 列才是解鎖流的正統形態）。
     * `PendingIntent.intentSender` 是 API 31 才有的面；28–30 回空回應
     * （佔位期無功能差，真正解鎖流是 P4b 第二批）。
     */
    private fun lockedResponse(request: FillRequest): FillResponse {
        val response = FillResponse.Builder()
        val focused = Build.VERSION.SDK_INT >= 31 && request.fillContexts.isNotEmpty() &&
            request.fillContexts.last().focusedId != null
        if (focused) {
            val openApp = Intent("android.intent.action.MAIN").apply {
                setClassName(packageName, "com.longbridge.nsh.AppActivity")
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
            val pi = PendingIntent.getActivity(
                this, 0, openApp,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            response.setAuthentication(
                arrayOf(request.fillContexts.last().focusedId),
                pi.intentSender,
                RemoteViews(packageName, R.layout.autofill_locked),
            )
        }
        return response.build()
    }
}

/** 同程序中樞的句柄：Rust 側（`libnsh.so`）起來時經 JNI 放進實作。 */
object HubHolder {
    @Volatile
    var bridge: BitwardAutofillService.HubBridge? = null
}
