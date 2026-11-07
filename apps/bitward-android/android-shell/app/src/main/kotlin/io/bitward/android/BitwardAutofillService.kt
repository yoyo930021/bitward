package io.bitward.android

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

/** 孤島共同 log tag：驗收 A9/A10/A11 靠它在 logcat 裡認出我們。 */
internal const val ISLAND_TAG = "bitward-island"

/**
 * 填充孤島（契約 §0.1 Android 列、§1「Android app＝Full（in-process 中樞）」）。
 *
 * 已進 APK（`android-shell/`，2026-11-07 起）：把 autofill 服務設為本服務
 * （Android 15+：`settings put secure autofill_service`；舊 image 為
 * `current_autofill_service`）後，系統 bind 到我們（onCreate/onFillRequest
 * 的 logcat 標記＝驗收 A9）。解鎖態走真候選（`HubHolder.ensureBridge()`＋
 * `NativeHub` JNI 面，驗收 A11）；鎖定態列「尚未解鎖」，點它拉開 app 解鎖。
 *
 * 分層紀律（契約 §2 不變量 5：孤島零業務語意）：比對、分級、去重都在
 * Rust 端（bw-vault/bw-store）；這裡只把欄位結構交出去、把回來的東西包成
 * Dataset。中樞與本服務同程序（`HubService`），走程序內介面，不經 BTP。
 */
class BitwardAutofillService : AutofillService() {

    private companion object {
        // `android.view.ViewHints` 的字面值（API 26 起；本機 android-35 stub jar
        // 沒打包該類，依規格寫死常數，值與框架定義一致）。
        const val HINT_USERNAME = "username"
        const val HINT_EMAIL = "emailAddress"
        const val HINT_WEB_USERNAME = "webUsername"
        const val HINT_PASSWORD = "password"
        const val HINT_WEB_PASSWORD = "webPassword"
    }

    /** 中樞的孤島視角：查詢與取用，回傳值只在當次呼叫的存活期內是明文。 */
    interface HubBridge {
        /** 中樞目前是否解鎖（金鑰在 Rust 記憶體裡）。 */
        fun unlocked(): Boolean

        /** 依 web host 或 app package 問候選：只回 id 與顯示標籤（metadata 級，不含秘密）。 */
        fun candidatesFor(query: String): List<FillCandidate>

        /** 取用一筆：填充用的明文（填完即歸零，不進 Kotlin String 常駐快取）。 */
        fun revealFor(itemId: String): SecretBundle

        /** 儲存新密碼：進 outbox（離線也可記，收斂靠伺服器）。寫入路徑下一批。 */
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
        val bridge = HubHolder.ensureBridge()
        val unlocked = bridge?.unlocked() == true
        Log.i(ISLAND_TAG, "onFillRequest unlocked=$unlocked")
        if (bridge == null || !unlocked) {
            // 中樞不在（未登入或程序被回收）：回「尚未解鎖」列，不自行降格持鑰（契約 §1.2）。
            callback.onSuccess(lockedResponse(request))
            return
        }
        val targets = analyze(request)
        val candidates = targets.queries
            .asSequence()
            .flatMap { bridge.candidatesFor(it).asSequence() }
            .distinctBy { it.id }
            .take(10)
            .toList()
        // 欄位綁定只靠結構（hint／focused），比對語意在 Rust（android-shell/README 紀律 2）。
        val userField = targets.username ?: targets.focused
        val response = FillResponse.Builder()
        var datasets = 0
        if (userField != null) {
            for (c in candidates) {
                val secret = runCatching { bridge.revealFor(c.id) }.getOrNull() ?: continue
                val row = RemoteViews(packageName, R.layout.autofill_dataset)
                row.setTextViewText(R.id.autofill_row, c.label)
                val dataset = Dataset.Builder()
                    .setValue(userField, AutofillValue.forText(secret.username), row)
                if (targets.password != null && secret.password.isNotEmpty()) {
                    dataset.setValue(targets.password, AutofillValue.forText(secret.password))
                }
                response.addDataset(dataset.build())
                datasets++
            }
        }
        Log.i(ISLAND_TAG, "fill response datasets=$datasets queries=${targets.queries.size}")
        callback.onSuccess(response.build())
    }

    /** 最近一次 fill 請求的結構判讀：可綁定的欄位 id 與該問中樞的查詢鍵。 */
    private class FillTargets(
        val focused: AutofillId?,
        val username: AutofillId?,
        val password: AutofillId?,
        val queries: List<String>,
    )

    private fun analyze(request: FillRequest): FillTargets {
        val ctx = request.fillContexts.lastOrNull()
            ?: return FillTargets(null, null, null, emptyList())
        var user: AutofillId? = null
        var pass: AutofillId? = null
        val queries = LinkedHashSet<String>()
        val structure = ctx.structure
        for (w in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(w).rootViewNode) { node ->
                node.autofillHints?.let { hints ->
                    if (user == null && hints.any {
                            it == HINT_USERNAME || it == HINT_EMAIL || it == HINT_WEB_USERNAME
                        }
                    ) {
                        user = node.autofillId
                    }
                    if (pass == null && hints.any { it == HINT_PASSWORD || it == HINT_WEB_PASSWORD }) {
                        pass = node.autofillId
                    }
                }
                // WebView 節點帶 webDomain；原生欄位沒有，改由 package 名兜底。
                node.webDomain?.lowercase()?.let { queries.add(it) }
                // 很多原生 app 不宣告 autofillHints、只設 inputType：密碼欄靠 variation 認。
                if (pass == null && node.autofillId != null && isPasswordInput(node.inputType)) {
                    pass = node.autofillId
                }
            }
        }
        structure.activityComponent?.packageName?.let { queries.add(it) }
        return FillTargets(ctx.focusedId, user, pass, queries.filter { it.isNotEmpty() })
    }

    private fun walk(node: AssistStructure.ViewNode, visit: (AssistStructure.ViewNode) -> Unit) {
        visit(node)
        for (i in 0 until node.childCount) walk(node.getChildAt(i), visit)
    }

    private fun isPasswordInput(inputType: Int): Boolean =
        inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT &&
            inputType and InputType.TYPE_MASK_VARIATION in setOf(
                InputType.TYPE_TEXT_VARIATION_PASSWORD,
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
                InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
            )

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Log.i(ISLAND_TAG, "onSaveRequest")
        val bridge = HubHolder.ensureBridge()
        if (bridge == null) {
            callback.onFailure("Bitward 本機中樞尚未啟動")
            return
        }
        if (!bridge.unlocked()) {
            callback.onFailure("Bitward 尚未解鎖")
            return
        }
        // TODO(P4b 下一批): 從 request.fillContexts 的 fillable values 取值後 save()
        //（寫入路徑＝bw-sync outbox，見 apps/bitward-android/README.md 已知的下一步 2）。
        callback.onSuccess()
    }

    /**
     * 鎖定態回應：response 級 setAuthentication 列「尚未解鎖」，點它拉開 app
     * 走登入解鎖（解鎖引導；下一次 fill 請求就是真候選）。
     * （Dataset 沒欄位值會被 `build()` 擋：「at least one of field or datatype
     * must be set」，實測 Android 16；response 級 auth 列才是解鎖流的正統形態）。
     * `PendingIntent.intentSender` 是 API 31 才有的面；28–30 回空回應。
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

/**
 * 同程序中樞的句柄。裝載是惰性的：孤島第一次被系統叫醒（fill/save 請求）時
 * 才探 `NativeHub`——UI 已起（libnsh.so 在記憶體）或 service 冷啟
 * （這裡 loadLibrary，Rust 側 `HUB` 直接開 Store）兩條路都成立。
 * 探測失敗（純 nsh 包、ABI 缺件、Store 開不起來）就保持 null，
 * 孤島走快速失敗路（契約 §1.2）。
 */
object HubHolder {
    @Volatile
    var bridge: BitwardAutofillService.HubBridge? = null
        private set

    @Synchronized
    fun ensureBridge(): BitwardAutofillService.HubBridge? {
        bridge?.let { return it }
        if (NativeHub.available()) {
            bridge = NativeHubBridge().also { Log.i(ISLAND_TAG, "hub bridge installed (in-process)") }
        }
        return bridge
    }
}
