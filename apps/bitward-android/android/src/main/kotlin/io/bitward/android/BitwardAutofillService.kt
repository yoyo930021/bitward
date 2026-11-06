package io.bitward.android

import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest

/**
 * 填充孤島（契約 §0.1 Android 列、§1「Android app＝Full（in-process 中樞）」）。
 *
 * **骨架狀態**：這份檔還沒進 APK。nsh 0.3.0 的 `nsh package --target android`
 * 只組裝 prebuilt runtime 的 `classes.dex` 與 `lib/<ABI>/libnsh.so`，沒有讓
 * app 帶自己的 Kotlin 來源或 manifest（實測見 `docs/design/android-findings.md`
 * 「P4b 第一批」節）。下一批要加一個 Gradle 外殼模組，把 nsh 的 dex 與
 * `libnsh.so` 當成依賴，孤島才真的編得進去；在此之前本檔刻意**只声明呼叫面**，
 * 不寫會誤導人的僞實作。
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

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val bridge = HubHolder.bridge
        if (bridge == null) {
            // 中樞不在（未登入或程序被回收）：快速失敗，不自行降格持鑰（契約 §1.2）。
            callback.onSuccess(android.service.autofill.FillResponse.Builder().build())
            return
        }
        // TODO(P4b 第二批): 由 request.fillContexts 取 assured structure，
        // 經 bridge 拿候選，再用 Dataset.Builder 綁 username/password 欄位 id。
        callback.onSuccess(android.service.autofill.FillResponse.Builder().build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        if (HubHolder.bridge == null) {
            callback.onError("Bitward 本機中樞尚未啟動")
            return
        }
        // TODO(P4b 第二批): 從 request.fillContexts 的 fillable values 取值後 save()。
        callback.onSuccess()
    }
}

/** 同程序中樞的句柄：Rust 側（`libnsh.so`）起來時經 JNI 放進實作。 */
object HubHolder {
    @Volatile
    var bridge: BitwardAutofillService.HubBridge? = null
}
