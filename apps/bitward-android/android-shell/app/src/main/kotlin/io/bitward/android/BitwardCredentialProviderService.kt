package io.bitward.android

import android.credentials.ClearCredentialStateException
import android.credentials.CreateCredentialException
import android.credentials.GetCredentialException
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CredentialProviderService
import android.util.Log

/**
 * API 34 `androidx.credentials` 孤島（契約 §0.1 Android 列、§1 Android app 列）。
 *
 * 語意：系統直接問密碼管理員要憑證（passkey 與 password 同一條路），
 * 不再靠 AutofillService 撈欄位。真正的 crypto（COSE 簽章、大範圍
 * `Get`/`Register` 語意）在中樞的 Rust 側（`bw-crypto::passkey`），
 * 這裡只做系統介面的轉接。
 *
 * 已進 APK（`android-shell/`）。本批三個回呼一律以「尚未解鎖」錯誤快速
 * 失敗（契約 §1.2：中樞不在不降格）；接 `HubBridge` 的 passkey 面是下一批。
 *
 * 注意：方法名是大寫開頭的 `Get`/`Create`…（框架 API 就長這樣），
 * 且回呼是 `OutcomeReceiver`（實測 android-35 android.jar，非佔位檔当初
 * 假設的 `(Response) -> Unit`）。
 */
class BitwardCredentialProviderService : CredentialProviderService() {

    override fun onCreate() {
        super.onCreate()
        Log.i(ISLAND_TAG, "credential provider service bound")
    }

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // bridge 已預留（同程序 in-process 中樞）；passkey 的 Get/Register 面接上来是下一批。
        val unlocked = HubHolder.ensureBridge()?.unlocked() == true
        Log.i(ISLAND_TAG, "onBeginGetCredential unlocked=$unlocked")
        callback.onError(
            GetCredentialException(if (unlocked) "Bitward passkey 面尚未接" else "Bitward 尚未解鎖"),
        )
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        Log.i(ISLAND_TAG, "onBeginCreateCredential")
        callback.onError(CreateCredentialException("Bitward 尚未解鎖"))
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialStateException>,
    ) {
        // 中樞沒有跨會話憑證狀態可清；確認回呼即可。
        callback.onResult(null)
    }
}
