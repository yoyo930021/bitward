package io.bitward.android

import android.os.CancellationSignal
import android.service.credentials.ClearCredentialRegistrationRequest
import android.service.credentials.CredentialProviderService
import android.service.credentials.GetCredentialEntryRequest
import android.service.credentials.GetCredentialRequest
import android.service.credentials.GetCredentialResponse
import android.service.credentials.RegisterCredentialRequest
import android.service.credentials.RegisterCredentialResponse

/**
 * API 34 `androidx.credentials` 孤島（契約 §0.1 Android 列、§1 Android app 列）。
 *
 * 語意：系統直接問密碼管理員要憑證（passkey 與 password 同一條路），
 * 不再靠 AutofillService 撈欄位。真正的 crypto（COSE 簽章、大範圍
 * `Get`/`Register` 語意）在中樞的 Rust 側（`bw-crypto::passkey`），
 * 這裡只做系統介面的轉接。
 *
 * **骨架狀態**：尚未編進 APK（見本目錄 README.md）；方法體刻意留空，
 * 因為要接的 `HubBridge` 還沒定義 passkey 面（P4b 第二批）。
 */
class BitwardCredentialProviderService : CredentialProviderService() {

    override fun GetCredential(
        request: GetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: (GetCredentialResponse) -> Unit,
    ) {
        // TODO(P4b 第二批): HubHolder.bridge → 依 request 的 candidate 條件回 entry。
        callback(GetCredentialResponse.Builder().build())
    }

    override fun RegisterCredential(
        request: RegisterCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: (RegisterCredentialResponse) -> Unit,
    ) {
        callback(RegisterCredentialResponse.Builder().build())
    }

    override fun ClearCredentialRegistration(
        request: ClearCredentialRegistrationRequest,
        cancellationSignal: CancellationSignal,
        callback: () -> Unit,
    ) {
        callback()
    }

    override fun GetCredentialEntry(
        request: GetCredentialEntryRequest,
        cancellationSignal: CancellationSignal,
        callback: (android.service.credentials.CredentialEntry?) -> Unit,
    ) {
        callback(null)
    }
}
