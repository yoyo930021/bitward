package io.bitward.android

import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log

/**
 * 生物辨識彈窗宿主（透明 Activity，零佈局）：[KeyStoreBridge] 的 CryptoObject
 * 驗證路經此落地——平台 API `android.hardware.biometrics.BiometricPrompt`
 * （API 28+；本專案零 androidx，同外殼一貫紀律）。
 *
 * 語意（macOS 裝置斷言等位）：指紋 STRONG 或裝置憑證（API 30+ 放行）通過，
 * 才讓綁定的 Keystore Cipher `doFinal`；取消／失敗＝回 null，呼叫端
 * （Rust `unseal`／`seal`）誠實降回主密碼路，不緩存、不重試到煩。
 *
 * 本地 stub jar 實錄（第五批）：平台面的重載是
 * `authenticate(CryptoObject, CancellationSignal, Executor, Callback)`（crypto
 * 在前，與 androidx 同名方法順序相反），退出鈕是
 * `setNegativeButton(label, Executor, OnClickListener)`（沒有
 * `setNegativeButtonText`）——照 javap 實查的形態寫。
 */
class BiometricPromptActivity : Activity() {

    private var myReq: KeyStoreBridge.CryptoRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val req = KeyStoreBridge.takePending()
        if (req == null) {
            Log.w(ISLAND_TAG, "biometric prompt 無對應請求（逾時殘影），直接收場")
            finish()
            return
        }
        myReq = req
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val cipher = result.cryptoObject?.cipher ?: req.cipher
                req.deliver(runCatching { req.complete(cipher) }.getOrNull())
                finish()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.i(ISLAND_TAG, "biometric prompt error $errorCode: $errString")
                req.deliver(null)
                finish()
            }

            override fun onAuthenticationFailed() {
                // 單次比對不符（假指紋）：彈窗留著等下一次，不結算。
                Log.i(ISLAND_TAG, "biometric prompt unmatched")
            }
        }
        val builder = BiometricPrompt.Builder(this)
            .setTitle("解鎖 Bitwarden")
            .setSubtitle("確認指紋以解密本機金鑰")
            .setNegativeButton("改用主密碼", mainExecutor) { dialog, _ ->
                dialog.dismiss()
                req.deliver(null)
                finish()
            }
        if (Build.VERSION.SDK_INT >= 30) builder.setDeviceCredentialAllowed(true)
        val prompt = builder.build()
        // API 28 沒有 CryptoObject 重載：驗證事件本身落入 30 秒視窗，
        // 成功回呼後照樣能用同一把 Cipher（實測路徑見 findings 第五批）。
        if (Build.VERSION.SDK_INT >= 29) {
            prompt.authenticate(BiometricPrompt.CryptoObject(req.cipher), CancellationSignal(), mainExecutor, callback)
        } else {
            prompt.authenticate(CancellationSignal(), mainExecutor, callback)
        }
    }

    override fun onDestroy() {
        // 系統回收／使用者從後台滑掉：結算 null（settled 閂防重複），
        // 別把呼叫端的閂吊死，也不誤傷後續新請求。
        myReq?.deliver(null)
        super.onDestroy()
    }
}
