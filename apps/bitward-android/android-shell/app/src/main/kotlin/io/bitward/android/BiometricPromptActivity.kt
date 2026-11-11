package io.bitward.android

import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log

/**
 * 生物辨識彈窗宿主（透明 Activity，零佈局）：[KeyStoreBridge] 的驗證路經此
 * 落地——平台 API `android.hardware.biometrics.BiometricPrompt`（API 28+；
 * 本專案零 androidx，同外殼一貫紀律）。
 *
 * 不綁 CryptoObject（實錄 13:15：平台面要求 Cipher init 成功才收
 * CryptoObject，而 Class 3 金鑰在 30 秒視窗外連 `init` 都丟
 * UserNotAuthenticatedException——「Crypto primitive not initialized」；
 * androidx 才有 init-throw 兜底）。改為：驗證通過＝開啟 30 秒使用者驗證
 * 視窗，[KeyStoreBridge] 隨後用同一把鑰重構 Cipher 靜默運算。三個 API
 * 世代（28／29／30+）同一條路，無版本分岔。
 *
 * 語意（macOS 裝置斷言等位）：指紋 STRONG 或裝置憑證（API 30+ 放行）通過
 * 才放行；取消／失敗＝回 false，呼叫端（Rust `unseal`／`seal`）誠實降回
 * 主密碼路，不緩存、不重試到煩。
 *
 * stub jar 實錄：本面只有 `authenticate(CancellationSignal, Executor,
 * Callback)` 與 `authenticate(CryptoObject, CancellationSignal, Executor,
 * Callback)` 兩支重載；退出鈕是 `setNegativeButton(label, Executor,
 * OnClickListener)`（沒有 `setNegativeButtonText`）。
 */
class BiometricPromptActivity : Activity() {

    private var myReq: KeyStoreBridge.AuthRequest? = null

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
                // 驗證事件即開啟 30 秒視窗；密碼運算交回呼叫端重構 Cipher 做。
                req.deliver(true)
                finish()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.i(ISLAND_TAG, "biometric prompt error $errorCode: $errString")
                req.deliver(false)
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
                req.deliver(false)
                finish()
            }
        if (Build.VERSION.SDK_INT >= 30) builder.setDeviceCredentialAllowed(true)
        builder.build()
            .authenticate(CancellationSignal(), mainExecutor, callback)
    }

    override fun onDestroy() {
        // 系統回收／使用者從後台滑掉：結算 false（settled 閂防重複），
        // 別把呼叫端的閂吊死，也不誤傷後續新請求。
        myReq?.deliver(false)
        super.onDestroy()
    }
}
