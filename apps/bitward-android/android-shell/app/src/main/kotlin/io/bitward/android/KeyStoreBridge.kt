package io.bitward.android

import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher

/**
 * Rust 中樞的反向呼叫對象（`src/island.rs` 綁定的就是這個單例實例）。
 *
 * 紀律（同 `NativeHub.kt`「接上去的紀律」1）：金鑰明文只以 `byte[]` 進出、
 * 用完立即 `fill(0)`（Java heap 歸零是尽力而為，形态紀律在兩側）；不經
 * Kotlin String。業務判定（封存格式、漂移、落地）全在 Rust，這裡只做
 * Keystore 密碼學與平台彈窗。
 *
 * 兩條解封路（契約路线 3「依實測能力定案」）：
 * - **靜默路**：30 秒使用者驗證視窗內（剛解鎖裝置／剛過生物辨識）直接
 *   `doFinal`；窗外 [UserNotAuthenticatedException] → 回 null，孤島誠實鎖態。
 * - **彈窗路**：[BiometricPromptActivity] 以 CryptoObject 綁同一把 Cipher，
 *   驗證通過才 `doFinal`——這是 App 解鎖閘「生物辨識直接解鎖」的落地。
 *
 * 包裹（seal）同構：登入成功點先試靜默（使用者剛解鎖過裝置的常態）；
 * 窗外自動退到彈窗路（同 macOS Keychain biometric ACL 的存取即斷言）。
 */
object KeyStoreBridge {

    /** 進程最早期由 [BitwardApplication] 塞入（service 冷啟也經 Application）。 */
    @Volatile
    var appContext: Context? = null

    /** 封存檔路徑：Rust 持格式與落地，這裡只在金鑰作廢時配合刪檔。 */
    @Volatile
    var sealedFile: java.io.File? = null

    private val ks = BitwardKeyStore()

    /** Kotlin 側等待上限：比 Rust 的 120s 閘短，絕不把 blocking 線程吊死。 */
    private const val PROMPT_WAIT_SECONDS = 110L

    /** 包裹 user key：回 IV‖密文‖tag；null＝孤島拒絕／金鑰不可用（Rust 記 log 不重試）。 */
    @JvmStatic
    fun sealUserKey(key: ByteArray): ByteArray? {
        val cipher = runCatching { ks.sealCipher() }.getOrNull()
            ?: return fail("seal cipher 構造失敗")
        try {
            val out = cipher.doFinal(key)
            key.fill(0)
            return out
        } catch (_: KeyPermanentlyInvalidatedException) {
            onKeyInvalidated()
        } catch (_: UserNotAuthenticatedException) {
            // 驗證視窗外：退到生物辨識彈窗（CryptoObject 綁同一把 cipher）。
            Log.i(ISLAND_TAG, "keystore seal needs user auth, prompting")
        } catch (e: Exception) {
            key.fill(0)
            return fail("seal doFinal 失敗：${e.javaClass.simpleName}")
        }
        val out = runCrypto(cipher, key, decrypt = false)
        key.fill(0)
        return out
    }

    /** 靜默解封（孤島冷啟專用，絕不彈窗）：視窗外明確回 null。 */
    @JvmStatic
    fun unsealUserKeySilent(blob: ByteArray): ByteArray? {
        val cipher = runCatching { unsealCipherOf(blob) }.getOrNull() ?: return null
        val plain = try {
            cipher.doFinal(blob, 12, blob.size - 12)
        } catch (_: KeyPermanentlyInvalidatedException) {
            onKeyInvalidated()
            return null
        } catch (e: Exception) {
            // UserNotAuthenticatedException（視窗外）與 Keystore 一般拒用同路：
            // 冷啟保持誠實鎖態，不打彈窗（findings 第五批取捨）。
            Log.i(ISLAND_TAG, "silent unseal denied：${e.javaClass.simpleName}")
            return null
        }
        Log.i(ISLAND_TAG, "silent unseal ok")
        return plain
    }

    /** 彈窗解封（App 解鎖閘）：生物辨識／裝置憑證通過才出明文。 */
    @JvmStatic
    fun unsealUserKeyPrompt(blob: ByteArray): ByteArray? {
        val cipher = runCatching { unsealCipherOf(blob) }.getOrNull() ?: return null
        return runCrypto(cipher, blob, decrypt = true)
    }

    /** 解鎖成功點的保命＋排程（冪等）：起 [HubService]（foreground）＋JobScheduler 週期。 */
    @JvmStatic
    fun ensureHubService() {
        val ctx = appContext ?: return
        runCatching {
            val i = Intent(ctx, HubService::class.java).setAction(HubService.ACTION_RUN)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }.onFailure { Log.w(ISLAND_TAG, "hub service start failed: ${it.message}") }
        HubService.scheduleJob(ctx)
    }

    // —— 內部 ——

    private fun unsealCipherOf(blob: ByteArray): Cipher {
        require(blob.size >= 29) { "封存 blob 太短：${blob.size}" }
        return ks.unsealCipher(blob.copyOfRange(0, 12))
    }

    /** 經 [BiometricPromptActivity] 完成一次 CryptoObject 運算（阻塞到驗證結果）。 */
    private fun runCrypto(cipher: Cipher, input: ByteArray, decrypt: Boolean): ByteArray? {
        val ctx = appContext ?: return null
        val request = CryptoRequest(cipher, input, decrypt)
        val prev = PENDING.getAndSet(request)
        prev?.deliver(null) // 理論上不會有併發封存流（單調用者 Rust），保底不吊死前者。
        try {
            val i = Intent(ctx, BiometricPromptActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
            ctx.startActivity(i)
            if (!request.latch.await(PROMPT_WAIT_SECONDS, TimeUnit.SECONDS)) {
                Log.w(ISLAND_TAG, "biometric prompt 逾時（${PROMPT_WAIT_SECONDS}s）")
                return null
            }
        } catch (e: Exception) {
            Log.w(ISLAND_TAG, "biometric prompt 失敗：${e.message}")
            return null
        } finally {
            PENDING.compareAndSet(request, null)
            input.fill(0)
        }
        return request.result
    }

    private fun fail(msg: String): ByteArray? {
        Log.w(ISLAND_TAG, "keystore bridge: $msg")
        return null
    }

    /** 單飛的彈窗請求（[BiometricPromptActivity] 消費）。 */
    class CryptoRequest(
        val cipher: Cipher,
        val blob: ByteArray,
        val decrypt: Boolean,
        val latch: CountDownLatch = CountDownLatch(1),
        @Volatile var result: ByteArray? = null,
    ) {
        private val settled = AtomicBoolean(false)

        /** 驗證通過後對綁定的 Cipher 收尾：解封要跳過頭 12 bytes 的 IV。 */
        fun complete(c: Cipher): ByteArray =
            if (decrypt) c.doFinal(blob, 12, blob.size - 12) else c.doFinal(blob)

        fun deliver(out: ByteArray?) {
            if (settled.compareAndSet(false, true)) {
                result = out
                latch.countDown()
            }
        }
    }

    /** 指紋重註冊作廢金鑰：清 alias＋封存檔（下次解鎖回主密碼路，誠實降級）。 */
    internal fun onKeyInvalidated() {
        ks.dropWrappingKey()
        runCatching { sealedFile?.delete() }
        Log.i(ISLAND_TAG, "keystore wrapping key 作廢（生物辨識重註冊），封存已清")
    }

    /** 單飛的彈窗請求（[BiometricPromptActivity] 經 [takePending] 消費）。 */
    private val PENDING = java.util.concurrent.atomic.AtomicReference<CryptoRequest?>(null)

    internal fun takePending(): CryptoRequest? = PENDING.get()
}
