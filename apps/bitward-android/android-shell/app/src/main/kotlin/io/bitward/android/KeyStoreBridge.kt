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
 *   `doFinal`；窗外明確失敗（init 即擋，實錄 13:12），孤島誠實鎖態。
 * - **彈窗路**：[BiometricPromptActivity] 過生物辨識／裝置憑證——**不綁
 *   CryptoObject**（平台 `android.hardware.biometrics.BiometricPrompt` 要求
 *   Cipher init 成功，而 Class 3 金鑰在視窗外 init 就丟 UNAE，實錄 13:15
 *   「Crypto primitive not initialized」；androidx 才有 init-throw 兜底）。
 *   驗證事件本身開啟 30 秒視窗，成功回呼後重構 Cipher 直接運算——與 API 28
 *   兼容路同構，一套走三個版本。
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

    /** 包裹 user key：回 IV‖密文‖tag；null＝孤島拒絕／金鑰不可用（Rust 記 log 不重試）。
     *  四支 Rust 反調入口刻意不加 `@JvmStatic`：object 加它只出 static 方法，
     *  jni 的 `call_method`（實例面）會 `NoSuchMethodError`（13:07 實錄）。 */
    fun sealUserKey(key: ByteArray): ByteArray? {
        val out = trySeal(key)
            ?: runAuthThen(key, decrypt = false)
        key.fill(0)
        return out
    }

    /** 靜默解封（孤島冷啟專用，絕不彈窗）：視窗外明確回 null。 */
    fun unsealUserKeySilent(blob: ByteArray): ByteArray? {
        val out = tryUnseal(blob)
        if (out == null) Log.i(ISLAND_TAG, "silent unseal denied")
        else Log.i(ISLAND_TAG, "silent unseal ok")
        return out
    }

    /** 彈窗解封（App 解鎖閘）：生物辨識／裝置憑證通過才出明文。 */
    fun unsealUserKeyPrompt(blob: ByteArray): ByteArray? = runAuthThen(blob, decrypt = true)

    /** 解鎖成功點的保命＋排程（冪等）：起 [HubService]（foreground）＋JobScheduler 週期。 */
    fun ensureHubService() {
        val ctx = appContext ?: return
        runCatching {
            val i = Intent(ctx, HubService::class.java).setAction(HubService.ACTION_RUN)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }.onFailure { Log.w(ISLAND_TAG, "hub service start failed: ${it.message}") }
        HubService.scheduleJob(ctx)
    }

    // —— 內部 ——

    /** 靜默包裹嘗試：視窗外（init 或 doFinal 擋）回 null，不彈窗不報錯。
     *  落地形態＝IV(12)‖密文‖tag——Keystore 的隨機 IV 在 [Cipher.getIV]，
     *  `doFinal` 本身不含它（漏前置時解密側把密文頭 12 bytes 當 IV，
     *  AEADBadTagException 現形，13:28 實錄）。 */
    private fun trySeal(key: ByteArray): ByteArray? = try {
        val (cipher, initErr) = ks.prepareSealCipher()
        if (initErr != null) {
            if (initErr is KeyPermanentlyInvalidatedException) onKeyInvalidated()
            null
        } else {
            val ct = cipher.doFinal(key)
            val iv = cipher.iv
            require(iv.size == 12) { "Keystore GCM IV 非 12 bytes：${iv.size}" }
            iv + ct
        }
    } catch (_: UserNotAuthenticatedException) {
        null
    } catch (_: KeyPermanentlyInvalidatedException) {
        onKeyInvalidated()
        null
    } catch (e: Exception) {
        fail("seal 失敗：${e.javaClass.simpleName}: ${e.message}")
        null
    }

    /** 靜默解封嘗試（形態閘＋Cipher＋doFinal）；任何拒用回 null。 */
    private fun tryUnseal(blob: ByteArray): ByteArray? {
        if (blob.size < 29) return fail("封存 blob 太短：${blob.size}")
        return try {
            val (cipher, initErr) = ks.prepareUnsealCipher(blob.copyOfRange(0, 12))
            if (initErr != null) {
                if (initErr is KeyPermanentlyInvalidatedException) onKeyInvalidated()
                null
            } else {
                cipher.doFinal(blob, 12, blob.size - 12)
            }
        } catch (_: UserNotAuthenticatedException) {
            null
        } catch (_: KeyPermanentlyInvalidatedException) {
            onKeyInvalidated()
            null
        } catch (_: javax.crypto.AEADBadTagException) {
            // 密文對不上現鑰（改密漂移漏網、舊格式殘檔、位元損壞）：封存作廢，
            // 鑰留著下次封存照用；誠實回主密碼路。
            Log.i(ISLAND_TAG, "sealed blob 驗證失敗（AEAD tag），封存作廢")
            runCatching { sealedFile?.delete() }
            null
        } catch (e: Exception) {
            fail("unseal 失敗：${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** 彈窗驗證 → 成功即落入 30 秒視窗 → 靜默路重試（同一把鑰、同一形態）。 */
    private fun runAuthThen(input: ByteArray, decrypt: Boolean): ByteArray? {
        val ctx = appContext ?: return null
        val request = AuthRequest()
        val prev = PENDING.getAndSet(request)
        prev?.deliver(false) // 併發封存流理論上不存在（單調用者 Rust），保底不吊死前者。
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
        }
        if (!request.authed) return null
        return if (decrypt) tryUnseal(input) else trySeal(input)
    }

    private fun fail(msg: String): ByteArray? {
        Log.w(ISLAND_TAG, "keystore bridge: $msg")
        return null
    }

    /** 單飛的彈窗請求（[BiometricPromptActivity] 結算；只傳「驗證過了沒」）。 */
    class AuthRequest(
        val latch: CountDownLatch = CountDownLatch(1),
        @Volatile var authed: Boolean = false,
    ) {
        private val settled = AtomicBoolean(false)
        fun deliver(ok: Boolean) {
            if (settled.compareAndSet(false, true)) {
                authed = ok
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

    private val PENDING = java.util.concurrent.atomic.AtomicReference<AuthRequest?>(null)

    internal fun takePending(): AuthRequest? = PENDING.get()
}
