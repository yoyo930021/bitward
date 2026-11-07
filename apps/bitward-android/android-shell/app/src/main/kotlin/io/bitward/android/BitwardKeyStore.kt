package io.bitward.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

/**
 * 金鑰封存孤島（契約 §0.1「Android Keystore Class 3/StrongBox（JNI）」、§1 落盤形態）。
 *
 * 語意：`vault.db` 存伺服器原樣密文，Protected Symmetric Key（`2.iv|ct|mac`）
 * 存在帳號檔；真正的 user key 由这把 Keystore 金鑰以 AES-GCM 封裝後落地。
 * 重啟時直接解封，**不重跑 KDF**（冷啟秒級，graft 自候選二）。
 *
 * 已進 APK（`android-shell/`）。本批先通「Class 3 生成路徑」（驗收 A10：
 * [`BitwardAutofillService`] 被綁定時跑 [`ensureClass3ProbeKey`]，logcat 回顯
 * alias）；wrap/unwrap 接 Rust 側 `UnlockMachine` 是下一批（P4b 第三批）。
 */
class BitwardKeyStore(private val keyAlias: String = "bitward-user-key-wrap") {

    private val ks: KeyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** Class 3（需使用者解鎖）+ StrongBox（若可用）的 AES-256-GCM 封裝金鑰。 */
    fun createWrappingKey(strongBoxBacked: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // 30 秒內已解鎖裝置即可用；超過要重新驗證（契約 §2.2 的 LockEpoch 對齊）。
            .setUserAuthenticationValidityDurationSeconds(30)
            .apply { if (Build.VERSION.SDK_INT >= 30) setUnlockedDeviceRequired(true) }
            .apply { if (strongBoxBacked) setIsStrongBoxBacked(true) }
            .build()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(spec)
        kg.generateKey()
    }

    /**
     * Class 3 EC（P-256，簽章用）探針金鑰：冪等，已存在就只回報。
     * StrongBox 不可用（emulator 常態）時降級軟體 Keystore——這條降級路
     * 就是未來 user-key wrap 金鑰的正式行為（契約 §2.2「StrongBox 可選」）。
     * 回傳值直接進 logcat（A10 斷言的字串）。
     */
    fun ensureClass3ProbeKey(alias: String = "bitward-class3-ec-probe"): String {
        if (ks.containsAlias(alias)) return "keystore EC class3 key present alias=$alias"
        var strongBox = false
        try {
            tryGenerate(alias, true)
            strongBox = true
        } catch (_: Exception) {
            tryGenerate(alias, false)
        }
        return "keystore EC class3 key ready alias=$alias strongbox=$strongBox"
    }

    private fun tryGenerate(alias: String, strongBoxBacked: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(30)
            .apply { if (Build.VERSION.SDK_INT >= 30) setUnlockedDeviceRequired(true) }
            .apply { if (strongBoxBacked) setIsStrongBoxBacked(true) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun wrappedKeyExists(): Boolean = ks.containsAlias(keyAlias)

    // TODO(P4b 第三批): wrap(userKeyBytes): ByteArray（存 account.json 旁路）、
    // unwrap(sealed): Zeroizing<ByteArray>（交回 Rust 側的 UnlockMachine）。
    // 明文經 FFI 的紀律：只回 byte[]，不讓它變成 Kotlin String（契約 §2.7 規則 1）。

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
