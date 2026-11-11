package io.bitward.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 金鑰封存孤島（契約 §0.1「Android Keystore Class 3/StrongBox（JNI）」、§1 落盤形態）。
 *
 * 語意：`vault.db` 存伺服器原樣密文，Protected Symmetric Key（`2.iv|ct|mac`）
 * 存在帳號檔；真正的 user key 由这把 Keystore 金鑰以 AES-GCM 封裝後落地
 * （`sealed.json`，形態與漂移判定在 Rust 側 `src/hub.rs`）。重啟時經生物辨識
 * 解封，**不重跑 KDF**（冷啟秒級，graft 自候選二）。
 *
 * 已進 APK（`android-shell/`）。第五批落地：wrap/unwrap 接 Rust 側的
 * `Hub.unlocked` 槽（`KeyStoreBridge` 承運，`src/island.rs` 過橋）。
 */
class BitwardKeyStore(private val keyAlias: String = "bitward-user-key-wrap") {

    private val ks: KeyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /**
     * 包裹金鑰（冪等取得或生成）：AES-256-GCM Class 3——需使用者驗證
     * （指紋 STRONG 或裝置憑證，30 秒視窗）＋解鎖裝置要求（API 30+）。
     * StrongBox 不可用（emulator 常態）降級軟體 Keystore——這條降級路
     * 就是正式行為（契約 §2.2「StrongBox 可選」）。
     */
    fun obtainWrappingKey(): SecretKey {
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        try {
            createWrappingKey(strongBoxBacked = true)
        } catch (_: Exception) {
            createWrappingKey(strongBoxBacked = false)
        }
        return ks.getKey(keyAlias, null) as SecretKey
    }

    /** 30 秒視窗／生物辨識彈窗兩條路共用的生成規格（冪等覆寫 alias）。 */
    private fun createWrappingKey(strongBoxBacked: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // 30 秒內已驗證裝置即可用；超過要重新驗證（契約 §2.2 的 LockEpoch 對齊）。
            // 30+ 用新面（明確允許指紋 STRONG＋裝置憑證）；28–29 留舊面（隱含同集合）。
            .apply {
                if (Build.VERSION.SDK_INT >= 30) {
                    setUserAuthenticationParameters(
                        AUTH_WINDOW_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                } else {
                    setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
                }
            }
            .apply { if (Build.VERSION.SDK_INT >= 30) setUnlockedDeviceRequired(true) }
            .apply { if (strongBoxBacked) setIsStrongBoxBacked(true) }
            .build()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(spec)
        kg.generateKey()
    }

    /**
     * 構造＋init 但**不吞驗證例外**：Class 3 金鑰在 30 秒視窗外 `init` 直接丟
     * [UserNotAuthenticatedException]（實錄 13:12：解密側連 init 都擋）。回
     * (cipher, 構造期例外)；null 例外＝視窗內、可直接 doFinal。例外為驗證族時
     * 的正確用法見 `KeyStoreBridge`（先過彈窗開視窗、再重構 Cipher 運算——
     * 平台 BiometricPrompt 不收 init 失敗的 CryptoObject，實錄 13:15）。IV 由
     * Keystore 在加密側自帶隨機 12 bytes（[Cipher.getIV] 取回）；解密側從 blob 頭還原。
     */
    fun prepareSealCipher(): Pair<Cipher, Exception?> = prepare(Cipher.ENCRYPT_MODE, null)

    fun prepareUnsealCipher(iv: ByteArray): Pair<Cipher, Exception?> =
        prepare(Cipher.DECRYPT_MODE, GCMParameterSpec(128, iv))

    private fun prepare(mode: Int, spec: GCMParameterSpec?): Pair<Cipher, Exception?> {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val err = try {
            if (spec == null) c.init(mode, obtainWrappingKey()) else c.init(mode, obtainWrappingKey(), spec)
            null
        } catch (e: Exception) {
            e
        }
        return c to err
    }

    /** 金鑰被生物辨識重註冊作廢（KeyPermanentlyInvalidated）時清_alias_，下次重生成。 */
    fun dropWrappingKey() {
        runCatching { if (ks.containsAlias(keyAlias)) ks.deleteEntry(keyAlias) }
    }

    /**
     * Class 3 EC（P-256，簽章用）探針金鑰：冪等，已存在就只回報。
     * （A10 的橋通證明；真正的 user-key 包裹走上面的 AES-GCM 路。）
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
            .setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
            .apply { if (Build.VERSION.SDK_INT >= 30) setUnlockedDeviceRequired(true) }
            .apply { if (strongBoxBacked) setIsStrongBoxBacked(true) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun wrappedKeyExists(): Boolean = ks.containsAlias(keyAlias)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AUTH_WINDOW_SECONDS = 30
    }
}
