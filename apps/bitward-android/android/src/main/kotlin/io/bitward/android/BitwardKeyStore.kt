package io.bitward.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyStore

/**
 * 金鑰封存孤島（契約 §0.1「Android Keystore Class 3/StrongBox（JNI）」、§1 落盤形態）。
 *
 * 語意：`vault.db` 存伺服器原樣密文，Protected Symmetric Key（`2.iv|ct|mac`）
 * 存在帳號檔；真正的 user key 由这把 Keystore 金鑰以 AES-GCM 封裝後落地。
 * 重啟時直接解封，**不重跑 KDF**（冷啟秒級，graft 自候選二）。
 *
 * **骨架狀態**：尚未編進 APK，也尚未接上 Rust 側（見本目錄 README.md）。
 * P4b 第一批的解鎖仍要主密碼（`apps/bitward-android/src/hub.rs`）。
 */
class BitwardKeyStore(private val keyAlias: String = "bitward-user-key-wrap") {

    private val ks: KeyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** Class 3（需使用者解鎖）+ StrongBox（若可用）。 */
    @RequiresApi(28)
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
            .setAuthenticationValidityDurationSeconds(30)
            .setUnlockedDeviceRequired(true)
            .apply { if (strongBoxBacked) setStrongBoxBacked(true) }
            .build()
        javax.crypto.KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        ).init(spec).generateKey()
    }

    fun wrappedKeyExists(): Boolean = ks.containsAlias(keyAlias)

    // TODO(P4b 第二批): wrap(userKeyBytes): ByteArray（存 account.json 旁路）、
    // unwrap(sealed): Zeroizing<ByteArray>（交回 Rust 側的 UnlockMachine），
    // 以及 StrongBox 不可用時的降級路徑（無 setStrongBoxBacked 的 Class 3 金鑰）。
    // 明文經 FFI 的紀律：只回 byte[]，不讓它變成 Kotlin String（契約 §2.7 規則 1）。

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
