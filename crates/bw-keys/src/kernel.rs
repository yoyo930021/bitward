//! 金鑰派生邊界：狀態機透過 `UnlockKernel` 取得 `KeyBundle`，
//! 不直接依賴 bw-crypto 的函數實作（測試可注入假內核，
//! 真實內核 `BwCryptoKernel` 走 §3.1 簽名）。

use bw_crypto::{KdfParams, UserKey};
use bw_proto::EncStr;
use zeroize::Zeroizing;

use crate::KeyBundle;
use crate::KeyError;
use crate::keystore::SealedKey;

/// 登入後、解鎖前就該持有的材料：KDF 參數 + Protected Symmetric Key。
/// 全部可在 `AuthLocked` 下自伺服器取得或自封存載入；離線解鎖只需要
/// `protected_user_key` 的 MAC 驗證（不打 identity server，治 #19055）。
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub email: String,
    pub kdf: KdfParams,
    pub protected_user_key: EncStr,
    /// 伺服器 `profile.keys` 指紋（KeyDrift 基準）。
    pub keys_fingerprint: Option<String>,
}

pub trait UnlockKernel: Send + Sync {
    /// 主密碼 → MasterKey → StretchedKey → 解出 UserKey。
    /// 密碼錯時 decrypt_user_key 的 MAC 檢查失敗 ⇒ `KeyError::AuthFailed`。
    fn unlock_password(&self, pw: &str, ctx: &AuthContext) -> Result<KeyBundle, KeyError>;
    /// OS 封存解包（biometric ACL / 檔案權限），不需網路。
    fn unlock_assertion(&self, sealed: &SealedKey) -> Result<KeyBundle, KeyError>;
}

/// 生產內核：編排 bw-crypto（§3.1）。
pub struct BwCryptoKernel;

impl UnlockKernel for BwCryptoKernel {
    fn unlock_password(&self, pw: &str, ctx: &AuthContext) -> Result<KeyBundle, KeyError> {
        let mk =
            bw_crypto::master_key(pw, &ctx.email, ctx.kdf).map_err(|_| KeyError::AuthFailed)?;
        let sk = bw_crypto::stretch(&mk);
        let user_key = bw_crypto::decrypt_user_key(&sk, &ctx.protected_user_key)
            .map_err(|_| KeyError::AuthFailed)?;
        Ok(KeyBundle::new(user_key, None, ctx.keys_fingerprint.clone()))
    }

    fn unlock_assertion(&self, sealed: &SealedKey) -> Result<KeyBundle, KeyError> {
        let user_key = UserKey::from_bytes(sealed.user_key.to_vec())
            .map_err(|e| KeyError::KeyStore(format!("sealed user key: {e}")))?;
        Ok(KeyBundle::new(
            user_key,
            sealed.enc_private_key.as_deref().map(|s| s.to_owned()),
            sealed.keys_fingerprint.clone(),
        ))
    }
}

impl SealedKey {
    /// 由鑰包產生封存記錄（成功以密碼解鎖後 enrollment）。
    pub(crate) fn from_bundle(b: &KeyBundle) -> Self {
        Self {
            user_key: Zeroizing::new(b.user_key().as_bytes().to_vec()),
            keys_fingerprint: b.fingerprint().map(str::to_owned),
            enc_private_key: b
                .encrypted_private_key()
                .map(|s| Zeroizing::new(s.to_owned())),
        }
    }
}
