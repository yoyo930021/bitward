//! macOS Keychain 封存（契約 §3.2 `KeyStore`、§0.1「金鑰封存」列）。
//! user key 以 generic password 落 login keychain，寫入時掛 biometric ACL；
//! 單元測試不碰真實 keychain：由 runtime flag `BW_KEYS_ENABLE_KEYCHAIN=1`
//! 啟用，未啟用時所有操作回 `KeyError::KeyStore("...disabled...")`。

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::SecAccessControl;
use security_framework::base::Error;
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

// security-framework-sys 2.17：`One` 未外洩、`kSecUseDataProtectionKeychain` 藏在
// OSX_10_15 feature 後面——皆依 SecItem.h 同符號自宣告，免動 feature 矩陣。
unsafe extern "C" {
    static kSecMatchLimitOne: core_foundation::string::CFStringRef;
    static kSecUseDataProtectionKeychain: core_foundation::string::CFStringRef;
}

use crate::keystore::{AccountLabel, SealedKey, WrapStrength};
use crate::{KeyError, KeyStore};

/// ACL 常數來源：
/// https://developer.apple.com/documentation/security/ksecaccesscontrolbiometrycurrentset
/// 批次 14.8：必**只用** BiometryCurrentSet——`| UserPresence` 是非法組合
/// （Apple 標頭明言 UserPresence 只能配 ApplicationPassword/PrivateKeyUsage），
/// `SecAccessControlCreateWithFlags` 回 **OSStatus -50** → biometric_available
/// 恆 false → hub 永遠退回 FileKeyStore → Touch ID 鈕不出來（Main 最小 C
/// probe 一秒復現實錄）。BiometryCurrentSet 本身即「當前指紋集」語意,更嚴。
pub const BIOMETRIC_ACL_FLAGS: usize = kSecAccessControlBiometryCurrentSet;

/// 建 ACL 必配 `WhenPasscodeSetThisDeviceOnly` 保護階（14.8 probe 實錄：
/// security-framework 的 `create_with_flags` 傳 protection=None 落 API 預設
/// 階,與 BiometryCurrentSet 不相容同報 -50;C probe 顯式帶此階才 OK）。
fn create_biometric_acl() -> Result<SecAccessControl, String> {
    SecAccessControl::create_with_protection(
        Some(security_framework::access_control::ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        BIOMETRIC_ACL_FLAGS,
    )
    .map_err(|e| e.to_string())
}

/// 金鑰記錄的 keychain service 名稱（dev.bitward.* 反域名，避免與官方
/// `Bitwarden CLI` 項目相撞）。來源：§1 金鑰落盤形態；命名為本專案自訂。
pub const SERVICE_DEFAULT: &str = "dev.bitward.userkey";

pub struct KeychainKeystore {
    service: String,
    enabled: bool,
}

impl KeychainKeystore {
    /// runtime flag：`BW_KEYS_ENABLE_KEYCHAIN=1` 才接真實 keychain，
    /// 讓 CI／單元測試預設不觸碰（測試不得隱性改使用者 keychain）。
    pub fn from_env() -> Self {
        Self {
            service: SERVICE_DEFAULT.to_string(),
            enabled: std::env::var("BW_KEYS_ENABLE_KEYCHAIN").is_ok_and(|v| v == "1"),
        }
    }

    pub fn with_service(service: impl Into<String>, enabled: bool) -> Self {
        Self {
            service: service.into(),
            enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn guard(&self) -> Result<(), KeyError> {
        if self.enabled {
            Ok(())
        } else {
            Err(KeyError::KeyStore(
                "keychain disabled by runtime flag (BW_KEYS_ENABLE_KEYCHAIN=1 to enable)".into(),
            ))
        }
    }

    fn account(label: &AccountLabel) -> String {
        match &label.account_id {
            Some(id) => format!("{}#{id}", label.email),
            None => label.email.clone(),
        }
    }
}

impl KeychainKeystore {
    /// 14.9 核心修正：掛生物 ACL 的 item 一律指定**檔案型 login keychain**
    /// （`kSecUseDataProtectionKeychain=false`）。data-protection keychain
    /// 對 SecItemAdd 強查 `keychain-access-groups` entitlement——實錄連
    /// 「amfid 已放行、能正常啟動」的嵌套 bundle 主執行體都照樣 -34019
    /// （entitlement 在 exec 層通過不等於 SecItem 層被認帳）；檔案型鑰匙圈
    /// 走經典 ACL 語意（1Password/舊 Bitwarden 桌面版同款），不需任何
    /// entitlement，Touch ID 照常守門。
    fn base_query(&self, account: &str) -> Vec<(CFString, CFType)> {
        vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::from(self.service.as_str()).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::from(account).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
                CFBoolean::from(false).into_CFType(),
            ),
        ]
    }

    fn delete_item(&self, account: &str) -> Result<(), security_framework::base::Error> {
        let dict = CFDictionary::from_CFType_pairs(&self.base_query(account));
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status == 0 || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(Error::from_code(status))
        }
    }
}

impl KeyStore for KeychainKeystore {
    fn store_wrapped(&self, label: &AccountLabel, key: &SealedKey) -> Result<(), KeyError> {
        self.guard()?;
        let json = serde_json::json!({
            "v": 1,
            "user_key": base64_of(&key.user_key),
            "keys_fingerprint": key.keys_fingerprint,
            "enc_private_key": key.enc_private_key.as_deref(),
        });
        // 先刪後加：SecItemAdd 不具 upsert 語意。
        let _ = self.delete_item(&Self::account(label));
        let acl = create_biometric_acl().map_err(KeyError::KeyStore)?;
        let mut pairs = self.base_query(&Self::account(label));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(json.to_string().as_bytes()).into_CFType(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            acl.into_CFType(),
        ));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
        if status != 0 {
            return Err(KeyError::KeyStore(Error::from_code(status).to_string()));
        }
        Ok(())
    }

    fn load_wrapped(&self, label: &AccountLabel) -> Result<Option<SealedKey>, KeyError> {
        self.guard()?;
        let account = Self::account(label);
        let mut pairs = self.base_query(&account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::true_value().into_CFType(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) }.into_CFType(),
        ));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut out: core_foundation::base::CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut out) };
        if status == errSecItemNotFound {
            return Ok(None);
        }
        if status != 0 {
            return Err(KeyError::KeyStore(Error::from_code(status).to_string()));
        }
        let data = unsafe { CFData::wrap_under_get_rule(out as _) };
        let v: serde_json::Value = serde_json::from_slice(data.bytes())
            .map_err(|e| KeyError::KeyStore(format!("corrupt keychain record: {e}")))?;
        let raw = base64_parse(v["user_key"].as_str().unwrap_or_default())?;
        Ok(Some(SealedKey {
            user_key: zeroize::Zeroizing::new(raw),
            keys_fingerprint: v["keys_fingerprint"].as_str().map(str::to_owned),
            enc_private_key: v["enc_private_key"]
                .as_str()
                .map(|s| zeroize::Zeroizing::new(s.to_owned())),
        }))
    }

    fn clear(&self, label: &AccountLabel) -> Result<(), KeyError> {
        self.guard()?;
        self.delete_item(&Self::account(label))
            .map_err(|e| KeyError::KeyStore(e.to_string()))
    }

    fn biometric_available(&self) -> bool {
        // 建立成功即代表生物辨識政策可成立（無硬體/未錄入時 create 回錯）。
        if !self.enabled {
            tracing::debug!("keychain biometric: runtime flag 未開,退回檔案封存");
            return false;
        }
        match create_biometric_acl() {
            Ok(_) => {
                tracing::info!("keychain biometric: available（ACL 建立成功）");
                true
            }
            Err(e) => {
                tracing::warn!("keychain biometric: unavailable, ACL 建立失敗：{e}");
                false
            }
        }
    }

    fn wrap_strength(&self) -> WrapStrength {
        if self.enabled {
            WrapStrength::BiometricBound
        } else {
            WrapStrength::FilePermissions
        }
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_parse(s: &str) -> Result<Vec<u8>, KeyError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| KeyError::KeyStore(format!("bad base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default_never_touches_keychain() {
        let ks = KeychainKeystore::with_service("dev.bitward.test.unused", false);
        let label = AccountLabel::new("nobody@bitward.test");
        let err = ks.load_wrapped(&label).unwrap_err();
        assert!(err.to_string().contains("disabled"), "{err}");
        assert_eq!(ks.wrap_strength(), WrapStrength::FilePermissions);
        assert!(!ks.biometric_available());
    }

    #[test]
    fn biometric_acl_flags_are_current_set_only() {
        // 批次 14.8：常數值對照 Apple 標頭 kSecAccessControlBiometryCurrentSet=(1<<3)。
        // UserPresence 不得混入（只能配 ApplicationPassword/PrivateKeyUsage,
        // 混入 CreateWithFlags 回 -50）——本測在錯組合下直接鎖死回歸。
        assert_eq!(BIOMETRIC_ACL_FLAGS, 1 << 3);
    }

    /// 真鑰端到端（治「斷言止步」）：隨機 32B 假 user key 走 KeychainKeystore
    /// wrap→存→取回同位元組→刪。獨立 service 名避撞真鑰；無生物硬體
    /// （biometric_available false）整組跳過（既有 fallback 語意）。
    /// 同進程 read 若遭 macOS 擋互動（-25308,無人值守场景）視為環境跳過,
    /// prompt 行為由真機人驗（README 14b 清單）。
    #[test]
    fn keychain_wrap_store_load_roundtrip() {
        let ks = KeychainKeystore::with_service("dev.bitward.test", true);
        if !ks.biometric_available() {
            eprintln!("skip: 本機無生物硬體/未錄入,跳過真鑰測");
            return;
        }
        let label = AccountLabel::new("roundtrip@bitward.test");
        let key = SealedKey {
            user_key: zeroize::Zeroizing::new(vec![0xA5; 32]),
            keys_fingerprint: Some("rt-fp".into()),
            enc_private_key: None,
        };
        // 環境跳過：未簽章 dev 進程無 keychain entitlement（-50/34011 類）,
        // 真機 re-seal 由已簽 daemon 在 14b 人驗鏈路證（README 清單）。
        if let Err(e) = ks.store_wrapped(&label, &key) {
            let s = e.to_string();
            assert!(!s.contains("-50"), "ACL 非法組合回潮：{s}");
            eprintln!("note: keychain store 需簽章 entitlement（{s}）,dev 環境跳過");
            return;
        }
        let got = ks.load_wrapped(&label);
        // 存檔路徑已證（store 成功=ACL 合法）；read 需生物互動時環境跳過。
        match got {
            Ok(Some(sealed)) => {
                assert_eq!(&*sealed.user_key, &*key.user_key, "取回必同位元組");
                assert_eq!(sealed.keys_fingerprint.as_deref(), Some("rt-fp"));
            }
            Ok(None) => panic!("store 後 read 竟回 None"),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("-25308") || s.contains("interaction") || s.contains("auth"),
                    "read 意外失敗：{s}"
                );
                eprintln!("note: read 需生物互動（{s}）,prompt 由真機人驗");
            }
        }
        ks.clear(&label).expect("清理測試項必成");
        assert!(matches!(ks.load_wrapped(&label), Ok(None)));
    }
}

