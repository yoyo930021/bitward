//! macOS Keychain 封存（契約 §3.2 `KeyStore`、§0.1「金鑰封存」列）。
//! user key 以 generic password 落 login keychain，寫入時掛 biometric ACL；
//! 單元測試不碰真實 keychain：由 runtime flag `BW_KEYS_ENABLE_KEYCHAIN=1`
//! 啟用，未啟用時所有操作回 `KeyError::KeyStore("...disabled...")`。

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::SecAccessControl;
use security_framework::base::Error;
use security_framework::passwords::{delete_generic_password, get_generic_password};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlUserPresence,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecValueData,
};
use security_framework_sys::keychain_item::SecItemAdd;

use crate::keystore::{AccountLabel, SealedKey, WrapStrength};
use crate::{KeyError, KeyStore};

/// ACL 常數來源：
/// https://developer.apple.com/documentation/security/ksecaccesscontrolbiometrycurrentset
/// https://developer.apple.com/documentation/security/ksecaccesscontroluserpresence
pub const BIOMETRIC_ACL_FLAGS: usize =
    kSecAccessControlBiometryCurrentSet | kSecAccessControlUserPresence;

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
        let _ = delete_generic_password(&self.service, &Self::account(label));
        let acl = SecAccessControl::create_with_flags(BIOMETRIC_ACL_FLAGS)
            .map_err(|e| KeyError::KeyStore(format!("SecAccessControl: {e}")))?;
        let pairs: Vec<(CFString, CFType)> = vec![
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
                CFString::from(Self::account(label).as_str()).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecValueData) },
                CFData::from_buffer(json.to_string().as_bytes()).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
                acl.into_CFType(),
            ),
        ];
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
        if status != 0 {
            return Err(KeyError::KeyStore(Error::from_code(status).to_string()));
        }
        Ok(())
    }

    fn load_wrapped(&self, label: &AccountLabel) -> Result<Option<SealedKey>, KeyError> {
        self.guard()?;
        let bytes = match get_generic_password(&self.service, &Self::account(label)) {
            Ok(b) => b,
            Err(e) if e.code() == errSecItemNotFound => return Ok(None),
            Err(e) => return Err(KeyError::KeyStore(e.to_string())),
        };
        let v: serde_json::Value = serde_json::from_slice(&bytes)
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
        match delete_generic_password(&self.service, &Self::account(label)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == errSecItemNotFound => Ok(()),
            Err(e) => Err(KeyError::KeyStore(e.to_string())),
        }
    }

    fn biometric_available(&self) -> bool {
        // 建立成功即代表生物辨識政策可成立（無硬體/未錄入時 create 回錯）。
        self.enabled && SecAccessControl::create_with_flags(BIOMETRIC_ACL_FLAGS).is_ok()
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
    fn biometric_acl_flags_are_current_set_and_presence() {
        // 常數值對照 Apple 標頭：(1<<3) | (1<<0)
        assert_eq!(BIOMETRIC_ACL_FLAGS, (1 << 3) | (1 << 0));
    }
}
