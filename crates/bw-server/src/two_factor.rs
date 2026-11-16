//! 服務端 2FA 因子管理面（PR3 子批 b）：`/two-factor/*` 端點代理。
//!
//! 源檔對照（Vaultwarden 1.37.2，`src/api/core/two_factor/`）：
//!
//! | 契約 | 端點 | 需要的驗證 |
//! |---|---|---|
//! | 已啟用因子清單 | `GET /two-factor` | bearer |
//! | TOTP 金鑰 | `POST /two-factor/get-authenticator` | `PasswordOrOtpData` |
//! | TOTP 啟用 | `POST /two-factor/authenticator` | 同上 |
//! | Email 寄驗證碼 | `POST /two-factor/send-email` | 同上 |
//! | Email 確認 | `PUT /two-factor/email` | 同上 |
//! | YubiKey 啟用 | `POST /two-factor/yubikey` | 同上 |
//! | 停用因子 | `POST /two-factor/disable` | 同上 |
//! | 救援碼 | `POST /two-factor/get-recover` | 同上 |
//!
//! `PasswordOrOtpData` 兩欄（`masterPasswordHash`／`otp`）至少要有一欄
//! （`src/api/mod.rs:51-77`）：本模組一律用主密碼 hash，派生在呼叫端
//! （bw-crypto），本 crate 不做 KDF（依賴方向紀律同模組頭）。
//! 官方雲同組端點但欄位是 PascalCase（.NET 反序列化大小寫不敏感，
//! 送出 camelCase 兩邊通；讀取走 `json::get` 的別名寬容）。

use serde_json::{Value, json};

use crate::Client;
use crate::error::ServerError;
use crate::json::{get, get_str};
use bw_proto::{TwoFactorDetails, TwoFactorProviderState};

/// 主密碼 hash 的驗證體（`PasswordOrOtpData` 的最小形態）。
fn password_body(master_password_hash: &str) -> Value {
    json!({ "masterPasswordHash": master_password_hash })
}

/// TOTP 金鑰取得結果。`already_enabled`＝該帳號早已啟用 Authenticator
/// （伺服器此時回的是既有 key，不是新鑰，`authenticator.rs:29-33`）。
#[derive(Clone, Debug)]
pub struct AuthenticatorKey {
    pub key: String,
    pub already_enabled: bool,
}

impl Client {
    /// `GET /two-factor`：已啟用因子清單。
    ///
    /// ListResponse 形態（`{"data":[{"type":0,"enabled":true,...}]}`）；
    /// Vaultwarden 只列已啟用的條目（`to_json_provider`，
    /// `src/db/models/two_factor.rs:71-77`）。解析見 [`parse_list`]。
    pub async fn two_factor_list(&self) -> Result<Vec<TwoFactorProviderState>, ServerError> {
        let raw = self.get_json("two-factor").await?;
        Ok(parse_list(&raw))
    }

    /// `POST /two-factor/get-authenticator`：取（或沿用）TOTP base32 金鑰。
    ///
    /// 伺服器只回 `{enabled, key}`——**沒有** otpauth URI，
    /// URI 由呼叫端以 [`otpauth_uri`] 自組（官方 web vault 同做法）。
    pub async fn two_factor_authenticator_key(
        &self,
        master_password_hash: &str,
    ) -> Result<AuthenticatorKey, ServerError> {
        let raw = self
            .post_json(
                "two-factor/get-authenticator",
                &password_body(master_password_hash),
            )
            .await?;
        let key = get_str(&raw, &["key", "Key"])
            .ok_or_else(|| ServerError::Rejected("get-authenticator 回包缺 key 欄".to_owned()))?
            .to_owned();
        Ok(AuthenticatorKey {
            key,
            already_enabled: get(&raw, &["enabled", "Enabled"])
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// `POST /two-factor/authenticator`：以驗證器現碼確認啟用。
    /// `key` 必須是 [`Self::two_factor_authenticator_key`] 取得的值——
    /// 伺服器比對落庫 key，不對就回「TOTP key … does not match recorded value」。
    pub async fn two_factor_enable_authenticator(
        &self,
        master_password_hash: &str,
        key: &str,
        token: &str,
    ) -> Result<(), ServerError> {
        self.try_empty_post_body(
            "two-factor/authenticator",
            &json!({
                "masterPasswordHash": master_password_hash,
                "key": key,
                "token": token,
            }),
        )
        .await
    }

    /// `POST /two-factor/send-email`：寄 Email 因子的驗證碼（兩步的第一步）。
    pub async fn two_factor_send_email_code(
        &self,
        master_password_hash: &str,
        email: &str,
    ) -> Result<(), ServerError> {
        self.try_empty_post_body(
            "two-factor/send-email",
            &json!({
                "masterPasswordHash": master_password_hash,
                "email": email,
            }),
        )
        .await
    }

    /// `PUT /two-factor/email`：以信中碼確認 Email 因子（兩步的第二步）。
    pub async fn two_factor_verify_email(
        &self,
        master_password_hash: &str,
        email: &str,
        token: &str,
    ) -> Result<(), ServerError> {
        self.try_empty_put_body(
            "two-factor/email",
            &json!({
                "masterPasswordHash": master_password_hash,
                "email": email,
                "token": token,
            }),
        )
        .await
    }

    /// `POST /two-factor/yubikey`：登記一把 YubiKey。
    /// `otp`＝tap 出的 44 字元（伺服器取前 12 字元作 key id，`yubikey.rs:56-65`）；
    /// 需 server 端 Yubico 憑證，未設定時伺服器回「Yubikey support is disabled」。
    pub async fn two_factor_enable_yubikey(
        &self,
        master_password_hash: &str,
        otp: &str,
        nfc: bool,
    ) -> Result<(), ServerError> {
        self.try_empty_post_body(
            "two-factor/yubikey",
            &json!({
                "masterPasswordHash": master_password_hash,
                "key1": otp,
                "nfc": nfc,
            }),
        )
        .await
    }

    /// `POST /two-factor/disable`：停用一個因子（`provider`＝upstream 編號）。
    /// 條目不存在時伺服器也回成功（冪等，`two_factor/mod.rs:137-167`）。
    pub async fn two_factor_disable(
        &self,
        master_password_hash: &str,
        provider: i32,
    ) -> Result<(), ServerError> {
        self.try_empty_post_body(
            "two-factor/disable",
            &json!({
                "masterPasswordHash": master_password_hash,
                "type": provider,
            }),
        )
        .await
    }

    /// `POST /two-factor/get-recover`：取備用救援碼。
    /// None＝伺服器尚未發碼（尚未啟用任何因子時 `totp_recover` 是 null）。
    pub async fn two_factor_recovery_code(
        &self,
        master_password_hash: &str,
    ) -> Result<Option<String>, ServerError> {
        let raw = self
            .post_json(
                "two-factor/get-recover",
                &password_body(master_password_hash),
            )
            .await?;
        Ok(get_str(&raw, &["code", "Code"]).map(str::to_owned))
    }
}

/// 清單解析（純函數，單測點）：`data` 逐條取 `type`＋`enabled`，
/// 只留啟用態；缺 `type` 或非數字的條目跳過（伺服器形態漂移不炸）。
pub fn parse_list(raw: &Value) -> Vec<TwoFactorProviderState> {
    let items = match get(raw, &["data", "Data"]).and_then(Value::as_array) {
        Some(a) => a,
        None => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|item| {
            let provider = get(item, &["type", "Type"])?.as_i64()?;
            let enabled = get(item, &["enabled", "Enabled"])
                .and_then(Value::as_bool)
                .unwrap_or(true);
            Some(TwoFactorProviderState {
                provider: provider as i32,
                enabled,
            })
        })
        .filter(|s| s.enabled)
        .collect()
}

/// `otpauth://totp/{issuer}:{account}?secret=..&issuer=..&accountName=..`
/// （RFC 6238 key-uri 慣例，官方 web vault 同形態）。
/// 純函數，單測點：label 與 query 值都要 percent 編碼。
pub fn otpauth_uri(key: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&accountName={}",
        pct_encode(issuer),
        pct_encode(account),
        pct_encode(key),
        pct_encode(issuer),
        pct_encode(account),
    )
}

/// 最小 percent 編碼（unreserved 外全部 `%XX`）：otpauth label 含 `:`／`@`，
/// 不編碼會造成解析歧義。不帶新依賴（本 crate 無 percent-encoding）。
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 登入挑戰的因子細節（`TwoFactorProviders2` 該 provider 的物件）→ 型別形態。
/// 源檔對照 `src/api/identity.rs:920-1010`：Duo iframe 態 `{"Host","Signature"}`、
/// Duo redirect 態 `{"AuthUrl"}`、WebAuthn 態 `{"challenge","allowCredentials",…}`、
/// YubiKey 態 `{"Nfc"}`；Email 態 `{"Email"}` 是水漬地址，已在 `hint`，這裡回 None。
/// 未知形態回 None（呼叫端退回純欄位流或給可懂錯誤），不猜。
pub fn challenge_details(provider: i32, raw: Option<&Value>) -> Option<TwoFactorDetails> {
    let raw = raw?;
    match provider {
        2 | 6 => {
            if let Some(auth_url) = get_str(raw, &["AuthUrl", "authUrl", "auth_url"]) {
                return Some(TwoFactorDetails::DuoRedirect {
                    auth_url: auth_url.to_owned(),
                });
            }
            let host = get_str(raw, &["Host", "host"])?;
            let signature = get_str(
                raw,
                &["Signature", "signature", "SignedRequest", "signedRequest"],
            )?;
            Some(TwoFactorDetails::DuoIframe {
                host: host.to_owned(),
                signature: signature.to_owned(),
            })
        }
        7 => {
            let challenge = get_str(raw, &["challenge", "Challenge"])?.to_owned();
            let credential_ids = get(raw, &["allowCredentials", "AllowCredentials"])
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|c| {
                            get(c, &["id", "ID", "rawId"])
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let rp_id = get_str(raw, &["rpId", "rp_id", "rpID"]).map(str::to_owned);
            Some(TwoFactorDetails::Webauthn {
                challenge,
                credential_ids,
                rp_id,
            })
        }
        3 => Some(TwoFactorDetails::Yubikey {
            nfc: get(raw, &["Nfc", "nfc"])
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_keeps_enabled_and_survives_shape_drift() {
        let vw = serde_json::json!({
            "data": [
                {"enabled": true, "type": 0, "object": "twoFactorProvider"},
                {"enabled": true, "type": 7, "object": "twoFactorProvider"},
                {"enabled": false, "type": 1, "object": "twoFactorProvider"},
                {"object": "twoFactorProvider"}
            ],
            "object": "list",
            "continuationToken": null
        });
        assert_eq!(
            parse_list(&vw),
            vec![
                TwoFactorProviderState {
                    provider: 0,
                    enabled: true
                },
                TwoFactorProviderState {
                    provider: 7,
                    enabled: true
                },
            ]
        );
        // 官方雲 PascalCase 同檢
        let cloud = serde_json::json!({
            "Data": [{"Enabled": true, "Type": 2}],
        });
        assert_eq!(
            parse_list(&cloud),
            vec![TwoFactorProviderState {
                provider: 2,
                enabled: true
            }]
        );
        assert!(parse_list(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn otpauth_uri_encodes_label_and_query() {
        let uri = otpauth_uri("JBSWY3DP", "a@b.test", "http://127.0.0.1:18097");
        assert_eq!(
            uri,
            "otpauth://totp/http%3A%2F%2F127.0.0.1%3A18097:a%40b.test?secret=JBSWY3DP&issuer=http%3A%2F%2F127.0.0.1%3A18097&accountName=a%40b.test"
        );
    }

    /// 挑戰細節：四形態各取所需，Email／未知回 None（水漬位在 hint）。
    #[test]
    fn challenge_details_per_provider() {
        let duo_iframe =
            serde_json::json!({"Host": "api-abc.duosecurity.com", "Signature": "AUTH|a|b:APP|c|d"});
        assert_eq!(
            challenge_details(2, Some(&duo_iframe)),
            Some(TwoFactorDetails::DuoIframe {
                host: "api-abc.duosecurity.com".into(),
                signature: "AUTH|a|b:APP|c|d".into(),
            })
        );
        let duo_redirect = serde_json::json!({"AuthUrl": "https://abc/login/dbf85e2c"});
        assert_eq!(
            challenge_details(2, Some(&duo_redirect)),
            Some(TwoFactorDetails::DuoRedirect {
                auth_url: "https://abc/login/dbf85e2c".into(),
            })
        );
        let wa = serde_json::json!({
            "challenge": "XyZ",
            "allowCredentials": [
                {"id": "credA", "type": "public-key", "transports": ["usb"]},
                {"type": "public-key"}
            ],
            "userVerification": "discouraged",
            "extensions": {"appid": "http://127.0.0.1:18097/app-id.json"}
        });
        assert_eq!(
            challenge_details(7, Some(&wa)),
            Some(TwoFactorDetails::Webauthn {
                challenge: "XyZ".into(),
                credential_ids: vec!["credA".into()],
                rp_id: None,
            })
        );
        assert_eq!(
            challenge_details(3, Some(&serde_json::json!({"Nfc": true}))),
            Some(TwoFactorDetails::Yubikey { nfc: true })
        );
        assert_eq!(
            challenge_details(1, Some(&serde_json::json!({"Email": "a***@b.test"}))),
            None
        );
        assert_eq!(challenge_details(0, Some(&serde_json::json!(null))), None);
        assert_eq!(challenge_details(2, None), None);
    }
}
