//! `/connect/token`：password grant（含 2FA 兩步）、client_credentials、refresh，
//! 以及 **Keys 寬容解析**（契约 §3.3、§2.6）。
//!
//! 三種已知回應形態都要吃：
//! 1. Vaultwarden 1.37.2：Keys 欄位**扁平地**混在 OAuth 欄位旁，PascalCase
//!    （`Key`/`PrivateKey`/`Kdf`/`KdfIterations`/`UserDecryptionOptions`/`AccountKeys`…）。
//! 2. 官方雲（較舊的 IdentityServer 形態）：`encrypted_payload` 為 base64(JSON)，
//!    裡面才有 `Keys`／`MasterPassword`。
//! 3. 巢狀 `Keys`/`keys` 物件（openapi 產生器的 `TokenResponse.keys`）。
//!
//! `UserDecryptionOptions` 缺失**不是錯誤**：vaultwarden#6729 就是官方 CLI 把它當
//! 必要欄位，打爆了尚未提供該欄位的舊 Vaultwarden。這裡缺欄位只記 quirk。

use base64::Engine as _;
use serde_json::Value;

use crate::Client;
use crate::error::{ApiError, ServerError};
use crate::json::{get, get_bool, get_i64, get_str, has_field};
use crate::profile::Quirk;

/// 認證用的 grant。master password hash 由呼叫方（bw-keys/bw-crypto）算好傳入：
/// bw-server 不做金鑰派生，也不鏈接 bw-crypto。
#[derive(Clone, Debug)]
pub enum TokenGrant {
    Password {
        email: String,
        master_password_hash: String,
        device_identifier: String,
    },
    ClientCredentials {
        client_id: String,
        client_secret: String,
    },
}

/// 第二因子輸入。`provider` 是協定層的編號（見 [`crate::TwoFactorProviderType`]）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondFactor {
    pub provider: crate::TwoFactorProviderType,
    pub token: String,
    /// 要求伺服器記住此裝置（`twoFactorRemember=1`）。
    pub remember: bool,
}

/// password grant 的完整請求參數（device 資訊在官方雲會被記錄到 devices 清單）。
#[derive(Clone, Debug)]
pub struct PasswordLogin {
    pub email: String,
    pub master_password_hash: String,
    pub device_identifier: String,
    pub device_name: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub two_factor: Option<SecondFactor>,
}

impl PasswordLogin {
    pub fn new(
        email: impl Into<String>,
        master_password_hash: impl Into<String>,
        device_identifier: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            master_password_hash: master_password_hash.into(),
            device_identifier: device_identifier.into(),
            device_name: None,
            client_id: None,
            scope: None,
            two_factor: None,
        }
    }

    pub fn two_factor(
        mut self,
        provider: crate::TwoFactorProviderType,
        token: impl Into<String>,
        remember: bool,
    ) -> Self {
        self.two_factor = Some(SecondFactor {
            provider,
            token: token.into(),
            remember,
        });
        self
    }
}

/// 成功登入後拿到的東西。`keys` 為 None 代表伺服器完全沒給金鑰資訊
/// （client_credentials 就是這種：API key 不解鎖 vault）。
#[derive(Clone, Debug)]
pub struct TokenBundle {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: String,
    pub keys: Option<KeysBundle>,
    /// 伺服器原樣回應（token 已保留；這是 raw mirror 的來源）。
    pub raw: Value,
}

/// 寬容解析後的 Keys 物件。缺的欄位就是 None，不炸。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeysBundle {
    /// 加密的 user key（`2.iv|ct|mac`），由 master key 解封。
    pub key: Option<String>,
    pub private_key: Option<String>,
    pub kdf: Option<i64>,
    pub kdf_iterations: Option<i64>,
    pub kdf_memory: Option<i64>,
    pub kdf_parallelism: Option<i64>,
    /// `UserDecryptionOptions` 原樣保留（TDE/KeyConnector 的分支資訊都在裡面）。
    pub user_decryption_options: Option<Value>,
    /// 伺服器有沒有回這個欄位；false + `Quirk::MissingUserDecryptionOptions` ⇒ 舊 server。
    pub has_user_decryption_options: bool,
    pub master_password_policy: Option<Value>,
    pub account_keys: Option<Value>,
    pub force_password_reset: bool,
    pub reset_master_password: bool,
    /// `encrypted_payload` 解開後的內容（若有），保留給上層查未建模欄位。
    pub encrypted_payload: Option<Value>,
    pub raw: Value,
}

impl KeysBundle {
    /// 解析後的 quirk 集合，供 ServerProfile 累加。
    pub fn quirks(&self) -> Vec<Quirk> {
        let mut q = Vec::new();
        if !self.has_user_decryption_options {
            q.push(Quirk::MissingUserDecryptionOptions);
        }
        if self.key.is_none()
            && self.user_decryption_options.is_none()
            && self.encrypted_payload.is_none()
        {
            q.push(Quirk::TokenWithoutKeys);
        }
        q
    }
}

/// 2FA 挑戰：第一步被擋下時的狀態，可直接重試。
#[derive(Clone, Debug)]
pub struct TwoFactorChallenge {
    pub login: PasswordLogin,
    pub providers: Vec<TwoFactorProvider>,
    /// 伺服器原樣 400 體（含 `TwoFactorProviders2` 的各 provider 詳細資料）。
    pub raw: Value,
    pub error: String,
}

impl std::fmt::Display for TwoFactorChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self.providers.iter().map(|p| p.to_string()).collect();
        write!(f, "providers [{}]", names.join(", "))
    }
}

impl TwoFactorChallenge {
    /// 第二步：同一個 password grant 加上 2FA 參數重送。
    ///
    /// 表單欄位與 `Two-Factor-Provider`/`Two-Factor-Token` header **同時**送出：
    /// 官方 client 以 header 重試（`docs/research/protocol.md` §1），而 Vaultwarden
    /// 1.37.2 只讀表單欄位（實測：只送 header 仍回 400 `Two factor required.`，
    /// 見 fixtures/token_2fa_retry_headers_vw.json）。
    pub async fn retry(
        &self,
        client: &Client,
        token: &str,
        remember: bool,
    ) -> Result<TokenBundle, ServerError> {
        let provider = self
            .providers
            .first()
            .map(|p| p.kind)
            .ok_or_else(|| ServerError::Rejected("challenge listed no provider".to_owned()))?;
        self.retry_with(client, provider, token, remember).await
    }

    pub async fn retry_with(
        &self,
        client: &Client,
        provider: crate::TwoFactorProviderType,
        token: &str,
        remember: bool,
    ) -> Result<TokenBundle, ServerError> {
        let mut login = self.login.clone();
        login.two_factor = Some(SecondFactor {
            provider,
            token: token.to_owned(),
            remember,
        });
        client.password_login(&login).await
    }
}

/// 伺服器宣告可用的第二因子。編號對齊 upstream `TwoFactorProviderType`
/// （https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/db/models/two_factor.rs#L28-L48）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TwoFactorProviderType {
    Authenticator,
    Email,
    Duo,
    YubiKey,
    U2f,
    Remember,
    OrganizationDuo,
    Webauthn,
    RecoveryCode,
    Other(i32),
}

impl TwoFactorProviderType {
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Authenticator => 0,
            Self::Email => 1,
            Self::Duo => 2,
            Self::YubiKey => 3,
            Self::U2f => 4,
            Self::Remember => 5,
            Self::OrganizationDuo => 6,
            Self::Webauthn => 7,
            Self::RecoveryCode => 8,
            Self::Other(n) => n,
        }
    }

    pub fn from_i32(n: i32) -> Self {
        match n {
            0 => Self::Authenticator,
            1 => Self::Email,
            2 => Self::Duo,
            3 => Self::YubiKey,
            4 => Self::U2f,
            5 => Self::Remember,
            6 => Self::OrganizationDuo,
            7 => Self::Webauthn,
            8 => Self::RecoveryCode,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for TwoFactorProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Authenticator => "Authenticator",
            Self::Email => "Email",
            Self::Duo => "Duo",
            Self::YubiKey => "YubiKey",
            Self::U2f => "U2f",
            Self::Remember => "Remember",
            Self::OrganizationDuo => "OrganizationDuo",
            Self::Webauthn => "Webauthn",
            Self::RecoveryCode => "RecoveryCode",
            Self::Other(n) => return write!(f, "Other({n})"),
        };
        f.write_str(name)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFactorProvider {
    pub kind: TwoFactorProviderType,
    /// `TwoFactorProviders2` 內的詳細資料（Email 的掩碼地址、WebAuthn 的 credential id…）。
    pub details: Option<Value>,
}

impl std::fmt::Display for TwoFactorProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)
    }
}

pub fn build_form(login: &PasswordLogin, defaults: &crate::ClientOptions) -> Vec<(String, String)> {
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".to_owned(), "password".to_owned()),
        ("username".to_owned(), login.email.clone()),
        ("password".to_owned(), login.master_password_hash.clone()),
        (
            "scope".to_owned(),
            login
                .scope
                .clone()
                .unwrap_or_else(|| defaults.scope.clone()),
        ),
        (
            "client_id".to_owned(),
            login
                .client_id
                .clone()
                .unwrap_or_else(|| defaults.client_id.clone()),
        ),
        (
            "deviceIdentifier".to_owned(),
            login.device_identifier.clone(),
        ),
        (
            "deviceName".to_owned(),
            login
                .device_name
                .clone()
                .unwrap_or_else(|| defaults.device_name.clone()),
        ),
        ("deviceType".to_owned(), defaults.device_type.to_string()),
    ];
    if let Some(sf) = &login.two_factor {
        form.push((
            "twoFactorProvider".to_owned(),
            sf.provider.as_i32().to_string(),
        ));
        form.push(("twoFactorToken".to_owned(), sf.token.clone()));
        form.push((
            "twoFactorRemember".to_owned(),
            if sf.remember { "1" } else { "0" }.to_owned(),
        ));
    }
    form
}

/// 解析 400 `invalid_grant` 的 2FA 挑戰體。
///
/// `TwoFactorProviders` 有兩種形態：官方雲是 map（`{"0":"Authenticator","1":"Email"}`），
/// Vaultwarden 1.37.2 是字串陣列（`["0"]`）。兩者都要能讀出可用的 provider 清單。
pub fn parse_two_factor_challenge(
    err: &ApiError,
    login: PasswordLogin,
) -> Option<TwoFactorChallenge> {
    if !err.is_invalid_grant() {
        return None;
    }
    let body: Value = serde_json::from_str(&err.raw).ok()?;
    let listed = get(
        &body,
        &[
            "TwoFactorProviders",
            "twoFactorProviders",
            "two_factor_providers",
        ],
    )?;
    let details = get(&body, &["TwoFactorProviders2", "twoFactorProviders2"])
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut providers: Vec<TwoFactorProvider> = Vec::new();
    match listed {
        Value::Array(items) => {
            for item in items {
                if let Some(n) = number_of(item) {
                    providers.push(TwoFactorProvider {
                        kind: TwoFactorProviderType::from_i32(n),
                        details: details.get(&n.to_string()).cloned(),
                    });
                }
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(n) = k.parse::<i32>().ok().or_else(|| number_of(v)) {
                    providers.push(TwoFactorProvider {
                        kind: TwoFactorProviderType::from_i32(n),
                        // 詳細資料一律從 `TwoFactorProviders2` 取（這裡的 value 常常只是名稱）
                        details: details
                            .get(&n.to_string())
                            .filter(|d| !d.is_null())
                            .cloned(),
                    });
                }
            }
        }
        _ => {}
    }
    if providers.is_empty() {
        return None;
    }
    Some(TwoFactorChallenge {
        login,
        providers,
        raw: body,
        error: err
            .error_description
            .clone()
            .unwrap_or_else(|| err.message.clone()),
    })
}

fn number_of(v: &Value) -> Option<i32> {
    match v {
        Value::Number(n) => n.as_i64().map(|i| i as i32),
        Value::String(s) => s.parse::<i32>().ok(),
        _ => None,
    }
}

/// 從 token 回應抽出 Keys。找不到任何金鑰形態時回 None（呼叫方記 quirk）。
pub fn parse_keys(response: &Value) -> Option<KeysBundle> {
    let payload = decode_encrypted_payload(response);
    // 優先序：扁平（VW 現行）→ 巢狀 keys → encrypted_payload 內部
    let source = if has_field(
        response,
        &["Key", "PrivateKey", "Kdf", "UserDecryptionOptions"],
    ) {
        response.clone()
    } else if let Some(keys) = get(response, &["Keys", "keys"]) {
        keys.clone()
    } else if let Some(inner) = payload.as_ref().and_then(|p| get(p, &["Keys", "keys"])) {
        inner.clone()
    } else {
        payload.clone()?
    };

    let has_udo = has_field(&source, &["UserDecryptionOptions", "userDecryptionOptions"]);
    Some(KeysBundle {
        key: get_str(&source, &["Key", "key"]).map(str::to_owned),
        private_key: get_str(&source, &["PrivateKey", "privateKey"]).map(str::to_owned),
        kdf: get_i64(&source, &["Kdf", "kdf"]),
        kdf_iterations: get_i64(&source, &["KdfIterations", "kdfIterations", "iterations"]),
        kdf_memory: get_i64(&source, &["KdfMemory", "kdfMemory", "memory"]),
        kdf_parallelism: get_i64(
            &source,
            &["KdfParallelism", "kdfParallelism", "parallelism"],
        ),
        user_decryption_options: get(&source, &["UserDecryptionOptions", "userDecryptionOptions"])
            .cloned(),
        has_user_decryption_options: has_udo,
        master_password_policy: get(&source, &["MasterPasswordPolicy", "masterPasswordPolicy"])
            .cloned(),
        account_keys: get(&source, &["AccountKeys", "accountKeys"]).cloned(),
        force_password_reset: get_bool(&source, &["ForcePasswordReset", "forcePasswordReset"])
            .unwrap_or(false),
        reset_master_password: get_bool(&source, &["ResetMasterPassword", "resetMasterPassword"])
            .unwrap_or(false),
        encrypted_payload: payload,
        raw: source.clone(),
    })
}

/// `encrypted_payload`：base64(UTF-8 JSON)。有些 server 回的是已解碼的物件，兩態都吃。
pub fn decode_encrypted_payload(response: &Value) -> Option<Value> {
    let raw = get(
        response,
        &["encrypted_payload", "encryptedPayload", "EncryptedPayload"],
    )?;
    match raw {
        Value::Object(_) | Value::Array(_) => Some(raw.clone()),
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .ok()?;
            serde_json::from_slice(&bytes).ok()
        }
        _ => None,
    }
}

pub(crate) fn parse_token_bundle(response: &Value) -> Result<TokenBundle, ServerError> {
    let access_token = get_str(response, &["access_token", "accessToken", "Access_Token"])
        .ok_or_else(|| ServerError::Malformed("token response has no access_token".to_owned()))?
        .to_owned();
    Ok(TokenBundle {
        access_token,
        refresh_token: get_str(response, &["refresh_token", "refreshToken"]).map(str::to_owned),
        expires_in: get_i64(response, &["expires_in", "expiresIn"]),
        token_type: get_str(response, &["token_type", "tokenType"])
            .unwrap_or("Bearer")
            .to_owned(),
        keys: parse_keys(response),
        raw: response.clone(),
    })
}

pub(crate) fn client_credentials_form(
    client_id: &str,
    client_secret: &str,
    device_identifier: Option<&str>,
    defaults: &crate::ClientOptions,
) -> Vec<(String, String)> {
    let mut form = vec![
        ("grant_type".to_owned(), "client_credentials".to_owned()),
        ("client_id".to_owned(), client_id.to_owned()),
        ("client_secret".to_owned(), client_secret.to_owned()),
        ("scope".to_owned(), defaults.api_key_scope.clone()),
    ];
    // Vaultwarden 1.37.2 對 API key 登入也要求裝置資訊（缺了回 400
    // `device_identifier cannot be blank`）；官方雲沒差，帶了也不會壞。
    // https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/identity.rs#L597-L660
    if let Some(id) = device_identifier {
        form.push(("deviceIdentifier".to_owned(), id.to_owned()));
        form.push(("deviceName".to_owned(), defaults.device_name.clone()));
        form.push(("deviceType".to_owned(), defaults.device_type.to_string()));
    }
    form
}

pub(crate) fn refresh_form(
    refresh_token: &str,
    defaults: &crate::ClientOptions,
) -> Vec<(String, String)> {
    vec![
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("refresh_token".to_owned(), refresh_token.to_owned()),
        ("client_id".to_owned(), defaults.client_id.clone()),
        ("scope".to_owned(), defaults.scope.clone()),
    ]
}
