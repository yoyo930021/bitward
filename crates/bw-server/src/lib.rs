//! # bw-server — Bitwarden Client API 用戶端
//!
//! 本 crate 是整個產品裡**唯一碰外部 HTTP/WS 的地方**（契约 §3 依賴方向）。
//! 型別契約見 `docs/ARCHITECTURE.md` §3.3（原 `warden-proto::BitwardenApi`）與 §2.6。
//!
//! 設計原則：
//! 1. **欄位寬容 + raw mirror**。Client API 沒有官方 spec，欄位隨 server 版本漂移
//!    （vaultwarden#6729 就是「把新欄位當必要」造成的當機）。所有回應先當 `Value` 收下，
//!    解析只取需要且存在的欄位，原始 JSON 一併回傳給鏡像層。
//! 2. **探測而非假設**。[`Client::probe`] 用 `GET /config`（+ `/api/config`）、
//!    `/api/version`、OpenID 發現文件判別 server 形態與能力，結果存程序記憶體（§5）。
//! 3. **金鑰語意在別處**。master password hash 是**已算好的字串**輸入；派生屬 bw-crypto，
//!    bw-server 不鏈接它（依賴方向：bw-crypto ← bw-keys ← …，本 crate 只依賴 bw-proto）。
//!
//! ## 端點對照（VW = Vaultwarden 1.37.2 實錄，見 `fixtures/README.md`）
//!
//! | 契約 | 端點 | 備註 |
//! |---|---|---|
//! | token（password，2FA 兩步） | `POST {identity}/connect/token` | 第二步同端點加 `twoFactorProvider`/`twoFactorToken` |
//! | token（client_credentials） | 同上 | 個人 API key，不解鎖 vault |
//! | token（refresh） | 同上 | `grant_type=refresh_token` |
//! | sync | `GET {api}/sync` | |
//! | ciphers | `GET/POST {api}/ciphers`、`GET/PUT/DELETE {api}/ciphers/{id}` | 軟刪 `PUT .../delete`、還原 `POST|PUT .../restore` |
//! | 附件 v2 | `POST {api}/ciphers/{id}/attachment/v2`、`GET/DELETE .../attachment/{aid}` | 只取 URL，上傳 PUT 由呼叫方做 |
//! | 探測 | `GET {api}/config`、`GET {api}/version`、`GET {identity}/.well-known/openid-configuration` | |
//! | notifications | `WS {notifications}/hub?access_token=…` | 官方 json hub protocol；VW messagepack |

pub mod auth;
pub mod error;
pub mod json;
pub mod notify;
pub mod profile;
pub mod vault;

pub use auth::{
    KeysBundle, PasswordLogin, SecondFactor, TokenBundle, TokenGrant, TwoFactorChallenge,
    TwoFactorProvider, TwoFactorProviderType,
};
pub use error::{ApiError, ServerError};
pub use notify::{NotificationMode, Notifications, ServerEvent, UpdateType};
pub use profile::{Quirk, ServerProbe, ServerUrls, feature};
pub use vault::{AttachmentDownload, AttachmentUpload, DeleteKind, NewAttachment, SyncResponse};

pub use bw_proto::{ItemId, ServerKind, ServerProfile};

use base64::Engine as _;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;

pub(crate) use json::get;

/// 每個請求都帶的固定資訊。`client_id` 用 desktop 是官方桌機/CLI 的既有做法
/// （`docs/research/protocol.md` §1：password grant 的 scope 為 `api offline_access`）。
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub client_id: String,
    pub device_name: String,
    /// 編號見 https://github.com/bitwarden/clients/blob/main/libs/common/src/enums/device-type.enum.ts
    /// （WindowsCLI=23、MacOsCLI=24、LinuxCLI=25；Vaultwarden 用同一套編號）。
    pub device_type: i32,
    pub scope: String,
    /// API key（client_credentials）用的 scope：官方只給 `api`，沒有 `offline_access`。
    pub api_key_scope: String,
    pub user_agent: String,
    pub request_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            client_id: "desktop".to_owned(),
            device_name: "bitward".to_owned(),
            device_type: default_device_type(),
            scope: "api offline_access".to_owned(),
            api_key_scope: "api".to_owned(),
            user_agent: concat!("bitward/", env!("CARGO_PKG_VERSION")).to_owned(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

fn default_device_type() -> i32 {
    if cfg!(target_os = "macos") {
        24
    } else if cfg!(target_os = "windows") {
        23
    } else {
        25
    }
}

#[derive(Default)]
struct State {
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_id: Option<String>,
    probe: Option<ServerProbe>,
    urls: Option<ServerUrls>,
    /// 打過探測了沒（即使全失敗也要記住，免得每個請求都重探一次）
    probed: bool,
}

/// 一個帳號對一個 server 的連線。可跨 `.await` 複製使用（內部是 `Arc`-free 的 RwLock 狀態）。
pub struct Client {
    base: Url,
    http: reqwest::Client,
    options: ClientOptions,
    state: RwLock<State>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base.as_str())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// 建立帳號用（VW 預設開放註冊；官方雲走 web vault 的註冊流程）。
#[derive(Clone, Debug)]
pub struct NewAccount {
    pub email: String,
    pub name: String,
    pub master_password_hash: String,
    /// 加密後的 user key（`2.iv|ct|mac`）。
    pub key: String,
    pub public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    pub master_password_hint: Option<String>,
    /// 0 = PBKDF2-SHA256（預設 600,000 次），1 = Argon2id。
    /// 來源：https://bitwarden.com/help/kdf-algorithms
    pub kdf: i32,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

impl NewAccount {
    pub fn new(
        email: impl Into<String>,
        name: impl Into<String>,
        master_password_hash: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
            master_password_hash: master_password_hash.into(),
            key: key.into(),
            public_key: None,
            encrypted_private_key: None,
            master_password_hint: None,
            kdf: 0,
            kdf_iterations: 600_000,
            kdf_memory: None,
            kdf_parallelism: None,
        }
    }
}

impl Client {
    pub fn new(base_url: &str) -> Result<Self, ServerError> {
        Self::with_options(base_url, ClientOptions::default())
    }

    pub fn with_options(base_url: &str, options: ClientOptions) -> Result<Self, ServerError> {
        let mut base = Url::parse(base_url)?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let http = reqwest::Client::builder()
            .user_agent(options.user_agent.clone())
            .timeout(options.request_timeout)
            .build()
            .map_err(|e| ServerError::Rejected(e.to_string()))?;
        Ok(Self {
            base,
            http,
            options,
            state: RwLock::new(State::default()),
        })
    }

    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }

    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// 某個子服務（api/identity/notifications/events/vault）的 base URL。
    /// 探測到 `/config` 的 `environment` 時用探索值，否則用 `<base>/<segment>`
    /// （self-hosted 的標準佈局：Vaultwarden 把 core 掛在 `/api`、identity 掛在 `/identity`，
    /// 見 https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/main.rs#L585-L591）。
    /// 某個子服務的 base URL（探測到的 `environment` 優先，並對別名 origin 做 rebase）。
    /// 給需要自己發請求的呼叫方用（例如附件上傳由 bw-sync 做）。
    pub async fn service_url(&self, segment: &str) -> String {
        self.url(segment).await
    }

    pub(crate) async fn url(&self, segment: &str) -> String {
        let discovered = self.state.read().await.urls.clone();
        if let Some(urls) = discovered {
            let found = match segment {
                "api" => urls.api,
                "identity" => urls.identity,
                "notifications" => urls.notifications,
                "events" => urls.events,
                "vault" => urls.vault,
                _ => None,
            };
            if let Some(f) = found {
                return f.trim_end_matches('/').to_owned();
            }
        }
        match self.base.join(segment) {
            Ok(u) => u.to_string().trim_end_matches('/').to_owned(),
            Err(_) => format!("{}{}", self.base, segment),
        }
    }

    // —— session 狀態 ——

    pub async fn set_access_token(&self, token: &str) {
        let mut st = self.state.write().await;
        st.access_token = Some(token.to_owned());
        st.user_id = crate::jwt_claim_str(token, "sub");
    }

    pub async fn access_token(&self) -> Option<String> {
        self.state.read().await.access_token.clone()
    }

    pub async fn refresh_token(&self) -> Option<String> {
        self.state.read().await.refresh_token.clone()
    }

    /// JWT `sub` claim（帳號 id）；不需要驗證簽章，只用来當 hub 的 group key。
    pub async fn user_id(&self) -> Option<String> {
        let st = self.state.read().await;
        st.user_id.clone().or_else(|| {
            st.access_token
                .as_deref()
                .and_then(|t| crate::jwt_claim_str(t, "sub"))
        })
    }

    pub async fn signed_in(&self) -> bool {
        self.state.read().await.access_token.is_some()
    }

    /// 丟棄 token 與探測結果（鎖定不等於登出；見契约 §2.2）。
    pub async fn sign_out(&self) {
        let mut st = self.state.write().await;
        st.access_token = None;
        st.refresh_token = None;
        st.user_id = None;
    }

    // —— token ——

    /// `POST /connect/token`。password grant 遇到第二因子時回
    /// [`ServerError::TwoFactorRequired`]，用 [`TwoFactorChallenge::retry`] 完成第二步。
    pub async fn token(&self, grant: TokenGrant) -> Result<TokenBundle, ServerError> {
        match grant {
            TokenGrant::Password {
                email,
                master_password_hash,
                device_identifier,
            } => {
                self.password_login(&PasswordLogin::new(
                    email,
                    master_password_hash,
                    device_identifier,
                ))
                .await
            }
            TokenGrant::ClientCredentials {
                client_id,
                client_secret,
            } => self.client_credentials(&client_id, &client_secret).await,
        }
    }

    pub async fn password_login(&self, login: &PasswordLogin) -> Result<TokenBundle, ServerError> {
        let form = auth::build_form(login, &self.options);
        let identity = self.url("identity").await;
        let url = format!("{identity}/connect/token");
        let mut req = self.http.post(&url).form(&form);
        if let Some(sf) = &login.two_factor {
            // 官方 client 用 header 重試；VW 只讀表單欄位，兩個都送（見 TwoFactorChallenge::retry）
            req = req
                .header("Two-Factor-Provider", sf.provider.as_i32().to_string())
                .header("Two-Factor-Token", sf.token.clone());
        }
        let (status, body) = self.send(req).await?;
        let value = match self.parse_ok(status, &body) {
            Ok(v) => v,
            Err(err) => {
                let challenge = err
                    .is_invalid_grant()
                    .then(|| auth::parse_two_factor_challenge(&err, login.clone()))
                    .flatten();
                return match challenge {
                    Some(challenge) => Err(ServerError::TwoFactorRequired {
                        challenge: Box::new(challenge),
                    }),
                    None => Err(err.into_server_error()),
                };
            }
        };
        self.finish_token(value).await
    }

    /// 個人 API key（`client_credentials`）。只給 `api` scope，回應裡沒有 Keys。
    /// API key 登入。`device_identifier` 為 None 時用 client_id 充當（VW 要求此欄位）。
    pub async fn client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenBundle, ServerError> {
        let form =
            auth::client_credentials_form(client_id, client_secret, Some(client_id), &self.options);
        let identity = self.url("identity").await;
        let (status, body) = self
            .send(
                self.http
                    .post(format!("{identity}/connect/token"))
                    .form(&form),
            )
            .await?;
        let value = self
            .parse_ok(status, &body)
            .map_err(|e| e.into_server_error())?;
        self.finish_token(value).await
    }

    /// 用目前（或指定）的 refresh token 換新的 access token。
    pub async fn refresh(&self) -> Result<TokenBundle, ServerError> {
        let stored = self.refresh_token().await;
        let token = stored.ok_or(ServerError::Unauthenticated)?;
        self.refresh_with(&token).await
    }

    pub async fn refresh_with(&self, refresh_token: &str) -> Result<TokenBundle, ServerError> {
        let form = auth::refresh_form(refresh_token, &self.options);
        let identity = self.url("identity").await;
        let (status, body) = self
            .send(
                self.http
                    .post(format!("{identity}/connect/token"))
                    .form(&form),
            )
            .await?;
        let value = self
            .parse_ok(status, &body)
            .map_err(|e| e.into_server_error())?;
        self.finish_token(value).await
    }

    async fn finish_token(&self, value: Value) -> Result<TokenBundle, ServerError> {
        let bundle = auth::parse_token_bundle(&value)?;
        let mut st = self.state.write().await;
        st.access_token = Some(bundle.access_token.clone());
        st.user_id = crate::jwt_claim_str(&bundle.access_token, "sub");
        if let Some(r) = bundle.refresh_token.clone() {
            st.refresh_token = Some(r);
        }
        drop(st);
        if let Some(keys) = &bundle.keys {
            self.record_quirks(keys.quirks()).await;
        } else {
            self.record_quirk(Quirk::TokenWithoutKeys).await;
        }
        Ok(bundle)
    }

    /// 建立帳號：`POST {identity}/accounts/register`（VW 1.37.2 實錄），
    /// 沒有這條 route 時退到 `{base}/accounts/register`。
    ///
    /// body 用「舊形」`{kdf, kdfIterations, key, masterPasswordHash}`；
    /// Vaultwarden 同時接受新形 `{masterPasswordAuthentication, masterPasswordUnlock}`，
    /// 舊形對官方雲也長年可用（https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/accounts.rs#L94-L160）。
    pub async fn register(&self, account: &NewAccount) -> Result<Value, ServerError> {
        let mut body = json!({
            "email": account.email,
            "name": account.name,
            "key": account.key,
            "masterPasswordHash": account.master_password_hash,
            "kdf": account.kdf,
            "kdfIterations": account.kdf_iterations,
            "kdfMemory": account.kdf_memory,
            "kdfParallelism": account.kdf_parallelism,
            "masterPasswordHint": account.master_password_hint,
        });
        if let (Some(pub_key), Some(enc_priv)) =
            (&account.public_key, &account.encrypted_private_key)
        {
            body["keys"] = json!({ "publicKey": pub_key, "encryptedPrivateKey": enc_priv });
        }
        let identity = self.url("identity").await;
        let (status, body_txt) = self
            .send(
                self.http
                    .post(format!("{identity}/accounts/register"))
                    .json(&body),
            )
            .await?;
        match self.parse_ok(status, &body_txt) {
            Ok(v) => Ok(v),
            Err(err) if err.is_route_missing() => {
                let (status2, body2) = self
                    .send(
                        self.http
                            .post(format!(
                                "{}/accounts/register",
                                self.base.as_str().trim_end_matches('/')
                            ))
                            .json(&body),
                    )
                    .await?;
                self.parse_ok(status2, &body2)
                    .map_err(|e| e.into_server_error())
            }
            Err(e) => Err(e.into_server_error()),
        }
    }

    /// `POST {api}/accounts/prelogin`：登入前取 KDF 參數（Argon2 帳號需要 memory/parallelism）。
    pub async fn prelogin(&self, email: &str) -> Result<Value, ServerError> {
        let identity = self.url("identity").await;
        let (status, body) = self
            .send(
                self.http
                    .post(format!("{identity}/accounts/prelogin"))
                    .json(&json!({"email": email})),
            )
            .await?;
        self.parse_ok(status, &body)
            .map_err(|e| e.into_server_error())
    }

    // —— 探測 ——

    /// 探測 server 形態/能力/quirks（契约 §2.6）。已探測過就直接回快取。
    pub async fn probe(&self) -> ServerProbe {
        if self.state.read().await.probed {
            return self.cached_probe().await;
        }
        self.probe_now().await
    }

    /// 只讀快取；沒探測過回一個 `Unknown` 的骨架（不觸發網路）。
    pub async fn cached_probe(&self) -> ServerProbe {
        self.state
            .read()
            .await
            .probe
            .clone()
            .unwrap_or_else(|| ServerProbe {
                profile: ServerProfile {
                    kind: ServerKind::Unknown,
                    version: None,
                    features: Vec::new(),
                },
                ..Default::default()
            })
    }

    /// 強制重新探測並更新快取。判讀本身是純函數 [`profile::assemble`]，
    /// 這裡只負責把三個探點的材料收齊（任何一點失敗都不讓探測失敗）。
    pub async fn probe_now(&self) -> ServerProbe {
        let api = self.url("api").await;
        let identity = self.url("identity").await;

        // 1) /config：Vaultwarden 只在 `/api/config`（實錄：根路徑回 HTML 404，
        //    fixtures/config_vw_root_404.html）；官方雲兩者都有。先打 /api/config 再退根路徑。
        let mut config = None;
        let mut config_at_api = false;
        for (url, under_api) in [
            (format!("{api}/config"), true),
            (
                format!("{}/config", self.base.as_str().trim_end_matches('/')),
                false,
            ),
        ] {
            match self.send(self.http.get(&url)).await {
                Ok((status, body)) if (200..299).contains(&status) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&body) {
                        config = Some(v);
                        config_at_api = under_api;
                        break;
                    }
                }
                Ok((status, _)) => tracing::debug!(url, status, "config probe not usable"),
                Err(e) => tracing::debug!(url, error = %e, "config probe failed"),
            }
        }

        // 2) /api/version：Vaultwarden 獨有，回產品版本（實錄 "1.37.2"）；官方雲沒有。
        let product_version = match self.send(self.http.get(format!("{api}/version"))).await {
            Ok((status, body)) if (200..299).contains(&status) => {
                serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
            }
            _ => None,
        };

        // 3) OpenID 發現：官方雲有（JWKS/RS256 都在裡面），VW 1.37.2 沒有
        //    （實錄：回 Rocket 的 422 HTML，fixtures/wellknown_vw_422.html）。
        let discovery = match self
            .send(
                self.http
                    .get(format!("{identity}/.well-known/openid-configuration")),
            )
            .await
        {
            Ok((status, body)) if (200..299).contains(&status) => {
                serde_json::from_str::<Value>(&body).ok()
            }
            _ => None,
        };

        let probe = profile::assemble(&profile::ProbeInputs {
            base_url: self.base.as_str().to_owned(),
            config,
            config_at_api,
            product_version,
            discovery,
        });

        let mut st = self.state.write().await;
        st.probe = Some(probe.clone());
        st.probed = true;
        if st.urls.is_none() {
            st.urls = Some(probe.urls.clone());
        }
        probe
    }

    /// 合併 runtime 觀察到的 quirk（寬容路徑走過哪條就記哪條）。
    pub async fn record_quirk(&self, q: Quirk) {
        self.record_quirks(vec![q]).await;
    }

    async fn record_quirks(&self, qs: Vec<Quirk>) {
        if qs.is_empty() {
            return;
        }
        let mut st = self.state.write().await;
        // 還沒探測過也要有地方記：quirks 是觀測累積，不是探測的專利
        let probe = st.probe.get_or_insert_with(ServerProbe::default);
        for q in qs {
            probe.record(q);
        }
    }

    pub(crate) async fn observe_sync(&self, sync: &Value) {
        let mut st = self.state.write().await;
        // 同上：/sync 常常是第一個碰到未建模欄位形態的地方
        let probe = st.probe.get_or_insert_with(ServerProbe::default);
        probe.observe_sync(sync);
    }

    // —— HTTP 基底 ——

    pub(crate) async fn send(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<(u16, String), ServerError> {
        let resp = req.send().await?;
        let status = u16::from(resp.status());
        let text = resp.text().await?;
        Ok((status, text))
    }

    /// 2xx → JSON（解析失敗視為畸形回應）；其他 → 解析過的 [`ApiError`]。
    pub(crate) fn parse_ok(&self, status: u16, body: &str) -> Result<Value, Box<ApiError>> {
        if (200..299).contains(&status) {
            if body.trim().is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_str(body).map_err(|e| {
                Box::new(ApiError {
                    status,
                    message: format!("response is not json: {e}"),
                    validation_errors: Vec::new(),
                    error: None,
                    error_description: None,
                    non_json: true,
                    raw: body.to_owned(),
                })
            });
        }
        Err(Box::new(ApiError::parse(status, body)))
    }

    async fn authorized(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.state.read().await.access_token.clone() {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn require_token(&self) -> Result<(), ServerError> {
        if self.signed_in().await {
            Ok(())
        } else {
            Err(ServerError::Unauthenticated)
        }
    }

    pub(crate) async fn get_json(&self, path: &str) -> Result<Value, ServerError> {
        self.require_token().await?;
        let url = format!("{}/{}", self.url("api").await, path);
        let req = self.authorized(self.http.get(&url)).await;
        let (status, body) = self.send(req).await?;
        match self.parse_ok(status, &body) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into_server_error()),
        }
    }

    pub(crate) async fn post_json(&self, path: &str, body: &Value) -> Result<Value, ServerError> {
        self.require_token().await?;
        let url = format!("{}/{}", self.url("api").await, path);
        let req = self.authorized(self.http.post(&url)).await;
        let (status, text) = self.send(req.json(body)).await?;
        match self.parse_ok(status, &text) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into_server_error()),
        }
    }

    pub(crate) async fn put_json(&self, path: &str, body: &Value) -> Result<Value, ServerError> {
        self.require_token().await?;
        let url = format!("{}/{}", self.url("api").await, path);
        let req = self.authorized(self.http.put(&url)).await;
        let (status, text) = self.send(req.json(body)).await?;
        match self.parse_ok(status, &text) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into_server_error()),
        }
    }

    pub(crate) async fn delete_json(&self, path: &str) -> Result<Value, ServerError> {
        self.require_token().await?;
        let url = format!("{}/{}", self.url("api").await, path);
        let req = self.authorized(self.http.delete(&url)).await;
        let (status, text) = self.send(req).await?;
        match self.parse_ok(status, &text) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into_server_error()),
        }
    }

    // 無回應體的寫入（delete/restore 之類）。

    pub(crate) async fn try_empty_put(&self, path: &str) -> Result<(), ServerError> {
        self.put_json(path, &Value::Null).await.map(|_| ())
    }

    pub(crate) async fn try_empty_post(&self, path: &str) -> Result<(), ServerError> {
        self.post_json(path, &Value::Null).await.map(|_| ())
    }

    pub(crate) async fn try_empty_post_body(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(), ServerError> {
        self.post_json(path, body).await.map(|_| ())
    }

    pub(crate) async fn try_empty_delete(&self, path: &str) -> Result<(), ServerError> {
        self.delete_json(path).await.map(|_| ())
    }

    pub(crate) async fn try_empty_put_body(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(), ServerError> {
        self.put_json(path, body).await.map(|_| ())
    }

    pub(crate) async fn try_empty_delete_body(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(), ServerError> {
        self.require_token().await?;
        let url = format!("{}/{}", self.url("api").await, path);
        let req = self.authorized(self.http.delete(&url)).await;
        let (status, text) = self.send(req.json(body)).await?;
        match self.parse_ok(status, &text) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into_server_error()),
        }
    }
}

/// 讀 JWT 的第二段（claims）。只取字串欄位，不做簽章驗證——
/// 簽章驗證在 P1 之後若要，應獨立成明確的一步，不是這裡的責任。
pub(crate) fn jwt_claim_str(token: &str, claim: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    get(&value, &[claim])
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 從錄製的真實 access token 取 sub（hub 的群組鍵、API key 的 client_id 都靠它）。
    #[test]
    fn jwt_sub_claim_from_recorded_token() {
        let body = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/token_password_vw_1.37.2.json"
        ))
        .unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        let token = value["access_token"].as_str().unwrap();
        assert_eq!(
            jwt_claim_str(token, "email").as_deref(),
            Some("fixture@bitward.test")
        );
        let sub = jwt_claim_str(token, "sub").unwrap();
        uuid::Uuid::parse_str(&sub).expect("sub 是 user id");
        // 同一帳號的 API key token 必須帶同一個 sub（hub 群組與 device 記錄都以此為鍵）
        let cc: Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/token_client_credentials_vw_1.37.2.json"
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            jwt_claim_str(cc["access_token"].as_str().unwrap(), "sub").as_deref(),
            Some(sub.as_str())
        );
        assert_eq!(jwt_claim_str(token, "nope"), None);
        assert_eq!(jwt_claim_str("not-a-jwt", "sub"), None);
    }

    #[test]
    fn msgpack_timestamp_becomes_rfc3339() {
        // 2026-10-28T18:15:44Z = 1793211344；nanos 放高 30 位（SignalR DateTime ext）
        let seconds: u64 = 1_793_211_344;
        let nanos: u64 = 926_131_500;
        assert_eq!(
            notify::format_rfc3339(seconds as i64, nanos as u32),
            "2026-10-28T18:15:44Z"
        );
        assert_eq!(notify::format_rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(notify::format_rfc3339(-86_400, 0), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn base_url_normalizes_missing_trailing_slash() {
        let client = Client::new("http://127.0.0.1:18080").unwrap();
        assert_eq!(client.base_url(), "http://127.0.0.1:18080/");
        let client = Client::new("http://127.0.0.1:18080/bw").unwrap();
        assert_eq!(client.base_url(), "http://127.0.0.1:18080/bw/");
        assert!(Client::new("不是 url").is_err());
    }

    #[tokio::test]
    async fn service_urls_default_to_self_hosted_layout() {
        let client = Client::new("http://127.0.0.1:18080").unwrap();
        assert_eq!(
            client.service_url("api").await,
            "http://127.0.0.1:18080/api"
        );
        assert_eq!(
            client.service_url("identity").await,
            "http://127.0.0.1:18080/identity"
        );
        assert_eq!(
            client.service_url("notifications").await,
            "http://127.0.0.1:18080/notifications"
        );
    }

    #[tokio::test]
    async fn unauthenticated_calls_fail_fast() {
        let client = Client::new("http://127.0.0.1:1").unwrap();
        assert!(matches!(
            client.sync().await,
            Err(ServerError::Unauthenticated)
        ));
        assert!(matches!(
            client.cipher_get(ItemId::nil()).await,
            Err(ServerError::Unauthenticated)
        ));
        assert!(!client.signed_in().await);
        client.set_access_token("a.b.c").await;
        assert!(client.signed_in().await);
        client.sign_out().await;
        assert!(!client.signed_in().await);
    }

    #[test]
    fn attachment_urls_are_absolute_against_api_base() {
        assert_eq!(
            vault::absolutize("http://h/api", "/ciphers/1/attachment/2"),
            "http://h/api/ciphers/1/attachment/2"
        );
        assert_eq!(
            vault::absolutize("http://h/api/", "ciphers/1"),
            "http://h/api/ciphers/1"
        );
        assert_eq!(
            vault::absolutize("http://h/api", "https://blob.core/1?sig=x"),
            "https://blob.core/1?sig=x",
            "Azure SAS 已經是指名道姓的絕對位址，不能重寫"
        );
    }

    #[test]
    fn signalr_length_prefix_is_a_7bit_varint() {
        // 202 -byte 的 body 前綴是 [0xca, 0x01]（74 | 1<<7）
        assert_eq!(
            notify::strip_length_prefix(&[0xca, 0x01, b'{', b'}']),
            b"{}"
        );
        assert_eq!(notify::strip_length_prefix(&[0x02, b'{', b'}']), b"{}");
    }

    #[test]
    fn options_default_to_cli_device_type() {
        let o = ClientOptions::default();
        assert_eq!(o.client_id, "desktop");
        assert_eq!(o.scope, "api offline_access");
        assert_eq!(o.api_key_scope, "api");
        let expected = if cfg!(target_os = "macos") {
            24
        } else if cfg!(target_os = "windows") {
            23
        } else {
            25
        };
        assert_eq!(o.device_type, expected);
    }
}
