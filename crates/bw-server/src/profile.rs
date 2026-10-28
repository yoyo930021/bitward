//! 協定漂移防禦（契约 §2.6）：`GET /config` + OpenID 發現 + `/sync` 欄位存在性，
//! 產出 [`ServerProfile`] 與 [`Quirk`] 集合。
//!
//! 探測全部是「有就有、沒有就算」：任何一個探點失敗都不讓探測失敗，
//! 因為目標之一就是舊 Vaultwarden 少了新端點（vaultwarden#6729 那類事故）。

use std::collections::BTreeSet;

use bw_proto::{ServerKind, ServerProfile};
use serde_json::Value;

use crate::json::{get, get_bool, get_str, has_field};

/// 觀測到的伺服器怪癖。命名一律「VW/官方在做什麼」，不加情緒。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quirk {
    /// 回應里沒有 `UserDecryptionOptions`（舊 Vaultwarden；vaultwarden#6729）。
    /// 語意是「僅密碼解鎖」，不是錯誤。
    MissingUserDecryptionOptions,
    /// password grant 成功但完全沒給金鑰欄位。
    TokenWithoutKeys,
    /// `TwoFactorProviders` 是字串陣列而非 map（Vaultwarden 1.37.2）。
    TwoFactorProvidersAsArray,
    /// 只送 `Two-Factor-Provider`/`Two-Factor-Token` header 不會被接受，必須用表單欄位
    /// （Vaultwarden 1.37.2 實測）。
    TwoFactorHeadersIgnored,
    /// 軟性刪除走 `PUT /ciphers/{id}/delete`，`POST` 是同路的**永久**刪除（Vaultwarden）。
    SoftDeleteUsesPutVerb,
    /// 還原只認 `PUT /ciphers/{id}/restore`，`POST` 是 404 route-not-found（Vaultwarden）。
    RestoreUsesPutVerb,
    /// 批次刪除的欄位名是 `ids`，不是 upstream 的 `cipherIds`（Vaultwarden）。
    BulkDeleteUsesIdsField,
    /// 附件上傳 URL 是 root-relative path，需自行拼上 server base（Vaultwarden 1.37.2）。
    AttachmentUploadUrlIsRelative,
    /// 沒有 `GET /ciphers/deleted`（Vaultwarden 1.37.2 回 route-not-found）。
    NoDeletedCiphersListing,
    /// `/config` 只在 `/api/config` 有，根路徑 404（Vaultwarden；官方雲兩者都有）。
    ConfigOnlyUnderApi,
    /// 沒有 OpenID 發現文件（Vaultwarden 1.37.2）。
    NoOpenIdDiscovery,
    /// 401/404 等非 2xx 回應是 HTML 頁而非 JSON（Rocket 預設錯誤頁）。
    NonJsonErrorPages,
    /// `/sync` 的 profile 缺少 `organizations` 以外的重要陣列欄位（欄位存在性探測）。
    SyncMissingProfileOrganizations,
    /// 軟刪只有 `POST /ciphers/{id}/delete`（沒有 PUT 形態）。
    SoftDeleteOnlyPostVerb,
    /// 沒有 `PUT /ciphers/{id}/partial`，欄位級 patch 只能整筆覆寫。
    NoPartialUpdateEndpoint,
    /// `/ciphers/{id}/partial` 只認 `folderId` 與 `favorite`，送 password/uri 會回 422
    /// （Vaultwarden 1.37.2 的 `PartialCipherData` 只有這兩個欄位）。
    PartialUpdateLimitedToFolderAndFavorite,
    /// 附件上傳要 `POST` multipart（欄位 `key` + `data`），不是 upstream 的 `PUT` raw body
    /// （Vaultwarden 1.37.2 實測：PUT 回 404 route-not-found）。
    AttachmentUploadRequiresMultipart,
    /// `client_credentials` 也要帶 deviceIdentifier/deviceName/deviceType，否則 400
    /// （Vaultwarden 1.37.2 實測：`device_identifier cannot be blank`）。
    ClientCredentialsRequiresDevice,
}

impl Quirk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingUserDecryptionOptions => "missing-user-decryption-options",
            Self::TokenWithoutKeys => "token-without-keys",
            Self::TwoFactorProvidersAsArray => "twofactor-providers-as-array",
            Self::TwoFactorHeadersIgnored => "twofactor-headers-ignored",
            Self::SoftDeleteUsesPutVerb => "soft-delete-uses-put",
            Self::RestoreUsesPutVerb => "restore-uses-put",
            Self::BulkDeleteUsesIdsField => "bulk-delete-uses-ids-field",
            Self::AttachmentUploadUrlIsRelative => "attachment-upload-url-is-relative",
            Self::NoDeletedCiphersListing => "no-deleted-ciphers-listing",
            Self::ConfigOnlyUnderApi => "config-only-under-api",
            Self::NoOpenIdDiscovery => "no-openid-discovery",
            Self::NonJsonErrorPages => "non-json-error-pages",
            Self::SyncMissingProfileOrganizations => "sync-missing-profile-organizations",
            Self::SoftDeleteOnlyPostVerb => "soft-delete-only-post-verb",
            Self::NoPartialUpdateEndpoint => "no-partial-update-endpoint",
            Self::PartialUpdateLimitedToFolderAndFavorite => {
                "partial-update-limited-to-folder-and-favorite"
            }
            Self::AttachmentUploadRequiresMultipart => "attachment-upload-requires-multipart",
            Self::ClientCredentialsRequiresDevice => "client-credentials-requires-device",
        }
    }
}

impl std::fmt::Display for Quirk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 探測到的能力旗標（`ServerProfile.features` 的內容物）。
pub mod feature {
    pub const CONFIG: &str = "config";
    pub const CONFIG_UNDER_API: &str = "config.under-api";
    pub const VERSION_ENDPOINT: &str = "version-endpoint";
    pub const OPENID_DISCOVERY: &str = "openid-configuration";
    pub const NOTIFICATIONS_WEBSOCKET: &str = "notifications.websocket";
    pub const PUSH_VAPID: &str = "push.vapid";
    pub const SSO: &str = "sso";
    pub const KEY_CONNECTOR: &str = "key-connector";
    pub const ACCOUNTS_REGISTER: &str = "accounts.register";
    pub const CIPHERS_PARTIAL: &str = "ciphers.partial";
    pub const ATTACHMENTS_V2: &str = "attachments.v2";
}

/// `probe()` 的完整結果：BTP 要帶的 `ServerProfile` 加上新增的 quirks 與原始文件。
#[derive(Clone, Debug)]
pub struct ServerProbe {
    /// 共享給 thin client 的那份（bw-proto 的型別沒有 quirks 欄位）。
    pub profile: ServerProfile,
    pub quirks: BTreeSet<Quirk>,
    pub features: BTreeSet<String>,
    /// `/config` 的 `version`：server 所模擬的 Bitwarden 協定版本。
    pub protocol_version: Option<String>,
    /// `/config` 的 `gitHash`。
    pub git_hash: Option<String>,
    /// 探索到的次網域（`environment` 或 `<x>Url` 欄位）。
    pub urls: ServerUrls,
    /// `featureStates` 原樣保留。
    pub feature_states: Option<Value>,
    pub config: Option<Value>,
    pub openid_discovery: Option<Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerUrls {
    pub base: String,
    pub vault: Option<String>,
    pub api: Option<String>,
    pub identity: Option<String>,
    pub notifications: Option<String>,
    pub events: Option<String>,
    pub sso: Option<String>,
}

impl Default for ServerProbe {
    fn default() -> Self {
        Self {
            profile: ServerProfile {
                kind: ServerKind::Unknown,
                version: None,
                features: Vec::new(),
            },
            quirks: BTreeSet::new(),
            features: BTreeSet::new(),
            protocol_version: None,
            git_hash: None,
            urls: ServerUrls::default(),
            feature_states: None,
            config: None,
            openid_discovery: None,
        }
    }
}

impl ServerProbe {
    pub fn kind(&self) -> ServerKind {
        self.profile.kind
    }

    pub fn is_vaultwarden(&self) -> bool {
        matches!(self.profile.kind, ServerKind::Vaultwarden)
    }

    pub fn has(&self, f: &str) -> bool {
        self.features.contains(f)
    }

    pub fn has_quirk(&self, q: Quirk) -> bool {
        self.quirks.contains(&q)
    }

    pub fn record(&mut self, q: Quirk) {
        self.quirks.insert(q);
    }

    /// 從 `/sync` 回應做欄位存在性探測（契约 §2.6 的第三步）。純函數，方便回放測試。
    pub fn observe_sync(&mut self, sync: &Value) {
        if sync.get("profile").is_some() {
            self.features.insert("sync.profile".to_owned());
        }
        for key in [
            "ciphers",
            "folders",
            "collections",
            "organizations",
            "policies",
            "sends",
        ] {
            if has_field(sync, &[key]) {
                self.features.insert(format!("sync.{key}"));
            }
        }
        if let Some(profile) = sync.get("profile") {
            if !has_field(profile, &["organizations"]) {
                self.record(Quirk::SyncMissingProfileOrganizations);
            }
            // 解密選項有兩個家：profile.userDecryptionOptions（token 回應用的名字）與
            // 顶层 userDecryption（/sync 用的名字）。兩個都沒有才是真的缺（#6729 形態）。
            let has_options =
                has_field(profile, &["userDecryptionOptions", "UserDecryptionOptions"]);
            let has_top_level = has_field(sync, &["userDecryption", "UserDecryption"]);
            if has_options {
                self.features
                    .insert("sync.profile.userDecryptionOptions".to_owned());
            }
            if has_top_level {
                self.features.insert("sync.userDecryption".to_owned());
            }
            if !has_options && !has_top_level {
                self.record(Quirk::MissingUserDecryptionOptions);
            }
            if has_field(profile, &["accountKeys"]) {
                self.features.insert("sync.profile.accountKeys".to_owned());
            }
        }
        // 附件容器形態：upstream 是 map（key = attachment id），Vaultwarden 1.37.2
        // 在 /sync 與 /ciphers/{id} 都回 array（見 fixtures/README.md）。鏡像層兩種都要吃，
        // 這裡只負責把觀測結果記下來。
        if let Some(ciphers) = sync.get("ciphers").and_then(Value::as_array) {
            let mut saw_map = false;
            let mut saw_array = false;
            let mut id_not_uuid = false;
            for cipher in ciphers {
                match get(cipher, &["attachments"]) {
                    Some(Value::Object(map)) => {
                        saw_map = true;
                        id_not_uuid |= map.keys().any(|id| uuid::Uuid::parse_str(id).is_err());
                    }
                    Some(Value::Array(items)) => {
                        saw_array = true;
                        id_not_uuid |= items
                            .iter()
                            .filter_map(|a| get(a, &["id", "Id"]).and_then(Value::as_str))
                            .any(|id| uuid::Uuid::parse_str(id).is_err());
                    }
                    _ => {}
                }
            }
            if saw_map {
                self.features
                    .insert("ciphers.attachments-as-map".to_owned());
            }
            if saw_array {
                self.features
                    .insert("ciphers.attachments-as-array".to_owned());
            }
            if id_not_uuid {
                self.features
                    .insert("ciphers.attachments.id-not-uuid".to_owned());
            }
        }
    }
}

/// 判別 `/config` 回應屬於哪種 server。
///
/// 判據（兩個獨立訊號，任一成立即定性）：
/// - `server.name` 含 "vaultwarden" → Vaultwarden（VW 在 `/api/config` 固定回這個名字，
///   見 https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/misc.rs）
/// - `server` 為 null 且 `environment.cloudRegion` 非 null → 官方雲
///   （實錄 https://api.bitwarden.com/config，2026-10-29）
/// - host 結尾是 bitwarden.com → 官方雲（config 拿不到時的退路）
pub fn classify(config: Option<&Value>, base_url: &str) -> ServerKind {
    if let Some(cfg) = config {
        if let Some(name) = get(cfg, &["server"])
            .and_then(|s| get(s, &["name", "Name"]))
            .and_then(Value::as_str)
        {
            if name.to_ascii_lowercase().contains("vaultwarden") {
                return ServerKind::Vaultwarden;
            }
            if !name.is_empty() {
                return ServerKind::Unknown;
            }
        }
        let cloud_region = get_path2(cfg, &["environment", "cloudRegion"])
            .or_else(|| get_path2(cfg, &["CloudRegion"]));
        if matches!(cloud_region, Some(Value::String(s)) if !s.is_empty()) {
            return ServerKind::BitwardenCloud;
        }
        if get(cfg, &["server"]).is_some_and(|v| v.is_null()) {
            return ServerKind::BitwardenCloud;
        }
    }
    if host_of(base_url)
        .is_some_and(|h| h.eq_ignore_ascii_case("bitwarden.com") || h.ends_with(".bitwarden.com"))
    {
        return ServerKind::BitwardenCloud;
    }
    ServerKind::Unknown
}

fn get_path2<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for name in path {
        cur = get(cur, std::slice::from_ref(name))?;
    }
    Some(cur)
}

pub(crate) fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

/// 從 `/config` 读出次網域。官方雲用 `<x>Url` 扁平欄位，Vaultwarden 用 `environment` 物件；
/// 兩種形態都讀。
///
/// 但自架 server 常從 `DOMAIN` 或 Host header 推出自己的網址，透過 port-forward
/// 或 IP/localhost 別名連線時那個網址對本連線是錯的（實錄：VW 在容器裡回
/// `http://localhost/api`，而用戶端連的是 `http://127.0.0.1:18080`）。
/// 規則：發現的 URL 若只有「標準路徑」而 origin 跟 base 不同，就保留 origin 用 base 的；
/// 路徑非標準（反代掛在 `/bw/api` 之类）或 origin 相同才採用發現值。
pub fn extract_urls(config: Option<&Value>, base_url: &str) -> ServerUrls {
    let mut urls = ServerUrls {
        base: base_url.to_owned(),
        ..Default::default()
    };
    let Some(cfg) = config else { return urls };
    let keep = |found: Option<String>, default_path: &str| {
        found.and_then(|f| rebase_if_alias(base_url, &f, default_path))
    };
    if let Some(env) = get(cfg, &["environment", "Environment"]) {
        let read = |names: &[&str], default_path: &str| {
            keep(get_str(env, names).map(str::to_owned), default_path)
        };
        urls.api = read(&["api", "ApiUrl", "apiUrl"], "/api");
        urls.identity = read(&["identity", "IdentityUrl", "identityUrl"], "/identity");
        urls.notifications = read(
            &["notifications", "NotificationsUrl", "notificationsUrl"],
            "/notifications",
        );
        urls.events = read(&["events", "EventsUrl", "eventsUrl"], "/events");
        urls.vault = read(&["vault", "VaultUrl", "vaultUrl"], "/");
        urls.sso = get_str(env, &["sso", "SsoUrl", "ssoUrl"])
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
    }
    // 舊式扁平欄位（config.notificationsUrl）
    urls.notifications = urls.notifications.or_else(|| {
        keep(
            get_str(cfg, &["notificationsUrl", "NotificationsUrl"]).map(str::to_owned),
            "/notifications",
        )
    });
    urls
}

/// 座標相同的 URL 直接採用；只有「標準路徑」卻換了 origin 的，視為 server 自報的別名，
/// 改回 base 的 origin 再沿用其路徑。
fn rebase_if_alias(base: &str, found: &str, default_path: &str) -> Option<String> {
    let mut found_url = url::Url::parse(found).ok()?;
    let base_url = url::Url::parse(base).ok()?;
    if found_url.origin() == base_url.origin() {
        return Some(found.trim_end_matches('/').to_owned());
    }
    let same_scheme = found_url.scheme() == base_url.scheme();
    let is_default_path =
        found_url.path().trim_end_matches('/') == default_path.trim_end_matches('/');
    if same_scheme && is_default_path {
        found_url.set_scheme(base_url.scheme()).ok();
        let _ = found_url.set_host(base_url.host_str());
        found_url.set_port(base_url.port()).ok();
        found_url.set_path(default_path);
        return Some(found_url.to_string().trim_end_matches('/').to_owned());
    }
    Some(found.trim_end_matches('/').to_owned())
}

/// 探測到的原始材料。分開收集與判讀，測試才能用錄好的 fixture 回放同一條判讀路徑。
#[derive(Clone, Debug, Default)]
pub struct ProbeInputs {
    pub base_url: String,
    /// `/config`（或 `/api/config`）的 JSON。
    pub config: Option<Value>,
    /// config 是從 `/api/config` 拿到的（VW 只在這裡有）。
    pub config_at_api: bool,
    /// `/api/version` 的 JSON 字串值（Vaultwarden 獨有，回產品版本）。
    pub product_version: Option<String>,
    /// `/.well-known/openid-configuration` 的 JSON。
    pub discovery: Option<Value>,
}

/// 把探測材料判讀成 [`ServerProbe`]。純函數。
pub fn assemble(input: &ProbeInputs) -> ServerProbe {
    let mut probe = ServerProbe::default();
    probe.profile.kind = classify(input.config.as_ref(), &input.base_url);
    probe.urls = extract_urls(input.config.as_ref(), &input.base_url);
    if let Some(cfg) = &input.config {
        probe.features.insert(feature::CONFIG.to_owned());
        if input.config_at_api {
            probe.features.insert(feature::CONFIG_UNDER_API.to_owned());
        } else {
            // 根路徑才有 /config：代表這不是 VW 的標準佈局
            probe.features.insert("config.at-root".to_owned());
        }
        probe.protocol_version = get_str(cfg, &["version"]).map(str::to_owned);
        probe.git_hash = get_str(cfg, &["gitHash"]).map(str::to_owned);
        probe.feature_states = get(cfg, &["featureStates"]).cloned();
        if probe.urls.notifications.is_some() {
            probe
                .features
                .insert(feature::NOTIFICATIONS_WEBSOCKET.to_owned());
        }
    } else {
        probe.record(Quirk::ConfigOnlyUnderApi);
    }
    if let Some(v) = &input.product_version {
        probe.features.insert(feature::VERSION_ENDPOINT.to_owned());
        let _ = v;
    }
    match &input.discovery {
        Some(d) => {
            probe.features.insert(feature::OPENID_DISCOVERY.to_owned());
            probe.openid_discovery = Some(d.clone());
        }
        None => probe.record(Quirk::NoOpenIdDiscovery),
    }
    // Vaultwarden 沒有 /api/version 時，產品版本就退回 config 宣稱的協定版本
    let product = input.product_version.clone().or_else(|| {
        if probe.is_vaultwarden() {
            None
        } else {
            probe.protocol_version.clone()
        }
    });
    let mut merged = build_profile(probe.profile.kind, product, input.config.as_ref());
    probe.profile.version = merged.version;
    let mut feats: Vec<String> = probe
        .features
        .iter()
        .cloned()
        .chain(merged.features.drain(..))
        .collect();
    feats.sort();
    feats.dedup();
    probe.profile.features = feats;
    probe.config = input.config.clone();
    if probe.is_vaultwarden() {
        // 這些是 Vaultwarden 與 upstream 的既有差異，來源見 NOTES.md；
        // 先記下來，請求路徑才不會每次都去撞 404。
        for q in [
            Quirk::SoftDeleteUsesPutVerb,
            Quirk::RestoreUsesPutVerb,
            Quirk::BulkDeleteUsesIdsField,
            Quirk::TwoFactorHeadersIgnored,
            Quirk::NonJsonErrorPages,
            Quirk::AttachmentUploadRequiresMultipart,
            Quirk::PartialUpdateLimitedToFolderAndFavorite,
            Quirk::NoDeletedCiphersListing,
            Quirk::ClientCredentialsRequiresDevice,
        ] {
            probe.record(q);
        }
    }
    probe
}

/// 由探測結果組出 `ServerProfile`。`version` 用產品版本（VW 的 `/api/version`），
/// 拿不到才退回 `/config` 宣稱的 Bitwarden 協定版本。
pub fn build_profile(
    kind: ServerKind,
    product_version: Option<String>,
    config: Option<&Value>,
) -> ServerProfile {
    let version = product_version
        .or_else(|| config.and_then(|c| get_str(c, &["version", "Version"]).map(str::to_owned)));
    let mut features: Vec<String> = Vec::new();
    if let Some(cfg) = config {
        if get_bool(cfg, &["settings", "disableUserRegistration"]).is_some()
            || has_field(cfg, &["settings"])
        {
            features.push("config.settings".to_owned());
        }
        if get(cfg, &["push"])
            .and_then(|p| get_str(p, &["vapidPublicKey", "VapidPublicKey"]))
            .is_some()
        {
            features.push(feature::PUSH_VAPID.to_owned());
        }
        if has_field(cfg, &["keyConnector"]) {
            features.push(feature::KEY_CONNECTOR.to_owned());
        }
        if let Some(states) =
            get(cfg, &["featureStates", "FeatureStates"]).and_then(Value::as_object)
        {
            for name in states.keys() {
                features.push(format!("featureStates.{name}"));
            }
        }
    }
    features.sort();
    features.dedup();
    ServerProfile {
        kind,
        version,
        features,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_vaultwarden_by_server_name() {
        let cfg = json!({"server": {"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}});
        assert_eq!(
            classify(Some(&cfg), "http://127.0.0.1:18080"),
            ServerKind::Vaultwarden
        );
    }

    #[test]
    fn classifies_cloud_by_null_server_and_region() {
        let cfg = json!({"server": null, "environment": {"cloudRegion": "US"}});
        assert_eq!(
            classify(Some(&cfg), "https://api.bitwarden.com"),
            ServerKind::BitwardenCloud
        );
    }

    #[test]
    fn falls_back_to_host_heuristic() {
        assert_eq!(
            classify(None, "https://vault.bitwarden.com/"),
            ServerKind::BitwardenCloud
        );
        assert_eq!(classify(None, "http://localhost:8080"), ServerKind::Unknown);
    }

    #[test]
    fn unknown_server_name_is_not_guessed_as_cloud() {
        let cfg = json!({"server": {"name": "buttercup"}});
        assert_eq!(
            classify(Some(&cfg), "https://bw.example.com"),
            ServerKind::Unknown
        );
    }

    #[test]
    fn urls_read_both_shapes() {
        let vw = json!({"environment": {"api": "http://h/api", "identity": "http://h/identity", "notifications": "http://h/notifications"}});
        let urls = extract_urls(Some(&vw), "http://h");
        assert_eq!(urls.api.as_deref(), Some("http://h/api"));
        assert_eq!(
            urls.notifications.as_deref(),
            Some("http://h/notifications")
        );
        let legacy = json!({"notificationsUrl": "https://n.example"});
        assert_eq!(
            extract_urls(Some(&legacy), "https://x")
                .notifications
                .as_deref(),
            Some("https://n.example")
        );
    }

    #[test]
    fn product_version_wins_over_protocol_version() {
        let cfg = json!({"version": "2026.6.0"});
        let p = build_profile(
            ServerKind::Vaultwarden,
            Some("1.37.2".to_owned()),
            Some(&cfg),
        );
        assert_eq!(p.version.as_deref(), Some("1.37.2"));
        let p2 = build_profile(ServerKind::BitwardenCloud, None, Some(&cfg));
        assert_eq!(p2.version.as_deref(), Some("2026.6.0"));
    }

    #[test]
    fn sync_observation_records_missing_user_decryption_options() {
        let mut probe = ServerProbe::default();
        probe.observe_sync(&json!({"profile": {}, "ciphers": []}));
        assert!(probe.quirks.contains(&Quirk::MissingUserDecryptionOptions));
        assert!(probe.has("sync.ciphers"));
        assert!(!probe.has("sync.folders"));
    }
}
