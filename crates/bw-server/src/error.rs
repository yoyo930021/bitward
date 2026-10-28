//! 錯誤模型：伺服器回什麼都先收下來，再決定是不是失敗。
//!
//! Client API 沒有官方 spec（`docs/research/protocol.md` §1），錯誤體在不同 server
//! 之間不一致：identity 端點回 OAuth 形（`error`/`error_description`），API 端點回
//! `errorModel`/`validationErrors` 形，而 Rocket（Vaultwarden）對「路由不存在」與
//! 「未授權」直接回 HTML 頁。因此錯誤解析必須容忍非 JSON 內容位元組。

use serde_json::Value;
use thiserror::Error;

use crate::auth::TwoFactorChallenge;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("http {status}: {detail}")]
    Http { status: u16, detail: String },
    #[error("transport: {0}")]
    Transport(String),
    #[error("rejected: {0}")]
    Rejected(String),
    /// 寬容解析失敗：欄位缺失到無法取得必要資訊（例如 token 回應沒有 access_token）。
    #[error("malformed response: {0}")]
    Malformed(String),
    /// 尚未认证成功就呼叫需要 Bearer 的端點。
    #[error("not authenticated")]
    Unauthenticated,
    /// 這個 server 沒有該端點（ServerProfile 探測到的能力缺口）。
    #[error("unsupported by server: {0}")]
    Unsupported(String),
    /// 第一步 password grant 被擋下：需要第二因子。用 [`TwoFactorChallenge::retry`] 重試。
    #[error("two-factor required: {challenge}")]
    TwoFactorRequired { challenge: Box<TwoFactorChallenge> },
}

impl ServerError {
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// token 遭拒的語意（契约 §2.2「token 遭拒」）：401/403 代表要重新認證。
    pub fn is_auth_rejected(&self) -> bool {
        matches!(self.status(), Some(401) | Some(403))
    }

    /// 429：上層（登入流程、bw-sync 的 drain）該退避重試，別把它當成憑證失效。
    /// Vaultwarden 對 login 與 2FA 共用同一個 token bucket，預設 60 秒平均 10 次
    /// （`LOGIN_RATELIMIT_SECONDS`/`LOGIN_RATELIMIT_MAX_BURST`，見 src/config.rs）。
    pub fn is_rate_limited(&self) -> bool {
        self.status() == Some(429)
    }
}

/// 已解析的錯誤回應。`raw` 保留伺服器原樣內容，供 ServerProfile 記錄 quirk 與除錯。
#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    pub status: u16,
    /// 人類可讀的主要原因（各格式擇一）。
    pub message: String,
    pub validation_errors: Vec<String>,
    /// OAuth 錯誤碼，例如 `invalid_grant`。
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// 回應體不是 JSON（Rocket 的 HTML 錯誤頁）。
    pub non_json: bool,
    pub raw: String,
}

impl ApiError {
    pub fn parse(status: u16, body: &str) -> Self {
        let json: Option<Value> = serde_json::from_str(body).ok();
        let (message, validation_errors, error, error_description) = match &json {
            Some(v) => {
                let mut msgs: Vec<String> = Vec::new();
                for path in [
                    vec!["errorModel", "message"],
                    vec!["Message"],
                    vec!["message"],
                    vec!["detail"],
                    vec!["error_description"],
                    vec!["errorDescription"],
                    vec!["description"],
                ] {
                    if let Some(Value::String(s)) = crate::json::get_path(v, &path) {
                        msgs.push(s.clone());
                    }
                }
                let mut validation = Vec::new();
                if let Some(Value::Object(map)) = crate::json::get_path(v, &["validationErrors"])
                    .or_else(|| crate::json::get_path(v, &["ValidationErrors"]))
                {
                    for (_k, vals) in map {
                        if let Value::Array(items) = vals {
                            for item in items {
                                if let Value::String(s) = item {
                                    validation.push(s.clone());
                                }
                            }
                        }
                    }
                }
                let error = crate::json::get_str(v, &["error", "Error"]).map(str::to_owned);
                let error_description =
                    crate::json::get_str(v, &["error_description", "errorDescription"])
                        .or_else(|| crate::json::get_str(v, &["exceptionMessage"]))
                        .map(str::to_owned);
                let message = msgs
                    .first()
                    .cloned()
                    .or_else(|| validation.first().cloned())
                    .unwrap_or_else(|| summarize(body));
                (message, validation, error, error_description)
            }
            None => (summarize(body), Vec::new(), None, None),
        };
        Self {
            status,
            message,
            validation_errors,
            error,
            error_description,
            non_json: json.is_none(),
            raw: body.to_owned(),
        }
    }

    /// Rocket 對「沒有這條 route」回 404 + 固定 JSON 體；語意上是端點缺，不是資料缺。
    pub fn is_route_missing(&self) -> bool {
        if self.status != 404 {
            return false;
        }
        self.raw.contains("Not Found") || self.non_json
    }

    pub fn is_invalid_grant(&self) -> bool {
        self.error.as_deref() == Some("invalid_grant")
    }

    pub(crate) fn into_server_error(self) -> ServerError {
        ServerError::Http {
            status: self.status,
            detail: self.message,
        }
    }
}

/// 把多行 HTML 壓成一行的短摘要，避免錯誤字串裡塞整份網頁。
fn summarize(body: &str) -> String {
    let flat: String = body
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let flat = flat.trim();
    if flat.len() <= 240 {
        return flat.to_owned();
    }
    let mut cut = 240;
    while !flat.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &flat[..cut])
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http {}: {}", self.status, self.message)
    }
}

impl From<ApiError> for ServerError {
    fn from(e: ApiError) -> Self {
        e.into_server_error()
    }
}

impl From<reqwest::Error> for ServerError {
    fn from(e: reqwest::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ServerError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<url::ParseError> for ServerError {
    fn from(e: url::ParseError) -> Self {
        Self::Rejected(format!("invalid url: {e}"))
    }
}

impl From<serde_json::Error> for ServerError {
    fn from(e: serde_json::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}
