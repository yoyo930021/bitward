//! APNs 推播用戶端（token-based provider 認證，§1.2 推播路徑的 Apple 形態）。
//!
//! ntfy 是自架信令（無後台也能跑）；APNs 是正式分發形態的喚醒/核准通道。
//! 兩者語意相同：**只傳不透明信令，明文永不上通道**。JWT 用 ES256（P-256），
//! 由 p256 crate 直接簽，不引入 jsonwebtoken——APNs 只要 header/payload 兩個
//! base64url 段加一段 raw r‖s 簽名，手寫比多依賴更清楚。

use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;

/// 生產與開發端點只差 host；測試可注入自架 mock（http，跳過 TLS 由呼叫端決定）。
pub struct ApnsConfig {
    /// 例：`https://api.push.apple.com`（staging 用 api.sandbox.push.apple.com）
    pub endpoint: String,
    pub key_id: String,
    pub team_id: String,
    pub bundle_id: String,
    signing: SigningKey,
    /// JWT 有效 60 分鐘；APNs 建議 20–60 分鐘輪替。
    token: Mutex<Option<(String, std::time::Instant)>>,
}

const JWT_TTL: Duration = Duration::from_secs(3000);

impl ApnsConfig {
    pub fn load(
        p8_path: &std::path::Path,
        key_id: &str,
        team_id: &str,
        bundle_id: &str,
        staging: bool,
    ) -> Result<Self, String> {
        let pem = std::fs::read(p8_path).map_err(|e| format!("讀 APNs .p8 失敗: {e}"))?;
        Self::from_pem(&pem, key_id, team_id, bundle_id, staging)
    }

    pub fn from_pem(
        pem: &[u8],
        key_id: &str,
        team_id: &str,
        bundle_id: &str,
        staging: bool,
    ) -> Result<Self, String> {
        let pem_str = std::str::from_utf8(pem).map_err(|e| e.to_string())?;
        let key = SigningKey::from_pkcs8_pem(pem_str).map_err(|e| format!("APNs .p8 解析失敗: {e}"))?;
        let endpoint = if staging {
            "https://api.sandbox.push.apple.com".to_string()
        } else {
            "https://api.push.apple.com".to_string()
        };
        Ok(Self {
            endpoint,
            key_id: key_id.to_string(),
            team_id: team_id.to_string(),
            bundle_id: bundle_id.to_string(),
            signing: key,
            token: Mutex::new(None),
        })
    }

    /// 產生（或續用）provider 認證 JWT：`{"alg":"ES256","kid":...}` + `{"iss":team,"iat":secs}`。
    pub fn provider_token(&self) -> String {
        let mut cache = self.token.lock().unwrap();
        if let Some((jwt, born)) = cache.as_ref()
            && born.elapsed() < JWT_TTL
        {
            return jwt.clone();
        }
        let iat = UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
        let jwt = self.build_jwt(iat);
        *cache = Some((jwt.clone(), std::time::Instant::now()));
        jwt
    }

    fn build_jwt(&self, iat: u64) -> String {
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id);
        let claims = format!(r#"{{"iss":"{}","iat":{}}}"#, self.team_id, iat);
        let signing_input = format!("{}.{}", b64(header.as_bytes()), b64(claims.as_bytes()));
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        format!("{}.{}", signing_input, b64(sig.to_bytes().as_slice()))
    }

    /// 對單一 device token 推不透明信令。fire-and-forget：呼叫端（Hub）spawn，
    /// 410（Unregistered）回傳 true 讓上層清理 token；網路失敗僅記日誌——
    /// 推播是加速器不是正確性依賴（ntfy/輪詢仍在）。
    pub async fn send(&self, device_token: &str, alert: &str) -> Result<bool, String> {
        let url = format!("{}/3/device/{}", self.endpoint, device_token);
        let body = serde_json::json!({
            "aps": {
                "alert": {"title": "Bitward", "body": alert},
                "sound": "default",
                "mutable-content": 1,
            },
            "signal": "bitward",
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(&url)
            .bearer_auth(self.provider_token())
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        match status {
            200 => Ok(false),
            // 410 = 裝置已卸載：呼叫端必須移除 token（Make Operations Idempotent：
            // 收斂到「不再對死 token 發推送」的穩定態）。
            410 => Ok(true),
            other => {
                let text = resp.text().await.unwrap_or_default();
                Err(format!("apns {other}: {text}"))
            }
        }
    }
}

use base64::Engine as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ApnsConfig {
        // 固定測試金鑰（僅測試用）；PEM 由 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 產生
        let pem = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQczA8C+zpC3p+q0M
wbyM5XjY2CXkv6vaUJkGmkoDXZOhRANCAAQyYnNJVzUqZQhk5bxgOsqDHIIKpOEE
ZCk+RA68NQS3ZMU4c2saIPqmcNdUbv/pBfCZx4sGwO2T5fMKfwug7tbl
-----END PRIVATE KEY-----";
        ApnsConfig::from_pem(pem.as_bytes(), "KEYID123", "TEAM456", "io.bitward.dev", false)
            .unwrap()
    }

    #[test]
    fn jwt_shape_and_fields() {
        let c = cfg();
        let jwt = c.provider_token();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT 必須三段");
        let dec = |s: &str| String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_str(&dec(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID123");
        let claims: serde_json::Value = serde_json::from_str(&dec(parts[1])).unwrap();
        assert_eq!(claims["iss"], "TEAM456");
        assert!(claims["iat"].as_u64().unwrap() > 0);
        // ES256 簽名 = raw r‖s 64 bytes
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(),
            64
        );
    }

    #[test]
    fn jwt_signature_verifies_with_public_key() {
        // 自證之外再加驗證：用同一金鑰的 public key 驗 JWT 簽名（抓錯位/錯編碼）
        let c = cfg();
        let jwt = c.provider_token();
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig_bytes =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let verifying = *c.signing.verifying_key();
        use p256::ecdsa::signature::Verifier;
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("JWT 簽名必須可驗");
    }

    #[test]
    fn token_cache_reuses_within_ttl() {
        let c = cfg();
        assert_eq!(c.provider_token(), c.provider_token());
    }
}
