//! Bitwarden Client API 用戶端：唯一碰 HTTP/WS 的地方（契約 §3.3）。
//! 欄位寬容 + raw mirror + ServerProfile 探測（§2.6）。簽名凍結自契約，實作由 U4 填入。

use bw_proto::{ItemId, ServerProfile};
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("http {status}: {detail}")]
    Http { status: u16, detail: String },
    #[error("transport: {0}")]
    Transport(String),
    #[error("rejected: {0}")]
    Rejected(String),
}

pub struct Client {
    _private: (),
}

impl Client {
    pub fn new(_base_url: &str) -> Result<Self, ServerError> {
        Ok(Self { _private: () })
    }

    pub async fn token(&self, _grant: TokenGrant) -> Result<Value, ServerError> {
        todo!("U4: POST /connect/token（password|client_credentials，TOTP 二步 header）")
    }

    pub async fn sync(&self) -> Result<Value, ServerError> {
        todo!("U4: GET /sync，寬容解析，原始 JSON 原樣返回")
    }

    pub async fn cipher_get(&self, _id: ItemId) -> Result<Value, ServerError> {
        todo!("U4: GET /ciphers/<id>（多中樞 targeted pull，§1.1）")
    }

    pub async fn cipher_put(&self, _id: ItemId, _body: &Value) -> Result<Value, ServerError> {
        todo!("U4: PUT /ciphers/<id>")
    }

    pub async fn probe(&self) -> ServerProfile {
        todo!("U4: GET /config + /.well-known + 欄位存在性（§2.6）")
    }
}

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

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // U4 以錄製 fixtures（官方雲+VW 兩份）+ e2e 取代（A2/A2b）
    }
}
