//! Send（加密分享）六端點代理（bearer 流；建/列/取/檔案/改密/刪）。
//!
//! 線格式查證（2026-11-10，VW 1.37.2 dev 容器實測＋官方原始碼對照）：
//! - 路由掛 `/api/sends*`——**非** `/accounts/sends`（實錄 `GET /api/accounts/sends`
//!   回 404）。官方雲同形：`SendsController` `[Route("sends")]`
//!   （https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Tools/Controllers/SendsController.cs#L29 ）。
//!   Vaultwarden：https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/sends.rs （`routes!` 全表）。
//! - 建立（文字）`POST /api/sends`：body 官方 `SendData` 形態
//!   `{type,key,name,notes?,text:{text,hidden},maxAccessCount?,password?,
//!   deletionDate,expirationDate?,disabled,hideEmail?}`；deletionDate 必須
//!   ≤31 天內（實錄超界回 400 訊息）。檔案型走 v2 兩段（見 [`Client::send_create_file`]）。
//! - 清單 `GET /api/sends` → `{data:[...], object:"list"}`（實錄）。
//! - 單取 `GET /api/sends/{id}`；刪 `DELETE /api/sends/{id}`（200 空體；
//!   404＝已不存在，冪等收斂由呼叫端吞）。
//! - 改/清取用密碼：官方無獨立 POST access-password 路由（VW 與官方雲同）——
//!   設/換＝`PUT /api/sends/{id}` 全量帶 `password`（伺服器只在欄位**有值**時
//!   重哈希，null 不動既有哈希，见 `update_send_from_data`）；清＝
//!   `PUT /api/sends/{id}/remove-password`（實錄 200 回完整 send）。
//! - 接收方（無 bearer，本層不代辦、e2e 直接 curl）：
//!   `POST /api/sends/access/{accessId}` body `{password}` → send-access
//!   （實錄 401 缺/password 未提供、400 錯密碼、404 耗盡或到期）；
//!   檔案下載 URL＝`POST /api/sends/{id}/access/file/{fileId}` 同 body → `{url}`
//!   （短效簽名，帶 bearer 亦通——本層給發送端自取用）。

use serde_json::{Value, json};

use bw_proto::ItemId;

use crate::json::{get_str, get};
use crate::{Client, ServerError};

/// 檔案 send v2 建立回包：上傳憑證（形態對齊 `AttachmentUpload`——
/// 只給 URL 與元資料，實際位元組推送由呼叫端做）。
#[derive(Clone, Debug)]
pub struct SendFileUpload {
    /// 伺服器生成的檔案 id（`data.id`，40 字元 hex；非 UUID）。
    pub file_id: String,
    /// 已解析成 absolute 的上傳 URL（VW 回相對路徑 `/sends/{id}/file/{fileId}`）。
    pub url: String,
    /// 已落庫的 send 物件（含 id/accessId/key；上傳成功後即最終形態）。
    pub send: Value,
}

impl Client {
    /// `GET /sends`：清單（`{data:[...], object:"list"}` 原樣回傳，raw mirror 紀律）。
    pub async fn sends_list(&self) -> Result<Value, ServerError> {
        self.get_json("sends").await
    }

    /// `GET /sends/{id}`：單筆（owner 視角完整 send，含 `key` 包裝信封）。
    pub async fn send_get(&self, id: ItemId) -> Result<Value, ServerError> {
        self.get_json(&format!("sends/{id}")).await
    }

    /// `POST /sends`：建立**文字** send（body 由 daemon 構好——金鑰欄全為
    /// 信封字串，本層不碰加密語意）。回完整 send 物件。
    pub async fn send_create(&self, body: &Value) -> Result<Value, ServerError> {
        self.post_json("sends", body).await
    }

    /// `POST /sends/file/v2`：建立**檔案** send 的第一段（登記元資料、拿上傳 URL）。
    /// body 需帶 `fileLength`（int）與 `file.fileName`（信封），`file.id/size/sizeName`
    /// 由伺服器補。實錄回包：`{fileUploadType:0, object:"send-fileUpload",
    /// url:"/sends/{id}/file/{fileId}", sendResponse:{...}}`。
    /// 官方 v1 multipart 直傳（`POST /sends/file`）已標註 deprecated，不實裝。
    pub async fn send_create_file(&self, body: &Value) -> Result<SendFileUpload, ServerError> {
        let raw = self.post_json("sends/file/v2", body).await?;
        let raw_url = get_str(&raw, &["url"]).unwrap_or_default().to_owned();
        let file_id = raw_url.rsplit('/').next().unwrap_or_default().to_owned();
        let url = self.absolute(&raw_url).await;
        let send = get(&raw, &["sendResponse"]).cloned().unwrap_or(Value::Null);
        Ok(SendFileUpload { file_id, url, send })
    }

    /// 第二段：把加密檔身 POST 到 v2 回的上傳 URL（multipart 欄位名 `data`）。
    /// 實錄（VW 1.37.2）：multipart filename 必須與 `data.fileName`（信封字串）
    /// **逐字相符**（非 CLI 裝置無 ends_with 寬容），位元組數必須與登記的
    /// `fileLength` 完全一致（不符回 400 "Send file size does not match."）。
    pub async fn send_upload_data(
        &self,
        upload_url: &str,
        file_name_enc: &str,
        data: &[u8],
    ) -> Result<(), ServerError> {
        self.require_token().await?;
        let form = reqwest::multipart::Form::new().part(
            "data",
            reqwest::multipart::Part::bytes(data.to_vec())
                .file_name(file_name_enc.to_owned())
                .mime_str("application/octet-stream")
                .map_err(|e| ServerError::Malformed(e.to_string()))?,
        );
        let req = self.authorized(self.http.post(upload_url)).await;
        let (status, text) = self.send(req.multipart(form)).await?;
        match self.parse_ok(status, &text) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into_server_error()),
        }
    }

    /// 發送端自取檔案：`POST /sends/{id}/access/file/{fileId}` body `{password}`
    /// → 短效簽名下載 URL（實錄形态同接收方，帶 bearer 亦通；password 為
    /// wire 哈希字串，無密碼 send 傳 None）。
    pub async fn send_file_access_url(
        &self,
        id: ItemId,
        file_id: &str,
        password: Option<&str>,
    ) -> Result<String, ServerError> {
        let raw = self
            .post_json(
                &format!("sends/{id}/access/file/{file_id}"),
                &json!({ "password": password }),
            )
            .await?;
        let raw_url = get_str(&raw, &["url"]).unwrap_or_default();
        if raw_url.is_empty() {
            return Err(ServerError::Malformed(
                "send file access response has no url".to_owned(),
            ));
        }
        Ok(self.absolute(raw_url).await)
    }

    /// `PUT /sends/{id}`：全量更新（官方語意：`password` 欄**有值才改哈希**、
    /// 類型不可變、file send 的 data 欄不動——`update_send_from_data`）。
    pub async fn send_put(&self, id: ItemId, body: &Value) -> Result<Value, ServerError> {
        self.put_json(&format!("sends/{id}"), body).await
    }

    /// `PUT /sends/{id}/remove-password`：清除取用密碼。回更新後 send。
    pub async fn send_remove_password(&self, id: ItemId) -> Result<Value, ServerError> {
        self.put_json(&format!("sends/{id}/remove-password"), &json!({}))
            .await
    }

    /// `DELETE /sends/{id}`：刪除（連帶檔案）。回 200 空體；404 原樣上拋由
    /// 呼叫端按冪等收斂語意吞掉。
    pub async fn send_delete(&self, id: ItemId) -> Result<(), ServerError> {
        self.try_empty_delete(&format!("sends/{id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_file_upload_parses_relative_url_and_file_id() {
        // VW 1.37.2 實錄形態（dev 容器 probe 2026-11-10）
        let raw = serde_json::json!({
            "fileUploadType": 0,
            "object": "send-fileUpload",
            "url": "/sends/71c53f06-b44d-4444-9ff4-07418882f139/file/f8ecd4e48350",
            "sendResponse": {"id": "71c53f06-b44d-4444-9ff4-07418882f139", "object": "send"}
        });
        let url = get_str(&raw, &["url"]).unwrap();
        assert_eq!(url.rsplit('/').next().unwrap(), "f8ecd4e48350");
        assert!(get(&raw, &["sendResponse"]).is_some());
    }
}
