//! Vault 讀寫：`/sync`、ciphers CRUD、附件 v2 簽名 URL（契约 §3.3）。
//!
//! 回傳型別一律保留伺服器原樣 JSON（raw mirror，不变量 8）：未建模欄位是真相源，
//! PUT 由 raw + diff 合成，才不會被我們抹掉。

use bw_proto::ItemId;
use serde_json::{Value, json};

use crate::Client;
use crate::error::ServerError;
use crate::json::{get, get_array, get_str};
use crate::profile::Quirk;

/// 寬容解析過的 `/sync`：缺少的陣列欄位視為空集合，不炸。
#[derive(Clone, Debug, Default)]
pub struct SyncResponse {
    pub object: Option<String>,
    pub profile: Option<Value>,
    pub ciphers: Vec<Value>,
    pub folders: Vec<Value>,
    pub collections: Vec<Value>,
    pub organizations: Vec<Value>,
    pub policies: Vec<Value>,
    pub sends: Vec<Value>,
    pub domains: Option<Value>,
    /// 原樣 JSON，鏡像層寫進 `Item.raw` 的來源。
    pub raw: Value,
}

impl SyncResponse {
    pub fn parse(raw: &Value) -> Self {
        let arr = |key: &'static str| -> Vec<Value> {
            get_array(raw, &[key]).into_iter().cloned().collect()
        };
        Self {
            object: get_str(raw, &["object"]).map(str::to_owned),
            profile: get(raw, &["profile"]).cloned(),
            ciphers: arr("ciphers"),
            folders: arr("folders"),
            collections: arr("collections"),
            organizations: arr("organizations"),
            policies: arr("policies"),
            sends: arr("sends"),
            domains: get(raw, &["domains"]).cloned(),
            raw: raw.clone(),
        }
    }

    /// 金鑰指紋（`Key` + `PrivateKey`）：變動代表別台裝置改了主密碼 → `VaultState::Stale`（§2.2）。
    pub fn key_fingerprint(&self) -> Option<String> {
        let profile = self.profile.as_ref()?;
        let key = get_str(profile, &["key", "Key"])?;
        let private = get_str(profile, &["privateKey", "PrivateKey"]).unwrap_or("");
        let stamp = get_str(profile, &["securityStamp", "SecurityStamp"]).unwrap_or("");
        Some(format!(
            "{}|{}|{}",
            sha256_hex(key),
            sha256_hex(private),
            stamp
        ))
    }
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 刪除語意。注意各 server 的動詞不一致（見 [`Quirk::SoftDeleteUsesPutVerb`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteKind {
    /// 回收桶：之後可 restore。
    Soft,
    /// 永久刪除。
    Hard,
}

/// 附件上傳準備完畢的憑證：**只取 URL**，實際上傳位元組由呼叫方做（bw-sync 的 blob 佇列）。
#[derive(Clone, Debug)]
pub struct AttachmentUpload {
    /// **不假設是 UUID**：Vaultwarden 1.37.2 回 20 字元 hex（見 fixtures/README.md）。
    pub attachment_id: String,
    /// 已解析成 absolute 的上傳 URL（相對路徑是相對於 **api** base）。
    pub url: String,
    /// 上傳要用什麼動詞與編碼（兩態：官方 Direct/Azure 是 PUT raw，Vaultwarden 是 POST multipart）。
    pub method: UploadMethod,
    /// 0 = Direct（自家儲存），1 = Azure SAS。来源：
    /// https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/ciphers.rs#L1125-L1128
    pub file_upload_type: Option<i64>,
    /// 部分 server 順带回 cipher 更新，省下第二次 GET。
    pub cipher: Option<Value>,
    pub raw: Value,
}

/// 上傳附件的方式。v2 流程只回 URL 與形態，不碰檔案內容。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadMethod {
    /// `PUT` 原始位元組（`Content-Type: application/octet-stream`）。官方雲 Direct/Azure 形態。
    PutRaw,
    /// `POST` multipart，欄位名 `key`（附件金鑰）與 `data`（檔案）。Vaultwarden 1.37.2 只認這個。
    PostMultipart,
}

#[derive(Clone, Debug)]
pub struct AttachmentDownload {
    pub attachment_id: Option<String>,
    /// 帶簽名 token 的下載 URL（有效期很短，Vaultwarden 為 5 分鐘）。
    pub url: Option<String>,
    pub file_name: Option<String>,
    pub size: Option<i64>,
    pub key: Option<String>,
    pub raw: Value,
}

#[derive(Clone, Debug)]
pub struct NewAttachment {
    pub file_name: String,
    pub size: u64,
    /// 附件級金鑰（加密後的 attachment key）；`None` 走舊式未分離金鑰流程。
    pub key: Option<String>,
}

impl Client {
    /// `GET /sync`：原始 JSON（契约凍結的簽名）。
    pub async fn sync(&self) -> Result<Value, ServerError> {
        let raw = self.get_json("sync").await?;
        // 欄位存在性探測（§2.6 第三步）：順帶更新快取的 profile，不额外發請求。
        self.observe_sync(&raw).await;
        Ok(raw)
    }

    /// `GET /sync` 的寬容解析版本。
    pub async fn sync_parsed(&self) -> Result<SyncResponse, ServerError> {
        Ok(SyncResponse::parse(&self.sync().await?))
    }

    /// `GET /ciphers`（列表；`GET /sync` 的輕量替代）。
    pub async fn ciphers_list(&self) -> Result<Value, ServerError> {
        self.get_json("ciphers").await
    }

    /// `GET /ciphers/{id}`：多中樞收斂的 targeted pull（§1.1）。
    pub async fn cipher_get(&self, id: ItemId) -> Result<Value, ServerError> {
        self.get_json(&format!("ciphers/{id}")).await
    }

    /// `POST /ciphers`：新建。
    pub async fn cipher_create(&self, body: &Value) -> Result<Value, ServerError> {
        self.post_json("ciphers", body).await
    }

    /// `PUT /ciphers/{id}`：整筆覆寫（body 由 raw + diff 合成）。
    pub async fn cipher_put(&self, id: ItemId, body: &Value) -> Result<Value, ServerError> {
        self.put_json(&format!("ciphers/{id}"), body).await
    }

    /// `PUT /ciphers/{id}/partial`：欄位級 patch（outbox 的欄位不相交合併靠它）。
    pub async fn cipher_patch(&self, id: ItemId, patch: &Value) -> Result<Value, ServerError> {
        match self.put_json(&format!("ciphers/{id}/partial"), patch).await {
            Err(e) if is_route_missing_err(&e) => {
                self.record_quirk(Quirk::NoPartialUpdateEndpoint).await;
                Err(e)
            }
            Err(e @ ServerError::Http { status: 422, .. }) => {
                // Vaultwarden 的 PartialCipherData 只有 folderId/favorite，其他欄位會撞 422
                self.record_quirk(Quirk::PartialUpdateLimitedToFolderAndFavorite)
                    .await;
                Err(e)
            }
            other => other,
        }
    }

    /// 刪除。Vaultwarden 的 `POST /ciphers/{id}/delete` 是**永久**刪除，
    /// 軟刪要 `PUT`；官方雲兩種動詞都接受。先打語意正確的那個，
    /// 只有對方回「沒有這條 route」才退到另一種，並記 quirk。
    pub async fn cipher_delete(&self, id: ItemId, kind: DeleteKind) -> Result<(), ServerError> {
        let path = format!("ciphers/{id}/delete");
        match kind {
            DeleteKind::Soft => {
                match self.try_empty_put(&path).await {
                    Ok(()) => Ok(()),
                    Err(err) if is_route_missing_err(&err) => {
                        // 只實作 POST 形態的 server（upstream 就是 POST 軟刪）
                        self.record_quirk(Quirk::SoftDeleteOnlyPostVerb).await;
                        self.try_empty_post(&path).await
                    }
                    Err(e) => Err(e),
                }
            }
            DeleteKind::Hard => self.try_empty_delete(&format!("ciphers/{id}")).await,
        }
    }

    /// 批次永久刪除。欄位名先試 upstream 的 `cipherIds`，422 再試 Vaultwarden 的 `ids`。
    pub async fn ciphers_delete_bulk(
        &self,
        ids: &[ItemId],
        kind: DeleteKind,
    ) -> Result<(), ServerError> {
        let list: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
        let body_upstream = json!({ "cipherIds": list });
        let body_vw = json!({ "ids": list });
        let path = if kind == DeleteKind::Soft {
            "ciphers/delete"
        } else {
            "ciphers"
        };
        let first = if kind == DeleteKind::Soft {
            self.try_empty_put_body(path, &body_upstream).await
        } else {
            self.try_empty_delete_body(path, &body_upstream).await
        };
        match first {
            Ok(()) => Ok(()),
            Err(ServerError::Http {
                status: 422 | 400, ..
            }) => {
                self.record_quirk(Quirk::BulkDeleteUsesIdsField).await;
                if kind == DeleteKind::Soft {
                    self.try_empty_put_body(path, &body_vw).await
                } else {
                    self.try_empty_delete_body(path, &body_vw).await
                }
            }
            Err(e) if is_route_missing_err(&e) && kind == DeleteKind::Soft => {
                // 只有 POST 形態的批次軟刪（upstream 的 `POST /ciphers/delete`）
                self.record_quirk(Quirk::SoftDeleteOnlyPostVerb).await;
                self.try_empty_post_body(path, &body_upstream).await
            }
            Err(e) => Err(e),
        }
    }

    /// 還原軟刪的 cipher。官方雲是 `POST /ciphers/{id}/restore`，
    /// Vaultwarden 1.37.2 只有 `PUT`（實錄：POST 回 route-not-found，
    /// 見 fixtures/cipher_restore_post_vw.json）。
    pub async fn cipher_restore(&self, id: ItemId) -> Result<(), ServerError> {
        let path = format!("ciphers/{id}/restore");
        match self.try_empty_post(&path).await {
            Ok(()) => Ok(()),
            Err(err) if is_route_missing_err(&err) => {
                self.record_quirk(Quirk::RestoreUsesPutVerb).await;
                self.try_empty_put(&path).await
            }
            Err(e) => Err(e),
        }
    }

    /// `POST /ciphers/{id}/attachment/v2`：拿上傳 URL（不傳檔案）。
    pub async fn attachment_prepare_upload(
        &self,
        cipher: ItemId,
        req: &NewAttachment,
    ) -> Result<AttachmentUpload, ServerError> {
        let mut body = json!({
            "fileName": req.file_name,
            "fileSize": req.size,
        });
        // Vaultwarden 1.37.2 把 key 列為必要欄位（缺了回 422 HTML）；官方雲可為 null。
        body["key"] = match &req.key {
            Some(k) => json!(k),
            None => Value::Null,
        };
        let raw = self
            .post_json(&format!("ciphers/{cipher}/attachment/v2"), &body)
            .await?;
        let raw_url = get_str(&raw, &["url"]).unwrap_or_default().to_owned();
        if raw_url.starts_with('/') {
            self.record_quirk(Quirk::AttachmentUploadUrlIsRelative)
                .await;
        }
        let url = self.absolute(&raw_url).await;
        let file_upload_type =
            get(&raw, &["fileUploadType", "file_upload_type"]).and_then(Value::as_i64);
        let method = if self
            .cached_probe()
            .await
            .has_quirk(Quirk::AttachmentUploadRequiresMultipart)
        {
            UploadMethod::PostMultipart
        } else {
            // Azure SAS（1）一定是指名道姓的 PUT；Direct（0/未給）預設也走 PUT，
            // 撞過 404 的 server 由 quirk 決定改 POST multipart。
            let _ = file_upload_type;
            UploadMethod::PutRaw
        };
        Ok(AttachmentUpload {
            attachment_id: get_str(&raw, &["attachmentId", "attachment_id", "id"])
                .unwrap_or_default()
                .to_owned(),
            url,
            method,
            file_upload_type,
            cipher: get(&raw, &["cipherResponse", "cipher"]).cloned(),
            raw,
        })
    }

    /// `GET /ciphers/{id}/attachment/{aid}`：拿簽好名的下載 URL。
    pub async fn attachment_download(
        &self,
        cipher: ItemId,
        attachment_id: &str,
    ) -> Result<AttachmentDownload, ServerError> {
        let raw = self
            .get_json(&format!("ciphers/{cipher}/attachment/{attachment_id}"))
            .await?;
        let raw_url = get_str(&raw, &["url"]).unwrap_or_default().to_owned();
        let url = if raw_url.is_empty() {
            None
        } else {
            Some(self.absolute(&raw_url).await)
        };
        Ok(AttachmentDownload {
            attachment_id: get_str(&raw, &["id", "attachmentId"]).map(str::to_owned),
            file_name: get_str(&raw, &["fileName", "title"]).map(str::to_owned),
            size: get(&raw, &["size"]).and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            }),
            key: get_str(&raw, &["key"]).map(str::to_owned),
            url,
            raw,
        })
    }

    /// `DELETE /ciphers/{id}/attachment/{aid}`。回傳更新後的 cipher。
    pub async fn attachment_delete(
        &self,
        cipher: ItemId,
        attachment_id: &str,
    ) -> Result<Value, ServerError> {
        let path = format!("ciphers/{cipher}/attachment/{attachment_id}");
        let raw = self.delete_json(&path).await?;
        Ok(get(&raw, &["cipher"]).cloned().unwrap_or(raw))
    }

    /// `GET /ciphers/deleted`。沒有這個端點的 server（Vaultwarden 1.37.2）回
    /// [`ServerError::Unsupported`] 並記 quirk，讓上層降回全量 `/sync`。
    pub async fn ciphers_deleted(&self) -> Result<Value, ServerError> {
        match self.get_json("ciphers/deleted").await {
            Err(err) if is_route_missing_err(&err) => {
                self.record_quirk(Quirk::NoDeletedCiphersListing).await;
                Err(ServerError::Unsupported("GET /ciphers/deleted".to_owned()))
            }
            other => other,
        }
    }

    /// 相對 URL 一律相對於 api base（實錄：Vaultwarden 的 v2 上傳 URL 是
    /// `/ciphers/{id}/attachment/{aid}`，實際 route 在 `/api` 之下）。
    pub(crate) async fn absolute(&self, url: &str) -> String {
        if url.is_empty() {
            return String::new();
        }
        let base = self.url("api").await;
        join_url(&base, url)
    }
}

/// 把 server 給的（可能相對的）URL 對上 api base。絕對 URL 原樣返回。
pub fn absolutize(api_base: &str, url: &str) -> String {
    join_url(api_base, url)
}

fn join_url(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_owned();
    }
    let mut out = base.trim_end_matches('/').to_owned();
    if !url.starts_with('/') {
        out.push('/');
    }
    out.push_str(url);
    out
}

pub(crate) fn is_route_missing_err(err: &ServerError) -> bool {
    matches!(
        err,
        ServerError::Http {
            status: 404 | 405,
            ..
        }
    )
}
