//! 批次 4a：附件 daemon 側全鏈（上傳／下載／刪除／投影）。
//!
//! 線格式實錄（VW 1.37.2 probe，2026-11-09）：
//! - 上傳 `POST /api/ciphers/{id}/attachment` multipart（`key`＝附件金鑰信封、
//!   `data`＝密文檔身；data 段 multipart filename 原樣落 `fileName`，故傳加密檔名）。
//! - 下載 `GET /api/ciphers/{id}/attachment/{aid}` → 短效簽名 URL → 直連取位元組。
//! - 刪除 `DELETE /api/ciphers/{id}/attachment/{aid}` → 回更新後 cipher。
//!
//! 金鑰模型（官方 jslib 同形）：每個附件一枚隨機 64B 對稱金鑰
//! （enc32+mac32，與 UserKey 同構）；檔身以它加密成信封字串；附件 `key`
//! 欄位存「該金鑰被本項目欄位金鑰重包」的信封字串——帶 item key 的項目用
//! item key（官方形態）、無 key 舊項目用歸屬鑰（user／org）。金鑰選擇
//! 唯讀 `Hub::cipher_decrypt_key`（別自創第二套）；該鑰不可得（org akey
//! 未解出、item key 解不開）時讀寫皆拒。

use rand::RngCore;
use serde_json::{Value, json};

use bw_proto::{AttachmentId, AttachmentOp, ItemId, Response, WtpError};
use bw_store::{MutState, Mutation, MutationDraft};

use crate::hub::Hub;

/// 單檔上限（Contract 1；BTP 幀上限的推導見 bw-btp MAX_FRAME 註解）。
pub const MAX_ATTACHMENT_BYTES: usize = 32 * 1024 * 1024;

impl Hub {
    /// 上傳：加密（`with_keys` 閉包內）→ blob 落盤 → outbox `Awaiting` 入列
    /// （單寫路徑紀律同 cipher 寫入：本地先收、drain 推送、離線自然佇列）
    /// → 觸發 drain。回應即 `Ok`；附件鏡像列隨伺服器回包（push 端）落地。
    pub async fn attach_upload(
        &self,
        session: &str,
        item_id: ItemId,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        if file_name.is_empty() {
            return Err(denied("附件需要檔名"));
        }
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(denied(format!(
                "附件 {} bytes 超過上限 {} bytes",
                bytes.len(),
                MAX_ATTACHMENT_BYTES
            )));
        }
        let row = self.store.item(item_id).map_err(denied)?;
        let cipher = row.ok_or(WtpError::NotFound)?.enc_cipher;
        // 附件金鑰包裝與檔名加密統一走解析器（`Hub::cipher_decrypt_key`）：
        // 帶 item key 的項目以 item key 包（官方同形，共享成員經 cipher.key
        // 兩段鏈解得到）；無 key 舊項目以歸屬鑰（user／org）包——org 未派生
        // 時拒寫，不產生成員解不開的密文。
        let org_keys = self.org_key_map();
        let (key_env, name_env, ct_blob) = self
            .machine
            .with_keys(|kb| -> Option<(String, String, Vec<u8>)> {
                let key = self.cipher_decrypt_key(kb, &cipher, &org_keys)?;
                let mut att_key = vec![0u8; 64];
                rand::thread_rng().fill_bytes(&mut att_key);
                let key_env = bw_crypto::encrypt_bytes_key(&key, &att_key).ok()?;
                let name_env = bw_crypto::encrypt_bytes_key(&key, file_name.as_bytes()).ok()?;
                let ct = bw_crypto::encrypt_bytes_key(&att_key, bytes).ok()?;
                Some((key_env, name_env, ct.into_bytes()))
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or_else(|| {
                denied("附件寫入金鑰不可用（共享項目需 org 對稱金鑰派生或 item key 解開）")
            })?;
        let blob = self.store.blob_put(&ct_blob).map_err(denied)?;
        let payload = json!({
            "op": "attach_upload",
            "blob": blob,
            "file_name": name_env,
            "key": key_env,
            "size": bytes.len(),
        });
        self.store
            .enqueue_state(
                &MutationDraft {
                    item: item_id,
                    payload,
                    base_rev: None,
                    origin: Some(session),
                    mirror: None,
                },
                MutState::Awaiting,
            )
            .map_err(denied)?;
        self.trigger_drain();
        Ok(Response::Ok)
    }

    /// drain 端（`push_one` 的 attach_upload op）：讀 blob → multipart POST →
    /// 伺服器回的完整 cipherDetails 落鏡像（附件列隨 `attachments{}` 重建）→
    /// 無其他引用時釋放 blob。可重試錯誤原樣上拋給 push_one 分類。
    pub(crate) async fn push_attach_upload(
        &self,
        client: &std::sync::Arc<bw_server::Client>,
        m: &Mutation,
    ) -> Result<(), (bw_server::ServerError, bool)> {
        let blob = m
            .payload
            .get("blob")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let key_env = m
            .payload
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name_env = m
            .payload
            .get("file_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ct = match self.store.blob_open(&blob) {
            Ok(b) => b,
            Err(_) => {
                // 佇列還在、檔已不在：無從重推，死信留觀測（fsck 口徑同 blob_missing）
                tracing::error!(blob = %blob, id = m.id.0, "attach blob missing at push time");
                let _ = self.store.settle(m.id, MutState::Dead);
                return Err((
                    bw_server::ServerError::Malformed("attach blob missing".into()),
                    true,
                ));
            }
        };
        let updated = client
            .attachment_upload(m.item, key_env, name_env, &ct)
            .await
            .map_err(|e| (e, false))?;
        let _ = self.store.put_mirror(m.item, &updated);
        let _ = self.reindex_one(m.item);
        let _ = self.store.blob_release(&blob);
        Ok(())
    }

    /// 下載：鏡像認列 → 重取簽名 URL（鏡像 url 短效過期是常態）→ 直連位元組
    /// → 解 `key` 信封得附件金鑰 → 解檔身信封 → 明文位元組回傳（本機線紀律）。
    pub async fn attach_download(
        &self,
        item_id: ItemId,
        attachment_id: &AttachmentId,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let rows = self.store.attachment_list(item_id).map_err(denied)?;
        let att = rows
            .into_iter()
            .find(|r| &r.id == attachment_id)
            .ok_or(WtpError::NotFound)?;
        let key_env = att
            .key
            .clone()
            .ok_or_else(|| denied("附件列缺 key（舊鏡像？請 sync 重拉）"))?;
        let client = self.client().await?;
        let meta = client
            .attachment_download(item_id, attachment_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        let url = meta.url.ok_or_else(|| crate::hub::drift("附件回包缺 url"))?;
        let ct = client
            .attachment_fetch_bytes(&url)
            .await
            .map_err(crate::hub::map_server_err)?;
        let row_cipher = {
            let row = self.store.item(item_id).map_err(denied)?;
            row.ok_or(WtpError::NotFound)?.enc_cipher
        };
        let org_keys = self.org_key_map();
        let plain = self
            .machine
            .with_keys(|kb| -> Option<Vec<u8>> {
                let field_key = self.cipher_decrypt_key(kb, &row_cipher, &org_keys)?;
                let ct_s = std::str::from_utf8(&ct).ok()?;
                let att_key = bw_crypto::decrypt_bytes_with_key(&field_key, &key_env).ok()?;
                bw_crypto::decrypt_bytes_with_key(&att_key, ct_s).ok()
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or_else(|| denied("附件解密失敗（金鑰或檔身漂移）"))?;
        Ok(Response::AttachmentBytes(plain))
    }

    /// 刪除：`DELETE /ciphers/{id}/attachment/{aid}` → 回更新後 cipher 落鏡像
    /// （附件列隨全量替換消失）。離線回錯不入列（本批語意；佇列化留 GUI 批評估）。
    pub async fn attach_delete(
        &self,
        item_id: ItemId,
        attachment_id: &AttachmentId,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let rows = self.store.attachment_list(item_id).map_err(denied)?;
        if !rows.iter().any(|r| &r.id == attachment_id) {
            return Err(WtpError::NotFound);
        }
        let client = self.client().await?;
        let updated = client
            .attachment_delete(item_id, attachment_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        let _ = self.store.put_mirror(item_id, &updated);
        let _ = self.reindex_one(item_id);
        self.emit(
            bw_proto::EventTopic::VaultChanged,
            json!({"id": item_id.to_string(), "op": "attach-delete"}),
        );
        Ok(Response::Ok)
    }

    /// ItemView 投影（Masked/Reveal 路徑呼叫；`dec` 為該 cipher 的欄位解密器）。
    /// 檔名鏡像端是信封字串：解不開（VW 明文殘留或金鑰漂移）原樣回傳。
    pub(crate) fn attachment_projection(
        &self,
        item_id: ItemId,
        dec: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<bw_proto::AttachmentMeta> {
        let decrypt_field = |v: &Option<String>| -> Option<String> {
            v.as_deref().map(|s| dec(s).unwrap_or_else(|| s.to_owned()))
        };
        self.store
            .attachment_list(item_id)
            .unwrap_or_default()
            .into_iter()
            .map(|r| bw_proto::AttachmentMeta {
                id: r.id,
                file_name: decrypt_field(&r.file_name).unwrap_or_default(),
                size: r.size.map(|s| s.max(0) as u64),
                size_name: decrypt_field(&r.size_name),
            })
            .collect()
    }
}

/// 審計摘要用：Upload 變體帶整檔位元組，Debug 不得.dump 進 audit 文字。
pub fn op_summary(sub: &AttachmentOp) -> String {
    match sub {
        AttachmentOp::Upload {
            item_id,
            file_name,
            bytes,
        } => format!("attach upload {item_id} {file_name} ({}B)", bytes.len()),
        AttachmentOp::Download {
            item_id,
            attachment_id,
        } => format!("attach download {item_id}/{attachment_id}"),
        AttachmentOp::Delete {
            item_id,
            attachment_id,
        } => format!("attach delete {item_id}/{attachment_id}"),
    }
}

fn denied(detail: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::tests::unlocked_hub;
    use serde_json::json;
    use uuid::Uuid;

    fn personal_cipher(hub: &Hub, tag: &str) -> ItemId {
        let id = Uuid::new_v4();
        hub.store
            .put_mirror(
                id,
                &json!({
                    "id": id.to_string(), "type": 1,
                    "name": format!("2.{tag}|x|y"),
                    "organizationId": null,
                }),
            )
            .unwrap();
        id
    }

    /// 上傳＝單寫路徑：加密（附件金鑰＋user key 重包）→ blob → Awaiting 入列。
    #[tokio::test]
    async fn upload_encrypts_with_per_attachment_key_and_queues() {
        let (hub, _d) = unlocked_hub("att1").await;
        let cid = personal_cipher(&hub, "n1");
        let resp = hub
            .attach_upload("s", cid, "帳單.pdf", b"secret-bytes")
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok));
        let due = hub.store.take_due(8).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].state, MutState::Awaiting, "附件佇列用 Awaiting 態");
        let payload = due[0].payload.clone();
        assert_eq!(payload["op"], json!("attach_upload"));
        let blob = payload["blob"].as_str().unwrap();
        let ct = hub.store.blob_open(blob).unwrap();
        let user = hub
            .machine
            .with_keys(|kb| kb.user_key().as_bytes().to_vec())
            .unwrap();
        // key 欄＝附件金鑰被 user key 重包；檔身＝該金鑰加密的信封位元組
        let att_key = bw_crypto::decrypt_bytes_with_key(
            &user,
            payload["key"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(att_key.len(), 64, "enc32+mac32 合成金鑰（UserKey 同構）");
        let plain = bw_crypto::decrypt_bytes_with_key(
            &att_key,
            std::str::from_utf8(&ct).unwrap(),
        )
        .unwrap();
        assert_eq!(plain, b"secret-bytes");
        let name = bw_crypto::decrypt_bytes_with_key(
            &user,
            payload["file_name"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(String::from_utf8(name).unwrap(), "帳單.pdf");
        // 同檔再傳：ref 去重但兩列各自持有引用計數（blob_release 語意的登録側）
        hub.attach_upload("s2", cid, "again.pdf", b"secret-bytes")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_guards_size_and_org_scope() {
        let (hub, _d) = unlocked_hub("att2").await;
        let cid = personal_cipher(&hub, "n2");
        let big = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
        let err = hub.attach_upload("s", cid, "big.bin", &big).await.unwrap_err();
        assert!(matches!(err, WtpError::Denied { .. }), "{err:?}");
        assert!(hub.attach_upload("s", cid, "", b"x").await.is_err(), "空檔名拒");

        let org = Uuid::new_v4();
        let shared = Uuid::new_v4();
        hub.store
            .put_mirror(
                shared,
                &json!({
                    "id": shared.to_string(), "type": 1, "name": "2.s|x|y",
                    "organizationId": org.to_string(),
                }),
            )
            .unwrap();
        let err = hub
            .attach_upload("s", shared, "f.bin", b"x")
            .await
            .unwrap_err();
        assert!(
            matches!(err, WtpError::Denied { .. }),
            "org key 未派生的共享項目寫附件必須拒寫（不產生成員解不開的密文）：{err:?}"
        );
    }

    /// 官方形態項目的附件：附件金鑰以 **item key** 重包、檔名以 item key
    /// 加密（jslib 同形，共享成員經 cipher.key 兩段鏈解得到）。
    #[tokio::test]
    async fn upload_wraps_attachment_key_with_item_key() {
        let (hub, _d) = unlocked_hub("att4").await;
        let user = hub
            .machine
            .with_keys(|kb| kb.user_key().as_bytes().to_vec())
            .unwrap();
        let item: Vec<u8> = (150u8..214).collect();
        let id = Uuid::new_v4();
        hub.store
            .put_mirror(
                id,
                &json!({
                    "id": id.to_string(), "type": 1,
                    "key": bw_crypto::encrypt_bytes_key(&user, &item).unwrap(),
                    "name": "2.n|x|y",
                }),
            )
            .unwrap();
        hub.attach_upload("s", id, "帳單.pdf", b"ik-bytes").await.unwrap();
        let due = hub.store.take_due(8).unwrap();
        let payload = due[0].payload.clone();
        let att_key =
            bw_crypto::decrypt_bytes_with_key(&item, payload["key"].as_str().unwrap()).unwrap();
        let ct = hub.store.blob_open(payload["blob"].as_str().unwrap()).unwrap();
        let plain =
            bw_crypto::decrypt_bytes_with_key(&att_key, std::str::from_utf8(&ct).unwrap()).unwrap();
        assert_eq!(plain, b"ik-bytes");
        let name =
            bw_crypto::decrypt_bytes_with_key(&item, payload["file_name"].as_str().unwrap()).unwrap();
        assert_eq!(name, "帳單.pdf".as_bytes());
        assert!(
            bw_crypto::decrypt_bytes_with_key(&user, payload["key"].as_str().unwrap()).is_err(),
            "附件金鑰不得再以 user key 直包（官方讀 item key 鏈）"
        );
    }

    #[tokio::test]
    async fn download_requires_known_attachment() {
        let (hub, _d) = unlocked_hub("att3").await;
        let cid = personal_cipher(&hub, "n3");
        let err = hub
            .attach_download(cid, &"nope".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, WtpError::NotFound), "{err:?}");
    }

    /// 投影：附件元資料隨 cipher 鏡像重建；檔名信封經 dec 解密、
    /// VW 明文 sizeName 解不開時原樣回傳（漂移寬容）。
    #[tokio::test]
    async fn projection_decrypts_names_tolerates_plaintext() {
        let (hub, _d) = unlocked_hub("att4").await;
        let cid = Uuid::new_v4();
        hub.store
            .put_mirror(
                cid,
                &json!({
                    "id": cid.to_string(), "type": 1, "name": "2.n|x|y",
                    "attachments": {
                        "a1": {
                            "id": "a1", "fileName": "2.Zm58|eA==|bQ==",
                            "size": "11", "sizeName": "11.00 bytes",
                            "key": "2.k|k|k", "url": "http://x/y"
                        }
                    }
                }),
            )
            .unwrap();
        let rows = hub.store.attachment_list(cid).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].size, Some(11));
        // dec 形態："2.Zm58|eA==|bQ==" 解出 "fn|"（base64 段 Zm58 → "fn|"）
        let metas = hub.attachment_projection(cid, &|s: &str| {
            s.strip_prefix("2.Zm58|eA==|bQ==")
                .map(|_| "fn".to_string())
        });
        assert_eq!(metas[0].file_name, "fn");
        assert_eq!(metas[0].size_name.as_deref(), Some("11.00 bytes"));
        assert_eq!(metas[0].id, "a1");
    }
}
