//! 緊急存取（EA）daemon 面（PR4）：`EmergencyAccess:*` 分派。
//!
//! 協議形態見 `bw_server::ea` 模組表（端點代理在那邊，本檔只做金鑰動作與
//! 治理）。金鑰鏈（CryptoGaps 定稿）：confirm 的 `key` ＝ grantor User.Key
//! 以 grantee RSA 公鑰 OAEP-SHA1 包裝（org invite 同支 `rsa_encrypt`）；
//! 派生與包裝只在 `with_keys` 閉包內發生（不變量 3）。
//!
//! 狀態機與本檔的對應：
//! - grantor 側（C1）：`Invite` →（VW 無 mail 自動 accept）→ `Confirm` → `Revoke`
//! - grantee 側（C2）：`Initiate` →（grantor `Approve`/`Reject` 或逾時）→ `View`
//! - 接管（C3）：`TakeoverPrepare` → `Takeover`（改 grantor 主密碼＋重包 akey，
//!   伺服器順手清空其 2FA 因子——語意在 handler 註記）

use bw_proto::{EaAccessType, EaCall, EaRole, ItemKind, ItemMeta, ItemView, Response, WtpError};
use serde_json::Value;

use crate::hub::{DispatchResult, denied, project_card, project_identity};

impl crate::hub::Hub {
    pub(crate) async fn ea_dispatch(&self, call: &EaCall) -> DispatchResult {
        match call {
            EaCall::ListGrantees => self.ea_list(EaRole::Grantee).await,
            EaCall::ListGrantors => self.ea_list(EaRole::Grantor).await,
            EaCall::Invite {
                email,
                access_type,
                wait_time_days,
            } => self.ea_invite(email, *access_type, *wait_time_days).await,
            EaCall::Confirm { ea_id } => self.ea_confirm(ea_id).await,
            EaCall::Revoke { ea_id } => self.ea_revoke(ea_id).await,
            EaCall::Initiate { ea_id } => self.ea_simple_post(ea_id, true).await,
            EaCall::Approve { ea_id } => self.ea_simple_post(ea_id, false).await,
            EaCall::Reject { ea_id } => self.ea_reject(ea_id).await,
            EaCall::View { ea_id } => self.ea_view(ea_id).await,
        }
    }

    /// initiate/approve：`POST {base}/{id}/{verb}` 空體（源檔兩支同形）。
    async fn ea_simple_post(&self, ea_id: &str, initiate: bool) -> DispatchResult {
        let client = self.ea_client().await?;
        if initiate {
            client.ea_initiate(ea_id).await
        } else {
            client.ea_approve(ea_id).await
        }
        .map_err(crate::hub::map_server_err)?;
        Ok(Response::Ok)
    }

    async fn ea_client(&self) -> Result<std::sync::Arc<bw_server::Client>, WtpError> {
        let guard = self.server.read().await;
        let h = guard.as_ref().ok_or(WtpError::NotFound)?;
        Ok(h.client.clone())
    }

    async fn ea_list(&self, role: EaRole) -> DispatchResult {
        let client = self.ea_client().await?;
        let contacts = client
            .ea_list(role)
            .await
            .map_err(crate::hub::map_server_err)?;
        Ok(Response::EaContacts(contacts))
    }

    async fn ea_invite(
        &self,
        email: &str,
        access_type: EaAccessType,
        wait_time_days: u32,
    ) -> DispatchResult {
        if !email.contains('@') {
            return Err(denied("邀請對象需要有效 email"));
        }
        // 等待天數官方 UI 範圍 1..=30；0 天＝立即放行（VW 源檔不做下限閘），
        // 上界防呆由伺服器裁決，本地只擋明顯荒謬值。
        if wait_time_days == 0 || wait_time_days > 3650 {
            return Err(denied("等待天數需介於 1..3650"));
        }
        let client = self.ea_client().await?;
        client
            .ea_invite(email, access_type, wait_time_days)
            .await
            .map_err(crate::hub::map_server_err)?;
        Ok(Response::Ok)
    }

    /// grantor 確認：查 trusted 清單拿 grantee user id → 取對方 RSA 公鑰 →
    /// 解鎖態閉包內以 OAEP-SHA1 包自己的 user key → `POST confirm`。
    /// VW 未啟 mail 時邀請對既有帳號直接落 Accepted（源檔 `send_invite`），
    /// 所以 e2e 鏈不需要 accept 步驟；雲端停在 Invited 時這裡給可懂錯誤。
    async fn ea_confirm(&self, ea_id: &str) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(denied("確認緊急存取需要解鎖態（要用 user key 派發金鑰）"));
        }
        let client = self.ea_client().await?;
        let contacts = client
            .ea_list(EaRole::Grantee)
            .await
            .map_err(crate::hub::map_server_err)?;
        let contact = contacts
            .into_iter()
            .find(|c| c.id == ea_id)
            .ok_or(WtpError::NotFound)?;
        let grantee_id = contact
            .user_id
            .ok_or_else(|| denied("對方尚未接受邀請（伺服器還沒有其 user id）"))?;
        let public_key = client
            .ea_public_key(&grantee_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        let key = self
            .machine
            .with_keys(|kb| {
                bw_crypto::rsa_encrypt(
                    &public_key,
                    bw_crypto::OaepHash::Sha1,
                    kb.user_key().as_bytes(),
                )
            })
            .map_err(|_| denied("vault 未解鎖"))?
            .map_err(|e| denied(format!("金鑰包裝失敗：{e}")))?;
        client
            .ea_confirm(ea_id, &key)
            .await
            .map_err(crate::hub::map_server_err)?;
        Ok(Response::Ok)
    }

    async fn ea_revoke(&self, ea_id: &str) -> DispatchResult {
        let client = self.ea_client().await?;
        client
            .ea_revoke(ea_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        Ok(Response::Ok)
    }

    /// grantor 拒絕恢復（狀態回 Confirmed）。
    async fn ea_reject(&self, ea_id: &str) -> DispatchResult {
        let client = self.ea_client().await?;
        client
            .ea_reject(ea_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        Ok(Response::Ok)
    }

    /// grantee 唯讀視圖（C2）：拉 `{ciphers,keyEncrypted}` → 以本機 user key
    /// 解自己的 RSA 私鑰 → `rsa_decrypt` 出 **grantor user key** → 經外部鑰
    /// 視窗（`cipher_field_decryptor` 吃候選鑰）投影 Reveal 級清單。
    /// 與 org 共享鏈同構：同一支三態選鑰解析器，只是候選鑰來自 EA 派發。
    /// 快取按 `LockEpoch` 閘控：同 epoch 重讀不打網路（VW access log 可證），
    /// 上鎖後 epoch 遞增＝整批作廢，重新解鎖須重取（plan epoch 語意）。
    async fn ea_view(&self, ea_id: &str) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(denied(
                "緊急檢視需要解鎖態（要以自己的 RSA 私鑰解金鑰信封）",
            ));
        }
        let epoch = self.machine.epoch().0;
        if let Some((e, items)) = self.ea_view_cache.lock().unwrap().get(ea_id)
            && *e == epoch
        {
            return Ok(Response::EaView(items.clone()));
        }
        let client = self.ea_client().await?;
        let raw = client
            .ea_view(ea_id)
            .await
            .map_err(crate::hub::map_server_err)?;
        let key_env = raw
            .get("keyEncrypted")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::hub::drift("view 回包缺 keyEncrypted（grantor 尚未派鑰？）"))?
            .to_owned();
        let ciphers: Vec<Value> = raw
            .get("ciphers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let items = self
            .machine
            .with_keys(|kb| {
                let enc_priv = kb.encrypted_private_key()?;
                let pkcs8 = bw_crypto::decrypt_private_key(kb.user_key(), enc_priv).ok()?;
                let uk_bytes = bw_crypto::rsa_decrypt(&pkcs8, &key_env).ok()?;
                let grantor_key = bw_crypto::UserKey::from_bytes(uk_bytes).ok()?;
                Some(
                    ciphers
                        .iter()
                        .filter_map(|c| self.project_external_cipher(c, &grantor_key))
                        .collect::<Vec<ItemView>>(),
                )
            })
            .map_err(|_| denied("金鑰閉包失效（請重新解鎖）"))?
            .ok_or_else(|| {
                denied("本帳號沒有可用的 RSA 私鑰（註冊時未生成），解不开派發金鑰信封")
            })?;
        self.ea_view_cache
            .lock()
            .unwrap()
            .retain(|_, (e, _)| *e == epoch);
        self.ea_view_cache
            .lock()
            .unwrap()
            .insert(ea_id.to_owned(), (epoch, items.clone()));
        Ok(Response::EaView(items))
    }

    /// 外部（grantor）cipher JSON → `ItemView`（Reveal 級）。鏡像層不在場：
    /// meta 直接從協議欄位構（紀律同 `bw_store::ciphers::write_cipher` 的讀側），
    /// 欄位解密走 [`Hub::cipher_field_decryptor`] 以 grantor user key 為候選鑰。
    /// EA view 端點回的是 grantor **個人** ciphers（源檔 find_owned_by_user），
    /// 無 org 歸屬：org_keys 恆空。附件略過（下載是另一步，本波不做）。
    pub(crate) fn project_external_cipher(
        &self,
        cipher: &Value,
        grantor_key: &bw_crypto::UserKey,
    ) -> Option<ItemView> {
        let id = uuid::Uuid::parse_str(cipher.get("id")?.as_str()?).ok()?;
        let empty_orgs = std::collections::HashMap::new();
        let dec = self.cipher_field_decryptor(grantor_key, cipher, &empty_orgs);
        let name = cipher
            .get("name")
            .and_then(Value::as_str)
            .and_then(&dec);
        let login = cipher.get("login");
        let uris: Vec<String> = login
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|u| u.get("uri").and_then(Value::as_str))
                    .filter_map(&dec)
                    .collect()
            })
            .unwrap_or_default();
        let uri_matches: Vec<Option<u8>> = login
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|u| u.get("match").and_then(Value::as_u64).map(|m| m as u8))
                    .collect()
            })
            .unwrap_or_default();
        let kind = match cipher.get("type").and_then(Value::as_u64) {
            Some(2) => ItemKind::SecureNote,
            Some(3) => ItemKind::Card,
            Some(4) => ItemKind::Identity,
            _ => ItemKind::Login,
        };
        let fields = match cipher.get("fields").and_then(Value::as_array) {
            Some(arr) => arr
                .iter()
                .map(|f| bw_proto::CipherField {
                    name: f
                        .get("name")
                        .and_then(Value::as_str)
                        .and_then(&dec)
                        .unwrap_or_default(),
                    value: f.get("value").and_then(Value::as_str).and_then(&dec),
                    kind: bw_proto::CipherFieldKind::from_wire(
                        f.get("type").and_then(Value::as_i64).unwrap_or(0),
                    ),
                })
                .collect(),
            None => Vec::new(),
        };
        let meta = ItemMeta {
            id,
            kind,
            name,
            uris,
            folder_id: cipher
                .get("folderId")
                .and_then(Value::as_str)
                .and_then(|s| uuid::Uuid::parse_str(s).ok()),
            organization_id: None,
            collections: Vec::new(),
            favorite: cipher
                .get("favorite")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            tags: Vec::new(),
            updated_at: cipher
                .get("revisionDate")
                .and_then(Value::as_str)
                .map(str::to_owned),
            pending: false,
            deleted_at: cipher
                .get("deletedDate")
                .and_then(Value::as_str)
                .map(str::to_owned),
            archived_at: cipher
                .get("archivedDate")
                .and_then(Value::as_str)
                .map(str::to_owned),
            uri_matches,
        };
        let username = login
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .and_then(&dec);
        let password = login
            .and_then(|l| l.get("password"))
            .and_then(Value::as_str)
            .and_then(&dec);
        let notes = cipher.get("notes").and_then(Value::as_str).and_then(&dec);
        let card = project_card(cipher, &dec, true);
        let identity = project_identity(cipher, &dec);
        Some(
            ItemView::metadata(meta)
                .masked(username, None, false)
                .revealed(password)
                .with_details(notes, fields, Vec::new())
                .with_card_identity(card, identity),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// 外部鑰視窗單元（plan 驗收「org 共享鏈同構回歸」）：投影器吃的
    /// 候選鑰是 **grantor** user key（非本機鑰），三態選鑰同解析器——
    /// 無 key 欄直解、有 key 欄兩段 unwrap、foreign 鑰不得誤解。
    /// 形態回放 `fixtures/ea_view_vw_1.37.2.json`（VW 真錄：key 欄缺席、
    /// 欄位全 `2.` 以 grantor user key 加密）。
    #[tokio::test]
    async fn external_key_window_projects_grantor_cipher() {
        let (hub, _d) = crate::passkey::tests::unlocked_hub("eaview1").await;
        let grantor = bw_crypto::UserKey::from_bytes((140u8..204).collect::<Vec<u8>>()).unwrap();
        let enc = |pt: &str| bw_crypto::encrypt(&grantor, pt).unwrap().to_string();
        let id = uuid::Uuid::new_v4();
        let cipher = json!({
            "id": id.to_string(),
            "type": 1,
            "name": enc("ea-login"),
            "revisionDate": "2026-11-16T12:00:00Z",
            "login": {
                "username": enc("fam@example.com"),
                "password": enc("s3cr3t-ea"),
                "uris": [{"uri": enc("https://ea.example.com"), "match": null}]
            },
            "notes": enc("備註"),
            "fields": [{"type": 0, "name": enc("f1"), "value": enc("v1")}]
        });
        let v = hub
            .project_external_cipher(&cipher, &grantor)
            .expect("外部鑰投影成功");
        assert_eq!(v.meta.id, id);
        assert_eq!(v.meta.name.as_deref(), Some("ea-login"));
        assert_eq!(v.meta.uris, ["https://ea.example.com"]);
        assert_eq!(v.username.as_deref(), Some("fam@example.com"));
        assert_eq!(
            v.password.as_deref(),
            Some("s3cr3t-ea"),
            "Reveal 級明文出口"
        );
        assert_eq!(v.notes.as_deref(), Some("備註"));
        assert_eq!(v.fields[0].name, "f1");
        assert_eq!(v.fields[0].value.as_deref(), Some("v1"));
        assert!(!v.meta.pending);
        // 本機鑰解不開 grantor 欄位：以錯鑰投影 → 名稱 None（解析器不猜）。
        let wrong = bw_crypto::UserKey::from_bytes((1u8..65).collect::<Vec<u8>>()).unwrap();
        let v2 = hub
            .project_external_cipher(&cipher, &wrong)
            .expect("列仍成形（欄位容忍）");
        assert_eq!(v2.meta.name, None);
        assert_eq!(v2.password, None);
    }

    /// item key 兩段鏈（官方新項目形態）：`key` 欄以 grantor user key 包
    /// item key，欄位以 item key 加密——同一支 `cipher_decrypt_key` 走通。
    #[tokio::test]
    async fn external_key_window_unwraps_item_key_chain() {
        let (hub, _d) = crate::passkey::tests::unlocked_hub("eaview2").await;
        let grantor = bw_crypto::UserKey::from_bytes((150u8..214).collect::<Vec<u8>>()).unwrap();
        let item: Vec<u8> = (20u8..84).collect();
        let key_env = bw_crypto::encrypt_bytes_key(grantor.as_bytes(), &item).unwrap();
        let enc = |pt: &str| bw_crypto::encrypt_bytes_key(&item, pt.as_bytes()).unwrap();
        let cipher = json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "type": 1,
            "key": key_env,
            "name": enc("itemkey-card"),
            "login": {"password": enc("pw-through-item-key")}
        });
        let v = hub.project_external_cipher(&cipher, &grantor).unwrap();
        assert_eq!(v.meta.name.as_deref(), Some("itemkey-card"));
        assert_eq!(v.password.as_deref(), Some("pw-through-item-key"));
    }
}
