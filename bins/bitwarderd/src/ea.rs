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
//! - 接管（C3）：`Takeover`（單次呼叫內走 takeover→重包→password；改 grantor
//!   主密碼＋重包 akey。伺服器順手清空其 2FA 因子並踢非 Owner 出組織——
//!   語意見 `password_emergency_access` 源檔）

use bw_proto::{EaAccessType, EaCall, EaRole, ItemKind, ItemMeta, ItemView, Response, WtpError};
use serde_json::Value;

use crate::hub::{DispatchResult, denied, map_server_err, project_card, project_identity};

/// VW/雲的 EA 端點錯誤是英文原文（源檔 `err!("Emergency access not valid.")`
/// 之類）；過一層常用對映再上收，未知形態原樣保留（誠實優先於整齊）。
/// 錯誤由伺服器裁判、本地不攔流程——這裡只翻譯不吞。
fn ea_err(e: bw_server::ServerError) -> WtpError {
    if let bw_server::ServerError::Http { status, detail } = &e
        && let Some(msg) = localize_ea_error(*status, detail)
    {
        return denied(msg);
    }
    map_server_err(e)
}

/// 對映表（純函數，單測釘點）：`detail` 已含伺服器訊息原文（`ApiError::parse`
/// 收攏 errorModel/validationErrors/message）。比對用小寫包含；回 None＝
/// 不認識，交回 `map_server_err` 原樣上拋。
fn localize_ea_error(status: u16, detail: &str) -> Option<String> {
    let low = detail.to_lowercase();
    [
        (
            "emergency access is not enabled",
            "伺服器未啟用緊急存取（自架需開 EA 設定）",
        ),
        (
            "emergency access not valid",
            "對方已撤銷或授權已失效（當前狀態不接受此操作）",
        ),
        ("can not set yourself", "不能把自己設為緊急联系人"),
        ("already invited", "對方已在受託名單中"),
        (
            "grantee user does not exist",
            "對方帳號不存在（且伺服器未開放邀請註冊）",
        ),
        ("grantee user not found", "找不到受託人帳號"),
        ("invited user not found", "找不到受邀帳號（邀請可能已過期）"),
        ("claim email does not match", "邀請信與此帳號的 email 不符"),
        (
            "emergency access invitation error",
            "邀請已被更動（請請對方重發邀請）",
        ),
        ("has no public_key", "對方帳號沒有 RSA 公鑰，無法派發金鑰"),
    ]
    .into_iter()
    .find(|(needle, _)| low.contains(needle))
    .map(|(_, msg)| format!("{msg}（HTTP {status}）"))
}

impl crate::accounts::Profile {
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
            EaCall::Takeover {
                ea_id,
                new_password,
            } => self.ea_takeover(ea_id, new_password).await,
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
        .map_err(ea_err)?;
        Ok(Response::Ok)
    }

    async fn ea_client(&self) -> Result<std::sync::Arc<bw_server::Client>, WtpError> {
        let guard = self.server.read().await;
        let h = guard.as_ref().ok_or(WtpError::NotFound)?;
        Ok(h.client.clone())
    }

    async fn ea_list(&self, role: EaRole) -> DispatchResult {
        let client = self.ea_client().await?;
        let contacts = client.ea_list(role).await.map_err(ea_err)?;
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
            .map_err(ea_err)?;
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
        let contacts = client.ea_list(EaRole::Grantee).await.map_err(ea_err)?;
        let contact = contacts
            .into_iter()
            .find(|c| c.id == ea_id)
            .ok_or(WtpError::NotFound)?;
        let grantee_id = contact
            .user_id
            .ok_or_else(|| denied("對方尚未接受邀請（伺服器還沒有其 user id）"))?;
        let public_key = client.ea_public_key(&grantee_id).await.map_err(ea_err)?;
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
        client.ea_confirm(ea_id, &key).await.map_err(ea_err)?;
        Ok(Response::Ok)
    }

    async fn ea_revoke(&self, ea_id: &str) -> DispatchResult {
        let client = self.ea_client().await?;
        client.ea_revoke(ea_id).await.map_err(ea_err)?;
        Ok(Response::Ok)
    }

    /// grantor 拒絕恢復（狀態回 Confirmed）。
    async fn ea_reject(&self, ea_id: &str) -> DispatchResult {
        let client = self.ea_client().await?;
        client.ea_reject(ea_id).await.map_err(ea_err)?;
        Ok(Response::Ok)
    }

    /// grantee 唯讀視圖（C2）：拉 `{ciphers,keyEncrypted}` → 以本機 user key
    /// 解自己的 RSA 私鑰 → `rsa_decrypt` 出 **grantor user key** → 經外部鑰
    /// 視窗（`cipher_field_decryptor` 吃候選鑰）投影 Reveal 級清單。
    /// 與 org 共享鏈同構：同一支三態選鑰解析器，只是候選鑰來自 EA 派發。
    /// 快取按 `LockEpoch` 閘控：上鎖後 epoch 遞增＝整批作廢（plan epoch 語意）；
    /// 同 epoch 命中也要過一發 `GET granted` 輕驗（產品裁決：revoke 即時失效，
    /// 不可預期地讀到已撤銷的明文＝否）。輕驗只花一個清單往返——慢路徑是
    /// 整庫 POST view＋RSA 解封＋逐筆投影，快取省的是大頭，計數斷言見
    /// `dev/e2e/ea.sh`（view POST 不增）。
    async fn ea_view(&self, ea_id: &str) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(denied(
                "緊急檢視需要解鎖態（要以自己的 RSA 私鑰解金鑰信封）",
            ));
        }
        let epoch = self.machine.epoch().0;
        let client = self.ea_client().await?;
        let cached = self
            .ea_view_cache
            .lock()
            .unwrap()
            .get(ea_id)
            .filter(|(e, _)| *e == epoch)
            .map(|(_, items)| items.clone());
        if let Some(items) = cached {
            let live = client
                .ea_list(EaRole::Grantor)
                .await
                .map_err(ea_err)?
                .iter()
                .any(|c| c.id == ea_id && c.status == bw_proto::EaStatus::RecoveryApproved);
            if live {
                return Ok(Response::EaView(items));
            }
            // 關係已撤銷或狀態倒退（reject）：明文即棄，交伺服器裁判回可懂錯誤。
            self.ea_view_cache.lock().unwrap().remove(ea_id);
        }
        let raw = client.ea_view(ea_id).await.map_err(ea_err)?;
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

    /// 接管（C3）：takeover 材料 → 外部鑰解包 → 新密碼重包 → password 端點。
    /// KDF 鹽優先級同官方：雲態 takeover 回包帶 `salt`（源檔
    /// `EmergencyAccessTakeoverResponseModel.Salt`）；VW 1.37.2 不帶，
    /// 退 grantor email（VW 的 master password salt 就是 email）。
    /// 成功後 grantor 主密碼即換、其 2FA 全清、refresh token 輪換
    /// （`set_password` 語意）——本裝置（grantee）鏡像不動，grantor 各端
    /// 需以新密碼重登入。
    async fn ea_takeover(&self, ea_id: &str, new_password: &str) -> DispatchResult {
        if !self.machine.is_unlocked() {
            return Err(denied("接管需要解鎖態（要以自己的 RSA 私鑰解派發信封）"));
        }
        if new_password.chars().count() < crate::hub::MIN_MASTER_PASSWORD {
            return Err(denied(format!(
                "新主密碼太短（至少 {} 字元）",
                crate::hub::MIN_MASTER_PASSWORD
            )));
        }
        let client = self.ea_client().await?;
        let raw = client.ea_takeover(ea_id).await.map_err(ea_err)?;
        let key_env = raw
            .get("keyEncrypted")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| crate::hub::drift("takeover 回包缺 keyEncrypted（grantor 未派鑰？）"))?
            .to_owned();
        let kdf = crate::hub::KdfWire::from_prelogin(&raw)
            .ok_or_else(|| crate::hub::drift("takeover 回包缺 KDF 欄位"))?;
        let salt = match raw.get("salt").and_then(Value::as_str) {
            Some(s) => s.to_owned(),
            // VW 態不帶 salt：＝grantor email，從 granted 清單按 ea_id 取。
            None => {
                let contacts = client.ea_list(EaRole::Grantor).await.map_err(ea_err)?;
                contacts
                    .into_iter()
                    .find(|c| c.id == ea_id)
                    .map(|c| c.email)
                    .ok_or(WtpError::NotFound)?
            }
        };
        let (hash, key) = self
            .machine
            .with_keys(|kb| {
                let enc_priv = kb.encrypted_private_key()?;
                let pkcs8 = bw_crypto::decrypt_private_key(kb.user_key(), enc_priv).ok()?;
                let uk_bytes = bw_crypto::rsa_decrypt(&pkcs8, &key_env).ok()?;
                let grantor_key = bw_crypto::UserKey::from_bytes(uk_bytes).ok()?;
                let mk_new = bw_crypto::master_key(new_password, &salt, kdf.to_params()).ok()?;
                let hash = bw_crypto::master_password_hash(&mk_new, new_password)
                    .as_b64()
                    .to_owned();
                let key = bw_crypto::encrypt_user_key(&mk_new, &grantor_key).ok()?;
                Some((hash, key))
            })
            .map_err(|_| denied("金鑰閉包失效（請重新解鎖）"))?
            .ok_or_else(|| {
                denied("本帳號沒有可用的 RSA 私鑰（註冊時未生成），解不开派發金鑰信封")
            })?;
        client
            .ea_takeover_password(ea_id, &hash, &key)
            .await
            .map_err(ea_err)?;
        Ok(Response::Ok)
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
        let name = cipher.get("name").and_then(Value::as_str).and_then(&dec);
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
    use super::localize_ea_error;
    use serde_json::json;

    #[test]
    fn localizes_common_ea_server_errors() {
        // VW 源檔原文形態（errorModel.message 進 detail）
        assert!(
            localize_ea_error(400, "Emergency access not valid.")
                .unwrap_or_default()
                .contains("對方已撤銷或授權已失效")
        );
        assert!(
            localize_ea_error(400, "Emergency access is not enabled.")
                .unwrap_or_default()
                .contains("未啟用緊急存取")
        );
        assert!(
            localize_ea_error(400, "You can not set yourself as an emergency contact.")
                .unwrap_or_default()
                .contains("自己")
        );
        assert!(
            localize_ea_error(400, "Grantee user already invited: a@b.test")
                .unwrap_or_default()
                .contains("已在受託名單")
        );
        assert!(
            localize_ea_error(404, "User has no public_key")
                .unwrap_or_default()
                .contains("RSA 公鑰")
        );
        // 大寫混排仍命中（比對小寫化）；未知英文原樣不放行（回 None→map_server_err）
        assert!(localize_ea_error(400, "EMERGENCY ACCESS NOT VALID.").is_some());
        assert_eq!(localize_ea_error(500, "Rocket exploded"), None);
    }

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
