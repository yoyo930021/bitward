//! 緊急存取（EA）端點代理（PR4）：`emergency-access/*` 全鏈。
//!
//! 源檔對照（Vaultwarden 1.37.2 `src/api/core/emergency_access.rs` routes! 全表）：
//!
//! | 契約 | 端點 | 需要的驗證 |
//! |---|---|---|
//! | 我授權的對象（grantee 清單） | `GET {base}/trusted` | bearer |
//! | 授權給我的對象（grantor 清單） | `GET {base}/granted` | bearer |
//! | 邀請 | `POST {base}/invite` | `{email,type,waitTimeDays}` |
//! | 接受邀請 | `POST {base}/{id}/accept` | 郵件 JWT token |
//! | 確認（派發金鑰） | `POST {base}/{id}/confirm` | `{key}` |
//! | 更新型別/等待天數 | `PUT {base}/{id}` | `{type,waitTimeDays,keyEncrypted?}` |
//! | 撤銷 | `DELETE {base}/{id}` | — |
//! | 發起恢復 | `POST {base}/{id}/initiate` | — |
//! | 批准／拒絕恢復 | `POST {base}/{id}/approve|reject` | — |
//! | 唯讀視圖 | `POST {base}/{id}/view` | `{ciphers,keyEncrypted}` |
//! | 接管材料 | `POST {base}/{id}/takeover` | `{kdf…,keyEncrypted}` |
//! | 接管改密 | `POST {base}/{id}/password` | `{newMasterPasswordHash,key}` |
//! | 策略 | `GET {base}/{id}/policies` | — |
//!
//! 金鑰語意（修正「伺服器派發明文密碼」的舊假設）：confirm 的 `key` 是
//! **grantor 的 User.Key 以 grantee RSA 公鑰 OAEP-SHA1 包裝**（`4.` 信封，
//! 與 org invite 的 `wrap_org_key` 同構；包裝在呼叫端 bw-crypto 做，
//! 本 crate 只運送不透明信封字串——依賴方向紀律同模組頭）。
//!
//! 路徑探測（§2.6 紀律）：現行官方雲（`src/Api/Auth/Controllers/
//! EmergencyAccessController.cs`，`[Route("emergency-access")]`）與 VW 同形；
//! 較舊的雲佈局掛在 `accounts/emergency-access/*`（CryptoGaps 調查實錄，
//! 未證事項之一）。[`Client::ea_paths`] 以一次 GET 探測定形並快取，
//! 兩態的清單解析由 fixtures 釘選（`parse_contacts` 雙態單測）。

use serde_json::{Value, json};

use crate::Client;
use crate::error::ServerError;
use crate::json::{get, get_i64, get_str};
use bw_proto::{EaAccessType, EaContact, EaRole, EaStatus};

/// EA 端點的路徑形態（相對 `{api}`）。`pubkey` 的 `{id}` 佔位換成 user id。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EaPaths {
    /// EA 記錄 base（`{base}/trusted` 等）
    pub base: &'static str,
    /// 取任意使用者 RSA 公鑰的模板（confirm 需要受託人公鑰）。
    /// VW 1.37.2：`GET {api}/users/{id}/public-key`（`accounts.rs` 的
    /// `#[get("/users/<user_id>/public-key")]` 直接掛 `/api`，無 accounts 前綴；
    /// `dev/e2e/orgpath.sh:155` 同路徑實錄）。官方雲 AccountsController 為
    /// `GET {api}/accounts/{id}/public-key`（推導，未證事項之一）。
    pub pubkey: &'static str,
}

impl EaPaths {
    /// Vaultwarden 與現行官方雲（`EmergencyAccessController.cs`
    /// `[Route("emergency-access")]`）共用的 EA base；公鑰路徑按 kind 分岔。
    pub const VAULTWARDEN: EaPaths = EaPaths {
        base: "emergency-access",
        pubkey: "users/{id}/public-key",
    };
    /// 現行官方雲形態。
    pub const CLOUD: EaPaths = EaPaths {
        base: "emergency-access",
        pubkey: "accounts/{id}/public-key",
    };
    /// 舊雲佈局（EA 掛 `accounts/emergency-access/*`；CryptoGaps 調查實錄）。
    pub const CLOUD_LEGACY: EaPaths = EaPaths {
        base: "accounts/emergency-access",
        pubkey: "accounts/{id}/public-key",
    };

    /// ServerProfile 判讀優先的形態（§2.6：探測而非假設，但已定性的 server
    /// 不必再打探測請求）。Unknown 走 [`Client::ea_paths`] 的實測回退。
    pub fn for_kind(kind: bw_proto::ServerKind) -> Option<EaPaths> {
        match kind {
            bw_proto::ServerKind::Vaultwarden => Some(Self::VAULTWARDEN),
            bw_proto::ServerKind::BitwardenCloud => Some(Self::CLOUD),
            bw_proto::ServerKind::Unknown => None,
        }
    }

    fn pubkey_for(&self, user_id: &str) -> String {
        self.pubkey.replace("{id}", user_id)
    }
}

impl Client {
    /// EA 路徑形態（快取）：`/config` 已定性者直接選型；Unknown 才實測——
    /// GET `{api}/emergency-access/trusted`，404（路由不存在）改探舊雲佈局。
    /// 探測失敗不炸呼叫：回退 VW 形態讓實際呼叫給出誠實錯誤
    /// （探測是優化不是閘門，同 profile.rs 的「有就有、沒有就算」）。
    pub async fn ea_paths(&self) -> EaPaths {
        if let Some(p) = self.state.read().await.ea_paths {
            return p;
        }
        let chosen = if let Some(p) = EaPaths::for_kind(self.probe().await.profile.kind) {
            p
        } else {
            match self.get_json("emergency-access/trusted").await {
                Err(ServerError::Http { status: 404, .. }) => {
                    match self.get_json("accounts/emergency-access").await {
                        Err(ServerError::Http { status: 404, .. }) => EaPaths::VAULTWARDEN,
                        // 舊雲佈局在場（成功或非 404 錯誤）：記 quirk 供報告。
                        _ => {
                            self.record_quirk(crate::profile::Quirk::EmergencyAccessUnderAccounts)
                                .await;
                            EaPaths::CLOUD_LEGACY
                        }
                    }
                }
                // 路由在場但拿不定 server 家鄉：EA base 用通用形態，
                // 公鑰路徑退 VW（自架 VW 是 Unknown 的多数派）。
                _ => EaPaths::VAULTWARDEN,
            }
        };
        self.state.write().await.ea_paths = Some(chosen);
        chosen
    }

    /// `GET {base}/trusted|granted` → 清單（解析見 [`parse_contacts`]）。
    pub async fn ea_list(&self, role: EaRole) -> Result<Vec<EaContact>, ServerError> {
        let paths = self.ea_paths().await;
        let seg = match role {
            EaRole::Grantee => "trusted",
            EaRole::Grantor => "granted",
        };
        let raw = self.get_json(&format!("{}/{}", paths.base, seg)).await?;
        Ok(parse_contacts(&raw, role))
    }

    /// `POST {base}/invite`：`type` 送整數（VW `NumberOrString` 兩態皆收）。
    pub async fn ea_invite(
        &self,
        email: &str,
        access_type: EaAccessType,
        wait_time_days: u32,
    ) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post_body(
            &format!("{}/invite", paths.base),
            &json!({
                "email": email,
                "type": access_type.wire(),
                "waitTimeDays": wait_time_days,
            }),
        )
        .await
    }

    /// `PUT {base}/{id}`：改型別/等待天數；`key_encrypted` 為 Some 才動金鑰欄
    /// （源檔 `put_emergency_access` 只在有值時覆寫）。
    pub async fn ea_update(
        &self,
        id: &str,
        access_type: EaAccessType,
        wait_time_days: u32,
        key_encrypted: Option<&str>,
    ) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        let mut body = json!({
            "type": access_type.wire(),
            "waitTimeDays": wait_time_days,
        });
        if let Some(k) = key_encrypted {
            body["keyEncrypted"] = json!(k);
        }
        self.try_empty_put_body(&format!("{}/{}", paths.base, id), &body)
            .await
    }

    /// `DELETE {base}/{id}`：撤銷（grantor 或 grantee 側皆可，源檔同路徑）。
    pub async fn ea_revoke(&self, id: &str) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_delete(&format!("{}/{}", paths.base, id))
            .await
    }

    /// 取任意使用者的 RSA 公鑰（PEM 裝甲字串，`wrap_org_key` 的解析器直接吃）。
    pub async fn ea_public_key(&self, user_id: &str) -> Result<String, ServerError> {
        let paths = self.ea_paths().await;
        let raw = self.get_json(&paths.pubkey_for(user_id)).await?;
        get_str(&raw, &["publicKey", "PublicKey"])
            .map(str::to_owned)
            .ok_or_else(|| ServerError::Malformed("public-key 回包缺 publicKey 欄".to_owned()))
    }

    /// grantor 確認（`POST {base}/{id}/confirm`）：`key` 是呼叫端包好的
    /// `4.<b64>`（user key 以受託人公鑰 OAEP-SHA1 包裝）。
    pub async fn ea_confirm(&self, id: &str, key: &str) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post_body(
            &format!("{}/{}/confirm", paths.base, id),
            &json!({ "key": key }),
        )
        .await
    }

    /// grantee 發起恢復（`POST {base}/{id}/initiate`）。
    pub async fn ea_initiate(&self, id: &str) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post(&format!("{}/{}/initiate", paths.base, id))
            .await
    }

    /// grantor 批准恢復（`POST {base}/{id}/approve`）。
    pub async fn ea_approve(&self, id: &str) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post(&format!("{}/{}/approve", paths.base, id))
            .await
    }

    /// grantor 拒絕恢復（`POST {base}/{id}/reject`，狀態回 Confirmed）。
    pub async fn ea_reject(&self, id: &str) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post(&format!("{}/{}/reject", paths.base, id))
            .await
    }

    /// grantee 唯讀視圖（`POST {base}/{id}/view`）：回原樣
    /// `{"ciphers":[…],"keyEncrypted":"4.…","object":"emergencyAccessView"}`，
    /// 解密在呼叫端（daemon 的外部鑰視窗）。
    pub async fn ea_view(&self, id: &str) -> Result<Value, ServerError> {
        let paths = self.ea_paths().await;
        self.post_json(&format!("{}/{}/view", paths.base, id), &json!({}))
            .await
    }

    /// 接管材料（`POST {base}/{id}/takeover`）：回原樣
    /// `{"kdf","kdfIterations","kdfMemory","kdfParallelism","keyEncrypted"}`。
    pub async fn ea_takeover(&self, id: &str) -> Result<Value, ServerError> {
        let paths = self.ea_paths().await;
        self.post_json(&format!("{}/{}/takeover", paths.base, id), &json!({}))
            .await
    }

    /// 接管改密（`POST {base}/{id}/password`）：`key` 是 grantor user key
    /// 以**新主密碼派生鑰**重包的 `2.` 信封（源檔直接寫進 `user.akey`，
    /// 語意同 `/accounts/password` 的 `key` 欄）；伺服器順手清空 grantor
    /// 全部 2FA 因子並踢非 Owner 成員出組織（takeover 語意註記）。
    pub async fn ea_takeover_password(
        &self,
        id: &str,
        new_master_password_hash: &str,
        key: &str,
    ) -> Result<(), ServerError> {
        let paths = self.ea_paths().await;
        self.try_empty_post_body(
            &format!("{}/{}/password", paths.base, id),
            &json!({
                "newMasterPasswordHash": new_master_password_hash,
                "key": key,
            }),
        )
        .await
    }
}

/// 清單解析（純函數，fixtures 雙態釘選點）：吃 ListResponse（`{data:[…]}`）
/// 或裸陣列，逐條取 `granteeId`/`grantorId`（依 `role`）、email、name、
/// status/type 編號、waitTimeDays、recoveryInitiatedDate（寬容，缺欄 None）。
/// 欄名比對經 `json::get` 大小寫不敏感——雲（.NET camelCase）與 VW 同鍵名。
/// 缺 `id` 或缺 status 數字的條目跳過（形態漂移不炸，紀律同 `two_factor::parse_list`）。
pub fn parse_contacts(raw: &Value, role: EaRole) -> Vec<EaContact> {
    let arr = match raw {
        Value::Array(a) => a.clone(),
        Value::Object(_) => get(raw, &["data"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let id_key = match role {
        EaRole::Grantee => "granteeId",
        EaRole::Grantor => "grantorId",
    };
    arr.iter()
        .filter_map(|c| {
            let id = get_str(c, &["id"])?;
            let status = get_i64(c, &["status"])?;
            let atype = get_i64(c, &["type"]).unwrap_or(0);
            Some(EaContact {
                id: id.to_owned(),
                user_id: get_str(c, &[id_key]).map(str::to_owned),
                email: get_str(c, &["email"]).unwrap_or_default().to_owned(),
                name: get_str(c, &["name"]).unwrap_or_default().to_owned(),
                status: EaStatus::from_wire(status),
                access_type: EaAccessType::from_wire(atype),
                wait_time_days: get_i64(c, &["waitTimeDays"]).unwrap_or(0) as u32,
                recovery_initiated_at: get_str(c, &["recoveryInitiatedDate"]).map(str::to_owned),
                role,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VW 1.37.2 實錄形態（`dev/e2e/ea.sh` 錄，2026-11-16）：
    /// grantee 清單含已確認（granteeId 在場）與邀請中（僅 email）兩條。
    #[test]
    fn parse_contacts_vaultwarden_shape() {
        let raw = serde_json::json!({
            "data": [
                {
                    "id": "6f1e0000-1111-4aaa-8bbb-000000000001",
                    "status": 2,
                    "type": 0,
                    "waitTimeDays": 7,
                    "granteeId": "3b3a0000-2222-4ccc-8ddd-000000000002",
                    "email": "grantee@bitward.test",
                    "name": "測試受託人",
                    "avatarColor": null,
                    "object": "emergencyAccessGranteeDetails"
                },
                {
                    "id": "6f1e0000-3333-4aaa-8bbb-000000000003",
                    "status": 0,
                    "type": 1,
                    "waitTimeDays": 2,
                    "granteeId": null,
                    "email": "ghost@bitward.test",
                    "name": "",
                    "object": "emergencyAccessGranteeDetails"
                },
                { "object": "junk-no-id" }
            ],
            "object": "list",
            "continuationToken": null
        });
        let rows = parse_contacts(&raw, EaRole::Grantee);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].status, EaStatus::Confirmed);
        assert_eq!(rows[0].access_type, EaAccessType::View);
        assert_eq!(rows[0].wait_time_days, 7);
        assert_eq!(
            rows[0].user_id.as_deref(),
            Some("3b3a0000-2222-4ccc-8ddd-000000000002")
        );
        assert_eq!(rows[1].status, EaStatus::Invited);
        assert_eq!(rows[1].access_type, EaAccessType::Takeover);
        assert_eq!(rows[1].user_id, None);
        assert_eq!(rows[1].recovery_initiated_at, None);
    }

    /// 官方雲形態（推導釘選，來源 `EmergencyAccessResponseModel.cs`：
    /// .NET camelCase、enum 序列化為整數，`EmergencyAccessViewResponseModel`
    /// 另帶 `recoveryInitiatedDate`；takeover 回包多一欄 `salt`＝KDF 鹽
    /// （VW 用 email，接管派生時有 salt 用 salt））。
    #[test]
    fn parse_contacts_cloud_shape_with_recovery_date() {
        let raw = serde_json::json!({
            "data": [
                {
                    "id": "e001",
                    "name": "家人",
                    "email": "fam@example.com",
                    "status": 3,
                    "type": 1,
                    "waitTimeDays": 3,
                    "granteeId": "u-9",
                    "avatarColor": null,
                    "recoveryInitiatedDate": "2026-11-16T00:00:00Z",
                    "object": "emergencyAccessGranteeDetails"
                }
            ],
            "object": "list",
            "continuationToken": null
        });
        let rows = parse_contacts(&raw, EaRole::Grantee);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, EaStatus::RecoveryInitiated);
        assert_eq!(rows[0].access_type, EaAccessType::Takeover);
        assert_eq!(
            rows[0].recovery_initiated_at.as_deref(),
            Some("2026-11-16T00:00:00Z")
        );
    }

    #[test]
    fn unknown_status_number_survives_as_other() {
        let raw = serde_json::json!([
            {"id": "x", "status": 9, "type": 0, "waitTimeDays": 1, "granteeId": "u"}
        ]);
        let rows = parse_contacts(&raw, EaRole::Grantee);
        assert_eq!(rows[0].status, EaStatus::Other(9));
    }

    #[test]
    fn paths_template_public_key_urls() {
        assert_eq!(EaPaths::VAULTWARDEN.pubkey_for("u1"), "users/u1/public-key");
        assert_eq!(EaPaths::CLOUD.pubkey_for("u1"), "accounts/u1/public-key");
        assert_eq!(EaPaths::CLOUD_LEGACY.base, "accounts/emergency-access");
    }

    #[test]
    fn for_kind_pins_server_shapes() {
        assert_eq!(
            EaPaths::for_kind(bw_proto::ServerKind::Vaultwarden),
            Some(EaPaths::VAULTWARDEN)
        );
        assert_eq!(
            EaPaths::for_kind(bw_proto::ServerKind::BitwardenCloud),
            Some(EaPaths::CLOUD)
        );
        assert_eq!(EaPaths::for_kind(bw_proto::ServerKind::Unknown), None);
    }
}
