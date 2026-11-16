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

use bw_proto::{EaAccessType, EaCall, EaRole, Response, WtpError};

use crate::hub::{DispatchResult, denied};

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
        }
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
}
