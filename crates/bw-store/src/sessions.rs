//! agent session 持久層（§2.3）。治理語意在 bw-agent；這裡只管落盤與
//! epoch 級聯（lock 之後整批標 revoked 的 store 端動作）。
//! push token 帳（§1.2 推播）同屬「配對裝置的持久登記」，寄此模組。

use serde::{Deserialize, Serialize};

use crate::{Store, StoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Suspended,
    Revoked,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Active => "active",
            SessionState::Suspended => "suspended",
            SessionState::Revoked => "revoked",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(SessionState::Active),
            "suspended" => Some(SessionState::Suspended),
            "revoked" => Some(SessionState::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub principal: serde_json::Value,
    pub grants: serde_json::Value,
    pub epoch: u64,
    pub state: SessionState,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl Store {
    pub fn session_put(&self, s: &SessionRow) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO sessions(id, principal, grants, epoch, state, created_at, expires_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET principal=excluded.principal, grants=excluded.grants,
               epoch=excluded.epoch, state=excluded.state, expires_at=excluded.expires_at",
            rusqlite::params![
                s.id,
                s.principal.to_string(),
                s.grants.to_string(),
                s.epoch as i64,
                s.state.as_str(),
                s.created_at as i64,
                s.expires_at.map(|v| v as i64),
            ],
        )?;
        Ok(())
    }

    pub fn session_get(&self, id: &str) -> StoreResult<Option<SessionRow>> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, principal, grants, epoch, state, created_at, expires_at FROM sessions WHERE id = ?1",
        )?;
        stmt.query_row([id], map_session)
            .optional()
            .map_err(Into::into)
    }

    pub fn session_list(&self) -> StoreResult<Vec<SessionRow>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, principal, grants, epoch, state, created_at, expires_at FROM sessions ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], map_session)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// 級聯撤銷：鎖世代推進後，綁在舊 epoch 的 active/suspended session 全部作廢
    /// （治 #22773 的共享狀態反面：本裝置解鎖態變動必須同步反映到 session 帳）。
    /// 回傳撤銷數。
    pub fn sessions_revoke_before(&self, epoch: u64) -> StoreResult<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n = conn.execute(
            "UPDATE sessions SET state = 'revoked'
             WHERE epoch < ?1 AND state IN ('active','suspended')",
            [epoch as i64],
        )?;
        Ok(n as u32)
    }

    pub fn session_set_state(&self, id: &str, state: SessionState) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE sessions SET state = ?2 WHERE id = ?1",
            rusqlite::params![id, state.as_str()],
        )?;
        Ok(())
    }

    /// 過期掃描：把到期 active session 標 revoked，回傳數量。
    pub fn sessions_expire(&self, now_ms: u64) -> StoreResult<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let n = conn.execute(
            "UPDATE sessions SET state = 'revoked'
             WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
            [now_ms as i64],
        )?;
        Ok(n as u32)
    }

    /// 推播 token 註冊（§1.2 APNs）：INSERT OR REPLACE——app 每次啟動重報同一
    /// token 只更新 platform/時刻，收斂到「已註冊」穩定態（Make Operations Idempotent）。
    pub fn push_token_put(&self, token: &str, platform: &str) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO push_tokens(token, platform, registered_at) VALUES(?1, ?2, ?3)",
            rusqlite::params![token, platform, self.now_ms() as i64],
        )?;
        Ok(())
    }

    /// 移除 token：APNs 410（卸載）或用戶端主動 Unregister 都走這裡。
    /// 不存在的 token 回 Ok（冪等：目標態是「不在表裡」）。
    pub fn push_token_remove(&self, token: &str) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("DELETE FROM push_tokens WHERE token = ?1", [token])?;
        Ok(())
    }

    /// 全部註冊 token（(token, platform)，按註冊時間升序）；副發與清單出口共用。
    pub fn push_token_list(&self) -> StoreResult<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT token, platform FROM push_tokens ORDER BY registered_at")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn map_session(r: &rusqlite::Row<'_>) -> Result<SessionRow, rusqlite::Error> {
    let state = SessionState::parse(&r.get::<_, String>(4)?).unwrap_or(SessionState::Revoked);
    Ok(SessionRow {
        id: r.get(0)?,
        principal: serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or(serde_json::Value::Null),
        grants: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or(serde_json::Value::Null),
        epoch: r.get::<_, i64>(3)? as u64,
        state,
        created_at: r.get::<_, i64>(5)? as u64,
        expires_at: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
    })
}
