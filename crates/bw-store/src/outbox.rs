//! 離線寫入 outbox（契約 §2.4）：mirror+outbox 同交易、同 item FIFO、
//! 認領帶租約（崩潰後可重取）、衝突收件匣。

use bw_proto::{ItemId, MutationId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Store, StoreError, StoreResult, ciphers::write_cipher, unix_ms};

/// 租約長度：`in_flight` 超過此時數可被 `take_due_at` 重取（daemon kill -9 復原）。
/// 本專案自訂（P2 設計）；A7 要求秒級重生，120s 上限讓重推不超過一個租約週期。
pub const LEASE_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutState {
    Queued,
    InFlight,
    Awaiting,
    Applied,
    Conflict,
    Dead,
}

impl MutState {
    pub fn as_str(self) -> &'static str {
        match self {
            MutState::Queued => "queued",
            MutState::InFlight => "in_flight",
            MutState::Awaiting => "awaiting",
            MutState::Applied => "applied",
            MutState::Conflict => "conflict",
            MutState::Dead => "dead",
        }
    }
    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "queued" => Ok(MutState::Queued),
            "in_flight" => Ok(MutState::InFlight),
            "awaiting" => Ok(MutState::Awaiting),
            "applied" => Ok(MutState::Applied),
            "conflict" => Ok(MutState::Conflict),
            "dead" => Ok(MutState::Dead),
            other => Err(StoreError::Invalid(format!("unknown mut state {other}"))),
        }
    }
    /// 終態：不再阻擋同 item 的後續變更。
    pub fn terminal(self) -> bool {
        matches!(self, MutState::Applied | MutState::Dead)
    }
}

/// 入列請求。`payload` 是 {op, ...} 的 JSON（機密欄位已由持有金鑰的呼叫端
/// 加密成信封字串；bw-store 不知金鑰語意），`mirror` 是同步要落的鏡像 cipher。
pub struct MutationDraft<'a> {
    pub item: ItemId,
    pub payload: Value,
    pub base_rev: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub mirror: Option<&'a Value>,
}

#[derive(Clone, Debug)]
pub struct Mutation {
    pub id: MutationId,
    pub item: ItemId,
    pub payload: Value,
    pub base_rev: Option<String>,
    pub state: MutState,
    pub origin: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboxDepth {
    pub queued: u32,
    pub in_flight: u32,
    pub awaiting: u32,
    pub conflict: u32,
    pub dead: u32,
    pub total: u32,
}

#[derive(Clone, Debug)]
pub struct ConflictRecord {
    pub id: MutationId,
    pub item: ItemId,
    pub ours: Value,
    pub base_rev: Option<String>,
    pub origin: Option<String>,
    pub created_at: u64,
}

impl Store {
    /// 寫入一律「本地 transaction（mirror+outbox 同交易）→ 非阻塞 push」（§2.4）。
    pub fn enqueue(&self, d: &MutationDraft<'_>) -> StoreResult<MutationId> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        if let Some(mirror) = d.mirror {
            if mirror.get("id").and_then(Value::as_str).is_none() {
                return Err(StoreError::Invalid("mirror cipher missing `id`".into()));
            }
            write_cipher(&tx, d.item, mirror)?;
        }
        tx.execute(
            "INSERT INTO outbox(item, base_rev, payload, state, origin, created_at)
             VALUES(?1,?2,?3,'queued',?4,?5)",
            rusqlite::params![
                d.item.to_string(),
                d.base_rev,
                serde_json::to_vec(&d.payload)?,
                d.origin,
                unix_ms() as i64,
            ],
        )?;
        let id = tx.last_insert_rowid() as u64;
        crate::ciphers::refresh_pending(&tx, Some(d.item))?;
        tx.commit()?;
        Ok(MutationId(id))
    }

    pub fn take_due(&self, n: u32) -> StoreResult<Vec<Mutation>> {
        self.take_due_at(unix_ms(), n)
    }

    /// 同 item FIFO：一個 item 一次只認領最舊的非終態列；前筆未 settled 之前，
    /// 後續筆不可出境（跨裝置併發靠 base_rev CAS + 這條序列，§1.1）。
    /// 租約過期的 `in_flight` 列可被重取（崩潰復原）。
    pub fn take_due_at(&self, now_ms: u64, n: u32) -> StoreResult<Vec<Mutation>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let mut stmt = tx.prepare(
            "SELECT o.seq, o.item, o.payload, o.base_rev, o.state, o.origin, o.created_at
             FROM outbox o
             WHERE (o.state = 'queued'
                    OR (o.state = 'in_flight' AND COALESCE(o.leased_at, 0) + ?1 <= ?2))
               AND o.seq = (SELECT MIN(x.seq) FROM outbox x
                            WHERE x.item = o.item AND NOT (x.state IN ('applied','dead')))
             ORDER BY o.seq LIMIT ?3",
        )?;
        let due: Vec<(i64, Vec<u8>)> = stmt
            .query_map(
                rusqlite::params![LEASE_MS as i64, now_ms as i64, n as i64],
                |r| Ok((r.get(0)?, r.get(2)?)),
            )?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        let mut out = Vec::with_capacity(due.len());
        for (seq, payload) in due {
            tx.execute(
                "UPDATE outbox SET state='in_flight', leased_at=?1 WHERE seq=?2",
                rusqlite::params![now_ms as i64, seq],
            )?;
            let row: (String, Option<String>, Option<String>, i64) = tx.query_row(
                "SELECT item, base_rev, origin, created_at FROM outbox WHERE seq = ?1",
                [seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            out.push(Mutation {
                id: MutationId(seq as u64),
                item: Uuid::parse_str(&row.0).map_err(|e| StoreError::Invalid(e.to_string()))?,
                payload: serde_json::from_slice(&payload)?,
                base_rev: row.1,
                state: MutState::InFlight,
                origin: row.2,
                created_at: row.3 as u64,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn settle(&self, id: MutationId, outcome: MutState) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let item: Option<String> = tx
            .query_row(
                "UPDATE outbox SET state = ?1, leased_at = NULL WHERE seq = ?2 RETURNING item",
                rusqlite::params![outcome.as_str(), id.0 as i64],
                |r| r.get(0),
            )
            .ok();
        let Some(item) = item else {
            return Err(StoreError::NotFound);
        };
        crate::ciphers::refresh_pending(&tx, Some(parse_id(&item)?))?;
        tx.commit()?;
        Ok(())
    }

    pub fn conflicts(&self) -> StoreResult<Vec<ConflictRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT seq, item, payload, base_rev, origin, created_at FROM outbox
             WHERE state = 'conflict' ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, item, payload, base_rev, origin, created_at) = row?;
            out.push(ConflictRecord {
                id: MutationId(seq as u64),
                item: parse_id(&item)?,
                ours: serde_json::from_slice(&payload)?,
                base_rev,
                origin,
                created_at: created_at as u64,
            });
        }
        Ok(out)
    }

    /// 「N 項待同步」給 UI。
    pub fn depth(&self) -> StoreResult<OutboxDepth> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT state, COUNT(*) FROM outbox GROUP BY state")?;
        let mut d = OutboxDepth::default();
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (state, n) = row?;
            let n = n as u32;
            d.total += n;
            match MutState::parse(&state)? {
                MutState::Queued => d.queued += n,
                MutState::InFlight => d.in_flight += n,
                MutState::Awaiting => d.awaiting += n,
                MutState::Conflict => d.conflict += n,
                MutState::Dead => d.dead += n,
                MutState::Applied => {}
            }
        }
        Ok(d)
    }
}

pub(crate) fn parse_id(s: &str) -> StoreResult<ItemId> {
    Uuid::parse_str(s).map_err(|e| StoreError::Invalid(format!("bad item id {s}: {e}")))
}
