//! append-only 審計 hash 鏈（契約 §2.3、A8）。
//! `bitward audit --verify` 逐列重算：篡改任一欄位或斷鏈都在該 seq 報錯。

use bw_proto::Sensitivity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Store, StoreError, StoreResult, sha256_hex};

/// 鏈頭：Genesis 用全零。來源：本專案自訂（§2.3 定義欄位集，未定初值）。
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub session: Option<String>,
    pub action: String,
    pub item: Option<String>,
    /// FieldPath 的 JSON 表示（§2.1 唯一座標系）。
    pub field: Option<Value>,
    pub sens: Sensitivity,
    pub outcome: String,
    pub bytes_out: u64,
    pub approval: Option<String>,
    pub epoch: u64,
}

#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub since_ts: Option<String>,
    pub session: Option<String>,
    pub item: Option<String>,
    pub limit: u32,
}

impl AuditRecord {
    /// 正規化序列化：欄位順序固定、以 \x1f 分隔（ASCII unit separator，
    /// 不會出現在 ts/action 等可讀欄位）。來源：本專案自訂。
    fn canonical(&self, seq: i64, prev_hash: &str) -> Vec<u8> {
        let field = field_text(self.field.as_ref());
        [
            seq.to_string(),
            prev_hash.to_string(),
            self.ts.clone(),
            self.session.clone().unwrap_or_default(),
            self.action.clone(),
            self.item.clone().unwrap_or_default(),
            field,
            sens_code(self.sens).to_string(),
            self.outcome.clone(),
            self.bytes_out.to_string(),
            self.approval.clone().unwrap_or_default(),
            self.epoch.to_string(),
        ]
        .join("\u{1f}")
        .into_bytes()
    }
}

fn field_text(field: Option<&Value>) -> String {
    field
        .map(|f| match f {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

fn parse_field(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_owned()))
}

impl Store {
    pub fn audit_append(&self, r: &AuditRecord) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let prev = audit_head_conn(&tx)?.unwrap_or_else(|| GENESIS_HASH.to_string());
        let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit", [], |r| {
            r.get(0)
        })?;
        let hash = sha256_hex(&r.canonical(seq, &prev));
        tx.execute(
            "INSERT INTO audit(seq, ts, session, action, item, field, sens, outcome, bytes_out, approval, epoch, prev_hash, hash)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            rusqlite::params![
                seq,
                r.ts,
                r.session,
                r.action,
                r.item,
                r.field.as_ref().map(|f| field_text(Some(f))),
                sens_code(r.sens),
                r.outcome,
                r.bytes_out as i64,
                r.approval,
                r.epoch as i64,
                prev,
                hash,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 回傳 (鏈長, 頭哈希)。重算每列 `hash` 並串接 `prev_hash`；
    /// 不符即 `ChainBroken`（篡改偵測）。
    pub fn audit_verify(&self) -> StoreResult<(u64, String)> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT seq, ts, session, action, item, field, sens, outcome, bytes_out, approval, epoch, prev_hash, hash
             FROM audit ORDER BY seq",
        )?;
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut last_hash = GENESIS_HASH.to_string();
        let mut count = 0u64;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, String>(11)?,
                r.get::<_, String>(12)?,
            ))
        })?;
        for row in rows {
            let (
                seq,
                ts,
                session,
                action,
                item,
                field,
                sens,
                outcome,
                bytes_out,
                approval,
                epoch,
                prev_hash,
                hash,
            ) = row?;
            if prev_hash != expected_prev {
                return Err(StoreError::ChainBroken {
                    seq,
                    expected: expected_prev,
                    found: prev_hash,
                });
            }
            let rec = AuditRecord {
                ts,
                session,
                action,
                item,
                field: field.as_deref().map(parse_field),
                sens: decode_sens(sens),
                outcome,
                bytes_out: bytes_out as u64,
                approval,
                epoch: epoch as u64,
            };
            let recomputed = sha256_hex(&rec.canonical(seq, &expected_prev));
            if recomputed != hash {
                return Err(StoreError::ChainBroken {
                    seq,
                    expected: recomputed,
                    found: hash,
                });
            }
            expected_prev = hash.clone();
            last_hash = hash;
            count += 1;
        }
        Ok((count, last_hash))
    }

    pub fn audit_query(&self, f: &AuditFilter) -> StoreResult<Vec<AuditRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut sql = String::from(
            "SELECT ts, session, action, item, field, sens, outcome, bytes_out, approval, epoch
             FROM audit WHERE 1=1",
        );
        let mut args: Vec<String> = Vec::new();
        if let Some(since) = &f.since_ts {
            sql.push_str(" AND ts >= ?");
            args.push(since.clone());
        }
        if let Some(s) = &f.session {
            sql.push_str(" AND session = ?");
            args.push(s.clone());
        }
        if let Some(i) = &f.item {
            sql.push_str(" AND item = ?");
            args.push(i.clone());
        }
        sql.push_str(" ORDER BY seq DESC");
        if f.limit > 0 {
            sql.push_str(" LIMIT ?");
            args.push(f.limit.to_string());
        }
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let field: Option<String> = r.get(4)?;
            Ok(AuditRecord {
                ts: r.get(0)?,
                session: r.get(1)?,
                action: r.get(2)?,
                item: r.get(3)?,
                field: field.as_deref().map(parse_field),
                sens: decode_sens(r.get(5)?),
                outcome: r.get(6)?,
                bytes_out: r.get::<_, i64>(7)? as u64,
                approval: r.get(8)?,
                epoch: r.get::<_, i64>(9)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn audit_head(&self) -> StoreResult<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        audit_head_conn(&conn)
    }
}

fn audit_head_conn(conn: &rusqlite::Connection) -> StoreResult<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok())
}

fn sens_code(s: Sensitivity) -> i64 {
    match s {
        Sensitivity::Opaque => 0,
        Sensitivity::Identity => 1,
        Sensitivity::Secret => 2,
    }
}

fn decode_sens(v: i64) -> Sensitivity {
    match v {
        1 => Sensitivity::Identity,
        2 => Sensitivity::Secret,
        _ => Sensitivity::Opaque,
    }
}
