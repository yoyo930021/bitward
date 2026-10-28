//! 本地權威 overlay：tags / pinned / last_used / sort_hint（§4 資料管理缺口）。
//! 協定沒有這些欄位 → 不進鏡像、不推伺服器（tags 跨裝置同步是開放問題 Q3）。

use bw_proto::ItemId;
use rusqlite::OptionalExtension;

use crate::{Store, StoreError, StoreResult};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Overlay {
    pub tags: Vec<String>,
    pub pinned: bool,
    pub last_used: Option<u64>,
    pub sort_hint: Option<f64>,
}

#[derive(Clone, Debug)]
pub enum OverlayOp {
    SetTags(Vec<String>),
    SetPinned(bool),
    TouchUsed { at_ms: u64 },
    SetSortHint(Option<f64>),
}

impl Store {
    pub fn overlay(&self, id: ItemId, op: OverlayOp) -> StoreResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO overlay(id, tags, pinned, last_used, sort_hint) VALUES(?1,'[]',0,NULL,NULL)
             ON CONFLICT(id) DO NOTHING",
            [id.to_string()],
        )?;
        let (col, val): (&str, rusqlite::types::Value) = match &op {
            OverlayOp::SetTags(tags) => (
                "tags",
                rusqlite::types::Value::Text(serde_json::to_string(tags)?),
            ),
            OverlayOp::SetPinned(p) => ("pinned", rusqlite::types::Value::Integer(*p as i64)),
            OverlayOp::TouchUsed { at_ms } => {
                ("last_used", rusqlite::types::Value::Integer(*at_ms as i64))
            }
            OverlayOp::SetSortHint(h) => (
                "sort_hint",
                match h {
                    Some(v) => rusqlite::types::Value::Real(*v),
                    None => rusqlite::types::Value::Null,
                },
            ),
        };
        let sql = format!("UPDATE overlay SET {col} = ?2 WHERE id = ?1");
        conn.execute(&sql, rusqlite::params![id.to_string(), val])?;
        Ok(())
    }

    pub fn overlay_get(&self, id: ItemId) -> StoreResult<Overlay> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let row = conn
            .query_row(
                "SELECT tags, pinned, last_used, sort_hint FROM overlay WHERE id = ?1",
                [id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, Option<f64>>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            Some((tags, pinned, last_used, sort_hint)) => Ok(Overlay {
                tags: serde_json::from_str(&tags)?,
                pinned: pinned != 0,
                last_used: last_used.map(|v| v as u64),
                sort_hint,
            }),
            None => Err(StoreError::NotFound),
        }
    }
}
