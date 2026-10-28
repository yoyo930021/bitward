//! SQLite 鏡像 + overlay + outbox + audit（契約 §3.4）。
//! 只存 `Prot<T>` 的加密態與已索引 metadata；不知金鑰語意。實作由 U5 填入。

use bw_proto::{ItemId, ItemMeta, MutationId};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("not found")]
    NotFound,
}

pub struct Store {
    _private: (),
}

impl Store {
    pub fn open(_path: &std::path::Path) -> Result<Self, StoreError> {
        todo!("U5: WAL、0600、schema migration（ciphers/meta_plain/overlay/outbox/audit/sessions）")
    }

    pub fn apply_sync(&self, _raw: &serde_json::Value) -> Result<u64, StoreError> {
        todo!("U5: 密文原樣落盤 + meta_plain 重建，回 cursor")
    }

    pub fn query(&self, _q: &bw_proto::Query) -> Result<Vec<ItemMeta>, StoreError> {
        todo!("U5: 只回 Opaque+Identity；永不含 Secret")
    }

    pub fn enqueue(&self, _item: ItemId, _op: serde_json::Value) -> Result<MutationId, StoreError> {
        todo!("U5: mirror+outbox 同 transaction（§2.4）")
    }

    pub fn audit_append(&self, _record: &serde_json::Value) -> Result<(), StoreError> {
        todo!("U5: hash 鏈 append-only（§2.3）")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // U5：transaction 原子性、hash 鏈驗證、0600 權限測試
    }
}
