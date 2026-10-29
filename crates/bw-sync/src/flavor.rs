//! Server 形態與刪除動詞（契约 §2.6）。
//!
//! Bitwarden 生態的寫入動詞不是單一套協定：官方雲（upstream `bitwarden/server`）
//! 與 Vaultwarden 在軟刪/還原/批次刪除上各有兩態，全部由 `crates/bw-server`
//! 在 VW 1.37.2 上實錄 + 原始碼雙重確認（見本 crate `NOTES.md` 的來源表）。
//! 這裡把這些 drift 釘成純資料，讓 outbox drain 不必在執行期試錯。

use bw_proto::ServerKind;
use serde::{Deserialize, Serialize};

/// 探測得到的伺服器形態（契约 §2.6 `ServerProfile` 的最小面）。
///
/// `version` 是 `/config.version`（協定版本，如 VW 1.37.2 報 `2026.6.0`）或
/// Vaultwarden 獨有的 `/api/version` 產品版本；呼叫端（daemon）決定放哪個，
/// 本層只承載、不判讀。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFlavor {
    /// 判讀後的 server 種類（判讀規則在 `crates/bw-server/NOTES.md`）。
    pub kind: ServerKind,
    /// 協定或產品版本字串（`/config.version`、`/api/version`）；未探測到時 `None`。
    pub version: Option<String>,
}

/// HTTP 動詞的最小鏡像。本層不依賴 `http`/`reqwest`（依賴方向：傳輸在
/// bw-server），只把「該用哪個動詞」講清楚，由呼叫端映射到自己的 client。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    /// `PUT`
    Put,
    /// `POST`
    Post,
    /// `DELETE`
    Delete,
}

impl Method {
    /// 大寫動詞字串，餵給任何 HTTP client。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// 刪除/還原/批次刪除的協定形態。路徑模板固定
/// （`/ciphers/{id}/delete`、`/ciphers/{id}/restore`、`/ciphers/delete`、
/// `/ciphers`），兩態只在動詞與批次欄位名。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteVerbs {
    /// 軟性刪除（進回收桶、可還原）的動詞。
    pub soft: Method,
    /// 永久刪除的動詞（`DELETE /ciphers/{id}`；Vaultwarden 的
    /// `POST /ciphers/{id}/delete` 是同效果的另一條路，不採用——
    /// 用 `DELETE` 讓兩態 server 的 hard 路徑完全一致）。
    pub hard: Method,
    /// 還原軟刪項目的動詞。
    pub restore: Method,
    /// 批次刪除 body 的欄位名：upstream 是 `cipherIds`，Vaultwarden 是 `ids`。
    pub bulk_field: &'static str,
}

/// 依 server kind 釘出刪除動詞組。來源見 `NOTES.md`「刪除動詞」表。
///
/// `Unknown` 採 upstream（官方雲）形態：Vaultwarden 的偏差是實錄出來的
/// 少數派，沒有任何旁證的 server 預設照 upstream 實作；若動詞被拒，
/// 降級與 quirk 記錄是 bw-server 傳輸層的責任（`Quirk::SoftDeleteOnlyPostVerb`
/// 等），不在本層猜。
#[must_use]
pub fn delete_verbs(kind: ServerKind) -> DeleteVerbs {
    match kind {
        // Official cloud: both PUT and POST `/ciphers/{id}/delete` soft-delete
        // (we pin PUT, matching bw-server `cipher_delete`'s first choice);
        // restore is POST; bulk body uses `cipherIds`.
        ServerKind::BitwardenCloud | ServerKind::Unknown => DeleteVerbs {
            soft: Method::Put,
            hard: Method::Delete,
            restore: Method::Post,
            bulk_field: "cipherIds",
        },
        // Vaultwarden: POST `/ciphers/{id}/delete` is a HARD delete, soft
        // delete must use PUT; restore only exists as PUT (POST is
        // route-not-found 404); bulk body uses `ids` (`CipherIdsData`).
        ServerKind::Vaultwarden => DeleteVerbs {
            soft: Method::Put,
            hard: Method::Delete,
            restore: Method::Put,
            bulk_field: "ids",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_verbs_pinned_from_upstream() {
        let v = delete_verbs(ServerKind::BitwardenCloud);
        assert_eq!(v.soft, Method::Put);
        assert_eq!(v.hard, Method::Delete);
        assert_eq!(v.restore, Method::Post);
        assert_eq!(v.bulk_field, "cipherIds");
    }

    #[test]
    fn vaultwarden_verbs_pinned_from_recorded_drift() {
        let v = delete_verbs(ServerKind::Vaultwarden);
        assert_eq!(v.soft, Method::Put, "POST 在 VW 是永久刪除，軟刪只能 PUT");
        assert_eq!(v.hard, Method::Delete);
        assert_eq!(v.restore, Method::Put, "VW 的 POST restore 是 404");
        assert_eq!(v.bulk_field, "ids");
    }

    #[test]
    fn unknown_server_defaults_to_upstream_shape() {
        assert_eq!(
            delete_verbs(ServerKind::Unknown),
            delete_verbs(ServerKind::BitwardenCloud)
        );
    }

    #[test]
    fn method_strings_are_uppercase() {
        assert_eq!(Method::Put.as_str(), "PUT");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    #[test]
    fn flavor_roundtrips_through_serde() {
        let f = ServerFlavor {
            kind: ServerKind::Vaultwarden,
            version: Some("2026.6.0".to_owned()),
        };
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<ServerFlavor>(&j).unwrap(), f);
    }
}
