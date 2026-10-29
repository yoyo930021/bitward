//! bw-sync — 多中樞收斂的純協定黏合層（契约 §1.1、§2.4、§2.6、§3.5）。
//!
//! 定位：daemon 的 outbox push 路徑（`PUT /ciphers/{id}` 合成）、notifications
//! 事件解析、與 sync 觸發的單飛去重，都在这里。本層**不做加解密、不持金鑰、
//! 不碰 HTTP/WS 傳輸**：
//!
//! - 信封合成需要金鑰 → `build_put_body` 只放佔位字串，加密與替換發生在
//!   daemon 的 `with_keys` 閉包（契约 §2.2，不變量 1/4）。
//! - 網路在 bw-server（唯一碰 HTTP/WS 處，§3 依賴方向）；本層只吃位元組與 JSON。
//! - 三方合併本體在 bw-vault；本層只負責把合併結果（`FieldMap`）落成 PUT body。
//!
//! 協定常數（動詞兩態、`0x1e` 分隔符、`UpdateType` 編號、msgpack timestamp ext）
//! 的出處全部記錄在 `crates/bw-sync/NOTES.md`，測試 fixtures 在 `fixtures/`。

#![forbid(unsafe_code)]

pub mod flavor;
pub mod flight;
pub mod notify;
pub mod put;

pub use flavor::{DeleteVerbs, Method, ServerFlavor, delete_verbs};
pub use flight::{Run, RunCancelled, RunOutcome, SingleFlight};
pub use notify::{NotifyEvent, NotifyParser};
pub use put::{PLACEHOLDER_PREFIX, build_put_body, placeholder_for};
