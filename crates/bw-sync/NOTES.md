# bw-sync NOTES — 協定常數與形態的出處

契约 §1.1、§2.4、§2.6、§3.5 的實作面。本 crate 是純協定黏合層：不加解密、
不持金鑰、不碰 HTTP/WS。每條常數給來源 URL；Vaultwarden 側的 drift 全部引
`crates/bw-server/NOTES.md` 的實錄（VW 1.37.2，2026-10-29 錄製）與原始碼行號，
不重複抄錄。測試樣本見 `fixtures/README.md`。

## 刪除動詞（`flavor::delete_verbs`）

| 事項 | BitwardenCloud | Vaultwarden 1.37.2 | 來源 |
|---|---|---|---|
| 軟刪 `/ciphers/{id}/delete` | `PUT`（POST 亦軟刪，取 PUT 與 bw-server 首選一致） | **`PUT`**（`POST` 是永久刪除！） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/ciphers.rs#L1462-L1484 |
| 硬刪 | `DELETE /ciphers/{id}` | `DELETE /ciphers/{id}`（兩態一致，故 hard 不分岔） | 同上 #L1462-L1484；bw-server `vault.rs::cipher_delete` 用同一條 |
| 還原 `/ciphers/{id}/restore` | `POST` | **只有 `PUT`**（POST 是 route-not-found 404） | 同上 #L1564-L1585；實錄 `crates/bw-server/fixtures/ciphers_restore_post_404_vw.json` |
| 批次刪除 body 欄位 | `cipherIds` | **`ids`**（`CipherIdsData`） | 同上 #L1841-L1843；實錄 `crates/bw-server/fixtures/ciphers_bulk_delete_cipherIds_400_vw.json` |
| `Unknown` 的預設 | 採 upstream 形態 | — | 「不猜」原則見 `crates/bw-server/NOTES.md`「ServerProfile 判讀」；偏差是實錄出來的少數派，quirk 降級歸 bw-server |

## PUT body 合成（`put::build_put_body`）

| 事項 | 值 | 來源 |
|---|---|---|
| 欄位路徑文法 | `name`、`notes`、`username`、`password`、`totp`、`favorite`、`uri.<n>`、`field.<id>.name`、`field.<id>.value` | 權威定義：`bw_proto::FieldEdit` 文件註解（三處共用：bw-vault flatten、bw-sync build_put_body、daemon）；`field.<id>.*` 是本層擴充（自訂欄位巢狀置換） |
| 欄位落點 | `$.name`、`$.notes`、`$.login.{username,password,totp}`、`$.login.uris[n].uri`、`$.fields[id==…].{name,value}`、`$.favorite` | 錄製形態 `crates/bw-server/fixtures/ciphers_update_request_vw.json`、`ciphers_get_vw_1.37.2.json` |
| 佔位字串 | `__bw_sync_pending__:<path>`（前綴 `PLACEHOLDER_PREFIX`） | 本層設計：加密在 daemon 的 `with_keys` 閉包（契约 §2.2），本層不持金鑰；內嵌路徑避免多欄位互撞 |
| `uri.<n>` 越界 | 回 `Err`（增刪 uri 屬整陣列替換的 op，不在此路徑） | 契约 §2.4：`Patch` 由 raw + diff 合成 |
| `fields[].id` 比對 | 字串或轉字串的數字都接受 | VW 的欄位 id 為字串；上游 JSON 形態見 `crates/bw-server/fixtures/ciphers_get_vw_1.37.2.json`（`fields` 兩態：VW 為 array） |
| 欄位級 `PUT /ciphers/{id}/partial` 的兩態 | Vaultwarden 只認 `folderId`/`favorite`（送 password → 422），所以本層走**全量 PUT raw+diff** 而非 partial | `crates/bw-server/NOTES.md`「欄位級 patch」列（`PartialUpdateLimitedToFolderAndFavorite`） |

## notifications 解析（`notify::NotifyParser`）

| 事項 | 值 | 來源 |
|---|---|---|
| 記錄分隔符 | `0x1e`（RECORD_SEPARATOR） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L334 |
| 官方雲協議 | ASP.NET Core SignalR json hub protocol；invocation `type:1`；`arguments` 可能再包一層 JSON 字串 | https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Protocols.Json/src/JsonHubProtocol.cs ；https://github.com/bitwarden/server/blob/main/src/Notifications/Hub.cs ；雙層包裹形態錄自 bw-server `tests/compat_fixtures.rs` |
| Vaultwarden 協議 | messagepack 握手後，binary frame = SignalR 長度前綴 + msgpack invocation `[1, headers, invId, target, arguments]`，通知本體 `{ContextId,Type,Payload}` | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L334-L345 、#L614-L650；實錄 `fixtures/notify_vw_msgpack_cipher_create.bin` |
| 長度前綴 | varint：7-bit 一組、最高位為續位元組 | https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Shared/src/BinaryMessageFormat.cs |
| SignalR 型別碼 | 1 = invocation、3 = completion、6 = ping/keepalive、7 = ack | https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Protocols.Json/src/JsonHubProtocol.cs |
| cipher 級事件編號 | SyncCipherUpdate=0、SyncCipherCreate=1、SyncLoginDelete=2 → `CipherChanged`；其他編號 → `Other`（承載通知本體 JSON） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L678-L700 （註解指向 https://github.com/bitwarden/server/blob/375af7c/src/Core/Enums/PushType.cs ） |
| 通知欄位大小寫 | `Type`/`NotificationType`/`notificationType` + `Payload`/`payload` 兩態都吃 | 官方雲用 `NotificationType`、VW 用 `Type`：bw-server `notify.rs` 實錄行為 |
| msgpack timestamp ext | type `-1`、8 bytes big-endian = `(nanos << 34) \| seconds`，轉秒級 RFC3339 | https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type ；https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L310-L322 |
| civil_from_days | 日期演算法 | http://howardhinnant.github.io/date_algorithms.html |

## 單飛去重（`flight::SingleFlight`）

| 事項 | 值 | 來源 |
|---|---|---|
| 重視窗 | 預設 250ms（`DEFAULT_COALESCE`） | 契約建議值（P2 assignment「如 250ms coalesce」）；debounce 同型見 research/prior-art.md 的 rbw-agent |
| 涵蓋規則 | 只認「在你 trigger 之後**開始**的 sync」；進行中的班機不回頭涵蓋晚到的 trigger | 契约 §1.1：notifications 事件 → targeted pull 的正確性條件（A12：事件到達後 5 秒內鏡像更新） |
| 世代計數器 | 單調遞增 u64，`completed_generation` 只由完成的班機推進 | 契約 §2.4 的 CAS 語意同構：鏡像比對用 `base_rev`，排程收斂用世代 |

## 邊界（刻意不做）

- **不加解密**：佔位字串由 daemon 換信封；本層看不到金鑰（不變量 1）。
- **不碰網路**：WS frame 邊界由傳輸層（bw-server）保證，`feed` 不收串流位元組。
- **不做 outbox 佇列本身**：`Mutation`/`seq`/`base_rev` 在 bw-store；本層只給
  push 前的 body 合成與觸發節流。
- **不驗證 JWT、不判讀 `ServerProfile` 探測**：判讀規則在
  `crates/bw-server/NOTES.md`「ServerProfile 判讀」，本層只承載結果型別。
