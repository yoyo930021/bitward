# bw-sync fixtures — 通知樣本出處

全部從 `crates/bw-server/fixtures/`（VW 1.37.2 於 2026-10-29 實錄）**唯讀複製**，
原檔未動；官方雲無帳號未錄製，以文件形態樣本覆蓋（依據同
`crates/bw-server/fixtures/README.md`）。協定常數來源總表見 `../NOTES.md`。

| 檔 | 形態 | 內容 | 來源 |
|---|---|---|---|
| `notify_vw_msgpack_cipher_create.bin` | WS binary frame（SignalR messagepack） | varint 長度前綴 `0xca 0x01`(=202) + `[1, {}, null, "ReceiveMessage", [{ContextId,Type:1,Payload:{Id:66b31944-…,RevisionDate:ext -1}}]]` → SyncCipherCreate | 位元組相同複製自 `crates/bw-server/fixtures/notifications_vw_msgpack_frame.bin`（真實 WS 連線錄得） |
| `notify_cloud_signalr_cipher_update.json` | WS text frame（SignalR json hub protocol） | `type:1` invocation，`arguments` 為**再包一層 JSON 字串**的 `{NotificationType:0, Payload:{Id:…}}` → SyncCipherUpdate | 形態：`crates/bw-server/tests/compat_fixtures.rs::signalr_json_invocation_frame_decodes`（文件形態內嵌樣本）；協議：aspnetcore JsonHubProtocol + bitwarden/server `src/Notifications/Hub.cs` |
| `notify_cloud_signalr_multi.txt` | WS text frame，3 條以 `0x1e` 分隔 | 握手回應 `{}` + keepalive `{"type":6}` + `NotificationType:5`（SyncVault）invocation → 只應解出 1 個 `Other` 事件 | 同上（`0x1e` 分包與控制 frame 形態依 NOTES.md「notifications」表） |

測試只斷言形態與欄位存在性（CipherChanged 的 id 值來自錄製樣本本身）。
重錄流程見 `crates/bw-server/fixtures/README.md`。
