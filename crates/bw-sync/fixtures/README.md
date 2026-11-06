# bw-sync fixtures — 通知樣本出處

全部從 `crates/bw-server/fixtures/`（VW 1.37.2 於 2026-10-29 實錄）**唯讀複製**，
原檔未動；官方雲無帳號未錄製，以文件形態樣本覆蓋（依據同
`crates/bw-server/fixtures/README.md`）。協定常數來源總表見 `../NOTES.md`。

| 檔 | 形態 | 內容 | 來源 |
|---|---|---|---|
| `notify_vw_msgpack_cipher_create.bin` | WS binary frame（SignalR messagepack） | varint 長度前綴 `0xca 0x01`(=202) + `[1, {}, null, "ReceiveMessage", [{ContextId,Type:1,Payload:{Id:66b31944-…,RevisionDate:ext -1}}]]` → SyncCipherCreate | 位元組相同複製自 `crates/bw-server/fixtures/notifications_vw_msgpack_frame.bin`（真實 WS 連線錄得） |
| `notify_cloud_signalr_cipher_update.json` | WS text frame（SignalR json hub protocol） | `type:1` invocation，`arguments` 為**再包一層 JSON 字串**的 `{NotificationType:0, Payload:{Id:…}}` → SyncCipherUpdate | 形態：`crates/bw-server/tests/compat_fixtures.rs::signalr_json_invocation_frame_decodes`（文件形態內嵌樣本）；協議：aspnetcore JsonHubProtocol + bitwarden/server `src/Notifications/Hub.cs` |
| `notify_cloud_signalr_multi.txt` | WS text frame，3 條以 `0x1e` 分隔 | 握手回應 `{}` + keepalive `{"type":6}` + `NotificationType:5`（SyncVault）invocation → 只應解出 1 個 `Other` 事件 | 同上（`0x1e` 分包與控制 frame 形態依 NOTES.md「notifications」表） |
| `sync_org_owner_vw.json` | 完整 `GET /sync`（org 形態） | 雙帳號 e2e 的 owner 視角：`profile.organizations[]`（`key` = `2.` 對稱 akey、status 2、type 0）、`collections[]`×2、org cipher（`organizationId` + `collectionIds`）+ 個人 cipher | `dev/e2e/orgpath.sh`（RECORD_FIXTURES=1）對 VW 1.37.2 實錄，2026-11-07 |
| `sync_org_member_vw.json` | 完整 `GET /sync`（org 形態） | 同次 e2e 的成員視角：`key` = `4.` RSA akey（成員公鑰包裝）、僅共享 cipher 可見 | 同上 |

org/collection 的解析回歸在 `crates/bw-store/tests/store.rs::apply_sync_replays_recorded_org_sync`
（`bw-store` 是 `apply_sync` 的家；本層只放錄製樣本，測試經 manifest 相對路徑讀取）。

測試只斷言形態與欄位存在性（CipherChanged 的 id 值來自錄製樣本本身）。
重錄流程見 `crates/bw-server/fixtures/README.md`。
