# bw-server NOTES — 魔術數字與欄位形態的出處

契约 §3.3 的實作面。每條都是「代碼show不了的 why」或需要 URL 背書的常數。
录製證據在 `fixtures/README.md`（Vaultwarden 1.37.2 於 2026-10-29 實錄，
官方雲的公開端點同日實錄）。

## 路徑佈局

| 事項 | 值 | 來源 |
|---|---|---|
| token 端點 | `POST {identity}/connect/token` | https://contributing.bitwarden.com/architecture/deep-dives/authentication |
| self-hosted 掛載 | identity 在 `/identity`、core API 在 `/api`、notifications 在 `/notifications`、events 在 `/events` | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/main.rs#L585-L591 |
| `/config` 位置 | Vaultwarden 只有 `/api/config`（根路徑被 web-vault 吃成 HTML 404）；官方雲 `https://api.bitwarden.com/config` | 實錄 `fixtures/config_vw_root_404.html`、`fixtures/config_bitwarden_cloud.json`；https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/mod.rs#L38 |
| 產品版本 | `GET /api/version` → `"1.37.2"`（VW 獨有；官方雲無此 route） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/mod.rs#L38 |
| 協定版本 | `/config.version`：VW 1.37.2 回 `2026.6.0`（它所對齊的 Bitwarden API 版本，共 248 個端點對齊） | https://github.com/frankhommers/bitwarden-openapi-generator |
| 註冊 | `POST {identity}/accounts/register`，body 用舊形 `{kdf,kdfIterations,key,masterPasswordHash}`（`RegisterDataOld`，另有 `userSymmetricKey`/`masterPasswordHash` alias） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/identity.rs#L1036 與 .../src/api/core/accounts.rs#L94-L160 |

## KDF

| 事項 | 值 | 來源 |
|---|---|---|
| 預設 PBKDF2-SHA256 迭代 | 600,000（`kdf: 0`） | https://bitwarden.com/help/kdf-algorithms |
| Argon2id | `kdf: 1`，另需 `kdfMemory`（預設 32 MiB）/`kdfParallelism`（預設 4） | 同上 |
| 本層對 master password hash 的態度 | **輸入是已算好的字串**；派生在 bw-crypto，bw-server 不鏈接它（依賴方向） | `docs/ARCHITECTURE.md` §3 |

`prelogin`（`POST {identity}/accounts/prelogin`）是取帳號實際 KDF 參數的來源；
本層只原樣回傳 JSON，派生由上層做。

## 認證表單

| 欄位 | 值 | 來源 |
|---|---|---|
| `scope`（password grant） | `api offline_access` | https://contributing.bitwarden.com/architecture/deep-dives/authentication |
| `scope`（client_credentials） | `api`（**不帶** offline_access；實錄回應沒有 `refresh_token`） | 同上 + `fixtures/token_client_credentials_vw_1.37.2.json` |
| `client_id` | `desktop`（官方桌機/CLI 用值；`web`/`cli`/`browser`/`mobile` 也在 VW 的註解清單內） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/identity.rs#L1118-L1120 |
| `deviceType` | WindowsCLI=23、MacOsCLI=24、LinuxCLI=25（按編譯目標選）；VW 與官方同一套編號 | https://github.com/bitwarden/clients/blob/main/libs/common/src/enums/device-type.enum.ts 與 https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/db/models/device.rs#L275-L330 |
| 個人 API key 的 `client_id` | `user.<userId>`，`client_secret` 是 `/accounts/api-key` 回的 `apiKey` | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/identity.rs#L597-L630 |
| 2FA 第二步欄位 | 表單 `twoFactorProvider`/`twoFactorToken`/`twoFactorRemember`；**同時**送 `Two-Factor-Provider`/`Two-Factor-Token` header | header 是官方 client 的重試路徑；VW 1.37.2 忽略 header（實錄 `fixtures/token_2fa_headers_only_400_vw.json`），只認表單（`.../src/api/identity.rs#L1148-L1156`） |
| 2FA provider 編號 | Authenticator=0、Email=1、Duo=2、YubiKey=3、U2f=4、Remember=5、OrganizationDuo=6、Webauthn=7、RecoveryCode=8 | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/db/models/two_factor.rs#L28-L48 |
| 429 | login 與 2FA 共用 token bucket，預設 60 秒平均 10 次（`LOGIN_RATELIMIT_SECONDS`/`LOGIN_RATELIMIT_MAX_BURST`） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/config.rs#L778-L780 |

## 動詞與欄位名的兩態（都是實錄 + 原始碼雙重確認）

| 操作 | 官方雲 | Vaultwarden 1.37.2 | quirk |
|---|---|---|---|
| 軟刪 cipher | `PUT`/`POST /ciphers/{id}/delete` 皆軟刪 | **`PUT` 軟刪、`POST` 永久刪除** | `SoftDeleteUsesPutVerb` https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/ciphers.rs#L1462-L1484 |
| 還原 | `POST /ciphers/{id}/restore` | **只有 `PUT`**（POST 是 route-not-found 404） | `RestoreUsesPutVerb` 同上 #L1564-L1585 |
| 批次刪除 body | `{"cipherIds":[…]}` | **`{"ids":[…]}`**（`CipherIdsData`） | `BulkDeleteUsesIdsField` 同上 #L1841-L1843 |
| 欄位級 patch | `uri`/`password`/`folderId`/`favorite` | **只認 `folderId`/`favorite`**（`PartialCipherData`，送 password → 422） | `PartialUpdateLimitedToFolderAndFavorite` 同上 #L305-L309 |
| 附件上傳（v2 之後） | `PUT {url}` raw body（Direct/Azure SAS） | **`POST {api}{url}` multipart**，欄位 `key` + `data`；PUT 回 404 | `AttachmentUploadRequiresMultipart` 同上 #L1356-L1375 |
| `GET /ciphers/deleted` | 有 | **無**（404） | `NoDeletedCiphersListing` |
| 401/404 回應體 | JSON | **Rocket HTML 頁** | `NonJsonErrorPages` |

## 附件 v2

| 事項 | 值 | 來源 |
|---|---|---|
| 請求 | `POST /ciphers/{id}/attachment/v2`，`{fileName, fileSize, key}`；VW 的 `AttachmentRequestData.key` 是**非 Option**（缺了 422） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/ciphers.rs#L1117-L1123 |
| 回應 | `{object:"attachment-fileUpload", attachmentId, url, fileUploadType, cipherResponse}`；`url` 是 root-relative（要相對於 **api** base 解析） | 同檔 #L1150-L1172 |
| `fileUploadType` | `Direct = 0`（Azure = 1 只在上游） | 同檔 #L1125-L1128 |
| 附件 id 形態 | VW 是 20 字元 hex（`crypto::generate_attachment_id()`），**不是 UUID**；`/sync` 的 `attachments` 在 VW 是 array、在 upstream 是 map | 同檔 #L1155；bw-proto 的 `AttachmentId = Uuid` 因此不能當唯一鍵，鏡像層要保留 raw |
| 下載 URL 有效期 | 簽名 JWT `iss = <base>|file_download`，實錄 `exp - nbf = 300` 秒 | `fixtures/attachments_download_vw_1.37.2.json` |

## notifications（兩種協議形態）

| 事項 | 值 | 來源 |
|---|---|---|
| 端點 | `WS {notifications}/hub?access_token=…`（VW 也接受 `Authorization` header：`WsAccessTokenHeader`） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L120-L140 |
| 官方雲 | ASP.NET Core SignalR **json hub protocol**：文字握手 `{"protocol":"json","version":1}` + `0x1e`，回應 `{}\u001e`；之后每條 JSON 訊息以 `0x1e` 分隔 | https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Shared/src/MessageFrameTypes.cs（型別碼見下表）；`Connect(userId, version?)` 依 https://github.com/bitwarden/server/blob/main/src/Notifications/Hub.cs |
| Vaultwarden | **只認 messagepack 握手**：`INITIAL_MESSAGE{protocol:"messagepack",version:1}`，回應是 binary `{}\u001e`（`INITIAL_RESPONSE`）；送 json 握手**不會**得到回應 | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L334-L345（實錄 `fixtures/notifications_vw_msgpack_frame.bin`） |
| 記錄分隔符 | `RECORD_SEPARATOR = 0x1e` | 同檔 #L334 |
| 二元訊息前綴 | SignalR BinaryMessageFormat：7-bit 一組、最高位為續位元組的 varint 長度 | 同檔 #L300-L320（其註解指向 https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Shared/src/BinaryMessageFormat.cs） |
| 通知結構 | msgpack `[1, {}, null, "ReceiveMessage", [{"ContextId","Type","Payload"}]]` | 同檔 #L614-L650 |
| keepalive | msgpack `[6]`（每 15 秒，且第一次 tick 立即觸發）；VW 另送 WS protocol-level Ping，tungstenite 自動 Pong | 同檔 #L158-L200、#L673-L675 |
| 匿名 hub | `/notifications/anonymous-hub?token=<authRequestId>`，target 拼字為 `AuthRequestResponseRecieved`（上游也拼錯） | 同檔 #L213-L235、#L645-L653 |
| SignalR 型別碼 | 1 = invocation、3 = completion、6 = ping/keepalive、7 = ack | https://github.com/aspnet/AspNetCore/blob/main/src/SignalR/common/Protocols.Json/src/JsonHubProtocol.cs |
| `UpdateType` 編號 | SyncCipherUpdate=0 … SyncCiphers=4、SyncVault=5、SyncOrgKeys=6、SyncFolder*、SyncSettings=10、LogOut=11、SyncSend*=12..14、AuthRequest=15、AuthRequestResponse=16（9 被上游導向 `SyncLoginDelete`） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L678-L700，註解指向 https://github.com/bitwarden/server/blob/375af7c/src/Core/Enums/PushType.cs |
| msgpack timestamp ext | type `-1`，8 bytes big-endian = `(nanos << 34) | seconds`（本層轉成 RFC3339） | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/notifications.rs#L310-L322；https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type |

## ServerProfile 判讀

| 判據 | 結論 | 來源 |
|---|---|---|
| `/config.server.name` 含 `vaultwarden` | `ServerKind::Vaultwarden` | https://github.com/dani-garcia/vaultwarden/blob/1.37.2/src/api/core/misc.rs（`server: {name: "Vaultwarden"}`） |
| `server: null` 且 `environment.cloudRegion` 非 null | `BitwardenCloud` | 實錄 `fixtures/config_bitwarden_cloud.json` |
| 其他 `server.name` | `Unknown`（**不猜**是官方雲） | — |
| 沒有 `/config` 時 | host 是 `*.bitwarden.com` 才算官方雲，否則 `Unknown` | https://bitwarden.com/help/what-is-the-bitwarden-cloud/ |
| `UserDecryptionOptions` 缺失 | 記 quirk、降為「僅密碼解鎖」，**不是錯誤** | vaultwarden#6729 https://github.com/dani-garcia/vaultwarden/issues/6729（教訓取自 `docs/research/protocol.md` §4） |

## 其他

- **`environment` URL 的別名問題**：VW 從 `DOMAIN` 或 Host header 自報 `http://localhost/api`，
  而用戶端可能用 `127.0.0.1:18080`（port-forward、IP/主機名別名）。因此只有「路徑是非標準佈局」
  （反代掛 `/bw/api` 之類）或 origin 相同時才採用發現值；標準路徑 + 不同 origin ⇒ 沿用發現值的 path、
  改用 base 的 origin。見 `profile::rebase_if_alias`。
- **不驗證 JWT 簽章**：`jwt_claim_str` 只解 `sub`/`email` 供 hub 群組與 API key client_id 使用。
  官方 identity 用 RS256（https://identity.bitwarden.com/.well-known/openid-configuration/jwks），
  要驗證得拉 JWKS 與 RSA 驗簽，那是明確的下一步、不是這層的責任。
- **不做附件上傳本身**：契约只要「取 URL」；實際位元組推送（含 multipart/PUT 兩態）由呼叫方
  （bw-sync 的 blob 佇列）拿 `AttachmentUpload.url` + `.method` 去做。
- **沒有 org/collection 管理面**：`docs/research/protocol.md` §3 的 Public API 不在本層（刻意不做）。
