# bw-server fixtures

`tests/compat_fixtures.rs` 回放的錄製回應（契约 §6 的 A2 / A2b）。
這裡**只放實際觀測到的位元組**或明確標注為推導的樣本；判讀規則的來源集中在上層 `NOTES.md`。

## 來源

| 群組 | 來源 | 日期 |
|---|---|---|
| `*_vw_1.37.2.*`、`*_vw.json`、`*_vw.html`、`*_vw.txt` | 本機 docker `vaultwarden/server:1.37.2`（`--platform` 原生 arm64，port 18080，`I_REALLY_WANT_VOLATILE_STORAGE=true`、`LOGIN_RATELIMIT_SECONDS=1`、`LOGIN_RATELIMIT_MAX_BURST=20`） | 2026-10-29 |
| `config_bitwarden_cloud.json`、`discovery_bitwarden_cloud.json` | 公開端點實錄 `https://api.bitwarden.com/config`、`https://identity.bitwarden.com/.well-known/openid-configuration`（無需認證） | 2026-10-29 |
| `token_2fa_challenge_cloud_map.json`、`token_password_cloud_encrypted_payload.json` | **推導樣本**（見下） | 2026-10-29 |
| `notifications_vw_msgpack_frame.bin` | 真實 WS 連線录下的 binary frame（SignalR messagepack），無損位元組 | 2026-10-29 |

測試帳號都是本機容器上的拋棄式帳號（`fixture@bitward.test`、`twofa@bitward.test`），
`key`/`privateKey` 是形狀正確但內容無意義的假信封；JWT 是該拋棄帳號的憑證，
容器銷毀後即失效。**這裡沒有任何真實機密。**

## 檔案

### 探測

- `config_vw_1.37.2.json` — `GET /api/config`。`server.name: "Vaultwarden"`、`version: "2026.6.0"`（協定版本，不是產品版本）、`environment.*` 自報 `http://localhost/...`。
- `version_vw_1.37.2.json` — `GET /api/version` → `"1.37.2"`。Vaultwarden 獨有，是產品版本的唯一可靠來源。
- `config_vw_root_404.html` — 同一個 `GET /config` 打在**根路徑**：Rocket/web-vault 的 HTML 404。證明 VW 只在 `/api` 下有 config。
- `wellknown_vw_422.html` — `GET /identity/.well-known/openid-configuration` 在 VW 是 422 HTML（沒有發現文件）。
- `config_bitwarden_cloud.json` — 官方雲：`server: null`、`environment.cloudRegion: "US"`、一大堆 `featureStates`。
- `discovery_bitwarden_cloud.json` — 官方雲 OpenID 發現（`token_endpoint`、JWKS、`RS256`）。

### token / 認證

- `token_password_request_vw.txt` — 第一步的表單內容（`grant_type=password&username=…&scope=api offline_access&client_id=desktop&deviceType=24&…`）。
- `token_password_vw_1.37.2.json` — **Keys 是扁平混在 OAuth 欄位旁**的 PascalCase 形態（`Key`/`PrivateKey`/`Kdf`/`KdfIterations`/`UserDecryptionOptions`/`AccountKeys`/`MasterPasswordPolicy`/`ForcePasswordReset`/`ResetMasterPassword`）。
- `token_password_vw_no_user_decryption_options.json` — **缺欄位範例**：上面那份刪掉 `UserDecryptionOptions`（vaultwarden#6729 的舊 server 形態）。這是 A2b 的輸入。
- `token_password_cloud_encrypted_payload.json` — **推導**：官方雲較舊的形態把 Keys 放進 base64(UTF-8 JSON) 的 `encrypted_payload`（內含 `MasterPassword`/`TokenResponse`/`Keys`）。組裝自 `docs/research/protocol.md` §1（引 contributing.bitwarden.com 的 authentication deep dive）與上面那份录製值；**不是逐位元組录製**，只保證欄位形態。
- `token_client_credentials_request_vw.txt` / `token_client_credentials_vw_1.37.2.json` — 個人 API key（`client_id=user.<uuid>`）；沒有 `refresh_token`，但 Vaultwarden 仍回 Keys/KDF。
- `token_refresh_vw_1.37.2.json` — `grant_type=refresh_token`。
- `token_2fa_challenge_vw_1.37.2.json` — 400 `invalid_grant` + `TwoFactorProviders: ["0"]`（**陣列**形態）。
- `token_2fa_challenge_cloud_map.json` — **推導**：同上但 `TwoFactorProviders` 是 map（`{"0":"Authenticator","1":"Email"}`）、`TwoFactorProviders2` 帶各 provider 的詳細資料（Email 的掩碼地址）。形态依據 `docs/research/protocol.md` §1 與 upstream `errorModel` 慣例。
- `token_2fa_retry_form_vw_1.37.2.json` — 表單帶 `twoFactorProvider`/`twoFactorToken`/`twoFactorRemember` 的第二步成功回應。
- `token_2fa_headers_only_400_vw.json` — **只送 `Two-Factor-Provider`/`Two-Factor-Token` header** 仍是 400「Two factor required.」→ Vaultwarden 忽略 header。
- `token_2fa_invalid_code_vw_1.37.2.json` — 錯碼回的是 `errorModel`（不是 OAuth 錯誤），不該被當成 2FA 挑戰。
- `error_400_bad_master_password_vw.json`、`error_400_unknown_email_vw.json` — 密碼錯/帳號不存在的 400 體。
- `two_factor_get-authenticator` 對應的 `two_factor_get_authenticator_vw_1.37.2.json` — 取 TOTP secret（`key` 為 base32）。

### sync / ciphers / 附件

- `sync_with_attachment_vw_1.37.2.json` — 完整 `GET /sync`：`profile`（含 `accountKeys`）、`ciphers`（`attachments` 是 **array**，附件 id 是 20 字元 hex 不是 UUID）、`folders`、`collections`、`domains`、`policies`、`sends`、`userDecryption`。
- `sync_bitwarden_cloud_fields.json` — **推導**（官方雲 `/sync` 沒有可录製的帳號）：欄位集合取自產生器對 upstream server 原始碼產出的 OpenAPI `SyncResponseModel`/`ProfileResponseModel`/`CipherDetailsResponseModel`
  （https://github.com/frankhommers/bitwarden-openapi-generator/blob/main/specs/bitwarden/2026.6.0/bitwarden-vault.json，2026-10-29 取），
  含 VW 不回的 `policiesNew`/`organizationsNew`/`data`/`verifyDevices`，且 `attachments` 是 **map**（upstream 形態）。
  值是假的、形態是真的；**A2 號稱的「官方雲那份」目前是這種等級，不是逐位元組录製。**
- `sync_client_credentials_vw_1.37.2.json` — API key token 讀 `/sync` 成功。
- `ciphers_create_request_vw.json` / `ciphers_create_vw_1.37.2.json` / `ciphers_get_vw_1.37.2.json` / `ciphers_update_request_vw.json` / `ciphers_update_vw_1.37.2.json` / `ciphers_list_vw_1.37.2.json` — CRUD 請求與回應成對。
- `ciphers_patch_request_vw.json` / `ciphers_patch_vw_1.37.2.json` — `PUT /ciphers/{id}/partial` 只吃 `folderId`/`favorite`。
- `ciphers_patch_password_422_vw.json` — 同端點送 `password` → 422（HTML）。
- `ciphers_soft_delete_put_vw_1.37.2.json`、`ciphers_get_deleted_vw_1.37.2.json`（軟刪後 `deletedDate` 有值）、`ciphers_restore_vw_1.37.2.json`（`PUT .../restore` 成功）、`ciphers_restore_post_404_vw.json`（`POST .../restore` 是 route-not-found）。
- `ciphers_bulk_delete_cipherIds_400_vw.json`（`{"cipherIds":[…]}` → 422）對照 `ciphers_bulk_delete_vw_1.37.2.json`（`{"ids":[…]}` → 200 空體）。
- `ciphers_deleted_listing_404_vw.json` — `GET /ciphers/deleted` 在 VW 沒有實作。
- `attachments_v2_request_vw.json` / `attachments_v2_vw_1.37.2.json` — `POST /ciphers/{id}/attachment/v2`；回應 `url` 是 **root-relative**、`fileUploadType: 0`、`attachmentId` 非 UUID。
- `attachments_v2_missing_key_422_vw.html` — 同一請求**少了 `key`** → 422（VW 把 key 當必要欄位）。
- `attachments_upload_put_404_vw.html` — 照 upstream 語意 `PUT` raw body → 404。
- `attachments_upload_multipart_vw.txt` — `POST` multipart（`key` + `data`）→ 200，VW 唯一可行的上傳形態。
- `attachments_download_vw_1.37.2.json` — 簽名下載 URL（`?token=`，issuer `<base>|file_download`，5 分鐘）。
- `attachments_delete_vw_1.37.2.json`、`ciphers_get_with_attachment_vw_1.37.2.json`、`folders_create_vw_1.37.2.json`、`profile_vw_1.37.2.json`、`prelogin_vw_1.37.2.json`、`accounts_register_request_vw.json` / `accounts_register_vw_1.37.2.json`、`accounts_api_key_vw_1.37.2.json`、`ciphers_create_denied_for_api_key_vw.json`。

### notifications

- `notifications_vw_msgpack_frame.bin` — 204 位元組的 WS binary frame：varint 長度前綴 `0xca 0x01`(=202) + SignalR messagepack invocation
  `[1, {}, null, "ReceiveMessage", [{"ContextId":"u4-probe-device","Type":1,"Payload":{"Id":"66b31944-…","UserId":"8c7bdf04-…","OrganizationId":null,"CollectionIds":null,"RevisionDate":<ext -1 timestamp>}}]]`。
- 官方雲的 json hub protocol frame 沒有录製（需要帳號），`tests/compat_fixtures.rs` 裡的 `signalr_json_invocation_frame_decodes` 用文件形態的內嵌樣本覆蓋；形態依據見 `NOTES.md`。

## 重錄

容器與帳號都是拋棄式的；要重錄就重新起一個容器再跑錄製腳本（`ciphers`/`attachments` 的 id 會變，
但測試只斷言形態與欄位存在性，不比對具體 id，除了 `notifications_vw_msgpack_frame.bin` 的 fixture 內 id）。
