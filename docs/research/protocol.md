# Bitwarden 第三方用戶端：協定與技術可行性（Research: ProtocolFeasibility）

日期：2026-10-28。標記 [推測] 者為無直接來源之判斷。

## 1. 客戶端加密架構
- **KDF（master key 派生）**：以 email 為 salt 對 master password 做 PBKDF2-SHA256，預設 600,000 次（2026.2.1 起最低即 600,000）；或 Argon2id（BLAKE2b），預設 memory=32MiB、iterations=6、parallelism=4。來源: https://bitwarden.com/help/kdf-algorithms
- **master password hash**：以 master key 為輸入、master password 為 salt 再做一層 PBKDF-SHA256；送到伺服器後伺服器再加隨機 salt 做第二輪 hash（白皮書：client 100,001 + server 100,000；現行 help 稱總預設 700,000 次）。來源: https://bitwarden.com/help/bitwarden-security-white-paper/ 與 https://bitwarden.com/help/kdf-algorithms （注意兩文件迭代數版本不同）
- **金鑰階層**：master key 經 HKDF 拉長為 stretched master key → 解密 Protected Symmetric Key（user key，AES-256-CBC+HMAC 加密 vault items）；註冊時另產生一組使用者 RSA keypair（private key 以 user key 加密），用於 Organization 對稱金鑰的共享加密。來源: https://bitwarden.com/help/bitwarden-security-white-paper/ 、 https://bitwarden.com/help/what-encryption-is-used
- **認證/tokens（使用者所述「雙層金鑰 RS256」）**：所有 login 都是 `POST {identity}/connect/token`，grant 依策略為 `password`（scope `api offline_access`）、`client_credentials`（API key）、`authorization_code`（SSO+PKCE）；成功後取得 **JWT access_token（RS256 簽章）+ refresh_token**（offline_access）。來源: https://contributing.bitwarden.com/architecture/deep-dives/authentication
  - RS256 直接證據：Discovery 文件 `id_token_signing_alg_values_supported: ["RS256"]`、JWKS 為 RSA 憑證（CN=bitwarden IdentityServer）：https://identity.bitwarden.com/.well-known/openid-configuration 與 .../openid-configuration/jwks
  - token 回應另含自訂 `Keys` 物件：`Key`（加密的 user key）、`PrivateKey`、`Kdf`/`KdfIterations`、`UserDecryptionOptions` 等，客戶端據此本地解鎖。來源: https://contributing.bitwarden.com/architecture/deep-dives/authentication
  - **Login with device / TDE**：非標準 RFC 8628，而是自有 auth-request 流程（client 產生一組暫時 RSA「Auth-request Public Key」+ access code，經已登入裝置以 user key 加密回傳）；Identity 伺服器亦另暴露 `device_authorization_endpoint`（`urn:ietf:params:oauth:grant-type:device_code`）。來源: https://bitwarden.com/help/log-in-with-device/ 、 https://identity.bitwarden.com/.well-known/openid-configuration
- **同步協定**：全量 `GET /sync` 取回加密的 profile+ciphers+folders+…（官方無公開文件；見 unofficial spec「bitwarden-vault.json：internal API — ciphers, folders, sync, sends, organizations (used by CLI, web vault, mobile)」）；變更以 CRUD REST 推回，跨裝置提示靠 notifications hub。增修刪自動 push、可手動 sync。來源: https://github.com/frankhommers/bitwarden-openapi-generator 、 https://bitwarden.com/help/vault-sync
- **REST API 文件位置**：官方只正式文件化 **Public API（組織管理）**： https://bitwarden.com/help/public-api 、 OAS3: https://docs.bitwarden.com/ 、 https://github.com/bitwarden/docs/blob/master/api/specs/public/swagger.json 。客戶端用的 **Client API（vault 同步）無官方公開 spec**，官方以 server 原始碼產生 Swagger 再自動生成 Rust bindings（sdk-internal 的 `bitwarden-api-api`/`bitwarden-api-identity`，且 `/connect/token` 不在 swagger 內需補丁）。來源: https://github.com/bitwarden/sdk-internal README 、 https://github.com/frankhommers/bitwarden-openapi-generator

## 2. 官方 Rust SDK 現況
- **bitwarden/sdk-internal**（PM SDK，供自家 clients 用）：README 明確警告「password manager SDK 不供公開使用、無官方支援、介面不穩定、隨時破壞性變更」。crates：`bitwarden-crypto`、`bitwarden-core`、`bitwarden-api-api/identity`（openapi 自動生成）、WASM（wasm-bindgen）與行動 UniFFI bindings。來源: https://github.com/bitwarden/sdk-internal 、 https://contributing.bitwarden.com/architecture/sdk 、 https://contributing.bitwarden.com/architecture/sdk/language-bindings
- **授權為雙軌**：OSS 套件僅含 GPL 程式碼；商業套件另含 Bitwarden 授權碼（`LICENSE_SDK.txt`，v2 2025-10-07）。來源: https://github.com/bitwarden/sdk-internal README（Licensing 節）、 https://raw.githubusercontent.com/bitwarden/sdk-internal/main/LICENSE_SDK.txt
- **Bitwarden SDK License 對第三方的限制**（§3.1–3.4）：僅允許開發/測試/展示「Compatible Application」、家庭個人使用、或搭配付費 Bitwarden server 授權的組織內部使用；**不得將該應用 offered/licensed/sold 給第三方**；不得修改、再散布、反向工程 SDK；不得用它對「non-compatible implementations of Bitwarden」（如 Vaultwarden [推測此即指之]）或開發另一個 SDK。GPL 元件另依其 GPL 條款（§3.5）。來源: https://raw.githubusercontent.com/bitwarden/sdk-internal/main/LICENSE_SDK.txt:44-140 、同文 v1 用於 Secrets Manager SDK: https://raw.githubusercontent.com/bitwarden/sdk-sm/main/LICENSE:40-75
- **bitwarden/sdk-sm**（公開 SDK）：只做 Secrets Manager（`bws`、Rust crate `bitwarden`、Node/Python/Go 綁定走 bitwarden-json/CGO）；不支援 vault 操作。來源: https://github.com/bitwarden/sdk-sm 、 https://docs.rs/bitwarden/latest/bitwarden/ 、 https://pypi.org/project/bitwarden-sdk 、 https://github.com/bitwarden/sdk-go
- 舊的公開 `bitwarden/sdk` 已封存（archive repo 標示 GPL-3.0）。來源: https://github.com/Bitwarden-Repository-Archive/bitwarden-sdk-internal （及 silver-fork 鏡像 https://github.com/silver-fork/bitwarden-sdk ）
- **對本專案含意**：第三方商業客戶端**不能**直接把 sdk-internal 的商業授權部分拿去出貨（§3.1 禁止對第三方提供）；可行路徑是 (a) 自行實作金鑰派生/加解密（規格公開、且 `bitwarden-crypto` GPL 碼可作參考），或 (b) 只用 GPL 元件並讓自己的 app 採 GPL 相容授權。[推測]

## 3. 授權（clients=GPL-3.0 的影響）
- bitwarden/clients 預設 **GPL-3.0**，僅 `/bitwarden_license` 目錄為 Bitwarden License v1.0；未授予任何 Bitwarden 商標權利。來源: https://raw.githubusercontent.com/bitwarden/clients/main/LICENSE.txt 、 https://github.com/bitwarden/clients/blob/main/LICENSE_BITWARDEN.txt
- server 為 AGPL-3.0（企業功能另計），見 LICENSE FAQ: https://github.com/bitwarden/server/blob/main/LICENSE_FAQ.md
- **影響**：GPL 只約束「衍生/連結作品」。全新第三方 client 若只透過公開 REST API 溝通、不含官方程式碼，不受 GPL 传染；若 fork clients 或鏈接其 GPL crates（如 bitwarden-crypto），則整個產品必須以 GPL-3.0 開放原始碼。商標（「Bitwarden」名稱/logo）使用須遵守 guidelines。來源: https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md 、 https://raw.githubusercontent.com/bitwarden/clients/main/LICENSE.txt 。[推測：法律細節建議自估]

## 4. Vaultwarden 相容性
- Vaultwarden（Rust、AGPL-3.0）自我定位為「Bitwarden Client API 的替代實作，與官方 clients 相容」，功能涵蓋 personal vault、Send、附件、組織/collections/政策、多種 2FA、Emergency Access、personal API key 等。來源: https://github.com/dani-garcia/vaultwarden （README Features）
- 相容度量化：unofficial OpenAPI 分析顯示 Vaultwarden 1.37.2 對應其宣告的 Bitwarden API 2026.6.0，三份 spec 共**對齊 248 個 endpoints**。來源: https://github.com/frankhommers/bitwarden-openapi-generator
- 相容性風險是雙向的：官方新 client 要求新欄位會打爆舊 Vaultwarden（例：CLI 2025.12.0 因 `UserDecryptionOptions are required` 無法登入舊版，issue #6729）；官方 SDK 連 Vaultwarden 亦被討論為部分不相容（discussion #5713）。來源: https://github.com/dani-garcia/vaultwarden/issues/6729 、 https://github.com/dani-garcia/vaultwarden/discussions/5713
- 用第三方 client 連 Vaultwarden **很常見**：社群公開伺服器 vaultwarden.com 即跑 Vaultwarden 讓各家 client 註冊；Keyguard 官方文件直接支援「任何 Bitwarden-compatible server（含自架）」；rbw 等 CLI 亦常用於 Vaultwarden。來源: https://vaultwarden.com/ 、 https://keyguard.dev/docs/bitwarden/self-hosted/ 、 https://github.com/doy/rbw 、 https://www.reddit.com/r/vaultwarden/comments/1u80kzr/clients_for_vaultwarden
- **含意**：第三方 client 應把「連 Vaultwarden」列為一級支援目標（自架族群大），並注意較舊 server 缺少新欄位時的容錯。[推測]

## 5. 既有第三方客戶端/SDK 生態
- **Keyguard**（AChep/keyguard-app）：最成熟的全功能替代客戶端，支援 Bitwarden 平台＋KDBX、autofill、passkeys、離線、Wear OS/桌面全平台；商業加值模式。來源: https://github.com/AChep/keyguard-app 、 https://keyguard.dev/ 、 https://formulae.brew.sh/cask/keyguard
- **Bitclient**（sgolub/bitclient）：Tauri 桌面替代客戶端（beta）。來源: https://github.com/sgolub/bitclient 、 https://www.reddit.com/r/Bitwarden/comments/1hst1v0/
- **rbw**（doy/rbw）：Rust 非官方 CLI／password-store 風格，主打無狀態 headless 使用；限制：不支援 WebAuthn 2FA。來源: https://github.com/doy/rbw 、 https://crates.io/crates/rbw 、 https://awkto.dev/blog/claude-code-bitwarden-cli-rbw-pinentry-shim
- **Passky**：注意——**不是** Bitwarden 第三方客戶端，是自有協定生態（XChaCha20+Argon2id、自家 server/API/客戶端），僅提供匯入 Bitwarden。來源: https://github.com/Rabbit-Company/Passky-Server 、 https://www.passky.org/
- **Python**：`bitwarden-py`（直接連 vault API、可自架 server_url）、`PyWarden`（包 bw CLI）、`bitwarden-sdk`（官方 SM SDK 綁定，非 vault）、`py-bw-vault-management-api-client`（連 bw serve 的 Vault Management API）、`vaultwarden-api`（Vaultwarden admin+使用者 API）。來源: https://pypi.org/project/bitwarden-py 、 https://pypi.org/project/PyWarden/ 、 https://pypi.org/project/bitwarden-sdk 、 https://pypi.org/project/py-bw-vault-management-api-client 、 https://github.com/klimbertechnologies/vaultwarden-api
- **Go**：官方 `bitwarden/sdk-go` 僅 Secrets Manager（CGO 綁 SM SDK）。來源: https://github.com/bitwarden/sdk-go
- **AI/MCP**：官方 `bitwarden/mcp-server`（包 CLI+Public API 給 Claude 等）與多間社群 MCP（warden-mcp 等）。來源: https://github.com/bitwarden/mcp-server 、 https://github.com/icoretech/warden-mcp
- **定位空隙**：現有第三方多为 CLI/單機 app/函式庫；「隱私優先＋AI-agent 原生＋補官方缺功能」的完整客戶端仍是空隙。[推測]

## 6. 官方 CLI（bw）認證模式與可取代性
- 三種 login：email+master password（2FA 僅支援 authenticator/email/YubiKey）、`--apikey`（personal API key，`BW_CLIENTID`/`BW_CLIENTSECRET`，可繞過不支援的 2FA）、`--sso`；API key/SSO 之後仍需 `bw unlock` 產生 session key（**API key 不取代 master password**）。來源: https://bitwarden.com/help/cli
- 已知限制：有 bot detection（`Your authentication request appears to be coming from a bot.`，須用 API key 過 challenge，見 https://bitwarden.com/help/cli-auth-challenges/ 及 awkto 上文）；**以 trusted device 加入組織（無 master password）的帳號無法用 CLI 取用資料**；OSS build 不含 device approval 等商業指令。來源: https://bitwarden.com/help/cli （CLI vs. unlock 註記、OSS/非 OSS build 說明）
- CLI 有 `bw serve` 提供本地 REST「Vault Management API」（官方 spec: https://bitwarden.com/help/vault-management-api/ 、 https://bitwarden.com/blog/bringing-restful-api-to-the-bitwarden-cli ）——等於官方承認「以 HTTP 介面操作 vault」的可行性。
- **可取代性**：CLI 本身只是 Client API 的另一個消費者（認證文件即證），第三方直接實作同一組 `/connect/token` + `/sync` + ciphers CRUD 即可完全取代並做得更好（常駐 token、原生 JSON、免 spawn Node）。風險在：無正式 spec、API 隨 server 版本漂移、以及自家裝置信任/TDE 流程需自行實作 auth-request。來源: 同 §1 之 contributing authentication 頁。

## 可行性結論（給主代理）
1. 協定全部可逆：金鑰派生、token 流程、sync/CRUD 都有公開文件＋GPL 原始碼可對照，實作門檻是中工程量而非封閉協議。
2. 官方 Rust SDK 對「要出貨的第三方 app」授權不可行（§3.1 禁止對第三方提供、§3.3 禁止用於不相容實作）；路徑為自寫 crypto 或僅取 GPL 元件並採 GPL。
3. 連 Vaultwarden 是剛需且常見，但無官方 client-API spec，需以 server swagger/unofficial OpenAPI 生成器追蹤漂移。
4. 生態定位：Keyguard 占「更好用的 GUI」、rbw 占「headless CLI」；AI-agent 原生＋官方缺功能的定位尚未被佔。
