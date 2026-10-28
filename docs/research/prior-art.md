# 先例查證：「主 App 持鑰、外圍 client 取資料」＋ Android autofill

研究員：ThinClientPriorArt（2026-10-28）。查不到者標 [推測]。

## 1. 1Password

### 1.1 瀏覽器 extension ↔ 桌面 App
- 1Password 8：App 與 extension 透過 **native messaging port** 連線；連線會**轉移帳戶資訊與加密金鑰**，讓兩者共享 vault 與 lock 狀態，並讓 extension 可用生物識別解鎖（解鎖材料來自 App）。App 端驗證 extension ID 與 native messaging hosts 檔；macOS/Windows 驗證瀏覽器**程式碼簽章**，Linux 檢查瀏覽器由 root/套件管理器安裝。<https://support.1password.com/1password-browser-connection-security/>、<https://support.1password.com/1password-browser-security>
- 明文邊界（官方自承）：瀏覽器本身無法偵測被惡意軟體操控；只要 App 解鎖，被操控的瀏覽器即等同取得資料。<https://support.1password.com/1password-browser-connection-security/>
- 歷史先例：2011 年「1Password mini」即為「App 持鑰解密、extension 無資料存取權，只經本機 IPC 取用」的設計討論（含惡意 App 冒充 mini 的競態與 socketpair 配對解法）。<https://1password.com/blog/1password-inter-process-communication-a-discussion>
- 1Password X（2017）對照組：純 extension 直連 1Password.com、在瀏覽器內自行解密、不需桌面 App——證明「thin client 自己持鑰」與「thin client 向 Full client 取鑰」兩條路線官方都做過。<https://1password.com/blog/1password-x-a-look-at-the-future-of-1password-in-the-browser>
- native messaging manifest 指向獨立的 helper 執行檔（`com.1password.1password.json` → Browser Helper），非直接指向主 App。<https://www.1password.community/1password-at-home-31/auto-generated-application-support-folders-15112>

### 1.2 桌面 App ↔ CLI（op）的 IPC
- macOS 用 **NSXPCConnection**：App 端設 `1Password Browser Helper` 作 XPC server，CLI 與 App 都連它，雙方以**簽章驗證**彼此身分，Helper 只做訊息中繼。Linux：App 開 unix socket，以 **setgid `onepassword-cli` group 的 GID** 驗證連線程序；Windows：named pipe + Authenticode 簽章互驗。<https://www.1password.dev/cli/app-integration-security>
- 授權模型：每次新終端機視窗要生物識別授權；session credential＝tty/PID＋啟動時間（非机密）；10 分鐘無活動到期、12 小時硬上限；**App 上鎖即撤銷全部授權**。已接受風險：root 可繞過；macOS accessibility 權限可繞過提示。<https://www.1password.dev/cli/app-integration-security>
- CLI 用 app integration 時不自己解密、金鑰不下放：CLI 只「取得對 App 內帳戶的存取」，取回的才是明文項目；App 有 CLI 活動稽核紀錄。<https://developer.1password.com/docs/cli/app-integration>
- 同框架也開放給 SDK 第三方整合（App 授權提示＋本機 IPC）。<https://developer.1password.com/docs/sdks/desktop-app-integrations>

## 2. KeePassXC-Browser
- 架構：extension ↔ **native messaging host**（`org.keepassxc.keepassxc_browser.json`）↔ 執行中的 KeePassXC（本機 socket/pipe）。主金鑰（KDBX 解密金鑰）**永遠不進瀏覽器**；瀏覽器只拿到被選取條目的明文帳號密碼。<https://github.com/keepassxreboot/keepassxc-browser>
- 傳輸加密：雙方交換公鑰、以 **libsodium crypto_box 加密每條訊息**（防本機竊聽用，非防 MITM——臨時連線金鑰可被惡意 proxy 換掉，官方 issue 內辯論過設計目標）。連線用**臨時金鑰**、識別用**永久金鑰**；識別金鑰私鑰即丟棄。<https://github.com/keepassxreboot/keepassxc-browser/issues/1884>
- ANSSI/Synacktiv 審計確認上述加密設計與其目的。<https://keepassxc.org/assets/pdf/Synacktiv-ANSSI-CSPN-KeePassXC-RTE-v1.3.pdf>
- 暴露面與緩衝：預設每次憑存取有 **Access Confirm dialog**；開發者承認 manifest 可被同使用者惡意替換、localStorage 內 token 是本機惡意的弱點，並曾考慮 `keepassxc-server` 遠端唯讀模式（加密層是為未來跨機預留）。<https://github.com/keepassxreboot/keepassxc-browser/issues/1884>
- 協議已被第三方重實作（SafariKeePassXC），代表「文件化協議＋thin client」可移植。<https://github.com/mgriesslehner/SafariKeePassXC>

## 3. Bitwarden 既有 extension/CLI ↔ 桌面 App IPC
- 途徑：Browser —stdio→ **desktop_proxy**（native messaging host）—IPC→ Desktop App。生物識別解鎖時：extension 產生公鑰金鑰對送給 App；App 回傳**以該公鑰加密的隨機對稱傳輸金鑰**，之後所有訊息加密；App 把「生物識別金鑰（＝帳戶加密金鑰）」存在 OS 密碼庫，解鎖時**傳給 extension，由 extension 自行解密 vault**（即「Full client 下放鑰、thin client 解密」模式）。無密碼學證明兩者同帳號。<https://github.com/quexten/bw-bio-handler>（第三方重實作，README 含協議細節；僅實作解鎖子集，證明協議可被第三方逆向/沿用）
- 官方文件佐證：extension 生物識別是「透過與桌面 App 的整合」、用 native messaging APIs；桌面 App 產生含 extension ID 的 manifest；macOS 需 Mac App Store 版。<https://contributing.bitwarden.com/getting-started/clients/browser/biometric>、<https://bitwarden.com/help/biometrics>、<https://bitwarden.com/en-gb/blog/browser-biometrics-now-available/>
- 新一代 **Desktop IPC 框架**（Rust SDK 核心）：訊息一律經 CryptoProvider 加密、有 session 管理、pub/sub＋request/response，destination 路由（DesktopMain/DesktopRenderer）；browser extension 的 service worker 與 **CLI** 都已掛上此傳輸（CLI spawn proxy 並宣告 `--client=cli`）。框架明示「不建議用於 content script 或 macOS extension 等小程序」。<https://contributing.bitwarden.com/architecture/deep-dives/ipc>、`apps/browser/src/platform/ipc/transports/desktop-ipc.transport.ts`、`apps/cli/src/platform/services/cli-desktop-ipc.transport.ts`、`apps/desktop/desktop_native/core/src/ipc/mod.rs`（unix socket／Windows named pipe、1MB 長度前綴框框）<https://github.com/bitwarden/clients>
- 桌面 App 作為認證器/代理：
  - 瀏覽器 passkeys：extension 自己實作簡化 FIDO2 authenticator（polyfill WebAuthn、強制 user presence），**不经桌面 App**。<https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension>
  - macOS 原生 passkey provider：App bundle 內 Swift autofill extension，經 **unix socket IPC**（Rust 實作、UniFFI+NAPI）向 Electron 主程序要簽名，桌面以 modal 模式顯示確認 UI。<https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/autofill_provider/README.md>（同目錄另有 `windows_plugin_authenticator/`，Windows 平台認證器插件，內含 ipc.rs）
  - 桌面 App 可當 **SSH agent**（金鑰放 vault、以 agent socket 供其他程式使用）。<https://bitwarden.com/help/ssh-agent>、<https://contributing.bitwarden.com/architecture/deep-dives/ssh/agent>
- CLI 本身傳統上是獨立全功能 client（自存 BW_SESSION）；`bw serve` 可在本機開 REST API 供其他程式取用。<https://bitwarden.com/help/cli>、<https://bitwarden.com/en-gb/blog/bringing-restful-api-to-the-bitwarden-cli/>

## 4. Android autofill 架構
### 4.1 誰看得到明文
- Autofill 流程：系統把 `AssistStructure`（含欄位值）傳給 autofill service 的 `onFillRequest()`；service 以 `Dataset`（**明文 AutofillValue**＋RemoteViews 呈現）回應，系統執行填入。因此**service 程序必然看得到明文**，目標 App 填入後也持有明文；系統只保證「service 綁定僅供 autofill 用途」。文件要求 service **持久化前必須加密敏感資料**（標籤可不加密以便未認證時呈現）。<https://developer.android.com/identity/autofill/autofill-services>
- 可延後暴露：`FillResponse.setAuthentication()`／`Dataset.setAuthentication()` 用 PendingIntent 讓使用者認證（指紋等）通過後才回傳真值，之前只給假呈現——「持鑰者解鎖、UI 先佔位」的官方機制。<https://developer.android.com/identity/autofill/autofill-services>
- 風險文獻：AutoFail（USENIX Security '26）展示惡意網頁可濫用 autofill 框架跨網域擷取資料——autofill service 交付的明文最終對網頁 JS 可見。<https://www.usenix.org/system/files/usenixsecurity26-lamarca.pdf>
### 4.2 Inline autofill
- Android **11+**（非 12）IME 可顯示 inline 建議；service 依 IME 的 `InlinePresentationSpec` 產生 `InlinePresentation`，**IME 在使用者選取前看不到建議內容**；service 需在 `<autofill-service android:supportsInlineSuggestions="true">` 宣告。<https://developer.android.com/identity/autofill/ime-autofill>
- Bitwarden 官方檔：Inline 需要 Android 11+ 且相容 IME；另提供 Popup／quick-action 等替代路徑。<https://bitwarden.com/help/auto-fill-android>
### 4.3 Credential Provider（androidx.credentials）
- 時間軸：`credentials:1.0.0-alpha01`＝2023-01-11（統一取得 password/passkey/federated，後端為 Google Password Manager）；**provider 端 API（存/取 password＋passkey）自 1.2.0-alpha01（2023-02-08）加入**、1.2.0（2023-11-01）轉穩定。現況：1.6.0 穩定、1.7.0-alpha03（2026-07）。<https://developer.android.com/jetpack/androidx/releases/credentials>
- 密碼型別狀態：provider 於 `provider.xml` 宣告 `android.credentials.TYPE_PASSWORD_CREDENTIAL` 能力；兩階段流程（begin/query 回 `CreateEntry`+PendingIntent → 使用者選擇後由 provider Activity 帶 BiometricPrompt 完成）；**CredentialProviderService 需 Android 14（API 34）**。表單欄位情境下密碼仍主要走 AutofillService；Android 15+ 才有 `pendingGetCredentialRequest` 把 Credential Manager 結果整合進 autofill UI。<https://developer.android.com/identity/sign-in/credential-provider>、<https://developer.android.com/identity/autofill/credential-manager-autofill>
### 4.4 Keystore 實務（biometric-bound／StrongBox）
- Keystore 金鑰不可導出、可綁定使用者認證（`setUserAuthenticationRequired`）；Android 9+ 裝置可選 **StrongBox** 獨立晶片；生物識別等級依 CDD Class 1–3。<https://developer.android.com/privacy-and-security/keystore>、<https://source.android.com/docs/security/features/keystore>、<https://source.android.com/docs/security/features/biometric>
- Bitwarden 官方行動端只接受 **Class 3** 生物識別。<https://bitwarden.com/help/biometrics>；NCC 2024 報告曾列「Android 生物識別驗證繞過」風險（BWN-11-005），實務上应綁 keystore-bound key 而非只看回調。<https://assets.ctfassets.net/7rncvj1f8mw7/bEfNZ6r3BJ9ehwNfAqw6C/4020b6eb762e0b6051a40638f45269d9/2024_Bitwarden_Mobile_Apps_and_SDK_Report.pdf>
### 4.5 Keyguard（第三方 Bitwarden Android client）
- 自寫 `androidLibAutofill` 模組：`KeyguardAutofillService : AutofillService`，**service 進程內直接持有解密後的 ciphers**（`Vault.Open(ciphers: List<DSecret>)`，記憶體快取 10 秒），用 `androidx.autofill.inline` 官方庫做 inline UI；結構解析 v2 自稱以 ML 式分類器把誤報率大降（v1 57%→v2 90.1%）。<https://github.com/ZQZCC/Keyguard/blob/master/androidLibAutofill/README.md>、<https://raw.githubusercontent.com/ZQZCC/Keyguard/master/common/src/androidMain/kotlin/com/artemchep/keyguard/android/autofill/KeyguardAutofillService.kt>
- `KeyguardCredentialService : CredentialProviderService`（`@RequiresApi(34)`）同時宣告 password＋passkey 能力。<https://raw.githubusercontent.com/ZQZCC/Keyguard/master/common/src/androidMain/res/xml/config_credential_service.xml>
- 金鑰管理：區分「帳號密碼（vault 金鑰）」與「裝置 app password（保護本機副本）」；生物識別限 Class 3；金鑰可只存記憶體（Linux 用 memfd_secret／kernel keyring），可選 YubiKey HMAC-SHA1 slot 或 FIDO2 PRF(hmac-secret) 解封裝。<https://keyguard.dev/docs/lock-and-unlock/>
- 另有 `androidSshAgent`（Rust daemon）＋ `SshAgentService`：把手機 vault 變成 SSH 簽名 agent（Termux 可接），是「裝置上的 Full client 提供 agent socket」先例。<https://github.com/ZQZCC/Keyguard/tree/master/androidSshAgent>
- 註：AChep/keyguard-app 為舊鏡像，現行 repo 是 ZQZCC/Keyguard。<https://github.com/AChep/keyguard-app>

## 5. 多裝置 thin client 先例（跨機取資料）
- **vaultgate**（self-hosted 遠端 MCP server）：AI agent 經 HTTPS＋OAuth 2.1 連到使用者主機上的 vaultgate；vaultgate 進程獨佔 master password/API key，背後用 loopback `bw serve` 驅動 Bitwarden；「use, don't read」——由 server 端注入憑證執行 http/sql/ssh/winrm 操作、回傳已去敏結果；另有 **credential relay：把 `bw serve` 讀取 API 服務給 Tailscale 節點上的程式**。官方 bitwarden/mcp-server 則明文規定只能本機 stdio、不可公開托管。比對表列 warden-mcp 遠端模式是「client 每-call 帶 X-BW-Password header」的反模式。<https://github.com/adamrowles1996/vaultgate>、<https://github.com/bitwarden/mcp-server>
- **rbw-agent**（GPG/ssh-agent 模式）：背景 agent 以 unix socket（`$XDG_RUNTIME_DIR/rbw/agent-socket`）持有**記憶體中的 master key**，CLI 短命程序向它取鑰後自行加解密；行為「類似 gpg-agent/ssh-agent」，lock_timeout 自動上鎖，用 pinentry 收主密碼；內建 SSH agent socket。皆為**同機**跨程序，未做跨機。<https://raw.githubusercontent.com/doy/rbw/master/README.md>、<https://manpages.ubuntu.com/manpages/tenacious/man1/rbw.1.html>
- **bw serve**：CLI 本機 REST API（express，預設 127.0.0.1:8087），端到端加密環境不变——是「Full client 開 localhost API、thin client 取資料」的官方雛形。<https://bitwarden.com/en-gb/blog/bringing-restful-api-to-the-bitwarden-cli/>、<https://bitwarden.com/help/cli>
- **1Password Connect Server**：自架橋接服務，憑 service account token（ES256、綁定 vault 範圍、可撤銷/輪換）經 REST API 存取**明文項目**；金鑰/憑證在 server 端（credentials file 含 encCredentials）。證明「一台機器持鑰、多台取用」在 1Password 生態是正式產品。<https://developer.1password.com/docs/connect/security>、<https://developer.1password.com/docs/connect/get-started>
- 1Password SSH agent 的远端用法（Notebook 經 SSH 轉發連回桌面 App 的 agent socket）同屬此類。<https://www.1password.dev/ssh/agent/security>（細節頁未逐頁驗證 [推測]）
- 綜合：先例全部走「**agent/daemon 持鑰＋本機 socket（stdio/unix pipe/XPC/named pipe）或 localhost HTTP**」；跨機則一律 TLS/SSH/Tailscale 包裝（vaultgate、Connect）。未見任何先例讓遠端 thin client 直接拿到**長期金鑰**；都是拿短期 session token 或乾脆只拿操作結果。[推測：這是刻意共識——金鑰出機即視為暴露面擴大]

## 6. 對 bitward 設計的啟示（摘要）
1. 「Full client 當 hub、thin client 經 IPC 取鑰或取資料」有直接先例：Bitwarden desktop_proxy（傳輸金鑰＋下放解鎖金鑰）、1Password App↔Extension（下放金鑰）、1Password App↔CLI（**不下放鑰**、逐次授權＋稽核）。兩種模式（下放鑰 vs 下放資料）業界並存，取決於 thin client 是否有解密能力。
2. 安全邊界慣例：驗證對端身分（簽章／extension ID／GID）＋訊息層加密（KeePassXC crypto_box、Bitwarden IPC CryptoProvider、1Password 驗證碼簽章）＋鎖定狀態同步撤銷授權（1Password App lock 撤銷 CLI session）。
3. Android 端無「主 App＋外圍 client」分割必要：AutofillService/CredentialProvider 本來就活在同一 app 進程、必然接觸明文；金鑰保護用 Keystore(Class 3-bound) 即可，Keyguard 已示範全棧（autofill v2＋API34 provider＋SSH agent）。
4. 多裝置 thin client 可行且有名詞可借：把 Full client 暴露成「scoped token＋可撤銷 session」的本地/遠端服務（vaultgate 模型），比讓每台裝置各自持 master key 更有稽核與撤銷優勢。
