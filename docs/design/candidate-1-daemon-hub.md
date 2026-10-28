# Warden 架構設計包（候選一：Daemon-centric Hub-and-Spoke）

日期：2026-10-29。設計包，非實作；型別與簽名皆為偽代碼層級。
前置閱讀：`local://bitward-research-protocol.md`、`-agent.md`、`-gaps.md`、`-macos.md`、`-priorart.md`。

---

## 0. 一句話架構與前提裁決

**一台機器上一個 `wardend`（Full client 核心）是唯一的金鑰持有者與唯一的 sync 擁有者；所有其他介面（CLI、GUI、macOS credential provider extension、MCP shim、跨機裝置）都是 Thin client，只講同一條協議 WTP，永不取得長期金鑰，預設只看 metadata、只用不讀。**

本包在多種可行結構中**只選這一種並全力貫徹**（daemon-centric hub-and-spoke，金鑰不下放）；其他形態（fat library 各自持鑰、GUI 當 hub、下放金鑰的 Bitwarden biometrics 模式、KMP/TS 單一語言核心）在第 6 節逐條拒絕。

### 0.1 命名與商標
- 產品工作名 **Warden**（待商標查證）。硬約束：不得以「Bitwarden」作為產品名或 logo；文件與 UI 一律寫「Warden — a Bitwarden-compatible client」，符合 https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md 。
- 二進位：`wardend`（daemon）、`wd`（一次性 CLI）、`warden-mcp`（MCP shim）、`Warden.app`（macOS GUI）、`WardenProvider.appex`（macOS extension）、`app.warden.android`。

### 0.2 授權與語言（不可協商的前提）
- 官方 `bitwarden/sdk-internal` 的 `LICENSE_SDK.txt` §3.1 禁止把用它做出的應用 offered/licensed/sold 給第三方、§3.3 禁止用於 non-compatible implementations（Vaultwarden）→ **不鏈接官方 SDK**（來源：https://raw.githubusercontent.com/bitwarden/sdk-internal/main/LICENSE_SDK.txt:44-140）。
- 因此：**自寫 Bitwarden 金鑰派生與信封加解密**（規格公開：https://bitwarden.com/help/bitwarden-security-white-paper/ 、https://bitwarden.com/help/what-encryption-is-used），GPL 原始碼僅作為對照參考不鏈接。
- 全 repo 採 **GPL-3.0-or-later**，保留日後取用 GPL 元件（如 `bitwarden-crypto` 作測試向量來源）的彈性；衍生風險單向可控。
- 核心語言 **Rust**（一份 crypto/protocol/store 實作，macOS 經 FFI、Android 經 UniFFI/JNI 重用）；UI 原生（macOS SwiftUI、Android Compose）。拒絕 Node/TS 核心的關鍵理由：官方 CLI 每次呼叫起一個完整 Node runtime、1–5 秒（https://github.com/bitwarden/clients/issues/2741），自動化路徑必須是常駐進程 + 短命 client。

### 0.3 協定紀律
- Client API 無官方公開 spec（來源：https://github.com/bitwarden/sdk-internal README 、https://github.com/frankhommers/bitwarden-openapi-generator ）→ 協定層集中在一個 crate（`warden-proto`），以「**lenient parse + raw mirror**」為第一級設計：每個 cipher 的伺服器原始 JSON 一律保留，寫回用 merge-patch，未建模欄位絕不遺失。
- **Vaultwarden 是一級支援目標**：所有 server 欄位視為可缺（例：舊版無 `UserDecryptionOptions` 讓 CLI 2025.12.0 登入失敗，https://github.com/dani-garcia/vaultwarden/issues/6729 ），並以 `ServerProfile` 能力探測決定行為，而非假設官方雲端。
- CI 必須同時跑 Bitwarden Cloud（staging）與 Vaultwarden（docker，釘版 1.37.2 對齊 API 2026.6.0／248 endpoints）。

---

## 1. 進程/模組圖

### 1.1 進程清單

| 進程 | 生命週期 | 職責 | 持長期金鑰 | 擁有 sync | 對 wardend 的角色 |
|---|---|---|---|---|---|
| **`wardend`** | 常駐（macOS LaunchAgent `gui/$UID`；Linux systemd user；Android 前景服務，僅 Full 模式） | 金鑰階層與解鎖狀態機、Bitwarden Client API、本地 store、sync+outbox、agent session/grant/approval/audit、metadata store 寫入、auto-type 排程 | **是（唯一）** | **是（唯一）** | — |
| **`wd`**（CLI） | 一次性（短命） | 人與腳本介面；無 socket 時 on-demand 拉起 wardend | 否 | 否 | Thin |
| **`warden-mcp`** | 由 agent host（Claude/Codex/MCP client）spawn，stdio 長駐到 host 退出 | MCP ↔ WTP 轉譯；唯一對 LLM 說話的進程 | 否 | 否 | Thin（預設 metadata-only） |
| **`Warden.app`**（macOS GUI） | 使用者可開可關；關閉不影響 daemon 服務能力 | 瀏覽/編輯 vault、enrollment 與 approval 的確認 UI、TCC 權限入口、匯出 | 否（只在顯示時持短命明文） | 否 | Thin |
| **`WardenProvider.appex`** | 系統按需啟動、隨時回收 | macOS credential provider（passwords/passkeys/OTP/text-to-insert）的 `ASCredentialProviderViewController` | 否 | 否 | Thin |
| **Android app** | 兩種形態：Full（前景服務內嵌 wardend 核心）或 Thin（連遠端 hub） | AutofillService / CredentialProviderService / IME inline 建議 | Full 時是（Keystore 綁定） | Full 時是 | 自決 |
| `Safari/Chrome extension` | 之後階段 | native messaging → `wd bridge` → WTP | 否 | 否 | Thin（非初期目標） |

**明確不存在的進程**：沒有第二個 sync 客戶端、沒有「GUI 內嵌的第二份金鑰」、沒有 `bw serve` 式的第二 HTTP 層（HTTP 只是 WTP 的一種 transport binding，同一個 core）。

### 1.2 金鑰持有矩陣（誰手上有什麼）

| 材料 | 位置（靜態） | 位置（動態） | 誰能讀明文 |
|---|---|---|---|
| master password | 只在解鎖瞬間存在（stdin/SecureField/BIOMETRIC 之後消失） | 只在 `wardend` 記憶體（`Zeroize`） | 无人（無 API 回傳） |
| master key / stretched master key | 不落地 | `wardend` 記憶體 `KeyBundle` | 仅 `wardend` |
| user key（ Protected Symmetric Key 解密後） | 以 OS 級 wrap 落地（見下） | `wardend` 記憶體 | 仅 `wardend` |
| 使用者 RSA private key | 以 user key 加密，存在 mirror | `wardend` 記憶體 | 仅 `wardend` |
| org 對稱金鑰 | 以 RSA 加密後落地 | `wardend` 記憶體 | 仅 `wardend` |
| **device wrap key**（自動解鎖用） | macOS Keychain（`SecAccessControl` biometric ACL，`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`）；Android Keystore（StrongBox、`setUserAuthenticationRequired`、僅接受 **Class 3**，對齊 https://bitwarden.com/help/biometrics ） | 只在 unwrap 瞬間 | `wardend` |
| **agent session token** | `~/.config/warden/sessions/*.0600` 或由 channel binding 派生（不落 env） | thin client 記憶體 | thin client 自己 |
| **short-lived secret lease**（填充/注入用，TTL≤5s、單次） | 不落任何盤 | 只在發起填充的那個 thin client 記憶體（GUI/extension/autotype actor） | 該進程，用完 `Zeroize` |
| **SecretRef URI**（`wd1:...`） | 可任意洩漏 | 可安全進 LLM context（本身不帶熵） | 無意義（需 grant 才能解析） |

邊界裁決（與 Bitwarden 官方 browser biometrics「把解鎖金鑰下放給 extension」相反，採 1Password App↔CLI 的**不下放**模式；兩者業界並存的證據見 `priorart` §1.2/§3）：
> Thin client 拿到的永遠是「資料/操作結果/短命 lease」，不是「金鑰」。理由：(a) 集中稽核與撤銷（`priorart` §6.2、§6.4）；(b) macOS extension 有記憶體上限，Argon2id ≥64MB 在 extension 內解鎖可能 OOM（https://raw.githubusercontent.com/rorkai/demo-bitwarden-ios/main/BitwardenShared/Core/Platform/Utilities/Constants.swift `maxArgon2IdMemoryBeforeExtensionCrashing`）→ fat 解密路徑在 extension 內是被平台限制否決的，不是風格偏好；(c) agent 隱私模型要求「能解密的進程數」可數。

### 1.3 Sync 所有權（單一寫者）

- `wardend` 的 `warden-sync` 是機器上**唯一**與 server 交換 ciphers/folders/collections 的元件；`/sync` 全量拉、ciphers CRUD 推、通知走 SignalR 相容 WebSocket（Vaultwarden 自建：https://github.com/dani-garcia/vaultwarden/blob/main/src/api/notifications.rs ），不可用時降級為抖動輪詢。
- Thin client **沒有**「觸發 sync」的語意，只有 `Sync.Trigger{reason}` 的**請求權**（可否執行取決於 grant）與事件訂閱權。
- 本地 SQLite 是 UI 的唯一真相源：任何列表/搜尋/排序都不等網路（治 `gaps` §B「擴充功能開啟延遲」同型的本地優先問題）。
- 寫入路徑永遠先落地再 push（見 §2.4 outbox）→ 離線可寫入是預設態而非特殊態（官方僅 read-only，https://bitwarden.com/help/using-bitwarden-offline ）。

### 1.4 Transport 總表

| 邊 | 傳輸 | 幀 | 對端身分驗證 | 訊息加密 |
|---|---|---|---|---|
| `wd`/`warden-mcp`/`Warden.app` → `wardend` | Unix domain socket `$(XDG_RUNTIME_DIR)/warden/agent.sock`（macOS：`~/Library/Application Support/Warden/run/agent.sock`），`0600`、同 uid | WTP（length-prefixed, postcard/JSON 雙模） | `LOCAL_PEERCRED`/`audit_token` 取 uid + pid → 讀 `/proc`/`proc_pidpath` 取實際執行檔路徑 → macOS 以 `SecCode` 驗證代碼簽章（Team ID 白名單） | 本機免（信任 socket 權限 + peer 驗證）；可選 HKDF 派生 per-conn AEAD |
| `WardenProvider.appex` → `wardend` | App group 上的 **Mach/XPC**（service name `group.com.warden.mac.<unique>`，Apple 明列 app group 可用 Mach IPC/XPC：https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups ）；wardend LaunchAgent 註冊 `MachServices` 以便**按需啟動** | WTP over XPC dictionary | sandbox extension + entitlement + container 歸屬 | 不需要（同 app group） |
| `warden-mcp` ↔ agent host | stdio JSON-RPC（MCP 2025-06） | MCP tools | 由 host 程序 fork 關係（`getppid` 鏈 + 可選 allowlist） | n/a |
| 跨機 Thin（Android → 桌上 wardend） | TCP + TLS1.3，或 Tailscale 等使用者自建隧道 | WTP（同一套訊息） | 配對碼（QR/9 位）+ SPKI pin + 綁定 `DeviceId`；每裝置獨立 grant | TLS；並在 WTP 層做 X25519 → HKDF session key 的雙層加密（防隧道被信任錯誤，思路同 KeePassXC crypto_box：https://github.com/keepassxreboot/keepassxc-browser/issues/1884 ） |
| Android 進程內（App ↔ AutofillService/CredentialProviderService） | 同 app 程序/同進程記憶體 + `BoundService` | 直接呼叫 in-proc API | Android 元件邊界 | n/a |
| 附件本機 blob | 檔案系統 `~/Library/Application Support/Warden/blobs/<sha256>`，`0600` | — | — | 已加密（伺服器信封） |

註：`priorart` §1.2 記錄 1Password 在 macOS 用 NSXPCConnection + Browser Helper、Linux 用 setgid unix socket、Windows 用 named pipe；本設計只在 macOS 走 XPC（因為 sandbox extension 強迫），其餘一律 UDS，避免四套 transport 語意漂移。Bitwarden 官方現行做法是 UDS + 1MB 長度前綴（https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/core/src/ipc/mod.rs ）且自評「XPC 可能更好」，本設計採其教訓。

### 1.5 進程圖

```
                        ┌──────────────────────────────────────────────────────┐
   LLM / agent host ───►│ warden-mcp (thin, stdio)                             │
   (Claude, Codex)      │  · tools 只回 metadata + wd1:// SecretRef            │
                        └───────────────────────┬──────────────────────────────┘
                                                │ WTP/UDS
   人類 ──► wd (thin, 一次性)  ─────────────────┤
   Safari ─► browser ext (thin, 之後) ─────────┤
   macOS ──► WardenProvider.appex (thin) ──XPC──┤   ← MachServices 按需啟動
   Android ─► AutofillService/CredentialProvider│
              (Full 形態時 in-proc；Thin 形態 TLS)│
                                                ▼
                        ╔══════════════════ wardend（Full client 核心）═══════════╗
                        ║ warden-keys   狀態機 + KeyBundle + LockEpoch            ║
                        ║   └ KeyStore: Keychain(biometric ACL)/Keystore(Class3)  ║
                        ║ warden-vault  Item 模型 + Sensitivity + Search/Dedupe    ║
                        ║ warden-store  SQLite mirror + Overlay + Outbox + Audit   ║
                        ║ warden-sync   pull/push + ServerProfile + Conflict       ║
                        ║ warden-proto  Bitwarden Client API (自寫 crypto)          ║
                        ║ warden-agent  Session/Grant/Approval/Redactor/SecretRef  ║
                        ║ warden-fill   AutoType 排程 + IdentityStore 寫入 + lease  ║
                        ║ warden-wtp    協議伺服（UDS / XPC / TLS binding）         ║
                        ╚═══════╤═════════════════════════════╤═══════════════════╝
                                │ HTTPS                       │ WebSocket (SignalR 相容)
                        Bitwarden Cloud /            /connect/token, /sync,
                        Vaultwarden（一級目標）       /ciphers CRUD, /notifications/hub
```

### 1.6 模組（crate）圖與依賴方向

```
warden-crypto  ←── warden-proto ←── warden-sync ←┐
      ↑                ↑                          │
      └── warden-vault ┴──── warden-store ── warden-keys
                             ↑        ↑
                    warden-agent   warden-fill
                             \      /
                              warden-wtp
                                 ↑
       bins: wardend ── wd ── warden-mcp    (platform/: swift, kotlin)
```
規則：`crypto` 不依賴任何上层；`vault` 不知道網路；`store` 不知道金鑰語意（只存 `Prot<T>` 的加密態 + 已索引的 metadata 欄）；`agent` 是唯一能把「session/grant」與「金鑰狀態」放在一起比較的模組；UI 端只依賴 `warden-wtp` 產物（Swift/Kotlin 由同一份 schema 產生 bindings，不重新實作）。

---

## 2. 核心型別草圖

### 2.1 Vault item 模型與敏感度分級

```rust
/// 加密態標記：同一欄位可能是信封或已解密值。Debug/serde 一律 REDACTED。
pub enum Prot<T> { Enc(CipherString), Dec(T) }

pub struct ItemId(pub Uuid);
pub enum Owner { Personal, Org { org: OrgId, collections: Vec<CollectionId>, use_type: UseType } }

pub struct Item {
    pub id: ItemId,
    pub kind: ItemKind,                  // Login | SecureNote | Card | Identity
    pub owner: Owner,
    pub folder_id: Option<FolderId>,
    pub name: Prot<String>,
    pub notes: Option<Prot<String>>,
    pub favorite: bool,
    pub reprompt: Reprompt,              // None | Password（填充前是否要二次主密碼）
    pub login: Option<Login>,
    pub card: Option<Card>,
    pub identity: Option<Identity>,
    pub fields: Vec<Field>,              // Text | Hidden | Boolean
    pub attachments: Vec<AttachmentMeta>,// 僅 metadata + 本地 blob 狀態
    pub revision: ServerRev,             // 伺服器 revisionDate
    pub raw: RawEnvelope,                // ★ 伺服器原始 JSON（未建模欄位的真相源）
    pub local: LocalOverlay,             // ★ 僅本機（tags/usage/dedupe group）
    pub pending: Option<MutationId>,     // outbox 中有未推的變更
    pub sync_state: MirrorState,         // Mirrored | Tombstoned{at} | LocalOnly{draft}
}

pub struct Login {
    pub username: Prot<String>,
    pub password: Prot<SecretString>,
    pub totp: Prot<Option<TotpSeed>>,    // 本地產生 code，不依賴伺服器
    pub uris: Vec<LoginUri>,             // uri + match_ + skip_auto_fill
    pub password_updated_at: Option<DateTime<Utc>>,
    pub password_strength: Option<u8>,   // 本地計算，永不推回
}

pub struct Field { pub id: FieldId, pub kind: FieldKind, pub name: Prot<String>, pub value: Prot<String> }

/// 欄位路徑：grant / patch / SecretRef / audit 共用的唯一座標系
pub enum FieldPath { Name, Notes, Username, Password, Totp, Uri(u32),
                     FieldName(FieldId), FieldValue(FieldId),
                     CardNumber, CardCode, CardHolder, IdentityField(String), Attachment(AttachmentId) }

/// ★ 隱私模型的基石：每一欄位有靜態敏感度分級
pub enum Sensitivity { Opaque,   // id, kind, owner, dates, revision → 任何 session 可見
                       Identity, // name, uris, folder, tags, favorite → 默認給 agent
                       Secret }  // password, totp seed, notes, hidden field, card number/code, username(可選), 附件內容
pub fn sensitivity_of(p: &FieldPath) -> Sensitivity;   // 純函數，無配置
```
分級表（默認；`username` 可經 account policy 降為 `Identity`）：

| 欄位 | 級 | 進 LLM context 默認 |
|---|---|---|
| id / kind / owner / revision / dates | Opaque | 是 |
| name, uris, folder, tags, favorite, 使用次數 | Identity | 是 |
| login.password, totp seed/代碼, notes, hidden fields, card number/code, identity 欄, 附件內容 | Secret | 否（需 Reveal grant 或 approval） |

理由：官方 MCP 的批評全部集中在「明文進 context」（`agent` §1、§4），而缓解模式的共識是 metadata-only tools + 單一受審計的 reveal（https://github.com/adamrowles1996/vaultgate 、https://1password.com/blog/where-mcp-fits-and-where-it-doesnt ）。以 `FieldPath` 為座標系，才能讓 grant、patch、audit、SecretRef 四件事共用同一套語意而不是各做一套。

### 2.2 金鑰生命週期狀態機

```rust
#[derive(Clone, Copy)] pub struct LockEpoch(pub u64);   // ★ 全域鎖世代

pub enum UnlockState {
    Locked      { why: LockReason, has_local_mirror: bool },
    Unlocking   { challenge: UnlockChallenge, deadline: Instant, origin: UnlockOrigin },
    Unlocked    { keys: KeyBundle, origin: UnlockOrigin, epoch: LockEpoch,
                  deadline: Option<Instant> },          // vault timeout；None = 手動鎖
}

pub struct KeyBundle { master: Option<MasterKey>, stretched: Option<StretchedKey>,
                       user_key: UserKey, private_key: Option<RsaPrivate>,
                       org_keys: HashMap<OrgId, SymmetricKey> }  // 全部 Zeroize + Debug=REDACTED

pub enum UnlockMaterial { MasterPassword(SecretString), DeviceAssertion(DeviceAssertion),
                          SessionKeyInterop /* Key Connector 例外路徑，見 §7 R4 */ }
pub enum LockReason { User, Timeout, ServerLogout, KeyRotation, Revoked{by}, Startup }
pub enum UnlockOrigin { Interactive, Biometric, ThinProxy{session} }

/// 狀態機事件（唯一寫入者：wardend 內一個 task）
pub enum UnlockEvent {
    LoginRequested { server: Url, email: String, material: UnlockMaterial },
    Unlocked       { epoch: LockEpoch },
    LockRequested  { reason: LockReason },               // → epoch += 1，broadcast
    VaultTimeout,
    TokenRefreshed { .. }, TokenRejected,
    KeyRotated     { new_epoch: LockEpoch },
    EgressChanged  { online: bool },                     // ★ 不改狀態！
}
```

轉移（`Locked` → `Unlocking` → `Unlocked` → `Locked`；`Unlocked` 內部轉換只換 `KeyBundle` 不換 epoch）：

| 現態 | 事件 | 新態 | 副作用（不變量） |
|---|---|---|---|
| Locked | `LoginRequested(MasterPassword)` | Unlocking → Unlocked | KDF（PBKDF2-SHA256 600k 或 Argon2id 32M/6/4，salt=email）→ hash 送 server 驗證 → 解 Protected Symmetric Key；`epoch++` |
| Locked | `LoginRequested(DeviceAssertion)` | Unlocking → Unlocked | Keychain/Keystore unwrap `WrappedUserKey`；不需網路（**離線可解鎖**，治 clients#19055） |
| Unlocking | `Timeout` / 用戶取消 | Locked | challenge 銷毀；不 bump epoch（從未解鎖） |
| Unlocked | `VaultTimeout` / `LockRequested` | Locked | **epoch++ → 所有 AgentSession 失效、所有 lease 撤銷、`ASCredentialIdentityStore` 標記 needs-auth、事件廣播** |
| Unlocked | `EgressChanged(false)` | Unlocked | 僅 `sync.paused = true`；讀寫與 outbox 照常 |
| Unlocked | `TokenRejected` | Unlocked(降級) | 保留金鑰、暫停 push、要求重新認證（官方 CLI 在此情況下直接壞：https://github.com/bitwarden/clients/issues/12270 ） |
| any | `KeyRotated` | Locked{KeyRotation} | 作廢 wrap、保留 mirror、要求重解鎖 |

三條關鍵裁決：
1. **離線不降級解鎖狀態**：`EgressChanged` 不是鎖事件。官方「離線僅 read-only」是把 sync 失敗誤當鎖定（https://bitwarden.com/help/using-bitwarden-offline ）。
2. **`LockEpoch` 是共享解鎖狀態的唯一機制**：任何 thin client 的 session 都記錄鑄造時的 epoch；請求時 epoch 不符 ⇒ `Err(StaleEpoch)` ⇒ 重新認證。一次鎖定即全域撤銷（1Password 的「App 上鎖撤銷全部 CLI 授權」模式，https://www.1password.dev/cli/app-integration-security ），同時實作 FR 1635「桌面↔瀏覽器共享解鎖狀態」（168 likes，https://community.bitwarden.com/t/1635 ）與 FR 101009。
3. **一次解鎖＝一個 KeyBundle**：治「第二次 `bw unlock` 作廢第一張 session token」（clients#6898）與「CLI 與 Desktop 解鎖狀態完全不相通」（clients#22773）——因為 unlock 是狀態機轉換而非 token 簽發，重複 unlock 冪等。

### 2.3 Agent session / scope / grant / approval / redaction

```rust
pub struct SessionId(pub Uuid);

pub enum Principal {
    Cli       { uid: Uid, exe: CodeId },
    McpShim   { shim: CodeId, host: AgentHost },          // host: claude-code | codex | cursor | unknown
    Extension { bundle_id: String, team_id: String },
    Gui       { window: WindowId },                        // 人類操作者，全權
    Device    { device_id: DeviceId, platform: Platform, pairing: PairingId },
}

/// 一個 session = (principal, grants, epoch, budget)。預設拒絕。
pub struct Session {
    pub id: SessionId, pub profile: ProfileId, pub principal: Principal,
    pub grants: GrantSet,
    pub epoch: LockEpoch,                    // ★ 綁鎖世代
    pub issued_at: DateTime<Utc>, pub expires_at: Option<DateTime<Utc>>,
    pub bound: ChannelBinding,               // peer 憑證摘要 / TLS finhsh / XPC 對端
    pub approvals: ApprovalMode,
    pub state: SessionState,                 // Active | Suspended{why} | Revoked{by}
    pub usage: UsageLedger,
}

pub struct Grant {
    pub target: Target,
    pub access: Access,
    pub budget: Budget,
    pub ttl: Option<Duration>,
    pub requires: Requires,                  // TouchId | GuiConfirm{timeout} | None
}
pub enum Target { All, Folder(FolderId), Tag(String), Collection(CollectionId),
                  Item(ItemId), UriDomain{ suffix: String }, DupGroup(GroupId),
                  FieldScope { item: ItemId, field: FieldPath } }
pub enum Access {
    See(SensitivityFloor),                   // 讀 metadata；floor 決定能看多高的欄位
    Use(UseKind),                            // ★ 用而不讀
    Reveal(SensitivityFloor),                // 取明文（會進 context！）
    Mutate(MutateSet),                       // Create|Patch|Delete|Move|Assign|Overlay
    Delegate,                                // 可簽發子 grant（不可超越自身）
}
pub enum UseKind { TotpCode, InjectEnv{slot: EnvSlot}, AutoType, Run{sandbox: ExecPolicy},
                   SshSign, PasskeyAssert, HttpBasic }
pub struct Budget { pub max_uses: u32, pub per_item_max_uses: u32,
                    pub max_bytes_out: u64, pub min_interval: Option<Duration> }
pub enum ApprovalMode { PerItem, PerSessionOnce{ttl}, PreGranted{budget}, Never{deny: bool} }
```

**Enrollment（人类在环）**：
```rust
pub struct EnrollmentRequest { principal: Principal, requested: GrantSet, display_name: String,
                               proof: PeerProof, callback_hint: Option<String> }
pub struct EnrollmentTicket { id: TicketId, expires: Instant, decided: Option<Decision> }
// GUI / wd 顯示「Claude Code 要求：See(Identity) All + Use(TotpCode) Item(x) 30d/100次」，
// 使用者可縮減 grant 後批准；批准產生 Session（含 token）， wardend 記 audit。
```

**SecretRef（機密在 context 裡的代表符號，不帶熵）**：
```rust
pub struct SecretRef { pub item: ItemId, pub field: FieldPath, pub once: OnceNonce }
// 文字形：wd1:<item>:<field>:<opaque>。可安全寫進 LLM context / 日誌 / git。
// 解析只在 wardend 內、且要求呼叫者 session 對該 FieldPath 有 Use|Reveal。
pub struct Resolved { pub value: SecretString, pub lease: LeaseId, pub ttl: Duration }
```

**Redaction（輸出淨化）**：
```rust
pub struct Redactor { known: Vec<(Digest, SecretString)>, min_len: usize }
// 凡離開 wardend 朝向 agent 的位元組（Run 的 stdout/stderr、錯誤字串、event payload）
// 一律過 Redactor；被替換為 wd1:...。
```
這條是實證要求的：研究顯示 73.5% 的洩漏來自 debug logging 把 stdout 直接餵進 context、89.6% 洩漏憑證立即可利用、fork 分發讓修補失效（https://arxiv.org/abs/2604.03070 ），且 multi-agent 共享 context 會造成跨 agent 邊界放大（https://arxiv.org/abs/2605.10614 ）。**只靠「工具別回傳機密」不夠，必須在出口做淨化**，因為注入點是 daemon 自己。

**Audit（append-only、hash 鏈）**：
```rust
pub struct AuditRecord { ts, session: SessionId, principal: Principal, action: ActionTag,
                         item: Option<ItemId>, field: Option<FieldPath>,
                         sens: Sensitivity, outcome: Outcome, bytes_out: u32,
                         approval: Option<ApprovalId>, epoch: LockEpoch, prev_hash: Hash }
```
這補的是「無 audit trail」（`agent` §1 對官方 MCP 的批評）與 Bitwarden 無 webhooks 造成 agent 只能輪詢（`gaps` §D1）。

### 2.4 離線寫入 outbox + 本機 overlay

```rust
pub struct MutationId(pub u64);
pub struct Mutation { pub id: MutationId, pub seq: u64, pub item: ItemId,
                      pub base: ServerRev,                    // ★ 樂觀併發的基準
                      pub created_at: DateTime<Utc>,
                      pub op: Op, pub state: MutState }
pub enum Op { Create(ItemDraft), Patch(ItemPatch), Delete, Restore,
              Move{ to: Owner }, Assign{ collections: Vec<CollectionId> },
              AttachmentAdd{ blob: BlobRef, file_name: Prot<String> }, AttachmentDel{ id } }
pub enum MutState { Queued, InFlight{ lease: LeaseId, until: Instant },
                    Awaiting{ why: Wait },                     // 例如附件需付費方案/大檔上傳
                    Applied{ new_rev: ServerRev },
                    Conflict{ server: ServerRev, ours: Item, theirs: Item },
                    Dead{ reason: String } }                   // 需人類介入，不再自動重試

/// merge-patch：只發我們改過的欄位 + 保留 raw 中未建模欄位
pub struct ItemPatch { pub diff: RawMergePatch, pub touched: BTreeSet<FieldPath> }
```

規則（全部可測）：
1. **提交順序**：本地套用 → `Mutation` 入 outbox（同一 SQLite transaction）→ 非阻塞 push。任何 UI 從不等網路。
2. **同機因果序**：`seq` 單調；同一 item 的 mutation 必須依序推。跨機合併採**欄位級 3-way merge**（base = `Mutation.base`）：`ours`/`theirs` 改動欄位不相交 ⇒ 自動合併；相交 ⇒ `Conflict` 進 GUI 佇列，**永不靜默覆蓋**（官方無離線寫入，所以也沒有這套規則可抄：FR 107，287 likes，https://community.bitwarden.com/t/107 ）。
3. **附件離線**：blob 落地、`Awaiting{ blob_upload }`，上線後走 `/ciphers/{id}/attachment` v2 流程；檔案名解密後必經 sanitize（clients#20790 的教訓）。
4. **TDE/無主密碼帳號**：`Op` 需要 user key；以 trusted device 加入 org 而無主密碼者，在官方 CLI 完全取不到資料（https://bitwarden.com/help/cli/ ）→ 本設計在 `warden-keys` 走 auth-request 流程（暫時 RSA key + access code，由已登入裝置以 user key 加密回傳；https://bitwarden.com/help/log-in-with-device/ ）把 `WrappedUserKey` 落地，之後離線可解鎖。

```rust
/// ★ Tags 等「協定裡不存在」的東西必須是本地 overlay，不能假裝是伺服器欄位
pub struct LocalOverlay { pub tags: BTreeSet<Tag>, pub usage: UsageStat,     // 最後使用/次數 → 排序
                          pub sort_hint: Option<f32>, pub dup_group: Option<GroupId>,
                          pub pinned: bool, pub notes_local: Option<Prot<String>> }
pub enum OverlayOp { AddTag(Tag), DelTag(Tag), Touch{at}, SetSortHint(f32), AssignGroup(GroupId) }
```
`gaps` §A2/§A3（tags 492 likes、排序 494 likes）與 §A12 都是**十年高分缺口且 server 無對應欄位**，所以只能 client-side。v1：overlay 僅本機。v2：以一個隱藏的 `SecureNote`（`name = "Warden Overlay"`，內容 = overlay JSON）作為跨裝置同步載體，per-tag LWW 合併——明標為「client 約定，非協定擴充」，不謊稱 server 支援。

### 2.5 Full↔Thin 協議訊息（WTP）

```rust
pub struct ProtoVersion(pub u16);                       // 協商：min/max
pub enum ClientMsg {
    Hello  { version: ProtoVersion, auth: Auth, wants: Vec<EventTopic>, caps: Vec<Cap> },
    Invoke { rid: u64, call: Call },
    Cancel { rid: u64 },
    Approval { id: ApprovalId, decision: Decision },     // thin 端替人類回答
    Pull   { cursor: StoreCursor },                      // 斷線補事件
}
pub enum ServerMsg {
    Welcome { proto: u16, profile: ProfileId, epoch: LockEpoch, server: ServerProfile,
              state: UnlockStateView, events_from: StoreCursor },
    Reply   { rid: u64, outcome: Result<Response, WtpError> },
    Event   { topic: EventTopic, seq: StoreCursor, payload: EventPayload },   // metadata-only
    NeedApproval { a: ApprovalRequest },                 // 反向請求（human-in-the-loop）
    Challenge { c: UnlockChallenge },                    // thin 代為收集主密碼/biometric
}
pub enum Auth { Session { token: SessionToken },
                Enroll  { pairing: Pairing, requested: GrantSet, proof: PeerProof },
                Resume  { session: SessionId, epoch: LockEpoch, mac: ChannelMac } }
pub enum WtpError { StaleEpoch{seen,now}, Locked, NeedsApproval{ApprovalId},
                    Denied{grant_gap}, NotFound, Conflict{ours,theirs},
                    Unsupported{feature}, ServerDrift{detail}, RetryAfter(Duration) }
```

```rust
pub enum Call {
  Auth  (AuthCall),                        // Login, Unlock, Lock, WhoAmI, RotateWrapKey
  Vault (VaultCall),                       // List, Get, Search, Create, Patch, Delete, Restore,
                                           // Move, Assign, Overlay, History, Import, Export
  Use   (UseCall),                         // TotpCode, GeneratePassword, ResolveRef, Run, SshSign, PasskeyAssert
  Fill  (FillCall),                        // FillRequest, AutoTypeOnce, ClaimLease, RegisterIdentity
  Sync  (SyncCall),                        // Trigger, Status, DrainOutbox, ResolveConflict
  Agent (AgentCall),                       // Enroll, Approve, Revoke, ListSessions, Audit, SetPolicy
  Admin (AdminCall),                       // ServerProfile, SetBaseUrl, Diagnostics, Version
}
pub enum EventTopic { VaultChanged, LockStateChanged, OutboxDrained, ConflictDetected,
                      ApprovalRequired, AgentUsage, EgressChanged, ProviderMetadataDirty }
```

協定紀律：(a) **事件承載只有 Opaque/Identity 級**，機密永不進 event；(b) `Pull{cursor}` 讓 thin client 斷線重連後補事件，取代 `bw serve` 跑幾小時 session 損壞的問題（clients#9306）；(c) `Unsupported{feature}` 明確表達「此 Vaultwarden 版本沒有這個」，而不是 500 或靜默錯。

### 2.6 ServerProfile 與 raw mirror（協定漂移的防禦）

```rust
pub struct ServerProfile { pub kind: ServerKind,       // BitwardenCloud | Vaultwarden{v} | Unknown
                           pub version: Option<String>,
                           pub has: BTreeSet<Feature>,
                           pub quirks: BTreeSet<Quirk> }
pub enum Feature { CipherBulkPut, AttachmentV2, NotificationsHub, AuthRequestTde, Send,
                   OrganizationDomainVerification, KeyConnector, PendingDeleteField }
pub enum Quirk { MissingUserDecryptionOptions, NonStandardErrorShape, NoKdfParameters }
// 探測：GET /config（version）+ /identity/.well-known/openid-configuration + 一次 /sync 的欄位存在性
```
`warden-proto` 對每個 response 走 `serde(deny_unknown_fields = false)` 並把原始 JSON 存進 `Item.raw`；`Patch` 由 `raw` + `diff` 合成，因此**我們未建模的欄位不會被我們的 PUT 抹掉**。這是無官方 spec 環境下唯一可靠的相容性策略（`protocol` §4 的雙向漂移風險）。

---

## 3. 主要模組公開 API 簽名

介面窄、複雜度藏在實作內。每個 crate 只對外暴露一個 trait（+ 資料型別）；跨 crate 只能透過這些 trait 或 `warden-wtp` 的訊息型別溝通。全部偽代碼。

### 3.1 `warden-crypto`（自寫，零依賴上層；授權隔離的重點）
```rust
pub trait BitwardenCrypto: Send + Sync {
    fn master_key(pw: &SecretStr, email: &str, kdf: KdfParams) -> Result<MasterKey>;      // PBKDF2-SHA256(600k) | Argon2id(32M,6,4)
    fn master_password_hash(mk: &MasterKey, pw: &SecretStr) -> PasswordHash;              // 送 server 的第一輪
    fn stretch(mk: &MasterKey) -> StretchedKey;                                           // HKDF 拉長
    fn decrypt_user_key(sk: &StretchedKey, enc: &ProtectedSymmetricKey) -> Result<UserKey>;
    fn encrypt<T: Encode>(k: &SymmetricKey, v: &T) -> CipherString;                       // 依 type 0/2 選信封
    fn decrypt<T: Decode>(k: &SymmetricKey, c: &CipherString) -> Result<T>;
    fn rsa_unwrap(priv_: &RsaPrivate, wrapped: &RsaCiphertext) -> Result<SymmetricKey>;   // org key
    fn totp_code(seed: &TotpSeed, at: DateTime<Utc>) -> Otp;                              // 本地產生，不問 server
    fn make_password(policy: &PwdPolicy) -> SecretString;
}
pub enum CryptoError { MacMismatch, UnknownCipherType(u8), BadB64, KdfUnsupported }
```
不變量：任何實作型別 `Debug` 輸出 `REDACTED`；`SecretString` 於 drop 時 `Zeroize`；本 crate **不得** `use` 任何網路/IO 型別（用 `cargo deny` + `#[allow]` 結構測試守住）。

### 3.2 `warden-keys`（狀態機 + OS 級金鑰保護）
```rust
pub trait UnlockMachine: Send + Sync {
    fn state(&self) -> UnlockStateView;                            // 不含金鑰本身
    fn epoch(&self) -> LockEpoch;
    fn submit(&self, material: UnlockMaterial) -> Result<UnlockReceipt>;  // 冪等：重複解鎖不撤銷別人
    fn lock(&self, reason: LockReason) -> LockEpoch;               // 回傳新 epoch
    fn watch(&self) -> broadcast::Receiver<UnlockEvent>;
    fn with_keys<R>(&self, f: impl FnOnce(&KeyBundle) -> R) -> Result<R>;  // ★ 金鑰不離開本模組的閉包
}
pub trait KeyStore {                                               // Keychain / Keystore 適配
    fn store_wrapped(&self, w: &WrappedUserKey, label: &AccountLabel) -> Result<()>;
    fn load_wrapped(&self, label: &AccountLabel) -> Result<Option<WrappedUserKey>>;
    fn unwrap(&self, a: &DeviceAssertion) -> Result<UserKey>;      // biometric / Class-3 bound
    fn clear(&self, label: &AccountLabel) -> Result<()>;
}
pub trait PlatformCrypto { fn biometric_available() -> bool; fn wrap_strength() -> WrapStrength; }
```
`with_keys` 是架構性的：其他模組永遠拿不到 `KeyBundle` 實值，只能在閉包內使用 → 編譯期就排除「金鑰被傳到 thin client / 存進 store / 印進 log」。

### 3.3 `warden-proto`（Bitwarden Client API）
```rust
#[async_trait] pub trait BitwardenApi {
    async fn token(&self, g: TokenGrant) -> Result<Tokens>;         // password | client_credentials | auth_code+PKCE
    async fn auth_request_new(&self, pubkey: &RsaPub, kdf: &KdfParams) -> Result<AuthRequest>;  // login-with-device / TDE
    async fn auth_request_answer(&self, id: &str, enc: &RsaCiphertext) -> Result<()>;
    async fn sync(&self) -> Result<RawSync>;                        // 全量，保留 raw
    async fn cipher_get(&self, id: ItemId) -> Result<RawEnvelope>;
    async fn cipher_post(&self, id: ItemId, patch: &RawMergePatch, base: ServerRev) -> Result<RawEnvelope>;
    async fn cipher_put_new(&self, draft: &RawEnvelope) -> Result<RawEnvelope>;
    async fn cipher_delete(&self, ids: &[ItemId], org: bool) -> Result<()>;
    async fn cipher_restore(&self, id: ItemId) -> Result<()>;       // admin-delete 者走 org 端點
    async fn attachment_url(&self, id: ItemId, req: &AttachReq) -> Result<AttachUpload>;
    async fn folders(&self) / collections(&self) / organizations(&self) -> Result<...>;
    async fn events_hub(&self) -> Result<Box<dyn EventStream>>;     // SignalR 相容 WS；None ⇒ 輪詢
    async fn probe(&self) -> ServerProfile;                         // §2.6
}
pub trait EventStream { fn next(&mut self) -> impl Future<Output = Option<ServerEvent>>; }
```
不實作 Public（組織管理）API 於初期；`bw` 的 org 管理由 MCP 官方 server 勝任，本專案不重複造輪（`gaps` §F5）。

### 3.4 `warden-store`
```rust
pub trait VaultStore {
    fn apply_sync(&self, raw: &RawSync, at: DateTime<Utc>) -> Result<StoreCursor>;   // 寫 mirror + 重建索引
    fn query(&self, q: Query) -> Result<Vec<ItemMeta>>;        // 只回 Opaque+Identity；永不含 Secret
    fn item(&self, id: ItemId) -> Result<Option<Item>>;        // 含 Prot::Enc
    fn raw(&self, id: ItemId) -> Result<RawEnvelope>;
    fn overlay(&self, id: ItemId, op: OverlayOp) -> Result<()>;
    fn index_secrets(&self, id: ItemId, needle_index: &SearchIndex) -> Result<()>;  // 明文值搜尋（FR 11941）用，見 §4 G2
    fn cursor(&self) -> StoreCursor;
}
pub struct Query { pub text: Option<String>, pub owner: OwnerFilter, pub folder: Option<FolderId>,
                   pub tags: TagFilter, pub kind: Option<ItemKind>, pub dup_group: Option<GroupId>,
                   pub sort: SortKey,                     // Name | Used | Updated | Created | Fuzzy
                   pub limit: u32, pub offset: u32 }
pub trait Outbox {
    fn enqueue(&self, tx: &Transaction, m: Mutation) -> Result<MutationId>;
    fn take_due(&self, now: Instant, n: u8) -> Result<Vec<Mutation>>;    // 認領 + lease
    fn settle(&self, id: MutationId, outcome: MutState) -> Result<()>;
    fn conflicts(&self) -> Vec<ConflictRecord>;
    fn depth(&self) -> OutboxDepth;                                       // 供 UI 顯示「N 項待同步」
}
pub trait AuditLog { fn append(&self, r: &AuditRecord) -> Result<()>;
                     fn query(&self, f: AuditFilter) -> Result<Vec<AuditRecord>>;
                     fn head(&self) -> Hash; }                            // hash 鏈驗證
pub trait BlobStore { fn put(&self, bytes: &[u8]) -> Result<BlobRef>;     // content-addressed
                      fn open(&self, b: &BlobRef) -> Result<File>; fn missing(&self) -> Vec<BlobRef>; }
```
SQLite（WAL）為唯一本地持久層；`0600`、目錄 `0700`。鏡像列存**加密態**；只有 Opaque/Identity 索引表存明文（name/uri/tags），且該表可選以 device wrap key 派生的 key 做 SQLCipher 式加密（v1 先以檔案權限 + 明文 metadata 索引實作，並把「索引是否需加密」列為 §7 R3 的開放問題——因為 name/uri 本身就是使用者視為敏感的資料）。

### 3.5 `warden-sync`
```rust
pub trait SyncEngine {
    fn trigger(&self, why: SyncReason) -> SyncHandle;                   // 去重＋抖動；併發請求合併
    fn drain(&self) -> DrainHandle;                                     // 推 outbox（依 seq）
    fn watch(&self) -> broadcast::Receiver<SyncEvent>;
    fn status(&self) -> SyncStatus;                                     // online, last_sync, outbox_depth, paused_because
    fn resolve(&self, c: ConflictId, pick: Resolution) -> Result<()>;   // Ours | Theirs | Merged(patch)
}
pub enum SyncReason { Startup, Timer, EgressRestored, ThinRequest{session}, OutboxNonEmpty, ServerPush }
```
`trigger` 的冪等與去重是刻意設計：官方「每次呼叫 spawn 一個 Node 且各自 sync」的痛（clients#2741、#2735）在此轉成「N 個請求 → 1 次 sync」。

### 3.6 `warden-vault`（模型語意與資料管理）
```rust
pub trait VaultModel {
    fn classify(&self, p: &FieldPath) -> Sensitivity;
    fn project(&self, item: &Item, floor: SensitivityFloor, unlocked: bool) -> ViewItem;  // ★ 唯一的「能看到什麼」函數
    fn patch(&self, base: &Item, edits: Vec<Edit>) -> Result<(ItemPatch, Item)>;
    fn can_change_type(&self, from: ItemKind, to: ItemKind) -> Reicon;   // FR 1148
    fn search(&self, q: &str, scope: SearchScope) -> Vec<Hit>;           // 含 by-password-value（FR 11941）
}
pub trait VaultOps {
    fn find_duplicates(&self, policy: DupPolicy) -> Vec<DupGroup>;       // 依 base domain + username（解密掃描在 daemon 內，只回 id）
    fn merge(&self, g: GroupId, into: ItemId, keep: MergePlan) -> Result<MutationId>;  // FR 648
    fn bulk(&self, ids: &[ItemId], op: Op) -> Vec<Result<MutationId>>;   // 批次搬移/歸檔/指派
    fn unshare(&self, id: ItemId, to: PersonalTarget) -> Result<MutationId>;            // FR 604/14489
}
```
`project()` 把「敏感度 × 解鎖態 × grant」三個維度收斂成單一函數，讓 CLI/GUI/MCP/extension 不可能各自發明月確的可見性規則（避免第二套慣例）。

### 3.7 `warden-agent`
```rust
pub trait AgentApi {
    fn enroll(&self, req: EnrollmentRequest) -> Result<EnrollmentTicket>;   // 觸發 NeedApproval
    fn decide(&self, ticket: TicketId, grants: GrantSet) -> Result<SessionToken>;  // 人類可縮減
    fn revoke(&self, s: SessionId, by: Revoker) -> Result<()>;
    fn sessions(&self) -> Vec<SessionView>;
    fn call(&self, s: SessionId, c: Call) -> Result<Response>;              // ★ 唯一入口：授權檢查+budget+audit+redaction
    fn mint_ref(&self, s: SessionId, p: FieldPath) -> Result<SecretRef>;
    fn resolve(&self, s: SessionId, r: &SecretRef) -> Result<Resolved>;     // 需 Use|Reveal
    fn run(&self, s: SessionId, plan: RunPlan) -> Result<RunOutcome>;       // 注入 env + Redactor
    fn policy(&self) -> AgentPolicy; fn set_policy(&self, p: AgentPolicy) -> Result<()>;
}
pub struct RunPlan { pub argv: Vec<String>, pub env: BTreeMap<String, SecretRefOrLiteral>,
                     pub cwd: PathBuf, pub timeout: Duration, pub net: NetPolicy }
pub struct RunOutcome { pub code: i32, pub stdout: RedactedText, pub stderr: RedactedText,
                        pub leaked: Vec<FieldPath> }                        // 偵測到但已淨化的
```
`call()` 作為**唯一**入口是安全設計的核心：授權、budget、audit、redaction 四個檢查不可能被新介面繞過（新增 `Call` variant 時，未分派會在 `match` 處編譯失敗）。

### 3.8 `warden-fill`（auto-type / identity store / lease）
```rust
pub trait FillBroker {
    fn request(&self, s: SessionId, q: FillQuery) -> Result<FillPlan>;     // 依 focus/uri 選 item（含 overlap 評分）
    fn claim(&self, s: SessionId, plan: FillPlanId) -> Result<SecretLease>;// ★ 短命明文，TTL≤5s，單次
    fn autotype(&self, s: SessionId, item: ItemId, target: FocusTarget,
                template: Option<TypeTemplate>) -> Result<TypedReport>;    // 回計數不回明文
    fn identity_store(&self) -> &dyn IdentityStoreWriter;
}
pub trait IdentityStoreWriter { fn register(&self, ids: &[CredentialIdentity]) -> Result<usize>;
                                fn invalidate(&self, epoch: LockEpoch); }  // 鎖 ⇒ 系統列表標記需認證
pub struct SecretLease { value: SecretString, expires: Instant, one_shot: bool }
```
`claim()`（lease）是「thin 不持長期金鑰」的唯一受控例外：**一次一格、5 秒、單次、強制 audit**，且只發給能證明 UI 邊界的 principal（GUI/extension/autotype actor），不發給 `McpShim{host: unknown}`。對應 Android 的 `FillResponse.setAuthentication()`（PendingIntent 延後暴露，https://developer.android.com/identity/autofill/autofill-services ）與 macOS 系統中介的 Touch ID 填充。

### 3.9 `warden-wtp`
```rust
pub trait Transport {
    fn listen(&self, endpoint: Endpoint) -> Result<Box<dyn Listener>>;   // Uds | Xpc | Tls
    fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Duplex>>;
}
pub trait WtpServer { fn serve(&self, l: Box<dyn Listener>, core: CoreHandles) -> ServerHandle; }
pub trait WtpClient {
    fn hello(&mut self, auth: Auth) -> Result<Welcome>;
    fn invoke(&mut self, c: Call) -> Result<Response>;
    fn events(&mut self) -> Box<dyn Iterator<Item = Event>>;              // 含 Pull 補遺
    fn on_approval(&mut self, cb: impl Fn(ApprovalRequest) -> Decision);
}
pub struct Schema;  impl Schema { pub fn generate() -> (rust::Types, ts::Types, swift::Types, kotlin::Types); }
```
bindings 由單一 schema 產生（Swift/Kotlin/TS），thin client 端**不該有第二份業務邏輯**。

### 3.10 CLI 表面（`wd`）
```
wd login --server URL --email E [--password-env|--sso|--device]   # 之後所有命令不需任何 env var
wd unlock [--biometric] / wd lock / wd status [--json]
wd ls [--filter 'tag:dev uri:*.example.com'] [--sort used] [--json]
wd get ITEM [--fields name,uri] | --reveal password | --ref        # --ref 印 wd1://，預設
wd totp ITEM [--copy|--exec 'prog {env}']                          # 默認 Use，不 Reveal
wd run --env TOKEN=wd1://ITEM/password -- cargo publish            # 注入 + scrub 輸出
wd new login --name N --uri U --password-from-prompt
wd edit ITEM --set password=<new> / --add-tag k8s / --move org:COL
wd sync [--force] / wd outbox [--resolve <id>:ours|theirs]
wd enroll --agent claude-code --grant 'see:identity all; use:totp item:X' --ttl 30d --max 100
wd sessions / wd revoke <id> / wd audit [--since 1d] [--json]
wd provider install|status|reindex                                # macOS credential provider
wd mcp                                                            # stdio server（等同 warden-mcp）
```
輸出契約：`--json` 永不含 Secret 級欄位，除非該行同時帶 `--reveal`（且 `--reveal` 在 stdout 為 TTY 時才允許，pipe 給 agent 時預設拒絕）→ 治 `bw get password` 強制寫剪貼簿無開關（clients#2742）與 Windows 剪貼簿殘留（#2621）。

### 3.11 端到端序列（驗證自洽性）

**(a) agent 要 TOTP 並用它登入 CLI 工具**
```
Claude → warden-mcp: tool call totp(uri:"github.com")
wardend: session.See(Identity) → 找到 item（只比對 name/uri 索引）
         session.Use(TotpCode) on Item(x)? → 是 → KeyBundle 閉包內算 code
         audit{action=Use.TotpCode, item=x, sens=Secret, bytes_out=6}; 回 "wd1:x/totp#once"
warden-mcp → Claude: "code ready as wd1:x/totp#once"（LLM 從未見過 6 位數字）
Claude → tool call run{argv:["gh","auth","login","--with-token"], env:{TOKEN:"wd1:x/password"}}
wardend: 檢查 Use(InjectEnv) + budget → spawn 子程（env 注入）→ 讀 stdout/stderr
         Redactor（已知值：該 password）→ 淨化後回傳 + audit
```
**(b) 離線新增（飛機上）**：GUI `wd new` → `wardend` 用 KeyBundle 加密 → 同一 transaction 寫 mirror + `Outbox{Create, base=None}` → UI 立刻顯示（`LocalOnly`）→ 上線後 `drain()` 推 `cipher_put_new` → 回 `Applied{new_rev}` → 事件 `OutboxDrained`。全程無網路也可完成。
**(c) macOS 系統填充**：Safari 觸發 AutoFill → 系統啟動 `WardenProvider.appex` → `provideCredentialWithoutUserInteraction` → XPC（必要時經 `MachServices` 按需拉起 wardend）→ `Fill.request(uri)` → 回候选 list（Identity 級）→ 使用者選取 + 系統 Touch ID → `Fill.claim` 取 lease → `completeRequest(withSelectedCredential:)`。extension 記憶體只需容納一個字串，不碰 Argon2。

---

## 4. 五個優先缺口的映射

階段劃分：P0 骨架 → P1 本地優先讀寫 → P2 agent 表面 → P3 資料管理 → P4 共享解鎖 + auto-type → P5 macOS provider → P6 跨機 thin。

| 缺口（選定優先序） | 負責模組 | 階段 | 具體交付與證據 |
|---|---|---|---|
| **1. 自動化缺口**（無 webhooks；CLI 主密碼耦合；`BW_SESSION` env 一開新 terminal 就失效；每次 1–5s Node 啟動；`bw serve` 跑久會壞；MCP 薄殼無 scope） | `warden-agent`（session/grant/budget/audit/redaction）、`warden-wtp`（事件流 + `Pull{cursor}`）、`warden-mcp`、`warden-sync`（去重 trigger） | **P2** 主體（P1 先有 daemon+socket） | 常駐 daemon 持鑰 ⇒ 腳本不需 `BW_SESSION` env（治 clients#19839、cli#65）；`LockEpoch` ⇒ 鎖即撤銷（治 #6898）；UDS 短命 client ⇒ 呼叫 p95 < 50ms（對照 #2741）；事件流取代輪詢（治 `gaps` §D1 無 webhooks）；`Run` + Redactor ⇒ 「用而不讀」（vaultgate/1Password Environments 已驗證此模式）；每 session 有 grant 與 audit（治官方 MCP 無 scope/無軌跡） |
| **2. 資料管理缺口**（tags 492👍、排序 494👍、去重合併 392👍、批次搬移/unshare 322👍、以密碼值搜尋 119👍、改型別） | `warden-store`（overlay 表 + FTS5 索引）、`warden-vault`（`VaultOps`、`project`、`classify`）、`warden-sync`（`Move`/`Assign`/bulk） | **P3**（tags/排序的本地部分在 P1 就有表結構，P3 開 API/UI） | `LocalOverlay` 承認 tags 不存在於協定（§2.4）；`Query.sort{used,updated,created,fuzzy}`；`find_duplicates`+`merge` 在 daemon 內掃描，只回 id（明文不出）；`unshare` 走 `Move{to:Personal}`+`Assign`，並規避 bw `move` 的 collection bug（clients#11689）；`index_secrets` 讓「搜密碼值」在本地明文索引上做，不上傳任何東西 |
| **3. auto-type 與共享解鎖狀態**（FR 158 719👍 / FR 93873 未實作；FR 1635 168👍；CLI↔Desktop 解鎖不相通 #22773） | `warden-keys`（`LockEpoch` + `watch`）、`warden-fill`（`autotype`、`identity_store`）、`Warden.app`（TCC 授權與確認 UI）、Android `AutofillService` | **P4**（共享解鎖狀態其實在 P1 隨狀態機就誕生；P4 交付 keystroke 注入） | epoch 廣播 = 單一真相的解鎖狀態，任何 thin client 訂閱 `LockStateChanged` ⇒ 桌面解鎖 → CLI/extension 同時可用（官方做不到是因為各 client 各自持 token）；auto-type 由已獲 TCC 授權的 GUI 進程執行、wardend 只給 lease（§3.8）；Android 用 `setAuthentication()` PendingIntent 做同語意的「先佔位後暴露」 |
| **4. 離線可寫入**（FR 107 287👍；官方文件明載離線僅 read-only） | `warden-store.Outbox`、`warden-sync`（欄位級 3-way merge + `Conflict` 佇列）、`warden-crypto`（離線加密不需網路）、`warden-keys`（離線解鎖 via DeviceAssertion） | **P1**（與本地優先 store 同期，因為它是資料路徑而非附加功能） | 提交順序 = 本地 transaction 先行（§2.4）；`EgressChanged` 不觸發鎖定（§2.2 裁決 1）；附件 blob 排隊；`wd outbox --resolve` 給人類解衝突，絕不靜默覆蓋 |
| **5. macOS 系統級密碼支援**（FR 93723 36 樓/78 讚仍 open；官方只有 passkey provider，beta 2026-10） | `WardenProvider.appex`（thin）、`warden-fill.IdentityStoreWriter`（`ASCredentialIdentityStore`）、`warden-wtp` 的 XPC binding、`wardend` 的 `MachServices` 按需啟動 | **P5** | 能力宣告 `ProvidesPasswords/ProvidesPasskeys/ProvidesOneTimeCodes/ProvidesTextToInsert`（缺項就不會被系統列出，1Password 的教訓）+ entitlement `com.apple.developer.authentication-services.autofill-credential-provider` 同時掛 container app 與 extension；走 `ASPasswordCredentialRequest`（macOS 14+）與 OTP（15+）；thin 模式規避 extension 記憶體上限；`invalidate(epoch)` 處理上鎖後系統仍快取列表的問題 |

缺口之外的刻意**不做**（避免重複造輪，`gaps` §F5）：passkey 登入填充（已 GA）、桌面 SSH agent（已 GA，本設計只在 `UseKind::SshSign` 預留位置）、archive（付費已有）、附件批次匯出（已有）、Secrets Manager（`bws` 生態不同）。

---

## 5. 第一個可獨立驗證的增量（P0+P1 的前段）

**名字：「Vaultwarden round-trip spine」。** 範圍刻意不含 GUI、不含 agent grant、不含 macOS extension——只證明最底層三件事成立：自寫 crypto 能與真實 server 互通；常駐 daemon + socket 能在 <50ms 內回 metadata；寫入能離線落地並最終收斂。

### 5.1 交付內容
1. Rust workspace：`warden-crypto`、`warden-proto`、`warden-store`、`warden-keys`、`wardend`、`wd`（`warden-sync` 只做 pull + 單筆 push）。
2. `wardend` 起 UDS listener，實作 `Auth::Enroll`(本地 uid 檢查) + 最小 `Call` 集：`Auth(Login/Unlock/Lock/WhoAmI)`、`Vault(List/Get/Create/Patch/Delete)`、`Sync(Trigger/Status)`。
3. `wd` 一次性 client：`login/unlock/lock/status/ls/get/new/edit/rm/sync`，全部 `--json`。
4. SQLite：`ciphers(raw, enc, rev, cursor)`、`meta_plain(name, uri, kind, updated_at)`、`outbox`、`audit`。
5. 測試向量集：從 GPL 的 bitwarden/clients 對照取 KDF/信封/HKDF 測試向量（不鏈接其碼），加上 Vaultwarden 端到端。

### 5.2 能跑的指令
```bash
docker run -d --name vw -p 8080:80 vaultwarden/server:1.37.2
cargo test -p warden-crypto                          # 純向量，無網路
cargo run -p wardend -- --data-dir ./dev --sock ./dev/a.sock serve &
cargo run -p wd     -- --sock ./dev/a.sock login --server http://127.0.0.1:8080 \
                       --email dev@warden.test --password-env WP
cargo run -p wd     -- --sock ./dev/a.sock sync
cargo run -p wd     -- --sock ./dev/a.sock ls --json | jq 'length'
cargo run -p wd     -- --sock ./dev/a.sock new login --name 'inc-1' --uri https://a.test
```

### 5.3 過關條件（每條都是可執行斷言，不是「看起來對」）
| # | 斷言 | 對標的真實痛點 |
|---|---|---|
| A1 | `warden-crypto` 向量測試 100% 通過，含 PBKDF2-SHA256 600k、Argon2id(1024MiB variant 縮參) 、type 0 信封 + HMAC 驗證失敗檢測、HKDF 拉長、RSA-OAEP unwrap org key | 自寫 crypto 正確性 |
| A2 | 對 Vaultwarden `login → sync → ls` 成功，`ls` 筆數等於手動 `GET /sync` 的 ciphers 數（腳本比對 id 集合） | 無官方 spec 下的互通性；Vaultwarden 一級目標 |
| A3 | `ls --json` 的每個物件鍵集合 ⊆ `{id,kind,name,uris,folder_id,owner,revision,tags,pending,local_only}`；`password`、`notes`、`totp` 鍵**不存在**（`jq -e 'any(has("password")) | not'`） | metadata-only 預設 |
| A4 | `grep -a "$WP" ./dev/store.db` 無輸出；`grep -a` 任一已知密碼值亦無輸出（附件/明文索引除外，此階段未開） | 靜態加密 |
| A5 | 冷 `wd ls --json` p95 < 50 ms（同一 daemon，100 次；對照官方 CLI 1–5 s） | clients#2741 |
| A6 | 兩個併發 `wd unlock` 之後，先前取得的 session 仍可呼叫（不斷言失誤）；`wd lock` 後兩者的請求都回 `StaleEpoch` | clients#6898、#19839 |
| A7 | `docker stop vw` → `new login` 成功且 `status` 顯示 `outbox.depth=1`、狀態 `LocalOnly`；`docker start vw` → 30 秒內 `depth=0` 且 server 上該 cipher 的 id 與本地一致 | 離線可寫入（FR 107） |
| A8 | 併發修改：兩终端（模擬兩裝置）改同一 item 的不同欄位 → 自動合併；改同一欄位 → `outbox` 進 `Conflict` 且 `wd outbox` 列出 ours/theirs，不發生靜默覆蓋 | 離線寫入的必要配套 |
| A9 | 每個 `Call` 都在 `audit` 表留下一列且 hash 鏈可驗證（`wd audit --verify` 回 `ok`）；把 daemon 的 log 設為 trace 後，日誌中搜尋密碼值應為 0 命中 | agent 缺口要求的稽核與不洩漏 |
| A10 | `cargo deny` + 結構測試：`warden-crypto`/`warden-proto` 不含任何 `bitwarden-*` SDK crate 依賴；repo `LICENSE` = GPL-3.0-or-later；README 含「not affiliated with Bitwarden, Inc.」商標聲明 | 授權硬約束 |

### 5.4 明確不在本增量
GUI、MCP shim、grant/approval/budget（只留 `Auth::Enroll` 的全權佔位）、auto-type、identity store、跨機 TLS、附件上傳、org/collection 寫入、overlay 跨裝置同步。這些在 P2+ 各自帶自己的可驗證增量。

### 5.5 為什麼這是正確的第一刀
它把**風險最高且不可回頭**的兩件事（自寫 crypto 的正確性、無 spec 環境的 server 互通性）在沒有 UI 的情況下證完；同時把本架構的三個招牌屬性（daemon 常駐、socket 短命 client、本地先行寫入）做成可計數的斷言。若 A1/A2 失敗，整個 hub-and-spoke 形態都要重估——所以必須最早失敗。

---

## 6. Rationale：考慮過並拒絕的替代形態

### 6.1 完整替代形態 B：「Fat core library，每個 client 各自持鑰各自 sync」（Keyguard / PanicVault / Bitwarden iOS 式）
每個介面（CLI、GUI、extension、Android）鏈接同一份 `warden-core`，金鑰在各自進程內、各自寫 app-group 容器、各自 sync，靠 `NSFileCoordinator` 式協調防併發損壞。
**拒絕理由**：
1. 與使用者已拍板的「Thin client 一律向 Full client 取資料」直接衝突——形態 B 裡不存在 thin。
2. 金鑰出現在 N 個進程 ⇒ agent 隱私模型破功：prompt injection 只要控制其中任何一個 client 就拿到解密能力，而 LLM 側的 MCP 進程恰恰是最不可信的。研究已指出 agent 記憶本身即持久洩漏面（https://www.1password.dev/environments/mcp-server ）。
3. 沒有單一 sync 擁有者 ⇒ 每個 client 都要實作 outbox/衝突解決，四種平台四套語意；`gaps` 裡官方產品的可靠性問題多數源自「多套實作各自為政」。
4. macOS extension 的記憶體上限讓 fat 路徑在 Argon2id 帳號上直接不可靠（`macos` §1、§4 表格）。
5. 無集中 audit/grant ⇒ 「誰在什麼時候讀了哪一格」要跨進程拼圖。
保留其優點的方式：形態 A 的 **Android Full 模式**就是形態 B 的一個實例（单進程 hub），所以行動端不必強造 RPC。

### 6.2 完整替代形態 C：「GUI app 當 hub，daemon 選配」（Bitwarden Desktop + desktop_proxy / 1Password 主 App 式）
主 App 持鑰並開 IPC，CLI/extension 連它；無常駐 daemon 概念。
**拒絕理由**：(a) 無頭情境（SSH 登入、CI、Termux、純 CLI 使用者）失去 hub，正是 `agent` §5 描述的離開官方 CLI 的動機；(b) GUI 重啟/更新即中斷所有 agent session 與 autofill 服務——1Password 的 "Failed to connect to 1Password.app" 是前車之鑑（`macos` §2）；(c) Electron/NSApplication 的 life-cycle 不適合承擔「唯一寫者」的責任；(d) 把 UI 進程提昇為信任根，等於讓最複雜、攻擊面最大的程式碼去守金鑰。

### 6.3 其他被拒的局部選擇
| 替代 | 拒絕理由 |
|---|---|
| 鏈接官方 `bitwarden/sdk-internal` | 授權硬牆：§3.1 禁止對第三方提供應用、§3.3 禁止用於 Vaultwarden 型實作；README 自承 API 隨時破壞。省下的工程量買不到出貨資格。 |
| 採「下放解鎖金鑰給 thin client」（Bitwarden browser biometrics 模式，`priorart` §3） | 與形態 B 同類問題：金鑰出 daemon 即不可稽核；且 extension/CLI 拿到金鑰後就必須自寫 crypto，等於把 A 的簡潔性換掉卻沒換到離線能力（離線已由本地 mirror + DeviceAssertion 達成）。只在「完全無 daemon 可用」的降級場景才考慮。 |
| 以 `bw serve` / HTTP 作為主要 thin 介面（vaultgate 式 loopback `bw serve`） | 官方自認不建議開放網路、無鑑權、無併發保證、跑久會壞（clients#9306）、且继承全部 CLI 痛點。本設計保留 HTTP 作為 **WTP 的 binding**（同一 core），但不讓它成為第一級介面。 |
| 遠端 gateway 為主要形態（vaultgate：機密留在 server 端，agent 遠端呼叫） | 那是**部署形態**而非程序形態；本設計的 `Use(InjectEnv)/Run` 讓同一套 grant 模型可跑在本機或跨機 TLS，不需另立架構。初期以本機 hub 為預設（隱私與延遲）。 |
| 核心用 TypeScript/Bun（與官方 clients 同语言） | Node 啟動成本已被實測抱怨（#2741）；行動端嵌入（Android/iOS extension）無乾淨路徑；GC 語言持有 `SecretString` 時明文殘留堆上不可控，`Zeroize` 語意無從保證。 |
| 核心用 Kotlin Multiplatform（一份碼覆蓋 Android+macOS） | Android 端最順，但 macOS credential provider extension 要背 K/N runtime + 體積/記憶體壓力（extension 已有上限）；且與 Rust 生態的 crypto 元件（`ring`/`rustcrypto`）相比需要更多自寫 binding。列為次選：若日後 Android 成為主戰場可重新評估。 |
| 四個平台各自 native 實作（無共用核心） | 協定漂移時要改四處；Vaultwarden 相容性測試矩陣 ×4。與 §6.1(3) 同因。 |
| 「GUI 用 gpui-kit/Electron 以共用一份 UI」 | 本設計的重點是核心共用，UI 選擇不影響架構成立與否；原生 UI 在 credential provider / biometric prompt / inline autofill 上有平台 API 的硬需求。 |

### 6.4 為什麼選形態 A（總結）
- 它是唯一同時滿足使用者四項決定的形態：agent 可操作但機密預設不進 context（單一出口 `AgentApi::call` + Redactor）、補官方缺口（daemon/共享鎖/離線寫入都是 hub 屬性）、CLI+GUI 跨平台且初期 macOS+Android（一份核心 + 原生 UI + 同一 WTP）、Full/Thin 之分（hub = Full，其餘 = Thin，定義清楚不需第二條規則）。
- 它有生產先例支持：rbw-agent（持鑰 daemon + UDS + TTL）、1Password App↔CLI（不下放鑰 + 逐次授權 + 稽核）、KeePassXC-Browser（主金鑰永不進瀏覽器 + 訊息層加密）、Bitwarden macOS passkey provider（薄 extension + socket 到主 App）、Keyguard androidSshAgent（裝置上 Full client 開 agent socket）。五個獨立實作收斂到同一形態，這不是巧合。

---

## 7. 全域不變量、風險與開放問題

### 7.1 不變量（每條都要有對應測試或 lint/結構檢查）
1. 除 `wardend`（Android Full 時為其 in-proc 等位物）外，沒有任何進程持有 user key。
2. 明文 Secret 級欄位不進入：WTP event、LLM tool 結果、audit 表、日誌、CLI 非 `--reveal` 輸出、`ASCredentialIdentityStore`。
3. 金鑰只在 `with_keys` 閉包內存在；`KeyBundle` 不實作 `Clone`，`Debug` 輸出為 `REDACTED`。
4. 所有對 server 的寫入必經 `Outbox`；沒有任何模組能直接呼叫 `cipher_post` 而不留 `Mutation`。
5. 所有 thin 請求必經 `AgentApi::call`；`Call` 的每個 variant 都要有 grant 分派（編譯期窮盡）。
6. `LockEpoch` 單調遞增；任何 session、lease、identity-store 註冊都記 epoch，比對不符即拒。
7. UI/搜尋只讀本地 store；網路永不阻塞讀路徑（讀路徑 p95 由 A5 守住）。
8. 未建模欄位透過 `raw` + merge-patch 無損往返（property test：`sync → put(unchanged)` 後 server JSON 逐位元組相同）。

### 7.2 風險與緩解
| 代號 | 風險 | 緩解 |
|---|---|---|
| R1 | Client API 無 spec，隨 server 版本漂移（官方新欄位打爆舊 Vaultwarden，反之亦然：vaultwarden#6729、discussion#5713） | `ServerProfile` 探測 + lenient parse + raw mirror（§2.6）；CI 釘 Vaultwarden 版本並定期跑「最新官方 clients 匯出 → 我們的 `/sync` 解析」golden 測試；追 frankhommers/bitwarden-openapi-generator 的 diff。 |
| R2 | thin 模式使 autofill 依賴 daemon 存活（1Password 的 connect 錯誤） | LaunchAgent `MachServices` 按需啟動 + extension 端有界重試（≤1.5s）+ 失敗時回 `.userInteractionRequired` 讓系統開互動 UI（而非靜默失敗）；`P0` 增量之後的第一件事就是做這個 spike 並量測冷啟動延遲。 |
| R3 | 本地明文 metadata 索引（name/uri）本身即敏感資料 | 開放問題：v1 以 `0600` + 目錄 `0700` 承受；v2 選項是把索引表放加密 DB 或以 FTS 索引存 HMAC(token) 而非明文——需先量測搜尋延遲再決定。 |
| R4 | Key Connector / 企業政策下無法本地解鎖（官方 CLI 在此無法 lock：community 帖 36885） | `UnlockMaterial::SessionKeyInterop` 預留；此形態下 `LockEpoch` 仍由 wardend 決定（本機撤銷 ≠ 伺服器撤銷），並在 UI 明示差異。企業 policy 拉取列 P6。 |
| R5 | 自寫 crypto 實作錯誤（HMAC 未驗、IV 重用、type 2 GCM nonce） | 向量測試 + 「用官方 clients 產出的 vault 檔做 golden 解密」+ 上線前對 `bitwarden-crypto` GPL 測試集跑一遍（取測試不改授權）。 |
| R6 | agent 端 `Run` 的沙箱不足（惡意 argv 把 secret 寫進檔案或網路外送） | `NetPolicy` 預設 deny、`RunPlan.cwd` 限 temporary、輸出紅化僅是事後補救；文檔明說「`Run` 的信任前提是把 secret 交給被執行的程式」——這是與 1Password `op run` 相同的已定義邊界，不假装更強。 |
| R7 | 商標與授權（GPL-3.0 传染性、Bitwarden 商標） | 全 repo GPL-3.0-or-later + 不用「Bitwarden」當產品名 + 不鏈接 GPL 元件於 v1（僅取測試向量）；發佈前做一次 `cargo deny` + NOTICE 檢查（A10）。 |

### 7.3 開放問題（需 Main 或下一階段決定，不影響本形態成立）
1. `wd` 是否支援「無 daemon 降級模式」（自己持鑰跑一次）？本包傾向**不支援**，以維持不變量 1；但 CI/容器場景可能需要一個明確標記的 `--standalone`（語意＝把 wardend 跑在 foreground）。
2. 多帳號：本包採「單 wardend、多 profile（每 profile 獨立 KeyBundle/epoch/outbox，socket 共用、請求帶 `profile`）」；若實際 UX 證明跨帳號 grant 複雜，再拆成 per-profile socket。
3. Overlay 跨裝置同步（§2.4 v2）是否要推遲到 tags 需求被真實使用者確認之後。
4. 瀏覽器 extension（native messaging）與 iOS 是否列為 P6 之後的獨立設計包（本包範圍：macOS + Android，與使用者決定一致）。
