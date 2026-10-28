# bitward 系統架構設計包（候選二：單進程金鑰中樞，Everything-Spoke）

日期：2026-10-29。作者：DesignCandidateTwo。本檔是設計包不是實作；所有型別與簽名皆為 `not implemented` 等級的偽代碼。事實依據五份 grounding 報告（protocol / agent / gaps / macos / priorart），文中以 [協議§n]、[agent§n]、[gaps§n]、[macos§n]、[priorart§n] 標註引用。

---

## 0. 選定的結構（一句話）與全域決策

**選定形態：單一常駐 daemon（`bitwarderd`）是唯一的 Full client runtime——它是唯一持鑰者、唯一 sync 擁有者、唯一審計點；桌面上所有其他東西（GUI、CLI、MCP server、macOS credential provider extension、瀏覽器 native messaging shim、Android autofill）一律是同一份文件化協議上的 Thin client。金鑰永不下放（keys never leave the daemon），Thin client 只取「結果」或「受審计的單次明文」。**

這是 1Password CLI app-integration 的「不下放鑰」路線 [priorart§1.2]，而非 Bitwarden desktop_proxy 的「下放解鎖金鑰」路線 [priorart§3]；也是 1Password macOS autofill 與 Bitwarden passkey provider 已生產驗證的「薄 extension + 常駐主體」拓撲 [macos§2]。所有其他可行結構（fat library、GUI-as-hub、CRDT local-first、下放鑰 hub）在 §6 列出並說明拒絕理由。**不折衷混合**：例如 macOS extension 記憶體痛點不用「extension 內解密」解決（那是混合制），而是用「identity store 預寫 metadata + 常駐 daemon 快速路徑」解決。

### 0.1 硬約束的遵守方式

| 約束 | 決策 |
|---|---|
| 官方 Rust SDK 商業授權禁止出貨第三方 app [協議§2] | 自寫 `bw-crypto` crate，實作公開規格：PBKDF2-SHA256（預設 600,000 次）/ Argon2id（32MiB/6/4）派生 master key、兩層 master password hash、HKDF stretched key、user key（AES-256-CBC + HMAC-SHA256，`2.iv|ct|mac` 字串格式）、RSA-2048 使用者金鑰對解封裝 org key [協議§1]。僅以 GPL 的 `bitwarden-crypto` 原始碼與官方 jest fixtures 作**測試參考**，不鏈接 sdk-internal 任何 crate。 |
| 授權 | 全專案採 **GPL-3.0**（與官方 clients 同照會），保留日後移植 GPL 元件的空間；不含任何 Bitwarden License 程式碼。 |
| Client API 無官方 spec、Vaultwarden 一級目標 [協議§1,§4] | `bw-server` 層以 frankhommers/bitwarden-openapi-generator 產出的 OpenAPI 為契約來源，**反序列化一律欄位寬容**（未知欄位忽略、可選欄位缺失不炸）；CI 釘選 Vaultwarden 版本矩陣跑相容性測試。教訓直接寫成回歸測試：CLI 2025.12.0 因 `UserDecryptionOptions are required` 打爆舊 Vaultwarden（vaultwarden#6729）→ 我們的規則：`UserDecryptionOptions` 缺失時降級為「僅密碼解鎖」，不视为错误。 |
| 「Bitwarden」是商標 | 產品名 `bitward`（working name），文件用語「Bitwarden-compatible client」。 |

### 0.2 技術棧

- 核心語言 **Rust**（daemon、CLI、crypto、sync、protocol、MCP、autotype 引擎、macOS extension 的 socket client）。理由：rbw 已證明 Rust 在 Bitwarden 協議上可行 [agent§6.4]；行動 UniFFI 綁定是現成模式；單一靜態二進位便于 LaunchAgent 常駐。
- macOS GUI：**SwiftUI** app（本身是 Thin client，僅畫 UI + 承載 extension 容器 + 系統整合）。
- Android：**Kotlin** app，核心 crate 經 UniFFI 編入，跑在 foreground service 內（見 §1.4）。
- 本機儲存：SQLite（WAL）。金鑰封存：macOS Keychain（biometric ACL）／Android Keystore（Class 3-bound）[macos§3 iOS 先例、priorart§4.4]。

---

## 1. 進程 / 模組圖

### 1.1 macOS 拓撲（初期主戰場）

```
                          ┌─────────────────────────────────────────────────┐
                          │ bitwarderd  (LaunchAgent, SMAppService 常駐)     │
                          │ ★唯一持鑰者 ★唯一 sync 擁有者 ★唯一審計點          │
                          │                                                 │
   一次性（on-demand）     │  bw-ipc ─ 監聽 ~/Library/Application Support/    │
  ┌────────────────────┐  │           bitward/daemon.sock  (unix socket)    │
  │ bitward (CLI)      │──┤◄──┤ 每連線: SO_PEERCRED+簽章驗證 + X25519 AEAD   │
  │  bitward mcp       │──┤   │ 框架: length-prefixed ClientMsg/ServerMsg   │
  │  bitward-nm (shim) │──┤   ├───────────────────────────────────────────  │
  └────────────────────┘  │   │ bw-agent   broker: session/scope/grant/審計  │
                          │   │ bw-vault   讀寫 facade、dedup/merge/bulk     │
  ┌────────────────────┐  │   │ bw-index   SQLite FTS + overlay(tags,sort)  │
  │ bitward-desktop    │──┤◄──┤ bw-sync    sync engine + outbox + reconcile │
  │ (SwiftUI GUI,thin) │  │   │ bw-unlock  金鑰生命週期狀態機               │
  └────────┬───────────┘  │   │ bw-autotype CGEvent 鍵盤注入引擎            │
           │ 安裝/容器      │   │ bw-store   vault.db(密文) + keystore 封裝   │
  ┌────────▼───────────┐  │   └──────────────────────┬──────────────────────┘
  │ macOS credential    │  │                          │ HTTPS + WebSocket
  │ provider extension  │──┤◄─ group container 內      ▼
  │ (系統按需拉起,thin)  │  │   unix socket            Bitwarden-compatible server
  └────────────────────┘  │   (app group IPC)          (identity: /connect/token,
                          │                            api: /sync, /ciphers CRUD,
   外部 agent 程序          │                            notifications hub WS)
  ┌────────────────────┐  │
  │ Claude/Codex 等     │──┘◄── stdio: MCP（bitward mcp 子命令）→ daemon 協議
  └────────────────────┘        機密預設不進此邊界（見 §2.3 grant 模型）
```

**常駐進程**（只有兩個半）：
1. `bitwarderd` — 唯一的 Full client runtime。由 GUI 首次設定時註冊為 LaunchAgent；被系統回收後 launchd 重啟（冷啟成本：讀 token + 封裝金鑰，**不需要**重新 KDF，因為 stretched key 以 device-bound 方式封存，見 §2.2）。
2. `bitward-desktop` GUI — 使用者不开它也全部功能可用（autofill、agent、CLI、autotype 都不依賴 GUI 進程存在）；GUI 只是解鎖 UI、審計瀏覽、衝突解決、grant 核准弹窗的其中一個面。
3. （半個）瀏覽器 native messaging host `bitward-nm` — 由瀏覽器按需 spawn 的純管道（stdio ↔ daemon socket，無邏輯、無金鑰），屬一次性介面。

**一次性介面**：`bitward` CLI（短命進程，向 daemon 取一切；解決官方 CLI「每次起 Node 1–5 秒」「BW_SESSION 每終端失效」「第二次 unlock 作廢第一張 token」三大痛點 [agent§5]——我們的 CLI 無狀態，session 在 daemon 內）。`bitward mcp`（agent spawn 的 stdio MCP server，本身也是 thin client，持一張 daemon 發的 scoped session token）。macOS provider extension（系統按需拉起，無狀態）。

**誰持有金鑰**：只有 `bitwarderd` 的記憶體中有解鎖態的 user key / stretched master key。落盤形態：`vault.db` 內存**伺服器原樣密文**（ciphers 的 `2.iv|ct|mac` 欄位不改寫）+ 本地 overlay 表；金鑰本體以 Keychain（biometric ACL）封存的 wrapped 形態存在。**任何 IPC 回應都不含長期金鑰**——這是與 Bitwarden 官方 extension 生物識別協議（把解鎖金鑰傳給 extension 自行解密 [priorart§3]）的根本分歧點。

**誰擁有 sync**：只有 `bitwarderd` 內的 `bw-sync`。所有 client 的「sync 請求」是同一個單飛（single-flight）佇列的輸入；写路徑一律 `意圖 → outbox → push → 確認`。跨裝置提示走 notifications hub WebSocket（Vaultwarden 的 SignalR 相容實作亦可）[gaps§E]。

### 1.2 模組（crate）依賴圖

```
 bw-proto   協議型別（無依賴；Thin/Full 兩側共用的單一事實來源）
   ▲
 bw-crypto  KDF/加解密/簽章原語（自寫，GPL-clean）
   ▲
 bw-server  Bitwarden Client API 用戶端（寬容解析、版本探測、auth-request/TDE）
   ▲
 bw-store   SQLite: vault 密文 + overlay + outbox + audit + session 表
   ▲
 bw-core ──┬─ bw-unlock  金鑰生命週期狀態機
           ├─ bw-sync    pull/merge/push + 三方合併
           ├─ bw-index   查詢/搜尋/去重/統計（讀 vault+overlay）
           ├─ bw-vault   寫入 facade（create/update/delete/move/unshare）
           ├─ bw-agent   session/scope/grant/approval/redaction/audit
           └─ bw-autotype（platform trait 注入 CGEvent）
   ▲
 bw-daemon（bitwarderd 主程式：組裝 bw-core + bw-ipc server）
 bw-cli / bw-mcp / bw-nm-shim / macos-provider-client（Thin 側二進位/extension 內嵌的 client crate）
```

Thin 側只允許依賴 `bw-proto`（+ 各自的 UI/平台碼）。**依賴方向即安全邊界**：extension、CLI、MCP 在編譯層就拿不到 `bw-crypto` 的解鎖 API。

### 1.3 transport 總表

| 鏈路 | transport | 對端驗證 | 機密性 |
|---|---|---|---|
| CLI/GUI/MCP ↔ daemon | unix socket（`$XDG_RUNTIME_DIR` 或 Application Support 下 `bitward/daemon.sock`） | `SO_PEERCRED` uid + 對端二進位代碼簽章（Team ID 白名單） | 每連線 X25519 握手 + AEAD 幀（防同機監聽/搶佔 socket，KeePassXC crypto_box 先例 [priorart§2]；纵深防御而非防 MITM） |
| provider extension ↔ daemon | **app group container 內** unix socket（`Group Containers/group.com.bitward/…`，Bitwarden passkey provider 同型 [macos§2]） | 同 group 成員資格 + 簽章 | 同上 |
| Android autofill/CP ↔ core | 同 app 進程內 mpsc channel（**訊息型別與 unix socket 完全相同**，見 §1.4） | n/a | n/a（不出進程） |
| daemon ↔ server | HTTPS（`/connect/token`、`/sync`、`/ciphers` CRUD、`/sends`…）+ notifications WS | 伺服器 TLS + JWT RS256 驗證 [協議§1] | E2EE 語意不變（伺服器只见密文） |
| 遠端 Thin ↔ daemon（P4） | TLS 1.3 + scoped 短期 token（vaultgate/1Password Connect 模式 [priorart§5]） | token（可撤銷）+ 設備綁定 | TLS |

### 1.4 Android 形態（同構，不是例外）

Android 上 AutofillService 與 CredentialProviderService 本来就與主 App 同進程、且必然接觸明文 [priorart§4.1]，進程邊界無安全增益。因此：**core 以 foreground service 形態跑在 App 內，autofill/credential 元件是「同進程的 Thin client」——走同一套 `bw-proto` 訊息型別（mpsc 承載），不另開第二套內部 API**。金鑰由 Keystore（Class 3 biometric-bound）解封裝，只在 core service 記憶體中為解鎖態。Keyguard 已示範全棧可行 [priorart§4.5]；我們與其差異是「協議同構 → 桌面/行動共用 broker、grant、審計、outbox 邏輯」。

---

## 2. 核心型別草圖（偽代碼）

### 2.1 Vault item 模型

```rust
// bw-proto / bw-store。線格式對齊 Bitwarden wire（server 欄位子集），本地欄位獨立命名空間。
pub struct CipherId(pub Uuid);

pub struct VaultItem {
    pub id: CipherId,
    pub account: AccountId,
    pub kind: ItemKind,
    // —— 伺服器权威欄位（以「原樣密文」落盤於 vault.db，解鎖後才存在明文形態）——
    pub name: EncStr,                    // "2.iv|ct|mac" 或舊 "enc(type)|ct|mac"
    pub notes: Option<EncStr>,
    pub login: Option<LoginData>,        // username/password/totp/uris/fido2
    pub card: Option<CardData>,
    pub identity: Option<IdentityData>,
    pub secure_note: Option<SecureNoteData>,
    pub ssh_key: Option<SshKeyData>,
    pub folder_id: Option<FolderId>,
    pub organization_id: Option<OrgId>,
    pub collection_ids: Vec<CollectionId>,
    pub attachments: Vec<AttachmentRef>, // { id, file_name: EncStr, size, key_enc, blob_local: Option<LocalBlob> }
    pub favorite: bool,
    pub reprompt: U2fPrompt,
    pub server_rev: DateTime<Utc>,       // revisionDate：樂觀併發版本
    pub deleted_date: Option<DateTime<Utc>>,
    // —— 本地 overlay（官方 wire 沒有的資料管理缺口，見 [gaps§A.2/3/9]）——
    pub local: LocalOverlay,
}

pub struct LocalOverlay {
    pub tags: Vec<Tag>,                  // tags：FR132/101008，本地先做，伺服器官方上後雙向合併
    pub last_used: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub custom_sort: Option<u32>,
    pub expiry: Option<ExpiryReminder>,  // 到期提醒 FR93914（全型別、可循環）
    pub merged_from: Vec<CipherId>,      // 去重合併 FR648 的溯源
}

/// 明文側包裝：Debug 永遠印 "▓▓▓"、Drop zeroize、未 reveal 不可 serde 序列化。
/// 針對實證：73.5% agent 洩漏來自 debug logging 把 stdout 餵進 context [agent§4]。
pub struct SecretString(Zeroizing<String>);

/// 三個讀取視圖等級——所有讀 API 都強制帶一個：
pub enum View { Metadata, Masked, Reveal }
// Metadata: 只回 id/type/name(解鎖後可解)/uris/folder/tags/dates，不含任何機密欄位
// Masked:   含 username、password 以 "••••12" 尾碼形態
// Reveal:   含 SecretString，必須由 grant 授權，且寫入 audit
```

org/collection 金鑰共享沿用協定既有 RSA+對稱 key 鏈 [協議§1]，封在 `bw-crypto::OrgKeyResolver`，不進模型。

### 2.2 解鎖 / 金鑰生命週期狀態機（只存在於 daemon）

```rust
pub enum VaultState {
    SignedOut,                                   // 無 token
    AuthLocked { token_expiry: Instant },        // 有 access/refresh token + wrapped key 於 Keychain；密文可讀、不可解
    Unlocking { challenge: UnlockKind, cancel: CancelHandle },
    Unlocked { until_idle: Duration, hard_deadline: Instant }, // stretched key 在記憶體
    Stale { reason: KeyDrift },                  // 伺服器 Keys/revision 變動（如別台改主密碼）→ 需 rekey 或強制 Lock
}

pub enum UnlockKind { Password, Biometric, DeviceApproval /* login-with-device/TDE 的 auth-request [協議§1] */, FromWrapped /* 開機後 Keychain 直接解包（未設 biometric 綁定時） */ }
pub enum LockReason { User, VaultTimeoutIdle, VaultTimeoutOnSleep, HardDeadline, RekeyRequired, AdminPolicy }

// 轉換（事件驅動；任何轉換都廣播 ServerMsg::LockStateChanged 給全部訂閱的 Thin client）
//   SignedOut ──login(token 取得)──► AuthLocked
//   AuthLocked ──unlock(challenge)──► Unlocking ──ok──► Unlocked
//   Unlocked  ──idle/hard/sleep/user──► AuthLocked      （撤銷所有 agent session 的 reveal 能力，
//                                                        未過期 token 一併作廢——1Password「App 上鎖即撤銷全部授權」語意 [priorart§1.2]，
//                                                        直接對治 gaps§A.10「桌面↔瀏覽器共享解鎖狀態」）
//   *  ──sync 發現 Key 欄位指紋變動──► Stale ──rekey 成功──► AuthLocked/Unlocked
pub struct VaultTimeoutPolicy { idle: Option<Duration>, on_sleep: bool, hard: Duration /* 預設 12h */ }
```

要點：
- **離線可解鎖**：登入時把「master password hash 驗證器」與 wrapped user key 一併封存（device-bound），之後解鎖不需要連 identity server——修掉「桌面 App 連解鎖都要連網」[gaps§A.8, clients#19055]。
- **一張解鎖態全機共用**：CLI/GUI/extension/MCP 只觀察與觸發狀態機，不各自持有 session。`BW_SESSION` 環境變數概念不存在。
- **API key（client_credentials）登入**：拿 token 不拿解密能力；agent -headless 場景 = daemon 已解鎖時 agent 直接用，未解鎖時依 scope 政策回 `Locked`（要人在場解鎖），這是刻意的安全取捨而非缺口（對應 [gaps§D.2]「API key 不取代主密碼」——我們把它變成明示的狀態機語意）。

### 2.3 Agent session 與 scope/grant 模型（`bw-agent`）

```rust
pub struct Principal {                      // 由 ipc 握手時從 OS 對端憑證構造
    pub exec_path: PathBuf, pub code_sign_id: Option<String>, pub launch_kind: LaunchKind,
}
pub enum SessionKind { Interactive /* GUI/CLI 人 */, Agent /* MCP/CLI 自動化 */, SystemProvider /* macOS extension / Android autofill */ }

pub struct AgentSession {
    pub id: SessionId,                      // 短期、可撤銷；MCP 進程spawn時由 `bitward agent open` 換發
    pub account: AccountId,
    pub principal: Principal,
    pub kind: SessionKind,
    pub scopes: BTreeSet<Scope>,
    pub grants: Vec<Grant>,
    pub policy: ApprovalPolicy,
    pub idle_ttl: Duration,                 // 預設 10min（1Password 同款 [priorart§1.2]）
    pub hard_ttl: Instant,                  // 預設 12h
    pub redaction_set: HashSet<SecretFingerprint>, // 本 session 曾 reveal 的值 → run 輸出 scrub 用
    pub state: SessionState,                // Active | Suspended(vault 鎖) | Revoked(級聯自 §2.2)
}

// Scope 是「能力格」，預設 agent session = {List, Search, ReadMeta}——機密預設不進 LLM context 的型別層保證
pub enum Scope { List, Search, ReadMeta, ReadMasked,
                 RevealField { item: ItemSel, field: SecretField }, // 單欄位、非全域
                 Totp { item: ItemSel },                            // TOTP 出碼≠出 secret（可回 code，獨立 scope）
                 Write, Delete, Move, Share, Send, Sync, AutoType, Run, Admin }
pub enum ItemSel { Id(CipherId), Uri(String), Query(QueryId /* 已存查詢 → item set，逐筆仍要 grant */), All }

pub struct Grant {                            // 使用者（GUI/CLI/生物辨識）核可後才存在
    pub scope: Scope, pub issued_by: SessionId /* 人或 provider */, pub ttl: Duration,
    pub max_uses: Option<u32>,                // reveal 常見: 1 次
    pub approval: Approval,                   // 核可方式的憑證
}
pub enum ApprovalPolicy { PerRevealPrompt, FirstTimeThenRemember(Duration), Biometric, Auto /* 限 ReadMeta 等無機密 scope */ }

// 「use, don't read」執行面（vaultgate / 1Password op run 模式 [agent§2,§3]）：
pub struct RunPlan { pub argv: Vec<String>, pub env_bind: BTreeMap<String, SecretRef>, pub scrub: ScrubPolicy }
pub enum SecretRef { ItemField(CipherId, SecretField), Totp(CipherId) }   // 語法 bitward://<id>/password
pub struct RunOutcome { pub exit: i32, pub stdout: Redacted<Vec<u8>>, pub stderr: Redacted<Vec<u8>>, pub revealed: Vec<(SecretRef, Duration)> }
// daemon spawn 子程、注入環境變數（明文只進子程環境），回傳前把 redaction_set 內所有值從 stdout/stderr 洗掉。

pub struct AuditEvent { pub ts: Instant, pub session: SessionId, pub kind: AuditKind /* Reveal|Totp|Run|Write|Lock|GrantIssued|GrantRevoked|ConflictResolved */, pub item: Option<CipherId>, pub scope: Scope, pub bytes_out: u32 }
// append-only 表；`bitward audit --tail`；prompt injection 事後的可鑑證性來源
```

### 2.4 離線寫入 outbox（`bw-sync`）

```rust
pub enum WriteOp { Create(NewItemDraft), Update(CipherId, FieldPatch), Delete(CipherId /* soft */), Restore(CipherId),
                   Move { item: CipherId, to: Location }, Share { item: CipherId, org: OrgId, collections: Vec<CollectionId> },
                   Unshare(CipherId), AttachUpload { item: CipherId, staged: LocalBlob }, SendCreate(..) }

pub struct OutboxEntry {
    pub seq: u64,                            // 全域單調序：同 item 的意圖按 seq FIFO，保證重放順序
    pub id: OutboxId,
    pub op: WriteOp,
    pub base_rev: DateTime<Utc>,             // 建立意圖時該 item 的伺服器 revisionDate
    pub payload_enc: EncryptedBlob,          // 離線時就用「已解鎖 session 的 user key」先加密好（含 org key），在線 push 不再碰金鑰
    pub staged_files: Vec<LocalBlob>,        // 附件離線上傳佇列（對治 FR4306）
    pub state: OutboxState,                  // Pending | InFlight | Applied{server_rev} | Conflict(ConflictCtx) | Failed{retry_at, attempt}
    pub origin: SessionId,                   // 誰發的（審計 + 衝突時知道該問誰）
}

pub struct ConflictCtx { pub local: DecryptedItem, pub server: DecryptedItem, pub base: DecryptedItem } // 三方
// 合併規則（偽代碼級）：
//   server_rev == base_rev                      → 直接 push
//   否則欄位級 diff(local,base) ∩ diff(server,base) == ∅ → 自動合併（disjoint fields）
//   否則 → 進 Conflict 態，广播 Event::ConflictPending → GUI/CLI「衝突收件匣」人裁 [gaps§A.8 官方只有 read-only 離線，這是超越點]
pub enum Resolution { KeepLocal, KeepServer, MergeFields(FieldPicks), KeepBoth /* 自動另存副本 */ }
```

語意：**寫入永遠成功**（進 outbox 即回 `WriteAck::Queued`），在線時背景 drain，離線時滯留；`Metadata/Masked/Reveal` 讀取永遠走本地庫（本機優先），所以 FR107 的「離線唯讀」在我們這裡是「離線可讀可寫」。

### 2.5 Full↔Thin 協議訊息（`bw-proto`，唯一契約；wire = JSON frames，4 bytes 長度前綴）

```rust
pub struct Envelope { pub v: ProtoVersion, pub req: u64, pub msg: ClientMsg }   // 應答同層

pub enum ClientMsg {
    Hello { client: ClientKind /* Cli|Gui|Mcp|NmShim|Provider|AndroidComp */, proto_range: (u16,u16), token: Option<SessionToken> },
    Status {},                                        // → VaultState 摘要（無任何機密）
    Unlock { kind: UnlockKind },  Lock {},            // 觸發 §2.2 狀態機（Provider session 只能 Lock 不能 Unlock）
    Sync { force: bool },                             // 排隊進單飛佇列，非同步完成 → Event::SyncDone
    List { query: Query, view: View, page: Page },    // 強制 view；Agent session 請求 Reveal 而無 grant → Err(InsufficientScope)
    Get { id: CipherId, view: View },
    Search { text: String, fields: FieldSel, view: View },   // 含「以密碼值搜尋」FR11941（解鎖態下對本地明文索引做）
    Write { op: WriteOp },                            // → OutboxAck（Queued/Applied/Conflict）
    ConflictResolve { id: OutboxId, r: Resolution },
    Totp { id: CipherId },                            // 回 code（8位、30s 窗口）；獨立於 Reveal
    Reveal { id: CipherId, field: SecretField, reason: RevealReason },  // → SecretString；進程即寫 audit
    Run { plan: RunPlan },                            // agent 的「use don't read」
    AutoType { target: FrontmostHint, template: Option<AutoTypeTemplate>, item: CipherId },
    Overlay { id: CipherId, patch: OverlayPatch },    // tags/pin/expiry/自訂排序
    DupReport {}, MergeDryRun { ids: Vec<CipherId> }, BulkMove { ids, to },   // 資料管理缺口
    Subscribe { events: EventFilter },                // 之後 daemon 主動推
    AgentOpen { scopes: BTreeSet<Scope>, ttl: Duration, policy: ApprovalPolicy }, // → SessionToken（給 MCP spawn 用）
    AgentApprove { pending: PendingApprovalId, decision: Decision },               // GUI 答核准弹窗
    AuditTail { n: u32 },
}

pub enum ServerMsg {
    Ready { state: VaultStateSummary, caps: Capabilities },        // Hello 應答；caps 含 server 相容性探測結果
    Ok { seq: u64 },
    ItemsPage { rows: Vec<ItemView>, next: Cursor },               // ItemView 依請求 view 裁剪欄位——**型別上就不可能多給**
    ItemOne { view: ItemView },
    TotpCode { code: String, valid_for: Duration },
    Secret { value: SecretString },
    RunOutput { chunks: Vec<RedactedChunk>, exit: Option<i32> },
    OutboxState { snapshot: Vec<(OutboxId, OutboxState)> },
    AgentSession { token: SessionToken, expires: Instant },
    Error { code: ErrCode /* Locked|InsufficientScope|ApprovalTimeout|ServerIncompat|Conflict|OfflineDenied.. */, retry_at: Option<Instant>, detail: String /* 已 scrub */ },
    // —— 推播 ——
    Event(VaultEvent),
}
pub enum VaultEvent { LockStateChanged(VaultStateSummary), ItemChanged { id, origin: EventOrigin /* Local|Remote|OutboxApplied */ },
                      SyncDone { stats }, OutboxDrained { n }, ConflictPending { id }, ApprovalNeeded { pending: PendingApprovalId, kind, item_hint },
                      GrantRevoked { session }, ServerCompatDowngrade { note } }
```

`ApprovalNeeded` 是 agent reveal 超出政策時的入口：daemon 推給 **GUI/手機**（人的面），agent 的 `Reveal` 請求同步阻塞至核准或逾時——機密要進 LLM context，必須有一個人類進程當中介。

---

## 3. 主要模組公開發 API（介面窄）

```rust
// —— Thin 側唯一Visible介面（CLI/GUI/MCP/extension 全用這一個）——
pub struct DaemonClient;                                     // bw-ipc-client
impl DaemonClient {
    pub fn connect_default() -> Result<Self>;                 // 找 daemon.sock；不存在→ Err(DaemonNotRunning)（CLI 提示 `bitward daemon up`，不自行降格持鑰）
    pub fn request(&self, msg: ClientMsg) -> Result<ServerMsg>;
    pub fn subscribe(&self, f: EventFilter) -> Result<EventStream>;
    pub fn stream(&self, req: ClientMsg) -> Result<ChunkStream>;  // Run/AuditTail 等長回應
}

// —— daemon 內服務介面（bw-core 對外只暴露這五個 trait，全部 ActorCtx = 經握手驗證的 session）——
pub trait UnlockService {                                     // bw-unlock
    fn state(&self) -> VaultState;
    fn unlock(&self, ctx: &ActorCtx, kind: UnlockKind) -> Result<()>;
    fn lock(&self, ctx: &ActorCtx, reason: LockReason) -> ();
    fn set_timeout_policy(&self, p: VaultTimeoutPolicy) -> ();
}
pub trait VaultRead {                                         // bw-index + bw-vault
    fn list(&self, ctx: &ActorCtx, q: Query, view: View, page: Page) -> Result<(Vec<ItemView>, Cursor)>;
    fn get(&self, ctx: &ActorCtx, id: CipherId, view: View) -> Result<ItemView>;
    fn search(&self, ctx: &ActorCtx, s: SearchQuery, view: View) -> Result<Vec<Hit>>;
    fn duplicates(&self, ctx: &ActorCtx) -> Result<Vec<DupCluster>>;      // 解密比對在 daemon 內做，回叢集不含明文
    fn merge_preview(&self, ctx: &ActorCtx, ids: &[CipherId]) -> Result<MergePlan>;
}
pub trait VaultWrite {                                        // bw-vault → bw-sync::outbox
    fn write(&self, ctx: &ActorCtx, op: WriteOp) -> Result<WriteAck>;     // 離線一律 Queued
    fn resolve_conflict(&self, ctx: &ActorCtx, id: OutboxId, r: Resolution) -> Result<()>;
    fn drain_outbox(&self, ctx: &ActorCtx) -> Result<DrainReport>;
}
pub trait AgentBroker {                                       // bw-agent
    fn open_session(&self, ctx: &ActorCtx, req: SessionRequest) -> Result<AgentSession>;   // 人類 session 才能開 agent session
    fn reveal(&self, sess: &AgentSession, id: CipherId, field: SecretField) -> Result<Approved<SecretString>>; // Approved = 已過政策/核准鏈的憑證型別
    fn totp(&self, sess: &AgentSession, id: CipherId) -> Result<Approved<TotpCode>>;
    fn run(&self, sess: &mut AgentSession, plan: RunPlan) -> Result<RunHandle>;
    fn revoke(&self, sess: SessionId, cascade: bool) -> ();    // vault lock 內部走同一條
    fn audit(&self, q: AuditQuery) -> Result<Vec<AuditEvent>>;
}
pub trait ServerApi {                                         // bw-server（唯一碰外部 HTTP 的地方）
    async fn token(&self, grant: Grant_) -> Result<TokenBundle /* + Keys 寬容解析 */>;
    async fn sync_full(&self) -> Result<SyncResponse /* 欄位寬容反序列化 */>;
    async fn put_cipher(&self, id, body: &EncryptedWire) -> Result<ServerRev>;
    async fn probe_compat(&self) -> Result<ServerFlavor /* BitwardenCloud|Vaultwarden(版本)|Unknown, 能力位 */>;
    async fn auth_request(&self, ..) -> Result<..>;            // login-with-device / TDE
}
pub trait AutoTypeEngine {                                    // bw-autotype（macOS 實作 = CGEvent；平台 trait）
    fn type_item(&self, sess: &ActorCtx, id: CipherId, tpl: AutoTypeTemplate, into: Frontmost) -> Result<TypeReport>; // 完成即擦（剪貼簿不留痕，治 clients#2621/#2742）
}
```

介面紀律：`View` 參數在讀取簽名上**不可省略**；回傳型別 `ItemView` 依 view 構造，`Reveal` 欄位在 `Metadata` 構造下為 `None` 且無 Debug——「機密不進 context」是編譯期+序列化期的雙重預設，不是呼叫紀律。

---

## 4. 五個優先缺口 → 模組 → 階段映射

優先序照使用者拍板順序。階段定義見 §5.0。

| # | 缺口（證據） | 負責模組 | 交付階段 | 交付內容 |
|---|---|---|---|---|
| 1 | **自動化缺口**：無 daemon/事件流、BW_SESSION 手管、MCP 薄殼把明文丟進 context、無 scope/audit [gaps§D, agent§1,§5] | `bw-agent` + `bw-mcp` + `bw-ipc`（推播事件） | **P1 基礎**：daemon 常駐共享解鎖、`AgentOpen`/`Reveal`+audit。**P2 完整**：MCP 工具面（metadata-only 預設、per-reveal 核准、`Run` 注入+scrub、TTL token、`VaultEvent` 訂閱取代輪詢） | 官方 MCP 五痛點（手動 session、全 vault 無分層、明文進 context、無 audit、無事件流）逐一有歸屬模組 |
| 2 | **資料管理缺口**：tags FR132、排序 FR2484、去重合併 FR648、unshare FR604/批次搬移 FR14489、值搜尋 FR11941、到期提醒 FR93914 [gaps§A] | `bw-index`（overlay 表 + FTS）+ `bw-vault`（dedup/merge/bulk） | **P2**：tags/自訂排序/last_used overlay、fuzzy+值搜尋。**P3**：dedup 報表、MergePlan（含欄位級合併、merged_from 溯源）、BulkMove/Unshare（走 outbox，離線可用） | overlay 是本地權威、官方 tags 上路後雙向同步（`LocalOverlay` 型別已預留合併語意） |
| 3 | **auto-type 與共享解鎖狀態**：FR158/93873（719 讚十年未解）、FR1635/Roadmap 101009 [gaps§A.1,§A.10] | 共享解鎖＝`bw-unlock` 狀態機 + `VaultEvent::LockStateChanged` 廣播（**P1 即獲得**，daemon 架構的紅利）；auto-type＝`bw-autotype` | **P1**：共享解鎖。**P3**：macOS CGEvent 引擎（含剪貼簿不留痕）、`AutoType` 協議訊息讓 CLI/MCP 也能觸發；瀏覽器經 `bw-nm-shim` 同 socket 共用解鎖態 | 官方「桌面↔CLI 解鎖完全不相通」(clients#22773) 在此是同一狀態機的兩個訂閱者 |
| 4 | **離線可寫入**：FR107（官方明載離線僅唯讀）、#19055 離線解鎖 [gaps§A.8] | `bw-sync::outbox` + `bw-store` + 離線解鎖封裝（§2.2） | **P1**：離線解鎖+離線讀。**P2**：outbox 全型別寫入 + 三方合併 + 衝突收件匣。**P3**：附件離線上傳佇列 | 寫入 API 從 P2 起就**不設計成可失敗**（Queued 語意），離線不是特殊路徑而是預設路徑 |
| 5 | **macOS 系統級密碼支援**：官方無 password provider（FR93723 open）、1Password 2026-10 GA 證明可行 [macos§2,§3, gaps§C] | `macos-provider`（extension target，thin）+ daemon 端 `ProviderFastPath`（List 依 domain 回 credential + `Reveal` 單次放行）+ `ASCredentialIdentityStore` 維護者（在 daemon 內） | **P3 骨架**：passkey assertion 路徑（對齊官方 beta 架構 [macos§3]）。**P4**：passwords（macOS 14+）與 OTP（macOS 15+）provider；核准走 extension→daemon→GUI/Touch ID 鏈 | 刻意選 **thin** 而非 grounding 報告建議的混合式（fat fast-path）：extension 內解密需要把金鑰下放給第二個進程，直接抵觸 §0 全域決策；代價（daemon 必常在）用 LaunchAgent + 秒級冷啟吸收，見 §6-R3 |

非目標（本設計包明確排除）：重寫官方瀏覽器擴充的相容層（用我們自己的 extension 走 NM shim）、Secrets Manager、Linux（結構預留 `AutoTypeEngine`/keystore platform trait，但初期不交付）。

---

## 5. 里程碑與第一個可獨立驗證的增量

### 5.0 階段劃分

- **P0** 倉庫骨架：workspace、`bw-proto` 定稿（含 conformance vectors 檔）、CI（Vaultwarden 版本矩陣、macOS+Linux test runner、Android compile-only）。
- **P1 「read-path daemon」**← **第一個可獨立驗證的增量**（詳下）。
- **P2 寫路徑+agent 面**：outbox+三方合併、衝突收件匣、tags/搜尋、MCP 完整工具面（approval、Run/scrub）、事件訂閱給 agent。
- **P3 系統整合**：auto-type、provider passkey 骨架、附件離線、dedup/merge/bulk。
- **P4 平台擴張**：passwords/OTP provider（macOS 14/15）、Android 全棧（同一 core via UniFFI + autofill/CP 元件）、遠端 thin（TLS+token）、多帳號。

### 5.1 增量 I1（P1）：「解鎖的只讀中樞」

範圍：`bitward login`（email+master password+TOTP 2FA；走 `/connect/token`，Keys 寬容解析）→ daemon 派生並封存金鑰（Keychain wrapped）→ 全量 `/sync` 落 `vault.db`（密文原樣）→ 狀態機 + vault timeout → unix socket 協議 + 對端驗證 → CLI `status/list/search/get/reveal/audit/lock`。不含：任何寫入、MCP、tags、autotype、extension。

**能跑什麼命令**（全部對本機 Vaultwarden，`docker compose -f dev/vaultwarden.yml up`）：

```console
$ bitward login --server http://localhost:8080 --email demo@x.io        # 互動收主密碼（pinentry 式，不回顯）
$ bitward status                                    # → { state: "unlocked", accounts: 1, items: 143, outbox: 0 }
$ (新終端機) bitward list --json | jq '.[0]'        # ← 無需任何 env var：共享解鎖證明（官方痛點 #19839 的直接反例）
$ bitward search github --view metadata --json      # 輸出欄位中不存在 password/secret/token（見自動化斷言）
$ bitward reveal 0f0d…c1 password --once            # 印一次明文 + 落 audit
$ bitward audit --tail 5                            # 兩筆 reveal 嘗試（含 --once 後第二次 → InsufficientScope）
$ bitward lock && bitward list                      # → error: locked（且既有 agent token 級聯失效）
```

**過什麼測試**：
1. `cargo nextest run -p bw-crypto` — KAT：以官方 clients 的 jest crypto fixtures（GPL 參考、僅作測試資料）比對 PBKDF2/Argon2id 派生、master hash 兩層、stretched key、`2.iv|ct|mac` round-trip；含 600k 預設與 Argon2id 參數組。
2. `cargo nextest run -p bw-server --test compat_fixtures` — 錄製的 `/sync` JSON 回放（官方雲 + Vaultwarden 1.37.x 兩份）；**回歸測試「UserDecryptionOptions 缺失」fixture**（vaultwarden#6729 教訓）必須登入成功並降級。
3. `cargo nextest run -p bw-proto -p bw-ipc --test conformance` — 記憶體 transport 上跑協議向量檔：list 的 `Metadata` 回應**結構上不含**機密欄位、reveal 無 grant → `InsufficientScope`、lock → session 級聯 revoked。
4. `dev/e2e/readpath.sh`（CI 內 against pinned Vaultwarden）— 上面命令列腳本化；其中斷言 `bitward list --json | jq 'tostring' | grep -c "$KNOWN_PASSWORD"` == 0（**機密預設不進輸出**，這條就是本專案主軸的可執行定義）與 SecretString 的 Debug 不洩漏單元測試。
5. 手動驗收（macOS）：`launchctl print gui/$UID/com.bitward.daemon` 顯示 KeepAlive 註冊成功；kill daemon 進程後 5 秒內自動重生並保留解鎖態（stretched key 從 Keychain 重包，不重跑 KDF）。

I1 為什麼是「正確的第一刀」：它同時驗證本設計三個最大賭注——(a) 自寫 crypto 對官方資料真的解得開；(b) daemon-hub 的共享解鎖真的消灭了 BW_SESSION 痛點；(c) View 型別層真的擋得住明文外洩。三者任一失敗都能在不到一個月的工程量內推翻並退到 §6 的替代結構。

---

## 6. Rationale：考慮過並拒絕的替代結構

**R1（完整替代形態）· Fat library / 每進程自理**：把 core 做成函式庫，CLI、GUI、extension 各自內嵌、各自 login+unlock+sync（官方 CLI 與 rbw 無 agent 模式的形態 [agent§5, priorart§5]）。拒絕：①「共享解鎖狀態」（缺口 #3）結構性不可能——N 個進程 N 份解鎖態與 N 個 vault timeout；② N 個 sync 寫入者 → outbox/衝突合併要跨進程協調，等於在沒有 daemon 的前提下重發明明；③ Argon2id/PBKDF2 600k 成本 × 每進程每次冷啟；④ 無單一審計點，agent 治理（缺口 #1 的 scope/audit）無處安放；⑤ macOS extension 記憶體上限使 in-extension 重派生金鑰是真實痛點（Bitwarden iOS 自家都要設 Argon2 門檻警告 [macos§1]）。

**R2（完整替代形態）· 下放鑰 hub（Bitwarden desktop_proxy / 1Password X 式）**：daemon 仍在，但把解鎖後的金鑰下放給Thin client 自行解密 [priorart§3]。拒絕：與主軸正面衝突——MCP 進程拿到 user key 等於 prompt-injected agent 一次工具呼叫就能Dump 整個 vault，「機密預設不進 context」退化為行為約定的修飾（官方 MCP 被罵的就是這個 [agent§1]）；1Password 自己在 App↔CLI 鏈上選了**不下放鑰**並換來「上鎖即撤銷」的治理性 [priorart§1.2]，這是業界兩條路線中符合本專案缺口優先序的那條。代價（Thin 側每次讀取過 IPC 一跳）用常駐 daemon + 本地明文索引吸收：過 socket 的是結果，不是金鑰，往返是 O(1) 微秒級。

**R3 · 混合式 extension（fat fast-path）**：grounding 報告建議 macOS provider 走「identity store + extension 內 biometric keychain 快速解密」混合式 [macos§4/§6]。拒絕並**接受其指出的代價**：thin extension 讓「daemon 常駐」成硬依賴（1Password 的 "Failed to connect to 1Password.app" 是前車）。制衡手段全部在 daemon 側：SMAppService KeepAlive、秒級重生（§5.1 驗收 5）、`SystemProvider` session 型別享有「vault 已解鎖時零 UI 往返」快路徑。選擇一致性：金鑰唯一持有者的承諾如果在 extension 上開洞，§2.3 的 grant/redaction/audit 模型就要在第二個進程重寫一份——那才是真正會腐化的地方。若 P4 實測冷啟延遲不可接受，**升級路徑是給 daemon 本體加快速路徑，不是把金鑰搬進 extension**。

**R4 · GUI-as-hub**：不另立 daemon 二進位，把核心跑在桌面 App 內（官方桌面 + 官方 CLI IPC 框架的形態 [priorart§3]）。拒絕：headless 機器（SSH 進去的伺服器、CI）是自動化缺口的核心場景，GUI 進程在那裡無法存在；GUI crash/重啟（渲染層意外）會連坐 autofill、agent、outbox drain；「CLI 掛在桌面 IPC 上」正是官方 `bw serve` 跑幾小時就壞的教訓變體 [agent§5]。我們反其道：daemon 是無 GUI 依賴的最小二進位，GUI 掉線不影响任何服務。

**R5 · CRDT / 事件日誌 local-first（server 降為鏡像）**：全域以本地事件流為權威、背景同步到 Bitwarden server。拒絕：其他 Bitwarden 用戶（官方 app、同事共用 org 的裝置）不遵守我們的 CRDT，server 才是跨客戶端權威；單人多裝置的衝突率與 [macos/priorart] 所示的 revisionDate 三方合併已足夠，CRDT 的向量時鐘/墓碑語意是永久雙存儲遷移負擔。保留其精神的極小子集：outbox 本身就是 append-only 意圖日誌（seq + 重放），這已支撐離線寫入與審計重建，不需要更貴的代數結構。

**R6 · 直接採用官方 sdk-internal（Rust）加速**：授權 §3.1 禁止對第三方出貨、§3.3 禁止用於 non-compatible 實作（Vaultwarden）[協議§2]，而 Vaultwarden 是一級目標——法律上不可行，非工程偏好。

### 6.1 選定結構的已知弱點（誠實列）
- daemon 是單點：用 KeepAlive + 狀態全部落盤（token/wrapped key/outbox）把重生做成常態；審計與 outbox 使崩潰後可重建因果。
- 本地明文索引在解鎖態下存在進程記憶體/加密表：威脅模型與「筆電已被 root 攻擊」同階（1Password 明示接受同類風險 [priorart§1.2]），不另加戲劇性防衛。
- 協議無官方 spec 可對齊，只能自我版本化：`ProtoVersion` + conformance vectors 進倉庫，Thin/Full 同 repo 演進（跨機遠端 P4 才面對版本漂移，屆時用 caps 協商）。

——完——
