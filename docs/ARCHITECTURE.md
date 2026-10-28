# bitward 架構設計（綜合版）

日期：2026-10-29。本檔是實作契約，由兩個獨立設計候選綜合而成（過程見 §9），證據來源見 `docs/research/`，兩份原始設計包保留於 `docs/design/` 當附錄。型別與簽名皆為偽代碼層級。

**一句話。** 每個裝置跑自己的中樞（`bitwarderd`；Android 是 app 內的 in-process 中樞）：裝置內，它是唯一持鑰者、唯一 sync 寫入者、唯一審計點；裝置間，多個中樞對等，靠伺服器收斂。其餘介面（CLI、GUI、macOS credential provider extension、MCP shim、瀏覽器 shim）都是 thin client，對自己裝置的中樞講同一份協議（BTP）。金鑰永不下放，agent 預設只用不讀，明文只活在受保護的記憶體區。

## 0. 決策摘要

| 決策 | 內容 | 依據 |
|---|---|---|
| 形態 | 每裝置一個中樞（hub），裝置間多中樞對等、經伺服器收斂；金鑰不下放 | 1Password App↔CLI（不下放鑰）、rbw-agent、KeePassXC、Bitwarden passkey provider 五個獨立實作收斂到同一形態（`research/prior-art.md`、`research/macos-provider.md`）；多 Full client 是操作者決定（2026-10-29） |
| 授權 | 全 repo GPL-3.0-or-later；自寫 crypto，不鏈接官方 SDK | `LICENSE_SDK.txt` §3.1 禁止對第三方出貨、§3.3 禁止連 Vaultwarden（`research/protocol.md` §2） |
| 語言 | 核心 Rust；macOS SwiftUI、Android Compose 原生 UI；bindings 由協議 schema 產生 | 官方 CLI Node 啟動 1–5s（clients#2741）；Zeroize 語意；UniFFI 為現成模式 |
| 伺服器 | Bitwarden Cloud 與 Vaultwarden 皆一級目標；欄位寬容 + raw mirror | client API 無官方 spec；vaultwarden#6729 漂移事故 |
| 隱私主軸 | 機密預設不進 LLM context；metadata-only + 單一受審計 reveal + 執行期注入出口淨化 | arXiv 2604.03070（73.5% 洩漏經 stdout、89.6% 立即可利用）；官方 MCP 反彈（`research/agent-ecosystem.md`） |
| 記憶體保護 | 明文只存在 mlock、MADV_DONTDUMP 的專用 arena，drop 即清零；不可變字串不跨 FFI；argv/env 無密碼（操作者要求 2026-10-29） | Keyguard 的 memfd_secret/kernel keyring 先例（`research/prior-art.md` §4.5）；1Password 同級風險取捨 |
| 安裝形態 | Full/Thin 以執行體劃分。thin client 可獨立安裝，但**不自動 provision 本機中樞**：可用性＝配對的中樞在線（同機由 Full 套件註冊，異機走配對＋推播喚醒）。中樞關閉時快速失敗 | 操作者決定 2026-10-29 |
| 名稱 | 工作名 `bitward`，文件一律寫「Bitwarden-compatible client」，出貨前查商標 | Bitwarden Trademark Guidelines |

### 0.1 技術線（逐 concern 選定）

| Concern | 選定 | 備註 |
|---|---|---|
| 核心語言 | Rust（stable，tokio 非同步 runtime） | 一顆核心複用：daemon、CLI、MCP shim、crypto、sync；Android 經 NSH Rust app 形態同檔打包（`libnsh.so` 含本 crate），UniFFI/JNI 只留給 Kotlin 孤島 |
| 加密原語 | rustcrypto 系：`pbkdf2`、`argon2`、`aes`+`hmac`（信封 type 2）、`hkdf`、`rsa`、`sha2`、`rand_core` | 信封/KDF 編排**自寫**（授權），底層算子用 MIT/Apache crate，組合為 GPL 著作沒有障礙 |
| 傳輸加密 | per-conn：`x25519-dalek` + `chacha20poly1305`；跨機：`rustls`（TLS1.3）+ 上層再疊一層 | KeePassXC crypto_box 教訓：不單信通道 |
| 序列化 | BTP wire 用 `postcard`（除錯模式走 JSON）；型別 schema 產生 Rust/Swift/Kotlin bindings，**只服務平台孤島**（provider extension、autofill 外殼）；UI 與核心同為 Rust，不需要綁定層 | thin 端零業務邏輯的結構保證 |
| 本地儲存 | SQLite（WAL，`rusqlite`）+ FTS5 索引；附件 content-addressed blob | 檔權限 0600；鏡像存密文原樣 |
| 金鑰封存 | macOS `security-framework`（Keychain biometric ACL）；Android Keystore Class 3/StrongBox（JNI） | §1 落盤形態 |
| 記憶體 | `zeroize` + 自寫 secret arena（`mlock`、`MADV_DONTDUMP`、Linux `memfd_secret`） | §2.7 |
| UI 框架 | **NSH（Native Shell，longbridge/nsh，Apache-2.0）**，Rust 元件一套碼覆蓋 macOS／Android／Linux／Web；後端是各平台原生 view（AppKit、Android views），不是自繪 | 見 §0.2。v0.2.x 新專案：鎖版本、UI 純介面零業務邏輯，框架抖動波及面只到 view 層 |
| macOS | NSH GUI（AppKit 後端）；provider extension 為 Swift + XPC 孤島（MachServices 按需啟動）；常駐 `SMAppService`；auto-type CGEvent | 簽章/公證走 Developer ID |
| Android | NSH UI（Android views 後端）+ Kotlin 整合孤島：`AutofillService`、`androidx.credentials`（API 34）、Keystore、UnifiedPush distributor 接單；foreground service 跑 in-process 中樞 | Keyguard 全棧先例 |
| 推播 | Android：**UnifiedPush 第一級**（`unifiedpush` crate，distributor：ntfy/Cone/…，FCM 僅可選 fallback）；macOS：APNs（官方雲）或 Vaultwarden web-push/VAPID（自架） | §1.2 推播路徑；只傳信令不傳明文；endpoint 按能力憑證處理 |
| CLI／MCP | `clap`；MCP 用 `rmcp`（Rust SDK），shim 只做 MCP↔BTP 轉譯 | shim 不含政策邏輯 |
| 可觀察性 | `tracing`，secret 出口經 Redactor 層 | 日誌零明文由 A8 守 |
| 測試 | `cargo nextest` + `proptest`（raw mirror 無損往返）+ 錄製 fixtures + docker Vaultwarden 釘版矩陣 + macOS runner + Android compile-only | A1..A12 |
| 打包 | macOS `.pkg`（公證）、Android AAB、Linux tarball + systemd user unit、後續 brew tap | `cargo deny` 守授權 |
| 授權 | GPL-3.0-or-later 全 repo | §0 授權列 |

### 0.2 NSH 採用評估（操作者提問 2026-10-29）

[NSH（Native Shell）](https://nsh.dev) 是 longbridge/nsh 的 Rust-first 原生 UI 框架：元件、signals、樣式一套碼，各平台用**自己的原生 view** 渲染（macOS 是 AppKit、Android 是 Android views、Web 是 HTML），Apache-2.0，v0.2.x（2026-10 docs.rs 首發約一週），macOS 14+、Android API 28+。與本專案的適配判斷：

- **省掉什麼**：SwiftUI 與 Compose 兩套 UI 碼、UI 層的 UniFFI/Swift 綁定生成、§2.7 最煩的一條（明文經 Swift `String`/Kotlin `String` 不可變拷貝）在 UI 路徑上直接消失，因為 UI 與核心同進程同語言。粗估 GUI 開發成本從兩套半（mac+android+bindings）降到一套 [推測：待 P1 後以真實畫面遷移校準]。
- **不省什麼**：平台整合孤島照樣要原生碼，NSH 幫不上也不擋路。macOS provider extension（AuthenticationServices/Swift）、Android `AutofillService`/`CredentialProviderService`/Keystore/FCM（Kotlin）、XPC。這些在本設計裡本來就是薄面。
- **新增紀律**：TSX 執行在 QuickJS，JS 字串不可變、不可清零 → **明文欄位只允許在 Rust 元件渲染；TSX/動態交付畫面最多拿 Masked**。副作用是正面的：AI 生成或動態下發的畫面天然看不見明文（§2.7 規則 6）。
- **風險與隔離**：v0.2.x 很年輕，API 會抖。緩衝有三層：UI 純介面零業務邏輯（不變量 5）、鎖版本 + 必要時 vendor 補丁（操作者已有 gpui-kit vendor-rebase 的同型經驗）、NSH 與本專案同走 GPUI 系生態（README 致謝 GPUI/GPUI Kit），語彙相近。
- **裁決**：採用為 GUI 層框架，macOS 與 Android 共用。P0 期間以 provider 設定頁 + vault 列表兩個真實畫面做 spike 驗證渲染品質與打包鏈，再全棧押上。

## 1. 進程拓撲

| 進程 | 生命週期 | 角色 | 持長期金鑰 |
|---|---|---|---|
| `bitwarderd` | 常駐，**每裝置一個**（macOS LaunchAgent/SMAppService KeepAlive；Linux systemd user；Android 為 app 內 in-process 等位物，foreground service） | 本裝置的金鑰狀態機、sync+outbox、agent 治理、審計、identity store 維護、auto-type 排程 | 本裝置唯一持有者 |
| `bitward`（CLI） | 一次性短命 | 人與腳本介面；無本機中樞時走已配對的遠端中樞，或給明確指令提示（註冊是中樞擁有者的權責，見 §1.2），永不自行降格持鑰 | 否 |
| `bitward-mcp` | 由 agent host spawn，stdio | MCP ↔ BTP 轉譯，唯一對 LLM 說話的進程 | 否（持 scoped session token） |
| `Bitward.app`（macOS GUI） | 可開可關，關閉不影響服務 | 瀏覽/編輯、enrollment 與衝突核准 UI、TCC 入口、審計瀏覽 | 否 |
| `BitwardProvider.appex` | 系統按需啟動、隨時回收 | passwords（macOS 14+）、passkeys、OTP（15+）、text-to-insert | 否 |
| Android app | **Full（預設：in-process 中樞，foreground service）**或 Thin（TLS 配對連遠端中樞） | AutofillService / CredentialProviderService(API 34) / inline IME | Full 時是（Keystore Class 3） |
| `bitward-nm` | 瀏覽器按需 spawn | native messaging ↔ BTP 純管道，無邏輯無金鑰 | 否 |

明確不存在：第二個 sync 客戶端、GUI 內嵌的第二份金鑰、獨立的 HTTP 服務層（HTTP/TLS 只是 BTP 的一種 transport binding）。

金鑰落盤形態：`vault.db` 存伺服器原樣密文（`2.iv|ct|mac` 不改寫）；user key 以 OS 級封存（macOS Keychain biometric ACL、Android Keystore Class 3-bound/StrongBox）；重啟 daemon 用封存金鑰直接解包，**不重跑 KDF**（冷啟秒級，graft 自候選二）。master password 只在解鎖瞬間存在，無任何常駐環境變數（`BW_SESSION` 概念不存在）。

### 1.1 多中樞拓撲（多個 Full client）

Full client = 中樞 = 持鑰者 + sync 寫入者 + 該裝置 agent 治理域。一台裝置一個，跨裝置 N 個對等。Android app 預設就是 Full（in-process 中樞），不依附桌面在不在；macOS/Linux 的 daemon 同為各裝置的中樞。

- **收斂點是伺服器。** Bitwarden 語意裡 server 就是跨客戶端權威（官方 app 們本來就是多寫者），中樞之間不做 P2P。notifications hub WS 的事件帶 cipherId → 收到就 targeted `GET /ciphers/{id}` 單筆拉（端點缺或不可用才降回全量 sync），把衝突窗口縮到最小。
- **合併是一級機制，不是離線備援。** 多裝置改同一 item：`base_rev` 比對 → 欄位不相交自動 3-way merge；相交 → 衝突收件匣。離線寫入與跨裝置併發共用同一條 outbox、同一個佇列、同一套裁決。
- **治理域是 per-device。** session/grant/`LockEpoch` 只約束本裝置的中樞與其 spokes。桌面鎖定不會鎖手機（金鑰在各自安全硬體），這正是正確的安全語意：FR 1635「共享解鎖狀態」的範圍是裝置內。跨裝置共享解鎖＝remote thin 配對（P6），不是預設。
- **共享寫入目標的結構化序列化。** 裝置內：消除共享（單寫者中樞，不變量 11）。裝置間：共享目標是伺服器 vault，消除不了 → 用 `base_rev` 樂觀併發（CAS 語意）+ outbox `seq` FIFO 結構化序列化，不靠約定。
- **金鑰輪播傳播：** 他台改主密碼 → 本裝置 sync 發現 Keys 指紋變動 → `Stale` → 要求重新解鎖（§2.2）。
- **TDE 審批：** 任何 Full 都能當批准裝置（auth-request answer），手機批桌面登入與官方行為同構。
- **Thin Android 保留**為配對模式：手機純當批准/輸入面、讀寫全部代理給桌面中樞。建立時選模式，資料模型與協議訊息完全相同（§2.5 同構規則）。

### 1.2 安裝形態與可用性（thin client 獨立安裝）

Full/Thin 的分界在執行體，不在套件。中樞（持鑰 runtime）與 GUI（介面）解耦。**thin surface 從不自動落地一個本機中樞**：它的可用性定義就是「它連的中樞在線」（操作者裁決 2026-10-29）。

| 安裝包 | 內容 | 場景 |
|---|---|---|
| `bitward`（Full 套件） | 中樞 + GUI（註冊常駐服務的是它） | 主力裝置 |
| `bitwardd`（headless Full） | 只有中樞，刻意安裝、刻意註冊 systemd user/LaunchAgent | Linux 伺服器、CI、無 GUI 機器 |
| `bitward-surface`（單一介面） | 純 thin：CLI、provider extension、MCP shim、瀏覽器 NM shim 各自成包，**不註冊任何東西** | 只要 autofill 或只要 agent 面的裝置 |

surface 的兩條連線路徑（協議同構，BTP 訊息不變）：

1. **同機中樞**：中樞由 Full 套件註冊（macOS `SMAppService`/LaunchAgent；provider extension 另可由 `MachServices` 按需拉起）。surface 單獨存在時中樞不在，CLI 給明確指令提示，extension 走 `.userInteractionRequired`；surface 永不自行降格持鑰。
2. **異機配對 + 推播喚醒**：`bitward pair` 顯示 QR/9 位配對碼，Full 端掃描確認 → 該裝置拿到綁定 `DeviceId` 的短期 token + 獨立 grant 集，走 TLS1.3 + per-conn AEAD。典型場景：伺服器上的 coding agent（`bitward-mcp`）配對回你的桌面或手機中樞；共用電腦上的瀏覽器 extension 連回自己裝置。這是 vaultgate/1Password Connect 已驗證的「一台持鑰、多台取用」形態。

**推播路徑**（異機場景的第二條線，操作者要求 2026-10-29）：Android **以 UnifiedPush 為第一級**（open standard，distributor 走 ntfy/Cone 等，Rust 端用 `unifiedpush` crate；FCM 降為有 GMS 裝置的可選便利，去 Google 化裝置 CalyxOS/GrapheneOS 原生可用），macOS 走 APNs（官方雲）或 Vaultwarden 的 web-push/VAPID（自架）。推播承載兩類訊息：

- **核准訊息**：agent 的 reveal/寫入超出預授政策 → 推到人機（手機或桌面通知），解鎖狀態下一鍵批准；approval 帶 TTL，過期 agent 收 `ApprovalExpired`。這把 §2.3 的 human-in-the-loop 從「GUI 開著才有效」升級為「手機在口袋裡就有效」。
- **喚醒訊息**：thin 的連線請求送達時中樞被系統掛起 → thin 直接 `POST` 中樞的 push endpoint（配對時交換的登記資料，UnifiedPush 規範允許匿名寫入 endpoint）→ distributor 喚醒中樞背景任務重新接單。Android foreground service 喚醒可靠；macOS APNs 喚醒是 best-effort（[推測：受 App Nap 與省電策略制約，P5 實測]）。
- **endpoint 即能力憑證**：知道 endpoint 就能推，所以 push endpoint 按機密處理：只存在配對元資料與中樞本地（secret arena 旁路，非明文欄位但其洩漏面＝垃圾訊息＋喚醒時序），不進日誌、不進 event payload，可在 App 內一鍵輪換（re-register distributor）。推播內容只放不透明信令（ticket id/epoch），載體一律經中樞拉取；distributor 伺服器（如 ntfy.sh）看得到 endpoint 與訊息字節數，全隱私取向預設建議自架 distributor。
- **失敗語意**：喚醒不成或中樞離線，thin 請求快速失敗 `HubOffline{last_seen}`，收到 `HubOnline` 事件後自動重試一次。**機密操作不排隊後補**：幾小時後用戶意外觸發的 reveal 是驚喜不是功能；只有 approval 請求可滯留，且帶 TTL 過期。推播同時補上官方生態的洞：Bitwarden Cloud 推播綁封閉 relay，Vaultwarden 自建 WS 通知（`research/feature-gaps.md` §E）。

安全語意：遠端 surface 掛掉或被入侵，洩漏面是 token + 該裝置 grant 集，不是金鑰；撤銷在 Full 端一鍵（`revoke device`），鎖世代級聯照常適用。推播只當「有請求等你」的信令，載體經中樞拉取，明文與密文憑證都不上推播通道。

## 2. 核心型別（偽代碼）

### 2.1 Item 模型與敏感度

```rust
pub enum Prot<T> { Enc(CipherString), Dec(T) }   // Debug/serde 預設 REDACTED

pub struct Item {
    pub id: ItemId, pub kind: ItemKind, pub owner: Owner,
    pub name: Prot<String>, pub login: Option<Login>,
    pub card: Option<Card>, pub identity: Option<Identity>,
    pub notes: Option<Prot<String>>, pub fields: Vec<Field>,
    pub attachments: Vec<AttachmentMeta>,
    pub revision: ServerRev,
    pub raw: RawEnvelope,            // 伺服器原始 JSON＝未建模欄位的真相源
    pub local: LocalOverlay,         // tags/usage/pinned/expiry/dup_group（協定無這些欄位）
    pub sync_state: MirrorState,     // Mirrored | Tombstoned | LocalOnly(draft)
    pub pending: Option<MutationId>,
}

/// grant、patch、SecretRef、audit 共用的唯一座標系
pub enum FieldPath { Name, Notes, Username, Password, Totp, Uri(u32),
                     FieldName(FieldId), FieldValue(FieldId), CardNumber, CardCode, /* ... */ }

/// 靜態分級，純函數，無配置
pub enum Sensitivity { Opaque,   // id/kind/owner/dates → 任何 session 可見
                       Identity, // name/uris/folder/tags/favorite → agent 默認可見
                       Secret }  // password/totp seed/notes/hidden fields/附件內容 → 需 grant
pub fn sensitivity_of(p: &FieldPath) -> Sensitivity;

/// 唯一的「能看到什麼」函數：CLI/GUI/MCP/extension 不可能各自發明可見性規則
pub fn project(item: &Item, floor: SensitivityFloor, unlocked: bool) -> ViewItem;
```

讀取簽名一律強制帶 `View`（`Metadata | Masked | Reveal`，graft 自候選二）：回傳型別依 view 構造，`Metadata` 下機密欄位在型別上不存在。

### 2.2 解鎖狀態機（只存在於 daemon）

```rust
pub struct LockEpoch(pub u64);   // 單調遞增的全域鎖世代

pub enum VaultState {
    SignedOut,
    AuthLocked  { has_mirror: bool },                      // token+wrapped key 在，密文可讀不可解
    Unlocking   { challenge: UnlockChallenge, deadline: Instant },
    Unlocked    { keys: KeyBundle, epoch: LockEpoch,
                  deadline: Option<Instant> },             // vault timeout
    Stale       { why: KeyDrift },                         // 伺服器 Keys 指紋變動（別台改主密碼）→ 強制 relock/rekey
}
pub enum UnlockMaterial { MasterPassword(SecretString), DeviceAssertion,   // Keychain/Keystore 解包，不需網路 → 離線可解鎖
                          AuthRequest /* login-with-device / TDE */, SessionKeyInterop /* Key Connector 例外 */ }
pub enum LockReason { User, Timeout, ServerLogout, KeyRotation, Revoked { by }, Startup }
```

轉移規則（任何轉換都廣播 `LockStateChanged` 給訂閱的 thin client）：

| 事件 | 結果 | 不變量 |
|---|---|---|
| `unlock(material)` | Unlocking → Unlocked，`epoch++` | 重複 unlock 冪等，不互毀 session（治 clients#6898） |
| `lock(reason)` / timeout | → AuthLocked，`epoch++` | 級聯撤銷全部 agent session、全部 lease、identity store 標記需認證（治 #22773，實作 FR 1635） |
| 斷網 `EgressChanged(false)` | **狀態不變**，僅 `sync.paused` | 離線不降級為鎖定（官方「離線僅 read-only」是把 sync 失敗誤當鎖定） |
| token 遭拒 | Unlocked 降級：保留金鑰、暫停 push、要求重新認證 | 官方 CLI 在此直接壞（#12270） |
| sync 發現金鑰指紋變動 | → Stale | 拒絕拿舊鑰硬解，強制重認證 |

狀態機是 per-device：`LockEpoch` 與其廣播只覆蓋本裝置的中樞與它的 thin clients，他台裝置鎖定不影響本機（§1.1）。

`with_keys` 閉包是金鑰邊界：其他模組永遠拿不到 `KeyBundle` 實值，只能在閉包內用 → 編譯期排除「金鑰被傳進 thin client / 存進 store / 印進 log」。

### 2.3 Agent session / grant / 出口淨化

```rust
pub enum Principal { Cli { uid, exe: CodeId }, McpShim { shim: CodeId, host: AgentHost },
                     Extension { bundle_id, team_id }, Gui { window }, Device { device_id, pairing } }

pub struct Session { pub id: SessionId, pub principal: Principal, pub grants: GrantSet,
                     pub epoch: LockEpoch,            // 綁鎖世代：epoch 不符 ⇒ StaleEpoch
                     pub expires_at: Option<DateTime<Utc>>,
                     pub bound: ChannelBinding,       // peer 簽章摘要 / TLS finished / XPC 對端
                     pub approvals: ApprovalMode, pub usage: UsageLedger,
                     pub state: SessionState }        // Active | Suspended | Revoked

pub struct Grant { pub target: Target,                // All | Folder | Tag | Item | UriDomain | FieldScope{item,field}
                   pub access: Access,                // See(floor) | Use(kind) | Reveal(floor) | Mutate | Delegate
                   pub budget: Budget,                // max_uses / per_item_max_uses / max_bytes_out / min_interval
                   pub ttl: Option<Duration>, pub requires: Requires }  // TouchId | GuiConfirm | None
pub enum UseKind { TotpCode, InjectEnv { slot }, AutoType, Run { sandbox: ExecPolicy }, SshSign, PasskeyAssert }

/// 可安全進 LLM context 的機密代表符號（本身不帶熵）
pub struct SecretRef;   // 文字形 btw://<item>/<field>#<once>；解析需 Use|Reveal grant

/// 唯一 thin 入口：授權、budget、audit、redaction 四檢查不可能被新介面繞過
pub fn call(s: SessionId, c: Call) -> Result<Response>;   // Call 新 variant 未分派 ⇒ 編譯失敗

pub struct RunPlan { pub argv: Vec<String>, pub env: BTreeMap<String, SecretRefOrLiteral>,
                     pub cwd: PathBuf, pub timeout: Duration, pub net: NetPolicy }  // net 預設 deny
pub struct Redactor;  // 凡離開 daemon 朝向 agent 的位元組（Run stdout/stderr、錯誤字串、event payload）一律淨化
```

Enrollment：agent 首次連線產生 `EnrollmentRequest`，daemon 推 `NeedApproval` 給 GUI/手機，人可**縮減** grant 後批准；`Reveal` 超出政策時同樣阻塞等人核准。機密要進 LLM context，必須有一個人類進程當中介。Audit 為 append-only hash 鏈（`AuditRecord { ts, session, action, item, field, sens, outcome, bytes_out, approval, epoch, prev_hash }`），`bitward audit --verify` 驗證鏈。

### 2.4 離線寫入 outbox

```rust
pub struct Mutation { pub id: MutationId, pub seq: u64,        // 同 item FIFO，跨機欄位級 3-way merge
                      pub item: ItemId, pub base: ServerRev,   // 樂觀併發基準
                      pub op: Op,                              // Create|Patch|Delete|Restore|Move|Assign|Attachment*
                      pub payload_enc: EncryptedBlob,          // 入列時即用 user key 加密好；push 路徑不再碰金鑰
                      pub origin: SessionId,                   // 衝突時知道該問誰
                      pub state: MutState }                    // Queued|InFlight|Awaiting|Applied|Conflict|Dead
```

規則：寫入一律「本地 transaction（mirror+outbox 同交易）→ 非阻塞 push」，UI 從不等網路；`ours`/`theirs` 欄位不相交 ⇒ 自動合併，相交 ⇒ `Conflict` 進 GUI 佇列，**永不靜默覆蓋**；附件 blob 落地排隊（治 FR 4306）；`Dead` 需人類介入，不再自動重試。

### 2.5 BTP（Full↔Thin 協議）

```rust
pub enum ClientMsg { Hello{version, auth, wants, caps}, Invoke{rid, call}, Cancel{rid},
                     Approval{id, decision}, Pull{cursor} }    // 斷線補事件（治 bw serve 跑久損壞 #9306）
pub enum ServerMsg { Welcome{epoch, server: ServerProfile, state, events_from},
                     Reply{rid, outcome}, Event{topic, seq, payload},   // payload 只有 Opaque/Identity 級
                     NeedApproval{..}, Challenge{..} }
pub enum Call { Auth(..), Vault(..), Use(..), Fill(..), Sync(..), Agent(..), Admin(..) }
pub enum WtpError { StaleEpoch, Locked, NeedsApproval, ApprovalExpired, Denied{grant_gap},
                    NotFound, HubOffline{last_seen},
                    Conflict{ours,theirs}, Unsupported{feature}, ServerDrift, RetryAfter }
```

 bindings 由單一 schema 產生（Rust/Swift/Kotlin；TSX 面只暴露 `MaskedView` 級型別），thin 端不該有第二份業務邏輯。**Android 同構規則**（graft 自候選二）：App 程序內 AutofillService ↔ 核心走完全相同的訊息型別（mpsc 承載），不另開內部 API；進程邊界在 Android 無安全增益，協議一致性有。

### 2.6 協定漂移防禦

```rust
pub struct ServerProfile { pub kind: ServerKind,     // BitwardenCloud | Vaultwarden(v) | Unknown
                           pub has: BTreeSet<Feature>, pub quirks: BTreeSet<Quirk> }
// 探測：GET /config + /.well-known/openid-configuration + 一次 /sync 欄位存在性
// 例：UserDecryptionOptions 缺失 ⇒ 降級為僅密碼解鎖，不视为错误（vaultwarden#6729 轉成回歸測試）
```

每個 response 寬容解析並把原始 JSON 存進 `Item.raw`；`Patch` 由 raw + diff 合成 merge-patch，我們未建模的欄位不會被我們的 PUT 抹掉（property test：`sync → put(unchanged)` 後 server JSON 逐位元組相同）。

### 2.7 記憶體保護（明文的生命週期）

目標兩條：密碼不進 LLM context（§2.3 已給型別層機制），以及密碼在記憶體裡盡可能短命、不可分頁、不可撿。

```rust
/// 明文只允許存在這個類型；底層是專用 arena 的 owned buffer
pub struct SecretString(Zeroizing<ArenaBuf>);

pub struct SecretArena;  // 進程啟動時 mmap 的單一區段：
                         //   mlock() 防分頁；MADV_DONTDUMP 防 core dump；
                         //   Linux 優先 memfd_secret()（Keyguard 先例），macOS 以
                         //   RLIMIT_CORE=0 + FileVault 假設退路；
                         //   drop 即 memset 零；arena 外不得出現明文位元組
```

規則（逐條可測）：

1. **單一落點。** 所有明文拷貝（parse、concat、serde 中間態）都必須經 arena allocator 配置；Redactor 的 `known` 集合在每次 reveal 時同步登記 → 「離開過程序的明文值」永遠有帳可查。單元測試：fill 已知 pattern → drop → 直讀 arena 原始位元組驗零。
2. **不可變字串不跨邊界。** Swift `String`、Kotlin `String`、JS `string` 無法清零且會 intern/複製 → bindings 對 secret 欄位一律自訂 FFI 型別（owned bytes buffer + 顯式 `clear()`），API 層 lint 禁止把密碼型別宣告成不可變字串。
3. **進程邊界不吃 argv/env。** 主密碼輸入走 stdin/pinentry 式 fd；`--password-env` 是唯一明示例外（`ps` 與 `/proc/*/environ` 對同 uid 可見）。IPC 從 arena buffer 直接 `writev`，不經中間 String；per-conn AEAD 已防同機監聽。
4. **Context 出口登記表。** 每個離開中樞的通道有預設視窗政策，審查與測試都以這張表為準（新增出口必須先登記，否則 CI 的 egress 清單檢查失敗）：

| 出口 | 預設內容 | 明文條件 |
|---|---|---|
| MCP tool 結果 | Opaque/Identity + `btw://` ref | Reveal grant，逐次 audit |
| CLI stdout | 同上 | `--reveal` 且 stdout 為 TTY；pipe 預設拒 |
| BTP event | 只有 Opaque/Identity | 永不帶明文（協定紀律） |
| 核准 UI（GUI/手機） | 單欄明文給人眼看 | 只顯示，不回存任何緩存 |
| `ASCredentialIdentityStore` | metadata | 無明文（Apple 限制即不變量） |
| audit / 日誌 | 值指紋 + 字節數 | 永不帶明文（A8 斷言） |
| `Run` 子程環境 | 注入明文 | 只進子程；stdout/stderr 出口淨化後才回 |

5. **威脅模型誠實邊界。** 同使用者 root/`ptrace` 與 cold boot 攻擊不在本層防禦（1Password 明示接受同級風險）；暫停（suspend-to-disk）後的記憶體影像交給平台全盤加密（macOS `hibernatemode 3` + FileVault），文件如實聲明。Android 端 AutofillService 依平台語意必然經手明文，用 `setAuthentication()` PendingIntent 延後暴露＋填充後立即清零（§4 缺口 3）。
6. **UI 層明文紀律（NSH）。** 明文欄位只允許在 Rust 元件渲染；TSX/QuickJS 動態畫面最多拿 `Masked`，因為 JS 字串不可變、無法清零，進去就留在堆上。執行方式：BTP 回應組 TSX props 前經 `MaskedView` 型別降級，明文型別在編譯期就傳不進去。

## 3. 模組圖與依賴方向

```
bw-crypto（自寫，零上層依賴）← bw-proto（Bitwarden Client API，唯一碰 HTTP/WS 處）
        ↑                              ↑
bw-keys（狀態機+KeyStore）      bw-store（SQLite: mirror+overlay+outbox+audit，存密文與已索引 metadata）
        ↖                            ↙
          bw-vault（Item 模型/project/classify/dedup/merge/bulk）
          bw-sync（單飛 trigger + drain + 三方合併 + ServerProfile）
          bw-agent（session/grant/approval/redaction/audit 寫入）
          bw-fill（auto-type 排程 + identity store + lease）
                    ↘      ↙
                     bw-btp（協議伺服：UDS / XPC / TLS binding）
bins: bitwarderd | bitward(CLI) | bitward-mcp | bitward-nm | provider-client
```

規則：thin 側編譯上碰不到 `bw-crypto` 的解鎖 API（依賴方向即安全邊界）；`bw-store` 不知金鑰語意（只存 `Prot<T>`）；`bw-vault` 不知網路；UI 只依賴 BTP bindings。

Transport 總表：

| 邊 | 傳輸 | 對端驗證 | 備註 |
|---|---|---|---|
| CLI/GUI/MCP ↔ daemon | UDS `0600`（`$XDG_RUNTIME_DIR` 或 Application Support 下） | `LOCAL_PEERCRED` uid+pid → 執行檔路徑 → 代碼簽章 Team ID 白名單；每連線 X25519+AEAD（防同機搶佔 socket，KeePassXC 教訓） | |
| Provider extension ↔ daemon | App group 上 **XPC/Mach**，service name `<group>.<name>` | sandbox extension + entitlement | 註冊 `MachServices` 讓 launchd **按需拉起 daemon**；若實測 XPC 受限，退為 group container 內 unix socket（Bitwarden passkey provider 生產先例） |
| 跨機 thin | TCP+TLS1.3 或 Tailscale；配對碼 + SPKI pin + DeviceId | 每裝置獨立 grant；BTP 層再疊一層 X25519（不單信隧道） | 借 vaultgate/1Password Connect 的短期 token 模式，遠端永不拿長期金鑰 |
| MCP ↔ host | stdio JSON-RPC | fork 關係 + 可選 allowlist | |
| Android 進程內 | mpsc（同 BTP 訊息型別） | 元件邊界 | |

## 4. 五個優先缺口 → 模組 → 階段

缺口證據全在 `research/feature-gaps.md` 與 `research/agent-ecosystem.md`。

| 缺口 | 負責模組 | 階段 | 交付 |
|---|---|---|---|
| 自動化（無 webhooks、CLI 綁主密碼、無 scope/audit、MCP 薄殼） | bw-agent、bw-btp（事件流+Pull）、bitward-mcp | **P3**（基礎共享解鎖在 P1 即成立） | 常駐 daemon 免 env var；事件流取代輪詢；enrollment/grant/budget/audit；`Run` 注入+出口淨化；TOTP 出碼不出 seed |
| 資料管理（tags 492👍、排序 494👍、去重合併 392👍、unshare/批次 322👍、值搜尋 119👍） | bw-store（overlay+FTS5）、bw-vault、bw-sync | **P4**（overlay 表結構 P1 就在） | `LocalOverlay` tags（協定無此欄位，本地權威；官方上路後雙向合併）；`find_duplicates`/`merge` 在 daemon 內掃描只回 id；`unshare` 避開 bw move bug（#11689）；值搜尋走本地明文索引，不上傳 |
| auto-type 與共享解鎖狀態（FR 158 719👍、FR 1635） | bw-fill（CGEvent 引擎+lease）、bw-keys（epoch 廣播） | **P4**（共享解鎖=P1 架構紅利） | epoch 訂閱讓本裝置解鎖 → 同機 CLI/extension/GUI 同時可用（FR 1635 的範圍就是裝置內；跨裝置各自解鎖，語意見 §1.1）；auto-type 由獲 TCC 授權的 GUI 執行、daemon 只給 ≤5s 單次 lease；剪貼簿不留痕（治 #2621/#2742） |
| 離線可寫入（FR 107、離線解鎖 #19055） | bw-store.Outbox、bw-sync、bw-keys | **P2** | 寫入 API 從第一天就不設計成可失敗（Queued 語意）；DeviceAssertion 離線解鎖；衝突收件匣 |
| macOS 系統級密碼（FR 93723；官方只有 passkey provider） | BitwardProvider.appex、identity store 寫入者（daemon 內）、XPC binding | **P5** | 能力宣告齊四項（ProvidesPasswords/Passkeys/OneTimeCodes/TextToInsert，缺項系統不列出）+ entitlement 雙掛；thin 路線避開 extension Argon2 記憶體上限；`invalidate(epoch)` 處理上鎖後系統快取 |

刻意不做（避免重複造輪）：passkey 登入填充已 GA、桌面 SSH agent 已 GA（僅預留 `UseKind::SshSign`）、Secrets Manager（bws 生態）、企業 org 管理（官方 MCP 勝任）。

## 5. 里程碑

| 階段 | 內容 | 出口條件 |
|---|---|---|
| P0 | workspace、`bw-proto` 型別+BTP schema+conformance vectors、CI（Vaultwarden docker 釘版矩陣 + macOS runner + Android compile-only）、GPL+`cargo deny`+商標聲明、**NSH spike**（provider 設定頁 + vault 列表兩個真實畫面，雙平台驗證渲染與打包鏈，§0.2） | 骨架編譯、CI 綠、spike 畫面可跑 |
| **P1（第一增量，可獨立驗證）** | **read-path daemon**：login（password+TOTP 2FA、API key 旁路）→ 金鑰派生與 Keychain 封存 → `/sync` 全量落 SQLite（密文原樣）→ 狀態機+timeout → UDS+BTP+對端驗證 → secret arena（mlock/清零）→ CLI `status/list/search/get/reveal/audit/lock` | §6 斷言全過 |
| P2 | 寫入路徑：outbox+欄位級三方合併+衝突佇列、離線解鎖與離線寫入收斂、附件 blob 佇列、**多裝置收斂**（cipherId targeted pull、雙裝置併發 e2e A12） | A7/A8 型斷言 + A12（見 §6 附註） |
| P3 | agent 面：session/grant/approval/budget/audit 鏈、`bitward-mcp`、`Run`+Redactor、事件訂閱 | grep 明文==0 端到端斷言 |
| P4 | 資料管理（tags/排序/去重/merge/bulk/unshare/值搜尋）+ auto-type（CGEvent）+ 瀏覽器 NM shim；**Android track 自此起平行**（NSH 同進程核心 + Kotlin 孤島：AutofillService、API 34 CredentialProviderService、Keystore；Full＝預設形態的 in-process 中樞） | 各缺口有專屬 e2e |
| P5 | macOS credential provider（先 passkey 骨架、再 passwords/OTP）+ identity store 維護 + MachServices 按需啟動 + **remote thin 配對伺服**（`pair`/撤銷/跨機 grant）+ **推播路徑**（APNs/FCM/Vaultwarden relay：核准訊息與喚醒訊息、`HubOffline` 快速失敗語意，操作者要求 2026-10-29） | 真機填充延遲量測；跨機 reveal 延遲與撤銷 e2e；手機在口袋裡批准 agent reveal 的 e2e |
| P6 | 跨機 thin 進階（多 hub 編組、Tailscale 場景）、多帳號打磨、Linux 正式支援 | 待定 |

## 6. P1 驗收斷言（可執行，不是「看起來對」）

```bash
docker run -d -p 8080:80 vaultwarden/server:1.37.2
cargo nextest run -p bw-crypto                       # A1 KDF/信封/HKDF/RSA unwrap 對官方 fixtures
cargo nextest run -p bw-server --test compat_fixtures # A2 錄製 /sync 回放（官方雲+VW 兩份）
                                                     # A2b UserDecryptionOptions 缺失 → 降級成功（#6729 回歸）
bitward login --server http://127.0.0.1:8080 --email dev@bitward.test
bitward sync && bitward ls --json | jq -e 'any(has("password")) | not'   # A3 輸出鍵集合無 Secret
grep -a "$WP" ./dev/store.db || true                 # A4 盤上無明文主密碼；已知密碼值亦無
hyperfine -N 'bitward ls --json'                     # A5 p95 < 50ms（對照官方 CLI 1–5s）
# A6 兩個併發 unlock 後双方 session 皆可用；lock 後双双 StaleEpoch
# A7 kill -9 daemon → launchctl 5 秒內重生且**不重跑 KDF** 即恢復解鎖態
# A8 每個 Call 落 audit 一列且 hash 鏈可驗證；trace 日誌搜尋密碼值 0 命中
# A9 cargo deny：無 bitwarden-* SDK crate 依賴；LICENSE=GPL-3.0；README 含非關聯聲明
# A10 secret arena：fill→drop 後直讀 arena 原始位元組全零；mlock 生效
#    （Linux smaps "Locked" >0；macOS 以 rlimit core=0 + malloc zone 檢查替代）
# A11 ps -axo command,environment 對 $WP 與已知密碼值 0 命中（CLI 與 daemon 皆然）
# A12（P2 出口）雙中樞併發：兩 client 改同一 item 的不同欄位 → 自動合併；
#     改同一欄位 → 衝突收件匣並列 ours/theirs，無靜默覆蓋；
#     notifications 事件到達後 5 秒內本機鏡像更新（targeted pull，非全量 sync）
```

P1 是最早失敗點：自寫 crypto 正確性與無 spec 互通性是風險最高且不可回頭的事，若 A1/A2 失敗，整個形態重估（退路見 `design/candidate-1` §6、`design/candidate-2` §6 的替代形態）。

## 7. 全域不變量（每條綁一個測試或結構檢查）

1. 除 daemon（Android Full 為其 in-proc 等位物）外，無進程持有 user key。
2. Secret 級明文不進入：事件 payload、LLM tool 結果、audit 表、日誌、非 reveal 輸出、`ASCredentialIdentityStore`。
3. `KeyBundle` 不實作 Clone、Debug 為 REDACTED、只活在 `with_keys` 閉包。
4. 所有 server 寫入必經 Outbox；無模組能繞過它直接呼叫 push。
5. 所有 thin 請求必經唯一入口 `call()`；grant 分派編譯期窮盡。
6. `LockEpoch` 單調遞增；session/lease/identity-store 皆記 epoch，不符即拒。
7. 讀路徑只讀本地 store，網路永不阻塞讀取。
8. 未建模欄位經 raw+merge-patch 無損往返（property test）。
9. 明文只存在 mlock、MADV_DONTDUMP 的 secret arena，drop 即清零；每個離開過程序的明文值都在 Redactor 帳上（§2.7）。
10. 明文不經不可變字串跨 FFI，不經 argv/env 跨進程。
11. 每裝置恰一個中樞（Android Full 的 in-process 核心是等位物）；跨裝置寫入收斂只經伺服器，衝突只經 merge/收件匣一條路。

## 8. 風險與緩解

| 風險 | 緩解 |
|---|---|
| client API 漂移（無 spec） | ServerProfile 探測 + 寬容解析 + raw mirror + conformance fixtures；追 openapi-generator diff；CI 釘 VW 版本矩陣 |
| thin 模式依賴 daemon 存活（1Password "Failed to connect" 前車） | SMAppService KeepAlive + MachServices 按需啟動 + 秒級重生（A7）+ extension 有界重試 ≤1.5s 後回 `.userInteractionRequired`（系統開互動 UI，不靜默失敗）；P5 第一件事是冷啟延遲 spike |
| 本地明文 metadata 索引（name/uri）本身敏感 | v1 檔案權限 0600 承受；v2 評估 SQLCipher 或索引存 HMAC(token)。先量測搜尋延遲再決定（開放問題 Q4） |
| 自寫 crypto 錯誤 | KAT 對官方 fixtures + golden vault 解密 + 上線前跑 bitwarden-crypto GPL 測試集（取資料不取碼） |
| `Run` 沙箱不足（惡意 argv 外送 secret） | NetPolicy 預設 deny、cwd 限 temporary、出口紅化；文件明說信任前提＝把 secret 交給被執行的程式（與 `op run` 同邊界，不假裝更強） |
| TDE/無主密碼帳號 | auth-request 流程（暫時 RSA + access code）落地 WrappedUserKey，之後離線可解鎖；這是官方 CLI 完全做不到的 |
| 商標與授權 | 不用 Bitwarden 當產品名；v1 不鏈接 GPL 元件（僅取測試向量）；出貨前 `cargo deny` + NOTICE + 商標查證 |
| 多中樞併發寫入（兩台裝置同時編輯） | 伺服器 `revisionDate` CAS + outbox `seq` FIFO；欄位不相交自動合併、相交進收件匣（A12）；notifications 事件帶 cipherId 做 targeted pull，縮小衝突窗口 |
| 堆記憶體／swap／core dump 殘留明文 | secret arena 是唯一明文落點：mlock 防分頁、MADV_DONTDUMP/RLIMIT_CORE=0 防影像、drop 即清零（不變量 9、斷言 A10/A11）；同 uid root 與 cold boot 為已聲明邊界 |

## 9. 綜合紀錄（arena synthesis note)

- **收斂**：兩個獨立候選（`design/candidate-1-daemon-hub.md`、`design/candidate-2-everything-spoke.md`）在形態、金鑰不下放、thin provider、Rust 核心、GPL、SQLite+outbox、LockEpoch/狀態機、1Password 式治理上完全收斂，強協議。
- **Base**：候選一。不變量機制最完整（`with_keys` 閉包、唯一入口 `call()`、raw mirror、hash 鏈審計、敏感度分級 × `project()`）。
- **Grafts**（自候選二，逐條手工折入）：(1) P1 收窄為只讀路徑，寫入獨立成 P2；(2) `VaultState::Stale` 金鑰指紋漂移態；(3) outbox `payload_enc` 入列即加密，push 不碰金鑰；(4) 封存 stretched key 的秒級冷啟 + KeepAlive 重生驗收（A7）；(5) Android「同構訊息、無第二套內部 API」規則；(6) `View` 作為讀取簽名的強制參數。
- **拒絕**：候選二的 app-group unix socket 給 extension（改 XPC+MachServices 換取按需啟動，保留 socket 為實測退路）；候選一原始 P1 含寫入（範圍過大，拆到 P2）。
- **驗證狀態**：設計包內部自洽性已對照 grounding 事實逐條檢查；尚未跑程式碼（repo 尚無實作）。P1 斷言即下一階段的驗證計劃。
- **跨候選未解分歧**：macOS extension 走純 thin（兩候選同）對上 grounding 報告建議的混合式 fat fast-path（`research/macos-provider.md` §4）。裁決：先 thin，理由是金鑰進第二進程會迫使 grant/audit 模型重寫一遍；若 P5 實測冷啟延遲不可接受，升級路徑是優化 daemon 快速路徑，不是把金鑰搬進 extension。
- **操作者修訂（2026-10-29，兩項）**：(1) 多 Full client。按 first-principles 重設計而非打補丁：「唯一」從 day-one 前提改寫為「裝置內唯一」，跨裝置收斂升級為一級機制（§1.1、不變量 11、A12），Android 預設 Full。(2) 明文記憶體保護。新增 §2.7（arena/mlock/清零/FFI 字串紀律/出口登記表）、不變量 9-10、斷言 A10-A11。兩份設計候選保留原樣，其「機器上唯一」措辭以本檔為準。
- **操作者修訂（2026-10-29，第二批）**：(3) thin client 獨立安裝。Full/Thin 分界改掛在執行體而非套件（§1.2、§0 安裝形態列），Q1 隨之關閉，remote 配對伺服提前到 P5。(4) 技術線逐 concern 明細化（§0.1）。
- **操作者修訂（2026-10-29，第三批）**：(5) 移除 thin 的本機自動 provision：surface 不註冊東西，可用性＝中樞在線，App 新增推播路徑（核准＋喚醒訊息、`HubOffline`/`ApprovalExpired` 快速失敗語意，§1.2、§2.5、P5）。(6) GUI 層採用 NSH（Apache-2.0，一套 Rust UI 碼覆蓋 macOS/Android，§0.2），連帶 §2.7 規則 6（明文只進 Rust 元件，TSX ≤ Masked）與 P0 spike。
- **操作者修訂（2026-10-29，第四批）**：(7) Android 推播第一級改 UnifiedPush（`unifiedpush` crate，FCM 降為可選 fallback），push endpoint 定義為能力憑證：不入日誌/event、可輪換、預設建議自架 distributor（§1.2、§0.1）。

## 10. 開放問題

1. （已裁決 2026-10-29，見 §1.2）無 `--standalone` 降級持鑰模式，亦無 thin 自動 provision：surface 不註冊任何東西，可用性＝同機中樞在線（由 Full 套件註冊）或異機配對＋推播喚醒；headless `bitwardd` 保留為刻意選擇的 Full 形態。
2. 多帳號：單 daemon 多 profile（各自 KeyBundle/epoch/outbox，共用 socket）vs per-profile socket。
3. tags overlay 跨裝置同步（隱藏 SecureNote 載體方案）是否推遲到真實使用確認之後。
4. 本地 metadata 索引是否需加密（先量測再決定）。
5. 瀏覽器 extension 完整化與 iOS 版是否列 P6 後獨立設計包。
6. 產品最終名稱與商標查證。
7. 跨裝置預設體驗：新裝置建立時預設走配對（remote thin）還是預設各自 Full、跨裝置只經伺服器收斂。協議兩者同構，這是 setup 流程的取捨，P5 前定案。
