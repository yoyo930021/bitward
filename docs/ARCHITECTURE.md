# bitward 架構設計（綜合版）

日期：2026-10-29。本檔是實作契約，由兩個獨立設計候選綜合而成（過程見 §9），證據來源見 `docs/research/`，兩份原始設計包保留於 `docs/design/` 當附錄。型別與簽名皆為偽代碼層級。

**一句話。** 一台機器上一個常駐 daemon（`bitwarderd`）是唯一的金鑰持有者、唯一的 sync 擁有者、唯一的審計點；CLI、GUI、macOS credential provider extension、MCP shim、跨機裝置、Android 元件全部是同一份協議（BTP）上的 thin client，金鑰永不下放，agent 預設只用不讀。

## 0. 決策摘要

| 決策 | 內容 | 依據 |
|---|---|---|
| 形態 | Daemon-centric hub-and-spoke，金鑰不下放 | 1Password App↔CLI（不下放鑰）、rbw-agent、KeePassXC、Bitwarden passkey provider 五個獨立實作收斂到同一形態（`research/prior-art.md`、`research/macos-provider.md`） |
| 授權 | 全 repo GPL-3.0-or-later；自寫 crypto，不鏈接官方 SDK | `LICENSE_SDK.txt` §3.1 禁止對第三方出貨、§3.3 禁止連 Vaultwarden（`research/protocol.md` §2） |
| 語言 | 核心 Rust；macOS SwiftUI、Android Compose 原生 UI；bindings 由協議 schema 產生 | 官方 CLI Node 啟動 1–5s（clients#2741）；Zeroize 語意；UniFFI 為現成模式 |
| 伺服器 | Bitwarden Cloud 與 Vaultwarden 皆一級目標；欄位寬容 + raw mirror | client API 無官方 spec；vaultwarden#6729 漂移事故 |
| 隱私主軸 | 機密預設不進 LLM context；metadata-only + 單一受審計 reveal + 執行期注入出口淨化 | arXiv 2604.03070（73.5% 洩漏經 stdout、89.6% 立即可利用）；官方 MCP 反彈（`research/agent-ecosystem.md`） |
| 名稱 | 工作名 `bitward`，文件一律寫「Bitwarden-compatible client」，出貨前查商標 | Bitwarden Trademark Guidelines |

## 1. 進程拓撲

| 進程 | 生命週期 | 角色 | 持長期金鑰 |
|---|---|---|---|
| `bitwarderd` | 常駐（macOS LaunchAgent/SMAppService KeepAlive；Linux systemd user；Android foreground service） | 金鑰狀態機、sync+outbox、agent 治理、審計、identity store 維護、auto-type 排程 | 唯一持有者 |
| `bitward`（CLI） | 一次性短命 | 人與腳本介面；無 daemon 時提示啟動，不自行降格持鑰 | 否 |
| `bitward-mcp` | 由 agent host spawn，stdio | MCP ↔ BTP 轉譯，唯一對 LLM 說話的進程 | 否（持 scoped session token） |
| `Bitward.app`（macOS GUI） | 可開可關，關閉不影響服務 | 瀏覽/編輯、enrollment 與衝突核准 UI、TCC 入口、審計瀏覽 | 否 |
| `BitwardProvider.appex` | 系統按需啟動、隨時回收 | passwords（macOS 14+）、passkeys、OTP（15+）、text-to-insert | 否 |
| Android app | Full（核心 in-proc）或 Thin（連遠端 hub） | AutofillService / CredentialProviderService(API 34) / inline IME | Full 時是（Keystore Class 3） |
| `bitward-nm` | 瀏覽器按需 spawn | native messaging ↔ BTP 純管道，無邏輯無金鑰 | 否 |

明確不存在：第二個 sync 客戶端、GUI 內嵌的第二份金鑰、獨立的 HTTP 服務層（HTTP/TLS 只是 BTP 的一種 transport binding）。

金鑰落盤形態：`vault.db` 存伺服器原樣密文（`2.iv|ct|mac` 不改寫）；user key 以 OS 級封存（macOS Keychain biometric ACL、Android Keystore Class 3-bound/StrongBox）；重啟 daemon 用封存金鑰直接解包，**不重跑 KDF**（冷啟秒級，graft 自候選二）。master password 只在解鎖瞬間存在，無任何常駐環境變數（`BW_SESSION` 概念不存在）。

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
pub enum WtpError { StaleEpoch, Locked, NeedsApproval, Denied{grant_gap}, NotFound,
                    Conflict{ours,theirs}, Unsupported{feature}, ServerDrift, RetryAfter }
```

 bindings 由單一 schema 產生（Rust/Swift/Kotlin/TS），thin 端不該有第二份業務邏輯。**Android 同構規則**（graft 自候選二）：App 程序內 AutofillService ↔ 核心走完全相同的訊息型別（mpsc 承載），不另開內部 API；進程邊界在 Android 無安全增益，協議一致性有。

### 2.6 協定漂移防禦

```rust
pub struct ServerProfile { pub kind: ServerKind,     // BitwardenCloud | Vaultwarden(v) | Unknown
                           pub has: BTreeSet<Feature>, pub quirks: BTreeSet<Quirk> }
// 探測：GET /config + /.well-known/openid-configuration + 一次 /sync 欄位存在性
// 例：UserDecryptionOptions 缺失 ⇒ 降級為僅密碼解鎖，不视为错误（vaultwarden#6729 轉成回歸測試）
```

每個 response 寬容解析並把原始 JSON 存進 `Item.raw`；`Patch` 由 raw + diff 合成 merge-patch，我們未建模的欄位不會被我們的 PUT 抹掉（property test：`sync → put(unchanged)` 後 server JSON 逐位元組相同）。

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
| auto-type 與共享解鎖狀態（FR 158 719👍、FR 1635） | bw-fill（CGEvent 引擎+lease）、bw-keys（epoch 廣播） | **P4**（共享解鎖=P1 架構紅利） | epoch 訂閱讓桌面解鎖 → CLI/extension 同時可用；auto-type 由獲 TCC 授權的 GUI 執行、daemon 只給 ≤5s 單次 lease；剪貼簿不留痕（治 #2621/#2742） |
| 離線可寫入（FR 107、離線解鎖 #19055） | bw-store.Outbox、bw-sync、bw-keys | **P2** | 寫入 API 從第一天就不設計成可失敗（Queued 語意）；DeviceAssertion 離線解鎖；衝突收件匣 |
| macOS 系統級密碼（FR 93723；官方只有 passkey provider） | BitwardProvider.appex、identity store 寫入者（daemon 內）、XPC binding | **P5** | 能力宣告齊四項（ProvidesPasswords/Passkeys/OneTimeCodes/TextToInsert，缺項系統不列出）+ entitlement 雙掛；thin 路線避開 extension Argon2 記憶體上限；`invalidate(epoch)` 處理上鎖後系統快取 |

刻意不做（避免重複造輪）：passkey 登入填充已 GA、桌面 SSH agent 已 GA（僅預留 `UseKind::SshSign`）、Secrets Manager（bws 生態）、企業 org 管理（官方 MCP 勝任）。

## 5. 里程碑

| 階段 | 內容 | 出口條件 |
|---|---|---|
| P0 | workspace、`bw-proto` 型別+BTP schema+conformance vectors、CI（Vaultwarden docker 釘版矩陣 + macOS runner + Android compile-only）、GPL+`cargo deny`+商標聲明 | 骨架編譯、CI 綠 |
| **P1（第一增量，可獨立驗證）** | **read-path daemon**：login（password+TOTP 2FA、API key 旁路）→ 金鑰派生與 Keychain 封存 → `/sync` 全量落 SQLite（密文原樣）→ 狀態機+timeout → UDS+BTP+對端驗證 → CLI `status/list/search/get/reveal/audit/lock` | §6 斷言全過 |
| P2 | 寫入路徑：outbox+三方合併+衝突佇列、離線解鎖與離線寫入收斂、附件 blob 佇列 | A7/A8 型斷言（見 §6 附註） |
| P3 | agent 面：session/grant/approval/budget/audit 鏈、`bitward-mcp`、`Run`+Redactor、事件訂閱 | grep 明文==0 端到端斷言 |
| P4 | 資料管理（tags/排序/去重/merge/bulk/unshare/值搜尋）+ auto-type（CGEvent）+ 瀏覽器 NM shim；**Android track 自此起平行**（UniFFI 核心 + AutofillService + API 34 CredentialProviderService） | 各缺口有專屬 e2e |
| P5 | macOS credential provider（先 passkey 骨架、再 passwords/OTP）+ identity store 維護 + MachServices 按需啟動 | 真機填充延遲量測 |
| P6 | 跨機 thin（TLS 配對）、多帳號打磨、Linux | 待定 |

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

## 9. 綜合紀錄（arena synthesis note)

- **收斂**：兩個獨立候選（`design/candidate-1-daemon-hub.md`、`design/candidate-2-everything-spoke.md`）在形態、金鑰不下放、thin provider、Rust 核心、GPL、SQLite+outbox、LockEpoch/狀態機、1Password 式治理上完全收斂，強協議。
- **Base**：候選一。不變量機制最完整（`with_keys` 閉包、唯一入口 `call()`、raw mirror、hash 鏈審計、敏感度分級 × `project()`）。
- **Grafts**（自候選二，逐條手工折入）：(1) P1 收窄為只讀路徑，寫入獨立成 P2；(2) `VaultState::Stale` 金鑰指紋漂移態；(3) outbox `payload_enc` 入列即加密，push 不碰金鑰；(4) 封存 stretched key 的秒級冷啟 + KeepAlive 重生驗收（A7）；(5) Android「同構訊息、無第二套內部 API」規則；(6) `View` 作為讀取簽名的強制參數。
- **拒絕**：候選二的 app-group unix socket 給 extension（改 XPC+MachServices 換取按需啟動，保留 socket 為實測退路）；候選一原始 P1 含寫入（範圍過大，拆到 P2）。
- **驗證狀態**：設計包內部自洽性已對照 grounding 事實逐條檢查；尚未跑程式碼（repo 尚無實作）。P1 斷言即下一階段的驗證計劃。
- **跨候選未解分歧**：macOS extension 走純 thin（兩候選同）對上 grounding 報告建議的混合式 fat fast-path（`research/macos-provider.md` §4）。裁決：先 thin，理由是金鑰進第二進程會迫使 grant/audit 模型重寫一遍；若 P5 實測冷啟延遲不可接受，升級路徑是優化 daemon 快速路徑，不是把金鑰搬進 extension。

## 10. 開放問題

1. `bitward` 是否支援無 daemon 降級模式（`--standalone`＝前景跑 daemon）？傾向不支援以守不變量 1，CI/容器場景再議。
2. 多帳號：單 daemon 多 profile（各自 KeyBundle/epoch/outbox，共用 socket）vs per-profile socket。
3. tags overlay 跨裝置同步（隱藏 SecureNote 載體方案）是否推遲到真實使用確認之後。
4. 本地 metadata 索引是否需加密（先量測再決定）。
5. 瀏覽器 extension 完整化與 iOS 版是否列 P6 後獨立設計包。
6. 產品最終名稱與商標查證。
