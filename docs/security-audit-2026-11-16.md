# bitward 資訊安全檢測報告（2026-11-16）

- 稽核基準：`main` @ `6857697`
- 方法：整個程式碼庫分七個區域平行審查，每項候選發現再做一輪驗證以過濾誤報。全程只讀，未建置、未執行。
- 結果：**7 項通過驗證（4 HIGH、3 MEDIUM）**，另有 2 項落盤機密的設計層問題、1 項未驗證的邊緣項目、2 項驗證後排除。
- 排除範圍：DoS、資源耗盡、rate limiting、過期相依套件、純測試程式碼、需控制環境變數或 CLI 旗標的攻擊。

## 驗證狀態說明

| 標記 | 意義 |
|---|---|
| 獨立驗證 | 由另一個只拿到程式碼位置的驗證者嘗試反駁後仍成立 |
| 直接讀碼 | 稽核後段工具故障，改由主稽核者直接讀原始碼確認，未經獨立驗證 |
| 未驗證 | 只有初次稽核的結論 |

## 修正進度總表

建議依此順序處理。前三項都在 daemon 授權路徑上，改動集中、彼此相關。

| # | 項目 | 嚴重度 | 信心 | 驗證 | 位置 | 狀態 |
|---|---|---|---|---|---|---|
| V1 | TLS 握手簽章未驗證 | HIGH | 9/10 | 直接讀碼 | `crates/bw-btp/src/tls.rs:165` | ☐ |
| V2 | 低權限 session 可自發任意權限配對碼 | HIGH | 9/10 | 直接讀碼 | `bins/bitwarderd/src/agent.rs:339` | ☐ |
| V3 | `use:run` 子行程可全權重入 daemon | HIGH | 8/10 | 獨立驗證 | `bins/bitwarderd/src/main.rs:574` | ☐ |
| V4 | Android autofill 信任自報 `webDomain` | HIGH | 8/10 | 獨立驗證 | `BitwardAutofillService.kt:187` | ☐ |
| V5 | `List{view: Reveal}` 繞過 reveal grant | MEDIUM | 8/10 | 直接讀碼 | `bins/bitwarderd/src/agent.rs:193` | ☐ |
| V6 | `btw://` 注入略過核准、Device 不查 scope | MEDIUM | 9/10、8/10 | 獨立驗證 | `bins/bitwarderd/src/agent.rs:683` | ☐ |
| V7 | 核准摘要以 `Debug` 洩漏明文 | MEDIUM | 8/10 | 直接讀碼 | `bins/bitwarderd/src/agent.rs:819` | ☐ |
| D1 | `vault.db` 持久保存明文帳密 | 設計層 | — | 直接讀碼（部分） | `crates/bw-store/src/schema.rs:82` | ✅ `d355504`（PR7b：password_hmac＋鎖態拒值查詢＋secure_delete/checkpoint） |
| D2 | `FileKeyStore` 落盤未包裝的 user key | 設計層 | — | 直接讀碼（部分） | `crates/bw-keys/src/machine.rs:376` | ✅ `d355504`（PR7b：strict 封存閘，僅自動解鎖 opt-in 落盤、lock 即清） |
| B1 | `/private/tmp` socket 目錄可被搶佔 | MEDIUM | 0.75 | 未驗證 | `bins/bitwarderd/src/main.rs:220` | ☐ |

---

## V1：TLS 握手簽章未驗證，SPKI pin 可被繞過

- **位置**：`crates/bw-btp/src/tls.rs:165-181`；使用端為 `bitward pair join` 與 `--remote`（`bins/bitward/src/main.rs:985`、`:1089`）
- **類別**：`certificate_validation_bypass`
- **攻擊者**：paired client 與 `bitwarderd --listen` 之間的主動網路攻擊者（同 LAN、Wi-Fi、ARP/DNS 欺騙）

**問題**

`PinVerifier::verify_server_cert` 只比對 server 憑證的 SPKI 雜湊。`verify_tls12_signature` 與 `verify_tls13_signature` 直接回 `HandshakeSignatureValid::assertion()`，握手因此不會證明對方持有憑證對應的私鑰。daemon 的憑證是公開的：`server_config` 用 `with_no_client_auth()`，任何人連上 `--listen` 埠就能取得。

**攻擊情境**

1. 攻擊者連一次真 daemon，存下憑證。
2. 攔截受害者的 `bitward --remote <profile> ...`，用該憑證加任意金鑰架假 server。
3. pin 相符、簽章不驗，握手成功。
4. client 送出長效 session token，攻擊者重放給真 daemon，取得該裝置的全部 grant。
5. 若攔到的是 `pair join`，攻擊者搶先兌換一次性配對碼，並能看到全部明文往來。

**修正**

- 兩個函式改為委派 `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature`，演算法清單取自 `rustls::crypto::ring::default_provider().signature_verification_algorithms`。
- `supported_verify_schemes` 從同一份清單導出，不要手寫。

**修後驗證**

- 新增測試：用正確憑證但錯誤私鑰的 server，client 握手必須失敗。
- 既有的 pin 相符與 pin 不符測試仍須通過。

---

## V2：任何低權限 session 都能自發任意權限的配對碼

- **位置**：`bins/bitwarderd/src/agent.rs:339-342`（分級）、`bins/bitwarderd/src/hub.rs:463-469`（分派）、`agent.rs:552`（`pair_start`）
- **類別**：`privilege_escalation`
- **攻擊者**：持有任一 `see:<x> all` grant 的遠端配對裝置或 agent

**問題**

- `call_req` 把所有 `Call::Auth(_)`、`Call::Admin(_)`、`Call::Sync(_)` 歸為最低的 `Access::See(Sensitivity::Opaque)`。
- `crates/bw-agent/src/lib.rs:271` 的 `same_access` 是 `x >= y`，任何 `see:* all` grant 都涵蓋 `See(Opaque)`。
- `dispatch_inner` 分派 `PairStart`、`PairList`、`PairRevoke` 時沒有檢查 session 種類；`Login` 與 `SignOut` 同樣未設限。只有 `Lock` 與 `Sync::Trigger` 被明確拒絕。
- `pair_start` 原樣接受呼叫者給的 grant DSL 與 TTL。

**攻擊情境**

只有 `see:identity all` 的裝置送出 `PairStart{name:"x", grant:"reveal:secret all; use:run all", ttl_secs: 31536000}`，拿到配對碼後另開連線以 `Enroll{pair_code: Some(code)}` 兌換。它得到可揭露全部機密的 Device session，並能透過 `use:run` 在 hub 主機上以使用者身分執行任意指令。同一個 session 還能用 `PairList` 讀到使用者剛產生的配對碼。

**修正**

- `Auth::*`（`WhoAmI` 可例外）一律限 `SessionKind::Interactive`，比照既有的 `Approve`、`SetSettings`、`OpenSession`。
- 更根本的做法：對非 Interactive session 的非 vault 類 Call 預設拒絕，改用明確的允許清單。

**修後驗證**

- 新增測試：Agent 與 Device session 呼叫 `PairStart` / `PairList` / `PairRevoke` / `Login` / `SignOut` 都必須回 `Denied`。

---

## V3：`use:run` 可讓受限 agent 取得整個 vault

- **位置**：`bins/bitwarderd/src/main.rs:574-587`（同 uid Enroll = 全權）、`bins/bitwarderd/src/agent.rs:109`（Interactive 直接放行）、`agent.rs:725-765`（`run_plan`）、`bins/bitward-mcp/src/tools.rs:157-207`
- **類別**：`authorization_bypass`
- **攻擊者**：被 prompt injection 的 agent，token 的 grant 含 `use:run`，但沒有 reveal 權限

**問題**

- `run_plan` 以 daemon 自己的 uid 啟動 agent 指定的任意程式，沒有白名單、沙箱或網路限制。
- 本機 socket 只檢查 peer uid。任何同 uid 的 peer 送 `Auth::Enroll{pair_code: None}`，就得到 `SessionKind::Interactive` 加 `GrantSet::default_full()`。
- `authorize()` 對 Interactive session 直接回 `Ok(None)`，不查 grant、預算或核准。
- 輸出 `Redactor` 只認本次注入的 `btw://` 值，子行程自己 reveal 出來的內容不會被遮蔽。
- `docs/ARCHITECTURE.md:192`、`:200-201`、`:315`、`:394` 描述的 `ExecPolicy` 沙箱、`NetPolicy` 預設 deny、peer 簽章檢查都沒有實作。

**攻擊情境**

agent 只有 `see:identity all; use:run all`，它呼叫 MCP `run`，argv 為 `["bitward","--sock","<sock>","reveal","<uuid>"]`（item id 可從 `vault_list` 取得）。子行程以全權身分 enroll，明文密碼從 stdout 回到 agent 的 context，不經核准也不計預算。TOTP、編輯、刪除、匯出同理。

**修正**

- 本機 Enroll 改驗 peer 的 audit token 與程式碼簽章（Team ID 允許清單），或要求 GUI/Touch ID 確認。不要用環境變數當標記，子行程能控制自己的環境。
- 補上設計中的沙箱：拒絕網路、拒絕 daemon socket 路徑、限制檔案存取。
- 在那之前：文件把 `use:run` 標為等同全權，並預設要求核准。

**備註**

若 agent 本來就有同使用者的 shell（例如另有 Bash 工具），這條邊界原本就不存在。此項影響的是「MCP 工具是 agent 唯一能力」的情境，也就是 agent token 與 grant 機制存在的理由。

---

## V4：Android autofill 信任任何 app 自報的 `webDomain`

- **位置**：`apps/bitward-android/android-shell/app/src/main/kotlin/io/bitward/android/BitwardAutofillService.kt:187`（查詢鍵）、`:103-128`（解密與建 Dataset）、`:182-191`（欄位選擇）、`:243`（儲存路徑）；`crates/bw-store/src/query.rs:119-123`（後綴比對）
- **類別**：`missing_origin_verification`
- **攻擊者**：零權限的惡意 app

**問題**

- 任何請求方的 `node.webDomain` 都直接成為查詢鍵。沒有瀏覽器白名單、Digital Asset Links 或簽章檢查；manifest 也沒有 autofill 相容瀏覽器設定。
- `onFillRequest` 對每個候選立刻呼叫 `revealFor` 解密並放進 Dataset，沒有 `Dataset.setAuthentication`。候選列只顯示項目名稱，不顯示比對到的 domain 或請求方。
- 密碼欄位以 hint 或 inputType 選定，不檢查可見性。

**加重因素**

- **後綴比對**：`query.rs:122` 是 `h == want || h.ends_with(".{want}")`，自報 `webDomain="com"` 會命中所有 `.com` 登入。每次上限 10 筆，但可重複請求或一次宣告多個 domain。
- **靜默解封**：vault 鎖定時 `onFillRequest` 呼叫 `nshTrySilentUnseal()`（`:93-95`）。Keystore 金鑰用 30 秒驗證視窗（`BitwardKeyStore.kt:54-66`），裝置解鎖後 30 秒內不會出現 Bitward 提示。目前也沒有自動鎖定計時器。
- **儲存路徑**：用同一個未驗證的 domain，可誘使使用者覆寫真實項目的密碼並同步到 server。

**攻擊情境**

惡意 app 顯示登入畫面，view 自報 `webDomain="paypal.com"`。使用者看到自己的 PayPal 建議並點一下，真實帳密就填進攻擊者的欄位，app 用 `getText()` 讀走。

**修正**

1. 只接受已知瀏覽器（最好驗簽章憑證）回報的 `webDomain`；其他 app 只比對 `androidapp://<package>`。
2. 拒絕 public suffix 查詢（`com`、`co.uk` 等），後綴比對前先過 PSL。
3. Dataset 改用 `setAuthentication`，使用者選定後才解密；候選列顯示請求方或比對到的 domain。
4. 略過不可見（`visibility != VISIBLE`、alpha 或尺寸接近零）的欄位。
5. `onFillRequest` 不要靜默解封；回傳鎖定回應並要求明確的 BiometricPrompt，最好用每次使用的 `CryptoObject`。

---

## V5：`List{view: Reveal}` 繞過 reveal grant 與核准

- **位置**：`bins/bitwarderd/src/agent.rs:193-199`（分級）、`bins/bitwarderd/src/hub.rs:490-506`（處理）
- **類別**：`authorization_bypass`
- **攻擊者**：grant 含 `see:secret all`，但明文存取受限（例如 `reveal:secret item:X approve`）的 agent 或 Device

**問題**

`Get` 的 `View::Reveal` 對應 `Access::Reveal(Secret)`，`List` 的同一個 view 卻只對應 `Access::See(Secret)`。處理端接著對每筆呼叫 `project_one(m.id, *view)`，也不經過 `audit_reveal`。

> 未確認的部分：`project_one` 本體沒有讀，假設它不另做授權。修正前請先確認。

**攻擊情境**

session 送出 `List{query: {limit: 很大的值}, view: Reveal}`，一次拿到整個 vault 的明文密碼、備註與隱藏欄位，沒有任何核准提示，預算只扣一次。

**修正**

- `List` 的 `View::Reveal` 改對應 `Access::Reveal(Secret)`，或對非 Interactive session 直接拒絕。
- 更好的做法：對回傳的每一筆做 item 層級判定，並逐筆寫 `audit_reveal`。

---

## V6：`btw://` 環境變數注入略過核准，Device session 不檢查 scope

- **位置**：`bins/bitwarderd/src/agent.rs:683-690`（`resolve_env`），由 MCP `run` 的 `env` 參數到達
- **類別**：`approval_bypass`
- **攻擊者**：持有 `use:run` 的 agent 或配對裝置

**問題**

1. **核准被略過**：`Decision::Allow(idx) | Decision::NeedApproval(idx)` 走同一個分支，只呼叫 `budget_ok`，不進 `authorize()` 在 `agent.rs:125-166` 的核准迴圈。`use:env item:X approve` 因此永遠不會詢問使用者。
2. **Device 不查 scope**：`use:env` 檢查包在 `if sess.kind == SessionKind::Agent` 裡。Device session 直接落到 `secret_plaintext`，可注入任意項目的 password、username、totp、notes。`SessionKind::Device` 的文件註解明寫「授權走同一張判定表」，所以這不是設計。
3. **用量不記帳**：`record_usage` 記的是 `use:run` grant 的索引，`use:env item:X uses=1` 形同無限次。
4. **Redactor 只做字面比對**：`crates/bw-agent/src/lib.rs:405-414` 用 `text.find(needle)`，任何編碼都能繞過。

**攻擊情境**

agent 呼叫 `run`，argv 為 `["/bin/sh","-c","printf %s \"$P\" | base64"]`，env 為 `{"P":"btw://<uuid>/password"}`。base64 輸出不被遮蔽，agent 解碼即得明文，使用者設定的核准從未觸發。配對裝置對 grant 範圍外的項目也能這樣做。

**修正**

- `NeedApproval` 走與 `authorize()` 相同的核准迴圈，摘要寫明項目與欄位。
- 檢查條件改為 `sess.kind != SessionKind::Interactive`。
- 為命中的 `use:env` grant 記帳。
- 文件註明 `use:env` 加 `use:run` 實質等同 reveal，因為輸出遮蔽擋不住子行程轉換機密。

---

## V7：核准摘要以 `Debug` 輸出，明文密碼被推送與廣播

- **位置**：`bins/bitwarderd/src/agent.rs:808-821`（`summarize`）、`agent.rs:139-143`（發送）；`crates/bw-proto/src/lib.rs:768`（`CipherDraft`）、`:794`（`ImportItem`）、`:809`（`FieldEdit`）
- **類別**：`sensitive_data_exposure`
- **攻擊者**：能讀 ntfy topic 的人（server 營運者、公開或可猜 topic 的訂閱者），或任何訂閱事件的已連線 session

**問題**

`summarize` 只對 `Get`、`ResolveRef`、`Run`、`Attachment`、`Send` 做去敏，其餘走 `other => format!("{other:?}")`。`CipherDraft`、`ImportItem`、`FieldEdit` 都是 derive `Debug`，會印出明文密碼、TOTP seed 與備註。摘要存進 `pending`、透過 `emit(ApprovalRequired)` 廣播，並交給 `publish_signal`。

> 未確認的部分：`publish_signal` 送往 ntfy/APNs 的實作沒有讀到，此處依初次稽核的敘述。

**攻擊情境**

使用者給 agent `mutate:create all approve`。agent 建立或輪替一筆密碼時，明文出現在 ntfy topic，也送到每個已連線的配對裝置。這違反專案自訂的「明文永不上通道」原則。

**修正**

- 摘要改用非機密欄位白名單（動作標籤、項目 id、名稱），不要對 `Call` 用 `Debug`。
- 為 `CipherDraft`、`ImportItem`、`FieldEdit` 實作會遮蔽的 `Debug`，防止日後其他地方誤用。

---

## 落盤機密（設計層，不列入正式發現）

這次稽核的規則把「機密落盤」排除在外，但對密碼管理器來說這兩項直接影響「鎖定」的意義，值得做一次明確的設計決定。

### D1：`vault.db` 持久保存明文帳密

- **位置**：`crates/bw-store/src/schema.rs:82-83`、`crates/bw-store/src/ciphers.rs:171-183`、`bins/bitwarderd/src/hub.rs:435`、`:1197`；Android 同樣（`apps/bitward-android/src/hub.rs:327`）
- **現況**：每次解鎖後，所有登入的帳號與密碼寫入 `meta_plain.username_plain` / `password_plain`。資料庫只設了 `journal_mode=WAL`、`synchronous`、`foreign_keys`，沒有加密或 `secure_delete`。`Auth::Lock` 與 `machine.lock` 都不清這些欄位。
- **影響**：鎖定狀態下，能讀到資料目錄的人（備份、離線磁碟、同使用者行程）不需主密碼就能讀出全部登入密碼。
- **未確認**：初次稽核回報只有下一次完整 sync 會清這些欄位，以及鎖定狀態下 `value` 查詢可當作密碼猜測 oracle，這兩點沒有親自確認。schema 註解引用「§2.7 R3」，看起來是有意的設計，但文件內容沒有查。
- **改善方向**：
  - 值搜尋索引只留在記憶體，或改存以 user key 導出金鑰計算的 HMAC。
  - 鎖定時清空這兩欄，開啟 `PRAGMA secure_delete=ON`，清完後 checkpoint 並截斷 WAL。
  - 鎖定狀態拒絕 `Query.value`。

### D2：`FileKeyStore` 落盤未包裝的 user key

- **位置**：`crates/bw-keys/src/keystore.rs:114-127`、`crates/bw-keys/src/machine.rs:375-383`、`:396-407`、`bins/bitwarderd/src/hub.rs:137-144`
- **現況**：`biometric_available()` 為 false 時選用 `FileKeyStore`。`finish_unlock` 每次解鎖都無條件把原始 64 位元組 user key 以 base64 寫進 `<data_dir>/keys/<sha256(label)[..8]>.key`，label 固定為 `default`。`lock` 不呼叫 `ks.clear`。
- **影響**：嚴格鎖定模式只在 daemon 端拒絕免密碼解鎖（`hub.rs:424`），金鑰仍在磁碟上、就在加密鏡像旁邊。能讀到資料目錄的人可解開整個 vault，包含備註、TOTP seed、卡片、passkey 與 org key。
- **矛盾點**：`FileKeyStore` 的註解寫「測試/開發用」，`WrapStrength::FilePermissions` 的註解寫「開發/測試退路」，實際卻是所有 Linux 安裝與未啟用 Keychain 的 Mac 的正式路徑。
- **未確認**：安裝版的 launchd plist 是否預設設定 `BW_KEYS_ENABLE_KEYCHAIN=1`，以及 `lock_on_sleep_restart` 的預設值。這決定了實際受影響的使用者範圍。
- **改善方向**：
  - 只在使用者選擇自動解鎖（`lock_on_sleep_restart=false`）或後端確實綁定生物辨識時才封存。
  - 其餘情況在解鎖與鎖定時都呼叫 `ks.clear()`。
  - Linux 改用 Secret Service/libsecret 或 TPM。

---

## 邊緣項目（未驗證）

### B1：`/private/tmp` socket 目錄可被搶佔

- **位置**：`bins/bitwarderd/src/main.rs:220-250`、`bins/bitwarderd/src/service.rs:30`
- **攻擊者**：同一台 Mac 上的另一個本機使用者
- **敘述**：正式預設 socket 是 `/private/tmp/io.bitward.dev/daemon.sock`。daemon 用 `create_dir_all` 建目錄後不檢查擁有者，`set_permissions(0o700)` 失敗也被忽略。另一個使用者可在受害者的 daemon 首次啟動前建立該目錄，之後替換或冒充 socket。client 不檢查 server 的 peer uid，經該路徑送出的 `unlock` 或 `login --password-stdin` 會把主密碼交給對方。
- **改善方向**：建目錄後 `lstat`，要求擁有者是自己、權限 0700、不是 symlink，否則拒絕啟動。更好的做法是改用每使用者專屬路徑（`$TMPDIR` 或 `~/Library`），並讓 client 以 `getpeereid` 檢查 server。

---

## 驗證後排除

| 項目 | 信心 | 排除原因 | 仍建議的加固 |
|---|---|---|---|
| MCP 無 token 時全權 | 2/10 | `bins/bitward-mcp/README.md:13` 與 `docs/ARCHITECTURE.md:413` 明載的設計；範例設定都帶 token；同 uid 行程本來就有同等權限 | 無 token 時拒絕啟動或要求明確 opt-in；修正 README 第 38-39 行「明文唯一去處需 `reveal:*` grant」的說法，註明只適用於 token session |
| GUI 開啟項目 URI 無 scheme 白名單 | 2/10 | `nsh-core` 的 `check_url` 已拒絕 `file`、`javascript`、`data` 等 scheme，宣稱的 `.terminal` 指令執行鏈不成立 | 在 `apps/bitward-gui/src/detail.rs:238` 只允許 http/https；`smb:` 與自訂 scheme 目前仍會開啟 |

---

## 沒有發現問題的區域

- **加密原語**（`bw-crypto`、`bw-keys`、`bw-vault`）：先驗 MAC 再解密、常數時間比較、拒絕無 MAC 的 type 0 降級；IV 與金鑰來自 CSPRNG；金鑰型別 drop 時清零且 `Debug` 已遮蔽。
- **本地儲存**（`bw-store`）：SQL 全部參數化，`ORDER BY` 欄名來自固定 enum，FTS 輸入有引號處理，LIKE 萬用字元有跳脫；blob 路徑限 64 個 hex 字元；檔案與目錄為 0600/0700。
- **`bw-server` / `bw-sync`**：`bw-server` 其實是 Bitwarden/Vaultwarden 的 client，不是 API server。TLS 沒有停用驗證，token 只送往設定的 server，log 不含機密。
- **daemon 其他部分**：兩個 UDS listener 都檢查 peer uid；配對碼為 9 字元、120 秒、單次使用；鎖定狀態下機密檢視、TOTP、autotype、附件、寫入都會拒絕；frame 長度在配置前檢查；launchd 自癒合的輸入只來自 daemon 自己的 argv 與使用者自己的 LaunchAgents。
- **native messaging**：Chrome `allowed_origins` 固定單一 extension ID；`credential.match` 在 LIKE 之後做精確 host 比對，`github.com.evil.com`、userinfo、IPv6 都處理正確；repo 內沒有瀏覽器 extension 程式碼。
- **autotype**：只用 CGEvent，沒有 osascript 或 shell-out；模板解析拒絕未知佔位符。
- **GUI 與 macOS**：原生 Rust GUI，沒有 webview、HTML sink 或 IPC capability 面；附件下載路徑固定在 `~/Downloads` 且有前綴防穿越；entitlements 沒有 `get-task-allow`、`disable-library-validation` 等；沒有 URL scheme、XPC listener 或應用內更新。
- **Android 其他部分**：服務以 `BIND_AUTOFILL_SERVICE` / `BIND_CREDENTIAL_PROVIDER_SERVICE` 保護；`PendingIntent` 為 `FLAG_IMMUTABLE`；資料放在 `noBackupFilesDir`；沒有自訂 TrustManager 或 WebView；Logcat 不含帳密。
- **git 與供應鏈**：292 個 commit 沒有外洩的私鑰或憑證，`keys/` 整個被忽略；樹內兩處 `BEGIN PRIVATE KEY`（`bins/bitwarderd/src/apns.rs:137`、`dev/e2e/pushpath.sh:33`）是同一把 dummy 測試金鑰，已比對公鑰雜湊。CI 只有 `push: main` 與 `pull_request`，不引用 secret。沒有 git 依賴、`[patch]` 或 `build.rs`。pkg 沒有以 root 執行的安裝腳本。

---

## 未達門檻的加固建議

**金鑰與版控**

- `keys/macdev.p12` 權限是 644，建議 `chmod 600`，或匯入 keychain 後刪除。
- `.gitignore` 只靠 `keys/` 目錄名保護，建議加 `*.p12`、`*.key`、`*.mobileprovision`、`*.provisionprofile` 全域 pattern。

**daemon 與授權**

- `Delete{ids}` 與 `Merge{keep, dupes}` 只對第一個 id / `keep` 做授權判定（`agent.rs:213-225`），持有 `mutate:delete item:X` 的 agent 可軟刪其他項目。
- `Fill.AutoType` 以 `Use(Run)`、item `None` 授權，直連 BTP 的 agent 可把任意項目的密碼打進自己的終端機。
- TLS 上的 `Auth::Session` 接受任何 token，包含本機 Interactive 的，沒有比對 session 種類與傳輸方式（`main.rs:608-622`）。
- Enroll 讓 client 自選 session token，`new_session` 會覆寫同 token 的既有項目。
- MCP `vault_reveal` 接受 `field` 參數但忽略，回傳整個 Reveal 檢視。
- AutoType 倒數 3 秒後打進當下有焦點的視窗，不檢查目標。

**網路與 KDF**

- PBKDF2 下限 5,000 次（`kdf.rs:16`，與官方 client 相同），惡意 server 可壓低，可考慮提高到 100k 以上。
- `crates/bw-server/src/profile.rs:355-372` 的 `rebase_if_alias` 會原樣接受 server 回報的 `http://` URL。目前 `probe()` 無呼叫點，接上之前應先拒絕 scheme 降級。
- 附件與 Send 的下載會把 bearer token 送到 server 指定的絕對 URL（`vault.rs:437`、`sends.rs:93`），建議只在同 origin 時附帶。
- Android 接受 `http://` server URL，預設值是 `http://10.0.2.2:18095`（`ui.rs:128`）。

**平台**

- 下載的附件沒有設 `com.apple.quarantine`（`apps/bitward-gui/src/attach.rs:137`）。
- 剪貼簿沒有標記 concealed（macOS `org.nspasteboard.ConcealedType`）或 `EXTRA_IS_SENSITIVE`（Android）。
- `ProviderViewController.swift:243`、`:336` 以 `privacy: .public` 把 username 寫進 unified log。
- AutoFill provider 的「解鎖」按鈕呼叫 `Auth.Unlock{biometric:false}`，是否安全取決於 daemon 對呼叫者的授權，建議一併檢視。
- `AutofillProbeActivity` 以 `exported=true` 出現在正式 manifest，建議移除或限 debug。
- `scripts/pkg-build.sh:186-192` 把 stderr 寫到固定路徑 `/tmp/productsign.err`；`productsign` 失敗時會退回未簽章的 pkg 而不報錯。

**程式碼衛生**

- `SealedKey`（`keystore.rs:36`）、`TokenGrant`、`PasswordLogin`、`TokenBundle`、`NewAccount` 含機密卻 derive `Debug`。目前沒有地方格式化它們，但一行 `tracing::debug!(?x)` 就會洩漏。
- `BW_KEYS_LA_MOCK=pass` 在正式程式碼中可跳過 Touch ID 提示（`keychain.rs:68-69`）。需控制環境變數才能利用，建議限 `cfg(test)` 或 debug build。
