# FINDINGS — macOS Xcode 骨架（P5 前置）

日期：2026-10-30。主機：macOS 27.0.1 / Xcode 27.1 / xcodegen 2.46.0（brew）。

## 1. 編譯鏈結論
- 選 xcodegen（`project.yml` 為唯一事實來源，`Bitward.xcodeproj` 為產物、一併入庫）。
- 坑 1：`com.apple.developer.authentication-services.autofill-credential-provider` 是受限
  entitlement，XCBuild 在 Manual+ad-hoc（無 Team ID）下硬性索求 provisioning profile，
  `AD_HOC_CODE_SIGNING_ALLOWED` 無解。做法：`CODE_SIGNING_ALLOWED=NO`，由 app target 的
  postCompileScript 由內而外手動 `codesign -s -`（先 appex 後 app）。
- 坑 2：xcodegen 把 `postCompileScripts` 排在「Embed Foundation Extensions」階段**之前**，
  簽章會落在尚未嵌入的殘缺 bundle 上。做法：dependency `embed: false`，腳本自己
  `ditto` appex 進 `Contents/PlugIns` 再簽。
- 坑 3：codesign 以 AMFI 解析 entitlements plist——XML 註解內不得有連續 `--`
  （例如 `--push-app-group`），否則 "Failed to parse entitlements"。
- 驗收：`xcodebuild -project Bitward.xcodeproj -scheme Bitward -destination 'platform=macOS' build`
  从零全量 **綠**（Debug 與 Release 皆）；`BitwardProvider.appex` 隨 .app 產出於
  `Contents/PlugIns`；`codesign --verify --deep --strict` 通過；entitlements 三項與
  `ASCredentialProviderExtensionCapabilities`（Passwords/OneTimeCodes/TextToInsert/
  ShowsConfigurationUI，Passkeys 屬 P5 未宣告）實測都在包內。

## 2. BTP client 冒煙（假 daemon）
- 以 Python 假 daemon 走過凍結流三條路徑：成功（Hello Enroll→Welcome→List{uri,Metadata}
  →Get{id,Reveal}→候選）、`daemonAbsent`（socket 不存在）、`timeout`（1.5s 總預算）。
- 協定細節（對齊 bw-proto serde）：幀 = 4-byte LE 長度 + externally-tagged JSON；
  `Reply` 的 result 在鍵 `outcome` 下（`{"Reply":{"rid":1,"outcome":{"Ok":…}}}`）；
  `Query` 無 serde default，七鍵（text/tag/uri/value/kind/sort/limit）必須全帶。
- macOS 的 `ASExtensionError.Code` **沒有** iOS 的 `credentialNoCredentials`；
  零候選映射到 `.credentialIdentityNotFound`，其餘失敗 → `.userInteractionRequired`（§8）。

## 3. ad-hoc 下 extension 能否被系統列出（實測到哪）
- ✅ LaunchServices 註冊成功：`pluginkit -m -p
  com.apple.authentication-services-credential-provider-ui` 列出 `io.bitward.dev.provider(0.1.0)`；
  系統日誌可見 SafariPlatformSupport `discovered extensions: {id = io.bitward.dev.provider}`。
- ✅ sandbox + app group 在 ad-hoc 下可用：啟動測試 app 後 `~/Library/Group Containers/
  group.io.bitward.dev` 實際被建立（daemon.sock 的落點機制成立）。
- ❌ **但**容器 App 經 launchd 啟動失敗（`INIT, code = 163` spawn failed）：對照實驗證明
  肇因就是該受限 entitlement——同一個最細 SwiftUI ad-hoc app，無 entitlements 可啟動，
  掛上 autofill-credential-provider 即 163。推測 authd 拉起 appex 程序時同樣會被拒
  （未驗，見下）。直接 exec 二進位則不受影響。
- 給 Main 的驗證步驟：
  1. 接 Apple Development 憑證（automatic signing）後 `open Bitward.app` 應可啟動；
  2. 系統設定 → 一般 → 登入項目與延伸功能 → AutoFill（或「密碼」App）確認 Bitward 出現，
     `pluginkit -e use -i io.bitward.dev.provider` 啟用後在 Safari 觸發填充，看 appex 是否被拉起；
  3. daemon `--push-app-group` 落地後端到端：`nc -U
     "~/Library/Group Containers/group.io.bitward.dev/daemon.sock"` 先手工驗幀，再走真 autofill；
  4. 若要在無憑證環境跑 GUI 冒煙，暫除該 entitlement 即可啟動（僅限骨架測試）。

## 4. 對 P5 正式整合的建議
- 簽章鏈是硬前提：受限 entitlement 無 Team ID 不生效；P5 第一件事接 ASC 憑證 +
  `SMAppService`，届时把 project.yml 的 ad-hoc 腳本換回 normal signing（保留腳本註解記錄教訓）。
- pairing uuid 已持久化於 app-group UserDefaults（ad-hoc 下實測可寫入 group 容器），
  Enroll 身分跨啟動穩定；daemon 端 Enroll 落地時以此為 device 錨點即可。
- 骨架目前單次連線 ≤1.5s 無重試；§8「有界重試 ≤1.5s」建議維持單次（autofill 延迟敏感），
  重試語意交給互動路徑，P5 定案。
- 未做（屬 P5）：`prepareCredentialList`（互動清單）、`prepareInterfaceToProvideCredential`、
  OTP/passkey request 分派、`ASCredentialIdentityStore` 寫入（daemon 側）、
  NeedApproval 的批准 UI 串接（現在一律降回 `.userInteractionRequired`，不靜默失敗）。
- 記憶體教訓沿用：client 手刻 POSIX socket、零第三方依賴；Reveal 明文只進
  `ASPasswordCredential`，不落地日誌。

## 5. P5 真機整合（2026-11-06 完成）
端到端已通：Safari「密碼自動填寫」→ 系統拉起 appex → 互動清單（BTP over app-group socket）→
點選 → Reveal → `completeRequest(expired=false)` → 欄位填入。五個實測坑，全部要記：

1. **macOS 開發裝置的 UDID 不是 IOPlatformUUID**。xcodebuild 要的註冊 ID 是 ECID 格式
   （本機為 `00006050-001C315C02F9401C`，錯誤訊息會直接吐出來）。用硬體 UUID 註冊到 portal
   後 xcodebuild 仍說「device isn't registered」，且誤導你往帳號快取查。
2. **簽章鏈可全程脫離 Xcode GUI 用 ASC API 建**：`asc certificates create
   --certificate-type MAC_APP_DEVELOPMENT --generate-csr`（私鑰留 `keys/`，p12 匯鑰匙圈）→
   `bundle-ids create`（platform 值為 `MAC_OS`）→ `bundle-ids capabilities add
   --capability AUTOFILL_CREDENTIAL_PROVIDER` → `profiles create MAC_APP_DEVELOPMENT` →
   `profiles local install` → project.yml 切 Manual + `PROVISIONING_PROFILE_SPECIFIER`。
   AutoFill capability 沒開時 profile 校验錯誤會明確點名 entitlement。
3. **app-group 名稱必須帶 Team ID 前綴**：`group.io.bitward.dev` 被 containermanagerd 擋
   （REJECTED：「Group containers identifiers should be prefixed by requestor's team ID」），
   改 `group.8V5224A99M.io.bitward.dev` 後 socket 容器才真正可用。daemon 端
   `--push-app-group` 與 Swift `BitwardGroup.id`、兩份 entitlements 四處要一起改。
4. **ViewBridge 面板尺寸取自 fittingSize/preferredContentSize**：清單 view 只有錨點約束、
   沒釘死自身尺寸時，面板以 `remote view frame {{0,0},{0,0}}` 出現——資料都拿到了但使用者
   看到的就是「點了沒反應」。`showList`/`showNote` 都要給 view 固定寬高 + `preferredContentSize`。
5. **Release build 的 `Logger.debug` 預設不發出**：整輪除錯以為「系統沒呼叫我們的路徑」，
   實際是日誌被層級吃掉。骨架期一律 `log.notice`，觀測別省這一行。
   另：`log stream --level debug` 只放寬顯示，救不了 emission 端。

其他：
- 互動清單的 metadata 視圖不含 username（分級表屬 Secret），清單第二欄改顯示首个 uri；
  username 的展示層級屬 P6 分級討論。
- daemon 重啟後 vault 為 `AuthLocked`：List（加密 metadata）仍可服務，Reveal 才要求解鎖——
  provider 依契約降回 `.userInteractionRequired`，Safari 保持氣泡不崩不卡，分級語意如設計。
- 公證（notarization）不是本地開發簽名的硬門檻：Apple Development + 本機 profile 的
  credential provider 在 macOS 27 可被 authd 正常拉起；`securityd` 的
  "Error checking with notarization daemon: 3" 是噪音，曾誤導一輪排查。
- `platforms/macos/probe/`：最小 credential provider（無 daemon、無 socket），
  用於切割「我們的程式碼 vs 環境/簽章」問題，留作日後回歸工具。

## 6. P6 批次（OTP／解鎖引導／保存路徑調查）
- **macOS Safari 不向第三方 provider 發 OTP 請求**：`autocomplete=one-time-code` 欄位
  不出現鑰匙圖示、無 `ASOneTimeCodeCredentialRequest`（驗證碼建議是 Apple 簡訊中繼專有路徑）。
  1Password 在 macOS 的互動模型是**清單多列一行「驗證碼」**——本專案照做：Login 項目在清單
  產生 password + TOTP 兩列，選 TOTP 列以 `Use(TotpCode)` 現算代碼、經
  `ASPasswordCredential(user:"", password:code)` 填入目前欄位。真機驗證：
  `totp ok → completeRequest expired=false`，代碼與 RFC 6238 獨立計算一致。
- **Locked 分級如設計**：daemon 鎖定下 List（加密 metadata）照常服務，Reveal/TOTP 才回
  `Err(Locked)`。清單選取撞鎖 → 面板轉「Vault 目前鎖定 ＋ 解鎖鈕」（裝置斷言免密解鎖）→
  `unlock ok` → 自動回清單。BTPError 拆出 `.locked`（WtpError externally-tagged 的 unit
  variant 是字串 "Locked"，struct variant 是單鍵物件——Err 形態解析要兩式都吃）。
- **保存密碼在 macOS 系統路徑走不通（暫）**：`prepareInterface(for: ASSavePasswordRequest)`
  為 `API_UNAVAILABLE(macos)`（iOS/visionOS 26.2 獨有）。系統級「儲存此密碼」對第三方
  provider 在 macOS 根本沒開門——與本專案「官方 macOS 支援缺席」的前提互為表裡。
  目前保存走 CLI `bitward new`；appex 保存等 Apple 補 API。
- **daemon 修復（真機踩出）**：
  1. `Auth::Session` 命中已被 lock 撤銷的 session 時原本照發 Welcome、到 Invoke 才回
     StaleEpoch——thin 端快取的殭屍 token 讓「重新執行指令即可」的承諾永不成立（每次重跑
     都重蹈同一死 session）。改為 Hello 階段即拒（Denied），CLI 既有的「刪檔重 Enroll 一次」
     路徑自然接住。真機驗證：lock 後 CLI status 自愈。
  2. `totp()` 對無 seed 項目誤報 `Locked`（`ok_or_else("no totp seed")` 折進
     `.map_err(|_| Locked)`）；seed 存在性不需金鑰，檢查前移回 `Denied("此項目沒有
     TOTP seed")`。

## 7. P7 批次（passkey／批准中心／identity store）
- **authData 佈局是 Safari 收單的全部**：`attested_credential_data` = AAGUID(16) ‖
  credIdLen(u16 BE) ‖ credId ‖ COSE_Key——rpIdHash 只在 authData 前綴出現一次。
  初版多塞了一遍 rpIdHash 且 credIdLen 用 u32（198B vs 正確 164B），Safari 客戶端直接
  NotAllowedError（連 finish POST 都不發）。COSE_Key 鍵序必須 canonical（1,3,-1,-2,-3；
  serde_cbor 的 BTreeMap 按整數值排序剛好不合）。獨立解析（cbor2/SimpleWebAuthn）
  與產生端常量函數要**分開寫測試**，否則自證循環。
- **Apple challenge 慣例**：provider 只拿得到 `clientDataHash`，clientDataJSON 的
  challenge 欄位填 b64url(clientDataHash raw bytes)、JSON 模板
  `{"type":...,"challenge":...,"origin":"https://<rpID>","crossOrigin":false}` 需逐字元
  對齊系統重建——本地 http RP 會因 origin（http+port）對不上而假性失敗，非實作 bug。
- **註冊確認時機**：互動路徑不可立即 `completeRegistrationRequest`——系統在等「人同意」，
  搶跑判定 user denied。確認按鈕內嵌於系統 sheet（ViewBridge remote view：**合成點擊
  （AXPress 與物理座標都打不進）；真人可按**——自動化到此為界）。
- **系統 Helper 崩潰（macOS 27 實測）**：`_ASCredentialAuthenticationViewController`
  `presentViewControllerAsSheet:` 在無 active display（螢幕睡眠）時 NSAssertion 崩潰。
  除錯前先 `caffeinate -u`；「Error checking with notarization daemon: 3」仍是噪音。
- **ASCredentialIdentityStore 可用**：容器 App（帶 autofill entitlement）
  `replaceCredentialIdentities` 落地
  `~/Library/Application Support/com.apple.AuthenticationServices/CredentialProviders/<bundle> (<team>)/Identities/Identities.db`。
  首呼可能報 "database could not be opened"（建檔競態），後續成功——重試即可。
  鎖定期間 metadata 是密文信封，寫入的 user/service 欄會是密文（解鎖後下一輪刷新為明）。
- **批准中心閉環**：pair code grant 支援 `approve` 修飾（`reveal:secret all approve`）→
  請求端阻塞 → 容器 App 輪詢 ListPending → 批准/拒絕（Deny 立即釋放，不等 120s）。
  真機閉環驗證通過。
- **macOS 27 容器 App 首窗**：背景 session `open` 啟動的 WindowGroup app 不自動建窗
  （此前視窗全靠 savedState 還原）；單例 `Window` scene + `.defaultLaunchBehavior(.presented)`
  修正。無窗進程會被 TAL 自動終止——首窗是生存問題不是美學問題。

### P7-C passkey 收單狀態（截至本批結束）
已確立：
- daemon 核心正確——獨立 SimpleWebAuthn/cbor2 round-trip 全驗（authData 164B、
  COSE canonical、counter、簽名）。
- Safari 端鏈路可達 `completeRegistrationRequest expired=false`（UI 流：
  Register → 系統面板「繼續」→ 內嵌「儲存 passkey」→ provider LAContext UV）。
- 補 UV 前已測（無 UV）與補 UV 後，WebKit 均靜默取消（Code=1000/1001），
  **finish POST 從未發出** → 拒因在 WebKit 收單層，非伺服器。
未解（下一步診斷程序，需人在場）：
1. **取得 Safari 實際送出的 clientDataJSON 原字節**——需要一个 Safari 接受的
   https RP（自簽憑證 Safari 直接拒開、無「繼續」選項；需將 CA 進系統鑰匙圈：
   `sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/
   System.keychain /tmp/wp_rp/cert.pem`，本地 RP 已備好於 https://localhost:8443
   並會 log `CLIENTDATA` 行）。
2. 拿到後 diff daemon `client_data_json()` 構造（challenge/origin/鍵序），
   讓簽名覆蓋位元組與系統重構一致——這是 thin provider 簽名被 RP 驗通的
   最後一塊（Apple 慣例 origin=`https://<rpID>` 無 port；頁面帶 port 時必對不上，
   推測即 webauthn.io（無 port https 實域）輪次仍被拒之外的環境變因）。
3. 對照實驗：裝官方 Bitwarden beta（PR #22624 已開 macOS passkey provider）或
   1Password 走同流程——若同樣 NotAllowedError 則為 macOS 27 系統支援度問題。

### P7-C2 真機閉環（2026-11-07 凌晨，註冊＋斷言雙向通過）
webauthn.io 實測：註冊 `New credential added!`；斷言日誌
`passkey credential list rp=webauthn.io allowed=1 → assertion confirmed →
completeRequest expired=false` → 伺服器驗簽成功（同時證明 counter 事務與
DER/hash 直簽修復生效）。本輪新增的實測坑：
- **macOS 斷言入口是帶參數變體**：系統呼 `prepareCredentialList(for:requestParameters:)`
  （macOS 14+，ObjC `prepareCredentialListForServiceIdentifiers:requestParameters:`），
  不是舊密碼版 `prepareCredentialList(for:)`。只覆寫舊版時新入口落到基類預設
  （不作為）→ Safari 無限等待（「卡住」）。
- **SE 金鑰三連坑**（每個都是硬錯誤、錯誤訊息被 os_log `<private>` 遮蔽，NSLog
  改自訂 Logger 才看見）：
  1. macOS `SecAccessControlCreateWithFlags` **拒 `userPresence`**（-50：僅可併
     ApplicationPassword/PrivateKeyUsage；iOS 專屬旗標）。生物要求由
     `biometryCurrentSet` 承擔——對 biometry-bound SE 金鑰 `SecKeyCreateSignature`
     本身就會觸發 Touch ID。
  2. ThisDeviceOnly 系列 accessibility 類**不能跨 keychain access group 共用**。
  3. SE 私鑰柄不支援 `SecKeyCopyExternalRepresentation`（-4 export not
     implemented）——先 `SecKeyCopyPublicKey` 再匯出。
- **cancel(.failed) 會把系統面板卡住不關**；錯誤路徑用 `.userCanceled` 才走關閉。

## 8. W1–W4 收尾批次（identity store 失效／LaunchAgent 常駐／p95 實測）
- **identity store 分級失效**：容器 App 依 `Welcome.state` 分派——Unlocked 才
  replace 明文候選，否則 `replace([])` 清空（真機雙態：25 筆 ↔ 0 筆）。
- **socket 落點試走 `/private/tmp/io.bitward.dev/`（0700 目錄 + 0600 sock +
  peer-uid）**：**觀察到的事實**是——terminal session 拉起的 daemon 能 bind/connect
  group container 的 sock；launchd daemon 與沙盒 App 對 group 路徑的 bind、
  沙盒 App 對 tmp sock 的 connect 都實測 EPERM（探測法：App init 內 connect +
  uiLog 記 errno——**檔寫探測會因沙盒重定向+try? 吞錯而假性消失，教訓**）。
  **根因未隔離**（未逐一排除簽章歸因/沙盒 network 權限/容器政策的各自貢獻），
  故 tmp 只是繞道、非「唯一活路」；且沙盒 connect tmp 亦 EPERM → **provider 端
  仍必須走 group sock**。常駐形態的正解候選＝SMAppService 歸因（見下）。
- **LaunchAgent 三條路現狀**：
  · daemon 自裝（`bitwarderd --service install|uninstall|status`，非沙盒 CLI 寫
    ~/Library/LaunchAgents + launchctl bootstrap）——能用：kill -9 → 3 秒復活 →
    客戶端可連；但該 daemon 只能綁 tmp sock（沙盒 provider 連不進 tmp）→
    僅對 terminal 型客戶端有效。plist 支援 BITWARD_DATA_DIR 環境透傳。
  · SMAppService.agent(plistName:) + **BundleProgram/__CFBundleIdentifier 歸因
    plist**（Contents/Library/LaunchAgents/；plutil lint OK、無標籤衝突）——
    disable→enable 乾淨重測：**status=notFound、register 拋 EINVAL**；早前
    EPERM 確係 plist 形態錯（$__AppDir__ 無 BundleProgram），形態修正後錯誤
    轉到 BTM 層。殘餘假說：**ditto 直拷的 bundle 未走正式安裝生命週期，
    BTM 登記可能要重登入/正式安裝**。**未結案，開為 P5' 常駐專項**。
  - **2026-11-07 實驗結果（重登入已執行）**：Label 不合規（`io.bitward.daemon`
    非 bundle-ID 前綴）是 EINVAL 的** proximate 原因**，改 `io.bitward.dev.daemon`
    後 register 成功、狀態頁現「已啟用」。但**重登入後 BTM record 消失**
    （smd: -95 record not found）、job 未載入、註冊未持久——「重登入即癒」
    **否證**，收斂到「非正式安裝（ditto/無公證）不被 BTM 生命週期接受」，
    解藥＝Developer ID 公證＋正式安裝流程，屬上架批次（P4' 簽章公證）。
    **G2 常駐案就此收案**：本機 ad-hoc/ditto 組建下，daemon 存活依賴手動/腳本
    啟動；legacy `--service install` 同牆（未再測，同一 BTM 閘門）。
  · mainAgent(url:) 非真 API（編譯期即糾）。
- **bind_sock 單實例守衛**：flock(.lock 檔，先於 unlink) → unlink 屍体（錯誤不吞，
  只饒 NotFound）→ mkdir -p + 0700 → bind。教訓：無守衛時前台測試實例把 launchd
  daemon 的 sock 位址蓋掉，退出後全员 ECONNREFUSED 且症狀酷似 daemon 掛掉。
- **R2 驗收**：kill -9 daemon → 3 秒 launchd 復活 → 客戶端可連（驗「連得上」
  而非「pid 存在」）。
- **p95 實測（benchmark-checklist）**：計畫宣稱「UDS 短命 client 呼叫 p95 < 50ms」
  （對照官方 bw CLI 1–5s、issue #2741）。主數字＝使用者可感路徑
  **`bitward status` 端到端**（進程 spawn + connect + 呼叫 + stdout 內容斷言
  必須含 Unlocked，否則計錯）：**p50 4.7ms、p95 5.2ms、max 5.9ms、0/60 錯**。
  in-process 純 UDS 環路為地板值（p50 0.09ms/p95 0.13ms，5×200 次 0/1000 錯）。
  量測環境：launchd→terminal demo daemon、demo vault、載入 1.9、release build。
- **scripts/dev-install.sh**：cargo release → xcodebuild → ditto → 強制重拷＋重簽
  helper＋功能探測 → 裝 agent → smoke connect。存在理由：Xcode script phase 增量
  不可靠（xcodegen 2.46 無視 alwaysOutOfDate），本會話三次被殭屍二進位誤導診斷。

## 9. G2/G3 終案（接續 §8 的兩條尾巴）
- **G3 text-to-insert＝幽灵活動，非欠債**：macOS SDK 的 AuthenticationServices
  全目錄無 `ASTextToInsert*` 符號（該 API 為 iOS/visionOS 18 限定）——原 plist 的
  `ProvidesTextToInsert` 是從 Bitwarden iOS 版照抄，macOS 系統永遠不會發此請求。
  撤宣告（W4）即最終形態，無實作項。
- **G2 常駐收斂到 BTM 生命週期**：SMAppService.agent（BundleProgram 形態）
  register 後 `~/Library/LaunchAgents` 連檔案都沒落地、status=notFound、再
  register 拋 EINVAL——ditto＋lsregister 的「非正式安裝」疑似不被 BTM 接受。
  **判別實驗（需使用者）：重登入一次**→ 若 job 出現即屬實；否則剩 MAS 分發
  限定假說。現行可用常駐＝`bitwarderd --service install`（legacy LaunchAgents，
  kill -9 自愈已驗），其群組 socket 限制見 §8。

## 10. 正式安裝管線＋BTM 判定實驗（2026-11-07，pkg 批次）
- **新增 `scripts/pkg-build.sh`（冪等）**：cargo release → xcodebuild Release →
  staging（殭屍二進位保險沿用 dev-install：強制重拷 helper＋重簽＋功能探測；
  **另發現 helper 重簽改變 bytes 後必須重封 App 外層**，否則 codesign
  --verify --deep --strict 對新裝 bundle 會炸）→ `pkgbuild --root`（component.plist
  `BundleOverwriteAction=update`，同版本重裝也覆蓋）→ `productbuild --synthesize`
  ＋`--distribution` → `dist/Bitward-<version>.pkg` → `sudo -n installer`，
  失敗 fallback `osascript do shell script … with administrator privileges`
  （SecurityAgent 彈框，使用者按一次密碼/Touch ID）→ 斷言（pkg 簽章（有簽名才查）、
  bundle 深驗、/Applications 落地、receipt `io.bitward.dev.pkg`、helper 功能探測）
  → `--experiment` 段做 BTM 判定（AX 按「啟用」＋launchctl/log/BTM db 取證）。
- **工具鏈坑（macOS 27.2／Xcode 27.2 實測）**：
  · `productbuild` 不吃 `--component-plist`/`--install-location`（那是 `pkgbuild`
    的選項；productbuild component 模式只有 positional install-path）→
    component.plist 要生效必須走 `pkgbuild --root` 再 `productbuild --distribution`。
  · `productsign` **拒絕一切 Code Signing EKU 身分**（含 Mac Developer
    LUL69RR52T 與 Apple Distribution）：「An installer signing identity
    (not an application signing identity) is required for signing flat-style
    products.」本機六張憑證 EKU 全是 Code Signing → pkg 以未簽名落地
    （`installer -target /` 本機不吃 pkg 簽章）；上架批次需另申請
    **Developer ID Installer**（公證則要 ASC API key，見腳本 BW_NOTARIZE 段）。
- **BTM 判定實驗（pkg 正式安裝後，第一輪）：「非正式安裝不被 BTM 接受」假說被駁
  ——pkg＋receipt 正式安裝後 register 照樣 EINVAL。** 差分矩陣（全部實測）：

  | bundle 來源 | 舊兄弟 plist | Standard*Path | 位置 | register 結果 |
  |---|---|---|---|---|
  | Xcode 封裝（run6 裝 /Applications） | 有 | 有 | /Applications | EINVAL |
  | 管線重封（staging） | 無 | 有 | repo dist | EINVAL |
  | 純 Xcode 封裝（btm-sink2 複製） | 無 | 有 | DerivedData | EINVAL |
  | 管線重封（staging／sink 複製） | 無 | **無** | repo／DerivedData | **EPERM** |

  · 舊兄弟 plist（`io.bitward.daemon.plist`，增量建置殘留）**不是** EINVAL 成因
    （有無皆 EINVAL），但仍是必須清的髒（project.yml phase 已改 `rm -rf "$LA"`
    再拷＋pkg-build.sh staging 以源檔為唯一事實重建該目錄）。
  · EINVAL 與 plist 的 `Standard{Out,Error}Path` 一一對應（4/4），移除後錯誤推進
    為 EPERM（2/2）。smd log 每次 EINVAL 嘗試都打
    「SMAppServiceFactory: Not allowed to use StandardInPath, StandardOutPath,
    and StandardErrorPath keys from AppSandboxed submitters」→ 源檔 plist 已刪
    這兩鍵（沙盒 App 送件不給指定 stdout/stderr 落點；daemon 日誌本就該走 os_log）。
  · EPERM 閘門**已隔離**（最終判定實驗，/Applications 裝修正後 bundle、
    `--experiment-only`）：smd 明打
    「`BTMManager registerLaunchItemWithAuditToken: error: SMAppService target
    executable must be sandboxed because the app is sandboxed` → Register
    rejected by BTM」。即：**容器 App 是沙盒 App，SMAppService 就要求
    BundleProgram 目標（Contents/Helpers/bitwarderd）也沙盒化**，而
    helper.entitlements 目前無 `com.apple.security.app-sandbox` → EPERM。
    register 被拒時 BTM store 仍留 record 殘跡（strings 見
    `file:///Applications/Bitward.app`＋DR＋Label）但 status()=notFound、
    `launchctl print gui/501/io.bitward.dev.daemon` 查無 job；unregister 則報
    -95 record not found。
  · 判定：**「非正式安裝」假說不足以解釋 G2**——pkg＋receipt 下 EINVAL、EPERM
    依序解鎖到同一堵沙盒牆。下一批的解法二選一（語意改動，超出本切片）：
    (a) helper 加 app-sandbox＋temporary-exception（/private/tmp sock、資料目錄）
    ＋沿用 app-group entitlement，走 SMAppService 正道；(b) 容器 App 撤沙盒
    （牵動 P5 provider 鏈，得不償失）。
  · 殘留矛盾（老實記）：§8 的 10:46 成功是用**含 Standard*Path**、helper 未沙盒
    的同型 bundle register 上去的（status 曾現「已啟用」）——本 session（11-07
    10:39 boot）無法重現該成功，且上述 smd 政策行在每次嘗試都出現。若使用者
    重登入後 `launchctl print gui/501/io.bitward.dev.daemon` 出現 job，則
    「先註銷再重登」可能是 BTM 卡死的解藥；請見交付之重登入驗證步驟。
- **本機現況＋待辦（寫給下一次 session 的你）**：`/Applications/Bitward.app`
  ＝修正後 bundle（單 plist、無 Standard*Path），但 **receipt 是 run6 舊 payload**
  （23:47 安裝；之後因授權框無人按，改 `ditto` 手動換裝同產物）。要還原一致性：
  `sudo installer -pkg dist/Bitward-0.1.0.pkg -target /`（pkg 已含修正後 payload）。
  重登入驗證步驟（G2 正解判定，需使用者）：重登入 → `open -a Bitward` →
  狀態頁按「啟用」→ 若顯示「已啟用」或 `launchctl print gui/501/io.bitward.dev.daemon`
  有 job＝沙盒牆外的 BTM 卡死被重登解除；仍 EPERM＋smd「must be sandboxed」
  ＝必須先做上面 (a) helper 沙盒化才有閉環。`scripts/pkg-build.sh
  --experiment-only` 可重複跑實驗段不再觸發授權。
- **helper 沙盒化切片（同夜，Main 追加）**：
  · 裸二進位（Contents/Helpers/bitwarderd）加 app-sandbox：register 過（狀態頁
    「已啟用」、BTM uuid 落地、launchd 收單），但 spawn 後 dyld
    `libsystem_secinit _libsecinit_appsandbox.cold.6` **SIGTRAP**（terminal 與
    launchd 皆掛；containermanagerd query 後即退）。換 reverse-DNS 簽章識別碼
    （-i）也無解——**裸二進位沒有 bundle 身分，沙盒容器建不起來**。
  · 正解形態（已落地 main 線）：巢狀 `Contents/Helpers/BitwardDaemon.app`
    （Resources/BitwardDaemon-Info.plist＋daemon.entitlements：sandbox＋
    application-groups＋network.client＋/private/tmp 絕對路徑例外；
    helper.entitlements 維持非沙盒供裸二進位/legacy 用）。沙盒 daemon
    **過 secinit、能被 launchd 跑起來**（Mac Developer 簽即可，SIGTRAP 牆只在
    裸二進位形態）。
  · 沙盒執行期語意（實測）：容器＝`~/Library/Containers/io.bitward.dev.daemon`
    （依 bundle ID，非 Main 預設的 App 容器）；預設 data_dir/sock 拼出 110 字元
    ＞ UDS SUN_LEN(104) → daemon exit(1) 迴圈（「path must be shorter than
    SUN_LEN」）。修：main.rs `real_user_home()`（getpwuid 回真 home，沙盒內
    $HOME 是容器路徑）給 group sock 用＋plist args 補
    `--sock /private/tmp/io.bitward.dev/daemon.sock`。沙盒內綁容器 sock OK；
    **綁 /private/tmp 即使有 temporary-exception 仍 EPERM**（seatbelt 對
    unix-bind 只放行容器內，檔案例外不覆蓋 network-bind）→ 沙盒形態的
    CLI/tmp sock 路徑不可用，provider 用的 group sock 綁定能否放行**未驗**
    （需先解 SUN_LEN 後再測；§8「沙盒 App 綁 group EPERM」同牆疑慮仍在）。
  · **分發形態決策點（給上架批次，smd 原文「because the app is sandboxed」
    ＝沙盒要求是連鎖的，只在送件 App 沙盒時成立）**：
    (MAS 路) App 留沙盒→helper 必須沙盒（BitwardDaemon.app 形態）→還得跨過
      沙盒 unix-bind 牆（tmp/group sock 皆 EPERM 風險）→可能改 XPC/Mach 服務。
    (Developer ID 直裝路) App 拿掉 app-sandbox→helper 免沙盒→裸二進位即可
      常駐。本機以临时建構驗證（dist/stage-nosb：App 去 sandbox＋BundleProgram
      指回裸二進位）：**register 通過、狀態「已啟用」、launchd 開始 spawn**
      ——secinit 牆消失；但 spawn「failed init」0 秒 exit（runs++循環），
      嫌疑＝taskgated「Disallowing bitwarderd because no eligible provisioning
      profiles found」（profile 不含 application-groups）→ 直裝路的下一道閘是
      **重產含 App Groups 的 provisioning profile**（portal 動作，非本機）。
    兩條路的共同前提仍是正式簽章批次。
- **本機收尾狀態**：/Applications＝mainline staging 產物（沙盒 App＋雙 helper）；
  SMAppService job 已 bootout（未註冊）；legacy LaunchAgent 未裝；
  demo daemon（pid 8934）活著，但 group `daemon.sock` 檔案現指向已死的
  手動實例 inode（我實測綁定權限所留），**重啟 demo daemon 才能恢復 group sock
  服務**（使用者方便時）。readpath／pushpath e2e 全綠（未沙盒 dev 形態不受影響）。

## 11. Developer ID 正式憑證批次（2026-11-08，G2 兩分叉復測）
- **管線參數化（契約 1，commit 4d73c37）**：`BW_SIGN_ID`／`BW_INSTALLER_ID`／
  `BW_FORM=sandbox|direct`／`BW_NOTARIZE`／`BW_PROFILE`（見腳本頭註解）。預設路徑
  （Mac Developer＋沙盒＋降未簽 pkg）全管線綠；`dev/e2e/signing.sh`（6cfcb09）
  為可重跑斷言（逐 Mach-O 身分／hardened／profile 剝除／pkg EKU／staple／spctl）。
- **鑰匙圈牆與解法**：p12 導入的舊 DP key bag「devid」ACL 只放行 `apple-tool:`，
  codesign 每發彈「想存取鑰匙圈中的密碼『devid』」——空密碼按「允許」無效會循環
  重彈（實測）；無簽章 CLI 摸不到 DP 項（SecItemDelete → -34018）、macOS 27
  Keychain Access.app 是無視窗空殼、`set-key-partition-list` 需登入密碼。**正解＝
  專用 signing keychain**：`/tmp/devid/signing.keychain-db`（`-A` 開放 ACL 導入
  cert＋PEM 鑰、`set-keychain-settings -t 0` 免自動鎖、放 search list 頭），
  codesign／productsign 全程免彈（productsign log 實拍 `from keychain
  /private/tmp/devid/signing.keychain-db`）。密碼在 `/tmp/devid/kcpass`——**交付：
  鑰匙圈＋kcpass＋profile 搬到 ~/.asc/keys 並清 /tmp**（含 /tmp/devid/*.key 私鑰）。
  另抓出腳本本體無聲早逝根因：`set -euo pipefail` 下 `P8=$(ls 缺glob… | head -1)`
  的 ls 非零狀態會經 pipefail 傳到賦值行斃掉整段（notarytool 根本沒跑）——已加
  `|| true` 包護（實測：修後公證段正常送出）。
- **公證**：notarytool 提交 `f68de3c4-8f49-4e62-aed1-f005398bdd15`（signed pkg，
  Developer ID Installer＋時間戳），收案時仍 In Progress；bg 收單迴圈會自動
  `stapler staple`＋`spctl -a -t install`（注意：該提交對像為嵌 profile 前位元組，
  ticket 只對舊摘要有效——最終產物以管線內重跑為準，見上條根因修正）。
- **契約 2 判定：Developer ID 直裝要不要 profile？→ App 要，但原因不是 App Groups**：
  無 profile 的 direct 產物 `open` 即 INIT 163（launchd spawn 拒）；TN3125 明列
  `com.apple.security.application-groups` 在 macOS 屬 unrestricted（裸 helper 免
  profile），真正把 App 打死的是 `keychain-access-groups`＋
  `com.apple.developer.authentication-services.autofill-credential-provider`
  （restricted）。解法已入管線：`asc --profile lamys`（API key 走檔案、避鑰匙圈框）
  `profiles create --profile-type MAC_APP_DIRECT --bundle XNW6LLZJU7（resource id，
  非 reverse-DNS）--certificate N2D9VUTK75` → 「Bitward Developer ID」**VBX7P3TXC9**
  （到期 2044-11-03；allowlist 含 group.8V5224A99M.io.bitward.dev、8V5224A99M.*
  keychain、autofill provider、aps production）→ `BW_PROFILE` 嵌 App 重簽 →
  **INIT 163 解除、App 正常啟動（實測）**。appex 屬另一 App ID（io.bitward.dev.provider）
  需另產同型 profile（provider 真機填充前置；不影響 register/spawn）。
- **G2 direct 分叉終態（本批止步點）**：register 仍被 smd 拒
  「target executable must be sandboxed because the app is sandboxed」——但程序實測
  **非沙盒**（`ps -E` HOME＝真 home、簽章 entitlements 無 app-sandbox）。判定＝
  **BTM store 殭屍 record 污染**：舊 record 帶 Mac Developer requirement 串
  （strings 實拍），新 bundle 的 unregister 報 record not found（log 實拍）清不到它。
  移開 `~/Library/Containers/io.bitward.dev`（→ `.bak-directfork`）無改善。
  **交付指令（需使用者）**：重登入 → `open -a Bitward` → 狀態頁按「啟用」→
  `launchctl print gui/501/io.bitward.dev.daemon` 有 job＝殭屍 record 假說成立、
  direct 分叉閉環；仍拒→ `sudo` 清 `/var/db/com.apple.backgroundtaskmanagement/
  BackgroundItems-v18*.btm` 或查 taskgated log 的「no eligible provisioning
  profiles」是否對裸 helper 復現（application-groups 屬 unrestricted，預期不復現）。
- **沙盒分叉（MAS 形態）正式簽章復測**：本批未跑（預算界）；指令就緒：
  `BW_SIGN_ID=152E4509D92E1F1CDC884E0D7A022A2F0F224B1D BW_INSTALLER_ID=AECAA36E20943AEA428C9643643DAD2C1D5459BD BW_FORM=sandbox BW_PROFILE=/tmp/devid/bitward-devid.provisionprofile bash scripts/pkg-build.sh`。
  預期過 smd 沙盒連鎖閘（目標已是沙盒 daemon.app），下一牆仍是沙盒 unix-bind
  group sock（§10 seatbelt 判定，形態無關）。
- **APNs（契約 3）**：`asc web sign-in-keys list` → portal auth keys **空**；
  create 僅支援 Sign in with Apple 型——**無 asc 產 APNs「Signing key for
  provider」路徑**，上架批次需 portal UI 產製（daemon 端 BW_APNS_* 注入已由
  pushpath e2e 驗證）。
- **本機收尾**：/Applications＝direct 產物（Developer ID＋VBX7P3TXC9＋裸 helper
  BundleProgram）；SMAppService 未註冊（殭屍 record）；demo daemon 現為 pid 51819
  （8934 已沒），其 group `daemon.sock` 路徑被我 unlink（清殭屍 sock 時誤判其已死），
  重登／重啟 daemon 即重建。readpath／pushpath 全綠。
