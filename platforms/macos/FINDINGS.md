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
