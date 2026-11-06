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
