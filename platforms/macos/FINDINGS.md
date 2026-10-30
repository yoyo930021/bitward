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
