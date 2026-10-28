# macOS Password Provider extension 作為 Thin client 可行性

研究日期：2026-10-28。所有結論附來源；查不到者標 [推測]。

## 0. 名稱與前提更正
- 任務中寫的 extension point `com.apple.authentication-services.password-provider` 與實際不符：Bitwarden iOS 與 macOS 雨邊 extension 的 Info.plist 都宣告 `com.apple.authentication-services-credential-provider-ui`（principal class = `ASCredentialProviderViewController` 子類）。"Password Provider" 是系統設定（AutoFill & Passwords）的產品用語，不是 extension point ID。
  - https://raw.githubusercontent.com/bitwarden/clients/main/apps/desktop/macos/autofill-extension/Info.plist
  - https://raw.githubusercontent.com/bitwarden/ios/main/BitwardenAutoFillExtension/Application/Support/Info.plist
- 時間軸（Apple 文件 availability metadata）：
  - `ASCredentialProviderViewController`：macOS 11+（https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller ）
  - `ASPasswordCredentialRequest`：macOS 14+（https://developer.apple.com/documentation/authenticationservices/aspasswordcredentialrequest ）
  - `ASOneTimeCodeCredentialRequest`（OTP）：macOS 15+/iOS 18+（https://developer.apple.com/documentation/authenticationservices/asonetimecodecredentialrequest ）
  - 系統設定選第三方 credential provider：macOS 13+（Apple Platform Security, https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web ）
  - 即「passwords 能當 provider」macOS 14 Sonoma 起、完整含 OTP/Passwords app 是 macOS 15 Sequoia——與任務前提一致。

## 1. API 面與執行模型
- 能力宣告：`ASCredentialProviderExtensionCapabilities`（ProvidesPasswords / ProvidesPasskeys / ProvidesOneTimeCodes / ProvidesTextToInsert / ShowsConfigurationUI / SupportsCredentialExchange / SupportsGeneratePasswordCredentials 等）。Bitwarden iOS 已全部啟用：https://raw.githubusercontent.com/bitwarden/ios/main/BitwardenAutoFillExtension/Application/Support/Info.plist
- Entitlement：`com.apple.developer.authentication-services.autofill-credential-provider` 要同時掛在容器 App 與 extension（Apple 文件步驟 1：https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller ）。1Password 的 FR 研究也指出缺 `ProvidesPasswords`/`ProvidesOneTimeCodes` 就不會被系統列出（https://community.bitwarden.com/t/register-as-macos-password-provider/93723 ）。
- 啟動時機：系統在使用者觸發 AutoFill 時按需啟動 extension 獨立程序。兩條路徑：
  1. 快速路徑 `provideCredentialWithoutUserInteraction(for:)`：成功直接 `extensionContext.completeRequest(withSelectedCredential:)`；無法就回 `.userInteractionRequired` 錯誤，系統改開互動 UI（`prepareCredentialList` / `prepareInterfaceToProvideCredential`）。此雙階段設計見 Apple 文件與第三方深度解析（https://www.panicvault.org/apple/credential-provider-extensions/ ）。
  2. 設定路徑：`prepareInterfaceForExtensionConfiguration()`（使用者在 Settings 啟用時）；容器 App 也可用 `ASSettingsHelper.requestToTurnOnCredentialProviderExtension` 請求開啟（macOS 14+，且有 10 秒冷卻限制：https://developer.apple.com/documentation/authenticationservices/assettingshelper ）。
- 容器 App 未執行能否服務：**API 上可以**——extension 與 App 共享 app group 容器與 keychain access group，建議清單（`ASCredentialIdentityStore`）存的是非機密 metadata，由 App 事先寫入，「iOS、iPadOS 和 macOS 在使用者選擇填充時與 extension 溝通取得密碼」（Apple Platform Security, sec6319ac7b9）。實務上 macOS 兩家現成案例都選擇讓主 App 常駐（見 §2/§3），所以「App 不在也能服務」是設計選擇而非系統限制。
- 延遲/資源限制：Apple 未公布 credential 請求的硬性 timeout [推測：系統轉圈、使用者可取消；extension 程序可被系統隨時回收]。具體可查的限制：
  - extension 記憶體上限比主 App 嚴：Bitwarden iOS 定義「Argon2id memory ≥ 64MB 時 extension 解鎖可能觸及記憶體上限而警告使用者」（https://raw.githubusercontent.com/rorkai/demo-bitwarden-ios/main/BitwardenShared/Core/Platform/Utilities/Constants.swift `maxArgon2IdMemoryBeforeExtensionCrashing`）。
  - extension 無背景執行、只能被請求喚起（PanicVault 技術解析，secondary source：https://www.panicvault.org/apple/credential-provider-extensions/ ）。
  - `requestToTurnOnCredentialProviderExtension` 每次呼叫需間隔 10 秒（Apple 文件，見上）。

## 2. Extension ↔ 容器 App 的 IPC
- Apple 官方文件直接把 app group 當成 sandboxed 進程間的 IPC 基礎：同组成员可用 **Mach IPC/XPC**（service name 格式 `<group-id>.<unique-name>`，受 `BOOTSTRAP_MAX_NAME_LEN` 限制）、**POSIX  semaphore/共享記憶體**、**UNIX domain socket（socket 檔必須放在 group container 內）**；「在 macOS 上，app group 用於讓兩個 sandboxed App、或 sandboxed 與非 sandboxed App 之間做 IPC」；app group 同時就是 keychain access group。
  - https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups
- Bitwarden macOS 的生產實作（先例）：extension 一律 sandboxed，「只能碰到 app group 容器裡的 socket」，所以 unix socket 放在 `~/Library/Group Containers/group.com.bitwarden.desktop`；README 註腳承認「XPC 或 CFMessagePort 對 sandbox 的支援可能更好，但實作早於現行 IPC 框架」。
  - https://raw.githubusercontent.com/bitwarden/clients/main/apps/desktop/desktop_native/core/src/ipc/mod.rs
  - https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/autofill_provider/README.md
- Apple 對「provider extension 與主 App 共享資料」的官方建議只有隱性兩條：(a) app group 容器放加密 vault、(b) `ASCredentialIdentityStore` 放非機密 metadata（Apple 明確寫 metadata 不含密碼：sec6319ac7b9）。沒有「IPC 取金鑰」的官方指引文件 [推測：因為 Apple 預設的 reference architecture 是 extension 自行解密]。
- Distributed notification（`NSDistributedNotificationCenter`）：無文件將其定位為憑證級安全通道；僅適合單向「通知有更新」用途 [推測]。
- 各家現況：
  - **1Password（macOS native AutoFill，2026-05 beta → 2026-10-05 8.12.40 穩定）**：走 Apple Passwords API 當 system-level Credential Provider；填充「不用打開 1Password App」，但錯誤訊息「Failed to connect to 1Password.app」+ 要求開啟 App Background Activity ⇒ extension 薄、主 App 常駐接單的 thin-client 模式；填充時 Touch ID 由系統中介（「Use Touch ID for autofilling passwords」）；需 macOS 14+（beta 限 Apple silicon）。
    - https://support.1password.com/macos-autofill
    - https://www.1password.community/announcements-52/may-2026-at-1password-native-macos-autofill-a-new-developer-site-and-more-24666
    - https://releases.1password.com/mac/stable （8.12.40, 2026-10-05：TOTP「Set Up Codes In」）
  - **Dashlane**：2024-09 宣布「iOS 18/macOS 15 day-one」支援新 autofill API（OTP 填充、context menu、passkey upgrade），但其 macOS App 文件承認「Apple 的限制使 Safari extension 仍是 autofill 必需」。
    - https://www.dashlane.com/blog/dashlane-with-ios-18-and-macos-15-enhanced-autofill-and-passkey-experience
    - https://support.dashlane.com/hc/en-us/articles/39026790117778-Install-Dashlane-on-macOS
  - **Proton Pass**：macOS 原生 autofill 截至 2026-07 仍是「即將支援」（over the coming months），現行靠 autotype。https://proton.me/blog/pass-improved-autofill
  - **PanicVault**（KeePass 系）：extension 內解密 + NSFileCoordinator 防併發損壞的完整技術描述（secondary source）。https://www.panicvault.org/apple/credential-provider-extensions/

## 3. Bitwarden 官方狀態
- **macOS 尚無 Password Provider（password 填充）**：FR 93723（2026-02-10 開，至 2026-10 仍開放，36 樓/78 讚）；另有 FR 97993。https://community.bitwarden.com/t/register-as-macos-password-provider/93723 、https://community.bitwarden.com/t/support-macos-native-autofill-provider-framework-for-passkeys-passwords/97993
- 已有 **macOS passkey provider**（thin extension 架構）：PR #13963「PM-8353 MacOS passkey provider」merged 2025-12-05；PR #22624「Enable macOS autofill extension in Beta channel」merged 2026-10-15。架構：Swift extension（App bundle 的 PlugIns）→ unix socket IPC（Rust + UniFFI + NAPI）→ Electron main → Angular renderer（modal mode 顯示確認 UI）。來源：README.md（見 §2）+ GitHub API。
- 社群提案 discussion #21537（2026-06-28）指出補上 passwords 只差三件事：Info.plist 加 `ProvidesPasswords`、處理 `ASPasswordCredentialRequest`、仿 passkey assertion 建 `prepare_password_assertion` IPC 流；ObjC sync 命令已把 `ASPasswordCredentialIdentity` 註冊進 `ASCredentialIdentityStore`（status 報 `password: YES`）。官方作者表示需先完成 #18787（PM-23485）重構。https://github.com/orgs/bitwarden/discussions/21537
- **iOS 架構（fat extension 先例）**：主 App 與 extension 共用 app group `group.$(BASE_BUNDLE_ID)` 與 keychain access group `$(AppIdentifierPrefix)$(BASE_BUNDLE_ID)`；extension 自帶 Face ID 解密（extension Info.plist 有 `NSFaceIDUsageDescription`），自己 sync（`minimumSyncInterval` 30 分鐘）。
  - https://raw.githubusercontent.com/bitwarden/ios/main/BitwardenAutoFillExtension/Application/Support/BitwardenAutoFill.entitlements
  - https://raw.githubusercontent.com/bitwarden/ios/main/Bitwarden/Application/Support/Bitwarden.entitlements
  - https://raw.githubusercontent.com/bitwarden/ios/main/BitwardenAutoFillExtension/Application/Support/Info.plist
  - 金鑰保護：`KeychainService.swift` 用 `SecAccessControlCreateWithFlags`（biometric ACL）https://raw.githubusercontent.com/bitwarden/ios/main/BitwardenKit/Core/Platform/Services/KeychainService.swift
  - 使用者文件：biometric 解鎖失效需重驗主密碼的 FAQ https://bitwarden.com/help/autofill-faqs/ ；iOS autofill 設定 https://bitwarden.com/help/auto-fill-ios/

## 4. 兩方案權衡（extension 內解密 vs IPC 取資料）
| 構面 | Extension 內解密（fat，Bitwarden iOS 式） | IPC 到 Full client（thin，1Password/Bitwarden macOS passkey 式） |
|---|---|---|
| App 未執行 | 可服務（資料在 app group、金鑰在 keychain） | 不可靠：需主 App 常駐（1Password 的 background activity 要求與 connect 錯誤） |
| 延遲 | 冷啟動要重導金鑰/讀 vault（Argon2 記憶體限制是真實痛點，Constants 見 §1） | 常駐時快；但多一進程往返 |
| 金鑰暴露面 | 金鑰解鎖態存在 extension 進程（受 biometric ACL keychain 保護） | 金鑰只在主 App；extension 只傳請求/短命憑證 |
| UI | 必須在 extension 內做解鎖/選取/確認 UI | 可重用主 App UI（Bitwarden modal mode） |
| 多平台一致性 | extension 邏輯各 OS 重寫 | Full client 邏輯集中，thin client 各端只實作協議 |
| 失敗模式 | 系統回收記憶體→重新解鎖 | 主 App 掛掉→autofill 直接失敗 |
- 混合式（建議方向）：快速路徑用 extension 內 biometric-ACL keychain 金鑰解密；需主 App 的操作（存密碼、產生密碼、passkey 註冊確認）才 IPC/fallback 到 Full client。API 支援這種分層（silent fast path + `.userInteractionRequired` fallback，§1）。1Password 的填充 Touch ID prompt 也是系統中介的混合驗證。

## 5. 初期過渡面（macOS）
- **Auto-type（鍵盤模擬）**：Bitwarden 已列 roadmap（thread 93873，2026-02-14；由來 FR 158；社群 2026-08 仍在催）。https://community.bitwarden.com/t/auto-type-for-windows-and-macos-desktop-apps/93873
- **Accessibility-based Universal Autofill**：1Password 現行方案，需系統 Accessibility 授權。https://support.1password.com/mac-universal-autofill
- **Proton Pass autotype**（付費方案）：https://proton.me/support/pass-autotype
- **剪貼簿/快捷鍵 + Safari Web Extension**：Bitwarden 現行 macOS 做法（快捷鍵文件 https://bitwarden.com/help/keyboard-shortcuts ；Safari extension 隨 MAS App 出貨 https://bitwarden.com/help/getting-started-browserext ）。
- Services 選單 / Full Keyboard Access：未見密碼管理器廠商以其為主要整合面 [推測]。

## 6. 結論
1. **可行**：macOS credential provider extension 支援 passwords/passkeys/OTP/text-to-insert，macOS 14 起可填密碼、15 起全功能；1Password（GA 2026-10）與 Bitwarden passkey provider（beta 2026-10）都是「薄 extension + 主 App」生產先例，與本專案 thin-client 架構同型。
2. **IPC 正解**：sandboxed extension ↔ 容器 App 走 app group 上的 XPC/Mach 或 group container 內 unix socket（Apple 官方文件明列；Bitwarden 現用後者並自評 XPC 可能更佳）。
3. **限制**：thin 模式把「主 App 背景常駐」變硬依賴（1Password 的 connect 錯誤是前車之鑑）；Apple 無公開 timeout 數值 [推測]；extension 記憶體上限制約 fat 解密路徑（Argon2）。
4. **建議**：混合式——identity store + extension 內 biometric keychain 快速解密，複雜操作 IPC 給 Full client；這同時覆蓋「App 未執行」與「金鑰集中」兩個目標。
