# Bitwarden 官方用戶端功能缺口調查（截至 2026-10-28）

調查範圍：community.bitwarden.com Feature Requests（分類 5）、bitwarden/clients GitHub issues、官方 help/Release Notes、bitwarden/server、Vaultwarden。

## A. 社群高度要求、官方仍未支援的功能缺口

| # | 功能缺口 | 證據（贊同度） | 官方狀態 |
|---|---|---|---|
| 1 | 桌面 App Auto-type（ keystroke 自動輸入，Windows/macOS） | FR 158「Desktop app - auto-type」719 likes，open：<https://community.bitwarden.com/t/158>；2026-02 重提 FR 93873：<https://community.bitwarden.com/t/93873> | 未支援。官方 help 無 auto-type 文件頁（<https://bitwarden.com/help/auto-type.md> 回 404）；已列入官方 Roadmap（未實作）：<https://community.bitwarden.com/c/feature-requests/roadmap/81> |
| 2 | Tags／標籤整理 vault items | FR 132「Tags (labels)」492 likes，open：<https://community.bitwarden.com/t/132> | 未支援；2026-08 才以「Use tags to organize vault items」進 Roadmap（FR 101008） |
| 3 | 排序選項（按修改時間／加入時間／最後使用） | FR 2484「Sorting Options」494 likes，open：<https://community.bitwarden.com/t/2484> | 未支援（僅字母序） |
| 4 | 重複密碼偵測＋合併工具 | FR 648「Duplicate removal tool / report (including merge)」392 likes，open：<https://community.bitwarden.com/t/648> | 未支援 |
| 5 | 附件預覽（不下載直接檢視） | FR 52「View attachments without downloading」353 likes，open：<https://community.bitwarden.com/t/52> | 未支援（僅上下載） |
| 6 | 取消共享：org 項目一鍵移回個人 vault／批次搬移 | FR 604「Add unshare option」322 likes，open：<https://community.bitwarden.com/t/604>；FR 14489「Bulk collection migration」open：<https://community.bitwarden.com/t/14489> | 未支援；CLI `bw move` 移 org＋指派 collection 有 bug（clients#11689：<https://github.com/bitwarden/clients/issues/11689>） |
| 7 | 簡化共享體驗（不用 org/collection 也能共享單筆） | FR 238「Vault Item Sharing」302 likes，open：<https://community.bitwarden.com/t/238> | 未支援；官方僅在 Roadmap 貼問卷調查（FR 97635「🧭 Survey: Password Manager and collections architecture」） |
| 8 | 離線編輯（寫入可離線） | FR 107「Offline Editing」287 likes，open：<https://community.bitwarden.com/t/107>；FR 4306（附件離線同步）、FR 49355（離線新增項目） | 官方文件明載離線僅「read-only mode」：<https://bitwarden.com/help/using-bitwarden-offline>；桌面 App 曾連解鎖都要連網（clients#19055，2026-04 修訂：<https://github.com/bitwarden/clients/issues/19055>） |
| 9 | 到期提醒（所有項目型別、可循環） | FR 93914「Expiration Reminders」176 likes，open：<https://community.bitwarden.com/t/93914> | 未支援（僅 login 密碼到期報告） |
| 10 | 桌面↔瀏覽器共享解鎖狀態 | FR 1635「Shared Unlock State」168 likes，open：<https://community.bitwarden.com/t/1635> | 未支援；Roadmap 有「Shared unlock state」（FR 101009，未完成） |
| 11 | 以密碼值搜尋／搜尋增強 | FR 11941「Ability to search for passwords」119 likes；FR 29041 手機完整搜尋，open | 未支援 |
| 12 | 鍵盤快捷鍵／拖放／自訂圖示／Reverse Send | FR 76（149）、265（197）、80（175）、27067（141），皆 open（URL 同格式 /t/<id>） | 未支援 |
| 13 | 改項目型別、全欄位歷史 | FR 1148「Change type of items」、FR 16871「History for all fields」open | 未支援 |
| 14 | 匯出彈性 | FR 7959（依資料夾/collection 匯出）、FR 40164（含 org 的整合匯出）、FR 94148（加密 ZIP：JSON＋附件）、FR 98807（離線還原加密匯出）皆 open | 未支援；現行加密匯出格式反遭要求移除（FR 92783） |
| 15 | Linux 細節 | FR 101「Provide software repositories for Linux」107 likes open；clients#8890 單色 tray icon 27👍 open：<https://github.com/bitwarden/clients/issues/8890> | Flathub（30823）與 Linux 生物辨識（2026）已補上，repo/AUR 官方支援仍缺 |

## B. 自動填充可靠性／效能（長期抱怨）
- 不彈出「儲存/更新憑證」提示：clients#1620（75👍，open）：<https://github.com/bitwarden/clients/issues/1620>；Reddit：<https://www.reddit.com/r/Bitwarden/comments/1mmu8w8/bitwarden_autofill_is_super_hitormiss_for_me/>
- 擴充功能開啟延遲：clients#12286（120👍，open，全 repo 最高）；拖慢瀏覽器：clients#21108（40👍）；htaccess/basic auth 填充：#23285（22👍）、#1191（13👍）；快捷鍵不穩：#2475（12👍）。
- 官方已部分緩解：inline autofill、Fill assist（官方 curated 網站修正）、一鍵點擊填充（見 Release Notes <https://bitwarden.com/help/releasenotes.md>），但核心可靠性投訴未消失（2026 年仍有新 issue）。
- 剪貼簿：Windows 剪貼簿歷史殘留密碼 clients#2621（48👍 open）；CLI `bw get password` 強制寫剪貼簿無開關 #2742（25👍 open）。

## C. Passkeys／SSH／2FA 現況（2024–2026 已補，勿誤判為缺口）
- Passkey 儲存＋登入＋瀏覽器填充：已 GA（2023–2024；2024-04 行動版 GA：<https://aijourn.com/bitwarden-adds-mobile-passkey-support-for-everyone>；inline passkeys：<https://investor.wedbush.com/wedbush/article/bizwire-2024-9-24-bitwarden-further-streamlines-passwordless-authentication-with-inline-autofill-for-passkeys>）。
- 「Unlock with passkeys」（web/擴充解鎖）已上線（Release Notes：<https://bitwarden.com/help/releasenotes.md>）；但桌面 App 原生 passkeys（FR 93876）、macOS Password Provider（FR 93723）、PRF extension（FR 82239，229 likes）、單一項目多組 passkey（FR 59691）仍 open。
- SSH：桌面 SSH Agent 已 GA（2025.1.2；<https://bitwarden.com/blog/ssh-agent/>、<https://bitwarden.com/help/ssh-agent/>）；SSH key 型別＋瀏覽器填充已上線；但 macOS App Store 版不支援、授權跳窗體驗差（clients#16196、#13099、FR 79954、FR 80435 open）。
- 附件：仍為付費限定（5GB，<https://bitwarden.com/help/attachments>）；.zip 批次匯出附件已上線（desktop/CLI，2025-04：<https://bitwarden.com/blog/upload-store-and-now-export-attached-files-in-your-secure-bitwarden-vault>）。
- Archive（付費方案）已上線（Release Notes 2024 末～2025 段落，含 action bar 批量歸檔 2026.7.0：<https://community.bitwarden.com/t/2026-7-0-release-notes/100062>）。
- 其他已補：TOTP 在 Authenticator↔PM 同步、CXP 傳輸協定（iOS 26/Android）、直接匯入器（Chrome/Edge/Keeper/KeePass KDBX/Delinea）、Flatpak/Snap 生物辨識、mTLS on mobile（見 Release Notes 總檔）。

## D. AI Agent／自動化相關缺口（本專案主打機會）
1. **無 webhooks／事件訂閱**：FR 53736「Make outgoing webhooks when specific event is reached」（2023，open）：<https://community.bitwarden.com/t/53736>；bitwarden/server 無任何 webhook 功能 request（issue 搜尋僅見內部 Stripe webhook PR）→ agent 只能輪詢 `bw sync`。
2. **CLI 解鎖模型不友善**：文件明載「API key 不是 master password 替代品」，`--apikey`/SSO 登入後仍需 `bw unlock` 帶出主密碼才能解密；用 trusted devices（無主密碼）入 org 者「完全無法用 CLI 存取資料」（<https://bitwarden.com/help/cli/>）。對 agent 代表必須保管明文主密碼或依賴桌面 App IPC。
3. **CLI 穩定性/效能**：啟動慢（Node）clients/cli#2741（29👍 open）；批次操作問題 #2735；離線時 `bw status`/`unlock` 回傳非零 exit code（#18373，2026-01）；`bw unlock` 回 token 但 vault 仍鎖住的回归（#20703，2026）：<https://github.com/bitwarden/clients/issues/20703>；org API key 不被 CLI 支援（#11965，7👍）。
4. **CLI 無 SSH agent**：FR 84421（2025-05 open）：<https://community.bitwarden.com/t/84421>；本機實測 `bw ssh` 回 "Invalid command: ssh"（[推測] 各版本行為可能不同）。
5. **`bw serve` 局限**：本機 REST 代理，綁 localhost、預設封鎖 Origin 標頭，官方自認不建議開放網路（<https://bitwarden.com/help/cli/#serve>）；跑久會壞（#9306 open）。端點清單（archive/restore/move/attachment/send 等）見原始碼 oss-serve-configurator.ts：<https://github.com/bitwarden/clients/blob/main/apps/cli/src/oss-serve-configurator.ts>。無鑑權、無並發保證、無事件推送。
6. **官方 MCP server 是薄殼**：bitwarden/mcp-server 直接包 CLI，需手動填 `BW_SESSION`（session token 存設定檔有外洩風險，README 有警告）、org 管理要另給 API key（<https://github.com/bitwarden/mcp-server>；<https://bitwarden.com/blog/bitwarden-mcp-server>）；2026-03 的 Agent Access SDK 主打企業 Secrets Manager 場景，非個人 vault（<https://bitwarden.com/blog/introducing-agent-access-sdk>）。
7. **CLI 其他缺口**：`bw generate` 不支援對任意 secret 產生 TOTP code（僅 `bw get totp`，<https://bitwarden.com/help/cli/>）；無 Alpine/musl 支援（#12097）；`bw --version` 要先有 config（#3667，3667 號 issue 為 clients repo 唯一 open `feature-request` 標籤 issue）；JSON 需經 `get template | jq | bw encode` 手動拼（agent 易錯，文件自述流程 <https://bitwarden.com/help/cli/#create>）。
8. **搜尋能力**：`bw get` 字串搜尋只回傳一筆、多筆即報錯（文件明載）；無 fuzzy／欄位級搜尋 → agent 定位項目困難。

## E. Vaultwarden 對比（自架社群選擇的替代點）
- Vaultwarden 把官方收費/企業功能全部免費開放：Attachments、Event Logs、Directory Connector、Emergency Access、Admin panel、改過的 web vault（<https://github.com/dani-garcia/vaultwarden#features>）。官方雲端對應限制：附件＝付費（<https://bitwarden.com/help/attachments>）、Archive＝付費方案、Event Logs/DC＝企業方案。
- 官方 self-hosted 的推播依賴 Bitwarden 封閉的 push relay（<https://bitwarden.com/help/configure-push-relay/>）；Vaultwarden 自建 SignalR 相容 WebSocket 通知達成即時同步（<https://github.com/dani-garcia/vaultwarden/blob/main/src/api/notifications.rs>、wiki：<https://github.com/dani-garcia/vaultwarden/wiki/Enabling-Mobile-Client-push-notification>）。
- 社群對官方不满集中在：功能被 license 牆擋、自架缺支援功能、同步通知封閉 → 第三方用戶端若做「本地優先＋開放 API」可同時滿足兩邊。

## F. 對 bitward 專案的缺口結論（摘要）
1. 資料管理（tags、排序、去重合併、批次編輯/搬移、unshare）是十年高分缺口，官方行動極慢。
2. 離線可寫入＋無縫跨裝置解鎖狀態是官方文件明載的不支援項。
3. 自動化是最大空白：無 webhooks、CLI 主密碼耦合、serve/MCP 皆薄殼、無穩定事件流 → AI-agent-first 用戶端（本專案）最有差異化之處。
4. Passkey 進階（PRF、桌面原生、多把/項）與附件預覽是「官方已表態但尚未做」的追擊點。
5. 避免重複造輪：passkey 登入、SSH agent（桌面）、archive、批次 action bar、附件匯出、TOTP（CLI get）已存在，需以「更好用」而非「有無」定位。
