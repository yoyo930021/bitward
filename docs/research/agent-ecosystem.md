# AI Agent × 密碼管理器：現況與隱私風險調查

調查日期：2026-10-28。所有聲稱附來源；查證不足處標 [推測]。

## 1. Bitwarden 官方 MCP server（bitwarden/mcp-server）

- 2025-07-10 宣布（beta/測試性質），2025-10-21 更新加入組織管理功能；官方客服明言「proof of concept，不適合生產環境」。
  - 來源：https://bitwarden.com/blog/bitwarden-mcp-server ；https://community.bitwarden.com/t/bitwarden-mcp-server-for-connecting-agentic-ai-with-secure-credential-management/86665 （post 19 引用官方 email）
- 架構：雙介面——vault 操作全部透過本機 `bw` CLI 子行程；組織管理走 Bitwarden Public API（client_id/secret）。本機 stdio 執行，README 警告「絕不可 hosted 到公開網路」。
  - 來源：https://github.com/bitwarden/mcp-server/blob/main/README.md
- Token 處理：`BW_SESSION`（`bw unlock --raw` 的 session token）直接寫進 MCP 設定檔 env；組織 API 用 `BW_CLIENT_ID`/`BW_CLIENT_SECRET`。設定檔本身即為敏感檔。
  - 來源：同上 README（Environment Variables 表）
- 功能範圍：解/鎖 vault、sync、items CRUD/restore、folders、TOTP、密碼產生、Send（文字/檔）、attachments、裝置核准、成員確認；組織端 collections/members/groups/policies/audit logs/訂閱/大量匯入。
  - 來源：https://github.com/bitwarden/mcp-server/blob/main/README.md （Available Tools）
- 限制與已知問題：
  - 密碼明文進 LLM context（README 自承「Expose credentials through AI responses」，強烈建議配 local LLM）。https://github.com/bitwarden/mcp-server/blob/main/README.md
  - 無 scope/權限分层：拿到 server 等於全 vault 讀寫；無 audit trail 文件。https://github.com/adamrowles1996/vaultgate/blob/main/README.md （比較表）
  - 檔案操作預設全拒，需 `BW_ALLOWED_DIRECTORIES`。https://github.com/bitwarden/mcp-server/blob/main/README.md
  - 社群批評：master password/session 進 chatbot context 後可被 prompt injection 洩漏、TOTP 全暴露、 shoulder-surfing；官方僅回「可自架、可不用」。https://community.bitwarden.com/t/bitwarden-mcp-server-for-connecting-agentic-ai-with-secure-credential-management/86665 （post 3、5、13、15）
  - 星數約 299（2026-10-27 仍有 push）。來源：GitHub API search（https://api.github.com/search/repositories?q=bitwarden+mcp）
- 官方後續方向：2026-03 推出 Agent Access SDK（alpha，open standard）：JIT、human-in-the-loop 核准、憑證注入工作流、agent 看不到明文。https://bitwarden.com/blog/how-bitwarden-helps-secure-agentic-ai-access-to-your-credentials/ ；https://github.com/bitwarden/agent-access

## 2. 社群第三方 Bitwarden MCP / agent 工具

（依 GitHub stars，2026-10-28 查詢 https://api.github.com/search/repositories?q=bitwarden+mcp&sort=stars）
- `icoretech/warden-mcp`（★26）：走 `bw` CLI，不重實作加密；特色是接受 `BW_PASSWORD` 主密碼直登（免手動 BW_SESSION）、有 READONLY/NOREVEAL 開關、遠端 HTTP 模式（但 v1 無內建認證）。https://github.com/icoretech/warden-mcp
- `adamrowles1996/vaultgate`（★3，RC）：self-hosted 遠端 MCP + 自帶 OAuth 2.1（PKCE、短效 revocable token）；核心賣點「use, don't read」——agent 呼叫受 policy 約束的 http/sql/ssh/winrm actions，由 server 取憑證執行、結果 scrub 掉機密再回傳；vault 工具只回 metadata，單一 reveal 工具每次一格且全程 audit。https://github.com/adamrowles1996/vaultgate
- `dceluis/rbw-mcp`（★1）：改接 rbw（Rust 社群 CLI）而非 bw。https://github.com/dceluis/rbw-mcp
- `raychao-oao/cred-mcp`（★1）：宣稱 secrets 永不進 LLM context。https://github.com/raychao-oao/cred-mcp
- `dinhkarate/keyshroud`（★1）：面向 Claude Code/Codex/Cursor 的 masked output + hooks。https://github.com/dinhkarate/keyshroud
- `Brissux-Labs/agent-secrets`（★1）：secret broker，scoped execution、raw values 不進 context。https://github.com/Brissux-Labs/agent-secrets
- `bchoor/bws-mcp`（★2）：Bitwarden Secrets Manager 的 Cloudflare Workers 遠端 MCP。https://github.com/bchoor/bws-mcp
- 其餘小型實作（snnalgz ★7 左右、giuliolibrando、fkom13/mcp-vaultwarden、ocoj/smartbw-mcp 等）多為「env 塞 email+master password → 呼叫 bw」的本地 stdio server。https://github.com/snnalgz/bitwarden-mcp-server
- 趨勢總結：社群已明顯分成兩派——(a) 把機密給 agent 看（官方、warden-mcp 型）；(b) 只給 metadata/代理執行、機密不進 context（vaultgate、cred-mcp、keyshroud 型）。派系 (b) 出現於 2026 下半年且全是个位數星 [推測：代表此需求未被滿足、市場仍空白]。

## 3. 競品的 AI/agent 整合

- 1Password 立場明確：「絕不透過 MCP 暴露 raw credentials」；MCP 只給低風險 metadata（SaaS Manager 應用清單、owner、license 用量）。理由：LLM 是非確定性通道、prompt injection 洩漏、進 context 後無撤銷模型。https://1password.com/blog/where-mcp-fits-and-where-it-doesnt
- 1Password Environments MCP server：跑在桌面 app 內、每 Environment 有人工核准 prompt、「by design 不能回傳 secret 值」；配 `op://` secret references + `op run`/`op inject` 讓 secret 只在執行期注入環境變數，不進 code/context。https://www.1password.dev/environments/mcp-server ；https://www.1password.dev/cli/secret-references
- 1Password 另有 Trelica MCP、Claude Code/Cursor/Kiro plugins、AGENTS.md 指引。https://www.1password.dev/get-started/secure-ai-access
- 1Password CLI 認證架構：op 透過 IPC（macOS XPC／Linux unix socket／Windows named pipe）向桌面 app 要金鑰 + 生物辨識，10 分鐘 session 自動續期，無環境變數——即 agent/daemon 模式。https://github.com/bitwarden/clients/issues/19839 （issue 內引述 https://developer.1password.com/docs/cli/biometric-security/）
- Bitwarden Secrets Manager CLI（bws）走 token + scoped access，社群偏好用它管 dev secrets 而非個人 vault。https://bitwarden.com/help/secrets-manager-cli ；https://community.bitwarden.com/t/bitwarden-mcp-server/86665 （post 14）

## 4. Vault 機密進 LLM 的隱私風險（文獻與實務）

- 實證研究（arXiv 2604.03070，2026-04）：分析 17,022 個 agent skills，520 個含 1,708 個洩漏問題；73.5% 漏洞來自 debug logging——agent framework 把 stdout 直接餵進 context window；89.6% 洩漏憑證立即可被利用；fork 分發讓修補失效。https://arxiv.org/abs/2604.03070
- PRISM（arXiv 2605.10614，2026-05）：multi-agent 共享 context 造成「propagation amplification」，一個 agent 讀到的機密會跨 agent 邊界再現於下游輸出；提出 generation-time per-token 偵測/介入。https://arxiv.org/abs/2605.10614
- OWASP LLM02:2025 Sensitive Information Disclosure、LLM07 System Prompt Leakage：憑證不應存在於 model context/system prompt。https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/ ；https://genai.owasp.org/llmrisks/llm072025-system-prompt-leakage
- OWASP AI Agent Security Cheat Sheet：prompt injection（直接/間接）+ tool access 是 agent 特有攻擊面。https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- 實務討論：Bitwarden 社群帖指出「chatbot 隨時可呼叫 tool 抽走整個 vault 含 TOTP」；結論是「secrets 要防的是其他 tools，唯一可靠方法是不讓它進 model context」。https://community.bitwarden.com/t/bitwarden-mcp-server/86665 （post 3、5）
- 1Password 補充警告：曾以明文存在 .env/Git history/「coding agent memory」的 secret 要輪換——agent 記憶本身即持久洩漏面。https://www.1password.dev/environments/mcp-server （WARNING 段）
- 已被驗證的緩解模式（各家共同點）：(1) metadata-only tools；(2) scoped + revocable token（OAuth 2.1）；(3) 執行期注入、用完 scrub（redaction）；(4) per-access human approval；(5) 全程 audit log。來源：vaultgate README、1Password blog/docs、Bitwarden Agent Access SDK blog（上方連結）。

## 5. bw CLI 對腳本/agent 的可用性

- 正面：所有命令支援 `--json`（配 jq 使用），`create --objectType` 有 JSON template；有 native 單檔執行檔；個人 API key 適合非互動登入。https://bitwarden.com/help/cli/
- 痛點（多為长期 open 的 GitHub issues，彙整自 #19839 及其 related issues 清單）：
  - 無 daemon/agent mode：`BW_SESSION` 存在 env var，新 terminal/pane 就失效；issue 稱「fundamentally broken for automation」，社群從 2019（bitwarden/cli#65）要到現在。https://github.com/bitwarden/clients/issues/19839 （closed as not planned，轉內部 PM-34275）
  - 並行互毀：第二次 `bw unlock` 作廢第一張 session token。https://github.com/bitwarden/clients/issues/6898
  - 每次呼叫起一個完整 Node runtime，1–5 秒/次，批次操作慢。https://github.com/bitwarden/clients/issues/2741
  - `bw serve`（本地 REST）非為 agent 設計、跑幾小時後 session 損壞。https://github.com/bitwarden/clients/issues/9306
  - 企業 policy/vault timeout 會令有效 token 中途要求主密碼。https://github.com/bitwarden/clients/issues/12270 ；https://github.com/bitwarden/clients/issues/16527
  - CLI 與 Desktop app 解鎖狀態完全不相通（Desktop 解鎖 ≠ CLI 可用）。https://github.com/bitwarden/clients/issues/22773
  - attachments：並行下載觸發 exception 卻回 exit code 0（#2731）、下載被附加錯誤副檔名（#19931）、解密檔名未 sanitize 直接寫盤（#20790，已修）。https://github.com/bitwarden/clients/issues/2731
  - Key Connector 環境下無法 lock、需手動 unset BW_SESSION。https://community.bitwarden.com/t/bitwarden-cli-you-cannot-lock-your-vault-because-you-are-using-key-connector-to-protect-your-vault-you-have-been-logged-out/36885
- 社群替代：`rbw`（Rust CLI + rbw-agent daemon，持 key 於記憶體、多 process 共享、可配 TTL）被 #19839 點名「證明此架構在 Bitwarden API 上可行」，是用戶離開官方 CLI 的主要原因之一。https://github.com/doy/rbw ；https://github.com/bitwarden/clients/issues/19839

## 6. 對 bitwarden 專案的啟示（綜合）

1. 官方 MCP = bw CLI 的 thin wrapper：继承全部 CLI 痛點（手動 BW_SESSION、無 scope、無 daemon），且把明文機密丟進 LLM context——社群反彈集中在這點。
2. 市場空缺明確：「agent 用得到憑證、但看不見憑證」的本機優先客戶端（1Password Environments、vaultgate 已驗證此模式，但都綁自家雲或 RC 阶段、無完整 vault 管理）。
3. 隱私架構底线應為：metadata-only 預設 + 單一受審計的 reveal + scoped/revocable tokens + redaction + human-in-the-loop 核准（見第 4 節五模式）。
4. 第三方 client 可繞過 bw CLI：直接講 Bitwarden 協議（如 rbw）自建 agent daemon（key 留記憶體、unix socket、TTL、生物辨識），一次解決 #19839 列出的所有痛點。

## 來源總表

- https://bitwarden.com/blog/bitwarden-mcp-server
- https://github.com/bitwarden/mcp-server/blob/main/README.md
- https://www.npmjs.com/package/@bitwarden/mcp-server
- https://community.bitwarden.com/t/bitwarden-mcp-server-for-connecting-agentic-ai-with-secure-credential-management/86665
- https://bitwarden.com/blog/how-bitwarden-helps-secure-agentic-ai-access-to-your-credentials/
- https://github.com/bitwarden/agent-access
- https://github.com/icoretech/warden-mcp
- https://github.com/adamrowles1996/vaultgate
- https://github.com/dceluis/rbw-mcp
- https://github.com/raychao-oao/cred-mcp
- https://github.com/dinhkarate/keyshroud
- https://github.com/Brissux-Labs/agent-secrets
- https://github.com/bchoor/bws-mcp
- https://1password.com/blog/where-mcp-fits-and-where-it-doesnt
- https://www.1password.dev/environments/mcp-server
- https://www.1password.dev/cli/secret-references
- https://www.1password.dev/get-started/secure-ai-access
- https://arxiv.org/abs/2604.03070
- https://arxiv.org/abs/2605.10614
- https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- https://genai.owasp.org/llmrisks/llm072025-system-prompt-leakage
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- https://bitwarden.com/help/cli/
- https://bitwarden.com/help/secrets-manager-cli
- https://github.com/bitwarden/clients/issues/19839
- https://github.com/bitwarden/clients/issues/6898
- https://github.com/bitwarden/clients/issues/2741
- https://github.com/bitwarden/clients/issues/9306
- https://github.com/bitwarden/clients/issues/12270
- https://github.com/bitwarden/clients/issues/16527
- https://github.com/bitwarden/clients/issues/22773
- https://github.com/bitwarden/clients/issues/2731
- https://github.com/bitwarden/clients/issues/19931
- https://github.com/bitwarden/clients/issues/20790
- https://community.bitwarden.com/t/bitwarden-cli-you-cannot-lock-your-vault-because-you-are-using-key-connector-to-protect-your-vault-you-have-been-logged-out/36885
- https://github.com/doy/rbw
- https://developer.1password.com/docs/cli/biometric-security/
