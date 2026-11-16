# bitward-mcp

MCP ↔ BTP 純轉譯 shim：對 agent host 講 newline-delimited JSON-RPC 2.0（stdio），對本裝置
`bitwarderd` 講 BTP（UDS）。**零政策邏輯**——授權、budget、人工核准、出口淨化全在 daemon
`call()`（契約 §2.3）；本程序被入侵，洩漏面是 token + grant 集，不是金鑰。
BTP 斷線即整體以錯結束（不重連）。

## 環境變數

| 變數 | 必要 | 語意 |
|---|---|---|
| `BITWARD_SOCK` | 是 | daemon UDS 路徑（shim 永不自行落地 daemon） |
| `BITWARD_AGENT_TOKEN` | 否 | 有：`Auth::Session` 續用 grant 受限 session；無：本機全權 `Enroll`，serverInfo 標 `mcp:<pid>` |

## 接到 agent host
Claude Code（`~/.claude.json` 的 `mcpServers`）：
```json
{
  "mcpServers": {
    "bitward": {
      "command": "bitward-mcp",
      "args": [],
      "env": { "BITWARD_SOCK": "/path/to/daemon.sock",
               "BITWARD_AGENT_TOKEN": "<bitward agent open 發的 token>" }
    }
  }
}
```
Codex（`~/.codex/config.toml`）：
```toml
[mcp_servers.bitward]
command = "bitward-mcp"
env = { BITWARD_SOCK = "/path/to/daemon.sock", BITWARD_AGENT_TOKEN = "..." }
```

## 政策：secrets 預設不進 context

`vault_list` 只有 metadata、`vault_get` 只給 mask。在 **token session**（設了
`BITWARD_AGENT_TOKEN`）下，明文唯一去處是 `vault_reveal`（需 `reveal:*` grant，逐次審計）。
`run` 的 `btw://` env 引用只注入子進程，stdout/stderr 經 Redactor 淨化後才回 context
（實證：洩漏主走 stdout，arXiv 2604.03070）。

**無 token 例外（設計使然）**：不帶 `BITWARD_AGENT_TOKEN` 時，shim 以本機全權
`Enroll`（`SessionKind::Interactive`）連線，等同使用者本人在場——所有讀取都可直接出
明文、不受 `reveal:*` grant 或人工核准約束，上述「明文唯一去處」敘事不適用。這是刻意
的免設定開發路徑（同 uid 進程本來就有同等權限），不是繞過。**建議**：給 agent host 的
正式設定一律帶 token（用 `bitward agent open` 簽發、只授所需 grant），把無 token 全權
留給本機開發／自測。

