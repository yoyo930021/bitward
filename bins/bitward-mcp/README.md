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

`vault_list` 只有 metadata、`vault_get` 只給 mask；明文唯一去處是 `vault_reveal`
（需 `reveal:*` grant，逐次審計）。`run` 的 `btw://` env 引用只注入子進程，
stdout/stderr 經 Redactor 淨化後才回 context（實證：洩漏主走 stdout，arXiv 2604.03070）。
