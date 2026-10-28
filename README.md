# bitward

A privacy-first, AI-agent-friendly [Bitwarden](https://bitwarden.com)-compatible client. Bitwarden is a trademark of Bitwarden Inc.; this project is not affiliated with, sponsored, or endorsed by Bitwarden, Inc.

常駐中樞持有金鑰，所有介面（CLI、GUI、macOS credential provider、MCP shim）都是 thin client。AI agent 預設「只用不讀」：機密不進 LLM context，reveal 逐筆受審計。

- 架構契約：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 研究紀錄：[`docs/research/`](docs/research/)
- 驗收斷言：契約 §6（A1-A12）

License: GPL-3.0-or-later.
