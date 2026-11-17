# bitward

A privacy-first, AI-agent-friendly [Bitwarden](https://bitwarden.com)-compatible client. Bitwarden is a trademark of Bitwarden Inc.; this project is not affiliated with, sponsored, or endorsed by Bitwarden, Inc.

常駐中樞持有金鑰，所有介面（CLI、GUI、macOS credential provider、MCP shim）都是 thin client。AI agent 預設「只用不讀」：機密不進 LLM context，reveal 逐筆受審計。

- 架構契約：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 研究紀錄：[`docs/research/`](docs/research/)
- 驗收斷言：契約 §6（A1-A12）

## 落盤安全（PR7b，對 2026-11-16 稽核 D1/D2 的裁決）

- **密碼明文不落盤**：`vault.db` 的值搜尋索引把密碼改存
  `HMAC-SHA256(HKDF(user key, "index"), 密碼)`（派生金鑰只在解鎖期存在
  記憶體）。識別欄 `username`、身分姓氏、卡號末四碼**如實留明文**——
  它們在 Masked 出口到處可見，加密不改變攻擊者可見集合；逐欄理由見
  [`crates/bw-store/NOTES.md`](crates/bw-store/NOTES.md)。鎖定狀態下值
  查詢直接回 `Locked` 拒絕（不給猜值 oracle）；鎖定即 `wal_checkpoint
  (TRUNCATE)`＋`secure_delete`，舊頁殘值不留在 WAL。
- **鎖定即毀鑰（strict 封存）**：沒有生物辨識 ACL 的後端（Linux 全部
  安裝、未啟用 Keychain 的 Mac 走 `FileKeyStore`）預設**不再**把包裝前
  的 user key 封存落盤。行為改變：Linux 開機／daemon 重啟後的第一次
  解鎖一律要主密碼（舊行為是把金鑰擱在加密鏡像旁邊的「假解鎖」）。
  想要重啟自動解鎖，明確開 opt-in（設定 `lock_on_sleep_restart=false`，
  GUI 重啟行為開關同義），此時封存才落盤（0600 檔）。macOS Keychain
  路徑（Touch ID）不受影響。

License: GPL-3.0-or-later.
