# bitward-nm FINDINGS

- Firefox macOS 目錄：凍結介面寫 `Profiles/<profile>/native-messaging-components/`，
  但 MDN（webextensions/manifest.json/native_messaging）的 extension manifest 目錄是
  `Profiles/<profile>/native-messaging-hosts/`（`components/manifests.json` 是另一套
  系統元件機制，非本 shim 所需）。實作採 `native-messaging-hosts`，profile 由
  `~/Library/Application Support/Firefox/profiles.ini` 的 `Default=` 解析；
  多 profile 無 Default 或解析不了 ⇒ 要求 `--dest`（錯誤訊息明示）。
- Chromium 4-byte 長度前綴為 native endian；macOS/Linux 皆 LE，協定採 LE。
- daemon 對 unknown session 的語意＝握手後即斷線（`serve_conn` 回 Denied 前不發
  Welcome，僅 tracing::debug），client 端只看到 EOF；重配對觸發條件據此設為
  「第一次嘗試任何握手失敗 ⇒ 刪 nm_session、Enroll 重來一次」（同 CLI 教訓）。
- daemon 的 `Query.uri` 過濾是子串 LIKE（bw-store/query.rs）；`credential.match`
  在 shim 端再做 host 精確比對（無 `url` crate，自寫最小 host 解析，測試覆蓋）。
- vault.list/reveal 的 `result` 直接序列化 daemon `Response`（externally-tagged，
  如 `{"Items":[...]}`），與 MCP 面 response_text 同形態，避免另發格式。
