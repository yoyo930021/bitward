# bw-store NOTES

實作契約：`docs/ARCHITECTURE.md` §3.4（warden-store 段）、§2.3（AuditRecord）、
§2.4（outbox）；魔術常數來源逐條列於下。

## 欄位語意

- `ciphers.enc_cipher`：伺服器 cipher JSON 剝掉 `revisionDate`/`deletedDate`
  （這兩項升為獨立欄位），信封字串（`2.iv|ct|mac`）不改寫。
- `ciphers.raw`：伺服器 cipher JSON 原樣，未建模欄位的真相源（不變量 8）。
- `meta_plain.name/uris`：`apply_sync` 時先存伺服器原樣（多半是信封字串）；
  解鎖後 daemon 在 `with_keys` 內解密、經 `set_plain_meta` 覆寫為明文，
  FTS5 觸發器自動重建索引。bw-store 不知金鑰語意（§3 規則）。

## 魔術常數

| 常數 | 值 | 來源 |
|---|---|---|
| cipher `type` → ItemKind | 0=Login, 1=SecureNote, 2=Card, 3=Identity | https://github.com/bitwarden/clients/blob/main/libs/common/src/enums/cipher-type.enum.ts |
| 信封格式 `type.iv|ct|mac`（type 2 = AES-256-CBC + HMAC-SHA256） | — | https://bitwarden.com/help/what-encryption-is-used ；docs/research/protocol.md「金鑰階層」段 |
| `/sync` 回應形態（`serverDate`、`ciphers[]`、`revisionDate`、`deletedDate`） | — | https://github.com/frankhommers/bitwarden-openapi-generator （unofficial spec，docs/research/protocol.md 引用）；寬容解析另收 `data.ciphers` |
| outbox `LEASE_MS` | 120_000 ms | 本專案自訂（P2）：A7 要求 daemon 5 秒內重生，崩潰重啟後最多等一個租約即可重取 in-flight 列 |
| audit 鏈 genesis hash | 64 個 '0' | 本專案自訂（§2.3 只定義欄位集） |
| audit canonical 分隔符 | U+001F（unit separator） | 本專案自訂；不會出現在 ts/action 等可讀欄位 |
| FTS5 tokenizer | `unicode61` + 前綴匹配 `"tok"*` | https://sqlite.org/fts5.html （prefix 語法） |
| 檔權限 | db/wal/shm 0600、目錄 0700 | 契約 §3.4、任務出口條件 |
| blob 目錄分片 | `blobs/<hex[0..2]>/<hex[2..]>` | git object store 形態：https://git-scm.com/docs/gitrepository-layout |
| WAL + synchronous=NORMAL | — | https://sqlite.org/wal.html ；單寫者中樞（不變量 11）下 NORMAL 為崩潰安全上界 |

## 已知邊界

- `apply_sync` 為全量替換語意（Bitwarden `/sync` 本來就是全量）；LocalOnly
  draft 在 P2 前只活在 outbox payload，鏡像列要等伺服器回 id。
- tags 跨裝置同步是開放問題 Q3；v1 overlay 是本機權威。
