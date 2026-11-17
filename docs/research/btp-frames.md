# BTP 幀規格（Research: BtpFrames）

日期：2026-11-17。本檔是 **bitward 自家線協定（BTP）** 的幀層規格與 conformance vectors；
`docs/research/protocol.md` 講的是**上游 Bitwarden/Vaultwarden HTTP API** 的調查，兩者不同物。
協定型別（欄位語意、variant 追加紀律）在 `crates/bw-proto/src/lib.rs`；
編碼層實作在 `crates/bw-proto/src/wire.rs`（Full 端 tokio 適配 `crates/bw-btp`、
thin 端 std 適配 `apps/bitward-gui/src/btp.rs`，兩側都從同一模組取碼）。

## 1. 幀佈局

```text
┌──────────────────────┬──────────────────────────────┐
│ 4 bytes LE：體長度 N │ N bytes：一個協定訊息的編碼後  │
└──────────────────────┴──────────────────────────────┘
```

- 長度前綴**不計自身**（只算訊息體）。
- 上限 `MAX_FRAME = 48 MiB`（`bw_proto::wire`）：32 MiB 附件的 base64 體 ≈43 MiB。
  讀側在前綴階段就擋（不在解碼後擋），按實際 N 分配、非上限預分配。
- 一條幀＝一個 `ClientMsg` 或 `ServerMsg`（externally-tagged enum：JSON 形態
  `{"Invoke":{...}}`；postcard 形態＝variant 索引 varint + 體）。

## 2. 訊息體編碼與連線級协商

兩種訊息體編碼（`bw_proto::wire::WireFormat`）：

| 格式 | 編碼器 | 特性 | 定位 |
|---|---|---|---|
| `Json` | `serde_json` | 自描述、人可讀 | 舊端唯一支援；除錯逃生舷 `BW_BTP_JSON=1` |
| `Postcard` | `postcard` | 非自描述、欄名不上線 | 新版互連主線 |

`serde_json::Value` 在 postcard 下**解不出來**（反序列化要 `deserialize_any`），
所以線上型別必須全型別化才能吃 postcard——這是 PR5 型別化子批的存在理由。

协商（不另開控制幀、不加 per-frame content-type 欄）：

1. 客戶端第一條 `ClientMsg::Hello` 帶 `formats: [偏好...]`（順序＝偏好序）。
2. daemon 用 `wire::select_format` 從偏好裡選自己支援的第一項，寫進
   `ServerMsg::Welcome::format`。
3. **握手兩幀（Hello、Welcome）恆 JSON**；選定格式自 Welcome 之後的幀生效
   （伺服器在寫完 Welcome 後切、客戶端在讀到 Welcome 後切）。
4. 無共同格式 → daemon 發 `ServerMsg::Error{message}`（握手層拒絕，rid 尚未存在）
   後收線；thin 端把拒絕原因顯式上螢幕，不得靜默重連（readpath A6 教訓）。

### 2.1 混版本矩陣

| 對端 | 行為 | 根據 |
|---|---|---|
| 舊客戶端（Hello 不帶 `formats`） | `serde(default)` → 空偏好 → 選 `Json` | 舊端只實作 JSON |
| 舊 daemon（Welcome 不帶 `format`） | `serde(default)` → `Json` | 同上 |
| 舊客戶端（`Enroll` 不帶 `profile`、`Login` 不帶 `profile`/`two_factor`） | `serde(default)` → None → 落 daemon 的預設帳號槽（E5 單帳號行為） | 握手兩幀恆 JSON，缺欄寬容真生效（`hello-legacy-no-formats` 釘解碼路徑） |
| 舊 daemon（`Welcome` 不帶 `profile`） | `serde(default)` → 空字串 → thin 端視為單帳號 | `welcome-legacy-no-format` 釘解碼路徑 |
| 新↔新 | 客戶端偏好 `[Postcard, Json]` → 選 `Postcard` | 本檔 §2 |
| 嚴格 postcard 客戶端 ↔ 只支援 JSON 的 daemon | `select_format` 回 None → 誠實拒（`Error` 幀） | 不得假成功降階 |
| peer `proto > PROTO_VERSION` | 既有 ceiling 拒（`WtpError::Unsupported`／`Error` 幀） | §2.6 協定漂移防禦 |

`PROTO_VERSION` 不因換編碼而 bump：編碼是协商出來的能力，不是語意版本。
postcard 是**索引**編碼，故協定型別的 variant/欄位只能**置尾追加**（§2.6 紀律），
追加後舊 build 的 postcard 索引與新 build 不同——混 postcard 版本仍靠 `proto` ceiling 擋。

## 3. Conformance vectors

區塊由 `cargo test -p bw-btp --test vectors` 逐條執行：重編等於 `frame`、
解碼等於 `msg`（`decode_only` 條只驗解碼寬容）。`frame` 是**完整上線位元組**
（含 4 bytes LE 前綴）的小寫 hex。

`msg` 的鍵序在文件裡是照打字方便；JSON 的鍵序不影響語意（serde 對 struct 按欄位名取值），
故 `decode_only` 條的前綴體就是文件內這份 JSON 的位元組。非 `decode_only` 條的
`frame` 由協定型別實際編碼產生（鍵序＝宣告序），兩者的區分正是要測的寬容性。

重生成 hex：`BTP_VECTORS_WRITE=1 cargo test -p bw-btp --test vectors -- --ignored --nocapture`。

```btp-vectors
[
  {
    "name": "hello-negotiates-formats",
    "dir": "client",
    "format": "json",
    "msg": {"Hello": {"version": 1, "auth": {"Enroll": {"pairing": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "display_name": "cli:4242", "pair_code": null, "profile": null}}, "wants": ["VaultChanged"], "formats": ["Postcard", "Json"]}},
    "frame": "cd0000007b2248656c6c6f223a7b2276657273696f6e223a312c2261757468223a7b22456e726f6c6c223a7b2270616972696e67223a2237633965363637392d373432352d343064652d393434622d653037666331663930616537222c22646973706c61795f6e616d65223a22636c693a34323432222c22706169725f636f6465223a6e756c6c2c2270726f66696c65223a6e756c6c7d7d2c2277616e7473223a5b225661756c744368616e676564225d2c22666f726d617473223a5b22506f737463617264222c224a736f6e225d7d7d"
  },
  {
    "name": "hello-legacy-no-formats",
    "dir": "client",
    "format": "json",
    "decode_only": true,
    "msg": {"Hello": {"version": 1, "auth": {"Enroll": {"pairing": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "display_name": "cli:4242", "pair_code": null, "profile": null}}, "wants": []}},
    "frame": "920000007b2248656c6c6f223a7b2261757468223a7b22456e726f6c6c223a7b22646973706c61795f6e616d65223a22636c693a34323432222c22706169725f636f6465223a6e756c6c2c2270616972696e67223a2237633965363637392d373432352d343064652d393434622d653037666331663930616537227d7d2c2276657273696f6e223a312c2277616e7473223a5b5d7d7d"
  },
  {
    "name": "hello-negotiates-formats-postcard",
    "dir": "client",
    "format": "postcard",
    "msg": {"Hello": {"version": 1, "auth": {"Enroll": {"pairing": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "display_name": "cli:4242", "pair_code": null, "profile": null}}, "wants": ["VaultChanged"], "formats": ["Postcard", "Json"]}},
    "frame": "380000000001012437633965363637392d373432352d343064652d393434622d65303766633166393061653708636c693a3432343200000100020100"
  },
  {
    "name": "invoke-list-metadata",
    "dir": "client",
    "format": "json",
    "msg": {"Invoke": {"rid": 3, "call": {"Vault": {"List": {"query": {"text": "git", "tag": null, "uri": null, "value": null, "kind": null, "sort": "Name", "limit": 100, "collection": null, "folder": null, "deleted": null, "archived": null}, "view": "Metadata"}}}}},
    "frame": "e10000007b22496e766f6b65223a7b22726964223a332c2263616c6c223a7b225661756c74223a7b224c697374223a7b227175657279223a7b2274657874223a22676974222c22746167223a6e756c6c2c22757269223a6e756c6c2c2276616c7565223a6e756c6c2c226b696e64223a6e756c6c2c22736f7274223a224e616d65222c226c696d6974223a3130302c22636f6c6c656374696f6e223a6e756c6c2c22666f6c646572223a6e756c6c2c2264656c65746564223a6e756c6c2c226172636869766564223a6e756c6c7d2c2276696577223a224d65746164617461227d7d7d7d7d"
  },
  {
    "name": "invoke-list-metadata-postcard",
    "dir": "client",
    "format": "postcard",
    "msg": {"Invoke": {"rid": 3, "call": {"Vault": {"List": {"query": {"text": "git", "tag": null, "uri": null, "value": null, "kind": null, "sort": "Name", "limit": 100, "collection": null, "folder": null, "deleted": null, "archived": null}, "view": "Metadata"}}}}},
    "frame": "140000000103010001036769740000000000640000000000"
  },
  {
    "name": "welcome-selects-postcard",
    "dir": "server",
    "format": "json",
    "msg": {"Welcome": {"proto": 1, "epoch": 3, "server": {"kind": "Vaultwarden", "version": "1.37.2", "features": []}, "state": {"Unlocked": {"epoch": 3, "deadline_epoch_ms": null}}, "events_from": 12, "format": "Postcard", "profile": ""}},
    "frame": "ce0000007b2257656c636f6d65223a7b2270726f746f223a312c2265706f6368223a332c22736572766572223a7b226b696e64223a225661756c7477617264656e222c2276657273696f6e223a22312e33372e32222c226665617475726573223a5b5d7d2c227374617465223a7b22556e6c6f636b6564223a7b2265706f6368223a332c22646561646c696e655f65706f63685f6d73223a6e756c6c7d7d2c226576656e74735f66726f6d223a31322c22666f726d6174223a22506f737463617264222c2270726f66696c65223a22227d7d"
  },
  {
    "name": "welcome-legacy-no-format",
    "dir": "server",
    "format": "json",
    "decode_only": true,
    "msg": {"Welcome": {"proto": 1, "epoch": 3, "server": {"kind": "Unknown", "version": null, "features": []}, "state": {"AuthLocked": {"items": 556}}, "events_from": 0, "profile": ""}},
    "frame": "8f0000007b2257656c636f6d65223a7b2265706f6368223a332c226576656e74735f66726f6d223a302c2270726f746f223a312c22736572766572223a7b226665617475726573223a5b5d2c226b696e64223a22556e6b6e6f776e222c2276657273696f6e223a6e756c6c7d2c227374617465223a7b22417574684c6f636b6564223a7b226974656d73223a3535367d7d7d7d"
  },
  {
    "name": "reply-totp-code",
    "dir": "server",
    "format": "json",
    "msg": {"Reply": {"rid": 3, "outcome": {"Ok": {"TotpCode": {"code": "424242", "valid_for_secs": 18}}}}},
    "frame": "570000007b225265706c79223a7b22726964223a332c226f7574636f6d65223a7b224f6b223a7b22546f7470436f6465223a7b22636f6465223a22343234323432222c2276616c69645f666f725f73656373223a31387d7d7d7d7d"
  },
  {
    "name": "reply-totp-code-postcard",
    "dir": "server",
    "format": "postcard",
    "msg": {"Reply": {"rid": 3, "outcome": {"Ok": {"TotpCode": {"code": "424242", "valid_for_secs": 18}}}}},
    "frame": "0c000000010300030634323432343212"
  },
  {
    "name": "reply-error-locked",
    "dir": "server",
    "format": "json",
    "msg": {"Reply": {"rid": 4, "outcome": {"Err": "Locked"}}},
    "frame": "2e0000007b225265706c79223a7b22726964223a342c226f7574636f6d65223a7b22457272223a224c6f636b6564227d7d7d"
  },
  {
    "name": "reply-error-locked-postcard",
    "dir": "server",
    "format": "postcard",
    "msg": {"Reply": {"rid": 4, "outcome": {"Err": "Locked"}}},
    "frame": "0400000001040101"
  },
  {
    "name": "handshake-error",
    "dir": "server",
    "format": "json",
    "msg": {"Error": {"message": "無共同線格式：peer 宣告 [Postcard]"}},
    "frame": "430000007b224572726f72223a7b226d657373616765223a22e784a1e585b1e5908ce7b79ae6a0bce5bc8fefbc9a7065657220e5aea3e5918a205b506f7374636172645d227d7d"
  }
]
```

postcard 條目刻意不含仍帶 `serde_json::Value` 的變體（`Response::Json`、
`Audit`、`Sessions`、`Event::payload`）——那些欄位在型別化收尾批清完前
只有 JSON 能回讀（本節開頭的 `deserialize_any` 限制）。

緊湊度現測（同一訊息、兩種編碼）：`invoke-list-metadata` 225 → 20 bytes、
`reply-totp-code` 87 → 12 bytes。

### 3.1 perf 死線收據（PR5 D5，2026-11-17）

同一 daemon（558 筆鏡像庫副本、544 筆未刪）、同一查詢（`ls --limit 0`）、交錯 5 輪：

| 指標 | JSON（逃生舷） | postcard（主線） | 變化 |
|---|---|---|---|
| 全量 List 回包幀體 | 285,595 B | 82,583 B | **−71.1%** |
| 端到端牆鐘（`time bitward ls`） | 0.00–0.01 s | 0.00–0.01 s | 不惡化 |
| 解碼耗時中位數（200 次同體） | 0.309 ms | 0.097 ms | 3.2× 快 |
| 對照 trunk 基線（PR5 前 JSON） | 217,595 B | 82,580 B | −62.0% |

兩個基準都過門檻（≥−40%）。**如實記一筆副作用**：移除 `skip_serializing_if` 後
JSON 模式的回包從 217,595 B 長到 285,595 B（+31%），因為缺席欄位現在寫顯式 null；
postcard 側不受影響（`Option::None` 每欄 1 byte 判別字，Metadata 視窗的
`ItemView` 十個可空欄 ≈ 10 B/筆 ≈ 5.4 KB，佔 postcard 回包 6.6%；card/identity
的 37 欄在父節點 `None` 時不佔位）。收據重跑：
`BW_PERF_STORE=<庫副本> cargo test -p bitwarderd --release -- --ignored wire_list_bytes --nocapture`。

## 4. 與既有機制的關係

- **XPC（macOS provider）**：走平台層封裝，訊息型別仍取自 bw-proto，
  不重複實作編碼。
- **Chrome Native Messaging（`bitward-nm`）**：stdio 那側是 NM 自己的
  4 bytes LE + JSON（`bins/bitward-nm/src/framing.rs`），與本規格無關且恆 JSON；
  該程序對 daemon 才走 BTP。
- **CLI stdout**：人讀/`--json` 輸出由 `bins/bitward` 自行 `serde_json` 序列化，
  與幀格式無關——換線格式不改腳本契約。
