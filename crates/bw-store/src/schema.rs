/// schema 版本；每次加表/改表就 +1 並在本檔補一段遷移 SQL。
pub const SCHEMA_VERSION: i64 = 10;

/// v1→v2：值搜尋明文索引欄。舊庫 ALTER；新庫 V1 已含，Duplicate column 容忍。
pub const V2: &str = "ALTER TABLE meta_plain ADD COLUMN username_plain TEXT;
ALTER TABLE meta_plain ADD COLUMN password_plain TEXT;";

/// v2→v3（P4b org 共享語意）：org/collection 鏡像表在 V1，遷移形態見 V4 註解。
pub const V3: &str = "";

/// v3→v4（APNs 推播）：push_tokens 表在 V1，遷移形態同 V3。
pub const V4: &str = "";

/// v4→v5（三件套：SecureNote／資料夾／自訂欄位）：
/// - `folders` 鏡像表在 V1（CREATE IF NOT EXISTS 冪等）。
/// - `meta_plain.fields_plain`：自訂欄**欄名**明文索引（hidden 欄值不入，§2.1
///   分級表 FieldValue=Secret）；逐條 ALTER 容忍 Duplicate column（同 V2 紀律）。
pub const V5: &str = "ALTER TABLE meta_plain ADD COLUMN fields_plain TEXT NOT NULL DEFAULT '[]';
ALTER TABLE meta_plain ADD COLUMN deleted_at TEXT;";

/// v5 第二段（必成，不容錯）：FTS5 不支援加欄，`meta_fts` 整組重建
/// （連帶 DROP 舊 trigger——`DROP TABLE` 不會移走掛在 content 表上的 trigger，
/// 留著它們會在下次寫入時撞上新表欄位數）。新建庫 V1 已是三欄形態，
/// 這裡 drop+recreate 收斂同一結果（冪等）。
pub const V5_FTS: &str = "DROP TRIGGER IF EXISTS meta_plain_ai;
DROP TRIGGER IF EXISTS meta_plain_ad;
DROP TRIGGER IF EXISTS meta_plain_au;
DROP TABLE IF EXISTS meta_fts;
CREATE VIRTUAL TABLE meta_fts USING fts5(
  name, uris, fields_plain,
  content='meta_plain', content_rowid='rowid',
  tokenize='unicode61'
);
INSERT INTO meta_fts(meta_fts) VALUES('rebuild');
CREATE TRIGGER meta_plain_ai AFTER INSERT ON meta_plain BEGIN
  INSERT INTO meta_fts(rowid, name, uris, fields_plain) VALUES (new.rowid, new.name, new.uris, new.fields_plain);
END;
CREATE TRIGGER meta_plain_ad AFTER DELETE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain);
END;
CREATE TRIGGER meta_plain_au AFTER UPDATE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain);
  INSERT INTO meta_fts(rowid, name, uris, fields_plain) VALUES (new.rowid, new.name, new.uris, new.fields_plain);
END;";

/// v5→v6（批次 4a 附件）：`attachments` 鏡像表在 V1（CREATE IF NOT EXISTS
/// 冪等，形態同 v3/v4 紀律）；欄位級無 ALTER，版本號提升只為
/// schema_version_guard 的可見性。
pub const V6: &str = "";

/// v6→v7（批次 B 封存支援）：`meta_plain.archived_at`——協定 `archivedDate`
/// 的鏡像投影欄（有值＝已封存）。逐條 ALTER 容忍 Duplicate column（同 V2 紀律）。
pub const V7: &str = "ALTER TABLE meta_plain ADD COLUMN archived_at TEXT;";

/// v7→v8（Send 面）：`sends` 鏡像表在 V1（CREATE IF NOT EXISTS 冪等，
/// 形態同 v3/v4/v6 紀律）；欄位級無 ALTER，版本號提升只為
/// schema_version_guard 的可見性。
pub const V8: &str = "";

/// v8→v9（PR1 型別節值搜尋，Q4 准則做）：`meta_plain` 加卡片末四碼＋
/// 身分姓氏明文索引欄（僅解鎖回填，§2.7 R3 明文只活在 0600 檔）。
/// 逐條 ALTER 容忍 Duplicate column（同 V2/V5/V7 紀律）。
pub const V9: &str = "ALTER TABLE meta_plain ADD COLUMN card_number_tail TEXT;
ALTER TABLE meta_plain ADD COLUMN identity_last_name TEXT;";

/// v9→v10（D1 落盤安全，稽核 2026-11-16）：秘密值明文不落盤——
/// `password_plain`（明文密碼）退役，改 `password_hmac` BLOB：
/// `HMAC-SHA256(derive_index_key(user_key), 密碼)`（演算法單源
/// `bw_crypto::index`；金鑰只在解鎖期存在記憶體）。逐條執行、各自容忍
/// 既定衝突（ADD 撞 Duplicate column＝新庫 V1 已含；DROP 撞 no such
/// column＝已退役或全新庫），同 V2/V5/V7/V9 紀律。DROP COLUMN 由 SQLite
/// 重寫全表行，配合連線級 `PRAGMA secure_delete=ON` 讓 freed 頁清零，
/// 舊明文不留在盤上。識別欄 `username_plain`／`identity_last_name` 與
/// 非秘密的 `card_number_tail`（末四碼，遮罩顯示同形）留明文——理由與
/// 範圍見 NOTES.md「留明文欄位」節；值搜尋的鎖態拒絕在 daemon 層。
pub const V10: &str = "ALTER TABLE meta_plain ADD COLUMN password_hmac BLOB;
ALTER TABLE meta_plain DROP COLUMN password_plain;";

/// v9 第二段（必成，不容錯）：FTS5 不支援加欄，`meta_fts` 整組重建加入
/// 兩張型別節索引欄（走 V5_FTS 先例——連帶 DROP 舊 trigger 免撞新表欄位數）。
/// 新建庫 V1 已是五欄形態，這裡 drop+recreate 收斂同一結果（冪等）。
pub const V9_FTS: &str = "DROP TRIGGER IF EXISTS meta_plain_ai;
DROP TRIGGER IF EXISTS meta_plain_ad;
DROP TRIGGER IF EXISTS meta_plain_au;
DROP TABLE IF EXISTS meta_fts;
CREATE VIRTUAL TABLE meta_fts USING fts5(
  name, uris, fields_plain, card_number_tail, identity_last_name,
  content='meta_plain', content_rowid='rowid',
  tokenize='unicode61'
);
INSERT INTO meta_fts(meta_fts) VALUES('rebuild');
CREATE TRIGGER meta_plain_ai AFTER INSERT ON meta_plain BEGIN
  INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
END;
CREATE TRIGGER meta_plain_ad AFTER DELETE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
END;
CREATE TRIGGER meta_plain_au AFTER UPDATE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
  INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
END;";

/// v1：鏡像（密文原樣）+ 明文 metadata 索引（FTS5）+ overlay + outbox +
/// audit（append-only hash 鏈）+ sessions + blobs 登記 + meta。
/// 來源：ARCHITECTURE §3.4；欄位語意見 crate NOTES.md。
pub const V1: &str = r#"
CREATE TABLE IF NOT EXISTS ciphers(
  id         TEXT PRIMARY KEY,
  enc_cipher BLOB NOT NULL,   -- 伺服器 cipher JSON，剝掉 revisionDate/deletedDate；信封字串不改寫
  raw        BLOB NOT NULL,   -- 伺服器 cipher JSON 原樣（未建模欄位的真相源）
  rev        TEXT,            -- revisionDate（樂觀併發基準 ServerRev）
  deleted    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta_plain(
  id         TEXT PRIMARY KEY,
  name       TEXT,            -- 未解鎖前可能仍是信封字串；解鎖後 set_plain_meta 覆寫為明文
  uris       TEXT NOT NULL DEFAULT '[]',  -- JSON array；同上
  kind       INTEGER,         -- 1 Login | 2 SecureNote | 3 Card | 4 Identity（來源見 NOTES.md）
  folder     TEXT,
  org        TEXT,
  favorite   INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  pending    INTEGER NOT NULL DEFAULT 0,
  username_plain TEXT,        -- v2：值搜尋索引（FR 11941），識別欄留明文（理由見 NOTES.md）
  password_hmac BLOB,         -- v10：HMAC-SHA256(index_key, 密碼)，秘密值明文不落盤（取代 v2 password_plain，D1 稽核 2026-11-16）
  fields_plain TEXT NOT NULL DEFAULT '[]',  -- v5：自訂欄欄名明文（JSON array；值不入）
  deleted_at TEXT,             -- v5：垃圾桶條目的伺服器 deletedDate；未刪 NULL
  archived_at TEXT,            -- v7：封存條目的伺服器 archivedDate；未封存 NULL
  card_number_tail TEXT,       -- v9：卡片末四碼明文（PR1 值搜尋；僅解鎖回填）
  identity_last_name TEXT      -- v9：身分姓氏明文（PR1 值搜尋；僅解鎖回填）
);

-- v3（P4b org 共享語意讀側）：/sync 的 organizations[] / collections[] 鏡像。
-- 信封欄位（name/key/encryptedPrivateKey）存伺服器原樣密文；金鑰語意在 daemon。
CREATE TABLE IF NOT EXISTS orgs(
  id              TEXT PRIMARY KEY,
  raw             BLOB NOT NULL,          -- profileOrganization JSON 原樣
  name            TEXT,                   -- 信封字串（org key 加密）
  key             TEXT,                   -- akey：org 對稱金鑰的包裝（2.=owner 對稱、4.=成員 RSA）
  public_key      TEXT,                   -- org RSA 公開金鑰（b64 SPKI）
  enc_private_key TEXT,                   -- org RSA 私鑰信封（user 對稱金鑰包裝，僅 owner 解得開）
  key_verified    INTEGER NOT NULL DEFAULT 0,  -- daemon 私鑰往返驗證通過
  status          INTEGER,                -- 0 Invited | 1 Accepted | 2 Confirmed（-1 Revoked）
  atype           INTEGER                 -- 0 Owner | 1 Admin | 2 User | 3 Manager/Custom
);

CREATE TABLE IF NOT EXISTS collections(
  id   TEXT PRIMARY KEY,
  org  TEXT NOT NULL,
  name TEXT,                  -- 信封字串（org key 加密）
  raw  BLOB NOT NULL
);

-- v5（三件套）：/sync 的 folders[] 鏡像。名稱是用戶 key 加密的信封字串
-- （官方語意：資料夾屬個人 vault，不走 org key）；全量替換見 apply_sync。
CREATE TABLE IF NOT EXISTS folders(
  id   TEXT PRIMARY KEY,
  name TEXT,                  -- 信封字串（未解鎖不解開）
  rev  TEXT,                  -- revisionDate
  raw  BLOB NOT NULL          -- 伺服器 folder JSON 原樣
);

CREATE TABLE IF NOT EXISTS cipher_collections(
  cipher     TEXT NOT NULL,
  collection TEXT NOT NULL,
  PRIMARY KEY (cipher, collection)
);
CREATE INDEX IF NOT EXISTS cipher_collections_col ON cipher_collections(collection);

-- v6（批次 4a 附件）：/sync 的 ciphers[].attachments 鏡像。
-- file_name/size_name/key 存伺服器原樣（信封或明文，本層不判斷）；
-- url 是短效簽名直連（過期是常態，下載前必經 GET attachment/{aid} 重取）；
-- id 非 UUID（VW 20 位 hex），TEXT 原樣主鍵。隨 write_cipher 逐 cipher 重建。
CREATE TABLE IF NOT EXISTS attachments(
  id        TEXT PRIMARY KEY,
  cipher    TEXT NOT NULL,
  file_name TEXT,
  size      INTEGER,
  size_name TEXT,
  key       TEXT,
  url       TEXT
);
CREATE INDEX IF NOT EXISTS attachments_cipher ON attachments(cipher);

-- v8（Send 面）：/sync 的 sends[] 與 `GET /sends` 刷新鏡像。
-- 信封欄（name/key/file_name）存伺服器原樣，本層不做金鑰語意（同 folders 紀律）；
-- raw 是 send JSON 原樣（真相源）；access_id＝b64url(uuid) 由伺服器給、缺欄時
-- 呼叫端可自算。全量替換見 apply_sync / sends_replace。
CREATE TABLE IF NOT EXISTS sends(
  id               TEXT PRIMARY KEY,
  stype            INTEGER NOT NULL,          -- 0 Text | 1 File
  name             TEXT,                      -- 信封字串（send key 加密）
  key              TEXT,                      -- seed 的 user key 包裝信封
  access_id        TEXT,
  deletion_date    TEXT,
  expiration_date  TEXT,
  max_access_count INTEGER,
  access_count     INTEGER NOT NULL DEFAULT 0,
  hide_email       INTEGER NOT NULL DEFAULT 0,
  file_id          TEXT,                      -- 檔案 send 的 server file id（非 UUID）
  file_name        TEXT,                      -- 信封字串
  file_size        INTEGER,
  rev              TEXT,                      -- revisionDate
  raw              BLOB NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS meta_fts USING fts5(
  name, uris, fields_plain, card_number_tail, identity_last_name,
  content='meta_plain', content_rowid='rowid',
  tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS meta_plain_ai AFTER INSERT ON meta_plain BEGIN
  INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
END;
CREATE TRIGGER IF NOT EXISTS meta_plain_ad AFTER DELETE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
END;
CREATE TRIGGER IF NOT EXISTS meta_plain_au AFTER UPDATE ON meta_plain BEGIN
  INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
  INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
END;

CREATE TABLE IF NOT EXISTS overlay(
  id        TEXT PRIMARY KEY,
  tags      TEXT NOT NULL DEFAULT '[]',  -- JSON array；本地權威（協定無此欄位，§4 缺口表）
  pinned    INTEGER NOT NULL DEFAULT 0,
  last_used INTEGER,                     -- unix ms（sort=Used）
  sort_hint REAL                         -- 手動排序權重（FR 494）
);

CREATE TABLE IF NOT EXISTS outbox(
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,  -- 即 MutationId；同 item FIFO
  item       TEXT NOT NULL,
  base_rev   TEXT,
  payload    BLOB NOT NULL,   -- 入列時已是 {op, ...} JSON，機密欄位由呼叫端先行加密
  state      TEXT NOT NULL,   -- queued|in_flight|awaiting|applied|conflict|dead（§2.4 MutState）
  origin     TEXT,            -- SessionId 字串；衝突時知道該問誰
  created_at INTEGER NOT NULL,
  leased_at  INTEGER          -- take_due 認領時刻（unix ms），過租約可被重取
);
CREATE INDEX IF NOT EXISTS outbox_item_state ON outbox(item, state);

CREATE TABLE IF NOT EXISTS audit(
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  session   TEXT,
  action    TEXT NOT NULL,
  item      TEXT,
  field     TEXT,
  sens      INTEGER NOT NULL,
  outcome   TEXT NOT NULL,
  bytes_out INTEGER NOT NULL,
  approval  TEXT,
  epoch     INTEGER NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TABLE IF NOT EXISTS sessions(
  id         TEXT PRIMARY KEY,
  principal  TEXT NOT NULL,   -- JSON（bw_proto 型別由呼叫端序列化）
  grants     TEXT NOT NULL,   -- JSON
  epoch      INTEGER NOT NULL,
  state      TEXT NOT NULL,   -- active|suspended|revoked
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS push_tokens(
  token         TEXT PRIMARY KEY,  -- APNs device token（不透明識別子）
  platform      TEXT NOT NULL,     -- 用戶端來源標記，daemon 不解釋
  registered_at INTEGER NOT NULL   -- unix ms；重複註冊 INSERT OR REPLACE 覆蓋
);

CREATE TABLE IF NOT EXISTS blobs(
  ref        TEXT PRIMARY KEY,  -- sha256 hex；內容定址
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;
