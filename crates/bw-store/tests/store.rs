//! 出口條件測試：transaction 原子性、hash 鏈篡改、FTS、0600、outbox FIFO。

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use bw_proto::{ItemKind, Query, SortKey};
use bw_store::{AuditRecord, MutState, MutationDraft, Overlay, OverlayOp, Store, StoreError};
use serde_json::{Value, json};
use uuid::Uuid;

fn tmp_vault(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), PermissionsExt::from_mode(0o755)).unwrap();
    let path = dir.path().join(format!("{name}.db"));
    (dir, path)
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn cipher(id: &str, name: &str, rev: &str, deleted: bool) -> serde_json::Value {
    let mut c = json!({
        "id": id,
        "type": 0,
        "name": name,
        "organizationId": null,
        "folderId": null,
        "favorite": false,
        "revisionDate": rev,
        "creationDate": "2024-01-01T00:00:00.000Z",
        "login": { "uris": [{ "uri": "https://example.com" }] },
        "notes": null,
        "fields": null,
        "attachments": null,
        "unknown_future_field": { "keep": "me" }
    });
    if deleted {
        c["deletedDate"] = json!("2025-01-01T00:00:00.000Z");
    }
    c
}

#[test]
fn open_sets_dir_0700_and_db_0600() {
    let (dir, path) = tmp_vault("perms");
    let store = Store::open(&path).unwrap();
    store.apply_sync(&json!({ "ciphers": [] })).unwrap();
    assert_eq!(mode(&path), 0o600, "db 檔必须 0600");
    assert_eq!(mode(dir.path()), 0o700, "存放目錄 0700");
    assert_eq!(mode(&dir.path().join("blobs")), 0o700);
    // WAL 檔若存在也得 0600
    for suffix in ["-wal", "-shm"] {
        let name = format!("{}{}", path.display(), suffix);
        let p = Path::new(&name);
        if p.exists() {
            assert_eq!(mode(p), 0o600, "{suffix} 檔必须 0600");
        }
    }
}

#[test]
fn apply_sync_rebuilds_meta_plain() {
    let (_d, path) = tmp_vault("sync");
    let store = Store::open(&path).unwrap();
    let id = Uuid::new_v4().to_string();
    let cur = store
        .apply_sync(&json!({
            "serverDate": "2026-10-29T00:00:00.000Z",
            "ciphers": [cipher(&id, "2.iv|ct|mac", "2026-10-01T00:00:00.000Z", false)]
        }))
        .unwrap();
    assert_eq!(cur, 1);
    assert_eq!(store.cursor().unwrap(), 1);
    let got = store.item(Uuid::parse_str(&id).unwrap()).unwrap().unwrap();
    assert_eq!(got.rev.as_deref(), Some("2026-10-01T00:00:00.000Z"));
    assert!(!got.deleted);
    // 未建模欄位必須原樣保留在 raw（不變量 8 的儲存端）
    assert_eq!(got.raw["unknown_future_field"]["keep"], "me");
    // enc_cipher 不含 revisionDate/deletedDate
    assert!(got.enc_cipher.get("revisionDate").is_none());

    // 第二次同步：游標遞增、鏡像整批替換
    let id2 = Uuid::new_v4().to_string();
    let cur = store
        .apply_sync(
            &json!({ "ciphers": [cipher(&id2, "2.a|b|c", "2026-10-02T00:00:00.000Z", false)] }),
        )
        .unwrap();
    assert_eq!(cur, 2);
    assert!(store.item(Uuid::parse_str(&id).unwrap()).unwrap().is_none());
    assert!(
        store
            .item(Uuid::parse_str(&id2).unwrap())
            .unwrap()
            .is_some()
    );
}

#[test]
fn apply_sync_rolls_back_halfway_failure() {
    let (_d, path) = tmp_vault("rollback");
    let store = Store::open(&path).unwrap();
    let keep = Uuid::new_v4().to_string();
    store
        .apply_sync(&json!({ "ciphers": [cipher(&keep, "2.old|old|old", "2026-01-01T00:00:00.000Z", false)] }))
        .unwrap();
    let before = store.cursor().unwrap();

    // 第二批：第一列好、第二列缺 id（模擬套一半崩壞）→ 整批回滾
    let fresh = Uuid::new_v4().to_string();
    let err = store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&fresh, "2.new|new|new", "2026-02-01T00:00:00.000Z", false),
                json!({ "name": "no-id" }),
            ]
        }))
        .expect_err("缺 id 應回滾");
    assert!(matches!(err, StoreError::Invalid(_)));
    // 舊鏡像還在、新列沒進、游標沒動
    assert!(
        store
            .item(Uuid::parse_str(&keep).unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .item(Uuid::parse_str(&fresh).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(store.cursor().unwrap(), before);
}

#[test]
fn fts_search_after_plain_index() {
    let (_d, path) = tmp_vault("fts");
    let store = Store::open(&path).unwrap();
    let gh = Uuid::new_v4();
    let gl = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&gh.to_string(), "2.encrypted|gh|mac", "2026-10-01T00:00:00.000Z", false),
                cipher(&gl.to_string(), "2.encrypted|gl|mac", "2026-10-02T00:00:00.000Z", false),
            ]
        }))
        .unwrap();
    // 未回填明文前，加密態名稱不可搜（只搜得到鏡像欄位 token）
    store
        .set_plain_meta(
            gh,
            Some("GitHub"),
            &["https://github.com/login".into()],
            &[],
        )
        .unwrap();
    store
        .set_plain_meta(gl, Some("GitLab"), &["https://gitlab.com".into()], &[])
        .unwrap();

    let hits = store
        .query(
            &Query {
                text: Some("git".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 2, "前綴匹配兩筆");
    let hits = store
        .query(
            &Query {
                text: Some("github".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, gh);
    // uri 也在 FTS 範圍內
    let hits = store
        .query(
            &Query {
                text: Some("gitlab.com".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, gl);
}

#[test]
fn query_filters_tags_uri_and_sort() {
    let (_d, path) = tmp_vault("filter");
    let store = Store::open(&path).unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&a.to_string(), "AAA", "2026-10-01T00:00:00.000Z", false),
                cipher(&b.to_string(), "bbb", "2026-10-05T00:00:00.000Z", false),
            ]
        }))
        .unwrap();
    store
        .set_plain_meta(a, Some("AAA"), &["https://a.example.com".into()], &[])
        .unwrap();
    store
        .set_plain_meta(b, Some("bbb"), &["https://b.example.org".into()], &[])
        .unwrap();
    store
        .overlay(
            a,
            OverlayOp::SetTags(vec!["work".to_string(), "vip".to_string()]),
        )
        .unwrap();
    store
        .overlay(b, OverlayOp::TouchUsed { at_ms: 123 })
        .unwrap();

    let hits = store
        .query(
            &Query {
                tag: Some("work".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, a);
    assert_eq!(hits[0].tags, vec!["work".to_string(), "vip".to_string()]);

    let hits = store
        .query(
            &Query {
                uri: Some("example.org".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, b);

    // 名稱排序不分大小寫
    let hits = store
        .query(
            &Query {
                sort: SortKey::Name,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(
        hits.iter().map(|h| h.id).collect::<Vec<_>>(),
        vec![a, b],
        "AAA < bbb (NOCASE)"
    );

    // Used 排序：有 last_used 的排前面
    let hits = store
        .query(
            &Query {
                sort: SortKey::Used,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits[0].id, b);

    // kind 過濾：全部是 Login(0)
    let hits = store
        .query(
            &Query {
                kind: Some(ItemKind::Card),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(hits.is_empty());

    // overlay 讀回
    assert_eq!(
        store.overlay_get(b).unwrap(),
        Overlay {
            tags: vec![],
            pinned: false,
            last_used: Some(123),
            sort_hint: None
        }
    );
}

#[test]
fn outbox_fifo_same_item_and_pending_flag() {
    let (_d, path) = tmp_vault("outbox");
    let store = Store::open(&path).unwrap();
    let item = Uuid::new_v4();
    let other = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&item.to_string(), "2.x|y|z", "2026-10-01T00:00:00.000Z", false),
                cipher(&other.to_string(), "2.x|y|w", "2026-10-01T00:00:00.000Z", false),
            ]
        }))
        .unwrap();

    let m1 = store
        .enqueue(&MutationDraft {
            item,
            payload: json!({ "op": "patch", "a": 1 }),
            base_rev: Some("2026-10-01T00:00:00.000Z"),
            origin: Some("session-1"),
            mirror: None,
        })
        .unwrap();
    let m2 = store
        .enqueue(&MutationDraft {
            item,
            payload: json!({ "op": "patch", "a": 2 }),
            base_rev: Some("2026-10-01T00:00:00.000Z"),
            origin: Some("session-1"),
            mirror: None,
        })
        .unwrap();
    let m3 = store
        .enqueue(&MutationDraft {
            item: other,
            payload: json!({ "op": "delete" }),
            base_rev: None,
            origin: None,
            mirror: None,
        })
        .unwrap();
    assert!(m1.0 < m2.0, "seq 單調");

    // pending 反映在 ItemMeta
    let meta = store.meta(item).unwrap().unwrap();
    assert!(meta.pending);
    assert!(
        store.meta(other).unwrap().unwrap().pending,
        "m3 已入列 queued"
    );

    let due = store.take_due(10).unwrap();
    assert_eq!(due.len(), 2, "同 item 只認領最舊一筆");
    assert_eq!(due[0].id, m1);
    assert_eq!(due[0].item, item);
    assert_eq!(due[0].payload["a"], 1);
    assert_eq!(due[1].id, m3, "seq FIFO");
    assert_eq!(store.take_due(10).unwrap().len(), 0, "m2 被 m1 擋住");

    let d = store.depth().unwrap();
    assert_eq!(d.in_flight, 2);
    assert_eq!(d.total, 3);

    // settle m1 applied → m2 才可出境
    store.settle(m1, MutState::Applied).unwrap();
    let due = store.take_due(10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, m2);
    store.settle(m2, MutState::Applied).unwrap();
    store.settle(m3, MutState::Applied).unwrap();
    assert!(!store.meta(item).unwrap().unwrap().pending);
    assert_eq!(store.depth().unwrap().total, 3);
    assert_eq!(store.depth().unwrap().queued, 0);
}

#[test]
fn outbox_lease_expiry_reclaim() {
    let (_d, path) = tmp_vault("lease");
    let store = Store::open(&path).unwrap();
    let item = Uuid::new_v4();
    let m = store
        .enqueue(&MutationDraft {
            item,
            payload: json!({"op":"patch"}),
            base_rev: None,
            origin: None,
            mirror: None,
        })
        .unwrap();
    let taken = store.take_due_at(1_000, 5).unwrap();
    assert_eq!(taken[0].id, m);
    assert!(
        store.take_due_at(2_000, 5).unwrap().is_empty(),
        "租約未過不可重取"
    );
    let re = store
        .take_due_at(1_000 + bw_store::LEASE_MS + 1, 5)
        .unwrap();
    assert_eq!(re.len(), 1, "租約過期可重取（崩潰復原）");
    assert_eq!(re[0].id, m);
}

#[test]
fn conflicts_inbox() {
    let (_d, path) = tmp_vault("conflict");
    let store = Store::open(&path).unwrap();
    let item = Uuid::new_v4();
    let m = store
        .enqueue(&MutationDraft {
            item,
            payload: json!({"op":"patch","fields":{"password":"2.x|y|z"}}),
            base_rev: Some("rev-a"),
            origin: Some("sess-9"),
            mirror: None,
        })
        .unwrap();
    store.take_due(1).unwrap();
    store.settle(m, MutState::Conflict).unwrap();
    let c = store.conflicts().unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].id, m);
    assert_eq!(c[0].base_rev.as_deref(), Some("rev-a"));
    assert_eq!(c[0].origin.as_deref(), Some("sess-9"));
    assert_eq!(c[0].ours["fields"]["password"], "2.x|y|z");
    // conflict 未裁決前，同 item 後續寫入不得出境
    let m2 = store
        .enqueue(&MutationDraft {
            item,
            payload: json!({"op":"patch","b":2}),
            base_rev: Some("rev-a"),
            origin: None,
            mirror: None,
        })
        .unwrap();
    assert!(store.take_due(5).unwrap().is_empty());
    store.settle(m2, MutState::Applied).unwrap(); // 人工裁決後放行
}

#[test]
fn enqueue_with_mirror_is_one_transaction() {
    let (_d, path) = tmp_vault("mirror");
    let store = Store::open(&path).unwrap();
    let item = Uuid::new_v4();
    let mirror = cipher(
        &item.to_string(),
        "2.p|a|t",
        "2026-10-03T00:00:00.000Z",
        false,
    );
    store
        .enqueue(&MutationDraft {
            item,
            payload: json!({"op":"create"}),
            base_rev: None,
            origin: None,
            mirror: Some(&mirror),
        })
        .unwrap();
    assert!(
        store.item(item).unwrap().is_some(),
        "鏡像與 outbox 同交易落地"
    );
    assert!(store.meta(item).unwrap().unwrap().pending);
}

#[test]
fn audit_chain_verifies_and_detects_tamper() {
    let (_d, path) = tmp_vault("audit");
    let store = Store::open(&path).unwrap();
    let rec = |i: u32| AuditRecord {
        ts: format!("2026-10-29T00:00:{i:02}Z"),
        session: Some("s".into()),
        action: "reveal".into(),
        item: Some(Uuid::new_v4().to_string()),
        field: Some(json!("Password")),
        sens: bw_proto::Sensitivity::Secret,
        outcome: "ok".into(),
        bytes_out: 12,
        approval: None,
        epoch: 3,
    };
    for i in 0..3 {
        store.audit_append(&rec(i)).unwrap();
    }
    let (n, head) = store.audit_verify().unwrap();
    assert_eq!(n, 3);
    assert_eq!(head.len(), 64);
    assert_eq!(store.audit_head().unwrap().unwrap(), head);

    // append-only：UPDATE/DELETE 被 trigger 擋下
    let conn = rusqlite::Connection::open(&path).unwrap();
    let e = conn.execute_batch("UPDATE audit SET outcome='hacked' WHERE seq=1;");
    assert!(e.is_err(), "audit 表不可 UPDATE");
    let e = conn.execute_batch("DELETE FROM audit WHERE seq=1;");
    assert!(e.is_err(), "audit 表不可 DELETE");
    drop(conn);

    // 篡改偵測：繞過 trigger 直接改 DB（模擬離線篡改），重算鏈必須斷
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "DROP TRIGGER audit_no_update;
             UPDATE audit SET bytes_out=999 WHERE seq=2;",
        )
        .unwrap();
    }
    let err = store.audit_verify().expect_err("篡改必須被偵測");
    match err {
        StoreError::ChainBroken { seq, .. } => assert_eq!(seq, 2),
        other => panic!("wrong error: {other}"),
    }

    // 過濾查詢
    let all = store
        .audit_query(&bw_store::AuditFilter {
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].bytes_out, 12, "query 是唯讀視角，不改寫內容");
}

#[test]
fn blobs_content_addressed_and_perm_0600() {
    let (_d, path) = tmp_vault("blob");
    let store = Store::open(&path).unwrap();
    let r = store.blob_put(b"attachment-bytes").unwrap();
    assert_eq!(r.len(), 64);
    // 冪等：同內容同 ref
    assert_eq!(store.blob_put(b"attachment-bytes").unwrap(), r);
    assert_eq!(store.blob_open(&r).unwrap(), b"attachment-bytes");
    let file = path
        .parent()
        .unwrap()
        .join("blobs")
        .join(&r[0..2])
        .join(&r[2..]);
    assert_eq!(mode(&file), 0o600, "blob 檔必须 0600");
    assert!(store.blob_missing().unwrap().is_empty());

    std::fs::remove_file(&file).unwrap();
    assert_eq!(store.blob_missing().unwrap(), vec![r.clone()]);

    let bad = store.blob_open("zz");
    assert!(matches!(bad, Err(StoreError::Invalid(_))));
}

#[test]
fn sessions_persist_and_cascade_revoke() {
    let (_d, path) = tmp_vault("sessions");
    let store = Store::open(&path).unwrap();
    let mk = |id: &str, epoch: u64| bw_store::SessionRow {
        id: id.to_string(),
        principal: json!({"kind":"cli"}),
        grants: json!(["reveal"]),
        epoch,
        state: bw_store::SessionState::Active,
        created_at: 1,
        expires_at: None,
    };
    store.session_put(&mk("a", 1)).unwrap();
    store.session_put(&mk("b", 2)).unwrap();
    // epoch 1 之後 lock 過：綁 1 的 session 全撤
    assert_eq!(store.sessions_revoke_before(2).unwrap(), 1);
    let a = store.session_get("a").unwrap().unwrap();
    assert_eq!(a.state, bw_store::SessionState::Revoked);
    assert_eq!(
        store.session_get("b").unwrap().unwrap().state,
        bw_store::SessionState::Active
    );
    assert_eq!(store.session_list().unwrap().len(), 2);
    // 過期掃描
    store
        .session_put(&bw_store::SessionRow {
            expires_at: Some(50),
            ..mk("c", 2)
        })
        .unwrap();
    assert_eq!(store.sessions_expire(100).unwrap(), 1);
}

#[test]
fn push_tokens_put_list_remove_converge() {
    let (_d, path) = tmp_vault("push");
    let store = Store::open(&path).unwrap();
    store.push_token_put("AAAA1111BBB", "ios").unwrap();
    store.push_token_put("CCCC2222DDD", "watchos").unwrap();
    // 重複註冊同 token：REPLACE 不加倍，platform 更新（app 每次啟動重報）
    store.push_token_put("AAAA1111BBB", "ios-safari").unwrap();
    let mut got = store.push_token_list().unwrap();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("AAAA1111BBB".to_string(), "ios-safari".to_string()),
            ("CCCC2222DDD".to_string(), "watchos".to_string()),
        ]
    );
    // 410 清理路徑的 store 端收斂：移除後不在清單；重刪不存在 token 不报错
    store.push_token_remove("AAAA1111BBB").unwrap();
    store.push_token_remove("AAAA1111BBB").unwrap();
    assert_eq!(
        store.push_token_list().unwrap(),
        vec![("CCCC2222DDD".to_string(), "watchos".to_string())]
    );
}

/// v8→v9 遷移（PR1 子批 d，Q4）：舊庫（三欄 FTS）升級後新增兩張型別節索引欄、
/// meta_fts 整組重建收斂五欄形態，且值搜尋命中卡片末四碼／身分姓氏。
#[test]
fn v9_migration_adds_type_node_index_and_fts_rebuild() {
    let (_d, path) = tmp_vault("v9migrate");
    // 造 v8 舊庫：手工建三欄 meta_plain + 三欄 FTS + trigger，user_version=8。
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta_plain(
               id TEXT PRIMARY KEY, name TEXT, uris TEXT NOT NULL DEFAULT '[]',
               kind INTEGER, folder TEXT, org TEXT, favorite INTEGER NOT NULL DEFAULT 0,
               updated_at TEXT, pending INTEGER NOT NULL DEFAULT 0,
               username_plain TEXT, password_plain TEXT,
               fields_plain TEXT NOT NULL DEFAULT '[]', deleted_at TEXT, archived_at TEXT);
             CREATE VIRTUAL TABLE meta_fts USING fts5(
               name, uris, fields_plain, content='meta_plain', content_rowid='rowid',
               tokenize='unicode61');
             CREATE TABLE ciphers(id TEXT PRIMARY KEY, enc_cipher BLOB NOT NULL, raw BLOB NOT NULL, rev TEXT, deleted INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE overlay(id TEXT PRIMARY KEY, tags TEXT NOT NULL DEFAULT '[]', pinned INTEGER NOT NULL DEFAULT 0, last_used INTEGER, sort_hint REAL);
             CREATE TABLE outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT NOT NULL, base_rev TEXT, payload BLOB NOT NULL, state TEXT NOT NULL, origin TEXT, created_at INTEGER NOT NULL, leased_at INTEGER);
             CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, session TEXT, action TEXT NOT NULL, item TEXT, field TEXT, sens INTEGER NOT NULL, outcome TEXT NOT NULL, bytes_out INTEGER NOT NULL, approval TEXT, epoch INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
             CREATE TABLE sessions(id TEXT PRIMARY KEY, principal TEXT NOT NULL, grants TEXT NOT NULL, epoch INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER);
             CREATE TABLE push_tokens(token TEXT PRIMARY KEY, platform TEXT NOT NULL, registered_at INTEGER NOT NULL);
             CREATE TABLE blobs(ref TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE orgs(id TEXT PRIMARY KEY, raw BLOB NOT NULL, name TEXT, key TEXT, public_key TEXT, enc_private_key TEXT, key_verified INTEGER NOT NULL DEFAULT 0, status INTEGER, atype INTEGER);
             CREATE TABLE collections(id TEXT PRIMARY KEY, org TEXT NOT NULL, name TEXT, raw BLOB NOT NULL);
             CREATE TABLE cipher_collections(cipher TEXT NOT NULL, collection TEXT NOT NULL, PRIMARY KEY(cipher,collection));
             CREATE TABLE folders(id TEXT PRIMARY KEY, name TEXT, rev TEXT, raw BLOB NOT NULL);
             CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher TEXT NOT NULL, file_name TEXT, size INTEGER, size_name TEXT, key TEXT, url TEXT);
             CREATE TABLE sends(id TEXT PRIMARY KEY, stype INTEGER NOT NULL, name TEXT, key TEXT, access_id TEXT, deletion_date TEXT, expiration_date TEXT, max_access_count INTEGER, access_count INTEGER NOT NULL DEFAULT 0, hide_email INTEGER NOT NULL DEFAULT 0, file_id TEXT, file_name TEXT, file_size INTEGER, rev TEXT, raw BLOB NOT NULL);
             PRAGMA user_version = 8;",
        )
        .unwrap();
        drop(conn);
    }
    // 開庫觸發遷移：user_version 8→9，兩欄 ALTER + FTS 五欄重建。
    let store = Store::open(&path).unwrap();
    let cid = Uuid::new_v4();
    let iid = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&cid.to_string(), "2.card|c|m", "2026-11-16T00:00:00.000Z", false),
                cipher(&iid.to_string(), "2.idn|i|m", "2026-11-16T00:00:00.000Z", false),
            ]
        }))
        .unwrap();
    // 明文索引回填：卡片末四碼 4242、身分姓氏 Chen。
    store.set_plain_type_nodes(cid, Some("4242"), None).unwrap();
    store.set_plain_type_nodes(iid, None, Some("Chen")).unwrap();
    // 值搜尋命中卡片末四碼（精確）
    let hits = store
        .query(
            &Query {
                value: Some("4242".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "卡片末四碼值搜尋");
    assert_eq!(hits[0].id, cid);
    // 值搜尋命中身分姓氏（前綴）
    let hits = store
        .query(
            &Query {
                value: Some("Che".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "身分姓氏前綴值搜尋");
    assert_eq!(hits[0].id, iid);
    // FTS 重建後文字搜尋仍可用（name 欄命中）＋遷移沒破壞既有 trigger。
    let hits = store
        .query(
            &Query {
                text: Some("2.card".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(hits.iter().any(|h| h.id == cid), "FTS 重建後文字搜尋存活");
}

/// v9→v10 遷移（D1 落盤安全）：password_plain 退役→password_hmac、遷移後
/// 舊明文不殘留盤上（DROP COLUMN 重寫＋secure_delete）、值搜尋改標籤等值
/// 語意（識別欄照舊、密碼項需呼叫端給 32 bytes HMAC 標籤）。
#[test]
fn v10_migration_password_hmac_scrubs_plaintext() {
    let (_d, path) = tmp_vault("v10migrate");
    let row_id = "11111111-1111-1111-1111-111111111111";
    // 造 v9 舊庫（含 password_plain 明文行），user_version=9。
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta_plain(
               id TEXT PRIMARY KEY, name TEXT, uris TEXT NOT NULL DEFAULT '[]',
               kind INTEGER, folder TEXT, org TEXT, favorite INTEGER NOT NULL DEFAULT 0,
               updated_at TEXT, pending INTEGER NOT NULL DEFAULT 0,
               username_plain TEXT, password_plain TEXT,
               fields_plain TEXT NOT NULL DEFAULT '[]', deleted_at TEXT, archived_at TEXT,
               card_number_tail TEXT, identity_last_name TEXT);
             CREATE VIRTUAL TABLE meta_fts USING fts5(
               name, uris, fields_plain, card_number_tail, identity_last_name,
               content='meta_plain', content_rowid='rowid', tokenize='unicode61');
             CREATE TABLE ciphers(id TEXT PRIMARY KEY, enc_cipher BLOB NOT NULL, raw BLOB NOT NULL, rev TEXT, deleted INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE overlay(id TEXT PRIMARY KEY, tags TEXT NOT NULL DEFAULT '[]', pinned INTEGER NOT NULL DEFAULT 0, last_used INTEGER, sort_hint REAL);
             CREATE TABLE outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT NOT NULL, base_rev TEXT, payload BLOB NOT NULL, state TEXT NOT NULL, origin TEXT, created_at INTEGER NOT NULL, leased_at INTEGER);
             CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, session TEXT, action TEXT NOT NULL, item TEXT, field TEXT, sens INTEGER NOT NULL, outcome TEXT NOT NULL, bytes_out INTEGER NOT NULL, approval TEXT, epoch INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
             CREATE TABLE sessions(id TEXT PRIMARY KEY, principal TEXT NOT NULL, grants TEXT NOT NULL, epoch INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER);
             CREATE TABLE push_tokens(token TEXT PRIMARY KEY, platform TEXT NOT NULL, registered_at INTEGER NOT NULL);
             CREATE TABLE blobs(ref TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE orgs(id TEXT PRIMARY KEY, raw BLOB NOT NULL, name TEXT, key TEXT, public_key TEXT, enc_private_key TEXT, key_verified INTEGER NOT NULL DEFAULT 0, status INTEGER, atype INTEGER);
             CREATE TABLE collections(id TEXT PRIMARY KEY, org TEXT NOT NULL, name TEXT, raw BLOB NOT NULL);
             CREATE TABLE cipher_collections(cipher TEXT NOT NULL, collection TEXT NOT NULL, PRIMARY KEY(cipher,collection));
             CREATE TABLE folders(id TEXT PRIMARY KEY, name TEXT, rev TEXT, raw BLOB NOT NULL);
             CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher TEXT NOT NULL, file_name TEXT, size INTEGER, size_name TEXT, key TEXT, url TEXT);
             CREATE TABLE sends(id TEXT PRIMARY KEY, stype INTEGER NOT NULL, name TEXT, key TEXT, access_id TEXT, deletion_date TEXT, expiration_date TEXT, max_access_count INTEGER, access_count INTEGER NOT NULL DEFAULT 0, hide_email INTEGER NOT NULL DEFAULT 0, file_id TEXT, file_name TEXT, file_size INTEGER, rev TEXT, raw BLOB NOT NULL);
             CREATE TRIGGER meta_plain_ai AFTER INSERT ON meta_plain BEGIN
               INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
             END;
             CREATE TRIGGER meta_plain_ad AFTER DELETE ON meta_plain BEGIN
               INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
             END;
             CREATE TRIGGER meta_plain_au AFTER UPDATE ON meta_plain BEGIN
               INSERT INTO meta_fts(meta_fts, rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES('delete', old.rowid, old.name, old.uris, old.fields_plain, old.card_number_tail, old.identity_last_name);
               INSERT INTO meta_fts(rowid, name, uris, fields_plain, card_number_tail, identity_last_name) VALUES (new.rowid, new.name, new.uris, new.fields_plain, new.card_number_tail, new.identity_last_name);
             END;
             INSERT INTO ciphers(id, enc_cipher, raw, rev, deleted) VALUES('11111111-1111-1111-1111-111111111111', x'01', x'01', 'r', 0);
             INSERT INTO meta_plain(id, name, username_plain, password_plain)
               VALUES('11111111-1111-1111-1111-111111111111', 'Legacy', 'alice', 'legacy-secret-pw');
             PRAGMA user_version = 9;",
        )
        .unwrap();
        drop(conn);
    }
    let store = Store::open(&path).unwrap();
    // 欄位形態：password_hmac 在、password_plain 退役；版本收斂 10；secure_delete 開。
    let conn = rusqlite::Connection::open(&path).unwrap();
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('meta_plain')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(cols.iter().any(|c| c == "password_hmac"), "{cols:?}");
    assert!(!cols.iter().any(|c| c == "password_plain"), "{cols:?}");
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 10);
    drop(conn);
    assert!(
        store.secure_delete_enabled().unwrap(),
        "D1：連線必開 secure_delete"
    );
    // 舊明文不殘留：主檔＋WAL 全檔掃。
    let mut disk = Vec::new();
    for suffix in ["", "-wal"] {
        let p = format!("{}{}", path.display(), suffix);
        if let Ok(b) = std::fs::read(&p) {
            disk.extend_from_slice(&b);
        }
    }
    assert!(
        !disk
            .windows(b"legacy-secret-pw".len())
            .any(|w| w == b"legacy-secret-pw"),
        "v10 遷移後盤上不得殘留舊密碼明文"
    );
    let id = Uuid::parse_str(row_id).unwrap();
    // 未 reindex：密碼項永不命中（NULL 標籤）、識別欄照舊命中。
    let hits = store
        .query(
            &Query {
                value: Some("alice".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "username 識別欄值搜尋不受遷移影響");
    // 回填 HMAC 標籤後：同標籤命中、它標籤不命中（等值語意）。
    store
        .set_plain_secrets(id, Some("alice"), Some(&[7u8; 32]))
        .unwrap();
    let hits = store
        .query(
            &Query {
                value: Some("anything".into()),
                ..Default::default()
            },
            Some(&[7u8; 32]),
        )
        .unwrap();
    assert_eq!(hits.len(), 1, "密碼 HMAC 等值命中");
    let hits = store
        .query(
            &Query {
                value: Some("anything".into()),
                ..Default::default()
            },
            Some(&[8u8; 32]),
        )
        .unwrap();
    assert!(hits.is_empty(), "錯標籤不得命中");
}

#[test]
fn schema_version_guard() {
    let (_d, path) = tmp_vault("version");
    let store = Store::open(&path).unwrap();
    drop(store);
    // 未來版本：user_version 高于本 crate 認識 → 拒絕開啟（遷移只能前滾）
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
    }
    match Store::open(&path) {
        Ok(_) => panic!("user_version 99 應拒絕開啟"),
        Err(e) => assert!(matches!(e, StoreError::SchemaVersion(99))),
    }
}

// P5-b3：uri 過濾 host 錨定（credential.match 教訓：整頁 URL 直查不得恆空、
// 子字串不得誤命中）
#[test]
fn query_uri_host_anchoring() {
    let (_d, path) = tmp_vault("anchor");
    let store = Store::open(&path).unwrap();
    let gh = Uuid::new_v4();
    let sub = Uuid::new_v4();
    let evil = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&gh.to_string(), "GitHub", "2026-10-01T00:00:00.000Z", false),
                cipher(&sub.to_string(), "Gist", "2026-10-02T00:00:00.000Z", false),
                cipher(&evil.to_string(), "Evil", "2026-10-03T00:00:00.000Z", false),
            ]
        }))
        .unwrap();
    store
        .set_plain_meta(
            gh,
            Some("GitHub"),
            &["https://github.com/login".into()],
            &[],
        )
        .unwrap();
    store
        .set_plain_meta(
            sub,
            Some("Gist"),
            &["https://gist.github.com/x".into()],
            &[],
        )
        .unwrap();
    store
        .set_plain_meta(evil, Some("Evil"), &["https://notgithub.com".into()], &[])
        .unwrap();

    // 整頁 URL 查詢：精確 host ＋ 子網域都命中，notgithub.com 不得誤入
    let hits = store
        .query(
            &Query {
                uri: Some("https://github.com/login?x=1".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.id).collect();
    assert!(
        ids.contains(&gh) && ids.contains(&sub) && !ids.contains(&evil),
        "{ids:?}"
    );

    // 子網域後綴命中（gist.github.com ∈ github.com）
    let hits = store
        .query(
            &Query {
                uri: Some("github.com".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 2);

    // 子字串不再誤命中：notgithub.com 不屬於 github.com
    let hits = store
        .query(
            &Query {
                uri: Some("otgithub.com".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(hits.is_empty());
}

fn org_fixture(id: &str, key: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": "2.orgname|ct|mac",
        "key": key,
        "status": 2,
        "type": 0,
        "keys": {
            "publicKey": "MIIBIjAN-PUB",
            "encryptedPrivateKey": "2.orgpriv|ct|mac"
        },
        "object": "profileOrganization"
    })
}

fn collection_fixture(id: &str, org: &str) -> serde_json::Value {
    json!({
        "id": id,
        "organizationId": org,
        "name": "2.collname|ct|mac",
        "object": "collection"
    })
}

fn shared_cipher(id: &str, org: &str, cols: &[String]) -> serde_json::Value {
    let mut c = cipher(id, "2.shared|ct|mac", "2026-10-01T00:00:00.000Z", false);
    c["organizationId"] = json!(org);
    c["collectionIds"] = json!(cols);
    c
}

#[test]
fn apply_sync_lands_orgs_collections_and_membership() {
    let (_d, path) = tmp_vault("org_sync");
    let store = Store::open(&path).unwrap();
    let org = Uuid::new_v4().to_string();
    let col = Uuid::new_v4().to_string();
    let shared = Uuid::new_v4().to_string();
    let personal = Uuid::new_v4().to_string();
    let akey = format!("2.{org}|ct|mac");
    store
        .apply_sync(&json!({
            "ciphers": [
                shared_cipher(&shared, &org, std::slice::from_ref(&col)),
                cipher(&personal, "2.p|c|m", "2026-10-01T00:00:00.000Z", false),
            ],
            "collections": [collection_fixture(&col, &org)],
            "profile": { "organizations": [org_fixture(&org, &akey)] },
        }))
        .unwrap();

    assert_eq!(store.org_count().unwrap(), 1);
    let o = store.org(Uuid::parse_str(&org).unwrap()).unwrap().unwrap();
    assert_eq!(o.key.as_deref(), Some(akey.as_str()));
    assert_eq!(o.public_key.as_deref(), Some("MIIBIjAN-PUB"));
    assert_eq!(o.enc_private_key.as_deref(), Some("2.orgpriv|ct|mac"));
    assert_eq!(o.status, Some(2));
    assert!(!o.key_verified);
    let cols = store.collection_list().unwrap();
    assert_eq!(cols.len(), 1);
    assert_eq!(cols[0].org, Uuid::parse_str(&org).unwrap());

    // 共享項目 metadata 帶 org/collection 歸屬；個人項目恆空
    let m = store
        .meta(Uuid::parse_str(&shared).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(m.organization_id, Some(Uuid::parse_str(&org).unwrap()));
    assert_eq!(m.collections, vec![Uuid::parse_str(&col).unwrap()]);
    let p = store
        .meta(Uuid::parse_str(&personal).unwrap())
        .unwrap()
        .unwrap();
    assert!(p.collections.is_empty() && p.organization_id.is_none());

    // Query.collection 過濾只回該集合的項目
    let hits = store
        .query(
            &Query {
                collection: Some(Uuid::parse_str(&col).unwrap()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, Uuid::parse_str(&shared).unwrap());

    // 全量替換語意：再同步缺 org/collection → 表清空
    store
        .apply_sync(&json!({
            "ciphers": [cipher(&personal, "2.p|c|m", "2026-10-02T00:00:00.000Z", false)],
        }))
        .unwrap();
    assert_eq!(store.org_count().unwrap(), 0);
    assert!(store.collection_list().unwrap().is_empty());
    assert!(
        store
            .meta(Uuid::parse_str(&personal).unwrap())
            .unwrap()
            .unwrap()
            .collections
            .is_empty()
    );
}

#[test]
fn apply_sync_accepts_v2_objects_shape() {
    let (_d, path) = tmp_vault("org_sync_v2");
    let store = Store::open(&path).unwrap();
    let org = Uuid::new_v4().to_string();
    let col = Uuid::new_v4().to_string();
    let shared = Uuid::new_v4().to_string();
    store
        .apply_sync(&json!({
            "version": 1,
            "objects": {
                "ciphers": [shared_cipher(&shared, &org, std::slice::from_ref(&col))],
                "collections": [collection_fixture(&col, &org)],
                "organizations": [org_fixture(&org, "4.rsawrapped")],
            },
        }))
        .unwrap();
    assert_eq!(store.org_count().unwrap(), 1);
    assert_eq!(store.collection_list().unwrap().len(), 1);
    assert_eq!(
        store
            .query(
                &Query {
                    collection: Some(Uuid::parse_str(&col).unwrap()),
                    ..Default::default()
                },
                None
            )
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn put_mirror_replaces_collection_membership() {
    let (_d, path) = tmp_vault("org_mirror");
    let store = Store::open(&path).unwrap();
    let org = Uuid::new_v4();
    let col_a = Uuid::new_v4();
    let col_b = Uuid::new_v4();
    let id = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [shared_cipher(
                &id.to_string(),
                &org.to_string(),
                &[col_a.to_string()],
            )],
            "collections": [collection_fixture(&col_a.to_string(), &org.to_string())],
            "profile": { "organizations": [org_fixture(&org.to_string(), "2.k|c|m")] },
        }))
        .unwrap();
    assert_eq!(store.meta(id).unwrap().unwrap().collections, vec![col_a]);
    // unshare：同一 cipher 換成 col_b 歸屬（move 後 put_mirror 的形態）
    store
        .put_mirror(
            id,
            &shared_cipher(&id.to_string(), &org.to_string(), &[col_b.to_string()]),
        )
        .unwrap();
    assert_eq!(store.meta(id).unwrap().unwrap().collections, vec![col_b]);
    // 完全撤出集合 → 個人項目
    store
        .put_mirror(
            id,
            &cipher(
                &id.to_string(),
                "2.p|c|m",
                "2026-10-03T00:00:00.000Z",
                false,
            ),
        )
        .unwrap();
    assert!(store.meta(id).unwrap().unwrap().collections.is_empty());
}

#[test]
fn org_key_verified_survives_sync_rebuild() {
    let (_d, path) = tmp_vault("org_verify");
    let store = Store::open(&path).unwrap();
    let org = Uuid::new_v4();
    let payload = json!({
        "ciphers": [],
        "collections": [],
        "profile": { "organizations": [org_fixture(&org.to_string(), "2.k|c|m")] },
    });
    store.apply_sync(&payload).unwrap();
    store.org_mark_verified(org, true).unwrap();
    // 重放同一 /sync：驗證結果不被鏡像重建抹除（避免每次 sync 重驗 RSA）
    store.apply_sync(&payload).unwrap();
    assert!(store.org(org).unwrap().unwrap().key_verified);
    // 換成新 org（不同 id）→ 從 0 開始
    let org2 = Uuid::new_v4();
    store
        .apply_sync(&json!({
            "ciphers": [],
            "profile": { "organizations": [org_fixture(&org2.to_string(), "2.k2|c|m")] },
        }))
        .unwrap();
    assert!(!store.org(org2).unwrap().unwrap().key_verified);
}

/// 真實錄製的 VW 1.37.2 org /sync（`dev/e2e/orgpath.sh` RECORD_FIXTURES=1 產出）。
fn recorded_sync(name: &str) -> serde_json::Value {
    let p = format!("{}/../bw-sync/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn apply_sync_replays_recorded_org_sync() {
    for fixture in ["sync_org_owner_vw.json", "sync_org_member_vw.json"] {
        let (_d, path) = tmp_vault("org_replay");
        let store = Store::open(&path).unwrap();
        let sync = recorded_sync(fixture);
        let shared = sync
            .get("ciphers")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .find(|c| !c["collectionIds"].as_array().unwrap().is_empty())
            .unwrap();
        let org_id = shared["organizationId"].as_str().unwrap();
        let col_id = shared["collectionIds"][0].as_str().unwrap();
        store.apply_sync(&sync).unwrap();

        assert_eq!(store.org_count().unwrap(), 1, "{fixture}");
        let o = store
            .org(Uuid::parse_str(org_id).unwrap())
            .unwrap()
            .unwrap();
        // owner 落 `2.` 對稱 akey、成員落 `4.` RSA akey（協定兩態都要如實鏡像）
        let prefix = o.key.as_deref().unwrap().chars().next().unwrap();
        assert!(matches!(prefix, '2' | '4'), "{fixture} akey={prefix}");
        assert!(o.public_key.is_none(), "VW 的 /sync 不含 org 公開金鑰");
        assert!(!store.collection_list().unwrap().is_empty(), "{fixture}");

        let hits = store
            .query(
                &Query {
                    collection: Some(Uuid::parse_str(col_id).unwrap()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(hits.len(), 1, "{fixture}");
        assert_eq!(
            hits[0].id,
            Uuid::parse_str(shared["id"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            hits[0].organization_id,
            Some(Uuid::parse_str(org_id).unwrap())
        );
        assert_eq!(hits[0].collections, vec![Uuid::parse_str(col_id).unwrap()]);
    }
}

// —— v5 三件套：資料夾鏡像／欄名索引／垃圾桶三態與硬刪 ——

#[test]
fn apply_sync_lands_folders_and_folder_filter() {
    let (_d, path) = tmp_vault("folders");
    let store = Store::open(&path).unwrap();
    let folder = Uuid::new_v4().to_string();
    let in_folder = Uuid::new_v4().to_string();
    let unfiled = Uuid::new_v4().to_string();
    let mut c1 = cipher(&in_folder, "2.n|n|n", "2026-11-01T00:00:00.000Z", false);
    c1["folderId"] = json!(&folder);
    let c2 = cipher(&unfiled, "2.n2|n2|n2", "2026-11-01T00:00:00.000Z", false);
    store
        .apply_sync(&json!({
            "ciphers": [c1, c2],
            "folders": [{
                "id": folder,
                "name": "2.f|f|f",
                "revisionDate": "2026-11-01T00:00:00.000Z"
            }],
        }))
        .unwrap();
    let folders = store.folder_list().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].id.to_string(), folder);
    assert_eq!(
        folders[0].name.as_deref(),
        Some("2.f|f|f"),
        "名稱鏡像存信封原樣"
    );

    let hits = store
        .query(
            &Query {
                folder: Some(folder.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id.to_string(), in_folder);
    assert_eq!(
        hits[0].folder_id,
        Some(Uuid::parse_str(&folder).unwrap()),
        "ItemMeta.folder_id 投影自鏡像 folderId"
    );
    let unfiled_hits = store
        .query(
            &Query {
                folder: Some(String::new()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(unfiled_hits.len(), 1);
    assert_eq!(unfiled_hits[0].id.to_string(), unfiled);
    let all = store
        .query(
            &Query {
                folder: None,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(all.len(), 2);

    // 全量替換語意：第二批沒帶 folders → 鏡像清空
    store.apply_sync(&json!({ "ciphers": [] })).unwrap();
    assert!(store.folder_list().unwrap().is_empty());

    // 即時 upsert／摘列（create/delete 收斂路徑用）
    store
        .folder_put(
            Uuid::parse_str(&folder).unwrap(),
            &json!({"id": folder, "name": "2.f|f|f", "revisionDate": "r1"}),
        )
        .unwrap();
    assert_eq!(store.folder_list().unwrap().len(), 1);
    store
        .folder_remove(Uuid::parse_str(&folder).unwrap())
        .unwrap();
    assert!(store.folder_list().unwrap().is_empty());
    store.folder_remove(Uuid::new_v4()).unwrap(); // 不存在的列：冪等 no-op
}

#[test]
fn fields_plain_indexes_names_not_values() {
    let (_d, path) = tmp_vault("fields_plain");
    let store = Store::open(&path).unwrap();
    let id = Uuid::new_v4();
    store
        .apply_sync(&json!({ "ciphers": [cipher(&id.to_string(), "2.n|n|n", "rev", false)] }))
        .unwrap();
    store
        .set_plain_meta(
            id,
            Some("GitHub"),
            &[],
            &["PIN".to_string(), "會員".to_string()],
        )
        .unwrap();
    // 欄名進 FTS：搜 "PIN" 命中
    let hits = store
        .query(
            &Query {
                text: Some("PIN".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    // hidden 欄值不入索引：值搜（q.value 走 username/password 明文欄）不經
    // fields_plain；欄名欄只由 set_plain_meta 寫入（PlainIndex.field_names
    // 端不收值，見 bw-vault 測試）。
    let by_value = store
        .query(
            &Query {
                value: Some("PIN".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(by_value.is_empty());
}

#[test]
fn trash_tristate_and_purge() {
    let (_d, path) = tmp_vault("trash");
    let store = Store::open(&path).unwrap();
    let live = Uuid::new_v4().to_string();
    let gone = Uuid::new_v4().to_string();
    store
        .apply_sync(&json!({
            "ciphers": [
                cipher(&live, "live", "2026-11-01T00:00:00.000Z", false),
                cipher(&gone, "gone", "2026-11-01T00:00:00.000Z", true),
            ]
        }))
        .unwrap();
    // None 與 Some(false)：只列未刪（現行預設不回歸）
    for deleted in [None, Some(false)] {
        let hits = store
            .query(
                &Query {
                    deleted,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(hits.len(), 1, "deleted={deleted:?}");
        assert_eq!(hits[0].id.to_string(), live);
        assert_eq!(hits[0].deleted_at, None);
    }
    // Some(true)：垃圾桶，帶伺服器軟刪時刻
    let trash = store
        .query(
            &Query {
                deleted: Some(true),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].id.to_string(), gone);
    assert_eq!(
        trash[0].deleted_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
    // 軟刪列的 meta 單讀也還在（Get 垃圾桶條目要能看到 deleted_at）
    let m = store.meta(Uuid::parse_str(&gone).unwrap()).unwrap();
    assert!(m.is_some() && m.unwrap().deleted_at.is_some());

    // 硬刪：鏡像＋明文索引＋outbox＋overlay 全清
    store
        .enqueue(&MutationDraft {
            item: Uuid::parse_str(&gone).unwrap(),
            payload: json!({"op": "delete"}),
            base_rev: None,
            origin: None,
            mirror: None,
        })
        .unwrap();
    store
        .overlay(
            Uuid::parse_str(&gone).unwrap(),
            bw_store::OverlayOp::SetTags(vec!["x".into()]),
        )
        .unwrap();
    let n = store.purge(Uuid::parse_str(&gone).unwrap()).unwrap();
    assert_eq!(n, 1);
    assert!(
        store
            .item(Uuid::parse_str(&gone).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .meta(Uuid::parse_str(&gone).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .query(
                &Query {
                    deleted: Some(true),
                    ..Default::default()
                },
                None
            )
            .unwrap()
            .len(),
        0
    );
    // outbox 未推列與 overlay 殭屍列一併清除
    assert_eq!(store.depth().unwrap().queued, 0);
    assert!(matches!(
        store.overlay_get(Uuid::parse_str(&gone).unwrap()),
        Err(StoreError::NotFound)
    ));
    // 冪等：再 purge 不存在列回 0、不报错
    assert_eq!(store.purge(Uuid::parse_str(&gone).unwrap()).unwrap(), 0);
}

#[test]
fn enqueue_batch_is_all_or_nothing() {
    let (_d, path) = tmp_vault("batch");
    let store = Store::open(&path).unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let ma = json!({"id": a.to_string(), "type": 1, "name": "2.x|y|z"});
    let mb = json!({"id": b.to_string(), "type": 1, "name": "2.x|y|z"});
    let ids = store
        .enqueue_batch(&[
            MutationDraft {
                item: a,
                payload: json!({"op": "create", "cipher": {"type": 1, "name": "2.x|y|z"}}),
                base_rev: None,
                origin: None,
                mirror: Some(&ma),
            },
            MutationDraft {
                item: b,
                payload: json!({"op": "create", "cipher": {"type": 1, "name": "2.x|y|z"}}),
                base_rev: None,
                origin: None,
                mirror: Some(&mb),
            },
        ])
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert!(store.item(a).unwrap().is_some() && store.item(b).unwrap().is_some());
    assert_eq!(store.depth().unwrap().queued, 2);

    // 第二筆缺 id → 整批回滾：鏡像與 outbox 都不留半套
    let c = Uuid::new_v4();
    let d = Uuid::new_v4();
    let mc = json!({"id": c.to_string(), "type": 1, "name": "2.x|y|z"});
    let md = json!({"type": 1});
    let err = store
        .enqueue_batch(&[
            MutationDraft {
                item: c,
                payload: json!({"op": "create"}),
                base_rev: None,
                origin: None,
                mirror: Some(&mc),
            },
            MutationDraft {
                item: d,
                payload: json!({"op": "create"}),
                base_rev: None,
                origin: None,
                mirror: Some(&md),
            },
        ])
        .expect_err("缺 id 應整批失敗");
    assert!(matches!(err, StoreError::Invalid(_)));
    assert!(store.item(c).unwrap().is_none(), "回滾後 c 不得留鏡像");
    assert!(store.item(d).unwrap().is_none());
    assert_eq!(store.depth().unwrap().queued, 2, "回滾不得增列");
}

#[test]
fn attachments_mirror_and_awaiting_take_due() {
    let (_d, path) = tmp_vault("att");
    let store = Store::open(&path).unwrap();
    let cid = Uuid::new_v4();
    let mut c = cipher(&cid.to_string(), "2.n|n|n", "rev", false);
    // 官方形態 attachments 是 map（key=id）；size 是字串
    c["attachments"] = json!({
        "8fd01a914baeef9d1efd": {
            "id": "8fd01a914baeef9d1efd",
            "fileName": "2.fn|fn|fn",
            "size": "11",
            "sizeName": "11.00 bytes",
            "key": "2.kk|kk|kk",
            "url": "http://vw/attachments/x?token=t"
        }
    });
    store.apply_sync(&json!({ "ciphers": [c] })).unwrap();
    let rows = store.attachment_list(cid).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "8fd01a914baeef9d1efd");
    assert_eq!(rows[0].size, Some(11));
    assert_eq!(rows[0].file_name.as_deref(), Some("2.fn|fn|fn"));

    // Awaiting 態入列 → take_due 認領（附件離線佇列與 queued 同視）
    store
        .enqueue_state(
            &MutationDraft {
                item: cid,
                payload: json!({"op": "attach_upload"}),
                base_rev: None,
                origin: None,
                mirror: None,
            },
            MutState::Awaiting,
        )
        .unwrap();
    let due = store.take_due_at(0, 8).unwrap(); // now=0：租約未過也能取 awaiting/queued
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].state, MutState::Awaiting, "認領保留原態供重試回置");
}

#[test]
fn archived_tristate_projection_and_filter() {
    let (_d, path) = tmp_vault("arch7");
    let store = Store::open(&path).unwrap();
    let live = Uuid::new_v4().to_string();
    let archived = Uuid::new_v4().to_string();
    let c1 = cipher(&live, "live", "2026-11-01T00:00:00.000Z", false);
    let mut c2 = cipher(&archived, "arch", "2026-11-01T00:00:00.000Z", false);
    c2["archivedDate"] = json!("2026-11-10T00:00:00.000000Z");
    store.apply_sync(&json!({ "ciphers": [c1, c2] })).unwrap();
    // 預設與 Some(false)：主列表排除已封存（使用者實錄缺陷的正解）
    for archived_q in [None, Some(false)] {
        let hits = store
            .query(
                &Query {
                    archived: archived_q,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(hits.len(), 1, "archived={archived_q:?}");
        assert_eq!(hits[0].id.to_string(), live);
        assert_eq!(hits[0].archived_at, None);
    }
    // Some(true)：獨立檢視，帶封存時刻
    let only = store
        .query(
            &Query {
                archived: Some(true),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(only.len(), 1);
    assert_eq!(only[0].id.to_string(), archived);
    assert_eq!(
        only[0].archived_at.as_deref(),
        Some("2026-11-10T00:00:00.000000Z")
    );
    // 與 deleted 正交合成：封存＋軟刪＝只命中 archived×true + deleted×true
    let mixed = store
        .query(
            &Query {
                archived: Some(true),
                deleted: Some(true),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(mixed.is_empty());
    // 回填範圍單源：`all_ids` 不分三態全覆蓋（列表 query 組合枚舉會漏列，
    // 2026-11-11 缺陷：reindex 以預設＋垃圾桶兩條 query 圈定，已封存列漏網）
    let mut ids = store.all_ids().unwrap();
    ids.sort();
    let mut want = [
        live.parse::<Uuid>().unwrap(),
        archived.parse::<Uuid>().unwrap(),
    ];
    want.sort();
    assert_eq!(ids, want.to_vec(), "已封存列不得從全鏡像清單漏掉");
}

#[test]
fn all_ids_covers_every_state() {
    let (_d, path) = tmp_vault("allids");
    let store = Store::open(&path).unwrap();
    let live = Uuid::new_v4();
    let arch = Uuid::new_v4();
    let trash = Uuid::new_v4();
    let both = Uuid::new_v4();
    let mut c_arch = cipher(&arch.to_string(), "a", "2026-11-01T00:00:00.000Z", false);
    c_arch["archivedDate"] = json!("2026-11-10T00:00:00.000Z");
    let mut c_both = cipher(&both.to_string(), "b", "2026-11-01T00:00:00.000Z", true);
    c_both["archivedDate"] = json!("2026-11-10T00:00:00.000Z");
    store
        .apply_sync(&json!({ "ciphers": [
            cipher(&live.to_string(), "l", "2026-11-01T00:00:00.000Z", false),
            c_arch,
            cipher(&trash.to_string(), "t", "2026-11-01T00:00:00.000Z", true),
            c_both,
        ] }))
        .unwrap();
    let mut ids = store.all_ids().unwrap();
    ids.sort();
    let mut want = [live, arch, trash, both];
    want.sort();
    assert_eq!(ids, want.to_vec());
}

/// D1 perf 框（交錯 5 輪，release 跑）：556 筆 reindex 增量＝「明文寫入」
/// vs「HMAC 派生＋標籤寫入」兩條回填路徑同庫交錯計時，另列值搜尋（帶標籤）
/// 與純列表查詢的單次延遲。跑法：
/// `cargo test --release -p bw-store --test store -- --ignored --nocapture d1_reindex`
#[test]
#[ignore = "perf 框：需 --release 與 --ignored"]
fn d1_reindex_perf_556_interleaved() {
    const N: usize = 556;
    const ROUNDS: usize = 5;
    let (_d, path) = tmp_vault("d1perf");
    let store = Store::open(&path).unwrap();
    let ciphers: Vec<Value> = (0..N)
        .map(|i| {
            cipher(
                &Uuid::new_v4().to_string(),
                &format!("perf-{i}"),
                "2026-11-17T00:00:00.000Z",
                false,
            )
        })
        .collect();
    store.apply_sync(&json!({ "ciphers": ciphers })).unwrap();
    let ids = store.all_ids().unwrap();
    assert_eq!(ids.len(), N);
    let user_key = vec![3u8; 64];
    let index_key = bw_crypto::derive_index_key(&user_key);
    let rows: Vec<(Uuid, String, String)> = ids
        .iter()
        .copied()
        .enumerate()
        .map(|(i, id)| (id, format!("user-{i}"), format!("pw-{i}-reused")))
        .collect();
    let mut plain_ms = Vec::new();
    let mut hmac_ms = Vec::new();
    let mut value_q_us = Vec::new();
    let mut list_q_us = Vec::new();
    for _ in 0..ROUNDS {
        // 基線：值明文直接入欄（v9 形態的寫入量）。
        let t0 = std::time::Instant::now();
        for (id, u, p) in &rows {
            store
                .set_plain_secrets(*id, Some(u), Some(p.as_bytes()))
                .unwrap();
        }
        plain_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        // D1：每筆多一次 HMAC-SHA256（派生金鑰每批一次，不計入迴圈）。
        let t1 = std::time::Instant::now();
        for (id, u, p) in &rows {
            let tag = bw_crypto::index_value_tag(&index_key, p.as_bytes());
            store.set_plain_secrets(*id, Some(u), Some(&tag)).unwrap();
        }
        hmac_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
        // 讀側：值搜尋（帶標籤）與純列表單次延遲。
        let probe = rows[N / 2].2.clone();
        let tag = bw_crypto::index_value_tag(&index_key, probe.as_bytes());
        let t2 = std::time::Instant::now();
        let hits = store
            .query(
                &Query {
                    value: Some(probe),
                    ..Default::default()
                },
                Some(&tag),
            )
            .unwrap();
        value_q_us.push(t2.elapsed().as_secs_f64() * 1000.0 * 1000.0);
        assert_eq!(hits.len(), 1, "標籤值搜尋必精確命中");
        let t3 = std::time::Instant::now();
        let listed = store
            .query(
                &Query {
                    limit: u32::MAX,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        list_q_us.push(t3.elapsed().as_secs_f64() * 1000.0 * 1000.0);
        assert_eq!(listed.len(), N);
    }
    let fmt = |v: &Vec<f64>| {
        v.iter()
            .map(|x| format!("{x:.2}"))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    println!("D1 perf（{N} 筆，{ROUNDS} 輪交錯，release）");
    println!("  明文回填 ms    : {}", fmt(&plain_ms));
    println!("  HMAC 回填 ms   : {}", fmt(&hmac_ms));
    println!("  值搜尋 us      : {}", fmt(&value_q_us));
    println!("  列表 us        : {}", fmt(&list_q_us));
}
