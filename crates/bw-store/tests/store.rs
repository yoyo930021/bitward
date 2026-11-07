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
        .set_plain_meta(gh, Some("GitHub"), &["https://github.com/login".into()])
        .unwrap();
    store
        .set_plain_meta(gl, Some("GitLab"), &["https://gitlab.com".into()])
        .unwrap();

    let hits = store
        .query(&Query {
            text: Some("git".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 2, "前綴匹配兩筆");
    let hits = store
        .query(&Query {
            text: Some("github".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, gh);
    // uri 也在 FTS 範圍內
    let hits = store
        .query(&Query {
            text: Some("gitlab.com".into()),
            ..Default::default()
        })
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
        .set_plain_meta(a, Some("AAA"), &["https://a.example.com".into()])
        .unwrap();
    store
        .set_plain_meta(b, Some("bbb"), &["https://b.example.org".into()])
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
        .query(&Query {
            tag: Some("work".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, a);
    assert_eq!(hits[0].tags, vec!["work".to_string(), "vip".to_string()]);

    let hits = store
        .query(&Query {
            uri: Some("example.org".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, b);

    // 名稱排序不分大小寫
    let hits = store
        .query(&Query {
            sort: SortKey::Name,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        hits.iter().map(|h| h.id).collect::<Vec<_>>(),
        vec![a, b],
        "AAA < bbb (NOCASE)"
    );

    // Used 排序：有 last_used 的排前面
    let hits = store
        .query(&Query {
            sort: SortKey::Used,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits[0].id, b);

    // kind 過濾：全部是 Login(0)
    let hits = store
        .query(&Query {
            kind: Some(ItemKind::Card),
            ..Default::default()
        })
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
        .set_plain_meta(gh, Some("GitHub"), &["https://github.com/login".into()])
        .unwrap();
    store
        .set_plain_meta(sub, Some("Gist"), &["https://gist.github.com/x".into()])
        .unwrap();
    store
        .set_plain_meta(evil, Some("Evil"), &["https://notgithub.com".into()])
        .unwrap();

    // 整頁 URL 查詢：精確 host ＋ 子網域都命中，notgithub.com 不得誤入
    let hits = store
        .query(&Query {
            uri: Some("https://github.com/login?x=1".into()),
            ..Default::default()
        })
        .unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.id).collect();
    assert!(
        ids.contains(&gh) && ids.contains(&sub) && !ids.contains(&evil),
        "{ids:?}"
    );

    // 子網域後綴命中（gist.github.com ∈ github.com）
    let hits = store
        .query(&Query {
            uri: Some("github.com".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 2);

    // 子字串不再誤命中：notgithub.com 不屬於 github.com
    let hits = store
        .query(&Query {
            uri: Some("otgithub.com".into()),
            ..Default::default()
        })
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
        .query(&Query {
            collection: Some(Uuid::parse_str(&col).unwrap()),
            ..Default::default()
        })
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
            .query(&Query {
                collection: Some(Uuid::parse_str(&col).unwrap()),
                ..Default::default()
            })
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
            .query(&Query {
                collection: Some(Uuid::parse_str(col_id).unwrap()),
                ..Default::default()
            })
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
