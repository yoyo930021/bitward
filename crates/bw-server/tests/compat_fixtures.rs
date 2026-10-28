//! A2 / A2b：錄製 fixtures 的回放測試（契约 §6）。
//!
//! 這裡**不碰網路**：所有輸入都是 `fixtures/` 裡錄下來的位元組（來源與日期見
//! `fixtures/README.md`）。跑真 server 的是 `tests/e2e_vaultwarden.rs`。

use std::fs;
use std::path::Path;

use bw_server::auth::{PasswordLogin, parse_keys, parse_two_factor_challenge};
use bw_server::error::ApiError;
use bw_server::notify::{NotificationMode, UpdateType, decode_binary_record, interpret};
use bw_server::profile::{ProbeInputs, Quirk, assemble, classify, extract_urls};
use bw_server::vault::SyncResponse;
use bw_server::{ServerKind, TokenGrant};
use serde_json::{Value, json};

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// 錄下來的 form body（`a=1&b=2`）還原成欄位清單。
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_decode(k),
                percent_decode(v).trim_end_matches('\n').to_owned(),
            )
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16)
                        .unwrap(),
                );
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

fn login() -> PasswordLogin {
    PasswordLogin::new("fixture@bitward.test", "aGFzaA==", "u4-fixture-device")
}

// —— Keys 寬容解析 ——

#[test]
fn token_password_from_vaultwarden_parses_flattened_keys() {
    let raw = fixture_json("token_password_vw_1.37.2.json");
    let keys = parse_keys(&raw).expect("Vaultwarden 的扁平 Keys 必須解析成功");
    assert!(
        keys.key.as_deref().is_some_and(|k| k.starts_with("2.")),
        "user key 是信封字串"
    );
    assert!(keys.private_key.is_some());
    assert_eq!(keys.kdf, Some(0), "0 = PBKDF2-SHA256");
    assert_eq!(keys.kdf_iterations, Some(600_000));
    assert!(keys.has_user_decryption_options);
    assert_eq!(keys.kdf_memory, None);
    assert_eq!(keys.kdf_parallelism, None);
    assert!(
        keys.user_decryption_options
            .as_ref()
            .is_some_and(|v| v["HasMasterPassword"].as_bool() == Some(true))
    );
    assert!(keys.account_keys.is_some());
    assert!(keys.quirks().is_empty());
}

/// A2b：`UserDecryptionOptions` 缺失不是錯誤，而是 quirk（vaultwarden#6729 回歸）。
#[test]
fn missing_user_decryption_options_degrades_instead_of_failing() {
    let raw = fixture_json("token_password_vw_no_user_decryption_options.json");
    assert!(
        !raw.as_object()
            .unwrap()
            .keys()
            .any(|k| k.eq_ignore_ascii_case("UserDecryptionOptions"))
    );
    let keys = parse_keys(&raw).expect("缺欄位不能讓解析炸掉");
    assert!(keys.key.is_some(), "密碼解鎖路徑仍然完整");
    assert!(!keys.has_user_decryption_options);
    assert_eq!(keys.quirks(), vec![Quirk::MissingUserDecryptionOptions]);
}

/// 官方雲舊式的 `encrypted_payload`（base64 JSON）也要能取出 Keys。
#[test]
fn keys_inside_encrypted_payload_are_reachable() {
    let raw = fixture_json("token_password_cloud_encrypted_payload.json");
    assert!(raw.get("Key").is_none(), "這份是 encrypted_payload 形態");
    let keys = parse_keys(&raw).expect("encrypted_payload 裡的 Keys 要能找到");
    assert!(keys.key.as_deref().is_some_and(|k| k.starts_with("2.")));
    assert_eq!(keys.kdf_iterations, Some(600_000));
    assert!(keys.encrypted_payload.is_some());
}

#[test]
fn nested_keys_object_is_accepted() {
    let raw = json!({"access_token": "x", "Keys": {"Key": "2.a|b|c", "Kdf": 0, "KdfIterations": 710_000}});
    let keys = parse_keys(&raw).unwrap();
    assert_eq!(keys.key.as_deref(), Some("2.a|b|c"));
    assert_eq!(keys.kdf_iterations, Some(710_000));
    assert!(keys.quirks().contains(&Quirk::MissingUserDecryptionOptions));
}

/// API key 登入沒有 refresh_token，但 Vaultwarden 仍會把 KDF/Keys 一起回傳；
/// 那不代表能解鎖（解鎖要的是 stretched master key，API key 拿不到）。
#[test]
fn client_credentials_token_parses_without_refresh_token() {
    let raw = fixture_json("token_client_credentials_vw_1.37.2.json");
    assert!(raw.get("access_token").is_some());
    assert!(
        raw.get("refresh_token").is_none(),
        "client_credentials 不發 offline_access"
    );
    let keys = parse_keys(&raw).expect("VW 對 API key 也回 Keys");
    assert_eq!(keys.kdf_iterations, Some(600_000));
    assert!(keys.encrypted_payload.is_none());
}

// —— 2FA 兩步 ——

#[test]
fn two_factor_challenge_from_vaultwarden_array_form() {
    let body = fixture("token_2fa_challenge_vw_1.37.2.json");
    let err = ApiError::parse(400, &body);
    assert!(err.is_invalid_grant());
    assert_eq!(
        err.error_description.as_deref(),
        Some("Two factor required.")
    );
    let challenge = parse_two_factor_challenge(&err, login()).expect("必須辨識出 2FA 挑戰");
    assert_eq!(challenge.providers.len(), 1);
    assert_eq!(
        challenge.providers[0].kind,
        bw_server::TwoFactorProviderType::Authenticator
    );
    assert!(challenge.to_string().contains("Authenticator"));
}

#[test]
fn two_factor_challenge_from_cloud_map_form_lists_every_provider() {
    let body = fixture("token_2fa_challenge_cloud_map.json");
    let err = ApiError::parse(400, &body);
    let challenge = parse_two_factor_challenge(&err, login()).unwrap();
    let kinds: Vec<_> = challenge.providers.iter().map(|p| p.kind).collect();
    assert!(kinds.contains(&bw_server::TwoFactorProviderType::Authenticator));
    assert!(kinds.contains(&bw_server::TwoFactorProviderType::Email));
    let email = challenge
        .providers
        .iter()
        .find(|p| p.kind == bw_server::TwoFactorProviderType::Email)
        .unwrap();
    assert_eq!(
        email
            .details
            .as_ref()
            .and_then(|d| d.get("Email"))
            .and_then(Value::as_str),
        Some("t***a@bitward.test")
    );
}

#[test]
fn wrong_totp_code_is_a_plain_rejection_not_a_challenge() {
    let body = fixture("token_2fa_invalid_code_vw_1.37.2.json");
    let err = ApiError::parse(400, &body);
    assert!(
        !err.is_invalid_grant(),
        "Vaultwarden 對錯碼回 errorModel 而非 OAuth 錯誤"
    );
    assert!(err.message.contains("Invalid TOTP code"));
    assert!(parse_two_factor_challenge(&err, login()).is_none());
}

#[test]
fn bad_master_password_is_not_a_challenge() {
    let body = fixture("error_400_bad_master_password_vw.json");
    let err = ApiError::parse(400, &body);
    assert!(parse_two_factor_challenge(&err, login()).is_none());
    assert!(err.message.contains("incorrect"));
}

// —— /sync ——

#[test]
fn sync_from_vaultwarden_replays_with_raw_mirror_intact() {
    let raw = fixture_json("sync_with_attachment_vw_1.37.2.json");
    let sync = SyncResponse::parse(&raw);
    assert_eq!(sync.object.as_deref(), Some("sync"));
    assert!(!sync.ciphers.is_empty());
    assert!(sync.profile.is_some());
    // raw mirror：解析不能動到原始位元組
    assert_eq!(
        serde_json::to_string(&sync.raw).unwrap(),
        serde_json::to_string(&raw).unwrap()
    );
    // 未建模欄位必須活著：organizationUseTotp / viewPassword 我們不碰
    let with_attachment = sync
        .ciphers
        .iter()
        .find(|c| c.get("attachments").is_some_and(|a| !a.is_null()))
        .expect("fixture 裡有一筆帶附件的 cipher");
    assert!(with_attachment.get("organizationUseTotp").is_some());
    let atts = with_attachment["attachments"]
        .as_array()
        .expect("VW 1.37.2 回 array");
    assert_eq!(atts.len(), 1);
    // 附件 id 不是 UUID（bw_proto::AttachmentId 目前是 Uuid，鏡像層得靠 raw 兜底）
    assert!(
        atts.iter()
            .all(|a| uuid::Uuid::parse_str(a["id"].as_str().unwrap()).is_err())
    );
    assert!(
        sync.key_fingerprint().is_some(),
        "金鑰指紋要能算出來（§2.2 漂移偵測）"
    );
    let mut probe = bw_server::profile::ServerProbe::default();
    probe.observe_sync(&raw);
    assert!(probe.has("ciphers.attachments-as-array"));
    assert!(probe.has("ciphers.attachments.id-not-uuid"));
    assert!(
        probe.has("sync.userDecryption"),
        "VW 把解密選項放在顶层 userDecryption，不是 profile.userDecryptionOptions"
    );
    assert!(!probe.has_quirk(Quirk::MissingUserDecryptionOptions));
}

/// 官方雲的 `/sync`（依 frankhommers 產生器的 `SyncResponseModel` 欄位組出的派發樣本，
/// 見 fixtures/README.md）：比 VW 多出的 `policiesNew`/`organizationsNew`/`data` 等欄位
/// 不能讓解析炸掉，且 `attachments` 是 **map**（VW 是 array）——兩種都要吃得下。
#[test]
fn sync_from_bitwarden_cloud_fields_parses_too() {
    let raw = fixture_json("sync_bitwarden_cloud_fields.json");
    let sync = SyncResponse::parse(&raw);
    assert_eq!(sync.object.as_deref(), Some("sync"));
    assert_eq!(sync.ciphers.len(), 1);
    let cipher = &sync.ciphers[0];
    let atts = cipher["attachments"]
        .as_object()
        .expect("upstream 形態是 map");
    assert!(atts.contains_key("b1a2c3d4-0000-4000-8000-000000000001"));
    // 未建模欄位原樣留在 raw（不變量 8）
    assert!(cipher.get("data").is_some());
    assert!(raw["profile"].get("organizationsNew").is_some());
    let mut probe = bw_server::profile::ServerProbe::default();
    probe.observe_sync(&raw);
    assert!(probe.has("ciphers.attachments-as-map"));
    assert!(!probe.has("ciphers.attachments-as-array"));
    assert!(probe.has("sync.policies"));
    assert!(probe.has("sync.userDecryption"));
    assert!(!probe.has_quirk(Quirk::MissingUserDecryptionOptions));
}

#[test]
fn sync_missing_sections_parse_as_empty() {
    let raw = json!({"object": "sync", "profile": {"id": "x"}});
    let sync = SyncResponse::parse(&raw);
    assert!(sync.ciphers.is_empty() && sync.folders.is_empty() && sync.collections.is_empty());
    assert!(sync.organizations.is_empty() && sync.policies.is_empty() && sync.sends.is_empty());
    assert!(sync.key_fingerprint().is_none());
}

#[test]
fn sync_with_null_arrays_parses_as_empty() {
    let sync = SyncResponse::parse(&json!({"ciphers": null, "folders": null}));
    assert!(sync.ciphers.is_empty());
}

// —— ServerProfile ——

#[test]
fn server_profile_identifies_vaultwarden_1_37_2() {
    let probe = assemble(&ProbeInputs {
        base_url: "http://127.0.0.1:18080".to_owned(),
        config: Some(fixture_json("config_vw_1.37.2.json")),
        config_at_api: true,
        product_version: Some("1.37.2".to_owned()),
        discovery: None,
    });
    assert_eq!(probe.kind(), ServerKind::Vaultwarden);
    assert_eq!(
        probe.profile.version.as_deref(),
        Some("1.37.2"),
        "產品版本優先於協定版本"
    );
    assert_eq!(probe.protocol_version.as_deref(), Some("2026.6.0"));
    assert!(probe.has("notifications.websocket"));
    assert!(!probe.has("openid-configuration"));
    assert!(probe.has_quirk(Quirk::NoOpenIdDiscovery));
    assert!(probe.has_quirk(Quirk::RestoreUsesPutVerb));
    assert!(probe.has_quirk(Quirk::SoftDeleteUsesPutVerb));
    assert!(probe.has_quirk(Quirk::AttachmentUploadRequiresMultipart));
    assert!(probe.has_quirk(Quirk::NoDeletedCiphersListing));
    // VW 自報 http://localhost/api（容器內看 Host header）；origin 與 base 不同但路徑是標準
    // 佈局 → 視為別名，沿用 base 的 origin。反代掛非標準路徑時才會照抄發現值。
    assert_eq!(
        probe.urls.api.as_deref(),
        Some("http://127.0.0.1:18080/api")
    );
    assert_eq!(
        probe.urls.identity.as_deref(),
        Some("http://127.0.0.1:18080/identity")
    );
    // VW 的 /config 沒有 notificationsUrl 之外的 push relay；VAPID 未啟用時不該有旗標
    assert!(!probe.has("push.vapid"));
}

#[test]
fn server_profile_identifies_bitwarden_cloud() {
    let probe = assemble(&ProbeInputs {
        base_url: "https://vault.bitwarden.com".to_owned(),
        config: Some(fixture_json("config_bitwarden_cloud.json")),
        config_at_api: true,
        product_version: None,
        discovery: Some(fixture_json("discovery_bitwarden_cloud.json")),
    });
    assert_eq!(probe.kind(), ServerKind::BitwardenCloud);
    assert!(
        probe
            .profile
            .version
            .as_deref()
            .unwrap()
            .starts_with("2026.")
    );
    assert!(probe.has("openid-configuration"));
    assert!(probe.has("notifications.websocket"));
    assert_eq!(
        probe.urls.notifications.as_deref(),
        Some("https://notifications.bitwarden.com")
    );
    assert!(!probe.has_quirk(Quirk::RestoreUsesPutVerb));
    // 官方雲的 featureStates 是一大票 PM-* 旗標，原樣保留但不進 features 清單以外判斷
    assert!(
        probe
            .feature_states
            .as_ref()
            .is_some_and(|v| !v.as_object().unwrap().is_empty())
    );
}

#[test]
fn unknown_server_stays_unknown_instead_of_guessing_cloud() {
    let cfg = json!({"version": "1.0", "server": {"name": "butewarden"}});
    assert_eq!(
        classify(Some(&cfg), "https://bw.example.org"),
        ServerKind::Unknown
    );
    let probe = assemble(&ProbeInputs {
        base_url: "https://bw.example.org".to_owned(),
        config: Some(cfg),
        config_at_api: false,
        product_version: None,
        discovery: None,
    });
    assert_eq!(probe.kind(), ServerKind::Unknown);
    assert!(probe.has_quirk(Quirk::NoOpenIdDiscovery));
}

#[test]
fn urls_absent_from_config_fall_back_to_base_paths() {
    let urls = extract_urls(Some(&json!({"version": "x"})), "https://h/");
    assert_eq!(urls.api, None);
    let probe = assemble(&ProbeInputs {
        base_url: "https://h".to_owned(),
        config: Some(json!({"version": "x", "server": null})),
        config_at_api: false,
        product_version: None,
        discovery: None,
    });
    assert_eq!(probe.urls.base, "https://h");
    assert!(!probe.has("notifications.websocket"));
}

// —— 錯誤體 ——

#[test]
fn rocket_html_error_pages_parse_without_panicking() {
    let body = fixture("error_401_no_token_vw.html");
    let err = ApiError::parse(401, &body);
    assert!(err.non_json);
    assert!(!err.message.is_empty());
    assert!(err.message.len() <= 300, "HTML 要被壓成短摘要");
}

#[test]
fn route_missing_is_distinguishable_from_data_missing() {
    let missing = ApiError::parse(404, &fixture("ciphers_deleted_listing_404_vw.json"));
    assert!(missing.is_route_missing());
    let not_found = ApiError::parse(400, &fixture("error_400_cipher_not_found_vw.json"));
    assert!(!not_found.is_route_missing());
    assert_eq!(not_found.message, "Cipher doesn't exist");
}

#[test]
fn bulk_delete_field_name_drift_is_visible_in_the_error() {
    // upstream 用 cipherIds，Vaultwarden 用 ids：422 的 HTML 頁要能被認成「欄位不對」
    let err = ApiError::parse(422, &fixture("ciphers_bulk_delete_cipherIds_400_vw.json"));
    assert_eq!(err.status, 422);
    assert!(err.non_json);
    // 成功時是 200 + 空回應體；解析成 Value::Null，不能被當成錯誤
    assert!(
        fixture("ciphers_bulk_delete_vw_1.37.2.json")
            .trim()
            .is_empty()
    );
}

#[test]
fn validation_errors_are_collected() {
    let err = ApiError::parse(400, &fixture("error_400_bad_master_password_vw.json"));
    assert_eq!(err.status, 400);
    assert!(!err.validation_errors.is_empty());
    assert!(err.message.contains("Username or password is incorrect"));
}

// —— notifications ——

#[test]
fn vaultwarden_msgpack_frame_decodes_to_cipher_event() {
    let bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("notifications_vw_msgpack_frame.bin"),
    )
    .unwrap();
    let ev = decode_binary_record(&bytes).expect("錄下來的 frame 必須解得出事件");
    assert_eq!(ev.update, UpdateType::SyncCipherCreate);
    assert_eq!(ev.target.as_deref(), Some("ReceiveMessage"));
    assert_eq!(ev.context_id.as_deref(), Some("u4-probe-device"));
    let id = ev
        .cipher_id()
        .expect("cipher 事件要帶得出 id（targeted pull 的依據）");
    assert_eq!(id.to_string(), "66b31944-ec07-485e-9716-2b0632299dd7");
    assert_eq!(
        ev.revision_date().unwrap().chars().nth(4),
        Some('-'),
        "RFC3339 日期"
    );
}

#[test]
fn signalr_json_invocation_frame_decodes() {
    // 官方雲的 json hub protocol：arguments 裡再包一層 JSON 字串
    let frame = json!({
        "type": 1,
        "target": "ReceiveMessage",
        "arguments": ["{\"NotificationType\":0,\"Payload\":{\"Id\":\"66b31944-ec07-485e-9716-2b0632299dd7\",\"UserId\":\"8c7bdf04-f1e7-4b92-873c-ec77cc7c7db9\",\"OrganizationId\":null,\"RevisionDate\":\"2026-10-28T18:15:44.9261315Z\"}}"],
    });
    let ev = interpret(&frame).expect("invocation 要能還原成事件");
    assert_eq!(ev.update, UpdateType::SyncCipherUpdate);
    assert!(ev.cipher_id().is_some());
    assert_eq!(ev.revision_date().unwrap(), "2026-10-28T18:15:44.9261315Z");
}

#[test]
fn signalr_keepalive_and_handshake_frames_are_not_events() {
    assert!(interpret(&json!({"type": 6})).is_none());
    assert!(interpret(&json!({})).is_none());
    assert!(interpret(&json!([6])).is_none());
    assert!(
        decode_binary_record(&[0x7b, 0x7d, 0x1e]).is_none(),
        "握手回應 {{}}\\u001e 不是事件"
    );
}

#[test]
fn notification_without_cipher_id_is_still_delivered() {
    let frame = json!({"type": 1, "target": "ReceiveMessage", "arguments": [{"NotificationType": 4, "Payload": {"UserId": "u", "Date": "2026-10-28T18:15:44Z"}}]});
    let ev = interpret(&frame).unwrap();
    assert_eq!(ev.update, UpdateType::SyncCiphers);
    assert!(ev.cipher_id().is_none(), "SyncCiphers 只能降回全量 sync");
    assert_eq!(ev.revision_date().unwrap(), "2026-10-28T18:15:44Z");
}

#[test]
fn logout_event_is_recognised() {
    let frame = json!({"Type": 11, "Payload": {"UserId": "u", "Date": "2026-10-28T18:15:44Z"}});
    let ev = interpret(&frame).unwrap();
    assert_eq!(ev.update, UpdateType::LogOut);
}

#[test]
fn mode_selection_follows_server_kind() {
    // 探測結果決定握手協議：VW 用 messagepack，其他用 json
    let vw = assemble(&ProbeInputs {
        base_url: "http://h".to_owned(),
        config: Some(fixture_json("config_vw_1.37.2.json")),
        config_at_api: true,
        product_version: Some("1.37.2".to_owned()),
        discovery: None,
    });
    let cloud = assemble(&ProbeInputs {
        base_url: "https://vault.bitwarden.com".to_owned(),
        config: Some(fixture_json("config_bitwarden_cloud.json")),
        config_at_api: true,
        product_version: None,
        discovery: Some(fixture_json("discovery_bitwarden_cloud.json")),
    });
    assert_eq!(
        bw_server::notify::mode_for(&vw),
        NotificationMode::VaultwardenWs
    );
    assert_eq!(
        bw_server::notify::mode_for(&cloud),
        NotificationMode::SignalRJson
    );
}

// —— 請求形態 ——

#[test]
fn password_grant_form_matches_recorded_request() {
    let recorded = parse_form(&fixture("token_password_request_vw.txt"));
    let get = |k: &str| {
        recorded
            .iter()
            .find(|(rk, _)| rk == k)
            .map(|(_, v)| v.trim_end_matches('\n').to_owned())
            .unwrap()
    };
    let options = bw_server::ClientOptions {
        device_name: get("deviceName"),
        device_type: get("deviceType").parse().unwrap(),
        ..Default::default()
    };
    let sent = bw_server::auth::build_form(
        &PasswordLogin::new(get("username"), get("password"), get("deviceIdentifier")),
        &options,
    );
    for (k, v) in &sent {
        let want = recorded
            .iter()
            .find(|(rk, _)| rk == k)
            .unwrap_or_else(|| panic!("recorded request has no {k}"));
        assert_eq!(&want.1, v, "欄位 {k} 的形態與錄製時不一致");
    }
    for (k, _) in &recorded {
        assert!(sent.iter().any(|(sk, _)| sk == k), "送出的表單少了 {k}");
    }
}

#[test]
fn grant_enum_stays_the_frozen_surface() {
    let g = TokenGrant::Password {
        email: "a@b.c".into(),
        master_password_hash: "hash".into(),
        device_identifier: "dev".into(),
    };
    matches!(g, TokenGrant::ClientCredentials { .. });
    assert!(matches!(g, TokenGrant::Password { .. }));
}
