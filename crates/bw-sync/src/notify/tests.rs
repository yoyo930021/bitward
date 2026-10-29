use super::*;
use serde_json::json;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

/// Recorded Vaultwarden 1.37.2 frame (see fixtures/README.md): msgpack
/// invocation carrying a SyncCipherCreate (Type 1) notification.
const VW_MSGPACK_FRAME: &str = "notify_vw_msgpack_cipher_create.bin";
/// Documented-shape official-cloud json hub frame with the double-wrapped
/// JSON-string argument (NotificationType 0 = SyncCipherUpdate).
const CLOUD_JSON_FRAME: &str = "notify_cloud_signalr_cipher_update.json";
/// Three `\u001e`-separated records: handshake, keepalive, SyncVault event.
const CLOUD_MULTI_FRAME: &str = "notify_cloud_signalr_multi.txt";

const CIPHER_ID: &str = "66b31944-ec07-485e-9716-2b0632299dd7";

#[test]
fn vaultwarden_msgpack_frame_yields_cipher_changed() {
    let events = NotifyParser::new().feed(&fixture(VW_MSGPACK_FRAME));
    let id: ItemId = CIPHER_ID.parse().unwrap();
    assert_eq!(events, vec![NotifyEvent::CipherChanged(id)]);
}

#[test]
fn vaultwarden_frame_parses_without_length_prefix_too() {
    let raw = fixture(VW_MSGPACK_FRAME);
    let stripped = strip_length_prefix(&raw).to_vec();
    let events = NotifyParser::new().feed(&stripped);
    assert_eq!(events.len(), 1, "bare msgpack body must also decode");
}

#[test]
fn cloud_signalr_json_frame_yields_cipher_changed() {
    let raw = fixture(CLOUD_JSON_FRAME);
    let events = NotifyParser::new().feed(&raw);
    let id: ItemId = CIPHER_ID.parse().unwrap();
    assert_eq!(events, vec![NotifyEvent::CipherChanged(id)]);
}

#[test]
fn multi_record_text_frame_splits_on_record_separator() {
    let events = NotifyParser::new().feed(&fixture(CLOUD_MULTI_FRAME));
    assert_eq!(events.len(), 1, "handshake and keepalive are not events");
    let NotifyEvent::Other(value) = &events[0] else {
        panic!("SyncVault must be Other: {:?}", events[0]);
    };
    assert_eq!(value["NotificationType"], json!(5));
    assert_eq!(
        value["Payload"]["UserId"],
        json!("8c7bdf04-f1e7-4b92-873c-ec77cc7c7db9")
    );
}

#[test]
fn sync_ciphers_without_id_falls_back_to_other() {
    // SyncCiphers (4) carries no cipher id: the daemon must downgrade to a
    // full sync, and the parser must not invent an id.
    let frame = json!({"type": 1, "target": "ReceiveMessage", "arguments": [
        {"NotificationType": 4, "Payload": {"UserId": "u", "Date": "2026-10-28T18:15:44Z"}}
    ]});
    let events = NotifyParser::new().feed(frame.to_string().as_bytes());
    assert!(matches!(&events[..], [NotifyEvent::Other(_)]));
}

#[test]
fn cipher_update_with_unparsable_id_is_other_not_dropped() {
    let frame = json!({"NotificationType": 0, "Payload": {"Id": "not-a-uuid"}});
    let events = NotifyParser::new().feed(frame.to_string().as_bytes());
    assert!(matches!(&events[..], [NotifyEvent::Other(_)]));
}

#[test]
fn logout_event_is_recognised_as_other() {
    let frame = json!({"Type": 11, "Payload": {"UserId": "u", "Date": "2026-10-28T18:15:44Z"}});
    let events = NotifyParser::new().feed(frame.to_string().as_bytes());
    let NotifyEvent::Other(v) = &events[0] else {
        panic!("LogOut must surface as Other");
    };
    assert_eq!(v["Type"], json!(11));
}

#[test]
fn vaultwarden_context_id_and_lowercase_variants_survive() {
    // VW nests {ContextId,Type,Payload} inside arguments; lowercase-keyed
    // servers (unknown builds) must still decode.
    let vw = json!({"ContextId": "u4-dev", "Type": 0, "Payload": {"Id": CIPHER_ID}});
    let lower = json!({"contextId": "u4-dev", "notificationType": 1, "payload": {"id": CIPHER_ID}});
    for frame in [vw, lower] {
        let events = NotifyParser::new().feed(frame.to_string().as_bytes());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], NotifyEvent::CipherChanged(_)));
    }
}

#[test]
fn keepalive_and_handshake_frames_are_not_events() {
    let parser = NotifyParser::new();
    assert!(parser.feed(b"{}\x1e").is_empty(), "handshake response");
    assert!(parser.feed(br#"{"type":6}"#).is_empty(), "json keepalive");
    assert!(
        parser.feed(&[0x91, 0x06]).is_empty(),
        "msgpack [6] keepalive"
    );
    assert!(parser.feed(b"").is_empty(), "empty frame");
    assert!(
        parser.feed(&[0xca, 0x01, 0xff, 0xfe]).is_empty(),
        "garbage frame"
    );
}

#[test]
fn msgpack_timestamp_ext_becomes_rfc3339() {
    // ext -1, 8 bytes: (nanos << 34) | seconds. 2026-10-28T18:15:44Z
    // = 1793211344 epoch seconds.
    let seconds: u64 = 1_793_211_344;
    let nanos: u64 = 926_131_500;
    let packed = (nanos << 34) | seconds;
    let mut bytes = vec![0xd7, 0xff];
    bytes.extend_from_slice(&packed.to_be_bytes());
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(
        json_from_msgpack(value),
        json!("2026-10-28T18:15:44Z"),
        "second precision, matching the recorded VW conversion"
    );
}

#[test]
fn msgpack_binary_values_become_base64() {
    let mut bytes = vec![0xc4, 0x03, 0x01, 0x02, 0x03];
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&mut bytes)).unwrap();
    assert_eq!(json_from_msgpack(value), json!("AQID"));
}

#[test]
fn invocation_array_shape_decodes() {
    // msgpack hub invocation arriving as pre-converted JSON:
    // [1, headers, invocationId, target, arguments]
    let frame = json!([1, {}, null, "ReceiveMessage", [{"ContextId": "c", "Type": 2, "Payload": {"Id": CIPHER_ID}}]]);
    let events = NotifyParser::new().feed(frame.to_string().as_bytes());
    let id: ItemId = CIPHER_ID.parse().unwrap();
    assert_eq!(
        events,
        vec![NotifyEvent::CipherChanged(id)],
        "SyncLoginDelete is a cipher event"
    );
}
