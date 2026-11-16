//! BTP 幀 conformance vectors：`docs/research/btp-frames.md` 的釘選樣本。
//!
//! 文檔是真相源、本測是執行器：逐條把 `frame`（hex，含 4 bytes LE 長度前綴）
//! 與 `msg` 對照，兩種編碼格式都走 `bw_proto::wire` 的編解碼。
//! 任何一侧改動協定型別而沒同步重算向量，這裡先紅。
//!
//! 重生成：`BTP_VECTORS_WRITE=1 cargo test -p bw-btp --test vectors -- --nocapture`

use bw_proto::wire::{self, WireFormat};
use bw_proto::{ClientMsg, ServerMsg};
use serde::Deserialize;
use serde_json::Value;

const DOC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/research/btp-frames.md"
);

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    /// `client`＝`ClientMsg`、`server`＝`ServerMsg`。
    dir: String,
    /// `json` | `postcard`。
    format: String,
    msg: Value,
    /// 完整上線位元組（含長度前綴）的小寫 hex。
    frame: String,
    /// 舊端樣本（缺协商欄）：只驗解碼寬容，不要求重編等於原位元組。
    #[serde(default)]
    decode_only: bool,
}

fn parse_format(s: &str) -> WireFormat {
    match s {
        "json" => WireFormat::Json,
        "postcard" => WireFormat::Postcard,
        other => panic!("unknown format {other:?} in vectors"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// 取文檔裡唯一的 ```btp-vectors 區塊。
fn vectors_from_doc() -> Vec<Vector> {
    let text = std::fs::read_to_string(DOC).expect("docs/research/btp-frames.md 必須存在");
    let mut lines = text.lines();
    for l in lines.by_ref() {
        if l.trim_start().starts_with("```btp-vectors") {
            break;
        }
    }
    let mut buf = String::new();
    for l in lines.by_ref() {
        if l.trim_start().starts_with("```") {
            break;
        }
        buf.push_str(l);
        buf.push('\n');
    }
    serde_json::from_str::<Vec<Vector>>(&buf).expect("btp-vectors 區塊必須是合法 JSON 陣列")
}

fn check(v: &Vector) {
    let fmt = parse_format(&v.format);
    let raw = unhex(&v.frame);
    let (prefix, body) = raw.split_at(4);
    assert_eq!(
        u32::from_le_bytes(prefix.try_into().unwrap()) as usize,
        body.len(),
        "{}: 長度前綴與體不符",
        v.name
    );
    let frame_hex = |body: &[u8]| -> String {
        let n = u32::try_from(body.len()).expect("向量不得超過幀上限");
        format!("{}{}", hex(&n.to_le_bytes()), hex(body))
    };
    match v.dir.as_str() {
        "client" => {
            let msg: ClientMsg = serde_json::from_value(v.msg.clone()).unwrap();
            if !v.decode_only {
                assert_eq!(
                    frame_hex(&wire::encode(fmt, &msg).unwrap()),
                    v.frame,
                    "{}: 重編位元組與向量不符",
                    v.name
                );
            }
            let back: ClientMsg = wire::decode(fmt, body).unwrap();
            assert_eq!(
                serde_json::to_value(&back).unwrap(),
                normalize(&v.msg),
                "{}: 解碼結果與向量不符",
                v.name
            );
        }
        "server" => {
            let msg: ServerMsg = serde_json::from_value(v.msg.clone()).unwrap();
            if !v.decode_only {
                assert_eq!(
                    frame_hex(&wire::encode(fmt, &msg).unwrap()),
                    v.frame,
                    "{}: 重編位元組與向量不符",
                    v.name
                );
            }
            let back: ServerMsg = wire::decode(fmt, body).unwrap();
            assert_eq!(
                serde_json::to_value(&back).unwrap(),
                normalize(&v.msg),
                "{}: 解碼結果與向量不符",
                v.name
            );
        }
        other => panic!("unknown dir {other:?} in vectors"),
    }
}

/// 舊端樣本缺协商欄：解碼補成預設值（JSON／Json）後再比對。
fn normalize(msg: &Value) -> Value {
    let mut out = msg.clone();
    if let Some(hello) = out.get_mut("Hello").and_then(|h| h.as_object_mut()) {
        hello
            .entry("formats")
            .or_insert_with(|| Value::Array(Vec::new()));
    }
    if let Some(w) = out.get_mut("Welcome").and_then(|h| h.as_object_mut()) {
        w.entry("format")
            .or_insert_with(|| Value::String("Json".into()));
    }
    out
}

#[test]
fn frames_match_specification_vectors() {
    let vs = vectors_from_doc();
    assert!(!vs.is_empty(), "文檔必須帶至少一條向量");
    for v in &vs {
        check(v);
    }
}

/// 重生成器：把當前協定型別的實際編碼寫回 hex（人工核對後貼進文檔）。
#[test]
#[ignore = "只在刻意更新向量時跑"]
fn print_vectors_for_doc() {
    if std::env::var("BTP_VECTORS_WRITE").is_err() {
        return;
    }
    for v in vectors_from_doc() {
        let fmt = parse_format(&v.format);
        // 舊端樣本（decode_only）的體＝原位元組：不得補上新欄位，
        // 否則測的就不是「舊幀能不能讀」這件事。
        if v.decode_only {
            let body = serde_json::to_vec(&v.msg).unwrap();
            println!(
                "{}\t{}\t{}{}",
                v.name,
                serde_json::to_string(&v.msg).unwrap(),
                hex(&(body.len() as u32).to_le_bytes()),
                hex(&body)
            );
            continue;
        }
        let body = match v.dir.as_str() {
            "client" => {
                let msg: ClientMsg = serde_json::from_value(v.msg.clone()).unwrap();
                wire::encode(fmt, &msg).unwrap()
            }
            _ => {
                let msg: ServerMsg = serde_json::from_value(v.msg.clone()).unwrap();
                wire::encode(fmt, &msg).unwrap()
            }
        };
        let frame = format!("{}{}", hex(&(body.len() as u32).to_le_bytes()), hex(&body));
        println!(
            "{}\t{}\t{frame}",
            v.name,
            serde_json::to_string(&v.msg).unwrap()
        );
    }
}
