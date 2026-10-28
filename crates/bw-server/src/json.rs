//! 欄位寬容讀取。Bitwarden 的 wire 欄位大小寫不一致（identity 用 PascalCase、
//! API 用 camelCase，Vaultwarden 兩邊都混），且同一欄位在不同版本換名字。
//! 所有跨 server 的讀取都走這裡，避免各模組各發明的查表慣例。

use serde_json::Value;

/// 依序嘗試多個候選名稱；先完全比對，再大小寫不敏感比對。
pub fn get<'a>(v: &'a Value, names: &[&str]) -> Option<&'a Value> {
    let obj = v.as_object()?;
    for name in names {
        if let Some(found) = obj.get(*name) {
            return Some(found);
        }
    }
    for name in names {
        for (k, val) in obj {
            if k.eq_ignore_ascii_case(name) {
                return Some(val);
            }
        }
    }
    None
}

/// 逐層深入；任何一層缺欄位就回 None（不炸）。
pub fn get_path<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for name in path {
        cur = get(cur, std::slice::from_ref(name))?;
    }
    Some(cur)
}

pub fn get_str<'a>(v: &'a Value, names: &[&str]) -> Option<&'a str> {
    match get(v, names) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
        // 少數 server 把單一欄位包成 {"$":"value"}（.NET 舊式 XML 轉 JSON 殘留）
        Some(Value::Object(obj)) => match obj.get("$").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => Some(s),
            _ => None,
        },
        _ => None,
    }
}

/// 存在但為 null 也要能區分「缺欄位」與「明確為空」，ServerProfile 的欄位存在性探測要用。
pub fn has_field(v: &Value, names: &[&str]) -> bool {
    v.as_object().is_some_and(|o| {
        names
            .iter()
            .any(|n| o.keys().any(|k| k == n || k.eq_ignore_ascii_case(n)))
    })
}

pub fn get_i64(v: &Value, names: &[&str]) -> Option<i64> {
    match get(v, names) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

pub fn get_bool(v: &Value, names: &[&str]) -> Option<bool> {
    get(v, names).and_then(Value::as_bool)
}

/// 陣列欄位缺失或形態不對時回空陣列；鏡像層只吃 `Vec<Value>`，不在此處丟資訊。
pub fn get_array<'a>(v: &'a Value, names: &[&str]) -> Vec<&'a Value> {
    match get(v, names) {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_pascal_and_camel_case() {
        let pascal = json!({ "UserDecryptionOptions": { "HasMasterPassword": true } });
        let camel = json!({ "userDecryptionOptions": { "hasMasterPassword": true } });
        for v in [&pascal, &camel] {
            assert!(
                get_path(v, &["UserDecryptionOptions", "HasMasterPassword"])
                    .unwrap()
                    .as_bool()
                    .unwrap()
            );
        }
        assert!(get_path(&pascal, &["UserDecryptionOptions", "Missing"]).is_none());
    }

    #[test]
    fn distinguishes_absent_from_null() {
        let v = json!({ "a": null, "Key": "2.x|y|z" });
        assert!(has_field(&v, &["a"]));
        assert!(!has_field(&v, &["b"]));
        assert_eq!(get_str(&v, &["key"]), Some("2.x|y|z"));
        assert_eq!(get_i64(&json!({"n": "12"}), &["n"]), Some(12));
        assert_eq!(get_array(&v, &["ciphers"]).len(), 0);
    }
}
