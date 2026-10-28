//! 資料載入：fixtures/items.json → `Vec<bw_proto::ItemMeta>`，與 provider
//! 設定的存檔。純 IO，無 UI。

use std::{
    fs,
    path::{Path, PathBuf},
};

use bw_proto::ItemMeta;
use serde::{Deserialize, Serialize};

/// 打包前 dev 階段的設定檔位置：與 fixture 同目錄（見 FINDINGS 的打包限制）。
const FIXTURE_REL: &str = "fixtures/items.json";

pub struct VaultData {
    pub items: Vec<ItemMeta>,
    /// 設定檔與 fixture 所在目錄（spike：存檔寫回這裡）。
    pub dir: PathBuf,
    /// 實際載入來源，給 UI 顯示與除錯。
    pub source: String,
}

/// 依序試 dev 執行時的 cwd 候選，最後退回編譯期 bake 的 manifest 目錄；
/// 全部失敗才用內嵌副本（保證打包後仍有畫面可截）。
fn fixture_candidates() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from(FIXTURE_REL),
        PathBuf::from("spike/nsh-spike").join(FIXTURE_REL),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL),
    ];
    if let Ok(exe) = std::env::current_exe() {
        // cargo run 的 bin 在 <target>/debug，往上是 workspace 根。
        if let Some(dir) = exe.ancestors().nth(3) {
            v.push(dir.join("spike/nsh-spike").join(FIXTURE_REL));
        }
    }
    v
}

/// `nsh test`/headless 之外，載入失敗不 panic：回空清單並記 source。
pub fn load_vault() -> VaultData {
    for path in fixture_candidates() {
        match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Vec<ItemMeta>>(&text) {
                Ok(items) => {
                    let dir = path.parent().unwrap_or(&path).to_path_buf();
                    return VaultData {
                        items,
                        dir,
                        source: path.display().to_string(),
                    };
                }
                Err(e) => {
                    eprintln!(
                        "nsh-spike: {} is not a valid ItemMeta list: {e}",
                        path.display()
                    );
                    return VaultData {
                        items: Vec::new(),
                        dir: PathBuf::from("."),
                        source: format!("{} (parse error)", path.display()),
                    };
                }
            },
            Err(_) => continue,
        }
    }
    // 內嵌副本：來源標記為 embedded（spike 不硬塞 asset 管線）。
    let embedded: Vec<ItemMeta> = serde_json::from_str(include_str!("../fixtures/items.json"))
        .expect("embedded fixture parses");
    let dir = std::env::temp_dir();
    VaultData {
        items: embedded,
        dir,
        source: "<embedded>".to_owned(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ProviderSettings {
    pub server_url: String,
    pub email: String,
    pub launch_at_login: bool,
    pub auto_lock: bool,
    pub use_system_keychain: bool,
}

impl ProviderSettings {
    pub fn load(dir: &Path) -> Self {
        fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<PathBuf, String> {
        let path = dir.join("settings.json");
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_proto::ItemKind;

    #[test]
    fn fixture_parses_as_item_meta_vec() {
        let text = include_str!("../fixtures/items.json");
        let items: Vec<ItemMeta> = serde_json::from_str(text).expect("fixture 可解析");
        assert_eq!(items.len(), 20);
        assert!(items.iter().any(|i| i.kind == ItemKind::Card));
        assert!(items.iter().any(|i| i.kind == ItemKind::SecureNote));
        assert!(items.iter().any(|i| i.kind == ItemKind::Identity));
        assert!(items.iter().any(|i| i.favorite));
        assert!(items.iter().any(|i| i.pending));
        assert!(items.iter().any(|i| i.updated_at.is_none()));
        assert_eq!(
            items
                .iter()
                .map(|i| i.id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            20,
            "ids must be unique"
        );
    }

    #[test]
    fn settings_roundtrip() {
        let dir = std::env::temp_dir().join("nsh-spike-settings-test");
        fs::create_dir_all(&dir).unwrap();
        let s = ProviderSettings {
            server_url: "https://vault.example".into(),
            email: "me@example".into(),
            launch_at_login: true,
            auto_lock: false,
            use_system_keychain: true,
        };
        s.save(&dir).unwrap();
        assert_eq!(ProviderSettings::load(&dir), s);
        fs::remove_dir_all(&dir).ok();
    }
}
