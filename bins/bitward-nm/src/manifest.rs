//! `install-manifest` 子命令：寫 native messaging manifest 並印安裝路徑。
//! path = 當前執行檔（`std::env::current_exe`）；name 固定 `com.bitward.client`。
//!
//! macOS 目錄（見 FINDINGS）：
//! - Chrome:  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
//! - Firefox: `~/Library/Application Support/Firefox/Profiles/<profile>/native-messaging-hosts/`
//!   （profile 由 `<AppSupport>/Firefox/profiles.ini` 的 Install.Default 解析；
//!   解析不了就要 `--dest`）
//!
//! Linux 對應 `~/.config/google-chrome/NativeMessagingHosts/` 與
//! `~/.mozilla/firefox/<profile>/native-messaging-hosts/`。

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

pub const HOST_NAME: &str = "com.bitward.client";
pub const DESCRIPTION: &str = "bitward bridge";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Browser {
    Chrome,
    Firefox,
}

/// manifest 內容（凍結形態）。Firefox 變體用 `allowed_extensions`。
pub fn manifest_value(browser: Browser, exe: &Path, extension_id: &str) -> Value {
    let mut m = json!({
        "name": HOST_NAME,
        "description": DESCRIPTION,
        "path": exe.display().to_string(),
        "type": "stdio",
    });
    match browser {
        Browser::Chrome => m["allowed_origins"] = json!([chrome_origin(extension_id)]),
        Browser::Firefox => m["allowed_extensions"] = json!([extension_id.trim()]),
    }
    m
}

/// `abcdef...` → `chrome-extension://abcdef.../`（已帶前綴/尾斜線也正規化）。
pub fn chrome_origin(id: &str) -> String {
    let id = id.trim();
    let bare = id
        .strip_prefix("chrome-extension://")
        .unwrap_or(id)
        .trim_end_matches('/');
    format!("chrome-extension://{bare}/")
}

/// 寫 manifest，回完整檔案路徑。
pub fn install(
    browser: Browser,
    extension_id: &str,
    dest: Option<&Path>,
    exe: &Path,
) -> Result<PathBuf, String> {
    if extension_id.trim().is_empty() {
        return Err("extension id required".into());
    }
    let dir = match dest {
        Some(d) => d.to_path_buf(),
        None => default_dest(browser)?,
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = dir.join(format!("{HOST_NAME}.json"));
    let body = serde_json::to_string_pretty(&manifest_value(browser, exe, extension_id))
        .map_err(|e| e.to_string())?;
    std::fs::write(&path, body + "\n").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn default_dest(browser: Browser) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("home dir unavailable; pass --dest")?;
    match browser {
        Browser::Chrome => {
            if cfg!(target_os = "macos") {
                Ok(home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"))
            } else if cfg!(target_os = "linux") {
                Ok(home.join(".config/google-chrome/NativeMessagingHosts"))
            } else {
                Err("unsupported platform; pass --dest".into())
            }
        }
        Browser::Firefox => firefox_dest(&home),
    }
}

fn firefox_dest(home: &Path) -> Result<PathBuf, String> {
    let ini = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Firefox/profiles.ini")
    } else if cfg!(target_os = "linux") {
        home.join(".mozilla/firefox/profiles.ini")
    } else {
        return Err("unsupported platform; pass --dest".into());
    };
    let hint = "cannot resolve Firefox profile; pass --dest <profile dir>";
    let profiles = parse_profiles_ini(&ini).ok_or(hint)?;
    let pick = match profiles.len() {
        0 => return Err(hint.into()),
        1 => &profiles[0],
        _ => {
            let default = parse_ini_default(&ini);
            profiles
                .iter()
                .find(|(name, _)| Some(name.as_str()) == default.as_deref())
                .ok_or(hint)?
        }
    };
    // pick.1 已由 parse_profiles_ini 對 profiles.ini 所在目錄解析（相對/絕對皆可）
    Ok(pick.1.join("native-messaging-hosts"))
}

/// `Default=`（[Install *] 或 [General]）→ profile 名。
fn parse_ini_default(ini: &Path) -> Option<String> {
    let text = std::fs::read_to_string(ini).ok()?;
    for line in text.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("Default=") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

/// [Profile <name>] 區塊 → [(name, path)]；IsRelative=1 時 path 相對於 ini 所在目錄
/// （join 語意：絕對 path 直接採用）。
fn parse_profiles_ini(ini: &Path) -> Option<Vec<(String, PathBuf)>> {
    let text = std::fs::read_to_string(ini).ok()?;
    let base = ini.parent()?.to_path_buf();
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut path: Option<String> = None;
    let mut relative = true;
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix('[') {
            if let (Some(name), Some(p)) = (cur.take(), path.take()) {
                let joined = if relative {
                    base.join(p)
                } else {
                    PathBuf::from(p)
                };
                out.push((name, joined));
            }
            path = None;
            relative = true;
            let sec = rest.trim_end_matches(']');
            cur = sec.strip_prefix("Profile ").map(|n| n.trim().to_owned());
        } else if l == "IsRelative=0" {
            relative = false;
        } else if let Some(v) = l.strip_prefix("Path=") {
            path = Some(v.trim().to_owned());
        }
    }
    if let (Some(name), Some(p)) = (cur, path) {
        let joined = if relative {
            base.join(p)
        } else {
            PathBuf::from(p)
        };
        out.push((name, joined));
    }
    Some(out)
}
