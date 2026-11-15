//! LaunchAgent 自管（計畫 R2：thin autofill 依賴 daemon 存活）。
//! SMAppService.agent(plistName:) 對本機組建的 app 回 EPERM（MAS 分發形態限定），
//! 故由非沙盒的 daemon 自己寫 ~/Library/LaunchAgents + launchctl bootstrap。
//! launchd 的 socket 激活只認 Mach port，我們的 BTP 是 UDS——等效手段為
//! RunAtLoad + KeepAlive 進程級常駐。
//!
//! 批次 14.5：本模組的 `render_plist` 是**註冊真相源**。bundle 內
//! `Contents/Library/LaunchAgents/` 那份是 SMAppService 時代殭屍拷貝（pkg 每輪
//! staged 但無人讀）。`self_heal` 讓 daemon 每次啟動比對現存 plist 與模板，
//! 不同即覆寫並重載——根治「裝了新 binary、註冊態卻停在舊模板」。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Status,
}

// SMAppService 硬規定：agent Label 必須以 App bundle ID 開頭，否則 BTM
// 「failed to construct an identifier」（EINVAL/EPERM），register 必敗。
const LABEL: &str = "io.bitward.dev.daemon";
const LEGACY_LABEL: &str = "io.bitward.daemon";
/// 批次 14.5：註冊環境常數——Keychain 封存開關恆寫入（keychain.rs 對無生物
/// 硬體本有 fallback，不需啟動偵測）。
const KEYCHAIN_ENV: &str = "BW_KEYS_ENABLE_KEYCHAIN";

fn retire_legacy_plist() {
    let Some(home) = dirs::home_dir() else { return };
    let old = home.join("Library/LaunchAgents").join(format!("{LEGACY_LABEL}.plist"));
    let _ = launchctl(&["bootout", &bootstrap_target(), &old.display().to_string()]);
    let _ = std::fs::remove_file(&old);
}

fn plist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| {
        h.join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"))
    })
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

fn bootstrap_target() -> String {
    format!("gui/{}", uid())
}

/// 渲染 LaunchAgent plist（註冊真相源，純函數，單測點）。
/// `exe`＝daemon 執行檔絕對路徑、`group`＝push app-group、`log`＝日誌路徑；
/// `data_dir_env`＝安裝者 `BITWARD_DATA_DIR`（demo/開發 vault），None＝走預設。
/// EnvironmentVariables 恆含 `BW_KEYS_ENABLE_KEYCHAIN=1`，有 data_dir 時再加一筆。
pub fn render_plist(exe: &str, group: &str, log: &str, data_dir_env: Option<&str>) -> String {
    let mut env_inner = format!(
        "        <key>{KEYCHAIN_ENV}</key>\n        <string>1</string>\n"
    );
    if let Some(d) = data_dir_env {
        env_inner.push_str(&format!(
            "        <key>BITWARD_DATA_DIR</key>\n        <string>{d}</string>\n"
        ));
    }
    let env_block = format!("    <key>EnvironmentVariables</key>\n    <dict>\n{env_inner}    </dict>\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--sock</string>
        <string>/private/tmp/io.bitward.dev/daemon.sock</string>
        <string>--push-app-group</string>
        <string>{group}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>1</integer>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
{env_block}</dict>
</plist>
"#
    )
}

/// 啟動自癒合判定（純函數，單測點）：現存內容與渲染模板**字串等值**才跳過；
/// 未安裝（None）跳過（建立是 Install 的職責）；不同→觸發覆寫。不做 mtime。
pub fn heal_needed(existing: Option<&str>, rendered: &str) -> bool {
    existing.is_some_and(|e| e != rendered)
}

/// 組裝當前環境下應該存在的 plist 內容（啟動與 Install 共用，單一真相源）。
fn desired_plist(exe: &Path, group: &str) -> String {
    let log = crate::default_data_dir().join("daemon.log");
    render_plist(
        &exe.display().to_string(),
        group,
        &log.display().to_string(),
        std::env::var("BITWARD_DATA_DIR").ok().as_deref(),
    )
}

/// daemon 啟動自癒合（非 `service install` 路徑）：現存 plist 若與模板不符，
/// 覆寫並派生**脫離進程**重載（bootout 會殺掉自己，故交 detached 子進程做，
/// 父進程只負責寫檔＋派生＋記 log 後繼續開檔）。僅在現存 plist 已指向本執行檔
/// 時才自愈，避免開發 nohup 實例覆寫正式註冊。回傳 Some(訊息) 表觸發了自愈。
pub fn self_heal(group: Option<&str>) -> Option<String> {
    let plist = plist_path()?;
    let existing = std::fs::read_to_string(&plist).ok()?; // 未安裝 → 跳過
    let exe = std::env::current_exe().ok()?;
    // 防呆：只自愈「plist 指向的本檔」。開發中 nohup 的 target/debug 路徑與
    // 正式註冊（/Applications/…）不同 → 跳過，不越權覆寫。
    if !existing.contains(&exe.display().to_string()) {
        return None;
    }
    let rendered = desired_plist(&exe, group.unwrap_or("group.8V5224A99M.io.bitward.dev"));
    if !heal_needed(Some(&existing), &rendered) {
        return None;
    }
    std::fs::write(&plist, &rendered).ok()?;
    spawn_reload(&plist);
    Some(format!(
        "self-heal: {LABEL}.plist 與模板不符，已覆寫並排程重載（新 env 下次啟動生效）"
    ))
}

/// 派生脫離式子進程重載：睡 1 秒讓父進程完成啟動日誌，再 bootout（殺父）＋
/// bootstrap（launchd 依新 plist 拉起）。子進程非 launchd job， survives 父死。
fn spawn_reload(plist: &Path) {
    let target = bootstrap_target();
    let p = plist.display().to_string();
    let _ = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "sleep 1; /bin/launchctl bootout {target} '{p}' 2>/dev/null; \
             /bin/launchctl bootstrap {target} '{p}' 2>/dev/null"
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

pub fn run(action: ServiceAction, exe: PathBuf, group: Option<&str>) -> Result<String, String> {
    let plist = plist_path().ok_or("no home dir")?;
    match action {
        ServiceAction::Install => {
            let group = group.ok_or("install 需要 --push-app-group <id>")?;
            std::fs::create_dir_all(plist.parent().unwrap()).map_err(|e| e.to_string())?;
            let xml = desired_plist(&exe, group);
            std::fs::write(&plist, xml).map_err(|e| e.to_string())?;
            // e2e 出口：只验渲染/落檔，不碰 launchd 域（同 Label 已载会撞真注册）。
            if std::env::var("BW_SERVICE_NO_BOOTSTRAP").is_ok() {
                return Ok(format!("installed {LABEL} <- {} (no-bootstrap)", exe.display()));
            }
            // 重裝語意：先 bootout（容忍未載入）再 bootstrap。
            let _ = launchctl(&["bootout", &bootstrap_target(), &plist.display().to_string()]);
            retire_legacy_plist();
            launchctl(&[
                "bootstrap",
                &bootstrap_target(),
                &plist.display().to_string(),
            ])?;
            Ok(format!("installed {LABEL} <- {}", exe.display()))
        }
        ServiceAction::Uninstall => {
            let _ = launchctl(&["bootout", &bootstrap_target(), &plist.display().to_string()]);
            let _ = std::fs::remove_file(&plist);
            retire_legacy_plist();
            Ok(format!("uninstalled {LABEL}"))
        }
        ServiceAction::Status => {
            let target = format!("{}/{}", bootstrap_target(), LABEL);
            let out = Command::new("launchctl")
                .args(["print", &target])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(if out.status.success() {
                "enabled"
            } else {
                "not-registered"
            }
            .into())
        }
    }
}

fn launchctl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "/Applications/Bitward.app/Contents/Helpers/bitwarderd";
    const GROUP: &str = "group.8V5224A99M.io.bitward.dev";
    const LOG: &str = "/Users/x/Library/Application Support/bitward/daemon.log";

    #[test]
    fn render_always_includes_keychain() {
        // 有無 BITWARD_DATA_DIR 兩態，KEYCHAIN 開關恆在。
        let a = render_plist(EXE, GROUP, LOG, None);
        let b = render_plist(EXE, GROUP, LOG, Some("/tmp/vault"));
        for plist in [&a, &b] {
            assert!(
                plist.contains("<key>BW_KEYS_ENABLE_KEYCHAIN</key>\n        <string>1</string>"),
                "模板必須恆含 Keychain 開關：{plist}"
            );
        }
        assert!(!a.contains("BITWARD_DATA_DIR"), "無 data_dir 環境不應寫入該鍵");
        assert!(b.contains("<key>BITWARD_DATA_DIR</key>\n        <string>/tmp/vault</string>"));
        // 兩態都是合法可解析形態的骨架（含 Label/exe/group）。
        assert!(a.contains(EXE) && a.contains(GROUP) && a.contains(LABEL));
    }

    #[test]
    fn render_is_deterministic() {
        let a = render_plist(EXE, GROUP, LOG, None);
        let b = render_plist(EXE, GROUP, LOG, None);
        assert_eq!(a, b, "同輸入必字串等值（自癒合比較靠這）");
    }

    #[test]
    fn heal_needed_compares_exact_text() {
        let rendered = render_plist(EXE, GROUP, LOG, None);
        // 同文跳過（冪等）；異文觸發；未安裝跳過。
        assert!(!heal_needed(Some(&rendered), &rendered));
        let stale = rendered.replace("1</string>", "0</string>");
        assert!(heal_needed(Some(&stale), &rendered));
        // 未安裝（無現存檔）→ 不自癒（那是 Install 的職責）。
        assert!(!heal_needed(None, &rendered));
        // plutil 重排鍵序也算「不同」→ 覆寫回正規模板形態。
        assert!(heal_needed(Some("<dict> reordered </dict>"), &rendered));
    }
}
