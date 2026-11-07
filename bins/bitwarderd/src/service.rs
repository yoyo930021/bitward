//! LaunchAgent 自管（計畫 R2：thin autofill 依賴 daemon 存活）。
//! SMAppService.agent(plistName:) 對本機組建的 app 回 EPERM（MAS 分發形態限定），
//! 故由非沙盒的 daemon 自己寫 ~/Library/LaunchAgents + launchctl bootstrap。
//! launchd 的 socket 激活只認 Mach port，我們的 BTP 是 UDS——等效手段為
//! RunAtLoad + KeepAlive 進程級常駐。

use std::path::PathBuf;
use std::process::Command;

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

pub fn run(action: ServiceAction, exe: PathBuf, group: Option<&str>) -> Result<String, String> {
    let plist = plist_path().ok_or("no home dir")?;
    match action {
        ServiceAction::Install => {
            let group = group.ok_or("install 需要 --push-app-group <id>")?;
            std::fs::create_dir_all(plist.parent().unwrap()).map_err(|e| e.to_string())?;
            let data_dir = crate::default_data_dir();
            // 安裝者環境若有 BITWARD_DATA_DIR（demo/開發 vault），寫進 plist 讓
            // launchd 啟動時沿用；否則走 daemon 預設資料目錄。
            let env_block = std::env::var("BITWARD_DATA_DIR")
                .ok()
                .map(|d| {
                    format!(
                        r#"    <key>EnvironmentVariables</key>
    <dict>
        <key>BITWARD_DATA_DIR</key>
        <string>{d}</string>
    </dict>
"#
                    )
                })
                .unwrap_or_default();
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
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
"#,
                exe.display(),
                log = data_dir.join("daemon.log").display()
            );
            std::fs::write(&plist, xml).map_err(|e| e.to_string())?;
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
