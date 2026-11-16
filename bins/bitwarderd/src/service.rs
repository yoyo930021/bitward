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
//!
//! 批次 16（PR6-E1）：Linux 等位實作＝systemd **user unit**（`render_unit`，
//! 同為純函數真相源＋同構自癒合）。語意對映：KeepAlive+ThrottleInterval→
//! Restart=always+RestartSec=1、RunAtLoad→WantedBy=default.target、
//! StandardOutPath→journald、第四閘 launchd 直屬→INVOCATION_ID 環境標記
//! （只有被 systemd --user 扶正的進程有此欄，terminal 手跑沒有）。

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
// Linux 側同值作 unit 檔名（io.bitward.dev.daemon.service）。
const LABEL: &str = "io.bitward.dev.daemon";
#[cfg(target_os = "macos")]
const LEGACY_LABEL: &str = "io.bitward.daemon";
/// 批次 14.5：註冊環境常數——Keychain 封存開關恆寫入（keychain.rs 對無生物
/// 硬體本有 fallback，不需啟動偵測）。
const KEYCHAIN_ENV: &str = "BW_KEYS_ENABLE_KEYCHAIN";
/// 正式默認 BTP socket（e2e 以 BW_SERVICE_SOCK 覆寫，同步入 plist env）。
const DEFAULT_SOCK: &str = "/private/tmp/io.bitward.dev/daemon.sock";

/// 批次 14.7：Label 可測覆寫——e2e 用獨立 label 在真 launchd 域自測自癒合
/// 重載，不碰常駐註冊（域是全域的，HOME 暫逃只躲得過 plist 檔、躲不過 bootstrap）。
fn service_label() -> String {
    std::env::var("BW_SERVICE_LABEL").unwrap_or_else(|_| LABEL.to_owned())
}

#[cfg(target_os = "macos")]
fn retire_legacy_plist() {
    let Some(home) = dirs::home_dir() else { return };
    let old = home.join("Library/LaunchAgents").join(format!("{LEGACY_LABEL}.plist"));
    let _ = launchctl(&["bootout", &bootstrap_target(), &old.display().to_string()]);
    let _ = std::fs::remove_file(&old);
}

#[cfg(target_os = "macos")]
fn plist_path() -> Option<PathBuf> {
    // 批次 14.7 老實：dirs::home_dir() 走 getpwuid、**不理 $HOME**——之前
    // service.sh 用 HOME=暫逃是假隔離（stage1-3 實測洩漏到真 home 致污染）。
    // 改顯式讀 HOME 環境優先,e2e 隔離成真;無 HOME 才退回 getpwuid。
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)?;
    Some(
        home.join("Library/LaunchAgents")
            .join(format!("{}.plist", service_label())),
    )
}

fn uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(target_os = "macos")]
fn bootstrap_target() -> String {
    format!("gui/{}", uid())
}

/// 渲染 LaunchAgent plist（註冊真相源，純函數，單測點）。
/// `exe`＝daemon 執行檔絕對路徑、`group`＝push app-group、`log`＝日誌路徑、
/// `sock`＝BTP socket 路徑（正式默認 /private/tmp/…；e2e 用獨立值避免撞
/// 常駐實例綁定，非默認時同步寫進 EnvironmentVariables 讓 launchd 拉起的
/// daemon 渲染出相同模板→自癒合判定穩定）；
/// `data_dir_env`＝安裝者 `BITWARD_DATA_DIR`（demo/開發 vault），None＝走預設。
/// EnvironmentVariables 恆含 `BW_KEYS_ENABLE_KEYCHAIN=1`，有 data_dir 時再加一筆。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // Linux 側保留給單測金標與文件
pub fn render_plist(
    exe: &str,
    group: &str,
    log: &str,
    sock: &str,
    data_dir_env: Option<&str>,
) -> String {
    let mut env_inner = format!("        <key>{KEYCHAIN_ENV}</key>\n        <string>1</string>\n");
    if sock != DEFAULT_SOCK {
        env_inner.push_str(&format!(
            "        <key>BW_SERVICE_SOCK</key>\n        <string>{sock}</string>\n"
        ));
    }
    if let Some(d) = data_dir_env {
        env_inner.push_str(&format!(
            "        <key>BITWARD_DATA_DIR</key>\n        <string>{d}</string>\n"
        ));
    }
    // e2e 白名單旗同步入 env：launchd 拉起的 daemon 渲染同一模板（判定穩定）。
    let label = service_label();
    if std::env::var("BW_SERVICE_ALLOW_DEV_HEAL").is_ok() {
        env_inner.push_str("        <key>BW_SERVICE_ALLOW_DEV_HEAL</key>\n        <string>1</string>\n");
    }
    if std::env::var("BW_SERVICE_LABEL").is_ok() {
        env_inner.push_str(&format!(
            "        <key>BW_SERVICE_LABEL</key>\n        <string>{label}</string>\n"
        ));
    }
    let env_block = format!(
        "    <key>EnvironmentVariables</key>\n    <dict>\n{env_inner}    </dict>\n"
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--sock</string>
        <string>{sock}</string>
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

/// Q3 裁決：Linux sock 主路徑＝`$XDG_RUNTIME_DIR/bitward/daemon.sock`；
/// 環境缺席才退 `/run/user/<uid>`（user manager 拉起時恆有值，純防呆）。
/// data_dir 退路屬連線端語意（見 `default_sock` 於 main.rs）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // macOS 側保留單測金標
pub fn linux_default_sock() -> PathBuf {
    let base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(format!("/run/user/{}", uid())),
    };
    base.join("bitward").join("daemon.sock")
}

/// 渲染 systemd user unit（Linux 註冊真相源，純函數，單測點——仿 `render_plist`）。
/// `exe`＝daemon 絕對路徑、`sock`＝BTP socket（默認 `linux_default_sock`，
/// 一律寫入 ExecStart argv＝穩定契約，拉起端與安裝端渲染同文才成立）、
/// `data_dir_env`＝安裝者 `BITWARD_DATA_DIR`，None＝走預設。
/// 日誌走 journald（等效 StandardOutPath，`journalctl --user -u <label>` 可查）；
/// e2e 白名單旗／label 覆寫同步入 Environment 讓拉起端渲染同模板（同 plist 紀律）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // macOS 側保留單測金標
pub fn render_unit(exe: &str, sock: &str, data_dir_env: Option<&str>) -> String {
    let label = service_label();
    let mut env_lines = String::new();
    if let Some(d) = data_dir_env {
        env_lines.push_str(&format!("Environment=BITWARD_DATA_DIR=\"{d}\"\n"));
    }
    if std::env::var("BW_SERVICE_ALLOW_DEV_HEAL").is_ok() {
        env_lines.push_str("Environment=BW_SERVICE_ALLOW_DEV_HEAL=1\n");
    }
    if std::env::var("BW_SERVICE_LABEL").is_ok() {
        env_lines.push_str(&format!("Environment=BW_SERVICE_LABEL={label}\n"));
    }
    format!(
        r#"[Unit]
Description=bitward hub daemon ({label})

[Service]
ExecStart="{exe}" --sock "{sock}"
Restart=always
RestartSec=1
{env_lines}
[Install]
WantedBy=default.target
"#
    )
}

/// unit 檔落點：`$HOME/.config/systemd/user/<label>.service`（user 域，
/// 不需 root）。顯式讀 HOME 優先（同 `plist_path` 的 14.7 老實教訓）。
#[cfg(target_os = "linux")]
fn unit_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)?;
    Some(
        home.join(".config/systemd/user")
            .join(format!("{}.service", service_label())),
    )
}

/// 組裝當前台應存在的 unit 內容（啟動與 Install 共用，單一真相源）。
#[cfg(target_os = "linux")]
fn desired_unit(exe: &Path, sock: Option<&str>) -> String {
    let sock_path = match sock {
        Some(s) => std::path::PathBuf::from(s),
        None => linux_default_sock(),
    };
    render_unit(
        &exe.display().to_string(),
        &sock_path.display().to_string(),
        std::env::var("BITWARD_DATA_DIR").ok().as_deref(),
    )
}

/// 啟動自癒合判定（純函數，單測點）：現存內容與渲染模板**字串等值**才跳過；
/// 未安裝（None）跳過（建立是 Install 的職責）；不同→觸發覆寫。不做 mtime。
pub fn heal_needed(existing: Option<&str>, rendered: &str) -> bool {
    existing.is_some_and(|e| e != rendered)
}

/// 組裝當前台應存在的 plist 內容（啟動與 Install 共用，單一真相源）。
/// 批次 14.7：全部輸入取自**啟動參數**（exe/group/sock/進程環境中的
/// BITWARD_DATA_DIR），不讀 only-shell 變數——launchd 拉起端與安裝端
/// 渲染同文才成立（env 會隨拉起者不同,argv 是穩定契約）。
#[cfg(target_os = "macos")]
fn desired_plist(exe: &Path, group: &str, sock: Option<&str>) -> String {
    let log = crate::default_data_dir().join("daemon.log");
    let sock = sock.unwrap_or(DEFAULT_SOCK);
    render_plist(
        &exe.display().to_string(),
        group,
        &log.display().to_string(),
        sock,
        std::env::var("BITWARD_DATA_DIR").ok().as_deref(),
    )
}

/// 自癒合守門（純函數，單測點）——四條全過才觸發：
/// 1. 現存 plist 存在且與模板字串不符（heal_needed）；
/// 2. 現存 plist 已指向本執行檔（不越權覆寫別人的註冊）；
/// 3. 本執行檔**不在 repo 構建目錄**（`/target/` 路徑＝開發二進位）——
///    批次 14.7 紀律：dev 實例絕不碰常駐註冊域（23:15 污染事故根因；
///    e2e 要測自癒合請用 BW_SERVICE_LABEL 獨立 label + 白名單旗）。
/// 4. 本進程由服務管理器直屬扶正，或持 dev 白名單旗——批次 14.9 實錄：
///    從 terminal 手跑 `/Applications` 版帶自訂 `--sock /tmp/149e.sock`，
///    前兩條全過、把一次性探測參數當成真相源覆寫了註冊模板（幽靈參數
///    頂掉常駐 13 分鐘）。只有「被管理器扶正的那個我」才有資格改註冊。
///    macOS＝launchd 直屬（PPID==1）；Linux＝systemd user 拉起（環境帶
///    `INVOCATION_ID`，terminal 手跑沒有——第四閘語意的等位對映）。
pub fn should_self_heal(
    existing: Option<&str>,
    rendered: &str,
    exe: &str,
    allow_dev_binary: bool,
    launched_by_manager: bool,
) -> bool {
    let Some(e) = existing else { return false };
    heal_needed(Some(e), rendered)
        && e.contains(exe)
        && (allow_dev_binary || !exe.contains("/target/"))
        && (allow_dev_binary || launched_by_manager)
}

/// daemon 啟動自癒合（非 `service install` 路徑）：現存註冊檔（macOS plist／
/// Linux systemd user unit）若與模板不符，覆寫並派生重載子進程。
/// 回傳 Some(訊息) 表觸發。
pub fn self_heal(group: Option<&str>, sock: Option<&str>) -> Option<String> {
    #[cfg(target_os = "macos")]
    return self_heal_macos(group, sock);
    #[cfg(target_os = "linux")]
    {
        let _ = group; // app-group 是 macOS 專有；Linux 註冊不含
        self_heal_linux(sock)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (group, sock);
        None
    }
}

#[cfg(target_os = "macos")]
fn self_heal_macos(group: Option<&str>, sock: Option<&str>) -> Option<String> {
    let plist = plist_path()?;
    let existing = std::fs::read_to_string(&plist).ok()?; // 未安裝 → 跳過
    let exe = std::env::current_exe().ok()?;
    let allow_dev = std::env::var("BW_SERVICE_ALLOW_DEV_HEAL").is_ok();
    let under_launchd = unsafe { libc::getppid() } == 1;
    let rendered = desired_plist(&exe, group.unwrap_or("group.8V5224A99M.io.bitward.dev"), sock);
    if !should_self_heal(
        Some(&existing),
        &rendered,
        &exe.display().to_string(),
        allow_dev,
        under_launchd,
    ) {
        return None;
    }
    std::fs::write(&plist, &rendered).ok()?;
    let sentinel = crate::default_data_dir().join("self-heal.result");
    let reloaded = if std::env::var("BW_SERVICE_NO_RELOAD").is_err() {
        spawn_reload(&plist, &sentinel);
        "已覆寫並派生重載"
    } else {
        let _ = std::fs::write(&sentinel, "written-no-reload");
        "已覆寫（NO_RELOAD:不派重載子）"
    };
    Some(format!(
        "self-heal: {}.plist 與模板不符，{reloaded}（結果哨兵：{}）",
        service_label(),
        sentinel.display()
    ))
}

/// Linux 自癒合（同構合同：比對 unit 檔與模板、四閘判定、覆寫＋派重載子）。
/// 第四閘輸入＝`INVOCATION_ID` 存在（只有被 systemd --user 扶正的進程有此欄，
/// 語意對映 macOS 的 PPID==1；terminal 手跑一次性探測不得覆寫註冊）。
#[cfg(target_os = "linux")]
fn self_heal_linux(sock: Option<&str>) -> Option<String> {
    let unit = unit_path()?;
    let existing = std::fs::read_to_string(&unit).ok()?; // 未安裝 → 跳過
    let exe = std::env::current_exe().ok()?;
    let allow_dev = std::env::var("BW_SERVICE_ALLOW_DEV_HEAL").is_ok();
    let under_manager = std::env::var_os("INVOCATION_ID").is_some();
    let rendered = desired_unit(&exe, sock);
    if !should_self_heal(
        Some(&existing),
        &rendered,
        &exe.display().to_string(),
        allow_dev,
        under_manager,
    ) {
        return None;
    }
    std::fs::write(&unit, &rendered).ok()?;
    let sentinel = crate::default_data_dir().join("self-heal.result");
    let reloaded = if std::env::var("BW_SERVICE_NO_RELOAD").is_err() {
        spawn_reload_linux(&sentinel);
        "已覆寫並派生重載"
    } else {
        let _ = std::fs::write(&sentinel, "written-no-reload");
        "已覆寫（NO_RELOAD:不派重載子）"
    };
    Some(format!(
        "self-heal: {}.service 與模板不符，{reloaded}（結果哨兵：{}）",
        service_label(),
        sentinel.display()
    ))
}

/// 派生重載子進程（批次 14.7 根治「bootout 殺父連坐、bootstrap 未落地」）：
/// - `process_group(0)`：自立進程組，父被 bootout 群殺時不被連坐；
/// - 睡 1 秒讓父完成啟動日誌；bootout（容忍未載入）；
/// - bootstrap 失敗重試 3 次、間隔 2 秒（域拆除中的瞬時失敗可救回）；
/// - 終態寫哨兵檔（ok/fail + launchctl print 覆核），供 e2e 與人工排障。
#[cfg(target_os = "macos")]
fn spawn_reload(plist: &Path, sentinel: &Path) {
    use std::os::unix::process::CommandExt;
    let target = bootstrap_target();
    let label = service_label();
    let p = plist.display().to_string();
    let s = sentinel.display().to_string();
    let script = format!(
        r#"sleep 1
/bin/launchctl bootout {target} '{p}' 2>/dev/null
i=0
until /bin/launchctl bootstrap {target} '{p}' 2>/dev/null; do
    i=$((i+1)); [ "$i" -ge 3 ] && break; sleep 2
done
if /bin/launchctl print {target}/{label} >/dev/null 2>&1; then
    echo ok > '{s}'
else
    echo fail > '{s}'
fi"#
    );
    let _ = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

pub fn run(
    action: ServiceAction,
    exe: PathBuf,
    group: Option<&str>,
    sock: Option<&str>,
) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return run_macos(action, exe, group, sock);
    #[cfg(target_os = "linux")]
    {
        let _ = group; // app-group 是 macOS 專有
        run_linux(action, exe, sock)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (action, exe, group, sock);
        Err("service 自管僅支援 macOS（LaunchAgent）與 Linux（systemd user）".into())
    }
}

#[cfg(target_os = "macos")]
fn run_macos(
    action: ServiceAction,
    exe: PathBuf,
    group: Option<&str>,
    sock: Option<&str>,
) -> Result<String, String> {
    let plist = plist_path().ok_or("no home dir")?;
    match action {
        ServiceAction::Install => {
            let group = group.ok_or("install 需要 --push-app-group <id>")?;
            std::fs::create_dir_all(plist.parent().unwrap()).map_err(|e| e.to_string())?;
            let xml = desired_plist(&exe, group, sock);
            std::fs::write(&plist, xml).map_err(|e| e.to_string())?;
            // e2e 出口：只验渲染/落檔，不碰 launchd 域（同 Label 已载会撞真注册）。
            if std::env::var("BW_SERVICE_NO_BOOTSTRAP").is_ok() {
                return Ok(format!("installed {} <- {} (no-bootstrap)", service_label(), exe.display()));
            }
            // 重裝語意：先 bootout（容忍未載入）再 bootstrap。
            let _ = launchctl(&["bootout", &bootstrap_target(), &plist.display().to_string()]);
            retire_legacy_plist();
            launchctl(&[
                "bootstrap",
                &bootstrap_target(),
                &plist.display().to_string(),
            ])?;
            Ok(format!("installed {} <- {}", service_label(), exe.display()))
        }
        ServiceAction::Uninstall => {
            let _ = launchctl(&["bootout", &bootstrap_target(), &plist.display().to_string()]);
            let _ = std::fs::remove_file(&plist);
            retire_legacy_plist();
            Ok(format!("uninstalled {}", service_label()))
        }
        ServiceAction::Status => {
            let target = format!("{}/{}", bootstrap_target(), service_label());
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

#[cfg(target_os = "macos")]
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

/// systemd user 域包裝（等效 launchctl 對 gui/<uid> 的操作）。
#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    cmd.args(args);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Linux 註冊鏈：bootstrap/bootstrap 的等位＝write unit → daemon-reload →
/// enable --now（RunAtLoad 語意在 `WantedBy=default.target`＋enable 符號連結）。
/// 同吃 `BW_SERVICE_NO_BOOTSTRAP` e2e 出口（只驗渲染落檔、不碰真域）。
#[cfg(target_os = "linux")]
fn run_linux(action: ServiceAction, exe: PathBuf, sock: Option<&str>) -> Result<String, String> {
    let unit = unit_path().ok_or("no home dir")?;
    let label = service_label();
    match action {
        ServiceAction::Install => {
            std::fs::create_dir_all(unit.parent().unwrap()).map_err(|e| e.to_string())?;
            let text = desired_unit(&exe, sock);
            std::fs::write(&unit, text).map_err(|e| e.to_string())?;
            if std::env::var("BW_SERVICE_NO_BOOTSTRAP").is_ok() {
                return Ok(format!(
                    "installed {label} <- {} (no-bootstrap)",
                    exe.display()
                ));
            }
            // 重裝語意：先 disable --now（容忍未載入）再覆寫重載。
            let _ = systemctl(&["disable", "--now", &label]);
            systemctl(&["daemon-reload"])?;
            systemctl(&["enable", "--now", &label])?;
            Ok(format!("installed {label} <- {}", exe.display()))
        }
        ServiceAction::Uninstall => {
            let _ = systemctl(&["disable", "--now", &label]);
            let _ = std::fs::remove_file(&unit);
            let _ = systemctl(&["daemon-reload"]);
            Ok(format!("uninstalled {label}"))
        }
        ServiceAction::Status => {
            let out = Command::new("systemctl")
                .args(["--user", "is-active", &label])
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

/// Linux 重載子：必經 `systemd-run --user` 把腳本搬到**本 unit cgroup 之外**
/// （restart 掃 cgroup 時會連坐殺掉普通子進程，process_group 在此無效——
/// 與 macOS 14.7 教訓同構但機制不同，哨兵必寫成才有 e2e 覆核點）。
/// systemd-run 缺席（非 systemd 環境）退回直派 sh，哨兵可能隨掃蕩失落。
#[cfg(target_os = "linux")]
fn spawn_reload_linux(sentinel: &Path) {
    let label = service_label();
    let s = sentinel.display().to_string();
    let script = format!(
        r#"sleep 1
systemctl --user daemon-reload
systemctl --user restart {label}
if systemctl --user is-active --quiet {label}; then
    echo ok > "{s}"
else
    echo fail > "{s}"
fi"#
    );
    let run = Command::new("systemd-run")
        .args(["--user", "--collect", "--quiet", "/bin/sh", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if run.is_ok() {
        return;
    }
    let _ = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "/Applications/Bitward.app/Contents/Helpers/bitwarderd";
    const GROUP: &str = "group.8V5224A99M.io.bitward.dev";
    const LOG: &str = "/Users/x/Library/Application Support/bitward/daemon.log";
    const SOCK: &str = "/private/tmp/io.bitward.dev/daemon.sock";

    #[test]
    fn render_always_includes_keychain() {
        // 有無 BITWARD_DATA_DIR 兩態，KEYCHAIN 開關恆在。
        let a = render_plist(EXE, GROUP, LOG, SOCK, None);
        let b = render_plist(EXE, GROUP, LOG, SOCK, Some("/tmp/vault"));
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
    fn render_unit_golden_and_heal_contract() {
        // PR6-E1：systemd user unit 渲染金標＋自癒合比較（仿 plist 測）。
        let exe = "/home/u/.local/bin/bitwarderd";
        let sock = "/run/user/501/bitward/daemon.sock";
        let a = render_unit(exe, sock, None);
        let b = render_unit(exe, sock, None);
        assert_eq!(a, b, "同輸入必字串等值（自癒合比較靠這）");
        assert!(
            a.contains(&format!("ExecStart=\"{exe}\" --sock \"{sock}\"")),
            "sock 必入 ExecStart argv（穩定契約）：{a}"
        );
        assert!(a.contains("Restart=always") && a.contains("RestartSec=1"));
        assert!(a.contains("WantedBy=default.target"));
        assert!(a.contains(LABEL), "unit 內文含 label 供狀態判定");
        assert!(
            !a.contains("BW_KEYS_ENABLE_KEYCHAIN"),
            "Keychain 開關是 macOS 專有，不入 unit"
        );
        let with_dd = render_unit(exe, sock, Some("/srv/vault"));
        assert!(with_dd.contains("Environment=BITWARD_DATA_DIR=\"/srv/vault\""));
        assert!(
            !a.contains("BITWARD_DATA_DIR"),
            "無 data_dir 環境不應寫入該鍵"
        );
        // 自癒合判定對 unit 同形：同文跳過、異文觸發、launchd 直屬對映 manager 旗。
        assert!(!heal_needed(Some(&a), &render_unit(exe, sock, None)));
        let stale = a.replace("RestartSec=1", "RestartSec=5");
        assert!(heal_needed(Some(&stale), &a));
        assert!(should_self_heal(Some(&stale), &a, exe, false, true));
        assert!(!should_self_heal(Some(&stale), &a, exe, false, false));
        // dev 二進位閘同構：/target/ 路徑預設跳過。
        let dev = render_unit("/repo/target/debug/bitwarderd", sock, None);
        let dev_stale = dev.replace("RestartSec=1", "RestartSec=5");
        assert!(!should_self_heal(
            Some(&dev_stale),
            &dev,
            "/repo/target/debug/bitwarderd",
            false,
            true
        ));
    }

    #[test]
    fn render_is_deterministic() {
        let a = render_plist(EXE, GROUP, LOG, SOCK, None);
        let b = render_plist(EXE, GROUP, LOG, SOCK, None);
        assert_eq!(a, b, "同輸入必字串等值（自癒合比較靠這）");
    }

    #[test]
    fn heal_needed_compares_exact_text() {
        let rendered = render_plist(EXE, GROUP, LOG, SOCK, None);
        // 同文跳過（冪等）；異文觸發；未安裝跳過。
        assert!(!heal_needed(Some(&rendered), &rendered));
        let stale = rendered.replace("1</string>", "0</string>");
        assert!(heal_needed(Some(&stale), &rendered));
        // 未安裝（無現存檔）→ 不自癒（那是 Install 的職責）。
        assert!(!heal_needed(None, &rendered));
        // plutil 重排鍵序也算「不同」→ 覆寫回正規模板形態。
        assert!(heal_needed(Some("<dict> reordered </dict>"), &rendered));
    }

    #[test]
    fn self_heal_guard_blocks_dev_binaries_and_foreign_exes() {
        let rendered = render_plist(EXE, GROUP, LOG, SOCK, None);
        let stale = rendered.replace("<string>1</string>", "<string>0</string>");
        // 正式二進位 + 指向本檔 + 內容過舊 + launchd 直屬 → 觸發。
        assert!(should_self_heal(Some(&stale), &rendered, EXE, false, true));
        // 同文 → 跳過（冪等）。
        assert!(!should_self_heal(Some(&rendered), &rendered, EXE, false, true));
        // plist 指向別家（/Applications vs 本檔是 temp）→ 跳過，不越權。
        assert!(!should_self_heal(
            Some(&stale), &rendered, "/somewhere/else/bitwarderd", false, true
        ));
        // 14.9 四閘：正式二進位但**非 launchd 直屬**（terminal 手跑探測帶自訂
        // --sock,把一次性參數當真相源覆寫註冊、幽靈頂掉常駐 13 分鐘的實錄）
        // → 跳過；dev 白名單旗仍可放行（e2e 於 temp HOME 內驗判定軸）。
        assert!(!should_self_heal(Some(&stale), &rendered, EXE, false, false));
        assert!(should_self_heal(Some(&stale), &rendered, EXE, true, false));
        // repo 構建目錄二進位（/target/debug|release）→ 預設跳過（14.7 紀律：
        // dev 實例絕不碰常駐註冊域）；e2e 白名單旗可放行。
        let dev = render_plist("/repo/target/debug/bitwarderd", GROUP, LOG, SOCK, None);
        let dev_stale = dev.replace("<string>1</string>", "<string>0</string>");
        assert!(!should_self_heal(
            Some(&dev_stale), &dev, "/repo/target/debug/bitwarderd", false, true
        ));
        assert!(should_self_heal(
            Some(&dev_stale), &dev, "/repo/target/debug/bitwarderd", true, false
        ));
        // 未安裝 → 跳過。
        assert!(!should_self_heal(None, &rendered, EXE, false, true));
    }
}
