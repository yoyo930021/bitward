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
/// 正式默認 BTP socket（e2e 以 BW_SERVICE_SOCK 覆寫，同步入 plist env）。
const DEFAULT_SOCK: &str = "/private/tmp/io.bitward.dev/daemon.sock";

/// 批次 14.7：Label 可測覆寫——e2e 用獨立 label 在真 launchd 域自測自癒合
/// 重載，不碰常駐註冊（域是全域的，HOME 暫逃只躲得過 plist 檔、躲不過 bootstrap）。
fn service_label() -> String {
    std::env::var("BW_SERVICE_LABEL").unwrap_or_else(|_| LABEL.to_owned())
}

fn retire_legacy_plist() {
    let Some(home) = dirs::home_dir() else { return };
    let old = home.join("Library/LaunchAgents").join(format!("{LEGACY_LABEL}.plist"));
    let _ = launchctl(&["bootout", &bootstrap_target(), &old.display().to_string()]);
    let _ = std::fs::remove_file(&old);
}

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

/// 啟動自癒合判定（純函數，單測點）：現存內容與渲染模板**字串等值**才跳過；
/// 未安裝（None）跳過（建立是 Install 的職責）；不同→觸發覆寫。不做 mtime。
pub fn heal_needed(existing: Option<&str>, rendered: &str) -> bool {
    existing.is_some_and(|e| e != rendered)
}

/// 組裝當前台應存在的 plist 內容（啟動與 Install 共用，單一真相源）。
/// 批次 14.7：全部輸入取自**啟動參數**（exe/group/sock/進程環境中的
/// BITWARD_DATA_DIR），不讀 only-shell 變數——launchd 拉起端與安裝端
/// 渲染同文才成立（env 會隨拉起者不同,argv 是穩定契約）。
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
/// 4. 本進程由 launchd 直屬（PPID==1）或持 dev 白名單旗——批次 14.9 實錄：
///    從 terminal 手跑 `/Applications` 版帶自訂 `--sock /tmp/149e.sock`，
///    前兩條全過、把一次性探測參數當成真相源覆寫了註冊模板（幽靈參數
///    頂掉常駐 13 分鐘）。只有「被 launchd 扶正的那個我」才有資格改註冊。
pub fn should_self_heal(
    existing: Option<&str>,
    rendered: &str,
    exe: &str,
    allow_dev_binary: bool,
    launched_by_launchd: bool,
) -> bool {
    let Some(e) = existing else { return false };
    heal_needed(Some(e), rendered)
        && e.contains(exe)
        && (allow_dev_binary || !exe.contains("/target/"))
        && (allow_dev_binary || launched_by_launchd)
}

/// daemon 啟動自癒合（非 `service install` 路徑）：現存 plist 若與模板不符，
/// 覆寫並派生重載子進程。回傳 Some(訊息) 表觸發。
pub fn self_heal(group: Option<&str>, sock: Option<&str>) -> Option<String> {
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

/// 派生重載子進程（批次 14.7 根治「bootout 殺父連坐、bootstrap 未落地」）：
/// - `process_group(0)`：自立進程組，父被 bootout 群殺時不被連坐；
/// - 睡 1 秒讓父完成啟動日誌；bootout（容忍未載入）；
/// - bootstrap 失敗重試 3 次、間隔 2 秒（域拆除中的瞬時失敗可救回）；
/// - 終態寫哨兵檔（ok/fail + launchctl print 覆核），供 e2e 與人工排障。
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
