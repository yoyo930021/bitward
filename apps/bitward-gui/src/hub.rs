//! 跨機中樞編組與設定面（PR6-E3b）。
//!
//! registry 與 CLI 共用 `<data_dir>/remotes/`：profile 檔 `{url,pin,token,wake}`、
//! `.default` 預設指標、`remote_<profile>_last_ok` 見活標記。形態真相源是 CLI
//! （`pair join` 落檔、`hub ls`/`hub default` 讀寫），本模組逐欄位對齊——兩邊
//! 寫檔對方都讀得到。清單／設預設／撤銷＝純本機檔案操作（同 `hub ls`：不連
//! daemon，本機中樞缺席時照樣能修編組）；只有「配對碼加入」走網路（`btp::join_hub`）。

use std::path::{Path, PathBuf};

use nsh_core::prelude::*;

use crate::btp::{TlsTarget, Transport};
use crate::state::{AppCore, Cmd};
use crate::theme;
use crate::ui;

/// 預設 hub 指標檔（remotes/ 下的 dotfile：不帶 .json 後綴，天然不進清單）。同 CLI 常量。
const DEFAULT_HUB_FILE: &str = ".default";
/// 配對目標缺省 port（同 CLI E4：tailnet 磁標只給 hostname 時用）。
const DEFAULT_PAIR_PORT: u16 = 8443;

/// `remotes/<profile>.json`：與 CLI `RemoteProfile` 同形（欄位名＝檔案契約）。
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteProfile {
    pub url: String,
    pub pin: String,
    pub token: String,
    #[serde(default)]
    pub wake: Option<String>,
}

/// 清單一列（視圖模型）：profile 名＋url＋預設旗＋最近成功連線時刻。
#[derive(Clone, Debug, PartialEq)]
pub struct HubRow {
    pub profile: String,
    pub url: String,
    pub is_default: bool,
    pub last_seen_ms: Option<u64>,
}

fn remotes_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("remotes")
}

/// 目標解析（CLI `split_url` 同式）：吃 `https://host:port`、`host:port`、裸
/// `host`（磁標→默認 port）。IPv6 字面量不支援（配對目標實務為 DNS/tailnet 名）。
pub fn split_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.trim();
    let rest = rest.strip_prefix("https://").unwrap_or(rest);
    if rest.is_empty() || rest.contains('/') {
        return Err("目標形態應為 host[:port]（不含 path）".into());
    }
    match rest.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Ok((
            h.to_owned(),
            p.parse::<u16>()
                .map_err(|e: std::num::ParseIntError| format!("port 非法：{e}"))?,
        )),
        Some(_) => Err("port 前缺 host".into()),
        None => Ok((rest.to_owned(), DEFAULT_PAIR_PORT)),
    }
}

/// profile 名＝檔名：限英數與 `-`/`_`，不撞 dotfile、不帶路徑語意。
pub fn check_profile(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if ok {
        Ok(())
    } else {
        Err("名稱限英數字元、-、_（1–64 字）".into())
    }
}

pub fn canonical_url(host: &str, port: u16) -> String {
    format!("https://{host}:{port}")
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// 落檔（0600：檔內是 device token）；建 remotes/ 目錄冪等。
pub fn save(data_dir: &Path, profile: &str, prof: &RemoteProfile) -> Result<(), String> {
    let dir = remotes_dir(data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{profile}.json"));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(prof).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load(data_dir: &Path, profile: &str) -> Result<RemoteProfile, String> {
    let path = remotes_dir(data_dir).join(format!("{profile}.json"));
    let raw = std::fs::read(&path).map_err(|_| format!("沒有 hub profile「{profile}」"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("{}.json 形態不合：{e}", path.display()))
}

/// 清單（名字典序，同 CLI `hub ls`）；形態壞檔跳過不炸整頁。
pub fn list(data_dir: &Path) -> Vec<HubRow> {
    let default = read_default(data_dir);
    let mut v: Vec<HubRow> = std::fs::read_dir(remotes_dir(data_dir))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let profile = name.strip_suffix(".json")?.to_owned();
            let prof = load(data_dir, &profile).ok()?;
            Some(HubRow {
                is_default: default.as_deref() == Some(profile.as_str()),
                last_seen_ms: last_seen(data_dir, &profile),
                url: prof.url,
                profile,
            })
        })
        .collect();
    v.sort_by(|a, b| a.profile.cmp(&b.profile));
    v
}

pub fn read_default(data_dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(remotes_dir(data_dir).join(DEFAULT_HUB_FILE)).ok()?;
    let t = s.trim().to_owned();
    (!t.is_empty()).then_some(t)
}

/// 設預設（存在性檢查同 CLI `hub default`）；None＝清除（failover 關閉）。
pub fn set_default(data_dir: &Path, profile: Option<&str>) -> Result<(), String> {
    let f = remotes_dir(data_dir).join(DEFAULT_HUB_FILE);
    match profile {
        None => {
            let _ = std::fs::remove_file(&f);
            Ok(())
        }
        Some(p) => {
            if !list(data_dir).iter().any(|r| r.profile == p) {
                return Err(format!("沒有 hub profile「{p}」"));
            }
            std::fs::write(&f, p).map_err(|e| e.to_string())
        }
    }
}

/// 撤銷＝刪本機存檔（含見活標記；預設指標指向它一併清除）。hub 端 device
/// session 歸 TTL／鎖態管轄，thin 端不越權代刪。
pub fn remove(data_dir: &Path, profile: &str) -> Result<(), String> {
    let path = remotes_dir(data_dir).join(format!("{profile}.json"));
    std::fs::remove_file(&path).map_err(|e| format!("移除「{profile}」失敗：{e}"))?;
    let _ = std::fs::remove_file(data_dir.join(format!("remote_{profile}_last_ok")));
    if read_default(data_dir).as_deref() == Some(profile) {
        let _ = std::fs::remove_file(remotes_dir(data_dir).join(DEFAULT_HUB_FILE));
    }
    Ok(())
}

fn last_seen(data_dir: &Path, profile: &str) -> Option<u64> {
    std::fs::read_to_string(data_dir.join(format!("remote_{profile}_last_ok")))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 成功連線後蓋見活標記（同 CLI `open_remote`；失聯提示的資料源）。
pub fn touch_last_ok(data_dir: &Path, profile: &str) {
    let _ = std::fs::write(
        data_dir.join(format!("remote_{profile}_last_ok")),
        now_ms().to_string(),
    );
}

/// profile → 連線目標（url 解析在此收斂；落檔 url 已是正規形態）。
pub fn target(profile: &str, prof: &RemoteProfile) -> Result<TlsTarget, String> {
    let (host, port) = split_url(&prof.url)?;
    Ok(TlsTarget {
        profile: profile.to_owned(),
        url: canonical_url(&host, port),
        host,
        port,
        pin: prof.pin.clone(),
        token: prof.token.clone(),
    })
}

/// failover 目標（§1.1，CLI `route_hub` 的 Failover 分支同語意）：只在
/// 「本機態且預設 hub 載入成功」時給目標——已是 TLS 態即 None，杜絕換 hub
/// 反覆失敗時的切換迴圈。
pub fn failover_target(data_dir: &Path, current: &Transport) -> Option<TlsTarget> {
    if !matches!(current, Transport::Unix(_)) {
        return None;
    }
    let d = read_default(data_dir)?;
    target(&d, &load(data_dir, &d).ok()?).ok()
}

/// 見活標記的人話版（同 CLI last_seen 欄）。
fn ago_label(ms: Option<u64>) -> String {
    let Some(seen) = ms else {
        return "從未連線".into();
    };
    let secs = now_ms().saturating_sub(seen) / 1000;
    match secs {
        0..=60 => "剛剛".into(),
        61..=3600 => format!("{} 分鐘前", secs / 60),
        3601..=86400 => format!("{} 小時前", secs / 3600),
        _ => format!("{} 天前", secs / 86400),
    }
}

/// 設定頁「跨機中樞」分節：現況列＋profile 清單（連線／設預設／撤銷）＋
/// 配對碼加入表單。清單是純檔案鏡（進頁與每次變更後 `Cmd::HubRefresh` 重讀）。
pub fn section(core: AppCore) -> View {
    let now_core = core.clone();
    let rows_core = core.clone();
    let url_core = core.clone();
    let pin_core = core.clone();
    let code_core = core.clone();
    let name_core = core.clone();
    let join_core = core.clone();
    let err_cond = core.clone();
    let err_build = core.clone();
    view()
        .flex_col()
        .gap_2()
        .child(ui::section_title("跨機中樞"))
        .child(
            text("本機 daemon 不在時改連已配對的遠端中樞（金鑰不出 hub，通道 TLS＋SPKI pin）。配對碼在 hub 機器以 `bitward pair start` 產生。")
                .text_size(px(theme::TEXT_PAGE_SUB))
                .line_height(px(17.0))
                .text_color(theme::TEXT_MUTED),
        )
        .child(dynamic(move || {
            text(format!("目前連線：{}", now_core.session.describe()))
                .text_size(px(12.5))
                .font_family(ui::mono_font())
                .text_color(theme::TEXT_SECONDARY)
        }))
        .child(dynamic(move || rows_block(rows_core.clone())))
        .child(ui::form_field(
            "目標 host[:port]",
            "desk.tailnet.ts（port 留空＝8443）",
            core.hub_form.url,
            false,
            move |v| url_core.hub_form.url.set(v),
        ))
        .child(ui::form_field(
            "SPKI pin",
            "pair start 回包中的 44 字元 pin",
            core.hub_form.pin,
            false,
            move |v| pin_core.hub_form.pin.set(v),
        ))
        .child(ui::form_field(
            "配對碼",
            "9 字元（一次性，用過即失效）",
            core.hub_form.code,
            false,
            move |v| code_core.hub_form.code.set(v),
        ))
        .child(ui::form_field(
            "名稱",
            "desk（英數、-、_）",
            core.hub_form.name,
            false,
            move |v| name_core.hub_form.name.set(v),
        ))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(ui::button_dyn(
                    move || {
                        if join_core.hub_busy.get() {
                            "配對中…".to_owned()
                        } else {
                            "配對並連線".to_owned()
                        }
                    },
                    ui::Btn::Ghost,
                    move || join_core.send(Cmd::HubJoin),
                ))
                .child(
                    text("加入後即存進 remotes/，CLI `bitward hub ls` 同步可見。")
                        .text_size(px(11.5))
                        .text_color(theme::TEXT_MUTED),
                ),
        )
        .child(when(
            move || err_cond.hub_error.get().is_some(),
            move || {
                text(move || err_build.hub_error.get().unwrap_or_default())
                    .text_size(px(12.5))
                    .line_height(px(18.0))
                    .text_color(theme::DESTRUCTIVE)
            },
        ))
}

/// 清單本體：本機列＋各 hub 列。
fn rows_block(core: AppCore) -> View {
    let mut col = view().flex_col().gap_1p5().w_full();
    let active_profile = core.session.active_profile();
    let is_active_local = active_profile.is_none();
    let c = core.clone();
    col = col.child(row_shell(
        "本機 daemon".to_owned(),
        crate::sock_path().display().to_string(),
        None,
        is_active_local,
        if is_active_local {
            None
        } else {
            Some(ui::button("連線", ui::Btn::Ghost, move || {
                c.send(Cmd::HubUseLocal)
            }))
        },
        None,
        None,
    ));
    for r in core.hub_rows.get().iter() {
        let name = r.profile.clone();
        let is_active = active_profile.as_deref() == Some(name.as_str());
        let c = core.clone();
        let connect = if is_active {
            None
        } else {
            let n = name.clone();
            Some(ui::button("連線", ui::Btn::Ghost, move || {
                c.send(Cmd::HubConnect(n.clone()))
            }))
        };
        let default_btn = if r.is_default {
            let c = core.clone();
            Some(ui::text_button_dyn(
                {
                    let n = name.clone();
                    move || format!("取消預設（{n}）")
                },
                move || c.send(Cmd::HubSetDefault(None)),
            ))
        } else {
            let c = core.clone();
            let n = name.clone();
            Some(ui::text_button_dyn(
                {
                    let n = n.clone();
                    move || format!("設為預設（{n}）")
                },
                move || c.send(Cmd::HubSetDefault(Some(n.clone()))),
            ))
        };
        let c = core.clone();
        let n = name.clone();
        let revoke = Some(ui::text_button_dyn(
            move || "撤銷".to_owned(),
            move || c.send(Cmd::HubRevoke(n.clone())),
        ));
        col = col.child(row_shell(
            name,
            r.url.clone(),
            Some(ago_label(r.last_seen_ms)),
            is_active,
            connect,
            default_btn,
            revoke,
        ));
    }
    if core.hub_rows.get().is_empty() {
        col = col.child(
            text("尚未配對任何跨機中樞。")
                .text_size(px(12.0))
                .text_color(theme::TEXT_MUTED),
        );
    }
    col
}

/// 一列：左名稱＋url＋見活標記，右側動作群（連線／預設／撤銷）。
fn row_shell(
    name: String,
    url: String,
    seen: Option<String>,
    active: bool,
    connect: Option<View>,
    default: Option<View>,
    revoke: Option<View>,
) -> View {
    let mut left = view()
        .flex_col()
        .gap_1()
        .flex_1()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    text(name)
                        .text_size(px(13.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY),
                )
                .child(when(
                    move || active,
                    || ui::badge("目前", theme::TEXT_ON_ACCENT, theme::ACCENT),
                )),
        )
        .child(
            text(url)
                .text_size(px(11.5))
                .font_family(ui::mono_font())
                .text_color(theme::TEXT_MUTED),
        );
    if let Some(seen) = seen {
        left = left.child(text(seen).text_size(px(11.0)).text_color(theme::TEXT_MUTED));
    }
    let mut actions = view().flex_row().items_center().gap_2();
    if let Some(v) = connect {
        actions = actions.child(v);
    }
    if let Some(v) = default {
        actions = actions.child(v);
    }
    if let Some(v) = revoke {
        actions = actions.child(v);
    }
    view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_4()
        .py_3()
        .rounded(px(theme::RADIUS_CARD))
        .border(px(1.0))
        .border_color(theme::HAIRLINE)
        .bg(theme::ELEVATED)
        .child(left)
        .child(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdd(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gui-hub-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::create_dir_all(d.join("remotes")).unwrap();
        d
    }

    /// 表格式金標（CLI `split_url` 同式）：三種輸入形態＋拒收面。
    #[test]
    fn split_url_forms_golden() {
        assert_eq!(
            split_url("https://desk.local:8443").unwrap(),
            ("desk.local".into(), 8443)
        );
        assert_eq!(
            split_url("desk.local:9000").unwrap(),
            ("desk.local".into(), 9000)
        );
        assert_eq!(
            split_url("  desk.tailnet.ts ").unwrap(),
            ("desk.tailnet.ts".into(), DEFAULT_PAIR_PORT)
        );
        assert!(split_url("https://desk.local/x").is_err());
        assert!(split_url(":8443").is_err());
        assert!(split_url("desk:notaport").is_err());
        assert!(split_url("").is_err());
    }

    #[test]
    fn profile_name_gate() {
        assert!(check_profile("desk-1_a").is_ok());
        assert!(check_profile("").is_err());
        assert!(check_profile("bad/name").is_err());
        assert!(check_profile(".default").is_err());
        assert!(check_profile(&"x".repeat(65)).is_err());
    }

    /// registry 閉環：存→列（含預設旗與見活標記）→設預設→撤銷連帶清指標。
    #[test]
    fn registry_roundtrip() {
        let d = tmpdd("rt");
        let prof = |t: &str| RemoteProfile {
            url: "https://desk.local:8443".into(),
            pin: "pin".into(),
            token: t.into(),
            wake: Some("https://ntfy/x".into()),
        };
        save(&d, "desk", &prof("t1")).unwrap();
        save(&d, "home", &prof("t2")).unwrap();
        let rows = list(&d);
        assert_eq!(
            rows.iter().map(|r| r.profile.as_str()).collect::<Vec<_>>(),
            vec!["desk", "home"]
        );
        assert!(!rows[0].is_default);
        assert_eq!(rows[0].last_seen_ms, None, "未打見活標記");
        touch_last_ok(&d, "desk");
        assert!(list(&d)[0].last_seen_ms.is_some());
        set_default(&d, Some("home")).unwrap();
        assert_eq!(read_default(&d).as_deref(), Some("home"));
        assert!(set_default(&d, Some("ghost")).is_err());
        remove(&d, "home").unwrap();
        assert_eq!(list(&d).len(), 1);
        assert_eq!(read_default(&d), None, "預設指向被撤 profile 時一併清除");
        // wake 欄往返不失（CLI 寫入的欄位 GUI 必須原樣保留）
        assert_eq!(
            serde_json::to_string(&load(&d, "desk").unwrap().wake).unwrap(),
            "\"https://ntfy/x\""
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 檔案契約：CLI `pair join` 落檔形態（含缺 wake）必須直接讀得動。
    #[test]
    fn cli_written_file_parses() {
        let d = tmpdd("cli");
        std::fs::write(
            d.join("remotes/desk.json"),
            br#"{"url":"https://127.0.0.1:18092","pin":"aaa","token":"tok","wake":"http://n"}"#,
        )
        .unwrap();
        std::fs::write(
            d.join("remotes/plain.json"),
            br#"{"url":"https://h:1","pin":"p","token":"t"}"#,
        )
        .unwrap();
        let p = load(&d, "desk").unwrap();
        assert_eq!(
            (p.url.as_str(), p.token.as_str()),
            ("https://127.0.0.1:18092", "tok")
        );
        assert_eq!(load(&d, "plain").unwrap().wake, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn target_and_failover_table() {
        let d = tmpdd("fo");
        save(
            &d,
            "desk",
            &RemoteProfile {
                url: "desk.local".into(),
                pin: "p".into(),
                token: "t".into(),
                wake: None,
            },
        )
        .unwrap();
        // 未設預設＝不 failover
        assert!(failover_target(&d, &Transport::Unix("/s".into())).is_none());
        set_default(&d, Some("desk")).unwrap();
        let t = failover_target(&d, &Transport::Unix("/s".into())).unwrap();
        assert_eq!(
            (t.profile.as_str(), t.host.as_str(), t.port),
            ("desk", "desk.local", DEFAULT_PAIR_PORT)
        );
        assert_eq!(t.url, "https://desk.local:8443");
        // 已是 TLS 態不再跳（防換 hub 迴圈）
        assert!(failover_target(&d, &Transport::Tls(t.clone())).is_none());
        // 預設檔損毀＝靜默不跳，原錯照報
        std::fs::write(d.join("remotes/ghost.json"), "not json").unwrap();
        set_default(&d, None).unwrap();
        std::fs::write(d.join("remotes/.default"), "ghost").unwrap();
        assert!(failover_target(&d, &Transport::Unix("/s".into())).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ago_label_bands() {
        assert_eq!(ago_label(None), "從未連線");
        assert_eq!(ago_label(Some(now_ms())), "剛剛");
        // +1s 餘量：now_ms() 兩次取值間的漂移不-cross 整分界
        assert_eq!(ago_label(Some(now_ms() - 5 * 60_000 - 1000)), "5 分鐘前");
        assert_eq!(ago_label(Some(now_ms() - 3 * 3_600_000 - 1000)), "3 小時前");
        assert_eq!(ago_label(Some(now_ms() - 2 * 86_400_000 - 1000)), "2 天前");
    }
}
