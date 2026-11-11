//! Dev 截圖器（照抄 spike/nsh-spike/src/shots.rs 的機制，env 換
//! `NSH_GUI_SHOTS`）：本機 agent 跑在 launchd `Background` session，
//! `screencapture` 無 Screen Recording 權限時回 "could not create image
//! from display"；`cacheDisplayInRect_toBitmapImageRep` 是 in-process
//! 自绘，不需 TCC。nsh-core 的 `set_timeout` 在 executor 執行緒跑
//! （非 AppKit main thread），故一切 AppKit 呼叫經 `dispatch_async` 回
//! main queue。驗證流程見 README。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nsh_core::prelude::*;

use crate::state::{AppCore, Cmd, FieldDraft, Route, SideGroup, name_is_envelope};

/// 在 AppKit main thread 上執行 `f`（macOS 限定；其餘平台直接跑）。
#[cfg(target_os = "macos")]
fn on_main(f: impl FnOnce() + 'static) {
    use std::ffi::c_void;

    unsafe extern "C" {
        // 新 SDK 把 dispatch_get_main_queue() inline 成對 `_dispatch_main_q`
        // 全域變數的參考（dispatch2 內部同款做法），函式符號已不存在。
        #[link_name = "_dispatch_main_q"]
        static MAIN_Q: c_void;
        fn dispatch_async_f(
            queue: *mut c_void,
            context: *mut c_void,
            work: Option<extern "C" fn(*mut c_void)>,
        );
    }
    extern "C" fn run(ctx: *mut c_void) {
        let f: Box<Box<dyn FnOnce()>> = unsafe { Box::from_raw(ctx as *mut Box<dyn FnOnce()>) };
        f();
    }
    let boxed: *mut c_void =
        Box::into_raw(Box::new(Box::new(f) as Box<dyn FnOnce()>)) as *mut c_void;
    unsafe { dispatch_async_f(&raw const MAIN_Q as *mut c_void, boxed, Some(run)) };
}

#[cfg(not(target_os = "macos"))]
fn on_main(f: impl FnOnce() + 'static) {
    f();
}

#[cfg(target_os = "macos")]
fn capture_now(dir: &Path, name: &'static str) {
    use nsh_platform_macos::objc2::AnyThread;
    use nsh_platform_macos::objc2::rc::Retained;
    use nsh_platform_macos::objc2::runtime::AnyObject;
    use nsh_platform_macos::objc2::{MainThreadMarker, class, msg_send};
    use nsh_platform_macos::objc2_app_kit::{
        NSApplication, NSBitmapImageFileType, NSBitmapImageRep, NSImage,
    };
    use nsh_platform_macos::objc2_foundation::{NSData, NSDictionary, NSString};

    let path = dir.join(name);
    let Some(mtm) = MainThreadMarker::new() else {
        eprintln!("bitward-gui: capture must run on the main thread ({name})");
        return;
    };
    unsafe {
        let app = NSApplication::sharedApplication(mtm);
        let Some(window) = app.windows().firstObject() else {
            eprintln!("bitward-gui: no window to capture for {name}");
            return;
        };
        let Some(view) = window.contentView() else {
            eprintln!("bitward-gui: window has no contentView for {name}");
            return;
        };
        // 只用已驗證的生成綁定：bitmapImageRepForCachingDisplayInRect → PNG；
        // 失敗退 dataWithPDFInsideRect → NSImage → TIFF → PNG（spike 同款）。
        if let Some(rep) = view.bitmapImageRepForCachingDisplayInRect(view.bounds()) {
            view.cacheDisplayInRect_toBitmapImageRep(view.bounds(), &rep);
            let props: Retained<NSDictionary<NSString, AnyObject>> =
                msg_send![class!(NSDictionary), dictionary];
            if let Some(png) =
                rep.representationUsingType_properties(NSBitmapImageFileType::PNG, &props)
                && png
                    .writeToFile_atomically(&NSString::from_str(&path.display().to_string()), true)
            {
                println!("bitward-gui: wrote {} (cache display)", path.display());
                return;
            }
        }
        let pdf = view.dataWithPDFInsideRect(view.bounds());
        let write_pdf = |ext: &str| {
            let p = path.with_extension(ext);
            let ok =
                pdf.writeToFile_atomically(&NSString::from_str(&p.display().to_string()), true);
            if ok {
                println!("bitward-gui: wrote {}", p.display());
            } else {
                eprintln!("bitward-gui: write failed {}", p.display());
            }
        };
        let Some(image) = NSImage::initWithData(NSImage::alloc(), &pdf) else {
            eprintln!("bitward-gui: PDF data is not an image for {name}, keeping PDF");
            write_pdf("pdf");
            return;
        };
        let Some(tiff) = image.TIFFRepresentation() else {
            eprintln!("bitward-gui: no TIFF rep for {name}, keeping PDF");
            write_pdf("pdf");
            return;
        };
        let Some(rep) = NSBitmapImageRep::imageRepWithData(&tiff) else {
            eprintln!("bitward-gui: no bitmap rep for {name}, keeping PDF");
            write_pdf("pdf");
            return;
        };
        let props: Retained<NSDictionary<NSString, AnyObject>> =
            msg_send![class!(NSDictionary), dictionary];
        let png: Option<Retained<NSData>> =
            rep.representationUsingType_properties(NSBitmapImageFileType::PNG, &props);
        match png {
            Some(png)
                if png.writeToFile_atomically(
                    &NSString::from_str(&path.display().to_string()),
                    true,
                ) =>
            {
                println!("bitward-gui: wrote {}", path.display());
            }
            _ => {
                eprintln!("bitward-gui: PNG encode failed for {name}, keeping PDF");
                write_pdf("pdf");
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn capture_now(dir: &Path, name: &'static str) {
    let _ = (dir, name);
}

fn capture(dir: &Path, name: &'static str) {
    let dir = dir.to_path_buf();
    on_main(move || capture_now(&dir, name));
}

fn at(ms: u64, f: impl FnOnce() + 'static) {
    set_timeout(Duration::from_millis(ms), f);
}

/// 收尾：AppKit main thread 上結束行程（非 macOS 直接 exit）。
fn quit() {
    on_main(|| {
        #[cfg(target_os = "macos")]
        {
            use nsh_platform_macos::objc2::MainThreadMarker;
            use nsh_platform_macos::objc2_app_kit::NSApplication;
            if let Some(mtm) = MainThreadMarker::new() {
                NSApplication::sharedApplication(mtm).terminate(None);
            }
        }
        #[cfg(not(target_os = "macos"))]
        std::process::exit(0);
    });
}

/// 徽章收斂證據流（`NSH_GUI_SHOTS_DRAIN`）：VW 停機下建項目（徽章掛上＝
/// shot-24）→ 外部腳本重啟 VW → 背景推送收斂發 `OutboxDrained` → 事件幫浦
/// 自動重抓列表（零按鈕）→ 徽章消失＝shot-25。90 秒未收斂即斷言失敗。
pub fn script_drain(dir: PathBuf, core: AppCore) {
    let c = core.clone();
    at(2600, move || c.send(Cmd::OpenCreate));
    let c = core.clone();
    at(3000, move || {
        c.form.name.set("Drain 徽章驗證".into());
        // 帶密碼欄：純名稱 Login 的 cipher 不帶 login 物件，VW 回 400
        // "Data missing"（daemon encrypt_draft 缺 `"login":{}`，已報 Main）。
        c.form.password.set("drain-secret-1".into());
        c.send(Cmd::SubmitForm);
    });
    let c = core.clone();
    at(4200, move || {
        c.query.set("Drain 徽章驗證".into());
        c.send(Cmd::RefetchList);
    });
    let d = dir.clone();
    let c = core.clone();
    at(5400, move || {
        let row = find_view(&c, "Drain 徽章驗證");
        assert!(
            row.is_some_and(|v| v.meta.pending),
            "shot-24 前提：新建項目應掛未同步徽章（確認 VW 已停）"
        );
        capture(&d, "shot-24-badge-pending.png");
    });
    poll_drained(dir, core, 7000);
}

fn poll_drained(dir: PathBuf, core: AppCore, ms: u64) {
    let d = dir.clone();
    let c = core.clone();
    at(ms, move || {
        let cleared = find_view(&c, "Drain 徽章驗證").is_some_and(|v| !v.meta.pending);
        if cleared {
            capture(&d, "shot-25-badge-cleared.png");
            println!("bitward-gui: badge auto-cleared at {ms}ms (event-driven)");
            at(ms + 800, quit);
        } else if ms < 95000 {
            poll_drained(dir, core, ms + 2000);
        } else {
            panic!("90 秒內未同步徽章未收斂：OutboxDrained 事件路徑失效？");
        }
    });
}

/// 登入卡驗收流（`NSH_GUI_SHOTS_LOGIN`，批次 8）：前提＝daemon 為 SignedOut
/// （gui-login.sh 起乾淨 data-dir daemon＋dev-register 只在 server 端建帳）。
/// 44 空卡（佔位提示）→ 填欄（env 帶真憑證）→ 45 填入態 → SubmitLogin →
/// 輪詢 Unlocked（登入即解鎖）→ 46 進庫＋帳號列 email → 偽造 needs_reauth
/// → 47 橫幅＋警告色帳號列 → 收復原並退出。90 秒 failsafe 硬退（斷言紅
/// 不掛驱动程序）。
pub fn script_login(dir: PathBuf, core: AppCore) {
    let server = std::env::var("BW_TEST_SERVER").unwrap_or_default();
    let email = std::env::var("BW_TEST_EMAIL").unwrap_or_default();
    let pw = std::env::var("BW_TEST_PASSWORD").unwrap_or_default();
    let c = core.clone();
    let d = dir.clone();
    at(3000, move || {
        assert!(
            matches!(c.vault.get(), Some(bw_proto::UnlockStateView::SignedOut)),
            "登入流前提＝daemon SignedOut，實際：{:?}",
            c.vault.get()
        );
        capture(&d, "shot-44-login-card.png");
    });
    let c = core.clone();
    at(3600, move || {
        c.login.server.set(server);
        c.login.email.set(email);
        c.login.password.set(pw);
    });
    let d = dir.clone();
    at(4200, move || capture(&d, "shot-45-login-filled.png"));
    let c = core.clone();
    at(4600, move || c.send(Cmd::SubmitLogin));
    poll_unlocked(dir, core, 6000);
    at(90000, || {
        eprintln!("bitward-gui: login e2e 90 秒未完成（掛在輪詢？）");
        std::process::exit(1);
    });
}

fn poll_unlocked(dir: PathBuf, core: AppCore, ms: u64) {
    let d = dir.clone();
    let c = core.clone();
    at(ms, move || {
        if !matches!(c.vault.get(), Some(bw_proto::UnlockStateView::Unlocked { .. })) {
            if ms < 60000 {
                poll_unlocked(dir, core, ms + 1000);
            }
            return;
        }
        // 登入成功回包應回填帳號列 email（Status 寬容欄實測）。
        let email_ok = c.acct_email.get().is_some();
        capture(&d, "shot-46-vault-after-login.png");
        let c2 = core.clone();
        at(ms + 1200, move || c2.needs_reauth.set(true));
        let d2 = dir.clone();
        let c3 = core.clone();
        at(ms + 2200, move || {
            assert!(c3.needs_reauth.get());
            capture(&d2, "shot-47-reauth-banner.png");
        });
        at(ms + 2800, move || {
            assert!(email_ok, "登入成功後帳號列應回填 email（status 資訊）");
        });
        at(ms + 3200, quit);
    });
}

/// base32（RFC 4648 無填充变體；VW 的 TOTP secret 形態）。
fn base32_decode(input: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for ch in input.bytes() {
        let ch = ch.to_ascii_uppercase() as char;
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let idx = alphabet.iter().position(|a| *a as char == ch).expect("base32 字元");
        acc = (acc << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// 視窗當前的 RFC 6238 TOTP（6 碼/30s/SHA1，同 Bitwarden 客户端）。填入時刻
/// 現算而非 env 預計算：nsh 啟動時間不定，預計算碼會撞過期邊界。
fn totp_now(secret_base32: &str) -> String {
    use hmac::{Hmac, Mac};
    let key = base32_decode(secret_base32);
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).expect("hmac 接受任意鍵長");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[off] & 0x7f) as u32) << 24
        | (h[off + 1] as u32) << 16
        | (h[off + 2] as u32) << 8
        | h[off + 3] as u32;
    format!("{:06}", bin % 1_000_000)
}

/// 2FA 登入卡驗收流（`NSH_GUI_SHOTS_LOGIN2FA`）：前提同 script_login（乾淨
/// daemon SignedOut）＋帳號已開 Authenticator 2FA（login2fa.sh 經 VW API 開）。
/// 填三欄 → SubmitLogin → 輪詢 providers 訊號（第二步態）→ 48 因子清單 →
/// 現算當窗碼填欄 → SubmitLogin2fa → 輪詢 Unlocked＋鏡像非空 → 49 進庫。
/// 碼錯/超時走斷言紅＋90s 硬退。
pub fn script_login2fa(dir: PathBuf, core: AppCore) {
    let server = std::env::var("BW_TEST_SERVER").unwrap_or_default();
    let email = std::env::var("BW_TEST_EMAIL").unwrap_or_default();
    let pw = std::env::var("BW_TEST_PASSWORD").unwrap_or_default();
    let secret = std::env::var("BW_TEST_TOTP_SECRET").unwrap_or_default();
    assert!(!secret.is_empty(), "BW_TEST_TOTP_SECRET 必要");
    let c = core.clone();
    at(3000, move || {
        assert!(
            matches!(c.vault.get(), Some(bw_proto::UnlockStateView::SignedOut)),
            "2FA 登入流前提＝daemon SignedOut，實際：{:?}",
            c.vault.get()
        );
        c.login.server.set(server);
        c.login.email.set(email);
        c.login.password.set(pw);
    });
    let c = core.clone();
    at(3800, move || c.send(Cmd::SubmitLogin));
    poll_2fa_step(dir, core, 5000, secret);
    at(90000, || {
        eprintln!("bitward-gui: 2fa login e2e 90 秒未完成（掛在輪詢？）");
        std::process::exit(1);
    });
}

fn poll_2fa_step(dir: PathBuf, core: AppCore, ms: u64, secret: String) {
    let d = dir.clone();
    let c = core.clone();
    at(ms, move || {
        let Some(providers) = c.login.providers.get() else {
            if ms < 60000 {
                poll_2fa_step(dir, core, ms + 1000, secret);
            }
            return;
        };
        assert!(
            providers.iter().any(|p| p.provider == 0),
            "第二步應列出 Authenticator（0），實際：{providers:?}"
        );
        assert_eq!(c.login.provider.get(), 0, "預選應落在首個支援因子");
        capture(&d, "shot-48-login-2fa-step.png");
        c.login.code.set(totp_now(&secret));
        c.send(Cmd::SubmitLogin2fa);
        poll_2fa_unlocked(dir, core, ms + 2000);
    });
}

fn poll_2fa_unlocked(dir: PathBuf, core: AppCore, ms: u64) {
    let d = dir.clone();
    let c = core.clone();
    at(ms, move || {
        let unlocked = matches!(c.vault.get(), Some(bw_proto::UnlockStateView::Unlocked { .. }));
        if !unlocked || c.items.get().is_empty() {
            if ms < 80000 {
                poll_2fa_unlocked(dir, core, ms + 1000);
            }
            return;
        }
        let err_open = c.login.error.get();
        assert!(
            err_open.is_none(),
            "2FA 登入後錯誤列應清空，實際：{err_open:?}"
        );
        capture(&d, "shot-49-vault-after-2fa.png");
        at(ms + 600, quit);
    });
}

/// 由目前列表訊號找名字完全相符的項目視圖。
fn find_view(core: &AppCore, name: &str) -> Option<bw_proto::ItemView> {
    core.items
        .get()
        .iter()
        .find(|v| v.meta.name.as_deref() == Some(name))
        .cloned()
}

/// 開窗後依序跑完整驗收流：列表全量（密度證據）→ 搜尋 → 詳情遮罩 → revealed → 新增表單
/// 模態 → 提交新增 → 編輯改名 → 刪除確認（先取消斷言、再確認）→
/// 匯出確認 → 鎖態頁/解鎖 → 選取態 → 垃圾桶（列表/還原動作/還原後列表）→
/// 產生器面板 → TOTP 倒數三段（真取碼後偽造時間源示 30/10/5 秒比例）→
/// 資料夾樹歸屬過濾 → SecureNote 模態 → 自訂欄位編輯列 →
/// 匯入模態（預覽/真跑/結果列）→ 編輯欄位解鎖（text→boolean、增刪列、
/// 開關樣落地）→ 附件生命週期（上傳確認/收斂在列/下載落地/刪除確認）→
/// 批准佇列（gated session 造真 pending：41 佇列有筆＋時間欄斷言、42 批准後
/// 清空＋徽章消失）→ 髒退出閘（編輯器弄髒被導航攔下走確認框，shot-43，
/// 拒絕留 edit、確認放棄完成重投）→ 已封存視角（封存→主列表消失→視角帶時間可見→
/// 取消回主列表，shot-52）→ favicon 實圖（GitHub 測試詳情＋列表圖示磚，shot-53）→ 產生器兩幀（編輯態產生面板展開 shot-54、獨立產生器頁 shot-55）→
/// 暗色皮自查三張（列表/詳情/新增器，SetTheme(Dark) 即時翻轉不重建視窗），
/// 各步存一張 shot-N-*.png 後結束行程。時序裕量對齊
/// spike（Background
/// session 無 vsync 可等，固定 sleep；本地 daemon 往返 <50ms）。
/// 詳情目標用驗收種子項目「GitHub 測試」，找不到退回第一筆。
pub fn script(dir: PathBuf, core: AppCore) {
    // 主流截圖釘選淺色皮（機器可能處在暗色系統外觀，跟隨系統會讓證據集
    // 隨環境漂移）；38–40 再明確切 Dark 做暗色自查，收尾復原 System。
    let c = core.clone();
    at(500, move || c.send(Cmd::SetTheme(Appearance::Light)));
    let d = dir.clone();
    at(1800, move || capture(&d, "shot-1-list.png"));
    let c = core.clone();
    at(2200, move || {
        c.query.set("GitHub".into());
        c.send(Cmd::RefetchList);
    });
    let c = core.clone();
    at(3200, move || {
        if let Some(id) = find_id(&c, "GitHub 測試") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let d = dir.clone();
    at(4200, move || capture(&d, "shot-2-detail-masked.png"));
    let c = core.clone();
    at(4500, move || {
        c.send(Cmd::RequestReveal);
        // 複製鈕同路徑的剪貼簿環境呼叫（e2e 側探針：不能炸）。
        set_clipboard("bitward-gui-e2e-clipboard-probe");
    });
    let d = dir.clone();
    at(5700, move || capture(&d, "shot-3-detail-revealed.png"));
    let c = core.clone();
    at(6000, move || c.send(Cmd::OpenCreate));
    let c = core.clone();
    at(6300, move || {
        // 表單回聲走訊號（與打字同路徑）。
        c.form.name.set("範例網站".into());
        c.form.username.set("me@example.com".into());
        c.form.password.set("s3cret-範例".into());
        c.form.uris.set(std::sync::Arc::new(vec![
            crate::state::UriDraft {
                key: crate::state::NEW_URI,
                uri: "https://example.com".into(),
                match_type: None,
            },
            crate::state::UriDraft {
                key: crate::state::NEW_URI.wrapping_sub(1),
                uri: "https://backup.example.com".into(),
                match_type: None,
            },
        ]));
        c.form.tags.set("dev, 工作".into());
    });
    let d = dir.clone();
    at(6900, move || capture(&d, "shot-4-create-form.png"));

    // —— 真送新增（Vault:Create + Overlay AddTag）——
    let c = core.clone();
    at(7200, move || {
        c.form.name.set("E2E 驗證項目".into());
        c.form.tags.set("dev, e2e".into());
        c.send(Cmd::SubmitForm);
    });
    let c = core.clone();
    at(8300, move || {
        c.query.set("E2E 驗證".into());
        c.send(Cmd::RefetchList);
    });
    let d = dir.clone();
    at(9100, move || capture(&d, "shot-5-created.png"));

    // —— 詳情 + TOTP 錯誤路徑（此項無 seed，daemon 裁決、banner 顯示）——
    let c = core.clone();
    at(9300, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    // 批次 A＃3：無 seed 項目——進詳情自動取碼被 daemon 回「沒有 TOTP seed」，
    // 驗證碼節整節不渲染（手動 RequestTotp 已退役；此處斷言缺席態）。
    let c = core.clone();
    at(10900, move || {
        assert!(
            c.totp.get().is_none() && c.totp_error.get().is_none(),
            "無 seed 項目：取碼應靜默缺席（totp 與 totp_error 皆 None）"
        );
    });
    let d = dir.clone();
    at(11000, move || capture(&d, "shot-6-totp-absent.png"));

    // —— 排序下拉與標籤 chips（標籤已改 chips 行：選中描邊即證據）——
    let c = core.clone();
    at(11100, move || {
        c.send(Cmd::OpenList);
        c.send(Cmd::ToggleSortMenu);
    });
    let d = dir.clone();
    at(11700, move || capture(&d, "shot-7-sort-menu.png"));
    let c = core.clone();
    at(11900, move || {
        c.send(Cmd::ToggleSortMenu);
        c.send(Cmd::ChooseTag(Some("dev".into())));
    });
    let d = dir.clone();
    at(12500, move || capture(&d, "shot-8-tag-menu.png"));
    let c = core.clone();
    at(12700, move || c.send(Cmd::ChooseTag(None)));

    // —— 編輯改名（Vault:Patch）＋morph 同骨架對比（批次 A＃2）——
    // 先拍查看態（同項目、同節序幾何），OpenEdit 後拍編輯態＝零跳動證據。
    let c = core.clone();
    at(12900, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let d = dir.clone();
    at(13400, move || capture(&d, "shot-50-morph-view.png"));
    let c = core.clone();
    at(13600, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目") {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let d = dir.clone();
    at(14300, move || capture(&d, "shot-51-morph-edit.png"));
    let c = core.clone();
    at(14500, move || c.form.name.set("E2E 驗證項目改名".into()));
    let c = core.clone();
    at(14700, move || c.send(Cmd::SubmitForm));
    let d = dir.clone();
    at(15400, move || capture(&d, "shot-9-edited.png"));

    // —— 刪除確認框：先取消（斷言未刪）再yes走 Vault:Delete ——
    let c = core.clone();
    at(14800, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目改名") {
            c.send(Cmd::AskDelete(id));
        }
    });
    let d = dir.clone();
    at(15300, move || capture(&d, "shot-10-delete-confirm.png"));
    let c = core.clone();
    at(15600, move || c.send(Cmd::ConfirmNo));
    let c = core.clone();
    at(16000, move || {
        let kept = find_id(&c, "E2E 驗證項目改名").is_some();
        println!("bitward-gui: delete-cancel kept item = {kept}");
        assert!(kept, "取消刪除後項目應仍在");
    });
    let c = core.clone();
    at(16200, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目改名") {
            c.send(Cmd::AskDelete(id));
        }
    });
    let c = core.clone();
    at(16500, move || c.send(Cmd::ConfirmYes));
    let d = dir.clone();
    at(17600, move || capture(&d, "shot-11-after-delete.png"));

    // —— 鎖態指示 + 解鎖鈕（Auth:Lock → 按鈕 → Auth:Unlock）——
    let c = core.clone();
    at(17800, move || c.send(Cmd::RequestLock));
    let d = dir.clone();
    at(19600, move || capture(&d, "shot-12-locked.png"));
    let c = core.clone();
    at(20100, move || c.send(Cmd::RequestUnlock));
    let d = dir.clone();
    at(21900, move || capture(&d, "shot-13-unlocked.png"));

    // —— 匯出：確認框（未加密提醒）→ 逐筆 Reveal → 落盤 ——
    let c = core.clone();
    at(22300, move || c.send(Cmd::AskExport));
    let d = dir.clone();
    at(22900, move || capture(&d, "shot-14-export-confirm.png"));
    let c = core.clone();
    at(23300, move || c.send(Cmd::ConfirmYes));
    let d = dir.clone();
    at(25500, move || capture(&d, "shot-15-export-done.png"));

    // —— 選取態：清搜尋、開詳情，證據為選中列提亮＋左 3px accent 條 ——
    let c = core.clone();
    at(25900, move || {
        c.query.set(String::new());
        c.send(Cmd::RefetchList);
    });
    let c = core.clone();
    at(26300, move || {
        if let Some(id) = find_id(&c, "GitHub 測試") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let d = dir.clone();
    at(27200, move || capture(&d, "shot-16-selected.png"));

    // —— 垃圾桶：進入（軟刪條目＋刪除時間）→ 詳情還原/永久刪除 → 還原回列表 ——
    let c = core.clone();
    at(28200, move || c.send(Cmd::ToggleTrash));
    let d = dir.clone();
    at(29000, move || capture(&d, "shot-17-trash.png"));
    let c = core.clone();
    at(29400, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目改名") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let d = dir.clone();
    at(30200, move || capture(&d, "shot-18-trash-restore.png"));
    let c = core.clone();
    at(30600, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目改名") {
            c.send(Cmd::RestoreItem(id));
        }
    });
    let c = core.clone();
    at(31600, move || c.send(Cmd::ToggleTrash));
    let d = dir.clone();
    at(32400, move || capture(&d, "shot-19-restored.png"));

    // —— 產生器：模態展開面板＋真送 Use:GeneratePassword 取草稿 ——
    let c = core.clone();
    at(33000, move || c.send(Cmd::OpenCreate));
    let c = core.clone();
    at(33400, move || {
        c.form.gen_panel.update(|g| g.open = true);
        c.send(Cmd::GeneratePassword);
    });
    let d = dir.clone();
    at(34400, move || capture(&d, "shot-20-generator.png"));

    // —— TOTP 倒數三段：真取碼（Local OTP 有 seed）＋偽造時間源示比例 ——
    let c = core.clone();
    at(34800, move || {
        c.send(Cmd::OpenList);
        if let Some(id) = find_id(&c, "Local OTP") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let c = core.clone();
    at(35600, move || c.send(Cmd::RequestTotp));
    let c = core.clone();
    at(36600, move || {
        c.totp_valid_for.set(30);
        c.totp_issued.set(Some(Instant::now()));
    });
    let d = dir.clone();
    at(36800, move || capture(&d, "shot-21-totp-30s.png"));
    let c = core.clone();
    at(37200, move || {
        c.totp_valid_for.set(30);
        c.totp_issued.set(Some(Instant::now() - Duration::from_secs(20)));
    });
    let d = dir.clone();
    at(37400, move || capture(&d, "shot-22-totp-10s.png"));
    let c = core.clone();
    at(37800, move || {
        c.totp_valid_for.set(30);
        c.totp_issued.set(Some(Instant::now() - Duration::from_secs(25)));
    });
    let d = dir.clone();
    at(38000, move || capture(&d, "shot-23-totp-5s.png"));

    // —— 資料夾樹：把「GitHub 測試」歸入工作資料夾 → 過濾態 ——
    let c = core.clone();
    at(39000, move || {
        if let Some(id) = find_id(&c, "GitHub 測試") {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let c = core.clone();
    at(39800, move || {
        let fid = folder_id_by_name(&c, "工作資料夾");
        if !fid.is_empty() {
            c.form.folder_id.set(fid);
        }
    });
    // 批次 9：編輯態產生器——morph 密碼欄的「產生」鈕接回面板（共用元件），
    // 展開＋現算草稿＝shot-54。
    let c = core.clone();
    at(40200, move || {
        c.form.gen_panel.update(|g| g.open = true);
        c.send(Cmd::GeneratePassword);
    });
    let d = dir.clone();
    at(40700, move || capture(&d, "shot-54-edit-generator.png"));
    let c = core.clone();
    at(41000, move || c.send(Cmd::SubmitForm));
    let c = core.clone();
    at(41400, move || {
        let fid = folder_id_by_name(&c, "工作資料夾");
        if !fid.is_empty() {
            c.send(Cmd::ChooseFolder(Some(fid)));
        }
    });
    let d = dir.clone();
    at(41800, move || capture(&d, "shot-26-folder-tree.png"));

    // —— SecureNote 模態：帳密收合、備註大欄 ——
    let c = core.clone();
    at(42200, move || c.send(Cmd::OpenCreate));
    let c = core.clone();
    at(42600, move || {
        c.form.kind.set(bw_proto::ItemKind::SecureNote);
        c.form.name.set("2b 筆記範例".into());
        c.form.notes.set("加密筆記內文：明文只進 Outgoing 幀。".into());
    });
    let d = dir.clone();
    at(43200, move || capture(&d, "shot-27-securenote-modal.png"));

    // —— 自訂欄位編輯列：切回登入、加一文字一隱藏欄 ——
    let c = core.clone();
    at(43600, move || {
        c.form.kind.set(bw_proto::ItemKind::Login);
        c.form.fields.set(std::sync::Arc::new(vec![
            FieldDraft {
                key: 1,
                name: "API Key".into(),
                value: "sk-demo-42".into(),
                kind: bw_proto::CipherFieldKind::Text,
            },
            FieldDraft {
                key: 2,
                name: "復原碼".into(),
                value: "rc-7788".into(),
                kind: bw_proto::CipherFieldKind::Hidden,
            },
        ]));
    });
    let d = dir.clone();
    at(44200, move || capture(&d, "shot-28-custom-fields.png"));
    let c = core.clone();
    at(44600, move || c.send(Cmd::SubmitForm));

    // —— 編輯模式欄位解鎖（批次 3）：text→boolean 拍板 ——
    // 先退出資料夾過濾（2b 筆記範例無資料夾，在過濾態下不可見）。
    let c = core.clone();
    at(45000, move || c.send(Cmd::ChooseFolder(None)));
    let c = core.clone();
    at(45600, move || {
        if let Some(id) = find_id(&c, "2b 筆記範例") {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let c = core.clone();
    at(46400, move || {
        c.form.fields.update(|v| {
            if let Some(f) = std::sync::Arc::make_mut(v).first_mut() {
                f.set_kind(bw_proto::CipherFieldKind::Boolean);
                f.value = "true".into();
            }
        });
    });
    let d = dir.clone();
    at(46800, move || capture(&d, "shot-31-edit-field-type.png"));
    // 增一欄、刪一欄（復原碼移除、配對碼追加）。
    let c = core.clone();
    at(47000, move || {
        c.form.fields.update(|v| {
            let list = std::sync::Arc::make_mut(v);
            if list.len() > 1 {
                list.remove(1);
            }
            list.push(FieldDraft {
                key: 99,
                name: "配對碼".into(),
                value: "pair-1".into(),
                kind: bw_proto::CipherFieldKind::Text,
            });
        });
    });
    let d = dir.clone();
    at(47400, move || capture(&d, "shot-32-edit-add-remove.png"));
    let c = core.clone();
    at(47600, move || c.send(Cmd::SubmitForm));
    let d = dir.clone();
    at(48800, move || capture(&d, "shot-33-edit-fields-applied.png"));

    // —— 匯入模態：fixture 預覽 → 真跑（批次 3：單交易 Import）→ 結果列 ——
    let fixture = std::env::temp_dir().join("bitward-gui-import-sample.json");
    let _ = std::fs::write(
        &fixture,
        r#"[{"name":"匯入示範 A","username":"ia@example.com","password":"imp-a-1","uri":"https://imp-a.test","tags":["e2e"]},{"name":"匯入示範 B","username":"ib@example.com","password":null,"uri":null,"tags":[]},{"name":"","username":"skipme"}]"#,
    );
    let c = core.clone();
    at(49800, move || c.send(Cmd::OpenImport));
    let c = core.clone();
    let fx = fixture.display().to_string();
    at(50200, move || {
        c.import_path.set(fx);
        c.send(Cmd::ImportPreview);
    });
    let d = dir.clone();
    at(51000, move || capture(&d, "shot-29-import-modal.png"));
    let c = core.clone();
    at(51400, move || c.send(Cmd::ImportRun));
    let c = core.clone();
    at(53000, move || {
        let n = c.notice.get().unwrap_or_default();
        println!("bitward-gui: import result = {n}");
        assert!(n.contains("已匯入 2 筆"), "匯入執行結果列應為已匯入 2 筆：{n}");
    });
    let c = core.clone();
    at(53200, move || c.send(Cmd::ChooseFolder(None)));
    let c = core.clone();
    at(53400, move || {
        c.query.set("匯入示範".into());
        c.send(Cmd::RefetchList);
    });
    let d = dir.clone();
    at(54200, move || capture(&d, "shot-30-import-result.png"));

    // —— 附件生命週期（批次 4b）：上傳確認 → 收斂後在列 → 下載 → 刪除確認 ——
    let attach_file = std::env::temp_dir().join("bitward-attach-sample.txt");
    let _ = std::fs::write(&attach_file, b"bitward gui attachment e2e payload 0123456789\n");
    let c = core.clone();
    at(55000, move || {
        c.query.set(String::new());
        c.send(Cmd::RefetchList);
    });
    let c = core.clone();
    at(55400, move || {
        if let Some(id) = find_id(&c, "2b 筆記範例") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let c = core.clone();
    let fx = attach_file.display().to_string();
    at(56000, move || {
        c.att_upload_path.set(fx.clone());
        c.att_upload_open.set(true);
    });
    let d = dir.clone();
    at(56400, move || capture(&d, "shot-34-attachment-upload.png"));
    let c = core.clone();
    let fx = attach_file.display().to_string();
    at(56600, move || {
        if let Some(id) = find_id(&c, "2b 筆記範例") {
            c.send(Cmd::UploadAttachment {
                item_id: id,
                path: fx.clone(),
            });
        }
    });
    let c = core.clone();
    at(57200, move || {
        let n = c.notice.get().unwrap_or_default();
        assert!(n.contains("已排隊上傳"), "上傳回執應為排隊語意：{n}");
    });
    // —— 髒退出閘（批次 7）：編輯器弄髒 → 導航被攔 → 確認框 → 留/edit、棄/nav ——
    let c = core.clone();
    at(57600, move || {
        if let Some(id) = find_id(&c, "GitHub") {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let c = core.clone();
    at(58600, move || {
        c.form.name.update(|n| n.push_str(" 髒"));
        c.send(Cmd::OpenList);
    });
    let c = core.clone();
    at(59200, move || {
        assert!(c.confirm.get().is_some(), "髒表單的導航應被確認框攔下");
        assert!(matches!(c.route.get(), Route::Edit(_)), "攔截後應仍留在編輯器");
    });
    let d = dir.clone();
    at(59600, move || capture(&d, "shot-43-dirty-guard.png"));
    let c = core.clone();
    at(60000, move || c.send(Cmd::ConfirmNo));
    let c = core.clone();
    at(60300, move || {
        assert!(
            c.confirm.get().is_none() && matches!(c.route.get(), Route::Edit(_)),
            "拒絕後應關框並留在編輯器"
        );
    });
    let c = core.clone();
    at(60600, move || c.send(Cmd::OpenList));
    let c = core.clone();
    at(60900, move || c.send(Cmd::ConfirmYes));
    let c = core.clone();
    at(61200, move || {
        assert!(matches!(c.route.get(), Route::List), "放棄編輯應完成被攔的導航");
        // —— 已封存視角（批次 C）：封存 → 主列表消失 → 節點視角可見 → 取消回主列表 ——
        if let Some(id) = find_id(&c, "E2E 驗證項目改名") {
            c.send(Cmd::SetArchived { id, archived: true });
        }
    });
    let c = core.clone();
    at(62000, move || {
        assert!(
            find_id(&c, "E2E 驗證項目改名").is_none(),
            "封存後主列表不應再見該項目"
        );
        c.send(Cmd::ToggleArchived);
    });
    let c = core.clone();
    let d = dir.clone();
    at(62900, move || {
        let row = find_view(&c, "E2E 驗證項目改名");
        assert!(
            row.as_ref().is_some_and(|v| v.meta.archived_at.is_some()),
            "已封存視角應含該項目且帶封存時間"
        );
        // 投影紀律（同批次 12 daemon 修復）：封存視角每一列名稱都得是
        // 回填明文（或鎖定態 null），不得是信封字串。
        for r in c.items.get().iter() {
            assert!(
                !r.meta.name.as_deref().is_some_and(name_is_envelope),
                "已封存視角名稱未回填明文：{:?}",
                r.meta.name
            );
        }
        capture(&d, "shot-52-archived-view.png");
        if let Some(id) = row.map(|v| v.meta.id) {
            c.send(Cmd::SetArchived { id, archived: false });
        }
    });
    let c = core.clone();
    at(63800, move || {
        c.send(Cmd::ToggleArchived);
    });
    let c = core.clone();
    at(64500, move || {
        assert!(
            find_id(&c, "E2E 驗證項目改名").is_some(),
            "取消封存應回到主列表"
        );
        if let Some(id) = find_id(&c, "2b 筆記範例") {
            c.send(Cmd::OpenDetail(id));
        }
    });
    // 附件列要等背景推送收斂（drain tick 5s＋推送＋VaultChanged 重取），
    // 用輪詢取代死時間：出現即拍，40 秒未現即斷言失敗。
    poll_attachment_row(dir, core, 66600);
}

/// 輪詢詳情附件列收斂；出現後串接下載→刪除確認→收尾。
fn poll_attachment_row(dir: PathBuf, core: AppCore, ms: u64) {
    let c = core.clone();
    at(ms, move || {
        let Some(dv) = c.detail.get() else {
            return;
        };
        let Some(att) = dv.attachments.first().cloned() else {
            if ms < 98000 {
                poll_attachment_row(dir, core, ms + 2000);
            } else {
                panic!("背景推送收斂後附件列仍未出現（VaultChanged 事件重取失效？）");
            }
            return;
        };
        let id = dv.meta.id;
        let att_dl = att.clone();
        // 發現與截圖錯開一拍：讓 dynamic 分節完成重繪再拍。
        let d1 = dir.clone();
        at(ms + 600, move || capture(&d1, "shot-35-attachment-row.png"));
        let c2 = core.clone();
        at(ms + 800, move || {
            c2.send(Cmd::DownloadAttachment {
                item_id: id,
                attachment_id: att_dl.id.clone(),
                file_name: att_dl.file_name.clone(),
            })
        });
        let d2 = dir.clone();
        at(ms + 2000, move || capture(&d2, "shot-36-attachment-downloaded.png"));
        let c3 = core.clone();
        let att3 = att;
        at(ms + 2400, move || {
            c3.send(Cmd::AskDeleteAttachment {
                item_id: id,
                attachment_id: att3.id.clone(),
                file_name: att3.file_name.clone(),
            })
        });
        let d3 = dir.clone();
        at(ms + 3000, move || capture(&d3, "shot-37-attachment-delete-confirm.png"));
        let c4 = core.clone();
        at(ms + 3400, move || c4.send(Cmd::ConfirmYes));
        // —— 批准佇列（批次 6）：gated device session 造一筆真 pending ——
        let c5 = core.clone();
        at(ms + 4200, move || spawn_gated_pending(&c5));
        let c6 = core.clone();
        at(ms + 5400, move || c6.send(Cmd::OpenApprovals));
        let c7 = core.clone();
        let d1 = dir.clone();
        at(ms + 6400, move || {
            let p = c7.pending.get();
            assert!(!p.is_empty(), "gated session 應造出一筆真 pending");
            // 時間欄斷言（DataModel 補 requested_at_ms 後生效）：合理 epoch。
            let t = p[0]
                .requested_at_ms
                .expect("pending 應帶 requested_at_ms");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default();
            assert!(
                t <= now && now - t < 5 * 60 * 1000,
                "請求時間應在近 5 分鐘內：{t}（now {now}）"
            );
            capture(&d1, "shot-41-approvals-queue.png");
        });
        let c8 = core.clone();
        at(ms + 6800, move || {
            if let Some(row) = c8.pending.get().first() {
                let id = row.id.clone();
                c8.send(Cmd::ApprovePending(id));
            }
        });
        let c9 = core.clone();
        let d2 = dir.clone();
        at(ms + 8200, move || {
            assert!(c9.pending.get().is_empty(), "批准後佇列應清空、徽章消失");
            capture(&d2, "shot-42-approvals-cleared.png");
        });
        // —— favicon 實圖幀（批次 C）：清單早已請求並快取 icons，開詳情作证 ——
        let c10 = core.clone();
        at(ms + 8600, move || {
            c10.send(Cmd::OpenList);
            if let Some(id) = find_id(&c10, "GitHub 測試") {
                c10.send(Cmd::OpenDetail(id));
            }
        });
        let df = dir.clone();
        at(ms + 9300, move || capture(&df, "shot-53-favicon.png"));
        // 批次 10 防閃斷言：強制兩次列表刷新，GetIcon 發送數不得增加
        // （同 host 已在 Loading/Ready/Failed 任態＝不重發；榜等值不重建）。
        let probe = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let c = core.clone();
        let p1 = probe.clone();
        at(ms + 9500, move || {
            p1.set(c.icon_sent.get());
            c.send(Cmd::RefetchList);
        });
        let c = core.clone();
        at(ms + 10100, move || {
            c.send(Cmd::RefetchList);
        });
        let c = core.clone();
        let p2 = probe.clone();
        at(ms + 10700, move || {
            assert_eq!(
                c.icon_sent.get(),
                p2.get(),
                "列表刷新不得重發任何已快取 host 的 GetIcon"
            );
        });
        // —— 側欄資訊架構（批次 12：按 kind 分組）：默認態三組全開 →
        //    收合「工具／系統」→ 展開回預設 → 設定頁含搬入項目 ——
        let c = core.clone();
        let d = dir.clone();
        at(ms + 11000, move || {
            let fold = c.sidebar_fold.get();
            assert!(
                !fold.collapsed(SideGroup::Tools) && !fold.collapsed(SideGroup::System),
                "默認態＝工具／系統全開（700px 窗實測定的預設）"
            );
            capture(&d, "shot-56-sidebar-groups.png");
        });
        let c = core.clone();
        at(ms + 11200, move || {
            c.send(Cmd::ToggleSidebarGroup(SideGroup::Tools));
            c.send(Cmd::ToggleSidebarGroup(SideGroup::System));
        });
        let c = core.clone();
        let d = dir.clone();
        at(ms + 11500, move || {
            let fold = c.sidebar_fold.get();
            assert!(
                fold.collapsed(SideGroup::Tools) && fold.collapsed(SideGroup::System),
                "組標題點擊應翻轉兩組收合態（庫視圖恆常駐）"
            );
            assert!(!fold.collapsed(SideGroup::Vault), "庫視圖不得被收合");
            capture(&d, "shot-58-sidebar-folded.png");
        });
        let c = core.clone();
        at(ms + 11700, move || {
            c.send(Cmd::ToggleSidebarGroup(SideGroup::Tools));
            c.send(Cmd::ToggleSidebarGroup(SideGroup::System));
            c.send(Cmd::OpenSettings);
        });
        let d = dir.clone();
        at(ms + 12100, move || capture(&d, "shot-57-settings-tools.png"));
        // —— 產生器頁（批次 9）：進頁自動現算一碼 ——
        let cg = core.clone();
        at(ms + 9700, move || cg.send(Cmd::OpenGenerator));
        let dg = dir.clone();
        at(ms + 10500, move || capture(&dg, "shot-55-generator-page.png"));
        // —— 暗色皮自查三張（列表／詳情／新增器）；收尾復原 system 預設 ——
        let c11 = core.clone();
        at(ms + 12500, move || {
            c11.send(Cmd::SetTheme(Appearance::Dark));
            c11.send(Cmd::OpenList);
        });
        let d3 = dir.clone();
        at(ms + 13100, move || capture(&d3, "shot-38-dark-list.png"));
        let c12 = core.clone();
        at(ms + 13300, move || {
            if let Some(id) = find_id(&c12, "2b 筆記範例") {
                c12.send(Cmd::OpenDetail(id));
            }
        });
        let d4 = dir.clone();
        at(ms + 13900, move || capture(&d4, "shot-39-dark-detail.png"));
        let c13 = core.clone();
        at(ms + 14100, move || c13.send(Cmd::OpenCreate));
        let d5 = dir.clone();
        at(ms + 14700, move || capture(&d5, "shot-40-dark-modal.png"));
        let c14 = core.clone();
        at(ms + 15000, move || c14.send(Cmd::SetTheme(Appearance::System)));
        at(ms + 15400, quit);
    });
}

/// 實拍模式（`NSH_GUI_SHOTS_CANDID`）：真庫零寫入三連拍——主列表（favicon
/// 實圖、無封存混入）→ 已封存視角 → 詳情查看／編輯 morph 對比。只發讀取
/// 與視角切換命令，拍完即退，不動庫一筆資料。
pub fn script_cand(dir: PathBuf, core: AppCore) {
    let c = core.clone();
    let d = dir.clone();
    at(4000, move || {
        assert!(
            matches!(c.vault.get(), Some(bw_proto::UnlockStateView::Unlocked { .. })),
            "實拍前提＝常駐 daemon 解鎖態，實際：{:?}",
            c.vault.get()
        );
        capture(&d, "cand-1-mainlist.png");
    });
    let c = core.clone();
    at(4600, move || c.send(Cmd::ToggleArchived));
    let c = core.clone();
    let d2 = dir.clone();
    at(5600, move || {
        // 缺陷回歸（2026-11-11 使用者實錄）：真庫（555 筆、含經 /sync 落盤的
        // 封存項）的封存視角名稱必須是回填明文或 null，不得是信封字串。
        let rows = c.items.get();
        assert!(!rows.is_empty(), "真庫應有已封存項目可拍");
        for r in rows.iter() {
            assert!(
                r.meta.archived_at.is_some(),
                "封存視角不得混入未封存列：{:?}",
                r.meta.name
            );
            assert!(
                !r.meta.name.as_deref().is_some_and(name_is_envelope),
                "已封存視角名稱未回填明文：{:?}",
                r.meta.name
            );
        }
        capture(&d2, "cand-2-archived.png");
    });
    let c = core.clone();
    at(6200, move || c.send(Cmd::ToggleArchived));
    let c = core.clone();
    at(7600, move || {
        // 退出封存的 ListLoaded 已回（4600→6200→回包），此時才找得到主榜項目。
        let id = c
            .items
            .get()
            .iter()
            .find(|v| !v.meta.uris.is_empty() && v.meta.kind == bw_proto::ItemKind::Login)
            .map(|v| v.meta.id);
        if let Some(id) = id {
            c.send(Cmd::OpenDetail(id));
        }
    });
    let d3 = dir.clone();
    at(8800, move || capture(&d3, "cand-3-detail-view.png"));
    let c = core.clone();
    at(9200, move || {
        if let Route::Detail(id) = c.route.get() {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let d4 = dir.clone();
    at(10600, move || capture(&d4, "cand-4-detail-edit.png"));
    at(11200, quit);
    at(60000, || {
        eprintln!("bitward-gui: 實拍 60 秒未完成");
        std::process::exit(1);
    });
}

/// 造一筆真 pending：`agent open` 簽發 gated token（reveal:secret 需人工核准），
/// 再用該 token 發 gated reveal——呼叫在 daemon 阻塞等批准，ListPending 即有筆
/// （agentpath.sh 同源手法，改由截圖腳本 spawn CLI）。
fn spawn_gated_pending(core: &AppCore) {
    let Some(item) = find_id(core, "Local OTP") else {
        eprintln!("bitward-gui: 找不到 Local OTP，跳過批准 e2e");
        return;
    };
    let sock = core.session.path().display().to_string();
    let Ok(out) = std::process::Command::new("../../target/debug/bitward")
        .args([
            "--sock",
            &sock,
            "agent",
            "open",
            "--name",
            "gui-e2e-gated",
            "--grant",
            "reveal:secret all approve",
            "--ttl",
            "180",
            "--json",
        ])
        .output()
    else {
        eprintln!("bitward-gui: agent open 失敗");
        return;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        eprintln!(
            "bitward-gui: agent open 回包解析失敗：{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    };
    let Some(tok) = v.get("token").and_then(|t| t.as_str()) else {
        eprintln!("bitward-gui: agent open 缺 token");
        return;
    };
    let dir = std::env::temp_dir().join("bitward-gui-gated");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("cli_session"), tok);
    // 背景阻塞至 GUI 批准；child 由系統回收（進程結尾一起走）。
    let _ = std::process::Command::new("../../target/debug/bitward")
        .env("BITWARD_DATA_DIR", &dir)
        .args(["--sock", &sock, "reveal", &item.to_string()])
        .stdout(std::process::Stdio::null())
        .spawn();
}

/// 由資料夾鏡像找名字的 id（找不到回空字串）。
fn folder_id_by_name(core: &AppCore, name: &str) -> String {
    core.folders
        .get()
        .iter()
        .find(|f| f.name.as_deref() == Some(name))
        .map(|f| f.id.clone())
        .unwrap_or_default()
}

/// 由目前列表訊號找名字完全相符的項目 id。
fn find_id(core: &AppCore, name: &str) -> Option<bw_proto::ItemId> {
    core.items
        .get()
        .iter()
        .find(|v| v.meta.name.as_deref() == Some(name))
        .map(|v| v.meta.id)
}
