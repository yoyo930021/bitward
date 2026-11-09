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

use crate::state::{AppCore, Cmd, FieldDraft};

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
/// 匯入模態（預覽/真跑/結果列），
/// 各步存一張 shot-N-*.png 後結束行程。時序裕量對齊
/// spike（Background
/// session 無 vsync 可等，固定 sleep；本地 daemon 往返 <50ms）。
/// 詳情目標用驗收種子項目「GitHub 測試」，找不到退回第一筆。
pub fn script(dir: PathBuf, core: AppCore) {
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
        c.form.uri.set("https://example.com".into());
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
    let c = core.clone();
    at(10100, move || c.send(Cmd::RequestTotp));
    let d = dir.clone();
    at(10900, move || capture(&d, "shot-6-totp-denied.png"));

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

    // —— 編輯改名（Vault:Patch）——
    let c = core.clone();
    at(12900, move || {
        if let Some(id) = find_id(&c, "E2E 驗證項目") {
            c.send(Cmd::OpenEdit(id));
        }
    });
    let c = core.clone();
    at(13300, move || c.form.name.set("E2E 驗證項目改名".into()));
    let c = core.clone();
    at(13500, move || c.send(Cmd::SubmitForm));
    let d = dir.clone();
    at(14600, move || capture(&d, "shot-9-edited.png"));

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
            c.send(Cmd::SubmitForm);
        }
    });
    let c = core.clone();
    at(41000, move || {
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
    at(50200, move || capture(&d, "shot-30-import-result.png"));
    at(50800, quit);
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
