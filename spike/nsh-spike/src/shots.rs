//! Dev 截圖器：`NSH_SPIKE_SHOTS=<dir>` 時由 app 自己渲染視窗成 PNG。
//!
//! 存在理由：本機 agent 跑在 launchd `Background` session，`screencapture`
//! 無 Screen Recording 權限時回 "could not create image from display"；
//! `NSImage +bitmapImageCacheForView:` 是 in-process 自绘，不需 TCC。
//! nsh-core 的 `set_timeout` 在 executor 執行緒跑（非 AppKit main thread，
//! 無公開 hop API），故一切 AppKit 呼叫經 `dispatch_async` 回 main queue。
//! 僅 spike 用，正式 GUI 走真實視窗流程。

use std::path::{Path, PathBuf};
use std::time::Duration;

use nsh_core::prelude::*;

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
        eprintln!("nsh-spike: capture must run on the main thread ({name})");
        return;
    };
    unsafe {
        let app = NSApplication::sharedApplication(mtm);
        let Some(window) = app.windows().firstObject() else {
            eprintln!("nsh-spike: no window to capture for {name}");
            return;
        };
        let Some(view) = window.contentView() else {
            eprintln!("nsh-spike: window has no contentView for {name}");
            return;
        };
        // 只用已驗證的生成綁定：dataWithPDFInsideRect → NSImage → TIFF →
        // NSBitmapImageRep::imageRepWithData → PNG。兩個 class factory
        // （bitmapImageCacheForView:/bitmapImageRepWithData: 的 msg_send 版）
        // 在此 runtime 回 method not found，故避開。
        if let Some(rep) = view.bitmapImageRepForCachingDisplayInRect(view.bounds()) {
            view.cacheDisplayInRect_toBitmapImageRep(view.bounds(), &rep);
            let props: Retained<NSDictionary<NSString, AnyObject>> =
                msg_send![class!(NSDictionary), dictionary];
            if let Some(png) =
                rep.representationUsingType_properties(NSBitmapImageFileType::PNG, &props)
                && png
                    .writeToFile_atomically(&NSString::from_str(&path.display().to_string()), true)
            {
                println!("nsh-spike: wrote {} (cache display)", path.display());
                return;
            }
        }
        let pdf = view.dataWithPDFInsideRect(view.bounds());
        let write_pdf = |ext: &str| {
            let p = path.with_extension(ext);
            let ok =
                pdf.writeToFile_atomically(&NSString::from_str(&p.display().to_string()), true);
            if ok {
                println!("nsh-spike: wrote {}", p.display());
            } else {
                eprintln!("nsh-spike: write failed {}", p.display());
            }
        };
        let Some(image) = NSImage::initWithData(NSImage::alloc(), &pdf) else {
            eprintln!("nsh-spike: PDF data is not an image for {name}, keeping PDF");
            write_pdf("pdf");
            return;
        };
        let Some(tiff) = image.TIFFRepresentation() else {
            eprintln!("nsh-spike: no TIFF rep for {name}, keeping PDF");
            write_pdf("pdf");
            return;
        };
        let Some(rep) = NSBitmapImageRep::imageRepWithData(&tiff) else {
            eprintln!("nsh-spike: no bitmap rep for {name}, keeping PDF");
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
                println!("nsh-spike: wrote {}", path.display());
            }
            _ => {
                eprintln!("nsh-spike: PNG encode failed for {name}, keeping PDF");
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

/// 開窗後依序：providers → vault 列表 → 第一筆詳情，各存一張 shot-N.png，
/// 然後結束行程（dev host 隨之收尾）。
pub fn script(
    dir: PathBuf,
    screen: Signal<crate::Screen>,
    selected: Signal<Option<bw_proto::ItemId>>,
    detail: Option<bw_proto::ItemId>,
) {
    let d = dir.clone();
    set_timeout(Duration::from_millis(2200), move || {
        capture(&d, "shot-1.png")
    });
    let s = screen;
    set_timeout(Duration::from_millis(2800), move || {
        s.set(crate::Screen::Vault)
    });
    let d = dir.clone();
    set_timeout(Duration::from_millis(3800), move || {
        capture(&d, "shot-2.png")
    });
    let sel = selected;
    set_timeout(Duration::from_millis(4400), move || {
        if let Some(id) = detail {
            sel.set(Some(id));
        }
    });
    let d = dir.clone();
    set_timeout(Duration::from_millis(5400), move || {
        capture(&d, "shot-3.png")
    });
    set_timeout(Duration::from_millis(6000), move || {
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
    });
}
