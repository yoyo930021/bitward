//! 桌機 dev 迴圈：`cargo run` 直接在本機原生後端起根元件
//! （Android 走 `nsh run --target android`／`nsh package --target android`）。

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "linux")]
use nsh_platform_linux as platform;
#[cfg(target_os = "macos")]
use nsh_platform_macos as platform;
#[cfg(target_os = "windows")]
use nsh_platform_windows as platform;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn main() -> impl std::process::Termination {
    env_logger::init();
    platform::run_app(
        platform::AppSource::Rust(platform::Root::of::<nsh_app_bitward_android::App>()),
        platform::AppOptions {
            title: "bitward".to_owned(),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            app_id: "io.bitward.android".to_owned(),
            size: (420, 780),
            ..Default::default()
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!(
    "Run this binary on macOS, Windows or Linux; Android goes through `nsh run --target android`."
);
