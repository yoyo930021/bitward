//! 孤島↔in-process 中樞的 JNI 橋（Kotlin 側：`android-shell` 的
//! `io.bitward.android.NativeHub`，符號 `Java_io_bitward_android_NativeHub_*`）。
//!
//! 形態（`android-shell/README.md`「銜接方案」1/2）：`libnsh.so` 與孤島同程序，
//! service 冷啟時 `System.loadLibrary("nsh")` 讓 `HUB` 經同一個 LazyLock 開
//! `vault.db`；`HubHolder.bridge` 裝的就是對這幾支符號的薄封裝。
//!
//! 紀律：
//! - user key 平常不過橋；第五批起只在**封存/解封兩個瞬間**以 `byte[]` 過橋
//!   （`src/island.rs`＋Kotlin `KeyStoreBridge`），不經 Kotlin String。
//!   過橋的其餘內容只有 metadata 級候選與填充用的明文欄位（Dataset 本來就要
//!   在 Java 側組 AutofillValue，契約 §2.7 規則 1 的 byte[] 限制指的是金鑰）。
//! - 分級、比對全在 Rust（bw-store 的 host 錨定查詢）；這裡零業務語意。
//! - 任何 Rust panic 不許穿越 JNI 邊界（會變 runtime abort）：全部 catch 後回空。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jsize, jobjectArray, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use crate::HUB;

fn hub() -> Option<&'static crate::hub::Hub> {
    HUB.as_ref().ok().map(Arc::as_ref)
}

fn arg_str(env: &mut JNIEnv<'_>, s: &JString<'_>) -> String {
    match env.get_string(s) {
        Ok(g) => g.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

/// String[] 過橋；任何 JNI 失敗回 null（Kotlin 端視同空）。
fn strings_array(env: &mut JNIEnv<'_>, values: &[String]) -> jobjectArray {
    let arr = match env.new_object_array(values.len() as jsize, "java/lang/String", JObject::null()) {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };
    for (i, v) in values.iter().enumerate() {
        match env.new_string(v) {
            Ok(js) => {
                if env.set_object_array_element(&arr, i as jsize, &js).is_err() {
                    return std::ptr::null_mut();
                }
            }
            Err(_) => return std::ptr::null_mut(),
        }
    }
    arr.into_raw()
}

/// 擋下邊界內的 panic（穿越 JNI 是 abort）；回 null 由 Kotlin 端降空值。
fn guard(body: impl FnOnce(&mut JNIEnv<'_>) -> jobjectArray, env: &mut JNIEnv<'_>) -> jobjectArray {
    let envp = env as *mut JNIEnv<'_>;
    match catch_unwind(AssertUnwindSafe(move || {
        // 單執行緒回呼內借用還原：env 只被這個閉包使用。
        body(unsafe { &mut *envp })
    })) {
        Ok(v) => v,
        Err(_) => {
            log::error!("jni: 橋內 panic（已擋在邊界，回空）");
            std::ptr::null_mut()
        }
    }
}

/// 中樞開得起來（Store 可用）才值得裝 bridge；解鎖與否另問 `nshIsUnlocked`。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshIsReady(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    match catch_unwind(AssertUnwindSafe(|| hub().is_some())) {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshIsUnlocked(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    match catch_unwind(AssertUnwindSafe(|| hub().is_some_and(|h| h.is_unlocked()))) {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// 候選：`query` 是 web host 或 app package；回 `[id, label, ...]` 扁平字串陣列
/// （空陣列＝沒命中；null＝橋內錯）。比對語意見 `Hub::candidates_for`。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshCandidates(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    query: JString<'_>,
) -> jobjectArray {
    guard(
        |env| {
            let q = arg_str(env, &query);
            let Some(h) = hub() else {
                return strings_array(env, &[]);
            };
            let found = h.candidates_for(&q, 10);
            log::info!("jni: candidates q={} n={}", q, found.len());
            let flat: Vec<String> = found
                .into_iter()
                .flat_map(|(id, label)| [id.to_string(), label])
                .collect();
            strings_array(env, &flat)
        },
        &mut env,
    )
}

/// 填充取用：回 `[username, password]`（缺欄＝空字串）；null＝找不到或未解鎖。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshReveal(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    id: JString<'_>,
) -> jobjectArray {
    guard(
        |env| {
            let raw = arg_str(env, &id);
            let Some(h) = hub() else {
                return std::ptr::null_mut();
            };
            let Ok(item) = uuid::Uuid::parse_str(&raw) else {
                log::warn!("jni: reveal 無效 id");
                return std::ptr::null_mut();
            };
            match h.reveal(item) {
                Ok(r) => {
                    // 明文只進陣列元素，不打 log。
                    strings_array(
                        env,
                        &[
                            r.username.unwrap_or_default(),
                            // Zeroizing Drop 歸零；這裡拷一份過橋（Dataset 需要）。
                            r.password.map(|p| p.to_string()).unwrap_or_default(),
                        ],
                    )
                }
                Err(_) => std::ptr::null_mut(),
            }
        },
        &mut env,
    )
}

/// AutofillService 儲存真寫入（onSaveRequest 落地端）：`query` 是 web host 或
/// app package（填充查詢鍵同源）。回 `[id, created|updated|unchanged]`；
/// null＝橋內錯或未解鎖（鎖態由 Kotlin 先擋，這裡再擋一道）。
/// 本地交易先行入 outbox（「待推送」），drain 收斂照既有「重新同步」路徑。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshSave(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    query: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
) -> jobjectArray {
    guard(
        |env| {
            let q = arg_str(env, &query);
            let user = arg_str(env, &username);
            let pass = arg_str(env, &password);
            let Some(h) = hub() else {
                return std::ptr::null_mut();
            };
            match h.save_from_autofill(&q, &user, &pass) {
                Ok((id, action)) => {
                    // 過橋只報 id 與動作；明文欄位不打 log。
                    log::info!("jni: save q={q} action={action} id={id}");
                    strings_array(env, &[id.to_string(), action.to_owned()])
                }
                Err(e) => {
                    log::warn!("jni: save 失敗：{e}");
                    std::ptr::null_mut()
                }
            }
        },
        &mut env,
    )
}

// —— P4b 第五批：Keystore 封存橋＋背景輪 ——

/// 綁定 Kotlin `KeyStoreBridge` 單例（反向呼叫的對象；冪等，重複綁定以首次
/// 為準）。傳物件實例而非類名：附著執行緒的 classloader 認不了 app 類
/// （假設 8 以來的老坑），方法解析直接對這個 GlobalRef 做。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshBindBridge(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    bridge: JObject<'_>,
) -> jboolean {
    let ok = catch_unwind(AssertUnwindSafe(|| crate::island::bind(&mut env, bridge)))
        .unwrap_or(false);
    log::info!("jni: island bridge bind ok={ok}");
    if ok { JNI_TRUE } else { JNI_FALSE }
}

/// 有無可用封存（登入頁生物辨識鈕的閘門；孤島冷啟的形態判定也問它）。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshHasSealed(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    match catch_unwind(AssertUnwindSafe(|| hub().is_some_and(|h| h.has_sealed()))) {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// 孤島冷啟的靜默解封（契約路线 3：能靜默就自動解鎖回真候選）：只在
/// 30 秒驗證視窗內成功、絕不彈窗；失敗保持誠實鎖態，由 Kotlin 走一鍵
/// 解鎖引導。成功回 true 並記鏡像數（不記金鑰、不記欄位明文）。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshTrySilentUnseal(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    let out = catch_unwind(AssertUnwindSafe(|| {
        let h = HUB.as_ref().ok()?.clone();
        let snap = crate::island::RUNTIME.block_on(h.unseal(false)).ok()?;
        Some(snap.items)
    }));
    match out {
        Ok(Some(items)) => {
            log::info!("jni: silent unseal ok items={items}");
            JNI_TRUE
        }
        _ => JNI_FALSE,
    }
}

/// `HubService` 背景輪（drain 收斂＋到拍 pull）：Kotlin 工作執行緒上跑，
/// 回終態字串給 logcat 斷言（`locked`|`ok`|`ok-synced`|`stalled`）；
/// null＝橋內錯（中樞開不起來／panic），Kotlin 側照樣收工等下個 job。
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_bitward_android_NativeHub_nshBackgroundRun(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jni::sys::jstring {
    let out = catch_unwind(AssertUnwindSafe(|| {
        hub().map(|h| crate::island::RUNTIME.block_on(h.background_run()))
    }));
    match out {
        Ok(Some(status)) => {
            log::info!("jni: background run → {status}");
            env.new_string(status).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
        }
        _ => std::ptr::null_mut(),
    }
}
