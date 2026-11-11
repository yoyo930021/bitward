//! Keystore 孤島橋（P4b 第五批：封存／解封 user key 的過橋面）。
//!
//! 分工（實測定案的形態，見 `docs/design/android-findings.md` 第五批）：
//! - **Kotlin 側持鑰**：AndroidKeyStore AES-256-GCM（Class 3：需使用者驗證，
//!   30 秒視窗＋解鎖裝置要求；emulator 無 StrongBox 走軟體 Keystore 降級路）。
//!   金鑰材料永不出 Keystore；這裡只收發 `byte[]`（IV‖密文‖tag 的不透明 blob）。
//! - **Rust 側持形態**：`sealed.json` 的記錄格式、漂移判定、落地與刪除都在
//!   `hub`（純函數可測）；user key 明文只在 seal/unseal 兩個瞬間過橋，
//!   全程 `Zeroizing`、不經 Kotlin String（契約 §2.7 規則 1 的 byte[] 紀律）。
//!
//! 反向呼叫（Rust→Kotlin）用 `nshBindBridge` 傳進來的物件 GlobalRef：
//! 不靠 FindClass（附著執行緒的 classloader 找不到 app 類，假設 8 以來的老坑），
//! 方法解析直接對該物件做。桌機（非 Android）編譯時整座橋是 no-op：
//! 封存路徑回 `Err`，登入照樣成功（沒封存只是沒有免重派生解鎖，不降格持鑰）。

#[cfg(target_os = "android")]
mod android {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{LazyLock, OnceLock};

    use jni::objects::{GlobalRef, JByteArray, JObject, JValue, JValueGen};
    use jni::{JNIEnv, JavaVM};
    use zeroize::Zeroizing;

    /// 背景解封的等待上限（生物辨識畫面開著不動的常識上限，超時視同取消）。
    const UNSEAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    /// Kotlin `KeyStoreBridge` 單例（`nshBindBridge` 綁定；重複綁定以首次為準）。
    static BRIDGE: OnceLock<(JavaVM, GlobalRef)> = OnceLock::new();

    /// 孤島反調／背景輪共用的執行緒池：反向 JNI 會擋在生物辨識閂上
    /// （最长 `UNSEAL_TIMEOUT`），不能佔用 nsh 引擎執行緒；`HubService`
    /// 的工作執行緒也從這裡 `block_on`，與 UI 反應鏈互不拖垮。
    pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("bitward-island")
            .enable_all()
            .build()
            .expect("island runtime")
    });

    pub(crate) fn bind(env: &mut JNIEnv<'_>, bridge: JObject<'_>) -> bool {
        match (env.get_java_vm(), env.new_global_ref(bridge)) {
            (Ok(vm), Ok(obj)) => BRIDGE.set((vm, obj)).is_ok(),
            _ => false,
        }
    }

    /// 金鑰明文／封存 blob 的雙向通道（`([B)[B`）；Java 例外與 null 回包
    /// 一律收斂成 Err 字串（panic 由呼叫端 `catch_unwind` 擋在邊界內）。
    fn call_bytes(env: &mut JNIEnv<'_>, obj: &JObject<'_>, method: &str, arg: &[u8]) -> Result<Vec<u8>, String> {
        let input = match env.byte_array_from_slice(arg) {
            Ok(a) => a,
            Err(e) => return Err(format!("配置緩衝失敗：{e}")),
        };
        let input_ref: &JObject<'_> = input.as_ref();
        let out = env.call_method(obj, method, "([B)[B", &[JValue::Object(input_ref)]);
        match out {
            Ok(JValueGen::Object(o)) => {
                let raw = o.into_raw();
                if raw.is_null() {
                    return Err("孤島回空（金鑰不可用、待驗證或被拒絕）".to_owned());
                }
                // 回包是 jbyteArray（Kotlin 端同一形態：零 Kotlin String）。
                let arr = JByteArray::from(unsafe { JObject::from_raw(raw) });
                env.convert_byte_array(&arr).map_err(|e| format!("讀取回包失敗：{e}"))
            }
            Ok(_) => Err(format!("孤島 {method} 回非位元組陣列")),
            Err(e) => Err(format!("孤島呼叫 {method} 失敗：{e}")),
        }
    }

    fn call_void(env: &mut JNIEnv<'_>, obj: &JObject<'_>, method: &str) {
        let _ = env.call_method(obj, method, "()V", &[]);
        let _ = env.exception_clear();
    }

    fn with_bridge(
        method: &'static str,
        arg: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (vm, obj) = BRIDGE.get().ok_or_else(|| "孤島橋未綁定".to_owned())?;
        let mut env = vm.attach_current_thread().map_err(|e| format!("附著失敗：{e}"))?;
        catch_unwind(AssertUnwindSafe(|| {
            call_bytes(&mut env, obj.as_ref(), method, arg)
        }))
        .unwrap_or_else(|_| Err(format!("孤島 {method} panic（已擋在邊界）")))
    }

    /// 封存：把 user key 明文交 Kotlin AES-GCM（Keystore 金鑰）包裹，
    /// 回不透明 blob（IV‖密文‖tag）。30 秒驗證視窗外由 Kotlin 側自行
    /// 退到生物辨識彈窗（呼叫端在 `RUNTIME` 的 blocking 執行緒上）。
    /// 明文進出都包 `Zeroizing`：過橋副本用完即歸零（Kotlin 端自行清零
    /// 它的 ByteArray；Java heap 歸零是尽力而為，形态紀律在兩側）。
    pub(crate) async fn seal(key: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
        bridge_round("sealUserKey", key).await
    }

    /// 解封：`prompt=false` 只走靜默路（驗證視窗內成功、視窗外明確失敗）；
    /// `prompt=true` 允許拉起生物辨識畫面。autofill 冷啟只用靜默路。
    pub(crate) async fn unseal(blob: Vec<u8>, prompt: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        bridge_round(if prompt { "unsealUserKeyPrompt" } else { "unsealUserKeySilent" }, Zeroizing::new(blob)).await
    }

    async fn bridge_round(method: &'static str, arg: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
        if BRIDGE.get().is_none() {
            return Err("孤島橋未綁定".to_owned());
        }
        let task = RUNTIME.spawn_blocking(move || with_bridge(method, &arg).map(Zeroizing::new));
        match tokio::time::timeout(UNSEAL_TIMEOUT, task).await {
            Ok(Ok(out)) => out,
            Ok(Err(_)) => Err("孤島任務被丟棄".to_owned()),
            Err(_) => Err("等待生物辨識逾時".to_owned()),
        }
    }

    /// `HubService` 保命＋週期排程（冪等；Kotlin 側 startForeground＋JobScheduler）。
    pub(crate) fn ensure_hub_service() {
        let Some((vm, obj)) = BRIDGE.get() else { return };
        let Ok(mut env) = vm.attach_current_thread() else { return };
        let _ = catch_unwind(AssertUnwindSafe(|| call_void(&mut env, obj.as_ref(), "ensureHubService")));
    }
}

#[cfg(not(target_os = "android"))]
mod desktop {
    use zeroize::Zeroizing;

    /// 桌機沒有 Keystore 孤島：一切封存呼叫明確失敗（登入路徑不依賴它）。
    pub(crate) async fn seal(_key: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("本平台沒有 Keystore 孤島".to_owned())
    }
    pub(crate) async fn unseal(_blob: Vec<u8>, _prompt: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("本平台沒有 Keystore 孤島".to_owned())
    }
    pub(crate) fn ensure_hub_service() {}
}

#[cfg(target_os = "android")]
pub(crate) use android::{RUNTIME, bind, ensure_hub_service, seal, unseal};

#[cfg(not(target_os = "android"))]
pub(crate) use desktop::{ensure_hub_service, seal, unseal};

// 桌機沒有反向 JNI，bind 符號保留給 jni.rs 的 cfg 面（不在桌機編譯）。
#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub(crate) fn bind(_env: &(), _bridge: &()) -> bool {
    false
}
