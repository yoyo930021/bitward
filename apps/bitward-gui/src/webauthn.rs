//! WebAuthn 安全金鑰島（PR3 GUI 面）：`ASAuthorizationController` ＋
//! `ASAuthorizationSecurityKeyPublicKeyCredentialProvider`（raw msg_send）。
//!
//! 依賴紀律（TwoFA 收案實錄）：`nsh run` 組 app lib 時剝 [target] 依賴、
//! 只注入它自己,故 objc2 棧一律經 `nsh_platform_macos::{objc2, objc2_app_kit,
//! objc2_foundation}` 再匯入取用；AuthenticationServices 沒有 bindings 也不必
//! 新增——先 `NSBundle …load` 把框架載進程序（dlopen 不可用,libc 未再匯出）,
//! 再以 `class!`/`extern_protocol!` 動態綁定。簽名逐條對照 SDK 標頭
//! （macOS 27.2）：provider init **無 error 參數**、
//! `createCredentialAssertionRequestWithChallenge:(NSData*)`（內容＝伺服器
//! b64url challenge 字串的 UTF-8 位元組——挑戰對金鑰是不透明資料,最終由
//! 伺服器比對 clientDataJSON.challenge）、斷言取欄走 `credentialID`/
//! `rawAuthenticatorData`/`rawClientDataJSON`/`signature` getter；
//! `performRequests` 後 controller 由框架持有至回話（標頭明言）,delegate 是
//! **weak**——由本檔 thread-local 保命池托住（主執行緒專屬）。
//!
//! 產物形態：`{"id","rawId","response":{"authenticatorData","clientDataJSON",
//! "signature"},"clientExtensionResults"}`（b64url 無填充）——bw-proto
//! `validate_token(7)` 欄位閘同源,VW webauthn 登入解析同形態。

use std::cell::RefCell;

use nsh_platform_macos::objc2::rc::{Allocated, Retained, Weak};
use nsh_platform_macos::objc2::runtime::{AnyObject, Bool, NSObject, ProtocolObject};
use nsh_platform_macos::objc2::{
    DefinedClass, MainThreadOnly, class, define_class, extern_protocol, msg_send,
};
use nsh_platform_macos::objc2_app_kit::NSWindow;
use nsh_platform_macos::objc2_foundation::{NSArray, NSData, NSError, NSObjectProtocol, NSString};

unsafe extern "C" {
    /// 本 app 未連結 AuthenticationServices（框架走 NSBundle 動態載入）,
    /// 符號改向全程序要：`dlsym(RTLD_DEFAULT, …)`（libSystem 恆有 dlsym,
    /// TwoFA 紀律「libc 未再匯出 dlopen」的替代路）。
    fn dlsym(
        handle: *mut std::ffi::c_void,
        symbol: *const std::ffi::c_char,
    ) -> *mut std::ffi::c_void;
}

/// macOS `RTLD_DEFAULT`＝((void*)-2)。
const RTLD_DEFAULT: *mut std::ffi::c_void = -2isize as *mut std::ffi::c_void;

/// 取 `ASAuthorizationAllSupportedPublicKeyCredentialDescriptorTransports()`
/// （標頭提供的 transports 全集合,usb/nfc/ble）；取不到＝回 None 由呼叫端
/// 跳過 allowedCredentials 收窄（寧寬勿拒,伺服器仍會拒絕非清單鑰）。
fn all_supported_transports() -> Option<Retained<NSArray<AnyObject>>> {
    let name = std::ffi::CString::new(
        "ASAuthorizationAllSupportedPublicKeyCredentialDescriptorTransports",
    )
    .ok()?;
    unsafe {
        let sym = dlsym(RTLD_DEFAULT, name.as_ptr());
        if sym.is_null() {
            return None;
        }
        let f: unsafe extern "C" fn() -> *mut NSArray<AnyObject> = std::mem::transmute(sym);
        Retained::from_raw(f())
    }
}

/// b64url（WebAuthn 水漬編碼,無填充）。
pub fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() as f64 * 4.0 / 3.0).ceil() as usize);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

/// b64url 解碼（僅容許 WebAuthn 字元集;失敗回 None 由呼叫端忽略該 id）。
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u64> {
        match c {
            b'A'..=b'Z' => Some(u64::from(c - b'A')),
            b'a'..=b'z' => Some(u64::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u64::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut acc: u64 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.as_bytes() {
        let v = val(*c)?;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// assertion → 送伺服器的 JSON token（欄位名與官方 clients 同形態）。
pub fn assertion_json(
    credential_id: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> String {
    format!(
        r#"{{"id":"{id}","rawId":"{id}","response":{{"authenticatorData":"{ad}","clientDataJSON":"{cd}","signature":"{sig}"}},"clientExtensionResults":{{}}}}"#,
        id = b64url(credential_id),
        ad = b64url(authenticator_data),
        cd = b64url(client_data_json),
        sig = b64url(signature),
    )
}

extern_protocol!(
    /// ASAuthorizationControllerDelegate（只用得到的兩支;其餘 optional 不宣告）。
    ///
    /// # Safety
    /// 鏡像 Apple AuthenticationServices 標頭的必選委派方法簽名（macOS 27.2 對照）。
    #[allow(clippy::missing_safety_doc)] // Safety 寫在上層 doc,macro 不外洩。
    unsafe trait ASAuthorizationControllerDelegate: NSObjectProtocol {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn did_complete(&self, controller: &AnyObject, authorization: &AnyObject);

        #[unsafe(method(authorizationController:didFailWithError:))]
        fn did_fail(&self, controller: &AnyObject, error: &NSError);
    }
);

extern_protocol!(
    /// ASAuthorizationControllerPresentationContextProviding。
    ///
    /// # Safety
    /// 鏡像 Apple 標頭：回傳承載彈窗的 NSWindow（ASPresentationAnchor 別名）。
    #[allow(clippy::missing_safety_doc)]
    unsafe trait ASAuthorizationControllerPresentationContextProviding:
        NSObjectProtocol
    {
        #[allow(deprecated)]
        #[unsafe(method_id(presentationAnchorForAuthorizationController:))]
        fn presentation_anchor(&self, controller: &AnyObject) -> Retained<NSWindow>;
    }
);

/// 系統回話的一次性交棒回调。
type DoneCb = Box<dyn FnOnce(Result<String, String>)>;

/// 實例ivar：一次性回調＋controller 弱引用（保命用,見標頭紀律）。
struct Ivars {
    done: RefCell<Option<DoneCb>>,
    controller: RefCell<Option<Weak<AnyObject>>>,
}

define_class!(
    /// 安全金鑰島委派（主執行緒專屬;保命池見 `POOL`）。
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "BitwardWebauthnIsland"]
    #[ivars = Ivars]
    struct IslandDelegate;

    unsafe impl NSObjectProtocol for IslandDelegate {}

    impl IslandDelegate {
        #[unsafe(method_id(initWithDone:))]
        fn init_with_done(
            this: Allocated<Self>,
            done: *mut std::ffi::c_void,
        ) -> Option<Retained<Self>> {
            // 由呼叫端 Box::into_raw 轉來（*mut c_void 保編碼合規）,這裡收回。
            let cb = unsafe { *Box::from_raw(done as *mut DoneCb) };
            let ivars = Ivars {
                done: RefCell::new(Some(cb)),
                controller: RefCell::new(None),
            };
            let this = this.set_ivars(ivars);
            unsafe { msg_send![super(this), init] }
        }
    }

    unsafe impl ASAuthorizationControllerDelegate for IslandDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn did_complete(&self, _controller: &AnyObject, authorization: &AnyObject) {
            let out = (|| -> Result<String, String> {
                let credential: Option<Retained<AnyObject>> =
                    unsafe { msg_send![authorization, credential] };
                let cred = credential.ok_or("回包缺 credential")?;
                // security-key 形態本尊藏在 rawCredential（ASAuthorization
                // .credential 的包裝欄）；缺席就用 credential 本身。
                let raw: Option<Retained<AnyObject>> = unsafe { msg_send![&*cred, rawCredential] };
                let cred = raw.unwrap_or(cred);
                let data_of = |which: u8| -> Result<Vec<u8>, String> {
                    let v: Option<Retained<AnyObject>> = unsafe {
                        match which {
                            0 => msg_send![&*cred, credentialID],
                            1 => msg_send![&*cred, rawAuthenticatorData],
                            2 => msg_send![&*cred, rawClientDataJSON],
                            _ => msg_send![&*cred, signature],
                        }
                    };
                    let names = ["credentialID", "rawAuthenticatorData", "rawClientDataJSON", "signature"];
                    let v = v.ok_or_else(|| format!("憑證缺欄 {}", names[which as usize]))?;
                    let ns: &NSData = unsafe { &*(&*v as *const AnyObject as *const NSData) };
                    Ok(ns.to_vec())
                };
                let id_bytes = data_of(0)?;
                let ad = data_of(1)?;
                let cd = data_of(2)?;
                let sig = data_of(3)?;
                Ok(assertion_json(&id_bytes, &ad, &cd, &sig))
            })();
            if let Some(cb) = self.ivars().done.borrow_mut().take() {
                cb(out);
            }
        }

        #[unsafe(method(authorizationController:didFailWithError:))]
        fn did_fail(&self, _controller: &AnyObject, error: &NSError) {
            if let Some(cb) = self.ivars().done.borrow_mut().take() {
                cb(Err(format!(
                    "安全金鑰辨識失敗：{}({})",
                    error.localizedDescription(),
                    error.code()
                )));
            }
        }
    }

    unsafe impl ASAuthorizationControllerPresentationContextProviding for IslandDelegate {
        #[unsafe(method_id(presentationAnchorForAuthorizationController:))]
        fn presentation_anchor(&self, _controller: &AnyObject) -> Retained<NSWindow> {
            // 彈窗掛在主視窗（GUI 的 key window；退而求其次 mainWindow）。
            unsafe {
                let app: Retained<AnyObject> =
                    msg_send![class!(NSApplication), sharedApplication];
                let win: Option<Retained<NSWindow>> = msg_send![&*app, keyWindow];
                match win {
                    Some(w) => w,
                    None => {
                        let mw: Option<Retained<NSWindow>> = msg_send![&*app, mainWindow];
                        mw.expect("無可用視窗承載金鑰提示")
                    }
                }
            }
        }
    }
);

// 回話池：delegate 被 controller **weak** 持有,必須有人留住它到系統回話;
// 每次新島啟動時順帶回收已交棒（done 已被 take）的舊任。
thread_local! {
    static POOL: RefCell<Vec<Retained<IslandDelegate>>> = const { RefCell::new(Vec::new()) };
}

/// 載入 AuthenticationServices（冪等；失敗回 false＝島不可用）。
fn ensure_framework_loaded() -> bool {
    let path = NSString::from_str("/System/Library/Frameworks/AuthenticationServices.framework");
    unsafe {
        let bundle: Option<Retained<AnyObject>> =
            msg_send![class!(NSBundle), bundleWithPath: &*path];
        let Some(bundle) = bundle else { return false };
        let ok: Bool = msg_send![&*bundle, load];
        ok.as_bool()
    }
}

/// 起一次安全金鑰 assertion（**主執行緒**呼叫；`on_done` 由系統回話執行一次）。
pub fn request_assertion(
    challenge: String,
    credential_ids: Vec<String>,
    rp_id: Option<String>,
    on_done: impl FnOnce(Result<String, String>) + 'static,
) {
    let Some(mtm) = nsh_platform_macos::objc2::MainThreadMarker::new() else {
        on_done(Err("安全金鑰島只准在主執行緒啟動".into()));
        return;
    };
    if !ensure_framework_loaded() {
        on_done(Err("AuthenticationServices 框架載入失敗".into()));
        return;
    }
    let rp = rp_id.unwrap_or_else(|| "bitward.local".to_owned());
    let rp_ns = NSString::from_str(&rp);
    // challenge：伺服器 b64url 字串的 UTF-8 位元組（見模組頭註）。
    let challenge_data = NSData::from_vec(challenge.into_bytes());
    unsafe {
        let provider: Option<Retained<AnyObject>> = msg_send![
            msg_send![
                class!(ASAuthorizationSecurityKeyPublicKeyCredentialProvider),
                alloc
            ],
            initWithRelyingPartyIdentifier: &*rp_ns
        ];
        let Some(provider) = provider else {
            on_done(Err("安全金鑰島不可用（provider 建立失敗）".into()));
            return;
        };
        let request: Option<Retained<AnyObject>> = msg_send![
            &*provider,
            createCredentialAssertionRequestWithChallenge: &*challenge_data
        ];
        let Some(request) = request else {
            on_done(Err("無法建立安全金鑰請求".into()));
            return;
        };
        // allowedCredentials：有清單才收窄（id 解碼失敗的跳過,寧寬勿拒）。
        if let Some(transports) = all_supported_transports().filter(|_| !credential_ids.is_empty())
        {
            let mut objs: Vec<Retained<AnyObject>> = Vec::new();
            for id in &credential_ids {
                let Some(bytes) = b64url_decode(id) else {
                    continue;
                };
                let data = NSData::from_vec(bytes);
                let desc: Option<Retained<AnyObject>> = msg_send![
                    msg_send![
                        class!(ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor),
                        alloc
                    ],
                    initWithCredentialID: &*data,
                    transports: &*transports
                ];
                if let Some(d) = desc {
                    objs.push(d);
                }
            }
            if !objs.is_empty() {
                let arr = NSArray::from_retained_slice(&objs);
                let _: () = msg_send![&*request, setAllowedCredentials: &*arr];
            }
        }
        let boxed: *mut std::ffi::c_void =
            Box::into_raw(Box::new(on_done)) as *mut std::ffi::c_void;
        let delegate: Option<Retained<IslandDelegate>> = msg_send![
            IslandDelegate::alloc(mtm),
            initWithDone: boxed
        ];
        let Some(delegate) = delegate else {
            let cb = Box::from_raw(boxed as *mut DoneCb);
            cb(Err("委派建立失敗".into()));
            return;
        };
        let requests = NSArray::from_retained_slice(&[request]);
        let controller: Option<Retained<AnyObject>> = msg_send![
            msg_send![class!(ASAuthorizationController), alloc],
            initWithAuthorizationRequests: &*requests
        ];
        let Some(controller) = controller else {
            let cb = Box::from_raw(boxed as *mut DoneCb);
            cb(Err("無法建立授權控制器".into()));
            return;
        };
        delegate
            .ivars()
            .controller
            .replace(Some(Weak::new(&controller)));
        let proto: Retained<ProtocolObject<dyn ASAuthorizationControllerDelegate>> =
            ProtocolObject::from_retained(delegate.clone());
        let ctx: Retained<
            ProtocolObject<dyn ASAuthorizationControllerPresentationContextProviding>,
        > = ProtocolObject::from_retained(delegate.clone());
        let _: () = msg_send![&*controller, setDelegate: Some(&*proto)];
        let _: () = msg_send![&*controller, setPresentationContextProvider: Some(&*ctx)];
        let _: () = msg_send![&*controller, performRequests];
        POOL.with(|p| {
            let mut p = p.borrow_mut();
            p.retain(|d| d.ivars().done.borrow().is_some());
            p.push(delegate);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_known_vectors_and_roundtrip() {
        // RFC 4648 範例＋邊界長度（1/2/3 字元尾段）。
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foob"), "Zm9vYg");
        // 62/63 號字元必須是 -/_（標準 base64 的 +/ 在 WebAuthn 不合規）。
        assert_eq!(b64url(&[0xFB, 0xFF]), "-_8");
        for raw in [&b"foo"[..], b"foob", b"fooba", b"\x00\x01\xfe\xff"] {
            let enc = b64url(raw);
            assert_eq!(
                b64url_decode(&enc).as_deref(),
                Some(raw),
                "roundtrip {raw:?}"
            );
        }
        assert_eq!(b64url_decode("a+"), None);
    }

    #[test]
    fn assertion_json_passes_proto_gate() {
        let j = assertion_json(b"cid", b"auth", b"client", b"sig");
        // bw-proto 欄位閘（CLI/GUI/daemon 同源真相）必收。
        assert!(bw_proto::TwoFactorProviderInfo::validate_token(7, &j).is_ok());
        assert!(
            bw_proto::TwoFactorProviderInfo::validate_token(7, r#"{"id":"","response":{}}"#)
                .is_err()
        );
    }
}
