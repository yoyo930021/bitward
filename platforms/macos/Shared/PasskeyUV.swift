import Foundation
import LocalAuthentication

/// Passkey 的 UV 由 provider 執行（provider 即 authenticator，WebAuthn 語意）。
/// 跳過 UV 直接宣告 authData UV bit 時，WebKit 靜默取消註冊（macOS 27 實測：
/// completeRequest expired=false 仍 NotAllowedError/Code=1000）。
enum PasskeyUV {
    enum UVErr: Error { case denied(String) }

    /// 彈系統 Touch ID／密碼。回 true = 人驗證通過。
    static func evaluate(reason: String) -> Bool {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            return false
        }
        var ok = false
        let sem = DispatchSemaphore(value: 0)
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            ok = success
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 120)
        return ok
    }
}
