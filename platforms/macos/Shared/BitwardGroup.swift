import Foundation

/// App group 常數與 daemon socket 定位。容器 App 與 extension 共用（凍結介面：
/// daemon 將以 `--push-app-group` 在 `<container>/daemon.sock` 多綁一個 BTP listener）。
enum BitwardGroup {
    static let id = "group.io.bitward.dev"

    /// sandboxed 進程走 containerURL API；非 sandbox（或 ad-hoc 簽章未獲 app group 核准）
    /// 時退回常規路徑——兩者在真機上是同一個目錄。
    static var containerURL: URL? {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id) {
            return url
        }
        let fallback = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Group Containers/\(id)")
        return FileManager.default.fileExists(atPath: fallback.path) ? fallback : nil
    }

    static var daemonSocketPath: String? {
        containerURL?.appendingPathComponent("daemon.sock").path
    }

    /// 自產 pairing uuid：Enroll auth 的身分錨點，必須跨啟動穩定，
    /// 否則每次 autofill 都會被 daemon 當成一台新裝置。
    static func pairingUUID() -> String {
        let key = "bitward.provider.pairing"
        let defaults = UserDefaults(suiteName: id)
        if let existing = defaults?.string(forKey: key) { return existing }
        let fresh = UUID().uuidString.lowercased()
        defaults?.set(fresh, forKey: key)
        return fresh
    }
}
