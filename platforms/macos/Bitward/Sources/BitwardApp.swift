import AuthenticationServices
import Foundation
import OSLog
import ServiceManagement
import SwiftUI
import UserNotifications

private let uiLog = Logger(subsystem: "io.bitward.dev", category: "gui")

/// daemon 常駐服務（計畫 R2 緩解：thin autofill 依賴 daemon 存活）。
/// launchd 的 UDS socket 激活不存在（MachServices 只認 Mach port），
/// 等效手段 = RunAtLoad + KeepAlive 進程級常駐。註冊動作由 daemon 自己
/// 執行（`--service install`）：SMAppService.agent(plistName:) 對本機組建
/// 回 EPERM（MAS 分發限定），非沙盒進程寫 LaunchAgents + launchctl 才是通的路。
enum DaemonService {
    private static let agent = SMAppService.agent(plistName: "io.bitward.dev.daemon.plist")

    static func status() -> String {
        switch agent.status {
        case .notRegistered: return "未註冊"
        case .enabled: return "已啟用"
        case .requiresApproval: return "待核准（系統設定→登入項目）"
        case .notFound: return "找不到（bundle 缺 LaunchAgents plist？）"
        @unknown default: return "未知"
        }
    }

    static func enable() -> String? {
        do { try agent.register(); return nil } catch { return error.localizedDescription }
    }

    static func disable() -> String? {
        do { try agent.unregister(); return nil } catch { return error.localizedDescription }
    }
}

/// 巢狀密碼庫（NSH GUI）轉發：本殼 LSUIElement 化後，vault 瀏覽面是
/// Bitward.app/Contents/Applications/BitwardGUI.app，Dock 只剩它一個入口。
enum VaultGUI {
    static var bundleURL: URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Applications/BitwardGUI.app")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    /// 傳給 GUI 的 `--sock`：預設 group container 路徑（與本殼同解析鏈）；
    /// `defaults write io.bitward.dev DaemonSockPath <path>` 覆寫（dev 指 demo sock 用）。
    static var sockPath: String {
        if let over = UserDefaults.standard.string(forKey: "DaemonSockPath"), !over.isEmpty {
            return over
        }
        return BitwardGroup.daemonSocketPath ?? BitwardGroup.tmpSock
    }

    /// NSWorkspace.open 巢狀 bundle（已在跑＝同 bundle id 單例，直接帶到前景）。
    static func open() {
        guard let url = bundleURL else {
            uiLog.notice("巢狀 BitwardGUI.app 不存在（dev 建置請直接 cargo run／nsh run 密碼庫）")
            return
        }
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.activates = true
        cfg.arguments = ["--sock", sockPath]
        NSWorkspace.shared.openApplication(at: url, configuration: cfg) { _, error in
            if let error {
                uiLog.notice("開啟密碼庫失敗：\(error.localizedDescription, privacy: .public)")
            }
        }
    }
}

@main
struct BitwardApp: App {
    @NSApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate

    var body: some Scene {
        // 殼轉背景（LSUIElement）：批准中心 UI 已併入 BitwardGUI（批次 6），
        // 殼只剩狀態頁（啟用開關）＋狀態列入口；批准輪詢＋identity store
        // 同步是 provider 基礎設施，留在 App 層單例（與視窗無關）。
        Window("狀態", id: "status") {
            StatusView()
        }
        .defaultLaunchBehavior(.suppressed)
        .commands {
            BitwardMenu()
        }
        // 狀態列入口（批次 5B）：LSUIElement 後主選單只在 App 前景時可見，
        // 使用者實測「找不到地方」——狀態列常駐圖示才是穩定入口。盾牌 glyph
        // 用 SF Symbol lock.shield（icon 素材只有彩色 icns，模板單色版未入庫；
        // systemName 天然走模板渲染，深淺選單列都對）。
        MenuBarExtra {
            MenuBarContent()
        } label: {
            Image(systemName: "lock.shield")
        }
        .menuBarExtraStyle(.menu)
    }
}

/// 狀態列選單：開啟密碼庫／狀態（「啟用」常駐開關在該頁）／離開。
/// 批准中心⋯已隨批次 6 移入 BitwardGUI 側欄「待批准」。
private struct MenuBarContent: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("開啟密碼庫") { VaultGUI.open() }
        Divider()
        Button("狀態⋯") {
            openWindow(id: "status")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button("離開") { NSApp.terminate(nil) }
    }
}

private struct BitwardMenu: Commands {
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button("狀態⋯") {
                openWindow(id: "status")
                NSApp.activate()
            }
            Divider()
            Button("開啟密碼庫⋯") { VaultGUI.open() }
        }
    }
}

/// APNs thin 端：拿 device token 經 BTP 註冊進 daemon（§1.2 推播路徑）。
/// 本機 ad-hoc/Mac Developer 無 push entitlement 時 didFail 屬預期——留日誌、
/// 不中斷 App（ntfy 信令仍是可用通道）。
final class PushAppDelegate: NSObject, NSApplicationDelegate {
    private let log = Logger(subsystem: "io.bitward.dev", category: "gui")

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 背景殼三件事：拉起密碼庫首窗、批准輪詢＋identity store 同步常駐、push 註冊。
        VaultGUI.open()
        ApprovalModel.shared.start()
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { [log] granted, error in
            log.notice("push auth granted=\(granted) err=\(String(describing: error), privacy: .public)")
        }
        center.delegate = self
        NSApp.registerForRemoteNotifications()
    }

    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        log.notice("apns token registered, forwarding to daemon")
        DispatchQueue.global(qos: .utility).async { [log] in
            do {
                guard let path = BitwardGroup.daemonSocketPath else { throw BTPError.daemonAbsent }
                let client = try BTPClient.connect(path: path, budget: 5.0)
                _ = try client.registerPush(token: token)
                log.notice("daemon push_token stored")
            } catch {
                log.notice("push token 上報 daemon 失敗（稍後随重啟重試）: \(String(describing: error), privacy: .public)")
            }
        }
    }

    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        log.notice("apns unavailable: \(error.localizedDescription, privacy: .public)")
    }

    /// `open -a Bitward`（已跑）＝把密碼庫帶回前景：Dock 單一入口的 reopen 語意。
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        VaultGUI.open()
        return false
    }
}

extension PushAppDelegate: UNUserNotificationCenterDelegate {
    /// 前台也顯示橫幅（核准提醒的可用性優先）。
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}


@MainActor
private final class ApprovalModel: ObservableObject {
    /// 殼轉背景常駐：輪詢＋identity store 同步不再綁視窗生命週期
    /// （改前視窗永遠開著＝效果相同；改後視窗選單才喚起，綁生命週期會靜默停擺）。
    static let shared = ApprovalModel()

    struct PendingItem: Identifiable, Equatable { let id: String; let summary: String }

    @Published var pending: [PendingItem] = []
    @Published var daemonReachable = false
    fileprivate var busyIds: Set<String> = []
    private var timer: Timer?

    private init() {}

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
        tick()
    }

    private var counter = 0
    private func tick() {
        refresh()
        counter += 1
        // 每 20 tick（30s）把候選站點寫進系統 identity store：Safari 欄位聚焦時
        // 能內聯顯示「Bitward」建議，不用先開清單（ASCredentialIdentityStore 語意）。
        if counter % 20 == 1 { syncIdentityStore() }
    }

    private func syncIdentityStore() {
        DispatchQueue.global(qos: .background).async {
            guard let client = try? Self.connect() else { return }
            do {
                guard try client.isUnlocked() else {
                    // 鎖定：清掉建議（密文名稱不配出現在系統下拉），解鎖後下一輪回填。
                    ASCredentialIdentityStore.shared.replaceCredentialIdentities([]) { ok, _ in
                        uiLog.notice("identity store cleared unlocked=false ok=\(ok)")
                    }
                    return
                }
                let items = try client.list(uri: "")
                let identities = items.compactMap { item -> ASPasswordCredentialIdentity? in
                    guard !item.detail.isEmpty else { return nil }
                    return ASPasswordCredentialIdentity(
                        serviceIdentifier: ASCredentialServiceIdentifier(identifier: item.detail, type: .URL),
                        user: item.name, recordIdentifier: item.id)
                }
                ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { ok, err in
                    uiLog.notice("identity store replace ok=\(ok) n=\(identities.count) err=\(err.map { "\(($0 as NSError).domain)#\(($0 as NSError).code)" } ?? "none", privacy: .public)")
                }
            } catch {
                uiLog.notice("identity store sync failed \(String(describing: error), privacy: .public)")
            }
        }
    }

    func refresh() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let items: [PendingItem]?
            do { items = try Self.query() } catch { items = nil }
            DispatchQueue.main.async {
                guard let self else { return }
                self.daemonReachable = items != nil
                if let items {
                    // 正在 approve 的列不閃除；其餘以 daemon 現況為準
                    self.pending = items.filter { !self.busyIds.contains($0.id) }
                }
            }
        }
    }

    func approve(id: String) { act(id: id, op: Self.approveNow) }
    func deny(id: String) { act(id: id, op: Self.denyNow) }

    private func act(id: String, op: @escaping (String) throws -> Void) {
        busyIds.insert(id)
        pending.removeAll { $0.id == id }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let ok: Bool
            do { try op(id); ok = true } catch { ok = false }
            DispatchQueue.main.async {
                guard let self else { return }
                self.busyIds.remove(id)
                if !ok { self.refresh() }
            }
        }
    }

    private nonisolated static func connect() throws -> BTPClient {
        guard let path = BitwardGroup.daemonSocketPath else { throw BTPError.daemonAbsent }
        return try BTPClient.connect(path: path, budget: 5.0)
    }

    private nonisolated static func query() throws -> [PendingItem] {
        try connect().listPending().map { PendingItem(id: $0.id, summary: $0.summary) }
    }

    private nonisolated static func approveNow(id: String) throws {
        try connect().approve(id: id)
    }

    private nonisolated static func denyNow(id: String) throws {
        try connect().deny(id: id)
    }
}

/// 狀態頁：骨架佔位（app group/socket/pairing 資訊）＋ daemon 常駐開關。
private struct StatusView: View {
    @State private var agentStatus = DaemonService.status()
    @State private var agentError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Bitward").font(.largeTitle.bold())
            Text("背景常駐殼：密碼庫視窗由本殼轉發開啟（Contents/Applications/BitwardGUI.app）；批准中心與本頁從選單「Bitward」喚起")
                .foregroundStyle(.secondary)
            Divider()
            HStack {
                Text("開機常駐 daemon：").bold()
                Text(agentStatus).foregroundStyle(.secondary)
                Button("啟用") {
                    agentError = DaemonService.enable()
                    agentStatus = DaemonService.status()
                }
                Button("停用") {
                    agentError = DaemonService.disable()
                    agentStatus = DaemonService.status()
                }
            }
            if let agentError {
                Text(agentError).font(.caption).foregroundStyle(.red)
            }
            Divider()
            Group {
                Text("app group: \(BitwardGroup.id)")
                Text("daemon socket: \(BitwardGroup.daemonSocketPath ?? "(container 尚未建立)")")
                Text("密碼庫轉發 sock: \(VaultGUI.sockPath)")
                Text("pairing id: \(BitwardGroup.pairingUUID())")
            }
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            Spacer()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
