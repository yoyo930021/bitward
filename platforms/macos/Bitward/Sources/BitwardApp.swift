import AuthenticationServices
import Foundation
import OSLog
import ServiceManagement
import SwiftUI

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

@main
struct BitwardApp: App {
    var body: some Scene {
        // macOS 27 實測：WindowGroup 從背景 session 啟動不自動建窗（savedState 還原
        // 是唯一出現過視窗的路徑）。單例 Window + presented 啟動行為才有可靠首窗。
        Window("Bitward", id: "main") {
            RootView()
        }
        .defaultLaunchBehavior(.presented)
    }
}

private struct RootView: View {
    var body: some View {
        TabView {
            ApprovalCenterView()
                .tabItem { Label("批准", systemImage: "checkmark.seal") }
            StatusView()
                .tabItem { Label("狀態", systemImage: "info.circle") }
        }
        .frame(minWidth: 560, minHeight: 340)
    }
}

/// 批准中心：遠端 device 的受控請求（requires_approval grant）在 daemon 排隊，
/// 這裡輪詢 ListPending 並由人批准或拒絕（Deny 立即釋放請求端）。
private struct ApprovalCenterView: View {
    @StateObject private var model = ApprovalModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if model.pending.isEmpty {
                Text(model.daemonReachable ? "目前沒有待批准的請求" : "連不到 daemon（bitwarderd 沒跑？）")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 24)
            } else {
                List {
                    ForEach(model.pending) { item in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.summary).font(.system(.body, design: .monospaced))
                                Text(item.id).font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("批准") { model.approve(id: item.id) }
                                .disabled(model.busyIds.contains(item.id))
                            Button("拒絕") { model.deny(id: item.id) }
                                .disabled(model.busyIds.contains(item.id))
                        }
                    }
                }
            }
        }
        .padding()
        .onAppear { model.start() }
        .onDisappear { model.stop() }
    }
}

@MainActor
private final class ApprovalModel: ObservableObject {
    struct PendingItem: Identifiable, Equatable { let id: String; let summary: String }

    @Published var pending: [PendingItem] = []
    @Published var daemonReachable = false
    fileprivate var busyIds: Set<String> = []
    private var timer: Timer?

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
        tick()
    }

    func stop() { timer?.invalidate(); timer = nil }

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
            Text("批准中心已上工；vault 瀏覽與 NSH 整合屬後續主項")
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
