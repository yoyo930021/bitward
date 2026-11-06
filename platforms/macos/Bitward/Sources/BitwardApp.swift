import AuthenticationServices
import SwiftUI

@main
struct BitwardApp: App {
    init() { NSLog("bitward app init") }
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
        // TEMP 隔離實驗：先不用 TabView
        VStack { Text("Bitward"); ApprovalCenterBody() }.frame(minWidth: 560, minHeight: 320)
    }
}

private struct ApprovalCenterBody: View {
    var body: some View { ApprovalCenterView() }
}

/// 批准中心：遠端 device 的受控請求（requires_approval grant）在 daemon 排隊，
/// 這裡輪詢 ListPending 並由人批准。拒絕＝讓它 120s 逾時（Deny call 屬後續批次）。
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
            guard let items = try? Self.queryAllItems() else { return }
            let identities = items.compactMap { item -> ASPasswordCredentialIdentity? in
                guard !item.detail.isEmpty else { return nil }
                return ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: item.detail, type: .URL),
                    user: item.name, recordIdentifier: item.id)
            }
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { ok, err in
                let detail = err.map { "\(($0 as NSError).domain)#\(($0 as NSError).code) \($0.localizedDescription) \($0 as NSError).userInfo" } ?? "none"
                NSLog("bitward identity store replace ok=\(ok) n=\(identities.count) err=\(detail)")
            }
        }
    }

    private nonisolated static func queryAllItems() throws -> [(id: String, name: String, detail: String)] {
        try connect().list(uri: "").map { ($0.id, $0.name, $0.detail) }
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

/// 狀態頁：骨架佔位（app group/socket/pairing 資訊）。NSH 正式 GUI 屬獨立主項。
private struct StatusView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Bitward").font(.largeTitle.bold())
            Text("批准中心已上工；vault 瀏覽與 NSH 整合屬後續主項")
                .foregroundStyle(.secondary)
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
