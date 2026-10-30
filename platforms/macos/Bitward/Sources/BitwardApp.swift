import SwiftUI

/// NSH（純 Rust GUI，契約 §0.2）整合不在本骨架範圍；此佔位視窗只證明
/// app target 與 BitwardProvider.appex 能共同建置、共享 app group 資訊。
@main
struct BitwardApp: App {
    var body: some Scene {
        WindowGroup {
            PlaceholderView()
        }
    }
}

private struct PlaceholderView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Bitward").font(.largeTitle.bold())
            Text("placeholder GUI — daemon hub 整合與 NSH 畫面屬 P5")
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
        .frame(minWidth: 540, minHeight: 260)
    }
}
