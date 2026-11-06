import AppKit
import AuthenticationServices
import OSLog

private let log = Logger(subsystem: "io.bitward.probe.provider", category: "probe")

/// 最小化探測 provider：不連 daemon，只證明系統會呼叫我們的哪條路徑。
final class ProbeVC: ASCredentialProviderViewController {
    override func loadView() {
        log.debug("PROBE loadView")
        let label = NSTextField(labelWithString: "PROBE loadView 有被呼叫")
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 160))
        label.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: container.centerYAnchor),
        ])
        view = container
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        log.debug("PROBE prepareCredentialList uris=\(serviceIdentifiers.map(\.identifier).joined(separator: ","), privacy: .public)")
        view.subviews.forEach { $0.removeFromSuperview() }
        let label = NSTextField(labelWithString: "PROBE 清單路徑有被呼叫")
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        log.debug("PROBE silent request")
        guard credentialRequest is ASPasswordCredentialRequest else {
            extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            return
        }
        let credential = ASPasswordCredential(user: "probe-user", password: "probe-pass-123")
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }
}
