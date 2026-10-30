import AuthenticationServices
import Foundation

/// Thin provider：金鑰與業務全在 daemon（契約 §1），本檔只做「翻譯請求 → BTP → 回候選」。
final class ProviderViewController: ASCredentialProviderViewController {
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasswordCredentialRequest else {
            // OTP / text-to-insert 的正式處理在 P5；先交回系統互動 UI，不靜默失敗（§8）。
            extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            return
        }
        // identifier 即 domain 或 URL 字串（ASCredentialServiceIdentifierType）；
        // daemon 端 Query.uri 負責匹配語意，thin 端不二次解讀。
        let uri = request.credentialIdentity.serviceIdentifier.identifier
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let candidate = try Self.resolve(uri: uri)
                let credential = ASPasswordCredential(user: candidate.username ?? "",
                                                      password: candidate.password ?? "")
                self.extensionContext.completeRequest(withSelectedCredential: credential,
                                                      completionHandler: nil)
            } catch let error as BTPError {
                // 語意映射（契約 §8）：無候選是事實；其餘（daemon 不在、逾時、Locked、
                // 需批准）都代表「要人」→ .userInteractionRequired，系統改開互動 UI。
                // macOS 面無 iOS 的 credentialNoCredentials；零候選的對應語意是
                // ASExtensionErrorCodeCredentialIdentityNotFound（ASExtensionErrors.h）。
                let code: ASExtensionError.Code = error == .noCredentials ? .credentialIdentityNotFound : .userInteractionRequired
                self.extensionContext.cancelRequest(withError: ASExtensionError(code))
            } catch {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            }
        }
    }

    private static func resolve(uri: String) throws -> BTPCandidate {
        guard let path = BitwardGroup.daemonSocketPath else { throw BTPError.daemonAbsent }
        return try BTPClient.connect(path: path).autofill(uri: uri)
    }

    /// ShowsConfigurationUI：Settings 裡按「進階設定」會走到這裡。骨架只顯示連線目標，
    /// 正式的 daemon 狀態/配對指引屬 P5。
    override func prepareInterfaceForExtensionConfiguration() {
        let text = "Bitward daemon socket: \(BitwardGroup.daemonSocketPath ?? "app group container unavailable")\n"
            + "pairing id: \(BitwardGroup.pairingUUID())"
        let label = NSTextField(wrappingLabelWithString: text)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.isSelectable = true
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.widthAnchor.constraint(lessThanOrEqualToConstant: 420),
        ])
    }
}
