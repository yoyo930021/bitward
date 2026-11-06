import AuthenticationServices
import Foundation
import OSLog
import AppKit

private let log = Logger(subsystem: "io.bitward.dev.provider", category: "autofill")

/// Thin provider：金鑰與業務全在 daemon（契約 §1），本檔只做「翻譯請求 → BTP → 回候選」。
final class ProviderViewController: ASCredentialProviderViewController {
    override func loadView() {
        // 系統沒指定 storyboard/nib；給個乾淨容器避免預設 NSView 行為干擾。
        view = NSView(frame: NSRect(x: 0, y: 0, width: 480, height: 320))
        log.notice("provider VC loadView")
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        if #available(macOS 14.0, *), let request = credentialRequest as? ASPasskeyCredentialRequest {
            // Passkey 斷言靜默路徑：daemon 持鑰現簽，thin 端只搬運材料。
            guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
                extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            let rpID = identity.relyingPartyIdentifier
            let clientDataHash = request.clientDataHash
            log.notice("silent passkey rp=\(rpID, privacy: .public)")
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let credential = try Self.assertPasskey(rpID: rpID, clientDataHash: clientDataHash,
                                                            allowed: identity.credentialID,
                                                            fallbackHandle: identity.userHandle,
                                                            fallbackUser: identity.userName)
                    self.extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
                } catch {
                    log.notice("silent passkey cancel \(String(describing: error), privacy: .public)")
                    self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
                }
            }
            return
        }
        if #available(macOS 15.0, *), let request = credentialRequest as? ASOneTimeCodeCredentialRequest {
            // OTP 走靜默路徑：代碼由 daemon 現算（TotpCode），thin 端不碰 seed。
            let uri = request.credentialIdentity.serviceIdentifier.identifier
            log.notice("silent OTP request uri=\(uri, privacy: .public)")
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let code = try Self.resolveOtp(uri: uri)
                    self.extensionContext.completeOneTimeCodeRequest(
                        using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
                } catch {
                    log.notice("silent OTP cancel \(String(describing: error), privacy: .public)")
                    self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
                }
            }
            return
        }
        guard let request = credentialRequest as? ASPasswordCredentialRequest else {
            // passkey / text-to-insert 的正式處理在後續批次；先交回系統互動 UI，不靜默失敗（§8）。
            extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            return
        }
        // identifier 即 domain 或 URL 字串（ASCredentialServiceIdentifierType）；
        // daemon 端 Query.uri 負責匹配語意，thin 端不二次解讀。
        let uri = request.credentialIdentity.serviceIdentifier.identifier
        log.notice("silent request uri=\(uri, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let candidate = try Self.resolve(uri: uri)
                log.notice("silent fill ok id=\(candidate.id, privacy: .public)")
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
                log.notice("silent cancel code=\(code.rawValue)")
                self.extensionContext.cancelRequest(withError: ASExtensionError(code))
            } catch {
                log.notice("silent cancel unknown error")
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            }
        }
    }

    /// 互動路徑：使用者從 Safari 的 AutoFill 選單選了本 provider → 列候選清單，
    /// 點選某列後才 Reveal 密碼並完成請求。清單連線用較寬的 5s 預算
    /// （§8 的 1.5s 只約束靜默路徑——那條不能拖住 Safari 的表单流程）。
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let uri = serviceIdentifiers.first?.identifier ?? ""
        pendingUnlockUri = uri
        log.notice("interactive list uri=\(uri, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let items = try Self.listClient().list(uri: uri)
                log.notice("interactive list count=\(items.count)")
                DispatchQueue.main.async { self.showList(items) }
            } catch let error as BTPError {
                if error == .locked {
                    log.notice("interactive list locked")
                    DispatchQueue.main.async { self.showUnlock(uri: uri) }
                } else {
                    log.notice("interactive list failed \(String(describing: error), privacy: .public)")
                    DispatchQueue.main.async { self.showNote("無法連線 Bitward daemon（\(error)）") }
                }
            } catch {
                log.notice("interactive list failed unknown")
                DispatchQueue.main.async { self.showNote("無法連線 Bitward daemon（\(error)）") }
            }
        }
    }

    /// Locked 的互動引導：本機解鎖走裝置斷言（免密碼），一鍵即回清單。
    private func showUnlock(uri: String) {
        view.subviews.forEach { $0.removeFromSuperview() }
        let label = NSTextField(labelWithString: "Vault 目前鎖定")
        let button = NSButton(title: "解鎖", target: self, action: #selector(unlockTapped))
        button.bezelStyle = .rounded
        button.keyEquivalent = "\r"
        label.translatesAutoresizingMaskIntoConstraints = false
        button.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        view.addSubview(button)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -16),
            button.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            button.topAnchor.constraint(equalTo: label.bottomAnchor, constant: 10),
            view.widthAnchor.constraint(equalToConstant: 460),
            view.heightAnchor.constraint(equalToConstant: 140),
        ])
        preferredContentSize = NSSize(width: 460, height: 140)
        pendingUnlockUri = uri
    }

    private var pendingUnlockUri: String = ""

    @objc private func unlockTapped() {
        let uri = pendingUnlockUri
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                _ = try Self.listClient().unlock()
                let items = try Self.listClient().list(uri: uri)
                log.notice("unlock ok items=\(items.count)")
                DispatchQueue.main.async { self.showList(items) }
            } catch {
                log.notice("unlock failed \(String(describing: error), privacy: .public)")
                DispatchQueue.main.async { self.showNote("解鎖失敗（\(error)）") }
            }
        }
    }

    private enum ListRow {
        case password(BTPListItem)
        /// macOS Safari 不發第三方 OTP 請求（驗證碼氣泡是 Apple 簡訊中繼路徑）；
        /// 照 1Password 的 macOS 互動模型：清單多列一行，選取後以代碼完成表單填充。
        case otp(BTPListItem)
        var item: BTPListItem {
            switch self {
            case .password(let i), .otp(let i): return i
            }
        }
    }
    private var rows: [ListRow] = []
    private var tableView: NSTableView?

    private func showList(_ items: [BTPListItem]) {
        rows = items.flatMap { item in
            item.kind == "Login" ? [ListRow.password(item), ListRow.otp(item)] : [ListRow.password(item)]
        }
        if rows.isEmpty {
            showNote("此網站沒有相符的項目")
            return
        }
        view.subviews.forEach { $0.removeFromSuperview() }
        let table = NSTableView()
        for (key, title) in [("name", "名稱"), ("username", "網站")] {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(key))
            col.title = title
            col.width = key == "name" ? 220 : 260
            table.addTableColumn(col)
        }
        table.headerView = NSTableHeaderView()
        table.dataSource = self
        table.delegate = self
        table.target = self
        table.action = #selector(rowSelected)
        table.usesAlternatingRowBackgroundColors = true
        table.rowHeight = 34
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        // ViewBridge 拿 fittingSize；沒有固定尺寸的約束時面板會縮成 0×0（真機實測）。
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: view.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            view.widthAnchor.constraint(equalToConstant: 460),
            view.heightAnchor.constraint(equalToConstant: 240),
        ])
        preferredContentSize = NSSize(width: 460, height: 240)
        tableView = table
    }

    private func showNote(_ text: String) {
        view.subviews.forEach { $0.removeFromSuperview() }
        let label = NSTextField(wrappingLabelWithString: text)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.alignment = .center
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.widthAnchor.constraint(lessThanOrEqualToConstant: 380),
            view.widthAnchor.constraint(equalToConstant: 460),
            view.heightAnchor.constraint(equalToConstant: 140),
        ])
        preferredContentSize = NSSize(width: 460, height: 140)
    }

    @objc private func rowSelected() {
        let row = tableView?.selectedRow ?? -1
        guard row >= 0, row < rows.count else { return }
        let picked = rows[row]
        log.notice("selected id=\(picked.item.id, privacy: .public) kind=\(picked.item.kind, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let credential: ASPasswordCredential
                switch picked {
                case .password(let item):
                    let candidate = try Self.listClient().reveal(id: item.id)
                    log.notice("reveal ok user=\(candidate.username ?? "", privacy: .public)")
                    credential = ASPasswordCredential(user: candidate.username ?? "",
                                                      password: candidate.password ?? "")
                case .otp(let item):
                    let code = try Self.listClient().totp(id: item.id).code
                    log.notice("totp ok")
                    credential = ASPasswordCredential(user: "", password: code)
                }
                self.extensionContext.completeRequest(withSelectedCredential: credential,
                                                      completionHandler: { expired in
                    log.notice("completeRequest expired=\(expired)")
                })
            } catch let error as BTPError where error == .locked {
                // 清單可在鎖定下服務（加密 metadata），撞鎖的是 Reveal/TOTP：就地給解鎖鈕。
                log.notice("selection hit locked")
                DispatchQueue.main.async { self.showUnlock(uri: self.pendingUnlockUri) }
            } catch {
                log.notice("selection failed \(String(describing: error), privacy: .public)")
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            }
        }
    }

    /// Passkey 註冊：骨架無確認 UI，直接經 daemon 生成並回 credential
    /// （批准/UV 確認 UI 屬後續批次；本機 Interactive 連線本來就是「人」）。
    /// macOS 27 實測：走互動 sheet 路徑會命中系統 Helper 的 AppKit 斷言崩潰
    /// （NSViewControllerSheetTransition 無宿主窗），而我們的語意本就是自動同意，
    /// 故優先接 interactonless 入口（macOS 15+），prepareInterface 留作回退。
    @available(macOS 15.0, *)
    override func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        log.notice("passkey registration (interactionless)")
        runRegistration(registrationRequest)
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        log.notice("prepareInterface(passkeyReg) got \(type(of: registrationRequest), privacy: .public)")
        guard #available(macOS 14.0, *), let request = registrationRequest as? ASPasskeyCredentialRequest else {
            log.notice("cancel(.failed): unexpected request type")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        log.notice("passkey registration (interactive fallback)")
        // 不能立即 complete：系統在等「人同意」，搶跑會被判定 user denied。
        // 給一個確認按鈕（Apple 官方 sample 同形），按下才走 daemon。
        pendingRegistration = request
        showRegistrationConfirm()
    }

    private var pendingRegistration: (any ASCredentialRequest)?

    @MainActor
    private func showRegistrationConfirm() {
        view.subviews.forEach { $0.removeFromSuperview() }
        let label = NSTextField(labelWithString: "要把此站的 passkey 存进 Bitward 吗？")
        let button = NSButton(title: "储存 passkey", target: self, action: #selector(confirmRegistration))
        button.bezelStyle = .rounded
        button.keyEquivalent = "\r"
        label.translatesAutoresizingMaskIntoConstraints = false
        button.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        view.addSubview(button)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -16),
            button.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            button.topAnchor.constraint(equalTo: label.bottomAnchor, constant: 10),
            view.widthAnchor.constraint(equalToConstant: 460),
            view.heightAnchor.constraint(equalToConstant: 140),
        ])
        preferredContentSize = NSSize(width: 460, height: 140)
    }

    @objc private func confirmRegistration() {
        guard #available(macOS 14.0, *), let request = pendingRegistration as? ASPasskeyCredentialRequest else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        pendingRegistration = nil
        runRegistration(request)
    }

    @available(macOS 14.0, *)
    private func runRegistration(_ request: ASPasskeyCredentialRequest) {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            log.notice("cancel(.failed): identity not passkey")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        let rpID = identity.relyingPartyIdentifier
        let clientDataHash = request.clientDataHash
        let userName = identity.userName
        let userHandle = identity.userHandle
        let uv = request.userVerificationPreference.rawValue
        log.notice("passkey registration rp=\(rpID, privacy: .public) user=\(userName, privacy: .public) uv=\(uv, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                // 先做人驗證（provider = authenticator 的 UV），再請 daemon 簽。
                guard PasskeyUV.evaluate(reason: "要為「\(rpID)」儲存 passkey") else {
                    log.notice("uv declined")
                    self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                    return
                }
                let client = try Self.connect(budget: 5.0)
                let (cid, attestation) = try client.registerPasskey(
                    rpID: rpID, challenge: clientDataHash.b64url,
                    userName: userName, userHandle: userHandle.b64url, displayName: userName)
                guard let credentialID = Data(b64url: cid), let attObj = Data(b64url: attestation) else {
                    throw BTPError.protocolError("attestation not b64url")
                }
                if #available(macOS 14.0, *) {
                    let credential = ASPasskeyRegistrationCredential(
                        relyingParty: rpID, clientDataHash: clientDataHash,
                        credentialID: credentialID, attestationObject: attObj)
                    self.extensionContext.completeRegistrationRequest(using: credential, completionHandler: { expired in
                        log.notice("registration completeRequest expired=\(expired)")
                    })
                }
            } catch {
                log.notice("registration failed \(String(describing: error), privacy: .public)")
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            }
        }
    }

    @available(macOS 14.0, *)
    private static func assertPasskey(rpID: String, clientDataHash: Data, allowed: Data?,
                                      fallbackHandle: Data?, fallbackUser: String) throws -> ASPasskeyAssertionCredential {
        let client = try connect(budget: 1.5)
        let entries = try client.passkeys(rpID: rpID)
        guard !entries.isEmpty else { throw BTPError.noCredentials }
        // allowedCredentials 有給就對齐（b64url 比對），否則取首筆。
        let picked = allowed.flatMap { a in entries.first { $0.credentialId == a.b64url } } ?? entries[0]
        let (authData, _, signature) = try client.assertPasskey(credentialId: picked.credentialId,
                                                                clientDataHash: clientDataHash.b64url, rpID: rpID)
        guard let ad = Data(b64url: authData), let sig = Data(b64url: signature),
              let cid = Data(b64url: picked.credentialId) else {
            throw BTPError.protocolError("assertion material not b64url")
        }
        let userHandle = Data(b64url: picked.userHandle) ?? fallbackHandle ?? Data()
        return ASPasskeyAssertionCredential(userHandle: userHandle, relyingParty: rpID,
                                            signature: sig, clientDataHash: clientDataHash,
                                            authenticatorData: ad, credentialID: cid)
    }

    private static func resolve(uri: String) throws -> BTPCandidate {
        let client = try connect(budget: 1.5)
        return try client.autofill(uri: uri)
    }

    /// OTP 靜默路徑：uri 命中首筆後請 daemon 現算代碼。
    /// 無 seed 時 daemon 回錯，映射同 §8（交回互動）。
    private static func resolveOtp(uri: String) throws -> String {
        let client = try connect(budget: 1.5)
        let items = try client.list(uri: uri, limit: 5)
        guard let first = items.first else { throw BTPError.noCredentials }
        return try client.totp(id: first.id).code
    }

    private static func listClient() throws -> BTPClient {
        try connect(budget: 5.0)
    }

    private static func connect(budget: TimeInterval) throws -> BTPClient {
        guard let path = BitwardGroup.daemonSocketPath else { throw BTPError.daemonAbsent }
        return try BTPClient.connect(path: path, budget: budget)
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

extension ProviderViewController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = rows[row].item
        let isOtp: Bool
        if case .otp = rows[row] { isOtp = true } else { isOtp = false }
        let colId = tableColumn?.identifier.rawValue ?? "name"
        let text: String
        switch (colId, isOtp) {
        case ("name", true): text = "驗證碼 · \(item.name)"
        case ("name", false): text = item.name
        case (_, true): text = "TOTP"
        default: text = item.detail
        }
        // cell 重用識別字要帶欄位：兩欄共用一個 id 會互相搶 view，第二欄就空了。
        let id = NSUserInterfaceItemIdentifier("cell-\(colId)")
        let cell = (tableView.makeView(withIdentifier: id, owner: self) as? NSTextField) ?? {
            let f = NSTextField(labelWithString: "")
            f.identifier = id
            f.lineBreakMode = .byTruncatingTail
            return f
        }()
        cell.stringValue = text
        return cell
    }
}
