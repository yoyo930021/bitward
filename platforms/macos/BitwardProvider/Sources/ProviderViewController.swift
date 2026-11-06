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
        guard let request = credentialRequest as? ASPasswordCredentialRequest else {
            // OTP / text-to-insert 的正式處理在 P5；先交回系統互動 UI，不靜默失敗（§8）。
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
        log.notice("interactive list uri=\(uri, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let items = try Self.listClient().list(uri: uri)
                log.notice("interactive list count=\(items.count)")
                DispatchQueue.main.async { self.showList(items) }
            } catch {
                log.notice("interactive list failed \(String(describing: error), privacy: .public)")
                DispatchQueue.main.async { self.showNote("無法連線 Bitward daemon（\(error)）") }
            }
        }
    }

    private var listItems: [BTPListItem] = []
    private var tableView: NSTableView?

    private func showList(_ items: [BTPListItem]) {
        listItems = items
        if items.isEmpty {
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
        guard row >= 0, row < listItems.count else { return }
        let picked = listItems[row]
        log.notice("selected id=\(picked.id, privacy: .public)")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let candidate = try Self.listClient().reveal(id: picked.id)
                log.notice("reveal ok user=\(candidate.username ?? "", privacy: .public)")
                let credential = ASPasswordCredential(user: candidate.username ?? "",
                                                      password: candidate.password ?? "")
                self.extensionContext.completeRequest(withSelectedCredential: credential,
                                                      completionHandler: { expired in
                    log.notice("completeRequest expired=\(expired)")
                })
            } catch {
                log.notice("reveal failed \(String(describing: error), privacy: .public)")
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
            }
        }
    }

    private static func resolve(uri: String) throws -> BTPCandidate {
        let client = try connect(budget: 1.5)
        return try client.autofill(uri: uri)
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
    func numberOfRows(in tableView: NSTableView) -> Int { listItems.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = listItems[row]
        let colId = tableColumn?.identifier.rawValue ?? "name"
        let text = colId == "name" ? item.name : item.detail
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
