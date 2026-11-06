import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// BTP 最小 client（契約 §2.5）：4-byte LE 長度前綴 + JSON 幀，externally-tagged serde。
/// 手刻 POSIX socket、不依賴 Rust bindings：provider extension 記憶體上限嚴，
/// 且 thin 端不該有第二份業務邏輯（macos-provider.md §1/§4）。
enum BTPError: Error, Equatable {
    case daemonAbsent          // connect 失敗：daemon 沒跑
    case timeout               // 超出 §8 的 1.5s 有界預算
    case locked                // Err(Locked)：清單頁給一鍵解鎖
    case needsInteraction      // NeedsApproval / StaleEpoch / Challenge
    case noCredentials         // 查詢成功但零候選
    case protocolError(String)
}

struct BTPCandidate {
    let id: String
    let username: String?
    let password: String?
}

/// Vault List 的 Metadata 視圖：互動清單只用這層，密碼要再 Reveal。
struct BTPListItem {
    let id: String
    let name: String
    /// metadata 分級表不含 username（屬 Secret），清單以首個 uri 呈現歸屬。
    let detail: String
    /// ItemKind 線格式（"Login" 等）；只有 Login 列附驗證碼行。
    let kind: String
}

final class BTPClient {
    /// 幀上限與 bw-btp 的 MAX_FRAME 對齊：解碼前擋住，不是解碼後。
    private static let maxFrame: UInt32 = 1024 * 1024

    private let fd: Int32
    private let deadline: Date

    private init(fd: Int32, deadline: Date) {
        self.fd = fd
        self.deadline = deadline
    }

    /// 總預算 ≤1.5s（契約 §8：有界重試後回 `.userInteractionRequired`，不靜默失敗）。
    static func connect(path: String, budget: TimeInterval = 1.5) throws -> BTPClient {
        let fd = socket(PF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BTPError.daemonAbsent }
        let deadline = Date().addingTimeInterval(budget)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        // sun_path 是 104 bytes 定長欄位；group container 路徑約 60，仍做防禦。
        guard path.utf8.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw BTPError.protocolError("socket path too long: \(path)")
        }
        memset(&addr, 0, MemoryLayout<sockaddr_un>.size)
        path.withCString { _ = memcpy(&addr.sun_path, $0, path.utf8.count) }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let err = errno
            guard err == EINPROGRESS else {
                close(fd)
                throw BTPError.daemonAbsent
            }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pr = poll(&pfd, 1, remainingMillis(deadline))
            var soerr: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            _ = getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len)
            if pr <= 0 || soerr != 0 {
                close(fd)
                throw pr == 0 ? BTPError.timeout : BTPError.daemonAbsent
            }
        }
        _ = fcntl(fd, F_SETFL, flags) // 恢復 blocking；後續靠 SO_RCVTIMEO/SO_SNDTIMEO 守 deadline
        applyTimeouts(fd: fd, deadline: deadline)
        return BTPClient(fd: fd, deadline: deadline)
    }

    deinit { close(fd) }

    private var enrolled = false
    /// Welcome.state 是否 Unlocked：identity store 等「明文投影」型消費者要據此
    /// 決定回填或清空——鎖定下 List 仍服務但 name 是密文信封，照寫會污染系統建議。
    private(set) var daemonUnlocked = false

    /// Hello(Enroll) → Welcome；同一連線內冪等（重複呼叫只發一次）。
    private func ensureEnrolled() throws {
        guard !enrolled else { return }
        try sendJSON(["Hello": [
            "version": 1,
            "auth": ["Enroll": ["pairing": BitwardGroup.pairingUUID(), "display_name": "provider"]],
            "wants": [Any](),
        ]])
        let welcome = try readFrames(until: { $0["Welcome"] != nil })
        if let w = welcome["Welcome"] as? [String: Any],
           let state = w["state"] as? [String: Any] {
            daemonUnlocked = state["Unlocked"] != nil
        }
        enrolled = true
    }

    /// 顯式觸發 enroll 後回傳解鎖態（daemonUnlocked 在 ensureEnrolled 內才賦值，
    /// 直接讀屬性會拿到未 enrolled 的預設 false）。
    func isUnlocked() throws -> Bool {
        try ensureEnrolled()
        return daemonUnlocked
    }

    /// Vault List(Metadata)：清單頁用，不觸碰密碼。
    func list(uri: String, limit: Int = 25) throws -> [BTPListItem] {
        try ensureEnrolled()
        // Query 欄位無 serde default：JSON 必須帶齊七鍵（對齊 bw-proto 的 struct 形態）。
        let query: [String: Any] = [
            "text": NSNull(), "tag": NSNull(), "uri": uri, "value": NSNull(),
            "kind": NSNull(), "sort": "Name", "limit": limit,
        ]
        try sendJSON(["Invoke": ["rid": 1, "call": ["Vault": ["List": ["query": query, "view": "Metadata"]]]]])
        let reply = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let rid = invoke["rid"] as? Int else { return false }
            return rid == 1
        })
        return try items(fromReply: reply).compactMap { item in
            guard let meta = item["meta"] as? [String: Any], let id = meta["id"] as? String else { return nil }
            let uris = (meta["uris"] as? [String]) ?? []
            return BTPListItem(id: id, name: meta["name"] as? String ?? id,
                               detail: uris.first ?? "", kind: meta["kind"] as? String ?? "")
        }
    }

    /// Get(Reveal)：只有使用者選取後才取實際密碼；需批准時 daemon 回 NeedsApproval → needsInteraction。
    func reveal(id: String) throws -> BTPCandidate {
        try ensureEnrolled()
        try sendJSON(["Invoke": ["rid": 2, "call": ["Vault": ["Get": ["id": id, "view": "Reveal"]]]]])
        let reveal = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let rid = invoke["rid"] as? Int else { return false }
            return rid == 2
        })
        let response = try response(fromReply: reveal)
        guard let item = response["Item"] as? [String: Any] else { throw BTPError.noCredentials }
        guard let password = item["password"] as? String else {
            throw BTPError.protocolError("Reveal view missing password key")
        }
        return BTPCandidate(id: id, username: item["username"] as? String, password: password)
    }

    /// Use(TotpCode)：目前有效的 30 秒代碼；清單選取與填充共用。
    func totp(id: String) throws -> (code: String, validForSecs: UInt32) {
        try ensureEnrolled()
        try sendJSON(["Invoke": ["rid": 3, "call": ["Use": ["TotpCode": ["id": id]]]]])
        let reply = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let rid = invoke["rid"] as? Int else { return false }
            return rid == 3
        })
        let response = try response(fromReply: reply)
        guard let totp = response["TotpCode"] as? [String: Any], let code = totp["code"] as? String else {
            throw BTPError.protocolError("Reply Ok is not TotpCode")
        }
        return (code, (totp["valid_for_secs"] as? UInt32) ?? 30)
    }

    /// Auth(Unlock{biometric:false})：本機 UDS 的裝置斷言解鎖，不需人在場輸入密碼。
    @discardableResult
    func unlock() throws -> Bool {
        try ensureEnrolled()
        try sendJSON(["Invoke": ["rid": 4, "call": ["Auth": ["Unlock": ["biometric": false]]]]])
        let reply = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let rid = invoke["rid"] as? Int else { return false }
            return rid == 4
        })
        _ = try response(fromReply: reply)
        return true
    }

    // MARK: - Passkey（Call::Passkey，worker 契約幀形）

    /// GetPasskeys：回 (credentialID, userHandle, userName) 全為 b64url 字串。
    func passkeys(rpID: String?) throws -> [(credentialId: String, userHandle: String, userName: String, rpId: String)] {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["GetPasskeys": ["rp_id": rpID as Any]]]
        let response = try invoke(rid: 7, call: call)
        guard let arr = response["Passkeys"] as? [[String: Any]] else { return [] }
        return arr.compactMap { row in
            guard let cid = row["credential_id"] as? String else { return nil }
            return (cid, row["user_handle"] as? String ?? "", row["user_name"] as? String ?? "",
                    row["rp_id"] as? String ?? "")
        }
    }

    /// RegisterPasskey → attestation object（b64url）＋新 credential id。
    func registerPasskey(rpID: String, challenge: String, userName: String,
                         userHandle: String, displayName: String) throws -> (credentialId: String, attestationObject: String) {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["RegisterPasskey": [
            "rp_id": rpID, "challenge": challenge, "user_name": userName,
            "user_handle": userHandle, "display_name": displayName, "item_id": NSNull(),
        ]]]
        let response = try invoke(rid: 8, call: call)
        guard let att = response["PasskeyAttestation"] as? [String: Any],
              let cid = att["credential_id"] as? String, let obj = att["attestation_object"] as? String else {
            throw BTPError.protocolError("Reply Ok is not PasskeyAttestation")
        }
        return (cid, obj)
    }

    /// AssertPasskey → 簽名材料（全 b64url）。Apple 流：challenge 與
    /// client_data_hash 都傳 b64url(clientDataHash 32B)——daemon 直接以 hash 簽
    /// （RP 驗的是系統將送的 clientDataJSON 之雜湊，自建 JSON 再雜湊必敗）。
    func assertPasskey(credentialId: String, clientDataHash: String, rpID: String) throws -> (authData: String, clientDataJSON: String, signature: String) {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["AssertPasskey": [
            "credential_id": credentialId, "challenge": clientDataHash, "rp_id": rpID,
            "client_data_hash": clientDataHash,
        ]]]
        let response = try invoke(rid: 9, call: call)
        guard let a = response["PasskeyAssertion"] as? [String: Any],
              let ad = a["authenticator_data"] as? String,
              let cd = a["client_data_json"] as? String,
              let sig = a["signature"] as? String else {
            throw BTPError.protocolError("Reply Ok is not PasskeyAssertion")
        }
        return (ad, cd, sig)
    }

    /// SE 流註冊第一步：daemon 預先協商 credential_id（Swift 以它作 SecKey tag）。
    func beginRegister(rpID: String, userName: String, userHandle: String,
                       displayName: String, itemId: String?) throws -> String {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["BeginRegister": [
            "rp_id": rpID, "user_name": userName, "user_handle": userHandle,
            "display_name": displayName, "item_id": itemId as Any,
        ]]]
        let response = try invoke(rid: 11, call: call)
        guard let begin = response["RegisterBegin"] as? [String: Any],
              let cid = begin["credential_id"] as? String else {
            throw BTPError.protocolError("Reply Ok is not RegisterBegin")
        }
        return cid
    }

    /// SE 流註冊第二步：提交 SPKI 公鑰（b64url），daemon 組 none-attestation。
    func finishRegister(credentialId: String, spkiPublicKey: String, rpID: String, challenge: String,
                        userName: String, userHandle: String,
                        displayName: String, itemId: String?) throws -> String /*attestation b64url*/ {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["FinishRegister": [
            "credential_id": credentialId, "credential_public_key": spkiPublicKey,
            "rp_id": rpID, "challenge": challenge, "user_name": userName,
            "user_handle": userHandle, "display_name": displayName, "item_id": itemId as Any,
        ]]]
        let response = try invoke(rid: 12, call: call)
        guard let att = response["PasskeyAttestation"] as? [String: Any],
              let obj = att["attestation_object"] as? String else {
            throw BTPError.protocolError("FinishRegister reply is not PasskeyAttestation")
        }
        return obj
    }

    /// SE 流斷言第一步：daemon 產 authData（含新 counter）回顯待簽。
    func beginAssert(credentialId: String, clientDataHash: String) throws -> String /*authenticator_data b64url*/ {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["BeginAssert": [
            "credential_id": credentialId, "client_data_hash": clientDataHash,
        ]]]
        let response = try invoke(rid: 13, call: call)
        guard let begin = response["AssertBegin"] as? [String: Any],
              let ad = begin["authenticator_data"] as? String else {
            throw BTPError.protocolError("BeginAssert reply is not AssertBegin")
        }
        return ad
    }

    /// SE 流斷言第二步：提交 SE 簽名（DER b64url），daemon 驗簽後才遞交 counter。
    func finishAssert(credentialId: String, signature: String) throws -> (authData: String, clientDataJSON: String, signature: String) {
        try ensureEnrolled()
        let call: [String: Any] = ["Passkey": ["FinishAssert": [
            "credential_id": credentialId, "signature": signature,
        ]]]
        let response = try invoke(rid: 14, call: call)
        guard let a = response["PasskeyAssertion"] as? [String: Any],
              let ad = a["authenticator_data"] as? String,
              let cd = a["client_data_json"] as? String,
              let sig = a["signature"] as? String else {
            throw BTPError.protocolError("FinishAssert reply is not PasskeyAssertion")
        }
        return (ad, cd, sig)
    }

    /// 授權治理類（ListPending／Approve）：批准中心用。
    func listPending() throws -> [(id: String, summary: String)] {
        try invoke(rid: 5, call: ["Agent": ["ListPending": NSNull()]])
        // Response::Sessions([{id, summary}])
        guard let arr = lastResponse?["Sessions"] as? [[String: Any]] else { return [] }
        return arr.compactMap { row in
            guard let id = row["id"] as? String else { return nil }
            return (id, row["summary"] as? String ?? "")
        }
    }

    func approve(id: String) throws {
        _ = try invoke(rid: 6, call: ["Agent": ["Approve": ["id": id, "grants": NSNull()]]])
    }

    func deny(id: String) throws {
        _ = try invoke(rid: 10, call: ["Agent": ["Deny": ["id": id]]])
    }

    private var lastResponse: [String: Any]?

    /// 通用 Invoke：回傳 Reply outcome 的 Ok 內容（rid 由呼叫端分配，避開清單流 1/2/3/4）。
    @discardableResult
    func invoke(rid: Int, call: [String: Any]) throws -> [String: Any] {
        try ensureEnrolled()
        try sendJSON(["Invoke": ["rid": rid, "call": call]])
        let reply = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let id = invoke["rid"] as? Int else { return false }
            return id == rid
        })
        let response = try response(fromReply: reply)
        lastResponse = response
        return response
    }

    /// 凍結流：Hello(Enroll) → List(Metadata by uri) → 取首筆 → Get(Reveal)。
    func autofill(uri: String) throws -> BTPCandidate {
        let items = try list(uri: uri, limit: 5)
        guard let first = items.first else { throw BTPError.noCredentials }
        return try reveal(id: first.id)
    }

    // MARK: - 幀處理

    /// Reply{rid, outcome: Ok(response) | Err(WtpError)}（serde externally-tagged）。
    private func response(fromReply frame: [String: Any]) throws -> [String: Any] {
        guard let reply = frame["Reply"] as? [String: Any] else {
            throw BTPError.protocolError("expected Reply")
        }
        guard let outcome = reply["outcome"] as? [String: Any] else {
            throw BTPError.protocolError("Reply without outcome")
        }
        if let err = outcome["Err"] {
            // WtpError 是 externally tagged：unit variant 為字串（"Locked"），
            // struct variant 為單鍵物件（{"Denied":{...}}）。只拆 Locked，
            // 其餘（NeedsApproval/Denied/StaleEpoch…）一律交回互動語意（§8）。
            let name: String
            if let s = err as? String { name = s }
            else if let d = err as? [String: Any] { name = d.keys.first ?? "" }
            else { name = "" }
            throw name == "Locked" ? BTPError.locked : BTPError.needsInteraction
        }
        guard let response = outcome["Ok"] as? [String: Any] else {
            throw BTPError.protocolError("Reply outcome without Ok/Err")
        }
        return response
    }

    private func items(fromReply frame: [String: Any]) throws -> [[String: Any]] {
        let response = try response(fromReply: frame)
        if case let list? = response["Items"] as? [[String: Any]] { return list }
        throw BTPError.protocolError("Reply Ok is not Items")
    }

    /// 讀幀直到 predicate 命中；跳過交錯的 Event，NeedApproval/Challenge 視為需互動。
    private func readFrames(until predicate: ([String: Any]) -> Bool) throws -> [String: Any] {
        while true {
            let frame = try recvJSON()
            if predicate(frame) { return frame }
            if frame["NeedApproval"] != nil || frame["Challenge"] != nil {
                throw BTPError.needsInteraction
            }
            if frame["Event"] == nil && frame["Welcome"] == nil {
                throw BTPError.protocolError("unexpected frame keys: \(frame.keys.sorted())")
            }
        }
    }

    private func recvJSON() throws -> [String: Any] {
        let header = try readExactly(4)
        let len = header.withUnsafeBytes { $0.load(as: UInt32.self) } // Darwin is LE on arm64/x86_64
        guard len > 0, len <= BTPClient.maxFrame else {
            throw BTPError.protocolError("bad frame length \(len)")
        }
        let data = try readExactly(Int(len))
        let obj = try JSONSerialization.jsonObject(with: data)
        guard let dict = obj as? [String: Any] else {
            throw BTPError.protocolError("frame is not a JSON object")
        }
        return dict
    }

    private func readExactly(_ count: Int) throws -> Data {
        var data = Data(capacity: count)
        var buf = [UInt8](repeating: 0, count: min(count, 65_536))
        while data.count < count {
            applyTimeouts(fd: fd, deadline: deadline)
            let n = recv(fd, &buf, min(buf.count, count - data.count), 0)
            if n > 0 {
                data.append(buf, count: n)
            } else if n == 0 {
                throw BTPError.protocolError("peer closed mid-frame")
            } else {
                if errno == EINTR { continue }
                throw errno == EAGAIN || errno == EWOULDBLOCK ? BTPError.timeout : BTPError.daemonAbsent
            }
        }
        return data
    }

    private func sendJSON(_ value: [String: Any]) throws {
        let payload = try JSONSerialization.data(withJSONObject: value)
        var frame = Data(capacity: payload.count + 4)
        var len = UInt32(payload.count).littleEndian
        withUnsafeBytes(of: &len) { frame.append(contentsOf: $0) }
        frame.append(payload)
        var offset = 0
        try frame.withUnsafeBytes { raw in
            while offset < frame.count {
                applyTimeouts(fd: fd, deadline: deadline)
                let n = send(fd, raw.baseAddress!.advanced(by: offset), frame.count - offset, 0)
                if n > 0 {
                    offset += n
                } else {
                    if errno == EINTR { continue }
                    throw errno == EAGAIN || errno == EWOULDBLOCK ? BTPError.timeout : BTPError.daemonAbsent
                }
            }
        }
    }

    // MARK: - 逾時

    private static func remainingMillis(_ deadline: Date) -> Int32 {
        Int32(max(1, deadline.timeIntervalSinceNow * 1000))
    }

    private static func applyTimeouts(fd: Int32, deadline: Date) {
        let seconds = max(0.001, deadline.timeIntervalSinceNow)
        var tv = timeval(tv_sec: Int(seconds), tv_usec: Int32((seconds - floor(seconds)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    private func applyTimeouts(fd: Int32, deadline: Date) {
        BTPClient.applyTimeouts(fd: fd, deadline: deadline)
    }
}
