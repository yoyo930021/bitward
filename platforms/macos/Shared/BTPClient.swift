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
    case needsInteraction      // Locked / NeedsApproval / StaleEpoch / Challenge
    case noCredentials         // 查詢成功但零候選
    case protocolError(String)
}

struct BTPCandidate {
    let id: String
    let username: String?
    let password: String?
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

    /// 凍結流：Hello(Enroll) → Welcome → Invoke Vault List(Metadata by uri) → Reply，
    /// 再以 Get(Reveal) 取首筆的實際密碼；Reveal 需批准時 daemon 回 NeedsApproval → needsInteraction。
    func autofill(uri: String) throws -> BTPCandidate {
        try sendJSON(["Hello": [
            "version": 1,
            "auth": ["Enroll": ["pairing": BitwardGroup.pairingUUID(), "display_name": "provider"]],
            "wants": [Any](),
        ]])
        let welcome = try readFrames(until: { $0["Welcome"] != nil })
        _ = welcome

        // Query 欄位無 serde default：JSON 必須帶齊七鍵（對齊 bw-proto 的 struct 形態）。
        let query: [String: Any] = [
            "text": NSNull(), "tag": NSNull(), "uri": uri, "value": NSNull(),
            "kind": NSNull(), "sort": "Name", "limit": 5,
        ]
        try sendJSON(["Invoke": ["rid": 1, "call": ["Vault": ["List": ["query": query, "view": "Metadata"]]]]])
        let reply = try readFrames(until: { frame in
            guard let invoke = frame["Reply"] as? [String: Any], let rid = invoke["rid"] as? Int else { return false }
            return rid == 1
        })
        let items = try items(fromReply: reply)
        guard let first = items.first, let id = (first["meta"] as? [String: Any])?["id"] as? String else {
            throw BTPError.noCredentials
        }

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

    // MARK: - 幀處理

    /// Reply{rid, outcome: Ok(response) | Err(WtpError)}（serde externally-tagged）。
    private func response(fromReply frame: [String: Any]) throws -> [String: Any] {
        guard let reply = frame["Reply"] as? [String: Any] else {
            throw BTPError.protocolError("expected Reply")
        }
        guard let outcome = reply["outcome"] as? [String: Any] else {
            throw BTPError.protocolError("Reply without outcome")
        }
        if outcome["Err"] != nil {
            // Locked / NeedsApproval / StaleEpoch / Denied 一律交回互動路徑（§8 語意）
            throw BTPError.needsInteraction
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
