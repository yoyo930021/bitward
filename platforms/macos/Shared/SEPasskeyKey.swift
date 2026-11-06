import Foundation
import Security

/// Passkey 私鑰 = Secure Enclave 金鑰，綁生物辨識（WebAuthn L1 §6.1：UV 位元
/// 可信的前提是簽名由 UV 綁定金鑰產生；純軟體鑰＋LAContext 宣告式 UV 實測被
/// WebKit/RP 拒收）。金鑰存 app-group keychain（共用 access group 給容器 App），
/// 每次 SecKeyCreateSignature 由 userPresence 自動彈 Touch ID。
enum SEPasskeyKey {
    enum Err: Error {
        case genFailed(String)
        case exportFailed(String)
        case signFailed(String)
        case notFound
    }

    private static let accessGroup = BitwardGroup.keychainAccessGroup

    /// 產生 SE ES256 私鑰；tag 即憑證 id 原料（32B 隨機，前綴 4B 辨識用）。
    static func create(tag: Data) -> SecKey? {
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryCurrentSet, .privateKeyUsage, .userPresence],
            &error) else {
            NSLog("bitward se: access control failed \(error?.takeRetainedValue().localizedDescription ?? "?")")
            return nil
        }
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: accessGroup,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: ac,
            ],
        ]
        return SecKeyCreateRandomKey(attrs as CFDictionary, &error)
    }

    /// 公鑁匯出（SecKey 給的是 SEC1 未壓縮點 0x04‖X‖Y）。
    static func publicKeySEC1(tag: Data) -> Result<Data, Err> {
        guard let key = copyKey(tag: tag) else { return .failure(.notFound) }
        var error: Unmanaged<CFError>?
        guard let pub = SecKeyCopyExternalRepresentation(key, &error) else {
            return .failure(.exportFailed(error?.takeRetainedValue().localizedDescription ?? "?"))
        }
        return .success(pub as Data)
    }

    /// 簽 authData ‖ clientDataHash（WebAuthn 斷言）。userPresence 金鑰會觸發
    /// Touch ID；回傳 DER ECDSA-Sig-Value（WebAuthn L1 §7.2 紀律）。
    static func sign(tag: Data, authData: Data, clientDataHash: Data) -> Result<Data, Err> {
        guard let key = copyKey(tag: tag) else { return .failure(.notFound) }
        var payload = authData
        payload.append(clientDataHash)
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              payload as CFData, &error) else {
            return .failure(.signFailed(error?.takeRetainedValue().localizedDescription ?? "?"))
        }
        return .success(sig as Data)
    }

    static func delete(tag: Data) {
        SecItemDelete([kSecClass: kSecClassKey,
                       kSecUseDataProtectionKeychain: true,
                       kSecAttrApplicationTag: tag] as CFDictionary)
    }

    private static func copyKey(tag: Data) -> SecKey? {
        var out: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return (out as! SecKey)
    }

    /// SEC1 未壓縮點 → DER SubjectPublicKeyInfo（EC + prime256v1 + BIT STRING）。
    /// DER 前綴固定（RFC 5480）：30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 ‖ SEC1
    static func sec1ToSPKI(_ sec1: Data) -> Data {
        var spki = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                         0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])
        spki.append(sec1)
        return spki
    }
}
