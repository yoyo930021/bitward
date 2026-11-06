//! WebAuthn passkey 核心（macOS autofill 契約 §3）：ES256（COSE -7，P-256）
//! 金鑰生成、registration attestation（fmt=none）、assertion 簽名。
//! 自己實作 40 行核心，不引 webauthn-rs 整包；CBOR 用 serde_cbor。
//!
//! 佈局來源（WebAuthn L3 §6.1/§7.1/§7.3）：
//! - authData = sha256(rpId) ‖ flags ‖ counter(32be) [‖ attestedCredentialData]
//! - attestedCredentialData = AAGUID(16B) ‖ credIdLen(16be) ‖ credId ‖ COSE_Key
//!   （rpIdHash 只在 authData 頭出現一次，**不在** attestedCredentialData 內重複）
//! - clientDataJSON = {"type","challenge","origin","crossOrigin"}（challenge 逐字元原樣嵌入）
//! - 簽名 = ECDSA-P256-SHA256(authData ‖ sha256(clientDataJSON))，出棧轉 raw r‖s(64B)。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use rand::RngCore;
use serde_cbor::Value as CborValue;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::CryptoError;

/// authenticatorData flags：User Present。
pub const FLAG_UP: u8 = 0x01;
/// User Verified（本 daemon 以解鎖態作為 UV 的等價證明）。
pub const FLAG_UV: u8 = 0x04;
/// Backup Eligibility（FIDO2 L3 §6.1，bit 3，此前 reserved 留 0）。
pub const FLAG_BE: u8 = 0x08;
/// Backup State（bit 4；本實作憑證經 vault sync 備份，BE=BS=1 為真）。
pub const FLAG_BS: u8 = 0x10;
/// attestedCredentialData 存在（僅註冊）。
pub const FLAG_AT: u8 = 0x40;

/// 註冊用 flags：UP|UV|BE|BS|AT = 0x5D。
/// 斷言用 flags：UP|UV|BE|BS = 0x1D。
/// Apple provider（AuthenticationServicesCore）對第三方憑證強制 BE=1、BS=1：
/// 缺失 → 系統直接丟棄憑證、finishRegistration 不下發、頁面 NotAllowedError
/// （真機實測；KeePassium #444 實測矩陣、Apple 論壇 742209/813844；
/// 官方 Bitwarden/1Password/Dashlane 皆 0x5D/0x1D）。
pub const FLAGS_REGISTER: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;
pub const FLAGS_ASSERT: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

/// b64url（無 padding）：WebAuthn 各欄位的傳輸形態。
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// b64url 解碼；接受有無 padding 兩種寫法。
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    let t = s.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(t).map_err(|_| CryptoError::BadB64)
}

/// 新生成 P-256 私鑰スカラー（32 bytes，big-endian）。
/// keyValue 的明文就是這 32 bytes 的標準 base64（信封加密由呼叫端做）。
pub fn generate_private_key() -> Zeroizing<Vec<u8>> {
    loop {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&raw) {
            return Zeroizing::new(sk.to_bytes().to_vec());
        }
    }
}

fn signing_key(scalar: &[u8]) -> Result<p256::ecdsa::SigningKey, CryptoError> {
    p256::ecdsa::SigningKey::from_slice(scalar).map_err(|_| CryptoError::InvalidKey)
}

/// 公鑰位元組（SEC1 未壓縮/壓縮點，或 DER SubjectPublicKeyInfo）→ VerifyingKey。
/// SE 註冊流的 keyValue 是 SPKI；軟體流匯出的也是 SPKI——兩條路徑共用此解析。
fn verifying_key(bytes: &[u8]) -> Result<p256::ecdsa::VerifyingKey, CryptoError> {
    use p256::pkcs8::DecodePublicKey;
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes) {
        return Ok(vk);
    }
    p256::ecdsa::VerifyingKey::from_public_key_der(bytes).map_err(|_| CryptoError::InvalidKey)
}

/// 私鑰標量 → DER SubjectPublicKeyInfo（P-256 公鑰，91 bytes）。
/// Swift 端由 SecKey 匯出的正是同一形態；GetPasskeys.public_key 用它。
pub fn spki_from_scalar(scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use p256::pkcs8::EncodePublicKey;
    let doc = signing_key(scalar)?
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(doc.as_bytes().to_vec())
}

fn cose_from_verifying_key(vk: &p256::ecdsa::VerifyingKey) -> Result<Vec<u8>, CryptoError> {
    let pt = vk.to_encoded_point(false);
    let x = pt.x().ok_or(CryptoError::InvalidKey)?.to_vec();
    let y = pt.y().ok_or(CryptoError::InvalidKey)?.to_vec();
    if x.len() != 32 || y.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let mut out = Vec::with_capacity(77);
    out.extend_from_slice(&[
        0xA5, // map(5)
        0x01, 0x02, // 1 (kty) = 2 (EC2)
        0x03, 0x26, // 3 (alg) = -7 (ES256)
        0x20, 0x01, // -1 (crv) = 1 (P-256)
        0x21, 0x58, 0x20, // -2 (x) = bstr(32)
    ]);
    out.extend_from_slice(&x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]); // -3 (y) = bstr(32)
    out.extend_from_slice(&y);
    Ok(out)
}

/// 私鑰 → COSE_Key（EC2/P-256/ES256）的 CBOR bytes。
/// 手寫 canonical 鍵序（RFC 8949 §4.2.1：鍵編碼位元組字典序 01,03,20,21,22）；
/// 77 bytes 定長。serde_cbor 的 BTreeMap 按整數值排序（-3,-2,-1,1,3）非 canonical。
pub fn cose_public_key(scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    cose_from_verifying_key(signing_key(scalar)?.verifying_key())
}

/// DER SPKI（Swift 匯出的 SE 公鑰）→ 同上 COSE_Key bytes。
pub fn cose_public_key_from_spki(spki_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    cose_from_verifying_key(&verifying_key(spki_der)?)
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// attestedCredentialData（L3 §6.1）：AAGUID(16) ‖ credIdLen(16be) ‖ credId ‖ COSE_Key。
/// AAGUID 取全零（本 daemon 無認證的 attester id）；rpIdHash 屬 authData 頭部，
/// 不在這裡重複（Safari 嚴格解析：多 32B 或長度欄 4B 都會整包拒收）。
fn attested_credential_data(credential_id: &[u8], cose: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + credential_id.len() + cose.len());
    out.extend_from_slice(&[0u8; 16]); // AAGUID
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes()); // credIdLen: 16 位
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose);
    out
}

fn auth_data_prefix(rp_id_hash: &[u8; 32], flags: u8, counter: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

/// 註冊：authenticatorData（含 attestedCredentialData）bytes。
pub fn registration_auth_data(
    rp_id: &str,
    credential_id: &[u8],
    scalar: &[u8],
    counter: u32,
) -> Result<Vec<u8>, CryptoError> {
    registration_auth_data_cose(rp_id, credential_id, &cose_public_key(scalar)?, counter)
}

/// 註冊（SE 公鑰流）：COSE 段由 DER SPKI 匯入的 P-256 公鑰產生。
pub fn registration_auth_data_from_spki(
    rp_id: &str,
    credential_id: &[u8],
    spki_der: &[u8],
    counter: u32,
) -> Result<Vec<u8>, CryptoError> {
    registration_auth_data_cose(
        rp_id,
        credential_id,
        &cose_public_key_from_spki(spki_der)?,
        counter,
    )
}

fn registration_auth_data_cose(
    rp_id: &str,
    credential_id: &[u8],
    cose: &[u8],
    counter: u32,
) -> Result<Vec<u8>, CryptoError> {
    let h = rp_id_hash(rp_id);
    let mut ad = auth_data_prefix(&h, FLAGS_REGISTER, counter);
    ad.extend_from_slice(&attested_credential_data(credential_id, cose));
    Ok(ad)
}

/// 註冊：attestation object（fmt=none、attStmt={}）→ b64url 字串。
/// 內部含 authData，故 rpIdHash 已「內含」（契約 §3）。
pub fn attestation_object(
    rp_id: &str,
    credential_id: &[u8],
    scalar: &[u8],
    counter: u32,
) -> Result<String, CryptoError> {
    attestation_object_from_ad(&registration_auth_data(
        rp_id,
        credential_id,
        scalar,
        counter,
    )?)
}

/// 註冊（SE 公鑰流）：同 `attestation_object`，但 attestedCredentialData 的
/// COSE 段取自 Swift 匯出的 DER SPKI（私鑰在 Secure Enclave，daemon 從未見過）。
pub fn attestation_object_from_spki(
    rp_id: &str,
    credential_id: &[u8],
    spki_der: &[u8],
    counter: u32,
) -> Result<String, CryptoError> {
    attestation_object_from_ad(&registration_auth_data_from_spki(
        rp_id,
        credential_id,
        spki_der,
        counter,
    )?)
}

fn attestation_object_from_ad(ad: &[u8]) -> Result<String, CryptoError> {
    let mut obj = BTreeMap::new();
    obj.insert(
        CborValue::Text("fmt".into()),
        CborValue::Text("none".into()),
    );
    obj.insert(
        CborValue::Text("attStmt".into()),
        CborValue::Map(BTreeMap::new()),
    );
    obj.insert(
        CborValue::Text("authData".into()),
        CborValue::Bytes(ad.to_vec()),
    );
    let cbor = serde_cbor::to_vec(&CborValue::Map(obj)).map_err(|_| CryptoError::InvalidKey)?;
    Ok(b64url(&cbor))
}

/// 斷言三段輸出（全部 b64url）；counter 由呼叫端決定並持久化。
#[derive(Clone, Debug)]
pub struct AssertionParts {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// clientDataJSON（webauthn.get）。challenge 原樣嵌入（不重新編碼），
/// 逐字元對齊由呼叫端傳入的 b64url 保證。
pub fn client_data_json(challenge_b64url: &str, rp_id: &str) -> String {
    serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": format!("https://{rp_id}"),
        "crossOrigin": false,
    })
    .to_string()
}

/// 私鑰標量 → SEC1 未壓縮公鑰（0x04‖x‖y，65B）。驗證端（測試/依賴方模擬）用。
pub fn public_key_sec1(scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(signing_key(scalar)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// 驗證斷言簽名：msg = authData ‖ sha256(clientDataJSON)，sig 為 DER（也收 raw）。
pub fn verify_es256(
    pub_sec1: &[u8],
    auth_data: &[u8],
    client_data_json: &[u8],
    sig_raw: &[u8],
) -> bool {
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    verify_es256_signing_input(pub_sec1, &msg, sig_raw)
}

/// 驗證「原始簽名輸入」：msg = authenticator_data ‖ clientDataHash(32B 本體)。
/// 這是 Apple provider 流 / Swift SE 簽名的校驗入口——與 `verify_es256`
/// 的「對 JSON 再雜湊」不同，混用必錯（hash 多雜湊一次 → 驗簽必敗）。
/// pub_key 收 SEC1 點或 DER SPKI；sig 收 DER（WebAuthn 出棧形態）或 raw r‖s。
pub fn verify_es256_signing_input(pub_key: &[u8], signing_input: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::{Signature, signature::Verifier};
    let Ok(vk) = verifying_key(pub_key) else {
        return false;
    };
    // WebAuthn 出棧是 DER；測試/內部路徑可能給 raw——兩種都收。
    let Ok(sig) = Signature::from_der(sig).or_else(|_| Signature::from_slice(sig)) else {
        return false;
    };
    vk.verify(signing_input, &sig).is_ok()
}

/// 私鑰標量 → 對任意簽名輸入的 ECDSA-P256-SHA256 DER 簽名。
/// 兩步斷言流中測試/CLI 模擬 Swift 側的 SE 簽名用；出棧形態同 WebAuthn（DER）。
pub fn sign_es256(scalar: &[u8], signing_input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig: p256::ecdsa::Signature = signing_key(scalar)?.sign(signing_input);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// 斷言：authData(flags=UP|UV, counter++)、clientDataJSON、raw r‖s 簽名。
pub fn assertion(
    rp_id: &str,
    scalar: &[u8],
    counter: u32,
    challenge_b64url: &str,
) -> Result<AssertionParts, CryptoError> {
    let ad = auth_data_prefix(&rp_id_hash(rp_id), FLAGS_ASSERT, counter);
    let cdj = client_data_json(challenge_b64url, rp_id);
    let mut payload = ad.clone();
    payload.extend_from_slice(&Sha256::digest(cdj.as_bytes()));
    let sig: p256::ecdsa::Signature = signing_key(scalar)?.sign(&payload);
    // WebAuthn L1 §7.2：response.signature 是 **DER** ASN.1 ECDSA-Sig-Value
    // （raw r‖s 是 COSE/JWT 紀律，不是 WebAuthn 的——真機 RP 驗簽實測）。
    let sig = sig.to_der().as_bytes().to_vec();
    Ok(AssertionParts {
        authenticator_data: b64url(&ad),
        client_data_json: b64url(cdj.as_bytes()),
        signature: b64url(&sig),
    })
}

/// 斷言用 authenticatorData（flags=UP|UV，無 attestedCredentialData）。
/// 兩步流（BeginAssert）先回給 Swift 簽，FinishAssert 驗完才持久化 counter。
pub fn assertion_auth_data(rp_id: &str, counter: u32) -> Vec<u8> {
    auth_data_prefix(&rp_id_hash(rp_id), FLAGS_ASSERT, counter)
}

/// Apple provider 流：系統只給 clientDataHash（32B，即 sha256(系統將送 RP 的
/// clientDataJSON)）。簽名輸入 = authData ‖ hash 本體，不再自建 JSON 雜湊。
/// 回傳的 client_data_json 僅供除錯顯示（challenge 欄放 hash 本身）。
pub fn assertion_with_hash(
    rp_id: &str,
    scalar: &[u8],
    counter: u32,
    client_data_hash: &[u8],
) -> Result<AssertionParts, CryptoError> {
    if client_data_hash.len() != 32 {
        return Err(CryptoError::InvalidLength);
    }
    let ad = auth_data_prefix(&rp_id_hash(rp_id), FLAGS_ASSERT, counter);
    let mut payload = ad.clone();
    payload.extend_from_slice(client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key(scalar)?.sign(&payload);
    Ok(AssertionParts {
        authenticator_data: b64url(&ad),
        client_data_json: b64url(client_data_json(&b64url(client_data_hash), rp_id).as_bytes()),
        signature: b64url(sig.to_der().as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;

    /// 獨立視角解析器：不用本模組任何佈局常數/組裝函數，
    /// 按 FIDO2 L3 §6.1 手撕固定位元組偏移。回傳 (credId, COSE bytes)。
    fn parse_authdata_independent(ad: &[u8], cose_len: usize) -> (Vec<u8>, Vec<u8>) {
        // 標頭：rpIdHash(32) ‖ flags(1) ‖ counter(4)
        let expect_total = 32 + 1 + 4 + 16 + 2 + 32 + cose_len;
        assert_eq!(ad.len(), expect_total, "authData 總長");
        assert_eq!(ad[32], 0x5D, "flags = UP|UV|BE|BS|AT（字面值）");
        assert_eq!(&ad[33..37], &[0x00, 0x00, 0x00, 0x01], "counter=1（32be）");
        // attestedCredentialData：AAGUID(16) ‖ credIdLen(2) ‖ credId(32) ‖ COSE
        assert_eq!(&ad[37..53], &[0u8; 16][..], "AAGUID 全零");
        assert_eq!(
            u16::from_be_bytes(ad[53..55].try_into().unwrap()),
            32,
            "credIdLen 必須是 16 位元組大端＝32"
        );
        let cred_id = ad[55..87].to_vec();
        let cose = ad[87..].to_vec();
        assert_eq!(cose.len(), cose_len);
        (cred_id, cose)
    }

    /// COSE bytes → (x, y)，用 serde_cbor + p256 公開 API 反解（不碰產生端）。
    fn cose_coords(cose: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let v: CborValue = serde_cbor::from_slice(cose).unwrap();
        let CborValue::Map(m) = v else {
            panic!("COSE_Key must be a map")
        };
        let int = |k: i128| {
            assert_eq!(
                m.get(&CborValue::Integer(k)),
                Some(&CborValue::Integer(match k {
                    1 => 2,
                    3 => -7,
                    -1 => 1,
                    _ => unreachable!(),
                })),
                "cose key {k}"
            )
        };
        int(1);
        int(3);
        int(-1);
        let bytes = |k: i128| -> Vec<u8> {
            match m.get(&CborValue::Integer(k)) {
                Some(CborValue::Bytes(b)) => b.clone(),
                other => panic!("cose key {k} not bytes: {other:?}"),
            }
        };
        (bytes(-2), bytes(-3))
    }

    #[test]
    fn registration_authdata_fido2_byte_layout() {
        let scalar = generate_private_key();
        let cred_id: Vec<u8> = (0u8..32).collect(); // 遞增花樣：任何錯位都瞞不過
        let ad = registration_auth_data("cbor.test", &cred_id, &scalar, 1).unwrap();
        assert_eq!(&ad[0..32], &Sha256::digest(b"cbor.test")[..], "rpIdHash");
        let (parsed_id, cose) = parse_authdata_independent(&ad, 77);
        assert_eq!(parsed_id, cred_id, "ACD 內 credId == 頂層 credential_id");
        // canonical 鍵序前導 10 字节：map(5), 1=>2, 3=>-7, -1=>1, -2=>bstr32
        assert_eq!(
            &cose[..10],
            &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        // COSE x/y 反解出的公鑰必須等於生成鑰
        let (x, y) = cose_coords(&cose);
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        let vk_from_cose = VerifyingKey::from_sec1_bytes(&uncompressed).unwrap();
        let vk_generated =
            VerifyingKey::from(&p256::ecdsa::SigningKey::from_slice(&scalar).unwrap());
        assert_eq!(
            vk_from_cose.to_encoded_point(false).as_bytes(),
            vk_generated.to_encoded_point(false).as_bytes(),
            "COSE 公鑰必須與生成私鑰一致"
        );
    }

    #[test]
    fn attestation_object_wraps_authdata_verbatim() {
        let scalar = generate_private_key();
        let cred_id = vec![0xab; 32];
        let ad = registration_auth_data("webauthn.test", &cred_id, &scalar, 1).unwrap();
        let att = attestation_object("webauthn.test", &cred_id, &scalar, 1).unwrap();
        let obj: CborValue = serde_cbor::from_slice(&b64url_decode(&att).unwrap()).unwrap();
        let CborValue::Map(m) = obj else {
            panic!("attestation must be a map")
        };
        assert_eq!(
            m.get(&CborValue::Text("fmt".into())),
            Some(&CborValue::Text("none".into()))
        );
        assert_eq!(
            m.get(&CborValue::Text("attStmt".into())),
            Some(&CborValue::Map(BTreeMap::new()))
        );
        let CborValue::Bytes(ad2) = m.get(&CborValue::Text("authData".into())).unwrap() else {
            panic!("authData must be bytes")
        };
        assert_eq!(ad2, &ad);
        parse_authdata_independent(ad2, 77);
    }

    #[test]
    fn assertion_with_hash_signs_over_raw_hash() {
        // Apple 流：簽名輸入 = authData ‖ clientDataHash（非自建 JSON 的雜湊）。
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let scalar = generate_private_key();
        let hash = [7u8; 32];
        let a = assertion_with_hash("apple.test", &scalar, 9, &hash).unwrap();
        let ad = b64url_decode(&a.authenticator_data).unwrap();
        let sig = b64url_decode(&a.signature).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&public_key_sec1(&scalar).unwrap()).unwrap();
        let mut msg = ad.clone();
        msg.extend_from_slice(&hash);
        assert!(
            vk.verify(
                &msg,
                &Signature::from_der(&sig)
                    .or_else(|_| Signature::from_slice(&sig))
                    .unwrap()
            )
            .is_ok(),
            "hash 直簽必須以 authData‖hash 驗通"
        );
        // 與自建 JSON 雜湊路徑不同輸入 → 簽不同
        let b = assertion("apple.test", &scalar, 9, &b64url(&hash)).unwrap();
        assert_ne!(a.signature, b.signature);
        assert_eq!(ad.len(), 37);
    }

    #[test]
    fn register_then_assert_roundtrip() {
        let scalar = generate_private_key();
        let cred_id = vec![0xab; 32];
        let ad = registration_auth_data("webauthn.test", &cred_id, &scalar, 1).unwrap();
        let (_parsed_id, cose) = parse_authdata_independent(&ad, 77);

        let parts = assertion("webauthn.test", &scalar, 2, "d2FsdGVyYXRl").unwrap();
        let ad_bytes = b64url_decode(&parts.authenticator_data).unwrap();
        // 斷言 authData（無 AT）：恰好 37B，佈局不受註冊端修復波及
        assert_eq!(ad_bytes.len(), 37, "assertion authData = 32+1+4，無 ACD");
        assert_eq!(&ad_bytes[0..32], &Sha256::digest(b"webauthn.test")[..]);
        assert_eq!(ad_bytes[32], 0x1D, "flags = UP|UV|BE|BS（字面值）");
        assert_eq!(&ad_bytes[33..37], &[0x00, 0x00, 0x00, 0x02]);
        let cdj = b64url_decode(&parts.client_data_json).unwrap();
        assert_eq!(
            String::from_utf8(cdj.clone()).unwrap(),
            r#"{"challenge":"d2FsdGVyYXRl","crossOrigin":false,"origin":"https://webauthn.test","type":"webauthn.get"}"#
        );
        let mut msg = ad_bytes.clone();
        msg.extend_from_slice(&Sha256::digest(&cdj));
        let sig_raw = b64url_decode(&parts.signature).unwrap();
        assert_eq!(sig_raw[0], 0x30, "DER SEQUENCE 頭（WebAuthn 簽名紀律）");
        let (x, y) = cose_coords(&cose);
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        use p256::ecdsa::{Signature, signature::Verifier};
        let vk = VerifyingKey::from_sec1_bytes(&uncompressed).unwrap();
        assert!(
            vk.verify(&msg, &Signature::from_der(&sig_raw).unwrap())
                .is_ok(),
            "attestation 內 COSE 公鑰必須驗通 assertion 簽名"
        );
    }

    #[test]
    fn client_data_challenge_is_verbatim() {
        // challenge 含 b64url 特殊字元（-、_）：必須逐字元原樣嵌入
        let cdj = client_data_json("a-_b", "ex.io");
        assert!(cdj.contains(r#""challenge":"a-_b""#), "{cdj}");
        assert!(cdj.contains(r#""origin":"https://ex.io""#));
    }

    #[test]
    fn b64url_roundtrip_with_padding_input() {
        let s = b64url(&[0xff, 0xfe, 0x00]);
        assert!(!s.contains('='));
        assert_eq!(b64url_decode(&s).unwrap(), vec![0xff, 0xfe, 0x00]);
        assert_eq!(
            b64url_decode(&format!("{s}==")).unwrap(),
            vec![0xff, 0xfe, 0x00]
        );
    }

    #[test]
    fn spki_export_import_is_lossless() {
        let sk = generate_private_key();
        let spki = spki_from_scalar(&sk).unwrap();
        // SPKI → COSE 與標量直出 COSE 逐位元組相同（x/y 一致）
        assert_eq!(
            cose_public_key_from_spki(&spki).unwrap(),
            cose_public_key(&sk).unwrap()
        );
        // SPKI 可被 SEC1 路徑解析（verifying_key 兩形態都吃）
        let sec1 = public_key_sec1(&sk).unwrap();
        let vk_from_spki = verifying_key(&spki).unwrap();
        let vk_from_sec1 = verifying_key(&sec1).unwrap();
        assert_eq!(vk_from_spki.to_sec1_bytes(), vk_from_sec1.to_sec1_bytes());
    }

    #[test]
    fn signing_input_verify_distinguishes_raw_hash_from_json_hash() {
        let sk = generate_private_key();
        let spki = spki_from_scalar(&sk).unwrap();
        let hash = [3u8; 32];
        let ad = assertion_auth_data("webauthn.test", 7);
        let mut input = ad.clone();
        input.extend_from_slice(&hash);
        let sig = sign_es256(&sk, &input).unwrap();
        assert!(
            verify_es256_signing_input(&spki, &input, &sig),
            "SPKI 驗 SE 流簽名"
        );
        assert!(verify_es256_signing_input(
            &public_key_sec1(&sk).unwrap(),
            &input,
            &sig
        ));
        // 混用「對 JSON 再雜湊」的舊訊息必須驗不過（事務根因防護）
        let cdj = client_data_json(&b64url(&hash), "webauthn.test");
        assert!(
            !verify_es256_signing_input(&spki, &ad, &sig),
            "少了 hash 尾段的訊息不得誤通過"
        );
        assert!(!verify_es256(&spki, &ad, cdj.as_bytes(), &sig));
        // counter 欄被改 → authData 不同 → 驗不過
        let mut tampered = ad.clone();
        tampered[36] ^= 0x01;
        let mut tampered_input = tampered.clone();
        tampered_input.extend_from_slice(&hash);
        assert!(!verify_es256_signing_input(&spki, &tampered_input, &sig));
    }

    #[test]
    fn attestation_from_spki_matches_software_attestation() {
        let sk = generate_private_key();
        let spki = spki_from_scalar(&sk).unwrap();
        let cred = [9u8; 32];
        let a = attestation_object("webauthn.test", &cred, &sk, 1).unwrap();
        let b = attestation_object_from_spki("webauthn.test", &cred, &spki, 1).unwrap();
        assert_eq!(
            a, b,
            "SPKI 流 attestation 與軟體流逐位元組同（COSE 段同源）"
        );
    }
}
