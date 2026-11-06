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
/// attestedCredentialData 存在（僅註冊）。
pub const FLAG_AT: u8 = 0x40;

/// 註冊用 flags：UP|UV|AT。
pub const FLAGS_REGISTER: u8 = FLAG_UP | FLAG_UV | FLAG_AT;
/// 斷言用 flags：UP|UV。
pub const FLAGS_ASSERT: u8 = FLAG_UP | FLAG_UV;

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

/// 私鑰 → COSE_Key（EC2/P-256/ES256）的 CBOR bytes。
/// 手寫 canonical 鍵序（RFC 8949 §4.2.1：鍵編碼位元組字典序 01,03,20,21,22）；
/// 77 bytes 定長。serde_cbor 的 BTreeMap 按整數值排序（-3,-2,-1,1,3）非 canonical。
pub fn cose_public_key(scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let vk = signing_key(scalar)?.verifying_key().to_encoded_point(false);
    let x = vk.x().ok_or(CryptoError::InvalidKey)?.to_vec();
    let y = vk.y().ok_or(CryptoError::InvalidKey)?.to_vec();
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

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// attestedCredentialData（L3 §6.1）：AAGUID(16) ‖ credIdLen(16be) ‖ credId ‖ COSE_Key。
/// AAGUID 取全零（本 daemon 無認證的 attester id）；rpIdHash 屬 authData 頭部，
/// 不在這裡重複（Safari 嚴格解析：多 32B 或長度欄 4B 都會整包拒收）。
fn attested_credential_data(credential_id: &[u8], scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cose = cose_public_key(scalar)?;
    let mut out = Vec::with_capacity(18 + credential_id.len() + cose.len());
    out.extend_from_slice(&[0u8; 16]); // AAGUID
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes()); // credIdLen: 16 位
    out.extend_from_slice(credential_id);
    out.extend_from_slice(&cose);
    Ok(out)
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
    let h = rp_id_hash(rp_id);
    let mut ad = auth_data_prefix(&h, FLAGS_REGISTER, counter);
    ad.extend_from_slice(&attested_credential_data(credential_id, scalar)?);
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
    let ad = registration_auth_data(rp_id, credential_id, scalar, counter)?;
    let mut obj = BTreeMap::new();
    obj.insert(
        CborValue::Text("fmt".into()),
        CborValue::Text("none".into()),
    );
    obj.insert(
        CborValue::Text("attStmt".into()),
        CborValue::Map(BTreeMap::new()),
    );
    obj.insert(CborValue::Text("authData".into()), CborValue::Bytes(ad));
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

/// 驗證斷言簽名：msg = authData ‖ sha256(clientDataJSON)，sig 為 raw r‖s。
pub fn verify_es256(
    pub_sec1: &[u8],
    auth_data: &[u8],
    client_data_json: &[u8],
    sig_raw: &[u8],
) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let Ok(vk) = VerifyingKey::from_sec1_bytes(pub_sec1) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig_raw) else {
        return false;
    };
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    vk.verify(&msg, &sig).is_ok()
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
    let sig = sig.to_bytes().to_vec();
    Ok(AssertionParts {
        authenticator_data: b64url(&ad),
        client_data_json: b64url(cdj.as_bytes()),
        signature: b64url(&sig),
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
        assert_eq!(ad[32], 0x45, "flags = UP|UV|AT（字面值）");
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
        assert_eq!(ad_bytes[32], 0x05, "flags = UP|UV（字面值）");
        assert_eq!(&ad_bytes[33..37], &[0x00, 0x00, 0x00, 0x02]);
        let cdj = b64url_decode(&parts.client_data_json).unwrap();
        assert_eq!(
            String::from_utf8(cdj.clone()).unwrap(),
            r#"{"challenge":"d2FsdGVyYXRl","crossOrigin":false,"origin":"https://webauthn.test","type":"webauthn.get"}"#
        );
        let mut msg = ad_bytes.clone();
        msg.extend_from_slice(&Sha256::digest(&cdj));
        let sig_raw = b64url_decode(&parts.signature).unwrap();
        assert_eq!(sig_raw.len(), 64, "raw r‖s");
        let (x, y) = cose_coords(&cose);
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        use p256::ecdsa::{Signature, signature::Verifier};
        let vk = VerifyingKey::from_sec1_bytes(&uncompressed).unwrap();
        assert!(
            vk.verify(&msg, &Signature::from_slice(&sig_raw).unwrap())
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
}
