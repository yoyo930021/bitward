//! WebAuthn passkey 核心（macOS autofill 契約 §3）：ES256（COSE -7，P-256）
//! 金鑰生成、registration attestation（fmt=none）、assertion 簽名。
//! 自己實作 40 行核心，不引 webauthn-rs 整包；CBOR 用 serde_cbor。
//!
//! 佈局來源（WebAuthn L3 §6.1/§7.1/§7.3）：
//! - authData = sha256(rpId) ‖ flags ‖ counter(32be) [‖ attestedCredentialData]
//! - attestedCredentialData = rpIdHash ‖ AAGUID(16B) ‖ credIdLen(32be) ‖ credId ‖ COSE_Key
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
pub fn cose_public_key(scalar: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let vk = signing_key(scalar)?.verifying_key().to_encoded_point(false);
    let x = vk.x().ok_or(CryptoError::InvalidKey)?;
    let y = vk.y().ok_or(CryptoError::InvalidKey)?;
    let mut m = BTreeMap::new();
    m.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty = EC2
    m.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg = ES256
    m.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv = P-256
    m.insert(CborValue::Integer(-2), CborValue::Bytes(x.to_vec()));
    m.insert(CborValue::Integer(-3), CborValue::Bytes(y.to_vec()));
    serde_cbor::to_vec(&CborValue::Map(m)).map_err(|_| CryptoError::InvalidKey)
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// attestedCredentialData（L3 §6.1）：AAGUID 取全零（本 daemon 無認證的 attester id）。
fn attested_credential_data(
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    scalar: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cose = cose_public_key(scalar)?;
    let mut out = Vec::with_capacity(52 + credential_id.len() + cose.len());
    out.extend_from_slice(rp_id_hash);
    out.extend_from_slice(&[0u8; 16]); // AAGUID
    out.extend_from_slice(&(credential_id.len() as u32).to_be_bytes());
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
    ad.extend_from_slice(&attested_credential_data(&h, credential_id, scalar)?);
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

    fn verify_with_cose(cose: &[u8], msg: &[u8], sig_raw: &[u8]) -> Option<bool> {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let v: CborValue = serde_cbor::from_slice(cose).unwrap();
        let CborValue::Map(m) = v else { return None };
        let get = |k: i128| -> Option<&Vec<u8>> {
            m.get(&CborValue::Integer(k)).and_then(|x| match x {
                CborValue::Bytes(b) => Some(b),
                _ => None,
            })
        };
        // 形態斷言：kty=EC2(2)、alg=ES256(-7)、crv=P-256(1)
        assert_eq!(
            m.get(&CborValue::Integer(1)),
            Some(&CborValue::Integer(2)),
            "kty"
        );
        assert_eq!(
            m.get(&CborValue::Integer(3)),
            Some(&CborValue::Integer(-7)),
            "alg"
        );
        assert_eq!(
            m.get(&CborValue::Integer(-1)),
            Some(&CborValue::Integer(1)),
            "crv"
        );
        let (x, y) = (get(-2)?, get(-3)?);
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(x);
        uncompressed.extend_from_slice(y);
        let vk = VerifyingKey::from_sec1_bytes(&uncompressed).ok()?;
        Some(
            vk.verify(msg, &Signature::from_slice(sig_raw).ok()?)
                .is_ok(),
        )
    }

    #[test]
    fn register_then_assert_roundtrip() {
        let scalar = generate_private_key();
        let cred_id = vec![0xab; 32];
        let ad = registration_auth_data("webauthn.test", &cred_id, &scalar, 1).unwrap();
        // authData 逐欄位：rpIdHash、flags、counter、ACD 佈局
        assert_eq!(&ad[0..32], &Sha256::digest(b"webauthn.test")[..]);
        assert_eq!(ad[32], FLAGS_REGISTER);
        assert_eq!(&ad[33..37], &1u32.to_be_bytes());
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
        // COSE 公鑰藏在 ACD 尾部：authData 前綴 37B 後是 ACD（32+16+4 起為 credId）
        assert_eq!(&ad[89..89 + cred_id.len()], cred_id.as_slice());
        assert_eq!(&ad2[89..89 + cred_id.len()], cred_id.as_slice());
        let cose = &ad2[89 + cred_id.len()..];

        let parts = assertion("webauthn.test", &scalar, 2, "d2FsdGVyYXRl").unwrap();
        let ad_bytes = b64url_decode(&parts.authenticator_data).unwrap();
        assert_eq!(&ad_bytes[0..32], &Sha256::digest(b"webauthn.test")[..]);
        assert_eq!(ad_bytes[32], FLAGS_ASSERT);
        assert_eq!(&ad_bytes[33..37], &2u32.to_be_bytes());
        let cdj = b64url_decode(&parts.client_data_json).unwrap();
        assert_eq!(
            String::from_utf8(cdj.clone()).unwrap(),
            r#"{"challenge":"d2FsdGVyYXRl","crossOrigin":false,"origin":"https://webauthn.test","type":"webauthn.get"}"#
        );
        let mut msg = ad_bytes;
        msg.extend_from_slice(&Sha256::digest(&cdj));
        assert_eq!(
            verify_with_cose(cose, &msg, &b64url_decode(&parts.signature).unwrap()),
            Some(true),
            "COSE 公鑰必須驗通 assertion 簽名"
        );
        assert_eq!(
            b64url_decode(&parts.signature).unwrap().len(),
            64,
            "raw r‖s"
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
