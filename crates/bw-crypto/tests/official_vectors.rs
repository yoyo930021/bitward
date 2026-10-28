//! A1（契約 §6）：官方實測向量。資料取自 bitwarden-crypto 4.0.0（crates.io .crate）
//! 與 sdk-internal 測試檔（只取資料、不鏈接其碼），來源逐筆記在
//! tests/vectors/official_bitwarden.json 的 `_source` 與 NOTES.md。

use bw_crypto::*;
use std::fs;

#[derive(serde::Deserialize)]
struct Vectors {
    pbkdf2_hash: Pbkdf2Hash,
    argon2id_hash: Argon2Hash,
    master_password_e2e: E2e,
    stretch: Stretch,
    aes_hmac_type2: AeVec,
    aes_hmac_deterministic: AeVec,
    decryptable_type2: Decryptable,
    legacy_type0_user_key: Legacy0,
    rsa_oaep_sha1_device: RsaDevice,
    synthetic_type2_user_key_e2e: Synthetic,
}

#[derive(serde::Deserialize)]
struct Pbkdf2Hash {
    password: String,
    email_variants: Vec<String>,
    iterations: u32,
    master_password_hash: String,
}
#[derive(serde::Deserialize)]
struct Argon2Hash {
    password: String,
    salt: String,
    m_mib: u32,
    t: u32,
    p: u32,
    master_password_hash: String,
}
#[derive(serde::Deserialize)]
struct E2e {
    email: String,
    password: String,
    iterations: u32,
    master_password_hash: String,
    protected_user_key: String,
}
#[derive(serde::Deserialize)]
struct Stretch {
    master_key: Vec<u8>,
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}
#[derive(serde::Deserialize)]
struct AeVec {
    key: Vec<u8>,
    iv: Vec<u8>,
    plaintext: String,
    ciphertext: Vec<u8>,
    mac: Option<Vec<u8>>,
}
#[derive(serde::Deserialize)]
struct Decryptable {
    key_b64: String,
    bytes_vec: String,
    bytes_pt: Vec<u8>,
    string_vec: String,
    string_pt: String,
}
#[derive(serde::Deserialize)]
struct Legacy0 {
    password: String,
    email: String,
    iterations: u32,
    protected_user_key: String,
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}
#[derive(serde::Deserialize)]
struct RsaDevice {
    user_key: Vec<u8>,
    device_key_data: Vec<u8>,
    protected_device_private_key: String,
    protected_user_key: String,
}
#[derive(serde::Deserialize)]
struct Synthetic {
    email: String,
    password: String,
    iterations: u32,
    master_key_b64: String,
    stretched_enc_key_b64: String,
    stretched_mac_key_b64: String,
    protected_user_key: String,
    user_key_b64: String,
}

fn load() -> Vectors {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/official_bitwarden.json"
    ))
    .expect("fixture present");
    serde_json::from_str(&raw).expect("fixture valid")
}

fn b64d(s: &str) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(s).unwrap()
}
fn b64e(b: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(b)
}

#[test]
fn official_pbkdf2_master_password_hash() {
    let v = load();
    for email in &v.pbkdf2_hash.email_variants {
        let mk = master_key(
            &v.pbkdf2_hash.password,
            email,
            KdfParams::Pbkdf2 {
                iterations: v.pbkdf2_hash.iterations,
            },
        )
        .unwrap();
        assert_eq!(
            master_password_hash(&mk, &v.pbkdf2_hash.password).as_b64(),
            v.pbkdf2_hash.master_password_hash,
            "email variant {email}"
        );
    }
}

#[test]
fn official_argon2id_master_password_hash() {
    let v = load();
    let mk = master_key(
        &v.argon2id_hash.password,
        &v.argon2id_hash.salt,
        KdfParams::Argon2id {
            m: v.argon2id_hash.m_mib,
            t: v.argon2id_hash.t,
            p: v.argon2id_hash.p,
        },
    )
    .unwrap();
    assert_eq!(
        master_password_hash(&mk, &v.argon2id_hash.password).as_b64(),
        v.argon2id_hash.master_password_hash
    );
}

#[test]
fn official_hkdf_stretch() {
    let v = load();
    let mk = MasterKey::from_bytes(v.stretch.master_key.clone()).unwrap();
    let sk = stretch(&mk);
    let mut want = v.stretch.enc_key.clone();
    want.extend_from_slice(&v.stretch.mac_key);
    assert_eq!(sk.as_bytes(), want);
}

#[test]
fn official_type2_aes_hmac_vectors() {
    let v = load();
    for a in [v.aes_hmac_type2, v.aes_hmac_deterministic] {
        let k = UserKey::from_bytes(a.key.clone()).unwrap();
        let enc = encrypt_with_iv(k.as_bytes(), &a.iv, a.plaintext.as_bytes()).unwrap();
        if let Some(mac) = &a.mac {
            let expected = format!("2.{}|{}|{}", b64e(&a.iv), b64e(&a.ciphertext), b64e(mac));
            assert_eq!(enc, expected);
        } else {
            let parts = parse_enc_str(&enc).unwrap();
            assert_eq!(parts.ct, a.ciphertext, "ct must match official vector");
        }
        assert_eq!(decrypt_bytes(&k, &enc).unwrap(), a.plaintext.as_bytes());
    }
}

#[test]
fn official_decryptable_type2_vectors() {
    let v = load();
    let k = UserKey::from_bytes(b64d(&v.decryptable_type2.key_b64)).unwrap();
    assert_eq!(
        decrypt_bytes(&k, &v.decryptable_type2.string_vec).unwrap(),
        v.decryptable_type2.string_pt.as_bytes()
    );
    assert_eq!(
        decrypt_bytes(&k, &v.decryptable_type2.bytes_vec).unwrap(),
        v.decryptable_type2.bytes_pt
    );
}

#[test]
fn official_legacy_type0_user_key_e2e() {
    let v = load();
    let mk = master_key(
        &v.legacy_type0_user_key.password,
        &v.legacy_type0_user_key.email,
        KdfParams::Pbkdf2 {
            iterations: v.legacy_type0_user_key.iterations,
        },
    )
    .unwrap();
    let uk = decrypt_user_key_legacy(&mk, &v.legacy_type0_user_key.protected_user_key).unwrap();
    let mut want = v.legacy_type0_user_key.enc_key.clone();
    want.extend_from_slice(&v.legacy_type0_user_key.mac_key);
    assert_eq!(uk.as_bytes(), want);
}

#[test]
fn official_master_password_e2e_auth_hash() {
    let v = load();
    let mk = master_key(
        &v.master_password_e2e.password,
        &v.master_password_e2e.email,
        KdfParams::Pbkdf2 {
            iterations: v.master_password_e2e.iterations,
        },
    )
    .unwrap();
    assert_eq!(
        master_password_hash(&mk, &v.master_password_e2e.password).as_b64(),
        v.master_password_e2e.master_password_hash
    );
    // TEST_USER_KEY 是官方測試裡的 desktop 範例密文：只驗證解析形態。
    let p = parse_enc_str(&v.master_password_e2e.protected_user_key).unwrap();
    assert_eq!(p.cipher_type, CipherType::Aes256CbcHmacSha256);
    assert_eq!(p.iv.len(), 16);
    assert_eq!(p.mac.as_deref().map(<[u8]>::len), Some(32));
}

#[test]
fn end_to_end_email_to_user_key() {
    // email+password → master key → stretched → 解 Protected Symmetric Key（type 2）。
    let v = load();
    let s = &v.synthetic_type2_user_key_e2e;
    let mk = master_key(
        &s.password,
        &s.email,
        KdfParams::Pbkdf2 {
            iterations: s.iterations,
        },
    )
    .unwrap();
    assert_eq!(b64e(mk.as_bytes()), s.master_key_b64);
    let sk = stretch(&mk);
    assert_eq!(b64e(&sk.as_bytes()[..32]), s.stretched_enc_key_b64);
    assert_eq!(b64e(&sk.as_bytes()[32..]), s.stretched_mac_key_b64);
    let uk = decrypt_user_key(&sk, &s.protected_user_key).unwrap();
    assert_eq!(b64e(uk.as_bytes()), s.user_key_b64);
    // 反向包裝再解一次（改密碼路徑的最小閉環）。
    let repacked = encrypt_user_key(&mk, &uk).unwrap();
    assert_eq!(
        decrypt_user_key(&stretch(&mk), &repacked)
            .unwrap()
            .as_bytes(),
        uk.as_bytes()
    );
}

#[test]
fn official_rsa_oaep_sha1_device_chain() {
    // 官方 device_key.rs 測試鏈：device key（64B composite）→ 解 type 2
    // 信封得 RSA 私鑰（PKCS8）→ OAEP-SHA1 解 `4.` 包裝得 user key（64B）。
    let v = load();
    let device_key = UserKey::from_bytes(v.rsa_oaep_sha1_device.device_key_data.clone()).unwrap();
    let pkcs8 = decrypt_private_key(
        &device_key,
        &v.rsa_oaep_sha1_device.protected_device_private_key,
    )
    .unwrap();
    let unwrapped = rsa_decrypt(&pkcs8, &v.rsa_oaep_sha1_device.protected_user_key).unwrap();
    assert_eq!(unwrapped, v.rsa_oaep_sha1_device.user_key);
}
