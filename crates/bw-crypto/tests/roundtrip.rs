//! 自洽性：proptest 任意明文 round-trip、MAC 纂改偵測、type 0/1 互操作。

use base64::Engine as _;
use bw_crypto::*;
use proptest::prelude::*;

fn key64() -> impl Strategy<Value = UserKey> {
    prop::collection::vec(any::<u8>(), 64).prop_map(|v| UserKey::from_bytes(v).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn type2_roundtrip_arbitrary_bytes(
        k in key64(),
        iv in prop::collection::vec(any::<u8>(), 16),
        pt in prop::collection::vec(any::<u8>(), 0..257usize),
    ) {
        let enc = encrypt_with_iv(k.as_bytes(), &iv, &pt)?;
        let back = decrypt_bytes(&k, &enc)?;
        prop_assert_eq!(back, pt);
    }

    #[test]
    fn type2_roundtrip_strings(k in key64(), pt in ".*") {
        let enc = encrypt(&k, &pt)?;
        prop_assert!(enc.starts_with("2."));
        prop_assert_eq!(decrypt(&k, &enc)?, pt.clone());
    }

    #[test]
    fn mac_tamper_detected(k in key64(), pt in prop::collection::vec(any::<u8>(), 1..64usize), bit in 0u8..8, pos in 0usize..32) {
        let enc = encrypt_with_iv(k.as_bytes(), &[3u8; 16], &pt)?;
        let parts: Vec<&str> = enc.split('.').nth(1).unwrap().split('|').collect();
        let mut mac = base64::engine::general_purpose::STANDARD.decode(parts[2]).unwrap();
        mac[pos] ^= 1 << bit;
        let tampered = format!(
            "2.{}|{}|{}",
            parts[0],
            parts[1],
            base64::engine::general_purpose::STANDARD.encode(&mac)
        );
        prop_assert!(matches!(decrypt_bytes(&k, &tampered), Err(CryptoError::MacMismatch)));
    }
}

/// type 0/2 互操作 + type 1 佈局（bitwarden-crypto 0.5.0：32-byte key enc=k[0..16]、
/// mac=k[16..32]；64-byte key 依 jslib 佈局 mac=k[32..64]）。
#[test]
fn type1_legacy_parse_and_decrypt() {
    let iv = [7u8; 16];
    let k32 = UserKey::from_bytes((0u8..32).collect()).unwrap();
    let ct = cbc_encrypt128(&k32.as_bytes()[0..16], &iv, b"legacy one");
    let mac = hmac_sha256(&k32.as_bytes()[16..32], &iv, &ct);
    let s = format!("1.{}|{}|{}", b64(&iv), b64(&ct), b64(&mac));
    let parts = parse_enc_str(&s).unwrap();
    assert_eq!(parts.cipher_type, CipherType::Aes128CbcHmacSha256);
    assert_eq!(
        decrypt_with_raw_key(k32.as_bytes(), &parts).unwrap(),
        b"legacy one"
    );

    // 64-byte key 佈局。
    let k64 = UserKey::from_bytes((0u8..64).collect()).unwrap();
    let mac64 = hmac_sha256(&k64.as_bytes()[32..64], &iv, &ct);
    let s64 = format!("1.{}|{}|{}", b64(&iv), b64(&ct), b64(&mac64));
    assert_eq!(decrypt_bytes(&k64, &s64).unwrap(), b"legacy one");
}

/// 64-byte key 對 type 0 必須拒絕（降級攻擊防護，官方 WrongKeyType 語意）。
#[test]
fn type0_rejected_under_64byte_key() {
    let k64 = UserKey::from_bytes((0u8..64).collect()).unwrap();
    assert!(matches!(
        decrypt_bytes(&k64, "0.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w=="),
        Err(CryptoError::KeyTypeMismatch(64))
    ));
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn cbc_encrypt128(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(pt)
}

fn hmac_sha256(mac_key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac_key).unwrap();
    m.update(iv);
    m.update(ct);
    m.finalize().into_bytes().to_vec()
}
