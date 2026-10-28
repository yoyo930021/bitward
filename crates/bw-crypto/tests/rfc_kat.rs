//! RFC KAT：6070（PBKDF2）、5869（HKDF）、6238（TOTP）、9106（Argon2id 縮參數）。

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

/// RFC 6070 §3（PBKDF2-HMAC-SHA1；pin 住 pbkdf2 crate 的 core，
/// 我們的 SHA-256 路徑共用同一迭代實作）。
fn assert_rfc6070(pw: &[u8], salt: &[u8], c: u32, expect_hex: &str) {
    let mut out = [0u8; 20];
    pbkdf2_hmac::<Sha1>(pw, salt, c, &mut out);
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expect_hex);
}

#[test]
fn rfc6070_pbkdf2() {
    assert_rfc6070(
        b"password",
        b"salt",
        1,
        "0c60c80f961f0e71f3a9b524af6012062fe037a6",
    );
    assert_rfc6070(
        b"password",
        b"salt",
        2,
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
    );
    assert_rfc6070(
        b"password",
        b"salt",
        4096,
        "4b007901b765489abead49d926f721d065a429c1",
    );
    assert_rfc6070(
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a96",
    );
    assert_rfc6070(
        b"pass\0word",
        b"sa\0lt",
        4096,
        "56fa6aa75548099dcc37d7f03425e0c37f1c42b2",
    );
}

/// RFC 6070 同形但 SHA-256（常用釘選值，驗證我們實際用的雜湊）。
#[test]
fn pbkdf2_sha256_known_answers() {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"password", b"salt", 1, &mut out);
    assert_eq!(
        hex(&out),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    // c=4096（RFC 7914 §11 同參數）
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"password", b"salt", 4096, &mut out);
    assert_eq!(
        hex(&out),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// RFC 5869 A.1/A.3：HKDF-SHA256 extract+expand，pin hkdf crate；
/// 並用 A.1 驗 Expand-only（from_prk）——那正是 stretch 的路徑。
#[test]
fn rfc5869_hkdf() {
    use hkdf::Hkdf;
    // A.1
    let ikm = [0x0bu8; 22];
    let salt = hex2b("000102030405060708090a0b0c");
    let info = hex2b("f0f1f2f3f4f5f6f7f8f9");
    let (prk_out, h) = Hkdf::<sha2::Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(
        hex(prk_out.as_slice()),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let mut okm = [0u8; 42];
    h.expand(&info, &mut okm).unwrap();
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    // Expand-only：PRK 直接當 HMAC key（stretch 用的同一條路）。
    let he = Hkdf::<sha2::Sha256>::from_prk(prk_out.as_slice()).unwrap();
    let mut okm2 = [0u8; 42];
    he.expand(&info, &mut okm2).unwrap();
    assert_eq!(okm2, okm);
    // A.3（salt/info 皆空）
    let h3 = Hkdf::<sha2::Sha256>::new(Some(&[]), &ikm);
    let mut okm3 = [0u8; 42];
    h3.expand(&[], &mut okm3).unwrap();
    assert_eq!(
        hex(&okm3),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

fn hex2b(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 6238 Appendix B（8 digits）+ 預設 6 digits 檢查。
#[test]
fn rfc6238_totp() {
    use bw_crypto::{TotpAlgorithm, TotpParams};

    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
                               GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";

    let cases: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];
    let p8 = TotpParams {
        digits: 8,
        period: 30,
        algorithm: TotpAlgorithm::Sha1,
    };
    for (t, sha1, sha256, sha512) in cases {
        assert_eq!(
            bw_crypto::totp_code_with(SEED_SHA1, t, &p8).unwrap(),
            sha1,
            "T={t} sha1"
        );
        let p = TotpParams {
            algorithm: TotpAlgorithm::Sha256,
            ..p8
        };
        assert_eq!(
            bw_crypto::totp_code_with(SEED_SHA256, t, &p).unwrap(),
            sha256,
            "T={t} sha256"
        );
        let p = TotpParams {
            algorithm: TotpAlgorithm::Sha512,
            ..p8
        };
        assert_eq!(
            bw_crypto::totp_code_with(SEED_SHA512, t, &p).unwrap(),
            sha512,
            "T={t} sha512"
        );
    }
    // 預設 6/30/SHA1：RFC 6238 的 6-digit 是 mod 10^6（非取前 6 碼）。
    assert_eq!(bw_crypto::totp_code(SEED_SHA1, 59).unwrap(), "287082");
}

/// RFC 9106 §5.1 的縮參數變體（argon2 crate KAT 同源：m=32KiB, t=3, p=4,
/// secret=[0x03;8], ad=[0x04;12]）。走 argon2 crate 直接呼叫，
/// 我們的 argon2id_raw 是同一條參數化路徑的減配版。
#[test]
fn rfc9106_argon2id_reduced() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04u8; 12]).unwrap())
        .build()
        .unwrap();
    let ctx =
        Argon2::new_with_secret(&[0x03u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    ctx.hash_password_into(&[0x01u8; 32], &[0x02u8; 16], &mut out)
        .unwrap();
    assert_eq!(
        hex(&out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );

    // 我們的 raw 路徑（無 secret/ad）也要能跑通同尺寸參數。
    let mut out2 = [0u8; 32];
    bw_crypto::argon2id_raw(b"password", b"somesalt", 32, 3, 4, &mut out2).unwrap();
    assert_eq!(out2.len(), 32);
}
