//! D1（稽核 2026-11-16）：值搜尋索引的金鑰派生與值 HMAC——演算法單源。
//!
//! 秘密值（密碼）明文不落盤：`meta_plain.password_hmac` 只存
//! `HMAC-SHA256(index_key, 值)`。`index_key` 以 HKDF-SHA256（RFC 5869
//! Extract+Expand，salt 缺＝32 零位元組）從 user key 派生、info=`"index"`，
//! 只在解鎖期存在於記憶體；鎖態下盤上 HMAC 欄無法反推值，也無法離線猜值
//! （oracle 需金鑰本身，不是需密碼）。

use hmac::Mac;
use zeroize::Zeroizing;

/// HKDF info 欄（派生金鑰的用途域別；改字串＝所有既有 HMAC 索引作廢重建）。
pub const INDEX_INFO: &[u8] = b"index";

/// user key（64 bytes 解縮後本體）→ 32 bytes 索引派生金鑰。
pub fn derive_index_key(user_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, user_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(INDEX_INFO, okm.as_mut())
        .expect("32 <= 255 * SHA-256 output");
    okm
}

/// 索引標籤：HMAC-SHA256(index_key, 明文值)。等值比對即精確值搜尋。
pub fn index_value_tag(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// KAT 釘住（RFC 5869 形態；期望值由 python hmac/hashlib 獨立實作產出，
    /// 2026-11-17，非本 crate 自證）：ikm=0x00..0x3f、info="index"。
    #[test]
    fn index_key_derivation_kat() {
        let ikm: Vec<u8> = (0u8..64).collect();
        let key = derive_index_key(&ikm);
        assert_eq!(
            hex(&key[..]),
            "6518f2b7daac3bc82510f4ea3c59d92687fdf95f1102a2a33480ee88b4a50606"
        );
        // 值標籤同錨：ASCII 與非 ASCII 明文各一。
        assert_eq!(
            hex(&index_value_tag(&key, b"hunter2")),
            "c64c5e791f7babd0a2668c2b0f36e11cd9958e759e0f220164eeee4de26d4957"
        );
        assert_eq!(
            hex(&index_value_tag(&key, "pässwörd✓".as_bytes())),
            "ebaccb8ba42645407105cb2b0222a992028574c6df6547ef066f5ac3e9b5b26b"
        );
    }

    /// 不同 user key ⇒ 同值不同標籤（盤上標籤不可跨帳號比對）。
    #[test]
    fn tag_is_key_dependent() {
        let k1 = derive_index_key(&[1u8; 64]);
        let k2 = derive_index_key(&[2u8; 64]);
        assert_ne!(index_value_tag(&k1, b"x"), index_value_tag(&k2, b"x"));
        assert_eq!(index_value_tag(&k1, b"x"), index_value_tag(&k1, b"x"));
    }
}
