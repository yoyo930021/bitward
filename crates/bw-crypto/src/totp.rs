//! RFC 6238 TOTP + `otpauth://` URI 解析 + RFC 4648 base32。
//! 預設 6 digits / 30 s / SHA1（RFC 6238 §3 與 Bitwarden 用戶端行為一致）。
//! 本地產生，不問伺服器。

use crate::CryptoError;
use hmac::Mac;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    pub digits: u8,
    pub period: u64,
    pub algorithm: TotpAlgorithm,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        }
    }
}

/// 解析完成的 otpauth URI。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Otpauth {
    /// RFC 4648 base32 secret（大寫、含填充）。
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub params: TotpParams,
}

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

fn hotp(
    secret: &[u8],
    counter: u64,
    algo: TotpAlgorithm,
    digits: u8,
) -> Result<String, CryptoError> {
    if digits == 0 || digits > 10 {
        return Err(CryptoError::BadTotpParams);
    }
    let msg = counter.to_be_bytes();
    let code: u32 = match algo {
        TotpAlgorithm::Sha1 => {
            let mut m = <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(secret)
                .map_err(|_| CryptoError::InvalidKey)?;
            m.update(&msg);
            truncate32(&m.finalize().into_bytes())
        }
        TotpAlgorithm::Sha256 => {
            let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(secret)
                .map_err(|_| CryptoError::InvalidKey)?;
            m.update(&msg);
            truncate32(&m.finalize().into_bytes())
        }
        TotpAlgorithm::Sha512 => {
            let mut m =
                <HmacSha512 as Mac>::new_from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
            m.update(&msg);
            truncate32(&m.finalize().into_bytes())
        }
    };
    let modulus = 10u32
        .checked_pow(digits as u32)
        .ok_or(CryptoError::BadTotpParams)?;
    Ok(format!(
        "{:0width$}",
        code % modulus,
        width = digits as usize
    ))
}

/// RFC 4231/6238 dynamic truncation：取 HMAC 結果末 nibble 為 offset，
/// 讀 4 bytes big-endian 去掉最高位元。
fn truncate32(mac: &[u8]) -> u32 {
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let raw = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    raw & 0x7fff_ffff
}

pub fn totp_code_with(
    seed_base32: &str,
    unix_secs: u64,
    params: &TotpParams,
) -> Result<String, CryptoError> {
    let seed = base32_decode(seed_base32)?;
    if params.period == 0 {
        return Err(CryptoError::BadTotpParams);
    }
    let counter = unix_secs / params.period;
    hotp(&seed, counter, params.algorithm, params.digits)
}

/// 產生一組可匯入其他 app 的 otpauth URI。
pub fn generate_uri(
    secret_base32: &str,
    issuer: &str,
    account: &str,
    params: &TotpParams,
) -> Result<String, CryptoError> {
    if params.period == 0 {
        return Err(CryptoError::BadTotpParams);
    }
    let algo = match params.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    Ok(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        url_encode(issuer),
        url_encode(account),
        secret_base32,
        url_encode(issuer),
        algo,
        params.digits,
        params.period
    ))
}

/// 解析 `otpauth://totp/...`（也接受 `otpauth://TIMEBASED/...` 變體）。
/// 不做 issuer/label 一致性檢查以外的政策；未知 query 參數忽略。
pub fn parse_otpauth(uri: &str) -> Result<Otpauth, CryptoError> {
    let rest = uri
        .strip_prefix("otpauth://")
        .or_else(|| uri.strip_prefix("OTPAUTH://"))
        .ok_or(CryptoError::BadOtpauthUri)?;
    let (kind, path_and_query) = rest.split_once('/').ok_or(CryptoError::BadOtpauthUri)?;
    if !matches!(
        kind.to_ascii_lowercase().as_str(),
        "totp" | "timebased" | "time-based"
    ) {
        return Err(CryptoError::BadOtpauthUri);
    }
    let (label, query) = match path_and_query.split_once('?') {
        Some((l, q)) => (l, q),
        None => (path_and_query, ""),
    };

    let mut params = TotpParams::default();
    let mut secret: Option<String> = None;
    let mut issuer_q: Option<String> = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k.to_ascii_lowercase().as_str() {
            "secret" => {
                let s = url_decode(v);
                // 只接受 base32 字元集（大小寫不拘、填充可省略）。
                base32_decode(&s)?;
                secret = Some(s.to_ascii_uppercase());
            }
            "issuer" => issuer_q = Some(url_decode(v)),
            "period" => {
                params.period = url_decode(v)
                    .parse::<u64>()
                    .map_err(|_| CryptoError::BadOtpauthUri)?;
            }
            "digits" => {
                params.digits = url_decode(v)
                    .parse::<u8>()
                    .map_err(|_| CryptoError::BadOtpauthUri)?;
            }
            "algorithm" => {
                params.algorithm = match url_decode(v).to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    "MD5" => return Err(CryptoError::BadTotpParams),
                    _ => return Err(CryptoError::BadOtpauthUri),
                };
            }
            _ => {}
        }
    }
    let secret = secret.ok_or(CryptoError::BadOtpauthUri)?;

    // label 形如 `Issuer:account`；query 的 issuer 優先（keyauth spec）。
    let (issuer_l, account) = match label.split_once(':') {
        Some((i, a)) => (Some(url_decode(i)), Some(url_decode(a))),
        None => (None, Some(url_decode(label))),
    };
    let issuer = issuer_q.or(issuer_l);

    if params.period == 0 || params.digits == 0 || params.digits > 10 {
        return Err(CryptoError::BadTotpParams);
    }
    Ok(Otpauth {
        secret,
        issuer,
        account,
        params,
    })
}

/// RFC 4648 base32 解碼（大小寫不拘、忽略空格、填充可省略）。
/// `0`/`1` 依 base32hex 慣例映射到 26/27（Google Authenticator 系常見）。
pub(crate) fn base32_decode(s: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &b in s.as_bytes() {
        let value: u32 = match b {
            b'=' | b' ' | b'-' | b'_' => continue,
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a') as u32,
            b'2'..=b'7' => 26 + (b - b'2') as u32,
            b'0' => 26,
            b'1' => 27,
            _ => return Err(CryptoError::BadBase32),
        };
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.is_empty() {
        return Err(CryptoError::BadBase32);
    }
    Ok(Zeroizing::new(out))
}

/// 最小 percent-decoding（otpauth query 用；不依賴 http crate）。
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    #[test]
    fn base32_rfc4648_vectors() {
        assert_eq!(&*base32_decode("MY======").unwrap(), b"f");
        assert_eq!(&*base32_decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(&*base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(&*base32_decode("mzxw6===").unwrap(), b"foo");
        assert_eq!(
            &*base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
        assert!(base32_decode("").is_err());
        assert!(base32_decode("!@#").is_err());
    }

    #[test]
    fn otpauth_parse_defaults_and_overrides() {
        let o = parse_otpauth(
            "otpauth://totp/ACME:alice@acme.test?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=ACME",
        )
        .unwrap();
        assert_eq!(o.secret, SEED_SHA1);
        assert_eq!(o.issuer.as_deref(), Some("ACME"));
        assert_eq!(o.account.as_deref(), Some("alice@acme.test"));
        assert_eq!(o.params, TotpParams::default());

        let o2 = parse_otpauth(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(
            o2.params,
            TotpParams {
                digits: 8,
                period: 60,
                algorithm: TotpAlgorithm::Sha256
            }
        );
        assert!(parse_otpauth("otpauth://hotp/x?secret=ABa").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://totp/x?issuer=NoSecret").is_err());
    }

    #[test]
    fn uri_generation_roundtrip() {
        let uri = generate_uri(SEED_SHA1, "ACME", "a@b.c", &TotpParams::default()).unwrap();
        let back = parse_otpauth(&uri).unwrap();
        assert_eq!(back.secret, SEED_SHA1);
        assert_eq!(back.issuer.as_deref(), Some("ACME"));
    }

    #[test]
    fn truncation_unit() {
        // RFC 4226 appendix D 的 HOTP 值（SHA1、counter 0..2）
        assert_eq!(
            hotp(b"12345678901234567890", 0, TotpAlgorithm::Sha1, 6).unwrap(),
            "755224"
        );
        assert_eq!(
            hotp(b"12345678901234567890", 1, TotpAlgorithm::Sha1, 6).unwrap(),
            "287082"
        );
        assert_eq!(
            hotp(b"12345678901234567890", 2, TotpAlgorithm::Sha1, 6).unwrap(),
            "359152"
        );
    }
}
