//! KDF 編排：master key 派生、master password hash、HKDF stretch。
//! 參數與正規化規則逐條對照官方實作（NOTES.md 有 URL 與行號）。

use crate::{CryptoError, KdfParams, MasterKey, PasswordHash, StretchedKey};

/// 官方預設值（sdk-internal bitwarden-crypto kdf.rs `default_pbkdf2_iterations`）。
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
/// 官方預設值（`default_argon2_memory`，單位 MiB）。
pub const DEFAULT_ARGON2_M_MIB: u32 = 32;
/// 官方預設值（`default_argon2_iterations`）。
pub const DEFAULT_ARGON2_T: u32 = 6;
/// 官方預設值（`default_argon2_parallelism`）。
pub const DEFAULT_ARGON2_P: u32 = 4;

/// 官方下限（kdf.rs `PBKDF2_MIN_ITERATIONS`）。
pub const MIN_PBKDF2_ITERATIONS: u32 = 5_000;
/// 官方上限（help/kdf-algorithms：2,100,000）。
pub const MAX_PBKDF2_ITERATIONS: u32 = 2_100_000;
/// 官方下限（`ARGON2ID_MIN_MEMORY`，16 MiB）。
pub const MIN_ARGON2_M_MIB: u32 = 16;
/// 官方下限（`ARGON2ID_MIN_ITERATIONS`）。
pub const MIN_ARGON2_T: u32 = 2;
/// 官方下限（`ARGON2ID_MIN_PARALLELISM`）。
pub const MIN_ARGON2_P: u32 = 1;

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::Pbkdf2 {
            iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

impl KdfParams {
    /// 官方預設 Argon2id 組合（32 MiB / 6 / 4）。
    pub const ARGON2ID_DEFAULT: KdfParams = KdfParams::Argon2id {
        m: DEFAULT_ARGON2_M_MIB,
        t: DEFAULT_ARGON2_T,
        p: DEFAULT_ARGON2_P,
    };

    /// 是否低於官方接受下限（低於此值的帳號官方 SDK 直接拒解）。
    pub fn is_below_minimum(&self) -> bool {
        match *self {
            KdfParams::Pbkdf2 { iterations } => {
                !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations)
            }
            KdfParams::Argon2id { m, t, p } => {
                m < MIN_ARGON2_M_MIB || t < MIN_ARGON2_T || p < MIN_ARGON2_P
            }
        }
    }
}

pub(crate) fn master_key(pw: &str, email: &str, kdf: KdfParams) -> Result<MasterKey, CryptoError> {
    if kdf.is_below_minimum() {
        return Err(CryptoError::InsufficientKdfParameters);
    }
    // 官方 MasterKey::derive：email 先 trim + lowercase 才當 salt。
    let salt = email.trim().to_lowercase();
    let mut out = [0u8; 32];
    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                pw.as_bytes(),
                salt.as_bytes(),
                iterations,
                &mut out,
            );
        }
        KdfParams::Argon2id { m, t, p } => {
            // 官方 derive_kdf_key：Argon2 的 salt 是 SHA-256(salt)，不是 salt 原樣。
            let salt_hash = {
                use sha2::Digest as _;
                sha2::Sha256::digest(salt.as_bytes())
            };
            argon2id_into(
                pw.as_bytes(),
                &salt_hash,
                (m as usize) * 1024,
                t,
                p,
                &mut out,
            )?;
        }
    }
    Ok(MasterKey(out.to_vec()))
}

fn argon2id_into(
    secret: &[u8],
    salt: &[u8],
    memory_kib: usize,
    iterations: u32,
    parallelism: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(memory_kib as u32, iterations, parallelism, Some(out.len()))
        .map_err(|_| CryptoError::KdfUnsupported)?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    ctx.hash_password_into(secret, salt, out)
        .map_err(|_| CryptoError::KdfUnsupported)?;
    Ok(())
}

/// ServerAuthorization：官方 derive_master_key_hash 以 `purpose as u32`（=1）為迭代數。
pub(crate) fn master_password_hash(mk: &MasterKey, pw: &str) -> PasswordHash {
    hash_purpose(mk, pw, 1)
}

pub(crate) fn hash_purpose(mk: &MasterKey, pw: &str, iterations: u32) -> PasswordHash {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(mk.as_bytes(), pw.as_bytes(), iterations, &mut out);
    PasswordHash(b64(&out))
}

/// HKDF-SHA256 Expand-only（mk 直接作 PRK）：info "enc"、"mac"，各 32 bytes。
/// 注意：vault 路徑不做 extract；salt="bitwarden" 只存在於 Secrets Manager 機器金鑰路徑。
pub(crate) fn stretch(mk: &MasterKey) -> StretchedKey {
    use hkdf::Hkdf;
    let hk =
        Hkdf::<sha2::Sha256>::from_prk(mk.as_bytes()).expect("master key is 32 bytes = PRK size");
    let mut enc = vec![0u8; 32];
    let mut mac = vec![0u8; 32];
    hk.expand(b"enc", &mut enc).expect("32 <= 255*32");
    hk.expand(b"mac", &mut mac).expect("32 <= 255*32");
    StretchedKey::from_parts(enc, mac)
}

/// 不经正規化/下限檢查的 raw PBKDF2-SHA256（KAT 用）。
pub fn pbkdf2_sha256_raw(secret: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, salt, iterations, out);
}

/// 不经 SHA-256(salt) 與下限檢查的 raw Argon2id（KAT 用；memory_kib 直接給 KiB）。
pub fn argon2id_raw(
    secret: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    argon2id_into(
        secret,
        salt,
        memory_kib as usize,
        iterations,
        parallelism,
        out,
    )
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(s).map_err(|_| CryptoError::BadB64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_official() {
        assert_eq!(
            KdfParams::default(),
            KdfParams::Pbkdf2 {
                iterations: 600_000
            }
        );
        assert_eq!(
            KdfParams::ARGON2ID_DEFAULT,
            KdfParams::Argon2id { m: 32, t: 6, p: 4 }
        );
    }

    #[test]
    fn below_minimum_rejected() {
        assert!(KdfParams::Pbkdf2 { iterations: 4_999 }.is_below_minimum());
        assert!(KdfParams::Argon2id { m: 15, t: 6, p: 4 }.is_below_minimum());
        assert!(KdfParams::Argon2id { m: 32, t: 1, p: 4 }.is_below_minimum());
        assert!(!KdfParams::default().is_below_minimum());
    }

    #[test]
    fn master_key_rejects_weak_kdf() {
        let e = master_key("pw", "a@b.c", KdfParams::Pbkdf2 { iterations: 100 }).unwrap_err();
        assert!(matches!(e, CryptoError::InsufficientKdfParameters));
    }
}
