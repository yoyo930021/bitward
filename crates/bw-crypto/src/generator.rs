//! 密碼產生器：長度 + 四类開關 + 易混淆字元排除。
//! 常數來源：sdk-internal bitwarden-generators/src/password.rs
//! （SPECIAL_CHARS、ambiguous `I O l 0 1`、預設 16、界 5..=128），見 NOTES.md。

use crate::CryptoError;
use rand::seq::SliceRandom;
use rand::thread_rng;

/// 官方 SPECIAL_CHARS：`!@#$%^&*`。
const SPECIAL_CHARS: &[u8] = b"!@#$%^&*";
/// 官方 avoid_ambiguous 排除集：`I, O, l, 0, 1`。
const AMBIGUOUS: &[u8] = b"IOl01";

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &[u8] = b"0123456789";

pub const DEFAULT_PASSWORD_LENGTH: usize = 16;
pub const MINIMUM_PASSWORD_LENGTH: usize = 5;
pub const MAXIMUM_PASSWORD_LENGTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: false,
            avoid_ambiguous: false,
        }
    }
}

fn filter(pool: &[u8], avoid_ambiguous: bool) -> Vec<u8> {
    if avoid_ambiguous {
        pool.iter()
            .copied()
            .filter(|c| !AMBIGUOUS.contains(c))
            .collect()
    } else {
        pool.to_vec()
    }
}

pub fn generate_password(opts: &PasswordOptions) -> Result<String, CryptoError> {
    if opts.length < MINIMUM_PASSWORD_LENGTH || opts.length > MAXIMUM_PASSWORD_LENGTH {
        return Err(CryptoError::InvalidLength);
    }
    let mut rng = thread_rng();
    let mut classes: Vec<Vec<u8>> = Vec::new();
    if opts.lowercase {
        classes.push(filter(LOWERCASE, opts.avoid_ambiguous));
    }
    if opts.uppercase {
        classes.push(filter(UPPERCASE, opts.avoid_ambiguous));
    }
    if opts.numbers {
        classes.push(filter(NUMBERS, opts.avoid_ambiguous));
    }
    if opts.special {
        classes.push(SPECIAL_CHARS.to_vec());
    }
    if classes.is_empty() || classes.iter().any(Vec::is_empty) {
        return Err(CryptoError::NoCharacterSetEnabled);
    }
    let required = classes.len();
    if opts.length < required {
        return Err(CryptoError::InvalidLength);
    }

    // 每個啟用字集保證至少一個，其餘從聯集抽，最後洗牌。
    let mut buf: Vec<u8> = Vec::with_capacity(opts.length);
    let pool: Vec<u8> = classes.concat();
    for class in &classes {
        buf.push(*class.as_slice().choose(&mut rng).expect("non-empty class"));
    }
    while buf.len() < opts.length {
        buf.push(*pool.as_slice().choose(&mut rng).expect("non-empty pool"));
    }
    buf.shuffle(&mut rng);
    // shuffle 後仍要保證「每個 class 至少一個」：取樣階段已保證，洗牌只動位置。
    String::from_utf8(buf).map_err(|_| CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honors_flags_and_bounds() {
        let o = PasswordOptions {
            length: 24,
            lowercase: false,
            uppercase: false,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
        };
        let p = generate_password(&o).unwrap();
        assert_eq!(p.len(), 24);
        assert!(
            p.bytes()
                .all(|c| NUMBERS.contains(&c) || SPECIAL_CHARS.contains(&c))
        );
        assert!(p.bytes().any(|c| NUMBERS.contains(&c)));
        assert!(p.bytes().any(|c| SPECIAL_CHARS.contains(&c)));

        assert!(matches!(
            generate_password(&PasswordOptions {
                length: 4,
                ..Default::default()
            }),
            Err(CryptoError::InvalidLength)
        ));
        assert!(matches!(
            generate_password(&PasswordOptions {
                length: 129,
                ..Default::default()
            }),
            Err(CryptoError::InvalidLength)
        ));
        assert!(matches!(
            generate_password(&PasswordOptions {
                lowercase: false,
                uppercase: false,
                numbers: false,
                special: false,
                ..Default::default()
            }),
            Err(CryptoError::NoCharacterSetEnabled)
        ));
    }

    #[test]
    fn ambiguous_exclusion() {
        let o = PasswordOptions {
            length: 128,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: false,
            avoid_ambiguous: true,
        };
        for _ in 0..20 {
            let p = generate_password(&o).unwrap();
            assert!(p.bytes().all(|c| !AMBIGUOUS.contains(&c)), "{p}");
        }
    }
}
