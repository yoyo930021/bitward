//! 密碼強度分級（報告儀表板資料源）：**自寫規則打分，非 zxcvbn 本體**。
//!
//! 分級語意對齊 zxcvbn 的 0–4 層（0 太易猜、2 尚可猜、3 安全難猜、4 極難猜），
//! 管線門檻＝score<3 列管。取捨：zxcvbn 系 crate 要拖 ~1MB 字典與 regex/unicode
//! 機器，本報告只需要 0–4 分級不需要熵估算精度；以「長度／字元類別／常見字典
//! top 詞（含 leet 歸一）／連續／重複」五條規則做可解釋的保守近似——
//! 目標是不誤報強碼（寧可放過邊界案例），人造弱碼必命中。
//! 零分配路徑以外只在字典比對用小寫化緩衝；呼叫端（daemon）只在解鎖態批次算，
//! 結果不落盤。

/// 字典 top 詞（rockyou 頭部常態，全小寫；比對前呼叫端密碼先過 leet 歸一）。
const COMMON_WORDS: &[&str] = &[
    "password", "passwort", "123456", "123456789", "12345678", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey", "dragon", "sunshine", "princess",
    "football", "iloveyou", "000000", "master", "login", "pass", "shadow", "baseball",
    "superman", "michael", "ninja", "mustang", "jordan", "harley", "ranger", "buster",
    "samsung", "whatever", "pepper", "test", "qwerty123", "zaq12wsx", "hunter", "fuckyou",
    "trustno1", "butterfly", "batman", "summer", "starwars", "hello", "charlie", "donald",
    "password1", "password123", "qwertyuiop", "asdfgh", "zxcvbn", "passw0rd", "p@ssword",
    "p@ssw0rd", "secret", "shopping", "matrix", "cheese", "camera", "gangster", "friends",
    "angel", "jennifer", "tinkerbell", "alexander", "computer", "mavericks", "phoenix",
    "merlin", "panther", "raiders", "yankees", "dallas", "austin", "thunder", "tiger",
    "doctor", "gateway", "golfer", "snoopy", "magic", "guitar", "pokemon", "internet",
    "service", "captain", "daniel", "hannah", "exuser", "braves", "hockey", "rachel",
    "blabla", "asshole", "bigdaddy", "212121",
];

/// 單調連續鏈的最大長度（字母表、數字、鍵盤三行，含反向；大小寫不敏感）。
fn max_sequence_len(pw: &str) -> usize {
    let lower: Vec<char> = pw.chars().flat_map(char::to_lowercase).collect();
    let chains: [&str; 9] = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "poiuytrewq",
        "lkjhgfdsa",
        "mnbvcxz",
    ];
    let mut best = 0;
    for chain in chains {
        let c: Vec<char> = chain.chars().collect();
        let mut run = 0;
        let mut prev: Option<usize> = None;
        for &ch in &lower {
            match c.iter().position(|&x| x == ch) {
                Some(idx) => {
                    run = match prev {
                        Some(p) if p + 1 == idx => run + 1,
                        _ => 1,
                    };
                    prev = Some(idx);
                }
                None => {
                    run = 0;
                    prev = None;
                }
            }
            best = best.max(run);
        }
    }
    best
}

/// 最長同字元重複段（大小寫不敏感）。
fn max_repeat_len(pw: &str) -> usize {
    let lower: Vec<char> = pw.chars().flat_map(char::to_lowercase).collect();
    let mut best = 0;
    let mut run = 0;
    let mut prev: Option<char> = None;
    for &ch in &lower {
        run = if prev == Some(ch) { run + 1 } else { 1 };
        prev = Some(ch);
        best = best.max(run);
    }
    best
}

/// leet/變體歸一：常見替換折回字母＋全小寫（字典比對的輸入正規化）。
fn normalize_leet(pw: &str) -> String {
    pw.chars()
        .flat_map(char::to_lowercase)
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            '$' => 's',
            other => other,
        })
        .collect()
}

/// 字元類別數（小寫／大寫／數字／符號）。
fn class_count(pw: &str) -> u8 {
    let (mut lo, mut up, mut dig, mut sym) = (false, false, false, false);
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lo = true;
        } else if c.is_ascii_uppercase() {
            up = true;
        } else if c.is_ascii_digit() {
            dig = true;
        } else {
            sym = true;
        }
    }
    lo as u8 + up as u8 + dig as u8 + sym as u8
}

/// 字典命中層級：Exact（整詞）> Prefix（頭部詞佔 ≥60% 長度且詞 ≥4 字元）。
enum DictHit {
    None,
    Exact,
    Prefix,
}

/// 兩形都比：小寫原形收數字系字典詞（123456、password123），
/// leet 歸一形收變體（p@ssw0rd→password）。
fn dictionary_hit(lc: &str, leet: &str) -> DictHit {
    if COMMON_WORDS.iter().any(|w| *w == lc || *w == leet) {
        return DictHit::Exact;
    }
    // 前綴命中：password1234、qwerty2020 這類「詞＋尾巴」結構。
    for w in COMMON_WORDS {
        if w.len() >= 4 && (lc.starts_with(w) || leet.starts_with(w)) {
            let rest = if lc.starts_with(w) { lc } else { leet };
            if rest.len() > w.len() && (w.len() as f64 / rest.len() as f64) >= 0.6 {
                return DictHit::Prefix;
            }
        }
    }
    DictHit::None
}

/// 密碼強度分級 0–4（zxcvbn 同口徑語意，規則近似見模組頭）。
/// 空字串回 0。呼叫端門檻：score<3 屬弱密碼列管。
pub fn password_score(pw: &str) -> u8 {
    let len = pw.chars().count();
    if len == 0 {
        return 0;
    }
    // 累積分：長度＋類別，再由模式上限收斂。
    let mut pts: i8 = 0;
    if len >= 16 {
        pts += 3;
    } else if len >= 12 {
        pts += 2;
    } else if len >= 8 {
        pts += 1;
    }
    pts += (class_count(pw).saturating_sub(1)) as i8;

    let base: i8 = match pts {
        6.. => 4,
        4..=5 => 3,
        2..=3 => 2,
        1 => 1,
        _ => 0,
    };

    let mut cap: i8 = 4;
    let lc: String = pw.chars().flat_map(char::to_lowercase).collect();
    let leet = normalize_leet(pw);
    match dictionary_hit(&lc, &leet) {
        DictHit::Exact => cap = cap.min(0),
        DictHit::Prefix => cap = cap.min(1),
        DictHit::None => {}
    }
    if len < 6 {
        cap = cap.min(1);
    }
    // 重複主導（最長同字元段佔 ≥70%）：aaaa、abababab 型。
    if max_repeat_len(pw) * 10 >= len * 7 && len >= 4 {
        cap = cap.min(1);
    }
    // 連續鏈佔 ≥50% 且整體不長：qwerty、12345678、asdfgh12 型。
    let seq = max_sequence_len(pw);
    if seq >= 4 && seq * 2 >= len && len <= 12 {
        cap = cap.min(1);
    }
    // 字元類別不足（契約弱信号）直接反映在 pts：類別數只加 class-1 分，
    // 單類別另設 cap 防「14+ 字元全同類」混過 2 分線。
    if class_count(pw) == 1 {
        cap = cap.min(if len >= 14 { 2 } else { 1 });
    }
    base.min(cap) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(pw: &str) -> u8 {
        password_score(pw)
    }

    #[test]
    fn weak_candidates_all_flagged() {
        for pw in [
            "", "123456", "password", "Password1", "qwerty", "abc123", "letmein", "111111",
            "aaaaaaaa", "passw0rd", "p@ssw0rd", "qwerty123", "dragon", "000000", "iloveyou",
            "admin", "welcome", "monkey", "sunshine", "hunter2", "abcdef", "12345678",
            "password123", "asdfgh", "121212",
        ] {
            assert!(s(pw) < 3, "{pw} 應列管，got {}", s(pw));
        }
    }

    #[test]
    fn strong_passwords_not_flagged() {
        for pw in [
            "FirstPass-Abc123!",
            "CorrectHorse42x",
            "Tr0ub4d0r&3xK",
            "Zk9$mVq2!xLp7Rt",
            "gh6#dNc9*Wm1",
            "Xy!4pQ&8zR#2m",
        ] {
            assert!(s(pw) >= 3, "{pw} 不應列管，got {}", s(pw));
        }
    }

    #[test]
    fn grade_bounds_and_edges() {
        assert_eq!(s(""), 0);
        assert_eq!(s("123456"), 0); // 字典整詞
        assert_eq!(s("password123"), 0); // 字典整詞（變體入列）
        assert!(s("aaaaaaaaaaaaaaaaaaaa") < 3); // 重複主導：20 個同字元仍列管
        assert_eq!(s("zqxjvkwbplzmxkfpn"), 2); // 17 字元單類別：列管但非 0
        assert!(s("Xy!4pQ&8zR#2m") >= 3); // 13 字元四類別無模式
        // 分級值域恆 0..=4
        for pw in ["a", "ab", "abc", "abcd1234", "Aa1!Aa1!", "x".repeat(64).as_str()] {
            assert!(s(pw) <= 4);
        }
    }

    #[test]
    fn sequence_and_repeat_runs() {
        assert_eq!(max_sequence_len("qwerty"), 6);
        assert_eq!(max_sequence_len("poiuyt"), 6);
        assert_eq!(max_sequence_len("4567"), 4);
        assert_eq!(max_sequence_len("QwerTy12"), 6);
        assert_eq!(max_repeat_len("aabbbcccc"), 4);
    }
}
