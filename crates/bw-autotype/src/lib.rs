//! AutoType：模板解析 + 按鍵注入（契約 §5.1 Fill.AutoType）。
//! 核心是純邏輯（零平台依賴、可測）；CGEvent 實作在 `MacSink`，
//! 非 macOS 上型別仍編譯但 `new()` 恆回 None（不註冊）。
//! API 取捨與來源 URL 見 NOTES.md。

use std::time::Duration;

/// daemon 端預設模板（呼叫端未帶 template 時）。
pub const DEFAULT_TEMPLATE: &str = "{username}{TAB}{password}{TAB}{enter}";

/// 按鍵間距。xdotool `type` 的預設即 12ms（NOTES.md 來源），
/// 取 10–20ms 安全帶中值：太短會被部分 app 的事件佇列吞鍵。
pub const KEY_INTERVAL: Duration = Duration::from_millis(12);

/// 打字前倒數秒數：留時間讓使用者把焦點切到目標視窗。
pub const COUNTDOWN_SECS: u32 = 3;

/// 模板長度上限：AutoType 呼叫可能來自 agent session，防超大模板塞爆事件佇列。
pub const MAX_TEMPLATE_LEN: usize = 4096;

/// 單次 `{delay:ms}` 上限；超過代表模板寫錯（或惡意），不是正常使用。
pub const MAX_DELAY_MS: u64 = 60_000;

/// kVK_Tab（HIToolbox/Events.h；core-graphics `KeyCode::TAB` 同值）。
pub const VK_TAB: u16 = 0x30;
/// kVK_Return（HIToolbox/Events.h；core-graphics `KeyCode::RETURN` 同值）。
pub const VK_RETURN: u16 = 0x24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Username,
    Password,
    Tab,
    Enter,
    Delay(Duration),
    Lit(String),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    #[error("模板超過上限（{0} 字元）")]
    TooLong(usize),
    #[error("模板有未關閉的 '{{'")]
    UnclosedBrace,
    #[error("空佔位符 '{{}}'")]
    EmptyPlaceholder,
    #[error("未知佔位符 '{{{0}}}'")]
    UnknownPlaceholder(String),
    #[error("`{{delay:x}}` 的 x 需為整數毫秒，實際 '{0}'")]
    BadDelay(String),
    #[error("delay {ms}ms 超過上限 {limit}ms")]
    DelayOutOfRange { ms: u64, limit: u64 },
}

/// 解析後的按鍵模板。未知佔位符一律拒（靜默忽略會打錯字，比拒絕危險）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeTemplate {
    tokens: Vec<Token>,
}

impl Default for TypeTemplate {
    fn default() -> Self {
        // 常數過得了解析，編輯期即保證
        Self::parse(DEFAULT_TEMPLATE).expect("DEFAULT_TEMPLATE 必可解析")
    }
}

impl TypeTemplate {
    /// 語法：`{username}` `{password}` `{tab}` `{enter}` `{delay:<ms>}`（大小寫不拘）；
    /// 其餘文字為字面值。 lone `}` 是合法字面字元。
    pub fn parse(s: &str) -> Result<Self, TemplateError> {
        if s.chars().count() > MAX_TEMPLATE_LEN {
            return Err(TemplateError::TooLong(s.chars().count()));
        }
        let mut tokens = Vec::new();
        let mut lit = String::new();
        let mut chars = s.char_indices();
        while let Some((i, c)) = chars.next() {
            if c != '{' {
                lit.push(c);
                continue;
            }
            // 佔位符：找最近的 '}'。巢狀不支援——`{` 在佔位符內即未知名稱，會回錯。
            let Some((close, _)) = chars.by_ref().find(|(_, d)| *d == '}') else {
                return Err(TemplateError::UnclosedBrace);
            };
            let name = &s[i + 1..close];
            if !lit.is_empty() {
                tokens.push(Token::Lit(std::mem::take(&mut lit)));
            }
            tokens.push(placeholder(name)?);
        }
        if !lit.is_empty() {
            tokens.push(Token::Lit(lit));
        }
        Ok(Self { tokens })
    }

    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }
}

fn placeholder(name: &str) -> Result<Token, TemplateError> {
    if name.is_empty() {
        return Err(TemplateError::EmptyPlaceholder);
    }
    let lower = name.to_lowercase();
    match lower.as_str() {
        "username" => Ok(Token::Username),
        "password" => Ok(Token::Password),
        "tab" => Ok(Token::Tab),
        "enter" => Ok(Token::Enter),
        other => match other.strip_prefix("delay:") {
            Some(rest) => {
                let ms: u64 = rest
                    .trim()
                    .parse()
                    .map_err(|_| TemplateError::BadDelay(name.to_owned()))?;
                if ms > MAX_DELAY_MS {
                    return Err(TemplateError::DelayOutOfRange {
                        ms,
                        limit: MAX_DELAY_MS,
                    });
                }
                Ok(Token::Delay(Duration::from_millis(ms)))
            }
            None => Err(TemplateError::UnknownPlaceholder(name.to_owned())),
        },
    }
}

/// 按鍵出口。實作：`MacSink`（CGEvent）或測試用 fake。
pub trait KeySink {
    /// 以 unicode string event 注入整段文字（不經鍵盤佈局）。
    fn unicode(&mut self, s: &str);
    /// 以虛擬 key code 注入實體鍵（down+up）。
    fn key(&mut self, kc: u16);
    fn sleep(&mut self, d: Duration);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmitStats {
    /// 注入的按鍵事件數（一段 unicode 算一次；空字串跳過不計）。
    pub typed: usize,
    /// 消费的機密欄位數（username/password 佔位符出現次數）。
    pub fields: usize,
}

/// 澆注模板。明文由呼叫端傳入（本 crate 不懂加密，也不日誌明文）。
pub fn emit(
    sink: &mut dyn KeySink,
    tpl: &TypeTemplate,
    username: &str,
    password: &str,
) -> EmitStats {
    let mut stats = EmitStats {
        typed: 0,
        fields: 0,
    };
    let mut just_delayed = false;
    for token in &tpl.tokens {
        if let Token::Delay(d) = token {
            sink.sleep(*d);
            just_delayed = true;
            continue; // 明確延遲本身就是間距，不疊 KEY_INTERVAL
        }
        if stats.typed > 0 && !just_delayed {
            sink.sleep(KEY_INTERVAL);
        }
        just_delayed = false;
        match token {
            Token::Username => {
                stats.fields += 1;
                if !username.is_empty() {
                    sink.unicode(username);
                    stats.typed += 1;
                }
            }
            Token::Password => {
                stats.fields += 1;
                if !password.is_empty() {
                    sink.unicode(password);
                    stats.typed += 1;
                }
            }
            Token::Tab => {
                sink.key(VK_TAB);
                stats.typed += 1;
            }
            Token::Enter => {
                sink.key(VK_RETURN);
                stats.typed += 1;
            }
            Token::Lit(s) => {
                if !s.is_empty() {
                    sink.unicode(s);
                    stats.typed += 1;
                }
            }
            Token::Delay(_) => unreachable!("上面已 continue"),
        }
    }
    stats
}

/// 倒數：`notify(剩餘秒)` 給 stderr/日誌提示，`sleep` 可注入（測試不真睡）。
pub fn countdown(mut notify: impl FnMut(u32), mut sleep: impl FnMut(Duration)) {
    for remaining in (1..=COUNTDOWN_SECS).rev() {
        notify(remaining);
        sleep(Duration::from_secs(1));
    }
}

/// CGEvent 按鍵出口。非 macOS 上存在且可執行（no-op），但不會註冊：
/// `new()` 恆回 None，daemon 據此回 Unsupported。
pub struct MacSink {
    #[cfg(target_os = "macos")]
    source: core_graphics::event_source::CGEventSource,
    #[cfg(not(target_os = "macos"))]
    _not_registered: (),
}

impl MacSink {
    /// 建立 HID 事件源。None = 本機不支援按鍵注入（非 macOS，或 CG 建立失敗）。
    #[cfg(target_os = "macos")]
    pub fn new() -> Option<Self> {
        use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
        // HIDSystemState：事件以硬件事件層進入，避免被 session 層的過濾丟棄
        CGEventSource::new(CGEventSourceStateID::HIDSystemState)
            .ok()
            .map(|source| Self { source })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Option<Self> {
        None
    }
}

/// 輔助使用（Accessibility）權限查詢。
/// CGEventPost 在**未授權時靜默丟事件**（不報錯），所以 autotype 前必須先查；
/// `prompt = true` 走 Apple 正統請求路徑：未授權時系統彈窗、並把本程式加入
/// 「設定 → 隱私與安全性 → 輔助使用」清單（該清單只列主動請求過的程式）。
/// 來源：https://developer.apple.com/documentation/applicationservices/1461188-axistrustedcheckoptionprompt
#[cfg(target_os = "macos")]
pub fn accessibility_trusted(prompt: bool) -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        // 以不透明指標宣告（CFStringRef）：直接宣告 CFString 會觸發 improper_ctypes
        static kAXTrustedCheckOptionPrompt: *const std::ffi::c_void;
        fn AXIsProcessTrusted() -> bool;
        fn AXIsProcessTrustedWithOptions(options: *const std::ffi::c_void) -> bool;
    }
    unsafe {
        if !prompt {
            return AXIsProcessTrusted();
        }
        let key = CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt as *const _);
        let dict = CFDictionary::<CFString, CFBoolean>::from_CFType_pairs(&[(
            key,
            CFBoolean::true_value(),
        )]);
        AXIsProcessTrustedWithOptions(dict.as_CFTypeRef())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn accessibility_trusted(_prompt: bool) -> bool {
    false
}

#[cfg(target_os = "macos")]
impl KeySink for MacSink {
    fn unicode(&mut self, s: &str) {
        use core_graphics::event::{CGEvent, CGEventTapLocation, KeyCode};
        if s.is_empty() {
            return;
        }
        for down in [true, false] {
            // keycode 只是載體：set_string 會覆寫事件的 unicode 負載，
            // 目標 app 收到的是字元而非鍵位（NOTES.md：CGEventKeyboardSetUnicodeString）。
            let Ok(ev) = CGEvent::new_keyboard_event(self.source.clone(), KeyCode::ANSI_A, down)
            else {
                return;
            };
            ev.set_string(s);
            ev.post(CGEventTapLocation::HID);
        }
    }

    fn key(&mut self, kc: u16) {
        use core_graphics::event::{CGEvent, CGEventTapLocation};
        for down in [true, false] {
            let Ok(ev) = CGEvent::new_keyboard_event(self.source.clone(), kc, down) else {
                return;
            };
            ev.post(CGEventTapLocation::HID);
        }
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(not(target_os = "macos"))]
impl KeySink for MacSink {
    fn unicode(&mut self, _s: &str) {}
    fn key(&mut self, _kc: u16) {}
    fn sleep(&mut self, _d: Duration) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Token> {
        TypeTemplate::parse(s).unwrap().tokens().to_vec()
    }

    #[derive(Default)]
    struct FakeSink {
        log: Vec<String>,
    }

    impl KeySink for FakeSink {
        fn unicode(&mut self, s: &str) {
            self.log.push(format!("unicode({s})"));
        }
        fn key(&mut self, kc: u16) {
            self.log.push(format!("key({kc:#04x})"));
        }
        fn sleep(&mut self, d: Duration) {
            self.log.push(format!("sleep({:?})", d.as_millis()));
        }
    }

    #[test]
    fn parses_default_template() {
        assert_eq!(
            toks(DEFAULT_TEMPLATE),
            vec![
                Token::Username,
                Token::Tab,
                Token::Password,
                Token::Tab,
                Token::Enter
            ]
        );
        assert_eq!(TypeTemplate::default().tokens().len(), 5);
    }

    #[test]
    fn placeholders_are_case_insensitive() {
        assert_eq!(
            toks("{UserName}{Enter}"),
            vec![Token::Username, Token::Enter]
        );
        assert_eq!(
            toks("{DELAY:5}"),
            vec![Token::Delay(Duration::from_millis(5))]
        );
    }

    #[test]
    fn literal_text_and_lone_brace() {
        assert_eq!(
            toks("ab{TAB}c}"),
            vec![Token::Lit("ab".into()), Token::Tab, Token::Lit("c}".into())]
        );
    }

    #[test]
    fn unknown_placeholder_rejected() {
        assert_eq!(
            TypeTemplate::parse("{user}").unwrap_err(),
            TemplateError::UnknownPlaceholder("user".into())
        );
        assert_eq!(
            TypeTemplate::parse("{").unwrap_err(),
            TemplateError::UnclosedBrace
        );
        assert_eq!(
            TypeTemplate::parse("a{").unwrap_err(),
            TemplateError::UnclosedBrace
        );
        assert_eq!(
            TypeTemplate::parse("{}").unwrap_err(),
            TemplateError::EmptyPlaceholder
        );
    }

    #[test]
    fn delay_boundaries() {
        assert_eq!(toks("{delay:0}"), vec![Token::Delay(Duration::ZERO)]);
        assert_eq!(
            toks("{delay:60000}"),
            vec![Token::Delay(Duration::from_millis(60_000))]
        );
        assert_eq!(
            TypeTemplate::parse("{delay:60001}").unwrap_err(),
            TemplateError::DelayOutOfRange {
                ms: 60_001,
                limit: 60_000
            }
        );
        assert!(matches!(
            TypeTemplate::parse("{delay:abc}").unwrap_err(),
            TemplateError::BadDelay(_)
        ));
        // u64 溢出不得 panic
        assert!(matches!(
            TypeTemplate::parse("{delay:99999999999999999999999}").unwrap_err(),
            TemplateError::BadDelay(_)
        ));
    }

    #[test]
    fn template_length_capped() {
        let big = "x".repeat(MAX_TEMPLATE_LEN + 1);
        assert!(matches!(
            TypeTemplate::parse(&big).unwrap_err(),
            TemplateError::TooLong(_)
        ));
    }

    #[test]
    fn emit_default_sequence_with_key_gaps() {
        let mut sink = FakeSink::default();
        let tpl = TypeTemplate::default();
        let stats = emit(&mut sink, &tpl, "me", "pw");
        let gap = format!("sleep({})", KEY_INTERVAL.as_millis());
        let expect =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| s.to_string()).collect() };
        assert_eq!(
            sink.log,
            expect(&[
                "unicode(me)",
                &gap,
                "key(0x30)",
                &gap,
                "unicode(pw)",
                &gap,
                "key(0x30)",
                &gap,
                "key(0x24)",
            ])
        );
        assert_eq!(
            stats,
            EmitStats {
                typed: 5,
                fields: 2
            }
        );
    }

    #[test]
    fn emit_skips_empty_values_and_gaps_only_between_keys() {
        let mut sink = FakeSink::default();
        let tpl = TypeTemplate::parse("{username}{TAB}{password}{enter}").unwrap();
        let stats = emit(&mut sink, &tpl, "", "x");
        let gap = format!("sleep({})", KEY_INTERVAL.as_millis());
        assert_eq!(
            sink.log,
            vec![
                "key(0x30)".to_string(),
                gap.clone(),
                "unicode(x)".to_string(),
                gap.clone(),
                "key(0x24)".to_string(),
            ]
        );
        assert_eq!(
            stats,
            EmitStats {
                typed: 3,
                fields: 2
            }
        );
    }

    #[test]
    fn emit_honors_explicit_delay_without_double_gap() {
        let mut sink = FakeSink::default();
        let tpl = TypeTemplate::parse("a{delay:250}b").unwrap();
        emit(&mut sink, &tpl, "u", "p");
        assert_eq!(
            sink.log,
            vec![
                "unicode(a)".to_string(),
                "sleep(250)".to_string(),
                "unicode(b)".to_string()
            ]
        );
    }

    #[test]
    fn countdown_notifies_3_2_1_with_injectable_sleep() {
        let mut secs = Vec::new();
        let mut sleeps = Vec::new();
        countdown(|r| secs.push(r), |d| sleeps.push(d));
        assert_eq!(secs, vec![3, 2, 1]);
        assert_eq!(sleeps, vec![Duration::from_secs(1); 3]);
    }

    #[test]
    fn mac_sink_not_registered_off_macos() {
        // 本測試跑在任意平台：只要求型別存在、new() 不 panic。
        let sink = MacSink::new();
        if cfg!(not(target_os = "macos")) {
            assert!(sink.is_none(), "非 macOS 不得註冊 CGEvent sink");
        }
    }
}
