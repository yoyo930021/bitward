//! agent 治理純函數層（契約 §2.3）：grant 解析、判定表、用量帳本、出口淨化、SecretRef。
//! 這裡沒有 IO 也沒有金鑰；daemon 持有唯一入口 `call()`，把判定結果執行出來。

use std::collections::HashMap;

use bw_proto::Sensitivity;
use thiserror::Error;
use uuid::Uuid;

pub const REDACTED: &str = "«redacted»";

// —— Grant DSL ——

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Access {
    /// 讀 metadata；floor 決定能看到多高敏感度的欄位
    See(Sensitivity),
    /// 用而不讀
    Use(UseKind),
    /// 取明文（會進 context）
    Reveal(Sensitivity),
    Mutate(MutateOp),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UseKind {
    TotpCode,
    InjectEnv,
    Run,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MutateOp {
    Create,
    Patch,
    Delete,
    Move,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Target {
    All,
    Item(Uuid),
    Folder(Uuid),
    Collection(Uuid),
    Tag(String),
    /// 後綴比對：example.com 命中 https://github.com/login 需 host 後綴相符
    UriDomain(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Budget {
    pub max_uses: Option<u32>,
    pub max_bytes_out: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub access: Access,
    pub target: Target,
    pub budget: Budget,
    /// true 時使用需先經人工核准（NeedApproval 流程）
    pub requires_approval: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantSet(pub Vec<Grant>);

impl GrantSet {
    /// Interactive 全權：每個判定維度都給到最高 floor、Target::All、無預算上限。
    pub fn default_full() -> Self {
        use bw_proto::Sensitivity::*;
        let g = |access: Access| Grant {
            access,
            target: Target::All,
            budget: Budget::default(),
            requires_approval: false,
        };
        GrantSet(vec![
            g(Access::See(Secret)),
            g(Access::Reveal(Secret)),
            g(Access::Use(UseKind::TotpCode)),
            g(Access::Use(UseKind::InjectEnv)),
            g(Access::Use(UseKind::Run)),
            g(Access::Mutate(MutateOp::Create)),
            g(Access::Mutate(MutateOp::Patch)),
            g(Access::Mutate(MutateOp::Delete)),
            g(Access::Mutate(MutateOp::Move)),
        ])
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("empty grant segment")]
    EmptySegment,
    #[error("unknown access {0}")]
    UnknownAccess(String),
    #[error("unknown target {0}")]
    UnknownTarget(String),
    #[error("bad uuid in {0}")]
    BadUuid(String),
    #[error("bad number in {0}")]
    BadNumber(String),
}

/// DSL：`;` 分隔多條。每條 `<access> <target> [uses=N] [bytes=N] [approve]`。
/// access ∈ `see:identity|see:secret|use:totp|use:env|use:run|reveal:identity|reveal:secret|mutate:create|...`
/// target ∈ `all|item:<uuid>|folder:<uuid>|collection:<uuid>|tag:<name>|uri:<domain>`
/// 範例：`see:identity all; use:totp item:<uuid> uses=50; reveal:secret item:<uuid> uses=1 approve`
pub fn parse_grants(spec: &str) -> Result<GrantSet, ParseError> {
    let mut out = Vec::new();
    for seg in spec.split(';') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let mut it = seg.split_whitespace();
        let access_tok = it.next().ok_or(ParseError::EmptySegment)?;
        let target_tok = it.next().ok_or(ParseError::EmptySegment)?;
        let access = parse_access(access_tok)?;
        let target = parse_target(target_tok)?;
        let mut budget = Budget::default();
        let mut requires_approval = false;
        for m in it {
            match m {
                "approve" => requires_approval = true,
                x => {
                    let (k, v) = x
                        .split_once('=')
                        .ok_or_else(|| ParseError::UnknownAccess(x.to_string()))?;
                    match k {
                        "uses" => {
                            budget.max_uses = Some(
                                v.parse()
                                    .map_err(|_| ParseError::BadNumber(x.to_string()))?,
                            )
                        }
                        "bytes" => {
                            budget.max_bytes_out = Some(
                                v.parse()
                                    .map_err(|_| ParseError::BadNumber(x.to_string()))?,
                            )
                        }
                        _ => return Err(ParseError::UnknownAccess(x.to_string())),
                    }
                }
            }
        }
        out.push(Grant {
            access,
            target,
            budget,
            requires_approval,
        });
    }
    if out.is_empty() {
        return Err(ParseError::EmptySegment);
    }
    Ok(GrantSet(out))
}

fn parse_access(tok: &str) -> Result<Access, ParseError> {
    let (head, arg) = tok
        .split_once(':')
        .ok_or_else(|| ParseError::UnknownAccess(tok.to_string()))?;
    let sens = |s: &str| match s {
        "identity" => Some(Sensitivity::Identity),
        "secret" => Some(Sensitivity::Secret),
        _ => None,
    };
    match head {
        "see" => sens(arg)
            .map(Access::See)
            .ok_or_else(|| ParseError::UnknownAccess(tok.to_string())),
        "reveal" => sens(arg)
            .map(Access::Reveal)
            .ok_or_else(|| ParseError::UnknownAccess(tok.to_string())),
        "use" => match arg {
            "totp" => Ok(Access::Use(UseKind::TotpCode)),
            "env" => Ok(Access::Use(UseKind::InjectEnv)),
            "run" => Ok(Access::Use(UseKind::Run)),
            _ => Err(ParseError::UnknownAccess(tok.to_string())),
        },
        "mutate" => match arg {
            "create" => Ok(Access::Mutate(MutateOp::Create)),
            "patch" => Ok(Access::Mutate(MutateOp::Patch)),
            "delete" => Ok(Access::Mutate(MutateOp::Delete)),
            "move" => Ok(Access::Mutate(MutateOp::Move)),
            _ => Err(ParseError::UnknownAccess(tok.to_string())),
        },
        _ => Err(ParseError::UnknownAccess(tok.to_string())),
    }
}

fn parse_target(tok: &str) -> Result<Target, ParseError> {
    if tok == "all" {
        return Ok(Target::All);
    }
    let (kind, arg) = tok
        .split_once(':')
        .ok_or_else(|| ParseError::UnknownTarget(tok.to_string()))?;
    match kind {
        "item" => Ok(Target::Item(uuid(arg, tok)?)),
        "folder" => Ok(Target::Folder(uuid(arg, tok)?)),
        "collection" => Ok(Target::Collection(uuid(arg, tok)?)),
        "tag" => Ok(Target::Tag(arg.to_string())),
        "uri" => Ok(Target::UriDomain(arg.to_lowercase())),
        _ => Err(ParseError::UnknownTarget(tok.to_string())),
    }
}

fn uuid(s: &str, ctx: &str) -> Result<Uuid, ParseError> {
    Uuid::parse_str(s).map_err(|_| ParseError::BadUuid(ctx.to_string()))
}

// —— 判定 ——

/// 一筆請求的判定輸入。daemon 從 Call + 目標 item 的 metadata 組出來。
#[derive(Clone, Debug)]
pub struct CallReq {
    pub access: Access,
    pub item: Option<Uuid>,
    pub tags: Vec<String>,
    /// 小寫 host 或 uri 字串，供 UriDomain 後綴比對
    pub uris: Vec<String>,
    pub est_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// 命中第 N 條 grant（索引對 GrantSet.0）
    Allow(usize),
    /// 命中但該 grant 要求人工核准
    NeedApproval(usize),
}

/// 判定表：由呼叫端對每個候選 grant 逐一询问 `match_grant`，這裡不排序不投機。
/// 回傳第一個命中（Allow 優先於 NeedApproval 由呼叫端決定取捨：這裡回全部命中，
/// daemon 取「最寬鬆可用」語意＝有 Allow 用 Allow）。
pub fn check(set: &GrantSet, req: &CallReq) -> Result<Decision, String> {
    let mut approval: Option<usize> = None;
    for (i, g) in set.0.iter().enumerate() {
        if !same_access(g.access, req.access) || !target_matches(g, req) {
            continue;
        }
        if g.requires_approval {
            approval.get_or_insert(i);
        } else {
            return Ok(Decision::Allow(i));
        }
    }
    match approval {
        Some(i) => Ok(Decision::NeedApproval(i)),
        None => Err(format!("no grant for {:?}", req.access)),
    }
}

fn same_access(a: Access, b: Access) -> bool {
    use Access::*;
    match (a, b) {
        // grant 的 floor 必須涵蓋請求的敏感度：see:secret ⊇ see:identity ⊇ see:opaque
        (See(x), See(y)) | (Reveal(x), Reveal(y)) => x >= y,
        (Use(x), Use(y)) => x == y,
        (Mutate(x), Mutate(y)) => x == y,
        _ => false,
    }
}

fn target_matches(g: &Grant, req: &CallReq) -> bool {
    match &g.target {
        Target::All => true,
        Target::Item(id) => req.item == Some(*id),
        Target::Tag(t) => req.tags.iter().any(|x| x == t),
        Target::UriDomain(d) => req
            .uris
            .iter()
            .any(|u| host_of(u).is_some_and(|h| h == d.as_str() || h.ends_with(&format!(".{d}")))),
        // P3：folder/collection 歸屬需 daemon 提供 item 的歸屬資料；未提供時不命中
        Target::Folder(_) | Target::Collection(_) => false,
    }
}

fn host_of(uri: &str) -> Option<&str> {
    let after = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri);
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    (!host.is_empty()).then_some(host)
}

// —— 用量帳本 ——

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// grant 索引 → 用量
    usage: HashMap<usize, Usage>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Usage {
    pub total: u32,
    pub per_item: HashMap<String, u32>,
    pub bytes: u64,
}

impl Ledger {
    pub fn budget_ok(&self, g: &Grant, idx: usize, item: Option<Uuid>, bytes: u64) -> bool {
        let _ = item;
        let (total, acc) = self
            .usage
            .get(&idx)
            .map(|u| (u.total, u.bytes))
            .unwrap_or((0, 0));
        if let Some(max) = g.budget.max_uses
            && total + 1 > max
        {
            return false;
        }
        if let Some(max) = g.budget.max_bytes_out
            && acc + bytes > max
        {
            return false;
        }
        true
    }

    pub fn record(&mut self, idx: usize, item: Option<Uuid>, bytes: u64) {
        let e = self.usage.entry(idx).or_default();
        e.total += 1;
        e.bytes += bytes;
        if let Some(i) = item {
            *e.per_item.entry(i.to_string()).or_insert(0) += 1;
        }
    }

    pub fn snapshot(&self) -> &HashMap<usize, Usage> {
        &self.usage
    }
}

// —— SecretRef ——

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub item: Uuid,
    /// FieldPath 文法字串（password|totp|username|notes|field.<id>）
    pub field: String,
}

#[derive(Error, Debug)]
pub enum RefError {
    #[error("bad secret ref: {0}")]
    Bad(String),
}

/// `btw://<uuid>/<field>`
pub fn parse_ref(s: &str) -> Result<SecretRef, RefError> {
    let rest = s
        .strip_prefix("btw://")
        .ok_or_else(|| RefError::Bad(s.to_string()))?;
    let (item, field) = rest
        .split_once('/')
        .ok_or_else(|| RefError::Bad(s.to_string()))?;
    if field.is_empty() {
        return Err(RefError::Bad(s.to_string()));
    }
    Ok(SecretRef {
        item: Uuid::parse_str(item).map_err(|_| RefError::Bad(s.to_string()))?,
        field: field.to_string(),
    })
}

// —— Redactor ——

/// 出口淨化：凡是已知明文值出現在要進 LLM context 的文字裡，一律取代。
/// 實證根據：73.5% 的 agent 洩漏來自 stdout 直接進 context（arXiv 2604.03070）。
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    needles: Vec<String>,
}

impl Redactor {
    pub fn new<I: IntoIterator<Item = String>>(values: I) -> Self {
        let mut needles: Vec<String> = values.into_iter().filter(|v| v.len() >= 3).collect();
        // 長值先替換，避免短值是長值子字串時的錯替換
        needles.sort_by_key(|b| std::cmp::Reverse(b.len()));
        needles.dedup();
        Self { needles }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    /// 回傳替換次數。
    pub fn scrub(&self, text: &mut String) -> usize {
        let mut n = 0;
        for needle in &self.needles {
            while let Some(pos) = text.find(needle.as_str()) {
                text.replace_range(pos..pos + needle.len(), REDACTED);
                n += 1;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::parse_str("0f0d0000-0000-4000-8000-0000000000c1").unwrap()
    }

    #[test]
    fn parse_full_dsl() {
        let g = parse_grants(&format!(
            "see:identity all; use:totp item:{0} uses=50; reveal:secret item:{0} uses=1 bytes=64 approve",
            id()
        ))
        .unwrap();
        assert_eq!(g.0.len(), 3);
        assert_eq!(g.0[0].access, Access::See(Sensitivity::Identity));
        assert_eq!(g.0[1].budget.max_uses, Some(50));
        assert!(g.0[2].requires_approval);
        assert_eq!(g.0[2].budget.max_bytes_out, Some(64));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_grants("fly:high all").is_err());
        assert!(parse_grants("see:identity item:notauuid").is_err());
        assert!(parse_grants("  ").is_err());
        assert!(parse_grants("see:identity all uses=x").is_err());
    }

    fn req(access: Access) -> CallReq {
        CallReq {
            access,
            item: Some(id()),
            tags: vec!["dev".into()],
            uris: vec!["https://github.com/login".into()],
            est_bytes: 8,
        }
    }

    #[test]
    fn check_allow_deny_and_approval() {
        let set = parse_grants(&format!("see:identity all; use:totp item:{0}", id())).unwrap();
        assert_eq!(
            check(&set, &req(Access::See(Sensitivity::Identity))).unwrap(),
            Decision::Allow(0)
        );
        assert_eq!(
            check(&set, &req(Access::Use(UseKind::TotpCode))).unwrap(),
            Decision::Allow(1)
        );
        assert!(check(&set, &req(Access::Reveal(Sensitivity::Secret))).is_err());
        // See(secret) 需要 floor 涵蓋：see:identity 不涵蓋 secret 請求
        assert!(check(&set, &req(Access::See(Sensitivity::Secret))).is_err());

        let ap = parse_grants(&format!("reveal:secret item:{0} approve", id())).unwrap();
        assert_eq!(
            check(&ap, &req(Access::Reveal(Sensitivity::Secret))).unwrap(),
            Decision::NeedApproval(0)
        );
    }

    #[test]
    fn check_prefer_unapproved_over_approved() {
        let set = parse_grants(&format!(
            "reveal:secret item:{0} approve; reveal:secret all",
            id()
        ))
        .unwrap();
        assert_eq!(
            check(&set, &req(Access::Reveal(Sensitivity::Secret))).unwrap(),
            Decision::Allow(1)
        );
    }

    #[test]
    fn uri_domain_suffix_match() {
        let set = parse_grants("use:run uri:example.com").unwrap();
        let mut r = req(Access::Use(UseKind::Run));
        r.uris = vec![
            "https://sub.example.com/x".into(),
            "https://evil.test".into(),
        ];
        assert!(matches!(check(&set, &r), Ok(Decision::Allow(0))));
        let set2 = parse_grants("use:run uri:evil.io").unwrap();
        assert!(check(&set2, &r).is_err());
    }

    #[test]
    fn ledger_budget() {
        let set = parse_grants(&format!("reveal:secret item:{0} uses=2 bytes=16", id())).unwrap();
        let g = &set.0[0];
        let mut l = Ledger::default();
        assert!(l.budget_ok(g, 0, Some(id()), 8));
        l.record(0, Some(id()), 8);
        assert!(l.budget_ok(g, 0, Some(id()), 0)); // 1 use, 8 bytes
        l.record(0, Some(id()), 8);
        assert!(!l.budget_ok(g, 0, Some(id()), 0)); // uses 已滿
        let l2 = Ledger::default();
        assert!(!l2.budget_ok(g, 0, Some(id()), 17)); // bytes 上限
    }

    #[test]
    fn ref_parse() {
        let r = parse_ref(&format!("btw://{0}/password", id())).unwrap();
        assert_eq!(r.item, id());
        assert_eq!(r.field, "password");
        assert!(parse_ref("btw://nope/password").is_err());
        assert!(parse_ref("http://x/y").is_err());
        assert!(parse_ref(&format!("btw://{0}/", id())).is_err());
    }

    #[test]
    fn redactor_scrubs_longest_first() {
        let rd = Redactor::new(["abc".to_string(), "abcdef".to_string(), "x".to_string()]);
        let mut s = "pw=abcdef tail=abc short=x".to_string();
        let n = rd.scrub(&mut s);
        assert_eq!(n, 2); // "x" 太短（<3）不收
        assert_eq!(s, format!("pw={REDACTED} tail={REDACTED} short=x"));
    }
}
