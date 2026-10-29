//! BTP 協議與 vault 模型的共享型別（契約 §2.1、§2.5）。
//! 這是 Full/Thin 兩側唯一的共同語言：依賴方向即安全邊界（§3）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ItemId = Uuid;
pub type FolderId = Uuid;
pub type CollectionId = Uuid;
pub type FieldId = String;
pub type AttachmentId = Uuid;

/// Bitwarden 信封字串 `type.iv|ct|mac`。密文原樣是鏡像與伺服器的共同通货。
pub type EncStr = String;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ItemKind {
    #[default]
    Login,
    SecureNote,
    Card,
    Identity,
}

/// 讀取視窗三級；所有讀取簽名強制帶（契約 §2.1）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum View {
    Metadata,
    Masked,
    Reveal,
}

/// 靜態敏感度分級（契約 §2.1）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Sensitivity {
    Opaque,
    Identity,
    Secret,
}

/// grant / patch / SecretRef / audit 共用的唯一座標系。
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub enum FieldPath {
    Name,
    Notes,
    Username,
    Password,
    Totp,
    Uri(u32),
    FieldName(FieldId),
    FieldValue(FieldId),
    CardNumber,
    CardCode,
    SecurityCode,
    IdentityField(String),
    Attachment(AttachmentId),
}

/// 分級表：純函數，無配置（契約 §2.1）。username 預設 Secret，
/// 帳號政策可降為 Identity（降級發生在 policy 層，不在這裡）。
pub fn sensitivity_of(p: &FieldPath) -> Sensitivity {
    match p {
        FieldPath::Name | FieldPath::Uri(_) | FieldPath::FieldName(_) => Sensitivity::Identity,
        FieldPath::Notes
        | FieldPath::Username
        | FieldPath::Password
        | FieldPath::Totp
        | FieldPath::FieldValue(_)
        | FieldPath::CardNumber
        | FieldPath::CardCode
        | FieldPath::SecurityCode
        | FieldPath::IdentityField(_)
        | FieldPath::Attachment(_) => Sensitivity::Secret,
    }
}

/// Opaque+Identity 級欄位。任何視窗都完整出現；永不內含機密。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemMeta {
    pub id: ItemId,
    pub kind: ItemKind,
    pub name: Option<String>,
    pub uris: Vec<String>,
    pub folder_id: Option<FolderId>,
    pub organization_id: Option<CollectionId>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub updated_at: Option<String>,
    /// outbox 中有未推的變更
    pub pending: bool,
}

/// 依 `View` 構造的回傳型別：Metadata 下機密欄位在型別上不存在（契約 §2.1）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemView {
    pub meta: ItemMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Masked 形態（例：`••••12`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_masked: Option<String>,
    /// 僅 Reveal 構造且 grant 通過時為 Some。skip-if-none 是 A3 的結構保證：
    /// Metadata 輸出的 JSON 里 `password` 鍵根本不存在，不是 null。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub totp_available: bool,
}

impl ItemView {
    pub fn metadata(meta: ItemMeta) -> Self {
        Self {
            meta,
            username: None,
            password_masked: None,
            password: None,
            totp_available: false,
        }
    }
    pub fn masked(
        mut self,
        username: Option<String>,
        tail_mask: Option<String>,
        totp: bool,
    ) -> Self {
        debug_assert!(self.password.is_none());
        self.username = username;
        self.password_masked = tail_mask;
        self.totp_available = totp;
        self
    }
    pub fn revealed(mut self, password: Option<String>) -> Self {
        self.password = password;
        self.password_masked = None;
        self
    }
}

// —— BTP 訊息（契約 §2.5）——

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoVersion(pub u16);
pub const PROTO_VERSION: u16 = 1;

pub type SessionToken = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalId(pub Uuid);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MutationId(pub u64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Auth {
    Session {
        token: SessionToken,
    },
    Enroll {
        pairing: String,
        display_name: String,
    },
    Resume {
        session: SessionId,
        epoch: u64,
        mac: [u8; 32],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Call {
    Auth(AuthCall),
    Vault(VaultCall),
    Use(UseCall),
    Fill(FillCall),
    Sync(SyncCall),
    Agent(AgentCall),
    Admin(AdminCall),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthCall {
    Login {
        server: String,
        email: String,
        /// None ＝ daemon 端向人收（pinentry 式）；Some 只允許經加密本機通道
        password: Option<String>,
        api_key: Option<(String, String)>,
    },
    Unlock {
        biometric: bool,
    },
    Lock,
    /// 登出：清 token 與封存金鑰（鏡像保留）
    SignOut,
    WhoAmI,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Query {
    pub text: Option<String>,
    pub tag: Option<String>,
    pub uri: Option<String>,
    pub kind: Option<ItemKind>,
    pub sort: SortKey,
    pub limit: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortKey {
    #[default]
    Name,
    Updated,
    Created,
    Used,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VaultCall {
    List { query: Query, view: View },
    Get { id: ItemId, view: View },
    Create { draft: CipherDraft },
    Patch { id: ItemId, edits: Vec<FieldEdit> },
    Delete { ids: Vec<ItemId> },
    Restore { id: ItemId },
}

/// CLI 邊界的明文草稿；加密只發生在 daemon 的 `with_keys` 閉包。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CipherDraft {
    pub kind: ItemKind,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub favorite: bool,
}

/// 欄位編輯。path 文法三處共用（bw-vault flatten、bw-sync build_put_body、daemon）：
/// `name`、`notes`、`username`、`password`、`totp`、`uri.<n>`、`favorite`。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldEdit {
    pub path: String,
    /// None ＝清空
    pub value: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UseCall {
    TotpCode { id: ItemId },
    GeneratePassword { policy: serde_json::Value },
    ResolveRef { uri: String },
    Run { plan: RunPlan },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunPlan {
    pub argv: Vec<String>,
    /// 值可為 `btw://` ref 或字面；ref 需要 Use(InjectEnv)
    pub env: Vec<(String, String)>,
    pub cwd: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FillCall {
    Request { uri: String },
    Claim { plan_id: u64 },
    AutoType { id: ItemId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncCall {
    Trigger {
        force: bool,
    },
    Status,
    /// 衝突收件匣列表（只給路徑，值不外洩）。
    ListConflicts,
    ResolveConflict {
        id: MutationId,
        pick: Resolution,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    Ours,
    Theirs,
    Merge,
    KeepBoth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AgentCall {
    OpenSession {
        scopes: Vec<String>,
        ttl_secs: u64,
        name: String,
    },
    Approve {
        id: ApprovalId,
        grants: Option<Vec<String>>,
    },
    Revoke {
        session: SessionId,
    },
    ListSessions,
    /// 待人工核准的請求（e2e/GUI 取 id 用）
    ListPending,
    Audit {
        since: Option<String>,
        limit: u32,
    },
    /// hash 鏈驗證（A8）：回 {count, head, ok}
    AuditVerify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminCall {
    ServerProfile,
    Diagnostics,
    Version,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello {
        version: ProtoVersion,
        auth: Auth,
        wants: Vec<EventTopic>,
    },
    Invoke {
        rid: u64,
        call: Call,
    },
    Cancel {
        rid: u64,
    },
    /// 斷線補事件（治 bw serve 跑久損壞 #9306）
    Pull {
        cursor: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub kind: ServerKind,
    pub version: Option<String>,
    pub features: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerKind {
    BitwardenCloud,
    Vaultwarden,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum UnlockStateView {
    SignedOut,
    AuthLocked {
        items: u32,
    },
    Unlocking,
    Unlocked {
        epoch: u64,
        deadline_epoch_ms: Option<u64>,
    },
    Stale {
        why: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    Items(Vec<ItemView>),
    Item(Option<ItemView>),
    TotpCode {
        code: String,
        valid_for_secs: u32,
    },
    Secret(String),
    RunOutput {
        exit: Option<i32>,
        stdout: String,
        stderr: String,
    },
    Conflicts(Vec<ConflictEntry>),
    AgentSession {
        token: SessionToken,
        expires_epoch_ms: u64,
    },
    /// 行內容為自構 JSON（字串/整數，無 f64）——postcard-safe，見測試。
    Audit(Vec<serde_json::Value>),
    AuditChain(AuditChainInfo),
    Sessions(Vec<serde_json::Value>),
    Account(Option<AccountInfo>),
    Profile(ServerProfile),
    Version(String),
    Ok,
}

/// 全型別化回應：這是 P2 切 postcard 主線的前置（`Value` 的 f64 postcard 不支援）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub state: UnlockStateView,
    pub epoch: u64,
    pub items: u32,
    pub outbox: OutboxCounts,
    pub needs_reauth: bool,
    pub proto: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxCounts {
    pub queued: u32,
    pub in_flight: u32,
    pub awaiting: u32,
    pub conflict: u32,
    pub dead: u32,
    pub total: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub email: String,
    pub server: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditChainInfo {
    pub ok: bool,
    pub count: u64,
    pub head: String,
}

/// 衝突收件匣的一列。`fields` 是相撞的欄位路徑（無值：明文不進列表）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictEntry {
    pub id: MutationId,
    pub item: ItemId,
    pub base_rev: Option<String>,
    pub origin: Option<String>,
    pub created_at: u64,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerMsg {
    Welcome {
        proto: u16,
        epoch: u64,
        server: ServerProfile,
        state: UnlockStateView,
        events_from: u64,
    },
    Reply {
        rid: u64,
        outcome: Result<Response, WtpError>,
    },
    /// payload 只有 Opaque/Identity 級（協定紀律）
    Event {
        topic: EventTopic,
        seq: u64,
        payload: serde_json::Value,
    },
    NeedApproval {
        id: ApprovalId,
        summary: String,
    },
    Challenge {
        kind: String,
    },
}

/// 協定級錯誤。serde 表示穩定：JSON 用 externally-tagged，postcard 同。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum WtpError {
    #[error("session 綁定的鎖世代已過期（seen {seen}, now {now}）")]
    StaleEpoch { seen: u64, now: u64 },
    #[error("vault 未解鎖")]
    Locked,
    #[error("需要人工核准 {id:?}")]
    NeedsApproval { id: ApprovalId },
    #[error("核准逾時")]
    ApprovalExpired,
    #[error("授權不足：{grant_gap}")]
    Denied { grant_gap: String },
    #[error("not found")]
    NotFound,
    #[error("中樞離線（last_seen: {last_seen_epoch_ms:?}）")]
    HubOffline { last_seen_epoch_ms: Option<u64> },
    #[error("寫入衝突 #{id:?}，待裁決")]
    Conflict { id: MutationId },
    #[error("此功能尚未提供：{feature}")]
    Unsupported { feature: String },
    #[error("伺服器漂移：{detail}")]
    ServerDrift { detail: String },
    #[error("{ms}ms 後重試")]
    RetryAfter { ms: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventTopic {
    VaultChanged,
    LockStateChanged,
    OutboxDrained,
    ConflictDetected,
    ApprovalRequired,
    AgentUsage,
    EgressChanged,
    HubOnline,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ItemMeta {
        ItemMeta {
            id: ItemId::new_v4(),
            kind: ItemKind::Login,
            name: Some("github".into()),
            uris: vec!["https://github.com".into()],
            folder_id: None,
            organization_id: None,
            favorite: false,
            tags: vec!["dev".into()],
            updated_at: None,
            pending: false,
        }
    }

    #[test]
    fn sensitivity_table() {
        assert_eq!(sensitivity_of(&FieldPath::Name), Sensitivity::Identity);
        assert_eq!(sensitivity_of(&FieldPath::Uri(0)), Sensitivity::Identity);
        assert_eq!(sensitivity_of(&FieldPath::Password), Sensitivity::Secret);
        assert_eq!(sensitivity_of(&FieldPath::Username), Sensitivity::Secret);
        assert_eq!(sensitivity_of(&FieldPath::Totp), Sensitivity::Secret);
    }

    #[test]
    fn metadata_view_has_no_secret_fields() {
        let v = ItemView::metadata(meta());
        let j = serde_json::to_string(&v).unwrap();
        assert!(!j.contains("\"password\":\""));
        assert!(!j.contains("\"username\":\""));
        assert!(v.password.is_none() && v.username.is_none());
    }

    #[test]
    fn btp_roundtrip_postcard_and_json() {
        let msg = ClientMsg::Invoke {
            rid: 7,
            call: Call::Vault(VaultCall::List {
                query: Query {
                    text: Some("git".into()),
                    ..Default::default()
                },
                view: View::Metadata,
            }),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&bytes).unwrap().rid(), 7);
        let j = serde_json::to_vec(&msg).unwrap();
        assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 7);
    }

    impl ClientMsg {
        fn rid(&self) -> u64 {
            match self {
                ClientMsg::Invoke { rid, .. } => *rid,
                _ => u64::MAX,
            }
        }
    }

    #[test]
    fn error_variants_roundtrip() {
        let e = WtpError::StaleEpoch { seen: 3, now: 5 };
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<WtpError>(&j).unwrap(), e);
    }
}
