//! BTP 協議與 vault 模型的共享型別（契約 §2.1、§2.5）。
//! 這是 Full/Thin 兩側唯一的共同語言：依賴方向即安全邊界（§3）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod wire;

pub type ItemId = Uuid;
pub type FolderId = Uuid;
pub type CollectionId = Uuid;
pub type FieldId = String;
/// 附件 id：伺服器生成——VW 1.37.2 實錄為 20 位 hex（非 UUID，
/// `dev/e2e/attachments.sh` 同源 probe），官方雲同為不透明字串。
pub type AttachmentId = String;

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

/// 官方 `card` 節欄位名（線格式鍵名，六欄全 EncString；查證：clients
/// `libs/common/src/vault/models/domain/card.ts`）。路徑文法 `card.<欄名>`。
pub const CARD_FIELDS: [&str; 6] = [
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
];

/// 官方 `identity` 節欄位名（線格式鍵名，十八欄全 EncString；查證：clients
/// `libs/common/src/vault/models/domain/identity.ts`）。路徑文法 `identity.<欄名>`。
pub const IDENTITY_FIELDS: [&str; 18] = [
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
];

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
    /// 卡片節非遮罩欄（cardholderName／brand／expMonth／expYear）：置尾紀律
    /// （postcard 變體索引追加）。number/code 用既有 CardNumber／CardCode 座標。
    CardField(String),
}

/// 欄位路徑字串（`FieldEdit::Set` 文法，見其文件）→ 敏感度座標。
/// 卡片／身分節的欄名按線格式鍵名原樣進座標系（`card.number` → CardNumber、
/// `card.code` → CardCode、其餘 `card.<f>` → CardField(f)、`identity.<f>` →
/// IdentityField(f)）。非 card/identity 路徑回 None（呼叫端自有既有映射）。
#[must_use]
pub fn card_identity_path_to_field_path(path: &str) -> Option<FieldPath> {
    if let Some(f) = path.strip_prefix("card.") {
        return Some(match f {
            "number" => FieldPath::CardNumber,
            "code" => FieldPath::CardCode,
            other if CARD_FIELDS.contains(&other) => FieldPath::CardField(other.to_owned()),
            _ => return None,
        });
    }
    let f = path.strip_prefix("identity.")?;
    IDENTITY_FIELDS
        .contains(&f)
        .then(|| FieldPath::IdentityField(f.to_owned()))
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
        | FieldPath::CardField(_)
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
    /// 共享歸屬（P4b）：cipher 所屬 collection id 集合；個人項目恆為空
    #[serde(default)]
    pub collections: Vec<CollectionId>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub updated_at: Option<String>,
    /// outbox 中有未推的變更
    pub pending: bool,
    /// 垃圾桶條目的軟刪時刻（鏡像 `deletedDate`，ISO 字串）；未刪恆 None。
    /// 投影自 raw 鏡像（協定欄位原樣），不是本地時鐘。
    #[serde(default)]
    pub deleted_at: Option<String>,
    /// 封存時刻（鏡像 `archivedDate`，ISO 字串）；未封存恆 None。
    /// 投影紀律同 `deleted_at`：協定欄位原樣，非本地時鐘。
    #[serde(default)]
    pub archived_at: Option<String>,
    /// 各網址列的 match 判定（鏡像 `login.uris[].match` 明文整數；缺欄＝None
    /// 預設）。順序對齊 `uris`；鎖定態（Metadata 視窗）不讀鏡像恆空，
    /// Masked/Reveal 由 `project_one` 回填（GUI 編輯面 match 下拉的基準值）。
    #[serde(default)]
    pub uri_matches: Vec<Option<u8>>,
}

/// 卡片節投影（type 3；六欄全 EncString，欄名鍵＝官方線格式，見 [`CARD_FIELDS`]）。
/// `number`/`code` 是遮罩欄：Masked 給 `number_masked`（末四碼）＋`code_masked`
/// （固定點號，不洩長度），Reveal 才出全值——紀律同 `password`/`password_masked`。
/// 其餘四欄（持卡人／品牌／有效月／有效年）解鎖即可讀，Masked/Reveal 同形。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<String>,
    /// 卡號遮罩態（例：`••••4242`；僅 Masked）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_masked: Option<String>,
    /// 卡號全值（僅 Reveal；A3 紀律：鍵缺席不是 null）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// CVV 遮罩態（固定 `••••`；僅 Masked 且有值）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_masked: Option<String>,
    /// CVV 全值（僅 Reveal）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// 身分節投影（type 4；十八欄全 EncString，欄名鍵見 [`IDENTITY_FIELDS`]）。
/// 官方詳情頁語意＝解鎖即可讀（同 `notes`/`username`），故 Masked/Reveal 同形、
/// 無遮罩欄；Metadata（鎖定態）整節缺席。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_number: Option<String>,
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
    /// 筆記明文（SecureNote 本體欄；Notes 為 Secret 級，Metadata 下鍵不存在）。
    /// Masked/Reveal 均帶全文（官方詳情頁語意：解鎖即可讀筆記）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// 自訂欄位（順序同線格式 `fields[]`）。Metadata 下恆為空（欄名是密文，
    /// 鎖定態解不了）；Masked 帶 text 欄值、hidden 欄值為 None；Reveal 全帶。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<CipherField>,
    /// 附件元資料（批次 4a）。Metadata/鎖定態恆為空（檔名是信封字串）；
    /// Masked/Reveal 帶解密檔名。內容位元組只經 Download 出口。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentMeta>,
    /// 卡片節（type 3，PR1）。Metadata 恆 None（欄位全密文）；Masked 帶四欄
    /// 明文＋卡號/CVV 遮罩態；Reveal 帶卡號/CVV 全值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardView>,
    /// 身分節（type 4，PR1）。Metadata 恆 None；Masked/Reveal 帶全十八欄。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityView>,
}

impl ItemView {
    pub fn metadata(meta: ItemMeta) -> Self {
        Self {
            meta,
            username: None,
            password_masked: None,
            password: None,
            totp_available: false,
            notes: None,
            fields: Vec::new(),
            attachments: Vec::new(),
            card: None,
            identity: None,
        }
    }

    /// 附掛 Secret 級詳情（筆記＋自訂欄＋附件元資料）；呼叫端已按 `View`
    /// 決定值可見性。
    pub fn with_details(
        mut self,
        notes: Option<String>,
        fields: Vec<CipherField>,
        attachments: Vec<AttachmentMeta>,
    ) -> Self {
        self.notes = notes;
        self.fields = fields;
        self.attachments = attachments;
        self
    }

    /// 附掛型別節（卡片／身分）；呼叫端已按 `View` 決定遮罩形態（紀律同
    /// [`Self::with_details`]）。
    pub fn with_card_identity(
        mut self,
        card: Option<CardView>,
        identity: Option<IdentityView>,
    ) -> Self {
        self.card = card;
        self.identity = identity;
        self
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

/// `Vec<u8>` 的線形態：JSON 走 base64 字串（serde 預設的數字陣列在
/// MiB 級附件上膨脹 4 倍且爆 BTP 幀），postcard 下同為緊湊字符串。
pub mod bytes_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(de::Error::custom)
    }
}

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
        /// Some(配對碼) = 跨機 Device session（§1.2 異機配對）；
        /// None = 本機 UDS 互動端（peer uid 已驗）
        pair_code: Option<String>,
    },
    Resume {
        session: SessionId,
        epoch: u64,
        mac: [u8; 32],
    },
}

// 線型枚舉：變體尺寸差是協議形態本質（大載體變體 vs 空變體）；
// 裝箱＝每幀多一次分配＋全庫 match 改寫，得不償失。lint 明拒。
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Call {
    Auth(AuthCall),
    Vault(VaultCall),
    Use(UseCall),
    Fill(FillCall),
    Sync(SyncCall),
    Agent(AgentCall),
    Admin(AdminCall),
    /// 置尾紀律：postcard 變體索引追加（P2 主線是 postcard，插在中间會移位舊變體）
    Passkey(PasskeyCall),
    /// 置尾（同上紀律）：APNs 推播 token 管理（§1.2 推播路徑）
    Push(PushCall),
    /// 置尾（同上紀律）：服務端 2FA 因子管理面（`/two-factor/*` 代理，PR3）。
    TwoFactor(TwoFactorCall),
    /// 置尾（同上紀律）：緊急存取（EA）管理與唯讀視圖（PR4）。
    EmergencyAccess(EaCall),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthCall {
    Login {
        server: String,
        email: String,
        /// None ＝ daemon 端向人收（pinentry 式）；Some 只允許經加密本機通道
        password: Option<String>,
        api_key: Option<(String, String)>,
        /// 登入第二步（2FA）：None＝第一步；Some＝帶因子與碼重送。
        /// 置尾＋`default`：舊幀缺欄＝None（語意＝第一步，postcard 變體序不動）。
        /// 伺服器挑戰不在 daemon 快取——hash 可由 password 重算，第二步由
        /// 呼叫端原樣重發 Login（理由見 hub::login 註解）。
        #[serde(default)]
        two_factor: Option<TwoFactorInput>,
    },
    Unlock {
        biometric: bool,
        /// 批次 14a：主密碼離線驗證（PSK MAC，不打網路）。None＋!biometric＝
        /// 裝置憑證路徑，僅在 `lock_on_sleep_restart=false`（自動解鎖 opt-in）
        /// 時放行；向後相容 default。
        #[serde(default)]
        password: Option<String>,
    },
    Lock,
    /// 登出：清 token 與封存金鑰（鏡像保留）
    SignOut,
    /// 產生一次性配對碼（跨機 thin 用，§1.2）
    PairStart {
        name: String,
        grant: String,
        ttl_secs: u64,
    },
    PairList,
    PairRevoke {
        code: String,
    },
    WhoAmI,
    /// 改主密碼（需解鎖態）。置尾紀律：postcard 變體索引只追加。
    /// None ＝ daemon 端向人收（同 Login 語意）；Some 只允許經加密本機通道，
    /// 明文密碼不得進 argv（A11）。
    ChangePassword {
        current: Option<String>,
        new: Option<String>,
    },
}

/// 登入第二步的使用者輸入。`provider` 是 upstream `TwoFactorProviderType` 編號
/// （見 [`TwoFactorProviderInfo`]）；`token` 為一次性代碼，明文紀律同
/// `AuthCall::Login` 的 password（只走本機線，不落 argv）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorInput {
    pub provider: i32,
    pub token: String,
    /// 要求伺服器記住此裝置（`twoFactorRemember=1`）。
    pub remember: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Query {
    pub text: Option<String>,
    pub tag: Option<String>,
    pub uri: Option<String>,
    /// 以密碼/帳號值精確搜尋（FR 11941；依賴本機明文索引，§2.7 R3）
    pub value: Option<String>,
    pub kind: Option<ItemKind>,
    pub sort: SortKey,
    pub limit: u32,
    /// 只列該 collection 的項目（P4b org 共享語意；`serde(default)` 保舊形相容）
    #[serde(default)]
    pub collection: Option<CollectionId>,
    /// 資料夾過濾（官方型別語意三態）：None＝全部；
    /// `Some("")`＝個人未歸屬（鏡像 `folderId IS NULL`）；`Some(id)`＝該資料夾。
    #[serde(default)]
    pub folder: Option<String>,
    /// 垃圾桶三態（布林旗關不得取代）：None／Some(false)＝只列未刪（現行預設）；
    /// Some(true)＝垃圾桶。軟刪項目的 `deleted_at` 見 `ItemMeta`。
    #[serde(default)]
    pub deleted: Option<bool>,
    /// 封存三態（官方 archivedDate 語意，同 deleted 手法）：None／Some(false)＝
    /// 排除已封存（主列表預設）；Some(true)＝只列已封存。與 `deleted` 正交合成。
    #[serde(default)]
    pub archived: Option<bool>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortKey {
    #[default]
    Name,
    Updated,
    Created,
    Used,
}

// 線型枚舉：變體尺寸差是協議形態本質（大載體變體 vs 空變體）；
// 裝箱＝每幀多一次分配＋全庫 match 改寫，得不償失。lint 明拒。
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VaultCall {
    List {
        query: Query,
        view: View,
    },
    Get {
        id: ItemId,
        view: View,
    },
    Create {
        draft: CipherDraft,
    },
    Patch {
        id: ItemId,
        edits: Vec<FieldEdit>,
    },
    Delete {
        ids: Vec<ItemId>,
    },
    Restore {
        id: ItemId,
    },
    Overlay {
        id: ItemId,
        op: OverlayOpWire,
    },
    FindDuplicates,
    Merge {
        keep: ItemId,
        dupes: Vec<ItemId>,
    },
    /// org None = unshare 回個人 vault
    MoveToOrg {
        item: ItemId,
        org: Option<String>,
        collections: Vec<String>,
    },
    /// 置尾紀律（postcard 變體索引追加）：資料夾三操作（官方 `/folders` 語意）。
    /// 建立＝同步 `POST /folders`（名稱 daemon 端以 user key 加密）；
    /// 離線時回錯不入列（資料夾非 outbox 載體，批次 2 GUI 再評估佇列化）。
    CreateFolder {
        name: String,
    },
    /// 資料夾清單；回應 `Response::Json`（[{"id","name"}]，鎖定態 name 為 null——
    /// 名稱是信封字串，金鑰不在時不猜）。
    ListFolders,
    /// 刪除資料夾：先將夾內項目 `folderId` 清 NULL（逐筆入 outbox patch），
    /// 再 `DELETE /folders/{id}`，最後摘除鏡像列（官方客戶端同序語意）。
    DeleteFolder {
        id: FolderId,
    },
    /// 硬刪（置尾紀律）：本機鏡像永久移除。VW 端既有 DELETE 路徑若已軟刪
    /// （`deletedDate` 有值＝垃圾桶條目），Purge 只做本地——鏡像行＋關聯＋
    /// 該 item 的 outbox 未推列一併清除，不發伺服器請求。
    /// 未軟刪的項目直接 Purge＝拒絕（`Denied`），避免本地消失但伺服器仍在。
    Purge {
        id: ItemId,
    },
    /// 置尾（同上紀律）：**原子批次匯入**。語意＝本地佇列全收或全拒
    /// （單交易寫鏡像＋outbox，任何一筆驗證失敗整批回滾），drain 逐筆推
    /// VW（VW 無批次端點，推送失敗走既有 outbox 重試/衝突佇列，
    /// 非分散式事務）。上限 500 筆防呆。
    /// `format`：官方 `bw import` 的格式參數佔位；本批 true/false 語意相同
    /// （明文集直入建立路徑，無第三方格式直譯），GUI 不需分支。
    Import {
        items: Vec<ImportItem>,
        format: bool,
    },
    /// 置尾（同上紀律）：附件四操作（VW 免費開放；語意見 `AttachmentOp`）。
    /// 清單走既有 ItemView（`attachments` 欄），無獨立 List 呼叫。
    Attachment {
        sub: AttachmentOp,
    },
    /// 置尾（同上紀律）：封存／取消封存（官方 `archivedDate` 語意）。
    /// 線格式查證（VW 1.37.2，2026-11-10）：`PUT /ciphers/{id}/partial` 帶
    /// archivedDate 回 422（partial 只有 folderId/favorite——既有 quirk 同形），
    /// **全量 PUT 帶 archivedDate 落庫**且 `/sync` 原樣返回；故實作照
    /// delete/restore 先例走 outbox 專屬 op，drain 端以即時 theirs 為基底
    /// 改 archivedDate 後全量 PUT（item key 層原樣隨鏡像帶回，不動金鑰欄）。
    /// 離線＝入列待推（收斂語意同寫路徑紀律）。
    SetArchived {
        id: ItemId,
        archived: bool,
    },
    /// 置尾（同上紀律）：網站圖示代理。daemon 打 `{server}/icons/{host}/icon.png`
    /// （VW 根路徑，非 /api；查證：未啟用路由的 server 回 404 → 本側轉
    /// `NotFound`，GUI 退回字母磚）並落盤快取（`data_dir/icons/`，TTL 7 天，
    /// 同 host 併發單飛去重）。回應 `Response::AttachmentBytes`（PNG/ICO 原樣位元組）。
    /// 隱私註記：本呼叫會向伺服器請求該 host——伺服器本來就存著含此 host 的
    /// 項目（icon 請求無新增外洩面）；VW 對解析失敗的 host 回占位 PNG（實錄
    /// 200＋19×19 gray），故成功分支不保證「該網站真有圖示」。
    GetIcon {
        host: String,
    },
    /// 置尾（同上紀律）：**報告儀表板**三操作（子孫見 `Reports`）。回包全部
    /// 去敏——重用只回 id 群集（`Response::DupGroups`）、弱密碼只回分數
    /// （`Response::Json`，明文只在 daemon 打分閉包內存活、不落盤）、
    /// 歷史只回日期＋解密名稱＋uri 數（名稱出口屬 Identity 級，同列表鏡像）。
    Reports {
        sub: Reports,
    },
    /// 置尾（同上紀律）：**Send 加密分享**五操作（子孫見 `SendOp`）。
    /// 無 outbox——建立/改密/刪除需連網（Send 語意＝交連結即存在，佇列
    /// 會造出「以為分享了其實沒有」的假象）；離線時回 `Denied` 可懂錯誤。
    Send {
        sub: SendOp,
    },
}

/// 弱密碼列管門檻：`password_score` **低於**此值進報告（zxcvbn 口徑 0–2＝可猜）。
/// daemon 過濾與 GUI 圖例共用同一個數，不在兩處重述。
pub const WEAK_PASSWORD_THRESHOLD: u8 = 3;

/// 報告面（VaultCall::Reports 子孫；置尾紀律同宿主）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reports {
    /// 重用密碼報告：既有 `FindDuplicates` 的 (host, username) 群集投影換形，
    /// 資料源同一條（`Response::DupGroups`），不另起掃描。
    PasswordReuse,
    /// 弱密碼報告：鏡像全量解密打分（需解鎖態；未解鎖回 `Locked`），
    /// `bw_crypto::password_score` < 3 列管。回應 `Response::Json`
    /// （{"threshold":3,"items":[{"id","name","score"}]}，分數升序）。
    WeakPasswords,
    /// 項目版本歷史：代理伺服器 `GET /api/ciphers/{id}/history`（官方舊版線格式，
    /// 查證記錄見 daemon `reports_cipher_history`）。VW 1.37.2 未實裝該路由
    /// （實錄 404）→ 回 {"supported":false,"versions":[]}，GUI 據此收合歷史節。
    CipherHistory { id: ItemId },
}

/// Send 面（`VaultCall::Send` 子孫；置尾紀律同宿主）。加密模型見 bw-crypto
/// `send.rs` 模組頭；端點與語意見 bw-server `sends.rs` 模組頭。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendOp {
    /// 建立。`name` None＝daemon 按內容推預設（文字首行截 32 字元／檔名）。
    /// `content` 為**明文**（本機線紀律同 `AttachmentOp::Upload`：加密發生在
    /// daemon `with_keys` 閉包，金鑰與 seed 不出閉包）；檔案 ≤32 MiB
    /// （借附件上限紀律，daemon 入口擋）。
    /// `password`：取用密碼明文（daemon 換成官方 wire 哈希再上線）。
    /// `deletion_hours`：到期刪除（官方選單 1/7/30 天＝24/168/720；
    /// 伺服器硬上限 31 天，VW `create_send` 實錄 400）。
    /// `max_access`：存取上限（None＝不限；0 拒收）。
    /// 成功回 `Response::Json`（{"id","url","webUrl","name","deletionDate"}——
    /// `url` 帶 seed 片段，屬 Secret 級出口；`webUrl`＝本機接收頁同形變體，
    /// daemon webui 未起時為 null）。
    Create {
        name: Option<String>,
        content: SendContent,
        password: Option<String>,
        deletion_hours: u32,
        max_access: Option<u32>,
        hide_email: bool,
    },
    /// 鏡像清單（`/sync` 的 `sends[]` 與線上 `GET /sends` 刷新落庫；
    /// 離線照回鏡像）。回應 `Response::Json`（{"items":[{"id","type",
    /// "name","url","webUrl","deletionDate","expirationDate","maxAccessCount","accessCount",
    /// "viewed","hideEmail","hasPassword"}]}，deletionDate 升序；`webUrl`＝
    /// 本機接收頁變體（webui 未起或鎖態為 null）；
    /// `name`/`url` 需解鎖態（seed 鏡像端為 user key 信封），鎖態為 null——
    /// 資料夾清單同語意；`viewed`＝accessCount>0（伺服器無 viewed 欄，實錄））。
    List,
    /// 分享 URL：`{帳號 server 值}/#/send/{accessId}/{b64url(seed)}`
    /// （官方 web vault 同形：`getSendUrl()+accessId+"/"+urlB64Key`）。
    /// 需解鎖態（seed 從鏡像 `key` 信封解出）；回應 `Response::Json`
    /// （{"id","url","webUrl"}，webUrl＝本機接收頁變體）。審計只記動作與 id，
    /// **不落片段**（A11 延伸）。
    Get { id: ItemId },
    /// 刪除（需連網；伺服器 404＝已不存在，照收斂摘鏡像列回 Ok）。
    Remove { id: ItemId },
    /// 取用密碼：`Some`＝設/換（`PUT /sends/{id}` 帶新哈希，seed 不變＝
    /// 既有連結的解密密鑰不受影響）；`None`＝清除（`remove-password`）。
    /// 需解鎖態＋連網；回應 `Response::Json`（{"id","hasPassword"}）。
    Password {
        id: ItemId,
        password: Option<String>,
    },
}

/// Send 內容二態（`SendOp::Create` 載體）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendContent {
    Text {
        text: String,
    },
    /// `bytes` 明文檔身（同附件 Upload 紀律）；`file_name` 原檔名
    /// （daemon 加密後逐字上傳——VW 比對 multipart filename 與登記檔名）。
    File {
        file_name: String,
        #[serde(with = "bytes_b64")]
        bytes: Vec<u8>,
    },
}

/// WebAuthn passkey 操作（macOS autofill 契約 §1）：金鑰與業務全在 daemon，
/// Swift 端只做翻譯。GetPasskeys 是 Metadata 級（public_key 是公開材料，
/// 私鑰/信封 keyValue 永不進回應）；Register/Assert 需取用私鑰（授權分級見 agent §2.1 表）。
/// SE 生物綁定金鑰的私鑰運算在 appex 內（Rust 碰不到 Secure Enclave），
/// 故註冊走「Swift 匯入公鑰」+ 斷言走「BeginAssert/FinishAssert 兩步事務」。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PasskeyCall {
    GetPasskeys {
        /// None = 全 vault；Some = 只列該 relying party
        rp_id: Option<String>,
    },
    RegisterPasskey {
        rp_id: String,
        challenge: String,
        user_name: String,
        user_handle: String,
        display_name: String,
        /// None = 新建 login item；Some = 附加到既有 item
        item_id: Option<ItemId>,
        /// SE 流：Swift 由 SecKey（Secure Enclave 生物綁定金鑰）匯出的
        /// b64url DER SubjectPublicKeyInfo。Some = daemon 不生成私鑰，
        /// keyValue 改存此公鑰、attestation COSE 段由 SPKI 轉出。
        /// id 由本呼叫隨機生成——Swift 整合請用 BeginRegister/FinishRegister
        /// （tag 先行協商）；單步 SE 流留給 CLI/測試。
        /// None = 既有純軟體流（測試/相容用）。
        #[serde(default)]
        credential_public_key: Option<String>,
    },
    AssertPasskey {
        credential_id: String,
        challenge: String,
        rp_id: String,
        /// Apple 流：系統只給 clientDataHash（=sha256(系統要送 RP 的 clientDataJSON)）。
        /// Some 時簽名輸入直接用它（authData ‖ hash），不自建 JSON 再雜湊——
        /// 否則 RP 以系統 JSON 驗簽必敗（真機實測 NotAllowedError 根因）。
        #[serde(default)]
        client_data_hash: Option<String>,
        /// Some = 簽名已在 Swift 側由 SE 金鑰完成：daemon 不簽名，只做
        /// 「找憑證 → 以 authData‖clientDataHash 驗簽 → 通過才 counter++
        /// 持久化進 outbox」。簽名對的 authData 由 daemon 決定，呼叫端須先
        /// 跑 BeginAssert 取得（或接受 daemon 以本次 counter 現算）。
        /// None = 軟體鑰流：daemon 以 keyValue 私鑰自簽（既有行為）。
        #[serde(default)]
        signature: Option<String>,
        /// Swift 側 keychain item 的不透明標籤（SE 金鑰識別）；daemon 不解釋，
        /// 僅隨呼叫接收。與 `signature` 成對出現。
        #[serde(default)]
        key_id: Option<String>,
    },
    /// 兩步斷言事務·第一步：daemon 以儲存公鑰流找憑證、算 counter+1、
    /// 產生 authData 並暫存 pending（不持久化 counter）。冪等：同 credential
    /// 重複 Begin 覆蓋 pending。
    BeginAssert {
        credential_id: String,
        /// b64url(32B)。rp_id 不再傳：以憑證內儲存的 rpId 為準。
        client_data_hash: String,
    },
    /// 兩步斷言事務·第二步：daemon 用 pending 的 authData‖clientDataHash
    /// 驗 `signature`（b64url DER，Swift 由 SE 金鑰產生）→ 通過才 counter
    /// 持久化進 outbox；不符 → Err(Denied) 且 counter 不動。
    FinishAssert {
        credential_id: String,
        signature: String,
    },
    /// 兩步註冊事務·第一步：簽發 credential id（32B 隨機 → b64url）。
    /// 解掉「SE 金鑰 tag 必須先於註冊協商」的循環依賴：Swift 拿 id 作
    /// SecKey tag 生金鑰，再以 FinishRegister 交回公鑰。無狀態：重複
    /// Begin 只是再抽一個 id，以最後取得的為準。
    BeginRegister {
        rp_id: String,
        user_name: String,
        user_handle: String,
        display_name: String,
        /// None = 新建 login item；Some = 附加到既有 item
        item_id: Option<ItemId>,
    },
    /// 兩步註冊事務·第二步：幀自含全部欄位（daemon 重啟不影响 Finish）。
    /// daemon 校驗 credential_id 格式（32B）與唯一性，以 SPKI 轉 COSE 組
    /// attestation（counter=1），存 fido2Credentials（keyValue=SPKI b64url
    /// 信封、authenticationType=platform-aaguid）→ 回 PasskeyAttestation。
    FinishRegister {
        /// BeginRegister 簽發的 b64url id（同時是 Swift 側 SecKey tag）
        credential_id: String,
        /// b64url DER SubjectPublicKeyInfo（SE 公鑰）
        credential_public_key: String,
        rp_id: String,
        challenge: String,
        user_name: String,
        user_handle: String,
        display_name: String,
        item_id: Option<ItemId>,
    },
    /// 刪除單條憑證（macOS 設定面：GUI 詳情頁 Passkeys 節）。`item_id` 是
    /// 呼叫端見解（GetPasskeys 列出的歸屬），daemon 以 `find_credential` 的
    /// 實查為準——兩者不符回 NotFound，不照單刪錯項目。鏡像 removal 走
    /// counter++ 同款全量 PUT 路徑（`enqueue_passkey_patch`），伺服器
    /// fido2Credentials 同步收斂（VW PUT 實錄見 e2e settings.sh）。
    DeletePasskey {
        item_id: ItemId,
        credential_id: String,
    },
}

/// APNs 推播 token 管理（§1.2 推播路徑正式分發形態）：iOS 端上報 device token，
/// daemon 於 ntfy 同源時機把同一條不透明信令逐 token 副發。回應重用 Ok 與
/// Json（陣列 of {"token","platform"}），不加 Response 變體——置尾紀律只約束
/// 必要新增；Json 值限字串（postcard-safe，見 Audit 註解）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PushCall {
    /// `platform` 是用戶端來源標記（"ios"|"watchos"…），daemon 不解釋、原樣存。
    /// 冪等：同 token 重複註冊覆蓋 platform/時刻（app 每次啟動都上報）。
    RegisterPush { token: String, platform: String },
    /// 卸載/退出時自撤；未知 token 回 Ok（收斂語意同 410 清理）。
    UnregisterPush { token: String },
    /// 註冊清單（Admin 級出口；token 去敏後回傳，見 daemon 分派）。
    ListPush,
}

/// 服務端 2FA 因子管理面（PR3 子批 b）：daemon 代理 upstream `/two-factor/*` 端點。
/// `master_password` 是主密碼明文，紀律同 `AuthCall::Login`：None＝呼叫端未帶
/// （daemon 拒，本倉無 pinentry 通道），Some 只允許經本機線送（A11 不得進 argv）。
/// daemon 以 prelogin KDF 換成伺服器的 `masterPasswordHash`（派生在 bw-crypto，
/// 不在本 crate、也不在 bw-server），因此改因子不需要 vault 解鎖態。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TwoFactorCall {
    /// 已啟用因子清單（`GET /two-factor`）
    List,
    /// 取 TOTP 設定（`POST /two-factor/get-authenticator`）→ [`Response::TwoFactorTotp`]
    GetAuthenticator { master_password: Option<String> },
    /// 啟用 TOTP（`POST /two-factor/authenticator`；`token`＝驗證器現碼、
    /// `key`＝GetAuthenticator 回的 secret）
    EnableAuthenticator {
        master_password: Option<String>,
        token: String,
        key: String,
    },
    /// 停用因子（`POST /two-factor/disable`；`provider`＝upstream 編號）
    Disable {
        master_password: Option<String>,
        provider: i32,
    },
    /// 取備用救援碼（`POST /two-factor/get-recover`）→ [`Response::TwoFactorRecoveryCode`]
    GetRecoveryCode { master_password: Option<String> },
    /// 寄 Email 因子驗證碼（`POST /two-factor/send-email`；伺服器落一個
    /// EmailVerificationChallenge，需再以 EmailVerify 收碼確認）
    EmailSendCode {
        master_password: Option<String>,
        email: String,
    },
    /// 確認 Email 因子（`PUT /two-factor/email`；`token`＝信中收到的碼）
    EmailVerify {
        master_password: Option<String>,
        email: String,
        token: String,
    },
    /// 啟用 YubiKey（`POST /two-factor/yubikey`；`otp`＝tap 出的 44 字元，
    /// 伺服器以首 12 字元為金鑰 id 落庫，需 server 端 Yubico 憑證）
    EnableYubikey {
        master_password: Option<String>,
        otp: String,
    },
}

/// 一個因子在伺服器的啟用狀態（管理面清單條目）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorProviderState {
    /// upstream `TwoFactorProviderType` 編號（見 [`TwoFactorProviderInfo::label`]）
    pub provider: i32,
    pub enabled: bool,
}

/// 緊急存取（EA）呼叫（PR4）：daemon 代理 upstream `emergency-access/*` 端點。
/// 狀態機（官方 readme 與 Vaultwarden 1.37.2 `src/api/core/emergency_access.rs`）：
/// invite→accept→confirm→initiate→approve/逾時→view/takeover。
/// `ea_id` 是 EA 記錄 id（端點路徑參數），不是 vault ItemId。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EaCall {
    /// 我授權的對象清單（`GET {base}/trusted`，我在 grantor 側）
    ListGrantees,
    /// 授權給我的對象清單（`GET {base}/granted`，我在 grantee 側）
    ListGrantors,
    /// 邀請（`POST {base}/invite`）。VW 未啟 mail 時對既有帳號直接 Accepted
    /// （源檔 `send_invite` 分支），雲端則停在 Invited 等對方 accept。
    Invite {
        email: String,
        access_type: EaAccessType,
        wait_time_days: u32,
    },
    /// grantor 確認（`POST {base}/{id}/confirm`）：daemon 以受託人 RSA 公鑰
    /// （OAEP-SHA1，同 org invite 的 `wrap_org_key` 一支）包裝自己的 user key
    /// 作 `key`。需要解鎖態；grantee 的 user id 由 daemon 查 trusted 清單取得。
    Confirm { ea_id: String },
    /// 撤銷（`DELETE {base}/{id}`，grantor/grantee 兩側皆可，源檔同路徑）。
    Revoke { ea_id: String },
    /// grantee 發起恢復（`POST {base}/{id}/initiate`，C2）：狀態 Confirmed →
    /// RecoveryInitiated，等待 `wait_time_days` 後伺服器自動批准
    /// （`emergency_request_timeout_job`，排程預設每天一跑）。
    Initiate { ea_id: String },
    /// grantor 批准恢復（`POST {base}/{id}/approve`，C2）→ RecoveryApproved。
    Approve { ea_id: String },
    /// grantor 拒絕恢復（`POST {base}/{id}/reject`，C2）→ 回 Confirmed。
    Reject { ea_id: String },
    /// grantee 唯讀視圖（`POST {base}/{id}/view`，C2）：daemon 拉
    /// `{ciphers,keyEncrypted}`，以己RSA 私鑰解出 grantor user key，經
    /// `Hub::cipher_decrypt_key` 外部鑰視窗投影成 Reveal 級 `ItemView` 清單。
    /// 需要解鎖態（解私鑰信封）；結果按 `LockEpoch` 快取——上鎖即失效。
    View { ea_id: String },
    /// 接管（C3）：daemon 一鍵走 `POST {base}/{id}/takeover`（拿 grantor
    /// KDF＋keyEncrypted）→ 己 RSA 私鑰解出 grantor user key → 以新主密碼
    /// 重包 akey＋算 hash → `POST {base}/{id}/password`。`new_password` 明文
    /// 紀律同 `AuthCall::ChangePassword`（只走本機線，不落 argv，A11）。
    /// 伺服器語意（源檔 `password_emergency_access`）：改 grantor 主密碼、
    /// **清空其全部 2FA 因子**、踢非 Owner 組織成員身分——接管即重生。
    Takeover { ea_id: String, new_password: String },
}

/// EA 存取等級（upstream `EmergencyAccessType`：0=View、1=Takeover）。
/// View＝唯讀帳密；Takeover＝可改主密碼接管帳號。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EaAccessType {
    View,
    Takeover,
}

impl EaAccessType {
    pub fn from_wire(v: i64) -> Self {
        match v {
            1 => EaAccessType::Takeover,
            _ => EaAccessType::View,
        }
    }
    pub fn wire(self) -> i64 {
        match self {
            EaAccessType::View => 0,
            EaAccessType::Takeover => 1,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            EaAccessType::View => "檢視",
            EaAccessType::Takeover => "接管",
        }
    }
}

/// EA 狀態機位置（upstream `EmergencyAccessStatus` 0..4；未知編號原樣承載）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EaStatus {
    Invited,
    Accepted,
    Confirmed,
    RecoveryInitiated,
    RecoveryApproved,
    Other(i32),
}

impl EaStatus {
    pub fn from_wire(v: i64) -> Self {
        match v {
            0 => EaStatus::Invited,
            1 => EaStatus::Accepted,
            2 => EaStatus::Confirmed,
            3 => EaStatus::RecoveryInitiated,
            4 => EaStatus::RecoveryApproved,
            other => EaStatus::Other(other as i32),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            EaStatus::Invited => "已邀請",
            EaStatus::Accepted => "已接受（待確認）",
            EaStatus::Confirmed => "已確認",
            EaStatus::RecoveryInitiated => "恢復請求中",
            EaStatus::RecoveryApproved => "恢復已批准",
            EaStatus::Other(_) => "未知狀態",
        }
    }
}

/// 清單列的視角：同一支 `EaContact` 服務兩側清單。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EaRole {
    /// 我在 grantor 側：`user_id`/`email` 是受託人（grantee）
    Grantee,
    /// 我在 grantee 側：`user_id`/`email` 是授權人（grantor）
    Grantor,
}

/// 一條緊急存取關係（daemon 由 `trusted`/`granted` 回包解析，欄位寬容）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EaContact {
    /// EA 記錄 id（confirm/initiate/… 端點的路徑參數）
    pub id: String,
    /// 對方 user id；邀請未被接受前伺服器只有 email → None
    pub user_id: Option<String>,
    pub email: String,
    pub name: String,
    pub status: EaStatus,
    pub access_type: EaAccessType,
    pub wait_time_days: u32,
    /// 恢復發起時刻（ISO 字串）。VW 1.37.2 的清單回包**不含**此欄（源檔
    /// `to_json_grantee_details`）→ None；官方雲有（`recoveryInitiatedDate`）。
    #[serde(default)]
    pub recovery_initiated_at: Option<String>,
    pub role: EaRole,
}

/// passkey 條目的 Metadata 級視圖：b64url 識別材料 + 公鑰，無密鑰。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyEntry {
    pub credential_id: String,
    pub user_handle: String,
    pub user_name: String,
    pub rp_id: String,
    /// b64url DER SubjectPublicKeyInfo（公開材料；Swift 直接匯入 SecKey 比對）。
    /// 選 SPKI 而非 COSE：SecKey 匯入端點只認 SPKI/PKCS#8，免 Swift 端再拆 CBOR。
    /// 舊資料無此欄 → 空字串。
    #[serde(default)]
    pub public_key: String,
    /// 憑證歸屬項目（macOS 設定面：GUI 詳情頁按 item 過濾＋刪除定位用）。
    /// 置尾＋`default`：舊 daemon 回包缺欄＝None（JSON 寬容，紀律同 StatusInfo）。
    #[serde(default)]
    pub item_id: Option<ItemId>,
}

/// overlay 操作（tags/pin/last-used）：協定無這些欄位，本地權威（§2.4）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OverlayOpWire {
    AddTag(String),
    RemoveTag(String),
    SetPinned(bool),
    Touch,
}

/// 附件操作（批次 4a；`VaultCall::Attachment { sub }` 承載）。
/// 線格式實錄（VW 1.37.2 probe）：上傳＝`POST /ciphers/{id}/attachment`
/// multipart（`key`＝附件金鑰信封字串、`data`＝密文檔，data 段的
/// multipart filename 原樣落 `fileName`——所以我們傳**加密後**的檔名）；
/// 下載＝`GET /ciphers/{id}/attachment/{aid}` 取短效簽名 URL 再直連取位元組；
/// 刪除＝`DELETE /ciphers/{id}/attachment/{aid}`。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AttachmentOp {
    /// `bytes` 為**明文**檔內容（本機線安全紀律，與 Login password 同級：
    /// 只走 UDS/TLS，加密發生在 daemon `with_keys` 閉包）。
    /// 上限 32 MiB（daemon 入列前擋；BTP 幀上限見 bw-btp MAX_FRAME）。
    Upload {
        item_id: ItemId,
        file_name: String,
        #[serde(with = "bytes_b64")]
        bytes: Vec<u8>,
    },
    /// 回應 `Response::AttachmentBytes`（解密後的明文位元組，同機線紀律）。
    Download {
        item_id: ItemId,
        attachment_id: AttachmentId,
    },
    Delete {
        item_id: ItemId,
        attachment_id: AttachmentId,
    },
}

/// 附件元資料（ItemView 投影；檔名/尺寸名鏡像端為信封字串，
/// 解鎖投影時解密——VW 自算的 sizeName 可能是明文，解不開原樣回傳）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub id: AttachmentId,
    pub file_name: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub size_name: Option<String>,
}

/// 自訂欄型別（官方 `login.fields[].type`：0=text、1=hidden、2=boolean）。
/// boolean 與官方 jslib 同形：值存 "true"/"false" 字串（信封承載）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherFieldKind {
    #[default]
    Text,
    Hidden,
    Boolean,
}

impl CipherFieldKind {
    /// 線格式 type 整數（VW/官方雲共同形態）。
    pub fn wire(self) -> u8 {
        match self {
            CipherFieldKind::Text => 0,
            CipherFieldKind::Hidden => 1,
            CipherFieldKind::Boolean => 2,
        }
    }
    /// 鏡像 type 整數 → 型別；未知值寬容歸 Text（raw 鏡像才是真相源）。
    #[must_use]
    pub fn from_wire(v: i64) -> Self {
        match v {
            1 => CipherFieldKind::Hidden,
            2 => CipherFieldKind::Boolean,
            _ => CipherFieldKind::Text,
        }
    }
}

/// 自訂欄位（官方 `login.fields[]` 的本地形態）。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CipherField {
    pub name: String,
    /// None ＝ 空值（官方允許 fields[].value 為 null）
    #[serde(default)]
    pub value: Option<String>,
    /// text／hidden／boolean（批次 3：取代舊 hidden 布林旗標）
    #[serde(default)]
    pub kind: CipherFieldKind,
}

/// `Debug` 去敏用的佔位標記：包裹可能含明文的值，只報「有無」不報內容（V7）。
struct Masked<T>(T);
impl<T: Maskable> core::fmt::Debug for Masked<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.is_present() {
            f.write_str("Some(<masked>)")
        } else {
            f.write_str("None")
        }
    }
}

trait Maskable {
    fn is_present(&self) -> bool;
}
impl Maskable for Option<String> {
    fn is_present(&self) -> bool {
        self.is_some()
    }
}
impl Maskable for &Option<String> {
    fn is_present(&self) -> bool {
        self.as_ref().is_some()
    }
}

/// CLI 邊界的明文草稿；加密只發生在 daemon 的 `with_keys` 閉包。
///
/// `Debug` 手寫去敏（V7）：password/totp/notes/username/自訂欄值/卡節/身分節
/// 一律遮罩，只留 kind/name/uris/favorite/folder_id 等非機密欄——防止核准摘要
/// 或 `tracing::debug!(?draft)` 把明文推上 ntfy/APNs。
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CipherDraft {
    pub kind: ItemKind,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    /// 建立時即歸屬的資料夾 id（UUID 字串；None＝不歸屬）。
    /// 非 UUID 字串由 daemon 拒收（鏡像 `folderId` 存原字串，查詢比對用）。
    #[serde(default)]
    pub folder_id: Option<String>,
    /// 自訂欄位（順序即線格式 `fields[]` 順序）
    #[serde(default)]
    pub fields: Vec<CipherField>,
    /// 各網址列的 match 判定（對齊 `uris[]` 索引；缺欄/缺項＝null 預設）。
    /// 官方線格式 `login.uris[].match` 明文整數（見 `FieldEdit::SetUriMatch`）。
    #[serde(default)]
    pub uri_matches: Vec<Option<u8>>,
    /// 卡片節明文草稿（type 3；僅 kind==Card 時有效）。欄名見 [`CARD_FIELDS`]，
    /// 加密發生在 daemon `with_keys` 閉包（同 password 紀律，A11 不落 argv 預設）。
    #[serde(default)]
    pub card: Option<CardDraft>,
    /// 身分節明文草稿（type 4；僅 kind==Identity 時有效）。欄名見 [`IDENTITY_FIELDS`]。
    #[serde(default)]
    pub identity: Option<IdentityDraft>,
}

impl core::fmt::Debug for CipherDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CipherDraft")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("username", &Masked(&self.username))
            .field("password", &Masked(&self.password))
            .field("totp", &Masked(&self.totp))
            .field("uris", &self.uris)
            .field("notes", &Masked(&self.notes))
            .field("favorite", &self.favorite)
            .field("folder_id", &self.folder_id)
            .field("fields", &MaskedFields(&self.fields))
            .field("uri_matches", &self.uri_matches)
            .field("card", &self.card.as_ref().map(|_| "CardDraft(<masked>)"))
            .field(
                "identity",
                &self.identity.as_ref().map(|_| "IdentityDraft(<masked>)"),
            )
            .finish()
    }
}

/// 自訂欄清單的去敏投影：留 name/kind，值遮罩（hidden/text 欄值都可能含機密）。
struct MaskedFields<'a>(&'a [CipherField]);
impl core::fmt::Debug for MaskedFields<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut l = f.debug_list();
        for field in self.0 {
            l.entry(&(field.name.as_str(), field.kind, Masked(&field.value)));
        }
        l.finish()
    }
}

/// 卡片節明文草稿（官方 `card` 六欄；None/空字串＝該欄不寫）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardDraft {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

/// 身分節明文草稿（官方 `identity` 十八欄；None/空字串＝該欄不寫）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityDraft {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

impl CardDraft {
    /// 線鍵名 → 欄位槽（CLI/GUI `k=v` 輸入端白名單；未知鍵回 None）。
    #[must_use]
    pub fn slot_mut(&mut self, key: &str) -> Option<&mut Option<String>> {
        Some(match key {
            "cardholderName" => &mut self.cardholder_name,
            "brand" => &mut self.brand,
            "number" => &mut self.number,
            "expMonth" => &mut self.exp_month,
            "expYear" => &mut self.exp_year,
            "code" => &mut self.code,
            _ => return None,
        })
    }
}

impl IdentityDraft {
    /// 線鍵名 → 欄位槽（白名單同 [`CardDraft::slot_mut`]）。
    #[must_use]
    pub fn slot_mut(&mut self, key: &str) -> Option<&mut Option<String>> {
        Some(match key {
            "title" => &mut self.title,
            "firstName" => &mut self.first_name,
            "middleName" => &mut self.middle_name,
            "lastName" => &mut self.last_name,
            "address1" => &mut self.address1,
            "address2" => &mut self.address2,
            "address3" => &mut self.address3,
            "city" => &mut self.city,
            "state" => &mut self.state,
            "postalCode" => &mut self.postal_code,
            "country" => &mut self.country,
            "company" => &mut self.company,
            "email" => &mut self.email,
            "phone" => &mut self.phone,
            "ssn" => &mut self.ssn,
            "username" => &mut self.username,
            "passportNumber" => &mut self.passport_number,
            "licenseNumber" => &mut self.license_number,
            _ => return None,
        })
    }
}

/// 官方未加密匯出（`bw export --format json`）的 `card` 節 → 明文草稿。
/// 空字串／null 欄跳過；全空回 None（不憑空造節）。CLI 與 GUI 匯入器共用。
#[must_use]
pub fn card_draft_from_export(section: Option<&serde_json::Value>) -> Option<CardDraft> {
    let obj = section?.as_object()?;
    let mut d = CardDraft::default();
    for key in CARD_FIELDS {
        if let Some(v) = obj.get(key).and_then(serde_json::Value::as_str)
            && !v.is_empty()
            && let Some(slot) = d.slot_mut(key)
        {
            slot.replace(v.to_owned());
        }
    }
    (d != CardDraft::default()).then_some(d)
}

/// 官方未加密匯出的 `identity` 節 → 明文草稿（語意同 [`card_draft_from_export`]）。
#[must_use]
pub fn identity_draft_from_export(section: Option<&serde_json::Value>) -> Option<IdentityDraft> {
    let obj = section?.as_object()?;
    let mut d = IdentityDraft::default();
    for key in IDENTITY_FIELDS {
        if let Some(v) = obj.get(key).and_then(serde_json::Value::as_str)
            && !v.is_empty()
            && let Some(slot) = d.slot_mut(key)
        {
            slot.replace(v.to_owned());
        }
    }
    (d != IdentityDraft::default()).then_some(d)
}

/// 卡片節 → 匯出 JSON（官方鍵名、空欄 null；語意同 [`card_draft_to_export`]）。
#[must_use]
pub fn card_view_to_export(v: &CardView) -> serde_json::Value {
    serde_json::json!({
        "cardholderName": v.cardholder_name,
        "brand": v.brand,
        "number": v.number,
        "expMonth": v.exp_month,
        "expYear": v.exp_year,
        "code": v.code,
    })
}

/// 身分節 → 匯出 JSON（語意同 [`card_view_to_export`]）。
#[must_use]
pub fn identity_view_to_export(v: &IdentityView) -> serde_json::Value {
    serde_json::json!({
        "title": v.title,
        "firstName": v.first_name,
        "middleName": v.middle_name,
        "lastName": v.last_name,
        "address1": v.address1,
        "address2": v.address2,
        "address3": v.address3,
        "city": v.city,
        "state": v.state,
        "postalCode": v.postal_code,
        "country": v.country,
        "company": v.company,
        "email": v.email,
        "phone": v.phone,
        "ssn": v.ssn,
        "username": v.username,
        "passportNumber": v.passport_number,
        "licenseNumber": v.license_number,
    })
}

/// 草稿節 → 匯出 JSON 節（官方鍵名、空欄 null）；None 節＝鍵缺席。
#[must_use]
pub fn card_draft_to_export(d: &Option<CardDraft>) -> Option<serde_json::Value> {
    let d = d.as_ref()?;
    Some(serde_json::json!({
        "cardholderName": d.cardholder_name,
        "brand": d.brand,
        "number": d.number,
        "expMonth": d.exp_month,
        "expYear": d.exp_year,
        "code": d.code,
    }))
}

/// 身分草稿節 → 匯出 JSON（語意同 [`card_draft_to_export`]）。
#[must_use]
pub fn identity_draft_to_export(d: &Option<IdentityDraft>) -> Option<serde_json::Value> {
    let d = d.as_ref()?;
    Some(serde_json::json!({
        "title": d.title,
        "firstName": d.first_name,
        "middleName": d.middle_name,
        "lastName": d.last_name,
        "address1": d.address1,
        "address2": d.address2,
        "address3": d.address3,
        "city": d.city,
        "state": d.state,
        "postalCode": d.postal_code,
        "country": d.country,
        "company": d.company,
        "email": d.email,
        "phone": d.phone,
        "ssn": d.ssn,
        "username": d.username,
        "passportNumber": d.passport_number,
        "licenseNumber": d.license_number,
    }))
}

/// 批次匯入的一筆（`VaultCall::Import` 載體）。draft 是**明文欄位結構**：
/// 與 `AuthCall::Login` 的 password 同級紀律——明文只走 UDS/TLS 本機線
/// （A11：不落 argv），加密發生在 daemon `with_keys` 閉包。
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportItem {
    #[serde(default)]
    pub draft: CipherDraft,
    /// 本地 overlay 標籤（§2.4：協定無 tags 欄位，匯入時直落 overlay 表）
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `Debug` 委派 `CipherDraft` 的去敏投影（V7）：draft 內明文字段已遮罩，tags 非機密原樣留。
impl core::fmt::Debug for ImportItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportItem")
            .field("draft", &self.draft)
            .field("tags", &self.tags)
            .finish()
    }
}

/// 欄位編輯。`Set` 的 path 文法三處共用（bw-vault flatten、bw-sync build_put_body、daemon）：
/// `name`、`notes`、`username`、`password`、`totp`、`uri.<n>`、`favorite`、
/// `folderId`（明文 UUID 字串；None＝移出資料夾）、
/// `field.<n>.name`／`field.<n>.value`（`<n>` 為 0 起 `fields[]` 索引）、
/// `field.<n>.type`（值域 `text|hidden|boolean`，見 `SetType`）、
/// `card.<欄名>`／`identity.<欄名>`（PR1 型別節：欄名＝官方線鍵名白名單，
/// 值域見 `CARD_FIELDS`／`IDENTITY_FIELDS`；全欄 EncString，None＝清 null）。
/// 增刪欄位走 `AppendField`／`RemoveField`（陣列形態變更，非 leaf 值編輯）。
///
/// `Debug` 手寫去敏（V7）：`Set` 值與 `AppendField` 欄值遮罩（path 可為 password/totp/notes），
/// 結構欄（index/kind/path/uri）非機密原樣留。
#[derive(Clone, Serialize, Deserialize)]
pub enum FieldEdit {
    /// leaf 值編輯（path 文法見模組文件）
    Set {
        path: String,
        /// None ＝清空
        value: Option<String>,
    },
    /// 改自訂欄型別（按 index 定位）。官方語意：type 改動连带整欄重加密，
    /// 所以欄位級合併把「同欄 type 改 × 同欄 name/value 改」判**同欄衝突**
    /// 進收件匣（principle：別靜默覆蓋），bw-vault::three_way 實現判定。
    SetType { index: u32, kind: CipherFieldKind },
    /// 附加自訂欄（落 `fields[]` 尾；name 必填）。
    AppendField { field: CipherField },
    /// 移除自訂欄（按 index；越界回錯）。
    RemoveField { index: u32 },
    /// 附加網址列（落 `login.uris[]` 尾；官方形態 `{uri:<信封>, match:null}`）。
    /// 陣列形態變更＝全 PUT 路徑（查證 2026-11-10：VW partial 端點只收
    /// folderId/favorite——既有 quirk；bw-sync `uri.<n>` 文法僅 leaf 值編輯，
    /// 增刪不在該路徑）。欄位級合併把增刪視為 `uri.<n>` 同族索引位移：
    /// 雙端各自改同索引列＝衝突收件匣（比照 field type×值紀律，不靜默）。
    AppendUri { uri: String },
    /// 移除網址列（按 index；越界回錯）。
    RemoveUri { index: u32 },
    /// 改網址列的 match 判定（官方 `login.uris[].match`：null=預設、
    /// 0=網域、1=網域＋子域、2=開頭符合、3=精確、4=正規表達式、5=永不）。
    /// `None`＝回落預設（null）。值為明文整數不落信封（協定欄位形態）；
    /// 按基準索引定位（同 `uri.<n>` Set 紀律：先值批後結構批，AppendUri
    /// 新增列的 match 由呼叫端在結構批落地後補一發）。
    /// 置尾紀律同 AppendUri：陣列欄位級寫入走全 PUT（VW partial 只收
    /// folderId/favorite，查證 2026-11-10）。
    SetUriMatch {
        index: u32,
        #[serde(rename = "match")]
        match_type: Option<u8>,
    },
}

impl core::fmt::Debug for FieldEdit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Set { path, value } => f
                .debug_struct("FieldEdit::Set")
                .field("path", path)
                .field("value", &Masked(value))
                .finish(),
            Self::SetType { index, kind } => f
                .debug_struct("FieldEdit::SetType")
                .field("index", index)
                .field("kind", kind)
                .finish(),
            Self::AppendField { field } => f
                .debug_struct("FieldEdit::AppendField")
                .field("name", &field.name)
                .field("kind", &field.kind)
                .field("value", &Masked(&field.value))
                .finish(),
            Self::RemoveField { index } => f
                .debug_struct("FieldEdit::RemoveField")
                .field("index", index)
                .finish(),
            Self::AppendUri { uri } => f
                .debug_struct("FieldEdit::AppendUri")
                .field("uri", uri)
                .finish(),
            Self::RemoveUri { index } => f
                .debug_struct("FieldEdit::RemoveUri")
                .field("index", index)
                .finish(),
            Self::SetUriMatch { index, match_type } => f
                .debug_struct("FieldEdit::SetUriMatch")
                .field("index", index)
                .field("match_type", match_type)
                .finish(),
        }
    }
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
    Request {
        uri: String,
    },
    Claim {
        plan_id: u64,
    },
    /// 按鍵注入。`template` None → daemon 預設模板；回應只含計數，明文不回傳。
    AutoType {
        id: ItemId,
        template: Option<String>,
    },
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
    /// 拒絕一個待批請求：請求端立刻收到 Denied（不等 120s 逾時）。
    /// 置尾：postcard 變體索引追加，不動既有呼叫的編碼。
    Deny {
        id: ApprovalId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminCall {
    ServerProfile,
    Diagnostics,
    Version,
    /// 本機設定讀寫（macOS 設定面）：置尾紀律同 Passkey（postcard 變體索引只追加）。
    /// 僅本機 Interactive session 受理——設定是這台裝置的偏好，跨機裝置不該改到別人。
    GetSettings,
    SetSettings(Settings),
}

// 線型枚舉：變體尺寸差是協議形態本質（大載體變體 vs 空變體）；
// 裝箱＝每幀多一次分配＋全庫 match 改寫，得不償失。lint 明拒。
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello {
        version: ProtoVersion,
        auth: Auth,
        wants: Vec<EventTopic>,
        /// 連線級訊息體編碼偏好（`bw_proto::wire`；順序＝偏好序）。
        /// `serde(default)`：舊客戶端不帶此欄＝空清單，daemon 據此選定 JSON。
        #[serde(default)]
        formats: Vec<crate::wire::WireFormat>,
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
    /// 鏡像 `ItemView` 體積大（meta＋詳情欄）：boxing 收斂 enum 變體尺寸差
    /// （clippy::large_enum_variant）；serde/postcard 對 Box 透明，線格式不變。
    Item(Option<Box<ItemView>>),
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
    /// 配對碼資訊（跨機 join 前的人類面）
    PairInfo(PairInfo),
    /// 去重報告：同 (domain, username) 叢集，只回 id 不回明文
    DupGroups(Vec<DupGroup>),
    /// 自構 JSON 結果（如 AutoType 計數）。值限字串/整數，無 f64——postcard-safe，見 Audit。
    Json(serde_json::Value),
    Ok,
    // —— passkey（macOS autofill 契約 §1；置尾保 postcard 變體索引）——
    Passkeys(Vec<PasskeyEntry>),
    PasskeyAttestation {
        credential_id: String,
        attestation_object: String,
    },
    PasskeyAssertion {
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    /// BeginAssert 回應：authData 已含新 counter，Swift 簽 `authData‖client_data_hash`
    /// 後以 FinishAssert 交回（事務語意見 PasskeyCall::BeginAssert 註解）。
    AssertBegin {
        credential_id: String,
        rp_id: String,
        /// b64url(authenticatorData)，flags=UP|UV|BE|BS、counter=本次新值
        authenticator_data: String,
        /// 回顯待簽名的 hash（b64url，同 BeginAssert 輸入）：Swift 直接
        /// 拼 `authenticator_data ‖ 此欄位解碼位元組` 作簽名輸入。
        client_data_hash: String,
        /// 固定提示：簽名輸入 = authenticator_data 原始位元組 ‖ client_data_hash 原始位元組，
        /// 演算法 ES256（ECDSA-P256-SHA256），出棧 DER。
        signing_input_note: String,
        counter: u32,
    },
    /// BeginRegister 回應：簽發的 credential id（b64url 32B）。
    /// 同時是 Swift 側 SecKey 的 tag；FinishRegister 以它交回公鑰。
    RegisterBegin {
        credential_id: String,
    },
    /// 附件下載的回傳位元組（批次 4a；解密後的明文內容，
    /// 本機線安全紀律同 Upload bytes；JSON 線形態為 base64 字串）。
    AttachmentBytes(#[serde(with = "bytes_b64")] Vec<u8>),
    /// 登入第一步被伺服器擋下：需要第二因子（2FA 回合）。置尾紀律同 Passkey：
    /// postcard 變體索引只追加。呼叫端據 providers 收碼後重發
    /// `AuthCall::Login{password, two_factor: Some(..)}`。
    TwoFactorRequest {
        providers: Vec<TwoFactorProviderInfo>,
    },
    /// `Admin:GetSettings` 回包（本機設定；置尾紀律同上）。
    Settings(Settings),
    /// `TwoFactor:List` 回包（已啟用因子清單；置尾紀律同 Passkey）。
    TwoFactorStates(Vec<TwoFactorProviderState>),
    /// `TwoFactor:GetAuthenticator` 回包：TOTP secret（base32，伺服器 `key` 欄）
    /// 與 client 側組好的 `otpauth://` URI（伺服器只給 key，不給 URI）。
    /// `secret` 是可入鏡像的秘密——只在本機線與設定頁出現，
    /// 語意同 `Use:TotpCode` 的回碼紀律。
    TwoFactorTotp {
        secret: String,
        key_uri: Option<String>,
    },
    /// `TwoFactor:GetRecoveryCode` 回包：None＝伺服器尚未發碼
    /// （启用任一因子後才有）。
    TwoFactorRecoveryCode(Option<String>),
    /// `EmergencyAccess:ListGrantees/ListGrantors` 回包（PR4；兩側清單同形態，
    /// `EaContact::role` 區分視角；置尾紀律同 Passkey）。
    EaContacts(Vec<EaContact>),
    /// `EmergencyAccess:View` 回包（PR4 C2）：grantor 項目的唯讀投影
    /// （Reveal 級欄位齊全；水印與只讀語意在 GUI 面）。
    EaView(Vec<ItemView>),
}

/// 伺服器宣告的可用第二因子（daemon 由 `bw-server` 挑戰映射而來的輕量形態）。
/// `provider` 編號對齊 upstream `TwoFactorProviderType`（0=Authenticator、
/// 1=Email、2=Duo、3=YubiKey、4=U2f、5=Remember、6=OrgDuo、7=WebAuthn、
/// 8=RecoveryCode）；`hint` 為顯示提示（Email 給伺服器回的水漬地址、
/// Authenticator 為 None），不含秘密值。
/// `details`（PR3 置尾欄）是該因子交涉所需的伺服器材料，daemon 已在邊界解析成
/// 型別形態（[`TwoFactorDetails`]）——不在線上帶 `serde_json::Value`：postcard 解
/// `Value` 是 `WontImplement`（既有 `Response::Json` 債即此，PR5 處理）。
/// 舊幀缺欄＝None（語意＝呼叫端只能走純欄位因子）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorProviderInfo {
    pub provider: i32,
    pub hint: Option<String>,
    /// 因子交涉所需的伺服器材料（見結構體文件；置尾＋default）。
    #[serde(default)]
    pub details: Option<TwoFactorDetails>,
}

/// 因子交涉材料（`TwoFactorProviders2` 中本產品用得著的欄位；其餘原樣丟棄）。
/// 內容非機密：challenge／水漬／Duo 簽章請求都是給**該次登入者**的公開挑戰值。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TwoFactorDetails {
    /// Duo 傳統 iframe 態：Duo API 主機＋簽章請求（`sig_request`）。
    /// 客戶面以 webview 承 Duo 頁，回捕 `AUTH…:APP…` 雙段 token。
    DuoIframe { host: String, signature: String },
    /// Duo redirect（OIDC/frameless）態：完整的 Duo 授權 URL。
    DuoRedirect { auth_url: String },
    /// WebAuthn：challenge（b64url）、可接受憑證 id 清單（b64url）、rpId。
    /// 客戶面的原生安全金鑰島據此出 assertion JSON token。
    Webauthn {
        challenge: String,
        credential_ids: Vec<String>,
        rp_id: Option<String>,
    },
    /// YubiKey：伺服器說這把鑰可能是 NFC 形態（GUI 提示「觸碰金鑰」用）。
    Yubikey { nfc: bool },
}

/// 因子要什麼樣的輸入（一表全收：校驗、提示、以及谁能產出它）。
/// 決定 daemon 是否受理該因子的 `twoFactorToken`，也決定客戶面要用哪套控件：
/// 純欄位（Otp／YubikeyOtp／Recovery）任何面都能收；
/// DuoHandoff／WebauthnAssertion 需要承載网页或原生憑證島的客戶面。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorMode {
    /// 6 位數字（TOTP 與 Email 代碼同形）
    Otp,
    /// 44 字元 YubiKey OTP（tap 出，modhex 字元集）
    YubikeyOtp,
    /// 備用救援碼（Vaultwarden 32 字元 base32、官方雲 30；比對前小寫化）
    Recovery,
    /// Duo 交接結果 `AUTH|…:APP|…`（webview 捕 iframe、或瀏覽器回捕）
    DuoHandoff,
    /// WebAuthn assertion JSON（原生安全金鑰島產出）
    WebauthnAssertion,
}

impl FactorMode {
    /// 是否需要純欄位以外的客戶面能力（webview／原生憑證島）。
    pub fn needs_island(self) -> bool {
        matches!(self, Self::DuoHandoff | Self::WebauthnAssertion)
    }

    /// 收碼欄佔位提示（CLI/GUI 共用）。
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Otp => "6 位數字",
            Self::YubikeyOtp => "觸碰金鑰後貼上 44 字元 OTP",
            Self::Recovery => "28–32 字元救援碼（用後 2FA 全清）",
            Self::DuoHandoff => "由 Duo 頁面取得（AUTH…:APP…）",
            Self::WebauthnAssertion => "由安全金鑰取得簽章",
        }
    }
}

impl TwoFactorProviderInfo {
    /// 因子輸入形態（查表）；None＝本產品不受理（4=U2f 已淘汰、
    /// 5=Remember 由伺服器自動處理、6=OrgDuo Vaultwarden 登入鏈未實裝、
    /// 其餘未知編號）。
    pub fn factor_mode(provider: i32) -> Option<FactorMode> {
        match provider {
            0 | 1 => Some(FactorMode::Otp),
            2 => Some(FactorMode::DuoHandoff),
            3 => Some(FactorMode::YubikeyOtp),
            7 => Some(FactorMode::WebauthnAssertion),
            8 => Some(FactorMode::Recovery),
            _ => None,
        }
    }

    /// daemon 受理的因子（能校驗並重送 `twoFactorToken`）。
    /// 未受理者（見 [`Self::factor_mode`]）由 daemon 給可懂錯誤。
    pub fn is_supported(provider: i32) -> bool {
        Self::factor_mode(provider).is_some()
    }

    /// 本客戶面能否產出該因子需要的輸入：純欄位任何面都可；
    /// 憑證島面（webview／原生安全金鑰）只有 GUI 有，CLI 傳 false。
    pub fn usable_on(provider: i32, has_island: bool) -> bool {
        match Self::factor_mode(provider) {
            None => false,
            Some(mode) => !mode.needs_island() || has_island,
        }
    }

    /// 因子繁中顯示名（CLI/GUI 共用，未知編號顯示原值不亂併名）。
    pub fn label(provider: i32) -> &'static str {
        match provider {
            0 => "手機驗證器（Authenticator）",
            1 => "Email",
            2 => "Duo",
            3 => "YubiKey",
            4 => "安全金鑰（U2f）",
            5 => "記住此裝置（Remember）",
            6 => "組織 Duo",
            7 => "WebAuthn",
            8 => "備用救援碼",
            _ => "未知因子",
        }
    }

    /// 收碼格式閘（純函數，單測點）：trim 後依因子形態校驗，回可送伺服器的正規形態。
    /// 救援碼小寫化（Vaultwarden 以 `totp_recover.to_lowercase()` 比對，
    /// 實錄 `src/db/models/user.rs:169-175`，大寫原樣送必敗），
    /// 容許貼上時夾帶的空格與連字號。最終裁判仍是伺服器。
    pub fn validate_token(provider: i32, raw: &str) -> Result<String, String> {
        let s = raw.trim();
        match Self::factor_mode(provider) {
            None => Err(format!("不支援的因子編號 {provider}")),
            Some(FactorMode::Otp) => {
                if s.len() != 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("驗證碼需為 6 位數字".into());
                }
                Ok(s.to_owned())
            }
            Some(FactorMode::YubikeyOtp) => {
                // Vaultwarden `validate_yubikey_login`：長度必須恰 44，前 12 字元為金鑰 id。
                if s.len() != 44 || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err("YubiKey OTP 需為 44 字元（請重新觸碰金鑰取得）".into());
                }
                Ok(s.to_owned())
            }
            Some(FactorMode::Recovery) => {
                let compact: String = s
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != '-')
                    .collect();
                if !(24..=40).contains(&compact.len())
                    || !compact.bytes().all(|b| b.is_ascii_alphanumeric())
                {
                    return Err("救援碼需為 24–40 字元英數（不含空格與連字號）".into());
                }
                Ok(compact.to_lowercase())
            }
            Some(FactorMode::DuoHandoff) => {
                // 兩態可判別（源檔對照）：iframe 態 `AUTH|…:APP|…`——伺服器以 ':'
                // 切恰兩段（Vaultwarden `duo.rs:284-300`），故首段必以 `AUTH|` 起頭
                // 且恰含一個 ':'；redirect（OIDC）態 `<code>|<state>`——伺服器以 '|'
                // 切恰兩段（`duo_oidc.rs:417-436`），其中不得含 ':'（否則兩態不可分）。
                let ok = (s.starts_with("AUTH|")
                    && s.split(':').collect::<Vec<_>>().len() == 2
                    && s.contains(":APP|"))
                    || (s.matches(':').next().is_none()
                        && s.split('|').all(|p| !p.is_empty())
                        && s.matches('|').count() == 1);
                if !ok {
                    return Err("Duo 結果形態不對（iframe 應為 AUTH…:APP…、\
                                瀏覽器回捕應為 code|state 兩段）"
                        .into());
                }
                Ok(s.to_owned())
            }
            Some(FactorMode::WebauthnAssertion) => {
                let v: serde_json::Value = serde_json::from_str(s)
                    .map_err(|_| "安全金鑰簽章形態不對（非 JSON）".to_owned())?;
                let resp = v
                    .get("response")
                    .and_then(|r| r.as_object())
                    .ok_or_else(|| "安全金鑰簽章缺 response 欄".to_owned())?;
                let has = |k1: &str, k2: &str| resp.contains_key(k1) || resp.contains_key(k2);
                if v.get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .is_empty()
                    || !has("authenticatorData", "authenticator_data")
                    || !has("clientDataJson", "clientDataJSON")
                    || !resp.contains_key("signature")
                {
                    return Err("安全金鑰簽章欄位不全".into());
                }
                Ok(s.to_owned())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DupGroup {
    pub domain: String,
    pub ids: Vec<ItemId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairInfo {
    pub code: String,
    /// SPKI pin；無 CA 體系的信任錨點（§1.2）
    pub pin: String,
    pub expires_in_secs: u64,
}

// —— 資料管理群回包形態（PR5 型別化子批 D1）——
// 這些原本走 `Response::Json`（daemon 手搭 `json!`、thin 端 runtime parser 讀鍵名）。
// 欄位名與鍵序照**既有 JSON 形態**逐字釘選（見 `datamanage_typed_shapes_are_json_compatible`
// 測），切換批只換變體不改Shape，e2e 與 GUI parser 才不會同時動兩處。

/// 弱密碼報告的一列（鏡像解密打分結果；明文不外洩，只 id/name/score）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WeakPasswordEntry {
    pub id: ItemId,
    /// 明文名稱（鎖定態解不開＝None，語意同 `ItemMeta::name`）。
    pub name: Option<String>,
    /// `bw_crypto::password_score` 分級（0–4）。
    pub score: u8,
}

/// `Reports:WeakPasswords` 回包。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WeakPasswordReport {
    pub threshold: u8,
    pub items: Vec<WeakPasswordEntry>,
}

/// 項目歷史的一版（名稱按該版本自帶 key 信封解密；解不開＝空字串，呼叫端顯佔位）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CipherHistoryVersion {
    pub id: String,
    /// 伺服器 ISO-8601 原樣（字串序即時間序）。
    #[serde(rename = "creationDate")]
    pub creation_date: String,
    pub name: String,
    #[serde(rename = "uriCount")]
    pub uri_count: usize,
}

/// `Reports:CipherHistory` 回包。`supported`＝伺服器有實裝歷史路由；
/// `restore_supported`＝有「從歷史還原」端點（查證：無，見 daemon 端註解）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CipherHistoryReport {
    pub supported: bool,
    #[serde(rename = "restoreSupported")]
    pub restore_supported: bool,
    pub versions: Vec<CipherHistoryVersion>,
}

/// 資料夾列（清單與新建回包同形態）。
/// `name` 是信封字串的明文：鎖定態解不開＝None（不猜，呼叫端決定隱藏節點）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FolderInfo {
    pub id: String,
    pub name: Option<String>,
}

/// 硬刪回包：鏡像摘除的列數（含關聯／outbox／overlay）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PurgeReport {
    pub id: ItemId,
    pub mirror_rows: u64,
}

/// 批次匯入回包：收下的筆數與本地 id（推送收斂屬 outbox，不在這裡結算）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImportReport {
    pub imported: usize,
    pub ids: Vec<ItemId>,
}

/// 推播 token 列（`token` 已是去敏形態：前 8 碼＋hash，見 `mask_push_token`）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushTokenInfo {
    pub token: String,
    pub platform: String,
}

/// AutoType 計數：明文只進按鍵事件、不回傳，這裡只有統計（§2.1 出口紀律）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AutoTypeStats {
    pub typed: usize,
    pub fields: usize,
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
    /// 已落庫的 organization 數（P4b 讀側；含邀請中/已接受全部狀態）。
    /// `default`：舊 daemon（P4b 前建置）不帶此欄位，thin 端寬容解析（§2.6 R3）。
    #[serde(default)]
    pub orgs: u32,
    /// 帳號顯示欄（批次 8：側欄帳號列 email、登入卡預填 server）。
    /// 置尾＋`default`：舊 daemon 回包缺欄＝None（JSON 寬容）；未登入兩者皆 None。
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    /// 批次 14b：生物辨識可用性（keystore 為 Keychain 且本機 ACL 可成立）。
    /// GUI 據此顯示「使用 Touch ID 解鎖」鈕；舊 daemon 缺欄＝false。
    #[serde(default)]
    pub biometric_available: bool,
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

/// `Settings::auto_lock_minutes` 的「立即」哨兵（閒置閾值 0：任何一拍心跳即鎖）。
/// 官方層級值域 1/5/15/30/60/240，0 另為「從不」，故取 u8 上端不重疊值。
pub const AUTO_LOCK_IMMEDIATE: u8 = 255;

/// 本機設定（macOS 設定面補齊：自動鎖定／剪貼簿清除／重啟鎖定／鎖定清搜尋）。
/// 存 daemon meta 表 JSON 行（本地權威，不同官方落伺服器 policy）。
/// 預設＝官方寫死值（查證 2026-11-10：vault timeout 預設 15 分鐘、
/// clear clipboard 預設 20 秒、desktop「Lock with master password on restart」
/// 預設開、鎖定清搜尋列預設開）。`serde(default)`：舊庫缺欄逐欄補預設。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 自動鎖定（分鐘）：0=從不、`AUTO_LOCK_IMMEDIATE`=立即、其餘＝閒置分鐘數。
    pub auto_lock_minutes: u8,
    /// 剪貼簿清除（秒）：0=從不；官方層級 10/20/40/60。執行在 GUI。
    pub clipboard_clear_secs: u8,
    /// 重新啟動後鎖定：true＝daemon 重啟一律從鎖態起（官方預設，使用者手動解鎖）；
    /// false＝daemon 啟動即以封存裝置金鑰自動解鎖（重啟不鎖）。
    pub lock_on_sleep_restart: bool,
    /// 鎖定時清除最近搜尋：true＝GUI 見鎖態轉換即清搜尋字串。
    pub clear_search_on_lock: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            clipboard_clear_secs: 20,
            lock_on_sleep_restart: true,
            clear_search_on_lock: true,
        }
    }
}

impl Settings {
    /// 自動鎖定 → 狀態機閒置政策（None＝從不；立即＝零寬閾值）。
    #[must_use]
    pub fn idle_timeout(&self) -> Option<std::time::Duration> {
        match self.auto_lock_minutes {
            0 => None,
            AUTO_LOCK_IMMEDIATE => Some(std::time::Duration::ZERO),
            m => Some(std::time::Duration::from_secs(u64::from(m) * 60)),
        }
    }
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
        /// daemon 選定的訊息體編碼（`bw_proto::wire`，取自 `Hello::formats` 偏好序）。
        /// 本幀本身仍走 JSON：协商結果自 Welcome 之後的幀生效，兩側据此切換。
        /// `serde(default)`＝JSON：舊 daemon 不帶此欄的語意（它只可能說 JSON）。
        #[serde(default)]
        format: crate::wire::WireFormat,
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
    /// 握手層拒絕（Hello 前無 rid 可用）：原因必須上車而非靜默 close，
    /// 否則 thin 端把「撤銷」誤歸因「daemon 重啟」（readpath A6 教訓）。
    /// 附加在 enum 尾端，postcard variant 索引紀律同 §2.6。
    Error {
        message: String,
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
    /// 批次 14：身分驗證失敗（錯主密碼／生物辨識拒絕／未封存）——語意上不同
    /// 於「授權不足」（Denied 是權限缺口，這是憑證不對），顯示不帶誤導前綴。
    /// 置尾紀律：postcard 變體索引追加，不動既有錯誤形態。
    #[error("{reason}")]
    AuthFailed { reason: String },
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

    // —— V7：明文承載型別的 Debug 必須去敏（防 `tracing::debug!(?draft)` 誤用）——

    #[test]
    fn cipher_draft_debug_masks_secret_fields() {
        let draft = CipherDraft {
            kind: ItemKind::Login,
            name: "GitHub".into(),
            username: Some("octo-SENTINEL".into()),
            password: Some("pw-SENTINEL".into()),
            totp: Some("totp-SENTINEL".into()),
            uris: vec!["github.com".into()],
            notes: Some("note-SENTINEL".into()),
            favorite: true,
            fields: vec![CipherField {
                name: "PIN".into(),
                value: Some("pin-SENTINEL".into()),
                kind: CipherFieldKind::Hidden,
            }],
            card: Some(CardDraft {
                number: Some("4111-SENTINEL".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let s = format!("{draft:?}");
        for leak in [
            "octo-SENTINEL",
            "pw-SENTINEL",
            "totp-SENTINEL",
            "note-SENTINEL",
            "pin-SENTINEL",
            "4111-SENTINEL",
        ] {
            assert!(!s.contains(leak), "明文不得進 Debug：{leak} 洩在 {s}");
        }
        // 非機密欄仍可辨識（供除錯與核准摘要白名單）
        assert!(
            s.contains("GitHub") && s.contains("github.com") && s.contains("PIN"),
            "{s}"
        );
    }

    #[test]
    fn import_item_and_field_edit_debug_mask_values() {
        let item = ImportItem {
            draft: CipherDraft {
                password: Some("imp-SENTINEL".into()),
                ..Default::default()
            },
            tags: vec!["finance".into()],
        };
        let si = format!("{item:?}");
        assert!(!si.contains("imp-SENTINEL"), "{si}");
        assert!(si.contains("finance"), "tags 非機密應保留：{si}");

        let edit = FieldEdit::Set {
            path: "password".into(),
            value: Some("ed-SENTINEL".into()),
        };
        let se = format!("{edit:?}");
        assert!(se.contains("password"), "path 應保留：{se}");
        assert!(!se.contains("ed-SENTINEL"), "值不得進 Debug：{se}");

        let append = FieldEdit::AppendField {
            field: CipherField {
                name: "API Key".into(),
                value: Some("ak-SENTINEL".into()),
                kind: CipherFieldKind::Hidden,
            },
        };
        let sa = format!("{append:?}");
        assert!(sa.contains("API Key"), "{sa}");
        assert!(!sa.contains("ak-SENTINEL"), "{sa}");
    }

    fn meta() -> ItemMeta {
        ItemMeta {
            id: ItemId::new_v4(),
            kind: ItemKind::Login,
            name: Some("github".into()),
            uris: vec!["https://github.com".into()],
            folder_id: None,
            organization_id: None,
            collections: vec![],
            favorite: false,
            tags: vec!["dev".into()],
            updated_at: None,
            pending: false,
            deleted_at: None,
            archived_at: None,
            uri_matches: vec![],
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

    /// 本機設定：空 JSON＝官方預設逐欄補齊；新變體（Admin/Response）postcard 往返。
    #[test]
    fn settings_defaults_and_roundtrip() {
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, Settings::default());
        assert_eq!(s.auto_lock_minutes, 15);
        assert_eq!(s.clipboard_clear_secs, 20);
        assert!(s.lock_on_sleep_restart && s.clear_search_on_lock);
        let partial: Settings = serde_json::from_str(r#"{"auto_lock_minutes":0}"#).unwrap();
        assert_eq!(partial.clipboard_clear_secs, 20);
        for call in [
            Call::Admin(AdminCall::GetSettings),
            Call::Admin(AdminCall::SetSettings(Settings {
                auto_lock_minutes: AUTO_LOCK_IMMEDIATE,
                clipboard_clear_secs: 0,
                lock_on_sleep_restart: false,
                clear_search_on_lock: false,
            })),
        ] {
            let bytes = postcard::to_allocvec(&call).unwrap();
            let back: Call = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                serde_json::to_string(&call).unwrap()
            );
        }
        let resp = Response::Settings(Settings::default());
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let back: Response = postcard::from_bytes(&bytes).unwrap();
        assert!(matches!(back, Response::Settings(s) if s == Settings::default()));
        // 批次 2/3 新變體：postcard 往返＋JSON 欄名（match 為關鍵字、線名不轉義）
        let edit = Call::Vault(VaultCall::Patch {
            id: Uuid::new_v4(),
            edits: vec![FieldEdit::SetUriMatch {
                index: 2,
                match_type: Some(3),
            }],
        });
        let bytes = postcard::to_allocvec(&edit).unwrap();
        let back: Call = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            serde_json::to_string(&edit).unwrap()
        );
        assert!(
            serde_json::to_string(&edit)
                .unwrap()
                .contains("\"match\":3")
        );
        let del = Call::Passkey(PasskeyCall::DeletePasskey {
            item_id: Uuid::new_v4(),
            credential_id: "cred".into(),
        });
        let bytes = postcard::to_allocvec(&del).unwrap();
        assert!(matches!(
            postcard::from_bytes::<Call>(&bytes).unwrap(),
            Call::Passkey(PasskeyCall::DeletePasskey { .. })
        ));
    }

    #[test]
    fn btp_roundtrip_postcard_and_json() {
        let msg = ClientMsg::Invoke {
            rid: 7,
            call: Call::Vault(VaultCall::List {
                query: Query {
                    text: Some("git".into()),
                    collection: Some(Uuid::new_v4()),
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

    /// 批次 14a：Unlock 加 password 欄 must `default`——舊幀（無此欄）解析為 None。
    #[test]
    fn unlock_frame_tolerates_legacy_without_password() {
        let legacy = serde_json::json!({"Unlock": {"biometric": false}});
        let call: AuthCall = serde_json::from_value(legacy).unwrap();
        assert!(matches!(
            call,
            AuthCall::Unlock {
                biometric: false,
                password: None
            }
        ));
        let full = AuthCall::Unlock {
            biometric: true,
            password: Some("pw".into()),
        };
        let j = serde_json::to_string(&full).unwrap();
        let back: AuthCall = serde_json::from_str(&j).unwrap();
        assert!(
            matches!(back, AuthCall::Unlock { biometric: true, password: Some(p) } if p == "pw")
        );
    }

    /// 批次 8 紀律：StatusInfo 尾附 email/server 兩欄 must `default`——
    /// 舊 daemon 的 JSON 幀（無此欄）要能解析成 None，不得互炸。
    #[test]
    fn statusinfo_tolerates_legacy_frames_without_account_fields() {
        let legacy = serde_json::json!({
            "state": {"Unlocked": {"epoch": 3, "deadline_epoch_ms": null}},
            "epoch": 3, "items": 9,
            "outbox": {"queued": 0, "in_flight": 0, "awaiting": 0, "conflict": 0, "dead": 0, "total": 0},
            "needs_reauth": false, "proto": 1, "orgs": 0,
        });
        let info: StatusInfo = serde_json::from_value(legacy).unwrap();
        assert_eq!(info.email, None);
        assert_eq!(info.server, None);
        assert!(!info.biometric_available, "舊幀缺欄＝false");
        let full = StatusInfo {
            state: UnlockStateView::SignedOut,
            epoch: 0,
            items: 0,
            outbox: OutboxCounts::default(),
            needs_reauth: true,
            proto: 1,
            orgs: 0,
            email: Some("a@b.test".into()),
            server: Some("http://127.0.0.1:1".into()),
            biometric_available: true,
        };
        let bytes = postcard::to_allocvec(&full).unwrap();
        let back: StatusInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.email.as_deref(), Some("a@b.test"));
        assert_eq!(back.server.as_deref(), Some("http://127.0.0.1:1"));
        let j = serde_json::to_string(&full).unwrap();
        let back: StatusInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back.email, full.email);
    }

    /// PR4 EA 變體：postcard＋JSON 雙線往返（置尾紀律的回歸釘選）。
    #[test]
    fn emergency_access_variants_roundtrip() {
        let contacts = Response::EaContacts(vec![EaContact {
            id: "ea-1".into(),
            user_id: Some("u-2".into()),
            email: "g@bitward.test".into(),
            name: "受托".into(),
            status: EaStatus::Confirmed,
            access_type: EaAccessType::Takeover,
            wait_time_days: 7,
            recovery_initiated_at: None,
            role: EaRole::Grantee,
        }]);
        let bytes = postcard::to_allocvec(&contacts).unwrap();
        let back: Response = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            serde_json::to_string(&contacts).unwrap()
        );
        let j = serde_json::to_string(&contacts).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
        for call in [
            EaCall::ListGrantees,
            EaCall::ListGrantors,
            EaCall::Invite {
                email: "a@b.test".into(),
                access_type: EaAccessType::View,
                wait_time_days: 2,
            },
            EaCall::Confirm { ea_id: "x".into() },
            EaCall::Revoke { ea_id: "x".into() },
            EaCall::Initiate { ea_id: "x".into() },
            EaCall::Approve { ea_id: "x".into() },
            EaCall::Reject { ea_id: "x".into() },
            EaCall::View { ea_id: "x".into() },
            EaCall::Takeover {
                ea_id: "x".into(),
                new_password: "pw".into(),
            },
        ] {
            let wrapped = Call::EmergencyAccess(call);
            let bytes = postcard::to_allocvec(&wrapped).unwrap();
            let back: Call = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                serde_json::to_string(&wrapped).unwrap()
            );
        }
    }

    /// 2FA 批紀律：Login 尾附 `two_factor` must `default`——舊 CLI 幀（無此欄）
    /// 解析＝None（＝第一步語意），不得互炸；postcard/JSON 往返帶欄同檢。
    #[test]
    fn login_tolerates_legacy_frames_without_two_factor() {
        let legacy = serde_json::json!({
            "Login": {
                "server": "http://127.0.0.1:18097",
                "email": "a@b.test",
                "password": "pw",
                "api_key": null,
            }
        });
        let call: AuthCall = serde_json::from_value(legacy).unwrap();
        let AuthCall::Login { two_factor, .. } = &call else {
            panic!("形態不符")
        };
        assert!(two_factor.is_none());
        let with = Call::Auth(AuthCall::Login {
            server: "http://127.0.0.1:18097".into(),
            email: "a@b.test".into(),
            password: Some("pw".into()),
            api_key: None,
            two_factor: Some(TwoFactorInput {
                provider: 0,
                token: "123456".into(),
                remember: true,
            }),
        });
        let bytes = postcard::to_allocvec(&with).unwrap();
        let back: Call = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        let j = serde_json::to_string(&with).unwrap();
        let back: Call = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }

    /// TwoFactorRequest 置尾變體：postcard 索引追加不動舊變體，且往返同檢。
    #[test]
    fn two_factor_request_roundtrips() {
        let resp = Response::TwoFactorRequest {
            providers: vec![
                TwoFactorProviderInfo {
                    provider: 0,
                    hint: None,
                    details: None,
                },
                TwoFactorProviderInfo {
                    provider: 1,
                    hint: Some("a***@b.test".into()),
                    details: None,
                },
                TwoFactorProviderInfo {
                    provider: 2,
                    hint: None,
                    details: Some(TwoFactorDetails::DuoIframe {
                        host: "api-abc123.duosecurity.com".into(),
                        signature: "AUTH|dGVzdA==|sig:APP|dGVzdA==|sig".into(),
                    }),
                },
            ],
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let back: Response = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        let j = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
        assert!(TwoFactorProviderInfo::is_supported(0));
        assert!(TwoFactorProviderInfo::is_supported(1));
        assert_eq!(TwoFactorProviderInfo::label(3), "YubiKey");
        assert_eq!(TwoFactorProviderInfo::label(99), "未知因子");
    }

    /// PR3 紀律：`details` 置尾欄 must `default`——舊 daemon 的 JSON 幀
    /// （只有 provider/hint）要能解析成 None，不得互炸；postcard 新幀往返同檢。
    #[test]
    fn provider_info_tolerates_legacy_frames_without_details() {
        let legacy = serde_json::json!({ "provider": 7, "hint": null });
        let info: TwoFactorProviderInfo = serde_json::from_value(legacy).unwrap();
        assert_eq!(info.details, None);
        let full = TwoFactorProviderInfo {
            provider: 7,
            hint: None,
            details: Some(TwoFactorDetails::Webauthn {
                challenge: "b64url-challenge".into(),
                credential_ids: vec!["credA".into(), "credB".into()],
                rp_id: Some("vault.example.com".into()),
            }),
        };
        let bytes = postcard::to_allocvec(&full).unwrap();
        let back: TwoFactorProviderInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, full);
    }

    /// 因子白名單與收碼形態（一表全收）：YubiKey OTP 44 字元、救援碼小寫化、
    /// Duo 兩段、WebAuthn assertion JSON 欄位；未知編號與已淘汰因子拒。
    #[test]
    fn factor_modes_and_token_gates() {
        use TwoFactorProviderInfo as P;
        assert_eq!(P::factor_mode(0), Some(FactorMode::Otp));
        assert_eq!(P::factor_mode(2), Some(FactorMode::DuoHandoff));
        assert_eq!(P::factor_mode(3), Some(FactorMode::YubikeyOtp));
        assert_eq!(P::factor_mode(7), Some(FactorMode::WebauthnAssertion));
        assert_eq!(P::factor_mode(8), Some(FactorMode::Recovery));
        for legacy in [4, 5, 6, 99] {
            assert_eq!(P::factor_mode(legacy), None, "{legacy} 不該受理");
            assert!(!P::is_supported(legacy));
        }
        for p in [0, 1, 2, 3, 7, 8] {
            assert!(P::is_supported(p), "{p} 應受理");
        }
        // 純欄位因子任何面可用；憑證島因子只有 GUI（has_island=true）可用。
        assert!(P::usable_on(3, false) && P::usable_on(8, false));
        assert!(!P::usable_on(2, false) && !P::usable_on(7, false));
        assert!(P::usable_on(2, true) && P::usable_on(7, true));

        let otp44 = "c".to_owned() + &"b".repeat(43);
        assert_eq!(P::validate_token(3, &otp44).unwrap(), otp44);
        assert_eq!(
            P::validate_token(3, &format!("  {otp44}\n")).unwrap(),
            otp44
        );
        assert!(P::validate_token(3, &"b".repeat(43)).is_err());
        assert!(P::validate_token(3, &format!("{}!", otp44)).is_err());

        let code = "Y3XV 4T6Z-7QBJ-KMNP-2RTW-3XYZ-ABCD";
        assert_eq!(
            P::validate_token(8, code).unwrap(),
            "y3xv4t6z7qbjkmnp2rtw3xyzabcd"
        );
        assert!(P::validate_token(8, "short").is_err());
        assert!(P::validate_token(0, "12345").is_err());
        assert_eq!(P::validate_token(0, " 123456 ").unwrap(), "123456");

        let duo = "AUTH|dGVzdA==|sig1|AUTO|AUTO:APP|dGVzdA==|sig2";
        assert_eq!(P::validate_token(2, duo).unwrap(), duo);
        // redirect（OIDC）態：`<code>|<state>` 兩段
        assert_eq!(
            P::validate_token(2, "dlm3Xk9s|2e1f4a6b").unwrap(),
            "dlm3Xk9s|2e1f4a6b"
        );
        // 無 ':' 的單 '|' 形態按 OIDC `code|state` 受理（`AUTH|only-one-segment`
        // 恰是此形態）；真裁判在伺服器（context 查不到即拒）。
        assert!(P::validate_token(2, "AUTH|only-one-segment").is_ok());
        assert!(P::validate_token(2, "AUTH|a:mid:APP|b").is_err());
        assert!(P::validate_token(2, "random:two:parts").is_err());
        assert!(P::validate_token(2, "code|state|extra").is_err());
        assert!(P::validate_token(2, "AUTH|a:APP|b:junk").is_err());
        assert!(P::validate_token(2, "").is_err());

        let assertion = serde_json::json!({
            "id": "cred",
            "rawId": "cred",
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": "ad",
                "clientDataJson": "cd",
                "signature": "sig"
            }
        })
        .to_string();
        assert_eq!(P::validate_token(7, &assertion).unwrap(), assertion);
        assert!(P::validate_token(7, r#"{"id":"c","response":{}}"#).is_err());
        assert!(P::validate_token(7, "not json").is_err());
        assert!(P::validate_token(4, "123456").is_err());
    }

    /// 管理面置尾變體：postcard 索引追加＋JSON 往返同檢（Call/Response 兩側）。
    #[test]
    fn two_factor_management_frames_roundtrip() {
        let calls = [
            TwoFactorCall::List,
            TwoFactorCall::GetAuthenticator {
                master_password: Some("pw".into()),
            },
            TwoFactorCall::EnableAuthenticator {
                master_password: Some("pw".into()),
                token: "123456".into(),
                key: "SECRET".into(),
            },
            TwoFactorCall::Disable {
                master_password: Some("pw".into()),
                provider: 0,
            },
            TwoFactorCall::GetRecoveryCode {
                master_password: None,
            },
            TwoFactorCall::EmailSendCode {
                master_password: Some("pw".into()),
                email: "a@b.test".into(),
            },
            TwoFactorCall::EmailVerify {
                master_password: Some("pw".into()),
                email: "a@b.test".into(),
                token: "123456".into(),
            },
            TwoFactorCall::EnableYubikey {
                master_password: Some("pw".into()),
                otp: "c".repeat(44),
            },
        ];
        for call in calls {
            let wrapped = Call::TwoFactor(call);
            let bytes = postcard::to_allocvec(&wrapped).unwrap();
            let back: Call = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        }
        for resp in [
            Response::TwoFactorStates(vec![
                TwoFactorProviderState {
                    provider: 0,
                    enabled: true,
                },
                TwoFactorProviderState {
                    provider: 8,
                    enabled: false,
                },
            ]),
            Response::TwoFactorTotp {
                secret: "SECRET".into(),
                key_uri: Some("otpauth://totp/…".into()),
            },
            Response::TwoFactorRecoveryCode(Some("abc123".into())),
            Response::TwoFactorRecoveryCode(None),
        ] {
            let bytes = postcard::to_allocvec(&resp).unwrap();
            let back: Response = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
            let j = serde_json::to_string(&resp).unwrap();
            let back: Response = serde_json::from_str(&j).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), j);
        }
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
    fn passkey_calls_roundtrip_json_and_postcard() {
        let msg = ClientMsg::Invoke {
            rid: 9,
            call: Call::Passkey(PasskeyCall::RegisterPasskey {
                rp_id: "webauthn.test".into(),
                challenge: "A-_b".into(),
                user_name: "u".into(),
                user_handle: "h".into(),
                display_name: "U".into(),
                item_id: None,
                credential_public_key: Some("MIIBvzCCAW".into()),
            }),
        };
        // externally tagged 形態（Swift 端契约）：幀例見 docs 回報
        let j = serde_json::to_vec(&msg).unwrap();
        assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 9);
        assert!(String::from_utf8(j).unwrap().contains("\"Passkey\""));
        let bytes = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&bytes).unwrap().rid(), 9);
        let resp = Response::PasskeyAssertion {
            credential_id: "cid".into(),
            authenticator_data: "ad".into(),
            client_data_json: "cd".into(),
            signature: "sig".into(),
        };
        let r2 = postcard::from_bytes::<Response>(&postcard::to_allocvec(&resp).unwrap()).unwrap();
        assert!(matches!(r2, Response::PasskeyAssertion { .. }));

        for call in [
            PasskeyCall::AssertPasskey {
                credential_id: "cid".into(),
                challenge: "ch".into(),
                rp_id: "webauthn.test".into(),
                client_data_hash: Some("hash".into()),
                signature: Some("der-sig".into()),
                key_id: Some("se-key-1".into()),
            },
            PasskeyCall::BeginAssert {
                credential_id: "cid".into(),
                client_data_hash: "hash".into(),
            },
            PasskeyCall::FinishAssert {
                credential_id: "cid".into(),
                signature: "der-sig".into(),
            },
            PasskeyCall::BeginRegister {
                rp_id: "webauthn.test".into(),
                user_name: "u".into(),
                user_handle: "h".into(),
                display_name: "U".into(),
                item_id: None,
            },
            PasskeyCall::FinishRegister {
                credential_id: "cid".into(),
                credential_public_key: "MIIBvzCCAW".into(),
                rp_id: "webauthn.test".into(),
                challenge: "ch".into(),
                user_name: "u".into(),
                user_handle: "h".into(),
                display_name: "U".into(),
                item_id: None,
            },
        ] {
            let msg = ClientMsg::Invoke {
                rid: 10,
                call: Call::Passkey(call),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 10);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 10);
        }
        let begin = Response::AssertBegin {
            credential_id: "cid".into(),
            rp_id: "webauthn.test".into(),
            authenticator_data: "ad".into(),
            client_data_hash: "hash".into(),
            signing_input_note: "note".into(),
            counter: 42,
        };
        let back =
            postcard::from_bytes::<Response>(&postcard::to_allocvec(&begin).unwrap()).unwrap();
        assert!(matches!(back, Response::AssertBegin { counter: 42, .. }));
        let j = serde_json::to_string(&begin).unwrap();
        assert!(j.contains("\"counter\":42"));
        let rb = Response::RegisterBegin {
            credential_id: "cid".into(),
        };
        let back = postcard::from_bytes::<Response>(&postcard::to_allocvec(&rb).unwrap()).unwrap();
        assert!(matches!(back, Response::RegisterBegin { .. }));
    }

    #[test]
    fn push_calls_roundtrip_json_and_postcard() {
        for call in [
            PushCall::RegisterPush {
                token: "A1B2C3D4E5F6".into(),
                platform: "ios".into(),
            },
            PushCall::UnregisterPush {
                token: "A1B2C3D4E5F6".into(),
            },
            PushCall::ListPush,
        ] {
            let msg = ClientMsg::Invoke {
                rid: 11,
                call: Call::Push(call),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 11);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 11);
        }
        // ListPush 出口形態：Json 重用，值限字串（postcard-safe，見 Audit）。
        // 紀律同 Audit：postcard 只保證編碼可發（Value 反序列化需 self-describing，
        // 見 P1 線格式註解）；JSON 才是可回讀的往返。
        let resp = Response::Json(serde_json::json!([
            {"token": "a1b2c3d4…0123456789ab", "platform": "ios"}
        ]));
        assert!(postcard::to_allocvec(&resp).is_ok());
        let j = serde_json::to_string(&resp).unwrap();
        let back = serde_json::from_str::<Response>(&j).unwrap();
        match back {
            Response::Json(v) => assert_eq!(v.as_array().map(Vec::len), Some(1)),
            other => panic!("expect Json, got {other:?}"),
        }
    }

    #[test]
    fn change_password_call_roundtrip_json_and_postcard() {
        for call in [
            AuthCall::ChangePassword {
                current: Some("舊鐵哥-1234".into()),
                new: Some("新鐵哥-5678".into()),
            },
            // None＝daemon 端向人收（同 Login 語意）：變體必須可過線
            AuthCall::ChangePassword {
                current: None,
                new: None,
            },
        ] {
            let msg = ClientMsg::Invoke {
                rid: 12,
                call: Call::Auth(call),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 12);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 12);
        }
        // 置尾紀律：WhoAmI（舊末位）索引不動，ChangePassword 在其後
        let idx = |c: &AuthCall| postcard::to_allocvec(c).unwrap()[0];
        assert_eq!(
            idx(&AuthCall::WhoAmI),
            idx(&serde_json::from_str::<AuthCall>(r#""WhoAmI""#).unwrap())
        );
        assert!(
            idx(&AuthCall::ChangePassword {
                current: None,
                new: None
            }) > idx(&AuthCall::WhoAmI)
        );
    }

    #[test]
    fn attachment_ops_roundtrip_and_frame_shape() {
        let sub = AttachmentOp::Upload {
            item_id: ItemId::new_v4(),
            file_name: "帳單.pdf".into(),
            bytes: vec![0u8, 1, 2, 255, 128],
        };
        let msg = ClientMsg::Invoke {
            rid: 17,
            call: Call::Vault(VaultCall::Attachment { sub }),
        };
        let j = serde_json::to_value(&msg).unwrap();
        // 線形態：bytes 是 base64 字串（不是數字陣列）
        assert_eq!(
            j["Invoke"]["call"]["Vault"]["Attachment"]["sub"]["Upload"]["bytes"],
            serde_json::json!("AAEC/4A=")
        );
        let back: ClientMsg = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
        assert_eq!(back.rid(), 17);
        let b = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 17);

        let resp = Response::AttachmentBytes(vec![7, 8, 9]);
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("BwgJ"), "{j}");
        let back =
            postcard::from_bytes::<Response>(&postcard::to_allocvec(&resp).unwrap()).unwrap();
        match back {
            Response::AttachmentBytes(v) => assert_eq!(v, vec![7, 8, 9]),
            other => panic!("expect AttachmentBytes, got {other:?}"),
        }

        // 置尾紀律：Attachment 索引在 Import 之後，既有變體不動
        let idx = |c: &VaultCall| postcard::to_allocvec(c).unwrap()[0];
        assert!(
            idx(&VaultCall::Attachment {
                sub: AttachmentOp::Download {
                    item_id: ItemId::new_v4(),
                    attachment_id: "8fd01a914baeef9d1efd".into(),
                }
            }) > idx(&VaultCall::Import {
                items: vec![],
                format: false
            })
        );

        // ItemView.attachments：無附件時鍵缺席（A3 紀律延伸），有則帶元資料
        let mut v = ItemView::metadata(meta());
        v.attachments = vec![AttachmentMeta {
            id: "8fd01a914baeef9d1efd".into(),
            file_name: "a.bin".into(),
            size: Some(11),
            size_name: Some("11.00 bytes".into()),
        }];
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains("\"attachments\""));
        assert_eq!(
            serde_json::from_str::<ItemView>(&j)
                .unwrap()
                .attachments
                .len(),
            1
        );
        let empty = serde_json::to_string(&ItemView::metadata(meta())).unwrap();
        assert!(!empty.contains("\"attachments\""));
    }

    #[test]
    fn set_archived_and_get_icon_roundtrip() {
        let idx = |c: &VaultCall| postcard::to_allocvec(c).unwrap()[0];
        let sa = VaultCall::SetArchived {
            id: ItemId::new_v4(),
            archived: true,
        };
        let gi = VaultCall::GetIcon {
            host: "github.com".into(),
        };
        // 置尾紀律：兩變體索引在 Attachment 之後，既有變體不動
        let attachment = VaultCall::Attachment {
            sub: AttachmentOp::Delete {
                item_id: ItemId::new_v4(),
                attachment_id: "a1".into(),
            },
        };
        assert!(idx(&sa) > idx(&attachment));
        assert!(idx(&gi) > idx(&sa));
        for c in [sa, gi] {
            let msg = ClientMsg::Invoke {
                rid: 18,
                call: Call::Vault(c),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 18);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 18);
        }
    }

    #[test]
    fn error_variants_roundtrip() {
        let e = WtpError::StaleEpoch { seen: 3, now: 5 };
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<WtpError>(&j).unwrap(), e);
    }

    #[test]
    fn send_ops_roundtrip_and_tail_discipline() {
        let idx = |c: &VaultCall| postcard::to_allocvec(c).unwrap()[0];
        // 置尾紀律：Send 索引在 Reports 之後，既有變體不動
        assert!(
            idx(&VaultCall::Send { sub: SendOp::List })
                > idx(&VaultCall::Reports {
                    sub: Reports::PasswordReuse
                })
        );
        let create = SendOp::Create {
            name: None,
            content: SendContent::File {
                file_name: "報表.pdf".into(),
                bytes: vec![0u8, 1, 2, 255, 128],
            },
            password: Some("pw".into()),
            deletion_hours: 168,
            max_access: Some(3),
            hide_email: true,
        };
        let msg = ClientMsg::Invoke {
            rid: 21,
            call: Call::Vault(VaultCall::Send { sub: create }),
        };
        // 線形態：bytes 是 base64 字串（附件同紀律）
        let j = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            j["Invoke"]["call"]["Vault"]["Send"]["sub"]["Create"]["content"]["File"]["bytes"],
            serde_json::json!("AAEC/4A=")
        );
        let back: ClientMsg = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
        assert_eq!(back.rid(), 21);
        let b = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 21);
        for sub in [
            SendOp::Get {
                id: ItemId::new_v4(),
            },
            SendOp::Remove {
                id: ItemId::new_v4(),
            },
            SendOp::Password {
                id: ItemId::new_v4(),
                password: None,
            },
        ] {
            let msg = ClientMsg::Invoke {
                rid: 22,
                call: Call::Vault(VaultCall::Send { sub }),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 22);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 22);
        }
    }

    #[test]
    fn query_and_meta_accept_old_json_without_new_fields() {
        // P4b 前形態的旧形訊息：collection/collections 欄位缺失 → serde default
        let q: Query = serde_json::from_str(r#"{"text":null,"sort":"Name","limit":10}"#).unwrap();
        assert_eq!(q.collection, None);
        assert_eq!(q.folder, None);
        assert_eq!(q.deleted, None);
        assert_eq!(q.archived, None);
        let m: ItemMeta = serde_json::from_str(
            r#"{"id":"0f0d0000-0000-4000-8000-0000000000c1","kind":"Login","name":null,
               "uris":[],"folder_id":null,"organization_id":null,"favorite":false,
               "tags":[],"updated_at":null,"pending":false}"#,
        )
        .unwrap();
        assert!(m.collections.is_empty());
        assert_eq!(m.deleted_at, None);
        assert_eq!(m.archived_at, None);
        // 三件套前形態的草稿：folder/fields 欄位缺失 → serde default
        let d: CipherDraft = serde_json::from_str(
            r#"{"kind":"SecureNote","name":"n","username":null,"password":null,
               "totp":null,"uris":[],"notes":"body","favorite":false}"#,
        )
        .unwrap();
        assert!(d.folder_id.is_none() && d.fields.is_empty());
        // ItemView 舊形：notes/fields 鍵不存在時可解析；Metadata 輸出無 Secret 鍵
        let v: ItemView = serde_json::from_str(
            r#"{"meta":{"id":"0f0d0000-0000-4000-8000-0000000000c1","kind":"Login",
               "name":null,"uris":[],"folder_id":null,"organization_id":null,
               "favorite":false,"tags":[],"updated_at":null,"pending":false},
               "totp_available":false}"#,
        )
        .unwrap();
        assert!(v.notes.is_none() && v.fields.is_empty());
    }

    #[test]
    fn field_edit_enum_and_import_roundtrip() {
        let edits = vec![
            FieldEdit::Set {
                path: "name".into(),
                value: Some("n".into()),
            },
            FieldEdit::Set {
                path: "field.0.value".into(),
                value: None,
            },
            FieldEdit::SetType {
                index: 1,
                kind: CipherFieldKind::Boolean,
            },
            FieldEdit::AppendField {
                field: CipherField {
                    name: "flag".into(),
                    value: Some("true".into()),
                    kind: CipherFieldKind::Boolean,
                },
            },
            FieldEdit::RemoveField { index: 2 },
            FieldEdit::AppendUri {
                uri: "https://new.example".into(),
            },
            FieldEdit::RemoveUri { index: 0 },
        ];
        let msg = ClientMsg::Invoke {
            rid: 15,
            call: Call::Vault(VaultCall::Patch {
                id: ItemId::new_v4(),
                edits: edits.clone(),
            }),
        };
        let j = serde_json::to_vec(&msg).unwrap();
        let back: ClientMsg = serde_json::from_slice(&j).unwrap();
        match back {
            ClientMsg::Invoke {
                call: Call::Vault(VaultCall::Patch { edits, .. }),
                ..
            } => {
                assert!(matches!(edits[2], FieldEdit::SetType { index: 1, .. }));
                assert!(matches!(edits[4], FieldEdit::RemoveField { index: 2 }));
                assert!(matches!(
                    &edits[5],
                    FieldEdit::AppendUri { uri } if uri == "https://new.example"
                ));
                assert!(matches!(edits[6], FieldEdit::RemoveUri { index: 0 }));
            }
            other => panic!("expect Patch, got {other:?}"),
        }
        let b = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 15);

        let imp = VaultCall::Import {
            items: vec![ImportItem {
                draft: CipherDraft {
                    kind: ItemKind::SecureNote,
                    name: " imported".into(),
                    notes: Some("n".into()),
                    ..Default::default()
                },
                tags: vec!["bulk".into()],
            }],
            format: false,
        };
        let msg = ClientMsg::Invoke {
            rid: 16,
            call: Call::Vault(imp.clone()),
        };
        // 置尾紀律：Import 索引必須在 Purge（三件套批次末位）之後
        let idx = |c: &VaultCall| postcard::to_allocvec(c).unwrap()[0];
        assert!(
            idx(&imp)
                > idx(&VaultCall::Purge {
                    id: ItemId::new_v4()
                })
        );
        let j = serde_json::to_vec(&msg).unwrap();
        assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 16);
        let b = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 16);

        // kind 線格式映射（官方 type 整數）
        assert_eq!(CipherFieldKind::Text.wire(), 0);
        assert_eq!(CipherFieldKind::Hidden.wire(), 1);
        assert_eq!(CipherFieldKind::Boolean.wire(), 2);
        assert_eq!(CipherFieldKind::from_wire(7), CipherFieldKind::Text);
    }

    #[test]
    fn folder_calls_and_draft_roundtrip() {
        let folder = Uuid::new_v4();
        for call in [
            VaultCall::CreateFolder {
                name: "工作".into(),
            },
            VaultCall::ListFolders,
            VaultCall::DeleteFolder { id: folder },
            VaultCall::Purge { id: folder },
        ] {
            let msg = ClientMsg::Invoke {
                rid: 13,
                call: Call::Vault(call),
            };
            let j = serde_json::to_vec(&msg).unwrap();
            assert_eq!(serde_json::from_slice::<ClientMsg>(&j).unwrap().rid(), 13);
            let b = postcard::to_allocvec(&msg).unwrap();
            assert_eq!(postcard::from_bytes::<ClientMsg>(&b).unwrap().rid(), 13);
        }
        // 置尾紀律：MoveToOrg（三件套前的末位）索引不動，資料夾變體在其後
        let idx = |c: &VaultCall| postcard::to_allocvec(c).unwrap()[0];
        let move_org = VaultCall::MoveToOrg {
            item: Uuid::new_v4(),
            org: None,
            collections: vec![],
        };
        assert!(
            idx(&VaultCall::ListFolders) > idx(&move_org),
            "資料夾變體必須置尾，不推擠既有索引"
        );

        let draft_in = CipherDraft {
            kind: ItemKind::SecureNote,
            name: "安全筆記".into(),
            notes: Some("內文".into()),
            folder_id: Some(folder.to_string()),
            fields: vec![
                CipherField {
                    name: "PIN".into(),
                    value: Some("1234".into()),
                    kind: CipherFieldKind::Hidden,
                },
                CipherField {
                    name: "會員".into(),
                    value: None,
                    kind: CipherFieldKind::Text,
                },
            ],
            ..Default::default()
        };
        let msg = ClientMsg::Invoke {
            rid: 14,
            call: Call::Vault(VaultCall::Create {
                draft: draft_in.clone(),
            }),
        };
        let b = postcard::to_allocvec(&msg).unwrap();
        match postcard::from_bytes::<ClientMsg>(&b).unwrap().call() {
            Call::Vault(VaultCall::Create { draft }) => assert_eq!(draft, &draft_in),
            other => panic!("expect Create, got {other:?}"),
        }
        let q = Query {
            folder: Some(folder.to_string()),
            ..Default::default()
        };
        let j = serde_json::to_string(&q).unwrap();
        assert_eq!(serde_json::from_str::<Query>(&j).unwrap().folder, q.folder);

        // ItemView 詳情附掛：notes/hidden 值的 skip-if-none 結構保證（A3 同款）
        let v = ItemView::metadata(meta())
            .masked(Some("u".into()), Some("••••12".into()), false)
            .with_details(
                Some("筆記".into()),
                vec![CipherField {
                    name: "PIN".into(),
                    value: None,
                    kind: CipherFieldKind::Hidden,
                }],
                vec![],
            );
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains("\"notes\":\"筆記\""));
        assert!(j.contains("\"kind\":\"hidden\""));
        assert!(!j.contains("\"password\":"));
        assert!(!j.contains("1234"));
        let back: ItemView = serde_json::from_str(&j).unwrap();
        assert_eq!(back.fields[0].name, "PIN");
    }

    /// PR5 D1 形態金標：型別化回包的 JSON 必須與**原手搭 `json!`** 逐字同形
    /// （鍵名、null 欄、數字形態），型別化子批才能只動 daemon 生產點而不动
    /// thin 端（GUI parser、e2e jq 路徑）；D5 換變體時同形性已由本測證明。
    /// 同測驗 postcard **往返含反序列化**（治 encode-only 舊債）。
    #[test]
    fn datamanage_typed_shapes_are_json_compatible() {
        let id = ItemId::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let cases: Vec<(serde_json::Value, serde_json::Value)> = vec![
            (
                serde_json::to_value(WeakPasswordReport {
                    threshold: WEAK_PASSWORD_THRESHOLD,
                    items: vec![WeakPasswordEntry {
                        id,
                        name: Some("gh".into()),
                        score: 0,
                    }],
                })
                .unwrap(),
                serde_json::json!({
                    "threshold": 3,
                    "items": [{"id": "67e55044-10b1-426f-9247-bb680e5fe0c8", "name": "gh", "score": 0}]
                }),
            ),
            (
                serde_json::to_value(CipherHistoryReport {
                    supported: true,
                    restore_supported: false,
                    versions: vec![CipherHistoryVersion {
                        id: "v1".into(),
                        creation_date: "2026-11-10T00:00:00.000Z".into(),
                        name: "gh-a".into(),
                        uri_count: 2,
                    }],
                })
                .unwrap(),
                serde_json::json!({
                    "supported": true,
                    "restoreSupported": false,
                    "versions": [{"id": "v1", "creationDate": "2026-11-10T00:00:00.000Z", "name": "gh-a", "uriCount": 2}]
                }),
            ),
            (
                serde_json::to_value(CipherHistoryReport {
                    supported: false,
                    restore_supported: false,
                    versions: Vec::new(),
                })
                .unwrap(),
                serde_json::json!({"supported": false, "restoreSupported": false, "versions": []}),
            ),
            (
                serde_json::to_value(vec![
                    FolderInfo {
                        id: id.to_string(),
                        name: Some("工作資料夾".into()),
                    },
                    FolderInfo {
                        id: "11111111-2222-3333-4444-555555555555".into(),
                        name: None,
                    },
                ])
                .unwrap(),
                serde_json::json!([
                    {"id": "67e55044-10b1-426f-9247-bb680e5fe0c8", "name": "工作資料夾"},
                    {"id": "11111111-2222-3333-4444-555555555555", "name": null}
                ]),
            ),
            (
                serde_json::to_value(ImportReport {
                    imported: 1,
                    ids: vec![id],
                })
                .unwrap(),
                serde_json::json!({"imported": 1, "ids": ["67e55044-10b1-426f-9247-bb680e5fe0c8"]}),
            ),
            (
                serde_json::to_value(vec![PushTokenInfo {
                    token: "a1b2c3d4…0123456789ab".into(),
                    platform: "ios".into(),
                }])
                .unwrap(),
                serde_json::json!([{"token": "a1b2c3d4…0123456789ab", "platform": "ios"}]),
            ),
            (
                serde_json::to_value(AutoTypeStats {
                    typed: 12,
                    fields: 2,
                })
                .unwrap(),
                serde_json::json!({"typed": 12, "fields": 2}),
            ),
        ];
        for (typed, hand_built) in cases {
            assert_eq!(typed, hand_built, "型別化回包的 JSON 形態漂移");
        }

        let folders = vec![FolderInfo {
            id: id.to_string(),
            name: None,
        }];
        let pushes = vec![PushTokenInfo {
            token: "t".into(),
            platform: "watchos".into(),
        }];
        let weak = WeakPasswordReport {
            threshold: WEAK_PASSWORD_THRESHOLD,
            items: vec![WeakPasswordEntry {
                id,
                name: Some("gh".into()),
                score: 1,
            }],
        };
        let history = CipherHistoryReport {
            supported: true,
            restore_supported: false,
            versions: vec![CipherHistoryVersion {
                id: "v1".into(),
                creation_date: "2026-11-10T00:00:00.000Z".into(),
                name: String::new(),
                uri_count: 0,
            }],
        };
        let purge = PurgeReport { id, mirror_rows: 7 };
        let import = ImportReport {
            imported: 0,
            ids: vec![id],
        };
        let autotype = AutoTypeStats {
            typed: 3,
            fields: 1,
        };
        // `Value` 本身走 postcard 會卡在 `deserialize_any`（本 PR 的債源），
        // 故逐條用**型別**往返回環，不比 `Value`。
        fn roundtrip<T: Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug>(
            v: &T,
        ) {
            let bytes = postcard::to_allocvec(v).unwrap();
            let back: T = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&back, v, "postcard 往返漂移");
            assert_eq!(
                postcard::to_allocvec(&back).unwrap(),
                bytes,
                "反序列化後再編不安定"
            );
        }
        roundtrip(&weak);
        roundtrip(&history);
        roundtrip(&folders);
        roundtrip(&purge);
        roundtrip(&import);
        roundtrip(&pushes);
        roundtrip(&autotype);
    }

    impl ClientMsg {
        fn call(&self) -> &Call {
            match self {
                ClientMsg::Invoke { call, .. } => call,
                _ => panic!("not an invoke"),
            }
        }
    }
}
