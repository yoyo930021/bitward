//! BTP 協議與 vault 模型的共享型別（契約 §2.1、§2.5）。
//! 這是 Full/Thin 兩側唯一的共同語言：依賴方向即安全邊界（§3）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// CLI 邊界的明文草稿；加密只發生在 daemon 的 `with_keys` 閉包。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
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
}

/// 批次匯入的一筆（`VaultCall::Import` 載體）。draft 是**明文欄位結構**：
/// 與 `AuthCall::Login` 的 password 同級紀律——明文只走 UDS/TLS 本機線
/// （A11：不落 argv），加密發生在 daemon `with_keys` 閉包。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportItem {
    #[serde(default)]
    pub draft: CipherDraft,
    /// 本地 overlay 標籤（§2.4：協定無 tags 欄位，匯入時直落 overlay 表）
    #[serde(default)]
    pub tags: Vec<String>,
}

/// 欄位編輯。`Set` 的 path 文法三處共用（bw-vault flatten、bw-sync build_put_body、daemon）：
/// `name`、`notes`、`username`、`password`、`totp`、`uri.<n>`、`favorite`、
/// `folderId`（明文 UUID 字串；None＝移出資料夾）、
/// `field.<n>.name`／`field.<n>.value`（`<n>` 為 0 起 `fields[]` 索引）、
/// `field.<n>.type`（值域 `text|hidden|boolean`，見 `SetType`）。
/// 增刪欄位走 `AppendField`／`RemoveField`（陣列形態變更，非 leaf 值編輯）。
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    SetType {
        index: u32,
        kind: CipherFieldKind,
    },
    /// 附加自訂欄（落 `fields[]` 尾；name 必填）。
    AppendField {
        field: CipherField,
    },
    /// 移除自訂欄（按 index；越界回錯）。
    RemoveField {
        index: u32,
    },
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DupGroup {
    pub domain: String,
    pub ids: Vec<ItemId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairInfo {
    pub code: String,
    /// SPKI pin；無 CA 體系的信任錨點（§1.2）
    pub pin: String,
    pub expires_in_secs: u64,
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
    /// `default`：舊 daemon（P4b 前建置）不帶此欄位，thin 端寬容解析（§2.6 同款紀律）。
    #[serde(default)]
    pub orgs: u32,
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
            collections: vec![],
            favorite: false,
            tags: vec!["dev".into()],
            updated_at: None,
            pending: false,
            deleted_at: None,
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
        assert!(idx(&AuthCall::ChangePassword {
            current: None,
            new: None
        }) > idx(&AuthCall::WhoAmI));
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
        assert_eq!(serde_json::from_str::<ItemView>(&j).unwrap().attachments.len(), 1);
        let empty = serde_json::to_string(&ItemView::metadata(meta())).unwrap();
        assert!(!empty.contains("\"attachments\""));
    }

    #[test]
    fn error_variants_roundtrip() {
        let e = WtpError::StaleEpoch { seen: 3, now: 5 };
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<WtpError>(&j).unwrap(), e);
    }

    #[test]
    fn query_and_meta_accept_old_json_without_new_fields() {
        // P4b 前形態的旧形訊息：collection/collections 欄位缺失 → serde default
        let q: Query = serde_json::from_str(r#"{"text":null,"sort":"Name","limit":10}"#).unwrap();
        assert_eq!(q.collection, None);
        assert_eq!(q.folder, None);
        assert_eq!(q.deleted, None);
        let m: ItemMeta = serde_json::from_str(
            r#"{"id":"0f0d0000-0000-4000-8000-0000000000c1","kind":"Login","name":null,
               "uris":[],"folder_id":null,"organization_id":null,"favorite":false,
               "tags":[],"updated_at":null,"pending":false}"#,
        )
        .unwrap();
        assert!(m.collections.is_empty());
        assert_eq!(m.deleted_at, None);
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
        assert!(idx(&imp) > idx(&VaultCall::Purge { id: ItemId::new_v4() }));
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

    impl ClientMsg {
        fn call(&self) -> &Call {
            match self {
                ClientMsg::Invoke { call, .. } => call,
                _ => panic!("not an invoke"),
            }
        }
    }
}
