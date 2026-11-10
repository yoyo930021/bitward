//! 應用狀態機：所有畫面轉移與 daemon 往返都收斂成一條命令佇列。
//!
//! 形态（契約 §0.2「UI 純介面零業務邏輯」）：
//! - `AppCore` 只持有訊號與一條 `Session`；分級、過濾、排序語意全在 daemon。
//! - UI handler 只做兩件事：直接寫輸入框訊號、`send(Cmd)`。
//! - 引擎執行緒上的 `set_interval` 幫浦每 tick 清空佇列並 `reduce`；
//!   需要 daemon 的動作由 `reduce` 派到 worker 執行緒，worker 只準
//!   回傳 `Cmd`，不碰訊號（訊號非執行緒安全，全在引擎執行緒寫入）。
//! - 導航用 `when` 區塊切頁（spike FINDINGS 卡點 4：nav_stack 在 macOS
//!   dev host 不渲染），Route 是唯一導航真相。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use bw_proto::{
    AdminCall, AgentCall, AttachmentOp, AuthCall, Call, CipherDraft, CipherFieldKind, EventTopic,
    FieldEdit, ItemId, ItemKind, ItemView, OverlayOpWire, PasskeyCall, Query, Response, SortKey,
    SyncCall, UnlockStateView, UseCall, VaultCall, View,
};
use nsh_core::prelude::*;

use crate::btp::Session;
use crate::export::{self, ExportOutcome};
use crate::passgen::GenState;

/// 連線生命週期（錯誤畫面 = Failed，重連 = 再發 Boot）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Connecting,
    Ready,
    Failed,
}

/// 頁面狀態機：取代 nav_stack 的自製路由（契約慣例）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    List,
    Detail(ItemId),
    Create,
    Edit(ItemId),
    /// 批准佇列（右欄視角，側欄「待批准」進入；單鍵直決無二次確認）。
    Approvals,
    /// 本機設定檢視（右欄視角，側欄「設定」進入；macOS 設定面）。
    Settings,
    /// 報告儀表板（右欄視角，側欄「報告」進入；卡面→清單兩層同訊號切換）。
    Reports,
}

/// 報告視角的兩態（儀表板卡面／清單）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReportsTab {
    Cards,
    Reuse,
    Weak,
}

/// 確認對話框（刪除、匯出共用）；`on_confirm` 是確認後要投遞的命令。
pub struct Confirm {
    pub title: String,
    pub description: String,
    pub confirm_label: String,
    pub destructive: bool,
    pub on_confirm: Cmd,
}

/// 編輯表單的比對基準（只存本輪載入的明文帳號，離開表單即丟）。
pub struct FormOriginal {
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    /// `uris` 平行的判定基準（缺欄＝None 預設；diff 出 SetUriMatch）。
    pub uri_matches: Vec<Option<u8>>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    /// 既有自訂欄位基準（編輯模式逐欄 diff；增刪不在此批）。
    pub fields: Vec<FieldDraft>,
}

/// 寫入完成後的落點。
#[derive(Clone, Copy)]
pub enum Follow {
    List,
    Detail(ItemId),
}

/// 側欄視角（官方左欄語意）：資料夾三態與垃圾桶**互斥**。
/// `folder`：None＝全部項目；`Some("")`＝未歸屬；`Some(id)`＝該資料夾。
/// 純狀態機：所有转移由方法承擔（單測），reduce 只調用。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct VaultFilter {
    pub folder: Option<String>,
    pub trash: bool,
    /// 已封存視角（批次 C）：與垃圾桶／資料夾四態互斥。
    pub archived: bool,
}

impl VaultFilter {
    /// 選資料夾（含未歸屬）：自動退出垃圾桶與已封存。`pick_folder(None)`＝回全部項目。
    pub fn pick_folder(&mut self, folder: Option<String>) {
        self.folder = folder;
        self.trash = false;
        self.archived = false;
    }

    /// 垃圾桶切換：進入時退出資料夾與已封存（回「全部項目」）。
    pub fn toggle_trash(&mut self) {
        self.trash = !self.trash;
        if self.trash {
            self.folder = None;
            self.archived = false;
        }
    }

    /// 已封存切換：進入時退出資料夾與垃圾桶（四態互斥，同垃圾桶語意）。
    pub fn toggle_archived(&mut self) {
        self.archived = !self.archived;
        if self.archived {
            self.folder = None;
            self.trash = false;
        }
    }
}

/// 封存三態查詢（批次 C，同 `deleted_filter` 紀律）：已封存視角 Some(true)，
/// 主列表 None（不發 Some(false)，舊 daemon 兼容）。
pub fn archived_filter(archived: bool) -> Option<bool> {
    archived.then_some(true)
}

/// 網站圖示快取態（批次 C）：host → 狀態。缺席＝尚未請求；`Loading` 即單飛
/// 令牌（同 host 併發只發一次 `GetIcon`）。`Ready` 存 data: URI 字串（PNG/ICO
/// 原樣位元組經 magic 嗅探定 MIME，macOS 端 CGImageSource 兩者皆吃）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IconState {
    Loading,
    Ready(String),
    Failed,
}

/// magic 嗅探（純函數，單測點）：PNG(`89 50 4E 47`)／ICO(`00 00 01 00`)
/// 回對應 MIME；其他形態回 None（呼叫端退字母磚，不硬塞未知型別）。
pub fn sniff_icon(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        Some("image/x-icon")
    } else {
        None
    }
}

/// 從 uri 字串取 host（純函數，單測點）：去 scheme、userinfo、port、path；
/// 無點且非 localhost 者視為無效（退回字母磚）。多網址由呼叫端取主 uri。
pub fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = hostport.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
    if host.is_empty() || (!host.contains('.') && host != "localhost") {
        return None;
    }
    Some(host)
}

/// 位元組 → `data:` URI（magic 決定 MIME；解不了的形態回 None＝字母磚）。
pub fn icon_data_uri(bytes: &[u8]) -> Option<String> {
    use base64::Engine;
    let mime = sniff_icon(bytes)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("data:{mime};base64,{b64}"))
}

/// 資料夾鏡像列（ListFolders 投影）：鎖定態 name 為 null → 節點隱藏。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FolderEntry {
    pub id: String,
    pub name: Option<String>,
}

/// 待批准列（`AgentCall::ListPending` → `Response::Sessions` 投影）。
/// `requested_at_ms`：daemon 現行回包尚無此欄（批次 6 查證缺角，已報）；
/// 欄位預留，daemon 補上即自動顯示，不虛構時間。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PendingRow {
    pub id: String,
    pub summary: String,
    pub requested_at_ms: Option<u64>,
}

/// 命令佇列的成員：意圖（UI/捷徑）與結果（worker 回傳）。
#[derive(Clone)]
pub enum Cmd {
    // —— 意圖 ——
    Boot,
    RefetchList,
    ChooseTag(Option<String>),
    ChooseSort(SortKey),
    ToggleSortMenu,
    OpenList,
    OpenDetail(ItemId),
    OpenCreate,
    OpenEdit(ItemId),
    /// 離開編輯器（取消/返回/Esc）：髒（相對基準有變更）時先走放棄確認框。
    RequestCloseForm,
    /// 確認框「放棄編輯」後的導航重投：跳過髒閘一次，避免自我鎖死。
    NavForced(Box<Cmd>),
    RequestReveal,
    RequestTotp,
    /// 產生器「產生/重新產生」：policy 由 reduce 讀 `form.gen_panel` 現算。
    GeneratePassword,
    /// 產生器回包：Some=明文草稿（只活到套用或離開表單）；None=失敗（錯誤已入橫條）。
    Generated(Option<String>),
    RequestUnlock,
    /// 側欄「立即同步」：Sync:Trigger{force} 拉伺服器＋催背景推送。
    TriggerSync,
    /// 僅 dev/驗證用：Auth:Lock（正式 UI 未列需求，解鎖鈕才是契約項目）。
    RequestLock,
    /// 開/關「變更主密碼」模態；送出由 SubmitChangePassword 落地。
    OpenChangePassword,
    CloseChangePassword,
    SubmitChangePassword,
    AskDelete(ItemId),
    /// 匯入模態開關；預覽＝本地解析計數（(可匯入, 跳過)），
    /// 執行＝逐筆既有 Create 路徑（daemon 無 import 面，2b 本地兜底）。
    OpenImport,
    CloseImport,
    ImportPreview,
    ImportPreviewed(Result<(usize, usize), String>),
    ImportRun,
    ImportDone(Result<crate::import::ImportOutcome, String>),
    /// 附件三操作（批次 4b）：item id 取當前行／Route::Detail；
    /// `AttachmentDone` 承載顯示文案（Ok）或可懂錯誤（Err）。
    UploadAttachment {
        item_id: ItemId,
        path: String,
    },
    DownloadAttachment {
        item_id: ItemId,
        attachment_id: String,
        file_name: String,
    },
    AskDeleteAttachment {
        item_id: ItemId,
        attachment_id: String,
        file_name: String,
    },
    DeleteAttachment {
        item_id: ItemId,
        attachment_id: String,
    },
    AttachmentDone {
        item_id: ItemId,
        op: crate::attach::AttOp,
        res: Result<String, String>,
    },
    /// 事件幫浦刷新：列表必刷，開著詳情時連詳情一起刷（附件列收斂語意）。
    EventsRefresh,
    /// 事件驱动的詳情重取：失敗靜默（下一拍事件再試，不閃橫條）。
    DetailRefreshed {
        id: ItemId,
        row: Option<Arc<ItemView>>,
    },
    /// 主題三態（跟隨系統／淺／暗）：App 的 effect 監 `theme_mode` 套
    /// `set_color_scheme`（元件上下文才准 act），這裡只記訊號＋落盤。
    SetTheme(Appearance),
    /// 垃圾桶切換（側欄列；None 視角＝一般列表）。
    ToggleTrash,
    /// 已封存視角切換（批次 C，四態互斥同垃圾桶）。
    ToggleArchived,
    /// 封存／取消封存（daemon `Vault:SetArchived`，官方 archivedDate 語意）。
    SetArchived {
        id: ItemId,
        archived: bool,
    },
    /// GetIcon 回包：Ok＝原樣位元組（magic 嗅探定生死）、Err＝字母磚。
    IconLoaded {
        host: String,
        res: Result<Vec<u8>, String>,
    },
    /// 側欄資料夾節點：None＝全部項目、Some("")＝未歸屬、Some(id)＝該夾。
    ChooseFolder(Option<String>),
    /// 批准中心（批次 6 併入 GUI）：佇列視角、輪詢、單鍵直決。
    OpenApprovals,
    /// 本機設定（macOS 設定面）：右欄視角、讀取、改即存。
    OpenSettings,
    FetchSettings,
    /// 報告儀表板（路線 4）：卡面彙整＋兩份清單＋詳情頁歷史節。
    OpenReports,
    ShowReportsTab(ReportsTab),
    FetchReuse,
    FetchWeak,
    ReuseLoaded(Arc<Vec<bw_proto::DupGroup>>),
    WeakLoaded(Arc<serde_json::Value>),
    FetchHistory(ItemId),
    HistoryLoaded {
        item: ItemId,
        report: Arc<serde_json::Value>,
    },
    /// 事件驱动的鎖態刷新（daemon `LockStateChanged` 廣播：自動鎖定沒有
    /// 人按的呼叫，界面只能靠事件看見；Status 屬輪詢豁免、不會餵活計時器）。
    RefreshStatus,
    SettingsLoaded(bw_proto::Settings),
    ApplySettings(bw_proto::Settings),
    SettingsSaved(Result<(), String>),
    /// 詳情頁 Passkeys 節（有才渲染）：取列表、刪除走確認模態。
    FetchPasskeys(ItemId),
    PasskeysLoaded {
        item: ItemId,
        entries: Arc<Vec<bw_proto::PasskeyEntry>>,
    },
    AskDeletePasskey {
        item: ItemId,
        credential: String,
        rp: String,
        user: String,
    },
    DeletePasskey {
        item: ItemId,
        credential: String,
    },
    PasskeyDeleted(Result<(), String>),
    FetchPending,
    PendingLoaded(Arc<Vec<PendingRow>>),
    ApprovePending(String),
    DenyPending(String),
    /// 批准/拒絕回包：Ok=成功（刷新佇列＋列表——批准可能放行鏡像變化）。
    PendingActed {
        approve: bool,
        res: Result<(), String>,
    },
    /// 拉資料夾鏡像（連線後與開表單前刷新）。
    FetchFolders,
    FoldersLoaded(Arc<Vec<FolderEntry>>),
    /// 垃圾桶詳情動作：還原（軟刪撤銷）與永久刪除（先確認再 PurgeNow）。
    RestoreItem(ItemId),
    AskPurge(ItemId),
    PurgeNow(ItemId),
    /// 還原／永久刪除回包：成功才收 notice、回列表重抓。
    TrashWriteDone {
        err: Option<String>,
        notify: Option<String>,
    },
    AskExport,
    ConfirmYes,
    ConfirmNo,
    SubmitForm,
    /// 確認框的後續意圖（只由 ConfirmYes 投遞）。
    DeleteNow(ItemId),
    RunExport,
    // —— worker 結果 ——
    Connected {
        state: UnlockStateView,
    },
    ConnectFailed {
        detail: String,
    },
    ListLoaded {
        seq: u64,
        rows: Arc<Vec<ItemView>>,
    },
    DetailLoaded {
        id: ItemId,
        row: Arc<ItemView>,
    },
    EditPrefilled {
        id: ItemId,
        row: Arc<ItemView>,
    },
    Revealed(Option<String>),
    TotpLoaded {
        code: String,
        valid_for_secs: u32,
    },
    /// 取碼回「無 seed」：正常缺席，整節不渲染、不報錯。
    TotpAbsent,
    /// 取碼其他失敗（seed 解錯/形態不符）：節內可懂一行，不彈窗不掛橫條。
    TotpErrored(String),
    StateUpdated {
        state: UnlockStateView,
        refetch: bool,
        /// 帳號顯示欄（批次 8）：None＝本路徑無情報（如 Welcome），不動現值。
        reauth: bool,
        email: Option<String>,
        server: Option<String>,
    },
    /// 主畫面切登入卡（帳號列/橫幅點擊；SignedOut 時本就是主畫面）。
    OpenLogin,
    /// 編輯態無變更退回查看態：保留 detail 骨架不重取（零跳動）；
    /// 骨架缺席才退回完整 OpenDetail 路徑。
    ShowDetailView(ItemId),
    /// 登入卡送出：前端校驗 → `Auth:Login{password:Some}`（本機 UDS 明文合法）。
    SubmitLogin,
    /// 第二步（2FA）：伺服器挑戰列出可用因子，卡原地進因子單選＋驗證碼態。
    Login2faRequested(Vec<bw_proto::TwoFactorProviderInfo>),
    /// 第二步送出：重發 Login{password, two_factor}（daemon 不存挑戰，
    /// hash 由密碼重算；密碼訊號跨步保留）。
    SubmitLogin2fa,
    /// 登入失敗回包（成功直接走 StateUpdated，登入即解鎖的 hub 語意）。
    LoginDone(Result<(), String>),
    /// 空作（背景路徑無情報可落地時佔位）。
    Nop,
    /// Sync:Trigger 成功回包：蓋同步時間戳、提示「已同步」、重抓列表。
    SyncDone {
        state: UnlockStateView,
        reauth: bool,
        email: Option<String>,
        server: Option<String>,
    },
    WriteDone {
        err: Option<String>,
        follow: Follow,
    },
    /// 改密 worker 結果：None＝成功（模態關閉 + notice）；Some＝daemon/VW 錯誤原文。
    ChangePasswordDone(Option<String>),
    ExportDone(Result<ExportOutcome, String>),
    Failed {
        err: String,
    },
}

/// 自訂欄位編輯草稿。三態型別（text/hidden/boolean）＋增刪在建立與
/// 編輯模式全開放（daemon 批次 3：SetType／AppendField／RemoveField）。
#[derive(Clone, Debug)]
pub struct FieldDraft {
    /// 列身份（每次編輯列唯一；不参与相等比較，只穩住 each 的 key
    /// 並讓 diff 以身分對齊而非位置）。
    pub key: u32,
    pub name: String,
    /// boolean 欄的值正規化成 "true"/"false"（daemon wire 形態）。
    pub value: String,
    pub kind: CipherFieldKind,
}

impl FieldDraft {
    /// 切型別並正規化值：進 boolean 欄只留 "true"/"false"。
    pub fn set_kind(&mut self, kind: CipherFieldKind) {
        self.kind = kind;
        if kind == CipherFieldKind::Boolean {
            self.value = if self.value == "true" { "true" } else { "false" }.to_owned();
        }
    }

    pub fn bool_value(&self) -> bool {
        self.value == "true"
    }
}

impl PartialEq for FieldDraft {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.value == other.value && self.kind == other.kind
    }
}

impl Eq for FieldDraft {}

impl Default for FieldDraft {
    fn default() -> Self {
        Self {
            key: rand_key(),
            name: String::new(),
            value: String::new(),
            kind: CipherFieldKind::Text,
        }
    }
}

/// 編輯列身份：uuid 前 4 bytes → u32（免拉 rand 依賴）。
fn rand_key() -> u32 {
    let id = uuid::Uuid::new_v4();
    u32::from_le_bytes(id.as_bytes()[..4].try_into().unwrap_or([0; 4]))
}

/// 表單欄位（新增/編輯共用一組；`Route` 決定語意）。
#[derive(Clone)]
pub struct FormFields {
    pub name: Signal<String>,
    pub username: Signal<String>,
    /// 明文只在這個訊號與送出時的 `Zeroizing` 副本裡存在（契約 §2.7 規則 6：
    /// UI 純介面零業務邏輯，明文不進 JS、不落盤）。
    pub password: Signal<String>,
    pub uris: Signal<std::sync::Arc<Vec<UriDraft>>>,
    pub tags: Signal<String>,
    /// 型別切換：本批僅 Login/SecureNote 可選，Card/Identity 佔位 disabled。
    pub kind: Signal<ItemKind>,
    /// 資料夾歸屬：""＝未歸屬；否則 ListFolders 的 id。
    pub folder_id: Signal<String>,
    pub notes: Signal<String>,
    /// 自訂欄位編輯列（順序即送出順序）。
    pub fields: Signal<Arc<Vec<FieldDraft>>>,
    pub error: Signal<Option<String>>,
    pub original: Signal<Option<Arc<FormOriginal>>>,
    /// 產生器面板狀態（開合／長度／字元集開關）。
    pub gen_panel: Signal<GenState>,
    /// 產生器明文草稿：只活到套用進 password 或離開表單（同 Zeroize 紀律）。
    pub gen_draft: Signal<Option<String>>,
}

impl FormFields {
    fn reset(&self, original: Option<Arc<FormOriginal>>) {
        self.name.set(String::new());
        self.username.set(String::new());
        self.password.set(String::new());
        self.uris.set(std::sync::Arc::new(Vec::new()));
        self.tags.set(String::new());
        self.error.set(None);
        self.original.set(original);
        self.kind.set(ItemKind::Login);
        self.folder_id.set(String::new());
        self.notes.set(String::new());
        self.fields.set(Arc::new(Vec::new()));
        self.gen_panel.set(GenState::default());
        self.gen_draft.set(None);
    }
}

/// 網址編輯列（批次 A：多網址）。`key`＝基準陣列位置（對齊手法同
/// `FieldDraft`，刪列/改列不錯位）；新增列用亂數哨兵 key（不在基準索引域，
/// diff 時落入 `AppendUri`，見 `uri_edits`）。`match_type`＝官方判定欄
/// （None=預設 null；0..4 見 `uri_match_label`），diff 走 `SetUriMatch`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriDraft {
    pub key: u32,
    pub uri: String,
    pub match_type: Option<u8>,
}

/// 新增列哨兵 key 的取值（語意見 `UriDraft`；實際判別按「key 是否在基準索引域」）。
pub const NEW_URI: u32 = u32::MAX;

impl Default for UriDraft {
    fn default() -> Self {
        Self {
            key: rand_key(),
            uri: String::new(),
            match_type: None,
        }
    }
}

/// 網址判定下拉的六態（官方 `login.uris[].match`；繁中標籤對齊 upstream
/// 語意：0=網域、1=網域＋子域、2=開頭符合、3=精確、4=正規表達式；
/// 5=永不僅值域不列 UI，同官方 web 層級表）。
pub const URI_MATCH_OPTIONS: [(Option<u8>, &str); 6] = [
    (None, "預設"),
    (Some(0), "網域"),
    (Some(1), "網域＋子域"),
    (Some(3), "精確符合"),
    (Some(2), "開頭符合"),
    (Some(4), "正規表達式"),
];

/// 判定值的顯示名（未知編號回「預設」不亂併名——5=Never 不在六態表）。
#[must_use]
pub fn uri_match_label(m: Option<u8>) -> &'static str {
    URI_MATCH_OPTIONS
        .iter()
        .find(|(v, _)| *v == m)
        .map(|(_, l)| *l)
        .unwrap_or("預設")
}

/// 改主密碼模態的三欄（現有/新/確認）。明文只活在訊號與送出時的
/// `Zeroizing` 副本（同 `FormFields.password` 紀律）；關閉模態即出棧。
#[derive(Clone)]
pub struct PwFields {
    pub current: Signal<String>,
    pub new: Signal<String>,
    pub confirm: Signal<String>,
    pub error: Signal<Option<String>>,
}

impl PwFields {
    fn reset(&self) {
        self.current.set(String::new());
        self.new.set(String::new());
        self.confirm.set(String::new());
        self.error.set(None);
    }
}

/// 登入卡三欄（批次 8）：server/email＋密碼明文（只進訊號與送出時的
/// `Zeroizing` 副本，同 `FormFields.password` 紀律）；error＝daemon 錯誤
/// 原文可懂化；busy＝送出中（防連點重複登入）。
#[derive(Clone)]
pub struct LoginFields {
    pub server: Signal<String>,
    pub email: Signal<String>,
    pub password: Signal<String>,
    pub error: Signal<Option<String>>,
    pub busy: Signal<bool>,
    /// 第二步（2FA）：Some＝伺服器挑戰列出的因子（卡進因子單選＋驗證碼態）；
    /// None＝第一步。password 訊號跨步保留＝重送 Login 的憑證來源。
    pub providers: Signal<Option<Arc<Vec<bw_proto::TwoFactorProviderInfo>>>>,
    /// 當前端選的因子編號。
    pub provider: Signal<i32>,
    pub code: Signal<String>,
    pub remember: Signal<bool>,
}

impl LoginFields {
    fn reset(&self) {
        self.password.set(String::new());
        self.error.set(None);
        self.busy.set(false);
        self.providers.set(None);
        self.code.set(String::new());
        self.remember.set(false);
    }
}

/// 伺服器 URL 正規化＋http(s) 閘（純函數，單測點）：缺 scheme 補 https、
/// 非 http(s) 拒絕、host 空/含空白拒絕。回傳送 daemon 的正規形態。
pub fn normalize_server(raw: &str) -> Result<String, &'static str> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("伺服器 URL 不可為空白");
    }
    let lower = s.to_lowercase();
    let (scheme, rest_raw) = match lower.split_once("://") {
        Some(("http", rest)) => ("http", rest),
        Some(("https", rest)) => ("https", rest),
        Some((_, _)) => return Err("僅支援 http(s) 伺服器 URL"),
        None => ("https", s),
    };
    let host = rest_raw.split('/').next().unwrap_or("");
    let host_ok = !host.is_empty()
        && !host.contains(char::is_whitespace)
        && (host.contains('.') || host == "localhost" || host.contains(':'));
    if !host_ok {
        return Err("伺服器 URL 格式不對，例：https://vault.example.com");
    }
    // scheme 以小寫正規化、host 起保留原樣（IDN/大小寫由 daemon 端处理）。
    let rest = &s[s.len() - rest_raw.len()..];
    Ok(format!("{scheme}://{rest}"))
}

/// 登入表單前端校驗（繁中訊息；省一次往返，最終裁判仍是 daemon）。
/// Ok＝正規化後的 server URL。
pub fn validate_login(server: &str, email: &str, password: &str) -> Result<String, String> {
    if email.trim().is_empty() {
        return Err("請輸入 email".into());
    }
    if password.is_empty() {
        return Err("請輸入主密碼".into());
    }
    normalize_server(server).map_err(str::to_owned)
}

/// 第二步預選因子（純函數，單測點）：首個本批支援的因子（Authenticator/Email）；
/// 全部未支援時退回首個列出的（選了會拿到 daemon「此因子尚未支援」可懂錯誤，
/// 看得見總比默靜成功好）。空清單＝None。
pub fn default_provider(infos: &[bw_proto::TwoFactorProviderInfo]) -> Option<i32> {
    infos
        .iter()
        .find(|p| bw_proto::TwoFactorProviderInfo::is_supported(p.provider))
        .or_else(|| infos.first())
        .map(|p| p.provider)
}

/// 一次性驗證碼格式閘（純函數，單測點）：6 位數字（TOTP/Email 代碼同形）。
/// 通過時回 trim 後的碼；最終裁判仍是伺服器。
pub fn validate_otp(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.len() != 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("驗證碼需為 6 位數字".into());
    }
    Ok(s.to_owned())
}

/// 登入錯誤可懂化（批次 8）：保留 daemon 原文（使用者要看真話），
/// 403／傳輸類另加一句繁中提示。
pub fn humanize_login(err: &str) -> String {
    if err.contains("403") || err.contains("incorrect") {
        format!("{err}（憑證遭拒：檢查 email 與主密碼）")
    } else if err.contains("Invalid TOTP") || err.contains("Invalid token") {
        format!("{err}（驗證碼錯誤或已過期：重新取碼後再試）")
    } else if err.contains("refused")
        || err.contains("transport")
        || err.contains("connect")
        || err.contains("dns")
    {
        format!("{err}（連不到伺服器：檢查 URL 與網路）")
    } else {
        err.to_owned()
    }
}

/// 「無 seed」錯誤判別（純函數，單測點）：daemon 對無 seed 項目的回絕
/// 措辭屬正常缺席（hub.rs totp()），其他錯誤才走可懂一行。
pub fn totp_absent(err: &str) -> bool {
    err.contains("沒有 TOTP seed")
}

/// 取碼錯誤可懂化：原樣保留 daemon 訊息並加一句繁中指引（不彈窗）。
pub fn humanize_totp(err: &str) -> String {
    if err.contains("Locked") || err.contains("鎖定") {
        "取碼失敗：庫已鎖定".into()
    } else {
        format!("取碼失敗：{err}")
    }
}

/// 「驗證碼」節渲染閘（純函數，單測點）：有碼或真錯誤才出現；
/// 無 seed（兩者皆 None）整節不渲染。
pub fn totp_section_shown(code: Option<&str>, err: Option<&str>) -> bool {
    code.is_some() || err.is_some()
}

/// 側欄帳號列的顯示態（純函數，單測點）：needs_reauth 優先（憑證失效
/// 時即使仍解鎖也要人看見）；未登入次之；其餘為已登入（email 可知則示）。
#[derive(Debug, PartialEq, Eq)]
pub enum AcctRow {
    Reauth,
    SignedOut,
    Signed(Option<String>),
}

pub fn account_row(state: Option<&UnlockStateView>, reauth: bool, email: Option<&str>) -> AcctRow {
    if reauth {
        return AcctRow::Reauth;
    }
    match state {
        None | Some(UnlockStateView::SignedOut) => AcctRow::SignedOut,
        _ => AcctRow::Signed(email.map(str::to_owned)),
    }
}

/// 新主密碼強度閘（與 daemon `hub::MIN_MASTER_PASSWORD` 同值；daemon 是
/// 真相源，這裡只是送出前的前端攔截，省一次往返）。
pub const MIN_MASTER_PASSWORD: usize = 12;

/// 改密表單的前端校驗（繁中錯誤訊息）。比對全在純函數裡，reduce 只分派。
pub fn validate_change_password(
    current: &str,
    new: &str,
    confirm: &str,
) -> Result<(), String> {
    if current.is_empty() {
        return Err("請輸入現有主密碼".into());
    }
    if new.chars().count() < MIN_MASTER_PASSWORD {
        return Err(format!("新主密碼太短（至少 {MIN_MASTER_PASSWORD} 字元）"));
    }
    if new != confirm {
        return Err("新密碼與兩次輸入不一致".into());
    }
    Ok(())
}

/// 根元件建立、以 `Copy` 訊號句柄向下傳播的應用核心。
#[derive(Clone)]
pub struct AppCore {
    pub session: Arc<Session>,
    /// favicon 專用第二連線（批次 C）：GetIcon 在 daemon 端要代理抓外站
    /// （秒級），若走互動 session 的 Mutex 會塞死一切命令（e2e14 實錄）；
    /// 自開一條只跑 icon 的連線，延遲彼此隔離。
    pub icon_session: Arc<Session>,
    tx: Sender<Cmd>,
    pub phase: Signal<Phase>,
    pub route: Signal<Route>,
    pub vault: Signal<Option<UnlockStateView>>,
    pub items: Signal<Arc<Vec<ItemView>>>,
    pub query: Signal<String>,
    pub tag: Signal<Option<String>>,
    /// 側欄視角（資料夾三態＋垃圾桶，互斥由 `VaultFilter` 方法保證）。
    pub filter: Signal<VaultFilter>,
    /// 資料夾鏡像（ListFolders；鎖定態 name None → 節點隱藏）。
    pub folders: Signal<Arc<Vec<FolderEntry>>>,
    /// 待批准佇列（側欄徽章＋右欄佇列視角的共同真相源）。
    pub pending: Signal<Arc<Vec<PendingRow>>>,
    /// 網站圖示快取（批次 C）：host → 態。單飛＝請求前先插 `Loading`。
    pub icons: Signal<Arc<HashMap<String, IconState>>>,
    pub sort: Signal<SortKey>,
    pub sort_menu: Signal<bool>,
    pub list_gen: Signal<u64>,
    pub busy: Signal<usize>,
    pub error_text: Signal<Option<String>>,
    pub notice: Signal<Option<String>>,
    pub detail: Signal<Option<Arc<ItemView>>>,
    pub revealed: Signal<Option<String>>,
    pub totp: Signal<Option<String>>,
    /// TOTP 倒數三件組：視窗秒數、取碼時刻、1s tick（App 的引擎計時器驅動，
    /// 只用於詳情重繪與到期重取，不是背景任務）。
    pub totp_valid_for: Signal<u32>,
    pub totp_issued: Signal<Option<Instant>>,
    /// 取碼失敗的可懂一行（解 seed 錯等）；「無 seed」不設此欄＝整節不渲染。
    pub totp_error: Signal<Option<String>>,
    pub totp_tick: Signal<u64>,
    /// 側欄同步狀態：本視窗最近一次 Sync:Trigger 成功時刻。
    pub last_sync: Signal<Option<Instant>>,
    /// daemon 憑證失效旗（status.needs_reauth）：橫幅＋帳號列 warning。
    pub needs_reauth: Signal<bool>,
    /// 帳號顯示欄（status.email/server）：側欄帳號列與登入卡預填。
    pub acct_email: Signal<Option<String>>,
    pub acct_server: Signal<Option<String>>,
    /// 主畫面強制切登入卡（needs_reauth 點擊進路；登入成功即清）。
    pub show_login: Signal<bool>,
    /// 登入卡三欄＋錯誤＋送出旗（批次 8：SignedOut 主畫面）。
    pub login: LoginFields,
    pub confirm: Signal<Option<Arc<Confirm>>>,
    pub form: FormFields,
    /// 改主密碼模態開關 + 三欄（true 時 App 掛 modal）。
    pub pw_modal: Signal<bool>,
    pub pw: PwFields,
    /// 匯入模態開關＋路徑＋預覽結果（None＝尚未預覽）。
    pub import_modal: Signal<bool>,
    pub import_path: Signal<String>,
    pub import_preview: Signal<Option<Result<(usize, usize), String>>>,
    /// 附件上傳草稿路徑（詳情頁內聯編輯器用）＋單飛狀態機＋編輯器開合。
    pub att_upload_path: Signal<String>,
    pub att_upload_open: Signal<bool>,
    pub att_state: Signal<crate::attach::AttState>,
    /// 外觀選擇（持久化到 `<datadir>/bitward/theme.txt`）。
    pub theme_mode: Signal<Appearance>,
    /// 本機設定鏡（daemon 真態在 meta 表）：連線後 FetchSettings 回填、
    /// 設定頁改即存；複製鈕的剪貼簿清除倒數也讀這裡（ui::copy_button）。
    pub settings: Signal<bw_proto::Settings>,
    /// 詳情頁 Passkeys（GetPasskeys 按 item 過濾後的快取；離開詳情即清）。
    pub passkeys: Signal<Arc<Vec<bw_proto::PasskeyEntry>>>,
    /// 報告儀表板：視角兩態＋兩份報告鏡（daemon 現算、每次進入重取，不落盤）。
    pub reports_tab: Signal<ReportsTab>,
    pub reports_reuse: Signal<Arc<Vec<bw_proto::DupGroup>>>,
    pub reports_weak: Signal<Arc<serde_json::Value>>,
    /// 詳情頁歷史節（Reports:CipherHistory 回包鏡；離開詳情即清，有才渲染）。
    pub history: Signal<Arc<serde_json::Value>>,
}

impl AppCore {
    /// 在元件上下文（`App`）裡呼叫：訊號隸屬目前 owner。
    pub fn boot(session: Arc<Session>) -> (AppCore, Receiver<Cmd>) {
        let (tx, rx) = channel();
        let icon_session = Arc::new(Session::new(session.path().to_path_buf()));
        let core = AppCore {
            icon_session,
            session,
            tx,
            phase: signal(Phase::Connecting),
            route: signal(Route::List),
            vault: signal(None),
            items: signal(Arc::new(Vec::new())),
            query: signal(String::new()),
            tag: signal(None),
            filter: signal(VaultFilter::default()),
            folders: signal(Arc::new(Vec::new())),
            pending: signal(Arc::new(Vec::new())),
            icons: signal(Arc::new(HashMap::new())),
            sort: signal(SortKey::Name),
            sort_menu: signal(false),
            list_gen: signal(0),
            busy: signal(0),
            error_text: signal(None),
            notice: signal(None),
            detail: signal(None),
            revealed: signal(None),
            totp: signal(None),
            totp_valid_for: signal(0),
            totp_issued: signal(None),
            totp_error: signal(None),
            totp_tick: signal(0),
            last_sync: signal(None),
            needs_reauth: signal(false),
            acct_email: signal(None),
            acct_server: signal(None),
            show_login: signal(false),
            login: LoginFields {
                server: signal(String::new()),
                email: signal(String::new()),
                password: signal(String::new()),
                error: signal(None),
                busy: signal(false),
                providers: signal(None),
                provider: signal(0),
                code: signal(String::new()),
                remember: signal(false),
            },
            confirm: signal_with(None, SignalEquals::Never),
            pw_modal: signal(false),
            pw: PwFields {
                current: signal(String::new()),
                new: signal(String::new()),
                confirm: signal(String::new()),
                error: signal(None),
            },
            import_modal: signal(false),
            import_path: signal(String::new()),
            import_preview: signal(None),
            att_upload_path: signal(String::new()),
            att_upload_open: signal(false),
            att_state: signal(crate::attach::AttState::default()),
            theme_mode: signal(Appearance::System),
            settings: signal(bw_proto::Settings::default()),
            passkeys: signal(Arc::new(Vec::new())),
            reports_tab: signal(ReportsTab::Cards),
            reports_reuse: signal(Arc::new(Vec::new())),
            reports_weak: signal(Arc::new(serde_json::json!({"threshold": bw_proto::WEAK_PASSWORD_THRESHOLD, "items": []}))),
            history: signal(Arc::new(serde_json::json!({"supported": false, "versions": []}))),
            form: FormFields {
                name: signal(String::new()),
                username: signal(String::new()),
                password: signal(String::new()),
                uris: signal(std::sync::Arc::new(Vec::new())),
                tags: signal(String::new()),
                kind: signal(ItemKind::Login),
                folder_id: signal(String::new()),
                notes: signal(String::new()),
                fields: signal(Arc::new(Vec::new())),
                error: signal(None),
                original: signal_with(None, SignalEquals::Never),
                gen_panel: signal(GenState::default()),
                gen_draft: signal(None),
            },
        };
        (core, rx)
    }

    pub fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    /// 派一個 daemon 往返到 worker 執行緒；結果以命令回投。
    /// 呼叫端必須在引擎執行緒（reduce / on_press）。
    fn ipc<F>(&self, f: F)
    where
        F: FnOnce(Arc<Session>) -> Cmd + Send + 'static,
    {
        self.busy.set(self.busy.get() + 1);
        let tx = self.tx.clone();
        let session = self.session.clone();
        std::thread::spawn(move || {
            let cmd = f(session);
            let _ = tx.send(cmd);
        });
    }

    fn settle(&self) {
        self.busy.set(self.busy.get().saturating_sub(1));
    }

    /// 輪詢专用：同 `ipc` 但不動 busy 計數（背景節拍不該讓標題閃「處理中…」）。
    fn ipc_quiet<F>(&self, f: F)
    where
        F: FnOnce(Arc<Session>) -> Cmd + Send + 'static,
    {
        let tx = self.tx.clone();
        let session = self.session.clone();
        std::thread::spawn(move || {
            let cmd = f(session);
            let _ = tx.send(cmd);
        });
    }

    /// 事件幫浦：自開一條 daemon 監聽連線（執行緒非「背景任務」語意的
    /// worker，只回投命令、不碰訊號）。`OutboxDrained`／`VaultChanged`
    /// 到達即重抓（未同步徽章無感消失）、`ApprovalRequired` 即重拉佇列；
    /// 斷線 1 秒重連（daemon 重啟自愈）。
    pub fn watch_events(&self) {
        let session = self.session.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || loop {
            let tx2 = tx.clone();
            let _ = session.listen(
                &[
                    EventTopic::OutboxDrained,
                    EventTopic::VaultChanged,
                    EventTopic::ApprovalRequired,
                    EventTopic::LockStateChanged,
                ],
                move |topic| {
                    match topic {
                        EventTopic::ApprovalRequired => {
                            let _ = tx2.send(Cmd::FetchPending);
                        }
                        // 自動鎖定/解鎖沒有人按的呼叫：靠事件刷新鎖態視角
                        EventTopic::LockStateChanged => {
                            let _ = tx2.send(Cmd::RefreshStatus);
                        }
                        EventTopic::OutboxDrained | EventTopic::VaultChanged => {
                            let _ = tx2.send(Cmd::EventsRefresh);
                        }
                        _ => {}
                    }
                },
            );
            std::thread::sleep(Duration::from_secs(1));
        });
    }

    /// 離開詳情/表單時清明文：Reveal 明文只活在詳情元件狀態（契約驗收 3）。
    fn leave_detail(&self) {
        self.detail.set(None);
        // 明文在此結束生命週期：訊號值 drop 即釋放（String 由 std 歸零記憶體
        // 前的最後持有者；常駐拷貝不存在——GUI 不緩存任何 Reveal 結果）。
        self.revealed.set(None);
        self.totp.set(None);
        self.totp_error.set(None);
        self.totp_valid_for.set(0);
        self.totp_issued.set(None);
        self.att_upload_path.set(String::new());
        self.att_upload_open.set(false);
        self.passkeys.set(Arc::new(Vec::new()));
        self.history.set(Arc::new(serde_json::json!({"supported": false, "versions": []})));
    }
}

/// 唯一狀態轉移函數：所有 `Cmd` 在此落地（表格化分派，避免散落的 if）。
pub fn reduce(core: &AppCore, cmd: Cmd) {
    // Inline 編輯器髒閘：會打斷編輯的導航先攔下走放棄確認框；
    // NavForced＝確認後的重投，跳過閘一次避免自我鎖死。
    let mut cmd = cmd;
    let forced = matches!(cmd, Cmd::NavForced(_));
    if let Cmd::NavForced(inner) = cmd {
        cmd = *inner;
    }
    if !forced
        && matches!(core.route.get(), Route::Create | Route::Edit(_))
        && nav_interrupts(&cmd)
        && form_dirty(core)
    {
        core.confirm.set(Some(Arc::new(Confirm {
            title: "放棄未儲存的編輯？".into(),
            description: "編輯器中的變更尚未儲存，離開後將遺失。".into(),
            confirm_label: "放棄編輯".into(),
            destructive: true,
            on_confirm: Cmd::NavForced(Box::new(cmd.clone())),
        })));
        return;
    }
    match cmd {
        Cmd::Boot => {
            core.phase.set(Phase::Connecting);
            core.error_text.set(None);
            // 初始鎖態直接讀 Welcome.state（§2.5）：不多發一個 Status，
            // 也避開新舊 daemon 的 StatusInfo 欄位漂移面。
            core.ipc(move |s| match s.ensure() {
                Ok(state) => Cmd::Connected { state },
                Err(e) => Cmd::ConnectFailed {
                    detail: e.display(),
                },
            });
        }
        Cmd::Connected { state } => {
            core.settle();
            core.phase.set(Phase::Ready);
            core.vault.set(Some(state));
            core.error_text.set(None);
            core.send(Cmd::FetchFolders);
            fetch_list(core);
            // 設定鏡先行回填（剪貼簿清除閘在複製鈕、鎖定清搜尋閘在 StateUpdated，
            // 兩處都要讀它；GetSettings 是本機純讀，不動 busy 計數）。
            core.ipc_quiet(|s| match s.call(&Call::Admin(AdminCall::GetSettings)) {
                Ok(Response::Settings(v)) => Cmd::SettingsLoaded(v),
                _ => Cmd::Nop,
            });
            // 批次 8：Welcome 不帶帳號情報，補一發輕量 Status 回填
            // 帳號列 email／登入卡 server 預填／needs_reauth 旗。
            core.ipc_quiet(|s| match s.call(&Call::Sync(SyncCall::Status)) {
                Ok(Response::Status(info)) => Cmd::StateUpdated {
                    state: info.state,
                    refetch: false,
                    reauth: info.needs_reauth,
                    email: info.email,
                    server: info.server,
                },
                _ => Cmd::Nop,
            });
        }
        Cmd::ConnectFailed { detail } => {
            core.settle();
            core.phase.set(Phase::Failed);
            core.error_text.set(Some(detail));
        }
        Cmd::RefetchList => fetch_list(core),
        Cmd::ChooseTag(tag) => {
            core.tag.set(tag);
            fetch_list(core);
        }
        Cmd::ChooseSort(sort) => {
            core.sort.set(sort);
            core.sort_menu.set(false);
            fetch_list(core);
        }
        Cmd::ToggleSortMenu => {
            let next = !core.sort_menu.get();
            core.sort_menu.set(next);
        }
        Cmd::ListLoaded { seq, rows } => {
            core.settle();
            if seq == core.list_gen.get() {
                core.items.set(rows);
                core.error_text.set(None);
                request_icons(core);
            }
        }
        // NavForced 已在入口剝殼；走到這裡＝巢狀 Box（不預期），靜默吞掉。
        Cmd::NavForced(_) => {}
        Cmd::RequestCloseForm => {
            let back = match core.route.get() {
                Route::Edit(id) => Cmd::ShowDetailView(id),
                _ => Cmd::OpenList,
            };
            if matches!(core.route.get(), Route::Create | Route::Edit(_)) && form_dirty(core) {
                core.confirm.set(Some(Arc::new(Confirm {
                    title: "放棄未儲存的編輯？".into(),
                    description: "編輯器中的變更尚未儲存，離開後將遺失。".into(),
                    confirm_label: "放棄編輯".into(),
                    destructive: true,
                    on_confirm: Cmd::NavForced(Box::new(back)),
                })));
            } else {
                reduce(core, back);
            }
        }
        Cmd::OpenList => {
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::List);
        }
        Cmd::OpenDetail(id) => {
            core.leave_detail();
            core.route.set(Route::Detail(id));
            core.ipc(move |s| match s.call(&get(id, View::Masked)) {
                Ok(Response::Item(Some(row))) => Cmd::DetailLoaded {
                    id,
                    row: Arc::new(*row),
                },
                Ok(Response::Item(None)) => Cmd::Failed {
                    err: "找不到該項目".into(),
                },
                Ok(other) => Cmd::Failed {
                    err: format!("Get 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::DetailLoaded { id, row } => {
            core.settle();
            if core.route.get() == Route::Detail(id) {
                let is_login = row.meta.kind == ItemKind::Login;
                let host = row.meta.uris.first().and_then(|u| host_of(u));
                core.detail.set(Some(row));
                if let Some(h) = host {
                    request_hosts(core, vec![h]);
                }
                // 批次 A：有 seed 與否由 daemon 裁決（投影不帶 seed 存在性），
                // 進詳情即自動取碼——成功現碼、無 seed 靜默收合、真錯一行。
                if is_login {
                    core.send(Cmd::RequestTotp);
                    // Passkeys 節（有才渲染）：GetPasskeys 按 item 過濾，
                    // 走 quiet 連線（鎖定態回 Locked 屬正常缺席，不閃橫條）。
                    core.send(Cmd::FetchPasskeys(id));
                    // 歷史節（有才渲染）：代理伺服器端點，VW 等未實裝路由的
                    // server 回 supported:false＋空 versions → 整節缺席。
                    core.send(Cmd::FetchHistory(id));
                }
            }
        }
        Cmd::OpenCreate => {
            core.send(Cmd::FetchFolders);
            core.leave_detail();
            core.form.reset(None);
            // 網址列至少給一列空框（舊單欄時代的發現性）。
            core.form
                .uris
                .set(std::sync::Arc::new(vec![UriDraft::default()]));
            core.route.set(Route::Create);
        }
        Cmd::OpenEdit(id) => {
            core.send(Cmd::FetchFolders);
            // 批次 A＃2 morph：不清 detail——編輯態沿用查看態骨架（節次序、
            // 標題、幾何全部原地，只欄位換輸入框），切換零跳動。
            core.form.reset(None);
            core.route.set(Route::Edit(id));
            core.ipc(move |s| match s.call(&get(id, View::Masked)) {
                Ok(Response::Item(Some(row))) => Cmd::EditPrefilled {
                    id,
                    row: Arc::new(*row),
                },
                _ => Cmd::Failed {
                    err: "載入編輯基準失敗".into(),
                },
            });
        }
        Cmd::EditPrefilled { id, row } => {
            core.settle();
            if core.route.get() != Route::Edit(id) {
                return;
            }
            // 骨架直接吃這份 Masked 投影（查看態 sections 的唯讀資料源）。
            core.detail.set(Some(row.clone()));
            core.form
                .name
                .set(row.meta.name.clone().unwrap_or_default());
            core.form
                .username
                .set(row.username.clone().unwrap_or_default());
            let uri_rows: Vec<UriDraft> = row
                .meta
                .uris
                .iter()
                .enumerate()
                .map(|(i, u)| UriDraft {
                    key: i as u32,
                    uri: u.clone(),
                    match_type: row.meta.uri_matches.get(i).copied().flatten(),
                })
                .collect();
            core.form
                .uris
                .set(std::sync::Arc::new(uri_rows.clone()));
            core.form.tags.set(row.meta.tags.join(", "));
            core.form.kind.set(row.meta.kind);
            core.form
                .folder_id
                .set(row.meta.folder_id.map(|f| f.to_string()).unwrap_or_default());
            core.form.notes.set(row.notes.clone().unwrap_or_default());
            let drafts: Vec<FieldDraft> = row
                .fields
                .iter()
                .map(|f| FieldDraft {
                    key: rand_key(),
                    name: f.name.clone(),
                    value: f.value.clone().unwrap_or_default(),
                    kind: f.kind,
                })
                .collect();
            core.form.fields.set(Arc::new(drafts.clone()));
            core.form.original.set(Some(Arc::new(FormOriginal {
                name: row.meta.name.clone().unwrap_or_default(),
                username: row.username.clone(),
                uris: row.meta.uris.clone(),
                uri_matches: row.meta.uri_matches.clone(),
                tags: row.meta.tags.clone(),
                notes: row.notes.clone(),
                folder_id: row.meta.folder_id.map(|f| f.to_string()),
                fields: drafts,
            })));
        }
        Cmd::RequestReveal => {
            let Route::Detail(id) = core.route.get() else {
                return;
            };
            // 切換語意：已顯示 → 隱藏（明文立刻出棧）。
            if core.revealed.get().is_some() {
                core.revealed.set(None);
                return;
            }
            core.ipc(move |s| match s.call(&get(id, View::Reveal)) {
                Ok(Response::Item(Some(row))) => Cmd::Revealed(row.password),
                Ok(Response::Item(None)) => Cmd::Failed {
                    err: "找不到該項目".into(),
                },
                Ok(other) => Cmd::Failed {
                    err: format!("Get(Reveal) 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::Revealed(pw) => {
            core.settle();
            core.revealed.set(Some(pw.unwrap_or_default()));
        }
        Cmd::RequestTotp => {
            let Route::Detail(id) = core.route.get() else {
                return;
            };
            core.ipc(
                move |s| match s.call(&Call::Use(UseCall::TotpCode { id })) {
                    Ok(Response::TotpCode {
                        code,
                        valid_for_secs,
                    }) => Cmd::TotpLoaded {
                        code,
                        valid_for_secs,
                    },
                    Err(e) => {
                        let msg = e.display();
                        if totp_absent(&msg) {
                            Cmd::TotpAbsent
                        } else {
                            Cmd::TotpErrored(msg)
                        }
                    }
                    Ok(other) => Cmd::TotpErrored(format!("TotpCode 回應形態不符：{other:?}")),
                },
            );
        }
        // 「此項目沒有 TOTP seed」＝正常缺席：靜默收合整節，不報錯。
        Cmd::TotpAbsent => {
            core.settle();
            core.totp.set(None);
            core.totp_error.set(None);
        }
        Cmd::TotpErrored(msg) => {
            core.settle();
            core.totp.set(None);
            core.totp_error.set(Some(humanize_totp(&msg)));
        }
        Cmd::TotpLoaded {
            code,
            valid_for_secs,
        } => {
            core.settle();
            core.totp.set(Some(code));
            core.totp_valid_for.set(valid_for_secs);
            core.totp_issued.set(Some(Instant::now()));
        }
        Cmd::GeneratePassword => {
            let policy = core.form.gen_panel.get().policy();
            core.ipc(move |s| match s.call(&Call::Use(UseCall::GeneratePassword { policy })) {
                Ok(Response::Secret(pw)) => Cmd::Generated(Some(pw)),
                Ok(other) => Cmd::Failed {
                    err: format!("GeneratePassword 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::Generated(pw) => {
            core.settle();
            core.form.gen_draft.set(pw);
        }
        Cmd::RequestUnlock => {
            core.ipc(
                |s| match s.call(&Call::Auth(AuthCall::Unlock { biometric: false })) {
                    Ok(Response::Status(info)) => Cmd::StateUpdated {
                        state: info.state,
                        refetch: true,
                        reauth: info.needs_reauth,
                        email: info.email,
                        server: info.server,
                    },
                    Ok(other) => Cmd::Failed {
                        err: format!("Unlock 回應形態不符：{other:?}"),
                    },
                    Err(e) => Cmd::Failed { err: e.display() },
                },
            );
        }
        Cmd::TriggerSync => {
            core.ipc(|s| match s.call(&Call::Sync(SyncCall::Trigger { force: true })) {
                Ok(Response::Status(info)) => Cmd::SyncDone {
                    state: info.state,
                    reauth: info.needs_reauth,
                    email: info.email,
                    server: info.server,
                },
                Ok(other) => Cmd::Failed {
                    err: format!("Sync.Trigger 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::SyncDone { state, reauth, email, server } => {
            core.settle();
            core.vault.set(Some(state));
            core.error_text.set(None);
            core.needs_reauth.set(reauth);
            if email.is_some() {
                core.acct_email.set(email);
            }
            if server.is_some() {
                core.acct_server.set(server);
            }
            core.last_sync.set(Some(Instant::now()));
            core.notice.set(Some("已同步".into()));
            fetch_list(core);
        }
        Cmd::RequestLock => {
            // lock 會撤銷本 session（A6）：後續 ensure() 重連重 Enroll，
            // 鎖態從新 Welcome 取，順帶演練 re-enroll 路徑。
            core.ipc(|s| {
                let _ = s.call(&Call::Auth(AuthCall::Lock));
                // lock 撤銷全部 session：舊連線的 Welcome 鎖態是過期快照，
                // 丟掉重連才能從新 Enroll 的 Welcome 讀到 AuthLocked。
                s.drop_conn();
                match s.ensure() {
                    Ok(state) => Cmd::StateUpdated {
                        state,
                        refetch: true,
                        reauth: false,
                        email: None,
                        server: None,
                    },
                    Err(e) => Cmd::Failed { err: e.display() },
                }
            });
        }
        Cmd::StateUpdated { state, refetch, reauth, email, server } => {
            core.settle();
            let unlocked = matches!(state, UnlockStateView::Unlocked { .. });
            // 鎖定轉換（解鎖→非解鎖）＝清除最近搜尋：官方 web vault 同位語意，
            // 字串只活在記憶體，清掉即從搜尋框與列表消失（設定可關）。
            let was_unlocked = is_unlocked(&core.vault.get());
            if was_unlocked
                && !unlocked
                && core.settings.get().clear_search_on_lock
                && !core.query.get().is_empty()
            {
                core.query.set(String::new());
            }
            core.vault.set(Some(state));
            core.error_text.set(None);
            core.needs_reauth.set(reauth);
            if email.is_some() {
                core.acct_email.set(email);
            }
            if server.is_some() {
                core.acct_server.set(server);
            }
            // 解鎖/登入成功＝離開登入卡並清明文（登入即解鎖的 hub 語意）。
            if unlocked {
                core.show_login.set(false);
                core.login.reset();
                core.send(Cmd::FetchFolders);
            }
            if refetch {
                fetch_list(core);
            }
        }
        Cmd::ShowDetailView(id) => {
            core.route.set(Route::Detail(id));
            // 明文出棧（取消／無變更退回）；骨架在＝不重取，缺席才補 fetch。
            core.form.password.set(String::new());
            if core.detail.get().is_none() {
                core.send(Cmd::OpenDetail(id));
            }
        }
        Cmd::OpenLogin => core.show_login.set(true),
        Cmd::SubmitLogin => {
            if core.login.busy.get() {
                return;
            }
            let server = core.login.server.get();
            let email = core.login.email.get().trim().to_owned();
            let pw = core.login.password.get().clone();
            match validate_login(&server, &email, &pw) {
                Err(msg) => core.login.error.set(Some(msg)),
                Ok(url) => {
                    core.login.busy.set(true);
                    core.login.error.set(None);
                    core.ipc(move |s| {
                        match s.call(&Call::Auth(AuthCall::Login {
                            server: url,
                            email,
                            password: Some(pw),
                            api_key: None,
                            two_factor: None,
                        })) {
                            // 登入即解鎖：成功直接回 Status，走 StateUpdated。
                            Ok(Response::Status(info)) => Cmd::StateUpdated {
                                state: info.state,
                                refetch: true,
                                reauth: info.needs_reauth,
                                email: info.email,
                                server: info.server,
                            },
                            // 伺服器要第二因子：原地進第二步。
                            Ok(Response::TwoFactorRequest { providers }) => {
                                Cmd::Login2faRequested(providers)
                            }
                            Ok(other) => Cmd::LoginDone(Err(format!(
                                "Login 回應形態不符：{other:?}"
                            ))),
                            Err(e) => Cmd::LoginDone(Err(humanize_login(&e.display()))),
                        }
                    });
                }
            }
        }
        Cmd::LoginDone(res) => {
            core.login.busy.set(false);
            match res {
                Ok(()) => core.login.reset(),
                Err(e) => core.login.error.set(Some(e)),
            }
        }
        Cmd::Login2faRequested(providers) => {
            core.login.busy.set(false);
            core.login.error.set(None);
            core.login.code.set(String::new());
            core.login
                .provider
                .set(default_provider(&providers).unwrap_or(0));
            core.login.providers.set(Some(Arc::new(providers)));
        }
        Cmd::SubmitLogin2fa => {
            if core.login.busy.get() {
                return;
            }
            let server = core.login.server.get();
            let email = core.login.email.get().trim().to_owned();
            let pw = core.login.password.get().clone();
            let code = match validate_otp(&core.login.code.get()) {
                Ok(c) => c,
                Err(msg) => {
                    core.login.error.set(Some(msg));
                    return;
                }
            };
            // 第一步欄位仍是憑證真相源（失焦不清號碼）；校驗共用 validate_login。
            match validate_login(&server, &email, &pw) {
                Err(msg) => core.login.error.set(Some(msg)),
                Ok(url) => {
                    core.login.busy.set(true);
                    core.login.error.set(None);
                    let tf = bw_proto::TwoFactorInput {
                        provider: core.login.provider.get(),
                        token: code,
                        remember: core.login.remember.get(),
                    };
                    core.ipc(move |s| {
                        match s.call(&Call::Auth(AuthCall::Login {
                            server: url,
                            email,
                            password: Some(pw),
                            api_key: None,
                            two_factor: Some(tf),
                        })) {
                            Ok(Response::Status(info)) => Cmd::StateUpdated {
                                state: info.state,
                                refetch: true,
                                reauth: info.needs_reauth,
                                email: info.email,
                                server: info.server,
                            },
                            // 再挑戰＝碼沒送對位；留第二步讓人重取碼。
                            Ok(Response::TwoFactorRequest { providers }) => {
                                Cmd::Login2faRequested(providers)
                            }
                            Ok(other) => Cmd::LoginDone(Err(format!(
                                "Login 回應形態不符：{other:?}"
                            ))),
                            Err(e) => Cmd::LoginDone(Err(humanize_login(&e.display()))),
                        }
                    });
                }
            }
        }
        Cmd::Nop => {}
        Cmd::OpenChangePassword => {
            core.pw.reset();
            core.pw_modal.set(true);
        }
        Cmd::CloseChangePassword => {
            // 明文出棧：關閉即清零三欄（同 leave_detail 的生命週期紀律）。
            core.pw.reset();
            core.pw_modal.set(false);
        }
        Cmd::SubmitChangePassword => {
            let current = core.pw.current.get();
            let new = core.pw.new.get();
            let confirm = core.pw.confirm.get();
            if let Err(e) = validate_change_password(&current, &new, &confirm) {
                core.pw.error.set(Some(e));
                return;
            }
            core.pw.error.set(None);
            core.ipc(move |s| {
                // Zeroize 點：兩份明文以 `Zeroizing` 持有到序列化進 Outgoing
                // 幀為止；錯誤原文（daemon/VW）原樣回給模態顯示。
                let current = zeroize::Zeroizing::new(current);
                let new = zeroize::Zeroizing::new(new);
                let call = Call::Auth(AuthCall::ChangePassword {
                    current: Some(current.to_string()),
                    new: Some(new.to_string()),
                });
                match s.call(&call) {
                    Ok(Response::Ok) => Cmd::ChangePasswordDone(None),
                    Ok(other) => Cmd::ChangePasswordDone(Some(format!(
                        "ChangePassword 回應形態不符：{other:?}"
                    ))),
                    Err(e) => Cmd::ChangePasswordDone(Some(e.display())),
                }
            });
        }
        Cmd::ChangePasswordDone(err) => {
            core.settle();
            match err {
                Some(e) => core.pw.error.set(Some(e)),
                None => {
                    core.pw_modal.set(false);
                    core.pw.reset();
                    core.notice.set(Some("主密碼已變更".into()));
                }
            }
        }
        Cmd::AskDelete(id) => {
            let name = item_name(core, id);
            core.confirm.set(Some(Arc::new(Confirm {
                title: format!("刪除「{name}」？"),
                description: "將以軟刪除排隊推送到伺服器（可稍後還原）。".into(),
                confirm_label: "刪除".into(),
                destructive: true,
                on_confirm: Cmd::DeleteNow(id),
            })));
        }
        Cmd::ToggleTrash => {
            core.filter.update(|f| f.toggle_trash());
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::List);
            fetch_list(core);
        }
        Cmd::ToggleArchived => {
            core.filter.update(|f| f.toggle_archived());
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::List);
            fetch_list(core);
        }
        Cmd::SetArchived { id, archived } => {
            core.ipc(move |s| match s.call(&Call::Vault(VaultCall::SetArchived { id, archived })) {
                Ok(Response::Ok) => Cmd::WriteDone { err: None, follow: Follow::List },
                Ok(other) => Cmd::WriteDone {
                    err: Some(format!("SetArchived 回應形態不符：{other:?}")),
                    follow: Follow::List,
                },
                Err(e) => Cmd::WriteDone { err: Some(e.display()), follow: Follow::List },
            });
        }
        Cmd::IconLoaded { host, res } => {
            core.icons.update(|m| {
                let map = Arc::make_mut(m);
                let state = match res {
                    Ok(b) => icon_data_uri(&b).map_or(IconState::Failed, IconState::Ready),
                    Err(_) => IconState::Failed,
                };
                map.insert(host, state);
            });
        }
        Cmd::ChooseFolder(folder) => {
            core.filter.update(|f| f.pick_folder(folder));
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::List);
            fetch_list(core);
        }
        Cmd::FetchFolders => {
            core.ipc(|s| match s.call(&Call::Vault(VaultCall::ListFolders)) {
                Ok(Response::Json(v)) => Cmd::FoldersLoaded(Arc::new(parse_folders(&v))),
                Ok(other) => Cmd::Failed {
                    err: format!("ListFolders 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::FoldersLoaded(rows) => {
            core.settle();
            core.folders.set(rows);
        }
        Cmd::RestoreItem(id) => {
            let name = item_name(core, id);
            core.ipc(move |s| match s.call(&Call::Vault(VaultCall::Restore { id })) {
                Ok(Response::Ok) => Cmd::TrashWriteDone {
                    err: None,
                    notify: Some(format!("已還原「{name}」")),
                },
                Ok(other) => Cmd::TrashWriteDone {
                    err: Some(format!("Restore 回應形態不符：{other:?}")),
                    notify: None,
                },
                Err(e) => Cmd::TrashWriteDone {
                    err: Some(e.display()),
                    notify: None,
                },
            });
        }
        Cmd::AskPurge(id) => {
            let name = item_name(core, id);
            core.confirm.set(Some(Arc::new(Confirm {
                title: format!("永久刪除「{name}」？"),
                description: "只清本機：鏡像列、關聯與該項未推送的 outbox 列一併移除，不再發伺服器請求。".into(),
                confirm_label: "永久刪除".into(),
                destructive: true,
                on_confirm: Cmd::PurgeNow(id),
            })));
        }
        Cmd::PurgeNow(id) => {
            core.ipc(move |s| match s.call(&Call::Vault(VaultCall::Purge { id })) {
                Ok(Response::Ok) => Cmd::TrashWriteDone {
                    err: None,
                    notify: Some("已永久刪除".into()),
                },
                Ok(other) => Cmd::TrashWriteDone {
                    err: Some(format!("Purge 回應形態不符：{other:?}")),
                    notify: None,
                },
                Err(e) => Cmd::TrashWriteDone {
                    err: Some(e.display()),
                    notify: None,
                },
            });
        }
        Cmd::TrashWriteDone { err, notify } => {
            core.settle();
            if let Some(e) = err {
                core.error_text.set(Some(e));
                return;
            }
            core.error_text.set(None);
            core.notice.set(notify);
            core.leave_detail();
            core.route.set(Route::List);
            fetch_list(core);
        }
        Cmd::AskExport => {
            core.confirm.set(Some(Arc::new(Confirm {
                title: "未加密匯出".into(),
                description: "每筆密碼將以明文經 Get(Reveal) 取回並寫入 ~/Downloads 的 JSON 檔案；檔案未加密，請自行保管與清除。".into(),
                confirm_label: "匯出".into(),
                destructive: false,
                on_confirm: Cmd::RunExport,
            })));
        }
        Cmd::OpenImport => {
            core.import_path.set(String::new());
            core.import_preview.set(None);
            core.import_modal.set(true);
        }
        Cmd::CloseImport => {
            core.import_modal.set(false);
            core.import_path.set(String::new());
            core.import_preview.set(None);
        }
        Cmd::ImportPreview => {
            let path = core.import_path.get();
            core.ipc(move |s| {
                let _ = s;
                Cmd::ImportPreviewed(match crate::import::read_text(&path) {
                    Err(e) => Err(e),
                    Ok(text) => crate::import::parse(&text)
                        .map(|p| (p.rows.len(), p.skipped)),
                })
            });
        }
        Cmd::ImportPreviewed(res) => {
            core.settle();
            core.import_preview.set(Some(res));
        }
        Cmd::ImportRun => {
            let path = core.import_path.get();
            core.ipc(move |s| Cmd::ImportDone(crate::import::read_text(&path).and_then(|text| {
                crate::import::run(&s, &text)
            })));
        }
        Cmd::ImportDone(res) => {
            core.settle();
            core.import_modal.set(false);
            match res {
                Ok(out) => {
                    if let Some(r) = &out.reason {
                        core.error_text.set(Some(format!("匯入拒收：{r}")));
                    } else {
                        core.error_text.set(None);
                    }
                    core.notice.set(Some(format!(
                        "已匯入 {} 筆（跳過 {}、失敗 {}）",
                        out.created, out.skipped, out.failed
                    )));
                    fetch_list(core);
                }
                Err(e) => core.error_text.set(Some(format!("匯入失敗：{e}"))),
            }
        }
        Cmd::UploadAttachment { item_id, path } => {
                if core.att_state.get().busy() {
                return;
            }
    core.att_state.update(|s| { s.start(crate::attach::AttOp::Upload); });
            core.ipc(move |s| {
                let res = crate::attach::read_for_upload(&path).and_then(|(name, bytes)| {
                    match s.call(&Call::Vault(VaultCall::Attachment {
                        sub: AttachmentOp::Upload {
                            item_id,
                            file_name: name.clone(),
                            bytes,
                        },
                    })) {
                        Ok(Response::Ok) => {
                            Ok(format!("已排隊上傳「{name}」（背景推送後入列，掛未同步）"))
                        }
                        Ok(other) => Err(format!("Attachment.Upload 回應形態不符：{other:?}")),
                        Err(e) => Err(e.display()),
                    }
                });
                Cmd::AttachmentDone {
                    item_id,
                    op: crate::attach::AttOp::Upload,
                    res,
                }
            });
        }
        Cmd::DownloadAttachment {
            item_id,
            attachment_id,
            file_name,
        } => {
                if core.att_state.get().busy() {
                return;
            }
    core.att_state.update(|s| { s.start(crate::attach::AttOp::Download); });
            core.ipc(move |s| {
                let res = match s.call(&Call::Vault(VaultCall::Attachment {
                    sub: AttachmentOp::Download {
                        item_id,
                        attachment_id,
                    },
                })) {
                    Ok(Response::AttachmentBytes(b)) => {
                        crate::attach::write_download(&file_name, &b)
                    }
                    Ok(other) => Err(format!("Attachment.Download 回應形態不符：{other:?}")),
                    Err(e) => Err(e.display()),
                };
                Cmd::AttachmentDone {
                    item_id,
                    op: crate::attach::AttOp::Download,
                    res: res.map(|p| format!("附件已下載至 {p}")),
                }
            });
        }
        Cmd::AskDeleteAttachment {
            item_id,
            attachment_id,
            file_name,
        } => {
            core.confirm.set(Some(Arc::new(Confirm {
                title: format!("刪除附件「{file_name}」？"),
                description: "從伺服器與本機鏡像移除；需連網，無離線佇列，不可復原。".into(),
                confirm_label: "刪除附件".into(),
                destructive: true,
                on_confirm: Cmd::DeleteAttachment {
                    item_id,
                    attachment_id,
                },
            })));
        }
        Cmd::DeleteAttachment {
            item_id,
            attachment_id,
        } => {
                if core.att_state.get().busy() {
                return;
            }
    core.att_state.update(|s| { s.start(crate::attach::AttOp::Delete); });
            core.ipc(move |s| {
                let res = match s.call(&Call::Vault(VaultCall::Attachment {
                    sub: AttachmentOp::Delete {
                        item_id,
                        attachment_id,
                    },
                })) {
                    Ok(Response::Ok) => Ok("附件已刪除".to_owned()),
                    Ok(other) => Err(format!("Attachment.Delete 回應形態不符：{other:?}")),
                    Err(e) => Err(e.display()),
                };
                Cmd::AttachmentDone {
                    item_id,
                    op: crate::attach::AttOp::Delete,
                    res,
                }
            });
        }
        Cmd::AttachmentDone { item_id, op, res } => {
            core.settle();
            core.att_state.update(|s| s.finish());
            match res {
                Ok(msg) => {
                    core.error_text.set(None);
                    core.notice.set(Some(msg));
                    // 上傳/刪除後重取詳情投影（附件列增減要落地到 UI）；
                    // 下載只動磁碟，不觸發重取。
                    if op != crate::attach::AttOp::Download {
                        core.send(Cmd::OpenDetail(item_id));
                    }
                }
                Err(e) => core.error_text.set(Some(e)),
            }
        }
        Cmd::EventsRefresh => {
            fetch_list(core);
            if let Route::Detail(id) = core.route.get() {
                core.ipc(move |s| match s.call(&get(id, View::Masked)) {
                    Ok(Response::Item(Some(row))) => Cmd::DetailRefreshed {
                        id,
                        row: Some(Arc::new(*row)),
                    },
                    _ => Cmd::DetailRefreshed { id, row: None },
                });
            }
        }
        Cmd::DetailRefreshed { id, row } => {
            core.settle();
            if core.route.get() == Route::Detail(id)
                && let Some(row) = row
            {
                core.detail.set(Some(row));
            }
        }
        Cmd::SetTheme(mode) => {
            core.theme_mode.set(mode);
            crate::save_theme_mode(mode);
        }
        Cmd::OpenApprovals => {
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::Approvals);
            core.send(Cmd::FetchPending);
        }
        Cmd::OpenSettings => {
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::Settings);
            core.send(Cmd::FetchSettings);
        }
        Cmd::FetchSettings => {
            core.ipc(|s| match s.call(&Call::Admin(AdminCall::GetSettings)) {
                Ok(Response::Settings(v)) => Cmd::SettingsLoaded(v),
                Ok(other) => Cmd::Failed {
                    err: format!("GetSettings 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::SettingsLoaded(v) => {
            core.settle();
            core.settings.set(v);
        }
        Cmd::OpenReports => {
            core.leave_detail();
            core.sort_menu.set(false);
            core.route.set(Route::Reports);
            core.reports_tab.set(ReportsTab::Cards);
            core.send(Cmd::FetchReuse);
            core.send(Cmd::FetchWeak);
        }
        Cmd::ShowReportsTab(tab) => {
            core.reports_tab.set(tab);
        }
        Cmd::FetchReuse => {
            // 重用掃描需金鑰（daemon 端 with_keys）：鎖定態回錯屬正常缺席，
            // 走 quiet 不閃橫條（卡面以「需解鎖」佔位語意呈現）。
            core.ipc_quiet(|s| match s.call(&Call::Vault(VaultCall::Reports {
                sub: bw_proto::Reports::PasswordReuse,
            })) {
                Ok(Response::DupGroups(g)) => Cmd::ReuseLoaded(Arc::new(g)),
                _ => Cmd::ReuseLoaded(Arc::new(Vec::new())),
            });
        }
        Cmd::FetchWeak => {
            core.ipc_quiet(|s| match s.call(&Call::Vault(VaultCall::Reports {
                sub: bw_proto::Reports::WeakPasswords,
            })) {
                Ok(Response::Json(v)) => Cmd::WeakLoaded(Arc::new(v)),
                _ => Cmd::WeakLoaded(Arc::new(serde_json::json!({
                    "threshold": bw_proto::WEAK_PASSWORD_THRESHOLD, "items": []
                }))),
            });
        }
        Cmd::ReuseLoaded(g) => {
            core.settle();
            core.reports_reuse.set(g);
        }
        Cmd::WeakLoaded(v) => {
            core.settle();
            core.reports_weak.set(v);
        }
        Cmd::FetchHistory(id) => {
            // 代理伺服器端點：離線／路由缺席都回 supported:false 形態；
            // 傳輸級失敗靜默（歷史是詳情頁配角，不搶錯誤橫條）。
            core.ipc_quiet(move |s| match s.call(&Call::Vault(VaultCall::Reports {
                sub: bw_proto::Reports::CipherHistory { id },
            })) {
                Ok(Response::Json(v)) => Cmd::HistoryLoaded {
                    item: id,
                    report: Arc::new(v),
                },
                _ => Cmd::HistoryLoaded {
                    item: id,
                    report: Arc::new(serde_json::json!({"supported": false, "versions": []})),
                },
            });
        }
        Cmd::HistoryLoaded { item, report } => {
            if matches!(core.route.get(), Route::Detail(i) | Route::Edit(i) if i == item) {
                core.history.set(report);
            }
        }
        Cmd::RefreshStatus => {
            core.ipc_quiet(|s| match s.call(&Call::Sync(SyncCall::Status)) {
                Ok(Response::Status(info)) => Cmd::StateUpdated {
                    state: info.state,
                    refetch: true,
                    reauth: info.needs_reauth,
                    email: info.email,
                    server: info.server,
                },
                _ => Cmd::Nop,
            });
        }
        Cmd::ApplySettings(next) => {
            // 改即存：整包回寫（四欄全量 PUT 語意，無部分更新競態面）。
            core.ipc(move |s| match s.call(&Call::Admin(AdminCall::SetSettings(next))) {
                Ok(Response::Ok) => Cmd::SettingsSaved(Ok(())),
                Ok(other) => Cmd::SettingsSaved(Err(format!("SetSettings 回應形態不符：{other:?}"))),
                Err(e) => Cmd::SettingsSaved(Err(e.display())),
            });
        }
        Cmd::SettingsSaved(res) => {
            core.settle();
            match res {
                Ok(()) => {
                    core.notice.set(Some("設定已儲存".into()));
                    core.send(Cmd::FetchSettings);
                }
                Err(e) => core.error_text.set(Some(e)),
            }
        }
        Cmd::FetchPasskeys(id) => {
            // rp_id=None 取全庫再按 item 過濾（列表本就是全庫投影）；鎖定態
            // daemon 回 Locked——輪詢類失敗靜默（詳情不因此閃橫條）。
            core.ipc_quiet(move |s| match s.call(&Call::Passkey(PasskeyCall::GetPasskeys { rp_id: None })) {
                Ok(Response::Passkeys(rows)) => Cmd::PasskeysLoaded {
                    item: id,
                    entries: Arc::new(rows.into_iter().filter(|e| e.item_id == Some(id)).collect()),
                },
                _ => Cmd::PasskeysLoaded {
                    item: id,
                    entries: Arc::new(Vec::new()),
                },
            });
        }
        Cmd::PasskeysLoaded { item, entries } => {
            if matches!(core.route.get(), Route::Detail(i) | Route::Edit(i) if i == item) {
                core.passkeys.set(entries);
            }
        }
        Cmd::AskDeletePasskey {
            item,
            credential,
            rp,
            user,
        } => {
            core.confirm.set(Some(Arc::new(Confirm {
                title: "刪除此 Passkey？".into(),
                description: format!("網站：{rp}\n使用者：{user}\n刪除後該網站將無法用這組金鑰登入，且變更會同步到伺服器。"),
                confirm_label: "刪除 Passkey".into(),
                destructive: true,
                on_confirm: Cmd::DeletePasskey { item, credential },
            })));
        }
        Cmd::DeletePasskey { item, credential } => {
            core.ipc(move |s| {
                match s.call(&Call::Passkey(PasskeyCall::DeletePasskey {
                    item_id: item,
                    credential_id: credential,
                })) {
                    Ok(Response::Ok) => Cmd::PasskeyDeleted(Ok(())),
                    Ok(other) => Cmd::PasskeyDeleted(Err(format!(
                        "DeletePasskey 回應形態不符：{other:?}"
                    ))),
                    Err(e) => Cmd::PasskeyDeleted(Err(e.display())),
                }
            });
        }
        Cmd::PasskeyDeleted(res) => {
            core.settle();
            match res {
                Ok(()) => {
                    core.notice.set(Some("Passkey 已刪除".into()));
                    if let Route::Detail(id) = core.route.get() {
                        core.send(Cmd::FetchPasskeys(id));
                    }
                }
                Err(e) => core.error_text.set(Some(e)),
            }
        }
        Cmd::FetchPending => {
            core.ipc_quiet(|s| match s.call(&Call::Agent(AgentCall::ListPending)) {
                Ok(Response::Sessions(rows)) => Cmd::PendingLoaded(Arc::new(parse_pending(&rows))),
                // 輪詢失敗靜默（下一拍重試；連線死因已由其他路徑顯式報）。
                _ => Cmd::PendingLoaded(Arc::new(Vec::new())),
            });
        }
        Cmd::PendingLoaded(rows) => {
            core.pending.set(rows);
        }
        Cmd::ApprovePending(id) => {
            core.ipc(move |s| {
                let res = match uuid::Uuid::parse_str(&id) {
                    Ok(uuid) => match s.call(&Call::Agent(AgentCall::Approve {
                        id: bw_proto::ApprovalId(uuid),
                        grants: None,
                    })) {
                        Ok(Response::Ok) => Ok(()),
                        Ok(other) => Err(format!("Approve 回應形態不符：{other:?}")),
                        Err(e) => Err(e.display()),
                    },
                    Err(e) => Err(format!("批准 id 非 uuid：{e}")),
                };
                Cmd::PendingActed { approve: true, res }
            });
        }
        Cmd::DenyPending(id) => {
            core.ipc(move |s| {
                let res = match uuid::Uuid::parse_str(&id) {
                    Ok(uuid) => match s.call(&Call::Agent(AgentCall::Deny {
                        id: bw_proto::ApprovalId(uuid),
                    })) {
                        Ok(Response::Ok) => Ok(()),
                        Ok(other) => Err(format!("Deny 回應形態不符：{other:?}")),
                        Err(e) => Err(e.display()),
                    },
                    Err(e) => Err(format!("拒絕 id 非 uuid：{e}")),
                };
                Cmd::PendingActed { approve: false, res }
            });
        }
        Cmd::PendingActed { approve, res } => {
            core.settle();
            match res {
                Ok(()) => {
                    core.error_text.set(None);
                    core.notice.set(Some(if approve { "已批准請求" } else { "已拒絕請求" }.into()));
                    core.send(Cmd::FetchPending);
                    // 批准可能放行了被擋的鏡像寫入，列表順勢重抓。
                    fetch_list(core);
                }
                Err(e) => core.error_text.set(Some(e)),
            }
        }
        Cmd::ConfirmYes => {
            let Some(c) = core.confirm.get() else {
                return;
            };
            let next = c.on_confirm.clone();
            core.confirm.set(None);
            reduce(core, next);
        }
        Cmd::ConfirmNo => core.confirm.set(None),
        Cmd::SubmitForm => submit_form(core),
        Cmd::DeleteNow(id) => {
            core.ipc(
                move |s| match s.call(&Call::Vault(VaultCall::Delete { ids: vec![id] })) {
                    Ok(Response::Ok) => Cmd::WriteDone {
                        err: None,
                        follow: Follow::List,
                    },
                    Ok(other) => Cmd::WriteDone {
                        err: Some(format!("Delete 回應形態不符：{other:?}")),
                        follow: Follow::List,
                    },
                    Err(e) => Cmd::WriteDone {
                        err: Some(e.display()),
                        follow: Follow::List,
                    },
                },
            );
        }
        Cmd::WriteDone { err, follow } => {
            core.settle();
            if let Some(e) = err {
                core.error_text.set(Some(e));
            } else {
                core.error_text.set(None);
            }
            match follow {
                Follow::List => {
                    core.leave_detail();
                    core.route.set(Route::List);
                    fetch_list(core);
                }
                Follow::Detail(id) => {
                    // 寫入成功＝編輯狀態正式落幕：導航跳過髒閘一次
                    // （表單訊號尚未重置，走普通 OpenDetail 會被自己攔下）。
                    core.send(Cmd::NavForced(Box::new(Cmd::OpenDetail(id))));
                    fetch_list(core);
                }
            }
        }
        Cmd::RunExport => {
            core.ipc(|s| match export::run(&s) {
                Ok(out) => Cmd::ExportDone(Ok(out)),
                Err(e) => Cmd::ExportDone(Err(e)),
            });
        }
        Cmd::ExportDone(res) => {
            core.settle();
            match res {
                Ok(out) => core.notice.set(Some(format!(
                    "已匯出 {} 筆（未加密）→ {}",
                    out.count,
                    out.path.display()
                ))),
                Err(e) => core.error_text.set(Some(format!("匯出失敗：{e}"))),
            }
        }
        Cmd::Failed { err } => {
            core.settle();
            core.error_text.set(Some(err));
        }
    }
}

pub fn get(id: ItemId, view: View) -> Call {
    Call::Vault(VaultCall::Get { id, view })
}

/// 垃圾桶模式 → `Query.deleted` 三態：true＝只列軟刪；false＝現行預設（None）。
/// 過濾語意在 daemon（store.query），這裡只做意圖映射（純函數，可單測）。
pub fn deleted_filter(trash: bool) -> Option<bool> {
    trash.then_some(true)
}

/// 確認框用的項目名稱：不在目前清單時退回泛稱。
fn item_name(core: &AppCore, id: ItemId) -> String {
    core.items
        .get()
        .iter()
        .find(|v| v.meta.id == id)
        .and_then(|v| v.meta.name.clone())
        .unwrap_or_else(|| "這個項目".to_owned())
}

/// 列表重抓：text/tag/sort 原樣送 daemon（過濾分級語意零複製到 GUI）。
pub fn fetch_list(core: &AppCore) {
    let seq = core.list_gen.get() + 1;
    core.list_gen.set(seq);
    let filter = core.filter.get();
    let q = Query {
        text: nonblank(&core.query.get()),
        tag: core.tag.get(),
        sort: core.sort.get(),
        limit: 0,
        deleted: deleted_filter(filter.trash),
        archived: archived_filter(filter.archived),
        folder: filter.folder.clone(),
        ..Default::default()
    };
    core.ipc(move |s| {
        match s.call(&Call::Vault(VaultCall::List {
            query: q,
            view: View::Metadata,
        })) {
            Ok(Response::Items(rows)) => Cmd::ListLoaded {
                seq,
                rows: Arc::new(rows),
            },
            Ok(other) => Cmd::Failed {
                err: format!("List 回應形態不符：{other:?}"),
            },
            Err(e) => Cmd::Failed { err: e.display() },
        }
    });
}

/// 批次 C favicon：為清單主 uri host 补缺失圖示（單飛＝先插 Loading 再發
/// `GetIcon`；同 host 併發只一條在途）。失敗/未知形態→字母磚（IconState::Failed）。
pub fn request_icons(core: &AppCore) {
    let hosts: Vec<String> = core
        .items
        .get()
        .iter()
        .filter_map(|v| v.meta.uris.first().and_then(|u| host_of(u)))
        .collect();
    request_hosts(core, hosts);
}

fn request_hosts(core: &AppCore, hosts: Vec<String>) {
    let mut missing: Vec<String> = Vec::new();
    core.icons.update(|m| {
        let map = Arc::make_mut(m);
        for h in hosts {
            if !map.contains_key(&h) {
                map.insert(h.clone(), IconState::Loading);
                missing.push(h);
            }
        }
    });
    for host in missing {
        // 走 icon 專用連線：daemon 代理抓外站是秒級延遲，絕不佔互動 session。
        let session = core.icon_session.clone();
        let tx = core.tx.clone();
        std::thread::spawn(move || {
            let cmd = match session.call(&Call::Vault(VaultCall::GetIcon { host: host.clone() })) {
                Ok(Response::AttachmentBytes(b)) => Cmd::IconLoaded { host, res: Ok(b) },
                Ok(other) => Cmd::IconLoaded {
                    host,
                    res: Err(format!("GetIcon 回應形態不符：{other:?}")),
                },
                Err(e) => Cmd::IconLoaded { host, res: Err(e.display()) },
            };
            let _ = tx.send(cmd);
        });
    }
}

/// 快取查閱：僅 Ready 回 data URI（Loading/Failed/缺席＝字母磚退路）。
pub fn icon_ready(core: &AppCore, host: &str) -> Option<String> {
    match core.icons.get().get(host) {
        Some(IconState::Ready(uri)) => Some(uri.clone()),
        _ => None,
    }
}

/// 表單送出：Create 走 CipherDraft，Edit 走欄位 diff（FieldEdit）；
/// tags 是本地 overlay（協定無此欄位，契約 §2.1），一律換成 AddTag/RemoveTag。
fn submit_form(core: &AppCore) {
    let route = core.route.get();
    let name = core.form.name.get().trim().to_owned();
    if name.is_empty() {
        core.form.error.set(Some("名稱不可為空白".into()));
        return;
    }
    core.form.error.set(None);
    let username = nonblank(&core.form.username.get());
    let password = nonblank(&core.form.password.get());
    let uri_rows = core.form.uris.get();
    let tags = parse_tags(&core.form.tags.get());
    let kind = core.form.kind.get();
    let folder_id = nonblank(&core.form.folder_id.get());
    let notes = nonblank(&core.form.notes.get());
    let drafts = core.form.fields.get();
    match route {
        Route::Create => {
            let fields: Vec<bw_proto::CipherField> = drafts
                .iter()
                .filter(|f| !f.name.trim().is_empty() || !f.value.trim().is_empty())
                .map(|f| bw_proto::CipherField {
                    name: f.name.trim().to_owned(),
                    value: if f.kind == CipherFieldKind::Boolean {
                        Some(if f.bool_value() { "true" } else { "false" }.to_owned())
                    } else {
                        nonblank(&f.value)
                    },
                    kind: f.kind,
                })
                .collect();
            core.ipc(move |s| {
                // Zeroize 點 ①：表單明文以 `Zeroizing` 持有，序列化進
                // Outgoing 幀（加密在 daemon 的 with_keys 閉包）後本地即出棧清零；
                // draft 內的最後一份拷貝隨幀寫出銷毀——GUI 不落地、不緩存。
                let password = password.map(zeroize::Zeroizing::new);
                let draft = CipherDraft {
                    kind,
                    name: name.clone(),
                    username,
                    password: password.as_deref().map(|p| p.to_string()),
                    totp: None,
                    uris: uri_rows
                        .iter()
                        .filter_map(|u| nonblank(u.uri.trim()))
                        .collect(),
                    // 建立面判定下拉：與 uris 平行（同樣 filter_map 掉空列）；
                    // None 列＝官方預設 null。
                    uri_matches: uri_rows
                        .iter()
                        .filter(|u| nonblank(u.uri.trim()).is_some())
                        .map(|u| u.match_type)
                        .collect(),
                    notes,
                    favorite: false,
                    folder_id,
                    fields,
                };
                let err = match s.call(&Call::Vault(VaultCall::Create { draft })) {
                    Ok(Response::Ok) => {
                        // daemon 的 Create 不回 id（Response::Ok）：tags 需要
                        // 剛建立項目的 id，以名稱精確查回（本機索引已回填）。
                        match find_created(&s, &name) {
                            Some(id) => apply_tags(&s, id, &[], &tags),
                            None if tags.is_empty() => None,
                            None => Some("已建立，但找不到項目以套用標籤".into()),
                        }
                    }
                    Ok(other) => Some(format!("Create 回應形態不符：{other:?}")),
                    Err(e) => Some(e.display()),
                };
                Cmd::WriteDone {
                    err,
                    follow: Follow::List,
                }
            });
        }
        Route::Edit(id) => {
            let Some(orig) = core.form.original.get() else {
                core.form.error.set(Some("尚未載入完成，請稍後再試".into()));
                return;
            };
            // 差異集全在 edit_delta（與髒閘共用單一真相源，紀律 1 零複製）。
            let input = FormInput {
                name: &name,
                username,
                password,
                uris: &uri_rows,
                notes,
                folder_id,
                tags: &tags,
                drafts: &drafts,
            };
            let (leaf, field_struct, match_tail, add, remove) = edit_delta(&orig, &input);
            if leaf.is_empty()
                && field_struct.is_empty()
                && match_tail.is_empty()
                && add.is_empty()
                && remove.is_empty()
            {
                core.send(Cmd::ShowDetailView(id));
                return;
            }
            core.ipc(move |s| {
                let mut err: Option<String> = None;
                // 三批 Patch：先 leaf 值（含 field.<n>.name/value 與 uri 值/既有列判定），
                // 再結構（SetType/增刪欄與 uri 列；分批避開同欄 type×值衝突），
                // 最後新列判定（索引域＝結構批落地後；daemon 鏡像入列即更新）。
                for batch in [leaf, field_struct, match_tail] {
                    if batch.is_empty() || err.is_some() {
                        continue;
                    }
                    // Zeroize 點 ②：edits 內的明文在此序列化進 Outgoing 幀，
                    // 呼叫結束即出棧；GUI 端不留常駐明文。
                    match s.call(&Call::Vault(VaultCall::Patch {
                        id,
                        edits: batch,
                    })) {
                        Ok(Response::Ok) => {}
                        Ok(other) => err = Some(format!("Patch 回應形態不符：{other:?}")),
                        Err(e) => err = Some(e.display()),
                    }
                }
                if err.is_none() && !(add.is_empty() && remove.is_empty()) {
                    err = apply_tags(&s, id, &remove, &add);
                }
                Cmd::WriteDone {
                    err,
                    follow: Follow::Detail(id),
                }
            });
        }
        _ => {
            core.form.error.set(Some("目前頁面不是表單".into()));
        }
    }
}

/// 逐筆套 overlay 標籤；回傳第一個錯誤（若有）。
pub(crate) fn apply_tags(s: &Session, id: ItemId, remove: &[String], add: &[String]) -> Option<String> {
    for t in remove {
        if let Err(e) = s.call(&Call::Vault(VaultCall::Overlay {
            id,
            op: OverlayOpWire::RemoveTag(t.clone()),
        })) {
            return Some(e.display());
        }
    }
    for t in add {
        if let Err(e) = s.call(&Call::Vault(VaultCall::Overlay {
            id,
            op: OverlayOpWire::AddTag(t.clone()),
        })) {
            return Some(e.display());
        }
    }
    None
}

/// Create 不回 id 的代償：用明文名稱查回剛建立的項目。
/// 候選取「名字完全相符且無 updated_at（尚未推過伺服器）」者。
pub(crate) fn find_created(s: &Session, name: &str) -> Option<ItemId> {
    let q = Query {
        text: Some(name.to_owned()),
        limit: 0,
        ..Default::default()
    };
    let rows = s
        .call(&Call::Vault(VaultCall::List {
            query: q,
            view: View::Metadata,
        }))
        .ok()?;
    let Response::Items(items) = rows else {
        return None;
    };
    let mut exact: Vec<ItemId> = items
        .into_iter()
        .filter(|v| v.meta.name.as_deref() == Some(name) && v.meta.updated_at.is_none())
        .map(|v| v.meta.id)
        .collect();
    if exact.len() == 1 { exact.pop() } else { None }
}

/// 逗號/分號/空白分隔的標籤輸入 → 去重有序清單。
pub fn parse_tags(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split([',', '，', ';', '；', '\n']) {
        let t = part.trim();
        if !t.is_empty() && !out.iter().any(|x| x == t) {
            out.push(t.to_owned());
        }
    }
    out
}

/// 標籤集合差異：(要新增, 要移除)。
pub fn diff_tags(orig: &[String], now: &[String]) -> (Vec<String>, Vec<String>) {
    let add = now
        .iter()
        .filter(|t| !orig.iter().any(|o| o == *t))
        .cloned()
        .collect();
    let remove = orig
        .iter()
        .filter(|t| !now.iter().any(|o| o == *t))
        .cloned()
        .collect();
    (add, remove)
}

pub fn nonblank(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// ListFolders 的 `Response::Json` 陣列 → 鏡像列（缺 id 的列跳過；
/// name null＝鎖定態信封解不了，呼叫端決定隱藏節點）。純函數可單測。
pub fn parse_folders(v: &serde_json::Value) -> Vec<FolderEntry> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|row| {
                    let id = row.get("id").and_then(|i| i.as_str())?.to_owned();
                    let name = row.get("name").and_then(|n| n.as_str()).map(str::to_owned);
                    Some(FolderEntry { id, name })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `Response::Sessions`（ListPending 行）→ 佇列列；缺 id 跳過。
/// `requested_at_ms` 為 daemon 後補欄位，缺席＝None（UI 不虛構時間）。
pub fn parse_pending(rows: &[serde_json::Value]) -> Vec<PendingRow> {
    rows.iter()
        .filter_map(|row| {
            let id = row.get("id").and_then(|i| i.as_str())?.to_owned();
            Some(PendingRow {
                id,
                summary: row
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                requested_at_ms: row.get("requested_at_ms").and_then(|t| t.as_u64()),
            })
        })
        .collect()
}

/// 多網址 diff（純函數，可單測）：回 (值批, 結構批, 新列判定批)。列身份按
/// `key` 對齊基準索引（同 `field_edits` 手法，刪列不錯位）：基準列改值→
/// `uri.<n>` Set；基準列改判定→`SetUriMatch`（基準索引，leaf 批先於結構批）；
/// 基準列消失→`RemoveUri`（索引由大而小，免位移）；新列（key 不在基準）→
/// `AppendUri`（空白列跳過，daemon 同拒）落結構批；新列帶非預設判定→
/// `SetUriMatch` 進第三批（索引＝基準數−刪除數＋附加序，結構批落地後才有效，
/// daemon 鏡像入列即更新故第二發 Patch 直接可用）。
pub fn uri_edits(
    orig: &[String],
    orig_matches: &[Option<u8>],
    rows: &[UriDraft],
) -> (Vec<FieldEdit>, Vec<FieldEdit>, Vec<FieldEdit>) {
    let present: std::collections::HashSet<u32> =
        rows.iter().map(|r| r.key).filter(|k| (*k as usize) < orig.len()).collect();
    let mut sets = Vec::new();
    let mut appends = Vec::new();
    let mut match_tail = Vec::new();
    for r in rows {
        let now = nonblank(r.uri.trim());
        if let Some(base) = orig.get(r.key as usize).filter(|_| (r.key as usize) < orig.len()) {
            if now.as_deref() != Some(base.as_str()) {
                sets.push(FieldEdit::Set {
                    path: format!("uri.{}", r.key),
                    value: now,
                });
            }
            if r.match_type != orig_matches.get(r.key as usize).copied().flatten() {
                sets.push(FieldEdit::SetUriMatch {
                    index: r.key,
                    match_type: r.match_type,
                });
            }
        } else if now.is_some() {
            appends.push(FieldEdit::AppendUri {
                uri: r.uri.trim().to_owned(),
            });
        }
    }
    let mut removes: Vec<u32> = (0..orig.len() as u32)
        .filter(|i| !present.contains(i))
        .collect();
    removes.sort_by(|a, b| b.cmp(a));
    let mut structural: Vec<FieldEdit> = removes
        .iter()
        .map(|index| FieldEdit::RemoveUri { index: *index })
        .collect();
    // 新列判定批：附加序 k 的落地索引＝基準數−刪除數＋k（AppendUri 依序落尾）。
    let mut append_i = 0usize;
    for r in rows {
        let now = nonblank(r.uri.trim());
        if now.is_some() && (r.key as usize) >= orig.len() {
            if let Some(m) = r.match_type {
                match_tail.push(FieldEdit::SetUriMatch {
                    index: (orig.len() - removes.len() + append_i) as u32,
                    match_type: Some(m),
                });
            }
            append_i += 1;
        }
    }
    structural.extend(appends);
    (sets, structural, match_tail)
}

/// 表單現值（`edit_delta`／`form_is_dirty` 統一輸入形態；正規化在呼叫端）。
pub struct FormInput<'a> {
    pub name: &'a str,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: &'a [UriDraft],
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: &'a [String],
    pub drafts: &'a [FieldDraft],
}

/// `edit_delta` 的五元組返回：leaf 值批、結構批、新列判定批、標籤增、標籤刪。
pub type EditDelta = (
    Vec<FieldEdit>,
    Vec<FieldEdit>,
    Vec<FieldEdit>,
    Vec<String>,
    Vec<String>,
);

/// 編輯表單的完整差異集（提交與髒閘的單一真相源，紀律 1 零複製）：
/// leaf 值批、結構批、新列判定批（結構批落地後補發）、標籤增/刪。
/// 密碼語意沿用編輯規則——空值＝不動基準。
pub fn edit_delta(orig: &FormOriginal, f: &FormInput<'_>) -> EditDelta {
    let mut leaf: Vec<FieldEdit> = Vec::new();
    if f.name != orig.name {
        leaf.push(FieldEdit::Set {
            path: "name".into(),
            value: Some(f.name.to_owned()),
        });
    }
    if f.username != orig.username {
        leaf.push(FieldEdit::Set {
            path: "username".into(),
            value: f.username.clone(),
        });
    }
    if f.password.is_some() {
        leaf.push(FieldEdit::Set {
            path: "password".into(),
            value: f.password.clone(),
        });
    }
    // 多網址（批次 A＃1＋C）：值改與既有列判定改併入 leaf 批；增刪列走結構批
    // （RemoveUri 遞減＋AppendUri 落尾，892c15b 面）；新列判定第三批改索引域。
    let (u_sets, u_struct, u_match_tail) = uri_edits(&orig.uris, &orig.uri_matches, f.uris);
    leaf.extend(u_sets);
    if f.notes != orig.notes {
        leaf.push(FieldEdit::Set {
            path: "notes".into(),
            value: f.notes.clone(),
        });
    }
    if f.folder_id != orig.folder_id {
        leaf.push(FieldEdit::Set {
            path: "folderId".into(),
            value: f.folder_id.clone(),
        });
    }
    // 自訂欄位：key 對齊做 diff，拆成 leaf（Set）與結構（SetType/
    // Append/Remove）兩批——同欄 type×值改動會被 daemon 判同欄衝突，
    // 分兩批送即迴避（先值後結構）。
    let (field_leaf, mut field_struct) = field_edits(&orig.fields, f.drafts);
    leaf.extend(field_leaf);
    field_struct.extend(u_struct);
    let (add, remove) = diff_tags(&orig.tags, f.tags);
    (leaf, field_struct, u_match_tail, add, remove)
}

/// 表單是否「髒」（純函數，單測點）：正規化與 `submit_form` 完全一致
/// （trim／nonblank／parse_tags），空白抖動不误報；有基準走 edit_delta
/// 空判，無基準（新增）＝任一輸入非空／切過型別／有非空欄位行。
#[allow(clippy::too_many_arguments)]
pub fn form_is_dirty(
    orig: Option<&FormOriginal>,
    name: &str,
    username: &str,
    password: &str,
    uris: &[UriDraft],
    tags: &str,
    notes: &str,
    folder_id: &str,
    kind: ItemKind,
    drafts: &[FieldDraft],
) -> bool {
    let name = name.trim().to_owned();
    let username = nonblank(username);
    let password = nonblank(password);
    let tag_list = parse_tags(tags);
    let notes = nonblank(notes);
    let folder = nonblank(folder_id);
    match orig {
        Some(o) => {
            let input = FormInput {
                name: &name,
                username,
                password,
                uris,
                notes,
                folder_id: folder,
                tags: &tag_list,
                drafts,
            };
            let (leaf, field_struct, match_tail, add, remove) = edit_delta(o, &input);
            !(leaf.is_empty()
                && field_struct.is_empty()
                && match_tail.is_empty()
                && add.is_empty()
                && remove.is_empty())
        }
        None => {
            !name.is_empty()
                || username.is_some()
                || password.is_some()
                || notes.is_some()
                || folder.is_some()
                || !tag_list.is_empty()
                || kind != ItemKind::Login
                || uris.iter().any(|u| nonblank(u.uri.trim()).is_some())
                || drafts
                    .iter()
                    .any(|f| !f.name.trim().is_empty() || !f.value.trim().is_empty())
        }
    }
}

/// 讀訊號版髒判定（reduce 閘與 RequestCloseForm 共用）。
pub fn form_dirty(core: &AppCore) -> bool {
    form_is_dirty(
        core.form.original.get().as_deref(),
        &core.form.name.get(),
        &core.form.username.get(),
        &core.form.password.get(),
        &core.form.uris.get(),
        &core.form.tags.get(),
        &core.form.notes.get(),
        &core.form.folder_id.get(),
        core.form.kind.get(),
        &core.form.fields.get(),
    )
}

/// 會打斷編輯器的導航命令（髒閘攔截清單）；編輯器自身命令與
/// 背景回包不列入（那些是編輯流程的一部分）。
fn nav_interrupts(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::OpenList
            | Cmd::OpenDetail(_)
            | Cmd::OpenCreate
            | Cmd::OpenEdit(_)
            | Cmd::OpenApprovals
            | Cmd::OpenSettings
            | Cmd::ShowDetailView(_)
            | Cmd::ChooseFolder(_)
            | Cmd::ToggleTrash
            | Cmd::ToggleArchived
    )
}

/// 自訂欄位 diff（純函數，可單測）：以 `key` 對齊基準／現況，回
/// `(leaf, structural)` 兩批。leaf＝`field.<i>.name/value`（i 為基準陣列
/// 位置）；structural＝SetType（基準位置）→ RemoveField（基準位置，
/// 遞減穩定）→ AppendField（新增列，尾插、維持表單順序）。
/// 分兩批是為了迴避 daemon「同欄 type×值」同欄衝突判定。
pub fn field_edits(
    orig: &[FieldDraft],
    cur: &[FieldDraft],
) -> (Vec<FieldEdit>, Vec<FieldEdit>) {
    let mut leaf = Vec::new();
    let mut types = Vec::new();
    let mut removes = Vec::new();
    for (i, base) in orig.iter().enumerate() {
        match cur.iter().find(|c| c.key == base.key) {
            Some(c) => {
                if c.name != base.name {
                    leaf.push(FieldEdit::Set {
                        path: format!("field.{i}.name"),
                        value: Some(c.name.clone()),
                    });
                }
                if c.value != base.value {
                    leaf.push(FieldEdit::Set {
                        path: format!("field.{i}.value"),
                        value: if c.kind == CipherFieldKind::Boolean {
                            Some(if c.bool_value() { "true" } else { "false" }.to_owned())
                        } else {
                            nonblank(&c.value)
                        },
                    });
                }
                if c.kind != base.kind {
                    types.push(FieldEdit::SetType {
                        index: i as u32,
                        kind: c.kind,
                    });
                }
            }
            None => removes.push(FieldEdit::RemoveField { index: i as u32 }),
        }
    }
    // 遞減刪除：后面的 index 不受前面移除影響。
    removes.sort_by_key(|e| match e {
        FieldEdit::RemoveField { index } => std::cmp::Reverse(*index),
        _ => unreachable!(),
    });
    let appends: Vec<FieldEdit> = cur
        .iter()
        .filter(|c| !orig.iter().any(|o| o.key == c.key))
        .filter(|c| !c.name.trim().is_empty() || !c.value.trim().is_empty())
        .map(|c| FieldEdit::AppendField {
            field: bw_proto::CipherField {
                name: c.name.trim().to_owned(),
                value: if c.kind == CipherFieldKind::Boolean {
                    Some(if c.bool_value() { "true" } else { "false" }.to_owned())
                } else {
                    nonblank(&c.value)
                },
                kind: c.kind,
            },
        })
        .collect();
    let mut structural = types;
    structural.extend(removes);
    structural.extend(appends);
    (leaf, structural)
}

/// 鎖態的中文標籤（標題列指示器）。
pub fn vault_label(st: &UnlockStateView) -> &'static str {
    match st {
        UnlockStateView::SignedOut => "未登入",
        UnlockStateView::AuthLocked { .. } => "已鎖定",
        UnlockStateView::Unlocking => "解鎖中",
        UnlockStateView::Unlocked { .. } => "已解鎖",
        UnlockStateView::Stale { .. } => "需重新認證",
    }
}

/// 只有「已鎖定 / 需重新認證」提供解鎖鈕（未登入不在此 App 的範圍）。
pub fn can_unlock(st: &Option<UnlockStateView>) -> bool {
    matches!(
        st,
        Some(UnlockStateView::AuthLocked { .. }) | Some(UnlockStateView::Stale { .. })
    )
}

/// 「變更主密碼」只在解鎖態開放（daemon 改密需舊 user key 驗金鑰鏈，
/// 鎖定態送出必被閘下；前端直接把鈕藏掉比讓它报错誠實）。
pub fn can_change_password(st: &Option<UnlockStateView>) -> bool {
    is_unlocked(st)
}

/// 解鎖態判定（頂部列搜尋/新增鈕的顯示閘：鎖定態官方不給庫操作入口）。
pub fn is_unlocked(st: &Option<UnlockStateView>) -> bool {
    matches!(st, Some(UnlockStateView::Unlocked { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_filter_four_way_exclusion() {
        let mut f = VaultFilter::default();
        f.toggle_archived();
        assert!(f.archived && !f.trash && f.folder.is_none());
        // 已封存態選資料夾→退封存；選垃圾桶→退封存；互斥四態。
        f.pick_folder(Some("x".into()));
        assert!(!f.archived && !f.trash && f.folder.as_deref() == Some("x"));
        f.toggle_archived();
        f.toggle_trash();
        assert!(f.trash && !f.archived && f.folder.is_none());
        f.toggle_trash();
        f.toggle_trash();
        f.toggle_archived();
        assert!(f.archived && !f.trash, "退出垃圾桶不應殘留封存態交叉污染");
        assert_eq!(archived_filter(true), Some(true));
        assert_eq!(archived_filter(false), None, "主列表不發 Some(false)（舊 daemon 兼容）");
    }

    #[test]
    fn icon_sniff_and_host_parsing() {
        // magic 嗅探：PNG／ICO 收，其他形態拒（字母磚退路）。
        assert_eq!(sniff_icon(&[0x89, b'P', b'N', b'G', 0]), Some("image/png"));
        assert_eq!(sniff_icon(&[0, 0, 1, 0, 1]), Some("image/x-icon"));
        assert_eq!(sniff_icon(b"GIF89a"), None);
        assert_eq!(sniff_icon(&[0x89, b'P']), None, "截斷的 magic 不認");
        // data URI：PNG 成形、垃圾回 None。
        let uri = icon_data_uri(&[0x89, b'P', b'N', b'G', 1, 2]).unwrap();
        assert!(uri.starts_with("data:image/png;base64,"));
        assert!(icon_data_uri(b"junk").is_none());
        // host 解析：去 scheme/userinfo/port/path；無點非 localhost 拒。
        assert_eq!(host_of("https://GitHub.com/x?q=1").as_deref(), Some("github.com"));
        assert_eq!(host_of("http://user:pw@127.0.0.1:18095/api").as_deref(), Some("127.0.0.1"));
        assert_eq!(host_of("localhost:3000").as_deref(), Some("localhost"));
        assert_eq!(host_of("no-host"), None);
        assert_eq!(host_of("https:///path"), None);
    }

    #[test]
    fn normalize_server_gates_scheme_and_host() {
        // 缺 scheme 補 https、大小寫正規化、localhost/含點 host 過閘。
        assert_eq!(normalize_server("vault.example.com").unwrap(), "https://vault.example.com");
        assert_eq!(normalize_server("HTTPS://Vault.Example.com/x").unwrap(), "https://Vault.Example.com/x");
        assert_eq!(normalize_server("http://127.0.0.1:18095").unwrap(), "http://127.0.0.1:18095");
        assert_eq!(normalize_server("localhost:8080").unwrap(), "https://localhost:8080");
        // 非 http(s)、空 host、含空白、空字串全拒。
        assert!(normalize_server("ftp://x.test").is_err());
        assert!(normalize_server("https://").is_err());
        assert!(normalize_server("https://a b").is_err());
        assert!(normalize_server("   ").is_err());
    }

    #[test]
    fn validate_login_requires_email_and_password() {
        assert_eq!(
            validate_login("vault.test", " a@b.c ", "").unwrap_err(),
            "請輸入主密碼"
        );
        assert_eq!(
            validate_login("vault.test", "  ", "pw").unwrap_err(),
            "請輸入 email"
        );
        assert_eq!(validate_login("vault.test", "a@b.c", "pw").unwrap(), "https://vault.test");
    }

    #[test]
    fn default_provider_prefers_supported_then_first() {
        let info = |p: i32| bw_proto::TwoFactorProviderInfo { provider: p, hint: None };
        // 首個支援因子（Authenticator=0）優先，即使不是清單第一位。
        assert_eq!(
            default_provider(&[info(1), info(0)]),
            Some(1),
            "Email(1) 是首個支援因子時選它"
        );
        assert_eq!(default_provider(&[info(2), info(0)]), Some(0));
        // 全未支援：退回首個列出的（選了給 daemon 可懂錯誤，不沉默）。
        assert_eq!(default_provider(&[info(3), info(2)]), Some(3));
        assert_eq!(default_provider(&[]), None);
    }

    #[test]
    fn validate_otp_gates_six_digits() {
        assert_eq!(validate_otp(" 123456 ").unwrap(), "123456");
        assert_eq!(validate_otp("000000").unwrap(), "000000");
        assert_eq!(validate_otp("12345").unwrap_err(), "驗證碼需為 6 位數字");
        assert_eq!(validate_otp("1234567").unwrap_err(), "驗證碼需為 6 位數字");
        assert_eq!(validate_otp("12a456").unwrap_err(), "驗證碼需為 6 位數字");
        assert_eq!(validate_otp("").unwrap_err(), "驗證碼需為 6 位數字");
    }

    #[test]
    fn humanize_login_flags_stale_totp() {
        let out = humanize_login("http 400: Invalid TOTP code! Server time: ...");
        assert!(out.starts_with("http 400: Invalid TOTP code!"), "原文保留：{out}");
        assert!(out.contains("驗證碼錯誤或已過期"), "加可懂提示：{out}");
        // 其他錯誤不動原文。
        assert_eq!(humanize_login("weird"), "weird");
    }

    #[test]
    fn account_row_maps_reauth_first() {
        let unlocked = UnlockStateView::Unlocked { epoch: 1, deadline_epoch_ms: None };
        let out = UnlockStateView::SignedOut;
        // needs_reauth 優先於一切（即使仍解鎖）。
        assert_eq!(account_row(Some(&unlocked), true, Some("a@b.c")), AcctRow::Reauth);
        assert_eq!(account_row(None, true, None), AcctRow::Reauth);
        // 未登入（含 Welcome 尚無狀態）→ 登入入口。
        assert_eq!(account_row(Some(&out), false, None), AcctRow::SignedOut);
        assert_eq!(account_row(None, false, None), AcctRow::SignedOut);
        // 其餘為已登入，email 可知則附。
        assert_eq!(account_row(Some(&unlocked), false, Some("a@b.c")), AcctRow::Signed(Some("a@b.c".into())));
        assert_eq!(account_row(Some(&unlocked), false, None), AcctRow::Signed(None));
    }

    #[test]
    fn form_dirty_edit_baseline_matches_submit_semantics() {
        let orig = FormOriginal {
            name: "GitHub".into(),
            username: Some("octo".into()),
            uris: vec!["https://github.com".into()],
            uri_matches: vec![None],
            tags: vec!["dev".into()],
            notes: None,
            folder_id: None,
            fields: vec![],
        };
        let rows = [UriDraft {
            key: 0,
            uri: "https://github.com".into(),
            match_type: None,
        }];
        // 基準原值＝不髒；空白抖動與「空密碼＝不動」也不髒（同 submit 正規化）。
        assert!(!form_is_dirty(
            Some(&orig), "GitHub", "octo", "", &rows, "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(!form_is_dirty(
            Some(&orig), "  GitHub ", "octo", "   ", &rows, " dev ", " ", "",
            ItemKind::Login, &[]
        ));
        // 改名字、換密碼、清空網址、動標籤＝髒。
        assert!(form_is_dirty(
            Some(&orig), "GitHub2", "octo", "", &rows, "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "newpw", &rows, "dev", "", "",
            ItemKind::Login, &[]
        ));
        // 清空網址列值（Set uri.0 None）＝髒；列數縮減在編輯面不可達（無 ✕）。
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "", &[UriDraft { key: 0, uri: "  ".into(), match_type: None }],
            "dev", "", "", ItemKind::Login, &[]
        ));
        // 只改判定欄（match 預設→精確）＝髒：SetUriMatch 走 leaf 批。
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "",
            &[UriDraft { key: 0, uri: "https://github.com".into(), match_type: Some(3) }],
            "dev", "", "", ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "", &rows, "dev, 工作", "", "",
            ItemKind::Login, &[]
        ));
    }

    #[test]
    fn form_dirty_create_treats_any_input_as_dirty() {
        // 無基準＝新增：全空乾淨；任一欄位、型別切換、非空欄列＝髒。
        assert!(!form_is_dirty(
            None, "", "", "", &[], "", "", "", ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            None, "x", "", "", &[], "", "", "", ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            None, "", "", "", &[], "", "", "", ItemKind::SecureNote, &[]
        ));
        assert!(form_is_dirty(
            None, "", "", "", &[UriDraft { key: NEW_URI, uri: "https://a.test".into(), match_type: None }],
            "", "", "", ItemKind::Login, &[]
        ));
        let row = FieldDraft {
            key: 1,
            name: "API Key".into(),
            value: String::new(),
            kind: CipherFieldKind::Text,
        };
        assert!(form_is_dirty(
            None, "", "", "", &[], "", "", "", ItemKind::Login, &[row]
        ));
        let blank = FieldDraft {
            key: 2,
            name: " ".into(),
            value: String::new(),
            kind: CipherFieldKind::Text,
        };
        assert!(!form_is_dirty(
            None, "", "", "", &[], "", "", "", ItemKind::Login, &[blank]
        ));
    }

    #[test]
    fn uri_edits_key_alignment_and_structural_batches() {
        let orig = vec!["https://a.test".to_owned(), "https://b.test".to_owned()];
        let no_match: [Option<u8>; 2] = [None, None];
        // 全等基準＝三批皆空。
        let same = [
            UriDraft { key: 0, uri: "https://a.test".into(), match_type: None },
            UriDraft { key: 1, uri: "https://b.test".into(), match_type: None },
        ];
        let (s, t, tail) = uri_edits(&orig, &no_match, &same);
        assert!(s.is_empty() && t.is_empty() && tail.is_empty());
        // 倒置排列但 key 對齊→只有真改動的列產 Set。
        let swapped = [
            UriDraft { key: 1, uri: "https://b.test".into(), match_type: None },
            UriDraft { key: 0, uri: "https://a2.test".into(), match_type: None },
        ];
        let (s, t, tail) = uri_edits(&orig, &no_match, &swapped);
        assert!(matches!(&s[..], [FieldEdit::Set{path, value}] if path=="uri.0" && value.as_deref()==Some("https://a2.test")));
        assert!(t.is_empty() && tail.is_empty());
        // 基準有 match、現值回落預設＝SetUriMatch None（leaf 批）。
        let reset = [
            UriDraft { key: 0, uri: "https://a.test".into(), match_type: None },
            same[1].clone(),
        ];
        let (s, _, _) = uri_edits(&orig, &[Some(1), None], &reset);
        assert!(matches!(&s[..], [FieldEdit::SetUriMatch{index, match_type: None}] if *index==0));
        // 清空列值＝Set None；刪列＝RemoveUri 按基準索引、由大而小。
        let dropped = [UriDraft { key: 0, uri: "https://a.test".into(), match_type: None }];
        let (s, t, _tail) = uri_edits(&orig, &no_match, &dropped);
        assert!(s.is_empty());
        assert!(matches!(&t[..], [FieldEdit::RemoveUri{index}] if *index==1));
        let dropped_both: [UriDraft; 0] = [];
        let (_, t, _) = uri_edits(&orig, &no_match, &dropped_both);
        assert!(matches!(&t[..], [FieldEdit::RemoveUri{index:1}, FieldEdit::RemoveUri{index:0}]));
        // 新增列（key 不在基準）＝AppendUri 落結構批尾端；空白新列跳過。
        let with_new = [
            same[0].clone(),
            same[1].clone(),
            UriDraft { key: NEW_URI, uri: " https://c.test ".into(), match_type: None },
            UriDraft { key: NEW_URI.wrapping_sub(1), uri: "   ".into(), match_type: None },
        ];
        let (s, t, tail) = uri_edits(&orig, &no_match, &with_new);
        assert!(s.is_empty());
        assert!(matches!(&t[..], [FieldEdit::AppendUri{uri}] if uri=="https://c.test"));
        assert!(tail.is_empty());
        // 新列帶判定＋刪一列：判定批索引＝基準數−刪除數＋附加序（0）＝1。
        let drop_and_append = [
            same[1].clone(),
            UriDraft { key: NEW_URI, uri: "https://c.test".into(), match_type: Some(2) },
        ];
        let (_, t, tail) = uri_edits(&orig, &no_match, &drop_and_append);
        assert!(matches!(&t[..], [FieldEdit::RemoveUri{index:0}, FieldEdit::AppendUri{..}]));
        assert!(matches!(&tail[..], [FieldEdit::SetUriMatch{index, match_type: Some(2)}] if *index==1));
    }

    #[test]
    fn totp_display_gates_classify_absent_vs_error() {
        // 無 seed＝正常缺席：不渲染、不報錯。
        assert!(totp_absent("denied: 此項目沒有 TOTP seed"));
        assert!(!totp_absent("denied: seed base32 無效"));
        assert!(!totp_section_shown(None, None));
        // 有碼或真錯才出現；錯誤走可懂一行。
        assert!(totp_section_shown(Some("123456"), None));
        assert!(totp_section_shown(None, Some("取碼失敗：seed 無效")));
        assert_eq!(humanize_totp("base32 decode error"), "取碼失敗：base32 decode error");
        assert_eq!(humanize_totp("WtpError::Locked"), "取碼失敗：庫已鎖定");
    }

    #[test]
    fn parse_tags_splits_dedups_and_trims() {
        assert_eq!(
            parse_tags("dev, 工作； home,dev ,"),
            vec!["dev".to_owned(), "工作".to_owned(), "home".to_owned()]
        );
        assert!(parse_tags("  ").is_empty());
    }

    #[test]
    fn diff_tags_is_directional() {
        let orig = vec!["a".to_owned(), "b".to_owned()];
        let now = vec!["b".to_owned(), "c".to_owned()];
        let (add, remove) = diff_tags(&orig, &now);
        assert_eq!(add, vec!["c".to_owned()]);
        assert_eq!(remove, vec!["a".to_owned()]);
    }

    #[test]
    fn nonblank_trims_to_none() {
        assert_eq!(nonblank("  git "), Some("git".into()));
        assert_eq!(nonblank("   "), None);
    }

    #[test]
    fn deleted_filter_maps_trash_mode_to_tri_state() {
        // 一般視角用 None（旧 daemon 兼容），垃圾桶用 Some(true)；不發 Some(false)。
        assert_eq!(deleted_filter(false), None);
        assert_eq!(deleted_filter(true), Some(true));
    }

    #[test]
    fn vault_filter_folder_and_trash_are_exclusive() {
        let mut f = VaultFilter::default();
        assert!(!f.trash && f.folder.is_none());
        // 選資料夾退出垃圾桶。
        f.trash = true;
        f.pick_folder(Some("id1".into()));
        assert!(!f.trash);
        assert_eq!(f.folder.as_deref(), Some("id1"));
        // 進垃圾桶退出資料夾；再點一次回全部。
        f.toggle_trash();
        assert!(f.trash && f.folder.is_none());
        f.toggle_trash();
        assert!(!f.trash && f.folder.is_none());
        // 未歸屬是 Some("")，與 None（全部）可區分。
        f.pick_folder(Some(String::new()));
        assert_eq!(f.folder.as_deref(), Some(""));
        f.pick_folder(None);
        assert!(f.folder.is_none() && !f.trash);
    }

    #[test]
    fn parse_folders_maps_json_rows_and_skips_bad() {
        let v = serde_json::json!([
            {"id": "a", "name": "工作"},
            {"id": "b", "name": null},
            {"name": "缺id"},
        ]);
        let rows = parse_folders(&v);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name.as_deref(), Some("工作"));
        assert_eq!(rows[1].name, None);
        assert!(parse_folders(&serde_json::json!({"not": "array"})).is_empty());
    }

    #[test]
    fn parse_pending_maps_rows_and_tolerates_missing_time() {
        let v = serde_json::json!([
            {"id": "x1", "summary": "Vault.Get.Reveal", "requested_at_ms": 1794000000123u64},
            {"id": "x2", "summary": "Use.Run"},
            {"summary": "缺id跳過"},
        ]);
        let rows = parse_pending(v.as_array().unwrap());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "x1");
        assert_eq!(rows[0].requested_at_ms, Some(1794000000123));
        // daemon 尚未帶時間欄：None 而非虛構值。
        assert_eq!(rows[1].requested_at_ms, None);
    }

    fn draft(key: u32, name: &str, value: &str, kind: CipherFieldKind) -> FieldDraft {
        FieldDraft {
            key,
            name: name.into(),
            value: value.into(),
            kind,
        }
    }

    #[test]
    fn field_edits_key_alignment_survives_middle_removal() {
        let orig = vec![
            draft(1, "a", "1", CipherFieldKind::Text),
            draft(2, "b", "2", CipherFieldKind::Text),
            draft(3, "c", "3", CipherFieldKind::Text),
        ];
        // 刪掉中間的 b：不得把 c 的值錯位寫進 b。
        let cur = vec![
            draft(1, "a", "1", CipherFieldKind::Text),
            draft(3, "c", "9", CipherFieldKind::Text),
        ];
        let (leaf, structural) = field_edits(&orig, &cur);
        assert_eq!(leaf.len(), 1);
        match &leaf[0] {
            FieldEdit::Set { path, value } => {
                assert_eq!(path, "field.2.value");
                assert_eq!(value.as_deref(), Some("9"));
            }
            other => panic!("expected Set, got {other:?}"),
        }
        assert!(matches!(
            structural.as_slice(),
            [FieldEdit::RemoveField { index: 1 }]
        ));
    }

    #[test]
    fn field_edits_type_change_is_structural_and_defers_value() {
        let orig = vec![draft(1, "k", "v", CipherFieldKind::Text)];
        // text→boolean：值被正規化成 true；type 走 SetType、值走 leaf，分兩批。
        let mut nd = draft(1, "k", "true", CipherFieldKind::Boolean);
        nd.value = "true".into();
        let (leaf, structural) = field_edits(&orig, &[nd]);
        assert_eq!(leaf.len(), 1);
        assert!(matches!(
            structural.as_slice(),
            [FieldEdit::SetType { index: 0, kind: CipherFieldKind::Boolean }]
        ));
    }

    #[test]
    fn field_edits_appends_keep_order_and_skips_empty() {
        let orig: Vec<FieldDraft> = Vec::new();
        let cur = vec![
            draft(7, "new1", "x", CipherFieldKind::Text),
            draft(8, "", "", CipherFieldKind::Text),
            draft(9, "new2", "true", CipherFieldKind::Boolean),
        ];
        let (leaf, structural) = field_edits(&orig, &cur);
        assert!(leaf.is_empty());
        let appends: Vec<_> = structural
            .iter()
            .filter(|e| matches!(e, FieldEdit::AppendField { .. }))
            .collect();
        assert_eq!(appends.len(), 2, "空名空值列不進 AppendField");
        match &structural[0] {
            FieldEdit::AppendField { field } => assert_eq!(field.name, "new1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn field_edits_multiple_removals_descending_indices() {
        let orig = vec![
            draft(1, "a", "", CipherFieldKind::Text),
            draft(2, "b", "", CipherFieldKind::Text),
            draft(3, "c", "", CipherFieldKind::Text),
        ];
        let cur = vec![draft(2, "b", "", CipherFieldKind::Text)];
        let (_, structural) = field_edits(&orig, &cur);
        let idx: Vec<u32> = structural
            .iter()
            .map(|e| match e {
                FieldEdit::RemoveField { index } => *index,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(idx, vec![2, 0], "遞減刪除保 index 穩定");
    }

    #[test]
    fn boolean_value_normalization_on_kind_switch() {
        let mut d = draft(1, "k", "abc", CipherFieldKind::Text);
        d.set_kind(CipherFieldKind::Boolean);
        assert_eq!(d.value, "false", "非 true 值進布林欄歸 false");
        d.set_kind(CipherFieldKind::Boolean);
        d.value = "true".into();
        assert!(d.bool_value());
    }

    #[test]
    fn validate_change_password_gates_locally() {
        // 空 current、太短 new、比對不一致各自擋下（錯誤是繁中文案）。
        assert_eq!(
            validate_change_password("", "new-password-123", "new-password-123").unwrap_err(),
            "請輸入現有主密碼"
        );
        assert!(
            validate_change_password("old", "短短短", "短短短")
                .unwrap_err()
                .contains("12")
        );
        assert_eq!(
            validate_change_password("old-pass-word", "new-password-123", "other-password")
                .unwrap_err(),
            "新密碼與兩次輸入不一致"
        );
        // 12 字元閘以 chars 計（中文不炸成 bytes）
        assert!(validate_change_password("old", "新密码-12345678", "新密码-12345678").is_ok());
        assert!(
            validate_change_password(
                "old",
                "一二三四五六七八九十一二",
                "一二三四五六七八九十一二"
            )
            .is_ok()
        );
        assert!(
            validate_change_password("old", "一二三四五六七八九十", "一二三四五六七八九十")
                .is_err()
        );
    }

    #[test]
    fn change_password_button_only_when_unlocked() {
        assert!(can_change_password(&Some(UnlockStateView::Unlocked {
            epoch: 1,
            deadline_epoch_ms: None
        })));
        assert!(!can_change_password(&Some(UnlockStateView::AuthLocked {
            items: 0
        })));
        assert!(!can_change_password(&None));
    }

    #[test]
    fn lock_state_labels() {
        assert_eq!(
            vault_label(&UnlockStateView::AuthLocked { items: 3 }),
            "已鎖定"
        );
        assert_eq!(
            vault_label(&UnlockStateView::Unlocked {
                epoch: 1,
                deadline_epoch_ms: None
            }),
            "已解鎖"
        );
        assert!(can_unlock(&Some(UnlockStateView::Stale {
            why: "key drift".into()
        })));
        assert!(!can_unlock(&Some(UnlockStateView::Unlocked {
            epoch: 1,
            deadline_epoch_ms: None
        })));
    }
}
