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

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use bw_proto::{
    AgentCall, AttachmentOp, AuthCall, Call, CipherDraft, CipherFieldKind, EventTopic, FieldEdit,
    ItemId, ItemKind, ItemView, OverlayOpWire, Query, Response, SortKey, SyncCall,
    UnlockStateView, UseCall, VaultCall, View,
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
    pub uri: Option<String>,
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
}

impl VaultFilter {
    /// 選資料夾（含未歸屬）：自動退出垃圾桶。`pick_folder(None)`＝回全部項目。
    pub fn pick_folder(&mut self, folder: Option<String>) {
        self.folder = folder;
        self.trash = false;
    }

    /// 垃圾桶切換：進入時退出資料夾（回「全部項目」）。
    pub fn toggle_trash(&mut self) {
        self.trash = !self.trash;
        if self.trash {
            self.folder = None;
        }
    }
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
    /// 側欄資料夾節點：None＝全部項目、Some("")＝未歸屬、Some(id)＝該夾。
    ChooseFolder(Option<String>),
    /// 批准中心（批次 6 併入 GUI）：佇列視角、輪詢、單鍵直決。
    OpenApprovals,
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
    StateUpdated {
        state: UnlockStateView,
        refetch: bool,
    },
    /// Sync:Trigger 成功回包：蓋同步時間戳、提示「已同步」、重抓列表。
    SyncDone {
        state: UnlockStateView,
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
    pub uri: Signal<String>,
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
        self.uri.set(String::new());
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
    pub totp_tick: Signal<u64>,
    /// 側欄同步狀態：本視窗最近一次 Sync:Trigger 成功時刻。
    pub last_sync: Signal<Option<Instant>>,
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
}

impl AppCore {
    /// 在元件上下文（`App`）裡呼叫：訊號隸屬目前 owner。
    pub fn boot(session: Arc<Session>) -> (AppCore, Receiver<Cmd>) {
        let (tx, rx) = channel();
        let core = AppCore {
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
            totp_tick: signal(0),
            last_sync: signal(None),
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
            form: FormFields {
                name: signal(String::new()),
                username: signal(String::new()),
                password: signal(String::new()),
                uri: signal(String::new()),
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
                ],
                move |topic| {
                    match topic {
                        EventTopic::ApprovalRequired => {
                            let _ = tx2.send(Cmd::FetchPending);
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
        self.totp_valid_for.set(0);
        self.totp_issued.set(None);
        self.att_upload_path.set(String::new());
        self.att_upload_open.set(false);
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
            }
        }
        // NavForced 已在入口剝殼；走到這裡＝巢狀 Box（不預期），靜默吞掉。
        Cmd::NavForced(_) => {}
        Cmd::RequestCloseForm => {
            let back = match core.route.get() {
                Route::Edit(id) => Cmd::OpenDetail(id),
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
                core.detail.set(Some(row));
            }
        }
        Cmd::OpenCreate => {
            core.send(Cmd::FetchFolders);
            core.leave_detail();
            core.form.reset(None);
            core.route.set(Route::Create);
        }
        Cmd::OpenEdit(id) => {
            core.send(Cmd::FetchFolders);
            core.leave_detail();
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
            core.form
                .name
                .set(row.meta.name.clone().unwrap_or_default());
            core.form
                .username
                .set(row.username.clone().unwrap_or_default());
            core.form
                .uri
                .set(row.meta.uris.first().cloned().unwrap_or_default());
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
                uri: row.meta.uris.first().cloned(),
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
                    Err(e) => Cmd::Failed { err: e.display() },
                    Ok(other) => Cmd::Failed {
                        err: format!("TotpCode 回應形態不符：{other:?}"),
                    },
                },
            );
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
                Ok(Response::Status(info)) => Cmd::SyncDone { state: info.state },
                Ok(other) => Cmd::Failed {
                    err: format!("Sync.Trigger 回應形態不符：{other:?}"),
                },
                Err(e) => Cmd::Failed { err: e.display() },
            });
        }
        Cmd::SyncDone { state } => {
            core.settle();
            core.vault.set(Some(state));
            core.error_text.set(None);
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
                    },
                    Err(e) => Cmd::Failed { err: e.display() },
                }
            });
        }
        Cmd::StateUpdated { state, refetch } => {
            core.settle();
            core.vault.set(Some(state));
            core.error_text.set(None);
            if refetch {
                fetch_list(core);
            }
        }
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
    let uri = nonblank(core.form.uri.get().trim());
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
                    uris: uri.into_iter().collect(),
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
                uri,
                notes,
                folder_id,
                tags: &tags,
                drafts: &drafts,
            };
            let (leaf, field_struct, add, remove) = edit_delta(&orig, &input);
            if leaf.is_empty() && field_struct.is_empty() && add.is_empty() && remove.is_empty() {
                core.send(Cmd::OpenDetail(id));
                return;
            }
            core.ipc(move |s| {
                let mut err: Option<String> = None;
                // 兩批 Patch：先 leaf 值（含 field.<n>.name/value），後結構
                // （SetType/RemoveField/AppendField）。分批避開同欄 type×值衝突。
                for batch in [leaf, field_struct] {
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

/// 表單現值（`edit_delta`／`form_is_dirty` 統一輸入形態；正規化在呼叫端）。
pub struct FormInput<'a> {
    pub name: &'a str,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: &'a [String],
    pub drafts: &'a [FieldDraft],
}

/// 編輯表單的完整差異集（提交與髒閘的單一真相源，紀律 1 零複製）：
/// leaf 值批、結構批、標籤增/刪。密碼語意沿用編輯規則——空值＝不動基準。
pub fn edit_delta(
    orig: &FormOriginal,
    f: &FormInput<'_>,
) -> (Vec<FieldEdit>, Vec<FieldEdit>, Vec<String>, Vec<String>) {
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
    if f.uri != orig.uri {
        leaf.push(FieldEdit::Set {
            path: "uri.0".into(),
            value: f.uri.clone(),
        });
    }
    if f.password.is_some() {
        leaf.push(FieldEdit::Set {
            path: "password".into(),
            value: f.password.clone(),
        });
    }
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
    let (field_leaf, field_struct) = field_edits(&orig.fields, f.drafts);
    leaf.extend(field_leaf);
    let (add, remove) = diff_tags(&orig.tags, f.tags);
    (leaf, field_struct, add, remove)
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
    uri: &str,
    tags: &str,
    notes: &str,
    folder_id: &str,
    kind: ItemKind,
    drafts: &[FieldDraft],
) -> bool {
    let name = name.trim().to_owned();
    let username = nonblank(username);
    let password = nonblank(password);
    let uri = nonblank(uri.trim());
    let tag_list = parse_tags(tags);
    let notes = nonblank(notes);
    let folder = nonblank(folder_id);
    match orig {
        Some(o) => {
            let input = FormInput {
                name: &name,
                username,
                password,
                uri,
                notes,
                folder_id: folder,
                tags: &tag_list,
                drafts,
            };
            let (leaf, field_struct, add, remove) = edit_delta(o, &input);
            !(leaf.is_empty() && field_struct.is_empty() && add.is_empty() && remove.is_empty())
        }
        None => {
            !name.is_empty()
                || username.is_some()
                || password.is_some()
                || uri.is_some()
                || notes.is_some()
                || folder.is_some()
                || !tag_list.is_empty()
                || kind != ItemKind::Login
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
        &core.form.uri.get(),
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
            | Cmd::ChooseFolder(_)
            | Cmd::ToggleTrash
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
    fn form_dirty_edit_baseline_matches_submit_semantics() {
        let orig = FormOriginal {
            name: "GitHub".into(),
            username: Some("octo".into()),
            uri: Some("https://github.com".into()),
            tags: vec!["dev".into()],
            notes: None,
            folder_id: None,
            fields: vec![],
        };
        // 基準原值＝不髒；空白抖動與「空密碼＝不動」也不髒（同 submit 正規化）。
        assert!(!form_is_dirty(
            Some(&orig), "GitHub", "octo", "", "https://github.com", "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(!form_is_dirty(
            Some(&orig), "  GitHub ", "octo", "   ", "https://github.com", " dev ", " ", "",
            ItemKind::Login, &[]
        ));
        // 改名字、換密碼、清空網址、動標籤＝髒。
        assert!(form_is_dirty(
            Some(&orig), "GitHub2", "octo", "", "https://github.com", "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "newpw", "https://github.com", "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "", "", "dev", "", "",
            ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            Some(&orig), "GitHub", "octo", "", "https://github.com", "dev, 工作", "", "",
            ItemKind::Login, &[]
        ));
    }

    #[test]
    fn form_dirty_create_treats_any_input_as_dirty() {
        // 無基準＝新增：全空乾淨；任一欄位、型別切換、非空欄列＝髒。
        assert!(!form_is_dirty(
            None, "", "", "", "", "", "", "", ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            None, "x", "", "", "", "", "", "", ItemKind::Login, &[]
        ));
        assert!(form_is_dirty(
            None, "", "", "", "", "", "", "", ItemKind::SecureNote, &[]
        ));
        let row = FieldDraft {
            key: 1,
            name: "API Key".into(),
            value: String::new(),
            kind: CipherFieldKind::Text,
        };
        assert!(form_is_dirty(
            None, "", "", "", "", "", "", "", ItemKind::Login, &[row]
        ));
        let blank = FieldDraft {
            key: 2,
            name: " ".into(),
            value: String::new(),
            kind: CipherFieldKind::Text,
        };
        assert!(!form_is_dirty(
            None, "", "", "", "", "", "", "", ItemKind::Login, &[blank]
        ));
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
