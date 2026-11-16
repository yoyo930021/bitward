//! bitward CLI：一次性短命 thin client（契約 §3.10）。
//! 輸出契約：`--json` 的 metadata 路徑結構上不含機密鍵（A3）；
//! 密碼輸入走 stdin/旗標轉 stdin，不進 argv（A11）。

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use uuid::Uuid;

use bw_btp::{read_server, write_client};
use bw_proto::wire::{self, WireFormat};
use bw_proto::{
    AdminCall, AgentCall, Auth, AuthCall, Call, CipherDraft, CipherField, CipherFieldKind,
    ClientMsg, EaAccessType, EaCall, EaRole, FieldEdit, FillCall, ImportItem, ItemId, ItemKind,
    ItemView, MutationId, OverlayOpWire, PROTO_VERSION, PasskeyCall, ProtoVersion, Query,
    Resolution, Response, ServerMsg, SessionToken, Settings, SortKey, SyncCall, TwoFactorCall,
    TwoFactorInput, TwoFactorProviderInfo, UseCall, VaultCall, View, WtpError,
};

#[derive(Parser)]
#[command(name = "bitward", version, about = "bitward thin client CLI")]
struct Args {
    #[arg(long, global = true)]
    sock: Option<PathBuf>,
    /// 輸出 JSON（機器可讀契約；ls 的 metadata 永不含 password/username 鍵）
    #[arg(long, global = true)]
    json: bool,
    /// 以跨機 device profile 連線（`pair join` 建立），值為 profile 名稱
    #[arg(long, global = true)]
    remote: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        /// 從 stdin 讀主密碼（第一行；pinentry 式）。帳號開 2FA 時，
        /// 同一流依序再收「因子編號、6 位驗證碼」兩行（提示走 stderr）。
        #[arg(long)]
        password_stdin: bool,
    },
    Unlock {
        /// 以主密碼解鎖（stdin 讀一行；嚴格模式 `lock_on_sleep_restart=true`
        /// 下裸解鎖會被拒，此旗為 CLI 的明確請求路徑，A11 密碼不進 argv）。
        #[arg(long)]
        password_stdin: bool,
        /// 以 Touch ID 解鎖（需已封存 Keychain；否則 daemon 回明確提示）。
        #[arg(long)]
        biometric: bool,
    },
    Lock,
    /// 改主密碼：stdin 依序讀入現有、新主密碼兩行（A11：密碼不進 argv）
    ChangePassword,
    Status,
    /// 本機設定（macOS 設定面）：自動鎖定／剪貼簿清除／重啟鎖定／鎖定清搜尋
    Settings {
        #[command(subcommand)]
        cmd: SettingsCmd,
    },
    /// 服務端 2FA 因子管理面（PR3）：清單／TOTP／Email／YubiKey／救援碼／停用。
    /// 需要驗身的子命令一律從 stdin 讀主密碼一行（A11：密碼不進 argv）。
    #[command(alias = "2fa")]
    TwoFactor {
        #[command(subcommand)]
        cmd: TwoFactorCmd,
    },
    /// 緊急存取（PR4）：联系人清單／邀請／確認／撤銷（C1）＋恢復與視圖（C2/C3）。
    #[command(alias = "emergency-access")]
    Ea {
        #[command(subcommand)]
        cmd: EaCmd,
    },
    Sync,
    Ls {
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        uri: Option<String>,
        /// 以密碼/帳號值精確搜尋（需曾解鎖回填索引）
        #[arg(long)]
        value: Option<String>,
        /// 只列該 collection（org 共享集合）的項目（P4b）
        #[arg(long)]
        collection: Option<String>,
        /// 只列該資料夾（UUID）；空字串＝個人未歸屬
        #[arg(long)]
        folder: Option<String>,
        /// 列垃圾桶（帶 deleted_at；默認只列未刪）
        #[arg(long)]
        trash: bool,
        /// 只列已封存項目（默認排除封存；官方 archivedDate 語意）
        #[arg(long)]
        archived: bool,
        #[arg(long, default_value = "name")]
        sort: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Get {
        id: String,
        #[arg(long, default_value = "metadata")]
        view: String,
    },
    Reveal {
        id: String,
    },
    Totp {
        id: String,
    },
    /// 產生密碼：隨機數與政策解讀走 daemon `Use:GeneratePassword`（與 macOS
    /// GUI 同源）。CLI 是 thin client（契約 §3.10），不在本地起第二套產生器；
    /// 產生器不碰金鑰，鎖定態的 daemon 也能用。輸出僅一行密碼（A11 慣例，
    /// 產生值非機密但照純值口徑走 stdout）。
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_lowercase: bool,
        #[arg(long)]
        no_uppercase: bool,
        #[arg(long)]
        no_numbers: bool,
        #[arg(long)]
        no_special: bool,
        /// 排除易混淆字元 `I O l 0 1`（官方 avoidAmbiguous）
        #[arg(long)]
        avoid_ambiguous: bool,
    },
    /// AutoType：daemon 解密後倒數 3 秒注入按鍵（明文不回程）
    Autotype {
        id: String,
        /// 模板，預設 {username}{TAB}{password}{TAB}{enter}
        #[arg(long)]
        template: Option<String>,
    },
    /// WebAuthn passkey（macOS autofill 的 daemon 端核心）
    Passkey {
        #[command(subcommand)]
        cmd: PasskeyCmd,
    },
    Audit {
        #[arg(long, default_value_t = 50)]
        tail: u32,
        #[arg(long)]
        verify: bool,
    },
    Version,
    New {
        #[arg(long)]
        name: String,
        /// 項目型別：login|note（SecureNote；card/identity 留後續批次）
        #[arg(long = "type", default_value = "login")]
        type_: String,
        #[arg(long)]
        username: Option<String>,
        /// 從 stdin 讀一行作為密碼（不進 argv，A11）
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        uri: Option<String>,
        #[arg(long)]
        totp: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// 建立時歸屬的資料夾（UUID；`bitward folder ls` 取 id）
        #[arg(long)]
        folder: Option<String>,
        /// 自訂文字欄 `k=v`，可重複
        #[arg(long = "field")]
        fields: Vec<String>,
        /// 自訂 hidden 欄 `k=v`，可重複（回程值以 ••• 代，reveal 才出）
        #[arg(long = "field!")]
        hidden_fields: Vec<String>,
        /// 自訂 boolean 欄 `k=v`（v ∈ true|false），可重複
        #[arg(long = "field?")]
        bool_fields: Vec<String>,
        /// 卡片欄 `k=v`（k ∈ cardholderName|brand|number|expMonth|expYear|code），
        /// 可重複；值 `-`＝從 stdin 讀一行（A11：卡號/CVV 不落 argv）
        #[arg(long = "card")]
        card_fields: Vec<String>,
        /// 身分欄 `k=v`（k ∈ identity.api.ts 十八欄鍵名），可重複；值 `-`＝stdin
        #[arg(long = "identity")]
        identity_fields: Vec<String>,
    },
    /// 資料夾（官方 folders 語意：名稱 user key 加密）
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// 硬刪垃圾桶項目：本機鏡像永久移除＋伺服器 DELETE（離線拒）
    Purge {
        id: String,
    },
    Edit {
        id: String,
        /// `path=value`，可重複。path ∈ name|notes|username|password|totp|uri.<n>|favorite|folderId|field.<n>.name|field.<n>.value|field.<n>.type
        #[arg(long = "set")]
        sets: Vec<String>,
        /// 改自訂欄型別 `<index>=<text|hidden|boolean>`，可重複。
        /// 官方語意 type 改動連帶整欄重加密：與另一端同欄的值改動判同欄衝突。
        #[arg(long = "set-type")]
        set_types: Vec<String>,
        /// 附加自訂文字欄 `k=v`，可重複
        #[arg(long = "append-field")]
        appends: Vec<String>,
        /// 附加 hidden 欄 `k=v`，可重複
        #[arg(long = "append-field!")]
        appends_hidden: Vec<String>,
        /// 附加自訂欄 `k=true|false`，可重複
        #[arg(long = "append-field?")]
        appends_bool: Vec<String>,
        /// 移除自訂欄（0 起 index），可重複
        #[arg(long = "remove-field")]
        removes: Vec<u32>,
        /// 附加網址列（官方形態新列 match=null），可重複
        #[arg(long = "append-uri")]
        append_uris: Vec<String>,
        /// 移除網址列（0 起 index），可重複
        #[arg(long = "remove-uri")]
        remove_uris: Vec<u32>,
        /// 改網址列判定 `<index>=<null|0..5>`，可重複（官方 `login.uris[].match`：
        /// null=預設、0=網域、1=網域＋子域、2=開頭符合、3=精確、4=正規表達式、5=永不）
        #[arg(long = "set-uri-match")]
        set_uri_matches: Vec<String>,
        /// 清除欄位，可重複
        #[arg(long = "clear")]
        clears: Vec<String>,
        /// 密碼類新值改由 stdin 讀（搭配 --secret-stdin）
        #[arg(long)]
        secret_stdin: bool,
    },
    /// 批次匯入未加密 JSON（官方匯出形態或本 CLI 欄位形態；單交易全收或全拒）
    Import {
        /// 檔案路徑或 `-`＝stdin。明文欄位走 UDS/TLS 本機線（A11：不落 argv）
        file: String,
        /// 官方 `bw import` 格式參數佔位（本批 true/false 語意相同）
        #[arg(long)]
        format: bool,
    },
    /// 封存／取消封存（官方 archivedDate 語意：主列表預設排除已封存）
    Archive {
        id: String,
        /// true＝封存（預設）、false＝取消封存
        #[arg(default_value = "true")]
        on: String,
    },
    /// 取網站圖示（daemon 代理＋7 天快取；`-`＝stdout。404＝server 無 icons）
    Icon {
        host: String,
        out: String,
    },
    Rm {
        id: String,
    },
    Restore {
        id: String,
    },
    Outbox,
    Conflicts,
    Resolve {
        id: u64,
        #[arg(long)]
        ours: bool,
        #[arg(long)]
        theirs: bool,
        #[arg(long)]
        keep_both: bool,
    },
    SignOut,
    /// 附件（VW 免費開放；內容加密以附件金鑰、元資料鏡像隨 /sync）
    Attach {
        #[command(subcommand)]
        cmd: AttachCmd,
    },
    /// 本地 overlay 標籤（FR 132）
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    /// 去重報告（同 host+username 群集）
    Dupes,
    /// 報告儀表板（重用密碼／弱密碼／項目歷史）
    Reports {
        /// reuse | weak | history
        what: String,
        /// history 的項目 id（其餘子命令忽略）
        #[arg(long)]
        id: Option<String>,
    },
    /// Send 加密分享（文字/檔案 → 連結；無 outbox，建立需連網）
    Send {
        #[command(subcommand)]
        cmd: SendCmd,
    },
    /// 合併重複項：保留 KEEP，軟刪其餘，tags 聯集
    Merge {
        keep: String,
        dupes: Vec<String>,
    },
    /// unshare：把 org 項目移回個人 vault（FR 604）
    Unshare {
        id: String,
    },
    /// agent session 治理（人在這台機器上簽發/管理）
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// 注入 vault 機密執行命令（出口經 Redactor 淨化）
    Run {
        /// `K=btw://<uuid>/<field>` 或 `K=literal`，可重複
        #[arg(long = "env")]
        env: Vec<String>,
        #[arg(long, default_value = "")]
        cwd: String,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// 核准一個待批請求（human-in-the-loop）
    Approve {
        id: String,
        /// 追加常駐 grant（DSL），可重複
        #[arg(long = "grant")]
        grants: Vec<String>,
    },
    /// 拒絕一個待批請求：請求端立刻收到 Denied，不必等 120s 逾時
    Deny {
        id: String,
    },
    /// 跨機配對（§1.2）
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// 跨機 hub 編組（§1.1 thin 端視圖）：清單/健康/預設/failover
    Hub {
        #[command(subcommand)]
        cmd: HubCmd,
    },
    /// e2e/開發用：向（自架）server 註冊新帳號，不寫入 daemon 狀態
    #[command(hide = true)]
    DevRegister {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// e2e/開發用：直接經 API 塞一筆 login cipher（繞過 P2 才有的 outbox）
    #[command(hide = true)]
    DevSeed {
        #[arg(long)]
        name: String,
        #[arg(long)]
        uri: String,
        #[arg(long)]
        password: String,
    },
}

fn session_file(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("cli_session")
}

#[derive(Subcommand)]
enum TagCmd {
    Add {
        id: String,
        tag: String,
    },
    Rm {
        id: String,
        tag: String,
    },
    Pin {
        id: String,
        #[arg(default_value = "true")]
        on: String,
    },
}

#[derive(Subcommand)]
enum AttachCmd {
    /// 上傳檔案（≤32MiB；離線自動入佇列收斂）
    Add { item: String, path: String },
    /// 列附件（元資料；需解鎖——檔名是信封字串）
    Ls { item: String },
    /// 下載到檔案（`-`＝stdout）
    Get {
        item: String,
        #[arg(name = "ATT_ID")]
        att_id: String,
        out: String,
    },
    /// 刪除附件（需線上；見 daemon 語意）
    Rm {
        item: String,
        #[arg(name = "ATT_ID")]
        att_id: String,
    },
}

#[derive(Subcommand)]
enum SendCmd {
    /// 分享文字（成功輸出分享 URL；需連網＋解鎖）
    Text {
        text: String,
        /// 存活天數：1|7|30（官方預設 7；伺服器硬閘 31 天）
        #[arg(long, default_value_t = 7)]
        days: u32,
        /// 從 stdin 讀取用密碼（無值＝不設）
        #[arg(long)]
        password_stdin: bool,
        /// 存取上限（留空＝不限）
        #[arg(long)]
        max: Option<u32>,
        /// 顯示名稱（留空＝取文字首行）
        #[arg(long)]
        name: Option<String>,
        /// 對接收方隱藏帳號 email
        #[arg(long)]
        hide_email: bool,
    },
    /// 分享檔案（≤32MiB；成功輸出分享 URL；需連網＋解鎖）
    File {
        path: String,
        #[arg(long, default_value_t = 7)]
        days: u32,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        max: Option<u32>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        hide_email: bool,
    },
    /// 列 Send（鏡像；name 需解鎖，鎖態為 null）
    Ls,
    /// 取分享 URL（本地組裝，不連網；URL 帶金鑰片段，勿貼進明文通道）
    Url {
        #[arg(name = "SEND_ID")]
        id: String,
    },
    /// 刪除（需連網；伺服器已不存在＝照收斂）
    Rm {
        #[arg(name = "SEND_ID")]
        id: String,
    },
    /// 接收方讀取（PR2）：解分享 URL 的金鑰片段→本地拉伸→存取端點→解密。
    /// 不需登入／解鎖（接收方常無帳號），也不經 daemon。
    Access {
        /// 分享 URL（`{server}/#/send/{id}/{金鑰片段}`；片段必須整條保留）
        url: String,
        /// 從 stdin 讀取用密碼（此 Send 設了密碼時需要）
        #[arg(long)]
        password_stdin: bool,
        /// 檔案 Send 輸出路徑（`-`＝stdout；省略＝原檔名落本目錄）
        #[arg(short = 'o', long, value_name = "FILE")]
        out: Option<String>,
    },
}

#[derive(Subcommand)]
enum FolderCmd {
    /// 列資料夾（鎖定態 name 為 null——名稱是信封字串）
    Ls,
    Create {
        name: String,
    },
    /// 刪除：夾內項目 folderId 先清 NULL（官方語意同序）
    Delete {
        id: String,
    },
}

#[derive(Subcommand)]
enum SettingsCmd {
    /// 讀取現行設定（輸出 Settings JSON）
    Show,
    /// 寫入設定：`<payload>` 為 Settings 形態 JSON，缺欄＝官方預設
    Set { payload: String },
}

#[derive(Subcommand)]
enum TwoFactorCmd {
    /// 已啟用因子清單（不需要主密碼，只要已登入）
    Ls,
    /// 取 TOTP 金鑰與 otpauth URI（stdin：主密碼）
    TotpKey,
    /// 以驗證器現碼啟用 TOTP（stdin：主密碼、6 位碼；`--key` 取 TotpKey 的 secret）
    TotpEnable { key: String },
    /// 取備用救援碼（stdin：主密碼）
    Recovery,
    /// 寄 Email 因子驗證碼（stdin：主密碼）
    EmailSend { email: String },
    /// 以信中碼確認 Email 因子（stdin：主密碼、碼）
    EmailVerify { email: String, token: String },
    /// 登記一把 YubiKey（stdin：主密碼、44 字元 OTP）
    YubikeyAdd,
    /// 停用一個因子（`provider`＝upstream 編號：0 TOTP、1 Email、2 Duo、
    /// 3 YubiKey、7 WebAuthn；stdin：主密碼）
    Disable { provider: i32 },
}

#[derive(Subcommand)]
enum EaCmd {
    /// 联系人清單：預設＝我授權的對象（grantee 側欄）；`--granted`＝授權給我的
    Ls {
        #[arg(long)]
        granted: bool,
    },
    /// 邀請緊急联系人（`--type view|takeover`、`--days` 恢復等待天數）
    Invite {
        email: String,
        #[arg(long, default_value = "view")]
        r#type: String,
        #[arg(long, default_value_t = 7)]
        days: u32,
    },
    /// grantor 確認（以對方公鑰派發 user key；需解鎖態）
    Confirm { id: String },
    /// 撤銷（grantor/grantee 兩側皆可）
    Revoke { id: String },
    /// grantee 發起恢復（Confirmed → RecoveryInitiated，等 wait 天自動批准）
    Initiate { id: String },
    /// grantor 批准恢復（→ RecoveryApproved，grantee 才能 view/takeover）
    Approve { id: String },
    /// grantor 拒絕恢復（回 Confirmed）
    Reject { id: String },
    /// grantee 唯讀視圖（需解鎖態；輸出 grantor 項目 Reveal 投影）
    View { id: String },
    /// 接管（stdin：新主密碼；需解鎖態。改 grantor 主密碼＋重包 akey，
    /// 伺服器順手清其 2FA 因子——源檔語意見 daemon 註解）
    Takeover { id: String },
}

#[derive(Subcommand)]
enum PasskeyCmd {
    /// 列 passkey（Metadata 級：只含識別欄，無密鑰材料）
    List {
        #[arg(long)]
        rp: Option<String>,
    },
    /// 註冊 passkey：預設 daemon 生成 P-256 私鑰（純軟體流）；
    /// 帶 --public-key = SE 公鑰單步流（keyValue 存 SPKI）。輸出 attestation（JSON）
    Register {
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        /// b64url challenge
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        /// 附加到既有 item（預設新建 login item）
        #[arg(long)]
        item: Option<String>,
        /// b64url DER SubjectPublicKeyInfo（Swift/SE 匯出的公鑰）
        #[arg(long)]
        public_key: Option<String>,
    },
    /// 兩步註冊·第一步：daemon 簽發 credential_id（b64url 32B，SecKey tag 用）
    BeginRegister {
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
    /// 兩步註冊·第二步：以 BeginRegister 的 id + SPKI 公鑰完成註冊（輸出 attestation JSON）
    FinishRegister {
        /// BeginRegister 回傳的 b64url credential id
        #[arg(long)]
        credential: String,
        /// b64url DER SubjectPublicKeyInfo
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        rp: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        display: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
    /// 簽發 assertion（counter++ 進 outbox）。純軟體流由 daemon 自簽；
    /// 帶 --signature = 簽名校驗流（Swift 已簽，驗過才提交 counter）。
    Assert {
        #[arg(long)]
        credential: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        rp: String,
        /// b64url(32B)：Apple provider 流的 clientDataHash
        #[arg(long)]
        hash: Option<String>,
        /// b64url DER ECDSA 簽名（對 authData‖hash）
        #[arg(long)]
        signature: Option<String>,
        /// Swift 側 keychain item 標籤（不透明，隨 audit 記錄）
        #[arg(long)]
        key_id: Option<String>,
    },
    /// 兩步斷言·第一步：取本次 authData（含新 counter；不持久化）
    Begin {
        #[arg(long)]
        credential: String,
        /// b64url(32B) clientDataHash
        #[arg(long)]
        hash: String,
    },
    /// 兩步斷言·第二步：交回 DER 簽名（b64url），驗過才持久化 counter
    Finish {
        #[arg(long)]
        credential: String,
        #[arg(long)]
        signature: String,
    },
    /// 刪除單條憑證（鏡像＋伺服器 fido2Credentials 同步收斂）
    Rm {
        /// 憑證所在項目 id（`bitward passkey ls --json` 的 item 歸屬）
        item: String,
        /// b64url credentialId
        credential: String,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// 全端：產生一次性配對碼
    Start {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "see:identity all")]
        grant: String,
        #[arg(long, default_value_t = 30 * 24 * 3600)]
        ttl: u64,
    },
    /// thin 端：用配對碼換長期 device token
    Join {
        /// 目標 host[:port]（`https://` 前綴可省、port 缺=8443；
        /// tailnet 磁標由系統/MagicDNS 解析，E4）
        #[arg(long)]
        url: String,
        #[arg(long)]
        pin: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        name: String,
        /// ntfy 喚醒 endpoint（能力憑證，選填）
        #[arg(long)]
        wake: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    List,
    Revoke {
        code: String,
    },
}

#[derive(Subcommand)]
enum HubCmd {
    /// 列已配對 hub（profile、url、預設標記、last_seen）；--probe 實測可達性
    Ls {
        #[arg(long)]
        probe: bool,
    },
    /// 設預設 hub（本地 daemon 不可達時的 failover 目標；`none` 清除）
    Default {
        /// profile 名稱（`pair join --profile` 建立）或 `none`
        profile: String,
    },
}

/// 預設 hub 指標檔（remotes/ 下的 dotfile：不帶 .json 後綴，天然不進清單）。
const DEFAULT_HUB_FILE: &str = ".default";

fn read_default_hub(data_dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(data_dir.join("remotes").join(DEFAULT_HUB_FILE)).ok()?;
    let t = s.trim().to_owned();
    (!t.is_empty()).then_some(t)
}

fn list_hub_profiles(data_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(data_dir.join("remotes"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json").map(str::to_owned)
        })
        .collect();
    v.sort();
    v
}

fn hub_last_seen(data_dir: &Path, profile: &str) -> Option<u64> {
    std::fs::read_to_string(data_dir.join(format!("remote_{profile}_last_ok")))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// failover 決策（純函數，單測點）：明示 --remote 直接走之；本地可達走本地；
/// 本地不可達且有預設 hub→Failover；無預設→NoHub（原錯照報＝「明確指令提示」語意）。
#[derive(Debug, PartialEq, Eq)]
enum HubRoute {
    Local,
    Remote(String),
    Failover(String),
    NoHub,
}

fn route_hub(requested: Option<&str>, local_ok: bool, default_hub: Option<String>) -> HubRoute {
    if let Some(p) = requested {
        return HubRoute::Remote(p.to_owned());
    }
    if local_ok {
        return HubRoute::Local;
    }
    match default_hub {
        Some(d) => HubRoute::Failover(d),
        None => HubRoute::NoHub,
    }
}

/// 預設 hub 亦失聯時的換 hub 提示（純函數，單測點；Lane 5 的可懂終態）。
fn failover_hint(default: &str, others: &[String]) -> String {
    let rest: Vec<&str> = others
        .iter()
        .map(String::as_str)
        .filter(|o| *o != default)
        .collect();
    if rest.is_empty() {
        return "無其他已配對 hub（`bitward pair join` 建立，或 `bitward hub default none` 回本地）".into();
    }
    format!(
        "其他可用 hub：{}（`bitward hub default <name>` 切預設、`--remote <name>` 單次指定）",
        rest.join(", ")
    )
}

#[derive(Subcommand)]
enum AgentCmd {
    Open {
        #[arg(long)]
        name: String,
        /// grant DSL（見 bw-agent 文件）
        #[arg(long)]
        grant: String,
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    List,
    /// 待核准佇列（回 [{"id","summary"}]）
    Pending,
    Revoke {
        id: String,
    },
}

fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_DATA_DIR") {
        return d.into();
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitward")
}

/// 連線端預設 sock。Q3 裁決（2026-11-16）：Linux＝`$XDG_RUNTIME_DIR/bitward/daemon.sock`
/// 主、`<data_dir>/daemon.sock` 退（主路徑不存在且退路存在才退——daemon 可能被
/// `--sock` 起在 data_dir）；macOS 維持 data_dir 不動。純函數便單測。
#[cfg(target_os = "linux")]
fn pick_cli_sock(xdg_runtime_dir: Option<&str>, data_dir: &Path) -> PathBuf {
    let fallback = data_dir.join("daemon.sock");
    match xdg_runtime_dir {
        Some(d) if !d.is_empty() => {
            let main = std::path::Path::new(d).join("bitward").join("daemon.sock");
            if !main.exists() && fallback.exists() {
                fallback
            } else {
                main
            }
        }
        _ => fallback,
    }
}

#[cfg(target_os = "linux")]
fn default_sock(data_dir: &Path) -> PathBuf {
    pick_cli_sock(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), data_dir)
}

#[cfg(not(target_os = "linux"))]
fn default_sock(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon.sock")
}

#[tokio::main]
async fn main() {
    // 批次 14.6:同 bitwarderd,先裝 ring provider 根除 auto-detect panic。
    bw_btp::tls::init_crypto_provider();
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// B1：連上本機 daemon socket 後，用 `getpeereid` 驗對端程序 uid 等於自己。
/// 世界可寫目錄被他人搶佔時，連上的可能是偽造 server；交 token／主密碼前先擋。
fn verify_server_peer(stream: &tokio::net::UnixStream) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    match bw_btp::peer_uid_from_fd(stream.as_raw_fd()) {
        Ok(uid) if uid == unsafe { libc::geteuid() } => Ok(()),
        Ok(uid) => Err(format!(
            "daemon socket 對端 uid {uid} 非本使用者（{}），拒絕（目錄可能被搶佔）",
            unsafe { libc::geteuid() }
        )),
        Err(e) => Err(format!("無法驗證 daemon socket 對端 uid：{e}")),
    }
}

async fn open_session(
    sock: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<
    (
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
        WireFormat,
    ),
    String,
> {
    // 一次 Session 續用；被拒（daemon 重啟過）則刪檔重 Enroll 一次。
    for attempt in 0..2u8 {
        let stream = tokio::net::UnixStream::connect(sock)
            .await
            .map_err(|_| format!("連不到 daemon（{}）；先啟動 bitwarderd", sock.display()))?;
        // B1：經搶佔目錄連上的可能是他人偽造的 socket，連上即驗對端 uid＝本使用者，
        // 否則把 token／主密碼交給對方前就擋下。
        verify_server_peer(&stream)?;
        let (mut rd, mut wr) = stream.into_split();
        let saved: Option<SessionToken> = if attempt == 0 {
            std::fs::read_to_string(session_file(data_dir))
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        let fresh = Uuid::new_v4().to_string();
        let auth = match saved {
            Some(t) => Auth::Session { token: t },
            None => Auth::Enroll {
                pairing: fresh.clone(),
                display_name: format!("cli:{}", std::process::id()),
                pair_code: None,
            },
        };
        write_client(
            &mut wr,
            WireFormat::Json,
            &ClientMsg::Hello {
                version: ProtoVersion(PROTO_VERSION),
                auth: auth.clone(),
                wants: vec![],
                formats: wire::supported_formats(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        match read_server(&mut rd, WireFormat::Json).await {
            Ok(ServerMsg::Welcome { proto, format, .. }) => {
                if let Some(s) = proto_mismatch(proto) {
                    return Err(s);
                }
                if matches!(auth, Auth::Enroll { .. }) {
                    let _ = std::fs::write(session_file(data_dir), &fresh);
                }
                return Ok((rd, wr, format));
            }
            Ok(ServerMsg::Error { message }) if attempt == 0 => {
                // daemon 明確拒絕（重啟過/隨鎖撤銷）：刪檔重 Enroll 續跑，但必須留痕
                // （readpath A6 的可觀察性）——靜默癒合會把「lock＝撤銷」洗成無感成功。
                eprintln!("warning: session 失效（{message}）；已重入會（enroll）並續跑指令");
                let _ = std::fs::remove_file(session_file(data_dir));
            }
            Ok(ServerMsg::Error { message }) => return Err(message),
            Ok(other) => return Err(format!("expected Welcome, got {other:?}")),
            Err(e) if attempt == 0 => {
                // 撤銷/失效必須留痕（readpath A6 的可觀察性）：靜默重 Enroll 會把
                // 「lock 級聯撤銷」這個安全語意洗成無感成功。
                eprintln!("warning: session 失效（{e}）；已重入會（enroll）並續跑指令");
                let _ = std::fs::remove_file(session_file(data_dir));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    unreachable!()
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    match &args.cmd {
        Cmd::DevRegister {
            server,
            email,
            password_stdin,
        } => return dev_register(server, email, *password_stdin).await,
        Cmd::DevSeed {
            name,
            uri,
            password,
        } => {
            let (server, email) = seed_target(&args)?;
            return dev_seed(&server, &email, name, uri, password).await;
        }
        // 接收方路徑：金鑰在 URL 片段、讀取不需帳號——完全不經 daemon
        // （接收方可能根本沒跑 daemon），故與 dev-* 同列提前返回。
        Cmd::Send {
            cmd:
                SendCmd::Access {
                    url,
                    password_stdin,
                    out,
                },
        } => {
            let pw = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            let accessed = access_send(url, pw.as_deref()).await?;
            return emit_accessed(accessed, out.as_deref(), args.json);
        }
        _ => {}
    }
    let data_dir = default_data_dir();
    if let Cmd::Pair {
        cmd: PairCmd::Join { .. },
    } = &args.cmd
    {
        return pair_join(&args, &data_dir).await;
    }
    if let Cmd::Hub { cmd } = &args.cmd {
        return hub_cmd(cmd, &data_dir, args.json).await;
    }
    let sock = args.sock.clone().unwrap_or_else(|| default_sock(&data_dir));
    let (mut rd, mut wr, fmt): (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        WireFormat,
    ) = match &args.remote {
        None => match open_session(&sock, &data_dir).await {
            Ok((r, w, f)) => (Box::new(r), Box::new(w), f),
            Err(le) => {
                // 編組 failover（§1.1）：本地中樞不可達且設了預設 hub→改用預設並
                // 留可懂提示；預設也失聯→HubOffline＋換 hub 指引（Lane 5 終態）。
                match route_hub(None, false, read_default_hub(&data_dir)) {
                    HubRoute::Failover(d) => {
                        eprintln!(
                            "warning: 本地 daemon 不可達（{le}）；改用預設 hub「{d}」（bitward hub default none 關閉此行為）"
                        );
                        open_remote(&d, &data_dir).await.map_err(|e| {
                            format!("{e}；{}", failover_hint(&d, &list_hub_profiles(&data_dir)))
                        })?
                    }
                    _ => return Err(le),
                }
            }
        },
        Some(profile) => open_remote(profile, &data_dir).await?,
    };

    let call = build_call(&args.cmd)?;
    if matches!(args.cmd, Cmd::Autotype { .. }) {
        // 倒數在 daemon 端跑，stderr 提示讓使用者抓時機切視窗
        eprintln!("AutoType: 準備倒數 3 秒後注入按鍵，請切到目標視窗");
    }
    let rid = 1u64;
    write_client(
        &mut wr,
        fmt,
        &ClientMsg::Invoke {
            rid,
            call: call.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut reply = await_reply(&mut rd, fmt, rid).await?;
    if matches!(args.cmd, Cmd::Login { .. }) {
        reply = login_2fa_rounds(&mut rd, &mut wr, fmt, &call, reply, rid).await?;
    }
    match reply {
        Ok(resp) => {
            // 二進位出口統一落檔：附件下載與圖示代理同形（AttachmentBytes）
            let bin_out = match &args.cmd {
                Cmd::Attach {
                    cmd: AttachCmd::Get { out, .. },
                }
                | Cmd::Icon { out, .. } => Some(out.clone()),
                _ => None,
            };
            if let (Some(out), Response::AttachmentBytes(bytes)) = (&bin_out, &resp) {
                // 附件內容寫檔不走 stdout（二進位；`-`＝stdout 供管線）
                if out == "-" {
                    use std::io::Write as _;
                    std::io::stdout()
                        .write_all(bytes)
                        .map_err(|e| e.to_string())?;
                } else {
                    std::fs::write(out, bytes).map_err(|e| format!("寫檔失敗：{e}"))?;
                    println!("ok ({} bytes)", bytes.len());
                }
                return Ok(());
            }
            if matches!(args.cmd, Cmd::ChangePassword) && matches!(resp, Response::Ok) && !args.json
            {
                println!("主密碼已變更");
            } else if !args.json
                && matches!(
                    &args.cmd,
                    Cmd::Send {
                        cmd: SendCmd::Url { .. } | SendCmd::Text { .. } | SendCmd::File { .. }
                    }
                )
                && let Response::Json(v) = &resp
                && let Some(u) = v.get("url").and_then(|x| x.as_str())
            {
                // 單一 URL 列：管線友善（$(bitward send url …)）；--json 才出整包
                println!("{u}");
            } else {
                print_response(&resp, args.json);
            }
            Ok(())
        }
        Err(e) => Err(wtp_to_string(&e)),
    }
}

fn proto_mismatch(peer: u16) -> Option<String> {
    if peer > PROTO_VERSION {
        Some(format!("daemon proto {peer} > CLI {PROTO_VERSION}"))
    } else {
        None
    }
}

type BoxRd = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxWr = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
type Reply = Result<Response, WtpError>;

async fn await_reply(rd: &mut BoxRd, fmt: WireFormat, rid: u64) -> Result<Reply, String> {
    loop {
        match read_server(rd, fmt).await.map_err(|e| e.to_string())? {
            ServerMsg::Reply { rid: r, outcome } if r == rid => return Ok(outcome),
            ServerMsg::Event { .. } => continue,
            other => return Err(format!("unexpected {other:?}")),
        }
    }
}

/// 登入 2FA 回合：daemon 回 TwoFactorRequest → stderr 列因子、stdin 收
/// 「因子編號＋6 位碼」→ 原樣重發 Login（password 再送一次，hash 由 daemon
/// 重算；本機線明文紀律同第一步）。碼錯時 VW 回「Invalid TOTP code」錯誤
/// （非新挑戰）→ 原樣返回讓末段顯示原文，使用者重跑 login 即可。
async fn login_2fa_rounds(
    rd: &mut BoxRd,
    wr: &mut BoxWr,
    fmt: WireFormat,
    first: &Call,
    reply: Reply,
    mut rid: u64,
) -> Result<Reply, String> {
    let mut reply = reply;
    let Call::Auth(AuthCall::Login {
        server,
        email,
        password,
        api_key,
        ..
    }) = first
    else {
        unreachable!("login_2fa_rounds 只接 Login call");
    };
    let mut last_pick: Option<i32> = None;
    for _ in 0..5 {
        let providers = match &reply {
            Ok(Response::TwoFactorRequest { providers }) if !providers.is_empty() => {
                providers.clone()
            }
            _ => {
                // 救援碼是一次性的：用掉之後伺服器把該帳號的 2FA 全部清空
                // （Vaultwarden `identity.rs:874-881`：`TwoFactor::delete_all_by_user`
                // ＋清 totp_recover）。使用者必須知道下次登入不再被挑戰。
                if matches!(last_pick, Some(8)) && matches!(reply, Ok(Response::Status(_))) {
                    eprintln!(
                        "注意：本次以備用救援碼登入，伺服器已清空該帳號的全部第二因子（含救援碼）。\
                         請到 GUI 設定頁「雙重驗證」重新啟用因子。"
                    );
                }
                return Ok(reply);
            }
        };
        eprintln!("此帳號需要第二因子驗證。可用因子：");
        for p in &providers {
            let gate = if !TwoFactorProviderInfo::is_supported(p.provider) {
                "（此因子尚未支援）".to_owned()
            } else if !TwoFactorProviderInfo::usable_on(p.provider, false) {
                // CLI 沒有 webview／原生憑證島： Duo 與 WebAuthn 得回 GUI 完成。
                "（需在 GUI 登入完成）".to_owned()
            } else {
                String::new()
            };
            let hint = p
                .hint
                .as_deref()
                .map(|h| format!("：{h}"))
                .unwrap_or_default();
            eprintln!(
                "  [{}] {}{hint}{gate}",
                p.provider,
                TwoFactorProviderInfo::label(p.provider)
            );
        }
        let default = providers
            .iter()
            .find(|p| TwoFactorProviderInfo::usable_on(p.provider, false))
            .map(|p| p.provider);
        match default {
            Some(d) => eprintln!("選擇因子編號（預設 {d}）："),
            None => eprintln!("選擇因子編號："),
        }
        let pick_line = read_line_stdin()?;
        let pick = match pick_line.trim() {
            "" => default,
            s => s
                .parse::<i32>()
                .ok()
                .filter(|n| providers.iter().any(|p| p.provider == *n)),
        };
        let Some(pick) = pick else {
            eprintln!("輸入無效：請輸入上面列出的因子編號");
            reply = Ok(Response::TwoFactorRequest {
                providers: providers.clone(),
            });
            continue;
        };
        if !TwoFactorProviderInfo::usable_on(pick, false) {
            let why = if TwoFactorProviderInfo::is_supported(pick) {
                "本因子需在 GUI 完成交涉（Duo 網頁／安全金鑰）"
            } else {
                "此因子尚未支援，請改選其他因子"
            };
            eprintln!("{}：{}（{why}）", TwoFactorProviderInfo::label(pick), pick);
            reply = Ok(Response::TwoFactorRequest {
                providers: providers.clone(),
            });
            continue;
        }
        let placeholder = TwoFactorProviderInfo::factor_mode(pick)
            .map(|m| m.placeholder())
            .unwrap_or("驗證碼");
        eprintln!("輸入{placeholder}：");
        let code = read_line_stdin()?;
        let code = match TwoFactorProviderInfo::validate_token(pick, &code) {
            Ok(c) => c,
            Err(msg) => {
                eprintln!("輸入格式不對：{msg}");
                reply = Ok(Response::TwoFactorRequest {
                    providers: providers.clone(),
                });
                continue;
            }
        };
        last_pick = Some(pick);
        rid += 1;
        let next = Call::Auth(AuthCall::Login {
            server: server.clone(),
            email: email.clone(),
            password: password.clone(),
            api_key: api_key.clone(),
            two_factor: Some(TwoFactorInput {
                provider: pick,
                token: code,
                remember: false,
            }),
        });
        write_client(wr, fmt, &ClientMsg::Invoke { rid, call: next })
            .await
            .map_err(|e| e.to_string())?;
        reply = await_reply(rd, fmt, rid).await?;
    }
    Err("第二因子嘗試次數過多（5 次）；請重試 login".into())
}

/// `pair join` 後的跨機身分檔：remotes/<profile>.json
#[derive(serde::Serialize, serde::Deserialize)]
struct RemoteProfile {
    url: String,
    pin: String,
    token: SessionToken,
    #[serde(default)]
    wake: Option<String>,
}

/// 配對目標默認 port（E4：tailnet 磁標只給 hostname 時用；daemon `--listen` 建議綁此）。
const DEFAULT_PAIR_PORT: u16 = 8443;

/// 目標解析（E4）：吃 `https://host:port`、`host:port`、裸 `host`（磁標→默認 port）。
/// IPv6 字面量不支援（配對目標實務為 DNS/tailnet 名）；不引入新傳輸。
fn split_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    if rest.is_empty() || rest.contains('/') {
        return Err("目標形態應為 host[:port]（不含 path）".into());
    }
    match rest.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Ok((
            h.to_owned(),
            p.parse::<u16>()
                .map_err(|e: std::num::ParseIntError| format!("port 非法：{e}"))?,
        )),
        Some(_) => Err("port 前缺 host".into()),
        None => Ok((rest.to_owned(), DEFAULT_PAIR_PORT)),
    }
}

/// 100.64.0.0/10＝Tailscale CGNAT 段（RFC 6598）：tailnet 磁標解析落此段即經隧道。
fn is_tailscale_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xC0) == 0x40
        }
        _ => false,
    }
}

/// 配對目標 hostname→IP 注記（解析交系統/MagicDNS）；純診斷面，失敗不擋連線。
async fn note_target(host: &str, port: u16) {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return; // 已是數值位址，無需解析注記
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            match addrs.first() {
                Some(sa) => {
                    let tag = if is_tailscale_addr(&sa.ip()) {
                        "（Tailscale）"
                    } else {
                        ""
                    };
                    eprintln!("note: {host} → {}{tag}", sa.ip());
                }
                None => eprintln!("note: {host} 無解析結果"),
            }
        }
        Err(e) => eprintln!("note: {host} 解析失敗：{e}"),
    }
}

async fn pair_join(args: &Args, data_dir: &Path) -> Result<(), String> {
    let PairCmd::Join {
        url,
        pin,
        code,
        name,
        wake,
        profile,
    } = (match &args.cmd {
        Cmd::Pair { cmd } => cmd,
        _ => unreachable!(),
    })
    else {
        unreachable!()
    };
    let (host, port) = split_url(url)?;
    note_target(&host, port).await;
    let stream = bw_btp::tls::connect(&host, port, pin)
        .await
        .map_err(|e| format!("TLS 連線失敗（pin 正確？）：{e}"))?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let fresh = Uuid::new_v4().to_string();
    write_client(
        &mut wr,
        WireFormat::Json,
        &ClientMsg::Hello {
            version: ProtoVersion(PROTO_VERSION),
            auth: Auth::Enroll {
                pairing: fresh.clone(),
                display_name: format!("remote:{name}"),
                pair_code: Some(code.clone()),
            },
            wants: vec![],
            formats: wire::supported_formats(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match read_server(&mut rd, WireFormat::Json)
        .await
        .map_err(|e| e.to_string())?
    {
        ServerMsg::Welcome { .. } => {}
        ServerMsg::Reply {
            outcome: Err(e), ..
        } => return Err(format!("join 被拒：{e}")),
        other => return Err(format!("預期 Welcome，got {other:?}")),
    }
    let dir = data_dir.join("remotes");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let prof = RemoteProfile {
        // 落檔一律正規形態（磁標/缺 port 輸入在連線端已解析）
        url: format!("https://{host}:{port}"),
        pin: pin.clone(),
        token: fresh,
        wake: wake.clone(),
    };
    let path = dir.join(format!("{profile}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&prof).unwrap()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    println!("paired → --remote {profile} ({})", path.display());
    Ok(())
}

async fn probe_tcp(url: &str) -> &'static str {
    let Ok((host, port)) = split_url(url) else {
        return "bad-url";
    };
    match tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => "online",
        Ok(Err(_)) => "offline",
        Err(_) => "timeout",
    }
}

async fn probe_local(sock: &Path) -> &'static str {
    match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::UnixStream::connect(sock),
    )
    .await
    {
        Ok(Ok(_)) => "online",
        _ => "offline",
    }
}

/// `hub ls`/`hub default`：純本機檔案操作（registry＝remotes/ 目錄＋.default 指標），
/// 不連任何 daemon——本地中樞缺席時仍要能用來修 failover 設定。
async fn hub_cmd(cmd: &HubCmd, data_dir: &Path, json: bool) -> Result<(), String> {
    match cmd {
        HubCmd::Ls { probe } => {
            let default = read_default_hub(data_dir);
            let mut rows = Vec::new();
            let local_sock = default_sock(data_dir);
            let local_health = if *probe {
                probe_local(&local_sock).await
            } else {
                "-"
            };
            rows.push(serde_json::json!({
                "name": "(local)", "url": local_sock.display().to_string(),
                "default": false, "last_seen": null, "probe": local_health,
            }));
            for p in list_hub_profiles(data_dir) {
                let path = data_dir.join("remotes").join(format!("{p}.json"));
                let prof: RemoteProfile =
                    serde_json::from_slice(&std::fs::read(&path).map_err(|e| format!("{p}: {e}"))?)
                        .map_err(|e| format!("{p}.json 形態不合：{e}"))?;
                let seen = hub_last_seen(data_dir, &p);
                let health = if *probe {
                    probe_tcp(&prof.url).await
                } else {
                    "-"
                };
                rows.push(serde_json::json!({
                    "name": p, "url": prof.url,
                    "default": default.as_deref() == Some(p.as_str()),
                    "last_seen": seen, "probe": health,
                }));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rows).unwrap());
                return Ok(());
            }
            println!(
                "{:<12} {:<44} {:<8} {:<14} {}",
                "HUB",
                "URL",
                "DEFAULT",
                "LAST_SEEN",
                if *probe { "PROBE" } else { "" }.trim_end()
            );
            for r in &rows {
                let seen = match r["last_seen"].as_u64() {
                    Some(ms) => format!("{}s ago", chrono_now_ms().saturating_sub(ms) / 1000),
                    None => "never".into(),
                };
                let star = if r["default"].as_bool().unwrap_or(false) {
                    "*"
                } else {
                    ""
                };
                println!(
                    "{:<12} {:<44} {:<8} {:<14} {}",
                    r["name"].as_str().unwrap_or("?"),
                    r["url"].as_str().unwrap_or("?"),
                    star,
                    seen,
                    r["probe"].as_str().unwrap_or("-")
                );
            }
            if default.is_none() {
                eprintln!(
                    "hint: 未設預設 hub（`bitward hub default <name>` 開啟本地不可達時的 failover）"
                );
            }
        }
        HubCmd::Default { profile } => {
            let f = data_dir.join("remotes").join(DEFAULT_HUB_FILE);
            if profile == "none" {
                let _ = std::fs::remove_file(&f);
                println!("已清除預設 hub（failover 關閉，本地 daemon 不可達即報錯）");
            } else {
                if !list_hub_profiles(data_dir).iter().any(|p| p == profile) {
                    return Err(format!(
                        "沒有 hub profile「{profile}」（bitward hub ls 列清單；bitward pair join 建立）"
                    ));
                }
                std::fs::write(&f, profile).map_err(|e| e.to_string())?;
                println!(
                    "預設 hub＝{profile}（本地 daemon 不可達時自動改用；bitward hub default none 清除）"
                );
            }
        }
    }
    Ok(())
}

/// 跨機連線：HubOffline 快速失敗 + 可選 wake 信令後重試一次（§1.2）
async fn open_remote(profile: &str, data_dir: &Path) -> Result<(BoxRd, BoxWr, WireFormat), String> {
    let path = data_dir.join("remotes").join(format!("{profile}.json"));
    let prof: RemoteProfile =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let (host, port) = split_url(&prof.url)?;
    let last_ok_path = data_dir.join(format!("remote_{profile}_last_ok"));

    for attempt in 0..2u8 {
        match try_remote(&host, port, &prof).await {
            Ok(pair) => {
                let _ = std::fs::write(&last_ok_path, chrono_now_ms().to_string());
                return Ok(pair);
            }
            Err(e) => {
                // 第一次失敗：發喚醒信令（endpoint 即能力憑證），稍後重試一次
                if attempt == 0
                    && let Some(wake) = &prof.wake
                {
                    let body = "bitward wake".to_string();
                    let url = wake.clone();
                    tokio::spawn(async move {
                        let _ = reqwest::Client::new().post(url).body(body).send().await;
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    continue;
                }
                let seen = std::fs::read_to_string(&last_ok_path).unwrap_or_default();
                return Err(format!(
                    "HubOffline（last_seen={}）：{e}",
                    if seen.is_empty() { "never" } else { &seen }
                ));
            }
        }
    }
    unreachable!()
}

async fn try_remote(
    host: &str,
    port: u16,
    prof: &RemoteProfile,
) -> Result<(BoxRd, BoxWr, WireFormat), String> {
    let stream = bw_btp::tls::connect(host, port, &prof.pin)
        .await
        .map_err(|e| e.to_string())?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    write_client(
        &mut wr,
        WireFormat::Json,
        &ClientMsg::Hello {
            version: ProtoVersion(PROTO_VERSION),
            auth: Auth::Session {
                token: prof.token.clone(),
            },
            wants: vec![],
            formats: wire::supported_formats(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match read_server(&mut rd, WireFormat::Json)
        .await
        .map_err(|e| e.to_string())?
    {
        ServerMsg::Welcome { proto, format, .. } => {
            if let Some(s) = proto_mismatch(proto) {
                return Err(s);
            }
            Ok((Box::new(rd), Box::new(wr), format))
        }
        other => Err(format!("expected Welcome, got {other:?}")),
    }
}

fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn build_call(cmd: &Cmd) -> Result<Call, String> {
    Ok(match cmd {
        Cmd::Login {
            server,
            email,
            password_stdin,
        } => {
            // 只取第一行＝主密碼；後續行留給 2FA 回合（選因子、驗證碼）。
            let pw = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            Call::Auth(AuthCall::Login {
                server: server.clone(),
                email: email.clone(),
                password: pw,
                api_key: None,
                two_factor: None,
            })
        }
        Cmd::Unlock {
            password_stdin,
            biometric,
        } => Call::Auth(AuthCall::Unlock {
            biometric: *biometric,
            password: password_stdin.then(read_line_stdin).transpose()?,
        }),
        Cmd::Lock => Call::Auth(AuthCall::Lock),
        Cmd::ChangePassword => {
            // 提示與警告走 stderr，stdout 留給結果行（機器可讀慣例）。
            // 強度閘不在此重複實作——daemon（hub::MIN_MASTER_PASSWORD）是唯一
            // 真相源，短碼由它拒絕、錯誤原文經 Reply 回程顯示。
            eprintln!(
                "請依序輸入現有主密碼、新主密碼（至少 12 字元）；注意：改密後其他裝置需重新登入"
            );
            let current = read_line_stdin()?;
            let new = read_line_stdin()?;
            Call::Auth(AuthCall::ChangePassword {
                current: Some(current),
                new: Some(new),
            })
        }
        Cmd::Status => Call::Admin(AdminCall::Diagnostics),
        Cmd::TwoFactor { cmd } => Call::TwoFactor(match cmd {
            TwoFactorCmd::Ls => TwoFactorCall::List,
            TwoFactorCmd::TotpKey => TwoFactorCall::GetAuthenticator {
                master_password: Some(read_line_stdin()?),
            },
            TwoFactorCmd::TotpEnable { key } => TwoFactorCall::EnableAuthenticator {
                master_password: Some(read_line_stdin()?),
                token: read_line_stdin()?,
                key: key.clone(),
            },
            TwoFactorCmd::Recovery => TwoFactorCall::GetRecoveryCode {
                master_password: Some(read_line_stdin()?),
            },
            TwoFactorCmd::EmailSend { email } => TwoFactorCall::EmailSendCode {
                master_password: Some(read_line_stdin()?),
                email: email.clone(),
            },
            TwoFactorCmd::EmailVerify { email, token } => TwoFactorCall::EmailVerify {
                master_password: Some(read_line_stdin()?),
                email: email.clone(),
                token: token.clone(),
            },
            TwoFactorCmd::YubikeyAdd => TwoFactorCall::EnableYubikey {
                master_password: Some(read_line_stdin()?),
                otp: read_line_stdin()?,
            },
            TwoFactorCmd::Disable { provider } => TwoFactorCall::Disable {
                master_password: Some(read_line_stdin()?),
                provider: *provider,
            },
        }),
        Cmd::Ea { cmd } => Call::EmergencyAccess(match cmd {
            EaCmd::Ls { granted } => {
                if *granted {
                    EaCall::ListGrantors
                } else {
                    EaCall::ListGrantees
                }
            }
            EaCmd::Invite {
                email,
                r#type,
                days,
            } => EaCall::Invite {
                email: email.clone(),
                access_type: match r#type.as_str() {
                    "takeover" => EaAccessType::Takeover,
                    "view" => EaAccessType::View,
                    other => return Err(format!("--type 只收 view|takeover（收到 {other}）")),
                },
                wait_time_days: *days,
            },
            EaCmd::Confirm { id } => EaCall::Confirm { ea_id: id.clone() },
            EaCmd::Revoke { id } => EaCall::Revoke { ea_id: id.clone() },
            EaCmd::Initiate { id } => EaCall::Initiate { ea_id: id.clone() },
            EaCmd::Approve { id } => EaCall::Approve { ea_id: id.clone() },
            EaCmd::Reject { id } => EaCall::Reject { ea_id: id.clone() },
            EaCmd::View { id } => EaCall::View { ea_id: id.clone() },
            EaCmd::Takeover { id } => EaCall::Takeover {
                ea_id: id.clone(),
                new_password: read_line_stdin()?,
            },
        }),
        Cmd::Settings { cmd } => match cmd {
            SettingsCmd::Show => Call::Admin(AdminCall::GetSettings),
            SettingsCmd::Set { payload } => {
                let s: Settings = serde_json::from_str(payload)
                    .map_err(|e| format!("settings JSON 不通：{e}"))?;
                Call::Admin(AdminCall::SetSettings(s))
            }
        },
        Cmd::Sync => Call::Sync(SyncCall::Trigger { force: true }),
        Cmd::Ls {
            text,
            tag,
            uri,
            value,
            collection,
            folder,
            trash,
            archived,
            sort,
            limit,
        } => Call::Vault(VaultCall::List {
            query: Query {
                text: text.clone(),
                tag: tag.clone(),
                uri: uri.clone(),
                value: value.clone(),
                kind: None,
                sort: match sort.as_str() {
                    "updated" => SortKey::Updated,
                    "created" => SortKey::Created,
                    "used" => SortKey::Used,
                    _ => SortKey::Name,
                },
                limit: *limit,
                collection: collection.as_deref().map(parse_id).transpose()?,
                folder: folder.clone(),
                deleted: trash.then_some(true),
                archived: archived.then_some(true),
            },
            view: View::Metadata,
        }),
        Cmd::Get { id, view } => Call::Vault(VaultCall::Get {
            id: parse_id(id)?,
            view: match view.as_str() {
                "masked" => View::Masked,
                "reveal" => View::Reveal,
                _ => View::Metadata,
            },
        }),
        Cmd::Reveal { id } => Call::Vault(VaultCall::Get {
            id: parse_id(id)?,
            view: View::Reveal,
        }),
        Cmd::Totp { id } => Call::Use(UseCall::TotpCode { id: parse_id(id)? }),
        // policy 欄名與 daemon 讀取端一致（length/lowercase/uppercase/numbers/
        // special/avoidAmbiguous）；值域把關在引擎（5–128），CLI 不重複驗。
        Cmd::Generate {
            length,
            no_lowercase,
            no_uppercase,
            no_numbers,
            no_special,
            avoid_ambiguous,
        } => Call::Use(UseCall::GeneratePassword {
            policy: bw_proto::PasswordPolicy {
                length: *length,
                lowercase: !no_lowercase,
                uppercase: !no_uppercase,
                numbers: !no_numbers,
                special: !no_special,
                avoid_ambiguous: *avoid_ambiguous,
            },
        }),
        Cmd::Autotype { id, template } => Call::Fill(FillCall::AutoType {
            id: parse_id(id)?,
            template: template.clone(),
        }),
        Cmd::Passkey { cmd } => match cmd {
            PasskeyCmd::List { rp } => {
                Call::Passkey(PasskeyCall::GetPasskeys { rp_id: rp.clone() })
            }
            PasskeyCmd::Register {
                rp,
                user,
                challenge,
                handle,
                display,
                item,
                public_key,
            } => Call::Passkey(PasskeyCall::RegisterPasskey {
                rp_id: rp.clone(),
                challenge: challenge.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
                credential_public_key: public_key.clone(),
            }),
            PasskeyCmd::BeginRegister {
                rp,
                user,
                handle,
                display,
                item,
            } => Call::Passkey(PasskeyCall::BeginRegister {
                rp_id: rp.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
            }),
            PasskeyCmd::FinishRegister {
                credential,
                public_key,
                rp,
                user,
                challenge,
                handle,
                display,
                item,
            } => Call::Passkey(PasskeyCall::FinishRegister {
                credential_id: credential.clone(),
                credential_public_key: public_key.clone(),
                rp_id: rp.clone(),
                challenge: challenge.clone(),
                user_name: user.clone(),
                user_handle: handle.clone().unwrap_or_else(|| user.clone()),
                display_name: display.clone().unwrap_or_else(|| user.clone()),
                item_id: item.as_deref().map(parse_id).transpose()?,
            }),
            PasskeyCmd::Assert {
                credential,
                challenge,
                rp,
                hash,
                signature,
                key_id,
            } => Call::Passkey(PasskeyCall::AssertPasskey {
                credential_id: credential.clone(),
                challenge: challenge.clone(),
                rp_id: rp.clone(),
                // CLI 走標準流（自組 JSON）；Apple provider 流由 Swift 端帶 hash。
                client_data_hash: hash.clone(),
                // Some = 簽名已在呼叫端（模擬 Swift SE 簽名路徑）
                signature: signature.clone(),
                key_id: key_id.clone(),
            }),
            PasskeyCmd::Begin { credential, hash } => Call::Passkey(PasskeyCall::BeginAssert {
                credential_id: credential.clone(),
                client_data_hash: hash.clone(),
            }),
            PasskeyCmd::Finish {
                credential,
                signature,
            } => Call::Passkey(PasskeyCall::FinishAssert {
                credential_id: credential.clone(),
                signature: signature.clone(),
            }),
            PasskeyCmd::Rm { item, credential } => Call::Passkey(PasskeyCall::DeletePasskey {
                item_id: parse_id(item)?,
                credential_id: credential.clone(),
            }),
        },
        Cmd::Audit { tail, verify } => {
            if *verify {
                Call::Agent(AgentCall::AuditVerify)
            } else {
                Call::Agent(AgentCall::Audit {
                    since: None,
                    limit: *tail,
                })
            }
        }
        Cmd::Version => Call::Admin(AdminCall::Version),
        Cmd::New {
            name,
            type_,
            username,
            password_stdin,
            uri,
            totp,
            notes,
            folder,
            fields,
            hidden_fields,
            bool_fields,
            card_fields,
            identity_fields,
        } => {
            let password = if *password_stdin {
                Some(read_line_stdin()?)
            } else {
                None
            };
            let kind = match type_.as_str() {
                "login" => ItemKind::Login,
                "note" => ItemKind::SecureNote,
                "card" => ItemKind::Card,
                "identity" => ItemKind::Identity,
                other => {
                    return Err(format!(
                        "--type 僅支援 login|note|card|identity，got {other}"
                    ));
                }
            };
            let mut draft_fields = parse_field_pairs(fields, CipherFieldKind::Text)?;
            draft_fields.extend(parse_field_pairs(hidden_fields, CipherFieldKind::Hidden)?);
            draft_fields.extend(parse_field_pairs(bool_fields, CipherFieldKind::Boolean)?);
            // 型別節（PR1）：`--card k=v`／`--identity k=v` 走官方鍵名白名單；
            // 值 `-`＝stdin 一行（卡號/CVV 不落 argv，A11）。
            let mut card = bw_proto::CardDraft::default();
            for p in card_fields {
                let (k, v) = p
                    .split_once('=')
                    .ok_or_else(|| format!("--card 需要 path=value，got {p}"))?;
                let v = if v == "-" {
                    read_line_stdin()?
                } else {
                    v.to_owned()
                };
                card.slot_mut(k)
                    .ok_or_else(|| format!("未知 card 欄名 {k:?}（值域 cardholderName|brand|number|expMonth|expYear|code）"))?
                    .replace(v);
            }
            let mut identity = bw_proto::IdentityDraft::default();
            for p in identity_fields {
                let (k, v) = p
                    .split_once('=')
                    .ok_or_else(|| format!("--identity 需要 path=value，got {p}"))?;
                let v = if v == "-" {
                    read_line_stdin()?
                } else {
                    v.to_owned()
                };
                identity
                    .slot_mut(k)
                    .ok_or_else(|| format!("未知 identity 欄名 {k:?}"))?
                    .replace(v);
            }
            let has_card = card_fields.iter().next().is_some();
            let has_identity = identity_fields.iter().next().is_some();
            Call::Vault(VaultCall::Create {
                draft: CipherDraft {
                    kind,
                    name: name.clone(),
                    username: username.clone(),
                    password,
                    totp: totp.clone(),
                    uris: uri.clone().into_iter().collect(),
                    // CLI new 不帶判定下拉（官方新建預設 null）；GUI 建立面走 draft.uri_matches
                    uri_matches: Vec::new(),
                    notes: notes.clone(),
                    favorite: false,
                    folder_id: folder.clone(),
                    fields: draft_fields,
                    card: has_card.then_some(card),
                    identity: has_identity.then_some(identity),
                },
            })
        }
        Cmd::Folder { cmd } => match cmd {
            FolderCmd::Ls => Call::Vault(VaultCall::ListFolders),
            FolderCmd::Create { name } => {
                Call::Vault(VaultCall::CreateFolder { name: name.clone() })
            }
            FolderCmd::Delete { id } => Call::Vault(VaultCall::DeleteFolder { id: parse_id(id)? }),
        },
        Cmd::Archive { id, on } => Call::Vault(VaultCall::SetArchived {
            id: parse_id(id)?,
            archived: match on.as_str() {
                "true" => true,
                "false" => false,
                other => return Err(format!("archive 值需 true|false，got {other}")),
            },
        }),
        Cmd::Icon { host, .. } => Call::Vault(VaultCall::GetIcon { host: host.clone() }),
        Cmd::Purge { id } => Call::Vault(VaultCall::Purge { id: parse_id(id)? }),
        Cmd::Edit {
            id,
            sets,
            set_types,
            appends,
            appends_hidden,
            appends_bool,
            removes,
            append_uris,
            remove_uris,
            set_uri_matches,
            clears,
            secret_stdin,
        } => {
            let mut edits = Vec::new();
            for s in sets {
                let (path, value) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set 需要 path=value， got {s}"))?;
                let value = if value == "-" || *secret_stdin {
                    read_line_stdin()?
                } else {
                    value.to_owned()
                };
                edits.push(FieldEdit::Set {
                    path: path.to_owned(),
                    value: Some(value),
                });
            }
            for s in set_types {
                let (idx, kind) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set-type 需要 index=kind， got {s}"))?;
                let index = idx
                    .parse::<u32>()
                    .map_err(|_| format!("--set-type index 需為數字，got {idx}"))?;
                let kind = match kind {
                    "text" => CipherFieldKind::Text,
                    "hidden" => CipherFieldKind::Hidden,
                    "boolean" => CipherFieldKind::Boolean,
                    other => {
                        return Err(format!("--set-type 值域 text|hidden|boolean，got {other}"));
                    }
                };
                edits.push(FieldEdit::SetType { index, kind });
            }
            for (pairs, kind) in [
                (appends, CipherFieldKind::Text),
                (appends_hidden, CipherFieldKind::Hidden),
                (appends_bool, CipherFieldKind::Boolean),
            ] {
                for f in parse_field_pairs(pairs, kind)? {
                    edits.push(FieldEdit::AppendField { field: f });
                }
            }
            for r in removes {
                edits.push(FieldEdit::RemoveField { index: *r });
            }
            for u in append_uris {
                edits.push(FieldEdit::AppendUri { uri: u.clone() });
            }
            for r in remove_uris {
                edits.push(FieldEdit::RemoveUri { index: *r });
            }
            for s in set_uri_matches {
                let (idx, val) = s
                    .split_once('=')
                    .ok_or_else(|| format!("--set-uri-match 需要 index=match， got {s}"))?;
                let index = idx
                    .parse::<u32>()
                    .map_err(|_| format!("--set-uri-match index 需為數字，got {idx}"))?;
                let match_type = match val {
                    "null" => None,
                    v => Some(
                        v.parse::<u8>()
                            .map_err(|_| format!("--set-uri-match 值域 null|0..5，got {val}"))?,
                    ),
                };
                edits.push(FieldEdit::SetUriMatch { index, match_type });
            }
            for c in clears {
                edits.push(FieldEdit::Set {
                    path: c.clone(),
                    value: None,
                });
            }
            Call::Vault(VaultCall::Patch {
                id: parse_id(id)?,
                edits,
            })
        }
        Cmd::Import { file, format } => {
            let raw = if file == "-" {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            } else {
                std::fs::read_to_string(file).map_err(|e| format!("讀不到匯入檔：{e}"))?
            };
            let items = parse_import_items(&serde_json::from_str(&raw).map_err(|e| {
                format!("匯入檔需為 JSON（官方未加密匯出或本 CLI 欄位形態）：{e}")
            })?)?;
            Call::Vault(VaultCall::Import {
                items,
                format: *format,
            })
        }
        Cmd::Rm { id } => Call::Vault(VaultCall::Delete {
            ids: vec![parse_id(id)?],
        }),
        Cmd::Restore { id } => Call::Vault(VaultCall::Restore { id: parse_id(id)? }),
        Cmd::Outbox => Call::Sync(SyncCall::Status),
        Cmd::Conflicts => Call::Sync(SyncCall::ListConflicts),
        Cmd::Resolve {
            id,
            ours,
            theirs,
            keep_both,
        } => {
            let pick = if *ours {
                Resolution::Ours
            } else if *theirs {
                Resolution::Theirs
            } else if *keep_both {
                Resolution::KeepBoth
            } else {
                return Err("需要 --ours/--theirs/--keep-both".into());
            };
            Call::Sync(SyncCall::ResolveConflict {
                id: MutationId(*id),
                pick,
            })
        }
        Cmd::Pair { cmd } => match cmd {
            PairCmd::Start { name, grant, ttl } => Call::Auth(AuthCall::PairStart {
                name: name.clone(),
                grant: grant.clone(),
                ttl_secs: *ttl,
            }),
            PairCmd::List => Call::Auth(AuthCall::PairList),
            PairCmd::Revoke { code } => Call::Auth(AuthCall::PairRevoke { code: code.clone() }),
            PairCmd::Join { .. } => unreachable!("join 不經 daemon 分派"),
        },
        Cmd::Hub { .. } => unreachable!("hub 純本機，run() 提前返回"),
        Cmd::SignOut => Call::Auth(AuthCall::SignOut),
        Cmd::Attach { cmd } => match cmd {
            AttachCmd::Add { item, path } => {
                let bytes = std::fs::read(path).map_err(|e| format!("讀不到附件檔：{e}"))?;
                let file_name = Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "attachment".to_owned());
                Call::Vault(VaultCall::Attachment {
                    sub: bw_proto::AttachmentOp::Upload {
                        item_id: parse_id(item)?,
                        file_name,
                        bytes,
                    },
                })
            }
            AttachCmd::Ls { item } => Call::Vault(VaultCall::Get {
                id: parse_id(item)?,
                view: View::Masked,
            }),
            AttachCmd::Get { item, att_id, .. } => Call::Vault(VaultCall::Attachment {
                sub: bw_proto::AttachmentOp::Download {
                    item_id: parse_id(item)?,
                    attachment_id: att_id.clone(),
                },
            }),
            AttachCmd::Rm { item, att_id } => Call::Vault(VaultCall::Attachment {
                sub: bw_proto::AttachmentOp::Delete {
                    item_id: parse_id(item)?,
                    attachment_id: att_id.clone(),
                },
            }),
        },
        Cmd::Tag { cmd } => Call::Vault(VaultCall::Overlay {
            id: parse_id(match cmd {
                TagCmd::Add { id, .. } | TagCmd::Rm { id, .. } | TagCmd::Pin { id, .. } => id,
            })?,
            op: match cmd {
                TagCmd::Add { tag, .. } => OverlayOpWire::AddTag(tag.clone()),
                TagCmd::Rm { tag, .. } => OverlayOpWire::RemoveTag(tag.clone()),
                TagCmd::Pin { on, .. } => OverlayOpWire::SetPinned(on == "true"),
            },
        }),
        Cmd::Dupes => Call::Vault(VaultCall::FindDuplicates),
        Cmd::Reports { what, id } => {
            let sub = match (what.as_str(), id.as_deref()) {
                ("reuse", _) => bw_proto::Reports::PasswordReuse,
                ("weak", _) => bw_proto::Reports::WeakPasswords,
                ("history", Some(i)) => bw_proto::Reports::CipherHistory { id: parse_id(i)? },
                ("history", None) => return Err("reports history 需要 --id".into()),
                other => {
                    return Err(format!(
                        "reports 子命令值域 reuse|weak|history，got {other:?}"
                    ));
                }
            };
            Call::Vault(VaultCall::Reports { sub })
        }
        Cmd::Send { cmd } => {
            let (name, content, password, days, max, hide_email) = match cmd {
                SendCmd::Text {
                    text,
                    days,
                    password_stdin,
                    max,
                    name,
                    hide_email,
                } => (
                    name.clone(),
                    bw_proto::SendContent::Text { text: text.clone() },
                    if *password_stdin {
                        Some(read_line_stdin()?)
                    } else {
                        None
                    },
                    *days,
                    *max,
                    *hide_email,
                ),
                SendCmd::File {
                    path,
                    days,
                    password_stdin,
                    max,
                    name,
                    hide_email,
                } => {
                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.clone());
                    let bytes = std::fs::read(path).map_err(|e| format!("讀不到分享檔：{e}"))?;
                    (
                        name.clone(),
                        bw_proto::SendContent::File { file_name, bytes },
                        if *password_stdin {
                            Some(read_line_stdin()?)
                        } else {
                            None
                        },
                        *days,
                        *max,
                        *hide_email,
                    )
                }
                SendCmd::Ls => {
                    return Ok(Call::Vault(VaultCall::Send {
                        sub: bw_proto::SendOp::List,
                    }));
                }
                SendCmd::Url { id } => {
                    return Ok(Call::Vault(VaultCall::Send {
                        sub: bw_proto::SendOp::Get { id: parse_id(id)? },
                    }));
                }
                SendCmd::Rm { id } => {
                    return Ok(Call::Vault(VaultCall::Send {
                        sub: bw_proto::SendOp::Remove { id: parse_id(id)? },
                    }));
                }
                // 接收方路徑在 run() 提前返回（不連 daemon），到此＝分派漏接
                SendCmd::Access { .. } => {
                    return Err("send access 不走 daemon（內部路徑錯誤）".into());
                }
            };
            Call::Vault(VaultCall::Send {
                sub: bw_proto::SendOp::Create {
                    name,
                    content,
                    password,
                    deletion_hours: days.saturating_mul(24),
                    max_access: max,
                    hide_email,
                },
            })
        }
        Cmd::Merge { keep, dupes } => Call::Vault(VaultCall::Merge {
            keep: parse_id(keep)?,
            dupes: dupes
                .iter()
                .map(|d| parse_id(d))
                .collect::<Result<_, _>>()?,
        }),
        Cmd::Unshare { id } => Call::Vault(VaultCall::MoveToOrg {
            item: parse_id(id)?,
            org: None,
            collections: vec![],
        }),
        Cmd::Run {
            env,
            cwd,
            timeout_ms,
            argv,
        } => {
            if argv.is_empty() {
                return Err("用法：bitward run -- cmd args...".into());
            }
            Call::Use(UseCall::Run {
                plan: bw_proto::RunPlan {
                    argv: argv.clone(),
                    env: env
                        .iter()
                        .map(|e| {
                            let (k, v) = e.split_once('=').unwrap_or((e.as_str(), ""));
                            (k.to_string(), v.to_string())
                        })
                        .collect(),
                    cwd: cwd.clone(),
                    timeout_ms: *timeout_ms,
                },
            })
        }
        Cmd::Approve { id, grants } => Call::Agent(AgentCall::Approve {
            id: bw_proto::ApprovalId(parse_approval(id)?),
            grants: (!grants.is_empty()).then(|| grants.clone()),
        }),
        Cmd::Deny { id } => Call::Agent(AgentCall::Deny {
            id: bw_proto::ApprovalId(parse_approval(id)?),
        }),
        Cmd::Agent { cmd } => match cmd {
            AgentCmd::Open { name, grant, ttl } => Call::Agent(AgentCall::OpenSession {
                scopes: vec![grant.clone()],
                ttl_secs: *ttl,
                name: name.clone(),
            }),
            AgentCmd::List => Call::Agent(AgentCall::ListSessions),
            AgentCmd::Pending => Call::Agent(AgentCall::ListPending),
            AgentCmd::Revoke { id } => Call::Agent(AgentCall::Revoke {
                session: bw_proto::SessionId(parse_approval(id)?),
            }),
        },
        Cmd::DevRegister { .. } | Cmd::DevSeed { .. } => {
            unreachable!("dev 命令在連 daemon 前攔截")
        }
    })
}

fn parse_id(s: &str) -> Result<ItemId, String> {
    Uuid::parse_str(s).map_err(|e| format!("item id: {e}"))
}

/// `--field k=v` / `--field! k=v` / `--field? k=v`：官方自訂欄。
/// boolean 欄值域 true|false（與 jslib 同形存字串）。
fn parse_field_pairs(pairs: &[String], kind: CipherFieldKind) -> Result<Vec<CipherField>, String> {
    pairs
        .iter()
        .map(|s| {
            let (k, v) = s
                .split_once('=')
                .ok_or_else(|| format!("--field 需要 k=v，got {s}"))?;
            if kind == CipherFieldKind::Boolean && !matches!(v, "true" | "false") {
                return Err(format!("boolean 欄值需 true|false，got {v:?}"));
            }
            Ok(CipherField {
                name: k.to_owned(),
                value: Some(v.to_owned()),
                kind,
            })
        })
        .collect()
}

/// 匯入檔 → ImportItem 集。吃兩形態：官方未加密匯出（`{"items":[...]}`，
/// login 子物件、type 整數、uris[{uri,match}]、fields[{name,value,type}]）
/// 或本 CLI 扁平欄位形態。加密匯出（`{"encrypted":true}`）擋下。
fn parse_import_items(v: &serde_json::Value) -> Result<Vec<ImportItem>, String> {
    if v.get("encrypted").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err("加密匯出檔不支援（需先用官方 App 解出未加密 JSON）".into());
    }
    let arr = v
        .as_array()
        .cloned()
        .or_else(|| {
            v.get("items")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .ok_or_else(|| "需要 JSON 陣列或 {\"items\":[...]}".to_string())?;
    arr.iter().map(parse_import_item).collect()
}

fn parse_import_item(c: &serde_json::Value) -> Result<ImportItem, String> {
    let name = c
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if name.is_empty() {
        return Err("匯入項缺 name".into());
    }
    let kind = match c.get("type") {
        Some(serde_json::Value::Number(n)) => match n.as_i64().unwrap_or(1) {
            2 => ItemKind::SecureNote,
            3 => ItemKind::Card,
            4 => ItemKind::Identity,
            _ => ItemKind::Login,
        },
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "note" | "securenote" => ItemKind::SecureNote,
            "card" => ItemKind::Card,
            "identity" => ItemKind::Identity,
            other => return Err(format!("未知 type {other:?}")),
        },
        _ => ItemKind::Login,
    };
    // 官方匯出把帳密放 login 子物件；扁平形態直接讀頂層欄
    let login = c
        .get("login")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let pick = |key: &str| -> Option<String> {
        c.get(key)
            .or_else(|| login.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let uris = c
        .get("uris")
        .or(login.get("uris"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|u| match u {
                    serde_json::Value::String(s) => Some(s.clone()),
                    obj => obj
                        .get("uri")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default();
    // 官方匯出 uris[].match（明文整數/null）：隨列序平行帶入 draft，缺位＝None 預設
    let uri_matches: Vec<Option<u8>> = c
        .get("uris")
        .or(login.get("uris"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|u| {
                    u.get("match")
                        .and_then(serde_json::Value::as_u64)
                        .map(|m| m as u8)
                })
                .collect()
        })
        .unwrap_or_default();
    let fields = c
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let name = f.get("name").and_then(serde_json::Value::as_str)?;
                    Some(CipherField {
                        name: name.to_owned(),
                        value: f
                            .get("value")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                        kind: CipherFieldKind::from_wire(
                            f.get("type")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0),
                        ),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let tags = c
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(ImportItem {
        draft: CipherDraft {
            kind,
            name,
            username: pick("username"),
            password: pick("password"),
            totp: pick("totp"),
            uris,
            notes: pick("notes"),
            favorite: c
                .get("favorite")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            folder_id: c
                .get("folderId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            fields,
            uri_matches,
            // 型別節（PR1）：官方未加密匯出的 card/identity 子物件（明文值）
            card: bw_proto::card_draft_from_export(c.get("card")),
            identity: bw_proto::identity_draft_from_export(c.get("identity")),
        },
        tags,
    })
}

fn parse_approval(s: &str) -> Result<Uuid, String> {
    Uuid::parse_str(s).map_err(|e| format!("approval/session id: {e}"))
}

fn print_response(resp: &Response, json: bool) {
    use serde_json::json;
    match resp {
        // EA view 明文出口（PR4 C2）與本庫清單同渲染（--json 扁平、人讀 format_item）
        Response::Items(rows) | Response::EaView(rows) => {
            if json {
                println!("{}", serde_json::to_string(rows).unwrap());
            } else {
                for r in rows {
                    let tags = if r.meta.tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", r.meta.tags.join(","))
                    };
                    let pending = if r.meta.pending { " (pending)" } else { "" };
                    println!(
                        "{}  {}{}{}",
                        r.meta.id,
                        r.meta.name.clone().unwrap_or_else(|| "…".into()),
                        tags,
                        pending
                    );
                }
            }
        }
        Response::Item(Some(v)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(v).unwrap());
            } else {
                println!("{}", format_item(v));
            }
        }
        Response::Item(None) => println!("(not found)"),
        Response::Secret(s) => println!("{s}"),
        Response::TotpCode {
            code,
            valid_for_secs,
        } => {
            if json {
                println!(
                    "{}",
                    json!({"code": code, "valid_for_secs": valid_for_secs})
                );
            } else {
                println!("{code}  ({valid_for_secs}s)");
            }
        }
        Response::Audit(rows) => {
            println!("{}", serde_json::to_string_pretty(rows).unwrap());
        }
        // AutoType 等計數類結果：扁平 JSON，無外殼（jq 直接命中 .typed）
        Response::Json(v) => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        // 附件位元組直出口（attach get 在 run() 已攔截寫檔；這裡是旁路觀測形態）
        Response::AttachmentBytes(v) => {
            println!("{}", json!({"bytes": v.len()}))
        }
        // passkey：恆為扁平 JSON（Swift/測試端直接解析，無 --json 分支）
        Response::Passkeys(v) => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        Response::PasskeyAttestation {
            credential_id,
            attestation_object,
        } => println!(
            "{}",
            json!({"credential_id": credential_id, "attestation_object": attestation_object})
        ),
        Response::PasskeyAssertion {
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
        } => println!(
            "{}",
            json!({
                "credential_id": credential_id,
                "authenticator_data": authenticator_data,
                "client_data_json": client_data_json,
                "signature": signature,
            })
        ),
        Response::AssertBegin {
            credential_id,
            rp_id,
            authenticator_data,
            client_data_hash,
            signing_input_note,
            counter,
        } => println!(
            "{}",
            json!({
                "credential_id": credential_id,
                "rp_id": rp_id,
                "authenticator_data": authenticator_data,
                "client_data_hash": client_data_hash,
                "signing_input_note": signing_input_note,
                "counter": counter,
            })
        ),
        Response::RegisterBegin { credential_id } => {
            println!("{}", json!({"credential_id": credential_id}));
        }
        Response::Version(s) => println!("{s}"),
        // 本機設定：扁平 Settings JSON（e2e/GUI 直讀，無外殼）
        Response::Settings(s) => {
            println!("{}", serde_json::to_string_pretty(s).unwrap());
        }
        // 2FA 因子清單：編號旁附繁中標籤（人讀不靠猜編號，jq 仍走 provider 欄）
        Response::TwoFactorStates(v) => {
            let rows: Vec<_> = v
                .iter()
                .map(|s| {
                    json!({
                        "provider": s.provider,
                        "label": TwoFactorProviderInfo::label(s.provider),
                        "enabled": s.enabled,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        // EA 清單（PR4）：扁平 JSON 列（e2e jq 直接命中 id/status）
        Response::EaContacts(v) => {
            let rows: Vec<_> = v
                .iter()
                .map(|c| {
                    json!({
                        "id": c.id,
                        "userId": c.user_id,
                        "email": c.email,
                        "name": c.name,
                        "status": format!("{:?}", c.status),
                        "statusLabel": c.status.label(),
                        "type": format!("{:?}", c.access_type),
                        "waitTimeDays": c.wait_time_days,
                        "grantedToMe": c.role == EaRole::Grantor,
                        "recoveryInitiatedAt": c.recovery_initiated_at,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        Response::Profile(p) => println!("{}", json!(p)),
        Response::Ok => println!("ok"),
        // 展開 newtype variant，jq 路徑直接命中欄位（避免 {"Status":{...}} 外殼）
        Response::Status(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
        Response::Account(a) => println!("{}", serde_json::to_string_pretty(&a).unwrap()),
        Response::AuditChain(c) => println!("{}", serde_json::to_string_pretty(&c).unwrap()),
        Response::Conflicts(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Response::AgentSessions(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Response::PendingApprovals(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Response::Pairings(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Response::DupGroups(g) => println!("{}", serde_json::to_string_pretty(g).unwrap()),
        Response::PairInfo(p) => println!("{}", serde_json::to_string_pretty(p).unwrap()),
        // agentpath.sh 依賴的扁平形狀：{"token","session","expires_at_ms"}
        Response::AgentSession {
            token,
            expires_epoch_ms,
        } => println!(
            "{}",
            serde_json::json!({"token": token, "session": token, "expires_at_ms": expires_epoch_ms})
        ),
        other => println!("{}", serde_json::to_string_pretty(other).unwrap()),
    }
}

/// 詳情頁人類可讀排版：筆記／資料夾／自訂欄（三件套）。
/// hidden 欄值缺席時以 ••• 代（daemon 未在該視窗返回值＝金鑰不可見）。
fn format_item(v: &ItemView) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}  {}\n",
        v.meta.id,
        v.meta.name.clone().unwrap_or_default()
    ));
    out.push_str(&format!("type: {:?}\n", v.meta.kind));
    if let Some(f) = &v.meta.folder_id {
        out.push_str(&format!("folder: {f}\n"));
    }
    for u in &v.meta.uris {
        out.push_str(&format!("uri: {u}\n"));
    }
    if let Some(u) = &v.username {
        out.push_str(&format!("username: {u}\n"));
    }
    if let Some(p) = &v.password_masked {
        out.push_str(&format!("password: {p}\n"));
    }
    if let Some(p) = &v.password {
        out.push_str(&format!("password: {p}\n"));
    }
    if let Some(n) = &v.notes {
        out.push_str(&format!("notes: {n}\n"));
    }
    // 型別節（PR1）：card/identity 欄按投影可見性輸出（卡號/CVV 僅 Reveal 帶全值）
    if let Some(c) = &v.card {
        if let Some(x) = &c.cardholder_name {
            out.push_str(&format!("card.cardholderName: {x}\n"));
        }
        if let Some(x) = &c.brand {
            out.push_str(&format!("card.brand: {x}\n"));
        }
        if let Some(x) = &c.number {
            out.push_str(&format!("card.number: {x}\n"));
        } else if let Some(x) = &c.number_masked {
            out.push_str(&format!("card.number: {x}\n"));
        }
        if let Some(x) = &c.exp_month {
            out.push_str(&format!("card.expMonth: {x}\n"));
        }
        if let Some(x) = &c.exp_year {
            out.push_str(&format!("card.expYear: {x}\n"));
        }
        if let Some(x) = &c.code {
            out.push_str(&format!("card.code: {x}\n"));
        } else if c.code_masked.is_some() {
            out.push_str("card.code: ••••\n");
        }
    }
    if let Some(i) = &v.identity {
        for (key, val) in [
            ("title", &i.title),
            ("firstName", &i.first_name),
            ("middleName", &i.middle_name),
            ("lastName", &i.last_name),
            ("address1", &i.address1),
            ("address2", &i.address2),
            ("address3", &i.address3),
            ("city", &i.city),
            ("state", &i.state),
            ("postalCode", &i.postal_code),
            ("country", &i.country),
            ("company", &i.company),
            ("email", &i.email),
            ("phone", &i.phone),
            ("ssn", &i.ssn),
            ("username", &i.username),
            ("passportNumber", &i.passport_number),
            ("licenseNumber", &i.license_number),
        ] {
            if let Some(x) = val {
                out.push_str(&format!("identity.{key}: {x}\n"));
            }
        }
    }
    for f in &v.fields {
        let val = match (&f.value, f.kind) {
            (Some(x), _) => x.clone(),
            (None, CipherFieldKind::Hidden) => "•••".into(),
            (None, _) => String::new(),
        };
        let tag = match f.kind {
            CipherFieldKind::Text => "text",
            CipherFieldKind::Hidden => "hidden",
            CipherFieldKind::Boolean => "boolean",
        };
        out.push_str(&format!("field[{}]: {} = {val}\n", tag, f.name));
    }
    for a in &v.attachments {
        let size = match (&a.size, &a.size_name) {
            (Some(s), _) => format!("{s} B"),
            (None, Some(n)) => n.clone(),
            (None, None) => "?".into(),
        };
        out.push_str(&format!("attach: {}  {}  ({size})\n", a.id, a.file_name));
    }
    if let Some(t) = &v.meta.updated_at {
        out.push_str(&format!("updated: {t}\n"));
    }
    if v.meta.pending {
        out.push_str("(pending)\n");
    }
    out.trim_end().to_owned()
}

fn wtp_to_string(e: &WtpError) -> String {
    match e {
        WtpError::Locked => "vault 未解鎖：bitward unlock".into(),
        WtpError::StaleEpoch { seen, now } => {
            format!("session 已隨鎖世代失效（seen {seen}, now {now}）：重新執行指令即可")
        }
        other => format!("{other:?}"),
    }
}

fn read_line_stdin() -> Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    if s.is_empty() {
        return Err("stdin 為空".into());
    }
    Ok(s.trim_end_matches(['\n', '\r']).to_owned())
}

fn kdf_from_prelogin(v: &serde_json::Value) -> bw_crypto::KdfParams {
    let iterations = v
        .get("kdfIterations")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(600_000);
    if v.get("kdf").and_then(serde_json::Value::as_i64) == Some(1) {
        bw_crypto::KdfParams::Argon2id {
            m: v.get("kdfMemory")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(64) as u32,
            t: iterations as u32,
            p: v.get("kdfParallelism")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(4) as u32,
        }
    } else {
        bw_crypto::KdfParams::Pbkdf2 {
            iterations: iterations as u32,
        }
    }
}

async fn dev_register(server: &str, email: &str, _stdin: bool) -> Result<(), String> {
    use bw_server::NewAccount;
    let pw = read_line_stdin()?;
    let client = bw_server::Client::new(server).map_err(|e| e.to_string())?;
    let pre = client.prelogin(email).await.map_err(|e| e.to_string())?;
    let kdf = kdf_from_prelogin(&pre);
    let mk = bw_crypto::master_key(&pw, email, kdf).map_err(|e| e.to_string())?;
    let mph = bw_crypto::master_password_hash(&mk, &pw)
        .as_b64()
        .to_owned();
    let mut raw = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    let uk = bw_crypto::UserKey::from_bytes(raw.to_vec()).map_err(|e| e.to_string())?;
    let key = bw_crypto::encrypt_user_key(&mk, &uk).map_err(|e| e.to_string())?;
    // RSA keypair（官方客戶端註冊同形）：EA confirm/takeover 與 org akey 的
    // RSA 鏈都要求帳號在伺服器上有 publicKey——缺了它 `/users/{id}/public-key`
    // 回「User has no public_key」（VW 1.37.2 實錄）。
    let pair = bw_crypto::generate_rsa_keypair(&uk).map_err(|e| e.to_string())?;
    // 伺服器上的 publicKey 欄是 PEM 裝甲（orgpath.sh 同形；官方客戶端同）——
    // 生成器給的是 b64 SPKI，裝甲後再送。
    let pub_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        pair.public_key_b64
    );
    let mut acc = NewAccount::new(email, "e2e dev", mph, key);
    acc.public_key = Some(pub_pem);
    acc.encrypted_private_key = Some(pair.encrypted_private_key);
    client.register(&acc).await.map_err(|e| e.to_string())?;
    println!("registered {email}");
    Ok(())
}

fn seed_target(args: &Args) -> Result<(String, String), String> {
    let _ = args;
    let path = default_data_dir().join("account.json");
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    Ok((
        v["server"].as_str().unwrap_or_default().to_owned(),
        v["email"].as_str().unwrap_or_default().to_owned(),
    ))
}

async fn dev_seed(
    server: &str,
    email: &str,
    name: &str,
    uri: &str,
    secret: &str,
) -> Result<(), String> {
    use bw_server::PasswordLogin;
    let pw = read_line_stdin()?;
    let client = bw_server::Client::new(server).map_err(|e| e.to_string())?;
    let pre = client.prelogin(email).await.map_err(|e| e.to_string())?;
    let kdf = kdf_from_prelogin(&pre);
    let mk = bw_crypto::master_key(&pw, email, kdf).map_err(|e| e.to_string())?;
    let mph = bw_crypto::master_password_hash(&mk, &pw)
        .as_b64()
        .to_owned();
    let login = PasswordLogin::new(email, mph, "dev-seed");
    let bundle = client
        .password_login(&login)
        .await
        .map_err(|e| e.to_string())?;
    let puk = bundle.keys.and_then(|k| k.key).ok_or("token 無 Keys")?;
    let sk = bw_crypto::stretch(&mk);
    let uk = bw_crypto::decrypt_user_key(&sk, &puk).map_err(|e| e.to_string())?;
    let enc = |s: &str| {
        bw_crypto::encrypt(&uk, s)
            .map(|e| e.to_string())
            .map_err(|e| e.to_string())
    };
    let body = serde_json::json!({
        "type": 1,
        "name": enc(name)?,
        "login": {
            "username": enc("e2e-user")?,
            "password": enc(secret)?,
            "uris": [{"uri": enc(uri)?, "match": null}]
        }
    });
    let created = client
        .cipher_create(&body)
        .await
        .map_err(|e| e.to_string())?;
    println!("seeded {}", created["id"].as_str().unwrap_or("?"));
    Ok(())
}

/// `send access` 的解密產物（列印與落檔由 [`emit_accessed`] 處理，
/// 單測直接斷言返回值，不捕 stdout）。
#[derive(Debug)]
enum Accessed {
    Text {
        name: String,
        text: String,
    },
    File {
        name: String,
        file_name: String,
        bytes: Vec<u8>,
    },
}

/// 分享 URL → `(server base, accessId, seed 鑰)`。官方形態
/// `{server}/#/send/{accessId}/{b64url(seed)}`；片段不經伺服器（瀏覽器
/// 不上送、本機只進解密閉包——A11「不落明文」延伸到 key 片段）。
fn parse_send_url(url: &str) -> Result<(String, String, bw_crypto::SendKey), String> {
    let (base, frag) = url
        .split_once('#')
        .ok_or("分享 URL 沒有金鑰片段（請貼上完整連結，含 # 之後）")?;
    let rest = frag
        .strip_prefix("/send/")
        .ok_or_else(|| format!("URL 片段應為 #/send/{{id}}/{{金鑰}} 形態，got #{frag}"))?;
    let (aid, seed) = rest
        .split_once('/')
        .ok_or("URL 片段缺金鑰段（#/send/{{id}}/{{金鑰}}）")?;
    if aid.is_empty() {
        return Err("URL 片段缺存取 id".into());
    }
    let raw = bw_crypto::b64url_decode(seed).map_err(|_| "金鑰片段不是合法 b64url")?;
    let key = bw_crypto::SendKey::from_bytes(raw)
        .map_err(|_| "金鑰片段長度不對（應為 16 bytes 的 b64url）")?;
    Ok((base.to_owned(), aid.to_owned(), key))
}

/// 接收方全鏈：URL 片段 seed → 官方拉伸 → 存取端點四態 → 本地解密。
/// 錯誤文案即使用者可觀察終態（需密碼／錯密碼／不可用／網路四態可懂）。
/// `password` 為取用密碼明文（呼叫端自 stdin 讀入；哈希在本閉包後即棄）。
async fn access_send(url: &str, password: Option<&str>) -> Result<Accessed, String> {
    let (base, aid, key) = parse_send_url(url)?;
    let pw_hash = password.map(|p| key.password_hash(p));
    let client =
        bw_server::Client::new(&base).map_err(|e| format!("分享 URL 的伺服器位址無效：{e}"))?;
    let outcome = client
        .send_access(&aid, pw_hash.as_deref())
        .await
        .map_err(|e| format!("網路錯誤：{e}"))?;
    let send = match outcome {
        bw_server::SendAccessOutcome::Send(v) => v,
        bw_server::SendAccessOutcome::PasswordRequired => {
            return Err("此 Send 設了取用密碼，請加 --password-stdin 提供".into());
        }
        bw_server::SendAccessOutcome::PasswordInvalid => return Err("取用密碼不正確".into()),
        bw_server::SendAccessOutcome::Inaccessible => {
            return Err("Send 不可用（已過期、存取次數耗盡或已被刪除）".into());
        }
    };
    let ck = key.stretch();
    let dec = |env: &str| -> Result<String, String> {
        let raw = bw_crypto::decrypt_bytes_with_key(ck.as_slice(), env)
            .map_err(|_| "解密失敗（金鑰片段與此 Send 不符）")?;
        String::from_utf8(raw).map_err(|_| "Send 內容不是有效的文字（UTF-8）".into())
    };
    let name = send
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(dec)
        .transpose()?
        .unwrap_or_default();
    if send.get("type").and_then(serde_json::Value::as_i64) == Some(1) {
        let sid = parse_id(
            send.get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or("Send 回包缺 id")?,
        )?;
        let file_id = send
            .pointer("/file/id")
            .and_then(serde_json::Value::as_str)
            .ok_or("Send 回包缺檔案 id（檔身可能未上傳完成）")?
            .to_owned();
        let file_name = send
            .pointer("/file/fileName")
            .and_then(serde_json::Value::as_str)
            .map(dec)
            .transpose()?
            .unwrap_or_else(|| "send-file".into());
        let raw = client
            .send_file_download(sid, &file_id, pw_hash.as_deref())
            .await
            .map_err(|e| format!("網路錯誤：{e}"))?;
        let env = String::from_utf8(raw).map_err(|_| "檔身不是信封字串".to_owned())?;
        let bytes = bw_crypto::decrypt_bytes_with_key(ck.as_slice(), &env)
            .map_err(|_| "解密失敗（金鑰片段與此 Send 不符）")?;
        Ok(Accessed::File {
            name,
            file_name,
            bytes,
        })
    } else {
        let env = send
            .pointer("/text/text")
            .and_then(serde_json::Value::as_str)
            .ok_or("Send 回包缺文字欄")?;
        Ok(Accessed::Text {
            name,
            text: dec(env)?,
        })
    }
}

/// 出口列印：文字→stdout（管線友善，逐字節不添換行）；檔案→落檔或
/// `-`＝stdout；`--json` 出結構（名稱屬 Identity 級，本機接收方自用）。
fn emit_accessed(accessed: Accessed, out: Option<&str>, json: bool) -> Result<(), String> {
    use std::io::Write as _;
    match accessed {
        Accessed::Text { name, text } => {
            if let Some(path) = out.filter(|p| *p != "-") {
                std::fs::write(path, &text).map_err(|e| format!("寫檔失敗：{e}"))?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"type":"text","name":name,"path":path})
                    );
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::json!({"type":"text","name":name,"text":text})
                );
            } else {
                std::io::stdout()
                    .write_all(text.as_bytes())
                    .map_err(|e| e.to_string())?;
            }
        }
        Accessed::File {
            name,
            file_name,
            bytes,
        } => {
            let path = out.unwrap_or(&file_name).to_owned();
            if path == "-" {
                std::io::stdout()
                    .write_all(&bytes)
                    .map_err(|e| e.to_string())?;
            } else {
                std::fs::write(&path, &bytes).map_err(|e| format!("寫檔失敗：{e}"))?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"type":"file","name":name,"file":file_name,
                                            "path":path,"bytes":bytes.len()})
                    );
                } else {
                    println!("已存 {path}（{} bytes）", bytes.len());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod access_tests {
    use super::*;

    /// 迴圈 mock server：依 request-line 包含的路由前綴回 canned 回應
    /// （(status, body, content-type)）；未命中＝500。讀掉宣告的 body 後
    /// 一連線一应答即關（reqwest 會重連，不談 keep-alive）。
    fn mock_server(routes: Vec<(&'static str, u16, String, &'static str)>) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let routes: Vec<(String, u16, String, String)> = routes
            .into_iter()
            .map(|(m, s, b, c)| (m.to_owned(), s, b, c.to_owned()))
            .collect();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            for stream in l.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(p + 4);
                            }
                        }
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let line = head.lines().next().unwrap_or("").to_owned();
                let clen: usize = head
                    .lines()
                    .find_map(|h| {
                        let (k, v) = h.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while buf.len() - head_end < clen {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let (status, body, ctype) = routes
                    .iter()
                    .find(|(m, ..)| line.contains(m.as_str()))
                    .map(|(_, s, b, c)| (*s, b.clone(), c.clone()))
                    .unwrap_or((500, "no route".into(), "text/plain".into()));
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn seed_key() -> bw_crypto::SendKey {
        bw_crypto::SendKey::from_bytes((0..16u8).collect()).unwrap()
    }

    fn enc(ck: &[u8], s: &str) -> String {
        bw_crypto::encrypt_bytes_key(ck, s.as_bytes()).unwrap()
    }

    #[test]
    fn url_parse_official_shape_and_errors() {
        let seed = seed_key();
        let url = format!(
            "http://127.0.0.1:9/#/send/ACC-IDA/{}",
            bw_crypto::b64url(seed.as_bytes())
        );
        let (base, aid, k) = parse_send_url(&url).unwrap();
        assert_eq!(base, "http://127.0.0.1:9/");
        assert_eq!(aid, "ACC-IDA");
        assert_eq!(k.as_bytes(), seed.as_bytes());
        assert!(
            parse_send_url("http://x/#/send/A/AAAAAAAAAAAAAAAAAAAA")
                .unwrap_err()
                .contains("16")
        );
        assert!(
            parse_send_url("http://x/send/A/B")
                .unwrap_err()
                .contains("片段")
        );
        assert!(
            parse_send_url("http://x/#/vault/AAECAwQFBgcICQoLDA0ODw")
                .unwrap_err()
                .contains("send")
        );
    }

    #[tokio::test]
    async fn access_three_error_states_readable() {
        let seed = seed_key();
        let aid = "ACC-ERR";
        let mk = |status: u16| {
            let routes = vec![(
                "/api/sends/access/ACC-ERR",
                status,
                "{}".to_string(),
                "application/json",
            )];
            mock_server(routes)
        };
        let url_for =
            |base: &str| format!("{base}/#/send/{aid}/{}", bw_crypto::b64url(seed.as_bytes()));
        // 401 → 需密碼文案
        let e = access_send(&url_for(&mk(401)), None).await.unwrap_err();
        assert!(e.contains("取用密碼"), "{e}");
        // 400 → 錯密碼文案
        let e = access_send(&url_for(&mk(400)), Some("nope"))
            .await
            .unwrap_err();
        assert!(e.contains("不正確"), "{e}");
        // 404 → 不可用文案（過期／耗盡／刪除合併態）
        let e = access_send(&url_for(&mk(404)), None).await.unwrap_err();
        assert!(e.contains("不可用"), "{e}");
        // 網路死 → 連字符都不潑 raw
        let e = access_send("http://127.0.0.1:1/#/send/A/AAECAwQFBgcICQoLDA0ODw", None)
            .await
            .unwrap_err();
        assert!(e.starts_with("網路錯誤"), "{e}");
    }

    #[tokio::test]
    async fn access_text_roundtrip_against_mock() {
        let seed = seed_key();
        let ck = seed.stretch();
        let body = serde_json::json!({
            "id": "6fe8bae0-e019-48fb-a651-f9e3514d156e",
            "type": 0,
            "name": enc(ck.as_slice(), "分享標題"),
            "text": {"text": enc(ck.as_slice(), "敏感文字 42"), "hidden": false},
            "object": "send-access",
        });
        let base = mock_server(vec![(
            "/api/sends/access/ACC-OK",
            200,
            body.to_string(),
            "application/json",
        )]);
        let url = format!(
            "{base}/#/send/ACC-OK/{}",
            bw_crypto::b64url(seed.as_bytes())
        );
        match access_send(&url, None).await.unwrap() {
            Accessed::Text { name, text } => {
                assert_eq!(name, "分享標題");
                assert_eq!(text, "敏感文字 42");
            }
            _ => panic!("應為文字態"),
        }
    }

    #[tokio::test]
    async fn access_file_roundtrip_sha256() {
        let seed = seed_key();
        let ck = seed.stretch();
        let sid = "6fe8bae0-e019-48fb-a651-f9e3514d156e";
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let env = bw_crypto::encrypt_bytes_key(ck.as_slice(), &payload).unwrap();
        let acc = serde_json::json!({
            "id": sid,
            "type": 1,
            "name": enc(ck.as_slice(), "blob.bin"),
            "file": {"id": "FID1", "size": env.len(), "sizeName": "1 KB",
                     "fileName": enc(ck.as_slice(), "blob.bin")},
            "object": "send-access",
        });
        let file_resp = "{\"url\":\"/blob/FID1\"}".to_owned(); // 相對路徑：absolute 補全
        let base = mock_server(vec![
            (
                "/api/sends/access/ACC-FILE",
                200,
                acc.to_string(),
                "application/json",
            ),
            ("/access/file/FID1", 200, file_resp, "application/json"),
            ("/blob/FID1", 200, env.clone(), "application/octet-stream"),
        ]);
        let url = format!(
            "{base}/#/send/ACC-FILE/{}",
            bw_crypto::b64url(seed.as_bytes())
        );
        match access_send(&url, None).await.unwrap() {
            Accessed::File {
                file_name, bytes, ..
            } => {
                assert_eq!(file_name, "blob.bin");
                assert_eq!(bytes, payload, "解密位元組應逐字等於原檔");
            }
            _ => panic!("應為檔案態"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod sock_default_tests {
    use super::pick_cli_sock;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bw-clisock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bitward")).unwrap();
        d
    }

    #[test]
    fn xdg_main_path_when_present_or_absent() {
        let rt = tmpdir("rt");
        let dd = tmpdir("dd");
        // 兩邊都沒 sock：照報主路徑（錯誤訊息指到正解，不誤導去 data_dir）。
        assert_eq!(
            pick_cli_sock(Some(rt.to_str().unwrap()), &dd),
            rt.join("bitward").join("daemon.sock")
        );
        // 未設／空字串＝退 data_dir。
        assert_eq!(pick_cli_sock(None, &dd), dd.join("daemon.sock"));
        assert_eq!(pick_cli_sock(Some(""), &dd), dd.join("daemon.sock"));
        std::fs::remove_dir_all(rt).ok();
        std::fs::remove_dir_all(dd).ok();
    }

    #[test]
    fn falls_back_only_when_main_absent_and_data_present() {
        let rt = tmpdir("rt2");
        let dd = tmpdir("dd2");
        let main = rt.join("bitward").join("daemon.sock");
        let fallback = dd.join("daemon.sock");
        std::fs::write(&fallback, "").unwrap();
        // 主路徑不存在＋退路在場（daemon 以 --sock 起於 data_dir）→ 退。
        assert_eq!(pick_cli_sock(Some(rt.to_str().unwrap()), &dd), fallback);
        // 主路徑也在場 → 主勝（同機兩態並存時按 Q3 口徑取主）。
        std::fs::write(&main, "").unwrap();
        assert_eq!(pick_cli_sock(Some(rt.to_str().unwrap()), &dd), main);
        std::fs::remove_dir_all(rt).ok();
        std::fs::remove_dir_all(dd).ok();
    }
}

#[cfg(test)]
mod hub_tests {
    use super::*;

    fn tmpdd(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bw-hub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("remotes")).unwrap();
        d
    }

    #[test]
    fn route_hub_table() {
        // 明示 --remote 永遠贏；本地可達走本地；不可達有預設→Failover；無預設→NoHub。
        assert_eq!(
            route_hub(Some("desk"), true, Some("home".into())),
            HubRoute::Remote("desk".into())
        );
        assert_eq!(route_hub(None, true, Some("home".into())), HubRoute::Local);
        assert_eq!(
            route_hub(None, false, Some("home".into())),
            HubRoute::Failover("home".into())
        );
        assert_eq!(route_hub(None, false, None), HubRoute::NoHub);
    }

    #[test]
    fn failover_hint_lists_alternatives() {
        let others: Vec<String> = ["home", "desk"].iter().map(|s| s.to_string()).collect();
        let h = failover_hint("home", &others);
        assert_eq!(
            h,
            "其他可用 hub：desk（`bitward hub default <name>` 切預設、`--remote <name>` 單次指定）"
        );
        assert!(failover_hint("home", &["home".to_string()]).contains("無其他已配對 hub"));
    }

    #[test]
    fn default_file_roundtrip_and_list_excludes_it() {
        let d = tmpdd("rt");
        let prof = |name: &str| RemoteProfile {
            url: format!("https://{name}:8443"),
            pin: "AA".into(),
            token: "t".into(),
            wake: None,
        };
        for n in ["home", "desk"] {
            std::fs::write(
                d.join("remotes").join(format!("{n}.json")),
                serde_json::to_vec(&prof(n)).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            list_hub_profiles(&d),
            vec!["desk".to_string(), "home".to_string()]
        );
        assert_eq!(read_default_hub(&d), None);
        std::fs::write(d.join("remotes").join(DEFAULT_HUB_FILE), "home\n").unwrap();
        assert_eq!(read_default_hub(&d).as_deref(), Some("home"));
        // dotfile 不入清單（profile 名與指標檔零撞名）
        assert_eq!(list_hub_profiles(&d).len(), 2);
        // 空指標＝None（清除語意的落盤態）
        std::fs::write(d.join("remotes").join(DEFAULT_HUB_FILE), "").unwrap();
        assert_eq!(read_default_hub(&d), None);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn split_url_forms_golden() {
        // E4：三形態＋錯誤路徑。
        assert_eq!(
            split_url("https://hub.tailnet:8443").unwrap(),
            ("hub.tailnet".into(), 8443)
        );
        assert_eq!(
            split_url("hub.tailnet:9000").unwrap(),
            ("hub.tailnet".into(), 9000)
        );
        assert_eq!(
            split_url("hub.tailnet").unwrap(),
            ("hub.tailnet".into(), DEFAULT_PAIR_PORT)
        );
        assert!(split_url("").is_err());
        assert!(split_url("https://").is_err());
        assert!(split_url("hub.tailnet:port").is_err());
        assert!(split_url("hub.tailnet:8443/pair").is_err());
    }

    #[test]
    fn tailscale_cgnat_range_classify() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(is_tailscale_addr(&ip("100.64.0.1")));
        assert!(is_tailscale_addr(&ip("100.127.255.255")));
        assert!(!is_tailscale_addr(&ip("100.128.0.0")));
        assert!(!is_tailscale_addr(&ip("10.0.0.1")));
        assert!(!is_tailscale_addr(&ip("127.0.0.1")));
        assert!(!is_tailscale_addr(&ip("fd7a:115c:a1e0::1")));
    }
}
