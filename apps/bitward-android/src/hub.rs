//! in-process 中樞（契約 §1：Android 的 Full 形態＝app 內的 daemon 等位物）。
//!
//! 核心 crate（bw-crypto / bw-server / bw-store）直接鏈進 app 的 `libnsh.so`：
//! UI 與核心同進程同語言，所以沒有 FFI 綁定面，也没有「GUI 內嵌第二份金鑰」
//! 之外的額外信任邊界（金鑰只在這個進程裡）。業務語意（KDF、信封、鏡像、
//! 明文索引）全部沿用根 workspace 的 crate，本檔只做編排。
//!
//! 明文紀律（契約 §2.7）：
//! - 主密碼在 [`Hub::login`] 內以 `Zeroizing<String>` 承載，`MasterKey` 派生完
//!   即 Drop 歸零（`bw_crypto::MasterKey` 自己的 `Drop` 清零 32 bytes）。
//! - user key 是 `bw_crypto::UserKey`（`Drop` 清零 enc‖mac），只存活在
//!   [`Hub`] 的 `unlocked` 槽；[`Hub::sign_out`] 丟棄它即歸零。
//! - 欄位明文（[`Revealed`]）只在詳情元件的訊號裡，離開視圖即 `set(None)`；
//!   本檔不把明文寫進日誌，也不寫進帳號檔。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bw_proto::{CipherDraft, CipherField, FieldEdit, ItemId, ItemMeta, Query};
use bw_server::{Client, ClientOptions, DeleteKind, PasswordLogin};
use bw_store::{MutState, Mutation, MutationDraft, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// 帳號落地資料（不含主密碼，也不含明文 user key）。
/// user key 的封存形態在 P4b 第二批交給 Keystore 孤島（`android-shell/README.md`），
/// 這批只在解鎖期間把金鑰放在記憶體。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub server: String,
    pub email: String,
    pub kdf: i64,
    pub kdf_iterations: u64,
    pub kdf_memory: Option<u64>,
    pub kdf_parallelism: Option<u64>,
    /// 服務器原樣的 Protected Symmetric Key（`2.iv|ct|mac`），未解封。
    pub protected_user_key: Option<String>,
    pub refresh_token: Option<String>,
}

/// 解鎖後的進程內狀態（金鑰只在這裡，登出即歸零）。
struct Unlocked {
    client: Arc<Client>,
    user_key: bw_crypto::UserKey,
}

/// 登入/同步後給 UI 的摘要（無明文欄位）。
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub email: String,
    pub server: String,
    pub items: usize,
    pub last_sync_ms: u64,
}

/// 詳情頁的單筆明文視圖。`password` 用 `Zeroizing` 包，
/// 詳情元件離開時 `set(None)` → Drop 歸零。
#[derive(Clone, Debug)]
pub struct Revealed {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub uris: Vec<String>,
    pub tags: Vec<String>,
    /// 本地現算的 TOTP（seed 只在計算期間存在）
    pub totp: Option<String>,
    pub updated_at: Option<String>,
    pub favorite: bool,
    pub pending: bool,
    /// 備註明文（詳情「備註」節與編輯表單預填用；無備註＝None）。
    pub notes: Option<String>,
    /// 鏡像 `folderId` 明文 UUID（未歸屬＝None）；名稱由 [`Hub::folders`] 對映。
    pub folder_id: Option<String>,
    /// 自訂欄位（順序同線格式 `fields[]`；hidden 欄值照官方詳情語意給明文，
    /// 顯示端自行遮罩）。boolean 欄值為 "true"/"false" 字串（jslib 同形）。
    pub fields: Vec<CipherField>,
    /// 是否有 TOTP seed（解鎖態判定）：詳情節的「有 seed 才出現」閘門，
    /// 區隔「無 seed（靜默收合）」與「有 seed 取碼失敗（可懂一行）」。
    pub totp_available: bool,
    /// 各網址列的 match 判定（鏡像 `login.uris[].match` 明文整數；順序對齊
    /// `uris`，缺欄/null＝None 預設）。編輯表單 match 下拉的差量基準
    /// （同 macOS `ItemView` 的 `uri_matches` 投影）。
    pub uri_matches: Vec<Option<u8>>,
}

/// 網站圖示快取態（形態同 macOS `state::IconState`）：缺席＝尚未請求；
/// `Loading` 即單飛令牌（同 host 併發只發一次取圖）。`Ready` 存 data: URI。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IconState {
    Loading,
    Ready(String),
    Failed,
}

/// 資料夾鏡像列（名稱只在解鎖態解密；鎖定態 None＝節點隱藏）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderEntry {
    pub id: String,
    pub name: Option<String>,
}

pub struct Hub {
    dir: PathBuf,
    store: Store,
    unlocked: Mutex<Option<Unlocked>>,
    device: OnceLock<String>,
    /// 最近一次全量 pull 收斂的時刻（背景節拍的依據；0＝本進程還沒拉過）。
    last_sync_ms: AtomicU64,
    /// drain 單飛：同一時間只有一條 outbox 推送序列（租約之外再加一道保險）。
    drain_lock: tokio::sync::Mutex<()>,
    /// favicon 單飛（同 daemon icon.rs）：同 host 併發只放一發外連，
    /// 其餘在閘後命中磁碟快取。
    icon_gate: tokio::sync::Mutex<()>,
}

impl Hub {
    pub fn open(dir: PathBuf) -> Result<Arc<Hub>, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("建立資料目錄失敗：{e}"))?;
        let store = Store::open(&dir.join("vault.db")).map_err(|e| format!("開庫失敗：{e}"))?;
        let hub = Arc::new(Hub {
            dir,
            store,
            unlocked: Mutex::new(None),
            device: OnceLock::new(),
            last_sync_ms: AtomicU64::new(0),
            drain_lock: tokio::sync::Mutex::new(()),
            icon_gate: tokio::sync::Mutex::new(()),
        });
        log::info!("bitward-android hub: dir={}", hub.dir.display());
        Ok(hub)
    }

    /// 穩定裝置 id：login 的 `deviceIdentifier` 用（與 daemon 同源語意）。
    fn device_id(&self) -> String {
        self.device.get_or_init(|| {
            let path = self.dir.join("device.id");
            if let Ok(s) = std::fs::read_to_string(&path) {
                let t = s.trim().to_owned();
                if !t.is_empty() {
                    return t;
                }
            }
            let fresh = uuid::Uuid::new_v4().to_string();
            let _ = std::fs::write(&path, &fresh);
            fresh
        });
        self.device.get().cloned().unwrap_or_default()
    }

    /// 已落地的帳號（登入頁預填用）。金鑰不在裡面，所以仍需主密碼解鎖。
    pub fn account(&self) -> Option<Account> {
        let text = std::fs::read_to_string(self.dir.join("account.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn persist_account(&self, acc: &Account) {
        if let Ok(text) = serde_json::to_string_pretty(acc) {
            let path = self.dir.join("account.json");
            let _ = std::fs::write(path, text);
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.lock().expect("hub mutex poisoned").is_some()
    }

    fn options() -> ClientOptions {
        ClientOptions {
            // Bitwarden device type 3 = Android（device-type.enum.ts）
            device_type: 3,
            device_name: "bitward-android".to_owned(),
            request_timeout: std::time::Duration::from_secs(20),
            ..Default::default()
        }
    }

    /// 完整登入：prelogin → 派生 → password grant → 解 user key → 全量 sync → 回填明文索引。
    pub async fn login(
        self: &Arc<Self>,
        server: &str,
        email: &str,
        password: &str,
    ) -> Result<Snapshot, String> {
        let server = server.trim().to_owned();
        let email = email.trim().to_owned();
        if server.is_empty() || email.is_empty() {
            return Err("服務器網址與電子信箱皆為必填".to_owned());
        }
        // 主密碼只在這個綁定內存活（Zeroizing：離開作用域即歸零）。
        let pw = Zeroizing::new(password.to_owned());
        let client = Arc::new(
            Client::with_options(&server, Self::options())
                .map_err(|e| format!("服務器網址無效：{e}"))?,
        );
        let pre = client
            .prelogin(&email)
            .await
            .map_err(|e| format!("問不到 KDF（prelogin）：{e}"))?;
        let kdf = kdf_from_prelogin(&pre);
        let mk = bw_crypto::master_key(&pw, &email, kdf).map_err(|e| format!("派生失敗：{e}"))?;
        let hash = bw_crypto::master_password_hash(&mk, &pw)
            .as_b64()
            .to_owned();
        let login = PasswordLogin::new(&email, hash, self.device_id());
        let bundle = client
            .password_login(&login)
            .await
            .map_err(|e| format!("登入被拒：{e}"))?;
        let keys = bundle
            .keys
            .clone()
            .filter(|k| k.key.is_some())
            .ok_or_else(|| "服務器沒回 vault 金鑰（API key 不解 vault）".to_owned())?;
        let protected = keys.key.clone().unwrap_or_default();
        let user_key = bw_crypto::decrypt_user_key(&bw_crypto::stretch(&mk), &protected)
            .map_err(|e| format!("user key 解封失敗（主密碼对不上？）：{e}"))?;
        client.set_access_token(&bundle.access_token).await;

        let (kdf, kdf_iterations, kdf_memory, kdf_parallelism) = kdf_wire(&kdf);
        self.persist_account(&Account {
            server: server.clone(),
            email: email.clone(),
            kdf,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
            protected_user_key: Some(protected),
            refresh_token: bundle.refresh_token.clone(),
        });
        {
            let mut g = self.unlocked.lock().expect("hub mutex poisoned");
            // 舊金鑰在這裡被 Drop（清零）後才換新金鑰。
            *g = Some(Unlocked {
                client: client.clone(),
                user_key,
            });
        }
        let items = self.pull_and_index(client.clone()).await?;
        // 解鎖成功點＝封存時機（P4b 第五批）：30 秒驗證視窗內靜默包裹；
        // 窗外孤島自行退到生物辨識彈窗。失敗只記 log——登入本身已完成，
        // 沒封存只是下次仍要主密碼，不降格、不重試到煩。
        if let Err(e) = self.seal_now().await {
            log::warn!("keystore 封存未落地：{e}");
        }
        crate::island::ensure_hub_service();
        Ok(Snapshot {
            email,
            server,
            items,
            last_sync_ms: self.store.now_ms(),
        })
    }

    /// 手動重新同步。
    pub async fn sync_now(self: &Arc<Self>) -> Result<usize, String> {
        let client = {
            let g = self.unlocked.lock().expect("hub mutex poisoned");
            g.as_ref().map(|u| u.client.clone()).ok_or("尚未解鎖")?
        };
        self.pull_and_index(client).await
    }

    async fn pull_and_index(&self, client: Arc<Client>) -> Result<usize, String> {
        // 先推後拉（契約 §2.4）：outbox 還有未結算列時全量重建會把「待推送」
        // 的本地鏡像列吞掉（伺服器還沒有它們），這時直接回本地計數。
        self.drain().await;
        let pending = self
            .store
            .depth()
            .map(|d| d.queued + d.in_flight + d.awaiting)
            .unwrap_or(u32::MAX);
        if pending > 0 {
            log::warn!("pull: outbox 尚有 {pending} 列未推送，跳過全量重建（離線態）");
            // 計數口徑＝可見鏡像（list 排除 tombstone／封存），不是 raw 行數。
            return Ok(self.list("").len());
        }
        let raw = client.sync().await.map_err(|e| format!("sync 失敗：{e}"))?;
        self.store
            .apply_sync(&raw)
            .map_err(|e| format!("鏡像落地失敗：{e}"))?;
        self.reindex_plain()?;
        self.last_sync_ms.store(self.store.now_ms(), Ordering::Relaxed);
        Ok(self.list("").len())
    }

    /// 鏡像落盤後的明文索引回填（與 daemon 同語意、同函數：欄位路徑見
    /// `bw_vault::plain_index`）：解密只在拿得到 user key 時發生，單筆失敗
    /// 容忍跳過（欄位漂移防禦）。登入＝本批唯一的解鎖完成點，回填接在這裡。
    fn reindex_plain(&self) -> Result<(), String> {
        let metas = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;
        self.reindex_ids(metas.iter().map(|m| m.id))
    }

    /// 單筆／複數 id 的明文索引回填（寫路徑 enqueue 後就地刷新，搜尋與列表
    /// 立刻看到新值；與批量回填同一條 `bw_vault::plain_index`）。內容金鑰
    /// 逐列解析（新建形態＝item key、舊鏡像＝user key，見 [`cipher_content_key`]）。
    fn reindex_ids(&self, ids: impl IntoIterator<Item = ItemId>) -> Result<(), String> {
        let user_key = {
            let g = self.unlocked.lock().expect("hub mutex poisoned");
            let u = g.as_ref().ok_or("尚未解鎖")?;
            u.user_key.clone()
        };
        for id in ids {
            let Some(row) = self.store.item(id).map_err(|e| e.to_string())? else {
                continue;
            };
            let Some(key) = cipher_content_key(&user_key, &row.enc_cipher) else {
                continue;
            };
            let dec = decryptor_with_key(&key);
            let idx = bw_vault::plain_index(&row.enc_cipher, &dec);
            let _ = self.store.set_plain_meta(
                id,
                idx.name.as_deref(),
                &idx.uris,
                &idx.field_names,
            );
            let _ =
                self.store
                    .set_plain_secrets(id, idx.username.as_deref(), idx.password.as_deref());
        }
        Ok(())
    }

    /// 列表：只讀本地鏡像的 metadata（搜尋走 FTS5／LIKE 退路，語意在 bw-store）。
    /// `folder`＝頂部 chip 的資料夾過濾（官方三態：None 全部、
    /// `Some("")` 未歸屬、`Some(id)` 該夾——口徑同 `Query.folder`）。
    pub fn list_in(&self, text: &str, folder: Option<&str>) -> Vec<ItemMeta> {
        let q = Query {
            text: (!text.trim().is_empty()).then(|| text.trim().to_owned()),
            folder: folder.map(str::to_owned),
            limit: u32::MAX,
            ..Default::default()
        };
        self.store.query(&q).unwrap_or_default()
    }

    pub fn list(&self, text: &str) -> Vec<ItemMeta> {
        self.list_in(text, None)
    }

    /// 單筆 metadata（無明文欄位）。
    pub fn meta(&self, id: ItemId) -> Result<Option<ItemMeta>, String> {
        self.store.meta(id).map_err(|e| e.to_string())
    }

    /// AutofillService 候選（JNI 橋用）：依 web host 或 app package 查
    /// Login 項目，比對語意全在 bw-store（host 錨定＋子網域後綴，P5-b3）。
    /// 未解鎖回空——孤島端以 [`Hub::is_unlocked`] 決定走鎖定態回應。
    pub fn candidates_for(&self, query: &str, limit: u32) -> Vec<(ItemId, String)> {
        if !self.is_unlocked() || query.is_empty() {
            return Vec::new();
        }
        let metas = self
            .store
            .query(&Query {
                uri: Some(query.to_owned()),
                kind: Some(bw_proto::ItemKind::Login),
                limit,
                ..Default::default()
            })
            .unwrap_or_default();
        metas
            .into_iter()
            .map(|m| (m.id, m.name.clone().unwrap_or_else(|| "(未命名)".to_owned())))
            .collect()
    }

    /// 本地時鐘（unix ms），給 UI 顯示「上次同步」。
    pub fn now_ms(&self) -> u64 {
        self.store.now_ms()
    }

    /// 詳情（Reveal）：只在這裡解密欄位，回傳的 `password` 由呼叫端負責清零。
    pub fn reveal(&self, id: ItemId) -> Result<Revealed, String> {
        let user_key = {
            let g = self.unlocked.lock().expect("hub mutex poisoned");
            g.as_ref().ok_or("尚未解鎖")?.user_key.clone()
        };
        let meta = self
            .store
            .meta(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "找不到這筆項目".to_owned())?;
        let row = self
            .store
            .item(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "找不到這筆項目".to_owned())?;
        let key = cipher_content_key(&user_key, &row.enc_cipher)
            .ok_or_else(|| "金鑰解析失敗（item key 解不開，請重新同步或重解）".to_owned())?;
        // 欄位路徑與 reindex 同源（bw_vault::plain_index）；totp/notes/自訂欄
        // 只有詳情要，走同一個解密閉包。
        let dec = decryptor_with_key(&key);
        let idx = bw_vault::plain_index(&row.enc_cipher, &dec);
        let totp = row
            .enc_cipher
            .pointer("/login/totp")
            .and_then(Value::as_str)
            .and_then(|seed_env| {
                let seed = dec(seed_env)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                bw_crypto::totp_code(seed.trim(), now).ok()
            });
        let notes = row
            .enc_cipher
            .get("notes")
            .and_then(Value::as_str)
            .and_then(&dec);
        let fields = field_rows(&row.enc_cipher, &dec);
        Ok(Revealed {
            name: meta.name.clone().unwrap_or_else(|| "(未命名)".to_owned()),
            username: idx.username,
            // 明文密碼進 Zeroizing：詳情元件 set(None) 時 Drop 歸零。
            password: idx.password.map(Zeroizing::new),
            uris: idx.uris,
            tags: meta.tags.clone(),
            totp,
            updated_at: meta.updated_at.clone(),
            favorite: meta.favorite,
            pending: meta.pending,
            notes,
            folder_id: meta.folder_id.map(|f| f.to_string()),
            fields,
            totp_available: row
                .enc_cipher
                .pointer("/login/totp")
                .and_then(Value::as_str)
                .is_some(),
            uri_matches: uri_match_rows(&row.enc_cipher),
        })
    }

    /// 資料夾鏡像清單（ListFolders 等位物：`Store::folder_list` ＋解鎖態解密
    /// 名稱；鎖定態回空——列表 chip 與表單下拉都只在解鎖態出現）。
    pub fn folders(&self) -> Vec<FolderEntry> {
        let user_key = match self.unlocked_user_key() {
            Some(k) => k,
            None => return Vec::new(),
        };
        self.store
            .folder_list()
            .unwrap_or_default()
            .into_iter()
            .map(|r| FolderEntry {
                id: r.id.to_string(),
                name: r.name.as_deref().and_then(|n| {
                    bw_crypto::decrypt_bytes_with_key(user_key.as_bytes(), n)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                }),
            })
            .collect()
    }

    /// TOTP 現算（UseCall::TotpCode 等位物，語意同 daemon `totp()`）：
    /// 無 seed＝`Ok(None)`（合法態，UI 靜默收合節，不借錯字串表達）；
    /// 有 seed 解不開＝Err。回 `(code, valid_for_secs)`，
    /// 倒數由 UI 心跳遞減、跨週期重取。
    pub fn totp_code(&self, id: ItemId) -> Result<Option<(String, u32)>, String> {
        let user_key = self.unlocked_user_key().ok_or("尚未解鎖")?;
        let row = self
            .store
            .item(id)
            .map_err(|e| e.to_string())?;
        let row = match row {
            Some(r) => r,
            None => return Err("找不到這筆項目".to_owned()),
        };
        let Some(seed_env) = row
            .enc_cipher
            .pointer("/login/totp")
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let key = cipher_content_key(&user_key, &row.enc_cipher)
            .ok_or("金鑰解析失敗（item key 解不開）")?;
        let seed = decryptor_with_key(&key)(seed_env).ok_or("TOTP seed 解不開")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let code = bw_crypto::totp_code(seed.trim(), now).map_err(|e| e.to_string())?;
        Ok(Some((code, (30 - now % 30) as u32)))
    }

    /// favicon 取圖（daemon `icon.rs` 的 in-process 等位物）：磁碟快取命中
    /// （TTL 7 天）直接回 data URI；miss → 單飛閘＋雙重檢查 → 打伺服器
    /// `{base}icons/{host}/icon.png`（root 路徑，VW 實錄）→ 原子落盤 → 回包。
    /// 404／非法 host／未解鎖（無 client）＝None，UI 退字母磚。
    pub async fn icon_data_uri(&self, host: &str) -> Option<String> {
        if !valid_icon_host(host) {
            return None;
        }
        let dir = self.dir.join("icons");
        let file = dir.join(format!("{host}.png"));
        if fresh_icon_cache(&file, ICON_TTL_MS, self.now_ms()) {
            if let Ok(bytes) = std::fs::read(&file)
                && let Some(uri) = icon_data_uri(&bytes)
            {
                return Some(uri);
            }
        }
        let client = self.unlocked_client()?;
        let _gate = self.icon_gate.lock().await;
        if fresh_icon_cache(&file, ICON_TTL_MS, self.now_ms()) {
            if let Ok(bytes) = std::fs::read(&file)
                && let Some(uri) = icon_data_uri(&bytes)
            {
                return Some(uri);
            }
        }
        let bytes = match client.fetch_icon(host).await {
            Ok(b) => b,
            Err(e) => {
                log::debug!("icon: {host} 取圖失敗：{e}");
                return None;
            }
        };
        if bytes.is_empty() {
            return None;
        }
        let uri = icon_data_uri(&bytes)?;
        if std::fs::create_dir_all(&dir).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            let tmp = dir.join(format!("{host}.png.partial"));
            if std::fs::write(&tmp, &bytes).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                }
                let _ = std::fs::rename(&tmp, &file);
            }
        }
        Some(uri)
    }

    /// 鎖定：丟棄 user key（Drop 即清零）與 token；鏡像與帳號檔留著。
    /// 封存檔（`sealed.json`）也留著——鎖定不等於登出，解鎖閘因此能給
    /// 「生物辨識直接解鎖」（同 macOS 裝置斷言語意：鑰匙歸零、封存不動）。
    pub fn sign_out(&self) {
        let mut g = self.unlocked.lock().expect("hub mutex poisoned");
        g.take();
        log::info!("hub: signed out（金鑰已歸零）");
    }
}

// —— Keystore 封存與免重派生解鎖（P4b 第五批，契約 §1「Keystore 封存」列）——
//
// 形態（實測收斂，findings 第五批）：Kotlin 持 AndroidKeyStore AES-256-GCM
// Class 3 金鑰（需使用者驗證＋30 秒視窗＋解鎖裝置要求；emulator 無 StrongBox
// 走軟體 Keystore 降級路），金鑰材料永不出 Keystore；Rust 持 `sealed.json`
// 的記錄格式、漂移判定與落地。user key 明文只在 seal/unseal 兩個瞬間以
// `Zeroizing<Vec<u8>>` 過橋（契約 §2.7 規則 1：不經 Kotlin String）。
// `puk` 錨定封存當下的 Protected Symmetric Key：主密碼在別處改過 → 下次
// 登入換 PUK → 漂移即作廢舊封存（寧可多打一次主密碼，不拿錯鑰解鏡像）。

/// `sealed.json` 的落盤記錄（`v` 留格式升級位；blob = IV‖密文‖tag base64，
/// 對 Rust 不透明——切 IV 是 Keystore 側的事）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedRecord {
    pub v: u8,
    pub email: String,
    pub puk: String,
    pub blob_b64: String,
}

const SEALED_V: u8 = 1;

/// 封存記錄 ↔ 帳號檔的一致性判定（純函數）：版本、信箱、PUK 三者全對才算
/// 可用；任一漂移＝封存作廢。
pub fn sealed_matches(rec: &SealedRecord, acc: &Account) -> bool {
    rec.v == SEALED_V
        && rec.email == acc.email
        && Some(rec.puk.as_str()) == acc.protected_user_key.as_deref()
}

/// blob 解碼（base64 破損或短於 `IV(12)+tag(16)+最小 key(1)` 視同無封存）。
pub fn sealed_blob(rec: &SealedRecord) -> Option<Vec<u8>> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(&rec.blob_b64).ok()?;
    (raw.len() >= 29).then_some(raw)
}

/// 背景推送退避（純函數，節拍語意同 daemon `drain_backoff`）：連續失敗第
/// n 次 → 30s·2^(n-1)，上限 10 分鐘；n=0 回 0（首輪直接跑）。
pub fn drain_backoff(failures: u32) -> std::time::Duration {
    if failures == 0 {
        return std::time::Duration::ZERO;
    }
    let secs = 30u64
        .saturating_mul(1u64 << (failures - 1).min(16))
        .min(600);
    std::time::Duration::from_secs(secs)
}

/// 背景 pull 節拍（契約路线 3：15 分鐘；JobScheduler 週期同值，這裡是
/// 「解鎖期間順手拉」的閘門）。
pub const SYNC_PERIOD: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// 背景輪連續失敗上限（超過即讓位：`HubService` 收工，下個 job 再來）。
const DRAIN_MAX_FAILURES: u32 = 6;

impl Hub {
    fn sealed_path(&self) -> PathBuf {
        self.dir.join("sealed.json")
    }

    /// 讀封存記錄（檔不存在／JSON 破損＝None；判定可用性另走 `has_sealed`）。
    fn read_sealed(&self) -> Option<SealedRecord> {
        let text = std::fs::read_to_string(self.sealed_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// 有可用封存（記錄存在且與帳號檔無漂移）：登入頁生物辨識鈕的閘門，
    /// 也是孤島冷啟「靜默解封 or 誠實鎖態」的判定依據。
    pub fn has_sealed(&self) -> bool {
        match (self.read_sealed(), self.account()) {
            (Some(rec), Some(acc)) => sealed_matches(&rec, &acc) && sealed_blob(&rec).is_some(),
            _ => false,
        }
    }

    /// 解鎖成功點呼叫：user key 交孤島包裹後落地（覆寫舊封存）。
    pub async fn seal_now(&self) -> Result<(), String> {
        let acc = self.account().ok_or("沒有帳號檔，無從封存")?;
        let puk = acc
            .protected_user_key
            .clone()
            .ok_or("帳號檔沒有 Protected User Key")?;
        let key = self.unlocked_user_key().ok_or("尚未解鎖")?;
        let blob = crate::island::seal(Zeroizing::new(key.as_bytes().to_vec())).await?;
        use base64::Engine;
        let rec = SealedRecord {
            v: SEALED_V,
            email: acc.email,
            puk,
            blob_b64: base64::engine::general_purpose::STANDARD.encode(blob.as_slice()),
        };
        let text = serde_json::to_string_pretty(&rec).map_err(|e| format!("封存序列化失敗：{e}"))?;
        std::fs::write(self.sealed_path(), text).map_err(|e| format!("封存落地失敗：{e}"))?;
        log::info!("keystore sealed user key（冷啟免重派生就緒）");
        Ok(())
    }

    /// 免主密碼解鎖：讀封存 → 孤島解封（`prompt` 決定可否拉生物辨識）→
    /// 以 refresh token 重建 client → 裝回 `unlocked` 槽 → 順手 pull
    /// （失敗不擋：鏡像本來就在本地，離線照讀）。
    pub async fn unseal(self: &Arc<Self>, prompt: bool) -> Result<Snapshot, String> {
        if self.is_unlocked() {
            return self.local_snapshot().ok_or_else(|| "已解鎖但帳號檔缺失".to_owned());
        }
        let acc = self.account().ok_or("尚未登入過，無從解封")?;
        let Some(rec) = self.read_sealed() else {
            return Err("沒有封存記錄".to_owned());
        };
        if !sealed_matches(&rec, &acc) || sealed_blob(&rec).is_none() {
            let _ = std::fs::remove_file(self.sealed_path());
            log::info!("keystore sealed user key 作廢（漂移或破損），需主密碼重登");
            return Err("封存已失效（主密碼在別處改過？），請以主密碼登入".to_owned());
        }
        let blob = sealed_blob(&rec).unwrap_or_default();
        let plain = crate::island::unseal(blob, prompt).await.map_err(|e| {
            // 靜默路失敗只是「驗證視窗過了」，封存保留；彈窗路失敗（取消／
            // 逾時／金鑰作廢）由 Kotlin 側自行清鑰，這裡不誤刪記錄。
            if prompt { e } else { format!("{e}（需生物辨識或主密碼）") }
        })?;
        let user_key = bw_crypto::UserKey::from_bytes(plain.to_vec())
            .map_err(|e| format!("解封出的金鑰形態不對：{e}"))?;
        let client = Arc::new(
            Client::with_options(&acc.server, Self::options())
                .map_err(|e| format!("服務器網址無效：{e}"))?,
        );
        client.set_refresh_token(acc.refresh_token.as_deref()).await;
        // 續期輪換下來的 refresh token 要落地，否則下次冷啟握的是死憑證
        // （daemon 同法：sink 直寫 account.json；Account 結構不認 access_token
        // 欄，多寫的鍵在讀取端自然忽略）。
        let weak = Arc::downgrade(self);
        client.set_token_sink(Arc::new(move |access, refresh| {
            let Some(h) = weak.upgrade() else { return };
            let path = h.dir.join("account.json");
            if let Ok(bytes) = std::fs::read(&path)
                && let Ok(mut v) = serde_json::from_slice::<Value>(&bytes)
            {
                v["access_token"] = json!(access);
                if let Some(r) = refresh {
                    v["refresh_token"] = json!(r);
                }
                let _ = std::fs::write(path, v.to_string());
            }
        }));
        // 冷啟沒有 access token（帳號檔不存它），而 401 收口只對「過期的舊
        // token」觸發續期（`send`：`sent_with.is_some()` 閘，實錄 13:33
        // "not authenticated"）→ 裝鑰前先主動跑一發 refresh grant。
        if let Err(e) = client.refresh().await {
            log::warn!("unseal refresh 未成（背景輪再試）：{e}");
        }
        {
            let mut g = self.unlocked.lock().expect("hub mutex poisoned");
            *g = Some(Unlocked { client: client.clone(), user_key });
        }
        log::info!("keystore unseal ok（免重派生解鎖）");
        if let Err(e) = self.pull_and_index(client).await {
            log::warn!("unseal 後同步未完成（本地鏡像照讀）：{e}");
        }
        crate::island::ensure_hub_service();
        self.local_snapshot().ok_or_else(|| "解封後狀態丟失".to_owned())
    }

    /// 本地態 Snapshot（帳號檔＋鏡像計數；unseal／背景路徑共用）。
    fn local_snapshot(&self) -> Option<Snapshot> {
        let acc = self.account()?;
        Some(Snapshot {
            email: acc.email,
            server: acc.server,
            items: self.list("").len(),
            last_sync_ms: self.last_sync_ms.load(Ordering::Relaxed),
        })
    }

    /// `HubService` 的背景輪（Kotlin 工作執行緒經 JNI `block_on` 這條）：
    /// 解鎖態才做事——drain 到結算（連續失敗退避 30s→10min，純函數測），
    /// 結算後距上次 pull 超過 [`SYNC_PERIOD`] 就順手拉。回終態字串給 logcat：
    /// `locked` | `ok` | `ok-synced` | `stalled`。
    pub async fn background_run(&self) -> String {
        if !self.is_unlocked() {
            return "locked".to_owned();
        }
        let mut failures = 0u32;
        loop {
            if self.drain().await {
                let now = self.store.now_ms();
                let last = self.last_sync_ms.load(Ordering::Relaxed);
                if now.saturating_sub(last) >= SYNC_PERIOD.as_millis() as u64
                    && let Some(client) = self.unlocked_client()
                {
                    match self.pull_and_index(client).await {
                        Ok(n) => {
                            log::info!("background sync: 鏡像 {n} 筆");
                            return "ok-synced".to_owned();
                        }
                        Err(e) => log::warn!("background sync 失敗：{e}"),
                    }
                }
                return "ok".to_owned();
            }
            failures += 1;
            if failures > DRAIN_MAX_FAILURES || !self.is_unlocked() {
                return "stalled".to_owned();
            }
            tokio::time::sleep(drain_backoff(failures)).await;
        }
    }
}

// —— vault 寫入路徑（新增／編輯／刪除）——
//
// 語意與 daemon 的 P2 寫路徑同源（契約 §2.4）：本地 transaction（mirror＋
// outbox 同交易）先行，UI 立刻以既有 `pending` 標記顯示「待推送」；push 由
// `drain` 執行，本批只在「重新同步」與登入後的 pull 前觸發（背景同步尚未接，
// 見 README 已知的下一步）。同 item FIFO、租約認領、base_rev CAS＋欄位級三方
// 合併全部沿用 `bw_store`／`bw_vault` 的原語，這裡只做編排，不另發一套流程。

impl Hub {
    fn unlocked_client(&self) -> Option<Arc<Client>> {
        let g = self.unlocked.lock().expect("hub mutex poisoned");
        g.as_ref().map(|u| u.client.clone())
    }

    fn unlocked_user_key(&self) -> Option<bw_crypto::UserKey> {
        let g = self.unlocked.lock().expect("hub mutex poisoned");
        g.as_ref().map(|u| u.user_key.clone())
    }

    /// 新增：本地鏡像＋outbox 同交易入列（離線也成功），回本地 id。
    /// 推送收斂後本地 id 由 `remap_item` 換成伺服器 id（與 daemon A7 同路徑）。
    pub fn create(&self, draft: &CipherDraft) -> Result<ItemId, String> {
        let user_key = self.unlocked_user_key().ok_or("尚未解鎖")?;
        if let Some(f) = &draft.folder_id
            && uuid::Uuid::parse_str(f).is_err()
        {
            return Err(format!("folderId 需為 UUID 字串，got {f:?}"));
        }
        let id = uuid::Uuid::new_v4();
        let cipher = encrypt_login_draft(&user_key, draft, id);
        self.store
            .put_mirror(id, &cipher)
            .map_err(|e| e.to_string())?;
        let mut body = cipher.clone();
        if let Some(o) = body.as_object_mut() {
            o.remove("id");
        }
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "create", "cipher": body}),
                base_rev: None,
                origin: Some("vault-ui"),
                mirror: None,
            })
            .map_err(|e| e.to_string())?;
        self.reindex_ids([id])?;
        log::info!("hub: create {id}（待推送）");
        // 寫入即踢背景輪（daemon `trigger_drain` 等位）：HubService 起來 drain
        // 收斂「待推送」，無須手動「重新同步」（路線 3 背景同步）。
        crate::island::ensure_hub_service();
        Ok(id)
    }

    /// 編輯：欄位級 patch（path 文法＝`bw_proto::FieldEdit` 權威定義）。
    /// 未列出的欄位原樣保留（鏡像無損往返，不变量 8）。預驗＋ours 構造＋
    /// touched 詞彙全部對齊 daemon `write_patch`：leaf 值走 `apply_merged`、
    /// 陣列增刪走 field/uri ops（先刪由大而小、再附加落尾）、內容金鑰逐列
    /// 解析（新建形態＝item key）。
    pub fn patch(&self, id: ItemId, edits: &[FieldEdit]) -> Result<(), String> {
        let user_key = self.unlocked_user_key().ok_or("尚未解鎖")?;
        let row = self
            .store
            .item(id)
            .map_err(|e| e.to_string())?
            .ok_or("找不到這筆項目")?;
        // org 共享項目的寫側金鑰是 org 對稱鑰，本批沒有 akey 解封路徑：
        // 直接拒絕，絕不以 user key 產生解不開的密文（daemon 同語意）。
        if row
            .enc_cipher
            .get("organizationId")
            .and_then(Value::as_str)
            .is_some()
        {
            return Err("組織共享項目暫不支援編輯".to_owned());
        }
        let base = row.enc_cipher;
        validate_edits(&base, edits)?;
        let key = cipher_content_key(&user_key, &base)
            .ok_or("金鑰解析失敗（item key 解不開，請重新同步或重解）")?;
        let enc = |v: &str| {
            bw_crypto::encrypt_bytes_key(&key, v.as_bytes()).unwrap_or_default()
        };
        let map: bw_vault::FieldMap = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::Set { path, value } => Some((path.clone(), value.clone())),
                FieldEdit::SetType { index, kind } => Some((
                    format!("field.{index}.type"),
                    Some(bw_vault::type_word(kind.wire() as i64)?.to_string()),
                )),
                // match 走 leaf 座標系（uri.<n>.match）明文整數：three_way
                // 看得見判定改動（同 daemon write_patch 口徑）。
                FieldEdit::SetUriMatch { index, match_type } => Some((
                    format!("uri.{index}.match"),
                    match_type.map(|m| m.to_string()),
                )),
                _ => None,
            })
            .collect();
        let ours = bw_vault::apply_merged(&base, &map, &enc);
        // 陣列形態操作（Set 型 leaf 做不到的增刪）：先刪後附加，全部落在
        // ours 副本上（daemon apply_field_ops/apply_uri_ops 同族紀律）。
        let removes_f: Vec<usize> = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::RemoveField { index } => Some(*index as usize),
                _ => None,
            })
            .collect();
        let appends_f: Vec<&CipherField> = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::AppendField { field } => Some(field),
                _ => None,
            })
            .collect();
        let removes_u: Vec<usize> = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::RemoveUri { index } => Some(*index as usize),
                _ => None,
            })
            .collect();
        let appends_u: Vec<&str> = edits
            .iter()
            .filter_map(|e| match e {
                FieldEdit::AppendUri { uri } => Some(uri.as_str()),
                _ => None,
            })
            .collect();
        let ours = apply_field_ops(ours, &removes_f, &appends_f, &enc);
        let ours = apply_uri_ops(ours, &removes_u, &appends_u, &enc);
        let touched: Vec<String> = edits
            .iter()
            .map(|e| match e {
                FieldEdit::Set { path, .. } => path.clone(),
                FieldEdit::SetType { index, .. } => format!("field.{index}.type"),
                FieldEdit::AppendField { .. } => "field.append".to_string(),
                FieldEdit::RemoveField { index } => format!("field.remove.{index}"),
                FieldEdit::AppendUri { .. } => "uri.append".to_string(),
                FieldEdit::RemoveUri { index } => format!("uri.remove.{index}"),
                FieldEdit::SetUriMatch { index, .. } => format!("uri.{index}.match"),
            })
            .collect();
        let raw = self.store.raw(id).map_err(|e| e.to_string())?;
        let rev = row_rev_of(&raw);
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "patch", "base": base, "ours": ours, "touched": touched}),
                base_rev: rev.as_deref(),
                origin: Some("vault-ui"),
                mirror: Some(&ours),
            })
            .map_err(|e| e.to_string())?;
        self.reindex_ids([id])?;
        log::info!("hub: patch {id}（待推送）");
        crate::island::ensure_hub_service();
        Ok(())
    }

    /// AutofillService 儲存真寫入（onSaveRequest 落地端，JNI 橋呼叫）：
    /// - `uri` 是 web host、origin 或 app package（孤島從 AssistStructure 取
    ///   webDomain／package，語意同填充查詢鍵）；
    /// - 既有項目（同 host 候選 × 同帳號）→ 密碼不同才 patch（欄位級存活），
    ///   相同＝unchanged 零寫入（冪等：重複提交不產生第二筆 outbox）；
    /// - 查無組合 → create 一筆 Login（名稱取 host/package、uri 落 https:// 形態）。
    /// 本地交易先行＝離線也成功，「待推送」由既有 drain 收斂；回 (id, 動作)。
    pub fn save_from_autofill(
        &self,
        uri: &str,
        username: &str,
        password: &str,
    ) -> Result<(ItemId, &'static str), String> {
        if !self.is_unlocked() {
            return Err("尚未解鎖".to_owned());
        }
        let key = uri.trim();
        if key.is_empty() {
            return Err("儲存需要網址或套件名".to_owned());
        }
        let candidates = self.candidates_for(key, 10);
        for (id, _) in candidates {
            let Ok(r) = self.reveal(id) else { continue };
            if r.username.as_deref().unwrap_or("") != username {
                continue;
            }
            if r.password.as_ref().map(|p| p.as_str()).unwrap_or("") == password {
                return Ok((id, "unchanged"));
            }
            // 密碼改了（改密流）：只動 password 欄，其餘欄位級存活。
            self.patch(
                id,
                &[FieldEdit::Set {
                    path: "password".into(),
                    value: Some(password.to_owned()),
                }],
            )?;
            return Ok((id, "updated"));
        }
        let name = host_of(key).unwrap_or_else(|| key.to_owned());
        let url = if key.contains("://") {
            key.to_owned()
        } else {
            format!("https://{key}")
        };
        let id = self.create(&CipherDraft {
            kind: bw_proto::ItemKind::Login,
            name,
            username: (!username.is_empty()).then(|| username.to_owned()),
            password: (!password.is_empty()).then(|| password.to_owned()),
            totp: None,
            uris: vec![url],
            notes: None,
            favorite: false,
            folder_id: None,
            fields: Vec::new(),
            uri_matches: Vec::new(),
        })?;
        Ok((id, "created"))
    }

    /// 刪除：軟刪（tombstone）。鏡像立刻標 `deletedDate`＝列表即刻消失，
    /// 伺服器端標記在 drain 送達；同步 pull 後收斂。
    pub fn delete(&self, id: ItemId) -> Result<(), String> {
        // 與 daemon 一致：刪除要求解鎖態（金鑰虽不參與 tombstone，但鎖定时
        // 使用者無法驗證刪的是哪筆明文，誤刪成本不對稱）。
        let _user_key = self.unlocked_user_key().ok_or("尚未解鎖")?;
        let row = self
            .store
            .item(id)
            .map_err(|e| e.to_string())?
            .ok_or("找不到這筆項目")?;
        let mut mirror = row.enc_cipher;
        if let Some(o) = mirror.as_object_mut() {
            o.insert("deletedDate".into(), json!(rfc3339_now()));
        }
        let raw = self.store.raw(id).map_err(|e| e.to_string())?;
        let rev = row_rev_of(&raw);
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "delete"}),
                base_rev: rev.as_deref(),
                origin: Some("vault-ui"),
                mirror: Some(&mirror),
            })
            .map_err(|e| e.to_string())?;
        log::info!("hub: delete {id}（軟刪，待推送）");
        crate::island::ensure_hub_service();
        Ok(())
    }

    /// outbox drain：認領→推送→結算，直到清空或遇到需稍後重試的列。
    /// 回 `true`＝已全部結算；`false`＝有列回到 queued（離線／限流／token 待刷）。
    pub async fn drain(&self) -> bool {
        let _g = self.drain_lock.lock().await;
        loop {
            let (Some(client), Some(user_key)) = (self.unlocked_client(), self.unlocked_user_key())
            else {
                return false;
            };
            let due = match self.store.take_due(16) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("drain: take_due 失敗：{e}");
                    return false;
                }
            };
            if due.is_empty() {
                return true;
            }
            for m in due {
                if !self.push_one(&client, &user_key, &m).await {
                    return false;
                }
            }
        }
    }

    /// 回 `false`＝同序列後續列也別再推（FIFO 頭未結算）。
    async fn push_one(&self, client: &Client, user_key: &bw_crypto::UserKey, m: &Mutation) -> bool {
        let op = m
            .payload
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match op {
            "create" => {
                let body = m.payload.get("cipher").cloned().unwrap_or(json!({}));
                match client.cipher_create(&body).await {
                    Ok(created) => {
                        if let Some(new_id) = cipher_id(&created) {
                            if new_id != m.item {
                                let _ = self.store.remap_item(m.item, new_id);
                            }
                            let _ = self.store.put_mirror(new_id, &created);
                            let _ = self.reindex_ids([new_id]);
                        }
                        self.settle_applied(m.id)
                    }
                    Err(e) => self.settle_retry_or_dead(m.id, &e),
                }
            }
            "patch" => self.push_patch(client, user_key, m).await,
            "delete" => match client.cipher_delete(m.item, DeleteKind::Soft).await {
                Ok(()) => self.settle_applied(m.id),
                Err(e) => self.settle_retry_or_dead(m.id, &e),
            },
            "restore" => match client.cipher_restore(m.item).await {
                Ok(()) => self.settle_applied(m.id),
                Err(e) => self.settle_retry_or_dead(m.id, &e),
            },
            other => {
                log::error!("drain: 未知 op「{other}」，結算為 dead");
                let _ = self.store.settle(m.id, MutState::Dead);
                true
            }
        }
    }

    /// patch 推送：base_rev CAS 命中直接推 ours；漂移走欄位級三方合併
    /// （明文域比較，`bw_vault::three_way`）；伺服器已無此列→衝突收件匣。
    async fn push_patch(
        &self,
        client: &Client,
        user_key: &bw_crypto::UserKey,
        m: &Mutation,
    ) -> bool {
        let theirs = match client.cipher_get(m.item).await {
            Ok(t) => t,
            Err(e) if e.status() == Some(404) => {
                log::warn!("drain: patch {} 已被他端刪除，進衝突收件匣", m.item);
                let _ = self.store.settle(m.id, MutState::Conflict);
                return true;
            }
            Err(e) => return self.settle_retry_or_dead(m.id, &e),
        };
        let their_rev = theirs
            .get("revisionDate")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let base_enc = m.payload.get("base").cloned().unwrap_or(json!({}));
        let ours_enc = m
            .payload
            .get("ours")
            .cloned()
            .unwrap_or_else(|| base_enc.clone());
        // 寫側與基準共用同一枚內容金鑰（enqueue 時就按 base 的 `key` 欄解析）；
        // theirs 是伺服器現態，可能已被他端換鑰重建——各自獨立解析。
        let Some(our_key) = cipher_content_key(user_key, &base_enc) else {
            log::error!("drain: patch {} 基準 item key 解不開，回 queued", m.item);
            let _ = self.store.settle(m.id, MutState::Queued);
            return false;
        };
        let their_key = cipher_content_key(user_key, &theirs);
        let enc = |v: &str| {
            bw_crypto::encrypt_bytes_key(&our_key, v.as_bytes()).unwrap_or_default()
        };
        let body = if m.base_rev.is_some() && their_rev == m.base_rev {
            ours_enc
        } else {
            let dec = decryptor_with_key(&our_key);
            let dec_theirs = match &their_key {
                Some(k) => decryptor_with_key(k),
                None => decryptor_with_key(&our_key),
            };
            let base = bw_vault::flatten(&base_enc, &dec);
            let ours = bw_vault::flatten(&ours_enc, &dec);
            let theirs_m = bw_vault::flatten(&theirs, &dec_theirs);
            match bw_vault::three_way(&base, &ours, &theirs_m) {
                bw_vault::Merge::Push(map) => {
                    if map.is_empty() {
                        // 我們的變更已被伺服器涵蓋：收斂鏡像即可，不用 PUT。
                        let _ = self.store.put_mirror(m.item, &theirs);
                        let _ = self.reindex_ids([m.item]);
                        return self.settle_applied(m.id);
                    }
                    bw_vault::apply_merged(&theirs, &map, &enc)
                }
                bw_vault::Merge::Noop => {
                    let _ = self.store.put_mirror(m.item, &theirs);
                    let _ = self.reindex_ids([m.item]);
                    return self.settle_applied(m.id);
                }
                bw_vault::Merge::Conflict { fields } => {
                    log::warn!("drain: patch {} 欄位相撞 {fields:?}，進衝突收件匣", m.item);
                    let _ = self.store.settle(m.id, MutState::Conflict);
                    return true;
                }
            }
        };
        let mut body = body;
        if let Some(o) = body.as_object_mut() {
            o.insert("id".into(), json!(m.item.to_string()));
        }
        match client.cipher_put(m.item, &body).await {
            Ok(resp) => {
                if let Some(nid) = cipher_id(&resp) {
                    let _ = self.store.put_mirror(nid, &resp);
                    let _ = self.reindex_ids([nid]);
                }
                self.settle_applied(m.id)
            }
            Err(e) => self.settle_retry_or_dead(m.id, &e),
        }
    }

    fn settle_applied(&self, id: bw_proto::MutationId) -> bool {
        match self.store.settle(id, MutState::Applied) {
            Ok(()) => true,
            Err(e) => {
                log::error!("drain: settle 失敗：{e}");
                false
            }
        }
    }

    /// 離線／限流／401 → 回 queued 稍後重試（本批 in-process 沒有 token
    /// 刷新路徑，下一次登入或同步自然重推）；其他 4xx/5xx → dead。
    fn settle_retry_or_dead(&self, id: bw_proto::MutationId, e: &bw_server::ServerError) -> bool {
        if e.is_rate_limited() || e.status().is_none() || e.is_auth_rejected() {
            let _ = self.store.settle(id, MutState::Queued);
            log::warn!("drain: 稍後重試（{e}）");
            false
        } else {
            log::error!("drain: 永久失敗，結算 dead：{e}");
            let _ = self.store.settle(id, MutState::Dead);
            true
        }
    }
}

/// 鏡像 `login.uris[].match` 明文整數投影（順序對齊 uris；缺欄/null＝None）。
fn uri_match_rows(cipher: &Value) -> Vec<Option<u8>> {
    cipher
        .pointer("/login/uris")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|u| u.get("match").and_then(Value::as_u64).map(|m| m as u8))
                .collect()
        })
        .unwrap_or_default()
}

/// 鏡像 `fields[]` → 明文 `CipherField` 列（詳情節與編輯預填用；信封解不開
/// 的單欄跳過，容忍漂移同 plain_index）。
fn field_rows(cipher: &Value, dec: &dyn Fn(&str) -> Option<String>) -> Vec<CipherField> {
    cipher
        .get("fields")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let name = f.get("name").and_then(Value::as_str).and_then(dec)?;
                    let kind = match f.get("type").and_then(Value::as_i64) {
                        Some(1) => bw_proto::CipherFieldKind::Hidden,
                        Some(2) => bw_proto::CipherFieldKind::Boolean,
                        _ => bw_proto::CipherFieldKind::Text,
                    };
                    Some(CipherField {
                        name,
                        value: f.get("value").and_then(Value::as_str).and_then(dec),
                        kind,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 快取有效期：7 天（同 daemon icon.rs：圖示極少變動）。
const ICON_TTL_MS: u64 = 7 * 24 * 3600 * 1000;

/// host 白名單校驗（快取檔名直接拼 `icons/{host}.png`，不擋路徑穿越＝
/// 讓呼叫端寫任意檔；口徑同 daemon `valid_host`）。
fn valid_icon_host(host: &str) -> bool {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    ok && !host.starts_with('*')
}

/// 快取新鮮度：檔存在且 mtime 距今 < ttl（同 daemon `fresh_cache`）。
fn fresh_icon_cache(path: &std::path::Path, ttl_ms: u64, now: u64) -> bool {
    path.metadata()
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| now.saturating_sub(d.as_millis() as u64) < ttl_ms)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// 位元組 → `data:` URI（magic 決定 MIME，同 macOS `icon_data_uri`：
/// VW 的 icon 代理可能回 PNG 或站方 ICO，解不了的形態回 None＝字母磚）。
fn icon_data_uri(bytes: &[u8]) -> Option<String> {
    use base64::Engine;
    let mime = if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        "image/x-icon"
    } else {
        return None;
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("data:{mime};base64,{b64}"))
}

/// 從 uri 字串取 host（同 macOS `state::host_of`：favicon 查詢鍵；
/// 無點且非 localhost 的（app package、`about:` 等）回 None＝字母磚）。
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

/// CipherDraft → 信封形態 cipher（與 daemon `encrypt_draft` 同形態：每枚隨機
/// 64B item key（enc‖mac），`key` 欄存 user key 包的它、內容欄全用 item key
/// 加密——新建項目對官方客戶端與我們都原生；uris 整陣列、folderId 明碼、
/// fields[] 官方形態、favorite 明碼）。
fn encrypt_login_draft(uk: &bw_crypto::UserKey, d: &CipherDraft, id: ItemId) -> Value {
    let mut ik = vec![0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ik);
    let enc = |s: &str| bw_crypto::encrypt_bytes_key(&ik, s.as_bytes()).unwrap_or_default();
    let mut c = json!({
        "type": match d.kind {
            bw_proto::ItemKind::Login => 1,
            bw_proto::ItemKind::SecureNote => 2,
            bw_proto::ItemKind::Card => 3,
            bw_proto::ItemKind::Identity => 4,
        },
        "name": enc(&d.name),
        "favorite": d.favorite,
        "key": bw_crypto::encrypt_bytes_key(uk.as_bytes(), &ik).unwrap_or_default(),
        "id": id.to_string(),
    });
    if let Some(f) = &d.folder_id {
        c["folderId"] = json!(f);
    }
    if let Some(n) = &d.notes {
        c["notes"] = json!(enc(n));
    }
    if !d.fields.is_empty() {
        let fields: Vec<Value> = d
            .fields
            .iter()
            .map(|f| {
                json!({
                    "name": enc(&f.name),
                    "value": f.value.as_deref().map(enc),
                    "linkedId": null,
                    "type": f.kind.wire(),
                })
            })
            .collect();
        c["fields"] = Value::Array(fields);
    }
    let mut login = serde_json::Map::new();
    if let Some(u) = &d.username {
        login.insert("username".into(), json!(enc(u)));
    }
    if let Some(p) = &d.password {
        login.insert("password".into(), json!(enc(p)));
    }
    if let Some(t) = &d.totp {
        login.insert("totp".into(), json!(enc(t)));
    }
    if !d.uris.is_empty() {
        let uris: Vec<Value> = d
            .uris
            .iter()
            .enumerate()
            .map(|(i, u)| {
                json!({"uri": enc(u), "match": d.uri_matches.get(i).copied().flatten().map(|m| m as i64)})
            })
            .collect();
        login.insert("uris".into(), json!(uris));
    }
    if !login.is_empty() {
        c["login"] = Value::Object(login);
    }
    c
}

/// 單筆 cipher 的內容加密金鑰（三態解析器，與 daemon `cipher_decrypt_key`
/// 同口徑，Android 無 org 共享寫入路徑所以候選只有 user key）：
/// - 帶 `key` 欄＝新建形態：item key（64B enc‖mac，或 legacy 32B）以 user
///   key 包存欄，內容欄全用 item key 加密；
/// - 無 `key` 欄＝舊內容直掛 user key（本 app 2026-11-08 前的既有鏡像）。
/// 解不開回 None（金鑰漂移≠空字串，呼叫端容忍跳過）。
fn cipher_content_key(uk: &bw_crypto::UserKey, cipher: &Value) -> Option<Zeroizing<Vec<u8>>> {
    match cipher.get("key").and_then(Value::as_str) {
        Some(env) => bw_crypto::decrypt_bytes_with_key(uk.as_bytes(), env)
            .ok()
            .filter(|ik| ik.len() == 32 || ik.len() == 64)
            .map(Zeroizing::new),
        None => Some(Zeroizing::new(uk.as_bytes().to_vec())),
    }
}

/// 依解析出的內容金鑰構造欄位解密閉包（形態同 daemon `cipher_field_decryptor`
/// 的个人項目分支；單欄解不開回 None，容忍漂移）。
fn decryptor_with_key(
    key: &Zeroizing<Vec<u8>>,
) -> impl Fn(&str) -> Option<String> + '_ {
    move |s: &str| {
        bw_crypto::decrypt_bytes_with_key(key, s)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    }
}

/// 三件套路徑預驗（入列前擋，不讓越界編輯靜默蒸發；口徑同 daemon
/// `write_patch` 預驗段）：`field.<n>.<leaf>` 的 n 必須落在現有 fields[] 內、
/// folderId 值為 UUID、SetType/RemoveField 按 index 同紀律、Append 要內容。
fn validate_edits(base: &Value, edits: &[FieldEdit]) -> Result<(), String> {
    let n_fields = base
        .get("fields")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let n_uris = base
        .pointer("/login/uris")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    for e in edits {
        match e {
            FieldEdit::SetType { index, .. } | FieldEdit::RemoveField { index } => {
                if (*index as usize) >= n_fields {
                    return Err(format!("field.{index} 越界：本項目只有 {n_fields} 個自訂欄位"));
                }
            }
            FieldEdit::RemoveUri { index } => {
                if (*index as usize) >= n_uris {
                    return Err(format!("uri.{index} 越界：本項目只有 {n_uris} 列網址"));
                }
            }
            FieldEdit::SetUriMatch { index, match_type } => {
                if (*index as usize) >= n_uris {
                    return Err(format!("uri.{index} 越界：本項目只有 {n_uris} 列網址"));
                }
                // 官方 UriMatchType：null|0..5（值域預驗同 daemon write_patch）。
                if match_type.is_some_and(|m| m > 5) {
                    return Err(format!("match 值域 null|0..5，got {match_type:?}"));
                }
            }
            FieldEdit::AppendUri { uri } => {
                if uri.trim().is_empty() {
                    return Err("新增網址列需要內容".to_owned());
                }
            }
            FieldEdit::AppendField { field } => {
                if field.name.is_empty() {
                    return Err("新增自訂欄需要欄名".to_owned());
                }
            }
            FieldEdit::Set { path, value } => {
                if let Some(rest) = path.strip_prefix("field.") {
                    let (id_s, leaf) = rest.rsplit_once('.').unwrap_or((rest, ""));
                    if !matches!(leaf, "name" | "value" | "type") {
                        return Err(format!("欄位路徑需 field.<n>.name|value|type，got {path:?}"));
                    }
                    let n = id_s
                        .parse::<usize>()
                        .map_err(|_| format!("field 索引需為數字，got {id_s:?}"))?;
                    if n >= n_fields {
                        return Err(format!("field.{n} 越界：本項目只有 {n_fields} 個自訂欄位"));
                    }
                    if leaf == "type"
                        && let Some(v) = value.as_deref()
                        && bw_vault::wire_of_type_word(v).is_none()
                    {
                        return Err(format!("field type 值域 text|hidden|boolean，got {v:?}"));
                    }
                }
                if path == "folderId"
                    && let Some(v) = value.as_deref()
                    && uuid::Uuid::parse_str(v).is_err()
                {
                    return Err(format!("folderId 需為 UUID 字串，got {v:?}"));
                }
            }
        }
    }
    Ok(())
}

/// fields[] 陣列操作（daemon `apply_field_ops` 等位物）：removes 由大而小
/// 先刪（免位移），appends 依序附加（官方形態 name/value 信封、linkedId null、
/// type 整數）。兩組皆空＝原值不動。
fn apply_field_ops(
    mut ours: Value,
    removes: &[usize],
    appends: &[&CipherField],
    enc: &dyn Fn(&str) -> String,
) -> Value {
    if removes.is_empty() && appends.is_empty() {
        return ours;
    }
    let obj = ours.as_object_mut().expect("cipher must be object");
    let fields = obj
        .entry("fields")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !fields.is_array() {
        *fields = Value::Array(Vec::new());
    }
    let arr = fields.as_array_mut().expect("fields must be array");
    remove_indices(arr, removes);
    for f in appends {
        arr.push(json!({
            "name": enc(&f.name),
            "value": f.value.as_deref().map(enc),
            "linkedId": null,
            "type": f.kind.wire(),
        }));
    }
    ours
}

/// `login.uris[]` 陣列操作（daemon `apply_uri_ops` 等位物）：官方形態
/// `{uri:<信封>, match:null}`；無 login 块的材料化、刪除降序紀律同族。
fn apply_uri_ops(
    mut ours: Value,
    removes: &[usize],
    appends: &[&str],
    enc: &dyn Fn(&str) -> String,
) -> Value {
    if removes.is_empty() && appends.is_empty() {
        return ours;
    }
    let obj = ours.as_object_mut().expect("cipher must be object");
    let login = obj.entry("login").or_insert_with(|| json!({}));
    if !login.is_object() {
        *login = json!({});
    }
    let login = login.as_object_mut().expect("login must be object");
    let uris = login
        .entry("uris")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !uris.is_array() {
        *uris = Value::Array(Vec::new());
    }
    let arr = uris.as_array_mut().expect("uris must be array");
    remove_indices(arr, removes);
    for u in appends {
        arr.push(json!({ "uri": enc(u), "match": null }));
    }
    ours
}

/// 索引刪除共同段：越界索引寬容跳過，降序執行免位移（同 daemon）。
fn remove_indices(arr: &mut Vec<Value>, removes: &[usize]) {
    let mut dels: Vec<usize> = removes.iter().copied().filter(|i| *i < arr.len()).collect();
    dels.sort_unstable_by(|a, b| b.cmp(a));
    for i in dels {
        arr.remove(i);
    }
}

fn cipher_id(c: &Value) -> Option<ItemId> {
    c.get("id")
        .and_then(Value::as_str)
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
}

/// 鏡像 raw 列的伺服器版本號（CAS 基準；與 daemon `row_rev_of` 同寬容鏈）。
fn row_rev_of(raw: &Value) -> Option<String> {
    raw.get("rev")
        .and_then(Value::as_str)
        .or_else(|| raw.get("revisionDate").and_then(Value::as_str))
        .or_else(|| raw.pointer("/cipher/revisionDate").and_then(Value::as_str))
        .map(str::to_owned)
}

/// RFC3339 UTC 現在式（tombstone 的 `deletedDate` 用；零依賴日期算術，
/// Howard Hinnant civil_from_days，同 daemon `chrono_now` 的出處）。
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let (y, m) = if m <= 2 { (y + 1, m) } else { (y, m) };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// prelogin 的 KDF 欄位 → `bw_crypto::KdfParams`（寬容：缺欄位退回 PBKDF2 600k）。
fn kdf_from_prelogin(v: &Value) -> bw_crypto::KdfParams {
    let kind = v.get("kdf").and_then(Value::as_i64).unwrap_or(0);
    let iterations = v
        .get("kdfIterations")
        .and_then(Value::as_u64)
        .unwrap_or(600_000);
    let memory = v.get("kdfMemory").and_then(Value::as_u64);
    let parallelism = v.get("kdfParallelism").and_then(Value::as_u64);
    if kind == 1 {
        bw_crypto::KdfParams::Argon2id {
            m: memory.unwrap_or(64) as u32,
            t: iterations as u32,
            p: parallelism.unwrap_or(4) as u32,
        }
    } else {
        bw_crypto::KdfParams::Pbkdf2 {
            iterations: iterations as u32,
        }
    }
}

/// `KdfParams` → 帳號檔的四個原始欄位（存回来時走同一條 `kdf_from_prelogin` 語意）。
fn kdf_wire(k: &bw_crypto::KdfParams) -> (i64, u64, Option<u64>, Option<u64>) {
    match *k {
        bw_crypto::KdfParams::Pbkdf2 { iterations } => (0, u64::from(iterations), None, None),
        bw_crypto::KdfParams::Argon2id { m, t, p } => {
            (1, u64::from(t), Some(u64::from(m)), Some(u64::from(p)))
        }
    }
}

/// 本機資料目錄。
///
/// Android 的 app 進程沒有可寫的 `$HOME`；nsh 0.3.0 把 Java 層的 `filesDir`
/// 只放進 JS runtime 的 `System.data_dir`，純 Rust app 拿不到（實測見
/// `docs/design/android-findings.md`）。正式解已就位：外殼的
/// `BitwardApplication` 在**任何進程入口之前**把 `BITWARD_ANDROID_DATA`
/// 指向 `noBackupFilesDir/bitward`（不被系統清、不進 Auto Backup——鏡像含
/// 明文索引欄，備份出裝置即破契約 §2.7 R3 的本地承載紀律；見 2026-11-07
/// 缺陷修）。TMPDIR 退路只留給沒跑外殼 Application 的場合（純 nsh 包 dev 迴圈）。
pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BITWARD_ANDROID_DATA") {
        return PathBuf::from(d);
    }
    if cfg!(target_os = "android") {
        if let Ok(t) = std::env::var("TMPDIR") {
            return PathBuf::from(t).join("bitward");
        }
        return PathBuf::from("/data/local/tmp/bitward");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".local/share/bitward-android")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_defaults_to_pbkdf2_when_fields_missing() {
        let k = kdf_from_prelogin(&serde_json::json!({}));
        assert!(matches!(
            k,
            bw_crypto::KdfParams::Pbkdf2 {
                iterations: 600_000
            }
        ));
    }

    #[test]
    fn argon2id_roundtrips_through_account_fields() {
        let k = kdf_from_prelogin(
            &serde_json::json!({"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4}),
        );
        let (kind, it, mem, par) = kdf_wire(&k);
        let back = kdf_from_prelogin(
            &serde_json::json!({"kdf": kind, "kdfIterations": it, "kdfMemory": mem, "kdfParallelism": par}),
        );
        assert_eq!(format!("{back:?}"), format!("{k:?}"));
    }

    #[test]
    fn hub_opens_store_and_reports_zero_items() {
        let dir =
            std::env::temp_dir().join(format!("bitward-android-test-{}", uuid::Uuid::new_v4()));
        let hub = Hub::open(dir.clone()).expect("hub opens");
        assert!(!hub.is_unlocked());
        assert!(hub.list("").is_empty());
        assert!(hub.reveal(ItemId::new_v4()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 解鎖態注入（不走網路）：client 只要構造得出來，drain 之外的路徑不碰它。
    fn unlocked_hub(tag: &str) -> (std::sync::Arc<Hub>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bitward-android-test-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        let hub = Hub::open(dir.clone()).expect("hub opens");
        let user_key = bw_crypto::UserKey::from_bytes(vec![7u8; 64]).unwrap();
        let client = Client::with_options("http://127.0.0.1:1", Hub::options()).expect("client");
        *hub.unlocked.lock().expect("mutex") = Some(Unlocked {
            client: std::sync::Arc::new(client),
            user_key,
        });
        (hub, dir)
    }

    fn draft(name: &str) -> CipherDraft {
        CipherDraft {
            kind: bw_proto::ItemKind::Login,
            name: name.to_owned(),
            username: Some("e2euser".to_owned()),
            password: Some("e2epass".to_owned()),
            totp: None,
            uris: vec!["https://added.example.com".to_owned()],
            notes: None,
            favorite: false,
            folder_id: None,
            fields: Vec::new(),
            uri_matches: Vec::new(),
        }
    }

    #[test]
    fn create_requires_unlock() {
        let dir =
            std::env::temp_dir().join(format!("bitward-android-test-{}", uuid::Uuid::new_v4()));
        let hub = Hub::open(dir.clone()).expect("hub opens");
        assert_eq!(hub.create(&draft("x")).err(), Some("尚未解鎖".to_owned()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_enqueue_marks_pending_and_plain_index() {
        let (hub, dir) = unlocked_hub("create");
        let id = hub.create(&draft("e2e-added")).expect("create ok");
        // 本地鏡像即刻可見＋「待推送」＋明文索引已回填（搜尋找得到新名字）。
        let metas = hub.list("");
        assert_eq!(metas.len(), 1);
        assert!(metas[0].pending, "create 後應掛待推送");
        assert_eq!(metas[0].name.as_deref(), Some("e2e-added"));
        assert_eq!(hub.list("added").len(), 1);
        assert_eq!(hub.store.depth().expect("depth").queued, 1);
        // outbox payload 契約（§2.4）：create 列的 cipher 不带 id。
        let due = hub.store.take_due(4).expect("take_due");
        assert_eq!(due[0].payload["op"], "create");
        assert!(due[0].payload["cipher"].get("id").is_none());
        hub.store
            .settle(due[0].id, MutState::Queued)
            .expect("requeue");
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.password.as_deref().map(|p| p.as_str()), Some("e2epass"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_touches_only_named_fields() {
        let (hub, dir) = unlocked_hub("patch");
        let id = hub.create(&draft("e2e-added")).expect("create ok");
        hub.patch(
            id,
            &[FieldEdit::Set {
                path: "password".to_owned(),
                value: Some("e2epass2".to_owned()),
            }],
        )
        .expect("patch ok");
        // 欄位級存活：沒點名的帳號／網址不動，只有密碼換值。
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.password.as_deref().map(|p| p.as_str()), Some("e2epass2"));
        assert_eq!(r.username.as_deref(), Some("e2euser"));
        assert_eq!(r.uris, vec!["https://added.example.com".to_owned()]);
        // 同 item 兩筆未結算列（create→patch FIFO），pending 仍真。
        assert_eq!(hub.store.depth().expect("depth").queued, 2);
        assert!(hub.list("").first().expect("row").pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_is_soft_and_leaves_outbox_record() {
        let (hub, dir) = unlocked_hub("delete");
        let id = hub.create(&draft("e2e-added")).expect("create ok");
        hub.delete(id).expect("delete ok");
        // 軟刪：列表即刻消失（tombstone），outbox 同 item 兩列（create→delete FIFO）。
        assert!(hub.list("").is_empty());
        assert!(hub.store.item(id).expect("store").expect("row").deleted);
        assert_eq!(hub.store.depth().expect("depth").queued, 2);
        // 同 item 一次只認領最舊列：結算 create 後 delete 列才可出境。
        let head = hub.store.take_due(8).expect("take_due");
        assert_eq!(head.len(), 1);
        assert_eq!(head[0].payload["op"], "create");
        hub.store
            .settle(head[0].id, MutState::Applied)
            .expect("settle");
        let next = hub.store.take_due(8).expect("take_due");
        assert_eq!(next[0].payload["op"], "delete");
        hub.store
            .settle(next[0].id, MutState::Queued)
            .expect("requeue");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rfc3339_now_is_parseable_utc() {
        let s = rfc3339_now();
        // 2026-11-08T12:34:56Z 形態；年、月、日、T、Z 位置全釘死。
        let b = s.as_bytes();
        assert_eq!(b.len(), 20, "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], "Z");
        assert!(s[..4].parse::<u32>().expect("year") >= 2025);
    }

    #[test]
    fn create_uses_item_key_envelope_and_roundtrips() {
        // 新建形態（daemon encrypt_draft 同形）：`key` 欄在、內容欄用 item key
        // 加密；reveal／reindex 走解析器讀得回——官方客戶端拿到同一個鏡像也解得開。
        let (hub, dir) = unlocked_hub("itemkey");
        let fid = uuid::Uuid::new_v4().to_string();
        let id = hub
            .create(&CipherDraft {
                name: "ik-probe".to_owned(),
                notes: Some("私密備註".to_owned()),
                folder_id: Some(fid.clone()),
                fields: vec![CipherField {
                    name: "PIN".to_owned(),
                    value: Some("1234".to_owned()),
                    kind: bw_proto::CipherFieldKind::Hidden,
                }],
                ..draft("ik-probe")
            })
            .expect("create ok");
        let row = hub.store.item(id).expect("store").expect("row");
        assert!(
            row.enc_cipher.get("key").and_then(Value::as_str).is_some(),
            "新建應帶 item key 包裝欄"
        );
        assert_eq!(
            row.enc_cipher.get("folderId").and_then(Value::as_str),
            Some(fid.as_str()),
            "folderId 明文落欄"
        );
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.notes.as_deref(), Some("私密備註"));
        assert_eq!(r.fields.len(), 1);
        assert_eq!(r.fields[0].name, "PIN");
        assert_eq!(r.fields[0].value.as_deref(), Some("1234"));
        assert!(r.folder_id.is_some());
        // 明文索引含欄名（搜尋找得到 PIN）。
        assert_eq!(hub.list("PIN").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_array_ops_append_and_remove_uri_and_field() {
        let (hub, dir) = unlocked_hub("arrayops");
        let id = hub.create(&draft("arr")).expect("create");
        hub.patch(
            id,
            &[
                FieldEdit::AppendUri {
                    uri: "https://second.example.com".to_owned(),
                },
                FieldEdit::AppendField {
                    field: CipherField {
                        name: "会员号".to_owned(),
                        value: Some("m-1".to_owned()),
                        kind: bw_proto::CipherFieldKind::Text,
                    },
                },
            ],
        )
        .expect("append ok");
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.uris.len(), 2);
        assert_eq!(r.uris[1], "https://second.example.com");
        assert_eq!(r.fields.len(), 1);
        // 越界刪除被預驗擋下（靜默蒸發＝缺陷）。
        assert!(
            hub.patch(id, &[FieldEdit::RemoveUri { index: 9 }])
                .err()
                .expect("越界應回錯")
                .contains("越界")
        );
        hub.patch(id, &[FieldEdit::RemoveUri { index: 0 }])
            .expect("remove ok");
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.uris, vec!["https://second.example.com".to_owned()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_from_autofill_creates_patches_and_is_idempotent() {
        let (hub, dir) = unlocked_hub("afsave");
        let (id, act) = hub
            .save_from_autofill("added.example.com", "newbie", "pw1")
            .expect("save");
        assert_eq!(act, "created");
        assert_eq!(hub.list("").len(), 1);
        // 同組合同密碼：冪等，不再入列（重複提交不產生第二筆 outbox）。
        let (same, act) = hub
            .save_from_autofill("https://added.example.com/login", "newbie", "pw1")
            .expect("resave");
        assert_eq!(same, id);
        assert_eq!(act, "unchanged");
        assert_eq!(hub.store.depth().expect("depth").queued, 1);
        // 同組合新密碼：patch 欄位級存活（帳號與網址不動、密碼換值）。
        let (_, act) = hub
            .save_from_autofill("added.example.com", "newbie", "pw2")
            .expect("respw");
        assert_eq!(act, "updated");
        let r = hub.reveal(id).expect("reveal");
        assert_eq!(r.password.as_ref().map(|p| p.as_str()), Some("pw2"));
        assert_eq!(r.username.as_deref(), Some("newbie"));
        assert_eq!(r.uris, vec!["https://added.example.com".to_owned()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn totp_code_present_and_absent() {
        let (hub, dir) = unlocked_hub("totp");
        let id = hub
            .create(&CipherDraft {
                totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
                ..draft("totp-probe")
            })
            .expect("create");
        let (code, valid_for) = hub.totp_code(id).expect("ok").expect("code");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&valid_for));
        // 無 seed：合法態 Ok(None)（UI 據此靜默收合節，不靠比對錯字串）。
        let other = hub.create(&draft("no-totp")).expect("create2");
        assert_eq!(hub.totp_code(other).expect("ok"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn icon_host_whitelist_and_data_uri_sniff() {
        assert!(valid_icon_host("github.com"));
        assert!(!valid_icon_host("../etc/passwd"));
        assert!(!valid_icon_host("a/b"));
        assert!(!valid_icon_host("*.example.com"));
        assert!(valid_icon_host("io.bitward.android")); // 含點 package 名可當檔名
        let png = [0x89u8, b'P', b'N', b'G', 1, 2, 3];
        assert!(icon_data_uri(&png).expect("png").starts_with("data:image/png;base64,"));
        let ico = [0x00u8, 0x00, 0x01, 0x00, 9];
        assert!(icon_data_uri(&ico).expect("ico").starts_with("data:image/x-icon;base64,"));
        assert!(icon_data_uri(b"garbage").is_none());
        assert_eq!(host_of("https://GitHub.com/x"), Some("github.com".to_owned()));
        assert_eq!(host_of("myapp"), None);
        assert_eq!(
            host_of("io.bitward.android"),
            Some("io.bitward.android".to_owned())
        );
    }

    #[test]
    fn folders_locked_empty_and_list_in_folder() {
        let (hub, dir) = unlocked_hub("folders");
        // 鏡像有資料夾欄但表為空：解鎖態回空清單（不是鎖定的空，語意一致）。
        assert!(hub.folders().is_empty());
        let fid = uuid::Uuid::new_v4().to_string();
        hub.store
            .folder_put(uuid::Uuid::parse_str(&fid).unwrap(), &json!({
                "id": fid,
                "name": format!("2.aa|bb|cc"),
            }))
            .expect("folder put");
        hub.create(&CipherDraft {
            folder_id: Some(fid.clone()),
            ..draft("in-folder")
        })
        .expect("create");
        hub.create(&draft("no-folder")).expect("create2");
        assert_eq!(hub.list_in("", Some(&fid)).len(), 1);
        assert_eq!(hub.list_in("", Some("")).len(), 1);
        assert_eq!(hub.list_in("", None).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_record_roundtrips_and_gates_on_drift() {
        use base64::Engine;
        let blob = vec![9u8; 12 + 64 + 16]; // IV‖user key‖tag 的最小正形
        let rec = SealedRecord {
            v: SEALED_V,
            email: "a@x.io".to_owned(),
            puk: "2.aaa|bbb|ccc".to_owned(),
            blob_b64: base64::engine::general_purpose::STANDARD.encode(&blob),
        };
        let acc = Account {
            email: "a@x.io".to_owned(),
            protected_user_key: Some("2.aaa|bbb|ccc".to_owned()),
            ..Default::default()
        };
        assert!(sealed_matches(&rec, &acc));
        assert_eq!(sealed_blob(&rec), Some(blob.clone()));
        // 主密碼在別處改過（PUK 漂移）→ 記錄不可用。
        let rotated = Account {
            protected_user_key: Some("2.ddd|eee|fff".to_owned()),
            ..acc.clone()
        };
        assert!(!sealed_matches(&rec, &rotated));
        // 換帳號（email 漂移）同判；版本不認得也作廢。
        assert!(!sealed_matches(&rec, &Account { email: "b@x.io".to_owned(), ..acc.clone() }));
        assert!(!sealed_matches(&SealedRecord { v: 9, ..rec.clone() }, &acc));
        // JSON round-trip（落盤形態就是 serde_json）。
        let text = serde_json::to_string(&rec).expect("encode");
        let back: SealedRecord = serde_json::from_str(&text).expect("decode");
        assert_eq!(back.blob_b64, rec.blob_b64);
        assert!(sealed_matches(&back, &acc));
    }

    #[test]
    fn sealed_blob_rejects_broken_or_short() {
        use base64::Engine;
        let rec = SealedRecord {
            v: SEALED_V,
            email: "a@x.io".to_owned(),
            puk: "2.x".to_owned(),
            blob_b64: "!!!not base64!!!".to_owned(),
        };
        assert!(sealed_blob(&rec).is_none());
        let short = SealedRecord { blob_b64: base64::engine::general_purpose::STANDARD.encode(&[0u8; 28]), ..rec };
        assert!(sealed_blob(&short).is_none());
    }

    #[test]
    fn hub_has_sealed_tracks_file_and_account() {
        use base64::Engine;
        let dir =
            std::env::temp_dir().join(format!("bitward-android-test-seal-{}", uuid::Uuid::new_v4()));
        let hub = Hub::open(dir.clone()).expect("hub opens");
        let acc = Account {
            server: "http://127.0.0.1:1".to_owned(),
            email: "seal@x.io".to_owned(),
            protected_user_key: Some("2.puk".to_owned()),
            refresh_token: Some("rt".to_owned()),
            ..Default::default()
        };
        // 沒帳號沒封存＝無；帳號落地但仍無封存檔。
        assert!(!hub.has_sealed());
        hub.persist_account(&acc);
        assert!(!hub.has_sealed());
        let rec = SealedRecord {
            v: SEALED_V,
            email: acc.email.clone(),
            puk: "2.puk".to_owned(),
            blob_b64: base64::engine::general_purpose::STANDARD.encode(vec![1u8; 92]),
        };
        std::fs::write(dir.join("sealed.json"), serde_json::to_string(&rec).unwrap())
            .expect("write sealed");
        assert!(hub.has_sealed());
        // PUK 換掉（下次登入的帳號檔形態）→ 舊封存不再可用。
        hub.persist_account(&Account { protected_user_key: Some("2.puk2".to_owned()), ..acc.clone() });
        assert!(!hub.has_sealed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_backoff_sequence_caps_at_ten_minutes() {
        use std::time::Duration;
        assert_eq!(drain_backoff(0), Duration::ZERO);
        for (n, secs) in [(1, 30), (2, 60), (3, 120), (4, 240), (5, 480), (6, 600), (7, 600), (64, 600)] {
            assert_eq!(drain_backoff(n), Duration::from_secs(secs), "n={n}");
        }
    }

    #[tokio::test]
    async fn background_run_locked_hub_converges_immediately() {
        let dir = std::env::temp_dir()
            .join(format!("bitward-android-test-bg-{}", uuid::Uuid::new_v4()));
        let hub = Hub::open(dir.clone()).expect("hub opens");
        assert_eq!(hub.background_run().await, "locked");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
