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
use std::sync::{Arc, Mutex, OnceLock};

use bw_proto::{ItemId, ItemMeta, Query};
use bw_server::{Client, ClientOptions, PasswordLogin};
use bw_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
}

pub struct Hub {
    dir: PathBuf,
    store: Store,
    unlocked: Mutex<Option<Unlocked>>,
    device: OnceLock<String>,
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
        let raw = client.sync().await.map_err(|e| format!("sync 失敗：{e}"))?;
        self.store
            .apply_sync(&raw)
            .map_err(|e| format!("鏡像落地失敗：{e}"))?;
        self.reindex_plain()?;
        Ok(self.store.cipher_count().unwrap_or(0) as usize)
    }

    /// 鏡像落盤後的明文索引回填（與 daemon 同語意、同函數：欄位路徑見
    /// `bw_vault::plain_index`）：解密只在拿得到 user key 時發生，單筆失敗
    /// 容忍跳過（欄位漂移防禦）。登入＝本批唯一的解鎖完成點，回填接在這裡。
    fn reindex_plain(&self) -> Result<(), String> {
        let user_key = {
            let g = self.unlocked.lock().expect("hub mutex poisoned");
            let u = g.as_ref().ok_or("尚未解鎖")?;
            u.user_key.clone()
        };
        let dec = |s: &str| bw_crypto::decrypt_bytes(&user_key, s).ok().and_then(|b| String::from_utf8(b).ok());
        let metas = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;
        for m in metas {
            let Some(row) = self.store.item(m.id).map_err(|e| e.to_string())? else {
                continue;
            };
            let idx = bw_vault::plain_index(&row.enc_cipher, &dec);
            let _ = self.store.set_plain_meta(m.id, idx.name.as_deref(), &idx.uris);
            let _ = self
                .store
                .set_plain_secrets(m.id, idx.username.as_deref(), idx.password.as_deref());
        }
        Ok(())
    }

    /// 列表：只讀本地鏡像的 metadata（搜尋走 FTS5／LIKE 退路，語意在 bw-store）。
    pub fn list(&self, text: &str) -> Vec<ItemMeta> {
        let q = Query {
            text: (!text.trim().is_empty()).then(|| text.trim().to_owned()),
            limit: u32::MAX,
            ..Default::default()
        };
        self.store.query(&q).unwrap_or_default()
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
        // 欄位路徑與 reindex 同源（bw_vault::plain_index）；totp 只有這裡要。
        let dec = |s: &str| {
            bw_crypto::decrypt_bytes(&user_key, s)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        };
        let idx = bw_vault::plain_index(&row.enc_cipher, &dec);
        let totp = row
            .enc_cipher
            .pointer("/login/totp")
            .and_then(Value::as_str)
            .and_then(dec)
            .and_then(|seed| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                bw_crypto::totp_code(&seed, now).ok()
            });
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
        })
    }

    /// 鎖定：丟棄 user key（Drop 即清零）與 token；鏡像與帳號檔留著。
    pub fn sign_out(&self) {
        let mut g = self.unlocked.lock().expect("hub mutex poisoned");
        g.take();
        log::info!("hub: signed out（金鑰已歸零）");
    }
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
}
