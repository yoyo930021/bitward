//! Send（加密分享）daemon 面（路線 5）：建立／清單／分享 URL／刪除／取用密碼。
//!
//! **無 outbox**（契約 3）：建立、改密、刪除需連網——Send 的語意是
//! 「交連結即存在」，佇列會造出「以為分享了其實沒有」的假象；離線時
//! 回 `Denied` 可懂錯誤（UI 誠實標註）。鏡像落庫三條路：`apply_sync`
//! （/sync 的 `sends[]` 欄，VW 1.37.2 實錄存在）、建立/更新回包即時 upsert、
//! 清單在連網時以 `GET /sends` 全量刷新。
//!
//! 金鑰流（bw-crypto `send.rs` 查證）：seed 16B 隨機 → 拉伸鍵加密內容欄；
//! wire `key` 欄＝seed 的 user key 信封。全部加密發生在 `with_keys` 閉包內
//! （不變量 3：金鑰與 seed 不出閉包；出口只帶信封字串與派生哈希）。
//! 審計紀律：分享 URL 帶 seed 片段，只進回應**不進審計**（audit 表只有
//! 動作、id 與位元組數——A11「不落明文」延伸到 key 片段）。

use serde_json::{Value, json};

use bw_crypto::{SendKey, b64url, unwrap_seed};
use bw_proto::{ItemId, Response, SendContent, SendOp, WtpError};
use bw_server::ServerError;

use crate::hub::{DispatchResult, Hub, denied, drift, map_server_err};

/// 檔案 Send 上限：借附件 32 MiB 紀律（同一條 BTP 幀容量推導，
/// 見 `crate::attach::MAX_ATTACHMENT_BYTES`）。
pub const MAX_SEND_FILE_BYTES: usize = crate::attach::MAX_ATTACHMENT_BYTES;

/// 存活上限 30 天（官方選單最大 30 天；伺服器硬閘 31 天留餘量，
/// 實錄超界回 400 "deletion date that far into the future"）。
const MAX_DELETION_HOURS: u32 = 720;

impl Hub {
    pub async fn send_op(&self, sub: &SendOp) -> DispatchResult {
        match sub {
            SendOp::Create {
                name,
                content,
                password,
                deletion_hours,
                max_access,
                hide_email,
            } => {
                self.send_create(
                    name.as_deref(),
                    content,
                    password.as_deref(),
                    *deletion_hours,
                    *max_access,
                    *hide_email,
                )
                .await
            }
            SendOp::List => self.send_list().await,
            SendOp::Get { id } => self.send_url(*id).await,
            SendOp::Remove { id } => self.send_remove(*id).await,
            SendOp::Password { id, password } => {
                self.send_password(*id, password.as_deref()).await
            }
        }
    }

    /// 建立：金鑰生成＋信封構裝在 `with_keys` 閉包內，接著連網建立
    /// （文字＝單段 POST；檔案＝v2 兩段：登記元資料 → 上傳密文檔身），
    /// 伺服器回包落鏡像、回分享 URL。
    async fn send_create(
        &self,
        name: Option<&str>,
        content: &SendContent,
        password: Option<&str>,
        deletion_hours: u32,
        max_access: Option<u32>,
        hide_email: bool,
    ) -> DispatchResult {
        self.require_unlocked()?;
        if deletion_hours == 0 || deletion_hours > MAX_DELETION_HOURS {
            return Err(denied(format!(
                "存活期需 1–{MAX_DELETION_HOURS} 小時（官方選單 24/168/720；伺服器硬閘 31 天）"
            )));
        }
        if matches!(max_access, Some(0)) {
            return Err(denied("存取上限 0＝一開即耗盡；不限請留空"));
        }
        let (is_text, default_name) = match content {
            SendContent::Text { text } => {
                if text.is_empty() {
                    return Err(denied("文字 Send 內容不可為空"));
                }
                (
                    true,
                    text.lines().next().unwrap_or("文字分享").chars().take(32).collect::<String>(),
                )
            }
            SendContent::File { file_name, bytes } => {
                if file_name.is_empty() {
                    return Err(denied("檔案 Send 需要檔名"));
                }
                if bytes.is_empty() {
                    return Err(denied("檔案 Send 內容不可為空"));
                }
                if bytes.len() > MAX_SEND_FILE_BYTES {
                    return Err(denied(format!(
                        "Send 檔案 {} bytes 超過上限 {MAX_SEND_FILE_BYTES} bytes",
                        bytes.len()
                    )));
                }
                (false, file_name.clone())
            }
        };
        let client = self.client().await.map_err(|_| {
            denied("Send 建立需要連網（Send 無 outbox 佇列：交連結即存在，離線不假排）")
        })?;
        let display_name = name.map(str::to_owned).unwrap_or(default_name);
        let now_ms = self.store.now_ms();
        let deletion_date =
            crate::sync::iso_utc_at_ms(now_ms + u64::from(deletion_hours) * 3_600_000);
        // 閉包產出：(wire body, seed b64url, 檔名信封, 密文檔身)
        let (body, seed_b64, file_name_env, ct) = self
            .machine
            .with_keys(|kb| -> Option<(Value, String, String, Option<Vec<u8>>)> {
                let key = SendKey::generate();
                let ck = key.stretch();
                let ck = ck.as_slice();
                let name_env =
                    bw_crypto::encrypt_bytes_key(ck, display_name.as_bytes()).ok()?;
                let key_env = key.wrap_with_user_key(kb.user_key()).ok()?;
                let mut body = json!({
                    "type": if is_text { 0 } else { 1 },
                    "key": key_env,
                    "name": name_env,
                    "notes": null,
                    "deletionDate": deletion_date,
                    "expirationDate": null,
                    "maxAccessCount": max_access,
                    "password": password.map(|p| key.password_hash(p)),
                    "disabled": false,
                    "hideEmail": hide_email,
                });
                let mut ct = None;
                let mut fname_env = String::new();
                if is_text {
                    let SendContent::Text { text } = content else { unreachable!() };
                    body["text"] = json!({
                        "text": bw_crypto::encrypt_bytes_key(ck, text.as_bytes()).ok()?,
                        "hidden": false,
                    });
                } else {
                    let SendContent::File { file_name, bytes } = content else {
                        unreachable!()
                    };
                    fname_env = bw_crypto::encrypt_bytes_key(ck, file_name.as_bytes()).ok()?;
                    // 檔身＝信封字串的位元組（官方同形；接收方 GET 後按 EncString 解）。
                    // fileLength 登記**加密後**長度——VW 逐字比對上傳位元組數，
                    // 明文長度登記會撞 400 "Send file size does not match."（實錄）
                    let ct_s = bw_crypto::encrypt_bytes_key(ck, bytes).ok()?;
                    ct = Some(ct_s.into_bytes());
                    body["file"] = json!({ "fileName": fname_env });
                    body["fileLength"] = json!(ct.as_ref().unwrap().len());
                }
                Some((body, b64url(key.as_bytes()), fname_env, ct))
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or_else(|| denied("Send 加密失敗（金鑰狀態漂移）"))?;
        let resp = if is_text {
            client.send_create(&body).await.map_err(map_server_err)?
        } else {
            let up = client.send_create_file(&body).await.map_err(map_server_err)?;
            let ct = ct.expect("檔案分支必帶密文檔身");
            if let Err(e) = client.send_upload_data(&up.url, &file_name_env, &ct).await {
                // 元資料已落庫、檔身上傳失敗：send 处于 disabled 前態（VW 對
                // 缺檔的 access 回 404 實錄）。鏡像照收（列可觀測），回錯讓
                // 呼叫端刪除重試——不留「連結已生出但沒回報」的孤兒。
                let _ = self.store.send_put(&up.send);
                return Err(map_server_err(e));
            }
            up.send
        };
        self.store.send_put(&resp).map_err(denied)?;
        let url = self.compose_send_url(&resp, &seed_b64).await?;
        Ok(Response::Json(json!({
            "id": resp.get("id").cloned().unwrap_or(Value::Null),
            "url": url,
            "name": display_name,
            "deletionDate": resp.get("deletionDate").cloned().unwrap_or(json!(deletion_date)),
        })))
    }

    /// 清單：連網時先以 `GET /sends` 全量刷新鏡像（伺服器是真相源），
    /// 離線照回鏡像（讀取面不需連網）。名稱與 URL 需解鎖態（seed 是
    /// user key 信封），鎖態兩者為 null——資料夾清單同語意。
    /// `viewed`＝accessCount>0（查證：VW send JSON **無** viewed 欄，實錄；
    /// 官方 web vault 同以存取計數推已檢視）。
    async fn send_list(&self) -> DispatchResult {
        if let Ok(client) = self.client().await
            && let Ok(raw) = client.sends_list().await
            && let Some(items) = raw.get("data").and_then(Value::as_array)
        {
            let _ = self.store.sends_replace(items);
        }
        let rows = self.store.send_list().map_err(denied)?;
        let unlocked = self.machine.is_unlocked();
        let base = self.server_base().await.unwrap_or_default();
        let items: Vec<Value> = rows
            .iter()
            .map(|s| {
                let (name, url) = if unlocked {
                    self.send_open_projection(s, &base)
                } else {
                    (None, None)
                };
                json!({
                    "id": s.get("id"),
                    "type": s.get("type"),
                    "name": name,
                    "url": url,
                    "deletionDate": s.get("deletionDate"),
                    "expirationDate": s.get("expirationDate"),
                    "maxAccessCount": s.get("maxAccessCount"),
                    "accessCount": s.get("accessCount"),
                    "viewed": s.get("accessCount").and_then(Value::as_i64).unwrap_or(0) > 0,
                    "hideEmail": s.get("hideEmail"),
                    "hasPassword": s.get("authType").and_then(Value::as_i64) == Some(1),
                    "fileSize": s.pointer("/file/size"),
                })
            })
            .collect();
        Ok(Response::Json(json!({ "items": items })))
    }

    /// 分享 URL（Get）：鏡像 seed ＋帳號 server 值組裝；不需連網
    /// （連結早存在，重取 URL 是本地操作）。
    async fn send_url(&self, id: ItemId) -> DispatchResult {
        self.require_unlocked()?;
        let s = self.store.send(id).map_err(denied)?.ok_or(WtpError::NotFound)?;
        let key_env = s
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| drift("Send 鏡像缺 key 欄（請同步重拉）"))?;
        let seed_b64 = self
            .machine
            .with_keys(|kb| {
                unwrap_seed(kb.user_key(), key_env)
                    .ok()
                    .map(|k| b64url(k.as_bytes()))
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or_else(|| denied("Send seed 解不開（信封漂移）"))?;
        let url = self.compose_send_url(&s, &seed_b64).await?;
        Ok(Response::Json(json!({ "id": id.to_string(), "url": url })))
    }

    /// 刪除：需連網；伺服器 404＝已不存在（過期自清是常態），
    /// 照收斂摘鏡像列回 Ok（冪等語意同 attachment delete）。
    async fn send_remove(&self, id: ItemId) -> DispatchResult {
        let client = self.client().await.map_err(|_| {
            denied("Send 刪除需要連網（Send 無 outbox 佇列；離線時鏡像照留）")
        })?;
        match client.send_delete(id).await {
            Ok(()) | Err(ServerError::Http { status: 404, .. }) => {
                self.store.send_remove(id).map_err(denied)?;
                Ok(Response::Ok)
            }
            Err(e) => Err(map_server_err(e)),
        }
    }

    /// 取用密碼：Some＝設/換（全量 PUT 帶新哈希——查證：VW/官方皆無
    /// POST access-password 路由，「改」即 PUT 帶值、伺服器只在欄位有值時
    /// 重哈希）；None＝清除（remove-password）。seed 不變 ⇒ 既有連結的
    /// 解密金鑰不受影響，只有取用門檻變。
    async fn send_password(&self, id: ItemId, password: Option<&str>) -> DispatchResult {
        self.require_unlocked()?;
        let client = self.client().await.map_err(|_| {
            denied("Send 改取用密碼需要連網（Send 無 outbox 佇列）")
        })?;
        let s = self.store.send(id).map_err(denied)?.ok_or(WtpError::NotFound)?;
        if password.is_none() {
            let updated = client
                .send_remove_password(id)
                .await
                .map_err(map_server_err)?;
            let _ = self.store.send_put(&updated);
            return Ok(Response::Json(json!({
                "id": id.to_string(), "hasPassword": false,
            })));
        }
        let key_env = s
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| drift("Send 鏡像缺 key 欄（請同步重拉）"))?;
        let pw = password.expect("已判非 None");
        let is_text = s.get("type").and_then(Value::as_i64) == Some(0);
        let body = self
            .machine
            .with_keys(|kb| -> Option<Value> {
                let seed = unwrap_seed(kb.user_key(), key_env).ok()?;
                Some(json!({
                    "type": s.get("type"),
                    // 包裝 seed 原樣帶回：連結不變、解密密鑰不變
                    "key": key_env,
                    "name": s.get("name"),
                    "notes": s.get("notes"),
                    // file send 的 data 欄伺服器不收更新（update_send_from_data），
                    // 官方形態給 null；text 原樣帶回（信封不改寫）
                    "text": if is_text { s.get("text").cloned().unwrap_or(Value::Null) } else { Value::Null },
                    "deletionDate": s.get("deletionDate"),
                    "expirationDate": s.get("expirationDate"),
                    "maxAccessCount": s.get("maxAccessCount"),
                    "password": seed.password_hash(pw),
                    "disabled": s.get("disabled").and_then(Value::as_bool).unwrap_or(false),
                    "hideEmail": s.get("hideEmail").and_then(Value::as_bool).unwrap_or(false),
                }))
            })
            .map_err(|_| WtpError::Locked)?
            .ok_or_else(|| denied("Send seed 解不開（信封漂移）"))?;
        if body
            .get("deletionDate")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
        {
            return Err(drift("Send 鏡像缺 deletionDate（PUT 全量必填）"));
        }
        let updated = client.send_put(id, &body).await.map_err(map_server_err)?;
        let _ = self.store.send_put(&updated);
        Ok(Response::Json(json!({
            "id": id.to_string(),
            "hasPassword": true,
        })))
    }

    /// 同 [`compose_send_url_from`]，但 base 取帳號 server 值；未登入回可懂錯誤。
    async fn compose_send_url(&self, send: &Value, seed_b64: &str) -> Result<String, WtpError> {
        let base = self
            .server_base()
            .await
            .ok_or_else(|| denied("尚未登入：分享 URL 的 web 前綴取帳號 server 值"))?;
        compose_send_url_from(send, &base, seed_b64).ok_or_else(|| drift("Send 回包缺 id"))
    }

    /// 鏡像列的解鎖投影：(解密名稱, 分享 URL)。seed 解不開時兩者都回
    /// None（比誤潑信封字串準，同資料夾清單語意）；base 缺席（未登入）
    /// 時名稱照回、URL 為 None。
    fn send_open_projection(&self, send: &Value, base: &str) -> (Option<String>, Option<String>) {
        let (Some(key_env), Some(name_env)) = (
            send.get("key").and_then(Value::as_str),
            send.get("name").and_then(Value::as_str),
        ) else {
            return (None, None);
        };
        self.machine
            .with_keys(|kb| -> Option<(String, Option<String>)> {
                let seed = unwrap_seed(kb.user_key(), key_env).ok()?;
                let ck = seed.stretch();
                let raw = bw_crypto::decrypt_bytes_with_key(ck.as_slice(), name_env).ok()?;
                let name = String::from_utf8(raw).ok()?;
                let url = compose_send_url_from(send, base, &b64url(seed.as_bytes()));
                Some((name, url))
            })
            .ok()
            .flatten()
            .map(|(n, u)| (Some(n), u))
            .unwrap_or((None, None))
    }
}

/// `{server}/#/send/{accessId}/{b64url(seed)}`（官方 web vault 同形：
/// `getSendUrl()+accessId+"/"+urlB64Key`，clients main 查證 2026-11-10）。
/// accessId 以伺服器回包為準；缺欄時按官方演算法自算
/// （`base64url_nopad(uuid bytes)`，VW send.rs `to_json` 同源）。
/// base 空（未登入）→ None。
fn compose_send_url_from(send: &Value, base: &str, seed_b64: &str) -> Option<String> {
    if base.is_empty() {
        return None;
    }
    let id_s = send.get("id").and_then(Value::as_str)?;
    let access_id = send
        .get("accessId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            uuid::Uuid::parse_str(id_s)
                .ok()
                .map(|u| b64url(u.as_bytes()))
        })?;
    Some(format!(
        "{}/#/send/{}/{}",
        base.trim_end_matches('/'),
        access_id,
        seed_b64
    ))
}

/// 審計動作欄（action_tag 用；細到子操作，同 Attachment 紀律）。
pub(crate) fn op_tag(sub: &SendOp) -> &'static str {
    match sub {
        SendOp::Create { .. } => "Vault.Send.Create",
        SendOp::List => "Vault.Send.List",
        SendOp::Get { .. } => "Vault.Send.Get",
        SendOp::Remove { .. } => "Vault.Send.Remove",
        SendOp::Password { .. } => "Vault.Send.Password",
    }
}

/// 核准摘要：Create 帶明文內容與密碼，Debug dump 會潑進核准文字/審計
/// （附件 op 同教訓），只報形態不報內容。
pub(crate) fn op_summary(sub: &SendOp) -> String {
    match sub {
        SendOp::Create { content, .. } => match content {
            SendContent::Text { text } => format!("send 建立：文字 {} 字元", text.chars().count()),
            SendContent::File { file_name, bytes } => {
                format!("send 建立：檔案 {file_name}（{} bytes）", bytes.len())
            }
        },
        SendOp::List => "send 清單".into(),
        SendOp::Get { id } => format!("send URL {id}"),
        SendOp::Remove { id } => format!("send 刪除 {id}"),
        SendOp::Password { id, password } => format!(
            "send 取用密碼 {id}（{}）",
            if password.is_some() { "設/換" } else { "清除" }
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::tests::unlocked_hub;
    use bw_crypto::UserKey;
    use uuid::Uuid;

    #[test]
    fn op_tag_is_stable_per_sub() {
        assert_eq!(op_tag(&SendOp::List), "Vault.Send.List");
        assert_eq!(
            op_tag(&SendOp::Get { id: ItemId::new_v4() }),
            "Vault.Send.Get"
        );
    }

    #[test]
    fn create_summary_hides_plaintext_and_password() {
        let sub = SendOp::Create {
            name: None,
            content: SendContent::Text {
                text: "銀行帳單號碼 1234".into(),
            },
            password: Some("s3cr3t-pw".into()),
            deletion_hours: 168,
            max_access: None,
            hide_email: false,
        };
        let s = op_summary(&sub);
        assert!(!s.contains("1234"), "{s}");
        assert!(!s.contains("s3cr3t"), "{s}");
        assert!(s.contains("文字"), "{s}");
    }

    /// 合成鏡像列：user key（fixture 的 64×7）包 seed、拉伸鍵加密名稱。
    fn mirror_send(id: Uuid, with_access_id: bool) -> Value {
        let uk = UserKey::from_bytes(vec![7u8; 64]).unwrap();
        let seed = SendKey::from_bytes((0..16u8).collect()).unwrap();
        let ck = seed.stretch();
        let name_env =
            bw_crypto::encrypt_bytes_key(ck.as_slice(), "帳單分享".as_bytes()).unwrap();
        let mut v = json!({
            "id": id.to_string(),
            "type": 0,
            "name": name_env,
            "key": seed.wrap_with_user_key(&uk).unwrap().to_string(),
            "accessCount": 2,
            "maxAccessCount": 5,
            "deletionDate": "2026-11-17T00:00:00Z",
            "expirationDate": null,
            "hideEmail": true,
            "authType": 1,
            "object": "send",
        });
        if with_access_id {
            v["accessId"] = json!("ACC-IDA");
        }
        v
    }

    #[tokio::test]
    async fn list_and_url_project_mirror_offline() {
        let (hub, _dir) = unlocked_hub("send-list").await;
        let id = Uuid::new_v4();
        hub.store.send_put(&mirror_send(id, true)).unwrap();
        // List：離線照回鏡像、名稱解密、viewed 由 accessCount 推
        let Response::Json(v) = hub.send_op(&SendOp::List).await.unwrap() else {
            panic!("expect Json");
        };
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "帳單分享");
        assert_eq!(items[0]["viewed"], true);
        assert_eq!(items[0]["hasPassword"], true);
        // 解鎖態清單直接帶可複製的分享 URL（GUI 列內複製鈕零跳）
        assert_eq!(
            items[0]["url"],
            "http://127.0.0.1:9/#/send/ACC-IDA/AAECAwQFBgcICQoLDA0ODw"
        );
        // URL：帳號 server 值 + accessId（伺服器給的為準）
        let Response::Json(u) = hub.send_op(&SendOp::Get { id }).await.unwrap() else {
            panic!("expect Json");
        };
        assert_eq!(
            u["url"].as_str().unwrap(),
            "http://127.0.0.1:9/#/send/ACC-IDA/AAECAwQFBgcICQoLDA0ODw"
        );
        // 缺 accessId 欄：按官方演算法自算 b64url(uuid bytes)
        let id2 = Uuid::new_v4();
        hub.store.send_put(&mirror_send(id2, false)).unwrap();
        let Response::Json(u2) = hub.send_op(&SendOp::Get { id: id2 }).await.unwrap() else {
            panic!("expect Json");
        };
        let expect = format!("http://127.0.0.1:9/#/send/{}/AAECAwQFBgcICQoLDA0ODw", b64url(id2.as_bytes()));
        assert_eq!(u2["url"].as_str().unwrap(), expect);
        // 鎖態：URL 取用需 seed（金鑰材料）→ Locked；清單照回但 name=null
        hub.machine.lock(bw_keys::LockReason::User);
        assert!(matches!(
            hub.send_op(&SendOp::Get { id }).await,
            Err(WtpError::Locked)
        ));
        let Response::Json(v) = hub.send_op(&SendOp::List).await.unwrap() else {
            panic!("expect Json");
        };
        assert_eq!(v["items"][0]["name"], Value::Null);
        assert_eq!(v["items"][0]["url"], Value::Null);
    }

    #[tokio::test]
    async fn remove_reports_unreachable_server() {
        // fixture 的 server 是 port 9（discard）：有 handle 但請求必敗——
        // 語意＝連網失敗回可懂錯誤，鏡像列**不得**被摘（離線照留）
        let (hub, _dir) = unlocked_hub("send-rm").await;
        let id = Uuid::new_v4();
        hub.store.send_put(&mirror_send(id, true)).unwrap();
        let e = hub.send_op(&SendOp::Remove { id }).await.unwrap_err();
        match e {
            WtpError::ServerDrift { .. } | WtpError::Denied { .. } => {}
            other => panic!("連網失敗應回可懂錯誤，got {other:?}"),
        }
        assert!(hub.store.send(id).unwrap().is_some(), "失敗不得收斂鏡像");
    }
}
