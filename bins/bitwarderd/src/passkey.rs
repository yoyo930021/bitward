//! Passkey 業務核心（macOS autofill 契約 §2–§5）：fido2Credentials 讀寫、
//! ES256 註冊/斷言、counter 持久化走既有 mutate→outbox→sync 機制。
//! 金鑰只經 `with_keys` 流通；識別欄位（credentialId/rpId/userHandle/userName）
//! 為鏡像內明文，GetPasskeys 因此不需解密即可投影（契約 §1 Metadata 級）。

use serde_json::{Value, json};
use sha2::Digest as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use bw_proto::{ItemId, PasskeyCall, PasskeyEntry, Query, Response, WtpError};
use bw_store::MutationDraft;

use crate::hub::Hub;

fn denied(e: impl std::fmt::Display) -> WtpError {
    WtpError::Denied {
        grant_gap: e.to_string(),
    }
}

/// 鏡像 cipher → login.fido2Credentials 陣列（不存在回空切片語意：None）。
fn fido_array(cipher: &Value) -> Option<&Vec<Value>> {
    cipher
        .pointer("/login/fido2Credentials")
        .and_then(Value::as_array)
}

/// 取得（或建立）login.fido2Credentials 的可變陣列引用。
fn fido_array_mut(cipher: &mut Value) -> &mut Vec<Value> {
    if !cipher.get("login").is_some_and(Value::is_object) {
        cipher["login"] = json!({});
    }
    let login = cipher
        .get_mut("login")
        .and_then(Value::as_object_mut)
        .expect("login is object");
    if !login.get("fido2Credentials").is_some_and(Value::is_array) {
        login.insert("fido2Credentials".into(), json!([]));
    }
    login
        .get_mut("fido2Credentials")
        .and_then(Value::as_array_mut)
        .expect("fido2Credentials is array")
}

/// b64url 規範化比對：容忍呼叫端帶 padding 的變體。
fn norm_b64url(s: &str) -> &str {
    s.trim_end_matches('=')
}

/// BeginAssert→FinishAssert 事務的暫存態（Hub::pending_asserts，記憶體態）。
/// Finish 驗簽成功才消耗；失敗保留（同 authData 可重試簽名）。
#[derive(Clone)]
pub struct PendingAssert {
    pub auth_data: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub counter: u32,
}

/// AssertBegin.signing_input_note：固定提示字串（Swift 端據此組簽名輸入）。
const SIGNING_INPUT_NOTE: &str = "DER ECDSA over authenticator_data‖client_data_hash";

/// 32B 隨機 credential id 原始位元組（b64url 編碼由呼叫端做）。
fn random_credential_id() -> Vec<u8> {
    let mut raw = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    raw
}

/// 註冊共核的金鑰來源分支（passkey_register_with 的參數形態）。
enum KeyMaterial<'a> {
    /// daemon 自生 P-256 標量（純軟體流）
    Software,
    /// Swift 匯入的 b64url DER SPKI（SE 流；daemon 從未見過私鑰）
    ProvidedSpki(&'a str),
}

/// 註冊幀的借用視圖（RegisterPasskey / FinishRegister 共核參數；欄位名同線格式）。
struct Registration<'a> {
    rp_id: &'a str,
    user_name: &'a str,
    user_handle: &'a str,
    display_name: &'a str,
    item_id: Option<ItemId>,
}

/// 已備妥待驗簽的斷言事務（settle_assert_signature 參數；見 Begin/Finish 語意）。
struct AssertTx<'a> {
    base: Value,
    item: ItemId,
    idx: usize,
    credential_id: &'a str,
    auth_data: &'a [u8],
    /// 簽名輸入尾段：clientDataHash 32B 本體，或 sha256(clientDataJSON)
    tail: &'a [u8],
    signature: &'a str,
    /// 佔位 clientDataJSON（b64url；RP 實際收到的是系統自建 JSON）
    client_data_json: String,
    counter: u32,
}

/// keyValue 信封解密後的明文形態。判别只靠 `authenticationType` 一處
/// （official fido2Credentials 欄位）：
/// - "enterprise"（含舊資料缺欄）：32B P-256 私鑰標量、標準 base64（純軟體流）
/// - "platform-aaguid"：b64url DER SPKI 公鑰（SE 流；私鑰在 appex keychain，
///   daemon 從未見過。公開材料仍走信封，保持 keyValue 單一形態）
#[derive(Clone)]
enum StoredKey {
    Scalar(Zeroizing<Vec<u8>>),
    Spki(Vec<u8>),
}

impl StoredKey {
    fn parse(auth_type: &str, plaintext: &str) -> Result<Self, String> {
        match auth_type {
            "platform-aaguid" => Ok(StoredKey::Spki(
                bw_crypto::b64url_decode(plaintext).map_err(|e| e.to_string())?,
            )),
            _ => Ok(StoredKey::Scalar(Zeroizing::new(
                bw_crypto::b64_decode(plaintext).map_err(|e| e.to_string())?,
            ))),
        }
    }

    /// 統一出口：b64url DER SPKI（GetPasskeys.public_key、驗簽公鑰）。
    fn spki_b64url(&self) -> Result<String, String> {
        match self {
            StoredKey::Spki(d) => Ok(bw_crypto::b64url(d)),
            StoredKey::Scalar(s) => Ok(bw_crypto::b64url(
                &bw_crypto::spki_from_scalar(s).map_err(|e| e.to_string())?,
            )),
        }
    }
}

impl Hub {
    /// 掃描全鏡像找 credential id；回傳 (item_id, 陣列索引)。
    fn find_credential(&self, credential_id: &str) -> Result<Option<(ItemId, usize)>, WtpError> {
        let want = norm_b64url(credential_id);
        let metas = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(denied)?;
        for m in metas {
            let Some(row) = self.store.item(m.id).map_err(denied)? else {
                continue;
            };
            if let Some(arr) = fido_array(&row.enc_cipher) {
                for (i, c) in arr.iter().enumerate() {
                    if c.get("credentialId")
                        .and_then(Value::as_str)
                        .is_some_and(|id| norm_b64url(id) == want)
                    {
                        return Ok(Some((m.id, i)));
                    }
                }
            }
        }
        Ok(None)
    }
    /// 讀取鏡像 entry 的 counter（缺/壞 = 0）。
    fn entry_counter(cipher: &Value, idx: usize) -> u32 {
        cipher
            .pointer(&format!("/login/fido2Credentials/{idx}/counter"))
            .and_then(Value::as_str)
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(0)
    }

    /// 鏡像 entry 的 rpId（註冊時寫入的權威值；BeginAssert 不再信任呼叫端）。
    fn entry_rp_id(cipher: &Value, idx: usize) -> Option<&str> {
        cipher
            .pointer(&format!("/login/fido2Credentials/{idx}/rpId"))
            .and_then(Value::as_str)
    }

    /// 解 entry 的 keyValue 信封 → StoredKey（軟體標量 or SE SPKI；判別只在此處）。
    fn stored_key(&self, cipher: &Value, idx: usize) -> Result<StoredKey, WtpError> {
        let enc = cipher
            .pointer(&format!("/login/fido2Credentials/{idx}/keyValue"))
            .and_then(Value::as_str)
            .ok_or_else(|| denied("credential has no keyValue"))?
            .to_owned();
        let auth_type = cipher
            .pointer(&format!("/login/fido2Credentials/{idx}/authenticationType"))
            .and_then(Value::as_str)
            .unwrap_or("enterprise")
            .to_owned();
        self.machine
            .with_keys(|kb| {
                let pt = bw_crypto::decrypt(kb.user_key(), &enc).map_err(|e| e.to_string())?;
                StoredKey::parse(&auth_type, &pt).map_err(|e| e.to_string())
            })
            .map_err(|_| WtpError::Locked)?
            .map_err(denied)
    }

    /// entry 公鑰（DER SPKI 位元組）：軟體流由標量匯出、SE 流直接是 keyValue 明文。
    fn entry_spki(&self, cipher: &Value, idx: usize) -> Result<Vec<u8>, WtpError> {
        let b64 = self
            .stored_key(cipher, idx)?
            .spki_b64url()
            .map_err(denied)?;
        bw_crypto::b64url_decode(&b64).map_err(denied)
    }

    /// GetPasskeys：Metadata 級投影 + public_key（SPKI 為公開材料；
    /// 私鑰/信封 keyValue 永不進回應）。keyValue 缺壞的條目 public_key 留空。
    pub fn passkey_list(&self, rp_id: Option<&str>) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let metas = self
            .store
            .query(&Query {
                limit: u32::MAX,
                ..Default::default()
            })
            .map_err(denied)?;
        let mut out = Vec::new();
        for m in metas {
            let Some(row) = self.store.item(m.id).map_err(denied)? else {
                continue;
            };
            let Some(arr) = fido_array(&row.enc_cipher) else {
                continue;
            };
            for (i, c) in arr.iter().enumerate() {
                let get = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default();
                let public_key = self
                    .stored_key(&row.enc_cipher, i)
                    .and_then(|k| k.spki_b64url().map_err(denied))
                    .unwrap_or_default();
                let entry = PasskeyEntry {
                    credential_id: get("credentialId").to_owned(),
                    user_handle: get("userHandle").to_owned(),
                    user_name: get("userName").to_owned(),
                    rp_id: get("rpId").to_owned(),
                    public_key,
                    item_id: Some(m.id),
                };
                if rp_id.is_none_or(|rp| norm_b64url(&entry.rp_id) == norm_b64url(rp)) {
                    out.push(entry);
                }
            }
        }
        Ok(Response::Passkeys(out))
    }

    /// 註冊共核：組 entry（keyValue 走 type-2 信封）→ 存鏡像 + outbox →
    /// none-attestation（counter=1）。Software = daemon 自生標量（既有流）；
    /// ProvidedSpki = SE 公鑰流（id 由 BeginRegister 協商或單步呼叫內生成）。
    async fn passkey_register_with(
        &self,
        session: &str,
        reg: &Registration<'_>,
        cred_id_raw: Vec<u8>,
        key: KeyMaterial<'_>,
    ) -> Result<Response, WtpError> {
        let Registration {
            rp_id,
            user_name,
            user_handle,
            display_name,
            item_id,
        } = *reg;
        self.require_unlocked()?;
        let credential_id = bw_crypto::b64url(&cred_id_raw);
        let (attestation_object, key_plain, auth_type, aaguid) = match key {
            KeyMaterial::Software => {
                let scalar = bw_crypto::generate_private_key();
                (
                    bw_crypto::attestation_object(rp_id, &cred_id_raw, &scalar, 1)
                        .map_err(denied)?,
                    // 明文＝私鑰標量的標準 base64（契約 §2）
                    bw_crypto::b64(&scalar),
                    "enterprise",
                    None,
                )
            }
            KeyMaterial::ProvidedSpki(spki_b64url) => {
                let spki = bw_crypto::b64url_decode(spki_b64url).map_err(denied)?;
                // 快驗：SPKI 解析不出 P-256 就拒，不把壞公鑰寫進 vault
                let att = bw_crypto::attestation_object_from_spki(rp_id, &cred_id_raw, &spki, 1)
                    .map_err(denied)?;
                (
                    att,
                    // 公開材料照樣走信封：keyValue 單一形態，Swift 匯入端解密後直接是 SPKI
                    bw_crypto::b64url(&spki),
                    // authenticationType：官方 clients 的 Fido2AuthenticatorType 列舉只有
                    // "enterprise"（vault 軟體鑰）與 "platform-aaguid"（平台綁定金鑰，配
                    // aaguid 欄）；伺服器/Vaultwarden 視它為不透明 metadata、不驗金鑰材料
                    // 格式，故 SE 流標 platform-aaguid 與官方 fido2Credentials 格式相容，
                    // 並讓 StoredKey::parse 能從條目本身判別金鑰來源。
                    "platform-aaguid",
                    // 與 authData 內 attestedCredentialData 的全零 AAGUID 一致
                    Some("00000000-0000-0000-0000-000000000000"),
                )
            }
        };
        let key_value = self
            .machine
            .with_keys(|kb| {
                bw_crypto::encrypt(kb.user_key(), &key_plain)
                    .map(|e| e.to_string())
                    .map_err(|e| e.to_string())
            })
            .map_err(denied)?
            .map_err(denied)?;
        let mut entry = json!({
            "credentialId": credential_id,
            "rpId": rp_id,
            "userHandle": user_handle,
            "userName": user_name,
            "displayName": display_name,
            "counter": "1",
            "credentialType": "public-key",
            "keyType": "public",
            "keyValue": key_value,
            "keySource": "generate",
            "authenticationType": auth_type,
        });
        if let Some(aag) = aaguid {
            entry["aaguid"] = json!(aag);
        }
        match item_id {
            Some(id) => self.passkey_attach(session, id, entry).await,
            None => {
                self.passkey_create_item(session, rp_id, user_name, entry)
                    .await
            }
        }?;
        Ok(Response::PasskeyAttestation {
            credential_id,
            attestation_object,
        })
    }

    /// RegisterPasskey（單步）：None=daemon 生成 P-256 私鑰（既有軟體流）；
    /// Some=SE 公鑰一次到位（id 本呼叫隨機生成；Swift 整合用 BeginRegister/
    /// FinishRegister，此形態留給 CLI/測試）。
    pub async fn passkey_register(
        &self,
        session: &str,
        call: &PasskeyCall,
    ) -> Result<Response, WtpError> {
        let PasskeyCall::RegisterPasskey {
            rp_id,
            challenge: _,
            user_name,
            user_handle,
            display_name,
            item_id,
            credential_public_key,
        } = call
        else {
            return Err(denied("expect RegisterPasskey"));
        };
        let key = match credential_public_key {
            Some(spki) => KeyMaterial::ProvidedSpki(spki),
            None => KeyMaterial::Software,
        };
        self.passkey_register_with(
            session,
            &Registration {
                rp_id,
                user_name,
                user_handle,
                display_name,
                item_id: *item_id,
            },
            random_credential_id(),
            key,
        )
        .await
    }

    /// BeginRegister：無狀態簽發 32B 隨機 credential id（b64url）。
    /// Swift 以解碼位元組作 SecKey tag 生 SE 金鑰，再 FinishRegister 交回公鑰。
    pub fn passkey_begin_register(&self) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        Ok(Response::RegisterBegin {
            credential_id: bw_crypto::b64url(&random_credential_id()),
        })
    }

    /// FinishRegister：校驗 id 格式/唯一性後走 SE 公鑰註冊共核。
    /// 幀自含全部欄位，daemon 重啟不影響（無 pending 表可失）。
    pub async fn passkey_finish_register(
        &self,
        session: &str,
        call: &PasskeyCall,
    ) -> Result<Response, WtpError> {
        let PasskeyCall::FinishRegister {
            credential_id,
            credential_public_key,
            rp_id,
            challenge: _,
            user_name,
            user_handle,
            display_name,
            item_id,
        } = call
        else {
            return Err(denied("expect FinishRegister"));
        };
        self.require_unlocked()?;
        let cred_id_raw = bw_crypto::b64url_decode(credential_id).map_err(denied)?;
        if cred_id_raw.len() != 32 {
            return Err(denied("credential_id must decode to 32 bytes"));
        }
        if self.find_credential(credential_id)?.is_some() {
            return Err(denied("credential_id already registered"));
        }
        self.passkey_register_with(
            session,
            &Registration {
                rp_id,
                user_name,
                user_handle,
                display_name,
                item_id: *item_id,
            },
            cred_id_raw,
            KeyMaterial::ProvidedSpki(credential_public_key),
        )
        .await
    }

    /// 附加到既有 item：patch mutation（base/ours/touched），同 write_patch 形態。
    async fn passkey_attach(
        &self,
        session: &str,
        id: ItemId,
        entry: Value,
    ) -> Result<(), WtpError> {
        let row = self.store.item(id).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let mut ours = base.clone();
        fido_array_mut(&mut ours).push(entry);
        ours["id"] = json!(id.to_string());
        self.enqueue_passkey_patch(session, id, base, ours).await
    }

    /// 新建承載 item：create mutation，同 write_create 形態（cipher 去 id 進 payload）。
    async fn passkey_create_item(
        &self,
        session: &str,
        rp_id: &str,
        user_name: &str,
        entry: Value,
    ) -> Result<(), WtpError> {
        let id = Uuid::new_v4();
        let cipher = self
            .machine
            .with_keys(|kb| {
                let uk = kb.user_key();
                let enc = |s: &str| -> String {
                    bw_crypto::encrypt(uk, s)
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                };
                let c = json!({
                    "id": id.to_string(),
                    "type": 1,
                    "name": enc(rp_id),
                    "login": {
                        "username": enc(user_name),
                        "uris": [{"uri": enc(&format!("https://{rp_id}")), "match": null}],
                        "fido2Credentials": [entry],
                    },
                });
                c
            })
            .map_err(denied)?;
        self.store.put_mirror(id, &cipher).map_err(denied)?;
        self.reindex_one(id)?;
        let mut body = cipher.clone();
        if let Some(o) = body.as_object_mut() {
            o.remove("id");
        }
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload: json!({"op": "create", "cipher": body}),
                base_rev: None,
                origin: Some(session),
                mirror: None,
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(())
    }

    /// AssertPasskey：找憑證 → 兩條路：
    /// - signature None（軟體流）：解密 keyValue 私鑰 → counter++ 簽名 →
    ///   新 counter 寫回鏡像並進 outbox（契約 §3 持久化要求）。SE 憑證（SPKI）
    ///   無私鑰可簽 → Denied，請改走 BeginAssert/FinishAssert。
    /// - signature Some（Swift 已簽）：daemon 以本次 counter 現算 authData、
    ///   驗 `authData‖(hash|sha256(cdj))` 簽名 → 通過才 counter 持久化。
    pub async fn passkey_assert(
        &self,
        session: &str,
        call: &PasskeyCall,
    ) -> Result<Response, WtpError> {
        let PasskeyCall::AssertPasskey {
            credential_id,
            challenge,
            rp_id,
            client_data_hash,
            signature,
            // key_id：Swift 側 keychain item 的不透明標籤，daemon 不解釋
            // （Debug 形態已進 audit 行）
            key_id: _,
        } = call
        else {
            return Err(denied("expect AssertPasskey"));
        };
        self.require_unlocked()?;
        let (item, idx) = self
            .find_credential(credential_id)?
            .ok_or(WtpError::NotFound)?;
        let row = self.store.item(item).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let next = Self::entry_counter(&base, idx).saturating_add(1);
        let auth_data = bw_crypto::assertion_auth_data(rp_id, next);
        if let Some(sig) = signature {
            let (tail, cdj_b64) = match client_data_hash {
                Some(h) => {
                    let hash = bw_crypto::b64url_decode(h).map_err(denied)?;
                    if hash.len() != 32 {
                        return Err(denied("client_data_hash must be 32 bytes"));
                    }
                    // 佔位 cdj：challenge 欄放 hash 本身（同 assertion_with_hash 除錯形態）
                    let cdj = bw_crypto::client_data_json(&bw_crypto::b64url(&hash), rp_id);
                    (hash, bw_crypto::b64url(cdj.as_bytes()))
                }
                None => {
                    let cdj = bw_crypto::client_data_json(challenge, rp_id);
                    let hash = sha2::Sha256::digest(cdj.as_bytes()).to_vec();
                    (hash, bw_crypto::b64url(cdj.as_bytes()))
                }
            };
            return self
                .settle_assert_signature(
                    session,
                    AssertTx {
                        base,
                        item,
                        idx,
                        credential_id,
                        auth_data: &auth_data,
                        tail: &tail,
                        signature: sig,
                        client_data_json: cdj_b64,
                        counter: next,
                    },
                )
                .await;
        }
        let parts = match (&self.stored_key(&base, idx)?, client_data_hash) {
            // Apple 流（有 hash）：簽 authData‖hash；標準流（只有 challenge）：自組 JSON。
            (StoredKey::Scalar(scalar), Some(h)) => {
                let hash = bw_crypto::b64url_decode(h).map_err(denied)?;
                if hash.len() != 32 {
                    return Err(denied("client_data_hash must be 32 bytes"));
                }
                bw_crypto::assertion_with_hash(rp_id, scalar, next, &hash).map_err(denied)?
            }
            (StoredKey::Scalar(scalar), None) => {
                bw_crypto::assertion(rp_id, scalar, next, challenge).map_err(denied)?
            }
            (StoredKey::Spki(_), _) => {
                return Err(denied(
                    "SE credential has no daemon-side private key; sign in appex via BeginAssert/FinishAssert",
                ));
            }
        };
        let mut ours = base.clone();
        ours["id"] = json!(item.to_string());
        ours["login"]["fido2Credentials"][idx]["counter"] = json!(next.to_string());
        self.enqueue_passkey_patch(session, item, base, ours)
            .await?;
        Ok(Response::PasskeyAssertion {
            credential_id: credential_id.clone(),
            authenticator_data: parts.authenticator_data,
            client_data_json: parts.client_data_json,
            signature: parts.signature,
        })
    }

    /// BeginAssert：以儲存憑證算 counter+1、產生 authData（flags=UP|UV|BE|BS）、
    /// 暫存 pending。**不持久化 counter**；冪等：同 credential 重複 Begin 覆蓋
    /// pending（以最後一次為準）。rp_id 不信任呼叫端，一律取鏡像 rpId。
    pub fn passkey_begin_assert(
        &self,
        credential_id: &str,
        client_data_hash: &str,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let hash = bw_crypto::b64url_decode(client_data_hash).map_err(denied)?;
        if hash.len() != 32 {
            return Err(denied("client_data_hash must be 32 bytes"));
        }
        let (item, idx) = self
            .find_credential(credential_id)?
            .ok_or(WtpError::NotFound)?;
        let row = self.store.item(item).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let rp_id =
            Self::entry_rp_id(&base, idx).ok_or_else(|| denied("credential has no rpId"))?;
        let next = Self::entry_counter(&base, idx).saturating_add(1);
        let auth_data = bw_crypto::assertion_auth_data(rp_id, next);
        self.pending_asserts.lock().unwrap().insert(
            norm_b64url(credential_id).to_owned(),
            PendingAssert {
                auth_data: auth_data.clone(),
                client_data_hash: hash.clone(),
                counter: next,
            },
        );
        Ok(Response::AssertBegin {
            credential_id: credential_id.to_owned(),
            rp_id: rp_id.to_owned(),
            authenticator_data: bw_crypto::b64url(&auth_data),
            client_data_hash: bw_crypto::b64url(&hash),
            signing_input_note: SIGNING_INPUT_NOTE.into(),
            counter: next,
        })
    }

    /// FinishAssert：用 pending 的 authData‖client_data_hash 驗 Swift 交回的
    /// DER 簽名（公鑰=儲存的 SPKI/標量匯出）→ 通過才 counter 持久化進 outbox
    /// 並消耗 pending；不符 → Err(Denied)、counter 不動、pending 保留可重試。
    pub async fn passkey_finish_assert(
        &self,
        session: &str,
        credential_id: &str,
        signature: &str,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let key = norm_b64url(credential_id).to_owned();
        let Some(pending) = self.pending_asserts.lock().unwrap().get(&key).cloned() else {
            // 未 Begin 或 daemon 重啟失憶：呼叫端重跑 BeginAssert（冪等）
            return Err(WtpError::NotFound);
        };
        let (item, idx) = self
            .find_credential(credential_id)?
            .ok_or(WtpError::NotFound)?;
        let row = self.store.item(item).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let rp_id =
            Self::entry_rp_id(&base, idx).ok_or_else(|| denied("credential has no rpId"))?;
        // 佔位 cdj：RP 實際收到的是系統自建 JSON，daemon 只供除錯顯示
        let cdj = bw_crypto::client_data_json(&bw_crypto::b64url(&pending.client_data_hash), rp_id);
        let resp = self
            .settle_assert_signature(
                session,
                AssertTx {
                    base,
                    item,
                    idx,
                    credential_id,
                    auth_data: &pending.auth_data,
                    tail: &pending.client_data_hash,
                    signature,
                    client_data_json: bw_crypto::b64url(cdj.as_bytes()),
                    counter: pending.counter,
                },
            )
            .await?;
        self.pending_asserts.lock().unwrap().remove(&key);
        Ok(resp)
    }

    /// 驗簽+counter 事務共核（AssertPasskey.signature 與 FinishAssert 共用）：
    /// 簽名輸入 = authData ‖ tail（tail=clientDataHash 32B 本體或 sha256(cdj)）。
    /// 驗不過 → Denied 且不碰鏡像/outbox；驗過 → counter 寫回鏡像並進 outbox。
    async fn settle_assert_signature(
        &self,
        session: &str,
        tx: AssertTx<'_>,
    ) -> Result<Response, WtpError> {
        let AssertTx {
            base,
            item,
            idx,
            credential_id,
            auth_data,
            tail,
            signature,
            client_data_json,
            counter,
        } = tx;
        let sig = bw_crypto::b64url_decode(signature).map_err(denied)?;
        let pub_spki = self.entry_spki(&base, idx)?;
        let mut input = auth_data.to_vec();
        input.extend_from_slice(tail);
        if !bw_crypto::verify_es256_signing_input(&pub_spki, &input, &sig) {
            return Err(denied(
                "assertion signature does not match stored credential public key",
            ));
        }
        let mut ours = base.clone();
        ours["id"] = json!(item.to_string());
        ours["login"]["fido2Credentials"][idx]["counter"] = json!(counter.to_string());
        self.enqueue_passkey_patch(session, item, base, ours)
            .await?;
        Ok(Response::PasskeyAssertion {
            credential_id: credential_id.to_owned(),
            authenticator_data: bw_crypto::b64url(auth_data),
            client_data_json,
            signature: signature.to_owned(),
        })
    }

    async fn enqueue_passkey_patch(
        &self,
        session: &str,
        id: ItemId,
        base: Value,
        ours: Value,
    ) -> Result<(), WtpError> {
        let raw = self.store.raw(id).map_err(denied)?;
        let rev = crate::sync::row_rev_of(&raw);
        let payload = json!({
            "op": "patch",
            "base": base,
            "ours": ours,
            "touched": ["fido2Credentials"],
        });
        self.store
            .enqueue(&MutationDraft {
                item: id,
                payload,
                base_rev: rev.as_deref(),
                origin: Some(session),
                mirror: Some(&ours),
            })
            .map_err(denied)?;
        self.trigger_drain();
        Ok(())
    }

    /// DeletePasskey：摘除 `login.fido2Credentials` 單條（鏡像即時改、伺服器
    /// 走 outbox 全量 PUT 收斂——語意同 counter++ 持久化路徑，VW PUT 收 fido2
    /// 陣列已由 writepath 實錄背書）。`item_id` 與 `find_credential` 實查不符
    /// （他端已搬／已刪）回 NotFound，不照單刪錯項目；空陣列原樣留欄
    /// （官方 jslib 同形，VW 收 `[]` 即清）。
    pub async fn passkey_delete(
        &self,
        session: &str,
        item_id: ItemId,
        credential_id: &str,
    ) -> Result<Response, WtpError> {
        self.require_unlocked()?;
        let (item, idx) = self
            .find_credential(credential_id)?
            .filter(|(found, _)| *found == item_id)
            .ok_or(WtpError::NotFound)?;
        let row = self.store.item(item).map_err(denied)?;
        let base = row.ok_or(WtpError::NotFound)?.enc_cipher;
        let mut ours = base.clone();
        ours["id"] = json!(item.to_string());
        if let Some(arr) = ours
            .pointer_mut("/login/fido2Credentials")
            .and_then(Value::as_array_mut)
            && idx < arr.len()
        {
            arr.remove(idx);
        }
        self.enqueue_passkey_patch(session, item, base, ours).await?;
        Ok(Response::Ok)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;

    use bw_crypto::MIN_PBKDF2_ITERATIONS;
    use bw_keys::UnlockMaterial;
    use bw_proto::PasskeyCall;

    pub(crate) fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bw-passkey-{}-{}-{tag}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&d).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        d
    }

    /// 合成帳號（PBKDF2 iter=1）落 account.json → Hub::open → MasterPassword 解鎖。
    /// server URL 是擺設：這些測試不碰網路（drain 無消費者）。
    pub(crate) async fn unlocked_hub(tag: &str) -> (Arc<Hub>, std::path::PathBuf) {
        let dir = tmp_dir(tag);
        let email = "t@example.com";
        let pw = "test-master-pw".to_string();
        let mk = bw_crypto::master_key(
            &pw,
            email,
            bw_crypto::KdfParams::Pbkdf2 {
                iterations: MIN_PBKDF2_ITERATIONS,
            },
        )
        .unwrap();
        let uk = bw_crypto::UserKey::from_bytes(vec![7u8; 64]).unwrap();
        let puk = bw_crypto::encrypt_user_key(&mk, &uk).unwrap().to_string();
        let account = json!({
            "server": "http://127.0.0.1:9",
            "email": email,
            "access_token": null,
            "refresh_token": null,
            "kdf": 0,
            "kdf_iterations": MIN_PBKDF2_ITERATIONS as u64,
            "kdf_memory": null,
            "kdf_parallelism": null,
            "protected_user_key": puk,
            "keys_fingerprint": null,
        });
        std::fs::write(dir.join("account.json"), account.to_string()).unwrap();
        let hub = Hub::open(&dir, None, None).await.unwrap();
        assert!(
            hub.machine
                .submit(UnlockMaterial::MasterPassword(Zeroizing::new(pw)))
                .is_ok()
        );
        (hub, dir)
    }

    fn register_call(item_id: Option<ItemId>) -> PasskeyCall {
        PasskeyCall::RegisterPasskey {
            rp_id: "webauthn.test".into(),
            challenge: "reg-challenge".into(),
            user_name: "alice".into(),
            user_handle: "handle-1".into(),
            display_name: "Alice".into(),
            item_id,
            credential_public_key: None,
        }
    }

    #[tokio::test]
    async fn register_assert_roundtrip_persists_counter_to_outbox() {
        let (hub, dir) = unlocked_hub("rt").await;
        let Response::PasskeyAttestation {
            credential_id,
            attestation_object,
        } = hub
            .passkey_register("s", &register_call(None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        // outbox：create 列，cipher 帶 fido2Credentials（keyValue 走信封、counter=1）
        let due = hub.store.take_due(16).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].payload["op"], "create");
        let cred = &due[0].payload["cipher"]["login"]["fido2Credentials"][0];
        assert_eq!(cred["credentialId"], credential_id.as_str());
        assert_eq!(cred["rpId"], "webauthn.test");
        assert_eq!(cred["userHandle"], "handle-1");
        assert_eq!(cred["userName"], "alice");
        assert_eq!(cred["displayName"], "Alice");
        assert_eq!(cred["counter"], "1");
        assert_eq!(cred["credentialType"], "public-key");
        assert_eq!(cred["keyType"], "public");
        assert_eq!(cred["keySource"], "generate");
        assert_eq!(cred["authenticationType"], "enterprise");
        let kv = cred["keyValue"].as_str().expect("keyValue is string");
        assert!(kv.starts_with("2."), "keyValue 必須是 type 2 信封");
        // 結算 create：否則同 item 的 counter patch 列被 FIFO 擋在後面
        for m in &due {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }

        // attestation 結構（b64url → CBOR）：fmt=none、authData 含 rpIdHash/flags/AT/counter
        let att_bytes = bw_crypto::b64url_decode(&attestation_object).unwrap();
        let obj: serde_cbor::Value = serde_cbor::from_slice(&att_bytes).unwrap();
        let serde_cbor::Value::Map(m) = obj else {
            panic!("attestation map")
        };
        let text = |k: &str| {
            m.get(&serde_cbor::Value::Text(k.into()))
                .expect("key present")
                .clone()
        };
        assert_eq!(text("fmt"), serde_cbor::Value::Text("none".into()));
        assert_eq!(text("attStmt"), serde_cbor::Value::Map(Default::default()));
        let serde_cbor::Value::Bytes(ad) = text("authData") else {
            panic!("authData bytes")
        };
        assert_eq!(
            &ad[0..32],
            &sha2::Sha256::digest(b"webauthn.test")[..],
            "rpIdHash 內含於 attestation authData"
        );
        assert_eq!(ad[32], bw_crypto::FLAGS_REGISTER);
        assert_eq!(&ad[33..37], &1u32.to_be_bytes());

        // GetPasskeys：Metadata 級投影（無 keyValue/密鑰材料）
        let Response::Passkeys(entries) = hub.passkey_list(Some("webauthn.test")).unwrap() else {
            panic!("expect passkeys");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].credential_id, credential_id);
        assert_eq!(entries[0].user_name, "alice");
        assert_eq!(entries[0].rp_id, "webauthn.test");
        let listed = serde_json::to_string(&entries).unwrap();
        assert!(!listed.contains("keyValue"), "Metadata 級不回密鑰材料");

        // 斷言：counter 2、flags=UP|UV、challenge 逐字元對齊、簽名可用鏡像私鑰驗通
        let challenge = "Q1-_2x";
        let Response::PasskeyAssertion {
            credential_id: cid_out,
            authenticator_data,
            client_data_json,
            signature,
        } = hub
            .passkey_assert(
                "s",
                &PasskeyCall::AssertPasskey {
                    credential_id: credential_id.clone(),
                    challenge: challenge.into(),
                    rp_id: "webauthn.test".into(),
                    client_data_hash: None,
                    signature: None,
                    key_id: None,
                },
            )
            .await
            .unwrap()
        else {
            panic!("expect assertion");
        };
        assert_eq!(cid_out, credential_id);
        let ad = bw_crypto::b64url_decode(&authenticator_data).unwrap();
        assert_eq!(&ad[0..32], &sha2::Sha256::digest(b"webauthn.test")[..]);
        assert_eq!(ad[32], bw_crypto::FLAGS_ASSERT);
        assert_eq!(u32::from_be_bytes(ad[33..37].try_into().unwrap()), 2);
        let cdj = bw_crypto::b64url_decode(&client_data_json).unwrap();
        let cdj_s = String::from_utf8(cdj.clone()).unwrap();
        assert!(
            cdj_s.contains(&format!(r#""challenge":"{challenge}""#)),
            "challenge 必須逐字元原樣嵌入：{cdj_s}"
        );

        // 存儲的私鑰（解密 keyValue）必須正是簽名者：公鑰驗通 assertion
        let item_id = {
            let (id, _) = hub.find_credential(&credential_id).unwrap().unwrap();
            id
        };
        let row = hub.store.item(item_id).unwrap().unwrap();
        assert_eq!(
            row.enc_cipher.pointer("/login/fido2Credentials/0/counter"),
            Some(&json!("2")),
            "鏡像 counter 同步遞增"
        );
        let stored_kv = row
            .enc_cipher
            .pointer("/login/fido2Credentials/0/keyValue")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let scalar = hub
            .machine
            .with_keys(|kb| {
                let pt = bw_crypto::decrypt(kb.user_key(), &stored_kv).unwrap();
                bw_crypto::b64_decode(&pt).unwrap()
            })
            .unwrap();
        let pub_key = bw_crypto::public_key_sec1(&scalar).unwrap();
        assert!(
            bw_crypto::verify_es256(
                &pub_key,
                &ad,
                &cdj,
                &bw_crypto::b64url_decode(&signature).unwrap()
            ),
            "出棧簽名必須由存儲私鑰產生"
        );

        // outbox：斷言後的 counter 更新以 patch 列入列（touched=fido2Credentials）
        let due = hub.store.take_due(16).unwrap();
        let patch = due
            .iter()
            .find(|m| m.payload["op"] == "patch")
            .expect("counter 更新必須進 outbox");
        assert_eq!(patch.payload["touched"][0], "fido2Credentials");
        assert_eq!(
            patch.payload["ours"]["login"]["fido2Credentials"][0]["counter"],
            "2"
        );
        assert_eq!(
            patch.payload["base"]["login"]["fido2Credentials"][0]["counter"],
            "1"
        );
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn register_attaches_to_existing_item_via_patch() {
        let (hub, dir) = unlocked_hub("attach").await;
        let seed = hub
            .write_create(
                "s",
                &bw_proto::CipherDraft {
                    kind: bw_proto::ItemKind::Login,
                    name: "existing".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(seed, Response::Ok));
        let id = {
            let metas = hub
                .store
                .query(&Query {
                    limit: u32::MAX,
                    ..Default::default()
                })
                .unwrap();
            metas[0].id
        };
        // 先結算 seed 的 create 列：outbox 同 item FIFO，未結算前 patch 不出境
        for m in hub.store.take_due(16).unwrap() {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        let Response::PasskeyAttestation { credential_id, .. } = hub
            .passkey_register("s", &register_call(Some(id)))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        let row = hub.store.item(id).unwrap().unwrap();
        let arr = row.enc_cipher["login"]["fido2Credentials"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["credentialId"], credential_id.as_str());
        // register-attach 走 patch outbox 列
        let due = hub.store.take_due(16).unwrap();
        assert!(due.iter().any(|m| {
            m.payload["op"] == "patch"
                && m.payload["ours"]["login"]["fido2Credentials"][0]["credentialId"]
                    == credential_id.as_str()
        }));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 測試用 SE 金鑰模擬：p256 標量 → 匯出 SPKI（Swift 由 SecKey 做的同一形態）。
    fn se_test_key() -> (Zeroizing<Vec<u8>>, String) {
        let scalar = bw_crypto::generate_private_key();
        let spki = bw_crypto::spki_from_scalar(&scalar).unwrap();
        (scalar, bw_crypto::b64url(&spki))
    }

    fn decrypted(hub: &Hub, env: &str) -> String {
        hub.machine
            .with_keys(|kb| bw_crypto::decrypt(kb.user_key(), &env.to_string()))
            .unwrap()
            .unwrap()
    }

    fn attestation_auth_data(att_b64url: &str) -> Vec<u8> {
        let bytes = bw_crypto::b64url_decode(att_b64url).unwrap();
        let obj: serde_cbor::Value = serde_cbor::from_slice(&bytes).unwrap();
        let serde_cbor::Value::Map(m) = obj else {
            panic!("attestation map")
        };
        let serde_cbor::Value::Bytes(ad) = m
            .get(&serde_cbor::Value::Text("authData".into()))
            .expect("authData key")
        else {
            panic!("authData bytes")
        };
        ad.clone()
    }

    fn register_spki_call(spki_b64: &str, item_id: Option<ItemId>) -> PasskeyCall {
        PasskeyCall::RegisterPasskey {
            rp_id: "webauthn.test".into(),
            challenge: "reg-challenge".into(),
            user_name: "alice".into(),
            user_handle: "handle-1".into(),
            display_name: "Alice".into(),
            item_id,
            credential_public_key: Some(spki_b64.into()),
        }
    }

    fn finish_register(credential_id: &str, spki_b64: &str) -> PasskeyCall {
        PasskeyCall::FinishRegister {
            credential_id: credential_id.into(),
            credential_public_key: spki_b64.into(),
            rp_id: "webauthn.test".into(),
            challenge: "reg-challenge".into(),
            user_name: "alice".into(),
            user_handle: "handle-1".into(),
            display_name: "Alice".into(),
            item_id: None,
        }
    }

    fn mirror_entry(hub: &Hub, credential_id: &str) -> (ItemId, Value) {
        let (item, idx) = hub.find_credential(credential_id).unwrap().unwrap();
        let row = hub.store.item(item).unwrap().unwrap();
        let entry = row.enc_cipher["login"]["fido2Credentials"][idx].clone();
        (item, entry)
    }

    #[tokio::test]
    async fn spki_registration_stores_platform_credential_and_lists_public_key() {
        let (hub, dir) = unlocked_hub("spki-reg").await;
        let (scalar, spki_b64) = se_test_key();
        let Response::PasskeyAttestation {
            credential_id,
            attestation_object,
        } = hub
            .passkey_register("s", &register_spki_call(&spki_b64, None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };

        // outbox entry：SE 流欄位——keyValue=信封(SPKI b64url)、platform-aaguid+aaguid
        let due = hub.store.take_due(16).unwrap();
        let cred = &due[0].payload["cipher"]["login"]["fido2Credentials"][0];
        assert_eq!(cred["credentialId"], credential_id.as_str());
        assert_eq!(cred["keyType"], "public");
        assert_eq!(cred["keySource"], "generate");
        assert_eq!(cred["authenticationType"], "platform-aaguid");
        assert_eq!(cred["aaguid"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(cred["counter"], "1");
        let kv = cred["keyValue"].as_str().expect("keyValue is string");
        assert!(kv.starts_with("2."), "keyValue 必須是 type 2 信封");
        assert_eq!(
            decrypted(&hub, kv),
            spki_b64,
            "keyValue 明文必須正是提交的金鑰 SPKI b64url"
        );
        for m in &due {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }

        // attestation COSE 段 = SPKI 轉出的 COSE（且與同金鑰標量路徑一致）
        let ad = attestation_auth_data(&attestation_object);
        let cose_expected =
            bw_crypto::cose_public_key_from_spki(&bw_crypto::b64url_decode(&spki_b64).unwrap())
                .unwrap();
        assert_eq!(&ad[ad.len() - cose_expected.len()..], &cose_expected[..]);
        assert_eq!(cose_expected, bw_crypto::cose_public_key(&scalar).unwrap());
        assert_eq!(ad[32], bw_crypto::FLAGS_REGISTER);

        // GetPasskeys：public_key 回傳與匯入一致（SPKI b64url）
        let Response::Passkeys(entries) = hub.passkey_list(Some("webauthn.test")).unwrap() else {
            panic!("expect passkeys");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].credential_id, credential_id);
        assert_eq!(entries[0].public_key, spki_b64);
        let listed = serde_json::to_string(&entries).unwrap();
        assert!(!listed.contains("keyValue"), "Metadata 級不回密鑰材料");
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn begin_register_finish_register_two_step_persists_issued_id() {
        let (hub, dir) = unlocked_hub("reg-2step").await;
        let Response::RegisterBegin { credential_id } = hub.passkey_begin_register().unwrap()
        else {
            panic!("expect RegisterBegin");
        };
        assert_eq!(bw_crypto::b64url_decode(&credential_id).unwrap().len(), 32);
        let (scalar, spki_b64) = se_test_key();
        let Response::PasskeyAttestation {
            credential_id: echoed,
            ..
        } = hub
            .passkey_finish_register("s", &finish_register(&credential_id, &spki_b64))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        assert_eq!(
            echoed, credential_id,
            "id 必須原樣沿用 BeginRegister 簽發值"
        );
        let due = hub.store.take_due(16).unwrap();
        let cred = &due[0].payload["cipher"]["login"]["fido2Credentials"][0];
        assert_eq!(cred["credentialId"], credential_id.as_str());
        assert_eq!(cred["authenticationType"], "platform-aaguid");
        for m in &due {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        // 重複 Finish（同 id）→ Denied：不產生第二份憑證
        assert!(matches!(
            hub.passkey_finish_register("s", &finish_register(&credential_id, &spki_b64))
                .await,
            Err(WtpError::Denied { .. })
        ));
        // 壞 id 格式（非 32B）→ Denied
        assert!(matches!(
            hub.passkey_finish_register("s", &finish_register("AA", &spki_b64))
                .await,
            Err(WtpError::Denied { .. })
        ));
        // 簽名事務在兩步流憑證上照樣可用
        let hash = [9u8; 32];
        let Response::AssertBegin {
            authenticator_data, ..
        } = hub
            .passkey_begin_assert(&credential_id, &bw_crypto::b64url(&hash))
            .unwrap()
        else {
            panic!("expect AssertBegin");
        };
        let ad = bw_crypto::b64url_decode(&authenticator_data).unwrap();
        let mut input = ad.clone();
        input.extend_from_slice(&hash);
        let sig = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input).unwrap());
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &sig).await,
            Ok(Response::PasskeyAssertion { .. })
        ));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn begin_finish_assert_persists_counter_only_after_valid_signature() {
        let (hub, dir) = unlocked_hub("assert-2step").await;
        let Response::PasskeyAttestation { credential_id, .. } = hub
            .passkey_register("s", &register_call(None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        for m in hub.store.take_due(16).unwrap() {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }

        // Begin：counter+1 進 authData，但鏡像與 outbox 都不動
        let hash = [9u8; 32];
        let Response::AssertBegin {
            authenticator_data,
            client_data_hash,
            signing_input_note,
            counter,
            rp_id,
            ..
        } = hub
            .passkey_begin_assert(&credential_id, &bw_crypto::b64url(&hash))
            .unwrap()
        else {
            panic!("expect AssertBegin");
        };
        assert_eq!(counter, 2);
        assert_eq!(rp_id, "webauthn.test");
        assert_eq!(client_data_hash, bw_crypto::b64url(&hash), "hash 須回顯");
        assert_eq!(
            signing_input_note,
            "DER ECDSA over authenticator_data‖client_data_hash"
        );
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "1", "Begin 不得持久化 counter");
        assert!(
            !hub.store
                .take_due(16)
                .unwrap()
                .iter()
                .any(|m| m.payload["op"] == "patch"),
            "Begin 不得進 outbox"
        );

        // 測試私鑰簽 ad‖hash（Swift SE 簽名的等價物）
        let scalar = Zeroizing::new(
            bw_crypto::b64_decode(&decrypted(&hub, entry["keyValue"].as_str().unwrap())).unwrap(),
        );
        let ad = bw_crypto::b64url_decode(&authenticator_data).unwrap();
        assert_eq!(ad[32], bw_crypto::FLAGS_ASSERT);
        assert_eq!(u32::from_be_bytes(ad[33..37].try_into().unwrap()), 2);
        let mut input = ad.clone();
        input.extend_from_slice(&hash);
        let sig_b64 = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input).unwrap());

        let Response::PasskeyAssertion {
            credential_id: cid_out,
            authenticator_data: ad_out,
            signature: sig_out,
            ..
        } = hub
            .passkey_finish_assert("s", &credential_id, &sig_b64)
            .await
            .unwrap()
        else {
            panic!("expect assertion");
        };
        assert_eq!(cid_out, credential_id);
        assert_eq!(ad_out, authenticator_data, "authData 必須原樣回傳");
        assert_eq!(sig_out, sig_b64, "簽名必須原樣回傳");
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "2", "驗簽通過後 counter 才持久化");
        let due = hub.store.take_due(16).unwrap();
        let patch = due
            .iter()
            .find(|m| m.payload["op"] == "patch")
            .expect("counter 更新必須進 outbox");
        assert_eq!(
            patch.payload["ours"]["login"]["fido2Credentials"][0]["counter"],
            "2"
        );
        // pending 已消耗：重複 Finish → NotFound
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &sig_b64)
                .await,
            Err(WtpError::NotFound)
        ));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn finish_assert_bad_signature_denied_counter_untouched() {
        let (hub, dir) = unlocked_hub("assert-badsig").await;
        let Response::PasskeyAttestation { credential_id, .. } = hub
            .passkey_register("s", &register_call(None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        for m in hub.store.take_due(16).unwrap() {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        let hash = [9u8; 32];
        let Response::AssertBegin {
            authenticator_data, ..
        } = hub
            .passkey_begin_assert(&credential_id, &bw_crypto::b64url(&hash))
            .unwrap()
        else {
            panic!("expect AssertBegin");
        };
        let (_, entry) = mirror_entry(&hub, &credential_id);
        let scalar = Zeroizing::new(
            bw_crypto::b64_decode(&decrypted(&hub, entry["keyValue"].as_str().unwrap())).unwrap(),
        );
        let mut ad = bw_crypto::b64url_decode(&authenticator_data).unwrap();
        // 錯的簽名輸入（多簽一個位元組）→ 驗簽必敗
        let mut input = ad.clone();
        input.extend_from_slice(&hash);
        input.push(0xFF);
        let bad_sig = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input).unwrap());
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &bad_sig)
                .await,
            Err(WtpError::Denied { .. })
        ));
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "1", "驗簽失敗 counter 不動");
        assert!(
            !hub.store
                .take_due(16)
                .unwrap()
                .iter()
                .any(|m| m.payload["op"] == "patch"),
            "驗簽失敗不得進 outbox"
        );
        // pending 保留：同 authData 以正確簽名重試成功
        ad.extend_from_slice(&hash);
        let good_sig = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &ad).unwrap());
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &good_sig)
                .await,
            Ok(Response::PasskeyAssertion { .. })
        ));
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "2");
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn begin_assert_repeat_overwrites_pending() {
        let (hub, dir) = unlocked_hub("assert-overwrite").await;
        let Response::PasskeyAttestation { credential_id, .. } = hub
            .passkey_register("s", &register_call(None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        for m in hub.store.take_due(16).unwrap() {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];
        let Response::AssertBegin {
            authenticator_data,
            counter,
            ..
        } = hub
            .passkey_begin_assert(&credential_id, &bw_crypto::b64url(&hash_a))
            .unwrap()
        else {
            panic!("expect AssertBegin");
        };
        assert_eq!(counter, 2);
        // 第二次 Begin：冪等覆蓋（counter 仍 2——第一次未持久化）
        let Response::AssertBegin { counter, .. } = hub
            .passkey_begin_assert(&credential_id, &bw_crypto::b64url(&hash_b))
            .unwrap()
        else {
            panic!("expect AssertBegin");
        };
        assert_eq!(counter, 2, "重複 Begin 不重複遞增");
        let (_, entry) = mirror_entry(&hub, &credential_id);
        let scalar = Zeroizing::new(
            bw_crypto::b64_decode(&decrypted(&hub, entry["keyValue"].as_str().unwrap())).unwrap(),
        );
        let ad = bw_crypto::b64url_decode(&authenticator_data).unwrap();
        // 以舊 hash A 簽 → 對 pending（已是 B）驗不過
        let mut input_a = ad.clone();
        input_a.extend_from_slice(&hash_a);
        let sig_a = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input_a).unwrap());
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &sig_a).await,
            Err(WtpError::Denied { .. })
        ));
        // 以新 hash B 簽 → 成功
        let mut input_b = ad.clone();
        input_b.extend_from_slice(&hash_b);
        let sig_b = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input_b).unwrap());
        assert!(matches!(
            hub.passkey_finish_assert("s", &credential_id, &sig_b).await,
            Ok(Response::PasskeyAssertion { .. })
        ));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn se_credential_requires_signature_and_inline_sig_path_persists() {
        let (hub, dir) = unlocked_hub("assert-inline").await;
        let (scalar, spki_b64) = se_test_key();
        let Response::PasskeyAttestation { credential_id, .. } = hub
            .passkey_register("s", &register_spki_call(&spki_b64, None))
            .await
            .unwrap()
        else {
            panic!("expect attestation");
        };
        for m in hub.store.take_due(16).unwrap() {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        let hash = [4u8; 32];
        // SE 憑證 + 無簽名：daemon 無私鑰可簽 → Denied
        assert!(matches!(
            hub.passkey_assert(
                "s",
                &PasskeyCall::AssertPasskey {
                    credential_id: credential_id.clone(),
                    challenge: "ch".into(),
                    rp_id: "webauthn.test".into(),
                    client_data_hash: Some(bw_crypto::b64url(&hash)),
                    signature: None,
                    key_id: Some("se-tag".into()),
                },
            )
            .await,
            Err(WtpError::Denied { .. })
        ));
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "1", "拒絕路徑 counter 不動");

        // AssertPasskey.signature Some：daemon 現算 authData → 驗簽 → 持久化
        let ad = bw_crypto::assertion_auth_data("webauthn.test", 2);
        let mut input = ad.clone();
        input.extend_from_slice(&hash);
        let sig = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, &input).unwrap());
        let Response::PasskeyAssertion {
            authenticator_data,
            signature,
            ..
        } = hub
            .passkey_assert(
                "s",
                &PasskeyCall::AssertPasskey {
                    credential_id: credential_id.clone(),
                    challenge: "ch".into(),
                    rp_id: "webauthn.test".into(),
                    client_data_hash: Some(bw_crypto::b64url(&hash)),
                    signature: Some(sig.clone()),
                    key_id: Some("se-tag".into()),
                },
            )
            .await
            .unwrap()
        else {
            panic!("expect assertion");
        };
        assert_eq!(authenticator_data, bw_crypto::b64url(&ad));
        assert_eq!(signature, sig);
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "2", "驗簽通過後 counter 持久化");
        let due = hub.store.take_due(16).unwrap();
        assert!(due.iter().any(|m| {
            m.payload["op"] == "patch"
                && m.payload["ours"]["login"]["fido2Credentials"][0]["counter"] == "2"
        }));

        // 錯簽名的內聯路徑：Denied 且 counter 不動
        let bad = bw_crypto::b64url(&bw_crypto::sign_es256(&scalar, b"wrong").unwrap());
        assert!(matches!(
            hub.passkey_assert(
                "s",
                &PasskeyCall::AssertPasskey {
                    credential_id: credential_id.clone(),
                    challenge: "ch".into(),
                    rp_id: "webauthn.test".into(),
                    client_data_hash: Some(bw_crypto::b64url(&hash)),
                    signature: Some(bad),
                    key_id: None,
                },
            )
            .await,
            Err(WtpError::Denied { .. })
        ));
        let (_, entry) = mirror_entry(&hub, &credential_id);
        assert_eq!(entry["counter"], "2", "失敗的内聯路徑 counter 不動");
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn locked_hub_rejects_passkey_calls() {
        let dir = tmp_dir("locked");
        let hub = Hub::open(&dir, None, None).await.unwrap();
        assert!(matches!(hub.passkey_list(None), Err(WtpError::Locked)));
        assert!(matches!(
            hub.passkey_register("s", &register_call(None)).await,
            Err(WtpError::Locked)
        ));
        assert!(matches!(
            hub.passkey_assert(
                "s",
                &PasskeyCall::AssertPasskey {
                    credential_id: "x".into(),
                    challenge: "y".into(),
                    rp_id: "r".into(),
                    client_data_hash: None,
                    signature: None,
                    key_id: None,
                }
            )
            .await,
            Err(WtpError::Locked)
        ));
        assert!(matches!(
            hub.passkey_begin_assert("x", &bw_crypto::b64url(&[7u8; 32])),
            Err(WtpError::Locked)
        ));
        assert!(matches!(
            hub.passkey_finish_assert("s", "x", "sig").await,
            Err(WtpError::Locked)
        ));
        assert!(matches!(
            hub.passkey_begin_register(),
            Err(WtpError::Locked)
        ));
        assert!(matches!(
            hub.passkey_finish_register(
                "s",
                &PasskeyCall::FinishRegister {
                    credential_id: "x".into(),
                    credential_public_key: "y".into(),
                    rp_id: "r".into(),
                    challenge: "c".into(),
                    user_name: "u".into(),
                    user_handle: "h".into(),
                    display_name: "U".into(),
                    item_id: None,
                }
            )
            .await,
            Err(WtpError::Locked)
        ));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// DeletePasskey：鏡像即時摘除＋outbox 全量 patch 收斂（touched=fido2Credentials）；
    /// item 歸屬不符回 NotFound（不刪錯項目）；刪後 GetPasskeys 不再列出。
    #[tokio::test]
    async fn delete_passkey_clears_mirror_and_enqueues_patch() {
        let (hub, dir) = unlocked_hub("del").await;
        let Response::PasskeyAttestation { credential_id, .. } =
            hub.passkey_register("s", &register_call(None)).await.unwrap()
        else {
            panic!("expect attestation");
        };
        let Response::Passkeys(entries) = hub.passkey_list(None).unwrap() else {
            panic!("expect passkeys");
        };
        let item = entries[0].item_id.expect("list 帶 item 歸屬");
        // 歸屬不符：錯 item_id 不動鏡像
        assert!(matches!(
            hub.passkey_delete("s", ItemId::new_v4(), &credential_id).await,
            Err(WtpError::NotFound)
        ));
        let due = hub.store.take_due(16).unwrap();
        for m in &due {
            hub.store.settle(m.id, bw_store::MutState::Applied).unwrap();
        }
        assert!(hub.passkey_delete("s", item, &credential_id).await.is_ok());
        let row = hub.store.item(item).unwrap().expect("項目仍在");
        assert!(
            row.enc_cipher["login"]["fido2Credentials"]
                .as_array()
                .is_some_and(|a| a.is_empty()),
            "鏡像 fido2Credentials 應已摘除"
        );
        let due = hub.store.take_due(16).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].payload["op"], "patch");
        assert_eq!(due[0].payload["touched"][0], "fido2Credentials");
        assert!(due[0].payload["ours"]["login"]["fido2Credentials"]
            .as_array()
            .is_some_and(|a| a.is_empty()));
        let Response::Passkeys(entries) = hub.passkey_list(None).unwrap() else {
            panic!("expect passkeys");
        };
        assert!(entries.is_empty(), "刪後不再列出");
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }
}
