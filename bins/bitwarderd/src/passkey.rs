//! Passkey 業務核心（macOS autofill 契約 §2–§5）：fido2Credentials 讀寫、
//! ES256 註冊/斷言、counter 持久化走既有 mutate→outbox→sync 機制。
//! 金鑰只經 `with_keys` 流通；識別欄位（credentialId/rpId/userHandle/userName）
//! 為鏡像內明文，GetPasskeys 因此不需解密即可投影（契約 §1 Metadata 級）。

use serde_json::{Value, json};
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
    /// GetPasskeys：Metadata 級投影，不含任何密鑰材料（keyValue 永不進回應）。
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
            for c in arr {
                let get = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default();
                let entry = PasskeyEntry {
                    credential_id: get("credentialId").to_owned(),
                    user_handle: get("userHandle").to_owned(),
                    user_name: get("userName").to_owned(),
                    rp_id: get("rpId").to_owned(),
                };
                if rp_id.is_none_or(|rp| norm_b64url(&entry.rp_id) == norm_b64url(rp)) {
                    out.push(entry);
                }
            }
        }
        Ok(Response::Passkeys(out))
    }

    /// RegisterPasskey：daemon 生成 P-256 私鑰 → COSE 公鑰 → none-attestation。
    /// item_id None = 新建 login item（name=rpId、username=user_name、uri=https://rpId）；
    /// Some = 附加 fido2Credentials 到既有 item。寫入一律走 outbox（§2.4）。
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
        } = call
        else {
            return Err(denied("expect RegisterPasskey"));
        };
        self.require_unlocked()?;
        let scalar = bw_crypto::generate_private_key();
        let cred_id_raw: Vec<u8> = {
            let mut raw = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
            raw
        };
        let credential_id = bw_crypto::b64url(&cred_id_raw);
        let attestation_object =
            bw_crypto::attestation_object(rp_id, &cred_id_raw, &scalar, 1).map_err(denied)?;
        // keyValue 明文＝私鑰標量的標準 base64，再走 type 2 信封（契約 §2）
        let key_value = self
            .machine
            .with_keys(|kb| {
                bw_crypto::encrypt(kb.user_key(), &bw_crypto::b64(&scalar))
                    .map(|e| e.to_string())
                    .map_err(|e| e.to_string())
            })
            .map_err(denied)?
            .map_err(denied)?;
        let entry = json!({
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
            "authenticationType": "enterprise",
        });
        match item_id {
            Some(id) => self.passkey_attach(session, *id, entry).await,
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

    /// AssertPasskey：找憑證 → 解密 keyValue 私鑰 → counter++ 簽名 →
    /// 新 counter 寫回鏡像並進 outbox（契約 §3 持久化要求）。
    pub async fn passkey_assert(
        &self,
        session: &str,
        call: &PasskeyCall,
    ) -> Result<Response, WtpError> {
        let PasskeyCall::AssertPasskey {
            credential_id,
            challenge,
            rp_id,
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
        let stored_counter = base
            .pointer(&format!("/login/fido2Credentials/{idx}/counter"))
            .and_then(Value::as_str)
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(0);
        let next = stored_counter.saturating_add(1);
        let parts = self
            .machine
            .with_keys(|kb| {
                let enc = base
                    .pointer(&format!("/login/fido2Credentials/{idx}/keyValue"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "credential has no keyValue".to_string())?;
                let scalar_b64 = bw_crypto::decrypt(kb.user_key(), &enc.to_string())
                    .map_err(|e| e.to_string())?;
                let scalar =
                    Zeroizing::new(bw_crypto::b64_decode(&scalar_b64).map_err(|e| e.to_string())?);
                bw_crypto::assertion(rp_id, &scalar, next, challenge).map_err(|e| e.to_string())
            })
            .map_err(|_| WtpError::Locked)?
            .map_err(denied)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bw_crypto::MIN_PBKDF2_ITERATIONS;
    use bw_keys::UnlockMaterial;
    use bw_proto::PasskeyCall;
    use sha2::Digest as _;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
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
    async fn unlocked_hub(tag: &str) -> (Arc<Hub>, std::path::PathBuf) {
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
        let hub = Hub::open(&dir, None).await.unwrap();
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

    #[tokio::test]
    async fn locked_hub_rejects_passkey_calls() {
        let dir = tmp_dir("locked");
        let hub = Hub::open(&dir, None).await.unwrap();
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
                }
            )
            .await,
            Err(WtpError::Locked)
        ));
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }
}
