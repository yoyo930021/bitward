# bw-keys NOTES

實作契約：`docs/ARCHITECTURE.md` §2.2（狀態機＋轉移表）、§3.2（公開 API）、
§1.1（per-device 治理域）；轉移表每條對應 `machine.rs` 的 `t01..t18` 測試。

## 魔術常數

| 常數 | 值 | 來源 |
|---|---|---|
| `EVENT_CAP`（watch 緩衝） | 256 | 本專案自訂；鎖態事件每裝置每秒 ≪1，容得下 thin client 重連窗口 |
| `DEFAULT_CHALLENGE_TTL_MS` | 60_000 | 本專案自訂的離線挑戰上界；Auth request 的伺服器端存活另見 https://bitwarden.com/help/login-with-device/ （以伺服器為準） |
| `BIOMETRIC_ACL_FLAGS` | `kSecAccessControlBiometryCurrentSet \| kSecAccessControlUserPresence`（1<<3 \| 1<<0） | https://developer.apple.com/documentation/security/ksecaccesscontrolbiometrycurrentset 、 https://developer.apple.com/documentation/security/ksecaccesscontroluserpresence |
| keychain service 名 | `dev.bitward.userkey` | 本專案自訂（反域名，避開官方 `Bitwarden CLI` 項目） |
| runtime flag | `BW_KEYS_ENABLE_KEYCHAIN=1` | 本專案自訂：單元測試預設不觸碰真實 keychain |
| KDF（MasterPassword 路徑） | PBKDF2-SHA256 600k / Argon2id 32M,6,4 | https://bitwarden.com/help/bitwarden-security-white-paper/ ；派生本身在 bw-crypto §3.1 |
| user key 形態 | 64 bytes（32 enc ‖ 32 mac） | https://bitwarden.com/help/what-encryption-is-used ；經 U3 的 `UserKey::from_bytes/as_bytes` |

## 設計裁決

- **冪等 submit（治 clients#6898，docs/research/agent-ecosystem.md:59）**：
  已解鎖時重複 submit 仍驗證材料（這是 token 遭拒後的重認證路徑），
  但通過時不 bump epoch、不發 `Revoked` ⇒ 併發雙 unlock 收斂到同一 epoch。
- **級聯撤銷（治 clients#22773，docs/research/agent-ecosystem.md:63）**：
  `lock()`/`sign_out()`/KeyDrift 都 bump epoch 並廣播 `UnlockEvent::Revoked`；
  session 綁 epoch（`check_epoch`）、store 端有 `sessions_revoke_before`、
  identity store 由 bw-fill 訂閱處置——本 crate 只給語意，不持有 lease。
- **斷網不鎖（§2.2 反例）**：`set_egress` 只廣播 `Egress`，不動 `VaultState`。
- **TokenRejected 降級（治 clients#12270，docs/research/agent-ecosystem.md:62）**：
  保留金鑰、`needs_reauth` 旗標 + `NeedsReauth` 事件；下次成功 submit 解除。
- **DeviceAssertion 不需網路（治 clients#19055，docs/research/feature-gaps.md:16）**：
  封存記錄自 `KeyStore` 載入，全程不碰 `AuthContext`/identity server。
- **deadline 用 unix ms**（非 `Instant`）：要進 `UnlockStateView::deadline_epoch_ms`
  跨進程可比；測試以 `ManualClock` 注入（任務：tokio::time::pause 或自定
  Clock trait——選自定 trait，因為狀態機不依賴 runtime）。

## 依賴 U3（已協調）

`UserKey::from_bytes(Vec<u8>) -> UserKey` 與 `as_bytes(&self) -> &[u8]`：
U3Crypto 確認將提供（64-byte enc‖mac、zeroize-on-drop）。
