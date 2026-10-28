# bw-crypto 來源查證筆記

實作契約見 `docs/ARCHITECTURE.md` §3.1。本檔記錄每個魔術常數的出處，
以及文件與原始碼不一致時的裁決。**查證基準日：2026-10-29。**

## 主要查證來源

- 官方 Rust 金鑰庫（現行客戶端實際使用的實作）：
  - `bitwarden/sdk-internal` @ main，`crates/bitwarden-crypto/src/`
    （經 GitHub API 逐檔下載比對，2026-10-29）
  - crates.io 發布件 `bitwarden-crypto 4.0.0`（`https://static.crates.io/crates/bitwarden-crypto/bitwarden-crypto-4.0.0.crate`）
- 官方 Web 客戶端（TS）：`bitwarden/clients` @ main，
  `libs/legacy-crypto/src/services/default-key-generation.service.ts`
- 伺服器互通目標：Vaultwarden（密文原樣存取，無額外約束）

## 參數裁決（文件 vs 原始碼不一致時以原始碼為準）

| 項目 | 值 | 來源 |
|---|---|---|
| PBKDF2 預設迭代 | 600,000 | sdk-internal `kdf.rs::default_pbkdf2_iterations`；與 https://bitwarden.com/help/kdf-algorithms 一致 |
| PBKDF2 下限/上限 | 5,000 / 2,100,000 | `kdf.rs::PBKDF2_MIN_ITERATIONS`；上限見 help/kdf-algorithms |
| Argon2id 預設 | m=32 MiB, t=6, p=4 | `kdf.rs::default_argon2_*` |
| Argon2id 下限 | m≥16 MiB, t≥2, p≥1 | `kdf.rs::ARGON2ID_MIN_*` |
| Argon2id salt | **SHA-256(trim+lowercase(email))**，非 email 原樣 | `kdf.rs::derive_kdf_key`（`sha2::Sha256::new().chain_update(salt).finalize()`） |
| master key 輸出 | 32 bytes | 同上 |
| KDF salt 正規化 | email `trim().to_lowercase()` | `KdfDerivedKeyMaterial::derive` 註解與實作 |
| master password hash | PBKDF2-HMAC-SHA256(mk, **password 為 salt**, **1 次**, 32 bytes) | `master_key.rs::derive_master_key_hash`，`HashPurpose::ServerAuthorization = 1`（LocalAuthorization = 2） |
| stretch | HKDF-SHA256 **Expand-only**：mk 直接作 PRK，info="enc"/"mac"，各 32 bytes，串成 64 bytes（enc‖mac） | `keys/utils.rs::stretch_key` + `util.rs::hkdf_expand`（`from_prk`）；TS 端同：`default-key-generation.service.ts` `hkdfExpand(key, "enc"/"mac", 32, "sha256")` |
| 信封 type 2 | AES-256-CBC(PKCS#7) + HMAC-SHA256(mac_key, iv‖ct)；Encrypt-then-MAC，驗證先於解密（常數時間） | `hazmat/symmetric_encryption/aes256_cbc_hmac_sha256_ae.rs::calculate_mac/decrypt` |
| 字串格式 | `2.<b64 iv>|<b64 ct>|<b64 mac>`；type 0 為 `0.<iv>|<ct>` | `enc_string/symmetric.rs::parse_known_format/to_buffer` |
| 子鑰切分 | 64B key：enc=k[0..32]、mac=k[32..64] | `ae.rs::split_to_subkeys` |
| type 0 + 64B key | 拒絕（防去 MAC 降級攻擊） | `enc_string/symmetric.rs::test_decrypt_downgrade_encstring_prevention`（官方 Err(WrongKeyType)） |
| type 1（遠古） | AES-128-CBC + HMAC-SHA256；32B key：enc=k[0..16]、mac=k[16..32]；64B key 依 jslib 佈局 mac=k[32..64]；只解析不生成 | 發布件 `bitwarden-crypto 0.5.0` `enc_string/symmetric.rs::decrypt_with_key`（現行 4.0.0 已移除 type 1） |
| RSA | RSA-2048；public=base64 SPKI DER、private=type 2 信封包 PKCS#8 DER；org key 包裝 = **RSA-OAEP(SHA-1)**，序列化 `4.<b64>` | `rsa.rs::make_key_pair`、`encrypt_rsa2048_oaep_sha1`（`Oaep::<Sha1>`）；`PublicKeyEncryptionAlgorithm::RsaOaepSha1`（bitwarden-organization-crypto）；`4.` 前綴實證見 `keys/device_key.rs` 測試常數 |
| user key 明文 | 64 bytes raw（enc‖mac，無型別前綴）；type 0 舊帳號以**未 stretch** 的 master key 直接 AES 解 | `master_key.rs::encrypt_user_key/decrypt_user_key`、`symmetric_crypto_key.rs::to_encoded_raw/as_slice` |
| TOTP | RFC 6238，預設 6 digits / 30 s / SHA1；6-digit 為 mod 10^6（非前 6 碼） | RFC 6238 §3/§5.4（https://www.rfc-editor.org/rfc/rfc6238.txt）；Bitwarden 用戶端同 |
| 密碼產生器 | 預設長度 16、界 5..=128、special 字集 `!@#$%^&*`、ambiguous 排除 `I O l 0 1` | `sdk-internal/crates/bitwarden-generators/src/password.rs`（`DEFAULT_PASSWORD_LENGTH`、`SPECIAL_CHARS`、`avoid_ambiguous` 文件註解） |

## 白皮書 vs 原始碼：迭代數不一致

https://bitwarden.com/help/bitwarden-security-white-paper/ 稱 master password
hash 為「客戶端 100,001 次 + 伺服器 100,000 次」；https://bitwarden.com/help/what-encryption-is-used
與 help/kdf-algorithms 又稱「總計預設 700,000 次」。現行原始碼
（`derive_master_key_hash`，ServerAuthorization）**只做 1 次 PBKDF-SHA256**
（以 master key 為 PRF 輸入、password 為 salt），白皮書數字是舊版方案。
依作業指示，以 clients/sdk-internal 原始碼為準；KAT 釘選見
`tests/vectors/official_bitwarden.json` 的 `pbkdf2_hash`（100k 派生 + 1 次 hash，
官方斷言值 `wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=`）。

## 測試向量來源（tests/vectors/official_bitwarden.json）

- `pbkdf2_hash`、`argon2id_hash`、`stretch`、`aes_hmac_type2`、
  `aes_hmac_deterministic`、`decryptable_type2`、`legacy_type0_user_key`、
  `master_password_e2e`（TEST_SALT/TEST_PASSWORD/AUTH_HASH 常數）、
  `rsa_oaep_sha1_device`：逐字取自 bitwarden-crypto 4.0.0 /
  sdk-internal `bitwarden-core/src/key_management/master_password.rs` 的
  測試斷言值（**只取資料，不鏈接其碼**，GPL 淨空）。
- `synthetic_type2_user_key_e2e`：官方測試中 `TEST_USER_KEY` 註明是
  desktop 範例金鑰、與 `test@example.com/test_password` **無綁定關係**
  （實測 MAC 不符，已驗證），故 type-2 Protected Symmetric Key 的端到端
  向量由本專案以獨立實作（python hashlib + openssl）產生並釘選：
  master key、stretch、hash 三步各有官方 KAT 鎖住，鏈接處可信。
- RFC：6070（PBKDF2-HMAC-SHA1）、5869 A.1/A.3（HKDF）、
  6238 Appendix B（TOTP 全表）、9106 縮參數 Argon2id
  （m=32KiB/t=3/p=4 + secret/ad，同 argon2 crate KAT 值）。

## 其他紀律

- 本 crate 零 fs/net：`cargo tree -p bw-crypto -e normal` 無
  tokio/reqwest/hyper/rustls/`std::fs` 使用；`getrandom`/`libc` 僅為
  `rand` 的 OS 熵來源。
- 金鑰型別（MasterKey/StretchedKey/UserKey/OrgKey/PasswordHash）：
  Debug 一律 REDACTED、Drop zeroize、無 Copy；`from_bytes` 供
  bw-keys 測試構造（U5 協定）。
- 官方 `hkdfSalt="bitwarden"`（extract+salt 模式）只用於 Secrets Manager
  機器金鑰（`bitwarden/sdk-sm` 路徑），vault 解鎖路徑不用——勿混用，
  否則解不出 Protected Symmetric Key。
