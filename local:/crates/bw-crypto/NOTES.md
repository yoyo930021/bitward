# Official source verification (2026-10-29)
- stretch_key: HKDF-SHA256 Expand-only (from_prk), info="enc" and "mac", 32 bytes each, concat 64 bytes enc||mac.
  Source: bitwarden-crypto 4.0.0 src/keys/utils.rs; clients default-key-generation.service.ts.
  Old "bitwarden" salt is Secrets Manager machine key only; vault path uses Expand with master key as PRK.
- master_password_hash: PBKDF2-HMAC-SHA256(master_key_bytes, password_bytes, 1, 32 bytes) = ServerAuthorization.
  LocalAuthorization uses iterations=2. Whitepaper 100,001 is outdated; code is authoritative.
- master_key: PBKDF2-HMAC-SHA256(password, lower/trim(email), iterations, 32) OR Argon2id(password, SHA256(lower/trim(email)), t, m MiB*1024 KiB, p, out=32).
- type 2: AES-256-CBC(PKCS7) + HMAC-SHA256(mac_key, iv||ct); key split first32=enc last32=mac; MAC verify constant-time before decrypt; string "2.b64iv|b64ct|b64mac".
- type 0: AES-256-CBC only, key first 32 bytes; string "0.b64iv|b64ct". New SDK rejects type 0 under 64-byte key (downgrade prevention).
- type 1: legacy AES-128-CBC + HMAC-SHA256; bitwarden-crypto 0.5.0 uses key[0..16] enc + key[16..32] mac for 32-byte keys.
- RSA: OAEP-SHA1 (rsa::Oaep::<Sha1>); RSA ciphertext serialized as "4.<b64>" (UnsignedSharedKey::Rsa2048_OaepSha1_B64).
- Official e2e vectors: test@example.com/test_password/600k auth hash Lyry95vlXEJ5FE0EXjeR9zgcsFSU0qGhP9l5X2jwE38=; TEST_USER_KEY 2.Q/2PhzcC7GdeiMHhWguYAQ==|...; legacy 0.8UClLa8IPE1iZT7chy5wzQ==|...; stretch 1f4f68e2... -> enc 6f1fb22d.../mac dd7fceea...; AE vector key 0..63 iv d8da2400... ct eacd100f... mac 3c4e2c6f...; decryptable vectors key sJnO8rVi... -> [1,2,3,4,5] and "Hello, World!".
