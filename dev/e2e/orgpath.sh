#!/usr/bin/env bash
# P4b org 共享語意讀側 e2e（契約交付 4）：VW 雙帳號全鏈。
# 鏈路：python3 註冊 A/B（含 RSA 金鑰）→ A 建 org（`2.` akey）→ invite B
# （mail 關閉時 VW 自動 Accepted）→ A confirm B（`4.` RSA akey 用 B 公鑰包
# org key）→ A 建 collection 並指派 B → A POST 共享 cipher（org key 加密）+
# 個人 cipher → 兩台 daemon 各自 login+sync。
# 斷言：org/collection 落庫、ls --collection 過濾、owner/成員兩條解密鏈各自
# 解出共享項目明文、metadata 不洩密、個人項目不外洩、collection grant 授權。
# 用法：dev/e2e/orgpath.sh [vaultwarden-url]
#   預設 http://127.0.0.1:18095（demo e2e 共用实例）；不可達時自起容器（CI 路徑）。
#   RECORD_FIXTURES=1 時把 A/B 的真實 /sync 錄進 crates/bw-sync/fixtures/。
set -euo pipefail
cd "$(dirname "$0")/../.."

WP="E2eMaster-9f3Kq!x"
SUFFIX=$(date +%s)
EMAIL_A="e2e-org-a-$SUFFIX@bitward.test"
EMAIL_B="e2e-org-b-$SUFFIX@bitward.test"
SHARED_NAME="E2E Shared Login"
SHARED_PW="Sh@red-Pw-7z!"
PERSONAL_NAME="A Personal Note"
DATA_A=dev/e2e/data/org-a
DATA_B=dev/e2e/data/org-b
VW_NAME=bitward-vw-orgpath
VW_PORT=18097
VW_URL="${1:-http://127.0.0.1:18095}"
OWN_VW=0

cleanup() {
  [[ -n "${DAEMON_A:-}" ]] && kill "$DAEMON_A" 2>/dev/null || true
  [[ -n "${DAEMON_B:-}" ]] && kill "$DAEMON_B" 2>/dev/null || true
  [[ "$OWN_VW" == 1 ]] && docker rm -f "$VW_NAME" >/dev/null 2>&1 || true
  rm -rf "$DATA_A" "$DATA_B"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward

if ! curl -fsS "$VW_URL/alive" >/dev/null 2>&1; then
  docker run -d --name "$VW_NAME" -p $VW_PORT:80 \
    -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
    vaultwarden/server:1.37.2 >/dev/null
  VW_URL="http://127.0.0.1:$VW_PORT"
  OWN_VW=1
  READY=0
  for i in $(seq 1 30); do
    if curl -fsS "$VW_URL/alive" >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
  done
  [[ "$READY" == 1 ]] || fail "Vaultwarden 未在 30 秒內就緒"
fi

# —— REST 全鏈（python3：PBKDF2/HKDF-expand/AES-CBC+HMAC type-2 信封、RSA-OAEP）——
OUT=$(python3 - "$VW_URL" "$EMAIL_A" "$EMAIL_B" "$WP" "$SHARED_PW" <<'PY'
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request
from cryptography.hazmat.primitives import hashes, hmac as c_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

server, email_a, email_b, pw, shared_pw = sys.argv[1:6]
b64 = lambda b: base64.b64encode(b).decode()

def http(method, url, body=None, headers=None):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        else:
            data = body.encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def master_key(email):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=email.lower().strip().encode(), iterations=600_000).derive(pw.encode())

def stretch(mk):  # HKDF-SHA256 expand-only：T(1)=HMAC(mk, info‖0x01)
    out = b""
    for info in (b"enc", b"mac"):
        h = c_hmac.HMAC(mk, hashes.SHA256()); h.update(info + b"\x01"); out += h.finalize()
    return out

def pw_hash(mk):  # 對齊 bw-crypto::hash_purpose：PBKDF2(password=mk, salt=pw, 1, 32)
    return b64(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=pw.encode(), iterations=1).derive(mk))

def pkcs7(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n

def enc_sym(key, data):  # Bitwarden type 2：2.b64iv|b64ct|b64mac（Encrypt-then-MAC）
    ek, mac_k = key[:32], key[32:64]
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = c.update(pkcs7(data)) + c.finalize()
    h = c_hmac.HMAC(mac_k, hashes.SHA256()); h.update(iv + ct)
    return f"2.{b64(iv)}|{b64(ct)}|{b64(h.finalize())}"

def gen_rsa():
    p = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = p.private_bytes(serialization.Encoding.DER,
                          serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pem = p.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return p, der, pem

def register(email):
    mk = master_key(email)
    uk = os.urandom(64)
    _, priv_der, pub_pem = gen_rsa()
    body = {"email": email, "name": "E2E Org User", "key": enc_sym(stretch(mk), uk),
            "masterPasswordHash": pw_hash(mk), "kdf": 0, "kdfIterations": 600_000,
            "kdfMemory": None, "kdfParallelism": None,
            "keys": {"publicKey": pub_pem, "encryptedPrivateKey": enc_sym(uk, priv_der)}}
    st, resp = http("POST", f"{server}/identity/accounts/register", body)
    if st == 404:
        st, resp = http("POST", f"{server}/accounts/register", body)
    assert st == 200, f"register {email}: {st} {resp}"
    return uk

def login(email):
    form = urllib.parse.urlencode({
        "grant_type": "password", "username": email, "password": pw_hash(master_key(email)),
        "scope": "api offline_access", "client_id": "mobile",
        "deviceIdentifier": f"orgpath-{email}", "deviceName": "orgpath", "deviceType": "7"})
    st, resp = http("POST", f"{server}/identity/connect/token", form)
    if st == 404:
        st, resp = http("POST", f"{server}/connect/token", form)
    assert st == 200, f"login {email}: {st} {resp}"
    return json.loads(resp)["access_token"]

def api(tok, method, path, body=None):
    st, resp = http(method, f"{server}/api/{path.lstrip('/')}", body, {"Authorization": f"Bearer {tok}"})
    assert st in (200, 201), f"{method} {path}: {st} {resp}"
    return json.loads(resp) if resp else {}

uk_a = register(email_a); tok_a = login(email_a)
uk_b = register(email_b); tok_b = login(email_b)
# B 的 RSA 公鑰：協定上 A 經 `GET /users/{userId}/public-key` 取得（1.37.2 route）；
# user id 自 B 自己的 /sync profile.id。
profile_b = api(tok_b, "GET", "sync")["profile"]
st, resp = http("GET", f"{server}/api/users/{profile_b['id']}/public-key", headers={"Authorization": f"Bearer {tok_a}"})
assert st == 200, f"public-key: {st} {resp}"
pub_b_pem = json.loads(resp)["publicKey"]

# A 建 org：org 對稱金鑰 K 以 A 的 user key 包裝（owner `2.` akey）
K = os.urandom(64)
_, org_priv_der, org_pub_pem = gen_rsa()
org = api(tok_a, "POST", "organizations", {
    "name": "E2E Org", "billingEmail": email_a, "key": enc_sym(uk_a, K),
    "collectionName": enc_sym(uk_a, b"Default Collection"), "planType": "enterprise",
    "keys": {"publicKey": org_pub_pem, "encryptedPrivateKey": enc_sym(uk_a, org_priv_der)}})
org_id = org["id"]

# invite B（mail 關閉 + 已註冊 → vaultwarden 直接 Accepted），再以 B 公鑰包 K confirm
api(tok_a, "POST", f"organizations/{org_id}/users/invite",
    {"emails": [email_b], "groups": [], "type": 2, "collections": [], "permissions": {}})
users = api(tok_a, "GET", f"organizations/{org_id}/users")["data"]
member = next(u for u in users if u["email"] == email_b)
assert member["status"] == 1, f"預期 invite 後自動 Accepted，實際 status={member['status']}"
pub_b = serialization.load_pem_public_key(pub_b_pem.encode())
akey_b = "4." + b64(pub_b.encrypt(K, asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)))
api(tok_a, "POST", f"organizations/{org_id}/users/confirm",
    {"keys": [{"id": member["id"], "key": akey_b}]})
users = api(tok_a, "GET", f"organizations/{org_id}/users")["data"]
member = next(u for u in users if u["email"] == email_b)
assert member["status"] == 2, f"confirm 後應 Confirmed，實際 status={member['status']}"

# A 建 collection 指派 B；共享 cipher 欄位以 org key K 加密
coll = api(tok_a, "POST", f"organizations/{org_id}/collections",
           {"name": enc_sym(K, b"E2E Shared Coll"), "externalId": None, "groups": [],
            "users": [{"id": member["id"], "readOnly": False, "hidePasswords": False, "manage": False}]})
coll_id = coll["id"]
cipher = api(tok_a, "POST", "ciphers", {
    "type": 1, "name": enc_sym(K, b"E2E Shared Login"), "folderId": None,
    "organizationId": org_id, "collectionIds": [coll_id], "favorite": False,
    "login": {"username": enc_sym(K, b"shared-user"), "password": enc_sym(K, shared_pw.encode())}})
# vaultwarden 1.37.2 的 POST /ciphers 不吃 collectionIds（建立時 shared_to_collections
# 恆 None）；集合歸屬要另走 PUT /ciphers/{id}/collections_v2（官方 web-vault 同路徑）。
api(tok_a, "PUT", f"ciphers/{cipher['id']}/collections_v2", {"collectionIds": [coll_id]})
personal = api(tok_a, "POST", "ciphers", {
    "type": 1, "name": enc_sym(uk_a, b"A Personal Note"), "folderId": None,
    "organizationId": None, "collectionIds": [], "favorite": False,
    "login": {"username": enc_sym(uk_a, b"a-owner"), "password": enc_sym(uk_a, b"Pw-A-Own-1x!")}})

sync_b = api(tok_b, "GET", "sync")
assert any(c["id"] == cipher["id"] for c in sync_b["ciphers"]), "B 的 /sync 看不到共享 cipher"
assert all(c["id"] != personal["id"] for c in sync_b["ciphers"]), "B 不該看到 A 的個人 cipher"

print(json.dumps({"org": org_id, "collection": coll_id, "cipher": cipher["id"],
                  "personal": personal["id"], "tokenA": tok_a, "tokenB": tok_b}))
PY
) || fail "REST org 全鏈（python3）失敗"
ORG_ID=$(jq -r .org <<<"$OUT")
COLL_ID=$(jq -r .collection <<<"$OUT")
CIPHER_ID=$(jq -r .cipher <<<"$OUT")
PERSONAL_ID=$(jq -r .personal <<<"$OUT")
pass "REST 全鏈：org=$ORG_ID coll=$COLL_ID cipher=$CIPHER_ID"

if [[ "${RECORD_FIXTURES:-0}" == 1 ]]; then
  curl -fsS -H "Authorization: Bearer $(jq -r .tokenA <<<"$OUT")" "$VW_URL/api/sync" \
    > crates/bw-sync/fixtures/sync_org_owner_vw.json
  curl -fsS -H "Authorization: Bearer $(jq -r .tokenB <<<"$OUT")" "$VW_URL/api/sync" \
    > crates/bw-sync/fixtures/sync_org_member_vw.json
  pass "錄製 /sync fixtures → crates/bw-sync/fixtures/sync_org_{owner,member}_vw.json"
fi

mkdir -p "$DATA_A" "$DATA_B"
SOCK_A="$PWD/$DATA_A/daemon.sock"; SOCK_B="$PWD/$DATA_B/daemon.sock"
./target/debug/bitwarderd --data-dir "$DATA_A" --sock "$SOCK_A" &
DAEMON_A=$!
./target/debug/bitwarderd --data-dir "$DATA_B" --sock "$SOCK_B" &
DAEMON_B=$!
for i in $(seq 1 20); do [[ -S "$SOCK_A" && -S "$SOCK_B" ]] && break; sleep 0.2; done
[[ -S "$SOCK_A" && -S "$SOCK_B" ]] || fail "daemon socket 未就緒"
BA() { BITWARD_DATA_DIR="$PWD/$DATA_A" ./target/debug/bitward --sock "$SOCK_A" --json "$@"; }
BB() { BITWARD_DATA_DIR="$PWD/$DATA_B" ./target/debug/bitward --sock "$SOCK_B" --json "$@"; }

echo "$WP" | BA login --server "$VW_URL" --email "$EMAIL_A" --password-stdin >/dev/null
echo "$WP" | BB login --server "$VW_URL" --email "$EMAIL_B" --password-stdin >/dev/null
BA sync >/dev/null; BB sync >/dev/null

# 1. status 顯示 org 數（兩台都應 1）
BA status | jq -e '.orgs == 1' >/dev/null || fail "daemon A status.orgs != 1"
BB status | jq -e '.orgs == 1' >/dev/null || fail "daemon B status.orgs != 1"
pass "status.orgs == 1（A/B）"

# 2. ls --collection 過濾 + org/collection 欄位正確 + 名稱已解密
#    （A：owner `2.` akey 路徑；B：成員 `4.` RSA akey 路徑）
for WHO in A B; do
  eval "LST=\$(B$WHO ls --collection '$COLL_ID')"
  jq -e --arg id "$CIPHER_ID" --arg org "$ORG_ID" --arg col "$COLL_ID" --arg name "$SHARED_NAME" '
    length == 1
    and .[0].meta.id == $id
    and .[0].meta.name == $name
    and .[0].meta.organization_id == $org
    and .[0].meta.collections == [$col]
  ' <<<"$LST" >/dev/null || fail "$WHO ls --collection 斷言失敗：$LST"
  pass "$WHO daemon 按 collection 過濾可見共享項目（名稱已走 org key 解密）"
done

# 3. 共享項目 secret 視窗：兩端 reveal 都拿得到 org key 加密的密碼
BA reveal "$CIPHER_ID" | jq -e --arg pw "$SHARED_PW" '.password == $pw and .username == "shared-user"' >/dev/null \
  || fail "A reveal 共享項目密碼不符"
BB reveal "$CIPHER_ID" | jq -e --arg pw "$SHARED_PW" '.password == $pw' >/dev/null \
  || fail "B reveal 共享項目密碼不符（成員 RSA 解密鏈）"
pass "reveal 共享項目（owner/成員雙路徑）"

# 4. 個人項目邊界：A 看得到自己的 personal；B 的 vault 只有共享那筆
BA ls | jq -e --arg id "$PERSONAL_ID" 'any(.meta.id == $id)' >/dev/null || fail "A 看不到自己的個人項目"
BB ls | jq -e --arg id "$PERSONAL_ID" 'any(.meta.id == $id) | not' >/dev/null || fail "不該在 B 出現的個人項目出現了"
BB ls | jq -e 'length == 1' >/dev/null || fail "B 鏡像筆數應為 1（僅共享項目）"
pass "個人項目不外洩（B 鏡像僅共享筆）"

# 5. metadata 出口不洩密（A3 同款紀律套在共享項目上）
BB ls --json | jq -e '[.[].meta | keys] | flatten | unique | . as $k
  | (["password","totp","notes"] | any(. as $b | $k | index($b))) | not' >/dev/null \
  || fail "共享項目 metadata 洩漏機密鍵"
BB ls --json | grep -q "$SHARED_PW" && fail "ls metadata 含共享密碼明文" || true
pass "共享項目 metadata-only 輸出無機密"

# 6. 按 collection 授權：agent session 只給 see:identity collection:X
OPEN1=$(BB agent open --name org-agent --grant "see:identity collection:$COLL_ID" --ttl 600)
TOK1=$(jq -r .token <<<"$OPEN1")
OPEN2=$(BB agent open --name other-agent --grant "see:identity collection:00000000-0000-4000-8000-000000000000" --ttl 600)
TOK2=$(jq -r .token <<<"$OPEN2")
printf '%s' "$TOK1" > "$DATA_B/cli_session"
BB get "$CIPHER_ID" | jq -e --arg name "$SHARED_NAME" '.meta.name == $name' >/dev/null \
  || fail "collection grant 的 agent 讀不到共享項目"
BB reveal "$CIPHER_ID" >/dev/null 2>&1 && fail "see:identity grant 竟能 reveal 共享項目" || true
printf '%s' "$TOK2" > "$DATA_B/cli_session"
BB get "$CIPHER_ID" >/dev/null 2>&1 && fail "無關 collection grant 竟能讀共享項目" || true
rm -f "$DATA_B/cli_session"
pass "collection 維度授權（命中放行、floor 與錯集合拒絕）"

# 7. 盤上無主密碼明文（鏡像與 keys 目錄）
grep -a "$WP" "$DATA_A/vault.db" "$DATA_A/vault.db-wal" 2>/dev/null && fail "A vault.db 含主密碼明文" || true
grep -ra "$WP" "$DATA_B/keys" 2>/dev/null && fail "B keys 目錄含主密碼明文" || true
pass "盤上無主密碼明文"

echo "ORGPATH E2E: ALL PASS"
