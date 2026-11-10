#!/usr/bin/env bash
# Item key 層 e2e（官方形態種子 × 跨實作 round-trip）。
# 背景：官方客戶端每筆 cipher 自帶 item key（`key` 欄＝user/org key 包的
# 64B 對稱鑰），name/帳密等內容欄全部 item-key 加密。本腳本用 Python
# （cryptography 庫，獨立於 bw-crypto 的「官方代理」實作）直接以官方演算法
# POST 帶 item key 的項目 → daemon sync 後必須讀得到一切（名稱/帳密/搜尋/
# FTS/TOTP）；daemon 編輯後官方代理再從 VW 讀回、以**原 item key** 解出新
# 密碼（證明我們沒寫壞金鑰層）；daemon 新建的項目必須自帶 key 欄且官方代理
# 解得開（新建走官方形態）。
# 用法：dev/e2e/itemkey.sh（需要 docker）
set -euo pipefail
cd "$(dirname "$0")/../.."

VW_NAME=bitward-vw-itemkey
VW_PORT=18098
SRV="http://127.0.0.1:$VW_PORT"
DATA=dev/e2e/data-itemkey
SOCK="$DATA/daemon.sock"
WP="ItemKey-Master-9f3Kq!x"
EMAIL="e2e-ik-$(date +%s)@bitward.test"
SEED_NAME="Item Key GitHub"
SEED_USER="ik-user"
SEED_PW="IkSeed-Pw-42!"
NEW_PW="IkEdited-Pw-7z!"
CLI_NAME="CLI 官方形態新項目"
CLI_PW="IkCli-Pw-5x!"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'
DAEMON_PID=""

cleanup() {
  kill "$DAEMON_PID" 2>/dev/null || true
  docker rm -f "$VW_NAME" >/dev/null 2>&1 || true
  rm -rf "$DATA"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

command -v docker >/dev/null || fail "需要 docker"
command -v jq >/dev/null || fail "需要 jq"
python3 -c "import cryptography" 2>/dev/null || fail "需要 python3 cryptography（官方代理）"

cargo build -q -p bitwarderd -p bitward

docker rm -f "$VW_NAME" >/dev/null 2>&1 || true
docker run -d --name "$VW_NAME" -p $VW_PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --max-time 3 "$SRV/alive" >/dev/null || fail "Vaultwarden 未在 30 秒內就緒"

# —— 官方代理（獨立跨實作：Python cryptography 復現 type-2 信封布線）——
mkdir -p "$DATA"
cat > "$DATA/official.py" <<'PY'
"""Bitwarden 官方代理（item key 形態），獨立於 bw-crypto 的第二實作。

信封佈線對照 bitwarden-crypto 線式（同 crates/bw-crypto/src/envelope.rs）：
`2.b64(iv)|b64(ct)|b64(mac)`，enc＝AES-256-CBC(PKCS#7) 用 key[0:32]、
mac＝HMAC-SHA256(key[32:64], iv‖ct)（Encrypt-then-MAC）。
item key＝64B composite；cipher.key 欄＝user key 包它的信封、內容欄以它加密。
subcommands：register / seed / verify。
"""
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request
from cryptography.hazmat.primitives import hashes, hmac as c_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

b64 = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

SERVER = sys.argv[2]
EMAIL = sys.argv[3]
PW = sys.argv[4]


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


def master_key():
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=EMAIL.lower().strip().encode(),
                      iterations=600_000).derive(PW.encode())


def stretch(mk):  # HKDF-SHA256 expand-only：T(1)=HMAC(mk, info‖0x01)
    out = b""
    for info in (b"enc", b"mac"):
        h = c_hmac.HMAC(mk, hashes.SHA256()); h.update(info + b"\x01"); out += h.finalize()
    return out


def pw_hash(mk):  # PBKDF2(password=mk, salt=pw, 1, 32)——bw-crypto::hash_purpose 同式
    return b64(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                          salt=PW.encode(), iterations=1).derive(mk))


def pkcs7(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def enc_sym(key, data):
    ek, mac_k = key[:32], key[32:64]
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = c.update(pkcs7(data)) + c.finalize()
    h = c_hmac.HMAC(mac_k, hashes.SHA256()); h.update(iv + ct)
    return f"2.{b64(iv)}|{b64(ct)}|{b64(h.finalize())}"


def dec_sym(key, s):
    assert s.startswith("2."), f"非 type-2 信封：{s[:8]}"
    iv, ct, mac = (b64d(p) for p in s[2:].split("|"))
    ek, mac_k = key[:32], key[32:64]
    h = c_hmac.HMAC(mac_k, hashes.SHA256())
    h.update(iv + ct)
    assert h.verify(mac) is None, "HMAC 不符（金鑰錯誤或被篡改）"
    d = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    n = pt[-1]
    assert 1 <= n <= 16, "PKCS#7 padding 非法"
    return pt[:-n]


def register():
    mk = master_key()
    uk = os.urandom(64)
    p = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = p.private_bytes(serialization.Encoding.DER,
                          serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pem = p.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    body = {"email": EMAIL, "name": "E2E ItemKey", "key": enc_sym(stretch(mk), uk),
            "masterPasswordHash": pw_hash(mk), "kdf": 0, "kdfIterations": 600_000,
            "kdfMemory": None, "kdfParallelism": None,
            "keys": {"publicKey": pem, "encryptedPrivateKey": enc_sym(uk, der)}}
    st, resp = http("POST", f"{SERVER}/identity/accounts/register", body)
    if st == 404:
        st, resp = http("POST", f"{SERVER}/accounts/register", body)
    assert st == 200, f"register {EMAIL}: {st} {resp}"


def login():
    mk = master_key()
    form = urllib.parse.urlencode({
        "grant_type": "password", "username": EMAIL, "password": pw_hash(mk),
        "scope": "api offline_access", "client_id": "mobile",
        "deviceIdentifier": f"itemkey-{EMAIL}", "deviceName": "itemkey", "deviceType": "7"})
    st, resp = http("POST", f"{SERVER}/identity/connect/token", form)
    if st == 404:
        st, resp = http("POST", f"{SERVER}/connect/token", form)
    assert st == 200, f"login {EMAIL}: {st} {resp}"
    tok = json.loads(resp)["access_token"]
    # protected user key 從 /api/accounts/profile 取（官方 Key 欄），以 stretch(mk) 解包
    st, prof = http("GET", f"{SERVER}/api/accounts/profile", headers={"Authorization": f"Bearer {tok}"})
    assert st == 200, f"profile: {st} {prof}"
    uk = dec_sym(stretch(mk), json.loads(prof)["key"])
    return tok, uk


def api(tok, method, path, body=None):
    st, resp = http(method, f"{SERVER}/api/{path}", body, {"Authorization": f"Bearer {tok}"})
    assert st in (200, 201), f"{method} {path}: {st} {resp}"
    return json.loads(resp) if resp else {}


cmd = sys.argv[1]
if cmd == "register":
    register()
elif cmd == "seed":
    tok, uk = login()
    ik = os.urandom(64)
    cipher = api(tok, "POST", "ciphers", {
        "type": 1, "name": enc_sym(ik, b"Item Key GitHub"), "folderId": None,
        "organizationId": None, "collectionIds": [], "favorite": False,
        "key": enc_sym(uk, ik),
        "login": {"username": enc_sym(ik, b"ik-user"),
                  "password": enc_sym(ik, b"IkSeed-Pw-42!"),
                  "totp": enc_sym(ik, b"JBSWY3DPEHPK3PXP"),
                  "uris": [{"uri": enc_sym(ik, b"https://ik.example.dev"), "match": None}]}})
    print(json.dumps({"id": cipher["id"], "ik": b64(ik)}))
elif cmd == "verify":
    cid, expect_ik_b64, want_name, want_user, want_pw = sys.argv[5:10]
    tok, uk = login()
    w = api(tok, "GET", f"ciphers/{cid}")
    assert w.get("key"), f"cipher {cid} 缺 key 欄（官方形態也、新建也該自帶）"
    got_ik = dec_sym(uk, w["key"])
    assert len(got_ik) == 64, f"item key 非 64B composite（{len(got_ik)}）"
    if expect_ik_b64 != "-":
        assert got_ik == b64d(expect_ik_b64), "編輯後 item key 被輪換/改包（金鑰層寫壞）"
    assert dec_sym(got_ik, w["name"]).decode() == want_name, "name 經 item key 解不符"
    assert dec_sym(got_ik, w["login"]["username"]).decode() == want_user, "username 解不符"
    assert dec_sym(got_ik, w["login"]["password"]).decode() == want_pw, "password 解不符"
    print("VERIFY OK")
else:
    raise SystemExit(f"unknown cmd {cmd}")
PY

OFFICIAL() { python3 "$DATA/official.py" "$@"; }

echo "—— 官方代理註冊＋item key 種子 ——（$EMAIL）"
OFFICIAL register "$SRV" "$EMAIL" "$WP"
SEED_JSON=$(OFFICIAL seed "$SRV" "$EMAIL" "$WP")
CID=$(jq -r .id <<<"$SEED_JSON")
IK=$(jq -r .ik <<<"$SEED_JSON")
pass "官方代理 POST 帶 item key 的項目 $CID"

# —— daemon 登入收庫 ——
./target/debug/bitwarderd --data-dir "$DATA" --sock "$SOCK" >>"$DATA/log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 20); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
[[ -S "$SOCK" ]] || fail "daemon socket 未就緒（見 $DATA/log）"
B() { BITWARD_DATA_DIR="$PWD/$DATA" ./target/debug/bitward --sock "$SOCK" --json "$@"; }
drained() {
  for _ in $(seq 1 60); do [[ "$(B outbox --json | jq "$PENDING")" == "0" ]] && return 0; sleep 1; done
  return 1
}
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
B sync >/dev/null

# 1) 真實官方庫投影：名稱明文（使用者缺陷「每筆都是 (未命名)」的直接回歸）
B ls --json | jq -e --arg id "$CID" --arg n "Item Key GitHub" \
  'any(.meta.id == $id and .meta.name == $n)' >/dev/null \
  || fail "item key 項目名稱未投影出明文（解析器缺 item key 層？）"
pass "官方形態種子：ls 名稱明文"

# 2) reveal：帳密經兩段鏈（user key→item key→欄位）解出
B reveal "$CID" | jq -e --arg pw "$SEED_PW" --arg u "$SEED_USER" \
  '.password == $pw and .username == $u' >/dev/null \
  || fail "reveal 解不出 item-key 加密的帳密"
pass "reveal item key 項目帳密"

# 3) 搜尋：FTS 名稱命中＋明文值索引命中（reindex 走解析器才會有）
B ls --text GitHub --json | jq -e --arg id "$CID" 'any(.meta.id == $id)' >/dev/null \
  || fail "FTS 名稱索引未命中"
B ls --value "$SEED_PW" --json | jq -e --arg id "$CID" 'any(.meta.id == $id)' >/dev/null \
  || fail "密碼明文索引未命中"
pass "搜尋（FTS 名稱＋值索引）命中"

# 4) TOTP seed 以 item key 加密：現算 6 位碼
CODE=$(B totp "$CID" | jq -r '.code // .')
[[ "$CODE" =~ ^[0-9]{6}$ ]] || fail "item key 項目 TOTP 解不出（got $CODE）"
pass "TOTP seed item-key 解密現算 $CODE"

# 5) 編輯（改 password）→ 推送收斂 → 官方代理以**原 item key** 解 VW 讀回：
#    key 欄未被改包、新密碼＝item key 加密（我們沒寫壞金鑰層）。
B edit "$CID" --set password="$NEW_PW" >/dev/null
drained || fail "編輯未收斂（outbox 未清）"
OFFICIAL verify "$SRV" "$EMAIL" "$WP" "$CID" "$IK" "Item Key GitHub" "$SEED_USER" "$NEW_PW" >/dev/null \
  || fail "官方代理讀回驗證失敗（編輯寫壞 item key 層？）"
B reveal "$CID" | jq -e --arg pw "$NEW_PW" '.password == $pw' >/dev/null \
  || fail "編輯後本端讀不回新密碼"
pass "跨實作 round-trip：daemon 編輯 → 官方代理以原 item key 解出新密碼"

# 6) 新建＝官方形態：daemon new 出的項目自帶 key 欄、欄位 item-key 加密、
#    官方代理解得開。
echo "$CLI_PW" | B new --name "$CLI_NAME" --username cli-u --password-stdin \
  --uri https://cli.example.dev >/dev/null
drained || fail "新建未收斂（outbox 未清）"
CID2=$(B ls --json | jq -r --arg n "$CLI_NAME" '.[] | select(.meta.name == $n) | .meta.id')
[[ -n "$CID2" && "$CID2" != "null" ]] || fail "新建項目本端讀不到名稱"
OFFICIAL verify "$SRV" "$EMAIL" "$WP" "$CID2" "-" "$CLI_NAME" "cli-u" "$CLI_PW" >/dev/null \
  || fail "新建項目官方代理驗證失敗（key 欄缺失或欄位未用 item key 加密？）"
pass "新建自帶 item key 欄且官方代理可解（雙原生）"

echo "ITEMKEY E2E: ALL PASS"
