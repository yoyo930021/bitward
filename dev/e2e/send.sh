#!/usr/bin/env bash
# 路線 5 Send（加密分享）e2e：自起 VW＋data-dir。
# 斷言鏈：建文字 Send（含密碼＋max 2）→ List 元資料對 → URL 形態（含 access 片段）
# → 公開端收發 round-trip：接收方以 URL 片段 seed 做官方拉伸鏈（HMAC "bitwarden-send"
#   → HKDF-Expand "send"）派生內容鑰與 PBKDF2 密碼哈希，本地解密還原原文
#   （跨端語意閉環：我們的 send key 對官方接收方正確）→ 401/400/404 三態實錄
#   （缺密／錯密／max 耗盡）→ 檔案 Send 上傳/下載 sha256 閉環 → 鎖態紀律 →
#   離線建立回 Denied 可懂錯誤（無 outbox 誠實標註）→ Remove 收斂 → 審計不落片段。
# 線格式查證全表見 crates/bw-server/NOTES.md（路由 /api/sends*，非 accounts/public）。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-send
VP=18097
DA=dev/e2e/data-send
WP="SendMaster-9zQ!x"
EMAIL="snd-$(date +%s)@bitward.test"
cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; docker rm -f "$VW" >/dev/null 2>&1 || true; rm -rf "$DA"; }
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; [[ -n "${DA:-}" ]] && tail -12 "$DA/log" 2>/dev/null || true; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1
docker run -d --name "$VW" -p $VP:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$VP/alive" >/dev/null 2>&1 && break; sleep 1; done
mkdir -p $DA

export BITWARD_DATA_DIR=$PWD/$DA
./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >$DA/log 2>&1 & PID=$!
sleep 1
B() { "$PWD/target/debug/bitward" --sock "$DA/s" "$@"; }
SRV="http://127.0.0.1:$VP"
echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
pass "login"

# —— 建文字 Send（含密碼＋max 2；--days 1 縮短到期窗避污染其他斷言）——
TXT="Send-e2e-敏感文字-42"
URLTXT=$(echo 'sendpw-1' | B send text "$TXT" --days 1 --password-stdin --max 2)
[[ "$URLTXT" =~ ^http://127\.0\.0\.1:$VP/\#/send/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]{22})$ ]] \
  || fail "URL 形態錯（應 {server}#/send/{accessId}/{b64url seed22 碼}）：$URLTXT"
AID="${BASH_REMATCH[1]}"; SEEDB64="${BASH_REMATCH[2]}"
pass "建立＋URL 形態（accessId＋16B seed 的 b64url 片段）"

# —— List 元資料對（名稱解密投影、max／hasPassword／viewed／URL 與建立一致）——
L=$(B send ls --json)
[[ "$(echo "$L" | jq -r '.items[0].name')" == "$TXT" ]] || fail "name 投影錯：$(echo "$L" | jq -r '.items[0].name')"
[[ "$(echo "$L" | jq -r '.items[0].maxAccessCount')" == "2" ]] || fail "maxAccessCount 投影錯"
[[ "$(echo "$L" | jq -r '.items[0].hasPassword')" == "true" ]] || fail "hasPassword 應 true"
[[ "$(echo "$L" | jq -r '.items[0].viewed')" == "false" ]] || fail "initial viewed 應 false"
[[ "$(echo "$L" | jq -r '.items[0].url')" == "$URLTXT" ]] || fail "清單 URL 與建立不一致"
[[ "$(echo "$L" | jq -r '.items[0].type')" == "0" ]] || fail "type 投影錯"
pass "List 元資料對（含清單 URL 直供複製）"

# —— 公開端收發 round-trip（接收方路徑：無 bearer；官方拉伸鏈獨立實作）——
python3 - "$SRV" "$AID" "$SEEDB64" "$TXT" 'sendpw-1' <<'PY' || fail "公開端 round-trip 敗"
import sys, base64, hmac, hashlib, json, subprocess, urllib.request, urllib.error
base, aid, seedb64, want, pw = sys.argv[1:6]
seed = base64.urlsafe_b64decode(seedb64 + '=' * (-len(seedb64) % 4))
assert len(seed) == 16, f"seed 應 16 bytes，got {len(seed)}"
# 官方 SDK 口徑：password 上線值＝b64(PBKDF2-SHA256(pw, salt=seed, 100_000))
ph = base64.b64encode(hashlib.pbkdf2_hmac('sha256', pw.encode(), seed, 100_000, 32)).decode()
def access(body):
    r = urllib.request.Request(f'{base}/api/sends/access/{aid}',
                               data=json.dumps(body).encode(), method='POST')
    r.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        e.read()
        return e.code, None
c, _ = access({})                       # 有密 Send 未帶密碼
assert c == 401, f"缺密碼應 401，got {c}"
c, _ = access({"password": "nope"})     # 實錄：VW 對照失敗回 400
assert c == 400, f"錯密碼應 400，got {c}"
c, acc = access({"password": ph})
assert c == 200 and acc.get('object') == 'send-access', f"正確哈希應 200，got {c}"
# URL 片段 seed → 官方拉伸（PRK=HMAC("bitwarden-send",seed)；HKDF-Expand info="send"）
prk = hmac.new(b'bitwarden-send', seed, hashlib.sha256).digest()
out, t, i = b'', b'', 1
while len(out) < 64:
    t = hmac.new(prk, t + b'send' + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
enc_k, mac_k = out[:32], out[32:64]
def dec(env):
    ty, rest = env.split('.', 1)
    assert ty == '2', env
    iv, body, mac = (base64.b64decode(x) for x in rest.split('|'))
    assert hmac.new(mac_k, iv + body, hashlib.sha256).digest() == mac, 'MAC 不符'
    p = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-d', '-K', enc_k.hex(),
                        '-iv', iv.hex()], input=body, capture_output=True, check=True)
    return p.stdout.decode()
assert dec(acc['text']['text']) == want, '文字解密不等原'
assert dec(acc['name']) == want, '名稱解密不等原（預設名＝首行文字）'
PY
pass "公開端收發閉環（401/400 實錄＋片段鑰本地解密還原原文）"

# —— max 耗盡實錄：第 2 次存取 200、第 3 次 404；清單計數與 viewed 收斂 ——
PH=$(python3 -c "import base64,hashlib; seed=base64.urlsafe_b64decode('$SEEDB64' + '=' * (-len('$SEEDB64') % 4)); print(base64.b64encode(hashlib.pbkdf2_hmac('sha256', b'sendpw-1', seed, 100000, 32)).decode())")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PH\"}" "$SRV/api/sends/access/$AID")
[[ "$CODE" == "200" ]] || fail "第 2 次存取應 200，got $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PH\"}" "$SRV/api/sends/access/$AID")
[[ "$CODE" == "404" ]] || fail "max 耗盡後應 404（SEND_INACCESSIBLE 實錄），got $CODE"
[[ "$(B send ls --json | jq -r '.items[0].accessCount')" == "2" ]] || fail "清單 accessCount 应收斂 2"
[[ "$(B send ls --json | jq -r '.items[0].viewed')" == "true" ]] || fail "存取後 viewed 應轉 true"
pass "max 耗盡 404 實錄＋清單存取計數/viewed 收斂"

# —— 檔案 Send：上傳/下載 round-trip sha256（v2 兩段＋接收方簽名 URL）——
head -c 20000 /dev/urandom | base64 > "$DA/blob.bin"
SH=$(shasum -a 256 "$DA/blob.bin" | cut -d' ' -f1)
URLF=$(echo 'filepw-9' | B send file "$DA/blob.bin" --days 7 --password-stdin)
[[ "$URLF" =~ ^http://127\.0\.0\.1:$VP/\#/send/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]{22})$ ]] \
  || fail "檔案 Send URL 形態錯：$URLF"
AIDF="${BASH_REMATCH[1]}"; SEEDF="${BASH_REMATCH[2]}"
python3 - "$SRV" "$(jq -r .access_token "$DA/account.json")" "$AIDF" "$SEEDF" "$SH" 'filepw-9' "$DA/blob.bin" <<'PY' || fail "檔案 round-trip 敗"
import sys, base64, hmac, hashlib, json, subprocess, urllib.request
base, tok, aid, seedb64, sha_want, pw, orig = sys.argv[1:8]
seed = base64.urlsafe_b64decode(seedb64 + '=' * (-len(seedb64) % 4))
hb = base64.urlsafe_b64decode(aid + '=' * (-len(aid) % 4)).hex()
sid = f"{hb[0:8]}-{hb[8:12]}-{hb[12:16]}-{hb[16:20]}-{hb[20:32]}"
def get(path, auth=True):
    r = urllib.request.Request(base + path)
    if auth: r.add_header('Authorization', 'Bearer ' + tok)
    return json.loads(urllib.request.urlopen(r, timeout=15).read())
send = get(f'/api/sends/{sid}')
fid = send['file']['id']
ph = base64.b64encode(hashlib.pbkdf2_hmac('sha256', pw.encode(), seed, 100_000, 32)).decode()
r = urllib.request.Request(f'{base}/api/sends/{sid}/access/file/{fid}',
                           data=json.dumps({"password": ph}).encode(), method='POST')
r.add_header('Content-Type', 'application/json')
acc = json.loads(urllib.request.urlopen(r, timeout=15).read())
blob = urllib.request.urlopen(acc['url'], timeout=30).read()
prk = hmac.new(b'bitwarden-send', seed, hashlib.sha256).digest()
out, t, i = b'', b'', 1
while len(out) < 64:
    t = hmac.new(prk, t + b'send' + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
enc_k, mac_k = out[:32], out[32:64]
ty, rest = blob.decode().split('.', 1)
assert ty == '2', blob[:40]
iv, body, mac = (base64.b64decode(x) for x in rest.split('|'))
assert hmac.new(mac_k, iv + body, hashlib.sha256).digest() == mac, '檔身 MAC 不符'
p = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-d', '-K', enc_k.hex(),
                    '-iv', iv.hex()], input=body, capture_output=True, check=True)
assert hashlib.sha256(p.stdout).hexdigest() == sha_want, '解密 sha256 不等原檔'
assert p.stdout == open(orig, 'rb').read(), '解密位元組不等原檔'
# 預設名＝檔名（信封解出後）
name_env = send['name']
iv, body, mac = (base64.b64decode(x) for x in name_env.split('.', 1)[1].split('|'))
assert hmac.new(mac_k, iv + body, hashlib.sha256).digest() == mac
q = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-d', '-K', enc_k.hex(),
                    '-iv', iv.hex()], input=body, capture_output=True, check=True)
assert q.stdout.decode() == 'blob.bin', f"預設名應為檔名，got {q.stdout.decode()}"
PY
pass "檔案 Send 上傳/下載 round-trip sha256 閉環"

# —— 鎖態紀律：清單照回但 name/URL 為 null；建/取 URL 需金鑰 ——
B lock >/dev/null
LS=$(B send ls --json)
[[ "$(echo "$LS" | jq -r '[.items[] | select(.name == null)] | length')" == "$(echo "$LS" | jq -r '.items | length')" ]] \
  || fail "鎖態清單名稱應全 null"
[[ "$(echo "$LS" | jq -r '[.items[] | select(.url != null)] | length')" == "0" ]] || fail "鎖態清單 URL 應全 null"
OUT=$(B send text "鎖態不給建" 2>&1 || true)
[[ "$OUT" == *"未解鎖"* || "$OUT" == *"Locked"* ]] || fail "鎖態建立應回未解鎖，got $OUT"
SID=$(echo "$LS" | jq -r '.items[0].id')
OUT=$(B send url "$SID" 2>&1 || true)
[[ "$OUT" == *"未解鎖"* || "$OUT" == *"Locked"* ]] || fail "鎖態取 URL 應回未解鎖，got $OUT"
B unlock >/dev/null
pass "鎖態紀律（鏡像照回、金鑰操作拒做、解鎖可回）"

# —— 離線建立：無 outbox 誠實標註（VW 停擺 → Denied 可懂錯誤）——
docker stop "$VW" >/dev/null
OUT=$(echo | B send text "離線不假排" --days 1 2>&1 || true)
[[ "$OUT" == *"連網"* || "$OUT" == *"transport"* ]] || fail "離線建立應回可懂連網錯誤，got $OUT"
OUT=$(B send rm "$SID" 2>&1 || true)
[[ "$OUT" == *"連網"* || "$OUT" == *"transport"* ]] || fail "離線刪除應回可懂連網錯誤，got $OUT"
docker start "$VW" >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$VP/alive" >/dev/null 2>&1 && break; sleep 1; done
pass "離線建立/刪除回可懂錯誤（無 outbox 佇列不假排）"

# —— Remove 收斂：鏡像摘列＋伺服器 404 ——
B send rm "$SID" >/dev/null
[[ "$(B send ls --json | jq -r --arg s "$SID" '[.items[].id] | index($s)')" == "null" ]] \
  || fail "Remove 後鏡像仍含該列"
TOK=$(jq -r .access_token "$DA/account.json")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$SRV/api/sends/$SID")
# 實錄：VW 缺列 GET 走 err! 預設＝400 "Send not found"（非 404）；兩態皆「已不存在」
[[ "$CODE" == "404" || "$CODE" == "400" ]] || fail "Remove 後伺服器應 404/400，got $CODE"
# 冪等：再刪一次（已不存在）照收斂回 ok
B send rm "$SID" >/dev/null && pass "Remove 收斂＋404 冪等再刪" || fail "重複刪除應冪等成功"

# —— 審計不落 access 片段（A11 延伸：URL/seed 只進回應不進審計表）——
if B audit | grep -qF "$SEEDF"; then fail "審計潑出 seed 片段"; fi
if B audit | grep -qF "$SEEDB64"; then fail "審計潑出 seed 片段（文字）"; fi
B audit | grep -q "Vault.Send.Create" || fail "審計缺 Send 動作列"
pass "審計不落 access 片段＋動作列在檔"

pass "send.sh 全綠"
