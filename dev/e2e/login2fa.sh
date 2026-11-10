#!/usr/bin/env bash
# 登入第二因子 e2e（批次 8b）：真 VW＋Authenticator(TOTP) 2FA，
# CLI 與 GUI 各走兩步登入並斷言入庫（status Unlocked＋items 非空）。
# 2FA 用 VW API 開啟（get-authenticator→authenticator，同 bw-server e2e 路徑），
# 不動 demo daemon／bitward-vw-demo（自起 bitward-vw-2fa 容器＋獨立埠 18097）。
# 用法：dev/e2e/login2fa.sh [GUI 截圖輸出目錄]
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-2fa
PORT=18097
SRV="http://127.0.0.1:$PORT"
WP='Login2FA-Mq7$x!'
EMAIL="login2fa-$(date +%s)@bitward.test"
OUT=${1:-$PWD/apps/bitward-gui}
DAC=/tmp/bitward-2fa-cli
DAG=/tmp/bitward-2fa-gui

command -v docker >/dev/null || { echo "FAIL: 需要 docker"; exit 1; }
command -v python3 >/dev/null || { echo "FAIL: 需要 python3"; exit 1; }
command -v jq >/dev/null || { echo "FAIL: 需要 jq"; exit 1; }
cargo build -q -p bitwarderd -p bitward

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cleanup() {
  docker rm -f "$VW" >/dev/null 2>&1 || true
  pkill -f "bitwarderd --data-dir $DAC" 2>/dev/null || true
  pkill -f "bitwarderd --data-dir $DAG" 2>/dev/null || true
}
trap cleanup EXIT

start_daemon() { # $1=dir
  pkill -f "bitwarderd --data-dir $1" 2>/dev/null || true
  sleep 0.3
  rm -rf "$1" && mkdir -p "$1"
  nohup ./target/debug/bitwarderd --data-dir "$1" --sock "$1/s" >"$1/log" 2>&1 &
  for _ in $(seq 1 20); do [[ -S "$1/s" ]] && return; sleep 0.2; done
  fail "daemon 未起（$1）"
}

docker rm -f "$VW" >/dev/null 2>&1 || true
docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --max-time 3 "$SRV/alive" >/dev/null || fail "VW 未就緒"

# ── 帳號與種子（2FA 尚未開啟）─────────────────────────────────
start_daemon "$DAC"
B() { BITWARD_DATA_DIR="$DAC" ./target/debug/bitward --sock "$DAC/s" "$@"; }
echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B dev-seed --name 2fa-item --uri https://2fa.example.com --password seedme >/dev/null
B sync >/dev/null
[[ "$(B status --json | jq '.items')" == "1" ]] || fail "前提：種子後 items 應為 1"

# ── 開 Authenticator 2FA（同 bw-server e2e 的 API 路徑）────────
SECRET=$(SRV="$SRV" EMAIL="$EMAIL" WP="$WP" python3 - <<'PY'
import base64, hashlib, hmac, json, os, struct, time, urllib.parse, urllib.request
base, email, pw = os.environ["SRV"], os.environ["EMAIL"], os.environ["WP"]
def post(path, body=None, form=None, tok=None):
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        data = json.dumps(body).encode()
        hdr = {"Content-Type": "application/json"}
        if tok:
            hdr["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(base + path, data, hdr)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())
pre = post("/identity/accounts/prelogin", {"email": email})
assert pre.get("kdf", 0) == 0, "e2e 只測 PBKDF2"
dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), email.encode(), pre["kdfIterations"])
# 同 bw-crypto::kdf::hash_purpose：hash=PBKDF2(mk, pw, 1, 32)→b64（不含 pw 後綴）。
h = hashlib.pbkdf2_hmac("sha256", dk, pw.encode(), 1)
mph = base64.b64encode(h).decode()
def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    c = int(time.time() // 30)
    h = hmac.new(key, struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    bin = ((h[o] & 0x7F) << 24 | h[o+1] << 16 | h[o+2] << 8 | h[o+3]) % 10**6
    return f"{bin:06d}"
tok = post("/identity/connect/token", form={
    "grant_type": "password", "username": email, "password": mph,
    "scope": "api offline_access", "client_id": "web",
    "deviceIdentifier": "e2e-2fa-setup", "deviceName": "e2e-2fa-setup", "deviceType": "12"})
auth = post("/api/two-factor/get-authenticator", {"masterPasswordHash": mph}, tok=tok["access_token"])
secret = auth["key"]
# 啟用本身消耗當窗口的碼：後續登入回合必須落在「之後的窗口」（VW 不收已用代碼）。
post("/api/two-factor/authenticator",
     {"key": secret, "token": totp(secret), "masterPasswordHash": mph}, tok=tok["access_token"])
print(secret)
PY
) || fail "開 2FA 失敗"
[[ -n "$SECRET" ]] || fail "拿不到 TOTP secret"
pass "Authenticator 2FA 已啟用（帳號 $EMAIL）"

# ── CLI 兩步登入 ─────────────────────────────────────────────
B sign-out >/dev/null
B status --json | jq -e '.state == "SignedOut"' >/dev/null || fail "前提：sign-out 後應 SignedOut"
# 越到下一個 30s 窗口再取碼（啟用已吃掉舊窗口）。
sleep $(( 31 - $(date +%s) % 30 ))
CODE=$(python3 -c "
import base64,hmac,hashlib,struct,time
key=base64.b32decode('$SECRET'+'='*(-len('$SECRET')%8))
c=int(time.time()//30)
h=hmac.new(key,struct.pack('>Q',c),hashlib.sha1).digest()
o=h[-1]&0x0F
print('%06d'%(((h[o]&0x7F)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%10**6))")
LOGIN_JSON=$(printf '%s\n0\n%s\n' "$WP" "$CODE" | B --json login \
  --server "$SRV" --email "$EMAIL" --password-stdin)
echo "$LOGIN_JSON" | jq -e '.state.Unlocked' >/dev/null \
  || fail "CLI 2FA 登入未進解鎖態：$LOGIN_JSON"
[[ "$(echo "$LOGIN_JSON" | jq '.items')" -ge 1 ]] || fail "CLI 2FA 登入後 items<1"
pass "CLI 兩步登入入庫（Unlocked、items=$(echo "$LOGIN_JSON" | jq '.items')）"

# 錯碼路徑：解鎖態先退回 SignedOut，再餵 000000＋下一窗真碼不給（只測拒絕面）。
B sign-out >/dev/null
if printf '%s\n0\n%s\n' "$WP" "000000" | B --json login --server "$SRV" --email "$EMAIL" --password-stdin >/tmp/bitward-2fa-bad.out 2>&1; then
  fail "錯碼竟登入成功"
fi
grep -qi "Invalid TOTP\|第二因子\|two.factor" /tmp/bitward-2fa-bad.out \
  || fail "錯碼錯誤不可懂：$(cat /tmp/bitward-2fa-bad.out)"
pass "錯碼被拒且錯誤可懂"

# ── GUI 兩步登入（NSH_GUI_SHOTS_LOGIN2FA）─────────────────────
start_daemon "$DAG"
rm -f "$OUT"/shot-4[89]-*2fa*.png
sleep $(( 31 - $(date +%s) % 30 ))
set +e
(cd apps/bitward-gui && NSH_GUI_SHOTS="$OUT" NSH_GUI_SHOTS_LOGIN2FA=1 \
BW_TEST_SERVER="$SRV" BW_TEST_EMAIL="$EMAIL" BW_TEST_PASSWORD="$WP" \
BW_TEST_TOTP_SECRET="$SECRET" \
BITWARD_GUI_SOCK="$DAG/s" nsh run --target macos)
RC=$?
set -e
for n in 48-login-2fa-step 49-vault-after-2fa; do
  [[ -f "$OUT/shot-$n.png" ]] || fail "缺 shot-$n.png（nsh exit $RC）"
done
[[ "$RC" == "0" ]] || fail "nsh exit $RC"
BITWARD_DATA_DIR="$DAG" ./target/debug/bitward --sock "$DAG/s" --json status \
  | jq -e '.state.Unlocked' >/dev/null || fail "GUI 2FA 登入後 daemon 非 Unlocked"
G_ITEMS=$(BITWARD_DATA_DIR="$DAG" ./target/debug/bitward --sock "$DAG/s" --json status | jq '.items')
[[ "$G_ITEMS" -ge 1 ]] || fail "GUI 2FA 登入後 items<1"
pass "GUI 兩步登入入庫（shot-48/49、Unlocked、items=$G_ITEMS）"

echo "LOGIN2FA: ALL PASS（帳號 $EMAIL）"
