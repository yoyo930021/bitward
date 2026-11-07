#!/usr/bin/env bash
# 切片 A e2e：改主密碼全鏈（CLI→daemon→VW `POST /accounts/password`）。
# 斷言：1 錯誤 current 拒且本地金鑰未變；2 改密後新密碼可用、舊密碼失效；
# 3 VW 端收斂（token 已隨 stamp reset 換新：sync 200、既有 cipher 仍可 reveal）；
# 4 太短新密碼被強度閘擋下；5 argv/env 無密碼（A11）；6 audit 落筆且 JSON 無明文。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-pwchange
PORT=18111
DA=dev/e2e/data-pwchange
WP="PwOld-Master-9f3K"
NEW="PwNew-Master-7xQ2"
SEED_SECRET="Sup3r-S3cret-V4lue-42"
EMAIL="pwchg-$(date +%s)@bitward.test"
SRV="http://127.0.0.1:$PORT"
export BITWARD_DATA_DIR="$PWD/$DA"

cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; tail -12 "$DA/log" 2>/dev/null || true; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1
docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
READY=0
for _ in $(seq 1 30); do
  if curl -fsS "$SRV/alive" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "Vaultwarden 未在 30 秒內就緒"
mkdir -p "$DA"
./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >>"$DA/log" 2>&1 & PID=$!
for _ in $(seq 1 40); do [[ -S "$DA/s" ]] && break; sleep 0.25; done
[[ -S "$DA/s" ]] || fail "daemon 沒起來（見 $DA/log）"
B() { "$PWD/target/debug/bitward" --sock "$DA/s" "$@"; }

echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B dev-seed --name pwgh --uri https://pwgh.example.com --password "$SEED_SECRET" >/dev/null
B sync >/dev/null

# 斷言 1：錯誤 current → 拒（400 原文進断言），本地金鑰未變（舊密碼仍可登入）
CHG_ERR=$(printf 'WrongCurrent-Pw1\n%s\n' "$NEW" | B change-password 2>&1 >/dev/null || true)
[[ "$CHG_ERR" == *"現有密碼不正確"* ]] \
  || fail "斷言 1：錯誤 current 應被拒並帶原因，got: $CHG_ERR"
echo "$CHG_ERR" | grep -q "$WP" && fail "斷言 1：錯誤訊息洩漏主密碼明文" || true
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null \
  || fail "斷言 1：被拒改密後舊密碼應仍可登入（本地/遠端金鑰未變）"
pass "斷言 1：錯誤 current 拒＋本地金鑰未變"

# 斷言 4：太短新密碼（≥12 閘）→ daemon 拒，未碰遠端
SHORT_ERR=$(printf '%s\nTiny-1\n' "$WP" | B change-password 2>&1 >/dev/null || true)
[[ "$SHORT_ERR" == *"太短"* && "$SHORT_ERR" == *"12"* ]] \
  || fail "斷言 4：太短新密碼應被強度閘拒（帶 12 字元提示），got: $SHORT_ERR"
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null \
  || fail "斷言 4：短碼拒後舊密碼應仍有效"
pass "斷言 4：強度閘（新密碼 <12 字元）拒下"

# 斷言 2：正確改密 → 成功行；冪等重跑（current==new）收斂為 no-op OK
if ! CHG_OUT=$(printf '%s\n%s\n' "$WP" "$NEW" | B change-password 2>&1); then
  fail "斷言 2：正確改密失敗: $CHG_OUT"
fi
[[ "$CHG_OUT" == *"主密碼已變更"* ]] || fail "斷言 2：成功應回繁中一行，got: $CHG_OUT"
printf '%s\n%s\n' "$NEW" "$NEW" | B change-password >/dev/null \
  || fail "斷言 2：current==new 應為 no-op 成功（冪等）"
pass "斷言 2a：改密成功＋no-op 冪等"

# 斷言 3：VW 端收斂——改密 reset security stamp，daemon 必須已換新 token；
# sync 200 且既有 cipher 仍可 reveal（user key 鏈沒斷）。
B sync >/dev/null || fail "斷言 3：改密後 sync 失敗（token 未隨 stamp reset 收斂？）"
CID=$(B ls --json | jq -r '.[0].meta.id // empty')
[[ -n "$CID" ]] || fail "斷言 3：改密後列表为空"
[[ "$(B --json reveal "$CID" | jq -r .password)" == "$SEED_SECRET" ]] \
  || fail "斷言 3：改密後 reveal 不符（金鑰鏈斷裂）"
pass "斷言 3：改密後 sync 200＋reveal 收斂"

# 斷言 2b：新密碼解鎖 OK、舊密碼解鎖失敗（密碼解鎖路徑＝login 的
# MasterPassword 材料驗證；DeviceAssertion 封存態另行驗證）
if echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null 2>&1; then
  fail "斷言 2b：改密後舊密碼不應仍可登入"
fi
echo "$NEW" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null \
  || fail "斷言 2b：新密碼登入失敗"
B lock >/dev/null
B unlock >/dev/null || fail "斷言 2b：改密後 lock→unlock（封存金鑰）失敗"
# 本地信封已換新形：account.json 的 protected_user_key 仍是 2. 信封
[[ "$(jq -r .protected_user_key "$DA/account.json" | cut -c1-2)" == "2." ]] \
  || fail "斷言 2b：account.json 的 protected_user_key 不是 2. 信封"
pass "斷言 2b：新密碼可用、舊密碼失效、封存解鎖不受影響"

# 斷言 5（A11）：ps 進程參數與 daemon 環境不含兩段主密碼
ps -axo command | grep -v grep | grep -q "$WP" && fail "斷言 5：argv 洩漏舊主密碼" || true
ps -axo command | grep -v grep | grep -q "$NEW" && fail "斷言 5：argv 洩漏新主密碼" || true
DAEMON_ENV=$(ps -E -p "$PID" -o command= 2>/dev/null || true)
echo "$DAEMON_ENV" | grep -q "$WP" && fail "斷言 5：daemon env 洩漏舊主密碼" || true
echo "$DAEMON_ENV" | grep -q "$NEW" && fail "斷言 5：daemon env 洩漏新主密碼" || true
pass "斷言 5：argv/env 無密碼"

# 斷言 6：audit 有 change-password 筆（1 拒×2＋成功×2＝4 起）、JSON 無明文、鏈可驗
AUDIT=$(B audit --tail 1000 --json)
N=$(echo "$AUDIT" | jq '[.[] | select(.action=="Auth.ChangePassword")] | length')
[[ "$N" -ge 4 ]] || fail "斷言 6：audit 應有 ≥4 筆 Auth.ChangePassword，got $N"
echo "$AUDIT" | grep -q "$WP" && fail "斷言 6：audit JSON 洩漏舊主密碼" || true
echo "$AUDIT" | grep -q "$NEW" && fail "斷言 6：audit JSON 洩漏新主密碼" || true
B audit --verify --json | jq -e '.ok' >/dev/null || fail "斷言 6：audit 鏈驗證失敗"
pass "斷言 6：audit 落筆（$N 筆）且無明文密碼、鏈 ok"

echo "PASSWORDCHANGE E2E: ALL PASS"
