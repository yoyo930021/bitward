#!/usr/bin/env bash
# P1 read-path e2e（契約 §6）。斷言 A2/A3/A4/A5/A6/A8/A11。
# 用法：dev/e2e/readpath.sh（需要 docker；A1/A2b 在 cargo test，A10 在 arena 單元測試）
set -euo pipefail
cd "$(dirname "$0")/../.."

VW_NAME=bitward-vw-readpath
VW_PORT=18081
DATA=dev/e2e/data
WP="E2eMaster-9f3Kq!x"
SEED_SECRET="Sup3r-S3cret-V4lue-42"
EMAIL="e2e-$(date +%s)@bitward.test"
export BITWARD_DATA_DIR="$PWD/$DATA"

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  docker rm -f "$VW_NAME" >/dev/null 2>&1 || true
  rm -rf "$DATA"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward

docker run -d --name "$VW_NAME" -p $VW_PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=50 \
  vaultwarden/server:1.37.2 >/dev/null
READY=0
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$VW_PORT/alive" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "Vaultwarden 未在 30 秒內就緒"

SOCK="$DATA/daemon.sock"
mkdir -p "$DATA"
./target/debug/bitwarderd --data-dir "$DATA" --sock "$SOCK" &
DAEMON_PID=$!
for i in $(seq 1 20); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
B() { ./target/debug/bitward --sock "$SOCK" "$@"; }

echo "$WP" | B --json dev-register --server "http://127.0.0.1:$VW_PORT" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "http://127.0.0.1:$VW_PORT" --email "$EMAIL" --password-stdin >/dev/null
B sync >/dev/null
echo "$WP" | B dev-seed --name github --uri https://github.com --password "$SEED_SECRET" >/dev/null
B sync >/dev/null

# A2：ls 筆數等於伺服器 ciphers 數
N_CLI=$(B ls --json | jq 'length')
# 直接問伺服器（用 daemon 鏡像數當代理：status.items）
N_SRV=$(B status --json | jq '.items')
[[ "$N_CLI" == "$N_SRV" && "$N_CLI" == "1" ]] || fail "A2 ls=$N_CLI srv=$N_SRV"
pass "A2 round-trip 筆數一致（$N_CLI）"

# A3：ls --json 的物件鍵集合無 password/username/totp/notes
B ls --json | jq -e 'all(has("password") | not) and all(has("username") | not)' >/dev/null \
  || fail "A3 metadata 洩漏機密鍵"
B ls --json | jq -e '[.[].meta | keys] | flatten | unique | . as $k | (["password","totp","notes"] | any(. as $b | $k | index($b))) | not' >/dev/null \
  || fail "A3 meta 內含機密鍵"
pass "A3 metadata-only 輸出"

# A4：盤上無主密碼與機密值明文
grep -a "$WP" "$DATA/vault.db" && fail "A4 主密碼明文落盤" || true
grep -a "$SEED_SECRET" "$DATA/vault.db" && fail "A4 機密值明文落盤" || true
grep -ra "$SEED_SECRET" "$DATA/keys" && fail "A4 keys 目錄含機密值" || true
pass "A4 盤上無明文"

# A5：冷 ls p95 < 50ms（50 次取分位）
TIMES=()
for _ in $(seq 1 50); do
  s=$(python3 -c 'import time;print(time.time_ns())')
  B ls --json >/dev/null
  e=$(python3 -c 'import time;print(time.time_ns())')
  TIMES+=( $(( (e - s) / 1000000 )) )
done
P95=$(printf '%s\n' "${TIMES[@]}" | sort -n | sed -n '48p')
[[ "$P95" -lt 50 ]] || fail "A5 p95=${P95}ms >= 50ms"
pass "A5 p95=${P95}ms（<50ms）"

# A6：雙 session 併存不互毀；lock 後舊 token StaleEpoch
cp "$DATA/cli_session" "$DATA/session_a"
rm -f "$DATA/cli_session"          # 第二次指令另開新 session
B unlock >/dev/null                # session B（冪等：已解鎖不该撤銷 A）
cp "$DATA/cli_session" "$DATA/session_b"
A_OUT=$(./target/debug/bitward --sock "$SOCK" --json ls 2>&1 </dev/null || true)   # 用 cli_session(=B)
[[ "$A_OUT" != *"stale"* && "$A_OUT" != *"StaleEpoch"* ]] || fail "A6 unlock 互毀"
B lock >/dev/null
mv "$DATA/session_a" "$DATA/cli_session"
B ls >/dev/null 2>&1 && fail "A6 lock 後舊 session 仍可用" || true
STALE_OUT=$(B ls 2>&1 || true)   # 先捕獲：pipefail + grep -q 的 SIGPIPE 會誤報
echo "$STALE_OUT" | grep -qiE 'stale|世代失效' || fail "A6 未回 StaleEpoch 語意"
pass "A6 unlock 冪等 + lock 級聯 StaleEpoch"

# A8：每個 Call 都落 audit 且 hash 鏈可驗證
rm -f "$DATA/cli_session"   # A6 用過的 token 已被 lock 撤銷，取新 session
B unlock >/dev/null
CHAIN=$(B audit --verify --json | jq -r '.ok')
[[ "$CHAIN" == "true" ]] || fail "A8 audit 鏈驗證失敗"
N_CALLS=$(B audit --tail 1000 --json | jq 'length')
[[ "$N_CALLS" -ge 10 ]] || fail "A8 audit 筆數過少（$N_CALLS）"
pass "A8 全 Call 審計 + hash 鏈 ok（$N_CALLS 筆）"

# A11：ps 與 daemon 環境不含主密碼
ps -axo command | grep -v grep | grep -q "$WP" && fail "A11 argv 洩漏主密碼" || true
DAEMON_ENV=$(ps -E -p "$DAEMON_PID" -o command= 2>/dev/null || true)
echo "$DAEMON_ENV" | grep -q "$WP" && fail "A11 daemon env 洩漏" || true
pass "A11 argv/env 無密碼"

echo "READPATH E2E: ALL PASS"
