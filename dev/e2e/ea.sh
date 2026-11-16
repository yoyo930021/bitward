#!/usr/bin/env bash
# 緊急存取（EA）雙帳號 e2e（PR4）：真 VW 1.37.2＋兩台獨立 daemon（grantor/grantee）。
# 全鏈：invite（無 mail 自動 accept）→confirm（RSA-OAEP 派發 user key）→
# initiate→approve→view（外部鑰唯讀投影）→lock 失效→takeover（改主密碼閉環）。
# 自起 bitward-vw-ea 容器（埠 18101）＋獨立 data-dir，絕不碰常駐 demo 域。
# 用法：dev/e2e/ea.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-ea
PORT=18101
SRV="http://127.0.0.1:$PORT"
PWG='Grantor-Pw7$x!'
PWB='Grantee-Pw7$x!'
PWNEW='TakenOver-Pw9$z!'
TS=$(date +%s)
EG="ea-grantor-$TS@bitward.test"
EB="ea-grantee-$TS@bitward.test"
ET="ea-takeover-$TS@bitward.test"
DG=/tmp/bitward-ea-g
DB=/tmp/bitward-ea-b

command -v docker >/dev/null || { echo "FAIL: 需要 docker"; exit 1; }
command -v jq >/dev/null || { echo "FAIL: 需要 jq"; exit 1; }
cargo build -q -p bitwarderd -p bitward

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cleanup() {
  [[ "${EA_KEEP:-}" == "1" ]] && return
  docker rm -f "$VW" >/dev/null 2>&1 || true
  pkill -f "bitwarderd --data-dir $DG" 2>/dev/null || true
  pkill -f "bitwarderd --data-dir $DB" 2>/dev/null || true
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

BG() { BITWARD_DATA_DIR=$DG ./target/debug/bitward --sock "$DG/s" "$@"; }
BB() { BITWARD_DATA_DIR=$DB ./target/debug/bitward --sock "$DB/s" "$@"; }

docker rm -f "$VW" >/dev/null 2>&1 || true
docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --max-time 3 "$SRV/alive" >/dev/null || fail "VW 未就緒"

start_daemon "$DG"
start_daemon "$DB"
echo "$PWG" | BG dev-register --server "$SRV" --email "$EG" --password-stdin >/dev/null
echo "$PWB" | BB dev-register --server "$SRV" --email "$EB" --password-stdin >/dev/null
echo "$PWG" | BG login --server "$SRV" --email "$EG" --password-stdin >/dev/null
echo "$PWB" | BB login --server "$SRV" --email "$EB" --password-stdin >/dev/null
pass "兩帳號註冊並登入（解鎖態；dev-register 帶 RSA keypair）"

# ── C1：grantor 邀請→確認→撤銷 ───────────────────────────────
# 自我邀請必須被伺服器擋下（源檔 send_invite「not set yourself」）。
if BG ea invite "$EG" --type view --days 1 >/dev/null 2>&1; then
  fail "自我邀請應被拒"
fi
pass "自我邀請回可懂錯誤"

BG ea invite "$EB" --type view --days 7 >/dev/null
ST=$(BG ea ls | jq -r '.[0].status')
[[ "$ST" == "Accepted" ]] || fail "VW 無 mail 應對既有帳號自動 accept（實得 $ST）"
pass "邀請落地並自動 Accepted（grantee 清單收斂同態）"
[[ "$(BB ea ls --granted | jq -r '.[0].status')" == "Accepted" ]] \
  || fail "grantee 側清單未見 Accepted"

EAID=$(BG ea ls | jq -r '.[0].id')
BG ea confirm "$EAID" >/dev/null
[[ "$(BG ea ls | jq -r '.[0].status')" == "Confirmed" ]] || fail "grantor 側未收斂 Confirmed"
[[ "$(BB ea ls --granted | jq -r '.[0].status')" == "Confirmed" ]] \
  || fail "grantee 側未收斂 Confirmed"
pass "confirm 閉環：雙方狀態收斂 Confirmed（user key 已 OAEP 派發）"

# 重複邀請同一人應被拒（源檔 already invited 閘）。
if BG ea invite "$EB" --type view --days 1 >/dev/null 2>&1; then
  fail "重複邀請應被拒"
fi
pass "重複邀請回可懂錯誤"

# ── C2：grantee 發起恢復→批准→唯讀檢視（外部鑰投影）──────────
echo "$PWG" | BG dev-seed --name ea-login --uri https://ea.example.com --password s3cr3t-ea >/dev/null
BG sync >/dev/null
BB ea initiate "$EAID" >/dev/null
[[ "$(BG ea ls | jq -r '.[0].status')" == "RecoveryInitiated" ]] \
  || fail "initiate 後 grantor 側應見 RecoveryInitiated"
BG ea approve "$EAID" >/dev/null
[[ "$(BB ea ls --granted | jq -r '.[0].status')" == "RecoveryApproved" ]] \
  || fail "approve 後 grantee 側未收斂 RecoveryApproved"
pass "initiate→approve 狀態收斂"

VIEW_JSON=$(BB --json ea view "$EAID")
echo "$VIEW_JSON" | jq -e '[.[].meta.name] | index("ea-login")' >/dev/null \
  || fail "view 未含 grantor 項目名：$(echo "$VIEW_JSON" | jq -c '[.[].meta.name]')"
echo "$VIEW_JSON" | jq -e '.[0].password == "s3cr3t-ea"' >/dev/null \
  || fail "view 未出 grantor 密碼明文（外部鑰鏈斷）：$(echo "$VIEW_JSON" | jq -c '.[0]|{username,password}')"
pass "grantee 以派發金鑰讀到 grantor 帳密明文"

# epoch 快取語意：同 epoch 重讀不打 VW（access log 只 1 發 view POST）。
VIEW_POSTS_1=$(docker logs "$VW" 2>&1 | grep -cE "\[request\]\[INFO\] POST /api/emergency-access/[^ ]+/view" || true)
BB ea view "$EAID" >/dev/null
VIEW_POSTS_2=$(docker logs "$VW" 2>&1 | grep -cE "\[request\]\[INFO\] POST /api/emergency-access/[^ ]+/view" || true)
[[ "$VIEW_POSTS_1" == "$VIEW_POSTS_2" && "$VIEW_POSTS_1" -ge 1 ]] \
  || fail "同 epoch 重讀應吃 daemon 快取（$VIEW_POSTS_1→$VIEW_POSTS_2）"
# 上鎖：明文閘拒；解鎖：epoch 已變，必須重新打 VW。
BB lock >/dev/null
if BB ea view "$EAID" >/dev/null 2>&1; then
  fail "鎖態 view 應被拒（快取已失效）"
fi
echo "$PWB" | BB unlock --password-stdin >/dev/null
BB ea view "$EAID" >/dev/null
VIEW_POSTS_3=$(docker logs "$VW" 2>&1 | grep -cE "\[request\]\[INFO\] POST /api/emergency-access/[^ ]+/view" || true)
[[ "$VIEW_POSTS_3" == "$((VIEW_POSTS_1 + 1))" ]] \
  || fail "鎖→解鎖後 view 應重取 VW 一次（$VIEW_POSTS_2→$VIEW_POSTS_3）"
pass "epoch 語意：鎖態明文出棧、解鎖後重取（access log 計數實證）"

# 拒絕路徑：RecoveryApproved 仍可 reject（源檔兩態皆收）→ 回 Confirmed。
BG ea reject "$EAID" >/dev/null
[[ "$(BB ea ls --granted | jq -r '.[0].status')" == "Confirmed" ]] \
  || fail "reject 後應回 Confirmed"
pass "reject 閉環回 Confirmed（view 入口消失由 can_view 純測釘選）"

echo "EXIT-C2-PARTIAL 0"
