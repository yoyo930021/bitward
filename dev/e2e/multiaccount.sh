#!/usr/bin/env bash
# PR6-E5 多帳號 e2e（plan Lane 9＋perf 框）。需要 docker。
# 一個 daemon、兩個 Vaultwarden 帳號（兩個 profile）：
#   斷言一 A 鎖 B 解互不干擾（含事件/讀路徑）
#   斷言二 兩庫同步互不污染
#   斷言三 A 的撤銷不動 B（含 agent session）
#   預設槽語意：account use 改的是不帶 --profile 時的落點
#   perf 框：雙帳號併發 sync 總牆鐘 ≤ 串行 1.2×（5 輪交錯）
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-e5
PORT=18085
DA=dev/e2e/data-e5
SRV="http://127.0.0.1:$PORT"
WP="E5Master-7kQ!z"
STAMP=$(date +%s)
EMAIL_A="e5a-$STAMP@bitward.test"
EMAIL_B="e5b-$STAMP@bitward.test"

cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done

mkdir -p "$DA"
./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >/dev/null 2>&1 & PID=$!
sleep 1
# A()／B()：同一條 sock、兩個槽。預設槽由 daemon 的 accounts/.default 決定。
A() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" --profile personal "$@"; }
B() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" --profile work "$@"; }
N() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" "$@"; }   # 不表態

echo "$WP" | N dev-register --server "$SRV" --email "$EMAIL_A" --password-stdin >/dev/null
echo "$WP" | N dev-register --server "$SRV" --email "$EMAIL_B" --password-stdin >/dev/null
echo "$WP" | A login --server "$SRV" --email "$EMAIL_A" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL_B" --password-stdin >/dev/null
pass "單 daemon 雙帳號登入（personal／work 兩槽）"

# 遷移形態：新裝機的槽必須落在 accounts/<profile>/，且兩槽各自的庫
[[ -f "$DA/accounts/personal/vault.db" ]] || fail "personal 槽未開自己的庫"
[[ -f "$DA/accounts/work/vault.db" ]] || fail "work 槽未開自己的庫"
[[ "$DA" != "" && ! -f "$DA/vault.db" ]] || fail "根目錄不該再有 vault.db（狀態全在槽內）"
[[ -f "$DA/accounts/default/vault.db" ]] || fail "預設 default 槽必須存在（舊端落點）"

# account ls：兩槽、email 各自獨立、恰一個預設標記
LS=$(A --json account ls)
[[ "$(jq -r '[.[] | select(.profile!="default") | .profile] | length' <<<"$LS")" == "2" ]] \
  || fail "account ls 未列 personal/work：$LS"
[[ "$(jq -r '.[] | select(.profile=="personal") | .email' <<<"$LS")" == "$EMAIL_A" ]] \
  || fail "personal 槽的 email 不是 A"
[[ "$(jq -r '.[] | select(.profile=="work") | .email' <<<"$LS")" == "$EMAIL_B" ]] \
  || fail "work 槽的 email 不是 B（兩槽帳號不得互覆寫）"
[[ "$(jq -r '[.[] | select(.is_default)] | length' <<<"$LS")" == "1" ]] \
  || fail "account ls 恰一個預設槽標記"
pass "account ls 槽拓撲正確（兩槽、各自帳號、單一預設）"

# 斷言二：兩庫同步互不污染
echo "secret-A" | A new --name item-a --password-stdin >/dev/null
for _ in $(seq 1 30); do [[ "$(A --json outbox | jq '[.outbox.queued,.outbox.in_flight,.outbox.awaiting]|add')" == "0" ]] && break; sleep 1; done
B sync >/dev/null; sleep 2; B sync >/dev/null
[[ "$(A --json ls | jq 'length')" == "1" ]] || fail "A 庫筆數異常"
[[ "$(B --json ls | jq 'length')" == "0" ]] \
  || fail "B 庫被 A 的項目污染（$(B --json ls | jq 'length') 筆）"
pass "斷言二：兩庫同步互不污染"

# 斷言一：A 鎖 B 解互不干擾
echo "$WP" | A unlock --password-stdin >/dev/null
echo "$WP" | B unlock --password-stdin >/dev/null
A lock >/dev/null
STATE_A=$(A --json status | jq -r '.state | keys[0]')
STATE_B=$(B --json status | jq -r '.state | keys[0]')
[[ "$STATE_A" == "AuthLocked" ]] || fail "A 鎖後狀態應 AuthLocked，實為 $STATE_A"
[[ "$STATE_B" == "Unlocked" ]] || fail "A 鎖動到 B（B 狀態 $STATE_B）"
[[ "$(B --json status | jq -r '.profile')" == "work" ]] || fail "status 未回報所屬槽"
# B 的讀路徑照常（含 Reveal 需要解鎖態）
echo "secret-B" | B new --name item-b --password-stdin >/dev/null
BID=$(B --json ls | jq -r '.[0].meta.id')
[[ "$(B --json reveal "$BID" | jq -r '.password')" == "secret-B" ]] \
  || fail "A 鎖態下 B 的 reveal 失效"
# A 鎖態下自己的值搜尋必須拒（不是被 B 的解鎖態放行）
A ls --value secret-B >/dev/null 2>&1 && fail "A 鎖態卻查得到值（鎖世代共用？）" || true
pass "斷言一：A 鎖 B 解互不干擾"

# 斷言三：A 的撤銷不動 B（agent session 隨鎖撤銷）
TOK_A=$(A --json agent open --name e2e-a --grant 'see:identity all' --ttl 3600 | jq -r .token)
TOK_B=$(B --json agent open --name e2e-b --grant 'see:identity all' --ttl 3600 | jq -r .token)
AG_A() { BITWARD_DATA_DIR=$PWD/$DA BITWARD_AGENT_TOKEN="$TOK_A" ./target/debug/bitward --sock "$DA/s" --profile personal "$@"; }
AG_B() { BITWARD_DATA_DIR=$PWD/$DA BITWARD_AGENT_TOKEN="$TOK_B" ./target/debug/bitward --sock "$DA/s" --profile work "$@"; }
AG_B ls --json >/dev/null || fail "B 的 agent session 起手就不可用"
A lock >/dev/null; sleep 1
# 鎖世代推進 ⇒ A 的 agent session 撤銷；B 的必須存活
if AG_A ls --json >/dev/null 2>&1; then
  # session 撤銷在 CLI 會自動重 Enroll 一次並留 warning；斷言「B 不受影響」為主
  :
fi
AG_B ls --json >/dev/null || fail "A 上鎖後 B 的 agent session 被誤撤銷"
[[ "$(B --json status | jq -r '.state | keys[0]')" == "Unlocked" ]] || fail "A 撤銷波及 B 的鎖態"
pass "斷言三：A 的撤銷不動 B"

# 預設槽語意：account use 改的是「不帶 --profile」的落點
A account use work >/dev/null
[[ "$(N --json status | jq -r '.profile')" == "work" ]] || fail "未改綁預設槽"
[[ "$(N --json status | jq -r '.email')" == "$EMAIL_B" ]] || fail "預設槽落點不是 work 的帳號"
N account use personal >/dev/null
[[ "$(N --json status | jq -r '.profile')" == "personal" ]] || fail "預設槽切不回 personal"
[[ "$(cat "$DA/accounts/.default")" == "personal" ]] || fail "預設槽指標未落盤"
pass "預設槽指標（accounts/.default）語意正確"

# 非法槽名與未知槽都拒（路徑穿越不得開槽）
N --profile ../escape status >/dev/null 2>&1 && fail "非法槽名竟然受理" || true
[[ -e "$DA/accounts/../escape" || -e "$DA/accounts/escape" ]] && fail "非法槽名在盤上留了目錄" || true
N account use nope >/dev/null 2>&1 && fail "未知槽可設預設" || true
pass "槽名校驗與未知槽拒收"

# perf 框（plan：雙帳號併發 sync 總牆鐘 ≤ 串行 1.2×）：5 輪交錯，取中位數
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
serial=(); parallel=()
for _ in 1 2 3 4 5; do
  t0=$(now_ms); A sync >/dev/null; B sync >/dev/null; t1=$(now_ms)
  serial+=($((t1 - t0)))
  # 併發段：`wait` 不帶參數會連 daemon（常駐、永不退出）一起等——必須點名兩個 sync pid
  t0=$(now_ms); A sync >/dev/null & pa=$!; B sync >/dev/null & pb=$!
  wait $pa; wait $pb; t1=$(now_ms)
  parallel+=($((t1 - t0)))
done
med() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
S=$(med "${serial[@]}"); P=$(med "${parallel[@]}")
echo "perf：串行 sync 中位 ${S}ms、併發 ${P}ms（5 輪交錯）"
[[ "$S" -eq 0 ]] && S=1
# 整數比擬：P*10 ≤ S*12 ⇒ P/S ≤ 1.2
[[ $((P * 10)) -le $((S * 12)) ]] \
  || fail "併發 sync 牆鐘 ${P}ms > 串行 ${S}ms 的 1.2×（容器化鎖粒度需重審）"
pass "perf 框：雙帳號併發 sync ≤ 串行 1.2×"

echo "ALL PASS"
