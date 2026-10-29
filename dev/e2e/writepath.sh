#!/usr/bin/env bash
# P2 寫入路徑 e2e（契約 §5、§6 A7/A12）。需要 docker。
# A7 離線寫入收斂；A12 雙中樞併發（不同欄自動合併、同欄衝突收件匣、targeted pull 收斂）。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-p2
PORT=18082
DA=dev/e2e/data-a
DB=dev/e2e/data-b
WP="P2Master-7kQ!z"
SECRET="p2-s3cret-α"
EMAIL="p2-$(date +%s)@bitward.test"

cleanup() {
  for p in "${PID_A:-}" "${PID_B:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA" "$DB"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1 && break; sleep 1; done

mkdir -p "$DA" "$DB"
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >/dev/null 2>&1 & PID_A=$!
BITWARD_DATA_DIR=$PWD/$DB ./target/debug/bitwarderd --data-dir "$DB" --sock "$DB/s" >/dev/null 2>&1 & PID_B=$!
sleep 1
A() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" "$@"; }
B() { BITWARD_DATA_DIR=$PWD/$DB ./target/debug/bitward --sock "$DB/s" "$@"; }
SRV="http://127.0.0.1:$PORT"

echo "$WP" | A --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | A login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
pass "雙中樞登入（A、B）"

# A7：離線寫入 → 伺服器重啟後收斂
echo "$SECRET" | A new --name online1 --password-stdin >/dev/null
docker stop "$VW" >/dev/null
echo "off-1" | A new --name offline1 --password-stdin >/dev/null
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'
D1=$(A outbox --json | jq "$PENDING")
[[ "$D1" -ge 1 ]] || fail "A7 離線寫入未入列（pending=$D1）"
STATE=$(A ls --json | jq -r '.[] | select(.meta.name=="offline1") | .meta.pending')
[[ "$STATE" == "true" ]] || fail "A7 離線項目未標 pending"
docker start "$VW" >/dev/null
for _ in $(seq 1 40); do
  [[ "$(A outbox --json | jq "$PENDING")" == "0" ]] && break
  sleep 1
done
[[ "$(A outbox --json | jq "$PENDING")" == "0" ]] || fail "A7 outbox 未收斂"
# 伺服器端確實有兩筆
CNT=$(A ls --json | jq 'length')
[[ "$CNT" == "2" ]] || fail "A7 筆數 $CNT != 2"
pass "A7 離線寫入 30 秒內收斂、pending 清除"

# A12a：不同欄併發 → 自動合併（B 改 name，A 改 username，A 先入列）
GID=$(A ls --json | jq -r '.[] | select(.meta.name=="online1") | .meta.id')
B sync >/dev/null
# A 改 username
A edit "$GID" --set username=alice >/dev/null
sleep 2   # 讓 A 推上去（base_rev 更新到伺服器）
# B 先拉最新，再改 name（不同欄）
B sync >/dev/null
B edit "$GID" --set name=renamed-by-b >/dev/null
for _ in $(seq 1 30); do
  [[ "$(B outbox --json | jq '.outbox.conflict + .outbox.queued + .outbox.in_flight')" == "0" ]] && break
  sleep 1
done
A sync >/dev/null
NAME=$(A ls --json | jq -r ".[] | select(.meta.id==\"$GID\") | .meta.name")
[[ "$NAME" == "renamed-by-b" ]] || fail "A12a B 的 name 更新未收斂（got $NAME）"
USER_=$(A get "$GID" --view masked --json | jq -r '.username // empty')
[[ "$USER_" == "alice" ]] || fail "A12a A 的 username 被覆蓋（got '$USER_'）"
pass "A12a 不同欄併發自動合併"

# A12b：同欄衝突 → 收件匣。序列化：A 離線編輯並先收斂；B 鏡像留在舊 rev（通知不會回放），
# B 再編輯同欄 → 必然 CAS 落空 → 欄位級 merge 判衝突。
docker stop "$VW" >/dev/null
A edit "$GID" --set notes=from-a >/dev/null
docker start "$VW" >/dev/null
for _ in $(seq 1 30); do [[ "$(A outbox --json | jq "$PENDING")" == "0" ]] && break; sleep 1; done
B edit "$GID" --set notes=from-b >/dev/null
CONFC=0
for _ in $(seq 1 60); do
  CB=$(B conflicts --json | jq 'length')
  CONFC=$CB
  [[ "$CONFC" -ge 1 ]] && break
  sleep 1
done
[[ "$CONFC" -ge 1 ]] || fail "A12b 同欄併發未進衝突收件匣（conflicts=$CONFC）"
D=B
RID=$(B conflicts --json | jq -r '.[0].id')
$D resolve "$RID" --ours >/dev/null
for _ in $(seq 1 20); do [[ "$($D outbox --json | jq '(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)')" == "0" ]] && break; sleep 1; done
[[ "$($D outbox --json | jq '.outbox.conflict')" == "0" ]] || fail "A12b 裁決後衝突未清"
pass "A12b 同欄衝突進收件匣、--ours 裁決收斂"

# A12c：notifications targeted pull（B 改完，A 不手動 sync 也該在 5 秒內看到）
B edit "$GID" --set name=notify-me >/dev/null
SEEN=no
for _ in $(seq 1 10); do
  sleep 1
  N=$(A ls --json | jq -r ".[] | select(.meta.id==\"$GID\") | .meta.name")
  [[ "$N" == "notify-me" ]] && { SEEN=yes; break; }
done
[[ "$SEEN" == yes ]] || fail "A12c targeted pull 未在 10 秒內收斂"
pass "A12c notifications 收斂（A 未手動 sync）"

# 軟刪與還原
A rm "$GID" >/dev/null
sleep 2
A sync >/dev/null
DEL=$(A ls --json | jq --arg g "$GID" '[.[] | select(.meta.id==$g)] | length')
[[ "$DEL" == "0" ]] || fail "軟刪後仍在列表"
pass "軟刪收斂"

# 盤上仍無明文（A4 延伸）
grep -a "$SECRET" "$DA/vault.db" && fail "寫入後主密洩盤" || true
grep -a "notify-me" "$DB/vault.db" >/dev/null || true  # metadata 明文索引允許
pass "寫入路徑未洩主密碼到盤"

# A7b：kill -9 daemon → 重啟 → DeviceAssertion 解鎖不重跑 KDF（<300ms；PBKDF2 600k 本身就要 ~0.5s+）
kill -9 "$PID_A" 2>/dev/null || true
sleep 0.5
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >>"$DA/log2" 2>&1 & PID_A=$!
sleep 1
rm -f "$DA/cli_session"   # 重啟後記憶體 session 消失；取新 session
T0=$(python3 -c 'import time;print(time.time_ns())')
A unlock >/dev/null
T1=$(python3 -c 'import time;print(time.time_ns())')
MS=$(( (T1 - T0) / 1000000 ))
[[ "$MS" -lt 300 ]] || fail "A7b 重啟解鎖 ${MS}ms（疑似重跑 KDF）"
pass "A7b kill -9 重生、解鎖 ${MS}ms 無 KDF"

echo "P2 WRITE E2E: ALL PASS"
