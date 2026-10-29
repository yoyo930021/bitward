#!/usr/bin/env bash
# P3 治理煙霧測：grant 判定、budget、run 淨化、approve 迴路。
set -uo pipefail
cd "$(dirname "$0")/../.."
DA=dev/e2e/smoke-a
VW=bitward-vw-smoke
PORT=18086
WP="SmokePw-7!x"
SECRET="smoke-s3cret-9e"
EMAIL="smoke-$(date +%s)@x.io"
cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null; docker rm -f $VW >/dev/null 2>&1; rm -rf $DA; }
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

cargo build -q -p bitwarderd -p bitward
docker rm -f $VW >/dev/null 2>&1
docker run -d --name $VW -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:$PORT/alive >/dev/null && break; sleep 1; done
mkdir -p $DA
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir $DA --sock $DA/s >$DA/log 2>&1 & PID=$!
sleep 1
export BITWARD_DATA_DIR=$PWD/$DA
B() { "$PWD/target/debug/bitward" --sock "$DA/s" "$@"; }
echo "$WP" | B --json dev-register --server "http://127.0.0.1:$PORT" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "http://127.0.0.1:$PORT" --email "$EMAIL" --password-stdin >/dev/null
echo "$SECRET" | B new --name s1 --password-stdin >/dev/null
GID=$(B ls --json | jq -r '.[0].meta.id')

cp $DA/cli_session $DA/human.token
AGENT=$(B --json agent open --name totp-only --grant "use:totp item:$GID; see:identity all" --ttl 600 | jq -r .token)
[[ -n "$AGENT" && "$AGENT" != null ]] || fail "agent open 未取得 token"

# 以 agent token 執行：reveal 應被拒（無 reveal grant）
echo "$AGENT" > $DA/cli_session
OUT=$(B reveal "$GID" 2>&1 || true)
grep -qiE 'grant|Denied' <<< "$OUT" || fail "無 reveal grant 應被拒，got: $OUT"
echo "ok: reveal 被 grant 擋下"
OUT=$(B ls --json)
grep -q agent1 <<< "$OUT" || grep -q s1 <<< "$OUT" || fail "see:identity all 應可列表"
echo "ok: see:identity 列表可用"

# run 淨化（human 全權 session 也要淨化出口）
cp $DA/human.token $DA/cli_session
RUNOUT=$(B run -- sh -c "echo done" 2>&1)
[[ "$RUNOUT" == *done* ]] || fail "run 未執行"
echo "ok: run 基本執行"
RUNOUT2=$(B run --env "TOKEN=btw://$GID/password" -- sh -c 'echo "T=$TOKEN"' 2>&1)
grep -q "«redacted»" <<< "$RUNOUT2" || { echo "$RUNOUT2"; fail "注入值未在出口被淨化"; }
grep -q "$SECRET" <<< "$RUNOUT2" && fail "注入明文外洩" || true
echo "ok: btw:// 注入 + 出口 Redactor 淨化"

# approve 迴路：gated agent 的 reveal 阻塞，human 端批准
GATED=$(B --json agent open --name gated --grant "reveal:secret item:$GID approve" --ttl 600 | jq -r .token)
echo "$GATED" > $DA/cli_session
( B reveal "$GID" >$DA/gated.out 2>&1 ) & GJOB=$!   # 立刻以 GATED 起跑，daemon 內阻塞等核准
sleep 1
cp $DA/human.token $DA/cli_session
for _ in $(seq 1 20); do
  PIDA=$(B --json agent pending | jq -r '.[0].id // empty')
  [[ -n "$PIDA" ]] && break
  sleep 0.5
done
[[ -n "${PIDA:-}" ]] || fail "pending 佇列為空"
B approve "$PIDA" >/dev/null
wait $GJOB || true
grep -q "$SECRET" $DA/gated.out || { cat $DA/gated.out; fail "批准後 reveal 未回明文"; }
echo "ok: NeedApproval 阻塞 → approve → 明文放行"

# revoke 後 agent 呼叫失效
cp $DA/human.token $DA/cli_session
SID=$(B --json agent list | jq -r --arg a "$AGENT" '.[] | select(.id==$a) | .id')
B agent revoke "$SID" >/dev/null
echo "$AGENT" > $DA/cli_session
OUT=$(B ls 2>&1 || true)
grep -qiE 'revoked|stale|dropped|Denied|世代失效' <<< "$OUT" || fail "revoke 後仍可用: $OUT"
echo "ok: revoke 即時生效"

echo "SMOKE P3: ALL PASS"
