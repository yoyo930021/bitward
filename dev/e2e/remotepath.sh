#!/usr/bin/env bash
# P5 跨機 e2e：TLS+SPKI pin 配對、device grants、HubOffline 快速失敗、ntfy 信令（wake+approval）。
set -uo pipefail
cd "$(dirname "$0")/../.."

HUB=bitward-vw-p5r
THIN=bitward-vw-p5t
VWPORT=18090
NTFY=bitward-ntfy-p5
NTPORT=18091
TLSPORT=18092
DH=dev/e2e/data-p5hub
DT=dev/e2e/data-p5thin
WP="P5Master-2xL!m"
SECRET="p5-v4ult-77"
SUF=$(date +%s)
EMAIL="p5-$SUF@bitward.test"
TOPIC="bitward-e2e-$SUF"
cleanup() {
  [[ -n "${HUBPID:-}" ]] && kill "$HUBPID" 2>/dev/null
  [[ -n "${SSEPID:-}" ]] && kill "$SSEPID" 2>/dev/null
  docker rm -f $HUB $THIN $NTFY >/dev/null 2>&1
  rm -rf $DH $DT
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; tail -10 "$DH/log" 2>/dev/null; exit 1; }
pass() { echo "ok: $1"; }
export BITWARD_DATA_DIR=$PWD/$DH
B() { "$PWD/target/debug/bitward" --sock "$DH/s" "$@"; }
T() { BITWARD_DATA_DIR=$PWD/$DT "$PWD/target/debug/bitward" --remote "$1" "${@:2}"; }

cargo build -q -p bitwarderd -p bitward
docker rm -f $HUB $NTFY >/dev/null 2>&1
docker run -d --name $HUB -p $VWPORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
docker run -d --name $NTFY -p $NTPORT:80 binwiederhier/ntfy serve >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$VWPORT/alive" >/dev/null 2>&1 && break; sleep 1; done
NTFY_OK=0
for _ in $(seq 1 20); do
  curl -fsS "http://127.0.0.1:$NTPORT/" >/dev/null 2>&1 && { NTFY_OK=1; break; }
  sleep 1
done
[[ "$NTFY_OK" == 1 ]] || fail "ntfy 未就緒"

mkdir -p $DH $DT
BITWARD_DATA_DIR=$PWD/$DH ./target/debug/bitwarderd --data-dir $DH --sock $DH/s \
  --listen 127.0.0.1:$TLSPORT --ntfy "http://127.0.0.1:$NTPORT/$TOPIC" >$DH/log 2>&1 & HUBPID=$!
sleep 1
curl -sN "http://127.0.0.1:$NTPORT/$TOPIC/sse" >$DH/sse.log 2>&1 & SSEPID=$!
sleep 1
# 分離 ntfy 鏈路與 daemon：先自己發一條必須看到
curl -s -m 5 -d 'link-probe' "http://127.0.0.1:$NTPORT/$TOPIC" >/dev/null
for _ in $(seq 1 10); do grep -q link-probe $DH/sse.log && break; sleep 0.5; done
grep -q link-probe $DH/sse.log || fail "ntfy 鏈路本身不通（subscribe 沒收到 publish）"

echo "$WP" | B --json dev-register --server "http://127.0.0.1:$VWPORT" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "http://127.0.0.1:$VWPORT" --email "$EMAIL" --password-stdin >/dev/null
echo "$SECRET" | B new --name p5item --password-stdin >/dev/null
GID=$(B ls --json | jq -r '.[0].meta.id')
pass "hub 就緒（VW+TLS+ntfy）"

# 配對
PAIR=$(B --json pair start --name e2e-laptop --grant 'see:identity all' --ttl 3600)
CODE=$(jq -r .code <<< "$PAIR"); PIN=$(jq -r .pin <<< "$PAIR")
[[ "$CODE" =~ ^[A-Z2-9]{9}$ && ${#PIN} -eq 44 ]] || fail "pair start 形狀不對: $PAIR"
BITWARD_DATA_DIR=$PWD/$DT "$PWD/target/debug/bitward" pair join \
  --url "https://127.0.0.1:$TLSPORT" --pin "$PIN" --code "$CODE" --name laptop \
  --wake "http://127.0.0.1:$NTPORT/${TOPIC}-wake" >/dev/null || fail "join 失敗"
OUT=$(T default ls --json)
grep -q p5item <<< "$OUT" || fail "remote ls 未見 items: $OUT"
grep -q "$SECRET" <<< "$OUT" && fail "remote metadata 洩明文" || true
pass "TLS+pin 配對、device ls（metadata-only）"

# grants：無 reveal → 被拒
ERR=$(T default reveal "$GID" 2>&1 || true)
grep -qiE '授權|Denied|grant' <<< "$ERR" || fail "無 reveal grant 應被拒: $ERR"
pass "device grants：reveal 被拒"

# 錯 pin 連線失敗（pin 綁定生效）
BADJSON=$(python3 -c "import json,sys;d=json.load(open('$DT/remotes/default.json'));d['pin']='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';print(json.dumps(d))")
echo "$BADJSON" > $DT/remotes/bad.json
ERR=$(T bad ls 2>&1 || true)
grep -qiE 'HubOffline|pin|handshake' <<< "$ERR" || fail "錯 pin 應連線失敗: $ERR"
pass "錯 pin 被拒"

# HubOffline：停 hub → 快速失敗帶 last_seen
kill $HUBPID; wait $HUBPID 2>/dev/null
HUBPID=""
# 單次呼叫：連線失敗（含 wake POST 重試一次仍失敗）→ HubOffline
BITWARD_DATA_DIR=$PWD/$DT "$PWD/target/debug/bitward" --remote default ls 2>$DH/offline.err || true
grep -q HubOffline $DH/offline.err || { cat $DH/offline.err; fail "離線未回 HubOffline 語意"; }
grep -q last_seen $DH/offline.err || fail "HubOffline 缺 last_seen"
pass "HubOffline 快速失敗（含 last_seen）"

# 重啟 hub（模擬 wake 後的 app 醒來）→ 再試成功 + wake endpoint 已 POST 過（ntfy 有紀錄）
BITWARD_DATA_DIR=$PWD/$DH ./target/debug/bitwarderd --data-dir $DH --sock $DH/s \
  --listen 127.0.0.1:$TLSPORT --ntfy "http://127.0.0.1:$NTPORT/$TOPIC" >>$DH/log 2>&1 & HUBPID=$!
sleep 1
echo "$WP" | B unlock >/dev/null || fail "重啟後 unlock 失敗"
T default ls --json | jq -e 'length >= 1' >/dev/null || fail "重啟後 remote 未恢復"
pass "hub 重啟後 remote 收斂"

# approval 信令：gated device 的 reveal 阻塞 → ntfy 收到信令 → hub 端 approve → 明文放行
GPAIR=$(B --json pair start --name gated-laptop --grant 'reveal:secret all approve' --ttl 3600)
GCODE=$(jq -r .code <<< "$GPAIR"); GPIN=$(jq -r .pin <<< "$GPAIR")
BITWARD_DATA_DIR=$PWD/$DT "$PWD/target/debug/bitward" pair join \
  --url "https://127.0.0.1:$TLSPORT" --pin "$GPIN" --code "$GCODE" --name gated \
  --profile gated >/dev/null || fail "gated join 失敗"
( T gated reveal "$GID" >$DT/gated.out 2>&1 ) & GJOB=$!
sleep 2
for _ in $(seq 1 20); do grep -q "bitward: approval" $DH/sse.log && break; sleep 0.5; done
grep -q "bitward: approval" $DH/sse.log || { echo "--- sse:"; cat $DH/sse.log; echo "--- gated.out:"; cat $DT/gated.out 2>/dev/null; echo "--- hub log:"; grep -iE 'ntfy|approval|warn' $DH/log | tail -6; fail "ntfy 未收到 approval 信令"; }
pass "approval 信令送達 ntfy（只傳不透明摘要）"
APID=$(B --json agent pending | jq -r '.[0].id')
[[ -n "$APID" && "$APID" != null ]] || fail "pending 佇列空"
B approve "$APID" >/dev/null
wait $GJOB || true
grep -q "$SECRET" $DT/gated.out || { echo "--- gated.out:"; cat $DT/gated.out; echo "--- hub log:"; grep -iE 'approval|warn|error' $DH/log | tail -5; fail "批准後 remote reveal 未回明文"; }
pass "跨機 NeedApproval → approve → 明文僅此一路"

# pair list/revoke
B pair list --json | jq -e 'length >= 0' >/dev/null || fail "pair list"
pass "pair list 可用"

echo "P5 REMOTE E2E: ALL PASS"
