#!/usr/bin/env bash
# 背景自動推送 e2e：VW 恢復後「待推送」無感自動收斂（退避紀律、REST 落地直讀）。
# 選新檔而非寫進 writepath.sh：本場景要一條獨立時間軸（停→寫→5 秒觀察→重啟→
# 90 秒收斂→log 斷言），writepath 的雙中樞 A7/A12 已各有停啟窗口與退避時序，
# 疊在同一檔會互吃彼此的 daemon log 計數與輪詢預算。
# 用法：dev/e2e/autodrain.sh（需要 docker）
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-autodrain
PORT=18083
DATA=dev/e2e/data-ad
WP="AdMaster-3xP!v"
EMAIL="ad-$(date +%s)@bitward.test"

cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  [[ -n "${KEEP_DATA:-}" ]] || rm -rf "$DATA"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
READY=0
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "Vaultwarden 未在 30 秒內就緒"

mkdir -p "$DATA"
BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitwarderd --data-dir "$DATA" --sock "$DATA/s" \
  >"$DATA/daemon.log" 2>&1 &
PID=$!
for _ in $(seq 1 20); do [[ -S "$DATA/s" ]] && break; sleep 0.2; done
D() { BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitward --sock "$DATA/s" "$@"; }
SRV="http://127.0.0.1:$PORT"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

echo "$WP" | D --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | D login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
pass "登入完成（VW 在線）"

# —— VW 掛掉：本機寫入排隊，不得自動推 ——
docker stop "$VW" >/dev/null
echo "ad-secret" | D new --name ad-cipher --password-stdin >/dev/null
[[ "$(D outbox --json | jq "$PENDING")" == "1" ]] || fail "離線寫入未入列"
sleep 5
[[ "$(D outbox --json | jq "$PENDING")" == "1" ]] || fail "VW 死亡卻已收斂（無事可推也該保持 1）"
STATE=$(D ls --json | jq -r '.[] | select(.meta.name=="ad-cipher") | .meta.pending')
[[ "$STATE" == "true" ]] || fail "待推送徽章未標 pending"
pass "VW 掛掉期間不自動推（pending=1 維持 5 秒、徽章在列）"

# —— VW 恢復：不碰任何手動同步，背景輪自行收斂 ——
docker start "$VW" >/dev/null
READY=0
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "Vaultwarden 重啟未在 30 秒內就緒"
CONVERGED=0
for _ in $(seq 1 90); do
  [[ "$(D outbox --json | jq "$PENDING")" == "0" ]] && { CONVERGED=1; break; }
  sleep 1
done
[[ "$CONVERGED" == "1" ]] || fail "VW 恢復後 90 秒内背景自動推送未收斂"
STATE=$(D ls --json | jq -r '.[] | select(.meta.name=="ad-cipher") | .meta.pending')
[[ "$STATE" == "false" ]] || fail "收斂後待推送徽章未消失"
pass "VW 恢復後無感自動收斂（pending 歸零、徽章消失）"

# —— 落地直讀：繞過 daemon，用 VW 自己的 REST 證明 cipher 在伺服器上 ——
GID=$(D ls --json | jq -r '.[] | select(.meta.name=="ad-cipher") | .meta.id')
LAND=$(python3 - "$SRV" "$EMAIL" "$WP" "$GID" <<'PY'
import base64, hashlib, json, sys, urllib.parse, urllib.request
srv, email, pw, gid = sys.argv[1:5]
mk = hashlib.pbkdf2_hmac("sha256", pw.encode(), email.encode(), 600_000)
h = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, pw.encode(), 1, 32)).decode()
form = urllib.parse.urlencode({
    "grant_type": "password", "username": email, "password": h,
    "scope": "api offline_access", "client_id": "mobile",
    "deviceIdentifier": "autodrain-e2e", "deviceName": "autodrain",
    "deviceType": "7"}).encode()
req = urllib.request.Request(srv + "/identity/connect/token", data=form,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
tok = json.load(urllib.request.urlopen(req, timeout=20))["access_token"]
req = urllib.request.Request(srv + "/api/sync", headers={"Authorization": "Bearer " + tok})
data = json.load(urllib.request.urlopen(req, timeout=20))
print(sum(1 for c in data.get("ciphers", []) if c.get("id") == gid))
PY
) || fail "REST 直讀失敗"
[[ "$LAND" == "1" ]] || fail "伺服器端查無已推送的 cipher（hits=$LAND）"
pass "REST 直讀證明 cipher 已落地 VW（/api/sync 命中 $GID）"

# —— 退避不破：deferred warn 至多一輪（首敗 warn、續敗 debug 不落 INFO log）、無死信 ——
WARN=$(grep -c 'background drain deferred' "$DATA/daemon.log" || true)
[[ "$WARN" -le 1 ]] || fail "退避失效：deferred warn $WARN 輪（應 ≤1）"
DEAD=$(grep -c 'push failed permanently' "$DATA/daemon.log" || true)
[[ "$DEAD" == "0" ]] || fail "退避期間出現永久失敗 $DEAD 筆"
ERR=$(grep -c 'ERROR' "$DATA/daemon.log" || true)
[[ "$ERR" == "0" ]] || fail "VW 停啟窗口出現 ERROR 洪流（$ERR 行）"
pass "退避紀律：deferred warn ≤1 輪、無死信、無 ERROR"

echo "AUTODRAIN E2E: ALL PASS"
