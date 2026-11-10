#!/usr/bin/env bash
# GUI 登入卡 e2e（批次 8）：乾淨 data-dir daemon（SignedOut）＋真 VW 帳號，
# 在 GUI 卡上完成一輪真登入，產 shot-44..47。demo daemon／bitward-vw-demo
# 不受影響（自起 bitward-vw-login 容器＋獨立埠）。用法：dev/e2e/gui-login.sh [輸出目錄]
set -euo pipefail
cd "$(dirname "$0")/../.."

DA=/tmp/bitward-gui-login-daemon
VW=bitward-vw-login
PORT=18096
SRV="http://127.0.0.1:$PORT"
WP='LoginMaster-9kQ!z'
EMAIL="gui-login-$(date +%s)@bitward.test"
OUT=${1:-$PWD/apps/bitward-gui}

command -v docker >/dev/null || { echo "FAIL: 需要 docker"; exit 1; }
cargo build -q -p bitwarderd -p bitward

docker rm -f "$VW" >/dev/null 2>&1 || true
docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --max-time 3 "$SRV/alive" >/dev/null || { echo "FAIL: VW 未就緒"; exit 1; }

# daemon：整包新資料目錄＝SignedOut 世界（登入前 daemon 不知有任何帳號）。
pkill -f "bitwarderd --data-dir $DA" 2>/dev/null || true
sleep 0.3
rm -rf "$DA"
mkdir -p "$DA"
nohup ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >"$DA/log" 2>&1 &
sleep 1
[[ -S "$DA/s" ]] || { echo "FAIL: daemon 未起"; exit 1; }

# 只在 server 端建帳（dev-register 不寫 daemon 狀態＝GUI 面對未登入）。
echo "$WP" | BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" \
  --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null

rm -f "$OUT"/shot-4[4-7]-*.png
set +e
(cd apps/bitward-gui && NSH_GUI_SHOTS="$OUT" NSH_GUI_SHOTS_LOGIN=1 \
BW_TEST_SERVER="$SRV" BW_TEST_EMAIL="$EMAIL" BW_TEST_PASSWORD="$WP" \
BITWARD_GUI_SOCK="$DA/s" nsh run --target macos)
RC=$?
set -e

docker rm -f "$VW" >/dev/null 2>&1 || true
pkill -f "bitwarderd --data-dir $DA" 2>/dev/null || true
for n in 44-login-card 45-login-filled 46-vault-after-login 47-reauth-banner; do
  [[ -f "$OUT/shot-$n.png" ]] || { echo "FAIL: 缺 shot-$n.png（nsh exit $RC）"; exit 1; }
done
[[ "$RC" == "0" ]] || { echo "FAIL: nsh exit $RC"; exit 1; }
echo "GUI-LOGIN: ALL PASS（shot-44..47、帳號 $EMAIL）"
