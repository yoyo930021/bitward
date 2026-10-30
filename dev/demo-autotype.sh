#!/usr/bin/env bash
# 一次性：起 demo daemon（docker VW + 隨機帳號），觸發輔助使用授權彈窗。
set -uo pipefail
cd "$(dirname "$0")/.."
DA=dev/e2e/demo
VW=bitward-vw-demo
PORT=18095
WP="DemoPw-5rT!k"
EMAIL="demo-$(date +%s)@bitward.test"
mkdir -p $DA
cargo build -q -p bitwarderd -p bitward
docker rm -f $VW >/dev/null 2>&1
docker run -d --name $VW -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1 && break; sleep 1; done
# daemon 若已在跑就重用
if ! BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock $DA/s status >/dev/null 2>&1; then
  BITWARD_DATA_DIR=$PWD/$DA nohup ./target/debug/bitwarderd --data-dir $DA --sock $DA/s >$DA/log 2>&1 &
  sleep 1
fi
B() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock $DA/s "$@"; }
SRV="http://127.0.0.1:$PORT"
if ! B status --json 2>/dev/null | grep -q '"Unlocked"'; then
  echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null 2>&1
  echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
  echo "hunter42-demo" | B new --name demo-edit --username demouser --password-stdin >/dev/null
fi
GID=$(B ls --json | jq -r '.[0].meta.id')
echo "item: $GID（demo-edit / demouser / hunter42-demo）"
echo "→ 現在觸發 autotype：未授權會彈系統窗"
B autotype "$GID" 2>&1 | head -2
echo "───"
echo "授權後重試（3 秒倒數內請把焦點切到 TextEdit 之类視窗）："
echo "  export BITWARD_DATA_DIR=$PWD/dev/e2e/demo"
echo "  ./target/debug/bitward --sock dev/e2e/demo/s autotype $GID"
