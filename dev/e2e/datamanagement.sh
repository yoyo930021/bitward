#!/usr/bin/env bash
# P4 資料管理 e2e：tags（FR132）、值搜尋（FR11941）、去重合併（FR648）、move 路徑。
# org 共享語意的完整覆蓋等 org 功能面（P4b，契約 §4）；這裡驗證 unshare 寫路徑收斂。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-p4
PORT=18087
DA=dev/e2e/data-p4
WP="P4Master-3mK!q"
EMAIL="p4-$(date +%s)@bitward.test"
cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; docker rm -f "$VW" >/dev/null 2>&1 || true; rm -rf "$DA"; }
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; [[ -n "$DA" ]] && tail -12 "$DA/log" 2>/dev/null || true; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1
docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1 && break; sleep 1; done
mkdir -p $DA
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >$DA/log 2>&1 & PID=$!
sleep 1
export BITWARD_DATA_DIR=$PWD/$DA
B() { "$PWD/target/debug/bitward" --sock "$DA/s" "$@"; }
SRV="http://127.0.0.1:$PORT"
echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null

# seed：gh（host github.com/user alice/pw-reuse）、gh2（同 host+user → 重複）、gh3（同 host 不同 user）
for n in gh:alice:pw-reuse gh2:alice:pw-reuse gh3:bob:other-pw; do
  IFS=: read -r name user pw <<< "$n"
  echo "$pw" | B new --name "$name" --username "$user" --uri "https://$name.example.com" --password-stdin >/dev/null
done
B sync >/dev/null

# tags：add/ls filter/rm
GHA=$(B ls --json | jq -r '.[] | select(.meta.name=="gh") | .meta.id')
B tag add "$GHA" work >/dev/null
B tag add "$GHA" work >/dev/null   # 冪等
N=$(B ls --tag work --json | jq 'length')
[[ "$N" == "1" ]] || fail "tag 過濾應 1 筆，got $N"
B tag rm "$GHA" work >/dev/null
[[ "$(B ls --tag work --json | jq 'length')" == "0" ]] || fail "tag 移除後仍命中"
pass "tags add/冪等/過濾/rm（FR 132 本地層）"

# 值搜尋
HIT=$(B ls --value pw-reuse --json | jq 'length')
[[ "$HIT" == "2" ]] || fail "值搜尋應命中 2，got $HIT"
[[ "$(B ls --value no-such-pw --json | jq 'length')" == "0" ]] || fail "值搜尋誤報"
pass "值搜尋（FR 11941，走解鎖回填的明文索引）"

# 去重：gh 與 gh2 同 host+user？host 不同（github.com vs gh2.example.com）——
# 群集按 (uri host, username)：gh/gh2 host 不同故不重複；造一筆真正重複：
echo pw-reuse | B new --name ghcopy --username alice --uri "https://gh.example.com" --password-stdin >/dev/null
# gh 的 uri 是 https://gh.example.com（上面 seed 用 $name.example.com）→ gh 與 ghcopy 同 host+user
B sync >/dev/null
G=$(B dupes --json | jq -r '.[] | select(.domain=="gh.example.com") | .ids | length')
[[ "$G" == "2" ]] || fail "dupes 應群集 2 筆，got $G"
pass "去重群集（FR 648 偵測面）"

# 合併：keep gh，軟刪 ghcopy，tags 聯集
B tag add "$GHA" keepme >/dev/null
GHCP=$(B ls --json | jq -r '.[] | select(.meta.name=="ghcopy") | .meta.id')
B tag add "$GHCP" fromdupe >/dev/null
B merge "$GHA" "$GHCP" >/dev/null
for _ in $(seq 1 30); do [[ "$(B outbox --json | jq '(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)')" == "0" ]] && break; sleep 1; done
[[ "$(B ls --json | jq --arg i "$GHCP" '[.[] | select(.meta.id==$i)] | length')" == "0" ]] || fail "merge 後 dupe 仍在列表"
TAGS=$(B ls --json | jq -r --arg i "$GHA" '.[] | select(.meta.id==$i) | .meta.tags | join(",")')
[[ "$TAGS" == *keepme* && "$TAGS" == *fromdupe* ]] || fail "tags 聯集遺失：$TAGS"
pass "合併：dupe 軟刪收斂、tags 聯集（FR 648 合併面）"

# unshare 寫路徑（個人項目：PUT organizationId null 應成功收斂）
B unshare "$GHA" >/dev/null
for _ in $(seq 1 30); do [[ "$(B outbox --json | jq '(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)')" == "0" ]] && break; sleep 1; done
[[ "$(B outbox --json | jq '.outbox.dead + .outbox.conflict')" == "0" ]] || fail "unshare 路徑未收斂"
pass "move/unshare outbox 路徑收斂（org 語意全覆蓋列 P4b）"

# 值索引不洩到 metadata 輸出
B ls --json | jq -e 'all(has("password") | not)' >/dev/null || fail "值索引回填後 metadata 輸出出現 password 鍵"
pass "值索引未破壞 A3 輸出契約"

echo "P4 DATAMANAGE E2E: ALL PASS"
