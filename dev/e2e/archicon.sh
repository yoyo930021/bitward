#!/usr/bin/env bash
# 批次 B e2e：封存三態（官方 archivedDate）× 圖示代理（icons 快取）。
# 自起 VW 1.37.2（port 18099）與獨立 data-dir——不碰常駐 demo daemon。
# 用法：dev/e2e/archicon.sh（需要 docker）
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-archicon
PORT=18099
DATA=dev/e2e/data-archicon
WP="AcMaster-7kQ!z"
EMAIL="ac-$(date +%s)@bitward.test"
SRV="http://127.0.0.1:$PORT"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DATA" /tmp/ac-*
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }
drained() {
  for _ in $(seq 1 "${1:-60}"); do
    [[ "$(D outbox --json | jq "$PENDING")" == "0" ]] && return 0
    sleep 1
  done
  return 1
}

command -v docker >/dev/null || fail "需要 docker"
command -v jq >/dev/null || fail "需要 jq"
cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1 || true
docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done

mkdir -p "$DATA"
BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitwarderd --data-dir "$DATA" --sock "$DATA/s" >"$DATA/log" 2>&1 & PID=$!
sleep 1
D() { BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitward --sock "$DATA/s" "$@"; }

echo "$WP" | D dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | D login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
TOK=$(jq -r .access_token "$DATA/account.json")
pass "daemon 登入"

# —— 1) 封存往復：archive → 主列表排除（帶 archived_at 於封存檢視）→ unarchive 回列 ——
D new --name archme >/dev/null
drained 60 || fail "archme 建立未收斂"
AID=$(D ls --json | jq -r '.[] | select(.meta.name=="archme") | .meta.id')
D archive "$AID" true >/dev/null
drained 60 || fail "封存未推完"
[[ "$(D ls --json | jq --arg a "$AID" '[.[] | select(.meta.id==$a)] | length')" == "0" ]] \
  || fail "已封存項目仍出現在主列表（預設排除失效）"
SEEN=$(D ls --archived --json)
[[ "$(jq -r --arg a "$AID" '.[] | select(.meta.id==$a) | .meta.archived_at' <<<"$SEEN")" != "null" ]] \
  || fail "Query(archived=true) 未見該項目或未帶 archived_at"
# 伺服器端如實落 archivedDate（官方線格式，非本地標記）
AW=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$AID")
[[ "$(jq -r '.archivedDate // "null"' <<<"$AW")" != "null" ]] || fail "REST 端 archivedDate 未落庫"
D archive "$AID" false >/dev/null
drained 60 || fail "取消封存未推完"
[[ "$(D ls --json | jq --arg a "$AID" '[.[] | select(.meta.id==$a)] | length')" == "1" ]] \
  || fail "取消封存未回主列表"
[[ "$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$AID" | jq -r '.archivedDate')" == "null" ]] \
  || fail "REST 端 archivedDate 未清"
pass "封存往復：主列表排除／封存檢視帶 archived_at／取消回列（REST 雙向核對）"

# —— 2) 官方代理形態：外部 PUT 帶 archivedDate → daemon /sync 後主列表不見 ——
D new --name ext-arch >/dev/null
drained 60 || fail "ext-arch 建立未收斂"
EID=$(D ls --json | jq -r '.[] | select(.meta.name=="ext-arch") | .meta.id')
python3 - "$SRV" "$TOK" "$EID" <<'PY' || fail "官方代理封存 PUT 失敗"
import json, sys, urllib.request
srv, tok, cid = sys.argv[1:4]
req = urllib.request.Request(f"{srv}/api/ciphers/{cid}", headers={"Authorization": f"Bearer {tok}"})
c = json.load(urllib.request.urlopen(req, timeout=20))
c["archivedDate"] = "2026-11-10T00:00:00.000000Z"
for k in ("revisionDate", "creationDate", "deletedDate", "object", "edit",
          "viewPassword", "organizationUseTotp", "permissions"):
    c.pop(k, None)
if isinstance(c.get("login"), dict):
    c["login"].pop("passwordHistory", None)
if c.get("key") is None:
    c.pop("key", None)
body = json.dumps(c).encode()
req = urllib.request.Request(f"{srv}/api/ciphers/{cid}", data=body, method="PUT",
                             headers={"Authorization": f"Bearer {tok}",
                                      "Content-Type": "application/json"})
print(urllib.request.urlopen(req, timeout=20).status)
PY
D sync >/dev/null
[[ "$(D ls --json | jq --arg e "$EID" '[.[] | select(.meta.id==$e)] | length')" == "0" ]] \
  || fail "官方代理封存的項目混進了主列表"
[[ "$(D ls --archived --json | jq --arg e "$EID" '[.[] | select(.meta.id==$e)] | length')" == "1" ]] \
  || fail "Query(archived=true) 未見官方代理封存項"
pass "官方代理 archived 形態經 /sync 落庫並被三態過濾正確歸類"

# —— 3) 圖示代理：首呼打 VW（日誌計數 +1）、再呼命中快取（零重連）、PNG magic ——
IC1=$(docker logs "$VW" 2>&1 | grep -c "icon_internal" || true)
D icon duckduckgo.com /tmp/ac-1.png >/dev/null || fail "GetIcon 首呼失敗"
file /tmp/ac-1.png | grep -q "PNG image" || fail "圖示非 PNG magic（$(file /tmp/ac-1.png)）"
IC2=$(docker logs "$VW" 2>&1 | grep -c "icon_internal" || true)
[[ "$IC2" -eq $((IC1 + 1)) ]] || fail "首呼未在 VW 留下 icon 請求（$IC1→$IC2）"
D icon duckduckgo.com /tmp/ac-2.png >/dev/null || fail "GetIcon 二呼失敗"
IC3=$(docker logs "$VW" 2>&1 | grep -c "icon_internal" || true)
[[ "$IC3" -eq "$IC2" ]] || fail "快取未命中：二呼又打了伺服器（$IC2→$IC3）"
cmp -s /tmp/ac-1.png /tmp/ac-2.png || fail "快取位元組與首呼不一致"
pass "GetIcon：首呼代理落 cache（PNG magic）、二呼零外連位元組一致"

# —— 4) host 校驗：路徑穿越拒（403 Denied 語意，非 panic）——
if D icon "../etc" /tmp/ac-x.png >/dev/null 2>&1; then
  fail "非法 host 竟被接受"
fi
pass "非法 host（路徑穿越）擋在 daemon 邊界"

# —— 5) uri 陣列操作：編輯增列 → REST 直讀 uris 兩筆 → 刪列收斂 ——
D new --name uritarget --uri https://one.ac.test >/dev/null
drained 60 || fail "uritarget 建立未收斂"
UID_=$(D ls --json | jq -r '.[] | select(.meta.name=="uritarget") | .meta.id')
D edit "$UID_" --append-uri https://two.ac.test >/dev/null
drained 60 || fail "uri 增列未推完"
U1=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$UID_")
[[ "$(jq '.login.uris | length' <<<"$U1")" == "2" ]] || fail "REST 端 uris 非兩筆（增列失效）"
jq -r '.login.uris[1].uri' <<<"$U1" | grep -q '^2\.' || fail "新增 uri 列非信封字串"
[[ "$(jq '.login.uris[1].match' <<<"$U1")" == "null" ]] || fail "新列 match 非 null（官方形態漂移）"
# 刪首列後收斂：剩一筆且內容解得回 two（刪錯列會在此現形）
D edit "$UID_" --remove-uri 0 >/dev/null
drained 60 || fail "uri 刪列未推完"
D sync >/dev/null
U2=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$UID_")
[[ "$(jq '.login.uris | length' <<<"$U2")" == "1" ]] || fail "REST 端 uris 未收斂至一筆"
[[ "$(D get "$UID_" --view masked --json | jq -r '.meta.uris[0]')" == "https://two.ac.test" ]] \
  || fail "刪後存活列內容錯誤（刪錯列或索引位移）"
# 越界刪列入列前拒（鏡像不動）
if D edit "$UID_" --remove-uri 7 >/dev/null 2>&1; then fail "越界 RemoveUri 竟被接受"; fi
[[ "$(D get "$UID_" --view masked --json | jq '.meta.uris | length')" == "1" ]] \
  || fail "越界拒絕後鏡像被污染"
pass "uri 增刪列：REST 直讀兩筆→一筆、存活列內容正確、越界擋在入列前"

echo "ARCHICON E2E: ALL PASS"
