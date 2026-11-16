#!/usr/bin/env bash
# PR1 Card/Identity 型別編輯 e2e（plan-wave2 管區：lane 2/4/5/6/7 場景的 CLI 端等位）。
# 斷言全部落在「使用者可觀察終態」：建卡回顯、web-vault 交叉解讀（REST 直讀 VW）、
# 雙裝置欄位級併發、值搜尋末四碼、import 往返、Reveal 審計座標、明文寬容態。
# 獨立 data-dir／sock／VW 容器（絕不碰常駐 launchd 域——四閘教訓）。需要 docker。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-cardid
PORT=18131
DA=dev/e2e/data-cardid-a
DB=dev/e2e/data-cardid-b
WP="CardId-Master-9kQ!z"
CARD_NUM="4111111111114242"
CARD_NUM2="5500805500801234"
CVV="987"
LAST_NAME="陳大文"
SURNAME="陳"
PLAIN_EXP="11"
EMAIL="cardid-$(date +%s)@bitward.test"
SRV="http://127.0.0.1:$PORT"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

cleanup() {
  for p in "${PID_A:-}" "${PID_B:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA" "$DB"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }

drained() { # $1=fn $2=timeout
  for _ in $(seq 1 "$2"); do
    [[ "$($1 outbox --json | jq "$PENDING")" == "0" ]] && return 0
    sleep 0.5
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

mkdir -p "$DA" "$DB"
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >/dev/null 2>&1 & PID_A=$!
BITWARD_DATA_DIR=$PWD/$DB ./target/debug/bitwarderd --data-dir "$DB" --sock "$DB/s" >/dev/null 2>&1 & PID_B=$!
sleep 1
A() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" "$@"; }
B() { BITWARD_DATA_DIR=$PWD/$DB ./target/debug/bitward --sock "$DB/s" "$@"; }

echo "$WP" | A --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | A login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
pass "雙裝置登入（A、B；獨立 data-dir/sock）"

# —— 1（lane 2）新建閉環：建卡→存→回讀＝輸入；鏡像 raw type==3 ——
A new --name 我的卡 --type card \
  --card cardholderName=Yoyo --card brand=Visa \
  --card "number=$CARD_NUM" --card expMonth=3 --card expYear=2032 --card "code=$CVV" >/dev/null
drained A 40 || fail "建卡未收斂"
CID=$(A ls --json | jq -r '.[] | select(.meta.name=="我的卡") | .meta.id')
[[ -n "$CID" && "$CID" != "null" ]] || fail "我的卡未入列"
[[ "$(A ls --json | jq -r ".[] | select(.meta.id==\"$CID\") | .meta.kind")" == "Card" ]] \
  || fail "kind 投影錯誤"
TOK=$(jq -r .access_token "$DA/account.json")
CW=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$CID")
[[ "$(jq -r .type <<<"$CW")" == "3" ]] || fail "REST type != 3（官方交叉前提）"
jq -r '.card | to_entries[] | select(.value != null) | .value' <<<"$CW" | grep -qv '^2\.' \
  && fail "REST card 欄未全信封化"
! grep -q "$CARD_NUM" <<<"$CW" || fail "REST 卡號明文外洩"
! grep -q "$CVV" <<<"$CW" || fail "REST CVV 明文外洩"
REVA=$(A reveal "$CID" --json)
[[ "$(jq -r '.card.number' <<<"$REVA")" == "$CARD_NUM" ]] || fail "reveal 卡號往返失敗"
[[ "$(jq -r '.card.code' <<<"$REVA")" == "$CVV" ]] || fail "reveal CVV 往返失敗"
[[ "$(jq -r '.card.brand' <<<"$REVA")" == "Visa" ]] || fail "reveal 品牌往返失敗"
MASK=$(A get "$CID" --view masked --json)
[[ "$(jq -r '.card.number_masked' <<<"$MASK")" == "••••4242" ]] || fail "Masked 未給末四碼遮罩"
[[ "$(jq -r '.card.number' <<<"$MASK")" == "null" ]] || fail "Masked 外洩全卡號"
[[ "$(jq -r '.card.code' <<<"$MASK")" == "null" ]] || fail "Masked 外洩 CVV"
[[ "$(jq -r '.card.code_masked' <<<"$MASK")" == "••••" ]] || fail "Masked 缺 CVV 遮罩欄"
pass "lane2 新建閉環（type==3、全欄信封、回顯等於輸入、Masked 遮罩/Reveal 全值）"

# —— 2（lane 4）Identity 讀寫：建 18 欄→單欄改不丟他欄 ——
A new --name 身分檔 --type identity \
  --identity lastName="$LAST_NAME" --identity firstName=Ming \
  --identity city=Taipei --identity postalCode=100 \
  --identity email=ming@example.test >/dev/null
drained A 40 || fail "建身分檔未收斂"
IID=$(A ls --json | jq -r '.[] | select(.meta.name=="身分檔") | .meta.id')
[[ "$(jq -r .type <<<"$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$IID")")" == "4" ]] \
  || fail "REST identity type != 4"
EOUT=$(A edit "$IID" --set "identity.lastName=陳小明" 2>&1) || fail "identity edit 失敗：$EOUT"
drained A 40 || fail "identity 單欄改未收斂"
IREV=$(A reveal "$IID" --json)
[[ "$(jq -r '.identity.last_name' <<<"$IREV")" == "陳小明" ]] || fail "lastName 改動未落地：$(jq -c '.identity' <<<"$IREV")"
[[ "$(jq -r '.identity.first_name' <<<"$IREV")" == "Ming" ]] || fail "單欄改動丟了 firstName"
[[ "$(jq -r '.identity.city' <<<"$IREV")" == "Taipei" ]] || fail "單欄改動丟了 city"
[[ "$(jq -r '.identity.email' <<<"$IREV")" == "ming@example.test" ]] || fail "單欄改動丟了 email"
pass "lane4 identity 讀寫（18 欄建檔、單欄改他欄存活、type==4 落庫）"

# —— 3（lane 5）雙裝置併發：A 改卡號、B 改效期同存，無整筆互贏 ——
B sync >/dev/null   # B 鏡像對齊當前 rev
docker stop "$VW" >/dev/null
A edit "$CID" --set "card.number=$CARD_NUM2" >/dev/null   # A 離線改卡號
docker start "$VW" >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
B edit "$CID" --set card.expMonth=9 >/dev/null            # B 帶舊 base 改效期
drained A 60 || fail "A 併發改動未收斂"
drained B 60 || fail "B 併發改動未收斂"
A sync >/dev/null
CREV=$(A reveal "$CID" --json)
[[ "$(jq -r '.card.number' <<<"$CREV")" == "$CARD_NUM2" ]] || fail "A 的卡號未收斂（整筆互贏？）"
[[ "$(jq -r '.card.exp_month' <<<"$CREV")" == "9" ]] || fail "B 的效期未收斂（整筆互贏？）"
[[ "$(jq -r '.card.code' <<<"$CREV")" == "$CVV" ]] || fail "併發合併洗掉了未觸及欄"
pass "lane5 雙裝置欄位級併發（卡號/效期各自收斂、無整筆互贏）"

# —— 4（lane 6）值搜尋（meta_plain v9）：併發收斂後的末四碼 1234 命中、姓氏命中 ——
HITS=$(A ls --value 1234 --json)
[[ "$(jq -r ".[0].meta.id" <<<"$HITS")" == "$CID" ]] || fail "卡號末四碼值搜尋未命中：$(jq -c '[.[] | .meta.name]' <<<"$HITS")"
[[ "$(jq '[.[] | select(.meta.kind != "Card")] | length' <<<"$HITS")" == "0" ]] \
  || fail "值搜尋混入非卡片列"
[[ "$(jq -e "[.[] | has(\"card\") or has(\"password\") or has(\"username\")] | all(not)" <<<"$HITS")" == "true" ]] \
  || fail "List 值搜尋出口帶型別節明文（鏡像層洩漏）"
IHITS=$(A ls --value "$SURNAME" --json)
[[ "$(jq -r ".[0].meta.id" <<<"$IHITS")" == "$IID" ]] || fail "姓氏值搜尋未命中身分檔"
pass "lane6 值搜尋（末四碼精確命中、姓氏前綴命中、明文不出 List 出口）"

# —— 5（lane 7）import 往返：官方 JSON 含 card→匯入→回讀欄不丟 ——
cat > "$DA/imp-card.json" <<JSON
{"encrypted": false, "items": [
  {"type": 3, "name": "匯入卡", "folderId": null, "favorite": false,
   "notes": null, "fields": [],
   "card": {"cardholderName": "Import User", "brand": "Mastercard",
            "number": "5500005500004242", "expMonth": "6", "expYear": "2035",
            "code": "321"}}
]}
JSON
IMP=$(A import "$DA/imp-card.json")
[[ "$(jq -r .imported <<<"$IMP")" == "1" ]] || fail "import 未收（got $IMP）"
drained A 40 || fail "import 未推完"
IMPID=$(A ls --json | jq -r '.[] | select(.meta.name=="匯入卡") | .meta.id')
IREVEAL=$(A reveal "$IMPID" --json)
[[ "$(jq -r '.card.brand' <<<"$IREVEAL")" == "Mastercard" ]] || fail "import 品牌丟失"
[[ "$(jq -r '.card.number' <<<"$IREVEAL")" == "5500005500004242" ]] || fail "import 卡號丟失"
[[ "$(jq -r '.card.exp_year' <<<"$IREVEAL")" == "2035" ]] || fail "import 效期丟失"
pass "lane7 import 往返（官方 JSON card 節六欄全存活；匯出端等位斷言見 GUI 單測 export 行構造）"

# —— 6（lane 8 等位）Reveal 審計座標：card reveal 記 CardNumber/CardCode ——
# （lane2/3/5 的多次 Reveal 已落審計筆；此處只驗座標形態，不再 lock/unlock——
# e2e 裝置未封存生物鑰，解鎖需主密碼stdin，見 readpath A12 形態）
AUD=$(A audit --tail 400 --json)
jq -e --arg id "$CID" '[.[] | select(.action=="Reveal.Get" and .item==$id and .field=="CardNumber")] | length >= 1' <<<"$AUD" >/dev/null \
  || fail "audit 未記 CardNumber 座標"
jq -e --arg id "$CID" '[.[] | select(.action=="Reveal.Get" and .item==$id and .field=="CardCode")] | length >= 1' <<<"$AUD" >/dev/null \
  || fail "audit 未記 CardCode 座標"
pass "lane8 敏感度座標消費（Reveal 審計逐欄記 CardNumber/CardCode）"

# —— 7 conditionalEncString 寬容：REST 直改明文效期→投影照讀 ——
CUR=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$CID")
NEW=$(jq --arg p "$PLAIN_EXP" '.card.expMonth = $p | del(.object, .edit, .viewPassword, .organizationUseTotp, .creationDate, .deletedDate, .archivedDate, .permissions)' <<<"$CUR")
curl -fsS -X PUT -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d "$NEW" "$SRV/api/ciphers/$CID" >/dev/null
A sync >/dev/null
[[ "$(jq -r '.card.exp_month' <<<"$(A reveal "$CID" --json)")" == "$PLAIN_EXP" ]] \
  || fail "明文 expMonth 未寬容：server=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$CID" | jq -c .card) daemon=$(A reveal "$CID" --json | jq -c .card)"
pass "conditionalEncString 明文寬容態（伺服器端明文欄原樣可讀）"

# —— 8 盤上紀律：全卡號明文不落鏡像層（v9 索引只收末四碼）——
A sync >/dev/null
grep -a "$CARD_NUM2" "$DA/vault.db" >/dev/null && fail "全卡號明文進鏡像層（v9 索引只收末四碼）" || true
pass "v9 明文索引紀律（鏡像密文原樣、全號明文不在盤）"

echo "PR1 CARDID E2E: ALL PASS"
