#!/usr/bin/env bash
# v5 三件套 e2e：SecureNote／資料夾／自訂欄＋垃圾桶三態（Main 裁定追加）。
# 官方兼容硬證據：curl 直讀 VW REST /ciphers/{id} 斷言線格式
# （type/folderId/fields 欄位形態與官方客戶端一致）。需要 docker。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-vt
PORT=18121
DA=dev/e2e/data-vt-a
DB=dev/e2e/data-vt-b
WP="VtMaster-9kQ!z"
HIDDEN="hunt3r-§"
NOTE_BODY="筆記內文-§α"
EMAIL="vt-$(date +%s)@bitward.test"
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
drained() { # $1=fn  $2=timeout
  for _ in $(seq 1 "${2:-30}"); do
    [[ "$($1 outbox --json | jq "$PENDING")" == "0" ]] && return 0
    sleep 1
  done
  return 1
}

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
pass "雙裝置登入（A、B）"

# 1) 建資料夾 → folder ls 看得到明文名
FID=$(A --json folder create 工作 | jq -r .id)
[[ -n "$FID" && "$FID" != "null" ]] || fail "folder create 未回 id"
[[ "$(A --json folder ls | jq -r --arg f "$FID" '.[] | select(.id==$f) | .name')" == "工作" ]] \
  || fail "folder ls 未列明文名"
pass "資料夾建立＋清單（名稱 user key 加密、解鎖解明文）"

# 2) 建 SecureNote 入夾、建 login 帶 hidden field（Create 回 Ok：id 以鏡像查詢取回）
A new --name note1 --type note --folder "$FID" --notes "$NOTE_BODY" >/dev/null
A new --name login1 --username u1 --field site=acme --field! secret="$HIDDEN" >/dev/null
drained A 40 || fail "初始寫入未收斂"
NID=$(A ls --json | jq -r '.[] | select(.meta.name=="note1") | .meta.id')
LID=$(A ls --json | jq -r '.[] | select(.meta.name=="login1") | .meta.id')
[[ -n "$NID" && "$NID" != "null" ]] || fail "note1 未入列"
[[ -n "$LID" && "$LID" != "null" ]] || fail "login1 未入列"
[[ "$(jq -r '.[0].meta.kind' <<<"$(A ls --folder "$FID" --json)")" == "SecureNote" ]] \
  || fail "note1 kind 投影錯誤（查證點 1：daemon 建立不再寫死 Login）"
pass "SecureNote 入夾＋login 帶 hidden 欄（create 收斂）"

# 3) List 過濾三態：全部／夾／未歸屬
ALL=$(A ls --json | jq 'length')
IN=$(A ls --folder "$FID" --json | jq 'length')
OUT=$(A ls --folder "" --json | jq 'length')
[[ "$ALL" == "2" ]] || fail "三態：全部=$ALL != 2"
[[ "$IN" == "1" && "$(A ls --folder "$FID" --json | jq -r '.[0].meta.id')" == "$NID" ]] \
  || fail "三態：夾內過濾未只含 note1"
[[ "$OUT" == "1" && "$(A ls --folder "" --json | jq -r '.[0].meta.id')" == "$LID" ]] \
  || fail "三態：未歸屬過濾未只含 login1"
pass "List 三態過濾（全部/夾/未歸屬）"

# 4) 詳情：筆記可見、hidden 欄值 masked 缺席、reveal 才出
[[ "$(A get "$NID" --view masked --json | jq -r .notes)" == "$NOTE_BODY" ]] \
  || fail "note 詳情未顯示筆記"
MASKED_HAS=$(A get "$LID" --view masked --json | jq -r '.fields[1].value')
[[ "$MASKED_HAS" == "null" ]] || fail "hidden 欄值在 Masked 視窗外洩：$MASKED_HAS"
[[ "$(A get "$LID" --view masked --json | jq -r '.fields[0].value')" == "acme" ]] \
  || fail "text 欄值 Masked 應可見"
REV=$(A reveal "$LID" --json | jq -r '.fields[1].value')
[[ "$REV" == "$HIDDEN" ]] || fail "reveal 未出 hidden 值"
DET=$(A reveal "$LID")
[[ "$DET" == *"field[hidden]: secret"* ]] || fail "詳情排版缺 hidden 欄列"
pass "詳情顯示筆記/自訂欄（hidden 值僅 reveal）"

# 5) 官方兼容硬證據：curl 直讀 VW REST /ciphers/{id}
TOK=$(jq -r .access_token "$DA/account.json")
NOTE_W=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$NID")
[[ "$(jq -r .type <<<"$NOTE_W")" == "2" ]] || fail "REST note type != 2"
[[ "$(jq -r .folderId <<<"$NOTE_W")" == "$FID" ]] || fail "REST note folderId 未落"
[[ "$(jq '.login' <<<"$NOTE_W")" == "null" ]] || fail "REST type 2 不應帶 login"
[[ "$(jq -r '.secureNote.type' <<<"$NOTE_W")" == "0" ]] || fail "REST 缺 secureNote 子物件（官方形）"
jq -r .notes <<<"$NOTE_W" | grep -q '^2\.' || fail "REST notes 非信封字串"
! grep -q "$NOTE_BODY" <<<"$NOTE_W" || fail "REST notes 明文外洩"
LOGIN_W=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$LID")
[[ "$(jq '.fields | length' <<<"$LOGIN_W")" == "2" ]] || fail "REST fields 數 != 2"
[[ "$(jq -r '.fields[1].type' <<<"$LOGIN_W")" == "1" ]] || fail "REST hidden 欄 type != 1"
[[ "$(jq -r '.fields[0].type' <<<"$LOGIN_W")" == "0" ]] || fail "REST text 欄 type != 0"
jq -r '.fields[1].name' <<<"$LOGIN_W" | grep -q '^2\.' || fail "REST 欄名非信封字串"
jq -r '.fields[1].value' <<<"$LOGIN_W" | grep -q '^2\.' || fail "REST 欄值非信封字串"
! grep -q "$HIDDEN" <<<"$LOGIN_W" || fail "REST hidden 值明文外洩"
pass "官方線格式 REST 直讀驗證（type/folderId/fields）"

# 6) 欄位級雙裝置：A 改 fields[0].value 不動欄名；B 改 name；另一端可見雙存活
A edit "$LID" --set field.0.value=rotated >/dev/null
drained A 40 || fail "A 欄位改動未收斂"
B sync >/dev/null
B edit "$LID" --set name=renamed-by-b >/dev/null
drained B 40 || fail "B name 改動未收斂"
A sync >/dev/null
NAME=$(A ls --json | jq -r ".[] | select(.meta.id==\"$LID\") | .meta.name")
[[ "$NAME" == "renamed-by-b" ]] || fail "欄位級：B 的 name 未收斂（got $NAME）"
A_REVEAL=$(A reveal "$LID" --json)
[[ "$(jq -r '.fields[0].value' <<<"$A_REVEAL")" == "rotated" ]] || fail "欄位級：A 的欄值被覆蓋"
[[ "$(jq -r '.fields[0].name' <<<"$A_REVEAL")" == "site" ]] || fail "欄位級：改值動到欄名"
[[ "$(jq -r '.fields[1].value' <<<"$A_REVEAL")" == "$HIDDEN" ]] || fail "欄位級：hidden 欄未存活"
pass "欄位級合併（改 fields[0] 值，name 與另一端改動雙存活）"

# 7) 垃圾桶三態＋硬刪（Main 裁定）
A rm "$NID" >/dev/null
drained A 40 || fail "軟刪未收斂"
TRASH=$(A ls --trash --json)
[[ "$(jq -r ".[] | select(.meta.id==\"$NID\") | .meta.deleted_at" <<<"$TRASH")" != "null" ]] \
  || fail "List(deleted=true) 未含軟刪項或未帶 deleted_at"
[[ "$(jq --arg n "$LID" '[.[] | select(.meta.id==$n)] | length' <<<"$TRASH")" == "0" ]] \
  || fail "List(deleted=true) 混入未刪項"
[[ "$(A ls --json | jq --arg n "$NID" '[.[] | select(.meta.id==$n)] | length')" == "0" ]] \
  || fail "默認 List 仍含軟刪項"
A purge "$NID" >/dev/null
[[ "$(A ls --trash --json | jq --arg n "$NID" '[.[] | select(.meta.id==$n)] | length')" == "0" ]] \
  || fail "Purge 後垃圾桶仍含它"
sleep 1
# VW 1.37.2 對不存在/已硬刪 cipher 的 GET 回 400（實錄；404 為官方雲形態），
# 兩者皆＝伺服器不再返回此 cipher（/sync grep 斷言補位復活疑慮）。
PURGE_W=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$NID")
[[ "$PURGE_W" == 400 || "$PURGE_W" == 404 ]] || fail "Purge 後伺服器仍可讀（$PURGE_W）"
[[ "$(curl -s -H "Authorization: Bearer $TOK" "$SRV/api/sync" | grep -c "$NID")" == "0" ]] \
  || fail "Purge 後 /sync 仍含該 cipher（會復活）"
pass "軟刪→垃圾桶三態（deleted_at）→Purge 本地＋伺服器永久移除"

# 8) 項目歸屬 patch → 刪夾 → 項目未歸屬
A edit "$LID" --set folderId="$FID" >/dev/null
drained A 40 || fail "folderId patch 未收斂"
[[ "$(A ls --folder "$FID" --json | jq -r '.[0].meta.id')" == "$LID" ]] || fail "歸屬後未列進夾"
A folder delete "$FID" >/dev/null
drained A 40 || fail "刪夾後項目 detach 未收斂"
[[ "$(A --json folder ls | jq 'length')" == "0" ]] || fail "刪夾後鏡像仍列"
[[ "$(A ls --folder "" --json | jq -r '.[0].meta.id')" == "$LID" ]] || fail "刪夾後項目未變未歸屬"
LOGIN_W2=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$LID")
[[ "$(jq -r .folderId <<<"$LOGIN_W2")" == "null" ]] || fail "REST folderId 未清 NULL"
FW=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$SRV/api/folders/$FID")
[[ "$FW" == 404 || "$FW" == 400 ]] || fail "REST 資料夾仍在（$FW）"
[[ "$(curl -s -H "Authorization: Bearer $TOK" "$SRV/api/sync" | grep -c "$FID")" == "0" ]] \
  || fail "/sync folders[] 仍含已刪資料夾"
pass "刪除資料夾：夾內項目 folderId 清 NULL（官方語意）"

# 9) 盤上明文紀律：hidden 欄值不得進明文索引（欄名可以）
grep -a "$HIDDEN" "$DA/vault.db" && fail "hidden 欄值洩盤（明文索引）" || true
grep -a "$NOTE_BODY" "$DA/vault.db" >/dev/null || true  # notes 是 Reveal 出口，不落索引＝可接受缺席
pass "hidden 欄值未進明文索引"

echo "V5 VAULTTYPES E2E: ALL PASS"
