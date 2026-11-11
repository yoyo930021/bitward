#!/usr/bin/env bash
# 路線 1（macOS 設定面補齊）e2e（VW 1.37.2，port 18137）。需要 docker。
# 斷言鏈：設定預設相容（舊庫無 settings 行＝官方 15分/20秒/true/true）→
# 往返＋值域拒收→自動鎖定實測（1 分鐘：解鎖帶 deadline→閒置轉 AuthLocked→
# 解鎖可回）→重啟語意（lock_on_sleep_restart=false 啟動自動解鎖＋設定存活）→
# passkey 刪除收斂（建→REST 看 fido2Credentials→刪→REST 清）→
# match 寫入 REST 直讀（1→null 回落）→generate 預設 20 字元四类全開＋--no-* 關閉。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-settings
PORT=18137
DA=dev/e2e/data-settings
WP="SetMaster-7kQ!z"
EMAIL="set-$(date +%s)@bitward.test"
SRV="http://127.0.0.1:$PORT"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

cleanup() {
  [[ -n "${PID_A:-}" ]] && kill "$PID_A" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA"
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }
drained() { # $1=timeout 秒
  for _ in $(seq 1 "${1:-40}"); do
    [[ "$(A outbox --json | jq "$PENDING")" == "0" ]] && return 0
    sleep 1
  done
  return 1
}
STATE() { A status --json | jq -r '.state | keys[0]'; }

cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1 || true
docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done

mkdir -p "$DA"
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >"$DA/log" 2>&1 & PID_A=$!
sleep 1
A() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" "$@"; }

# 1) 預設值相容：新庫（無 settings 行）＝官方寫死預設。
S=$(A settings show --json)
[[ "$(jq -r .auto_lock_minutes <<<"$S")" == "15" ]] || fail "auto_lock 預設非 15（$S）"
[[ "$(jq -r .clipboard_clear_secs <<<"$S")" == "20" ]] || fail "clipboard 預設非 20（$S）"
[[ "$(jq -r .lock_on_sleep_restart <<<"$S")" == "true" ]] || fail "重啟鎖定預設非 true"
[[ "$(jq -r .clear_search_on_lock <<<"$S")" == "true" ]] || fail "清搜尋預設非 true"
pass "舊庫無 settings 行＝官方預設 15分/20秒/true/true"

echo "$WP" | A dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | A login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
# 預設 15 分鐘政策已餵進狀態機：解鎖態必帶 idle deadline。
DL=$(A status --json | jq -r '.state.Unlocked.deadline_epoch_ms // empty')
[[ -n "$DL" && "$DL" != "null" ]] || fail "預設自動鎖定未套 policy（deadline 缺席）"
pass "登入解鎖＋自動鎖定 policy 落地（deadline=$DL）"

# 2) 設定往返＋值域拒收。
A settings set '{"auto_lock_minutes":5,"clipboard_clear_secs":60,"lock_on_sleep_restart":false,"clear_search_on_lock":false}' >/dev/null
S=$(A settings show --json)
[[ "$(jq -r .auto_lock_minutes <<<"$S")" == "5" ]] || fail "往返 auto_lock != 5（$S）"
[[ "$(jq -r .clipboard_clear_secs <<<"$S")" == "60" ]] || fail "往返 clipboard != 60（$S）"
[[ "$(jq -r .lock_on_sleep_restart <<<"$S")" == "false" ]] || fail "重啟鎖定未落地"
[[ "$(jq -r .clear_search_on_lock <<<"$S")" == "false" ]] || fail "清搜尋未落地"
if A settings set '{"auto_lock_minutes":7}' >/dev/null 2>&1; then
  fail "非官方層級 7 分鐘未拒收"
fi
pass "設定往返＋層級外值域拒收"

# 3) 自動鎖定實測：1 分鐘閾值→閒置（status 輪詢豁免不餵活）→AuthLocked→解鎖可回。
A settings set '{"auto_lock_minutes":1,"clipboard_clear_secs":60,"lock_on_sleep_restart":false,"clear_search_on_lock":false}' >/dev/null
A unlock >/dev/null
[[ "$(STATE)" == "Unlocked" ]] || fail "解鎖後狀態非 Unlocked"
LOCKED=no
for _ in $(seq 1 90); do
  [[ "$(STATE)" == "AuthLocked" ]] && { LOCKED=yes; break; }
  sleep 1
done
[[ "$LOCKED" == "yes" ]] || fail "閒置 90 秒未自動鎖定（idle 計時器未生效或輪詢餵活）"
A unlock >/dev/null
[[ "$(STATE)" == "Unlocked" ]] || fail "自動鎖定後解鎖不回"
pass "自動鎖定實測：1 分鐘閒置轉 AuthLocked、解鎖可回（status 輪詢不重計時）"

# 4) 重啟語意：lock_on_sleep_restart=false→daemon 重啟以封存金鑰自動解鎖＋設定存活。
kill "$PID_A" 2>/dev/null || true
sleep 2
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >>"$DA/log" 2>&1 & PID_A=$!
sleep 2
S=$(A settings show --json)
[[ "$(jq -r .auto_lock_minutes <<<"$S")" == "1" ]] || fail "重啟後設定未持久（$S）"
[[ "$(STATE)" == "Unlocked" ]] || fail "lock_on_sleep_restart=false 重啟未自動解鎖"
pass "重啟：設定持久＋lock_on_sleep_restart=false 自動解鎖落地"
# 後續鏈（passkey/match）依賴穩定解鎖態：收掉 1 分鐘計時器免與 60s 級 drain 賽跑。
A settings set '{"auto_lock_minutes":0,"clipboard_clear_secs":60,"lock_on_sleep_restart":false,"clear_search_on_lock":false}' >/dev/null

# 5) passkey 刪除收斂：建→REST 看 fido2Credentials→刪→REST 清＋列表收斂。
A passkey register --rp webauthn.test --user alice --challenge cha1 >/dev/null
drained 60 || fail "passkey 註冊未收斂"
PK=$(A passkey list --json)
CRED=$(jq -r '.[0].credential_id' <<<"$PK")
PID=$(jq -r '.[0].item_id' <<<"$PK")
[[ -n "$CRED" && -n "$PID" && "$PID" != "null" ]] || fail "GetPasskeys 未帶 credential/item 歸屬（$PK）"
CW=$(curl -fsS -H "Authorization: Bearer $(jq -r .access_token "$DA/account.json")" "$SRV/api/ciphers/$PID")
[[ "$(jq '.login.fido2Credentials | length' <<<"$CW")" == "1" ]] || fail "伺服器端 fido2Credentials 未落地"
A passkey rm "$PID" "$CRED" >/dev/null
drained 60 || fail "passkey 刪除未收斂"
for _ in $(seq 1 20); do
  CW=$(curl -fsS -H "Authorization: Bearer $(jq -r .access_token "$DA/account.json")" "$SRV/api/ciphers/$PID")
  [[ "$(jq '(.login.fido2Credentials // []) | length' <<<"$CW")" == "0" ]] && break
  sleep 1
done
[[ "$(jq '(.login.fido2Credentials // []) | length' <<<"$CW")" == "0" ]] \
  || fail "REST 端 fido2Credentials 未隨刪除收斂"
[[ "$(A passkey list --json | jq 'length')" == "0" ]] || fail "鏡像列表未隨刪除收斂"
pass "passkey 刪除：鏡像摘除＋VW PUT 收 fido2Credentials 清空實錄"

# 6) URI match 寫入 REST 直讀：null→1→回落 null。
A new --name matchitem --uri https://m.test >/dev/null
drained 60 || fail "matchitem 建立未收斂"
A sync >/dev/null
MID=$(A ls --json | jq -r '.[] | select(.meta.name=="matchitem") | .meta.id')
TOK=$(jq -r .access_token "$DA/account.json")
A edit "$MID" --set-uri-match 0=1 >/dev/null
drained 60 || fail "match 寫入未收斂"
for _ in $(seq 1 20); do
  CW=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$MID")
  [[ "$(jq '.login.uris[0].match' <<<"$CW")" == "1" ]] && break
  sleep 1
done
[[ "$(jq '.login.uris[0].match' <<<"$CW")" == "1" ]] \
  || fail "REST 端 uris[0].match != 1（got $(jq '.login.uris[0].match' <<<"$CW")）"
# Masked 投影基準值（GUI 下拉資料源）同步可見
[[ "$(A get "$MID" --view masked --json | jq -r '.meta.uri_matches[0]')" == "1" ]] \
  || fail "Masked 投影未帶 uri_matches 基準"
A edit "$MID" --set-uri-match 0=null >/dev/null
drained 60 || fail "match 回落未收斂"
for _ in $(seq 1 20); do
  CW=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$MID")
  [[ "$(jq '.login.uris[0].match' <<<"$CW")" == "null" ]] && break
  sleep 1
done
[[ "$(jq '.login.uris[0].match' <<<"$CW")" == "null" ]] || fail "REST 端 match 未回落 null"
pass "URI match：寫入/投影/回落全鏈 REST 直讀收斂"

# 7) generate：隨機數在 daemon（Use:GeneratePassword 與 macOS GUI 同源）。
#    預設 20 字元、四类全開——引擎保證每個啟用字集至少一個，斷言照此驗。
GEN=$(A generate)
[[ ${#GEN} -eq 20 ]] || fail "generate 預設長度非 20：$GEN"
for cls in '[a-z]' '[A-Z]' '[0-9]' '[!@#$%^&*]'; do
  grep -qE "$cls" <<<"$GEN" || fail "generate 預設缺字類 $cls：$GEN"
done
GEN2=$(A generate --length 8 --no-uppercase --no-numbers --no-special)
[[ ${#GEN2} -eq 8 ]] || fail "generate --length 8 未生效：$GEN2"
grep -qE '^[a-z]+$' <<<"$GEN2" || fail "generate --no-* 未關字類：$GEN2"
pass "generate：預設 20 字元含四类、--length/--no-* 生效（daemon 引擎）"

echo "settings.sh ALL GREEN"
