#!/usr/bin/env bash
# 批次 4a 附件 e2e（VW 1.37.2，port 18131）。需要 docker。
# 斷言鏈：上傳收斂→鏡像元資料→下載位元組 round-trip→REST 直讀認得附件→
# 刪除收斂→離線上傳入佇列（autodrain 語意，不碰手動同步）→大小上限拒→
# 明文不落盤。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-att
PORT=18131
DA=dev/e2e/data-att
WP="AttMaster-7kQ!z"
EMAIL="att-$(date +%s)@bitward.test"
SRV="http://127.0.0.1:$PORT"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

cleanup() {
  [[ -n "${PID_A:-}" ]] && kill "$PID_A" 2>/dev/null || true
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DA" /tmp/att-e2e-*
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }
drained() { # $1=timeout
  for _ in $(seq 1 "${1:-40}"); do
    [[ "$(A outbox --json | jq "$PENDING")" == "0" ]] && return 0
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

mkdir -p "$DA"
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >"$DA/log" 2>&1 & PID_A=$!
sleep 1
A() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock "$DA/s" "$@"; }

echo "$WP" | A dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | A login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
A new --name withfile >/dev/null
drained 40 || fail "初始建立未收斂"
CID=$(A ls --json | jq -r '.[0].meta.id')
TOK=$(jq -r .access_token "$DA/account.json")
pass "daemon 登入＋目標 cipher 就緒"

# 1) 上傳真檔（100KB 隨機）→ drain 收斂 → 鏡像元資料
head -c 102400 /dev/urandom > /tmp/att-e2a.bin
SHA_A=$(shasum -a 256 /tmp/att-e2a.bin | cut -d' ' -f1)
A attach add "$CID" /tmp/att-e2a.bin >/dev/null
drained 60 || fail "附件上傳未收斂（outbox 滯留）"
A sync >/dev/null
VIEW=$(A get "$CID" --view masked --json)
ATT_ID=$(jq -r '.attachments[0].id // empty' <<<"$VIEW")
[[ -n "$ATT_ID" ]] || fail "/sync 後鏡像未含附件元資料"
[[ "$(jq -r '.attachments[0].fileName // .attachments[0].file_name // empty' <<<"$VIEW")" != "" ]] \
  || { ATT_NAME=$(jq -r '.attachments[0] | .fileName // .file_name' <<<"$VIEW"); fail "附件檔名投影為空（got {$ATT_NAME}）"; }
jq -r '.attachments[0] | .fileName // .file_name' <<<"$VIEW" | grep -q 'att-e2a.bin' \
  || fail "附件檔名解密失敗（Masked 出口應帶明文名）"
# size 語意＝伺服器存放的**密文信封**位元組數（官方同形：存下的檔身含
# type.iv|ct|mac 前綴，必 ≥ 原檔；不是原檔明文大小）
[[ "$(jq -r '.attachments[0].size' <<<"$VIEW")" -ge 102400 ]] || fail "附件 size 元資料錯誤"
pass "上傳收斂＋鏡像含附件元資料（id/檔名/size）"

# 2) 下載 round-trip（sha256 比對）
A attach get "$CID" "$ATT_ID" /tmp/att-e2b.bin >/dev/null
SHA_B=$(shasum -a 256 /tmp/att-e2b.bin | cut -d' ' -f1)
[[ "$SHA_A" == "$SHA_B" ]] || fail "附件 round-trip 不一致（$SHA_A vs $SHA_B）"
pass "下載解密 round-trip sha256 一致"

# 3) REST 直讀 VW：官方客戶端視角認得附件、檔名是信封（不是明文）
CW=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$CID")
[[ "$(jq '.attachments | length' <<<"$CW")" == "1" ]] || fail "REST 端 attachments 缺失"
jq -r '.attachments[0].fileName // (.attachments | to_entries[0].value.fileName)' <<<"$CW" \
  | grep -q '^2\.' || fail "REST 檔名非信封字串（加密紀律失守）"
! grep -q 'att-e2a.bin' <<<"$CW" || fail "REST 回包洩明文檔名"
pass "REST 直讀：VW 認得附件且檔名為信封"

# 4) 明文不落盤（鏡像 db 與 blob 檔都只得見密文）
if ! python3 - "$DA" /tmp/att-e2a.bin <<'PY'
import os, sys
da, src = sys.argv[1], sys.argv[2]
probe = open(src, "rb").read(64)
hits = []
for root, _, files in os.walk(da):
    for f in files:
        p = os.path.join(root, f)
        try:
            if probe in open(p, "rb").read():
                hits.append(p)
        except OSError:
            pass
sys.exit(f"盤上出現附件明文: {hits}" if hits else 0)
PY
then fail "附件明文落盤"; fi
pass "附件內容盤上僅密文"

# 5) 刪除收斂
A attach rm "$CID" "$ATT_ID" >/dev/null
A sync >/dev/null
[[ "$(A get "$CID" --view masked --json | jq '.attachments | length')" == "0" ]] \
  || fail "刪除後鏡像仍含附件"
CW2=$(curl -fsS -H "Authorization: Bearer $TOK" "$SRV/api/ciphers/$CID")
[[ "$(jq '(.attachments // []) | length' <<<"$CW2")" == "0" ]] || fail "REST 端附件未刪"
pass "刪除收斂（鏡像與伺服器雙清）"

# 6) 離線上傳：停 VW → 入佇列（不推）→ 重啟 → autodrain 無感推上（不碰手動同步）
docker stop "$VW" >/dev/null
head -c 4096 /dev/urandom > /tmp/att-e2c.bin
SHA_C=$(shasum -a 256 /tmp/att-e2c.bin | cut -d' ' -f1)
A attach add "$CID" /tmp/att-e2c.bin >/dev/null
sleep 5
P=$(A outbox --json | jq "$PENDING")
[[ "$P" -ge 1 ]] || fail "離線上傳未入佇列（pending=$P）"
AW=$(A outbox --json | jq '.outbox.awaiting')
[[ "$AW" -ge 1 ]] || fail "佇列未以 Awaiting 態觀測（awaiting=$AW）"
docker start "$VW" >/dev/null
CONV=no
for _ in $(seq 1 90); do
    [[ "$(A outbox --json | jq "$PENDING")" == "0" ]] && { CONV=yes; break; }
    sleep 1
done
[[ "$CONV" == yes ]] || fail "VW 重啟後附件佇列未在 90 秒內自動收斂"
A sync >/dev/null
ATT2=$(A get "$CID" --view masked --json | jq -r '.attachments[0].id // empty')
[[ -n "$ATT2" ]] || fail "收斂後鏡像仍無附件"
A attach get "$CID" "$ATT2" /tmp/att-e2d.bin >/dev/null
[[ "$SHA_C" == "$(shasum -a 256 /tmp/att-e2d.bin | cut -d' ' -f1)" ]] || fail "離線佇列附件 round-trip 不一致"
pass "離線上傳入佇列（Awaiting）→ VW 回來無感收斂＋round-trip"

# 7) 大小上限拒（32MiB+1）
head -c $((32*1024*1024+1)) /dev/urandom > /tmp/att-e2big.bin
if A attach add "$CID" /tmp/att-e2big.bin >/dev/null 2>&1; then
  fail "超過 32MiB 上限竟被接受"
fi
drained 10 || fail "超限嘗試污染了佇列"
pass "大小上限（32MiB）拒收，佇列無污染"

echo "ATTACHMENTS E2E: ALL PASS"
