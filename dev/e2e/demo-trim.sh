#!/usr/bin/env bash
# demo 庫清帳（冪等）：策展保留清單以外的項目全數軟刪→Purge，垃圾桶掃平。
# 保留清單每名各留第一筆（同名多餘副本＝歷輪 e2e 淨增種子，一併清）；
# 連現存 demo daemon（不重啟、不動 pkg 管線），走批次 3/4a 的 Delete+Purge 面。
# 用法：dev/e2e/demo-trim.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

D() { BITWARD_DATA_DIR=$PWD/dev/e2e/demo ./target/debug/bitward --sock dev/e2e/demo/s "$@"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'
KEEP='["GitHub","GitHub 測試","AWS Console","Local OTP","API token 範本","網銀 個人","webauthn.io","bitward-selftest"]'

# 選擇器：非保留名全中；保留名命中「同名的非首筆」。ls 預設 name 序，
# 首筆＝策展本體。輸入＝ls --json，輸出＝每行一個 id。
select_ids() {
  jq -r --argjson keep "$KEEP" '
    [ .[].meta | {name: (.name // ""), id} ] as $items
    | $items | to_entries[]
    | . as $e
    | select(
        if ($e.value.name | IN($keep[])) then
          ([ $items[0:$e.key][] | select(.name == $e.value.name) ] | length) > 0
        else true end)
    | $e.value.id'
}

command -v jq >/dev/null || fail "需要 jq"
[[ -S dev/e2e/demo/s ]] || fail "demo daemon 未在線（dev/e2e/demo/s）"
SRV=$(jq -r .server dev/e2e/demo/account.json)
curl -fsS --max-time 5 "$SRV/alive" >/dev/null 2>&1 || fail "demo server 不可達（$SRV）：Purge 需線上硬刪"
D unlock >/dev/null 2>&1 || true # 冪等：已解鎖回 AlreadyUnlocked

# 基線：只報告不阻塞——demo 庫可能帶歷史衝突列（同 item FIFO 會卡住新列，
# 但下方 Purge 連帶摘該 item 全部 outbox 列，卡住的隨清帳對象一起消失）
echo "基線 outbox：$(D outbox --json | jq -c .outbox)"

SNAP=$(D ls --json)
TRASH_IDS=$(D ls --trash --json | jq -r '.[].meta.id')
EXPECTED=$(jq -n --argjson keep "$KEEP" --argjson snap "$SNAP" \
  '[$snap[].meta.name // empty] | unique | map(select(IN($keep[]))) | length')
VICTIMS=$(select_ids <<<"$SNAP")
BEFORE=$(jq 'length' <<<"$SNAP")
echo "清帳目標：現 $BEFORE 筆＋垃圾桶 ${TRASH_IDS:+$(wc -l <<<"$TRASH_IDS" | tr -d ' ')}${TRASH_IDS:-0} 筆 → 保留 $EXPECTED 筆"

if [[ -n "$VICTIMS" ]]; then
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    out=$(D rm "$id" 2>&1) || fail "rm $id: $out"
  done <<<"$VICTIMS"
fi

# Purge：NotFound＝週期 sync 已把垃圾桶列摘走（VW /sync 不含軟刪項），屬已收斂。
# 先 purge 再等收斂——被歷史衝突卡住的列會隨 purge 一併清除，無需先推空。
purge_tolerant() {
  local id="$1" out
  if ! out=$(D purge "$id" 2>&1); then
    case "$out" in
      *NotFound*|*"not found"*) : ;;
      *) fail "purge $id: $out" ;;
    esac
  fi
}
for id in $VICTIMS $TRASH_IDS; do purge_tolerant "$id"; done

for _ in $(seq 1 180); do [[ "$(D outbox --json | jq "$PENDING")" == "0" ]] && break; sleep 1; done
[[ "$(D outbox --json | jq "$PENDING")" == "0" ]] || {
  D outbox --json | jq -c .outbox
  fail "清帳後佇列未歸零（殘留列不屬清帳對象，先人工收拾）"
}

AFTER=$(D ls --json | jq 'length')
[[ "$(D ls --trash --json | jq 'length')" == "0" ]] || fail "清帳後垃圾桶未掃平"
[[ "$AFTER" == "$EXPECTED" ]] || fail "清帳後筆數 $AFTER ≠ 保留清單 $EXPECTED"
pass "清帳收斂：$AFTER 筆＝保留清單、垃圾桶 0"

# 冪等驗證：第二輪选择必須 0 變更
VICTIMS2=$(select_ids <<<"$(D ls --json)")
[[ -z "$VICTIMS2" ]] || fail "冪等破壞：第二輪仍選出 $(wc -l <<<"$VICTIMS2" | tr -d ' ') 筆"
[[ "$(D ls --json | jq 'length')" == "$AFTER" ]] || fail "冪等破壞：筆數漂移"
pass "冪等：第二輪 0 變更"

echo "DEMO-TRIM: ALL PASS"
