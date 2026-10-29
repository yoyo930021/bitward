#!/usr/bin/env bash
# P3 agent 治理面 e2e（契約 §2.3、§4 缺口表第 1 列）：session/grant/redactor/
# human-in-the-loop 核准、MCP stdio 轉譯。核心出口斷言＝$SECRET 在整個 MCP
# stdout 淨洩漏（grep -c == 0），唯一例外是 f 的核准後明文。需要 docker + jq。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-p3
PORT=18085
DATA=dev/e2e/data-p3
WP="P3Master-9kQ!z"
SECRET="p3-s3cret-XYZ"
EMAIL="p3-$(date +%s)@bitward.test"
UUID_RE='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

cleanup() {
  for p in "${PID_D:-}" "${PID_MCP_A:-}" "${PID_MCP_F:-}" "${PID_MCP_G:-}"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
  done
  docker rm -f "$VW" >/dev/null 2>&1 || true
  rm -rf "$DATA"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $1" >&2
  if [[ -f "$DATA/log" ]]; then
    echo "--- daemon log tail ---" >&2
    tail -50 "$DATA/log" >&2 || true
  fi
  exit 1
}
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward -p bitward-mcp

docker run -d --name "$VW" -p $PORT:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
  vaultwarden/server:1.37.2 >/dev/null
READY=0
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/alive" >/dev/null 2>&1 && { READY=1; break; }
  sleep 1
done
[[ "$READY" == 1 ]] || fail "Vaultwarden 未在 30 秒內就緒"

SOCK="$DATA/daemon.sock"
mkdir -p "$DATA"
BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitwarderd --data-dir "$DATA" --sock "$SOCK" >"$DATA/log" 2>&1 &
PID_D=$!
for _ in $(seq 1 20); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
B() { BITWARD_DATA_DIR=$PWD/$DATA ./target/debug/bitward --sock "$SOCK" "$@"; }
SRV="http://127.0.0.1:$PORT"

echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$SECRET" | B new --name agent1 --password-stdin >/dev/null
B sync >/dev/null
pass "VW+daemon+login+agent1 就緒"

# —— MCP 驅動器：FIFO 餵 stdin（fd 保持不 EOF），stdout 落檔逐行斷言 ——
declare -A MCP_FD MCP_PID

mcp_start() { # $1=tag $2=token（空＝本機全權 Enroll）
  local tag=$1 tok=$2 d="$DATA/mcp-$1"
  mkdir -p "$d"
  mkfifo "$d/in"
  : >"$d/out"
  if [[ -n "$tok" ]]; then
    BITWARD_SOCK="$PWD/$SOCK" BITWARD_AGENT_TOKEN="$tok" \
      ./target/debug/bitward-mcp <"$d/in" >"$d/out" 2>"$d/err" &
  else
    BITWARD_SOCK="$PWD/$SOCK" \
      ./target/debug/bitward-mcp <"$d/in" >"$d/out" 2>"$d/err" &
  fi
  MCP_PID[$tag]=$!
  local fd
  exec {fd}<>"$d/in" # read-write 開啟：MCP 不會看到 EOF，直到我們主動 close
  MCP_FD[$tag]=$fd
}
# 計數器落盤：mcp_send 常在 $() 子程裡跑，記憶體變數的遞增會丟失。
RPC_COUNTER="$DATA/rpc.id"
mcp_send() { # $1=tag $2=method $3=params（JSON）；echo 該請求的 id
  local prev id
  prev=$(cat "$RPC_COUNTER" 2>/dev/null || echo 0)
  id=$((prev + 1))
  echo "$id" >"$RPC_COUNTER"
  printf '{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}\n' \
    "$id" "$2" "${3:-{\}}" >&"${MCP_FD[$1]}"
  echo "$id"
}
mcp_notify() { # $1=tag $2=method
  printf '{"jsonrpc":"2.0","method":"%s"}\n' "$2" >&"${MCP_FD[$1]}"
}
mcp_wait() { # $1=tag $2=id → 印出該 id 的回應行（串行服務＝行序＝id 序）
  local tag=$1 want=$2 out="$DATA/mcp-$1/out" line
  # 60 秒預算：f 的核准流程含背景 5 秒延遲＋poll 節拍。
  for _ in $(seq 1 600); do
    if line=$(jq -c --argjson w "$want" 'select(.id == $w)' "$out" 2>/dev/null | head -1) && [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    kill -0 "${MCP_PID[$tag]}" 2>/dev/null || fail "mcp-$tag 意外結束: $(cat "$DATA/mcp-$tag/err" 2>/dev/null)"
    sleep 0.1
  done
  fail "mcp-$tag 等 id=$want 逾時；stdout=$(cat "$out") stderr=$(cat "$DATA/mcp-$tag/err")"
}
mcp_tool() { # $1=tag $2=tool $3=arguments → 印出回應 JSON 行
  local id
  id=$(mcp_send "$1" tools/call "$(jq -nc --arg n "$2" --argjson a "${3:-{\}}" '{name:$n,arguments:$a}')")
  mcp_wait "$1" "$id"
}
text_of() { jq -r '.result.content[0].text // empty' <<<"$1"; }

# —— b：open session（grant: see:identity + use:totp；沒有 reveal）——
OPEN=$(B agent open --name e2e-agent --grant 'see:identity all; use:totp all' --ttl 3600 --json)
TOKEN=$(jq -r .token <<<"$OPEN")
SESSION=$(jq -r .session <<<"$OPEN")
[[ -n "$TOKEN" && "$TOKEN" != null ]] || fail "agent open 未回 token：$OPEN"
[[ "$SESSION" =~ $UUID_RE ]] || fail "agent open 未回 session uuid：$OPEN"
pass "b：e2e-agent session 建立（ttl 3600）"

# —— c/d：同一個 MCP 程序跑完 initialize→tools/list→vault_list→totp_code→vault_reveal ——
mcp_start A "$TOKEN"
IID=$(mcp_send A initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}')
INIT=$(mcp_wait A "$IID")
[[ $(jq -r '.result.protocolVersion' <<<"$INIT") == "2025-06-18" ]] || fail "initialize 版本錯：$INIT"
mcp_notify A notifications/initialized
LID=$(mcp_send A tools/list '{}')
TL=$(mcp_wait A "$LID")
for t in vault_list vault_get vault_reveal totp_code run audit_tail session_whoami; do
  jq -e --arg t "$t" '.result.tools | any(.[]; .name == $t)' <<<"$TL" >/dev/null \
    || fail "tools/list 缺 $t"
done
pass "d：tools/list 含全部 7 工具"

VL=$(mcp_tool A vault_list '{"text":"agent1"}')
[[ $(jq -r '.result.isError' <<<"$VL") == "false" ]] || fail "d：vault_list 失敗：$VL"
text_of "$VL" | grep -q agent1 || fail "d：vault_list 輸出不含 agent1：$(text_of "$VL")"
pass "d：vault_list 回 metadata 含 agent1"

A1=$(text_of "$VL" | jq -r '.Items[] | select(.meta.name=="agent1") | .meta.id')
[[ "$A1" =~ $UUID_RE ]] || fail "無法從 vault_list 取 agent1 uuid（got '$A1'）"

TC=$(mcp_tool A totp_code "$(jq -nc --arg i "$A1" '{id:$i}')")
[[ $(jq -r '.result.isError' <<<"$TC") == "true" ]] || fail "d：agent1 無 totp seed，totp_code 應回錯：$TC"
pass "d：totp_code 如期待回錯（無 seed）"

RV=$(mcp_tool A vault_reveal "$(jq -nc --arg i "$A1" '{id:$i}')")
[[ $(jq -r '.result.isError' <<<"$RV") == "true" ]] || fail "d：無 reveal grant 應被拒：$RV"
text_of "$RV" | grep -qiE 'grant|denied|授權' || fail "d：reveal 錯誤文字缺 grant/Denied 語意：$(text_of "$RV")"
pass "d：vault_reveal 被拒（授權語意在錯文）"

# P3 契約出口：整個 MCP stdout 不含 $SECRET（唯一的明文出口都被政策擋掉）
[[ $(grep -c "$SECRET" "$DATA/mcp-A/out") == 0 ]] || fail "d：MCP stdout 洩明文"
pass "d：契約出口——整個 MCP stdout 對 \$SECRET 淨空（grep -c == 0）"

# —— e：人類側 list/revoke；revoke 之後同一條 MCP 連線的回覆必須是錯 ——
AL=$(B agent list --json)
jq -e --arg s "$SESSION" 'any(.[]; (.id // .session // "" | tostring) == $s or (.name // "") == "e2e-agent")' <<<"$AL" >/dev/null \
  || fail "e：agent list 不含 e2e-agent：$AL"
pass "e：agent list 含 e2e-agent"
B agent revoke "$SESSION" >/dev/null
VL2=$(mcp_tool A vault_list '{}')
[[ $(jq -r '.result.isError' <<<"$VL2") == "true" ]] \
  || fail "e：revoke 後 vault_list 竟成功：$VL2"
text_of "$VL2" | grep -qiE 'drop|stale|revok|unknown session|撤銷|過期' \
  || fail "e：revoke 後錯誤文字非 dropped/stale 語意：$(text_of "$VL2")"
pass "e：revoke 級聯生效（vault_list 回 session 失效語意）"
eval "exec ${MCP_FD[A]}>&-"
wait "${MCP_PID[A]}" 2>/dev/null || true # stdin 關閉 → 正常 EOF 收工

# —— f：reveal:* approve 流程（daemon 阻塞等人工核准；MCP 無感轉譯）——
OPEN_F=$(B agent open --name gated --grant 'reveal:secret all approve' --ttl 600 --json)
TOKEN_F=$(jq -r .token <<<"$OPEN_F")
[[ "$TOKEN_F" != null && -n "$TOKEN_F" ]] || fail "f：gated open 失敗：$OPEN_F"
mcp_start F "$TOKEN_F"
mcp_send F initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}' >/dev/null
mcp_notify F notifications/initialized
RID=$(mcp_send F tools/call "$(jq -nc --arg i "$A1" '{name:"vault_reveal",arguments:{id:$i}}')")
# 背景批准：poll pending 取 id → approve（5 秒節拍，語意同規格）
(
  sleep 5
  for _ in $(seq 1 12); do
    AID=$(B agent pending --json 2>/dev/null | jq -r '.[0].id // empty' || true)
    if [[ -n "$AID" ]] && B approve "$AID" >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
) &
APPROVER=$!
FRV=$(mcp_wait F "$RID")
wait "$APPROVER" 2>/dev/null || true
[[ $(jq -r '.result.isError' <<<"$FRV") == "false" ]] || fail "f：核准後 vault_reveal 仍失敗：$FRV"
text_of "$FRV" | grep -q "$SECRET" || fail "f：核准後未回 \$SECRET 明文：$(text_of "$FRV")"
pass "f：NeedsApproval → 人工 approve → 同 call 成功，明文如約出現"
eval "exec ${MCP_FD[F]}>&-"
wait "${MCP_PID[F]}" 2>/dev/null || true

# —— g：run 出口淨化（Redactor：明文只進子程，stdout 淨化後才回）——
OPEN_G=$(B agent open --name runner --grant 'use:run all; use:env all' --ttl 600 --json)
TOKEN_G=$(jq -r .token <<<"$OPEN_G")
[[ "$TOKEN_G" != null && -n "$TOKEN_G" ]] || fail "g：runner open 失敗：$OPEN_G"
mcp_start G "$TOKEN_G"
mcp_send G initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}' >/dev/null
mcp_notify G notifications/initialized
RUN_ARGS=$(jq -nc --arg i "$A1" '{argv:["/bin/sh","-c","echo TOKEN=$TOKEN; echo done"],env:{TOKEN:("btw://" + $i + "/password")}}')
GRV=$(mcp_tool G run "$RUN_ARGS")
[[ $(jq -r '.result.isError' <<<"$GRV") == "false" ]] || fail "g：run 失敗：$GRV"
GTEXT=$(text_of "$GRV")
grep -q "done" <<<"$GTEXT" || fail "g：run 輸出不含 done：$GTEXT"
grep -q '«redacted»' <<<"$GTEXT" || fail "g：run 輸出未被淨化（缺 «redacted»）：$GTEXT"
if grep -q "$SECRET" <<<"$GTEXT"; then fail "g：run 輸出洩 \$SECRET"; fi
pass "g：run 淨化——含 done、含 «redacted»、不含 \$SECRET"
eval "exec ${MCP_FD[G]}>&-"
wait "${MCP_PID[G]}" 2>/dev/null || true

echo "P3 AGENT E2E: ALL PASS"
