#!/usr/bin/env bash
# demo 驗收環境重建（一鍵、冪等重建語意）：VW 容器 + 全新帳號 + 策展種子 40 筆。
# 背景：bitward-vw-demo 開 I_REALLY_WANT_VOLATILE_STORAGE=true，容器重啟＝伺服器端
# 帳號/資料全滅（簽名鍵也重生成，舊 token/refresh 一律 401）；本腳本把
# server+daemon+種子一次重建，恢復 GUI 截圖 e2e 的固定資料面。
# 用法：dev/e2e/demo-seed.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

DA=dev/e2e/demo
VW=bitward-vw-demo
PORT=18095
SRV="http://127.0.0.1:$PORT"
WP='DemoMaster-9kQ!z'
EMAIL="demo-$(date +%s)@bitward.test"
PENDING='(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)'

B() { BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitward --sock $DA/s "$@"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
command -v docker >/dev/null || fail "需要 docker"
command -v jq >/dev/null || fail "需要 jq"
cargo build -q -p bitwarderd -p bitward
# 批次 14：GUI e2e 解鎖走離線 600k PBKDF2——debug daemon 單次派生 ~4s，
# 固定時間軸罩不住；e2e daemon 改 release 二進位（派生 ~300ms，且與使用者
# 實裝的 release daemon 同形，測得的解鎖延遲更具代表性）。CLI 仍 debug。
cargo build -q --release -p bitwarderd

# 1. VW 容器：在就重啟（VOLATILE＝舊帳號必死，重建帳號是常態路徑）、不在就建。
if docker ps -a --format '{{.Names}}' | grep -qx "$VW"; then
  docker start "$VW" >/dev/null
else
  docker run -d --name "$VW" -p $PORT:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 \
    vaultwarden/server:1.37.2 >/dev/null
fi
for _ in $(seq 1 30); do curl -fsS "$SRV/alive" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --max-time 3 "$SRV/alive" >/dev/null || fail "VW 未就绪（: $PORT）"

# 2. daemon：舊實例一律換掉、資料目錄整包重建（殘留 outbox 死信屬舊帳號）。
pkill -f "bitwarderd --data-dir $PWD/$DA" 2>/dev/null || true
sleep 0.3
rm -rf "$DA"
mkdir -p "$DA"
nohup ./target/release/bitwarderd --data-dir "$PWD/$DA" --sock "$DA/s" >"$DA/log" 2>&1 &
sleep 1
[[ -S "$DA/s" ]] || fail "daemon 未起（$DA/s）"

# 3. 帳號：註冊＋登入（login 內含 sync，解鎖由 device assertion 接手）。
echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$EMAIL" >"$DA/email.txt"
B status --json | jq -e '.state.Unlocked != null' >/dev/null || fail "login 後未解鎖"

# 4. 種子：資料夾＋策展 8 名（e2e 以名字硬引用，勿改名）＋填補 32 筆湊 40。
FW=$(B folder create 工作資料夾 --json | jq -r '.id')
[[ "$FW" != "null" && -n "$FW" ]] || fail "資料夾建立失敗"

N() { # N <name> <uri> <user> <pass> [extra args...]
  local name="$1" uri="$2" user="$3" pass="$4"; shift 4
  local args=(new --name "$name" --username "$user")
  [[ -n "$uri" ]] && args+=(--uri "$uri")
  if [[ -n "$pass" ]]; then
    echo "$pass" | B "${args[@]}" --password-stdin "$@" >/dev/null
  else
    B "${args[@]}" "$@" >/dev/null
  fi
}
# —— 策展名（shots.rs / 徽章流硬依賴：GitHub 測試、Local OTP、2b 筆記範例）——
N "GitHub" "https://github.com" octocat 'gh-pass-1'
N "GitHub 測試" "https://github.com" tester 'Gh-test-123'
N "AWS Console" "https://console.aws.amazon.com" admin@corp 'aws-pass-2'
N "Local OTP" "http://127.0.0.1:18099/" otp-user '' --totp 'JBSWY3DPEHPK3PXP'
N "API token 範本" "https://api.example.dev" tokenholder 'tok-pass' --field! 'API Key=ak_demo_1'
N "網銀 個人" "https://bank.example.tw" me 'bank-pass-9'
N "webauthn.io" "https://webauthn.io" wa-user 'wa-pass'
N "2b 筆記範例" "" "" "" --type note --notes "加密筆記內文：明文只進 Outgoing 幀。" --field 'API Key=sk_demo_9' --field '配對碼=4f2c'
# —— 填補 32 筆（僅供列表密度視覺；名字不進斷言）——
FILLERS=(
  "Slack 工作區|https://app.slack.com|s1" "Figma|https://figma.com|s2" "GitLab|https://gitlab.com|s3"
  "Jira|https://corp.atlassian.net|s4" "GCP Console|https://console.cloud.google.com|s5"
  "Azure Portal|https://portal.azure.com|s6" "Cloudflare|https://dash.cloudflare.com|s7"
  "Vercel|https://vercel.com|s8" "Netlify|https://app.netlify.com|s9" "Fly.io|https://fly.io|s10"
  "Hetzner|https://console.hetzner.cloud|s11" "AWS IAM|https://console.aws.amazon.com/iam|s12"
  "Linear|https://linear.app|s13" "Notion|https://notion.so|s14" "Obsidian Sync|https://obsidian.md|s15"
  "ProtonMail|https://mail.proton.me|s16" "Fastmail|https://www.fastmail.com|s17"
  "Tailscale|https://login.tailscale.com|s18" "Router 主頁|http://192.168.1.1|s19"
  "NAS 管理|http://nas.local:5000|s20" "Pi-hole|http://pi.hole/admin|s21" "Jellyfin|http://nas.local:8096|s22"
  "Home Assistant|http://ha.local:8123|s23" "Steam|https://steamcommunity.com|s24"
  "Epic Games|https://unrealengine.com|s25" "PlayStation Network|https://psn.playstation.com|s26"
  "Nintendo Account|https://accounts.nintendo.com|s27" "Gmail 應用密碼|https://mail.google.com|s28"
  "App Store|https://appleid.apple.com|s29" "Discord|https://discord.com|s30"
  # facebook.com：VW icons 端回 MS ICO（非 PNG）——批次 13 轉碼鏈活體標靶。
  "Facebook|https://facebook.com|s31" "Shopify 後台|https://admin.shopify.com|s32"
)
for e in "${FILLERS[@]}"; do
  IFS='|' read -r nm uri u <<<"$e"
  N "$nm" "$uri" "$u" "fill-$u-pass"
done
B tag add "$(B ls --json | jq -r '.[] | select(.meta.name=="API token 範本") | .meta.id')" 範本 >/dev/null

# 5. 收斂：推送清空＋筆數核對（e2e 前提＝乾淨同步態）。
for _ in $(seq 1 120); do [[ "$(B outbox --json | jq "$PENDING")" == "0" ]] && break; sleep 1; done
[[ "$(B outbox --json | jq "$PENDING")" == "0" ]] || fail "種子推送未收斂"
CNT=$(B ls --json | jq 'length')
[[ "$CNT" == "40" ]] || fail "種子筆數 $CNT ≠ 40"
echo "DEMO-SEED: OK（$EMAIL，40 筆、資料夾 1、outbox 收斂）"
