#!/usr/bin/env bash
# Android P4b 驗收（契約 §5 P4 列「Android track 自此起平行」）。
#
# 名斷言：
#   A1 in-process 核心（bw-crypto/bw-server/bw-store）交叉編譯進三 ABI 的 APK
#   A2 app 裝進 emulator 並啟動到登入畫面（原生 nav 標題渲染）
#   A3 真實 UI 路徑完成登入：prelogin→派生→password grant→user key 解封→sync→明文索引
#   A4 列表渲染同步資料、搜尋過濾生效
#   A5 詳情頁預設遮罩；按「顯示」才出明文（Reveal）
#   A6 系統返回鍵 pop 詳情並清明文（再進詳情是遮罩態）
#   A7 鎖定回登入頁、帳號檔預填（金鑰已歸零）
# 產物：apps/bitward-android/shots/*.png（截圖）與 .nsh/out/bitward.apk
set -euo pipefail
cd "$(dirname "$0")/../.."

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export PATH="$HOME/.local/bin:$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator"
ADB=adb
AVD=${AVD:-Pixel_10_Pro_XL}
VW_PORT=${VW_PORT:-18095}
VW_NAME=${VW_NAME:-bitward-vw-demo}
SRV_HOST="http://127.0.0.1:$VW_PORT"
SRV_EMU="http://10.0.2.2:$VW_PORT"          # 10.0.2.2 = emulator 視角的 host loopback
WP='E2eMaster-9f3Kq!x'
EMAIL=${EMAIL:-"android-e2e-$(date +%s)@bitward.test"}
PKG=io.bitward.android
APP=apps/bitward-android
SHOTS=$APP/shots
DA=${DA:-/tmp/bitward-android-hub}

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "ok: $1"; }
mkdir -p "$SHOTS"

dump() {  # $1 = 本機留檔路徑
  $ADB shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
  $ADB pull /sdcard/window_dump.xml "$1" >/dev/null 2>&1
}
has_text() { grep -q "$2" "$1"; }  # has_text <xml> <text>
center_of() {  # center_of <xml> <text> → "x y"
  python3 -c "
import re, sys
x = open(sys.argv[1]).read()
for m in re.finditer(r'text=\"([^\"]*)\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"', x):
    if m.group(1) == sys.argv[2]:
        x1, y1, x2, y2 = map(int, m.groups()[1:])
        print((x1 + x2) // 2, (y1 + y2) // 2)
        break
" "$1" "$2"
}
tap_text() {  # tap_text <xml 留檔名> <text>
  dump "/tmp/android-$1.xml"
  local xy
  xy=$(center_of "/tmp/android-$1.xml" "$2")
  [[ -n "$xy" ]] || fail "找不到節點「$2」（見 /tmp/android-$1.xml）"
  # </dev/null：adb 會吃 stdin，別讓它把腳本的 while 迴圈讀走
  $ADB shell input tap $xy </dev/null >/dev/null 2>&1
  sleep 1
}
type_text() {
  local esc=${1//!/\\!}
  $ADB shell input text "$esc" </dev/null >/dev/null 2>&1
  sleep 1
}
hide_ime() {  # 軟鍵盤開著時，第一個 tap 只被 IME 吃掉、送不到 app（實測）
  $ADB shell input keyevent 111 </dev/null >/dev/null 2>&1
  sleep 1
}
shot() { $ADB exec-out screencap -p > "$SHOTS/$1.png"; }
wait_text() {  # wait_text <text> <秒>
  for _ in $(seq 1 "${2:-30}"); do
    dump /tmp/android-wait.xml
    has_text /tmp/android-wait.xml "$1" && return 0
    sleep 1
  done
  return 1
}

# --- 0. 依賴 ------------------------------------------------------------------
command -v nsh >/dev/null || fail "找不到 nsh（install.sh 裝到 ~/.local/bin）"
docker inspect "$VW_NAME" >/dev/null 2>&1 || fail "Vaultwarden 容器 $VW_NAME 不存在；先起 docker run -d -p $VW_PORT:80 -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2"
curl -fsS "$SRV_HOST/alive" >/dev/null 2>&1 || fail "$SRV_HOST 沒回應"

# 專屬 target dir：repo 的 target/ 會被並行的 cargo build 換掉執行檔（實測撞過兩次，
# 一次在 build 與使用之間被 relink 拿走）。
export CARGO_TARGET_DIR="${ANDROID_E2E_TARGET:-/tmp/bitward-android-e2e-target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo build -q --release -p bitward -p bitwarderd
DAEMON="$CARGO_TARGET_DIR/release/bitwarderd"; CLI="$CARGO_TARGET_DIR/release/bitward"
[[ -x "$DAEMON" && -x "$CLI" ]] || fail "取不到 CLI/daemon 執行檔（$CARGO_TARGET_DIR）"

# --- 1. 註冊示範帳號並播資料（經暫時 daemon，核心語意與正式路徑相同） --------
rm -rf "$DA" && mkdir -p "$DA"
BITWARD_DATA_DIR="$PWD/$DA" "$DAEMON" --data-dir "$DA" --sock "$DA/s" >"$DA/log" 2>&1 &
HUB_PID=$!
trap 'kill $HUB_PID 2>/dev/null || true' EXIT
sleep 1
B() { "$CLI" --sock "$DA/s" "$@"; }
echo "$WP" | B --json dev-register --server "$SRV_HOST" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV_HOST" --email "$EMAIL" --password-stdin >/dev/null
for n in github:alice:pw-github gitlab:bob:pw-gitlab cloudflare:carol:pw-cf; do
  IFS=: read -r name user pw <<<"$n"
  echo "$pw" | B new --name "$name" --username "$user" --uri "https://$name.example.com" --password-stdin >/dev/null
done
B sync >/dev/null
kill $HUB_PID 2>/dev/null || true
trap - EXIT
pass "seed：$EMAIL 三筆項目入庫"

# --- 2. emulator --------------------------------------------------------------
if ! $ADB get-state >/dev/null 2>&1; then
  echo "啟動 AVD $AVD（無視窗）…"
  emulator -avd "$AVD" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect \
    -no-snapshot-save >/tmp/android-emulator.log 2>&1 &
  EMU_PID=$!
  trap 'kill $EMU_PID 2>/dev/null || true' EXIT
fi
$ADB wait-for-device
for _ in $(seq 1 90); do
  [[ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
  sleep 2
done
[[ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] || fail "emulator 沒開機完成"
pass "emulator 就緒（$($ADB get-state)）"

# --- 3. A1：三 ABI APK（含 in-process 核心） ----------------------------------
(cd "$APP" && nsh package --target android)
APK="$APP/.nsh/out/bitward.apk"
[[ -f "$APK" ]] || fail "APK 沒產出"
# 不用 `unzip -l | grep -q`：grep 提前收工會讓 unzip 吃到 SIGPIPE，
# 在 `set -o pipefail` 下變成「匹配成功但管道失敗」。
APK_LIST=$(unzip -l "$APK")
for abi in armeabi-v7a arm64-v8a x86_64; do
  [[ "$APK_LIST" == *"lib/$abi/libnsh.so"* ]] || fail "APK 缺 $abi 的 libnsh.so"
done
pass "A1 APK 三 ABI 齊備（$(du -h "$APK" | cut -f1)）"

# --- 4. A2：裝並啟動到登入畫面 ------------------------------------------------
$ADB install -r "$APK" >/dev/null
# 清掉上輪的 app 資料（登入頁預填會變，斷言要可重跑）
$ADB shell pm clear $PKG >/dev/null
$ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
wait_text "登入你的密碼庫" 30 || fail "登入畫面沒出現"
dump /tmp/android-login.xml
has_text /tmp/android-login.xml "$SRV_EMU" || fail "服務器欄位沒預填 $SRV_EMU"
shot 1-login
pass "A2 啟動到登入畫面（原生 nav 標題「bitward」渲染）"

# --- 5. A3：真實 UI 完成登入 --------------------------------------------------
tap_text login-field "me@example.com"
type_text "$EMAIL"
tap_text pw-field "只用於派生金鑰，不落地"
type_text "$WP"
hide_ime
shot 2-login-filled
$ADB logcat -c
tap_text login-btn "登入"
wait_text "鏡像 3 筆" 40 || { $ADB logcat -d | grep -E 'nsh|AndroidRuntime' | tail -20; fail "登入後列表沒出現"; }
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'已登入：3 筆鏡像'* ]] || fail "logcat 沒有登入成功軌跡"
shot 3-vault
pass "A3 in-process 登入＋sync＋明文索引回填（3 筆）"

# --- 6. A4：搜尋過濾 ----------------------------------------------------------
tap_text search-field "搜尋名稱或網址"
type_text "git"
hide_ime
sleep 1
dump /tmp/android-search.xml
has_text /tmp/android-search.xml "gitlab" || fail "搜尋 git 應留 gitlab"
if has_text /tmp/android-search.xml "cloudflare"; then fail "搜尋 git 不應留 cloudflare"; fi
shot 4-search
pass "A4 搜尋走 bw-store 的 FTS5 索引（3→2 筆）"

# --- 7. A5/A6：詳情遮罩 → Reveal → 返回清明文 --------------------------------
tap_text gitlab-row "gitlab"
dump /tmp/android-detail.xml
has_text /tmp/android-detail.xml "••••••••" || fail "詳情頁密碼應是遮罩態"
if has_text /tmp/android-detail.xml "pw-gitlab"; then fail "未按要求就出現明文密碼"; fi
shot 5-detail-masked
pass "A5a 詳情頁預設遮罩"
tap_text reveal-btn "顯示"
dump /tmp/android-revealed.xml
has_text /tmp/android-revealed.xml "pw-gitlab" || fail "按顯示後應出現明文密碼"
has_text /tmp/android-revealed.xml "bob" || fail "按顯示後應出現帳號"
shot 6-detail-revealed
pass "A5b Reveal 出明文（bob / pw-gitlab）"
$ADB shell input keyevent 4 </dev/null >/dev/null 2>&1
sleep 1
tap_text gitlab-row2 "gitlab"
dump /tmp/android-detail2.xml
has_text /tmp/android-detail2.xml "••••••••" || fail "返回後再進詳情應回到遮罩態"
if has_text /tmp/android-detail2.xml "pw-gitlab"; then fail "返回後明文未清"; fi
shot 7-detail-remasked
pass "A6 系統返回鍵 pop 詳情並清明文"

# --- 8. A7：鎖定與預填 --------------------------------------------------------
$ADB shell input keyevent 4 </dev/null >/dev/null 2>&1
sleep 1
tap_text lock-btn "鎖定"
wait_text "登入你的密碼庫" 20 || fail "鎖定後沒回登入頁"
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'signed out'* ]] || fail "logcat 沒有鎖定軌跡"
dump /tmp/android-locked.xml
has_text /tmp/android-locked.xml "$EMAIL" || fail "帳號檔預填失效"
shot 8-locked-prefilled
pass "A7 鎖定回登入頁（金鑰歸零）、下次冷啟預填帳號"

echo
echo "截圖：$(ls "$SHOTS" | tr '\n' ' ')"
echo "APK：$APK"
