#!/usr/bin/env bash
# Android P4b 驗收（契約 §5 P4 列「Android track 自此起平行」）。
#
# 十七斷言（A1–A17）：
#   A1 in-process 核心（bw-crypto/bw-server/bw-store）交叉編譯進三 ABI 的 APK
#   A2 app 裝進 emulator 並啟動到登入畫面（原生 nav 標題渲染）
#   A3 真實 UI 路徑完成登入：prelogin→派生→password grant→user key 解封→sync→明文索引
#   A4 列表渲染同步資料、搜尋過濾生效
#   A5 詳情頁預設遮罩；按「顯示」才出明文（Reveal）
#   A6 系統返回鍵 pop 詳情並清明文（再進詳情是遮罩態）
#   A7 鎖定回登入頁、帳號檔預填（金鑰已歸零）
#   A8 系統列舉我們的 AutofillService（settings 切換成功、dumpsys 認得）
#   A9 表單觸發 autofill 面板＋logcat 證明系統真的 bind 到我們並送 fill 請求
#   A10 Keystore 橋：service 內 Android Keystore 生成 Class 3 EC 金鑰、回顯 alias
#   A11 解鎖態真候選：重新登入後 fill 請求回真 dataset（非佔位），commit 後
#       欄位出現真 username（logcat＋層級雙證據）
#   A12 vault 新增：本地鏡像即刻可見＋「待推送」→「重新同步」（drain 先推
#       再拉）收斂清標記→暫時 daemon 對 VW reveal 出新明文（金鑰鏈沒斷）
#   A13 編輯只動密碼欄：預填走 reveal、送欄位級差量→同步後 VW 端帳號欄存活
#   A14 刪除＝軟刪：tombstone 即刻離列→同步後 VW 端鏡像不再列出（restore
#       語意在 Hub，UI 本批不掛）
#   A15 手機新皮：頂部列＋搜尋＋資料夾 chip 列＋FAB 全在層級；全頁表單建
#       TOTP 項目（seed 欄真落鏡像）、詳情分節值塊截圖
#   A16 autofill save 全鏈：探針頁輸入未儲存組合→fill 回 SaveInfo→提交→
#       onSaveRequest→Hub::save_from_autofill create→outbox→重新同步 drain
#       →暫時 daemon 對 VW reveal 出存进去的帳密（鎖態不假裝存）
#   A17 詳情 TOTP 自動碼：進頁免按鈕現算，碼與本機 python HMAC 同值、
#       倒數條「剩餘 N 秒」渲染（≤5s 轉警告色屬視覺，截圖留證）
# 產物：apps/bitward-android/shots/*.png（截圖）與 .nsh/out/bitward-islands.apk
#       （孤島＋nsh 中樞的合併 APK；A1–A7 裝的就是這顆）
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
BG=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
AF_SVC="$PKG/$PKG.BitwardAutofillService"
EMU_PIN=${EMU_PIN:-0000}

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
type_verify() {  # type_verify <打的字> <dump 留檔名>：長字串實錄會被面板/焦點
  # 事件截尾（f1 username 19→13、f2 seed 16→13），驗層級現值、不實清欄重打一次。
  type_text "$1"
  for _ in 1 2; do
    dump "/tmp/android-$2.xml"
    has_text "/tmp/android-$2.xml" "$1" && return 0
    $ADB shell input keyevent 123 </dev/null >/dev/null 2>&1
    for _ in $(seq 1 30); do $ADB shell input keyevent 67 </dev/null >/dev/null 2>&1; done
    type_text "$1"
  done
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
wait_gone() {  # wait_gone <text> <秒>：等某段文字從層級消失（drain 收斂用）
  for _ in $(seq 1 "${2:-30}"); do
    dump /tmp/android-gone.xml
    has_text /tmp/android-gone.xml "$1" || return 0
    sleep 1
  done
  return 1
}
tap_first_edittext() {  # focus 第一個原生 EditText（autofill 面板由 focus 觸發）
  dump "/tmp/$1"
  tap_edittext_of "/tmp/$1" 0
}
tap_edittext_of() {  # tap_edittext_of <留檔> <第幾個 EditText（0 起）>
  # 遮罩欄的 text 是圓點不是 placeholder（實錄），改欄位現值時按序定位。
  local xy
  xy=$(python3 -c "
import re, sys
x = open(sys.argv[1]).read()
ms = re.findall(r'class=\"android.widget.EditText\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"', x)
if len(ms) > int(sys.argv[2]):
    x1, y1, x2, y2 = map(int, ms[int(sys.argv[2])])
    print((x1 + x2) // 2, (y1 + y2) // 2)
" "$1" "$2")
  [[ -n "$xy" ]] || fail "層級裡沒有第 $2 個 EditText（見 $1）"
  $ADB shell input tap $xy </dev/null >/dev/null 2>&1
  sleep 1
}
unlock_device() {  # 設了 PIN 之後 keyguard 可能在螢幕喚醒時擋路（A8–A10 前必跑）
  $ADB shell input keyevent 224 </dev/null >/dev/null 2>&1   # WAKEUP
  $ADB shell wm dismiss-keyguard >/dev/null 2>&1
  sleep 1
  local win
  win=$($ADB shell dumpsys window 2>/dev/null || true)
  if [[ "$win" == *"mShowingLockscreen=true"* ]] || [[ "$win" == *"mDreamingLockscreen=true"* ]]; then
    $ADB shell input text "$EMU_PIN" </dev/null >/dev/null 2>&1
    $ADB shell input keyevent 66 </dev/null >/dev/null 2>&1
    sleep 1
  fi
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
# 第四筆是 A11 自用：uri 存本 app 的 package 名（原生欄位的查詢鍵就是
# package，見 BitwardAutofillService.analyze），autofill 面板 commit 斷言靠它。
for n in github:alice:pw-github gitlab:bob:pw-gitlab cloudflare:carol:pw-cf bitward-selftest:dave:pw-selftest:io.bitward.android; do
  IFS=: read -r name user pw host <<<"$n"
  echo "$pw" | B new --name "$name" --username "$user" --uri "https://${host:-$name.example.com}" --password-stdin >/dev/null
done
B sync >/dev/null
kill $HUB_PID 2>/dev/null || true
trap - EXIT
pass "seed：$EMAIL 四筆項目入庫（第四筆 uri＝本 app package，A11 用）"

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
# Keystore Class 3（需使用者解鎖）的金鑰生成要求裝置有安全鎖屏（實測：無 PIN 時
# 拋 IllegalStateException "Secure lock screen must be enabled"）。冪等設定；
# 不用 `adb shell ... | grep -q`：grep 早收工讓 adb 吃 SIGPIPE，pipefail 下變失敗。
HAS_PW=$($ADB shell locksettings get-password 2>/dev/null || true)
if [[ "$HAS_PW" != *"lock credential"* ]] && [[ "$HAS_PW" != "true" ]]; then
  $ADB shell locksettings set-pin "$EMU_PIN" >/dev/null 2>&1 || fail "locksettings set-pin 失敗（A10 需要安全鎖屏）"
fi
$ADB shell svc power stayon true >/dev/null 2>&1
unlock_device
pass "emulator 就緒（$($ADB get-state)）"

# --- 3. A1：三 ABI＋孤島 dex 的合併 APK ---------------------------------------
(cd "$APP" && nsh package --target android)
NSH_APK="$APP/.nsh/out/bitward.apk"
[[ -f "$NSH_APK" ]] || fail "nsh APK 沒產出"
"$APP/android-shell/build.sh" || fail "孤島外殼 build 失敗"
APK="$APP/.nsh/out/bitward-islands.apk"
[[ -f "$APK" ]] || fail "孤島合併 APK 沒產出"
# 不用 `unzip -l | grep -q`：grep 提前收工會讓 unzip 吃到 SIGPIPE，
# 在 `set -o pipefail` 下變成「匹配成功但管道失敗」。
APK_LIST=$(unzip -l "$APK")
for abi in armeabi-v7a arm64-v8a x86_64; do
  [[ "$APK_LIST" == *"lib/$abi/libnsh.so"* ]] || fail "APK 缺 $abi 的 libnsh.so"
done
# 兩套 dex 共存：外殼（孤島 Kotlin）＋ nsh runtime（AppActivity）
DEX_TMP=$(mktemp -d)
unzip -q "$APK" -d "$DEX_TMP" 'classes*.dex'
HAS_ISLAND=0; HAS_RUNTIME=0
for d in "$DEX_TMP"/classes*.dex; do
  DUMP=$("$BG/dexdump" -f "$d" 2>/dev/null)
  [[ "$DUMP" == *"Lio/bitward/android/BitwardAutofillService;"* ]] && HAS_ISLAND=1
  [[ "$DUMP" == *"Lcom/longbridge/nsh/AppActivity;"* ]] && HAS_RUNTIME=1
done
rm -rf "$DEX_TMP"
[[ $HAS_ISLAND == 1 ]] || fail "APK 的 dex 裡沒有 BitwardAutofillService（孤島沒編進去）"
[[ $HAS_RUNTIME == 1 ]] || fail "APK 的 dex 裡沒有 nsh runtime（AppActivity）"
pass "A1 合併 APK：三 ABI＋孤島 dex＋runtime dex 齊備（$(du -h "$APK" | cut -f1)）"

# --- 4. A2：裝並啟動到登入畫面 ------------------------------------------------
# Android 15+ 的 autofill 服務 key 是 `autofill_service`（舊 key
# `current_autofill_service` 在此 image 上已無人監聽；實測 dumpsys 只認新 key）。
# 先歸零：避免上一輪 A8–A10 設的服務讓「尚未解鎖」彈窗干擾 A2–A7 的表單點擊。
$ADB shell settings put secure autofill_service null >/dev/null 2>&1 || true
$ADB shell settings put secure current_autofill_service null >/dev/null 2>&1 || true
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
wait_text "鏡像 4 筆" 40 || { $ADB logcat -d | grep -E 'nsh|AndroidRuntime' | tail -20; fail "登入後列表沒出現"; }
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'已登入：4 筆鏡像'* ]] || fail "logcat 沒有登入成功軌跡"
shot 3-vault
pass "A3 in-process 登入＋sync＋明文索引回填（4 筆）"

# --- 6. A4：搜尋過濾 ----------------------------------------------------------
tap_text search-field "搜尋名稱或網址"
type_text "git"
hide_ime
sleep 1
dump /tmp/android-search.xml
has_text /tmp/android-search.xml "gitlab" || fail "搜尋 git 應留 gitlab"
if has_text /tmp/android-search.xml "cloudflare"; then fail "搜尋 git 不應留 cloudflare"; fi
shot 4-search
pass "A4 搜尋走 bw-store 的 FTS5 索引（4→2 筆）"

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

# --- 9. A8：系統列舉我們的 autofill 服務 --------------------------------------
# 注意：Android 15+ 用 `autofill_service`；`current_autofill_service` 一併寫
# （舊 image 上 A8 才成立），兩邊都認。
$ADB shell settings put secure autofill_service "$AF_SVC"
$ADB shell settings put secure current_autofill_service "$AF_SVC"
for _ in $(seq 1 10); do
  AF=$($ADB shell dumpsys autofill)
  [[ "$AF" == *"$AF_SVC"* ]] && break
  sleep 1
done
[[ "$AF" == *"$AF_SVC"* ]] || fail "dumpsys autofill 沒列舉到 $AF_SVC"
pass "A8 系統列舉到我們的 AutofillService（Service Label: bitward）"

# --- 10. A9＋A10：focus 欄位 → 系統 bind、fill 請求、Keystore 橋 ---------------
unlock_device
hide_ime
$ADB logcat -c
tap_first_edittext android-af-focus.xml
wait_text "尚未解鎖" 15 || fail "autofill 面板沒出現「尚未解鎖」列"
shot 9-autofill-panel
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'bitward-island: autofill service bound by system'* ]] \
  || fail "logcat 沒有系統 bind 標記（孤島沒被接到單）"
[[ "$APP_LOG" == *'bitward-island: onFillRequest'* ]] \
  || fail "logcat 沒有 onFillRequest 標記"
pass "A9 系統真的 bind 到我們並送 fill 請求（面板截圖 9-autofill-panel）"
[[ "$APP_LOG" == *'bitward-island: keystore EC class3 key'*'alias=bitward-class3-ec-probe'* ]] \
  || fail "logcat 沒有 Keystore Class 3 EC 金鑰標記"
pass "A10 Keystore 橋生成 Class 3 EC 金鑰並回顯 alias"

# --- 11. A11：解鎖態真候選（孤島真回密碼，不是佔位列） ------------------------
# 實測：autofill service 開著時，app 自己欄位 focus 會彈「尚未解鎖」面板並
# 搶走輸入焦點，之後的 input text／按「登入」都送不到 app（logcat 完全沒有
# 第二次 Auth.Success）。所以重登這一段先關服務打字，再開服務驗真候選
# （服務已在 A8–A10 被系統 bind 過，重設 key 立即生效）。
$ADB shell am force-stop $PKG
$ADB shell settings put secure autofill_service null >/dev/null 2>&1 || true
$ADB shell settings put secure current_autofill_service null >/dev/null 2>&1 || true
$ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
wait_text "登入你的密碼庫" 30 || fail "A11 重啟後登入畫面沒出現"
tap_text pw-field "只用於派生金鑰，不落地"
type_text "$WP"
hide_ime
$ADB logcat -c
tap_text login-btn "登入"
wait_text "鏡像 4 筆" 40 || { $ADB logcat -d | grep -E 'bitward|nsh|AndroidRuntime' | tail -20; fail "A11 重新登入失敗"; }
$ADB shell settings put secure autofill_service "$AF_SVC"
$ADB shell settings put secure current_autofill_service "$AF_SVC"
sleep 2
# 列表頁搜尋欄（第一個原生 EditText）focus → fill 請求走解鎖態分支
hide_ime
$ADB logcat -c
tap_first_edittext android-a11-focus.xml
wait_text "bitward-selftest" 15 || { $ADB logcat -d | grep bitward-island | tail -5; fail "A11 autofill 面板沒出現真候選列"; }
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'bitward-island: onFillRequest unlocked=true'* ]] \
  || fail "A11 logcat 沒有 unlocked=true 的 fill 請求標記"
[[ "$APP_LOG" == *'bitward-island: fill response datasets=1'* ]] \
  || fail "A11 沒有回真 dataset（fill response 標記缺失）"
[[ "$APP_LOG" == *'jni: candidates q=io.bitward.android n=1'* ]] \
  || fail "A11 Rust 側沒有命中候選（JNI log 缺失）"
shot 10-autofill-real-panel
tap_text a11-pick "bitward-selftest"
dump /tmp/android-a11-filled.xml
has_text /tmp/android-a11-filled.xml "dave" || fail "A11 commit 後欄位內不是真 username（dave）"
shot 11-autofill-filled
pass "A11 解鎖態真候選：面板列 bitward-selftest、commit 後欄位＝dave（非佔位）"

# --- 12. A12：vault 新增（本地先行→待推送→drain 收斂→VW reveal） -------------
# 重新起一個乾淨 app 態（A11 後搜尋欄殘留「dave」＋面板開著）。autofill 服務
# 先關：自家欄位 focus 會彈面板搶焦點（A11 段同款陷阱，模態四欄都要打字）。
$ADB shell am force-stop $PKG
$ADB shell settings put secure autofill_service null >/dev/null 2>&1 || true
$ADB shell settings put secure current_autofill_service null >/dev/null 2>&1 || true
$ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
wait_text "登入你的密碼庫" 30 || fail "A12 重啟後登入畫面沒出現"
tap_text pw-field2 "只用於派生金鑰，不落地"
type_text "$WP"
hide_ime
$ADB logcat -c
tap_text login-btn2 "登入"
wait_text "鏡像 4 筆" 40 || { $ADB logcat -d | grep -E 'bitward|nsh|AndroidRuntime' | tail -20; fail "A12 重新登入失敗"; }
$ADB logcat -c
tap_text a12-add "新增"
wait_text "新增項目" 10 || fail "A12 編輯模態沒出現"
shot 12-editor-modal
tap_text a12-name "項目名稱（必填）"
type_text "e2e-added"
# 每欄打完先收鍵盤再點下一欄：模態四欄加按鈕高於視窗，鍵盤開著時下一欄
# 常被 IME 蓋住，tap 落在鍵盤上、文字接錯欄（A12 首輪實錄：uri 接進密碼欄）。
hide_ime
tap_text a12-user "帳號（可留空）"
type_text "e2euser"
hide_ime
tap_text a12-pass "密碼（可留空）"
type_text "e2epass"
hide_ime
tap_text a12-uri "網址（可留空）"
type_text "https://added.example.com"
hide_ime
tap_text a12-save "儲存"
wait_text "e2e-added" 15 || { $ADB logcat -d | grep -E 'nsh_app|bitward' | tail -20; fail "A12 新增後列表沒出現該筆"; }
dump /tmp/android-a12-pending.xml
has_text /tmp/android-a12-pending.xml "待推送" || fail "A12 新增列應掛「待推送」（outbox 未推，本地先行）"
shot 12-vault-pending
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'create'*'待推送'* ]] || fail "logcat 沒有 create 入列軌跡"
# 「重新同步」＝drain 先推再拉（契約 §2.4）：Busy 期間列表暫卸，等按鈕回
# 到層級＝已回 Vault 態；此時 pending 必已結算（drain 在 pull 前完成）。
tap_text a12-sync "重新同步"
wait_text "重新同步" 60 || fail "A12 同步沒完成（一直卡在 Busy）"
dump /tmp/android-a12-synced.xml
has_text /tmp/android-a12-synced.xml "e2e-added" || fail "A12 同步後新增列被全量重建吞了"
if has_text /tmp/android-a12-synced.xml "待推送"; then fail "A12 同步後「待推送」沒清（drain 未收斂）"; fi
shot 12-vault-synced
# VW 端收斂：暫時 daemon（seed 用的帳號檔還在 $DA）登入拉鏡像、reveal 明文。
BITWARD_DATA_DIR="$PWD/$DA" "$DAEMON" --data-dir "$DA" --sock "$DA/s2" >"$DA/log2" 2>&1 &
HUB_PID=$!
trap 'kill $HUB_PID 2>/dev/null || true' EXIT
sleep 1
B2() { "$CLI" --sock "$DA/s2" "$@"; }
echo "$WP" | B2 login --server "$SRV_HOST" --email "$EMAIL" --password-stdin >/dev/null \
  || fail "A12 暫時 daemon 登入失敗"
B2 sync >/dev/null
ADDED_ID=$(B2 --json ls --text "e2e-added" | python3 -c 'import json,sys; rows=json.load(sys.stdin); print(rows[0]["meta"]["id"] if rows else "")')
[[ -n "$ADDED_ID" ]] || fail "A12 伺服器鏡像沒有 e2e-added（push 未送達 VW）"
REVEAL=$(B2 --json reveal "$ADDED_ID")
[[ "$REVEAL" == *'"password": "e2epass"'* ]] || fail "A12 VW 端 reveal 密碼不對：$REVEAL"
[[ "$REVEAL" == *"e2euser"* ]] || fail "A12 VW 端 reveal 帳號欄缺失：$REVEAL"
pass "A12 新增：本地先行掛「待推送」→同步收斂→VW 端 reveal 明文 OK"

# --- 13. A13：編輯只動密碼欄（欄位級存活） ------------------------------------
tap_text a13-row "e2e-added"
tap_text a13-edit "編輯"
wait_text "編輯項目" 10 || fail "A13 編輯模態沒出現"
dump /tmp/android-a13-prefill.xml
has_text /tmp/android-a13-prefill.xml "e2euser" || fail "A13 帳號欄沒預填（reveal 預填路徑斷了）"
shot 13-editor-prefilled
# 清空密碼欄再打新值：遮罩欄的 text 是圓點（實錄），按第 3 個 EditText 定位；
# 移到行尾逐字退（欄內現值 e2epass＝7 字，30 下留足餘量）。
dump /tmp/android-a13-fields.xml
tap_edittext_of /tmp/android-a13-fields.xml 2
$ADB shell input keyevent 123 </dev/null >/dev/null 2>&1
for _ in $(seq 1 30); do $ADB shell input keyevent 67 </dev/null >/dev/null 2>&1; done
type_text "e2epass2"
hide_ime
tap_text a13-save "儲存"
wait_text "待推送" 15 || fail "A13 編輯後列表沒回到「待推送」態"
tap_text a13-sync "重新同步"
wait_text "重新同步" 60 || fail "A13 同步沒完成（一直卡在 Busy）"
dump /tmp/android-a13-synced.xml
if has_text /tmp/android-a13-synced.xml "待推送"; then fail "A13 同步後「待推送」沒清"; fi
B2 sync >/dev/null
REVEAL=$(B2 --json reveal "$ADDED_ID")
[[ "$REVEAL" == *'"password": "e2epass2"'* ]] || fail "A13 VW 端密碼沒更新：$REVEAL"
[[ "$REVEAL" == *"e2euser"* ]] || fail "A13 只改密碼卻弄丟帳號欄（欄位級存活斷了）"
shot 13-after-sync
pass "A13 編輯：預填走 reveal、差量只動 password，VW 端 username 欄存活"

# --- 14. A14：刪除（軟刪 tombstone 即刻離列→同步後 VW 端不再列出） ------------
# Hub::delete 語意＝軟刪（deletedDate tombstone，同 daemon write_delete）；
# 本批 UI 定案：列表即刻消失＋outbox 掛 delete 列，restore 入口留後續批。
tap_text a14-row "e2e-added"
tap_text a14-del "刪除"
wait_text "確定刪除這筆" 10 || fail "A14 二次確認列沒出現"
shot 14-delete-confirm
tap_text a14-ok "確定刪除"
wait_gone "e2e-added" 20 || fail "A14 確認後該筆沒立刻離列（tombstone 未生效）"
dump /tmp/android-a14-gone.xml
if has_text /tmp/android-a14-gone.xml "e2e-added"; then fail "A14 刪除後列表仍有該列"; fi
shot 14-vault-after-delete
tap_text a14-sync "重新同步"
wait_text "重新同步" 60 || fail "A14 同步沒完成（一直卡在 Busy）"
B2 sync >/dev/null
# 全量重建後本地鏡像也不該有它（伺服器已標 deletedDate）。
dump /tmp/android-a14-final.xml
if has_text /tmp/android-a14-final.xml "e2e-added"; then fail "A14 同步後該筆又回來（VW 端沒標刪除）"; fi
# VW 端收斂：daemon 鏡像重拉後查無此筆（deleted 列不進列表）。
LEFT=$(B2 --json ls --text "e2e-added" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
[[ "$LEFT" == "0" ]] || fail "A14 VW 端鏡像仍列出 e2e-added（軟刪未送達）"
kill $HUB_PID 2>/dev/null || true
trap - EXIT
pass "A14 刪除：軟刪即刻離列、同步後 VW 端收斂（列表不再含該筆）"

# --- 15. A15：手機新皮層級＋全頁表單建 TOTP 項目 ------------------------------
# 表單打字照 IME 教訓：autofill 服務保持關（A12 起未開），A16 才開。
dump /tmp/android-a15-vault.xml
for t in "鏡像 4 筆" "全部" "未歸屬" "新增" "搜尋名稱或網址"; do
  has_text /tmp/android-a15-vault.xml "$t" || fail "A15 新皮層級缺「$t」（見 /tmp/android-a15-vault.xml）"
done
# 列距實測：相鄰列名文字 y 差＝列高節拍（44dp 換算裝置 px，容許 ±3px 取整）。
DEN=$($ADB shell wm density | sed -E 's/.*: ([0-9]+).*/\1/' | tr -d '\r')
PITCH=$(python3 -c "print(int(44*$DEN/160))")
python3 - "$PITCH" <<'PY' || fail "A15 列高不是 44dp 節拍"
import re, sys
pitch = int(sys.argv[1])
x = open('/tmp/android-a15-vault.xml').read()
ys = []
for m in re.finditer(r'text="(github|gitlab|cloudflare|bitward-selftest)"[^>]*bounds="\[\d+,(\d+)\]\[\d+,\d+\]"', x):
    ys.append(int(m.group(2)))
ys.sort()
pitches = [b - a for a, b in zip(ys, ys[1:])]
assert any(abs(p - pitch) <= 3 for p in pitches), f"row pitch {pitches} vs {pitch}"
PY
shot 15-vault-skin
# 詳情分節截圖（遮罩態值塊）
tap_text a15-row "gitlab"
dump /tmp/android-a15-detail.xml
has_text /tmp/android-a15-detail.xml "帳號" || fail "A15 詳情分節缺「帳號」label"
has_text /tmp/android-a15-detail.xml "••••••••" || fail "A15 詳情值塊應遮罩"
has_text /tmp/android-a15-detail.xml "其他資訊" || fail "A15 詳情缺「其他資訊」節"
shot 15-detail-skin
$ADB shell input keyevent 4 </dev/null >/dev/null 2>&1
sleep 1
# 全頁表單：FAB → 新增項目頁（名稱＋seed＋網址），存完列表掛待推送。
tap_text a15-fab "新增"
wait_text "新增項目" 10 || fail "A15 全頁表單沒出現"
shot 15-form
tap_text a15-name "項目名稱（必填）"
type_text "totp-demo"
hide_ime
tap_text a15-totp "驗證碼 seed（可留空；編輯不改動＝保留原 seed）"
type_verify "JBSWY3DPEHPK3PXP" a15-seed
hide_ime
tap_text a15-uri "網址（可留空）"
type_text "https://totp.example.com"
hide_ime
$ADB logcat -c
tap_text a15-save "儲存"
wait_text "totp-demo" 15 || { $ADB logcat -d | grep -E 'nsh_app|bitward' | tail -20; fail "A15 表單新增後列表沒出現該筆"; }
dump /tmp/android-a15-pending.xml
has_text /tmp/android-a15-pending.xml "待推送" || fail "A15 表單新增列應掛「待推送」"
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'create'*'待推送'* ]] || fail "A15 logcat 沒有 create 入列軌跡"
shot 15-vault-totp-pending
pass "A15 新皮：chip 列＋FAB＋44px 列節拍、全頁表單建 TOTP 項目（seed 落鏡像）"

# --- 16. A16：autofill save 全鏈（SaveInfo→onSaveRequest→outbox→drain→VW） ----
# 探針頁（AutofillProbeActivity）：hint 帳密欄＋commit 鈕；app 進程未重啟，
# 中樞保持解鎖（force-stop 會丟金鑰，這裡刻意不重啟）。
SAVE_USER="save-e2e-$(date +%s)"
SAVE_PASS="SavePass-9f3Kq"
$ADB shell settings put secure autofill_service "$AF_SVC"
$ADB shell settings put secure current_autofill_service "$AF_SVC"
sleep 2
$ADB logcat -c
$ADB shell am start -n "$PKG/.AutofillProbeActivity" >/dev/null 2>&1
sleep 2
tap_text a16-user "probe-user"
for _ in $(seq 1 15); do
  $ADB logcat -d | grep -q 'saveinfo=true' && break
  sleep 1
done
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'onFillRequest unlocked=true'* ]] \
  || { echo "$APP_LOG" | grep -E 'bitward-island|AutofillManager' | tail -8; fail "A16 探針頁沒送來解鎖態 fill 請求"; }
[[ "$APP_LOG" == *'saveinfo=true'* ]] || fail "A16 未儲存組合沒掛 SaveInfo"
type_verify "$SAVE_USER" a16-typed
hide_ime
tap_text a16-pass "probe-pass"
type_text "$SAVE_PASS"
hide_ime
$ADB logcat -c
tap_text a16-submit "提交"
# 系統存檔提示（SaveInfo 流的必經步驟）：emulator 是 zh 語系，Save 鈕實錄
# 文案＝「保存」（描述列「儲存到 Bitward」不可點，別誤打）；英文 image 退
# 「Save」。点了才會有 onSaveRequest。
for _ in $(seq 1 12); do
  dump /tmp/android-a16-prompt.xml
  if has_text /tmp/android-a16-prompt.xml "保存"; then tap_text a16-btn "保存"
  elif has_text /tmp/android-a16-prompt.xml "Save"; then tap_text a16-btn "Save"
  fi
  $ADB logcat -d | grep -q 'save ok action=' && break
  sleep 1
done
APP_LOG=$($ADB logcat -d)
[[ "$APP_LOG" == *'bitward-island: save ok action=created'* ]] \
  || { echo "$APP_LOG" | grep bitward-island | tail -8; fail "A16 onSaveRequest 全鏈沒落地（無 save ok 標記）"; }
[[ "$APP_LOG" == *'jni: save q=io.bitward.android action=created'* ]] \
  || fail "A16 Rust 側沒有 create 軌跡（JNI save 標記缺失）"
shot 16-save-prompt
# 收斂走「登入 pull 前 drain」的正史路徑：重啟 app 重登（A11/A12 同款），
# 計數 4→6（seed＋totp-demo＋存檔項）且待推送清乾淨。
$ADB shell am force-stop $PKG
$ADB shell settings put secure autofill_service null >/dev/null 2>&1 || true
$ADB shell settings put secure current_autofill_service null >/dev/null 2>&1 || true
$ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
wait_text "登入你的密碼庫" 30 || fail "A16 重啟後登入畫面沒出現"
tap_text pw-field3 "只用於派生金鑰，不落地"
type_text "$WP"
hide_ime
tap_text login-btn3 "登入"
wait_text "鏡像 6 筆" 60 || { $ADB logcat -d | grep -E 'bitward|nsh|AndroidRuntime' | tail -20; fail "A16 重登後計數不對（應 6＝seed4＋totp-demo＋存檔）"; }
dump /tmp/android-a16-list.xml
has_text /tmp/android-a16-list.xml "io.bitward.android" || fail "A16 存檔項沒進列表"
if has_text /tmp/android-a16-list.xml "待推送"; then fail "A16 登入 drain 後「待推送」沒清"; fi
shot 16-save-synced
# VW 直讀：暫時 daemon 拉鏡像、reveal 存進去那組帳密（金鑰鏈同 A12 口徑）。
BITWARD_DATA_DIR="$PWD/$DA" "$DAEMON" --data-dir "$DA" --sock "$DA/s3" >"$DA/log3" 2>&1 &
HUB_PID=$!
trap 'kill $HUB_PID 2>/dev/null || true' EXIT
sleep 1
B3() { "$CLI" --sock "$DA/s3" "$@"; }
echo "$WP" | B3 login --server "$SRV_HOST" --email "$EMAIL" --password-stdin >/dev/null \
  || fail "A16 暫時 daemon 登入失敗"
B3 sync >/dev/null
SAVED_ID=$(B3 --json ls --text "io.bitward.android" | python3 -c 'import json,sys
# 查詢鍵同字串會連 bitward-selftest（uri 同 host）一起命中；按名稱取存檔那筆。
rows=[r for r in json.load(sys.stdin) if r["meta"].get("name")=="io.bitward.android"]
print(rows[0]["meta"]["id"] if rows else "")')
[[ -n "$SAVED_ID" ]] || fail "A16 伺服器鏡像沒有存檔項（push 未送達 VW）"
REVEAL=$(B3 --json reveal "$SAVED_ID")
[[ "$REVEAL" == *"\"password\": \"$SAVE_PASS\""* ]] || fail "A16 VW 端 reveal 密碼不對：$REVEAL"
[[ "$REVEAL" == *"$SAVE_USER"* ]] || fail "A16 VW 端 reveal 帳號欄缺失：$REVEAL"
TOTPID=$(B3 --json ls --text "totp-demo" | python3 -c 'import json,sys; rows=json.load(sys.stdin); print(rows[0]["meta"]["id"] if rows else "")')
[[ -n "$TOTPID" ]] || fail "A16 表單建的 totp-demo 沒推達 VW（同批 drain）"
pass "A16 autofill save 全鏈：SaveInfo→onSaveRequest→Hub create→drain→VW reveal 實帳密"

# --- 17. A17：詳情 TOTP 自動碼（免按鈕、碼與本機 HMAC 同值） ------------------
tap_text a17-row "totp-demo"
wait_text "剩餘" 20 || { dump /tmp/android-a17-totp.xml; fail "A17 進詳情沒出現倒數條（自動取碼沒跑）"; }
CODE=""
for _ in $(seq 1 10); do
  C=$(python3 -c "
import base64,hmac,struct,time,hashlib
seed=base64.b32decode('JBSWY3DPEHPK3PXP')
t=int(time.time())//30
d=hmac.new(seed,struct.pack('>Q',t),hashlib.sha1).digest()
print('%06d' % (struct.unpack('>I',d[-4:])[0] % 1000000))")
  dump /tmp/android-a17-code.xml
  grep -q "text=\"$C\"" /tmp/android-a17-code.xml && { CODE=$C; break; }
  sleep 1
done
[[ -n "$CODE" ]] || { dump /tmp/android-a17-code.xml; fail "A17 自動碼與本機 HMAC 不同值"; }
shot 17-totp-auto
$ADB shell input keyevent 4 </dev/null >/dev/null 2>&1
kill $HUB_PID 2>/dev/null || true
trap - EXIT
pass "A17 TOTP 自動碼現算渲染（code=$CODE 同值、倒數條在），詳情截圖留證"

echo
echo "截圖：$(ls "$SHOTS" | tr '\n' ' ')"
echo "APK：$APK"
