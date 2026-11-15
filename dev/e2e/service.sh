#!/usr/bin/env bash
# LaunchAgent 註冊鏈 e2e（批次 14.5）：service install 落檔必含 Keychain 開關；
# 註冊檔被改舊後 daemon 啟動自癒合覆寫回模板。全程 HOME=临时目录 +
# BW_SERVICE_NO_BOOTSTRAP，不碰真機 launchd 域。用法：dev/e2e/service.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

cargo build -q -p bitwarderd
BIN=$PWD/target/debug/bitwarderd
H=$(mktemp -d)
P="$H/Library/LaunchAgents/io.bitward.dev.daemon.plist"
trap 'rm -rf "$H"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# 1. install（no-bootstrap）：落檔必含 BW_KEYS_ENABLE_KEYCHAIN=1。
HOME="$H" BW_SERVICE_NO_BOOTSTRAP=1 "$BIN" --push-app-group group.test --service install >/dev/null \
  || fail "service install 非零退出"
grep -q '<key>BW_KEYS_ENABLE_KEYCHAIN</key>' "$P" || fail "註冊檔缺 Keychain 開關"
grep -q '<string>1</string>' "$P" || fail "Keychain 開關值非 1"
echo "ok: install 落檔含 KEYCHAIN=1"

# 2. 自癒合：把註冊檔改成「舊模板」（首個 <string>1</string> 翻 0），起 daemon
#    （臨時 data-dir/sock）→ 啟動即覆寫回模板值。
perl -0pi -e 's/<string>1<\/string>/<string>0<\/string>/' "$P"
grep -q '<string>0</string>' "$P" || fail "改版未生效（前置條件）"
HOME="$H" BW_SERVICE_ALLOW_DEV_HEAL=1 nohup "$BIN" --data-dir "$H/dd" --sock "$H/s" --push-app-group group.test \
  >"$H/daemon.log" 2>&1 &
DPID=$!
trap 'kill $DPID 2>/dev/null || true; rm -rf "$H"' EXIT
for _ in $(seq 1 30); do grep -q 'self-heal' "$H/daemon.log" 2>/dev/null && break; sleep 0.3; done
grep -q 'self-heal' "$H/daemon.log" || fail "啟動未觸發自癒合（log：$(tail -3 "$H/daemon.log")）"
for _ in $(seq 1 20); do grep -q '<string>1</string>' "$P" && break; sleep 0.3; done
grep -q '<string>1</string>' "$P" || fail "自癒合未覆寫回模板"
echo "ok: 啟動自癒合覆寫舊註冊"

# 3. 冪等：再啟動一次，不應重複觸發（同文跳過）。
kill $DPID 2>/dev/null || true; wait $DPID 2>/dev/null || true
: >"$H/daemon2.log"
HOME="$H" BW_SERVICE_ALLOW_DEV_HEAL=1 nohup "$BIN" --data-dir "$H/dd" --sock "$H/s" --push-app-group group.test \
  >"$H/daemon2.log" 2>&1 &
DPID2=$!
trap 'kill $DPID2 2>/dev/null || true; rm -rf "$H"' EXIT
sleep 2
kill $DPID2 2>/dev/null || true
grep -q 'self-heal' "$H/daemon2.log" && fail "同文重複觸發自癒合（非冪等）"
echo "ok: 同文跳過（冪等）"

# 4. 真域自癒合重載存活（14.7）：獨立 label＋獨立 sock＋臨時 data-dir 全經
#    plist env 傳導（launchd 拉起端 HOME=真 home,靠 label 隔離不撞常駐）。
#    破註冊檔→kickstart→daemon 自癒合→重載子進程（process_group 脫組＋
#    bootstrap 重試）必須在父死後存活並完成重掛：哨兵 ok、job 仍在 list。
TLABEL="io.bitward.dev.daemontest$$"
TSOCK="$H/test.sock"
TP="$HOME/Library/LaunchAgents/$TLABEL.plist"
cleanup4() { launchctl bootout "gui/$(id -u)/$TLABEL" 2>/dev/null || true; rm -f "$TP"; }
trap 'cleanup4; kill $DPID2 2>/dev/null || true; rm -rf "$H"' EXIT
BW_SERVICE_LABEL="$TLABEL" BW_SERVICE_ALLOW_DEV_HEAL=1 \
BITWARD_DATA_DIR="$H/dd" \
  "$BIN" --sock "$TSOCK" --push-app-group group.test --service install >/dev/null \
  || fail "test-label 真 bootstrap 失敗"
for _ in $(seq 1 20); do launchctl print "gui/$(id -u)/$TLABEL" >/dev/null 2>&1 && break; sleep 0.5; done
launchctl print "gui/$(id -u)/$TLABEL" >/dev/null 2>&1 || fail "test job 未掛載"
perl -0pi -e 's/<string>1<\/string>/<string>0<\/string>/' "$TP"
launchctl kickstart -k "gui/$(id -u)/$TLABEL"
SENT="$H/dd/self-heal.result"
for _ in $(seq 1 40); do [[ -f "$SENT" ]] && break; sleep 1; done
[[ "$(cat "$SENT" 2>/dev/null)" == "ok" ]] || fail "自癒合重載未完成（哨兵=$(cat "$SENT" 2>/dev/null || echo 無)）"
launchctl print "gui/$(id -u)/$TLABEL" >/dev/null 2>&1 || fail "重載後 job 未回掛（race 未根治）"
grep -q '<string>1</string>' "$TP" || fail "自癒合未還原模板值"
cleanup4
echo "ok: 真域自癒合重載存活（哨兵=ok、job 回掛、模板還原）"

echo "SERVICE: ALL PASS"
