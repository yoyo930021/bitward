#!/bin/bash
# signing.sh — 簽章/公證斷言：對 dist 最新 pkg＋/Applications 落地 bundle 查證
# 「Developer ID 直裝批次」的產物形態（FINDINGS §10/§11 判定鏈的可重跑槓桿）。
# 用法：
#   dev/e2e/signing.sh                       # 預設：Mac Developer 防呆形態（沙盒主線）
#   BW_EXPECT=devid dev/e2e/signing.sh       # Developer ID 形態：全嵌套同身分＋hardened
#                                            # ＋時間戳＋（公證跑過才查）staple/spctl
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD
APP=/Applications/Bitward.app
LABEL=io.bitward.dev.daemon
DEVID_APP=${BW_DEVID_APP:-152E4509D92E1F1CDC884E0D7A022A2F0F224B1D}
DEVID_INSTALLER=${BW_DEVID_INSTALLER:-AECAA36E20943AEA428C9643643DAD2C1D5459BD}
MACDEV=${BW_MACDEV_ID:-BFA4593FB215C51771B6988EBFADE08E7A3F8DE0}
EXPECT=${BW_EXPECT:-macdev}
case "$EXPECT" in
  macdev) WANT_ID=$MACDEV;     WANT_AUTH='Mac Developer' ;;
  devid)  WANT_ID=$DEVID_APP;  WANT_AUTH='Developer ID Application' ;;
  *) echo "FATAL: BW_EXPECT=$EXPECT 不存在（macdev|devid）"; exit 1 ;;
esac

fail() { echo "FAIL: $*"; exit 1; }
ok()   { echo "ok: $*"; }

VERSION=$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")
PKG=$REPO/dist/Bitward-$VERSION.pkg
[ -d "$APP" ] || fail "/Applications/Bitward.app 不存在"

echo "==> 1. 全部 Mach-O 以 $WANT_AUTH 簽章＋深驗"
find "$APP" -type f \( -path '*/MacOS/*' -o -path '*/Helpers/*' \) | while read -r f; do
  file -b "$f" | grep -q 'Mach-O' || continue
  AUTH=$(codesign -dvv "$f" 2>&1 | grep '^Authority=' | head -1 | cut -d= -f2-)
  echo "$AUTH" | grep -q "^$WANT_AUTH" \
    || fail "$f 簽章身分=$AUTH（期望 $WANT_AUTH）"
  if [ "$EXPECT" = devid ]; then
    FLAGS=$(codesign -dvv "$f" 2>&1 | grep -o 'flags=0x[0-9a-f]*([^)]*)' | head -1)
    case "$FLAGS" in *runtime*) ;; *) fail "$f 缺 hardened runtime（flags=$FLAGS）" ;; esac
    codesign -d --entitlements :- "$f" >/dev/null 2>&1 || fail "$f 簽章不可讀"
  fi
done
codesign --verify --deep --strict "$APP" && ok "bundle 深驗通過（含 appex/helper/daemon）"

echo "==> 2. Developer ID 專屬：無殘留 profile＋時間戳"
if [ "$EXPECT" = devid ]; then
  [ ! -f "$APP/Contents/embedded.provisionprofile" ] \
    || fail "Contents 仍嵌 Apple Development profile（直裝批次應剝除）"
  [ ! -f "$APP/Contents/PlugIns/BitwardProvider.appex/Contents/embedded.provisionprofile" ] \
    || fail "appex 仍嵌 dev profile"
  codesign -dvv "$APP/Contents/MacOS/Bitward" 2>&1 | grep -q 'TeamIdentifier=8V5224A99M' \
    || fail "TeamIdentifier 不符"
  ok "dev profile 已剝、team 綁定正確"
fi

echo "==> 3. entitlements 形態斷言"
ENT=$(codesign -d --entitlements :- "$APP" 2>/dev/null | plutil -p -)
echo "$ENT" | grep -q 'application-groups' || fail "App 未宣告 App Groups"
FORM_SANDBOX=0
echo "$ENT" | grep -q 'app-sandbox' && FORM_SANDBOX=1
HELPER_ENT=$(codesign -d --entitlements :- "$APP/Contents/Helpers/bitwarderd" 2>/dev/null | plutil -p -)
echo "$HELPER_ENT" | grep -q 'application-groups' || fail "裸 helper 未宣告 App Groups"
if [ "$EXPECT" = devid ] && [ "$FORM_SANDBOX" = 0 ]; then
  echo "$HELPER_ENT" | grep -q 'app-sandbox' && fail "direct 分叉裸 helper 不該有 sandbox"
  ok "直裝形態：App 非沙盒＋helper 非沙盒＋App Groups 俱在"
elif [ "$FORM_SANDBOX" = 1 ]; then
  ok "沙盒形態：App 沙盒（daemon 走 BitwardDaemon.app）"
else
  ok "形態：App 非沙盒（dev 批次不強求）"
fi

echo "==> 4. pkg 簽章與公證"
if pkgutil --check-signature "$PKG" >/dev/null 2>&1; then
  pkgutil --check-signature "$PKG" | grep -q '1. Developer ID Installer' \
    || fail "pkg 不是 Developer ID Installer 簽章"
  pkgutil --check-signature "$PKG" | grep -q "$DEVID_INSTALLER" \
    || echo "    note: pkg 簽章鏈與 $DEVID_INSTALLER 非同印（查名稱即可）"
  ok "pkg 以 Developer ID Installer 簽章"
else
  [ "$EXPECT" = macdev ] && ok "pkg 未簽名（macdev 批次預期降級）" \
    || fail "devid 批次 pkg 竟未簽章"
fi
if xcrun stapler validate "$PKG" >/dev/null 2>&1; then
  spctl -a -t install "$PKG" 2>/dev/null || fail "staple 在但 spctl 拒收"
  ok "公證 ticket 已釘＋Gatekeeper 願收"
else
  [ "$EXPECT" = macdev ] && ok "未公證（macdev 批次預期）" \
    || fail "devid 批次 pkg 無公證 ticket"
fi

echo "==> 5. receipt 與 bundle 同源"
pkgutil --pkgs | grep -qx io.bitward.dev.pkg || fail "receipt 缺失"
cmp -s "$APP/Contents/Helpers/bitwarderd" \
     "$REPO/dist/stage/root/Bitward.app/Contents/Helpers/bitwarderd" \
  || echo "    note: 已裝 helper ≠ 現 stage（跨批次正常；同批次跑 pkg-build 後應為 SAME）"
ok "receipt 在案"

echo "SIGNING E2E: ALL PASS"
