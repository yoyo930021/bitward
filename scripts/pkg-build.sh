#!/bin/bash
# pkg-build.sh — 正式安裝管線：建置 → dist/Bitward-<version>.pkg → installer -target /
# → receipt/簽章斷言 →（--experiment）BTM 判定實驗（啟用 SMAppService agent＋抓證據）。
# 冪等：可重複執行；staging 每回合重建（殭屍二進位保險沿用 dev-install.sh 的教訓：
# ditto 後強制重拷 helper＋重簽＋功能探測，並重封 App 外層）。
# 簽章參數（預設＝開發防呆：Mac Developer、沙盒形態、未簽 pkg 降級）：
#   BW_SIGN_ID       重簽 bundle 全家（executable/appex/helper/daemon/外層）的身分
#                    （SHA 或名稱）。Developer ID Application → 自動加
#                    -o runtime --timestamp（公證必要）並重簽 appex。
#   BW_INSTALLER_ID  productsign 用的 Developer ID Installer 身分；設了就必簽
#                    （失敗即 FATAL），沒設維持「試 $BW_SIGN_ID、不支就降未簽」。
#   BW_FORM          sandbox（預設，現行主線）| direct（Developer ID 直裝分叉：
#                    App 去 app-sandbox、BundleProgram 指回裸二進位、剝 dev profile）。
#   BW_NOTARIZE=1    notarytool 真公證＋staple＋spctl 斷言（需 BW_APPLE_API_KEY /
#                    BW_APPLE_API_ISSUER；p8 找 ~/private_keys、~/.asc/keys）。
#   BW_PROFILE       Developer ID（MAC_APP_DIRECT）.provisionprofile 路徑；設了就嵌進
#                    App（受限 entitlements 授權用）。BW_PROFILE_APPEX 同型、嵌 appex
#                    （provider 屬另一 App ID）；只給 BW_PROFILE 時 appex 維持剝除。
# 巢狀密碼庫：staging 一律經 scripts/gui-bundle.sh 組 BitwardGUI.app 進
#   Contents/Applications（同身分＋同 runtime flags 重簽，納入深簽鏈）。
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
BUNDLE=~/Library/Developer/Xcode/DerivedData/Bitward-essisnxmmachgpfgzkzjfqzduucb/Build/Products/Release/Bitward.app
IDENTITY=${BW_SIGN_ID:-BFA4593FB215C51771B6988EBFADE08E7A3F8DE0}   # 預設 Mac Developer: Created via API (team 8V5224A99M)
INSTALLER_ID=${BW_INSTALLER_ID:-}
FORM=${BW_FORM:-sandbox}
GROUP=group.8V5224A99M.io.bitward.dev
PKG_ID=io.bitward.dev.pkg
LABEL=io.bitward.dev.daemon
STAGE=$REPO/dist/stage
EXPERIMENT=0
EXPERIMENT_ONLY=0
case "${1:-}" in
  --experiment) EXPERIMENT=1 ;;
  --experiment-only) EXPERIMENT=1; EXPERIMENT_ONLY=1 ;;
esac

# 身分形態：Developer ID Application → 公證三要件（-o runtime＋--timestamp＋同身分重簽
# 全部嵌套 code，含 appex；Xcode 只吃 Apple Development，dev profile 對直裝無意義→剝）。
ID_NAME=$(security find-identity -v -p codesigning 2>/dev/null \
  | awk -F'"' -v s="$IDENTITY" 'index($0, s){print $2; exit}')
IS_DEVID=0
case "$ID_NAME" in Developer\ ID\ Application*) IS_DEVID=1 ;; esac
CS_RUNTIME=''
[ "$IS_DEVID" = 1 ] && CS_RUNTIME='-o runtime --timestamp'
case "$FORM" in
  sandbox) APP_ENT=platforms/macos/Bitward/Bitward.entitlements
           LA_PLIST=platforms/macos/Bitward/Resources/io.bitward.dev.daemon.plist ;;
  direct)  APP_ENT=platforms/macos/Bitward/Bitward.direct.entitlements
           LA_PLIST=platforms/macos/Bitward/Resources/io.bitward.dev.daemon.direct.plist ;;
  *) echo "FATAL: BW_FORM=$FORM 不存在（sandbox|direct）"; exit 1 ;;
esac
echo "==> 簽章形態：${ID_NAME:-$IDENTITY}／form=$FORM"

# --experiment-only：跳過建置/安裝（／Applications 已是同產物時免再要授權），
# 直接斷言＋BTM 實驗。
if [ "$EXPERIMENT_ONLY" = 0 ]; then

echo "==> app icons（gen-icons.sh；xcodebuild 的 resources 階段吃生成物）"
bash scripts/gen-icons.sh

echo "==> cargo release (bitwarderd, bitward)"
cargo build --release -q -p bitwarderd -p bitward

echo "==> xcodebuild release"
cd platforms/macos
xcodegen generate >/dev/null
xcodebuild -project Bitward.xcodeproj -scheme Bitward -destination 'platform=macOS' \
  -configuration Release build 2>&1 | grep -E 'error:|BUILD (SUCCEEDED|FAILED)' | head -3
cd "$REPO"
[ -d "$BUNDLE" ] || { echo "FATAL: DerivedData 無 Release bundle"; exit 1; }

echo "==> staging（殭屍二進位保險）"
rm -rf "$STAGE"; mkdir -p "$REPO/dist" "$STAGE/root"
ditto "$BUNDLE" "$STAGE/root/Bitward.app"
cp -f target/release/bitwarderd "$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd"
# 新鮮度：重簽前 cmp 內容（簽章後 sha 必變，只能在此之前比）
cmp -s target/release/bitwarderd "$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd" \
  || { echo "FATAL: staged helper 與 cargo release 內容不符（殭屍拷貝？）"; exit 1; }
# 功能探測跑 cargo 產物本尊（同 bytes、未沙盒）：staged helper 沙盒化後
# 從 terminal 直接跑會卡在 secinit（容器歸屬），其真運行環境是 launchd。
target/release/bitwarderd --service status >/dev/null 2>&1 \
  || { echo "FATAL: bitwarderd 不支援 --service（舊殭屍二進位？）"; exit 1; }
codesign -f -s "$IDENTITY" $CS_RUNTIME --entitlements bins/bitwarderd/helper.entitlements \
  "$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd"
# 沙盒 daemon（SMAppService 目標）：重組嵌套 BitwardDaemon.app（同殭屍保險）
DA_STAGED="$STAGE/root/Bitward.app/Contents/Helpers/BitwardDaemon.app"
rm -rf "$DA_STAGED"; mkdir -p "$DA_STAGED/Contents/MacOS"
cp -f target/release/bitwarderd "$DA_STAGED/Contents/MacOS/bitwarderd"
cmp -s target/release/bitwarderd "$DA_STAGED/Contents/MacOS/bitwarderd" \
  || { echo "FATAL: staged daemon app 二進位不符"; exit 1; }
cp -f platforms/macos/Bitward/Resources/BitwardDaemon-Info.plist "$DA_STAGED/Contents/Info.plist"
codesign -f -s "$IDENTITY" $CS_RUNTIME -i io.bitward.dev.daemon --entitlements bins/bitwarderd/daemon.entitlements \
  "$DA_STAGED/Contents/MacOS/bitwarderd"
codesign -f -s "$IDENTITY" $CS_RUNTIME -i io.bitward.dev.daemon --entitlements bins/bitwarderd/daemon.entitlements \
  "$DA_STAGED"
# Developer ID 批次：appex 也要同身分重簽（公證要求全部嵌套 code 皆 Developer ID＋
# 時間戳＋hardened runtime；Xcode 留 Apple Development 會被 notarytool 打回），
# 並剝掉對直裝無意義的 Apple Development profile（殭屍 profile 保險）。
# BW_PROFILE=<path.provisionprofile>（MAC_APP_DIRECT，含 App Groups）→ 改嵌該 profile
# 進 App＋appex（沙盒形態 group.* 需 profile 授權時用；裸二進位無法嵌 profile，
# TN3125 正解＝BitwardDaemon.app 包殼，direct 分叉不需要它）。
APPEX="$STAGE/root/Bitward.app/Contents/PlugIns/BitwardProvider.appex"
if [ "$IS_DEVID" = 1 ]; then
  if [ -n "${BW_PROFILE:-}" ]; then
    cp -f "$BW_PROFILE" "$STAGE/root/Bitward.app/Contents/embedded.provisionprofile"
    if [ -n "${BW_PROFILE_APPEX:-}" ]; then
      cp -f "$BW_PROFILE_APPEX" "$APPEX/Contents/embedded.provisionprofile"
    else
      rm -f "$APPEX/Contents/embedded.provisionprofile"
    fi
  else
    rm -f "$STAGE/root/Bitward.app/Contents/embedded.provisionprofile" \
          "$APPEX/Contents/embedded.provisionprofile"
  fi
  codesign -f -s "$IDENTITY" $CS_RUNTIME \
    --entitlements platforms/macos/BitwardProvider/BitwardProvider.entitlements \
    "$APPEX/Contents/MacOS/BitwardProvider"
  codesign -f -s "$IDENTITY" $CS_RUNTIME \
    --entitlements platforms/macos/BitwardProvider/BitwardProvider.entitlements \
    "$APPEX"
fi
# 巢狀密碼庫（NSH GUI）：BitwardGUI.app 進 Contents/Applications——殼轉 LSUIElement
# 背景後由殼 NSWorkspace.open 此 bundle，Dock 只剩「Bitward 密碼庫」單一入口。
# gui-bundle.sh 先內後外簽完 GUI bundle 深鏈，外層 seal（下段）才把它收進 CodeResources。
BW_SIGN_ID="$IDENTITY" BW_CS_FLAGS="$CS_RUNTIME" bash scripts/gui-bundle.sh \
  "$STAGE/root/Bitward.app/Contents/Applications"
# 殭屍 plist 保險：增量建置可能殘留舊 LaunchAgents（不合規 Label 的兄弟檔會讓
# SMAppService register 拋 EINVAL，2026-11-07 實測）→ 以源檔為唯一事實重建目錄。
LA_STAGED="$STAGE/root/Bitward.app/Contents/Library/LaunchAgents"
rm -rf "$LA_STAGED"; mkdir -p "$LA_STAGED"
cp -f "$LA_PLIST" "$LA_STAGED/io.bitward.dev.daemon.plist"
# 剝掉 AppleDouble 側錄（._*，xattr 隨 cp 落地）——pkg payload 髒檔
find "$STAGE/root" -name '._*' -delete
# helper/plist 改變 bytes → 外層 CodeResources 需重封（entitlements 依 $FORM 選檔，
# 沙盒形態與專案源檔 CODE_SIGN_ENTITLEMENTS 一致；Mac Developer 維持 flags=none，
# Developer ID 由 $CS_RUNTIME 補 hardened runtime＋時間戳）
codesign -f -s "$IDENTITY" $CS_RUNTIME --entitlements "$APP_ENT" \
  "$STAGE/root/Bitward.app"
codesign --verify --deep --strict "$STAGE/root/Bitward.app"
echo "    staged helper fresh + bundle seal OK"
VERSION=$(plutil -extract CFBundleShortVersionString raw \
  "$STAGE/root/Bitward.app/Contents/Info.plist")

echo "==> productbuild + productsign"
# BundleOverwriteAction=update：同版本重複安裝也要覆蓋（upgrade 只在版本較新时装）
cat > "$STAGE/component.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>BundleHasStrictIdentifier</key>
		<true/>
		<key>BundleIsRelocatable</key>
		<false/>
		<key>BundleIsVersionChecked</key>
		<true/>
		<key>BundleOverwriteAction</key>
		<string>update</string>
		<key>RootRelativeBundlePath</key>
		<string>Bitward.app</string>
	</dict>
</array>
</plist>
EOF
UNSIGNED=$STAGE/Bitward-$VERSION.unsigned.pkg
PKG=$REPO/dist/Bitward-$VERSION.pkg
# productbuild 不支援 --component-plist；pkgbuild 的 component-plist 只吃 --root
# 佈局（root/Bitward.app → /Applications/Bitward.app），再 productbuild 合成 product 歸檔。
pkgbuild --root "$STAGE/root" --component-plist "$STAGE/component.plist" \
  --install-location /Applications \
  --identifier "$PKG_ID" --version "$VERSION" "$STAGE/bitward-component.pkg"
productbuild --synthesize --package "$STAGE/bitward-component.pkg" \
  "$STAGE/distribution.plist"
productbuild --distribution "$STAGE/distribution.plist" --package-path "$STAGE" \
  --identifier "$PKG_ID" --version "$VERSION" "$UNSIGNED"
# productsign 只吃 Installer Signing EKU（1.3.6.1.4.1.311.10.3.8）：實測 Mac Developer
# 與 Apple Distribution 都被拒（「An installer signing identity (not an application
# signing identity) is required」）。BW_INSTALLER_ID（Developer ID Installer）設了就
# 必簽、失敗即 FATAL；沒設維持試 $IDENTITY、不支就降未簽 pkg（本機 installer 不吃 pkg 簽章）。
if [ -n "$INSTALLER_ID" ]; then
  productsign --sign "$INSTALLER_ID" "$UNSIGNED" "$PKG" 2>/tmp/productsign.err \
    || { echo "FATAL: productsign（$INSTALLER_ID）失敗：$(tail -1 /tmp/productsign.err)"; exit 1; }
  echo "    productsign OK（Installer 身分）"
elif productsign --sign "$IDENTITY" "$UNSIGNED" "$PKG" 2>/tmp/productsign.err; then
  echo "    productsign OK"
else
  echo "    productsign skipped：$(tail -1 /tmp/productsign.err)"
  mv "$UNSIGNED" "$PKG"
fi
echo "    $PKG"

echo "==> notarize（BW_NOTARIZE=${BW_NOTARIZE:-0}）"
# 紀律（2026-11-09 實錄）：公證單綁的是「送件當下那份 pkg」。若送單後又重跑管線
# 覆蓋 dist/*.pkg，stapler 會補到未公證的新產物上（error 65）。正解＝功能收斂後
# 一次性 build→submit→staple→install，中途重建別送單。
if [ "${BW_NOTARIZE:-0}" = 1 ]; then
  : "${BW_APPLE_API_KEY:?BW_NOTARIZE=1 需 BW_APPLE_API_KEY（ASC API key id）}"
  : "${BW_APPLE_API_ISSUER:?BW_NOTARIZE=1 需 BW_APPLE_API_ISSUER}"
  # p8 依 key id 配對優先（private_keys → .asc/keys），再降任何 private_keys/*.p8（舊慣例）。
  # || true：ls 對不存在 glob 回非零，pipefail＋set -e 會在賦值處無聲斃掉腳本（2026-11-08 實測）。
  P8=${BW_APPLE_API_KEY_P8:-$( { ls "$HOME"/private_keys/AuthKey_${BW_APPLE_API_KEY}.p8 \
    "$HOME"/.asc/keys/AuthKey_${BW_APPLE_API_KEY}.p8 \
    "$HOME"/private_keys/*.p8 2>/dev/null || true; } | head -1)}
  [ -n "$P8" ] || { echo "FATAL: BW_NOTARIZE=1 但找不到 AuthKey_${BW_APPLE_API_KEY}.p8（BW_APPLE_API_KEY_P8 可指定）"; exit 1; }
  xcrun notarytool submit "$PKG" --key "$P8" --key-id "$BW_APPLE_API_KEY" \
    --issuer "$BW_APPLE_API_ISSUER" --wait
  xcrun stapler staple "$PKG"
  # 公證結果入檔：ticket 在 pkg 上＋Gatekeeper 願收（-t install）
  xcrun stapler validate "$PKG"
  spctl -a -t install -vvv "$PKG"
else
  echo "    skipped：BW_NOTARIZE!=1；本機 installer 路徑不吃 Gatekeeper 公證"
fi

echo "==> installer -pkg -target /"
# BundleOverwriteAction=update 只覆蓋 BOM 內檔：dev-install 塞的 embedded.provisionprofile
# 等殭屍檔不在新 BOM→裝後殘留→deep seal 紅（2026-11-08 實測）。殭屍清理放裝後：
# 裝前 rm 整包會令 installer 對「被改過的 bundle」拒覆蓋、靜默裝半套（同日實測）。
pgrep -x Bitward >/dev/null && kill -9 "$(pgrep -x Bitward)" 2>/dev/null || true
# 舊密碼庫實例若活著，殼轉發只會起它（同 bundle id 單例）——先清再測才收新產物。
pgrep -x BitwardGUI >/dev/null && kill -9 "$(pgrep -x BitwardGUI)" 2>/dev/null || true
if [ "${BW_NO_INSTALL:-0}" = 1 ]; then
  echo "    BW_NO_INSTALL=1：跳過安裝（產物以 ditto 手動換裝，receipt 維持既有）"
elif ! sudo -n installer -pkg "$PKG" -target /; then
  echo "    無免密 sudo → 系統授權框（SecurityAgent），需要使用者按一次密碼/Touch ID"
  osascript -e "do shell script \"/usr/sbin/installer -pkg '$PKG' -target /\" with administrator privileges"
fi

echo "==> 斷言"
# 殭屍檔清理（dev-install 形態殘留，見上註）：判定＝staging 沒有同路徑檔即屬殭屍。
# 舊實作寫死排除外層路徑，把 BW_PROFILE_APPEX 合法的 appex profile 也誤刪
# （appex CodeResources 缺檔→deep seal 紅，2026-11-09 實測）。
find /Applications/Bitward.app -name embedded.provisionprofile 2>/dev/null | while read -r pf; do
  [ -f "$STAGE/root/Bitward.app/${pf#/Applications/Bitward.app/}" ] || rm -f "$pf"
done
if [ ! -f /Applications/Bitward.app/Contents/embedded.provisionprofile ] \
   && [ -f "$STAGE/root/Bitward.app/Contents/embedded.provisionprofile" ]; then
  # installer 拒覆蓋改過的 bundle（殭屍在場時裝半套）→ admin 群組直接換裝整包
  ditto "$STAGE/root/Bitward.app" /Applications/Bitward.app.tmp && \
    rm -rf /Applications/Bitward.app && mv /Applications/Bitward.app.tmp /Applications/Bitward.app \
    || osascript -e "do shell script \"/bin/rm -rf /Applications/Bitward.app && /usr/bin/ditto '$STAGE/root/Bitward.app' '/Applications/Bitward.app'\" with administrator privileges"
  echo "    已裝 bundle 與 staging 不符 → ditto 換裝完成"
fi
if pkgutil --check-signature "$PKG" >/dev/null 2>&1; then
  pkgutil --check-signature "$PKG" | grep -q 'Installer' \
    || { echo "FATAL: pkg 簽章不是 Installer 身分"; exit 1; }
  echo "    pkg 簽章 OK"
else
  echo "    pkg 未簽名（無 Installer Signing 憑證；見 productsign 段），跳過 check-signature"
fi
codesign --verify --deep --strict /Applications/Bitward.app
[ -d /Applications/Bitward.app ] || { echo "FATAL: /Applications/Bitward.app 不存在"; exit 1; }
pkgutil --pkgs | grep -qx "$PKG_ID" || { echo "FATAL: receipt 缺失"; exit 1; }
cmp -s /Applications/Bitward.app/Contents/Helpers/bitwarderd \
     "$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd" \
  || { echo "FATAL: 已裝 helper 與 staging 產物不符"; exit 1; }
cmp -s /Applications/Bitward.app/Contents/Helpers/BitwardDaemon.app/Contents/MacOS/bitwarderd \
     "$STAGE/root/Bitward.app/Contents/Helpers/BitwardDaemon.app/Contents/MacOS/bitwarderd" \
  || { echo "FATAL: 已裝 BitwardDaemon.app 與 staging 產物不符"; exit 1; }
cmp -s /Applications/Bitward.app/Contents/Applications/BitwardGUI.app/Contents/MacOS/BitwardGUI \
     "$STAGE/root/Bitward.app/Contents/Applications/BitwardGUI.app/Contents/MacOS/BitwardGUI" \
  || { echo "FATAL: 已裝 BitwardGUI.app 與 staging 產物不符"; exit 1; }
echo "    已裝 helper ＝ staging 產物（沙盒 helper 的執行探測交給 launchd＋實驗段）"
echo "    pkg 簽章 / bundle 簽章 / 落地路徑 / receipt / helper 功能：全部 OK"
pkgutil --pkg-info "$PKG_ID" | sed 's/^/    /'
fi

if [ "$EXPERIMENT" = 1 ]; then
  echo "==> BTM 判定實驗：open -a Bitward → 選單喚起狀態頁 → AX 按「啟用」"
  # group sock 若被 terminal demo daemon 佔用，helper 起不來屬預期；
  # 判定看 BTM record 與 job 載入，不看 daemon 能否連 Vaultwarden。
  BTM_SNAP=$REPO/dist/btm-before.txt
  strings /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v18*.btm \
    2>/dev/null | grep -i bitward | sort -u > "$BTM_SNAP" || true
  ls -la /Applications/Bitward.app/Contents/Library/LaunchAgents/
  open -a /Applications/Bitward.app
  osascript <<'EOF'
on settleTree()
	-- System Events quirk（2026-11-07 實測）：`entire contents` 必須先存進變數，
	-- 在 repeat 裡直接展開 `entire contents of window 1` 會拿到空清單。
	tell application "System Events"
		tell process "Bitward"
			repeat 15 times
				set w to window 1
				set allE to entire contents of w
				if (count of allE) > 5 then return allE
				delay 1
			end repeat
			return {}
		end tell
	end tell
end settleTree

on textOf(allE)
	set s to ""
	tell application "System Events"
		repeat with e in allE
			try
				if (role of e as string) is "AXStaticText" then set s to s & ((value of e) as string) & linefeed
			end try
		end repeat
	end tell
	return s
end textOf

tell application "System Events"
	set frontmost of process "Bitward" to true
	delay 1
	-- 殼轉 LSUIElement：無首窗（TabView 已拆）→ 選單「Bitward → 狀態⋯」喚起。
	tell process "Bitward"
		click menu bar item "Bitward" of menu bar 1
		click menu item "狀態⋯" of menu 1 of menu bar item "Bitward" of menu bar 1
	end tell
	repeat 30 times
		if (count of windows of process "Bitward") > 0 then exit repeat
		delay 1
	end repeat
end tell
set allE to my settleTree()
if allE is {} then return "NO AX TREE（視窗沒出來？）"
set txt to ""
set bEn to missing value
set bDis to missing value
-- 切 tab 後 SwiftUI 重繪有延遲，整段探測包進 retry
repeat 10 times
	set allE to my settleTree()
	set txt to my textOf(allE)
	set bEn to missing value
	set bDis to missing value
	set xEn to 1000000
	set xDis to -1
	repeat with e in allE
		tell application "System Events"
			try
				if (role of e as string) is "AXButton" and (description of e as string) is "button" then
					-- quirk：`item 1 of (position of e)` 直寫會被 System Events 當 specifier 強轉噴錯
					set p to position of e
					set px to item 1 of p
					if px < xEn then
						set xDis to xEn
						set bDis to bEn
						set xEn to px
						set bEn to contents of e
					else if px < xDis then
						set xDis to px
						set bDis to contents of e
					end if
				end if
			end try
		end tell
	end repeat
	if bEn is not missing value then exit repeat
	delay 1
end repeat
if bEn is missing value then return "NO BUTTONS" & linefeed & txt
tell application "System Events"
	-- 無條件先停用：清掉同 path 的過期 BTM record（checksum 不符的殭屍 record
	-- 會污染下一次 register；§8「重登入後 record 消失」同族症狀）
	if bDis is not missing value then
		perform action "AXPress" of bDis
		delay 2
	end if
	perform action "AXPress" of bEn
end tell
delay 3
return "BEFORE:" & linefeed & txt & linefeed & "AFTER:" & linefeed & (my textOf(my settleTree()))
EOF
  echo "--- launchctl print gui/$(id -u)/$LABEL"
  launchctl print "gui/$(id -u)/$LABEL" 2>&1 | head -40 || true
  echo "--- BTM db（strings 免 root；before 快照＝dist/btm-before.txt）"
  strings /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v18*.btm \
    2>/dev/null | grep -i bitward | sort -u || true
  echo "--- smd / backgroundtaskmanagementd log（近 5 分鐘，含 bitward 行）"
  log show --last 5m --style compact \
    --predicate 'process == "smd" OR process == "backgroundtaskmanagementd"' 2>/dev/null \
    | grep -iE 'bitward|LaunchAgents|register' | tail -40 || true
fi
echo "==> done"
