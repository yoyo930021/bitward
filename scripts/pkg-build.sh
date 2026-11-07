#!/bin/bash
# pkg-build.sh — 正式安裝管線：建置 → dist/Bitward-<version>.pkg → installer -target /
# → receipt/簽章斷言 →（--experiment）BTM 判定實驗（啟用 SMAppService agent＋抓證據）。
# 冪等：可重複執行；staging 每回合重建（殭屍二進位保險沿用 dev-install.sh 的教訓：
# ditto 後強制重拷 helper＋重簽＋功能探測，並重封 App 外層）。
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
BUNDLE=~/Library/Developer/Xcode/DerivedData/Bitward-essisnxmmachgpfgzkzjfqzduucb/Build/Products/Release/Bitward.app
IDENTITY=BFA4593FB215C51771B6988EBFADE08E7A3F8DE0   # Mac Developer: Created via API (team 8V5224A99M)
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

# --experiment-only：跳過建置/安裝（／Applications 已是同產物時免再要授權），
# 直接斷言＋BTM 實驗。
if [ "$EXPERIMENT_ONLY" = 0 ]; then

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
codesign -f -s "$IDENTITY" --entitlements bins/bitwarderd/helper.entitlements \
  "$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd"
# 殭屍 plist 保險：增量建置可能殘留舊 LaunchAgents（不合規 Label 的兄弟檔會讓
# SMAppService register 拋 EINVAL，2026-11-07 實測）→ 以源檔為唯一事實重建目錄。
LA_STAGED="$STAGE/root/Bitward.app/Contents/Library/LaunchAgents"
rm -rf "$LA_STAGED"; mkdir -p "$LA_STAGED"
cp -f platforms/macos/Bitward/Resources/io.bitward.dev.daemon.plist "$LA_STAGED/"
# 剝掉 AppleDouble 側錄（._*，xattr 隨 cp 落地）——pkg payload 髒檔
find "$STAGE/root" -name '._*' -delete
# helper/plist 改變 bytes → 外層 CodeResources 需重封（entitlements 用專案源檔，
# 與 project.yml CODE_SIGN_ENTITLEMENTS 一致；原簽章 flags=none，不加 -o runtime）
codesign -f -s "$IDENTITY" --entitlements platforms/macos/Bitward/Bitward.entitlements \
  "$STAGE/root/Bitward.app"
# 功能探測（舊殭屍二進位不認 --service）
"$STAGE/root/Bitward.app/Contents/Helpers/bitwarderd" --service status >/dev/null 2>&1 \
  || { echo "FATAL: staged helper 不支援 --service（舊殭屍二進位？）"; exit 1; }
codesign --verify --deep --strict "$STAGE/root/Bitward.app"
echo "    staged helper functional + bundle seal OK"
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
# productsign 只吃 Installer Signing 憑證（EKU 1.3.6.1.4.1.311.10.3.8）。本機六張
# 憑證全是 Code Signing EKU——實測 Mac Developer 與 Apple Distribution 都被拒：
# "An installer signing identity (not an application signing identity) is required"。
# 無 Developer ID Installer 前降為未簽名 pkg（本機 installer 不吃 pkg 簽章）。
if productsign --sign "$IDENTITY" "$UNSIGNED" "$PKG" 2>/tmp/productsign.err; then
  echo "    productsign OK"
else
  echo "    productsign skipped：$(tail -1 /tmp/productsign.err)"
  mv "$UNSIGNED" "$PKG"
fi
echo "    $PKG"

echo "==> notarize（BW_NOTARIZE=${BW_NOTARIZE:-0}）"
if [ "${BW_NOTARIZE:-0}" = 1 ]; then
  P8=${BW_APPLE_API_KEY_P8:-$(ls "$HOME"/private_keys/*.p8 2>/dev/null | head -1)}
  [ -n "$P8" ] || { echo "FATAL: BW_NOTARIZE=1 但找不到 .p8（~/private_keys 或 BW_APPLE_API_KEY_P8）"; exit 1; }
  : "${BW_APPLE_API_KEY:?BW_NOTARIZE=1 需 BW_APPLE_API_KEY（ASC API key id）}"
  : "${BW_APPLE_API_ISSUER:?BW_NOTARIZE=1 需 BW_APPLE_API_ISSUER}"
  xcrun notarytool submit "$PKG" --key "$P8" --key-id "$BW_APPLE_API_KEY" \
    --issuer "$BW_APPLE_API_ISSUER" --wait
  xcrun stapler staple "$PKG"
else
  echo "    skipped：無 Developer ID 身分與 ASC API key；本機 installer 路徑不吃 Gatekeeper 公證"
fi

echo "==> installer -pkg -target /"
pgrep -x Bitward >/dev/null && kill -9 "$(pgrep -x Bitward)" 2>/dev/null || true
if ! sudo -n installer -pkg "$PKG" -target /; then
  echo "    無免密 sudo → 系統授權框（SecurityAgent），需要使用者按一次密碼/Touch ID"
  osascript -e "do shell script \"/usr/sbin/installer -pkg '$PKG' -target /\" with administrator privileges"
fi

echo "==> 斷言"
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
/Applications/Bitward.app/Contents/Helpers/bitwarderd --service status >/dev/null 2>&1 \
  || { echo "FATAL: 已裝 helper 不支援 --service"; exit 1; }
echo "    pkg 簽章 / bundle 簽章 / 落地路徑 / receipt / helper 功能：全部 OK"
pkgutil --pkg-info "$PKG_ID" | sed 's/^/    /'
fi

if [ "$EXPERIMENT" = 1 ]; then
  echo "==> BTM 判定實驗：open -a Bitward → AX 按「啟用」"
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
	repeat 30 times
		if (count of windows of process "Bitward") > 0 then exit repeat
		delay 1
	end repeat
end tell
set allE to my settleTree()
if allE is {} then return "NO AX TREE（視窗沒出來？）"
-- SwiftUI 控制項 name 全 missing value；tab 標籤在 description
tell application "System Events"
	repeat with e in allE
		try
			if (role of e as string) is "AXRadioButton" and (description of e as string) is "狀態" then
				perform action "AXPress" of e
				exit repeat
			end if
		end try
	end repeat
end tell
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
