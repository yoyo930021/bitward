#!/bin/bash
# gui-bundle.sh — 「Bitward 密碼庫」（NSH Rust GUI，apps/bitward-gui）bundle 組裝＋重簽：
# cargo release（GUI 是獨立 workspace）→ 巢狀 BitwardGUI.app（Contents/MacOS 殼＝
# cargo 產物二進位本尊＋Info.plist）→ 先內後外逐層重簽。存在理由：Bitward.app
# （LSUIElement 背景殼）啟動時 NSWorkspace.open 此 bundle，Dock 只剩密碼庫單一入口。
# 用法：scripts/gui-bundle.sh <輸出目錄>   # 產物 <輸出目錄>/BitwardGUI.app
#   BW_SIGN_ID   簽章身分（預設 ad-hoc "-"，本機防呆；正式管線傳 Developer ID）
#   BW_CS_FLAGS  附加 codesign flags（正式管線：-o runtime --timestamp）
# 巢狀落點（pkg-build.sh staging／dev-install.sh）由呼叫方決定；放進 Bitward.app
# 後外層必須再 seal 一次（CodeResources 含嵌套 bundle，深簽順序先內後外）。
# nsh 0.3.0 的 `nsh package --target macos` 只出 debug runner（無 --release），
# 故直接以 cargo release 產物組最小 bundle；dev 形態（cargo run／nsh run）不受影響。
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=${1:?用法：scripts/gui-bundle.sh <輸出目錄>}
IDENTITY=${BW_SIGN_ID:--}
CS_FLAGS=${BW_CS_FLAGS:-}
APP="$DEST/BitwardGUI.app"
GUI=apps/bitward-gui

echo "==> cargo release（$GUI）"
cargo build --release -q --manifest-path "$GUI/Cargo.toml"
BIN="$GUI/target/release/nsh-app-bitward-gui"
[ -x "$BIN" ] || { echo "FATAL: 無 release 產物 $BIN"; exit 1; }
VERSION=$(python3 -c 'import json;print(json.load(open("'"$GUI"'/nsh.json"))["version"])')
BUILD=$(python3 -c 'import json;print(json.load(open("'"$GUI"'/nsh.json"))["build"])')

echo "==> 組 $APP（v$VERSION）"
mkdir -p "$DEST"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp -f "$BIN" "$APP/Contents/MacOS/BitwardGUI"
# 殭屍二進位保險：簽章前 cmp 內容（簽後 sha 必變）
cmp -s "$BIN" "$APP/Contents/MacOS/BitwardGUI" \
  || { echo "FATAL: bundle 內二進位與 cargo release 不符（殭屍拷貝？）"; exit 1; }
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>zh_TW</string>
	<key>CFBundleDisplayName</key>
	<string>Bitward 密碼庫</string>
	<key>CFBundleExecutable</key>
	<string>BitwardGUI</string>
	<key>CFBundleIdentifier</key>
	<string>io.bitward.dev.gui</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>Bitward 密碼庫</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>$BUILD</string>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>GPL-3.0. Not affiliated with Bitwarden Inc.</string>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
</dict>
</plist>
EOF
# Dock 入口是這顆巢狀 bundle：icon 與外層 App 同源（gen-icons.sh 生成制，產物不入庫）
ICNS=platforms/macos/Bitward/Resources/AppIcon.icns
[ -f "$ICNS" ] || { echo "FATAL: 缺 $ICNS——先跑 scripts/gen-icons.sh"; exit 1; }
mkdir -p "$APP/Contents/Resources"
cp -f "$ICNS" "$APP/Contents/Resources/AppIcon.icns"
find "$APP" -name '._*' -delete
# 無 entitlements：2026-11-08 實測 hardened runtime 不擋 group container sock
# 連線與 ~/Downloads 匯出寫入（非沙盒＋Developer ID 直讀直寫），最小形態即可。
codesign -f -s "$IDENTITY" $CS_FLAGS "$APP/Contents/MacOS/BitwardGUI"
codesign -f -s "$IDENTITY" $CS_FLAGS "$APP"
codesign --verify --strict "$APP"
echo "    BitwardGUI.app 組裝＋重簽 OK（$IDENTITY${CS_FLAGS:+ $CS_FLAGS}）"
