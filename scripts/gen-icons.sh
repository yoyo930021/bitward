#!/bin/bash
# gen-icons.sh — APP icon 產生器：artwork/appicon.svg → macOS icns＋Android adaptive icon。
# 冪等：每次執行都從源檔全量重建產物（崩在中途＝下輪整批覆蓋，收斂到同一終態）。
#
# 產物歸屬（repo 慣例「產物不入庫」只套 macOS）：
#   macOS   build/AppIcon.iconset/*.png → iconutil → platforms/macos/Bitward/Resources/AppIcon.icns
#           icns 屬管線生成物：.gitignore 不入庫，pkg-build.sh／dev-install.sh 建置前呼叫本腳本。
#   Android res/mipmap-*／res/values 產物入 git（Android 慣例 res＝源檔，
#           新 clone 免 resvg 直接 assemble 有 icon；改主設計後重跑本腳本更新）。
#           foreground＝從 appicon.svg 衍生的盾＋鑰匙孔獨立層（無圓角底板、置中、
#           縮 0.95 留 66dp 安全區），background＝純色 #14409E。
# 用法：scripts/gen-icons.sh          # 產生（需 resvg）
#       scripts/gen-icons.sh --check  # 只斷言產物存在且尺寸正確（管線/e2e 用，免 resvg）
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=artwork/appicon.svg
ICNS=platforms/macos/Bitward/Resources/AppIcon.icns
ICONSET=build/AppIcon.iconset
RES=apps/bitward-android/android-shell/app/src/main/res
FG=build/appicon-android-fg.svg

CHECK=0
case "${1:-}" in
  --check) CHECK=1 ;;
  '') ;;
  *) echo "用法：$0 [--check]"; exit 2 ;;
esac

# 產物清單（check 與產生後的自我斷言共用同一事實來源）："kind|path|寬|高"
EXPECTED=(
  "icns|$ICNS||"
  "xml|$RES/mipmap-anydpi-v26/ic_launcher.xml||"
  "xml|$RES/mipmap-anydpi-v26/ic_launcher_round.xml||"
  "xml|$RES/values/ic_launcher_background.xml||"
)
for pair in 16:icon_16x16.png 32:icon_16x16@2x.png 32:icon_32x32.png 64:icon_32x32@2x.png \
            128:icon_128x128.png 256:icon_128x128@2x.png 256:icon_256x256.png \
            512:icon_256x256@2x.png 512:icon_512x512.png 1024:icon_512x512@2x.png; do
  EXPECTED+=("png|$ICONSET/${pair#*:}|${pair%%:*}|${pair%%:*}")
done
for bucket in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
  d=${bucket%%:*}; px=${bucket##*:}; fg=$(( px * 9 / 4 ))   # foreground＝108dp @ 同密度（48dp×2.25）
  for name in ic_launcher ic_launcher_round; do
    EXPECTED+=("png|$RES/mipmap-$d/$name.png|$px|$px")
  done
  EXPECTED+=("png|$RES/mipmap-$d/ic_launcher_foreground.png|$fg|$fg")
done

png_size() {  # PNG IHDR 直讀寬高（免 sips／PIL）
  python3 -c 'import struct,sys; w,h=struct.unpack(">II", open(sys.argv[1],"rb").read(24)[16:24]); print(w,h)' "$1"
}

verify() {
  local bad=0 entry kind path w h got
  for entry in "${EXPECTED[@]}"; do
    IFS='|' read -r kind path w h <<<"$entry"
    if [ ! -s "$path" ]; then echo "FAIL: 產物缺失 $path"; bad=1; continue; fi
    case $kind in
      png) got=$(png_size "$path")
           [ "$got" = "$w $h" ] || { echo "FAIL: $path 尺寸 $got ≠ ${w}x${h}"; bad=1; } ;;
      icns) [ "$(head -c 4 "$path")" = "icns" ] || { echo "FAIL: $path 非 icns 檔頭"; bad=1; } ;;
      xml)  head -c 5 "$path" | grep -q '<?xml' || { echo "FAIL: $path 非 XML"; bad=1; } ;;
    esac
  done
  [ "$bad" = 0 ] || return 1
  echo "OK: ${#EXPECTED[@]} 項 icon 產物存在且尺寸正確"
}

if [ "$CHECK" = 1 ]; then
  verify
  exit $?
fi

command -v resvg >/dev/null || { echo "FATAL: 找不到 resvg（brew install resvg）；icon 產物需要它"; exit 1; }
[ -f "$SRC" ] || { echo "FATAL: 缺主設計 $SRC"; exit 1; }

echo "==> macOS iconset（$ICONSET）→ $ICNS"
rm -rf "$ICONSET"; mkdir -p "$ICONSET" build
for pair in 16:icon_16x16.png 32:icon_16x16@2x.png 32:icon_32x32.png 64:icon_32x32@2x.png \
            128:icon_128x128.png 256:icon_128x128@2x.png 256:icon_256x256.png \
            512:icon_256x256@2x.png 512:icon_512x512.png 1024:icon_512x512@2x.png; do
  resvg "$SRC" "$ICONSET/${pair#*:}" -w "${pair%%:*}" >/dev/null
done
rm -f "$ICNS"
iconutil -c icns "$ICONSET" -o "$ICNS"

echo "==> Android adaptive icon（foreground 衍生自 $SRC 的盾＋鑰匙孔層）"
# 取 defs（盾漸變）＋「<!-- 盾」標記之後的全部圖形，丟掉底板 rect 與 </svg>。
# 標記是 appicon.svg 的契約錨點；對不上就 fail-fast，不默默產出空 foreground。
{
  echo '<svg xmlns="http://www.w3.org/2000/svg" width="108" height="108" viewBox="0 0 1024 1024">'
  echo '  <g transform="translate(512 512) scale(0.95) translate(-512 -512)">'
  awk '/<defs>/{f=1} f{print} /<\/defs>/{f=0} /<!-- 盾/{exit}' "$SRC" | sed 's/^/  /'
  awk '/<!-- 盾/{f=1} f && !/^<\/svg>/{print}' "$SRC" | sed 's/^/  /'
  echo '  </g>'
  echo '</svg>'
} > "$FG"
grep -q 'url(#shield)' "$FG" && grep -q '<path' "$FG" \
  || { echo "FATAL: foreground 衍生失敗（$SRC 缺「<!-- 盾」標記或 defs 內無 shield 漸變）"; exit 1; }
for bucket in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
  d=${bucket%%:*}; px=${bucket##*:}
  mkdir -p "$RES/mipmap-$d"
  resvg "$SRC" "$RES/mipmap-$d/ic_launcher.png" -w "$px" >/dev/null
  cp -f "$RES/mipmap-$d/ic_launcher.png" "$RES/mipmap-$d/ic_launcher_round.png"
  resvg "$FG" "$RES/mipmap-$d/ic_launcher_foreground.png" -w "$(( px * 9 / 4 ))" >/dev/null
done
mkdir -p "$RES/mipmap-anydpi-v26" "$RES/values"
for name in ic_launcher ic_launcher_round; do
  cat > "$RES/mipmap-anydpi-v26/$name.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
    <monochrome android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
EOF
done
cat > "$RES/values/ic_launcher_background.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="ic_launcher_background">#14409E</color>
</resources>
EOF

verify
