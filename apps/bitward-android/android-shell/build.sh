#!/usr/bin/env bash
# 產出「孤島進 APK」的最終包（路線 A：Gradle 外殼）。
#
#   1. nsh package（若 .nsh/out/bitward.apk 不存在）→ 三 ABI libnsh.so + runtime dex + assets
#   2. 解壓 nsh 產物到 app/build/nsh/（Gradle 的 jniLibs/assets 來源）
#   3. gradle assembleDebug → 孤島 Kotlin + 資源 + manifest 的外殼 APK
#   4. 把 nsh runtime 的 classes.dex 追加為 classesN.dex，zipalign + debug 簽章
#
# 輸出：apps/bitward-android/.nsh/out/bitward-islands.apk（簽章＝~/.android/debug.keystore，
# 與 nsh package 產物同鑰，`adb install -r` 可互換）。
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
APP_DIR=$(dirname "$HERE")
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export PATH="$HOME/.local/bin:$PATH:$ANDROID_HOME/platform-tools"
BG=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
NSH_APK="$APP_DIR/.nsh/out/bitward.apk"
OUT_APK="$APP_DIR/.nsh/out/bitward-islands.apk"
STAGE="$HERE/build/nsh-stage"
KS="${NSH_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"

[[ -f "$NSH_APK" ]] || (cd "$APP_DIR" && nsh package --target android)
[[ -f "$KS" ]] || { echo "找不到簽章鑰匙庫 $KS（nsh package 用的同一把）" >&2; exit 1; }

# --- 1. nsh 產物解壓（jniLibs/assets/runtime-dex） -----------------------------
rm -rf "$STAGE" && mkdir -p "$STAGE"
TMP=$(mktemp -d)
unzip -q "$NSH_APK" -d "$TMP" 'lib/*' 'assets/*' 'classes.dex'
mv "$TMP/lib" "$STAGE/libs"
mv "$TMP/assets" "$STAGE/assets"
mv "$TMP/classes.dex" "$STAGE/classes.dex"
rm -rf "$TMP"

# --- 2. Gradle 外殼 APK（孤島 Kotlin＋資源＋manifest＋jniLibs＋assets） --------
# 離線優先：AGP 8.13.1/Kotlin 2.2.21/aapt2 都已在本機 ~/.gradle 快取；
# 快取不全時退回線上解析（GRADLE_FLAGS 可覆寫）。
(cd "$HERE" && gradle --offline ${GRADLE_FLAGS:-} -q assembleDebug) \
  || (cd "$HERE" && gradle ${GRADLE_FLAGS:-} -q assembleDebug)
SHELL_APK="$HERE/app/build/outputs/apk/debug/app-debug.apk"
[[ -f "$SHELL_APK" ]] || { echo "Gradle 沒產出 $SHELL_APK" >&2; exit 1; }

# --- 3. 併入 nsh runtime dex（classesN.dex）＋對齊＋簽章 ------------------------
cp "$SHELL_APK" "$OUT_APK.tmp"
LAST=$(unzip -l "$OUT_APK.tmp" | awk '{print $4}' | grep -oE '^classes[0-9]*\.dex$' | grep -oE '[0-9]+' | sort -n | tail -1 || true)
NEXT=$(( ${LAST:-1} + 1 ))
cp "$STAGE/classes.dex" "$STAGE/classes$NEXT.dex"
(cd "$STAGE" && zip -q "$OUT_APK.tmp" "classes$NEXT.dex")
"$BG/zipalign" -f 4 "$OUT_APK.tmp" "$OUT_APK"
"$BG/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias androiddebugkey --min-sdk-version 28 "$OUT_APK"
rm -f "$OUT_APK.tmp" "$STAGE/classes$NEXT.dex"
echo "OK: $OUT_APK"
