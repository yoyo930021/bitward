#!/usr/bin/env bash
# tarball.sh — Linux 正式打包（PR6-E1，§1.2 `bitwardd` headless Full 形態）：
# release 建置 → dist/bitward-linux-<arch>-<version>.tar.gz（bin/ + install.sh +
# unit 參考模板）＋ sha256。在目標平台跑（OrbStack/docker/實體機），不做交叉。
# 常駐註冊不打包進 unit 檔內容——安裝時由 `bitwarderd --service install`
# 渲染（真相源 service.rs::render_unit），本腳本只隨附人讀模板。
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD

[ "$(uname -s)" = Linux ] || { echo "FATAL: 在 Linux 上跑（VM/容器內构建本平台 tarball）" >&2; exit 1; }
ARCH=$(uname -m)
VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$REPO/Cargo.toml")

echo "==> cargo release (bitwarderd, bitward)"
cargo build --release -q -p bitwarderd -p bitward

STAGE=$REPO/dist/stage-linux
OUT=dist/bitward-linux-$ARCH-$VERSION.tar.gz
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/share/bitward"
cp target/release/bitwarderd target/release/bitward "$STAGE/bin/"
cp scripts/linux/install.sh "$STAGE/install.sh"
chmod +x "$STAGE/install.sh"
cp scripts/linux/unit-template.service "$STAGE/share/bitward/io.bitward.dev.daemon.service"
cat > "$STAGE/README.md" <<EOF
# bitward $VERSION（Linux headless）

安裝（目標使用者本人，非 root）：

    tar -xzf $(basename "$OUT"); cd 解包目錄 && ./install.sh

裝完：bitwarderd 已註冊 systemd user unit 並啟動；
sock 按 Q3 裁決＝\$XDG_RUNTIME_DIR/bitward/daemon.sock；
日誌 journalctl --user -u io.bitward.dev.daemon；
卸載 \`~/.local/bin/bitwarderd --service uninstall\`。
EOF
tar -czf "$OUT" -C "$STAGE" .
( cd dist && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
echo "==> $OUT"
cat "dist/$(basename "$OUT").sha256"
