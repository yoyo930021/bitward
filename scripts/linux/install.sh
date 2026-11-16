#!/usr/bin/env bash
# install.sh — Linux headless tarball 解包後執行（目標使用者本人、非 root；
# 對位 macOS 的 pkg-build/dev-install 角色，§1.2 `bitwardd` headless Full 形態）。
# 落二進位到 BIN_DIR（默認 ~/.local/bin）→ `bitwarderd --service install`
# 渲染 systemd user unit（註冊真相源＝service.rs::render_unit）並 enable --now。
# 卸載：bitwarderd --service uninstall && rm BIN_DIR/bitwarderd BIN_DIR/bitward
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
BIN_DIR=${BIN_DIR:-$HOME/.local/bin}

command -v systemctl >/dev/null 2>&1 || { echo "FATAL: 無 systemctl（本腳本走 systemd user 域）" >&2; exit 1; }
[ -n "${XDG_RUNTIME_DIR:-}" ] || { echo "FATAL: 無 XDG_RUNTIME_DIR＝非使用者 login session（systemd user 域不可用）" >&2; exit 1; }

install -d "$BIN_DIR"
install -m 0755 "$DIR/bin/bitwarderd" "$DIR/bin/bitward" "$BIN_DIR/"

"$BIN_DIR/bitwarderd" --service install
"$BIN_DIR/bitwarderd" --service status

echo "完成：確認 PATH 含 $BIN_DIR；起 daemon、log 查 journalctl --user -u io.bitward.dev.daemon"
echo "下一步：bitward login --server <url> --email <mail>（或 bitward unlock）"
