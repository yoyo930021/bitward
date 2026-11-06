#!/bin/bash
# dev-install.sh — 一鍵建置＋部署 macOS App（含 daemon helper）。
# 會話中被「殭屍二進位」咬過三次後的教訓：Xcode script phase 增量不可靠、
# ditto 會蓋回舊 staging——本腳本在 ditto 後強制重拷＋重簽＋sha 驗證。
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
BUNDLE=~/Library/Developer/Xcode/DerivedData/Bitward-essisnxmmachgpfgzkzjfqzduucb/Build/Products/Release/Bitward.app
IDENTITY=BFA4593FB215C51771B6988EBFADE08E7A3F8DE0   # Mac Developer: Created via API (team 8V5224A99M)
GROUP=group.8V5224A99M.io.bitward.dev

echo "==> cargo release (bitwarderd, bitward)"
cargo build --release -q -p bitwarderd -p bitward

echo "==> xcodebuild"
cd platforms/macos
xcodegen generate >/dev/null
xcodebuild -project Bitward.xcodeproj -scheme Bitward -destination 'platform=macOS' \
  -configuration Release build 2>&1 | grep -E 'error:|BUILD (SUCCEEDED|FAILED)' | head -3
cd "$REPO"

echo "==> deploy to /Applications"
kill -9 "$(pgrep -x Bitward)" 2>/dev/null || true
rm -rf /Applications/Bitward.app
ditto "$BUNDLE" /Applications/Bitward.app

echo "==> force-fresh daemon helper (殭屍二進位保險)"
cp -f target/release/bitwarderd /Applications/Bitward.app/Contents/Helpers/bitwarderd
codesign -f -s "$IDENTITY" --entitlements bins/bitwarderd/helper.entitlements \
  /Applications/Bitward.app/Contents/Helpers/bitwarderd 2>/dev/null
# 功能探測（簽章會改 sha，比內容無意義）：舊 binary 不認 --service
/Applications/Bitward.app/Contents/Helpers/bitwarderd --service status >/dev/null 2>&1 \
  || { echo "FATAL: staged helper 不支援 --service（舊殭屍二進位？）"; exit 1; }
echo "    helper functional OK"

echo "==> (re)install LaunchAgent"
/Applications/Bitward.app/Contents/Helpers/bitwarderd --service uninstall >/dev/null 2>&1 || true
/Applications/Bitward.app/Contents/Helpers/bitwarderd --service install --push-app-group "$GROUP"

echo "==> smoke: connect via launchd daemon (tmp sock)"
sleep 2
python3 - <<'EOF'
import socket, struct, json, uuid
s = socket.socket(socket.AF_UNIX); s.settimeout(4)
s.connect("/private/tmp/io.bitward.dev/daemon.sock")
b = json.dumps({"Hello":{"version":1,"auth":{"Enroll":{"pairing":str(uuid.uuid4()),"display_name":"install-smoke","pair_code":None}},"wants":[]}}).encode()
s.sendall(struct.pack("<I", len(b)) + b)
n = struct.unpack("<I", s.recv(4))[0]
buf = b""
while len(buf) < n: buf += s.recv(n - len(buf))
assert "Welcome" in json.loads(buf), "handshake failed"
print("    daemon reachable: OK")
EOF
echo "==> done"
