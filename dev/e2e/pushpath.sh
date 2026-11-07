#!/usr/bin/env bash
# APNs 推播路徑 e2e（§1.2 正式分發形態）：PushCall 帳、publish_signal 的 APNs
# 副發、410（卸載）清理收斂、BW_APNS_ENDPOINT 端點注入。
# Mock APNs 是本機 http.server（記錄 path/headers/body），無 docker 依賴：
# 推播只需 daemon、token 帳與通道，不需要真 vault。
set -uo pipefail
cd "$(dirname "$0")/../.."

PORT=18095
D=dev/e2e/data-push
GOOD="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90"
DEAD="DEADBEEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567"
BUNDLE=com.bitward.e2e
MOCKPID=""
DAEMONPID=""
PARTPID=""
DEVPID=""
cleanup() {
  for p in $PARTPID $DEVPID $DAEMONPID $MOCKPID; do kill $p 2>/dev/null; done
  rm -rf $D
}
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; tail -20 "$D/log" 2>/dev/null; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd || fail "build"
rm -rf $D
mkdir -p $D
# 測試用 P-256 PKCS#8（named-curve 編碼；同 apns.rs 單元測 golden）。
# 不用 openssl 現場生：macOS 系統 openssl 是 LibreSSL，內嵌 explicit curve
# 參數，p256 crate 拒絕解析。
cat > "$D/apns.p8" <<'PEMEOF'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQczA8C+zpC3p+q0M
wbyM5XjY2CXkv6vaUJkGmkoDXZOhRANCAAQyYnNJVzUqZQhk5bxgOsqDHIIKpOEE
ZCk+RA68NQS3ZMU4c2saIPqmcNdUbv/pBfCZx4sGwO2T5fMKfwug7tbl
-----END PRIVATE KEY-----
PEMEOF

# mock APNs：/3/device/DEADBEEF* 回 410，其餘 200；每筆 POST 落一列 JSON
python3 - "$D/apns.log" "$PORT" <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
LOG = sys.argv[1]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(LOG, "a") as f:
            f.write(json.dumps({
                "path": self.path,
                "auth": self.headers.get("authorization", ""),
                "topic": self.headers.get("apns-topic", ""),
                "push_type": self.headers.get("apns-push-type", ""),
                "body": body,
            }) + "\n")
        dead = self.path.startswith("/3/device/DEADBEEF")
        self.send_response(410 if dead else 200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"reason":"Unregistered"}' if dead else b"")
    def log_message(self, *a):
        pass
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), H).serve_forever()
PYEOF
MOCKPID=$!
READY=0
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -X POST -d '{}' "http://127.0.0.1:$PORT/3/device/READY" && { READY=1; break; }
  sleep 0.3
done
[[ "$READY" == 1 ]] || fail "mock APNs 未在 10 秒內就緒"
: > "$D/apns.log"   # READY 探測留痕不算推播

# 部分 APNs 參數（只給 2/4）：必須警告降級、照常開站
mkdir -p "$D/partial"
( ./target/debug/bitwarderd --data-dir "$D/partial" --sock "$D/partial/s" \
    --apns-p8 "$D/apns.p8" --apns-team-id E2ETEAM1 >"$D/partial/log" 2>&1 ) & PARTPID=$!
sleep 1
grep -q "不完整" "$D/partial/log" || fail "部分 APNs 參數未警告降級: $(cat "$D/partial/log" 2>/dev/null)"
[[ -S "$D/partial/s" ]] || fail "部分參數降級後 daemon 未開站"
kill $PARTPID 2>/dev/null; PARTPID=""
pass "部分 APNs 參數：警告降級，ntfy 路照常"

# 完整四參 ＋ BW_APNS_ENDPOINT 注入 mock
BITWARD_DATA_DIR="$PWD/$D" BW_APNS_ENDPOINT="http://127.0.0.1:$PORT" \
  ./target/debug/bitwarderd --data-dir "$D" --sock "$D/s" \
  --apns-p8 "$D/apns.p8" --apns-key-id E2EKEY01 --apns-team-id E2ETEAM1 \
  --apns-bundle-id "$BUNDLE" --apns-staging >"$D/log" 2>&1 &
DAEMONPID=$!
for _ in $(seq 1 40); do [[ -S "$D/s" ]] && break; sleep 0.25; done
[[ -S "$D/s" ]] || fail "daemon 未起: $(tail -5 "$D/log" 2>/dev/null)"
grep -q "APNs endpoint" "$D/log" || fail "BW_APNS_ENDPOINT 覆蓋未生效"
pass "daemon 帶 APNs 啟動，endpoint 由環境變數注入"

# 最小 BTP 用戶端（4B LE + JSON，同 bw-btp P1 線格式）
cat > "$D/wtp.py" <<'PYEOF'
import json, socket, struct, sys

uds, cmd, *args = sys.argv[1:]

def send(s, m):
    b = json.dumps(m).encode()
    s.sendall(struct.pack("<I", len(b)) + b)

def recv(s):
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c:
            raise SystemExit("eof in header")
        h += c
    n = struct.unpack("<I", h)[0]
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise SystemExit("eof in body")
        buf += c
    return json.loads(buf)

def open_sess(auth):
    s = socket.socket(socket.AF_UNIX)
    s.connect(uds)
    send(s, {"Hello": {"version": 1, "auth": auth, "wants": []}})
    w = recv(s)
    if "Welcome" not in w:
        raise SystemExit(f"welcome failed: {w}")
    return s

def invoke(s, call):
    send(s, {"Invoke": {"rid": 1, "call": call}})
    while True:
        m = recv(s)
        if "Reply" in m and m["Reply"]["rid"] == 1:
            return m["Reply"]["outcome"]

CALLS = {
    "reg": lambda a: {"Push": {"RegisterPush": {"token": a[0], "platform": a[1]}}},
    "unreg": lambda a: {"Push": {"UnregisterPush": {"token": a[0]}}},
    "list": lambda a: {"Push": {"ListPush": None}},
    "pairstart": lambda a: {"Auth": {"PairStart": {"name": "e2e-dev", "grant": a[0], "ttl_secs": 3600}}},
    "pending": lambda a: {"Agent": {"ListPending": None}},
    "approve": lambda a: {"Agent": {"Approve": {"id": a[0], "grants": None}}},
}
if cmd == "device":
    auth = {"Enroll": {"pairing": "", "display_name": "e2e-device", "pair_code": args[0]}}
    print(json.dumps(invoke(open_sess(auth), CALLS["list"]([]))))
else:
    auth = {"Enroll": {"pairing": "", "display_name": "e2e-push", "pair_code": None}}
    print(json.dumps(invoke(open_sess(auth), CALLS[cmd](args))))
PYEOF
W() { python3 "$D/wtp.py" "$PWD/$D/s" "$@"; }

OUT=$(W reg "$GOOD" ios); jq -e '.Ok == "Ok"' <<<"$OUT" >/dev/null || fail "RegisterPush GOOD: $OUT"
OUT=$(W reg "$DEAD" watchos); jq -e '.Ok == "Ok"' <<<"$OUT" >/dev/null || fail "RegisterPush DEAD: $OUT"
LIST=$(W list)
[[ "$(jq '.Ok.Json | length' <<<"$LIST")" == 2 ]] || fail "ListPush 應 2 筆: $LIST"
grep -q "$GOOD" <<<"$LIST" && fail "ListPush 外洩完整 token"
jq -e --arg g "${GOOD:0:8}" '.Ok.Json | any(.token | startswith($g)) and any(.platform == "watchos")' \
  <<<"$LIST" >/dev/null || fail "ListPush 去敏形態不對: $LIST"
pass "RegisterPush×2、ListPush 去敏（前 8 碼＋hash，無全 token）"

# 觸發 publish_signal：配對 Device session 的 ListPush 帶 approve 標記
# → authorize NeedApproval 排隊，與 ntfy 同源副發 APNs
PAIR=$(W pairstart 'see:identity all approve')
CODE=$(jq -r '.Ok.PairInfo.code' <<<"$PAIR")
[[ "$CODE" =~ ^[A-Z2-9]{9}$ ]] || fail "pair start 形狀不對: $PAIR"
W device "$CODE" >"$D/device.out" 2>&1 & DEVPID=$!
PEND=""
for _ in $(seq 1 40); do
  PEND=$(W pending 2>/dev/null) || true
  jq -e '.Ok.Sessions | length >= 1' <<<"$PEND" >/dev/null 2>&1 && break
  sleep 0.25
done
APID=$(jq -r '(.Ok.Sessions[0].id // "null")' <<<"$PEND")
[[ "$APID" != "null" ]] || fail "pending 佇列空（approve 閘未觸發）: $PEND"
W approve "$APID" | jq -e '.Ok' >/dev/null || fail "approve 失敗"
wait $DEVPID || fail "device 呼叫非零退出"
# 批准後放行即可；筆數不在此斷言（410 清理可能先跑完，確切 2 筆 POST 問 mock log）
jq -e '.Ok.Json | length >= 1' "$D/device.out" >/dev/null \
  || fail "device 批准後 ListPush 未放行: $(cat "$D/device.out")"
pass "gated Device ListPush → NeedApproval（信令已副發）→ approve 放行"

for _ in $(seq 1 40); do [[ "$(grep -c . "$D/apns.log" 2>/dev/null || echo 0)" -ge 2 ]] && break; sleep 0.25; done
NPOST=$(grep -c . "$D/apns.log" 2>/dev/null || echo 0)
[[ "$NPOST" == 2 ]] || fail "mock 收到 $NPOST 筆 POST（應 2）: $(cat "$D/apns.log" 2>/dev/null)"
LINE=$(grep "/3/device/$GOOD" "$D/apns.log" | head -1)
[[ -n "$LINE" ]] || fail "GOOD token 未見推播"
jq -e --arg g "$GOOD" --arg b "$BUNDLE" \
  '.path == "/3/device/\($g)"
   and ((.auth | sub("^[Bb]earer "; "") | split(".") | length) == 3)
   and .topic == $b and .push_type == "alert"' <<<"$LINE" >/dev/null \
  || fail "GOOD 推播 shape 不對: $LINE"
grep -q "/3/device/$DEAD" "$D/apns.log" || fail "DEAD token 未見推播"
pass "APNs 副發 2 POST：path=/3/device/<token>、bearer 三段 JWT、apns-topic 對"

# 410 收斂：DEADBEEF 必須被 daemon 從帳上移除
LIST=""
for _ in $(seq 1 40); do
  LIST=$(W list)
  [[ "$(jq '.Ok.Json | length' <<<"$LIST" 2>/dev/null || echo 2)" == 1 ]] && break
  sleep 0.25
done
[[ "$(jq '.Ok.Json | length' <<<"$LIST")" == 1 ]] || fail "410 token 未清理: $LIST"
jq -e --arg g "${GOOD:0:8}" '.Ok.Json[0].token | startswith($g)' <<<"$LIST" >/dev/null \
  || fail "清理後留下的不是 GOOD: $LIST"
pass "410（DEADBEEF）token 已由 daemon 清理"

W unreg "$GOOD" >/dev/null
LIST=$(W list)
[[ "$(jq '.Ok.Json | length' <<<"$LIST")" == 0 ]] || fail "UnregisterPush 後仍有殘留: $LIST"
pass "UnregisterPush 收斂至空帳"

echo "PUSH E2E: ALL PASS"
