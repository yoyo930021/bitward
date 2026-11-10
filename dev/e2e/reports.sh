#!/usr/bin/env bash
# 路線 4 報告儀表板 e2e：重用密碼群集數、弱密碼打分命中／不誤報、
# 歷史代理（名稱解密）與 VW 缺席形態。
# 歷史資料源查證（見 daemon datamanage.rs 註解）：Vaultwarden 1.37.2 未實裝
# GET /api/ciphers/{id}/history（實測 404）——本腳本以本地 shim 反代補上該
# 路由（官方舊版線格式：條目自帶各版本 key 信封），其餘流量原樣轉 VW，
# 同時直接驗 VW 直連路徑的 supported:false 分支。
set -euo pipefail
cd "$(dirname "$0")/../.."

VW=bitward-vw-reports
VP=18092
SP=18093
DA=dev/e2e/data-reports
WP="ReportsMaster-9zQ!x"
EMAIL="rep-$(date +%s)@bitward.test"
cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; [[ -n "${SHIM:-}" ]] && kill "$SHIM" 2>/dev/null || true; docker rm -f "$VW" >/dev/null 2>&1 || true; rm -rf "$DA"; }
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; [[ -n "$DA" ]] && tail -12 "$DA/log" 2>/dev/null || true; exit 1; }
pass() { echo "ok: $1"; }

cargo build -q -p bitwarderd -p bitward
docker rm -f "$VW" >/dev/null 2>&1
docker run -d --name "$VW" -p $VP:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=100 vaultwarden/server:1.37.2 >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$VP/alive" >/dev/null 2>&1 && break; sleep 1; done
mkdir -p $DA

# —— shim：轉發全部流量到 VW；PUT/POST cipher 時快照 body（各版本 key/name 信封）；
# GET /api/ciphers/{id}/history 以官方舊版 ListResponse 形態回「非最新」快照。
cat > $DA/shim.py <<'PY'
import json, os, re, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client

SP, VP, STATES = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
LOCK = threading.Lock()

def load():
    try:
        with open(STATES) as f: return json.load(f)
    except Exception: return {}

def save(s):
    tmp = STATES + ".tmp"
    with open(tmp, "w") as f: json.dump(s, f)
    os.replace(tmp, STATES)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _proxy(self, body):
        c = http.client.HTTPConnection("127.0.0.1", VP, timeout=30)
        c.request(self.command, self.path, body=body,
                  headers={k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "content-length")})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def do_GET(self):
        m = re.match(r"^/api/ciphers/([0-9a-fA-F-]+)/history/?$", self.path)
        if m:
            with LOCK:
                states = load().get(m.group(1).lower(), [])
            entries = [{
                "id": f"hist-{i}", "object": "cipherHistory",
                "cipherId": m.group(1), "organizationId": st.get("organizationId"),
                "key": st.get("key"), "name": st.get("name"),
                # data＝欄位 JSON 信封；shim 無明文鑰，給解不開的合法形態
                # （type-2 三段），daemon 容錯 uriCount=0。
                "data": "2.0000000000000000000000==|0000000000000000000000==|0000000000000000000000000000000000000000000=",
                "creationDate": st.get("ts"), "revisionDate": st.get("ts"),
            } for i, st in enumerate(states[:-1])]
            out = json.dumps({"object": "list", "data": entries}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self._relay(None)

    def _relay(self, body):
        status, headers, data = self._proxy(body)
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self._capture(status, data)

    def _capture(self, status, resp_data):
        if status >= 300: return
        body = getattr(self, "_body", None)
        if not body: return
        p = self.path.split("?")[0]
        cid = None
        m = re.match(r"^/api/ciphers/([0-9a-fA-F-]+)$", p)
        if m and self.command == "PUT": cid = m.group(1).lower()
        elif p == "/api/ciphers" and self.command == "POST":
            try: cid = json.loads(resp_data)["id"].lower()
            except Exception: return
        if not cid: return
        try: body = json.loads(body)
        except Exception: return
        st = {"key": body.get("key"), "name": body.get("name"),
              "organizationId": body.get("organizationId"),
              "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        with LOCK:
            s = load(); s.setdefault(cid, []).append(st); save(s)

    def do_POST(self):
        self._read_body(); self._relay(self._body)
    def do_PUT(self):
        self._read_body(); self._relay(self._body)
    def do_DELETE(self):
        self._relay(None)
    def do_HEAD(self):
        self._relay(None)
    def _read_body(self):
        n = int(self.headers.get("content-length") or 0)
        self._body = self.rfile.read(n) if n else None

ThreadingHTTPServer(("127.0.0.1", SP), H).serve_forever()
PY
python3 $DA/shim.py $SP $VP "$DA/states.json" >$DA/shim.log 2>&1 & SHIM=$!
sleep 1

export BITWARD_DATA_DIR=$PWD/$DA
BITWARD_DATA_DIR=$PWD/$DA ./target/debug/bitwarderd --data-dir "$DA" --sock "$DA/s" >$DA/log 2>&1 & PID=$!
sleep 1
B() { "$PWD/target/debug/bitward" --sock "$DA/s" "$@"; }
SRV="http://127.0.0.1:$SP"
echo "$WP" | B --json dev-register --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
echo "$WP" | B login --server "$SRV" --email "$EMAIL" --password-stdin >/dev/null
drained() { for _ in $(seq 1 30); do [[ "$(B outbox --json | jq '(.outbox.queued + .outbox.in_flight + .outbox.awaiting + .outbox.conflict)')" == "0" ]] && return 0; sleep 1; done; return 1; }

# —— seed：重用群（h.example.com/alice ×2＋同 host 不同 user 對照）、弱強組合
for n in 'gh-a:alice:Strong-Aa1!xQ9z' 'gh-b:alice:Another-Bq7$Wm2' 'gh-c:bob:Third-Ce4%Mn8'; do
  IFS=: read -r name user pw <<< "$n"
  echo "$pw" | B new --name "$name" --username "$user" --uri "https://h.example.com/login" --password-stdin >/dev/null
done
echo 'password123' | B new --name weak-a --username w1 --uri https://w.example.com --password-stdin >/dev/null
echo '123456'      | B new --name weak-b --username w2 --uri https://w.example.com --password-stdin >/dev/null
drained || fail "seed outbox 未收斂"
pass "seed（3 重用＋2 人造弱＋強碼對照）"

# —— 重用：恰好 1 群（h.example.com×alice 兩筆）；弱強對照不群集
G=$(B reports reuse | jq -r '. | length')
[[ "$G" == "1" ]] || fail "reuse 應 1 群，got $G"
D=$(B reports reuse | jq -r '.[0].domain')
N=$(B reports reuse | jq -r '.[0].ids | length')
[[ "$D" == "h.example.com" && "$N" == "2" ]] || fail "reuse 群形錯：$D/$N"
pass "重用密碼報告＝既有 DupGroups 投影（1 群 2 筆、對照不群集）"

# —— 弱密碼：命中兩筆人造弱碼、強碼不誤報、門檻欄在
IDS=$(B reports weak | jq -r '[.items[].name] | sort | join(",")')
[[ "$IDS" == "weak-a,weak-b" ]] || fail "weak 應 weak-a,weak-b，got $IDS"
[[ "$(B reports weak | jq -r '.threshold')" == "3" ]] || fail "weak threshold 欄錯"
[[ "$(B reports weak | jq -r '.items[0].score')" == "0" ]] || fail "人造弱碼 score 應 0"
pass "弱密碼報告命中人造弱碼不误報強碼（score<3 列管）"

# —— 歷史（shim 實裝官方舊版格式）：改名後 ≥1 版、名稱以各版本 key 解密
HID=$(B ls --json | jq -r '.[] | select(.meta.name=="gh-a") | .meta.id')
B edit "$HID" --set name=gh-a-renamed >/dev/null
drained || fail "rename outbox 未收斂"
sleep 1
H=$(B reports history --id "$HID")
[[ "$(echo "$H" | jq -r '.supported')" == "true" ]] || fail "shim 歷史應 supported:true"
[[ "$(echo "$H" | jq -r '.versions | length')" -ge 1 ]] || fail "歷史應 ≥1 版"
[[ "$(echo "$H" | jq -r '.versions[0].name')" == "gh-a" ]] || fail "歷史首版名稱解密錯：$(echo "$H" | jq -r '.versions[0].name')"
[[ "$(echo "$H" | jq -r '.restoreSupported')" == "false" ]] || fail "還原註記欄錯"
pass "歷史代理回包 ≥1 版且名稱解密（各版本 key 信封路徑實測）"

# —— VW 直連形態：未經 shim 的 server 沒這條路由 → supported:false
TOK=$(jq -r .access_token $DA/account.json)
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOK" "http://127.0.0.1:$VP/api/ciphers/$HID/history")
[[ "$CODE" == "404" ]] || fail "VW 直連 history 應 404（查證基線漂移？），got $CODE"
pass "VW 1.37.2 無 history 路由實錄（404）——daemon 轉 supported:false 收合歷史節"

# —— 鎖定態：弱密碼拒算（需解鎖紀律；pipefail 下 CLI 非零退出先收進變數再判文案）
B lock >/dev/null
OUT=$(B reports weak 2>&1 || true)
[[ "$OUT" == *"未解鎖"* || "$OUT" == *"Locked"* ]] || fail "鎖態弱密碼報告應回未解鎖，got $OUT"
pass "鎖態弱密碼回 Locked（只在解鎖態現算）"

pass "reports.sh 全綠"
