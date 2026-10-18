# -*- coding: utf-8 -*-
# nginx `split_clients` 指令 E2E —— 用真实 HTTP 流量证明按键模板哈希加权分流落地：
#   * /show：不同 X-Key / User-Agent 驱动 ngx.var.<split 目标>，验证确定性、两条解析
#            路径一致，并对若干固定键用独立移植的 MurmurHash2 参考实现核对落桶；
#   * 分布：对上千个不同键统计各桶占比，验证 25/25/25/25 与 10%+* 的实际分流比例；
#   * /echo：split 目标写进 proxy_set_header，经真实代理转发到回显后端，后端把
#            X-Roll / X-Bucket 原样打回，证明 config 字符串插值路径也解析了 split_clients。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/split_clients_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "split_clients_e2e.conf")
HOST, PORT = "127.0.0.1", 18172
ECHO_PORT = 18173
BASE = f"http://{HOST}:{PORT}"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


# --- 独立移植的 nginx ngx_murmur_hash2（32 位，小端），用于对固定键核对落桶 ---
M = 0x5BD1E995
MASK = 0xFFFFFFFF


def murmur2(data: bytes) -> int:
    length = len(data)
    h = (length ^ 0x9DC03AC8) & MASK
    i = 0
    while i + 4 <= length:
        k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k = (k * M) & MASK
        k ^= k >> 24
        k = (k * M) & MASK
        h = (h * M) & MASK
        h ^= k
        i += 4
    rem = length - i
    if rem == 3:
        h ^= data[i + 2] << 16
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 2:
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 1:
        h ^= data[i]
        h = (h * M) & MASK
    h ^= h >> 13
    h = (h * M) & MASK
    h ^= h >> 15
    return h


def split_id(key: str) -> int:
    return murmur2(key.encode()) % 10000


def ref_roll(key: str) -> str:
    # 25/25/25/25 → 累计上界 2500 / 5000 / 7500 / 10000
    idv = split_id(key)
    if idv < 2500:
        return "q1"
    if idv < 5000:
        return "q2"
    if idv < 7500:
        return "q3"
    return "q4"


def ref_bucket(remote_addr: str, ua: str) -> str:
    # 10% yes + * no → 上界 1000
    return "yes" if split_id(remote_addr + ua) < 1000 else "no"


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def get(path, headers=None):
    r = urllib.request.Request(BASE + path, method="GET", headers=headers or {})
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    d = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def make_echo(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            lines = [f"{k.lower()}={v}" for k, v in self.headers.items()]
            body = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_ready(timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    echo = make_echo(ECHO_PORT)

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "split_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            check("server-start", False, "onrouter 未监听 18172")
            return
        check("server-start", True)

        # ---- 确定性：同一 X-Key 多次请求落同一桶 ----
        seq = []
        for _ in range(6):
            s, b = get("/show", {"X-Key": "stable-key-1", "User-Agent": "stable-key-1"})
            d = kv(b)
            seq.append(d.get("roll"))
        check("show-determinism", all(x == seq[0] for x in seq) and seq[0] in ("q1", "q2", "q3", "q4"), str(seq))

        # ---- 参考核对：若干固定键，Lua 读取路径与 proxy 插值路径都应与移植 murmur 一致 ----
        probe_keys = ["alice", "bob", "carol-123", "x" * 5, "user-agent/mozilla-5", "weird!@#$key"]
        all_roll_ok = True
        all_bucket_ok = True
        for k in probe_keys:
            s, b = get("/show", {"X-Key": k, "User-Agent": k})
            d = kv(b)
            if d.get("roll") != ref_roll(k):
                all_roll_ok = False
            if d.get("bucket") != ref_bucket("127.0.0.1", k):
                all_bucket_ok = False
            # 同一键走 /echo（proxy_set_header 路径）应得到相同落桶
            s2, b2 = get("/echo", {"X-Key": k, "User-Agent": k})
            d2 = kv(b2)
            if d2.get("x-roll") != ref_roll(k):
                all_roll_ok = False
            if d2.get("x-bucket") != ref_bucket("127.0.0.1", k):
                all_bucket_ok = False
        check("reference-roll-matches", all_roll_ok, "Lua 读取与 proxy 插值两条路径落桶应与移植 murmur2 一致")
        check("reference-bucket-matches", all_bucket_ok, "* 兜底桶落桶核对")

        # ---- 分布：1200 个不同键，roll 四桶≈25%，bucket yes≈10% ----
        N = 1200
        roll_counts = Counter()
        bucket_counts = Counter()
        for i in range(N):
            key = f"client-{i}"
            s, b = get("/show", {"X-Key": key, "User-Agent": key})
            d = kv(b)
            roll_counts[d.get("roll")] += 1
            bucket_counts[d.get("bucket")] += 1

        check("roll-covers-all-4-buckets",
              set(roll_counts) == {"q1", "q2", "q3", "q4"}, dict(roll_counts))
        pcts = {b: 100.0 * c / N for b, c in roll_counts.items()}
        roll_even = all(19.0 <= pcts.get(q, 0) <= 31.0 for q in ("q1", "q2", "q3", "q4"))
        check("roll-distribution-25pct", roll_even, str(pcts))

        yes_rate = 100.0 * bucket_counts.get("yes", 0) / N
        check("bucket-covers-yes-and-no",
              {"yes", "no"} <= set(bucket_counts), dict(bucket_counts))
        check("bucket-distribution-10pct", 6.0 <= yes_rate <= 15.0, f"yes={yes_rate:.2f}%")

        # ---- 两条解析路径整体一致：抽样比对 /show 与 /echo ----
        agree = True
        for i in range(0, 200, 7):
            key = f"cross-{i}"
            s, b = get("/show", {"X-Key": key, "User-Agent": key})
            d = kv(b)
            s2, b2 = get("/echo", {"X-Key": key, "User-Agent": key})
            d2 = kv(b2)
            if d.get("roll") != d2.get("x-roll") or d.get("bucket") != d2.get("x-bucket"):
                agree = False
                break
        check("lua-and-proxy-paths-agree", agree, "/show(ngx.var) 与 /echo(proxy_set_header) 落桶应完全一致")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        echo.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== split_clients E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
