# -*- coding: utf-8 -*-
# nginx `geo` 指令 E2E —— 真实 HTTP 流量证明按 IP 的派生变量落地：
#   /show：客户端带不同 X-IP 头，读回 ngx.var.net（主机 /32、宽网段 /8、更具体 /16、
#          另一段、default）以及默认源 ngx.var.from_remote（$remote_addr 命中 127/8）；
#   /echo：geo 目标写进 proxy_set_header，经真实代理转发到回显后端，后端原样打回，
#          证明 config 字符串插值路径也解析了 geo。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/geo_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "geo_e2e.conf")
HOST, PORT = "127.0.0.1", 18170
ECHO_PORT = 18171
BASE = f"http://{HOST}:{PORT}"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


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
            lines = []
            for k, v in self.headers.items():
                lines.append(f"{k.lower()}={v}")
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
    logf = open(os.path.join(ROOT, "logs", "geo_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            check("server-start", False, "onrouter 未监听 18170")
            return
        check("server-start", True)

        # ---- /show：Lua ngx.var 读 geo 目标 ----
        s, b = get("/show", {"X-IP": "127.0.0.1"})
        d = kv(b)
        check("show-host32-loopback", d.get("net") == "loopback", b)
        # 默认源 $remote_addr（本地=127.0.0.1）命中 127.0.0.0/8
        check("show-default-source", d.get("from") == "localnet", b)

        # 最长前缀：10.1.0.0/16 比 10.0.0.0/8 更具体 → net10-1（并触发 Lua 分支）
        s, b = get("/show", {"X-IP": "10.1.2.3"})
        d = kv(b)
        check("show-longest-prefix", d.get("net") == "net10-1", b)
        check("show-lua-branch", d.get("branch") == "most-specific", b)

        # 只命中宽网段：10.2.0.1 → net10（/8）
        s, b = get("/show", {"X-IP": "10.2.0.1"})
        check("show-wide-net", kv(b).get("net") == "net10", b)

        # 另一网段：192.168.5.5 → rfc1918
        s, b = get("/show", {"X-IP": "192.168.5.5"})
        check("show-another-net", kv(b).get("net") == "rfc1918", b)

        # 都不匹配 → default external
        s, b = get("/show", {"X-IP": "8.8.8.8"})
        check("show-default-external", kv(b).get("net") == "external", b)

        # ---- /echo：geo 目标写进 proxy_set_header，经真实代理转发到回显后端 ----
        s, b = get("/echo", {"X-IP": "10.1.9.9", "X-Anything": "1"})
        d = kv(b)
        check("echo-longest-prefix", d.get("x-net") == "net10-1", b)
        check("echo-default-source", d.get("x-from") == "localnet", b)

        s, b = get("/echo", {"X-IP": "8.8.4.4"})
        d = kv(b)
        check("echo-default", d.get("x-net") == "external", b)

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
    print(f"\n==== geo E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
