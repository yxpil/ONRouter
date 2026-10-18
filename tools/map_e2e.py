# -*- coding: utf-8 -*-
# nginx `map` 指令 E2E —— 用真实 HTTP 流量证明派生变量落地：
#   /show：客户端带不同 X-Src / Upgrade 头，读回 ngx.var.<map 目标> 的精确/正则/
#          大小写不敏感/捕获组/空串/default/内置源/未定义 各类结果；
#   /echo：map 目标写进 proxy_set_header，经真实代理转发到回显后端，后端把收到的
#          X-Kind / X-Conn / X-Secure 原样打回，证明 config 字符串插值路径也解析了 map。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/map_e2e.py
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
CONF = os.path.join(ROOT, "conf", "map_e2e.conf")
HOST, PORT = "127.0.0.1", 18168
ECHO_PORT = 18169
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
    logf = open(os.path.join(ROOT, "logs", "map_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            check("server-start", False, "onrouter 未监听 18168")
            return
        check("server-start", True)

        # ---- /show：Lua ngx.var 读 map 目标 ----
        # 精确匹配 ios → mobile（并触发 Lua 分支判断）
        s, b = get("/show", {"X-Src": "ios"})
        d = kv(b)
        check("show-exact-ios", d.get("kind") == "mobile", b)
        check("show-lua-branch", d.get("branch") == "mobile", b)
        # 内置变量源 $scheme（明文 http）→ insecure
        check("show-builtin-src", d.get("secure") == "insecure", b)
        # 未定义的 map 目标 → nil
        check("show-undef-nil", d.get("undef") == "nil", b)

        # 大小写不敏感正则 ^android（源值 ANDROID-13）→ mobile
        s, b = get("/show", {"X-Src": "ANDROID-13"})
        d = kv(b)
        check("show-regex-ci", d.get("kind") == "mobile", b)

        # 带捕获组正则 ^/v([0-9]+)$ → ver-$1
        s, b = get("/show", {"X-Src": "/v42"})
        d = kv(b)
        check("show-regex-capture", d.get("kind") == "ver-42", b)

        # 都不匹配 → default generic
        s, b = get("/show", {"X-Src": "something-else"})
        d = kv(b)
        check("show-default", d.get("kind") == "generic", b)

        # 空串匹配：Upgrade 头缺失 → $connection_upgrade == close
        s, b = get("/show", {})
        d = kv(b)
        check("show-empty-close", d.get("conn") == "close", b)
        # Upgrade: websocket（非空）→ default upgrade
        s, b = get("/show", {"Upgrade": "websocket"})
        d = kv(b)
        check("show-nonempty-upgrade", d.get("conn") == "upgrade", b)

        # ---- /echo：map 目标写进 proxy_set_header，经真实代理转发到回显后端 ----
        s, b = get("/echo", {"X-Src": "ios", "Upgrade": "websocket"})
        d = kv(b)
        check("echo-kind-exact", d.get("x-kind") == "mobile", b)
        check("echo-conn-upgrade", d.get("x-conn") == "upgrade", b)
        check("echo-secure", d.get("x-secure") == "insecure", b)

        s, b = get("/echo", {"X-Src": "/v7"})
        d = kv(b)
        check("echo-capture", d.get("x-kind") == "ver-7", b)
        # 无 Upgrade 头 → 空串分支 close（证明 config 插值路径也解析空串匹配）
        check("echo-conn-close", d.get("x-conn") == "close", b)

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
    print(f"\n==== map E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
