# -*- coding: utf-8 -*-
# nginx `sub_filter` 响应体替换 E2E —— 用真实 HTTP 流量证明字面/正则/once/类型门控
# 以及三条输出路径（proxy / content_by_lua / 静态，含 Range 不改写）都正确落地。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/sub_filter_e2e.py
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
CONF = os.path.join(ROOT, "conf", "sub_filter_e2e.conf")
HOST, PORT = "127.0.0.1", 18174
BACK_PORT = 18175
BASE = f"http://{HOST}:{PORT}"
WEBROOT = os.path.join(ROOT, "public_sub_filter_e2e")

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


def make_backend(port):
    HTML = "<p>BACKEND_HOST one</p><p>BACKEND_HOST two</p><v>v1.0</v>"
    REGEX = "count=42 count=7 done"

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/json"):
                body, ct = b'{"marker":"BACKEND_HOST"}', "application/json"
            elif self.path.startswith("/rx"):
                body, ct = REGEX.encode(), "text/html"
            else:  # /proxy, /once 及其它 → 两段 HTML
                body, ct = HTML.encode(), "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ct)
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


def write_static():
    os.makedirs(WEBROOT, exist_ok=True)
    # 前 12 字节恰为 STATIC_TOKEN，供 Range 0-11 断言
    with open(os.path.join(WEBROOT, "s.html"), "w") as f:
        f.write("STATIC_TOKEN and STATIC_TOKEN and padding-zzzzzzzzzzzzzzzzzzzz")


def main():
    write_static()
    back = make_backend(BACK_PORT)
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "sub_filter_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            check("server-start", False, "onrouter 未监听 18174")
            return
        check("server-start", True)

        # 1) 字面串全替换（once off）+ 两条规则顺序应用
        s, b = get("/proxy")
        check("proxy-literal-all",
              b.count("REWRITTEN") == 2 and "BACKEND_HOST" not in b and "v9.9" in b, b)

        # 2) 类型门控：application/json 不改写
        s, b = get("/json")
        check("proxy-type-gated-noop",
              "BACKEND_HOST" in b and "NOPE" not in b, b)

        # 3) once 默认 on：仅第一处替换
        s, b = get("/once")
        check("proxy-once-first-only",
              "Z one" in b and b.count("BACKEND_HOST") == 1, b)

        # 4) ~正则 + & 回填（once off 全替换）
        s, b = get("/rx")
        check("proxy-regex-amp-backref",
              "count=N-42" in b and "count=N-7" in b and "done" in b, b)

        # 5) content_by_lua 路径（finish_response）
        s, b = get("/lua")
        check("lua-path-subfilter",
              b.count("LUA_DONE") == 2 and "LUA_TOKEN" not in b, b)

        # 6) 静态完整体改写
        s, b = get("/s/s.html")
        check("static-full-rewritten",
              b.startswith("S_DONE") and "STATIC_TOKEN" not in b, b)

        # 7) 静态 Range 切片不改写（对齐 nginx：不在字节区间上做替换）
        s, b = get("/s/s.html", {"Range": "bytes=0-11"})
        check("static-range-not-rewritten",
              s == 206 and b == "STATIC_TOKEN", f"status={s} body={b!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        back.shutdown()
        import shutil
        shutil.rmtree(WEBROOT, ignore_errors=True)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== sub_filter E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
