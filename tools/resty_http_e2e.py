# -*- coding: utf-8 -*-
# resty.http 纯 Lua HTTP 客户端 E2E —— 网关内 resty.http 向一个真实 Python HTTP 后端发请求，
# 用真实流量证明 GET/HEAD/POST、Content-Length 与 chunked 体解析、204、自定义头、query 编码、
# keepalive 连接池复用、以及错误路径全部可用。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/resty_http_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "resty_http.conf")
HOST, PORT = "127.0.0.1", 18145
BACKEND_HOST, BACKEND_PORT = "127.0.0.1", 18146
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


def get(path):
    r = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    m = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        m[k.strip()] = v.strip()
    return m


# ------------------- 真实 HTTP 后端（供 resty.http 抓取）-------------------
class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body=b"", headers=None, chunked=False):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            i, step = 0, max(1, len(body) // 3)
            while i < len(body):
                part = body[i:i + step]
                self.wfile.write(("%x\r\n" % len(part)).encode() + part + b"\r\n")
                i += step
            self.wfile.write(b"0\r\n\r\n")
        elif code in (204, 304):
            self.end_headers()
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?", 1)
        if p[0] == "/plain":
            self._send(200, b"hello resty", {"Content-Type": "text/plain"})
        elif p[0] == "/chunked":
            self._send(200, b"abcdefghij", {}, chunked=True)
        elif p[0] == "/empty":
            self._send(204)
        elif p[0] == "/headers":
            self._send(200, b"ok", {"X-Test": "yes-42", "Content-Type": "application/json"})
        elif p[0] == "/echo":
            q = p[1] if len(p) > 1 else ""
            self._send(200, q.encode(), {"Content-Type": "text/plain"})
        else:
            self._send(404, b"nf")

    def do_HEAD(self):
        self._send(200, b"", {"Content-Type": "text/plain"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(n) if n else b""
        self._send(200, data, {"Content-Type": "text/plain"})

    def log_message(self, *a):
        pass


def start_backend():
    srv = ThreadingHTTPServer((BACKEND_HOST, BACKEND_PORT), Backend)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main():
    srv = start_backend()
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "resty_http_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if get("/get_plain")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18145 被占用？看 logs/resty_http_err.log）")

        st, body = get("/get_plain")
        b = kv(body)
        check("/get_plain 经 resty.http 200", b.get("status") == "200", f"{b}")
        check("Content-Length 体正确", b.get("body") == "hello resty", f"body={b.get('body')}")
        check("响应头 content-length=11", b.get("cl") == "11", f"cl={b.get('cl')}")

        st, body = get("/get_chunked")
        c = kv(body)
        check("/get_chunked 200", c.get("status") == "200", f"{c}")
        check("chunked 重组为 abcdefghij", c.get("body") == "abcdefghij", f"body={c.get('body')}")
        check("chunked body_len=10", c.get("body_len") == "10", f"len={c.get('body_len')}")

        st, body = get("/get_204")
        e = kv(body)
        check("/get_204 状态 204", e.get("status") == "204", f"{e}")
        check("204 空体", e.get("body_len") == "0", f"len={e.get('body_len')}")

        st, body = get("/head")
        hd = kv(body)
        check("/head HEAD 状态 200", hd.get("status") == "200", f"{hd}")
        check("HEAD 恒空体", hd.get("body_len") == "0", f"len={hd.get('body_len')}")

        st, body = get("/post")
        po = kv(body)
        check("/post POST 200", po.get("status") == "200", f"{po}")
        check("POST 体回显", po.get("echo") == "hello=1&x=2", f"echo={po.get('echo')}")

        st, body = get("/headers")
        he = kv(body)
        check("/headers 自定义头 x-test", he.get("x_test") == "yes-42", f"x_test={he.get('x_test')}")
        check("/headers content-type", he.get("ctype") == "application/json", f"ctype={he.get('ctype')}")

        st, body = get("/query")
        q = kv(body)
        echo = q.get("echo", "")
        check("/query 自动编码含 a=1", "a=1" in echo, f"echo={echo}")
        check("/query 空格编码 %20", "b=x%20y" in echo, f"echo={echo}")

        st, body = get("/keepalive")
        ka = kv(body)
        check("/keepalive 两次复用请求 200", ka.get("s1") == "200" and ka.get("s2") == "200", f"{ka}")
        check("set_keepalive 成功(返回 1)", ka.get("ka") in ("1", "true"), f"ka={ka.get('ka')}")
        check("池复用第三次请求 200", ka.get("s3") == "200", f"s3={ka.get('s3')}")

        st, body = get("/badhost")
        bh = kv(body)
        check("连不通端口 res=nil", bh.get("res") == "nil", f"res={bh.get('res')}")
        check("连不通端口有 err", bh.get("has_err") == "true", f"has_err={bh.get('has_err')}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        srv.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== resty.http E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
