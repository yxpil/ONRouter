# -*- coding: utf-8 -*-
"""ONRouter 冒烟测试：自动拉起两个演示后端 + 网关，跑完全部检查后清理。"""
import subprocess, sys, time, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request, urllib.error

RUST = os.path.dirname(os.path.abspath(__file__))  # 仓库根：脚本与 conf/、target/ 同级

class Backend(BaseHTTPRequestHandler):
    name = "backend-?"
    def do_GET(self):
        body = f"{self.name} path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Backend", self.name)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

def start_backend(port, name):
    cls = type("B", (Backend,), {"name": name})
    srv = HTTPServer(("127.0.0.1", port), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

import ssl as _ssl

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

_ctx = _ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = _ssl.CERT_NONE

# 禁用系统代理（HTTP_PROXY/HTTPS_PROXY），本机直连测试；HTTPS 跳过自签名验证
_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                      urllib.request.HTTPSHandler(context=_ctx))

def req(method, path, headers=None, data=None, timeout=10, https=False):
    url = ("https://127.0.0.1:8443" if https else "http://127.0.0.1:8080") + path
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        resp = _opener.open(r, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL"), name, detail if not ok or detail else "")

def main():
    b1 = start_backend(9001, "backend-1")
    b2 = start_backend(9002, "backend-2")

    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    if not os.path.exists(exe):
        exe = os.path.join(RUST, "target", "debug", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "onrouter.conf")],
                          cwd=RUST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                req("GET", "/health"); break
            except Exception: time.sleep(0.2)

        # 1 基础
        st, h, b = req("GET", "/")
        check("index 页面", st == 200 and "ONRouter" in b.decode("utf-8", "ignore"), f"{st} {b[:80]}")
        st, h, b = req("GET", "/static/logo.png")
        check("logo 静态文件", st == 200 and "image/png" in h.get("content-type", ""), f"{st} {b[:60]}")
        st, h, b = req("GET", "/static/")
        check("静态 index", st == 200 and b"ONRouter" in b, f"{st} {b[:60]}")
        st, h, b = req("GET", "/no/such/path")
        check("404", st == 404, f"{st} {b[:60]}")

        # 2 Lua
        st, h, b = req("GET", "/hello")
        check("content_by_lua 内联", st == 200 and b"Hello from Lua" in b, f"{st} {b[:80]}")
        st, h, b = req("GET", "/api/time")
        check("lua 文件 + rewrite + sleep", st == 200 and b"now" in b, f"{st} {b[:80]}")
        st, h, b = req("GET", "/api/protected")
        check("鉴权 401", st == 401, f"{st}")
        st, h, b = req("GET", "/api/protected", {"x-token": "wrong"})
        check("鉴权 403", st == 403, f"{st}")
        st, h, b = req("GET", "/api/protected", {"x-token": "secret123"})
        check("鉴权 200", st == 200 and b"welcome" in b, f"{st} {b[:60]}")
        st, h, b = req("GET", "/api/slow")
        check("ngx.sleep 异步", st == 200 and b"0.1s" in b, f"{st} {b[:60]}")

        # 3 反代 + LB 轮询
        bodies = set()
        sts = []
        for _ in range(4):
            st, h, b = req("GET", "/proxy/ping")
            sts.append(st)
            bodies.add(b.decode("utf-8", "ignore").split(" ")[0])
        check("upstream 轮询", set(sts) == {200} and bodies == {"backend-1", "backend-2"},
              f"{sts} {bodies}")

        # 4 rewrite/return
        st, h, b = req("GET", "/old/thing")
        check("rewrite last", st == 200 and b"/new/thing" in b, f"{st} {b[:80]}")
        st, h, b = req("GET", "/health")
        check("return 200", st == 200 and b == b"ok", f"{st} {b[:40]}")
        st, h, b = req("GET", "/jump")
        check("return 301", st == 301 and "hello" in h.get("location", ""), f"{st} {h.get('location')}")
        st, h, b = req("GET", "/user/42")
        check("正则 location", st == 200 and b"user id" in b, f"{st} {b[:60]}")
        st, h, b = req("GET", "/api/info")
        check("rust 原生模块", st == 200 and b"method=GET" in b, f"{st} {b[:60]}")

        # 5 新功能
        st1, _, b1_ = req("GET", "/count")
        st2, _, b2_ = req("GET", "/count")
        n1 = int(b1_.decode().split("hits=")[1].split("\n")[0])
        n2 = int(b2_.decode().split("hits=")[1].split("\n")[0])
        check("shared.DICT 原子计数", st1 == 200 and n2 == n1 + 1, f"{st1}/{st2} {n1}->{n2}")

        st, h, b = req("GET", "/go")
        check("ngx.redirect 302", st == 302 and h.get("location", "").endswith("/hello"),
              f"{st} {h.get('location')} {b[:60]}")
        st, h, b = req("GET", "/inner")
        check("ngx.exec 内部重定向", st == 200 and b"Hello from Lua" in b, f"{st} {b[:80]}")

        st, h, b = req("GET", "/api/tools")
        txt = b.decode("utf-8", "ignore")
        check("ngx.re 正则捕获", st == 200 and "re-capture=tools" in txt, f"{st} {b[:100]}")
        check("escape_uri/unescape_uri", "a%20b%2Fc%3Fd" in txt and "你好" in txt, txt[:150])
        st, h, b = req("POST", "/api/tools", data=b"hello-onrouter-body")
        check("请求体读取", st == 200 and "body_len=19" in b.decode("utf-8", "ignore"),
              f"{st} {b.decode('utf-8', 'ignore')[:150]}")

        # 6 add_header
        st, h, b = req("GET", "/hello")
        # 断言的是 add_header 生效，不是版本号本身：写死 "ONRouter/x.y" 会让每次发版都误报
        check("add_header", (h.get("x-powered-by") or "").startswith("ONRouter/"), f"{st} {h.get('x-powered-by')}")

        # 7 HTTPS/TLS（8443 端口，自签名证书）
        st, h, b = req("GET", "/hello", https=True)
        check("HTTPS Lua", st == 200 and b"Hello from Lua" in b, f"{st} {b[:60]}")
        check("HTTPS Server 头", h.get("server", "").startswith("ONRouter/"), str(h.get("server")))
        st, h, b = req("GET", "/proxy/ping", https=True)
        check("HTTPS 反代", st == 200 and b"backend-" in b, f"{st} {b[:60]}")
        st, h, b = req("GET", "/count", https=True)
        check("HTTPS shared.DICT", st == 200 and "hits=" in b.decode("utf-8", "ignore"), f"{st}")
        st, h, b = req("POST", "/api/tools", data=b"tls-body", https=True)
        check("HTTPS 请求体", st == 200 and "body_len=8" in b.decode("utf-8", "ignore"), f"{st}")

    finally:
        gw.kill()
        b1.shutdown(); b2.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n=== {passed}/{len(results)} 通过 ===")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
