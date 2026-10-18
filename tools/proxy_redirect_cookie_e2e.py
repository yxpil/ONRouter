# -*- coding: utf-8 -*-
# proxy_redirect + proxy_cookie_domain/path E2E —— 用真实流量证明代理响应头改写：
#   * 字面量前缀 redirect（流式缝 convert_upstream_response）
#   * proxy_redirect default（上游 origin → 对外前缀，相对 Location）
#   * 正则 redirect + 捕获组
#   * proxy_cookie_domain/path 改写 + `none` 删除 + 多条 Set-Cookie 都各自改写
#   * 全 off 对照 → 原样透传
#   * sub_filter 强制缓冲路径（缓冲缝 build_buffered_response）同样改写、body 不变
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_redirect_cookie_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "proxy_redirect_cookie_e2e.conf")

BACKEND_PORT = 18201
GW_HOST, GW_PORT = "127.0.0.1", 18200
BASE = f"http://{GW_HOST}:{GW_PORT}"

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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # 不要自动跟随 302：改写后的 Location 可能指向不存在的域名，我们只检查响应头本身。
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


def request(path):
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(req, timeout=10)
        return resp.status, resp.headers, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode(errors="replace")


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path
        # 默认：一个 302 + 若干响应头，按路径前缀决定具体值
        if p.startswith("/lit/"):
            self._send(
                "http://backend.internal:8080/a/b",
                ["sid=1; domain=backend.internal; path=/app/sub"],
                "text/html",
            )
        elif p.startswith("/def/"):
            # 上游 origin = proxy_pass authority，路径不含 location 前缀
            self._send(f"http://127.0.0.1:{BACKEND_PORT}/target", [], "text/html")
        elif p.startswith("/regex/"):
            self._send("http://x:9000/pa/th", [], "text/html")
        elif p.startswith("/cookienone/"):
            self._send(
                "http://noop/x",
                [
                    "a=1; domain=.backend.internal; path=/p",
                    "b=2; domain=.backend.internal; path=/p",
                ],
                "text/html",
            )
        elif p.startswith("/off/"):
            self._send(
                "http://backend.internal:8080/x",
                ["c=3; domain=backend.internal; path=/app"],
                "text/html",
            )
        elif p.startswith("/buf/"):
            # body 含可缓冲的普通文本；sub_filter 的 AAA 不命中 → body 不变
            self._send(
                "http://backend.internal:8080/buf",
                ["d=4; domain=backend.internal; path=/app"],
                "text/html",
                body="hello-body",
            )
        else:
            self._send("http://backend.internal:8080/other", [], "text/html")

    def _send(self, location, cookies, ctype, body="ok"):
        data = body.encode()
        self.send_response(302)
        self.send_header("Location", location)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_a):
        pass


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "proxy_redirect_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping")[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18200/18201 被占用？看 logs/proxy_redirect_out.log）")

        # 1) 字面量前缀 redirect + cookie domain/path（流式缝）
        st, hs, _ = request("/lit/redir")
        check("/lit 302", st == 302, f"st={st}")
        check("/lit Location 前缀改写", hs.get("location") == "http://public.example/a/b",
              f"loc={hs.get('location')}")
        sc = hs.get("set-cookie") or ""
        check("/lit cookie domain 改写", "domain=public.example" in sc, f"sc={sc}")
        check("/lit cookie path 前缀替换保留尾部", "path=/gateway/sub" in sc, f"sc={sc}")
        check("/lit 其它属性不动", "sid=1" in sc, f"sc={sc}")

        # 2) proxy_redirect default → 相对 Location（origin 换成 location 前缀）
        st, hs, _ = request("/def/redir")
        check("/def 302", st == 302, f"st={st}")
        check("/def default 产出相对 Location /def/target", hs.get("location") == "/def/target",
              f"loc={hs.get('location')}")

        # 3) 正则 redirect + 捕获组
        st, hs, _ = request("/regex/redir")
        check("/regex 正则改写 + $1 捕获", hs.get("location") == "https://pub/pa/th",
              f"loc={hs.get('location')}")

        # 4) proxy_cookie_domain none 删除 + 两条 Set-Cookie 都各自改写
        st, hs, _ = request("/cookienone/redir")
        allc = hs.get_all("set-cookie") or []
        check("/cookienone 两条 Set-Cookie 都保留", len(allc) == 2, f"cookies={allc}")
        check("/cookienone 两条都删除 domain", all(("domain" not in c.lower()) for c in allc),
              f"cookies={allc}")
        check("/cookienone 两条都保留 path 与 name", all(("path=/p" in c) for c in allc)
              and any("a=1" in c for c in allc) and any("b=2" in c for c in allc),
              f"cookies={allc}")

        # 5) 全 off 对照 → 原样透传
        st, hs, _ = request("/off/redir")
        check("/off Location 未被改写", hs.get("location") == "http://backend.internal:8080/x",
              f"loc={hs.get('location')}")
        sc = hs.get("set-cookie") or ""
        check("/off cookie 未被改写", "domain=backend.internal" in sc and "path=/app" in sc,
              f"sc={sc}")

        # 6) 缓冲缝（sub_filter 强制缓冲）：Location/cookie 改写生效、body 不变
        st, hs, body = request("/buf/redir")
        check("/buf 302", st == 302, f"st={st}")
        check("/buf 缓冲缝 Location 改写", hs.get("location") == "/pub/buf",
              f"loc={hs.get('location')}")
        sc = hs.get("set-cookie") or ""
        check("/buf 缓冲缝 cookie domain 改写", "domain=example.net" in sc, f"sc={sc}")
        check("/buf sub_filter 未命中 → body 原样", body == "hello-body", f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== proxy_redirect/cookie E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
