# -*- coding: utf-8 -*-
# proxy_cache E2E —— 用真实流量证明响应缓存真的命中/回源：
#   * 首次可缓存响应 → X-Cache-Status: MISS，后端计数 +1
#   * 再次相同请求   → X-Cache-Status: HIT，后端计数不变（证明真的没打后端），响应体字节一致
#   * 带 Set-Cookie 的响应 → 不缓存，每次都回源（BYPASS）
#   * 上游 Cache-Control: no-store → 不缓存（BYPASS）
#   * 未启缓存的对照 location → 不带 X-Cache-Status 头，且每次回源
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_cache_e2e.py
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
CONF = os.path.join(ROOT, "conf", "proxy_cache.conf")

BACKEND_PORT = 18122
GW_HOST, GW_PORT = "127.0.0.1", 18123
BASE = f"http://{GW_HOST}:{GW_PORT}"

# 后端按路径维护"真实被服务次数"，用于判定网关是否命中缓存（命中则不再打后端）
counter_lock = threading.Lock()
hits = {}
# 收到过几次真正的条件请求（If-None-Match 命中→304）：与 hits 分开记，
# 因为"问了"和"重发了整份"是两件事，测试要能分开断言
conditionals = {}
# rv/rvn 两个区的"整份响应发出过几次"：304 不算，所以它与 hits 分开
rv_served = {}

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, headers=None):
    req = urllib.request.Request(BASE + path, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=10)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        with counter_lock:
            hits[path] = hits.get(path, 0) + 1
            n = hits[path]
        # 缓存探针：/count 可缓存
        if path.startswith("/count"):
            body = f"count={n} nonce=abc123".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/cookie"):
            body = f"cookie={n}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "sid=xyz; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/rv/") or path.startswith("/rvn/"):
            # 短 max-age=2 + 固定 ETag：条目过期后能不能复用，取决于网关有没有带着条件头来问。
            # rv 与 rvn 各用一个 ETag，两区的 304 不会互相认错对象。
            name = "rv" if path.startswith("/rv/") else "rvn"
            etag = f'"{name}-1"'
            if self.headers.get("If-None-Match") == etag:
                # 304 不带 body：整份响应没重发，但"问过上游"必须记账 —— conditionals 与 hits
                # 分开，测试才能把"问了"与"重发了整份"断言成两件事
                with counter_lock:
                    conditionals[path] = conditionals.get(path, 0) + 1
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "max-age=2")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # 只有真的发出整份时才让发出计数涨：304 不能推它，否则 R4 什么也说明不了
            with counter_lock:
                rv_served[name] = rv_served.get(name, 0) + 1
                served = rv_served[name]
            body = f"{name}={served} n={n}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", "Wed, 21 Oct 2026 08:00:00 GMT")
            self.send_header("Cache-Control", "max-age=2")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/nocache"):
            body = f"nc={n}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"other"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_a):
        pass


def backend_count(path):
    with counter_lock:
        return hits.get(path, 0)


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "proxy_cache_out.log"), "wb")
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
            raise SystemExit("!! onrouter 未就绪（端口 18123/18122 被占用？看 logs/proxy_cache_out.log）")

        # 1) 首次 MISS
        st, hs, body = request("/c/count")
        check("/c/count 首次 200", st == 200, f"st={st}")
        check("首次 X-Cache-Status=MISS", hdr(hs, "X-Cache-Status") == "MISS", f"xcs={hdr(hs,'X-Cache-Status')}")
        check("首次确实打了后端（count=1）", backend_count("/count") == 1, f"cnt={backend_count('/count')}")

        # 2) 再次 HIT：不打后端，响应体与首次字节一致
        st2, hs2, body2 = request("/c/count")
        check("重复 X-Cache-Status=HIT", hdr(hs2, "X-Cache-Status") == "HIT", f"xcs={hdr(hs2,'X-Cache-Status')}")
        check("HIT 时后端计数未增加（真的命中缓存）", backend_count("/count") == 1, f"cnt={backend_count('/count')}")
        check("HIT 响应体与 MISS 完全一致", body2 == body, f"body1={body!r} body2={body2!r}")
        check("缓存保留 Content-Type", (hdr(hs2, "Content-Type") or "").startswith("text/plain"), f"ct={hdr(hs2,'Content-Type')}")

        # 3) 不同 key 不串：/c/count?x=1 视为不同 cache key → MISS
        st3, hs3, _ = request("/c/count?x=1")
        check("不同 query → 不同 cache key（MISS）", hdr(hs3, "X-Cache-Status") == "MISS", f"xcs={hdr(hs3,'X-Cache-Status')}")

        # 4) Set-Cookie → 不缓存，每次回源
        st4, hs4, b4 = request("/c/cookie")
        check("/c/cookie（Set-Cookie）→ BYPASS", hdr(hs4, "X-Cache-Status") == "BYPASS", f"xcs={hdr(hs4,'X-Cache-Status')}")
        c_before = backend_count("/cookie")
        request("/c/cookie")
        check("Set-Cookie 每次都回源（计数增加）", backend_count("/cookie") == c_before + 1, "cookie 响应未被缓存")

        # 5) Cache-Control: no-store → 不缓存
        st5, hs5, _ = request("/c/nocache")
        check("/c/nocache（no-store）→ BYPASS", hdr(hs5, "X-Cache-Status") == "BYPASS", f"xcs={hdr(hs5,'X-Cache-Status')}")

        # 6) 对照：未启缓存的 location 不带 X-Cache-Status，且每次回源
        st6, hs6, _ = request("/nocache-proxy/count")
        check("对照 location 无 X-Cache-Status 头", hdr(hs6, "X-Cache-Status") is None, f"xcs={hdr(hs6,'X-Cache-Status')}")
        nb = backend_count("/count")
        request("/nocache-proxy/count")
        check("对照 location 每次都回源", backend_count("/count") == nb + 1, f"cnt={backend_count('/count')}")

        # ---- proxy_cache_revalidate：过期后带条件问一次，304 就复用存下来的 body ----
        st, hsb, body = request("/rv/x")
        check("R1 /rv 首次 MISS 并写入缓存",
              hdr(hsb, "X-Cache-Status") == "MISS" and body.startswith("rv=1"),
              f'xcs={hdr(hsb, "X-Cache-Status")} body={body!r}')
        st, hsb, body2 = request("/rv/x")
        check("R2 未过期时直接 HIT", hdr(hsb, "X-Cache-Status") == "HIT" and body2 == body,
              f'xcs={hdr(hsb, "X-Cache-Status")} body={body2!r}')
        time.sleep(2.4)                      # 上游 max-age=2 → 条目过期
        nb = backend_count("/rv/x")
        cond_b = conditionals.get("/rv/x", 0)
        st, hsb, body3 = request("/rv/x")
        check("R3 过期后答 304 时按 REVALIDATED 收口",
              st == 200 and hdr(hsb, "X-Cache-Status") == "REVALIDATED",
              f'st={st} xcs={hdr(hsb, "X-Cache-Status")}')
        check("R4 复用的是缓存里那份 body（没有第二遍内容）", body3 == body,
              f"cached={body!r} now={body3!r}")
        check("R5 确实问了上游，而且是条件请求",
              backend_count("/rv/x") == nb + 1 and conditionals.get("/rv/x", 0) == cond_b + 1,
              f'backend={backend_count("/rv/x")} nb={nb} cond={conditionals.get("/rv/x", 0)}')
        st, hsb, body4 = request("/rv/x")
        check("R6 304 重算了有效期（紧接着是内存 HIT，不再问上游）",
              hdr(hsb, "X-Cache-Status") == "HIT" and backend_count("/rv/x") == nb + 1
              and body4 == body,
              f'xcs={hdr(hsb, "X-Cache-Status")} backend={backend_count("/rv/x")}')
        # 对照组：同样 max-age=2，但没开 revalidate → 过期只能整份重取，也从不发条件请求
        request("/rvn/x")
        time.sleep(2.4)
        nb2 = backend_count("/rvn/x")
        cond2 = conditionals.get("/rvn/x", 0)
        st, hsb, body5 = request("/rvn/x")
        # EXPIRED 而不是 REVALIDATED，且拿到的是第二份内容（rvn=2）：这就是开不开 revalidate 的
        # 可观测差别——上游被问了同样的次数，但一次要重发整份 body，一次只用 304
        check("R7 没开 revalidate 的对照组过期后整份重取（EXPIRED + 第二份内容）",
              hdr(hsb, "X-Cache-Status") == "EXPIRED" and body5.startswith("rvn=2"),
              f'xcs={hdr(hsb, "X-Cache-Status")} body={body5!r}')
        check("R8 对照组没发过条件请求（上游没收到 If-None-Match）",
              conditionals.get("/rvn/x", 0) == cond2 and backend_count("/rvn/x") == nb2 + 1,
              f'cond={conditionals.get("/rvn/x", 0)} backend={backend_count("/rvn/x")}')

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
    print(f"\n==== proxy_cache E2E: {passed}/{total} passed ====")
    print(f"     后端命中计数: {dict(hits)}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
