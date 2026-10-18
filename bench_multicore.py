# -*- coding: utf-8 -*-
"""多核并发压测：验证 Lua VM 池并行 + shared.DICT 计数在多 VM 下依然原子一致。"""
import subprocess, sys, time, os, threading
import urllib.request, urllib.error
import ssl as _ssl

RUST = os.path.dirname(os.path.abspath(__file__))
BASE = "http://127.0.0.1:8080"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

_ctx = _ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = _ssl.CERT_NONE
_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                      urllib.request.HTTPSHandler(context=_ctx))

def req(path, timeout=10):
    r = urllib.request.Request(BASE + path)
    try:
        resp = _opener.open(r, timeout=timeout)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def main():
    b1 = subprocess.Popen([sys.executable, "-c", """
from http.server import BaseHTTPRequestHandler, HTTPServer
class B(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',9001),B).serve_forever()
"""])
    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "onrouter.conf")],
                          cwd=RUST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = True
    try:
        for _ in range(50):
            try: req("/health"); break
            except Exception: time.sleep(0.2)

        # --- 1. 并发 Lua：128 线程 x 8 次 /api/slow（ngx.sleep 异步）+ /hello ---
        errors = []
        hits = [0]
        lock = threading.Lock()
        def worker(n):
            for _ in range(n):
                try:
                    st, b = req("/hello")
                    if st != 200 or b"Hello from Lua" not in b:
                        errors.append(f"/hello {st}")
                except Exception as e:
                    errors.append(f"/hello {type(e).__name__}")
        def worker_sleep(n):
            for _ in range(n):
                try:
                    st, b = req("/api/slow")
                    if st != 200 or b"slept" not in b:
                        errors.append(f"/api/slow {st}")
                except Exception as e:
                    errors.append(f"/api/slow {type(e).__name__}")
        threads = [threading.Thread(target=worker, args=(8,)) for _ in range(64)] + \
                  [threading.Thread(target=worker_sleep, args=(4,)) for _ in range(32)]
        t0 = time.time()
        for t in threads: t.start()
        for t in threads: t.join()
        dt = time.time() - t0
        total = 64*8 + 32*4
        print(f"并发 Lua 请求 {total} 个（128 线程）耗时 {dt*1000:.0f}ms，吞吐 {total/dt:.0f} req/s，错误 {len(errors)}")
        if errors: ok = False; print("  错误样例:", errors[:5])

        # --- 2. shared.DICT 多 VM 原子性：并发 incr 后总和必须精确 ---
        n_threads, n_incr = 32, 25
        def incr_worker():
            for _ in range(n_incr):
                req("/count")
        # 先读基线
        st, b = req("/count")
        base = int(b.decode().split("hits=")[1].split("\n")[0])
        threads = [threading.Thread(target=incr_worker) for _ in range(n_threads)]
        for t in threads: t.start()
        for t in threads: t.join()
        st, b = req("/count")
        final = int(b.decode().split("hits=")[1].split("\n")[0])
        expected = base + n_threads * n_incr + 1  # +1 为本次读值请求自身
        print(f"shared.DICT 原子计数: 基线 {base} + {n_threads}x{n_incr} 并发 incr，最终 {final}（期望 {expected}）")
        if final != expected: ok = False

        # --- 3. upstream 轮询正确性 ---
        # 等后端 9001 就绪（避免冷启动 502 触发被动摘除）
        import socket
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', 9001), timeout=0.5).close()
                break
            except Exception:
                time.sleep(0.2)
        sts, bodies = [], set()
        for _ in range(8):
            st, b = req("/proxy/ping")
            sts.append(st); bodies.add(b.decode().split(" ")[0])
        print(f"upstream 轮询: {sts} {bodies}")
        if set(sts) != {200}: ok = False

    finally:
        gw.kill(); b1.kill()
    print("\n=== 多核压测:", "通过" if ok else "失败", "===")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
