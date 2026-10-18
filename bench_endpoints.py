# -*- coding: utf-8 -*-
"""端点性能基准：静态文件 / Lua / 反代 三类端点吞吐（keep-alive 长连接，串行 + 并发）。"""
import subprocess, sys, time, os, threading
import socket
import http.client

RUST = os.path.dirname(os.path.abspath(__file__))
PORT = 8080

BACKEND_SRC = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = {port}
class B(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = ('{{"node":"n-%d","path":"%s"}}' % (PORT, self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", PORT), B).serve_forever()
"""

def start_backend(port):
    return subprocess.Popen([sys.executable, "-c", BACKEND_SRC.format(port=port)])

def bench(path, n, threads=1):
    errs = [0]
    per = n // threads
    def worker():
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        except Exception:
            errs[0] += per
            return
        for _ in range(per):
            try:
                conn.request("GET", path)
                r = conn.getresponse()
                r.read()
                if r.status != 200:
                    errs[0] += 1
            except Exception:
                errs[0] += 1
                try: conn.close()
                except Exception: pass
                try: conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
                except Exception: return
        try: conn.close()
        except Exception: pass
    t0 = time.time()
    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()
    dt = time.time() - t0
    return n / dt, errs[0], dt

def main():
    backends = [start_backend(p) for p in (9001, 9002)]
    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "onrouter.conf")],
                          cwd=RUST, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        for p in (9001, 9002):
            for _ in range(50):
                try: socket.create_connection(("127.0.0.1", p), timeout=0.5).close(); break
                except Exception: time.sleep(0.2)
        for _ in range(50):
            try:
                c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
                c.request("GET", "/health"); c.getresponse().read(); c.close(); break
            except Exception: time.sleep(0.2)

        print(f"{'端点':<26}{'模式':<9}{'req/s':>9}{'耗时s':>9}{'错误':>6}")
        for name, path in [("静态 /index.html", "/index.html"),
                           ("Lua content_by_lua", "/hello"),
                           ("Lua shared.DICT", "/count"),
                           ("反代 /proxy/ping", "/proxy/ping")]:
            rps, errs, dt = bench(path, 500, threads=1)
            print(f"{name:<26}{'串行':<9}{rps:>9.0f}{dt:>9.2f}{errs:>6}")
            rps, errs, dt = bench(path, 2000, threads=32)
            print(f"{name:<26}{'32并发':<9}{rps:>9.0f}{dt:>9.2f}{errs:>6}")
    finally:
        gw.kill()
        for b in backends: b.kill()
    sys.exit(0)

if __name__ == "__main__":
    main()
