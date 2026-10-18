# -*- coding: utf-8 -*-
# ngx.balancer (balancer_by_lua) E2E —— 用真实流量证明 Lua 在转发前选定上游节点：
#   * proxy_pass 指向一个"死" upstream(18999)，无 balancer 时必然 502（对照组 /dead）；
#   * balancer_by_lua 用 set_current_peer 把连接改到真实后端，按查询串/请求头分流到 A/B；
#   * set_timeouts 覆盖读超时：慢后端睡 3s，但读超时压到 400ms → ~0.4s 内 502；
#   * 服务发现风格轮转：共享字典计数器在 A/B 间均分真实请求。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/balancer_e2e.py
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
CONF = os.path.join(ROOT, "conf", "balancer_e2e.conf")
HOST, PORT = "127.0.0.1", 18150
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
    t0 = time.time()
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), time.time() - t0


# ------------------- 三个真实后端 -------------------
def make_backend(tag, port, sleep=0.0):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if sleep:
                time.sleep(sleep)
            body = f"be={tag}\n".encode()
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


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    a = make_backend("A", 18151)
    b = make_backend("B", 18152)
    slow = make_backend("SLOW", 18153, sleep=3.0)

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "balancer_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if get("/ping")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18150 被占用？看 logs/balancer_e2e_err.log）")

        st, body, _ = get("/ping")
        check("/ping pong", st == 200 and "pong" in body, f"st={st} body={body!r}")

        # 对照组：无 balancer，代理到死 upstream → 502
        st, body, _ = get("/dead")
        check("/dead 无 balancer→502", st == 502, f"st={st}")

        # 按查询串选点
        st, body, _ = get("/pick?be=A")
        check("/pick?be=A→后端 A", st == 200 and "be=A" in body, f"st={st} body={body!r}")
        st, body, _ = get("/pick?be=B")
        check("/pick?be=B→后端 B", st == 200 and "be=B" in body, f"st={st} body={body!r}")
        st, body, _ = get("/pick")
        check("/pick 默认→后端 A", st == 200 and "be=A" in body, f"st={st} body={body!r}")

        # 按请求头选点（证明 balancer 阶段可读 ngx.req.get_headers）
        st, body, _ = get("/hdr", headers={"X-Backend": "B"})
        check("/hdr X-Backend:B→后端 B", st == 200 and "be=B" in body, f"st={st} body={body!r}")
        st, body, _ = get("/hdr")
        check("/hdr 默认→后端 A", st == 200 and "be=A" in body, f"st={st} body={body!r}")

        # set_timeouts 覆盖读超时：慢后端睡 3s，读超时 400ms → 应快速 502
        st, body, el = get("/to")
        check("/to 502(read timeout)", st == 502, f"st={st}")
        check("/to 挂钟≈400ms(<1.2s)证明 set_timeouts 生效", el < 1.2, f"elapsed={el:.2f}s")

        # 服务发现轮转：10 次请求应在 A/B 间精确均分（顺序请求，计数器 1..10 奇偶各半）
        ca = cb = 0
        for _ in range(10):
            st, body, _ = get("/rr")
            if "be=A" in body:
                ca += 1
            elif "be=B" in body:
                cb += 1
        check("/rr 全部命中(10)", ca + cb == 10, f"A={ca} B={cb}")
        check("/rr 精确均分 5/5", ca == 5 and cb == 5, f"A={ca} B={cb}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for s in (a, b, slow):
            s.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.balancer E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
