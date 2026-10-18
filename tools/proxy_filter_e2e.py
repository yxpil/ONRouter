# -*- coding: utf-8 -*-
# header_filter_by_lua + body_filter_by_lua 对代理响应生效 E2E —— 真实流量证明：
#   后端固定返回 "hello world"(text/plain + X-Backend: raw)，网关缓冲代理回传并跑过滤器。
#   /body 大写体、/hdr 改状态+响应头、/both 两者同时。对照 nginx：响应过滤器对 proxy 也生效。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_filter_e2e.py
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
CONF = os.path.join(ROOT, "conf", "proxy_filter_e2e.conf")
HOST, PORT = "127.0.0.1", 18162
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
        return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)


def make_backend(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello world"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Backend", "raw")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def hdr(h, name):
    for k, v in h.items():
        if k.lower() == name.lower():
            return v
    return None


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    be = make_backend(18163)

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "proxy_filter_out.log"), "wb")
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
            raise SystemExit("!! onrouter 未就绪（端口 18162 被占用？看 logs/proxy_filter_e2e_err.log）")

        check("/ping pong", get("/ping")[1].strip() == "pong")

        # /body : body_filter 大写代理响应体，且上游头保留
        st, body, h = get("/body")
        check("/body body_filter→'HELLO WORLD'", st == 200 and body == "HELLO WORLD", f"st={st} body={body!r}")
        check("/body 上游 X-Backend 透传保留", hdr(h, "X-Backend") == "raw", f"h={h}")
        check("/body Content-Length 重算正确", hdr(h, "Content-Length") == str(len(body)), f"cl={hdr(h,'Content-Length')} len={len(body)}")

        # /hdr : header_filter 改状态 + 加/改响应头
        st, body, h = get("/hdr")
        check("/hdr header_filter→状态203", st == 203, f"st={st}")
        check("/hdr X-Filtered=yes", hdr(h, "X-Filtered") == "yes", f"h={h}")
        check("/hdr content-type 改为 json", (hdr(h, "Content-Type") or "").lower().startswith("application/json"), f"ct={hdr(h,'Content-Type')}")

        # /both : 两个过滤器同时生效
        st, body, h = get("/both")
        check("/both 状态(上游200)", st == 200, f"st={st}")
        check("/both X-Filtered=yes", hdr(h, "X-Filtered") == "yes", f"h={h}")
        check("/both body_filter→'HELLO WORLD!'", body == "HELLO WORLD!", f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        be.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== proxy header/body filter E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
