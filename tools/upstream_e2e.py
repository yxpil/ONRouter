# -*- coding: utf-8 -*-
# $upstream_* 指标 E2E —— 真实代理流量证明 forward() 把后端地址/状态码/响应头耗时
# 记进 RequestCtx，log_by_lua 经 ngx.var.$upstream_* 读入共享字典，再用 /meta 回读断言：
#   * 成功：$upstream_addr=后端、$upstream_status=200、$upstream_header_time 为真实数值；
#   * 后端返 503：透传给客户端，且 $upstream_status 记录 503（对照 nginx）；
#   * 慢后端睡 0.6s：$upstream_header_time ≥ ~0.55，证明记录的是真实后端往返而非零。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/upstream_e2e.py
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "upstream_e2e.conf")
HOST, PORT = "127.0.0.1", 18156
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


def req(path, headers=None):
    r = urllib.request.Request(BASE + path, method="GET", headers=headers or {})
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def meta(id_):
    """回读 /meta：解析 addr=/status=/hdr="""
    st, body = req("/meta?id=" + id_)
    kv = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


# 后端 A：默认 200；路径含 err → 503（验证 upstream_status 透传）
def make_a(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            code = 503 if "err" in self.path else 200
            body = b"backend-A\n"
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# 慢后端：睡 0.6s 才回头，验证 upstream_header_time 记的是真实往返
def make_slow(port, sleep):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(sleep)
            body = b"backend-slow\n"
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
    a = make_a(18157)
    slow = make_slow(18158, 0.6)

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "upstream_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if req("/ping")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18156 被占用？看 logs/upstream_e2e_err.log）")

        check("/ping pong", req("/ping")[1].strip() == "pong")

        # 1) 成功代理：$upstream_addr / status=200 / header_time 数值
        st, body = req("/up", headers={"X-Req-Id": "ok1"})
        check("/up 代理后端 A→200", st == 200 and "backend-A" in body, f"st={st} body={body!r}")
        time.sleep(0.3)  # 等 log 阶段落字典
        kv = meta("ok1")
        check("$upstream_addr=127.0.0.1:18157", kv.get("addr") == "127.0.0.1:18157", f"addr={kv.get('addr')!r}")
        check("$upstream_status=200", kv.get("status") == "200", f"status={kv.get('status')!r}")
        check("$upstream_header_time 是数值", re.fullmatch(r"\d+\.\d+", kv.get("hdr", "")) is not None, f"hdr={kv.get('hdr')!r}")

        # 2) 后端 503：透传 + upstream_status 记录 503
        st, _ = req("/up?err=1", headers={"X-Req-Id": "e1"})
        check("/up?err=1 透传后端 503", st == 503, f"st={st}")
        time.sleep(0.3)
        kv = meta("e1")
        check("$upstream_status=503(失败也记状态)", kv.get("status") == "503", f"status={kv.get('status')!r}")

        # 3) 慢后端：header_time ≥ 0.55（真实往返，而非 0）
        st, body = req("/upslow", headers={"X-Req-Id": "s1"})
        check("/upslow 代理慢后端→200", st == 200 and "backend-slow" in body, f"st={st}")
        time.sleep(0.3)
        kv = meta("s1")
        check("$upstream_addr=127.0.0.1:18158", kv.get("addr") == "127.0.0.1:18158", f"addr={kv.get('addr')!r}")
        hdr = float(kv.get("hdr", "0") or 0)
        check("$upstream_header_time≥0.55(真实往返)", hdr >= 0.55, f"hdr={hdr}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for s in (a, slow):
            s.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== $upstream_* metrics E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
