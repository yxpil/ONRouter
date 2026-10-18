# -*- coding: utf-8 -*-
# ngx.re 扩展 + ngx.req 头改写 E2E —— 真实 HTTP 流量验证：
#   /re 逐条核对 gmatch/sub/gsub/回调/opt 的返回；
#   /hdr 核对 set_header(含多值)/clear_header 后 get_headers 读回；
#   /echo 让 rewrite_by_lua 改写的头经真实 proxy 转发，回显后端据收到的头证明生效。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/req_re_e2e.py
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
CONF = os.path.join(ROOT, "conf", "req_re_e2e.conf")
HOST, PORT = "127.0.0.1", 18160
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
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    d = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


# echo 后端：把收到的请求头以 name=value 逐行回显（小写归一，重复头逐行都打）
def make_echo(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            lines = []
            for k, v in self.headers.items():
                lines.append(f"{k.lower()}={v}")
            body = ("\n".join(lines) + "\n").encode()
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
    echo = make_echo(18161)

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "req_re_out.log"), "wb")
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
            raise SystemExit("!! onrouter 未就绪（端口 18160 被占用？看 logs/req_re_e2e_err.log）")

        check("/ping pong", get("/ping")[1].strip() == "pong")

        # ---- ngx.re ----
        st, body = get("/re")
        d = kv(body)
        check("/re gmatch 迭代 a1,b2,c3,", d.get("gmatch") == "a1,b2,c3,", f"got {d.get('gmatch')!r}")
        check("/re sub 仅首个→'X world foo/1'", d.get("sub") == "X world foo/1", f"got {d.get('sub')!r}")
        check("/re gsub 全替→'a_b_c/2'", d.get("gsub") == "a_b_c/2", f"got {d.get('gsub')!r}")
        check("/re 回调替换→'x[1]y[2]/2'", d.get("cb") == "x[1]y[2]/2", f"got {d.get('cb')!r}")
        check("/re opt 句柄复用→'*1*/2'", d.get("opt") == "*1*/2", f"got {d.get('opt')!r}")

        # ---- ngx.req.get_headers 读回改写 ----
        st, body = get("/hdr", headers={"User-Agent": "curl/probe"})
        d = kv(body)
        check("/hdr set_header→get_headers foo=bar", d.get("foo") == "bar", f"got {d.get('foo')!r}")
        check("/hdr clear_header→user-agent=nil", d.get("del") == "nil", f"got {d.get('del')!r}")

        # ---- rewrite_by_lua 改写的头经真实 proxy 转发到后端 ----
        st, body = get("/echo", headers={"x-drop": "gone", "User-Agent": "probe"})
        lines = [ln.split("=", 1) for ln in body.splitlines() if "=" in ln]
        names = [k.strip().lower() for k, _ in lines]
        vals = {}
        for k, v in lines:
            vals.setdefault(k.strip().lower(), []).append(v.strip())
        check("/echo 后端 200", st == 200, f"st={st}")
        check("/echo 新增头 X-Added 被转发", "x-added" in names and vals.get("x-added") == ["yes"], f"names={names}")
        check("/echo 多值 X-Multi v1,v2 均转发", sorted(vals.get("x-multi", [])) == ["v1", "v2"], f"x-multi={vals.get('x-multi')}")
        check("/echo clear_header 后 x-drop 未转发", "x-drop" not in names, f"names={names}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        echo.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.re + ngx.req headers E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
