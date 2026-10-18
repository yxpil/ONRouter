# -*- coding: utf-8 -*-
# ngx.var E2E —— 用真实 HTTP 流量证明 Lua 读/写 nginx 变量语义正确。
#   cargo build --release -p onrouter-server --bin onrouter && python tools/ngxvar_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "ngxvar_e2e.conf")
HOST, PORT = "127.0.0.1", 18154
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


def req(path, method="GET", headers=None):
    r = urllib.request.Request(BASE + path, method=method, headers=headers or {})
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


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "ngxvar_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if req("/echo")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18154 被占用？看 logs/ngxvar_e2e_err.log）")

        st, body = req("/echo?x=1&y=2", headers={"X-Test": "abc"})
        e = kv(body)
        check("/echo uri=/echo", e.get("uri") == "/echo", f"{e}")
        check("/echo request_uri 保留原始含 query", e.get("request_uri") == "/echo?x=1&y=2", f"{e}")
        check("/echo method=GET", e.get("method") == "GET", f"{e}")
        check("/echo args", e.get("args") == "x=1&y=2", f"{e}")
        check("/echo query_string 同 args", e.get("query_string") == "x=1&y=2", f"{e}")
        check("/echo is_args=?", e.get("is_args") == "?", f"{e}")
        check("/echo scheme=http", e.get("scheme") == "http", f"{e}")
        check("/echo server_port=18154", e.get("server_port") == "18154", f"{e}")
        check("/echo remote_addr=127.0.0.1", e.get("remote_addr") == "127.0.0.1", f"{e}")
        check("/echo host 含 127.0.0.1", "127.0.0.1" in e.get("host", ""), f"{e}")
        check("/echo http_x_test=abc", e.get("x_test") == "abc", f"{e}")
        check("/echo 未定义变量=nil", e.get("missing") == "nil", f"{e}")
        check("/echo status=200", e.get("status") == "200", f"{e}")

        st, body = req("/post", method="POST")
        p = kv(body)
        check("/post method=POST", p.get("method") == "POST", f"{p}")
        check("/post is_args 空", p.get("is_args") == "[]", f"{p}")
        check("/post args 空", p.get("args") == "[]", f"{p}")

        st, body = req("/seturi")
        s = kv(body)
        check("/seturi 写后读回 /final-target", s.get("rewritten") == "/final-target", f"{s}")

        st, body = req("/setstatus")
        check("/setstatus 真实 HTTP 码=418", st == 418, f"st={st} body={body!r}")
        check("/setstatus body=teapot", "teapot" in body, f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.var E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
