# -*- coding: utf-8 -*-
# include E2E —— 用真实流量证明 `include <glob>;` 在 Config::load 阶段把片段就地拼接：
#   · vhosts/*.conf 里的 location /inc_a、/inc_b 可被路由命中；
#   · 片段内部再 include 的 nested/d.conf（递归展开）给 /inc_c 加上响应头；
#   · 非 *.conf 的 notes.txt（含 /decoy）不被通配命中 → /decoy 应 404。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/include_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "include_demo", "main.conf")
HOST, PORT = "127.0.0.1", 18112
BASE = f"http://{HOST}:{PORT}"

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


def get(path, timeout=8):
    r = urllib.request.Request(BASE + path, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        resp = opener.open(r, timeout=timeout)
        return resp.status, resp.read().decode(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), {k.lower(): v for k, v in e.headers.items()}


def main():
    exe = find_binary()
    logf = open(os.path.join(ROOT, "conf", "include_demo", "out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18112 被占用？看 conf/include_demo/out.log）")

        st, body, _ = get("/inc_a")
        check("include 片段 vhosts/10-a.conf 的 /inc_a 命中", st == 200 and body == "A-from-include", f"st={st} body={body!r}")

        st, body, _ = get("/inc_b")
        check("include 片段 vhosts/20-b.conf 的 /inc_b 命中", st == 200 and body == "B-from-include", f"st={st} body={body!r}")

        st, body, hdrs = get("/inc_c")
        check("嵌套递归 include 生效（/inc_c 带 x-nested-include 头）",
              st == 200 and hdrs.get("x-nested-include") == "yes", f"st={st} hdr={hdrs.get('x-nested-include')!r}")

        st, _, _ = get("/decoy")
        check("非 *.conf 的 notes.txt 未被通配命中 → /decoy 404", st == 404, f"st={st}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== include E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
