# -*- coding: utf-8 -*-
# ngx.thread.* 轻量级线程 E2E —— 用真实 HTTP 流量证明 spawn/wait/yield/kill 语义对齐 ngx_lua，
# 并用挂钟时间证明同一 VM 内多条 light thread 真并发交错。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/thread_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "thread_e2e.conf")
HOST, PORT = "127.0.0.1", 18144
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
        resp = _opener.open(r, timeout=10)
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
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "thread_e2e_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if get("/basic")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18144 被占用？看 logs/thread_e2e_err.log）")

        st, body = get("/basic")
        b = kv(body)
        check("/basic 200", st == 200, f"st={st}")
        check("单线程 wait ok=true", b.get("ok") == "true", f"ok={b.get('ok')}")
        check("多返回值 a,b,c", b.get("a") == "x" and b.get("b") == "y" and b.get("c") == "123", f"{b}")

        st, body = get("/multi")
        m = kv(body)
        check("/multi 200", st == 200, f"st={st}")
        check("顺序 wait 求和==6", m.get("sum") == "6", f"sum={m.get('sum')}")
        check("三次 wait 全 ok", m.get("allok") == "true", f"allok={m.get('allok')}")

        st, body = get("/waitany")
        w = kv(body)
        check("/waitany 200", st == 200, f"st={st}")
        check("wait-any 返回快线程", w.get("who") == "fast" and w.get("ok") == "true", f"{w}")

        st, body = get("/error")
        e = kv(body)
        check("/error 200", st == 200, f"st={st}")
        check("子线程错误 ok=false", e.get("ok") == "false", f"ok={e.get('ok')}")
        check("错误消息含 kaboom", e.get("has_err") == "true", f"has_err={e.get('has_err')}")

        st, body = get("/kill")
        k = kv(body)
        check("/kill 200", st == 200, f"st={st}")
        check("kill 后线程副作用未发生", k.get("ran") == "nil", f"ran={k.get('ran')}")

        st, body = get("/killed_wait")
        kw = kv(body)
        check("/killed_wait 200", st == 200, f"st={st}")
        check("wait 被杀线程 ok=false", kw.get("ok") == "false", f"ok={kw.get('ok')}")
        check("被杀线程 err=thread killed", kw.get("err") == "thread killed", f"err={kw.get('err')}")

        st, body = get("/conc")
        c = kv(body)
        check("/conc 200", st == 200, f"st={st}")
        check("4 线程结果求和==10", c.get("acc") == "10", f"acc={c.get('acc')}")
        check("挂钟时间证明真并发(<1.0s)", c.get("concurrent") == "true", f"elapsed={c.get('elapsed')}")

        st, body = get("/yield")
        y = kv(body)
        check("/yield 200", st == 200, f"st={st}")
        check("yield 交错调度", y.get("interleaved") == "true", f"seq={y.get('seq')}")
        check("两线程各 3 步共 6 次", len(y.get("seq", "")) == 6, f"seq={y.get('seq')}")

        st, body = get("/badwait")
        bw = kv(body)
        check("/badwait 200", st == 200, f"st={st}")
        check("非线程对象 wait 返回 nil,err", bw.get("ok") == "nil" and bw.get("err") == "true", f"{bw}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.thread E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
