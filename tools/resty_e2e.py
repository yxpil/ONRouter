# -*- coding: utf-8 -*-
# Batch 4：resty.string + resty.lock 纯 Lua 模块 E2E —— 真实流量验证 require 加载、
# 摘要正确性，以及 resty.lock 在并发临界区下的互斥（计数精确，无丢更新）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/resty_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "resty_e2e.conf")
HOST, PORT = "127.0.0.1", 18143
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
        resp = _opener.open(r, timeout=15)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    m = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        if v.startswith(" "):
            v = v[1:]
        m[k.strip()] = v
    return m


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "resty_e2e_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/probe")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18143 被占用？看 logs/resty_e2e_err.log）")

        # 0) require 可用性
        st, body = get("/probe")
        pr = kv(body)
        check("/probe 200", st == 200, f"st={st}")
        check("require 是函数", pr.get("has_require") == "true", f"has_require={pr.get('has_require')}")
        check("require 'resty.string' 成功", pr.get("load_string") == "true", f"err={pr.get('err')}")
        check("require 'resty.lock' 成功", pr.get("load_lock") == "true", f"err2={pr.get('err2')}")

        # 1) resty.string 已知向量
        st, body = get("/str")
        s = kv(body)
        check("/str 200", st == 200, f"st={st}")
        check("to_hex('ABC')==414243", s.get("tohex") == "414243", f"tohex={s.get('tohex')}")
        check("sha256_hex('abc')",
              s.get("sha256") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              f"sha256={s.get('sha256')}")
        check("md5_hex('abc')", s.get("md5") == "900150983cd24fb0d6963f7d28e17f72",
              f"md5={s.get('md5')}")
        check("sha256_hex('')",
              s.get("sha256_empty") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              f"sha256_empty={s.get('sha256_empty')}")

        # 2) resty.lock 基本语义
        st, body = get("/lock_basic")
        lb = kv(body)
        check("/lock_basic 200", st == 200, f"st={st}")
        check("首次立即获得锁(elapsed=0)", lb.get("acquire") == "true" and lb.get("acq_elapsed0") == "true", f"lb={lb}")
        check("他人持有时超时返回 nil", lb.get("contend_nil") == "true", f"contend_nil={lb.get('contend_nil')}")
        check("超时错误=='timeout'", lb.get("contend_timeout") == "timeout", f"contend_timeout={lb.get('contend_timeout')}")
        check("unlock 成功", lb.get("unlocked") == "true", f"unlocked={lb.get('unlocked')}")
        check("解锁后可重新获取", lb.get("reacquire") == "true", f"reacquire={lb.get('reacquire')}")

        # 3) 锁过期自动释放：等待后获取，elapsed>0
        st, body = get("/lock_expiry")
        le = kv(body)
        check("/lock_expiry 200", st == 200, f"st={st}")
        check("过期锁可等待获取", le.get("acquired") == "true", f"le={le}")
        check("等待耗时>0(证明轮询)", le.get("waited") == "true", f"waited={le.get('waited')}")

        # 4) 并发临界区互斥：N 个并发请求，计数必须精确==N（否则说明丢更新）
        get("/reset")
        N = 12
        errs = []

        def worker():
            code, body = get("/lock_crit")
            if code != 200 or "done" not in body:
                errs.append((code, body.strip()))

        threads = [threading.Thread(target=worker) for _ in range(N)]
        t0 = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.time() - t0
        check("并发 /lock_crit 无错误", not errs, f"errs={errs[:3]}")

        st, body = get("/counter")
        c = kv(body)
        check(f"resty.lock 串行化：counter=={N}", c.get("counter") == str(N),
              f"counter={c.get('counter')} wall={wall:.2f}s")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== resty E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
