# -*- coding: utf-8 -*-
# ngx.shared.DICT 方法面补全 E2E —— 用真实流量证明 Batch 2 新增字典方法语义对齐 OpenResty。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/dict_api_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "dict_api.conf")
HOST, PORT = "127.0.0.1", 18132
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
        resp = _opener.open(r, timeout=8)
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
    logf = open(os.path.join(ROOT, "logs", "dict_api_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/basic")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18132 被占用？看 logs/dict_api_err.log）")

        st, body = get("/basic")
        b = kv(body)
        check("/basic 200", st == 200, f"st={st}")
        check("set_auto 返回 true", b.get("sa") == "true" and b.get("sa2") == "true", f"sa={b.get('sa')} sa2={b.get('sa2')}")
        check("key_present 命中/未命中", b.get("present") == "true" and b.get("missing") == "false", f"present={b.get('present')} missing={b.get('missing')}")
        check("len==num==2", b.get("len") == "2" and b.get("num") == "2", f"len={b.get('len')} num={b.get('num')}")
        check("size==值字节和(10)", b.get("size") == "10", f"size={b.get('size')}")

        st, body = get("/fadd")
        f = kv(body)
        check("/fadd 200", st == 200, f"st={st}")
        check("force_add 首次 true / 重复 false", f.get("fa1") == "true" and f.get("fa2") == "false", f"fa1={f.get('fa1')} fa2={f.get('fa2')}")
        check("force_add 不覆盖既有值", f.get("val") == "1", f"val={f.get('val')}")
        check("force_set 覆盖生效", f.get("fs") == "true" and f.get("val2") == "5", f"fs={f.get('fs')} val2={f.get('val2')}")

        st, body = get("/count")
        c = kv(body)
        check("/count 200", st == 200, f"st={st}")
        check("incr(1,init0)==1", c.get("i1") == "1", f"i1={c.get('i1')}")
        check("decr(3)==-2", c.get("d1") == "-2", f"d1={c.get('d1')}")
        check("incr(5)==3", c.get("i2") == "3", f"i2={c.get('i2')}")
        check("bump(+2)==5", c.get("b1") == "5", f"b1={c.get('b1')}")
        check("bump 缺失键→nil", c.get("bmissing") == "nil", f"bmissing={c.get('bmissing')}")

        st, body = get("/stale")
        s = kv(body)
        check("/stale 200", st == 200, f"st={st}")
        check("get_stale 存活值", s.get("v") == "v", f"v={s.get('v')}")
        check("get_stale stale==false", s.get("stale") == "false", f"stale={s.get('stale')}")

        st, body = get("/plus")
        p = kv(body)
        check("/plus 200", st == 200, f"st={st}")
        check("get_plus 值 42", p.get("pv") == "42", f"pv={p.get('pv')}")
        check("get_plus flags==0（无类型存储）", p.get("pflags") == "0", f"pflags={p.get('pflags')}")
        check("get2 值/stale/flags", p.get("g2v") == "42" and p.get("g2stale") == "false" and p.get("g2flags") == "0", f"g2={p}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== dict API E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
