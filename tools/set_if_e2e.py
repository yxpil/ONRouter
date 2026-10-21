# -*- coding: utf-8 -*-
# set/if E2E —— REWRITE 阶段 set / if 子集，全部用真实流量断言：
#   S1..S6 set 的基本语义（请求级、模板展开、多 token、覆盖内置名）
#   S7     命中 break 后同 location 的后续 set 不再执行
#   S8..S12 if 的条件形式（真值 / !x / = / ~ / !~ / ~*）
#   S13    if 里的 rewrite ... last 重新匹配 location
#   S14    已知差异：if 块里的 return 不许绕过 allow/deny
#   S15    启动日志里 set/if 不再是未知指令
#
#   S16..S19 server 级 set/if/rewrite（18371）：在 location 匹配之前生效，能改变
#            最终落到哪个 location
#   S20    server 级 if 里的 return 同样生效
#   S21    纯跳转 vhost（18372）：server 级 return 301 真的给出 301（过去被忽略→404）
#   S22    server 级 return 先于 location（18373）
#   S23    -t 不再对这些指令报"已被忽略"
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/set_if_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "set_if.conf")

GW_PORT = 18370
BASE = f"http://127.0.0.1:{GW_PORT}"

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, headers=None, method="GET", timeout=15):
    req = urllib.request.Request(BASE + path, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


SRV_PORT, REDIRECT_PORT, MAINT_PORT = 18371, 18372, 18373


def request_at(port, path, headers=None):
    """跨 vhost 的请求：server 级指令要换监听口才验得出差异。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=15)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def request_no_follow(port, path):
    """301 必须原样收到：默认 opener 会自己跟随并重呈 200，那就什么也验不出来。"""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    r = conn.getresponse()
    hs = dict(r.getheaders())
    body = r.read().decode(errors="replace")
    conn.close()
    return r.status, hs, body


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    out = open(os.path.join(ROOT, "logs", "setif_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)
        if not ready:
            check("网关启动", False, "见 logs/setif_out.log 与 conf/logs/setif_err.log")
            return 1

        # ---- S1..S6 set ----
        _, h, _ = request("/set")
        check("S1 set 写入的请求级变量可被 add_header 读到", hdr(h, "X-Tag") == "A",
              f"X-Tag={hdr(h, 'X-Tag')!r}")
        check("S2 set 的值里变量被展开（$arg_who 缺失→空串）", hdr(h, "X-Who") == "anon-",
              f"X-Who={hdr(h, 'X-Who')!r}")
        check("S3 set 的多 token 值按空格拼回", hdr(h, "X-Pair") == "a b",
              f"X-Pair={hdr(h, 'X-Pair')!r}")
        check("S4 set 覆盖同名内置变量只影响本请求的变量视图", hdr(h, "X-Uri") == "/not-real-uri",
              f"X-Uri={hdr(h, 'X-Uri')!r}")
        _, h2, b2 = request("/set?who=zoe")
        check("S5 展开跟随请求：?who=zoe → anon-zoe", hdr(h2, "X-Who") == "anon-zoe",
              f"X-Who={hdr(h2, 'X-Who')!r}")
        check("S6 location 仍按真实路径命中（set $uri 不改路由）", b2.strip() == "ok", f"body={b2!r}")

        _, hf, _ = request("/set?flip=1")
        check("S7 if 成立时后写的 set 覆盖先写的", hdr(hf, "X-Tag") == "B",
              f"X-Tag={hdr(hf, 'X-Tag')!r}")

        _, hs, _ = request("/stop")
        check("S8 rewrite ... break 收束 rewrite 阶段，后面的 set 不执行", hdr(hs, "X-Tag") == "A",
              f"X-Tag={hdr(hs, 'X-Tag')!r}")

        # ---- S9..S13 if 的条件形式 ----
        st, _, body = request("/guard?block=1")
        check("S9 if ($arg_block) 真值判断成立 → 403", st == 403 and body.strip() == "blocked",
              f"st={st} body={body!r}")
        st, _, body = request("/guard")
        check("S9 条件不成立时照常 200", st == 200 and body.strip() == "open",
              f"st={st} body={body!r}")

        st, _, body = request("/need-debug")
        check("S10 if (!$x)：变量缺失 → 404", st == 404 and body.strip() == "need-debug",
              f"st={st} body={body!r}")
        st, _, body = request("/need-debug?debug=1")
        check("S10 if (!$x)：有值 → 放行", st == 200 and body.strip() == "debug-on",
              f"st={st} body={body!r}")
        st, _, body = request("/need-debug?debug=")
        check("S10 空值仍然算假（?debug= 依旧 404）", st == 404, f"st={st}")

        st, _, body = request("/method", method="POST")
        check("S11 if ($request_method = POST) 命中 → 405", st == 405 and body.strip() == "no-post",
              f"st={st} body={body!r}")
        st, _, body = request("/method")
        check("S11 GET 不命中 → 200", st == 200 and body.strip() == "get-ok",
              f"st={st} body={body!r}")

        _, ha, _ = request("/agent", headers={"X-Kind": "api/v1"})
        check("S12 if (~ ^api) 区分大小写命中", hdr(ha, "X-Route") == "api",
              f"X-Route={hdr(ha, 'X-Route')!r}")
        _, hb, _ = request("/agent", headers={"X-Kind": "web"})
        check("S12 if (!~ ^api) 取反分支", hdr(hb, "X-Route") == "other",
              f"X-Route={hdr(hb, 'X-Route')!r}")
        _, hc, _ = request("/agent")
        check("S12 头缺失时左值是空串（!~ 仍成立）", hdr(hc, "X-Route") == "other",
              f"X-Route={hdr(hc, 'X-Route')!r}")

        st, _, body = request("/ci", headers={"X-Flag": "ON"})
        check("S13 ~* 忽略大小写", st == 200 and body.strip() == "ci-hit", f"body={body!r}")
        st, _, body = request("/ci", headers={"X-Flag": "off"})
        check("S13 ~* 不匹配时走默认分支", body.strip() == "ci-miss", f"body={body!r}")

        # ---- S14 if 里的 rewrite ... last ----
        st, _, body = request("/jump?go=yes")
        check("S14 if 命中后 rewrite ... last 重新匹配 location",
              st == 200 and body.strip() == "landed", f"st={st} body={body!r}")
        st, _, body = request("/jump?go=no")
        check("S14 = 右值不匹配时留在本 location", body.strip() == "stayed", f"body={body!r}")

        # ---- S15 已知差异：条件 return 不许绕过访问控制 ----
        st, _, _ = request("/acl")
        check("S15 allow/deny 正常拒绝", st == 403, f"st={st}")
        st, _, body = request("/acl?admin=1")
        check("S15 if 里的 return 不先于 allow/deny（与 nginx 不同的刻意差异）",
              st == 403 and "if-bypass" not in body, f"st={st} body={body!r}")

        err_path = os.path.join(ROOT, "conf", "logs", "setif_err.log")
        with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
            err = fh.read()
        check("错误日志里没有 panic/回溯",
              "panicked" not in err and "traceback" not in err.lower(), err[-300:])
        check("set/if 不再被报成未知指令",
              "未知指令 'set'" not in err and "未知指令 'if'" not in err, err[-300:])
        # ---- S16..S23 server 级 REWRITE 相位 ----
        _, h, b = request_at(SRV_PORT, "/echo")
        check("S16 server 级 set 的变量在 location 里可见", hdr(h, "X-Channel") == "grey",
              f"X-Channel={hdr(h, 'X-Channel')!r} body={b!r}")
        _, h, _ = request_at(SRV_PORT, "/echo?from=ctx")
        check("S17 server 级 set 一样展开变量（$arg_from）", hdr(h, "X-From") == "ctx",
              f"X-From={hdr(h, 'X-From')!r}")
        _, h, _ = request_at(SRV_PORT, "/echo", headers={"X-Grey": "1"})
        check("S18 server 级 if 覆盖 server 级 set", hdr(h, "X-Channel") == "blue",
              f"X-Channel={hdr(h, 'X-Channel')!r}")
        st, h, b = request_at(SRV_PORT, "/old/hop")
        check("S19 server 级 rewrite ... last 改变了选中的 location",
              st == 200 and b.strip() == "landed-hop" and hdr(h, "X-Rewrote") == "1",
              f"st={st} body={b!r} X-Rewrote={hdr(h, 'X-Rewrote')!r}")
        st, _, b = request_at(SRV_PORT, "/echo?kill=1")
        check("S20 server 级 if 里的 return 也生效（过去它和裸 return 一起被忽略）",
              st == 404 and b.strip() == "killed-at-server", f"st={st} body={b!r}")
        st, h, b = request_no_follow(REDIRECT_PORT, "/any/thing?x=1")
        check("S21 纯跳转 vhost 给出 301（过去这条被静默忽略 → 404）",
              st == 301 and hdr(h, "Location") == "https://example.com/any/thing?x=1",
              f"st={st} Location={hdr(h, 'Location')!r}")
        st, h, b = request_at(MAINT_PORT, "/")
        check("S22 server 级 return 先于 location 结束请求",
              st == 403 and b == "server-blocked:maintenance",
              f"st={st} body={b!r}")
        t_run = subprocess.run([exe, "-t", CONF], cwd=ROOT, capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
        tout = (t_run.stdout or "") + (t_run.stderr or "")
        check("S23 -t 不再把 server 级指令报成\"已被忽略\"",
              t_run.returncode == 0 and "已被忽略" not in tout, tout[-400:])

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        out.close()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== set/if E2E: {passed}/{len(results)} passed ====")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
