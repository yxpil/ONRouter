# -*- coding: utf-8 -*-
# ngx.location.capture 子请求 E2E —— 用真实流量证明「完整管线」子请求：
#   * 捕获 Lua content 子请求（状态码 201 + 自定义响应头 + 响应体）
#   * 捕获 return 子请求
#   * 捕获带 query 的子请求，子请求内读回参数
#   * 捕获不存在的 location → 子请求 404
#   * 嵌套子请求（子请求里再发子请求）
#   * 自循环触发深度护栏（不死锁、逐级回传）
#   * 外部直接访问 internal location → 404（仅子请求可穿透 internal）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/subrequest_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "subrequest.conf")
HOST, PORT = "127.0.0.1", 18115
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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path, timeout=10):
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "subrequest_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/cap_lua")[0] in (200, 500):
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18115 被占用？看 conf/logs/subrequest_err.log）")

        # 1) 捕获 Lua content 子请求：status/body/header 全对齐
        st, body = get("/cap_lua")
        check("/cap_lua 外层 200", st == 200, f"st={st}")
        check("子请求状态码透传为 201", "status:201" in body, f"body={body!r}")
        check("子请求响应体透传 INNER-BODY", "INNER-BODY" in body, f"body={body!r}")
        check("子请求响应头 x-inner 透传", "hdr:yes" in body, f"body={body!r}")

        # 2) 捕获 return 子请求
        st, body = get("/cap_return")
        check("/cap_return 外层 200", st == 200, f"st={st}")
        check("return 子请求体透传 static-data", "static-data" in body, f"body={body!r}")
        check("return 子请求状态码 200", "status:200" in body, f"body={body!r}")

        # 3) 捕获带 query 的子请求，子请求内 get_uri_args 读回
        st, body = get("/cap_query")
        check("/cap_query 外层 200", st == 200, f"st={st}")
        check("子请求 query 参数透传 q=hello", "q=hello" in body, f"body={body!r}")

        # 4) 捕获不存在的 location → 子请求 404
        st, body = get("/cap_404")
        check("/cap_404 外层 200", st == 200, f"st={st}")
        check("缺失 location 子请求返回 404", "status:404" in body, f"body={body!r}")

        # 5) 嵌套子请求（子请求里再捕获）
        st, body = get("/cap_outer")
        check("/cap_outer 外层 200", st == 200, f"st={st}")
        check("嵌套：外层捕获到内层 200", "outer_status:200" in body, f"body={body!r}")
        check("嵌套：内层的 201 透传上来", "status:201" in body, f"body={body!r}")
        check("嵌套：INNER-BODY 贯穿两层", "INNER-BODY" in body, f"body={body!r}")

        # 6) 自循环触发深度护栏：不死锁，逐级回传，最深 0 → 上层 200
        st, body = get("/selfloop")
        check("/selfloop 深度护栏后仍返回 200（无死锁）", st == 200, f"st={st} body={body!r}")
        check("自循环子请求回传 child:200", "child:200" in body, f"body={body!r}")

        # 7) 对照组：外部直接访问 internal location → 404
        st, _ = get("/inner")
        check("外部直接访问 internal /inner → 404", st == 404, f"st={st}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.location.capture 子请求 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
