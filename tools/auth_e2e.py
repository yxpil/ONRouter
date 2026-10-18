# -*- coding: utf-8 -*-
# auth_basic + allow/deny E2E —— 用真实 HTTP 流量证明 ACCESS 阶段的 IP 规则与基本认证生效：
#   * /private 无凭据 → 401 + WWW-Authenticate: Basic realm="Members Only"
#   * 错误口令 → 401；{SHA}/$apr1$/明文 三种存储各用正确口令 → 200
#   * /allow_localhost 本机连接命中 allow → 200；/deny_all → 403
#   * auth_basic off 显式关闭 → 200
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/auth_e2e.py
import base64
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "auth.conf")
HOST, PORT = "127.0.0.1", 18114
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


def basic(user, pw):
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return "Basic " + tok


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path, auth=None):
    r = urllib.request.Request(BASE + path, method="GET")
    if auth:
        r.add_header("Authorization", auth)
    try:
        resp = _opener.open(r, timeout=8)
        return resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def main():
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "auth_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/open")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18114 被占用？看 conf/logs/auth_err.log）")

        # ---- 对照组 ----
        st, body, _ = get("/open")
        check("/open 无需认证返回 200", st == 200 and body.strip() == "open", f"st={st} body={body!r}")

        # ---- auth_basic：缺失质询 ----
        st, body, hdrs = get("/private")
        wa = hdrs.get("WWW-Authenticate") or hdrs.get("www-authenticate") or ""
        check("/private 无凭据 → 401", st == 401, f"st={st}")
        check("401 带 WWW-Authenticate: Basic realm=\"Members Only\"",
              wa.startswith("Basic") and "Members Only" in wa, f"wa={wa!r}")

        # ---- 错误口令 ----
        st, body, _ = get("/private", basic("alice", "wrongpw"))
        check("/private 错误口令 → 401", st == 401, f"st={st}")
        st, body, _ = get("/private", basic("nobody", "secret"))
        check("/private 不存在的用户 → 401", st == 401, f"st={st}")

        # ---- 三种口令存储各用正确凭据放行 ----
        st, body, _ = get("/private", basic("alice", "secret"))
        check("/private {SHA} alice:secret → 200 且返回受保护内容",
              st == 200 and body.strip() == "secret-stuff", f"st={st} body={body!r}")
        st, body, _ = get("/private", basic("bob", "secret"))
        check("/private $apr1$ bob:secret → 200", st == 200 and body.strip() == "secret-stuff", f"st={st}")
        st, body, _ = get("/private", basic("carol", "plaintextpass"))
        check("/private 明文 carol → 200", st == 200, f"st={st}")
        st, body, _ = get("/private", basic("carol", "wrong"))
        check("/private 明文用户错误口令 → 401", st == 401, f"st={st}")

        # ---- auth_basic off 显式关闭 ----
        st, body, _ = get("/reopened")
        check("/reopened auth_basic off → 200 无需凭据", st == 200 and body.strip() == "reopened", f"st={st} body={body!r}")

        # ---- allow/deny ----
        st, body, _ = get("/allow_localhost")
        check("/allow_localhost 本机(127.0.0.1)命中 allow → 200",
              st == 200 and body.strip() == "from-localhost", f"st={st} body={body!r}")
        st, body, _ = get("/deny_all")
        check("/deny_all → 403（deny all 拦住本机）", st == 403, f"st={st}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== auth E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
