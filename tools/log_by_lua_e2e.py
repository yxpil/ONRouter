# -*- coding: utf-8 -*-
# log_by_lua E2E —— 用真实流量证明响应成形后 LOG 阶段会运行，能读到最终 ngx.status
# （含 5xx）与请求信息，并写入共享字典跨请求累计；同时证明 LOG 阶段不会回灌/篡改已发送响应。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/log_by_lua_e2e.py
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_log.conf")
HOST, PORT = "127.0.0.1", 18109
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
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def peek_map():
    st, body = get("/peek")
    m = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        m[k.strip()] = v.strip()
    return st, m


def main():
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "lua_log_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/peek")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18109 被占用？看 logs/lua_log_err.log）")

        get("/reset")

        # === 正常 200 路径：LOG 阶段累计 hits 并记录 status ===
        for _ in range(3):
            st, body = get("/hit")
            check(f"/hit 返回 200 且响应体不被 LOG 阶段篡改", st == 200 and body.strip() == "served", f"st={st} body={body!r}")
        st, m = peek_map()
        check("LOG 阶段把 3 次 /hit 计入 hits", m.get("hits") == "3", f"peek={m}")
        check("LOG 阶段读到最终 ngx.status=200", m.get("last_status") == "200", f"peek={m}")

        # === 5xx 路径：LOG 阶段看到非 200，且不篡改客户端收到的 503 ===
        st, body = get("/boom")
        check("/boom 客户端收到 503（LOG 阶段未回灌 resp）", st == 503 and "nope" in body, f"st={st} body={body!r}")
        st, m = peek_map()
        check("LOG 阶段计入 boom 命中", m.get("boom") == "1", f"peek={m}")
        check("LOG 阶段读到最终 ngx.status=503", m.get("boom_status") == "503", f"peek={m}")

        # === 真实流量证据：error_log 里出现 log_by_lua 写入的行 ===
        # conf 里 `error_log "logs/lua_log_err.log"` 相对 conf 目录解析 → ROOT/conf/logs/...
        time.sleep(0.3)
        err_path = os.path.join(ROOT, "conf", "logs", "lua_log_err.log")
        try:
            with open(err_path, "rb") as f:
                log = f.read().decode("utf-8", errors="ignore")
        except FileNotFoundError:
            log = ""
        check("ngx.log(ngx.INFO) 在 LOG 阶段真正落盘", "log_by_lua ran status= 200" in log, f"未找到，读取 {err_path}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== log_by_lua E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
