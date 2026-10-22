# -*- coding: utf-8 -*-
# HTTP/2 serving E2E —— 用真实 h2 流量证明两条服务路径都可用。
# 本机 libcurl 不带 HTTP/2，故 h2 侧改用 Node 核心 http2（明文 h2c prior-knowledge
# 与 TLS ALPN 都支持），HTTP/1.1 共存侧继续用 curl。
#   * 明文 h2c（prior-knowledge）→ 协商到 HTTP/2
#   * TLS h2（ALPN）→ 协商到 HTTP/2
#   * 同一明文端口上 HTTP/1.1 → 仍是 1.1（前导未命中即回落 h1，共存）
#   * 单连接多路复用：并发多流都拿到 200
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/http2_e2e.py
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "http2.conf")
PROBE = os.path.join(HERE, "http2_check.js")
ACCESS_LOG = os.path.join(ROOT, "conf", "logs", "http2_access.log")

H2C_PORT = 18124
TLS_PORT = 18125

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


CURL = shutil.which("curl") or "curl"
NODE = shutil.which("node")


def curl(args, timeout=15):
    """返回 (returncode, stdout)。stdout 末尾是 |%{http_version}。"""
    try:
        out = subprocess.run(
            [CURL, "-sS", "--max-time", str(timeout), "-w", "|%{http_version}", *args],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return out.returncode, out.stdout, out.stderr
    except Exception as e:
        return 127, "", str(e)


def split_ver(stdout):
    if "|" in stdout:
        body, ver = stdout.rsplit("|", 1)
        return body, ver.strip()
    return stdout, ""


def wait_for_log(path, needle, timeout=5.0):
    """等 access_log 落盘（写线程是异步的），返回 (命中, 全文)。"""
    end = time.time() + timeout
    text = ""
    while time.time() < end:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            text = ""
        if needle in text:
            return True, text
        time.sleep(0.1)
    return False, text


def node_probe(url, mode, n=None, timeout=20):
    """跑 Node http2 探针，返回解析后的键值 dict。"""
    if not NODE:
        raise SystemExit("!! 需要 node（本机 curl 无 HTTP/2 支持）")
    cmd = [NODE, PROBE, url, mode]
    if n is not None:
        cmd.append(str(n))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return {"__err__": str(e)}
    kv = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("ERROR"):
            kv["__err__"] = line
        elif "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    if out.returncode != 0 and "__err__" not in kv:
        kv["__err__"] = (out.stderr or out.stdout).strip()
    return kv


def main():
    if not NODE:
        raise SystemExit("!! 需要 node 在 PATH 上")
    if not os.path.exists(os.path.join(ROOT, "certs_scenario", "server.pem")):
        raise SystemExit("!! 缺证书 certs_scenario/server.pem")

    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    try:
        os.remove(ACCESS_LOG)
    except FileNotFoundError:
        pass
    logf = open(os.path.join(ROOT, "logs", "http2_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        # 就绪：探明文 h1（不依赖 h2 客户端），curl 本地
        ready = False
        for _ in range(80):
            rc, so, _ = curl(["--http1.1", f"http://127.0.0.1:{H2C_PORT}/"])
            if rc == 0 and "h2-cleartext-ok" in so:
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18124/18125 被占用？看 logs/http2_out.log）")

        # 1) 明文 h2c prior-knowledge（Node 客户端只在服务端确实协商 h2 时才拿到 200）
        kv = node_probe(f"http://127.0.0.1:{H2C_PORT}/", "single")
        check("h2c prior-knowledge 请求成功", "STATUS" in kv, f"probe={kv}")
        check("h2c 响应状态 200", kv.get("STATUS") == "200", f"probe={kv}")
        check("h2c 响应体正确", "h2-cleartext-ok" in kv.get("BODY", ""), f"probe={kv}")

        # 2) TLS h2（ALPN 协商）
        kv = node_probe(f"https://localhost:{TLS_PORT}/", "single")
        check("TLS h2 请求成功", "STATUS" in kv, f"probe={kv}")
        check("TLS 响应状态 200", kv.get("STATUS") == "200", f"probe={kv}")
        check("TLS h2 响应体正确", "h2-tls-ok" in kv.get("BODY", ""), f"probe={kv}")

        # 2.5) $request_uri：h2 上没有请求行，必须是 :path（含 query），不能是绝对 URI。
        # 这是 `return 302 https://main$request_uri` 这类整站跳转正确性的前提。
        kv = node_probe(f"http://127.0.0.1:{H2C_PORT}/redir?x=1", "redirect")
        check(
            "h2c $request_uri 只有 path+query",
            kv.get("STATUS") == "302" and kv.get("LOCATION") == "https://dest.local/redir?x=1",
            f"probe={kv}",
        )
        kv = node_probe(f"https://localhost:{TLS_PORT}/redir?x=1", "redirect")
        check(
            "TLS h2 $request_uri 只有 path+query",
            kv.get("STATUS") == "302" and kv.get("LOCATION") == "https://dest.local/redir?x=1",
            f"probe={kv}",
        )
        rc, so, se = curl(["-i", "--http1.1", f"http://127.0.0.1:{H2C_PORT}/redir?x=1"])
        check(
            "HTTP/1.1 $request_uri 保持原样",
            rc == 0 and "location: https://dest.local/redir?x=1" in so.lower(),
            f"rc={rc} out={so!r} err={se}",
        )
        ok, logtext = wait_for_log(ACCESS_LOG, '"GET /redir?x=1 HTTP/2.0"')
        check("h2 access log 的 request 是 origin-form", ok, f"log={logtext[-500:]!r}")
        check(
            "access log 不含绝对 URI",
            "GET http://" not in logtext and "GET https://" not in logtext,
            f"log={logtext[-500:]!r}",
        )

        # 3) 同一明文端口 HTTP/1.1 共存（前导未命中回落 h1）
        rc, so, se = curl(["--http1.1", f"http://127.0.0.1:{H2C_PORT}/"])
        body, ver = split_ver(so)
        check("h2c 端口上 HTTP/1.1 仍可用", rc == 0 and ver == "1.1", f"rc={rc} ver={ver!r} err={se}")
        check("HTTP/1.1 响应体正确", "h2-cleartext-ok" in body, f"body={body!r}")

        # 4) 多路复用：单个 h2 连接上并发 3 个流
        kv = node_probe(f"http://127.0.0.1:{H2C_PORT}/", "streams", 3)
        check("h2 单连接多路复用 3 个流", kv.get("STREAMS") == "3", f"probe={kv}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== HTTP/2 serving E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
