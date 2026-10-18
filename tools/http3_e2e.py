# -*- coding: utf-8 -*-
# HTTP/3 (QUIC) serving E2E —— 用真实 QUIC/h3 流量证明 HTTP/3 服务真的可用。
# 本机 curl/Node 均无 HTTP/3，故用自研 quinn+h3 客户端探针 orr-h3check（与 ONRouter 同栈）：
#   * h3 单请求：STATUS=200 且 PROTO=HTTP/3 且 BODY 正确
#   * h3 较大响应体：逐帧 send_data 完整送达（按长度校验）
#   * h3 单连接多路复用：并发多流都拿到 200
#   * 同端口共存：TCP-TLS 上 HTTP/1.1（curl -k --http1.1）仍可用，且响应带 alt-svc: h3
#
#   cargo build --release -p onrouter-server && python tools/http3_e2e.py
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "http3.conf")
CERT = os.path.join(ROOT, "certs_scenario", "server.pem")

H3_PORT = 18127
# 用 localhost 作为 SNI：自签名证书 SAN 含 localhost（QUIC 强制校验服务器名），
# 单 vhost 场景下 :authority=localhost 会回落到默认 server（h3.local），路由不受影响。
SNI = "localhost"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_bin(name):
    for profile in ("release", "debug"):
        for ext in (".exe", ""):
            p = os.path.join(ROOT, "target", profile, name + ext)
            if os.path.exists(p):
                return p
    return None


CURL = shutil.which("curl") or "curl"


def curl(args, timeout=15):
    try:
        out = subprocess.run(
            [CURL, "-sS", "--max-time", str(timeout), *args],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return out.returncode, out.stdout, out.stderr
    except Exception as e:
        return 127, "", str(e)


def h3_probe(exe, path, mode, n=None, timeout=25):
    """跑 orr-h3check，返回解析后的键值 dict。"""
    cmd = [exe, f"127.0.0.1:{H3_PORT}", SNI, path, mode]
    if n is not None:
        cmd.append(str(n))
    env = dict(os.environ, ORR_H3_CERT=CERT)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             cwd=ROOT, env=env)
    except Exception as e:
        return {"__err__": str(e)}
    kv = {}
    for line in out.stdout.splitlines():
        line = line.rstrip("\n")
        if line.startswith("ERROR"):
            kv["__err__"] = line
        elif "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    if out.returncode != 0 and "__err__" not in kv:
        kv["__err__"] = (out.stderr or out.stdout).strip()
    return kv


def kill_orphans():
    """清掉残留的 onrouter 进程，避免占用 18127（教训：先杀孤儿再跑 E2E）。"""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq onrouter.exe"],
                             capture_output=True, text=True, timeout=10)
        if "onrouter.exe" in out.stdout:
            subprocess.run(["taskkill", "/IM", "onrouter.exe", "/F"],
                           capture_output=True, text=True, timeout=10)
            time.sleep(0.5)
    except Exception:
        pass


def main():
    if not os.path.exists(CERT):
        raise SystemExit("!! 缺证书 certs_scenario/server.pem")
    server = find_bin("onrouter")
    probe = find_bin("orr-h3check")
    if not server or not probe:
        raise SystemExit("!! 先构建：cargo build --release -p onrouter-server")

    kill_orphans()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "http3_out.log"), "wb")
    proc = subprocess.Popen([server, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        # 就绪：先用 TCP-TLS 上的 HTTP/1.1 探活（不依赖 h3 客户端）
        ready = False
        for _ in range(80):
            rc, so, _ = curl(["-k", "--http1.1", f"https://127.0.0.1:{H3_PORT}/"])
            if rc == 0 and "h3-tcp-fallback" in so:
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（18127 被占用？看 logs/http3_out.log）")

        # 1) h3 单请求
        kv = h3_probe(probe, "/hi", "single")
        check("HTTP/3 单请求成功", "STATUS" in kv, f"probe={kv}")
        check("HTTP/3 状态 200", kv.get("STATUS") == "200", f"probe={kv}")
        check("HTTP/3 协议版本为 3", kv.get("PROTO", "").startswith("HTTP/3"), f"probe={kv}")
        check("HTTP/3 响应体正确", "hello-h3" in kv.get("BODY", ""), f"probe={kv}")

        # 2) h3 较大响应体（逐帧 send_data 完整送达）
        kv = h3_probe(probe, "/big", "single")
        body = kv.get("BODY", "")
        check("HTTP/3 大响应体长度符合", len(body) >= 15000, f"len={len(body)} probe_err={kv.get('__err__')}")

        # 3) h3 单连接多路复用 5 流
        kv = h3_probe(probe, "/hi", "streams", 5)
        check("HTTP/3 多路复用 5 流", kv.get("STREAMS") == "5", f"probe={kv}")

        # 4) 同端口共存：TCP-TLS 上 HTTP/1.1 仍可用
        rc, so, se = curl(["-k", "--http1.1", "-D", "-", f"https://127.0.0.1:{H3_PORT}/"])
        check("h3 端口上 HTTP/1.1 仍可用", rc == 0 and "h3-tcp-fallback" in so, f"rc={rc} err={se}")
        check("TCP 响应广播 alt-svc: h3", "alt-svc: h3=" in so.lower(), f"headers={so[:400]!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== HTTP/3 serving E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
