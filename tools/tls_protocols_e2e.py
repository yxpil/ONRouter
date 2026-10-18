# -*- coding: utf-8 -*-
# ssl_protocols E2E —— 用真实 TLS 握手证明内置 rustls 后端能按 nginx 语义显式裁剪协议版本集合。
# 客户端用 Python ssl 把 min/max 钉死到单一版本，验证“启用的能协商、未启用的被握手拒绝”。
#   * 18128 ssl_protocols TLSv1.2 → 1.2 客户端拿到 only-1.2；1.3 客户端握手失败
#   * 18129 ssl_protocols TLSv1.3 → 1.3 客户端拿到 only-1.3；1.2 客户端握手失败
#   * 18130 默认               → 1.2 与 1.3 都能协商到 both
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/tls_protocols_e2e.py
import os
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "tls_protocols.conf")

P12 = 18128   # ssl_protocols TLSv1.2
P13 = 18129   # ssl_protocols TLSv1.3
PBOTH = 18130  # 默认（1.2+1.3）
HOST = "localhost"  # 证书 SAN 含 localhost

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


def kill_orphans():
    try:
        subprocess.run(["taskkill", "/F", "/IM", "onrouter.exe"],
                       capture_output=True, text=True)
    except Exception:
        pass
    time.sleep(0.3)


def make_ctx(version):
    """把 min/max 钉死到单一 TLS 版本；自签名证书 → 关闭校验。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tv = ssl.TLSVersion.TLSv1_2 if version == "1.2" else ssl.TLSVersion.TLSv1_3
    ctx.minimum_version = tv
    ctx.maximum_version = tv
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_get(port, version, timeout=8):
    """返回 dict：ok/err/ver/status/body。握手失败（版本不重叠）记 err。"""
    ctx = make_ctx(version)
    try:
        raw = socket.create_connection((HOST, port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=HOST)
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}
    try:
        ver = s.version()
        req = f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
    except Exception as e:
        return {"ok": False, "err": f"post-handshake {type(e).__name__}: {e}", "ver": ver}
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b" ", 2)[1].decode() if b" " in head else ""
    return {"ok": True, "ver": ver, "status": status, "body": body.decode("utf-8", "replace")}


def main():
    if not os.path.exists(os.path.join(ROOT, "certs_scenario", "server.pem")):
        raise SystemExit("!! 缺证书 certs_scenario/server.pem")

    exe = find_binary()
    kill_orphans()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "tls_protocols_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        # 就绪：默认端口 18130 用 1.2 客户端探通
        ready = False
        for _ in range(80):
            if tls_get(PBOTH, "1.2").get("ok"):
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18128/18129/18130 被占用？看 logs/tls_protocols_out.log）")

        # 1) 只开 TLS1.2：1.2 成功，1.3 被拒
        r = tls_get(P12, "1.2")
        check("only-1.2：TLS1.2 握手成功", r.get("ok"), f"probe={r}")
        check("only-1.2：协商到 TLSv1.2", r.get("ver") == "TLSv1.2", f"ver={r.get('ver')}")
        check("only-1.2：状态 200", r.get("status") == "200", f"status={r.get('status')}")
        check("only-1.2：响应体正确", "only-1.2" in r.get("body", ""), f"body={r.get('body')!r}")
        r = tls_get(P12, "1.3")
        check("only-1.2：TLS1.3-only 客户端被握手拒绝", not r.get("ok"), f"expected reject, got={r}")

        # 2) 只开 TLS1.3：1.3 成功，1.2 被拒
        r = tls_get(P13, "1.3")
        check("only-1.3：TLS1.3 握手成功", r.get("ok"), f"probe={r}")
        check("only-1.3：协商到 TLSv1.3", r.get("ver") == "TLSv1.3", f"ver={r.get('ver')}")
        check("only-1.3：响应体正确", "only-1.3" in r.get("body", ""), f"body={r.get('body')!r}")
        r = tls_get(P13, "1.2")
        check("only-1.3：TLS1.2-only 客户端被握手拒绝", not r.get("ok"), f"expected reject, got={r}")

        # 3) 默认（1.2+1.3）：两者都可
        r = tls_get(PBOTH, "1.2")
        check("默认：TLS1.2 可协商", r.get("ok") and r.get("ver") == "TLSv1.2", f"probe={r}")
        check("默认：TLS1.2 响应体正确", "both" in r.get("body", ""), f"body={r.get('body')!r}")
        r = tls_get(PBOTH, "1.3")
        check("默认：TLS1.3 可协商", r.get("ok") and r.get("ver") == "TLSv1.3", f"probe={r}")
        check("默认：TLS1.3 响应体正确", "both" in r.get("body", ""), f"body={r.get('body')!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ssl_protocols E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
