# -*- coding: utf-8 -*-
# L4 stream{} + ssl_preread E2E —— 用真实 TCP/TLS 流量证明四层代理端到端可用：
#   1) ssl_preread 解析 ClientHello SNI，精确匹配路由到命名 upstream（alpha.test → 18231）
#   2) sni_match "*.wild.test" 通配：恰好一级子域命中（foo.wild.test → 18233）
#   3) 通配不误伤：裸域 wild.test / 两级 a.b.wild.test → 回落默认（18234）
#   4) SNI 完全未命中 other.test → 回落 proxy_pass 默认（18234）
#   5) 字节透明：整条 TLS 握手穿过隧道成功（能读到后端握手后发的一行身份）
#   6) 无 preread 的纯四层 proxy_pass：TCP 原样接线（18240 → echo 18241）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/stream_ssl_preread_e2e.py
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "stream_ssl_preread_e2e.conf")
CERT_DIR = os.path.join(ROOT, "certs_stream")

# 网关
GW_PRE = ("127.0.0.1", 18230)   # ssl_preread 路由
GW_PLAIN = ("127.0.0.1", 18240)  # 纯四层转发

# 后端
BE_ALPHA = 18231   # TLS，握手后回 "BACKEND=alpha"
BE_WILD = 18233    # TLS，握手后回 "BACKEND=wild"
BE_DEFAULT = 18234  # TLS，握手后回 "BACKEND=default"
BE_ECHO = 18241    # TCP，回显 "ECHO:<line>"

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


# ----------------------------- 证书（一次性自签，客户端不校验）-----------------------------
def gen_cert():
    crt = os.path.join(CERT_DIR, "server.crt")
    key = os.path.join(CERT_DIR, "server.key")
    if os.path.exists(crt) and os.path.exists(key):
        return
    os.makedirs(CERT_DIR, exist_ok=True)
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "server.key",
         "-out", "server.crt", "-days", "3650", "-nodes", "-subj", "/CN=localhost"],
        cwd=CERT_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        raise SystemExit("!! openssl 失败:\n" + r.stdout.decode(errors="replace"))


def server_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# --------------------------- TLS 身份后端（握手后发一行即关）---------------------------
def tls_id_backend(port, identity):
    ctx = server_ctx()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def loop():
        while True:
            try:
                raw, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=hello, args=(ctx, raw, identity), daemon=True).start()

    def hello(ctx_, raw, ident):
        try:
            c = ctx_.wrap_socket(raw, server_side=True)
            c.sendall(f"BACKEND={ident}\n".encode())
            c.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                raw.close()

    threading.Thread(target=loop, daemon=True).start()


# --------------------------- 纯 TCP echo 后端 ---------------------------
def echo_backend(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    def serve(c):
        try:
            c.settimeout(5)
            buf = b""
            while b"\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            line = buf.split(b"\n", 1)[0].decode(errors="replace")
            c.sendall(f"ECHO:{line}\n".encode())
        except Exception:
            pass
        finally:
            c.close()

    threading.Thread(target=loop, daemon=True).start()


# --------------------------- 客户端探测 ---------------------------
def tls_probe(addr, sni):
    """经网关做完整 TLS 握手，读回后端身份行。返回 'BACKEND=x' 或抛异常。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(addr, timeout=10)
    try:
        c = ctx.wrap_socket(raw, server_hostname=sni)
        c.settimeout(10)
        line = b""
        while not line.endswith(b"\n"):
            d = c.recv(4096)
            if not d:
                break
            line += d
        return line.decode(errors="replace").strip()
    finally:
        try:
            c.close()
        except Exception:
            raw.close()


def tcp_probe(addr, payload):
    c = socket.create_connection(addr, timeout=10)
    try:
        c.settimeout(10)
        c.sendall(payload.encode())
        buf = b""
        while b"\n" not in buf:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        return buf.decode(errors="replace").strip()
    finally:
        c.close()


def wait_ready(addr, tries=100):
    for _ in range(tries):
        try:
            s = socket.create_connection(addr, timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    exe = find_binary()
    gen_cert()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    tls_id_backend(BE_ALPHA, "alpha")
    tls_id_backend(BE_WILD, "wild")
    tls_id_backend(BE_DEFAULT, "default")
    echo_backend(BE_ECHO)

    logf = open(os.path.join(ROOT, "logs", "stream_e2e_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not (wait_ready(GW_PRE) and wait_ready(GW_PLAIN)):
            raise SystemExit("!! 网关 stream 监听未就绪（18230/18240 被占用？看 logs/stream_e2e_out.log）")

        # 1) 精确 SNI → 命名 upstream alpha
        r = tls_probe(GW_PRE, "alpha.test")
        check("精确 SNI alpha.test → 后端 alpha", r == "BACKEND=alpha", f"got={r!r}")

        # 2) 通配 *.wild.test 命中一级子域 → 后端 wild
        r = tls_probe(GW_PRE, "foo.wild.test")
        check("通配 *.wild.test 命中 foo.wild.test → 后端 wild", r == "BACKEND=wild", f"got={r!r}")

        # 3a) 裸域不匹配通配 → 回落默认
        r = tls_probe(GW_PRE, "wild.test")
        check("裸域 wild.test 不匹配通配 → 默认后端", r == "BACKEND=default", f"got={r!r}")

        # 3b) 两级子域不匹配通配 → 回落默认
        r = tls_probe(GW_PRE, "a.b.wild.test")
        check("两级 a.b.wild.test 不匹配通配 → 默认后端", r == "BACKEND=default", f"got={r!r}")

        # 4) 完全未命中 → 回落 proxy_pass 默认
        r = tls_probe(GW_PRE, "other.test")
        check("未命中 other.test → 默认后端", r == "BACKEND=default", f"got={r!r}")

        # 5) 纯四层 proxy_pass（无 preread）：字节透明回显
        r = tcp_probe(GW_PLAIN, "PING123\n")
        check("纯四层 TCP 回显", r == "ECHO:PING123", f"got={r!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== stream/ssl_preread E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
