# -*- coding: utf-8 -*-
# cosocket TLS E2E —— 用真实 TLS echo 后端证明 sock:tlshandshake 能把明文 TCP cosocket
# 升级为 rustls 客户端 TLS 流，并在其上正常 send/receive/receiveany。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/sock_tls_e2e.py
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "sock_tls.conf")

ORR_HOST, ORR_PORT = "127.0.0.1", 18141
TLS_PORT = 18142
# 复用 https_backend 套件已生成的 localhost 证书；没有就现场自签一张（verify off，自签即可）。
CERT_DIR = os.path.join(ROOT, "certs_https")
CERT = os.path.join(CERT_DIR, "server.crt")
KEY = os.path.join(CERT_DIR, "server.key")

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    os.makedirs(CERT_DIR, exist_ok=True)

    def run(args):
        r = subprocess.run(["openssl", *args], cwd=CERT_DIR,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise SystemExit("!! openssl 失败:\n" + r.stdout.decode(errors="replace"))

    run(["req", "-x509", "-newkey", "rsa:2048", "-keyout", "server.key", "-out", "server.crt",
         "-days", "3650", "-nodes", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"])


def start_tls_echo(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)

    def handle(conn):
        try:
            conn.settimeout(15)
            buf = b""
            while b"\n" not in buf:
                d = conn.recv(4096)
                if not d:
                    break
                buf += d
            line = buf.split(b"\n", 1)[0]
            conn.sendall(b"TLS:" + line + b"\n")
            conn.sendall(b"EXTRA-TLS-DATA\n")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                break
            tc = ctx.wrap_socket(c, server_side=True)
            threading.Thread(target=handle, args=(tc,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def wait_ready(timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((ORR_HOST, ORR_PORT), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def http_get(path, timeout=20):
    s = socket.create_connection((ORR_HOST, ORR_PORT), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: socktls.local\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        buf += c
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, body.decode("utf-8", errors="replace")


def main():
    ensure_cert()
    srv = start_tls_echo(TLS_PORT)
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %d" % ORR_PORT)

        # 1) 握手 + 在 TLS 流上 receive(*l)
        st, body = http_get("/tls")
        nb = body.replace(" ", "")
        check("/tls tlshandshake 返回 1", st == 200 and "tls:1" in nb, f"body={body!r}")
        check("/tls 在 TLS 流上收到后端 TLS:secret", "data:TLS:secret" in nb, f"body={body!r}")

        # 2) TLS 流上 receiveany
        st, body = http_get("/tls_any")
        nb = body.replace(" ", "")
        check("/tls_any 在 TLS 流上 receiveany 取到数据", st == 200 and "any:TLS:burst" in nb, f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        try:
            srv.close()
        except Exception:
            pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== cosocket TLS E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
