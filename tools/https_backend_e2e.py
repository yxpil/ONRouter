# -*- coding: utf-8 -*-
# https/wss 后端 E2E —— 用真实流量证明反向代理能连到**加密后端**：
#   1) HTTP GET 过 https 后端：proxy_ssl_verify on + 信任自签 CA + proxy_ssl_name localhost
#      → 真实 TLS 握手 + 证书链校验通过，后端确实被服务（proto=tls）。
#   2) HTTP POST 过 https 后端：请求体经 TLS 转发并被后端原样读回。
#   3) wss/Upgrade 隧道：客户端明文升级到网关，网关经 **TLS** 后端完成 101，
#      后端在 101 头后抢发一行（验证 prefix 透传），随后双向回显（验证隧道上下行）。
#   4) 负例 /bad/：proxy_ssl_verify on 却无 trusted cert → 建 TLS 配置失败 → 502（进程不崩）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/https_backend_e2e.py
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: F401 (unused, kept for parity)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "https_backend.conf")
CERT_DIR = os.path.join(ROOT, "certs_https")

BACKEND_PORT = 18443
GW_HOST, GW_PORT = "127.0.0.1", 18444
BASE = f"http://{GW_HOST}:{GW_PORT}"

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

results = []
tls_hits = {}
hit_lock = threading.Lock()


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


def http_request(path, method="GET", body=None, headers=None):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(BASE + path, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=10)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


# ----------------------------- 证书生成 -----------------------------
def gen_certs():
    ca_crt = os.path.join(CERT_DIR, "ca.crt")
    srv_crt = os.path.join(CERT_DIR, "server.crt")
    srv_key = os.path.join(CERT_DIR, "server.key")
    if all(os.path.exists(p) for p in (ca_crt, srv_crt, srv_key)):
        return  # 复用已生成的证书
    os.makedirs(CERT_DIR, exist_ok=True)

    def run(args):
        r = subprocess.run(["openssl", *args], cwd=CERT_DIR,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise SystemExit("!! openssl 失败:\n" + r.stdout.decode(errors="replace"))

    run(["req", "-x509", "-newkey", "rsa:2048", "-keyout", "ca.key", "-out", "ca.crt",
         "-days", "3650", "-nodes", "-subj", "/CN=ONRouter-Test-CA",
         "-addext", "basicConstraints=critical,CA:TRUE"])
    run(["req", "-newkey", "rsa:2048", "-keyout", "server.key", "-out", "server.csr",
         "-nodes", "-subj", "/CN=localhost"])
    with open(os.path.join(CERT_DIR, "server.ext"), "w") as f:
        f.write("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
    run(["x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
         "-CAcreateserial", "-out", "server.crt", "-days", "3650",
         "-extfile", "server.ext"])


def tls_record_count():
    with hit_lock:
        return sum(tls_hits.values())


# ------------------------- TLS 后端（线程）-------------------------
def backend_loop():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BACKEND_PORT))
    srv.listen(16)
    while True:
        raw, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(ctx, raw), daemon=True).start()


def read_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 64 * 1024:
            break
    sep = buf.find(b"\r\n\r\n")
    if sep < 0:
        return None, buf
    return buf[:sep], buf[sep + 4:]


def parse_head(head_bytes):
    lines = head_bytes.decode(errors="replace").split("\r\n")
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, headers


def handle_conn(ctx, raw):
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except Exception as e:
        print("!! 后端 TLS 握手失败:", e)
        raw.close()
        return
    try:
        head, rest = read_head(conn)
        if head is None:
            return
        method, path, headers = parse_head(head)
        is_upgrade = "upgrade" in headers and "websocket" in headers["upgrade"].lower()
        if is_upgrade:
            # 计算 Sec-WebSocket-Accept（RFC6455），原样回 101
            import hashlib
            import base64
            key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
            conn.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {accept}\r\n"
                 "\r\n").encode()
            )
            # 101 之后立刻抢发一行（测试网关的 prefix 透传）
            conn.sendall(b"HELLO-FROM-BACKEND\n")
            # 之后原样回显收到的每一个字节（透明隧道）
            conn.settimeout(5)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except socket.timeout:
                pass
            return

        # 普通 HTTPS：读 body，计数，回显
        cl = int(headers.get("content-length", "0") or 0)
        body = rest or b""
        while len(body) < cl:
            body += conn.recv(4096)
        with hit_lock:
            tls_hits[path] = tls_hits.get(path, 0) + 1
            n = tls_hits[path]
        text = f"HTTPS-BACKEND method={method} path={path} proto=tls count={n}"
        if method == "POST":
            text += f" body={body.decode(errors='replace')}"
        payload = (text + "\n").encode()
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "\r\n"
        )
        conn.sendall(head.encode() + payload)
    except Exception as e:
        print("!! 后端处理异常:", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------- WS 隧道测试客户端 -------------------------
def ws_tunnel_test():
    s = socket.create_connection((GW_HOST, GW_PORT), timeout=8)
    req = (
        "GET /wss/echo HTTP/1.1\r\n"
        f"Host: {GW_HOST}:{GW_PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    s.sendall(req.encode())
    # 单一滚动缓冲：101 头与后端抢发的 prefix 常常同批到达，不能丢弃、也不该为
    # 已在缓冲里的 marker 再阻塞等待（否则后端 echo 循环的 recv 超时会先关闭连接）。
    buf = bytearray()

    def pump(marker, timeout=6.0):
        mb = marker.encode()
        if mb in buf:
            return True
        end = time.time() + timeout
        while mb not in buf and time.time() < end:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
        return mb in buf

    pump("\r\n\r\n")
    head_s = bytes(buf).split(b"\r\n\r\n", 1)[0].decode(errors="replace").lower()
    ok101 = head_s.splitlines()[0].find(" 101 ") >= 0 if head_s else False
    check("wss 隧道：网关回 101 Switching Protocols", ok101, f"head={head_s[:80]!r}")
    check("wss 隧道：透传后端 Sec-WebSocket-Accept", "sec-websocket-accept" in head_s,
          f"head={head_s[:160]!r}")
    check("wss 隧道：101 后后端抢发的前导字节被透传",
          pump("HELLO-FROM-BACKEND"), f"got={bytes(buf)[-40:]!r}")
    token = "ping-9f2a\n"
    s.sendall(token.encode())
    check("wss 隧道：客户端→TLS后端→回显 双向贯通", pump("ping-9f2a"), f"got={bytes(buf)[-40:]!r}")
    s.close()


# ------------------------------- main -------------------------------
def main():
    exe = find_binary()
    gen_certs()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    threading.Thread(target=backend_loop, daemon=True).start()
    time.sleep(0.3)

    logf = open(os.path.join(ROOT, "logs", "https_backend_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if http_request("/ping")[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18444/18443 被占用？看 logs/https_backend_out.log）")

        # 1) HTTP GET 过 https 后端（verify on）
        before = tls_record_count()
        st, body = http_request("/sec/hello")
        check("/sec/hello 经 TLS 后端返回 200", st == 200, f"st={st} body={body!r}")
        check("后端确为 TLS（proto=tls）", "proto=tls" in body, f"body={body!r}")
        check("URI 前缀被正确替换（path=/hello）", "path=/hello" in body, f"body={body!r}")
        check("请求真的打了后端", tls_record_count() > before, f"hits={tls_hits}")

        # 2) HTTP POST 过 https 后端：请求体经 TLS 转发被后端读回
        st2, body2 = http_request("/sec/submit", method="POST", body="payload=xyz&n=7")
        check("/sec/submit POST 经 TLS 返回 200", st2 == 200, f"st={st2} body={body2!r}")
        check("POST 体经 TLS 完整转发并被后端读回", "body=payload=xyz&n=7" in body2, f"body={body2!r}")

        # 3) wss/Upgrade 隧道过 TLS 后端
        try:
            ws_tunnel_test()
        except Exception as e:
            check("wss 隧道测试执行", False, f"异常: {e}")

        # 4) 负例：verify on 无 trusted cert → 502，进程仍存活
        st3, _ = http_request("/bad/x")
        check("/bad/（verify on 无 CA）返回 502", st3 == 502, f"st={st3}")
        check("负例后网关仍存活（/ping=200）", http_request("/ping")[0] == 200)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== https/wss backend E2E: {passed}/{total} passed ====")
    print(f"     TLS 后端命中计数: {dict(tls_hits)}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
