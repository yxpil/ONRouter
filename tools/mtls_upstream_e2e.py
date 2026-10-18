# -*- coding: utf-8 -*-
# mTLS 上游客户端证书 E2E —— 用真实 TLS 流量证明反向代理能向"要求客户端证书的后端"出示证书：
#   1) /mtls/hello  ：proxy_ssl_certificate(+key) → 双向 TLS 握手成功，后端回显它用 CA 校验通过的
#      客户端证书 CN（证明证书被真正呈现且通过验证），请求确实打到后端（count 递增）。
#   2) /mtls/ POST  ：带体的请求经 mTLS 通道完整转发并被后端读回。
#   3) /nomtls/x    ：同后端（CERT_REQUIRED），但网关**不附客户端证书** → 后端握手期即拒绝 →
#      网关 502。这条负例证明成功完全取决于客户端证书本身。
#   4) 负例后 /ping 仍 200 → 网关进程存活。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/mtls_upstream_e2e.py
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "mtls_upstream.conf")
CERT_DIR = os.path.join(ROOT, "certs_mtls")

BACKEND_PORT = 18454
GW_HOST, GW_PORT = "127.0.0.1", 18455
BASE = f"http://{GW_HOST}:{GW_PORT}"

CLIENT_CN = "onrouter-mtls-client"

results = []
tls_hits = {}
hit_lock = threading.Lock()
handshake_errors = []


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


# ----------------------------- 证书生成（CA / server / client）-----------------------------
def gen_certs():
    ca_crt = os.path.join(CERT_DIR, "ca.crt")
    srv_crt = os.path.join(CERT_DIR, "server.crt")
    srv_key = os.path.join(CERT_DIR, "server.key")
    cli_crt = os.path.join(CERT_DIR, "client.crt")
    cli_key = os.path.join(CERT_DIR, "client.key")
    if all(os.path.exists(p) for p in (ca_crt, srv_crt, srv_key, cli_crt, cli_key)):
        return
    os.makedirs(CERT_DIR, exist_ok=True)

    def run(args):
        r = subprocess.run(["openssl", *args], cwd=CERT_DIR,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise SystemExit("!! openssl 失败:\n" + r.stdout.decode(errors="replace"))

    # 根 CA
    run(["req", "-x509", "-newkey", "rsa:2048", "-keyout", "ca.key", "-out", "ca.crt",
         "-days", "3650", "-nodes", "-subj", "/CN=ONRouter-mTLS-CA",
         "-addext", "basicConstraints=critical,CA:TRUE"])
    # 服务端证书（SAN localhost + serverAuth），供网关 proxy_ssl_name/verify 校验
    run(["req", "-newkey", "rsa:2048", "-keyout", "server.key", "-out", "server.csr",
         "-nodes", "-subj", f"/CN=localhost"])
    with open(os.path.join(CERT_DIR, "server.ext"), "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    run(["x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
         "-CAcreateserial", "-out", "server.crt", "-days", "3650", "-extfile", "server.ext"])
    # 客户端证书（clientAuth），由网关向后端出示 —— 这是本套件的主角
    run(["req", "-newkey", "rsa:2048", "-keyout", "client.key", "-out", "client.csr",
         "-nodes", "-subj", f"/CN={CLIENT_CN}"])
    with open(os.path.join(CERT_DIR, "client.ext"), "w") as f:
        f.write("extendedKeyUsage=clientAuth\n")
    run(["x509", "-req", "-in", "client.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
         "-CAcreateserial", "-out", "client.crt", "-days", "3650", "-extfile", "client.ext"])


def peer_cn(cert_dict):
    """从 getpeercert() 的结构里取 commonName。"""
    for rdn in cert_dict.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


# ------------------------- TLS 后端（要求客户端证书）-------------------------
def backend_loop():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    ctx.load_verify_locations(cafile=os.path.join(CERT_DIR, "ca.crt"))
    # CERT_REQUIRED：不呈递（可校验通过的）客户端证书 → 握手直接失败。mTLS 的强制点。
    ctx.verify_mode = ssl.CERT_REQUIRED
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
    parts = (lines[0] if lines else "").split(" ")
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
        # /nomtls 会走到这里：客户端未出示证书 → 握手失败。记录下来作为负例证据。
        with hit_lock:
            handshake_errors.append(str(e))
        try:
            raw.close()
        except Exception:
            pass
        return
    try:
        head, rest = read_head(conn)
        if head is None:
            return
        method, path, headers = parse_head(head)
        cl = int(headers.get("content-length", "0") or 0)
        body = rest or b""
        while len(body) < cl:
            body += conn.recv(4096)
        peercert = conn.getpeercert()
        cn = peer_cn(peercert) if peercert else None
        verified = bool(peercert)
        with hit_lock:
            tls_hits[path] = tls_hits.get(path, 0) + 1
            n = tls_hits[path]
        text = (f"MTLS-BACKEND path={path} proto=tls client_verified={verified} "
                f"client_cn={cn} count={n}")
        if method == "POST":
            text += f" body={body.decode(errors='replace')}"
        payload = (text + "\n").encode()
        resp_head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "\r\n"
        )
        conn.sendall(resp_head.encode() + payload)
    except Exception as e:
        print("!! 后端处理异常:", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ------------------------------- main -------------------------------
def main():
    exe = find_binary()
    gen_certs()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    threading.Thread(target=backend_loop, daemon=True).start()
    time.sleep(0.3)

    logf = open(os.path.join(ROOT, "logs", "mtls_upstream_out.log"), "wb")
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
            raise SystemExit("!! onrouter 未就绪（端口 18455/18454 被占用？看 logs/mtls_upstream_out.log）")

        # 1) mTLS GET：握手成功 + 后端校验到的客户端证书 CN 被回显
        before = sum(tls_hits.values())
        st, body = http_request("/mtls/hello")
        check("/mtls/hello 经 mTLS 后端返回 200", st == 200, f"st={st} body={body!r}")
        check("后端确为 TLS（proto=tls）", "proto=tls" in body, f"body={body!r}")
        check("后端要求并校验通过客户端证书（client_verified=True）",
              "client_verified=True" in body, f"body={body!r}")
        check(f"后端看到的客户端证书 CN={CLIENT_CN}", f"client_cn={CLIENT_CN}" in body,
              f"body={body!r}")
        check("URI 前缀被正确替换（path=/hello）", "path=/hello" in body, f"body={body!r}")
        check("请求真的打了后端", sum(tls_hits.values()) > before, f"hits={tls_hits}")

        # 2) mTLS POST：请求体经双向 TLS 通道完整转发并被后端读回
        st2, body2 = http_request("/mtls/submit", method="POST", body="secret=abc&n=3")
        check("/mtls/submit POST 经 mTLS 返回 200", st2 == 200, f"st={st2} body={body2!r}")
        check("POST 体经 mTLS 完整转发并被后端读回", "body=secret=abc&n=3" in body2,
              f"body={body2!r}")

        # 3) 负例：同后端 CERT_REQUIRED，网关不附客户端证书 → 握手失败 → 502
        st3, _ = http_request("/nomtls/x")
        check("/nomtls/（无客户端证书）返回 502", st3 == 502, f"st={st3}")
        with hit_lock:
            got_hs_err = len(handshake_errors) > 0
        check("后端确实因缺客户端证书而拒绝握手（服务端记录到 TLS 失败）", got_hs_err,
              f"errors={handshake_errors!r}")

        # 4) 负例后网关仍存活
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
    print(f"\n==== mTLS 上游 E2E: {passed}/{total} passed ====")
    print(f"     TLS 后端命中计数: {dict(tls_hits)}")
    print(f"     握手失败(无证书)计数: {len(handshake_errors)}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
