# -*- coding: utf-8 -*-
# Protocol matrix E2E: one ONRouter process serves every client-facing protocol
# on real sockets, and the access log proves which protocol the gateway decoded.
# Author: yxpil
#
#   HTTP/1.0 plaintext + TLS : one-shot close and Connection: keep-alive, plus a
#                              request body; nothing here may fall back to chunked
#   HTTP/1.1 plaintext + TLS : two requests on one keep-alive connection
#   HTTP/2 h2c               : Node core http2, prior knowledge, 8 concurrent streams
#   HTTP/2 TLS               : Node core http2 over ALPN h2
#   HTTP/3                   : orr-h3check (quinn+h3), single, large body, 5 streams
#   ws / wss                 : RFC6455 101 + text/binary/ping/close frames through
#                              the gateway to a real node WebSocket backend
#
#   cargo build --release -p onrouter-server && python tools/protocol_matrix_e2e.py
import base64
import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "protocol_matrix.conf")
CERT = os.path.join(ROOT, "certs_scenario", "server.pem")
H2_PROBE = os.path.join(HERE, "http2_check.js")
WS_BACKEND = os.path.join(HERE, "ws_backend.js")
ACCESS_LOG = os.path.join(ROOT, "conf", "logs", "protocol_matrix_access.log")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "protocol_matrix_err.log")

PLAIN, TLS, QUIC, WS_BACKEND_PORT = 18570, 18571, 18572, 18573
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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


def wait_tcp(port, timeout=12.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


# ------------------------------- raw HTTP -------------------------------
def recv_head(sock, buf=b"", timeout=6.0):
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in buf:
        d = sock.recv(4096)
        if not d:
            raise EOFError("closed before headers: " + buf[:120].decode("latin1"))
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    text = head.decode("latin1")
    lines = text.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers, rest


def recv_body(sock, head, rest, timeout=6.0):
    sock.settimeout(timeout)
    n = int(head.get("content-length", "0") or 0)
    while len(rest) < n:
        d = sock.recv(4096)
        if not d:
            break
        rest += d
    return rest[:n], rest[n:]


def recv_tail_until_close(sock, timeout=6.0):
    """Read whatever is left; True means the peer closed the connection."""
    sock.settimeout(timeout)
    try:
        while True:
            d = sock.recv(4096)
            if not d:
                return True, b""
    except socket.timeout:
        return False, b""


def tls_connect(port, sni="localhost"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=8)
    return ctx.wrap_socket(raw, server_hostname=sni)


def http10(port, host, path="/", body=None, tls=False):
    s = tls_connect(port) if tls else socket.create_connection(("127.0.0.1", port), timeout=8)
    method = "POST" if body is not None else "GET"
    extra = ""
    if body is not None:
        extra += f"Content-Length: {len(body)}\r\n"
    req = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n{extra}\r\n"
    s.sendall(req.encode() + (body or b""))
    head, headers, rest = recv_head(s)
    data, rest = recv_body(s, headers, rest)
    closed, tail = recv_tail_until_close(s)
    s.close()
    return head, headers, data, closed, tail


def http11_two(port, host, tls=False):
    s = tls_connect(port) if tls else socket.create_connection(("127.0.0.1", port), timeout=8)
    first = []
    buf = b""
    for _ in range(2):
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        head, headers, buf = recv_head(s, buf)
        data, buf = recv_body(s, headers, buf)
        first.append((head, headers, data))
    s.close()
    return first


# ------------------------------- RFC6455 -------------------------------
def ws_handshake(port, host, tls=False):
    s = tls_connect(port) if tls else socket.create_connection(("127.0.0.1", port), timeout=8)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        "GET /ws HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    line, headers, rest = recv_head(s)
    expect = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    return s, rest, line, headers, expect


def ws_frame(payload, opcode=0x1):
    data = payload.encode() if isinstance(payload, str) else payload
    mask = os.urandom(4)
    h = bytes([0x80 | opcode])
    n = len(data)
    if n < 126:
        h += bytes([0x80 | n])
    elif n < 65536:
        h += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:
        h += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    return h + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def ws_recv(sock, buf, timeout=8.0):
    sock.settimeout(timeout)

    def need(k):
        nonlocal buf
        while len(buf) < k:
            d = sock.recv(65536)
            if not d:
                raise EOFError("ws closed")
            buf += d

    need(2)
    b0, b1 = buf[0], buf[1]
    ln, off = b1 & 0x7F, 2
    if ln == 126:
        need(4)
        ln = int.from_bytes(buf[2:4], "big")
        off = 4
    elif ln == 127:
        need(10)
        ln = int.from_bytes(buf[2:10], "big")
        off = 10
    need(off + ln)
    return b0 & 0x0F, buf[off:off + ln], buf[off + ln:]


# ------------------------------- probes -------------------------------
def h2_probe(url, mode="single", n=3):
    out = subprocess.run(
        ["node", H2_PROBE, url, mode, str(n)],
        capture_output=True, text=True, timeout=30, cwd=ROOT,
    )
    kv = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    if out.returncode != 0 and "ERROR" not in kv:
        kv["ERROR"] = (out.stderr or out.stdout).strip()
    return kv


def h3_probe(exe, path, mode="single", n=None, attempts=3):
    cmd = [exe, f"127.0.0.1:{QUIC}", "localhost", path, mode]
    if n is not None:
        cmd.append(str(n))
    env = dict(os.environ, ORR_H3_CERT=CERT)
    kv = {}
    for _ in range(attempts):
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=ROOT, env=env)
        kv = {}
        for line in out.stdout.splitlines():
            if line.startswith("ERROR"):
                kv["ERROR"] = line
            elif "=" in line:
                k, v = line.split("=", 1)
                kv[k] = v
        if out.returncode != 0 and "ERROR" not in kv:
            kv["ERROR"] = (out.stderr or out.stdout).strip()
        if kv.get("STATUS") or kv.get("STREAMS"):
            return kv
        time.sleep(0.3)
    return kv


def log_wait(needles, timeout=8.0):
    """Poll the access log until every needle appears; return the text."""
    end = time.time() + timeout
    text = ""
    while time.time() < end:
        try:
            with open(ACCESS_LOG, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            text = ""
        if all(n in text for n in needles):
            return text
        time.sleep(0.2)
    return text


def main():
    if not os.path.exists(CERT):
        raise SystemExit("!! missing certs_scenario/server.pem")
    server = find_bin("onrouter")
    if not server:
        raise SystemExit("!! build first: cargo build --release -p onrouter-server")
    h3check = find_bin("orr-h3check")
    if not h3check:
        raise SystemExit("!! build first: cargo build --release -p onrouter-server (orr-h3check)")
    node = shutil.which("node")
    if not node:
        raise SystemExit("!! node is required (h2 client and ws backend)")

    for p in (PLAIN, TLS, QUIC, WS_BACKEND_PORT):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            raise SystemExit(f"!! port {p} is already in use; stop the stale process first")
        finally:
            s.close()
    # QUIC binds UDP, which the TCP preflight above cannot see.
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", QUIC))
    except OSError:
        raise SystemExit(f"!! UDP port {QUIC} is already in use; stop the stale h3 listener first")
    finally:
        u.close()

    for p in (ACCESS_LOG, ERR_LOG):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    ws_log = open(os.path.join(ROOT, "logs", "protocol_matrix_ws.log"), "wb")
    gw_log = open(os.path.join(ROOT, "logs", "protocol_matrix_out.log"), "wb")
    ws = subprocess.Popen(["node", WS_BACKEND, str(WS_BACKEND_PORT)], cwd=ROOT,
                          stdout=ws_log, stderr=subprocess.STDOUT)
    gw = subprocess.Popen([server, CONF], cwd=ROOT, stdout=gw_log, stderr=subprocess.STDOUT)
    try:
        if not wait_tcp(WS_BACKEND_PORT) or not wait_tcp(PLAIN) or not wait_tcp(TLS) or not wait_tcp(QUIC):
            time.sleep(0.5)
            err = ""
            try:
                with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
                    err = f.read()[-1200:]
            except FileNotFoundError:
                pass
            raise SystemExit(f"!! gateway/backend not ready; error log:\n{err}")

        # ---------------- HTTP/1.0 ----------------
        head, hdrs, body, closed, _tail = http10(PLAIN, "proto.local")
        check("HTTP/1.0 plaintext: status line is 1.0 + 200",
              head.startswith("HTTP/1.0 200"), head)
        check("HTTP/1.0 plaintext: body served", body == b"plain-ok\n", f"body={body!r}")
        check("HTTP/1.0 plaintext: no chunked encoding",
              "transfer-encoding" not in hdrs, f"headers={hdrs}")
        check("HTTP/1.0 plaintext: connection closes by default", closed)

        nonce = b"hello world"
        head, hdrs, body, _c, _t = http10(PLAIN, "proto.local", path="/body", body=nonce)
        check("HTTP/1.0 POST: body length reaches the handler",
              body.strip() == f"POST:{len(nonce)}".encode(), f"body={body!r}")

        s = socket.create_connection(("127.0.0.1", PLAIN), timeout=8)
        s.sendall(b"GET / HTTP/1.0\r\nHost: proto.local\r\nConnection: keep-alive\r\n\r\n")
        h1, hh1, rest = recv_head(s)
        b1, rest = recv_body(s, hh1, rest)
        s.sendall(b"GET / HTTP/1.0\r\nHost: proto.local\r\nConnection: keep-alive\r\n\r\n")
        h2, hh2, rest = recv_head(s, rest)
        b2, rest = recv_body(s, hh2, rest)
        s.close()
        check("HTTP/1.0 keep-alive: two requests on one connection",
              h1.startswith("HTTP/1.0 200") and h2.startswith("HTTP/1.0 200")
              and b1 == b2 == b"plain-ok\n" and "keep-alive" in hh1.get("connection", ""),
              f"h1={h1} h2={h2} hdrs={hh1}")

        head, hdrs, body, closed, _t = http10(TLS, "proto-tls.local", tls=True)
        check("HTTP/1.0 over TLS: status + body",
              head.startswith("HTTP/1.0 200") and body == b"tls-ok\n", f"head={head} body={body!r}")
        check("HTTP/1.0 over TLS: connection closes without chunked",
              closed and "transfer-encoding" not in hdrs, f"closed={closed} headers={hdrs}")

        # ---------------- HTTP/1.1 ----------------
        pair = http11_two(PLAIN, "proto.local")
        check("HTTP/1.1 plaintext: two keep-alive requests",
              all(h.startswith("HTTP/1.1 200") and b == b"plain-ok\n" for h, _hd, b in pair),
              f"pair={[(h, b) for h, _hd, b in pair]}")
        pair = http11_two(TLS, "proto-tls.local", tls=True)
        check("HTTP/1.1 over TLS: two keep-alive requests",
              all(h.startswith("HTTP/1.1 200") and b == b"tls-ok\n" for h, _hd, b in pair),
              f"pair={[(h, b) for h, _hd, b in pair]}")

        # ---------------- HTTP/2 ----------------
        kv = h2_probe(f"http://127.0.0.1:{PLAIN}", "single")
        check("HTTP/2 h2c: 200 + body", kv.get("STATUS") == "200" and kv.get("BODY") == "plain-ok",
              f"probe={kv}")
        kv = h2_probe(f"http://127.0.0.1:{PLAIN}", "streams", 8)
        check("HTTP/2 h2c: 8 concurrent streams", kv.get("STREAMS") == "8", f"probe={kv}")
        kv = h2_probe(f"https://127.0.0.1:{TLS}", "single")
        check("HTTP/2 over TLS (ALPN h2): 200 + body",
              kv.get("STATUS") == "200" and kv.get("BODY") == "tls-ok", f"probe={kv}")
        head, _hd, body, _c, _t = http10(PLAIN, "proto.local")
        check("HTTP/1.0 still served on the h2c port", head.startswith("HTTP/1.0 200")
              and body == b"plain-ok\n", f"head={head}")

        # ---------------- HTTP/3 ----------------
        kv = h3_probe(h3check, "/hi")
        check("HTTP/3 single: 200 + protocol is HTTP/3",
              kv.get("STATUS") == "200" and kv.get("PROTO", "").startswith("HTTP/3"), f"probe={kv}")
        check("HTTP/3 single: body", "hello-h3" in kv.get("BODY", ""), f"probe={kv}")
        kv = h3_probe(h3check, "/big")
        check("HTTP/3 large body arrives whole", len(kv.get("BODY", "")) >= 15000,
              f"len={len(kv.get('BODY', ''))} probe={kv.get('ERROR', '')}")
        kv = h3_probe(h3check, "/hi", "streams", 5)
        check("HTTP/3: 5 concurrent streams", kv.get("STREAMS") == "5", f"probe={kv}")
        s = tls_connect(QUIC)
        s.sendall(b"GET / HTTP/1.1\r\nHost: h3.local\r\nConnection: close\r\n\r\n")
        h3head, h3hdr, rest = recv_head(s)
        h3body, _ = recv_body(s, h3hdr, rest)
        s.close()
        check("h3 port keeps HTTP/1.1 on TCP", h3head.startswith("HTTP/1.1 200")
              and b"h3-tcp-fallback" in h3body, f"head={h3head} body={h3body!r}")
        check("h3 port advertises Alt-Svc on TCP",
              'h3=":' in h3hdr.get("alt-svc", ""), f"alt-svc={h3hdr.get('alt-svc')}")

        # ---------------- ws ----------------
        s, buf, line, hdrs, expect = ws_handshake(PLAIN, "proto.local")
        check("ws: 101 Switching Protocols", "101" in line and hdrs.get("upgrade", "").lower() == "websocket", line)
        check("ws: Sec-WebSocket-Accept matches RFC6455", hdrs.get("sec-websocket-accept") == expect,
              f"got={hdrs.get('sec-websocket-accept')} want={expect}")
        s.sendall(ws_frame("ws-matrix-1"))
        op, payload, buf = ws_recv(s, buf)
        check("ws: text frame round-trip", op == 0x1 and payload == b"echo:ws-matrix-1", f"op={op} payload={payload!r}")
        s.sendall(ws_frame(b"B" * 500, 0x2))
        op, payload, buf = ws_recv(s, buf)
        check("ws: binary frame round-trip (500B)",
              payload == b"echo:" + b"B" * 500, f"op={op} len={len(payload)}")
        s.sendall(ws_frame(b"beat", 0x9))
        op, payload, buf = ws_recv(s, buf)
        check("ws: ping answered with pong", op == 0xA and payload == b"beat", f"op={op} payload={payload!r}")
        s.sendall(ws_frame(b"", 0x8))
        op, payload, buf = ws_recv(s, buf)
        s.close()
        check("ws: close handshake", op == 0x8, f"op={op}")

        # ---------------- wss ----------------
        s, buf, line, hdrs, expect = ws_handshake(TLS, "proto-tls.local", tls=True)
        check("wss: 101 over TLS", "101" in line and hdrs.get("upgrade", "").lower() == "websocket", line)
        check("wss: Sec-WebSocket-Accept matches RFC6455", hdrs.get("sec-websocket-accept") == expect,
              f"got={hdrs.get('sec-websocket-accept')} want={expect}")
        s.sendall(ws_frame("wss-matrix-1"))
        op, payload, buf = ws_recv(s, buf)
        check("wss: text frame round-trip", op == 0x1 and payload == b"echo:wss-matrix-1", f"op={op} payload={payload!r}")
        big = b"W" * 70000
        s.sendall(ws_frame(big, 0x2))
        op, payload, buf = ws_recv(s, buf)
        check("wss: 70000B frame round-trip (64-bit length)",
              payload == b"echo:" + big, f"op={op} len={len(payload)}")
        s.sendall(ws_frame(b"", 0x8))
        op, payload, buf = ws_recv(s, buf)
        s.close()
        check("wss: close handshake", op == 0x8, f"op={op}")

        check("one gateway process served every protocol", gw.poll() is None,
              f"exit={gw.poll()}")

        # ---------------- access log: the gateway's own protocol view ----------------
        text = log_wait([
            '"GET / HTTP/1.0"', '"POST /body HTTP/1.0"', '"GET / HTTP/1.1"',
            'HTTP/2.0" 200', 'HTTP/3.0" 200',
        ])
        check("log: HTTP/1.0 requests recorded", '"GET / HTTP/1.0"' in text and '"POST /body HTTP/1.0"' in text)
        check("log: HTTP/1.1 requests recorded", '"GET / HTTP/1.1"' in text)
        # h2/h3 requests carry the absolute URI (scheme + authority), so the
        # protocol token plus the status is the stable needle.
        check("log: HTTP/2 requests recorded", 'HTTP/2.0" 200' in text)
        check("log: HTTP/3 requests recorded", 'HTTP/3.0" 200' in text)
        check("log: ws 101 upgrades recorded",
              text.count('"GET /ws HTTP/1.1" 101') >= 2, f"count={text.count('\"GET /ws HTTP/1.1\" 101')}")
    finally:
        gw.terminate()
        ws.terminate()
        for p in (gw, ws):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        gw_log.close()
        ws_log.close()

    passed = sum(1 for _n, ok in results if ok)
    total = len(results)
    print(f"PROTOCOL MATRIX {passed}/{total} passed")
    for n, ok in results:
        if not ok:
            print("  FAIL:", n)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
