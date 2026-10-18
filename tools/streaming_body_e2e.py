#!/usr/bin/env python3
# Streaming request-body E2E (real traffic).
#
# Discriminating signal: how the reverse proxy delivers a *slowly dribbled* request body
# to the backend. We POST a body in small pieces with sleeps in between (total ~1.2s) and
# have the backend record the wall-clock span over which it actually read body bytes.
#
#   proxy_request_buffering on  (buffered): the proxy reads the WHOLE body first, then
#     ships it to the backend in one burst -> backend read span ~= 0 (all bytes at once).
#   proxy_request_buffering off (streaming): the proxy pipes bytes to the backend as they
#     arrive -> backend read span ~= the client's send duration.
#
# Integrity is checked too: the backend echoes the sha256 of the bytes it received, which
# must match what the client sent, for BOTH paths.
#
#   cargo build -p onrouter-server --bin onrouter && python tools/streaming_body_e2e.py
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "streaming_body.conf")
BACKEND_PORT = 18115
ORR_PORT = 18103

BACKEND_HOST, BACKEND_PORT_ = "127.0.0.1", BACKEND_PORT
ORR_HOST, ORR_PORT_ = "127.0.0.1", ORR_PORT

_server = None
_threads = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # readiness probe
        self._json({"ready": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        h = hashlib.sha256()
        total = 0
        reads = 0
        first = last = None
        while total < length:
            need = min(4096, length - total)
            chunk = self.rfile.read1(need)  # return what's available now, don't block to fill
            if not chunk:
                break
            now = time.monotonic()
            if first is None:
                first = now
            last = now
            h.update(chunk)
            total += len(chunk)
            reads += 1
        span_ms = int((last - first) * 1000) if (first is not None and last is not None) else 0
        self._json({
            "total": total,
            "reads": reads,
            "span_ms": span_ms,
            "sha256": h.hexdigest(),
        })

    def log_message(self, *a):
        pass


def start_backend():
    global _server
    _server = ThreadingHTTPServer((BACKEND_HOST, BACKEND_PORT), Handler)
    t = threading.Thread(target=_server.serve_forever, daemon=True)
    t.start()
    _threads.append(t)


def http_post_dribble(path, data, chunk, delay):
    """Raw-socket POST that writes `data` in `chunk`-sized pieces with `delay` between them,
    then reads the full HTTP response. Returns (parsed_json, client_send_ms)."""
    s = socket.create_connection((ORR_HOST, ORR_PORT_), timeout=30)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: stream.local\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head)
    t0 = time.monotonic()
    for i in range(0, len(data), chunk):
        s.sendall(data[i:i + chunk])
        time.sleep(delay)
    send_ms = int((time.monotonic() - t0) * 1000)
    # read full response (rely on Content-Length; Connection: close is our backstop)
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            break
        buf += c
    header_blob, _, rest = buf.partition(b"\r\n\r\n")
    cl = 0
    for line in header_blob.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1].strip())
    body = rest
    while len(body) < cl:
        c = s.recv(4096)
        if not c:
            break
        body += c
    s.close()
    return json.loads(body.decode()), send_ms


def wait_ready(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = socket.create_connection((ORR_HOST, ORR_PORT_), timeout=1)
            r.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def find_binary():
    for name in ("onrouter.exe", "onrouter"):
        p = os.path.join(ROOT, "target", "debug", name)
        if os.path.exists(p):
            return p
    raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")


def main():
    # Body dribbled: 1600 bytes in 80-byte pieces, 60ms apart => ~1.14s send window.
    data = bytes((i * 7) % 251 for i in range(1600))
    expected_sha = hashlib.sha256(data).hexdigest()
    chunk, delay = 80, 0.06

    start_backend()
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_ready():
        proc.kill(); raise SystemExit("!! onrouter never became ready")

    passed = failed = 0
    def check(name, cond, detail):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS: {name}  ({detail})")
        else:
            failed += 1; print(f"  FAIL: {name}  ({detail})")

    try:
        print("== streaming (proxy_request_buffering off) ==")
        rj, sms = http_post_dribble("/stream/", data, chunk, delay)
        print(f"  client sent {len(data)}B in {sms}ms; backend: {rj}")
        check("stream: body delivered complete",
              rj["total"] == len(data), f"total={rj['total']}")
        check("stream: bytes intact (sha256)",
              rj["sha256"] == expected_sha, f"sha={rj['sha256'][:12]}")
        check("stream: body TRICKLED to backend (span ~= send duration)",
              rj["span_ms"] >= 0.5 * sms, f"span_ms={rj['span_ms']} vs send_ms={sms}")

        print("== buffered (proxy_request_buffering on) ==")
        rj2, sms2 = http_post_dribble("/buffered/", data, chunk, delay)
        print(f"  client sent {len(data)}B in {sms2}ms; backend: {rj2}")
        check("buffered: body delivered complete",
              rj2["total"] == len(data), f"total={rj2['total']}")
        check("buffered: bytes intact (sha256)",
              rj2["sha256"] == expected_sha, f"sha={rj2['sha256'][:12]}")
        check("buffered: body arrived as a BURST (span << send duration)",
              rj2["span_ms"] <= 0.35 * sms2, f"span_ms={rj2['span_ms']} vs send_ms={sms2}")

        # The differential is the actual proof: streaming span must be many times the buffered span.
        check("differential: streaming span >> buffered span",
              rj["span_ms"] >= 5 * max(rj2["span_ms"], 1),
              f"stream={rj['span_ms']}ms buffered={rj2['span_ms']}ms")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        _server.shutdown()

    print()
    print("================ streaming-body E2E: PASS=%d FAIL=%d ================" % (passed, failed))
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
