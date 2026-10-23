# -*- coding: utf-8 -*-
# Author: yxpil
# URI encoding E2E -- real traffic proof that the request line the gateway forwards is the
# target the client sent.
#
# Trigger: every /@username/ homepage returned 404. The gateway matches locations on the decoded
# path and re-encodes it before forwarding, and the re-encoder used ngx.escape_uri's
# "unreserved only" set, which percent-encodes `@` (a legal pchar) into %40. The origin and the
# WAF in front of it only match the literal `@`, so every user homepage 404'd through the gateway.
# The forwarding encoder now works over RFC 3986's pchar set: `@ : + , ; = & $ ! ' ( ) * ~` pass
# through, while `% # ?`, space, control bytes and non-ASCII are still escaped back.
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/uri_encode_e2e.py
import os
import subprocess
import sys
import threading
import time
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "uri_encode_e2e.conf")
LOG_DIR = os.path.join(ROOT, "conf", "logs")

BACKEND_PORT = 18291
GW_PORT = 18290

seen = []


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        # self.path is the raw, undecoded target as the origin received it -- exactly what
        # this suite asserts on
        seen.append(self.path)
        body = self.path.encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def fetch(path):
    conn = http.client.HTTPConnection("127.0.0.1", GW_PORT, timeout=10)
    conn.putrequest("GET", path, skip_host=True)
    conn.putheader("Host", "encode.local")
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()
    return resp.status, body


# (target sent to the gateway, target the origin must see)
CASES = [
    ("/@yinglink/", "/@yinglink/"),
    ("/u/@name/sub", "/u/@name/sub"),
    ("/a%20b", "/a%20b"),
    ("/%E4%B8%AD%E6%96%87.html", "/%E4%B8%AD%E6%96%87.html"),
    # bytes that would truncate the URI or fork the two sides' decoding stay escaped
    ("/a%23b", "/a%23b"),
    ("/100%25", "/100%25"),
    ("/a%5Bb%5D", "/a%5Bb%5D"),
    ("/p%3Fq=1", "/p%3Fq=1"),
    # nothing in the pchar set may be touched
    ("/a+b", "/a+b"),
    ("/a:b", "/a:b"),
    ("/a,b;c=d", "/a,b;c=d"),
    ("/a&b$c!d'e(d)f*g", "/a&b$c!d'e(d)f*g"),
    ("/a~b", "/a~b"),
]

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def main():
    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    os.makedirs(LOG_DIR, exist_ok=True)
    gw = subprocess.Popen(
        [find_binary(), CONF],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(80):
            try:
                if fetch("/ping")[1] == "pong":
                    break
            except Exception:
                time.sleep(0.05)
        else:
            raise SystemExit("!! gateway not ready")

        for sent, want in CASES:
            del seen[:]
            status, body = fetch(sent)
            got = seen[0] if seen else None
            check(f"{sent} forwarded verbatim", status == 200 and got == want,
                  f"status={status} origin saw {got!r} want {want!r} body={body!r}")

        # the query string is forwarded as it arrived and never goes through path re-encoding
        del seen[:]
        fetch("/search?q=%40yinglink&r=1")
        check("query passed through untouched",
              (seen[0] if seen else None) == "/search?q=%40yinglink&r=1", f"origin saw {seen}")
    finally:
        gw.terminate()
        try:
            gw.wait(timeout=5)
        except Exception:
            gw.kill()
        backend.shutdown()

    bad = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
