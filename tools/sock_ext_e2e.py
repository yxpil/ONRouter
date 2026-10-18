# -*- coding: utf-8 -*-
# cosocket 扩展 API E2E —— 用真实 TCP 后端证明 receiveany / receiveuntil / shutdown /
# setsize / setkeepalive（进程级连接池跨请求复用）全部工作。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/sock_ext_e2e.py
import itertools
import os
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "sock_ext.conf")

ORR_HOST, ORR_PORT = "127.0.0.1", 18133
KA_PORT, SHUT_PORT, ANY_PORT, UNTIL_PORT = 18134, 18135, 18136, 18137

results = []
CONN_SEQ = itertools.count(1)


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PersistentEchoHandler(socketserver.BaseRequestHandler):
    """常驻连接：每条以换行结尾的请求回 ECHO:<line>#<connid>；连接不关闭（供池复用）。"""

    def handle(self):
        connid = next(CONN_SEQ)
        self.request.settimeout(30)
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    self.request.sendall(b"ECHO:" + line + b"#" + str(connid).encode() + b"\n")
                except OSError:
                    return


class ShutHandler(socketserver.BaseRequestHandler):
    """读到 EOF（客户端写半关闭的 FIN）后回 AFTER-EOF，证明对端确实收到关闭且仍可被读。"""

    def handle(self):
        self.request.settimeout(30)
        while True:
            try:
                if not self.request.recv(4096):
                    break
            except OSError:
                break
        try:
            self.request.sendall(b"AFTER-EOF\n")
            time.sleep(1.0)
            self.request.close()
        except OSError:
            pass


class AnyHandler(socketserver.BaseRequestHandler):
    """一次性吐 10 字节，保持连接，供 receiveany 分段与 setsize 超限。"""

    def handle(self):
        try:
            self.request.sendall(b"0123456789")
            time.sleep(3.0)
            self.request.close()
        except OSError:
            pass


class UntilHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"HEAD-A\r\nHEAD-B\r\n\r\nTAIL")
            time.sleep(3.0)
            self.request.close()
        except OSError:
            pass


def start(handler, port):
    srv = Server(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
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


def http_get(path, timeout=15):
    s = socket.create_connection((ORR_HOST, ORR_PORT), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: sockext.local\r\nConnection: close\r\n\r\n".encode())
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


def connid_of(line):
    m = re.search(r"ECHO:probe#(\d+)", line)
    return m.group(1) if m else None


def main():
    srvs = [
        start(PersistentEchoHandler, KA_PORT),
        start(ShutHandler, SHUT_PORT),
        start(AnyHandler, ANY_PORT),
        start(UntilHandler, UNTIL_PORT),
    ]
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %d" % ORR_PORT)

        # === setkeepalive 连接池跨请求复用 ===
        st1, b1 = http_get("/ka")
        st2, b2 = http_get("/ka")
        id1 = connid_of(b1)
        id2 = connid_of(b2)
        check("/ka setkeepalive 成功（ka:1 kaerr:nil）", st1 == 200 and "ka: 1" in b1 and "kaerr: nil" in b1, f"b1={b1!r}")
        check("/ka 首请求非复用（reused:nil）", st1 == 200 and "reused: nil" in b1, f"b1={b1!r}")
        check("/ka 第二请求命中连接池（reused:reused）", st2 == 200 and "reused: reused" in b2, f"b2={b2!r}")
        check("/ka 两次请求走同一后端连接（connid 相同）", id1 is not None and id1 == id2, f"id1={id1} id2={id2} b1={b1!r} b2={b2!r}")

        # === shutdown 写半关闭：后端收到 EOF 回 AFTER-EOF，本端仍可读 ===
        st, body = http_get("/shut")
        nb = body.replace(" ", "")
        check("/shut shutdown 返回 1", st == 200 and "shutdown:1" in nb, f"body={body!r}")
        check("/shut 后端确实收到写关闭（after:AFTER-EOF）", "after:AFTER-EOF" in nb, f"body={body!r}")

        # === receiveany 分段取字节 ===
        st, body = http_get("/any")
        nb = body.replace(" ", "")
        check("/any receiveany(4,6) 取到前 6 字节", st == 200 and "a:012345" in nb, f"body={body!r}")
        check("/any 再 receiveany(2) 取到剩余 4 字节", "b:6789" in nb, f"body={body!r}")

        # === receiveuntil 截断到分隔符 ===
        st, body = http_get("/until")
        check("/until receiveuntil 返回分隔符前的头", st == 200 and "HEAD-A" in body and "HEAD-B" in body, f"body={body!r}")
        check("/until 未吞过分隔符（不含 TAIL）", "TAIL" not in body, f"body={body!r}")

        # === setsize 缓冲上限 ===
        st, body = http_get("/cap")
        nb = body.replace(" ", "")
        check("/cap setsize(4) 使 receive(10) 报 exceeds", st == 200 and "d:nil" in nb and "exceeds" in nb, f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        for s in srvs:
            s.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== cosocket 扩展 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
