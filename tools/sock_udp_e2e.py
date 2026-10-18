# -*- coding: utf-8 -*-
# ngx.socket.udp E2E —— 用真实 UDP 后端证明数据报 setpeername/send/receive 往返、
# 同一 socket 连续收发、以及无应答时的超时/拒收（nil + err）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/sock_udp_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "sock_udp.conf")

ORR_HOST, ORR_PORT = "127.0.0.1", 18138
ECHO_PORT, DEAD_PORT = 18139, 18140

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def start_udp_echo(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.settimeout(0.5)

    def loop():
        while True:
            try:
                data, addr = srv.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                srv.sendto(b"UDP:" + data, addr)
            except OSError:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
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
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: sockudp.local\r\nConnection: close\r\n\r\n".encode())
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
    echo = start_udp_echo(ECHO_PORT)
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %d" % ORR_PORT)

        # 1) 单数据报往返
        st, body = http_get("/udp")
        nb = body.replace(" ", "")
        check("/udp setpeername+send+receive 得到 UDP:ping", st == 200 and "data:UDP:ping" in nb, f"body={body!r}")
        check("/udp send 返回 4 字节", "sent:4" in nb, f"body={body!r}")

        # 2) 同一 socket 连续两个数据报
        st, body = http_get("/udp2")
        nb = body.replace(" ", "")
        check("/udp2 连续收发两个数据报", st == 200 and "a:UDP:one" in nb and "b:UDP:two" in nb, f"body={body!r}")

        # 3) 无应答 → receive 得 nil + err（超时或 ICMP 拒收）
        st, body = http_get("/udptimeout")
        nb = body.replace(" ", "")
        check("/udptimeout 无应答 receive → nil,err", st == 200 and "data:nil" in nb and "err:nil" not in nb, f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        echo.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.socket.udp E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
