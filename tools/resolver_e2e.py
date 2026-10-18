# -*- coding: utf-8 -*-
# resolver 指令 + 异步 DNS E2E —— 用真实流量证明 proxy_pass 域名走的是非阻塞异步解析：
#   * test.invalid 是 RFC6761 保留域，系统 getaddrinfo 解析不出来，只有脚本起的存根 DNS
#     服务器能给答案 → 代理成功即证明命中的是 resolver 路径
#   * 解析出的 IP 用于连接，Host 头仍是原始域名（proxy_set_header Host test.invalid）
#   * 存根对 missing.invalid 回 NXDOMAIN → 解析失败 → 502（对齐 nginx）
#   * valid=30s TTL 缓存：第二次代理请求不再向 DNS 服务器发查询（脚本侧对 A 查询计数）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/resolver_e2e.py
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "resolver.conf")

DNS_PORT = 18120
BACKEND_PORT = 18121
GW_HOST, GW_PORT = "127.0.0.1", 18119
BASE = f"http://{GW_HOST}:{GW_PORT}"

# 存根 DNS 的记录表：只给 test.invalid 一条 A；其余 *.invalid 回 NXDOMAIN
A_RECORDS = {"test.invalid": "127.0.0.1"}
# 计数：分别记录对 test.invalid 的 A 查询数与总查询数
stats = {"a_test": 0, "queries": 0, "aa": 0}
_lock = threading.Lock()

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path, timeout=10):
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def parse_qname(msg, i):
    labels = []
    while i < len(msg):
        ln = msg[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            i += 2
            break
        labels.append(msg[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    return ".".join(labels), i


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", DNS_PORT))
    sock.settimeout(1.0)
    while True:
        try:
            msg, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(msg) < 17:
            continue
        qid = msg[0:2]
        name, qname_end = parse_qname(msg, 12)
        qtype = struct.unpack(">H", msg[qname_end:qname_end + 2])[0]
        question = msg[12:qname_end + 4]  # QNAME + QTYPE + QCLASS
        name_l = name.lower().rstrip(".")
        with _lock:
            stats["queries"] += 1
            if qtype == 1 and name_l == "test.invalid":
                stats["a_test"] += 1
            if qtype == 28:
                stats["aa"] += 1
        ip = A_RECORDS.get(name_l)
        if qtype == 1 and ip:
            rdata = socket.inet_aton(ip)
            hdr = qid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
            ans = struct.pack(">HHIH", 0xC00C, 1, 1, 30) + struct.pack(">H", 4) + rdata
            sock.sendto(hdr + question + ans, addr)
        else:
            # NXDOMAIN：QR=1 RCODE=3，回显 question，AN=0
            hdr = qid + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0)
            sock.sendto(hdr + question, addr)


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"BACKEND host={self.headers.get('Host')} path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    dns_t = threading.Thread(target=dns_server, daemon=True)
    dns_t.start()

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "resolver_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        # 等网关就绪：先用一个必然走 DNS 的请求探活
        ready = False
        for _ in range(80):
            try:
                if get("/upstream-by-name")[0] in (200, 502):
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18119 被占用？看 logs/resolver_out.log）")

        with _lock:
            first_round = stats["queries"]
        check("首次请求触发了异步 DNS 查询", first_round >= 1, f"queries={first_round}")

        # 1) 域名解析 + 代理成功（test.invalid 系统解析不了，成功即证明走 resolver）
        st, body = get("/upstream-by-name")
        check("/upstream-by-name → 200（域名经异步 DNS 解析并代理）", st == 200, f"st={st} body={body!r}")
        check("后端收到 Host=原始域名 test.invalid", "host=test.invalid" in body, f"body={body!r}")
        check("后端收到原始路径", "path=/upstream-by-name" in body, f"body={body!r}")

        # 2) valid=30s 缓存：再次请求不应新增对 test.invalid 的 A 查询
        with _lock:
            before = stats["a_test"]
        get("/upstream-by-name")
        get("/upstream-by-name")
        with _lock:
            after = stats["a_test"]
        check("TTL 缓存命中：重复请求未新增 DNS A 查询", after == before, f"before={before} after={after}")
        # A 记录命中即不发 AAAA（IPv4 优先）
        with _lock:
            aa = stats["aa"]
        check("解析到 A 记录后未额外查询 AAAA", aa == 0, f"aaaa_queries={aa}")

        # 3) NXDOMAIN → 解析失败 → 502
        st, _ = get("/upstream-missing")
        check("/upstream-missing（NXDOMAIN）→ 502", st == 502, f"st={st}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== resolver 异步 DNS E2E: {passed}/{total} passed ====")
    print(f"     DNS 查询统计: {dict(stats)}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
