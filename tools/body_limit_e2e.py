# -*- coding: utf-8 -*-
# 请求体上限 E2E —— 真实 POST 流量验证：
#   * 未配置 client_max_body_size 时按 nginx 默认 1m 拒绝（缓冲与流式两个路径都要生效）；
#   * `client_max_body_size 0` = 不限制（可传 >1m）；
#   * chunked 流式超限时，网关在计数越界处中断，后端不会收到超过限额的字节，客户端得到 413。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/body_limit_e2e.py
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "body_limit_e2e.conf")
GW_HOST, GW_PORT = "127.0.0.1", 18188
BK_HOST, BK_PORT = "127.0.0.1", 18189
MB = 1024 * 1024

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
received = {}
recv_lock = threading.Lock()


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


def gw_get(path):
    try:
        resp = _opener.open(f"http://{GW_HOST}:{GW_PORT}{path}", timeout=5)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


class Reader:
    def __init__(self, sock, initial):
        self.s = sock
        self.buf = bytearray(initial)

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError
        self.buf.extend(d)

    def readline(self):
        while b"\r\n" not in self.buf:
            self._fill()
        line, _, rest = bytes(self.buf).partition(b"\r\n")
        self.buf = bytearray(rest)
        return line

    def readn(self, n):
        while len(self.buf) < n:
            self._fill()
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


class BodyBackend(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(15)
        rd = Reader(s, b"")
        try:
            while b"\r\n\r\n" not in rd.buf:
                rd._fill()
        except (EOFError, OSError):
            # 请求体在首帧就超限时，网关可能连请求头都没发完就中止了上游连接
            return
        head, _, rest = bytes(rd.buf).partition(b"\r\n\r\n")
        rd.buf = bytearray(rest)
        lines = head.decode(errors="replace").split("\r\n")
        try:
            _method, path, _ver = lines[0].split(" ", 2)
        except ValueError:
            return
        path = path.split("?", 1)[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        got = 0
        try:
            if "content-length" in headers:
                got = int(headers["content-length"])
                rd.readn(got)
            elif "chunked" in headers.get("transfer-encoding", "").lower():
                while True:
                    size_line = rd.readline().split(b";", 1)[0]
                    n = int(size_line, 16)
                    if n == 0:
                        # 吃掉 trailer 结束行
                        while rd.readline():
                            pass
                        break
                    rd.readn(n)
                    rd.readn(2)
                    got += n
        except (EOFError, OSError):
            # 网关在超限处断开连接：记录已收到的字节后直接退出
            with recv_lock:
                received[path] = got
            return
        with recv_lock:
            received[path] = got
        body = f"ok {path} bytes={got}".encode()
        try:
            s.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
        except OSError:
            pass


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def post(path, data, chunked=False):
    """返回 (status, body)；chunked=True 时不带 Content-Length 分块发送。"""
    s = socket.create_connection((GW_HOST, GW_PORT), timeout=20)
    if chunked:
        head = (f"POST {path} HTTP/1.1\r\nHost: {GW_HOST}:{GW_PORT}\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        s.sendall(head.encode())
        try:
            for i in range(0, len(data), 32 * 1024):
                piece = data[i:i + 32 * 1024]
                s.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        except OSError:
            pass
    else:
        head = (f"POST {path} HTTP/1.1\r\nHost: {GW_HOST}:{GW_PORT}\r\n"
                f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n")
        try:
            s.sendall(head.encode() + data)
        except OSError:
            pass
    s.settimeout(1.0)
    buf = bytearray()
    end = time.time() + 20
    while time.time() < end:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf.extend(d)
    s.close()
    head_s = bytes(buf).split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    status = 0
    parts = head_s.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            pass
    return status, head_s


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    srv = BackendServer((BK_HOST, BK_PORT), BodyBackend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "body_limit_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if gw_get("/ping")[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not ready:
            raise SystemExit("!! 网关未就绪，见 logs/body_limit_out.log")
        print("网关已就绪", GW_HOST, GW_PORT)

        payload = b"a" * MB
        st, head = post("/buffered/", payload)
        check("缓冲路径：恰好 1m 放行", st == 200, f"status={st} head={head[:120]!r}")
        with recv_lock:
            n = received.get("/buffered/", -1)
        check("缓冲路径：后端收到完整 1m", n == MB, f"backend_bytes={n}")

        st, head = post("/buffered/", payload + b"b")
        check("缓冲路径：1m+1 → 413", st == 413, f"status={st} head={head[:120]!r}")

        st, head = post("/stream/", payload + b"c" * 65536, chunked=True)
        check("流式 chunked：超 1m → 413", st == 413, f"status={st} head={head[:120]!r}")
        time.sleep(0.4)
        with recv_lock:
            n = received.get("/stream/", 0)
        check("流式 chunked：后端收到的字节不超过限额", n <= MB, f"backend_bytes={n} (limit={MB})")

        small = b"s" * 8192
        st, head = post("/small/", small, chunked=True)
        check("流式小限额：8k > 2k → 413", st == 413, f"status={st} head={head[:120]!r}")
        time.sleep(0.4)
        with recv_lock:
            n = received.get("/small/", 0)
        check("流式小限额：越界帧没有被转发（后端 ≤2k）", n <= 2048, f"backend_bytes={n}")

        st, head = post("/unlimited/", payload + b"d" * (MB // 2), chunked=True)
        check("client_max_body_size 0：1.5m 流式放行", st == 200, f"status={st} head={head[:120]!r}")

        st, head = post("/stream/", b"e" * (256 * 1024), chunked=True)
        check("流式未超限：256k → 200", st == 200, f"status={st} head={head[:120]!r}")
        with recv_lock:
            n = received.get("/stream/", -1)
        check("流式未超限：后端收到完整 256k", n == 256 * 1024, f"backend_bytes={n}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        srv.shutdown()

    ok = sum(1 for _, r in results if r)
    print(f"\n{ok}/{len(results)} 通过")
    if ok != len(results):
        print("失败项：")
        for name, r in results:
            if not r:
                print("  -", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
