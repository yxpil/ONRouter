# -*- coding: utf-8 -*-
# 上游响应体超时 + upstream guard 生命周期 E2E。
#
# 用真实流量证明：
#   1) 后端发完响应头后停住 → proxy_read_timeout 生效：客户端连接在约 1s 被中断，
#      而不是无限悬挂；日志记录“上游响应体读取超时”。
#   2) 超时连接不会回到连接池：下一次正常请求必须向它新建 TCP 连接
#      （后端统计接受的连接数 +1）。
#   3) 超时是“两次相邻读之间的空闲上限”：后端每 200ms 一字节、总时长约 3s，
#      远大于 1s 读超时，但每个间隔都小于 1s → 响应完整成功（不会被总时长误杀）。
#   4) upstream guard 持有到响应体结束：max_conns=1 的节点在慢体期间仍被占用，
#      并发第二个请求得到 502 no live upstreams；体读完后立即恢复。
#   5) 缓存路径（collect 整个体）同样受读超时约束 → 1s 后 504（超时是 504，口径同 nginx），不悬挂。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_body_timeout_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "proxy_body_timeout.conf")
LOG = os.path.join(ROOT, "conf", "logs", "proxy_body_timeout_err.log")
HOST, PORT = "127.0.0.1", 18196
BACKEND_PORT = 18197

results = []
stats_lock = threading.Lock()
stats = {"conns": 0}


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


def raw_get(path, timeout=10.0):
    """手写 HTTP/1.1 客户端：返回状态码 / 已收字节 / 是否被中断 / 耗时。

    用裸 socket 是为了区分“完整收到 Content-Length”和“连接中途被砍”，
    urllib 会把后者包装成异常而丢掉已收到的状态行。
    """
    t0 = time.time()
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(
        f"GET {path} HTTP/1.1\r\nHost: bt.local\r\nConnection: close\r\n\r\n".encode()
    )
    data = b""
    err = None
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except (ConnectionResetError, socket.timeout, TimeoutError) as e:
        err = type(e).__name__
    finally:
        s.close()
    elapsed = time.time() - t0
    head, _, body = data.partition(b"\r\n\r\n")
    status = 0
    first = head.split(b"\r\n", 1)[0]
    if first.startswith(b"HTTP/"):
        try:
            status = int(first.split(b" ")[1])
        except (IndexError, ValueError):
            pass
    return {
        "status": status,
        "head": head,
        "body": body,
        "err": err,
        "elapsed": elapsed,
    }


def backend_conns():
    with stats_lock:
        return stats["conns"]


class Backend:
    """最小的 TCP HTTP 后端：支持 keep-alive，便于观察连接复用/淘汰。"""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.stop = False

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with stats_lock:
                stats["conns"] += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(30)
        buf = b""
        try:
            while not self.stop:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                path = head.split(b" ")[1].decode(errors="replace")
                keep = self._respond(conn, path)
                if not keep:
                    return
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _respond(self, conn, path):
        if path.startswith("/stall"):
            body = b"x" * 100
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/plain\r\n\r\n"
                + body[:10]
            )
            time.sleep(3)
            try:
                conn.sendall(body[10:])
            except OSError:
                pass
            return False
        if path.startswith("/trickle"):
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nContent-Type: text/plain\r\n\r\n"
            )
            for _ in range(15):
                time.sleep(0.2)
                conn.sendall(b"z")
            return True
        if path in ("/hold/1", "/hold/2", "/hold/3"):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
            conn.sendall(b"a")
            time.sleep(1.2)
            conn.sendall(b"b")
            return True
        body = b"ok"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n" + body
        )
        return True

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def wait_ready():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(80):
        try:
            with opener.open(f"http://{HOST}:{PORT}/ping", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def log_text():
    try:
        with open(LOG, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "conf", "logs"), exist_ok=True)
    exe = find_binary()
    backend = Backend(BACKEND_PORT)
    backend.start()
    logf = open(os.path.join(ROOT, "logs", "proxy_body_timeout_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        check("网关就绪", wait_ready())

        # ---- 1) 正常请求先建立池化连接，记录连接数 ----
        r_ok = raw_get("/ok/first")
        check("正常请求 200/ok", r_ok["status"] == 200 and r_ok["body"] == b"ok",
              f"{r_ok['status']} {r_ok['body']!r}")
        conns_before = backend_conns()

        # ---- 2) 体超时：约 1s 中断，不是无限挂起 ----
        r_stall = raw_get("/stall/1", timeout=8)
        check("停顿响应先拿到 200 头", r_stall["status"] == 200, f"status={r_stall['status']}")
        check("响应体被截断（未收满 Content-Length: 100）", len(r_stall["body"]) < 100,
              f"got={len(r_stall['body'])} err={r_stall['err']}")
        check("约 1s（proxy_read_timeout）后中断，而不是挂到后端 3s",
              0.8 <= r_stall["elapsed"] < 2.6, f"elapsed={r_stall['elapsed']:.2f}s")
        check("日志记录上游响应体读取超时", "上游响应体读取超时" in log_text())

        # ---- 3) 超时连接未回池：下一次请求必须新建连接 ----
        r_ok2 = raw_get("/ok/second")
        check("超时后正常请求恢复 200", r_ok2["status"] == 200 and r_ok2["body"] == b"ok",
              f"{r_ok2['status']} {r_ok2['body']!r}")
        conns_after = backend_conns()
        check("超时的上游连接已被淘汰（后端新建连接）", conns_after > conns_before,
              f"conns before={conns_before} after={conns_after}")

        # ---- 4) 每读空闲语义：总时长 3s > 1s 超时，但间隔 200ms → 完整成功 ----
        r_trickle = raw_get("/trickle/1", timeout=10)
        check("慢速滴水响应完整成功（总时长远超读超时）",
              r_trickle["status"] == 200 and r_trickle["body"] == b"z" * 15,
              f"status={r_trickle['status']} body={r_trickle['body']!r} err={r_trickle['err']}")
        check("滴水响应确实耗时 > 读超时（证明非“总时长”超时）",
              r_trickle["elapsed"] >= 2.5, f"elapsed={r_trickle['elapsed']:.2f}s")

        # ---- 5) guard 持有到体结束：慢体期间 max_conns=1 被占用 ----
        out = {}

        def hold_first():
            out["r"] = raw_get("/hold/1", timeout=8)

        t = threading.Thread(target=hold_first)
        t.start()
        time.sleep(0.5)  # 此时响应头已到、响应体还在慢发（后端 hold 1.2s）
        r_busy = raw_get("/hold/2", timeout=5)
        check("慢响应体期间第二个请求命中 max_conns=1 → 502",
              r_busy["status"] == 502, f"status={r_busy['status']} body={r_busy['body'][:80]!r}")
        t.join(timeout=8)
        r_hold1 = out.get("r", {})
        check("慢响应体本身完整成功（guard 不提前释放也不误杀）",
              r_hold1.get("status") == 200 and r_hold1.get("body") == b"ab",
              f"{r_hold1.get('status')} {r_hold1.get('body')!r}")
        r_after = raw_get("/hold/3")
        check("体读完后并发额度立即恢复（200/ab）",
              r_after["status"] == 200 and r_after["body"] == b"ab",
              f"{r_after['status']} {r_after['body']!r}")

        # ---- 6) 缓存路径 collect 同样受读超时约束 ----
        r_cached = raw_get("/cached/stall/1", timeout=8)
        check("缓存路径遇到停顿上游 → 约 1s 后 504（不悬挂）",
              r_cached["status"] == 504 and r_cached["elapsed"] < 2.6,
              f"status={r_cached['status']} elapsed={r_cached['elapsed']:.2f}s")
        check("进程全程存活", proc.poll() is None, f"returncode={proc.poll()}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 上游响应体超时 / guard E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
