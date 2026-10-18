# -*- coding: utf-8 -*-
# L4 stream{} 连接额度与隧道生命周期 E2E —— 用真实 TCP 流量证明：
#   1) worker_connections 是进程级共享额度：一条 L4 隧道占满后，
#      第二条 L4 连接被立即断开，同时 HTTP 连接得到 503（快速过载拒绝）；
#      隧道关闭后 L4/HTTP 都恢复
#   2) 命名 upstream 的 max_conns 覆盖整条隧道：第二条隧道被拒且不触达后端，
#      第一条关闭后额度释放
#   3) Prometheus 指标把 L4 连接计入 accepted/active（隧道关闭后 active 回落）
#   4) Ctrl+Break 优雅停机：先关闭监听（新连接被拒），shutdown_grace 内
#      在途隧道继续可通信，超时后被强制断开，进程正常退出并留下停机日志
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/stream_lifecycle_e2e.py
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_LIMIT = os.path.join(ROOT, "conf", "stream_limit_e2e.conf")
CONF_LIFE = os.path.join(ROOT, "conf", "stream_lifecycle_e2e.conf")
LIFE_LOG = os.path.join(ROOT, "conf", "logs", "stream_lifecycle_err.log")

LIMIT_GW = ("127.0.0.1", 18260)
LIMIT_ECHO = 18261
LIMIT_HTTP = ("127.0.0.1", 18268)

LIFE_HTTP = ("127.0.0.1", 18262)
LIFE_SOLO_GW = ("127.0.0.1", 18263)
LIFE_SOLO_BE = 18264
LIFE_DRAIN_GW = ("127.0.0.1", 18265)
LIFE_DRAIN_BE = 18266

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


# ------------------------------ TCP echo 后端 ------------------------------
class EchoBackend:
    """逐行回显；同时记账总连接数与并发峰值，用于验证 max_conns / 拒绝是否触达后端。"""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.active = 0
        self.total = 0
        self.max_active = 0
        self.stopped = False
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(64)

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stopped:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        with self.lock:
            self.active += 1
            self.total += 1
            self.max_active = max(self.max_active, self.active)
        buf = b""
        try:
            c.settimeout(60)
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    c.sendall(b"ECHO:" + line + b"\n")
        except Exception:
            pass
        finally:
            with self.lock:
                self.active -= 1
            try:
                c.close()
            except Exception:
                pass

    def snapshot(self):
        with self.lock:
            return self.total, self.active, self.max_active

    def stop(self):
        self.stopped = True
        try:
            self.srv.close()
        except Exception:
            pass


class LineClient:
    def __init__(self, addr, timeout=3):
        self.sock = socket.create_connection(addr, timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def send(self, line):
        self.sock.sendall(line.encode() + b"\n")

    def recv_line(self, timeout=3):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            d = self.sock.recv(4096)
            if not d:
                return None
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace")

    def wait_closed(self, timeout):
        """等到对端关闭；返回等待秒数，超时返回 None。"""
        self.sock.settimeout(timeout)
        started = time.time()
        try:
            while True:
                d = self.sock.recv(4096)
                if not d:
                    return time.time() - started
                self.buf += d
        except (ConnectionResetError, ConnectionAbortedError):
            return time.time() - started
        except socket.timeout:
            return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def http_get(addr, path="/", timeout=5):
    s = socket.create_connection(addr, timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: e2e.local\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(m.group(1)) if m else 0
    return status, body


def wait_http(addr, path="/", tries=100):
    for _ in range(tries):
        try:
            status, body = http_get(addr, path, timeout=1)
            if status == 200:
                return True
            if status in (502, 503):
                return True  # 进程已起，只是额度/后端暂不可用
        except OSError:
            pass
        time.sleep(0.1)
    return False


def parse_metrics(body):
    out = {}
    for line in body.decode(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                out[parts[0]] = float(parts[1])
            except ValueError:
                pass
    return out


def metrics(addr=LIFE_HTTP):
    status, body = http_get(addr, "/metrics")
    return status, parse_metrics(body)


def start_gw(exe, conf, out_name, new_group=False):
    logf = open(os.path.join(ROOT, "logs", out_name), "wb")
    flags = 0
    if new_group and os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(
        [exe, conf], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT, creationflags=flags
    )
    return proc, logf


def stop_gw(proc, logf):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    logf.close()


# ------------------------------- 套件 1：额度共享 -------------------------------
def run_limit(exe):
    echo = EchoBackend(LIMIT_ECHO)
    echo.start()
    proc, logf = start_gw(exe, CONF_LIMIT, "stream_limit_out.log")
    try:
        if not wait_http(LIMIT_HTTP, "/ping"):
            raise SystemExit("!! 网关未就绪（18260/18268 被占用？看 logs/stream_limit_out.log）")
        time.sleep(0.4)  # 就绪探针的连接释放额度需要一点时间

        a = LineClient(LIMIT_GW)
        a.send("A-1")
        check("worker_connections=1：第一条隧道可用", a.recv_line() == "ECHO:A-1")

        b = LineClient(LIMIT_GW)
        b.send("B-1")
        rejected = b.wait_closed(3)
        check("额度耗尽：第二条 L4 连接被立即断开", rejected is not None, "连接未被关闭")
        b.close()
        total, active, _ = echo.snapshot()
        check("被拒的 L4 连接没有触达后端", total == 1 and active == 1,
              f"total={total} active={active}")

        status, _ = http_get(LIMIT_HTTP, "/ping")
        check("额度耗尽：HTTP 快速返回 503", status == 503, f"status={status}")

        a.close()
        time.sleep(0.6)
        status, body = http_get(LIMIT_HTTP, "/ping")
        check("隧道关闭后 HTTP 恢复 200", status == 200 and body == b"pong",
              f"status={status} body={body!r}")

        c = LineClient(LIMIT_GW)
        c.send("C-1")
        check("隧道关闭后 L4 额度归还", c.recv_line() == "ECHO:C-1")
        c.close()
        total, _, peak = echo.snapshot()
        check("echo 后端并发峰值始终为 1", peak == 1 and total == 2,
              f"total={total} peak={peak}")
    finally:
        stop_gw(proc, logf)
        echo.stop()


# ---------------------------- 套件 2：隧道生命周期 ----------------------------
def run_lifecycle(exe):
    solo = EchoBackend(LIFE_SOLO_BE)
    drain = EchoBackend(LIFE_DRAIN_BE)
    solo.start()
    drain.start()
    if os.path.exists(LIFE_LOG):
        os.remove(LIFE_LOG)
    proc, logf = start_gw(exe, CONF_LIFE, "stream_lifecycle_out.log", new_group=True)
    try:
        if not wait_http(LIFE_HTTP, "/metrics"):
            raise SystemExit("!! 网关未就绪（18262-18266 被占用？看 logs/stream_lifecycle_out.log）")
        time.sleep(0.4)

        status, m = metrics()
        check("metrics 端点可用且容量为 64",
              status == 200 and m.get("onrouter_connections_capacity") == 64.0,
              f"status={status} cap={m.get('onrouter_connections_capacity')}")
        accepted0 = m.get("onrouter_connections_accepted", 0.0)

        # max_conns=1：第一条隧道占用额度
        a = LineClient(LIFE_SOLO_GW)
        a.send("A-1")
        check("max_conns=1：第一条隧道可用", a.recv_line() == "ECHO:A-1")
        total, _, _ = solo.snapshot()
        check("后端已建立 1 条连接", total == 1, f"total={total}")

        # 第二条隧道在 resolve_target 阶段拿不到额度，连接被关闭
        b = LineClient(LIFE_SOLO_GW)
        b.send("B-1")
        rejected = b.wait_closed(3)
        check("max_conns=1：第二条隧道被拒", rejected is not None, "连接未被关闭")
        b.close()
        total, _, _ = solo.snapshot()
        check("被拒隧道没有触达后端", total == 1, f"total={total}")

        # 指标：隧道存活期间 active 计入 L4（隧道 + 本次 metrics HTTP）
        status, m = metrics()
        active = m.get("onrouter_connections_active")
        accepted1 = m.get("onrouter_connections_accepted", 0.0)
        check("active 指标计入存活隧道", status == 200 and active == 2.0,
              f"active={active} status={status}")
        check("accepted 指标计入 L4 连接", accepted1 >= accepted0 + 3,
              f"{accepted0} → {accepted1}")

        a.close()
        time.sleep(0.6)
        c = LineClient(LIFE_SOLO_GW)
        c.send("C-1")
        check("第一条隧道关闭后 max_conns 额度释放", c.recv_line() == "ECHO:C-1")
        total, _, _ = solo.snapshot()
        check("后端总连接数为 2（被拒隧道未重连）", total == 2, f"total={total}")
        c.close()
        time.sleep(0.5)

        status, m = metrics()
        check("L4 隧道关闭后 active 回落到仅本次 HTTP 连接",
              status == 200 and m.get("onrouter_connections_active") == 1.0,
              f"active={m.get('onrouter_connections_active')}")

        # 停机排空：用独立隧道监听（不受 max_conns 影响）
        d = LineClient(LIFE_DRAIN_GW)
        d.send("D-1")
        check("排空测试隧道已建立", d.recv_line() == "ECHO:D-1")

        t0 = time.time()
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            signaled = True
        except (AttributeError, OSError, ValueError) as e:
            signaled = False
            check("发送 Ctrl+Break 优雅停机信号", False, repr(e))

        time.sleep(0.6)
        if signaled:
            try:
                n = socket.create_connection(LIFE_DRAIN_GW, timeout=1)
                n.close()
                refused = False
            except OSError:
                refused = True
            check("停机开始后监听已关闭（新连接被拒）", refused)

            time.sleep(0.5)  # t≈1.1s，仍在 3s grace 内
            d.send("D-2")
            check("grace 期内在途隧道仍可通信", d.recv_line(timeout=3) == "ECHO:D-2")

            waited = d.wait_closed(6)
            elapsed = time.time() - t0
            check("grace 3s 后隧道被强制断开",
                  waited is not None and 2.5 <= elapsed <= 6.0,
                  f"waited={waited} elapsed={elapsed:.2f}s")

            try:
                rc = proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                rc = None
            check("进程在排空后正常退出", rc == 0, f"rc={rc}")
        d.close()

        if os.path.exists(LIFE_LOG):
            with open(LIFE_LOG, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            check("停机日志记录停止接收与强制断开",
                  "停止接收" in text and "强制断开" in text,
                  "日志缺少停机排空记录")
            check("停机排空只统计真实在途隧道（历史连接已回收）",
                  re.search(r"127\.0\.0\.1:18265 停止接收，等待 1 条在途连接", text) is not None,
                  "18265 在途计数不是 1，JoinSet 可能未回收已完成任务")
        else:
            check("停机日志记录停止接收与强制断开", False, "日志文件不存在")
    finally:
        stop_gw(proc, logf)
        solo.stop()
        drain.stop()


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    run_limit(exe)
    run_lifecycle(exe)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== stream lifecycle E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
