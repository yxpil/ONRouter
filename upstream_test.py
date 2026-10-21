# -*- coding: utf-8 -*-
"""upstream 端到端验证：SWRR 分布、down/backup、被动摘除 + 换节点重试、全死 502、主动健康检查。

后端在脚本内用线程起（和 smoke_suite 一样），这样能精确知道哪个节点收到了请求；
断言看的是响应里的 X-Backend，而不是猜轮询状态。
"""
import os
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(ROOT, "conf", "upstream_test.conf")
HOST, PORT = "127.0.0.1", 18094
# 日志路径相对于配置文件所在目录（base_dir = conf/）
ERRLOG = os.path.join(ROOT, "conf", "logs", "upstream_err.log")

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


class Backend(BaseHTTPRequestHandler):
    name = "backend-?"

    def _reply(self, code=200):
        body = f"{self.name} {self.path}".encode()
        self.send_response(code)
        self.send_header("X-Backend", self.name)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply()

    def log_message(self, *a):
        pass


def start_backend(port, name):
    cls = type("B", (Backend,), {"name": name})
    srv = HTTPServer((HOST, port), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def http(path, timeout=8):
    """一次请求，返回 (status, backend名或None, body)"""
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    backend = None
    for line in lines[1:]:
        if line.lower().startswith("x-backend:"):
            backend = line.split(":", 1)[1].strip()
    return status, backend, body


def wait_ready():
    for _ in range(60):
        try:
            http("/wrr/ready", timeout=2)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    for srv in (start_backend(9101, "b1"), start_backend(9102, "b2"), start_backend(9106, "b6")):
        pass
    if os.path.exists(ERRLOG):
        os.remove(ERRLOG)

    exe = os.path.join(ROOT, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, CONF], cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            print("网关没起来，测试终止")
            return 1

        # 1 平滑加权轮询：weight=3/1 → 40 个请求恰好 30/10，且分布均匀不是扎堆
        got = Counter()
        seq = []
        for _ in range(40):
            st, b, _ = http("/wrr/ping")
            assert st == 200, f"wrr 不该出 {st}"
            got[b] += 1
            seq.append(b)
        check("SWRR 权重分布 3:1", got["b1"] == 30 and got["b2"] == 10, f"{dict(got)}")
        check("SWRR 平滑（任意 8 连击里 b1 不多于 7）",
              all(Counter(seq[i:i + 8])["b1"] <= 7 for i in range(len(seq) - 7)), str(seq))
        check("下一轮周期里 b2 不会饿死",
              Counter(seq[:4])["b2"] == 1 and Counter(seq[4:8])["b2"] == 1, str(seq[:8]))

        # 2 down 节点永不接流量、backup 在主组健康时不接流量
        check("down 与 backup 节点零流量", set(got) == {"b1", "b2"}, f"{dict(got)}")

        # 3 死节点：max_fails=1 + proxy_next_upstream → 客户端仍看到 200，靠活节点兜住
        stats = Counter()
        for _ in range(6):
            st, b, _ = http("/flaky/ping")
            stats[st] += 1
            stats["served" if b else "unserved"] += 1
        check("死节点首次失败后换节点重试", stats[200] == 6, f"{stats}")

        # 4 摘除期内只会选活节点（被动健康检查生效后不再有重试）
        served_directly = 0
        for _ in range(4):
            st, b, _ = http("/flaky/ping")
            if st == 200 and b == "b2":
                served_directly += 1
        check("被动摘除期内只落到活节点", served_directly == 4, f"{served_directly}/4")
        with open(ERRLOG, "r", encoding="utf-8", errors="ignore") as f:
            errs = f.read()
        check("摘除事件进了错误日志",
              "9105" in errs and "摘除" in errs, errs[-400:])

        # 5 全部后端不可用 → 按根因给码：SYN 没人应答是**超时**（504），端口主动 RST 才是
        # **连不上**（502）。同一台机器上这两类端口可以并存（本机回环上 9107/9108 是丢包，
        # 18999 是拒绝），所以断言"码与网关写下的根因一致"，而不是硬绑其中一个。
        st, b, body = http("/dead/ping")
        with open(ERRLOG, "r", encoding="utf-8", errors="ignore") as f:
            errs = f.read()
        said_timeout = "连接后端超时" in errs[-4000:]
        check("全死时失败，且状态码与真实根因一致（超时=504 / 连不上=502）",
              (st == 504 and said_timeout) or (st == 502 and not said_timeout),
              f"{st} {b} 根因超时={said_timeout}")

        # 6 主动健康检查：interval=1s fails=1，9109 没人监听应被摘除
        time.sleep(2.5)
        probed = Counter()
        for _ in range(12):
            st, b, _ = http("/probed/ping")
            probed[(st, b)] += 1
        check("探测摘除死节点后全部由活节点服务",
              probed == Counter({(200, "b6"): 12}), f"{probed}")
        with open(ERRLOG, "r", encoding="utf-8", errors="ignore") as f:
            errs = f.read()
        check("主动健康检查摘除了 9109",
              "主动健康检查" in errs and "9109" in errs, errs[-400:])

        # 7 ip_hash：同一客户端 IP 稳定命中同一节点
        stick = Counter(http("/stick/ping")[1] for _ in range(8))
        check("ip_hash 同源粘滞", len(stick) == 1, f"{stick}")

    finally:
        gw.terminate()
        try:
            gw.wait(5)
        except Exception:
            gw.kill()

    failed = [n for n, ok in results if not ok]
    print(f"\n=== {len(results) - len(failed)}/{len(results)} 通过 ===")
    if failed:
        print("失败：", ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
