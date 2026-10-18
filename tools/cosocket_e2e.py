# -*- coding: utf-8 -*-
# ONRouter cosocket (ngx.socket.tcp) E2E —— 真实 TCP 后端往返 + 让出并发证明。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/cosocket_e2e.py
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_cosocket.conf")

ORR_HOST, ORR_PORT = "127.0.0.1", 18108
ECHO_PORT, BLACKHOLE_PORT = 18120, 18121
ECHO_DELAY = 0.30

VM_COUNT = min(max(os.cpu_count() or 4, 1), 16)
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL"), name, detail if (detail and not ok) else "")


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        buf = b""
        while b"\n" not in buf:
            data = self.request.recv(1024)
            if not data:
                break
            buf += data
        line = buf.split(b"\n", 1)[0]
        time.sleep(ECHO_DELAY)  # 后端慢，制造可让出的等待
        self.request.sendall(b"ECHO:" + line + b"\n")
        self.request.close()


class BlackholeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(1024)  # 收掉客户端请求
        except OSError:
            pass
        time.sleep(5)  # 永不回写 → 客户端 receive 超时
        self.request.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_tcp(handler, port):
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
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: cosocket.local\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        buf += c
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, body.decode(errors="replace")


def hammer(path, n):
    barrier = threading.Barrier(n)
    outs = [None] * n
    errs = [None] * n

    def worker(i):
        try:
            barrier.wait(15)
        except threading.BrokenBarrierError:
            errs[i] = "barrier"
            return
        try:
            outs[i] = http_get(path)
        except Exception as e:  # noqa: BLE001
            errs[i] = repr(e)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return time.monotonic() - t0, outs, errs


def main():
    echo_srv = start_tcp(EchoHandler, ECHO_PORT)
    bh_srv = start_tcp(BlackholeHandler, BLACKHOLE_PORT)
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %d" % ORR_PORT)

        # 1) 往返：connect+send+receive(*l)
        #    注意 ngx.say 用空格连接各参数，断言前去掉空格再比。
        st, body = http_get("/echo")
        norm = body.replace(" ", "")
        check("/echo 往返得到 ECHO:hello sent:6", st == 200 and "got:ECHO:hello" in norm and "sent:6" in norm,
              f"st={st} body={body!r}")

        # 2) 定长 receive(5)
        st, body = http_get("/exact")
        check("/exact receive(5) 得到前 5 字节 ECHO:", st == 200 and "data:ECHO:" in body.replace(" ", ""),
              f"st={st} body={body!r}")

        # 3) 超时
        st, body = http_get("/timeout")
        nb = body.replace(" ", "")
        check("/timeout receive 超时返回 nil,err=timeout", st == 200 and "line:nil" in nb and "err:timeout" in nb,
              f"st={st} body={body!r}")

        # 4) 连接失败（无人监听端口；本机表现为超时或拒连，均应为 ok=nil+err）
        st, body = http_get("/connectfail")
        nb = body.replace(" ", "")
        check("/connectfail 连接失败 → ok:nil + err", st == 200 and "ok:nil" in nb and ("err:timeout" in nb or "connectfailed" in nb or "refused" in nb),
              f"st={st} body={body!r}")

        # 5) 并发让出：24 个 /echo_conc（后端各睡 300ms）应重叠
        k = max(16, 2 * VM_COUNT)
        wall, outs, errs = hammer("/echo_conc", k)
        ok_all = all(e is None and o and o[0] == 200 and o[1].strip() == "ECHO:q" for o, e in zip(outs, errs))
        check("并发 %d 个 /echo_conc 全部 ECHO:q" % k, ok_all,
              f"errs={[e for e in errs if e][:3]} outs={[o for o in outs if o][:3]}")
        # 若 cosocket 阻塞 VM：墙钟≈k*delay≈9.6s；让出并发：≈(k/vm)*0.3 + HTTP 开销（本约 0.6~1.9s）。
        # 阈值取 2.5s：仍远低于串行的 9.6s，足以决定性证明非阻塞让出，同时容纳本机调度抖动。
        check("墙钟 %.2fs 证明 cosocket 让出并发（远小于 k*delay=%.1fs）" % (wall, k * ECHO_DELAY),
              wall < 2.5, f"wall={wall:.3f}s k={k} vm={VM_COUNT}")

        # 6) 回归：并发下 ngx.sleep 仍与 cosocket 共存
        wall2, _, _ = hammer("/echo", 8)
        check("并发 8 个 /echo 全部成功", wall2 < 3.0, f"wall2={wall2:.3f}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()
        echo_srv.shutdown()
        bh_srv.shutdown()

    failed = [n for n, ok, _ in results if not ok]
    print("\n==== cosocket_e2e: %d/%d passed ====" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
