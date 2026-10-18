# -*- coding: utf-8 -*-
# ONRouter VM 内 Lua 协程并发 E2E —— 用真实并发流量证明同一 VM 上多条在途请求能在
# ngx.sleep 处交错让出（墙钟≈单次睡眠时长），而非各自独占 VM 串行（墙钟≈ceil(K/vm)*时长）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/lua_concurrency_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_concurrency.conf")
ORR_HOST, ORR_PORT = "127.0.0.1", 18106

VM_COUNT = min(max(os.cpu_count() or 4, 1), 16)  # 与 lua_engine.rs 的 clamp(1,16) 对齐
SLEEP_MS = 500

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL"), name, detail if (detail and not ok) else "")


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
    """阻塞式单次 GET，返回 (status, body_text)。每次一条新连接，用于制造并发。"""
    s = socket.create_connection((ORR_HOST, ORR_PORT), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: concurrency.local\r\nConnection: close\r\n\r\n".encode())
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


def hammer(path, n, barrier_timeout=10):
    """n 个线程在 barrier 处对齐后同时发起 GET，返回 (墙钟秒, [各自返回体])。"""
    barrier = threading.Barrier(n)
    bodies = [None] * n
    errs = [None] * n

    def worker(i):
        try:
            barrier.wait(barrier_timeout)
        except threading.BrokenBarrierError:
            errs[i] = "barrier broken"
            return
        try:
            st, body = http_get(path)
            bodies[i] = (st, body)
        except Exception as e:  # noqa: BLE001
            errs[i] = repr(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return time.monotonic() - t0, bodies, errs


def main():
    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %s" % ORR_PORT)

        # ---- 1) 并发让出证明：K=3*VM 个 /sleep500 同时打到网关 ----
        #   旧模型（每 VM 串行一条）：墙钟≈ceil(3*VM/VM)*0.5=1.5s
        #   新模型（VM 内协程并发）  ：墙钟≈0.5s + 调度开销
        k = 3 * VM_COUNT
        wall, bodies, errs = hammer("/sleep500", k)
        ok_all = all(e is None and b and b[0] == 200 and "ok" in b[1] for b, e in zip(bodies, errs))
        check("并发 %d 个 /sleep500 全部 200/ok" % k, ok_all,
              "errs=%s" % [e for e in errs if e][:3])
        # 阈值取 (SLEEP + 明确余量) 且远低于旧模型的 ceil(k/vm)*SLEEP
        old_model_s = (k + VM_COUNT - 1) // VM_COUNT * (SLEEP_MS / 1000.0)
        threshold = min(old_model_s * 0.6, (SLEEP_MS / 1000.0) + 0.6)
        check("墙钟 %.2fs < 阈值 %.2fs（并发让出，非 VM 串行）" % (wall, threshold), wall < threshold,
              "wall=%.3fs old_model≈%.2fs vm=%d" % (wall, old_model_s, VM_COUNT))

        # ---- 2) 更大并发（4*VM）墙钟不随 VM 数线性增长 ----
        k2 = 4 * VM_COUNT
        wall2, _, _ = hammer("/sleep200", k2)
        check("墙钟 %.2fs < 阈值 0.9s（200ms 睡眠 x%d 并发仍近似恒定）" % (wall2, k2), wall2 < 0.9,
              "wall2=%.3fs (旧模型≈%.2fs)" % (wall2, (k2 + VM_COUNT - 1) // VM_COUNT * 0.2))

        # ---- 3) ngx.ctx 跨 sleep 让出必须保持每请求独立 ----
        #   每个请求先置 stage=1，睡 120ms，再 +10 → 恒为 11；若被其它协程覆盖会偏离
        n3 = 2 * VM_COUNT
        _, bodies3, errs3 = hammer("/ctxacross", n3)
        vals = []
        good = True
        for b, e in zip(bodies3, errs3):
            if e or not b:
                good = False
                continue
            st, body = b
            if st != 200 or body.strip() != "11":
                good = False
                vals.append(body.strip())
        check("并发 %d 个 /ctxacross 每个都得到 11（ngx.ctx 请求级隔离跨让出保持）" % n3, good,
              "异常值样例=%s" % vals[:5])

        # ---- 4) 单请求基本功能未回归 ----
        st1, body1 = http_get("/sleep200")
        check("单请求 /sleep200 正常", st1 == 200 and "ok" in body1, "st=%s body=%r" % (st1, body1))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()

    failed = [n for n, ok, _ in results if not ok]
    print("\n==== lua_concurrency_e2e: %d/%d passed ====" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
