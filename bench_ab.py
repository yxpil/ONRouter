# -*- coding: utf-8 -*-
"""ONRouter vs OpenResty 同机 A/B 压测。

两侧各用一份专用配置（conf/bench_ab.conf / openresty conf/bench.conf），
端点逐条对齐：同一份静态文件、同一段 Lua 源码、同一组 Python 后端。

    python bench_ab.py                    # 全量跑
    python bench_ab.py --targets orr      # 只跑 ONRouter
    python bench_ab.py --connections 128 --requests 20000

口径与限制见脚本末尾的 CAVEATS，以及打印出来的"客户端天花板"参照行。
"""
import argparse
import http.client
import json
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = 8080
BACKEND_PORTS = (9001, 9002)

IS_WINDOWS = os.name == "nt"
EXE_SUFFIX = ".exe" if IS_WINDOWS else ""
ORR_EXE = (os.environ.get("ONROUTER_EXE")
           or os.path.join(ROOT, "target", "release", "onrouter" + EXE_SUFFIX))
ORR_CONF = os.path.join(ROOT, "conf", "bench_ab.conf")

# 压测进程数：客户端不能成为瓶颈，但也不能把核抢光饿着网关 —— 按逻辑核的一半封顶
_MP_PROCS = max(1, min(8, (os.cpu_count() or 4) // 2))
_POOL = None

# OpenResty 前缀目录（放置 logs/ 与 conf/bench.conf；Linux 脚本用临时前缀，避免写系统目录）
OR_DIR = os.environ.get("OPENRESTY_DIR") or (
    r"C:\Users\User\bench\openresty-1.25.3.1-win64" if IS_WINDOWS
    else "/usr/local/openresty")
OR_CONF_REL = "conf/bench.conf"


def _find_nginx():
    """定位 nginx 可执行文件：显式变量 > 前缀目录布局 > PATH。"""
    explicit = os.environ.get("OPENRESTY_NGINX")
    if explicit:
        return explicit
    candidates = []
    if IS_WINDOWS:
        candidates.append(os.path.join(OR_DIR, "nginx.exe"))
    else:
        candidates += [
            os.path.join(OR_DIR, "nginx"),
            os.path.join(OR_DIR, "nginx", "sbin", "nginx"),
            "/usr/local/openresty/nginx/sbin/nginx",
        ]
        import shutil
        for name in ("openresty", "nginx"):
            p = shutil.which(name)
            if p:
                candidates.append(p)
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]

ENDPOINTS = [
    ("静态 index.html", "/index.html", 200),
    ("return 200", "/health", 200),
    ("Lua content_by_lua", "/bench/hello", 200),
    ("Lua shared.DICT incr", "/bench/count", 200),
    ("Lua *_file", "/bench/luafile", 200),
    ("反代 upstream", "/bench/proxy/ping", 200),
]

BACKEND_SRC = r'''
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[1])
class B(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = json.dumps({"node": port, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
import json
ThreadingHTTPServer(("127.0.0.1", port), B).serve_forever()
'''


def wait_port(port, timeout=25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start_backends():
    ps = [subprocess.Popen([sys.executable, "-c", BACKEND_SRC, str(p)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
          for p in BACKEND_PORTS]
    for p in BACKEND_PORTS:
        if not wait_port(p):
            raise RuntimeError("后端 %d 起不来" % p)
    return ps


def start_orr():
    if not os.path.exists(ORR_EXE):
        raise RuntimeError("找不到 %s，先 cargo build --release" % ORR_EXE)
    log = open(os.path.join(ROOT, "logs", "bench_orr.log"), "a", buffering=1)
    p = subprocess.Popen([ORR_EXE, "-c", ORR_CONF], cwd=os.path.join(ROOT, "conf"),
                         stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(PORT):
        p.kill()
        raise RuntimeError("ONRouter 未在 %d 就绪" % PORT)
    return p


def start_openresty():
    exe = _find_nginx()
    if not os.path.exists(exe):
        raise RuntimeError("找不到 nginx（OpenResty）：设置 OPENRESTY_NGINX 或 OPENRESTY_DIR，当前 %s" % exe)
    # Windows 的 nginx 是前台常驻 master；Unix 加 daemon off 让 Popen 持有 master
    args = [exe, "-p", OR_DIR, "-c", OR_CONF_REL]
    if not IS_WINDOWS:
        args += ["-g", "daemon off;"]
    # -p prefix 让它用前缀目录下的 logs/temp
    p = subprocess.Popen(args, cwd=OR_DIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(PORT):
        stop_openresty(p)
        raise RuntimeError("OpenResty 未在 %d 就绪，检查 %s" % (PORT, os.path.join(OR_DIR, OR_CONF_REL)))
    return p


def stop_openresty(p=None):
    exe = _find_nginx()
    subprocess.call([exe, "-p", OR_DIR, "-s", "quit"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        if not _listening(PORT):
            break
        time.sleep(0.2)
    if p is not None and p.poll() is None:
        p.kill()
    for _ in range(40):
        if not _listening(PORT):
            return
        time.sleep(0.2)
    raise RuntimeError("端口 %d 释放失败" % PORT)


def _listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
        return True
    except OSError:
        return False


def stop(proc):
    if proc is None:
        return
    proc.kill()
    for _ in range(40):
        if not _listening(PORT):
            return
        time.sleep(0.2)
    raise RuntimeError("端口 %d 释放失败" % PORT)


def fetch(path):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, body, hdrs
    finally:
        c.close()


def _bench_conn(port, path, per, timeout, sink, errs, headers=None):
    """一条长连接跑 per 个请求，把每次往返耗时追加进 sink。"""
    local = []
    headers = headers or {}
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    except OSError:
        errs.append(per)
        return
    for _ in range(per):
        t0 = time.perf_counter()
        try:
            c.request("GET", path, headers=headers)
            r = c.getresponse()
            r.read()
            local.append(time.perf_counter() - t0)
            if r.status != 200:
                errs.append(1)
        except Exception:
            errs.append(1)
            try:
                c.close()
            except Exception:
                pass
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
            except OSError:
                break
    try:
        c.close()
    except Exception:
        pass
    sink.extend(local)


def _bench_proc(job):
    """一个压测进程：起 threads 条连接。返回 (完成数, 错误数, 自身耗时s, p50, p90, p99)。
    分进程是为了绕开单进程 GIL —— 32 线程共用一个解释器时，瓶颈是 Python 而不是网关。"""
    port, path, per, threads, timeout, headers = job
    sink, errs = [], []
    ts = [threading.Thread(target=_bench_conn,
                           args=(port, path, per, timeout, sink, errs, headers))
          for _ in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.perf_counter() - t0
    if not sink:
        return 0, len(errs), dt, 0.0, 0.0, 0.0
    sink.sort()
    q = lambda p: sink[min(len(sink) - 1, int(len(sink) * p))] * 1000.0
    return len(sink), len(errs), dt, q(0.50), q(0.90), q(0.99)


def _pool():
    """固定大小的压测进程池，进程内首次用到时建好并全程复用（建池成本落在计时窗口外）。"""
    global _POOL
    if _POOL is None:
        _POOL = multiprocessing.get_context("spawn").Pool(_MP_PROCS)
        _POOL.map(_bench_proc, [])  # 触达一次，确保子进程已完成 import
    return _POOL


def bench(path, n, conns, timeout=20, port=None, headers=None):
    """固定请求数、固定并发长连接，压测端按进程切分。
    返回 (req/s, p50, p90, p99, 错误数)；rps 用父进程墙钟，分位数是各进程分位数的
    按完成数加权平均（跨进程合并完整样本太贵，同数量级下不影响结论）。"""
    port = port or PORT
    per = max(1, n // conns)
    procs = max(1, min(conns, _MP_PROCS))
    base, extra = divmod(conns, procs)
    jobs = [(port, path, per, base + (1 if i < extra else 0), timeout, headers)
            for i in range(procs) if base + (1 if i < extra else 0) > 0]
    t0 = time.perf_counter()
    if procs == 1:
        # 单并发直接在进程内跑：跨进程 map 的调度开销和 2000 次请求同量级，会把 c=1 的
        # req/s 与延迟读数压低，而 c=1 恰恰是比延迟的那一行。
        res = [_bench_proc(jobs[0])]
    else:
        res = _pool().map(_bench_proc, jobs)
    dt = time.perf_counter() - t0
    done = sum(r[0] for r in res)
    errs = sum(r[1] for r in res)
    if not done:
        return 0.0, 0.0, 0.0, 0.0, errs
    pct = lambda i: sum(r[i] * r[0] for r in res) / done
    return done / dt, pct(3), pct(4), pct(5), errs


def warmup():
    for _, path, _ in ENDPOINTS:
        try:
            fetch(path)
        except Exception:
            pass
    time.sleep(0.3)


def equivalence(label):
    print("\n--- 端点等价性核对：%s ---" % label)
    snap = {}
    for name, path, want in ENDPOINTS:
        try:
            st, body, hdrs = fetch(path)
        except Exception as e:
            print("  %-24s ERROR %s" % (name, e))
            continue
        snap[path] = (st, body)
        print("  %-24s status=%s bytes=%-5d server=%s" %
              (name, st, len(body), hdrs.get("server", "-")))
    return snap


def ceiling(connections, requests):
    """直连 Python 后端，量出这套客户端（多进程版）自己能产生多少 req/s。"""
    rps, _, _, _, e = bench("/direct", requests, connections, port=BACKEND_PORTS[0])
    return rps, e


def run_target(key, conns, requests):
    if key == "orr":
        starter, stopper = start_orr, stop
    else:
        starter, stopper = start_openresty, stop_openresty
    label = "ONRouter" if key == "orr" else "OpenResty"
    proc = starter()
    try:
        snap = equivalence(label)
        warmup()
        rows = []
        for name, path, want in ENDPOINTS:
            rps, p50, p90, p99, errs = bench(path, requests, conns)
            rows.append((name, path, rps, p50, p90, p99, errs))
            print("  %-24s %8.0f req/s  p50=%6.2fms p90=%6.2fms p99=%7.2fms  err=%d"
                  % (name, rps, p50, p90, p99, errs))
        return rows, snap
    finally:
        stopper(proc)


def sweep(levels, endpoints, keys=("orr", "or")):
    """并发扫描：在客户端不饱和的低并发区间比，rps 才反映网关本身。
    keys 只给一个时退化成单侧扫描（用于同一个二进制的新旧版本对比）。"""
    out = {}
    for key in keys:
        starter, stopper = (start_orr, stop) if key == "orr" else (start_openresty, stop_openresty)
        label = "ONRouter" if key == "orr" else "OpenResty"
        proc = starter()
        try:
            warmup()
            grid = {}
            for name, path, _ in endpoints:
                for c in levels:
                    # 每格请求数随并发放大，保证单次运行 ≥ ~0.5s，够摊薄跨进程调度开销
                    n = max(2000, c * 800)
                    rps, p50, p90, p99, errs = bench(path, n, c)
                    grid[(name, c)] = (rps, p50, p99, errs)
            out[key] = grid
            print("\n--- %s 扫描完成 ---" % label)
        finally:
            stopper(proc)

    both = len(keys) == 2
    hdr = "%-24s %-9s" % ("端点", "并发")
    for key in keys:
        hdr += "%18s" % ("ONRouter" if key == "orr" else "OpenResty")
    if both:
        hdr += "%10s" % "ORR/OR"
    print("\n=== 并发扫描（每格 %s 请求，err 全 0 才有效）===" % "max(2000, 并发x800)")
    print(hdr)
    print("-" * len(hdr))
    for name, _, _ in endpoints:
        for c in levels:
            a = out[keys[0]][(name, c)]
            row = "%-24s %-9d %9.0f/s %5.2fms" % (name, c, a[0], a[1])
            if both:
                b = out["or"][(name, c)]
                ratio = a[0] / b[0] if b[0] else float("nan")
                row += " %9.0f/s %5.2fms %9.2fx" % (b[0], b[1], ratio)
            print(row)
        print()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="orr,or", help="orr,or / orr / or")
    ap.add_argument("--connections", type=int, default=32)
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--sweep", default=None, help="并发扫描，如 1,4,8,16,32")
    ap.add_argument("--json", dest="json_out", default=None)
    a = ap.parse_args()

    backends = start_backends()
    _pool()  # 建池放在任何计时之前，否则第一格会把 spawn 8 个进程的成本算进 req/s
    results = {}
    try:
        if a.sweep:
            levels = [int(x) for x in a.sweep.split(",") if x.strip()]
            print("ONRouter 二进制：%s" % ORR_EXE)
            cap, _ = ceiling(max(levels), a.requests)
            print("\n=== 直连后端（绕过两个网关）：%d 并发 -> %.0f req/s ===" % (max(levels), cap))
            print("这是 Python 后端自身能扛的量，只卡反代那一行；静态/Lua 行不经过后端。")
            print("压测端已按 %d 进程切分，客户端不再是本地端点的瓶颈（rps 若随并发继续涨即未饱和）。"
                  % _MP_PROCS)
            endpoints = [e for e in ENDPOINTS if e[0] != "return 200"]
            keys = tuple(x.strip() for x in a.targets.split(",") if x.strip())
            bad = [k for k in keys if k not in ("orr", "or")]
            if bad:
                raise SystemExit("--targets 只接受 orr / or，收到 %s" % bad)
            data = sweep(levels, endpoints, keys)
            if a.json_out:
                with open(a.json_out, "w", encoding="utf-8") as f:
                    json.dump({"levels": levels, "client_ceiling_rps": cap,
                               "data": {"%s|%s|%d" % (k, name, c): v
                                        for k, g in data.items()
                                        for (name, c), v in g.items()}},
                              f, ensure_ascii=False, indent=1)
            return

        cap, caperr = ceiling(a.connections, a.requests)
        print("\n=== 客户端天花板（直连 Python 后端，绕过被测网关）===")
        print("  %d 并发 -> %.0f req/s, err=%d" % (a.connections, cap, caperr))
        print("  注：这是这套 Python 压测客户端自身的上限，网关只会比它低。"
              "两侧若都逼近该值说明已客户端受限，差距会被压平。")

        for key in [t.strip() for t in a.targets.split(",") if t.strip()]:
            rows, snap = run_target(key, a.connections, a.requests)
            results[key] = {"rows": rows, "snap": {k: [v[0], len(v[1])] for k, v in snap.items()}}
    finally:
        if _POOL is not None:
            _POOL.terminate()
        for b in backends:
            b.kill()

    print("\n=== 对照表（%d 并发 / %d 请求每格）===" % (a.connections, a.requests))
    if len(results) == 2:
        o, r = results["orr"]["rows"], results["or"]["rows"]
        print("%-24s %12s %12s %10s" % ("端点", "ONRouter", "OpenResty", "ORR/OR"))
        print("-" * 62)
        for (n1, _, rps1, *_), (n2, _, rps2, *_) in zip(o, r):
            ratio = (rps1 / rps2) if rps2 else float("nan")
            print("%-24s %9.0f/s %9.0f/s %9.2fx" % (n1, rps1, rps2, ratio))
        print("\n响应等价性（status/bytes 两侧应一致）：")
        for name, path, _ in ENDPOINTS:
            x = results["orr"]["snap"].get(path)
            y = results["or"]["snap"].get(path)
            print("  %-24s orr=%s or=%s %s" % (name, x, y, "OK" if x == y else "← 不一致，需对齐"))
    else:
        for key, v in results.items():
            print("[%s]" % key)
            for (name, _, rps, p50, p90, p99, errs) in v["rows"]:
                print("  %-24s %9.0f/s p50=%6.2fms p99=%7.2fms err=%d" % (name, rps, p50, p99, errs))

    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump({"connections": a.connections, "requests": a.requests,
                       "client_ceiling_rps": cap, "results": results}, f,
                      ensure_ascii=False, indent=1)
        print("\n原始数据已写 %s" % a.json_out)


CAVEATS = """
口径说明（写结论时必须带上）：
1. 同 OS 同机对比，相对值可信；但 nginx/Windows 只能单 worker、用 select() 事件模型，
   而 ONRouter 默认 16 个 Lua VM / 18 worker 线程用 tokio 完成端口。所以这张表量的是
   "ONRouter vs OpenResty 在 Windows 上的形态"，不代表 Linux 生产环境下的差距。
2. 压测端是 multiprocessing 进程池（每进程内再开线程），单进程 Python 受 GIL 限制在
   ~1 万 req/s，会把两侧差距压平，所以已切到多进程。判读方法：某行 rps 若仍随并发线性上涨，
   说明没饱和；若在两侧都停在同一数值，才是客户端/后端天花板。直连后端那一行量的是
   Python 后端自己的上限，只约束反代行。
2b. 分位数是各压测进程分位数按完成数加权平均（合并全样本的跨进程传输本身会干扰测量），
    当并发高时是近似值；req/s 用父进程墙钟，是下限。
3. ONRouter 带 ≤1MB 静态文件的进程内缓存，OpenResty 每次走磁盘 —— 静态那一行是设计差异，
   不是实现优劣。
4. 两侧都开 access_log、同一份 index.html、同一段 Lua 源码字符串、同一组 Python 后端。
5. 只测 keep-alive 长连接、GET、无 TLS。冷连接/TLS/大 body/慢客户端未覆盖。
"""

if __name__ == "__main__":
    main()
    print(CAVEATS)
