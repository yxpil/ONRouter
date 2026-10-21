# -*- coding: utf-8 -*-
# 稳定性压测：20 分钟混合流量 + 进程内存采样与泄漏判定。
#
# 流量不是"打一个 /ping"：每条路径都有不同的内存增长风险，并且都校验响应语义：
#   /plain     反代 8 KiB 响应，连接池/缓冲区反复建立与回收
#   /wasm      每请求实例化 WASM 插件，改写状态/响应头并缓冲 32 KiB 响应体
#   /cached    4 MiB 缓存区、512 个键（装得下，MISS/HIT 混合）
#   /cold      1k 冷层区、256 个键循环（淘汰→落盘→冷读→提升全程都在跑）
#   /lua       每请求跑一段 Lua
#   /static    8 KiB 静态文件走 WASM 过滤器
# 另有 4 条长连接 worker 持续复用 keep-alive，专门看连接级缓冲是否随时间上涨。
#
# 内存口径：Windows 用 PrivateUsage，Linux 用 RssAnon，macOS 退回 RSS。
# 预热期（默认前 5 分钟）用于让缓存/线程池/分配器达到稳态，之后才做线性趋势判定；
# 判定看"私有内存的绝对增长 + 回归斜率"两条同时越线，避免把分配器预留误报成泄漏。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/soak_test.py --minutes 20
import argparse
import ctypes
import json
import os
import random
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CONF_REL = os.path.join("conf", "soak.conf")
GW_PORT = 18500
BE_PORT = 18501
GW = ("127.0.0.1", GW_PORT)
BASE = f"http://127.0.0.1:{GW_PORT}"
ERR_LOG = ROOT / "conf" / "logs" / "soak_err.log"
OUT_LOG = ROOT / "conf" / "logs" / "soak_out.log"
CACHE_DIR = ROOT / "conf" / "logs" / "soak_cache"
STATIC_FILE = ROOT / "conf" / "soak_static" / "static.txt"
REPORT_JSON = ROOT / "target" / "soak_report.json"
SAMPLES_CSV = ROOT / "target" / "soak_samples.csv"
METRICS_START = ROOT / "target" / "soak_metrics_start.txt"
METRICS_END = ROOT / "target" / "soak_metrics_end.txt"

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
STOP = threading.Event()


# ---------------------------------------------------------------- 后端

def _make_backend_handler():
    from http.server import BaseHTTPRequestHandler
    from urllib.parse import urlsplit, parse_qs

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a):  # 压测期别让访问日志本身成为变量
            pass

        def do_GET(self):
            p = urlsplit(self.path)
            k = parse_qs(p.query).get("k", [""])[0]
            if p.path == "/plain":
                prefix, size = "PLAIN-", 8192
            elif p.path == "/wasm":
                prefix, size = "WASM-", 32768
            elif p.path == "/cached":
                prefix, size = "CACHE-", 2048
            elif p.path == "/cold":
                # 长 TTL 是有意的：冷层只收"还新鲜"的条目，10s 就过期的对象永远测不到落盘
                prefix, size = "COLD-", 4096
            else:
                self.send_error(404)
                return
            unit = prefix + k + "-"
            body = (unit * (size // len(unit) + 1))[:size].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Soak-Backend", "1")
            self.send_header("X-Backend-Secret", "hidden")
            ttl = "600" if p.path == "/cold" else "10"
            self.send_header("Cache-Control", f"public, max-age={ttl}")
            self.end_headers()
            self.wfile.write(body)
            COUNTERS.backend += 1

    return Handler


def start_backend():
    from http.server import ThreadingHTTPServer

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 256

        def handle_error(self, request, client_address):
            exc = sys.exc_info()[1]
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                return
            super().handle_error(request, client_address)

    srv = Server(("127.0.0.1", BE_PORT), _make_backend_handler())
    t = threading.Thread(target=srv.serve_forever, name="soak-backend", daemon=True)
    t.start()
    return srv


# ---------------------------------------------------------------- 计数器

class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = 0
        self.fail = 0
        self.bytes = 0
        self.backend = 0
        self.errors = Counter()
        self.examples = []

    def success(self, nbytes):
        with self.lock:
            self.ok += 1
            self.bytes += nbytes

    def failure(self, category, detail=""):
        with self.lock:
            self.fail += 1
            self.errors[category] += 1
            if len(self.examples) < 8:
                self.examples.append(f"{category}: {str(detail)[:180]}")

    def snap(self):
        with self.lock:
            return {
                "ok": self.ok,
                "fail": self.fail,
                "bytes": self.bytes,
                "backend": self.backend,
                "errors": dict(self.errors),
                "examples": list(self.examples),
            }


COUNTERS = Counters()


# ---------------------------------------------------------------- 请求与校验

def tok():
    return f"{random.getrandbits(32):08x}"


def choose_path(rng):
    r = rng.random()
    if r < 0.40:
        return "/plain?k=" + tok()
    if r < 0.65:
        return "/wasm?k=" + tok()
    if r < 0.85:
        return "/cached?k=" + str(rng.randrange(512))
    if r < 0.90:
        return "/cold?k=" + str(rng.randrange(256))
    if r < 0.95:
        return "/lua?k=" + tok()
    return "/static.txt"


def validate(path, status, headers, body):
    """返回 None 表示符合语义，否则返回失败类别。"""
    if path.startswith("/wasm"):
        if status != 202:
            return f"wasm-status-{status}"
        if body != b"WASM-":
            return f"wasm-body-{len(body)}"
        if headers.get("x-wasm-header-filter") != "on":
            return "wasm-header"
        if headers.get("x-backend-secret") is not None:
            return "wasm-secret-leak"
    elif path.startswith("/plain"):
        if status != 200:
            return f"plain-status-{status}"
        if len(body) != 8192 or not body.startswith(b"PLAIN-"):
            return f"plain-body-{len(body)}"
    elif path.startswith("/cached"):
        if status != 200:
            return f"cached-status-{status}"
        if len(body) != 2048 or not body.startswith(b"CACHE-"):
            return f"cached-body-{len(body)}"
        xc = headers.get("x-cache")
        if xc not in {"MISS", "HIT", "STALE", "EXPIRED", "BYPASS", "UPDATING", "REVALIDATED"}:
            return f"cached-header-{xc!r}"
    elif path.startswith("/cold"):
        if status != 200:
            return f"cold-status-{status}"
        if len(body) != 4096 or not body.startswith(b"COLD-"):
            return f"cold-body-{len(body)}"
        xc = headers.get("x-cache")
        if xc not in {"MISS", "HIT", "STALE", "EXPIRED", "BYPASS", "UPDATING", "REVALIDATED"}:
            return f"cold-header-{xc!r}"
    elif path.startswith("/lua"):
        if status != 200:
            return f"lua-status-{status}"
        if len(body) < 2048 or not body.startswith(b"lua-"):
            return f"lua-body-{len(body)}"
    elif path == "/static.txt":
        if status != 202:
            return f"static-status-{status}"
        if body != b"SOAK-":
            return f"static-body-{len(body)}"
    return None


def one_shot_worker(deadline, rng):
    while not STOP.is_set() and time.time() < deadline:
        path = choose_path(rng)
        try:
            with OPENER.open(BASE + path, timeout=10) as r:
                status = r.status
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = r.read()
            bad = validate(path, status, headers, body)
            if bad:
                COUNTERS.failure(bad, path)
            else:
                COUNTERS.success(len(body))
        except urllib.error.HTTPError as e:
            COUNTERS.failure(f"http-{e.code}", path)
        except Exception as e:  # noqa: BLE001
            COUNTERS.failure(type(e).__name__, f"{path} {e}")


def _read_response(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("eof in headers")
        buf += chunk
        if len(buf) > 1_000_000:
            raise RuntimeError("header too large")
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split(None, 2)[1])
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        raise RuntimeError("unexpected chunked response")
    need = int(headers.get("content-length", "0"))
    while len(rest) < need:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("eof in body")
        rest += chunk
    return status, headers, rest[:need]


def keepalive_worker(deadline, rng):
    while not STOP.is_set() and time.time() < deadline:
        try:
            s = socket.create_connection(GW, timeout=10)
            s.settimeout(15)
            try:
                for _ in range(40):
                    if time.time() >= deadline:
                        break
                    path = "/plain?k=ka" + tok()
                    req = (
                        f"GET {path} HTTP/1.1\r\nHost: soak.local\r\n"
                        "Connection: keep-alive\r\n\r\n"
                    ).encode()
                    s.sendall(req)
                    status, headers, body = _read_response(s)
                    bad = validate(path, status, headers, body)
                    if bad:
                        COUNTERS.failure(bad, path)
                    else:
                        COUNTERS.success(len(body))
            finally:
                s.close()
        except Exception as e:  # noqa: BLE001
            COUNTERS.failure("keepalive-" + type(e).__name__, str(e))


# ---------------------------------------------------------------- 内存采样

def _win_mem(pid):
    from ctypes import wintypes

    class PMC_EX(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = getattr(k32, "K32GetProcessMemoryInfo", None)
    if fn is None:
        fn = ctypes.WinDLL("psapi").GetProcessMemoryInfo
    fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC_EX), wintypes.DWORD]
    fn.restype = wintypes.BOOL
    handle = k32.OpenProcess(0x0410, False, pid)  # QUERY_INFORMATION | VM_READ
    if not handle:
        return None
    try:
        c = PMC_EX()
        c.cb = ctypes.sizeof(c)
        if not fn(handle, ctypes.byref(c), c.cb):
            return None
        return {"rss": int(c.WorkingSetSize), "priv": int(c.PrivateUsage)}
    finally:
        k32.CloseHandle(handle)


def read_mem(pid):
    if os.name == "nt":
        return _win_mem(pid)
    if sys.platform.startswith("linux"):
        rss = priv = 0
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) * 1024
                    elif line.startswith("RssAnon:"):
                        priv = int(line.split()[1]) * 1024
        except OSError:
            return None
        return {"rss": rss, "priv": priv or rss}
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
        return {"rss": int(out.strip()) * 1024, "priv": 0}
    except Exception:
        return None


# ---------------------------------------------------------------- 工具

def wait_port(port, up=True, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            ok = True
        except OSError:
            ok = False
        finally:
            s.close()
        if ok == up:
            return True
        time.sleep(0.1)
    return False


def find_binary():
    path = ROOT / "target" / "release" / ("onrouter.exe" if os.name == "nt" else "onrouter")
    if not path.exists():
        raise SystemExit("!! 先用 release 构建：cargo build --release -p onrouter-server --bin onrouter")
    return str(path)


def scrape_metrics():
    try:
        with OPENER.open(BASE + "/metrics", timeout=10) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"# scrape failed: {e}\n"


def fmt_mib(n):
    return n / (1024 * 1024)


def median(vals):
    return statistics.median(vals) if vals else 0.0


def linfit(xs, ys):
    if len(xs) < 2:
        return 0.0, 0.0
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    return slope, my - slope * mx


def analyze(samples, warmup_s, max_growth_mib, max_slope):
    post = [s for s in samples if s["t"] >= warmup_s / 60.0]
    result = {
        "checked": False,
        "warmup_minutes": round(warmup_s / 60.0, 2),
        "post_samples": len(post),
        "metric": "priv",
        "baseline_mib": None,
        "end_mib": None,
        "growth_mib": None,
        "slope_mib_min": None,
        "peak_mib": None,
        "rss_baseline_mib": None,
        "rss_end_mib": None,
        "notes": [],
    }
    if len(post) < 4:
        result["notes"].append("预热后样本不足，未做趋势判定")
        return result
    use_priv = any(s["priv"] for s in post)
    key = "priv" if use_priv else "rss"
    result["metric"] = "private" if use_priv else "rss"
    early = [s[key] for s in post if s["t"] <= post[0]["t"] + 1.0]
    late = [s[key] for s in post[-3:]]
    base = median(early)
    end = median(late)
    xs = [s["t"] for s in post]
    ys = [fmt_mib(s[key]) for s in post]
    slope, _ = linfit(xs, ys)
    result.update(
        checked=True,
        baseline_mib=round(fmt_mib(base), 2),
        end_mib=round(fmt_mib(end), 2),
        growth_mib=round(fmt_mib(end - base), 2),
        slope_mib_min=round(slope, 3),
        peak_mib=round(fmt_mib(max(s[key] for s in post)), 2),
        rss_baseline_mib=round(fmt_mib(median([s["rss"] for s in post[:3]])), 2),
        rss_end_mib=round(fmt_mib(median([s["rss"] for s in post[-3:]])), 2),
    )
    if result["growth_mib"] > max_growth_mib and slope > max_slope:
        result["notes"].append(
            f"私有内存增长 {result['growth_mib']} MiB、斜率 +{slope:.2f} MiB/min，"
            f"两条均超过阈值（{max_growth_mib} MiB / {max_slope} MiB/min）"
        )
    if result["growth_mib"] > max_growth_mib * 1.5:
        result["notes"].append(f"私有内存增长 {result['growth_mib']} MiB 超过硬上限")
    if result["baseline_mib"] and result["end_mib"] > result["baseline_mib"] * 2 and result["growth_mib"] > 32:
        result["notes"].append("结束内存超过预热基线的 2 倍，疑似未回收")
    return result


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description="ONRouter 稳定性压测")
    ap.add_argument("--minutes", type=float, default=20.0, help="压测时长（分钟，默认 20）")
    ap.add_argument("--workers", type=int, default=24, help="短连接并发 worker 数")
    ap.add_argument("--keepalive-workers", type=int, default=4, help="keep-alive 长连接 worker 数")
    ap.add_argument("--interval", type=float, default=5.0, help="内存采样间隔（秒）")
    ap.add_argument("--warmup-minutes", type=float, default=5.0)
    ap.add_argument("--max-growth-mib", type=float, default=48.0)
    ap.add_argument("--max-slope-mib-min", type=float, default=1.0)
    args = ap.parse_args()
    minutes = max(0.5, args.minutes)
    duration = minutes * 60.0
    warmup_s = args.warmup_minutes * 60.0
    if minutes < 8:
        warmup_s = min(warmup_s, duration * 0.25)
    warmup_s = max(30.0, min(warmup_s, duration * 0.5))

    for port, why in ((GW_PORT, "网关"), (BE_PORT, "后端")):
        if wait_port(port, up=True, timeout=0.2):
            raise SystemExit(f"!! {why}端口 {port} 已被占用，先确认没有残留进程")

    exe = find_binary()
    test = subprocess.run(
        [exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )
    if test.returncode != 0:
        raise SystemExit("!! 压测配置未通过 -t：\n" + ((test.stdout or "") + (test.stderr or ""))[-1200:])

    shutil.rmtree(CACHE_DIR, ignore_errors=True)
    (ROOT / "conf" / "logs").mkdir(parents=True, exist_ok=True)
    for f in (ERR_LOG, OUT_LOG):
        if f.exists():
            f.unlink()

    backend = start_backend()
    if not wait_port(BE_PORT, up=True, timeout=5):
        backend.shutdown()
        raise SystemExit("!! 压测后端没起来")

    proc = subprocess.Popen(
        [exe, "-c", CONF_REL], cwd=ROOT,
        stdout=open(OUT_LOG, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    samples = []
    abort_reason = None
    end_metrics = "# metrics unavailable\n"
    health_ok = False
    pool = None
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + str(ERR_LOG))
        METRICS_START.write_text(scrape_metrics(), encoding="utf-8")
        print(f"=== ONRouter 稳定性压测：{minutes:g} 分钟 / {args.workers} 短连接 + "
              f"{args.keepalive_workers} 长连接 ===")
        print(f"网关 {exe}，后端 127.0.0.1:{BE_PORT}，采样每 {args.interval:g}s")

        start = time.time()
        deadline = start + duration
        COUNTERS.__init__()
        rng = random.Random(20261021)
        pool = ThreadPoolExecutor(max_workers=args.workers + args.keepalive_workers)
        futures = []
        for _ in range(args.workers):
            futures.append(pool.submit(one_shot_worker, deadline, random.Random(rng.getrandbits(64))))
        for _ in range(args.keepalive_workers):
            futures.append(pool.submit(keepalive_worker, deadline, random.Random(rng.getrandbits(64))))

        next_sample = start
        last_report = start
        while time.time() < deadline:
            if proc.poll() is not None:
                abort_reason = f"网关进程提前退出（code={proc.returncode}）"
                break
            now = time.time()
            if now >= next_sample:
                mem = read_mem(proc.pid)
                sn = COUNTERS.snap()
                if mem:
                    samples.append({
                        "t": round((now - start) / 60.0, 3),
                        "rss": mem["rss"],
                        "priv": mem["priv"],
                        "ok": sn["ok"],
                        "fail": sn["fail"],
                    })
                next_sample += args.interval
            if now - last_report >= 60:
                sn = COUNTERS.snap()
                mem = samples[-1] if samples else {"rss": 0}
                print(f"[{(now - start) / 60:5.1f} min] ok={sn['ok']:7d} fail={sn['fail']:5d} "
                      f"RSS={fmt_mib(mem['rss']):6.1f} MiB backend={sn['backend']}")
                last_report = now
            time.sleep(0.2)

        STOP.set()
        pool.shutdown(wait=True, cancel_futures=True)
        health_ok = proc.poll() is None
        end_metrics = scrape_metrics() if health_ok else "# gateway exited unexpectedly\n"
    finally:
        STOP.set()
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        backend.shutdown()
        backend.server_close()

    METRICS_END.write_text(end_metrics, encoding="utf-8")
    sn = COUNTERS.snap()
    total = sn["ok"] + sn["fail"]
    elapsed = (samples[-1]["t"] * 60.0) if samples else 0.0
    analysis = analyze(samples, warmup_s, args.max_growth_mib, args.max_slope_mib_min)

    print("\n==== 结果 ====")
    print(f"请求总数 {total}（成功 {sn['ok']}，失败 {sn['fail']}），"
          f"实际时长 {elapsed / 60.0:.1f} 分钟，平均 {total / max(elapsed, 1e-9):.1f} req/s")
    print(f"后端收到的回源请求 {sn['backend']}；错误分类 {sn['errors'] or '无'}")
    if sn["examples"]:
        print("失败样例：")
        for e in sn["examples"]:
            print("  -", e)
    if analysis["checked"]:
        print(f"内存（{analysis['metric']}，预热 {analysis['warmup_minutes']} min 后 "
              f"{analysis['post_samples']} 个样本）：")
        print(f"  基线 {analysis['baseline_mib']} MiB -> 结束 {analysis['end_mib']} MiB"
              f"（{analysis['growth_mib']:+} MiB），峰值 {analysis['peak_mib']} MiB，"
              f"趋势 {analysis['slope_mib_min']:+} MiB/min")
        print(f"  RSS 基线 {analysis['rss_baseline_mib']} MiB -> 结束 {analysis['rss_end_mib']} MiB")
    else:
        print("内存：" + "；".join(analysis["notes"]))
    for note in analysis["notes"]:
        print("  ! " + note)

    failures = []
    if abort_reason:
        failures.append(abort_reason)
    if not health_ok:
        failures.append("压测结束时网关已不在运行（或健康检查失败）")
    if total < max(100, minutes * 60 * 5):
        failures.append(f"请求量过低（{total}），压测没有真正施压")
    if sn["fail"] > max(50, total * 0.002):
        failures.append(f"失败率过高（{sn['fail']}/{total}）")
    if analysis["checked"] and analysis["notes"]:
        failures.extend(analysis["notes"])

    verdict = "PASS" if not failures else "FAIL"
    print(f"\n==== 稳定性压测: {verdict} ====")
    for f in failures:
        print("FAILED:", f)
    if abort_reason and ERR_LOG.exists():
        print("网关错误日志末尾：")
        print("\n".join(ERR_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]))

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "minutes_requested": minutes,
        "minutes_run": round(elapsed / 60.0, 2),
        "workers": args.workers,
        "keepalive_workers": args.keepalive_workers,
        "requests": {"ok": sn["ok"], "fail": sn["fail"], "total": total,
                     "backend_hits": sn["backend"], "errors": sn["errors"]},
        "memory": analysis,
        "thresholds": {"max_growth_mib": args.max_growth_mib,
                       "max_slope_mib_min": args.max_slope_mib_min},
        "samples": samples,
        "verdict": verdict,
        "failures": failures,
    }
    REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with SAMPLES_CSV.open("w", encoding="utf-8") as f:
        f.write("minute,rss_bytes,private_bytes,ok,fail\n")
        for s in samples:
            f.write(f"{s['t']},{s['rss']},{s['priv']},{s['ok']},{s['fail']}\n")
    print(f"报告：{REPORT_JSON}\n样本：{SAMPLES_CSV}\n指标：{METRICS_END}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n中断")
        sys.exit(130)
