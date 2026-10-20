# -*- coding: utf-8 -*-
"""least_time 这条支路的成本与收益 —— 同一个二进制、同一个 vhost、四个只差一档的池。

问的三件事：
  1) 功能在但关掉（`off`，以及只有一个节点的 `floor`）时，成本是不是零？
  2) `observe`（只测量、选点不变）与 `on`（按 P2C + 时延 EWMA 选点）各加多少 req/s？
  3) 后端**确实**快慢不一时，这套打分把客户端延迟买回来多少？

两个场景分开回答 1/2 与 3：
  same    三个后端完全一样（0ms）—— 选择算法无从"选对"，两行之差只可能是代码成本
  hetero  三个后端 0/10/40ms —— 这才是"谁反应快选谁"要解决的问题

口径与 bench_front_proxy.py 一致：同一台机、同一个 release 二进制、同一个 vhost 形状，
唯一变量是 upstream 里的 `least_time`；每格先预热再计时，多轮取中位数，
并且**每行先自证走的是哪条支路**（哪几个后端真的服务过 + 计时窗口内的计数增量）。
增量为 0 的那一行，rps 测的就不是这条支路。

    cargo build --release -p onrouter-server --bin onrouter
    python bench_least_time.py                          # 两场景、3 轮、并发 1 与 32
    python bench_least_time.py --passes 5 --levels 1,8,32
    python bench_least_time.py --scenarios same

注意：本机不要与回归套件或构建同时跑（tls_legacy_e2e.py 会把 release 二进制换成
native-tls 构建）。
"""
import argparse
import http.client
import json
import os
import re
import statistics
import subprocess
import sys
import time

import bench_ab as B

try:                       # Windows 控制台默认按本地代码页输出，中文诊断会成乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = B.ROOT
CONF_DIR = os.path.join(ROOT, "conf")
LT_CONF = os.path.join(CONF_DIR, "bench_least_time.conf")
GW_PORT = 8700
BE_PORTS = (9001, 9002, 9003)

# 四个池 -> 四条 location；顺序就是打印顺序，floor 永远是形状参照
ROWS = [
    ("floor", "单节点池（没有选择这回事）", "/lt/floor", "ltFloor"),
    ("off",   "3 节点纯轮询（默认档）", "/lt/off", "ltOff"),
    ("obs",   "observe：照样轮询，但每请求测量", "/lt/obs", "ltObs"),
    ("on",    "on：按 P2C + 时延 EWMA 选点", "/lt/on", "ltOn"),
]
ROLES = ("sampled", "picked", "would_differ", "cold")
SCENARIOS = {
    "same": dict.fromkeys(BE_PORTS, 0.0),
    "hetero": {9001: 0.0, 9002: 0.010, 9003: 0.040},
}

BACKEND_SRC = r'''
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[1])
delay = float(sys.argv[2])
class B(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if delay:
            time.sleep(delay)
        body = json.dumps({"node": port, "delay": delay, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ThreadingHTTPServer(("127.0.0.1", port), B).serve_forever()
'''


def fetch(path, port=GW_PORT, timeout=15):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def start_backends(delays):
    ps = []
    for p in BE_PORTS:
        proc = subprocess.Popen([sys.executable, "-c", BACKEND_SRC, str(p), "%.3f" % delays[p]],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ps.append(proc)
        if not B.wait_port(p, timeout=20):
            raise RuntimeError("后端 %d 起不来" % p)
    return ps


def start_gateway():
    if not os.path.exists(B.ORR_EXE):
        raise RuntimeError("找不到 %s，先 cargo build --release" % B.ORR_EXE)
    log = open(os.path.join(ROOT, "logs", "bench_least_time.log"), "a", buffering=1)
    p = subprocess.Popen([B.ORR_EXE, "-c", LT_CONF], cwd=CONF_DIR, stdout=log, stderr=log)
    if not B.wait_port(GW_PORT, timeout=25):
        p.kill()
        raise RuntimeError("网关没在 %d 就绪，看 logs/bench_least_time.log" % GW_PORT)
    return p, log


def stop_gateway(p, log):
    p.kill()
    deadline = time.time() + 10
    while time.time() < deadline:
        if not B._listening(GW_PORT):
            break
        time.sleep(0.2)
    log.close()


def metrics():
    st, body = fetch("/metrics")
    if st != 200:
        raise RuntimeError("/metrics -> %s" % st)
    return body.decode("utf-8", "replace")


def lt_counters(text):
    """{upstream: {role: n}} —— 只有非 off 档的池会被渲染，缺池就是缺行。"""
    out = {}
    for m in re.finditer(r'onrouter_upstream_least_time_total\{upstream="([^"]+)",role="([^"]+)"\} (\d+)', text):
        out.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    return out


def ewmas(text):
    """{upstream: {server: seconds}}，用来证明估计值真的按后端快慢排出来了。"""
    out = {}
    for m in re.finditer(
        r'onrouter_upstream_server_ewma_seconds\{upstream="([^"]+)",server="([^"]+)"\} ([0-9.]+)', text
    ):
        out.setdefault(m.group(1), {})[m.group(2)] = float(m.group(3))
    return out


def node_share(path, k=24):
    """连打 k 次，看是哪几个后端服务回来的（这就是"支路真的在跑"的直接证据）。"""
    share = {}
    for _ in range(k):
        st, body = fetch(path)
        node = json.loads(body.decode("utf-8", "replace")).get("node") if st == 200 else "err%s" % st
        share[node] = share.get(node, 0) + 1
    return share


def prove(label, path, up):
    text = metrics()
    share = node_share(path)
    ctr = lt_counters(text).get(up, {})
    ew = ewmas(text).get(up, {})
    print("  %-6s %-14s 后端分布=%s  计数=%s  EWMA=%s" % (
        label, path, dict(sorted(share.items())),
        {r: ctr.get(r, 0) for r in ROLES} if ctr else "(无 least_time 行)",
        {k.split(":")[-1]: round(v * 1000, 1) for k, v in sorted(ew.items())} if ew else "(无)"))
    return share, bool(ctr)


def n_for(level):
    """每格请求数：后端慢的时候要把单次运行控制在几秒内，所以比纯成本场景收一些。"""
    return max(3000, level * 500)


def run_cell(path, up, level):
    n = n_for(level)
    B.bench(path, max(200, n // 20), level, port=GW_PORT)      # 预热，不计时
    before = lt_counters(metrics())
    rps, p50, p90, p99, errs = B.bench(path, n, level, port=GW_PORT)
    after = lt_counters(metrics())
    b, a = before.get(up, {}), after.get(up, {})
    delta = {r: a.get(r, 0) - b.get(r, 0) for r in ROLES}
    return {"rps": rps, "p50": p50, "p90": p90, "p99": p99, "errs": errs, "n": n, "delta": delta}


def run_scenario(name, delays, levels, passes):
    print("\n########## 场景 %s（后端延迟 %s）##########" %
          (name, {p: "%.0fms" % (d * 1000) for p, d in delays.items()}))
    backends = start_backends(delays)
    data = {}
    try:
        print("=== 第一步：先证明每一行走的是哪条支路 ===")
        proofs = {}
        for key, label, path, up in ROWS:
            proofs[key] = prove(key, path, up)
        for key in ("floor", "off"):
            if proofs[key][1]:
                raise RuntimeError("%s 档本不该渲染出 least_time 计数，现在有了" % key)
        for key in ("obs", "on"):
            if not proofs[key][1]:
                raise RuntimeError("%s 档没被渲染出计数，后面的数字无意义" % key)

        print("\n=== 第二步：计时（每格先预热，轮内错开档位顺序）===")
        for p in range(passes):
            order = ROWS[p % len(ROWS):] + ROWS[:p % len(ROWS)]
            print("--- 第 %d 轮（顺序：%s）---" % (p + 1, ",".join(r[0] for r in order)))
            for key, label, path, up in order:
                for level in levels:
                    cell = run_cell(path, up, level)
                    data.setdefault((key, level), []).append(cell)
                    print("  %-6s c=%-3d %9.0f/s p50=%7.2fms p99=%7.2fms err=%-2d 窗口Δ=%s" %
                          (key, level, cell["rps"], cell["p50"], cell["p99"], cell["errs"],
                           {k: v for k, v in cell["delta"].items() if v}))
    finally:
        for b in backends:
            b.kill()
    return data


def summarize(data, levels, passes):
    med = {}
    for k, cells in data.items():
        med[k] = {
            "rps": statistics.median(c["rps"] for c in cells),
            "p50": statistics.median(c["p50"] for c in cells),
            "p99": statistics.median(c["p99"] for c in cells),
            "errs": sum(c["errs"] for c in cells),
            "passes": [round(c["rps"]) for c in cells],
            "spread": (max(c["rps"] for c in cells) - min(c["rps"] for c in cells))
                      / max(1.0, statistics.median(c["rps"] for c in cells)),
            "delta": {r: sum(c["delta"][r] for c in cells) for r in ROLES},
        }
    for level in levels:
        print("\n=== 汇总 c=%d（%d 轮中位数）===" % (level, passes))
        hdr = "%-6s %-24s %10s %9s %9s %10s %9s %9s %22s" % (
            "档", "说明", "req/s", "p50ms", "p99ms", "vs floor", "vs off", "轮间极差", "窗口内计数Δ")
        print(hdr)
        print("-" * len(hdr))
        base = med[("floor", level)]["rps"]
        off = med[("off", level)]["rps"]
        for key, label, _, _ in ROWS:
            v = med[(key, level)]
            d = v["delta"]
            print("%-6s %-24s %8.0f/s %9.2f %9.2f %9.1f%% %8.1f%% %7.0f%% %22s%s" %
                  (key, label, v["rps"], v["p50"], v["p99"],
                   (v["rps"] / base - 1) * 100 if base else float("nan"),
                   (v["rps"] / off - 1) * 100 if off else float("nan"),
                   v["spread"] * 100,
                   "sam+%d pick+%d diff+%d cold+%d" % (d["sampled"], d["picked"], d["would_differ"], d["cold"]),
                   "  ← 有错误，别用" if v["errs"] else ""))
    print("\n各轮 req/s（看抖动）：")
    for level in levels:
        print("  c=%-3d %s" % (level, " ".join("%s=%s" % (k, med[(k, level)]["passes"]) for k, _, _, _ in ROWS)))
    return med


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--levels", default="1,32", help="并发档位，如 1,8,32")
    ap.add_argument("--scenarios", default="same,hetero", help="same / hetero，逗号分隔")
    ap.add_argument("--json", dest="json_out", default=None)
    a = ap.parse_args()

    levels = [int(x) for x in a.levels.split(",") if x.strip()]
    wanted = [s.strip() for s in a.scenarios.split(",") if s.strip()]
    for s in wanted:
        if s not in SCENARIOS:
            raise SystemExit("未知场景 %s（可选 same / hetero）" % s)

    print("ONRouter 二进制：%s" % B.ORR_EXE)
    print("档：%s ｜ 每格 %d 轮取中位数 ｜ 场景：%s" % (levels, a.passes, wanted))

    B._pool()                       # 建池放在任何计时之前
    proc, log = start_gateway()
    all_med = {}
    raw = {}
    try:
        for s in wanted:
            data = run_scenario(s, SCENARIOS[s], levels, a.passes)
            all_med[s] = summarize(data, levels, a.passes)
            raw[s] = {"%s|%d" % k: [c["rps"] for c in v] for k, v in data.items()}
    finally:
        if B._POOL is not None:
            B._POOL.terminate()
        stop_gateway(proc, log)

    # 收益那一句只用 hetero 场景说话：同一批请求，off 与 on 的 p50 差
    if "hetero" in all_med:
        print("\n=== 收益（后端确实快慢不一时，p50 买回来多少）===")
        for level in levels:
            off = all_med["hetero"][("off", level)]
            on = all_med["hetero"][("on", level)]
            print("  c=%-3d off p50=%.2fms -> on p50=%.2fms（%.1f%%），req/s %.0f -> %.0f（%+.1f%%）" %
                  (level, off["p50"], on["p50"], (on["p50"] / off["p50"] - 1) * 100,
                   off["rps"], on["rps"], (on["rps"] / off["rps"] - 1) * 100 if off["rps"] else float("nan")))

    out = a.json_out or os.path.join(ROOT, "bench_least_time_%s.json" % time.strftime("%Y%m%d"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"exe": B.ORR_EXE, "levels": levels, "passes": a.passes,
                   "n_per_cell": {str(l): n_for(l) for l in levels},
                   "scenarios": {k: {"delays_ms": {str(p): round(d * 1000) for p, d in v.items()}}
                                 for k, v in SCENARIOS.items()},
                   "median": {s: {"%s|%d" % k: v for k, v in m.items()} for s, m in all_med.items()},
                   "raw": raw}, f, ensure_ascii=False, indent=1, default=str)
    print("\n原始数据已写 %s" % out)


CAVEATS = """
口径说明（写结论时必须带上）：
1. 一台 Windows 机、一个 release 二进制、一个 vhost 四条 location，四个池只有
   upstream 里那一档不同；后端是同一份 Python 源码起的三个进程，唯一变量是 sleep。
2. floor 行是"只有一个节点的池"：它把选点彻底省掉，但同时也只有一个 Python 后端进程，
   所以它的 req/s 受后端单进程上限约束（32 并发时比三节点行还低），只能当形状参照，
   不能当成本基线。真正的成本对比只看 obs/on 相对 off 的差。
3. 每行的窗口内计数增量（sampled/picked/would_differ/cold）先证明这条支路真的跑了：
   off/floor 两行本来就渲染不出 least_time 行，obs 行只有 sampled、on 行才有 picked。
4. 分位数是各压测进程分位数按完成数加权平均，req/s 用父进程墙钟（下限）。
   只测 keep-alive、GET、明文 HTTP/1.1、小 body；TLS、大 body、WS 升级未覆盖。
5. hetero 场景里 req/s 受后端 sleep 与 Python 单进程线程池约束，那一场景要看的是 p50
   与分布，req/s 只作趋势；纯成本结论看 same 场景。
"""

if __name__ == "__main__":
    main()
    print(CAVEATS)
