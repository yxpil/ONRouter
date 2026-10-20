# -*- coding: utf-8 -*-
"""front_proxy 这条缝的每请求成本 —— 同机、同一个二进制、形状完全相同的入口逐档对比。

问的不是"ONRouter 快不快"，而是三个具体问题：
  1) 功能在但关掉（off / 整个实例没声明 profile）时，成本是不是零？
  2) detect（只识别）与 egress（全量改写：地址 + 协议 + 国家 + Host + Cache-Status）各加多少？
  3) egress vhost 上最常见的那部分流量 —— 请求根本不带能力头（探针不命中）—— 付多少钱？

口径：六个入口跑同一组端点、同一组后端、同一份 Lua 源码字符串，请求头也完全一致，
于是两行之间的差只能来自 front_proxy_mode 那一条。

先证明被测支路真的执行了，再谈数字：每档测前抓 /who 的回显（改写后的 $remote_addr、
$front_proxy、$front_proxy_verified、$scheme）、缓存行抓 Cache-Status，测量窗口前后各取一次
onrouter_front_proxy_total 计数，把窗口内的增量打在每一格旁边 —— 增量为 0 的那一行，
rps 测的就不是这条缝，数字无意义。

    cargo build --release -p onrouter-server --bin onrouter
    python bench_front_proxy.py                     # 3 轮，取中位数
    python bench_front_proxy.py --passes 1 --levels 1,8 --endpoints health,lua

注意：本机不要与回归套件同时跑（tls_legacy_e2e.py 会把 release 二进制换成 native-tls 构建）。
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
FP_CONF = os.path.join(CONF_DIR, "bench_front_proxy.conf")
FLOOR_CONF = os.path.join(CONF_DIR, "bench_front_proxy_floor.conf")
FP_LOG_DIR = CONF_DIR  # conf 里的相对路径落在 conf/ 下
ACCESS_LOG_FP = os.path.join(FP_LOG_DIR, "logs", "bench_fp_access.log")
ACCESS_LOG_FLOOR = os.path.join(FP_LOG_DIR, "logs", "bench_fp_floor_access.log")

# 门面（完全没声明 profile）+ 五个同形状 vhost
FLOOR_PORT = 8695
MODE_PORTS = {"off": 8690, "detect": 8691, "egress": 8692, "notrust": 8693, "bare": 8694}

# 一套 CDN 形状的头，发给除 bare 以外的每一个端口 —— 唯一变量是模式
HEADERS = {
    "X-Bench-Edge-Id": "edge-kx9",
    "X-Bench-Edge-Ray": "7f3c1a2b4d5e0001",
    "X-Bench-Real-Client": "203.0.113.77",
    "X-Forwarded-For": "198.51.100.1, 203.0.113.77",
    "X-Bench-Edge-Country": "US",
    "X-Bench-Visitor": '{"scheme":"https","ssl_protocol":"TLSv1.3"}',
    "X-Forwarded-Host": "fp-bench.example.com",
    "X-Bench-Nope": "none-of-the-profiles-looks-at-this",
}

ENDPOINTS = [
    ("health", "return 200", "/health"),
    ("static", "静态 index.html", "/index.html"),
    ("lua", "Lua content_by_lua", "/bench/hello"),
    ("proxy", "反代 upstream", "/bench/proxy/ping"),
    ("cached", "缓存命中（缓冲响应）", "/bench/cached/x"),
]

ROWS = [
    ("floor",  "门面：整个实例一个 profile 都没声明", FLOOR_PORT, HEADERS),
    ("off",    "off：profile 表在世，一行不跑",        MODE_PORTS["off"], HEADERS),
    ("detect", "detect：只识别与标注，不改写",          MODE_PORTS["detect"], HEADERS),
    ("egress", "egress + auto_trust：全量改写",         MODE_PORTS["egress"], HEADERS),
    ("notrust", "egress，auto_trust 未开：采元数据不动地址", MODE_PORTS["notrust"], HEADERS),
    ("bare",   "egress + auto_trust，但不带能力头（探针不命中）", MODE_PORTS["bare"], {}),
]

FP_ROLES = ("matched", "ip_applied", "ip_blocked", "origin_applied", "origin_blocked",
            "country_applied")


def fetch(port, path, headers=None, timeout=10):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, body, hdrs
    finally:
        c.close()


def start_gateway(conf_path, port, tag):
    """起一个 ONRouter 实例并等它监听；日志句柄单独开，诊断落到自己的文件。"""
    if not os.path.exists(B.ORR_EXE):
        raise RuntimeError("找不到 %s，先 cargo build --release" % B.ORR_EXE)
    log = open(os.path.join(ROOT, "logs", "%s.log" % tag), "a", buffering=1)
    p = subprocess.Popen([B.ORR_EXE, "-c", conf_path], cwd=CONF_DIR,
                         stdout=log, stderr=subprocess.STDOUT)
    if not B.wait_port(port, timeout=25):
        p.kill()
        raise RuntimeError("%s 没在 %d 就绪，看 logs/%s.log" % (tag, port, tag))
    return p


def stop_gateway(p, ports):
    if p is None:
        return
    p.kill()
    deadline = time.time() + 10
    while time.time() < deadline:
        if not any(B._listening(x) for x in ports):
            return
        time.sleep(0.2)
    raise RuntimeError("端口未释放：%s（先手动 taskkill，别把上一轮留着）" % list(ports))


def fp_counts():
    """从 egress vhost 抓一次 /metrics（不带能力头，探针不命中，所以这次抓取本身不动计数）。"""
    st, body, _ = fetch(MODE_PORTS["egress"], "/metrics")
    out = dict.fromkeys(FP_ROLES, 0)
    if st != 200:
        return out
    for line in body.decode("utf-8", "replace").splitlines():
        m = re.match(r'onrouter_front_proxy_total\{profile="[^"]+",role="([^"]+)"\} (\d+)', line)
        if m and m.group(1) in out:
            out[m.group(1)] = int(m.group(2))
    return out


def delta(before, after):
    return {k: after[k] - before.get(k, 0) for k in FP_ROLES}


def last_access_line(path, needle):
    """访问日志是 combined 格式、异步落盘；取最后一条含 needle 的行，字段一会儿就够定位。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f if needle in l]
        return lines[-1] if lines else ""
    except OSError:
        return ""


def prove(port, headers, label):
    """证明这一档到底走了哪条支路：回显 + Cache-Status + 访问日志首列。"""
    log = ACCESS_LOG_FLOOR if port == FLOOR_PORT else ACCESS_LOG_FP
    st, body, hdrs = fetch(port, "/who", headers)
    echo = body.decode("utf-8", "replace").strip()
    print("  %-8s /who -> status=%s $remote_addr=%-15s front_proxy=%-11s verified=%-5s "
          "country=%-4s $scheme=%s" %
          (label, st, echo, hdrs.get("x-fp", "-"), hdrs.get("x-fp-verified", "-"),
           hdrs.get("x-fp-country", "-"), hdrs.get("x-scheme", "-")))
    time.sleep(0.25)
    line = last_access_line(log, "/who")
    print("  %-8s 访问日志首列（改写后的 $remote_addr 要能落到这里）：%s" %
          ("", line.split(" - ")[0] if line else "(无行)"))
    cache = []
    for _ in range(3):                      # 第 1 次建条目，后两次才是命中
        st2, _, h2 = fetch(port, "/bench/cached/x", headers)
        cache.append("%s/%s" % (h2.get("x-cache-status", "-"),
                                h2.get("cache-status", "-")))
    print("  %-8s /bench/cached/x X-Cache-Status/Cache-Status 三次：%s" % ("", " -> ".join(cache)))
    return echo, hdrs


def n_for(level):
    """每格请求数随并发放大：保证单次运行 ≥ ~1s，够摊薄跨进程调度与客户端抖动。"""
    return max(8000, level * 1200)


def run_cell(port, headers, path, level):
    n = n_for(level)
    B.bench(path, max(200, n // 20), level, port=port, headers=headers)   # 预热，不计时
    before = fp_counts()
    rps, p50, p90, p99, errs = B.bench(path, n, level, port=port, headers=headers)
    return {"rps": rps, "p50": p50, "p90": p90, "p99": p99, "errs": errs,
            "n": n, "delta": delta(before, fp_counts())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--levels", default="1,32", help="并发档位，如 1,8,32")
    ap.add_argument("--endpoints", default="", help="端点 key 子集，逗号分隔，如 health,lua")
    ap.add_argument("--json", dest="json_out", default=None)
    a = ap.parse_args()

    levels = [int(x) for x in a.levels.split(",") if x.strip()]
    want = {x.strip() for x in a.endpoints.split(",") if x.strip()}
    endpoints = [e for e in ENDPOINTS if not want or e[0] in want]

    print("ONRouter 二进制：%s" % B.ORR_EXE)
    print("档：%s ｜ 端点：%s ｜ 每档 %d 轮取中位数" %
          (levels, [e[1] for e in endpoints], a.passes))

    backends = B.start_backends()
    B._pool()                                  # 建池放在任何计时之前
    fp_proc = floor_proc = None
    try:
        floor_proc = start_gateway(FLOOR_CONF, FLOOR_PORT, "bench_fp_floor")
        fp_proc = start_gateway(FP_CONF, MODE_PORTS["off"], "bench_fp")
        for p in (MODE_PORTS["egress"], MODE_PORTS["detect"], MODE_PORTS["notrust"],
                  MODE_PORTS["bare"]):
            if not B.wait_port(p, timeout=10):
                raise RuntimeError("vhost 端口 %d 没起来" % p)

        print("\n=== 第一步：证明每一档走的是哪条支路（支路没跑，数字就没意义）===")
        proofs = {}
        for key, label, port, headers in ROWS:
            proofs[key] = prove(port, headers, label)

        cap, caperr = B.ceiling(max(levels), n_for(max(levels)))
        print("\n=== 客户端天花板（直连 Python 后端，绕过网关）：%d 并发 -> %.0f req/s, err=%d ==="
              % (max(levels), cap, caperr))
        print("只约束反代/缓存那两行；静态、Lua、return 200 不经过后端。")

        data = {}
        for p in range(a.passes):
            # 轮内错开每档起点：热/频率漂移不会固定砸在同一档上
            order = ROWS[p % len(ROWS):] + ROWS[:p % len(ROWS)]
            print("\n--- 第 %d 轮（档位顺序：%s）---" %
                  (p + 1, ",".join(r[0] for r in order)))
            for key, label, port, headers in order:
                for ekey, elabel, path in endpoints:
                    for level in levels:
                        cell = run_cell(port, headers, path, level)
                        cell["pass"] = p + 1
                        data.setdefault((key, ekey, level), []).append(cell)
                        print("  %-8s %-14s c=%-3d %9.0f/s p50=%6.2fms err=%-2d 计数Δ=%s" %
                              (key, elabel, level, cell["rps"], cell["p50"], cell["errs"],
                               {k: v for k, v in cell["delta"].items() if v}))
    finally:
        if B._POOL is not None:
            B._POOL.terminate()
        stop_gateway(fp_proc, list(MODE_PORTS.values()))
        stop_gateway(floor_proc, [FLOOR_PORT])
        for b in backends:
            b.kill()

    print("\n=== 汇总（每格 %d 轮中位数；Δ 行是同一二进制内相对门面的差）===" % a.passes)
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
            "delta": {r: sum(c["delta"][r] for c in cells) for r in FP_ROLES},
        }
    bad = [k for k, v in med.items() if v["errs"]]
    for ekey, elabel, _ in endpoints:
        for level in levels:
            hdr = "%-9s %-40s %10s %8s %9s %9s %8s %14s" % (
                "档", elabel + " c=%d" % level, "req/s", "p50ms", "vs 门面", "vs off",
                "轮间极差", "窗口内计数Δ")
            print("\n" + hdr)
            print("-" * len(hdr))
            base = med[("floor", ekey, level)]["rps"]
            off = med[("off", ekey, level)]["rps"]
            for key, label, _, _ in ROWS:
                v = med[(key, ekey, level)]
                d = v["delta"]
                hits = "matched+%d ip+%d blk+%d" % (d["matched"], d["ip_applied"], d["ip_blocked"])
                print("%-9s %-40s %8.0f/s %8.2f %8.1f%% %8.1f%% %6.0f%% %14s%s" %
                      (key, label, v["rps"], v["p50"],
                       (v["rps"] / base - 1) * 100 if base else float("nan"),
                       (v["rps"] / off - 1) * 100 if off else float("nan"),
                       v["spread"] * 100, hits, "  ← 有错误，别用" if v["errs"] else ""))
    if bad:
        print("\n注意：以下格子有非零错误数，不能用来下结论：%s" % bad)

    print("\n各轮 rps（看抖动）：")
    for ekey, _, _ in endpoints:
        for level in levels:
            parts = []
            for key, _, _, _ in ROWS:
                parts.append("%s=%s" % (key, med[(key, ekey, level)]["passes"]))
            print("  %-14s c=%-3d %s" % (ekey, level, " ".join(parts)))

    out = a.json_out or os.path.join(ROOT, "bench_front_proxy_%s.json" %
                                     time.strftime("%Y%m%d"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"exe": B.ORR_EXE, "levels": levels, "passes": a.passes,
                   "n_per_cell": {str(l): n_for(l) for l in levels},
                   "client_ceiling_rps": cap,
                   "headers_sent": sorted(HEADERS),
                   "proofs": {k: {"remote_addr": v[0], "echo_headers": v[1]}
                              for k, v in proofs.items()},
                   "cells": {"%s|%s|%d" % k: v for k, v in med.items()},
                   "raw": {"%s|%s|%d" % k: [c["rps"] for c in v] for k, v in data.items()}},
                  f, ensure_ascii=False, indent=1, default=str)
    print("原始数据已写 %s" % out)


CAVEATS = """
口径说明（写结论时必须带上）：
1. 同一台 Windows 机、同一个 release 二进制、同起两个进程（门面 + 五个 vhost）。空闲的那个不
   占 CPU，但两次扫描不同步进行，所以行与行之间可比、轮与轮之间看中位数。
2. 六个入口的 location 集合逐条一致，请求头也只有一套（bare 那行刻意不带，用来量"探针不命中"）。
   profile 表全局共享，所以窗口计数增量按"当时只有这一档在被打"归属。
3. 门面行用来分离两种成本："这个 vhost 形状本身"与"这条缝"。off 行用来确认
   "功能在但关掉"与门面同价；detect/egress 行才是被测开销。
4. 分位数是各压测进程分位数按完成数加权平均，req/s 用父进程墙钟（下限）。
   只测 keep-alive、GET、明文 HTTP/1.1；冷连接、TLS、大 body、WS 升级路径未覆盖。
5. 反代/缓存两行受 Python 后端天花板约束（见"客户端天花板"行），那两行的差要按
   min(网关成本, 距天花板余量) 解读。
"""

if __name__ == "__main__":
    main()
    print(CAVEATS)
