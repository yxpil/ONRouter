# -*- coding: utf-8 -*-
"""业务分流（split_clients → proxy_pass http://$变量）的每请求成本 —— 同一个二进制、同一个 vhost、七条只差一档的 location。

问的三件事：
  1) 不用这个功能时成本是不是真的零？`floor`/`literal`/`lithdr` 三行是字面量 proxy_pass：
     既不查全局 split 表、不哈希、也不碰账本，所以它们的计时窗口内**分流计数增量必须为 0**
     —— 增量不为 0 就说明这几行测的根本不是"没有分流"。
  2) 用了之后每请求加多少，并且把加法拆开归因（每段减的都在同一并发档里）：
        lithdr - literal   往上游多写两条定长请求头（分流各行要靠它们核对落点）
        const  - lithdr    查 split 表 + 哈希落桶 + 写账本（分支全指同一个池，后端形状不变）
        hdr    - const     每请求展开键模板（查请求头 + 拼串）
        two    - hdr       真实形状：两个业务版本各一个池
        off vs two         `proxy_split_failover` 是构建期策略，不该进热路径
  3) 这点成本换来的"声明比例 vs 实际落点"是不是真在跑？第一步用变化的键把每个分支都打中，
     并把 /metrics 的 target 增量与网关自己报告的落点（后端打回的 X-Split-Served）对死。

后端形状为什么必须一样：psLit/psA/psB 三个池都是同样两台 Python 后端，所以无论比例把请求
判给哪一路，两台后端承接的总请求数都与 literal 行一致 —— 档与档之间的 rps 差只可能是
网关这段代码的成本，不是"后端被压的程度"不同。

    python bench_proxy_split.py                    # 定形 1 轮 + 计时 3 轮，c=1 与 c=32 取中位数
    python bench_proxy_split.py --passes 5 --levels 8,32 --warmup-passes 2

二进制默认取最近构建的那份，并先用 -t 验它认不认 proxy_split_failover（见 pick_exe 的说明）。
注意：本机不要与回归套件或构建同时跑。
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

sys.path.insert(0, os.path.join(B.ROOT, "tools"))
from proxy_split_e2e import split_id          # 同一份 murmur 移植，保证与网关、与 E2E 同口径

try:                       # Windows 控制台默认按本地代码页输出，中文诊断会成乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = B.ROOT
CONF_DIR = os.path.join(ROOT, "conf")
PS_CONF = os.path.join(CONF_DIR, "bench_proxy_split.conf")
PS_CONF_REL = os.path.join("conf", "bench_proxy_split.conf")
GW_PORT = 8710
BE_PORTS = (9201, 9202)

# 与 conf/bench_proxy_split.conf 逐条对齐：(档, 说明, path, split 变量名, 键模板)
# split 为 None = 这行没有分流，窗口内分流账本必须一动不动。
ROWS = [
    ("floor",   "单节点池 + 字面量 proxy_pass",      "/ps/floor",  None,      None),
    ("literal", "双节点池 + 字面量（改动前基线）",    "/ps/literal", None,     None),
    ("lithdr",  "字面量 + 同样两条定长上游头",       "/ps/lithdr", None,      None),
    ("const",   "常量键：只有哈希落桶与账本",        "/ps/const",  "psConst", "bench"),
    ("hdr",     "请求头键：再叠每请求展开键模板",    "/ps/hdr",    "psHdr",   "${http_x_split_key}"),
    ("two",     "真实形状：两个版本各一个池",        "/ps/two",    "psTwo",   "${http_x_split_key}"),
    ("off",     "同 two + proxy_split_failover off", "/ps/off",    "psOff",   "${http_x_split_key}"),
]

# conf 里每条 split 的（声明顺序的桶, * 兜底）——参考实现用来预测某个键落哪一路
SPLITS = {
    "psConst": ([(50.0, "psLit")], "psLit"),
    "psHdr":   ([(50.0, "psLit")], "psLit"),
    "psTwo":   ([(50.0, "psA")], "psB"),
    "psOff":   ([(50.0, "psA")], "psB"),
}
ROLES = ("routed", "bled", "down", "empty")
HDR_KEY = "X-Split-Key"
# 计时窗口固定用这一个键：两台后端承接的量仍然与 literal 行一致，只是账本全落在同一条
# target 上，脚本据此把"请求数 == 那一路的转发增量"对死。
TIMED_KEY = "bench"


def ref_bucket(dest, key):
    """网关的落桶算法：权重按声明顺序累加（×100 换成万分比），落空取 *。"""
    buckets, star = SPLITS[dest]
    idv = split_id(key)
    total = 0.0
    for percent, target in buckets:
        total += percent * 100.0
        if idv < total:
            return target
    return star


BACKEND_SRC = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[1])
class B(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = json.dumps({
            "node": port,
            "split": self.headers.get("X-Split", ""),
            "served": self.headers.get("X-Split-Served", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ThreadingHTTPServer(("127.0.0.1", port), B).serve_forever()
'''


def pick_exe(explicit):
    """选二进制：显式指定 > 最近构建的那份，而且必须真的认识分流。

    为什么不照抄 bench_least_time 直接指到 release：target/release 里现在那份是上一次
    发布留下的证据产物，本功能的代码不在里面。而 `-t` 对未知指令只**告警**不失败
    （那条口径本身是对的：配置里写错一个指令名不该挡住启动），所以 -t 退出码 0 完全
    不代表它认得 proxy_split_failover —— 老二进制照样过 -t，然后在请求期把
    `http://$psConst` 当主机名去解析，一路 502，看着像"分流很贵"，其实测的是不存在的东西。
    所以这里要正面证据：-t 的打印里必须出现这几条分流的落点描述。
    要出 release 口径的数字，得先授权重建 release，再用 --exe 指过去。
    """
    needles = ("按 $psConst 分流", "按 $psTwo 分流", "不串台")
    cands = [explicit] if explicit else [
        os.path.join(ROOT, "target", p, n)
        for p in ("release", "debug") for n in ("onrouter.exe", "onrouter")
    ]
    for c in cands:
        if not c or not os.path.exists(c):
            continue
        r = subprocess.run([c, "-t", "-c", PS_CONF_REL], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        if r.returncode != 0:
            print("  跳过 %s：-t 失败" % c)
            continue
        out = (r.stdout or "") + (r.stderr or "")
        missing = [n for n in needles if n not in out]
        if missing:
            print("  跳过 %s：-t 过了，但打印里没有 %s —— 这份构建不含本功能，"
                  "用它测出来的成本不是这条支路的成本" % (c, "、".join(missing)))
            continue
        kind = "debug" if "debug" in c.replace("\\", "/") else "release"
        print("使用网关二进制：%s（%s 构建，%s，-t 已确认认识这几条分流）" % (
            c, kind, time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(c)))))
        return c, kind
    raise SystemExit("没有一份二进制认识分流；先 cargo build -p onrouter-server --bin onrouter"
                     "（要出生产口径数字需要授权重建 release）")


def start_backends():
    ps = []
    for p in BE_PORTS:
        proc = subprocess.Popen([sys.executable, "-c", BACKEND_SRC, str(p)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ps.append(proc)
        if not B.wait_port(p, timeout=20):
            raise RuntimeError("后端 %d 起不来" % p)
    return ps


def start_gateway(exe):
    log = open(os.path.join(ROOT, "logs", "bench_proxy_split.log"), "a", buffering=1)
    p = subprocess.Popen([exe, "-c", PS_CONF_REL], cwd=ROOT, stdout=log, stderr=log)
    if not B.wait_port(GW_PORT, timeout=25):
        p.kill()
        raise RuntimeError("网关没在 %d 就绪，看 logs/bench_proxy_split.log" % GW_PORT)
    return p, log


def stop_gateway(p, log):
    p.kill()
    deadline = time.time() + 10
    while time.time() < deadline:
        if not B._listening(GW_PORT):
            break
        time.sleep(0.2)
    log.close()


def fetch(path, headers=None, timeout=15):
    c = http.client.HTTPConnection("127.0.0.1", GW_PORT, timeout=timeout)
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def metrics():
    st, body = fetch("/metrics")
    if st != 200:
        raise RuntimeError("/metrics -> %s" % st)
    return body.decode("utf-8", "replace")


def parse_metrics(text):
    """(roles, targets)：{split: {role|target: n}}"""
    roles, targets = {}, {}
    for m in re.finditer(r'onrouter_proxy_split_total\{split="([^"]+)",role="([^"]+)"\} (\d+)', text):
        roles.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    for m in re.finditer(
        r'onrouter_proxy_split_targets_total\{split="([^"]+)",target="([^"]+)"\} (\d+)', text
    ):
        targets.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    return roles, targets


def growth(before, after):
    """{split: {name: 正增量}} —— 只留非零，用来抓"这行不该碰账本却碰了"。"""
    out = {}
    for sp, cur in after.items():
        d = {name: cur[name] - before.get(sp, {}).get(name, 0)
             for name in cur if cur[name] - before.get(sp, {}).get(name, 0)}
        if d:
            out[sp] = d
    return out


def prove(label, path, split, key_tmpl):
    """第一步：这条支路真的在跑吗？用变化的键把每个分支都打中，落点与参考实现逐问核对。"""
    keys = ["prove-%s-%d" % (label, i) for i in range(48)]
    r0, t0 = parse_metrics(metrics())
    seen, errs = {}, 0
    for k in keys:
        st, body = fetch(path, {HDR_KEY: k})
        if st != 200:
            errs += 1
            continue
        j = json.loads(body.decode("utf-8", "replace"))
        served = j.get("served", "")
        seen[served] = seen.get(served, 0) + 1
        if split is not None:
            want = ref_bucket(split, k if key_tmpl == "${http_x_split_key}" else TIMED_KEY)
            if served != want or j.get("split") != want:
                raise RuntimeError("%s：键 %s 网关说这一路是 '%s'（落点 '%s'），参考实现算出 '%s'"
                                   % (label, k, j.get("split"), served, want))
    r1, t1 = parse_metrics(metrics())
    n = len(keys) - errs
    tg, rg = growth(t0, t1), growth(r0, r1)

    if split is None:
        if tg or rg:
            raise RuntimeError("%s 是字面量行，却有分流账本被写了：targets%s roles%s" % (label, tg, rg))
        print("  %-7s %-12s 全 200，分流账本一动没动（“没用到就零成本”的直接证据）" % (label, path))
        return

    if errs:
        raise RuntimeError("%s：48 请求里 %d 个不是 200" % (label, errs))
    if rg != {split: {"routed": n}}:
        raise RuntimeError("%s：结局计数增量应为 {%s: routed=%d}，实际 %s" % (label, split, n, rg))
    if tg != {split: seen}:
        raise RuntimeError("%s：落点账本 %s 与实测分支分布 %s 不一致" % (label, tg, seen))
    print("  %-7s %-12s 分支分布=%s  账本Δ=%s routed+%d" %
          (label, path, dict(sorted(seen.items())), split, n))


def n_for(level):
    return max(3000, level * 500)


def run_cell(path, split, level):
    n = n_for(level)
    hdrs = {HDR_KEY: TIMED_KEY}
    B.bench(path, max(200, n // 20), level, port=GW_PORT, headers=hdrs)   # 预热，不计时
    r0, t0 = parse_metrics(metrics())
    rps, p50, p90, p99, errs = B.bench(path, n, level, port=GW_PORT, headers=hdrs)
    r1, t1 = parse_metrics(metrics())
    rg, tg = growth(r0, r1), growth(t0, t1)
    branch = ref_bucket(split, TIMED_KEY) if split else None
    if split is None:
        if rg or tg:
            raise RuntimeError("%s 是字面量行，计时窗口内却有分流计数 %s / %s" % (path, rg, tg))
    else:
        # 自证走的是这条支路：每一问都记成 routed，且全部记在预测的那一路名下
        if rg != {split: {"routed": n - errs}}:
            raise RuntimeError("%s：计时窗口内结局 %s 与请求数 %d（err %d）不符" % (path, rg, n, errs))
        if tg != {split: {branch: n - errs}}:
            raise RuntimeError("%s：落点账本 %s != {%s: %d}" % (path, tg, branch, n - errs))
    return {"rps": rps, "p50": p50, "p90": p90, "p99": p99, "errs": errs, "n": n,
            "branch": branch, "routed": (n - errs) if split else 0}


def summarize(data, levels, passes, kind):
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
            "routed": sum(c["routed"] for c in cells),
            "branch": cells[0]["branch"],
        }
    for level in levels:
        print("\n=== 汇总 c=%d（%d 轮中位数，%s 构建）===" % (level, passes, kind))
        hdr = "%-7s %-32s %10s %9s %9s %11s %10s %8s %14s" % (
            "档", "说明", "req/s", "p50ms", "p99ms", "vs literal", "vs floor",
            "轮间极差", "窗口内 routed")
        print(hdr)
        print("-" * len(hdr))
        base = med[("literal", level)]["rps"]
        floor = med[("floor", level)]["rps"]
        for key, label, _p, _s, _t in ROWS:
            v = med[(key, level)]
            print("%-7s %-32s %8.0f/s %9.2f %9.2f %10.1f%% %9.1f%% %7.0f%% %14s%s" %
                  (key, label, v["rps"], v["p50"], v["p99"],
                   (v["rps"] / base - 1) * 100 if base else float("nan"),
                   (v["rps"] / floor - 1) * 100 if floor else float("nan"),
                   v["spread"] * 100,
                   "+%d（%s）" % (v["routed"], v["branch"]) if v["routed"] else "0",
                   "  ← 有错误，别用" if v["errs"] else ""))
    print("\n各轮 req/s（看抖动）：")
    for level in levels:
        print("  c=%-3d %s" % (level, " ".join("%s=%s" % (k, med[(k, level)]["passes"])
                                                for k, _l, _p, _s, _t in ROWS)))
    print("\n=== 归因（同一并发档逐段相减；落在轮间极差以内就不能当成成本）===")
    for level in levels:
        g = lambda k: med[(k, level)]["rps"]
        worst = max(med[(k, level)]["spread"] for k, _l, _p, _s, _t in ROWS)
        print("  c=%-3d 两条上游头 %+.1f%% ｜ 哈希落桶+账本 %+.1f%% ｜ 键展开 %+.1f%% ｜ "
              "两分支真实形状 %+.1f%% ｜ failover 声明 %+.1f%% ｜ 分流整套 %+.1f%% ｜ 本轮最大轮间极差 %.0f%%" %
              (level,
               (g("lithdr") / g("literal") - 1) * 100,
               (g("const") / g("lithdr") - 1) * 100,
               (g("hdr") / g("const") - 1) * 100,
               (g("two") / g("hdr") - 1) * 100,
               (g("off") / g("two") - 1) * 100,
               (g("two") / g("literal") - 1) * 100,
               worst * 100))
    return med


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=os.environ.get("ONROUTER_EXE"),
                    help="显式指定二进制；默认取最近构建且 -t 认得这份 conf 的那份")
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--warmup-passes", dest="warmup_passes", type=int, default=1,
                    help="不计入样本的定形轮数（本机第 1 轮系统性偏快，默认 1）")
    ap.add_argument("--levels", default="1,32", help="并发档位，如 1,8,32")
    ap.add_argument("--json", dest="json_out", default=None)
    a = ap.parse_args()

    levels = [int(x) for x in a.levels.split(",") if x.strip()]
    exe, kind = pick_exe(a.exe)
    if not os.path.exists(PS_CONF):
        raise SystemExit("缺少 %s" % PS_CONF)

    B._pool()                       # 建池放在任何计时之前
    backends = start_backends()
    proc, log = start_gateway(exe)
    data = {}
    cap = cerr = None
    try:
        cap, _p50, _p90, _p99, cerr = B.bench("/ps/literal", n_for(max(levels)),
                                              max(levels), port=BE_PORTS[0])
        print("\n=== 客户端天花板：直连单台 Python 后端（绕过网关）c=%d -> %.0f req/s err=%d ==="
              % (max(levels), cap, cerr))
        print("除 floor 外各行的池都是两台后端，所以这个数只约束单台那一侧；"
              "某档 rps 若仍随并发线性上涨，说明没饱和，差值才可信。")

        print("\n=== 第一步：先证明每一行走的是哪条支路 ===")
        for key, _label, path, split, tmpl in ROWS:
            prove(key, path, split, tmpl)

        print("\n=== 第二步：计时（每格先预热，轮内错开档位顺序）===")

        def sweep(rot, record, title):
            """跑一轮全档；record=False 的定形轮不写进样本，只用来把"第一轮特别快"这种
            系统性漂移压掉（本机实测：同一档第 1 轮比后面几轮高 5~20%，留着会让归因失真）。
            rot 连着算，定形轮与计时轮才不会都用同一个起始档位。"""
            order = ROWS[rot % len(ROWS):] + ROWS[:rot % len(ROWS)]
            print("--- %s（顺序：%s）---" % (title, ",".join(r[0] for r in order)))
            for key, _label, path, split, _tmpl in order:
                for level in levels:
                    cell = run_cell(path, split, level)
                    if record:
                        data.setdefault((key, level), []).append(cell)
                        print("  %-7s c=%-3d %9.0f/s p50=%7.2fms p99=%7.2fms err=%-2d 窗口Δ=%s" %
                              (key, level, cell["rps"], cell["p50"], cell["p99"], cell["errs"],
                               "routed+%d 落点=%s" % (cell["n"] - cell["errs"], cell["branch"])
                               if split else "无分流计数"))

        for p in range(a.warmup_passes):
            sweep(p, False, "定形轮 %d/%d（不计入样本）" % (p + 1, a.warmup_passes))
        for p in range(a.passes):
            sweep(a.warmup_passes + p, True, "计时第 %d 轮" % (p + 1))
    finally:
        if B._POOL is not None:
            B._POOL.terminate()
        stop_gateway(proc, log)
        for b in backends:
            b.kill()

    med = summarize(data, levels, a.passes, kind)
    out = a.json_out or os.path.join(ROOT, "bench_proxy_split_%s.json" % time.strftime("%Y%m%d"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"exe": exe, "build": kind, "levels": levels, "passes": a.passes,
                   "timed_key": TIMED_KEY, "n_per_cell": {str(l): n_for(l) for l in levels},
                   "client_ceiling_rps": cap,
                   "median": {"%s|%d" % k: v for k, v in med.items()},
                   "raw": {"%s|%d" % k: [c["rps"] for c in v] for k, v in data.items()}},
                  f, ensure_ascii=False, indent=1, default=str)
    print("\n原始数据已写 %s" % out)


CAVEATS = """
口径说明（写结论时必须带上）：
1. 一台 Windows 机、一个二进制、一个 vhost 七条 location；七行的 upstream 形状刻意一致
   （psLit/psA/psB 都是同样两台后端，floor 只有一台），后端是同一份 Python 源码起的两个进程。
2. 二进制是哪一种必须跟着数字一起说：debug 构建的绝对值不能和任何 release 基线比，
   只能看同一轮内各档的相对差；要出生产口径的数字得授权重建 release 再用 --exe 指过去。
   没有重跑 release 之前，本功能的结论只写到"相对差"这一层。
   另外 `-t` 对未知指令只告警不失败，所以脚本不拿退出码当证据：它要求 -t 的打印里
   真的出现这几条分流的落点描述，否则那份构建压根没有这段代码，测出来的差是假的。
3. 字面量三行（floor/literal/lithdr）在计时窗口内分流账本增量必须为 0，脚本是直接断言的：
   这就是"没用到就零成本"的证据，不是靠读代码说的。lithdr 那行专门用来把"分流各行要带
   两条归属请求头"的成本从机制成本里分出去——归属头是这套设计的证据面，但它不是哈希落桶。
4. 计时窗口内 %s 固定为 "%s"，所以每一问都落同一分支（脚本按参考实现预测那一路，
   并把"该路转发增量 == 请求数"对死）；分支分布的验证在第一步用 48 个变化的键做。
5. 分位数是各压测进程分位数按完成数加权平均，req/s 用父进程墙钟（下限）。
   只测 keep-alive、GET、明文 HTTP/1.1、小 body；TLS、大 body、WS 升级、POST 未覆盖。
6. 后端是 Python 单进程线程池：某档之间落在轮间极差以内的差更可能是后端与调度抖动，
   不是这段代码的成本；只有稳定复现、且明显大于极差的差才写进结论。
7. 默认先跑 1 轮不计入样本的定形轮：本机第 1 轮普遍比后面几轮高 5~20%%（客户端进程与两台
   后端还没进稳定状态），留着会让"哪一档更贵"随起始顺序摆动。归因的每一段都要同时看
   汇总表右侧的轮间极差：极差比那段差大，就只能写"没测出稳定差值"。
""" % (HDR_KEY, TIMED_KEY)

if __name__ == "__main__":
    main()
    print(CAVEATS)
