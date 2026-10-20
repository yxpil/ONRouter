# -*- coding: utf-8 -*-
# 队列学习（按 key 的突发形状 → 自适应排队上界）E2E。
#
# 证明了什么（同一个进程、同一批 10r/s burst=0 的限流区，只改"超限之后怎么办"）：
#   1) 默认关闭（plain）：一股 12 个并发只放 1 个，其余 429 带 Retry-After，
#      且 /metrics 里**没有**这个区的队列行——没开队列就不编数字。
#   2) 开队列不学（stat）：同样 12 个并发放出 1 + depth(8) = 9 个，
#      被排队的那些**真的晚了**几百毫秒（逐个测时延），队列仍然是有界的（仍有 429）。
#      放出的数量与"排进名额的数量"逐个对得上：排队时在判定这一刻就把这一格的令牌
#      预留掉（记成欠账），所以排上队的一定等到，不会"等完了再吃 429"。
#   3) 开学习（learn）：冷 key 只给 depth_min=1（放出约 2 个）；
#      等这股突发结束、配置一个字不改，再来同样一股 → 放出 9 个，
#      同时 learned 深度指标从 0 跳到 >= 8。这才是"自动调 queue 深度"的证据，
#      而不是把 depth 直接调大：天花板仍是运维给的 8。
#   4) 持续洪水（间隔都小于 gap_cap、累计越过 depth*4）：学到的深度重新归零，
#      429 大量出现——队列不会被攻击者当缓冲用。
#   5) 内存账：整张突发表 <= 声明的 16k，且与进程级账本 used 完全一致；
#      没开学习的 stat 区表字节为 0（配了队列没配学习 = 看板看得出来）。
#   6) 热重载把预算调到小于表大小：队列照旧工作（退回配置天花板 8），
#      表被如实放掉（used 归 0），日志说清了为什么。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/queue_learning_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "queue_learning.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "queue_learning_err.log")
OUT_LOG = os.path.join(ROOT, "logs", "queue_learning_out.log")

BACKEND_PORT = 18281
GW_PORT = 18280
BASE = f"http://127.0.0.1:{GW_PORT}"

BURST = 12           # 每股并发的请求数，必须大于 depth(8)+1
results = []
lock = threading.Lock()
served = {}

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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


def request(path, timeout=10):
    req = urllib.request.Request(BASE + path, method="GET")
    t0 = time.monotonic()
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace"), time.monotonic() - t0
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace"), time.monotonic() - t0
    except Exception as e:
        return 0, {}, str(e), time.monotonic() - t0


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def metrics_body():
    _, _, body, _ = request("/metrics")
    return body


def metric(body, name, **labels):
    """取一个 Prometheus 指标的数值。多标签写成 {a="x",b="y"}（一对花括号、逗号分隔）。"""
    if labels:
        name += "{" + ",".join('%s="%s"' % (k, v) for k, v in labels.items()) + "}"
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line == name or line.startswith(name + " "):
            return float(line.split()[-1])
    return None


def metric_debug(body, name):
    return [l for l in body.splitlines() if l.startswith(name)]


def queued_events(body, zone):
    """该区累计"排上队"的次数（单调递增，所以成对取差值才是这一股的数据）。"""
    return int(metric(body, "onrouter_queue_events_total", zone=zone, role="queued") or 0)


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        with lock:
            served[path] = served.get(path, 0) + 1
            n = served[path]
        body = f"{path.strip('/')} count={n}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def burst(prefix, n, tag):
    """并发打 n 个请求（各自独立连接、独立 URL），返回 (放行数, 429 数, 最慢放行时延)。"""
    out = []

    def one(i):
        out.append(request(f"{prefix}{tag}{i}"))

    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.monotonic() - t0
    ok = [r for r in out if r[0] == 200]
    busy = [r for r in out if r[0] == 429]
    slowest = max((r[3] for r in ok), default=0.0)
    return len(ok), len(busy), slowest, wall, out


def wait_metric(pred, timeout=8.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = metrics_body()
        if pred(last):
            return last
        time.sleep(0.1)
    return last


def write_conf(text):
    """改写主配置触发热重载（reload 200ms 轮询 mtime）。"""
    time.sleep(0.05)
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        os.utime(CONF, None)


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    original = open(CONF, encoding="utf-8").read()

    # 1) -t：认识新指令、给出队列概况，并拒绝引用未声明的区
    tproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(CONF, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    tout = (tproc.stdout or "") + (tproc.stderr or "")
    check("-t 通过", tproc.returncode == 0, tout[-500:])
    for d in ("limit_req_queue", "limit_req_learning", "learning", "learning_memory_budget"):
        check(f"-t 认识 {d}", f"未知指令 '{d}'" not in tout, "-t 把它报成了未知指令")
    check("-t 打印队列概况", "限流队列" in tout and "zone=stat" in tout and "zone=learn" in tout, tout[-400:])
    check("-t 打印学习预算", "limit_req_learning zone=learn" in tout, tout[-400:])
    bad = os.path.join(ROOT, "conf", "queue_learning_bad.conf")
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write(original.replace("limit_req_queue stat", "limit_req_queue ghost", 1))
    bproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(bad, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    bout = (bproc.stdout or "") + (bproc.stderr or "")
    check("-t 拒绝引用未声明的队列区", bproc.returncode != 0 and "ghost" in bout, bout[-300:])
    os.remove(bad)

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    for stale in (ERR_LOG, OUT_LOG):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping")[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit(f"!! onrouter 未就绪（端口 {GW_PORT}/{BACKEND_PORT} 被占用？看 logs/queue_learning_out.log）")

        # ---- 2) 默认关闭：超限即拒，且看板不给没开队列的区编数字 ----
        ok1, busy1, slow1, wall1, out1 = burst("/plain/", BURST, "p")
        check("未开队列：一股并发只放 1 个（等价 nodelay）", ok1 == 1, f"实放 {ok1}")
        check("未开队列：其余全部 429", busy1 == BURST - 1, f"429={busy1}")
        ra = [hdr(h, "retry-after") for st, h, _b, _t in out1 if st == 429]
        check("未开队列：429 带 Retry-After", all(v for v in ra) and len(ra) == busy1, f"{ra[:3]}")
        m = metrics_body()
        check(
            "未开队列：/metrics 不渲染这个区的队列行",
            metric(m, "onrouter_queue_depth", zone="plain", kind="max") is None,
            f"同名行 {metric_debug(m, 'onrouter_queue_depth')}",
        )

        # ---- 3) 开队列不学：固定 depth，排队真的要等，队列仍有界 ----
        q0 = queued_events(metrics_body(), "stat")
        ok2, busy2, slow2, wall2, _o2 = burst("/stat/", BURST, "s")
        m = metrics_body()
        dq = queued_events(m, "stat") - q0
        check("固定队列：这一股排进了 depth=8 个名额", dq == 8, f"实际 {dq}")
        check("固定队列：放出的 = 1 + 排队数（排上队的一个都没在等完后被拒）", ok2 == 1 + dq, f"实放 {ok2} 排队 {dq}")
        check("固定队列：排不下仍然拒（不是无限吸收）", busy2 >= 1, f"429={busy2}")
        check(f"固定队列：被排队的请求真的晚了（最慢 {slow2*1000:.0f}ms >= 300ms）", slow2 >= 0.3, "")
        wt = metric(m, "onrouter_queue_wait_ms_total", zone="stat")
        check("指标：stat 区累计排队时长 >= 1000ms", wt is not None and wt >= 1000, f"实际 {wt}")
        check(
            "指标：stat 区没在学（表 0 字节、learned 深度 0）",
            metric(m, "onrouter_queue_table_bytes", zone="stat") == 0
            and metric(m, "onrouter_queue_depth", zone="stat", kind="learned") == 0,
            f"同名行 {metric_debug(m, 'onrouter_queue_table_bytes')}",
        )
        check("指标：stat 区深度上界就是配置值 8", metric(m, "onrouter_queue_depth", zone="stat", kind="max") == 8)

        # ---- 4) 学习：冷 key 只给下界 ----
        lq0 = queued_events(metrics_body(), "learn")
        ok3, busy3, slow3, _w3, _o3 = burst("/learn/", BURST, "a")
        m = metrics_body()
        lq1 = queued_events(m, "learn")
        check("学习：冷 key 只给 depth_min=1（放出 <=3，对比固定队列区的 9）", 2 <= ok3 <= 3, f"实放 {ok3}")
        check("学习：冷 key 这一股排进 1~2 个（下界 1 + 醒来腾出的名额）", 1 <= lq1 - lq0 <= 2, f"排队 {lq1 - lq0}")
        check("学习：冷 key 的 429 明显多于固定队列区", busy3 >= BURST - 4, f"429={busy3}")
        m = metrics_body()
        check("学习：还没结束任何突发时 learned 深度为 0", metric(m, "onrouter_queue_depth", zone="learn", kind="learned") == 0,
              f"同名行 {metric_debug(m, 'onrouter_queue_depth')}")

        # 这股突发结束（间隔必须大于 gap_cap = 2 * 令牌周期 = 200ms）
        time.sleep(0.30)
        bq0 = queued_events(m, "learn")
        ok4, busy4, slow4, _w4, _o4 = burst("/learn/", BURST, "b")
        m = metrics_body()
        dq4 = queued_events(m, "learn") - bq0
        check("学习：同样的配置，这一股排进了 8 个名额（第一股只有 1）", dq4 == 8, f"实际 {dq4}")
        check("学习：第二股放出 1 + 8 = 9 个（第一股只有 2 个），排上的全都等到了", ok4 == 1 + dq4, f"实放 {ok4} 排队 {dq4}")
        check(f"学习：第二股同样真的排了队（最慢 {slow4*1000:.0f}ms >= 250ms）", slow4 >= 0.25, "")
        learned = metric(m, "onrouter_queue_depth", zone="learn", kind="learned")
        check("指标：learned 深度跳到 >= 8（学到的突发长度）", learned is not None and learned >= 8, f"实际 {learned}")
        adj = metric(m, "onrouter_queue_depth_adjust_total", zone="learn")
        check("指标：深度改写过并计数", adj is not None and adj >= 1, f"实际 {adj}")
        tb = metric(m, "onrouter_queue_table_bytes", zone="learn")
        check("指标：整张突发表 <= 声明的 16k", tb is not None and 0 < tb <= 16 * 1024, f"实际 {tb}")
        used = metric(m, "onrouter_learning_memory_bytes", role="used")
        check("指标：进程级账本 used 与表字节完全一致（本 conf 只有队列在学）", used == tb, f"used={used} table={tb}")
        check("指标：预算够用，没有申领失败", metric(m, "onrouter_learning_budget_denied_total") == 0)

        # ---- 5) 持续洪水：越过 depth*4 就把记忆清零 ----
        # 必须并发打：串行请求的间隔会被自己的排队时长拉开（超过 gap_cap 就不算洪水了），
        # 密集到达才是真实攻击形状。8 路 × 10 个 = 80 个，足够越过洪水线 32。
        counts = [0, 0]  # [放行, 429]

        def hammer(tid):
            for i in range(10):
                st, _h, _b, _t = request(f"/learn/x{tid}-{i}")
                with lock:
                    counts[0 if st == 200 else 1] += 1
                time.sleep(0.002)

        ths = [threading.Thread(target=hammer, args=(t,)) for t in range(8)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        m = metrics_body()
        learned2 = metric(m, "onrouter_queue_depth", zone="learn", kind="learned")
        check("洪水：深度被打回低位（远不及学到的 8+）", learned2 is not None and learned2 < 8, f"实际 {learned2}")
        check("洪水：429 占绝大多数（队列没被当缓冲）", counts[1] >= 40, f"放 {counts[0]} / 拒 {counts[1]}")
        # 收手后再来同样一股：惩罚的落点是行为，不只是看板
        time.sleep(0.30)
        ok6, _b6, _s6, _w6, _o6 = burst("/learn/", BURST, "d")
        check("洪水后：同样一股只放出下界水平（<= 4，对比洪水前的 9）", ok6 <= 4, f"实放 {ok6}")

        # ---- 6) 热重载把预算调到小于表大小：退回配置天花板，表如实放掉 ----
        write_conf(original.replace("learning_memory_budget 64k;", "learning_memory_budget 8k;", 1))
        shrunk = wait_metric(lambda b: metric(b or "", "onrouter_queue_table_bytes", zone="learn") == 0)
        check(
            "热重载：预算不足时放掉突发表",
            metric(shrunk or "", "onrouter_queue_table_bytes", zone="learn") == 0,
            f"实际 {metric(shrunk or '', 'onrouter_queue_table_bytes', zone='learn')}",
        )
        check("热重载：账本 used 归零", metric(shrunk or "", "onrouter_learning_memory_bytes", role="used") == 0)
        # 排队预留出去的令牌是欠账，必须等它按速率补回来（10r/s → 最坏 -19 格 ≈ 2s），
        # 否则这一股测的是"洪水还没还清"而不是"降级后的天花板"。
        time.sleep(2.5)
        ok5, busy5, slow5, _w5, _o5 = burst("/learn/", BURST, "c")
        check("热重载：没在学时队列仍按配置天花板放行（>= 9）", ok5 >= 9, f"实放 {ok5}")
        check("热重载：降级不影响可用性（仍有 429，队列仍有界）", busy5 >= 1, f"429={busy5}")

        write_conf(original)
        back = wait_metric(lambda b: metric(b or "", "onrouter_queue_table_bytes", zone="learn") > 0)
        check("热重载：恢复预算后重新建表", metric(back or "", "onrouter_queue_table_bytes", zone="learn") > 0,
              "没重建突发表")

        logf.flush()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()
        write_conf(original)

    raw = ""
    for p in (ERR_LOG, OUT_LOG):
        if os.path.exists(p):
            raw += open(p, encoding="utf-8", errors="replace").read()
    check("启动日志说明学了什么", "limit_req_learning zone=learn" in raw, "日志里看不到队列学习概况")
    check("启动日志给出队列概况", "队列 depth=" in raw or "限流队列" in raw, "日志里看不到队列上界")
    check("降级日志说明了预算收敛", "放掉区 'learn'" in raw, "预算调小后没写放表原因")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 队列学习 E2E: {passed}/{total} passed ====")
    print(f"     后端共收到 {sum(served.values())} 次回源（{len(served)} 个路径）")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
