# -*- coding: utf-8 -*-
# 缓存学习（TinyLFU 准入 + 驱逐）E2E —— 用真实流量证明"学了到底有什么用"。
#
# 证明了什么（全部在同一个进程、同一个 8 条容量的缓存区上发生）：
#   1) 学习区（proxy_cache_learning lc）被 40 个一次性 URL 冲刷后，热对象**仍在缓存里**：
#      重复请求拿到 HIT，且后端计数没有增加（真的没回源）。
#   2) 对照区（同容量、未声明学习）被同样冲刷后热对象**已经没了**：MISS + 后端计数 +1。
#      —— 这两条一起才说明准入闸门起了作用，而不是"缓存本来就不会满"。
#   3) 被反复访问的新 key 进得来，并把最冷的那位挤出去（evicted_cold=1、被挤的那个转为 MISS）
#      —— 说明学的是"谁更热"，不是"一律拒新"。
#   4) /metrics 里的逐区账目与上面一致：学习区有草图字节、拒绝计数、驱逐计数；
#      对照区草图 0 字节（配了区没学 = 看板上看得出来）。
#   5) 热重载把 `learning on` 改成 `off`：草图立刻归还预算（sketch_bytes=0、used=0），
#      随后同样的冲刷会把热对象冲掉 —— 关闭路径在真实流量下确实是惰性的。
#   6) -t：认识这三条顶层指令、打印逐区学习概况，并且**否决**引用未声明 keys_zone 的
#      `proxy_cache_learning`（区名写错时 apply_learning 根本不会遍历到它，一行都不生效）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/learning_cache_e2e.py
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
CONF = os.path.join(ROOT, "conf", "learning_cache.conf")
# error_log/access_log 的相对路径以 conf 目录为基准（与其它套件一致）；
# 这两个文件是**追加**写的，跑之前必须删掉，否则断言可能读到上一次运行的旧证据。
ERR_LOG = os.path.join(ROOT, "conf", "logs", "learning_cache_err.log")
OUT_LOG = os.path.join(ROOT, "logs", "learning_cache_out.log")

BACKEND_PORT = 18176
GW_HOST, GW_PORT = "127.0.0.1", 18177
BASE = f"http://{GW_HOST}:{GW_PORT}"

SCAN_N = 40          # 一次性 URL 数量，必须远大于缓存区容量（1k keys_zone = 8 条）
results = []
counter_lock = threading.Lock()
hits = {}


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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path):
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(req, timeout=10)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def cache_status(path):
    st, hs, body = request(path)
    return hdr(hs, "X-Cache-Status"), body


def metrics_body():
    _, _, body = request("/metrics")
    return body


def metric(body, name, **labels):
    """取一个 Prometheus 指标的数值。多标签要写成 {a="x",b="y"}（一对花括号、逗号分隔），
    每个标签各带一对花括号是查不到行的——渲染端就是这么拼的。"""
    if labels:
        name += "{" + ",".join('%s="%s"' % (k, v) for k, v in labels.items()) + "}"
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line == name or line.startswith(name + " "):
            return float(line.split()[-1])
    return None


def metric_debug(body, name):
    """失败详情用：把同名行原样带出来，一眼分清"整段没渲染"还是"标签对不上"。"""
    return [l for l in body.splitlines() if l.startswith(name)]


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        with counter_lock:
            hits[path] = hits.get(path, 0) + 1
            n = hits[path]
        body = f"{path.strip('/')} count={n}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def count(path):
    with counter_lock:
        return hits.get(path, 0)


def write_conf(text):
    """改写主配置触发热重载（reload 200ms 轮询 mtime）；稍停以保证时间戳单调变化。"""
    time.sleep(0.05)
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
    os.utime(CONF, None)


def wait_metric(pred, timeout=8.0):
    """等某个指标达到期望值（重载是异步的，不能靠固定 sleep 判定）。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = metrics_body()
        if pred(last):
            return last
        time.sleep(0.1)
    return last


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    original = open(CONF, encoding="utf-8").read()

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    # -t 不得把这几条指令报成"未知指令"（顶层白名单回归）
    tproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(CONF, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    tout = (tproc.stdout or "") + (tproc.stderr or "")
    check("-t 通过", tproc.returncode == 0, tout[-400:])
    for d in ("learning", "learning_memory_budget", "proxy_cache_learning"):
        check(
            f"-t 认识 {d}",
            f"未知指令 '{d}'" not in tout,
            "-t 输出把它报成了未知指令",
        )
    check("-t 打印缓存学习概况", "proxy_cache_learning zone=lc" in tout, tout[-400:])
    # 引用未声明的 keys_zone：这行学习配置一行都不会生效，-t 必须否决而不是告警
    bad = os.path.join(ROOT, "conf", "learning_cache_bad.conf")
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write(original.replace("proxy_cache_learning lc", "proxy_cache_learning ghost", 1))
    bproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(bad, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    bout = (bproc.stdout or "") + (bproc.stderr or "")
    check("-t 拒绝引用未声明的缓存区", bproc.returncode != 0 and "ghost" in bout, bout[-300:])
    os.remove(bad)

    # 清掉上一轮运行的日志：日志是追加写的，留着就会把旧证据当成本轮的结论
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
            raise SystemExit("!! onrouter 未就绪（端口 18177/18176 被占用？看 logs/learning_cache_out.log）")

        # 1) 两个区各放一个热对象（各访问 3 次攒频率）
        for prefix in ("/lc/", "/lru/"):
            obj = "hot" if prefix == "/lc/" else "hotctl"
            first, _ = cache_status(f"{prefix}{obj}")
            again, body = cache_status(f"{prefix}{obj}")
            check(f"{prefix}{obj} 首次 MISS", first == "MISS", f"xcs={first}")
            check(f"{prefix}{obj} 重复 HIT", again == "HIT", f"xcs={again}")
            check(f"{prefix}{obj} 只回源一次", count(f"/{obj}") == 1, f"cnt={count('/' + obj)}")
            cache_status(f"{prefix}{obj}")

        # 2) 一次性 URL 冲刷：每个 key 只访问一次，量远大于容量
        for i in range(SCAN_N):
            cache_status(f"/lc/scan{i}")
            cache_status(f"/lru/cscan{i}")

        # 3) 决定性对比：学习区的热对象还在，对照区的已经没了
        st, _ = cache_status("/lc/hot")
        check("学习区：冲刷后热对象仍是 HIT（准入挡住了扫描流量）", st == "HIT", f"xcs={st}")
        check("学习区：热对象没有再打后端", count("/hot") == 1, f"cnt={count('/hot')}")
        st2, _ = cache_status("/lru/hotctl")
        check("对照区：同样冲刷后热对象变成 MISS（纯 LRU 被冲掉了）", st2 == "MISS", f"xcs={st2}")
        check("对照区：热对象回源了", count("/hotctl") >= 2, f"cnt={count('/hotctl')}")

        # 4) 看板与上面一致
        m = metrics_body()
        check("指标：learning 已启用", metric(m, "onrouter_learning_enabled") == 1, "看板没说是开的")
        check(
            "指标：学习区草图 65536 B（与 sketch=64k 一致）",
            metric(m, "onrouter_cache_learning_sketch_bytes", zone="lc") == 65536,
            f"实际 {metric(m, 'onrouter_cache_learning_sketch_bytes', zone='lc')}",
        )
        check(
            "指标：未声明学习的区草图 0 B（配了区没学要看得见）",
            metric(m, "onrouter_cache_learning_sketch_bytes", zone="lru") == 0,
            "对照区不该有草图",
        )
        rej = metric(m, "onrouter_cache_learning_events_total", zone="lc", role="admission_rejected")
        check(
            f"指标：准入拒绝 ≥ {SCAN_N - 8} 次",
            rej is not None and rej >= SCAN_N - 8,
            f"实际 {rej}；同名行 {metric_debug(m, 'onrouter_cache_learning_events_total')}",
        )
        check(
            "指标：预算没被拒过（1m 够用）",
            metric(m, "onrouter_learning_budget_denied_total") == 0,
            "不该出现申领失败",
        )
        used = metric(m, "onrouter_learning_memory_bytes", role="used")
        check("指标：已用预算正好是一张草图", used == 65536, f"实际 {used}")

        # 5) 更热的新 key 要进得来：反复访问 /lc/warm，它必须挤掉最冷的那位
        for _ in range(20):
            cache_status("/lc/warm")
        st3, _ = cache_status("/lc/warm")
        check("学习区：被反复访问的新 key 准入成功", st3 == "HIT", f"xcs={st3}")
        check("学习区：新 key 只回源 2 次（第 1 次太冷被拒，第 2 次够热进来）", count("/warm") == 2, f"cnt={count('/warm')}")
        # 先读驱逐计数：紧接着的 scan0 探测本身也会再准入一次，会把数字再 +1
        ev = metric(metrics_body(), "onrouter_cache_learning_events_total", zone="lc", role="evicted_cold")
        check(
            "指标：记下一次冷位驱逐",
            ev == 1,
            f"实际 {ev}；同名行 {metric_debug(metrics_body(), 'onrouter_cache_learning_events_total')}",
        )
        st4, _ = cache_status("/lc/scan0")
        check("学习区：被抢位的是最冷的那个一次性 key", st4 == "MISS", f"xcs={st4}")

        # 6) 热重载关掉学习：草图必须立刻归还，且关闭路径在真实流量下回到纯 LRU
        write_conf(original.replace("learning on;", "learning off;", 1))
        off = wait_metric(lambda b: metric(b or "", "onrouter_learning_enabled") == 0)
        check("热重载：learning off 生效（指标翻转为 0）", metric(off or "", "onrouter_learning_enabled") == 0, "指标仍是 1")
        check(
            "热重载：草图字节已归还（used=0）",
            metric(off or "", "onrouter_learning_memory_bytes", role="used") == 0,
            f"实际 {metric(off or '', 'onrouter_learning_memory_bytes', role='used')}",
        )
        check(
            "热重载：该区草图归零",
            metric(off or "", "onrouter_cache_learning_sketch_bytes", zone="lc") == 0,
            "放图不彻底",
        )
        base_hot = count("/hot")
        for i in range(SCAN_N, SCAN_N * 2):
            cache_status(f"/lc/scan{i}")
        st5, _ = cache_status("/lc/hot")
        check("热重载：关闭学习后同样的冲刷会冲掉热对象（= 纯 LRU，行为可预期）", st5 == "MISS", f"xcs={st5}")
        check("热重载：关闭后确实回到回源路径", count("/hot") == base_hot + 1, f"cnt={count('/hot')}")

        # 7) 恢复配置并确认能再学起来（重载是双向可用的，不是一次性开关）
        write_conf(original)
        back = wait_metric(lambda b: metric(b or "", "onrouter_learning_enabled") == 1)
        check("热重载：改回 learning on 后重新建图", metric(back or "", "onrouter_cache_learning_sketch_bytes", zone="lc") == 65536, "没重建草图")

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
    check("启动日志说明学了什么", "learning 已启用" in raw and "zone=lc" in raw, "日志里看不到学习概况")
    check("日志没有谎报未启用", "learning 未启用" not in raw, "开着学习却打了未启用")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 缓存学习 E2E: {passed}/{total} passed ====")
    print(f"     后端计数: {dict(sorted(hits.items())) if len(hits) < 12 else str(len(hits)) + ' 个路径'}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
