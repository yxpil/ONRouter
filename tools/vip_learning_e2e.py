# -*- coding: utf-8 -*-
# 重要客户学习（VIP 信誉评分 → 队列优先级 + 缓存驻留）E2E。
#
# 证明了什么（同一个进程、同一份配置，只区分"这个客户端地址有没有信誉"）：
#   1) 没有信誉的地址：突发学习只教到"长度 1"，所以一股 9 个并发只放出 2 个（1 放行 + 1 排队），
#      其余 429；它因此攒下的分数也够不着晋升门槛（队列名额是"欠账换来的"，排队不加分）。
#   2) 守规矩走一段的地址：分数越过 min=10 后晋升（onrouter_vip_clients 从 0 变 1），
#      同样一股 9 个并发放出 9 个（排队 8 = 运维给的天花板），一个 429 都没有。
#      注意这只改变"排几个"，速率没变——排上队的仍按同一速率逐个放行。
#   3) 它替自己写入的缓存对象在频率草图里加权（retained 计数 +1），于是后面 7 次"更热的新
#      对象换掉更冷的旧对象"的冲刷里：由无信誉地址写入的同条件对象被换掉了，它还在。
#   4) 信誉不豁免行为：晋升过的地址一旦冲刷，429 照样扣分，两次就掉级
#      （demoted 计数、vip_clients 回到 0）；它刚才那股被记下的突发深度（>= 8）也会被
#      洪水线（depth*4=32）打回下界，之后同样一股只放出 depth_min 水平。
#   5) 内存账：信誉表固定大小（8k 申领 → 682 个 12 字节槽位），与突发表、频率草图一起
#      记在同一本进程级账上，总额 <= learning_memory_budget，且没有一次申领失败。
#   6) 热重载：去掉 vip_learning 后表被如实放掉（/metrics 里那些行整段消失，日志说明原因），
#      限流与队列本身不受影响；配置恢复后表重新建起来。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/vip_learning_e2e.py
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
CONF = os.path.join(ROOT, "conf", "vip_learning.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "vip_learning_err.log")
ACCESS_LOG = os.path.join(ROOT, "conf", "logs", "vip_learning_access.log")
OUT_LOG = os.path.join(ROOT, "logs", "vip_learning_out.log")

BACKEND_PORT = 18291
GW_PORT = 18290
BASE = f"http://127.0.0.1:{GW_PORT}"

# 三个虚拟客户地址：realip 之后 $remote_addr 就是它们，信誉与突发形状都按这个 key 记
STRANGER = "203.0.113.10"
VIP = "203.0.113.40"
PLAIN = "203.0.113.50"
LATE = "203.0.113.80"

BURST = 9              # = depth(8) + 1：VIP 应当一个不落地吸收，没信誉的只放出 2 个
MIN_SCORE = 10         # 与 conf 里 vip_learning min=10 一致
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


def request(path, timeout=10, xff=None):
    req = urllib.request.Request(BASE + path, method="GET")
    if xff:
        req.add_header("X-Forwarded-For", xff)
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
    """该区累计"排上队"的次数（单调递增，取差值才是这一股的数据）。"""
    return int(metric(body, "onrouter_queue_events_total", zone=zone, role="queued") or 0)


def vip_events(body, role):
    return int(metric(body, "onrouter_vip_events_total", role=role) or 0)


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


def burst(prefix, n, tag, xff):
    """并发打 n 个请求（各自独立连接、独立 URL），返回 (放行数, 429 数, 最慢放行时延, 状态列表)。"""
    out = []

    def one(i):
        out.append(request(f"{prefix}{tag}{i}", xff=xff))

    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok = [r for r in out if r[0] == 200]
    busy = [r for r in out if r[0] == 429]
    slowest = max((r[3] for r in ok), default=0.0)
    return len(ok), len(busy), slowest, [r[0] for r in out]


def polite(prefix, n, xff, gap=0.25):
    """按速率守规矩地走：每次间隔都大于 gap_cap(200ms)，所以既不会被拒、
    也不会让突发学习把这个 key 教成"长突发"（学到的长度只会是 1）。"""
    codes = []
    for i in range(n):
        st, _h, _b, _t = request(f"{prefix}q{i}", xff=xff)
        codes.append(st)
        time.sleep(gap)
    return codes


def cache_status(path, xff=None):
    st, hs, body, _t = request(path, xff=xff)
    return hdr(hs, "X-Cache-Status"), st, body


def wait_metric(pred, timeout=10.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = metrics_body()
        if pred(last):
            return last
        time.sleep(0.1)
    return last


def wait_access_line(addr, timeout=5.0):
    """访问日志的首字段就是 $remote_addr，用它确认 realip 真的改写了客户端地址。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(ACCESS_LOG, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith(addr + " "):
                        return line.rstrip("\n")
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return None


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

    # ---- 1) -t：认识 vip_learning、给出信誉概况，坏参数只告警不否决 ----
    tproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(CONF, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    tout = (tproc.stdout or "") + (tproc.stderr or "")
    check("-t 通过", tproc.returncode == 0, tout[-500:])
    check("-t 认识 vip_learning", "未知指令 'vip_learning'" not in tout, "-t 把它报成了未知指令")
    check("-t 打印信誉概况", "vip_learning 信誉表 table=8192 B" in tout and "min=10/255" in tout, tout[-400:])
    check("-t 同时打印队列与缓存的学习概况",
          "limit_req_learning zone=vip" in tout and "proxy_cache_learning zone=rc" in tout, tout[-400:])
    bad = os.path.join(ROOT, "conf", "vip_learning_bad.conf")
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write(original.replace("vip_learning table=8k min=10 decay=30s;",
                                 "vip_learning table=8k min=0 decay=30s bogus=1;", 1))
    bproc = subprocess.run(
        [exe, "-t", "-c", os.path.relpath(bad, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    bout = (bproc.stdout or "") + (bproc.stderr or "")
    check("-t：min=0 只告警不否决", bproc.returncode == 0, bout[-300:])
    check("-t：越界的 min 被点名", "min='0'" in bout, bout[-300:])
    check("-t：不认识的参数被点名", "不认识的参数 'bogus=1'" in bout, bout[-300:])
    os.remove(bad)

    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    for stale in (ERR_LOG, ACCESS_LOG, OUT_LOG):
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
            raise SystemExit(f"!! onrouter 未就绪（端口 {GW_PORT}/{BACKEND_PORT} 被占用？看 logs/vip_learning_out.log）")

        # ---- 2) realip 生效：同一个进程要能区分两个客户端地址 ----
        request("/probe", xff=STRANGER)
        line = wait_access_line(STRANGER)
        check("realip 生效：访问日志首字段是虚拟客户地址（不是 127.0.0.1）", line is not None,
              f"访问日志 {ACCESS_LOG} 里看不到 {STRANGER}")
        m = metrics_body()
        check("指标：信誉表已建（8k 申领 → 682 个 12 字节槽位）",
              metric(m, "onrouter_vip_table_bytes") == 682 * 12
              and metric(m, "onrouter_vip_slots", kind="total") == 682,
              f"同名行 {metric_debug(m, 'onrouter_vip')}")
        check("指标：晋升门槛与衰减时长如实渲染",
              metric(m, "onrouter_vip_score", kind="threshold") == MIN_SCORE
              and metric(m, "onrouter_vip_decay_ms") == 30_000,
              f"同名行 {metric_debug(m, 'onrouter_vip_score')}")
        check("指标：开局没有任何重要客户", metric(m, "onrouter_vip_clients") == 0,
              f"同名行 {metric_debug(m, 'onrouter_vip_clients')}")

        # ---- 3) 没信誉的地址：一股并发只放出下界水平 ----
        codes_s = polite("/vip/", 4, STRANGER)
        check("没信誉的地址：守规矩的 4 个请求全部放行", all(c == 200 for c in codes_s), f"{codes_s}")
        m = metrics_body()
        check("指标：4 次放行不到晋升门槛", metric(m, "onrouter_vip_clients") == 0
              and metric(m, "onrouter_vip_score", kind="max") == 4,
              f"分数行 {metric_debug(m, 'onrouter_vip_score')}")
        s0 = queued_events(metrics_body(), "vip")
        ok_s, busy_s, slow_s, _cs = burst("/vip/", BURST, "s", STRANGER)
        m = metrics_body()
        dq_s = queued_events(m, "vip") - s0
        check("没信誉：这一股只排进 depth_min=1 个名额", dq_s == 1, f"实际 {dq_s}")
        check("没信誉：放出 1 + 1 = 2 个（对比下一组的 9 个）", ok_s == 1 + dq_s, f"实放 {ok_s}")
        check("没信誉：其余全部 429", busy_s == BURST - ok_s, f"429={busy_s}")
        check("指标：429 会扣信誉，一次都晋升不了",
              vip_events(m, "rejected") >= BURST - ok_s
              and metric(metrics_body(), "onrouter_vip_clients") == 0,
              f"事件行 {metric_debug(m, 'onrouter_vip_events_total')}")

        # ---- 4) 守规矩的地址：越过门槛就晋升 ----
        check("候选：稀疏流量全部放行", all(c == 200 for c in polite("/vip/", MIN_SCORE + 2, VIP)), "")
        promoted = wait_metric(lambda b: metric(b or "", "onrouter_vip_clients", ) == 1)
        check("学习：这个地址被学成了重要客户（vip_clients 0 → 1）",
              metric(promoted or "", "onrouter_vip_clients") == 1,
              f"同名行 {metric_debug(promoted or '', 'onrouter_vip_clients')}")
        check("学习：晋升有计数", vip_events(promoted or "", "promoted") >= 1, "")

        # ---- 5) 同一股并发，学到的形状同样是"长度 1"，差别只在信誉 ----
        v0 = queued_events(metrics_body(), "vip")
        ok_v, busy_v, slow_v, codes_v = burst("/vip/", BURST, "v", VIP)
        m = metrics_body()
        dq_v = queued_events(m, "vip") - v0
        check("重要客户：同样的天花板 8 真的用上了（排进 8 个名额）", dq_v == 8, f"实际 {dq_v}")
        check("重要客户：一股 9 个全部放出，一个 429 都没有", ok_v == 1 + dq_v and busy_v == 0,
              f"实放 {ok_v} 429={busy_v} 状态={codes_v}")
        check(f"重要客户：排上队的真的晚了（最慢 {slow_v*1000:.0f}ms >= 300ms）", slow_v >= 0.3, "")
        check("重要客户：排队不加分，但守规矩的放行加分（分数还在门槛之上）",
              metric(m, "onrouter_vip_clients") == 1
              and metric(m, "onrouter_vip_score", kind="max") >= MIN_SCORE + 3,
              f"同名行 {metric_debug(m, 'onrouter_vip_score')}")
        check("指标：排队事件如实计入信誉账（role=queued 只记录不打分）",
              vip_events(m, "queued") >= 9, f"实际 {vip_events(m, 'queued')}")
        # 排队的令牌是欠账（最坏 -8 格 → 10r/s 下约 0.8s），等它还清再往下测
        time.sleep(1.5)

        # ---- 6) 缓存驻留：VIP 写入的对象扛得住冲刷，同条件的普通对象扛不住 ----
        cs, st, _b = cache_status("/r/vip-obj", xff=VIP)
        check("驻留：重要客户的对象写入（MISS → 存储）", st == 200 and cs == "MISS", f"{st} {cs}")
        m = metrics_body()
        check("驻留：这次写入记了一次加权（retained 计数 +1）",
              metric(m, "onrouter_cache_learning_events_total", zone="rc", role="retained") == 1,
              f"同名行 {metric_debug(m, 'onrouter_cache_learning_events_total')}")
        cs, st, _b = cache_status("/r/plain-obj", xff=PLAIN)
        check("驻留：对照组对象同样写入（MISS）", st == 200 and cs == "MISS", f"{st} {cs}")
        # 把 8 条容量填满（先写的最老，正落在淘汰窗口里）
        for i in range(6):
            request(f"/r/junk{i}", xff=PLAIN)
        # 7 个"访问过 3 次"的新对象：草图里 3 分，够换掉任何一个 1 分的冷对象
        for i in range(7):
            for _ in range(3):
                request(f"/h/new{i}", xff=PLAIN)
        m = metrics_body()
        ev = metric(m, "onrouter_cache_learning_events_total", zone="rc", role="evicted_cold")
        check("驻留：换位驱逐真的发生了（>= 7 次）", ev is not None and ev >= 7, f"实际 {ev}")
        cs_vip, st_vip, _b = cache_status("/r/vip-obj", xff=PLAIN)
        check("驻留：重要客户写入的对象还在（HIT）——加权买到的是驻留，不是插队",
              cs_vip == "HIT", f"实得 {cs_vip}（{st_vip}）")
        cs_plain, st_plain, _b = cache_status("/r/plain-obj", xff=PLAIN)
        check("驻留：没信誉地址写入的同条件对象已被换掉（MISS）", cs_plain == "MISS",
              f"实得 {cs_plain}（{st_plain}）")
        check("驻留：对照对象被换掉时重要客户没被波及（retained 仍只有那一次）",
              metric(metrics_body(), "onrouter_cache_learning_events_total", zone="rc", role="retained") == 1,
              "")

        # ---- 7) 信誉不豁免行为：晋升过的地址冲刷照样掉级，也照样被洪水线清零 ----
        ok_h, busy_h, _sl, _ch = burst("/vip/", 20, "f", VIP)
        demoted = wait_metric(lambda b: metric(b or "", "onrouter_vip_clients") == 0)
        check("掉级：重要客户冲刷后跌回门槛之下（vip_clients 1 → 0）",
              metric(demoted or "", "onrouter_vip_clients") == 0,
              f"同名行 {metric_debug(demoted or '', 'onrouter_vip_clients')}")
        check("掉级：掉级有计数", vip_events(demoted or "", "demoted") >= 1, "")
        check("掉级：扣分来自 429 而不是排队",
              vip_events(metrics_body(), "rejected") >= busy_h,
              f"rejected={vip_events(metrics_body(), 'rejected')} 429={busy_h}")
        # 这股 20 个的突发（第一下与上一股之间隔了 >gap_cap）会被当成"形状"记下来：
        # 这就是马上要被洪水线抹掉的那个深度，所以先取一次证据再冲刷。
        learned_pre = metric(metrics_body(), "onrouter_queue_depth", zone="vip", kind="learned")
        check("冲刷前：VIP 那股突发确实被记成了深度（learned >= 8）",
              learned_pre is not None and learned_pre >= 8, f"实际 {learned_pre}")
        # 继续冲刷到越过洪水线（depth*4 = 32）：学到的突发长度与信誉一起清零
        counts = [0, 0]

        def hammer(tid):
            for i in range(8):
                st, _h, _b, _t = request(f"/vip/x{tid}-{i}", xff=VIP)
                with lock:
                    counts[0 if st == 200 else 1] += 1
                time.sleep(0.002)

        ths = [threading.Thread(target=hammer, args=(t,)) for t in range(8)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        check("冲刷：429 大量出现（深队列不是攻击者的缓冲）", counts[1] >= 20,
              f"放 {counts[0]} / 拒 {counts[1]}")
        m = metrics_body()
        learned = metric(m, "onrouter_queue_depth", zone="vip", kind="learned")
        # learned 是整个区的最大值，不是这个地址的：守规矩的那些地址合法地留着
        # "稀疏流量 = 长度 1" 的记忆，所以这里能证明的是——刚才那个 >= 8 的深度没了。
        check("冲刷：越过洪水线（depth*4=32）后学到的突发深度被打回下界",
              learned is not None and learned <= 1 and learned_pre is not None and learned < learned_pre,
              f"实际 {learned}（冲刷前 {learned_pre}）同名行 {metric_debug(m, 'onrouter_queue_depth')}")
        time.sleep(2.5)
        # 掉级 + 突发记忆被洪水线抹掉之后再打同样一股：只放出下界水平
        ok_g, busy_g, _sg, _cg = burst("/vip/", BURST, "g", VIP)
        check("掉级后：同样一股只放出下界水平（<= 3，对比晋升时的 9）", ok_g <= 3, f"实放 {ok_g}")
        check("掉级后：可用性不受影响（仍有 429，队列仍有界）", busy_g >= BURST - 4, f"429={busy_g}")

        # ---- 8) 内存账：三张表记在同一本账上，总额不超配置 ----
        m = metrics_body()
        qtb = metric(m, "onrouter_queue_table_bytes", zone="vip") or 0
        skb = metric(m, "onrouter_cache_learning_sketch_bytes", zone="rc") or 0
        vtb = metric(m, "onrouter_vip_table_bytes") or 0
        used = metric(m, "onrouter_learning_memory_bytes", role="used")
        check("账本：used 就是三张表之和（没泄漏、没重复申领）",
              used == qtb + skb + vtb, f"used={used} 队列={qtb} 草图={skb} 信誉={vtb}")
        check(f"账本：三张表合计 {int(used or 0)} B <= 预算 64k", used is not None and used <= 64 * 1024, "")
        check("账本：没有一次申领失败", metric(m, "onrouter_learning_budget_denied_total") == 0, "")

        # ---- 9) 热重载：去掉 vip_learning 就把表放掉，限流本身不受影响 ----
        write_conf(original.replace("vip_learning table=8k min=10 decay=30s;\n", ""))
        off = wait_metric(lambda b: metric(b or "", "onrouter_vip_table_bytes") is None)
        check("热重载：信誉表被如实放掉（/metrics 里那些行整段消失）",
              metric(off or "", "onrouter_vip_table_bytes") is None,
              f"仍在渲染 {metric_debug(off or '', 'onrouter_vip')}")
        ok_off, busy_off, _so, codes_off = burst("/vip/", BURST, "h", LATE)
        check("热重载：没信誉表不影响限流与队列（新地址仍按下界得到 1~3 个）",
              1 <= ok_off <= 4 and 500 not in codes_off, f"实放 {ok_off} 429={busy_off}")
        write_conf(original)
        back = wait_metric(lambda b: metric(b or "", "onrouter_vip_table_bytes") is not None)
        check("热重载：恢复配置后信誉表重新建起来",
              metric(back or "", "onrouter_vip_table_bytes") == 682 * 12,
              f"实际 {metric(back or '', 'onrouter_vip_table_bytes')}")
        check("热重载：账本 used 也回到三张表之和",
              metric(back or "", "onrouter_learning_memory_bytes", role="used") == qtb + skb + 682 * 12,
              f"实际 {metric(back or '', 'onrouter_learning_memory_bytes', role='used')}")

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
    check("启动日志说清了信誉表怎么学", "信誉学习：已建" in raw and "682 个槽位" in raw,
          "日志里看不到信誉表概况")
    check("启动日志同时给出学习与队列概况",
          "limit_req_learning zone=vip" in raw and "proxy_cache_learning zone=rc" in raw, "")
    check("热重载日志说明为什么放表", "放掉旧信誉表" in raw, "没写放表原因")
    check("日志里没有 panic / 没有 500 的处理线程痕迹", "panicked" not in raw, "日志里出现 panic")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 重要客户学习 E2E: {passed}/{total} passed ====")
    print(f"     后端共收到 {sum(served.values())} 次回源（{len(served)} 个路径）")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
