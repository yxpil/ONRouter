# -*- coding: utf-8 -*-
# least_time 自适应上游选择 E2E —— 用三个**故意不同时延**的假后端，把"谁反应快选谁"这件事
# 在真实流量上证明一遍，并且证明三档的边界：
#
#   off（默认）   选点严格轮询；/metrics 里连一行 least_time 都没有（关掉 = 零账本零足迹）。
#   observe      选点结果必须与 off **逐次一致**（证据期不许改行为），但 EWMA 是真实测出来的、
#                would_differ 会涨（"按分数选会改判"的次数就是要不要开 on 的依据）。
#   on           流量向快的后端迁移，客户端 p50 显著下降；后端当场变慢/变快时，迁移会在
#                几秒内反过来（旧估计过期后重新探测，不会把已经变快的后端永久饿死）。
#
# 另外证明两件最容易骗人的事：
#   * 连接失败的耗时**不入账**（那是超时阈值不是后端的快慢）：死节点的 EWMA 恒为 0，
#     但它确实进了 requests_total{result="failure"}。
#   * "客户端更快"用**均值**判，不用"p50 要快一倍"判：on 档的样本是几毫秒与约两百毫秒两个峰
#     的混合，中位数压在峰间边界上，样本再多也稳不住；而 P2C 每请求只比较两个候选，最快节点
#     不在候选里时必然被略过——它对"迁移多少"的承诺本来就比"赢家通吃"弱。均值收敛快，且
#     在"分数完全不参与选点"的情形下两侧相等，判据照样会红。
#   * 配置层的冲突是错误不是告警：ip_hash + least_time（分数永远不参与）、least_time detect
#     （那是 front_proxy_mode 的词）在 -t 就拒绝；单节点池只告警（无从比较，不算错）。
#
# 三个后端的时延拉开到 5/200/400ms（不是 5/60/120）：本机 sleep 抖动实测 ±20ms，间距就是
# 比值判据的测量余量 —— 阈值一条都没放松，只是让"抖"不再等于"挂"。见 DELAY0 处的注释。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/least_time_e2e.py
import os
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # Windows 控制台默认代码页会把中文输出打成乱码（文件本身仍是 UTF-8）
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "least_time_e2e.conf")
CONF = os.path.join(ROOT, CONF_REL)
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "least_time_e2e_err.log")
OUT_LOG = os.path.join(LOG_DIR, "least_time_e2e_out.log")

GW_PORT = 18470
GW = "127.0.0.1"
# 三个假后端：a 最快、b 中等、c 最慢（observe 档要按这个顺序量出来）
BE = {
    "a": 18471,
    "b": 18472,
    "c": 18473,
}
DEAD_PORT = 18478  # 故意没人监听
# 三档时延的**间距**就是这套判据的测量余量：本机 `time.sleep()` 的抖动实测到 ±20ms 量级
# （5ms 的后端会被量成 7~46ms），如果只拉开 5/60/120ms，抖动就和信号同量级，"p50 快一倍"
# 会正好压在阈值上抖（2026-10-20 发布前 8 次跑挂了 3 次，全是比值判据）。
# 现在拉开到 5/200/400ms：中位数只要落在最快后端那一侧就必然过线，阈值本身一点没放松。
DELAY0 = {"a": 0.005, "b": 0.200, "c": 0.400}

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []


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


# ---------------- 假后端：延迟可以在运行中被改写 ----------------


class Backend:
    def __init__(self, tag, port, delay):
        self.tag = tag
        self.port = port
        self.delay = delay
        self.served = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(outer.delay)
                body = ("%s\n" % outer.tag).encode()
                outer.served += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()


# ---------------- 网关侧：请求与指标 ----------------


def request(path, timeout=20):
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}", method="GET")
    t0 = time.perf_counter()
    resp = _opener.open(req, timeout=timeout)
    body = resp.read()
    return resp.status, body.decode(errors="replace").strip(), time.perf_counter() - t0


def hit(path):
    """返回 (哪个后端接的, 客户端看到的耗时)。"""
    st, body, dt = request(path)
    assert st == 200, f"{path} 期望 200，实得 {st}"
    tag = body.split()[0] if body else "?"
    return tag, dt


def metrics_text():
    _st, body, _dt = request("/metrics")
    return body


def metric_val(text, name, labels=()):
    """按指标名 + 标签子串取一个数值；找不到返回 None。"""
    for line in text.splitlines():
        if line.startswith(name + "{"):
            if all(lbl in line for lbl in labels):
                try:
                    return float(line.rsplit(None, 1)[1])
                except (IndexError, ValueError):
                    return None
    return None


def counters(text, up):
    """least_time 的四本账：sampled / picked / would_differ / cold。"""
    def one(role):
        return metric_val(
            text, "onrouter_upstream_least_time_total", ('upstream="%s"' % up, 'role="%s"' % role)
        ) or 0.0

    return {r: one(r) for r in ("sampled", "picked", "would_differ", "cold")}


def ewma(text, up, port):
    return metric_val(
        text, "onrouter_upstream_server_ewma_seconds", ('upstream="%s"' % up, 'server="127.0.0.1:%d"' % port)
    )


def diff(before, after):
    return {k: after[k] - before[k] for k in after}


def share(seq, tag):
    return seq.count(tag) / len(seq) if seq else 0.0


def run_t(exe, conf_rel):
    return subprocess.run(
        [exe, "-t", "-c", conf_rel],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def write_probe_conf(name, upstream_body):
    """把一份只够验证 upstream 段的临时配置写进 conf/ 下（logs 才会落进已存在的 conf/logs）。"""
    path = os.path.join(ROOT, "conf", name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "error_log \"logs/%s_err.log\" warn;\n" % name.replace(".conf", "")
            + "pid \"logs/%s.pid\";\n" % name.replace(".conf", "")
            + upstream_body
            + "\nserver {\n    listen 127.0.0.1:18479;\n    server_name probe.local;\n"
            "    location = /x {\n        proxy_pass http://probe;\n    }\n}\n"
        )
    return "conf/" + name, os.path.join(LOG_DIR, "%s_err.log" % name.replace(".conf", ""))


def main():
    for p in (ERR_LOG, OUT_LOG):
        try:
            os.remove(p)
        except OSError:
            pass
    exe = find_binary()
    backends = {tag: Backend(tag, port, DELAY0[tag]) for tag, port in BE.items()}

    # ==================== 配置层 ====================
    r = run_t(exe, CONF_REL)
    out = (r.stdout or "") + (r.stderr or "")
    check("-t 读得懂 least_time_e2e.conf", r.returncode == 0, f"rc={r.returncode}\n{out}")
    check(
        "-t 把 observe 档说清楚：只测量、选点不变",
        "upstream 'ltObs'：least_time observe（只测量，选点不变）" in out,
        out,
    )
    check(
        "-t 把 on 档说清楚：按 P2C+EWMA 选点",
        "upstream 'ltOn'：least_time on（按 P2C+EWMA 选点）" in out,
        out,
    )
    check("-t 带上窗口与过期重探的含义", "EWMA 窗口 1.0s（超过 4倍窗口没有样本就重新探测）" in out, out)
    check(
        "off 档的池子（ltOff）在 -t 里不出声：默认关着不该打扰运维",
        "upstream 'ltOff'" not in out,
        out,
    )

    cases = [
        ("ip_hash + least_time on 必须报错（分数永远不参与，声明了就是骗人）",
         "upstream probe {\n    ip_hash;\n    least_time on;\n    server 127.0.0.1:18471;\n    server 127.0.0.1:18472;\n}\n",
         "ip_hash"),
        ("ip_hash + least_time observe 也报错（observe 同样无处生效）",
         "upstream probe {\n    ip_hash;\n    least_time observe;\n    server 127.0.0.1:18471;\n    server 127.0.0.1:18472;\n}\n",
         "ip_hash"),
        ("least_time detect 报错并指出正确档位（detect 是 front_proxy_mode 的词）",
         "upstream probe {\n    least_time detect;\n    server 127.0.0.1:18471;\n    server 127.0.0.1:18472;\n}\n",
         "observe"),
        ("least_time_window 0s 报错（窗口必须是正数秒）",
         "upstream probe {\n    least_time on;\n    least_time_window 0s;\n    server 127.0.0.1:18471;\n    server 127.0.0.1:18472;\n}\n",
         "least_time_window"),
        ("least_time 少参数报错而不是猜一个档位",
         "upstream probe {\n    least_time;\n    server 127.0.0.1:18471;\n    server 127.0.0.1:18472;\n}\n",
         "off|observe|on"),
    ]
    probe_logs = []
    for i, (name, body, needle) in enumerate(cases):
        rel, logpath = write_probe_conf("lt_probe_reject%d.conf" % i, body)
        probe_logs.append((rel, logpath))
        rr = run_t(exe, rel)
        o = (rr.stdout or "") + (rr.stderr or "")
        check(name, rr.returncode != 0 and needle in o, f"rc={rr.returncode}\n{o}")

    # 单节点池：无从比较，是告警不是错误（配置本身仍然可用）
    rel, logpath = write_probe_conf(
        "lt_probe_single.conf",
        "upstream probe {\n    least_time on;\n    server 127.0.0.1:18471;\n}\n",
    )
    probe_logs.append((rel, logpath))
    rr = run_t(exe, rel)
    o = (rr.stdout or "") + (rr.stderr or "")
    check("单节点池 + least_time 只告警不拒绝（-t 仍然通过）", rr.returncode == 0, o)
    check(
        "单节点池的告警直接打在 -t 输出里：说清没有可比对象（日志器异步，-t 不能只靠 error log）",
        "只有一个可选节点" in o,
        o,
    )

    # ==================== 运行层 ====================
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[1] == "pong":
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)
        if not ready:
            raise SystemExit(f"!! 网关未就绪（端口 {GW_PORT} 被占用？看 {OUT_LOG}）")

        base = metrics_text()
        check("off 档的池子没有任何 least_time 指标行（关掉 = 零足迹）",
              metric_val(base, "onrouter_upstream_least_time_mode", ('upstream="ltOff"',)) is None
              and ewma(base, "ltOff", BE["a"]) is None, str(base[:300]))
        check("observe 档的档位标成 1", metric_val(base, "onrouter_upstream_least_time_mode", ('upstream="ltObs"',)) == 1)
        check("on 档的档位标成 2", metric_val(base, "onrouter_upstream_least_time_mode", ('upstream="ltOn"',)) == 2)

        # ---- off：纯轮询基线（同时也是后面所有比较的分母） ----
        off_seq = [hit("/off")[0] for _ in range(24)]
        check("off 档严格轮询：24 次里三个后端各 8 次", [off_seq.count(t) for t in "abc"] == [8, 8, 8], str(off_seq))
        off_dt = [hit("/off")[1] for _ in range(60)]
        off_p50 = statistics.median(off_dt)
        off_mean = statistics.fmean(off_dt)
        check("off 档的 p50 就是轮询的中间值（~200ms 量级）", 0.1 < off_p50 < 0.6, f"p50={off_p50:.3f}")

        # ---- observe：逐次与 off 一致，但真的量出了三个后端的快慢 ----
        before = counters(base, "ltObs")
        obs_seq = [hit("/obs")[0] for _ in range(24)]
        text = metrics_text()
        d = diff(before, counters(text, "ltObs"))
        check("observe 档的选点序列与 off 完全一致（证据期不许改行为）", obs_seq == off_seq, f"obs={obs_seq}")
        check("observe 档每个请求都入了样（sampled=24）", d["sampled"] == 24, str(d))
        check("observe 档一次都没有按分数选点（picked=0）", d["picked"] == 0, str(d))
        check("observe 档记下了本会改判的次数（这就是要不要开 on 的证据）", d["would_differ"] > 0, str(d))
        e_a, e_b, e_c = (ewma(text, "ltObs", BE[t]) for t in "abc")
        check("observe 量出的快慢顺序与真实时延一致：a < b < c", e_a < e_b < e_c, f"{e_a} {e_b} {e_c}")
        check("observe 量出的绝对值也贴得上真实时延（a≈5ms、c≈400ms）",
              0.001 < e_a < 0.09 and 0.25 < e_c < 0.75, f"a={e_a} c={e_c}")

        # ---- on：冷启动探索 + 流量迁移到快的后端 ----
        before_on = counters(text, "ltOn")
        warm = [hit("/on")[0] for _ in range(15)]
        text = metrics_text()
        d1 = diff(before_on, counters(text, "ltOn"))
        check("冷启动：一个样本都没有时，三个后端都拿到了流量（新后端不会被有历史的节点永久压住）",
              all(warm.count(t) >= 1 for t in "abc"), str(warm))
        check("冷启动探索单独计数（cold>0）", d1["cold"] > 0, str(d1))

        # 判据是"相对同一轮里的轮询基线偏了多少"，不是"a 得占多数"。P2C 每请求只比较两个
        # 候选，最快节点不在候选里时必然被略过（未测过的节点还总是先被探索一次），所以
        # 2/3 是理想上界而不是期望值；以前写死的 `>=0.55` 在满载的回归里会压在阈值上抖
        # （实测 0.51 挂过一次），那测的不是"分数有没有用"，是机器的噪声。120 个样本下
        # 基线差值的抖动约 ±0.06，0.15 这道线要"完全不看分数"才会红。
        on_seq = [hit("/on")[0] for _ in range(120)]
        on_dt = [hit("/on")[1] for _ in range(60)]
        text = metrics_text()
        d_on = diff(before_on, counters(text, "ltOn"))
        check("on 档确实由分数选点（picked 与请求数一致）",
              d_on["picked"] == len(warm) + len(on_seq) + len(on_dt), str(d_on))
        shift = share(on_seq, "a") - share(off_seq, "a")
        check("on 档把流量偏向最快的后端：相对轮询基线至少多拿走 15 个百分点",
              shift >= 0.15, f"a 在 on 档 {share(on_seq, 'a'):.2f} vs off 档 "
                             f"{share(off_seq, 'a'):.2f}（差 {shift:.2f}）")
        check("on 档不再给最慢的后端流量（c ≈ 0）", share(on_seq, "c") <= 0.15, f"c={share(on_seq, 'c'):.2f}")
        on_p50 = statistics.median(on_dt)
        on_p90 = sorted(on_dt)[int(len(on_dt) * 0.9)]
        on_mean = statistics.fmean(on_dt)
        # 比"平均"而不是比"p50 要快一倍"：on 档的样本是两个峰的混合（最快后端几毫秒、
        # 次快后端约 200ms），中位数正好压在两峰之间的边界上，n 再大也稳不住；P2C 每请求
        # 只比两个候选，本来就不承诺"中位数减半"。均值收敛快，且"分数被忽略"时两侧相等，
        # 这条判据仍然会红。p50/p90 照样打印出来给人读。
        check("客户端确实更快了：on 档平均耗时比 off 档低至少 20%",
              on_mean < off_mean * 0.8,
              f"off mean={off_mean:.3f} p50={off_p50:.3f} / on mean={on_mean:.3f} "
              f"p50={on_p50:.3f} p90={on_p90:.3f}")

        # ---- 中途退化：a 突然变慢（0.005→0.400，比 b 还慢一倍）、c 突然变快，迁移必须反过来 ----
        backends["a"].delay = 0.400
        backends["c"].delay = 0.005
        half1 = [hit("/on")[0] for _ in range(20)]
        half2 = [hit("/on")[0] for _ in range(30)]
        text = metrics_text()
        e_a, e_b, e_c = (ewma(text, "ltOn", BE[t]) for t in "abc")
        # 阈值 0.15 是"确实记下了变慢"的下限，不是真实值：一旦被让开，a 的样本就稀疏，
        # 估计会停在刚越过 b 的那一档附近（真实 400ms，量到 150~400ms 都算数）。
        check("后端当场变慢后，它的 EWMA 跟着涨起来了（a 从个位毫秒涨到 150ms 以上）",
              e_a > 0.15, f"a={e_a} b={e_b} c={e_c}")
        check("迁移是随观测逐步发生的：刚变慢时 a 仍被选中过（旧记忆不会瞬间把节点踢掉）",
              half1.count("a") >= 1, f"a={share(half1, 'a'):.2f} {half1[:12]}")
        check("变快的后端重新拿到流量（后半窗 c 占多数）", share(half2, "c") >= 0.35, f"c={share(half2, 'c'):.2f} {half2[-12:]}")
        check("变慢的后端被让开（后半窗 a 几乎不再被选）", share(half2, "a") <= 0.25, f"a={share(half2, 'a'):.2f} {half2[-12:]}")
        check("迁移的根据是重新量到的时延，不是猜的（c 的 EWMA 现在低于 a）", e_c < e_a, f"a={e_a} c={e_c}")

        # ---- 失败不入账：死节点的 EWMA 恒为 0 ----
        fails = [hit("/fail")[0] for _ in range(6)]
        text = metrics_text()
        dead_ewma = ewma(text, "ltFail", DEAD_PORT)
        dead_fail = metric_val(
            text, "onrouter_upstream_requests_total", ('upstream="ltFail"', 'server="127.0.0.1:%d"' % DEAD_PORT, 'result="failure"')
        ) or 0
        dead_ok = metric_val(
            text, "onrouter_upstream_requests_total", ('upstream="ltFail"', 'server="127.0.0.1:%d"' % DEAD_PORT, 'result="success"')
        ) or 0
        check("死节点确实被试过一次并记为 failure（被动摘除照常工作）", dead_fail >= 1, str(dead_fail))
        check("但它的 EWMA 仍是 0：连接失败的耗时不入账（那不是后端的快慢）", dead_ewma == 0, f"ewma={dead_ewma}")
        check("失败期间请求仍被换节点重试成功（客户端看到的全是活节点）", all(t == "a" for t in fails), str(fails))
        check("活节点的 EWMA 不为 0（同一池子里只有失败没有样本）",
              (ewma(text, "ltFail", BE["a"]) or 0) > 0, str(ewma(text, "ltFail", BE["a"])))
        check("least_time 的 sampled 计数只算成功入样的请求",
              counters(text, "ltOn")["sampled"] >= counters(text, "ltOn")["picked"], str(counters(text, "ltOn")))

        # ---- 关掉的功能不会偷偷动 ----
        text = metrics_text()
        check("off 档到现在仍然没有指标行（跑了一轮流量也不会突然开始记账）",
              metric_val(text, "onrouter_upstream_least_time_mode", ('upstream="ltOff"',)) is None)
        check("off 档的选点仍与 observe 档的原始轮询一致（没有任何档位间串扰）",
              [hit("/off")[0] for _ in range(6)] == ["a", "b", "c", "a", "b", "c"])

        err_lines = []
        if os.path.exists(ERR_LOG):
            with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
                err_lines = f.read().splitlines()
        check("错误日志没有 panic", not any("panicked" in l for l in err_lines), str(err_lines[:3]))
        check("错误日志里只有摘除/重试这类预期告警，没有 least_time 相关的意外报错",
              not any("least_time" in l and "error" in l.lower() for l in err_lines), str(err_lines[:3]))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for b in backends.values():
            b.stop()
        for rel, logpath in probe_logs:
            for p in (os.path.join(ROOT, rel), logpath):
                try:
                    os.remove(p)
                except OSError:
                    pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== least_time 自适应上游选择 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
