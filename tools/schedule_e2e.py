# -*- coding: utf-8 -*-
# 定时访问窗口（schedule_window + schedule_access）E2E。
#
# 证明了什么（真实流量、真实分钟边界，不是代码审查）：
#   1) 闸门按日历生效：脚本把 office 改写成"两分钟后开、三分钟后关"，网关在**真实**的
#      分钟边界上把 /office/ 从 403 翻成 200，热重载推后关闭时刻后再翻回 403。
#   2) 被挡住时一次都不回源：403 期间后端**总**请求增量为 0（同一段里 /free/ 的 200 会
#      让增量 +1，所以这不是"表坏了自己不知道"），闸门确实在 proxy 之前。
#   3) 没挂闸门的路由（/free/）与恒开放窗口（/any/）全程 200：默认 off 不是"一律 403"。
#   4) 落点两种都对：18338 的闸门写在 server 级，/inherited/ 跟着翻、/override/ 恒 403，
#      证明 location 显式声明优先于 server 继承。
#   5) 自证时间：next_fire_ms 与脚本自己算出的 epoch 毫秒**逐位相等**（关着时=开的那一刻、
#      开着时=关的那一刻、翻转后=明天的开），连没被引用的 tzcheck 也按 +08 核对 ——
#      时区口径写错的话这里必炸。
#   6) 热重载只改定义不丢状态：开着的时候把 close 推后，窗口越过原来的 close 仍 200，
#      next_fire_ms 改成新值，changes 不因为"到点却没翻转"而虚增。
#   7) -t 是执行点：引用未声明的窗口、缺 tz、open/close 同一分钟、窗口重名、
#      schedule_access 漏名字，五种都退出码非 0 并给出可定位的原因；
#      "声明了但没人引用"只告警并退 0（老配置的 -t 结果不能变差）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/schedule_e2e.py
#   整套约 8 分钟：三分之二花在等真实分钟边界 —— 这类特性只有等到点才算证过。
import datetime as dt
import os
import re
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
CONF = os.path.join(ROOT, "conf", "schedule.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "schedule_err.log")
OUT_LOG = os.path.join(ROOT, "logs", "schedule_out.log")

GW_PORT = 18330          # 闸门写在 location
GATED_PORT = 18338       # 闸门写在 server 级
BACKEND_PORT = 18337     # 18331-18336 由 router.rs 单测占用
BASE = f"http://127.0.0.1:{GW_PORT}"
GATED = f"http://127.0.0.1:{GATED_PORT}"

TZ_OFFICE = dt.timezone(dt.timedelta(hours=8))
results = []
lock = threading.Lock()
served = {}
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
EXE = None


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


def request(url, timeout=10):
    req = urllib.request.Request(url, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def status(url, timeout=10):
    return request(url, timeout)[0]


def wait_status(url, want, timeout, every=0.4):
    """轮询到某个状态码为止。每轮只发一个请求 —— 多发的那几次会污染回源计数。"""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = status(url)
        if last == want:
            return last
        time.sleep(every)
    return last


def metrics_body():
    return request(BASE + "/metrics")[1]


def metric(body, mname, **labels):
    """取一个 Prometheus 指标的数值。标签写成 {k="v"}（这里标签键本身就叫 name）。"""
    full = mname + ("{" + ",".join('%s="%s"' % (k, v) for k, v in labels.items()) + "}" if labels else "")
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line == full or line.startswith(full + " "):
            return float(line.split()[-1])
    return None


def mrow(body, mname, win):
    return metric(body, mname, name=win)


def ms(when):
    return int(when.timestamp() * 1000)


def cron_fields(when):
    """把某个绝对时刻写成**该窗口时区（+08:00）**里的 cron 分/时字段（每天一次）。"""
    w = when.astimezone(TZ_OFFICE)
    return f"{w.minute} {w.hour} * * *"


def wall_text(when):
    """网关 fmt_wall 的口径：%Y-%m-%d %H:%M，按窗口自己的时区。"""
    return when.astimezone(TZ_OFFICE).strftime("%Y-%m-%d %H:%M")


def office_block(open_at, close_at):
    return (
        "schedule_window office { tz +08:00; "
        f'open "{cron_fields(open_at)}"; close "{cron_fields(close_at)}"; }}'
    )


def with_office(text, open_at, close_at):
    """只替换 office 那一段，另外三个窗口保持原样（恒开/恒关对照不参与改写）。"""
    block = office_block(open_at, close_at)
    new, n = re.subn(r"schedule_window office \{[^}]*\}", lambda _m: block, text, count=1)
    if n != 1:
        raise SystemExit("!! conf/schedule.conf 里找不到 office 窗口，脚本与配置的锚点分叉了")
    return new


def write_conf(text):
    time.sleep(0.05)
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        os.utime(CONF, None)


def run_t(path):
    p = subprocess.run(
        [EXE, "-t", "-c", os.path.relpath(path, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def office_line(out):
    for l in out.splitlines():
        if "schedule window 'office'" in l:
            return l
    return ""


def daily_utc(hh, mm, after):
    """第一个严格晚于 after 的"每天 hh:mm UTC"时刻。"""
    cand = after.replace(hour=hh, minute=mm, second=0, microsecond=0, tzinfo=dt.timezone.utc)
    if cand <= after:
        cand += dt.timedelta(days=1)
    return cand


def open_log():
    raw = ""
    for p in (ERR_LOG, OUT_LOG):
        if os.path.exists(p):
            raw += open(p, encoding="utf-8", errors="replace").read()
    return raw


def wait_until(when):
    delta = (when - dt.datetime.now(dt.timezone.utc)).total_seconds()
    if delta > 0:
        time.sleep(delta)


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            served[self.path] = served.get(self.path, 0) + 1
        body = f"backend {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def backend_total():
    with lock:
        return sum(served.values())


def hits_delta(fn):
    """跑一次 fn，返回 (fn 的结果, 这段时间里后端收到的请求数)。
    用"总数增量"而不是"某个路径的计数"：proxy_pass 带 URI 会把 location 前缀剥掉，
    后端看到的是 /x2 而不是 /office/x2 —— 按路径数会数错，而"回没回源"才是这里要证的。"""
    before = backend_total()
    r = fn()
    return r, backend_total() - before


def main():
    global EXE
    EXE = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    original = open(CONF, encoding="utf-8").read()

    # ---- 排期：以"下一个真实分钟边界"为准，全程绝对时刻 ----
    now = dt.datetime.now(dt.timezone.utc)
    floor = now.replace(second=0, microsecond=0)
    open_at = floor + dt.timedelta(minutes=2)
    close_at = open_at + dt.timedelta(minutes=3)
    close2 = close_at + dt.timedelta(minutes=2)
    print(f"# office 将于 {wall_text(open_at)}(+08) 开放、{wall_text(close_at)} 关闭，"
          f"热重载后推迟到 {wall_text(close2)}")

    generated = with_office(original, open_at, close_at)
    write_conf(generated)

    # ---- 1) -t：合法配置要把"算出来的墙钟"摆出来 ----
    rc, out = run_t(CONF)
    ol = office_line(out)
    check("-t 通过（四个窗口 + 两处闸门落点）", rc == 0, out[-600:])
    check("-t 打印改写后的 office 定义", f'open="{cron_fields(open_at)}"' in ol, ol)
    check("-t 的下次触发就是脚本算的那一刻", f"下次触发={wall_text(open_at)}" in ol, ol)
    check("-t 里 office 此刻=关闭", "此刻=关闭" in ol, ol)
    check("-t 告警：声明了却没人引用（tzcheck）",
          "tzcheck" in out and "没有任何 server/location" in out, out[-600:])

    # ---- 2) -t 的硬失败：写歪的定时不能带着半套上线 ----
    bad = os.path.join(ROOT, "conf", "_schedule_bad.conf")

    def expect_reject(tag, text, *needles):
        with open(bad, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        rc, out = run_t(bad)
        check(f"-t 拒绝：{tag}", rc != 0 and all(n in out for n in needles),
              f"rc={rc} 缺 {needles} / {out[-400:]}")

    expect_reject("引用未声明的窗口",
                  generated.replace("schedule_access office;", "schedule_access ghost;", 1),
                  "引用了未声明的窗口 'ghost'")
    expect_reject("窗口缺少 tz",
                  generated.replace("schedule_window office { tz +08:00;", "schedule_window office {", 1),
                  "缺少 tz", "office")
    expect_reject("open 与 close 落在同一分钟", with_office(original, open_at, open_at),
                  "同一分钟同时要求改变状态")
    expect_reject("窗口重名", generated + "\n" + office_block(open_at, close_at) + "\n", "重复声明")
    expect_reject("schedule_access 漏了名字",
                  generated.replace("schedule_access office;", "schedule_access;", 1), "缺少窗口名")
    # 全都只声明不引用：必须还是 0（-t 结果不能比老配置更悲观），但要说清有几个没挂上
    unreferenced = re.sub(r"\n[ ]*schedule_access [a-z_]+;", "", generated)
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write(unreferenced)
    rc, out = run_t(bad)
    check("-t 对'声明但没引用'只告警并退 0",
          rc == 0 and "4 个没有任何 server/location" in out, f"rc={rc} / {out[-500:]}")
    if os.path.exists(bad):
        os.remove(bad)

    # ---- 3) 起网关，跑真实分钟边界 ----
    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    for stale in (ERR_LOG, OUT_LOG):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    write_conf(generated)
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([EXE, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    notable = []
    try:
        if not wait_status(BASE + "/ping", 200, 30):
            raise SystemExit(f"!! onrouter 未就绪（端口 {GW_PORT}/{GATED_PORT}/{BACKEND_PORT} 被占用？看 logs/schedule_out.log）")

        # ---- 关闭时段 ----
        st1, h1 = hits_delta(lambda: status(BASE + "/office/x1"))
        check("窗口关闭：/office/ 403", st1 == 403, f"实际 {st1}")
        check("窗口关闭：403 由网关本地答复（一次都没回源）", h1 == 0, f"后端多了 {h1} 次")
        stf, hf = hits_delta(lambda: status(BASE + "/free/x1"))
        check("没挂闸门的 /free/ 200（默认 off 零代价）", (stf, hf) == (200, 1), f"{stf}、回源 {hf}")
        check("恒关窗口 /locked/ 全程 403 且不回源",
              hits_delta(lambda: status(BASE + "/locked/x1")) == (403, 0))
        check("恒开窗口 /any/ 200 且真的回源", hits_delta(lambda: status(BASE + "/any/x1")) == (200, 1))
        check("server 级闸门也挡住 /inherited/ 且不回源",
              hits_delta(lambda: status(GATED + "/inherited/x1")) == (403, 0))
        read_at = dt.datetime.now(dt.timezone.utc)
        m = metrics_body()
        check("指标：office 关闭", mrow(m, "onrouter_schedule_open", "office") == 0)
        check("指标：next_fire_ms 逐位等于脚本算的开放时刻",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(open_at),
              f"指标 {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(open_at)}")
        # tzcheck 没有任何路由引用，但它的排期照样是同一套日历算术 —— 用它单独核对时区换算：
        # 12:00-13:00 (+08) = 04:00-05:00 UTC，下次触发必然是两者中较早的那个。
        # 允许落在"紧随其后的那一次"：读取指标这一刻正好压着分钟边界时，两边算出的 now 会差一格。
        tz_cands = sorted({daily_utc(4, 0, read_at), daily_utc(5, 0, read_at),
                           daily_utc(4, 0, read_at + dt.timedelta(days=1)),
                           daily_utc(5, 0, read_at + dt.timedelta(days=1))})
        want_tz = min(daily_utc(4, 0, read_at), daily_utc(5, 0, read_at))
        got_tz = mrow(m, "onrouter_schedule_next_fire_ms", "tzcheck")
        check("指标：tzcheck 的下次触发证明 +08:00 真的换成了 UTC",
              got_tz in [ms(tz_cands[0]), ms(tz_cands[1])],
              f"指标 {got_tz}，期望 {ms(want_tz)}（候选 {[ms(c) for c in tz_cands[:3]]}）")
        check("指标：还没翻转，changes=0", mrow(m, "onrouter_schedule_changes_total", "office") == 0)
        d0 = mrow(m, "onrouter_schedule_denied_total", "office") or 0
        check("指标：关闭期间的 403 计入 denied_total", d0 >= 1, f"实际 {d0}")
        check("指标：恒开窗口一次都没挡过", mrow(m, "onrouter_schedule_denied_total", "always_open") == 0)
        check("指标：窗口在 -t 之后仍然 enabled", mrow(m, "onrouter_schedule_enabled", "office") == 1)
        check("指标：闸门没有落空（gate_miss=0）", metric(m, "onrouter_schedule_gate_miss_total") == 0)
        check("启动日志给出 runner 概况", "定时窗口 runner 已启动" in open_log(),
              "日志里看不到 runner 概况")

        # ---- 等第一个真实分钟边界：开 ----
        wait_for_open = max(5.0, (open_at - dt.datetime.now(dt.timezone.utc)).total_seconds() + 40)
        before_flip = backend_total()
        got = wait_status(BASE + "/office/x2", 200, wait_for_open)
        d_flip = backend_total() - before_flip
        check("到点真的翻了：/office/ 200", got == 200, f"实际 {got}")
        check("整个等待里只回源一次（其余轮询都挡在网关，闸门确实在 proxy 之前）",
              d_flip == 1, f"后端增量 {d_flip}")
        check("server 级闸门的 /inherited/ 同步放开",
              hits_delta(lambda: status(GATED + "/inherited/x2")) == (200, 1))
        check("location 显式声明优先：office 开着时 /override/ 仍 403 且不回源",
              hits_delta(lambda: status(GATED + "/override/x1")) == (403, 0))
        m = metrics_body()
        check("指标：office 开放", mrow(m, "onrouter_schedule_open", "office") == 1)
        check("指标：翻转计数=1", mrow(m, "onrouter_schedule_changes_total", "office") == 1,
              f"实际 {mrow(m, 'onrouter_schedule_changes_total', 'office')}")
        check("指标：next_fire_ms 改成脚本算的关闭时刻",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(close_at),
              f"指标 {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(close_at)}")
        raw = open_log()
        check("error_log 记下这一次翻转（开放）", "转为开放" in raw and "窗口 'office'" in raw,
              "日志里看不到翻转")

        # ---- 热重载：开着的时候把 close 推后 ----
        write_conf(with_office(original, open_at, close2))

        def moved():
            return mrow(metrics_body(), "onrouter_schedule_next_fire_ms", "office") == ms(close2) or None

        check("热重载：next_fire_ms 跟着新配置改成推迟后的关闭时刻", wait_for_pred(moved, 25) is not None,
              f"停在 {mrow(metrics_body(), 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(close2)}")
        m = metrics_body()
        check("热重载：状态重算没错（仍开放）", mrow(m, "onrouter_schedule_open", "office") == 1)
        check("热重载：没有虚增翻转次数", mrow(m, "onrouter_schedule_changes_total", "office") == 1,
              f"实际 {mrow(m, 'onrouter_schedule_changes_total', 'office')}")

        # 走到原 close 之后：旧的关闭时刻必须真的不再适用
        wait_until(close_at + dt.timedelta(seconds=25))
        st3, d3 = hits_delta(lambda: status(BASE + "/office/x3"))
        check("越过原 close 仍放行（重载推后的就是它自己那条日历）", (st3, d3) == (200, 1),
              f"{st3}、回源 {d3}")
        check("放行期间恒关窗口仍 403", hits_delta(lambda: status(BASE + "/locked/x2")) == (403, 0))

        # ---- 等第二个真实边界：关 ----
        wait_until(close2 + dt.timedelta(seconds=8))
        before_close = backend_total()
        got = wait_status(BASE + "/office/x4", 403, 40)
        d_close = backend_total() - before_close
        check("新 close 到点：/office/ 回到 403", got == 403, f"实际 {got}")
        st5, d5 = hits_delta(lambda: status(BASE + "/office/x5"))
        check("关闭后不再回源", (st5, d5) == (403, 0), f"{st5}、回源 {d5}")
        check("关闭时刻之后的轮询一次都没漏出去", d_close == 0, f"后端增量 {d_close}")
        m = metrics_body()
        check("指标：office 重新关闭", mrow(m, "onrouter_schedule_open", "office") == 0)
        check("指标：累计两次真实翻转", mrow(m, "onrouter_schedule_changes_total", "office") == 2,
              f"实际 {mrow(m, 'onrouter_schedule_changes_total', 'office')}")
        check("指标：下次触发=明天的开放时刻",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(open_at + dt.timedelta(days=1)),
              f"指标 {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(open_at + dt.timedelta(days=1))}")
        d1 = mrow(m, "onrouter_schedule_denied_total", "office") or 0
        check("指标：关闭后的 403 继续累计", d1 >= d0 + 2, f"d0={d0} d1={d1}")
        check("指标：恒关窗口一路在挡（locked denied >= 3）",
              mrow(m, "onrouter_schedule_denied_total", "locked") >= 3)
        check("指标：移除之前的窗口不会冻结排期（tzcheck 仍在走）",
              mrow(m, "onrouter_schedule_next_fire_ms", "tzcheck") != -1)
        raw = open_log()
        check("error_log 记下第二次翻转（关闭）", "转为关闭" in raw, "日志里看不到第二次翻转")
        check("热重载后重打了窗口摘要", "热重载后 schedule window 'office'" in raw,
              "重载后没重打窗口概况")
        notable = [l for l in raw.splitlines() if "schedule: 窗口" in l or "热重载定时窗口" in l]
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

    for l in notable:
        print(f"#   {l.strip()[:160]}")
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== 定时访问窗口 E2E: {passed}/{total} passed ====")
    print(f"     后端共收到 {sum(served.values())} 次回源（{len(served)} 个路径：{sorted(served)}）")
    sys.exit(0 if passed == total else 1)


def wait_for_pred(pred, timeout, every=0.4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = pred()
        if r:
            return r
        time.sleep(every)
    return None


if __name__ == "__main__":
    main()
