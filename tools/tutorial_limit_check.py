# -*- coding: utf-8 -*-
"""教程 §12「限流与配额」的可运行核对。

这一章的每个数字都是照着 conf/tutorial_limit.conf 跑出来的：文档里的示例配置必须
真的能 `-t` 通过、真的按声明的那一维计数、真的把"没带头"的请求挡在门外，而"超限即拒"
和"有界排队"两条路要在同一份 rate 上同时成立。

限流的坑从来不是指令写错，而是"配了但计数的维度不是想要的那个"——所以这里的判定
全部从同一个出口 IP 发出，换 Cookie / 换请求头就是换桶，肉眼可验。

与 tools/limit_key_e2e.py 的分工：那 35 项验的是网关的行为契约（开发用）；
这一份验的是**文档里那几行配置和那几个数字**（读者照着抄能不能得到同样结果）。

  python tools/tutorial_limit_check.py
"""
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "tutorial_limit.conf")
GW = 18650
OUT_LOG = os.path.join(ROOT, "logs", "tutorial_limit_out.log")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
notes = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:240])


def note(text):
    notes.append(text)
    print("  实测", text)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def raw(path, headers=None, cookie=None):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (GW, path))
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with _opener.open(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def get(path, cookie=None, headers=None):
    return raw(path, headers, cookie)[0]


def burst(path, n, cookie=None, headers=None):
    return [get(path, cookie, headers) for _ in range(n)]


def concurrent(path, n, cookie):
    """同一时刻发出 n 个请求，返回按完成时刻排序的 [(状态, 耗时 ms, retry-after)]。"""
    lock = threading.Lock()
    t0 = time.monotonic()
    out = []

    def one(_i):
        st, _, hdr = raw(path, None, "sid=%s" % cookie)
        with lock:
            out.append((st, (time.monotonic() - t0) * 1000.0,
                        hdr.get("retry-after") or hdr.get("Retry-After")))
        return st

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(one, range(n)))
    out.sort(key=lambda x: x[1])
    return out


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "conf", "logs"), exist_ok=True)
    # error_log 的相对路径以配置文件目录为基准（教程 §1 讲过），生效行就落在那里
    ERR_LOG = os.path.join(ROOT, "conf", "logs", "tutorial_limit_err.log")
    for f in (OUT_LOG, ERR_LOG):
        try:
            open(f, "w").close()
        except OSError:
            pass

    # 1) 文档里的配置要能过 -t，且把队列预算如实说出来
    t = subprocess.run([exe, "-t", "-c", CONF], cwd=ROOT, capture_output=True,
                       encoding="utf-8", errors="replace")
    tout = (t.stdout or "") + (t.stderr or "")
    check("§12 示例配置 -t 通过", t.returncode == 0, "rc=%s %s" % (t.returncode, tout[-300:]))
    check("-t 说出队列预算：zone=queued depth=20..20 max_delay=3000ms",
          re.search(r"zone=queued depth=20\.\.20 max_delay=3000ms", tout) is not None,
          tout[-400:])
    check("-t 不给没写 limit_req_queue 的区编造队列行", "zone=plain depth=" not in tout, tout[-400:])

    # 2) 启动日志逐区说出实际的计数维度
    with open(OUT_LOG, "w", encoding="utf-8", errors="replace") as logf:
        proc = subprocess.Popen([exe, "-c", CONF], cwd=ROOT, stdout=logf,
                                stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            if get("/ping") == 200:
                break
            time.sleep(0.1)
        else:
            raise SystemExit("!! 网关未就绪，见 %s" % OUT_LOG)
        time.sleep(0.4)
        with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
            log = f.read()

        def zone_line(zone):
            m = re.search(r"生效 limit_req zone=%s \S+ \S+ key=\S+" % zone, log)
            return m.group(0) if m else ""

        check("日志说出 perip 的维度是地址",
              "$binary_remote_addr" in zone_line("perip"), zone_line("perip"))
        check("日志说出 peruser 的维度是会话", "$cookie_sid" in zone_line("peruser"),
              zone_line("peruser"))
        check("日志说出 perapp 的维度是请求头", "$http_x_api_key" in zone_line("perapp"),
              zone_line("perapp"))
        check("队列只挂在写了 limit_req_queue 的那一个区上",
              "zone=queued" in zone_line("queued") and "队列" in zone_line("queued")
              and "队列" not in zone_line("peruser"), zone_line("queued"))
        note("启动行：%s" % zone_line("queued"))

        # 3) §12.4 的 curl 实验：同一出口 IP，换 Cookie 就是换桶
        a = concurrent("/api/order/x", 12, "A")
        b = concurrent("/api/order/x", 4, "B")
        pa = [s for s, _, _ in a]
        pb = [s for s, _, _ in b]
        check("会话 A 同时 12 个：只放行 burst+1 个（rate=2r/s burst=5），其余 429",
              pa.count(200) == 6 and pa.count(429) == 6, pa)
        check("同 IP 的会话 B 不被 A 的桶拖累", pb.count(200) == 4, pb)
        note("同一 IP 同时发出：sid=A 12 个 %s；sid=B 4 个 %s" % (pa, pb))
        ra = [r for _, _, r in a if r is not None]
        check("被拒的请求带 retry-after", len(ra) == 6, ra)

        # 4) §12.2 的 if 判定：不带头先 401，才谈得上按调用方限流
        st, body, _ = raw("/api/public/ping")
        check('不带 X-Api-Key 的请求 401（if ($http_x_api_key = "")）', st == 401,
              "%s %s" % (st, body[:80]))
        check("401 的正文就是配置里写的那句", "need api key" in body, body[:80])
        check("带上键的请求正常放行", raw("/api/public/ping", {"X-Api-Key": "k1"})[0] == 200)

        # 5) §12.3 同一份 rate 的两条路：超限即拒 vs 有界排队
        plain = concurrent("/api/plain/x", 4, "P")
        queued = concurrent("/api/queued/x", 4, "Q")
        check("不排队的那条：4 个并发只放行 1 个",
              [s for s, _, _ in plain].count(200) == 1
              and [s for s, _, _ in plain].count(429) == 3, plain)
        check("排队的那条：4 个全部放行", [s for s, _, _ in queued].count(200) == 4, queued)
        ms = [round(m) for _, m, _ in queued]
        check("排队确实在等（最后一个等到 1.2s 以上），且没超过 max_delay=3000ms",
              ms[-1] >= 1200 and ms[-1] < 3000, ms)
        note("4 个并发的完成时刻：不排队 %s / 排队 %s（ms）"
             % ([round(m) for _, m, _ in plain], ms))

        # 6) 精确匹配的健康检查没配限流
        check("= /ping 没有限流，连打 40 次全 200", burst("/ping", 40).count(200) == 40)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    bad = [n for n, ok in results if not ok]
    print("\n%d/%d 通过" % (len(results) - len(bad), len(results)))
    if bad:
        print("失败：", " | ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
