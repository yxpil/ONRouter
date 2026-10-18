# -*- coding: utf-8 -*-
# /metrics E2E —— 用真实流量证明运行时指标端点：Prometheus 文本渲染、请求/状态码分类
# 计数随流量单调增长（做前后差值，避开全局单例的绝对值）、活跃连接 gauge 在途时 >=1、
# capacity 取 worker_connections 默认值 10240。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/metrics_e2e.py
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "metrics.conf")
HOST, PORT = "127.0.0.1", 18113
BASE = f"http://{HOST}:{PORT}"

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


def get(path, timeout=8):
    r = urllib.request.Request(BASE + path, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        resp = opener.open(r, timeout=timeout)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def parse_prom(text):
    """把 Prometheus 文本解析成 {指标名(含标签): float}。"""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+)\s+([0-9.eE+]+)$", line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def main():
    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "metrics_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if get("/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18113 被占用？看 conf/logs/metrics_err.log）")

        # 快照 1（这次 /metrics 请求本身也会计数，所以后面用差值）
        st, text1 = get("/metrics")
        check("/metrics 返回 200", st == 200, f"st={st}")
        m1 = parse_prom(text1)
        for fam in ["onrouter_uptime_seconds", "onrouter_connections_accepted",
                    "onrouter_connections_active", "onrouter_connections_capacity",
                    "onrouter_http_requests_total", "onrouter_lua_phase_inline_total",
                    "onrouter_lua_phase_adopted_total", "onrouter_lua_phase_scheduled_total"]:
            check(f"渲染含 {fam}", fam in m1, f"文本={text1!r}")
        for cls in ["2xx", "3xx", "4xx", "5xx"]:
            check(f"渲染含 onrouter_http_responses_total{{class=\"{cls}\"}}",
                  f'onrouter_http_responses_total{{class="{cls}"}}' in m1, f"parsed={m1}")

        # capacity 应等于 worker_connections 默认值 10240
        check("capacity = worker_connections 默认 10240",
              m1.get("onrouter_connections_capacity") == 10240,
              f"got={m1.get('onrouter_connections_capacity')}")

        # === 真实流量：5 个 200 + 3 个 404 ===
        N_HEALTH, N_404 = 5, 3
        for _ in range(N_HEALTH):
            get("/health")
        for _ in range(N_404):
            get("/notfound")

        # === Lua 调度快速路径：无让出 + 有让出各打若干真实请求 ===
        N_INLINE, N_SLEEP = 10, 5
        for _ in range(N_INLINE):
            st, body = get("/lua-inline")
            check("/lua-inline 返回 200", st == 200 and "inline-ok" in body, f"st={st} body={body!r}")
        for _ in range(N_SLEEP):
            st, body = get("/lua-sleep")
            check("/lua-sleep 返回 200", st == 200 and "slept" in body, f"st={st} body={body!r}")

        # 快照 2
        st, text2 = get("/metrics")
        m2 = parse_prom(text2)
        d_inline = (m2["onrouter_lua_phase_inline_total"]
                    - m1["onrouter_lua_phase_inline_total"])
        d_adopted = (m2["onrouter_lua_phase_adopted_total"]
                     - m1["onrouter_lua_phase_adopted_total"])
        d_sched = (m2["onrouter_lua_phase_scheduled_total"]
                   - m1["onrouter_lua_phase_scheduled_total"])
        check("无让出的 Lua 阶段走 inline 快速路径", d_inline >= N_INLINE,
              f"delta={d_inline}（若并发抢占 VM 锁会退回调度器）")
        check("让出的 Lua 阶段被 adopt 给调度器", d_adopted >= N_SLEEP,
              f"delta={d_adopted}")
        check("Lua 阶段计数覆盖全部请求",
              d_inline + d_adopted + d_sched >= N_INLINE + N_SLEEP,
              f"inline={d_inline} adopted={d_adopted} scheduled={d_sched}")
        d_req = m2["onrouter_http_requests_total"] - m1["onrouter_http_requests_total"]
        d_2xx = m2['onrouter_http_responses_total{class="2xx"}'] - m1['onrouter_http_responses_total{class="2xx"}']
        d_4xx = m2['onrouter_http_responses_total{class="4xx"}'] - m1['onrouter_http_responses_total{class="4xx"}']

        # 两次快照之间至少发生了 N_HEALTH+N_404 个请求（快照 2 自身的 /metrics 也计入 requests_total/2xx）
        check("requests_total 随流量增长（>= 20 个业务请求）",
              d_req >= N_HEALTH + N_404, f"delta={d_req}")
        check("2xx 计数随 /health 流量增长", d_2xx >= N_HEALTH, f"delta={d_2xx}")
        check("4xx 计数随 /notfound 流量增长", d_4xx >= N_404, f"delta={d_4xx}")
        check("active gauge 在途请求时 >= 1",
              m2["onrouter_connections_active"] >= 1,
              f"active={m2['onrouter_connections_active']}")
        check("accepted >= active",
              m2["onrouter_connections_accepted"] >= m2["onrouter_connections_active"],
              f"accepted={m2['onrouter_connections_accepted']} active={m2['onrouter_connections_active']}")

        # Content-Type 校验（单独一次连接拿头）
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        resp = opener.open(urllib.request.Request(BASE + "/metrics"), timeout=8)
        ctype = resp.headers.get("content-type", "")
        check("响应头 Content-Type 是 text/plain; version=0.0.4",
              ctype.startswith("text/plain; version=0.0.4"), f"ctype={ctype!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== /metrics E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
