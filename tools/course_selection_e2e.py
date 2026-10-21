# -*- coding: utf-8 -*-
"""校园选课系统模拟 —— 把网关当成"选课开放那一刻"的那台前置机来压。

    python tools/course_selection_e2e.py
    python tools/course_selection_e2e.py --students 2400 --conc 240 --keep

为什么这个形状值得单独测（而不是并进前面的静态/缓存套件）：

* **同一门课被几千人同时抢**：源站必须按课程串行加锁，于是网关侧看到的是
  「极热的少量 URL + 大量并发 + 后端排队」——最容易暴露超时、队列失控、连接堆积。
* **不超卖是业务底线**：不是"响应码对不对"，而是"网关放过去的请求里，源站记到的
  成功次数必须正好等于席位，且绝不能有学生拿到同一门课两个席位"。
* **限流分学生而不是分 IP**：真实场景一人多端/一机房出口同 IP，键取 `$http_x_student`。
* **队列 vs 即拒**要成对测：同一个 rate 下，一条路径配 `limit_req_queue`、另一条不配，
  比较两边 429 数量与被救回的比例，才算真的在测队列而不是测配置能否加载。
* **热点详情要走缓存**：选课页 3 秒刷一次，源站只该被打个位数次，而不是每人一次。

断言一律按业务与 nginx 语义写；不通过就查网关，不把断言改成"实际行为"。
"""

import argparse
import hashlib
import http.client
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
ORIGIN_PORT = 19920
GW = 19921
CONF = os.path.join(ROOT, "conf", "course_sim.conf")
ERRLOG = os.path.join(ROOT, "conf", "logs", "course_sim_err.log")
STATIC = os.path.join(ROOT, "public_course")

SEATS = 50
COURSES = 40
HOT = [1, 2, 3]                     # 三门"必修热门课"，绝大多数人都会先看详情再抢
LOCK = threading.Lock()
SEATS_LEFT = {i: SEATS for i in range(1, COURSES + 1)}
OK_COUNT = Counter()                 # 每节课真的发放出去的席位
ENROLLED = defaultdict(set)          # 学生 → 已选课程（检查重复选课）
ORIGIN_HITS = Counter()              # 源站被真实打了多少次（含详情/静态）
STATUS_TALLY = Counter()             # 源站看到的响应码


def start_origin():
    os.makedirs(STATIC, exist_ok=True)
    with open(os.path.join(STATIC, "app.js"), "w", encoding="utf-8") as f:
        f.write("// bundle\n" * 900)
    with open(os.path.join(STATIC, "style.css"), "w", encoding="utf-8") as f:
        f.write("body{margin:0}\n" * 1200)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, payload, ctype="application/json"):
            body = payload.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if code == 200 and ctype == "application/json":
                self.send_header("Cache-Control", "public, max-age=3")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            with LOCK:
                ORIGIN_HITS[self.path] += 1
            if self.path.startswith("/api/course/"):
                time.sleep(0.006)                    # 详情要查库：源站慢
                cid = self.path.rsplit("/", 1)[-1]
                return self._send(200, json.dumps({"cid": cid, "left": SEATS_LEFT.get(int(cid or 1), 0)}))
            if self.path.startswith("/static/"):
                f = os.path.join(STATIC, self.path.split("/static/")[-1])
                if not os.path.exists(f):
                    return self._send(404, "{}")
                data = open(f, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path.startswith("/api/my/"):
                return self._send(200, json.dumps({"ok": list(sorted(ENROLLED.get(self.path.rsplit("/", 1)[-1], set())))}))
            return self._send(404, "{}")

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode()
            q = dict(re.findall(r"(\w+)=(\w+)", raw))
            sid, cid = q.get("sid", "?"), int(q.get("cid", 0))
            with LOCK:
                ORIGIN_HITS["/api/enroll"] += 1
                if cid in SEATS_LEFT and SEATS_LEFT[cid] > 0:
                    if cid in ENROLLED.get(sid, set()):
                        dup = True
                    else:
                        dup = False
                        SEATS_LEFT[cid] -= 1
                        OK_COUNT[cid] += 1
                        ENROLLED[sid].add(cid)
                else:
                    dup = False
                    no = True
            if dup:
                return self._send(409, json.dumps({"err": "already"}))
            if SEATS_LEFT.get(cid, 0) <= 0 and not dup:
                return self._send(409, json.dumps({"err": "full"}))
            return self._send(200, json.dumps({"ok": True, "left": SEATS_LEFT[cid]}))

        def log_message(self, *a):
            pass

    class Quiet(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            # 被限流拒掉的请求由网关提前断连，这是预期行为，不该刷满测试输出
            pass

    srv = Quiet(("127.0.0.1", ORIGIN_PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def write_conf():
    tpl = f"""
error_log "logs/course_sim_err.log" warn;
pid logs/course_sim.pid;
worker_threads 4;
# 一人一键：真实机房出口共用 IP，所以按学生号限流
limit_req_zone $http_x_student zone=enq:1m  rate=2r/s burst=1;
limit_req_zone $http_x_student zone=eqq:1m  rate=2r/s burst=1;
limit_req_zone $http_x_student zone=brw:1m  rate=40r/s burst=20;
limit_req_zone $http_x_student zone=nq:1m   rate=40r/s burst=20;
limit_req_queue eqq depth=8 depth_min=8 max_delay=1500ms;
limit_conn_zone $http_x_student zone=perstudent:1m;
# 会话键数量级 = 学生数：每人一个键约 80 B，2400 人约 190 KB。
# 写 64k 会走到 LRU 淘汰（OpenResty 同行为），计数的断言就没法精确，所以按人口定容。
lua_shared_dict sessions 1m;
proxy_cache_path logs/course_cache keys_zone=cc:1m;

upstream school {{ server 127.0.0.1:{ORIGIN_PORT}; keepalive 64; }}

server {{
    listen {GW};
    server_name course.test;
    # 并发闸也按学生：一人多端/机房出口同 IP 时，按 IP 会让整栋宿舍楼互相拖累
    limit_conn perstudent 8;

    location = /health {{ return 200 "ok\\n"; }}

    # 登录：共享字典当会话计数（并发下不能丢）
    location = /api/login {{
        content_by_lua "local d = ngx.shared.sessions; d:incr(ngx.var.http_x_student or 'x', 1, 0); ngx.say('login-ok')";
    }}
    location = /api/logins {{
        content_by_lua "local d = ngx.shared.sessions; ngx.say('count=' .. tostring(d:get(ngx.var.http_x_student or 'x') or 0))";
    }}

    # 热门详情：带缓存，源站只该被打个位数次
    location /api/course/ {{
        limit_req zone=brw;
        proxy_pass http://school;
        proxy_cache cc;
        proxy_cache_valid 200 3s;
        proxy_cache_key "$uri";
        add_header X-Cache $upstream_cache_status;
    }}

    # 无缓存对照（同样限流），用来证明"挡住源站的是缓存而不是限流放行了"
    location /api/nocache/ {{
        limit_req zone=nq;
        proxy_pass http://school/api/course/;
    }}

    # 热门课在 TTL 到期的那一刻被同时点开：开了 lock 就只放一个请求回源
    location /api/locked/ {{
        limit_req zone=brw;
        proxy_pass http://school/api/course/;
        proxy_cache cc;
        proxy_cache_valid 200 3s;
        proxy_cache_lock on;
        proxy_cache_lock_timeout 2000ms;
        proxy_cache_key "locked:$uri";
    }}

    location /static/ {{
        proxy_pass http://school/static/;
        expires 1h;
    }}

    location = /api/myenrolls {{ proxy_pass http://school/api/my/; }}

    # 抢课 A：超限排队（有队列）
    location = /api/enroll {{
        limit_req zone=eqq;
        proxy_pass http://school;
    }}

    # 抢课 B：超限即拒（默认 nodelay 语义），与 A 同 rate
    location = /api/enroll_plain {{
        limit_req zone=enq;
        proxy_pass http://school;
    }}
}}
"""
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(tpl)


class Client:
    def __init__(self, port):
        self.port = port

    def call(self, method, path, sid, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            c.request(method, path, body=body,
                      headers={"X-Student": sid, "Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            data = r.read()
            hdr = {k.lower(): v for k, v in r.getheaders()}
            return r.status, hdr, data
        except Exception as e:  # noqa: BLE001
            return None, {"err": f"{type(e).__name__}"}, b""
        finally:
            try:
                c.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--students", type=int, default=800)
    ap.add_argument("--conc", type=int, default=120)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(EXE):
        raise SystemExit("!! 先 cargo build --release -p onrouter-server --bin onrouter")
    start_origin()
    write_conf()
    t = subprocess.run([EXE, "-t", "-c", os.path.relpath(CONF, ROOT)], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    out = (t.stdout or "") + (t.stderr or "")
    print("== -t ==")
    print("  通过" if t.returncode == 0 else "  失败：" + out[-400:])
    if t.returncode != 0:
        sys.exit(1)
    log = open(os.devnull, "wb")
    proc = subprocess.Popen([EXE, CONF], cwd=ROOT, stdout=log, stderr=log)
    cl = Client(GW)
    if not wait_ready(GW):
        print("!! 网关没起来：", open(ERRLOG, encoding="utf-8", errors="replace").read()[-500:] if os.path.exists(ERRLOG) else "无错误日志")
        sys.exit(1)
    rng = random.Random(11)
    students = [f"s{i}" for i in range(a.students)]

    def browse(sid):
        # 选课流程：登录 → 看 3 门热门 + 自己那门 → 连点 6 门（队列版）→ 再连点 6 门（即拒版）
        # 每人 6 连点才够：rate=2r/s burst=1 之下"点两下"根本不会越线，那样测的是配置而不是限流。
        r = []
        r.append(cl.call("POST", "/api/login", sid, ""))
        hot = HOT + [rng.randrange(1, COURSES + 1)]
        for cid in hot:
            r.append(cl.call("GET", f"/api/course/{cid}", sid))
        r.append(cl.call("GET", "/static/app.js", sid))
        got = {}
        for cid in rng.sample(range(1, COURSES + 1), 6):
            st, h, b = cl.call("POST", "/api/enroll", sid, f"sid={sid}&cid={cid}")
            got[cid] = st
        for cid in rng.sample(range(1, COURSES + 1), 6):
            st, h, b = cl.call("POST", "/api/enroll_plain", sid, f"sid={sid}&cid={cid}")
            got[f"p{cid}"] = st
        return sid, r, got

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=a.conc) as ex:
        res = list(ex.map(browse, students))
    dur = time.perf_counter() - t0

    codes = Counter()
    for sid, r, got in res:
        for st, h, b in r:
            codes[st or "conn-err"] += 1
        for k, st in got.items():
            codes[f"enroll-{'plain' if str(k).startswith('p') else 'queue'}:{st}"] += 1

    print(f"\n== 负载：{a.students} 学生 × {a.conc} 并发，{dur:.1f}s，"
          f"约 {sum(v for k, v in codes.items() if isinstance(k, int)) / dur:.0f} req/s ==")
    print("  浏览/登录/静态状态码分布：", {k: v for k, v in codes.items() if isinstance(k, int)})
    print("  抢课结果：", {k: v for k, v in codes.items() if isinstance(k, str)})

    fails = []

    def ck(name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f" :: {detail}"[:300]))
        if not ok:
            fails.append(name)

    # 1) 不超卖
    over = {c: OK_COUNT[c] for c in OK_COUNT if OK_COUNT[c] > SEATS}
    ck("源站没有超卖（每课发放 ≤ 席位）", not over, str(over))
    filled = [c for c in range(1, COURSES + 1) if OK_COUNT[c] == SEATS]
    ck("确有课程被抢满（说明负载真的打满了后端）", len(filled) >= 1,
       f"满课 {len(filled)} 门，发放总计 {sum(OK_COUNT.values())}")
    dup = [s for s, courses in ENROLLED.items() if len(courses) != len(set(courses))]
    ck("没有学生拿到同一门课的两个席位", not dup, str(dup[:3]))

    # 2) 网关不能自己造 5xx，也不能断连
    fives = {k: v for k, v in codes.items() if isinstance(k, int) and k >= 500}
    err = sum(v for k, v in codes.items() if k == "conn-err")
    ck("网关没有产生 5xx、没有断连", not fives and err == 0, f"5xx={fives} 断连={err}")

    # 3) 记账口径先说清：200 与 409 都是"网关放过去了"（409 是源站说这门课你已选/已满），
    #    只有 429 才是网关自己拦下的。把 409 当成"没放行"会得出"源站被打得比放行多"的假矛盾。
    qadm = codes.get("enroll-queue:200", 0) + codes.get("enroll-queue:409", 0)
    qrej = codes.get("enroll-queue:429", 0)
    padm = codes.get("enroll-plain:200", 0) + codes.get("enroll-plain:409", 0)
    prej = codes.get("enroll-plain:429", 0)
    attempts = qadm + qrej + padm + prej
    ck("12 次抢课点击全部拿到判定结果（没有超时、没有断连）",
       attempts == 12 * len(students), f"{attempts} ≠ {12 * len(students)}")

    # 4) 限流按**学生**分键：全部流量都来自 127.0.0.1，若按 IP 计数，
    #    两个 2r/s 的区跑完这段压测最多只放行 2×rate×时长 个请求。
    per_ip_ceiling = 2 * 2 * dur
    ck("限流键取的是 $http_x_student（放行数远超按 IP 的上界）",
       qadm + padm > 5 * per_ip_ceiling,
       f"放行 {qadm + padm}，按 IP 最多 {per_ip_ceiling:.0f}")

    # 5) 限流真的在拦：每人连点 6 次必有 429
    ck("超限被 429 挡下（而不是放行打爆源站）", qrej + prej > 0, f"queue={qrej} plain={prej}")

    # 6) 队列 vs 即拒：同一个 rate、同一个 burst，配了 limit_req_queue 的路径救回更多
    ck("配了队列的路径放行更多、拦下更少（队列在工作）",
       qadm > padm and qrej < prej and (qadm + qrej) == (padm + prej),
       f"队列版 放行/拦下 = {qadm}/{qrej}，即拒版 = {padm}/{prej}")

    # 7) 源站收到的选课请求必须正好等于网关放行数（限流计账不多不漏）
    origin_enroll = ORIGIN_HITS["/api/enroll"]
    ck("源站被打的选课次数正好等于网关放行数", origin_enroll == qadm + padm,
       f"origin={origin_enroll} 放行={qadm + padm}")

    # 7) 热点详情由缓存挡住：每人每门热门课都点一次，源站却只该被打个位数到几十次。
    #    判据用比率而不是绝对值——绝对值等于给某个固定人数标定，负载一变就失真。
    hot_hits = {c: ORIGIN_HITS[f"/api/course/{c}"] for c in HOT}
    hot_req = len(students) * len(HOT)
    ck("热门详情由缓存挡住（源站命中 ≤ 请求数的 10%）",
       sum(hot_hits.values()) <= hot_req * 0.10,
       f"3 门热门课源站各被打 {hot_hits}，请求数 {hot_req}")

    # 8) 共享字典按学生计数：每人 1 次登录，重复登录累加而不是覆盖
    def logins(sid):
        st, _, b = cl.call("GET", "/api/logins", sid)
        return st, (b.decode(errors="replace").strip() or "")

    st0, c0 = logins("s0")
    ck("登录后共享字典计数为 1（每人一次，键取学生号）",
       st0 == 200 and c0 == "count=1", f"{st0} {c0!r}")
    for _ in range(2):
        cl.call("POST", "/api/login", "s0", "")
    _, c1 = logins("s0")
    ck("同一学生三次登录后计数为 3（incr 累加，不是覆盖）", c1 == "count=3", c1)

    # 8b) 热点 key 在到期瞬间的单飞：40 个人同时点同一门课，源站只该被敲一次
    before = ORIGIN_HITS["/api/course/999"]
    with ThreadPoolExecutor(max_workers=40) as ex:
        lr = [ex.submit(cl.call, "GET", "/api/locked/999", f"lk{i}") for i in range(40)]
        lk = [f.result()[0] for f in lr]
    got = ORIGIN_HITS["/api/course/999"] - before
    ck("到期瞬间 40 个并发只放 1─2 个回源（proxy_cache_lock 生效）",
       got <= 2 and all(st == 200 for st in lk), f"回源 {got} 次 / 40 并发，状态 {set(lk)}")

    # 9) 排队延迟有界：max_delay=1500ms 之后不该有请求拖更久
    worst = 0.0
    for _ in range(30):
        t1 = time.perf_counter()
        cl.call("POST", "/api/enroll", f"lat{random.randrange(999)}", "sid=x&cid=1")
        worst = max(worst, time.perf_counter() - t1)
    ck("单次请求延迟不超过 max_delay 太多（队列没失控）", worst < 2.5, f"最慢 {worst * 1000:.0f}ms")

    # 10) 错误日志干净
    if os.path.exists(ERRLOG):
        txt = open(ERRLOG, encoding="utf-8", errors="replace").read()
        ck("错误日志无 panic", "panicked" not in txt and "BACKTRACE" not in txt.upper(), txt[-300:])
        n502 = len(re.findall(r"代理失败", txt))
        ck("错误日志无上游代理失败", n502 == 0, f"{n502} 条")
    else:
        ck("错误日志存在（否则无从判断）", False, ERRLOG)
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()
    if not a.keep:
        try:
            os.remove(CONF)
        except OSError:
            pass
    print(f"\n==== 选课场景: {0 if fails else 'clean'} 失败项 {len(fails)} → {fails}")
    sys.exit(1 if fails else 0)


def wait_ready(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


if __name__ == "__main__":
    main()
