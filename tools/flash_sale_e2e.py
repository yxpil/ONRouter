# -*- coding: utf-8 -*-
# 大促 / 闪购：把网关当成"开抢那一刻"的那台机器来压。
#
#   cargo build --release -p onrouter-server --bin onrouter
#   python tools/flash_sale_e2e.py
#   python tools/flash_sale_e2e.py --seconds 40     # 拉长混合流量窗口
#
# 判定写的都是业务底线，不是"指令有没有生效"：
#
# 1. **热点详情不被击穿**。一个 sku 的详情在 TTL 到期的瞬间被 1200 人同时要，源站只该被
#    敲 1─2 次（`proxy_cache_lock`）。这跟命中率无关，跟"到期时刻"有关，所以要专门造。
# 2. **库存一件都不能多卖**。400 个并发抢 50 件，成功数必须正好 50；同一个用户不能拿两件；
#    网关自己不能制造 5xx。
# 3. **非幂等 POST 超时后不得重放到第二个后端**。这条最狠：一个下单请求已经在 A 上被执行、
#    只是响应慢，如果网关因为超时就换一台再发一遍，用户就被扣了两次库存/下了两单。
#    判据是两个后端各自记到的 idempotency key 集合**必须不相交**。
# 4. **限流按人不按出口 IP**。大促时一个家宽出口后面是整个小区；`$cookie_sid` 为键时
#    U1 的洪水不能把 U2 一起挡在门外。
# 5. **一台后端被压死时剩下的要顶住，恢复后要回得来**（max_fails 摘除 + lazy rejoin）。
# 6. **长轮询不能把连接额度吃光**：60 个各挂 1.2s 的请求必须并发进行，不是排队。
#
# 不通过就查网关，不把断言改成"实际行为"。
import argparse
import http.client
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
CONF = os.path.join(ROOT, "conf", "flash_sale.conf")
ERRLOG = os.path.join(ROOT, "conf", "logs", "flash_sale_err.log")
SITE = os.path.join(ROOT, "public_flash")

GW = 18630
ORD_A, ORD_B = 18631, 18632
SALE, STOCK = 18633, 18634

SEATS = 50
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []

LOCK = threading.Lock()
HITS = Counter()             # 源站/后端被真实打到的次数，按 "node:path"
SEEN = set()                 # 源站实际收到的路径原样（用来盯 proxy_pass 的前缀替换）
RECV_KEYS = {ORD_A: set(), ORD_B: set()}   # 每个下单后端记到的 idempotency key
ORDERS = {ORD_A: [], ORD_B: []}            # 实际生成的订单（含 key）
SECK = {"left": SEATS, "sold": [], "users": set()}
SICK = {ORD_A: False}                       # 手动把某个后端设成"一直 503"


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:240])


def bump(key):
    with LOCK:
        HITS[key] += 1


def find_binary():
    if not os.path.exists(EXE):
        raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")
    return EXE


class Quiet(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # 网关提前掐断的连接（超时、被限流）是预期内的，不刷回溯
        pass


# ---------------------------------------------------------------- 后端
class OrderHandler(BaseHTTPRequestHandler):
    """下单后端。self.node 由子类闭包决定。"""
    protocol_version = "HTTP/1.1"
    node = 0
    delay = 0.0

    def _reply(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def do_GET(self):
        bump(f"{self.node}:GET")
        if SICK.get(self.node):
            return self._reply(503, "unavailable\n")
        self._reply(200, f"ok-{self.node}\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode(errors="replace")
        key = ""
        for part in raw.split("&"):
            if part.startswith("key="):
                key = part[4:]
        bump(f"{self.node}:POST")
        if self.delay:
            time.sleep(self.delay)          # 慢到超过 proxy_read_timeout
        with LOCK:
            RECV_KEYS[self.node].add(key)
            ORDERS[self.node].append(key)
        self._reply(201, f"order-{self.node}-{key}\n")

    def log_message(self, *a):
        pass


class SaleHandler(BaseHTTPRequestHandler):
    """详情/券/长轮询的源站。"""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        with LOCK:
            SEEN.add(path)
        bump(f"sale:{path}")
        if path == "/api/hot":
            time.sleep(0.25)                 # 详情要查库：慢一点，才看得见击穿
            body = b'{"sku":1,"price":99,"v":1}\n'
        elif path == "/api/stock-poll":
            time.sleep(1.2)                  # 长轮询：挂着等变化
            body = b'{"left":3}\n'
        elif path == "/api/coupon":
            body = b'{"coupon":"OK"}\n'
        else:
            body = b"{}\n"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "public, max-age=5")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class StockHandler(BaseHTTPRequestHandler):
    """权威库存：按 SKU 串行扣减，同一用户只能拿一件。"""
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode(errors="replace")
        user = ""
        for part in raw.split("&"):
            if part.startswith("user="):
                user = part[5:]
        bump("stock:POST")
        # 判定与扣减必须在这把锁里一次做完：锁外面再查一次账就会给同一个人两件
        with LOCK:
            if user and user in SECK["users"]:
                code, body = 409, b'{"ok":false,"err":"dup"}\n'
            elif SECK["left"] > 0:
                SECK["left"] -= 1
                SECK["sold"].append(user)
                SECK["users"].add(user)
                code, body = 200, b'{"ok":true}\n'
            else:
                code, body = 409, b'{"ok":false,"err":"soldout"}\n'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_backends():
    def mk(port, node, delay=0.0):
        class H(OrderHandler):
            pass
        H.node = node
        H.delay = delay
        srv = Quiet(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    a = mk(ORD_A, ORD_A, delay=3.0)     # A 慢：制造"请求已发出但响应超时"
    b = mk(ORD_B, ORD_B)
    s = Quiet(("127.0.0.1", SALE), SaleHandler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    k = Quiet(("127.0.0.1", STOCK), StockHandler)
    threading.Thread(target=k.serve_forever, daemon=True).start()
    return [a, b, s, k]


def build_site():
    shutil.rmtree(SITE, ignore_errors=True)
    os.makedirs(os.path.join(SITE, "assets"), exist_ok=True)
    # 一张 1.2 MB 的"商品图"：够大到值得走长缓存与 Range
    with open(os.path.join(SITE, "assets", "pic.png"), "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + bytes(bytearray((i * 7) % 251 for i in range(1_200_000))))
    with open(os.path.join(SITE, "assets", "app.js"), "w", encoding="utf-8", newline="\n") as f:
        f.write("// bundle\n" * 3000)


# ---------------------------------------------------------------- 客户端
def req(path, method="GET", body=None, headers=None, timeout=10):
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    c = http.client.HTTPConnection("127.0.0.1", GW, timeout=timeout)
    t0 = time.perf_counter()
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        hdr = {k.lower(): v for k, v in r.getheaders()}
        return r.status, hdr, data, time.perf_counter() - t0
    except Exception as e:  # noqa: BLE001
        return None, {"err": type(e).__name__}, b"", time.perf_counter() - t0
    finally:
        try:
            c.close()
        except OSError:
            pass


def fanout(jobs, workers):
    """jobs 里每一项都是 req 的位置参数元组。"""
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return [f.result() for f in [ex.submit(req, *j) for j in jobs]]


def codes(rs):
    out = Counter()
    for r in rs:
        out[r[0] if r[0] is not None else "conn-err"] += 1
    return out


def metric(name, label=""):
    try:
        c = http.client.HTTPConnection("127.0.0.1", GW, timeout=6)
        c.request("GET", "/metrics")
        r = c.getresponse()
        txt = r.read().decode("utf-8", "replace")
        c.close()
    except OSError:
        return None
    want = name + label
    for line in txt.splitlines():
        if line.startswith(want) and (not label or line.startswith(want + " ") or line.startswith(want + "}")):
            return float(line.split()[-1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=20)
    a = ap.parse_args()
    exe = find_binary()
    if os.path.exists(ERRLOG):
        os.remove(ERRLOG)
    build_site()
    backends = start_backends()

    # 1) -t：这份大促配置不许有任何"写了但没生效"
    t = subprocess.run([exe, "-t", "-c", "conf/flash_sale.conf"], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    tout = (t.stdout or "") + (t.stderr or "")
    check("-t 通过", t.returncode == 0, tout[-200:])
    check("-t 没有未知指令告警", "未知指令" not in tout, tout[-200:])
    check("-t 报告了限流队列", "zone=cq" in tout, tout[-200:])

    # CI 是干净检出：logs/ 在 .gitignore 里，套件自己把它建出来
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "flash_sale_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(120):
            try:
                ready = req("/ping")[0] == 200
            except (OSError, http.client.HTTPException):
                ready = False      # 还没监听：Linux CI 上首个探测常常早于 bind 完成
            if ready:
                break
            time.sleep(0.25)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/flash_sale_out.log / conf/logs/flash_sale_err.log")
        print("网关已就绪", GW)

        # ── 2) 热点详情：1200 并发抢同一个 key，源站只该被打 1─2 次 ──────────
        before = HITS["sale:/api/hot"]
        jobs = [("/api/hot",)] * 1200
        rs = fanout(jobs, 300)
        hits = HITS["sale:/api/hot"] - before
        cs = codes(rs)
        tags = Counter((h.get("x-cache") or "-") for _s, h, _b, _d in rs)
        print(f"  热点详情：1200 并发 → 源站 {hits} 次，X-Cache {dict(tags)}")
        check("热点详情 1200 并发全部 200", cs.get(200, 0) == 1200, str(cs))
        # 两个独立测量必须对上：网关说几个 MISS，源站就该被真实打到几次。
        # 只数 X-Cache 或只数源站都会放过"标签与行为不一致"这类 bug。
        misses = tags.get("MISS", 0)
        check("源站被真实打到的次数 == MISS 响应数，且 ≤2（没有击穿）",
              hits == misses and hits <= 2, f"源站 {hits} 次 / MISS {misses} 个 / {dict(tags)}")
        check("绝大多数并发请求是命中或等待，不是各自回源", tags.get("HIT", 0) >= 1100,
              str(dict(tags)))
        # location /api/hot（不带尾斜杠）+ proxy_pass …/api/hot：nginx 是纯字符串替换，
        # 请求正好等于前缀时余下部分是空的，转发的就是 /api/hot。曾经被补成 /api/hot/，
        # 于是"同一个资源"在后端的精确路由表里变成两条，缓存键也跟着分叉。
        with LOCK:
            seen_now = set(SEEN)
        check("源站收到的路径正好是 /api/hot（前缀替换不补尾斜杠）",
              seen_now == {"/api/hot"}, str(sorted(seen_now))[:120])
        bodies = {b for _s, _h, b, _d in rs}
        check("1200 个响应体完全一致", len(bodies) == 1, f"{len(bodies)} 种")
        check("详情带上了 expires 5s 的过期头",
              all((h.get("cache-control") or "") == "max-age=5" for _s, h, _b, _d in rs[:80]),
              str({h.get("cache-control") for _s, h, _b, _d in rs[:20]}))

        # ── 3) 静态资产：商品图一年缓存 + Range ─────────────────────────────
        rs = fanout([("/assets/pic.png",)] * 600, 120)
        cs = codes(rs)
        cc = {(h.get("cache-control") or "") for _s, h, _b, _d in rs}
        check("商品图 600 并发全部 200 且长度一致",
              cs.get(200, 0) == 600 and all(len(b) == 1_200_008 for _s, _h, b, _d in rs), str(cs))
        check("商品图是十年策略（expires max）",
              cc == {"public, max-age=315360000"}, str(cc)[:160])
        st, h, b, _d = req("/assets/pic.png", headers={"Range": "bytes=100-199"})
        check("商品图 Range 分片返回 206/100 字节", st == 206 and len(b) == 100, (st, len(b)))

        # ── 4) 秒杀不超卖：400 并发抢 50 件 ─────────────────────────────────
        jobs = [("/api/seckill", "POST", f"user=u{i % 220}", None) for i in range(400)]
        rs = fanout(jobs, 200)
        cs = codes(rs)
        ok = sum(1 for s, _h, b, _d in rs if s == 200 and b'"ok":true' in b)
        fives = sum(v for k, v in cs.items() if isinstance(k, int) and k >= 500)
        with LOCK:
            sold = list(SECK["sold"])
        check("秒杀成功数正好等于库存（不超卖、也不少卖）", ok == SEATS and len(sold) == SEATS,
              f"成功 {ok}，账目 {len(sold)}，库存 {SEATS}")
        check("同一个用户不会拿到两件", len(sold) == len(set(sold)), str(sold[:6]))
        check("秒杀全程没有 5xx、没有断连", fives == 0 and cs.get("conn-err", 0) == 0, str(cs))

        # ── 5) 非幂等 POST 超时后不得重放到第二个后端 ──────────────────────
        with LOCK:
            for k in RECV_KEYS:
                RECV_KEYS[k].clear()
                ORDERS[k].clear()
        jobs = [("/api/order", "POST", f"key=ord{i}&sku=1", None) for i in range(16)]
        rs = fanout(jobs, 4)                    # 少量并发：让 round-robin 把两边都用上
        # A 慢到超过 proxy_read_timeout：网关 1s 就回了客户端，但订单确实到了 A，
        # 它要睡满 3s 才记账。不等这一段时间就去数 RECV_KEYS，会把"送到 A 了"读成"没送到"。
        time.sleep(3.6)
        got_a, got_b = len(RECV_KEYS[ORD_A]), len(RECV_KEYS[ORD_B])
        overlap = RECV_KEYS[ORD_A] & RECV_KEYS[ORD_B]
        st_dist = codes(rs)
        print(f"  下单：A 收到 {got_a} 个 key，B 收到 {got_b} 个，交集 {sorted(overlap)}，状态 {dict(st_dist)}")
        check("每个下单请求只被一个后端看到（没有重放＝不会重复扣库存）",
              not overlap and got_a + got_b == 16, f"A={got_a} B={got_b} 交集={overlap}")
        check("慢后端 A 的那些请求按超时失败（504），不是把订单再交给 B",
              st_dist.get(504, 0) == got_a and st_dist.get(201, 0) == got_b, str(st_dist))

        # ── 6) 券接口按人限流：U1 的洪水不能饿死 U2 ─────────────────────────
        # 这一区是 rate=2r/s burst=5，所以**任何**一个键同时发 12 个都只会放行 6 个，
        # "U2 全部放行"是个错的期望。对的判定是：U2 在 U1 的洪水里拿到的额度，和它
        # 独自使用时一模一样。于是先单独量一遍基线，再在洪水中重放同形状的压力。
        alone = codes(fanout([("/api/coupon", "GET", None, {"Cookie": "sid=ALONE"})] * 12, 12))
        u1 = [("/api/coupon", "GET", None, {"Cookie": "sid=U1"}) for _ in range(60)]
        u2 = [("/api/coupon", "GET", None, {"Cookie": "sid=U2"}) for _ in range(12)]
        r1 = fanout(u1, 60)
        r2 = fanout(u2, 12)
        c1, c2 = codes(r1), codes(r2)
        check("U1 洪水之内仍按自己的额度放行（burst=5 → 至少 6 个 200）",
              c1.get(200, 0) >= 6, str(c1))
        check("U1 的洪水产生了 429（限流确实在按会话拦）", c1.get(429, 0) > 0, str(c1))
        check("同一出口 IP 的 U2 额度与独自使用时一致（不被 U1 拖累）",
              c2.get(200, 0) == alone.get(200, 0) and c2.get(200, 0) >= 6,
              f"独自 {dict(alone)} / U1 洪水下 {dict(c2)}")

        # ── 7) 队列 vs 即拒：同额度下队列把请求救回来 ───────────────────────
        jqs = [("/api/coupon_q", "GET", None, {"Cookie": "sid=QQ"}) for _ in range(20)]
        rq = fanout(jqs, 20)
        jpl = [("/api/coupon", "GET", None, {"Cookie": "sid=PP"}) for _ in range(20)]
        rp = fanout(jpl, 20)
        cq, cp = codes(rq), codes(rp)
        tq = max(d for _s, _h, _b, d in rq)
        check("有队列的券接口放行数明显更高",
              cq.get(200, 0) > cp.get(200, 0), f"队列 {dict(cq)} / 即拒 {dict(cp)}")
        check("排队等待没有失控（最慢 < 3s 预算）", tq < 3.2, f"最慢 {tq:.2f}s")

        # ── 8) 长轮询：60 个各挂 1.2s 的请求必须并发而不是排队 ───────────────
        t0 = time.perf_counter()
        rs = fanout([("/api/stock-poll",)] * 60, 60)
        dur = time.perf_counter() - t0
        cs = codes(rs)
        check("60 个长轮询全部 200", cs.get(200, 0) == 60, str(cs))
        check("长轮询没有被串行化（总耗时 < 4s，串行要 72s）", dur < 4.0, f"{dur:.2f}s")

        # ── 9) 一台后端被压死：摘除、剩余顶住、恢复后回得来 ─────────────────
        # 第 5 节把 A 打成过"超时"，它可能还在 fail_timeout 的摘除期里。不先等它回到池里
        # 就按下 SICK，这一节实际测到的是"摘除期还没结束"，503→换节点这条路径一次都没走到。
        def hit_of(k):
            with LOCK:
                return HITS.get(k, 0)

        base_a = hit_of(f"{ORD_A}:GET")
        for _ in range(140):
            req("/api/order")
            if hit_of(f"{ORD_A}:GET") > base_a:
                break
            time.sleep(0.1)
        check("A 已回到节点池（上一节的摘除期已过，503 这一路确实会被走到）",
              hit_of(f"{ORD_A}:GET") > base_a, f"A 仍是 {base_a} 次")
        with LOCK:
            SICK[ORD_A] = True
        rs = fanout([("/api/order",)] * 60, 30)      # GET 幂等：允许 failover
        cs = codes(rs)
        check("A 节点持续 503 时请求全部由健康节点接住", cs.get(200, 0) == 60, str(cs))
        with LOCK:
            during_a = HITS[f"{ORD_A}:GET"]
        rs = fanout([("/api/order",)] * 80, 40)
        with LOCK:
            grew_a = HITS[f"{ORD_A}:GET"] - during_a
        check("被摘除的节点不再接新请求（max_fails 生效）", grew_a == 0, f"A 又收到 {grew_a} 次")
        check("摘除期间没有任何 5xx 漏到客户端", codes(rs).get(200, 0) == 80, str(codes(rs)))
        with LOCK:
            SICK[ORD_A] = False
        time.sleep(6.5)                                # > fail_timeout=5s，等懒重连
        fanout([("/api/order",)] * 60, 30)
        with LOCK:
            back_a = HITS[f"{ORD_A}:GET"]
        check("恢复后 A 重新接到流量（懒重连，不是永久拉黑）", back_a > 0, f"A 收到 {back_a} 次")

        # ── 10) 混合流量窗口：静态 + 详情 + 券 + 秒杀 一起打 ────────────────
        stop = time.time() + a.seconds
        mix_codes = Counter()
        mix_lat = []
        lock = threading.Lock()

        def worker(i):
            while time.time() < stop:
                pick = i % 5
                if pick == 0:
                    r = req("/assets/app.js")
                elif pick == 1:
                    r = req("/api/hot")
                elif pick == 2:
                    r = req("/api/coupon", headers={"Cookie": f"sid=mix{i%37}"})
                elif pick == 3:
                    r = req("/api/seckill", "POST", f"user=mix{i}")
                else:
                    r = req("/assets/pic.png", headers={"Range": "bytes=0-1023"})
                with lock:
                    mix_codes[r[0] if r[0] is not None else "conn-err"] += 1
                    mix_lat.append(r[3])

        ths = [threading.Thread(target=worker, args=(i,)) for i in range(48)]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        total = sum(mix_codes.values())
        bad5 = {k: v for k, v in mix_codes.items() if isinstance(k, int) and k >= 500}
        p50, p99 = statistics.median(mix_lat) * 1000, sorted(mix_lat)[int(len(mix_lat) * 0.99) - 1] * 1000
        print(f"  混合 {a.seconds}s：{total} 请求 ≈ {total / a.seconds:,.0f} rps，"
              f"p50 {p50:.1f}ms p99 {p99:.1f}ms，状态 {dict(mix_codes)}")
        check("混合流量窗口内网关没有制造 5xx", not bad5, str(bad5))
        check("混合流量窗口没有断连", mix_codes.get("conn-err", 0) == 0, str(mix_codes.get("conn-err")))
        check("混合流量 p99 在秒级以内", p99 < 1500, f"p99={p99:.1f}ms")

        # ── 11) 账目与可观测性 ─────────────────────────────────────────────
        cache_hit = metric("onrouter_cache_requests_total", '{status="hit"}')
        accepted = metric("onrouter_connections_accepted")
        check("缓存命中被计进指标", (cache_hit or 0) > 0, str(cache_hit))
        check("连接接受计数在涨", (accepted or 0) > 0, str(accepted))

        txt = open(ERRLOG, encoding="utf-8", errors="replace").read() if os.path.exists(ERRLOG) else ""
        check("错误日志无 panic", "panicked" not in txt and "BACKTRACE" not in txt.upper(), txt[-240:])
        check("错误日志里能看到按会话计数的限流区", "key=$cookie_sid" in txt, txt[-160:])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for b in backends:
            b.shutdown()
        shutil.rmtree(SITE, ignore_errors=True)

    ok = sum(1 for _, r in results if r)
    print(f"\n==== 大促闪购 E2E: {ok}/{len(results)} passed ====")
    if ok != len(results):
        print("失败项：")
        for name, r in results:
            if not r:
                print("  -", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
