# -*- coding: utf-8 -*-
# 限流 key 用请求期变量（$http_* / $cookie_* / $arg_*）的端到端验证。
#
# 为什么值得单独一个套件：限流键取什么，决定的是"谁和谁共享同一个令牌桶"。
# 校园/企业出口整栋楼共用一个 IP 时，$remote_addr 会把几十个人算成同一个人；
# 而配置写下去如果那一维其实不展开（历史上的实现只认地址），运维看到的是
# "限流生效了"，实际发生的是按 IP 限——这是静默的放行失败，不是形状不对。
#
# 本套件的判定全部从同一个 IP 发出，因此"换个 key 就是换个桶"是可以直接观察的：
#   * 同 IP 下 A 被限、B 照常放行；
#   * 没带那个头的请求在这一维上没有值 → 不限流（nginx 的空 key 语义）；
#   * 队列救回的是"这个 key"的后续请求；
#   * limit_conn 也按头分桶，同 IP 的另一个 key 不被拖累。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/limit_key_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "limit_key.conf")
GW, GW_CONN, GW_LOCCONN = 18580, 18582, 18586
ORIGIN = 18581
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []
hits = {}
hits_lock = threading.Lock()
SLOW = 1.2


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:220])


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


# ------------------------------------------------------------------ 源站
def start_origin():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Quiet(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            # 被 limit_conn 拒掉的连接由网关提前掐断，这是预期行为，不该刷回溯
            pass

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with hits_lock:
                hits[self.path] = hits.get(self.path, 0) + 1
            if self.path.startswith("/slow"):
                time.sleep(SLOW)
            body = b"origin-ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = Quiet(("127.0.0.1", ORIGIN), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def get(path, headers=None, port=GW, timeout=8):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = _opener.open(req, timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (socket.timeout, OSError) as e:
        return None, str(e)


def burst(path, n, headers, port=GW):
    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = [ex.submit(get, path, headers, port) for _ in range(n)]
        return [f.result() for f in futs]


def tally(res):
    out = {}
    for st, _ in res:
        out[st] = out.get(st, 0) + 1
    return out


# ------------------------------------------------------------------ -t 判定
def t_check(exe, body):
    """把一段配置写进 conf/ 跑 `-t`（相对路径按配置文件所在目录解析）。"""
    p = os.path.join(ROOT, "conf", "limit_key_t.conf")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    try:
        r = subprocess.run([exe, "-t", "-c", "conf/limit_key_t.conf"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


def conf_with(zone_key):
    return (
        'error_log "logs/limit_key_t_err.log" warn;\npid logs/limit_key_t.pid;\n'
        f"limit_req_zone {zone_key} zone=tk:1m rate=1r/s;\n"
        "server { listen 127.0.0.1:18583; server_name t.limit.key.test;"
        " location / { limit_req zone=tk; return 200 ok; } }\n"
    )


def main():
    exe = find_binary()
    # 1) -t：请求期变量可以作为 key；判定时刻取不到值的写法必须否决
    rc, out = t_check(exe, conf_with("$http_x_client"))
    check("-t 接受 $http_x_client 作为限流 key", rc == 0, out[-200:])
    for ok_key in ["$cookie_sid", "$arg_token", "$cookie_sid$remote_addr", "$uri", "$host"]:
        rc, out = t_check(exe, conf_with(ok_key))
        check(f"-t 接受 {ok_key}", rc == 0, out[-200:])
    for bad_key in ["$status", "$request_body", "$upstream_addr", "$server_name"]:
        rc, out = t_check(exe, conf_with(bad_key))
        check(f"-t 否决 {bad_key}（判定时刻取不到值）", rc != 0, f"rc={rc}")
        check(f"-t 的否决里点名 {bad_key}", bad_key in out, out[-160:])

    origin = start_origin()
    # CI 是干净检出：logs/ 在 .gitignore 里，套件自己把它建出来
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "limit_key_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                ready = get("/ping")[0] == 200
            except (urllib.error.URLError, OSError):
                ready = False      # 还没监听：Linux CI 上首个探测常常早于 bind 完成
            if ready:
                break
            time.sleep(0.25)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/limit_key_out.log")
        print("网关已就绪", GW)

        # 2) 按请求头：同 IP 换 key 就是换桶
        st_a1, _ = get("/hdr/a", {"X-Client": "A"})
        st_a2, _ = get("/hdr/a", {"X-Client": "A"})
        st_b1, _ = get("/hdr/b", {"X-Client": "B"})
        check("头 A 的第一个请求放行", st_a1 == 200, st_a1)
        check("头 A 的第二个请求 429（rate=1r/s burst=0）", st_a2 == 429, st_a2)
        check("同 IP、换头 B 照常放行（key 真的是 $http_x_client）", st_b1 == 200, st_b1)

        # 3) 令牌按各自 key 回补：A 等过 refill 就又能过
        time.sleep(1.15)
        st_a3, _ = get("/hdr/a", {"X-Client": "A"})
        check("A 等过一个补桶周期后放行", st_a3 == 200, st_a3)

        # 4) Retry-After 跟着判定走
        get("/hdr/c", {"X-Client": "C"})
        st_c2, body_c = get("/hdr/c", {"X-Client": "C"})
        check("超限仍是 429 且带响应体", st_c2 == 429 and len(body_c) > 0, st_c2)

        # 5) 按 Cookie
        k = {"Cookie": "sid=A; theme=dark"}
        s1, _ = get("/cookie/a", k)
        s2, _ = get("/cookie/a", k)
        s3, _ = get("/cookie/b", {"Cookie": "sid=B"})
        check("Cookie sid=A 首个放行", s1 == 200, s1)
        check("Cookie sid=A 次个 429", s2 == 429, s2)
        check("Cookie sid=B 独立计数（同 IP）", s3 == 200, s3)

        # 6) 拼接 key：$arg_k$remote_addr
        s1, _ = get("/arg/a?k=A")
        s2, _ = get("/arg/a?k=A")
        s3, _ = get("/arg/b?k=B")
        check("?k=A 首个放行", s1 == 200, s1)
        check("?k=A 次个 429", s2 == 429, s2)
        check("?k=B 独立计数（同 IP、同地址段拼接）", s3 == 200, s3)

        # 7) 空 key = 这一维没有值 = 本区不限流（绝不能并成一个空桶）
        res = [get("/hdr/anon") for _ in range(6)]
        codes = tally(res)
        with hits_lock:
            n = sum(v for p, v in hits.items() if p.startswith("/hdr/anon"))
        check("没带 X-Client 的请求全部放行（空 key 不参与计数）",
              codes.get(200, 0) == 6 and n == 6, f"{codes} 源站命中={n}")

        # 8) 队列按 key 救回：同 rate 下有队列 vs 无队列
        t0 = time.perf_counter()
        q = burst("/queue/a", 4, {"X-Client": "Q1"})
        lat_q = time.perf_counter() - t0
        t0 = time.perf_counter()
        p = burst("/plain/a", 4, {"X-Client": "P1"})
        lat_p = time.perf_counter() - t0
        tq, tp = tally(q), tally(p)
        check("有队列的区把 4 个请求全部救成 200", tq == {200: 4}, tq)
        check("同 rate 无队列的区只放行 1 个", tp == {200: 1, 429: 3}, tp)
        check("救回来的等待没有失控（整批 < 3s 预算）", lat_q < 3.0, f"{lat_q:.2f}s")
        check("即拒版不挂连接（整批 < 1s）", lat_p < 1.0, f"{lat_p:.2f}s")

        # 9) limit_conn 也按头分桶：同 IP 的另一个 key 不该被拖住
        with ThreadPoolExecutor(max_workers=4) as ex:
            fx = [ex.submit(get, "/slow/x", {"X-Client": "X"}, GW_CONN) for _ in range(3)]
            time.sleep(0.25)  # 让 X 的三个连接都进到源站的慢请求里
            fy = ex.submit(get, "/slow/y", {"X-Client": "Y"}, GW_CONN)
            rx = [f.result() for f in fx]
            ry = fy.result()
        cx = tally(rx)
        check("同头 3 个并发：2 个占住额度", cx.get(200, 0) == 2, cx)
        check("同头第 3 个被 limit_conn 拒绝（503）", cx.get(503, 0) == 1, cx)
        check("同 IP、换头的并发请求不受别人的额度影响", ry[0] == 200, ry)

        # 10) location 级 limit_conn 整组替换 server 级：这条路由每人只许 1 个并发，
        #     如果实现把上级那条 5 合并进来，这里就会 3 个全放行——限流等于没写。
        get("/ping", port=GW_LOCCONN)
        rx = burst("/own/x", 3, {"X-Client": "L1"}, GW_LOCCONN)
        cx = tally(rx)
        check("location 级 limit_conn 1 生效（不是继承上级的 5）",
              cx.get(200, 0) == 1 and cx.get(503, 0) == 2, cx)
        # 没自写的兄弟路由照旧继承 server 级 5：同 3 个并发全放行
        ry = burst("/inh/x", 3, {"X-Client": "L2"}, GW_LOCCONN)
        check("未自写的 location 继承 server 的额度", tally(ry).get(200, 0) == 3, tally(ry))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        origin.shutdown()

    ok = sum(1 for _, r in results if r)
    print(f"\n{ok}/{len(results)} 通过")
    if ok != len(results):
        print("失败项：")
        for name, r in results:
            if not r:
                print("  -", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
