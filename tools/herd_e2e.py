# -*- coding: utf-8 -*-
# 惊群（thundering herd / cache stampede）实测。
#
# 关注点不是"缓存命中率好不好"，而是**热点对象在同一刻失效时，源站被敲了几下**：
# 一次大促、一次选课开放、一次 CDN 回源，命的是同一条 URL。这种情况下：
#
#   * `proxy_cache_lock` 能把 N 个并发未命中合成 1 次回源；
#   * ONRouter 目前**默认是 off**，而 nginx 的 `proxy_cache_lock` 默认是 on——
#     一份从 nginx 抄来的配置在两边拿到的源站保护并不一样。本套件把这个差异
#     变成打印出来的数字，而不是埋在注释里；
#   * `proxy_cache_lock_timeout` 到点之后的分支（等待者自己回源）也要有边界；
#   * 磁盘冷层里的"过期"与内存里不同：冷层条目只在校验期内提供，过期即整份重取。
#     锁能不能盖住这条路，是这条路径是否值得开 `disk=on` 的关键；
#   * 限流桶在同一个键被极端争用（200 并发打 rate=1r/s burst=0）时不能多放一个令牌。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/herd_e2e.py
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "herd.conf")
GW, ORIGIN = 18593, 18594
ERRLOG = os.path.join(ROOT, "conf", "logs", "herd_err.log")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []
HITS = {}
HITS_LOCK = threading.Lock()
SLEEP_API = 0.6      # /api/<k>：够慢，让 20 个并发能真正堆在锁前
SLEEP_SLOW = 1.2     # /slow/<k>：比 proxy_cache_lock_timeout(300ms) 慢，专门踩超时分支


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


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # 被限流拒掉的连接由网关提前掐断，这是预期内的，不该刷回溯
        pass


def start_origin():
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _hit(self, path):
            with HITS_LOCK:
                HITS[path] = HITS.get(path, 0) + 1
                return HITS[path]

        def do_GET(self):
            if self.path.startswith("/api/"):
                n = self._hit(self.path)
                time.sleep(SLEEP_API)
                body = json.dumps({"path": self.path, "n": n}).encode()
            elif self.path.startswith("/fast/"):
                n = self._hit(self.path)
                body = json.dumps({"path": self.path, "n": n}).encode()
            elif self.path.startswith("/slow/"):
                n = self._hit(self.path)
                time.sleep(SLEEP_SLOW)
                body = json.dumps({"path": self.path, "n": n}).encode()
            else:
                body = b'{"path":"other"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = Quiet(("127.0.0.1", ORIGIN), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def get(path, headers=None, timeout=25):
    req = urllib.request.Request(f"http://127.0.0.1:{GW}{path}", headers=headers or {})
    t0 = time.perf_counter()
    try:
        r = _opener.open(req, timeout=timeout)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(), time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(), time.perf_counter() - t0
    except Exception as e:  # noqa: BLE001
        return None, {"err": repr(e)}, b"", time.perf_counter() - t0


def metrics_text():
    st, _h, b, _t = get("/metrics", timeout=8)
    return b.decode("utf-8", "replace") if st == 200 else ""


def wait_spill_settled(limit=10.0):
    """落盘是异步的（请求线程不等磁盘）。刚挤完淘汰就要读冷层，必须先等写线程排空。"""
    end = time.time() + limit
    while time.time() < end:
        txt = metrics_text()
        total = 0
        for line in txt.splitlines():
            if line.startswith("onrouter_proxy_cache_disk_pending_jobs"):
                total += int(float(line.split()[-1]))
        if total == 0:
            return True
        time.sleep(0.1)
    return False


def hammer(path, n, headers=None):
    with ThreadPoolExecutor(max_workers=n) as ex:
        return [f.result() for f in [ex.submit(get, path, headers) for _ in range(n)]]


def hits(path):
    with HITS_LOCK:
        return HITS.get(path, 0)


def tags(rs):
    out = {}
    for st, h, _b, _t in rs:
        out[h.get("x-cache", "-")] = out.get(h.get("x-cache", "-"), 0) + 1
    return out


def main():
    exe = find_binary()
    if os.path.exists(ERRLOG):
        os.remove(ERRLOG)
    origin = start_origin()
    # CI 是干净检出：logs/ 在 .gitignore 里，套件自己把它建出来
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "herd_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try:
                ready = get("/ping")[0] == 200
            except (urllib.error.URLError, OSError):
                ready = False      # 还没监听：Linux CI 上首个探测常常早于 bind 完成
            if ready:
                break
            time.sleep(0.25)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/herd_out.log / conf/logs/herd_err.log")
        print("网关已就绪", GW)

        # ── 1) 默认（没写 proxy_cache_lock）：把差异量化出来 ─────────────────
        rs = hammer("/nolock/k1", 20)
        print(f"  默认无锁：20 并发 → 源站 {hits('/api/k1')} 次，状态 {sorted(set(x[0] for x in rs))}")
        check("无锁组全部拿到 200", all(st == 200 for st, _h, _b, _t in rs), tags(rs))
        check("无锁组确实打了 20 次源站（这条记录的是 ONRouter 的默认值，见下面 §5）",
              hits("/api/k1") == 20, f"实际 {hits('/api/k1')}")

        # ── 2) proxy_cache_lock on：单飞 ────────────────────────────────────
        rs = hammer("/lock/k2", 20)
        got = hits("/api/k2")
        check("加锁后 20 并发只回源 1 次", got == 1, f"源站 {got} 次")
        tg = tags(rs)
        check("加锁结果 1 MISS + 19 HIT", tg.get("MISS") == 1 and tg.get("HIT") == 19, str(tg))
        bodies = {b for _st, _h, b, _t in rs}
        check("加锁组拿到的体完全一致（没有各自取到不同版本）", len(bodies) == 1, f"{len(bodies)} 种")

        # ── 3) lock_timeout 到期分支：预算 300ms < 回源 1.2s ─────────────────
        t0 = time.perf_counter()
        rs = hammer("/timeout/k3", 12)
        batch = time.perf_counter() - t0
        got = hits("/slow/k3")
        check("超时分支全部拿到 200（没有谁被挂死或拿到 5xx）",
              all(st == 200 for st, _h, _b, _t in rs), sorted(set(x[0] for x in rs)))
        check("超时后等待者自己回源（源站次数 > 1 且远小于并发数）", 1 < got <= 12, f"源站 {got} 次 / 12 并发")
        # 12 次串行回源会是 12×1.2s；这里要求整批明显小于串行的量级
        check("整批耗时没有被串行化（<6s，串行要 ~14s）", batch < 6.0, f"{batch:.2f}s")

        # ── 4) 冷层里的过期瞬间：条目先被挤出内存落到磁盘，再在冷层里过期 ────
        st, h, _b, _t = get("/cold/k4")
        check("冷层用例预热 MISS", st == 200 and h.get("x-cache") == "MISS", (st, h.get("x-cache")))
        # 先把 k4 的频次抬过 spill_after 门槛（一次性流量本来就不该进冷层，见 proxy_disk_e2e 的门槛项），
        # 再用别的键把 1k(=8 条) 的内存区挤满，让 k4 被淘汰并落到冷层
        for _ in range(2):
            get("/cold/k4")
        for i in range(24):
            get(f"/cold/filler{i}")
        check("淘汰下来的写盘确实异步完成（pending_jobs 归过零）", wait_spill_settled())
        st, h, _b, _t = get("/cold/k4")
        check("淘汰后由冷层供出（X-Cache-Tier: disk）",
              st == 200 and h.get("x-cache-tier") == "disk", (st, h.get("x-cache"), h.get("x-cache-tier")))
        after_cold = hits("/fast/k4")
        time.sleep(2.3)                    # proxy_cache_valid 200 2s → 冷层里那份也过期
        rs = hammer("/cold/k4", 40)
        got = hits("/fast/k4") - after_cold
        check("冷层过期瞬间 40 并发只放 1─2 个回源（锁覆盖冷层这条路）", got <= 2,
              f"源站 {got} 次 / 40 并发，状态 {sorted(set(x[0] for x in rs))}")
        check("冷层过期后所有人仍拿到 200", all(st == 200 for st, _h, _b, _t in rs),
              sorted(set(x[0] for x in rs)))

        # ── 5) 限流桶的极端争用：同一个键 200 并发 ───────────────────────────
        rs = hammer("/limit/x", 200, headers={"X-Herd": "samekey"})
        codes = {}
        for st, _h, _b, _t in rs:
            codes[st] = codes.get(st, 0) + 1
        check("rate=1r/s burst=0 下同键 200 并发恰好放行 1 个", codes.get(200, 0) == 1, str(codes))
        check("其余全部 429，没有 5xx、没有断连",
              codes.get(429, 0) == 199 and sum(v for k in codes if k and k >= 500) == 0, str(codes))
        slowest = max(x[3] for x in rs)
        check("被拒的请求立即返回（没有把 200 个连接挂住）", slowest < 3.0, f"最慢 {slowest:.2f}s")

        # ── 6) 错误日志：超时分支要说话，但不能有 panic ──────────────────────
        txt = open(ERRLOG, encoding="utf-8", errors="replace").read() if os.path.exists(ERRLOG) else ""
        check("锁等待超时在日志里可见（不是静默多打后端）",
              "proxy_cache_lock 等待超时" in txt, txt[-200:])
        check("日志无 panic", "panicked" not in txt and "BACKTRACE" not in txt.upper(), txt[-200:])

        print("\n  ── 默认值对照（不是断言，是给运维看的数字）──")
        print(f"  ONRouter 未写 proxy_cache_lock 时：20 并发 → 源站 {hits('/api/k1')} 次")
        print("  nginx 的 proxy_cache_lock 默认是 on；这里的默认是 off。")
        print("  也就是说：一份照抄 nginx 的配置，在热点过期那一刻打到源站的次数不同。")
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
