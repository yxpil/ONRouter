# -*- coding: utf-8 -*-
# cache_advanced E2E —— 用真实并发/故障流量验证 proxy_cache 的进阶语义：
#   * proxy_cache_lock：20 个并发同 key MISS 只有 1 个回源，其余等待后拿到 HIT
#   * proxy_cache_use_stale http_502：上游 502 时回放过期内容（STALE）
#   * proxy_cache_use_stale error：上游进程被关掉后仍能回放（STALE）
#   * proxy_cache_use_stale updating + lock：刷新进行中，后来请求立刻 STALE
#   * proxy_cache_bypass：跳过读取但仍写入新响应
#   * proxy_no_cache：既跳过读取也不写入
#   * keys_zone 容量（tiny:1k → 8 条）：按 LRU 淘汰最久未使用
#   * HEAD 只读不写：可从 GET 缓存命中，但不会把空体写进共享 key
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/cache_advanced_e2e.py
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "cache_advanced.conf")

BACKEND_PORT = 18131
DEAD_PORT = 18132
GW_HOST, GW_PORT = "127.0.0.1", 18130
BASE = f"http://{GW_HOST}:{GW_PORT}"

state_lock = threading.Lock()
hits = {}
# 命中这些前缀时后端返回 502（用于 use_stale http_502）
failing = set()

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, timeout=15, method="GET"):
    req = urllib.request.Request(BASE + path, method=method)
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def version_of(body):
    m = re.search(r"\bv=(\d+)\b", body)
    return int(m.group(1)) if m else None


def backend_count(path):
    with state_lock:
        return hits.get(path, 0)


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path
        with state_lock:
            hits[path] = hits.get(path, 0) + 1
            n = hits[path]
            fail = any(path.startswith(p) for p in failing)
        # /lock 让并发请求有足够时间堆在 proxy_cache_lock 上；/updating 让刷新变慢
        if path.startswith("/lock/"):
            time.sleep(0.5)
        elif path.startswith("/updating/"):
            time.sleep(0.6)
        if fail:
            body = b"upstream failed"
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = f"v={n} path={path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        # HEAD 与 GET 共享同一个 cache key；响应只有头、没有 body
        path = self.path
        with state_lock:
            hits[path] = hits.get(path, 0) + 1
            n = hits[path]
            fail = any(path.startswith(p) for p in failing)
        if fail:
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = f"v={n} path={path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def log_message(self, *_a):
        pass


class DeadBackend(Backend):
    # HTTP/1.0 不保持连接：关掉进程后网关不会复用到仍然存活的 keep-alive 连接
    protocol_version = "HTTP/1.0"


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # 网关进程退出时会断开 keep-alive 连接，属预期噪音
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    backend = QuietServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    dead = QuietServer(("127.0.0.1", DEAD_PORT), DeadBackend)
    threading.Thread(target=dead.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "cache_advanced_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit("!! onrouter 未就绪（端口 18130/18131/18132 被占用？看 logs/cache_advanced_out.log）")

        # 1) 基础命中（对照）
        st, hs, b1 = request("/plain/count")
        check("/plain 首次 200", st == 200, f"st={st}")
        check("首次 MISS 且回源 v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b1) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b1!r}")
        st, hs, b2 = request("/plain/count")
        check("再次 HIT 且响应体一致", hdr(hs, "X-Cache-Status") == "HIT" and b2 == b1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b2!r}")
        check("HIT 不再打后端", backend_count("/plain/count") == 1, f"cnt={backend_count('/plain/count')}")

        # 2) proxy_cache_lock：20 并发只回源 1 次
        with ThreadPoolExecutor(max_workers=20) as ex:
            rs = [f.result() for f in [ex.submit(request, "/lock/count") for _ in range(20)]]
        check("并发 20 个请求全部 200", all(st == 200 for st, _, _ in rs),
              f"statuses={sorted(st for st, _, _ in rs)}")
        tags = [hdr(hs, "X-Cache-Status") for _, hs, _ in rs]
        check("并发结果：1 个 MISS + 19 个 HIT", tags.count("MISS") == 1 and tags.count("HIT") == 19,
              f"tags={tags}")
        check("并发 20 个请求只打了 1 次后端", backend_count("/lock/count") == 1,
              f"cnt={backend_count('/lock/count')}")
        bodies = {b for _, _, b in rs}
        check("并发响应体完全一致（v=1）", len(bodies) == 1 and version_of(next(iter(bodies))) == 1,
              f"bodies={bodies}")

        # 3) use_stale http_502：过期后上游 502 → 回放旧内容
        st, hs, b = request("/stale/count")
        check("/stale 预热 MISS v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        time.sleep(1.2)
        with state_lock:
            failing.add("/stale/")
        try:
            st, hs, b = request("/stale/count")
        finally:
            with state_lock:
                failing.discard("/stale/")
        check("上游 502 → 200 STALE（回放 v=1）",
              st == 200 and hdr(hs, "X-Cache-Status") == "STALE" and version_of(b) == 1,
              f"st={st} xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        check("STALE 之前确实又一次回源（计数=2）", backend_count("/stale/count") == 2,
              f"cnt={backend_count('/stale/count')}")

        # 4) use_stale error：上游进程消失 → 回放
        st, hs, b = request("/dead/count")
        check("/dead 预热 MISS v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        time.sleep(1.2)
        dead.shutdown()
        dead.server_close()
        st, hs, b = request("/dead/count")
        check("上游不可达 → 200 STALE（回放 v=1）",
              st == 200 and hdr(hs, "X-Cache-Status") == "STALE" and version_of(b) == 1,
              f"st={st} xcs={hdr(hs,'X-Cache-Status')} body={b!r}")

        # 5) use_stale updating：刷新中，后到请求立即 STALE，刷新完成后 HIT 新值
        st, hs, b = request("/updating/count")
        check("/updating 预热 MISS v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        time.sleep(1.2)
        with ThreadPoolExecutor(max_workers=1) as ex:
            refresh = ex.submit(request, "/updating/count")
            # 后端在回源开始时先 +1 再 sleep：计数=2 说明 leader 已在回源途中并持有 cache lock
            for _ in range(100):
                if backend_count("/updating/count") == 2:
                    break
                time.sleep(0.01)
            t0 = time.time()
            st, hs, b_stale = request("/updating/count")
            elapsed = time.time() - t0
            st_r, hs_r, b_r = refresh.result()
        check("刷新进行中 → 立即 STALE（不排队等锁）",
              hdr(hs, "X-Cache-Status") == "STALE" and version_of(b_stale) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b_stale!r}")
        check("STALE 响应耗时 < 0.45s（后端刷新需 0.6s）", elapsed < 0.45, f"elapsed={elapsed:.3f}s")
        check("刷新请求本身 EXPIRED 且拿到 v=2",
              hdr(hs_r, "X-Cache-Status") == "EXPIRED" and version_of(b_r) == 2,
              f"xcs={hdr(hs_r,'X-Cache-Status')} body={b_r!r}")
        st, hs, b = request("/updating/count")
        check("刷新完成后 HIT 新值 v=2",
              hdr(hs, "X-Cache-Status") == "HIT" and version_of(b) == 2,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")

        # 6) proxy_cache_bypass：跳过读取但写入新响应
        st, hs, b = request("/bypass/count")
        check("/bypass 预热 MISS v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        st, hs, b = request("/bypass/count?nocache=1")
        check("bypass 命中表达式 → BYPASS 且读到新回源内容",
              hdr(hs, "X-Cache-Status") == "BYPASS" and "nocache=1" in b,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        st, hs, b = request("/bypass/count")
        check("bypass 响应已写入缓存（随后 HIT 新内容）",
              hdr(hs, "X-Cache-Status") == "HIT" and "nocache=1" in b,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        check("bypass 未额外回源无查询串的 key", backend_count("/bypass/count") == 1,
              f"cnt={backend_count('/bypass/count')}")

        # 7) proxy_no_cache：跳过读取且不写入
        st, hs, b = request("/nocache_ctl/count")
        check("/nocache_ctl 预热 MISS v=1", hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        st, hs, b = request("/nocache_ctl/count?nocache=1")
        check("no_cache 请求 → BYPASS 且拿到新内容",
              hdr(hs, "X-Cache-Status") == "BYPASS" and "nocache=1" in b,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        st, hs, b = request("/nocache_ctl/count")
        check("no_cache 响应未被写入（仍 HIT 旧 v=1）",
              hdr(hs, "X-Cache-Status") == "HIT" and version_of(b) == 1 and "nocache=1" not in b,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")

        # 8) keys_zone=tiny:1k → 容量 8，LRU 淘汰最久未使用
        for i in range(8):
            st, hs, b = request(f"/lru/k{i}")
            if not (st == 200 and hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 1):
                check(f"/lru/k{i} 首次 MISS v=1", False,
                      f"st={st} xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        st, hs, b = request("/lru/k0")
        check("LRU 触摸 k0 → HIT", hdr(hs, "X-Cache-Status") == "HIT" and version_of(b) == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        for i in range(8, 12):
            request(f"/lru/k{i}")
        st, hs, b = request("/lru/k0")
        check("最近用过的 k0 未被淘汰（HIT，后端计数=1）",
              hdr(hs, "X-Cache-Status") == "HIT" and backend_count("/lru/k0") == 1,
              f"xcs={hdr(hs,'X-Cache-Status')} cnt={backend_count('/lru/k0')}")
        st, hs, b = request("/lru/k1")
        check("最久未用的 k1 已被淘汰（MISS，后端计数=2）",
              hdr(hs, "X-Cache-Status") == "MISS" and backend_count("/lru/k1") == 2 and version_of(b) == 2,
              f"xcs={hdr(hs,'X-Cache-Status')} cnt={backend_count('/lru/k1')} body={b!r}")

        # 9) HEAD 只读不写：HEAD 响应无 body，不能污染同 key 的 GET 缓存
        st, hs, _ = request("/plain/count", method="HEAD")
        check("HEAD 命中 GET 已缓存条目（HIT，Content-Length 与 GET 一致）",
              st == 200 and hdr(hs, "X-Cache-Status") == "HIT"
              and hdr(hs, "Content-Length") == str(len(b1.encode())),
              f"st={st} xcs={hdr(hs,'X-Cache-Status')} cl={hdr(hs,'Content-Length')} expect={len(b1.encode())}")
        st, hs, _ = request("/plain/headtest", method="HEAD")
        check("HEAD 未命中正常回源（且不写缓存）",
              st == 200 and hdr(hs, "X-Cache-Status") == "BYPASS",
              f"st={st} xcs={hdr(hs,'X-Cache-Status')}")
        st, hs, b = request("/plain/headtest")
        check("HEAD 未污染 GET 缓存：随后 GET 仍 MISS 且 body 完整",
              hdr(hs, "X-Cache-Status") == "MISS" and version_of(b) == 2
              and "path=/plain/headtest" in b,
              f"xcs={hdr(hs,'X-Cache-Status')} body={b!r}")
        check("HEAD 与 GET 各回源一次（HEAD 没有把空体存进缓存）",
              backend_count("/plain/headtest") == 2,
              f"cnt={backend_count('/plain/headtest')}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()
        backend.server_close()
        try:
            dead.shutdown()
            dead.server_close()
        except Exception:
            pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== cache_advanced E2E: {passed}/{total} passed ====")
    print(f"     后端命中计数: {dict(sorted(hits.items()))}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
