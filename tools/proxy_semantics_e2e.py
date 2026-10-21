# -*- coding: utf-8 -*-
# proxy 语义 E2E —— 用真实流量验证 #37 的三组补全：
#   * proxy_send_timeout：后端不读请求体时，64MB 上传在 300ms 写空闲后断开；
#     对照组 send=0 不会被写超时提前掐断（read 超时只从请求体发完起算）；
#     正常后端持续读取时大上传不被误伤
#   * proxy_next_upstream：http_500 / non_idempotent / tries / timeout / invalid_header
#     各自触发（或不触发）换节点，用坏/好两台后端的命中计数证明真实重试
#   * 默认值（error timeout）不因 500 换节点（对照组）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_semantics_e2e.py
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "proxy_semantics.conf")

GW_HOST, GW_PORT = "127.0.0.1", 18160
GOOD_PORT, BAD_PORT, SINK_PORT, UPLOAD_PORT, MALFORMED_PORT = 18161, 18162, 18163, 18164, 18165
BASE = f"http://{GW_HOST}:{GW_PORT}"
BIG = b"x" * (64 * 1024 * 1024)

results = []
hits = {}
_hits_lock = threading.Lock()


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def hit(tag, path):
    with _hits_lock:
        hits[(tag, path)] = hits.get((tag, path), 0) + 1


def hit_count(tag, path):
    with _hits_lock:
        return hits.get((tag, path), 0)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, data=None, timeout=20):
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data is not None else "GET")
    t0 = time.time()
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), time.time() - t0


class Good(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _reply(self):
        hit("good", self.path)
        body = f"GOOD path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *_a):
        pass


class Bad(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _reply(self):
        hit("bad", self.path)
        time.sleep(0.03)
        body = b"BAD"
        self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *_a):
        pass


class Sink(BaseHTTPRequestHandler):
    # 只读请求头，不收 body：让网关的上游写缓冲持续阻塞
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        hit("sink", self.path)
        # 只收头部、不收 body（睡一会儿再关闭，避免立即断开掩盖超时行为）
        time.sleep(6)

    def log_message(self, *_a):
        pass


class Upload(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        hit("upload", self.path)
        n = int(self.headers.get("Content-Length", "0"))
        got = 0
        while got < n:
            chunk = self.rfile.read(min(65536, n - got))
            if not chunk:
                break
            got += len(chunk)
        body = f"UPLOAD got={got}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class Malformed(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        hit("malformed", self.path)
        # 非法 Content-Length：hyper 在解析响应头时应报 invalid/parse 错误
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nBAD")

    def log_message(self, *_a):
        pass


class SinkServer(ThreadingHTTPServer):
    """把接收缓冲压到最小，确保上游写端会真正阻塞（而不是被 8MB 内核缓冲吃掉）。"""

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        super().server_bind()


def serve(port, handler, server_cls=ThreadingHTTPServer):
    srv = server_cls(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    servers = [
        serve(GOOD_PORT, Good),
        serve(BAD_PORT, Bad),
        serve(SINK_PORT, Sink, SinkServer),
        serve(UPLOAD_PORT, Upload),
        serve(MALFORMED_PORT, Malformed),
    ]

    logf = open(os.path.join(ROOT, "logs", "proxy_semantics_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18160 被占用？看 logs/proxy_semantics_err.log）")

        # 1) http_500 触发换节点：4 次请求全部 200，且确实打到过坏节点
        sts = []
        for _ in range(4):
            st, body, _ = request("/nu-retry")
            sts.append((st, "GOOD" in body))
        check("/nu-retry 4/4 → 200（500 换到好节点）", all(s == 200 and ok for s, ok in sts), f"{sts}")
        bad = hit_count("bad", "/nu-retry")
        good = hit_count("good", "/nu-retry")
        check("/nu-retry 确实先撞过坏节点", bad >= 1, f"bad={bad} good={good}")

        # 2) 默认 error timeout 不因 500 换节点（对照组）
        sts = [request("/nu-default")[0] for _ in range(2)]
        check("/nu-default 默认不重试 500（出现 500）", 500 in sts, f"{sts}")
        check("/nu-default 坏/好节点都被轮到", hit_count("bad", "/nu-default") >= 1 and hit_count("good", "/nu-default") >= 1,
              f"bad={hit_count('bad', '/nu-default')} good={hit_count('good', '/nu-default')}")

        # 3) POST + non_idempotent：允许换节点
        sts = [request("/nu-post", data=b"")[0] for _ in range(2)]
        check("/nu-post non_idempotent 2/2 → 200", sts == [200, 200], f"{sts}")
        check("/nu-post 确实撞过坏节点", hit_count("bad", "/nu-post") >= 1, f"bad={hit_count('bad', '/nu-post')}")

        # 4) POST 未配 non_idempotent：500 直接返回
        sts = [request("/nu-post-strict", data=b"")[0] for _ in range(2)]
        check("/nu-post-strict 未配 non_idempotent → 出现 500", 500 in sts, f"{sts}")
        check("/nu-post-strict 坏节点没有被重试两次", hit_count("bad", "/nu-post-strict") == 1,
              f"bad={hit_count('bad', '/nu-post-strict')}")

        # 5) tries=1 禁止第二次尝试；tries=2 允许
        sts = [request("/nu-tries1")[0] for _ in range(2)]
        check("/nu-tries1（tries=1）→ 出现 500", 500 in sts, f"{sts}")
        sts = [request("/nu-tries2")[0] for _ in range(2)]
        check("/nu-tries2（tries=2）2/2 → 200", sts == [200, 200], f"{sts}")

        # 6) next_upstream_timeout=1ms：坏节点先睡 30ms 才回 500，预算已耗尽 → 不再换节点
        st, body, _ = request("/nu-deadline")
        check("/nu-deadline 1ms 预算耗尽 → 500", st == 500, f"st={st} body={body!r}")
        check("/nu-deadline 未打到好节点", hit_count("good", "/nu-deadline") == 0,
              f"good={hit_count('good', '/nu-deadline')}")

        # 7) invalid_header：坏响应头 → 换到好节点
        sts = [request("/nu-invalid")[0] for _ in range(2)]
        check("/nu-invalid invalid_header 2/2 → 200", sts == [200, 200], f"{sts}")
        check("/nu-invalid 确实收到过非法响应头", hit_count("malformed", "/nu-invalid") >= 1,
              f"malformed={hit_count('malformed', '/nu-invalid')}")

        # 8) proxy_send_timeout：sink 不收 body，300ms 写空闲后断开（远早于 30s read 超时）
        st, _, el = request("/big", data=BIG, timeout=40)
        check("/big 后端不收 body → 504（写超时也是超时，不是连不上）", st == 504, f"st={st}")
        check("/big 在 send_timeout(300ms) 后快速失败（<1.5s）", el < 1.5, f"elapsed={el:.2f}s")

        # 9) 对照：send=0 时只能等 read 超时(2s)
        st, _, el = request("/big-nolimit", data=BIG, timeout=40)
        check("/big-nolimit send=0 不被写超时掐断 → 由 read 2s 兜底 504", st == 504, f"st={st}")
        check("/big-nolimit 耗时 >=1.7s（证明没有 300ms 写超时）", el >= 1.7, f"elapsed={el:.2f}s")

        # 10) 正常后端持续读取：写超时不应误伤 8MB 上传
        st, body, el = request("/big-ok", data=BIG, timeout=40)
        check("/big-ok 64MB 上传 → 200", st == 200 and "got=67108864" in body, f"st={st} body={body!r}")
        check("/big-ok 在 send_timeout 内完成且数据完整", el < 5.0, f"elapsed={el:.2f}s")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for s in servers:
            s.shutdown()
            s.server_close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== proxy 语义 E2E: {passed}/{total} passed ====")
    print(f"     命中统计: {dict(sorted(hits.items()))}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
