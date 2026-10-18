# -*- coding: utf-8 -*-
# 可观测性 E2E（#40）：用真实流量证明新增指标与访问日志字段。
#   1) upstream 每节点 success/failure/连接数/健康度：正常节点、连不上的节点、换节点重试
#   2) proxy_cache HIT / MISS / EXPIRED / BYPASS 计数与 X-Cache-Status 一致
#   3) limit_req / limit_conn 拒绝计数
#   4) 入站 TLS 握手失败计数（明文垃圾打到 TLS 端口）
#   5) access_log 追加 request_time + "upstream_addr" upstream_status upstream_header_time
#   6) Upgrade（101）路径同样回填 upstream 指标与日志字段
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/observability_e2e.py
#
# 证书与配置都在临时目录里现生成，不污染 conf/。
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HTTP_PORT = 18300
UP_OK_PORT = 18301
UP_DEAD_PORT = 18302
CACHE_PORT = 18303
TLS_PORT = 18304
CONN_PORT = 18305
WS_PORT = 18307

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def slash(p):
    return p.replace("\\", "/")


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def http_get(port, path, timeout=8, host="127.0.0.1"):
    req = urllib.request.Request(f"http://{host}:{port}{path}", method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def parse_prom(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+)\s+([0-9.eE+]+)$", line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def get_metrics():
    st, _, body = http_get(HTTP_PORT, "/metrics")
    if st != 200:
        raise SystemExit(f"!! /metrics 返回 {st}")
    return parse_prom(body)


class BackendHandler(BaseHTTPRequestHandler):
    marker = b"A"

    def do_GET(self):
        cls = type(self)
        cls.count += 1
        body = cls.marker + str(cls.count).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend-Count", str(cls.count))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def backend_class(marker, name):
    return type(name, (BackendHandler,), {"marker": marker, "count": 0})


class WsBackend(socketserver.BaseRequestHandler):
    """读到完整升级请求后回 101，并挂着等客户端断开。"""

    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        time.sleep(0.4)


def ws_upgrade(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(
        b"GET /ws HTTP/1.1\r\n"
        b"Host: obs.local\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp


def raw_tls_garbage(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: tls.local\r\n\r\n")
    try:
        s.recv(64)
    except OSError:
        pass
    s.close()


def gen_certs(tmp):
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    r = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", slash(key), "-out", slash(cert),
            "-days", "2", "-nodes", "-subj", "/CN=obs.local",
        ],
        capture_output=True,
    )
    if r.returncode != 0:
        raise SystemExit("!! openssl 生成证书失败:\n" + r.stderr.decode(errors="replace"))
    return slash(cert), slash(key)


def write_conf(tmp, cert, key):
    cache_dir = os.path.join(tmp, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    conf = os.path.join(tmp, "obs.conf")
    err = slash(os.path.join(tmp, "obs_err.log"))
    access = slash(os.path.join(tmp, "obs_access.log"))
    text = f"""worker_connections 256;
error_log "{err}" info;
access_log "{access}";
shutdown_grace 2s;

limit_req_zone $remote_addr zone=obsr:1m rate=1r/s burst=0;
limit_conn_zone $binary_remote_addr zone=obsc:1m;
proxy_cache_path {slash(cache_dir)} keys_zone=obsz:1m;

upstream obs_up {{
    server 127.0.0.1:{UP_OK_PORT};
    server 127.0.0.1:{UP_DEAD_PORT};
}}
upstream ws_up {{
    server 127.0.0.1:{WS_PORT};
}}

server {{
    listen 127.0.0.1:{HTTP_PORT};
    server_name obs.local;

    location = /ping {{ return 200 "pong"; }}

    location /up/ {{
        proxy_pass http://obs_up;
    }}

    location /cached/ {{
        proxy_cache obsz;
        proxy_cache_valid 200 1s;
        proxy_cache_bypass $arg_bypass;
        proxy_pass http://127.0.0.1:{CACHE_PORT};
    }}

    location = /limited {{
        limit_req zone=obsr;
        return 200 "ok";
    }}

    location /ws {{
        proxy_pass http://ws_up;
    }}

    location /metrics {{ content_by_rust metrics; }}
}}

# limit_conn 用独立监听：server 级额度覆盖该 server 全部 location
server {{
    listen 127.0.0.1:{CONN_PORT};
    server_name conn.local;
    limit_conn obsc 1;

    location = /hold {{
        content_by_lua_block {{ ngx.sleep(0.8) ngx.say("held") }}
    }}
    location = /ping {{ return 200 "pong"; }}
}}

server {{
    listen 127.0.0.1:{TLS_PORT} ssl;
    server_name tls.local;
    ssl_certificate "{cert}";
    ssl_certificate_key "{key}";
    location / {{ return 200 "tls"; }}
}}
"""
    with open(conf, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return conf, access


def wait_ready(proc, port, err_log):
    for _ in range(100):
        if proc.poll() is not None:
            raise SystemExit(f"!! 网关提前退出（{proc.returncode}），见 {err_log}")
        try:
            st, _, _ = http_get(port, "/ping", timeout=1)
            if st == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise SystemExit(f"!! 网关未就绪，见 {err_log}")


def wait_log_line(path, needle, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if needle in line:
                        return line.rstrip("\n")
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    return ""


def run(tmp):
    cert, key = gen_certs(tmp)
    conf, access_log = write_conf(tmp, cert, key)
    err_log = os.path.join(tmp, "obs_err.log")

    ok_cls = backend_class(b"A", "OkBackend")
    cache_cls = backend_class(b"C", "CacheBackend")
    ok_srv = ThreadingHTTPServer(("127.0.0.1", UP_OK_PORT), ok_cls)
    cache_srv = ThreadingHTTPServer(("127.0.0.1", CACHE_PORT), cache_cls)
    ws_srv = socketserver.ThreadingTCPServer(("127.0.0.1", WS_PORT), WsBackend)
    ws_srv.daemon_threads = True
    for s in (ok_srv, cache_srv):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    threading.Thread(target=ws_srv.serve_forever, daemon=True).start()

    exe = find_binary()
    logf = open(os.path.join(tmp, "obs_stdout.log"), "wb")
    proc = subprocess.Popen([exe, conf], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        wait_ready(proc, HTTP_PORT, err_log)

        # ---- 1. upstream success/failure：b 端口没人监听，换节点后仍由 a 成功 ----
        up_status = [http_get(HTTP_PORT, "/up/x")[0] for _ in range(3)]
        check("upstream 三连请求全部 200（连接失败自动换节点）", up_status == [200, 200, 200], str(up_status))
        m = get_metrics()
        a_succ = m.get(f'onrouter_upstream_requests_total{{upstream="obs_up",server="127.0.0.1:{UP_OK_PORT}",result="success"}}', -1)
        b_fail = m.get(f'onrouter_upstream_requests_total{{upstream="obs_up",server="127.0.0.1:{UP_DEAD_PORT}",result="failure"}}', -1)
        check("正常节点 success 计数 = 3", a_succ == 3, f"got {a_succ}")
        check("死节点 failure 计数 = 1（只尝试一次）", b_fail == 1, f"got {b_fail}")
        a_conn = m.get(f'onrouter_upstream_server_connections{{upstream="obs_up",server="127.0.0.1:{UP_OK_PORT}"}}', -1)
        check("upstream 在途连接 gauge 归零", a_conn == 0, f"got {a_conn}")
        a_health = m.get(f'onrouter_upstream_server_healthy{{upstream="obs_up",server="127.0.0.1:{UP_OK_PORT}"}}', -1)
        check("upstream 健康 gauge = 1", a_health == 1, f"got {a_health}")

        # ---- 2. cache 状态计数：MISS → HIT → BYPASS → EXPIRED ----
        st1, h1, _ = http_get(HTTP_PORT, "/cached/k1")
        st2, h2, _ = http_get(HTTP_PORT, "/cached/k1")
        st3, h3, _ = http_get(HTTP_PORT, "/cached/k1?bypass=1")
        time.sleep(1.2)
        st4, h4, _ = http_get(HTTP_PORT, "/cached/k1")
        tags = [h1.get("x-cache-status"), h2.get("x-cache-status"), h3.get("x-cache-status"), h4.get("x-cache-status")]
        check("X-Cache-Status 依次为 MISS/HIT/BYPASS/EXPIRED", tags == ["MISS", "HIT", "BYPASS", "EXPIRED"], str(tags))
        check("缓存序列四个响应都是 200", [st1, st2, st3, st4] == [200, 200, 200, 200], str([st1, st2, st3, st4]))
        m = get_metrics()
        for tag, want in (("hit", 1), ("miss", 1), ("expired", 1), ("bypass", 1)):
            got = m.get(f'onrouter_cache_requests_total{{status="{tag}"}}', -1)
            check(f"cache 指标 {tag} = {want}", got == want, f"got {got}")

        # ---- 3. limit_req：rate=1r/s burst=0，第二次立刻 429 ----
        s1 = http_get(HTTP_PORT, "/limited")[0]
        s2, h2, _ = http_get(HTTP_PORT, "/limited")
        check("limit_req 首个请求放行", s1 == 200, f"got {s1}")
        check("limit_req 第二个请求 429", s2 == 429, f"got {s2}")
        check("429 带 Retry-After", "retry-after" in h2, str(h2))

        # ---- 4. limit_conn：/hold 在途时同 IP 的 /ping 被 503 ----
        hold_result = {}

        def do_hold():
            try:
                hold_result["st"] = http_get(CONN_PORT, "/hold", timeout=8)[0]
            except Exception as e:  # noqa: BLE001
                hold_result["err"] = str(e)

        th = threading.Thread(target=do_hold)
        th.start()
        time.sleep(0.25)
        st_busy = http_get(CONN_PORT, "/ping")[0]
        th.join(timeout=5)
        st_after = http_get(CONN_PORT, "/ping")[0]
        check("hold 请求本身 200", hold_result.get("st") == 200, str(hold_result))
        check("额度占满时 /ping 被 503", st_busy == 503, f"got {st_busy}")
        check("hold 结束额度释放，/ping 恢复 200", st_after == 200, f"got {st_after}")
        m = get_metrics()
        check("limit_req 拒绝计数 = 1", m.get('onrouter_limit_rejections_total{type="req"}') == 1)
        check("limit_conn 拒绝计数 = 1", m.get('onrouter_limit_rejections_total{type="conn"}') == 1)

        # ---- 5. TLS 握手失败：明文垃圾打到 TLS 端口 ----
        raw_tls_garbage(TLS_PORT)
        time.sleep(0.3)
        m = get_metrics()
        tls_fail = m.get("onrouter_tls_handshake_failures_total", -1)
        check("TLS 握手失败计数 >= 1", tls_fail >= 1, f"got {tls_fail}")

        # ---- 6. Upgrade(101)：上游 success 与日志 status/addr 同时生效 ----
        resp = ws_upgrade(HTTP_PORT)
        check("WebSocket 升级返回 101", b"101 Switching Protocols" in resp, resp[:120].decode(errors="replace"))
        time.sleep(0.3)
        m = get_metrics()
        ws_succ = m.get(f'onrouter_upstream_requests_total{{upstream="ws_up",server="127.0.0.1:{WS_PORT}",result="success"}}', -1)
        check("Upgrade 上游 success 计数 = 1", ws_succ == 1, f"got {ws_succ}")

        # ---- 7. access_log：request_time + "upstream_addr" upstream_status header_time ----
        line_up = wait_log_line(access_log, " /up/x ")
        pat_up = re.compile(
            r'^127\.0\.0\.1 - - \[[^\]]+\] "GET /up/x HTTP/1\.1" 200 \d+ '
            r'"[^"]*" "[^"]*" \d+\.\d{3} "127\.0\.0\.1:1830[12]" 200 \d+\.\d{3}$'
        )
        check("access_log /up/x 含 request_time + upstream 三元组", bool(pat_up.match(line_up)), line_up)
        line_plain = wait_log_line(access_log, ' "GET /ping HTTP/1.1"')
        check("无上游请求的 upstream 字段为 - - -", line_plain.endswith(" - - -"), line_plain)
        line_ws = wait_log_line(access_log, " /ws ")
        pat_ws = re.compile(
            rf'^127\.0\.0\.1 - - \[[^\]]+\] "GET /ws HTTP/1\.1" 101 \d+ '
            rf'"[^"]*" "[^"]*" \d+\.\d{{3}} "127\.0\.0\.1:{WS_PORT}" 101 \d+\.\d{{3}}$'
        )
        check("access_log Upgrade 行记录 101 + upstream", bool(pat_ws.match(line_ws)), line_ws)

        m = get_metrics()
        check("access_log 丢弃计数暴露且为 0", m.get("onrouter_access_log_dropped_total") == 0)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        ok_srv.shutdown()
        cache_srv.shutdown()
        ws_srv.shutdown()
        for s in (ok_srv, cache_srv, ws_srv):
            s.server_close()


def main():
    tmp = tempfile.mkdtemp(prefix="onrouter_obs_")
    try:
        run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{'=' * 56}\n{passed}/{total} PASS")
    if passed != total:
        print("FAILURES:")
        for name, ok in results:
            if not ok:
                print(" -", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
