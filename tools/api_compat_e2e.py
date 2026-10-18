# -*- coding: utf-8 -*-
# OpenResty API 兼容层 E2E —— 真实流量验证：
#   ngx.req.start_time/http_version/is_internal、ngx.send_headers/headers_sent/eof、
#   init_body/append_body/finish_body/set_body_data/discard_body（含代理转发）、
#   ngx.worker.*、shared dict get_keys/expire、capture method/body/args、capture_multi 并发、
#   ngx.semaphore、resty.cookie（多 Set-Cookie）、resty.limit.count/req/conn、
#   cosocket sslhandshake 别名 + getreusedtimes（跨请求连接池复用）、新增 ngx.var。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/api_compat_e2e.py
import http.client
import itertools
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "api_compat.conf")

ORR_HOST, ORR_PORT = "127.0.0.1", 18200
ECHO_PORT, TCP_PORT = 18201, 18202

results = []
CONN_SEQ = itertools.count(1)


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


# ---------------- 上游：HTTP echo ----------------
class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "query": urlparse(self.path).query,
            "body": body.decode("utf-8", errors="replace"),
            "content_length": self.headers.get("Content-Length"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _echo
    do_POST = _echo
    do_PUT = _echo

    def log_message(self, *a):
        pass


# ---------------- 上游：TCP 行 echo（带连接编号） ----------------
class TcpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        connid = next(CONN_SEQ)
        self.request.settimeout(30)
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    self.request.sendall(b"OK:" + line + b"#" + str(connid).encode() + b"\n")
                except OSError:
                    return


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class QuietHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # 客户端半路断开（连接池关闭）不算测试失败


# ---------------- ONRouter 生命周期 ----------------
def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def wait_ready(timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection(ORR_HOST, ORR_PORT, timeout=1)
            conn.request("GET", "/meta", headers={"Host": "api.local"})
            conn.getresponse().read()
            conn.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def http_req(method, path, body=None, headers=None, timeout=15):
    conn = http.client.HTTPConnection(ORR_HOST, ORR_PORT, timeout=timeout)
    hdrs = {"Host": "api.local", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    if isinstance(body, str):
        body = body.encode()
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    hs = resp.getheaders()
    status = resp.status
    conn.close()
    return status, hs, data.decode("utf-8", errors="replace")


def kv_lines(body):
    out = {}
    for line in body.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def header_values(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


def main():
    http_srv = QuietHttpServer(("127.0.0.1", ECHO_PORT), EchoHandler)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    tcp_srv = TcpServer(("127.0.0.1", TCP_PORT), TcpEchoHandler)
    threading.Thread(target=tcp_srv.serve_forever, daemon=True).start()

    binp = find_binary()
    proc = subprocess.Popen([binp, "-c", CONF],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            raise SystemExit("!! onrouter never became ready on %d" % ORR_PORT)

        # ---- 1. 请求元信息 + worker ----
        st, _, body = http_req("GET", "/meta")
        kv = kv_lines(body)
        check("/meta 状态 200", st == 200, body)
        check("/meta start_time > 0", kv.get("start_ok") == "true", body)
        check("/meta http_version=1.1", kv.get("http_version") == "1.1", body)
        check("/meta is_internal=false（外部请求）", kv.get("internal") == "false", body)
        check("/meta worker.pid 等于进程 PID", kv.get("pid") == str(proc.pid), f"pid={kv.get('pid')} proc={proc.pid}")
        check("/meta worker.pids 只含自身",
              kv.get("pids_count") == "1" and kv.get("pid1") == str(proc.pid), body)
        check("/meta worker id/count = 0/1", kv.get("wid") == "0" and kv.get("wcount") == "1", body)
        check("/meta worker.exiting=false", kv.get("exiting") == "false", body)

        # ---- 2. 新增 ngx.var ----
        st, _, body = http_req(
            "POST", "/vars?a=hello%20world", body="xyz",
            headers={"Cookie": "sid=abc123", "Content-Type": "text/plain"})
        kv = kv_lines(body)
        check("/vars arg_a 解码正确", kv.get("arg_a") == "hello world", body)
        check("/vars cookie_sid", kv.get("cookie_sid") == "abc123", body)
        check("/vars request_body", kv.get("body") == "xyz", body)
        check("/vars content_length=3", kv.get("cl") == "3", body)
        check("/vars https 为空（明文）", kv.get("https", "MISSING") == "", body)
        try:
            rt_ok = float(kv.get("rt", "-1")) >= 0
            msec_ok = float(kv.get("msec", "-1")) > 1_600_000_000
        except ValueError:
            rt_ok = msec_ok = False
        check("/vars request_time 数值", rt_ok, body)
        check("/vars msec 为 epoch 毫秒/秒", msec_ok, body)
        check("/vars server_addr=127.0.0.1", kv.get("server_addr") == "127.0.0.1", body)
        check("/vars hostname 可读", kv.get("hostname_ok") == "true", body)

        # ---- 3. send_headers / headers_sent / eof ----
        st, _, body = http_req("GET", "/send_headers")
        check("/send_headers 前 false 后 true",
              st == 200 and "before:false" in body and "after:true" in body, body)

        st, _, body = http_req("GET", "/eof")
        check("/eof 只输出 eof 前内容", st == 200 and body.strip() == "A", repr(body))

        # ---- 4. 请求体构造 + 代理转发 ----
        st, _, body = http_req("GET", "/echo_body")
        try:
            j = json.loads(body)
        except Exception:
            j = {}
        check("/echo_body 转成 POST", j.get("method") == "POST", body)
        check("/echo_body 转发构造体 hello world", j.get("body") == "hello world", body)
        check("/echo_body Content-Length=11", j.get("content_length") == "11", body)

        st, _, body = http_req("POST", "/echo_set", body="original-body")
        j = json.loads(body) if body.startswith("{") else {}
        check("/echo_set set_body_data 覆盖原体", j.get("body") == "replaced-body", body)
        check("/echo_set Content-Length=13", j.get("content_length") == "13", body)

        st, _, body = http_req("POST", "/echo_drop", body="discard-me")
        j = json.loads(body) if body.startswith("{") else {}
        check("/echo_drop discard_body 转发空体", j.get("body") == "", body)
        check("/echo_drop Content-Length=0", j.get("content_length") == "0", body)

        # ---- 5. capture 选项 + capture_multi 并发 ----
        st, _, body = http_req("GET", "/cap_up")
        check("/cap_up 子请求返回 200", "status: 200" in body.replace(":", ": ") or "status:200" in body, body)
        check("/cap_up capture body 生效", "cap-payload" in body, body)
        check("/cap_up capture args 生效", "x=1" in body and "y=two" in body, body)
        check("/cap_up capture method 生效", '"method": "POST"' in body or '"method":"POST"' in body, body)
        check("/cap_up 子请求 is_internal=true", "internal:true" in body.replace(" ", ""), body)

        st, _, body = http_req("GET", "/cap_multi", timeout=25)
        check("/cap_multi 4 个子请求结果齐全",
              st == 200 and all(f"s{i}" in body for i in (1, 2, 3, 4)), body)
        m = re.search(r"elapsed:\s*([0-9.]+)", body)
        dt = float(m.group(1)) if m else 99
        check("/cap_multi 并发执行（<0.45s，串行需 0.8s）", dt < 0.45, f"elapsed={dt} body={body!r}")

        # ---- 6. ngx.semaphore ----
        st, _, body = http_req("GET", "/sem")
        kv = kv_lines(body)
        woke = float(kv.get("woke_after", "-1"))
        check("/sem wait 被 post 唤醒", kv.get("wait") == "true", body)
        check("/sem 唤醒时延≈0.1s（不是超时 1s）", 0.08 <= woke <= 0.5, f"woke={woke} body={body!r}")
        check("/sem 线程返回 posted", kv.get("thread") == "posted", body)
        check("/sem 无信号时超时", kv.get("timeout") == "nil" and kv.get("timeout_err") == "timeout", body)

        # ---- 7. shared dict get_keys / expire ----
        st, _, body = http_req("GET", "/dict")
        kv = kv_lines(body)
        check("/dict get_keys 只列存活键", kv.get("keys") == "k1" and kv.get("more") == "false", body)
        check("/dict expire 不存在的 key=false", kv.get("expire_missing") == "false", body)
        check("/dict expire 成功=true", kv.get("expire_k1") == "true", body)
        check("/dict expire 到期后读取 nil", kv.get("k1_after") == "nil", body)

        # ---- 8. resty.cookie + 多 Set-Cookie ----
        st, hs, body = http_req("GET", "/cookie", headers={"Cookie": "sid=abc123"})
        kv = kv_lines(body)
        sc = header_values(hs, "Set-Cookie")
        check("/cookie 解析请求 Cookie", kv.get("sid") == "abc123", body)
        check("/cookie 读取多值头为 table#3",
              kv.get("multi_type") == "table" and kv.get("multi_count") == "3", body)
        check("/cookie 响应含 3 条 Set-Cookie", len(sc) == 3, f"sc={sc!r} body={body!r}")
        check("/cookie 追加项带 HttpOnly",
              len(sc) == 3 and any("new=v" in v and "HttpOnly" in v for v in sc), f"sc={sc!r}")

        # ---- 9. resty.limit.count ----
        seq = [http_req("GET", "/limit_count") for _ in range(5)]
        rem = [kv_lines(b).get("remaining") for st_, _, b in seq if st_ == 200]
        rejected = [b for st_, _, b in seq if st_ == 429]
        check("/limit_count 前 3 次放行且余量递减", rem == ["2", "1", "0"], f"rem={rem}")
        check("/limit_count 后 2 次 429 rejected", len(rejected) == 2 and all("rejected" in b for b in rejected), f"rej={rejected}")

        # ---- 10. resty.limit.req ----
        st1, _, b1 = http_req("GET", "/limit_req")
        st2, _, b2 = http_req("GET", "/limit_req")
        check("/limit_req 首个放行 delay 0", st1 == 200 and "delay:0.00" in b1, b1)
        check("/limit_req 同秒第二个 429", st2 == 429 and "rejected" in b2, b2)

        # ---- 11. resty.limit.conn（并发占位） ----
        box = {}

        def hold():
            box["first"] = http_req("GET", "/limit_conn", timeout=20)

        th = threading.Thread(target=hold)
        th.start()
        time.sleep(0.08)
        st2, _, b2 = http_req("GET", "/limit_conn", timeout=20)
        th.join(timeout=20)
        st1, _, b1 = box.get("first", (0, [], ""))
        check("/limit_conn 首请求占位 conn:1", st1 == 200 and "conn:1" in b1.replace(" ", ""), b1)
        check("/limit_conn 并发第二请求 429", st2 == 429 and "rejected" in b2, b2)
        check("/limit_conn leaving 后计数归零", "left:0" in b1.replace(" ", ""), b1)
        st3, _, b3 = http_req("GET", "/limit_conn")
        check("/limit_conn 释放后新请求放行", st3 == 200 and "conn:1" in b3.replace(" ", ""), b3)

        # ---- 12. cosocket 别名 + getreusedtimes 池复用 ----
        st1, _, b1 = http_req("GET", "/sock_alias")
        st2, _, b2 = http_req("GET", "/sock_alias")
        kv1 = kv_lines(b1)
        kv2 = kv_lines(b2)
        m1 = re.search(r"#(\d+)", b1)
        m2 = re.search(r"#(\d+)", b2)
        check("/sock_alias sslhandshake 是函数", kv1.get("alias") == "function", b1)
        check("/sock_alias 首连接 reused=0", kv1.get("reused") == "0", b1)
        check("/sock_alias 第二次 reused=1", kv2.get("reused") == "1", b2)
        check("/sock_alias 命中同一后端连接", m1 and m2 and m1.group(1) == m2.group(1),
              f"b1={b1!r} b2={b2!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        http_srv.shutdown()
        tcp_srv.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== API 兼容层 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
