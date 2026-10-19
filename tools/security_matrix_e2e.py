# -*- coding: utf-8 -*-
# 安全审计复现套件：把审计中确认的每条问题都用真实流量打成证据。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/security_matrix_e2e.py
#
# 覆盖：
#   S1 auth_basic 只有 realm、没有 user_file → 曾经放行（fail-open）
#   S2 htpasswd 里 `user:`（空哈希）→ 空口令即可登录
#   S3 htpasswd 缓存只按 mtime → 保持 mtime 改写文件，被删用户仍可登录
#   S4 Upgrade 隧道请求行不做百分号重编码 → 网关看到的资源与后端不同（# / ? 走私）
#   S5 流式上传（proxy_request_buffering off）不受 client_body_timeout 约束 → 慢客户端钉住连接
#   S6 sub_filter 命中大静态文件时整份读入内存 → 大文件 × 并发 = 内存放大
#   S7 Lua `while true` 无迭代上限 → 单进程内所有 Lua 端点一起失联（爆炸半径）
#
# 每个探针独立起一个进程（互不污染），端口 18320，后端 18321/18322。
import base64
import hashlib
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 18320
WS_BACKEND = 18321
SINK_BACKEND = 18322

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
    raise SystemExit("!! 先 cargo build --release -p onrouter-server --bin onrouter")


def wait_port(port, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_free(port, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            time.sleep(0.1)
        except OSError:
            return True
    return False


class Gateway:
    """一条配置 = 一个进程，探针之间完全隔离。"""

    def __init__(self, tmp, tag, body, head=""):
        self.tmp = tmp
        self.err = os.path.join(tmp, f"err_{tag}.log")
        conf = (
            f"error_log \"{slash(self.err)}\" warn;\n"
            f"pid \"{slash(os.path.join(tmp, 'p.pid'))}\";\n"
            + head
            + f"\nserver {{\n  listen 127.0.0.1:{PORT};\n  server_name sec.local;\n{body}\n}}\n"
        )
        path = os.path.join(tmp, f"{tag}.conf")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(conf)
        self.log = open(os.path.join(tmp, f"stdout_{tag}.log"), "ab")
        self.proc = subprocess.Popen([find_binary(), "-c", path], cwd=ROOT,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        self.dead = None

    def ready(self):
        if not wait_port(PORT):
            self.dead = self.read_err()
            return False
        return True

    def read_err(self):
        try:
            with open(self.err, "rb") as fh:
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)
        self.log.close()
        wait_free(PORT)


def http_call(path, method="GET", headers=None, body=None, timeout=8):
    """返回 (status, 小写响应头, body, 异常文本)。"""
    conn = HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        hdrs = {"Host": "sec.local"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data, ""
    except Exception as exc:  # noqa: BLE001 - 探针就是要捕获传输层异常
        return 0, {}, b"", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            conn.close()
        except OSError:
            pass


def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def raw_request(payload, timeout=4, read=True):
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    sock.sendall(payload)
    if not read:
        return sock
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 1 << 20:
                break
    except OSError:
        pass
    sock.close()
    return data


def rss_kb(pid):
    """Windows 任务管理器口径的内存占用（KB）。"""
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    m = re.search(r'"[^"]*","(\d+)","[^"]*","\d+","([\d,]+) K"', out)
    return int(m.group(2).replace(",", "")) if m else -1


# ---------------------------------------------------------------- 后端

class WsEcho(threading.Thread):
    """把收到的请求行原样回报，用来证明网关转发了什么。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.ss = socket.socket()
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ss.bind(("127.0.0.1", port))
        self.ss.listen(8)

    def run(self):
        while True:
            try:
                c, _ = self.ss.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            c.settimeout(6)
            buf = b""
            while b"\r\n\r\n" not in buf:
                got = c.recv(4096)
                if not got:
                    return
                buf += got
            first = buf.split(b"\r\n", 1)[0]
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      b"Connection: Upgrade\r\n\r\n")
            c.sendall(b"REQUEST-LINE:" + first + b"\r\n")
            c.settimeout(2)
            try:
                while True:
                    if not c.recv(4096):
                        break
            except OSError:
                pass
        except OSError:
            pass
        finally:
            c.close()


class SinkBody(threading.Thread):
    """收到完整请求体才回 200 —— 客户端一停，上游连接就一直悬着。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.ss = socket.socket()
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ss.bind(("127.0.0.1", port))
        self.ss.listen(8)
        self.done = 0

    def run(self):
        while True:
            try:
                c, _ = self.ss.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            c.settimeout(20)
            buf = b""
            while b"\r\n\r\n" not in buf:
                got = c.recv(4096)
                if not got:
                    return
                buf += got
            rest = buf.split(b"\r\n\r\n", 1)[1]
            body = rest
            while b"\r\n0\r\n\r\n" not in body and b"0\r\n\r\n" != body[-5:]:
                got = c.recv(4096)
                if not got:
                    return
                body += got
            self.done += 1
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()


def metrics(pid_port=None):
    st, _, body, err = http_call("/metrics")
    vals = {}
    for line in body.decode("utf-8", "replace").splitlines():
        m = re.match(r"^([a-z_:]+)(\{[^}]*\})?\s+([0-9.e+]+)$", line)
        if m:
            vals[m.group(1) + (m.group(2) or "")] = float(m.group(3))
    return vals, st, err


# ---------------------------------------------------------------- 探针

def s1_auth_without_file(tmp):
    """auth_basic 有 realm 但没有 user_file：绝不能放行。"""
    gw = Gateway(tmp, "s1", '  location /open {\n    auth_basic "Members";\n    return 200 "secret-data";\n  }')
    try:
        assert gw.ready(), gw.dead
        st, hd, body, _ = http_call("/open")
        check("S1 auth_basic 缺 user_file 不放行", st in (401, 500), f"status={st} body={body[:40]!r}")
    finally:
        gw.stop()


def s2_empty_hash(tmp):
    """htpasswd 里 `user:`（空哈希）不等于「空口令可登录」。"""
    ht = os.path.join(tmp, "ht2")
    sha = base64.b64encode(hashlib.sha1(b"pw2").digest()).decode()
    with open(ht, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"carol:{{SHA}}{sha}\ndave:\n")
    gw = Gateway(tmp, "s2",
                 f'  location /p2 {{\n    auth_basic "R";\n    auth_basic_user_file "{slash(ht)}";\n'
                 '    return 200 "ok";\n  }')
    try:
        assert gw.ready(), gw.dead
        st, _, _, _ = http_call("/p2", headers={"Authorization": basic("carol", "pw2")})
        check("S2 正常口令可用（对照组）", st == 200, f"status={st}")
        st, _, body, _ = http_call("/p2", headers={"Authorization": basic("dave", "")})
        check("S2 空哈希条目不接受空口令", st == 401, f"status={st} body={body[:40]!r}")
        st, _, _, _ = http_call("/p2", headers={"Authorization": basic("dave", "guess")})
        check("S2 空哈希条目猜口令也拒", st == 401, f"status={st}")
    finally:
        gw.stop()


def s3_htpasswd_staleness(tmp):
    """删除用户 + 保持 mtime 不变，凭据必须失效。"""
    ht = os.path.join(tmp, "ht3")
    sha = base64.b64encode(hashlib.sha1(b"pw3").digest()).decode()
    entry = f"erin:{{SHA}}{sha}\n"
    with open(ht, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(entry)
    gw = Gateway(tmp, "s3",
                 f'  location /p3 {{\n    auth_basic "R";\n    auth_basic_user_file "{slash(ht)}";\n'
                 '    return 200 "ok";\n  }')
    try:
        assert gw.ready(), gw.dead
        hdr = {"Authorization": basic("erin", "pw3")}
        st, _, _, _ = http_call("/p3", headers=hdr)
        check("S3 删除前可登录（对照组）", st == 200, f"status={st}")
        stamp = os.stat(ht).st_mtime
        with open(ht, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# erin revoked\nfrank:{SHA}" + base64.b64encode(hashlib.sha1(b"pw4").digest()).decode() + "\n")
        os.utime(ht, (stamp, stamp))  # 攻击场景：文件被换掉但 mtime 不变（脚本/rsync 保留时间戳）
        time.sleep(2.0)  # 允许一个「秒级 TTL」的刷新窗口
        st, _, body, _ = http_call("/p3", headers=hdr)
        check("S3 撤销用户后不再放行", st == 401, f"status={st} body={body[:40]!r}")
        st, _, _, _ = http_call("/p3", headers={"Authorization": basic("frank", "pw4")})
        check("S3 新用户在同一 mtime 下生效", st == 200, f"status={st}")
    finally:
        gw.stop()


def s4_upgrade_uri_desync(tmp):
    """Upgrade 隧道的请求行必须与网关路由所见的资源一致（# 与多余的 ? 都要重编码）。"""
    gw = Gateway(tmp, "s4", f'  location /ws {{\n    proxy_pass http://127.0.0.1:{WS_BACKEND};\n  }}',
                 head="")
    try:
        assert gw.ready(), gw.dead
        payload = (b"GET /ws%23frag?x=1%3fy=2 HTTP/1.1\r\n"
                   b"Host: sec.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        sock = raw_request(payload, timeout=6, read=False)
        head_buf = b""
        sock.settimeout(6)
        while b"\r\n\r\n" not in head_buf:
            got = sock.recv(1)
            if not got:
                break
            head_buf += got
        line = b""
        while not line.endswith(b"\r\n"):
            got = sock.recv(1)
            if not got:
                break
            line += got
        sock.close()
        seen = line.decode("utf-8", "replace").strip()
        up = head_buf.split(b"\r\n", 1)[0]
        check("S4 Upgrade 建隧道成功（对照组）", b"101" in up, up[:40])
        check("S4 请求行无裸 # 片段", b"#" not in seen.encode(), seen)
        check("S4 请求行只有一个 ? 分隔符", seen.count("?") == 1, seen)
    finally:
        gw.stop()


def s5_stalled_upload(tmp):
    """proxy_request_buffering off 的上传也受 client_body_timeout 管。"""
    gw = Gateway(
        tmp, "s5",
        f'  location /up {{\n    proxy_pass http://127.0.0.1:{SINK_BACKEND};\n'
        '    proxy_request_buffering off;\n  }\n'
        '  location /ping { return 200 "pong"; }\n'
        '  location /metrics { content_by_rust metrics; }',
        # client_body_timeout 是进程级设置，写在 server 块里不生效（与 settings 解析一致）
        head='client_body_timeout 2s;\n',
    )
    try:
        assert gw.ready(), gw.dead
        base, _, _ = metrics()
        active_base = base.get("onrouter_connections_active", 0)
        sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        sock.sendall(b"POST /up HTTP/1.1\r\nHost: sec.local\r\nTransfer-Encoding: chunked\r\n\r\n")
        sock.sendall(b"4\r\nabcd\r\n")
        time.sleep(5.0)  # 远超 client_body_timeout=2s
        stalled_active = metrics()[0].get("onrouter_connections_active", -1)
        # 网关应当已经回一个客户端错误并收口：读到 EOF 即切断。
        # 之前只看首个 recv 是否为空会误判——切断前网关还会先把错误响应发出来。
        sock.settimeout(3)
        got = b""
        closed = False
        try:
            while True:
                d = sock.recv(4096)
                if not d:
                    closed = True
                    break
                got += d
        except OSError:
            closed = True  # 已被 RST：同样算切断
        head_line = got.split(b"\r\n", 1)[0].decode("latin-1") if got else ""
        check("S5 停摆上传按 client_body_timeout 切断", closed and b"HTTP/" in got,
              f"5s 后未收口（收到 {len(got)} 字节）")
        check("S5 停摆上传回 408（nginx 语义）", head_line.split()[1] == "408" if len(head_line.split()) > 1 else False, head_line)
        pinned = stalled_active - active_base
        after, _, _ = metrics()
        active = after.get("onrouter_connections_active", -1)
        check("S5 停摆上传不长期占用连接额度", active <= active_base,
              f"停摆期间 +{pinned:.0f}，切断后 baseline={active_base} now={active}")
        st, _, body, _ = http_call("/ping", timeout=4)
        check("S5 其余请求不受影响", st == 200 and body == b"pong", f"status={st}")
    finally:
        gw.stop()


def s6_sub_filter_memory(tmp):
    """sub_filter 的缓冲必须有一个上限：小文件照常改写，大文件不许整份进内存。"""
    root = os.path.join(tmp, "big")
    os.makedirs(root, exist_ok=True)
    block = b"<p>" + b"x" * (64 * 1024 - 3) + b"</p>\n"
    # 2 MiB：低于缓冲上限，sub_filter 必须照常生效
    with open(os.path.join(root, "mid.html"), "wb") as fh:
        for _ in range(2 * 16):
            fh.write(block)
        fh.write(b"NEEDLE\n")
    # 32 MiB：高于上限，应当原样流式发送并在 error_log 里说明跳过原因
    with open(os.path.join(root, "huge.html"), "wb") as fh:
        for _ in range(32 * 16):
            fh.write(block)
        fh.write(b"NEEDLE\n")
    gw = Gateway(tmp, "s6",
                 f'  root "{slash(root)}";\n'
                 '  location / {\n    sub_filter "NEEDLE" "R";\n  }')
    try:
        assert gw.ready(), gw.dead
        st, _, body, _ = http_call("/mid.html", timeout=30)
        check("S6 上限内的文件仍然改写", st == 200 and b"\nR\n" in body[-16:],
              f"status={st} 尾部={body[-24:]!r}")
        st, _, body, _ = http_call("/huge.html", timeout=60)
        check("S6 超限文件仍可服务", st == 200, f"status={st}")
        # 缓冲整份的外部特征：首字节要等全文读完+改写完，于是 TTFB ≈ 总耗时。
        # 原样流式发送应当在几十毫秒内就吐出第一个字节。
        conn = HTTPConnection("127.0.0.1", PORT, timeout=60)
        t0 = time.time()
        conn.request("GET", "/huge.html", headers={"Host": "sec.local"})
        resp = conn.getresponse()
        first = resp.read(1)
        ttfb = time.time() - t0
        total_bytes = len(first)
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            total_bytes += len(chunk)
        total = time.time() - t0
        conn.close()
        mb = total_bytes / (1 << 20)
        check("S6 sub_filter 超限大文件走流式（不整份缓冲）", ttfb < total * 0.5,
              f"{mb:.0f} MiB 响应 ttfb={ttfb:.2f}s total={total:.2f}s")
        with open(gw.err, "r", encoding="utf-8", errors="replace") as fh:
            log_text = fh.read()
        check("S6 跳过改写会在 error_log 说明", "sub_filter" in log_text and "缓冲上限" in log_text,
              log_text[-300:])
    finally:
        gw.stop()


def s7_lua_infinite_loop(tmp):
    """一段死循环 Lua 不能把整个进程的 Lua 流量拖死。"""
    gw = Gateway(tmp, "s7",
                 '  location /spin {\n    content_by_lua_block { while true do end }\n  }\n'
                 '  location /lua {\n    content_by_lua_block { ngx.say("alive") }\n  }\n'
                 '  location /ping { return 200 "pong"; }\n')
    try:
        assert gw.ready(), gw.dead
        burner = threading.Thread(
            target=lambda: raw_request(
                f"GET /spin HTTP/1.1\r\nHost: sec.local\r\n\r\n".encode(), timeout=30, read=True),
            daemon=True)
        burner.start()
        time.sleep(0.8)
        t0 = time.time()
        st, _, body, err = http_call("/lua", timeout=5)
        spent = time.time() - t0
        check("S7 死循环期间其它 Lua 端点仍可响应", st == 200 and body.strip() == b"alive",
              f"status={st} 耗时={spent:.1f}s {err}")
        st, _, body, err = http_call("/ping", timeout=5)
        check("S7 死循环期间非 Lua 端点仍可响应", st == 200 and body == b"pong",
              f"status={st} {err}")
    finally:
        gw.stop()


def main():
    tmp = tempfile.mkdtemp(prefix="orr_sec_")
    ws = WsEcho(WS_BACKEND)
    sink = SINK_BACKEND and SinkBody(SINK_BACKEND)
    ws.start()
    sink.start()
    probes = [s1_auth_without_file, s2_empty_hash, s3_htpasswd_staleness,
              s4_upgrade_uri_desync, s5_stalled_upload, s6_sub_filter_memory, s7_lua_infinite_loop]
    if len(sys.argv) > 1:  # python tools/security_matrix_e2e.py s5,s6
        want = {x.strip() for x in sys.argv[1].split(",")}
        probes = [p for p in probes if p.__name__.split("_")[0] in want]
    try:
        for probe in probes:
            print(f"\n--- {probe.__name__} ---")
            try:
                probe(tmp)
            except AssertionError as exc:
                check(probe.__name__ + " 启动", False, f"进程未就绪：{str(exc)[:400]}")
            except Exception as exc:  # noqa: BLE001
                check(probe.__name__ + " 执行", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n_ok = sum(1 for _, ok in results if ok)
    print("\n" + "=" * 56)
    print(f"{n_ok}/{len(results)} PASS")
    for name, ok in results:
        if not ok:
            print("  FAIL:", name)
    print("=" * 56)
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
