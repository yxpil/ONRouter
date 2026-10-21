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
#   S8 run_phases 极性反了 → 阶段脚本报错被当成"检查通过"（见 rce_matrix 的 r1）
#   S9 Still ONLine 副本区不看响应 Cache-Control：`private` 的按租户响应被存下来，
#      上游一挂就回放给**另一个客户端**（跨用户泄漏）。对照：public 响应仍要能顶住。
#   S10 冷层 atomic_write 的临时文件名可预测（<hex>.<pid>.tmp）且用 File::create：
#      预先在 tmp 路径上放一个硬链接到别处的文件，落盘就会把那个文件截断（任意覆盖写）。
#   S11 limit_req_zone 的 key 变量在请求路径上从不展开（永远按 $remote_addr）：
#      写了 `$http_x_api_key` 的运维以为按令牌限流，实际是按 IP 限流 —— -t 必须否决。
#   S12 信誉表是直接映射 + 冲突即覆盖：算出一个 tag 撞进 VIP 槽位的地址，
#      一个请求就把那个 VIP 的分数清零（定向降级）。realip 还让 key 可伪报。
#
# 每个探针独立起一个进程（互不污染），端口 18320，后端 18321/18322/18323。
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
VARIANT_BACKEND = 18323

results = []
VARIANT = None  # s9 用的按租户后端，在 main() 里起
DBG = bool(os.environ.get("SECDBG"))


def dbg(*args):
    """SECDBG=1 时打印诊断行：探针在断言之前的原始观测（指标原文、启动日志尾巴）。"""
    if DBG:
        print("    dbg:", *args, flush=True)


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
        self.conf = path
        self.log = open(os.path.join(tmp, f"stdout_{tag}.log"), "ab")
        self.proc = subprocess.Popen([find_binary(), "-c", path], cwd=ROOT,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        self.dead = None

    def ready(self):
        if not wait_port(PORT):
            # error_log 常常是空的：配置加载失败、指令拼错这些走的是进程 stdout/stderr
            self.dead = self.read_err() or self.boot_output()
            return False
        return True

    def read_err(self):
        try:
            with open(self.err, "rb") as fh:
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def boot_output(self):
        """进程自己的 stdout/stderr 落点：配置加载失败这类"根本不会进 error_log"的话在这儿。"""
        p = os.path.join(os.path.dirname(self.conf), f"stdout_{os.path.basename(self.conf)[:-5]}.log")
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
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


class VariantBackend(threading.Thread):
    """按请求头分租户的后端：用来证明"响应带 Cache-Control: private"的按租户正文
    会不会被 Still ONLine 收进副本区、然后回放给没有凭证的另一个客户端。

    /priv/panel -> Cache-Control: private（正文随 X-Api-Key 变，无 Set-Cookie）
    /pub/panel  -> Cache-Control: public, max-age=60（正文恒定）
    dead=True   -> 接受连接后立刻断开（上游故障，触发回放路径）
    """

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.dead = False
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
            if self.dead:
                c.close()
                return
            path = buf.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin-1")
            key = ""
            for line in buf.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"x-api-key":
                    key = v.strip().decode("latin-1")
            if path.startswith("/priv/"):
                who = "VICTIM" if key.startswith("victim") else "ANON"
                body = f"TENANT-{who}-DATA".encode()
                head = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nCache-Control: private, max-age=300\r\nConnection: close\r\n\r\n" % len(body)
            else:
                body = b"PUBLIC-PANEL-DATA"
                head = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nCache-Control: public, max-age=60\r\nConnection: close\r\n\r\n" % len(body)
            c.sendall(head.encode() + body)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass


def run_t(tmp, tag, conf_text):
    """跑 `onrouter -c <conf> -t`，返回 (退出码, 合并输出)。用于"配置期就该拦住"的断言。"""
    path = os.path.join(tmp, f"{tag}_t.conf")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(conf_text)
    p = subprocess.run([find_binary(), "-c", path, "-t"], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def murmur_hash2(data: bytes) -> int:
    """与 engine::murmur_hash2 逐位一致（nginx 的 32 位 murmur，种子 = len ^ 0x9dc03ac8）。
    复刻它不是为了绕过什么，而是为了**证明**信誉表是直接映射：能算出撞进同一个槽的地址。"""
    M = 0x5BD1E995
    MASK = 0xFFFFFFFF
    ln = len(data)
    h = (ln ^ 0x9DC03AC8) & MASK
    i = 0
    while i + 4 <= ln:
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * M) & MASK
        k ^= k >> 24
        k = (k * M) & MASK
        h = (h * M) & MASK
        h ^= k
        i += 4
    rem = ln - i
    if rem == 3:
        h ^= data[i + 2] << 16
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 2:
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 1:
        h ^= data[i]
        h = (h * M) & MASK
    h ^= h >> 13
    h = (h * M) & MASK
    h ^= h >> 15
    return h


def fnv_key_hash(key: str) -> int:
    """与 disk_cache::key_hash 一致（FNV-1a 64 + 末位混淆）：用来预测冷层条目文件的路径。"""
    h = 0xCBF29CE484222325
    for b in key.encode():
        h ^= b
        h = (h * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 29
    return h


def entry_path_of(root, key: str, levels=(1, 2)) -> str:
    hexs = "%016x" % fnv_key_hash(key)
    p = root
    off = 0
    for l in levels:
        off = min(off + l, len(hexs))
        p = os.path.join(p, hexs[:off])
    return os.path.join(p, hexs + ".bin")


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


def s13_duplicate_host(tmp):
    """两条 Host 头必须 400（RFC 9112 只允许一条）。

    历史行为是"取第一条"：客户端库常在显式 Host 之前自动加一条 `127.0.0.1:端口`，
    于是请求被路由到该端口的**默认站点**——响应完全正常，只是内容来自别的租户。
    这类"看起来成功"的跨站点路由比一个 400 危险得多。（随机拓扑套件正是被这个形态
    骗出了几十条"网关选错 vhost"的假故障。）
    """
    gw = Gateway(tmp, "s13", '  location / { return 200 "ok"; }', head="")
    try:
        assert gw.ready(), gw.dead
        dup = (b"GET / HTTP/1.1\r\n"
               b"Host: 127.0.0.1:18320\r\n"
               b"Host: sec.local\r\n"
               b"Connection: close\r\n\r\n")
        got = raw_request(dup)
        first = got.split(b"\r\n", 1)[0]
        check("S13 两条 Host 头被拒（400，不是默默按第一条路由）", b"400" in first, first[:60])

        one = (b"GET / HTTP/1.1\r\n"
               b"Host: sec.local\r\n\r\n")
        got1 = raw_request(one)
        # 对照组：单条 Host 照常服务，证明上面的 400 不是"整台都在拒"
        check("S13 对照组：单条 Host 正常放行", b"200" in got1.split(b"\r\n", 1)[0],
              got1.split(b"\r\n", 1)[0][:60])
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
    # 64 MiB：高于上限，应当原样流式发送并在 error_log 里说明跳过原因。
    # 体积就是测量余量：缓冲整份的特征是 TTFB ≈ 总耗时，文件太小（32 MiB）时
    # 热页缓存下一趟 0.04s 就传完，比值正好压在 0.5 的判据上抖；64 MiB 让流式路径
    # 的 TTFB 稳在总量的 1/8 左右，判据两边都有余量。
    with open(os.path.join(root, "huge.html"), "wb") as fh:
        for _ in range(64 * 16):
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


def s9_lkg_private_body_leaks(tmp):
    """Still ONLine 不许收 `Cache-Control: private` 的响应：副本区是"上游挂了顶给下一个读者"，
    按租户的正文一旦入区，就会在故障期间回放给完全没有凭证的另一个客户端。
    对照：public 响应必须照常入区并顶住 —— 否则这个"修复"是把功能关掉，不是把洞补上。"""
    gw = Gateway(
        tmp, "s9",
        '  location = /ping { return 200 "pong"; }\n'
        "  location = /metrics { content_by_rust metrics; }\n"
        f"  location /priv/ {{ proxy_pass http://127.0.0.1:{VARIANT_BACKEND}; still_online lkg; still_online_retry 600s; }}\n"
        f"  location /pub/ {{ proxy_pass http://127.0.0.1:{VARIANT_BACKEND}; still_online lkg; still_online_retry 600s; }}",
        head="still_online_zone lkg 8m;\n",
    )
    stored = 'onrouter_still_online_total{kind="stored"}'
    try:
        assert gw.ready(), gw.dead
        base = metrics()[0].get(stored, 0)
        st, _, body, _ = http_call("/priv/panel", headers={"X-Api-Key": "victim-secret-key"})
        check("S9 对照组：租户能看到自己的正文", st == 200 and b"TENANT-VICTIM" in body,
              f"status={st} body={body[:40]!r}")
        st, _, body, _ = http_call("/pub/panel")
        check("S9 对照组：公共正文正常返回", st == 200 and body == b"PUBLIC-PANEL-DATA",
              f"status={st} body={body[:40]!r}")
        wrote = metrics()[0].get(stored, 0) - base
        dbg("两次响应后 stored 增量 =", wrote, "基线 =", base)
        # private 那份不该入区，所以两次响应只该留下 1 条副本
        check("S9 private 响应不入副本区（写入闸门看响应侧的 Cache-Control）", wrote <= 1,
              f"两次响应后 stored 计数 +{wrote:.0f}（应当只有 public 那条入区）")
        VARIANT.dead = True
        time.sleep(0.3)
        st, hd, body, _ = http_call("/priv/panel")
        check("S9 上游故障时不把别人的正文回放给匿名访客", b"TENANT-VICTIM" not in body,
              f"status={st} body={body[:48]!r} 头 X-Still-Online={hd.get('x-still-online', '-')}")
        st, hd, body, _ = http_call("/pub/panel")
        check("S9 公共副本仍能顶住（修复没有牺牲功能）",
              st == 200 and body == b"PUBLIC-PANEL-DATA", f"status={st} body={body[:40]!r}")
    finally:
        gw.stop()
        VARIANT.dead = False


def s10_dict_tmp_link_overwrite(tmp):
    """冷层用 `<十六进制条目名>.<pid>.tmp` 做临时名再 rename。两个问题叠在一起：
    名字可预测（条目名由 key 哈希确定、pid 从进程来），且 `File::create` 会**跟随**已存在的
    路径。攻击者只要先在那个名字上放一个硬链接指向别处的文件，下一次落盘就把那个文件截断了
    —— 一个"缓存目录里能放文件"就能换到"覆盖网关用户能写的任意文件"的原语。"""
    root = os.path.join(tmp, "disk10")
    gw = Gateway(
        tmp, "s10",
        "  location = /metrics { content_by_rust metrics; }\n"
        "  location /fill {\n    content_by_lua \"\n"
        "      local d = ngx.shared.s10\n"
        "      local a = ngx.req.get_uri_args()\n"
        "      if a.v then d:set('victim-key', string.rep('v', 900)) end\n"
        "      if a.n then for i = 0, tonumber(a.n) do d:set('k' .. i, string.rep('x', 900)) end end\n"
        "      ngx.say('done')\n\";\n  }\n"
        '  location /read {\n    content_by_lua "\n'
        "      local v = ngx.shared.s10:get('victim-key')\n"
        '      ngx.say(v and #v or 0)\n";\n  }',
        head=f'lua_shared_dict s10 8k disk={slash(root)} max_disk=4m spill_after=0 max_value=2k;\n',
    )
    pending = 'onrouter_dict_disk_pending_jobs{dict="s10"}'
    ORIGINAL = b"IMPORTANT-NOT-CACHE-DATA"

    def drain(limit=6.0):
        end = time.time() + limit
        while time.time() < end:
            if metrics()[0].get(pending, 0) == 0:
                return True
            time.sleep(0.05)
        return False

    try:
        if not gw.ready():
            dbg("启动日志:", (gw.dead or "")[-900:])
            dbg("配置原文:", open(gw.conf, encoding="utf-8").read())
        assert gw.ready(), gw.dead
        http_call("/fill?v=1")
        http_call("/fill?n=20")  # 内存 8k 只留得下 ~8 条，最早那条（victim-key）被淘汰落盘
        check("S10 前提：淘汰下来的条目确实按可预测文件名落盘", drain(), "落盘队列没排空")
        entry = entry_path_of(root, "victim-key")
        check("S10 前提：文件名可由 key 独立推算（这就是可预测性）", os.path.exists(entry),
              f"预期 {slash(entry)} 不存在")
        victim = os.path.join(tmp, "victim.txt")
        with open(victim, "wb") as fh:
            fh.write(ORIGINAL)
        # 临时名 = 去掉 .bin 后接 ".<pid>.tmp"（与 Rust 侧 with_extension 一致）
        planted = entry[: -len(".bin")] + ".%d.tmp" % gw.proc.pid
        try:
            os.link(victim, planted)
        except OSError as exc:
            check("S10 能在预测出的临时名上放硬链接", False, f"{type(exc).__name__}: {exc}")
            return
        # 读一次把它提回内存，再灌 20 条逼它第二次落盘 —— 这次会走 atomic_write
        http_call("/read")
        http_call("/fill?n=21")
        drain()
        with open(victim, "rb") as fh:
            after = fh.read()
        check("S10 预先占位的临时名不会截断别处的文件", after == ORIGINAL,
              f"victim.txt 被改成 {len(after)} 字节：{after[:32]!r}")
        st, _, body, _ = http_call("/read")
        check("S10 修复不许牺牲落盘本身：条目仍完整可读回",
              st == 200 and body.strip().splitlines()[-1: ] == [b"900"],
              f"读回长度={body!r}")
        os.remove(planted) if os.path.exists(planted) else None
    finally:
        gw.stop()


def s11_limit_key_var_is_a_hard_error(tmp):
    """限流区的 key 必须在判定时刻展开得出值。历史上更糟：写了 `$http_x_api_key` 也能过 -t，
    然后暗地里按 `$remote_addr` 计数——运维以为在按令牌限流，实际在按 IP 限。
    现在请求期变量真的参与计数（`tools/limit_key_e2e.py` 判行为），这一项判的是另一头：
    判定时刻取不到值的写法（响应期变量、`$request_body`、常量键）必须被 -t 硬否决，
    因为那种键会把全区并成一个空桶/常量桶，是比"按 IP 限"更静默的策略反转。"""
    head = 'error_log "%s" warn;\npid "%s";\n' % (slash(os.path.join(tmp, "s11_t_err.log")),
                                                  slash(os.path.join(tmp, "s11_t.pid")))
    # 判定时刻取不到值的 key：全区会并成一个空桶/常量桶，必须否决
    for bad_key, why in [
        ("$status", "响应期变量"),
        ("$request_body", "判定时刻请求体还没读完"),
        ("$upstream_addr", "后端变量"),
        ("$server_name", "本实现没有这个变量"),
        ("$1abc", "没有任何可展开变量＝常量键"),
    ]:
        bad = head + ("limit_req_zone " + bad_key + " zone=bykey:1m rate=10r/s;" + chr(10)
                      + "server { listen 127.0.0.1:18320; server_name sec.local;"
                      + " location / { limit_req zone=bykey; return 200 " + chr(34) + "ok"
                      + chr(34) + "; } }" + chr(10))
        rc, out = run_t(tmp, "s11", bad)
        check("S11 -t 否决 " + bad_key + "（" + why + "）", rc != 0,
              "rc=" + str(rc) + " 输出尾部=" + repr(out[-200:]))
        bare = bad_key.replace("$", "").lstrip("1")
        check("S11 报错点名 " + bad_key, bare in out, out[-200:])

    # 请求期变量现在真的参与计数：这一维必须通过 -t
    # （真实计数行为由 tools/limit_key_e2e.py 判：全部同 IP，换键就必须换桶）
    for good in ["$binary_remote_addr", "$http_x_api_key", "$cookie_sid", "$arg_token"]:
        okc = head + ("limit_req_zone " + good + " zone=bykey:1m rate=10r/s;" + chr(10)
                      + "server { listen 127.0.0.1:18320; server_name sec.local;"
                      + " location / { limit_req zone=bykey; return 200 " + chr(34) + "ok"
                      + chr(34) + "; } }" + chr(10))
        rcd, outd = run_t(tmp, "s11ok", okc)
        check("S11 对照组：" + good + " 通过 -t", rcd == 0, "rc=" + str(rcd) + " " + repr(outd[-200:]))


def s12_vip_slot_collision(tmp):
    """信誉表是直接映射（8k → 682 个 12 字节槽），冲突时的写法是"旧的那位直接换成新的、分数归零"。
    于是一个只想废掉某个 VIP 的人，不需要任何凭据：算一个 tag 撞进同一格的地址，发一个请求就行。
    安全的方向是——宁可让新来的这位学不到东西，也不能把已有分数的槽位清空。"""
    victim = "203.0.113.77"
    gw = Gateway(
        tmp, "s12",
        "  real_ip_header X-Forwarded-For;\n"
        "  set_real_ip_from 127.0.0.0/8;\n"
        "  location = /metrics { content_by_rust metrics; }\n"
        '  location /vip/ { limit_req zone=vip; return 200 "ok"; }',
        head="learning on;\nlearning_memory_budget 64k;\n"
             "vip_learning table=8k min=10 decay=30s;\n"
             "limit_req_zone $remote_addr zone=vip:1m rate=10r/s burst=0;\n",
    )
    try:
        assert gw.ready(), gw.dead
        for _ in range(14):  # 14 次放行 = 14 分，越过 min=10
            http_call("/vip/", headers={"X-Forwarded-For": victim})
            time.sleep(0.14)
        mm = metrics()[0]
        dbg("晋升后指标原文:", [l for l in http_call("/metrics")[2].decode("utf-8", "replace")
                              .splitlines() if l.startswith("onrouter_vip")])
        check("S12 对照组：守规矩的地址已晋升为 VIP",
              mm.get("onrouter_vip_clients", 0) >= 1, f"vip_clients={mm.get('onrouter_vip_clients')}")
        slots = int(mm.get("onrouter_vip_slots{kind=\"total\"}", 682))
        want = max(murmur_hash2(victim.encode()), 1) % slots
        attacker = None
        for i in range(20000):
            cand = "198.18.%d.%d" % (i // 250 + 1, i % 250 + 1)
            if max(murmur_hash2(cand.encode()), 1) % slots == want:
                attacker = cand
                break
        check("S12 能算出一个撞进同一槽的地址（在 %d 个槽里）" % slots, attacker is not None,
              "搜索空间被算尽了还没找到——那这条断言本身要重看")
        if attacker is None:
            return
        http_call("/vip/", headers={"X-Forwarded-For": attacker})
        mm = metrics()[0]
        check("S12 撞槽的新地址不得清空已有分数的 VIP 槽位",
              mm.get("onrouter_vip_clients", 0) >= 1,
              f"一个来自 {attacker} 的请求之后 vip_clients={mm.get('onrouter_vip_clients')}")
        # realip 是信誉的信任根：这个前提必须写在 -t 输出里，而不是埋在 README 里
        head = ('error_log "%s" warn;\npid "%s";\n' % (slash(os.path.join(tmp, "s12_t_err.log")),
                                                      slash(os.path.join(tmp, "s12_t.pid")))
                + "limit_req_zone $remote_addr zone=vip:1m rate=10r/s;\n"
                  "learning on;\nvip_learning table=8k min=10 decay=30s;\n"
                  "server { listen 127.0.0.1:18320; server_name sec.local;"
                  " real_ip_header X-Forwarded-For; set_real_ip_from 127.0.0.0/8;"
                  " location / { limit_req zone=vip; return 200 \"ok\"; } }\n")
        rc, out = run_t(tmp, "s12t", head)
        check("S12 -t 说明 realip 信任范围就是信誉的信任范围（告警但不否决）",
              rc == 0 and "set_real_ip_from" in out and "信誉" in out,
              f"rc={rc} 输出尾部={out[-300:]!r}")
    finally:
        gw.stop()


def main():
    global VARIANT
    tmp = tempfile.mkdtemp(prefix="orr_sec_")
    ws = WsEcho(WS_BACKEND)
    sink = SINK_BACKEND and SinkBody(SINK_BACKEND)
    VARIANT = VariantBackend(VARIANT_BACKEND)
    ws.start()
    sink.start()
    VARIANT.start()
    probes = [s1_auth_without_file, s2_empty_hash, s3_htpasswd_staleness,
              s4_upgrade_uri_desync, s5_stalled_upload, s6_sub_filter_memory, s7_lua_infinite_loop,
              s9_lkg_private_body_leaks, s10_dict_tmp_link_overwrite,
              s11_limit_key_var_is_a_hard_error, s12_vip_slot_collision,
              s13_duplicate_host]
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
