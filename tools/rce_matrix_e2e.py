# -*- coding: utf-8 -*-
# 远程执行面（RCE / SSRF / internal 逃逸 / 注入）复现套件：每条判断都用真实流量出证据。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/rce_matrix_e2e.py
#
# 覆盖：
#   R1 客户端输入能否变成 Lua 源码或 Lua 文件路径（配置参数不做变量插值）
#   R2 internal location 的可达性边界（直连/规范化变体 vs 网关自己的内部重定向）
#   R3 动态上游：proxy_pass 里的 $arg_/$http_ 是否让客户端决定连到哪儿（SSRF），
#      以及绝对形式请求目标（GET http://host:port/）会不会被原样转发或触发外连
#   R4 CRLF：编码后的 CR/LF 能否变成后端请求行里的第二个头，Lua 把 $uri 写进响应头
#      能否做响应拆分（必须失败关闭）
#   R5 Lua 能力面（事实记录）：debug 库不可达；os/io/load 可达 = 脚本级任意代码，
#      所以"客户端输入能否进入脚本"才是这个网关的真正边界，R1 就是证这一条
#
# 探针各自起一个进程；网关 18340，回显后端 18341，SSRF 金丝雀 18343。
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
PORT = 18340
ECHO_BACKEND = 18341
CANARY_PORT = 18343

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def info(name, detail=""):
    print("INFO", name, detail)


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
    """一条配置 = 一个进程，探针之间不互相污染。"""

    def __init__(self, tmp, tag, body, head=""):
        self.tmp = tmp
        self.err = os.path.join(tmp, f"err_{tag}.log")
        conf = (
            f'error_log "{slash(self.err)}" warn;\n'
            f'pid "{slash(os.path.join(tmp, "p.pid"))}";\n'
            + head
            + f"\nserver {{\n  listen 127.0.0.1:{PORT};\n  server_name rce.local;\n{body}\n}}\n"
        )
        path = os.path.join(tmp, f"{tag}.conf")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(conf)
        self.path = path
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
    conn = HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        hdrs = {"Host": "rce.local"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data, ""
    except Exception as exc:  # noqa: BLE001 - 传输层异常就是要捕获
        return 0, {}, b"", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            conn.close()
        except OSError:
            pass


def raw_request(payload, timeout=4):
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    sock.sendall(payload)
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


# ---------------------------------------------------------------- 后端

class EchoBackend(threading.Thread):
    """把收到的请求行 + 头部块原样回报，用来证明网关到底转发了什么。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.ss = socket.socket()
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ss.bind(("127.0.0.1", port))
        self.ss.listen(16)
        self.lines = []
        self.lock = threading.Lock()

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
            head, _, _ = buf.partition(b"\r\n\r\n")
            first = head.split(b"\r\n", 1)[0]
            with self.lock:
                self.lines.append(first)
            body = head.decode("utf-8", "replace").replace("\r\n", "\\r\\n\n")
            payload = body.encode("utf-8")
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                      + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def seen(self):
        with self.lock:
            return list(self.lines)


class Canary(threading.Thread):
    """SSRF 金丝雀：只记录有人来连，不回应任何 HTTP。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.ss = socket.socket()
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ss.bind(("127.0.0.1", port))
        self.ss.listen(16)
        self.hits = 0
        self.lock = threading.Lock()

    def run(self):
        while True:
            try:
                c, _ = self.ss.accept()
            except OSError:
                return
            with self.lock:
                self.hits += 1
            try:
                c.close()
            except OSError:
                pass

    def count(self):
        with self.lock:
            return self.hits


# ---------------------------------------------------------------- R1

def r1_source_injection(tmp):
    """客户端输入不能变成 Lua 源码，也不能变成 _file 的路径；脚本加载失败必须失败关闭。"""
    marker = os.path.join(tmp, "r1_executed.marker")
    evil = os.path.join(tmp, "marker.lua")
    with open(evil, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f'local f = io.open("{slash(marker)}", "w"); f:write("ran"); f:close()\n'
                 'ngx.say("evil-loaded")\n')
    deny = os.path.join(tmp, "deny.lua")
    with open(deny, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("ngx.exit(403)\n")
    missing = slash(os.path.join(tmp, "nope.lua"))
    deny_ref = slash(deny)
    gw = Gateway(
        tmp, "r1",
        '  location /lit {\n    content_by_lua_block {\n'
        '      ngx.say("[$host][$uri][$arg_marker]")\n    }\n  }\n'
        '  location /f {\n    content_by_lua_file "$arg_f.lua";\n  }\n'
        '  location /reg {\n    content_by_lua_block {\n'
        '      if not debug then ngx.say("no-debug-library") return end\n'
        '      local ok, e = pcall(function() return debug.getregistry() end)\n'
        '      ngx.say("debug-ok " .. tostring(ok))\n    }\n  }\n'
        '  location /caps {\n    content_by_lua_block {\n'
        '      local ks = {}\n      for k in pairs(_G) do ks[#ks + 1] = k end\n'
        '      table.sort(ks)\n      ngx.say(table.concat(ks, " "))\n    }\n  }\n'
        f'  location /miss_content {{\n    content_by_lua_file "{missing}";\n  }}\n'
        f'  location /miss_access {{\n    access_by_lua_file "{missing}";\n'
        '    return 200 "SECRET-DATA";\n  }\n'
        f'  location /deny_ok {{\n    access_by_lua_file "{deny_ref}";\n'
        '    return 200 "SECRET-DATA";\n  }\n'
        '  location /err_access {\n    access_by_lua_block {\n'
        '      error("access 检查自身出错")\n    }\n'
        '    return 200 "SECRET-DATA";\n  }\n'
        '  location /ping { return 200 "pong"; }\n',
    )
    try:
        assert gw.ready(), gw.dead
        st, _, body, errtxt = http_call("/lit?marker=1")
        text = body.decode("utf-8", "replace")
        check("R1 配置参数不被请求变量插值（源码注入面为零）",
              st == 200 and "[$host][$uri][$arg_marker]" in text, f"st={st} body={text[:160]}{errtxt}")

        st2, _, _, _ = http_call("/f?f=marker")
        time.sleep(0.4)
        check("R1 _by_lua_file 路径按字面解析，?f= 不能指向别的脚本",
              not os.path.exists(marker), f"status={st2} 但标记文件出现了（脚本被执行）")

        st3, _, body3, _ = http_call("/reg")
        t3 = body3.decode("utf-8", "replace")
        check("R1 debug 库不可达（拿不到 registry，跨请求句柄无从下手）",
              st3 == 200 and "no-debug-library" in t3, f"st={st3} body={t3[:160]}")

        st4, _, body4, _ = http_call("/caps")
        g = body4.decode("utf-8", "replace")
        has = {n: (" " + n + ":") in (" " + g) or (n in g.split()) for n in ("os", "io", "load", "require", "dofile")}
        info("R1 Lua 全局面", sorted(x for x, y in has.items() if y))
        check("R1 事实确认：os/io/load 对脚本可用（脚本=任意代码，故 R1 第一须成立）",
              all(has.values()), f"globals={g[:300]}")

        st5, _, body5, _ = http_call("/deny_ok")
        check("R1 对照组：access 脚本正常 ngx.exit(403) 能拦住",
              st5 == 403 and b"SECRET-DATA" not in body5, f"st={st5} body={body5[:60]}")

        st6, _, body6, _ = http_call("/miss_access")
        check("R1 access_by_lua_file 读不到时必须失败关闭（绝不允许内容通过）",
              st6 >= 500 and b"SECRET-DATA" not in body6,
              f"st={st6} body={body6[:60]!r} 检查脚本没跑成却放行了")

        st7, _, body7, _ = http_call("/err_access")
        check("R1 access 脚本运行时 error 同样失败关闭",
              st7 >= 500 and b"SECRET-DATA" not in body7,
              f"st={st7} body={body7[:60]!r}")

        st8, _, body8, _ = http_call("/miss_content")
        check("R1 content_by_lua_file 读不到时报 5xx（不是 200 空体）",
              st8 >= 500, f"st={st8} body={body8[:60]!r}")

        st9, _, body9, _ = http_call("/ping")
        check("R1 网关全程存活", st9 == 200 and body9 == b"pong", f"st={st9}")
    finally:
        gw.stop()


# ---------------------------------------------------------------- R2

def r2_internal(tmp):
    """internal location 只能被网关的内部重定向命中，客户端无法把它凑出来。"""
    gw = Gateway(
        tmp, "r2",
        '  location /admin {\n    internal;\n    content_by_lua_block { ngx.say("ADMIN-MARKER") }\n  }\n'
        '  location /go {\n    rewrite ^/go$ /admin last;\n    return 200 "public-go";\n  }\n'
        '  location /tf {\n    try_files /nope_such /admin;\n  }\n'
        '  location /cap {\n    content_by_lua_block {\n'
        '      local res = ngx.location.capture("/admin")\n'
        '      ngx.say("cap " .. tostring(res.status) .. " " .. (res.body or ""))\n    }\n  }\n'
        '  location /exec {\n    content_by_lua_block { ngx.exec("/admin") }\n  }\n'
        '  location /pub { return 200 "public"; }\n',
    )
    try:
        assert gw.ready(), gw.dead
        direct = ["/admin", "/admin/", "//admin", "/./admin", "/pub/../admin",
                  "/%61dmin", "/ADMIN", "/admin%20", "/admin;x"]
        leaks = []
        for p in direct:
            st, _, body, _ = http_call(p)
            if b"ADMIN-MARKER" in body:
                leaks.append((p, st))
        check("R2 外部直连 internal 一律拿不到处理程序", not leaks, f"命中={leaks}")

        st_cap, _, body_cap, _ = http_call("/cap")
        check("R2 capture 走内部请求，允许命中（对标 nginx）",
              st_cap == 200 and b"ADMIN-MARKER" in body_cap, f"st={st_cap} body={body_cap[:120]}")
        st_ex, _, body_ex, _ = http_call("/exec")
        check("R2 ngx.exec 走内部重定向，允许命中",
              st_ex == 200 and b"ADMIN-MARKER" in body_ex, f"st={st_ex} body={body_ex[:120]}")
        st_go, _, body_go, _ = http_call("/go")
        info("R2 rewrite ... last 到 internal", f"st={st_go} body={body_go[:60]!r}")
        st_tf, _, body_tf, _ = http_call("/tf")
        info("R2 try_files 兜底到 internal", f"st={st_tf} body={body_tf[:60]!r}")
        check("R2 try_files 兜底不会把 internal 端点变成公开端点",
              b"ADMIN-MARKER" not in body_tf, f"/tf st={st_tf} 返回了 ADMIN-MARKER")
        st_pub, _, body_pub, _ = http_call("/pub")
        check("R2 /pub 仍是公开内容（internal 没有被顺带公开）",
              st_pub == 200 and body_pub == b"public", f"st={st_pub} body={body_pub[:60]!r}")
    finally:
        gw.stop()


# ---------------------------------------------------------------- R3

def r3_ssrf(tmp, echo):
    """客户端不能决定网关连到哪里；绝对形式请求目标也不能变成外连或转发信号。"""
    gw = Gateway(
        tmp, "r3",
        '  location /p {\n    proxy_pass http://127.0.0.1:$arg_port/x;\n  }\n'
        '  location /h {\n    proxy_pass http://$http_x_canary_host:$arg_p/;\n  }\n'
        '  location /e {\n    proxy_pass http://127.0.0.1:18341;\n  }\n'
        '  location /ping { return 200 "pong"; }\n',
    )
    try:
        assert gw.ready(), gw.dead
        base = echo.seen()
        before = CANARY.count()
        st, _, body, _ = http_call(f"/p?port={CANARY_PORT}")
        time.sleep(0.3)
        check("R3 proxy_pass 的端口不由 $arg_ 决定（无 SSRF 原语）",
              CANARY.count() == before, f"status={st} 金丝雀 +{CANARY.count()-before}")

        st2, _, _, _ = http_call("/h", headers={"X-Canary-Host": "127.0.0.1"})
        time.sleep(0.3)
        check("R3 上游主机名不由请求头决定",
              CANARY.count() == before, f"status={st2} 金丝雀 +{CANARY.count()-before}")

        st3, _, body3, _ = http_call("/e/probe-normal")
        got = [l for l in echo.seen()[len(base):]]
        check("R3 固定上游照常代理（对照组不是假阴性）",
              st3 == 200 and any(b"/probe-normal" in l for l in got), f"st={st3} 后端看到={got[:2]}")

        raw = raw_request((f"GET http://127.0.0.1:{CANARY_PORT}/abs HTTP/1.1\r\n"
                           f"Host: rce.local\r\nConnection: close\r\n\r\n").encode())
        time.sleep(0.3)
        check("R3 绝对形式请求目标不会让网关外连金丝雀地址",
              CANARY.count() == before, f"resp={raw[:80]!r}")
        seen_abs = [l for l in echo.seen() if b"http://" in l]
        code = raw.split(b" ", 2)[1].decode(errors="replace") if len(raw.split(b" ", 2)) > 1 else "?"
        info("R3 绝对形式请求行的去向", f"status={code} 后端看到绝对URI={seen_abs[:1]}")
        check("R3 绝对形式请求目标不会原样转发给后端", not seen_abs, f"{seen_abs[:1]}")

        raw2 = raw_request(f"GET //127.0.0.1:{CANARY_PORT}/rel HTTP/1.1\r\n"
                           f"Host: rce.local\r\nConnection: close\r\n\r\n".encode())
        time.sleep(0.3)
        check("R3 协议相对形式路径不会变成新的上游选择",
              CANARY.count() == before, f"resp={raw2[:60]!r}")

        st4, _, body4, _ = http_call("/ping")
        check("R3 网关全程存活", st4 == 200 and body4 == b"pong", f"st={st4}")
    finally:
        gw.stop()


# ---------------------------------------------------------------- R4

def r4_crlf(tmp, echo):
    """编码后的 CR/LF 不许在后端请求行或客户端响应头里'落地'成第二个头。"""
    gw = Gateway(
        tmp, "r4",
        '  location /e {\n    proxy_pass http://127.0.0.1:18341;\n  }\n'
        '  location /hdr {\n    content_by_lua_block {\n'
        '      ngx.header["x-echo-path"] = ngx.var.uri\n'
        '      ngx.say("ok")\n    }\n  }\n'
        '  location /add {\n    content_by_lua_block {\n'
        '      ngx.header["x-from-arg"] = ngx.var.arg_v\n'
        '      ngx.say("ok")\n    }\n  }\n'
        '  location /ping { return 200 "pong"; }\n',
    )
    try:
        assert gw.ready(), gw.dead
        base = len(echo.seen())
        st, _, body, _ = http_call("/e/%0d%0aX-Injected%3a%201?q=%0d%0aSet-Cookie%3a%20bad")
        time.sleep(0.3)
        seen = echo.seen()[base:]
        joined = b" ".join(seen)
        # 两种都能接受：网关自己 400 掉（更严），或原样把百分号转发（对标 nginx）。
        # 不能接受的是：解码出真的 CR/LF，在后端请求行里变成第二个头。
        check("R4 编码 CR/LF 不会在后端请求行解码成注入头",
              st in (200, 400) and b"\r\nX-Injected" not in joined and b"\r\nSet-Cookie" not in joined,
              f"st={st} 后端请求行={seen[:1]}")
        info("R4 编码 CR/LF 的处置", f"status={st} 后端收到={seen[:1]!r}")

        b1 = len(echo.seen())
        st_c1, _, _, _ = http_call("/e/plain%20x")
        st_c2, _, _, _ = http_call("/e/a%23b")
        time.sleep(0.3)
        ctrl = echo.seen()[b1:]
        check("R4 对照组：普通百分号编码照常原样转发（400 不是普遍误伤）",
              st_c1 == 200 and st_c2 == 200
              and any(b"/e/plain%20x" in l for l in ctrl) and any(b"a%23b" in l for l in ctrl),
              f"st={st_c1}/{st_c2} 后端={ctrl[:2]}")

        raw = raw_request(b"GET /hdr/.%0d%0aSet-Cookie:%20evil HTTP/1.1\r\nHost: rce.local\r\n"
                          b"Connection: close\r\n\r\n")
        low = raw.lower()
        check("R4 Lua 把解码后的 $uri 写进响应头时失败关闭（无响应拆分）",
              b"\r\nset-cookie: evil" not in low, f"resp={raw[:200]!r}")

        raw2 = raw_request(b"GET /add?v=a%0d%0aX-Second:%201 HTTP/1.1\r\nHost: rce.local\r\n"
                           b"Connection: close\r\n\r\n")
        check("R4 请求参数里的 CR/LF 原样进不了响应头",
              b"\r\nX-Second" not in raw2, f"resp={raw2[:200]!r}")

        raw3 = raw_request(b"GET /ping HTTP/1.1\r\nHost: rce.local\r\nX: a\rb\r\n"
                           b"Connection: close\r\n\r\n")
        st3 = raw3.split(b" ", 2)[1] if len(raw3.split(b" ", 2)) > 1 else b"?"
        check("R4 裸 CR 的请求头被传输层拒绝", st3 in (b"400", b"401") or b"400" in raw3[:40],
              f"status={st3} resp={raw3[:80]!r}")

        st4, _, body4, _ = http_call("/ping")
        check("R4 网关全程存活（注入尝试没有打崩进程）",
              st4 == 200 and body4 == b"pong", f"st={st4}")
    finally:
        gw.stop()


def main():
    global CANARY
    tmp = tempfile.mkdtemp(prefix="orr_rce_")
    echo = EchoBackend(ECHO_BACKEND)
    echo.start()
    CANARY = Canary(CANARY_PORT)
    CANARY.start()
    wait_port(ECHO_BACKEND)
    try:
        r1_source_injection(tmp)
        r2_internal(tmp)
        r3_ssrf(tmp, echo)
        r4_crlf(tmp, echo)
    finally:
        for s in (echo, CANARY):
            try:
                s.ss.close()
            except OSError:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
    bad = [n for n, ok in results if not ok]
    print("=" * 56)
    print(f"{len(results) - len(bad)}/{len(results)} PASS")
    for n in bad:
        print("  !!", n)
    print("=" * 56)
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    main()
