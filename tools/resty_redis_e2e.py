# -*- coding: utf-8 -*-
# resty.redis 纯 Lua RESP 客户端 E2E —— 网关内 resty.redis 向一个真实 RESP 存根服务器发命令，
# 用真实流量证明动态命令派发、全类型回复解析、pipeline、错误/nil 回复、keepalive 连接池复用。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/resty_redis_e2e.py
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "resty_redis.conf")
HOST, PORT = "127.0.0.1", 18148
BACKEND_HOST, BACKEND_PORT = "127.0.0.1", 18147
BASE = f"http://{HOST}:{PORT}"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
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


def get(path):
    r = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(r, timeout=12)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    m = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        m[k.strip()] = v.strip()
    return m


# ------------------- RESP 存根服务器（真实 TCP，供 resty.redis 抓取）-------------------
STORE = {}
LOCK = threading.Lock()


class RedisHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.f = self.request.makefile("rb")

    def _line(self):
        buf = b""
        while True:
            ch = self.f.read(1)
            if not ch:
                return None
            if ch == b"\n":
                return buf[:-1]  # 去掉尾部 \r
            buf += ch

    def _read_cmd(self):
        line = self._line()
        if line is None:
            return None
        if not line.startswith(b"*"):
            # 兼容 inline 命令（本存根不需要，但防御性处理）
            return line.split()
        n = int(line[1:])
        args = []
        for _ in range(n):
            ln = self._line()
            if ln is None:
                return None
            sz = int(ln[1:])  # $len
            data = self.f.read(sz)
            self.f.read(2)  # CRLF
            args.append(data.decode("utf-8", "replace"))
        return args

    @staticmethod
    def _simple(s):
        return b"+" + s + b"\r\n"

    @staticmethod
    def _err(s):
        return b"-" + s + b"\r\n"

    @staticmethod
    def _int(i):
        return b":" + str(i).encode() + b"\r\n"

    @staticmethod
    def _bulk(v):
        if v is None:
            return b"$-1\r\n"
        b = v.encode() if isinstance(v, str) else v
        return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"

    @staticmethod
    def _array(items):
        out = b"*" + str(len(items)).encode() + b"\r\n"
        for it in items:
            out += RedisHandler._bulk(it)
        return out

    def _dispatch(self, args):
        if not args:
            return self._err(b"ERR empty command")
        cmd = args[0].upper()
        with LOCK:
            if cmd == "PING":
                return self._simple(b"PONG")
            if cmd == "SET" and len(args) >= 3:
                STORE[args[1]] = args[2]
                return self._simple(b"OK")
            if cmd == "GET" and len(args) == 2:
                return self._bulk(STORE.get(args[1]))
            if cmd == "DEL":
                c = 0
                for k in args[1:]:
                    if k in STORE:
                        del STORE[k]
                        c += 1
                return self._int(c)
            if cmd == "EXISTS" and len(args) == 2:
                return self._int(1 if args[1] in STORE else 0)
            if cmd == "INCR" and len(args) == 2:
                cur = int(STORE.get(args[1], "0")) + 1
                STORE[args[1]] = str(cur)
                return self._int(cur)
            if cmd == "MGET":
                return self._array([STORE.get(k) for k in args[1:]])
            if cmd == "QUIT":
                self.wfile_write(self._simple(b"OK"))
                return None
        return self._err(b"ERR unknown command '" + args[0].encode() + b"'")

    def wfile_write(self, data):
        self.request.sendall(data)

    def handle(self):
        while True:
            args = self._read_cmd()
            if args is None:
                break
            reply = self._dispatch(args)
            if reply is None:
                break
            try:
                self.wfile_write(reply)
            except (BrokenPipeError, ConnectionResetError):
                break
        try:
            self.f.close()
        except Exception:
            pass


def start_backend():
    class Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Srv((BACKEND_HOST, BACKEND_PORT), RedisHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main():
    srv = start_backend()
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "resty_redis_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            try:
                if get("/basic")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit("!! onrouter 未就绪（端口 18148 被占用？看 logs/resty_redis_err.log）")

        st, body = get("/basic")
        b = kv(body)
        check("/basic set==OK", b.get("set") == "OK", f"set={b.get('set')}")
        check("/basic get==bar", b.get("get") == "bar", f"get={b.get('get')}")
        check("/basic incr 1→2", b.get("incr") == "1" and b.get("incr2") == "2", f"{b}")
        check("/basic del==1", b.get("del") == "1", f"del={b.get('del')}")
        check("/basic ping==PONG", b.get("ping") == "PONG", f"ping={b.get('ping')}")

        st, body = get("/nil")
        n = kv(body)
        check("缺失键 GET→false", n.get("v") == "false", f"v={n.get('v')}")
        check("EXISTS 缺失键→0", n.get("exists") == "0", f"exists={n.get('exists')}")

        st, body = get("/error")
        e = kv(body)
        check("未知命令 ok==nil", e.get("ok") == "nil", f"ok={e.get('ok')}")
        check("未知命令返回含 ERR", e.get("has_err") == "true", f"has_err={e.get('has_err')}")

        st, body = get("/array")
        a = kv(body)
        check("MGET 回复为 table", a.get("type") == "table", f"type={a.get('type')}")
        check("MGET 3 元素", a.get("n") == "3", f"n={a.get('n')}")
        check("MGET 命中值 1,2 / 缺失→false", a.get("r1") == "1" and a.get("r2") == "2" and a.get("r3") == "false", f"{a}")

        st, body = get("/pipeline")
        p = kv(body)
        check("pipeline 4 条回复", p.get("n") == "4", f"n={p.get('n')}")
        check("pipeline set→OK", p.get("r1") == "OK", f"r1={p.get('r1')}")
        check("pipeline get→x", p.get("r3") == "x", f"r3={p.get('r3')}")
        check("pipeline incr→1", p.get("r4") == "1", f"r4={p.get('r4')}")

        st, body = get("/keepalive")
        k = kv(body)
        check("keepalive 首次 ping PONG", k.get("p1") == "PONG", f"p1={k.get('p1')}")
        check("set_keepalive 成功(1)", k.get("ka") in ("1", "true"), f"ka={k.get('ka')}")
        check("池复用二次 ping PONG", k.get("p2") == "PONG", f"p2={k.get('p2')}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        srv.shutdown()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== resty.redis E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
