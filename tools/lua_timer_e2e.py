# -*- coding: utf-8 -*-
# ngx.timer 回调协程化 E2E —— 用真实流量证明定时器回调里可以：
#   * ngx.sleep 让出（不再报 "must run inside a coroutine"）；
#   * cosocket 连真实 TCP 后端完成一次往返；
#   * ngx.location.capture 按注册时的 server 路由走完整代理管线；
#   * ngx.thread.spawn + ngx.thread.wait；
#   * ngx.timer.every 回调 return false 后停止续期。
# 同时校验：注册定时器的客户端请求立即返回，不被后台任务阻塞。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/lua_timer_e2e.py
import os
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_timer_e2e.conf")
GW = "http://127.0.0.1:18250"
BK_HOST, BK_PORT = "127.0.0.1", 18251

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
hits = []
hit_lock = threading.Lock()


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


def get(path, timeout=5):
    try:
        resp = _opener.open(GW + path, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def state():
    st, body = get("/timer/state")
    kv = {}
    for line in body.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    return st, kv


class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(5)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except OSError:
            return
        try:
            path = buf.split(b" ", 2)[1].decode(errors="replace").split("?", 1)[0]
        except (IndexError, UnicodeDecodeError):
            return
        with hit_lock:
            hits.append(path)
        body = b"backend-timer" if path == "/timer-cosocket" else b"backend-sub"
        try:
            s.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
        except OSError:
            pass


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def wait_for(fn, timeout=6.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
            if v:
                return v
        except Exception:
            pass
        time.sleep(interval)
    return None


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    srv = BackendServer((BK_HOST, BK_PORT), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "lua_timer_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_for(lambda: get("/ping") == (200, "pong"), timeout=25):
            raise SystemExit("!! 网关未就绪，见 logs/lua_timer_out.log")
        print("网关已就绪", GW)

        # ---- 1) 注册请求立即返回，后台定时器随后把活干完 ----
        t0 = time.time()
        st, body = get("/timer/start")
        elapsed = time.time() - t0
        check("/timer/start 200 且立即返回", st == 200 and body.strip() == "registered",
              f"st={st} body={body!r}")
        check("注册请求未被后台定时器阻塞（客户端耗时 < 0.5s）", elapsed < 0.5, f"elapsed={elapsed:.3f}s")

        got = wait_for(lambda: (lambda kv: kv if kv.get("done") == "yes" else None)(state()[1]))
        ok = got is not None
        check("定时器回调最终完成（shared.done=yes）", ok, f"state={state()}")
        if ok:
            check("回调里 ngx.get_phase() == 'timer'", got.get("phase") == "timer", f"phase={got.get('phase')}")
            check("回调里 ngx.sleep 让出成功", got.get("slept") == "yes", f"slept={got.get('slept')}")
            check("回调里 cosocket 往返真实后端", got.get("cosocket") == "ok", f"cosocket={got.get('cosocket')}")
            check("回调里 ngx.location.capture 子请求成功", got.get("subrequest") == "ok",
                  f"subrequest={got.get('subrequest')}")
            check("回调里 ngx.thread.spawn+wait 成功", got.get("thread") == "thread-ok",
                  f"thread={got.get('thread')}")

        with hit_lock:
            seen = list(hits)
        check("后端确实收到定时器 cosocket 请求", "/timer-cosocket" in seen, f"hits={seen}")
        check("后端确实收到定时器子请求", "/sub" in seen, f"hits={seen}")

        # ---- 2) every 回调 return false 后停止续期 ----
        st, body = get("/timer/every/start")
        check("ngx.timer.every 注册成功", st == 200 and body.strip() == "registered", f"st={st} body={body!r}")

        def every_n():
            st2, b2 = get("/timer/every/state")
            for line in b2.splitlines():
                if line.startswith("n="):
                    return int(line[2:])
            return 0

        n3 = wait_for(lambda: (lambda n: n if n >= 3 else None)(every_n()))
        check("every 回调按 0.1s 跑满 3 次", n3 is not None, f"n={every_n()}")
        time.sleep(0.45)
        final_n = every_n()
        check("回调 return false 后 every 停止续期", final_n == 3, f"n={final_n}")

        check("进程仍存活（定时器未把调度器打死）", proc.poll() is None)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        srv.shutdown()

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
