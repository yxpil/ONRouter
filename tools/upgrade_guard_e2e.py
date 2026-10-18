# -*- coding: utf-8 -*-
# Upgrade 访问控制 + 隧道生命周期 E2E —— 用真实 socket 流量证明：
#   * 带 Upgrade: websocket 的请求不再旁路 deny all / auth_basic / access_by_lua / limit_req，
#     被拒绝时回 403/401/限流码，且后端根本没有收到这次 HTTP 请求；
#   * 放行的升级照常 101，并能双向透传；
#   * rewrite ... last 对升级请求生效；
#   * 隧道空闲超过 proxy_read_timeout 后由网关主动关闭，limit_conn 额度随之释放。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/upgrade_guard_e2e.py
import base64
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import socketserver

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "upgrade_guard.conf")
GW_HOST, GW_PORT = "127.0.0.1", 18186
BK_HOST, BK_PORT = "127.0.0.1", 18187
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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


def gw_get(path):
    try:
        resp = _opener.open(f"http://{GW_HOST}:{GW_PORT}{path}", timeout=5)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


# ------------------------------- 后端（原始 TCP，以便控制 101 后的行为） -------------------------------
class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(10)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except OSError:
            return
        head, _rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode(errors="replace").split("\r\n")
        try:
            _method, full_path, _ver = lines[0].split(" ", 2)
        except ValueError:
            return
        path = full_path.split("?", 1)[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        upgrade = headers.get("upgrade", "").lower() == "websocket"
        with hit_lock:
            hits.append((path, upgrade))
        if not upgrade:
            body = ("plain-" + path).encode()
            try:
                s.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
            except OSError:
                pass
            return
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        try:
            s.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode()
            )
        except OSError:
            return
        if path == "/ws/hold":
            # 握手后保持沉默，等网关按空闲超时关闭
            try:
                while True:
                    if not s.recv(4096):
                        break
            except OSError:
                pass
            return
        # 其余路径：原样回显，证明隧道双向可用
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                s.sendall(data)
        except OSError:
            pass


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ------------------------------- 原始 HTTP/WS 客户端 -------------------------------
def open_upgrade(path, extra=None, timeout=8):
    s = socket.create_connection((GW_HOST, GW_PORT), timeout=timeout)
    headers = {
        "Host": f"{GW_HOST}:{GW_PORT}",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
    }
    if extra:
        headers.update(extra)
    req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    s.sendall(req.encode())
    return s


def read_head(s, deadline=6.0):
    buf = b""
    end = time.time() + deadline
    while b"\r\n\r\n" not in buf and time.time() < end:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    status = 0
    parts = head.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    return status, head.lower(), buf


def wait_close(s, deadline=8.0):
    """等到对端关闭（recv 返回 EOF）；返回 (closed, 等待秒数)。"""
    start = time.time()
    s.settimeout(0.2)
    while time.time() - start < deadline:
        try:
            data = s.recv(4096)
            if not data:
                return True, time.time() - start
        except socket.timeout:
            continue
        except OSError:
            return True, time.time() - start
    return False, time.time() - start


def backend_saw(path, upgrade=None):
    with hit_lock:
        return any(p == path and (upgrade is None or u == upgrade) for p, u in hits)


# ------------------------------- main -------------------------------
def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    srv = BackendServer((BK_HOST, BK_PORT), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    logf = open(os.path.join(ROOT, "logs", "upgrade_guard_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if gw_get("/ping")[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not ready:
            raise SystemExit("!! 网关未就绪，见 logs/upgrade_guard_out.log")
        print("网关已就绪", GW_HOST, GW_PORT)

        # ---- 1) deny all 必须先于 101 ----
        s = open_upgrade("/ws/deny")
        st, head, _ = read_head(s)
        s.close()
        check("Upgrade + deny all → 403（不是 101）", st == 403, f"status={st} head={head[:120]!r}")
        time.sleep(0.2)
        check("被 deny 的 Upgrade 没有到达后端", not backend_saw("/ws/deny"), f"hits={hits}")

        # ---- 2) auth_basic 必须先于 101 ----
        s = open_upgrade("/ws/auth")
        st, head, _ = read_head(s)
        s.close()
        check("Upgrade + auth_basic 无凭据 → 401", st == 401, f"status={st}")
        check("401 带 WWW-Authenticate 质询", "www-authenticate" in head, f"head={head[:160]!r}")
        time.sleep(0.2)
        check("需要认证的 Upgrade 没有到达后端", not backend_saw("/ws/auth"), f"hits={hits}")

        # ---- 3) access_by_lua 必须先于 101 ----
        s = open_upgrade("/ws/lua-deny")
        st, head, _ = read_head(s)
        s.close()
        check("Upgrade + access_by_lua ngx.exit(403) → 403", st == 403, f"status={st}")
        time.sleep(0.2)
        check("Lua 拒绝的 Upgrade 没有到达后端", not backend_saw("/ws/lua-deny"), f"hits={hits}")

        # ---- 4) limit_req 必须先于 101：首个放行，第二个立即被限 ----
        s1 = open_upgrade("/ws/limited")
        st1, head1, _ = read_head(s1)
        check("limit_req（burst=0）首个 Upgrade → 101", st1 == 101, f"status={st1} head={head1[:120]!r}")
        s2 = open_upgrade("/ws/limited")
        st2, head2, _ = read_head(s2)
        s2.close()
        check("limit_req 超限 Upgrade → 429/503（不是 101）", st2 in (429, 503), f"status={st2} head={head2[:120]!r}")
        with hit_lock:
            n_limited = sum(1 for p, u in hits if p == "/ws/limited" and u)
        check("限流拒绝的 Upgrade 没有多打一次后端", n_limited == 1, f"upstream_upgrades={n_limited} hits={hits}")
        s1.close()

        # ---- 5) 正常升级 + 双向透传 ----
        s = open_upgrade("/ws/ok")
        st, head, buf = read_head(s)
        check("普通 Upgrade → 101", st == 101, f"status={st} head={head[:120]!r}")
        check("101 透传后端 Sec-WebSocket-Accept", "sec-websocket-accept" in head, f"head={head[:160]!r}")
        s.sendall(b"ping-7c1d\n")
        deadline = time.time() + 5
        s.settimeout(0.3)
        got = b""
        while b"ping-7c1d" not in got and time.time() < deadline:
            try:
                got += s.recv(4096)
            except socket.timeout:
                continue
        check("升级后双向透传（先发的字节与回显都在）", b"ping-7c1d" in got, f"got={got[-60:]!r}")
        s.close()

        # ---- 6) rewrite ... last 对升级请求生效 ----
        s = open_upgrade("/ws/rewrite")
        st, head, _ = read_head(s)
        s.close()
        check("rewrite 内部跳转后的 Upgrade → 101", st == 101, f"status={st} head={head[:120]!r}")
        time.sleep(0.2)
        check("rewrite 后转发到 /ws/ok", backend_saw("/ws/ok", True), f"hits={hits}")

        # ---- 7) upstream max_conns 覆盖整条 Upgrade 隧道 ----
        s = open_upgrade("/ws/up/a")
        st, head, _ = read_head(s)
        check("走 upstream 的 Upgrade → 101", st == 101, f"status={st} head={head[:120]!r}")
        st_busy, body_busy = gw_get("/up/plain/x")
        check("隧道存活期间 max_conns=1 仍被占用（普通请求 502）",
              st_busy == 502, f"status={st_busy} body={body_busy[:80]!r}")
        s.close()
        released = False
        waited = 0.0
        for _ in range(30):
            time.sleep(0.2)
            waited += 0.2
            st_after, body_after = gw_get("/up/plain/x")
            if st_after == 200 and body_after == "plain-/ws/plain/x":
                released = True
                break
        check("隧道关闭后 upstream 并发额度释放（普通请求恢复 200）",
              released, f"waited={waited:.1f}s status={st_after} body={body_after[:80]!r}")

        # ---- 8) 隧道空闲超过 proxy_read_timeout(2s) 必须被网关关闭 ----
        s = open_upgrade("/ws/hold")
        st, head, _ = read_head(s)
        check("hold 隧道建立 → 101", st == 101, f"status={st}")
        closed, waited = wait_close(s, deadline=8.0)
        s.close()
        check("空闲隧道在 proxy_read_timeout 后被关闭", closed, f"waited={waited:.2f}s")
        check("关闭时机符合 2s 空闲超时（1.5s~6s）", closed and 1.5 <= waited <= 6.0, f"waited={waited:.2f}s")

        # 关闭后再等一小会，确认没有残留连接把进程拖住
        time.sleep(0.3)
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
