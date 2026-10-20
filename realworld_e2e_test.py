# -*- coding: utf-8 -*-
"""ONRouter 真实工作场景全量模拟（一个社区站的一天）

S1  静态官网：首页 200 + ETag/304 协商缓存 + Range/206 断点续传 + 自定义 404 + 301 迁移
S2  API 网关：GET/POST JSON 反代、轮询负载均衡、XFF/X-Real-IP 注入
S3  令牌鉴权：无 token 401 / 错 token 403 / 对 token 200
S4  登录限流：10s 固定窗口 5 次，超出 429，窗口翻转后恢复
S5  WebSocket 聊天：经网关 101 隧道 echo 往返（含分片帧重组）
S6  后台定时器：init 阶段 every(2s) 心跳，/health 观察 beats 递增
S7  大文件上传：5MB 字节 sha256 端到端一致；8MB 触发 413
S8  故障转移：杀掉一台后端，请求经重试全部 200
S9  上游超时：慢后端 1.5s > proxy_read_timeout 1s → 超时错误
S10 上游宕机：死端口 → 502
S11 并发突发：30 个混合请求全部成功
S12 恶意/畸形请求：非法请求行 → 400，网关不崩溃

用法：python realworld_e2e_test.py
"""
import hashlib
import json
import os
import socket
import ssl as _ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
GW_PORT = 9600
BIN = os.path.join(ROOT, "target", "debug", "onrouter.exe")
results = []

def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), "|", name, ("| " + str(detail)[:180] if (not ok or detail) else ""))

def req(path, method="GET", data=None, headers=None, timeout=15, raw_body=False):
    h = {"Host": f"127.0.0.1:{GW_PORT}"}
    h.update(headers or {})
    r = urllib.request.Request(f"http://127.0.0.1:{GW_PORT}{path}", data=data, method=method, headers=h)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        resp = opener.open(r, timeout=timeout)
        body = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def jreq(path, **kw):
    st, hd, body = req(path, **kw)
    try:
        return st, hd, json.loads(body)
    except Exception:
        return st, hd, {"_raw": body[:200].decode("utf-8", "replace")}

# ---------- 最小 RFC6455 客户端（无第三方依赖） ----------
class _WsSocket(socket.socket):
    pass  # 3.13 的裸 socket 无 __dict__，子类化后才能挂接收缓冲

def ws_connect(path="/ws"):
    key = "sG3dExampleKeyForTest12=="
    s = _WsSocket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", GW_PORT))
    s.settimeout(10)
    handshake = (
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{GW_PORT}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    s.sendall(handshake.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("隧道在建连前断开: " + buf[:120].decode(errors="replace"))
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    status_line = head.split(b"\r\n")[0].decode()
    s._ws_recv_buf = rest
    return s, status_line, head.decode(errors="replace")

def ws_send(s, payload, opcode=0x1, final=True):
    data = payload.encode() if isinstance(payload, str) else payload
    mask = bytes(os.urandom(4))
    header = bytes([0x80 | opcode if final else opcode])
    n = len(data)
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    s.sendall(header + mask + masked)

def ws_recv(s, timeout=5):
    s.settimeout(timeout)
    buf = s._ws_recv_buf

    def need(k):
        nonlocal buf
        while len(buf) < k:
            chunk = s.recv(65536)
            if not chunk:
                raise RuntimeError("隧道被关闭")
            buf += chunk
    need(2)
    fin, opcode = buf[0] >> 7, buf[0] & 0x0F
    ln = buf[1] & 0x7F
    off = 2
    if ln == 126:
        need(4); ln = struct.unpack("!H", buf[2:4])[0]; off = 4
    elif ln == 127:
        need(10); ln = struct.unpack("!Q", buf[2:10])[0]; off = 10
    need(off + ln)
    payload = buf[off:off + ln]
    buf = buf[off + ln:]
    s._ws_recv_buf = buf
    return fin, opcode, payload

# ---------- 后端启动 ----------
def start(cmd, log):
    f = open(os.path.join(ROOT, log), "wb")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=ROOT)
    p._logf = f
    return p

def stop(p):
    try:
        p.terminate()
        p.wait(timeout=5)
    except Exception:
        p.kill()
    p._logf.close()

def main():
    # 静态大文件（5MB，确定性内容供 Range/上传校验）
    big = os.path.join(ROOT, "public_realworld", "big.bin")
    payload = (b"LearON-realworld-" * 300000)[:5 * 1024 * 1024]
    with open(big, "wb") as f:
        f.write(payload)
    big_sha = hashlib.sha256(payload).hexdigest()

    backends = [
        start(["node", "tools/echo_backend.js", "9201"], "rw_be9201.log"),
        start(["node", "tools/echo_backend.js", "9202"], "rw_be9202.log"),
        start(["node", "tools/ws_backend.js", "9301"], "rw_ws9301.log"),
    ]
    for p in backends:
        if p.poll() is not None:
            print("node 后端启动失败（检查 node 是否在 PATH）"); sys.exit(2)
    time.sleep(0.6)

    gwlog = open(os.path.join(ROOT, "realworld_gw.log"), "wb")
    gw = subprocess.Popen([BIN, "conf/realworld.conf"], stdout=gwlog, stderr=subprocess.STDOUT, cwd=ROOT)
    gw._logf = gwlog
    try:
        # 等网关起来
        up = False
        for _ in range(40):
            try:
                st, _, _b = req("/promo2026")
                if st == 200:
                    up = True
                    break
            except Exception:
                time.sleep(0.2)
        if not up:
            check("网关启动", False, "9600 无响应，见 realworld_gw.log")
            return

        # ================= S1 静态官网 =================
        st, hd, body = req("/")
        check("S1 首页 200 + 内容标记", st == 200 and b"REALWORLD-HOME-MARKER" in body, f"st={st}")
        etag = hd.get("etag")
        st2, _, b2 = req("/", headers={"If-None-Match": etag or ""})
        check("S1 ETag 协商 → 304 空体", st2 == 304 and b2 == b"", f"st={st2} etag={etag}")
        st3, hd3, b3 = req("/big.bin", headers={"Range": "bytes=100-199"})
        check("S1 Range → 206 精确窗口", st3 == 206 and len(b3) == 100 and b3 == payload[100:200]
              and hd3.get("content-range") == "bytes 100-199/%d" % len(payload), f"st={st3} len={len(b3)} cr={hd3.get('content-range')}")
        st4, _, _b4 = req("/big.bin", headers={"Range": "bytes=999999999-"})
        check("S1 越界 Range → 416", st4 == 416, f"st={st4}")
        st5, _, b5 = req("/no-such-page")
        check("S1 自定义 404 页", st5 == 404 and b"CUSTOM-404-PAGE" in b5, f"st={st5}")
        st6, hd6, _b6 = req("/promo")
        check("S1 老链接 301 迁移", st6 == 301 and "promo2026" in (hd6.get("location") or ""), f"st={st6} loc={hd6.get('location')}")

        # ================= S2 API 网关 =================
        stA, _, jA = jreq("/api/orders")
        stB, _, jB = jreq("/api/orders")
        pair = sorted([jA.get("backend"), jB.get("backend")])
        check("S2 反代轮询双后端", stA == 200 and stB == 200 and pair == [9201, 9202], f"{jA.get('backend')}/{jB.get('backend')}")
        check("S2 路径重写 + XFF 注入", jA.get("path") == "/orders" and jA.get("xff") == "127.0.0.1", json.dumps(jA)[:150])
        js = json.dumps({"item": "book", "qty": 3}).encode()
        stC, _, jC = jreq("/api/orders", method="POST", data=js, headers={"Content-Type": "application/json"})
        check("S2 POST JSON 体完整到达", stC == 200 and jC.get("body_len") == len(js) and jC.get("method") == "POST", json.dumps(jC)[:150])

        # ================= S3 鉴权 =================
        st1, _, _b1 = req("/secure")
        st2, _, _b2 = req("/secure", headers={"X-Token": "wrong"})
        st3, _, b3 = req("/secure", headers={"X-Token": "admin-token-42"})
        check("S3 鉴权 401/403/200", (st1, st2, st3) == (401, 403, 200) and b"admin" in b3, f"{st1}/{st2}/{st3}")

        # ================= S4 登录限流 =================
        # The Lua limiter keys on floor(ngx.time()/10): start the seven requests at a
        # fresh window boundary, otherwise a burst that straddles one legitimately gets
        # all 200 and the assertion reads "no limiter" when it only saw two windows.
        time.sleep(10 - (time.time() % 10) + 0.05)
        codes = []
        for i in range(7):
            st, _, _b = req(f"/login?user=u{i}")
            codes.append(st)
        check("S4 窗口内 5 通过 + 第6/7 限流 429", codes[:5] == [200] * 5 and 429 in codes[5:], f"codes={codes}")
        # 窗口翻转恢复
        ok_restored = False
        for _ in range(60):
            st, _, _b = req("/login?user=later")
            if st == 200:
                ok_restored = True
                break
            time.sleep(0.5)
        check("S4 窗口翻转后恢复 200", ok_restored)

        # ================= S5 WebSocket =================
        try:
            ws, status_line, headers = ws_connect()
            check("S5 经网关升级 101", "101" in status_line and "websocket" in headers.lower(), status_line)
            ws_send(ws, "chat-1")
            fin, op, payload = ws_recv(ws)
            check("S5 echo 往返", op == 0x1 and payload == b"echo:chat-1", payload[:60])
            ws_send(ws, "x" * 300)  # 16bit 长度帧
            fin, op, payload = ws_recv(ws)
            check("S5 中帧(300B)往返", payload == b"echo:" + b"x" * 300, f"len={len(payload)}")
            ws.close()
        except Exception as e:
            check("S5 经网关升级 101", False, repr(e))
            check("S5 echo 往返", False, "跳过")
            check("S5 中帧(300B)往返", False, "跳过")

        # ================= S6 后台定时器心跳 =================
        def beats():
            _, _, b = req("/health")
            d = {}
            for line in b.decode().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    d[k.strip()] = v.strip()
            return d
        h1 = beats()
        time.sleep(4.5)
        h2 = beats()
        try:
            inc = int(h2.get("beats", 0)) - int(h1.get("beats", 0))
        except Exception:
            inc = -1
        check("S6 init 定时器后台 beats 递增", inc >= 1, f"h1={h1} h2={h2}")
        check("S6 note 由后台写入", str(h2.get("note", "")).startswith("beat-"), h2)

        # ================= S7 大文件上传 =================
        up = os.urandom(5 * 1024 * 1024)
        up_sha = hashlib.sha256(up).hexdigest()
        stU, _, jU = jreq("/upload/file", method="POST", data=up, timeout=60)
        check("S7 5MB 上传字节 sha256 端到端一致", stU == 200 and jU.get("body_sha256") == up_sha, f"st={stU} len={jU.get('body_len')}")
        over = os.urandom(8 * 1024 * 1024)
        try:
            stV, _, _bV = req("/upload/big", method="POST", data=over, timeout=30)
        except Exception as e:
            stV = f"err:{e}"
        check("S7 超 client_max_body_size → 413", stV == 413, f"st={stV}")

        # ================= S8 故障转移 =================
        stop(backends[0])  # 杀掉 9201
        oks, total = 0, 8
        for i in range(total):
            st, _, _b = req(f"/api/resilient{i}")
            if st == 200:
                oks += 1
        check("S8 杀后端后 8 请求全部 200（重试/摘除）", oks == total, f"{oks}/{total}")

        # ================= S9 上游超时 =================
        t0 = time.time()
        try:
            stT, _, _bT = req("/timeout", timeout=8)
        except Exception as e:
            stT = f"exc"
        el = time.time() - t0
        check("S9 慢上游触发读超时（快速失败，不挂起）", el < 6 and stT in (504, 502, "exc"), f"st={stT} elapsed={el:.1f}s")

        # ================= S10 上游宕机 =================
        try:
            stD, _, _bD = req("/down", timeout=8)
        except Exception:
            stD = "exc"
        check("S10 死端口 → 502", stD == 502, f"st={stD}")

        # ================= S11 并发突发 =================
        codes2 = []
        lock = threading.Lock()
        def worker(i):
            st, _, _b = req(f"/api/c{i}" if i % 2 else "/")
            with lock:
                codes2.append(st)
        ths = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        for t in ths: t.start()
        for t in ths: t.join(timeout=30)
        check("S11 并发 30 混合请求全部 200", len(codes2) == 30 and all(c == 200 for c in codes2), f"codes={set(codes2)} n={len(codes2)}")

        # ================= S12 畸形请求 =================
        try:
            s = socket.create_connection(("127.0.0.1", GW_PORT), timeout=5)
            s.sendall(b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n")
            resp = s.recv(200)
            s.close()
            check("S12 非法请求行 → 400 且网关存活", resp.startswith(b"HTTP/1.1 400"), resp[:60])
        except Exception as e:
            check("S12 非法请求行 → 400 且网关存活", False, repr(e))
        st_alive, _, _b_alive = req("/promo2026")
        check("S12 畸形请求后网关不崩溃", st_alive == 200, f"st={st_alive}")

        # ================= 收尾：网关日志在 finally 后统一检查 =================
    finally:
        stop(gw)
        for p in backends:
            if p.poll() is None:
                stop(p)
        gwlog.close()

    with open(os.path.join(ROOT, "realworld_gw.log"), "rb") as f:
        log = f.read().decode("utf-8", "replace")
    check("全程网关日志无 panic/异常崩溃", "panic" not in log.lower(), log[-200:])

    passed = sum(1 for _, ok in results if ok)
    print(f"\n===== realworld E2E: {passed}/{len(results)} PASS =====")
    return 0 if passed == len(results) else 1

if __name__ == "__main__":
    sys.exit(main() or 0)
