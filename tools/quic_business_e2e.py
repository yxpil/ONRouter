# -*- coding: utf-8 -*-
"""QUIC(HTTP/3) 与 HTTPS(h2/h1.1) 的业务形状 E2E。

为什么单独一条套件：`http3_e2e` 已经证明"h3 能握手、能拿 200、能并发多流"，但生产里真正
要回答的是另一件事 —— **同一个站、同一套策略，在三种传输上是不是同一回事**：

  * 静态站的字节、`expires`、gzip、Range、条件请求、HEAD，h3 有没有另开一套行为；
  * `proxy_cache` 与 `limit_req` 是不是**同一本账**（跨传输共享），还是每种协议各一套；
  * POST 的 64 KB 请求体在 h3 上是不是按字节交到源站（多包/流控这条路径最容易出quiet bug）；
  * 上游超时是不是照样 504、连不上是不是照样与 h2 给出同一个码；
  * SSE 这类逐帧 flush 的响应，h3 上是流式还是被缓冲成一坨；
  * **多证书 / 多 SNI 挂在同一个端口号上**（18156，三张证书）：h2 与 h3 是否都按 SNI 出示
    各自的证书、站点是否仍按 `:authority` 选、SNI 匹配不上时兜底的是不是 `default_server`
    那张（它故意写在最后一个块），以及 h2 与 h3 是不是共用同一本证书账。

客户端：h3 用与网关同栈的自研探针 `orr-h3check`（本机 curl/Node 都没有 HTTP/3），
h2 与 h1.1 用 Node 核心 `http2` / `https`（本机 libcurl 不带 HTTP/2）。三者输出同一套
字段（STATUS/PROTO/LEN/SHA/HDR…），因此跨传输的对撞是逐字段比较，不是"都返回 200"。

  cargo build --release -p onrouter-server && python tools/quic_business_e2e.py
"""
import gzip
import hashlib
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)          # import selfsigned：夹具模块与套件同目录
import selfsigned                     # noqa: E402
CONF = os.path.join(ROOT, "conf", "quic_business.conf")
CERT = os.path.join("certs_qbiz", "server.pem")
KEY = os.path.join("certs_qbiz", "server.key")
SITE = os.path.join(ROOT, "public_qbiz")
CACHE = os.path.join(ROOT, "conf", "logs", "qbiz_cache")
ERRLOG = os.path.join(ROOT, "conf", "logs", "qbiz_err.log")
JS = os.path.join(HERE, "h2_request_check.js")
GW = 18155
ORIGIN = 18159
SNI = "localhost"          # 自签证书 SAN 里有 localhost，QUIC 强制校验服务器名

results = []
LOCK = threading.Lock()
HITS = Counter()
ORDERS = {}
BIG = bytes((i * 7) % 251 for i in range(2 * 1024 * 1024))


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:260])


def find_bin(name):
    for prof in ("release", "debug"):
        for ext in (".exe", ""):
            p = os.path.join(ROOT, "target", prof, name + ext)
            if os.path.exists(p):
                return p
    return None


def build_site():
    shutil.rmtree(SITE, ignore_errors=True)
    os.makedirs(os.path.join(SITE, "assets"), exist_ok=True)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write("<html><head><title>qbiz</title></head><body>shop</body></html>\n")
    for i in range(20):
        with open(os.path.join(SITE, "assets", "s%02d.css" % i), "w", encoding="utf-8", newline="\n") as f:
            f.write("/* sheet %d */\n" % i + ".k%d{color:#%06x}\n" % (i, i * 4096 % 0xFFFFFF) * 30)
    with open(os.path.join(SITE, "assets", "big.txt"), "wb") as f:
        f.write(bytes((i * 13) % 251 for i in range(300 * 1024)))


def origin_server():
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body, extra=None, chunked=False):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if not chunked:
                self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if chunked:
                for part in body:
                    self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            with LOCK:
                HITS[path] += 1
                HITS["full:" + self.path] += 1
            if path == "/api/hot":
                time.sleep(0.2)                      # 详情要查库：够慢才看得出借线
                self._send(200, b'{"sku":1,"price":99,"v":1}\n')
            elif path == "/api/big":
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(BIG)))
                self.end_headers()
                self.wfile.write(BIG)
            elif path == "/api/limited":
                self._send(200, b"ok\n")
            elif path == "/api/stream":
                # 每帧单独 flush 再睡 200ms，共 8 帧 1.6 秒：客户端看到的帧间隔就是
                # "边生成边转发"的证据；如果被整份缓冲，八帧会在最后一刻一起到齐
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for i in range(8):
                    part = ("id: %d\n" % i + "d" * 1500 + "\n\n").encode()
                    self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
                    self.wfile.flush()
                    time.sleep(0.2)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            elif path == "/api/slow":
                time.sleep(1.6)                      # 比 proxy_read_timeout(1s) 慢
                self._send(200, b"late\n")
            else:
                self._send(404, b"{}\n")

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n)
            key = ""
            for part in raw.decode("utf-8", "replace").split("&"):
                if part.startswith("key="):
                    key = part[4:]
            with LOCK:
                HITS["order"] += 1
                HITS["order_bytes"] += len(raw)
                dup = key in ORDERS
                if not dup:
                    ORDERS[key] = (len(raw), _hex(raw))
            body = ("dup\n" if dup else "new\n").encode() + (
                "len=%d sha=%s\n" % (len(raw), _hex(raw)[:16])).encode()
            self._send(409 if dup else 201, body)

        def log_message(self, *a):
            pass

    class Quiet(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            pass

    srv = Quiet(("127.0.0.1", ORIGIN), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv


def _hex(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------ 三种客户端
def parse(out):
    d = {"hdrs": {}, "reqs": [], "frames": []}
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "HDR":
            name, _, val = v.partition(": ")
            d["hdrs"][name.lower()] = val
        elif k == "REQ":
            parts = dict(p.split("=", 1) for p in v.split(" ") if "=" in p)
            d["reqs"].append(parts)
        elif k == "FRAME":
            parts = dict(p.split("=", 1) for p in v.split(" ") if "=" in p)
            d["frames"].append(parts)
        elif k == "FILE":
            d["file"] = v
        else:
            d[k] = v
    return d


def raw_bytes(d):
    """探针/驱动把响应原文写进临时文件，这里读回来做逐字节比较。"""
    fp = d.get("file")
    if not fp or not os.path.exists(fp):
        return b""
    with open(fp, "rb") as f:
        return f.read()


def h3(path, mode="detail", n=1, hdrs=None, body_file=None, timeout=60):
    exe = find_bin("orr-h3check")
    env = dict(os.environ, ORR_H3_CERT=CERT)
    if hdrs:
        env["ORRH3_HDRS"] = hdrs
    if body_file:
        env["ORRH3_BODY"] = body_file
    cmd = [exe, "127.0.0.1:%d" % GW, SNI, path, mode] + ([str(n)] if n else [])
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env, timeout=timeout)
    return parse(r.stdout)


def h2(path, mode="detail", n=1, hdrs=None, body_file=None, timeout=60):
    env = dict(os.environ)
    if hdrs:
        env["QBIZ_HDRS"] = hdrs
    if body_file:
        env["QBIZ_BODY"] = body_file
    cmd = ["node", JS, "https://%s:%d" % (SNI, GW), mode, path] + ([str(n)] if n else [])
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env, timeout=timeout)
    return parse(r.stdout)


def h1(path, hdrs=None, timeout=60):
    return h2(path, mode="h1", hdrs=hdrs, timeout=timeout)


# ── 多证书 / 多 SNI / 单端口（18156）用的另一组探针 ─────────────────────────
# SNI 与 :authority 必须能分开给：证书在握手期按 SNI 选，站点在收到请求后按 authority 选。
# 两者相同的情形任何实现都能蒙对，只有分开时才看得出网关是不是真的分账。
JS_MULTI = os.path.join(HERE, "https_matrix_h2.js")
GW_MULTI = 18156
BUNDLE = os.path.join("certs_qbiz", "bundle.pem")
MULTI_HOSTS = ("a.qbiz.test", "b.qbiz.test", "catchall.qbiz.test")
# 不在任何 server_name 里、但在兜底证书 SAN 里的名字：拿它当 SNI 就会走"匹配不上 → 默认 server"
FALLBACK_SNI = "fallback.qbiz.test"


def fp_of(name):
    """<name>.pem 的 DER sha256，与探针打出来的 PEER_SHA256 同一口径。"""
    with open(os.path.join(ROOT, "certs_qbiz", name + ".pem"), encoding="ascii") as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def make_multi_certs():
    """三张独立证书 + 一份受信包（h3 客户端要同时信任三张才能读出指纹而不是掐断握手）。"""
    selfsigned.ensure(ROOT, "certs_qbiz", base="a", dns=("a.qbiz.test",), ips=())
    selfsigned.ensure(ROOT, "certs_qbiz", base="b", dns=("b.qbiz.test",), ips=())
    selfsigned.ensure(ROOT, "certs_qbiz", base="catchall",
                      dns=("catchall.qbiz.test", FALLBACK_SNI), ips=())
    out = os.path.join(ROOT, BUNDLE)
    with open(out, "w", encoding="ascii", newline="\n") as w:
        for name in ("a", "b", "catchall"):
            with open(os.path.join(ROOT, "certs_qbiz", name + ".pem"), encoding="ascii") as f:
                w.write(f.read())
    return out


def h3_multi(path, sni, authority=None, mode="detail"):
    exe = find_bin("orr-h3check")
    env = dict(os.environ, ORR_H3_CERT=BUNDLE)
    if authority:
        env["ORRH3_AUTHORITY"] = authority
    cmd = [exe, "127.0.0.1:%d" % GW_MULTI, sni, path, mode, "1"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env, timeout=60)
    return parse(r.stdout)


def h2_multi(path, sni, authority):
    cmd = ["node", JS_MULTI, "https://127.0.0.1:%d" % GW_MULTI, sni, authority, path]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    return parse(r.stdout)


def test_multi_sni():
    """同一个 TCP+UDP 端口号上三张证书：h2 与 h3 都必须按 SNI 出各自的证书，
    而站点按 authority 选——两本账分开，且**跨传输是同一本账**。"""
    fp = {h: fp_of(h.split(".")[0]) for h in MULTI_HOSTS}
    cases = [
        ("a.qbiz.test", "a.qbiz.test", "a", "vhost-a", "具名站点各归各的证书"),
        ("b.qbiz.test", "b.qbiz.test", "b", "vhost-b", "另一个具名站点另一张证书"),
        ("a.qbiz.test", "b.qbiz.test", "a", "vhost-b", "证书按 SNI、站点按 authority：两者可以不同"),
        (FALLBACK_SNI, "b.qbiz.test", "catchall", "vhost-b",
         "SNI 谁都不匹配 → 兜底证书必须是 default_server 那张（它写在最后一个块）"),
        (FALLBACK_SNI, FALLBACK_SNI, "catchall", "vhost-default",
         "SNI 与 authority 都不匹配 → 兜底证书 + 默认站点应答"),
    ]
    for sni, auth, want_cert, want_body, why in cases:
        d3 = h3_multi("/who", sni, auth)
        d2 = h2_multi("/who", sni, auth)
        # h3 探针把体报成 SHA/LEN（它要能传二进制），h2 探针报 BODY 文本：两侧都换算到
        # "这一站该回的那几个字节"，比较才是逐字节的而不是"看着像"。
        want = fp[want_cert + ".qbiz.test"]
        want_sha = hashlib.sha256((want_body + "\n").encode()).hexdigest()
        check(f"h3 SNI={sni} authority={auth} → {want_cert}.pem + {want_body}（{why}）",
              d3.get("PEER_SHA256") == want and d3.get("SHA") == want_sha,
              f"fp={str(d3.get('PEER_SHA256'))[:16]} want={want[:16]} "
              f"sha={str(d3.get('SHA'))[:16]} want_sha={want_sha[:16]} err={d3.get('ERROR')}")
        check(f"h2 SNI={sni} authority={auth} → {want_cert}.pem + {want_body}（{why}）",
              d2.get("PEER_SHA256") == want and (d2.get("BODY") or "") == want_body,
              f"fp={str(d2.get('PEER_SHA256'))[:16]} want={want[:16]} "
              f"body={str(d2.get('BODY'))[:40]!r} alpn={d2.get('ALPN')}")
        check(f"同一 (SNI={sni}, authority={auth}) 在 h2 与 h3 上是同一张证书、同一份应答",
              d3.get("PEER_SHA256") == d2.get("PEER_SHA256")
              and d3.get("SHA") == want_sha and (d2.get("BODY") or "") == want_body,
              f"h3={str(d3.get('PEER_SHA256'))[:12]} h2={str(d2.get('PEER_SHA256'))[:12]}")
    # ALPN 与站点独立可达性：18156 的 TCP 侧协商 h2、UDP 侧是 h3，两个具名站点都要能用
    d2 = h2_multi("/ping", "a.qbiz.test", "a.qbiz.test")
    d3 = h3_multi("/ping", "b.qbiz.test", "b.qbiz.test")
    check("18156 的 TCP 侧协商到 h2（不是只有 h1）", (d2.get("ALPN") or "") == "h2", d2)
    check("两个具名站点在新端口上各自应答自己的 /ping（h2 拿 a、h3 拿 b）",
          (d2.get("BODY") or "") == "pong-a"
          and d3.get("SHA") == hashlib.sha256(b"pong-b\n").hexdigest(),
          (str(d2.get("BODY"))[:20], str(d3.get("SHA"))[:12]))



def status_of(d):
    try:
        return int(d.get("STATUS", "0"))
    except ValueError:
        return 0


def main():
    gw_exe = find_bin("onrouter")
    if not gw_exe:
        raise SystemExit("!! 先构建：cargo build --release -p onrouter-server")
    if not find_bin("orr-h3check"):
        raise SystemExit("!! 先构建探针：cargo build --release -p onrouter-server --bin orr-h3check")
    if subprocess.run(["node", "-v"], capture_output=True).returncode != 0:
        raise SystemExit("!! 需要 node 来驱动 h2/h1 客户端")

    build_site()
    shutil.rmtree(CACHE, ignore_errors=True)
    os.makedirs(os.path.dirname(ERRLOG), exist_ok=True)
    for f in (ERRLOG,):
        if os.path.exists(f):
            os.remove(f)
    # 自带夹具：这张证书 h3 客户端是**真校验**的（CA=自己 + SAN 必须含 localhost），
    # 不能借别的套件的目录——CI 干净检出时那个目录根本不存在。
    selfsigned.ensure(ROOT, "certs_qbiz", base="server",
                      dns=("localhost",), ips=("127.0.0.1",))
    make_multi_certs()

    # 1) -t：quic 监听要在检查里说出来
    t = subprocess.run([gw_exe, "-t", "-c", CONF], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    tout = (t.stdout or "") + (t.stderr or "")
    check("-t 通过", t.returncode == 0, tout[-300:])
    check("-t 没有未知指令告警", "未知指令" not in tout, tout[-200:])
    check("-t 说出这个端口的 TLS 监听同时用 HTTP/3 服务（不只从外部才能探出来）",
          "HTTP/3" in tout, tout[-400:])

    srv = origin_server()
    # CI 是干净检出：logs/ 在 .gitignore 里，套件自己把它建出来
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "qbiz_out.log"), "wb")
    proc = subprocess.Popen([gw_exe, "-c", CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(160):
            try:
                if status_of(h3("/ping")) == 200:
                    break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            raise SystemExit("!! 网关未就绪，看 logs/qbiz_out.log 与 conf/logs/qbiz_err.log")
        print("网关已就绪", GW)

        # ── 2) 协商：三种传输各自真的走各自协议，且同一个端口 ──────────────
        a1 = h1("/index.html")
        a2 = h2("/index.html")
        a3 = h3("/index.html")
        check("h1.1 over TLS 协商到 HTTP/1.1", a1.get("PROTO") == "HTTP/1.1", a1.get("PROTO"))
        check("h2 over TLS 协商到 HTTP/2", a2.get("PROTO") == "HTTP/2", a2.get("PROTO"))
        # 探针报的是 http crate 的版本枚举（"HTTP/3.0"），按前缀判而不是猜拼写
        check("h3 over UDP 协商到 HTTP/3",
              str(a3.get("PROTO", "")).startswith("HTTP/3"), a3.get("PROTO"))
        check("三种传输都 200", [status_of(x) for x in (a1, a2, a3)] == [200, 200, 200],
              [status_of(x) for x in (a1, a2, a3)])

        # ── 3) 静态站字节一致 ─────────────────────────────────────────────
        check("首页在三端字节一致（SHA 相同）",
              a1.get("SHA") == a2.get("SHA") == a3.get("SHA") and a1.get("SHA") != "",
              (a1.get("SHA"), a2.get("SHA"), a3.get("SHA")))
        diffs = []
        for i in range(0, 20, 4):
            p = "/assets/s%02d.css" % i
            x2, x3 = h2(p), h3(p)
            if not (status_of(x2) == status_of(x3) == 200 and x2.get("SHA") == x3.get("SHA")):
                diffs.append(p)
        check("静态资产 h2 与 h3 逐份字节一致（抽样 5 份）", not diffs, diffs)
        st1, st2, st3 = h1("/assets/s01.css"), h2("/assets/s01.css"), h3("/assets/s01.css")
        check("expires 在三种传输上都是 max-age=2592000（同一份策略，不是每种协议一套）",
              all(d["hdrs"].get("cache-control") == "max-age=2592000" for d in (st1, st2, st3)),
              [d["hdrs"].get("cache-control") for d in (st1, st2, st3)])

        gz1 = h1("/assets/s00.css", hdrs="accept-encoding:gzip")
        gz2 = h2("/assets/s00.css", hdrs="accept-encoding:gzip")
        gz3 = h3("/assets/s00.css", hdrs="accept-encoding:gzip")
        check("三端都按 accept-encoding 压（h1/h2/h3 都给 gzip）",
              all(d["hdrs"].get("content-encoding") == "gzip" for d in (gz1, gz2, gz3)),
              [d["hdrs"].get("content-encoding") for d in (gz1, gz2, gz3)])
        etag = a2["hdrs"].get("etag") or a3["hdrs"].get("etag")
        nc = h3("/index.html", hdrs="if-none-match:" + (etag or "?"))
        hc = h2("/index.html", hdrs="if-none-match:" + (etag or "?"))
        if etag:
            check("条件请求在 h2/h3 上都给 304 且没有 body",
                  status_of(nc) == 304 and status_of(hc) == 304 and nc.get("LEN") == "0",
                  (status_of(nc), status_of(hc), nc.get("LEN")))
        else:
            check("静态文件带 ETag（条件请求的前提）", False, "响应头里没有 etag")
        rg = h3("/assets/big.txt", hdrs="range:bytes=100-199")
        rh = h2("/assets/big.txt", hdrs="range:bytes=100-199")
        check("Range 分片：h2/h3 都 206、都是 100 字节、内容一致",
              status_of(rg) == 206 and status_of(rh) == 206
              and rg.get("LEN") == rh.get("LEN") == "100" and rg.get("SHA") == rh.get("SHA"),
              (status_of(rg), rg.get("LEN"), status_of(rh), rh.get("LEN")))
        hd = h3("/index.html", mode="head")
        hh = h2("/index.html", mode="head")
        check("HEAD 在 h2/h3 上都是空 body 且 content-length 与 GET 一致",
              status_of(hd) == 200 and hd.get("LEN") == "0"
              and hd["hdrs"].get("content-length") == hh["hdrs"].get("content-length"),
              (hd.get("LEN"), hd["hdrs"].get("content-length")))
        # 网关的 gzip 是"每段 flush 一次"的多段 gzip 流：浏览器/curl/Python 的 gzip 模块都按
        # 拼接的多 member 处理，但 zlib.decompress 只认第一段之后会报"incorrect header check"。
        # 用 gzip.decompress（真实解码器口径）比，别拿 zlib 的局限当网关的 bug。
        plain = h2("/assets/s00.css")
        z3, z2 = raw_bytes(gz3), raw_bytes(gz2)
        try:
            u3 = gzip.decompress(z3)
        except Exception as e:  # noqa: BLE001
            u3 = b"<decompress-failed: %s>" % str(e).encode()
        try:
            u2 = gzip.decompress(z2)
        except Exception as e:  # noqa: BLE001
            u2 = b"<decompress-failed: %s>" % str(e).encode()
        check("gzip 响应在 h2/h3 上都能解压回原字节（多段 gzip 流是合法 gzip）",
              u3 == u2 == raw_bytes(plain) and z3[:2] == bytes([31, 139]),
              "h2 压缩=%d 解压=%r / h3 压缩=%d 解压=%r / 明文=%s"
              % (len(z2), u3[:24], len(z3), u2[:24], plain.get("LEN")))

        # ── 4) 缓存与限流是同一本账 ────────────────────────────────────────
        base = HITS["/api/hot"]
        h2many = h2("/api/hot", mode="many", n=30)
        h3many = h3("/api/hot", mode="many", n=30)
        got = HITS["/api/hot"] - base
        ok2 = h2many.get("SUMMARY", "").split("/")
        ok3 = h3many.get("SUMMARY", "").split("/")
        check("热点详情：h2 30 次 + h3 30 次，源站只被打 1 次（同一条缓存）",
              got == 1, f"源站 {got} 次")
        check("两种传输上 60 次都拿到 200", ok2[0] == "30" and ok3[0] == "30",
              (h2many.get("SUMMARY"), h3many.get("SUMMARY")))
        check("h2 与 h3 看到的详情字节完全一致", h2many["reqs"][0]["SHA"] == h3many["reqs"][0]["SHA"],
              (h2many["reqs"][0]["SHA"][:12], h3many["reqs"][0]["SHA"][:12]))
        xh = h3("/api/hot")
        check("h3 命中同一条缓存（X-Cache: HIT）", xh["hdrs"].get("x-cache") == "HIT",
              xh["hdrs"].get("x-cache"))

        n_herd = 7
        base_h = HITS["full:/api/hot?n=%d" % n_herd]
        par = h3("/api/hotn?n=%d" % n_herd, mode="streams", n=20)
        hits_herd = HITS["full:/api/hot?n=%d" % n_herd] - base_h
        check("h3 上的惊群：20 个并发流抢一个全新 key，源站只被打 ≤2 次",
              hits_herd <= 2 and par.get("STREAMS") == "20", f"源站 {hits_herd} 次 {par.get('STREAMS')}")

        base_l = HITS["/api/limited"]
        b1 = h2("/api/limited", mode="streams", n=12, hdrs="cookie:sid=A")
        b2 = h3("/api/limited", mode="streams", n=6, hdrs="cookie:sid=A")
        b3 = h3("/api/limited", mode="streams", n=6, hdrs="cookie:sid=B")
        check("限流按会话：sid=A 在 h2 上 12 并发放行 6 个（rate=2r/s burst=5）",
              b1.get("STREAMS") == "6", b1.get("STREAMS"))
        check("同一个 sid=A 换到 h3 上几乎没有余量（跨传输共用一个桶）",
              int(b2.get("STREAMS", "9")) <= 2, b2.get("STREAMS"))
        check("换 sid=B 立刻恢复满额（不是全局变慢，也不是按连接/按协议）",
              b3.get("STREAMS") == "6", b3.get("STREAMS"))
        b4 = h3("/api/limited", mode="streams", n=20)
        check("h3 上不带 cookie = 空键 = 本区不限流（nginx 语义在 h3 上一致）",
              b4.get("STREAMS") == "20", b4.get("STREAMS"))

        # ── 5) 真实业务动作 over QUIC ──────────────────────────────────────
        pf = os.path.join(ROOT, "target", "qbiz_post.bin")
        payload = ("key=ord-h3&sku=7&note=" + "x" * (64 * 1024)).encode()
        with open(pf, "wb") as f:
            f.write(payload)
        p3 = h3("/api/order", mode="post", body_file=pf)
        p2 = h2("/api/order", mode="post", body_file=pf)
        check("h3 上 64 KB 的 POST 完整交到源站（状态 201）", status_of(p3) == 201,
              (status_of(p3), raw_bytes(p3)[:24]))
        check("同一个 key 换到 h2 上重发，被源站按重复挡住（409）——幂等性由源站判定，"
              "网关没有把它变成两次投递", status_of(p2) == 409, status_of(p2))
        with LOCK:
            seen = ORDERS.get("ord-h3", (None, None))
        # 这一条就是"h2/h3 把请求体丢了"那个 bug 的回归闸：以前源站收到的 POST 是
        # 0 字节（网关自述 body=nil），因为 has_body 只看 Content-Length/Transfer-Encoding，
        # 而分帧协议两个都不带。长度与摘要都必须对上。
        check("POST 请求体按字节交到源站（h2/h3 都不许丢 body：长度与 sha 一起对）",
              seen[0] == len(payload) and seen[1] == _hex(payload),
              (seen[0], len(payload), (seen[1] or "")[:12]))

        big3 = h3("/api/big")
        big2 = h2("/api/big")
        check("2 MB 大响应过 h3：长度与摘要正确（QUIC 多包/重组这条路完整）",
              big3.get("LEN") == big2.get("LEN") == str(len(BIG)) and big3.get("SHA") == big2.get("SHA"),
              (big3.get("LEN"), big2.get("LEN")))

        # 上游 8 帧、每 200ms 一帧。h3 探针是逐 DATA 帧计数的，所以它能直接证明
        # "边到边转发"；Node 的 stream 层会把小块合并，帧数不是它的证据，因此 h2 一侧
        # 判"总字节对 + 整体耗时覆盖住源站的节奏"（没缓冲成一坨才可能花这么久）。
        s3 = h3("/api/stream", mode="sse")
        s2 = h2("/api/stream", mode="sse")
        at3 = [int(x["AT"]) for x in s3["frames"]]
        check("SSE over h3：至少 6 帧分开到达，首末帧间隔 ≥800ms（逐帧转发，没有整份缓冲）",
              int(s3.get("FRAMES", "0")) >= 6 and len(at3) >= 6 and at3[-1] - at3[0] >= 800,
              (s3.get("FRAMES"), at3[:10]))
        total2 = sum(int(x["BYTES"]) for x in s2["frames"])
        at2 = [int(x["AT"]) for x in s2["frames"]]
        check("SSE over h2：字节完整（8×1509 B），且整体耗时覆盖源站的 1.6s 节奏",
              12000 <= total2 <= 12100 and (not at2 or at2[-1] >= 1200),
              (total2, s2.get("FRAMES"), at2))

        par = h3("/assets/big.txt", mode="streams", n=50)
        check("h3 单连接 50 条并发流全部 200（真多路复用，不是排队）",
              par.get("STREAMS") == "50", par.get("STREAMS"))

        cx = h3("/api/hot", mode="cancel", n=20)
        check("丢 20 条半途而废的流之后，同一条 h3 连接仍能正常服务",
              cx.get("CANCELLED", "").startswith("20") and "THEN=200" in cx.get("CANCELLED", ""),
              cx.get("CANCELLED"))

        slow3 = h3("/api/slow")
        slow2 = h2("/api/slow")
        check("上游超时：h3 给 504（把 502/504 的口径带到 QUIC 上）",
              status_of(slow3) == 504, status_of(slow3))
        check("上游超时：h2 同样 504（跨传输一致）", status_of(slow2) == 504, status_of(slow2))
        dead3 = h3("/api/dead")
        dead2 = h2("/api/dead")
        check("上游连不上：h3 与 h2 给出同一个码（本机是 502 还是 504 由主机决定，一致性由我们保证）",
              dead3.get("STATUS") == dead2.get("STATUS")
              and dead3.get("STATUS") in ("502", "504"),
              (dead3.get("STATUS"), dead2.get("STATUS")))

        big_hdr = "cookie:sid=HDR-%d-" % (time.time() * 1000 % 100000) + "z" * 8192
        bh = h3("/api/limited", hdrs=big_hdr)
        check("8 KB 级别的请求头在 h3 上正常送达（不是被截断成 400）",
              status_of(bh) in (200, 429), status_of(bh))
        asv = h1("/index.html")
        check("TCP 侧响应通告 alt-svc: h3（浏览器才知道能跳过去）",
              "h3=" in (asv["hdrs"].get("alt-svc") or "").lower(), asv["hdrs"].get("alt-svc"))

        # ── 6) 混合窗口：三种传输一起打 15 秒 ─────────────────────────────
        t0 = time.time()
        codes = Counter()

        def one_mix(i):
            which = i % 3
            p = ["/index.html", "/api/hot", "/assets/s03.css"][i % 3]
            try:
                d = [h3, h2, h1][which](p)
                return status_of(d)
            except Exception as e:
                return "exc:" + type(e).__name__

        with ThreadPoolExecutor(max_workers=8) as ex:
            for st in ex.map(one_mix, range(120)):
                codes[st] += 1
        wall = time.time() - t0
        check("混合窗口 120 个请求（h3/h2/h1 轮转）没有 5xx、没有异常",
              not any(isinstance(k, int) and k >= 500 for k in codes)
              and not any(isinstance(k, str) for k in codes), dict(codes))
        check("混合窗口没有把请求排成长队（%.1fs 内完成 120 个跨三传输请求）" % wall, wall < 120, wall)

        # ── 6b) 多证书 / 多 SNI / 单端口：h2 与 h3 各按 SNI 出示证书，站点仍按 authority ──
        print("\n-- 6b) 18156：三张证书一个端口（h2 + h3） --")
        test_multi_sni()

        with open(ERRLOG, encoding="utf-8", errors="replace") as f:
            errs = f.read()
        check("错误日志里没有 panic / 崩溃", "panic" not in errs.lower(),
              [l for l in errs.splitlines() if "panic" in l.lower()][:2])
        # /api/slow 与 /api/dead 是我们**故意**打的两条失败路径（504/502 的证据），
        # 它们必然在日志里留下"代理失败"；除此之外的回源失败才是问题
        stray = [l for l in errs.splitlines()
                 if "代理失败" in l and "/api/slow" not in l and "/api/dead" not in l]
        check("除刻意制造的超时/死端口之外没有回源失败", not stray, stray[:2])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        srv.shutdown()
        logf.close()

    bad = [n for n, ok in results if not ok]
    print("\n%d/%d 通过" % (len(results) - len(bad), len(results)))
    if bad:
        print("失败：", " | ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
