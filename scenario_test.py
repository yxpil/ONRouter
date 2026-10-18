# -*- coding: utf-8 -*-
"""ONRouter 场景模拟测试（本地签名证书，全 HTTPS 9443）

场景：
  S1  静态官网（site1.local）：首页 / about / 自定义 404 / 301 跳转
  S2  API 网关（api.local → 反代集群）：GET / POST
  S3  Lua 鉴权：无 token 401 / 错 token 403 / 对 token 200
  S4  负载均衡：两后端轮询
  S5  故障转移：杀掉一个后端 → 请求全部仍 200（被动健康检查摘除）
  S6  访问计数（shared.DICT）
  S7  证书验证：本地签名证书 SAN + 信任校验（server_hostname 匹配）
  S8  并发 HTTPS 请求
"""
import subprocess, sys, time, os, threading, socket, json
import urllib.request, urllib.error
import ssl as _ssl

RUST = os.path.dirname(os.path.abspath(__file__))  # 仓库根：脚本与 conf/、target/ 同级
HOST = "127.0.0.1"
PORT = 9443

# 信任本地签名证书
_ctx = _ssl.create_default_context(cafile=os.path.join(RUST, "certs_scenario", "server.pem"))
_ctx.check_hostname = True

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                      urllib.request.HTTPSHandler(context=_ctx))

def req(path, host="site1.local", method="GET", data=None, headers=None, timeout=8):
    """HTTPS 请求，SNI/Host 均为虚拟主机名"""
    h = {"Host": f"{host}:{PORT}"}
    h.update(headers or {})
    url = f"https://{host}:{PORT}{path}"   # 实际解析到 127.0.0.1（见 DNS 补丁）
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    # 强制连到本地
    try:
        resp = _opener.open(r, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

# 本地 DNS 补丁：*.local 全部解析到本机（SNI 与证书主机名校验保持真实）
import socket as _socket
_orig_gai = _socket.getaddrinfo
def _gai(host, *a, **k):
    if isinstance(host, str) and (host.endswith(".local") or host == "localhost"):
        host = "127.0.0.1"
    return _orig_gai(host, *a, **k)
_socket.getaddrinfo = _gai

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, (detail if not ok or detail else "")[:160])

# ---------- 模拟后端 ----------
def start_backend(port, name):
    code = f'''
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class B(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path == "/users":
            body = json.dumps({{"users": ["alice", "bob"], "node": "{name}"}}).encode()
        else:
            body = json.dumps({{"node": "{name}", "path": self.path}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        body = json.dumps({{"node": "{name}", "echo": raw.decode("utf-8", "ignore")}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("{HOST}", {port}), B).serve_forever()
'''
    return subprocess.Popen([sys.executable, "-c", code])

def main():
    b1 = start_backend(9101, "api-node-1")
    b2 = start_backend(9102, "api-node-2")
    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "scenario.conf")],
                          cwd=RUST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        # 等 API 集群就绪
        for p in (9101, 9102):
            for _ in range(50):
                try: socket.create_connection((HOST, p), timeout=0.5).close(); break
                except Exception: time.sleep(0.2)
        for _ in range(60):
            try:
                req("/", timeout=2); break
            except Exception: time.sleep(0.2)

        # ===== S1 静态官网 =====
        st, h, b = req("/")
        check("S1 首页 HTTPS+虚拟主机", st == 200 and "site1.local" in b.decode(), f"{st} {b[:80]}")
        st, h, b = req("/about.html")
        check("S1 静态子页", st == 200 and "关于我们" in b.decode(), f"{st} {b[:80]}")
        st, h, b = req("/no/such/page")
        check("S1 自定义 404 页", st == 404 and "custom-404" in b.decode(), f"{st} {b[:80]}")
        st, h, b = req("/promo")
        check("S1 301 跳转", st == 301 and "/promo-2026" in h.get("location", ""), f"{st} {h.get('location')}")
        check("S1 Server 头", h.get("server", "").startswith("ONRouter/"), h.get("server"))

        # ===== S2 API 反代 =====
        st, h, b = req("/api/users", host="api.local")
        j = json.loads(b.decode())
        check("S2 GET 反代 JSON", st == 200 and j.get("node") in ("api-node-1", "api-node-2") and j.get("users"), f"{st} {b[:100]}")
        check("S2 JSON Content-Type", "application/json" in h.get("content-type", ""), h.get("content-type"))
        st, h, b = req("/api/echo", host="api.local", method="POST", data=b'{"msg":"hello-scenario"}')
        j = json.loads(b.decode())
        check("S2 POST 反代回显", st == 200 and j.get("echo") == '{"msg":"hello-scenario"}', f"{st} {b[:100]}")

        # ===== S3 Lua 鉴权 =====
        st, h, b = req("/secure/panel", host="api.local")
        check("S3 无 token 401", st == 401, f"{st} {b[:80]}")
        st, h, b = req("/secure/panel", host="api.local", headers={"x-token": "wrong"})
        check("S3 错 token 403", st == 403, f"{st} {b[:80]}")
        st, h, b = req("/secure/panel", host="api.local", headers={"x-token": "admin-token-42"})
        check("S3 对 token 200", st == 200 and b"admin" in b, f"{st} {b[:80]}")

        # ===== S4 负载均衡 =====
        nodes = set()
        for _ in range(6):
            st, h, b = req("/api/lb", host="api.local")
            if st == 200: nodes.add(json.loads(b.decode())["node"])
        check("S4 双节点轮询", nodes == {"api-node-1", "api-node-2"}, str(nodes))

        # ===== S5 故障转移：杀掉 node-2 =====
        b2.kill(); b2.wait()
        time.sleep(0.3)
        sts = []
        for _ in range(6):
            st, h, b = req("/api/users", host="api.local")
            sts.append(st)
        check("S5 单节点故障转移", set(sts) == {200}, str(sts))
        st, h, b = req("/api/users", host="api.local")
        check("S5 流量全部落存活节点", json.loads(b.decode())["node"] == "api-node-1", b[:100])

        # ===== S6 访问计数 =====
        n1 = int(req("/visit")[2].decode().split("visit-no=")[1])
        n2 = int(req("/visit")[2].decode().split("visit-no=")[1])
        check("S6 shared.DICT 计数", n2 == n1 + 1, f"{n1}->{n2}")

        # ===== S7 本地签名证书验证 =====
        pem = _ssl.get_server_certificate((HOST, PORT))
        local = open(os.path.join(RUST, "certs_scenario", "server.pem"), "rb").read()
        check("S7 服务器证书=本地签名证书", pem.encode().replace(b"\r\n", b"\n") == local.replace(b"\r\n", b"\n"))
        # 信任校验 + 主机名匹配（SAN）
        try:
            st, h, b = req("/", timeout=5)
            check("S7 CA 信任链+SAN 主机名校验", st == 200)
        except _ssl.SSLCertVerificationError as e:
            check("S7 CA 信任链+SAN 主机名校验", False, f"证书校验失败: {e}")

        # ===== S8 并发 HTTPS =====
        errs = []
        def worker():
            for _ in range(5):
                try:
                    st, h, b = req("/")
                    if st != 200: errs.append(st)
                except Exception as e:
                    errs.append(type(e).__name__)
        ts = [threading.Thread(target=worker) for _ in range(24)]
        for t in ts: t.start()
        for t in ts: t.join()
        check("S8 并发 HTTPS 120 请求", not errs, str(errs[:5]))

    finally:
        gw.kill()
        b1.kill()
        b2.kill()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n=== {passed}/{len(results)} 通过 ===")
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    main()
