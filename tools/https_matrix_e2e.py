# -*- coding: utf-8 -*-
# HTTPS 实际业务矩阵 E2E —— 一个进程内同时验证：
#   1) 多证书 SNI 选择：精确 > *.通配 > 默认第一张；大小写、无 SNI、未知 SNI、通配打通配
#      （18443 的 default_server 写在最前）
#   1b) 同形状但 default_server 写在最后一个块（18449）：兜底证书必须跟着 default_server 走，
#      而不是跟着配置顺序 —— 只有这一组能分辨这两种实现
#   2) 证书链/主机名校验：用各自自签证书当 CA，正常域名通过、错域名被拒
#   3) Host 与 SNI 不一致：证书由 SNI 决定，路由由 Host 决定（互相独立）
#   4) 多端口隔离：同一域名在 TLS / 明文 / 仅1.2 / 仅1.3 / h2 端口上各回各的
#   5) 协议版本与密码套件：TLS1.2/1.3 可协商与裁剪；Python + openssl s_client 双客户端取证
#   6) ALPN：18443 只给 http/1.1，18447 可协商 h2；Node 真发 h2 请求
#   7) 会话复用：同端口 TLS1.2/1.3 可复用；默认 ssl_session_tickets on 且 ticket 密钥
#      进程内共享，跨监听端口也可无状态恢复（显式 shared 缓存的矩阵见 tls_session_e2e.py）
#   8) 并发混合流量：多域名 × 多端口 × 双版本，断言 0 错误
#   9) 握手/新建连接性能：TLS1.3 vs TLS1.2 vs 明文，p50/p90/p99 与 ops/s
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/https_matrix_e2e.py
import concurrent.futures
import hashlib
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "https_matrix.conf")
CERT_DIR = os.path.join(ROOT, "certs_https")

HOST = "127.0.0.1"
SNI_PORT = 18443   # 多 vhost + 多证书，TLS1.2/1.3
P12 = 18444        # 仅 TLS1.2
P13 = 18445        # 仅 TLS1.3
PPLAIN = 18446     # 明文
PH2 = 18447        # TLS + ALPN h2
PHMH = 18448       # TLS + ALPN h2 + 多域名（default_server 在最前）
PDEFAULT_LAST = 18449  # 多域名，但 default_server 写在最后一个块
PORTS = [SNI_PORT, P12, P13, PPLAIN, PH2, PHMH, PDEFAULT_LAST]

results = []
gaps = []
bench_rows = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def gap(name, detail=""):
    gaps.append((name, detail))
    print("GAP ", name, "" if not detail else detail)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


OPENSSL = None
NODE = None


def ensure_tools():
    global OPENSSL, NODE
    import shutil
    OPENSSL = shutil.which("openssl")
    if not OPENSSL:
        raise SystemExit("!! 需要 openssl 在 PATH 上（生成多证书夹具）")
    NODE = shutil.which("node")


# ---------------- 证书夹具 ----------------

CERT_SPECS = {
    # name: (CN, SANs, key kind)
    "default": ("default.local", ["default.local"], "rsa"),
    "a": ("a.local", ["a.local", "www.a.local"], "rsa"),
    "b": ("b.local", ["b.local"], "ec"),
    "wild": ("*.wild.local", ["*.wild.local"], "ec"),
    "api": ("api.wild.local", ["api.wild.local"], "ec"),
}


def cert_paths(name):
    return (os.path.join(CERT_DIR, name + ".pem"), os.path.join(CERT_DIR, name + ".key"))


def ensure_certs():
    os.makedirs(CERT_DIR, exist_ok=True)
    for name, (cn, sans, kind) in CERT_SPECS.items():
        pem, key = cert_paths(name)
        if os.path.exists(pem) and os.path.exists(key):
            continue
        cmd = [OPENSSL, "req", "-x509"]
        if kind == "rsa":
            cmd += ["-newkey", "rsa:2048"]
        else:
            cmd += ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
        cmd += [
            "-days", "3650", "-nodes", "-subj", f"/CN={cn}",
            "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans),
            "-keyout", key, "-out", pem,
        ]
        p = subprocess.run(cmd, capture_output=True, timeout=60)
        if p.returncode != 0:
            raise SystemExit(
                f"!! 生成证书 {name} 失败: {p.stderr.decode('utf-8', 'replace')[:500]}"
            )


def cert_fingerprint(name):
    pem, _ = cert_paths(name)
    with open(pem, "r", encoding="ascii") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return hashlib.sha256(der).hexdigest()


# ---------------- TLS 客户端 ----------------

def make_ctx(version=None, alpn=None, cafile=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cafile:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if alpn is not None:
        ctx.set_alpn_protocols(alpn)
    return ctx


def read_http_response(sock, timeout=8):
    sock.settimeout(timeout)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, sep, body = data.partition(b"\r\n\r\n")
    status = ""
    if sep and b" " in head:
        parts = head.split(b" ", 2)
        if len(parts) >= 2:
            status = parts[1].decode("ascii", "replace")
    return status, body.decode("utf-8", "replace")


def tls_request(port, sni, host=None, version=None, alpn=None, timeout=8,
                cafile=None, request=True):
    """完整 TLS 请求。sni=None 表示不发 SNI；host=None 时 Host 用 sni。
    失败返回 ok=False 与 phase（connect/handshake/post）。"""
    res = {"ok": False, "phase": "connect"}
    raw = None
    s = None
    try:
        ctx = make_ctx(version, alpn, cafile)
        raw = socket.create_connection((HOST, port), timeout=timeout)
        res["phase"] = "handshake"
        s = ctx.wrap_socket(raw, server_hostname=sni)
        res["ver"] = s.version()
        cipher = s.cipher()
        res["cipher"] = cipher[0] if cipher else None
        res["alpn"] = s.selected_alpn_protocol()
        der = s.getpeercert(binary_form=True)
        res["fp"] = hashlib.sha256(der).hexdigest() if der else None
        res["reused"] = bool(s.session_reused)
        if cafile:
            res["cert"] = s.getpeercert()
        if request:
            res["phase"] = "post"
            h = host if host is not None else (sni or "default.local")
            req = f"GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii"))
            status, body = read_http_response(s, timeout)
            res["status"] = status
            res["body"] = body
        res["ok"] = True
    except Exception as e:
        res["err"] = f"{type(e).__name__}: {e}"
    finally:
        for sk in (s, raw):
            if sk is not None:
                try:
                    sk.close()
                except Exception:
                    pass
    return res


def plain_request(port, host, timeout=8):
    res = {"ok": False}
    s = None
    try:
        s = socket.create_connection((HOST, port), timeout=timeout)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode("ascii"))
        status, body = read_http_response(s, timeout)
        res.update(ok=True, status=status, body=body)
    except Exception as e:
        res["err"] = f"{type(e).__name__}: {e}"
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return res


def body_is(res, want):
    return res.get("status") == "200" and res.get("body", "").strip() == want


def openssl_probe(port, servername, version_arg, alpn=None, timeout=15):
    cmd = [OPENSSL, "s_client", "-connect", f"{HOST}:{port}", "-servername", servername, version_arg]
    if alpn:
        cmd += ["-alpn", alpn]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except Exception as e:
        return {"rc": 127, "text": str(e)}
    text = (p.stdout + p.stderr).decode("utf-8", "replace")
    m = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.M)
    c = re.search(r"^\s*Cipher\s*:\s*(\S+)", text, re.M)
    a = re.search(r"ALPN protocol:\s*(\S+)", text)
    return {
        "rc": p.returncode,
        "proto": m.group(1) if m else None,
        "cipher": c.group(1) if c else None,
        "alpn": a.group(1) if a else None,
        "text": text,
    }


def node_h2(url, servername=None, authority=None, path="/", timeout=20):
    if not NODE:
        return {"__err__": "node not found"}
    cmd = [NODE, os.path.join(HERE, "https_matrix_h2.js"), url]
    if servername:
        cmd.append(servername)
    if authority:
        cmd.append(authority)
    if path != "/":
        cmd.append(path)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception as e:
        return {"__err__": str(e)}
    kv = {}
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("ERROR"):
            kv["__err__"] = line
        elif "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    if p.returncode != 0 and "__err__" not in kv:
        kv["__err__"] = (p.stderr.decode("utf-8", "replace") or p.stdout.decode("utf-8", "replace")).strip()
    return kv


def assert_ports_free(ports):
    """按「能否连上」判断占用：避免 TIME_WAIT 让 bind 误报。"""
    busy = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            if s.connect_ex((HOST, p)) == 0:
                busy.append(p)
        finally:
            s.close()
    if busy:
        raise SystemExit(f"!! 端口被占用: {busy}（不杀任何进程，请先确认是谁在监听）")


# ---------------- 性能 ----------------

def pct(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = int(round((len(xs) - 1) * p))
    return xs[k]


def bench_connections(port, version, mode, threads=8, per_thread=150):
    """mode=handshake: connect + TLS 握手后立即关闭；mode=request: 再加上一次 GET。
    version=None 且 mode=tcp → 纯 TCP connect/close（明文请求另测）。"""
    def worker(_):
        lat = []
        errs = 0
        ctx = make_ctx(version) if version else None
        for _ in range(per_thread):
            t0 = time.perf_counter()
            raw = None
            s = None
            try:
                raw = socket.create_connection((HOST, port), timeout=8)
                if ctx is not None:
                    s = ctx.wrap_socket(raw, server_hostname="a.local")
                sock = s if s is not None else raw
                if mode == "request":
                    h = "a.local"
                    sock.sendall(f"GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n".encode())
                    status, body = read_http_response(sock, 8)
                    if status != "200":
                        raise RuntimeError(f"status={status}")
                lat.append((time.perf_counter() - t0) * 1000.0)
            except Exception:
                errs += 1
            finally:
                for sk in (s, raw):
                    if sk is not None:
                        try:
                            sk.close()
                        except Exception:
                            pass
        return lat, errs

    # 预热，避免首批连接承担 DNS/证书缓存等一次性成本
    for _ in range(10):
        try:
            raw = socket.create_connection((HOST, port), timeout=8)
            if version:
                s = make_ctx(version).wrap_socket(raw, server_hostname="a.local")
                s.close()
            else:
                raw.close()
        except Exception:
            pass

    wall0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        chunks = list(ex.map(worker, range(threads)))
    wall = time.perf_counter() - wall0
    lat = [x for c, _ in chunks for x in c]
    errs = sum(e for _, e in chunks)
    return {
        "lat": lat,
        "errs": errs,
        "ops": len(lat) / wall if wall > 0 else 0.0,
        "p50": pct(lat, 0.50),
        "p90": pct(lat, 0.90),
        "p99": pct(lat, 0.99),
        "wall": wall,
    }


def print_bench(label, r):
    print(f"  {label:<26} {r['ops']:8.0f} op/s  p50={r['p50']:6.2f}ms  "
          f"p90={r['p90']:6.2f}ms  p99={r['p99']:6.2f}ms  errs={r['errs']}")
    bench_rows.append((label, r))


# ---------------- 主流程 ----------------

def main():
    ensure_tools()
    ensure_certs()
    fps = {name: cert_fingerprint(name) for name in CERT_SPECS}
    pem = {name: cert_paths(name)[0] for name in CERT_SPECS}

    if not os.path.exists(CONF):
        raise SystemExit(f"!! 缺配置 {CONF}")
    assert_ports_free(PORTS)

    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    out_path = os.path.join(ROOT, "logs", "https_matrix_out.log")
    logf = open(out_path, "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(100):
            if proc.poll() is not None:
                break
            if tls_request(SNI_PORT, "a.local", host="a.local").get("ok"):
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            logf.flush()
            tail = ""
            try:
                with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                    tail = "".join(f.readlines()[-30:])
            except Exception:
                pass
            raise SystemExit(f"!! onrouter 未就绪（看 {out_path}）\n{tail}")

        # ========== 1) SNI 选证书 ==========
        print("\n-- 1) SNI 选证书（精确 / 通配 / 默认） --")
        sni_cases = [
            ("a.local", "a", "精确名"),
            ("A.LOCAL", "a", "大小写无关"),
            ("www.a.local", "a", "同一 server 的第二个 server_name"),
            ("b.local", "b", "另一张精确证书"),
            ("x.wild.local", "wild", "通配子域"),
            ("a.b.wild.local", "wild", "通配多级子域（与 nginx 一致）"),
            ("api.wild.local", "api", "精确名压过通配"),
            ("wild.local", "default", "通配不匹配裸域"),
            ("unknown.local", "default", "未知 SNI 回落默认证书"),
            (None, "default", "无 SNI 回落默认证书"),
        ]
        for sni, want, why in sni_cases:
            r = tls_request(SNI_PORT, sni)
            check(f"SNI {sni or '<无>'} → {want} 证书（{why}）",
                  r.get("ok") and r.get("fp") == fps[want],
                  f"ok={r.get('ok')} fp={str(r.get('fp'))[:16]} want={fps[want][:16]} err={r.get('err')}")

        # ========== 1b) 兜底证书跟的是 default_server，不是配置顺序 ==========
        # 上面那组恰好把 default_server 写在第一个块，两种实现看不出差别；这一组写在最后。
        print("\n-- 1b) default_server 写在最后：兜底证书仍必须是它的那张 --")
        for sni, want, why in [
            ("a.local", "a", "精确名照旧（对照组：证明指纹判定不是恒真）"),
            ("unknown.local", "default", "未知 SNI → default_server 的证书"),
            (None, "default", "无 SNI → default_server 的证书"),
        ]:
            r = tls_request(PDEFAULT_LAST, sni)
            check(f"18449 SNI {sni or '<无>'} → {want} 证书（{why}）",
                  r.get("ok") and r.get("fp") == fps[want],
                  f"ok={r.get('ok')} fp={str(r.get('fp'))[:16]} want={fps[want][:16]} err={r.get('err')}")
        r = tls_request(PDEFAULT_LAST, "unknown.local")
        check("18449 未知 Host 由 default_server 应答（证书与站点同源，不能一个按顺序一个按 default）",
              r.get("ok") and r.get("body", "").strip() == "lastgroup-default", f"{r}")
        r = tls_request(PDEFAULT_LAST, "a.local")
        check("18449 SNI=a.local 且 Host=a.local → a 站内容",
              r.get("ok") and r.get("body", "").strip() == "lastgroup-a", f"{r}")

        # ========== 2) 证书链 + 主机名校验 ==========
        print("\n-- 2) 证书链与主机名校验（各自自签证书当 CA） --")
        for name, sni, want_body in [
            ("a", "a.local", "vhost-a"),
            ("b", "b.local", "vhost-b"),
            ("wild", "x.wild.local", "vhost-wild"),
            ("api", "api.wild.local", "vhost-api"),
            ("default", "default.local", "vhost-default"),
        ]:
            r = tls_request(SNI_PORT, sni, cafile=pem[name])
            san = []
            if r.get("cert"):
                san = [v for typ, v in r["cert"].get("subjectAltName", ()) if typ == "DNS"]
            # SAN 可能是 *.wild.local，客户端侧按单层通配核对
            san_ok = any(
                v == sni or (v.startswith("*.") and sni.endswith(v[1:]) and "." not in sni[: -len(v[1:])])
                for v in san
            )
            check(f"信任 {name}.pem 时 {sni} 主机名校验通过",
                  r.get("ok") and body_is(r, want_body) and san_ok,
                  f"ok={r.get('ok')} body={r.get('body')!r} san={san} err={r.get('err')}")

        r = tls_request(SNI_PORT, "b.local", cafile=pem["a"])
        check("信任 a.pem 时连接 b.local 被证书校验拒绝",
              not r.get("ok") and r.get("phase") == "handshake",
              f"ok={r.get('ok')} phase={r.get('phase')} err={r.get('err')}")
        r = tls_request(SNI_PORT, "a.local", cafile=pem["b"])
        check("信任 b.pem 时连接 a.local 被证书校验拒绝",
              not r.get("ok") and r.get("phase") == "handshake",
              f"ok={r.get('ok')} phase={r.get('phase')} err={r.get('err')}")

        # ========== 3) Host 与 SNI 交叉 ==========
        print("\n-- 3) Host 与 SNI 不一致：证书看 SNI、路由看 Host --")
        cross = [
            ("a.local", "b.local", "a", "vhost-b"),
            ("b.local", "a.local", "b", "vhost-a"),
            ("unknown.local", "a.local", "default", "vhost-a"),
            ("a.local", "unknown.local", "a", "vhost-default"),
            ("a.local", "a.local:18443", "a", "vhost-a"),
            ("a.local", "A.LOCAL", "a", "vhost-a"),
            ("a.local", "www.a.local", "a", "vhost-a"),
            ("unknown.local", "wild.local", "default", "vhost-default"),
            ("x.wild.local", "y.wild.local", "wild", "vhost-wild"),
        ]
        for sni, host, want_cert, want_body in cross:
            r = tls_request(SNI_PORT, sni, host=host)
            check(f"SNI={sni} + Host={host} → 证书 {want_cert} / 路由 {want_body}",
                  r.get("ok") and r.get("fp") == fps[want_cert] and body_is(r, want_body),
                  f"ok={r.get('ok')} fp={str(r.get('fp'))[:16]} body={r.get('body')!r} err={r.get('err')}")

        # ========== 4) 多端口隔离 ==========
        print("\n-- 4) 多端口隔离：同域名不同端口各回各的 --")
        r = tls_request(SNI_PORT, "a.local", version="1.2")
        check("a.local@18443（多 vhost）→ vhost-a", r.get("ok") and body_is(r, "vhost-a"), f"{r}")
        r = tls_request(P12, "a.local", version="1.2")
        check("a.local@18444（仅1.2）→ port-tls12", r.get("ok") and body_is(r, "port-tls12"), f"{r}")
        r = tls_request(P13, "a.local", version="1.3")
        check("a.local@18445（仅1.3）→ port-tls13", r.get("ok") and body_is(r, "port-tls13"), f"{r}")
        r = plain_request(PPLAIN, "a.local")
        check("a.local@18446（明文）→ port-plain", r.get("ok") and body_is(r, "port-plain"), f"{r}")
        r = plain_request(PPLAIN, "b.local")
        check("b.local@18446（该端口无 b vhost）→ 回落 port-plain",
              r.get("ok") and body_is(r, "port-plain"), f"{r}")
        r = tls_request(PH2, "a.local", alpn=["http/1.1"])
        check("a.local@18447（h2 端口、客户端只要 1.1）→ port-h2",
              r.get("ok") and body_is(r, "port-h2") and r.get("alpn") == "http/1.1", f"{r}")
        r = tls_request(P12, "b.local", version="1.2")
        check("b.local@18444（该端口无 b vhost）→ 回落 port-tls12",
              r.get("ok") and body_is(r, "port-tls12") and r.get("fp") == fps["a"], f"{r}")

        # ========== 5) TLS 版本与密码套件 ==========
        print("\n-- 5) TLS 版本裁剪与密码套件 --")
        r = tls_request(SNI_PORT, "a.local", version="1.2")
        check("18443：TLS1.2 可协商", r.get("ok") and r.get("ver") == "TLSv1.2", f"{r}")
        check("18443：TLS1.2 套件为 ECDHE",
              bool(r.get("cipher")) and "ECDHE" in r.get("cipher", ""), f"cipher={r.get('cipher')}")
        r = tls_request(SNI_PORT, "a.local", version="1.3")
        check("18443：TLS1.3 可协商", r.get("ok") and r.get("ver") == "TLSv1.3", f"{r}")
        check("18443：TLS1.3 套件为 TLS_*",
              bool(r.get("cipher")) and r.get("cipher", "").startswith("TLS_"), f"cipher={r.get('cipher')}")

        r = tls_request(P12, "a.local", version="1.2")
        check("18444：TLS1.2 成功", r.get("ok") and r.get("ver") == "TLSv1.2", f"{r}")
        r = tls_request(P12, "a.local", version="1.3")
        check("18444：仅 TLS1.3 的客户端被拒绝",
              not r.get("ok") and r.get("phase") == "handshake", f"{r}")
        r = tls_request(P13, "a.local", version="1.3")
        check("18445：TLS1.3 成功", r.get("ok") and r.get("ver") == "TLSv1.3", f"{r}")
        r = tls_request(P13, "a.local", version="1.2")
        check("18445：仅 TLS1.2 的客户端被拒绝",
              not r.get("ok") and r.get("phase") == "handshake", f"{r}")

        # openssl s_client 独立取证（不复用 Python 的 ssl 结论）
        o = openssl_probe(SNI_PORT, "a.local", "-tls1_3", alpn="h2,http/1.1")
        check("openssl s_client：18443 协商 TLS1.3 + TLS_* 套件",
              o["rc"] == 0 and o["proto"] == "TLSv1.3" and (o["cipher"] or "").startswith("TLS_"),
              f"rc={o['rc']} proto={o['proto']} cipher={o['cipher']} tail={o['text'][-300:]}")
        check("openssl s_client：18443 ALPN 回落 http/1.1（未开 h2）",
              o["alpn"] == "http/1.1", f"alpn={o['alpn']}")
        o = openssl_probe(SNI_PORT, "a.local", "-tls1_2")
        check("openssl s_client：18443 协商 TLS1.2 + ECDHE 套件",
              o["rc"] == 0 and o["proto"] == "TLSv1.2" and "ECDHE" in (o["cipher"] or ""),
              f"rc={o['rc']} proto={o['proto']} cipher={o['cipher']}")
        o = openssl_probe(P12, "a.local", "-tls1_3")
        check("openssl s_client：18444 拒绝 TLS1.3",
              o["rc"] != 0 or o["proto"] is None,
              f"rc={o['rc']} proto={o['proto']}")
        o = openssl_probe(PH2, "a.local", "-tls1_3", alpn="h2,http/1.1")
        check("openssl s_client：18447 协商 h2",
              o["rc"] == 0 and o["alpn"] == "h2", f"rc={o['rc']} alpn={o['alpn']}")

        # ========== 6) ALPN ==========
        print("\n-- 6) ALPN 协商 --")
        alpn_cases = [
            (SNI_PORT, ["h2", "http/1.1"], "http/1.1", "未开 h2 的端口回落到 http/1.1"),
            (PH2, ["h2", "http/1.1"], "h2", "h2 端口优先 h2"),
            (PH2, ["http/1.1"], "http/1.1", "h2 端口兼容 1.1"),
            (PH2, None, None, "客户端不提 ALPN 则不协商"),
        ]
        for port, offer, want, why in alpn_cases:
            # 只为看 ALPN 结果，不在这条连接上发 HTTP/1.1 字节：
            # 协商到 h2 后发 h1 文本会让服务端按 h2 帧解析而报错。
            r = tls_request(port, "a.local", alpn=offer, request=False)
            check(f"ALPN offer={offer} @{port} → {want}（{why}）",
                  r.get("ok") and r.get("alpn") == want,
                  f"ok={r.get('ok')} alpn={r.get('alpn')} err={r.get('err')}")

        # 客户端与端口没有共同 ALPN 时：nginx/OpenSSL 会继续握手、不选协议；
        # rustls 默认发 no_application_protocol fatal alert。业务上少见（浏览器都带 h1 兜底），
        # 但属于可观测的行为差异，单独记录。
        r = tls_request(SNI_PORT, "a.local", alpn=["h2"], request=False)
        if r.get("ok") and r.get("alpn") is None:
            check("ALPN 无交集 @18443 → 继续握手但不选协议（nginx 语义）", True)
        elif not r.get("ok"):
            gap("ALPN 无交集时 rustls 直接中止握手",
                f"客户端只提供 h2、18443 只支持 http/1.1 → {r.get('err')}；"
                f"nginx/OpenSSL 会继续 HTTP/1.1（不协商 ALPN）")
        else:
            check("ALPN 无交集 @18443 → 不选协议", False, f"{r}")

        if NODE:
            kv = node_h2(f"https://{HOST}:{PH2}", "a.local", "a.local")
            check("Node h2：真实 HTTP/2 请求成功",
                  kv.get("STATUS") == "200" and kv.get("BODY") == "port-h2" and kv.get("ALPN") == "h2",
                  f"probe={kv}")
            check("Node h2：SNI=a.local 拿到 a 证书",
                  kv.get("PEER_SHA256") == fps["a"],
                  f"fp={str(kv.get('PEER_SHA256'))[:16]} want={fps['a'][:16]}")
            kv = node_h2(f"https://{HOST}:{PH2}", "b.local", "a.local")
            check("Node h2：SNI=b.local（端口只有 a 证书）+ Host=a.local → 仍 200，证书为默认 a",
                  kv.get("STATUS") == "200" and kv.get("BODY") == "port-h2"
                  and kv.get("PEER_SHA256") == fps["a"], f"probe={kv}")
        else:
            gap("Node h2 真实请求", "node 不在 PATH 上，跳过功能性 h2 请求")

        # ========== 6b) 同一 TLS 端口 + ALPN h2 + 多域名 vhost ==========
        # h2 没有 Host 头：站名只能从 :authority 取。这里三种情形都要对上：
        # 具名站各归各、未知域名落到 default_server、SNI 与 authority 不一致时以
        # authority 决定 vhost（内容）而证书由 SNI 决定 —— 两条都是 nginx 的行为。
        if NODE:
            for name, want_body, want_fp in (
                ("a.local", "vhost-a", fps["a"]),
                ("www.a.local", "vhost-a", fps["a"]),
                ("b.local", "vhost-b", fps["b"]),
                ("nobody.local", "vhost-default", fps["default"]),
            ):
                kv = node_h2(f"https://{HOST}:{PHMH}", name, name)
                check(f"同端口 h2 + SNI/authority={name} → {want_body}",
                      kv.get("STATUS") == "200" and kv.get("BODY", "").strip() == want_body
                      and kv.get("ALPN") == "h2",
                      f"probe={kv}")
                check(f"同端口 h2 + authority={name} → 证书为 {want_body}",
                      kv.get("PEER_SHA256") == want_fp,
                      f"fp={str(kv.get('PEER_SHA256'))[:16]} want={want_fp[:16]}")
            kv = node_h2(f"https://{HOST}:{PHMH}", "a.local", "b.local")
            check("同端口 h2：SNI=a.local 但 :authority=b.local → 站按 authority 选、证书按 SNI 选",
                  kv.get("STATUS") == "200" and kv.get("BODY", "").strip() == "vhost-b"
                  and kv.get("PEER_SHA256") == fps["a"],
                  f"probe={kv}")
        else:
            gap("同端口 h2 多域名", "node 不在 PATH 上，跳过 h2 vhost 断言")

        # ========== 7) 会话复用现状 ==========
        print("\n-- 7) 会话复用（TLS session resumption） --")

        def probe_resumption(v, src_port, dst_port):
            """同一 SSLContext 先建会话，再拿它连 dst_port，返回是否复用。
            同端口成功 = rustls 内存态 session storage 生效；
            跨端口成功 = 两个监听端口共享会话缓存（nginx shared 缓存语义）。"""
            out = {"session": "none", "reused": False, "ticket": None, "err": None}
            s1 = None
            s2 = None
            try:
                # 同一个 SSLContext：Python 拒绝使用来自别的 context 的 session
                ctx = make_ctx(v)
                s1 = ctx.wrap_socket(socket.create_connection((HOST, src_port), timeout=8),
                                     server_hostname="a.local")
                s1.sendall(b"GET / HTTP/1.1\r\nHost: a.local\r\nConnection: close\r\n\r\n")
                read_http_response(s1, 8)
                sess = s1.session
                out["session"] = "present" if sess is not None else "none"
                out["ticket"] = getattr(sess, "has_ticket", None) if sess is not None else None
                s1.close()
                s1 = None
                if sess is None:
                    return out
                s2 = ctx.wrap_socket(socket.create_connection((HOST, dst_port), timeout=8),
                                     server_hostname="a.local", session=sess)
                out["reused"] = bool(s2.session_reused)
                out["ver"] = s2.version()
                s2.close()
                s2 = None
            except Exception as e:
                out["err"] = f"{type(e).__name__}: {e}"
            finally:
                for sk in (s1, s2):
                    if sk is not None:
                        try:
                            sk.close()
                        except Exception:
                            pass
            return out

        # 同端口：TLS1.2 用 session ID，TLS1.3 用 rustls 的内存态 ticket；都应复用
        for ver, port in (("1.2", P12), ("1.3", P13)):
            r = probe_resumption(ver, port, port)
            check(f"TLS{ver} 同端口会话复用生效", r["reused"],
                  f"session={r['session']} has_ticket={r['ticket']} reused={r['reused']} "
                  f"err={r['err']}")

        # openssl 独立取证：sess_out 写出会话，第二次 sess_in 应显示 Reused。
        # s_client 要等到 NewSessionTicket（TLS1.3）才有会话文件，所以保持 stdin 1 秒再关。
        def openssl_resumption(v):
            d = tempfile.mkdtemp(prefix="orr_https_matrix_")
            sf = os.path.join(d, "sess.pem")
            varg = "-tls1_3" if v == "1.3" else "-tls1_2"

            def run(extra):
                cmd = [OPENSSL, "s_client", "-connect", f"{HOST}:{SNI_PORT}",
                       "-servername", "a.local", varg, *extra]
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
                time.sleep(1.0)
                out, _ = p.communicate(input=b"", timeout=15)
                return out.decode("utf-8", "replace")

            t1 = run(["-sess_out", sf])
            t2 = run(["-sess_in", sf]) if os.path.exists(sf) else ""
            first_new = bool(re.search(r"^New,", t1, re.M))
            second_reused = bool(re.search(r"^Reused,", t2, re.M))
            size = os.path.getsize(sf) if os.path.exists(sf) else 0
            try:
                os.remove(sf)
                os.rmdir(d)
            except OSError:
                pass
            return first_new, second_reused, size

        for ver in ("1.2", "1.3"):
            first_new, reused, size = openssl_resumption(ver)
            check(f"openssl：TLS{ver} 会话文件生成且第二次握手复用",
                  first_new and reused and size > 0,
                  f"first_new={first_new} second_reused={reused} sess_bytes={size}")

        # 跨端口：默认 ssl_session_tickets on，ticket 密钥整进程一份 →
        # 在一个端口建立的会话可以在另一个端口无状态恢复。
        # （若显式 `ssl_session_tickets off` + `builtin`，缓存按监听隔离，跨端口不复用；
        #   该矩阵见 tools/tls_session_e2e.py）
        for ver, src in (("1.2", P12), ("1.3", P13)):
            r = probe_resumption(ver, src, SNI_PORT)
            check(f"TLS{ver} 会话跨监听端口恢复（默认共享 ticket 密钥）",
                  r["reused"],
                  f"在 {src} 建立的会话到 {SNI_PORT} 复用失败 (reused={r['reused']} "
                  f"session={r['session']} err={r['err']})")

        # ========== 8) 并发混合流量 ==========
        print("\n-- 8) 并发混合流量（多域名 × 多端口 × 双版本） --")
        mix = [
            dict(port=SNI_PORT, sni="a.local", host="a.local", ver="1.2",
                 body="vhost-a", fp="a"),
            dict(port=SNI_PORT, sni="b.local", host="b.local", ver="1.3",
                 body="vhost-b", fp="b"),
            dict(port=SNI_PORT, sni="x.wild.local", host="a.local", ver="1.3",
                 body="vhost-a", fp="wild"),
            dict(port=SNI_PORT, sni="api.wild.local", host="unknown.local", ver="1.2",
                 body="vhost-default", fp="api"),
            dict(port=P12, sni="a.local", host="a.local", ver="1.2",
                 body="port-tls12", fp="a"),
            dict(port=P13, sni="a.local", host="a.local", ver="1.3",
                 body="port-tls13", fp="a"),
            dict(port=PH2, sni="a.local", host="a.local", ver=None,
                 body="port-h2", fp="a"),
            dict(port=PPLAIN, sni=None, host="a.local", ver=None,
                 body="port-plain", fp=None),
        ]
        random.seed(20261018)

        def mixed_worker(_):
            errs = []
            for _ in range(60):
                sc = random.choice(mix)
                if sc["port"] == PPLAIN:
                    r = plain_request(PPLAIN, sc["host"])
                    ok = r.get("ok") and body_is(r, sc["body"])
                else:
                    r = tls_request(sc["port"], sc["sni"], host=sc["host"],
                                    version=sc["ver"], alpn=["http/1.1"] if sc["port"] == PH2 else None)
                    ok = (r.get("ok") and body_is(r, sc["body"])
                          and (sc["fp"] is None or r.get("fp") == fps[sc["fp"]]))
                    if sc["ver"] and r.get("ok"):
                        ok = ok and r.get("ver") == ("TLSv1.2" if sc["ver"] == "1.2" else "TLSv1.3")
                if not ok:
                    errs.append(f"{sc} -> {r}")
            return errs

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            all_errs = [e for chunk in ex.map(mixed_worker, range(8)) for e in chunk]
        check("混合流量 480 请求 0 错误", not all_errs,
              f"errors={len(all_errs)} first={all_errs[:2]}")

        # ========== 9) 握手 / 新建连接性能 ==========
        print("\n-- 9) 握手与新建连接性能（8 线程，本机回环） --")
        print("  注：p90/p99 受 Python 线程与 Windows 调度影响，重点看 p50 与 errs=0")
        h12 = bench_connections(SNI_PORT, "1.2", "handshake")
        h13 = bench_connections(SNI_PORT, "1.3", "handshake")
        tcp = bench_connections(PPLAIN, None, "handshake")
        r12 = bench_connections(SNI_PORT, "1.2", "request", per_thread=100)
        r13 = bench_connections(SNI_PORT, "1.3", "request", per_thread=100)
        rpl = bench_connections(PPLAIN, None, "request", per_thread=100)
        print_bench("TLS1.3 握手", h13)
        print_bench("TLS1.2 握手", h12)
        print_bench("TCP connect（参照）", tcp)
        print_bench("TLS1.3 新建连接+GET", r13)
        print_bench("TLS1.2 新建连接+GET", r12)
        print_bench("明文 新建连接+GET", rpl)
        check("握手压测 0 错误", h13["errs"] == 0 and h12["errs"] == 0 and tcp["errs"] == 0,
              f"errs={h13['errs']}/{h12['errs']}/{tcp['errs']}")
        check("新建连接请求压测 0 错误", r13["errs"] == 0 and r12["errs"] == 0 and rpl["errs"] == 0,
              f"errs={r13['errs']}/{r12['errs']}/{rpl['errs']}")
        if h12["p50"] > 0:
            print(f"  参考：TLS1.3 握手 p50 / TLS1.2 握手 p50 = "
                  f"{h13['p50'] / h12['p50']:.2f}x；TLS1.3 建连请求速率 / 明文 = "
                  f"{r13['ops'] / rpl['ops'] if rpl['ops'] else 0:.2f}x")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== HTTPS 业务矩阵 E2E: {passed}/{total} passed, {len(gaps)} gaps ====")
    if gaps:
        print("GAP 明细：")
        for name, detail in gaps:
            print(f"  - {name}: {detail}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
