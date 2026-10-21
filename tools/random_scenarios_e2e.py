# -*- coding: utf-8 -*-
"""随机场景 E2E —— 不是"用例"，是每轮随机生成拓扑 + 路由 + 证书绑定，然后用**独立实现的
nginx 语义 oracle** 算出"该落哪一站 / 该命中哪个 location / 该发哪张证书 / 该打哪个后端"，
再拿真实流量（h1 + h2 + L4 裸 TCP + ssl_preread）比对。

    cargo build --release -p onrouter-server --bin onrouter
    python tools/random_scenarios_e2e.py                 # 默认 4 轮，随机种子
    python tools/random_scenarios_e2e.py --seed 7 --iters 12 --keep

设计上的三个刻意选择：

1. **oracle 不复用网关的任何代码**：站点选择（精确 > 通配 > default_server > 列表第一个）、
   location 匹配（`=` 精确 → 最长前缀 → `^~` 截断 → 按序正则 → 回落最长前缀）、rewrite ... last
   后重新匹配、未匹配路径落到 `location /` 兜底 —— 全部在 Python 里按 nginx 文档重写一遍。
   两边不一致就是 bug 或者文档误读，两边都有价值。
2. **每一站都能被区分**：站名写进所有响应体（`<station>|<route-tag>`），代理路线再额外用
   `add_header X-Route` 标出是哪条 location 执行的，后端回 `be<k>-<次数>`。于是"串站"、
   "串路由"、"串后端"三类错误互不混淆，也不会被同一个 200 掩盖。
3. **证书按 SNI、站点按 :authority** 是两条独立断言（v1.0.1 修掉的 h2 串站 bug 正是只验证书
   没验站点导致的漏网）；h2 探针复用 tools/https_matrix_h2.js，可以把 SNI 与 authority 分开传。

UDP 不在这套里：本项目的四层 `stream{}` 目前只有 TCP（UDP 只有 Lua cosocket 侧），
所以"游戏服务器转发"这一维覆盖的是多端口 TCP 聚合 + SNI 预读分流。
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
H2_JS = os.path.join(HERE, "https_matrix_h2.js")
CERT_DIR = os.path.join(ROOT, "certs_random")
LOG_DIR = os.path.join(ROOT, "logs")
OUT_CONF = os.path.join(ROOT, "conf", "random_scenarios.conf")

BE_PORTS = [18741, 18742, 18743, 18744]          # L7 具名后端（回 "be<k>-<n>"）
L4_PORTS = [18751, 18752, 18753, 18754]          # L4 TLS echo 后端（ssl_preread 的落点）
L4_PLAIN_PORT = 18755                              # 纯 TCP 聚合端口的明文后端
GW_HTTP = 18711
GW_TLS_PORTS = [18710, 18712, 18713]             # 18710 恒为多站共享；其余按随机拓扑用
GW_L4 = 18720                                     # stream: ssl_preread + sni_match
GW_L4_PLAIN = 18721                               # stream: 纯 TCP 聚合端口

STATIONS = [
    ("a.test", "a"), ("b.test", "b"), ("c.test", "c"), ("d.test", "d"),
    ("x.w.test", "wildx"), ("y.w.test", "wily"), ("z.w.test", "wildz"),
]
WILDCARD_CERTS = [("*.w.test", "wildcard")]
HTTP_LOCK = threading.Lock()
HTTP_HITS = {}
L4_LOCK = threading.Lock()
L4_HITS = {}
results = {"pass": 0, "fail": 0, "cases": []}


def check(name, ok, detail=""):
    if ok:
        results["pass"] += 1
    else:
        results["fail"] += 1
        results["cases"].append(f"FAIL {name} {detail}")
        print("FAIL", name, detail[:400])


# ---------------------------------------------------------------- 证书夹具
def ensure_certs():
    os.makedirs(CERT_DIR, exist_ok=True)
    have = {n for _, n in STATIONS} | {n for _, n in WILDCARD_CERTS} | {"fallback"}
    for name in have:
        pem = os.path.join(CERT_DIR, f"{name}.pem")
        if os.path.exists(pem):
            continue
        cn = name if name == "wildcard" else f"{name}.test"
        subj = "/CN=*.w.test" if name == "wildcard" else f"/CN={cn}"
        san = "DNS:*.w.test" if name == "wildcard" else f"DNS:{cn},DNS:www.{cn}"
        cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
               "-keyout", os.path.join(CERT_DIR, f"{name}.key"),
               "-out", pem, "-days", "3", "-subj", subj,
               "-addext", f"subjectAltName={san}"]
        p = subprocess.run(cmd, capture_output=True)
        if p.returncode != 0:
            raise SystemExit("!! openssl 生成证书夹具失败: " + p.stderr.decode("utf-8", "replace")[:300])


def cert_fp(name):
    with open(os.path.join(CERT_DIR, f"{name}.pem"), encoding="ascii") as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


# ---------------------------------------------------------------- 随机拓扑生成
class Plan:
    """一轮场景：端口 → 站列表；站 → location 列表。同时是 oracle 的数据源。"""

    def __init__(self, rng):
        self.rng = rng
        self.ports = {}          # port -> {"tls": bool, "h2": bool, "servers": [station]}
        self.stations = {}       # station name -> dict(cert, locs, catch_all)
        self.lines = []
        self.backends = {}       # route key -> backend index
        self.stream_sni = []     # [(pattern, port)]
        self.stream_default = rng.choice(L4_PORTS)
        self.notes = []

    def build(self):
        rng = self.rng
        names = [n for n, _ in STATIONS]
        # --- 多站共享 TLS 端口（18710）：2~5 站，default_server 位置随机
        pool = names[:]
        rng.shuffle(pool)
        shared = pool[: rng.randint(2, 5)]
        cert_of = dict(STATIONS)
        servers = []
        if rng.random() < 0.7:
            servers.append("fallback")
        servers += shared
        if rng.random() < 0.5:                     # 有时把兜底站放到列表末尾
            servers = shared + (["fallback"] if "fallback" in servers else [])
        self.ports[GW_TLS_PORTS[0]] = {"tls": True, "h2": rng.random() < 0.8, "servers": servers}
        # --- 一个多站明文端口，验证没有 TLS 时同样的选站规则
        plain = [s for s in pool[5:8]] or [names[0]]
        self.ports[GW_HTTP] = {"tls": False, "h2": False, "servers": plain}
        # --- 单站端口（多端口聚合）
        extra = pool[8:10] if len(pool) > 9 else [names[1]]
        for i, st in enumerate(extra):
            self.ports[GW_TLS_PORTS[1 + i]] = {"tls": True, "h2": True, "servers": [st]}
        # --- 每站的 location 集合
        for port, cfg in self.ports.items():
            for st in cfg["servers"]:
                if st in self.stations:
                    continue
                self.stations[st] = self.make_station(st, cfg["tls"], cert_of.get(st, "fallback"))
        # --- L4：sni_match 精确 + 通配 + 兜底
        chosen = rng.sample(L4_PORTS, rng.randint(2, len(L4_PORTS)))
        # pattern 必须唯一：同一个 SNI 写两条时网关按配置顺序取第一条，而预言机是逐条比对的，
        # 第二条就会拿到"错误"的端口（重复本身不是被禁止的写法，是这一轮的预言机判不了它）。
        used = set()

        def add_sni_rule(pat, port):
            if pat.lower() not in used:
                used.add(pat.lower())
                self.stream_sni.append((pat, port))

        add_sni_rule(chosen[0] == L4_PORTS[0] and "*.w.test" or f"{names[0]}", chosen[0])
        for p in chosen[1:]:
            add_sni_rule(f"{rng.choice(names)}", p)
        if rng.random() < 0.6:
            self.stream_sni = [("*" if pat == "*.w.test" else pat, port) for pat, port in self.stream_sni]
        self.emit()
        return self

    def make_station(self, name, tls, cert):
        rng = self.rng
        locs = []
        for i in range(rng.randint(2, 5)):
            kind = rng.choice(["exact", "pprefix", "prefix", "regex", "rewrite", "proxycache"])
            tag = f"{name}#{kind}{i}"
            path = f"/{kind}/{i}"
            locs.append(self.make_loc(kind, path, tag, name))
        locs.append({"modifier": "prefix", "pattern": "/",
                     "action": ("return", 404, f"{name}|nofile")})
        # 别名在这里定，不在 emit 里掷骰子：oracle 与配置必须读同一份事实
        aliases = [name] + (["www." + name] if rng.random() < 0.4 else [])
        return {"cert": cert, "tls": tls, "locs": locs, "aliases": aliases}

    def make_loc(self, kind, path, tag, name):
        rng = self.rng
        if kind == "exact":
            return {"modifier": "=", "pattern": path,
                    "action": ("return", rng.choice([200, 404, 418]), f"{name}|{tag}")}
        if kind == "regex":
            return {"modifier": "~*", "pattern": f"^{path}/[0-9a-f]+$",
                    "action": ("return", 200, f"{name}|{tag}")}
        be = rng.randrange(len(BE_PORTS))
        self.backends[tag] = be
        if kind == "pprefix":
            return {"modifier": "^~", "pattern": path, "action": ("proxy", be, tag)}
        if kind == "proxycache":
            return {"modifier": "prefix", "pattern": path, "action": ("proxy", be, tag), "cache": tag}
        if kind == "rewrite":
            return {"modifier": "prefix", "pattern": path,
                    "action": ("rewrite", f"^{path}/(.*)$", f"/rt/{name}/$1", "last")}
        return {"modifier": "prefix", "pattern": path, "action": ("proxy", be, tag)}

    def emit(self):
        L = self.lines.append
        L("# 由 tools/random_scenarios_e2e.py 生成，不要手改")
        L('error_log "logs/random_scen_err.log" info;')
        L("pid logs/random_scen.pid;")
        for tag in sorted({t for s in self.stations.values() for t in [x["action"][-1] if x["action"][0] == "proxy" else None for x in s["locs"]] if t}):
            pass
        L("proxy_cache_path logs/random_cache keys_zone=rc:2m;")
        L("upstream lb0 { server 127.0.0.1:%d; }" % BE_PORTS[0])
        for i, p in enumerate(BE_PORTS[1:], 1):
            L("upstream lb%d { server 127.0.0.1:%d; }" % (i, p))
        L("stream {")
        L("    server {")
        L(f"        listen {GW_L4};")
        L("        ssl_preread on;")
        for j, (pat, port) in enumerate(self.stream_sni):
            L(f"        sni_match \"{pat}\" 127.0.0.1:{port};")
        L(f"        proxy_pass 127.0.0.1:{self.stream_default};")
        L("    }")
        L("    server {")
        L(f"        listen {GW_L4_PLAIN};")
        L(f"        proxy_pass 127.0.0.1:{L4_PLAIN_PORT};")
        L("    }")
        L("}")
        for port, cfg in sorted(self.ports.items()):
            for st in cfg["servers"]:
                info = self.stations[st]
                L("server {")
                tls_part = f" listen {port}{' ssl' if cfg['tls'] else ''}{' http2' if cfg.get('h2') else ''};"
                if st == "fallback":
                    tls_part = tls_part[:-1] + " default_server;"
                L("   " + tls_part)
                if st == "fallback":
                    L("    server_name _;")
                    L(f"    ssl_certificate \"../certs_random/fallback.pem\";" if cfg["tls"] else "", )
                    L(f"    ssl_certificate_key \"../certs_random/fallback.key\";" if cfg["tls"] else "")
                else:
                    names = " ".join(info["aliases"])
                    L(f"    server_name {names};")
                    L(f"    ssl_certificate \"../certs_random/{info['cert']}.pem\";" if cfg["tls"] else "")
                    L(f"    ssl_certificate_key \"../certs_random/{info['cert']}.key\";" if cfg["tls"] else "")
                    L(f"    set $station {st};")
                    L("    add_header X-Station $station;")
                    if self.rng.random() < 0.5:
                        L("    if ($arg_block) {")
                        L(f'        return 451 "blocked@{st}";')
                        L("    }")
                L('    location /rt/ { return 200 "%s|rewrite-target\\n"; }' % st)
                for loc in info["locs"]:
                    emit_loc(L, loc, cfg["tls"])
                L("}")
            L("")


def emit_loc(L, loc, tls):
    mod = {"prefix": "", "=": "= ", "^~": "^~ ", "~*": "~* "}[loc["modifier"]]
    L(f'    location {mod}{loc["pattern"]} {{')
    act = loc["action"]
    if act[0] == "return":
        L(f'        return {act[1]} "{act[2]}\\n";')
    elif act[0] == "rewrite":
        L(f'        rewrite {act[1]} {act[2]} {act[3]};')
        L('        return 404 "should-not-fall-through\\n";')
    else:
        L(f"        proxy_pass http://lb{act[1]};")
        L(f'        add_header X-Route "{act[2]}";')
        if loc.get("cache"):
            L("        proxy_cache rc;")
            L("        proxy_cache_valid 200 30s;")
    L("    }")


def rng_pick(rng, seq):
    return rng.choice(seq)


# ---------------------------------------------------------------- 后端
def start_http_backends():
    class H(BaseHTTPRequestHandler):
        tag = "be?"

        def do_GET(self):
            with HTTP_LOCK:
                HTTP_HITS[self.tag] = HTTP_HITS.get(self.tag, 0) + 1
                n = HTTP_HITS[self.tag]
            body = f"{self.tag}-{n}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    for i, p in enumerate(BE_PORTS):
        cls = type(f"BE{i}", (H,), {"tag": f"be{i}"})
        s = HTTPServer(("127.0.0.1", p), cls)
        threading.Thread(target=s.serve_forever, daemon=True).start()


def start_l4_backends():
    """L4 落点是真正的 TLS 后端：`ssl_preread` 不终结 TLS，握手是客户端与后端之间端到端的事。
    这里是明文 echo 的话，探针一发 ClientHello 就得到 WRONG_VERSION_NUMBER，红的是夹具本身。"""
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(os.path.join(CERT_DIR, "fallback.pem"),
                            os.path.join(CERT_DIR, "fallback.key"))

    def serve(port, tag):
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sv.bind(("127.0.0.1", port))
        sv.listen(16)
        while True:
            try:
                c, _ = sv.accept()
            except OSError:
                return
            try:
                w = srv_ctx.wrap_socket(c, server_side=True)
            except OSError:
                c.close()
                continue
            with L4_LOCK:
                L4_HITS[tag] = L4_HITS.get(tag, 0) + 1
            data = w.recv(256)
            w.sendall(f"{tag}:{data.decode('utf-8', 'replace').strip()}\n".encode())
            w.close()

    for i, p in enumerate(L4_PORTS):
        threading.Thread(target=serve, args=(p, f"l4{i}"), daemon=True).start()

    def serve_plain():
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sv.bind(("127.0.0.1", L4_PLAIN_PORT))
        sv.listen(16)
        while True:
            try:
                c, _ = sv.accept()
            except OSError:
                return
            data = c.recv(256)
            c.sendall(b"plain:" + data)
            c.close()

    threading.Thread(target=serve_plain, daemon=True).start()


# ---------------------------------------------------------------- oracle
def pick_station(server_names_by_port, port, authority, stations=None):
    """精确 > 通配（一级子域）> default_server（在 servers 里用 'fallback' 表示）> 第一个"""
    servers = server_names_by_port[port]
    stations = stations or {}
    host = (authority or "").split(":")[0].lower()
    exact = [s for s in servers if s != "fallback" and host in station_aliases(s, stations)]
    if exact:
        return exact[0]
    wild = [s for s in servers if s != "fallback" and any(
        host.endswith("." + suf) and len(host) > len(suf) + 1
        for suf in wildcard_suffixes(s))]
    if wild:
        return wild[0]
    return "fallback" if "fallback" in servers else servers[0]


def station_aliases(st, stations):
    """站点实际声明的 server_name 列表。曾经这里是硬编码 {st, www.st}，
    而生成器只有 40% 概率写出 www.<st>——于是预言机把一半探针判给了错误的站点，
    报出来的是"网关选错 vhost"，实际是它自己记错了配置。"""
    info = stations.get(st) or {}
    return set(info.get("aliases") or [st])


def wildcard_suffixes(st):
    # 生成器里没用通配站名（通配只在 L4 的 sni_match 上），保留接口以便扩展
    return []


def sni_rule_matches(pat, sni):
    """对齐 stream.rs::sni_pattern_matches：精确名大小写不敏感；`*.s` 只吃**恰好一级**子域
    （`a.e.com` 命中 `*.e.com`，`e.com` 和 `x.y.e.com` 都不命中）；单独的 `*` 不是全匹配，
    它只是一个精确名。L4 预言机按声明顺序取第一条命中的规则。"""
    p, n = pat.lower(), sni.lower()
    if p.startswith("*."):
        suffix = "." + p[2:]
        if not n.endswith(suffix):
            return False
        prefix = n[:len(n) - len(suffix)]
        return bool(prefix) and "." not in prefix
    return n == p


def pick_location(locs, path):
    """nginx：`=` 精确 → 最长前缀记下 → `^~` 命中即停 → 按序正则 → 回落记下的最长前缀"""
    best, best_len = None, -1
    for loc in locs:
        if loc["modifier"] != "=":
            continue
        if path == loc["pattern"]:
            best, best_len = loc, len(loc["pattern"]) + 1000
            break
    longest = None
    llen = -1
    for loc in locs:
        if loc["modifier"] in ("prefix", "^~") and path.startswith(loc["pattern"]):
            if len(loc["pattern"]) > llen:
                longest, llen = loc, len(loc["pattern"])
    if best:
        return best
    if longest and longest["modifier"] == "^~":
        return longest
    for loc in locs:
        if loc["modifier"] == "~*" and re.match(loc["pattern"], path, re.I):
            return loc
    return longest or {"modifier": "prefix", "pattern": "/", "action": ("return", 404, "unmatched")}


def expect_for(plan, port, authority, path):
    """Host/:authority → 哪个站应答、命中哪个 location。**这里不含证书**：
    证书由 SNI 在握手期决定，与 Host 选站是两件事（旧预言机把它们记成一件，
    于是同一端口多站时证书断言成片红，报出来的却是"网关选错站"）。"""
    st = pick_station(plan_ports(plan), port, authority, plan.stations)
    if st == "fallback" and "fallback" not in plan.ports[port]["servers"]:
        return None
    info = plan.stations.get(st)
    if info is None:
        return {"station": st, "status": 404,
                "body": st + "|nofile\n", "route": None}
    loc = pick_location(info["locs"], path)
    act = loc["action"]
    if act[0] == "return":
        return {"station": st, "status": act[1], "body": act[2] + "\n", "route": None}
    if act[0] == "rewrite":
        target = re.sub(act[1], act[2], path)
        return {"station": st, "status": 200,
                "body": f"{st}|rewrite-target\n", "route": None, "rewritten": target}
    return {"station": st, "status": 200, "backend": f"be{act[1]}",
            "route": act[2], "body": None, "cache": bool(loc.get("cache"))}


def pick_cert(plan, port, sni):
    """SNI → 该端口上哪张证书：精确 server_name > 通配 > 该端口的默认 server。
    默认 server = 写了 `default_server` 的那个块；没写则是配置顺序第一个（nginx 同）。
    证书选择在握手期完成，此时还没有 Host，所以**不能**用选站结果反推证书。"""
    servers = plan.ports[port]["servers"]
    host = (sni or "").split(":")[0].lower()
    if host:
        for s in servers:
            if s == "fallback":
                continue
            if host in station_aliases(s, plan.stations):
                return plan.stations[s]["cert"]
        for s in servers:
            if s == "fallback":
                continue
            if any(host.endswith("." + suf) and len(host) > len(suf) + 1
                   for suf in wildcard_suffixes(s)):
                return plan.stations[s]["cert"]
    default = "fallback" if "fallback" in servers else servers[0]
    return plan.stations[default]["cert"]


def st_in_plan(plan, st):
    return st in plan.stations


def plan_ports(plan):
    return {p: c["servers"] for p, c in plan.ports.items()}


# ---------------------------------------------------------------- 客户端
def h1(port, host, path, tls=True, timeout=8):
    ctx = ssl._create_unverified_context() if tls else None
    ctx = ctx or None
    try:
        conn = http_connect(port, host, tls, ctx)
        # skip_host=True：默认那条 Host 是 127.0.0.1:端口，会和下面显式写的 Host 组成
        # 两条 Host 头。RFC 9112 只允许一条，网关现在按 400 拒掉——探针必须发得合法。
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        conn.endheaders()
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in r.getheaders()}
        fp = peer_fp(conn) if tls else None
        conn.close()
        return r.status, body, headers, fp
    except Exception as e:  # noqa: BLE001
        return None, f"error:{e}", {}, None


def http_connect(port, host, tls, ctx):
    import http.client

    if tls:
        # 显式控制 SNI：不能用 HTTPSConnection("127.0.0.1", port)，那会把 SNI 写成 IP，
        # 网关按"匹配不到"回落默认证书，而预言机以为探针发的是 host —— 报出来的就成了
        # "证书指纹不对"。先自己 wrap 出带 SNI 的 socket，再交给 http.client 走 HTTP。
        raw = socket.create_connection(("127.0.0.1", port), timeout=8)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.sock = ctx.wrap_socket(raw, server_hostname=host)
        return c
    return http.client.HTTPConnection("127.0.0.1", port, timeout=8)


def peer_fp(conn):
    der = conn.sock.getpeercert(True)
    return hashlib.sha256(der).hexdigest() if der else None


def h2_probe(port, sni, authority, path):
    """SNI 与 :authority 分开传：证书按 SNI、站点按 authority，两条断言互不掩盖。"""
    if not shutil.which("node"):
        return None
    p = subprocess.run(["node", H2_JS, f"https://127.0.0.1:{port}/", sni or "", authority or "", path],
                       capture_output=True, text=True, timeout=30, cwd=HERE)
    out = {}
    for line in (p.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def l4_probe(port, payload):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.sendall(payload.encode())
    try:
        data = s.recv(256)
    except socket.timeout:
        data = b""
    s.close()
    return data.decode("utf-8", "replace").strip()


def tls_probe(port, sni):
    ctx = ssl._create_unverified_context()
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    try:
        w = ctx.wrap_socket(s, server_hostname=sni)
        der = w.getpeercert(True)
        alpn = w.selected_alpn_protocol()
        w.close()
        return (hashlib.sha256(der).hexdigest() if der else None), alpn
    except Exception as e:  # noqa: BLE001
        return None, f"error:{e}"
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 一轮
def run_iteration(seed, verbose=False):
    rng = random.Random(seed)
    plan = Plan(rng).build()
    conf = "\n".join(plan.lines)
    with open(OUT_CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(conf)
    wait_port_gone(GW_HTTP)
    proc = subprocess.Popen([EXE, OUT_CONF], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_ready()
        # 自检：预言机用的 plan 与**实际写出去的**配置必须一致。
        # 不一致就是夹具自己的漂移（过去它以"网关选错站点"的形式报出来，一次刷掉几十条红，
        # 而手工拿同一份配置探针却是对的）——这种情况要一条说清，不能留下几十条误导人的失败。
        drift = []
        for port, cell in plan.ports.items():
            want = set()
            for st in cell["servers"]:
                if st == "fallback":
                    continue
                want |= set(plan.stations[st]["aliases"])
            got = set()
            pat = (r"listen " + str(port)
                   + r"(?: ssl| http2| udp| default_server)*;"
                   + r"\n\s*server_name ([^;]+);")
            for m in re.finditer(pat, conf):
                got |= {x.strip() for x in m.group(1).split() if x.strip() != chr(95)}
            if got != want:
                drift.append((port, sorted(want - got), sorted(got - want)))
        if drift:
            raise AssertionError("plan 与写出的配置不一致（夹具漂移，不是网关问题）：" + str(drift))
        tls_ports = [p for p, c in plan.ports.items() if c["tls"]]
        plain_ports = [p for p, c in plan.ports.items() if not c["tls"]]

        paths = sorted({loc["pattern"] for s in plan.stations.values() for loc in s["locs"] if loc["modifier"] == "="})
        paths += [f"/regex/{i}/{'af' * 2}" for i in range(3)]
        paths += [loc["pattern"] + "/deep" for s in plan.stations.values() for loc in s["locs"] if loc["modifier"] == "prefix"]
        paths += ["/nothing/here"]
        cases = []
        for port in tls_ports + plain_ports:
            for st in plan.ports[port]["servers"]:
                probes = [st, f"www.{st}", "totally-unknown.invalid"] if st != "fallback" else ["totally-unknown.invalid"]
                for probe in probes:
                    for path in rng.sample(paths, min(len(paths), 4)):
                        cases.append((port, probe, path))
        for port, host, path in cases:
            tls = port in tls_ports
            exp = expect_for(plan, port, host, path)
            status, body, headers, fp = h1(port, host, path, tls)
            label = f"h1 {port} {host} {path}"
            if exp is None:
                continue
            if exp.get("backend"):
                ok = (status == 200 and body.startswith(exp["backend"] + "-")
                      and headers.get("x-route") == exp["route"])
                check(f"h1 {port} {host} {path} → {exp['backend']} 经 {exp['route']}", ok,
                      f"status={status} body={body!r} x-route={headers.get('x-route')!r}")
            else:
                ok = status == exp["status"] and body == exp["body"]
                check(f"{label} 期望 {exp['status']} {exp['body']!r}", ok,
                      f"实得 status={status} body={body!r} headers={ {k: v for k, v in headers.items() if k in ('x-route','x-station')} }")
            if headers.get("x-station") is not None and st_in_plan(plan, exp["station"]):
                check(f"{label} 站点归属 X-Station", headers.get("x-station") == exp["station"],
                      f"x-station={headers.get('x-station')!r} want={exp['station']!r}")
            if tls and fp:
                want = cert_fp(pick_cert(plan, port, host))
                check(f"h1 {port} SNI={host} 证书指纹", fp == want, f"{fp[:12]} != {want[:12]}")
            # rewrite 之后不得再落到本 location 的兜底 return
            if exp.get("rewritten"):
                check(f"h1 {port} {host} rewrite 到 {exp['rewritten']}",
                      "should-not-fall-through" not in body, f"body={body!r}")
        # h2：SNI 与 authority 分开，站点按 authority、证书按 SNI
        for port in tls_ports:
            if not plan.ports[port].get("h2"):
                continue
            srvs = [s for s in plan.ports[port]["servers"] if s != "fallback"]
            if len(srvs) < 1:
                continue
            sni = rng.choice(srvs + ["nomatch.invalid"])
            auth = rng.choice(srvs + ["nope.invalid"])
            path = rng.sample(paths, 1)[0]
            kv = h2_probe(port, sni, auth, path)
            if kv is None:
                continue
            exp = expect_for(plan, port, auth, path)
            want_body = (exp["body"] or "").strip()
            got_body = kv.get("BODY", "").strip()
            ok = kv.get("STATUS") == "200" or (exp["status"] and kv.get("STATUS") == str(exp["status"]))
            check(f"h2 {port} SNI={sni} authority={auth} {path} → {want_body}",
                  got_body.startswith(want_body.split("|")[0]) and want_body.split("|")[-1] in got_body,
                  f"probe={kv}")
            if kv.get("PEER_SHA256"):
                check(f"h2 {port} 证书按 SNI={sni}",
                      kv["PEER_SHA256"] == cert_fp(pick_cert(plan, port, sni)), f"probe={kv}")
        # L4：sni_match 分流 + 兜底 + 纯 TCP 聚合
        # sni_match 是**依序取第一条命中**（stream.rs::pick_sni_target），所以一条通配写在
        # 前面就会遮住后面的精确名，而 `sni_match "*"` 这种"看起来像全匹配"的写法在实现里
        # 只是名字恰好等于 "*" 的精确名。预言机必须按同一个顺序算，不能逐条独立预期——
        # 之前逐条预期就是这里剩下的那条红。
        probes = [("one.w.test" if pat == "*.w.test" else pat) for pat, _ in plan.stream_sni]
        probes.append("nomatch.l4.test")          # 谁都不命中 → proxy_pass 兜底
        for sni in dict.fromkeys(probes):         # 去重且保持顺序
            hit = next((port for pat, port in plan.stream_sni if sni_rule_matches(pat, sni)),
                       plan.stream_default)
            shadowed = [pat for pat, _ in plan.stream_sni
                        if sni_rule_matches(pat, sni) and pat != sni]
            got = tls_tls_l4(sni, hit)
            check(f"L4 SNI={sni} → l4{L4_PORTS.index(hit)}"
                  + (f"（被 {shadowed} 这类先写的规则命中，依序第一条）" if shadowed else ""),
                  got == f"l4{L4_PORTS.index(hit)}:sni={sni}", f"got={got!r}")
        got = l4_probe(GW_L4_PLAIN, "rawtcp")
        check("L4 纯 TCP 聚合端口（明文后端）", got.endswith(":rawtcp") and got.startswith("plain"),
              f"got={got!r}")
        if verbose:
            print(conf)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=8)
    return plan


def tls_tls_l4(sni, want_port):
    """向 stream 监听发一次真实 TLS ClientHello（带 SNI），L4 后端会回自己的标签。"""
    ctx = ssl._create_unverified_context()
    ctx.set_alpn_protocols(None) if False else None
    s = socket.create_connection(("127.0.0.1", GW_L4), timeout=8)
    try:
        w = ctx.wrap_socket(s, server_hostname=sni)
        w.sendall(want_sni_marker(sni))
        data = w.recv(128)
        w.close()
        return data.decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return f"error:{e}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def want_sni_marker(sni):
    return f"sni={sni}".encode()


def wait_port_gone(port, timeout=20):
    """上一轮的网关可能还在收尾（Windows 上 kill 之后监听端口还会占一会儿）。
    不等它就起下一轮，探针连上的是**旧进程**，于是预言机按新拓扑判，答案来自旧拓扑——
    报出来的是"网关选错站点"这类并不存在的故障。先确认端口没人听了再起下一轮。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        except OSError:
            return True
        time.sleep(0.2)
    raise SystemExit(f"!! 端口 {port} 一直没空出来：上一轮的网关没退干净")


def wait_ready(timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", GW_HTTP), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"!! 网关未就绪，见 logs/random_scen_err.log 与 {OUT_CONF}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=random.randrange(10**6))
    ap.add_argument("--iters", type=int, default=4)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    ensure_certs()
    start_http_backends()
    start_l4_backends()
    print(f"随机场景 E2E：seed={a.seed} iters={a.iters}")
    for k in range(a.iters):
        results["pass"] = results["pass"]
        before = results["fail"]
        try:
            run_iteration(a.seed + k, a.verbose)
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            import traceback

            traceback.print_exc()
            check(f"seed={a.seed + k} 崩溃", False, str(e)[:200])
        print(f"  轮 {k + 1}（seed={a.seed + k}）累计 {results['pass']} 通过 / {results['fail']} 失败")
        if results["fail"] != before:
            print("  本轮失败样本：")
            for line in results["cases"][-10:]:
                print("   ", line)
            break
    print(f"\n==== 随机场景 E2E: {results['pass']}/{results['pass'] + results['fail']} passed ====")
    if results["fail"]:
        print("复现：python tools/random_scenarios_e2e.py --seed %s --iters 1 --verbose" % a.seed)
        sys.exit(1)


if __name__ == "__main__":
    main()
