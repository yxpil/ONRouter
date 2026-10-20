# -*- coding: utf-8 -*-
# front_proxy（前置代理/CDN 感知）E2E —— 用真实流量证明三件事：
#   1) 识别与信任是两件事：伪造全套厂商头的请求，只要直连对端不在声明的网段里，一个值都不许改
#   2) 出口模式改的是"全链路共用"的那个地址：$remote_addr、访问日志、geo、limit_req 的键一起跟上
#   3) 每种模式的边界：detect 只标注；egress+auto_trust off 只采来源元数据不动地址；
#      egress+auto_trust on 才按 profile 的头链改写
# 外加源站侧的 Cache-Status（RFC 9209）、传给后端的 X-Forwarded-Proto/XFF、指标计数、
# 一次性告警不刷屏，以及 -t 对"读起来像生效、运行时一行不跑"的配置硬失败。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/front_proxy_e2e.py
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "front_proxy_e2e.conf")
CONF = os.path.join(ROOT, CONF_REL)
# 日志与 pid 的路径按配置文件所在目录解析（全库一致），所以是 conf/logs/ 而不是 ./logs/
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ACCESS_LOG = os.path.join(LOG_DIR, "front_proxy_access.log")
ERR_LOG = os.path.join(LOG_DIR, "front_proxy_err.log")
TMP_DIR = os.path.join(ROOT, "conf", ".tmp_front_proxy")

GW = "127.0.0.1"
P_EGRESS, P_UNVERIFIED, P_RECOG, P_DETECT, P_ORIGIN, P_BACK = 18380, 18381, 18382, 18383, 18384, 18385

# demo-edge 的两个探针 + 一条地址链，取值刻意做成各家常见形状的"超集"
PROBE = {"X-Demo-Edge-Id": "edge-req-1", "X-Demo-Edge-Ray": "ray-abc"}
FORGED = {
    **PROBE,
    "X-Demo-Real-Client": "203.0.113.9",
    "X-Demo-Edge-Country": "cn",
    "X-Demo-Edge-Visitor": '{"scheme":"https","ssl_protocol":"TLSv1.3"}',
    "X-Forwarded-Host": "www.example.org:443",
}

results = []
lock = threading.Lock()
backend_hits = {"n": 0}
backend_seen = []  # 每次回源收到的 (path, x-forwarded-proto, x-forwarded-for)，用于证明协议/地址传到后端


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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def base(port):
    return f"http://{GW}:{port}"


def request(port, path, timeout=15, headers=None):
    req = urllib.request.Request(base(port) + path, method="GET", headers=headers or {})
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def body_text(port, path, headers=None):
    st, hs, body = request(port, path, headers=headers)
    return st, hs, body.decode(errors="replace").strip()


def metrics(port=P_ORIGIN):
    st, _, body = request(port, "/metrics", timeout=5)
    assert st == 200, f"metrics 未就绪: {st}"
    return body.decode(errors="replace")


def fp_metric(text, profile, role):
    m = re.search(
        r'onrouter_front_proxy_total\{profile="%s",role="%s"\}\s+(\d+)' % (profile, role), text
    )
    return int(m.group(1)) if m else None


def read_lines(path, timeout=6.0):
    """日志是异步刷盘的：读到出现内容或超时为止，别用固定 sleep 赌它已经落盘。"""
    deadline = time.time() + timeout
    lines = []
    while time.time() < deadline:
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = [l for l in f.read().splitlines() if l.strip()]
        if lines:
            return lines
        time.sleep(0.2)
    return lines


# ==================== 假源站：回显协议/地址头，并按需追加 Cache-Status ====================


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with lock:
            backend_hits["n"] += 1
            n = backend_hits["n"]
            backend_seen.append(
                (
                    self.path,
                    self.headers.get("x-forwarded-proto") or "",
                    self.headers.get("x-forwarded-for") or "",
                )
            )
        extra = {}
        if self.path.startswith("/c/up"):
            # 上游（这里模拟"前置 CDN 已经写过一条"）：本机那条必须追加在后面，不能覆盖
            extra["Cache-Status"] = "cdn; detail=miss"
        if self.path.startswith("/c/nc"):
            extra["Cache-Control"] = "no-store"
        body = json.dumps({"n": n, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=60")
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静音，别把 E2E 控制台搞脏
        pass


def start_backend():
    srv = ThreadingHTTPServer((GW, P_BACK), Backend)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ==================== -t 用例：该否决的一律否决 ====================

BAD_CASES = [
    (
        "detect_auto_trust",
        "front_proxy b1 { probe x; ip_header y; trust 10.0.0.0/8; }\n"
        "server { listen 127.0.0.1:18399; front_proxy_mode detect; front_proxy_auto_trust on; }\n",
        "永远不生效",
    ),
    (
        "bad_trust_cidr",
        "front_proxy b2 { probe x; trust 192.0.2.0/33; }\n"
        "server { listen 127.0.0.1:18399; front_proxy_mode detect; }\n",
        "192.0.2.0/33",
    ),
    (
        "egress_without_root",
        "front_proxy b3 { probe x; ip_header y; }\n"
        "server { listen 127.0.0.1:18399; front_proxy_mode egress; }\n",
        "不会生效",
    ),
    (
        "bad_mode_value",
        "front_proxy b4 { probe x; trust 10.0.0.0/8; }\n"
        "server { listen 127.0.0.1:18399; front_proxy_mode egres; }\n",
        "只接受 off / detect / egress",
    ),
    (
        "no_profiles",
        "server { listen 127.0.0.1:18399; front_proxy_mode detect; }\n",
        "没有任何 front_proxy 块",
    ),
]


def run_t(exe, conf_path):
    # 网关诊断日志是 UTF-8 写进管道的：不显式指定 encoding，Windows 上会按本地代码页解，
    # 中文断言（"只接受 off / detect / egress"）全部匹配不上
    return subprocess.run(
        [exe, "-t", "-c", conf_path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def test_config_layer(exe):
    r = run_t(exe, CONF_REL)
    out = (r.stdout or "") + (r.stderr or "")
    check("-t 通过示例配置", r.returncode == 0, f"rc={r.returncode}\n{out}")
    check(
        "-t 打印出声明的 profile 与地址链",
        "前置代理识别" in out and "x-demo-real-client → x-forwarded-for" in out,
        out,
    )
    if os.path.isdir(TMP_DIR):
        shutil.rmtree(TMP_DIR)
    os.makedirs(TMP_DIR)
    for name, text, needle in BAD_CASES:
        rel = os.path.join("conf", ".tmp_front_proxy", name + ".conf")
        with open(os.path.join(ROOT, "conf", ".tmp_front_proxy", name + ".conf"), "w", encoding="utf-8") as f:
            f.write(text)
        r = run_t(exe, rel)
        o = (r.stdout or "") + (r.stderr or "")
        check(
            f"-t 否决 {name}",
            r.returncode != 0 and needle in o,
            f"rc={r.returncode} needle={needle!r}\n{o}",
        )
    shutil.rmtree(TMP_DIR)


# ==================== 运行层 ====================


def main():
    for p in (ACCESS_LOG, ERR_LOG):
        try:
            os.remove(p)
        except OSError:
            pass
    exe = find_binary()
    test_config_layer(exe)

    backend = start_backend()
    logf = open(os.path.join(LOG_DIR, "front_proxy_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request(P_EGRESS, "/ping", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit(f"!! 网关未就绪（端口被占用？看 {os.path.join('conf','logs','front_proxy_out.log')}）")

        # ---- 1. egress + auto_trust on：全量出口改写 ----
        st, hs, body = body_text(P_EGRESS, "/who", FORGED)
        check("egress：$remote_addr 改成头里的真实客户端", st == 200 and body == "203.0.113.9", f"body={body}")
        check("egress：$front_proxy 标注命中的 profile", hdr(hs, "X-Fp") == "demo-edge", hdr(hs, "X-Fp"))
        check("egress：$front_proxy_verified=1（对端在声明网段内）", hdr(hs, "X-Fp-Verified") == "1", hdr(hs, "X-Fp-Verified"))
        check("egress：国家码归一成 CN", hdr(hs, "X-Fp-Country") == "CN", hdr(hs, "X-Fp-Country"))
        check("egress：$front_proxy_host 去了端口", hdr(hs, "X-Fp-Host") == "www.example.org", hdr(hs, "X-Fp-Host"))
        check("egress：$realip_remote_addr 仍是真实 TCP 对端", hdr(hs, "X-Realip-Remote") == "127.0.0.1", hdr(hs, "X-Realip-Remote"))
        check("egress：JSON 形状的协议头解析成 https", hdr(hs, "X-Scheme") == "https", hdr(hs, "X-Scheme"))
        check("egress：geo 看到的是改写后的地址（testnet）", hdr(hs, "X-Net") == "testnet", hdr(hs, "X-Net"))

        # 访问日志与 $remote_addr 必须一致：这条留到最后统一核对（日志是异步刷盘的）

        # ---- 2. 网段对不上：识别照做，取值一个都不给（防伪造）----
        forged_odd = {
            "X-Odd-Edge-Id": "1",
            "X-Demo-Real-Client": "203.0.113.77",
            "X-Demo-Edge-Country": "jp",
            "X-Demo-Edge-Visitor": "https",
        }
        st, hs, body = body_text(P_UNVERIFIED, "/who", forged_odd)
        check("伪造头 + 对端不可信：地址一点没改", st == 200 and body == "127.0.0.1", f"body={body}")
        check("伪造头 + 对端不可信：仍然识别得出（识别≠信任）", hdr(hs, "X-Fp") == "demo-edge-wrong-range", hdr(hs, "X-Fp"))
        check("伪造头 + 对端不可信：verified 为空", (hdr(hs, "X-Fp-Verified") or "") == "", repr(hdr(hs, "X-Fp-Verified")))
        check("伪造头 + 对端不可信：国家不采信", (hdr(hs, "X-Fp-Country") or "") == "", repr(hdr(hs, "X-Fp-Country")))
        check("伪造头 + 对端不可信：协议不降级/不升级", hdr(hs, "X-Scheme") == "http", hdr(hs, "X-Scheme"))
        check("伪造头 + 对端不可信：geo 仍是节点地址", hdr(hs, "X-Net") == "localnet", hdr(hs, "X-Net"))

        # ---- 3. auto_trust 默认 off：来源元数据照采，地址一律不动 ----
        st, hs, body = body_text(P_RECOG, "/who", FORGED)
        check("auto_trust off：地址不动（默认档不给 profile 授权）", st == 200 and body == "127.0.0.1", f"body={body}")
        check("auto_trust off：识别照做", hdr(hs, "X-Fp") == "demo-edge", hdr(hs, "X-Fp"))
        check("auto_trust off：协议与国家这类来源元数据仍采用", hdr(hs, "X-Scheme") == "https" and hdr(hs, "X-Fp-Country") == "CN", f"{hdr(hs,'X-Scheme')}/{hdr(hs,'X-Fp-Country')}")
        check("auto_trust off：geo 按节点地址（这正是它要告警的成因）", hdr(hs, "X-Net") == "localnet", hdr(hs, "X-Net"))

        # ---- 4. detect：只标注 ----
        st, hs, body = body_text(P_DETECT, "/who", FORGED)
        check("detect：不改写地址", st == 200 and body == "127.0.0.1", f"body={body}")
        check("detect：不采协议", hdr(hs, "X-Scheme") == "http", hdr(hs, "X-Scheme"))
        check("detect：不采国家", (hdr(hs, "X-Fp-Country") or "") == "", repr(hdr(hs, "X-Fp-Country")))
        check("detect：只做标注", hdr(hs, "X-Fp") == "demo-edge", hdr(hs, "X-Fp"))

        # ---- 5. 头链的方言与回落 ----
        junk = dict(FORGED, **{"X-Demo-Real-Client": "not-an-ip", "X-Forwarded-For": "198.51.100.7, 203.0.113.31"})
        _, _, body = body_text(P_EGRESS, "/who", junk)
        check("首选头是垃圾 → 按链落到下一个候选头", body == "203.0.113.31", f"body={body}")
        v6 = dict(FORGED, **{"X-Demo-Real-Client": "2001%3A0db8%3A0%3A0%3A0%3A0%3A0%3A1%3A46532"})
        _, _, body = body_text(P_EGRESS, "/who", v6)
        check("URL 编码的 IPv6+端口形状解得开", body == "2001:db8::1", f"body={body}")
        badgeo = dict(FORGED, **{"X-Demo-Edge-Country": "CN;evil"})
        _, hs, _ = request(P_EGRESS, "/who", headers=badgeo)
        check("国家头夹了就整个不采（不原样透传进日志）", (hdr(hs, "X-Fp-Country") or "") == "", repr(hdr(hs, "X-Fp-Country")))
        none = dict(FORGED, **{"X-Demo-Real-Client": "", "X-Forwarded-For": "unknown, unknown"})
        _, hs, body = body_text(P_EGRESS, "/who", none)
        check("链里全是垃圾 → 地址保持节点值", body == "127.0.0.1", f"body={body}")

        # ---- 6. 限流键落对地址（"计数与信誉落对真实客户端"这一组）----
        m0 = metrics()
        codes_split = []
        for i in range(8):
            h = dict(PROBE, **{"X-Demo-Real-Client": f"203.0.114.{i}"})
            codes_split.append(request(P_EGRESS, "/lim", headers=h)[0])
        check(
            "egress：8 个不同真实客户端各 1 次 → 全过（键被拆开）",
            all(c == 200 for c in codes_split),
            str(codes_split),
        )
        codes_same = []
        for _ in range(8):
            h = dict(PROBE, **{"X-Demo-Real-Client": "203.0.115.9"})
            codes_same.append(request(P_EGRESS, "/lim", headers=h)[0])
        check(
            "egress：同一真实客户端连发 8 次 → 被自己的键限住（429 出现）",
            any(c == 429 for c in codes_same),
            str(codes_same),
        )
        codes_lump = []
        for i in range(8):
            h = dict(FORGED, **{"X-Demo-Real-Client": f"203.0.116.{i}"})
            codes_lump.append(request(P_RECOG, "/lim", headers=h)[0])
        check(
            "对照 auto_trust off：8 个不同伪造客户端仍全落节点地址一个键 → 被限",
            any(c == 429 for c in codes_lump),
            str(codes_lump),
        )
        codes_forge = []
        for i in range(8):
            h = {
                "X-Odd-Edge-Id": "1",
                "X-Demo-Real-Client": f"203.0.117.{i}",
            }
            codes_forge.append(request(P_UNVERIFIED, "/lim", headers=h)[0])
        check(
            "对照 不可信对端：伪造的不同客户端不会把限流拆成 8 个键",
            any(c == 429 for c in codes_forge),
            str(codes_forge),
        )

        # ---- 7. 源站侧可缓存性与协议传到后端 ----
        with lock:
            backend_hits["n"] = 0
        st, hs, body = request(P_ORIGIN, "/c/a", headers=FORGED)
        cs1 = hdr(hs, "Cache-Status")
        xc1 = hdr(hs, "X-Cache-Status")
        st2, hs2, _ = request(P_ORIGIN, "/c/a", headers=FORGED)
        cs2 = hdr(hs2, "Cache-Status")
        xc2 = hdr(hs2, "X-Cache-Status")
        check(
            "egress：回源首次输出 RFC 9209 Cache-Status detail=miss",
            st == 200 and cs1 == "onrouter; detail=miss" and xc1 == "MISS",
            f"cs={cs1} xc={xc1}",
        )
        check("egress：缓存命中改报 detail=hit 且不再打后端", st2 == 200 and cs2 == "onrouter; detail=hit" and xc2 == "HIT", f"cs={cs2} xc={xc2}")
        with lock:
            n_after_two = backend_hits["n"]
        check("Cache-Status 的 hit 名副其实（两次请求只回源一次）", n_after_two == 1, f"backend={n_after_two}")

        # 上游已经写过一条：本机那条追加在后，不能覆盖
        st, hs, _ = request(P_ORIGIN, "/c/up", headers=FORGED)
        csu = hdr(hs, "Cache-Status")
        check("上游的 Cache-Status 在前、本机追加在后", csu == "cdn; detail=miss, onrouter; detail=miss", f"cs={csu}")

        # 对端不可信 → 不报 Cache-Status（不知道对面是不是声明的那家，报了只会污染它的观测）
        st, hs, _ = request(P_ORIGIN, "/c/b", headers={"X-Odd-Edge-Id": "1"})
        check("对端未验证时不输出 Cache-Status", st == 200 and hdr(hs, "Cache-Status") is None, hdr(hs, "Cache-Status"))

        # 只有通用 XFF（没有专有名头）也算识别得到：profile 是配置数据，不靠厂商白名单
        st, hs, _ = request(P_ORIGIN, "/c/x", headers={"X-Forwarded-For": "203.0.118.5"})
        check(
            "纯 XFF 的 profile 同样能触发出口判定",
            st == 200 and hdr(hs, "Cache-Status") is not None,
            hdr(hs, "Cache-Status"),
        )

        # 协议与真实地址要能传到后端（proxy_set_header 用的正是被改写后的 $scheme/$remote_addr）
        with lock:
            seen = list(backend_seen)
        hit = [s for s in seen if s[0].startswith("/c/a")]
        check(
            "回源请求带上真实客户端与来源侧协议（XFF / X-Forwarded-Proto）",
            any(xfp == "https" and xff.startswith("203.0.113.9") for _, xfp, xff in hit),
            str(hit),
        )

        # ---- 8. 指标账目 ----
        m1 = metrics()
        for profile in ("demo-edge", "demo-edge-wrong-range", "plain-xff"):
            for role in ("matched", "ip_applied", "ip_blocked", "origin_applied", "origin_blocked", "country_applied"):
                a, b = fp_metric(m0, profile, role), fp_metric(m1, profile, role)
                if a is None or b is None or b < a:
                    check(f"指标 {profile}/{role} 可读且单调", False, f"{a} -> {b}")
        check(
            "matched 随真实流量增长（识别有账）",
            fp_metric(m1, "demo-edge", "matched") > fp_metric(m0, "demo-edge", "matched"),
            f"{fp_metric(m0,'demo-edge','matched')} -> {fp_metric(m1,'demo-edge','matched')}",
        )
        check(
            "不可信 profile 的 ip_blocked/origin_blocked 各 +1 每请求（挡下有账）",
            fp_metric(m1, "demo-edge-wrong-range", "ip_blocked") is not None
            and fp_metric(m1, "demo-edge-wrong-range", "origin_blocked") >= 2,
            f"ip={fp_metric(m1,'demo-edge-wrong-range','ip_blocked')} origin={fp_metric(m1,'demo-edge-wrong-range','origin_blocked')}",
        )
        check(
            "auto_trust off 的 vhost 计入 ip_blocked（不是无声退回节点地址）",
            fp_metric(m1, "demo-edge", "ip_blocked") >= 2,
            str(fp_metric(m1, "demo-edge", "ip_blocked")),
        )
        check(
            "ip_applied 只在 egress+auto_trust on 处累计",
            fp_metric(m1, "demo-edge", "ip_applied") >= 10,
            str(fp_metric(m1, "demo-edge", "ip_applied")),
        )

        # ---- 9. 访问日志与 $remote_addr 一致（改写发生在 set_remote 之前，日志跟着走）----
        acc = read_lines(ACCESS_LOG)
        firsts = [l.split()[0] for l in acc if l.split()]
        check(
            "访问日志里出现真实客户端地址（egress 改写过的请求）",
            "203.0.113.9" in firsts,
            f"共 {len(firsts)} 行，首字段样本={firsts[:5]}",
        )
        check(
            "不可信对端/detect/auto_trust off 的请求在日志里仍是节点地址",
            "127.0.0.1" in firsts,
            f"首字段样本={firsts[:5]}",
        )

        # ---- 10. 一次性告警：刷屏了就是缺陷 ----
        err_lines = read_lines(ERR_LOG)
        warns = [l for l in err_lines if "命中但来源判定没走通" in l]
        per = {}
        for line in warns:
            m = re.search(r"front_proxy '([^']+)'", line)
            if m:
                per[m.group(1)] = per.get(m.group(1), 0) + 1
        check(
            "同一个 profile 的告警只打一条（挡下几十次也不刷屏）",
            per.get("demo-edge-wrong-range") == 1 and per.get("demo-edge") == 1,
            str(per),
        )
        check(
            "告警给出可执行的下一步（写 set_real_ip_from 或显式开 auto_trust）",
            any("set_real_ip_from" in l and "front_proxy_auto_trust" in l for l in warns),
            str(warns[:2]),
        )
        # 启动横幅走 log_info!（stderr 侧的诊断日志），不是 stdout —— 断言要落在错误日志上
        startup = "\n".join(err_lines)
        check(
            "启动横幅说明声明了几家与各自证据",
            "前置代理识别" in startup and "trust 网段 1 条" in startup,
            startup[-300:],
        )
        check(
            "auto_trust 开在 egress 上时启动日志点名 vhost",
            any("front_proxy_auto_trust" in l and "fp-egress.local" in l for l in err_lines),
            startup[-300:],
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()
        backend.server_close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== front_proxy E2E: {passed}/{total} passed ====")
    print(f"     后端累计回源次数: {backend_hits['n']}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
