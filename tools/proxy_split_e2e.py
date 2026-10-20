# -*- coding: utf-8 -*-
# 业务分流比例（split_clients → proxy_pass 变量）E2E —— 用真实 HTTP 流量把"按业务比例
# 把流量分到不同版本"这件事证明一遍，重点不是比例对不对，而是**边界**对不对：
#
#   比例      声明 50/30/20，观察到的落点必须贴得上，同一个键永远落同一路（粘性）。
#   改投      只有"这一路给不出一个后端节点"才跨路（整池在摘除期 / 名字解析不出来）。
#             第一问交给这一路时连接被拒 = 这一路的失败，不改投；第二问才算没人。
#   不串台    proxy_split_failover off：灰度实验要的是"这路没人就是没人"，绝不静默换版本。
#   显式退路  只退到写死的那一路，同比例里的另一路也不碰。
#   5xx       后端返回 500 一律不跨路重投 —— 否则一个 POST 会被打进两个业务版本上写两次。
#   归属      $proxy_split（比例选中的那一路）与 $proxy_split_served（请求真正交给的那一路）
#             可以不同，不同就是串了台；两个值都随请求头送到后端，也进 /metrics 的两本账。
#   缓存      每一路各成自己的缓存条目；命中时 $proxy_split 仍说得出是哪一路，
#             $proxy_split_served 是空串（请求根本没交给节点）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_split_e2e.py
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # Windows 控制台默认代码页会把中文输出打成乱码（文件本身仍是 UTF-8）
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "proxy_split_e2e.conf")
CONF = os.path.join(ROOT, CONF_REL)
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "proxy_split_e2e_err.log")
OUT_LOG = os.path.join(LOG_DIR, "proxy_split_e2e_out.log")
CACHE_DIR = os.path.join(LOG_DIR, "proxy_split_cache")

GW = "127.0.0.1"
GW_PORT = 18350
BASE = f"http://{GW}:{GW_PORT}"
# 三个 200 后端 + 一个只会 500 的后端；18355 是死池地址，18356 故意没人监听
BE_PORTS = {"blue": 18351, "green": 18352, "grey": 18353, "ver500": 18354}
BE = {}  # main() 起后端后填充：Backend(tag, port[, status])

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    """用最近构建出来的那份二进制，而不是写死 release。

    release 那份可能是别的任务留下的证据产物（时间戳更早），拿它跑本功能的 E2E
    会得到"未知指令 'proxy_split_failover'"这种假故障：配置里 proxy_pass 的变量
    不展开，分流表也空的，于是一路 502，看起来像是新功能坏了。
    """
    cands = [
        os.path.join(ROOT, "target", profile, name)
        for profile in ("release", "debug")
        for name in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    print("使用网关二进制：", exe)
    return exe


# ---------------- 独立移植的 ngx_murmur_hash2 + 分桶参考实现 ----------------
M = 0x5BD1E995
MASK = 0xFFFFFFFF


def murmur2(data: bytes) -> int:
    length = len(data)
    h = (length ^ 0x9DC03AC8) & MASK
    i = 0
    while i + 4 <= length:
        k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k = (k * M) & MASK
        k ^= k >> 24
        k = (k * M) & MASK
        h = (h * M) & MASK
        h ^= k
        i += 4
    rem = length - i
    if rem == 3:
        h ^= data[i + 2] << 16
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 2:
        h ^= data[i + 1] << 8
        h ^= data[i]
        h = (h * M) & MASK
    elif rem == 1:
        h ^= data[i]
        h = (h * M) & MASK
    h ^= h >> 13
    h = (h * M) & MASK
    h ^= h >> 15
    return h


def split_id(key: str) -> int:
    return murmur2(key.encode()) % 10000


# conf/proxy_split_e2e.conf 里每条 split 的（声明顺序的桶, * 兜底）
SPLITS = {
    "variant": ([(50.0, "blue"), (30.0, "green"), (20.0, "grey")], None),
    "deadAuto": ([(70.0, "deadAuto")], "blue"),
    "deadStrict": ([(70.0, "deadStrict")], "blue"),
    "deadExplicit": ([(70.0, "deadExplicit"), (20.0, "blue"), (10.0, "green")], None),
    "noStarOff": ([(0.01, "blue")], None),
    "noStarOn": ([(0.01, "blue")], None),
    "direct": ([(50.0, "127.0.0.1:18351")], "127.0.0.1:18352"),
    "refused": ([(50.0, "127.0.0.1:18356")], "127.0.0.1:18351"),
    "with500": ([(50.0, "ver500")], "blue"),
    "zeroRoute": ([(0.0, "grey"), (70.0, "deadZero")], "blue"),
}


def ref_bucket(dest: str, key: str) -> str:
    """网关的落桶算法：权重按声明顺序累加（×100 换成万分比），落空且没有 * 就是空串。"""
    buckets, star = SPLITS[dest]
    idv = split_id(key)
    total = 0.0
    for percent, target in buckets:
        total += percent * 100.0
        if idv < total:
            return target
    return star if star is not None else ""


def key_for(dest: str, target: str, prefix: str = "k") -> str:
    """按参考实现反查一个会落到 target 那一路的键：断言由此不是"碰巧对上"。"""
    for i in range(4000):
        k = f"{prefix}-{dest}-{i}"
        if ref_bucket(dest, k) == target:
            return k
    raise SystemExit(f"!! 找不到落到 {dest}:{target} 的键")


# ---------------- 假后端：报出自己是谁，并把网关发来的归属头原样打回 ----------------


class Backend:
    def __init__(self, tag, port, status=200):
        self.tag = tag
        self.port = port
        self.status = status
        self.served = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                lines = [f"who={outer.tag}"]
                lines += [f"{k.lower()}={v}" for k, v in self.headers.items()]
                body = ("\n".join(lines) + "\n").encode()
                outer.served += 1
                self.send_response(outer.status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()


# ---------------- 请求与指标 ----------------


def hit(path, key=None, timeout=15):
    """一次真实请求：返回 (状态码, 响应体 kv, 响应头, 原始体)。X-Key 就是分流用的粘性键。"""
    headers = {"X-Key": key} if key is not None else {}
    req = urllib.request.Request(BASE + path, method="GET", headers=headers)
    try:
        resp = _opener.open(req, timeout=timeout)
        status = resp.status
        body = resp.read().decode(errors="replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode(errors="replace")
        hdrs = {k.lower(): v for k, v in e.headers.items()}
    kv = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return status, kv, hdrs, body


def metrics_text():
    req = urllib.request.Request(BASE + "/metrics", method="GET")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def metric_val(text, name, labels=()):
    for line in text.splitlines():
        if line.startswith(name + "{") and all(lbl in line for lbl in labels):
            try:
                return float(line.rsplit(None, 1)[1])
            except (IndexError, ValueError):
                return None
    return None


def branch_names(dest):
    buckets, star = SPLITS[dest]
    out = [t for _p, t in buckets]
    if star:
        out.append(star)
    return out


def roles(text, dest):
    def one(role):
        return metric_val(
            text, "onrouter_proxy_split_total", ('split="%s"' % dest, 'role="%s"' % role)
        ) or 0.0

    return {r: one(r) for r in ("routed", "bled", "down", "empty")}


def targets(text, dest):
    """{分支: 已转发的请求数}；只含这条 split 声明过的分支，标签基数有上界。"""
    return {
        t: (
            metric_val(
                text,
                "onrouter_proxy_split_targets_total",
                ('split="%s"' % dest, 'target="%s"' % t),
            )
            or 0.0
        )
        for t in branch_names(dest)
    }


def diff_map(before, after):
    return {k: after[k] - before.get(k, 0) for k in after}


def delta(before, after):
    return {k: after[k] - before[k] for k in after}


def served_now(*tags):
    return {t: BE[t].served for t in tags}


def run_t(exe, conf_rel):
    return subprocess.run(
        [exe, "-t", "-c", conf_rel],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


TMP_CONFS = []


def write_case(stem, body):
    """-t 用例：把一份临时配置写进 conf/ 下，跑完删掉。"""
    path = os.path.join(ROOT, "conf", stem + ".conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write('error_log "logs/%s_err.log" warn;\npid "logs/%s.pid";\n' % (stem, stem))
        f.write(body)
    TMP_CONFS.append(path)
    return "conf/" + stem + ".conf"


def expect_reject(exe, stem, body, needles, label):
    out = run_output(exe, write_case(stem, body))
    check(label + "：-t 拒绝", out[0] != 0, out[1])
    check(label + "：说清为什么", all(n in out[1] for n in needles), out[1])


def run_output(exe, conf_rel):
    r = run_t(exe, conf_rel)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


# ==================== 配置层 ====================


def config_layer(exe):
    rc, out = run_output(exe, CONF_REL)
    check("-t 读得懂 proxy_split_e2e.conf", rc == 0, f"rc={rc}\n{out}")
    lines = [l for l in out.splitlines() if "按 $" in l and "分流" in l]
    check(
        "-t 为每个分流 location 出一行（10 条 split、11 个 location）",
        len(lines) == 11,
        f"{len(lines)} 行：\n" + "\n".join(lines),
    )
    check("-t 写明声明的比例", "[50%->blue 30%->green 20%->grey]" in out, out)
    check(
        "-t 如实写出 0% 的那一路（比例选不到它，它只是改投落点）",
        "[0%->grey 70%->deadZero *->blue]" in out,
        "\n".join(lines),
    )
    check("-t 写明粘性键（谁决定落点必须看得见）", "粘性键 ${http_x_key}" in out, out)
    auto = next((l for l in lines if "$deadAuto" in l), "")
    strict = next((l for l in lines if "$deadStrict" in l), "")
    expl = next((l for l in lines if "$deadExplicit" in l), "")
    check("-t 默认档写明会改投下一路", "选中路全挂时改投下一路" in auto, auto)
    check("-t 的 off 写明不串台", "不串台（原样失败）" in strict, strict)
    check("-t 的显式退路写明只退哪一路", "只改投 green" in expl, expl)

    expect_reject(
        exe,
        "proxy_split_t1",
        "upstream blue { server 127.0.0.1:18351; }\n"
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://blue; proxy_split_failover off; }\n}\n",
        ["proxy_split_failover", "不会生效"],
        "目标是写死的却声明了改投策略",
    )
    expect_reject(
        exe,
        "proxy_split_t2",
        'split_clients "${http_x_key}" $badshape { 50% blue/api; * blue; }\n'
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://$badshape; }\n}\n",
        ["不能放在主机位"],
        "分流目标写了路径",
    )
    expect_reject(
        exe,
        "proxy_split_t3",
        'split_clients "${http_x_key}" $badfb { 70% blue; * green; }\n'
        "upstream blue { server 127.0.0.1:18351; }\n"
        "upstream green { server 127.0.0.1:18352; }\n"
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://$badfb; proxy_split_failover http://grey; }\n}\n",
        ["proxy_split_failover http://grey", "0% 的那一路"],
        "显式退路不在这套比例里",
    )
    expect_reject(
        exe,
        "proxy_split_t4",
        'split_clients "${http_x_key}" $badfb2 { 70% blue; * green; }\n'
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://pre$badfb2; }\n}\n",
        ["主机位中间"],
        "变量拼在主机位中间",
    )
    expect_reject(
        exe,
        "proxy_split_t5",
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://backend; proxy_split_failover $fb; }\n}\n",
        ["$fb", "不能是变量"],
        "改投目标写成变量",
    )
    expect_reject(
        exe,
        "proxy_split_t6",
        'split_clients "${http_x_key}" $allempty { 0.01% ""; }\n'
        "server { listen 127.0.0.1:18399;\n"
        "  location / { proxy_pass http://$allempty; }\n}\n",
        ["每一路目标都是空串"],
        "分流的每一路都是空串",
    )
    # 变量来自 set 而不是 split_clients：目标照样跟着变量走，但没有可枚举的分支 —— 告警而不是否决
    rc, out = run_output(
        exe,
        write_case(
            "proxy_split_t7",
            "upstream blue { server 127.0.0.1:18351; }\n"
            "server { listen 127.0.0.1:18399;\n"
            "  location / { set $route blue; proxy_pass http://$route; }\n}\n",
        ),
    )
    check("变量来自 set 时 -t 照常通过", rc == 0, out)
    check("变量不是 split_clients 产的：-t 告警说清分流不生效", "不是 split_clients 产的" in out, out)


# ==================== 流量层 ====================


def ratio_and_sticky():
    before_m = metrics_text()
    b_r = roles(before_m, "variant")
    b_t = targets(before_m, "variant")
    served0 = served_now("blue", "green", "grey")
    # 这一段每一问都记在这里：指标窗口是从头到尾的，落点数也必须数满整段，
    # 只拿 1200 个 dist 键去对指标增量会凭空少掉前面粘性/参考核对那 24 问。
    seen = Counter()

    # 粘性：同一个键 6 次必须同一路
    key = key_for("variant", "blue", "sticky")
    seq = []
    for _ in range(6):
        _st, kv, _h, _b = hit("/split", key)
        seq.append(kv.get("who"))
        seen[kv.get("who")] += 1
    check("同一个键恒落同一路（粘性）", len(set(seq)) == 1 and seq[0] == "blue", str(seq))

    # 参考实现逐键核对：网关落点 == 移植 murmur 的落点
    probe = [key_for("variant", t, "ref") for t in ("blue", "green", "grey")]
    probe += ["alice", "bob", "carol-123", "user-agent/mozilla-5", "weird!@#$key", "x" * 40]
    agree, bad = True, None
    for k in probe:
        _st, kv, _h, _b = hit("/split", k)
        seen[kv.get("who")] += 1
        want = ref_bucket("variant", k)
        if kv.get("who") != want or kv.get("x-split") != want:
            agree = False
            bad = (k, want, kv.get("who"), kv.get("x-split"))
            break
    check(f"落点与移植的 murmur2 参考实现逐键一致（{len(probe)} 键）", agree, str(bad))

    # 归属：健康期不许串台
    mix_ok, mix_bad = True, None
    for k in probe:
        _st, kv, _h, _b = hit("/split", k)
        seen[kv.get("who")] += 1
        if kv.get("x-split") != kv.get("x-split-served"):
            mix_ok = False
            mix_bad = (k, kv.get("x-split"), kv.get("x-split-served"))
            break
    check("健康期 $proxy_split == $proxy_split_served（没串台）", mix_ok, str(mix_bad))

    # 分布：1200 个不同键
    N = 1200
    counts = Counter()
    for i in range(N):
        _st, kv, _h, _b = hit("/split", f"dist-{i}")
        counts[kv.get("who")] += 1
        seen[kv.get("who")] += 1
    check("三桶都被命中", set(counts) == {"blue", "green", "grey"}, dict(counts))
    pcts = {t: 100.0 * counts.get(t, 0) / N for t in ("blue", "green", "grey")}
    check(
        "观察比例贴得上声明比例 50/30/20",
        44.0 <= pcts["blue"] <= 56.0 and 25.0 <= pcts["green"] <= 35.0 and 15.0 <= pcts["grey"] <= 25.0,
        str({k: round(v, 2) for k, v in pcts.items()}),
    )

    after_m = metrics_text()
    a_r = roles(after_m, "variant")
    a_t = targets(after_m, "variant")
    served1 = served_now("blue", "green", "grey")
    d_t = diff_map(b_t, a_t)
    d_r = delta(b_r, a_r)
    back_delta = {t: served1[t] - served0[t] for t in served1}

    check(
        "/metrics 的每路转发数 == 实测落点数",
        all(abs(d_t[t] - seen[t]) < 1e-9 for t in ("blue", "green", "grey")),
        f"指标增量 {d_t} vs 实测 {dict(seen)}",
    )
    check(
        "指标增量 == 后端实际接到的请求数（不空转、不漏记）",
        all(abs(d_t[t] - back_delta[t]) < 1e-9 for t in ("blue", "green", "grey")),
        f"指标 {d_t} vs 后端 {back_delta}",
    )
    total_sent = 6 + 2 * len(probe) + N
    check(
        "routed 增量 == 本段请求数（每一问都交给了本意那一路）",
        d_r["routed"] == total_sent and sum(seen.values()) == total_sent,
        f"routed+{d_r['routed']}，发出 {total_sent} 问，记到落点 {sum(seen.values())}",
    )
    check(
        "后端都在时 bled/down/empty 全为 0（没有一次跨路）",
        d_r["bled"] == 0 and d_r["down"] == 0 and d_r["empty"] == 0,
        str(d_r),
    )


def direct_host_branches():
    """分支写成 host:port（不依赖 upstream 池）也要成。"""
    before = metrics_text()
    b_t = targets(before, "direct")
    _st, kv1, _h, _b = hit("/direct", key_for("direct", "127.0.0.1:18351", "dport"))
    _st, kv2, _h, _b = hit("/direct", key_for("direct", "127.0.0.1:18352", "dport"))
    d_t = diff_map(b_t, targets(metrics_text(), "direct"))
    check(
        "分支写 host:port 时两路都能转发到",
        kv1.get("who") == "blue" and kv2.get("who") == "green",
        f"{kv1.get('who')} / {kv2.get('who')}",
    )
    check(
        "host:port 作为分支名进指标标签（基数有上界）",
        all(abs(d_t.get(t, 0) - 1) < 1e-9 for t in ("127.0.0.1:18351", "127.0.0.1:18352")),
        str(d_t),
    )
    check(
        "host:port 分支的归属同样写进两个变量",
        kv1.get("x-split") == "127.0.0.1:18351" and kv1.get("x-split-served") == "127.0.0.1:18351",
        f"{kv1.get('x-split')} / {kv1.get('x-split-served')}",
    )


def bleed_when_branch_has_no_backend():
    """默认档：本意那一路给不出后端时才改投，并且改投是记账的、可查的。"""
    before = metrics_text()
    b_r = roles(before, "deadAuto")
    b_t = targets(before, "deadAuto")
    blue0 = BE["blue"].served
    key = key_for("deadAuto", "deadAuto", "bleed")

    st1, _kv1, _h, body1 = hit("/auto", key)
    # 第一问单独结账：这一路当时还给得出节点，连接被拒是它自己的失败（归 proxy_next_upstream），
    # 既不该改投也不该记成"这一路没人"。和两问合计混在一起看，就分不清这两件事了。
    d1 = delta(b_r, roles(metrics_text(), "deadAuto"))
    st2, kv2, _h, _b = hit("/auto", key)
    after = metrics_text()
    d_r = delta(b_r, roles(after, "deadAuto"))
    d_t = diff_map(b_t, targets(after, "deadAuto"))

    check(
        "第一问：请求交给了这一路，连接被拒就是它的失败（502 而不是改投）",
        st1 == 502,
        f"{st1}\n{body1[:200]}",
    )
    check(
        "第一问只记 routed：bled/down/empty 一个都不涨",
        d1["routed"] == 1 and d1["bled"] == 0 and d1["down"] == 0 and d1["empty"] == 0,
        str(d1),
    )
    check(
        "第二问：这一路给不出后端了，改投成功返回 200",
        st2 == 200 and kv2.get("who") == "blue",
        f"{st2} {kv2.get('who')}",
    )
    check(
        "第二问的归属：比例仍说 deadAuto，真正接走的是 blue",
        kv2.get("x-split") == "deadAuto" and kv2.get("x-split-served") == "blue",
        f"{kv2.get('x-split')} / {kv2.get('x-split-served')}",
    )
    check("改投记在账上：bled 增量 1、down 增量 1", d_r["bled"] == 1 and d_r["down"] == 1, str(d_r))
    check(
        "两路各记一次转发（deadAuto 1、blue 1）",
        abs(d_t.get("deadAuto", 0) - 1) < 1e-9 and abs(d_t.get("blue", 0) - 1) < 1e-9,
        str(d_t),
    )
    check("blue 只多接了改投那一问", BE["blue"].served - blue0 == 1, BE["blue"].served - blue0)

    err = ""
    if os.path.exists(ERR_LOG):
        with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
            err = f.read()
    check(
        "改投写进 error log（出事要查得出是谁改投的）",
        "分流改投" in err and "deadAuto" in err,
        err[-400:],
    )


def failover_off_never_bleeds():
    """proxy_split_failover off：这路没人就是没人，绝不静默换版本。"""
    before = metrics_text()
    b_r = roles(before, "deadStrict")
    b_t = targets(before, "deadStrict")
    blue0 = BE["blue"].served
    key = key_for("deadStrict", "deadStrict", "strict")

    codes = [hit("/strict", key)[0] for _ in range(3)]
    after = metrics_text()
    d_r = delta(b_r, roles(after, "deadStrict"))
    d_t = diff_map(b_t, targets(after, "deadStrict"))

    check("off：三问全部原样失败（502），没有一次改投", codes == [502, 502, 502], str(codes))
    check("off：bled 增量 0", d_r["bled"] == 0, str(d_r))
    check("off：另一路一次都没被用上", BE["blue"].served - blue0 == 0, BE["blue"].served - blue0)
    check(
        "off：第一问算这一路的（routed 1），后两问是没人可服务（down 2）",
        d_r["routed"] == 1 and d_r["down"] == 2 and abs(d_t.get("blue", 0)) < 1e-9,
        f"{d_r} {d_t}",
    )


def explicit_failover_target():
    """只退到写死的那一路：同比例里的另一路也不许碰。"""
    before = metrics_text()
    b_r = roles(before, "deadExplicit")
    b_t = targets(before, "deadExplicit")
    blue0 = BE["blue"].served
    green0 = BE["green"].served
    key = key_for("deadExplicit", "deadExplicit", "expl")

    st1, _kv1, _h, _b = hit("/explicit", key)
    st2, kv2, _h, _b = hit("/explicit", key)
    after = metrics_text()
    d_r = delta(b_r, roles(after, "deadExplicit"))
    d_t = diff_map(b_t, targets(after, "deadExplicit"))

    check("显式退路：第一问仍在本路失败（502）", st1 == 502, st1)
    check(
        "显式退路：第二问只退到 green",
        st2 == 200 and kv2.get("who") == "green" and kv2.get("x-split-served") == "green",
        f"{st2} {kv2.get('who')} / {kv2.get('x-split-served')}",
    )
    check(
        "显式退路：比例里的 blue 一次都没被碰",
        BE["blue"].served - blue0 == 0 and abs(d_t.get("blue", 0)) < 1e-9,
        f"后端 {BE['blue'].served - blue0} 指标 {d_t}",
    )
    check(
        "显式退路：green 的转发数与 bled 各记一次",
        BE["green"].served - green0 == 1 and abs(d_t.get("green", 0) - 1) < 1e-9 and d_r["bled"] == 1,
        f"后端+{BE['green'].served - green0} 指标 {d_t} 结局 {d_r}",
    )


def zero_percent_is_fallback_only():
    """0% 的那一路：比例永远选不到它，只有改投会走到 —— "退到比例之外"的正规写法。

    这条存在的理由是 `-t` 的报错文案自己：它让用户"把 0% 的那一路写进 split_clients"当退路。
    文案不能是空话，所以这里同时验两件事 —— 参考实现扫遍桶坐标选不到它，真实流量里它只在
    改投那一刻接到请求。
    """
    never = all(ref_bucket("zeroRoute", f"zp-{i}") != "grey" for i in range(20000))
    check("0% 那一路不会被比例选中（参考实现扫 2 万个键）", never, "有键落到了 grey")

    before = metrics_text()
    b_t = targets(before, "zeroRoute")
    grey0 = BE["grey"].served
    key = key_for("zeroRoute", "deadZero", "zp")

    st1, _kv1, _h, _b = hit("/zero", key)
    st2, kv2, _h, _b = hit("/zero", key)
    d_t = diff_map(b_t, targets(metrics_text(), "zeroRoute"))

    check("0% 实验：第一问交给本意那一路并按它失败（502）", st1 == 502, st1)
    check(
        "0% 实验：这一路给不出后端时，改投落到 0% 声明的那一路",
        st2 == 200 and kv2.get("who") == "grey" and kv2.get("x-split-served") == "grey",
        f"{st2} {kv2.get('who')} / {kv2.get('x-split-served')}",
    )
    check(
        "0% 实验：比例说的仍是 deadZero，归属与落点分开记账",
        kv2.get("x-split") == "deadZero" and d_t.get("grey", 0) == 1.0 and abs(d_t.get("blue", 0)) < 1e-9,
        f"x-split={kv2.get('x-split')} 指标 {d_t}",
    )
    check(
        "0% 那一路只接改投来的请求（后端计数从 0 起跳 +1）",
        BE["grey"].served - grey0 == 1,
        BE["grey"].served - grey0,
    )


def empty_bucket():
    """没有 * 兜底时桶值可以是空串：off 原样失败，on 仍按"这一路没人"处置。"""
    key = "alice"
    check(
        "参考实现确认这个键就是落空（空串）",
        ref_bucket("noStarOff", key) == "" and ref_bucket("noStarOn", key) == "",
        repr(ref_bucket("noStarOff", key)),
    )
    before = metrics_text()
    b_off = roles(before, "noStarOff")
    st_off, _kv, _h, _b = hit("/empty-off", key)
    after = metrics_text()
    d_off = delta(b_off, roles(after, "noStarOff"))
    check("落空 + off：原样 502", st_off == 502, st_off)
    check(
        "落空 + off：empty 记 1、down 记 1，一次都没改投",
        d_off["empty"] == 1 and d_off["down"] == 1 and d_off["bled"] == 0 and d_off["routed"] == 0,
        str(d_off),
    )

    b_on = roles(before, "noStarOn")
    st_on, kv_on, _h, _b = hit("/empty-on", key)
    d_on = delta(b_on, roles(metrics_text(), "noStarOn"))
    check(
        "落空 + 默认档：按这一路没人处理，改投到 blue",
        st_on == 200 and kv_on.get("who") == "blue",
        f"{st_on} {kv_on.get('who')}",
    )
    check(
        "落空时 $proxy_split 是空串、$proxy_split_served 是接走的那一路",
        kv_on.get("x-split", "") == "" and kv_on.get("x-split-served") == "blue",
        f"[{kv_on.get('x-split')}] / [{kv_on.get('x-split-served')}]",
    )
    check("落空 + 默认档：empty 与 bled 各记一次", d_on["empty"] == 1 and d_on["bled"] == 1, str(d_on))


def five_xx_never_reroutes():
    """后端 5xx 绝不跨路重投 —— 这条边界是整个分流最重要的安全约束。"""
    before = metrics_text()
    b_r = roles(before, "with500")
    b_t = targets(before, "with500")
    blue0 = BE["blue"].served
    key = key_for("with500", "ver500", "err500")

    codes = []
    last = {}
    for _ in range(3):
        st, kv, _h, _b = hit("/err500", key)
        codes.append(st)
        last = kv
    after = metrics_text()
    d_r = delta(b_r, roles(after, "with500"))
    d_t = diff_map(b_t, targets(after, "with500"))

    check(
        "500 的那一路自己扛下 500（不是 502，也不是被换掉的 200）",
        codes == [500, 500, 500],
        str(codes),
    )
    check(
        "归属仍是这一路：$proxy_split 与 $proxy_split_served 都是 ver500",
        last.get("x-split") == "ver500" and last.get("x-split-served") == "ver500",
        f"{last.get('x-split')} / {last.get('x-split-served')}",
    )
    check(
        "5xx 不跨路：另一路一次都没被写（后端与指标增量都是 0）",
        BE["blue"].served - blue0 == 0 and abs(d_t.get("blue", 0)) < 1e-9,
        f"后端+{BE['blue'].served - blue0} 指标 {d_t}",
    )
    check(
        "三问全部记成 routed，bled/down 一律不涨",
        d_r["routed"] == 3 and d_r["bled"] == 0 and d_r["down"] == 0,
        str(d_r),
    )


def refused_connect_is_not_a_dead_branch():
    """分支指向没人监听的 host:port：地址是这一路给的，失败就归这一路，不许改投。"""
    before = metrics_text()
    b_r = roles(before, "refused")
    b_t = targets(before, "refused")
    blue0 = BE["blue"].served
    key = key_for("refused", "127.0.0.1:18356", "refused")

    st, _kv, _h, _b = hit("/refused", key)
    after = metrics_text()
    d_r = delta(b_r, roles(after, "refused"))
    d_t = diff_map(b_t, targets(after, "refused"))

    check("连不上就是这一路的 502", st == 502, st)
    check(
        "被拒不等于这一路没人：bled 0、down 0、routed 1",
        d_r["bled"] == 0 and d_r["down"] == 0 and d_r["routed"] == 1,
        str(d_r),
    )
    check(
        "另一路没被牵连（后端与指标都没动）",
        BE["blue"].served - blue0 == 0 and abs(d_t.get("127.0.0.1:18351", 0)) < 1e-9,
        f"后端+{BE['blue'].served - blue0} 指标 {d_t}",
    )


def cache_is_per_branch():
    """每一路各成自己的缓存条目：命中时也要说得出这是哪一路的缓存。"""
    kb = key_for("variant", "blue", "cacheme")
    kg = key_for("variant", "green", "cacheme")

    _st, _kv1, h1, _b = hit("/cached", kb)
    _st, _kv2, h2, _b = hit("/cached", kb)
    check(
        "缓存：同一路第二问命中",
        h1.get("x-cache") == "MISS" and h2.get("x-cache") == "HIT",
        f"{h1.get('x-cache')} {h2.get('x-cache')}",
    )
    check("缓存命中时 $proxy_split 仍说得出哪一路（归属不丢）", h2.get("x-split") == "blue", str(h2))
    check(
        "缓存命中没有交给任何节点：$proxy_split_served 是空串（转发那问才有值）",
        h1.get("x-split-served") == "blue" and h2.get("x-split-served", "") == "",
        f"MISS={h1.get('x-split-served')!r} HIT={h2.get('x-split-served')!r}",
    )
    _st, kv3, h3, _b = hit("/cached", kg)
    check(
        "另一路的同一 URI 读不到这路的缓存（各自成条目）",
        h3.get("x-cache") == "MISS" and kv3.get("who") == "green",
        f"{h3.get('x-cache')} {kv3.get('who')}",
    )
    _st, kv4, h4, _b = hit("/cached", kg)
    check(
        "两条路各自都能命中，内容不会串",
        h4.get("x-cache") == "HIT" and kv4.get("who") == "green" and h4.get("x-split") == "green",
        f"{h4.get('x-cache')} {kv4.get('who')} {h4.get('x-split')}",
    )


def banner_and_ledger():
    """启动横幅要把分流的落点指向 /metrics —— 第一眼就要知道去哪核对比例。

    横幅是 log_info! 写的，只落 error_log 文件（stderr 侧只回显 warn 以上），
    所以断言读 ERR_LOG 而不是进程 stdout —— 前提是本 conf 的 error_log 级别是 info。
    """
    text = ""
    if os.path.exists(ERR_LOG):
        with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
            text = f.read()
    check(
        "启动横幅逐条列出分流并指向 /metrics",
        "按 $variant 分流" in text and "onrouter_proxy_split_targets_total" in text,
        text[-600:],
    )
    check(
        "启动横幅写明 off 的那一条不串台",
        any("不串台" in line for line in text.splitlines() if "按 $deadStrict 分流" in line),
        text[-600:],
    )


def main():
    global BE
    exe = find_binary()
    for p in (ERR_LOG, OUT_LOG):
        try:
            os.remove(p)
        except OSError:
            pass
    # 上一轮留下的缓存会让第一问就是 HIT，"第一问"这件事就验不到
    shutil.rmtree(CACHE_DIR, ignore_errors=True)

    config_layer(exe)

    BE = {tag: Backend(tag, port, 500 if tag == "ver500" else 200) for tag, port in BE_PORTS.items()}
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([exe, CONF_REL], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        t0, ready = time.time(), False
        while time.time() - t0 < 15:
            try:
                with socket.create_connection((GW, GW_PORT), timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        check("网关起来了并监听 18350", ready, "15s 内没起来")
        if not ready:
            return
        ratio_and_sticky()
        direct_host_branches()
        bleed_when_branch_has_no_backend()
        failover_off_never_bleeds()
        explicit_failover_target()
        zero_percent_is_fallback_only()
        empty_bucket()
        five_xx_never_reroutes()
        refused_connect_is_not_a_dead_branch()
        cache_is_per_branch()
        banner_and_ledger()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        for b in BE.values():
            b.stop()
        shutil.rmtree(CACHE_DIR, ignore_errors=True)
        for p in TMP_CONFS:
            try:
                os.remove(p)
            except OSError:
                pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== proxy_split E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
