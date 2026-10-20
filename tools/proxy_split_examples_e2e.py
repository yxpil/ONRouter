# -*- coding: utf-8 -*-
# conf/proxy_split_examples.conf 的运行态证明 —— 示例配置不是文案，抄下去必须真的能跑。
#
# 这份脚本只干一件事：把示例里那几条声明在真实流量上各验一次，因为示例是用户唯一会
# 照抄的东西，它错了就等于功能是错的：
#   /whoami  1% canary + 5% v2 + * v1   → 比例落得对、会话键真的粘、指标与实测对得上，
#                                          并且"分流是池级的"：v1 内部仍由 upstream 分节点
#   /beta    30% beta + off             → 这一路没人就是没人：502，稳定版一次都没被写
#   /hotfix  0% hotfix + 60% gray + on    → 0% 那一路只由改投到达，$proxy_split 与 served 分得开
#   /        （带 proxy_cache）         → 命中时归属仍看得见，别的版本读不到这一路的缓存
#
# 参考哈希与主 E2E 共用同一份移植：两份脚本对同一个键必须算出同一个落点，
# 复制两份哈希就是在给"两边都过但网关其实不一样"留门。
#
#   python tools/proxy_split_examples_e2e.py
import os
import re
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

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "proxy_split_examples.conf")
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "proxy_split_examples_err.log")
OUT_LOG = os.path.join(LOG_DIR, "proxy_split_examples_out.log")
CACHE_DIR = os.path.join(LOG_DIR, "proxy_split_examples_cache")

sys.path.insert(0, HERE)
from proxy_split_e2e import split_id  # noqa: E402

GW, GW_PORT = "127.0.0.1", 18360
# 18366（app_beta）与 18367（app_gray）故意不起后端：示例要靠它们演示"这一路给不出后端"。
# 两条声明各用各的死池，因为节点健康是按池算的（见 conf 里那段注释）。
NODES = {
    "v1a": ("app_v1", 18361),
    "v1b": ("app_v1", 18362),
    "v2": ("app_v2", 18363),
    "canary": ("app_canary", 18364),
    "hotfix": ("app_hotfix", 18365),
}
BRANCH_OF = {tag: branch for tag, (branch, _port) in NODES.items()}
SPLITS = {
    "app_release": ([(1.0, "app_canary"), (5.0, "app_v2")], "app_v1"),
    "beta_release": ([(30.0, "app_beta")], "app_v1"),
    "hotfix_release": ([(0.0, "app_hotfix"), (60.0, "app_gray")], "app_v1"),
}

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
BE = {}


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    """最近构建的那份二进制。release 可能是别的任务留下的旧产物，用它会得到假故障
    （旧二进制不认 split 变量，proxy_pass http://$x 会被当成主机名去解析）。"""
    cands = [
        os.path.join(ROOT, "target", p, n)
        for p in ("release", "debug")
        for n in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    print("使用网关二进制：", exe)
    return exe


def ref_bucket(dest, key):
    buckets, star = SPLITS[dest]
    idv = split_id(key)
    total = 0.0
    for percent, target in buckets:
        total += percent * 100.0
        if idv < total:
            return target
    return star


def key_for(dest, branch, prefix):
    """按参考实现反查一个会落到 branch 的会话键：断言由此不是"碰巧对上"。"""
    for i in range(40000):
        k = f"{prefix}-{i}"
        if ref_bucket(dest, k) == branch:
            return k
    raise SystemExit(f"!! 找不到落到 {dest}:{branch} 的键")


class Backend:
    def __init__(self, tag, port):
        self.tag = tag
        self.port = port
        self.served = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                lines = [f"who={outer.tag}", f"branch={BRANCH_OF[outer.tag]}"]
                lines += [f"{k.lower()}={v}" for k, v in self.headers.items()]
                body = ("\n".join(lines) + "\n").encode()
                outer.served += 1
                self.send_response(200)
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


def v1_served():
    return BE["v1a"].served + BE["v1b"].served


def hit(path, sid=None):
    """带会话 Cookie 的一问；返回 (状态, 后端回显的 kv, 响应头)。"""
    headers = {"Cookie": f"sid={sid}"} if sid else {}
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}", headers=headers)
    try:
        resp = _opener.open(req, timeout=20)
        code, body, hdrs = resp.status, resp.read().decode(errors="replace"), resp.headers
    except urllib.error.HTTPError as e:
        code = e.code
        body = e.read().decode(errors="replace")
        hdrs = e.headers or {}
    kv = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v.strip()
    return code, kv, {k.lower(): v for k, v in hdrs.items()}


def metrics_text():
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}/metrics")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def target_map(text, split):
    pat = re.compile(
        r'onrouter_proxy_split_targets_total\{split="' + re.escape(split)
        + r'",target="([^"]+)"\}\s+([0-9.]+)'
    )
    return {m.group(1): float(m.group(2)) for m in pat.finditer(text)}


def role_map(text, split):
    pat = re.compile(
        r'onrouter_proxy_split_total\{split="' + re.escape(split)
        + r'",role="([^"]+)"\}\s+([0-9.]+)'
    )
    out = {m.group(1): float(m.group(2)) for m in pat.finditer(text)}
    for r in ("routed", "bled", "down", "empty"):
        out.setdefault(r, 0.0)
    return out


# ==================== 各条示例声明 ====================


def ratio_and_sticky():
    """声明一：1% / 5% / 其余，粘性键取业务身份而不是 $remote_addr。"""
    before = metrics_text()
    b_t = target_map(before, "app_release")
    seen = Counter()

    sticky = key_for("app_release", "app_v2", "sticky")
    seq = []
    for _ in range(5):
        st, kv, _h = hit("/whoami", sticky)
        check_ok = st == 200 and kv.get("branch") == "app_v2"
        seq.append(kv.get("who"))
        seen[kv.get("branch")] += 1
        if not check_ok:
            check("同一个会话（Cookie sid）恒落同一路", False, f"{st} {kv.get('branch')}")
            return
    check("同一个会话（Cookie sid）恒落同一路", len(set(seq)) == 1, str(seq))

    N = 1200
    for i in range(N):
        st, kv, _h = hit("/whoami", f"dist-{i}")
        if st != 200 or kv.get("branch") not in {"app_v1", "app_v2", "app_canary"}:
            check("分布段全部 200 且落在声明过的三路之一", False, f"第 {i} 问 {st} {kv.get('branch')}")
            return
        seen[kv.get("branch")] += 1

    total = sum(seen.values())
    check("三条路都被命中", set(seen) == {"app_v1", "app_v2", "app_canary"}, dict(seen))
    got = {t: 100.0 * seen.get(t, 0) / total for t in ("app_canary", "app_v2", "app_v1")}
    check(
        "示例里的 1%/5%/94% 真落在真实流量上",
        0.3 <= got["app_canary"] <= 2.5 and 3.0 <= got["app_v2"] <= 7.5 and got["app_v1"] >= 90.0,
        str({k: round(v, 2) for k, v in got.items()}),
    )

    after = metrics_text()
    a_t = target_map(after, "app_release")
    d = {k: a_t.get(k, 0.0) - b_t.get(k, 0.0) for k in a_t}
    check(
        "/metrics 的每一路转发数 == 实测落点",
        all(abs(d.get(t, 0.0) - seen[t]) < 1e-9 for t in ("app_v1", "app_v2", "app_canary")),
        f"指标 {d} vs 实测 {dict(seen)}",
    )
    r = role_map(after, "app_release")
    rb = role_map(before, "app_release")
    check(
        "后端都在时没有一次跨路（bled/down/empty 增量为 0）",
        r["bled"] == rb["bled"] and r["down"] == rb["down"] and r["empty"] == rb["empty"],
        f"{r} vs {rb}",
    )
    check(
        "routed 增量 == 本段请求数（每一问都交给了本意那一路）",
        r["routed"] - rb["routed"] == total,
        f"routed+{r['routed'] - rb['routed']}，发出 {total} 问",
    )
    check(
        "分流是池级的：v1 这一路内部仍按 upstream 自己的算法分两个节点",
        v1_served() == seen["app_v1"] and min(BE["v1a"].served, BE["v1b"].served) > 0,
        f"v1a={BE['v1a'].served} v1b={BE['v1b'].served} 实测 app_v1={seen['app_v1']}",
    )


def read_err():
    if not os.path.exists(ERR_LOG):
        return ""
    with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
        return f.read()


def beta_off_never_bleeds():
    """声明二：off —— 命中 beta 的人失败了就是失败，不许被悄悄改投到稳定版。"""
    before = metrics_text()
    r0 = role_map(before, "beta_release")
    t0 = target_map(before, "beta_release")
    v1_0 = v1_served()
    key = key_for("beta_release", "app_beta", "beta")

    # 五问同一个会话键：第一问时 app_beta 的节点还在，交给它就归它（连接被拒 → 502，
    # 顺带把节点打进 30s 摘除期）；后四问才是"这一路给不出后端"，off 下照样 502。
    codes = [hit("/beta", key)[0] for _ in range(5)]
    after = metrics_text()
    dr = {k: role_map(after, "beta_release")[k] - r0[k] for k in r0}
    at = target_map(after, "beta_release")
    dt = {k: at.get(k, 0.0) - t0.get(k, 0.0) for k in ("app_beta", "app_v1")}

    check("off：五问全部原样失败（502），没有一次被换成稳定版", codes == [502] * 5, str(codes))
    check(
        "off：稳定版一次都没被写（后端与指标同时不动）",
        v1_served() == v1_0 and abs(dt.get("app_v1", 0.0)) < 1e-9,
        f"节点+{v1_served() - v1_0} 指标 {dt}",
    )
    check(
        "off：第一问算这一路的转发，后四问是没人可服务，bled 始终 0",
        dr["bled"] == 0 and dr["routed"] == 1 and dr["down"] == 4 and abs(dt.get("app_beta", 0.0) - 1) < 1e-9,
        f"结局 {dr} 转发 {dt}",
    )
    check(
        "off：error log 说清是哪一路给不出后端，且没有一行它的改投",
        "no live upstreams: app_beta" in read_err() and "分流改投：'app_beta'" not in read_err(),
        read_err()[-400:],
    )


def hotfix_zero_branch():
    """声明三：0% 的那一路只由改投到达。"""
    before = metrics_text()
    r0 = role_map(before, "hotfix_release")
    t0 = target_map(before, "hotfix_release")
    hot0 = BE["hotfix"].served
    v1_0 = v1_served()
    key = key_for("hotfix_release", "app_gray", "hotfix")

    st1, _kv1, _h = hit("/hotfix", key)
    st2, kv2, _h = hit("/hotfix", key)
    after = metrics_text()
    dr = {k: role_map(after, "hotfix_release")[k] - r0[k] for k in r0}
    at = target_map(after, "hotfix_release")
    dt = {
        k: at.get(k, 0.0) - t0.get(k, 0.0)
        for k in ("app_hotfix", "app_gray", "app_v1")
    }

    check("第一问交给本意那一路，连不上就是它的 502", st1 == 502, st1)
    check(
        "第二问：这一路给不出后端，默认档改投先落到 0% 声明的 app_hotfix",
        st2 == 200 and kv2.get("who") == "hotfix" and BE["hotfix"].served - hot0 == 1,
        f"{st2} {kv2.get('who')}",
    )
    check(
        "0% 那一路不消耗比例：它只接到改投这一问，稳定版一次都没被碰",
        abs(dt.get("app_hotfix", 0.0) - 1) < 1e-9 and abs(dt.get("app_v1", 0.0)) < 1e-9 and v1_served() == v1_0,
        f"转发 {dt} 节点+{v1_served() - v1_0}",
    )
    check(
        "归属与落点分开：比例说 app_gray，接走的是 app_hotfix，账上记 bled",
        kv2.get("x-split") == "app_gray" and kv2.get("x-split-served") == "app_hotfix" and dr["bled"] == 1,
        f"{kv2.get('x-split')} / {kv2.get('x-split-served')} 结局 {dr}",
    )
    never = all(ref_bucket("hotfix_release", f"zp-{i}") != "app_hotfix" for i in range(20000))
    check("参考实现扫 2 万个键：0% 那一路永远不被比例选中", never, "有键落到了 app_hotfix")

    err = ""
    if os.path.exists(ERR_LOG):
        with open(ERR_LOG, encoding="utf-8", errors="replace") as f:
            err = f.read()
    check(
        "改投在 error log 里查得出来（示例的 warn 级就够）",
        "分流改投" in err and "app_gray" in err,
        err[-300:],
    )


def per_branch_cache():
    """示例里的 proxy_cache：命中时归属仍看得见，别的版本读不到这一路的条目。"""
    key = key_for("app_release", "app_v1", "cacheme")
    _st1, _kv1, h1 = hit("/", key)
    _st2, _kv2, h2 = hit("/", key)
    check(
        "同一路第二问命中缓存",
        h1.get("x-cache") == "MISS" and h2.get("x-cache") == "HIT",
        f"{h1.get('x-cache')} {h2.get('x-cache')}",
    )
    check("命中时 X-Split 仍说得出哪一路", h2.get("x-split") == "app_v1", str(h2))

    other = key_for("app_release", "app_v2", "cacheme")
    _st3, _kv3, h3 = hit("/", other)
    check(
        "别的版本读不到 v1 的缓存（缓存键含插值后的目标，各成条目）",
        h3.get("x-cache") == "MISS" and h3.get("x-split") == "app_v2",
        f"{h3.get('x-cache')} {h3.get('x-split')}",
    )


def literal_target_costs_nothing():
    """/admin 的字面量 proxy_pass：这一路不参与分流，也不该被分流代码碰。"""
    st, kv, _h = hit("/admin")
    check(
        "字面量目标照常代理（且不带分流的两个归属头）",
        st == 200 and "x-split" not in kv and "x-split-served" not in kv,
        f"{st} {kv.get('who')}",
    )


def main():
    exe = find_binary()
    for p in (ERR_LOG, OUT_LOG):
        try:
            os.remove(p)
        except OSError:
            pass
    shutil.rmtree(CACHE_DIR, ignore_errors=True)

    r = subprocess.run(
        [exe, "-t", "-c", CONF_REL],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    out = (r.stdout or "") + (r.stderr or "")
    check("-t 读得懂这份示例", r.returncode == 0, out)
    check(
        "-t 把示例里的声明原样打印（1%/5%、off 不串台、0% 那一路）",
        all(
            s in out
            for s in (
                "[1%->app_canary 5%->app_v2 *->app_v1]",
                "不串台（原样失败）",
                "[0%->app_hotfix 60%->app_gray *->app_v1]",
            )
        ),
        "\n".join(l for l in out.splitlines() if "分流" in l),
    )

    for tag, (_branch, port) in NODES.items():
        BE[tag] = Backend(tag, port)
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
        check("示例配置直接跑得起来（监听 18360）", ready, "15s 内没起来")
        if not ready:
            return
        ratio_and_sticky()
        beta_off_never_bleeds()
        hotfix_zero_branch()
        per_branch_cache()
        literal_target_costs_nothing()
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

    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== proxy_split 示例配置 E2E: {passed}/{len(results)} passed ====")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
