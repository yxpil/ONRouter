# -*- coding: utf-8 -*-
# 业务分流的**真实业务形态** E2E —— 不按指令逐条打钩，而是照一个 UGC 站点的一天来打流量。
#
# 为什么还要再来一份：前两套（proxy_split_e2e / proxy_split_examples_e2e）验的是"语义对不对"，
# 每条请求都是为那条语义量身定做的。运维真正要的是另一句话：把它抄进生产配置、按真实形状
# 打流量之后，**用户看到的还是不是同一个版本、一条评论会不会被写两遍、某一路整体挂掉时
# 我该怎么向老板解释指标**。所以这份脚本只有一个业务模型：
#
#   登录用户（240 个不同 uid，各带自己的 Cookie）→ 一次会话问三件事：
#     GET  /home/<uid>   主页，走缓存
#     GET  /api/<uid>/f  动态接口，不缓存
#     POST /write        写评论，body 里带全局唯一 id
#   比例是 18% 到 app_next，其余 app_stable（声明一）；另有发布阶梯 2%/18%/*（声明二）、
#   不许串台的灰度（声明三）、默认档且整路没人（声明四）、以及把键换成 $remote_addr 的
#   反面教材（声明五）。
#
# 断言全部从"业务后果"倒推，不看代码路径：
#   粘性      一个用户的三问必须全在同一版本；主页与动态接口给出不同版本 = 界面撕裂。
#   比例      落到 app_next 的用户数 == 参考哈希对这 240 个 uid 算出的那一批，一个不多一个不少。
#   不重复写  每个评论 id 在**所有版本池**里恰好出现一次；这是"绝不跨路重投"唯一有意义的证法。
#   缓存      同一 URL 被两个版本的用户各问一次：各自 MISS→HIT，且各自读到的仍是自己版本的体。
#   整路挂了  默认档下第一问是这一路自己的失败（连上了又被拒），此后该路进摘除期，
#             用户被改投到下一路（$proxy_split=app_bleed 而 $proxy_split_served=app_stable），
#             并且改投发生在这条评论被任何节点收下之前 —— 所以还是不重复。
#   灰度      off 档下这一路 100% 失败，稳定版的写入计数一次都没动，指标里 bled 恒为 0；
#             这条就是"为什么不许串台"的业务理由：悄悄改投会让灰度的错误率变成假的。
#   键选错    所有请求都从 127.0.0.1 来，用 $remote_addr 当键时 50 个不同用户全塌进同一路。
#   账本      routed == served==split 的请求数；targets 增量 == 实测落点；字面量 /admin 零增量。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_split_business_e2e.py
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
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "proxy_split_business.conf")
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "proxy_split_business_err.log")
OUT_LOG = os.path.join(LOG_DIR, "proxy_split_business_out.log")
CACHE_DIR = os.path.join(LOG_DIR, "proxy_split_business_cache")

sys.path.insert(0, HERE)
from proxy_split_e2e import split_id  # noqa: E402  与主 E2E 共用同一份哈希移植

GW, GW_PORT = "127.0.0.1", 18372
# 18377(app_grey) 与 18378(app_bleed) 故意不起后端，且必须是两个池：
# 节点健康是按池算的，共用一个死池会让两条声明互相踩健康计数（见 conf 注释）。
NODES = {
    "stable-a": ("app_stable", 18373),
    "stable-b": ("app_stable", 18374),
    "next": ("app_next", 18375),
    "hotfix": ("app_hotfix", 18376),
}
BRANCH_OF = {tag: branch for tag, (branch, _p) in NODES.items()}
SPLITS = {
    "app_release": ([(18.0, "app_next")], "app_stable"),
    "ladder_release": ([(2.0, "app_hotfix"), (18.0, "app_next")], "app_stable"),
    "grey_release": ([(20.0, "app_grey")], "app_stable"),
    "bleed_release": ([(20.0, "app_bleed")], "app_stable"),
    "addr_release": ([(18.0, "app_next")], "app_stable"),
}

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
BE = {}


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    """最近构建的那份；release 可能是上一版发布的旧产物，旧二进制不认 proxy_pass 变量。
    `-t` 对未知指令只告警仍退 0，所以这里要的是**正面证据**：-t 必须把分流声明打出来。"""
    cands = [
        os.path.join(ROOT, "target", p, n)
        for p in ("release", "debug")
        for n in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    out = subprocess.run([exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    blob = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0 or "按 $app_release 分流" not in blob:
        raise SystemExit("!! %s 里没有这份业务分流配置（-t 只告警不失败，必须看正面证据）：\n%s"
                         % (exe, blob[-1200:]))
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
    for i in range(60000):
        k = f"{prefix}-{i}"
        if ref_bucket(dest, k) == branch:
            return k
    raise SystemExit(f"!! 找不到落到 {dest}:{branch} 的键")


# ---------------- 后端：一个最小的"版本"，会记账 ----------------
class QuietServer(ThreadingHTTPServer):
    """网关停机时会硬断连接，stdlib 的默认 handle_error 把这种情况打整屏 traceback。
    它们不是业务失败（断言只看网关侧的响应），所以只吞掉连接类异常。"""

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, (ConnectionError, socket.timeout, OSError)):
            ThreadingHTTPServer.handle_error(self, request, client_address)


class Backend:
    """每个版本池一台（stable 两台）。写评论记在全局 store 里，
    于是"这条评论到底被谁收了"是可以跨版本对账的。"""

    def __init__(self, tag, port, store):
        self.tag, self.port = tag, port
        self.served = 0
        outer, branch = self, BRANCH_OF[tag]

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _reply(self, code, text):
                body = text.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, body_text):
                outer.served += 1
                split = self.headers.get("X-Split", "")
                served = self.headers.get("X-Split-Served", "")
                if self.command == "POST" and "/write" in self.path:
                    cid = (body_text or "").strip()
                    if cid:
                        with store["lock"]:
                            store["by_id"][cid].append(outer.tag)
                            store["by_branch"][branch].append(cid)
                        return self._reply(200, f"who={outer.tag} branch={branch} wrote={cid}\n"
                                                f"split={split} served={served}\n")
                    return self._reply(400, "empty comment id\n")
                head = f"who={outer.tag} branch={branch} path={self.path}\n"
                head += f"split={split} served={served}\n"
                return self._reply(200, head)

            do_GET = lambda self: self._handle("")  # noqa: E731
            do_POST = lambda self: self._handle(  # noqa: E731
                self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(errors="replace"))

            def log_message(self, *a):
                pass

        self.srv = QuietServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


STORE = {"lock": threading.Lock(), "by_id": defaultdict(list), "by_branch": defaultdict(list)}


def request(method, path, uid=None, body=None):
    """一问：返回 (状态, 解析出的 kv, 响应头)。uid 就是业务身份，走 Cookie 带进去。"""
    headers = {}
    if uid:
        headers["Cookie"] = f"uid={uid}"
    data = body.encode() if body is not None else None
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}", data=data,
                                 headers=headers, method=method)
    try:
        resp = _opener.open(req, timeout=20)
        code, raw, hdrs = resp.status, resp.read().decode(errors="replace"), resp.headers
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode(errors="replace")
        hdrs = e.headers or {}
    except Exception as e:  # noqa: BLE001
        return 0, {"err": str(e)}, {}
    words = {}
    for line in raw.splitlines():
        for piece in line.split():
            if "=" in piece:
                k, v = piece.split("=", 1)
                words[k] = v
    return code, words, {k.lower(): v for k, v in hdrs.items()}


def metrics_text():
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}/metrics")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def _grab(text, family, split):
    pat = re.compile(r'onrouter_' + family + r'\{split="' + re.escape(split)
                     + r'",(?:target|role)="([^"]+)"\}\s+([0-9.]+)')
    return {m.group(1): float(m.group(2)) for m in pat.finditer(text)}


def targets(text, split):
    return _grab(text, "proxy_split_targets_total", split)


def roles(text, split):
    out = _grab(text, "proxy_split_total", split)
    for r in ("routed", "bled", "down", "empty"):
        out.setdefault(r, 0.0)
    return out


def wait_port(port, up=True, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", port))
            ok = True
        except Exception:
            ok = False
        finally:
            s.close()
        if ok == up:
            return True
        time.sleep(0.2)
    return False


def branch_counts(by_branch):
    return {b: len(v) for b, v in by_branch.items()}


# ==================== 业务场景 ====================


def scenario_session():
    """一个站点的一天：240 个登录用户，各问主页 + 动态接口 + 写一条评论。"""
    users = [f"u{i:04d}" for i in range(240)]
    per_user_branch, api_branch, mism, codes = {}, {}, [], Counter()
    wrote = 0
    for uid in users:
        st, home, _h = request("GET", f"/home/{uid}", uid)
        st2, feed, _h2 = request("GET", f"/api/{uid}/feed", uid)
        st3, wr, _h3 = request("POST", f"/write?u={uid}", uid, body=f"c-{uid}")
        codes[(st, st2, st3)] += 1
        for step, kv in (("home", home), ("feed", feed), ("write", wr)):
            b = kv.get("branch")
            if b is None:
                mism.append((uid, step, kv))
                continue
            if step == "write":
                wrote += 1
            if step == "home":
                per_user_branch[uid] = b
            elif per_user_branch.get(uid) and b != per_user_branch[uid]:
                mism.append((uid, step, b, per_user_branch[uid]))
            if step == "feed":
                api_branch[uid] = b

    check("整段业务流量没有失败请求（240 用户 × 主页/接口/写评论全 200）",
          list(codes) == [(200, 200, 200)], f"状态组合={dict(codes)} 无回显={mism[:3]}")
    check("一个用户的一整个会话只见到一个版本（主页与接口不撕裂）",
          not mism, str(mism[:4]))
    check("评论真的写出去了（每用户一条）", wrote == len(users), f"wrote={wrote}")

    got = Counter(per_user_branch.values())
    want = Counter(ref_bucket("app_release", u) for u in users)
    check("18% 的比例落在真实用户身上：与参考哈希逐一对上，一个不差",
          got == want and len(got) == 2, f"实测={dict(got)} 参考={dict(want)}")
    share = 100.0 * got.get("app_next", 0) / sum(got.values())
    check("用户口径的版本占比在声明比例附近", 12.0 <= share <= 24.0, f"app_next {share:.1f}%")
    check("两个版本都真的有真实用户在用",
          got.get("app_next", 0) >= 20 and got.get("app_stable", 0) >= 20, str(dict(got)))

    dup = {cid: tags for cid, tags in STORE["by_id"].items() if len(tags) > 1}
    total_ids = sum(len(v) for v in STORE["by_id"].values())
    check("一条评论只进一个版本池（绝不跨路重投）",
          not dup and total_ids == wrote, f"重复={list(dup.items())[:3]} 记到 {total_ids} 次，发出 {wrote} 条")
    check("版本池内部仍然按 upstream 自己分节点（分流是池级的）",
          min(BE["stable-a"].served, BE["stable-b"].served) > 0,
          f"stable-a={BE['stable-a'].served} stable-b={BE['stable-b'].served}")
    return per_user_branch


def scenario_metrics(per_user_branch):
    """运维要核对的那张表：/metrics 的比例 == 用户实际看到的比例。"""
    txt = metrics_text()
    t = targets(txt, "app_release")
    seen = Counter(per_user_branch.values())
    r = roles(txt, "app_release")
    # 会话里每个用户的三个 URL 各不相同（主页带 uid），所以主页那问也是 MISS：
    # 这一路的转发数应当正好是"用户数 × 3"，每一问都交给了本意那一路。
    check("/metrics 的每路转发数 == 该路用户数 × 三问（指标就是运维那张比例表）",
          all(abs(t.get(b, 0.0) - 3.0 * seen[b]) < 1e-9 for b in seen)
          and sum(t.values()) == 3 * sum(seen.values()),
          f"指标={t} 实测用户={dict(seen)}")
    check("后端都在的时候没有一次串台（bled/down/empty 全为 0）",
          r["bled"] == 0 and r["down"] == 0 and r["empty"] == 0, str(r))
    check("routed == 本段全部请求数（每一问都交给了比例选中的那一路）",
          r["routed"] == 3 * sum(seen.values()),
          f"routed={r['routed']}，发出 {3 * sum(seen.values())} 问")


def scenario_cache():
    """同一 URL、两个版本的用户各自问：各成自己的缓存条目，不许读到对方的页面。"""
    a = key_for("app_release", "app_stable", "cache")
    b = key_for("app_release", "app_next", "cache")
    path = "/home/shared-profile"
    st1, kv1, h1 = request("GET", path, a)
    st2, kv2, h2 = request("GET", path, b)
    # 两问 MISS 是**应该**记账的（请求确实交给了节点），账本快照从这里开始取。
    before = metrics_text()
    st3, kv3, h3 = request("GET", path, a)
    st4, kv4, h4 = request("GET", path, b)

    check("两个版本的用户各自先 MISS、再 HIT",
          (h1.get("x-cache"), h3.get("x-cache"), h2.get("x-cache"), h4.get("x-cache"))
          == ("MISS", "HIT", "MISS", "HIT"),
          f"{h1.get('x-cache')}/{h3.get('x-cache')}/{h2.get('x-cache')}/{h4.get('x-cache')}")
    check("各自读到的是自己版本的页面（缓存没有串版本）",
          st1 == st2 == st3 == st4 == 200 and kv1.get("branch") == kv3.get("branch") == "app_stable"
          and kv2.get("branch") == kv4.get("branch") == "app_next",
          f"{kv1.get('branch')} / {kv2.get('branch')} / {kv3.get('branch')} / {kv4.get('branch')}")
    check("命中时归属仍然看得见：响应头里 $proxy_split 有值、$proxy_split_served 是空串",
          h3.get("x-split") == "app_stable" and h3.get("x-split-served") == ""
          and h4.get("x-split") == "app_next" and h4.get("x-split-served") == "",
          f"A {h3.get('x-split')!r}/{h3.get('x-split-served')!r} "
          f"B {h4.get('x-split')!r}/{h4.get('x-split-served')!r}")
    after = metrics_text()
    check("缓存命中不交给任何节点，因此不产生分流账本增量",
          targets(after, "app_release") == targets(before, "app_release")
          and roles(after, "app_release") == roles(before, "app_release"),
          f"{targets(before, 'app_release')} -> {targets(after, 'app_release')}")


def scenario_ladder():
    """发布阶梯：2% hotfix / 18% next / 其余 stable，真实用户沿阶梯分布。"""
    users = [f"L{i:04d}" for i in range(200)]
    seen = Counter()
    bad = []
    for uid in users:
        st, kv, _h = request("GET", f"/ladder/{uid}", uid)
        if st != 200 or kv.get("branch") != ref_bucket("ladder_release", uid):
            bad.append((uid, st, kv.get("branch"), ref_bucket("ladder_release", uid)))
            continue
        seen[kv.get("branch")] += 1
    check("阶梯三档都有真实用户，且每人落点与参考哈希一致",
          not bad and set(seen) == {"app_hotfix", "app_next", "app_stable"},
          f"分布={dict(seen)} 异常={bad[:3]}")
    t = targets(metrics_text(), "ladder_release")
    check("阶梯的指标账本与实测分布逐路相等",
          all(abs(t.get(b, 0.0) - seen[b]) < 1e-9 for b in seen), f"{t} vs {dict(seen)}")


def scenario_grey():
    """灰度（不许串台）：这一路整体挂了，命中它的人必须失败，稳定版一次都不许被写。"""
    grey_users = [key_for("grey_release", "app_grey", "grey") for _ in range(8)]
    ok_users = [key_for("grey_release", "app_stable", "greyok") for _ in range(8)]
    before = metrics_text()
    stable_before = len(STORE["by_branch"].get("app_stable", []))
    next_served_before = BE["next"].served
    res = {}
    for uid in grey_users + ok_users:
        want_grey = uid in grey_users
        st, _kv, _h = request("POST", f"/grey/write?u={uid}", uid, body=f"g-{uid}")
        res.setdefault(want_grey, []).append(st)

    grey_codes = set(res[True])
    ok_codes = set(res[False])
    after = metrics_text()
    r, b = roles(after, "grey_release"), roles(before, "grey_release")
    leaked = [cid for cid in ("g-" + u for u in grey_users) if cid in STORE["by_id"]]

    check("灰度里命中故障版本的用户 100% 失败（不静默换版本）",
          grey_codes == {502}, f"故障档状态={sorted(grey_codes)}")
    check("没命中灰度的用户完全不受影响（仍 200）",
          ok_codes == {200}, f"稳定档状态={sorted(ok_codes)}")
    check("失败一次都没有改投到别处：bled 增量为 0",
          r["bled"] == b["bled"], f"bled {b['bled']} -> {r['bled']}")
    check("故障用户的那 8 条评论一次都没有落到任何版本里（既不写两遍也不悄悄降级写）",
          not leaked, f"漏进的评论={leaked}")
    check("稳定版的写入增量 == 恰好是那 8 个没命中灰度的用户",
          len(STORE["by_branch"].get("app_stable", [])) - stable_before == len(ok_users),
          f"{stable_before} -> {len(STORE['by_branch'].get('app_stable', []))}")
    check("故障请求也没有溜进另一个在线版本（app_next 一次都没被问到）",
          BE["next"].served == next_served_before,
          f"app_next served {next_served_before} -> {BE['next'].served}")
    check("故障档的失败按这一路自己的账记（down 增量 > 0）",
          r["down"] > b["down"], f"down {b['down']} -> {r['down']}")


def scenario_bleed():
    """默认档：这一路整体挂掉时用户被改投到下一路，业务不中断，评论仍然只有一条。"""
    uid = key_for("bleed_release", "app_bleed", "bleed")
    before = metrics_text()
    st_first, kv_first, _h = request("POST", f"/bleed/write?u={uid}", uid, body=f"b-{uid}")
    r1 = roles(metrics_text(), "bleed_release")
    b1 = roles(before, "bleed_release")
    st_second, kv_second, _h2 = request("POST", f"/bleed/write?u={uid}", uid, body=f"b2-{uid}")
    r2 = roles(metrics_text(), "bleed_release")

    check("第一问是这一路自己的失败：连上了但被拒，账本只记 routed，不记改投",
          st_first == 502 and r1["bled"] == b1["bled"] and r1["down"] == b1["down"],
          f"状态={st_first} roles {b1} -> {r1}")
    check("第二问起该路进摘除期，用户被改投到下一路并成功（业务不中断）",
          st_second == 200 and kv_second.get("branch") == "app_stable",
          f"状态={st_second} 落点={kv_second.get('branch')} 失败详情={kv_second.get('err')}")
    check("改投看得见：后端回显的比例选中路是 app_bleed，实际接走路是 app_stable",
          kv_second.get("split") == "app_bleed" and kv_second.get("served") == "app_stable",
          f"split={kv_second.get('split')!r} served={kv_second.get('served')!r}")
    check("改投被记账：bled 增量 >= 1", r2["bled"] > r1["bled"], f"{r1} -> {r2}")
    first_cid, second_cid = "b-" + uid, "b2-" + uid
    check("改投发生在这条评论被任何节点收下之前：失败的那条零落点，改投成功的那条只有一个落点",
          first_cid not in STORE["by_id"]
          and len(STORE["by_id"].get(second_cid, [])) == 1,
          f"失败条落点={STORE['by_id'].get(first_cid)} 改投条落点={STORE['by_id'].get(second_cid)}")


def scenario_wrong_key():
    """反面教材：键换成 $remote_addr，所有请求都从 127.0.0.1 来 —— 整站塌进同一路。"""
    users = [f"cdn-{i}" for i in range(50)]
    seen = Counter()
    for uid in users:
        st, kv, _h = request("GET", f"/addr/{uid}", uid)
        if st == 200:
            seen[kv.get("branch")] += 1
    check("用 $remote_addr 当键时，50 个不同用户全部落到同一路（这就是全站切版本）",
          len(seen) == 1 and sum(seen.values()) == len(users), str(dict(seen)))
    t = targets(metrics_text(), "addr_release")
    check("对应的指标也只记了一路（运维看 /metrics 才知道出事）",
          len([k for k, v in t.items() if v > 0]) == 1, str(t))


def scenario_no_split_cost():
    """不参与分流的路径必须一分不付：账本零增量。"""
    before = metrics_text()
    bset = {s: (targets(before, s), roles(before, s)) for s in SPLITS}
    for i in range(30):
        # /admin 是 `location = /admin` 精确匹配，且查询串不影响归属，所以反复问同一条。
        st, _kv, _h = request("GET", f"/admin?i={i}")
        if st != 200:
            check("字面量 proxy_pass 正常服务", False, f"第 {i} 问状态={st}")
            return
    after = metrics_text()
    grew = {s: (targets(after, s), roles(after, s)) != v for s, v in bset.items()}
    check("字面量 proxy_pass 不产生任何分流账本增量（没配分流的写法零成本）",
          not any(grew.values()), str([s for s, g in grew.items() if g]))


def main():
    exe = find_binary()
    for p in NODES.values():
        if wait_port(p[1], up=True, timeout=0.2):
            raise SystemExit(f"!! 端口 {p[1]} 已被占用，先确认没有残留进程")
    if os.path.isdir(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
    for f in (ERR_LOG, OUT_LOG):
        if os.path.exists(f):
            os.remove(f)

    for tag, (_b, port) in NODES.items():
        BE[tag] = Backend(tag, port, STORE)
    proc = subprocess.Popen([exe, "-c", CONF_REL], cwd=ROOT,
                            stdout=open(OUT_LOG, "w"), stderr=subprocess.STDOUT)
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + ERR_LOG)
        print("=== 业务分流真实场景 E2E：一个 UGC 站点的一天 ===")
        branches = scenario_session()
        scenario_metrics(branches)
        scenario_cache()
        scenario_ladder()
        scenario_grey()
        scenario_bleed()
        scenario_wrong_key()
        scenario_no_split_cost()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        for b in BE.values():
            b.stop()

    passed = sum(1 for _n, ok in results if ok)
    print("\n==== 业务分流真实场景 E2E: %d/%d passed ====" % (passed, len(results)))
    for n, ok in results:
        if not ok:
            print("FAILED:", n)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
