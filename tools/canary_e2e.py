# -*- coding: utf-8 -*-
# 灰度发布（canary）E2E —— 用真实 HTTP 流量把"按请求特征选版本"证明一遍。
#
# 验的不是配置能不能 -t 通过，而是运维真正会问的几件事：
#   条件       cookie（精确/存在/空值不算）、header（名字大小写不敏感、值精确）、
#              arg、UA 正则、OS 族识别，各自都能单独把请求送进灰度版本；
#   顺序       同时命中多条时按声明顺序取第一条（cookie 压过 header）；
#   百分比     未命中任何条件的用户按粘性键哈希分档，同一个人永远同一档；
#   默认       所有条件与百分比都没选中时回到 default；
#   不串台     灰度版本整池不可用时，默认改投 / off 原样失败 / 显式退路只退指定版本，
#              $proxy_split 与 $proxy_split_served 如实说明"选的是谁、实际交给谁"；
#   缓存       每个版本各成缓存条目，命中时归属仍看得见（served 为空）；
#   变量       $版本变量不只在主机位可用，作为请求头转发时照样是选中的版本。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/canary_e2e.py
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
CONF_REL = os.path.join("conf", "canary_e2e.conf")
CONF = os.path.join(ROOT, CONF_REL)
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "canary_e2e_err.log")
OUT_LOG = os.path.join(LOG_DIR, "canary_e2e_out.log")
CACHE_DIR = os.path.join(LOG_DIR, "canary_cache")

sys.path.insert(0, HERE)
from proxy_split_e2e import split_id  # noqa: E402  与分流 E2E 共用同一份哈希移植

GW, GW_PORT = "127.0.0.1", 18390
BE_PORTS = {"stable": 18391, "beta": 18392, "alt": 18393}
DEAD_PORT = 18394

# 中性 UA：不含任何灰度规则会命中的标记（Firefox/Edg/iPhone/Windows）
UA = "Mozilla/5.0 (X11; Linux x86_64) onrouter-canary-e2e/1.0"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
UA_EDGE_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")
UA_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
UA_IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
UA_ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
BE = {}


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    """要的是"这份二进制认得 canary"的正面证据：-t 必须把灰度自述打出来。
    旧二进制对未知指令只告警仍退 0，光看退出码会把假故障当配置问题。"""
    cands = [
        os.path.join(ROOT, profile, name)
        for profile in ("target/release", "target/debug")
        for name in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    out = subprocess.run([exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    blob = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0 or "按 $release 灰度分流" not in blob:
        raise SystemExit("!! %s 里没有这份灰度配置（-t 只告警不失败，必须看正面证据）：\n%s"
                         % (exe, blob[-1600:]))
    print("使用网关二进制：", exe)
    return exe


def percent_target(uid):
    """$release 的百分比档：键是 "${cookie_uid}${remote_addr}"，20% 进 beta，其余 stable。
    条件规则会先于百分比命中，所以这里只对"不带任何条件"的请求成立。"""
    return "beta" if split_id(uid + GW) < 2000 else "stable"


def uid_for(target, prefix):
    """反查一个按百分比会落到 target 的 uid：断言由此不是碰巧对上。"""
    for i in range(20000):
        uid = f"{prefix}-{i}"
        if percent_target(uid) == target:
            return uid
    raise SystemExit(f"!! 找不到百分比落到 {target} 的 uid")


# ---------------- 后端：只回显"我是谁 / 网关认为我在哪一路" ----------------
class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, (ConnectionError, socket.timeout, OSError)):
            ThreadingHTTPServer.handle_error(self, request, client_address)


class Backend:
    def __init__(self, tag, port):
        self.tag = tag
        self.served = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                outer.served += 1
                body = (
                    f"who={outer.tag}\n"
                    f"path={self.path}\n"
                    f"split={self.headers.get('X-Split', '')}\n"
                    f"served={self.headers.get('X-Split-Served', '')}\n"
                    f"release={self.headers.get('X-Release', '')}\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = QuietServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def request(path, cookie=None, headers=None, ua=UA):
    hdrs = {"User-Agent": ua}
    if cookie:
        hdrs["Cookie"] = cookie
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}", headers=hdrs)
    try:
        resp = _opener.open(req, timeout=20)
        code, raw, hdrs = resp.status, resp.read().decode(errors="replace"), resp.headers
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode(errors="replace")
        hdrs = e.headers or {}
    except Exception as e:  # noqa: BLE001
        return 0, {}, str(e), {}
    kv = {}
    for line in raw.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    return code, kv, raw, {k.lower(): v for k, v in hdrs.items()}


def metrics_text():
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}/metrics")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def targets(text, split):
    pat = re.compile(r'onrouter_proxy_split_targets_total\{split="' + re.escape(split)
                     + r'",target="([^"]+)"\}\s+([0-9.]+)')
    return {m.group(1): float(m.group(2)) for m in pat.finditer(text)}


def roles(text, split):
    pat = re.compile(r'onrouter_proxy_split_total\{split="' + re.escape(split)
                     + r'",role="([^"]+)"\}\s+([0-9.]+)')
    out = {m.group(1): float(m.group(2)) for m in pat.finditer(text)}
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


# ==================== 场景 ====================


def scenario_conditions():
    """每条条件单独发力；同时命中按声明顺序；空 cookie 不算命中。"""
    stable_uid = uid_for("stable", "cond-stable")
    cases = [
        # (说明, 请求参数, 期望版本)
        ("cookie 精确匹配（beta=1）",
         dict(path="/release", cookie=f"uid={stable_uid}; beta=1"), "beta"),
        ("cookie 仅要求存在且非空（preview=1）",
         dict(path="/release", cookie=f"uid={stable_uid}; preview=1"), "beta"),
        ("空 cookie 不算命中，回到百分比档",
         dict(path="/release", cookie=f"uid={stable_uid}; preview="), "stable"),
        ("header 值精确匹配（X-Channel: Vip）",
         dict(path="/release", cookie=f"uid={stable_uid}", headers={"X-Channel": "Vip"}), "alt"),
        ("header 名字大小写不敏感（x-channel: Vip）",
         dict(path="/release", cookie=f"uid={stable_uid}", headers={"x-channel": "Vip"}), "alt"),
        ("header 值大小写敏感（X-Channel: vip 不命中）",
         dict(path="/release", cookie=f"uid={stable_uid}", headers={"X-Channel": "vip"}), "stable"),
        ("query 参数（?ver=beta）",
         dict(path="/release?ver=beta", cookie=f"uid={stable_uid}"), "beta"),
        ("query 参数值大小写敏感（?ver=Beta 不命中）",
         dict(path="/release?ver=Beta", cookie=f"uid={stable_uid}"), "stable"),
        ("UA 正则 ~*（Firefox）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_FIREFOX), "beta"),
        ("UA 规则先于 OS 规则（Windows 上的 Edg 仍走 ua 那条）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_EDGE_WIN), "beta"),
        ("OS 族识别（Windows）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_WINDOWS), "alt"),
        ("iOS 先于 macOS（iPhone UA）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_IPHONE), "beta"),
        ("Android 不误判成 iOS/Linux（走百分比档）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_ANDROID), "stable"),
        ("macOS 没有对应规则（走百分比档）",
         dict(path="/release", cookie=f"uid={stable_uid}", ua=UA_MAC), "stable"),
        ("第一条命中生效：cookie 规则压在 header 规则前面",
         dict(path="/release", cookie=f"uid={stable_uid}; beta=1",
              headers={"X-Channel": "Vip"}), "beta"),
        ("所有条件都没命中：回到 default",
         dict(path="/release", cookie=f"uid={stable_uid}"), "stable"),
    ]
    bad = []
    for desc, kw, want in cases:
        st, kv, raw, _h = request(**kw)
        if st != 200 or kv.get("who") != want or kv.get("split") != want \
                or kv.get("served") != want:
            bad.append((desc, st, kv.get("who"), kv.get("split"), kv.get("served"), raw[:120]))
    check("条件/顺序/default 共 %d 种写法各自落到正确版本" % len(cases),
          not bad, str(bad[:4]))


def scenario_percent():
    """未命中条件的用户按 20% 分档：与参考哈希逐一对上、同一个人永远同一档。"""
    users = [f"pct-{i:04d}" for i in range(300)]
    seen, bad = Counter(), []
    for uid in users:
        st, kv, _raw, _h = request("/release", cookie=f"uid={uid}")
        want = percent_target(uid)
        if st != 200 or kv.get("who") != want or kv.get("split") != want:
            bad.append((uid, st, kv.get("who"), want))
            continue
        seen[want] += 1
    check("300 个无特征用户与参考哈希逐一对上，一个不差",
          not bad and set(seen) == {"stable", "beta"},
          f"异常={bad[:3]} 分布={dict(seen)}")
    share = 100.0 * seen["beta"] / max(1, sum(seen.values()))
    check("观察到的百分比档贴近声明的 20%", 14.0 <= share <= 26.0, f"beta {share:.1f}%")

    sticky_bad = []
    for uid in users[:60]:
        st0, kv0, raw0, _ = request("/release", cookie=f"uid={uid}")
        first = kv0.get("who")
        for _ in range(2):
            st, kv, raw, _ = request("/release", cookie=f"uid={uid}")
            again = kv.get("who")
            if again != first:
                # 带上状态码与体：分不清"换了档"和"这次根本没拿到灰度响应"的失败无法追
                sticky_bad.append((uid, first, f"{st}/{again}", raw[:80]))
    check("同一个用户连续访问永远同一档（粘性键是 cookie_uid+地址）",
          not sticky_bad, str(sticky_bad[:4]))

    before = targets(metrics_text(), "release")
    rounds = {"stable": 0, "beta": 0}
    for uid in users[:80]:
        who = request("/release", cookie=f"uid={uid}")[1].get("who")
        rounds[who] = rounds.get(who, 0) + 1
    after = targets(metrics_text(), "release")
    delta = {k: after.get(k, 0.0) - before.get(k, 0.0) for k in set(after) | set(before)}
    want = {k: float(v) for k, v in rounds.items()}
    check("指标账本与实测落点逐路相等（运维的比例表就是它）",
          all(abs(delta.get(k, 0.0) - want[k]) < 1e-9 for k in want)
          and abs(sum(delta.values()) - sum(want.values())) < 1e-9,
          f"增量={delta} 实测={want}")


def scenario_blocked_cookie():
    """用户清掉灰度标记（空 cookie）后必须回得到默认版本，而不是永远留在灰度里。"""
    uid = uid_for("stable", "clear")
    st, kv, _raw, _h = request("/release", cookie=f"uid={uid}; beta=")
    check("把 beta cookie 清成空值后回到默认版本（不会被永久钉在灰度）",
          st == 200 and kv.get("who") == "stable", f"{st} {kv.get('who')}")


def scenario_header_variable():
    """灰度变量不只在主机位可用：目标写死时也能作为请求头转发。"""
    stable_uid = uid_for("stable", "hdr")
    st1, _kv1, raw1, _h1 = request("/hdr", cookie=f"uid={stable_uid}")
    st2, _kv2, raw2, _h2 = request("/hdr", cookie=f"uid={stable_uid}; beta=1")
    check("$release 作为 proxy_set_header 转发也解析成选中的版本",
          st1 == 200 and st2 == 200 and "release=stable" in raw1 and "release=beta" in raw2,
          f"{st1}/{st2} {raw1[:60]!r} {raw2[:60]!r}")
    check("默认版本的头转发是 stable", st1 == 200 and "release=stable" in raw1, raw1[:80])
    check("命中 cookie 灰度时同一个头变成 beta", st2 == 200 and "release=beta" in raw2, raw2[:80])


def scenario_cache():
    """每个版本各成缓存条目；命中时归属仍可见、served 为空。"""
    beta_uid = uid_for("beta", "cache")
    stable_uid = uid_for("stable", "cache")
    path = "/cached?item=shared"
    st1, kv1, _r1, h1 = request(path, cookie=f"uid={beta_uid}")
    st2, kv2, _r2, h2 = request(path, cookie=f"uid={stable_uid}")
    before = targets(metrics_text(), "release")
    st3, kv3, _r3, h3 = request(path, cookie=f"uid={beta_uid}")
    st4, kv4, _r4, h4 = request(path, cookie=f"uid={stable_uid}")
    after = targets(metrics_text(), "release")

    check("两个版本的用户各自先 MISS、再 HIT",
          (h1.get("x-cache"), h3.get("x-cache"), h2.get("x-cache"), h4.get("x-cache"))
          == ("MISS", "HIT", "MISS", "HIT"),
          f"{h1.get('x-cache')}/{h3.get('x-cache')}/{h2.get('x-cache')}/{h4.get('x-cache')}")
    check("各自读到的是自己版本的页面（缓存没有串版本）",
          st1 == st2 == st3 == st4 == 200
          and kv1.get("who") == kv3.get("who") == "beta"
          and kv2.get("who") == kv4.get("who") == "stable",
          f"{kv1.get('who')}/{kv2.get('who')}/{kv3.get('who')}/{kv4.get('who')}")
    check("命中时归属仍然看得见：X-Split 有值、X-Split-Served 为空",
          h3.get("x-split") == "beta" and not h3.get("x-split-served")
          and h4.get("x-split") == "stable" and not h4.get("x-split-served"),
          f"beta {h3.get('x-split')!r}/{h3.get('x-split-served')!r} "
          f"stable {h4.get('x-split')!r}/{h4.get('x-split-served')!r}")
    check("缓存命中不产生分流账本增量（请求没交给任何节点）",
          targets(metrics_text(), "release") == after and before == after,
          f"{before} -> {targets(metrics_text(), 'release')}")


def scenario_failover():
    """灰度版本整池不可用：默认改投、off 不串台、显式退路只退指定版本。"""
    uid_auto = uid_for("stable", "auto")
    before = roles(metrics_text(), "dead_release")
    st1, kv1, _r1, _h1 = request("/auto", cookie=f"uid={uid_auto}; beta=1")
    r1 = roles(metrics_text(), "dead_release")
    st2, kv2, _r2, _h2 = request("/auto", cookie=f"uid={uid_auto}; beta=1")
    r2 = roles(metrics_text(), "dead_release")
    check("auto 第一问是这一路自己的失败（连上了但被拒），不计改投",
          st1 == 502 and r1["bled"] == before["bled"], f"{st1} {before} -> {r1}")
    check("auto 第二问起该路进摘除期，用户被改投到下一路并成功",
          st2 == 200 and kv2.get("who") == "alt",
          f"{st2} {kv2.get('who')} {kv2}")
    check("改投看得见：选中的是 deadAuto，实际接走的是 alt",
          kv2.get("split") == "deadAuto" and kv2.get("served") == "alt",
          f"split={kv2.get('split')!r} served={kv2.get('served')!r}")
    check("改投被记账：bled 增量 >= 1", r2["bled"] > r1["bled"], f"{r1} -> {r2}")

    uid_strict = uid_for("stable", "strict")
    before = roles(metrics_text(), "strict_release")
    st1, _kv1, _r1, _h1 = request("/strict", cookie=f"uid={uid_strict}; beta=1")
    st2, _kv2, _r2, _h2 = request("/strict", cookie=f"uid={uid_strict}; beta=1")
    after = roles(metrics_text(), "strict_release")
    check("off：这一路没人就是没人，第二问仍是 502",
          st1 == 502 and st2 == 502, f"{st1}/{st2}")
    check("off：一次都没有改投（bled 增量为 0），但失败按这一路记账（down > 0）",
          after["bled"] == before["bled"] and after["down"] > before["down"],
          f"{before} -> {after}")

    uid_exp = uid_for("stable", "explicit")
    before = roles(metrics_text(), "explicit_release")
    st1, _kv1, _r1, _h1 = request("/explicit", cookie=f"uid={uid_exp}; beta=1")
    st2, kv2, _r2, _h2 = request("/explicit", cookie=f"uid={uid_exp}; beta=1")
    after = roles(metrics_text(), "explicit_release")
    check("显式退路：第二问只退到声明的 alt 并成功",
          st1 == 502 and st2 == 200 and kv2.get("who") == "alt"
          and kv2.get("split") == "deadExplicit" and kv2.get("served") == "alt",
          f"{st1}/{st2} {kv2}")
    check("显式退路也记 bled", after["bled"] > before["bled"], f"{before} -> {after}")


def scenario_config_check(exe):
    """-t 必须否决写下去也不可能工作的灰度配置（这里只挑两条最有代表性的）。"""
    checks = [
        ("canary $rel { cookie beta beta; }", "缺少 default"),
        ("canary $rel { cookie beta beta; default stable; }\n"
         "server { listen 127.0.0.1:18389; location / { proxy_pass http://$rel; "
         "proxy_split_failover http://other; } }", "不是"),
    ]
    import tempfile
    bad = []
    for body, needle in checks:
        fd, path = tempfile.mkstemp(suffix=".conf", dir=os.path.join(ROOT, "conf"))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body + "\n")
            rel = os.path.relpath(path, ROOT)
            out = subprocess.run([exe, "-t", "-c", rel], cwd=ROOT, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace")
            blob = (out.stdout or "") + (out.stderr or "")
            if out.returncode == 0 or needle not in blob:
                bad.append((body.splitlines()[0], out.returncode, blob[-300:]))
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    check("-t 否决没有 default / 退路不是已声明版本的灰度配置", not bad, str(bad[:2]))


def main():
    exe = find_binary()
    for p in list(BE_PORTS.values()) + [DEAD_PORT]:
        if p != DEAD_PORT and wait_port(p, up=True, timeout=0.2):
            raise SystemExit(f"!! 端口 {p} 已被占用，先确认没有残留进程")
    if wait_port(DEAD_PORT, up=True, timeout=0.2):
        raise SystemExit(f"!! 端口 {DEAD_PORT} 是死池地址，不能有进程监听")
    shutil.rmtree(CACHE_DIR, ignore_errors=True)
    for f in (ERR_LOG, OUT_LOG):
        if os.path.exists(f):
            os.remove(f)

    for tag, port in BE_PORTS.items():
        BE[tag] = Backend(tag, port)
    proc = subprocess.Popen([exe, "-c", CONF_REL], cwd=ROOT,
                            stdout=open(OUT_LOG, "w"), stderr=subprocess.STDOUT)
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + ERR_LOG)
        print("=== 灰度发布 E2E：条件 / 比例 / 默认 / 改投 / 缓存 ===")
        scenario_conditions()
        scenario_percent()
        scenario_blocked_cookie()
        scenario_header_variable()
        scenario_cache()
        scenario_failover()
        scenario_config_check(exe)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        for b in BE.values():
            b.stop()

    passed = sum(1 for _n, ok in results if ok)
    print("\n==== 灰度发布 E2E: %d/%d passed ====" % (passed, len(results)))
    for n, ok in results:
        if not ok:
            print("FAILED:", n)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
