# nginx `expires` 的端到端验证 —— 静态 / 反代 / 缓存 / Lua（含流式）四条响应路径
#
# 场景：小网站与选课系统这类静态站把网关当 CDN 边缘，资产要"缓存一年"，
# 登录页与 API 要"不许缓存"。nginx 用一个 `expires` 就写完的事，如果网关只认
# add_header，配置会带着"未知指令（已忽略）"的告警静默上线：响应里一个过期头都没有，
# 浏览器每次都回源，而运维以为已经缓存住了。
#
# 判定口径按 nginx：
#   * 只在可缓存的状态码上改写（404/500 一字不动）；
#   * 正时长 → max-age + 未来的 Expires；负时长 / 已过去的 @时刻 → no-cache；
#   * max → public, max-age=315360000；epoch → no-store + 1970；文本 → 原样进 Cache-Control；
#   * location 写了就整条替换 server 的，`off` 是显式关闭而不是"没写"；
#   * 网关的策略覆盖源站自己那份 Cache-Control（nginx 的 header filter 同样如此）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/expires_e2e.py
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "expires.conf")
SITE = os.path.join(ROOT, "public_expires")
GW = 18584
ORIGIN = 18585
GW_SCHOOL = 18589
GW_OVERRIDE = 18590
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:220])


def t_key_checks(exe):
    """-t 对限流 key 的取舍：请求期就有值的维度必须收下，判定时刻取不到值的必须否决。
    （计数行为不在这里判——那是 tools/limit_key_e2e.py 的 35 项。）"""
    nl = chr(10)
    q = chr(34)
    head = ("error_log " + q + "logs/expires_t_err.log" + q + " warn;" + nl
            + "pid " + q + "logs/expires_t.pid" + q + ";" + nl)

    def t_conf(zone_key):
        frag = (head + "limit_req_zone " + zone_key + " zone=tk:1m rate=10r/s;" + nl
                + "server { listen 127.0.0.1:18591; server_name t.expires.test;"
                + " location / { limit_req zone=tk; return 200 " + q + "ok" + q + "; } }" + nl)
        tp = os.path.join(ROOT, "conf", "expires_t.conf")
        with open(tp, "w", encoding="utf-8", newline=nl) as f:
            f.write(frag)
        try:
            r = subprocess.run([exe, "-t", "-c", "conf/expires_t.conf"], cwd=ROOT,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        finally:
            try:
                os.remove(tp)
            except OSError:
                pass

    for good in ["$remote_addr", "$http_x_api_key", "$cookie_sid", "$arg_token"]:
        rc, out = t_conf(good)
        check("-t 接受限流 key " + good, rc == 0, out[-160:])
    for bad in ["$status", "$request_body", "$server_name", "$1abc"]:
        rc, out = t_conf(bad)
        check("-t 否决限流 key " + bad + "（判定时刻取不到值）", rc != 0, out[-160:])


def build_site():
    """每个 expires 写法各占一个真实目录：root 是 URI 拼接，不是别名。"""
    os.makedirs(os.path.join(ROOT, "public_course", "static"), exist_ok=True)
    with open(os.path.join(ROOT, "public_course", "index.html"), "w", encoding="utf-8", newline=chr(10)) as f:
        f.write("<title>school</title>" + chr(10))
    with open(os.path.join(ROOT, "public_course", "static", "app.js"), "w", encoding="utf-8", newline=chr(10)) as f:
        f.write("// bundle" + chr(10))
    for d in ("base", "max", "epoch", "off", "neg", "text", "tod"):
        os.makedirs(os.path.join(SITE, d), exist_ok=True)
        with open(os.path.join(SITE, d, "index.html"), "w", encoding="utf-8", newline="\n") as f:
            f.write("<title>expires case " + d + "</title>\n")


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


# ------------------------------------------------------------------ 源站
class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # 客户端/网关提前断开是预期内的，不该把回溯打到测试输出里
        pass


def start_origin():
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"origin-body\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            # 源站自己声明 7 秒：网关的 expires 必须覆盖它（nginx 的 header filter 语义）
            self.send_header("Cache-Control", "max-age=7")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = Quiet(("127.0.0.1", ORIGIN), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def get(path, port=GW):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        r = _opener.open(req, timeout=8)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def hdrs(path, port=GW):
    st, h, b = get(path, port)
    return st, h.get("cache-control"), h.get("expires"), b, h


def to_epoch(s):
    try:
        return parsedate_to_datetime(s).timestamp()
    except Exception:  # noqa: BLE001
        return None


def main():
    exe = find_binary()
    # -t：expires 不能再是"未知指令（已忽略）"
    t = subprocess.run([exe, "-t", "-c", "conf/expires.conf"], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    tout = (t.stdout or "") + (t.stderr or "")
    check("-t 通过", t.returncode == 0, tout[-200:])
    check("-t 不再把 expires 当未知指令", "未知指令 'expires'" not in tout, tout[-200:])

    build_site()
    t_key_checks(exe)

    origin = start_origin()
    logf = open(os.path.join(ROOT, "logs", "expires_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            if get("/ping")[0] == 200:
                break
            time.sleep(0.1)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/expires_out.log")
        print("网关已就绪", GW)

        now = time.time()

        # 1) 静态：server 级 1h 被 location 继承
        st, cc, ex, body, _ = hdrs("/base/index.html")
        check("静态 200 且有响应体", st == 200 and len(body) > 0, st)
        check("静态继承 server 的 expires 1h → max-age=3600", cc == "max-age=3600", cc)
        e = to_epoch(ex)
        check("静态的 Expires 是 now+3600（IMF 格式，可被解析）",
              e is not None and abs((e - now) - 3600) < 90, ex)

        # 2) max / epoch / 文本 / 负值
        _, cc, ex, _, _ = hdrs("/max/index.html")
        check("expires max → public, max-age=315360000",
              cc == "public, max-age=315360000", cc)
        e = to_epoch(ex)
        # 315360000 秒是十年（nginx 的 max 就是这个常量），别把它当成一百年
        check("expires max 的 Expires 在十年后", e and abs((e - now) - 315360000) < 90, ex)

        _, cc, ex, _, _ = hdrs("/epoch/index.html")
        check("expires epoch → no-store", cc == "no-store", cc)
        check("expires epoch 的 Expires 是 1970",
              (ex or "").startswith("Thu, 01 Jan 1970"), ex)

        _, cc, ex, _, _ = hdrs("/text/index.html")
        check("裸文本原样作为 Cache-Control", cc == "private, no-store", cc)
        check("裸文本写法不动 Expires", ex is None, ex)

        _, cc, ex, _, _ = hdrs("/neg/index.html")
        check("负时长 → no-cache", cc == "no-cache", cc)
        e = to_epoch(ex)
        check("负时长的 Expires 在过去", e is not None and e < now, ex)

        # 3) @时刻：目标就是当天 UTC 的 23:59:59
        _, cc, ex, _, _ = hdrs("/tod/index.html")
        day = int(now) - int(now) % 86400
        want = day + 23 * 3600 + 59 * 60 + 59
        e = to_epoch(ex)
        check("@23:59:59 的 Expires 落在当天那个时刻", e is not None and abs(e - want) < 5, f"{ex} 期望 {want}")
        if want > now:
            left = int((cc or "").split("=")[-1] or -1)
            check("@时刻还没到 → max-age 是剩余秒数", abs(left - (want - now)) <= 3, cc)
        else:
            check("@时刻已过 → no-cache", cc == "no-cache", cc)

        # 4) off：显式关闭，不是"没写"
        _, cc, ex, _, _ = hdrs("/off/index.html")
        check("expires off 既不写 Cache-Control 也不写 Expires",
              cc is None and ex is None, f"{cc!r} {ex!r}")

        # 5) 反代：网关覆盖源站自己那份
        st, cc, ex, body, _ = hdrs("/prox/index.html")
        check("反代 200 且回源体正常", st == 200 and body.startswith(b"origin-body"), (st, body[:40]))
        check("反代覆盖源站的 max-age=7", cc == "max-age=3600", cc)

        # 6) 缓存路径：MISS 与 HIT 都要带上同一个策略
        st1, cc1, _, _, h1 = hdrs("/cached/index.html")
        st2, cc2, _, _, h2 = hdrs("/cached/index.html")
        check("缓存 MISS 落 30m 策略", cc1 == "max-age=1800", f"{cc1} status={h1.get('x-cache-status')}")
        check("第二次是命中（证明真的走了缓存这条路）",
              cc2 == "max-age=1800" and (h2.get("x-cache-status") or "").upper() in ("HIT", "STALE", "REVALIDATED"),
              f"{cc2} status={h2.get('x-cache-status')}")

        # 7) Lua：缓冲与流式两条都要落（流式的头在 Head 帧就定型，最容易漏）
        _, cc, _, body, _ = hdrs("/lua")
        check("content_by_lua 继承 server 的 1h", cc == "max-age=3600", cc)
        _, cc, _, body, _ = hdrs("/luastream")
        check("flush 过的流式响应同样落 expires", cc == "max-age=3600", f"{cc} body={body[:40]!r}")

        # 8) return 200
        _, cc, _, body, _ = hdrs("/ret")
        check("return 200 也落过期头", cc == "max-age=3600" and body == b"ret-ok\n", cc)

        # 9) 不可缓存的状态码：一字不动（404 页面不能被说成能存一小时）
        st, cc, ex, _, _ = hdrs("/base/does-not-exist.html")
        check("404 不落 expires", st == 404 and cc is None and ex is None, (st, cc, ex))
        st, cc, ex, _, _ = hdrs("/off/none.html")
        check("off 之下 404 同样干净", st == 404 and cc is None, (st, cc))
        # nginx 的 safe_status 列表里**有 204**（ngx_http_headers_filter_module.c），
        # 空响应也照样写过期头；过去我们把它当成"不可缓存"跳过了。
        st, cc, ex, body, _ = hdrs("/nocontent")
        check("204 按 nginx 的口径落过期头", st == 204 and cc == "max-age=3600"
              and ex is not None, (st, cc, ex))
        check("204 的响应体仍然是空的（写了头不等于造了 body）", body == b"", len(body))
        # 10) 学校/选课站点的形状：一台没有站点级兜底的 vhost，每条路由各自决定
        _, cc, ex, _, _ = hdrs("/static/app.js", GW_SCHOOL)
        check("选课站资产 expires max → 十年", cc == "public, max-age=315360000", cc)
        e = to_epoch(ex)
        check("选课站资产的 Expires 与 max-age 一致", e and abs((e - now) - 315360000) < 90, ex)
        _, cc, ex, _, _ = hdrs("/login", GW_SCHOOL)
        check("登录页没有任何 expires 规则 → 不落过期头", cc is None and ex is None, f"{cc!r} {ex!r}")
        _, cc, ex, _, _ = hdrs("/api/courses", GW_SCHOOL)
        check("API 用 expires off → 不干预，源站自己那份透传", cc == "max-age=7", cc)
        st, cc, ex, _, _ = hdrs("/static/nope.js", GW_SCHOOL)
        check("选课站 404 不被说成能存一年", st == 404 and cc is None and ex is None, (st, cc, ex))

        # 11) location 与 server 同时写：location 说了算（含写成 off 关掉）
        _, cc, ex, _, _ = hdrs("/ping", GW_OVERRIDE)
        check("server 级 expires 30d → max-age=2592000", cc == "max-age=2592000", cc)
        _, cc, ex, _, _ = hdrs("/off/index.html", GW_OVERRIDE)
        check("location 的 expires off 关掉 server 的 30d（不是叠加）",
              cc is None and ex is None, f"{cc!r} {ex!r}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        origin.shutdown()

    ok = sum(1 for _, r in results if r)
    print(f"\n{ok}/{len(results)} 通过")
    if ok != len(results):
        print("失败项：")
        for name, r in results:
            if not r:
                print("  -", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
