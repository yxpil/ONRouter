# -*- coding: utf-8 -*-
# WASM 网关插件 E2E —— 证明插件真的在请求链路上，而不是"模块能编译"。
#
# 断言全部从**客户端看到的结果**倒推：
#   access      缺 token 时 403、body 来自插件、后端一次都没被问；带 token 时放行，
#               且插件写回的请求头真的随转发到了后端（后端回显 verified=1）。
#   过滤器      上游的 200 被改成 202；上游的内部头被删；上游的体被截成前 5 字节；
#               没声明插件的 location 完全不受影响（同一后端、同一条响应）。
#   缓存        MISS 和 HIT 都过同一条过滤器：缓存只省掉回源，不省掉关口。
#   静态        静态文件同样过 header/body 过滤器。
#   fuel        死循环插件被指令预算拦住：请求 5xx、耗时在毫秒级、进程继续服务。
#   指标        /metrics 里每个插件/阶段的调用数、错误数、fuel 耗尽数与实测一致。
#   -t          未声明插件、阶段函数缺失、非法 fuel/memory、重复声明、未知选项一律否决。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/wasm_e2e.py
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "wasm_e2e.conf")
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "wasm_e2e_err.log")
OUT_LOG = os.path.join(LOG_DIR, "wasm_e2e_out.log")
CACHE_DIR = os.path.join(LOG_DIR, "wasm_cache")

GW, GW_PORT = "127.0.0.1", 18395
BE_PORT = 18396

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
BE = {}


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
    """要正面证据：-t 必须把编译好的 WASM 插件列出来。
    旧二进制对未知指令只告警仍退 0，光看退出码会把"根本没加载"当成通过。"""
    cands = [
        os.path.join(ROOT, p, n)
        for p in ("target/release", "target/debug")
        for n in ("onrouter.exe", "onrouter")
    ]
    have = [p for p in cands if os.path.exists(p)]
    if not have:
        raise SystemExit("!! build first: cargo build -p onrouter-server --bin onrouter")
    exe = max(have, key=os.path.getmtime)
    out = subprocess.run([exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    blob = (out.stdout or "") + (out.stderr or "")
    if out.returncode != 0 or "WASM 插件 authz" not in blob or "on_access" not in blob:
        raise SystemExit("!! %s 里没有编译好的 WASM 插件（-t 只告警不失败，必须看正面证据）：\n%s"
                         % (exe, blob[-1600:]))
    print("使用网关二进制：", exe)
    return exe


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, (ConnectionError, socket.timeout, OSError)):
            ThreadingHTTPServer.handle_error(self, request, client_address)


class Backend:
    """一个会记账的后端：每次被真正问到就 +1，并把网关转发过来的请求头原样回显。"""

    def __init__(self, port):
        self.served = 0
        self.paths = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                outer.served += 1
                outer.paths.append(self.path)
                body = (
                    f"HELLO from backend path={self.path} "
                    f"verified={self.headers.get('X-Wasm-Verified', '-')} "
                    f"token={self.headers.get('X-Gateway-Token', '-')}\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Backend-Secret", "internal-only")
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


def request(path, headers=None, method="GET"):
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}", headers=headers or {},
                                 method=method)
    started = time.time()
    try:
        resp = _opener.open(req, timeout=20)
        code, raw, hdrs = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        code, raw, hdrs = e.code, e.read(), e.headers
    elapsed = time.time() - started
    return code, raw.decode(errors="replace"), {k.lower(): v for k, v in hdrs.items()}, elapsed


def metrics_text():
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}/metrics")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def _grab(text, family):
    pat = re.compile(r'onrouter_' + family + r'\{plugin="([^"]+)",phase="([^"]+)"\}\s+([0-9.]+)')
    return {(m.group(1), m.group(2)): float(m.group(3)) for m in pat.finditer(text)}


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


def scenario_access():
    """认证在边缘做完：没有 token 的业务请求连后端都到不了；有 token 的带上身份。"""
    before = BE["app"].served
    code, body, hdrs, _ = request("/guarded")
    check("access：缺 token 时插件就地 403（状态与体都来自插件）",
          code == 403 and body == "wasm denied: token required", f"{code} {body!r}")
    check("access：被拒的请求一次都没有到达后端", BE["app"].served == before,
          f"后端 served {before} -> {BE['app'].served}")

    code, body, hdrs, _ = request("/guarded", {"X-Gateway-Token": "s3cr3t"})
    check("access：带 token 放行，后端真的收到了插件写回的 X-Wasm-Verified: 1",
          code == 200 and "verified=1" in body and "token=s3cr3t" in body,
          f"{code} {body!r}")
    check("access：没有 header 过滤器的地方，上游响应原样透传（状态 200、内部头在）",
          code == 200 and hdrs.get("x-backend-secret") == "internal-only"
          and "x-wasm-header-filter" not in hdrs,
          f"{code} secret={hdrs.get('x-backend-secret')!r}")


def scenario_filters():
    """上游的响应被过滤器改写：状态、头（增/删）、体。"""
    code, body, hdrs, _ = request("/filtered")
    check("header_filter：状态从 200 改成 202", code == 202, str(code))
    check("header_filter：加上 X-Wasm-Header-Filter: on", hdrs.get("x-wasm-header-filter") == "on",
          str(hdrs.get("x-wasm-header-filter")))
    check("header_filter：删掉了上游的内部头 X-Backend-Secret",
          "x-backend-secret" not in hdrs, str(hdrs.get("x-backend-secret")))
    check("body_filter：客户端拿到的体是上游体的前 5 字节", body == "HELLO", repr(body))

    code, body, hdrs, _ = request("/plain")
    check("没有声明过滤器的 location 完全不受影响（200 / 完整体 / 内部头仍在）",
          code == 200 and body.startswith("HELLO from backend") and "--" not in body
          and hdrs.get("x-backend-secret") == "internal-only",
          f"{code} {body[:40]!r} secret={hdrs.get('x-backend-secret')!r}")


def scenario_cache():
    """缓存命中仍然要过过滤器：省的是回源，不是关口。"""
    before = BE["app"].served
    code1, body1, h1, _ = request("/cached")
    code2, body2, h2, _ = request("/cached")
    check("缓存：第一问 MISS、第二问 HIT", (h1.get("x-cache"), h2.get("x-cache")) == ("MISS", "HIT"),
          f"{h1.get('x-cache')}/{h2.get('x-cache')}")
    check("缓存：两问都过了 body/header 过滤器（202 + 截断体 + 加头 + 删头）",
          code1 == code2 == 202 and body1 == body2 == "HELLO"
          and h2.get("x-wasm-header-filter") == "on" and "x-backend-secret" not in h2,
          f"{code1}/{code2} {body1!r}/{body2!r}")
    check("缓存：第二问没有再回源（后端只被问了一次）", BE["app"].served == before + 1,
          f"后端 served {before} -> {BE['app'].served}")


def scenario_static():
    code, body, hdrs, _ = request("/static.txt")
    check("静态文件也过 header_filter（202 + 标记头）",
          code == 202 and hdrs.get("x-wasm-header-filter") == "on", f"{code} {hdrs}")
    check("静态文件也过 body_filter（只剩前 5 字节）", body == "HELLO", repr(body))


def scenario_fuel():
    before = BE["app"].served
    code, body, _h, elapsed = request("/fuel")
    check("fuel：死循环插件被指令预算拦下，请求按 5xx 收口", code == 500, str(code))
    check("fuel：拦截发生在毫秒级（不是等超时）", elapsed < 3.0, f"{elapsed:.3f}s")
    check("fuel：失败请求没有到达后端", BE["app"].served == before,
          f"后端 served {before} -> {BE['app'].served}")
    code, _body, _h, _ = request("/plain")
    check("fuel：一次插件事故没有影响后续请求（进程仍在服务）", code == 200, str(code))


def scenario_metrics():
    txt = metrics_text()
    inv = _grab(txt, "wasm_invocations_total")
    err = _grab(txt, "wasm_errors_total")
    fuel = _grab(txt, "wasm_fuel_exhausted_total")

    check("指标：authz 的 access 调用数 = 2（拒绝一次 + 放行一次）",
          inv.get(("authz", "access")) == 2, str({k: v for k, v in inv.items() if k[0] == "authz"}))
    check("指标：hf/bf 的过滤器调用覆盖代理、缓存 MISS/HIT、静态（各 4 次）",
          inv.get(("hf", "header_filter")) == 4 and inv.get(("bf", "body_filter")) == 4,
          f"hf={inv.get(('hf', 'header_filter'))} bf={inv.get(('bf', 'body_filter'))}")
    check("指标：spin 记一次 access 错误，并单独记 fuel 耗尽",
          err.get(("spin", "access")) == 1 and fuel.get(("spin", "access")) == 1,
          f"errors={err} fuel={fuel}")
    denied = re.search(r'onrouter_wasm_denied_total\{plugin="authz"\}\s+([0-9.]+)', txt)
    check("指标：authz 的 denied 计数 = 1", denied and float(denied.group(1)) == 1,
          denied.group(1) if denied else "缺失")


def scenario_config_check(exe):
    """-t 必须否决"写得出来但跑不起来"的插件配置。"""
    cases = [
        ("server { listen 127.0.0.1:18399; location / { access_by_wasm ghost; } }",
         "未声明的 WASM 插件"),
        ("wasm_plugin bf wasm/body_filter.wat;\n"
         "server { listen 127.0.0.1:18399; location / { access_by_wasm bf; } }",
         "没有导出 on_access()"),
        ("wasm_plugin p wasm/fuel.wat fuel=0;\n"
         "server { listen 127.0.0.1:18399; }", "不是正整数"),
        ("wasm_plugin p wasm/fuel.wat memory=1k;\n"
         "server { listen 127.0.0.1:18399; }", "最小 64k"),
        ("wasm_plugin p wasm/fuel.wat fuel=1;\nwasm_plugin p wasm/authz.wat;\n"
         "server { listen 127.0.0.1:18399; }", "重复声明"),
        ("wasm_plugin p wasm/fuel.wat turbo=1;\nserver { listen 127.0.0.1:18399; }",
         "不认识选项"),
    ]
    import tempfile
    bad = []
    for body, needle in cases:
        fd, path = tempfile.mkstemp(suffix=".conf", dir=os.path.join(ROOT, "conf"))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body + "\n")
            rel = os.path.relpath(path, ROOT)
            out = subprocess.run([exe, "-t", "-c", rel], cwd=ROOT, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace")
            blob = (out.stdout or "") + (out.stderr or "")
            if out.returncode == 0 or needle not in blob:
                bad.append((body.splitlines()[0], out.returncode, blob[-260:]))
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    check("-t 否决未声明插件/缺导出/非法 fuel/过小内存/重名/未知选项", not bad,
          str(bad[:2]))


def main():
    exe = find_binary()
    if wait_port(BE_PORT, up=True, timeout=0.2):
        raise SystemExit(f"!! 端口 {BE_PORT} 已被占用，先确认没有残留进程")
    shutil.rmtree(CACHE_DIR, ignore_errors=True)
    for f in (ERR_LOG, OUT_LOG):
        if os.path.exists(f):
            os.remove(f)

    BE["app"] = Backend(BE_PORT)
    proc = subprocess.Popen([exe, "-c", CONF_REL], cwd=ROOT,
                            stdout=open(OUT_LOG, "w"), stderr=subprocess.STDOUT)
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + ERR_LOG)
        print("=== WASM 网关插件 E2E：access / 过滤器 / 缓存 / 静态 / fuel / 指标 ===")
        scenario_access()
        scenario_filters()
        scenario_cache()
        scenario_static()
        scenario_fuel()
        scenario_metrics()
        scenario_config_check(exe)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        BE["app"].stop()

    passed = sum(1 for _n, ok in results if ok)
    print("\n==== WASM 网关插件 E2E: %d/%d passed ====" % (passed, len(results)))
    for n, ok in results:
        if not ok:
            print("FAILED:", n)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
