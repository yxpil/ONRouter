# -*- coding: utf-8 -*-
# cache_header_gap E2E —— 缓存/响应头与 nginx 的语义差，全部用真实流量断言：
#   G1 add_header 的变量展开（nginx: "Parameter value can contain variables."）
#   G2 变量与字面文本混写
#   G3 $upstream_cache_status 存在；POST 这类非缓存方法下是空串
#   G4 proxy_cache_bypass 多值：任一值非空且非 "0" 才跳过读取
#   G4b 表达式里的"此刻没值的变量"不能因为变量名被当字面量而永远为真
#   G5 proxy_no_cache 多值/空值：不给 ?nc=1 时照常写入
#   G6/G7 proxy_ignore_headers Cache-Control / Set-Cookie（并对照不忽略时）
#   G8 被忽略的头仍然原样透传给客户端
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/cache_header_gap_e2e.py
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "cache_header_gap.conf")

GW_PORT = 18360
BACKEND_PORT = 18361
BASE = f"http://127.0.0.1:{GW_PORT}"

results = []
lock = threading.Lock()
count = {}


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


def request(path, method="GET", timeout=15):
    req = urllib.request.Request(BASE + path, method=method)
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def version_of(body):
    m = re.search(r"\bv=(\d+)\b", body)
    return int(m.group(1)) if m else None


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self):
        path = self.path.split("?")[0]
        with lock:
            count[path] = count.get(path, 0) + 1
            n = count[path]
        body = f"v={n} path={path}\n".encode()
        extra = []
        if path.startswith("/cc/"):
            # 上游明确要求不缓存
            extra.append(("Cache-Control", "no-store"))
        elif path.startswith("/cookie/"):
            extra.append(("Set-Cookie", "sid=abc; Path=/"))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve

    def log_message(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    backend = QuietServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    out = open(os.path.join(ROOT, "logs", "gap_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/ping", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)
        if not ready:
            check("网关启动", False, "见 logs/gap_out.log")
            return 1

        # ---- G1/G2/G8 add_header 变量展开 ----
        st, h, _ = request("/hdr/?x=1", method="GET")
        check("G1 add_header 展开 $remote_addr", hdr(h, "X-Addr") == "127.0.0.1",
              f"X-Addr={hdr(h, 'X-Addr')!r}")
        check("G1 add_header 展开 $request_method", hdr(h, "X-Meth") == "GET",
              f"X-Meth={hdr(h, 'X-Meth')!r}")
        check("G1 缺失的 $arg_ 展开为空串（不是字面量）", hdr(h, "X-Empty") == "",
              f"X-Empty={hdr(h, 'X-Empty')!r}")
        check("G1 缺失的 $cookie_ 展开为空串", hdr(h, "X-Cookie") == "",
              f"X-Cookie={hdr(h, 'X-Cookie')!r}")
        check("G1 非 nginx 变量的名字保留字面量", hdr(h, "X-Unk") == "$no_such_var_xyz",
              f"X-Unk={hdr(h, 'X-Unk')!r}")
        st, h, _ = request("/hdr-lit/")
        check("G2 变量与字面文本混写只展开变量", hdr(h, "X-Mix") == "127.0.0.1/static",
              f"X-Mix={hdr(h, 'X-Mix')!r}")
        check("G2b $host 去端口（nginx：要端口用 $http_host/$server_port）",
              hdr(h, "X-Host") == "127.0.0.1" and hdr(h, "X-Raw-Host") == "127.0.0.1:18360",
              f"X-Host={hdr(h, 'X-Host')!r} X-Raw-Host={hdr(h, 'X-Raw-Host')!r}")

        # ---- G3 $upstream_cache_status ----
        _, h1, _ = request("/cs/t1")
        _, h2, _ = request("/cs/t1")
        check("G3 首次请求 $upstream_cache_status=MISS", hdr(h1, "X-Cs") == "MISS",
              f"X-Cs={hdr(h1, 'X-Cs')!r}")
        check("G3 第二次 HIT", hdr(h2, "X-Cs") == "HIT", f"X-Cs={hdr(h2, 'X-Cs')!r}")
        _, hp, _ = request("/cs/t1", method="POST")
        check("G3 POST（非缓存方法）变量为空串", hdr(hp, "X-Cs") == "",
              f"X-Cs={hdr(hp, 'X-Cs')!r}")

        # ---- G4 proxy_cache_bypass 多值 ----
        _, ha, _ = request("/bypass2/t2")
        _, hb, _ = request("/bypass2/t2")
        check("G4 无参数第二次 HIT", hdr(hb, "x-cache-status") == "HIT",
              f"tag={hdr(hb, 'x-cache-status')!r}")
        _, h0, _ = request("/bypass2/t2?a=0&b=0")
        check("G4 两个值都是 \"0\" → 不跳过", hdr(h0, "x-cache-status") == "HIT",
              f"tag={hdr(h0, 'x-cache-status')!r}")
        _, hy, _ = request("/bypass2/t2?a=0&b=1")
        check("G4 第二个值非空 → 跳过读取", hdr(hy, "x-cache-status") == "BYPASS",
              f"tag={hdr(hy, 'x-cache-status')!r}")
        _, hx, _ = request("/bypass2/t2?a=1&b=0")
        check("G4 第一个值非空 → 跳过读取", hdr(hx, "x-cache-status") == "BYPASS",
              f"tag={hdr(hx, 'x-cache-status')!r}")

        # ---- G4b 此刻没有值的变量不能永远为真 ----
        request("/bypass3/t3")
        _, h3, _ = request("/bypass3/t3")
        check("G4b 全空的 bypass 表达式不许永远跳过读取", hdr(h3, "x-cache-status") == "HIT",
              f"tag={hdr(h3, 'x-cache-status')!r}")

        # ---- G5 proxy_no_cache：nginx 文档只禁止"保存"，读取不受影响 ----
        _, m1, b1 = request("/nocache2/t4?nc=1")
        _, m2, b2 = request("/nocache2/t4")
        check("G5 ?nc=1 的响应不写入（随后普通请求仍 MISS，且回源了第二次）",
              hdr(m1, "x-cache-status") == "BYPASS"
              and hdr(m2, "x-cache-status") == "MISS"
              and version_of(b2) == version_of(b1) + 1,
              f"t1={hdr(m1, 'x-cache-status')!r} t2={hdr(m2, 'x-cache-status')!r} "
              f"v={version_of(b1)}/{version_of(b2)}")
        _, m3, b3 = request("/nocache2/t4")
        _, m4, b4 = request("/nocache2/t4")
        check("G5 不带 nc 时照常写入（第二次 HIT）",
              hdr(m4, "x-cache-status") == "HIT" and version_of(b4) == version_of(b3),
              f"t={hdr(m4, 'x-cache-status')!r} v={version_of(b3)}/{version_of(b4)}")

        # ---- G6/G7 proxy_ignore_headers ----
        request("/ignore-cc/t5")
        _, ig, big = request("/ignore-cc/t5")
        check("G6 忽略 Cache-Control 后 no-store 响应也能缓存",
              hdr(ig, "x-cache-status") == "HIT", f"tag={hdr(ig, 'x-cache-status')!r}")
        check("G8 被忽略的头仍然透传给客户端",
              (hdr(ig, "Cache-Control") or "").lower().startswith("no-store"),
              f"CC={hdr(ig, 'Cache-Control')!r}")
        _, _, body_ig = request("/ignore-cc/t5c")
        request("/noignore-cc/t5")
        _, ni, _ = request("/noignore-cc/t5")
        check("G6 对照：不忽略时 no-store 拒绝缓存", hdr(ni, "x-cache-status") != "HIT",
              f"tag={hdr(ni, 'x-cache-status')!r}")

        request("/ignore-cookie/t6")
        _, ic, _ = request("/ignore-cookie/t6")
        check("G7 忽略 Set-Cookie 后带 Cookie 的响应也能缓存",
              hdr(ic, "x-cache-status") == "HIT", f"tag={hdr(ic, 'x-cache-status')!r}")
        check("G7 被忽略的 Set-Cookie 仍然透传", (hdr(ic, "Set-Cookie") or "").startswith("sid="),
              f"SC={hdr(ic, 'Set-Cookie')!r}")
        request("/noignore-cookie/t6")
        _, nc, _ = request("/noignore-cookie/t6")
        check("G7 对照：不忽略时 Set-Cookie 阻断写入", hdr(nc, "x-cache-status") != "HIT",
              f"tag={hdr(nc, 'x-cache-status')!r}")

        err_path = os.path.join(ROOT, "conf", "logs", "gap_err.log")
        with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
            err = fh.read()
        check("错误日志里没有 panic/回溯",
              "panicked" not in err and "traceback" not in err.lower(), err[-300:])
        check("proxy_ignore_headers 被识别（不再报未知指令）",
              "proxy_ignore_headers" not in err, err[-300:])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        out.close()
        backend.shutdown()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== 缓存/响应头语义 E2E: {passed}/{len(results)} passed ====")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
