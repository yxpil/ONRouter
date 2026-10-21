# -*- coding: utf-8 -*-
# 后端韧性 E2E：被动摘除 / 惰性重加入 / 熔断器。
#
# 不按指令打钩，只看运维会问的三句话：
#   1) 一台后端挂了，用户还看不看得见错误？（pair：默认换节点，全程 200）
#   2) 挂掉的那台会不会被一直白喂流量？恢复后要不要重启网关才能加回？
#      （摘除期内只按 lazy_rejoin 的间隔、由真实请求顺带探测；恢复后自动回到轮询）
#   3) 一个已经宕机的后端会不会在每个请求上继续烧连接超时？
#      （breaker：连续失败后打开，open 期内快速失败；到期半开探针，成功即闭合）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/resilience_e2e.py
import os
import re
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
CONF_REL = os.path.join("conf", "resilience_e2e.conf")
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ERR_LOG = os.path.join(LOG_DIR, "resilience_e2e_err.log")
OUT_LOG = os.path.join(LOG_DIR, "resilience_e2e_out.log")

GW, GW_PORT = "127.0.0.1", 18400
PORT_A, PORT_B, PORT_CB = 18401, 18402, 18403

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
HITS = {"a": 0, "b": 0, "cb": 0}
LOCK = threading.Lock()
BE = {}


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_binary():
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
    if out.returncode != 0 or "lazy_rejoin 1s" not in blob or "circuit_breaker errors=2" not in blob:
        raise SystemExit("!! %s 里没有这份韧性配置（-t 必须把两行自述打出来）：\n%s"
                         % (exe, blob[-1400:]))
    print("使用网关二进制：", exe)
    return exe


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, (ConnectionError, socket.timeout, OSError)):
            ThreadingHTTPServer.handle_error(self, request, client_address)


class Backend:
    def __init__(self, tag, port):
        self.tag, self.port = tag, port
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                with LOCK:
                    HITS[outer.tag] += 1
                body = f"who={outer.tag}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                # 不复用连接：否则 stop() 之后网管仍握着的空闲长连接会替"已下线"的后端
                # 继续回包，把"节点已摘除"这件事演成假通过。
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = QuietServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def request(path):
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}{path}",
                                 headers={"Connection": "close"})
    try:
        resp = _opener.open(req, timeout=20)
        code, raw = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return 0, str(e)
    return code, raw


def metrics_text():
    req = urllib.request.Request(f"http://{GW}:{GW_PORT}/metrics")
    return _opener.open(req, timeout=20).read().decode(errors="replace")


def lazy_probes(text, server):
    m = re.search(
        r'onrouter_upstream_lazy_probes_total\{upstream="pair",server="' + re.escape(server)
        + r'"\}\s+([0-9.]+)', text)
    return float(m.group(1)) if m else None


def circuit_state(text):
    m = re.search(
        r'onrouter_upstream_circuit_state\{upstream="breaker",server="127\.0\.0\.1:18403"\}\s+([0-9.]+)',
        text)
    return int(float(m.group(1))) if m else None


def circuit_trips(text):
    m = re.search(
        r'onrouter_upstream_circuit_trips_total\{upstream="breaker",server="127\.0\.0\.1:18403"\}\s+([0-9.]+)',
        text)
    return float(m.group(1)) if m else None


def upstream_result(text, server, result):
    m = re.search(
        r'onrouter_upstream_requests_total\{upstream="pair",server="' + re.escape(server)
        + r'",result="' + result + r'"\}\s+([0-9.]+)', text)
    return float(m.group(1)) if m else None


def server_available(text, upstream, server):
    m = re.search(
        r'onrouter_upstream_server_available\{upstream="' + re.escape(upstream)
        + r'",server="' + re.escape(server) + r'"\}\s+([0-9.]+)', text)
    return int(float(m.group(1))) if m else None


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
        time.sleep(0.1)
    return False


# ==================== 场景 ====================


def scenario_lazy_rejoin():
    """两台后端杀掉一台：用户无感、宕机节点不白吃流量、恢复后自动加回。"""
    check("初始两台后端都在服务：两问分别落到 a / b",
          request("/pair") == (200, "who=a\n") and request("/pair") == (200, "who=b\n"),
          f"hits={HITS}")

    BE["a"].stop()
    wait_port(PORT_A, up=False, timeout=5)

    # 轮询下一次会轮到 a：这一问会先失败再换到 b，客户端仍应看到 200。
    code, body = request("/pair")
    check("杀掉 a 后第一次轮到它：默认 proxy_next_upstream 换节点，用户仍然是 200",
          code == 200 and body == "who=b\n", f"{code} {body!r} hits={HITS}")
    check("a 的失败被记账（被动摘除的输入）",
          (upstream_result(metrics_text(), "127.0.0.1:18401", "failure") or 0) >= 1,
          metrics_text()[:0])
    txt = metrics_text()
    check("被动摘除后调度器不再选 a（server_available=0）",
          server_available(txt, "pair", "127.0.0.1:18401") == 0,
          txt[:0])
    check("未配置主动检查时 healthy 仍为 1（两个信号语义不同）",
          re.search(r'onrouter_upstream_server_healthy\{upstream="pair",server="127\.0\.0\.1:18401"\}\s+1', txt) is not None,
          "")

    # 摘除期内、探测间隔未到：突发 4 问必须全部由 b 接住，且不产生探针。
    before = lazy_probes(metrics_text(), "127.0.0.1:18401") or 0.0
    hits_b = HITS["b"]
    codes = [request("/pair")[0] for _ in range(4)]
    after = lazy_probes(metrics_text(), "127.0.0.1:18401") or 0.0
    check("摘除期内、探测间隔未到：4 问全部由 b 接住（无错误、不白喂 a）",
          codes == [200] * 4 and HITS["b"] == hits_b + 4, f"codes={codes} hits={HITS}")
    check("探测间隔未到时不生成探针（lazy 计数不变）", after == before, f"{before} -> {after}")

    # 等过一个探测间隔：真实用户请求里会有一问被派去试探 a，失败后换 b。
    time.sleep(1.25)
    hits_b = HITS["b"]
    code, body = request("/pair")
    probes = lazy_probes(metrics_text(), "127.0.0.1:18401") or 0.0
    check("间隔到期后的一次真实请求顺带探测了 a（lazy 计数 +1）",
          probes == after + 1, f"{after} -> {probes}")
    check("探测失败也不会把错误给用户：这一问仍由 b 接住", code == 200 and body == "who=b\n",
          f"{code} {body!r}")

    # 后端恢复：下一次探测成功，节点自动加回。
    BE["a"] = Backend("a", PORT_A)
    wait_port(PORT_A, up=True, timeout=5)
    time.sleep(1.25)
    code, body = request("/pair")
    probes2 = lazy_probes(metrics_text(), "127.0.0.1:18401") or 0.0
    check("a 恢复后的第一次真实请求成为成功探针（lazy 再 +1，用户 200）",
          probes2 == probes + 1 and code == 200 and body == "who=a\n",
          f"probes {probes} -> {probes2}，{code} {body!r}")
    check("a 的成功计数开始增长（节点已被加回）",
          (upstream_result(metrics_text(), "127.0.0.1:18401", "success") or 0) >= 1,
          "")
    check("加回后 server_available 回到 1",
          server_available(metrics_text(), "pair", "127.0.0.1:18401") == 1,
          "")

    # 加回后轮询恢复：连续 4 问应同时命中 a 和 b。
    a0, b0 = HITS["a"], HITS["b"]
    codes = [request("/pair")[0] for _ in range(4)]
    check("加回后重新参与轮询：4 问里 a 与 b 都接到了流量",
          codes == [200] * 4 and HITS["a"] >= a0 + 1 and HITS["b"] >= b0 + 1,
          f"codes={codes} hits={HITS} (before a={a0} b={b0})")


def scenario_circuit_breaker():
    """单台后端连续失败：熔断打开、打开期不再重试、到期半开探针成功即闭合。"""
    before_trips = circuit_trips(metrics_text()) or 0.0
    codes = [request("/breaker")[0] for _ in range(2)]
    txt = metrics_text()
    state = circuit_state(txt)
    trips = circuit_trips(txt) or 0.0
    check("连续两次失败后熔断器打开（state=2），触发计数 +1",
          codes == [502, 502] and state == 2 and trips == before_trips + 1,
          f"codes={codes} state={state} trips {before_trips} -> {trips}")

    code = request("/breaker")[0]
    txt = metrics_text()
    check("打开期内请求快速失败，且不会重复触发（trips 不变）",
          code == 502 and circuit_trips(txt) == trips and circuit_state(txt) == 2,
          f"{code} state={circuit_state(txt)} trips={circuit_trips(txt)}")

    BE["cb"] = Backend("cb", PORT_CB)
    wait_port(PORT_CB, up=True, timeout=5)
    time.sleep(2.2)
    code, body = request("/breaker")
    txt = metrics_text()
    check("open 到期后半开探针成功：请求 200，熔断器闭合（state=0）",
          code == 200 and body == "who=cb\n" and circuit_state(txt) == 0,
          f"{code} {body!r} state={circuit_state(txt)}")
    check("闭合后不再产生新的 trips", circuit_trips(txt) == trips,
          f"{trips} -> {circuit_trips(txt)}")


def main():
    exe = find_binary()
    for p in (PORT_A, PORT_B, PORT_CB):
        if wait_port(p, up=True, timeout=0.2):
            raise SystemExit(f"!! 端口 {p} 已被占用，先确认没有残留进程")
    for f in (ERR_LOG, OUT_LOG):
        if os.path.exists(f):
            os.remove(f)

    BE["a"] = Backend("a", PORT_A)
    BE["b"] = Backend("b", PORT_B)
    proc = subprocess.Popen([exe, "-c", CONF_REL], cwd=ROOT,
                            stdout=open(OUT_LOG, "w"), stderr=subprocess.STDOUT)
    try:
        if not wait_port(GW_PORT, up=True, timeout=20):
            raise SystemExit("!! 网关没起来，看 " + ERR_LOG)
        print("=== 后端韧性 E2E：被动摘除 / 惰性重加入 / 熔断器 ===")
        scenario_lazy_rejoin()
        scenario_circuit_breaker()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        for b in BE.values():
            b.stop()

    passed = sum(1 for _n, ok in results if ok)
    print("\n==== 后端韧性 E2E: %d/%d passed ====" % (passed, len(results)))
    for n, ok in results:
        if not ok:
            print("FAILED:", n)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
