# -*- coding: utf-8 -*-
# ngx.flush / ngx.req.socket 实跑 E2E
#   1) /flush：脚本 sleep 前就发出响应头+首块（TTFB 远小于总耗时）
#   2) /buffered：不 flush 的反证（头要等脚本跑完）
#   3) /big：无显式 flush，越过 64KB 自动阈值后开始流式，且 1MiB 字节完整
#   4) /status-flush：首帧头定稿后再改 ngx.header 不生效；状态码透传
#   5) /filtered：带 header_filter_by_lua 时退回缓冲路径，过滤器仍生效
#   6) /socket、/socket-until：ngx.req.socket 定长/receiveuntil/EOF 语义
#   7) log_by_lua 在流式响应收尾后仍执行（状态码可见）
#   8) limit_conn 额度覆盖整个流式响应期间，结束后释放
#   9) 流式响应是 chunked/END_STREAM，h1 keep-alive 可继续复用
#  10) HTTP/2 上同样能提前收到 DATA 帧（Node http2 真客户端取证）
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/lua_flush_socket_e2e.py
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "lua_flush_e2e.conf")
LOG = os.path.join(ROOT, "logs", "lua_flush_err.log")
HOST = "127.0.0.1"
PORT = 18520
TLS_PORT = 18521
LIMIT_PORT = 18522

results = []


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


def wait_port(port, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def timed_request(path, method="GET", body=None, headers=None, timeout=15, port=PORT):
    """返回 status, headers, body, 头到达耗时, 首块到达耗时, 总耗时（毫秒）

    用 read1 而不是 read：chunked 响应下 read(n) 会一直攒到 n 字节/EOF，
    量不到首块真实到达时间。
    """
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    head_ms = (time.perf_counter() - t0) * 1000
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    data = b""
    first_ms = None
    while True:
        chunk = resp.read1(65536)
        if not chunk:
            break
        if first_ms is None:
            first_ms = (time.perf_counter() - t0) * 1000
        data += chunk
    total_ms = (time.perf_counter() - t0) * 1000
    status = resp.status
    conn.close()
    return status, hdrs, data, head_ms, first_ms, total_ms


def h2_probe(path, servername):
    node = shutil.which("node")
    if not node:
        return None
    probe = os.path.join(HERE, "h2_stream_probe.js")
    out = subprocess.check_output(
        [node, probe, f"https://{HOST}:{TLS_PORT}", path, servername],
        cwd=ROOT, timeout=20,
    ).decode("utf-8", "replace").strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        raise SystemExit(f"h2 probe 输出无法解析: {out}")


def main():
    if not all(os.path.exists(os.path.join(ROOT, "certs_https", f)) for f in ("a.pem", "a.key")):
        raise SystemExit("!! 缺少 certs_https/a.pem|a.key，先跑 python tools/https_matrix_e2e.py 生成")
    exe = find_binary()
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    try:
        os.remove(LOG)
    except FileNotFoundError:
        pass

    logf = open(LOG, "ab")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_port(PORT) or not wait_port(TLS_PORT):
            raise SystemExit("!! 服务没起来，检查 logs/lua_flush_err.log")

        # 1) 流式正例
        st, hdrs, body, head_ms, first_ms, total_ms = timed_request("/flush")
        check("GET /flush → 200", st == 200, f"status={st}")
        check("ngx.flush 后头/首块提前到达（<500ms，脚本还要 sleep 1s）",
              head_ms < 500 and first_ms is not None and first_ms < 500,
              f"head={head_ms:.0f}ms first={first_ms}ms total={total_ms:.0f}ms")
        check("GET /flush 总耗时覆盖脚本 sleep（>=900ms）", total_ms >= 900,
              f"total={total_ms:.0f}ms")
        check("GET /flush 响应体完整", body == b"first\nsecond\n", f"{body!r}")
        check("流式响应无 Content-Length（chunked/流式分帧）",
              "content-length" not in hdrs and hdrs.get("transfer-encoding", "") == "chunked",
              f"{hdrs}")

        # 2) 不 flush 的反证
        st, hdrs, body, head_ms, first_ms, total_ms = timed_request("/buffered")
        check("GET /buffered → 200 且体完整", st == 200 and body == b"a\nb\n", f"{st} {body!r}")
        check("未 flush 时响应头等脚本结束才发（>=600ms）", head_ms >= 600,
              f"head={head_ms:.0f}ms total={total_ms:.0f}ms")

        # 3) 自动阈值流式 + 1MiB 完整性
        st, hdrs, body, head_ms, first_ms, total_ms = timed_request("/big", timeout=30)
        expect_len = 1024 * 1024 + len(b"done\n")
        check("GET /big → 200 且 1MiB+done 字节完整",
              st == 200 and len(body) == expect_len and body[: 1024 * 1024] == b"x" * (1024 * 1024)
              and body.endswith(b"done\n"),
              f"status={st} len={len(body)} expect={expect_len}")
        check("无显式 flush 但越过 64KB 阈值 → 提前流式（<500ms）",
              first_ms is not None and first_ms < 500,
              f"first={first_ms}ms total={total_ms:.0f}ms")
        check("自动流式响应总耗时覆盖 sleep（>=700ms）", total_ms >= 700,
              f"total={total_ms:.0f}ms")

        # 4) 首帧头定稿
        st, hdrs, body, head_ms, first_ms, total_ms = timed_request("/status-flush")
        check("GET /status-flush → 201", st == 201, f"status={st}")
        check("flush 之后修改 ngx.header 不生效",
              "x-late" not in hdrs and body == b"x\ny\n",
              f"x-late={hdrs.get('x-late')} body={body!r}")
        check("流式响应内容类型默认为 text/plain",
              hdrs.get("content-type", "").startswith("text/plain"), f"{hdrs.get('content-type')}")

        # 5) header_filter 回退
        st, hdrs, body, head_ms, first_ms, total_ms = timed_request("/filtered")
        check("带 header_filter_by_lua 时退回缓冲且过滤器生效",
              st == 200 and hdrs.get("x-filtered") == "1" and body == b"f\ng\n",
              f"status={st} x-filtered={hdrs.get('x-filtered')} body={body!r}")
        check("过滤器路径不会提前发送响应（>=600ms）", head_ms >= 600,
              f"head={head_ms:.0f}ms total={total_ms:.0f}ms")

        # 6) ngx.req.socket
        st, hdrs, body, *_ = timed_request(
            "/socket", method="POST", body=b"part1\r\n\r\npart2",
            headers={"Content-Type": "application/octet-stream"},
        )
        text = body.decode("utf-8", "replace")
        check("ngx.req.socket receive/receiveuntil 读到完整请求体",
              st == 200 and "a=part1" in text and "sep=4" in text and "rest=part2" in text
              and "eof=nil/closed" in text,
              f"status={st} body={text!r}")
        st, hdrs, body, *_ = timed_request(
            "/socket-until", method="POST", body=b"a=1&b=2&c=3&",
        )
        text = body.decode("utf-8", "replace")
        check("receiveuntil inclusive=false 丢弃分隔符且可重复迭代",
              st == 200 and "1=a=1" in text and "2=b=2" in text and "3=c=3" in text
              and "eof=nil/closed" in text,
              f"status={st} body={text!r}")

        # 7) 流式请求的 log_by_lua 仍执行
        deadline = time.time() + 3
        log_text = ""
        while time.time() < deadline:
            try:
                with open(LOG, "r", encoding="utf-8", errors="replace") as f:
                    log_text = f.read()
            except FileNotFoundError:
                pass
            if "log-phase /flush status=200" in log_text:
                break
            time.sleep(0.1)
        check("流式响应收尾后 log_by_lua 仍以最终状态执行",
              "log-phase /flush status=200" in log_text,
              "error_log 中未找到 log-phase /flush status=200")

        # 8) limit_conn 覆盖流式期间
        import threading
        first = {}

        def slow_first():
            first["r"] = timed_request("/slow", timeout=20, port=LIMIT_PORT)

        t = threading.Thread(target=slow_first)
        t.start()
        time.sleep(0.3)  # 让第一条进入流式并占住 limit_conn 额度
        st2, _, body2, *_ = timed_request("/slow", timeout=10, port=LIMIT_PORT)
        check("流式在途时 limit_conn 额度仍被占用（第二条 503）", st2 == 503,
              f"status={st2} body={body2[:80]!r}")
        t.join()
        st1, _, body1, *_ = first["r"]
        check("第一条流式请求正常完成", st1 == 200 and body1 == b"start\nend\n", f"{st1} {body1!r}")
        st3, _, body3, *_ = timed_request("/slow", timeout=10, port=LIMIT_PORT)
        check("流式结束后 limit_conn 额度释放（再次 200）",
              st3 == 200 and body3 == b"start\nend\n", f"{st3} {body3!r}")

        # 9) h1 keep-alive：chunked 流式响应结束后连接可复用
        conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
        conn.request("GET", "/flush")
        r1 = conn.getresponse()
        b1 = r1.read()
        conn.request("GET", "/hello")
        r2 = conn.getresponse()
        b2 = r2.read()
        conn.close()
        check("流式 chunked 响应后 h1 连接可继续复用",
              r1.status == 200 and b1 == b"first\nsecond\n" and r2.status == 200 and b2 == b"hi\n",
              f"{r1.status}/{b1!r} -> {r2.status}/{b2!r}")

        # 10) HTTP/2 真客户端
        probe = h2_probe("/flush", "a.local")
        if probe is None:
            check("HTTP/2 流式（需要 node）", False, "未找到 node")
        else:
            check("HTTP/2 上 ngx.flush 同样提前发 DATA 帧",
                  probe.get("status") == 200 and 0 <= probe.get("ttfb_ms", -1) < 500
                  and probe.get("total_ms", 0) >= 900
                  and probe.get("bytes") == len("h2-first\nh2-second\n")
                  and probe.get("chunks", 0) >= 2,
                  f"{probe}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ngx.flush / ngx.req.socket E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
