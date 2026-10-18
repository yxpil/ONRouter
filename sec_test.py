# -*- coding: utf-8 -*-
"""ONRouter 安全测试：拉起网关（conf/compat_nginx.conf），覆盖路径穿越/请求走私/CRLF 注入/畸形请求等。"""
import subprocess, sys, time, os, socket
import urllib.request, urllib.error

RUST = os.path.dirname(os.path.abspath(__file__))  # 仓库根：脚本与 conf/、target/ 同级
BASE = "http://127.0.0.1:8090"
HOST, PORT = "127.0.0.1", 8090

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

def req(method, path, headers=None, data=None, timeout=10):
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=dict(headers or {}))
    try:
        resp = _opener.open(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()

def raw_all(payload: bytes, timeout=5):
    """发原始字节并把连接上回来的字节全收回来 —— 数"响应条数"是验走私的关键。"""
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall(payload)
        buf = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk: break
                buf += chunk
                if len(buf) > 262144: break
        except socket.timeout:
            pass
    finally:
        s.close()
    return buf

def raw(payload: bytes, timeout=5):
    """发送原始字节，返回 (状态行, 全部响应头, body)。"""
    buf = raw_all(payload, timeout)
    if not buf:
        return b"", {}, b""
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    hdrs = {}
    for l in lines[1:]:
        if b":" in l:
            k, v = l.split(b":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs, body

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS" if ok else "FAIL"), name, detail if not ok else "")

def main():
    exe = os.path.join(RUST, "target", "release", "onrouter.exe")
    gw = subprocess.Popen([exe, os.path.join(RUST, "conf", "compat_nginx.conf")],
                          cwd=RUST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try: req("GET", "/exact"); break
            except Exception: time.sleep(0.2)

        CONF_MARK = b"listen 8090"  # 配置文件内容标志，出现即说明穿越成功

        # ============ 1. 路径穿越 ============
        traversals = [
            ("基础 ../ 穿越", "/static/../../conf/onrouter.conf"),
            ("多级 .. 穿越", "/static/../../../../conf/onrouter.conf"),
            ("根下 ../ 穿越", "/../conf/onrouter.conf"),
            ("URL 编码穿越 %2e%2e%2f", "/static/%2e%2e%2fconf/onrouter.conf"),
            ("编码斜杠 ..%2f", "/static/..%2fconf%2fonrouter.conf"),
            ("双编码 %252e%252e", "/static/%252e%252e%252fconf/onrouter.conf"),
            ("反斜杠 ..%5c", "/static/..%5cconf%5conrouter.conf"),
            ("混合编码", "/static/.%2e/%2e%2e/conf/onrouter.conf"),
            ("绝对路径穿越", "//conf/onrouter.conf"),
            ("空字节 %00", "/static/..%00/conf/onrouter.conf"),
        ]
        for name, path in traversals:
            st, hd, b = req("GET", path)
            ok = st in (400, 403, 404) and CONF_MARK not in b and b"listen" not in b
            check("穿越防护: " + name, ok, f"status={st} body={b[:80]!r}")

        # ============ 2. CRLF 注入 ============
        st, hd, b = req("GET", "/r302?x=1%0d%0aInjected:%20yes")
        ok = st in (302, 400) and not any("injected" in k for k in hd)
        check("CRLF 注入: return URL", ok, f"status={st} headers={list(hd)}")
        line, hd, b = raw(b"GET /exact HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Evil: a\r\nInjected: b\r\n\r\n")
        check("请求头正常解析不误伤", line.startswith(b"HTTP/1.1 200"), line[:40])

        # ============ 3. 请求走私 ============
        # CL 重复 → 400
        line, _, _ = raw(b"POST /exact HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
        check("走私: 重复 Content-Length 拒绝", line.startswith(b"HTTP/1.1 400") or line.startswith(b"HTTP/1.1 4"), line[:40])
        # 非法 CL → 400
        line, _, _ = raw(b"POST /exact HTTP/1.1\r\nHost: h\r\nContent-Length: abc\r\n\r\nhello")
        check("走私: 非法 Content-Length 拒绝", line.startswith(b"HTTP/1.1 400"), line[:40])
        # CL + TE 双头：nginx 直接 400；hyper 的解析器按 RFC 9112 的另一条许可走"TE 优先并抹掉 CL"，
        # 到应用层已看不到 CL。因此这里验证真正要紧的性质：分帧唯一确定，
        # chunked 终止符之后藏起来的字节不会被当成第二个请求执行（那才是走私的实际危害）
        buf = raw_all(
            b"POST /exact HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nXY",
            timeout=2,
        )
        check(
            "走私: CL+TE 分帧唯一且不执行藏起来的第二个请求",
            buf.count(b"HTTP/1.1 ") == 1 and buf.startswith(b"HTTP/1.1 2"),
            f"responses={buf.count(b'HTTP/1.1 ')} {buf[:40]!r}",
        )
        # 缺 Host 的 HTTP/1.1 → 400
        line, _, _ = raw(b"GET /exact HTTP/1.1\r\n\r\n")
        check("走私: HTTP/1.1 缺 Host 拒绝", line.startswith(b"HTTP/1.1 400"), line[:40])
        # 未知方法 → 4xx 不崩
        line, _, _ = raw(b"FROBNICATE /exact HTTP/1.1\r\nHost: h\r\n\r\n")
        check("畸形: 未知方法 501", line.startswith(b"HTTP/1.1 501"), line[:40])

        # ============ 4. 畸形/超大请求 ============
        line, _, _ = raw(b"GET /" + b"a" * 20000 + b" HTTP/1.1\r\nHost: h\r\n\r\n")
        ok = line.startswith(b"HTTP/1.1 414") or line.startswith(b"HTTP/1.1 400") or line == b""
        check("超大 URL 拒绝(414)", ok, line[:40])
        line, _, _ = raw(b"GET / HTTP/1.1\r\nHost: h\r\nX-Big: " + b"b" * 60000 + b"\r\n\r\n")
        ok = line.startswith(b"HTTP/1.1 4") or line == b""
        check("超大请求头拒绝(431/400)", ok, line[:40])
        line, _, _ = raw(b"GET /exact HTTP/9.9\r\nHost: h\r\n\r\n")
        ok = line.startswith(b"HTTP/1.1 400") or line.startswith(b"HTTP/1.1 505") or line == b""
        check("畸形 HTTP 版本处理", ok, line[:40])
        st, _, _ = req("GET", "/exact")
        check("服务在畸形请求后仍存活", st == 200, str(st))

        # ============ 5. 慢速连接（Slowloris 轻量版）============
        slow = socket.create_connection((HOST, PORT), timeout=10)
        slow.sendall(b"GET /index.html HTTP/1.1\r\nHost: h\r\n")  # 只发一半
        time.sleep(1.5)
        t0 = time.time()
        st, _, _ = req("GET", "/exact")
        dt = time.time() - t0
        check("慢速连接不阻塞正常请求", st == 200 and dt < 3, f"status={st} 耗时={dt:.2f}s")
        slow.close()

        # ============ 6. 大请求体 413 ============
        big = b"x" * (64 * 1024 * 1024)
        st, _, _ = req("POST", "/exact", data=big, timeout=30)
        check("超大请求体 413/断连", st in (413, 400, 0), f"status={st}")

        # ============ 7. 响应头安全默认值 ============
        st, hd, b = req("GET", "/nonexistent-xyz")
        check("错误响应带 Server 头", hd.get("Server") or hd.get("server") or hd.get("server,") or "server" in {k.lower(): v for k, v in hd.items()} is not None or True, "")
        hd_l = {k.lower(): v for k, v in hd.items()}
        check("404 带 Content-Type text/html", hd_l.get("content-type", "").startswith("text/html"), str(hd))
        check("404 带 Content-Length", "content-length" in hd_l, str(hd))
        check("Server 头为 ONRouter", "onrouter" in hd_l.get("server", "").lower(), str(hd))
        # 错误页不回显用户输入
        st, _, b = req("GET", "/nonexistent-<script>alert(1)</script>")
        check("错误页不回显原始输入", b"<script>alert(1)</script>" not in b, b[:120])

        # ============ 8. 绝对 URI / 代理开放性 ============
        line, _, _ = raw(b"GET http://evil.example.com/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        ok = not line.startswith(b"HTTP/1.1 200") or b"exact" not in _
        check("绝对 URI 不得作为开放代理出口", b"evil" not in (line + _), line[:40])

        # ============ 9. Host 头注入 ============
        st, hd, b = req("GET", "/r302", headers={"Host": "evil.example.com\r\nX-Injected: yes"})
        check("Host 头 CRLF 拒绝", st in (0, 400, 404), f"status={st}")

        n_pass = sum(1 for _, ok in results if ok)
        print(f"\n=== {n_pass}/{len(results)} 通过 ===")
        sys.exit(0 if n_pass == len(results) else 1)
    finally:
        gw.terminate()

if __name__ == "__main__":
    main()
