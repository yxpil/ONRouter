# -*- coding: utf-8 -*-
# ssl_certificate_by_lua* 握手阶段 E2E：
#   1) _block 语法 + ngx.ssl.server_name()/ngx.var.ssl_server_name/ngx.get_phase()
#   2) set_cert_and_key 动态按 SNI 选证书；legacy set_cert + set_priv_key 同样生效
#   3) 脚本不设置证书 -> 回落静态 SNI 证书；无 SNI -> 默认证书
#   4) 同一监听多 vhost 各自脚本：*.dyn.local 命中第二个 server 的脚本
#   5) ngx.exit(ngx.ERROR) / Lua error / clear_certs 后不补证书 -> 握手必须失败
#   6) _file 形式；HTTP/1.1 与 h2、TLS1.2 均可完成；普通请求里 ngx.ssl.server_name() 为 nil
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/ssl_cert_lua_e2e.py
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CERT_DIR = os.path.join(ROOT, "certs_https")
TMP = os.path.join(ROOT, "conf", ".tmp_ssl_cert_lua")
CONF = os.path.join(TMP, "ssl_cert_lua.conf")
FILE_LUA = os.path.join(TMP, "select_file.lua")
ERROR_LOG = os.path.join(TMP, "error.log")

HOST = "127.0.0.1"
P1 = 18540  # 多 vhost + _block
P2 = 18541  # _file
OPENSSL = shutil.which("openssl")
NODE = shutil.which("node")

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


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def lua_long(s):
    """放进 Lua 长括号字符串；PEM 中不含 ]=]，固定用 [==[ ]==]。"""
    assert "]==]" not in s
    return "[==[" + s + "]==]"


def assert_ports_free(ports):
    busy = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            if s.connect_ex((HOST, p)) == 0:
                busy.append(p)
        finally:
            s.close()
    if busy:
        raise SystemExit(f"!! 端口被占用: {busy}（不杀任何进程，请先确认是谁在监听）")


def write_conf():
    a_pem, a_key = read(os.path.join(CERT_DIR, "a.pem")), read(os.path.join(CERT_DIR, "a.key"))
    b_pem, b_key = read(os.path.join(CERT_DIR, "b.pem")), read(os.path.join(CERT_DIR, "b.key"))
    d_pem = os.path.join(CERT_DIR, "default.pem").replace("\\", "/")
    d_key = os.path.join(CERT_DIR, "default.key").replace("\\", "/")
    a_path = os.path.join(CERT_DIR, "a.pem").replace("\\", "/")
    b_path = os.path.join(CERT_DIR, "b.pem").replace("\\", "/")

    os.makedirs(TMP, exist_ok=True)
    with open(FILE_LUA, "w", encoding="utf-8") as f:
        f.write(
            "local ssl = require \"ngx.ssl\"\n"
            f"local cert = assert(ssl.parse_pem_cert({lua_long(b_pem)}))\n"
            f"local key = assert(ssl.parse_pem_priv_key({lua_long(b_key)}))\n"
            "assert(ssl.set_cert_and_key(cert, key))\n"
            "ngx.log(ngx.INFO, 'ssl-file-phase sni=' .. tostring(ssl.server_name()))\n"
        )

    conf = f'''
error_log "{ERROR_LOG.replace(chr(92), "/")}" info;

server {{
    listen {HOST}:{P1} ssl http2 default_server;
    server_name default.local;
    ssl_certificate "{d_pem}";
    ssl_certificate_key "{d_key}";
    ssl_certificate_by_lua_block {{
        local ssl = require "ngx.ssl"
        local sni = ssl.server_name()
        ngx.log(ngx.INFO, "ssl-phase sni=" .. tostring(sni)
                .. " phase=" .. ngx.get_phase()
                .. " var=" .. tostring(ngx.var.ssl_server_name))
        if sni == "a.local" or sni == "www.a.local" then
            local cert = assert(ssl.parse_pem_cert({lua_long(a_pem)}))
            local key = assert(ssl.parse_pem_priv_key({lua_long(a_key)}))
            assert(ssl.set_cert_and_key(cert, key))
        elseif sni == "b.local" then
            assert(ssl.set_cert(ssl.parse_pem_cert({lua_long(b_pem)})))
            assert(ssl.set_priv_key(ssl.parse_pem_priv_key({lua_long(b_key)})))
        elseif sni == "reject.local" then
            ngx.exit(ngx.ERROR)
        elseif sni == "broken.local" then
            error("intentional ssl script error")
        elseif sni == "clear.local" then
            ssl.clear_certs()
        end
    }}
    location = /hello {{ return 200 "hello"; }}
    location = /outside {{
        content_by_lua_block {{
            local ssl = require "ngx.ssl"
            ngx.say("sni=" .. tostring(ssl.server_name()))
        }}
    }}
}}

server {{
    listen {HOST}:{P1} ssl http2;
    server_name *.dyn.local;
    ssl_certificate "{d_pem}";
    ssl_certificate_key "{d_key}";
    ssl_certificate_by_lua_block {{
        local ssl = require "ngx.ssl"
        local cert = assert(ssl.parse_pem_cert({lua_long(b_pem)}))
        local key = assert(ssl.parse_pem_priv_key({lua_long(b_key)}))
        assert(ssl.set_cert_and_key(cert, key))
        ngx.log(ngx.INFO, "ssl-dyn-phase sni=" .. tostring(ssl.server_name()))
    }}
    location / {{ return 200 "dyn"; }}
}}

server {{
    listen {HOST}:{P2} ssl;
    server_name file.local;
    ssl_certificate "{d_pem}";
    ssl_certificate_key "{d_key}";
    ssl_certificate_by_lua_file "{FILE_LUA.replace(chr(92), "/")}";
    location / {{ return 200 "file"; }}
}}
'''
    with open(CONF, "w", encoding="utf-8") as f:
        f.write(conf)
    _ = (a_path, b_path)


def cert_cn(der):
    if not OPENSSL:
        return "?"
    p = subprocess.run(
        [OPENSSL, "x509", "-inform", "DER", "-noout", "-subject"],
        input=der,
        capture_output=True,
    )
    text = p.stdout.decode("utf-8", "replace")
    m = re.search(r"CN\s*=\s*([^,\n]+)", text)
    return m.group(1).strip() if m else text.strip()


def connect(port, sni, tls12=False, timeout=8):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection((HOST, port), timeout=timeout)
    try:
        if sni is None:
            s = ctx.wrap_socket(raw)
        else:
            s = ctx.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise
    s.settimeout(timeout)
    return s


def http_get(s, host, path="/hello"):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    chunks = []
    while True:
        try:
            b = s.recv(65536)
        except socket.timeout:
            break
        if not b:
            break
        chunks.append(b)
    data = b"".join(chunks)
    head, _, body = data.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0] if head else b""
    parts = line.split()
    status = parts[1].decode("latin1") if len(parts) >= 2 else line.decode("latin1")
    return status, body


def handshake_only(port, sni, tls12=False):
    try:
        s = connect(port, sni, tls12=tls12)
        cn = cert_cn(s.getpeercert(binary_form=True))
        ver = s.version()
        s.close()
        return True, cn, ver
    except Exception as e:
        return False, str(e), None


def dynamic_cert_http(port, sni, host):
    s = connect(port, sni)
    cn = cert_cn(s.getpeercert(binary_form=True))
    status, body = http_get(s, host)
    s.close()
    return cn, status, body


def node_h2(port, sni, path="/hello"):
    if not NODE:
        return None
    p = subprocess.run(
        [NODE, os.path.join(HERE, "h2_stream_probe.js"), f"https://{HOST}:{port}", path, sni],
        capture_output=True,
        timeout=20,
    )
    out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    m = re.search(r'"status"\s*:\s*(\d+)', out)
    return int(m.group(1)) if m else None


def main():
    if not OPENSSL:
        raise SystemExit("!! 需要 openssl 在 PATH 上")
    assert_ports_free([P1, P2])
    write_conf()
    exe = find_binary()
    try:
        os.remove(ERROR_LOG)
    except FileNotFoundError:
        pass
    logf = open(os.path.join(TMP, "stdout.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([exe, "-c", CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        up = False
        while time.time() < deadline:
            try:
                s = socket.create_connection((HOST, P1), timeout=0.3)
                s.close()
                up = True
                break
            except OSError:
                time.sleep(0.05)
        if not up:
            raise SystemExit("!! 网关未在 10s 内监听 18540，见 " + os.path.join(TMP, "stdout.log"))

        # ---------- 1. 动态选证书（_block + set_cert_and_key） ----------
        cn, status, body = dynamic_cert_http(P1, "a.local", "a.local")
        check("SNI a.local -> 握手脚本换成 a.local 证书", cn == "a.local", f"cn={cn!r}")
        check("动态证书连接可正常完成 HTTP/1.1 请求", status == "200" and body == b"hello", f"{status} {body!r}")

        ok, cn, _ = handshake_only(P1, "www.a.local")
        check("SNI www.a.local -> 同一分支命中 a.local 证书", ok and cn == "a.local", f"{ok} cn={cn!r}")

        # 2. legacy set_cert + set_priv_key
        ok, cn, _ = handshake_only(P1, "b.local")
        check("set_cert + set_priv_key（legacy API）-> b.local 证书", ok and cn == "b.local", f"{ok} cn={cn!r}")

        # 3. 脚本不改证书 -> 静态 SNI 回落默认证书
        ok, cn, _ = handshake_only(P1, "unknown.local")
        check("未知 SNI 脚本不改证书 -> 默认证书", ok and cn == "default.local", f"{ok} cn={cn!r}")
        ok, cn, _ = handshake_only(P1, None)
        check("无 SNI -> 默认证书且握手成功", ok and cn == "default.local", f"{ok} cn={cn!r}")

        # 4. 多 vhost 各自的脚本（*.dyn.local 是第二个 server block）
        cn, status, body = dynamic_cert_http(P1, "x.dyn.local", "x.dyn.local")
        check("SNI x.dyn.local 命中第二个 vhost 的握手脚本 -> b 证书", cn == "b.local", f"cn={cn!r}")
        check("第二 vhost 的路由按 Host 命中", status == "200" and body == b"dyn", f"{status} {body!r}")

        # 5. 拒绝/报错/清空证书 -> 握手失败
        ok, err, _ = handshake_only(P1, "reject.local")
        check("ngx.exit(ngx.ERROR) 中止握手", not ok, f"unexpected success: {err}")
        ok, err, _ = handshake_only(P1, "broken.local")
        check("握手脚本 Lua 错误中止握手", not ok, f"unexpected success: {err}")
        ok, err, _ = handshake_only(P1, "clear.local")
        check("clear_certs() 后未设新证书 -> 握手失败", not ok, f"unexpected success: {err}")

        # 6. _file 形式
        cn, status, body = dynamic_cert_http(P2, "file.local", "file.local")
        check("ssl_certificate_by_lua_file 动态设置 b 证书", cn == "b.local", f"cn={cn!r}")
        check("_file 监听上的 HTTP 请求正常", status == "200" and body == b"file", f"{status} {body!r}")

        # 7. TLS1.2 与 h2 不受 LazyConfigAcceptor 影响
        ok, cn, ver = handshake_only(P1, "a.local", tls12=True)
        check("TLS1.2 下动态证书同样生效", ok and cn == "a.local" and ver == "TLSv1.2", f"{ok} {cn!r} {ver}")
        h2_status = node_h2(P1, "a.local")
        check("ALPN h2 + 动态证书可完成 HTTP/2 请求", h2_status == 200, f"status={h2_status}")

        # 8. 普通请求里 ngx.ssl 不可用（server_name 为 nil）
        s = connect(P1, "a.local")
        status, body = http_get(s, "a.local", "/outside")
        s.close()
        check("非握手阶段 ngx.ssl.server_name() 返回 nil", status == "200" and body.strip() == b"sni=nil", f"{status} {body!r}")

        # 9. 连续多次连接（动态配置缓存复用）稳定
        certs = []
        for _ in range(10):
            ok, cn, _ = handshake_only(P1, "a.local")
            certs.append(cn if ok else None)
        check("连续 10 次动态选证书均成功且一致", certs == ["a.local"] * 10, f"{certs}")

        # ---------- 日志证据 ----------
        time.sleep(0.3)
        log = read(ERROR_LOG) if os.path.exists(ERROR_LOG) else ""
        check(
            "日志记录 ssl 阶段 SNI/phase/变量",
            "ssl-phase sni=a.local phase=ssl_certificate var=a.local" in log,
            "缺少 ssl-phase 日志",
        )
        check("日志记录第二个 vhost 脚本执行", "ssl-dyn-phase sni=x.dyn.local" in log, "缺少 ssl-dyn-phase")
        check("日志记录 _file 脚本执行", "ssl-file-phase sni=file.local" in log, "缺少 ssl-file-phase")
        fails = log.count("TLS 握手脚本失败")
        check("三次失败握手都有告警日志", fails >= 3, f"warn 次数={fails}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== ssl_certificate_by_lua E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
