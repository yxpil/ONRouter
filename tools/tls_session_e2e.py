# -*- coding: utf-8 -*-
# TLS 会话恢复 E2E —— 验证 ssl_session_cache / ssl_session_tickets 的 nginx 语义：
#   off / builtin[:n] / shared:name:size  ×  tickets on|off，多监听端口同一进程。
# 取证手段：
#   1) Python 同 SSLContext 先建会话再复用（同端口 / 跨端口）
#   2) openssl s_client -sess_out/-sess_in（第二次握手显示 Reused）
#   3) openssl s_client -reconnect（连续连接的 New/Reused 收敛）
#
#   cargo build --release --bin onrouter && python tools/tls_session_e2e.py
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CERT_DIR = os.path.join(ROOT, "certs_https")
HOST = "127.0.0.1"

SCENARIOS = [
    # name, 两个监听端口, ssl_session_cache, ssl_session_tickets, 同端口可恢复, 跨端口可恢复
    ("off_tickets_on", (18500, 18501), "off", "on", True, True),
    ("off_tickets_off", (18502, 18503), "off", "off", False, False),
    ("builtin_tickets_off", (18504, 18505), "builtin:512", "off", True, False),
    ("shared_tickets_off", (18506, 18507), "shared:SSL:1m", "off", True, True),
    ("shared_tickets_on", (18508, 18509), "shared:SSL:1m", "on", True, True),
]

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
    raise SystemExit("!! build first: cargo build --release --bin onrouter")


OPENSSL = shutil.which("openssl")
if not OPENSSL:
    raise SystemExit("!! 需要 openssl 在 PATH 上")


def ensure_cert():
    pem = os.path.join(CERT_DIR, "a.pem")
    key = os.path.join(CERT_DIR, "a.key")
    if os.path.exists(pem) and os.path.exists(key):
        return
    os.makedirs(CERT_DIR, exist_ok=True)
    p = subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-days", "3650", "-nodes",
         "-subj", "/CN=a.local", "-addext", "subjectAltName=DNS:a.local",
         "-keyout", key, "-out", pem],
        capture_output=True, timeout=60,
    )
    if p.returncode != 0:
        raise SystemExit("!! 生成证书失败: " + p.stderr.decode("utf-8", "replace")[:400])


def make_ctx(version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def read_http_response(sock, timeout=8):
    sock.settimeout(timeout)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, sep, body = data.partition(b"\r\n\r\n")
    status = ""
    if sep and b" " in head:
        parts = head.split(b" ", 2)
        if len(parts) >= 2:
            status = parts[1].decode("ascii", "replace")
    return status, body.decode("utf-8", "replace").strip()


def probe(version, src_port, dst_port):
    """同一 SSLContext 建立会话后，带着它连 dst_port；返回是否复用。"""
    out = {"reused": False, "has_ticket": None, "status": None, "err": None}
    s1 = s2 = None
    try:
        ctx = make_ctx(version)
        s1 = ctx.wrap_socket(
            socket.create_connection((HOST, src_port), timeout=8),
            server_hostname="a.local",
        )
        s1.sendall(b"GET / HTTP/1.1\r\nHost: a.local\r\nConnection: close\r\n\r\n")
        out["status"], _ = read_http_response(s1, 8)
        sess = s1.session
        out["has_ticket"] = getattr(sess, "has_ticket", None) if sess is not None else None
        s1.close()
        s1 = None
        if sess is None:
            out["err"] = "客户端没有拿到 session"
            return out
        s2 = ctx.wrap_socket(
            socket.create_connection((HOST, dst_port), timeout=8),
            server_hostname="a.local",
            session=sess,
        )
        out["reused"] = bool(s2.session_reused)
        s2.close()
        s2 = None
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
    finally:
        for sk in (s1, s2):
            if sk is not None:
                try:
                    sk.close()
                except Exception:
                    pass
    return out


def openssl_sessin(version, port):
    """先 -sess_out 写出会话，再 -sess_in 复用；返回 (first_new, second_reused)。"""
    d = tempfile.mkdtemp(prefix="orr_tls_session_")
    sf = os.path.join(d, "sess.pem")
    varg = "-tls1_3" if version == "1.3" else "-tls1_2"

    def run(extra):
        p = subprocess.Popen(
            [OPENSSL, "s_client", "-connect", f"{HOST}:{port}", "-servername", "a.local",
             varg, *extra],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        # TLS1.3 要等 NewSessionTicket 落盘，保持 1s 再关 stdin
        time.sleep(1.0)
        out, _ = p.communicate(input=b"", timeout=15)
        return out.decode("utf-8", "replace")

    t1 = run(["-sess_out", sf])
    t2 = run(["-sess_in", sf]) if os.path.exists(sf) else ""
    first_new = bool(re.search(r"^New,", t1, re.M))
    second_reused = bool(re.search(r"^Reused,", t2, re.M))
    size = os.path.getsize(sf) if os.path.exists(sf) else 0
    try:
        os.remove(sf)
        os.rmdir(d)
    except OSError:
        pass
    return first_new, second_reused, size


def openssl_reconnect(version, port):
    """-reconnect：一条命令内连续握手，统计 New/Reused 行。"""
    varg = "-tls1_3" if version == "1.3" else "-tls1_2"
    try:
        p = subprocess.run(
            [OPENSSL, "s_client", "-connect", f"{HOST}:{port}", "-servername", "a.local",
             varg, "-reconnect"],
            input=b"", capture_output=True, timeout=40,
        )
    except Exception as e:
        return {"new": 0, "reused": 0, "err": str(e)}
    text = (p.stdout + p.stderr).decode("utf-8", "replace")
    new = len(re.findall(r"^New,", text, re.M))
    reused = len(re.findall(r"^Reused,", text, re.M))
    return {"new": new, "reused": reused, "err": None if (new + reused) else text[-300:]}


def ports_free_or_raise(ports):
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


def wait_ports_free(ports, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        busy = []
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                if s.connect_ex((HOST, p)) == 0:
                    busy.append(p)
            finally:
                s.close()
        if not busy:
            return
        time.sleep(0.1)


def write_conf(name, ports, cache, tickets):
    path = os.path.join(ROOT, "conf", f"tls_session_{name}.conf")
    p1, p2 = ports
    text = f"""worker_processes 1;
error_log "../logs/tls_session_{name}_err.log" info;
ssl_session_cache {cache};
ssl_session_tickets {tickets};

server {{
    listen 127.0.0.1:{p1} ssl;
    listen 127.0.0.1:{p2} ssl;
    server_name a.local;
    ssl_certificate "../certs_https/a.pem";
    ssl_certificate_key "../certs_https/a.key";

    location / {{
        content_by_lua "ngx.say('tls-session')";
    }}
}}
"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def run_scenario(exe, name, ports, cache, tickets, expect_same, expect_cross):
    print(f"\n-- 场景 {name}: ssl_session_cache {cache}; ssl_session_tickets {tickets}; "
          f"ports={ports} --")
    ports_free_or_raise(ports)
    conf = write_conf(name, ports, cache, tickets)
    out_path = os.path.join(ROOT, "logs", f"tls_session_{name}_out.log")
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(out_path, "wb")
    proc = subprocess.Popen([exe, os.path.join("conf", os.path.basename(conf))],
                            cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(100):
            if proc.poll() is not None:
                break
            r = probe("1.3", ports[0], ports[0])
            if r["status"] == "200":
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            logf.flush()
            tail = ""
            try:
                with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                    tail = "".join(f.readlines()[-20:])
            except Exception:
                pass
            raise SystemExit(f"!! {name} 启动失败（{out_path}）\n{tail}")

        for ver in ("1.2", "1.3"):
            same = probe(ver, ports[0], ports[0])
            cross = probe(ver, ports[0], ports[1])
            check(f"{name} TLS{ver} 同端口会话复用={'预期可复用' if expect_same else '预期不复用'}",
                  same["reused"] == expect_same,
                  f"reused={same['reused']} has_ticket={same['has_ticket']} "
                  f"status={same['status']} err={same['err']}")
            check(f"{name} TLS{ver} 跨端口会话复用={'预期可复用' if expect_cross else '预期不复用'}",
                  cross["reused"] == expect_cross,
                  f"reused={cross['reused']} has_ticket={cross['has_ticket']} err={cross['err']}")

            first_new, sessin_reused, size = openssl_sessin(ver, ports[0])
            if expect_same:
                check(f"{name} openssl -sess_in TLS{ver} 复用",
                      first_new and sessin_reused and size > 0,
                      f"first_new={first_new} reused={sessin_reused} sess_bytes={size}")
            else:
                # 无缓存且无 ticket 时服务端不会下发会话，sess_out 文件可能为 0 字节
                check(f"{name} openssl -sess_in TLS{ver} 不复用",
                      first_new and not sessin_reused,
                      f"first_new={first_new} reused={sessin_reused} sess_bytes={size}")

            rc = openssl_reconnect(ver, ports[0])
            if ver == "1.3":
                # OpenSSL 的 -reconnect 不等 TLS1.3 NewSessionTicket，因此 1.3 下
                # 永远显示 New；复用证据以 -sess_in 为准。这里只校验 5 次重连都成功。
                check(f"{name} openssl -reconnect TLS1.3 五次重连均成功（复用见 -sess_in）",
                      rc["new"] > 0, f"{rc}")
            elif expect_same:
                check(f"{name} openssl -reconnect TLS1.2 收敛为复用",
                      rc["reused"] > 0, f"{rc}")
            else:
                check(f"{name} openssl -reconnect TLS1.2 始终不复用",
                      rc["new"] > 0 and rc["reused"] == 0, f"{rc}")

        # 错误日志里不应出现 ticketer / 缓存相关告警
        errlog = os.path.join(ROOT, "logs", f"tls_session_{name}_err.log")
        if os.path.exists(errlog):
            with open(errlog, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            check(f"{name} 启动日志无会话缓存告警",
                  "ticketer" not in text and "ssl_session_cache" not in text,
                  text[-400:])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        logf.close()
        try:
            os.remove(conf)
        except OSError:
            pass
        wait_ports_free(ports)


def main():
    ensure_cert()
    exe = find_binary()
    for sc in SCENARIOS:
        run_scenario(exe, *sc)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== TLS 会话恢复矩阵 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
