# -*- coding: utf-8 -*-
# TLS 证书热重载 E2E —— 用真实 TLS 握手取证（SHA-256 对比证书 DER）。
#
# 证明了什么：
#   1) 证书文件**原地替换**（不改 conf、不重启进程）后，新连接的下一次握手即出示新证书；
#      证书文件 mtime 由重载任务自动监视（对齐自动续证场景）。
#   2) 换证期间，一条换证前建立的 TLS keep-alive 连接继续可用（同一 socket 拿到 200），
#      说明监听与在途连接都没有被打断。
#   3) 写入损坏证书：热重载失败但旧证书继续服务（不退出、不降级），修复后再次生效。
#   4) QUIC/HTTP/3 侧同样热刷新：换证后旧信任根握手失败、信任新旧根成功（真 UDP 流量）。
#   5) 全程同一进程（pid 文件与子进程一致）。
#
#   cargo build --release -p onrouter-server && python tools/tls_reload_e2e.py
import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "tls_reload.conf")
CERT_DIR = os.path.join(ROOT, "certs_tls_reload")
LOG = os.path.join(ROOT, "conf", "logs", "tls_reload_err.log")
HOST, PORT = "127.0.0.1", 18192
QUIC_PORT = 18193
SNI = "reload.local"
BODY = b"tls-reload-ok"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def find_bin(name):
    for profile in ("release", "debug"):
        for ext in (".exe", ""):
            p = os.path.join(ROOT, "target", profile, name + ext)
            if os.path.exists(p):
                return p
    return None


def find_binary():
    p = find_bin("onrouter")
    if p:
        return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server")


def run(cmd):
    r = subprocess.run(cmd, cwd=CERT_DIR, capture_output=True)
    if r.returncode != 0:
        raise SystemExit("!! openssl 失败:\n" + (r.stderr or r.stdout).decode(errors="replace")[-1500:])


def gen_cert(base, cn):
    # OpenSSL 3.x 的 `req -x509` 默认 basicConstraints=CA:TRUE，而 webpki 会拒绝
    # 把 CA 证书当服务器叶子证书（CaUsedAsEndEntity）；显式标为 CA:FALSE。
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "2", "-nodes",
        "-keyout", base + ".key", "-out", base + ".pem",
        "-subj", "/CN=" + cn,
        "-addext", "subjectAltName=DNS:reload.local,DNS:" + cn,
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
    ])


def install(base):
    """原子替换生效中的证书文件（证书与私钥分别替换 + 重试，模拟证书续期落盘）。"""
    for ext in ("key", "pem"):
        src = os.path.join(CERT_DIR, base + "." + ext)
        dst = os.path.join(CERT_DIR, "server." + ext)
        tmp = dst + ".tmp"
        for attempt in range(10):
            try:
                shutil.copyfile(src, tmp)
                os.replace(tmp, dst)
                break
            except PermissionError:
                time.sleep(0.05)
        else:
            raise SystemExit("!! 无法替换 " + dst)
        os.utime(dst, None)


def write_bad_cert():
    dst = os.path.join(CERT_DIR, "server.pem")
    tmp = dst + ".tmp"
    with open(tmp, "wb") as f:
        f.write(b"-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n")
    os.replace(tmp, dst)
    os.utime(dst, None)


def pem_sha(path):
    with open(path, encoding="ascii") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return hashlib.sha256(der).hexdigest()


def tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe():
    """新建一条 TLS 连接：返回 (证书 SHA-256, HTTP 状态, 正文)。"""
    with socket.create_connection((HOST, PORT), timeout=3) as raw:
        with tls_ctx().wrap_socket(raw, server_hostname=SNI) as s:
            fp = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
            s.sendall(b"GET / HTTP/1.1\r\nHost: reload.local\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0
    return fp, status, body


class KeepAlive:
    """一条在换证前建立、换证后继续使用的 TLS keep-alive 连接。"""

    def __init__(self):
        self.raw = socket.create_connection((HOST, PORT), timeout=3)
        self.sock = tls_ctx().wrap_socket(self.raw, server_hostname=SNI)
        self.fp = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
        self.buf = b""

    def request(self):
        self.sock.sendall(
            b"GET / HTTP/1.1\r\nHost: reload.local\r\nConnection: keep-alive\r\n\r\n"
        )
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("keep-alive 连接被关闭")
            self.buf += chunk
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get(b"content-length", b"0"))
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("keep-alive 响应体被截断")
            self.buf += chunk
        body, self.buf = self.buf[:n], self.buf[n:]
        return int(head.split(b" ")[1]), body

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def h3_probe(trust_pem):
    """真实 HTTP/3（QUIC over UDP + TLS1.3）请求，返回解析后的键值 dict。"""
    exe = find_bin("orr-h3check")
    if not exe:
        raise SystemExit("!! 缺 orr-h3check：cargo build --release -p onrouter-server")
    env = dict(os.environ, ORR_H3_CERT=trust_pem)
    try:
        r = subprocess.run(
            [exe, f"127.0.0.1:{QUIC_PORT}", SNI, "/", "single"],
            capture_output=True, text=True, timeout=30, cwd=ROOT, env=env,
        )
    except Exception as e:
        return {"ERROR": repr(e)}
    kv = {}
    for line in r.stdout.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    if r.returncode != 0 and "ERROR" not in kv:
        kv["ERROR"] = (r.stderr or r.stdout).strip()
    return kv


def wait_for(predicate, timeout=10.0, interval=0.2):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            ok, last = predicate()
            if ok:
                return True, last
        except (OSError, ssl.SSLError) as e:
            last = repr(e)
        time.sleep(interval)
    return False, last


def log_text():
    try:
        with open(LOG, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def main():
    os.makedirs(CERT_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    if shutil.which("openssl") is None:
        raise SystemExit("!! 需要 openssl 在 PATH 上")

    # 两套证书：A 为启动证书，B 模拟续期后的新证书（每次重生成，避免旧夹具扩展不合规）
    for base, cn in (("a", "reload-a.local"), ("b", "reload-b.local")):
        gen_cert(base, cn)
    sha_a = pem_sha(os.path.join(CERT_DIR, "a.pem"))
    sha_b = pem_sha(os.path.join(CERT_DIR, "b.pem"))
    install("a")

    # 同时信任 A 与 B 的根包：A 单独失败而 A+B 成功，即可证明 QUIC 端点已换到 B
    roots_both = os.path.join(CERT_DIR, "roots_both.pem")
    with open(roots_both, "w", encoding="ascii") as out:
        for base in ("a", "b"):
            with open(os.path.join(CERT_DIR, base + ".pem"), encoding="ascii") as f:
                out.write(f.read())
                out.write("\n")

    exe = find_binary()
    logf = open(os.path.join(ROOT, "logs", "tls_reload_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    ka = None
    try:
        def ready():
            fp, st, body = probe()
            return (st == 200 and body.strip() == BODY, fp)

        ok, detail = wait_for(ready)
        check("服务就绪且返回 200", ok, f"detail={detail}")
        fp0, st0, body0 = probe()
        check("首握手出示证书 A", fp0 == sha_a, f"fp={fp0[:16]} a={sha_a[:16]}")
        check("响应正文正确", st0 == 200 and body0.strip() == BODY, f"st={st0} body={body0!r}")

        def h3_ready():
            kv = h3_probe(os.path.join(CERT_DIR, "a.pem"))
            return (kv.get("STATUS") == "200" and kv.get("BODY", "").strip() == BODY.decode(), kv)

        ok, detail = wait_for(h3_ready)
        check("HTTP/3 基线：QUIC 端点出示证书 A 并返回 200", ok, f"detail={detail}")

        # 换证前建立一条 keep-alive 连接，换证后继续使用
        ka = KeepAlive()
        st_ka, body_ka = ka.request()
        check("换证前 keep-alive 连接可用", st_ka == 200 and body_ka.strip() == BODY and ka.fp == sha_a,
              f"st={st_ka} body={body_ka!r}")

        # ---- 1) 原地续期证书 A -> B（不写 conf，靠证书 mtime 触发）----
        install("b")

        def sees_b():
            fp, _, _ = probe()
            return (fp == sha_b, fp)

        ok, detail = wait_for(sees_b)
        check("新连接出示证书 B（证书文件变更自动触发刷新）", ok, f"detail={detail}")
        check("刷新后证书 A 不再被出示", probe()[0] != sha_a)

        # ---- 1b) QUIC/HTTP/3 端点同样完成换证（真 UDP 流量验证）----
        def h3_old_fails():
            kv = h3_probe(os.path.join(CERT_DIR, "a.pem"))
            return ("ERROR" in kv and "STATUS" not in kv, kv)

        ok, detail = wait_for(h3_old_fails)
        check("HTTP/3 换证后：只信任旧证书 A 的客户端握手失败", ok, f"detail={detail}")

        def h3_both_ok():
            kv = h3_probe(roots_both)
            return (kv.get("STATUS") == "200" and kv.get("BODY", "").strip() == BODY.decode(), kv)

        ok, detail = wait_for(h3_both_ok)
        check("HTTP/3 换证后：信任 A+B 的客户端成功（A 已失败，故出示的必为 B）", ok, f"detail={detail}")

        # ---- 2) 换证前建立的 TLS 连接未被中断 ----
        try:
            st_ka2, body_ka2 = ka.request()
            ka_ok = st_ka2 == 200 and body_ka2.strip() == BODY
            err = ""
        except (OSError, ConnectionError) as e:
            ka_ok, err = False, repr(e)
        check("换证后既有 TLS keep-alive 连接仍可请求", ka_ok, err or "请求失败")
        check("既有连接持有旧证书、未重新握手", ka.fp == sha_a)

        # ---- 3) 损坏证书：刷新失败，旧证书 B 继续服务 ----
        write_bad_cert()
        time.sleep(1.5)  # 多个 300ms 轮询周期
        try:
            fp_bad, st_bad, body_bad = probe()
        except (OSError, ssl.SSLError) as e:
            fp_bad, st_bad, body_bad = None, 0, repr(e).encode()
        check("损坏证书被拒绝，旧证书 B 继续服务", fp_bad == sha_b and st_bad == 200 and body_bad.strip() == BODY,
              f"fp={str(fp_bad)[:16]} st={st_bad} body={body_bad!r}")
        check("损坏证书未导致进程退出", proc.poll() is None, f"returncode={proc.poll()}")
        check("日志记录了 TLS 热刷新失败", "TLS 热刷新失败" in log_text())
        h3_bad = h3_probe(os.path.join(CERT_DIR, "b.pem"))
        check("HTTP/3 在刷新失败时继续使用旧配置（证书 B）",
              h3_bad.get("STATUS") == "200" and h3_bad.get("BODY", "").strip() == BODY.decode(),
              f"{h3_bad}")

        # ---- 4) 恢复证书 B：下一轮轮询重新加载成功 ----
        before = log_text().count("TLS 已热刷新")
        install("b")

        def reloaded_again():
            n = log_text().count("TLS 已热刷新")
            return (n > before, n)

        ok, detail = wait_for(reloaded_again)
        check("修复证书后热刷新恢复成功（日志再次出现 TLS 已热刷新）", ok, f"count={detail} before={before}")

        # ---- 5) 全程同一进程 ----
        pid_file = os.path.join(ROOT, "conf", "logs", "tls_reload.pid")
        pid_ok = os.path.exists(pid_file) and open(pid_file).read().strip() == str(proc.pid)
        check("pid 文件与子进程一致（未重启）", pid_ok,
              f"file={open(pid_file).read().strip() if os.path.exists(pid_file) else None!r} actual={proc.pid}")
        check("进程全程存活", proc.poll() is None, f"returncode={proc.poll()}")

        log = log_text()
        check("日志确认证书热刷新（含监听地址）", "TLS 已热刷新" in log and str(PORT) in log)
        check("日志确认 QUIC 端点热刷新（含 UDP 监听地址）",
              "QUIC 证书已热刷新" in log and str(QUIC_PORT) in log)
    finally:
        if ka is not None:
            ka.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        # 还原为启动证书 A，保持夹具可重复
        try:
            install("a")
        except SystemExit:
            pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== TLS 证书热重载 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
