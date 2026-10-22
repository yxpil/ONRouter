# -*- coding: utf-8 -*-
"""TLS 密钥交换组（supported_groups）边界 + 握手失败的可见性。

业务形状：源站挂在 CDN 后面时，"能不能握手"由 CDN 的客户端决定，不是由我们决定。
Cloudflare 的某个 zone 实测发来的 ClientHello 里只有 secp521r1（NIST P-521）：
OpenSSL 系的 nginx 会用它谈成，rustls（provider = ring/aws-lc 都不含 P-521）只能
NoKxGroupsInCommon 拒绝，于是浏览器看到 525，而源站日志一片空白——红的是 CDN，
查不到的是自己。这套件把两件事钉住：

1. 边界要说清楚：支持的曲线必须逐个谈成（X25519 / P-256 / P-384），
   不支持的必须**干净地**拒（alert handshake_failure，不是超时、不是半握手挂住），
   而"支持 + 不支持"混在一起时必须落到支持的那条上（有些实现会整条 hello 拒绝）。
2. 失败必须留下现场：warn 级日志点名对端与原因，握手失败计数 +1。
   把日志降回 debug、或让计数器不涨，这两条断言就会红。

    cargo build --release -p onrouter-server --bin onrouter && python tools/tls_groups_e2e.py
"""
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import selfsigned  # noqa: E402

CONF = os.path.join("conf", "tls_groups.conf")
CERT_DIR = "certs_tlsgroups"
GW_TLS = 18641
GW_METRICS = 18642
SNI = "g.tls.test"
# error_log 的相对路径按配置文件所在目录解析（与 ssl_certificate 同一口径），
# 所以它落在 conf/logs/ 而不是仓库根的 logs/。
ERR_LOG = os.path.join(ROOT, "conf", "logs", "tls_groups_err.log")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else str(detail)[:220])


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def openssl_ver():
    p = subprocess.run(["openssl", "version"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", p.stdout or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def s_client(groups=None, tls13_only=False):
    """跑一次 openssl s_client，返回 (是否完成握手, 合并输出)。"""
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{GW_TLS}", "-servername", SNI]
    if groups:
        cmd += ["-groups", groups]
    if tls13_only:
        cmd += ["-tls1_3"]
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=30)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        # 卡住也当作"没谈成"：下面的断言会把它判成握手失败，套件不会整条崩
        out = "TIMEOUT after 30s"
    done = bool(re.search(r"^(New|Reused), TLSv1", out, re.M))
    return done, out


def http_over_tls():
    """握手成功后这条连接要真能应答（失败握手不能把 worker 或连接表带坏）。"""
    import ssl
    import socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", GW_TLS), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=SNI) as t:
            t.sendall(("GET / HTTP/1.1" + chr(13) + chr(10)
                       + f"Host: {SNI}" + chr(13) + chr(10)
                       + "Connection: close" + chr(13) + chr(10)
                       + chr(13) + chr(10)).encode())
            data = b""
            while len(data) < 4096:
                chunk = t.recv(4096)
                if not chunk:
                    break
                data += chunk
    return data.decode("utf-8", "replace")


def metric(name):
    try:
        with _opener.open(f"http://127.0.0.1:{GW_METRICS}/metrics", timeout=8) as r:
            body = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None
    m = re.search(re.escape(name) + r" (\d+)", body)
    return int(m.group(1)) if m else None


def warn_lines():
    """握手失败行可能落在 error_log 文件里，也可能（目录缺失时）走 stderr。

    两处都读：CI 是干净检出，conf/logs/ 不存在时日志会退到 stderr，
    断言不能因为夹具没建目录就红。
    """
    out = []
    for p in (ERR_LOG, os.path.join(ROOT, "logs", "tls_groups_out.log")):
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                out += [ln for ln in f.read().splitlines() if "TLS 握手失败" in ln]
    return out


def main():
    exe = find_binary()
    v = subprocess.run([exe, "-V"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    vtext = (v.stdout or "") + (v.stderr or "")
    pq_on = "[pq=on]" in vtext
    print("被测算的构建: " + " | ".join(x.strip() for x in vtext.splitlines() if x.strip()))
    selfsigned.ensure(ROOT, CERT_DIR, base="g", dns=(SNI,))

    t = subprocess.run([exe, "-t", "-c", CONF], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    check("-t 通过", t.returncode == 0, ((t.stdout or "") + (t.stderr or ""))[-200:])
    if t.returncode != 0:
        print(((t.stdout or "") + (t.stderr or ""))[-800:])
        sys.exit(1)

    os.makedirs(os.path.join(ROOT, "conf", "logs"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    for f in (ERR_LOG, os.path.join(ROOT, "logs", "tls_groups_out.log")):
        try:
            os.remove(f)
        except OSError:
            pass
    logf = open(os.path.join(ROOT, "logs", "tls_groups_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(80):
            if metric("onrouter_connections_active") is not None:
                break
            time.sleep(0.25)
        else:
            raise SystemExit("!! 网关未就绪，见 logs/tls_groups_out.log")

        ver = openssl_ver()
        # ---- 1. 支持的曲线必须逐条谈成 ------------------------------------
        for g in ("X25519", "secp256r1", "secp384r1"):
            done, out = s_client(g)
            check(f"仅 offered group={g} 应协商成功", done, out[-200:])
        done, out = s_client(None)
        check("默认 ClientHello（不限制曲线）应协商成功", done, out[-200:])

        # ---- 2. 混合列表要落到支持的那条，而不是整条拒绝 --------------------
        for mix in ("secp384r1:secp521r1", "secp521r1:X25519"):
            done, out = s_client(mix)
            check(f"offered groups={mix} 必须回退到支持的那条曲线", done, out[-200:])

        # ---- 3. 不支持的曲线：干净拒绝，且留下现场 --------------------------
        # 编译期决定能谈哪些组，所以断言跟着 -V 走：pq=off 时 X25519MLKEM768 必须被拒，
        # pq=on 时它必须谈成（后者就是 Cloudflare 那个 zone 发来的形状）。
        # P-521 两种构建都必须拒——rustls 的 ring 与 aws-lc 都没有它的密钥交换实现。
        before = metric("onrouter_tls_handshake_failures_total") or 0
        forced = 0
        done, out = s_client("secp521r1")
        check("offered groups=P-521 单一曲线必须被拒（任何 provider 都没有它）",
              not done, "竟然握手成功：" + out[-160:])
        check("拒绝方式是 handshake_failure 告警，不是超时/半开",
              bool(re.search(r"handshake failure|alert", out, re.I)), out[-200:])
        if not done:
            forced += 1
        if ver >= (3, 5, 0):
            done2, out2 = s_client("X25519MLKEM768")
            if pq_on:
                check("pq=on 构建必须谈成 X25519MLKEM768（CDN 的 PQC-only 回源形状）",
                      done2 and "TLSv1.3" in out2, out2[-200:])
            else:
                check("默认构建（pq=off）必须拒绝 X25519MLKEM768",
                      not done2, "竟然握手成功：" + out2[-160:])
                if not done2:
                    forced += 1
        else:
            print(f"SKIP 后量子曲线用例：本机 openssl {ver} 不认识 X25519MLKEM768")

        after = metric("onrouter_tls_handshake_failures_total")
        check(f"握手失败计数 +{forced}（实得 +{None if after is None or before is None else after - before}）",
              after is not None and before is not None and after - before == forced,
              f"before={before} after={after}")

        lines = warn_lines()
        check(f"warn 级日志出现 {forced} 行握手失败（ nginx 同款可见性）",
              len(lines) >= forced, f"行数={len(lines)} {lines[-2:]}")
        joined = " ".join(lines[-2:])
        check("握手失败日志点名对端地址", "127.0.0.1:" in joined, joined[-200:])
        check("握手失败日志给出可行动的原因（曲线/参数不匹配）",
              bool(re.search(r"incompatible|NoKxGroups", joined)), joined[-200:])

        # ---- 4. 失败握手之后服务照常 ---------------------------------------
        try:
            body = http_over_tls()
        except Exception as e:  # noqa: BLE001
            body = f"EXCEPTION {type(e).__name__}: {e}"
        check("失败握手之后，同一监听仍正常应答", "200 OK" in body and "g" in body,
              body[:160])
        st = None
        try:
            with _opener.open(f"http://127.0.0.1:{GW_METRICS}/metrics", timeout=8) as r:
                st = r.status
        except (urllib.error.URLError, OSError):
            pass
        check("另一条监听（metrics）未受影响", st == 200, st)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

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
