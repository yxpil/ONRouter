# -*- coding: utf-8 -*-
# 旧协议 TLS E2E —— 证明 feature-gated 的“平台原生后端”（Windows=Schannel）能协商内置 rustls
# 无法实现的 TLS 1.0 / 1.1，同时证明默认（纯 rustls）构建会拒绝旧协议、仅服务 1.2/1.3。
#
# 为什么需要两个二进制：
#   * rustls 0.23 只实现 TLS1.2/1.3，无法协商 TLS1.0/1.1（协议根本不在其能力内）。
#   * native-tls（Windows Schannel）能，但 Identity::from_pkcs8 只接受 RSA 私钥，
#     拒绝 ECDSA（本机 certs_scenario 是 id-ecPublicKey，故本套件在运行时自签一张
#     RSA-2048 证书，用完即删，绝不落盘进仓库）。
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/tls_legacy_e2e.py
#
# 依赖：openssl 客户端（本机 MSYS2 openssl 3.5.7）。设 ONROUTER_SKIP_BUILD=1 可复用已构建二进制。
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 18131
CONNECT = "127.0.0.1"  # 服务绑定 IPv4；localhost 在 Windows 可能先解析到 ::1
HOST = "localhost"     # SNI/证书 SAN 用 localhost
BODY = "legacy-ok"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def build_native(dst):
    r = run(["cargo", "build", "--release", "--features", "native-tls",
             "-p", "onrouter-server", "--bin", "onrouter"])
    if r.returncode != 0:
        raise SystemExit("!! native-tls 构建失败：\n" + r.stderr[-2000:])
    src = os.path.join(ROOT, "target", "release", "onrouter.exe")
    shutil.copy(src, dst)


def build_default(dst):
    r = run(["cargo", "build", "--release", "-p", "onrouter-server", "--bin", "onrouter"])
    if r.returncode != 0:
        raise SystemExit("!! 默认构建失败：\n" + r.stderr[-2000:])
    src = os.path.join(ROOT, "target", "release", "onrouter.exe")
    shutil.copy(src, dst)


def gen_rsa_cert(tmp):
    pem = os.path.join(tmp, "server.pem")
    key = os.path.join(tmp, "server.key")
    r = run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key, "-out", pem, "-days", "1", "-nodes",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"])
    if r.returncode != 0 or not os.path.exists(pem):
        raise SystemExit("!! openssl 生成 RSA 自签证书失败（需要 openssl 在 PATH）：\n" + (r.stderr or "")[-1500:])
    return pem, key


def write_conf(tmp, pem, key):
    # 绝对路径 + 正斜杠：Windows/Rust 都接受，避开反斜杠转义
    def esc(p):
        return os.path.abspath(p).replace("\\", "/")
    conf = os.path.join(tmp, "legacy.conf")
    with open(conf, "w", encoding="utf-8") as f:
        f.write(
            'error_log "%s" info;\n' % esc(os.path.join(tmp, "err.log")) +
            'pid "%s";\n' % esc(os.path.join(tmp, "onrouter.pid")) +
            "server {\n"
            "    listen 127.0.0.1:%d ssl;\n" % PORT +
            "    server_name legacy.local;\n"
            '    ssl_certificate     "%s";\n' % esc(pem) +
            '    ssl_certificate_key "%s";\n' % esc(key) +
            "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n"
            '    location / { return 200 "%s\\n"; }\n' % BODY +
            "}\n"
        )
    return conf


def kill(exe_name):
    try:
        subprocess.run(["taskkill", "/F", "/IM", exe_name], capture_output=True, text=True)
    except Exception:
        pass


def start(exe, conf, tmp):
    outlog = open(os.path.join(tmp, "out.log"), "wb")
    proc = subprocess.Popen([exe, conf], cwd=ROOT, stdout=outlog, stderr=subprocess.STDOUT)
    return proc, outlog


def wait_ready():
    # 先做纯 TCP 连通判定（服务绑定即成功），再做一次 1.2 TLS 握手确认后端可用
    import socket as _s
    for _ in range(150):
        try:
            with _s.create_connection((CONNECT, PORT), timeout=1):
                pass
        except OSError:
            time.sleep(0.2)
            continue
        if s_client("1.2")["ok"]:
            return True
        time.sleep(0.2)
    return False


def dump(tmp, why):
    print("---- 诊断：%s ----" % why)
    for name in ("out.log", "err.log"):
        p = os.path.join(tmp, name)
        print("[%s]" % name)
        if os.path.exists(p):
            with open(p, "rb") as f:
                print(f.read().decode("utf-8", "replace")[-1200:])
        else:
            print("(不存在)")
    print("---- 临时目录（退出时清理）：%s ----" % tmp)


def s_client(version, timeout=10):
    """用 openssl s_client 钉死单一版本；返回 {ok, ver, body}。
    旧协议需 -cipher DEFAULT@SECLEVEL=0 才能被 openssl 客户端发出。
    请求以 bytes 传入：Windows 上 text=True 会把 \n 转成 \r\n，叠加我们显式写的
    \r\n 变成 \r\r\n，HTTP 请求行被多余 CR 破坏 → 服务器返回 400。故全程走字节。"""
    flag = {"1.0": "-tls1", "1.1": "-tls1_1", "1.2": "-tls1_2", "1.3": "-tls1_3"}[version]
    cmd = ["openssl", "s_client", "-connect", "%s:%d" % (CONNECT, PORT),
           flag, "-servername", HOST]
    if version in ("1.0", "1.1"):
        cmd += ["-cipher", "DEFAULT@SECLEVEL=0"]
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % HOST).encode()
    try:
        p = subprocess.run(cmd, input=req, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": "timeout", "ver": "", "body": "", "raw": ""}
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    ver = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Protocol  :"):
            ver = s.split(":", 1)[1].strip()
    ok = BODY in out
    return {"ok": ok, "ver": ver, "body": BODY if ok else out[-200:], "raw": out}


def read_err(tmp):
    p = os.path.join(tmp, "err.log")
    if not os.path.exists(p):
        return ""
    # 中文日志按字节读，避免编码问题
    with open(p, "rb") as f:
        return f.read().decode("utf-8", "replace")


def probe_all(tag):
    return {v: s_client(v) for v in ("1.0", "1.1", "1.2", "1.3")}


def main():
    for exe in ("openssl",):
        if shutil.which(exe) is None:
            raise SystemExit("!! 需要 %s 在 PATH" % exe)

    tmp = tempfile.mkdtemp(prefix="onrouter-legacy-")
    pem, key = gen_rsa_cert(tmp)
    conf = write_conf(tmp, pem, key)

    native_exe = os.path.join(tmp, "onrouter-native.exe")
    default_exe = os.path.join(tmp, "onrouter-default.exe")
    if os.environ.get("ONROUTER_SKIP_BUILD") == "1":
        # 复用调用方预先放到 tmp 之外的二进制
        cand = os.path.join(ROOT, "target", "release", "onrouter.exe")
        shutil.copy(cand, native_exe)
        shutil.copy(cand, default_exe)
        print("!! ONROUTER_SKIP_BUILD=1：两阶段都用同一二进制，仅当它确为 native 构建时有效")
    else:
        build_native(native_exe)
        build_default(default_exe)

    try:
        # ========== 阶段 A：native 后端应协商全部 1.0/1.1/1.2/1.3 ==========
        kill("onrouter-native.exe")
        proc, outlog = start(native_exe, conf, tmp)
        try:
            if not wait_ready():
                dump(tmp, "native 服务未就绪")
                raise SystemExit("!! native 服务未就绪")
            res = probe_all("native")
            check("native：TLS1.0 握手成功", res["1.0"]["ok"], f"raw={res['1.0'].get('raw','')[-200:]}")
            check("native：TLS1.0 协商到 TLSv1", res["1.0"]["ver"] == "TLSv1", f"ver={res['1.0']['ver']}")
            check("native：TLS1.1 握手成功", res["1.1"]["ok"], f"raw={res['1.1'].get('raw','')[-200:]}")
            check("native：TLS1.1 协商到 TLSv1.1", res["1.1"]["ver"] == "TLSv1.1", f"ver={res['1.1']['ver']}")
            check("native：TLS1.2 握手成功", res["1.2"]["ok"], f"raw={res['1.2'].get('raw','')[-200:]}")
            check("native：TLS1.3 握手成功", res["1.3"]["ok"], f"raw={res['1.3'].get('raw','')[-200:]}")
            err = read_err(tmp)
            check("native：日志确认走平台原生后端", ("原生" in err or "native" in err), f"err.log 摘要={err[-300:]!r}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            outlog.close()
            kill("onrouter-native.exe")

        # ========== 阶段 B：默认 rustls 应拒绝 1.0/1.1、仍服务 1.2/1.3 ==========
        # 清空 err.log 以便断言本阶段的告警
        ep = os.path.join(tmp, "err.log")
        if os.path.exists(ep):
            os.remove(ep)
        kill("onrouter-default.exe")
        proc, outlog = start(default_exe, conf, tmp)
        try:
            if not wait_ready():
                dump(tmp, "默认 服务未就绪")
                raise SystemExit("!! 默认服务未就绪，看 %s" % ep)
            res = probe_all("default")
            check("默认(rustls)：TLS1.2 仍可", res["1.2"]["ok"], f"raw={res['1.2'].get('raw','')[-200:]}")
            check("默认(rustls)：TLS1.3 仍可", res["1.3"]["ok"], f"raw={res['1.3'].get('raw','')[-200:]}")
            check("默认(rustls)：TLS1.0 被拒绝", not res["1.0"]["ok"], f"expected reject got={res['1.0']}")
            check("默认(rustls)：TLS1.1 被拒绝", not res["1.1"]["ok"], f"expected reject got={res['1.1']}")
            err = read_err(tmp)
            check("默认(rustls)：日志提示未启用 native-tls",
                  ("native-tls" in err or "旧协议" in err), f"err.log 摘要={err[-300:]!r}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            outlog.close()
            kill("onrouter-default.exe")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)  # 私钥/证书只存在于临时目录，随用随删

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== legacy TLS E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
