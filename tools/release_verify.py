"""发布产物闸门：验证 target/dist/archives 里**随包的 zip**（解压后驱动），不是构建树里的 exe。

为什么单独要这一个脚本：构建树的 target/release/onrouter.exe 可能被别的脚本换掉过
（tls_legacy_e2e.py 会临时写入 native-tls 构建），而且 CI 打包的产物和本地构建不是同一份字节。
这里检查的是用户实际下载到的东西：

  1) 解压出的 onrouter.exe 自报版本 == Cargo.toml 版本，响应 Server 头同样是这个版本；
  2) 随包的 conf/front_proxy_examples.conf 用这个二进制 -t 退 0，并且真能服务静态文件；
  3) 带 CF-Ray 探针头的请求被标成 cloudflare-edge，而 $remote_addr 仍是直连对端（识别 ≠ 信任），
     缺探针的对照请求**不**被标成 Cloudflare（探针是 AND 语义）；
  4) 二进制里厂商名/专有头 0 命中，并打印控制项次数（front_proxy / auto_trust / nginx 自己的头），
     防止"grep 写错了所以 0 命中"这种假阳性 —— 控制项必须 > 0。

用法：python tools/release_verify.py [path/to/archive.zip]
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CARGO = os.path.join(ROOT, "Cargo.toml")
CONF_REL = os.path.join("conf", "front_proxy_examples.conf")
PORT = 18400
GW = "127.0.0.1"

VENDOR_PATTERNS = [
    "Cloudflare", "CF-Connecting-IP", "CF-IPCountry", "CF-Ray", "CF-IPFS",
    "Fastly", "CloudFront", "CloudFront-Viewer", "Akamai", "X-Akamai", "CDN-Loop",
]
CONTROLS = ["front_proxy", "auto_trust", "x-real-ip", "x-forwarded-for"]

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)


def version():
    with open(CARGO, encoding="utf-8") as f:
        for line in f:
            m = re.match(r'^version = "([^"]+)"', line)
            if m:
                return m.group(1)
    raise SystemExit("!! Cargo.toml 里没有 version")


def default_archive(ver):
    p = os.path.join(ROOT, "target", "dist", "archives", "onrouter-v%s-x86_64-pc-windows-msvc.zip" % ver)
    if not os.path.exists(p):
        raise SystemExit("!! 找不到随包产物 %s（先跑 build-release.ps1）" % p)
    return p


def hdr(hs, name):
    # 响应头名是小写的（x-fp / server），而 dict(headers) 会丢掉大小写无关查找，必须自己按小写取。
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((GW, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def request(path, headers=None, timeout=15):
    """显式绕开系统代理：走代理时那些厂商形状的头会被改写，测出来的就不是网关的行为了。"""
    import urllib.error
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request("http://%s:%d%s" % (GW, PORT, path), method="GET", headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    ver = version()
    archive = sys.argv[1] if len(sys.argv) > 1 else default_archive(ver)
    print("=== 发布产物验证：%s（版本 %s）===" % (os.path.basename(archive), ver))

    tmp = tempfile.mkdtemp(prefix="orr-verify-")
    with zipfile.ZipFile(archive) as z:
        z.extractall(tmp)
    exe = os.path.join(tmp, "onrouter.exe" if os.name == "nt" else "onrouter")
    check("zip 里有网关二进制", os.path.exists(exe), exe)
    check("zip 里有 orr-gencert 证书工具",
          os.path.exists(os.path.join(tmp, "orr-gencert.exe" if os.name == "nt" else "orr-gencert")))

    out = subprocess.run([exe, "--version"], capture_output=True).stdout.decode(errors="replace")
    check("解压出的二进制自报 %s" % ver, ver in out, out.strip())

    t = subprocess.run([exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True)
    check("-t 随包的 front_proxy 示例配置退 0", t.returncode == 0, t.stderr.decode(errors="replace")[:400])

    logf = open(os.path.join(ROOT, "logs", "release_verify_out.log"), "wb")
    proc = subprocess.Popen([exe, os.path.join(ROOT, CONF_REL)], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        check("监听 %d 端口起来了" % PORT, wait_port(PORT))
        st, hd, body = request("/")
        check("静态文件真的服务出去了", st == 200 and len(body) > 100, (st, len(body)))
        check("Server 头报 %s" % ver, ver in (hdr(hd, "Server") or ""), hdr(hd, "Server"))

        cf = {
            "CF-Ray": "8f3c1d2e4f5a6b7c-LAX",
            "CF-Connecting-IP": "203.0.113.9",
            "CF-IPCountry": "JP",
            "X-Forwarded-For": "203.0.113.9",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "yxpil.com",
        }
        st, hd, body = request("/who", cf)
        label = (hdr(hd, "X-Fp") or "").strip()
        check("带 CF-Ray 探针头认出 cloudflare-edge（示例配置随包可用）", label == "cloudflare-edge", label)
        check("识别不等于信任：detect 档 $remote_addr 仍是直连对端",
              body.decode(errors="replace").strip() == GW, body[:40])
        check("伪造头买不到改写：X-Fp-Verified 不为 true",
              (hdr(hd, "X-Fp-Verified") or "").strip().lower() != "true")
        st, hd, _ = request("/who", {"CF-Connecting-IP": "203.0.113.9"})
        check("缺探针 CF-Ray 不认成 Cloudflare（探针 AND 语义在产物里同样成立）",
              (hdr(hd, "X-Fp") or "").strip() != "cloudflare-edge", hdr(hd, "X-Fp"))
        text = request("/metrics")[2].decode(errors="replace")
        check("/metrics 里有这条 profile 的识别计数",
              "onrouter_front_proxy_total" in text and 'profile="cloudflare-edge"' in text)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    data = open(exe, "rb").read()
    shutil.rmtree(tmp, ignore_errors=True)
    for v in VENDOR_PATTERNS:
        n = len(re.findall(re.escape(v).encode(), data, re.IGNORECASE))
        check("二进制里没有厂商名/专有头 %s" % v, n == 0, n)
    ctrl = {c: len(re.findall(re.escape(c).encode(), data, re.IGNORECASE)) for c in CONTROLS}
    check("控制项有命中（证明 grep 本身写对了）", all(ctrl[c] > 0 for c in ["front_proxy", "auto_trust"]), ctrl)
    print("  控制项：" + "  ".join("%s=%d" % (c, ctrl[c]) for c in CONTROLS))

    bad = [n for n, o in results if not o]
    print("\n==== 发布产物验证：%d/%d passed ====" % (len(results) - len(bad), len(results)))
    if bad:
        for n in bad:
            print("  FAILED:", n)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
