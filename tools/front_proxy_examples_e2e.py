# -*- coding: utf-8 -*-
# front_proxy **真实厂商声明**的 E2E —— 只证明一件事：CDN 完全靠配置声明，二进制里没有任何厂商知识。
#
# 与 tools/front_proxy_e2e.py 的分工：那个套件用 X-Demo-Edge-* 这种假头名把**机制**测穿
# （改写、闸门、Cache-Status、限流键、告警）；这个套件用**真实的厂商头名与真实网段**
# （conf/front_proxy_examples.conf）证明：
#   1) 抄来的三份声明能被解析、能按书写顺序构成地址链、网段条数对得上官方发布列表
#   2) 只用真实形状的头就能认出是谁（CF-Ray / CloudFront-Viewer-Address / 纯 XFF 三家互不干扰）
#   3) 认出但"直连对端不在网段里"时，一个值都不改 —— 本机环回打不进任何一家真实网段，
#      所以这份示例配置天然演示"识别 ≠ 信任"，不需要额外关掉什么
#   4) detect 是安静的：不告警、不改访问日志身份，只在 /metrics 记 matched
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/front_proxy_examples_e2e.py
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

try:  # Windows 控制台默认代码页会把中文断言输出打成乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF_REL = os.path.join("conf", "front_proxy_examples.conf")
CONF = os.path.join(ROOT, CONF_REL)
LOG_DIR = os.path.join(ROOT, "conf", "logs")
ACCESS_LOG = os.path.join(LOG_DIR, "front_proxy_examples_access.log")
ERR_LOG = os.path.join(LOG_DIR, "front_proxy_examples_err.log")
OUT_LOG = os.path.join(LOG_DIR, "front_proxy_examples_out.log")

PORT = 18400
GW = "127.0.0.1"

# 真实形状的头名与取值（2026-10-20 对照各家公开文档核对，见 conf/front_proxy_examples.conf）
CF = {
    "CF-Ray": "8f3c1d2e4f5a6b7c-LAX",
    "True-Client-IP": "198.51.100.24",
    "CF-Connecting-IP": "203.0.113.7",
    "CF-IPCountry": "US",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "yxpil.com",
    "X-Forwarded-For": "203.0.113.7",
}
CF_ONLY_IP = {"CF-Connecting-IP": "203.0.113.7"}  # 缺探针：不该被认成 Cloudflare
CF_ONLY_RAY = {"CF-Ray": "abc123-FRA", "CF-Connecting-IP": "203.0.113.8"}  # 无 True-Client-IP：链要退到下一档
CF_RAY_AND_XFF = {"CF-Ray": "abc123-SEA", "X-Forwarded-For": "203.0.113.9, 192.0.2.5"}  # 两家都像：先声明者胜
CF_DIST = {
    "CloudFront-Viewer-Address": "198.51.100.10:46532",
    "CloudFront-Viewer-Country": "JP",
    "CloudFront-Forwarded-Proto": "https",
    "X-Forwarded-Host": "static.example.net",
    "X-Forwarded-For": "198.51.100.10",
}
XFF_ONLY = {"X-Forwarded-For": "203.0.113.42, 192.0.2.1"}

results = []
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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


def request(path, headers=None, timeout=15):
    req = urllib.request.Request(f"http://{GW}:{PORT}{path}", method="GET", headers=headers or {})
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def hdr(hs, name):
    for k, v in hs.items():
        if k.lower() == name.lower():
            return v
    return None


def who(headers=None):
    """返回 (标签, 是否已验证, 国家, 响应体里的 $remote_addr)。"""
    st, hs, body = request("/who", headers=headers)
    assert st == 200, f"/who 未就绪: {st}"
    return (
        (hdr(hs, "X-Fp") or "").strip(),
        (hdr(hs, "X-Fp-Verified") or "").strip(),
        (hdr(hs, "X-Fp-Country") or "").strip(),
        body.decode(errors="replace").strip(),
    )


def run_t(exe):
    return subprocess.run(
        [exe, "-t", "-c", CONF_REL],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def fp_metric(text, profile, role):
    m = re.search(
        r'onrouter_front_proxy_total\{profile="%s",role="%s"\}\s+(\d+)' % (re.escape(profile), role), text
    )
    return int(m.group(1)) if m else None


def read_lines(path, timeout=6.0):
    deadline = time.time() + timeout
    lines = []
    while time.time() < deadline:
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = [l for l in f.read().splitlines() if l.strip()]
            if lines:
                break
        time.sleep(0.2)
    return lines


def main():
    for p in (ACCESS_LOG, ERR_LOG, OUT_LOG):
        try:
            os.remove(p)
        except OSError:
            pass
    exe = find_binary()

    # ==================== 配置层：抄来的声明必须原样被读懂 ====================
    r = run_t(exe)
    out = (r.stdout or "") + (r.stderr or "")
    check("-t 通过厂商示例配置", r.returncode == 0, f"rc={r.returncode}\n{out}")
    check(
        "-t 三条 profile 全被读出来",
        all(n in out for n in ("'cloudflare-edge'", "'cloudfront-edge'", "'my-own-edge'")),
        out,
    )
    check(
        "Cloudflare 的地址链按书写顺序成立（True-Client-IP → CF-Connecting-IP → XFF）",
        "[true-client-ip → cf-connecting-ip → x-forwarded-for]" in out,
        out,
    )
    check(
        "Cloudflare 网段条数 = 官方列表快照的 15 个 v4 + 7 个 v6",
        re.search(r"'cloudflare-edge'（[^）]*trust 网段 22 条", out) is not None,
        out,
    )
    check(
        "CloudFront 没填网段时是 0 条（只识别、永不自证），不是偷偷继承别家的",
        re.search(r"'cloudfront-edge'（[^）]*trust 网段 0 条", out) is not None,
        out,
    )
    check(
        "自建层用私有网段也照样能声明（3 条）",
        re.search(r"'my-own-edge'（[^）]*trust 网段 3 条", out) is not None,
        out,
    )
    check(
        "detect 起步的配置在 -t 上不产生 auto_trust 告警（照抄示例不该先挨一顿提醒）",
        "front_proxy_auto_trust" not in out,
        out,
    )

    # ==================== 运行层：真实头形状 + 环回对端 ====================
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(80):
            try:
                if request("/who", timeout=2)[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not ready:
            raise SystemExit(f"!! 网关未就绪（端口 {PORT} 被占用？看 {OUT_LOG}）")

        label, verified, _country, addr = who()
        check("不带任何厂商头的普通请求：谁都没被认出来，地址仍是环回", label == "" and addr == GW, f"{label!r} {addr}")

        label, verified, country, addr = who(CF)
        check("全套真实 Cloudflare 头 → 认出 cloudflare-edge", label == "cloudflare-edge", f"{label!r}")
        check(
            "但环回不在 Cloudflare 的网段里：verified 为空、$remote_addr 一个字都不改",
            verified == "" and addr == GW,
            f"verified={verified!r} addr={addr}",
        )
        check("detect 档连国家都不采（只标注，不改任何行为）", country == "", f"{country!r}")

        label, verified, _c, addr = who(CF_ONLY_IP)
        check("只有 CF-Connecting-IP、缺探针 CF-Ray → 不认成 Cloudflare（探针是 AND 语义）", label != "cloudflare-edge", f"{label!r}")
        check("同上：地址当然也没动", addr == GW, addr)

        label, _v, _c, addr = who(CF_ONLY_RAY)
        check("带 CF-Ray 的裸请求 → 认出 cloudflare-edge（首档 True-Client-IP 缺失不影响识别）", label == "cloudflare-edge", f"{label!r}")

        label, _v, _c, addr = who(CF_DIST)
        check("CloudFront 的 ip:port 形状 → 认出 cloudfront-edge", label == "cloudfront-edge", f"{label!r}")
        check("0 条网段的 profile 认得出但一律不采信（地址仍是环回）", addr == GW, addr)

        label, _v, _c, addr = who(XFF_ONLY)
        check("只有 XFF → 认出自建的 my-own-edge", label == "my-own-edge", f"{label!r}")

        label, _v, _c, addr = who(CF_RAY_AND_XFF)
        check("两家都像时按声明顺序择优：先声明的 cloudflare-edge 胜出", label == "cloudflare-edge", f"{label!r}")

        st, _hs, _b = request("/metrics")
        text = _b.decode(errors="replace")
        check("/metrics 按 profile 展开了 cloudflare-edge 的 matched 计数", (fp_metric(text, "cloudflare-edge", "matched") or 0) >= 2, text[:400])
        check(
            "detect 档不该有任何改写类计数（ip_applied/ip_blocked 要么不出现，要么为 0）",
            not fp_metric(text, "cloudflare-edge", "ip_applied")
            and not fp_metric(text, "cloudflare-edge", "ip_blocked"),
            str((fp_metric(text, "cloudflare-edge", "ip_applied"), fp_metric(text, "cloudflare-edge", "ip_blocked"))),
        )
        check("/metrics 里 cloudfront-edge 也各自计数（三条 profile 不串账）", (fp_metric(text, "cloudfront-edge", "matched") or 0) >= 1, text[:400])

        firsts = []
        for line in read_lines(ACCESS_LOG):
            firsts.append(line.split()[0])
        check("访问日志首列全是环回：detect 不改写日志里的客户端身份", bool(firsts) and all(f == GW for f in firsts), str(firsts[:5]))

        err_lines = read_lines(ERR_LOG, timeout=2.0)
        check("识别成功但来源不可信的请求不打告警（那是 egress 档的事，detect 要安静）", not any("没走通" in l for l in err_lines), str(err_lines[:3]))
        check("错误日志里没有 panic / ERROR 级意外", not any("panicked" in l or " [error] " in l.lower() for l in err_lines), str(err_lines[:3]))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== front_proxy 厂商示例 E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
