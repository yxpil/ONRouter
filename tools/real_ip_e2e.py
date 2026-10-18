# -*- coding: utf-8 -*-
# nginx realip 模块 E2E —— 用真实流量证明 $remote_addr 被真实客户端 IP 覆盖，且 geo 等下游派生变量随之前移。
#   cargo build --release -p onrouter-server --bin onrouter && python tools/real_ip_e2e.py
#
#   所有连接都来自 127.0.0.1，用不同端口=不同 server（不同 set_real_ip_from）区分可信/不可信对端。
import os
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "real_ip_e2e.conf")

GW = "127.0.0.1"
P_REALIP_TRUSTED = 18180
P_REALIP_UNTRUSTED = 18181
P_XFF_OFF = 18182
P_XFF_ON = 18183

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


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(port, path="/", headers=None):
    req = urllib.request.Request(f"http://{GW}:{port}{path}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = _opener.open(req, timeout=10)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def parse_kv(body):
    d = {}
    for ln in body.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def wait_ready(port):
    for _ in range(80):
        try:
            if get(port)[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def main():
    exe = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "real_ip_e2e_out.log"), "wb")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    try:
        for p in (P_REALIP_TRUSTED, P_REALIP_UNTRUSTED, P_XFF_OFF, P_XFF_ON):
            if not wait_ready(p):
                raise SystemExit(f"!! onrouter 未就绪（端口 {p} 被占用？看 logs/real_ip_e2e_out.log）")

        # 1) 可信对端 + X-Real-IP：改写 + geo 命中改写后 IP 的网段
        st, body = get(P_REALIP_TRUSTED, headers={"X-Real-IP": "203.0.113.9"})
        kv = parse_kv(body)
        check("可信对端：$remote_addr 被 X-Real-IP 覆盖", kv.get("addr") == "203.0.113.9",
              f"body={body!r}")
        check("可信对端：geo $net 命中改写后 IP 的网段(testnet)", kv.get("net") == "testnet",
              f"body={body!r}")
        check("原始头仍可经 $http_x_real_ip 读取", kv.get("seen") == "203.0.113.9", f"body={body!r}")

        # 2) 不可信对端：伪造头被无视，$remote_addr 保持真实 socket 对端（防伪造）
        st, body = get(P_REALIP_UNTRUSTED, headers={"X-Real-IP": "203.0.113.9"})
        kv = parse_kv(body)
        check("不可信对端：X-Real-IP 被忽略（防伪造）", kv.get("addr") == "127.0.0.1",
              f"body={body!r}")
        check("不可信对端：geo $net 回落 localnet（仍按真实对端）", kv.get("net") == "localnet",
              f"body={body!r}")

        # 3+4) 同一 XFF 值，recursive off vs on —— 清晰对照
        xff = "203.0.113.5, 198.51.100.9"  # 198.51/24 在 :18183 是可信代理段
        st, body = get(P_XFF_OFF, headers={"X-Forwarded-For": xff})
        kv = parse_kv(body)
        check("XFF recursive off：取最右地址(代理 198.51.100.9)", kv.get("addr") == "198.51.100.9",
              f"body={body!r}")
        check("XFF recursive off：geo 对该代理段判 external", kv.get("net") == "external",
              f"body={body!r}")

        st, body = get(P_XFF_ON, headers={"X-Forwarded-For": xff})
        kv = parse_kv(body)
        check("XFF recursive on：跳过可信(198.51/24)取真实客户端(203.0.113.5)",
              kv.get("addr") == "203.0.113.5", f"body={body!r}")
        check("XFF recursive on：geo 对真实客户端判 testnet", kv.get("net") == "testnet",
              f"body={body!r}")

        # 5) 可信对端但无该头 → 不改写（保持 127.0.0.1）
        st, body = get(P_REALIP_TRUSTED)  # 不发 X-Real-IP
        kv = parse_kv(body)
        check("可信对端但缺头部：保持真实对端 127.0.0.1", kv.get("addr") == "127.0.0.1",
              f"body={body!r}")

        # 6) 非法/非 IP 头部值 → 静默忽略，不改写
        st, body = get(P_REALIP_TRUSTED, headers={"X-Real-IP": "not-an-ip"})
        kv = parse_kv(body)
        check("非法头部值：不改写（保持 127.0.0.1）", kv.get("addr") == "127.0.0.1", f"body={body!r}")

        # 7) IPv4:port 与带空格链的容错解析（XFF on，右段可信）
        st, body = get(P_XFF_ON, headers={"X-Forwarded-For": "  203.0.113.200 , 198.51.100.8:4321 "})
        kv = parse_kv(body)
        check("XFF 容错：端口/空格被正确处理，跳过可信得 203.0.113.200",
              kv.get("addr") == "203.0.113.200", f"body={body!r}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== realip E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
