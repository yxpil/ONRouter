# -*- coding: utf-8 -*-
"""规模与并发压测 —— 大促 / 前置 CDN 形状：几百~几千域名挂在少数几个监听端口上，
外加游戏服务器形状的多 TCP 端口聚合。测的是**扩展性曲线**，不是单次吞吐。

    python tools/scale_stress.py                 # 默认扫 vhost 数与端口数
    python tools/scale_stress.py --only vhosts   # 只跑一轴
    python tools/scale_stress.py --conns 20000   # 并发爬升目标

两件事必须分开，否则结论会被混掉：

1. **配置规模**：`-t` 耗时、启动耗时、RSS、每站内存。几千个 server 块是不是线性变贵。
2. **每请求的选站成本**：`match_server` 是在该端口的 vhost 列表上顺序扫，所以 1 站与
   3000 站挂在同一个 443 上时，每个请求的开销差别就是这一轴要量出来的东西。同理
   `groups` 是 HashMap<SocketAddr,…>，监听地址与请求本地地址不完全相等时要退化成
   按端口扫全表取最小 —— 几百个监听端口时这条兜底路径也会被每个请求踩到。

并发上限的诚实说明：本机回环做几十万连接受限于 (源IP,源端口) 四元组与 fd，
所以这里报"实测爬到多少、卡在什么上"，不报"能到几十万"。用 127.0.0.x 扩源地址。
"""

import argparse
import http.client
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "target", "release", "onrouter.exe" if os.name == "nt" else "onrouter")
CONF = os.path.join(ROOT, "conf", "scale_stress.conf")
ERRLOG = os.path.join(ROOT, "logs", "scale_stress_err.log")
CERTS = ["fallback", "a", "b", "c", "d", "wildcard", "wildx", "wily"]


def write_conf(vhosts=1, tcp_ports=0, tls_vhosts=0, base_port=18800):
    """生成 conf：一个明文端口挂 vhosts 个站，一个 TLS 端口挂 tls_vhosts 个站，
    再加 tcp_ports 个 stream 监听端口（游戏服务器形状的多端口聚合）。"""
    L = []
    L.append("# 由 tools/scale_stress.py 生成")
    L.append('error_log "logs/scale_stress_err.log" warn;')
    L.append("pid logs/scale_stress.pid;")
    L.append("worker_threads 4;")
    L.append("proxy_cache_path logs/scale_cache keys_zone=sc:8m;")
    L.append("upstream origin { server 127.0.0.1:%d; keepalive 64; }" % (base_port + 900))
    L.append('server { listen %d; location /health { return 200 "ok\\n"; } }\n' % base_port)
    for i in range(vhosts):
        n = f"h{i}.scale.test"
        L.append(f"server {{ listen {base_port}; server_name {n}; "
          f"location /health {{ return 200 \"{n}\\n\"; }} "
          f"location /api{i} {{ proxy_pass http://origin; }} }}")
    for i in range(tls_vhosts):
        n = f"t{i}.scale.test"
        cert = CERTS[i % len(CERTS)]
        L.append(f"server {{ listen {base_port + 1} ssl http2; server_name {n}; "
          f'ssl_certificate "../certs_random/{cert}.pem"; '
          f'ssl_certificate_key "../certs_random/{cert}.key"; '
          f'location /health {{ return 200 "{n}\\n"; }} }}')
    if tcp_ports:
        L.append("stream {")
        for i in range(tcp_ports):
            L.append(f"    server {{ listen {base_port + 2 + i}; "
              f"proxy_pass 127.0.0.1:{base_port + 901}; proxy_timeout 5s; }}")
        L.append("}")
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    return len(L)


def rss_mib(proc):
    def ps(cmd):
        # 中文 Windows 的管道默认 cp936，直接 text=True 会用 gbk 解 powershell 的 UTF-8 输出并抛异常
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True)
        for enc in ("utf-8", "utf-16", "gbk"):
            try:
                return r.stdout.decode(enc).strip()
            except UnicodeDecodeError:
                continue
        return ""

    out = ps(f"$p = Get-Process -Id {proc.pid} -ErrorAction SilentlyContinue;"
             "if ($p) { '{0} {1}' -f $p.WorkingSet64, $p.HandleCount } else { '-1 -1' }")
    parts = out.split()
    try:
        return int(parts[0]) / 1048576.0, (int(parts[1]) if len(parts) > 1 else -1)
    except ValueError:
        return -1.0, -1


def timed_t():
    t0 = time.perf_counter()
    p = subprocess.run([EXE, "-t", "-c", os.path.relpath(CONF, ROOT)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    dt = (time.perf_counter() - t0) * 1000.0
    return dt, p.returncode, (p.stdout or "") + (p.stderr or "")


def start():
    logf = open(os.devnull, "wb")
    proc = subprocess.Popen([EXE, CONF], cwd=ROOT, stdout=logf, stderr=logf)
    proc._logf = logf
    return proc


def wait_port(port, timeout=60, up=True):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            if up:
                return True
        except OSError:
            if not up:
                return True
        time.sleep(0.1)
    return False


def load(port, paths, seconds=4.0, conns=64, host_pick=None, src_ips=1):
    """keep-alive 压测：conns 个长连接循环请求 paths，返回吞吐与延迟分位。"""
    lat, errs = [], {}
    stop = time.time() + seconds
    lock = threading.Lock()

    def worker(idx):
        host = host_pick(idx) if host_pick else None
        src = f"127.0.{idx // 60000 % src_ips or 0}" if src_ips > 1 else "127.0.0.1"
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10,
                                           **({"source_address": (src, 0)} if src_ips > 1 else {}))
        except Exception as e:  # noqa: BLE001
            with lock:
                errs[f"connect:{type(e).__name__}"] = errs.get(f"connect:{type(e).__name__}", 0) + 1
            return
        k = 0
        local = []
        while time.time() < stop:
            path = paths[k % len(paths)]
            k += 1
            t0 = time.perf_counter()
            try:
                c.request("GET", path, headers={"Host": host} if host else {})
                r = c.getresponse()
                body = r.read()
                if r.status != 200:
                    raise RuntimeError(f"status {r.status}")
                if host and body.decode("utf-8", "replace").strip() not in (host, "ok"):
                    raise RuntimeError(f"cross-host leak: asked {host} got {body[:40]!r}")
                local.append((time.perf_counter() - t0) * 1000.0)
            except Exception as e:  # noqa: BLE001
                with lock:
                    key = f"{type(e).__name__}"
                    errs[key] = errs.get(key, 0) + 1
                try:
                    c.close()
                except OSError:
                    pass
                try:
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                except OSError:
                    break
        with lock:
            lat.extend(local)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(conns)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.perf_counter() - t0
    lat.sort()
    if not lat:
        return {"rps": 0.0, "p50": -1, "p99": -1, "n": 0, "errs": errs, "seconds": dt}
    return {
        "rps": len(lat) / dt,
        "p50": round(statistics.median(lat), 3),
        "p99": round(lat[int(len(lat) * 0.99) - 1], 3),
        "n": len(lat),
        "errs": errs,
        "seconds": round(dt, 2),
    }


def ramp(port, target, host=None, seconds=6.0):
    """并行建立 keep-alive 连接并保持住，同时在旁路测新请求的延迟 —— 这才是在问
    "网关能同时挂着多少条空闲连接、还接不接得进新请求"，而不是"我这台机器能串行握几次手"。"""
    best = 0
    info = {}
    for conns in (1000, 5000, 10000, 20000, 40000, 80000):
        if conns > target * 4:
            break
        socks, errs = [], {}
        t0 = time.perf_counter()

        def open_many(chunk):
            for i in chunk:
                try:
                    s = socket.create_connection(("127.0.%d.%d" % (i // 250 % 254 + 1, i % 250 + 1), port),
                                                 timeout=3.0)
                    s.sendall(("GET /health HTTP/1.1
Host: %s

" % (host or "h0.scale.test")).encode())
                    data = s.recv(256)
                    if b"200" not in data:
                        raise RuntimeError(f"unexpected {data[:24]!r}")
                    socks.append(s)
                except Exception as e:  # noqa: BLE001
                    k = type(e).__name__
                    errs[k] = errs.get(k, 0) + 1

        threads = []
        per = (conns + 31) // 32
        groups = [range(i, min(i + per, conns)) for i in range(0, conns, per)]
        for g in groups:
            th = threading.Thread(target=open_many, args=(g,))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()
        built = len(socks)
        probe = load(port, ["/health"], seconds=2.0, conns=16,
                     host_pick=(lambda _i: host) if host else None)
        info[built] = {"probe_p99": probe["p99"], "probe_rps": round(probe["rps"], 1), "errs": errs,
                       "open_s": round(time.perf_counter() - t0, 2)}
        print(f"   保持 {built:>6}/{conns} 条（{(time.perf_counter() - t0):.1f}s 建立）："
              f"旁路新请求 p99={probe['p99']}ms rps={probe['rps']:.0f} 失败={dict(list(errs.items())[:3])}")
        best = max(best, built)
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        if built < conns * 0.5 or probe["p99"] < 0:
            break
    return best, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["vhosts", "ports", "conns"])
    ap.add_argument("--vhosts", default="1,200,1000,3000")
    ap.add_argument("--tls-vhosts", default="1,100,500")
    ap.add_argument("--ports", default="1,200,800")
    ap.add_argument("--conns", type=int, default=20000)
    ap.add_argument("--base-port", type=int, default=18800)
    a = ap.parse_args()
    if not os.path.exists(EXE):
        raise SystemExit("!! 先 cargo build --release -p onrouter-server --bin onrouter")
    base = a.base_port
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    if a.only in (None, "vhosts"):
        print("== 轴 1：同一端口挂多少个 vhost（选站成本与配置规模）==")
        for nv in [int(x) for x in a.vhosts.split(",")]:
            for nt in ([int(x) for x in a.tls_vhosts.split(",")] if nv == 1 else [0]):
                write_conf(vhosts=nv, tls_vhosts=nt, base_port=base)
                t_ms, rc, out = timed_t()
                assert rc == 0, out[-500:]
                p = start()
                wait_port(base)
                rss, handles = rss_mib(p)
                # 只打一台站点的健康检查：路径固定，差别只来自"选站"这一步
                r1 = load(base, ["/health"], seconds=3.0, conns=64,
                          host_pick=lambda i: f"h{i % max(nv, 1)}.scale.test")
                rrand = load(base, ["/health"], seconds=3.0, conns=64)
                p.terminate(); p._logf.close()
                print(f"  vhost={nv:<5} tls_vhost={nt:<4} -t={t_ms:7.0f}ms 启动后RSS={rss:6.1f}MiB 句柄={handles} "
                      f"具名遍历 rps={r1['rps']:8.0f} p50={r1['p50']:6.2f} p99={r1['p99']:7.2f} | "
                      f"同名复用 rps={rrand['rps']:8.0f}")

    if a.only in (None, "ports"):
        print("\n== 轴 2：多端口聚合（游戏服务器形状，几百~几千 listen）==")
        for np in [int(x) for x in a.ports.split(",")]:
            write_conf(vhosts=1, tcp_ports=np, base_port=base)
            t_ms, rc, out = timed_t()
            assert rc == 0, out[-500:]
            p = start()
            wait_port(base)
            rss, handles = rss_mib(p)
            r = load(base, ["/health"], seconds=3.0, conns=64)
            p.terminate(); p._logf.close()
            print(f"  listen端口={np:<5} -t={t_ms:7.0f}ms RSS={rss:6.1f}MiB 句柄={handles} "
                  f"同进程 HTTP rps={r['rps']:8.0f} p99={r['p99']:7.2f}ms")

    if a.only in (None, "conns"):
        print(f"\n== 轴 3：并发爬升（目标 {a.conns} 条同时保持的连接）==")
        write_conf(vhosts=2000, base_port=base)
        p = start()
        wait_port(base)
        best, info = ramp(base, a.conns, host="h777.scale.test")
        r2, h2c = rss_mib(p)
        print(f"  实测能同时保持 {best} 条连接；网关句柄数={h2c}；RSS={r2:.1f}MiB")
        p.terminate(); p._logf.close()
        print("  说明：受本机 (源IP,源端口) 四元组与 fd 限制，这里报实测上限与瓶颈，不推算绝对值。")

    try:
        os.remove(CONF)
    except OSError:
        pass


if __name__ == "__main__":
    main()
