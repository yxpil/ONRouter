# -*- coding: utf-8 -*-
"""proxy_cache 磁盘冷层 E2E —— 用真实流量证明响应缓存的磁盘层整条链路在跑。

    cargo build --release -p onrouter-server --bin onrouter && python tools/proxy_disk_e2e.py

证明的是这几件事，全部走 HTTP 响应、/metrics 账目和真实文件：
 1. 内存容量（keys_zone）挤出去的**新鲜**响应落到 disk=on 的目录里，异步、不挡请求线程；
 2. 下一次同 key 请求由冷层供：X-Cache-Status 仍是 HIT、额外带 X-Cache-Tier: disk，
    **后端计数不变**（这一条才是"真的没回源"的证据，不是头部自称）；
 3. 读回来会提升进内存，第二次命中就不再报冷层；
 4. 没写 disk=on 的对照区同样被挤掉，但只能回源，而且目录根本不会被创建（开关是真的开关）；
 5. spill_after 门槛：一次性流量（只被请求过一次）不进冷层，disk 不会被扫库写满；
 6. 冷层文件是自描述的（magic "ORDK"），坏掉一个不会发出错内容，也不会让请求 5xx；
 7. 停机排空 + 重启扫目录：warm_recovered 与目录里的文件数一致，重启后冷命中照旧成立；
 8. /metrics 的 onrouter_proxy_cache_disk_* 只覆盖开了冷层的区，且不与 onrouter_dict_disk_* 混名。

频率门槛的"正向落盘"一侧（达到阈值才写盘）由 proxy_cache.rs 的单测覆盖，这里只验反向：
一次性流量不写盘。端口与其它套件错开（18480 / 18481）。
"""

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "proxy_disk.conf")
CONF_REL = "conf/proxy_disk.conf"
OUT_LOG = os.path.join(ROOT, "logs", "proxy_disk_out.log")

GW_HOST, GW_PORT = "127.0.0.1", 18480
BE_PORT = 18481
BASE = f"http://{GW_HOST}:{GW_PORT}"

# 冷层目录写在配置里是相对路径 → 以配置文件所在目录为基准
TIER_DIR = os.path.join(ROOT, "conf", "logs", "proxy_disk_tier")
GATE_DIR = os.path.join(ROOT, "conf", "logs", "proxy_disk_gate")
PLAIN_DIR = os.path.join(ROOT, "conf", "logs", "proxy_disk_plain")

IDS = list(range(12))          # 12 条 URL 打过一个 8 条容量的区 → 最早的 4 条必然被淘汰
PAD = "p" * 400

counter_lock = threading.Lock()
hits = {}                      # 后端真的服务过几次：(zone, id) -> count
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


def request(path, timeout=10):
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def hdr(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-0-9.eE+]+)$",
    re.M,
)


def metrics():
    st, _, body = request("/metrics", timeout=10)
    if st != 200:
        raise SystemExit(f"!! /metrics 返回 {st}")
    out = []
    for m in LINE_RE.finditer(body):
        out.append((m.group("name"), m.group("labels") or "", float(m.group("value"))))
    return out


def series(mm, zone, metric, op=None):
    """取 onrouter_proxy_cache_disk_<metric>{zone=".."[,op=".."]} 的值，没有则 None。"""
    for name, lab, val in mm:
        if name != f"onrouter_proxy_cache_disk_{metric}":
            continue
        if f'zone="{zone}"' not in lab:
            continue
        if op is not None and f'op="{op}"' not in lab:
            continue
        if op is None and "op=" in lab:
            continue
        return val
    return None


def backend_count(zone, i):
    # 后端记录的是 URL 里的 id 字符串，这里必须用同一个口径查表（早先用 int 查永远得 0，
    # 于是所有"有没有回源"的断言都失真）
    with counter_lock:
        return hits.get((zone, str(i)), 0)


def prime(zone, i, extra=""):
    """走网关取一次，返回 (status, x-cache-status, x-cache-tier, body, 后端计数增量)"""
    before = backend_count(zone, i)
    st, hs, body = request(f"/{zone}/item?id={i}{extra}")
    after = backend_count(zone, i)
    return st, hdr(hs, "X-Cache-Status"), hdr(hs, "X-Cache-Tier"), body, after - before


class Backend(BaseHTTPRequestHandler):
    """按 (zone, id) 记服务次数，并把次数写进响应体——体里的 n 不变就说明是同一份缓存副本。"""

    def do_GET(self):  # noqa: N802
        if not self.path.startswith(("/tier/", "/gate/", "/plain/")):
            self.send_response(404)
            self.end_headers()
            return
        zone = self.path.split("/")[1]
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        ident = dict(p.split("=", 1) for p in q.split("&") if "=" in p).get("id", "?")
        key = (zone, ident)
        with counter_lock:
            hits[key] = hits.get(key, 0) + 1
            n = hits[key]
        body = f"id={ident} zone={zone} n={n} {PAD}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "max-age=600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def wait_pending_zero(limit=12.0):
    """等写线程把排队的落盘做完。期间网关照常响应，这本身就是"请求线程不等磁盘"的证据。"""
    t0 = time.time()
    while time.time() - t0 < limit:
        mm = metrics()
        total = sum(
            v for name, lab, v in mm
            if name == "onrouter_proxy_cache_disk_pending_jobs"
        )
        if total == 0:
            return True
        time.sleep(0.1)
    return False


def files_under(root):
    out = []
    for dirpath, _, names in os.walk(root):
        out += [os.path.join(dirpath, n) for n in names]
    return out


def start_proc(exe):
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(OUT_LOG, "ab")
    proc = subprocess.Popen([exe, CONF], cwd=ROOT, stdout=logf, stderr=logf)
    for _ in range(100):
        try:
            if request("/ping", timeout=2)[0] == 200:
                return proc, logf
        except Exception:
            pass
        time.sleep(0.15)
    raise SystemExit(f"!! onrouter 未就绪（端口 {GW_PORT}/{BE_PORT} 被占用？看 {OUT_LOG}）")


def stop_proc(proc, logf):
    # Windows 的 terminate() 是硬结束，先确认落盘队列已排空再停
    wait_pending_zero()
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    logf.close()


def clean_dirs():
    for d in (TIER_DIR, GATE_DIR, PLAIN_DIR):
        shutil.rmtree(d, ignore_errors=True)


def main():
    exe = find_binary()

    # ---------- 1. -t：配置能通过，且冷层自述只点名开了 disk=on 的区 ----------
    t = subprocess.run(
        [exe, "-t", "-c", CONF_REL], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )
    tout = (t.stdout or "") + (t.stderr or "")
    check("-t 通过（含 disk=on 的 proxy_cache_path）", t.returncode == 0, tout[-600:])
    check("-t 列出 tier 冷层", "proxy_cache 冷层 区 tier" in tout, tout[-600:])
    check("-t 列出 gate 冷层并带上 spill_after 门槛",
          "proxy_cache 冷层 区 gate" in tout and "spill_after=3" in tout, tout[-600:])
    check("-t 不提没开 disk=on 的 plain 区", "区 plain" not in tout, tout[-600:])
    check("-t 不因这份配置告警",
          not re.search(r"proxy_cache_path.*(无效|非法|暂未实现|缺少)", tout), tout[-600:])

    clean_dirs()
    backend = HTTPServer(("127.0.0.1", BE_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    proc, logf = start_proc(exe)
    try:
        # ---------- 2. 冷层目录只在 disk=on 的区出现 ----------
        check("开冷层的区建了目录", os.path.isdir(TIER_DIR) and os.path.isdir(GATE_DIR))
        check("没开冷层的区连目录都不建（开关是真开关）", not os.path.exists(PLAIN_DIR))

        # ---------- 3. 首轮全部回源，容量把最早的几条挤出去 ----------
        first = [prime("tier", i) for i in IDS]
        check("tier 首轮 12 条全 MISS", all(s[1] == "MISS" for s in first),
              f"{[s[1] for s in first]}")
        check("tier 首轮每条都真的回源一次", all(s[4] == 1 for s in first),
              f"{[s[4] for s in first]}")
        check("落盘排空（等待期间请求照常服务）", wait_pending_zero())
        mm = metrics()
        spilled = series(mm, "tier", "operations_total", op="spill") or 0
        entries = series(mm, "tier", "entries") or 0
        check("被淘汰的新鲜条目落盘（spill 计数 ≥ 4）", spilled >= 4, f"spilled={spilled}")
        check("冷层索引条目与落盘账目一致", entries >= 4, f"entries={entries}")
        check("内存条目不会超容量还留在内存里（keys_zone 仍是上限）",
              (series(mm, "tier", "entries") or 0) > 0)
        files = files_under(TIER_DIR)
        check("目录里确实有文件", len(files) >= 4, f"files={len(files)}")
        magic_ok = all(open(f, "rb").read(4) == b"ORDK" for f in files)
        check("冷层条目文件自描述（magic ORDK）", magic_ok,
              f"{[open(f, 'rb').read(4) for f in files[:3]]}")

        # ---------- 4. 冷命中：状态仍是 HIT，层级另说一个头，且没打后端 ----------
        st, xcs, tier_hdr, body, delta = prime("tier", 0)
        check("被淘汰的 id=0 由冷层供：200", st == 200, f"st={st}")
        check("冷命中的 X-Cache-Status 仍是 HIT（不改 nginx 词表）", xcs == "HIT", f"xcs={xcs}")
        check("冷命中额外带 X-Cache-Tier: disk", tier_hdr == "disk", f"tier={tier_hdr}")
        check("冷命中真的没打后端", delta == 0, f"backend delta={delta}")
        check("冷命中回来的 body 与原响应一致", "id=0 zone=tier n=1" in body, body[:80])

        st, xcs, tier_hdr, body, delta = prime("tier", 0)
        check("第二次命中已提升回内存（不再报冷层）",
              xcs == "HIT" and tier_hdr is None and delta == 0,
              f"xcs={xcs} tier={tier_hdr} delta={delta}")
        mm = metrics()
        check("冷命中/提升各自记了一笔",
              (series(mm, "tier", "operations_total", op="cold_hit") or 0) >= 1
              and (series(mm, "tier", "operations_total", op="promote") or 0) >= 1,
              str([(n, l, v) for n, l, v in mm if n.endswith("operations_total") and 'zone="tier"' in l]))

        # ---------- 5. 对照组：没冷层的区被挤掉只能回源 ----------
        for i in IDS:
            prime("plain", i)
        wait_pending_zero()
        st, xcs, tier_hdr, _, delta = prime("plain", 0)
        check("对照区被淘汰后回源（MISS + 后端 +1）",
              xcs == "MISS" and delta == 1, f"xcs={xcs} delta={delta}")
        check("对照区永远不报冷层", tier_hdr is None, f"tier={tier_hdr}")

        # ---------- 6. 频率门槛：一次性流量不写盘 ----------
        for i in IDS:
            prime("gate", i)
        wait_pending_zero()
        mm = metrics()
        gate_spill = series(mm, "gate", "operations_total", op="spill") or 0
        check("spill_after=3 挡下一次性流量（gate 区落盘 0 条）",
              gate_spill == 0, f"gate spilled={gate_spill}")
        check("被挡下的条目不进冷层索引", (series(mm, "gate", "entries") or 0) == 0,
              f"gate entries={series(mm, 'gate', 'entries')}")
        st, xcs, _, _, delta = prime("gate", 0)
        check("gate 区被淘汰后仍要回源（内存与磁盘都没有它）",
              xcs == "MISS" and delta == 1, f"xcs={xcs} delta={delta}")

        # ---------- 7. 指标族分离：proxy_cache 的账不挂 dict 的名字 ----------
        zones_reported = sorted({
            re.search(r'zone="([^"]+)"', lab).group(1)
            for name, lab, _ in mm if name.startswith("onrouter_proxy_cache_disk_")
        })
        check("onrouter_proxy_cache_disk_* 只覆盖开了冷层的两个区",
              zones_reported == ["gate", "tier"], f"{zones_reported}")
        check("这些区不出现在 onrouter_dict_disk_* 里",
              all("proxy_disk" not in lab and 'zone="' not in lab
                  for name, lab, _ in mm if name.startswith("onrouter_dict_disk_")),
              "dict 族串了 proxy_cache 的标签")

        # ---------- 8. 冷层条目坏掉：不发错内容、不 5xx，坏账目要被记下来 ----------
        # 文件名是哈希分片，从外部反推不出属于哪个 key，而且刚被提升过的条目文件已不在索引里，
        # 所以逐条挑一条来改很可能"根本没被读到"。做法是把内存区整体换血（8 条新 URL 填满
        # keys_zone），让前面 12 条只剩磁盘一份，再把整个目录改坏：这样"坏数据绝不变成错误响应"
        # 和"坏计数不是 0"两件事都有确定的判据。
        for k in range(100, 108):
            prime("tier", k)
        wait_pending_zero()
        files = sorted(files_under(TIER_DIR))
        check("内存换血后冷层仍留着被淘汰的条目", len(files) >= 8, f"files={len(files)}")
        mm = metrics()
        corrupt_before = series(mm, "tier", "operations_total", op="corrupt") or 0
        for f in files:
            with open(f, "r+b") as fh:
                data = bytearray(fh.read())
                data[len(data) // 2] ^= 0xFF          # CRC 覆盖 key+value，改中间一个字节必失配
                fh.seek(0)
                fh.write(data)
        origin_extra = 0
        bad = []
        for i in IDS:
            st, xcs, tier_hdr, body, delta = prime("tier", i)
            origin_extra += delta
            if st != 200 or f"id={i} zone=tier" not in body or xcs != "MISS":
                bad.append((i, st, xcs, body[:40]))
        check("整目录损坏后不发错内容、不 5xx，且一律按未命中回源", not bad, str(bad[:2]))
        check("坏掉的条目全部回源重建（12 条，一条都没被当成命中）",
              origin_extra == len(IDS), f"origin extra={origin_extra}")
        mm = metrics()
        corrupt_after = series(mm, "tier", "operations_total", op="corrupt") or 0
        check("坏条目被计数（corrupt 至少 +12）", corrupt_after - corrupt_before >= len(IDS),
              f"{corrupt_before} -> {corrupt_after}")
        wait_pending_zero()
        mm = metrics()
        check("读回的数据重新灌满冷层（自愈）",
              (series(mm, "tier", "operations_total", op="spill") or 0) > spilled,
              f"spilled now={series(mm, 'tier', 'operations_total', op='spill')}")

        # ---------- 9. 停机排空 + 重启扫目录 ----------
        wait_pending_zero()
        mm = metrics()
        entries_before = series(mm, "tier", "entries") or 0
        files_before = len(files_under(TIER_DIR))
        stop_proc(proc, logf)
        proc, logf = start_proc(exe)
        mm = metrics()
        recovered = series(mm, "tier", "operations_total", op="warm_recovered") or 0
        check("重启扫目录重建（warm_recovered 与停机前索引一致）",
              recovered == entries_before and entries_before > 0,
              f"recovered={recovered} before={entries_before} files={files_before}")
        cold_hits = 0
        for i in IDS:
            st, xcs, tier_hdr, body, delta = prime("tier", i)
            if xcs == "HIT" and tier_hdr == "disk" and delta == 0:
                cold_hits += 1
            if "zone=tier" not in body:
                check("重启后每条响应内容仍然正确", False, f"st={st} body={body[:60]}")
                break
        else:
            check("重启后每条响应内容仍然正确", True)
        check("重启后冷命中照旧成立（至少 3 条没打后端）", cold_hits >= 3, f"cold hits={cold_hits}")

        # ---------- 10. 关掉冷层再启动：目录留着但不再多写 ----------
        off_conf = CONF + ".tmp"
        text = open(CONF, encoding="utf-8").read().replace("keys_zone=tier:1k  disk=on", "keys_zone=tier:1k  disk=off")
        open(off_conf, "w", encoding="utf-8").write(text)
        try:
            t2 = subprocess.run([exe, "-t", "-c", os.path.relpath(off_conf, ROOT)], cwd=ROOT,
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
            t2out = (t2.stdout or "") + (t2.stderr or "")
            check("disk=off 被 -t 接受且不再自述该区的冷层",
                  t2.returncode == 0 and "区 tier" not in t2out, t2out[-400:])
        finally:
            os.remove(off_conf)
        check("落盘全程异步：pending_jobs 归零过（请求线程不等磁盘）", wait_pending_zero())
    finally:
        stop_proc(proc, logf)
        backend.shutdown()
        threading.Thread(target=backend.server_close, daemon=True).start()
        clean_dirs()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== proxy_cache 磁盘冷层 E2E: {passed}/{len(results)} passed ====")
    if passed != len(results):
        for name, ok in results:
            if not ok:
                print("FAILED:", name)
        sys.exit(1)


if __name__ == "__main__":
    main()
