# -*- coding: utf-8 -*-
"""ngx.shared.DICT 磁盘分层冷层 E2E —— 用真实流量证明分层整条链路在转。

    cargo build --release -p onrouter-server --bin onrouter && python tools/disk_cache_e2e.py

证明的事（证据全部来自 HTTP 响应、/metrics 计数与磁盘上的真实文件）：
 1. 内存写满后淘汰的条目落到冷层，读回来并提升回内存（spill / cold_hit / promote 计数）
 2. 一个 key 恰好在一层：num() 恒等于 key 总数，内存字节 + 冷层条目数 = 全量
 3. Lua API 一点没改：同一段不改写的脚本在带冷层/不带冷层的区里结果逐字节一致
 4. 进程重启后扫目录重建索引，上次落盘的数据照样读得回来
 5. 条目文件被截断只丢那一条：计数、不 panic、进程继续正常读写
 6. 真未命中零磁盘 IO（计数器不动、延迟与不带冷层的区一致）；冷读不拖慢请求路径
 7. 遍历型 key 也只能落在冷层根目录下的十六进制目录里
 8. 策略选择性：一次性数据被 admit 拦下，一个字节都不许写盘
"""
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "disk_cache.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "disk_cache_err.log")
CACHE = os.path.join(ROOT, "conf", "cache")
STORES = ["e2e-tier", "e2e-bench", "e2e-policy"]
HOST, PORT = "127.0.0.1", 18152
BASE = f"http://{HOST}:{PORT}"

# 单条成本：key + value + 64B 节点开销（见 shared_dict::NODE_OVERHEAD）
TIER_KEY_LEN, TIER_VAL_LEN = 3, 900                       # key 是 k00..k39
TIER_COST = TIER_KEY_LEN + TIER_VAL_LEN + 64          # 967
TIER_CAP = 24576
TIER_KEEP = TIER_CAP // TIER_COST                      # 25 条留在内存
TIER_SPILL = 40 - TIER_KEEP                            # 其余进盘

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []

LINE_RE = re.compile(r"^([a-z_0-9]+)(?:\{([^}]*)\})?\s+([0-9eE.+-]+)$", re.M)
HEX_DIR_RE = re.compile(r"^[0-9a-f]+$")
BIN_RE = re.compile(r"^[0-9a-f]{16}\.bin$")


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail, flush=True)


def find_binary():
    for profile in ("release", "debug"):
        for name in ("onrouter.exe", "onrouter"):
            p = os.path.join(ROOT, "target", profile, name)
            if os.path.exists(p):
                return p
    raise SystemExit("!! build first: cargo build --release -p onrouter-server --bin onrouter")


def get(path, headers=None):
    r = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        resp = _opener.open(r, timeout=10)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def kv(body):
    out = {}
    for line in body.strip().splitlines():
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def metrics():
    st, body = get("/metrics")
    if st != 200:
        raise SystemExit(f"!! /metrics 返回 {st}")
    mm = {}
    for m in LINE_RE.finditer(body):
        mm[(m.group(1), m.group(2) or "")] = float(m.group(3))
    return mm


def gauge(mm, family, d):
    """冷层 gauge：entries/bytes/value_bytes/capacity_bytes/pending_*。缺区返回 None。"""
    return mm.get((f"onrouter_dict_disk_{family}", f'dict="{d}"'))


def op(mm, d, name):
    """冷层计数的某一类（spill/cold_hit/promote/…）。"""
    return mm.get(("onrouter_dict_disk_operations_total", f'dict="{d}",op="{name}"'))


def files_in(store):
    root = os.path.join(CACHE, store)
    out = []
    for dirpath, _, names in os.walk(root):
        out += [os.path.join(dirpath, n) for n in names]
    return out


def start_proc():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    logf = open(os.path.join(ROOT, "logs", "disk_cache_out.log"), "ab")
    proc = subprocess.Popen([find_binary(), CONF], cwd=ROOT, stdout=logf, stderr=logf)
    for _ in range(80):
        try:
            if get("/metrics")[0] == 200:
                return proc, logf
        except Exception:
            pass
        time.sleep(0.15)
    raise SystemExit(f"!! onrouter 未就绪（端口 {PORT} 被占用？看 {ERR_LOG}）")


def wait_idle(limit=10.0):
    """等写线程把排队的落盘做完。期间服务照常响应，这本身就是"请求线程不等磁盘"的证据。"""
    t0 = time.time()
    while time.time() - t0 < limit:
        mm = metrics()
        if sum(v for (n, _l), v in mm.items() if n.endswith("pending_jobs")) == 0:
            return True
        time.sleep(0.05)
    return False


def stop_proc(proc, logf):
    # Windows 上 terminate() 是硬结束，先排空队列再停；unix 走 SIGTERM 还会额外触发停机排空
    wait_idle()
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
    logf.close()


def timed(path, n, expect=None, query=False):
    lat, bad = [], 0
    for i in range(1, n + 1):
        url = f"{path}?i={i}" if query else path
        t0 = time.perf_counter()
        st, body = get(url)
        lat.append(time.perf_counter() - t0)
        if st != 200 or (expect and expect not in body):
            bad += 1
    lat.sort()
    p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
    return sum(lat) / len(lat), lat[-1], p95, bad


def main():
    for s in STORES:
        shutil.rmtree(os.path.join(CACHE, s), ignore_errors=True)
    if os.path.exists(ERR_LOG):
        os.remove(ERR_LOG)

    proc, logf = start_proc()
    try:
        # ---------- 1+2. 机制与"一层一份"不变式 ----------
        st, body = get("/tier/warm")
        w = kv(body)
        check("/tier/warm 200 且写了 40 条", st == 200 and w.get("written") == "40", f"st={st} {w}")
        check("capacity() 仍是内存层语义 24k", w.get("cap") == str(TIER_CAP), f"cap={w.get('cap')}")
        check("落盘队列排空", wait_idle(), "10s 内 pending_jobs 没归零")
        mm = metrics()
        check(f"spill{{tier}}=={TIER_SPILL}（{TIER_CAP} 只留得下 {TIER_KEEP} 条）",
              op(mm, "tier", "spill") == TIER_SPILL, f"spill={op(mm, 'tier', 'spill')}")
        check(f"entries{{tier}}=={TIER_SPILL}（淘汰的都在盘上）",
              gauge(mm, "entries", "tier") == TIER_SPILL,
              f"entries={gauge(mm, 'entries', 'tier')}")
        check("spill_skipped{tier}==0（spill_after=0 不该拦）",
              op(mm, "tier", "spill_skipped") == 0, f"skipped={op(mm, 'tier', 'spill_skipped')}")
        check("bytes{tier} 记账非零", (gauge(mm, "bytes", "tier") or 0) > 0,
              f"bytes={gauge(mm, 'bytes', 'tier')}")
        check("max_disk=4m 生效", gauge(mm, "capacity_bytes", "tier") == 4194304,
              f"cap={gauge(mm, 'capacity_bytes', 'tier')}")
        check("对照区 plain 完全没有冷层指标",
              not any('dict="plain"' in l for (_n, l) in mm),
              f"出现了 {[l for (_n, l) in mm if 'plain' in l][:3]}")

        before = op(mm, "tier", "cold_hit") or 0
        st, body = get("/tier/readall")
        r = kv(body)
        check("40 条全部读回且值正确（bad=丢数据，等落盘窗口不算）",
              st == 200 and r.get("ok") == "40" and r.get("bad") == "0", f"{r}")
        wait_idle()
        mm = metrics()
        cold = (op(mm, "tier", "cold_hit") or 0) - before
        check("至少 15 次冷命中（真的从盘上读）", cold >= TIER_SPILL, f"cold_hit delta={cold}")
        check("promote{tier} >= 15", (op(mm, "tier", "promote") or 0) >= TIER_SPILL,
              f"promote={op(mm, 'tier', 'promote')}")
        st, body = get("/tier/state")
        s = kv(body)
        check("排空后 num() == 40（计数覆盖两层，提升不复制数据）",
              s.get("num") == "40", f"num={s.get('num')} {s}")
        used = int(s.get("cap", TIER_CAP)) - int(s.get("free", 0))
        mem_n, extra = divmod(used, TIER_COST)
        check(f"内存字节账目精确（{TIER_COST}×条数）",
              extra == 0 and mem_n == TIER_KEEP, f"used={used} mem={mem_n} extra={extra}")
        cold_n = gauge(mm, "entries", "tier") or 0
        check("内存条数 + 冷层条数 == 40（一个 key 只在一层）",
              mem_n + cold_n == 40, f"mem={mem_n} cold={cold_n}")

        # ---------- 3. 不改写的 OpenResty 脚本两边结果一致 ----------
        st, body = get("/parity")
        p = kv(body)
        check("/parity same==true（Lua API 未变）", st == 200 and p.get("same") == "true",
              f"plain={p.get('plain')}\n  tier={p.get('tier')}")

        # ---------- 7. 遍历型 key 的路径安全 ----------
        st, body = get("/evilkeys/write")
        check("/evilkeys/write 200", st == 200 and "written=5" in body, f"st={st} {body!r}")
        wait_idle()
        weird, seen_files = [], 0
        for s in STORES:
            root = os.path.join(CACHE, s)
            for dirpath, dirnames, names in os.walk(root):
                rel = os.path.relpath(dirpath, root).replace("\\", "/")
                if rel != ".":
                    weird += [c for c in rel.split("/") if not HEX_DIR_RE.match(c)]
                for n in names:
                    seen_files += 1
                    if not BIN_RE.match(n):
                        weird.append(os.path.join(dirpath, n))
        check(f"冷层目录只含十六进制路径（{seen_files} 个文件）",
              not weird and seen_files > 0, f"异常项={weird[:5]}")
        st, body = get("/evilkeys/read")
        check("遍历型 key 从盘上原样读回", "roundtrip=5" in body, f"{body!r}")

        # ---------- 4. 重启不丢 ----------
        st, body = get("/persist/seed")
        check("/persist/seed 200", st == 200 and "seeded=40" in body, f"st={st}")
        wait_idle()
        mm = metrics()
        check(f"重启前台面上有 {TIER_SPILL} 条在盘上",
              gauge(mm, "entries", "tier") == TIER_SPILL,
              f"entries={gauge(mm, 'entries', 'tier')}")
        stop_proc(proc, logf)
        proc, logf = start_proc()
        mm = metrics()
        recovered = op(mm, "tier", "warm_recovered")
        check(f"重启后扫目录重建出 {TIER_SPILL} 条", recovered == TIER_SPILL,
              f"warm_recovered={recovered}")
        st, body = get("/persist/read")
        r2 = kv(body)
        check("上次落盘的数据这次读得回来",
              int(r2.get("ok", -1)) == TIER_SPILL and recovered == TIER_SPILL, f"{r2} rec={recovered}")
        check("读不到的正是当初留在内存层的那批", r2.get("bad") == str(40 - TIER_SPILL), f"{r2}")

        # ---------- 5. 坏文件容忍（先在 bench 里攒出条目，再全部截断） ----------
        st, body = get("/bench/seed")
        check("/bench/seed 200", st == 200 and "seeded=300" in body, f"st={st}")
        wait_idle()
        bench_files = files_in("e2e-bench")
        check("bench 冷层攒出了条目文件", len(bench_files) >= 100, f"文件数={len(bench_files)}")
        stop_proc(proc, logf)
        for f in bench_files:
            with open(f, "r+b") as fh:
                fh.truncate(7)  # 连 32 字节表头都凑不齐
        proc, logf = start_proc()
        mm = metrics()
        check("坏文件被计数丢弃（corrupt==文件数）",
              op(mm, "bench", "corrupt") == len(bench_files),
              f"corrupt={op(mm, 'bench', 'corrupt')} files={len(bench_files)}")
        check("坏目录重建后条目数为 0", gauge(mm, "entries", "bench") == 0,
              f"entries={gauge(mm, 'entries', 'bench')}")
        st, body = get("/bench/miss?i=1")
        check("截断全部条目后服务照常响应", st == 200 and "nil=true" in body, f"st={st} {body!r}")
        st, body = get("/bench/seed")
        check("冷层受损后仍能继续读写", st == 200 and "seeded=300" in body, f"st={st}")
        # 播种期间挤出去的条目要靠写线程落盘，等它写完再验证冷读恢复
        wait_idle()
        st, body = get("/bench/cold?i=1")
        check("重新播种后冷读恢复", "len=300" in body, f"{body!r}")

        # ---------- 6. 延迟：内存读 / 冷读 / 真未命中 ----------
        avg_hot, max_hot, p95_hot, bad_hot = timed("/bench/hotpath", 150, expect="len=300")
        mm = metrics()
        before = op(mm, "bench", "cold_hit") or 0
        avg_cold, max_cold, p95_cold, bad_cold = timed("/bench/cold", 200, expect="len=300", query=True)
        mm = metrics()
        cold_delta = (op(mm, "bench", "cold_hit") or 0) - before
        print(f"     内存读 avg={avg_hot*1e3:.3f}ms p95={p95_hot*1e3:.3f}ms max={max_hot*1e3:.3f}ms")
        print(f"     冷读    avg={avg_cold*1e3:.3f}ms p95={p95_cold*1e3:.3f}ms max={max_cold*1e3:.3f}ms")
        check("两条路径 150/200 次请求全部 200 且值正确",
              bad_hot == 0 and bad_cold == 0, f"bad_hot={bad_hot} bad_cold={bad_cold}")
        check("冷读确实发生了 >=150 次磁盘读", cold_delta >= 150, f"cold_hit delta={cold_delta}")
        check("冷读没把请求路径拖垮（avg<20ms 且 <10×内存读）",
              avg_cold < 0.020 and avg_cold < max(10 * avg_hot, avg_hot + 0.005),
              f"avg_cold={avg_cold*1e3:.3f}ms avg_hot={avg_hot*1e3:.3f}ms")
        check("最坏一次冷读 < 250ms", max_cold < 0.25, f"max={max_cold*1e3:.3f}ms")

        # 先排空：冷读那 200 次提升会挤掉内存条目，落盘是异步的，
        # 不等写完就取快照的话，计数动一下是上一轮的尾巴，不是未命中造成的
        wait_idle()
        mm = metrics()
        c0 = op(mm, "bench", "cold_hit") or 0
        e0 = gauge(mm, "entries", "bench") or 0
        avg_miss, max_miss, _p95, bad1 = timed("/bench/miss", 200, expect="nil=true", query=True)
        avg_plain, max_plain, _p95, bad2 = timed("/bench/plainmiss", 200, expect="nil=true", query=True)
        mm = metrics()
        check("未命中路径 200 次全部 nil", bad1 == 0 and bad2 == 0, f"bad={bad1}/{bad2}")
        check("真未命中零磁盘 IO（cold_hit 与 entries 计数不动）",
              (op(mm, "bench", "cold_hit") or 0) == c0 and gauge(mm, "entries", "bench") == e0,
              f"cold_hit {c0}->{op(mm, 'bench', 'cold_hit')} "
              f"entries {e0}->{gauge(mm, 'entries', 'bench')}")
        print(f"     真未命中 avg={avg_miss*1e3:.3f}ms max={max_miss*1e3:.3f}ms（不带冷层对照 "
              f"avg={avg_plain*1e3:.3f}ms max={max_plain*1e3:.3f}ms）")
        check("带冷层的未命中与不带冷层同量级",
              avg_miss < max(2.5 * avg_plain, avg_plain + 0.002),
              f"{avg_miss*1e3:.3f}ms vs {avg_plain*1e3:.3f}ms")

        # ---------- 并发压力下不阻塞、不丢正确性 ----------
        def one(i):
            return get("/load", headers={"X-Seq": str(i)})

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            codes = list(pool.map(one, range(200)))
        wall = time.perf_counter() - t0
        check("20 并发 × 10 轮全部 200", all(st == 200 for st, _ in codes) and len(codes) == 200,
              f"非 200={sum(1 for st, _ in codes if st != 200)}")
        check("并发下每条都读到值", all("len=500" in b for _, b in codes), f"样例={codes[0][1]!r}")
        check("并发压完队列仍能排空", wait_idle(), "落盘滞后超过 10s")
        print(f"     并发 200 请求耗时 {wall*1e3:.0f}ms")

        # ---------- 8. 策略选择性：一次性数据不许占磁盘 ----------
        st, body = get("/policy/hot")
        ph = kv(body)
        check("/policy/hot 攒热度且没触发淘汰",
              st == 200 and ph.get("hot") == "H" and ph.get("num") == "1", f"{ph}")
        wait_idle()
        mm = metrics()
        check("此刻 disk 上一个字节都没有",
              (op(mm, "policy", "spill") or 0) == 0 and gauge(mm, "entries", "policy") == 0,
              f"spill={op(mm, 'policy', 'spill')} entries={gauge(mm, 'entries', 'policy')}")
        time.sleep(1.3)  # 让 hot 的 recency 掉到一次性数据之下
        st, body = get("/policy/churn")
        pc = kv(body)
        wait_idle()
        mm = metrics()
        check("变冷的高频条目落盘恰好一次", op(mm, "policy", "spill") == 1,
              f"spill={op(mm, 'policy', 'spill')}")
        check("200 条一次性填充全被策略拦下",
              pc.get("churned") == "200" and (op(mm, "policy", "spill_skipped") or 0) >= 100,
              f"{pc} skipped={op(mm, 'policy', 'spill_skipped')}")
        st, body = get("/policy/recheck")
        pr = kv(body)
        wait_idle()
        mm = metrics()
        check("hot 从盘上读回并提升（值正确）",
              pr.get("hot") == "H" and (op(mm, "policy", "cold_hit") or 0) >= 1
              and (op(mm, "policy", "promote") or 0) >= 1,
              f"{pr} cold_hit={op(mm, 'policy', 'cold_hit')} promote={op(mm, 'policy', 'promote')}")
        check("提升后冷层不留副本（一层一份）", gauge(mm, "entries", "policy") == 0,
              f"entries={gauge(mm, 'entries', 'policy')}")

        # ---------- flush_all 不许被排队中的落盘复活 ----------
        st, body = get("/race/flush")
        rc = kv(body)
        check("/race/flush 内存当场清零", st == 200 and rc.get("flushed") == "0", f"{rc}")
        wait_idle()
        mm = metrics()
        check("排队中的落盘整批作废（冷层条目为 0）",
              gauge(mm, "entries", "tier") == 0, f"entries={gauge(mm, 'entries', 'tier')}")
        st, body = get("/tier/state")
        s4 = kv(body)
        check("num() 也是 0：没有一条迟到的落盘登记回索引", s4.get("num") == "0", f"{s4}")
        left = files_in("e2e-tier")
        check("磁盘上没有残留条目文件", not left, f"残留={left[:3]}")

        # ---------- flush_all 覆盖两层 ----------
        get("/tier/clear")
        st, body = get("/tier/readall?wait=0")
        r3 = kv(body)
        st, body = get("/tier/state")
        s3 = kv(body)
        wait_idle()
        mm = metrics()
        check("flush_all 连冷层一起清（一条都读不回）",
              r3.get("ok") == "0" and s3.get("num") == "0"
              and gauge(mm, "entries", "tier") == 0,
              f"{r3} {s3} entries={gauge(mm, 'entries', 'tier')}")

        err = open(ERR_LOG, "rb").read().decode(errors="replace") if os.path.exists(ERR_LOG) else ""
        low = err.lower()
        check("错误日志里没有 panic/回溯", "panic" not in low and "traceback" not in low,
              f"日志片段={err[-400:]!r}")
    finally:
        stop_proc(proc, logf)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n==== 磁盘分层冷层 E2E: {passed}/{len(results)} passed ====")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
