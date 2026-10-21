# -*- coding: utf-8 -*-
# Author: yxpil
# Cache governor E2E: sleep <-> boost phases driven by real traffic.
#
# What this proves (real requests on a real clock -- not a code review):
#   1) Default off leaves no footprint: the control instance (conf/governor_off.conf)
#      exposes no onrouter_governor_* series at all and logs no governor banner.
#   2) Quiet startup settles into sleep: the phase gauge reads 0 within seconds and
#      stays there while the only traffic is the test's own 0.5 rps polling.
#   3) A moderate rate wakes it (8 rps > low*1.5) and the phase goes back to normal.
#   4) Deep sleep demotes real dict state: after seeding 64 keys and letting the
#      gateway go quiet, the phase returns to sleep, `demoted_total` reaches 64, the
#      cold root actually contains files (spill_after is 1000, so ordinary eviction
#      cannot have written any of them -- this is the governor's forced spill), and
#      free_space jumps back because the memory layer was reclaimed.
#   5) Demoted values stay readable: reading keys afterwards returns the exact 512
#      byte values through the cold tier (the sleep contract is "memory reclaimed",
#      never "data lost").
#   6) A burst pre-warms: 45 rps crosses high on the trailing-8s estimate, boost is
#      entered within the burst, and prewarmed_total grows (the cold copies that
#      survived the sample reads are pulled back into memory on entry).
#   7) The trailing estimate also brings it back down: stopping the traffic exits
#      boost to normal without a restart.
#   8) The learned profile is fed by the running gateway (profile_coverage > 0) --
#      the same calendar that prediction reads.
#   9) -t is the gate: inverted thresholds and learn-with-off exit non-zero; deep
#      tier without a disk= zone warns (still exit 0) exactly because it would
#      otherwise sleep without being able to demote anything; observe+learn warns.
#  10) Hot reload swaps the governor configuration in place: removing the whole
#      directive family makes every onrouter_governor_* series disappear while the
#      dict data stays readable, and putting it back brings the series back.
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/governor_e2e.py
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "governor.conf")
OFF_CONF = os.path.join(ROOT, "conf", "governor_off.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "governor_err.log")
OFF_ERR_LOG = os.path.join(ROOT, "conf", "logs", "governor_off_err.log")
OUT_LOG = os.path.join(ROOT, "logs", "governor_out.log")
COLD_ROOT = os.path.join(ROOT, "conf", "logs", "gov_cache")

GW_PORT = 18560
OFF_PORT = 18561
BASE = f"http://127.0.0.1:{GW_PORT}"
OFF_BASE = f"http://127.0.0.1:{OFF_PORT}"

LOW, HIGH, HOLD = 2.0, 20.0, 3.0
KEYS = 64
VALUE_LEN = 512
results = []
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
EXE = None


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


def request(url, timeout=10):
    try:
        resp = _opener.open(urllib.request.Request(url, method="GET"), timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def status(url, timeout=10):
    return request(url, timeout)[0]


def metrics_body():
    return request(BASE + "/metrics")[1]


def metric(body, name, **labels):
    if labels:
        name += "{" + ",".join('%s="%s"' % (k, v) for k, v in labels.items()) + "}"
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line == name or line.startswith(name + " "):
            return float(line.split()[-1])
    return None


def phase():
    v = metric(metrics_body(), "onrouter_governor_phase")
    return None if v is None else int(v)


def wait_phase(want, timeout, every=0.4):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = phase()
        if last == want:
            return last
        time.sleep(every)
    return last


def wait_for(pred, timeout, every=0.4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = pred()
        if r:
            return r
        time.sleep(every)
    return None


def get_len(key):
    """Length of the value as reported by /get, newline-insensitive (Lua ngx.say)."""
    return request(BASE + f"/get?key={key}")[1].strip()


def stats():
    _, body = request(BASE + "/stats")
    out = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            try:
                out[k] = int(v)
            except ValueError:
                pass
    return out


def run_t(path):
    p = subprocess.run(
        [EXE, "-t", "-c", os.path.relpath(path, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def cold_file_count():
    n = 0
    for _dirpath, _dirs, files in os.walk(COLD_ROOT):
        n += len(files)
    return n


def send_rate(rate, seconds, stop=None):
    """Aim at ~rate requests/second on /hit, paced; stops early when `stop` is set."""
    interval = 1.0 / rate
    deadline = time.monotonic() + seconds
    next_at = time.monotonic()
    while time.monotonic() < deadline:
        if stop is not None and stop.is_set():
            return
        request(BASE + "/hit", timeout=5)
        next_at += interval
        d = next_at - time.monotonic()
        if d > 0:
            time.sleep(d)


def with_conf_text(transform):
    """Run a -t variant without touching the live config: the file is written next to
    it (relative log/pid paths resolve to the same conf dir, no process is running)."""
    text = open(CONF, encoding="utf-8").read()
    variant = os.path.join(ROOT, "conf", "_governor_t.conf")
    with open(variant, "w", encoding="utf-8", newline="\n") as f:
        f.write(transform(text))
    try:
        return run_t(variant)
    finally:
        os.remove(variant)


def strip_governor(text):
    return "\n".join(l for l in text.splitlines() if not l.strip().startswith("cache_governor")) + "\n"


def start(conf_path, out_name):
    logf = open(os.path.join(ROOT, "logs", out_name), "w", encoding="utf-8")
    proc = subprocess.Popen([EXE, conf_path], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    return proc, logf


def stop(proc, logf):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    logf.close()


def main():
    global EXE
    EXE = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    original = open(CONF, encoding="utf-8").read()
    off_proc = off_log = None
    proc = None
    logf = None
    try:
        # ---- 1) -t variants, before anything is listening ----
        rc, out = run_t(CONF)
        check("-t passes on the auto/deep config", rc == 0, out[-500:])
        check("-t spells out the phase machine it parsed",
              "cache_governor auto:" in out and "tier=Deep" in out, out[-400:])
        rc, out = with_conf_text(lambda t: t.replace("cache_governor_low 2;", "cache_governor_low 30;"))
        check("-t rejects low >= high", rc != 0 and "must be below" in out, out[-400:])
        rc, out = with_conf_text(lambda t: t.replace("cache_governor auto;", "cache_governor off;"))
        check("-t rejects learn without a live mode", rc != 0 and "requires cache_governor" in out, out[-400:])
        rc, out = with_conf_text(lambda t: re.sub(r"lua_shared_dict govcache[^;]*;\n?", "", t))
        check("-t warns that deep sleep has nothing to demote without disk=",
              rc == 0 and "nothing to demote" in out, out[-500:])
        rc, out = with_conf_text(lambda t: t.replace("cache_governor auto;", "cache_governor observe;"))
        check("-t warns that observe+learn records a profile nobody reads yet",
              rc == 0 and "keeps recording" in out, out[-500:])
        rc, out = run_t(OFF_CONF)
        check("-t on the off control prints no governor line", rc == 0 and "cache_governor" not in out, out[-400:])

        # ---- 2) default off: no series, no banner, no task ----
        off_proc, off_log = start(OFF_CONF, "governor_off_out.log")
        if not wait_for(lambda: status(OFF_BASE + "/ping") == 200, 20):
            raise SystemExit("!! off control instance did not come up")
        off_body = request(OFF_BASE + "/metrics")[1]
        check("default off: not one onrouter_governor_* series",
              "onrouter_governor_" not in off_body, "control instance leaked governor metrics")
        time.sleep(1.0)
        raw_off = ""
        for p in (OFF_ERR_LOG, os.path.join(ROOT, "logs", "governor_off_out.log")):
            if os.path.exists(p):
                raw_off += open(p, encoding="utf-8", errors="replace").read()
        # The config path itself contains "governor_off.conf", so only the
        # governor's own log lines count as a leak here.
        check("default off: no phase machine banner / task in the logs",
              "cache_governor" not in raw_off.lower() and "governor: phase" not in raw_off.lower(),
              raw_off[-300:])

        # ---- 3) the main instance: fresh cold root so every file is this run's ----
        if os.path.isdir(COLD_ROOT):
            shutil.rmtree(COLD_ROOT)
        proc, logf = start(CONF, "governor_out.log")
        if not wait_for(lambda: status(BASE + "/ping") == 200, 20):
            raise SystemExit("!! governor instance did not come up")
        check("startup banner names the parsed phase machine",
              wait_for(lambda: "cache_governor auto:" in open(ERR_LOG, encoding="utf-8").read(), 10, every=0.3)
              is not None)

        # ---- 4) quiet -> sleep (the very first ticks have nothing to measure) ----
        got = wait_phase(0, 10, every=1.0)
        check("quiet startup settles into sleep", got == 0, f"phase={got}")
        check("sleep shows up in the rps gauge as (near) zero", (metric(metrics_body(), "onrouter_governor_rps") or 1) < 1.0)

        # ---- 5) moderate traffic wakes it: 8 rps > low*1.5, below high ----
        send_rate(8, 4)
        got = wait_phase(1, 8, every=0.5)
        check("8 rps wakes the cache layer back to normal", got == 1, f"phase={got}")

        # ---- 6) seed real dict state, then go quiet and let deep sleep demote it ----
        _, seed_out = request(BASE + f"/seed?n={KEYS}")
        after_seed = stats()
        check("seeded keys are in memory before the sleep",
              seed_out.strip() == f"seeded={KEYS}" and after_seed.get("num") == KEYS, f"{seed_out} {after_seed}")
        got = wait_phase(0, 30, every=2.0)
        check("quiet again -> sleep after hold", got == 0, f"phase={got}")
        # The phase is stored before the bounded demotion passes run, so poll the
        # counter instead of sampling it once against a task that is still working.
        demoted = wait_for(
            lambda: (lambda v: v if v >= KEYS else None)(
                int(metric(metrics_body(), "onrouter_governor_demoted_total") or 0)),
            15, every=0.3) or 0
        body = metrics_body()
        demoted_bytes = int(metric(body, "onrouter_governor_demoted_bytes_total") or 0)
        check("deep sleep demoted every seeded key", demoted >= KEYS, f"demoted={demoted}")
        check("the reclaimed byte count is reported", demoted_bytes > KEYS * VALUE_LEN // 2, f"bytes={demoted_bytes}")
        files = wait_for(lambda: cold_file_count() or None, 10, every=0.25)
        check("the cold root actually holds the forced spills (spill_after=1000 rules out eviction)",
              bool(files), f"files={cold_file_count()}")
        # 冷层索引要等写线程真正落盘才出现（spill() 只是排队），所以这里必须等账目落定：
        # 一次性的快照读到的是"已经落了几个"，满载机器上会读到 num=15 size=7680 这种半路值，
        # 报出来的样子像"降级把 49 条数据弄丢了"。等待的是最终状态，断言本身没有放松。
        after_sleep = wait_for(
            lambda: (lambda s: s if s.get("num") == KEYS
                                 and s.get("size") == KEYS * VALUE_LEN else None)(stats()),
            24, every=0.3) or stats()
        check("memory was reclaimed: free_space jumped back",
              after_sleep.get("free", 0) - after_seed.get("free", 0) > 20_000,
              f"before={after_seed.get('free')} after={after_sleep.get('free')}")
        check("num/size still count the cold copies (nothing was lost, only demoted)",
              after_sleep.get("num") == KEYS and after_sleep.get("size") == KEYS * VALUE_LEN,
              f"{after_sleep}")

        # ---- 7) the demoted values are still readable through the cold tier ----
        reads = []
        for i in range(5):
            k = f"k{i:03d}"
            got_v = wait_for(lambda k=k: (lambda o: o if "len=" in o else None)(get_len(k)), 10, every=0.25)
            reads.append(got_v)
        check("sampled values come back at full length after demotion",
              reads == [f"len={VALUE_LEN}"] * 5, f"{reads}")

        # ---- 8) a burst crosses high on the trailing-8s estimate and boosts ----
        stop_ev = threading.Event()
        sender = threading.Thread(target=send_rate, args=(45, 12, stop_ev), daemon=True)
        sender.start()
        got = wait_phase(2, 12, every=0.25)
        stop_ev.set()
        sender.join(timeout=5)
        check("45 rps burst enters boost", got == 2, f"phase={got}")
        # The phase is stored before the pre-warm runs, so poll instead of reading once:
        # a single sample can race the very task that does the pre-warming.
        prewarmed = wait_for(
            lambda: (lambda v: v if v >= 40 else None)(
                int(metric(metrics_body(), "onrouter_governor_prewarmed_total") or 0)),
            10, every=0.3)
        check("boost pre-warmed the demoted keys back from the cold tier",
              (prewarmed or 0) >= 40, f"prewarmed={prewarmed}")
        # The tick counter only moves on the next 500ms tick after the switch.
        ticks = wait_for(
            lambda: (lambda v: v if v and v > 0 else None)(
                metric(metrics_body(), "onrouter_governor_boost_ticks_total")),
            6, every=0.25)
        check("boost ticks are counted (the phase was really held)", bool(ticks), f"ticks={ticks}")
        check("the learned profile is fed", (metric(metrics_body(), "onrouter_governor_profile_coverage") or 0) > 0)

        # ---- 9) stopping the traffic brings boost back to normal ----
        got = wait_phase(1, 25, every=1.0)
        check("trailing estimate decays: boost exits to normal", got == 1, f"phase={got}")
        check("a second sampled key is still readable after the round trip",
              get_len("k010") == f"len={VALUE_LEN}")

        # ---- 10) hot reload: disable -> series gone, data intact; restore -> back ----
        def write_conf(text):
            with open(CONF, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                os.utime(CONF, None)

        write_conf(strip_governor(original))
        gone = wait_for(lambda: "onrouter_governor_" not in request(BASE + "/metrics")[1], 15, every=0.5)
        check("hot reload to off removes every governor series", bool(gone), "series survived the reload")
        check("dict data is untouched by turning the governor off",
              get_len("k020") == f"len={VALUE_LEN}" and stats().get("num") == KEYS)
        raw = open(ERR_LOG, encoding="utf-8", errors="replace").read()
        check("the reload explains that the phase machine went idle",
              "cache_governor off: phase machine stays idle" in raw)
        write_conf(original)
        back = wait_for(lambda: "onrouter_governor_phase" in request(BASE + "/metrics")[1], 15, every=0.5)
        check("hot reload back to auto restores the series", bool(back), "series did not come back")
        check("the reload log carries the parsed line again",
              wait_for(lambda: "cache_governor auto:" in open(ERR_LOG, encoding="utf-8").read(),
                       5, every=0.25) is not None)
    finally:
        if proc is not None:
            stop(proc, logf)
        if off_proc is not None:
            stop(off_proc, off_log)
        with open(CONF, "w", encoding="utf-8", newline="\n") as f:
            f.write(original)

    for f in (OUT_LOG,):
        if os.path.exists(f):
            print(f"#   (run log: {os.path.relpath(f, ROOT)})")
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== cache governor E2E: {passed}/{total} passed ====")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
