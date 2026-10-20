# -*- coding: utf-8 -*-
# Author: yxpil
# Scheduled access windows (schedule_window + schedule_access) E2E.
#
# What this proves (real traffic, real minute boundaries -- not a code review):
#   1) The gate follows the calendar: the script rewrites office into "opens two minutes from now, closes three
#      minutes from now", the gateway flips /office/ from 403 to 200 on a **real** minute boundary, and only after
#      a hot reload pushes the close time out does it flip back to 403.
#   2) Nothing is proxied while blocked: during the 403 period the **total** backend request delta is 0 (the 200s
#      on /free/ inside the same stretch would have pushed that delta to +1, so this is not "a counter that is
#      broken and says nothing"), which puts the gate in front of the proxy.
#   3) A route with no gate (/free/) and an always-open window (/any/) answer 200 for the whole run: defaulting to
#      off is not "a blanket 403".
#   4) Both placements are right: the gate on 18338 is written at the server level, /inherited/ flips along with it
#      and /override/ stays 403, proving an explicit location declaration beats server inheritance.
#   5) It verifies its own clock: next_fire_ms is **digit for digit equal** to the epoch milliseconds the script
#      computes (while closed = the moment it opens, while open = the moment it closes, after a flip = tomorrow's
#      open), and the unreferenced tzcheck is checked against +08 too -- a wrong timezone convention must blow up
#      right here.
#   6) A hot reload swaps definitions without losing state: while the window is open the close time is pushed
#      back, the window still answers 200 past its original close, next_fire_ms takes the new value, and changes
#      does not grow just because "the moment came and nothing flipped".
#   7) -t is the enforcement point: referencing an undeclared window, a missing tz, open/close on the same minute,
#      a duplicate window name and a schedule_access with no name all exit non-zero and each give a locatable
#      reason; "declared but referenced by nobody" only warns and still exits 0 (the -t result of an old config
#      must not get worse).
#
#   cargo build --release -p onrouter-server --bin onrouter && python tools/schedule_e2e.py
#   The whole run takes about 8 minutes: two thirds of it is spent waiting on real minute boundaries -- for a
#   feature like this nothing counts as proof until the time actually comes.
import datetime as dt
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONF = os.path.join(ROOT, "conf", "schedule.conf")
ERR_LOG = os.path.join(ROOT, "conf", "logs", "schedule_err.log")
OUT_LOG = os.path.join(ROOT, "logs", "schedule_out.log")

GW_PORT = 18330          # gate written on the location
GATED_PORT = 18338       # gate written at the server level
BACKEND_PORT = 18337     # 18331-18336 are taken by the router.rs unit tests
BASE = f"http://127.0.0.1:{GW_PORT}"
GATED = f"http://127.0.0.1:{GATED_PORT}"

TZ_OFFICE = dt.timezone(dt.timedelta(hours=8))
results = []
lock = threading.Lock()
served = {}
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
    req = urllib.request.Request(url, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def status(url, timeout=10):
    return request(url, timeout)[0]


def wait_status(url, want, timeout, every=0.4):
    """Poll until a given status code shows up. One request per round -- the extra ones would pollute the
    upstream hit counting."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = status(url)
        if last == want:
            return last
        time.sleep(every)
    return last


def metrics_body():
    return request(BASE + "/metrics")[1]


def metric(body, mname, **labels):
    """Read one Prometheus metric value. Labels are written as {k="v"} (here the label key itself is called name)."""
    full = mname + ("{" + ",".join('%s="%s"' % (k, v) for k, v in labels.items()) + "}" if labels else "")
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line == full or line.startswith(full + " "):
            return float(line.split()[-1])
    return None


def mrow(body, mname, win):
    return metric(body, mname, name=win)


def ms(when):
    return int(when.timestamp() * 1000)


def cron_fields(when):
    """Write an absolute moment as the cron minute/hour fields **in that window's own timezone (+08:00)**,
    once per day."""
    w = when.astimezone(TZ_OFFICE)
    return f"{w.minute} {w.hour} * * *"


def wall_text(when):
    """The gateway's fmt_wall convention: %Y-%m-%d %H:%M, read in the window's own timezone."""
    return when.astimezone(TZ_OFFICE).strftime("%Y-%m-%d %H:%M")


def office_block(open_at, close_at):
    return (
        "schedule_window office { tz +08:00; "
        f'open "{cron_fields(open_at)}"; close "{cron_fields(close_at)}"; }}'
    )


def with_office(text, open_at, close_at):
    """Replace only the office block; the other three windows stay as they are (the always-open and always-closed
    controls never take part in the rewrite)."""
    block = office_block(open_at, close_at)
    new, n = re.subn(r"schedule_window office \{[^}]*\}", lambda _m: block, text, count=1)
    if n != 1:
        raise SystemExit("!! no office window found in conf/schedule.conf: the script and the config have "
                         "diverged at their anchor")
    return new


def write_conf(text):
    time.sleep(0.05)
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        os.utime(CONF, None)


def run_t(path):
    p = subprocess.run(
        [EXE, "-t", "-c", os.path.relpath(path, ROOT)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def office_line(out):
    for l in out.splitlines():
        if "schedule window 'office'" in l:
            return l
    return ""


def daily_utc(hh, mm, after):
    """The first "daily hh:mm UTC" moment strictly later than after."""
    cand = after.replace(hour=hh, minute=mm, second=0, microsecond=0, tzinfo=dt.timezone.utc)
    if cand <= after:
        cand += dt.timedelta(days=1)
    return cand


def open_log():
    raw = ""
    for p in (ERR_LOG, OUT_LOG):
        if os.path.exists(p):
            raw += open(p, encoding="utf-8", errors="replace").read()
    return raw


def wait_until(when):
    delta = (when - dt.datetime.now(dt.timezone.utc)).total_seconds()
    if delta > 0:
        time.sleep(delta)


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            served[self.path] = served.get(self.path, 0) + 1
        body = f"backend {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


def backend_total():
    with lock:
        return sum(served.values())


def hits_delta(fn):
    """Run fn once and return (its result, how many requests the backend received during it).
    A "delta of the total" rather than "the count of one path": a proxy_pass with a URI strips the location
    prefix, so the backend sees /x2 instead of /office/x2 -- counting by path would miscount, while "did it proxy
    or not" is exactly what has to be proven here."""
    before = backend_total()
    r = fn()
    return r, backend_total() - before


def main():
    global EXE
    EXE = find_binary()
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    original = open(CONF, encoding="utf-8").read()

    # ---- schedule: anchored on "the next real minute boundary", absolute moments throughout ----
    now = dt.datetime.now(dt.timezone.utc)
    floor = now.replace(second=0, microsecond=0)
    open_at = floor + dt.timedelta(minutes=2)
    close_at = open_at + dt.timedelta(minutes=3)
    close2 = close_at + dt.timedelta(minutes=2)
    print(f"# office opens at {wall_text(open_at)} (+08) and closes at {wall_text(close_at)}, "
          f"pushed to {wall_text(close2)} after the hot reload")

    generated = with_office(original, open_at, close_at)
    write_conf(generated)

    # ---- 1) -t: a valid config has to lay out "the wall clock it computed" ----
    rc, out = run_t(CONF)
    ol = office_line(out)
    check("-t passes (four windows + two gate placements)", rc == 0, out[-600:])
    check("-t prints the rewritten office definition", f'open="{cron_fields(open_at)}"' in ol, ol)
    check("-t next trigger is the exact moment the script computed",
          f"next_trigger={wall_text(open_at)}" in ol, ol)
    check("-t shows office closed right now", "state=closed" in ol, ol)
    check("-t warning: declared but referenced by nobody (tzcheck)",
          "tzcheck" in out and "are referenced by no server or location" in out, out[-600:])

    # ---- 2) hard failures at -t: a mistyped schedule must not go live with half a window table ----
    bad = os.path.join(ROOT, "conf", "_schedule_bad.conf")

    def expect_reject(tag, text, *needles):
        with open(bad, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        rc, out = run_t(bad)
        check(f"-t rejects: {tag}", rc != 0 and all(n in out for n in needles),
              f"rc={rc} missing {needles} / {out[-400:]}")

    expect_reject("reference to an undeclared window",
                  generated.replace("schedule_access office;", "schedule_access ghost;", 1),
                  "references the undeclared window 'ghost'")
    expect_reject("window without tz",
                  generated.replace("schedule_window office { tz +08:00;", "schedule_window office {", 1),
                  "has no tz", "office")
    expect_reject("open and close land in the same minute", with_office(original, open_at, open_at),
                  "state change in the same minute")
    expect_reject("duplicate window name", generated + "\n" + office_block(open_at, close_at) + "\n",
                  "is declared twice")
    expect_reject("schedule_access with a missing name",
                  generated.replace("schedule_access office;", "schedule_access;", 1),
                  "is missing the window name")
    # All of them declared but referenced by nobody: the exit code must still be 0 (a -t result must not be more
    # pessimistic than the old config), but it has to say how many windows carry no gate.
    unreferenced = re.sub(r"\n[ ]*schedule_access [a-z_]+;", "", generated)
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write(unreferenced)
    rc, out = run_t(bad)
    check("-t only warns about 'declared but unreferenced' and exits 0",
          rc == 0 and "declarations, 4 are referenced by no server or location" in out, f"rc={rc} / {out[-500:]}")
    if os.path.exists(bad):
        os.remove(bad)

    # ---- 3) start the gateway, run through real minute boundaries ----
    backend = HTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    for stale in (ERR_LOG, OUT_LOG):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    write_conf(generated)
    logf = open(OUT_LOG, "wb")
    proc = subprocess.Popen([EXE, CONF], cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT)
    notable = []
    try:
        if not wait_status(BASE + "/ping", 200, 30):
            raise SystemExit(f"!! onrouter never became ready (port {GW_PORT}/{GATED_PORT}/{BACKEND_PORT} "
                             f"already in use? see logs/schedule_out.log)")

        # ---- closed period ----
        st1, h1 = hits_delta(lambda: status(BASE + "/office/x1"))
        check("window closed: /office/ 403", st1 == 403, f"actual {st1}")
        check("window closed: the 403 is answered locally by the gateway (not one request proxied)", h1 == 0,
              f"backend saw {h1} extra requests")
        stf, hf = hits_delta(lambda: status(BASE + "/free/x1"))
        check("ungated /free/ answers 200 (default off costs nothing)", (stf, hf) == (200, 1),
              f"{stf}, proxied {hf}")
        check("always-closed window /locked/ is 403 throughout and never proxies",
              hits_delta(lambda: status(BASE + "/locked/x1")) == (403, 0))
        check("always-open window /any/ answers 200 and really proxies",
              hits_delta(lambda: status(BASE + "/any/x1")) == (200, 1))
        check("the server-level gate also blocks /inherited/ without proxying",
              hits_delta(lambda: status(GATED + "/inherited/x1")) == (403, 0))
        read_at = dt.datetime.now(dt.timezone.utc)
        m = metrics_body()
        check("metrics: office closed", mrow(m, "onrouter_schedule_open", "office") == 0)
        check("metrics: next_fire_ms is digit for digit the open moment the script computed",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(open_at),
              f"metric {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(open_at)}")
        # tzcheck is referenced by no route, but its schedule is the same calendar arithmetic -- use it on its own
        # to verify the timezone conversion: 12:00-13:00 (+08) = 04:00-05:00 UTC, so the next trigger must be the
        # earlier of the two.
        # Landing on "the occurrence just after" is allowed: when the metrics read happens to sit exactly on the
        # minute boundary, the two sides compute a now that is one tick apart.
        tz_cands = sorted({daily_utc(4, 0, read_at), daily_utc(5, 0, read_at),
                           daily_utc(4, 0, read_at + dt.timedelta(days=1)),
                           daily_utc(5, 0, read_at + dt.timedelta(days=1))})
        want_tz = min(daily_utc(4, 0, read_at), daily_utc(5, 0, read_at))
        got_tz = mrow(m, "onrouter_schedule_next_fire_ms", "tzcheck")
        check("metrics: tzcheck's next trigger proves +08:00 really converts to UTC",
              got_tz in [ms(tz_cands[0]), ms(tz_cands[1])],
              f"metric {got_tz}, expected {ms(want_tz)} (candidates {[ms(c) for c in tz_cands[:3]]})")
        check("metrics: nothing flipped yet, changes=0",
              mrow(m, "onrouter_schedule_changes_total", "office") == 0)
        d0 = mrow(m, "onrouter_schedule_denied_total", "office") or 0
        check("metrics: the 403s of the closed period count into denied_total", d0 >= 1, f"actual {d0}")
        check("metrics: the always-open window never blocked anything",
              mrow(m, "onrouter_schedule_denied_total", "always_open") == 0)
        check("metrics: the window is still enabled after -t", mrow(m, "onrouter_schedule_enabled", "office") == 1)
        check("metrics: no gate fell through (gate_miss=0)", metric(m, "onrouter_schedule_gate_miss_total") == 0)
        check("startup log carries the runner banner", "scheduled window runner started" in open_log(),
              "no runner banner in the log")

        # ---- wait for the first real minute boundary: open ----
        wait_for_open = max(5.0, (open_at - dt.datetime.now(dt.timezone.utc)).total_seconds() + 40)
        before_flip = backend_total()
        got = wait_status(BASE + "/office/x2", 200, wait_for_open)
        d_flip = backend_total() - before_flip
        check("it really flipped when the time came: /office/ 200", got == 200, f"actual {got}")
        check("the whole wait proxied exactly once (every other poll was stopped by the gateway, so the gate "
              "really is in front of the proxy)", d_flip == 1, f"backend delta {d_flip}")
        check("the server-level gate opens /inherited/ in step",
              hits_delta(lambda: status(GATED + "/inherited/x2")) == (200, 1))
        check("an explicit location wins: while office is open /override/ is still 403 and does not proxy",
              hits_delta(lambda: status(GATED + "/override/x1")) == (403, 0))
        m = metrics_body()
        check("metrics: office open", mrow(m, "onrouter_schedule_open", "office") == 1)
        check("metrics: flip counter = 1", mrow(m, "onrouter_schedule_changes_total", "office") == 1,
              f"actual {mrow(m, 'onrouter_schedule_changes_total', 'office')}")
        check("metrics: next_fire_ms moved to the close moment the script computed",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(close_at),
              f"metric {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(close_at)}")
        raw = open_log()
        check("error_log recorded this flip (open)",
              "switched to open" in raw and "window 'office'" in raw, "no flip line in the log")

        # ---- hot reload: push the close time back while the window is open ----
        write_conf(with_office(original, open_at, close2))

        def moved():
            return mrow(metrics_body(), "onrouter_schedule_next_fire_ms", "office") == ms(close2) or None

        check("hot reload: next_fire_ms follows the new config to the pushed-back close moment",
              wait_for_pred(moved, 25) is not None,
              f"stuck at {mrow(metrics_body(), 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(close2)}")
        m = metrics_body()
        check("hot reload: state recomputed correctly (still open)",
              mrow(m, "onrouter_schedule_open", "office") == 1)
        check("hot reload: no phantom flip counted",
              mrow(m, "onrouter_schedule_changes_total", "office") == 1,
              f"actual {mrow(m, 'onrouter_schedule_changes_total', 'office')}")

        # Past the original close: that old close moment must really no longer apply.
        wait_until(close_at + dt.timedelta(seconds=25))
        st3, d3 = hits_delta(lambda: status(BASE + "/office/x3"))
        check("still allowed past the original close (the reload pushed back that very calendar entry)",
              (st3, d3) == (200, 1), f"{st3}, proxied {d3}")
        check("the always-closed window is still 403 while traffic is allowed",
              hits_delta(lambda: status(BASE + "/locked/x2")) == (403, 0))

        # ---- wait for the second real boundary: close ----
        wait_until(close2 + dt.timedelta(seconds=8))
        before_close = backend_total()
        got = wait_status(BASE + "/office/x4", 403, 40)
        d_close = backend_total() - before_close
        check("the new close came due: /office/ back to 403", got == 403, f"actual {got}")
        st5, d5 = hits_delta(lambda: status(BASE + "/office/x5"))
        check("no proxying after the close", (st5, d5) == (403, 0), f"{st5}, proxied {d5}")
        check("not one poll escaped after the close moment", d_close == 0, f"backend delta {d_close}")
        m = metrics_body()
        check("metrics: office closed again", mrow(m, "onrouter_schedule_open", "office") == 0)
        check("metrics: two real flips accumulated", mrow(m, "onrouter_schedule_changes_total", "office") == 2,
              f"actual {mrow(m, 'onrouter_schedule_changes_total', 'office')}")
        check("metrics: next trigger = tomorrow's open moment",
              mrow(m, "onrouter_schedule_next_fire_ms", "office") == ms(open_at + dt.timedelta(days=1)),
              f"metric {mrow(m, 'onrouter_schedule_next_fire_ms', 'office')} vs {ms(open_at + dt.timedelta(days=1))}")
        d1 = mrow(m, "onrouter_schedule_denied_total", "office") or 0
        check("metrics: the 403s after the close keep accumulating", d1 >= d0 + 2, f"d0={d0} d1={d1}")
        check("metrics: the always-closed window kept blocking all along (locked denied >= 3)",
              mrow(m, "onrouter_schedule_denied_total", "locked") >= 3)
        check("metrics: removing the earlier windows does not freeze the schedule (tzcheck still moving)",
              mrow(m, "onrouter_schedule_next_fire_ms", "tzcheck") != -1)
        raw = open_log()
        check("error_log recorded the second flip (closed)", "switched to closed" in raw,
              "no second flip in the log")
        check("the window summary was reprinted after the hot reload",
              "after hot reload, schedule window 'office'" in raw, "window summary not reprinted after reload")
        notable = [l for l in raw.splitlines() if "schedule: window" in l or "scheduled window reload" in l]
        logf.flush()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        backend.shutdown()
        write_conf(original)

    for l in notable:
        print(f"#   {l.strip()[:160]}")
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n==== scheduled access window E2E: {passed}/{total} passed ====")
    print(f"     backend served {sum(served.values())} proxied requests "
          f"({len(served)} paths: {sorted(served)})")
    sys.exit(0 if passed == total else 1)


def wait_for_pred(pred, timeout, every=0.4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = pred()
        if r:
            return r
        time.sleep(every)
    return None


if __name__ == "__main__":
    main()
