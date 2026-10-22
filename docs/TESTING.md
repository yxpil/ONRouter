# Testing

How the suite is organized, what each group of scripts proves, and how the full gate is run. The
short version: `cargo test --workspace` for units, `python run_regression.py <script list>` for the
E2E roll. CI runs the unit tests plus the E2E steps on Linux.
## E2E tests (ported assertions from the upstream Lua-module suite)

OpenResty publishes its E2E tests in the `t/` directory of `openresty/lua-nginx-module` (193 `.t`
files driven by Perl Test::Nginx). This repo adopts a "ported-assertions" strategy: extract
config/request/response/error_log expectations from the official `.t` `__DATA__` sections and rewrite
them as standalone runnable assertion scripts.

- `timer_e2e_test.py`: 11/11 passing, ported from `t/106-timer.t`, `t/152-timer-every.t`,
  `t/107-timer-errors.t` (premature first arg, vararg forwarding, `every`'s `return false` stop, four
  error-string classes, no log cross-talk).
- `realworld_e2e_test.py`: 26/26 passing, a full simulation of real-world scenarios (static cache
  negotiation / range resume, API reverse proxy, auth, login rate limit 429, WebSocket 101 tunnel
  round-trip, background timer heartbeat, 5 MB upload with matching sha256, 413, failover, timeout,
  502 on a dead backend, 30-request concurrency burst, malformed request → 400 with the gateway
  staying alive).
- `tools/api_compat_e2e.py`: 57/57 passing, one process plus real HTTP/TCP backends covering the
  newer API surface end-to-end — request metadata (`start_time/http_version/is_internal`), extra
  `ngx.var`s, `send_headers`/`headers_sent`/`eof`, body builders reaching `proxy_pass` with an exact
  `Content-Length`, `discard_body`, capture `method/body/args` + internal-only locations,
  `capture_multi` concurrency (4×0.2 s in <0.45 s), `ngx.semaphore` wake/timeout, dict
  `get_keys`/`expire`, `resty.cookie` multi-cookie output, `resty.limit.count/req/conn` incl. a
  concurrent rejection, socket `sslhandshake`/`getreusedtimes`, and `ngx.worker.pid/pids`.
- `tools/cache_advanced_e2e.py`: 32/32 passing — `proxy_cache_lock` coalescing (20 concurrent
  same-key requests → 1 origin fetch, 1 `MISS` + 19 `HIT`), `use_stale` for HTTP 502, connect
  failure and `updating` (STALE returned in <0.45 s while the 0.6 s refresh is in flight),
  `bypass`/`no_cache` store-vs-skip semantics, keys_zone-driven LRU eviction, and HEAD
  serving from (but never populating) the shared GET cache entry; the basic suite
  `tools/proxy_cache_e2e.py` remains 21/21.
- `tools/proxy_disk_e2e.py`: 39/39 passing — the `proxy_cache` disk cold tier over real traffic with
  three zones of the *same* 8-entry `keys_zone`: `disk=on spill_after=0` (mechanism), `disk=on
  spill_after=3` (gate) and no `disk=` at all (control). Proved: the evicted-but-fresh entries really
  land in the directory as self-describing `ORDK` records; a request for one of them returns
  `X-Cache-Status: HIT` + `X-Cache-Tier: disk` **with the backend counter unchanged** (the only
  evidence that matters — no origin call), then promotes it so the next hit is memory-only; the
  control zone's directory is never even created and its evicted key goes back to the origin; the
  gate zone writes nothing for one-shot traffic; flipping a byte in every cold file yields correct
  bodies for all 12 keys, 12 origin refetches and a `corrupt` count that moves — never a wrong
  response and never a 5xx; after a stop/start `warm_recovered` equals the index size that was
  reported before shutdown and cold hits keep serving.
- `tools/still_online_e2e.py`: 25/25 passing — Still ONLine under a real backend kill/restart. The
  backend is Python's `ThreadingHTTPServer` with keep-alive, so "crash" is simulated by hard-closing
  established connections too (a bare `shutdown()` would leave pooled connections serving 200s and
  the outage would be invisible). Covers: copy written on healthy `GET` 2xx, replay as `200` +
  `X-Still-Online: stale` + `Age` with byte-identical body while the origin is dead, credentialed
  `GET` → 502 (no read of someone else's copy) unless `still_online_allow_credentials on`, replays
  never carrying `Set-Cookie`, `POST` staying 502, `Set-Cookie` and over-`max_body` responses never
  entering the zone, a no-zone control location always returning a plain 502, `served`/
  `rejected_credential`/`pending_jobs` counters moving, then after the origin returns both dirty keys
  are re-fetched (`refreshed +2`), the queue drains to zero, and a second outage replays the
  *recovered* version instead of the pre-crash one.
- `tools/disk_cache_e2e.py`: 53/53 passing — the DICT disk cold tier under real traffic. Filling a
  24 KiB zone proves the evicted tail lands on disk (`spill`/`entries` gauges) and reads back
  byte-identical through `get()` (`cold_hit`/`promote`), that `num()` spans both tiers while
  `free_space()` stays exact to `key+value+64` per memory entry, that one key never sits in both tiers,
  that a process restart rebuilds 15 entries by scanning the directory, that truncating **every**
  entry file only costs those entries (`corrupt` == file count, service keeps serving and re-spilling),
  that a true miss leaves both cold-tier counters frozen and is as fast as a diskless control zone,
  that traversal-shaped keys can only ever land in hex directories, that `spill_after=2` writes
  exactly the one warm key to disk while 200 one-shot writes are all refused, and that `flush_all()`
  arriving while spills are still queued discards that whole generation (no resurrected keys, no
  orphan files) — the last three checks fail 3/3 on a build with the generation guard removed.
- `tools/learning_cache_e2e.py`: 34/34 passing — cache learning under real traffic, with a control
  zone. Two `proxy_cache_path` zones of the *same* capacity (`keys_zone=1k` → 8 entries each), one
  declaring `proxy_cache_learning`, one not. The same flood of one-shot URLs runs through both: on the
  learning side the hot object survives and the one-shots are refused entry
  (`onrouter_cache_learning_events_total{role="admission_rejected"}` climbing while `evicted_cold`
  stays 0), on the plain-LRU side the hot object is flushed out (`HIT` → `MISS`), which is the point —
  the assertion is about observable cache status, not about sketch internals. Also covers the budget
  ledger (`used` == the zone's sketch bytes), a zone that is declared but refused (bytes stay 0), and
  the hot-reload path where shrinking `learning_memory_budget` drops the sketch and returns to LRU.
  Its last two checks are the `-t` round: the three directives are not reported as unknown, the
  per-zone learning summary is printed, and a `proxy_cache_learning` naming a `keys_zone` that was
  never declared is **rejected** — `apply_learning` only walks existing zones, so a typo there would
  silently learn nothing.
- `tools/queue_learning_e2e.py`: 42/42 passing — three locations over one `10r/s burst=0` zone, only
  "what happens when a request is over rate" differing. `plain` (no queue): 12 concurrent → 1 released,
  11×`429` with `Retry-After`, and `/metrics` renders **no** queue rows for it. `stat` (queue, no
  learning): 12 concurrent → 1 + `depth(8)` = 9 released, the per-request latency of the queued ones is
  measured to really be hundreds of ms, and the queue stays bounded. `learn` (learning on): the first
  burst of a cold key gets only `depth_min=1`, then with **no config change** the identical burst gets
  all 8 slots and `onrouter_queue_depth{kind="learned"}` jumps to ≥ 8 — that is the evidence depth
  adapted by itself, under an operator-held ceiling. Then a dense flood wipes the learned shape
  (`learned` back to the floor, `429` dominant), a hot reload shrinking `learning_memory_budget` below
  the table releases it (`used` → 0, log says why) while the queue keeps serving at the configured
  ceiling, and restoring the budget rebuilds it.
- `tools/vip_learning_e2e.py`: 51/51 passing — reputation with real client addresses, fed through
  `real_ip_header X-Forwarded-For` + `set_real_ip_from 127.0.0.0/8` (proven by the access log's first
  field being the virtual address), because `limit_req` zones can only key on `$remote_addr`. Covers:
  an address with no reputation getting 1 queue slot for a burst of 9 and 8×`429`; the same address
  after sparse in-rate traffic crossing `min=10` (`onrouter_vip_clients` 0 → 1, `role="promoted"` ≥ 1)
  then getting all 8 slots for the *same* burst with zero `429`s and a measured ≥ 300 ms wait for the
  last one; queuing scoring nothing either way (`role="queued"` recorded, score unchanged); cache
  retention as a differential — the VIP's object is still `HIT` after 7 hotter newcomers displaced the
  identical object written by a no-reputation address (`evicted_cold` ≥ 7, `retained` == 1), and the
  boost never skips admission (a VIP write into a full zone is still refused); a promoted client that
  starts flooding losing the status (`vip_clients` 1 → 0, `demoted` ≥ 1, `rejected` ≥ the number of
  `429`s) and its learned depth being knocked back to the floor by the flood line; and the ledger
  check that `onrouter_learning_memory_bytes{role="used"}` equals burst table + sketch + reputation
  table bytes exactly, under `learning_memory_budget 64k`, with `budget_denied` at 0.
- `tools/observability_e2e.py`: 26/26 passing, one process and real traffic for the #40 telemetry:
  a live + dead node pair (`success`/`failure` per node, connection gauge back to 0, healthy gauge),
  a MISS→HIT→BYPASS→EXPIRED cache sequence matched against `X-Cache-Status` **and** the per-status
  Prometheus counters, `limit_req` 200→429 with `Retry-After`, `limit_conn` 503 under an in-flight
  `ngx.sleep` request and recovery afterwards, a raw TLS-garbage probe bumping the handshake-failure
  counter, a WebSocket 101 upgrade counted against its upstream, and access-log line assertions for
  `$request_time` + the upstream triple (proxied, no-upstream `- - -`, and Upgrade `101`).
- `tools/front_proxy_e2e.py`: 54/54 passing — CDN awareness proved on both sides of the trust gate, over
  six ports (`conf/front_proxy_e2e.conf`: egress+`auto_trust`, an out-of-range control, `auto_trust off`,
  `detect`, an origin vhost with `proxy_cache`, and a Python fake origin). The address rewrite is proved
  where it matters — the access log's first column and a `geo $net` derived variable — and the forged case
  is proved to change *nothing* while still being labelled. `limit_req` gives the causal split: the same 8
  faked client addresses are 8 buckets on the egress vhost (all 200) and one bucket on both controls
  (node address, 429s). `Cache-Status` is asserted as a real `MISS→HIT` pair with exactly **one** origin
  request, as ours appended after an upstream `Cache-Status`, and as absent on an unverified peer. The
  config layer gets its own `-t` rejections (inert `auto_trust`, `egress` with no range, mode typo, bad
  CIDR, mode without profiles), and the advisory layer is asserted to stay one line per profile after
  dozens of blocked requests.
- `tools/least_time_e2e.py`: 43/43 passing — adaptive selection proved against three fake backends with
  deliberately different, *runtime-changeable* delays (5 ms / 200 ms / 400 ms, spaced that wide on purpose:
  this host's `sleep()` jitter is ±20 ms, so the spacing is the measurement margin for every ratio
  assertion and none of the thresholds was relaxed) behind `off` / `observe` /
  `on` pools in one gateway (`conf/least_time_e2e.conf`). The `off` baseline is exact round-robin (8/8/8
  over 24 requests) and has **no** `least_time` metric lines at all, before and after the whole run.
  `observe` is proved not to change behaviour — its 24-request backend *sequence equals `off`'s* — while
  still measuring (`sampled=24`, `picked=0`, `would_differ>0`, and the EWMAs come out ordered
  `a<b<c` and within a few ms of the delays actually configured). `on` then migrates traffic (fastest
  node ≥55%, slowest ≤15%, client p50 at least halved), explores every backend while no sample exists,
  and reverses the migration when the fastest backend is slowed to 400 ms while the slowest is sped up to
  5 ms — the re-measured EWMA is what moves the traffic. Failure is proved not to pollute the estimate:
  a dead port in the same pool shows `requests_total{result="failure"}≥1` with `ewma_seconds` still `0`,
  while requests keep succeeding via node switching. The config layer is asserted to reject what would be
  silently inert (`ip_hash`+`least_time` in either tier, `least_time detect`, `least_time` with no
  argument, `least_time_window 0s`) and to *warn* — not fail — for a single-node pool.
- `tools/proxy_split_e2e.py`: 76/76 passing — business splitting proved on both sides of every
  boundary, over ten `split_clients` declarations and eleven splitting locations in one gateway
  (`conf/proxy_split_e2e.conf`: four header-echo backends, one 500-only pool, a dead port nobody
  listens on, and a pool that only becomes "nobody left" after the first request trips `max_fails`).
  Config layer: `-t` prints one line per splitting location naming the declared ratio, the sticky key
  and the policy (`改投下一路` / `不串台（原样失败）` / `只改投 green`), shows a `0%` branch as what it
  is, and rejects the six shapes that would otherwise be silently inert — `proxy_split_failover` on a
  literal `proxy_pass`, a branch containing a path, an explicit fallback that is not one of the
  declared branches (and tells you to declare it as the `0%` one), a variable embedded mid-host,
  `proxy_split_failover $var`, and a split whose every branch is the empty string; a `set`-produced
  target variable still passes `-t` but warns that no branch set exists. Traffic layer: per-branch
  counts match an independently ported MurmurHash2 reference **key by key**, 1200 distinct keys
  reproduce 50/30/20, the `targets_total` deltas equal the backend-side counts exactly, the `routed`
  delta equals the number of requests sent, and both nodes *inside* the winning pool serve — the split
  is pool-level and that pool's own balancing still runs. `off` returns four `502`s while the stable
  branch's backend counter and both metrics do not move by one; the explicit fallback touches only the
  named branch and never the sibling declared in the same ratio; a `0%` branch is unreachable by the
  ratio (a 20 000-key scan, plus the Rust sweep over all 10 000 bucket coordinates) yet reached by
  exactly one bleed; an empty bucket is "this branch has nobody" under `on` and a plain `502` under
  `off`; a `500`-only branch bleeds nothing; a refused TCP connection after an address was picked is
  that branch's own failure (`routed+1`, `bled 0`, `down 0`); and the cache is per branch
  (`MISS`→`HIT`, the other version still `MISS`, `$proxy_split_served` empty on the hit).
- `tools/proxy_split_business_e2e.py`: 32/32 passing — the same feature viewed as *a day of traffic on a
  real site* rather than as a list of directives. `conf/proxy_split_business.conf` models a UGC homepage
  host: 240 logged-in users keyed by `${cookie_uid}` (business identity, not `$remote_addr`), each running
  one session — own homepage (cached), own feed call (uncached), one POST comment with a globally unique
  id — against `app_stable`/`app_next`/`app_hotfix` as three separate version pools, plus a release ladder
  (2%/18%/rest), a grey experiment under `proxy_split_failover off`, a version pool that is *entirely down*
  mid-scenario, and a `$remote_addr`-keyed declaration as the counter-example. Every assertion is a business
  consequence, read out of the origins' own records rather than out of the gateway: all 720 requests succeed;
  a user's homepage and feed never disagree about which version they are on; the 18% is the exact set the
  reference hash predicts for those 240 keys (not a ±tolerance on a sample); the comment-id ledger across
  **all** pools shows each id written exactly once; the two-node pool still spreads inside its own branch
  (splitting is pool-level); `/metrics` per-branch counts equal "users in that branch × 3" with
  `bled=down=empty=0`; a homepage cached at 18% and at 82% gets `MISS`→`HIT` independently and each keeps
  serving its own version's body, with `$proxy_split` still set and `$proxy_split_served` empty on the hit;
  when the grey branch is down its users fail 100% (502) with the stable version's write ledger untouched
  and `bled` still 0 — which is the business reason `off` exists, because a silent re-route would publish a
  fake error rate; on the default tier the *first* request to the dead pool is that branch's own failure
  (`routed` only, no `bled`/`down`), and from the second request the same user is served by the next branch
  with `$proxy_split=app_bleed` vs `$proxy_split_served=app_stable`, still with the failed comment id absent
  and the re-routed one present exactly once (the re-route happens before any node has the body); 50
  distinct users on the `$remote_addr` key all collapse into one branch, which is what "behind a CDN this
  switch flips the whole site" looks like in real traffic; and the literal `proxy_pass` path produces zero
  movement in every split ledger.
- `tools/proxy_split_examples_e2e.py`: 24/24 passing — it runs the file operators are told to copy
  (`conf/proxy_split_examples.conf`), not a test-only shape: a 1%/5%/`*` release ladder, a 30% grey
  branch under `proxy_split_failover off`, a `0%` hotfix branch reachable only through failover, and a
  literal `proxy_pass /admin` that pays nothing for any of it (no attribution headers, no ledger
  movement). It imports the same hash port as the suite above, so key→branch prediction is one
  implementation shared by both, and the branch is read back out of the origin's own response body
  (`who=<node>` + `branch=<pool>`), so "which release answered" is the backend's word plus the
  gateway's header plus the metric increment, required to agree.
- `tools/schedule_e2e.py`: 50/50 passing — timed access windows proved across **two genuine minute
  boundaries** with real traffic, not a faked clock: the script rewrites `conf/schedule.conf`'s `office`
  window into "open at floor(now)+2 min, close +3 min after that", starts the gateway, and waits. Closed
  phase: `/office/` is `403` while the origin's total request count does not move by one — and the very
  next assertions (`/free/` → `200` with delta +1, `/any/` → `200` with delta +1) are what make that zero
  mean "the gate answered locally" instead of "the counter is broken". Flip: `/office/` turns `200` and the
  whole wait produced **exactly one** origin hit, `onrouter_schedule_open` went 0→1 with
  `changes_total=1`, and `next_fire_ms` equals the epoch-ms the script computed, to the digit — before the
  flip the open instant, after it the close instant, after the close tomorrow's open. `+08:00` is verified
  as arithmetic rather than as a log line: an unreferenced window's `next_fire_ms` must be the UTC instant
  of its 12:00 wall clock. Then a hot reload moves the close two minutes later while the window is open:
  `next_fire_ms` follows, `changes_total` stays 1 (reaching a trigger that flips nothing is not a change),
  and requests keep passing *past the old close* — which is only possible if the state really is re-derived
  from the calendar. Precedence is asserted on a second listener whose gate sits on the `server`: an
  ungated location inherits it and flips with it, while a location that names the permanently-closed window
  stays `403` throughout. Five configs are asserted to fail `-t` with a locate-able reason (a reference to
  an undeclared window, a missing `tz`, an open/close pair that fires in the same minute, a duplicate name,
  a bare `schedule_access;`), and "declared but referenced by nobody" is asserted to stay a *warning* with
  exit 0, so an old config's `-t` result cannot get worse.
- `tools/governor_e2e.py`: 32/32 passing — the phase machine proved on two live gateways (auto/deep
  on 18560, the off control on 18561) with real traffic on a real clock, never a faked one. Default
  off leaves the control instance with **not one** `onrouter_governor_*` series and no governor line
  in its logs, while the auto instance starts the run in `sleep` on an idle start. The test's own
  traffic is the only input: 8 rps wakes the cache layer to `normal` (`> low × 1.5`) and quiet
  settles it back to `sleep`; deep sleep then demotes all 64 seeded 512-byte dict entries
  (`demoted_total ≥ 64`), the cold root holds the forced spills with `spill_after=1000` (ordinary
  eviction cannot have written a byte), `free_space` jumps back by >20 KB while `num()`/`size()`
  still report 64 cold copies, and sampled reads return the full 512-byte values through the cold
  tier. A paced 45 rps burst crosses `high` on the trailing-8s estimate, enters `boost` inside the
  burst, pre-warms ≥40 keys back, moves `boost_ticks_total` and feeds the minute profile
  (`profile_coverage > 0`); stopping the traffic decays the estimate and exits to `normal` with no
  restart. Five `-t` variants pin the contract (inverted thresholds and orphan `learn` exit
  non-zero; deep-without-`disk=` and observe+learn warn at exit 0; the off config prints no governor
  line), and a hot reload strips the whole directive family — every series disappears while dict
  data stays readable — then restores it, with the parsed line re-logged.
- `tools/protocol_matrix_e2e.py`: 37/37 passing — one gateway process serving every client-facing
  protocol at once, with both the client's and the gateway's own view asserted (the access log is
  read back, so a 200 cannot come from a protocol the gateway silently down-converted). HTTP/1.0 on
  plaintext and TLS returns an `HTTP/1.0` status line with no chunked encoding, closes by default,
  honors `Connection: keep-alive` for a second request on the same socket, and carries a POST body;
  HTTP/1.1 does two keep-alive requests on one connection on both transports. HTTP/2 is a real
  Node-core-`http2` h2c prior-knowledge session (8 streams) and an ALPN-h2 TLS session, while
  HTTP/1.0 still works on the h2c port. HTTP/3 runs over QUIC via `orr-h3check` (single request,
  ≥15 KB body, 5 streams) and the same port keeps serving HTTP/1.1 with `Alt-Svc: h3=":port"`. ws
  and wss both complete the RFC6455 handshake, check the computed `Sec-WebSocket-Accept`, and
  round-trip text frames, a ping answered as pong, and a close handshake through a real Node
  WebSocket backend (ws also sends a 500 B binary frame, wss a 70 000 B one — the latter exercises
  the 64-bit length).
  The access log then shows `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0` and two `101` upgrades.
  Boundary, asserted by construction rather than by omission: WebSocket upgrades stay HTTP/1.1
  (RFC 8441/9220 over h2/h3 are not implemented, matching nginx), and h2/h3 to upstreams remain
  open as noted below.
- The 1.0 batch is verified on its own release build: `cargo test --workspace` → 482/482
  (469 in `onrouter-server` + 13 in `onrouter-config`), clippy clean, and five real-traffic
  suites pass 145/145 — `canary_e2e` 22/22 (cookie/header/arg/UA/OS/percent rules,
  first-match-wins, stickiness across a cache purge), `wasm_e2e` 23/23
  (access/header_filter/body_filter, host ABI, fail-closed), `resilience_e2e` 17/17
  (passive removal, lazy rejoin driven by a real request, circuit open/half-open, and the
  `server_available` gauge), `affinity_e2e` 7/7 (mask parsing, rotation, topology and `-t`),
  plus the existing `proxy_split` 76/76. The tutorial walkthrough itself is exercised end to
  end — `conf/tutorial_full.conf` with 33 assertions across static, canary, rewrite, cache,
  WASM, shared dict, circuit and lazy rejoin — and passes 33/33. A 21-minute soak on the
  release build (24 short + 4 keep-alive workers, 5-minute warmup) reports PASS:
  **2,591,305 requests, 0 failures, 2064.7 req/s**, private memory 20.11 → 21.97 MiB
  (+1.86 MiB, +0.067 MiB/min; a first run added +2.19 MiB over 2,787,193 requests).
  Full tables in OPERATIONS §13.1.
- 1.0.1 adds the response-cache cold tier, conditional revalidation and server-level REWRITE, and is
  verified the same way: `cargo test --workspace` → **503/503** (490 `onrouter-server` + 13
  `onrouter-config`) with no new clippy findings, and the cache suites it must not regress all pass on
  real traffic — `proxy_disk_e2e` 39/39 (spill → cold hit with
  the backend counter unchanged → promote → restart `warm_recovered` → whole-directory corruption
  counted and refetched, never served), `proxy_cache` 21/21 (`proxy_cache_revalidate`'s R1–R8 run
  against a backend that counts conditional answers separately from full sends, so "the origin was
  asked" and "the origin resent the body" cannot be conflated, with a no-revalidate control showing
  `EXPIRED` plus a second full copy), `set_if_e2e` 34/34 (server-level REWRITE: S16–S23, variable
  visible in the location, `if` overriding `set`, a rewrite changing which location matches,
  `if`-body `return` and bare `return` both terminating the phase, a redirect-only vhost answering
  301 with `$host` expanded, and `-t` going quiet), `cache_advanced` 32/32,
  `cache_header_gap` 25/25, `disk_cache` 53/53, `learning_cache` 34/34, `still_online` 25/25,
  `governor` 32/32. The six feature suites now total 184 assertions (canary 22, wasm 23,
  resilience 17, affinity 7, proxy_split 76, proxy_disk 39) and `conf/tutorial_full.conf` verifies
  end to end at 38/38 including its new `/cold` endpoint. The 21-minute soak now *churns* the tier
  (an 8-entry `disk=on` zone against a repeating 256-key space — the old 4 MiB zone could never
  evict, so a passing soak proved nothing about the new code): **2,231,814 requests, 0 failures**,
  20.92 min, 1778.1 req/s, private memory 18.58 → 19.29 MiB (+0.71 MiB, +0.021 MiB/min against a
  1 MiB/min gate), peak 21.07 MiB, and end-of-run tier accounts of 81,723 spills / 80,986 cold hits /
  80,986 promotions with `pending_jobs` 0, `corrupt` 0 and `never_read` 0. The whole roll runs on the
  final binary: `python run_regression.py reg_101_roll.txt` → `TOTAL 86 scripts, nonzero=1` (the one
  failure it reported was `smoke_suite.py` asserting `add_header`'s value as the literal
  `ONRouter/0.2` — a version pin passing itself off as a behaviour test; it now asserts the prefix
  and exits 0, including on the 1.0.2 roll below).
- The pre-1.0 roll (0.8.0, 460 unit tests + 81 Python E2E scripts: every `tools/*_e2e.py`
  (73) plus the 8 root scenario/compat/security/static/upstream suites) was re-run on that
  build: every E2E script passes with real traffic
  (`python run_regression.py reg_proto_20261021.txt` → `TOTAL 81 scripts, nonzero=0`,
  2026-10-21 — the run over the protocol-matrix build, adding `protocol_matrix_e2e` 37/37
  (HTTP/1.0, HTTP/1.1, h2c/TLS h2, HTTP/3 and ws/wss on one process) to `governor_e2e`
  32/32, `schedule_e2e` 50/50, `least_time` 43/43, `realworld` 26/26 and the
  binary-swapping `tls_legacy` passing *including* its native-tls rebuild/restore,
  alongside `proxy_split` 76/76, the business model 32/32, the shipped example config
  24/24, `front_proxy` 54/54, `rce_matrix` 32/32, `security_matrix` 36/36 and the
  three learning suites 34/34, 42/42 and 51/51; the previous roll is
  `reg_gov_final_20261021.txt` → `TOTAL 80 scripts, nonzero=0`) and
  `cargo test --workspace` → 460/460
  (447 in `onrouter-server` + 13 in `onrouter-config`; the previous 0.7.0 roll is
  `reg_070_20261020.txt` → `TOTAL 79 scripts, nonzero=0`, and `reg_fpopt_20261020.txt`
  re-ran the same 79 over the post-de-allocation build).
  The packaged artefact is checked separately by `tools/release_verify.py` (26/26 for 1.0.0 —
  the fresh extract `-t`s the shipped `conf/onrouter.conf` including its 8443 TLS listener,
  using the self-signed pair generated at packaging time —
  including the 0.7.0 schedule checks: the extracted binary must `-t` the shipped
  `conf/schedule.conf` to exit 0 *and* print the per-window `describe` lines, proving the
  gate feature is compiled into what users download):
  it extracts the shipped zip — not the build tree, which another suite may have swapped the
  binary under — boots it on the shipped example config and asserts the version string, the
  `Server` header, a real static response, the recognise-but-don't-trust split and the
  probe-AND-semantics negative control, then greps the provider names out of that exact binary.
  `python run_regression.py <name>.txt` runs all of them and writes the exit-code
  roll-up plus per-script logs under `logs/regression/`. `tls_legacy_e2e.py` rebuilds
  the release binary with `--features native-tls` and restores the default build, so
  never start two suites at once on this host.
- The official suite is vendored under `vendor/lua-nginx-module/t/` (gitignored) as a semantics
  reference. Running a full `.t` directly via Test::Nginx requires a real OpenResty binary as
  `TEST_NGINX_BINARY` plus `*_by_lua_block` syntax and Unix signals, which do not run on this Windows
  host — hence the ported-assertions route.
- nginx syntax-compat shim: ONRouter now accepts nginx's `-p <prefix>`, `-g "<directives>"`, `-e <file>`
  flags and writes a pid file, and the config parser flattens the `http{}` wrapper (dropping
  `events{}`), so the official `nginx-tests` Perl harness (Test::Nginx) can spawn ONRouter directly.
- Compatibility regression: `compat_test.py` 17/17, security `sec_test.py` 30 checks, plus the
  static / scenario / upstream suites in this directory.
