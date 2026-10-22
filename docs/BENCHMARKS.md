# Benchmarks & measurement notes

Every benchmark here is a single-feature seam with its own self-proof: a row whose counters did not
move is not measuring that seam. Numbers are for this host on the stated date; run the harness on
your own hardware before quoting them.
## Benchmarks and deployment docs

- `bench_ab.py` runs ONRouter vs OpenResty on the same endpoints (Windows and Linux);
  `tools/linux_ab.sh` renders an OpenResty config into a temporary prefix and runs the sweep.
  Procedure, caveats, and the pending Linux baseline are in [LINUX_AB.md](LINUX_AB.md).
- `bench_front_proxy.py` costs a single feature seam rather than a whole gateway, and it is the
  pattern any new per-request path should follow. One binary serves five identically-shaped vhosts
  that differ only in `front_proxy_mode` (`conf/bench_front_proxy.conf`: off / detect / egress +
  `front_proxy_auto_trust` / egress without it / egress with no vendor headers at all), plus a floor
  gateway that declares no `front_proxy` block whatsoever (`conf/bench_front_proxy_floor.conf`) — so
  "cost of this seam" is separable from "cost of this vhost shape". Every row sends the *same*
  header set, so the mode is the only variable. Before timing anything it proves each branch actually
  ran: a `/who` Lua echo of `$remote_addr` / `$front_proxy` / `$front_proxy_verified` / `$scheme`,
  `Cache-Status` on the buffered path, the first access-log field, and the per-window delta of
  `onrouter_front_proxy_total{role=…}` around each cell — a row whose counters did not move is not
  measuring that seam. Multiple passes take the median (single-pass numbers on this host carry
  ~10% jitter, enough to invent a 10% difference on a code path that runs zero instructions).
  Run it with `python bench_front_proxy.py --passes 5 --levels 1,32`; never at the same time as a
  build or a regression pass, and never concurrently with `tls_legacy_e2e.py`, which swaps the
  release binary to a `native-tls` build. Measured on this host (2026-10-20, 5 passes, n=8000 at
  c=1 / 38400 at c=32, `logs/bench_fp_run.log` then `logs/bench_fp_loggate.log`): read every cell as
  *that row against its own `off` row*, because the floor row's per-cell round spread reached 36% and
  cannot carry a claim. `detect` costs nothing measurable (−0.6% … +2.6%, inside jitter) — it returns
  after labelling, before address parsing. `egress` — the only row that rewrites, and the only one that
  emits the per-request `log_debug!` — cost −0.4% … −9.2% at c=1 and −1.6% … −3.9% at c=32 before that
  diagnostic was gated, and −0.4% … −4.8% / −1.6% … −4.2% after the log macros started checking
  `log::enabled(level)` before building their `format!` string. The rest of the egress cost is the
  per-request `String`/`Vec` clones on the rewrite path, not the log line. A follow-up round
  (2026-10-20) removed most of those: `percent_decode` returns `Cow<str>` (no `%` ⇒ borrowed, zero
  alloc), `ip_from_value` walks the comma chain without materialising a `Vec` (forward pass keeps the
  last address, reverse pass the leftmost non-trusted), `scheme_from_value` returns `&'static str`, and
  `nets_for` borrows either trust list when the other is empty. The rps bench cannot separate this
  round from jitter (medians overlap pass-to-pass spread at c=32), so the causal proof is
  allocation-count tests instead: a counting thread-local global allocator in the `front_proxy.rs`
  test module asserts 0 heap allocations for a plain XFF chain, for the recursive walk with trusted
  nets, and for every scheme shape, and exactly 1 for a percent-encoded value (the decoded string).
- `bench_least_time.py` costs *and* earns back the adaptive-selection branch with the same harness
  shape: one binary, one vhost, four `proxy_pass` locations pointing at four pools that differ only by
  the `least_time` tier (`conf/bench_least_time.conf`: single-node pool, default `off`, `observe`,
  `on`), in front of three Python backends started from one source file whose only variable is a
  per-request `sleep`. Two scenarios answer two different questions — `same` (all three backends 0 ms,
  so a row-to-row gap can only be code cost) and `hetero` (0/10/40 ms, the case the branch exists to
  solve). Each row self-proves before timing: which backends actually answered (24 sequential requests
  read the serving port out of the body), plus the per-window delta of
  `onrouter_upstream_least_time_total` — which came out exactly `n` for `sampled` under `observe` and
  for `picked` under `on`, `would_differ` ≈ 66% of requests with `picked` still 0 in `observe`, and no
  `least_time` series for `off` either before or after the whole run. Measured 2026-10-20
  (`--passes 3 --levels 1,32`, `logs/bench_lt_full.txt` → `bench_least_time_full.json`, err=0 in every
  cell): the **cost is not resolvable** — at c=32 `observe` was +6.0% and `on` +7.6% against `off`, at
  c=1 −9.3% / −8.6%, and every one of those gaps is smaller than its own row's round-to-round spread
  (`off` alone spread 20% at c=32 and 49% at c=1). The honest statement is "nothing like the 7–22% the
  front-proxy egress row cost", not "free". The **benefit is well outside noise**: with backends at
  0/10/40 ms, `on` moved c=1 p50 from 11.55 ms to 0.83 ms (−92.8%) and throughput 55 → 233 req/s
  (+323%), c=32 p50 from 10.99 ms to 1.00 ms (−90.9%) with 1645 → 5753 req/s (+250%), spreads 1–6%;
  `observe` reproduced `off` there too (p50 within 0.05 ms, +0.2% / +1.1%), which is the traffic-level
  form of "observe changes nothing but the numbers it prints". Caveats that must travel with these
  numbers: p99 stays at the slow backend's latency (~41 ms) *by design*, because an unmeasured or
  4×-window-stale node scores negative and is re-explored instead of being starved; `on` does not
  reproduce the round-robin distribution (three equally-fast backends served 24 requests as 12/1/11),
  which is exactly why `observe` is the pre-flight tier; the single-node row is capped by one backend
  process (5.3k req/s at c=32 vs 12.6k for the 3-node `off` row) so it is a shape reference, never a
  cost baseline; and because both scenarios share one gateway process, the second scenario's
  pre-timing snapshot inherits EWMA values and counters from the first — read it as "still
  converging", not as a fresh-state measurement.
- `bench_proxy_split.py` costs the business-splitting branch with the same harness shape, and adds one
  row the earlier benches did not need: `conf/bench_proxy_split.conf` has seven `proxy_pass` locations
  (single-node pool, two-node pool with a literal target, **the same literal target plus two fixed-length
  upstream headers**, then split targets whose branches all point at that same pool, whose key comes from
  a header instead of a constant, whose two branches are two separate pools, and finally the same thing
  with `proxy_split_failover off`). The attribution row exists because a splitting location has to carry
  its two ownership headers for the script to see the branch at all — without that row, "cost of the
  split" would silently include "cost of writing two more headers upstream". `psLit`/`psA`/`psB` are all
  the same two Python backends, so whichever branch the ratio picks, the origins absorb exactly the load
  the literal row does, and a row-to-row gap can only be gateway code. Each cell self-proves: the three
  literal rows must show **zero** movement in both split counters over their timing windows, and the four
  splitting rows must show `routed` moving by precisely the request count with all of it landing on the
  branch the reference implementation predicts for that key. Two things this harness learned the hard
  way and now encodes: `-t` **only warns** about an unknown directive, so exit code 0 does not prove a
  build contains the feature (a stale binary happily passed `-t` and 502'd every split request — the
  script requires the splitting lines to appear in `-t`'s own output before it will use a binary), and
  the first timed round on this host is systematically faster than the rest, so one uncounted warm-up
  round runs before samples are taken (`--warmup-passes`, default 1). Measured 2026-10-20 **twice**, on
  a debug build first and then on a release build (`--passes 5 --levels 1,8,32 --warmup-passes 2`,
  `bench_proxy_split_20261020_full.json` then `bench_proxy_split_20261020_release.json`, err=0 in every
  cell of both): the **cost is not resolvable either time**. On the release build the full split path
  comes in at +2.2% (c=8) and +4.1% (c=32) against the no-splitting baseline row, while those same rows'
  own round-to-round spread is 4% and 7% — the gap never exceeds the noise it is measured against, so
  the honest statement is an upper bound (≲5%, and nothing like the 7–9% the front-proxy egress row
  cost), not a number. Every intermediate segment is smaller still (upstream headers +1.3/+2.8%,
  hash+buckets+ledger +1.7/+1.9%, key expansion −0.3/−0.5%, two real branch pools −0.5/−0.2%, the
  `off` policy line +1.7/−0.8%). The c=1 tier is unusable here (round spread 20–42%, and the sign of the
  difference flips between tiers). What *is* established both times: the feature is inert when not used
  (zero ledger movement on the literal rows, asserted over 16 000-request windows), and when used, the
  machinery runs on every request (`routed` delta == requests) without measurably moving throughput.
  The single-node row is again only a shape reference (6.5k req/s at c=32 against 10.9k for the two-node
  rows on the release build — one Python process is the cap, not the gateway).
- [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md) is the capability matrix with test evidence.
- [USR2_HOT_UPGRADE.md](USR2_HOT_UPGRADE.md) explains why nginx-style USR2 needs a process-model change,
  gives two designs (SO_REUSEPORT handover / master+worker FD inheritance), and a Linux test plan.
