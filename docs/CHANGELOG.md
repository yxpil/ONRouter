# Changelog

What changed in each 1.0.x release, and why it mattered in real traffic. The README is a front
page; this file is the detailed record. Per-row capability status and known gaps are in
[CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md).
## What's new in 1.0

- **CPU affinity**: `worker_threads N;` plus `worker_cpu_affinity auto|off|<hex masks>;`. Each tokio
  worker can be pinned to a core (or a set of cores); masks rotate across threads, and `-t` prints
  the per-thread plan before the process starts. Linux `sched_setaffinity`, Windows
  `SetThreadAffinityMask`; macOS has no hard thread affinity and says so. See
  [OPERATIONS.md §6](OPERATIONS.md#6-cpu-亲和性).
- **Resilience**: passive removal (`max_fails`/`fail_timeout`), `lazy_rejoin <interval>;` (a real
  user request doubles as the recovery probe, so no separate health-check traffic), and
  `circuit_breaker errors=… window=… open=…;` (closed → open → a single half-open probe), with
  `onrouter_upstream_{server_available,server_healthy,lazy_probes_total,circuit_state,circuit_trips_total}`.
- **Canary / grey release**: top-level `canary $var "<sticky key>" { cookie …; header …; arg …;
  ua ~* …; os …; percent …; default …; }` selects a whole declared upstream per request, first
  match wins. `$proxy_split` / `$proxy_split_served` and the per-branch ledger make a cross-version
  failover (`proxy_split_failover on|off|http://target`) visible instead of silent.
- **WASM gateway plugins**: `wasm_plugin <name> <file.wat|file.wasm> [fuel=…] [memory=…];` plugged
  into `access_by_wasm`, `header_filter_by_wasm` and `body_filter_by_wasm`. A small stable host ABI
  exposes request/response headers, status and body; traps and fuel exhaustion fail closed.
- **1.0.1 — cache and config semantics**:
  - `proxy_cache_path <dir> … disk=on` gives the response cache the
  same cold tier as `lua_shared_dict disk=`. What LRU pushes out of the `keys_zone` while it is still
  fresh is spilled to that directory (always async, one writer thread per zone, temp+rename), the next
  request for that key is served from the tier and promoted back into memory, and a restart rebuilds the
  index by scanning the tree. Off unless you write `disk=on` — a zone without it never creates the
  directory. A cold hit keeps the nginx vocabulary (`X-Cache-Status: HIT`) and adds
    `X-Cache-Tier: disk`; counts land in `onrouter_proxy_cache_disk_*`.
  - `proxy_cache_revalidate on;` asks the origin "still this one?" with the cached entry's own
    `ETag`/`Last-Modified` and replays the stored body on a 304 (`X-Cache-Status: REVALIDATED`) —
    no second transfer of an object nobody changed.
  - `return` / `rewrite` / `set` / `if` work at `server` level too (nginx's SERVER-rewrite phase,
    before location matching), so `server { return 301 https://$host$request_uri; }` — the plainest
    HTTPS-redirect vhost there is — stops being a line in `-t`'s ignored list and starts being a
    redirect. Server-level `set`/`rewrite` can therefore change *which* location answers.
- **1.0.2 — who a limit counts, response freshness, a datagram front door, and the request bodies
  h2/h3 were dropping**:
  - `limit_req_zone` / `limit_conn_zone` now key on **any request-phase variable** —
    `$http_x_api_key`, `$cookie_JSESSIONID`, `$arg_token`, `$uri`, `$host`, and concatenations like
    `$cookie_sid$remote_addr`. Behind a campus or corporate egress, `$remote_addr` counts a whole
    building as one client; the dimension is now the operator's choice. A request whose key expands
    to nothing is **not limited by that zone** (nginx's empty-key rule) instead of being merged into
    one anonymous bucket, and keys that cannot have a value at the deciding moment (`$status`,
    `$upstream_*`, `$sent_http_*`, `$request_body`, `$server_name`, anything made by `set`) stay
    `-t` errors — silently counting the wrong thing on a rate limiter is a policy inversion.
    `limit_conn` also became legal in `location`, **replacing** the server rule set rather than
    merging with it. Proven by `tools/limit_key_e2e.py` 35/35 with every request from one IP, so
    "different key ⇒ different bucket" is directly observable.
  - `expires` implemented across all nginx value forms (`off` / `epoch` / `max` / `@hh:mm:ss` /
    `+|-<time>` / bare text), at both `server` and `location`, on the static, proxied, cache-hit,
    `return` and already-flushed streaming-Lua paths; only the cacheable status set is rewritten, and
    a malformed time fails `-t` rather than shipping a site with no expiry headers at all.
    `tools/expires_e2e.py` 40/40.
  - **Four-layer UDP** (`listen <addr> udp;`, `proxy_responses <n>;`, `proxy_timeout`, plus an
    ONRouter-only `udp_max_sessions` ceiling): one session per client 4-tuple riding a socket
    *connected* to its backend, so cross-client reply delivery is impossible at the kernel level,
    and `proxy_responses 0` forwards heartbeats without ever opening a session or an fd.
    `tools/game_udp_e2e.py` 31/31 — 60 concurrent clients with zero cross-talk, 30k datagrams with
    the gateway's own accounting exact (`received = forwarded + dropped`, by reason) and nothing
    reaching the backend that the gateway did not forward; the delivery *rate* is a machine property,
    not a contract — ≈58k pps on an idle host, ≈14k pps inside a full regression, and a loaded
    loopback can drop datagrams before they ever enter the gateway, which is why the assertion is
    about accounting rather than about a magic percentage. Sessions
    reusing rather than respawning,
    TCP and UDP sharing one port number, and a capped-vs-uncapped control that measures the
    noisy-neighbour starvation instead of asserting it away.
  - Six silent-failure fixes, each with a case that would have caught it: a duplicated `Host:`
    header is now a 400 (RFC 9112) instead of silently using the first — which meant a client
    library's automatic `Host: 127.0.0.1:port` could route a request to a listener's **default
    vhost**; `$binary_remote_addr` expands instead of being left as a literal;
    `if ($http_x_api_key = "")` — the plainest way to say "this header is absent" — used to lose its
    empty right-hand side to paren stripping and fail `-t`, so a whole vhost could not start;
    `proxy_pass` with a URI part now does the **pure string replacement** nginx documents
    ("the part of a normalized request URI matching the location is replaced by a URI specified in
    the directive") — when the request path equals the location prefix exactly, nothing is appended,
    so `location /api/hot` + `proxy_pass …/api/hot` forwarded `/api/hot/` and the backend's exact
    route table saw a second resource while the cache key forked; an upstream that times out now
    returns **504**, not 502, matching nginx's own
    `ngx_http_upstream_next()` (`FT_TIMEOUT`/`FT_HTTP_504` → `GATEWAY_TIME_OUT`, everything else →
    `BAD_GATEWAY`) — with it, `max_fails` finally counts the attempts that actually switched nodes
    (403/404 excluded, also per nginx), so a node that only ever answers 503 stops being unkillable;
    and **HTTP/2 / HTTP/3 request bodies were being dropped**. The last one is the serious one: the
    gateway asked "is there a body?" from `Content-Length` / `Transfer-Encoding`, and framed
    protocols carry neither — a 64 KB POST over h2 or h3 reached the upstream as a POST with no body
    and no `Content-Length` (the gateway's own `ngx.req.get_body_data()` reported `nil`), so every
    API write on the site's main TLS transport silently lost its payload while HTTP/1.1 was fine.
    Framed protocols are now always read to stream-end (an empty stream costs one poll).
  - Business-shape suites added this round: `tools/course_selection_e2e.py` (2400 students at the
    moment enrollment opens — no oversell, and the origin's enroll count equals the gateway's
    admitted count exactly), `tools/flash_sale_e2e.py` 36/36 (flash sale: 1200 concurrent on one hot
    SKU reached the origin **exactly once** — and the suite now requires the origin's own hit counter
    and the gateway's `X-Cache: MISS` count to be the same number, which is how the trailing-slash bug
    above was caught; 400 concurrent fought over 50 seats with no oversell; a slow node's orders came
    back 504 with its four idempotency keys on that node and nowhere else, i.e. no non-idempotent POST
    was ever replayed to a second backend), `tools/herd_e2e.py` 18/18 (stampedes, including an expired
    entry served from the disk cold tier), `tools/production_shape_e2e.py` 529/529 (800-file static
    site + WASM over TLS + Lua in one process), `tools/quic_business_e2e.py` 41/41
    (the same site served over HTTP/1.1-TLS, HTTP/2-TLS and HTTP/3/QUIC on one port number:
    byte-identical statics, gzip that round-trips, Range/HEAD/conditional requests, one shared
    `proxy_cache` and one shared cookie-keyed limit bucket across all three transports, POST payloads
    checked by length *and* SHA at the origin, per-frame SSE delivery, 50 multiplexed h3 streams,
    abandoned h3 streams not poisoning the connection, and 504-vs-502 parity between transports).
  - Verified on the release binary: `cargo test --workspace` **500/500**, full regression
    `python run_regression.py reg_102_ship.txt` → **TOTAL 94 scripts, nonzero=0**
    (at that roll `random_scenarios_e2e.py` was still held out, with the reason written into
    `run_regression.py`'s `SKIP`; its TLS oracle has since been repaired and it is back —
    the roll is **95 scripts** with `SKIP` empty), and a 21-minute soak on the release binary
    (**2,275,361 requests, 0 failures**, private memory +0.49 MiB with slope +0.055 MiB/min against
    a 1.0 MiB/min gate, cold-tier accounts clean: `corrupt` 0 / `never_read` 0 / `pending_jobs` 0) as
    recorded in [OPERATIONS.md](OPERATIONS.md) §13.1, and `tools/release_verify.py` 26/26 against the **unpacked** `target/dist/archives/onrouter-v1.0.2-*.zip` (the artifact a user actually downloads, not the build tree's binary). CI's E2E job was widened in 1.0.2 from six suites to fourteen across three steps (functional contract, business shapes, HTTP/3+HTTPS transport parity), and is **fifteen** now: `https_matrix` joined the functional-contract step because it is the only suite that can tell "the fallback certificate follows config order" from "it follows `default_server`".

- **1.0.3 — the fallback certificate, six TLS-stack advisories closed, and a cold tier that no longer
  eats what it was told to demote**:
  - **The fallback certificate follows `default_server`.** On a TLS port carrying several vhosts, an
    unmatched or absent **SNI** presented whichever `server` block happened to be written *first*,
    instead of the block marked `default_server` as nginx does. Routing was always right, so nothing
    looked wrong from the HTTP side — the symptom is a client that typed a domain this edge doesn't
    serve getting *someone else's* certificate, and a config reorder silently changing which
    certificate answers. Fixed for both accounts (static certs and `ssl_certificate_by_lua*` scripts),
    proven by `router::tests::fallback_cert_follows_default_server_not_config_order` and by a new port
    group in `tools/https_matrix_e2e.py` (76/76): 18443 writes `default_server` **first**, where the
    two implementations are indistinguishable — which is exactly why this survived every earlier
    suite — and 18449 writes it **last**, the only shape that can tell them apart. The framed
    transports got their own multi-cert port: `tools/quic_business_e2e.py` **18156** hangs three
    certificates on one TCP+UDP port number and asserts over h2 (Node, `servername` split from
    `:authority`) and h3 (`orr-h3check` + `ORRH3_AUTHORITY`) that the certificate follows SNI while
    the vhost follows authority, including the unmatched-SNI case — where reverting the fix does not
    merely mismatch a fingerprint but fails the handshake outright with
    `certificate is only valid for DnsName("a.qbiz.test")` (58/58).
  - **Six vulnerabilities in the TLS stack, all closed.** `cargo audit` against 1.0.2's lockfile found
    `rustls 0.23.45` × 4 (RUSTSEC-2026-0346/0347/**0348**/0349 — 0348 lets a Brotli-compressed
    certificate allocate ~1 GiB *before* authentication, i.e. attacker-shaped input at a TLS edge;
    0349 lets an unauthenticated ServerHello downgrade later connections to classical key exchange),
    `rustls-webpki 0.103.15` (verification may accept distrusted intermediates) and
    `webpki-root-certs 1.0.9` (bundled roots trusted distrusted emSign intermediates). All six were
    patch-level inside the declared range → 0.23.46 / 0.103.16 / 1.0.10; re-audit reports **zero**,
    and the whole TLS suite family was re-run on the rebuilt binary (`https_matrix` 76/76,
    `tls_session` 45/45, `tls_protocols` 13/13, `tls_legacy` 12/12, `mtls_upstream` 11/11,
    `https_backend` 12/12, `protocol_matrix` 37/37, `quic_business` 58/58). What this is *not*: the
    Cranelift/Wasmtime advisories do not reach ONRouter — `Cargo.lock` has zero `cranelift*` entries
    and the plugin host is a bytecode interpreter with no code generation, so "compiler miscompiles
    guest memory ⇒ sandbox escape" has no path here (analysis in `SECURITY_AUDIT.md`).
  - **A refused cold-tier spill no longer destroys the value.** The cache governor's deep-sleep
    demotion removed a `lua_shared_dict` value from memory and then ignored `spill()`'s refusal (disk
    full, pending byte/job caps, writer channel closed) while still counting it as demoted — under
    cold-tier pressure, "demote" silently meant "delete". It now restores the entry, counts the
    refusal, and stops the pass to retry later
    (`shared_dict::tests::governor_demote_pass_keeps_values_the_cold_tier_refuses`).
  - **Test and CI infrastructure** — all of it previously "green on this host, red in CI": each TLS
    suite signs its own fixture (`tools/selfsigned.py`) instead of borrowing a neighbour's gitignored
    directory; suites that write into `logs/` create it; readiness probes survive a gateway that is
    still binding; the token-refill unit test no longer requires two checks inside one millisecond;
    and `random_scenarios_e2e` is back in the roll with a cert oracle that derives certificates from
    SNI (its probe had been sending `127.0.0.1` as the SNI) — 20 random topologies, 4122/4122. The
    regression is **95 scripts with an empty `SKIP` set**, and CI's E2E job is 15 suites in three
    steps, now including `https_matrix` because it is the only suite that can tell "fallback cert
    follows config order" from "follows `default_server`".
  - Verified on the 1.0.3 release binary: unit **502/502**, full regression **`TOTAL 95 scripts,
    nonzero=0`**, Linux CI green on unit+clippy and all three E2E steps, and a 21-minute soak —
    **2,161,682 requests, 0 failures**, private memory 18.71 → 20.02 MiB with a post-warmup slope of
    **+0.043 MiB/min** against a 1.0 MiB/min gate, and the cold tier churning throughout (79,254
    spills / 78,520 cold hits / 78,520 promotions) with `corrupt` 0, `never_read` 0,
    `pending_jobs` 0 and `spill_skipped` 0 (that last counter is new in 1.0.3 — a cold tier that
    refuses a spill is now visible instead of silent).

- **1.0.4 — post-quantum key exchange as a build option, visible handshake failures, and the
  framed-transport request target**:
  - **Inbound TLS can negotiate `X25519MLKEM768`** with `--features pq`. A CDN origin fetch that
    offered only post-quantum groups (`0x11ec`, `0xfe32`, `0x6399`) and no classical curve produced
    a 525 with an empty origin log; adding rustls' `aws_lc_rs` group fixes that case. ring still
    owns cipher suites, signing and the RNG, the new group is ordered last, and the option is off by
    default because `aws-lc-sys` is a C build. P-521 is not implemented by any rustls provider and
    is refused rather than silently ignored.
  - **Handshake failures are visible.** They log at `warn`, name the peer, carry SNI on
    `ssl_certificate_by_lua*` listeners, and increment
    `onrouter_tls_handshake_failures_total`. `tools/tls_hello_tap.py` decodes `supported_groups`
    from a live `:443` ClientHello over `AF_PACKET` without installing a sniffer.
  - **`$request_uri` on h2/h3 is `:path` plus the raw query**, not hyper's rebuilt absolute URI;
    the access log records the same value. `tools/http2_e2e.py` 14/14 covers h2c, TLS-h2 and an
    h1.1 control, including a `return 302 https://dest$request_uri` whose old h2 output was
    `https://desthttps://source/`.
  - **A `pq` build keeps HTTP/3 up.** `build_quic_server_config` now uses the same explicit
    CryptoProvider as TCP; the auto-detecting builder panicked when both ring and aws-lc were
    compiled in, and `tools/quic_business_e2e.py` 58/58 runs on the pq build.
  - Verified on the final pq build: unit **504/504**, full regression `reg_104_pq4.txt` →
    **TOTAL 96 scripts, nonzero=0** with `SKIP` empty, `tls_groups_e2e` 16/16 on both builds (the
    ML-KEM case is skipped on an OpenSSL 3.0 runner and measured against 3.5), and Linux CI green
    on unit+clippy, sixteen E2E suites and the pq build job. Published release archives remain
    `[pq=off]`; the `[pq=on]` Linux binary is built by CI as a workflow artifact.

- **Release engineering**: CI runs unit tests + clippy + sixteen real-traffic E2E suites in three
  steps (functional contract — `tls_groups` joined it, since a refused handshake is a production
  shape no other suite covers — business shapes, then the h1/h2/h3 transport-parity suite), with an
  optional `workflow_dispatch` 21-minute soak that checks private-memory growth. The 1.0 docs are
  [OPERATIONS.md](OPERATIONS.md) (run it in production) and
  [TUTORIAL.md](TUTORIAL.md) (build it feature by feature).
