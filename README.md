<p align="center">
  <img src="public/logo.png" alt="ONRouter logo" width="180">
</p>

# ONRouter (Rust)

> **ONRouter** (short **ORR**) — an OpenResty alternative written from scratch in Rust.

A Nginx / OpenResty-style gateway server **implemented from scratch in Rust**: reverse proxy, load
balancing (with passive health checks), rewrite, virtual hosts, an embedded Lua 5.4 scripting layer
(the `ngx.*` API), plus native Rust modules. Apart from foundational libraries such as tokio/hyper,
all gateway logic is hand-written.

## What's new in 1.0

- **CPU affinity**: `worker_threads N;` plus `worker_cpu_affinity auto|off|<hex masks>;`. Each tokio
  worker can be pinned to a core (or a set of cores); masks rotate across threads, and `-t` prints
  the per-thread plan before the process starts. Linux `sched_setaffinity`, Windows
  `SetThreadAffinityMask`; macOS has no hard thread affinity and says so. See
  [OPERATIONS.md §6](docs/OPERATIONS.md#6-cpu-亲和性).
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
- **Release engineering**: CI runs unit tests + clippy + five real-traffic E2E suites, with an
  optional `workflow_dispatch` 21-minute soak that checks private-memory growth. The 1.0 docs are
  [OPERATIONS.md](docs/OPERATIONS.md) (run it in production) and
  [TUTORIAL.md](docs/TUTORIAL.md) (build it feature by feature).

## Blocking analysis & static-path optimization (spawn_blocking + file cache)

- **Lua script file cache**: `LuaSource::File` used to read from disk synchronously on every request
  (`fs::read_to_string`), one of the largest blocking points. It is now a process-level cache
  (`OnceLock<RwLock<HashMap<PathBuf, Arc<str>>>>`) — each file is read once, on first request.
- **Static IO moved off workers**: the filesystem calls in the static-serving path (resolve / index /
  autoindex) are handed wholesale to `tokio::task::spawn_blocking` via an owned snapshot, so tokio
  worker threads are never blocked by disk IO; large-file body reads use `tokio::fs` chunked reads
  (which themselves run on the blocking pool per chunk).
- **error_page target files** are likewise read once to build the response, removing extra synchronous
  IO round-trips from the error-page hot path.
- Measured (32 concurrent keep-alive connections): static 4880 → 6715 req/s (+38%), Lua
  7867 → 9044 req/s (+15%).
- **Static file in-memory cache**: files ≤1 MB are held entirely in process memory (up to 512 entries),
  invalidated by (mtime, size). A cache hit costs zero disk reads and zero syscalls beyond a single
  `stat`; file edits are detected automatically. Cached bodies are `Bytes`, so a full-file hit and a
  `Range` slice served from cache are reference-counted, not copied.
- **Large/uncached files stream from disk**: files above the cache threshold (and `Range` windows that
  miss it) are no longer read into memory. `serve_static_flow` emits a chunked `DiskBody` that seeks
  once and reads 64 KiB per poll while the response is written, with an explicit `Content-Length` so
  keep-alive framing and `HEAD` stay exact; `HEAD` doesn't even open the file. `sub_filter` needs the
  whole body to rewrite it, so it buffers only when its MIME gate matches and only up to a hard
  8 MiB ceiling (`SUB_FILTER_MAX_BUFFER`); above that the file keeps streaming untouched and the
  skip is logged. Verified by `tools/static_stream_e2e.py`
  (19 checks: a 128 MB file served whole / by mid-file `Range` / suffix `Range` / `HEAD` / `304` /
  `416` with sha256 equality, a 2 MB file rewritten by `sub_filter` while its `Range` slice stays
  byte-exact, and a paused mid-download showing **0.6 MB RSS delta for a 128 MB file** versus the old
  whole-file buffer) + unit test `large_files_and_ranges_stream_from_disk`.

## Security

- **Path traversal protection**: RFC 3986 dot-segment normalization; `../` / `..%2f` / `%252e` /
  backslash / null-byte payloads are all blocked, and escaping the root returns 400 directly.
- **Request smuggling protection**: duplicate Content-Length / illegal CL / CL+TE together → 400;
  HTTP/1.1 missing Host → 400.
- **Unknown method** → 501; URL > 8 KB → 414; oversized headers → 431; oversized body → 413
  (rejected before the body is read).
- **Slow connections**: do not block normal requests (the tokio concurrency model is inherently
  resistant to single-connection Slowloris attacks). Streamed uploads (`proxy_request_buffering off`)
  are covered by `client_body_timeout` too — the limit is per inter-read interval, not total body time.
- **Fail-closed access control**: `auth_basic` without `auth_basic_user_file` denies (401) instead of
  serving, htpasswd entries with an empty hash are dropped (no empty-password login), an unparsable
  peer address denies rather than skips the `allow`/`deny` rules, and the htpasswd cache is bounded by
  a 1 s staleness limit on top of `(mtime, size)` invalidation so revoked credentials stop working even
  when a file is rebuilt with identical timestamps.
- **No front/back URI disagreement**: the Upgrade (WebSocket) tunnel forwards the client's raw,
  undecoded request target — routing/ACL decisions and what the backend parses are about the same URI.
- **Bounded blast radius**: `sub_filter` buffers at most 8 MiB per response (larger files stream
  unfiltered, with a warning), and Lua coroutines are preempted every `lua_slice_instructions`
  VM instructions (default 1 000 000) so a runaway loop can no longer stall the single process.
- **Still ONLine copies cannot carry a session**: the last-known-good replay layer has three hard
  rules with no configuration switch — a response containing `Set-Cookie` is never stored, a request
  carrying `Cookie`/`Authorization` never writes a copy (and by default is not served one either, so a
  shared copy can never be handed to a logged-in visitor as if it were theirs), and `Set-Cookie` is
  stripped from every replayed response. Only anonymous `GET` + 2xx responses enter the zone, and the
  background re-fetch after recovery is itself an anonymous request that goes through the normal ACL /
  `limit_req` / rewrite path.
- **CDN headers cannot move an identity**: every value `front_proxy` derives from a request header —
  client address, `$scheme`, country, visible host — is used only when the direct TCP peer falls inside a
  `trust` range the operator declared (or `set_real_ip_from`), so a client that copies a real provider's
  whole header set is left on the node address for `allow`/`deny`, `limit_req`, `geo`, VIP reputation, the
  access log and the cache key alike. Recognition alone only labels; a profile with no `probe` can never
  match; and promoting a profile's own ranges into a rewriting authority needs the explicit
  `front_proxy_auto_trust on`, which warns once per profile and names the vhost at `-t`. `Cache-Status` is
  likewise suppressed for unverified peers, so a hit rate a client could inflate is not a metric.
- Security tests: `sec_test.py` (30 checks, covering traversal / smuggling / CRLF injection /
  malformed requests / oversized requests / default response headers),
  `tools/security_matrix_e2e.py` (36 checks, one gateway process per probe, reproducing each finding
  from `docs/SECURITY_AUDIT.md` with real traffic — every probe fails on the pre-fix binary) and
  `tools/rce_matrix_e2e.py` (27 checks on the remote-execution surface: Lua-source/path injection,
  `internal` location escape, `proxy_pass` SSRF with a canary listener, encoded-CRLF request
  splitting; the backend used by these probes echoes the exact request line it received).

## Multi-core architecture

- **tokio multi-threaded runtime**: `worker_threads N;` (default = number of logical CPU cores).
  With `worker_cpu_affinity auto;` or explicit masks, each worker is pinned to its core; the
  default is `off`, so existing deployments keep the OS scheduler's placement. `-t` reports the
  per-thread plan and the startup log records each successful binding.
- **Lua VM pool**: one independent Lua VM per CPU core (mirroring OpenResty's one VM per worker).
  Multiple requests execute scripts fully in parallel with no global single-point lock;
  `init_by_lua` runs once per VM (matching nginx's once-per-worker initialization semantics).
- **Within-VM coroutine scheduler**: each VM is driven by a dedicated scheduler task that interleaves
  many in-flight requests as Lua coroutines — a request yields only at `ngx.sleep` and the VM lock is
  released between synchronous resume segments, so `ngx.timer` callbacks and sleep timers progress
  while other requests on the same VM run (OpenResty's single-worker C10K, not one-request-per-VM).
  Because there is only one process, a script that *never* yields is more damaging here than in
  multi-worker nginx — it parks that VM's tokio worker outright. So every resume arms a Lua count hook
  (`lua_slice_instructions`, default 1 000 000 VM instructions ≈ 10 ms) that yields the coroutine back
  to the scheduler; after 8 consecutive slices the scheduler leaves its lock/await loop. A runaway
  `while true do end` then degrades to "one core busy, its own request never finishes" instead of
  taking the whole gateway down with it.
- **Low-concurrency fast path (no scheduler hop for the common case)**: when the target VM lock is
  free, the request task compiles/resumes the first Lua segment inline; scripts that never yield
  finish without ever touching the scheduler task. On the first yield the coroutine is handed to the
  scheduler (`Job::Adopt`) and resumed there like any other request. A shared per-VM chunk cache keeps
  compilation single-flight. Exposed as `onrouter_lua_phase_{inline,adopted,scheduled}_total`; real
  traffic shows 100/100 inline for a no-yield script and 50/50 adopt for `ngx.sleep`.
- **16-shard ngx.shared.DICT**: sharded by key hash, each shard with its own lock, so multi-core
  concurrent reads/writes never block each other.
- **Optional DICT disk cold tier**: hot data stays in the sharded memory map, eviction victims that are
  warm enough spill to disk and are promoted back on the next read, so a small `lua_shared_dict` can
  cache far more than its memory size. Three disciplines keep it off the request path: writes are
  always handed to one background writer thread per store, the cold index is in memory so a true miss
  costs zero disk I/O, and capacity trimming is a coalesced job on that writer thread rather than work
  inside `set()`.
- **Lock-free hot paths**: round-robin cursor / node health state / VM selection are all atomic.
- **Async access log**: a dedicated writer thread + buffered batch flush; the request hot path does
  only one lock-free enqueue.
- **proxy_next_upstream**: nginx token semantics — `error`, `timeout`, `invalid_header`, `http_XXX`,
  `non_idempotent`, `off`, plus `proxy_next_upstream_tries` / `_timeout` budgets. Connection-level
  failures retry even for non-idempotent requests (nothing was sent yet); once bytes hit the wire only
  idempotent methods (or an explicit `non_idempotent`) retry, and streamed request bodies are never
  replayed. When the retry budget/node list is exhausted the last upstream response is returned as-is.
- **TCP_NODELAY**: Nagle disabled by default on all inbound connections.

## Feature map

| Nginx / OpenResty | ONRouter (Rust) | Location |
|---|---|---|
| master/worker event loop | tokio async runtime + hyper HTTP/1 | `server.rs` |
| nginx.conf syntax | custom lexer + recursive-descent parser, incl. `include <file \| glob>` (with unit tests) | `crates/onrouter-config` |
| `upstream` + load balancing | weighted round-robin / `least_conn` / `ip_hash` (with connection tracking) | `upstream.rs` |
| passive health checks `max_fails` / `fail_timeout` | failure counting + node removal + expiry recovery (falls back to full set when all are down) | `upstream.rs` |
| `least_time off\|observe\|on` adaptive selection (ONRouter-only) | picks the backend that is **actually answering faster**, from two signals the gateway can measure itself (no backend-supplied load header): P2C — draw two candidates, take the lower `score = (in-flight/weight + 1) × latency-EWMA`, so a momentarily-fast node is never swarmed the way an argmin would herd it — over a time-decayed EWMA of the observed response-header time (`least_time_window`, default 5 s; convergence time is in wall-clock seconds and therefore independent of QPS, whereas nginx's `least_time` — a Plus feature, no source in this repo to check against — smooths by response count, so its memory length moves with traffic). Samples come only from requests that got a response header: a connect failure or read timeout costs "as long as the timeout", which says nothing about how fast that backend is, so it never enters the EWMA and is handled by `max_fails` instead. A node with no sample (or one older than 4× the window) scores negative — i.e. "unknown" — and is therefore explored, which is how a new backend gets traffic and how a backend that quietly got fast again proves it, instead of being starved by a stale estimate forever. Rollout is deliberately staged: `off` (default) writes no atomics and emits no metric lines, `observe` measures and publishes per-node EWMA plus a `would_differ` count while the **selection sequence stays identical to `off`** (unit-tested, E2E-asserted), and only `on` lets the score choose. `least_time` with `ip_hash` is a `-t` error (the hash already decides), a single-node pool is a warning; changing an `upstream {}` block needs a restart because the pool is built once. Measured on this host: **no resolvable per-request cost** against the default tier (the gap is smaller than its own round-to-round spread) and **−92.8% p50** when the backends genuinely differ in speed — see Benchmarks | `upstream.rs`, `proxy.rs`, `metrics.rs`, `tools/least_time_e2e.py`, `bench_least_time.py` |
| `proxy_pass` reverse proxy | hyper connection pool, `proxy_set_header` variable interpolation, prefix replacement | `proxy.rs` |
| `resolver` + async DNS | pure-Rust non-blocking UDP stub resolver (A/AAAA, RFC1035 + compression pointers), `valid=` TTL cache | `dns.rs` |
| `proxy_cache` response caching | in-memory named zones sized from `keys_zone` with LRU eviction, `proxy_cache_valid`/key/methods/min_uses, `proxy_cache_lock` coalescing, `use_stale` (error/timeout/updating/http_xxx), `proxy_cache_bypass`/`proxy_no_cache` (multi-value, nginx truthiness: a value counts only when non-empty and not `"0"`), `proxy_ignore_headers`, upstream `Cache-Control`/`Expires` precedence, `X-Cache-Status` + `$upstream_cache_status` | `proxy_cache.rs` |
| `proxy_pass https://` / `wss://` backends | pure-Rust rustls client over one pooled `Service<Uri>` connector shared with http backends; `proxy_ssl_verify`/`_trusted_certificate`/`_name`/`_server_name` + `proxy_ssl_certificate`/`_certificate_key` (mTLS client cert), TLS policy incl. client cert in the pool key | `proxy_tls.rs`, `proxy.rs` |
| `Still ONLine` last-known-good replay | separate **byte-budgeted** zones (`still_online_zone <name> <size>;`) opened per server/location with `still_online <zone>;` (`off` stops inheritance); only anonymous `GET` + 2xx responses without `Set-Cookie` are stored (`still_online_max_body`), retained copies replay as `200` + `X-Still-Online: stale` + `Age` + `$still_online` when the origin is unreachable **or** answers 5xx, until `still_online_max_age` expires them; recovery-triggered anonymous re-fetch runs through the normal request path (so `rewrite`/location/`limit_req`/ACL apply) with single-flight + exponential backoff (`still_online_retry`/`_retry_max`/`_retry_deadline`). Credential hard rules, with **no switch to turn them off**: `Set-Cookie` is never stored and never replayed, a request carrying `Cookie`/`Authorization` never writes a copy, and by default never reads one either — `still_online_allow_credentials on` only opens the *read* side | `still_online.rs`, `server.rs`, `router.rs` |
| `rewrite ... last/break/redirect/permanent` | regex engine + `$1..$9` back-references | `engine.rs` |
| `set $var <value>;` + `if (cond) { … }` | REWRITE-phase subset executed **in config order** (nginx-like): `set` writes request-scoped variables (and may shadow a built-in for that request), `if` supports `$var` truthiness / `!$var`, and `=`, `!=`, `~`, `~*`, `!~`, `!~*` against a `$var` or literal RHS; the block may contain `rewrite`/`set`/`return`, nested `if` is rejected at parse time, file tests (`-f`/`-d`/`-e`/`-x`) fail with an explicit message instead of being ignored. Deliberate divergence: a `return` recorded inside `if` runs **after** the ACCESS phase, so it can never preempt `allow`/`deny`/`auth_basic` (nginx's `return` is a rewrite-phase directive and does) | `engine.rs`, `router.rs`, `server.rs` |
| `add_header` / `proxy_set_header` / cache-key variable semantics | every value surface interpolates through one resolver (`engine::resolve_var`): known variables take their value, a known-but-currently-valueless one (`$arg_missing`, `$cookie_missing`, `$upstream_cache_status` on a POST) expands to **empty**, and a name that is not an nginx variable at all keeps its literal so a typo stays visible in the response. `$host` strips the port (bracketed IPv6 kept intact), `$http_host` returns the raw header; both Lua `ngx.var`, `add_header` and cache keys share the one resolver | `proxy.rs`, `engine.rs` |
| `map $src $dst { … }` derived variables | exact/`~`/`~*`/capture-group cases + `default`, shared resolver for `ngx.var` + config interpolation | `engine.rs`, `router.rs` |
| `geo [$src] $dst { … }` IP-derived variables | longest-prefix CIDR match (IPv4+IPv6), host `/32`, networks, `default`, same shared resolver | `engine.rs`, `router.rs` |
| `split_clients <key> $dst { … }` weighted-derived variables | MurmurHash2 over an interpolated key template, `%` buckets (fractional allowed) + `*` catch-all, same shared resolver | `engine.rs`, `router.rs` |
| `proxy_pass http://$split_var` + `proxy_split_failover on\|off\|http://target` — business traffic splitting by a declared ratio (the ratio and the sticky key are nginx's; the failover policy and the per-branch ledger are ONRouter-only) | the split's bucket value is the **host part** of `proxy_pass`, so a branch is a whole service/version release, not a node: `30%` of the traffic goes to that release's pool and that pool's own `least_conn`/`ip_hash`/`max_fails`/`keepalive` still choose inside it. Every branch must be enumerable at `-t` time — a declared `upstream` name or a `host:port` — and a bare name with no such pool is the runtime error `no split branch`, never a DNS guess (`resolver` cannot know which release a hostname is). **Host-position variables that are not produced by `split_clients`** (`set`/`map`/`geo`, or `$http_*`/`$arg_*` straight off the request) get no ratio and no cross-branch failover, and whatever they interpolate to must be a target this config declares — a pool name, a literal `proxy_pass` host, a branch, a `proxy_split_failover` target — otherwise the request is refused before any socket is opened (`undeclared proxy_pass target`, TCP and `Upgrade` alike): the client never gets to choose where the gateway connects, see the SSRF entry in `docs/SECURITY_AUDIT.md`. **The one non-negotiable boundary:** a cross-branch re-route happens only at the moment *no node of that branch has been handed the request yet* (branch name unknown, bucket value empty, or every node inside `fail_timeout`). A backend `5xx` never re-routes — otherwise one `POST` would be written into two business versions — and a TCP refusal after an address was already picked belongs to that branch (`502`, `routed+1`, `bled 0`). `on` (default) falls to the next declared branch in declaration order and counts it as `bled` rather than hiding it; `off` returns the failure as the branch produced it (grey experiments, non-replayable writes); `http://target` touches only the named branch, which must be one of the declared ones — and `0%` is the way to declare a branch that the ratio can never select but failover can (a negative weight is a `-t` error). The sticky key is the operator's business signal: `${remote_addr}` alone behind a CDN or NAT collapses the entire site onto one branch, so the shipped example keys on `${cookie_sid}${http_x_user_bucket}`. Attribution is two variables and two counters: `$proxy_split` is the branch the ratio chose, `$proxy_split_served` the branch that actually took the request (they differ ⇒ a bleed happened; on a cache `HIT` the first is set and the second is empty, because nothing was handed to any node), `onrouter_proxy_split_targets_total{split,target}` is a *forwarding* count (divide it by the branch total to check the observed ratio against the declared one) and `onrouter_proxy_split_total{split,role=routed\|bled\|down\|empty}` is the outcome ledger. Cache keys contain `$proxy_host`, which is the interpolated target, so each version gets its own cache entry set and can never read another version's stored body. Measured on this host: the literal-`proxy_pass` rows show **zero** ledger movement (asserted per timing window, not inferred from reading the code), the split rows are proved to run on every request (`routed` delta == request count), and the per-request cost of the machinery is **not resolvable** on this machine, on either build — on the release build the whole path is +2.2%/+4.1% against the no-split row at c=8/c=32 while those rows' own round-to-round spread is 4%/7%, so what this host can defend is an upper bound (≲5%), not a number — see Benchmarks | `engine.rs`, `router.rs`, `proxy.rs`, `metrics.rs`, `tools/proxy_split_e2e.py`, `tools/proxy_split_examples_e2e.py`, `tools/proxy_split_business_e2e.py`, `bench_proxy_split.py` |
| `sub_filter <m> <r>;` response rewrite | literal + `~`/`~*` regex match, `&` back-reference in the replacement, `sub_filter_once`/`sub_filter_types`, applied on buffered proxy/cache/static/Lua bodies | `engine.rs`, `server.rs`, `router.rs` |
| `set_real_ip_from` + `real_ip_header`/`real_ip_recursive` | realip module: trust the client IP from a header only when the direct peer is in a trusted CIDR, XFF chain right-most (off) / recursive-trusted-skip (on); overrides `$remote_addr` before geo/limit/auth | `realip.rs`, `router.rs`, `server.rs` |
| `proxy_redirect` + `proxy_cookie_domain`/`proxy_cookie_path` | rewrite upstream `Location`/`Refresh` (literal prefix, `~regex` with captures, or `default` = origin→location-prefix relative form) and `Set-Cookie` `domain=`/`path=` (literal/regex, `none` deletes, path prefix-preserving); applied on both proxy seams (streaming + buffered), multi `Set-Cookie` preserved | `resp_rewrite.rs`, `router.rs`, `server.rs` |
| `stream { server { … } }` L4 proxy + `ssl_preread` | byte-transparent TCP tunnel (no TLS termination, no protocol parsing); optional `ssl_preread` peeks the first TLS record and parses SNI from the ClientHello (a self-contained offset-walk, best-effort: non-TLS/incomplete/no-SNI still wires to the default), routing by `sni_match <name> <target>` (exact or `*.suffix` single-label wildcard; target = named `upstream` reusing the L7 pool, or a literal `host:port`), falling back to `proxy_pass`; peeked bytes are replayed to the backend so the handshake is untouched; tunnels share the process-wide `worker_connections` budget and metrics with HTTP, hold an upstream guard (`max_conns`/passive health) for the whole tunnel, and stop/drain via `shutdown_grace` (listener closed first) | `stream.rs`, `router.rs`, `main.rs` |
| `proxy_read_timeout` / `_connect_timeout` / `_send_timeout` | per-chunk response idle, connect, and idle-write watchdog (ms precision; `0` disables); `proxy_next_upstream` tokens + `_tries` / `_timeout` | `router.rs`, `proxy.rs`, `proxy_tls.rs` |
| `location =` / prefix / `~` regex | exact > regex > longest prefix | `router.rs` |
| `listen <port> ssl` + `ssl_certificate` | rustls TLS (HTTPS endpoints; multiple `listen` directives coexist) | `server.rs` |
| Multi-certificate SNI vhosts | several `server` blocks share one `listen … ssl` port, each with its own cert; ClientHello `server_name` selects exact > `*.suffix` wildcard > default (first) cert, while request routing still follows `Host` (they may intentionally differ); verified by `tools/https_matrix_e2e.py` | `certs.rs`, `router.rs` |
| `ssl_protocols TLSv1..TLSv1.3` | explicit enabled-version set (rustls serves the 1.2/1.3 subset by default); `--features native-tls` routes a legacy-needing listener to the OS stack (Windows Schannel) to truly negotiate TLS 1.0/1.1 | `certs.rs`, `tls.rs`, `router.rs` |
| `ssl_session_cache` / `ssl_session_tickets` | process-wide session resumption shared by every TLS listener (all SNI vhosts and ports): `off` / `builtin[:n]` / `shared:name:size` with approximate LRU eviction, plus rustls `Ticketer` for stateless TLS1.3 tickets (`ssl_session_tickets on/off`, default on). Verified across two ports with `openssl -sess_out/-sess_in` and Python `session_reused` | `certs.rs`, `router.rs`, `tools/tls_session_e2e.py` |
| `ssl_certificate_by_lua*` | per-SNI handshake script runs before certificate selection: `ngx.ssl.server_name()`, `ngx.ssl.parse_pem_cert` / `parse_pem_priv_key`, `ngx.ssl.set_cert` / `set_priv_key` / `clear_certs`, plus the `certificate` / `priv_key` legacy aliases; dynamic configs cached by cert+key hash. A handshake script error or `ngx.exit(ngx.ERROR)` aborts the handshake; `_file` form supported | `certs.rs`, `tls.rs`, `lua_engine.rs`, `tools/ssl_cert_lua_e2e.py` |
| HTTP/2 serving (`http2 on;` + `listen … http2`) | TLS h2 via ALPN; cleartext h2c prior-knowledge via 24-byte preface sniff (MSG_PEEK, non-consuming) so h1/h2c share one listener; hyper multiplexed streams | `server.rs`, `router.rs` |
| `SIGHUP` graceful config reload | in-process hot swap of the routing table behind `RwLock<Arc<Router>>`; listeners never rebound (no accept gap), per-request snapshot, invalid config keeps old; portable `reload <interval>;` mtime poll | `server.rs`, `main.rs` |
| `init_by_lua*` / `init_worker_by_lua*` / `lua_package_path` | `init_by_lua*` once per VM at startup; `init_worker_by_lua*` (inline and `_file`) once per VM after its scheduler is live, so timers/cosockets/`ngx.sleep` work; startup aborts non-zero on script errors. `lua_package_path` supports `$prefix`/`${prefix}` and OpenResty's `;;` default-path semantics, repeatable directives joined with `;`, applied before init scripts | `lua_engine.rs`, `main.rs`, `tools/init_worker_package_e2e.py` |
| HTTP/3 serving (`listen … quic`) | quinn QUIC endpoint (UDP) + h3 over it, TLS1.3/ALPN `h3` reusing the SNI cert store; same body-agnostic request core as h1/h2 (vhost/location/rewrite/access/proxy/lua); TCP-TLS on the same port serves h1/h2 and advertises `Alt-Svc: h3=":port"` | `server.rs`, `certs.rs`, `router.rs` |
| `ngx_lua` scripting layer | mlua (Lua 5.4), see the Lua API list below | `lua_engine.rs` |
| `lua_slice_instructions <n>;` | ONRouter-only cooperative preemption quantum: every coroutine resume arms a Lua count hook that yields back to the VM scheduler after `n` VM instructions (default 1 000 000 ≈ 10 ms of pure Lua; `0` disables). Bounds how long one script can hold a VM/tokio worker, so a runaway loop no longer blackouts the single process. Normal request scripts never reach a slice, so measured Lua throughput is unchanged (12.9k → 13.3k req/s within noise) | `lua_engine.rs`, `tools/security_matrix_e2e.py` |
| `lua_shared_dict` / `ngx.shared.DICT` | full OpenResty method surface: `get`/`get_stale`/`get_plus`/`get2`, `set`/`safe_set`/`force_set`/`set_auto`, `add`/`force_add`/`replace`, `incr`/`decr`/`bump`, `delete`/`flush_all`/`flush_expired`, `ttl`/`key_present`/`size`/`len`/`num`/`capacity`/`free_space`/`get_keys`/`expire` (true multi-value returns) | `shared_dict.rs`, `lua_engine.rs` |
| `lua_shared_dict … disk=` cold tier (ONRouter-only) | optional second tier per zone: eviction victims whose access frequency passes `spill_after` are written to `disk=` (always async, one writer thread per store, temp+rename), everything else is dropped. A cold hit reads the entry back and promotes it into memory, so **one key lives in exactly one tier at a time**. Cold index is in memory, so a true miss costs zero disk I/O; `num()`/`size()`/`get_keys()`/`ttl()`/`delete()` see both tiers while `capacity()`/`free_space()` stay memory-only. Restart rebuilds the index by scanning the directory (no index file). `max_disk=` caps the tier, `max_value=` skips oversized blobs, and a corrupt/truncated entry file is counted and dropped, never a panic | `disk_cache.rs`, `shared_dict.rs`, `tools/disk_cache_e2e.py` |
| `Learning` subsystem: one shared byte budget (ONRouter-only) | `learning on;` master switch (**default off** — with it off every learning path below short-circuits and behavior is identical to a build without it) plus one process-wide ledger `learning_memory_budget <size>;` (default 1 MiB, clamped to 8 KiB…16 MiB). Every learned structure — cache frequency sketch, burst-shape table, reputation table — claims from and releases back into this one ledger, so "the models fit in a tiny amount of memory" is a number the operator sets rather than something the gateway grows into. A claim that does not fit is refused, counted (`onrouter_learning_budget_denied_total`), written to the log, and that feature falls back to its configured unlearned behavior — never a silent partial table | `learning.rs`, `metrics.rs` |
| `proxy_cache_learning` TinyLFU admission + eviction (ONRouter-only) | `proxy_cache_learning <zone> [sketch=<size>];` (default 256 KiB per zone, minimum 8 KiB): a 4-row × 4-bit count-min sketch (estimate = min over rows, aging = whole table halved once every counter has been written on average) sits in front of `proxy_cache`. A newcomer is admitted only when its estimate beats the coldest of the `8` oldest entries, so one-shot URLs can no longer flush a hot object; when a newcomer does win, the eviction inside that window is by frequency, not by pure LRU. Weighted writes still advance the aging clock, so a saturating scanner cannot freeze the sketch's memory of the old hot set | `learning.rs`, `proxy_cache.rs` |
| `limit_req_queue` bounded waiting + `limit_req_learning` burst-shape learning (ONRouter-only) | `limit_req_queue <zone> [depth=10] [depth_min=1] [max_delay=5s];` makes an over-rate request wait instead of 429, up to `depth` concurrent waiters per key (the token is reserved at admit time, so a request that got a slot is never refused after waiting; `depth` is hard-capped at 4096). `limit_req_learning <zone> [table=<size>];` (default 64 KiB, 12 B per key, direct-mapped) then lets each key's own history choose its depth inside `[depth_min, depth]`: it records the length of **finished** bursts (a gap over `gap_cap` = 2× the token period, clamped 20 ms…1 s, ends one), and a burst that reaches `depth × 4` without ever ending is classified as a flood and wipes the memory — so a deep queue is never a buffer for an attacker, and the ceiling is still whatever the operator wrote | `limit.rs` |
| `vip_learning` client reputation → queue priority + cache retention (ONRouter-only) | `vip_learning [table=<size>] [min=24] [decay=30s];` (default 64 KiB, 12 B per key). Fed only by `limit_req` verdicts, never by headers or business signals: in-rate `+1`, queued `0` (already over rate — not a merit), rejected `−8`, minus one more point per `decay` of silence, so an address that keeps coming back *within* rate crosses `min` and one that goes quiet or misbehaves falls back. Reputation buys exactly two things: while trusted, that key's queue opens to the configured `depth` ceiling instead of the learned floor — **the rate is untouched**, the same bucket still releases tokens one at a time — and objects it causes to be cached get a `+4` sketch boost, which buys *retention*, never a jump past admission. A promoted client that starts flooding loses the status through the same 429s | `vip.rs`, `limit.rs`, `proxy_cache.rs` |
| `front_proxy` profiles + `front_proxy_mode off/detect/egress` (ONRouter-only) | know a CDN/LB sits in front **without naming the vendor**: each front is declared as config data (`front_proxy <name> { probe <hdr> [~ substr]; ip_header <hdr>; country_header/proto_header/host_header <hdr>; trust <cidr>; }`) and the engine only sees roles, so adding a provider is a config edit, never a code change. Recognition is never trust: a probe match only labels, and **every** header-derived value requires the direct TCP peer to fall inside `trust` ∪ `set_real_ip_from` — otherwise the request keeps the node address (a client that guesses a vendor header cannot move `$remote_addr`, `$scheme` or the cache key). `detect` labels (`$front_proxy`) and counts; `egress` additionally repoints `$remote_addr`/`limit_req`/`geo`/ACL/`access_log`/VIP reputation at the true client, restores `$scheme` from the declared protocol header, forwards the real client + protocol upstream, and emits `Cache-Status: onrouter; detail=hit\|miss\|stale\|bypass\|proxy-revalidated` (RFC 9209) on buffered cached responses so the CDN can measure its own hit rate. `front_proxy_auto_trust on` is the one explicit way to promote a profile's own `trust` ranges into a rewrite authority root (loud one-shot warning + `-t` naming the vhost); a mode typo, `egress` with no trusted range at all, and `auto_trust` outside `egress` are `-t` **errors**, not warnings | `front_proxy.rs`, `router.rs`, `server.rs` |
| `access_log` combined format | local file + stdout; `$remote_addr` is captured after realip, so logs show the real client, not the trusted proxy; each line also carries `$request_time` and the `$upstream_addr` / `$upstream_status` / `$upstream_header_time` triple (`- - -` when no upstream was contacted; Upgrade tunnels log the `101` peer); a full async queue drops and counts lines instead of blocking request tasks | `access_log.rs` |
| third-party C modules | `content_by_rust` / `access_by_rust` compile-time registered Rust handlers | `engine.rs` |
| `stub_status` / Prometheus scraping | process-global runtime metrics (accepted/active/capacity + requests + 2xx/3xx/4xx/5xx) plus per-upstream node connections/health/success/failure, cache-status counters, TLS handshake failures, limit_req/limit_conn rejections and dropped access-log lines, rendered as Prometheus text via `content_by_rust metrics` | `metrics.rs` |
| `allow` / `deny` | ACCESS-phase IP ACL: IPv4/IPv6/CIDR/`all`, ordered first-match-wins (default allow), location inherits server rules | `access.rs` |
| `auth_basic` / `auth_basic_user_file` | HTTP Basic auth in ACCESS phase; htpasswd supports plaintext, `{SHA}` (SHA-1), `$1$`/`$apr1$` (MD5-crypt), realm tri-state incl. `off`. Fail closed: a realm with no user file denies, empty-hash entries are dropped, and the file cache invalidates on `(mtime, size)` **or** after 1 s of age, so a rewritten credential file takes effect even with preserved timestamps | `access.rs` |
| `schedule_window <name> { tz/open/close }` + `schedule_access <name>;` — calendar-gated access (ONRouter-only) | a window is a pair of Vixie crons (`min hour dom mon dow`, with `*/n`, ranges, lists, month/weekday names, `@daily`-style aliases); **the state is derived from the calendar, never remembered** — `open ⟺ the last open firing is newer than the last close firing`, so a gateway that starts mid-window, a hot reload and a clock jump all land on the same answer with nothing persisted. A trigger does not imply a flip (`0 0 29 2 *` opened, then a `0 0 1 3 *` close firing every March 1 leaves the state as it was), so the runner re-evaluates at every real minute boundary instead of toggling: a late wake costs at most one minute of judgement and can never skip a whole window. Zones are `UTC` or a fixed `±HH:MM` only — an IANA name is refused at `-t` because no tz database is vendored, which also means DST-following is explicitly given up, not silently approximate. The gate runs in the ACCESS phase **after** `allow`/`deny` (the IP allowlist stays the operator's escape hatch during closed hours) and **before** `auth_basic`; a `location` wins over the `server`, and a window that is merely *unreferenced* is a `-t` warning, not a failure. Requests for a name this process has no instance of pass and count `onrouter_schedule_gate_miss_total` (the only way to reach it is a window added by reload, and blocking live traffic there is worse than letting it through) while a typo is a `-t` **error**, together with a missing `tz`/`close`, a duplicate name, an open/close pair that can fire in the same minute (that instant has no criterion for "open or closed"), a name that would break a Prometheus label, and more than 64 windows. With no window declared the runner task is never spawned and the request path pays one `Option` check. `onrouter_schedule_open/_next_fire_ms/_changes_total/_denied_total` plus a `-t` line per window (computed wall-clock open/close in the window's own zone) exist so an operator can check the gateway's arithmetic against their own calendar | `schedule.rs`, `router.rs`, `server.rs`, `main.rs`, `metrics.rs`, `tools/schedule_e2e.py` |
| `cache_governor off\|observe\|auto;` + `cache_governor_low/high/hold/tier/learn/lead` — traffic-phase sleep/boost (ONRouter-only) | one process-wide phase machine (`sleep` / `normal` / `boost`) fed by a 32-slot per-second request ring; the trailing **8 whole seconds** are the estimate, so the partial second under measurement never enters it. Entry and exit are separated by hysteresis (`high` needs two consecutive 500 ms ticks; boost exits below `0.8 × high`; sleep exits above `1.5 × low`) plus a `hold` dwell that makes flapping impossible in a jittery rps curve. `auto` light sleep only stretches the background sweep from 60 s to 600 s (cheap, reversible, no data movement); **deep** sleep additionally demotes: shared-dict entries whose zone declares `disk=` are force-spilled past `spill_after` (bounded passes per tick, so a long sleep stays responsive) and `proxy_cache` zones evict least-recently-used entries (reconstructible from the origin). A shared-dict zone **without** `disk=` is never touched — it is Lua application state, and sleep must not mean data loss; a deep tier with no `disk=` zone at all is a `-t` warning. Demotions are recorded in a bounded ring, and boost pulls a bounded batch back through the transparent cold path while restoring the 60 s cadence. `learn on` keeps one EWMA slot per minute of day (1440 × u16 ≈ 2.9 KiB, **memory-only**, folded at most once per natural minute) and may pre-switch to boost `lead` seconds before a learned busy slot; a predicted boost holds `hold` and exits to `normal`, never straight to `sleep`. **Default off** (directive absent): no task, no allocation, no metric series; the request path pays one relaxed `AtomicBool` load while enabled and one `fetch_add` per request. Hot reload swaps the whole family in place (off leaves the task idle; on starts it). `-t` rejects `low >= high` and `learn` without a live mode, and warns on observe+learn and deep-without-`disk=` | `governor.rs`, `shared_dict.rs`, `proxy_cache.rs`, `main.rs`, `server.rs`, `metrics.rs`, `tools/governor_e2e.py` |
| nginx syntax compatibility | `location =/\^~/~/~*`, server_name wildcards, error_page, try_files, index, autoindex, alias, client_max_body_size, return URL shorthand | |

## Directory layout

```
rust/
├── conf/onrouter.conf        # example gateway config (full-feature demo)
├── conf/tutorial_hello.conf  # 1.0 tutorial: minimal static/return config
├── conf/tutorial_full.conf   # 1.0 tutorial: proxy + resilience + cache + canary + WASM + Lua
├── docs/OPERATIONS.md        # operations manual (process, capacity, release, rollback)
├── docs/TUTORIAL.md          # step-by-step tutorial
├── lua/                     # Lua business scripts (auth.lua / time.lua / rewrite_mark.lua)
├── public/                  # static file root (includes logo.png)
└── crates/
    ├── onrouter-config/      # Nginx-style config parser
    └── onrouter-server/      # server main program
        └── src/
            ├── main.rs      # startup: config -> router -> upstream -> lua -> listen
            ├── router.rs    # server/location matching (= / prefix / ~ regex), directive model
            ├── upstream.rs  # upstream pool + 3 load-balancing methods + passive health checks
            ├── proxy.rs     # reverse proxy engine (reports failures to health checks)
            ├── engine.rs    # rewrite/return engine + native Rust handler registry
            ├── shared_dict.rs # ngx.shared.DICT shared dict
            ├── disk_cache.rs  # DICT disk cold tier (async writer thread, hash-named entry files)
            ├── limit.rs     # limit_req/limit_conn token buckets + bounded queue + burst-shape learning
            ├── proxy_cache.rs # proxy_cache zones: LRU + TinyLFU admission/eviction
            ├── learning.rs  # learning master switch, frequency sketch, process-level byte ledger, directive parsing
            ├── vip.rs       # client reputation table (limit verdicts in, queue ceiling + cache retention out)
            ├── front_proxy.rs # vendor-free CDN/LB profiles: probes, header dialects, trust gate, Cache-Status
            ├── lua_engine.rs# Lua VM + ngx.* API
            ├── wasm.rs      # WASM plugin host: ABI, fuel/memory bounds, 3 phases
            ├── affinity.rs  # worker_cpu_affinity plan + per-thread pinning
            ├── access_log.rs# combined access log
            ├── stream.rs    # L4 stream{} proxy + ssl_preread SNI routing (byte-transparent TCP)
            └── server.rs    # HTTP pipeline: rewrite -> access -> content -> log
```

## Running

```bash
# Option 1: run directly with cargo (debug)
cargo run -- conf/onrouter.conf
# Option 2: packaged exe (release)
cargo build --release
target\release\onrouter.exe conf\onrouter.conf

# start two demo backends (either way):
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1

# config test (also the place to see which directives were accepted and which were ignored)
target\release\onrouter.exe -t conf\onrouter.conf

# 1.0 tutorial: two tiny backends + the complete example (gateway on 127.0.0.1:18600)
python tools/tutorial_backend.py a 18601
python tools/tutorial_backend.py b 18602
target\release\onrouter.exe -t conf\tutorial_full.conf
target\release\onrouter.exe -c conf\tutorial_full.conf
```

See [docs/TUTORIAL.md](docs/TUTORIAL.md) for the walkthrough and
[docs/OPERATIONS.md](docs/OPERATIONS.md) for production operation.

`-t` validates listeners, certificates and limit references, then prints `配置测试通过。` **and every
startup warning line** (`告警 N 条：` followed by one bullet each — e.g. an unknown directive that was
ignored, or a server-level `return`/`rewrite`/`set`/`if` that is not supported there). Exit code stays
`0` for ignored directives, so read the printed warnings, not just the exit code.

### HTTPS / certificates

```bash
# generate a self-signed cert (SAN: localhost, 127.0.0.1; custom domains also supported)
cargo run --bin orr-gencert -- certs/cert.pem certs/key.pem your.domain.com
```

Config:

```nginx
server {
    listen 8080;              # HTTP
    listen 8443 ssl;          # HTTPS (a single server block may carry multiple listen directives)
    ssl_certificate     "certs/cert.pem";
    ssl_certificate_key "certs/key.pem";
}
```

The example config ships an 8443 HTTPS endpoint (a self-signed cert is already generated under
`certs/`) and is verified end-to-end: TLS handshake, Lua, reverse proxy, shared dict, and POST bodies
all work correctly over HTTPS. Replace with a CA-issued certificate in production.

Verified routes (28 smoke checks, full HTTP + HTTPS coverage):

| Route | Function |
|---|---|
| `GET /proxy/` | reverse proxy + upstream round-robin (backend-1/2 alternating) |
| `GET /hello` | inline `content_by_lua` script |
| `GET /api/time` | `rewrite_by_lua_file` + `content_by_lua_file` + async `ngx.sleep` |
| `GET /api/protected` | `access_by_lua` auth: no token 401 / wrong token 403 / correct 200 |
| `GET /count` | `ngx.shared.DICT` atomic counter (accumulates across requests) |
| `GET /go` | `ngx.redirect` 302 (Location header) |
| `GET /inner` | `ngx.exec` internal redirect → /hello (transparent to the client) |
| `GET /api/tools` | `ngx.re` regex capture / escape_uri / unescape_uri / body read |
| `GET /old/thing` | `rewrite last` → /new/thing (internal redirect) |
| `GET /health`, `/jump` | `return` 200 / 301 |
| `GET /user/42` | regex location |
| `GET /api/info` | `content_by_rust` native module |
| `GET /static/` | static files; unknown path → 404 |

## Lua API (aligned with ngx.*)

- Response: `ngx.say / print / status (read-write) / exit / flush([wait]) / send_headers() / eof() / headers_sent /
  header["X"]=v (read+write via metatable) / header.set / resp.get_headers()`
  — `ngx.flush` switches the response to streaming: head + buffered body go out immediately
  (h1 chunked / h2 DATA), later writes keep streaming; without an explicit flush the first 64 KiB
  does the same automatically. `ngx.send_headers()` flushes the status line + headers while staying
  streaming, `ngx.eof()` ends the stream early and drops any later `ngx.say` output, and
  `ngx.headers_sent` reports whether the head is already on the wire. `ngx.header["Set-Cookie"]`
  accepts a table to emit repeated header lines (and reads back as a table when repeated). A location
  with response filters (`header_filter_by_lua` / `body_filter_by_lua`) stays buffered by design,
  since filters need the whole response.
  Verified by `tools/lua_flush_socket_e2e.py` (23 checks incl. early-first-byte timing, h1 keepalive
  reuse after a chunked response, h2 DATA frames, `limit_conn` accounting, and `log_by_lua`) and
  `tools/api_compat_e2e.py` (send_headers/eof/headers_sent and multi-value Set-Cookie).
- Request: `ngx.req.get_method / set_method / get_path / get_query / get_headers / set_header(name, value | array | nil) / set_raw_header / clear_header / get_uri_args / set_uri / set_uri_args / read_body / get_body_data / set_body_data / discard_body / init_body / append_body / finish_body / get_body_file / get_post_args / raw_header([full]) / start_time() / http_version() / is_internal()` —
  `set_header`/`clear_header` mutate the live inbound request headers, so a rewrite/access-phase change
  is carried all the way to the proxied backend. `init_body`/`append_body`/`finish_body` build a new
  request body from scratch (streamed chunks committed as the new `Content-Length`); the built body
  also overrides what `proxy_pass` forwards. `start_time()` / `http_version()` / `is_internal()` expose
  the request timestamp, the HTTP version (1.0/1.1/2.0), and whether this is an internal subrequest.
- Request body reader: `ngx.req.socket([raw])` → `receive(size?) / receiveuntil(delim, opts?) / close()`
  — reads the already-buffered request body in order, with OpenResty's `nil, err, partial` convention;
  `receiveuntil` defaults to trimming the delimiter and its iterator can be called repeatedly.
  Verified by `tools/lua_flush_socket_e2e.py` (raw body bytes, delimiter boundaries, inclusive mode).
- Control: `ngx.redirect(uri, code?) / ngx.exec(uri) / ngx.exit / ngx.sleep(secs) (async coroutine, seconds unit aligned with OpenResty)`
- Cosocket: `ngx.socket.tcp()` → `connect / send / receive(*l | *a | n) / receiveany(min,max) /
  receiveuntil(delim) / shutdown(read?,write?) / settimeout / setsize / setkeepalive(timeout,pool) /
  tlshandshake(opts) / reconnect / close / getstats` — non-blocking TCP, every op yields to the VM
  scheduler so concurrent requests
  interleave on one VM (mirrors ngx_lua's cosocket yield-and-resume model). `setkeepalive`
  returns the idle connection to a process-global pool keyed by `host:port`, and a later `connect`
  to the same peer reuses it (skip the handshake, second return `"reused"`). `tlshandshake` upgrades
  the stream to a rustls client TLS connection (`CosStream::Plain`→`CosStream::Tls`), after which
  every receive variant runs over the encrypted stream. `sslhandshake` is an alias of `tlshandshake`,
  and `getreusedtimes()` returns `1` after a pooled connection was reused (`0` on a fresh socket).
  Verified by `tools/sock_ext_e2e.py` / `tools/sock_tls_e2e.py` / `tools/api_compat_e2e.py` against
  real TCP and TLS backends.
- UDP: `ngx.socket.udp()` → `setpeername / send / receive(max) / settimeout / close` — connected-UDP
  datagram I/O on the same scheduler yield path; verified by `tools/sock_udp_e2e.py`.
- Regex: `ngx.re.match(s, pat, flags?) / find / gmatch(s, pat, flags?)→iterator / sub(s, pat, repl, flags?) /
  gsub(s, pat, repl, flags?) / opt(pat, flags?)→reusable compiled handle` — flags support `i s m`
  (ignorecase / dotall / multiline); `sub`/`gsub` accept a replacement string (`$0`/`$1`/`${name}`
  expansion) or a callback function and return `new_subject, count`; `gmatch` returns a capture object with
  `[0]` whole match, `[N]` groups and named groups; `opt`'s handle avoids recompiling on the hot path.
- Encoding: `ngx.encode_base64 / decode_base64 / escape_uri / unescape_uri / decode_args / encode_args`
- Shared memory: `ngx.shared.<zone>:get / get_stale / set / safe_set / add / replace / delete / incr / ttl / flush_all / get_keys(max?) / expire(key, ttl)`
  — the Lua surface is unchanged by the optional disk tier; it is configured purely by directives:

  ```nginx
  lua_shared_dict tier 24k disk=cache/tier max_disk=4m levels=1:2 inactive=10m spill_after=2 max_value=2k;
  ```

  `disk=` turns on the cold tier for that zone (path resolved like every other relative path: against
  `-p <prefix>`, else against the config file's directory; **write the path bare** — these `k=v`
  arguments are taken literally, so `disk="cache/tier"` tries to create a directory whose name includes
  the quote characters). Eviction then splits by frequency: a victim
  whose self-decaying access count reaches `spill_after` (default 3) is written to disk, anything colder
  is dropped as before. `max_value=` (default 64 KiB) keeps big blobs out of the tier, `max_disk=` caps
  it, `levels=` shapes the directory tree nginx-style (≤3 levels, hex digits), `inactive=` (default off)
  lets the background sweep also retire entries nobody has read in that long. Writes are 100% async (one writer thread per store, temp+rename), so an entry that was just
  evicted becomes visible on disk a moment later — the request path never waits for it. Each zone needs
  its own directory; two zones sharing one `disk=` is rejected at config load, because entry files are
  named only by key hash and one zone's `delete` would erase the other's data. Gauges and counters are
  exported as `onrouter_dict_disk_*` on `/metrics` per zone. Verified by `tools/disk_cache_e2e.py`
  (53 checks on real traffic, incl. spill/promote counts, byte ledger, restart rebuild, truncated
  entry files, 20-way concurrency, cold-read vs true-miss latency, and path-traversal keys).
- Background timers: `ngx.timer.at(delay_sec, cb, ...) / ngx.timer.every(interval_sec, cb, ...) / running_count() / pending_count()`
  — seconds unit, `premature` as the callback's first argument, user varargs forwarded verbatim,
  failures return `(nil, err)`, `return false` stops the interval (semantics aligned with official t/106/152/107)
- Response filters: `header_filter_by_lua*` (mutate response headers / status before sending),
  `body_filter_by_lua*` (rewrite the response body via `ngx.arg[1]` chunk, `ngx.arg[2]` eof) — these now
  run on **both** the `content_by_lua`/static path **and** the `proxy_pass` return path: a proxied response
  is buffered, its status/headers/body loaded into the request context, the filters applied, then a
  buffered response is emitted (matching nginx, where response filters cover upstream responses; the cost
  is disabling streaming for that location, like `proxy_buffering off` vs filters). Verified by
  `tools/proxy_filter_e2e.py` (10 checks: `body_filter_by_lua` uppercases a proxied backend body while
  upstream `X-Backend` is preserved and Content-Length recomputed; `header_filter_by_lua` sets `ngx.status`
  203 and rewrites `content-type`; both filters compose) + unit tests
  `body_filter_lua_transforms_chunk` / `header_filter_lua_sets_status_and_headers`.
- Log phase: `log_by_lua` / `log_by_lua_file` (runs after the response is formed, reads the final
  `ngx.status` incl. 5xx and request info; its `ngx.say` writes go to a throwaway copy so they can't
  alter the already-built response — verified by `tools/log_by_lua_e2e.py`)
- Constants: `ngx.OK / ngx.ERROR`, log levels `ngx.STDERR/EMERG/ALERT/CRIT/ERR/WARN/NOTICE/INFO/DEBUG`
  (OpenResty's numeric values, recognized by `ngx.log`), and the common `ngx.HTTP_*` status codes
- cosocket: `ngx.socket.tcp()` with `connect/send/receive(*l|*a|n)/settimeout/close` — ops run in
  tokio tasks (no VM lock held) and yield to the scheduler, so many socket-bound requests share one
  VM concurrently; partial-data + timeout semantics mirror ngx_lua (`nil, err, partial`)
- Subrequests: `ngx.location.capture(uri, opts?)` → `{ status, body, header }` (`opts.method`, `opts.body`,
  `opts.args`) — runs the *full* pipeline for the captured location (rewrite → access → content: static /
  `return` / `proxy_pass` / nested Lua all work) as an internal subrequest against the same vhost, then
  yields to the VM scheduler (like the cosocket ops) so the parent coroutine and other in-flight requests
  keep progressing; nested captures are supported with a depth guard (`status = 0` on overflow, mirroring
  ngx_lua's error sentinel), and `ngx.is_subrequest` is true inside. `ngx.location.capture_multi({{uri,
  opts}, …})` runs several captures concurrently as light threads (four 0.2 s subrequests finish in
  ~0.2 s, not 0.8 s) and returns one `{status, body, header}` per entry. Verified by
  `tools/subrequest_e2e.py` and `tools/api_compat_e2e.py`.
- Light threads: `ngx.thread.spawn(func, ...) / ngx.thread.wait(thread...) / ngx.thread.yield() /
  ngx.thread.kill(thread)` — spawned threads are first-class coroutines on
  the same VM scheduler (they share the parent request's `ngx.ctx` and interleave real `ngx.sleep` /
  cosocket I/O, not OS threads). `wait` returns on whichever awaited thread finishes *first* (any
  completion wakes the parked parent), forwarding that thread's return values on success
  (`ok, ret…`) or `(false, err)` when the thread errors or is killed; `yield` gives other coroutines a
  scheduling turn; killing a thread drops its in-flight sleep/socket op. The request terminating reaps
  any still-running children (mirrors ngx_lua). Verified by `tools/thread_e2e.py` (24 checks, incl. a
  wall-clock proof that 4 concurrent 0.4 s sleeps finish in ≪ 1.6 s and that two yielding threads
  interleave `ABABAB`). `ngx.semaphore` (`new(n) / count() / post(n) / wait(timeout?)`) is implemented
  on the same scheduler coroutines as the official API: `wait` yields without blocking the VM, `post`
  wakes a waiter, `timeout` returns `nil, "timeout"` and `0` polls non-blocking; it is per-VM (each VM
  owns its own Lua state, so a semaphore is not shared across VMs). `ngx.on_abort(handler)` additionally
  accepts and stores a per-request abort callback (API-compatible); the disconnect-driven *invocation*
  hook is not yet wired to the server's connection-liveness path and is on the roadmap.
- Balancer phase: `balancer_by_lua` / `balancer_by_lua_file` + `ngx.balancer`
  (`set_current_peer(host, port) / get_current_peer() / set_timeouts(connect_ms, send_ms, read_ms) /
  set_more_failures({failures,return_code,escalate}) / recreate_request(bool?)`) — the phase runs just
  before `proxy_pass` forwarding, reading the request via `ngx.req.get_uri_args()` / `ngx.req.get_headers()`
  and, on `set_current_peer`, routing the connection to the Lua-selected `host:port` *instead of* the
  upstream's load balancer (so Lua drives dynamic peer selection / service discovery). `set_timeouts`
  overrides the location's connect/send/read timeouts for that hop, and the read value also bounds the
  idle timeout of a WebSocket tunnel opened to the selected peer. All five functions return OpenResty's
  `true` / `nil, err` convention; `set_current_peer('')` and negative timeouts reject. Tradeoff vs
  ngx_lua: the balancer runs once per request (not once per retry attempt), so a Lua-chosen peer is a
  single hop without in-upstream failover, and the `ngx.balancer.set_upstream_*` override APIs remain
  (though the `$upstream_addr / $upstream_status / $upstream_header_time` log variables are now
  recorded by the proxy path — see "Upstream metrics"). The balancer phase also runs before Upgrade
  handshakes, so WebSocket peers are selected the same way. Verified by `tools/balancer_e2e.py`
  (17 checks: a `proxy_pass` to a dead upstream 502s on its own but the balancer re-routes it to live
  backends; query- and header-driven A/B selection; `set_timeouts` cutting a 3 s backend down to a
  ~0.4 s 502 and aborting an 8 MB upload to a non-reading sink after 300 ms; a WebSocket 101 + tunnel
  echo that only succeed through the balancer-selected peer; a shared-dict counter giving an exact
  5/5 round-robin split of real traffic). Engine-level unit test `balancer_lua_phase_stashes_peer_on_ctx`.
- Others: `ngx.ctx (per-request table) / ngx.time / ngx.now / ngx.log / ngx.config.* / ngx.version`
- Variables: `ngx.var` (metatable-backed nginx variables read off the live request) — `$uri /
  $request_uri / $args / $query_string / $is_args / $method→request_method / $scheme / $host /
  $remote_addr / $remote_port / $server_addr / $server_port / $hostname / $content_type /
  $content_length / $status / $body_bytes_sent / $request_length / $request_body / $request_time /
  $msec / $time_local / $time_iso8601 / $https / $realip_remote_addr (the direct TCP peer, i.e. the
  node address before any realip/front_proxy rewrite — kept for audit on every request) /
  $front_proxy (name of the recognised CDN profile, empty when none) / $front_proxy_verified (`1`
  only when that peer fell in a trusted range, else empty) / $front_proxy_country / $front_proxy_host
  (`$host` is the request name **without** the port,
  `[::1]:8080` → `[::1]`, while `$http_host` returns the raw header), `$arg_<name> / $cookie_<name> /
  $http_<name> (request header) / $sent_http_<name> (response header) / $proxy_add_x_forwarded_for /
  $upstream_addr / $upstream_status / $upstream_header_time(≡$upstream_response_time) /
  $upstream_cache_status (empty string when the request never engaged the cache, e.g. a POST)`, all returned
  as strings with `nil` for undefined vars (OpenResty semantics). `$uri` (rewrites the path) and
  `$status` are writable; read-only vars ignore assignment. Verified by `tools/ngxvar_e2e.py` (19
  checks: live request metadata, `$http_x_test` header echo, undefined→nil, `$uri` write-then-read,
  `$status=418` producing a real 418 response) + unit test `ngx_var_reads_and_writes`, plus the
  `arg_/cookie_/request_time/msec/time_*` cases in `tools/api_compat_e2e.py`.
- Derived variables — the nginx `map` directive. Top-level `map <source> <dest> { … }` blocks build a
  process-wide table (installed on every `Router::build`/hot-reload). Reads funnel through a single
  `engine::resolve_variable` so a `$dest` resolves identically in **both** `ngx.var.<dest>` (Lua) and
  config-string interpolation (`proxy_set_header … $dest;`). Cases follow nginx precedence: all exact
  matches first (incl. the `""` empty-string branch), then `~regex` / `~*case-insensitive regex` in
  order, then `default`. Regex results may reference capture groups (`$1…$9`, `${name}`). Sources may
  be request headers (`$http_*`), built-ins (`$scheme`, `$host`, …) or another mapped variable
  (cycle-guarded). Verified by `tools/map_e2e.py` (15 checks across the exact / `~*` / capture /
  empty-string / default / built-in-source / undefined→nil cases, each exercised through Lua *and*
  the proxied `proxy_set_header` path against a header-echo backend) + unit tests `match_map_*`,
  `parse_maps_all_forms`, and `quoted_token_can_start_a_statement` (parser now accepts a quoted
  directive name, which `map`'s `""` / quoted patterns require).
- Derived variables — the nginx `geo` directive. Top-level `geo [$source] $dest { … }` matches the
  source variable's IP against a table of CIDR networks and returns the **longest-prefix**
  (most-specific) hit's value, else `default`. Both IPv4 and IPv6 are supported (a v4 target never
  matches a v6 rule); a bare address is `/32` / `/128`. The source may be omitted (`geo $dest`
  defaults to `$remote_addr`) or be any IP-valued variable (`$http_x_forwarded_for`, `$arg_ip`, …).
  Rules are pre-sorted by prefix length at config-parse time. Because it shares `engine::resolve_variable`
  with `map`, a geo `$dest` resolves identically in `ngx.var.<dest>` and in config strings like
  `proxy_set_header … $dest;`. Verified by `tools/geo_e2e.py` (11 checks: host `/32`, wide `/8`, a
  more-specific `/16` beating it via longest-prefix, a second network, `default`, and the omitted-source
  `$remote_addr` form — each through Lua and the proxied `proxy_set_header` path against a header-echo
  backend) + unit tests `geo_*` and `parse_geos_*`.
- Derived variables — the nginx `split_clients` directive. Top-level `split_clients <key> $dest { … }`
  hashes an interpolated key template (e.g. `"${remote_addr}${http_user_agent}"`) with nginx's
  MurmurHash2 and maps the value into weighted percentage buckets, with a `*` catch-all taking the
  remaining share. Weights may be fractional (`0.5%`) and are accumulated in declaration order; the
  chosen bucket is the first whose cumulative upper bound exceeds `hash % 10000`, giving two-decimal
  resolution. The key template's variables are resolved through the same `engine::resolve_variable`
  seam, so a split `$dest` is derived identically in `ngx.var.<dest>` and in config strings like
  `proxy_set_header … $dest;`, and selection is stable for a given key across the whole fleet.
  Verified by `tools/split_clients_e2e.py` (9 checks: per-key determinism, an independently-ported
  MurmurHash2 reference confirming both the Lua-read and proxy-interpolation paths land the exact same
  bucket for fixed keys, a 1200-request distribution giving ~25/25/25/25 and ~10%-with-`*`-catch-all
  splits, and cross-path agreement) + unit tests `murmur_hash2_*`, `pick_split_bucket_*`,
  `expand_split_key_*` and `parse_splits_*`.
- Business traffic splitting — the same directive pointed at *services* instead of strings, by letting
  `proxy_pass` take a variable in its host position: `split_clients <key> $app { 5% v2; * v1; }` plus
  `location / { proxy_pass http://$app/; }`. Copy `conf/proxy_split_examples.conf`; it is the reviewed
  shape and it runs. The rules an operator has to know, all of them proved with real traffic by
  `tools/proxy_split_e2e.py`, `tools/proxy_split_examples_e2e.py` and the day-of-traffic model in
  `tools/proxy_split_business_e2e.py`:
  - **A branch is a pool.** The bucket value is the host part of `proxy_pass`, so `5%` means "5% of the
    requests go to that release"; node choice inside that release stays whatever that `upstream`
    declares. The E2E sends 1200 distinct keys through a 3-way split and separately counts the two nodes
    *inside* the winning pool, so "splitting is pool-level" is a measured statement, not a claim.
  - **The default tier re-routes.** If the branch the ratio chose currently has no selectable node, `on`
    hands the request to the next declared branch and counts it as `bled`. That is exactly what you do
    *not* want for a grey release or a non-replayable write: declare `proxy_split_failover off;` there
    and the failure reaches the client unchanged (E2E: four requests, four `502`s, the stable branch's
    backend counter and metrics do not move by one).
  - **A backend `5xx` never crosses branches, and a refused connection is not "this branch is empty".**
    Both belong to the branch that already took the request (one `500`-only pool sits in a split in the
    E2E config and is asserted to bleed nothing). Re-routing only happens before any node is handed
    anything, because otherwise a `POST` would be written twice, into two business versions.
  - **Choose the sticky key like a business key.** `${remote_addr}` behind a CDN or a corporate NAT puts
    every visitor in the same bucket, i.e. the whole site silently lands on one branch; the example keys
    on `${cookie_sid}${http_x_user_bucket}`. A key that expands to empty is a legitimate sticky key (all
    traffic one branch), not an error — check the observed ratio, below.
  - **Branch targets are enumerated at `-t`, never guessed.** Each must be a declared `upstream` name or
    `host:port`; a name that is not a pool is `no split branch` at request time, and a branch containing
    `/`, a space or a `$` is a `-t` error. `0%` is legal and means "this branch is only ever reached by
    failover" — that is how you declare a hotfix as a fallback without giving it any ratio; a negative
    weight is refused.
  - **A variable in the host position may only name a target the config already wrote down.** Keep the host
    as a whole segment (`http://$backend`) or `-t` refuses it; `$backend` may come from `split_clients`,
    `set`, `map` or `geo` — the last three get no ratio and no cross-branch failover, and they are also the
    ones a client can influence directly (`proxy_pass http://$http_x_target/`). So the resolved value is
    checked against the set of targets this config *declares* — a `upstream` name, a literal `proxy_pass`
    host, a `split_clients` branch, a `proxy_split_failover` target — and anything else is refused before a
    socket is opened (502, `undeclared proxy_pass target` in the error log, TCP and `Upgrade` alike).
    That keeps `map $http_x_env $backend` picking between declared pools working, and takes away the
    "gateway connects where the request says" primitive; measured by `tools/rce_matrix_e2e.py` R3 with a
    canary listener (header- and query-controlled host → 502 and zero canary accepts, declared-pool
    control group → 200).
  - **Every request is attributable.** `$proxy_split` = the branch the ratio chose, `$proxy_split_served`
    = the branch that took it; unequal means a bleed happened, and on a cache `HIT` the first is filled
    while the second is empty. Check the declared ratio against reality with
    `onrouter_proxy_split_targets_total{split,target}` (a *forwarding* count) and the outcome ledger
    `onrouter_proxy_split_total{split,role="routed|bled|down|empty"}`. Because the cache key contains
    `$proxy_host` — the interpolated target — each version has its own entries and cannot read another
    version's cached body (E2E: `MISS`→`HIT` per branch, and the other version still `MISS`).
  - Not using it costs nothing: the literal `proxy_pass` rows in the benchmark assert zero movement in
    both split counters over their timing windows, and the machinery's own per-request cost was not
    resolvable on this host (see Benchmarks).
- REWRITE-phase conditionals — the nginx `set` and `if` directives, plus `rewrite`/`return`, now parsed
  into one ordered step list per location (`loc.rewrite_steps`) and executed **in the order written**,
  exactly like nginx. `set $name <value…>;` writes a request-scoped variable — the value is interpolated
  (`set $who anon-$arg_who;`), the last write wins, and `set` may deliberately shadow a built-in for that
  request (`set $uri /not-real-uri;`). `if (<cond>) { … }` supports bare truthiness `if ($v)` /
  `if (!$v)` (only an empty expansion is false — `"0"` is *true* here, unlike `proxy_cache_bypass`
  where `"0"` is false, matching nginx in both places) and the string operators `=`, `!=`, `~`,
  `~*`, `!~`, `!~*`, whose right-hand side may itself be a variable and is interpolated before comparing;
  the block may hold `rewrite`, `set` or `return`. Nested `if` and the file tests `-f`/`-d`/`-e`/`-x` are
  rejected at config-parse time with a message naming what to use instead — they are never silently
  dropped, and `if` without its `{ }` block is a hard parse error. Two deliberate divergences from nginx:
  (1) a `return` recorded inside an `if` block is applied at the *same* point as a bare `return`, i.e.
  **after** the ACCESS phase, so `if (…) { return …; }` can never preempt `allow`/`deny`/`auth_basic`
  (in nginx `return` is a rewrite-module directive and does run first) — a fail-safe ordering, since a
  conditionally-ignored ACL is worse than a conditionally-late response; (2) `server`-level `return` /
  `rewrite` / `set` / `if` are not supported and now emit an explicit "已被忽略" warning naming the line,
  instead of the previous silent fail-open where they parsed as known directives and did nothing.
  Verified by `tools/set_if_e2e.py` (26 checks on real traffic: `set` ordering and interpolation,
  built-in shadowing, `if`-gated `set`, each operator incl. case-insensitive regex and negation, POST-only
  branch, `rewrite … break` stopping the rest of the sequence, `last` re-matching the location, and
  `/acl` proving an `if`-block `return` cannot bypass `allow`/`deny`) + unit tests `set_writes_request_var_*`,
  `if_conds_follow_nginx_truthiness_*`, `if_gates_inner_set_then_return`, `recorded_return_stops_the_rest_*`,
  `if_and_set_reject_unsupported_forms_at_parse_time`, `server_level_rewrite_directives_warn_instead_of_failing_open`.
- Response rewrite — the nginx `sub_filter` output filter. `sub_filter <match> <replacement>;`
  (repeatable) substitutes into the buffered response body; the match may be a literal string or a
  `~regex` / `~*case-insensitive regex`, and the replacement expands `&` to the just-matched text
  (`\&`, `\\` escape). `sub_filter_once on|off` (default `on` = replace only the first occurrence)
  and `sub_filter_types …` (default `text/html`; `*`/`all` or a `type/*` wildcard accepted) gate it.
  It runs as a pure `engine::apply_sub_filter` over three output seams — buffered proxy/cache
  responses (`build_buffered_response`), static files (`serve_static_flow`, complete bodies only:
  a `Range`/206 slice is left byte-exact, matching nginx), and `content_by_lua` / `return` bodies
  (`finish_response`). Declaring `sub_filter` in a proxied location forces the response to buffer
  (the same streaming tradeoff as `body_filter_by_lua`); non-UTF-8 bodies are never touched. Verified
  by `tools/sub_filter_e2e.py` (8 checks: literal multi-replacement, `sub_filter_once` first-only,
  regex + `&` back-reference, `application/json` left alone under the default `text/html` gate, the
  `content_by_lua` path, a static file fully rewritten, and the same file's `Range` slice kept
  un-rewritten) + unit tests `sub_filter_*` and `parse_sub_filter_directives`.
  On the static seam only the served `[start, start+len)` window is read from disk, and a body larger
  than `SUB_FILTER_MAX_BUFFER` (8 MiB) is streamed **un-rewritten** with a warning: nginx streams the
  substitution with a small tail window, we buffer, so the buffer has to be capped (a single
  `sub_filter` line must not turn a large file into a per-request memory amplification). Verified by
  `tools/security_matrix_e2e.py` probe `s6`.
- Real client IP — the nginx `ngx_http_realip_module` (`realip.rs`). Behind a CDN or load balancer the
  socket peer is the proxy, not the visitor; `set_real_ip_from <ip>|<cidr>` (repeatable) lists the
  **trusted proxy** ranges, `real_ip_header <name>` (default `X-Real-IP`; e.g. `X-Forwarded-For`, or
  Cloudflare's `CF-Connecting-IP`) names the header to trust, and `real_ip_recursive on|off` (default
  `off`) decides how a comma-separated chain is reduced: off takes the right-most address, on scans
  right-to-left and returns the first address that is *not* itself trusted. The rewrite is applied only
  when the **direct peer** is trusted (so a client cannot forge the header) and it overwrites
  `ctx.remote_addr` **before** every downstream consumer, so `$remote_addr`, `$binary_remote_addr`,
  `geo`, `limit_req`/`limit_conn`, `allow`/`deny` and `access_log` all key off the real client. The
  access-log record is created at request entry but its remote field is updated right after realip
  (both the normal and `Upgrade` paths), so the combined-log first column is the rewritten IP. Verified
  by `tools/real_ip_e2e.py` (14 checks across four server blocks that turn the always-`127.0.0.1` test
  peer into trusted vs untrusted cases: X-Real-IP rewrite, the anti-forgery no-rewrite on an untrusted
  peer, the same `X-Forwarded-For` value yielding the right-most proxy address under `recursive off` vs
  the true client under `recursive on`, a `geo $net` derived variable tracking the rewritten IP through
  each case, and the on-disk access-log line starting with `203.0.113.9` for the trusted case) + pure
  unit tests in `realip.rs` and router tests `parse_real_ip_directives_into_server`.
- Front-proxy / CDN awareness — ONRouter-only, and **vendor-free by construction** (`front_proxy.rs`).
  Nothing in the engine knows what a Cloudflare, Fastly or EdgeOne header is: each front in front of the
  gateway is *declared* as a profile of roles, so supporting a new provider — or a second CDN in front of
  the first — is a config edit, never a code path. A profile names how it is recognised (`probe <header>`
  [ `~ <substring>` ], all probes must appear and match: AND), where the true client lives (`ip_header
  <header>`, repeatable, tried in declaration order as a fallback chain), and which optional headers carry
  the visitor country, the original scheme and the public host:

  ```nginx
  front_proxy demo-edge {
      probe X-Demo-Edge-Id ~ edge;   # evidence: header present AND value contains the substring
      probe X-Demo-Edge-Ray;
      ip_header X-Demo-Real-Client;  # preferred: the front's own capability header
      ip_header X-Forwarded-For;     # fallback: the generic chain, tried in this order
      country_header X-Demo-Edge-Country;
      proto_header   X-Demo-Edge-Visitor;
      host_header    X-Forwarded-Host;
      trust 203.0.113.0/24;          # this front's node ranges = the authority root
  }
  server { front_proxy_mode egress; front_proxy_auto_trust on; }
  ```

  The hard rule, with no switch: **recognition is not trust**. A probe match only *labels* the request;
  every value that comes out of a header (address, scheme, country, host) is used only if the **direct TCP
  peer** falls inside `trust` ∪ `set_real_ip_from`. Peer not in range → the request keeps the node address
  and the real scheme, and `$front_proxy` still names the profile that was recognised (that asymmetry is
  the point: the label is a metric, the rewrite is a privilege). A profile declaring no `probe` can never
  match — otherwise "any request with an `X-Forwarded-For`" would become a spoofable identity. When
  several profiles match, the ranking is `(peer verified, probe count)` and strictly-greater wins, so the
  first declared profile breaks ties. Header *dialects* are normalised in one place: bare IP, `a, b, c`
  chains, `ip:port` / `[v6]:port`, percent-encoded IPv6+port, `{"scheme":"https","…"}` JSON, `https, http`
  chains and `on`/`ssl`/`1` scheme aliases — the config picks the header name, the code handles the shape.
  Three per-server modes: `off` (default, nothing runs), `detect` (label + counters only, no rewrite at
  all), `egress` (apply and optimise). In `egress` the decision runs at the same seam as realip — before
  the access-log record, `limit_req`/`limit_conn` guards, `match_location`, `geo`, cache keys and the
  upstream headers — so one rewrite moves *all* of them onto the real client, and it is recomputed per
  request, which is what a connection-reusing CDN requires (two visitors can share one inbound stream).
  `egress` then does four things: keys counters, reputation, ACLs and logs on the true client; restores
  `$scheme` from the declared protocol header (so `https` redirects and `X-Forwarded-Proto` to the origin
  stop looping); publishes the visible domain as `$front_proxy_host` **without** overwriting `$host`
  (routing already picked the vhost from it, and silently replacing it would change which server answers);
  and, when this gateway is itself the origin, appends its own `Cache-Status: onrouter; detail=hit|miss|
  stale|bypass|proxy-revalidated` (RFC 9209) to buffered cached responses — appended after any upstream
  entry, so a chain of proxies keeps each layer's judgement — which lets the CDN quantify how much of the
  traffic it is *not* absorbing. Only when the peer was verified: an unverified "hit" rate would be a
  number the client controls.
  Trust promotion is explicit and noisy: `front_proxy_auto_trust on` makes a profile's own `trust` ranges a
  rewriting authority root (default `off`, where the profile only describes the front and `set_real_ip_from`
  alone authorises). With it off but a profile chain configured, every request logs nothing and every rewrite
  silently falls back to the node address, so the first such request emits **one** warning per profile naming
  both fixes (`set_real_ip_from`, or `front_proxy_auto_trust on;`) and `ip_blocked` climbs — the config reads
  as if it were rate-limiting real clients while it is rate-limiting one CDN node. Four config-time
  rejections (same class as S11: "declared but inert" is an error, not a warning): an unrecognised
  `front_proxy_mode` value, `egress` with no trusted range anywhere, `auto_trust` on while the mode is not
  `egress`, and a non-parseable `trust` CIDR. `-t` prints the declared profiles with their probe count,
  address chain and range count, and names each vhost that turned `auto_trust` on. Verified by
  `tools/front_proxy_e2e.py` (54 checks: egress rewriting `$remote_addr`/`geo`/the access-log first field,
  forged headers from an out-of-range peer changing nothing, `auto_trust off` leaving the node address,
  `detect` labelling only, the dialect fall-through incl. percent-encoded IPv6 and a poisoned `CN;evil`
  country value, `limit_req` splitting 8 faked clients into 8 buckets on the egress vhost while both control
  vhosts lump them, a real `MISS→HIT` pair with `Cache-Status` and exactly one origin request, an upstream
  `Cache-Status` kept with ours appended, no header at all when unverified, the XFF-only profile, the real
  client and scheme reaching the origin, per-profile metric deltas, one-shot advisories, the startup banner
  and the `-t` rejections) + 13 unit tests in `front_proxy.rs` and router test
  `front_proxy_config_validation`. **When you declare a real provider**, take its header names and `trust`
  ranges from its own published list at deploy time rather than from a table in this repo — the ranges are
  a rolling announcement, and some of its headers are *not* what they look like: `True-Client-IP` and
  `CF-Connecting-IP` are only meaningful from that provider's ranges (which is exactly what the gate
  enforces), Cloudflare documents `True-Client-IP` as Enterprise-plus-managed-transform and says the two
  differ "besides the name" only, Cloudflare also overwrites a client-supplied value of these headers and
  can strip visitor-IP headers entirely with the "Remove visitor IP headers" transform (then the profile
  matches but never applies an address), Fastly only adds `Fastly-Client-IP` when absent, and CloudFront
  **appends** the viewer IP to `X-Forwarded-For` (creating it when absent) while removing `X-Real-Ip`, so
  XFF is a fallback there, not a first choice — its `CloudFront-Viewer-Address` (`ip:port`, non-ASCII
  percent-encoded per RFC 3986) must be enabled in an origin request policy and cannot go in a cache
  policy. A request without it simply does not match that profile, which is the intended "no evidence, no
  claim". Verified against those three docs on 2026-10-20 and written up as copy-paste profiles in
  `conf/front_proxy_examples.conf` (Cloudflare / CloudFront / a plain-XFF self-built edge, each with how to
  refresh its ranges) — keep that in the config file where `-t` can check it, never in the binary. That file
  is booted, not eyeballed: `tools/front_proxy_examples_e2e.py` (24 checks) runs the gateway on it and proves
  both halves — `-t` echoes all three profiles with their chains and 22/0/3 range counts, and at runtime a
  full Cloudflare-shaped header set is *labelled* but never *applied* from a loopback peer, the probe is
  AND-ed, and per-profile counters stay in their own accounts. `grep -a -i -o` over the 1.0.0 release binary
  finds 0 hits for any provider name or its headers, while the controls `front_proxy`/`auto_trust` hit 49/10
  times (re-measured against the packaged zip by `tools/release_verify.py`).
- Proxy response-header rewrite — the nginx `proxy_redirect` + `proxy_cookie_domain`/`proxy_cookie_path`
  (`resp_rewrite.rs`). These are config-time string rewrites applied to the upstream `Location`/`Refresh`
  and `Set-Cookie` response headers. `proxy_redirect <match> <replacement>` (repeatable) treats `match` as a
  literal prefix, or a `~regex` whose replacement expands `$1`/`${name}` captures; `proxy_redirect default`
  synthesises one rule mapping the upstream origin (`scheme://authority` of `proxy_pass`) to the location's
  public prefix, producing a **relative** `Location` (nginx's common default effect). `proxy_cookie_domain`
  and `proxy_cookie_path` rewrite the `domain=`/`path=` attributes of `Set-Cookie` (literal or `~regex`; a
  replacement of `none` **deletes** the attribute; `domain` matches case-insensitively tolerating a leading
  dot, `path` is a prefix replacement that keeps the tail). Deliberate deviation: when no `proxy_redirect`
  is declared the `Location` is passed through **unchanged** (nginx would apply an implicit default) — write
  `proxy_redirect default;` to opt in, so existing proxy tests aren't surprised. The rewrite runs at both
  proxy output seams — the streaming fast path (`convert_upstream_response`) and the buffered path forced by
  `sub_filter`/body/header filters or a cache replay (`build_buffered_response`) — and preserves multiple
  `Set-Cookie` headers. Verified by `tools/proxy_redirect_cookie_e2e.py` (17 checks: literal-prefix redirect
  + cookie domain/path rewrite with tail preserved, `default` → `/def/target` relative Location, regex + `$1`
  capture, `none` deleting `domain` across **two** Set-Cookie that both survive, the all-`off` pass-through
  control, and the buffered `sub_filter` seam rewriting headers while leaving the body byte-exact) + pure
  unit tests in `resp_rewrite.rs` and router tests `parse_proxy_redirect_and_cookie_directives`.
- L4 `stream{}` proxy + `ssl_preread` — a transport-layer path entirely separate from the HTTP request core
  (`stream.rs`). Each `stream { server { … } }` block binds its own TCP listener with its own accept loop and
  shares only the shutdown signal and the upstream pool with L7. A client connection is wired byte-for-byte to
  a backend — **no TLS termination, no protocol parsing** — so any TCP protocol passes through. With
  `ssl_preread on;`, the first TLS record is peeked (bounded by `preread_timeout`, capped at 16KB) and the SNI
  is extracted from the ClientHello by a self-contained offset walk over the record/handshake/extension
  headers; a non-TLS, truncated or SNI-less hello simply yields `None` and still wires to the default. Routing
  uses `sni_match <name> <target>` (repeatable, first match wins; `name` is an exact case-insensitive host or a
  `*.suffix` wildcard matching exactly one extra label, so `*.e.com` hits `a.e.com` but not `e.com`/`x.y.e.com`),
  and the target is a named `upstream` (reusing the L7 weighted-RR/health-check pool via `acquire`) or a literal
  `host:port`; no match falls back to `proxy_pass`. The peeked prefix is replayed to the backend before relaying,
  so the handshake is never disturbed, and `relay` runs both directions concurrently inside the single connection
  task with an idle (`proxy_timeout`) bound — draining or aborting a connection cannot leave an orphan pump
  holding half a socket. L4 uses the same process-wide `worker_connections` semaphore and connection metrics as
  HTTP: a tunnel that cannot get a permit is dropped immediately (an HTTP peer gets a fast 503 instead), and a
  tunnel to a named upstream holds its `UpstreamGuard` (hence `max_conns` and passive-health accounting) for the
  whole tunnel rather than only `connect`. On shutdown the listening socket is closed first (new connects are
  refused), in-flight tunnels drain within `shutdown_grace`, then leftovers are force-aborted; completed
  connection tasks are reaped continuously instead of accumulating in the JoinSet.
  Verified by `tools/stream_lifecycle_e2e.py` (24 checks driven by **real TCP traffic**: with
  `worker_connections 1` the second L4 tunnel is dropped while HTTP receives 503, and both recover once the
  first tunnel closes; an upstream `max_conns=1` rejects the second tunnel before any backend connection and
  releases when the first closes; Prometheus `accepted`/`active` include L4 and fall back after close; a
  Ctrl+Break graceful stop refuses new connections, keeps the in-flight tunnel echoing through a 3s
  `shutdown_grace`, force-closes it on schedule and exits 0) plus `tools/stream_ssl_preread_e2e.py` (6 checks
  driven by real Python TLS clients: full handshake through the tunnel proves byte transparency, exact SNI
  `alpha.test` → the named upstream, wildcard `foo.wild.test` → `*.wild.test` backend,
  `wild.test`/`a.b.wild.test` correctly *not* matched and `other.test` unmatched all fall back to `proxy_pass`,
  plus a no-preread plain TCP echo) + pure unit tests in `stream.rs` (ClientHello SNI parse, truncation/garbage →
  `None`, exact+wildcard matcher, first-match-wins).
- Upstream metrics: proxied requests record the backend actually contacted — `ProxyEngine::forward`
  writes the chosen peer into `$upstream_addr`, the response code into `$upstream_status` (transport
  failures log `0`, matching nginx) and the connect+send+first-response-header round-trip into
  `$upstream_header_time`. These surface to Lua through `ngx.var` (above) so `log_by_lua` can harvest
  per-request upstream timing/status, and to the combined access log line (including the Upgrade
  tunnel path). Process-wide, each upstream node also exposes connection count, active health and
  lifetime success/failure counters through `/metrics` (see “Runtime metrics endpoint”); the
  success/failure counters are updated with a lock-free atomic write, and a Content-Length response
  settles success as soon as its last body frame arrives (hyper need not poll the body to `None`).
  Verified by `tools/upstream_e2e.py` (10 checks: `$upstream_addr`
  = the live backend, a backend-emitted 503 is both passed through and logged as `$upstream_status=503`,
  and a 0.6s backend yields `$upstream_header_time ≥ 0.55` — real round-trip, not a placeholder) +
  `tools/observability_e2e.py` (live/dead node success/failure split, connection gauge back to 0,
  WebSocket 101 success) + unit tests `forward_records_upstream_metrics_on_failure`.
- Digests & CRC (pure-Rust, via `ring` + a self-contained MD5): `ngx.md5(s[, binary]) / md5_bin /
  sha1_bin(s[, hex]) / sha256_bin(s[, hex]) / hmac_sha1(secret, s) / crc32_short / crc32_long` — verified byte-for-byte
  against RFC 1321 / RFC 2202 / FIPS 180-4 / the CRC-32 `0xCBF43926` vector
- `resty.*` Lua modules (loaded with `require`, registered via `package.preload`; original pure-Lua
  implementations, not vendored OpenResty source): `resty.string` (`to_hex / sha256_hex / md5_hex`,
  layered on the native digests) and `resty.lock` (`new(dict, {timeout,exptime}) / lock(key) / unlock()`,
  a shared-dict `add`-based mutex with `ngx.sleep` backoff polling and a monotonic owner token so an
  expired lock is never unlocked by the wrong holder). Verified by `tools/resty_e2e.py`, including N-way
  concurrent `resty.lock` critical sections where the shared counter is exact (no lost updates) across VMs.
  Also `resty.http` (`new / connect / request / set_timeout / set_keepalive / close` + `get_status_code /
  get_headers`): a full HTTP/1.1 client built purely on the native cosocket — request-line + header + body
  assembly, `Host`/`Content-Length`/`Connection` defaults, response status-line and header parsing
  (lower-cased keys, repeated-header aggregation), `Content-Length`, `chunked`, and read-until-close body
  framing, HEAD/204/304 empty-body handling, `query` table auto-encoding via `ngx.encode_args`, `https`
  via `sock:tlshandshake`, and connection-pool reuse through `set_keepalive`. Verified by
  `tools/resty_http_e2e.py` (21 checks) against a real Python HTTP backend serving chunked /
  content-length / 204 / HEAD / POST-echo / custom-header responses. Also `resty.redis`
  (`new / connect / command / set_timeout / set_keepalive / reconnect / close / pipeline` plus dynamic
  command dispatch so `redis:get("k")` == `redis:command({"get","k"})`): a RESP client on the native
  cosocket — request arrays encoded as `*N/$len`, replies parsed for all five types (simple string,
  error→`nil,err`, integer, bulk incl. nil→`false`, nested multi-bulk), `pipeline()`/`commit()` batching,
  and pool reuse via `set_keepalive`. Verified by `tools/resty_redis_e2e.py` (19 checks) against a real
  RESP stub server exercising SET/GET/INCR/DEL/EXISTS/MGET/PING, nil and error replies, and pipelines.
  `resty.cookie` (`new(cookie_str) / get / get_all / set(opts)`, module called as `_M.new(self, str)`)
  parses Cookie headers and emits `Set-Cookie` with `path/domain/expires/max_age/secure/httponly/
  samesite/version/comment`; `value=false` emits a delete cookie, and multiple cookies append as
  repeated response headers. `resty.limit.req` (leaky bucket `new(dict, rate, burst) / incoming(key,
  commit) / uncommit`), `resty.limit.count` (fixed 1 s window), and `resty.limit.conn` (in-flight
  connection accounting) reuse the shared-dict primitives and return the OpenResty `delay / nil,
  "rejected" / remaining` conventions. Verified by `tools/api_compat_e2e.py` (real traffic incl.
  concurrent rejection of the second `limit_conn` request and multi-line Set-Cookie).
- Time: `ngx.today() / cookie_time(ts) / http_time(ts) / parse_http_time(str) / update_time()`
  (IMF + Netscape-cookie formats, `parse_http_time` returns `nil` on garbage)
- Phase & request introspection: `ngx.get_phase()` (returns the running phase, e.g. `content_by_lua`)
  and `ngx.is_subrequest` (true inside an `ngx.location.capture` subrequest)
- Workers & config: `ngx.worker.pid() / id() / count() / pids() / exiting()` and `ngx.config.subsystem / prefix() /
  no_debug` — ONRouter is a single-process reactor, so `id()` is always `0` and `count()` is `1`
  (`pid()` is the real OS pid; `pids()` returns that same single pid; `exiting()` flips true when
  SIGTERM/SIGINT — or Ctrl+C/Ctrl+Break on Windows — starts a graceful stop)
- All of the above are exercised end-to-end against real traffic by `tools/ngx_api_e2e.py` (36 checks).

## E2E tests (aligned with the OpenResty official suite)

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
  `tools/proxy_cache_e2e.py` remains 13/13.
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

## Benchmarks and deployment docs

- `bench_ab.py` runs ONRouter vs OpenResty on the same endpoints (Windows and Linux);
  `tools/linux_ab.sh` renders an OpenResty config into a temporary prefix and runs the sweep.
  Procedure, caveats, and the pending Linux baseline are in `docs/LINUX_AB.md`.
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
- `docs/OPENRESTY_GAP_ANALYSIS.md` is the current capability/gap matrix with test evidence.
- `docs/USR2_HOT_UPGRADE.md` explains why nginx-style USR2 needs a process-model change,
  gives two designs (SO_REUSEPORT handover / master+worker FD inheritance), and a Linux test plan.

## Design tradeoffs & roadmap

Already done (previously listed as gaps, now implemented):

- **`*_by_lua_block` syntax**: the config lexer rewrites `<phase>_by_lua_block { <bare Lua> }` into the
  equivalent quoted directive before parsing, understanding nested `{}`/tables, single/double-quoted
  strings, Lua comments, and `[[long brackets]]`; line numbers are preserved so diagnostics still point
  at the original directive. All phases support it (`content_by_lua_block`, `init_worker_by_lua_block`,
  `ssl_certificate_by_lua_block`, …).
- **Unknown-directive warnings**: unrecognized top-level directives are surfaced at startup/reload in
  both the console and `error_log` instead of being silently dropped; `worker_processes` and
  `log_format` are explicitly reported as “ignored” with the reason (single-process model / built-in
  combined format).
- **`ssl_certificate_by_lua*` + `ngx.ssl`**: handshake-time per-SNI certificate selection with a
  cert/key-hash dynamic config cache; verified by `tools/ssl_cert_lua_e2e.py` (21 checks: two vhosts,
  legacy `set_cert` aliases, TLS1.2, ALPN h2, unknown/no SNI fallback, script error → aborted
  handshake, `clear_certs`, `_file`, and warning logs).
- **`init_worker_by_lua*` + `lua_package_path`**: run once per VM after its scheduler is live (timers,
  `ngx.sleep`, cosockets work), with `$prefix` and `;;` semantics; verified by
  `tools/init_worker_package_e2e.py` (21 checks incl. per-VM count, ordering vs `init_by_lua`, module
  `require` from disk, no re-run on later requests, and startup failure on script error).
- **`ngx.flush` + `ngx.req.socket`**: streaming responses (early first byte, h1 chunked/h2 DATA,
  64 KiB auto-flush) and sequential buffered body reads; verified by
  `tools/lua_flush_socket_e2e.py` (23 checks).
- **`proxy_cache` advanced semantics**: `proxy_cache_lock` coalescing of concurrent same-key misses,
  `use_stale` (`error`/`timeout`/`updating`/`http_xxx`) replay of expired entries, `bypass`/`no_cache`,
  and keys_zone-sized zones with LRU eviction; verified by `tools/cache_advanced_e2e.py` (32 checks:
  20-way concurrency → one origin fetch, stale during refresh, upstream death, eviction order, and
  HEAD non-poisoning).
- **TLS session reuse across ports**: one process-wide `ssl_session_cache` store plus a stateless
  ticketer shared by every listener, with `builtin`/`shared` modes and `ssl_session_tickets on|off`;
  verified by `tools/tls_session_e2e.py` with `openssl -sess_out/-sess_in` and `session_reused`.
- **Two-hop Lua scheduling fast path**: the request task runs the first Lua segment inline when the VM
  is free and only hands off to the VM scheduler on a yield; no-yield scripts never cross task
  boundaries. `onrouter_lua_phase_{inline,adopted,scheduled}_total` exposes which path each phase took.
  On this Windows host the A/B sweep is neutral within run-to-run noise (Lua `content_by_lua` c=1
  6518–6428/s after vs 6678/s before; c=4 15366–14882/s vs 15043/s); static/proxy rows moved with the
  client ceiling (9844 → 8865–9193 req/s), so the host, not the change, dominates.

- **Lua VM pool**: one VM per CPU core, so multiple requests execute scripts truly in parallel across
  VMs (no single process-wide lock).
- **`lua_shared_dict` capacity enforcement**: `set`/`incr` keep total usage within the declared
  capacity via Redis-style approximate LRU eviction; `safe_set` refuses to evict and returns
  `no memory` instead.
- **`lua_shared_dict` disk cold tier — what it costs**: the `ngx.shared.DICT` bindings are
  synchronous Lua calls, so a cold read is a disk read inside whichever VM worker is serving that
  request. Three things keep that affordable: the cold index lives in memory (a key that was never
  spilled resolves as a miss with **zero** disk I/O — asserted by frozen `cold_hit`/`entries` counters
  under 200 real misses), values above `max_value` (default 64 KiB) are never written to the tier, and
  every write goes to one background writer thread per store (temp file + rename). That last choice has
  a visible consequence: an entry that was *just* evicted is not yet readable from disk, so a `get()`
  landing inside that window returns `nil` instead of promoting it. The request thread never waits for
  the disk, which is the intended trade — data that is only in flight between tiers is a brief
  throughput miss, not corruption, and the next read gets it back (`tools/disk_cache_e2e.py` synchronises
  on the `onrouter_dict_disk_pending_jobs` gauge wherever it needs the write to be durable).
  `capacity()`/`free_space()` deliberately stay memory-tier-only; `num()`/`size()`/`get_keys()`/`ttl()`
  span both tiers. `flush_all()` is not fooled by that window either: the store carries a generation
  counter, so a spill that was still queued when the flush happened is discarded instead of registering
  itself back into the index — otherwise a flushed zone would resurrect entries (and files) later, or
  after a restart.
- **Active health checks**: `health_check interval=… fails=… rises=… uri=… timeout=…` drives a
  background prober per upstream (in addition to passive `max_fails`/`fail_timeout`).
- **WebSocket / Upgrade tunnel**: `proxy_pass` auto-detects Upgrade requests and, after completing the
  101 handshake with the backend, hands off to hyper's upgrade mechanism for a bidirectional pipe
  (`server.rs::handle_upgrade` + `ProxyEngine::upgrade`); WS-frame bytes that race ahead of the
  backend's 101 are not lost (prefix buffer). The tunnel reaches both `http://` and TLS backends
  (`https://`/`wss://`) through the same connector (`proxy.rs` → `proxy_tls.rs`), verified by
  `tools/https_backend_e2e.py`. The request line sent to the backend carries the client's **raw,
  undecoded** request target (nginx behaviour): routing/`allow`/`deny`/`limit` decisions were made on
  that same string, so `%23` cannot arrive as a bare `#` (fragment truncation) or `%3f` as a second
  `?` and make the backend talk about a different resource than the gateway guarded. Only a
  `rewrite`-produced path (already decoded) or a non-origin-form target is re-encoded per segment.
  Verified by `tools/security_matrix_e2e.py` probe `s4`, which reads the request line the fake
  backend actually received, plus unit test `upgrade_target_forwards_raw_undecoded_uri`.
- **https / wss backends**: `proxy_pass https://…` (and `wss://…` upgrades) terminate TLS to the
  upstream with a pure-Rust rustls client over one pooled connector shared with plain-HTTP backends
  (`proxy_tls.rs::ProxyConnector` implements `tower_service::Service<Uri>`; `ProxyStream` is either a
  bare `TcpStream` or a rustls `TlsStream`, so hyper pools both by scheme+authority). Directives
  mirror nginx: `proxy_ssl_verify on|off` (default on), `proxy_ssl_trusted_certificate <path>` (a PEM
  CA bundle, resolved relative to the conf dir), `proxy_ssl_name <host>` (override SNI / the name the
  cert is checked against), `proxy_ssl_server_name on|off`. The TLS policy is part of the pool key, so
  a `proxy_ssl_verify off` location can never leak its no-verify connector into another. Verified by
  `tools/https_backend_e2e.py` (GET/POST through a verified https backend, a `wss` 101 tunnel, and a
  `verify on`-without-CA location that correctly 502s). **Mutual TLS (client certs)**: `proxy_ssl_certificate
  <path>` + `proxy_ssl_certificate_key <path>` make the gateway present a client certificate during the
  upstream handshake (rustls `with_client_auth_cert`; the cert chain is parsed with `rustls_pemfile::certs`,
  the key as PKCS8/RSA/EC), for backends that enforce `CERT_REQUIRED`. Both paths resolve relative to the
  conf dir; the pair is folded into the pool fingerprint so an mTLS location never reuses a cert-less
  connector (and vice-versa). Verified by `tools/mtls_upstream_e2e.py`: an https backend that requires a
  client cert echoes the verified client CN back for GET and POST through `/mtls/`, while a cert-less
  `/nomtls/` location against the same backend fails the handshake and 502s. **Limitations**: this is an
  offline, pure-Rust
  build, so there is **no system trust store** — `proxy_ssl_verify on` requires an explicit
  `proxy_ssl_trusted_certificate`, and a missing one fails with a clear `proxy_ssl_trusted_certificate`
  error rather than a silent accept; ALPN is pinned to `http/1.1` (no h2 upstreams); the proxy
  forwards to a TLS backend by DNS name (rustls derives SNI from it), so `proxy_ssl_verify off` is the
  path for arbitrary/self-signed backends while `verify on` needs the CA + a matching SAN.
- **gzip response compression**: `gzip on;` + `gzip_min_length` / `gzip_comp_level` / `gzip_types`
  stream-compress eligible 2xx responses (flate2, pure-Rust). Respects `Accept-Encoding` (including
  `q=0` decline), skips HEAD and non-listed content types, enforces the length threshold via the
  body's exact `size_hint`, sets `Content-Encoding: gzip` + `Vary: Accept-Encoding`, and drops
  `Content-Length` so the access log's `bytes_sent` reflects the real compressed wire bytes.
  (`compress.rs::GzipBody`, `server.rs::finalize`, verified by `tools/gzip_e2e.sh`.)
- **Upstream keep-alive pool tuning**: per-upstream `keepalive N` and `keepalive_timeout <t>` drive
  hyper's client connection pool (`pool_max_idle_per_host` / `pool_idle_timeout`); the proxy caches
  one pooled client per `(connect_timeout, send_timeout, max_idle, idle_timeout)` tuple so
  differently-configured upstreams get separate pools. (`upstream.rs::KeepaliveOpts`, `proxy.rs::client`, verified by
  `tools/keepalive_e2e.sh`: `keepalive` reuses one backend connection, a short `keepalive_timeout`
  reaps the idle one between spaced requests.)
- **Streaming request-body forwarding**: `proxy_request_buffering off` (per server/location, default
  `on` as in nginx) pipes the client request body straight to the backend as it arrives instead of
  buffering the whole thing first — the proxy sends a `BoxBody` wrapping the incoming `Incoming` so
  memory stays O(1) and hyper derives `Content-Length`/chunked framing from the body's `size_hint`.
  Because streamed bytes can't be replayed, the streaming path disables `proxy_next_upstream` node
  switching. (`proxy.rs::ProxyBody`, `server.rs::handle_request`, verified by
  `tools/streaming_body_e2e.py`: a body dribbled to the backend over ~1.2s shows a ~1.1s read span
  through `off` but a single burst read through `on`, with matching sha256 both ways.)
  The forwarded body is wrapped in `StreamBodyGuard`, which enforces **both** `client_max_body_size`
  (counted while streaming, since chunked has no declared length to pre-check → 413) and
  `client_body_timeout` (a `tokio::time::Sleep` re-armed on every data frame, so a client that sends
  one chunk and stalls is cut after the idle interval → 408, the nginx status for this case).
  `tools/security_matrix_e2e.py` probe `s5` shows a stalled upload being closed at the configured
  2 s while `/ping` keeps answering.
- **`proxy_send_timeout` idle-write watchdog**: covers every header/body/flush write on the upstream
  stream (plain or TLS). A write that stays `Pending` for the configured duration aborts the hop with
  `Timed out`; `0` disables it, matching nginx (the timeout is per write operation, not a total
  transfer budget). Writes are capped at 64 KiB per syscall so kernel backpressure stays observable on
  every platform — Windows loopback completion I/O otherwise accepts a single 64 MB send immediately,
  hiding the stall. `proxy_read_timeout` starts only after the request body has been handed to the
  connection (frames are polled as hyper drains them), so streamed uploads are bounded by the write
  watchdog rather than the response timeout; `0` disables the read timeout too. Verified by
  `tools/proxy_semantics_e2e.py` (a 300 ms send timeout aborts a 64 MB upload to a non-reading backend
  in <1.5 s; with `send 0` the 300 ms abort does not happen and the 2 s read timeout bounds the
  exchange; and a continuously-reading backend receives all 64 MB untouched) plus `proxy_tls` unit
  tests for the watchdog on/off paths.
- **Within-VM Lua coroutine concurrency**: each VM is run by a scheduler task that holds the `Lua`
  lock only for a synchronous resume segment and releases it between segments, so many requests share
  one VM and interleave at `ngx.sleep` (a Lua wrapper around a `tokio::time::sleep` that yields the
  sleep id; the scheduler re-readies the coroutine when the timer fires). `ngx.ctx` is a per-request
  table re-attached before each resume, so it survives a yield and stays isolated from other coroutines
  on the same VM. (`lua_engine.rs::run_scheduler`/`co_spawn`, verified by `tools/lua_concurrency_e2e.py`:
  48 concurrent 500ms `ngx.sleep` requests finish in ~0.5s wall — not ~1.5s as the old one-request-per-VM
  serialization would give — and 32 concurrent `ngx.ctx` requests each keep their own counter across the yield.
  `ngx.socket.tcp` cosocket ops share the same yield-and-resume path, verified by `tools/cosocket_e2e.py`:
  32 concurrent connect/send/receive round-trips finish in ~1.3s wall, far below the ~9.6s a serialized
  model would take, while per-op timeout returns `(nil, "timeout")` and connect failure returns `(nil, err)`.)
- **Runtime metrics endpoint**: a process-global `Metrics` singleton (std `OnceLock`) is fed by the
  connection layer — accepted-count on each TCP accept, an active-connections gauge via an RAII guard
  scoped to each connection task, requests-handled per HTTP request, and responses bucketed by status
  class (2xx/3xx/4xx/5xx) in `finalize`. The same singleton is fed by the rest of the request path:
  every cached-location response records its `X-Cache-Status` (`hit`/`miss`/`expired`/`bypass`/
  `stale`), TLS accept/handshake failures (including a QUIC handshake failure) increment
  `onrouter_tls_handshake_failures_total`, `limit_req`/`limit_conn` rejections increment
  `onrouter_limit_rejections_total{type="req"|"conn"}`, and an access-log queue overflow increments
  `onrouter_access_log_dropped_total` instead of blocking the request task. The upstream pool is
  registered once at startup (`register_upstreams` keeps the live `Arc`s, so reloads stay current)
  and renders per-node `onrouter_upstream_server_connections{upstream,server}`,
  `onrouter_upstream_server_healthy` (active-check verdict),
  `onrouter_upstream_server_available` (schedulable now: not `down`, not passively removed,
  circuit not open) and
  `onrouter_upstream_requests_total{upstream,server,result="success|failure"}`; the success/failure
  counters live on the nodes themselves, not under the SWRR scheduling lock. Adaptive selection adds
  `onrouter_upstream_least_time_mode{upstream}` (0/1/2 = off/observe/on), the per-node
  `onrouter_upstream_server_ewma_seconds{upstream,server}` and
  `onrouter_upstream_least_time_total{upstream,role="sampled|picked|would_differ|cold"}` — and all three
  are rendered **only** for pools whose tier is not `off`, so a deployment that never turned the feature
  on carries no zero-valued series for it, and `would_differ` rising while `picked` stays at 0 is
  exactly the "observe 档只测量、没有改行为" evidence the tier is meant to produce. `content_by_rust metrics`
  reads the singleton and renders it in the Prometheus text exposition format (`# HELP`/`# TYPE` +
  `onrouter_uptime_seconds`, `onrouter_connections_{accepted,active,capacity}`,
  `onrouter_http_requests_total`, `onrouter_http_responses_total{class="…"}`, the cache/TLS/limit/log
  families above, the upstream-server families, the cold-tier gauges
  `onrouter_dict_disk_{entries,bytes,value_bytes,capacity_bytes,pending_jobs,pending_bytes}{dict=…}`
  and `onrouter_dict_disk_operations_total{dict,op="spill|spill_skipped|cold_hit|promote|evict|expire|corrupt|cold_error|never_read|warm_recovered"}`
  (only for zones that actually declared `disk=`, so a diskless deployment carries no zero-valued noise
  series), and the Lua scheduling-path counters
  `onrouter_lua_phase_{inline,adopted,scheduled}_total`, and the CDN-awareness counter
  `onrouter_front_proxy_total{profile,role="matched|ip_applied|ip_blocked|origin_applied|origin_blocked|country_applied"}`
  — one series per declared profile and role, nothing rendered when no profile is declared, so
  `ip_blocked` climbing while `ip_applied` stays at 0 is the signature of "recognised but the rewrite was
  not authorised"; the counters live with the profile table, so `SIGHUP` restarts them, exactly as nginx's
  `stub_status` counters restart on reload), escaping label values. It uses the singleton
  because the native handler signature has no access to `AppState`. (`metrics.rs`, `server.rs`,
  `engine.rs`, verified by `tools/metrics_e2e.py` 38/38 and `tools/observability_e2e.py` 26/26 with
  real traffic: with traffic interleaved between two scrapes, `requests_total`/`2xx`/`4xx` deltas track
  the real request counts, the active gauge stays ≥1 while a connection is in flight, `capacity` equals
  the `worker_connections` default, a no-yield Lua endpoint increments `inline` while an `ngx.sleep`
  endpoint increments `adopted`, three proxied requests through a two-node upstream count 3 successes
  on the live node and 1 failure on the dead one, the MISS→HIT→BYPASS→EXPIRED cache sequence maps 1:1
  onto the status counters, a raw TLS-garbage probe increments the handshake-failure counter, and one
  each of limit_req/limit_conn rejections and a WebSocket upgrade (101, recorded against its upstream)
  show up with the exact labels.)
- **Access-log upstream fields**: besides the combined fields, every line carries
  `$request_time` (3 decimals) and `$upstream_addr` / `$upstream_status` /
  `$upstream_header_time`. The triple is filled after the whole proxy phase (including
  `proxy_next_upstream` retries), so it names the backend that actually produced the response;
  requests that never touch an upstream (static/return/Lua) log `- - -`; transport failures log `0`
  like nginx; Upgrade tunnels are recorded too (`101` + peer). Streaming responses handed off to a
  background task log the request-level fields and `- - -`, since their `RequestCtx` moved.
  Emitting never blocks: a bounded channel to the writer thread drops lines under overload and the
  drop count is exported as `onrouter_access_log_dropped_total`.
- **Access control (`allow`/`deny` + `auth_basic`)**: an ACCESS-phase gate runs before
  `access_by_*` (matching nginx's built-in module order). `allow`/`deny` accept IPv4/IPv6/CIDR/`all`,
  evaluated first-match-wins with default-allow, and a location with no own rules inherits the
  server's. `auth_basic`/`auth_basic_user_file` enforce HTTP Basic with the realm as a tri-state
  (`unset` inherits, `off`/`""` disables, else enables); the htpasswd file is loaded through a
  process-wide cache that reloads when `(mtime, size)` changes **or** once the entry is older than
  1 s. Both gates fail closed: an unparsable peer address is a `403` rather than "no rules matched",
  a realm without a user file is a `401` challenge rather than a pass, and an htpasswd line with an
  empty hash is dropped so it can never match an empty password. Password records may be plaintext,
  `{SHA}` (SHA-1 base64),
  `$1$` (glibc MD5-crypt) or `$apr1$` (Apache MD5-crypt) — MD5 and SHA-1 are implemented in pure Rust
  (no crypto crates, so cross-compiles stay clean), and the MD5-crypt output is validated against
  `openssl passwd` reference vectors. Comparisons are constant-time. (`access.rs`, `server.rs`,
  `router.rs`, verified by `tools/auth_e2e.py`: missing/wrong credentials → `401` with a
  `WWW-Authenticate: Basic realm=…` challenge, correct `{SHA}`/`$apr1$`/plaintext logins → `200`,
  `deny all` → `403`, `allow 127.0.0.1/32` matches the loopback client; plus
  `tools/security_matrix_e2e.py` probes `s1`/`s2`/`s3` for the three fail-open cases and unit tests
  `empty_hash_entry_never_authenticates`, `htpasswd_cache_*`.) crypt-DES and bcrypt
  (`$2y$`) htpasswd records are not yet supported.
- **Subrequests (`ngx.location.capture`)**: a captured location runs the entire request pipeline
  (rewrite → access → content: static, `return`, `proxy_pass`, and nested Lua content all work) as an
  internal subrequest resolved against the parent's vhost, returning a `{ status, body, header }`
  table. It is a scheduler yield point (`coroutine.yield(op_id)`) exactly like the cosocket ops — the
  subrequest runs in a tokio task that reaches `AppState` through a late-bound `Weak<AppState>` handle
  (the Lua engine is constructed before `AppState`, so main.rs binds it after startup) — so the parent
  coroutine releases the VM lock and other in-flight requests keep progressing. Nested captures work
  because a subrequest's own Lua re-enters the scheduler without deadlock, and a `capture_depth` guard
  caps runaway recursion (returns `status = 0`, the ngx_lua error sentinel). `internal;` locations are
  reachable only via capture, not from the client. (`server.rs::run_capture`, `lua_engine.rs`,
  verified by `tools/subrequest_e2e.py`: Lua/return/query/404 captures, a two-level nested capture, a
  self-referential capture hitting the depth guard, and an external request to an `internal` location
  still returning 404.) `opts.method` / `opts.body` / `opts.args` are honored, and
  `ngx.location.capture_multi` runs a list of captures concurrently as light threads (verified in
  `tools/api_compat_e2e.py`). `share_all_vars`/`ctx` option passing is not yet implemented.
- **`resolver` + async DNS**: a pure-Rust, non-blocking UDP DNS stub resolver (`dns.rs`) — it builds
  RFC1035 queries for A/AAAA, follows compression pointers in the answer, and caches results for the
  `valid=` TTL (default 10s), with negative caching for NXDOMAIN. Without it, `proxy_pass` relies on
  the OS `getaddrinfo` (which a busy worker would block on); with it, `proxy.rs` resolves the backend
  hostname to an IP literal before connecting and rewrites the URI authority — hyper then skips
  `getaddrinfo` entirely, and the original name is kept in the `Host` header. Applies to both the
  forward path and the WebSocket/`upgrade` raw-socket path. `resolver <addr…> [valid=…] [timeout=…]
  [ipv6=on|off];` (plus `resolver_timeout`). Resolution failure returns the nginx-mapped `502`.
  (Verified by `tools/resolver_e2e.py`, which points `resolver` at a stub DNS server and proxies to
  `test.invalid` — an RFC6761 reserved name the OS cannot resolve — proving the async path is taken,
  then shows a repeated request does **not** re-query thanks to the TTL cache.) `ngx.socket.tcp`
  `connect` still uses system resolution.
- **`proxy_cache` response caching**: an in-memory, named-zone cache (`proxy_cache.rs`) for the
  `proxy_pass` path. Directives: `proxy_cache <zone>|off`, `proxy_cache_key <template>` (default
  `$scheme$proxy_host$request_uri`; variables are lexed on the template itself rather than on the
  half-substituted string — a naive text replacement of `$proxy_host` with a dotted-numeric
  authority turns the *preceding* `$scheme` into the non-existent `$scheme127`, and the key keeps an
  unexpandable literal), `proxy_cache_valid <codes…|any> <time>` (multi-line),
  `proxy_cache_methods` (default `GET HEAD`), `proxy_cache_min_uses` (default 1),
  `proxy_cache_lock on` + `proxy_cache_lock_timeout`, `proxy_cache_use_stale
  error|timeout|updating|http_xxx`, `proxy_cache_bypass <v…>` / `proxy_no_cache <v…>` (both take
  multiple values and follow nginx truthiness: a value counts only when it expands to a non-empty
  string that is not `"0"`, so `proxy_no_cache $arg_nc` stays inert until `?nc=` is actually given),
  `proxy_ignore_headers <name…>` (case-insensitive) which removes the named upstream headers from
  the *cache-decision* view only — an ignored `Cache-Control: no-store` no longer forbids caching and
  an ignored `Set-Cookie` no longer blocks storing, while both are still forwarded to the client
  unchanged; top-level
  `proxy_cache_path … keys_zone=<name>:<size>` sets per-zone capacity (128 B/entry; the path itself
  is never written — the cache is memory-only). Freshness precedence matches nginx: the upstream's
  own `Cache-Control`/`Expires` wins (and an explicit `no-store`/`no-cache`/`private`/`max-age=0`
  forbids caching outright), falling back to `proxy_cache_valid` only when the upstream gives no
  hint. Responses carrying `Set-Cookie` are never stored (shared-cache safety) unless
  `proxy_ignore_headers Set-Cookie` says otherwise.
  `proxy_cache_lock` coalesces concurrent same-key misses into one origin fetch (20 concurrent
  requests → exactly 1 backend hit, 1 `MISS` + 19 `HIT`). Expired entries stay in memory for an
  hour so `proxy_cache_use_stale` can replay them (`STALE`) on origin 5xx, connect failure, or while
  another request is already refreshing (`updating`, served immediately without queueing on the
  lock). Matches nginx's split: `proxy_cache_bypass` skips the *read* but still stores the fresh
  response, `proxy_no_cache` only skips the *store* (a later normal request can still hit). HEAD
  requests can be served from a GET-populated entry (the HTTP layer suppresses the body) but never
  populate the cache themselves, so an empty HEAD response cannot poison the shared GET key. Zones
  evict least-recently-used entries at capacity, expired entries are cleaned as writes accumulate, and a
  config reload applies new `keys_zone` sizes to live zones. Every response through a cached
  location carries `X-Cache-Status: HIT|MISS|EXPIRED|BYPASS|STALE` — `BYPASS` also covers "the origin
  answer was fetched but deliberately not stored" (blocked by `proxy_no_cache`, `Set-Cookie`,
  `min_uses` or a non-cacheable method), and the same status feeds
  `onrouter_cache_requests_total{status=…}` on `/metrics`. `$upstream_cache_status` is exposed as a
  built-in variable for `add_header`/`proxy_set_header`/`access_log`/cache keys, and is an **empty
  string** when the request never engaged the cache (POST and other non-idempotent methods, streaming
  bodies, a location without `proxy_cache`), so `add_header X-Cs $upstream_cache_status` emits an empty
  header instead of a literal — same as nginx.
  (Verified by `tools/proxy_cache_e2e.py` 13/13, `tools/cache_advanced_e2e.py` 32/32: concurrent
  coalescing, 502/error/updating stale replay, bypass/no_cache, keys_zone-driven LRU, and HEAD
  non-poisoning; `tools/observability_e2e.py` asserts the status→counter mapping 1:1; and
  `tools/cache_header_gap_e2e.py` 25/25 for the semantics aligned in this round: `add_header` variable
  expansion, `$upstream_cache_status` on a POST, multi-value `proxy_cache_bypass` / `proxy_no_cache`
  including all-`"0"` and never-set variables, and `proxy_ignore_headers` with a control location that
  does not ignore.) Not yet
  implemented: revalidation (`If-None-Match` to origin), `proxy_cache_purge`, `proxy_cache_lock_age`,
  on-disk persistence, `Vary`-aware keying.
- **Learning (ONRouter-only: cache admission, queue depth, client reputation)**: three small online
  models, all built on the premise that a gateway that learns must still be a gateway whose memory you
  can state in one sentence. Everything hangs off `learning on;` (**off by default**; with it off, the
  admission check, the depth lookup and the reputation lookup each short-circuit, so the shipped
  default build is the un-learned build) and off one process-level byte ledger
  (`learning_memory_budget`, default 1 MiB) that every structure claims from and releases back. Tables
  are rounded *down* to whole slots and the rounding remainder is returned to the ledger immediately,
  so `onrouter_learning_memory_bytes{role="used"}` equals the sum of the per-zone table bytes exactly —
  the E2E asserts that identity rather than trusting a comment.
  What each model is, and what it deliberately is not:
  **Cache** (`proxy_cache_learning <zone> [sketch=<size>]`): TinyLFU, i.e. a 4-row × 4-bit count-min
  sketch whose estimate is the min over rows and whose aging is a whole-table halving every time each
  counter has been written once on average. It answers exactly one question — may this newcomer take a
  slot from the coldest of the 8 oldest entries — so the property being bought is that a scan of
  one-shot URLs no longer evicts the object everyone actually reads. It is not a hit-rate predictor and
  it changes nothing about TTLs, `use_stale`, or the revalidation gap above.
  **Queue** (`limit_req_queue <zone> [depth] [depth_min] [max_delay]` + `limit_req_learning <zone>
  [table]`): the learned quantity is the length of a key's *finished* bursts (a gap larger than
  `gap_cap`, 2× the token period clamped to 20 ms…1 s, is what commits a length), and it only ever
  moves the per-key depth inside `[depth_min, depth]` — `depth` stays the operator's hard ceiling and
  is clamped at 4096. A burst that reaches `depth × 4` without ever ending is classified as a flood and
  the memory is zeroed mid-burst **and** at burst end, so "attack for a minute then stop" cannot buy a
  deep queue either. Admitting a request to the queue reserves its token (`st.tokens -= 1.0`, the bucket
  goes into debt), which is why a queued request never gets a 429 after waiting — and why the E2E sleeps
  between phases: that debt must be repaid at the configured rate before the next phase measures it.
  **Reputation** (`vip_learning [table] [min] [decay]`): the only signal is the rate limiter's own verdict
  — in-rate `+1`, queued `0`, rejected `−8`, decayed by 1 point per `decay` of silence — so nothing a
  client sends (header, cookie, path, User-Agent) can claim VIP status; it has to be earned from
  behaviour the limiter already observed. The key is `$remote_addr` (that is all a `limit_req_zone` can
  key on), which is why the E2E runs on `realip`-presented virtual client addresses. It acts on two
  places and no others: a trusted key's queue opens to the configured ceiling instead of the learned
  floor — the **rate is untouched**, the same token bucket still releases one request per period, so
  this reorders waiting, it does not permit more traffic — and objects written on behalf of a trusted
  key get a fixed `+4` sketch boost applied *after* the admission check, so reputation buys retention,
  never a jump past admission. Everything else about being "important" is explicitly out of scope.
  Aging/decay counters are driven by writes and by silence, never by a background thread, and there is
  no cross-process or shared-memory state: a reload rebuilds in place, `apply_queue`/`apply_vip` reuse
  an unchanged table by comparing the **operator-requested** size (not the rounded allocation) so a
  reload that changes nothing else never wipes live reputation.
  `-t` knows all six directives, prints a per-zone learning summary, and warns rather than fails on a
  bad size/`min`/unknown argument (falling back to the default and saying so); referencing a
  `limit_req_queue`/`limit_req_learning`/`proxy_cache_learning` zone that was never declared is an
  error. Metrics: `onrouter_learning_enabled`, `onrouter_learning_memory_bytes{role="used|budget"}`,
  `onrouter_learning_budget_denied_total`, `onrouter_cache_learning_sketch_bytes{zone}`,
  `onrouter_cache_learning_aging_total{zone}`, `onrouter_cache_learning_events_total{zone,role=
  "admission_rejected|evicted_cold|retained"}`, `onrouter_queue_depth{zone,kind="min|max|learned"}`,
  `onrouter_queue_max_delay_ms{zone}`, `onrouter_queue_occupied{zone,kind}`,
  `onrouter_queue_events_total{zone,role}`, `onrouter_queue_wait_ms_total{zone}`,
  `onrouter_queue_depth_adjust_total{zone}`, `onrouter_queue_table_bytes{zone}`,
  `onrouter_queue_table_slots{zone,kind}`, `onrouter_vip_table_bytes`, `onrouter_vip_slots{kind}`,
  `onrouter_vip_score{kind="threshold|max"}`, `onrouter_vip_clients`, `onrouter_vip_decay_ms`,
  `onrouter_vip_events_total{role="passed|queued|rejected|promoted|demoted|collision"}`. The slot table is
  direct-mapped, so collisions are expected; the rule is that the **newcomer loses** — a key that hits a
  slot still holding reputation never erases it (`role="collision"` counts how often that happened, and a
  growing number means `table=` is too small). Reputation is keyed on the client address, so combining
  `vip_learning` with `set_real_ip_from` makes part of that key client-asserted; `-t` warns about it
  (it cannot change whether a request is allowed, only queue depth and cache retention). Runnable examples live in
  `conf/learning_cache.conf`, `conf/queue_learning.conf` and `conf/vip_learning.conf`; verification is
  `tools/learning_cache_e2e.py` (34/34), `tools/queue_learning_e2e.py` (42/42),
  `tools/vip_learning_e2e.py` (51/51) plus the unit tests in `learning.rs`, `limit.rs`, `proxy_cache.rs`
  and `vip.rs`. Not learned, on purpose: nothing per-user across processes, no rate limits being
  relaxed for anyone, and no model whose output can only be read off a dashboard — every effect above is
  asserted through the response a client actually got.
- **Still ONLine (last-known-good replay)**: a second, deliberately separate layer (`still_online.rs`)
  for "the origin is down, keep serving what this URL looked like". `proxy_cache` cannot host those
  copies: its capacity is an *entry count* derived from `keys_zone`, its lifetime is bound to the TTL and
  `use_stale` window, and its entries are exactly what a revalidation is supposed to replace — a
  last-known-good copy must survive all of that. So zones are declared as **byte** budgets
  (`still_online_zone <name> <size>;`, floored at one entry cap so a zone can always hold one copy) and
  opened per server or location with `still_online <zone>;` (`off` re-disables, and a location that
  references a zone nobody declared is a `-t` **error**, not a warning).
  Retention/pricing knobs per block: `still_online_max_age` (default 7 d — older than that the copy is
  dropped on read rather than shown), `still_online_max_body` (default 1 MiB — bigger responses are
  skipped, never truncated), `still_online_retry`/`_retry_max`/`_retry_deadline` (default 5 s / 300 s /
  30 min backoff curve for the background re-fetch).
  What enters a zone: an anonymous (no `Cookie`, no `Authorization`) **`GET`** whose upstream answer was
  `2xx` and carried **no `Set-Cookie`**, buffered, not an internal subrequest, and not excluded by
  `proxy_no_cache`. What replays: origin connect/read failure **or** an upstream 5xx (a crashing backend
  mostly answers 500/502 first), producing the stored status/body with `X-Still-Online: stale`, a real
  `Age`, and `$still_online` = `STALE` for logs/`add_header`; `X-Cache-Status` stays whatever the cache
  layer said because the two are independent. Cold miss stays honest: no `still_online_page` is served
  by default — you get the normal `502` (nginx has no such directive at all, so inventing a friendly
  error page here would only hide an outage).
  Recovery is health-triggered, not request-triggered: every replay parks the key in a bounded dirty
  table, and a background loop (1 s tick) re-drives an **anonymous** `GET` for due keys through the
  normal `process()` pipeline — so `rewrite`, location matching, `limit_req`, `allow`/`deny`
  and `auth_basic` apply to the re-fetch exactly as to a client request, and the successful answer is
  stored by the same write gate rather than a second copy path. Single-flight falls out of the table
  (`due_jobs` removes the key when it hands it out), failures back off exponentially and give up after
  the deadline, and a response that itself carries `X-Still-Online` counts as a failure (that "success"
  was only ever our own stale copy). Jobs for zones removed by a config reload are dropped with the
  zone.
  Credential rules are hardcoded and have **no off switch** — this is the part that would otherwise
  leak a login: `Set-Cookie` responses are never stored, `Set-Cookie` is stripped from every replay, and
  a credentialed request never writes. `still_online_allow_credentials on` relaxes *only* the credentialed
  read (a logged-in visitor may be shown the shared public copy); it cannot make a copy containing a
  session be stored or replayed. Non-`GET` methods are never replayed, so nobody's "action" is answered
  from another visitor's copy.
  A fourth hardcoded rule covers the case where the credential is not in a credential header: the copy
  key is `$scheme$proxy_host$request_uri`, so if the *upstream* says the response belongs to this one
  visitor — `Cache-Control: private` / `no-store` / `no-cache` / `max-age=0`, a zero hinted TTL, or
  `Vary` naming anything but `Accept-Encoding` — it is not stored either. A tenant authenticated by a
  custom header looks anonymous to the three credential gates above; the response's own cache directive
  is what says it is not public. Same predicate `proxy_cache` already uses, so the two layers cannot
  disagree.
  Metrics: `onrouter_still_online_total{kind="stored|served|refreshed|refresh_failed|rejected_credential|rejected_private|evicted"}`,
  `onrouter_still_online_pending_jobs`, `onrouter_still_online_zone_entries{zone}` and
  `onrouter_still_online_zone_bytes{zone,role="used|budget"}`. Verified by
  `tools/still_online_e2e.py` (25/25, real kill + restart of the backend) and 22 unit tests in
  `still_online.rs` / `router.rs`.
- **HTTP/2 serving**: ONRouter serves HTTP/2 over both transports. On TLS endpoints the `h2` protocol is
  negotiated through ALPN (`listen … ssl http2`). On cleartext endpoints `http2 on;` turns on
  prior-knowledge h2c: the connection layer peeks the first 24 bytes with `MSG_PEEK` (`TcpStream::peek`,
  non-consuming) and, only if they match the client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`),
  hands the socket to hyper's `http2` server; otherwise the same listener serves HTTP/1.1 unchanged — so
  h1 and h2c coexist on one port. Requests are handled by the same vhost/location pipeline as HTTP/1, and
  a single h2 connection multiplexes concurrent streams.
  (Verified by `tools/http2_e2e.py` via Node's core `http2` client — the local libcurl has no HTTP/2:
  cleartext h2c and TLS-ALPN h2 both return the configured bodies, HTTP/1.1 still works on the same
  cleartext port, and 3 concurrent streams on one h2 connection all reach `200`.)
  HTTP/2 to *upstreams* (h2 `proxy_pass`) and `server_tokens`/hpack tuning remain open.
- **Zero-downtime config hot-reload**: the routing table lives behind an
  `RwLock<Arc<Router>>` in `AppState`; every request takes a one-time snapshot of that `Arc`, and a
  background reload task swaps it for a freshly built one. On unix, `SIGHUP` triggers the reload
  (`SIGUSR1` still reopens logs; only `SIGTERM`/`SIGINT` shut down); on every platform a top-level
  `reload <interval>;` (e.g. `reload 2s;`, or `reload on;` = 1s) makes the task poll the main config's
  mtime and reload only when it changes. The reload rebuilds only the vhost/location table
  (`Router::rebuild_routing`) and reuses the process's already-bound listener set, so **no socket is ever
  closed or rebound** — there is no accept gap, existing keep-alive connections are never dropped, and
  new requests immediately hit the new routing (a connection sees the change on its very next request). A
  config that fails to parse or build is rejected and the old routing keeps serving. Reload does not
  re-bind newly-added `listen` addresses and does not re-apply `-g` globals or process-global runtime
  knobs (`worker_connections`, TLS acceptors) — those still need a restart.
  (Verified by `tools/hotreload_e2e.py`: a single never-reconnecting connection observes `v1→v2→v3` as the
  conf is edited in place; a fresh connection opened every 40ms records zero failures across the whole
  reload window (no accept gap); an intentionally broken (unbalanced-brace) config leaves the old routing
  serving and is not adopted; the child process stays alive with an unchanged pid file throughout.)
- **Lua script files reload by periodic self-check**: `*_by_lua_file` sources live in an in-memory
  cache and the request path only does a map lookup — it never `stat()`s. A background task `stat`s
  the cached scripts once per second (`lua_engine::LUA_FILE_CHECK_INTERVAL`; always on, independent
  of `reload off`) and re-reads only the ones whose mtime moved, so an edit lands within ~1s without
  a restart. The new source is then compiled once per VM into that VM's chunk cache, which mirrors
  OpenResty's `lua_code_cache on` (mlua's `Function` is `!Send`, so the cache holds `RegistryKey`
  handles instead). A half-written file keeps serving the previous version instead of returning 500,
  and each phase's bucket is capped so repeated edits cannot grow the cache without bound.
  (Verified by `tools/lua_watch_e2e.py`: with no `reload` directive in the config at all, six in-place
  edits each converge in 0.5–1.0s, every sampled request stays `200`, and the error log records one
  self-check reload per change.)
- **HTTP/3 serving (`listen … quic`)**: `listen <addr> quic` implies TLS and additionally binds a
  **QUIC/UDP** endpoint on that address (separate from the TCP listener, so the same port serves
  h1/h2 over TCP and h3 over UDP). The QUIC server config is pinned to TLS 1.3 with ALPN `h3` and reuses
  the same SNI multi-cert resolver as the TCP path (`certs::build_quic_server_config`). Each accepted QUIC
  connection runs an h3 server whose request streams feed the **same transport-agnostic request core**
  (`handle_request`) as HTTP/1 and HTTP/2: the h3 request body is erased into `ProxyReqBody`, every phase
  (vhost/location/rewrite/access/try_files/content/proxy/lua) is identical, and the returned `RespBody` is
  framed back over h3 with hop-by-hop headers stripped per RFC 9114. The TCP-TLS sibling of a quic
  endpoint advertises `Alt-Svc: h3=":<port>"; ma=3600` so real clients can discover HTTP/3. Hot-reload
  works for h3 too (shared `RwLock<Arc<Router>>`; the UDP socket is never rebound). WebSocket `Upgrade`
  tunnels remain HTTP/1.1-over-TCP only (h3 has no `Upgrade`).
  (Verified by `tools/http3_e2e.py` with the in-repo `orr-h3check` probe — quinn+h3, since local curl/Node
  have no HTTP/3: a real QUIC handshake + h3 GET returns `200` with protocol `HTTP/3` and the configured
  body; a ~15 KB response arrives complete across h3 `DATA` frames; 5 concurrent streams on one QUIC
  connection all reach `200`; and HTTP/1.1 over TLS still works on the same port with an `alt-svc: h3=`
  header present.)
- **Protocol matrix (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3, ws, wss)**: all six client-facing protocols are
  served by the same process and the same request core. HTTP/1.0 requests are answered with an
  `HTTP/1.0` status line, are never chunked, close by default and keep the connection alive when the
  client asks with `Connection: keep-alive` (bodies and request bodies work); HTTP/1.1 runs keep-alive
  on plaintext and TLS; HTTP/2 is served as h2c (prior knowledge) and as ALPN h2 over TLS; HTTP/3 is
  served over QUIC with TCP `Alt-Svc` advertisement on the same port; ws and wss are the HTTP/1.1
  Upgrade tunnel on a plaintext and a TLS listener respectively (the tunnel's backend may itself be
  `http://` or `https://`/`wss://`, see below). `tools/protocol_matrix_e2e.py` proves all of this in
  one run (37/37) and asserts the gateway's own access-log protocol field, not just the client's
  parse. Explicit boundaries: WebSocket over HTTP/2 (RFC 8441) and over HTTP/3 (RFC 9220) are not
  implemented — nginx does not implement them either — and `proxy_pass` to h2/h3 *upstreams* remains
  open; WebSocket `Upgrade` therefore stays an HTTP/1.1 feature by design.
- **TLS protocol selection (`ssl_protocols`)**: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;` sets an
  explicit *enabled version set*, nginx-style, and `ssl_min_version` is accepted as an alias for the
  "everything from this floor up" form. Several servers sharing one `listen` address merge their sets by
  **union**. The built-in **rustls** backend can only ever negotiate **TLS 1.2/1.3** (rustls 0.23 has no
  1.0/1.1), so within that world `ssl_protocols` precisely trims which of 1.2/1.3 are offered and a client
  pinned to an excluded version fails the handshake. A config that requests **TLS 1.0/1.1** therefore
  needs a second, opt-in backend: build with `cargo build --release --features native-tls` and any listener
  whose set includes a legacy version is routed to the **platform-native stack** (Windows → Schannel, via
  the `native-tls` crate), which negotiates the whole `min..max` range including 1.0/1.1; every other
  listener still uses rustls. Both backends feed the **same** hyper h1/h2 request loop through one
  `ServerStream` enum, so nothing downstream differs.
  Two honest caveats: the native path is legacy/HTTP-1.1-only (no ALPN `h2`, and Schannel's
  `Identity::from_pkcs8` accepts **RSA** keys only — an ECDSA cert like `certs_scenario/` is rejected, so
  supply an RSA keypair for legacy listeners), and a feature-off build simply logs that `native-tls` is not
  enabled and serves 1.2/1.3 instead.
  (Verified by `tools/tls_protocols_e2e.py` — rustls trims exactly: `only-1.2` answers a 1.2 client and
  rejects a 1.3-only client, `only-1.3` the mirror, the default serves both; and `tools/tls_legacy_e2e.py`
  — a throwaway runtime-generated RSA cert (never committed) proves the `--features native-tls` binary
  handshakes **TLS 1.0 and 1.1** and returns the configured body, while the same conf on the **default**
  rustls binary refuses 1.0/1.1 and still serves 1.2/1.3.)
- **HTTPS business matrix (multi-port / multi-domain / multi-cert)**: `tools/https_matrix_e2e.py` spins
  one process with five listeners (18443 multi-vhost TLS1.2+1.3, 18444 TLS1.2-only, 18445 TLS1.3-only,
  18446 cleartext, 18447 TLS+h2) and five self-signed certs generated on demand into `certs_https/`
  (git-ignored). 60 checks cover: SNI exact > wildcard > default (no-SNI, unknown SNI, wildcard-vs-apex,
  case-insensitivity, exact-beats-wildcard); hostname verification with each PEM used as its own CA
  (wrong name rejected); Host-vs-SNI cross-cases (certificate follows SNI, routing follows Host); port
  isolation; TLS1.2/1.3 trimming and cipher families (Python `ssl` plus independent `openssl s_client`
  probes); ALPN `h2` vs `http/1.1` with a real Node h2 request; same-port session resumption (TLS1.2
  session IDs, TLS1.3 stateful tickets, independently proven with `openssl -sess_out/-sess_in`); 480
  concurrent mixed requests with zero errors; and new-connection/handshake p50/p90/p99 at 8 threads.
  Observed gaps (reported as `GAP`, not failures): the session store/ticketer are now **process-wide**
  (a session established on one port resumes on another, verified by `tools/tls_session_e2e.py`), but
  they are still in-memory and ticket keys are ephemeral, so sessions do not survive a process restart;
  a client whose ALPN list has no overlap with a
  non-h2 listener gets rustls's fatal `no_application_protocol` alert, whereas nginx/OpenSSL continues
  with HTTP/1.1 and no ALPN. `ssl_certificate_by_lua*` is implemented
  (`tools/ssl_cert_lua_e2e.py`); still unimplemented: `ssl_session_store_by_lua`, OCSP stapling and
  server-side client-certificate verification (mTLS termination).

Remaining tradeoffs / roadmap:

- **Cosocket coverage**: `ngx.socket.tcp` now runs the full OpenResty method surface as scheduler
  yield points — `connect/send/receive(*l|*a|n)/receiveany/receiveuntil/shutdown/setsize/
  settimeout/setkeepalive`(backed by a real process-global connection pool)`/reconnect/close`
  (see the API section and `tools/sock_ext_e2e.py`). `ngx.socket.udp` (datagram I/O) is covered too
  (`tools/sock_udp_e2e.py`), as is `sock:tlshandshake` — the stream upgrades to a rustls client TLS
  connection and all receive variants run over it (`tools/sock_tls_e2e.py`). Still open:
  `ngx.location.capture`'s `share_all_vars`/`ctx` option passing remain open. `balancer_by_lua` +
  `ngx.balancer` is now implemented (see the API section and `tools/balancer_e2e.py`); its remaining
  gap is per-retry-attempt re-execution and `send`-timeout / `ngx.balancer.set_upstream_*` override
  APIs. The `$upstream_addr / $upstream_status / $upstream_header_time` log variables are recorded by
  the proxy path and exposed through `ngx.var` (`tools/upstream_e2e.py`).
- **`ngx.sleep` inside `ngx.timer` callbacks**: timer callbacks run synchronously under the VM lock,
  outside a scheduler coroutine, so `ngx.sleep` there is not yet a yield point (request-phase Lua is).
