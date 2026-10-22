# Design notes & roadmap

Deliberate choices, implemented extensions, and what is still open — each with the boundary that
makes the behaviour predictable rather than surprising.
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
  `proxy_cache_path … keys_zone=<name>:<size>` sets per-zone capacity (128 B/entry). Without `disk=on`
  the path is only a name — nothing is written and the directory is not even created; with `disk=on`
  it becomes that zone's cold tier root, honouring `max_size`/`levels`/`inactive` plus ONRouter's own
  `spill_after`/`max_value`, so an evicted-but-still-fresh response is served from disk later instead
  of going back to the origin. Freshness precedence matches nginx: the upstream's
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
  (Verified by `tools/proxy_cache_e2e.py` 21/21, `tools/cache_advanced_e2e.py` 32/32: concurrent
  coalescing, 502/error/updating stale replay, bypass/no_cache, keys_zone-driven LRU, and HEAD
  non-poisoning; `tools/observability_e2e.py` asserts the status→counter mapping 1:1; and
  `tools/cache_header_gap_e2e.py` 25/25 for the semantics aligned in this round: `add_header` variable
  expansion, `$upstream_cache_status` on a POST, multi-value `proxy_cache_bypass` / `proxy_no_cache`
  including all-`"0"` and never-set variables, and `proxy_ignore_headers` with a control location that
  does not ignore.)
  `proxy_cache_revalidate on;` is implemented: an expired entry takes *its own* `ETag` /
  `Last-Modified` to the origin, and a 304 refreshes the expiry and replays the stored body
  (`X-Cache-Status: REVALIDATED`) instead of transferring a second copy of an object nobody asked to
  change — `tools/proxy_cache_e2e.py` proves it by counting the origin's conditional answers
  separately from its full sends, so "asked" and "resent" cannot be confused. With `disk=on` the same
  reuse applies to entries read back from the cold tier. Still not implemented:
  `proxy_cache_purge`, `proxy_cache_lock_age`, `proxy_cache_background_update`, `Vary`-aware keying.
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
  `lua_code_cache on` (mlua's `Function` is `!Send`, so the cache holds `RegistryKey`
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

- **Cosocket coverage**: `ngx.socket.tcp` now runs the full cosocket method surface as scheduler
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
