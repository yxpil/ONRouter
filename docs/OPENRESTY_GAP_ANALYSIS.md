# ONRouter vs OpenResty — Gap Analysis

Updated: 2026-10-20 (v0.5.0, Windows host). This revision also folds in the
front-proxy seam (`front_proxy` profiles + `front_proxy_auto_trust`, its vendor-side config-only
example `conf/front_proxy_examples.conf`, and the measured cost of that seam), the
`log_debug!`/`log_info!` level gate that stopped building a `format!` string for a line that was
never going to be written, and the previous round's cache/header semantics
(`proxy_ignore_headers`, multi-value
`proxy_cache_bypass`/`proxy_no_cache`, `add_header` variable expansion,
`$upstream_cache_status`) and the REWRITE-phase `set`/`if` subset. Previous
revisions of this document were written before the `ngx_lua` async surface landed
and understated the implementation; this revision is status-first and cites the
E2E/unit evidence that enforces each row.

## Executive summary

ONRouter now covers the core nginx request pipeline plus a broad OpenResty Lua
surface: all request phases (including response filters and log phase), timers,
TCP/UDP cosockets, light threads, `ngx.semaphore`, subrequests (including
concurrent `capture_multi`), shared dicts, `resty.lock` / `resty.http` /
`resty.redis` / `resty.string` / `resty.cookie` / `resty.limit.req|count|conn`,
dynamic TLS certificate selection at handshake time, session resumption shared
across listeners, and in-process config/Lua hot reload. It also carries four
additions nginx/OpenResty has no equivalent for: a disk cold tier behind
`ngx.shared.DICT` (§1.2), the Still ONLine last-known-good replay layer (§1.3),
an opt-in learning layer — TinyLFU cache admission, per-key adaptive queue
depth and client reputation, all on one process-wide byte budget (§1.3) — and a
vendor-free front-proxy layer that puts recognition *after* realip's trust gate,
adds an egress mode and emits RFC 9209 `Cache-Status` (§1.3).

The remaining gaps are concentrated in four areas:

1. **Process model / zero-downtime binary upgrade** — no master/worker split, no
   USR2 upgrade (design and Linux test plan in `docs/USR2_HOT_UPGRADE.md`).
2. **Raw Lua performance** — mlua/Lua 5.4 interpreted vs LuaJIT; expect roughly
   0.7–0.9x on Lua-only endpoints and much faster static paths on Windows
   (Linux numbers still pending, see `docs/LINUX_AB.md`).
3. **OpenResty-specific ecosystem breadth** — `ssl_session_store_by_lua`,
   OCSP stapling, `stream_*_by_lua`, `resty.websocket/jwt/mysql/dns/upload/...`.
4. **Long-tail `ngx.*` semantics** — `ngx.on_abort` invocation, full
   `share_all_vars` capture options, HTTP/2 upstreams, and a few phase/API
   corner cases listed below.

## 1. Implemented (with evidence)

### 1.1 Configuration and lifecycle

| Feature | Status | Evidence |
|---|---|---|
| nginx config syntax, `include`, `-p/-g/-e`, `http{}` flattening, pid file | ✅ | parser unit tests, `compat_test.py` |
| `*_by_lua_block { … }` for every phase | ✅ | lexer unit tests (nested tables/strings/comments/long brackets, line numbers) |
| Unknown top-level directive warnings; `worker_processes`/`log_format` explicitly “ignored” | ✅ | `router::warn_unknown_top_level`, startup log |
| `set` / `if` / `return` in the REWRITE phase, in config order (subset) | ✅ | `tools/set_if_e2e.py`, `engine`/`router` unit tests; unsupported `if` forms are parse errors, server-level ones warn |
| `still_online*` directives: byte-budgeted zones, server→location inheritance, `-t` hard error on a zone nobody declared, warning on parameters in a block with no zone | ✅ | `router` unit tests `still_online_*` (6), `-t conf/still_online.conf` prints the zone list |
| `init_by_lua*` once per VM | ✅ | `lua_engine` unit tests |
| `init_worker_by_lua*` once per VM after scheduler start; timers/cosockets/`ngx.sleep` work | ✅ | `tools/init_worker_package_e2e.py` 21/21 |
| `lua_package_path` (`$prefix`, `${prefix}`, `;;`, repeatable) | ✅ | same suite 21/21 + unit tests |
| `SIGHUP` / `reload <interval>;` in-process routing hot swap; Lua file mtime self-check | ✅ | `tools/hotreload_e2e.py`, `tools/lua_watch_e2e.py` |
| `*_by_lua_file` changes picked up without restart; compiles once per VM | ✅ | `tools/lua_watch_e2e.py` |
| USR2 zero-downtime binary upgrade | ❌ | design only (`docs/USR2_HOT_UPGRADE.md`); blocked on Linux verification |

### 1.2 Lua API (implemented and exercised)

- **Phases**: `rewrite`, `access`, `content`, `header_filter`, `body_filter`, `log`,
  `balancer`, `ssl_certificate`, `init`, `init_worker` — inline, `_file`, and
  `_block` forms where applicable.
- **Response**: `ngx.say/print/status/exit/redirect/exec`, `ngx.header` read/write
  (table values emit/read repeated lines, e.g. multiple `Set-Cookie`),
  `header.set`, `resp.get_headers`, **`ngx.flush([wait])`** (streaming head/body;
  64 KiB auto-flush; h1 chunked and h2 DATA paths), **`ngx.send_headers()`**,
  **`ngx.eof()`**, `ngx.headers_sent`; response filters keep the location buffered.
  Evidence: `tools/lua_flush_socket_e2e.py` 23/23, `tools/api_compat_e2e.py` 57/57.
- **Request**: method/path/query/header mutation APIs, `read_body`, `get_body_data`,
  `set_body_data`, `discard_body`, `init_body`/`append_body`/`finish_body` (commit a
  rebuilt body + accurate `Content-Length`, also used by `proxy_pass`),
  `get_post_args`, `raw_header`, `start_time()`, `http_version()`,
  `is_internal()`, **`ngx.req.socket([raw])`** with `receive` / `receiveuntil` /
  `close`.
- **Control**: `ngx.sleep`, `ngx.exit`, `ngx.exec`, `ngx.redirect`,
  `ngx.semaphore.new/count/post/wait` (scheduler-yielding per-VM semaphore),
  `ngx.on_abort` (registration only; disconnect hook not wired).
- **Cosockets**: `ngx.socket.tcp` (`connect/send/receive*/receiveany/receiveuntil/
  settimeout/setsize/setkeepalive/tlshandshake/sslhandshake/reconnect/close/
  getstats/getreusedtimes`, shared keepalive pool), `ngx.socket.udp`.
  Evidence: `cosocket`, `sock_ext`, `sock_tls`, `sock_udp` suites.
- **Concurrency**: `ngx.thread.spawn/wait/yield/kill`; `ngx.location.capture`
  (full subrequest pipeline, nesting + depth guard, `method`/`body`/`args` opts);
  `ngx.location.capture_multi` (concurrent captures via light threads);
  `ngx.timer.at/every/running_count/pending_count`.
- **Shared state**: `ngx.shared.DICT` full method surface (sharded, capacity/LRU,
  `get_keys`, `expire`), `resty.lock`, `ngx.socket.tcp` keepalive pool. Beyond
  OpenResty (whose DICT is memory-only), a zone can declare a disk cold tier —
  `lua_shared_dict name 24k disk=cache/tier max_disk=4m spill_after=2 max_value=2k`
  — so eviction victims that are still warm spill to disk and get promoted back on
  the next read, while one-shot data is dropped as before. The Lua API is
  untouched: unchanged OpenResty scripts see identical results (asserted by
  `tools/disk_cache_e2e.py` running one script against both a diskless and a
  tiered zone). Evidence: `tools/disk_cache_e2e.py` 53/53.
- **Encoding/crypto/regex**: base64, URI escape/unescape, args encode/decode,
  `ngx.re.*` (`match/find/gmatch/sub/gsub/opt`), `md5/sha1/sha256` and `_bin`
  variants; `resty.string`.
- **Bundled resty modules**: `resty.lock`, `resty.http`, `resty.redis`,
  `resty.string`, `resty.cookie`, `resty.limit.req` / `resty.limit.count` /
  `resty.limit.conn` (pure-Lua originals over the native cosocket + shared-dict
  surface, not upstream source copies). Evidence: `tools/resty_e2e.py`,
  `tools/resty_http_e2e.py`, `tools/resty_redis_e2e.py`,
  `tools/api_compat_e2e.py`.
- **Response filters**: `header_filter_by_lua*` and `body_filter_by_lua*` on both
  Lua/static and proxied responses (proxied responses are buffered so filters see
  the whole body). Evidence: `tools/proxy_filter_e2e.py`, `tools/sub_filter_e2e.py`.
- **Variables**: `ngx.var` (request/response/upstream variables, incl.
  `$upstream_cache_status`; `$uri` and `$status` writable), plus derived variables
  from `map` / `geo` / `split_clients` and request variables written by `set`,
  resolved identically in Lua and config interpolation (`engine::resolve_var` is the
  single seam; `$host` drops the port, `$http_host` does not).

### 1.3 HTTP / TLS / upstream

- HTTP/1.1 (keepalive, upgrades/WebSocket tunnel), HTTP/2 (ALPN + h2c
  prior-knowledge), HTTP/3 (QUIC + Alt-Svc).
- Multi-certificate SNI vhosts on shared listen ports; exact > wildcard > default;
  Host routing independent of SNI.
- TLS 1.2/1.3 via rustls; legacy TLS 1.0/1.1 via the optional `native-tls`
  platform backend.
- **TLS sessions**: process-wide `ssl_session_cache` (`off` / `builtin[:n]` /
  `shared:name:size`, approximate LRU) plus a stateless ticketer, shared by every
  listener and SNI config; `ssl_session_tickets on|off`. Cross-port resumption
  verified with `openssl -sess_out/-sess_in`; evidence `tools/tls_session_e2e.py`.
- **`ssl_certificate_by_lua*` + `ngx.ssl`**: per-SNI handshake scripts with
  `server_name`, PEM cert/key parse, `set_cert/set_priv_key/clear_certs` and legacy
  aliases; dynamic configs cached by cert/key hash; script error or
  `ngx.exit(ngx.ERROR)` aborts the handshake. Evidence:
  `tools/ssl_cert_lua_e2e.py` 21/21 (TLS1.2, ALPN h2, `_file`, two vhosts).
- Reverse proxy: HTTP/HTTPS/WSS upstreams, mTLS client certs, connection pool,
  `proxy_next_upstream`, passive + active health checks, request buffering on/off,
  streaming response, `proxy_cache`, `proxy_redirect`/cookie rewrites, gzip,
  `sub_filter`, real-IP, rate/conn limits (over-rate can wait in a bounded, per-key-depth-adaptive
  queue instead of 429 — see **Learning** below), basic auth, `stream{}` L4 proxy with
  `ssl_preread`, `resolver` async DNS.
- **Proxy cache**: in-memory named zones with capacity from
  `proxy_cache_path … keys_zone=<name>:<size>` (LRU eviction — or, with `proxy_cache_learning`,
  admission and the eviction victim decided by a TinyLFU frequency sketch; expiry cleanup
  every 128 stores), `proxy_cache_lock`/`_lock_timeout` request coalescing,
  `proxy_cache_use_stale` (`error`, `timeout`, `updating`, `http_4xx/5xx`),
  `proxy_cache_bypass`/`proxy_no_cache` with nginx's multi-value truthiness (a value counts only when
  it expands non-empty and is not `"0"`; bypass skips the read but still stores, `no_cache` only skips
  the store), `proxy_ignore_headers` (decision-view only — an ignored `Cache-Control: no-store` or
  `Set-Cookie` stops blocking the store yet is still forwarded), upstream freshness precedence, HEAD
  lookup without HEAD-response cache population, `X-Cache-Status: HIT|MISS|EXPIRED|BYPASS|STALE` and
  the `$upstream_cache_status` variable (empty string when the request never engaged the cache).
  Evidence: `tools/proxy_cache_e2e.py` 13/13, `tools/cache_advanced_e2e.py` 32/32,
  `tools/cache_header_gap_e2e.py` 25/25 (add_header interpolation, `$upstream_cache_status`
  on a POST, multi-value bypass/no_cache, ignore_headers with control locations).
- **Still ONLine (last-known-good replay, ONRouter-only)**: separate byte-budgeted zones
  (`still_online_zone <name> <size>;`) opened per server/location (`still_online <zone>|off;`) with
  `still_online_max_age`/`_max_body` retention and `still_online_retry`/`_retry_max`/`_retry_deadline`
  backoff; replays on origin failure *or* upstream 5xx as `X-Still-Online: stale` + `Age` +
  `$still_online`, and re-fetches dirty keys anonymously through the normal request pipeline once the
  origin answers again (single-flight, exponential backoff, bounded queue). Storing and replaying
  credentials is blocked by three hardcoded rules (`Set-Cookie` never stored, never replayed;
  credentialed requests never write and by default never read). Evidence:
  `tools/still_online_e2e.py` 25/25 (real kill + restart), 16 `still_online` + 6 `router` unit tests.
- **Learning (ONRouter-only: cache admission, queue depth, client reputation)**: `learning on;`
  (**default off** — off means every learning lookup short-circuits) plus one process-wide byte ledger
  `learning_memory_budget <size>;` (default 1 MiB) that the three learned structures claim from and
  release back, so total footprint is a configured number, not an emergent one.
  `proxy_cache_learning <zone> [sketch=<size>]` puts a 4-row × 4-bit count-min sketch in front of
  `proxy_cache`: a newcomer is admitted only if its estimate beats the coldest of the 8 oldest entries,
  aging is a whole-table halving (weighted writes still advance the clock, so a saturating scanner
  cannot freeze it). `limit_req_queue <zone> [depth] [depth_min] [max_delay]` turns over-rate into a
  bounded wait with the token reserved at admit (a queued request never 429s after waiting), and
  `limit_req_learning <zone> [table=<size>]` lets each key's own *finished* burst length (committed by
  a gap over 2× the token period) pick its depth inside `[depth_min, depth]`; reaching `depth × 4`
  without ever ending is classified as a flood and wipes the memory. `vip_learning [table] [min]
  [decay]` scores an address purely from the limiter's verdicts (`+1` in-rate, `0` queued, `−8`
  rejected, `−1` per decay of silence) and acts in exactly two places: a trusted key's queue ceiling
  (never its rate) and a `+4` sketch boost applied after admission for objects it caused to be cached
  (retention, never queue-jumping). Claims that do not fit are refused, counted and logged, and that
  feature falls back to its unlearned behavior; referencing an undeclared zone is a `-t` error for both
  the queue and the cache side. Evidence: `tools/learning_cache_e2e.py` 34/34,
  `tools/queue_learning_e2e.py` 42/42, `tools/vip_learning_e2e.py` 51/51, unit tests in
  `learning.rs`, `limit.rs`, `proxy_cache.rs`, `vip.rs`, `router.rs`.
- **Front-proxy / CDN awareness (ONRouter-only, vendor-free)**: nginx only has `realip`, which trusts one
  header from one range list and knows nothing about *who* is in front. ONRouter declares each front as a
  profile of roles (`front_proxy <name> { probe/ip_header/country_header/proto_header/host_header/trust }`)
  so the engine contains no vendor name or vendor branch — adding a provider is config. Recognition and
  trust stay separate: a probe match only labels (`$front_proxy`, `onrouter_front_proxy_total{role="matched"}`),
  and every header-derived value requires the direct peer inside `trust` ∪ `set_real_ip_from`. `detect`
  labels without rewriting; `egress` repoints `$remote_addr` (logs, `geo`, `limit_req`, ACL, VIP reputation,
  cache keys) and `$scheme` at what the front reported, forwards the real client/protocol upstream and emits
  its own `Cache-Status: onrouter; detail=…` (RFC 9209, appended after an upstream entry, buffered path only,
  verified peers only). `front_proxy_auto_trust on` is the only way a profile's own ranges become a rewrite
  authority, and it warns once per profile at runtime and names the vhost at `-t`; a mode typo, `egress` with
  no range anywhere, `auto_trust` outside `egress` and a bad `trust` CIDR are `-t` errors.
  Evidence: `tools/front_proxy_e2e.py` 54/54 (six ports: rewrite proven through the access log and a `geo`
  variable, forged headers proven inert, `limit_req` splitting 8 faked clients on the egress vhost while both
  controls lump them, real `MISS→HIT` with exactly one origin request, one-shot advisories), 13 `front_proxy`
  + 1 `router` unit tests. Vendor knowledge stays data, not code: `grep -a -i -o` over the 0.5.0 release binary
  finds 0 occurrences of `Cloudflare`/`Fastly`/`CloudFront`/`Akamai` and 0 of their header names (`CF-Ray`,
  `True-Client-IP`, `CloudFront-Viewer-Address`, …), while the control words `front_proxy`/`auto_trust`
  occur 48/10 times — the only baked-in header names are nginx's own (`x-real-ip` as the `real_ip_header`
  default, `x-forwarded-for` in the header interning table and in `$proxy_add_x_forwarded_for`).
  `conf/front_proxy_examples.conf` ships the copy-paste profiles for Cloudflare, CloudFront and a plain-XFF
  self-built edge, each naming where to refresh that provider's ranges (ranges are a rolling announcement),
  and that file is itself executed rather than eyeballed: `tools/front_proxy_examples_e2e.py` 24/24 — config
  layer (`-t` accepts it and echoes all three profiles, the address chain in written order, 22/0/3 ranges, no
  `auto_trust` advisory on a `detect`-only example) and runtime layer (a full Cloudflare header set labels
  `cloudflare-edge` while `$remote_addr`, the access-log first field and both rewrite counters stay untouched
  because the loopback peer is outside the ranges; the probe is AND-ed, so `CF-Connecting-IP` alone is not
  recognised while `CF-Ray` alone is; CloudFront's `ip:port` shape labels `cloudfront-edge` and a profile with
  0 ranges can never self-authorise; XFF alone labels the self-built profile; a request claimed by two
  profiles goes to the first declared; per-profile counters do not cross accounts).
- **REWRITE-phase conditionals**: `set $var <value…>` (request-scoped, interpolated, last write wins,
  may shadow a built-in) and `if ($v)` / `if (!$v)` / `=`, `!=`, `~`, `~*`, `!~`, `!~*` wrapping
  `rewrite`/`set`/`return`, executed in config order alongside `rewrite`. Unsupported forms (nested
  `if`, file tests `-f/-d/-e/-x`, `if` without a block) are parse-time errors, never silent
  no-ops. Evidence: `tools/set_if_e2e.py` 26/26, unit tests `if_*`, `set_*`,
  `rewrite_set_if_keep_the_written_order`.
- **Scheduler fast path**: first Lua segment runs inline when the VM lock is free;
  only yielding phases hand off to the scheduler. Counters exposed as
  `onrouter_lua_phase_{inline,adopted,scheduled}_total`; E2E traffic shows
  100/100 inline for a no-yield script and 50/50 adopt for `ngx.sleep`.

### 1.4 Operations

- Prometheus metrics via `content_by_rust metrics`: uptime, accepted/active/capacity,
  requests, status classes, Lua scheduling counters, per-upstream node
  connections/health/success/failure, cache status (`hit/miss/expired/bypass/stale`),
  Still ONLine copy events (`stored/served/refreshed/refresh_failed/rejected_credential/
  rejected_private/evicted`,
  pending re-fetch jobs and per-zone entries/used/budget bytes),
  learning state (`onrouter_learning_enabled`, `onrouter_learning_memory_bytes{role="used|budget"}`,
  `onrouter_learning_budget_denied_total`, per-zone `onrouter_cache_learning_sketch_bytes`/
  `aging_total`/`events_total{role="admission_rejected|evicted_cold|retained"}`, per-zone
  `onrouter_queue_table_bytes`/`table_slots`/`depth{kind="min|max|learned"}`/`occupied`/`events_total`/
  `wait_ms_total`/`depth_adjust_total`, and `onrouter_vip_table_bytes`/`slots`/`score`/`clients`/
  `decay_ms`/`events_total{role="passed|queued|rejected|promoted|demoted"}`),
  TLS handshake failures, limit_req/limit_conn rejections, dropped access-log lines
  (`metrics.rs`, `tools/metrics_e2e.py` 38/38, `tools/observability_e2e.py` 26/26).
- Access log (combined) with `$request_time` and the
  `$upstream_addr`/`$upstream_status`/`$upstream_header_time` triple (including the
  Upgrade path; `- - -` when no upstream), plus error log, `SIGUSR1`/`SIGHUP` log
  reopen, and a counted non-blocking drop path under queue pressure.
- Graceful shutdown with `shutdown_grace`, `worker_connections`, `keepalive_requests`.
- Windows and Linux builds; Windows is the verified host for this snapshot.

## 2. Remaining gaps (ranked)

### 2.1 High

| Gap | Impact | Notes |
|---|---|---|
| USR2 zero-downtime binary upgrade | deploy needs a restart (or external LB draining) | Requires SO_REUSEPORT handover or master/worker + FD inheritance; see `docs/USR2_HOT_UPGRADE.md` |
| LuaJIT-class performance | Lua endpoints ~0.7–0.9x OpenResty on Windows | interpreted Lua 5.4; static/proxy paths are competitive. Linux baseline pending (`docs/LINUX_AB.md`) |
| `ssl_session_store_by_lua*` | no custom session store | memory store + ticketer are fixed |
| OCSP stapling | no stapling | `proxy_tls.rs` has an unused OCSP slot only |
| `stream_*_by_lua*` | L4 proxy has no Lua hooks | `stream{}` supports SNI preread + upstream only |
| HTTP/2 upstream (`proxy_http_version 2`) | upstream h1 only | client-side h2/h3 fully supported |

### 2.2 Medium

- `ngx.on_abort` callback is accepted but not invoked on client disconnect.
- `ngx.location.capture` lacks `share_all_vars` / `ctx` option passing; capture
  response shares no request context.
- `ngx.req.socket` reads the buffered body only; it is not a duplex raw socket
  (no `send`/`shutdown` on the client socket).
- `header_filter_by_lua`/`body_filter_by_lua` force buffering (no streaming through
  filters; same tradeoff as nginx filters but no `proxy_buffering off` bypass).
- `return` does not interpolate variables (`engine.rs:1255` copies the text verbatim,
  including the 30x `Location`). Verified on a live listener:
  `return 200 "ip=$remote_addr uri=$uri"` responds `ip=$remote_addr uri=$uri`, while
  nginx returns the values. `content_by_rust echo`/`status` *do* interpolate, and so
  do header/cache-key surfaces, which makes the inconsistency easy to miss.
- Intentional divergences kept on purpose (both are fail-safe choices, not gaps):
  `if (…) { return …; }` applies its `return` **after** the ACCESS phase — together with a
  bare `return` — so a conditional response can never preempt `allow`/`deny`/`auth_basic`
  (nginx runs `return` in the rewrite module, before access); and `add_header` (plus
  `proxy_set_header`, cache keys and `access_log`) leaves a token that is not an nginx
  variable at all as a **literal** (`$no_such_var_xyz` echoes back) instead of failing the
  config like nginx's parse-time `unknown "…" variable`, so a typo stays visible rather than
  silently empty. A *known* variable that has no value for this request expands to an empty
  string, which is nginx's answer.
- `X-Cache-Status: BYPASS` also covers "origin answered but the response was deliberately not
  stored" (`proxy_no_cache`, `Set-Cookie`, `min_uses`, non-cacheable method). nginx has no such
  header; its `$upstream_cache_status` would report `MISS` there, which the variable itself now does.
- Still ONLine is a ONRouter-only layer with no nginx/OpenResty counterpart, so its divergences are
  choices rather than gaps: `X-Still-Online: stale` + `Age` + `$still_online` mark a replay (nginx's
  `proxy_cache_use_stale` replies `STALE` and cannot survive a zone being emptied); a cold miss stays a
  plain `502` because there is no nginx directive to imitate and an invented "outage page" would only
  hide incidents; only anonymous `GET` + `2xx` responses without `Set-Cookie` are stored, and the three
  credential rules (never store `Set-Cookie`, never replay `Set-Cookie`, credentialed requests never
  write) have no configuration switch — `still_online_allow_credentials on` relaxes only the
  credentialed *read*; the recovery re-fetch is an anonymous request routed through the normal
  pipeline, so `limit_req`, `allow`/`deny` and `auth_basic` gate background traffic exactly as they gate
  clients (a deliberately stricter model than nginx, which has no background re-fetch of last-known-good
  copies at all).
- Native-tls legacy backend ignores `ssl_certificate_by_lua` and session options.
- With no ALPN overlap (client offers only `h2`, vhost serves HTTP/1.1), rustls
  aborts with a `no_application_protocol` alert; nginx/OpenSSL continue the
  handshake and serve HTTP/1.1. Surfaced as the two `GAP` lines in
  `tools/https_matrix_e2e.py` (that suite still exits 0, so read its log, not its
  exit code).
- QUIC listeners use the static SNI cert store; handshake scripts do not run on
  QUIC.
- `init_by_lua*` / `init_worker_by_lua*` / `lua_package_path` changes require a
  restart: `SIGHUP` swaps routing only, not the Lua engine.
- `init_worker_by_lua*` runs once per VM (16 times), not once per OS process;
  matching nginx semantics would require the multi-process model.
- Relative `lua_package_path` entries resolve against the process CWD, not the
  config directory (use `$prefix` or absolute paths).
- `ssl_session_cache shared:` is an in-process LRU, not a cross-process shared
  memory zone; capacity is per process.
- `proxy_cache` is memory-only: `proxy_cache_path`'s directory/`levels`/`max_size`
  are ignored (only `keys_zone` capacity is used), so entries do not survive a
  restart. Missing: revalidation (`proxy_cache_revalidate`, If-None-Match → 304),
  `proxy_cache_purge`, `proxy_cache_lock_age`, `proxy_cache_background_update`,
  `proxy_cache_convert_head` (HEAD may read but never populate) and `Vary`-aware
  keying.

### 2.3 Ecosystem / long tail

- Modules: `resty.websocket`, `resty.jwt`, `resty.mysql`, `resty.dns.resolver`,
  `resty.upload`, `resty.core` — absent. `resty.cookie` and `resty.limit.{req,
  count,conn}` are now bundled (see above).
- Third-party nginx modules (echo, headers-more, set-misc, srcache, memc, redis2,
  drizzle) are not loadable; use `content_by_rust` or Lua instead.
- Cron-like `ngx.timer` workers exist, but there is no `init_worker`-based
  “privileged agent”/shared-memory zone pruning parity.
- No built-in WAF/OAuth/LDAP/SAML; basic auth + IP ACL only.
- Test harness: ported assertion scripts, not the full Perl `Test::Nginx` suite
  (the official suite is vendored as semantics reference only).

### 2.4 nginx directives that parse, warn and are ignored

Verified by running `onrouter -t` on a config that uses each of them (2026-10-19):
every one emits `未知指令 '<name>'（已忽略…）` and the config test still **passes
with exit code 0** — but `-t` now prints every collected warning line to stdout
(`告警 N 条：` + one bullet each), so an ignored directive is visible in the very
command an operator runs before deploying. In the surfaces that *do* interpolate (`proxy_set_header`,
`add_header`, `proxy_cache_key`, `proxy_cache_bypass`, log lines), a variable nginx
knows but has no value for this request renders as empty and a name that is not a
variable at all is left literal (`interpolate_vars`, `proxy.rs:756`); the template is
tokenized **before** any value is substituted, so a value that starts with a digit —
the `127.0.0.1:18271` injected for `$proxy_host` in a cache key — cannot swallow the
`$scheme` that precedes it (an earlier text-replacement build produced keys like
`$scheme127.0.0.1:18271/lkg/v`, i.e. a silently unexpanded prefix that still matched
nginx's behaviour only by accident of consistency); elsewhere
variables are not expanded at all — see the `return` note in §2.2. So this is a
migration hazard, not a crash: a security control copied from a nginx config
(`auth_request`, `valid_referers`, `secure_link`) can be absent while the gateway
reports a healthy start — read the warning lines, not just the exit code.

| Scope | Directives | Notes |
|---|---|---|
| top | `worker_shutdown_timeout`, `ssl_stapling` | `shutdown_grace` is ONRouter's own drain knob; stapling is a §2.1 gap |
| server | `valid_referers`, `secure_link`, `secure_link_md5`, `gzip_static` | referer/link checks: do in Lua or `content_by_rust`; pre-compressed `.gz` serving falls back to on-the-fly gzip |
| server | `return`, `rewrite`, `set`, `if` | REWRITE-phase steps are only executed inside a `location`; a server-level one now warns with its line number and is skipped, where it used to be a silent no-op |
| location | `limit_rate`, `auth_request`, `dav_methods`, `grpc_pass`, `fastcgi_pass`, `mirror`, `proxy_bind`, `proxy_cache_revalidate` | Downstream-protocol upstreams (`grpc`/`fastcgi`) and upstream source binding are simply not implemented. `if` is no longer in this list: the `set`/`if` subset above is implemented and unsupported `if` forms are parse-time errors |
| scope | `client_body_timeout` (and the other process timeouts) is **root-level only** | `client_body_timeout 2s;` inside `server {}`/`location {}` warns as unknown and is ignored — it is a `Settings` field, not a per-vhost override (nginx allows it per server/location) |

## 3. Performance snapshot (Windows, 2026-10-18)

`python bench_ab.py --sweep 1,4 --requests 12000` on a 16-logical-core Windows
host (`bench_win_ab.json`); ratios are ONRouter/OpenResty:

| Endpoint | c=1 | c=4 |
|---|---:|---:|
| static `index.html` | 3595/s vs 2863/s (**1.26x**) | 8025/s vs 3614/s (**2.22x**) |
| Lua `content_by_lua` | 6309/s vs 7111/s (0.89x) | 15197/s vs 19850/s (0.77x) |
| Lua `shared.DICT` serialized incr | 6445/s vs 7778/s (0.83x) | 15091/s vs 20784/s (0.73x) |
| Lua `*_file` | 6295/s vs 7907/s (0.80x) | 15733/s vs 22109/s (0.71x) |
| reverse proxy upstream | 3411/s vs 96/s (artifact) | 8041/s vs 2721/s (2.96x) |

Caveats: Windows nginx uses `select()` and a limited worker count; OpenResty's
c=1 proxy row (96 req/s, 14 ms) is an environment artifact; the Python client
ceiling moved between runs (9844 → 8865–9193 req/s); all rows are keep-alive GET
without TLS. Do not treat these as Linux/production conclusions — rerun
`tools/linux_ab.sh` on Linux and record the median of 3 runs.

Fast-path A/B (same Windows host, before → after, two after runs): Lua
`content_by_lua` c=1 6678 → 6518/6428, c=4 15043 → 15366/14882; DICT c=1 5807 →
5909/5762, c=4 14262 → 14893/14861; static and proxy rows tracked the client
ceiling. Conclusion: neutral within noise on this host; the win is architectural
(no scheduler hop), observable in the `inline/adopted/scheduled` counters.

## 4. Verification inventory

- Unit tests: 386 passing (`cargo test --workspace`; 373 in onrouter-server +
  13 in onrouter-config).
- E2E suites (real traffic), this snapshot:
  - `lua_concurrency` 5/5, `thread` 24/24, `cosocket` 7/7, `subrequest` 18/18
  - `lua_flush_socket` 23/23, `init_worker_package` 21/21, `ssl_cert_lua` 21/21,
    `metrics` 38/38, `observability` 26/26, `api_compat` 57/57, `dict_api` 42/42,
    `disk_cache` 53/53 (the DICT cold tier: real spill/promote traffic through a
    24 KiB memory zone, zero-IO true misses, corrupt-entry rejection, and the
    `flush_all` generation guard)
  - `cache_header_gap` 25/25 (the cache/header semantics round: `add_header`
    variable expansion incl. known-but-valueless → empty and non-variable → literal,
    `$upstream_cache_status` = `MISS`/`HIT`/empty-on-POST, multi-value
    `proxy_cache_bypass`/`proxy_no_cache` with `"0"` and unset variables,
    `proxy_ignore_headers` Cache-Control / Set-Cookie against control locations)
  - `set_if` 26/26 (the REWRITE-phase round: `set` ordering/interpolation/built-in
    shadowing, every `if` operator, `if`-gated `rewrite break`/`last`, and
    an `if (…) { return … }` that cannot preempt `allow`/`deny`)
  - `still_online` 25/25 (the last-known-good round, with the backend really killed
    and restarted: copy written on healthy `GET`, replayed as `200` +
    `X-Still-Online: stale` + `Age` with a byte-identical body, credentialed `GET`
    kept out of both the write and (by default) the read side, replays never carrying
    `Set-Cookie`, `POST` staying `502`, `Set-Cookie`/over-`max_body` responses never
    entering the zone, a no-zone control location always plain `502`, then after
    recovery both dirty keys re-fetched (`refreshed +2`), the queue drained, and the
    second outage replaying the *recovered* version)
  - `learning_cache` 34/34, `queue_learning` 42/42, `vip_learning` 51/51 (the learning
    trio, each with a control path so the effect cannot be confused with the baseline:
    cache — a 8-entry learning zone keeps its hot object through 40 one-shot URLs while
    an identically-sized plain-LRU zone loses it; queue — one `10r/s burst=0` zone behind
    three locations, no queue (1 released + `Retry-After`), fixed queue (1 + `depth`),
    learning (first burst 2 released, second identical burst 9 with **no config change**
    and `learned` depth jumping to 8, then a dense flood knocking it back); VIP — virtual
    client addresses injected through `realip`, an address promoted after sparse in-rate
    traffic getting the full 8 queue slots with zero 429s where the same burst got 1 slot
    before promotion, its cached object surviving a displacement round that evicted the
    identical object written by a no-reputation address, then losing VIP status and depth
    under a flood; all three assert `onrouter_learning_memory_bytes{role="used"}` equals
    the sum of the per-zone table bytes under `learning_memory_budget`, plus the `-t`
    round: directives recognized, per-zone learning summary printed, an undeclared zone
    referenced by `limit_req_queue`/`limit_req_learning`/`proxy_cache_learning` rejected,
    a `limit_req_zone`/`limit_conn_zone` keyed on anything but `$remote_addr` /
    `$binary_remote_addr` rejected (that variable is never expanded on the request path,
    so accepting it would mean silently limiting by IP), and `set_real_ip_from` alongside
    `vip_learning` warned about (client-asserted address is the reputation trust root)
  - `front_proxy` 54/54 (the CDN-awareness round over six ports: egress rewriting `$remote_addr` proven
    through the access log's first column and a `geo` variable rather than through a header echo, forged
    vendor headers from an out-of-range peer proven to change nothing while still being *labelled*,
    `auto_trust off` and `detect` each leaving the node address, the header-dialect fall-through
    (vendor-specific header → XFF, percent-encoded IPv6+port, a poisoned `CN;evil` country value rejected, JSON
    and chained protocol headers accepted), `limit_req` splitting 8 faked clients into 8 buckets on the
    egress vhost while both control vhosts lump them onto the node address, a real `MISS→HIT` pair with
    `Cache-Status` and exactly one origin request, ours appended after an upstream `Cache-Status` entry,
    none emitted for an unverified peer, per-profile metric deltas, one line per profile after dozens of
    blocked requests, the startup banner, and the five `-t` rejections)
  - `security_matrix` 36/36 (the twelve findings from `docs/SECURITY_AUDIT.md`, each
    probe asserting the pre-fix failure mode is gone: fail-closed `auth_basic` and
    `allow/deny`, streamed-body `client_body_timeout` → 408, raw undecoded Upgrade
    request-target, htpasswd change visibility, `sub_filter` memory ceiling, Lua
    runaway-loop preemption, Still ONLine refusing `Cache-Control: private` copies,
    cold-tier `create_new` temp files, non-address limit keys, VIP slot collisions), `rce_matrix` 27/27 (Lua source/path injection,
    `internal` location escape, `proxy_pass` SSRF against a canary listener,
    encoded-CRLF splitting), `static_stream` 19/19, `streaming_body` 7/7
  - Full regression: 73 scripts (8 root scenario/compat/security/static/upstream
    suites + every `tools/*_e2e.py` incl. TLS matrix, HTTP/2, HTTP/3, hot reload,
    the cache/header-semantics gap suite, the `set`/`if` suite, cache, the DICT disk
    cold tier, Still ONLine, the three learning suites, CDN/front-proxy awareness,
    filters, auth, stream, resty, security-matrix, rce-matrix and API-compat) —
    `summaryH.txt` had one failure (`http3_e2e` 7/8: its 5-concurrent-stream check
    reported 4, a QUIC stream-opening timing flake on this host; the script passed
    8/8 re-run alone), and the complete re-runs after the final binary changes
    (`summaryI.txt`, `summaryJ.txt` after the cache-key lexer fix, `learningTrio.txt`
    after the learning trio + its `-t` zone check landed, and `frontProxy.txt` after
    CDN awareness + its 54-check suite landed) are **all green, nonzero=0** (69/69
    then, 72/72, 73/73 now). Run them with
    `python run_regression.py frontProxy.txt` (per-script logs and the exit-code
    roll-up land in `logs/regression/`; `tls_legacy_e2e.py` swaps the release
    binary to a `native-tls` build and restores it, so never run two suites at
    once on this host).
  - `native-tls` legacy handshake suite 12/12 with `--features native-tls`
    (runtime-generated RSA cert); the default rustls build still passes it.
- Not verifiable on this host: USR2/Linux signal behavior and the Linux A/B
  baseline (no Linux/WSL/Docker or Linux toolchain on this machine).

## 5. Roadmap

1. **Linux CI baseline** (`tools/linux_ab.sh`) with 3-run medians; use it to decide
   whether Lua performance work is warranted.
2. **USR2 upgrade, option A** (SO_REUSEPORT handover) behind `cfg(unix)`, with the
   pipeline in `docs/USR2_HOT_UPGRADE.md`; keep Windows on rolling restart.
3. **TLS/ops parity**: `ssl_session_store_by_lua`, OCSP stapling, QUIC handshake
   scripts, per-process vs shared session-store documentation.
4. **Lua API long tail**: `ngx.on_abort` invocation, capture `ctx`/`share_all_vars`,
   duplex `ngx.req.socket`, streaming filters where safe.
5. **Ecosystem**: `resty.websocket`/`jwt`/`mysql`/`dns` on top of the existing
   cosocket core; optional LuaJIT investigation (mlua supports LuaJIT builds, but
   the Rust module surface would need auditing).
6. **Disk tier phase 2**: give `proxy_cache` the same cold-tier treatment as
   `ngx.shared.DICT` — nginx `proxy_cache_path` semantics (`levels`/`max_size`/
   `inactive`/`min_free_size`/`use_temp_path`), warm start by scanning the cache
   tree, and `X-Cache-Status` reporting hits served from disk.
7. **Learned eviction/scarcity scorer (offline-trained weights; design constraints, not yet
   built)** — the *online* tiny models shipped (§1.3: TinyLFU admission, per-key burst depth,
   client reputation, all a few KB per zone on one budgeted ledger); what is still open here is a
   scorer whose weights come from off-line training. Any
   model that decides spill/promote/evict must be **inference-only at request time**,
   **lazy-loaded** (weights mmap'd or parsed on first use after `init_worker`, never on
   the accept path, and dropped on `flush_all`-style config change), and **trained
   offline/asynchronously** — a background task or an external job consumes the access
   counters and writes a new weight file that is swapped atomically; the request path
   never computes a gradient. It ships **default-off** with the deterministic
   CLOCK + frequency policy as the always-available fallback, so a burst (or a corrupt
   weight file) degrades to today's behavior instead of adding latency: budget one
   scoring pass per eviction decision, no per-request inference unless the location
   opts in. Small models only (the ≤5 MB envelope already agreed for this feature);
   WASM is out of scope.
8. **CDN-awareness follow-ups**: the `Upgrade`/101 seam calls `apply_front_proxy` in the right place but
   `tools/front_proxy_e2e.py` has no WebSocket-capable backend, so that path is wired rather than observed;
   `Cache-Status` is emitted on the buffered path only (the streaming path would have to decide the tag
   before the first byte leaves); and per-provider *deployment* examples — where the ranges are fetched from
   the vendor's published list at install time — belong in configs, which is why none ship in the engine.

## References

- OpenResty documentation: https://openresty.org/
- lua-nginx-module wiki: https://github.com/openresty/lua-nginx-module/wiki
- OpenResty best practices: https://github.com/moonbingbing/openresty-best-practices
- `docs/USR2_HOT_UPGRADE.md`, `docs/LINUX_AB.md`, `README.md` (feature map + Lua API)
