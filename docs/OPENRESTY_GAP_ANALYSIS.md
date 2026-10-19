# ONRouter vs OpenResty — Gap Analysis

Updated: 2026-10-19 (v0.4.0, Windows host). Previous revisions of this document
were written before the `ngx_lua` async surface landed and understated the
implementation; this revision is status-first and cites the E2E/unit evidence
that enforces each row.

## Executive summary

ONRouter now covers the core nginx request pipeline plus a broad OpenResty Lua
surface: all request phases (including response filters and log phase), timers,
TCP/UDP cosockets, light threads, `ngx.semaphore`, subrequests (including
concurrent `capture_multi`), shared dicts, `resty.lock` / `resty.http` /
`resty.redis` / `resty.string` / `resty.cookie` / `resty.limit.req|count|conn`,
dynamic TLS certificate selection at handshake time, session resumption shared
across listeners, and in-process config/Lua hot reload.

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
  `get_keys`, `expire`), `resty.lock`, `ngx.socket.tcp` keepalive pool.
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
- **Variables**: `ngx.var` (request/response/upstream variables; `$uri` and
  `$status` writable), plus derived variables from `map` / `geo` / `split_clients`,
  resolved identically in Lua and config interpolation.

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
  `sub_filter`, real-IP, rate/conn limits, basic auth, `stream{}` L4 proxy with
  `ssl_preread`, `resolver` async DNS.
- **Proxy cache**: in-memory named zones with capacity from
  `proxy_cache_path … keys_zone=<name>:<size>` (LRU eviction, expiry cleanup
  every 128 stores), `proxy_cache_lock`/`_lock_timeout` request coalescing,
  `proxy_cache_use_stale` (`error`, `timeout`, `updating`, `http_4xx/5xx`),
  `proxy_cache_bypass`/`proxy_no_cache`, upstream freshness precedence, HEAD lookup without
  HEAD-response cache population, and `X-Cache-Status: HIT|MISS|EXPIRED|BYPASS|STALE`. Evidence:
  `tools/proxy_cache_e2e.py` 13/13, `tools/cache_advanced_e2e.py` 32/32.
- **Scheduler fast path**: first Lua segment runs inline when the VM lock is free;
  only yielding phases hand off to the scheduler. Counters exposed as
  `onrouter_lua_phase_{inline,adopted,scheduled}_total`; E2E traffic shows
  100/100 inline for a no-yield script and 50/50 adopt for `ngx.sleep`.

### 1.4 Operations

- Prometheus metrics via `content_by_rust metrics`: uptime, accepted/active/capacity,
  requests, status classes, Lua scheduling counters, per-upstream node
  connections/health/success/failure, cache status (`hit/miss/expired/bypass/stale`),
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
- `return` does not interpolate variables (`engine.rs:1041` copies the text verbatim,
  including the 30x `Location`). Verified on a live listener:
  `return 200 "ip=$remote_addr uri=$uri"` responds `ip=$remote_addr uri=$uri`, while
  nginx returns the values. `content_by_rust echo`/`status` *do* interpolate, and so
  do header/cache-key surfaces, which makes the inconsistency easy to miss.
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
  `proxy_cache_convert_head` (HEAD may read but never populate), `Vary`-aware
  keying, and the `$upstream_cache_status` variable (`X-Cache-Status` is emitted
  instead).

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
with exit code 0**. In the surfaces that *do* interpolate (`proxy_set_header`,
`add_header`, `proxy_cache_key`, `proxy_cache_bypass`, log lines), an unknown
`$variable` renders as empty (`interpolate_vars`, `proxy.rs:756`); elsewhere it is
left literal — see the `return` note in §2.2. So this is a migration hazard, not a
crash: a security control copied from a nginx config (`auth_request`, `if`,
`valid_referers`, `secure_link`) can be absent while the gateway reports a healthy
start — always read the warnings, not just the exit code.

| Scope | Directives | Notes |
|---|---|---|
| top | `worker_shutdown_timeout`, `ssl_stapling` | `shutdown_grace` is ONRouter's own drain knob; stapling is a §2.1 gap |
| server | `valid_referers`, `secure_link`, `secure_link_md5`, `gzip_static` | referer/link checks: do in Lua or `content_by_rust`; pre-compressed `.gz` serving falls back to on-the-fly gzip |
| location | `if` (with its whole block), `limit_rate`, `auth_request`, `dav_methods`, `grpc_pass`, `fastcgi_pass`, `mirror`, `proxy_bind`, `proxy_cache_revalidate` | `if` swallows its block: a nested `return 405` is ignored too. Downstream-protocol upstreams (`grpc`/`fastcgi`) and upstream source binding are simply not implemented |
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

- Unit tests: 255 passing (`cargo test --workspace`; 242 in onrouter-server +
  13 in onrouter-config).
- E2E suites (real traffic), this snapshot:
  - `lua_concurrency` 5/5, `thread` 24/24, `cosocket` 7/7, `subrequest` 18/18
  - `lua_flush_socket` 23/23, `init_worker_package` 21/21, `ssl_cert_lua` 21/21,
    `metrics` 38/38, `observability` 26/26, `api_compat` 57/57
  - `security_matrix` 20/20 (the seven findings from `docs/SECURITY_AUDIT.md`, each
    probe asserting the pre-fix failure mode is gone: fail-closed `auth_basic` and
    `allow/deny`, streamed-body `client_body_timeout` → 408, raw undecoded Upgrade
    request-target, htpasswd change visibility, `sub_filter` memory ceiling, Lua
    runaway-loop preemption), `rce_matrix` 27/27 (Lua source/path injection,
    `internal` location escape, `proxy_pass` SSRF against a canary listener,
    encoded-CRLF splitting), `static_stream` 19/19, `streaming_body` 7/7
  - Full regression: 65 scripts (8 root scenario/compat/security/static/upstream
    suites + every `tools/*_e2e.py` incl. TLS matrix, HTTP/2, HTTP/3, hot reload,
    cache, filters, auth, stream, resty, security-matrix, rce-matrix and API-compat)
    all exited 0. Run them with `python run_regression.py summaryE.txt`
    (per-script logs and the exit-code roll-up land in `logs/regression/`).
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

## References

- OpenResty documentation: https://openresty.org/
- lua-nginx-module wiki: https://github.com/openresty/lua-nginx-module/wiki
- OpenResty best practices: https://github.com/moonbingbing/openresty-best-practices
- `docs/USR2_HOT_UPGRADE.md`, `docs/LINUX_AB.md`, `README.md` (feature map + Lua API)
