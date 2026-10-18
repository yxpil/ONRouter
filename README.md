<p align="center">
  <img src="public/logo.png" alt="ONRouter logo" width="180">
</p>

# ONRouter (Rust)

> **ONRouter** (short **ORR**) — an OpenResty alternative written from scratch in Rust.

A Nginx / OpenResty-style gateway server **implemented from scratch in Rust**: reverse proxy, load
balancing (with passive health checks), rewrite, virtual hosts, an embedded Lua 5.4 scripting layer
(the `ngx.*` API), plus native Rust modules. Apart from foundational libraries such as tokio/hyper,
all gateway logic is hand-written.

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
  keep-alive framing and `HEAD` stay exact; `HEAD` doesn't even open the file. `sub_filter` still needs
  the whole body, but only buffers when its MIME gate matches. Verified by `tools/static_stream_e2e.py`
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
  resistant to single-connection Slowloris attacks).
- Security tests: `sec_test.py` (30 checks, covering traversal / smuggling / CRLF injection /
  malformed requests / oversized requests / default response headers).

## Multi-core architecture

- **tokio multi-threaded runtime**: worker thread count = number of logical CPU cores.
- **Lua VM pool**: one independent Lua VM per CPU core (mirroring OpenResty's one VM per worker).
  Multiple requests execute scripts fully in parallel with no global single-point lock;
  `init_by_lua` runs once per VM (matching nginx's once-per-worker initialization semantics).
- **Within-VM coroutine scheduler**: each VM is driven by a dedicated scheduler task that interleaves
  many in-flight requests as Lua coroutines — a request yields only at `ngx.sleep` and the VM lock is
  released between synchronous resume segments, so `ngx.timer` callbacks and sleep timers progress
  while other requests on the same VM run (OpenResty's single-worker C10K, not one-request-per-VM).
- **Low-concurrency fast path (no scheduler hop for the common case)**: when the target VM lock is
  free, the request task compiles/resumes the first Lua segment inline; scripts that never yield
  finish without ever touching the scheduler task. On the first yield the coroutine is handed to the
  scheduler (`Job::Adopt`) and resumed there like any other request. A shared per-VM chunk cache keeps
  compilation single-flight. Exposed as `onrouter_lua_phase_{inline,adopted,scheduled}_total`; real
  traffic shows 100/100 inline for a no-yield script and 50/50 adopt for `ngx.sleep`.
- **16-shard ngx.shared.DICT**: sharded by key hash, each shard with its own lock, so multi-core
  concurrent reads/writes never block each other.
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
| `proxy_pass` reverse proxy | hyper connection pool, `proxy_set_header` variable interpolation, prefix replacement | `proxy.rs` |
| `resolver` + async DNS | pure-Rust non-blocking UDP stub resolver (A/AAAA, RFC1035 + compression pointers), `valid=` TTL cache | `dns.rs` |
| `proxy_cache` response caching | in-memory named zones sized from `keys_zone` with LRU eviction, `proxy_cache_valid`/key/methods/min_uses, `proxy_cache_lock` coalescing, `use_stale` (error/timeout/updating/http_xxx), `bypass`/`no_cache`, upstream `Cache-Control`/`Expires` precedence, `X-Cache-Status` | `proxy_cache.rs` |
| `proxy_pass https://` / `wss://` backends | pure-Rust rustls client over one pooled `Service<Uri>` connector shared with http backends; `proxy_ssl_verify`/`_trusted_certificate`/`_name`/`_server_name` + `proxy_ssl_certificate`/`_certificate_key` (mTLS client cert), TLS policy incl. client cert in the pool key | `proxy_tls.rs`, `proxy.rs` |
| `rewrite ... last/break/redirect/permanent` | regex engine + `$1..$9` back-references | `engine.rs` |
| `map $src $dst { … }` derived variables | exact/`~`/`~*`/capture-group cases + `default`, shared resolver for `ngx.var` + config interpolation | `engine.rs`, `router.rs` |
| `geo [$src] $dst { … }` IP-derived variables | longest-prefix CIDR match (IPv4+IPv6), host `/32`, networks, `default`, same shared resolver | `engine.rs`, `router.rs` |
| `split_clients <key> $dst { … }` weighted-derived variables | MurmurHash2 over an interpolated key template, `%` buckets (fractional allowed) + `*` catch-all, same shared resolver | `engine.rs`, `router.rs` |
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
| `lua_shared_dict` / `ngx.shared.DICT` | full OpenResty method surface: `get`/`get_stale`/`get_plus`/`get2`, `set`/`safe_set`/`force_set`/`set_auto`, `add`/`force_add`/`replace`, `incr`/`decr`/`bump`, `delete`/`flush_all`/`flush_expired`, `ttl`/`key_present`/`size`/`len`/`num`/`capacity`/`free_space`/`get_keys`/`expire` (true multi-value returns) | `shared_dict.rs`, `lua_engine.rs` |
| `access_log` combined format | local file + stdout; `$remote_addr` is captured after realip, so logs show the real client, not the trusted proxy; each line also carries `$request_time` and the `$upstream_addr` / `$upstream_status` / `$upstream_header_time` triple (`- - -` when no upstream was contacted; Upgrade tunnels log the `101` peer); a full async queue drops and counts lines instead of blocking request tasks | `access_log.rs` |
| third-party C modules | `content_by_rust` / `access_by_rust` compile-time registered Rust handlers | `engine.rs` |
| `stub_status` / Prometheus scraping | process-global runtime metrics (accepted/active/capacity + requests + 2xx/3xx/4xx/5xx) plus per-upstream node connections/health/success/failure, cache-status counters, TLS handshake failures, limit_req/limit_conn rejections and dropped access-log lines, rendered as Prometheus text via `content_by_rust metrics` | `metrics.rs` |
| `allow` / `deny` | ACCESS-phase IP ACL: IPv4/IPv6/CIDR/`all`, ordered first-match-wins (default allow), location inherits server rules | `access.rs` |
| `auth_basic` / `auth_basic_user_file` | HTTP Basic auth in ACCESS phase; htpasswd supports plaintext, `{SHA}` (SHA-1), `$1$`/`$apr1$` (MD5-crypt), realm tri-state incl. `off`, mtime-cached file reload | `access.rs` |
| nginx syntax compatibility | `location =/\^~/~/~*`, server_name wildcards, error_page, try_files, index, autoindex, alias, client_max_body_size, return URL shorthand | |

## Directory layout

```
rust/
├── conf/onrouter.conf        # example gateway config (full-feature demo)
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
            ├── lua_engine.rs# Lua VM + ngx.* API
            ├── access_log.rs# combined access log
            ├── stream.rs    # L4 stream{} proxy + ssl_preread SNI routing (byte-transparent TCP)
            └── server.rs    # HTTP pipeline: rewrite -> access -> content -> log
```

## Running

```bash
cd rust
# Option 1: run directly with cargo (debug)
cargo run -- conf/onrouter.conf
# Option 2: packaged exe (release)
cargo build --release
target\release\onrouter.exe conf\onrouter.conf

# start two demo backends (either way):
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1
```

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
  $msec / $time_local / $time_iso8601 / $https / $arg_<name> / $cookie_<name> /
  $http_<name> (request header) / $sent_http_<name> (response header) / $proxy_add_x_forwarded_for /
  $upstream_addr / $upstream_status / $upstream_header_time(≡$upstream_response_time)`, all returned
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
- `tools/observability_e2e.py`: 26/26 passing, one process and real traffic for the #40 telemetry:
  a live + dead node pair (`success`/`failure` per node, connection gauge back to 0, healthy gauge),
  a MISS→HIT→BYPASS→EXPIRED cache sequence matched against `X-Cache-Status` **and** the per-status
  Prometheus counters, `limit_req` 200→429 with `Retry-After`, `limit_conn` 503 under an in-flight
  `ngx.sleep` request and recovery afterwards, a raw TLS-garbage probe bumping the handshake-failure
  counter, a WebSocket 101 upgrade counted against its upstream, and access-log line assertions for
  `$request_time` + the upstream triple (proxied, no-upstream `- - -`, and Upgrade `101`).
- The whole suite (unit tests + 63 Python E2E scripts: every `tools/*_e2e.py` plus the root
  scenario/compat/security/static/upstream suites) is re-run after these changes:
  `cargo test --workspace` 251/251 and every E2E script passes with real traffic.
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
- **Active health checks**: `health_check interval=… fails=… rises=… uri=… timeout=…` drives a
  background prober per upstream (in addition to passive `max_fails`/`fail_timeout`).
- **WebSocket / Upgrade tunnel**: `proxy_pass` auto-detects Upgrade requests and, after completing the
  101 handshake with the backend, hands off to hyper's upgrade mechanism for a bidirectional pipe
  (`server.rs::handle_upgrade` + `ProxyEngine::upgrade`); WS-frame bytes that race ahead of the
  backend's 101 are not lost (prefix buffer). The tunnel reaches both `http://` and TLS backends
  (`https://`/`wss://`) through the same connector (`proxy.rs` → `proxy_tls.rs`), verified by
  `tools/https_backend_e2e.py`.
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
  `onrouter_upstream_server_healthy` and
  `onrouter_upstream_requests_total{upstream,server,result="success|failure"}`; the success/failure
  counters live on the nodes themselves, not under the SWRR scheduling lock. `content_by_rust metrics`
  reads the singleton and renders it in the Prometheus text exposition format (`# HELP`/`# TYPE` +
  `onrouter_uptime_seconds`, `onrouter_connections_{accepted,active,capacity}`,
  `onrouter_http_requests_total`, `onrouter_http_responses_total{class="…"}`, the cache/TLS/limit/log
  families above, the upstream-server families, and the Lua scheduling-path counters
  `onrouter_lua_phase_{inline,adopted,scheduled}_total`), escaping label values. It uses the singleton
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
  process-wide cache keyed by mtime. Password records may be plaintext, `{SHA}` (SHA-1 base64),
  `$1$` (glibc MD5-crypt) or `$apr1$` (Apache MD5-crypt) — MD5 and SHA-1 are implemented in pure Rust
  (no crypto crates, so cross-compiles stay clean), and the MD5-crypt output is validated against
  `openssl passwd` reference vectors. Comparisons are constant-time. (`access.rs`, `server.rs`,
  `router.rs`, verified by `tools/auth_e2e.py`: missing/wrong credentials → `401` with a
  `WWW-Authenticate: Basic realm=…` challenge, correct `{SHA}`/`$apr1$`/plaintext logins → `200`,
  `deny all` → `403`, `allow 127.0.0.1/32` matches the loopback client.) crypt-DES and bcrypt
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
  `$scheme$proxy_host$request_uri`), `proxy_cache_valid <codes…|any> <time>` (multi-line),
  `proxy_cache_methods` (default `GET HEAD`), `proxy_cache_min_uses` (default 1),
  `proxy_cache_lock on` + `proxy_cache_lock_timeout`, `proxy_cache_use_stale
  error|timeout|updating|http_xxx`, `proxy_cache_bypass`, `proxy_no_cache`; top-level
  `proxy_cache_path … keys_zone=<name>:<size>` sets per-zone capacity (128 B/entry; the path itself
  is never written — the cache is memory-only). Freshness precedence matches nginx: the upstream's
  own `Cache-Control`/`Expires` wins (and an explicit `no-store`/`no-cache`/`private`/`max-age=0`
  forbids caching outright), falling back to `proxy_cache_valid` only when the upstream gives no
  hint. Responses carrying `Set-Cookie` are never stored (shared-cache safety).
  `proxy_cache_lock` coalesces concurrent same-key misses into one origin fetch (20 concurrent
  requests → exactly 1 backend hit, 1 `MISS` + 19 `HIT`). Expired entries stay in memory for an
  hour so `proxy_cache_use_stale` can replay them (`STALE`) on origin 5xx, connect failure, or while
  another request is already refreshing (`updating`, served immediately without queueing on the
  lock). `bypass` skips reads but still stores the fresh response; `no_cache` skips both. HEAD
  requests can be served from a GET-populated entry (the HTTP layer suppresses the body) but never
  populate the cache themselves, so an empty HEAD response cannot poison the shared GET key. Zones
  evict least-recently-used entries at capacity, expired entries are cleaned as writes accumulate, and a
  config reload applies new `keys_zone` sizes to live zones. Every response through a cached
  location carries `X-Cache-Status: HIT|MISS|EXPIRED|BYPASS|STALE`, and the same status feeds
  `onrouter_cache_requests_total{status=…}` on `/metrics`.
  (Verified by `tools/proxy_cache_e2e.py` 13/13 and `tools/cache_advanced_e2e.py` 32/32: concurrent
  coalescing, 502/error/updating stale replay, bypass/no_cache, keys_zone-driven LRU, and HEAD
  non-poisoning; `tools/observability_e2e.py` asserts the status→counter mapping 1:1.) Not yet
  implemented: revalidation (`If-None-Match` to origin), `proxy_cache_purge`, `proxy_cache_lock_age`,
  on-disk persistence, `Vary`-aware keying, and the `$upstream_cache_status` variable.
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
