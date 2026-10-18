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
- **Static IO moved off workers**: every filesystem call in the static-serving path (resolve / index /
  autoindex / read) is handed wholesale to `tokio::task::spawn_blocking` via an owned snapshot, so
  tokio worker threads are never blocked by disk IO.
- **error_page target files** are likewise read once to build the response, removing extra synchronous
  IO round-trips from the error-page hot path.
- Measured (32 concurrent keep-alive connections): static 4880 → 6715 req/s (+38%), Lua
  7867 → 9044 req/s (+15%).
- **Static file in-memory cache**: files ≤1 MB are held entirely in process memory (up to 512 entries),
  invalidated by (mtime, size). A cache hit costs zero disk reads and zero syscalls beyond a single
  `stat`; file edits are detected automatically.

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
- **16-shard ngx.shared.DICT**: sharded by key hash, each shard with its own lock, so multi-core
  concurrent reads/writes never block each other.
- **Lock-free hot paths**: round-robin cursor / node health state / VM selection are all atomic.
- **Async access log**: a dedicated writer thread + buffered batch flush; the request hot path does
  only one lock-free enqueue.
- **proxy_next_upstream**: connection-level upstream failures automatically retry once against the next
  node (self-heals stale connection-pool hits).
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
| `proxy_cache` response caching | in-memory named zones, `proxy_cache_valid`/key/methods/min_uses, upstream `Cache-Control`/`Expires` precedence, `X-Cache-Status` | `proxy_cache.rs` |
| `proxy_pass https://` / `wss://` backends | pure-Rust rustls client over one pooled `Service<Uri>` connector shared with http backends; `proxy_ssl_verify`/`_trusted_certificate`/`_name`/`_server_name` + `proxy_ssl_certificate`/`_certificate_key` (mTLS client cert), TLS policy incl. client cert in the pool key | `proxy_tls.rs`, `proxy.rs` |
| `rewrite ... last/break/redirect/permanent` | regex engine + `$1..$9` back-references | `engine.rs` |
| `map $src $dst { … }` derived variables | exact/`~`/`~*`/capture-group cases + `default`, shared resolver for `ngx.var` + config interpolation | `engine.rs`, `router.rs` |
| `geo [$src] $dst { … }` IP-derived variables | longest-prefix CIDR match (IPv4+IPv6), host `/32`, networks, `default`, same shared resolver | `engine.rs`, `router.rs` |
| `split_clients <key> $dst { … }` weighted-derived variables | MurmurHash2 over an interpolated key template, `%` buckets (fractional allowed) + `*` catch-all, same shared resolver | `engine.rs`, `router.rs` |
| `sub_filter <m> <r>;` response rewrite | literal + `~`/`~*` regex match, `&` back-reference in the replacement, `sub_filter_once`/`sub_filter_types`, applied on buffered proxy/cache/static/Lua bodies | `engine.rs`, `server.rs`, `router.rs` |
| `set_real_ip_from` + `real_ip_header`/`real_ip_recursive` | realip module: trust the client IP from a header only when the direct peer is in a trusted CIDR, XFF chain right-most (off) / recursive-trusted-skip (on); overrides `$remote_addr` before geo/limit/auth | `realip.rs`, `router.rs`, `server.rs` |
| `proxy_redirect` + `proxy_cookie_domain`/`proxy_cookie_path` | rewrite upstream `Location`/`Refresh` (literal prefix, `~regex` with captures, or `default` = origin→location-prefix relative form) and `Set-Cookie` `domain=`/`path=` (literal/regex, `none` deletes, path prefix-preserving); applied on both proxy seams (streaming + buffered), multi `Set-Cookie` preserved | `resp_rewrite.rs`, `router.rs`, `server.rs` |
| `stream { server { … } }` L4 proxy + `ssl_preread` | byte-transparent TCP tunnel (no TLS termination, no protocol parsing); optional `ssl_preread` peeks the first TLS record and parses SNI from the ClientHello (a self-contained offset-walk, best-effort: non-TLS/incomplete/no-SNI still wires to the default), routing by `sni_match <name> <target>` (exact or `*.suffix` single-label wildcard; target = named `upstream` reusing the L7 pool, or a literal `host:port`), falling back to `proxy_pass`; peeked bytes are replayed to the backend so the handshake is untouched; separate accept loop shares only the shutdown signal + upstream pool with HTTP | `stream.rs`, `router.rs`, `main.rs` |
| `return` / `add_header` / `proxy_read_timeout` | same semantics | `router.rs` |
| `location =` / prefix / `~` regex | exact > regex > longest prefix | `router.rs` |
| `listen <port> ssl` + `ssl_certificate` | rustls TLS (HTTPS endpoints; multiple `listen` directives coexist) | `server.rs` |
| `ssl_protocols TLSv1..TLSv1.3` | explicit enabled-version set (rustls serves the 1.2/1.3 subset by default); `--features native-tls` routes a legacy-needing listener to the OS stack (Windows Schannel) to truly negotiate TLS 1.0/1.1 | `certs.rs`, `tls.rs`, `router.rs` |
| HTTP/2 serving (`http2 on;` + `listen … http2`) | TLS h2 via ALPN; cleartext h2c prior-knowledge via 24-byte preface sniff (MSG_PEEK, non-consuming) so h1/h2c share one listener; hyper multiplexed streams | `server.rs`, `router.rs` |
| `SIGHUP` graceful config reload | in-process hot swap of the routing table behind `RwLock<Arc<Router>>`; listeners never rebound (no accept gap), per-request snapshot, invalid config keeps old; portable `reload <interval>;` mtime poll | `server.rs`, `main.rs` |
| HTTP/3 serving (`listen … quic`) | quinn QUIC endpoint (UDP) + h3 over it, TLS1.3/ALPN `h3` reusing the SNI cert store; same body-agnostic request core as h1/h2 (vhost/location/rewrite/access/proxy/lua); TCP-TLS on the same port serves h1/h2 and advertises `Alt-Svc: h3=":port"` | `server.rs`, `certs.rs`, `router.rs` |
| `ngx_lua` scripting layer | mlua (Lua 5.4), see the Lua API list below | `lua_engine.rs` |
| `init_by_lua` | runs once at startup | `lua_engine.rs` |
| `lua_shared_dict` / `ngx.shared.DICT` | full OpenResty method surface: `get`/`get_stale`/`get_plus`/`get2`, `set`/`safe_set`/`force_set`/`set_auto`, `add`/`force_add`/`replace`, `incr`/`decr`/`bump`, `delete`/`flush_all`/`flush_expired`, `ttl`/`key_present`/`size`/`len`/`num`/`capacity`/`free_space` (true multi-value returns) | `shared_dict.rs`, `lua_engine.rs` |
| `access_log` combined format | local file + stdout | `access_log.rs` |
| third-party C modules | `content_by_rust` / `access_by_rust` compile-time registered Rust handlers | `engine.rs` |
| `stub_status` / Prometheus scraping | process-global runtime metrics (accepted/active/capacity + requests + 2xx/3xx/4xx/5xx) rendered as Prometheus text via `content_by_rust metrics` | `metrics.rs` |
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

- Response: `ngx.say / print / status (read-write) / exit / header["X"]=v (read+write via metatable) / header.set / resp.get_headers()`
- Request: `ngx.req.get_method / set_method / get_path / get_query / get_headers / set_header(name, value | array | nil) / set_raw_header / clear_header / get_uri_args / set_uri / set_uri_args / read_body / get_body_data / set_body_data / discard_body / get_body_file / get_post_args / raw_header([full])` —
  `set_header`/`clear_header` mutate the live inbound request headers, so a rewrite/access-phase change
  is carried all the way to the proxied backend.
- Control: `ngx.redirect(uri, code?) / ngx.exec(uri) / ngx.exit / ngx.sleep(secs) (async coroutine, seconds unit aligned with OpenResty)`
- Cosocket: `ngx.socket.tcp()` → `connect / send / receive(*l | *a | n) / receiveany(min,max) /
  receiveuntil(delim) / shutdown(read?,write?) / settimeout / setsize / setkeepalive(timeout,pool) /
  tlshandshake(opts) / reconnect / close / getstats` — non-blocking TCP, every op yields to the VM
  scheduler so concurrent requests
  interleave on one VM (mirrors ngx_lua's cosocket yield-and-resume model). `setkeepalive`
  returns the idle connection to a process-global pool keyed by `host:port`, and a later `connect`
  to the same peer reuses it (skip the handshake, second return `"reused"`). `tlshandshake` upgrades
  the stream to a rustls client TLS connection (`CosStream::Plain`→`CosStream::Tls`), after which
  every receive variant runs over the encrypted stream. Verified by
  `tools/sock_ext_e2e.py` / `tools/sock_tls_e2e.py` against real TCP and TLS backends.
- UDP: `ngx.socket.udp()` → `setpeername / send / receive(max) / settimeout / close` — connected-UDP
  datagram I/O on the same scheduler yield path; verified by `tools/sock_udp_e2e.py`.
- Regex: `ngx.re.match(s, pat, flags?) / find / gmatch(s, pat, flags?)→iterator / sub(s, pat, repl, flags?) /
  gsub(s, pat, repl, flags?) / opt(pat, flags?)→reusable compiled handle` — flags support `i s m`
  (ignorecase / dotall / multiline); `sub`/`gsub` accept a replacement string (`$0`/`$1`/`${name}`
  expansion) or a callback function and return `new_subject, count`; `gmatch` returns a capture object with
  `[0]` whole match, `[N]` groups and named groups; `opt`'s handle avoids recompiling on the hot path.
- Encoding: `ngx.encode_base64 / decode_base64 / escape_uri / unescape_uri / decode_args / encode_args`
- Shared memory: `ngx.shared.<zone>:get / get_stale / set / safe_set / add / replace / delete / incr / ttl / flush_all`
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
- Subrequests: `ngx.location.capture(uri, opts?)` → `{ status, body, header }` (and `opts.method`) —
  runs the *full* pipeline for the captured location (rewrite → access → content: static / `return` /
  `proxy_pass` / nested Lua all work) as an internal subrequest against the same vhost, then yields to
  the VM scheduler (like the cosocket ops) so the parent coroutine and other in-flight requests keep
  progressing; nested captures are supported with a depth guard (`status = 0` on overflow, mirroring
  ngx_lua's error sentinel). Verified by `tools/subrequest_e2e.py`.
- Light threads: `ngx.thread.spawn(func, ...) / ngx.thread.wait(thread...) / ngx.thread.yield() /
  ngx.thread.kill(thread)` — spawned threads are first-class coroutines on
  the same VM scheduler (they share the parent request's `ngx.ctx` and interleave real `ngx.sleep` /
  cosocket I/O, not OS threads). `wait` returns on whichever awaited thread finishes *first* (any
  completion wakes the parked parent), forwarding that thread's return values on success
  (`ok, ret…`) or `(false, err)` when the thread errors or is killed; `yield` gives other coroutines a
  scheduling turn; killing a thread drops its in-flight sleep/socket op. The request terminating reaps
  any still-running children (mirrors ngx_lua). Verified by `tools/thread_e2e.py` (24 checks, incl. a
  wall-clock proof that 4 concurrent 0.4 s sleeps finish in ≪ 1.6 s and that two yielding threads
  interleave `ABABAB`). `ngx.on_abort(handler)` additionally accepts and stores a per-request abort
  callback (API-compatible); the disconnect-driven *invocation* hook is not yet wired to the server's
  connection-liveness path and is on the roadmap.
- Balancer phase: `balancer_by_lua` / `balancer_by_lua_file` + `ngx.balancer`
  (`set_current_peer(host, port) / get_current_peer() / set_timeouts(connect_ms, send_ms, read_ms) /
  set_more_failures({failures,return_code,escalate}) / recreate_request(bool?)`) — the phase runs just
  before `proxy_pass` forwarding, reading the request via `ngx.req.get_uri_args()` / `ngx.req.get_headers()`
  and, on `set_current_peer`, routing the connection to the Lua-selected `host:port` *instead of* the
  upstream's load balancer (so Lua drives dynamic peer selection / service discovery). `set_timeouts`
  overrides the location's connect/read timeouts for that hop. All five functions return OpenResty's
  `true` / `nil, err` convention; `set_current_peer('')` and negative timeouts reject. Tradeoff vs
  ngx_lua: the balancer runs once per request (not once per retry attempt), so a Lua-chosen peer is a
  single hop without in-upstream failover, and the `send` timeout / `ngx.balancer.set_upstream_*`
  override APIs remain (though the `$upstream_addr / $upstream_status / $upstream_header_time` log
  variables are now recorded by the proxy path — see "Upstream metrics"). Verified by `tools/balancer_e2e.py` (11 checks: a `proxy_pass` to a dead upstream
  502s on its own but the balancer re-routes it to live backends; query- and header-driven A/B
  selection; `set_timeouts` cutting a 3 s backend down to a ~0.4 s 502; a shared-dict counter giving an
  exact 5/5 round-robin split of real traffic). Engine-level unit test `balancer_lua_phase_stashes_peer_on_ctx`.
- Others: `ngx.ctx (per-request table) / ngx.time / ngx.now / ngx.log / ngx.config.* / ngx.version`
- Variables: `ngx.var` (metatable-backed nginx variables read off the live request) — `$uri /
  $request_uri / $args / $query_string / $is_args / $method→request_method / $scheme / $host /
  $remote_addr / $remote_port / $server_port / $content_type / $status / $body_bytes_sent /
  $request_length / $http_<name> (request header) / $sent_http_<name> (response header) /
  $upstream_addr / $upstream_status / $upstream_header_time(≡$upstream_response_time)`, all returned
  as strings with `nil` for undefined vars (OpenResty semantics). `$uri` (rewrites the path) and
  `$status` are writable; read-only vars ignore assignment. Verified by `tools/ngxvar_e2e.py` (19
  checks: live request metadata, `$http_x_test` header echo, undefined→nil, `$uri` write-then-read,
  `$status=418` producing a real 418 response) + unit test `ngx_var_reads_and_writes`.
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
  `geo`, `limit_req`/`limit_conn`, `allow`/`deny` and `access_log` all key off the real client. Verified
  by `tools/real_ip_e2e.py` (12 checks across four server blocks that turn the always-`127.0.0.1` test
  peer into trusted vs untrusted cases: X-Real-IP rewrite, the anti-forgery no-rewrite on an untrusted
  peer, the same `X-Forwarded-For` value yielding the right-most proxy address under `recursive off` vs
  the true client under `recursive on`, and a `geo $net` derived variable tracking the rewritten IP
  through each case) + pure unit tests in `realip.rs` and router tests `parse_real_ip_directives_into_server`.
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
  so the handshake is never disturbed, and `relay` splits each direction onto its own task with an idle
  (`proxy_timeout`) bound. Verified by `tools/stream_ssl_preread_e2e.py` (6 checks driven by **real Python TLS
  clients**: full handshake through the tunnel proves byte transparency, exact SNI `alpha.test` → the named
  upstream, wildcard `foo.wild.test` → `*.wild.test` backend, `wild.test`/`a.b.wild.test` correctly *not* matched
  and `other.test` unmatched all fall back to `proxy_pass`, plus a no-preread plain TCP echo) + pure unit tests in
  `stream.rs` (ClientHello SNI parse, truncation/garbage → `None`, exact+wildcard matcher, first-match-wins).
- Upstream metrics: proxied requests record the backend actually contacted — `ProxyEngine::forward`
  writes the chosen peer into `$upstream_addr`, the response code into `$upstream_status` (transport
  failures log `0`, matching nginx) and the connect+send+first-response-header round-trip into
  `$upstream_header_time`. These surface to Lua through `ngx.var` (above) so `log_by_lua` can harvest
  per-request upstream timing/status. Verified by `tools/upstream_e2e.py` (10 checks: `$upstream_addr`
  = the live backend, a backend-emitted 503 is both passed through and logged as `$upstream_status=503`,
  and a 0.6s backend yields `$upstream_header_time ≥ 0.55` — real round-trip, not a placeholder) +
  unit test `forward_records_upstream_metrics_on_failure`.
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
- Time: `ngx.today() / cookie_time(ts) / http_time(ts) / parse_http_time(str) / update_time()`
  (IMF + Netscape-cookie formats, `parse_http_time` returns `nil` on garbage)
- Phase & request introspection: `ngx.get_phase()` (returns the running phase, e.g. `content_by_lua`)
  and `ngx.is_subrequest` (true inside an `ngx.location.capture` subrequest)
- Workers & config: `ngx.worker.pid() / id() / count()` and `ngx.config.subsystem / prefix() /
  no_debug` — ONRouter is a single-process reactor, so `id()` is always `0` and `count()` is `1`
  (`pid()` is the real OS pid)
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
- The official suite is vendored under `vendor/lua-nginx-module/t/` (gitignored) as a semantics
  reference. Running a full `.t` directly via Test::Nginx requires a real OpenResty binary as
  `TEST_NGINX_BINARY` plus `*_by_lua_block` syntax and Unix signals, which do not run on this Windows
  host — hence the ported-assertions route.
- nginx syntax-compat shim: ONRouter now accepts nginx's `-p <prefix>`, `-g "<directives>"`, `-e <file>`
  flags and writes a pid file, and the config parser flattens the `http{}` wrapper (dropping
  `events{}`), so the official `nginx-tests` Perl harness (Test::Nginx) can spawn ONRouter directly.
- Compatibility regression: `compat_test.py` 17/17, security `sec_test.py` 30 checks, plus the
  static / scenario / upstream suites in this directory.

## Design tradeoffs & roadmap

Already done (previously listed as gaps, now implemented):

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
  one pooled client per `(connect_timeout, max_idle, idle_timeout)` triple so differently-configured
  upstreams get separate pools. (`upstream.rs::KeepaliveOpts`, `proxy.rs::client`, verified by
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
  class (2xx/3xx/4xx/5xx) in `finalize`. `content_by_rust metrics` reads the singleton and renders it
  in the Prometheus text exposition format (`# HELP`/`# TYPE` + `onrouter_uptime_seconds`,
  `onrouter_connections_{accepted,active,capacity}`, `onrouter_http_requests_total`,
  `onrouter_http_responses_total{class="…"}`). It uses the singleton because the native handler signature
  has no access to `AppState`. (`metrics.rs`, `server.rs`, `engine.rs`, verified by
  `tools/metrics_e2e.py`: with traffic interleaved between two scrapes, `requests_total`/`2xx`/`4xx`
  deltas track the real request counts, the active gauge stays ≥1 while a connection is in flight, and
  `capacity` equals the `worker_connections` default.)
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
  still returning 404.) `share_all_vars`/`ctx` option passing is not yet implemented.
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
  `proxy_cache_methods` (default `GET HEAD`), `proxy_cache_min_uses` (default 1). Freshness precedence
  matches nginx: the upstream's own `Cache-Control`/`Expires` wins (and an explicit `no-store`/`no-cache`/
  `private`/`max-age=0` forbids caching outright), falling back to `proxy_cache_valid` only when the
  upstream gives no hint. Responses carrying `Set-Cookie` are never stored (shared-cache safety). Every
  proxied response through a cached location gets an `X-Cache-Status: HIT|MISS|BYPASS` header. A hit
  replays the buffered status/headers/body without contacting the backend.
  (Verified by `tools/proxy_cache_e2e.py`: MISS→backend then HIT→same bytes with the backend counter
  unchanged, distinct `?query` → distinct keys, `Set-Cookie` and `no-store` → `BYPASS`, and a
  non-caching control location with no `X-Cache-Status`.) Not yet implemented: `proxy_cache_use_stale`,
  revalidation (`If-None-Match` to origin), `proxy_cache_purge`, on-disk `keys_zone`, and `Vary`-aware
  keying.
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
