# Lua API

The scripting layer embeds Lua 5.4 and exposes the `ngx.*` API shape — request phases, timers,
cosockets, subrequests, shared dicts, dynamic TLS certificates, and the `resty.*` modules.
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
  — reads the already-buffered request body in order, with the `nil, err, partial` convention;
  `receiveuntil` defaults to trimming the delimiter and its iterator can be called repeatedly.
  Verified by `tools/lua_flush_socket_e2e.py` (raw body bytes, delimiter boundaries, inclusive mode).
- Control: `ngx.redirect(uri, code?) / ngx.exec(uri) / ngx.exit / ngx.sleep(secs) (async coroutine, seconds unit)`
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
  (the numeric levels `ngx.log` accepts), and the common `ngx.HTTP_*` status codes
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
  idle timeout of a WebSocket tunnel opened to the selected peer. All five functions return the
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
  as strings with `nil` for undefined vars. `$uri` (rewrites the path) and
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
  implementations, not vendored source): `resty.string` (`to_hex / sha256_hex / md5_hex`,
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
  connection accounting) reuse the shared-dict primitives and return the `delay / nil,
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
