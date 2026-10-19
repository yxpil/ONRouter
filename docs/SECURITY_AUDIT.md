# ONRouter security audit (2026-10-19)

Scope: the local gateway only (`127.0.0.1`), no production traffic, no external hosts.
Method: read the hot paths, write a probe that sends **real traffic** for every suspicion,
then fix and re-probe. Every finding below was reproduced before it was fixed and every fix
is covered by a probe that fails on the pre-fix binary and passes on the post-fix one.

Harness: `tools/security_matrix_e2e.py` (S1-S7 class) and `tools/rce_matrix_e2e.py`
(remote-execution surface) — one gateway process per probe (no cross-contamination),
backends that report what they actually received.
Current result: **20/20** and **27/27 PASS**.
Post-fix regression (2026-10-19): `cargo test --workspace` 255/255 and all E2E
scripts exited 0 (`python run_regression.py summaryE.txt`, 2026-10-19 run).

| # | Finding (pre-fix behaviour) | Class | Fix | Probe |
|---|---|---|---|---|
| S1 | `auth_basic "Realm";` with no `auth_basic_user_file` served the location **without any credential** (`?` on the user-file lookup returned `None` = "no decision" = allow) | Fail-open auth | Missing credential source is now an explicit denial: 401 + `WWW-Authenticate` + `error_log` | `s1_auth_without_file` (was `status=200 body=b'secret-data'`) |
| S2 | An htpasswd line `dave:` stored an empty hash, and the plaintext fallback compares `"" == ""`, so **an empty password authenticated** | Fail-open auth | `Htpasswd::parse` drops empty-hash entries; the user simply does not exist | `s2_empty_hash` (was `status=200`) |
| S3 | The htpasswd cache keyed on **mtime only**. Rewriting the file with `htpasswd -b`/rsync-copied timestamps (same second, same length) meant revoked users kept logging in — and new users could not | Stale credential cache | Cache entry keyed on `(mtime, len)` **and** bounded by `HTPASSWD_MAX_AGE = 1s`; either change reloads | `s3_htpasswd_staleness` (revoke still 200 / new user 401 before the fix) |
| S4 | The Upgrade (WebSocket) request line was built from the **decoded** path: `/ws%23frag` reached the backend as `/ws#frag`, `%3f` as a second `?`. The gateway routed/ACL'd one resource, the backend saw another | URI desync → ACL/limit bypass | Forward the client's **raw, undecoded** request target (nginx behaviour); fall back to per-segment re-encoding only for rewrite-produced paths and non-`/` targets | `s4_upgrade_uri_desync` (backend echoed `GET /ws#frag?x=1%3fy=2`) |
| S5 | `proxy_request_buffering off` bypassed `read_body`, so `client_body_timeout` did not apply to streamed uploads: one client that sends a single chunk and stalls pins the connection, an upstream connection and the connection budget indefinitely | Slow-client DoS | `StreamBodyGuard` (renamed from `BodyLimitBody`) arms a per-frame `tokio::time::Sleep`, rearmed on every data frame — the nginx "time between reads", not total time. `0s` disables | `s5_stalled_upload` (still alive after 5s with `client_body_timeout 2s`) |
| S6 | Any `sub_filter` in a location made the static handler `fs::read()` the **whole file** (even for a byte range) and buffer the rewritten result: 32 MiB file × concurrency = memory amplification switched on by one directive | Memory amplification | Read only the `[start, start+len)` window; above `SUB_FILTER_MAX_BUFFER = 8 MiB` stream the file unfiltered (zero-copy) and log why. nginx streams this case; we trade fidelity for a bounded footprint, loudly | `s6_sub_filter_memory` (TTFB ≈ total time = buffering signature; now TTFB ≪ total, mid.html still rewritten) |
| S7 | A `while true do end` in `content_by_lua_block` never yields; it occupies the Lua VM's tokio worker thread outright. Because ONRouter is **one process**, unrelated endpoints — including non-Lua `return 200` locations — stopped answering within 5s | Single-process blast radius | Cooperative preemption: every resume arms a Lua count hook (`lua_slice_instructions`, default 1 000 000 VM instructions ≈ 10 ms of pure Lua). The hook yields the coroutine back to the scheduler, which round-robins it and, after `PREEMPT_PER_HOLD = 8` slices, leaves the lock/await loop entirely | `s7_lua_infinite_loop` (`/lua` and `/ping` both timed out before; both answer now) |
| S8 | Every caller of `run_phases` was written `if !run_phases(...) { <termination> }`, but that helper returns **`true` on error**. So any error in `rewrite_by_lua` / `access_by_lua` / `balancer_by_lua` — file missing, Lua compile error, runtime `error()` — was swallowed and the request kept going into `return` / `proxy_pass` / static. A location guarded only by `access_by_lua_file` served its protected body with **200** the moment that script became unreadable (deployed wrong, deleted, syntax-broken). The content phase had the same shape in a milder form: a streaming `content_by_lua_file` that failed to load produced an **empty 200** instead of 5xx | Fail-open auth (phase error treated as "check passed") | Callers terminate on `true` — `server.rs:1498` (rewrite), `:1523` (access), `:1576` and `:3312` (balancer, incl. the Upgrade path), plus `:1879` where the content-phase `failed` flag now goes to `error_response(500)`. `run_phases`' contract is documented at `:1954` so the polarity cannot be re-inverted silently. Matches nginx, where a missing `access_by_lua_file` is a 500, not a pass | `r1_source_injection` — pre-fix: `access_by_lua_file` → `st=200 body=b'SECRET-DATA'`, runtime `error()` → same, missing content script → `st=200 body=b''`; post-fix all three are 5xx with no body leak |

## Verified as *not* vulnerable (probed or read, no finding)

- **realip** trusts only the socket peer address, never a header, and runs before the ACL / limit /
  access-log consumers of `$remote_addr`, so the key that limits see is the post-realip one.
- **limit_req / limit_conn** use bounded (LRU) key maps and guards that release on `Drop`, so an
  attacker-churned key set cannot grow the table without bound.
- **HTTP/1 framing** is owned by hyper, plus explicit duplicate-CL / CL+TE / bad-CL checks; the
  streamed-body limit is enforced while forwarding, not after buffering.
- **Path traversal** is neutralised in `decode_and_normalize` before any filesystem join; `autoindex`
  HTML-escapes names.
- **Header injection**: every outbound value goes through `HeaderValue::try_from`, so CR/LF cannot
  reach a response or a forwarded request.
- **`proxy_ssl_verify`** defaults to on; hop-by-hop headers are stripped before forwarding.
- **Panic isolation**: `catch_unwind` per request; one crashing handler does not take the process.
- **Access log** never records `Authorization` or cookie values.

### Remote-execution surface (2026-10-19, `tools/rce_matrix_e2e.py`)

The Lua VM is deliberately **not** sandboxed — `os`, `io`, `load`, `loadfile`, `dofile`, `require`
and `package` are all reachable from a script, exactly as in OpenResty. So "RCE" here means one
thing: **client input must never become script source, script path, or upstream target.** Probes:

- **No config → request variable interpolation.** `content_by_lua_block { ngx.say("[$host][$uri][$arg_marker]") }`
  renders its source verbatim; the config parser never expands `$var` inside a `_by_lua_*` body, so there is
  no path from a query string to Lua source. (`engine.rs` `apply_return` likewise copies `ret.text` literally —
  see the `return` gap in the OpenResty analysis.)
- **`*_by_lua_file` paths are config-time literals.** `content_by_lua_file "$arg_f.lua";` resolves to a file
  actually named `$arg_f.lua`, not to whatever `?f=` says; the request 404s/fail-closes instead of executing
  `marker.lua` (a script that writes a marker file — the marker never appeared).
- **`debug` is unavailable to scripts**, so `debug.getregistry()` cannot reach mlua's named registry
  (`__ctx`), which is where cross-request live handles would have been found.
- **No memory-corruption path in our own `unsafe`**: all five sites are the self-owned-field
  `Pin` pattern (`Option<Pin<Box<Sleep>>>` guards) or the hyper `ReadBuf`/`TokioIo` adapter; no
  `get_unchecked` on caller-supplied indices, no FFI buffers fed from the wire.
- **No process spawn** in the request path (`std::process::Command` does not appear in shipped code),
  **no request-driven file write** (no `client_body_temp` — bodies stay in memory or stream),
  **no `X-Accel-Redirect`**, and upstream responses are not gzip-decoded by us, so there is no
  decompression-bomb sink either.
- **SSRF**: `proxy_pass http://127.0.0.1:$arg_port/` and `proxy_pass http://$http_x_host:$arg_p/` never
  open a socket to a client-chosen target (canary listener accept count stayed at `0`); the variable that
  looks like an upstream is forwarded as a literal, and a raw absolute-form request line
  (`GET http://127.0.0.1:PORT/abs`) is rejected with 404 rather than proxied.
- **CRLF**: `%0d%0a` in the path is answered by the gateway with **400** — stricter than nginx, which
  forwards the encoded sequence. `%20` and `%23` still pass through untouched, so this is not naive
  over-decoding. Header values set from `ngx.var.uri` / `ngx.var.arg_*` go through
  `HeaderValue::try_from`, and a bare `\r` in a request header is rejected at parse time.
- **`internal` locations** stay unreachable from the socket across 9 encodings
  (`/admin`, `//admin`, `/.//admin`, `/pub/../admin`, `/%61dmin`, `/ADMIN`, `/admin%20`, `/admin;x`, `/admin/`).
  Note `rewrite … last` and `try_files` into an internal location are *internal redirects* and therefore
  allowed — same as nginx (`r->internal = 1`); `capture`/`ngx.exec` are allowed for the same reason.

## Residual risk / follow-ups

- S8's polarity is a hazard the compiler cannot catch (`run_phases` returns a plain `bool`), so the guard
  is the `rce_matrix_e2e.py` probe plus the doc comment at `server.rs:1954`. Returning a `Result` from
  `run_phases` — or a dedicated `PhaseError` that the caller must match — is the durable fix.
- S7 is bounded, not eliminated: a runaway script still burns one core and its own request never
  completes. Coroutines a script spawns itself (`coroutine.resume` inside user code) are not armed —
  the hook slot is one per VM thread and the scheduler owns it.
- `sub_filter` over the 8 MiB ceiling is served **unfiltered**. nginx streams the substitution instead;
  a streaming literal-substitution filter (tail window) is the proper fix and is on the roadmap.
- `client_body_timeout` is a process-level setting (`Settings`), not per `server`/`location` as nginx
  allows; writing it inside a `server { }` block has no effect.
- Htpasswd entries with an unsupported crypt form (DES `crypt(3)`, `$2y$` bcrypt) still fall through to
  a literal compare, which cannot match a real hash — deny, not allow.
