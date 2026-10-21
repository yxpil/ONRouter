# ONRouter security audit (round 1: 2026-10-19, round 2: 2026-10-20)

Scope: the local gateway only (`127.0.0.1`), no production traffic, no external hosts.
Method: read the hot paths, write a probe that sends **real traffic** for every suspicion,
then fix and re-probe. Every finding below was reproduced before it was fixed and every fix
is covered by a probe that fails on the pre-fix binary and passes on the post-fix one.

Harness: `tools/security_matrix_e2e.py` (S1-S7 + S9-S12) and `tools/rce_matrix_e2e.py`
(remote-execution surface) — one gateway process per probe (no cross-contamination),
backends that report what they actually received.
Current result: **49/49** (`tools/security_matrix_e2e.py`, S1-S7 + S9-S13, re-run on the 1.0.2
binary in `logs/regression/reg_102.txt`) and **32/32 PASS** (R3 grew from 6 to 11 checks when S13
was closed).
Post-fix regression (2026-10-20, after S9-S12): `cargo test --workspace` **360/360** and
the full suite — `python run_regression.py secFixRound.txt` → `TOTAL 72 scripts,
nonzero=0` (`logs/regression/secFixRound.txt`). Round 1 recorded 281 unit tests and a
roll-up whose only nonzero line was `tls_legacy_e2e.py` colliding with a second suite run
started by mistake over the same `target/release/onrouter.exe` — alone it is 12/12 and it
restores the default rustls build. The CDN-awareness round added `tools/front_proxy_e2e.py`
(54/54, the forged-header/out-of-range peer cases above) and brought the suite to 73 scripts:
`python run_regression.py frontProxy.txt` → `TOTAL 73 scripts, nonzero=0` with
`cargo test --workspace` **386/386** (2026-10-20, `logs/regression/frontProxy.txt`).
The splitting round added S13 (a `proxy_pass` variable in the host position could be steered at any
target by the request) and brought the suite to 78 scripts: `python run_regression.py
reg_060_20261020.txt` → `TOTAL 78 scripts, nonzero=0` with `cargo test --workspace` **409/409**
(2026-10-20, `logs/regression/reg_060_20261020.txt`). The rule that round leaves behind is recorded
in the S13 entry below and applies to every future grammar widening: a config that passes `-t` is
not evidence of safety — the rejection has to be observed at runtime, in the error log, with a
legal control route still working next to it.

| # | Finding (pre-fix behaviour) | Class | Fix | Probe |
|---|---|---|---|---|
| S1 | `auth_basic "Realm";` with no `auth_basic_user_file` served the location **without any credential** (`?` on the user-file lookup returned `None` = "no decision" = allow) | Fail-open auth | Missing credential source is now an explicit denial: 401 + `WWW-Authenticate` + `error_log` | `s1_auth_without_file` (was `status=200 body=b'secret-data'`) |
| S2 | An htpasswd line `dave:` stored an empty hash, and the plaintext fallback compares `"" == ""`, so **an empty password authenticated** | Fail-open auth | `Htpasswd::parse` drops empty-hash entries; the user simply does not exist | `s2_empty_hash` (was `status=200`) |
| S3 | The htpasswd cache keyed on **mtime only**. Rewriting the file with `htpasswd -b`/rsync-copied timestamps (same second, same length) meant revoked users kept logging in — and new users could not | Stale credential cache | Cache entry keyed on `(mtime, len)` **and** bounded by `HTPASSWD_MAX_AGE = 1s`; either change reloads | `s3_htpasswd_staleness` (revoke still 200 / new user 401 before the fix) |
| S4 | The Upgrade (WebSocket) request line was built from the **decoded** path: `/ws%23frag` reached the backend as `/ws#frag`, `%3f` as a second `?`. The gateway routed/ACL'd one resource, the backend saw another | URI desync → ACL/limit bypass | Forward the client's **raw, undecoded** request target (nginx behaviour); fall back to per-segment re-encoding only for rewrite-produced paths and non-`/` targets | `s4_upgrade_uri_desync` (backend echoed `GET /ws#frag?x=1%3fy=2`) |
| S5 | `proxy_request_buffering off` bypassed `read_body`, so `client_body_timeout` did not apply to streamed uploads: one client that sends a single chunk and stalls pins the connection, an upstream connection and the connection budget indefinitely | Slow-client DoS | `StreamBodyGuard` (renamed from `BodyLimitBody`) arms a per-frame `tokio::time::Sleep`, rearmed on every data frame — the nginx "time between reads", not total time. `0s` disables | `s5_stalled_upload` (still alive after 5s with `client_body_timeout 2s`) |
| S6 | Any `sub_filter` in a location made the static handler `fs::read()` the **whole file** (even for a byte range) and buffer the rewritten result: 32 MiB file × concurrency = memory amplification switched on by one directive | Memory amplification | Read only the `[start, start+len)` window; above `SUB_FILTER_MAX_BUFFER = 8 MiB` stream the file unfiltered (zero-copy) and log why. nginx streams this case; we trade fidelity for a bounded footprint, loudly | `s6_sub_filter_memory` (TTFB ≈ total time = buffering signature; now TTFB ≪ total, mid.html still rewritten — the fixture is 64 MiB on purpose: at 32 MiB a warm page cache serves the whole file in ~40 ms and the ratio sits on the judgement line) |
| S7 | A `while true do end` in `content_by_lua_block` never yields; it occupies the Lua VM's tokio worker thread outright. Because ONRouter is **one process**, unrelated endpoints — including non-Lua `return 200` locations — stopped answering within 5s | Single-process blast radius | Cooperative preemption: every resume arms a Lua count hook (`lua_slice_instructions`, default 1 000 000 VM instructions ≈ 10 ms of pure Lua). The hook yields the coroutine back to the scheduler, which round-robins it and, after `PREEMPT_PER_HOLD = 8` slices, leaves the lock/await loop entirely | `s7_lua_infinite_loop` (`/lua` and `/ping` both timed out before; both answer now) |
| S8 | Every caller of `run_phases` was written `if !run_phases(...) { <termination> }`, but that helper returns **`true` on error**. So any error in `rewrite_by_lua` / `access_by_lua` / `balancer_by_lua` — file missing, Lua compile error, runtime `error()` — was swallowed and the request kept going into `return` / `proxy_pass` / static. A location guarded only by `access_by_lua_file` served its protected body with **200** the moment that script became unreadable (deployed wrong, deleted, syntax-broken). The content phase had the same shape in a milder form: a streaming `content_by_lua_file` that failed to load produced an **empty 200** instead of 5xx | Fail-open auth (phase error treated as "check passed") | Callers terminate on `true` — `server.rs:1498` (rewrite), `:1523` (access), `:1576` and `:3312` (balancer, incl. the Upgrade path), plus `:1879` where the content-phase `failed` flag now goes to `error_response(500)`. `run_phases`' contract is documented at `:1954` so the polarity cannot be re-inverted silently. Matches nginx, where a missing `access_by_lua_file` is a 500, not a pass | `r1_source_injection` — pre-fix: `access_by_lua_file` → `st=200 body=b'SECRET-DATA'`, runtime `error()` → same, missing content script → `st=200 body=b''`; post-fix all three are 5xx with no body leak |

| S9 | Still ONLine stored and replayed a **private body across visitors**. The write gate looked at the request (`Cookie`/`Authorization`) and at `Set-Cookie`, but never at what the upstream said about the response itself. A tenant request authenticated by a custom header (`X-Api-Key`) has neither cookie nor `Authorization`, so it passed gate 3; the origin answered `Cache-Control: private, max-age=300` with tenant data and no `Set-Cookie`, so it was stored under the identity-free key `$scheme$proxy_host$request_uri`. Once the origin died, the **next anonymous visitor** of the same URL was served that tenant's body with `X-Still-Online: stale` | Cross-tenant leak in the fallback layer | Hard rule 4 (no switch, same as the credential rules): `still_online::response_forbids_copy()` refuses storage when the upstream says `private`/`no-store`/`no-cache`/`max-age=0`, when the hinted TTL is zero, or when `Vary` names any header other than `Accept-Encoding`. It reuses `proxy_cache::upstream_directive`, so the cache layer and the copy layer can no longer disagree about what "this visitor's own copy" means. New counter `onrouter_still_online_total{kind="rejected_private"}`; the startup/`-t` copy-zone banner says so | `s9_lkg_private_body_leaks` (pre-fix: `stored` +2 and the anonymous visitor got `TENANT-VICTIM-DATA`; post-fix a plain 502, while the public copy still survives the outage — the fix costs no function) |
| S10 | The DICT cold tier's file names are **predictable**, and the writer followed them. An entry path is a pure function of the key (FNV-1a-64 → `<disk>/<h[0]>/<h[0..3]>/<hex>.bin`) and the temp name is `<hex>.<pid>.tmp`; `atomic_write` used `File::create`, which **truncates whatever already lives at that name** — including a hard link someone else pre-placed. Any local actor able to create a link inside the `disk=` root could therefore have the gateway (a process with broader write access) overwrite an arbitrary file with cache bytes on the next spill. Same shape on the read side: `File::open` follows links, and `scan_rebuild` descended into symlinked directories (`p.is_dir()`) — deleting every `*.tmp` it found there | Predictable temp file → arbitrary file overwrite; link-following read | `atomic_write` now uses `OpenOptions::create_new(true)`: the temp name must be created by *this* write. `AlreadyExists` — a crashed predecessor's leftover — is resolved with one `remove_file` + retry, and unlink never touches another name's content. `read_path_at` requires `symlink_metadata().is_file()`, and the scan walk only descends real directories and only collects real files | `s10_dict_tmp_link_overwrite` (pre-fix: `victim.txt` became a 942-byte cache entry starting `ORDK\x01…`; post-fix the victim is byte-identical and the entry still lands and reads back — unit tests `disk_cache::tests::atomic_write_never_writes_through_a_pre_existing_temp_name`, `scan_does_not_follow_a_link_out_of_the_cache_root`) |
| S11 | `limit_req_zone $http_x_api_key zone=bykey:1m rate=10r/s;` passed `-t`, logged a **warning**, and then keyed the zone by `$remote_addr` anyway. The variable is never expanded on the request path, so the operator thinks they rate-limit per API token while the gateway limits per IP — a silent policy inversion sitting on a security control | Fail-open configuration (misleading success) | `Router::build` rejects it as a hard error (non-zero `-t`, refuses to start), naming the variable and what *is* supported; `Limits::parse_all` dropped its own weaker second opinion so the two cannot diverge again | `s11_limit_key_var_is_a_hard_error` (pre-fix `rc=0`) + `router::tests::non_address_limit_zone_key_is_a_hard_error`, `limit::tests::only_address_keys_are_supported` |
| S12 | The VIP reputation table is direct-mapped (`tag % n` — 682 slots at the default 8 KiB) and a new tag **overwrote** the incumbent with `score = 0`. `tag = murmur_hash2(client address)` is public and computable offline, so one request from a chosen address erased a long-standing VIP's reputation: an unauthenticated "demote anyone" switch (that client loses the queue-depth ceiling and the cache-retention boost). Blast radius is quality of service only — reputation is never part of the allow/deny decision | Reputation poisoning / QoS degradation | `note()` now lets the **newcomer** lose the slot whenever the incumbent still scores after applying its silence decay; a fully decayed incumbent still gives the slot up, so the table cannot be fenced off by dead entries. Collisions are counted — `onrouter_vip_events_total{role="collision"}` — because a rising collision count is how an operator sees the table is too small. Separately: `set_real_ip_from` + `vip_learning` means part of the reputation key is client-asserted (`X-Forwarded-For`), so `-t` prints a warning naming the vhost and the two behaviours it can influence (still exits 0) | `s12_vip_slot_collision` (pre-fix: after one request from `198.18.3.128`, `onrouter_vip_clients` fell to 0; post-fix the VIP keeps its score and `-t` warns) + `vip::tests::a_collision_never_wipes_an_incumbent_vip`, `a_fully_decayed_incumbent_relinquishes_the_slot`, `router::tests::realip_plus_vip_learning_warns_about_the_trust_root` |
| S13 | Business splitting (0.6.0) let `proxy_pass` take a variable in its host position, and the check only asked *"is this a `split_clients` target?"* — a variable from `set`/`map`/`geo`/the request itself passed `-t` with a warning and then **connected wherever the request said**: `proxy_pass http://$http_x_target/` with `X-Target: 127.0.0.1:<canary>` returned `200` with the canary's body, and so did `?host=` on `http://$arg_host/`. That is the exact surface the round-1 SSRF entry claimed was closed — it was closed by those shapes not parsing at all | SSRF (self-inflicted regression, found pre-release) | Two layers. (1) A variable concatenated *inside* the host position cannot enumerate candidates → hard `-t` error. (2) A whole-segment variable that is not `split_clients`-produced keeps its route (so `map $http_x_env $backend` still works) but its interpolated value must be a target the config declares — a `upstream` name, a literal `proxy_pass` host, a `split_clients` branch, a `proxy_split_failover` target — else no socket is opened; enforced in both `forward()` and `upgrade()`, logged as `undeclared proxy_pass target`. Literal and split routes get `None` for the set, so they pay no lookup | `tools/rce_matrix_e2e.py` R3 (now 32/32): header- and query-controlled host → 502 with canary accept count unchanged, declared-pool control group → 200 (proves the block is not blanket); refusal reason asserted in the error log, not inferred from a 502. Unit: `variable_host_outside_allowlist_never_connects` (accept-counting canary backend), `declared_targets_only_lists_what_the_config_writes_down`, `only_variable_host_routes_carry_the_allowlist` |

## Verified as *not* vulnerable (probed or read, no finding)

- **realip** trusts only the socket peer address, never a header, and runs before the ACL / limit /
  access-log consumers of `$remote_addr`, so the key that limits see is the post-realip one.
  (What is *not* a property of it: once a peer is trusted, the resulting address comes from a
  client-asserted header. For access control that is the documented nginx behaviour; for
  `vip_learning` it is a reputation input, so `-t` warns — see S12.)
- **front_proxy** header forgery: a probe match never grants anything. Every derived value — the client
  address, `$scheme`, country, and the visible host — is used only when the direct TCP peer lands in that
  profile's `trust` ranges ∪ `set_real_ip_from`, so a client that copies a real CDN's header set (the E2E
  sends `X-Demo-Real-Client`, a full XFF chain, a country, a JSON protocol header and an
  `X-Forwarded-Host` on the same request) from an out-of-range peer is left on the node address with the
  original scheme, and `geo`/`limit_req`/ACL/VIP reputation all keep seeing the node. A profile with no
  `probe` can never match at all, which is what stops "request has X-Forwarded-For" from becoming an
  identity. Values are re-parsed, not trusted verbatim: a country header that is not a bare 2-letter token
  (`CN;evil`, `<script>`) yields nothing, and the host header takes the first element of a comma chain,
  drops the port, and is rejected outright when the remainder is empty, longer than 253 bytes, or contains
  anything outside `[A-Za-z0-9._-]` — it is a value that can be interpolated into a generated `Location`
  and a cache key. The derived host is exposed as `$front_proxy_host` and
  deliberately **never** overwrites `$host` — vhost and location selection already happened, so a header
  cannot move a request into a different server block. `Cache-Status` is emitted only for verified peers
  (an unverified "hit" counter would be a number the client controls) and only after any upstream entry, so
  a client cannot erase a layer's judgement. (What is *not* a property of it: inside a `trust` range the
  front is fully believed — that is the nginx realip contract, and it is why `front_proxy_auto_trust on`
  prints a one-shot warning naming both fixes and `-t` names the vhost: promoting a profile's own ranges
  into a rewrite authority is the operator's call, never a side effect of recognition. Ranges that are
  stale in the config file are the realistic failure mode, so they belong in deployment, not in code.)
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
- **DICT disk cold tier paths** (`disk=`): the only two inputs that reach the filesystem are the
  directory from the config (a config-time literal, resolved under `-p`/the config dir) and a 64-bit
  hash of the key. A key is never joined into a path, so traversal-shaped keys — `../../../../Windows/
  System32/evil`, `..\..\evil`, `/absolute/evil`, `CRLF`-prefixed — can only ever land on
  `<disk>/<hex>/<hex>/<16hex>.bin`; `tools/disk_cache_e2e.py` walks the whole tree after writing those
  keys and asserts every directory component is hex and every file matches the hash filename, then
  reads all five back intact. Two zones sharing one `disk=` directory is rejected at config load
  (entry files are named by key hash alone, so one zone's `delete` would erase the other's data).
  Entry files are length- and CRC-checked on read, so a truncated or hand-edited file is counted and
  dropped (`corrupt` counter) rather than panicking or being trusted.
  (This bullet is about the *shape* of the path — traversal. The *write* side of those same predictable
  file names was a real finding; see S10.)

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
- **SSRF**: the client cannot decide where the gateway connects, and that property is now enforced in two
  places, not just by absence of a feature. A variable concatenated *inside* the host position
  (`proxy_pass http://127.0.0.1:$arg_port/x`, `http://$http_x_host:$arg_p/`) cannot enumerate its candidates,
  so `-t` rejects the config outright. A whole-segment variable (`http://$backend`) stays legal — `set`/`map`/`geo`
  picking a pool is a legitimate pattern — but whatever it interpolates to at request time must be a target the
  config already wrote down (a declared `upstream` name, a literal `proxy_pass` host, a `split_clients` branch, or a
  `proxy_split_failover` target); anything else is refused before a socket is opened, logged as
  `undeclared proxy_pass target` in both the TCP and the `Upgrade` path. Measured, re-verified 2026-10-20 with a
  canary listener: `X-Target: 127.0.0.1:<canary>` and `?host=127.0.0.1:<canary>` → **502, canary accept count 0**,
  while a `map`/`set` pointing at a *declared* pool still returns 200 (control group, so the refusal is not
  "variables never work" and the block is not a false negative). A raw absolute-form request line
  (`GET http://127.0.0.1:PORT/abs`) is still rejected with 404 rather than proxied.
  **History worth keeping**: adding variable support to the host position for business splitting (0.6.0) reopened
  exactly this hole for ~one development cycle — before the gate landed, the same two probes returned **200 with the
  canary's body**, and the suite's own `-t` assertion had been quietly relaxed to "variable routes pass with a
  warning". `tools/rce_matrix_e2e.py` R3 caught it; the probe now asserts the *stricter* semantics (config-layer
  refusal + runtime allowlist + declared-target control group), and `tools/proxy_split_e2e.py` no longer treats a
  passing `-t` as proof of safety.
- **CRLF**: `%0d%0a` in the path is answered by the gateway with **400** — stricter than nginx, which
  forwards the encoded sequence. `%20` and `%23` still pass through untouched, so this is not naive
  over-decoding. Header values set from `ngx.var.uri` / `ngx.var.arg_*` go through
  `HeaderValue::try_from`, and a bare `\r` in a request header is rejected at parse time.
- **`internal` locations** stay unreachable from the socket across 9 encodings
  (`/admin`, `//admin`, `/.//admin`, `/pub/../admin`, `/%61dmin`, `/ADMIN`, `/admin%20`, `/admin;x`, `/admin/`).
  Note `rewrite … last` and `try_files` into an internal location are *internal redirects* and therefore
  allowed — same as nginx (`r->internal = 1`); `capture`/`ngx.exec` are allowed for the same reason.

## WASM runtime dependency surface (2026-10-22, checked against RustSec)

Trigger: the April 2026 Wasmtime/Cranelift batch (e.g. `GHSA-jhxm-h53p-jm7w`, a miscompiled guest
heap access on aarch64 that escapes the sandbox; `RUSTSEC-2026-0094`, Winch typing `table.grow`'s
result wrongly; `RUSTSEC-2026-0022`, a panic when an async `Func::call` future is dropped early —
wasmtime currently carries 47 recorded advisories in total). **None of them reach ONRouter, and the
reason is structural rather than a version we happened to be on:**

- `Cargo.lock` contains **zero** `cranelift*` entries and no `wasmtime`. ONRouter's plugin host is
  `wasmi` — a bytecode interpreter with **no JIT/AOT code generation**, so there is no native
  codegen step that could miscompile guest memory accesses. The whole class "compiler emits wrong
  machine code ⇒ sandbox escape" does not exist in this binary.
- What we actually ship for WASM: `wasmi 0.31.2` (runtime) plus `wat 1.262.0` / `wast 262.0.0` /
  `wasmparser 0.262.0` (the `.wat` text assembler and validator used by the shipped examples and
  suites). RustSec records **no advisory for any of these four** (`rustsec.org/packages/<name>.html`
  has no page for them, while it does for wasmtime — so this is absence of advisories, not absence
  of a lookup). The parser stack is on the **current release line** (0.262 is the newest on the
  registry index).
- What bounds the blast radius even if the interpreter itself were ever found faulty: modules are
  named in operator config and never derived from a request; the import surface is only what
  `wasm.rs` registers on its `Linker`; every call is fuel-metered (exhaustion traps rather than
  hanging a worker) under a `StoreLimits` memory ceiling; exports are validated at `-t` time so a
  module that does not match the declared phases never serves traffic. Evidence:
  `tools/wasm_e2e.py`, `tools/production_shape_e2e.py` (WASM access/header/body filters over TLS),
  `tools/api_compat_e2e.py`.

**Honest gap, recorded and deliberately not acted on in this batch:** upstream `wasmi` is at
**2.0.0** while we are on **0.31.2** — two majors behind. Nothing is known to be exploitable here,
but the cost of that gap is *responsiveness*: when a wasmi advisory does land, taking it will be an
API migration (fuel accounting, `TrapCode` paths, resource-limiter naming), not a version bump. The
API surface we touch is small (`Engine`/`Store`/`Module`/`Linker`/`Caller`/`Extern(Type)`/
`StoreLimits(Builder)` + `add_fuel`/`consume_fuel`/`call`/`memory_size`), so the migration is
contained — it just needs its own change with its own evidence pass (`wasm_e2e`, `production_shape`,
`protocol_matrix`, `api_compat`, then the full roll), not a drive-by during a release.

## Residual risk / follow-ups

- **`wasmi 0.31.2 → 2.0.0` is open** (see the section above). Recorded as a follow-up rather than a
  drive-by during a release: the upgrade is an API migration in `wasm.rs` and must come with its own
  evidence pass. Until then, "we are not affected by the Cranelift advisories" is a statement about
  *architecture* (interpreter, no codegen), not about being current.
- **`cargo audit` is a release-gate command, not a per-push CI step.** A transitive `unsound`/
  `unmaintained` advisory should not silently block shipping a production fix, but it must be triaged
  into this file before the tag (§16 of OPERATIONS.md).

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
- S10 needs one precondition: the attacker can create a link **inside** the `disk=` root. Keep that
  directory's ACL as tight as the gateway's own write access (`cache=`/`disk=` on a shared host is a
  delegation of that process's file permissions). `create_new` removes the privilege-escalation path,
  not the ability of someone already inside the tree to delete or rename cache entries.
- S12 trades one failure for another on purpose: with a small table, a newcomer can be permanently
  locked out of reputation ("collision") instead of someone else's score being erased. Watch
  `onrouter_vip_events_total{role="collision"}` and raise `vip_learning table=` if it climbs —
  the locked-out client is simply treated as non-VIP, which is the behaviour before the directive existed.
- S11 is a *narrow* fix: the durable one is nginx's shared variable system so `$http_*`/`$uri` keys
  can actually be expanded. Until then, refusing the config is the only honest option.
- `front_proxy trust` ranges are a **snapshot the operator owns**. Ranges rotate, and nothing in the code
  can check that a declared range still belongs to the front it describes — `-t` only checks it parses.
  Too-narrow is fail-safe: the request keeps the node address, `ip_blocked` climbs and one warning per
  profile says so. Too-wide is not: paste in a whole provider ASN or a colocation block and anyone inside
  it can assert a client address, which is exactly the realip trust root with a bigger surface. Declare the
  edge ranges the vendor publishes for *your* traffic, not a convenience supernet.
- The `Upgrade`/101 seam calls `apply_front_proxy` before its connection guards (same ordering as the main
  path), but `tools/front_proxy_e2e.py` has no WebSocket-capable backend, so that path is **wired and read,
  not observed under traffic**. An address rewrite that gates a WS handshake deserves its own probe when a
  real backend exists in the suite.
