# Architecture & internals

How the process is put together, where the hot paths would block and how they avoid it, and where
each part lives in the tree.


## Multi-core architecture

- **tokio multi-threaded runtime**: `worker_threads N;` (default = number of logical CPU cores).
  With `worker_cpu_affinity auto;` or explicit masks, each worker is pinned to its core; the
  default is `off`, so existing deployments keep the OS scheduler's placement. `-t` reports the
  per-thread plan and the startup log records each successful binding.
- **Lua VM pool**: one independent Lua VM per CPU core, so no script state is shared across cores.
  Multiple requests execute scripts fully in parallel with no global single-point lock;
  `init_by_lua` runs once per VM (matching nginx's once-per-worker initialization semantics).
- **Within-VM coroutine scheduler**: each VM is driven by a dedicated scheduler task that interleaves
  many in-flight requests as Lua coroutines — a request yields only at `ngx.sleep` and the VM lock is
  released between synchronous resume segments, so `ngx.timer` callbacks and sleep timers progress
  while other requests on the same VM run (many requests in flight per VM, not one-request-per-VM).
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
            ├── stream.rs    # L4 stream{} proxy: byte-transparent TCP tunnels + ssl_preread SNI routing, and UDP datagram sessions
            └── server.rs    # HTTP pipeline: rewrite -> access -> content -> log
```
