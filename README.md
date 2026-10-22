<p align="center">
  <img src="public/logo.png" alt="ONRouter logo" width="180">
</p>

# ONRouter

**ONRouter** (short **ORR**) is a general-purpose gateway server written from scratch in Rust.

One process terminates TLS, serves static files, proxies and load-balances upstreams, caches
responses, rate-limits traffic, runs Lua and WASM at request time, and forwards raw TCP and UDP.
It is configured with an nginx-style configuration language, shipped as a single binary, and runs
on Linux, Windows and macOS.

- **HTTP/1.1, HTTP/2 and HTTP/3** — TLS or cleartext h2c; QUIC on the same port number as TCP.
- **Reverse proxy** — weighted round-robin, `least_conn`, `ip_hash`, adaptive `least_time`, passive
  health checks, circuit breaker, keepalive pools, TLS/mTLS upstreams.
- **Response cache** — named zones with an optional disk cold tier, revalidation, request
  coalescing, stale-while-revalidate.
- **Scripting** — Lua 5.4 (`ngx.*`: phases, timers, cosockets, subrequests, shared dicts, TLS
  certificate selection) and WASM plugins, both resource-bounded.
- **Traffic control** — `limit_req` / `limit_conn` keyed by any request variable, canary releases,
  calendar access windows.
- **Layer 4** — byte-transparent TCP tunnels with SNI preread, and UDP sessions with per-client
  isolation.

[Quick start](#quick-start) · [Examples](examples/) · [Documentation](#documentation)

## Quick start

```bash
cargo build --release

# validate a config: listeners, certificates, zones, directives (warnings included)
target/release/onrouter -t examples/static-site.conf

# serve it
target/release/onrouter -c examples/static-site.conf
curl -i http://127.0.0.1:18080/
```

On Windows the binary is `target\release\onrouter.exe`.

For the proxy examples, start two demo backends in another shell:

```bash
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1
```

A minimal configuration looks like this:

```nginx
server {
    listen 8080;
    server_name example.test;
    root "./public";
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /health {
        return 200 "ok\n";
    }
}
```

`-t` prints every ignored or unknown directive as a warning but exits `0`; read the output. A
running process reloads routing, Lua scripts and certificates on `SIGHUP` (or on file changes when
`reload <interval>;` is set); new `listen` ports need a restart. Relative paths resolve against the
config file's directory.

## Examples

Small, complete configs you can start and probe. Each file begins with its own commands.

| Example | What it shows |
|---|---|
| [static-site.conf](examples/static-site.conf) | static files, index/autoindex, gzip, `expires`, conditional requests |
| [reverse-proxy.conf](examples/reverse-proxy.conf) | upstream pool, `least_conn`, health checks, `lazy_rejoin`, timeouts |
| [tls-http2-http3.conf](examples/tls-http2-http3.conf) | HTTP/1.1 + HTTP/2 + HTTP/3 on one TLS port |
| [lua-gateway.conf](examples/lua-gateway.conf) | shared-dict counter, `access_by_lua`, redirect |
| [rate-limit.conf](examples/rate-limit.conf) | `limit_req` keyed by a header, `limit_conn` by address |
| [proxy-cache.conf](examples/proxy-cache.conf) | `proxy_cache`, coalescing lock, revalidation |
| [canary.conf](examples/canary.conf) | canary routing by cookie / header / percent, sticky keys |
| [stream-tcp-udp.conf](examples/stream-tcp-udp.conf) | SNI-routed TCP tunnel and UDP sessions |

See [examples/README.md](examples/README.md) for the common setup and per-example `curl` checks.

## Capabilities

**Protocols.** HTTP/1.1 and HTTP/2 over TLS or cleartext (h2c prior knowledge), HTTP/3 over QUIC,
WebSocket/Upgrade tunnels, `ssl_preread` SNI routing, TCP tunnels and UDP sessions in the same
process. TLS 1.2/1.3 with SNI certificate selection across vhosts, session resumption, per-SNI
Lua certificate callbacks.

**Routing.** Exact, prefix and regex locations; server-level `return`/`rewrite`; variables and
`map` / `geo` / `split_clients`; `error_page`, `try_files`, `alias`, `index`, `autoindex`,
`sub_filter`, location and cookie rewriting; named upstreams and `proxy_pass` with URI replacement.

**Upstreams.** Weighted round-robin, `least_conn`, `ip_hash`; `max_fails` / `fail_timeout`;
`lazy_rejoin` (the next real request probes a recovered node); `circuit_breaker`; keepalive pools;
`proxy_next_upstream` with timeout budgets; HTTPS and mTLS backends; an asynchronous DNS resolver.

**Caching.** In-memory `proxy_cache` zones, optional disk cold tier for evicted-but-fresh entries,
revalidation with `ETag` / `Last-Modified`, request coalescing (`proxy_cache_lock`), stale serving,
bypass rules, upstream cache headers and `X-Cache-Status`.

**Traffic and access.** Rate and concurrency limits keyed by IP, header, cookie, query or a
concatenation; bounded queues; canary releases; `allow` / `deny`; basic auth; real-IP handling
behind CDNs; time-windowed access.

**Scripting and observability.** Lua 5.4 with the `ngx.*` API and `resty.*` modules; WASM plugins in
access, header and body filters; Prometheus metrics (process, upstreams, cache, limits, TLS);
access logs with upstream address, status and timings.

**Operations.** Config validation (`-t`), hot reload, worker threads and CPU affinity, graceful
shutdown, one process for L7 and L4.

## Documentation

| Document | Contents |
|---|---|
| [Examples](examples/README.md) | runnable configurations |
| [Tutorial](docs/TUTORIAL.md) | build a gateway feature by feature |
| [Operations](docs/OPERATIONS.md) | production process, capacity, release and rollback |
| [Capability matrix](docs/CAPABILITY_MATRIX.md) | what is implemented, the evidence per row, and what is not |
| [Feature map](docs/FEATURES.md) | directive-by-directive map to the source |
| [Lua API](docs/LUA_API.md) | the `ngx.*` surface and `resty.*` modules |
| [Architecture](docs/ARCHITECTURE.md) | process model, hot paths, source layout |
| [Design notes](docs/DESIGN.md) | deliberate choices, extensions, roadmap |
| [Security](docs/SECURITY.md) | defaults and hard rules; [audit](docs/SECURITY_AUDIT.md) |
| [Testing](docs/TESTING.md) | test organization and the full gate |
| [Benchmarks](docs/BENCHMARKS.md) | measured costs and methodology |
| [Changelog](docs/CHANGELOG.md) | release history |
| [CROSS_PLATFORM.md](CROSS_PLATFORM.md) | platform notes and build matrix |

Deployment: [Dockerfile](Dockerfile), [docker-compose.yml](docker-compose.yml),
[kubernetes/](kubernetes/), [CLOUD_DEPLOY.md](CLOUD_DEPLOY.md).

## Building and testing

```bash
cargo build --release
cargo test --workspace

# optional: post-quantum key exchange on inbound TLS (adds aws-lc, a C build)
cargo build --release --features pq
```

The E2E roll drives real traffic through the built binary; start it with a script list:

```bash
python run_regression.py reg_104_gate.txt
```

CI runs unit tests, clippy and the E2E suites on Linux.

## Compatibility and status

The configuration language follows nginx syntax, and the Lua layer follows the `ngx.*` API shape.
ONRouter is an independent implementation, not affiliated with nginx or any other gateway; where
behaviour differs, it is documented rather than silent: see
[CAPABILITY_MATRIX.md](docs/CAPABILITY_MATRIX.md) and [DESIGN.md](docs/DESIGN.md). Features with no
counterpart elsewhere are marked in [FEATURES.md](docs/FEATURES.md).

1.0.x is the current release line. What changed in each release is in
[CHANGELOG.md](docs/CHANGELOG.md).

## License

MIT.
