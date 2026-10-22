# Examples

Runnable configurations, smallest first. Every file starts with the exact commands to try it.

```bash
cargo build --release

target/release/onrouter -t examples/static-site.conf    # validate, print warnings
target/release/onrouter -c examples/static-site.conf    # serve
```

| File | What it shows | Ports |
|---|---|---|
| [static-site.conf](static-site.conf) | static files, autoindex, gzip, `expires`, conditional requests | 18080 |
| [reverse-proxy.conf](reverse-proxy.conf) | `upstream`, `least_conn`, passive health checks, `lazy_rejoin`, timeouts | 18081 → 9001/9002 |
| [tls-http2-http3.conf](tls-http2-http3.conf) | one port serving HTTP/1.1, HTTP/2 and HTTP/3 over TLS | 18443 (TCP+UDP) |
| [lua-gateway.conf](lua-gateway.conf) | Lua: shared-dict counter, `access_by_lua`, redirect | 18082 |
| [rate-limit.conf](rate-limit.conf) | `limit_req` keyed by a header, `limit_conn` by address | 18083 |
| [proxy-cache.conf](proxy-cache.conf) | `proxy_cache`, request coalescing, revalidation | 18084 → 9001 |
| [canary.conf](canary.conf) | canary routing by cookie/header/percent with sticky keys | 18085 → 9001/9002 |
| [stream-tcp-udp.conf](stream-tcp-udp.conf) | SNI-routed TCP tunnel and UDP sessions | 18751/18752 |

## Common setup

```bash
# two demo backends for the proxy examples
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1
```

- All examples bind loopback only and use disjoint ports, so they can run together.
- Relative paths (`root`, `proxy_cache_path`, certificates) resolve against the directory of the
  config file. Run the commands from the repository root so the paths above line up.
- `certs/cert.pem` is a self-signed pair for `localhost` / `127.0.0.1`; generate your own with
  `cargo run --bin orr-gencert -- certs/cert.pem certs/key.pem your.domain`.
- `-t` prints every ignored/unknown directive as a warning but still exits `0`; read the output.
- HTTP/3 needs an h3 client: `cargo build --bin orr-h3check`, then
  `target/release/orr-h3check 127.0.0.1:18443 localhost / single`.
  In Git Bash, prefix it with `MSYS2_ARG_CONV_EXCL='*'` — MSYS otherwise rewrites the `/`
  path argument into a Windows path before the probe sees it.
- A running process reloads routing, Lua and certificates on `SIGHUP`; new `listen` ports and log
  levels need a restart.

For larger end-to-end shapes (cache cold tier, WASM, traffic splitting, the full tutorial), see
`conf/tutorial_full.conf` and [the tutorial](../docs/TUTORIAL.md).
