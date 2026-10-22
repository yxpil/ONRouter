# Security

The defaults and hard rules this gateway enforces, and what each one is defending against. The
audit trail — every finding, reproduction and fix — is in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
## Security

- **Path traversal protection**: RFC 3986 dot-segment normalization; `../` / `..%2f` / `%252e` /
  backslash / null-byte payloads are all blocked, and escaping the root returns 400 directly.
- **Request smuggling protection**: duplicate Content-Length / illegal CL / CL+TE together → 400;
  HTTP/1.1 missing Host → 400.
- **Unknown method** → 501; URL > 8 KB → 414; oversized headers → 431; oversized body → 413
  (rejected before the body is read).
- **Slow connections**: do not block normal requests (the tokio concurrency model is inherently
  resistant to single-connection Slowloris attacks). Streamed uploads (`proxy_request_buffering off`)
  are covered by `client_body_timeout` too — the limit is per inter-read interval, not total body time.
- **Fail-closed access control**: `auth_basic` without `auth_basic_user_file` denies (401) instead of
  serving, htpasswd entries with an empty hash are dropped (no empty-password login), an unparsable
  peer address denies rather than skips the `allow`/`deny` rules, and the htpasswd cache is bounded by
  a 1 s staleness limit on top of `(mtime, size)` invalidation so revoked credentials stop working even
  when a file is rebuilt with identical timestamps.
- **No front/back URI disagreement**: the Upgrade (WebSocket) tunnel forwards the client's raw,
  undecoded request target — routing/ACL decisions and what the backend parses are about the same URI.
- **Bounded blast radius**: `sub_filter` buffers at most 8 MiB per response (larger files stream
  unfiltered, with a warning), and Lua coroutines are preempted every `lua_slice_instructions`
  VM instructions (default 1 000 000) so a runaway loop can no longer stall the single process.
- **Still ONLine copies cannot carry a session**: the last-known-good replay layer has three hard
  rules with no configuration switch — a response containing `Set-Cookie` is never stored, a request
  carrying `Cookie`/`Authorization` never writes a copy (and by default is not served one either, so a
  shared copy can never be handed to a logged-in visitor as if it were theirs), and `Set-Cookie` is
  stripped from every replayed response. Only anonymous `GET` + 2xx responses enter the zone, and the
  background re-fetch after recovery is itself an anonymous request that goes through the normal ACL /
  `limit_req` / rewrite path.
- **CDN headers cannot move an identity**: every value `front_proxy` derives from a request header —
  client address, `$scheme`, country, visible host — is used only when the direct TCP peer falls inside a
  `trust` range the operator declared (or `set_real_ip_from`), so a client that copies a real provider's
  whole header set is left on the node address for `allow`/`deny`, `limit_req`, `geo`, VIP reputation, the
  access log and the cache key alike. Recognition alone only labels; a profile with no `probe` can never
  match; and promoting a profile's own ranges into a rewriting authority needs the explicit
  `front_proxy_auto_trust on`, which warns once per profile and names the vhost at `-t`. `Cache-Status` is
  likewise suppressed for unverified peers, so a hit rate a client could inflate is not a metric.
- Security tests: `sec_test.py` (30 checks, covering traversal / smuggling / CRLF injection /
  malformed requests / oversized requests / default response headers),
  `tools/security_matrix_e2e.py` (36 checks, one gateway process per probe, reproducing each finding
  from `SECURITY_AUDIT.md` with real traffic — every probe fails on the pre-fix binary) and
  `tools/rce_matrix_e2e.py` (27 checks on the remote-execution surface: Lua-source/path injection,
  `internal` location escape, `proxy_pass` SSRF with a canary listener, encoded-CRLF request
  splitting; the backend used by these probes echoes the exact request line it received).
