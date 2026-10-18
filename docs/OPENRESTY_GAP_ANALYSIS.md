# ONRouter vs OpenResty - Gap Analysis

This document analyzes what ONRouter is missing compared to OpenResty and identifies areas for improvement.

## Executive Summary

**OpenResty** is a mature, production-grade Web platform based on Nginx + LuaJIT with extensive ecosystem. **ONRouter** is a Rust-based gateway inspired by Nginx/OpenResty architecture but still in early development.

### Current Status
- ✅ **Core Architecture**: Event-driven model, request lifecycle phases (implemented)
- ✅ **Basic Features**: Reverse proxy, load balancing, static files, TLS/SNI (implemented)
- ✅ **Lua Support**: Basic ngx.* API, shared_dict, file caching (implemented)
- ⚠️ **Missing**: Advanced modules, ecosystem, battle-tested stability

---

## 1. Critical Missing Features (High Priority)

### 1.1 Request/Response Body Filters
**OpenResty has:**
- `body_filter_by_lua` - Stream response body modification
- `header_filter_by_lua` - Response header manipulation

**ONRouter status:** ❌ Not implemented

**Impact:** Cannot do real-time response transformation, compression, or content injection.

### 1.2 Subrequests (Internal HTTP Calls)
**OpenResty has:**
- `ngx.location.capture()` - Make internal subrequests
- `ngx.location.capture_multi()` - Parallel subrequests

**ONRouter status:** ❌ Not implemented

**Impact:** Cannot compose responses from multiple backends, implement aggregation patterns.

### 1.3 Cosockets (Non-blocking I/O in Lua)
**OpenResty has:**
- `resty.socket` - Non-blocking TCP/UDP sockets
- `resty.redis`, `resty.mysql`, `resty.http` - Async database/HTTP clients

**ONRouter status:** ❌ Not implemented

**Impact:** Lua scripts cannot make async calls to Redis/MySQL/external APIs without blocking workers.

### 1.4 Timer Support
**OpenResty has:**
- `ngx.timer.at(delay, callback)` - One-shot timers
- `ngx.timer.every(interval, callback)` - Periodic timers
- Background tasks independent of requests

**ONRouter status:** ❌ Not implemented

**Impact:** Cannot run periodic cleanup, health checks, cache warming in background.

### 1.5 Shared Memory Locks
**OpenResty has:**
- `resty.lock` - Distributed locks using shared memory
- Mutex primitives for cross-worker coordination

**ONRouter status:** ❌ Not implemented (only shared_dict exists)

**Impact:** Cannot implement distributed rate limiting, leader election, or coordinated operations.

---

## 2. Important Missing Features (Medium Priority)

### 2.1 Advanced Lua APIs

| OpenResty API | ONRouter Status | Description |
|--------------|----------------|-------------|
| `ngx.req.set_body_data()` | ❌ | Modify request body |
| `ngx.req.discard_body()` | ❌ | Discard request body |
| `ngx.req.init_body()` | ❌ | Initialize buffered body |
| `ngx.req.append_body()` | ❌ | Append to request body |
| `ngx.req.finish_body()` | ❌ | Finalize request body |
| `ngx.req.socket()` | ❌ | Get raw request socket |
| `ngx.resp.get_headers()` | ⚠️ Partial | Response headers (basic) |
| `ngx.var.VARIABLE` | ❌ | Access nginx variables |
| `ngx.ctx` isolation | ⚠️ Basic | Per-request context (needs metatable) |
| `phase.is_internal()` | ❌ | Check if internal redirect |

### 2.2 Stream/TCP Proxying
**OpenResty has:**
- `stream-lua-nginx-module` - TCP/UDP proxying with Lua
- `stream_by_lua*` directives

**ONRouter status:** ❌ Only HTTP supported

**Impact:** Cannot proxy databases, custom protocols, WebSocket upgrades properly.

### 2.3 Dynamic Module Loading
**OpenResty has:**
- Hot-reload Lua modules without restart
- `package.path` customization
- Dynamic code compilation

**ONRouter status:** ⚠️ File mtime cache only (no hot reload)

### 2.4 SSL/TLS Session Management
**OpenResty has:**
- `ssl_certificate_by_lua` - Dynamic certificate selection
- `ssl_session_store_by_lua` - Custom session storage
- OCSP stapling support

**ONRouter status:** ⚠️ Static cert loading only

### 2.5 DNS Resolver
**OpenResty has:**
- `resty.dns.resolver` - Async DNS resolution
- Dynamic upstream discovery
- SRV record support

**ONRouter status:** ❌ Static config only

---

## 3. Ecosystem Gaps (Library Support)

### 3.1 Missing lua-resty-* Libraries

OpenResty provides these official libraries that ONRouter lacks:

| Library | Purpose | ONRouter Alternative |
|---------|---------|---------------------|
| `lua-resty-redis` | Async Redis client | ❌ None |
| `lua-resty-mysql` | Async MySQL client | ❌ None |
| `lua-resty-http` | Async HTTP client | ❌ None |
| `lua-resty-websocket` | WebSocket handling | ❌ None |
| `lua-resty-jwt` | JWT validation | ❌ None |
| `lua-resty-string` | Crypto utilities | ❌ None |
| `lua-resty-lock` | Shared memory locks | ❌ None |
| `lua-resty-dns` | DNS resolver | ❌ None |
| `lua-resty-upload` | Multipart upload parser | ❌ None |
| `lua-resty-cookie` | Cookie management | ❌ None |
| `lua-resty-core` | Core optimizations | ❌ None |
| `lua-resty-limit-traffic` | Rate limiting | ⚠️ Basic only |

### 3.2 Third-party Module Compatibility

OpenResty supports these Nginx modules that ONRouter doesn't:

- `echo-nginx-module` - Debug/testing commands
- `headers-more-nginx-module` - Advanced header manipulation
- `set-misc-nginx-module` - Utility functions (md5, sha1, etc.)
- `srcache-nginx-module` - Transparent caching layer
- `memc-nginx-module` - Memcached integration
- `redis2-nginx-module` - Redis upstream module
- `drizzle-nginx-module` - MySQL upstream module

---

## 4. Performance & Scalability Gaps

### 4.1 Worker Model Differences

| Feature | OpenResty | ONRouter |
|---------|-----------|---------|
| Workers | Multi-process (one per CPU) | Single process with thread pool |
| VM per worker | Yes (isolated) | Pool of VMs (shared) |
| IPC | Shared memory + Unix socket | Shared memory only |
| Graceful reload | `kill -HUP` (zero downtime) | ❌ Requires restart |

**Impact:** ONRouter cannot achieve zero-downtime reloads like OpenResty.

### 4.2 LuaJIT vs mlua

| Aspect | OpenResty (LuaJIT) | ONRouter (mlua/Lua 5.4) |
|--------|-------------------|------------------------|
| Performance | JIT compiled (~10x faster) | Interpreted |
| FFI | Yes (call C directly) | Limited |
| Coroutine | Native support | Via mlua |
| GC tuning | Advanced options | Standard Lua GC |

**Impact:** Lua scripts in ONRouter will be significantly slower than OpenResty.

---

## 5. Operational Gaps

### 5.1 Monitoring & Observability

**OpenResty has:**
- Prometheus metrics via `lua-resty-prometheus`
- Distributed tracing (Jaeger, Zipkin)
- Detailed error logging with stack traces
- Admin API for runtime inspection

**ONRouter status:** ❌ Basic access/error logs only

### 5.2 Configuration Management

**OpenResty has:**
- Dynamic configuration via REST API
- Configuration versioning
- Blue-green deployment support

**ONRouter status:** ❌ File-based config only (requires restart)

### 5.3 Testing Framework

**OpenResty has:**
- `Test::Nginx` - Perl-based test framework
- Built-in mock servers
- Traffic replay tools

**ONRouter status:** ⚠️ Basic Rust unit tests only

---

## 6. Security Gaps

### 6.1 WAF (Web Application Firewall)

**OpenResty has:**
- ModSecurity integration
- `lua-resty-waf` - Rule-based filtering
- SQL injection/XSS detection libraries

**ONRouter status:** ❌ No WAF capabilities

### 6.2 Rate Limiting

**OpenResty has:**
- Token bucket algorithm (`lua-resty-limit-traffic`)
- Sliding window counters
- Distributed rate limiting with Redis

**ONRouter status:** ⚠️ Basic leaky bucket only

### 6.3 Authentication

**OpenResty has:**
- OAuth2/OIDC libraries
- LDAP integration
- SAML support
- API key management

**ONRouter status:** ❌ No built-in auth

---

## 7. Roadmap Recommendations

### Phase 1: Core Stability (Current - v0.3)
- [ ] Fix shared_dict deadlock ✅ (Done)
- [ ] Complete WebSocket tunnel implementation
- [ ] Add timer support (`ngx.timer.at`)
- [ ] Implement `ngx.ctx` proper isolation
- [ ] Add request/response body filters

### Phase 2: Async I/O (v0.4 - v0.5)
- [ ] Implement cosocket API
- [ ] Build `resty.redis` equivalent
- [ ] Build `resty.http` client
- [ ] Add DNS resolver
- [ ] Subrequest support (`ngx.location.capture`)

### Phase 3: Ecosystem (v0.6 - v0.8)
- [ ] Port `lua-resty-jwt`
- [ ] Port `lua-resty-lock`
- [ ] Port `lua-resty-string` (crypto)
- [ ] Build rate limiting library
- [ ] Add authentication middleware

### Phase 4: Operations (v0.9 - v1.0)
- [ ] Prometheus metrics export
- [ ] Dynamic configuration API
- [ ] Graceful reload (zero downtime)
- [ ] Admin dashboard
- [ ] Comprehensive test suite

### Phase 5: Production Ready (v1.0+)
- [ ] WAF module
- [ ] Stream/TCP proxying
- [ ] Distributed tracing
- [ ] Enterprise features (LDAP, SAML)
- [ ] Performance optimization (consider LuaJIT binding)

---

## 8. Competitive Advantages of ONRouter

Despite gaps, ONRouter has unique strengths:

1. **Memory Safety**: Rust prevents entire classes of bugs (buffer overflows, use-after-free)
2. **Modern Tooling**: Cargo ecosystem, easy dependency management
3. **Cross-platform**: Windows/macOS/Linux/ARM/RISC-V builds
4. **Single Binary**: No external dependencies (unlike OpenResty needing LuaJIT)
5. **Cloud-native**: Docker/K8s ready out of the box
6. **Type Safety**: Compile-time guarantees reduce runtime errors

---

## 9. Conclusion

**ONRouter is approximately 30-40% feature-complete compared to OpenResty.**

The core gateway functionality is solid, but the rich ecosystem of async libraries, advanced Lua APIs, and operational tooling are missing. Focus should be on:

1. **Short-term**: Implement critical missing APIs (timers, body filters, subrequests)
2. **Mid-term**: Build async I/O foundation (cosockets) and port key resty libraries
3. **Long-term**: Develop operational excellence (metrics, dynamic config, zero-downtime reload)

**Estimated timeline to parity**: 12-18 months with dedicated team of 3-5 developers.

---

## References

- [OpenResty Official Documentation](https://openresty.org/)
- [lua-nginx-module Wiki](https://github.com/openresty/lua-nginx-module/wiki)
- [OpenResty Best Practices](https://github.com/moonbingbing/openresty-best-practices)
- [GeekBang OpenResty Course](https://time.geekbang.org/column/intro/100028301)

Sources:
- [OpenResty核心定位与优势](https://m.blog.csdn.net/qq_58967403/article/details/155502632)
- [Nginx Lua动态扩展](https://m.blog.csdn.net/onlymscn/article/details/154872138)
- [探索OpenResty：高性能Web开发利器](https://m.blog.csdn.net/weixin_43663196/article/details/151294235)
- [OpenResty官方文档](https://openresty.org/cn/)
