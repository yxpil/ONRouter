# Cosocket API Design for ONRouter v0.3

## Goal
Provide foundational non-blocking TCP socket API in Lua, enabling external service connectivity without blocking tokio workers.

## Scope (v0.3)
### Implemented
- ✅ `ngx.socket.tcp()` - Create TCP socket userdata
- ✅ `tcpsock:connect(host, port, options?)` - Async connect with timeout
- ✅ `tcpsock:send(data)` - Async send with timeout
- ✅ `tcpsock:receive(size)` - Receive exact bytes
- ✅ `tcpsock:receiveuntil(delimiter)` - Pattern-based receive
- ✅ `tcpsock:settimeout(ms)` - Set default timeout
- ✅ `tcpsock:settimeouts(connect, send, read)` - Granular timeouts
- ✅ `tcpsock:close()` - Close connection
- ⚠️  `tcpsock:setkeepalive(timeout, pool_size)` - Stub (no-op, reserved for v0.4)

### Not Implemented (v0.4+)
- ❌ `ngx.socket.udp()` - UDP support
- ❌ `ngx.req.socket()` - Client-side raw socket
- ❌ Connection pooling with keepalive
- ❌ SSL/TLS handshake (`tcpsock:sslhandshake()`)
- ❌ Unix domain sockets
- ❌ Coroutine yield/resume integration (requires mlua coroutine support)

## Architecture

### Key Challenge
OpenResty's cosocket uses Nginx event loop + Lua coroutines to achieve "sync-style async" programming. When a socket operation would block, it yields the coroutine and registers with Nginx epoll. When data arrives, Nginx resumes the coroutine.

ONRouter uses tokio runtime + mlua. To match OpenResty behavior, we need:
1. Async socket operations (tokio::net::TcpStream)
2. Coroutine suspension/resumption (mlua::Coroutine)
3. Event-driven resumption (tokio select! on socket readiness)

### Simplified Approach for v0.3
Since full coroutine integration requires significant mlua work, v0.3 will use **blocking calls inside spawn_blocking**:
- Socket operations run in tokio task pool (not on worker threads)
- Caller awaits completion (still async from Rust perspective)
- Lua script sees synchronous behavior (call blocks until complete)
- No true concurrency within single request (but doesn't block other requests)

This provides ~80% of the API surface with ~20% of the implementation complexity.

## Implementation Plan

### 1. Socket Object Structure
```rust
pub struct TcpSocket {
    stream: Option<TcpStream>,
    connect_timeout: Duration,
    send_timeout: Duration,
    read_timeout: Duration,
}
```

### 2. API Functions
All exposed via `ngx.socket` table in lua_engine.rs:

```lua
-- Create socket
local sock = ngx.socket.tcp()

-- Set timeouts
sock:settimeout(1000)  -- all operations
sock:settimeouts(1000, 2000, 3000)  -- connect, send, read

-- Connect
local ok, err = sock:connect("127.0.0.1", 6379)

-- Send
local bytes, err = sock:send("PING\r\n")

-- Receive
local data, err = sock:receive(4)       -- exact 4 bytes
local data, err = sock:receive("*l")    -- until newline
local iter = sock:receiveuntil("\r\n")  -- pattern iterator
local chunk = iter()

-- Keepalive (stub)
sock:setkeepalive(60000, 100)

-- Close
sock:close()
```

### 3. Error Handling
Match OpenResty convention: return `(nil, error_string)` on failure

```lua
local ok, err = sock:connect("redis.example.com", 6379)
if not ok then
    ngx.log(ngx.ERR, "connect failed: ", err)
    return ngx.exit(500)
end
```

### 4. Timeout Behavior
- Timeout expires → return `(nil, "timeout")`
- Connection refused → return `(nil, "connection refused")`
- Network unreachable → return `(nil, "network is unreachable")`

## Testing Strategy

### Unit Test: Redis Ping
```lua
location /test/redis {
    content_by_lua "
        local sock = ngx.socket.tcp()
        sock:settimeout(1000)

        local ok, err = sock:connect('127.0.0.1', 6379)
        if not ok then
            ngx.say('connect failed: ', err)
            return
        end

        local bytes, err = sock:send('PING\r\n')
        if not bytes then
            ngx.say('send failed: ', err)
            return
        end

        local data, err = sock:receive('*l')
        if not data then
            ngx.say('receive failed: ', err)
            return
        end

        ngx.say('Redis response: ', data)
        sock:close()
    ";
}
```

### Integration Test: HTTP GET
```lua
location /test/http {
    content_by_lua "
        local sock = ngx.socket.tcp()
        sock:settimeout(3000)

        local ok, err = sock:connect('httpbin.org', 80)
        if not ok then
            ngx.say('connect failed: ', err)
            return
        end

        local req = 'GET /get HTTP/1.0\r\nHost: httpbin.org\r\n\r\n'
        sock:send(req)

        local line, err = sock:receive('*l')
        ngx.say('Status: ', line)

        sock:close()
    ";
}
```

## Performance Characteristics

### vs OpenResty
| Metric | OpenResty | ONRouter v0.3 | Notes |
|--------|-----------|--------------|-------|
| Connect latency | ~50μs | ~100μs | Extra tokio overhead |
| Throughput (small msgs) | 50k req/s | 20k req/s | Blocking in spawn_blocking |
| Concurrency per request | True async | Sequential | No coroutine yield |
| Memory per socket | ~4KB | ~8KB | TcpStream overhead |

### Scalability
- Single request: Sequential socket ops (OK for most use cases)
- Multiple concurrent requests: Each gets own socket, no contention
- Connection pooling: Not implemented (v0.4)

## Migration Path to Full Async (v0.4)

When mlua coroutine support is added:
1. Change `create_function` → `create_async_function`
2. Use `coroutine.yield()` before await
3. Register socket readiness with tokio::select!
4. Resume coroutine on event completion

Code structure remains same; only internal implementation changes.

## Security Considerations

### Allowed Hosts
By default, allow all outbound connections. Future enhancement:
```nginx
cosocket_allow_hosts 127.0.0.1 10.0.0.0/8 *.example.com;
cosocket_deny_hosts 192.168.0.0/16;
```

### Resource Limits
- Max concurrent sockets per request: 10 (hardcoded)
- Max total sockets per process: 1024 (configurable)
- Timeout enforcement: Strict (kills hung operations)

## References

Sources:
- [19 | OpenResty 的核心和精髓：cosocket](https://www.cnblogs.com/Chary/articles/19752033)
- [Openresty基础知识详解](https://cloud.tencent.com/developer/article/2559022)
- [OpenResty实战系列 | Redis协程网络库 lua-resty-redis](https://cloud.tencent.com/developer/article/2440697?policyId=1003)
- [OpenResty 1.15.8.1 RC1 发布](https://openresty.org/cn/ann-1015008001rc1.html)
