//! 纯 Lua 的 `resty.*` 模块库：通过 `package.preload` 注册，使请求脚本可以
//! `require "resty.string"` / `require "resty.lock"`，对标 OpenResty 的同名模块语义。
//!
//! 这里的 Lua 源码全部为本项目原创实现（对照公开 API 文档语义手写），未复制任何
//! OpenResty / MIT 上游源码。模块只依赖已在 `lua_engine.rs` 暴露的原生能力：
//!   - `ngx.sha256_bin` / `ngx.md5_bin`（ring 摘要，供 resty.string 复用）；
//!   - `ngx.shared.DICT` 的 `add/get/delete/incr`（供 resty.lock 做分布式互斥）；
//!   - `ngx.now` / `ngx.sleep`（让出式轮询退避）。

use mlua::prelude::*;

/// resty.string —— to_hex / sha256_hex / md5_hex。
const RESTY_STRING: &str = r##"
local _M = {}

local byte  = string.byte
local fmt   = string.format
local concat = table.concat

-- to_hex(str)：把任意字节串编码为小写十六进制（OpenResty 语义）。
function _M.to_hex(s)
    local out = {}
    for i = 1, #s do
        out[i] = fmt("%02x", byte(s, i))
    end
    return concat(out)
end

-- sha256_hex(str)：底层调用原生 ngx.sha256_bin（原始 32 字节）再转十六进制。
function _M.sha256_hex(s)
    return _M.to_hex(ngx.sha256_bin(s))
end

-- md5_hex(str)：底层调用原生 ngx.md5_bin（原始 16 字节）再转十六进制。
function _M.md5_hex(s)
    return _M.to_hex(ngx.md5_bin(s))
end

return _M
"##;

/// resty.lock —— 基于共享字典 add() 原子占位的分布式互斥锁，支持超时与自动过期。
const RESTY_LOCK: &str = r##"
local _M = {}
local mt = { __index = _M }

local COUNTER_KEY = "@resty.lock.monotonic"

-- new(dict, opts)：dict 可为共享字典名（字符串）或 DICT 对象本身。
--   opts.timeout  = 获取锁的最长等待秒数（默认 1）
--   opts.exptime  = 锁的自动过期秒数（默认 = timeout）
function _M.new(self, dict, opts)
    local d
    if type(dict) == "string" then
        d = ngx.shared[dict]
        if not d then
            return nil, "shared dict not found: " .. dict
        end
    else
        d = dict
    end
    opts = opts or {}
    local timeout = opts.timeout or 1
    local exptime = opts.exptime or timeout
    if exptime <= 0 then exptime = 0.001 end
    return setmetatable({
        dict = d,
        timeout = timeout,
        exptime = exptime,
        token = nil,
        key = nil,
    }, mt)
end

-- lock(key) -> elapsed | nil, err
--   成功返回等待耗时（秒，0 表示立即获得）；失败返回 nil 与 "timeout"/其它错误。
--   用单调递增令牌作为锁值，使 unlock() 只释放自己那一把（防止过期后被他人重取再误删）。
function _M.lock(self, key, ...)
    if self.key then
        return nil, "already locked"
    end
    local dict = self.dict
    local exptime = self.exptime

    local token = dict:incr(COUNTER_KEY, 1, 0)
    if not token then
        return nil, "failed to allocate lock token"
    end

    local elapsed = 0
    local step = 0.001

    local ok, err = dict:add(key, token, exptime)
    if ok == nil then return nil, err end
    if ok then
        self.token = token
        self.key = key
        return elapsed
    end

    -- 锁被他人持有：带上限的指数退避轮询（ngx.sleep 为让出点，不阻塞 VM）。
    while true do
        ngx.sleep(step)
        elapsed = elapsed + step
        if elapsed > self.timeout then
            return nil, "timeout"
        end
        ok, err = dict:add(key, token, exptime)
        if ok == nil then return nil, err end
        if ok then
            self.token = token
            self.key = key
            return elapsed
        end
        step = step * 2
        if step > 0.05 then step = 0.05 end
    end
end

-- unlock() -> true | nil, err：仅当锁值仍是本实例令牌时才删除。
function _M.unlock(self)
    local dict = self.dict
    local key = self.key
    if not key then
        return nil, "not locked"
    end
    local cur = dict:get(key)
    if cur ~= nil and tostring(cur) == tostring(self.token) then
        dict:delete(key)
    end
    self.key = nil
    self.token = nil
    return true
end

return _M
"##;

/// resty.http —— 基于原生 cosocket 的纯 Lua HTTP/1.1 客户端（本项目原创实现，
/// 对照 lua-resty-http 公开 API 语义手写，未复制上游源码）。支持 connect/request、
/// Content-Length 与 chunked 响应体、HEAD/204/304 空体、keepalive 连接复用与 TLS 升级。
const RESTY_HTTP: &str = r##"
local _M = {}
local mt = { __index = _M }

local lower = string.lower
local sub   = string.sub
local find  = string.find
local byte  = string.byte
local tonumber = tonumber

-- 大写化方法名（仅 ASCII，避免本地化影响）
local function upper_ascii(s)
    local out = {}
    for i = 1, #s do
        local b = byte(s, i)
        if b >= 97 and b <= 122 then out[i] = string.char(b - 32) else out[i] = sub(s, i, i) end
    end
    return table.concat(out)
end

-- 状态行 "HTTP/1.1 200 OK" -> { version, status, reason }
local function parse_status(line)
    local code = tonumber(line:match("^HTTP/%d%.%d%s+(%d+)"))
    if not code then return nil, "bad status line: " .. tostring(line) end
    local reason = line:match("^HTTP/%d%.%d%s+%d+%s+(.*)$") or ""
    return { status = code, reason = reason }
end

-- 逐行读响应头（大小写归一为小写键），空行结束
local function read_headers(sock)
    local h = {}
    while true do
        local line, err = sock:receive("*l")
        if not line then return nil, err end
        if line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.-)%s*$")
        if k then
            local lk = lower(k)
            -- 重复头聚合为逗号分隔（对标常见行为）
            if h[lk] then h[lk] = h[lk] .. ", " .. v else h[lk] = v end
        end
    end
    return h
end

-- 组装并读取响应体：chunked / Content-Length / 读到关闭；HEAD 与 204/304 恒空。
local function read_body(sock, headers, method, status)
    if method == "HEAD" or status == 204 or status == 304 then
        return ""
    end
    local te = headers["transfer-encoding"]
    if te and lower(te):find("chunked", 1, true) then
        local parts = {}
        while true do
            local szline, e1 = sock:receive("*l")
            if not szline then return nil, e1 or "chunk size error" end
            local sz = tonumber(szline:match("^%x+") or "", 16)
            if not sz then return nil, "bad chunk size: " .. szline end
            if sz == 0 then
                sock:receive("*l") -- 消费收尾空行（无 trailer 情形）
                break
            end
            local data, e2 = sock:receive(sz)
            if not data then return nil, e2 or "chunk data error" end
            parts[#parts + 1] = data
            sock:receive(2) -- 吃掉块后 CRLF
        end
        return table.concat(parts)
    end
    local cl = headers["content-length"]
    if cl then
        local n = tonumber(cl)
        if not n then return nil, "bad content-length" end
        if n == 0 then return "" end
        local data, err = sock:receive(n)
        if not data then return nil, err end
        return data
    end
    -- 无长度信息：读到连接关闭
    local data, err = sock:receive("*a")
    sock:close()
    if not data then
        if err == "closed" then return "" end
        return nil, err
    end
    return data
end

-- new() -> 客户端对象
function _M.new(_)
    return setmetatable({
        sock = nil,
        connected = false,
        keepalive = false,
        timeout_ms = 30000,
        host = nil,
        port = nil,
        scheme = "http",
    }, mt)
end

-- set_timeout(ms)：cosocket 各操作的超时（毫秒，与 OpenResty settimeout 单位一致）
function _M.set_timeout(self, ms)
    self.timeout_ms = ms
    if self.sock then self.sock:settimeout(ms) end
    return true
end

-- set_keepalive(timeout_sec, pool_size)：请求结束后把空闲连接归还 cosocket 连接池
function _M.set_keepalive(self, timeout, pool_size)
    if not self.sock then return nil, "closed" end
    local ok, err = self.sock:setkeepalive(timeout, pool_size)
    if ok then self.connected = false end
    return ok, err
end

-- connect(opts)：opts = { scheme, host, port, ssl_verify, ssl_cafile, server_name }
function _M.connect(self, opts)
    opts = opts or {}
    local scheme = lower(opts.scheme or self.scheme or "http")
    local host = opts.host or self.host
    if not host then return nil, "no host specified" end
    local port = opts.port or (scheme == "https" and 443 or 80)
    if self.connected and self.host == host and self.port == port then
        return 1
    end
    self.sock = self.sock or ngx.socket.tcp()
    self.sock:settimeout(self.timeout_ms)
    local ok, err = self.sock:connect(host, port)
    if not ok then return nil, err end
    if scheme == "https" then
        local hs, herr = self.sock:tlshandshake({
            server_name = opts.server_name or host,
            verify = opts.ssl_verify,
            ca = opts.ssl_cafile,
        })
        if not hs then return nil, "tls handshake failed: " .. tostring(herr) end
    end
    self.connected = true
    self.host, self.port, self.scheme = host, port, scheme
    return ok
end

-- request(opts)：opts = { method, path, headers, body, query, keepalive, scheme/host/port }
-- 成功返回 { status_code, headers, body, reason }；失败返回 nil, err。
function _M.request(self, opts)
    opts = opts or {}
    if opts.keepalive == nil then opts.keepalive = self.keepalive end
    if not self.connected or opts.host or opts.scheme or opts.port then
        local ok, err = self:connect(opts)
        if not ok then return nil, err end
    end
    local method = upper_ascii(opts.method or "GET")
    local path = opts.path or "/"
    if opts.query then
        local q = type(opts.query) == "table" and ngx.encode_args(opts.query) or tostring(opts.query)
        if q ~= "" then
            path = path .. (find(path, "?", 1, true) and "&" or "?") .. q
        end
    end
    local headers = opts.headers or {}

    -- 规范化 headers：允许数组式 {["K"]="V"}，检测 Host/Content-Length/Connection 是否已给
    local line = {}
    line[#line + 1] = method .. " " .. path .. " HTTP/1.1\r\n"
    local has_host, has_cl, has_conn = false, false, false
    for k, v in pairs(headers) do
        local lk = lower(tostring(k))
        if lk == "host" then has_host = true
        elseif lk == "content-length" then has_cl = true
        elseif lk == "connection" then has_conn = true end
        line[#line + 1] = tostring(k) .. ": " .. tostring(v) .. "\r\n"
    end
    if not has_host then
        local hp = tostring(self.host)
        local default_port = (self.scheme == "https") and 443 or 80
        if self.port ~= default_port then hp = hp .. ":" .. self.port end
        line[#line + 1] = "Host: " .. hp .. "\r\n"
    end
    local body = opts.body
    if body and not has_cl then
        line[#line + 1] = "Content-Length: " .. #body .. "\r\n"
    end
    if not has_conn then
        if opts.keepalive then
            line[#line + 1] = "Connection: keep-alive\r\n"
        else
            line[#line + 1] = "Connection: close\r\n"
        end
    end
    line[#line + 1] = "\r\n"

    local bytes, serr = self.sock:send(table.concat(line))
    if not bytes then return nil, serr end
    if body and #body > 0 then
        local b2, berr = self.sock:send(body)
        if not b2 then return nil, berr end
    end

    local sline, rerr = self.sock:receive("*l")
    if not sline then return nil, rerr end
    local st, perr = parse_status(sline)
    if not st then return nil, perr end
    local hdrs, herror = read_headers(self.sock)
    if not hdrs then return nil, herror end
    local rbody, berror = read_body(self.sock, hdrs, method, st.status)
    if not rbody then return nil, berror end

    local conn = lower(hdrs["connection"] or "")
    if find(conn, "close", 1, true) then self.connected = false end

    self._status = st.status
    self._headers = hdrs
    return {
        status_code = st.status,
        reason      = st.reason,
        headers     = hdrs,
        body        = rbody,
        code        = st.status,
    }
end

function _M.get_status_code(self) return self._status end
function _M.get_headers(self) return self._headers end

function _M.set_client_cert(self, _) return true end

-- close()：关闭底层连接
function _M.close(self)
    if self.sock then self.sock:close() end
    self.connected = false
    return true
end

-- 便捷方法
function _M.request_path(self, path, timeout)
    if timeout then self:set_timeout(timeout) end
    return self:request({ path = path })
end

return _M
"##;

/// resty.redis —— 基于原生 cosocket 的纯 Lua RESP 客户端（本项目原创实现，对照
/// lua-resty-redis 公开 API 语义手写，未复制上游源码）。支持 connect/command、
/// 动态命令派发（redis:get(...)）、+/-/:/$/* 全类型回复解析、pipeline/commit、
/// keepalive 连接池复用与错误/nil 回复。
const RESTY_REDIS: &str = r##"
local _M = {}
local mt = { __index = nil }   -- __index 稍后设为函数（已知方法 or 动态命令派发）

local sub      = string.sub
local concat   = table.concat
local tonumber = tonumber
local select   = select

-- 读取一条 RESP 回复。返回约定：simple string→字符串；error→nil,err；integer→数字；
-- bulk→字符串 / false(nil) / ""(空)；array→表 / false(nil)。
local function read_reply(sock)
    local line, err = sock:receive("*l")
    if not line then return nil, err end
    local t = sub(line, 1, 1)
    local body = sub(line, 2)
    if t == "+" then
        return body
    elseif t == "-" then
        return nil, body
    elseif t == ":" then
        return tonumber(body)
    elseif t == "$" then
        local n = tonumber(body)
        if n == -1 then return false end
        if n == 0 then return "" end
        local data, e = sock:receive(n)
        if not data then return nil, e end
        sock:receive(2) -- 吃掉数据后 CRLF
        return data
    elseif t == "*" then
        local cnt = tonumber(body)
        if cnt == -1 then return false end
        local out = {}
        for i = 1, cnt do
            local r, e = read_reply(sock)
            if r == nil and e ~= nil then return nil, e end
            out[i] = r
        end
        return out
    end
    return nil, "unknown RESP reply type: " .. tostring(t)
end

-- new() -> 客户端对象
function _M.new(_)
    return setmetatable({
        sock = nil,
        connected = false,
        timeout = 5000,
        host = nil,
        port = nil,
        err = nil,
    }, mt)
end

-- connect(host, port, opts?)：opts.timeout（毫秒）
function _M.connect(self, host, port, opts)
    opts = opts or {}
    self.sock = self.sock or ngx.socket.tcp()
    local ms = opts.timeout or self.timeout
    self.sock:settimeout(ms)
    local ok, err = self.sock:connect(host, port)
    if not ok then
        self.connected = false
        self.err = err
        return nil, err
    end
    self.connected = true
    self.host, self.port = host, port
    self.err = nil
    return ok
end

-- set_timeout(ms)：读写超时（毫秒）
function _M.set_timeout(self, ms)
    self.timeout = ms
    if self.sock then self.sock:settimeout(ms) end
    return true
end

-- close() -> 1：关闭底层连接
function _M.close(self)
    if not self.sock then return true end
    local ok = self.sock:close()
    self.connected = false
    return ok
end

-- set_keepalive(timeout_ms?, pool_size?)：把空闲连接归还 cosocket 连接池
function _M.set_keepalive(self, timeout, pool_size)
    if not self.sock then return nil, "closed" end
    local ok, err = self.sock:setkeepalive(timeout, pool_size)
    if ok then self.connected = false end
    return ok, err
end

-- reconnect(host?, port?, opts?)：断开并重连（默认复用上次对端）
function _M.reconnect(self, host, port, opts)
    self:close()
    return self:connect(host or self.host, port or self.port, opts)
end

-- command(arr)：arr 为 RESP 命令各 token（如 {"SET","k","v"}）；编码发送并读回复。
function _M.command(self, arr)
    if type(arr) ~= "table" or #arr == 0 then
        return nil, "bad command"
    end
    if not self.connected then
        local ok, err = self:connect(self.host, self.port)
        if not ok then return nil, err end
    end
    local parts = { "*" .. #arr .. "\r\n" }
    for i = 1, #arr do
        local v = tostring(arr[i])
        parts[#parts + 1] = "$" .. #v .. "\r\n" .. v .. "\r\n"
    end
    local bytes, err = self.sock:send(concat(parts))
    if not bytes then
        self.connected = false
        self.err = err
        return nil, err
    end
    local r, e = read_reply(self.sock)
    if r == nil and e then self.err = e end
    return r, e
end

-- pipeline() -> 流水线对象：pipe:cmd(...) 累积（动态派发，同单命令）、pipe:commit() 批量发送并读回全部回复。
function _M.pipeline(self)
    local owner = self
    local p = { buf = {} }
    -- 动态命令：pipe:get("k") / pipe:set("k","v") 累积为一条命令，等 commit 一起发出。
    setmetatable(p, { __index = function(tbl, key)
        local v = rawget(tbl, key)
        if v ~= nil then return v end
        if key == "buf" then return nil end
        return function(_, ...)
            local arr = { key }
            local n = select('#', ...)
            local rest = { ... }
            for i = 1, n do arr[#arr + 1] = rest[i] end
            tbl.buf[#tbl.buf + 1] = arr
            return true
        end
    end })
    function p.commit(tbl)
        if not owner.connected then
            local ok, err = owner:connect(owner.host, owner.port)
            if not ok then return nil, err end
        end
        for i = 1, #tbl.buf do
            local arr = tbl.buf[i]
            local parts = { "*" .. #arr .. "\r\n" }
            for j = 1, #arr do
                local v = tostring(arr[j])
                parts[#parts + 1] = "$" .. #v .. "\r\n" .. v .. "\r\n"
            end
            local bytes, err = owner.sock:send(concat(parts))
            if not bytes then return nil, err end
        end
        local replies = {}
        for i = 1, #tbl.buf do
            local r, e = read_reply(owner.sock)
            if r == nil and e then return nil, e end
            replies[i] = r
        end
        tbl.buf = {}
        return replies
    end
    return p
end

-- 未知键 → 动态命令派发：redis:get("k") 等价于 redis:command({"get","k"})
-- 但对象自身的状态字段（尚未赋值时从实例表读为 nil）必须原样返回 nil，绝不能被派发成命令。
local STATE = { sock = true, connected = true, timeout = true, host = true, port = true, err = true }
mt.__index = function(self, key)
    local known = rawget(_M, key)
    if known then return known end
    if STATE[key] then return nil end
    return function(s, ...)
        local arr = { key }
        local n = select('#', ...)
        local rest = { ... }
        for i = 1, n do arr[#arr + 1] = rest[i] end
        return s:command(arr)
    end
end

return _M
"##;
/// ngx.semaphore —— 信号量。OpenResty 原生实现基于事件；这里用
/// `ngx.sleep` 让出轮询（步长从 1ms 指数退避到 20ms），语义一致且不占死 VM。
/// 计数器是每个 VM（≈每个 worker）独立的，与 OpenResty 的 per-worker 语义一致。
const NGX_SEMAPHORE: &str = r##"
local _M = {}
local mt = { __index = _M }

local min, max = math.min, math.max

-- new([n])：初始计数，默认 0
function _M.new(n)
    n = tonumber(n) or 0
    if n < 0 then
        return nil, "invalid initial count"
    end
    return setmetatable({ _count = n }, mt)
end

-- count()：当前计数（不等待）
function _M:count()
    return self._count
end

-- post([n])：增加计数并唤醒等待者（轮询模型下等待者下一拍看到）
function _M:post(n)
    n = tonumber(n) or 1
    if n < 0 then
        return nil, "invalid post value"
    end
    self._count = self._count + n
    return true
end

-- wait([timeout])：计数 > 0 则消耗并返回 true；超时返回 nil, "timeout"。
-- timeout = 0 表示非阻塞试取。
function _M:wait(timeout)
    if timeout ~= nil then
        timeout = tonumber(timeout)
        if not timeout or timeout < 0 then
            return nil, "invalid timeout value"
        end
    end
    if self._count > 0 then
        self._count = self._count - 1
        return true
    end
    if timeout == 0 then
        return nil, "timeout"
    end

    local start = ngx.now()
    local step = 0.001
    while true do
        ngx.sleep(step)
        if self._count > 0 then
            self._count = self._count - 1
            return true
        end
        if timeout then
            local left = timeout - (ngx.now() - start)
            if left <= 0 then
                return nil, "timeout"
            end
            step = min(step * 2, left, 0.02)
        else
            step = min(step * 2, 0.02)
        end
    end
end

return _M
"##;

/// resty.cookie —— 请求 Cookie 解析与 Set-Cookie 生成（对照公开 API 语义手写）。
const RESTY_COOKIE: &str = r##"
local _M = {}
local mt = { __index = _M }

local byte, sub, find, gsub = string.byte, string.sub, string.find, string.gsub
local concat = table.concat
local tonumber, tostring, type = tonumber, tostring, type

local function trim(s)
    return (gsub(s, "^%s*(.-)%s*$", "%1"))
end

local function parse(str)
    local cookies = {}
    if not str or str == "" then
        return cookies
    end
    for pair in (str .. ";"):gmatch("([^;]*);") do
        local eq = find(pair, "=", 1, true)
        if eq then
            local k = trim(sub(pair, 1, eq - 1))
            local v = trim(sub(pair, eq + 1))
            if k ~= "" then
                if #v >= 2 and byte(v, 1) == 34 and byte(v, #v) == 34 then
                    v = sub(v, 2, #v - 1)
                end
                cookies[k] = v
            end
        end
    end
    return cookies
end

-- new([cookie_header])：不传则读当前请求的 Cookie 头
function _M.new(self, cookie_str)
    if cookie_str == nil then
        cookie_str = ngx.var.http_cookie
    end
    return setmetatable({ _cookies = parse(cookie_str), _raw = cookie_str }, mt)
end

function _M.get(self, key)
    local v = self._cookies[key]
    if v == nil then
        return nil, "cookie not found"
    end
    return v
end

function _M.get_all(self)
    if not self._raw or self._raw == "" then
        return nil, "no cookies found"
    end
    local t = {}
    for k, v in pairs(self._cookies) do
        t[k] = v
    end
    return t
end

-- 不依赖 os.date/os.time（可能受沙箱影响），按 UTC 手算 epoch 秒。
local function mktime(t)
    local year, month, day = tonumber(t.year), tonumber(t.month), tonumber(t.day)
    if not (year and month and day) then
        return nil
    end
    local hour, min, sec = tonumber(t.hour) or 0, tonumber(t.min) or 0, tonumber(t.sec) or 0
    local y = month <= 2 and year - 1 or year
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = (month + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + day - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + min * 60 + sec
end

local function expires_str(expires)
    if type(expires) == "number" then
        return ngx.cookie_time(expires)
    end
    if type(expires) == "table" then
        local ts = mktime(expires)
        if ts then
            return ngx.cookie_time(ts)
        end
    end
    return tostring(expires)
end

local function add_set_cookie(s)
    local cur = ngx.header["Set-Cookie"]
    if cur == nil then
        ngx.header["Set-Cookie"] = s
    elseif type(cur) == "table" then
        -- __index 返回的是副本，必须整体重新赋值才能写回响应头集合
        local list = {}
        for i = 1, #cur do list[i] = cur[i] end
        list[#list + 1] = s
        ngx.header["Set-Cookie"] = list
    else
        ngx.header["Set-Cookie"] = { cur, s }
    end
end

-- set({ key=..., value=..., path=..., domain=..., expires=..., max_age=...,
--       secure=..., httponly=..., samesite=..., version=..., comment=... })
-- value = false 表示删除该 cookie（value 置空 + expires 置过去）。
function _M.set(self, opts)
    if type(opts) ~= "table" then
        return nil, "opts must be a table"
    end
    local key = opts.key
    if not key or key == "" then
        return nil, "missing cookie key"
    end
    local value = opts.value
    local deleting = value == false
    if value == nil or deleting then
        value = ""
    else
        value = tostring(value)
    end

    local parts = { key .. "=" .. value }
    local path = opts.path
    if path == nil and not deleting then
        path = "/"
    end
    if path then
        parts[#parts + 1] = "Path=" .. tostring(path)
    end
    if opts.domain then
        parts[#parts + 1] = "Domain=" .. tostring(opts.domain)
    end
    if deleting then
        parts[#parts + 1] = "Expires=" .. ngx.cookie_time(1)
        parts[#parts + 1] = "Max-Age=0"
    else
        if opts.expires ~= nil then
            parts[#parts + 1] = "Expires=" .. expires_str(opts.expires)
        end
        if opts.max_age ~= nil then
            parts[#parts + 1] = "Max-Age=" .. tostring(opts.max_age)
        end
    end
    if opts.secure then
        parts[#parts + 1] = "Secure"
    end
    if opts.httponly then
        parts[#parts + 1] = "HttpOnly"
    end
    if opts.samesite then
        parts[#parts + 1] = "SameSite=" .. tostring(opts.samesite)
    end
    if opts.version then
        parts[#parts + 1] = "Version=" .. tostring(opts.version)
    end
    if opts.comment then
        parts[#parts + 1] = "Comment=" .. tostring(opts.comment)
    end

    add_set_cookie(concat(parts, "; "))
    if deleting then
        self._cookies[key] = nil
    else
        self._cookies[key] = value
    end
    return true
end

return _M
"##;

/// resty.limit.req —— 漏桶限速（rate r/s + burst 余量），语义对齐
/// lua-resty-limit-traffic 的 resty.limit.req：incoming() 返回需要延迟的秒数，
/// 超出 burst 返回 nil, "rejected"。
const RESTY_LIMIT_REQ: &str = r##"
local _M = {}
local mt = { __index = _M }

local tonumber, tostring = tonumber, tostring
local max, ceil = math.max, math.ceil

function _M.new(self, dict_name, rate, burst)
    local dict = ngx.shared[dict_name]
    if not dict then
        return nil, "shared dict not found: " .. tostring(dict_name)
    end
    rate = tonumber(rate)
    burst = tonumber(burst) or 0
    if not rate or rate <= 0 then
        return nil, "rate must be positive"
    end
    if burst < 0 then
        return nil, "burst must be non-negative"
    end
    return setmetatable({ dict = dict, rate = rate, burst = burst, key = nil }, mt)
end

local function decode(v)
    if not v then return 0, 0 end
    local s = tostring(v)
    local a, b = s:match("^([%d%.]+),([%d%.]+)$")
    if not a then return 0, 0 end
    return tonumber(a) or 0, tonumber(b) or 0
end

function _M.incoming(self, key, commit)
    if key == nil then
        return 0
    end
    if commit == nil then
        commit = false
    end
    self.key = key
    local now = ngx.now() * 1000
    local last, excess = decode(self.dict:get(key))
    local elapsed = now - last
    if elapsed < 0 then elapsed = 0 end
    excess = max(0, excess - elapsed * self.rate / 1000) + 1
    if excess > self.burst + 1 then
        return nil, "rejected"
    end
    if commit then
        local ttl = max(60, ceil((self.burst + 1) / self.rate * 2))
        self.dict:set(key, tostring(now) .. "," .. tostring(excess), ttl)
    end
    if excess <= 1 then
        return 0
    end
    return (excess - 1) / self.rate
end

function _M.uncommit(self, key)
    local k = key or self.key
    if not k then return nil, "no key" end
    local last, excess = decode(self.dict:get(k))
    if excess > 0 then
        self.dict:set(k, tostring(last) .. "," .. tostring(excess - 1), 60)
    end
    return true
end

return _M
"##;

/// resty.limit.count —— 固定 1 秒窗口计数限流，对齐 resty.limit.count。
const RESTY_LIMIT_COUNT: &str = r##"
local _M = {}
local mt = { __index = _M }

local tonumber, tostring = tonumber, tostring
local max = math.max

function _M.new(self, dict_name, count)
    local dict = ngx.shared[dict_name]
    if not dict then
        return nil, "shared dict not found: " .. tostring(dict_name)
    end
    count = tonumber(count)
    if not count or count <= 0 then
        return nil, "count must be positive"
    end
    return setmetatable({ dict = dict, count = count, key = nil }, mt)
end

function _M.incoming(self, key, commit)
    local dict, count = self.dict, self.count
    if key == nil then
        return count
    end
    if commit == nil then commit = false end
    self.key = key

    if not commit then
        local v = tonumber(dict:get(key)) or 0
        if v >= count then
            return nil, "rejected"
        end
        return count - v
    end

    local n
    local ok = dict:add(key, 1, 1)      -- 1 秒窗口
    if ok then
        n = 1
    else
        local v, err = dict:incr(key, 1)
        if not v then
            return nil, err
        end
        n = v
    end
    if n > count then
        return nil, "rejected"
    end
    return count - n
end

function _M.remaining(self, key)
    local v = tonumber(self.dict:get(key or self.key)) or 0
    return max(0, self.count - v)
end

function _M.uncommit(self, key)
    local k = key or self.key
    if not k then return nil, "no key" end
    self.dict:incr(k, -1)
    return true
end

return _M
"##;

/// resty.limit.conn —— 并发连接数限制（incoming/leaving），对齐 resty.limit.conn。
const RESTY_LIMIT_CONN: &str = r##"
local _M = {}
local mt = { __index = _M }

local tonumber, tostring = tonumber, tostring
local max = math.max

function _M.new(self, dict_name, max_conn, burst)
    local dict = ngx.shared[dict_name]
    if not dict then
        return nil, "shared dict not found: " .. tostring(dict_name)
    end
    max_conn = tonumber(max_conn)
    burst = tonumber(burst) or 0
    if not max_conn or max_conn <= 0 then
        return nil, "max connections must be positive"
    end
    if burst < 0 then
        return nil, "burst must be non-negative"
    end
    return setmetatable({ dict = dict, max = max_conn, burst = burst, key = nil }, mt)
end

function _M.incoming(self, key, commit)
    if key == nil then
        return 0
    end
    if commit == nil then commit = false end
    self.key = key
    local dict = self.dict
    if not commit then
        local cur = tonumber(dict:get(key)) or 0
        if cur >= self.max + self.burst then
            return nil, "rejected"
        end
        return cur
    end
    local n, err = dict:incr(key, 1, 0)
    if not n then
        return nil, err
    end
    dict:expire(key, 60)   -- 防止异常退出留下永久计数
    if n > self.max + self.burst then
        dict:incr(key, -1)
        return nil, "rejected"
    end
    return n
end

function _M.leaving(self, key, commit)
    local k = key or self.key
    if not k then return nil, "no key" end
    if commit == false then
        return 0
    end
    local n = self.dict:incr(k, -1)
    if n == nil then
        return 0
    end
    if n < 0 then
        self.dict:set(k, 0, 60)
        return 0
    end
    return n
end

function _M.conn(self, key)
    local k = key or self.key
    return max(0, tonumber(self.dict:get(k)) or 0)
end

return _M
"##;

/// 这里对 `package`/`preload` 表做存在性兜底，避免个别精简运行时缺表时失败。
pub fn install_modules(lua: &Lua) -> LuaResult<()> {
    let string_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_STRING).set_name("resty.string").eval::<LuaValue>()
    })?;
    let lock_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_LOCK).set_name("resty.lock").eval::<LuaValue>()
    })?;
    let http_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_HTTP).set_name("resty.http").eval::<LuaValue>()
    })?;
    let redis_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_REDIS).set_name("resty.redis").eval::<LuaValue>()
    })?;
    let semaphore_loader = lua.create_function(|lua, _: ()| {
        lua.load(NGX_SEMAPHORE).set_name("ngx.semaphore").eval::<LuaValue>()
    })?;
    let cookie_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_COOKIE).set_name("resty.cookie").eval::<LuaValue>()
    })?;
    let limit_req_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_LIMIT_REQ).set_name("resty.limit.req").eval::<LuaValue>()
    })?;
    let limit_count_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_LIMIT_COUNT).set_name("resty.limit.count").eval::<LuaValue>()
    })?;
    let limit_conn_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_LIMIT_CONN).set_name("resty.limit.conn").eval::<LuaValue>()
    })?;

    let globals = lua.globals();
    let package: LuaTable = match globals.get("package") {
        Ok(p) => p,
        Err(_) => {
            let t = lua.create_table()?;
            globals.set("package", t.clone())?;
            t
        }
    };
    let preload: LuaTable = match package.get("preload") {
        Ok(p) => p,
        Err(_) => {
            let t = lua.create_table()?;
            package.set("preload", t.clone())?;
            t
        }
    };
    preload.set("resty.string", string_loader)?;
    preload.set("resty.lock", lock_loader)?;
    preload.set("resty.http", http_loader)?;
    preload.set("resty.redis", redis_loader)?;
    preload.set("ngx.semaphore", semaphore_loader)?;
    preload.set("resty.cookie", cookie_loader)?;
    preload.set("resty.limit.req", limit_req_loader)?;
    preload.set("resty.limit.count", limit_count_loader)?;
    preload.set("resty.limit.conn", limit_conn_loader)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resty_modules_register_and_require() {
        let lua = mlua::Lua::new();
        install_modules(&lua).unwrap();
        // require "resty.string" → to_hex 可用且正确
        let hex: String = lua
            .load(r#"local s = require "resty.string"; return s.to_hex("AB")"#)
            .eval()
            .unwrap();
        assert_eq!(hex, "4142");
        // require "resty.http" → 模块面对象具备公开方法
        for name in ["new", "connect", "request", "set_timeout", "set_keepalive", "close"] {
            let ok: bool = lua
                .load(format!(
                    r#"local h = require "resty.http"; return type(h.{name}) == 'function'"#
                ))
                .eval()
                .unwrap();
            assert!(ok, "resty.http missing method {name}");
        }
        // require "resty.lock" → new/lock/unlock 存在
        for name in ["new", "lock", "unlock"] {
            let ok: bool = lua
                .load(format!(
                    r#"local l = require "resty.lock"; return type(l.{name}) == 'function'"#
                ))
                .eval()
                .unwrap();
            assert!(ok, "resty.lock missing method {name}");
        }
    }

    // resty.http 客户端对象：new() 返回带方法的实例，未连接前 get_headers/get_status_code 为 nil。
    #[test]
    fn resty_http_new_instance_shape() {
        let lua = mlua::Lua::new();
        // 桩：模块加载只定义函数，不触碰 ngx；request/connect 才被调用。
        install_modules(&lua).unwrap();
        let res: bool = lua
            .load(
                r#"
                local h = require "resty.http"
                local c = h.new()
                return type(c) == 'table' and c:get_status_code() == nil and c:get_headers() == nil
                "#,
            )
            .eval()
            .unwrap();
        assert!(res);
    }

    #[test]
    fn semaphore_post_wait_and_timeout() {
        let lua = mlua::Lua::new();
        install_modules(&lua).unwrap();
        let ok: bool = lua
            .load(
                r#"
                local t = 0
                ngx = {
                    now = function() return t end,
                    sleep = function(s) t = t + s end,
                }
                local sem = require "ngx.semaphore".new(1)
                assert(sem:count() == 1)
                assert(sem:wait(0) == true)
                assert(sem:wait(0) == nil)
                sem:post(2)
                assert(sem:count() == 2)
                assert(sem:wait(0) == true)
                assert(sem:wait(0) == true)
                local ok, err = sem:wait(0.005)
                assert(ok == nil and err == "timeout", "无信号时应超时")
                assert(t >= 0.005)
                sem:post()
                return sem:wait(1) == true
                "#,
            )
            .eval()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn cookie_parse_set_and_delete() {
        let lua = mlua::Lua::new();
        install_modules(&lua).unwrap();
        let ok: bool = lua
            .load(
                r##"
                ngx = {
                    var = { http_cookie = 'a=1; b="x y"; empty=' },
                    header = {},
                    cookie_time = function(ts) return "TS(" .. ts .. ")" end,
                }
                local m = require "resty.cookie"
                local ck = m:new()
                assert(ck:get("a") == "1")
                assert(ck:get("b") == "x y")
                assert(ck:get("empty") == "")
                local _, e = ck:get("missing")
                assert(e == "cookie not found")
                local all = ck:get_all()
                assert(all.a == "1" and all.b == "x y")

                assert(ck:set({ key = "s", value = "v", httponly = true, secure = true,
                                max_age = 60, expires = 1700000000 }))
                local sc = ngx.header["Set-Cookie"]
                assert(type(sc) == "string" and sc:find("HttpOnly", 1, true)
                       and sc:find("Secure", 1, true) and sc:find("Path=/", 1, true)
                       and sc:find("Max%-Age=60") and sc:find("Expires=TS%(1700000000%)"))
                assert(ck:get("s") == "v")

                assert(ck:set({ key = "s", value = false }))
                local list = ngx.header["Set-Cookie"]
                assert(type(list) == "table" and #list == 2, "删除应追加第二条 Set-Cookie")
                assert(list[2]:find("Max%-Age=0") and list[2]:find("TS%(1%)"))
                assert(ck:get("s") == nil)
                return true
                "##,
            )
            .eval()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn limit_req_count_conn_semantics() {
        let lua = mlua::Lua::new();
        install_modules(&lua).unwrap();
        let ok: bool = lua
            .load(
                r#"
                local now = 0
                local store = {}
                local dict = {}
                function dict:get(k) return store[k] end
                function dict:set(k, v, ex) store[k] = v; return true end
                function dict:add(k, v, ex)
                    if store[k] ~= nil then return false, "exists" end
                    store[k] = v
                    return true
                end
                function dict:incr(k, d)
                    local v = (tonumber(store[k]) or 0) + (d or 1)
                    store[k] = v
                    return v
                end
                function dict:expire(k, ex) return store[k] ~= nil end
                ngx = { now = function() return now end, shared = { test = dict } }

                -- 漏桶：rate=2/s, burst=1
                local req = require "resty.limit.req"
                local lim = assert(req:new("test", 2, 1))
                assert(lim:incoming("r", true) == 0)
                local d = assert(lim:incoming("r", true))
                assert(math.abs(d - 0.5) < 1e-9, "第二个请求应延迟 0.5s，实际 " .. d)
                local x, err = lim:incoming("r", true)
                assert(x == nil and err == "rejected")
                -- commit=false 不消耗
                local y = assert(lim:incoming("r2", false))
                assert(y == 0 and store["r2"] == nil)

                -- 计数：窗口内 2 次
                local count = require "resty.limit.count"
                local cl = assert(count:new("test", 2))
                assert(cl:incoming("c", true) == 1)
                assert(cl:incoming("c", true) == 0)
                local cr, ce = cl:incoming("c", true)
                assert(cr == nil and ce == "rejected")
                assert(cl:remaining("c") == 0)

                -- 并发：max=1, burst=0
                local conn = require "resty.limit.conn"
                local co = assert(conn:new("test", 1, 0))
                assert(co:incoming("x", true) == 1)
                local nr, ne = co:incoming("x", true)
                assert(nr == nil and ne == "rejected")
                assert(co:leaving("x") == 0)
                assert(co:conn("x") == 0)
                return true
                "#,
            )
            .eval()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn resty_redis_surface_and_state_guard() {
        let lua = mlua::Lua::new();
        install_modules(&lua).unwrap();
        // require 与公开方法面
        for name in ["new", "connect", "command", "set_timeout", "set_keepalive", "reconnect", "close", "pipeline"] {
            let ok: bool = lua
                .load(format!(r#"local r = require "resty.redis"; return type(r.{name}) == 'function'"#))
                .eval()
                .unwrap();
            assert!(ok, "resty.redis missing method {name}");
        }
        // 关键回归：动态 __index 不能把对象状态字段（sock/connected/...）合成成命令函数
        let ok: bool = lua
            .load(
                r#"
                local redis = require "resty.redis"
                local r = redis:new()
                local is_fn = type(r.sock) == "function" or type(r.connected) == "function"
                -- 未知命令名仍应派发为可调用函数
                local cmd_callable = type(r.get) == "function"
                return (not is_fn) and r.sock == nil and cmd_callable
                "#,
            )
            .eval()
            .unwrap();
        assert!(ok, "resty.redis __index leaked a command function for a state field");
    }
}
