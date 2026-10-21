# ONRouter 1.0 使用教程

本教程带你从一条 `return` 开始，逐步搭起一个具备反向代理、故障韧性、缓存、灰度、
WASM 鉴权、Lua 脚本和 CPU 绑定的网关。每一章都有可执行的命令和验证点，最后落到仓库里
可直接运行的 `conf/tutorial_full.conf`。

- 生产运维（进程、信号、容量、发布、回滚）看 [OPERATIONS.md](OPERATIONS.md)。
- 教程中的路径都以仓库根目录为当前目录；Windows 下二进制加 `.exe`，PowerShell 里用
  `curl.exe` 避免 `curl` 别名，其余命令在 Git Bash / PowerShell 下等价。

## 0. 路线图

| 章 | 你会得到什么 | 验证入口 |
|---|---|---|
| 1 | release 构建与两个路径规则 | `onrouter -V` |
| 2 | 最小 HTTP 服务、静态文件、`-t` | `:18600/hello` |
| 3 | 反向代理与两台后端轮询 | `:18600/api/hello` |
| 4 | 自动摘除、懒重连、熔断 | `/pair`、`/breaker`、`/metrics` |
| 5 | 内存缓存与灰度隔离 | `/cached` 的 `X-Cache` |
| 6 | 按 Cookie/UA/OS/比例灰度 | `/release` |
| 7 | WASM access 鉴权与响应过滤 | `/guarded`、`/filtered` |
| 8 | Lua 内容与共享字典 | `/lua`、`/lua/count` |
| 9 | 工作线程与 CPU 亲和性 | `-t` 的逐线程计划 |
| 10 | 指标、热重载边界、优雅停机 | `/metrics`、改配置 |
| 11 | 单元测试、E2E、20 分钟稳定性压测、CI | `tools/soak_test.py` |
| 12 | 把完整配置讲清楚 + 上线检查表 | `conf/tutorial_full.conf` |

---

## 1. 准备环境

### 1.1 构建 release

需要 Rust stable（`rustup` 安装即可）。在仓库根目录：

```bash
cargo build --release --workspace
```

只构建网关与证书工具：

```bash
cargo build --release -p onrouter-server --bin onrouter --bin orr-gencert
```

产物：

```text
target/release/onrouter        # Windows: target\release\onrouter.exe
target/release/orr-gencert     # Windows: target\release\orr-gencert.exe
```

确认版本：

```bash
target/release/onrouter -V
# ONRouter/1.0.0 (Rust, OpenResty-compatible)
```

教程里的辅助后端和压测脚本需要 Python 3.8+，只用于本机练习，不参与网关进程。

### 1.2 两个必须知道的路径规则

1. **配置里的相对路径基于配置文件所在目录**，不是当前工作目录。
   教程配置在 `conf/`，所以 `logs/tutorial_err.log` 实际写到 `conf/logs/`，
   `root "../public"` 指向仓库根目录的 `public/`。
2. `-p <dir>` 可以把前缀目录换成别的路径（nginx 兼容）。不写 `-p` 时，配置里的相对路径
   以配置文件父目录为基准。

先确保日志目录存在：

```bash
mkdir -p conf/logs
# PowerShell: New-Item -ItemType Directory -Force conf\logs
```

### 1.3 配置检查

`-t` 会解析配置、加载并编译 WASM 插件、检查证书与引用，**不监听端口**。任何上线动作之前
都先跑它：

```bash
target/release/onrouter -t -c conf/tutorial_hello.conf
echo $?    # 0
```

`-t` 的输出末尾会列出 worker 线程数、亲和性计划和所有被接受的配置告警。看到
“unknown directive” 或“已忽略”不要跳过，它们通常意味着你写错了名字或放错了层级。

---

## 2. 第一个服务：静态文件、精确路由、健康检查

`conf/tutorial_hello.conf` 已经放在仓库里：

```nginx
error_log "logs/tutorial_hello_err.log" info;
pid "logs/tutorial_hello.pid";

server {
    listen 127.0.0.1:18600;
    server_name tutorial.local;

    location = /health {
        return 200 "ok";
    }

    location = /hello {
        return 200 "hello from onrouter";
    }

    location / {
        root "../public";
    }
}
```

- `listen` 指定地址与端口；本教程只绑回环地址，避免暴露到局域网。
- `location = /health` 是精确匹配，只命中这一个 URI。
- `location /` 是前缀匹配，作为兜底；`root` 把 URI 映射到 `public/` 下的文件。
- 同一端口只能有一个进程监听。如果 18600 被占用，先停掉占用者或改端口。

启动（前台运行，另开一个终端做请求）：

```bash
target/release/onrouter -c conf/tutorial_hello.conf
```

验证：

```bash
curl -i http://127.0.0.1:18600/health
curl -i http://127.0.0.1:18600/hello
curl -i http://127.0.0.1:18600/
```

预期：

- `/health` 返回 `200` 和 `ok`；
- `/hello` 返回 `200` 和 `hello from onrouter`；
- `/` 返回 `public/index.html`；
- 响应头里有 `Server: ONRouter/1.0.0`（可通过 `server_tokens` 调整）。

停止：前台按 `Ctrl+C`；Linux/macOS 也可以 `kill -TERM <pid>`。进程会停止接受新连接，
等待存量请求完成，最长 `shutdown_grace`（默认 30 秒）。

---

## 3. 反向代理与 upstream

先启动两台“后端”。仓库里的 `tools/tutorial_backend.py` 只会回显自己的名字和收到的头，
用来观察网关把请求交给了谁：

```bash
# 终端 A
python tools/tutorial_backend.py a 18601

# 终端 B
python tools/tutorial_backend.py b 18602
```

现在用完整教程配置启动网关。它包含本章及后面所有章节的模块，先整体 `-t` 一次：

```bash
target/release/onrouter -t -c conf/tutorial_full.conf
target/release/onrouter -c conf/tutorial_full.conf
```

其中最核心的一段：

```nginx
upstream app {
    server 127.0.0.1:18601 max_fails=1 fail_timeout=60s;
    server 127.0.0.1:18602 max_fails=1 fail_timeout=60s;
    lazy_rejoin 2s;
    keepalive 16;
}

location /api/ {
    proxy_pass http://app/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_next_upstream error timeout;
}
```

验证：

```bash
curl -s http://127.0.0.1:18600/api/hello
# backend=a 或 backend=b，path=/hello
```

多请求几次，应该看到 `a`、`b` 交替出现（默认加权轮询）。`proxy_pass http://app/` 末尾的
`/` 会把 `/api/` 前缀替换掉，后端收到 `/hello`；如果写成 `proxy_pass http://app;`（无末尾
斜杠），后端会收到完整的 `/api/hello`。这是 nginx 的既有语义，迁移时最容易踩。

`upstream` 里可以按需加：

```nginx
least_conn;      # 选当前在途连接最少的节点
# ip_hash;       # 按客户端地址粘滞（与 least_time 互斥）
# server ... weight=3;   # 加权轮询
keepalive 32;    # 到后端的空闲长连接池
```

`keepalive` 只影响网关到后端的连接复用，不改变负载均衡算法。修改 `upstream` 段（包括
`lazy_rejoin`、`circuit_breaker`、权重）需要**重启进程**，热重载不会替换已经运行的池，
具体边界见第 10 章。

---

## 4. 后端挂了怎么办：摘除、懒重连、熔断

这一章用同一份 `conf/tutorial_full.conf`，其中准备了两套独立的池：

```nginx
upstream app {
    server 127.0.0.1:18601 max_fails=1 fail_timeout=60s;
    server 127.0.0.1:18602 max_fails=1 fail_timeout=60s;
    lazy_rejoin 2s;
}

upstream breaker {
    server 127.0.0.1:18602 max_fails=100 fail_timeout=60s;
    circuit_breaker errors=2 window=5s open=2s;
}

location = /pair {
    proxy_pass http://app;
}

location = /breaker {
    proxy_next_upstream off;
    proxy_pass http://breaker;
}
```

### 4.1 被动摘除与懒重连

1. 两个后端都运行时：

   ```bash
   curl -s http://127.0.0.1:18600/pair
   # backend=a 或 backend=b
   ```

2. 在终端 B 按 `Ctrl+C` 杀掉后端 `b`，然后连续请求：

   ```bash
   curl -s http://127.0.0.1:18600/pair
   curl -s http://127.0.0.1:18600/pair
   # backend=a
   ```

   第一次可能先打到 `b`，连接失败后由 `proxy_next_upstream` 换到 `a`，客户端仍然看到 200；
   失败计数器达到 `max_fails=1` 后，`b` 被摘除 `fail_timeout=60s`。

3. 等 2 秒以上再请求。`lazy_rejoin 2s` 让被摘除的节点在到期后，由**一次真实用户请求**顺带
   探活；`b` 还没恢复时，这次探测失败，继续留在摘除状态。

4. 重新启动后端 `b`：

   ```bash
   python tools/tutorial_backend.py b 18602
   ```

   等 2 秒以上再请求，下一次真实请求成为成功探针，`b` 自动回到轮询。这个过程没有独立
   探测线程、没有额外健康检查端口，探针走的就是正常转发路径。

### 4.2 熔断

`breaker` 池只有一台后端，并用 `proxy_next_upstream off` 让失败真的返回客户端：

1. 杀掉后端 `b`。
2. 连续请求两次：

   ```bash
   curl -i http://127.0.0.1:18600/breaker
   curl -i http://127.0.0.1:18600/breaker
   # 502 Bad Gateway
   ```

   `errors=2 window=5s` 表示 5 秒窗口内连续 2 次失败后打开（期间成功一次会清零），打开期间
   不再反复尝试连接，避免每个请求都交一次连接超时的学费。

3. 查看指标：

   ```bash
   curl -s http://127.0.0.1:18600/metrics | grep onrouter_upstream
   ```

   重点看：

   ```text
   onrouter_upstream_server_available{upstream="app",server="127.0.0.1:18602"} 0
   onrouter_upstream_lazy_probes_total{upstream="app",server="127.0.0.1:18602"} ...
   onrouter_upstream_circuit_state{upstream="breaker",server="127.0.0.1:18602"} 2
   onrouter_upstream_circuit_trips_total{upstream="breaker",server="127.0.0.1:18602"} 1
   ```

   `server_available=0` 表示调度器当前不会选它（被动摘除、人工 `down` 或熔断打开）；
   `server_healthy` 是**主动健康检查**的判定，本教程没有配置 `health_check`，所以它一直是 1，
   不要拿它判断被动摘除。

4. 重启后端 `b`，等 `open=2s` 到期。下一次请求进入半开，探针成功就闭合熔断器；指标里的
   `circuit_state` 回到 0。若探针失败，会重新打开一个周期。

**两套机制的分工**：`max_fails/fail_timeout` 回答“这台暂时别选了”；`circuit_breaker` 回答
“这台连续失败，先停一段时间，别再让每个请求都去撞一次”。它们可以同时开，互不替代。

### 4.3 为什么不用后台健康检查线程

懒重连把“恢复探测”挂在真实流量上：恢复延迟最多一个探测间隔，但不产生空闲探测流量，
探针也天然走过与业务相同的 DNS、TLS、连接池和超时路径。代价是低流量时恢复会慢一些，
这时把 `lazy_rejoin` 调到 1s~2s，不建议低于 1s。

---

## 5. 缓存：MISS 到 HIT

完整配置的缓存段：

```nginx
proxy_cache_path logs/tutorial_cache keys_zone=tutorial:16m;

location = /cached {
    proxy_cache tutorial;
    proxy_cache_valid 200 10s;
    add_header X-Cache $upstream_cache_status;
    proxy_pass http://$release;
    proxy_set_header X-Split $proxy_split;
}
```

`proxy_cache_path` 在这个版本是**纯内存缓存**：`path` 不落盘，`keys_zone` 的容量决定
条目上限，按 LRU 淘汰。进程重启后缓存清空。

用固定落到 `beta` 的 Cookie 请求两次：

```bash
curl -i -H "Cookie: beta=1" http://127.0.0.1:18600/cached | grep -i x-cache
# X-Cache: MISS

curl -i -H "Cookie: beta=1" http://127.0.0.1:18600/cached | grep -i x-cache
# X-Cache: HIT
```

等 10 秒（`proxy_cache_valid`）后再请求，会看到 `EXPIRED`，随后回源并重新缓存。缓存键包含
实际转发目标（`$proxy_host`），所以 `stable` 和 `beta` 各自成条目；beta 的页面不可能被
当成 stable 的命中结果下发。

要观察缓存效果：

```bash
curl -s http://127.0.0.1:18600/metrics | grep onrouter_cache_requests_total
# onrouter_cache_requests_total{status="MISS"} ...
# onrouter_cache_requests_total{status="HIT"} ...
```

注意：

- 带查询串的 URL 是不同的键；参数顺序变化也会生成新键。
- `POST` 等非缓存方法默认不进缓存。
- 上游返回 `Set-Cookie` 的响应不会进入缓存。
- 缓存只省回源；WASM 过滤器仍会在缓存命中时执行（过滤的是发给客户端的那一份）。

Still ONLine（最后已知好副本）是另一层机制，默认只收匿名 GET + 2xx，规则见
[OPERATIONS.md](OPERATIONS.md) 第 9.3 节。

---

## 6. 灰度：按 Cookie、Header、UA、系统、比例分流

完整配置的灰度段：

```nginx
canary $release "${cookie_uid}${remote_addr}" {
    cookie beta=1 beta;          # Cookie beta=1 -> beta
    header X-Channel=Vip beta;   # 请求头精确匹配
    ua ~* (Firefox|Edg) beta;    # UA 正则，~* 忽略大小写
    os ios beta;                 # iOS 客户端
    percent 20 beta;             # 其余用户按粘性键 20% 进 beta
    default stable;              # 必填
}

location = /release {
    proxy_pass http://$release;
    proxy_set_header X-Split $proxy_split;
    proxy_set_header X-Split-Served $proxy_split_served;
}
```

语义是“声明顺序，第一条命中生效”：

1. 先看 `cookie` / `header` / `arg` / `ua` / `os`；
2. 都没命中才看 `percent`；
3. 最后落到 `default`。

### 6.1 条件命中

```bash
# Cookie 精确匹配 -> beta
curl -s -H "Cookie: beta=1" http://127.0.0.1:18600/release
# backend=b  x-split=beta  x-split-served=beta

# 请求头 -> beta
curl -s -H "X-Channel: Vip" http://127.0.0.1:18600/release

# Firefox / Edge UA -> beta
curl -s -A "Mozilla/5.0 (Windows NT 10.0) Firefox/120.0" \
     http://127.0.0.1:18600/release

# iOS UA -> beta（os ios）
curl -s -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" \
     http://127.0.0.1:18600/release
```

响应体里的 `backend=` 说明实际由哪台后端接走；`x-split` 是规则选中的版本，
`x-split-served` 是最终服务的版本。正常情况下两者一致。

### 6.2 比例与粘性

不带任何条件时，按 `${cookie_uid}${remote_addr}` 的稳定哈希分桶。用 40 个不同的
`uid` 观察比例：

```bash
for i in $(seq 1 40); do
  curl -s -H "Cookie: uid=u$i" http://127.0.0.1:18600/release
done | grep '^backend=' | sort | uniq -c
```

同一个 `uid` 重复请求永远落同一档，这是“用户不会在版本间来回跳”的前提。只用
`${remote_addr}` 时，NAT 后的所有用户会共享一个桶；生产上应把业务用户标识放进键里。

### 6.3 灰度版本整体不可用时

默认 `proxy_split_failover on`：选中的版本没有任何可连接节点时，改投到候选顺序的下一路，
并在账本里记为 `bled`。试试在 `b` 下线时带 beta Cookie 请求：

```bash
curl -s -H "Cookie: beta=1" http://127.0.0.1:18600/release
# backend=a  x-split=beta  x-split-served=stable
```

响应仍然可用，但你能清楚看到“选的是 beta，实际是 stable”。如果实验不允许串台：

```nginx
proxy_split_failover off;              # beta 挂了就 502，不把实验用户混进 stable
# proxy_split_failover http://stable;  # 只允许退到 stable
```

后端返回 5xx 不会触发跨版本改投，避免一个 `POST` 被写进两个版本。

账本在 `/metrics`：

```bash
curl -s http://127.0.0.1:18600/metrics | grep onrouter_proxy_split
# onrouter_proxy_split_targets_total{split="release",target="beta"} ...
# onrouter_proxy_split_total{split="release",role="routed"} ...
# onrouter_proxy_split_total{split="release",role="bled"} ...
```

推进节奏建议 1% → 5% → 20% → 50% → 100%，每档至少观察一个业务高峰；同时对比错误率、
P99 和缓存命中率。回滚只需把 `percent` 调回 0 或删掉条件，等 `reload 2s` 生效即可；
不需要重启，因为 canary 规则属于路由表。

---

## 7. WASM 插件：在网关边缘做鉴权和响应改写

完整配置里声明了两个插件，并在 location 上按阶段引用：

```nginx
wasm_plugin authz wasm/authz.wat;
wasm_plugin hf wasm/header_filter.wat;

location = /guarded {
    access_by_wasm authz;
    proxy_pass http://app;
}

location = /filtered {
    header_filter_by_wasm hf;
    proxy_pass http://app;
}
```

`.wat` 是文本格式，启动时由 `wat` 编译为 wasm 模块；也可以直接放 `.wasm`。路径相对配置
文件目录，所以 `wasm/authz.wat` 指向 `conf/wasm/authz.wat`。

### 7.1 access 阶段：缺 token 直接 403

`conf/wasm/authz.wat` 的逻辑：

```wat
(module
  (import "env" "host_read_len" (func $len (param i32 i32 i32) (result i32)))
  (import "env" "host_set_header" (func $set (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "host_set_status" (func $status (param i32)))
  (import "env" "host_set_body" (func $body (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "X-Gateway-Token")
  (data (i32.const 32) "X-Wasm-Verified")
  (data (i32.const 64) "1")
  (data (i32.const 96) "wasm denied: token required")

  (func (export "on_access") (result i32)
    i32.const 4 i32.const 0 i32.const 15 call $len
    i32.const 0 i32.gt_s
    if (result i32)
      i32.const 4 i32.const 32 i32.const 15 i32.const 64 i32.const 1 call $set drop
      i32.const 0
    else
      i32.const 403 call $status
      i32.const 96 i32.const 27 call $body drop
      i32.const 1
    end))
```

`on_access` 返回 0 表示放行，返回非 0 表示插件已经生成响应、请求不再转发。第 4 类数据
是“请求头”：`host_read_len(4, name_ptr, name_len)` 读长度，放行时用
`host_set_header(4, ...)` 给上游加 `X-Wasm-Verified: 1`。

验证（两个后端都在运行）：

```bash
curl -i http://127.0.0.1:18600/guarded
# HTTP/1.1 403 Forbidden
# wasm denied: token required

curl -s -H "X-Gateway-Token: letmein" http://127.0.0.1:18600/guarded
# backend=a 或 b
# x-wasm-verified=1
```

把两个后端都停掉再试一次：没有 token 仍然返回 403，而不是 502。这证明鉴权发生在转发之前，
业务后端没有被访问。带 token 时才会尝试连接后端，此时才会得到 502。

### 7.2 header_filter 阶段：改写上游响应

`conf/wasm/header_filter.wat` 做三件事：给客户端加 `X-Wasm-Header-Filter: on`、删掉上游的
`X-Backend-Secret`、把状态码改成 202。

```bash
curl -i http://127.0.0.1:18600/filtered
# HTTP/1.1 202
# X-Wasm-Header-Filter: on
# （没有 X-Backend-Secret）
```

`body_filter_by_wasm` 用法相同，但会缓冲整个响应体；静态文件超过 8 MiB 时跳过过滤，
避免为了改写一个字节把大文件读进内存。缓存命中时过滤器仍会执行，缓存只省回源。

### 7.3 预算与失败边界

- `wasm_plugin authz wasm/authz.wat fuel=5000000 memory=4m;` 可以设置单次调用预算和内存上限；
  默认 fuel 10M、内存 16 MiB；`memory` 最小 64k。
- 插件 trap、越界或 fuel 耗尽时**失败关闭**：请求得到 5xx，工作线程不会挂死。
- `onrouter_wasm_errors_total` / `onrouter_wasm_fuel_exhausted_total` 增长说明插件有 bug
  或被恶意输入触发；`onrouter_wasm_denied_total` 是 access 阶段直接拒绝的业务计数。
- 插件名、阶段函数缺失或使用了未声明的插件，`-t` 就会失败，不会留到线上。

适用场景：边缘鉴权、租户路由、响应头清洗、统一错误页、灰度标记。需要复杂状态机或大量
Lua 生态库时，用下一章的 Lua。

---

## 8. Lua：内容生成与共享状态

完整配置里的 Lua 段：

```nginx
lua_shared_dict tutorial 1m;

location = /lua {
    content_by_lua "ngx.say('hello from lua, path=', ngx.req.get_path())";
}

location = /lua/count {
    content_by_lua "
        local d = ngx.shared.tutorial
        local n, err = d:incr('hits', 1, 0)
        if not n then ngx.say('incr failed: ', err) return end
        ngx.header['Content-Type'] = 'text/plain; charset=utf-8'
        ngx.say('hits=', n)
    ";
}
```

验证：

```bash
curl -s http://127.0.0.1:18600/lua
# hello from lua, path=/lua

curl -s http://127.0.0.1:18600/lua/count
# hits=1
curl -s http://127.0.0.1:18600/lua/count
# hits=2
```

`ngx.shared.tutorial` 是进程级共享字典，16 个分片各自加锁，多核并发读写不会互相阻塞；
容量在 `lua_shared_dict` 里声明，改容量需要重启。Lua VM 池按 CPU 核数建立，每个 VM 有独立
的调度器，`ngx.sleep` 不会阻塞工作线程；`lua_slice_instructions`（默认 1,000,000 条指令）
会周期性抢占死循环，把它降级成“一个请求卡住”，而不是拖垮整个进程。

常用 API 覆盖 `ngx.say/print/header/status/exit`、`ngx.req.*`、`ngx.resp.*`、
`ngx.shared.DICT`、`ngx.timer.*`、`ngx.re`、`ngx.location.capture`、`ngx.socket` 等，
完整清单见 [README 的 Lua API 一节](../README.md#lua-api-aligned-with-ngx)。

Lua 文件脚本用 `content_by_lua_file "../lua/time.lua";` 引用；文件只读一次并缓存，
编辑后由脚本自检/重载机制生效。大量计算或需要强隔离的第三方代码优先放 WASM；需要
成熟的 Lua 生态和快速迭代时用 Lua。

---

## 9. 多核：worker_threads 与 CPU 亲和性

默认 tokio 工作线程数等于逻辑 CPU 数。可以显式设置，并把线程绑定到核：

```nginx
worker_threads 4;
worker_cpu_affinity auto;                          # 线程 i -> 逻辑核 i
# worker_cpu_affinity 00000001 00000002 00000004;  # 显式掩码，按声明顺序轮换
# worker_cpu_affinity off;                         # 默认，不绑定
```

仓库里的亲和性示例可以直接验证（它用 3 个线程和两个掩码，第三个线程轮回到 CPU0）：

```bash
target/release/onrouter -t -c conf/affinity_e2e.conf
# worker_threads=3（逻辑核 N）...；亲和性：0=[0], 1=[1], 2=[0]

target/release/onrouter -c conf/affinity_e2e.conf
grep "绑定 CPU 核心" conf/logs/affinity_e2e_err.log
# worker 线程 0 绑定 CPU 核心 [0]
# worker 线程 1 绑定 CPU 核心 [1]
# worker 线程 2 绑定 CPU 核心 [0]
```

平台差异：

- Linux 使用 `sched_setaffinity`，容器里要按 cpuset 内可见的编号写掩码；
- Windows 使用 `SetThreadAffinityMask`，单处理器组最多 64 核；
- macOS/BSD 没有线程级硬亲和性，`auto`/掩码配置会告警，不要在生产依赖。

什么时候值得开：高 QPS、小对象、缓存命中率高的网关，绑定通常能减少跨核迁移。先用
`off` 做基线，再用相同压测对比 P99、上下文切换和吞吐；低负载或 CPU 配额很小时收益
不明显。亲和性不解决单进程瓶颈，扩容优先看 `worker_threads`、连接池和缓存命中率。

修改 `worker_threads` / `worker_cpu_affinity` 必须重启；热重载不会重建线程池。

---

## 10. 指标、热重载与停机

### 10.1 /metrics

完整配置里：

```nginx
location = /metrics {
    content_by_rust metrics;
}
```

生产上要限制来源（只监听内网地址，或加 `allow/deny`）。常用指标：

```bash
curl -s http://127.0.0.1:18600/metrics | grep -E \
  "onrouter_(http_requests|connections|upstream|proxy_split|cache_requests|wasm)"
```

几个排障入口：

| 症状 | 先看 |
|---|---|
| 5xx 升高 | `onrouter_http_responses_total`、`onrouter_upstream_requests_total{result="failure"}` |
| 某台后端不接流量 | `onrouter_upstream_server_available`、`circuit_state` |
| 灰度比例不对 | `onrouter_proxy_split_targets_total`、`proxy_split_total{role}` |
| 缓存命中低 | `onrouter_cache_requests_total{status}` |
| WASM 拒绝/失败 | `onrouter_wasm_denied_total`、`wasm_errors_total`、`fuel_exhausted_total` |
| 连接打满 | `onrouter_connections_active` / `onrouter_connections_capacity` |

告警建议：5xx 比例突增、`server_available == 0` 持续超过一个摘除/探测周期、`circuit_state == 2`、
WASM 错误/拒绝快速增长、连接水位超过 0.8、`access_log_dropped_total` 增长。配置了主动
`health_check` 时再对 `server_healthy` 告警。

### 10.2 热重载

配置里已经有：

```nginx
reload 2s;
```

进程每 2 秒检查一次配置文件与证书的 mtime；Linux/macOS 也可以 `kill -HUP <pid>` 立即触发。
热重载失败（配置语法错、证书读不到）会保留旧配置继续服务，并在 `error_log` 写明原因。

改一个路由试试：把 `/health` 的响应从 `ok` 改成 `ok-v2`，保存，等 2 秒：

```bash
curl -s http://127.0.0.1:18600/health
# ok-v2
```

无需重启，正在处理的请求不受影响。**但热重载不是万能的**：

| 改动 | 是否热生效 |
|---|---|
| location/server/rewrite/return、canary、WASM、TLS 证书 | 是 |
| `proxy_cache_path` keys_zone 容量、`still_online_zone` 预算 | 是 |
| scheduled window、cache_governor | 是 |
| `listen` 地址/端口/TLS 开关 | 否，重启 |
| `worker_threads`、`worker_cpu_affinity` | 否，重启 |
| upstream 池：server 列表/权重/算法/keepalive/lazy_rejoin/circuit_breaker | 否，重启 |
| `lua_shared_dict` 容量、`error_log` 目标/级别 | 否，重启 |

改 upstream 后热重载不会替换运行中的池，日志会明确写出“upstream 池不热替换，档位改动要
重启才生效”，不要把它当成已经切换。生产上做 upstream 变更要走滚动重启或蓝绿。

### 10.3 停机

`Ctrl+C`（Windows）或 `SIGTERM`/`SIGINT`（Linux/macOS）触发优雅停机：停止 accept，等待存量
请求完成，最长 `shutdown_grace`（默认 30 秒）。大文件下载或长连接会占满这段时间；要快速
下线，先从外层负载均衡摘除，再发信号。

---

## 11. 测试、20 分钟稳定性压测与 CI

### 11.1 单元测试与静态检查

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

仓库现有代码里可能有一些历史 clippy 告警，CI 不把它们设为 `-D warnings`；但新增代码不应
引入新的 warning。

### 11.2 五组真实流量 E2E

这些脚本会自己起网关、后端和探针，使用固定端口；运行前先停掉本机占用这些端口的进程。
教程的 18600 不会冲突。

```bash
python tools/canary_e2e.py        # 22 项
python tools/wasm_e2e.py         # 23 项
python tools/resilience_e2e.py   # 17 项
python tools/affinity_e2e.py     # 7 项
python tools/proxy_split_e2e.py  # 76 项
```

它们验证的是行为，不是“能编译”：灰度第一条命中、熔断半开、懒重连真实探针、WASM 改写
状态/头/体、亲和性逐线程绑定、分流账本等（合计 145 项断言）。任何一项失败都会打印 HTTP
状态、响应头或进程日志，先看脚本输出再改代码。

### 11.3 21 分钟稳定性压测

`tools/soak_test.py` 会启动后端、生成混合流量（普通反代、WASM 过滤、缓存 churn、Lua、
静态文件、keep-alive），每 5 秒采样一次内存，预热 5 分钟后做趋势判定：

```bash
cargo build --release -p onrouter-server --bin onrouter
python tools/soak_test.py --minutes 21
```

产物：

```text
target/soak_report.json        # 结论、基线/结束私有内存、斜率、失败分类
target/soak_samples.csv        # 每次采样的 rss/priv、请求数、失败数
target/soak_metrics_start.txt
target/soak_metrics_end.txt
# 终端进度本身不落盘；想留档就像 CI 一样：
# python tools/soak_test.py --minutes 21 | tee target/soak_console.log
```

判定口径：

- 预热后的私有内存增长超过 48 MiB **且**回归斜率超过 1 MiB/min，判为疑似泄漏；
- 增长超过 72 MiB，或结束值超过基线 2 倍且增长超过 32 MiB，判为失败；
- 请求失败率超过 0.2%（且至少 50 个）或请求量过低，也判失败；
- 通过时 `soak_report.json` 的 `verdict` 为 `"PASS"`，并且 `memory.checked` 为 true；
  失败分类在 `failures` 里，请求数在 `requests.{ok,fail}`。

看趋势而不是看绝对吞吐：不同机器的 RSS 基数、后端延迟和 Python 压测器本身都会影响
数字。真正要确认的是“预热后曲线走平、失败为零、没有单调上升”。

1.0.0 发布前沿用本口径跑了两次 21 分钟：2,591,305 请求 / 0 失败 / 私有内存 +1.86 MiB
（斜率 +0.067 MiB/min），以及首次 2,787,193 请求 / 0 失败 / +2.19 MiB，均 PASS。
完整表格见 `docs/OPERATIONS.md` §13.1。

### 11.4 CI

`.github/workflows/ci.yml` 在 push / PR 到 `master`/`main` 时运行：

- `unit`：`cargo test --workspace` + clippy；
- `e2e`：release 构建后依次跑上面五组脚本，失败时上传 `conf/logs/`；
- `soak`：仅 `workflow_dispatch` 且输入分钟数非 0 时运行（建议填 21），报告作为 artifact 上传。

本地通过不等于 CI 通过：CI 是 Linux，端口、路径大小写、证书和信号行为都要以它为准。

---

## 12. 完整配置导读与上线检查表

`conf/tutorial_full.conf` 把前面所有模块放在同一个进程里，端口与引用关系如下：

```text
浏览器/curl
   │ 127.0.0.1:18600
   ▼
ONRouter
   ├─ /release   canary $release ── stable(18601) / beta(18602)
   ├─ /api/      app（轮询 + lazy_rejoin + keepalive）
   ├─ /pair      app（观察摘除/恢复）
   ├─ /breaker   breaker（单节点 + circuit_breaker）
   ├─ /cached    proxy_cache tutorial + canary
   ├─ /guarded   access_by_wasm authz ── app
   ├─ /filtered  header_filter_by_wasm hf ── app
   ├─ /lua, /lua/count   Lua 内容与共享字典
   ├─ /health    直返
   └─ /metrics   指标
```

配置从上到下分成六块：全局（日志/pid/reload/线程）→ 缓存区 → upstream → canary →
WASM/Lua → server/location。每一块都可以单独 `-t` 验证；排障时先确认请求命中了哪个
location、`proxy_pass` 的目标池是否存在、目标池里是否有健康节点。

上线前至少过一遍：

1. `onrouter -t -c <生产配置>` 退出码 0，告警逐条确认；
2. 监听地址、TLS 证书、私钥权限、`/metrics` 来源限制；
3. upstream 每台后端可连接，`max_fails`/`fail_timeout` 与业务超时匹配；
4. 灰度规则有 `default`，粘性键包含业务用户标识而不是只有 `$remote_addr`；
5. 缓存 TTL 与业务可接受的新鲜度一致，敏感响应不被缓存；
6. WASM/Lua 的预算、日志与失败关闭行为符合预期；
7. 有 `reload` 或 SIGHUP 流程，且知道哪些改动必须重启；
8. 用生产同规格机器跑过 20 分钟 soak，并做过杀后端、恢复、配置回滚演练；
9. 发布产物用 `tools/release_verify.py` 验过，回滚包和配置都在手边。

更细的容量、安全、升级与排障见 [OPERATIONS.md](OPERATIONS.md)。

---

## 13. 常见问题

| 现象 | 常见原因 | 处理 |
|---|---|---|
| 404，其他路径正常 | location 前缀/精确匹配写错；`root` 相对路径指向了别处 | 用 `-t` 看路由；确认相对路径基于配置文件目录 |
| 502 | 后端没起、端口错、upstream 池里没有可用节点 | 查 `server_available`、`circuit_state`；先直连后端 |
| 熔断实验里看不到 502 | 默认 `proxy_next_upstream` 会换节点 | 实验 location 写 `proxy_next_upstream off;` |
| 改 upstream 后没变化 | 热重载不替换运行中的池 | 重启进程（见第 10 章表格） |
| Windows 改配置不生效 | 没有 `reload` 指令，也没有 SIGHUP | 加 `reload 2s;` 或重启 |
| `/guarded` 一直 403 | 没带 `X-Gateway-Token`，或插件名引用错 | 带 token 重试；`-t` 检查 `access_by_wasm` 名字 |
| WASM 请求返回 5xx | 插件 trap、越界、fuel 耗尽 | 看 `wasm_errors_total`/`fuel_exhausted_total` 与 error_log |
| 缓存一直 MISS | URL 每次不同（查询串）、TTL 为 0、方法是 POST、上游发 Set-Cookie | 用固定 URL 连测两次；检查 `X-Cache` 与 TTL |
| 灰度比例明显偏离 | 粘性键只有 IP、样本太小、上游池容量不足 | 换业务用户键；看 `proxy_split_targets_total` 的增量 |
| 启动报端口占用 | 已有进程监听同一地址/端口 | 停掉旧进程或换端口 |
| 日志找不到 | 相对路径基于配置文件目录 | 去 `conf/logs/` 找，或改绝对路径 |
| 压测内存缓慢上升 | 缓存条目/共享字典增长、连接池、真实泄漏 | 看 soak 的私有内存斜率与 `target/soak_samples.csv` |

---

## 附：命令速查

```bash
# 构建与版本
cargo build --release --workspace
target/release/onrouter -V

# 配置检查与启动
target/release/onrouter -t -c conf/tutorial_full.conf
target/release/onrouter -c conf/tutorial_full.conf

# 教程后端
python tools/tutorial_backend.py a 18601
python tools/tutorial_backend.py b 18602

# 关键请求
curl -s http://127.0.0.1:18600/api/hello
curl -s -H "Cookie: beta=1" http://127.0.0.1:18600/release
curl -i http://127.0.0.1:18600/guarded
curl -s http://127.0.0.1:18600/metrics | grep onrouter_upstream

# 重载与停机（Linux/macOS）
kill -HUP "$(cat conf/logs/tutorial.pid)"
kill -TERM "$(cat conf/logs/tutorial.pid)"

# 测试
cargo test --workspace
python tools/soak_test.py --minutes 21
```

下一站：[OPERATIONS.md](OPERATIONS.md) 的进程模型、容量预算、发布与回滚章节。
