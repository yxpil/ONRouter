# ONRouter 1.0 操作手册

适用版本：**1.0.2**（2026-10-21）
面向：部署、值守、容量规划与故障排查。
配套文档：[使用教程](TUTORIAL.md)、[完整功能矩阵与 Lua API](../README.md)、[能力矩阵与证据](CAPABILITY_MATRIX.md)。

---

## 1. 进程模型与运维边界

ONRouter 是**单进程、多线程**网关：没有 nginx 的 master/worker 进程树，所有工作线程共享监听
socket、连接池、缓存和指标。运维上要记住三条：

1. 线程数由 `worker_threads` 决定（默认等于逻辑 CPU 数），不再是固定值；CPU 亲和性绑定的是
   这些工作线程，不是子进程。
2. 配置热重载在**同一进程内**原子替换路由表，监听 socket 不重绑，因此没有 accept 空窗；
   监听地址、端口、`worker_threads`、`worker_cpu_affinity` 的变更必须重启进程。
3. 进程内任何一处失控（Lua 死循环、WASM 死循环、超大过滤器缓冲）都会影响整个网关。为此 1.0
   提供三层预算：Lua 指令切片、WASM fuel/内存上限、响应过滤器缓冲上限。容量规划时必须把它们
   算进去（见第 11 节）。

Linux/macOS 用信号管理进程；Windows 只响应 Ctrl+C，热重载依赖配置里的 `reload <interval>;`
轮询。二进制热升级（nginx `USR2`）在 1.0 中**尚未实现**，升级请用滚动/蓝绿发布（见第 16 节）。

---

## 2. 安装与目录

### 2.1 使用发布包

有两种产物，装的东西不一样，先看清要拿哪一个：

**A. GitHub Release 上的平台包**（`release.yml` 推 `v*` 标签时自动产出 8 个）——
每个里面**只有两个可执行文件**（`onrouter` 与 `orr-gencert`），文件名是
`onrouter-v<版本>-<target>.tar.gz`（Linux/macOS）或 `.zip`（Windows），
target 为 `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、
`armv7-unknown-linux-gnueabihf`、`riscv64gc-unknown-linux-gnu`、
`x86_64-apple-darwin`、`aarch64-apple-darwin`、`x86_64-pc-windows-msvc`、
`aarch64-pc-windows-msvc`。配置、示例站点与文档**不在**这种包里，随仓库拿或自己准备。

**B. 本地/内网构建机打包的"开箱可跑"完整目录**（`build-release.ps1` / `build-release.sh`
产出，落在 `target/dist/archives/`）——除两个可执行文件外还带：

| 路径 | 用途 |
|---|---|
| `conf/*.conf` | 示例配置（含 `tutorial_hello.conf`、`tutorial_full.conf`） |
| `conf/wasm/`、`conf/wasm_static/` 等 | WASM 插件与 E2E/教学用静态资源 |
| `lua/`、`public/` | 示例 Lua 脚本与静态站点 |
| `certs/` | 打包时由 `orr-gencert` 现生成的自签名证书对，供 `conf/onrouter.conf` 的 8443 TLS 演示直接使用 |
| `docs/`、`README.md` | 操作手册、使用教程与项目说明 |

两种包的压缩结构都是"内容在压缩包根"，**没有** `onrouter-v1.0.2-…/` 这样的外层目录，
所以解压时先自己建目录，别指望 `cd` 进一个包里不存在的名字：

```bash
# A 类（GitHub 资产）：Linux / macOS
mkdir -p /usr/local/onrouter && tar xzf onrouter-v1.0.2-x86_64-unknown-linux-gnu.tar.gz -C /usr/local/onrouter
install -m 0755 /usr/local/onrouter/onrouter /usr/local/onrouter/orr-gencert /usr/local/bin/
onrouter -V

# A 类：Windows PowerShell
New-Item -ItemType Directory -Force C:\onrouter | Out-Null
Expand-Archive onrouter-v1.0.2-x86_64-pc-windows-msvc.zip -DestinationPath C:\onrouter
C:\onrouter\onrouter.exe -V

# B 类（完整目录包）：解开就是推荐布局，conf/ 与可执行文件同级，直接能跑
mkdir -p orr && tar xzf onrouter-v1.0.2-x86_64-unknown-linux-gnu.tar.gz -C orr
cd orr && ./onrouter -t -c conf/onrouter.conf
```

`certs/` 里的私钥不进入 git，每次打包现生成；它只用于开箱验证，生产环境请按第 5 节
替换为自己的证书。`logs/`、`cache/` 等运行时状态**不会**打进包内，首次启动前需保证对应
目录可写。教程见 `docs/TUTORIAL.md`。

### 2.2 从源码构建

```bash
cargo build --release -p onrouter-server --bin onrouter
cargo build --release --bin orr-gencert
target/release/onrouter -V
```

建议的生产目录：

```text
/opt/onrouter/
├── onrouter                 # 可执行文件
├── conf/
│   ├── onrouter.conf        # 主配置
│   ├── logs/                # 相对路径日志的落点（需可写）
│   └── wasm/                # .wasm / .wat 插件
├── lua/                     # Lua 业务脚本
├── public/                  # 静态文件
└── certs/                   # 证书与私钥
```

配置里的相对路径**以配置文件所在目录为基准**（不是进程当前目录）：

- `onrouter -c conf/onrouter.conf` → `logs/a.log` 落在 `conf/logs/a.log`；
- `wasm_plugin authz conf/wasm/authz.wat;` 会去 `conf/conf/wasm/authz.wat` 找文件，应写成
  `wasm_plugin authz wasm/authz.wat;`（相对 `conf/`，仓库里就带 `authz.wat`/`header_filter.wat`/
  `body_filter.wat`/`fuel.wat` 四个示例）；
- 使用 `-p <prefix>` 时，所有相对路径以 prefix 为基准，配置文件本身也是 `prefix/<conf>`。

这是新用户最容易踩的坑：`-t` 能过、启动后日志却找不到，通常就是基准目录理解错了。

---

## 3. 命令行与配置检查

```text
onrouter [选项] [配置文件]

  -c <file>       指定配置文件（默认 conf/onrouter.conf）
  -p <dir>        前缀目录，配置内相对路径以此为基准
  -g <directives> 命令行全局指令，可重复，例如 -g 'pid run.pid; error_log err.log warn;'
  -e <file>       兼容 nginx 测试工具，接受但忽略（错误日志由配置决定）
  -t              只检查配置（含证书、引用、WASM 模块），不启动
  -V              显示版本
  -h, --help      帮助
```

### 3.1 上线前必须跑 `-t`

```bash
onrouter -t -c conf/onrouter.conf
```

`-t` 会打印：

- 监听地址与 server_name；
- `worker_connections` / `keepalive_requests` / `shutdown_grace`；
- `worker_threads`、逻辑核数、`worker_cpu_affinity` 的**逐线程计划**；
- Still ONLine 区、限流队列、学习表、前置代理识别；
- 调度窗口、缓存 governor、upstream 的 `least_time`/韧性摘要；
- 每条业务分流（`proxy_pass http://$var`）的声明比例与候选版本；
- 每个 WASM 插件的路径、fuel、内存上限、导出函数；
- 每个开了 `disk=on` 的 `proxy_cache` 区：冷层目录、`max_size`、`levels`、`inactive`、
  `spill_after`、`max_value`（没开的区一行都不打印，也不建目录）；
- **所有“写了但没生效”的告警**（未知指令、被忽略的指令、掩码越界裁剪等）。

退出码：

| 退出码 | 含义 |
|---|---|
| `0` | 配置可运行；**即使有告警也返回 0**，必须读输出里的“告警 N 条” |
| `1` | 配置/证书/引用错误，进程不会启动 |
| `2` | 命令行参数错误 |

不要只看退出码。未知指令、`worker_processes`、`log_format` 等被忽略的写法只发告警，不会让
`-t` 失败；这类“写了但没生效”正是上线事故的高发区。

### 3.2 启动

```bash
onrouter -c conf/onrouter.conf
```

前台运行，日志按配置写入 `error_log`/`access_log`。生产环境请交给 systemd、Windows 服务或
容器编排托管；ONRouter 不提供 `daemon on;`。

systemd 示例：

```ini
[Unit]
Description=ONRouter gateway
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/onrouter
ExecStart=/opt/onrouter/onrouter -c conf/onrouter.conf
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=35
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

`TimeoutStopSec` 应大于配置里的 `shutdown_grace`（默认 30s），否则 systemd 会在网关排空存量
连接前强杀。

---

## 4. 进程管理：重载、日志、停机

| 操作 | Linux/macOS | Windows |
|---|---|---|
| 热重载配置 | `kill -HUP <pid>` | 配置 `reload <interval>;` 轮询 |
| 只重开日志 | `kill -USR1 <pid>` | 无信号；重启或由日志切割后触发重载 |
| 优雅停机 | `SIGTERM` / `SIGINT` | Ctrl+C |
| 二进制热升级 | 1.0 未实现；滚动/蓝绿 | 滚动/蓝绿 |

### 4.1 热重载能改什么

`SIGHUP` 或轮询检测到主配置/证书文件变化后，进程重新读盘并**原子替换路由表**；构建失败时
保留旧配置继续服务，并在 `error_log` 写明原因。可热更新：

- server/location/rewrite/return/proxy_pass 以及 `proxy_cache`、`add_header` 等路由级指令；
- canary / split_clients 规则（引用的 upstream 池必须启动时已存在）；
- WASM 插件代码与 `*_by_wasm` 阶段引用；
- TLS 证书与私钥（证书原地续期也会被检测到，不必改配置）；
- `proxy_cache_path` 的 `keys_zone` 容量、`still_online_zone` 预算（已有条目立即按新上限裁剪），以及各区冷层的开关（`disk=on` 增删会重开 store：先把旧队列排空再打开新的，避免同一目录被两个 store 同时持有）；
- scheduled window 与 cache_governor 配置。

必须重启：

- `listen` 的地址/端口/TLS 开关；
- `worker_threads`、`worker_cpu_affinity`（线程池与绑定在启动时建立）；
- upstream 池定义与池内状态：`server` 列表、权重、`least_conn`/`ip_hash`/`keepalive`、
  `lazy_rejoin`、`circuit_breaker`、`least_time`。热重载只会把新档位写进日志并提示要重启，
  不会替换正在使用的池，也不会清空节点健康计数；
- `lua_shared_dict` 的容量与 VM 池配置（VM 在启动时建立，`init_by_lua` 不会重跑）；
- `error_log` 的目标与级别；
- 更换二进制版本。

`reload 2s;` 表示每 2 秒检查一次配置与证书的 mtime；未配置时只响应 `SIGHUP`（Lua 脚本文件
仍会每秒自检）。轮询间隔不要低于 100ms，否则大配置下会做无意义的频繁 stat。

### 4.2 停机

收到 `SIGTERM`/`SIGINT` 后停止接受新连接，等待存量请求完成，最长等待 `shutdown_grace`
（默认 30s）。长连接/大文件下载会占满这段时间；需要更快下线时，先把它从负载均衡器摘除，
再发信号。

`pid` 指令只写 PID 文件，不负责进程守护：

```nginx
pid "logs/onrouter.pid";
```

Windows 没有 `SIGHUP`：改了配置后要么重启，要么预先配置 `reload 2s;`。轮询模式在所有平台
都可用，适合容器和 Windows。

### 4.3 日志

nginx 的 `error_log` 级别不记 info，但 ONRouter 的启动摘要（每个限流区的实际 `key=`、缓存区、
调度窗口、冷层目录）都是 info 级：**排障要看这些行就得留 info**。下面的日志路径都是相对路径，
按**配置文件所在目录**解析（配置放 `conf/` 时就是 `conf/logs/`，不是仓库根的 `logs/`）。

```nginx
error_log "logs/error.log" info;   # debug|info|warn|error
error_log_max_size 64m;            # 单文件上限，超出滚动
error_log_keep 5;                  # 保留份数
access_log "logs/access.log";
access_log_max_size 64m;
access_log_keep 5;
```

访问日志是内置 combined 格式；`log_format` 目前不生效（`-t` 会告警）。日志写满时丢弃会记在
`onrouter_access_log_dropped_total`，出现非零值说明磁盘或消费速度跟不上。

---

## 5. 关键全局指令

| 指令 | 说明 | 默认 |
|---|---|---|
| `worker_threads <n>;` | tokio 工作线程数，1..=1024 | 逻辑 CPU 数 |
| `worker_cpu_affinity off/auto/mask...;` | 工作线程 CPU 绑定 | `off` |
| `worker_connections <n>;` | 每进程连接额度 | 10240 |
| `keepalive_requests <n>;` | 单连接最多请求数 | 1000 |
| `keepalive_timeout <t>;` | 下游空闲 keep-alive 超时 | 见示例配置 |
| `client_header_timeout` / `client_body_timeout` | 读请求头/体的空闲超时（体超时是**单帧之间**的最大间隔，不是总时长） | 15s / 30s |
| `tls_handshake_timeout <t>;` | 与客户端 TLS 握手的上限，超时直接关连接（不占 worker 额度干等） | 10s |
| `shutdown_grace <t>;` | 优雅停机排空上限 | 30s |
| `reload <t>;` | 配置/证书轮询间隔 | 仅信号 |
| `server_tokens on/off;` | 是否暴露版本（`Server:` 与错误页） | on |
| `tcp_nodelay on/off;` | TCP_NODELAY | on |
| `accept_backlog <n>;` | listen backlog | 512 |
| `gzip ...` | 响应压缩 | 关闭 |
| `proxy_cache_path <path> keys_zone=<name>:<size> [disk=on] [max_size=] [levels=] [inactive=] [spill_after=] [max_value=];` | 缓存区；`disk=on` 时 `<path>` 就是该区冷层目录 | 冷层关闭 |
| `still_online_zone <name> <size>;` | 最后已知好副本区 | — |

### 5.1 server 级的 `return` / `rewrite` / `set` / `if`

这四条属于 nginx 的 REWRITE 相位，在 **location 匹配之前**执行（SERVER-rewrite）。1.0.1 之前它们
写在 `server` 块里只会得到一行"已被忽略"的告警，于是最常见的跳转 vhost 静默变成 404：

```nginx
server {
    listen 80;
    server_name www.example.com;
    return 301 https://$host$request_uri;   # 现在真的回 301
}
```

运维要点：

- server 级 `set`/`rewrite` 改的是路径与变量，因此它们会**改变最终命中哪个 location**；写的时候
  按"先 server、后 location"的顺序理解执行流。
- server 级 `return` 先于访问控制执行（nginx 一致，否则没有 location 的跳转 vhost 无法工作）。
  **location 级 `return` 仍然是 ONRouter 的刻意差异**：它排在 `allow`/`deny`/`auth_basic`/
  `access_by_*` 之后，见 `docs/CAPABILITY_MATRIX.md` §1.1。同一个条件在两级写出来结果不同，
  别指望它们等价。
- 形态检查与 location 级共用同一套解析器：`if` 嵌套、`set plain 1`（变量名不是 `$` 开头）、
  非法条件都会在 `-t` 直接失败，不是告警。
- 执行仍受 `MAX_URI_CHANGES` 的环检测保护；server 级 rewrite 自身不消耗跳数额度。

### 5.2 限流的计数维度：`limit_req_zone` / `limit_conn_zone` 的 key

`limit_*_zone` 的第一个参数决定**谁和谁共用同一个令牌桶**，所以它是限流配置里最要紧的一个选择。
按 IP 计数在机房出口、校园网、公司 NAT 之后会把一整栋楼算成一个人；真实业务经常需要按人、
按会话、按调用方限：

```nginx
# 按会话限：一人一键，同 IP 的另一个人不受影响
limit_req_zone  $cookie_JSESSIONID  zone=peruser:1m  rate=2r/s  burst=5;
# 按调用方限（API 网关常见形状：一个 key 一个配额）
limit_req_zone  $http_x_api_key     zone=perapp:1m   rate=50r/s burst=100;
# 拼一个键：参数 + 地址一起构成计数维度
limit_req_zone  $arg_k$remote_addr  zone=perpath:1m   rate=1r/s;
# 并发额度是另一类区（limit_conn_zone），与 limit_req_zone 不能互换
limit_conn_zone $cookie_JSESSIONID  zone=peruser_conn:1m;

server {
    location /api/ { limit_req zone=peruser; }
    # limit_conn 用的是并发区（limit_conn_zone），也可以写在 location 里：
    # 写了就整组替换 server 级那一条，不是叠加
    location /export/ { limit_conn peruser_conn 1; }
}
```

支持的维度：

| 写法 | 计的是什么 |
|---|---|
| `$remote_addr` / `$binary_remote_addr` | 客户端地址（走 realip / front_proxy 采信后的地址） |
| `$http_<头名>` | 请求头，如 `$http_x_api_key`（不存在的头 = 空 = 不限流） |
| `$cookie_<名>` | Cookie 里的一个值，如 `$cookie_JSESSIONID`（没有这个 Cookie = 空 = 不限流） |
| `$arg_<名>` | URL 查询参数，如 `$arg_token` |
| `$remote_port` `$server_addr` `$server_port` `$scheme` `$https` `$request_method`（`$method`） `$uri`（规范化后的） `$request_uri` `$args`（=`$query_string`） `$is_args` `$hostname` `$host` `$ssl_server_name` `$realip_remote_addr` `$content_type` `$content_length` `$request_length` `$proxy_add_x_forwarded_for` `$front_proxy*` | 判定时刻就有值的固定变量 |
| 以上任意拼接 | `$cookie_sid$remote_addr`，按整模板插值成一个键 |

明确**不支持**、并且 `-t` 会直接否决的写法（不是告警）：

- 响应期/后端变量：`$status`、`$upstream_*`、`$sent_http_*`。限流判定发生在回源之前，这些取不到值，
  写下去等于把全区流量并成一个空键的桶。
- `$request_body`：判定时刻请求体还没读完，恒为空。
- `set` 出来的请求级变量：限流跑在 REWRITE 之前，那时 `set` 还没执行。nginx 允许这种写法，
  ONRouter 目前不允许 —— 请直接用 `set` 右边那个来源变量当键。
- 本实现没有的变量（如 `$server_name`）。想按站点限流请为每个站点声明各自的区。

运维上必须知道的三件事：

1. **空键 = 这个请求不受本区限流**（与 nginx 一致）。没带 `$http_x_api_key` 的请求不会占任何桶，
   所以"按头限流"必须和 ACL 或 `if` + `return` 搭配，否则不带头的流量完全不受约束。
   想确认实际生效的维度：`error_log ... info;` 下每个区启动时都有一行
   `生效 limit_req zone=peruser rate=2.0r/s burst=5 key=$cookie_JSESSIONID`（`-t` 只摘要开了队列的区）。
2. **键的基数由客户端决定时要设防**。每个区最多跟踪 32 分片 × 16384 个键。到顶时：
   `limit_req_zone` 淘汰最久未使用的那批（它们的桶被清空 = 重新计数），`limit_conn_zone`
   优先复用已归零的键、一个都没有时按 nginx 的 shm 耗尽语义**拒绝**新连接。
   拿一个客户端可以随意伪造的头当键，攻击者只要每次换个值就能永远落在"新键"上，等于绕过限流。
   因此这类键要么必须是服务端签发的会话号，要么就得接受"换键成本为零"的事实。
3. **`zone=<名>:<容量>` 里的容量数字目前只用于展示**，实际表上限就是上面那条 32×16384。
   写 `1m` 还是 `10m` 不改变能跟踪多少个键。
4. **拒绝时回哪个码是两处默认值差异**：`limit_req_status`（http 级）ONRouter 默认 **429**，
   nginx 默认 503；`limit_conn_status` 两边都是 503。`limit_req` 拒绝的响应还带 `Retry-After`
   （`limit_conn` 是直接收口的，没有这个头）。
   从 nginx 迁过来、告警规则按"503 才是被限流"写的，显式写一行 `limit_req_status 503;`，
   别依赖默认值。

### 5.3 静态资源的过期头：`expires`

`expires` 只管响应头（`Cache-Control` / `Expires`），不影响本机 `proxy_cache` 的存留时间——
那一维由 `proxy_cache_valid` 决定。nginx 的取值口径这里全部可用：

| 写法 | 落下的头 |
|---|---|
| `expires 30d;` / `expires +1h;` | `Cache-Control: max-age=2592000` + 未来的 `Expires` |
| `expires -1h;` | `Cache-Control: no-cache` + 已经过去的 `Expires` |
| `expires max;` | `Cache-Control: public, max-age=315360000`（十年） |
| `expires epoch;` | `Cache-Control: no-store` + `Expires: Thu, 01 Jan 1970 00:00:01 GMT` |
| `expires @23:59:59;` | 定到当天 UTC 的那个时刻；已过则 `no-cache` |
| `expires "private, no-store";` | 原样作为 `Cache-Control` 的值，不动 `Expires` |
| `expires off;` | 什么都不写 |

要点：

- server 与 location 两级都能写。location 一旦写了就**整条替换** server 的（写成 `off` 是显式关闭，
  与"没写"不同），与 nginx 的指令继承一致。
- 只在可缓存的状态码上改写：**200/201/204/206/301/302/303/304/307/308**，逐条对照 nginx
  `ngx_http_headers_filter_module.c` 里的 `safe_status` 分支（**包含 204**：空响应也可以被说成
  能存一小时）；其余（404、500……）一字不动，否则错误页会被浏览器存成"能看一小时的本页"。
  用例在 `router::tests` 里逐码钉住，端到端由 `tools/expires_e2e.py` 覆盖。
- 网关的策略**覆盖源站自己那份 `Cache-Control`**（nginx 的 header filter 同样如此）。要透传源站的
  过期策略就别在这一级写 `expires`。
- 静态文件、反向代理、缓存命中、Lua（含已经 `flush` 出去的流式响应）、`return` 五条响应路径都落。
  流式那条最容易漏，`tools/expires_e2e.py` 逐条钉住。
- 时间值写坏（`expires 1x;`）在 `-t` 直接失败：那种配置落下去是"响应里一个过期头都没有"，
  而运维以为已经缓存住了。

```nginx
server {
    root /srv/site;
    expires 1h;                       # 兜底：整站一小时
    location /assets/ { expires max; }    # 带指纹的静态资源：十年
    location /login   { expires off; }    # 显式不写（不是"没配"）
}
```

### 5.4 传输协议：h1 / h2 / h3 各自要写对的地方

```nginx
server {
    listen 443 ssl http2 quic;       # TCP 上 h1.1+h2，UDP 443 上 h3
    server_name www.example.com;
}
```

- **`quic` 只带来 UDP 上的 HTTP/3，不会把 TCP 侧顺手升级成 h2**（口径同 nginx：那是两个
  参数）。只写 `ssl quic` 时，用 ALPN 要 h2 的客户端会被拒绝（`no application protocol`）——
  想三种都要就写全 `ssl http2 quic`。
- `-t` 与启动横幅会把这个端点的形状说出来：`监听 127.0.0.1:443 TLS+HTTP/3(同端口 UDP) -> […]`。
  运维不该靠外部探测才知道"这台到底开没开 h3"。TCP 侧的响应会自动带
  `Alt-Svc: h3=":443"; ma=3600`，浏览器据此跳到 QUIC。
- **请求体按分帧读，不按头猜**：h2/h3 的请求既没有 `Content-Length` 也没有
  `Transfer-Encoding: chunked`，字节就在 DATA 帧里、流的结束标记就是体的结束。1.0.2 之前
  网关用"这两个头在不在"来决定读不读体，于是 h2/h3 上的 POST 交到上游时是**空体**（源站看到
  一个没有 Content-Length 的 POST），而 h1 一切正常——这类差别不会报错，只会让业务"偶尔丢单"。
  现在三种传输的 body 长度与摘要在 `tools/quic_business_e2e.py` 里逐个对齐。
- 缓存、限流、`expires`、状态码这些**策略是跨传输共享的同一本账**：同一会话的令牌桶不会因为
  它从 h2 换到 h3 就重置；一条 `proxy_cache` 命中对三种传输是同一份字节。这一点是刻意测的
  （同一条套件），因为"每种协议各一套行为"是这类网关最常见的坑。
- 已知边界：网关到后端只说 HTTP/1.1（ALPN 固定 `http/1.1`，没有 h2/h3 upstream）；
  WebSocket over h2/h3（RFC 8441 / 9220）未实现——要 WS 就走 h1.1 的 Upgrade 那条路。

### 5.5 同一端口多个站点：证书按 SNI，站点按 Host

一个 TLS 端口上挂多个 `server` 块（多域名单端口，`yxpil.com` 这类部署的常态）时，**有两本独立
的账**，它们各自的取法不一样：

| 决定什么 | 依据 | 取法 |
|---|---|---|
| 出示哪张证书 | ClientHello 的 **SNI** | 精确名 > `*.通配` > 该地址的**默认 server** |
| 请求由哪个站点应答 | HTTP 的 `Host`（h1）或 `:authority`（h2/h3） | 同样是 精确 > 通配 > 默认 server |

- 默认 server = 写了 `listen … default_server` 的那个块；**没写**才是配置顺序里的第一个块。
  这一条是 v1.0.2 **之后**发现的静默不一致（当前已发布的那批二进制还没有它）：兜底证书原先跟着
  "配置顺序第一个"走，于是 SNI 匹配不上时出示的是"恰好第一个写的 vhost"的证书，而不是
  `default_server` 的证书——两个后果都不体面：带错域名的客户端看到一个与请求域名无关的证书
  （浏览器报名称不匹配），而换一行配置顺序就会换一张证书。站点选择那半边一直是对的，
  所以从 HTTP 侧完全看不出异常。
- 两本账**可以分开**：`SNI=a.com` 而 `Host=b.com` 时，出示 a 的证书、由 b 站应答（nginx 同）。
  这也是 `https_matrix` 里那条专门断言。
- 因此证书与站点的对应关系要按"这个站点配了哪张证书"来检查，而不是按配置顺序想当然。
  `-t` 打印的 `监听 … TLS -> [default.local(default), a.local]` 里括号标的就是默认 server，
  它对证书和站点同时生效。
- 验证：`tools/https_matrix_e2e.py` 76/76。其中 18443 那组把 `default_server` 写在**第一个**块，
  两种实现看不出差别；18449 那组把它写在**最后一个**块——只有这一组能分辨"跟配置顺序"和
  "跟默认 server"，兜底证书那条红就是靠它复现的。`tools/random_scenarios_e2e.py` 每轮随机
  把兜底块放在最前或最后，并让 SNI 与 authority 各取来源，证书指纹逐探针比对。

---

## 6. CPU 亲和性

### 6.1 配置

```nginx
worker_threads 8;
worker_cpu_affinity auto;                         # 线程 i -> 逻辑核 i
# worker_cpu_affinity 00000001 00000002 00000004; # 显式掩码，按声明顺序轮换
# worker_cpu_affinity off;                        # 默认，不绑定
```

- 显式掩码是 64 位十六进制（与 Windows 处理器组、Linux `cpu_set_t` 单组一致），最多覆盖 64 个
  逻辑核；超出本机核数的位会被裁掉，并在 `-t`/启动日志里告警。
- 掩码列表按线程轮换：3 个线程 + 两个掩码 → `0->CPU0, 1->CPU1, 2->CPU0`。
- 每线程可以绑定一组核（如 `00000003` = CPU0+CPU1），适合把超线程对放在一起。

### 6.2 验证

```bash
onrouter -t -c conf/affinity_e2e.conf
#   worker_threads=3（逻辑核 18）worker_cpu_affinity=0000...0001 0000...0002；亲和性：0=[0], 1=[1], 2=[0]

onrouter -c conf/affinity_e2e.conf
grep "绑定 CPU 核心" conf/logs/affinity_e2e_err.log
# worker 线程 0 绑定 CPU 核心 [0]
# worker 线程 1 绑定 CPU 核心 [1]
# worker 线程 2 绑定 CPU 核心 [0]
```

平台差异：

- Linux：`sched_setaffinity`，受容器 cpuset 限制；容器只看到部分核时，掩码要按容器内可见的
  核编号写，否则绑定会失败并告警。
- Windows：`SetThreadAffinityMask`，掩码限制在当前处理器组（最多 64 核）。
- macOS/BSD：没有线程级硬亲和性，除 `off` 外的配置会在绑定时告警，不要在生产依赖它。

### 6.3 什么时候值得开

- 高 QPS、小对象、缓存命中率高的网关：绑定能减少跨核迁移，通常收益 3%~10%；
- 后端是延迟敏感型、线程数远小于核数：`auto` 让每个线程独占一个核；
- 低负载或容器 CPU 配额很小时收益不明显，先用 `off` 做基线，再对比 P99 与上下文切换。

绑定不能解决单进程瓶颈；真正扩容优先看 `worker_threads`、连接池、缓存命中率与 Lua/WASM 预算。

---

## 7. Upstream、自动摘除、懒重连与熔断

### 7.1 基本配置

```nginx
upstream app {
    least_conn;                       # 默认加权轮询；也可 ip_hash
    server 10.0.0.11:8080 weight=3 max_fails=2 fail_timeout=10s;
    server 10.0.0.12:8080 weight=1 max_fails=2 fail_timeout=10s;
    server 10.0.0.13:8080 down;       # 手动下线
    keepalive 64;                     # 到后端的空闲连接池
}
```

`max_fails`/`fail_timeout` 是被动健康检查。"一次尝试算不算失败"分两类，这个区别在 nginx
源码里就存在（`ngx_http_upstream_next()` 在函数开头就把对端记为失败，"要不要重试"是后面
另一件事）：

- **连不上、等满 `proxy_*_timeout`、响应非法**：一定算一次失败，**即使这次不能重发**。
  非幂等方法（POST/LOCK/PATCH）不会被重发，但那台后端照样被记一次——它确实没答上来。
- **状态码命中 `proxy_next_upstream http_XXX`**：只有**真的换了节点**的那一次才算失败，
  且 `http_403`/`http_404` 永远不算（nginx 走 `NGX_PEER_NEXT`）。所以一台"只会回 503"的
  后端，没写 `http_503` 时它的响应会被当成合法响应原样回给客户端，既不换节点也不计入
  `max_fails`；要摘它就得把 `http_503` 写进 `proxy_next_upstream`。

`down` 是人工下线，不参与探测。

给客户端的码也按根因分：**等满超时是 504**，连不上、响应非法、所有节点都在摘除期是 502。
这两个码在告警与 `error_page` 里不该合并——一台只是慢的后端和一台已经死掉的后端，处理方式不同。
非幂等方法（POST/LOCK/PATCH）默认不参与换节点重试，请求一旦交到某台后端就只在那台上成败，
除非显式写 `non_idempotent`。

### 7.2 懒重连（lazy rejoin）

```nginx
upstream app {
    server 10.0.0.11:8080 max_fails=1 fail_timeout=60s;
    server 10.0.0.12:8080 max_fails=1 fail_timeout=60s;
    lazy_rejoin 2s;
}
```

被摘除的节点不会由独立线程轮询，而是每 `lazy_rejoin` 到期后，由**一次真实用户请求**顺带作为
探针；探针成功即把节点加回候选集。好处：

- 不引入后台探测流量，也不需要额外的健康检查端口；
- 恢复探测和真实流量走同一条 DNS/连接/超时路径，探针成功基本等于服务可用；
- 探测失败继续摘除，不会形成“恢复—打满—再挂”的抖动（探测有间隔上限）。

代价是恢复延迟最多一个探测间隔；要求秒级恢复就把间隔调小，但不要低于 1s。

### 7.3 熔断（circuit_breaker）

```nginx
upstream app {
    server 10.0.0.11:8080 max_fails=100 fail_timeout=60s;
    circuit_breaker errors=2 window=5s open=2s;
}
```

- `errors=2 window=5s`：5 秒窗口内连续 2 次失败（连接失败、超时、无效响应）后打开，
  期间任一次成功会把计数清零；
- `open=2s`：打开期间不再尝试该节点；
- 到期进入半开，只放**一个**探针；成功闭合，失败重新打开一个周期。

熔断和被动摘除是两套机制，可以同时用：

- 被动摘除回答“这台暂时别选了”；
- 熔断回答“这台连续失败，先彻底停一段时间，别让每次请求都交一次连接超时学费”。

注意 `proxy_next_upstream` 默认会在 `error,timeout` 时换节点，所以客户端可能看到 200 而不是
502。验证熔断语义时，把实验 location 写成 `proxy_next_upstream off;`，让失败真的返回客户端。

### 7.4 观测

```bash
curl -s http://127.0.0.1:8080/metrics | grep onrouter_upstream
```

| 指标 | 含义 |
|---|---|
| `onrouter_upstream_server_available{upstream,server}` | 1 = 常规调度可选（已排除 `down`、被动摘除期内与熔断打开；全池摘除时的兜底试探和并发额度不计） |
| `onrouter_upstream_server_healthy{upstream,server}` | 主动健康检查的判定；**只有配置了 `health_check` 才有实际意义**，未配置时恒为 1 |
| `onrouter_upstream_requests_total{...result="success/failure"}` | 真实结果账本 |
| `onrouter_upstream_lazy_probes_total{...}` | 真实请求被顺带用作恢复探针的次数 |
| `onrouter_upstream_circuit_state{...}` | 0 闭合 / 1 半开 / 2 打开 |
| `onrouter_upstream_circuit_trips_total{...}` | 熔断打开次数 |
| `onrouter_upstream_server_connections{...}` | 在途连接 |

排障顺序：先看 `server_available` 是否与预期一致，再看 `requests_total` 的 failure 增量，最后看
`circuit_state` 是否卡在 2。被动摘除/懒重连没有独立线程，`lazy_probes_total` 的增量就是恢复
探测发生的证据。

---

### 7.5 四层 UDP：游戏 / 语音 / 实时状态同步

```nginx
stream {
    server {
        listen 18613 udp;
        proxy_pass 127.0.0.1:18621;
        proxy_responses 0;      # 心跳/状态上报：只发不等，不建会话也不占 fd
        proxy_timeout 5s;
    }
    server {
        listen 18614 udp;
        proxy_pass rooms;       # 房间服：命名 upstream，选点与 max_conns 照常生效
        proxy_timeout 2s;
        udp_max_sessions 2048;  # 见下：这条监听同时最多维持多少条会话
    }
    server {
        listen 18615 udp;
        proxy_pass 127.0.0.1:18623;
        proxy_responses 4;      # 一问多答：匹配结果 + 若干状态帧
    }
}
```

要点（都是 `tools/game_udp_e2e.py` 量过的，不是设计意图）：

- **会话按客户端 4 元组归位**，并且每条会话用一条 `connect` 到后端的 socket：内核只会把
  那个后端发来的报文交给我们，所以"把 A 的位置/血量发给 B"这条路径在操作系统层面不存在。
  60 个客户端并发、每人只该收到自己的 player 号——这套件的判定就是这个。
- **一个会话 = 一个 fd**，与 HTTP/stream 共用 `worker_connections` 额度。额度用尽时**丢包并计数**
  （`onrouter_stream_udp_dropped_total{role="no_permit"}`），不会把进程拖到 EMFILE。
- `proxy_timeout` 是会话的**空闲回收**期限。60 个客户端停手后 `…_sessions_active` 必须回落到 0，
  否则就是 fd 泄漏（件套件钉住了这一条）。
- **`udp_max_sessions` 是 ONRouter 的扩展，nginx 没有对应物**，而且它是给 UDP 用的护栏：
  UDP 的源地址与 4 元组是可以伪造的，一条吵闹的 UDP 服务在没有上限时会把 `worker_connections`
  吃光，**连七层一起饿死**。实测对照（`worker_connections=256`，同时打开 600 个客户端）：

  | 配置 | 活跃会话 | `/ping` | 备注 |
  |---|---|---|---|
  | 不设 `udp_max_sessions` | 顶到额度 | 取不到（含 `/metrics`） | 洪水期间整台不可观测 |
  | `udp_max_sessions 32` | 32 | 200 | 568 次挡在门外，记 `role="session_cap"` |

  UDP 监听没设上限而同一进程里又有七层监听时，启动日志会给一条告警说明这件事。
- 同一端口号上的 TCP 与 UDP 互不干扰（`listen 18613;` 与 `listen 18613 udp;` 可以并存）。
- 数据报边界：0 字节与 65000 字节都能原路往返；单个数据报上限 65535，每会话入向队列 256，
  队列满即丢并记 `role="queue_full"`。
- 本机回环上的实测延迟：p50 0.25 ms、p99 0.86 ms（一问一答，三轮回归里都稳定在这个量级）。
  心跳路径的判定是**计数守恒**而不是速率：3 万个数据报全部到达后端、
  `datagrams_in == forwarded + dropped` 严格成立；速率同一份代码从 ≈58k pps（空载单跑）到
  ≈3.9k pps（在全量回归的负载里跑）都出现过，所以它只能按机器读，容量规划要用自己机器的数。
- 能力边界：`listen … udp` 不能配 `ssl_preread`/`sni_match`（数据报会乱序、会丢失，从半条
  ClientHello 里取 SNI 不是安全操作），也不能写在 HTTP 的 `listen` 上（那里 UDP 只有 QUIC）。
  两种写法都在 `-t` 直接失败。

---

## 8. 灰度发布（canary）

### 8.1 最小可用配置

```nginx
upstream stable { server 10.0.0.11:8080; }
upstream beta   { server 10.0.0.12:8080; }

canary $release "${cookie_uid}${remote_addr}" {
    cookie beta=1 beta;          # cookie beta 的值等于 1 -> beta
    cookie preview beta;         # 只要求 cookie preview 存在且非空
    header X-Channel=Vip beta;   # header 精确匹配（名字大小写不敏感）
    arg ver=beta beta;           # query 参数精确匹配
    ua ~* (Firefox|Edg) beta;    # UA 正则，~* 忽略大小写
    os ios beta;                 # windows/macos/linux/android/ios/other
    percent 10 beta;             # 其余用户里 10% 进 beta（粘性哈希）
    default stable;              # 必填
}

server {
    listen 127.0.0.1:8080;

    location / {
        proxy_pass http://$release;
        proxy_set_header X-Split $proxy_split;
        proxy_set_header X-Split-Served $proxy_split_served;
    }
}
```

语义：

1. 条件按声明顺序匹配，**第一条命中生效**；条件都未命中才进入 `percent`，最后落到 `default`。
2. 粘性键是第二个参数（缺省 `${remote_addr}`）。`"${cookie_uid}${remote_addr}"` 表示同一用户
   换网络也可能换档；只用 `$remote_addr` 会让 NAT 后所有用户共用一档。
3. `percent` 是稳定哈希，不是随机数；同一键永远同一档。
4. 版本落点必须是已声明的 `upstream` 名或写死的 `host:port`，不能是变量/带路径；`-t` 会拒绝
   无法枚举的配置。
5. `default` 缺失、版本名拼错、`proxy_split_failover` 退到未声明的版本，都会让 `-t` 失败。

### 8.2 版本整体不可用时的改投

```nginx
canary $release "${cookie_uid}${remote_addr}" {
    percent 20 beta;
    default stable;
}

location / {
    proxy_pass http://$release;
    proxy_split_failover on;              # 默认：候选顺序里下一路
    # proxy_split_failover off;           # 实验不串台：502 就是 502
    # proxy_split_failover http://stable; # 只退到 stable（必须已声明）
}
```

- 改投只发生在“选中的版本没有任何可连接节点”时；后端返回 5xx 不会跨版本改投。
- `$proxy_split` = 比例/条件选中的版本；`$proxy_split_served` = 实际接走请求的版本。缓存命中
  时后者为空（请求没有交给任何节点）。
- 灰度与缓存天然按目标隔离：每个版本的响应各自成条目，不会把 beta 的页面喂给 stable 用户。

### 8.3 观测与推进节奏

```bash
curl -s http://127.0.0.1:8080/metrics | grep onrouter_proxy_split
```

- `onrouter_proxy_split_targets_total{split,target}`：实际落到各版本的数量，用增量比值对照声明
  比例；
- `onrouter_proxy_split_total{split,role}`：`routed` 正常、`bled` 改投、`down` 选中版本无节点、
  `empty` 落到空目标。

建议 1% → 5% → 20% → 50% → 100%，每一档至少观察一个业务高峰时长；同时对比两个版本的错误率、
P99 与缓存命中率。回滚只需把 `percent` 改成 0 或删掉对应条件，热重载即可生效。

---

## 9. 缓存与 Still ONLine

### 9.1 proxy_cache

```nginx
proxy_cache_path logs/cache keys_zone=pages:64m;                     # 纯内存（默认）
proxy_cache_path logs/cache_disk keys_zone=big:64m disk=on max_size=2g;  # 冷层：path 就是目录

location /api/ {
    proxy_cache pages;
    proxy_cache_valid 200 30s;
    proxy_cache_lock on;
    proxy_cache_revalidate on;
    proxy_cache_use_stale error timeout updating http_502 http_503;
    proxy_pass http://app;
}
```

- 区容量按 **128 B/条目** 估算；`64m` ≈ 52 万条（键+元数据，响应体另计）。容量不够时按 LRU
  淘汰，`keys_zone` 过小会表现为命中率上不去而不是报错。
- 不写 `disk=on` 时缓存**完全在内存**：`proxy_cache_path` 的路径只是一个名字，目录都不会被创建，
  进程重启即清空。写了 `disk=on` 之后，路径成为该区的磁盘冷层，语义与 `lua_shared_dict disk=`
  同源：被 `keys_zone` 容量挤出去**且还没过期**的响应异步落盘（每区一个写线程，temp+rename，
  条目自描述带 CRC），下次同 key 请求从冷层读回并提升进内存，重启靠扫目录重建索引。
- 冷层不是 nginx 那种全量写盘缓存：**只在内存淘汰时才写**。留在内存里的对象不在磁盘上，所以
  重启能救回的是"上次运行中被挤出去过的那批"。要更大的热集合请加大 `keys_zone`，
  而不是指望 `max_size`。`min_free_size=` / `use_temp_path=` 尚未实现，`-t` 会点名告警。
- 落盘与冷读都不占请求线程：请求路径最多付一次"序列化 + 入队"，写文件在后台。`max_size` 满时
  新的落盘直接被拒（`spill_skipped`），等后台按分数逐出，绝不把淘汰路径变成阻塞 IO。
- 什么值得落盘由 `spill_after`（默认 1）决定：`proxy_cache_learning` 开着时这个数就是草图里的
  频率估计，与内存准入同一口径，扫库式一次性 URL 既进不了内存也写不了磁盘。单条超过
  `max_value`（默认 4 MiB）的响应留在内存，不落盘。
- 把 `disk=on` 改回关闭**不会**删掉目录里已有的条目文件，只是从此不再读写它；下次再打开同一目录，
  旧条目会按 TTL/`inactive` 被继续回收。要彻底清干净请在停服时自己删目录。
- 冷命中在 nginx 的词表里仍然是 `X-Cache-Status: HIT`（不新增状态词，免得客户端与前置代理的
  判断逻辑被我们改宽度），层级另用一个头 `X-Cache-Tier: disk` 说出来；账在
  `onrouter_proxy_cache_disk_*`。磁盘条目坏掉（CRC 不符、截断、版本不认识）一律**按未命中处理并回源**，
  计入 `corrupt`，绝不会把坏数据拼成响应发出去。
- 新鲜度优先取上游 `Cache-Control`/`Expires`；上游没给提示才用 `proxy_cache_valid`。带
  `Set-Cookie` 的响应默认不缓存。
- `proxy_cache_lock` 合并同键并发回源；对热点 key 的缓存击穿很有效。
- `proxy_cache_revalidate on`：条目过期后不再直接重取整份，而是带上**缓存自己**的
  `ETag`/`If-Modified-Since` 去问一次；上游答 304 就只重算有效期、把存下来的 body 原样发回，
  响应头是 `X-Cache-Status: REVALIDATED`。省的是上游第二次传 body 的带宽与时间，
  **不省**那次往返 —— 上游仍然被问了一次，所以别把它当"过期也不回源"用（那是
  `proxy_cache_background_update`，还没实现，原因见能力矩阵 §5）。
- 用了 revalidate 就要知道一件事：这条路径上客户端自带的 `If-None-Match` / `If-Modified-Since`
  会被替换掉。"我们缓存里的副本没变"和"你浏览器里的副本没变"是两件事，混在一个条件请求里
  就会把 304 发给没带对副本的客户端。客户端自己做协商时，请让请求绕过缓存
  （`proxy_cache_bypass`）或别开 revalidate。
- 304 里没有的头**不会被删掉**：`content-type` 这类描述 body 的头在 304 里通常缺席，
  合并规则是"304 出现过的名字覆盖旧值，其余原样保留"。
- 每个经过缓存的响应带 `X-Cache-Status`，并计入 `onrouter_cache_requests_total{status}`：
  `MISS` / `HIT` / `EXPIRED` / `STALE` / `BYPASS`。`BYPASS` 也包括“回源了但按规则不存”。

排障“为什么没有 HIT”：

1. 上游发了 `Cache-Control: no-store/private/no-cache/max-age=0`；
2. 响应带 `Set-Cookie`；
3. 方法是 POST（默认只缓存 GET/HEAD）；
4. `proxy_cache_bypass`/`proxy_no_cache` 命中；
5. 缓存键里带了每次变化的变量；
6. 响应体超过单条预算或 zone 太小被很快淘汰。

### 9.2 缓存与 WASM 过滤器

响应过滤器（header/body filter）启用时，缓存里存的是**上游原始响应**，每次给客户端发送时再
套一遍过滤器。这样 MISS/HIT/STALE 看到的是同一份变换结果，不会出现“第一次 MISS 改写、第二次
HIT 再改写一次”的双重变换。代价是命中时仍要付出过滤器 CPU。

### 9.3 Still ONLine：最后已知好副本

```nginx
still_online_zone lkg 32m;

location /catalog/ {
    still_online lkg;
    still_online_max_age 7d;        # 超过则不再展示
    still_online_max_body 1m;       # 超过则不收（不截断）
    still_online_retry 5s;
    still_online_retry_max 300s;
    still_online_retry_deadline 600s;
    proxy_pass http://app;
}
```

当上游不可达或返回 5xx 时，重放该 location 最后一份成功的匿名 GET 响应，带
`X-Still-Online: stale` 与 `Age`。恢复时后台重新抓取，走完整路由/ACL/限流链路。

硬规则（没有开关可以关闭）：

- 含 `Set-Cookie` 的响应永不存入，也永不重放；
- 带 `Cookie`/`Authorization` 的请求默认既不写副本也不读副本；
- `still_online_allow_credentials on` 只打开“读”的一侧，不会让带凭证的响应被存下来。

这是“降级展示”而不是“会话兜底”：登录态页面不会从共享副本里被喂给另一个用户。

---

## 10. WASM 插件

### 10.1 配置

```nginx
wasm_plugin authz wasm/authz.wat;
wasm_plugin hf     wasm/header_filter.wat fuel=2000000 memory=4m;

server {
    location /api/ {
        access_by_wasm authz;
        header_filter_by_wasm hf;
        body_filter_by_wasm hf;
        proxy_pass http://app;
    }
}
```

- 支持 `.wasm` 与文本 `.wat`；模块在 `-t`/启动时编译一次，请求期只实例化。
- 每个插件可设置 `fuel=<N>`（指令预算，默认 10,000,000）与 `memory=<size>`（线性内存上限，
  默认 16 MiB，最低 64k）。
- 单份配置最多 256 个插件；同名重复声明、路径不存在、选项拼错、模块缺少所引用阶段的导出，
  都会让 `-t` 直接失败。
- 插件可以被多个 location 共用；`access_by_wasm` 等指令可写在 server 或 location 级。

### 10.2 阶段语义

| 指令 | 导出函数 | 返回值 | 行为 |
|---|---|---|---|
| `access_by_wasm` | `on_access` | 0 / 1 | 0 继续；1 就地响应（默认 403，可用 `host_set_status`/`host_set_body` 改） |
| `header_filter_by_wasm` | `on_header_filter` | 0 / 1 | 0 继续；1 丢弃响应体 |
| `body_filter_by_wasm` | `on_body_filter` | 0 / 1 | 0 继续；1 丢弃响应体 |

插件 trap、越界、fuel 耗尽时**失败关闭**：请求返回 500，不会静默跳过“本该加安全头/删内部头”
的插件。响应过滤器看到的是完整缓冲后的响应；启用过滤器会关闭该 location 的流式代理，静态文件
超过 8 MiB 时跳过过滤器并告警。

### 10.3 宿主 ABI

模块导入 `env`，指针都是 guest 线性内存偏移：

| 导入 | 说明 |
|---|---|
| `host_log(level, ptr, len)` | 0=info 1=warn 2=error |
| `host_read_len(kind, name_ptr, name_len) -> i32` | 数据长度，不存在返回 -1 |
| `host_read_into(kind, name_ptr, name_len, dst, cap) -> i32` | 拷入 guest 缓冲，返回实际字节数 |
| `host_header_count(kind) -> i32` | kind 4/5 的头数量 |
| `host_header_name_len(kind, idx) -> i32` | 第 idx 个头名字长度 |
| `host_header_name_read(kind, idx, dst, cap) -> i32` | 读第 idx 个头名字 |
| `host_status() -> i32` | 当前响应状态码 |
| `host_set_status(code)` | 改写响应状态码 |
| `host_set_header(kind, name, value) -> i32` | kind 4=请求头 5=响应头 |
| `host_del_header(kind, name) -> i32` | 删除同名头，大小写不敏感 |
| `host_set_body(ptr, len) -> i32` | 改写/生成响应体 |

`kind`：0=方法 1=路径 2=query 3=客户端地址 4=请求头 5=响应头 6=请求体 7=响应体。
请求头/响应头的值通过 `host_read_into` 读取（`kind` 传 4/5，`name_ptr/name_len` 传头名）。
访问阶段改写的请求头会随请求转发到后端；响应过滤器改写的头/体只影响回给客户端的副本。

### 10.4 观测与边界

```bash
curl -s http://127.0.0.1:8080/metrics | grep onrouter_wasm
```

- `onrouter_wasm_invocations_total{plugin,phase}`
- `onrouter_wasm_errors_total{plugin,phase}`（trap、越界、预算耗尽）
- `onrouter_wasm_fuel_exhausted_total{plugin,phase}`
- `onrouter_wasm_denied_total{plugin}`（access 阶段直接响应）

WASM 是**受控执行环境**，不是完整沙箱：它没有 WASI、文件、网络导入，只能通过上表宿主函数
接触请求/响应；但插件文件本身来自磁盘，必须与配置同权限保护，不能允许业务用户上传任意模块。
`body_filter` 会把整个响应体读进内存再改写，大响应场景要评估每请求内存峰值。

完整可运行示例见 `conf/wasm/`、`conf/wasm_e2e.conf` 与 `tools/wasm_e2e.py`（23 项断言）。

---

## 11. Lua 和容量预算

Lua 5.4（mlua）通过 `*_by_lua` / `*_by_lua_file` 接入，覆盖 rewrite/access/content/header/body
等阶段，提供 `ngx.*` API、共享字典、cosocket、定时器、子请求等；完整列表见 README 的
“Lua API”一节。运维侧只需记住：

- `lua_slice_instructions` 控制协程被抢占的指令间隔（默认 1,000,000），防止死循环卡死进程；
- `lua_shared_dict <name> <size>;` 的容量是硬预算，写满后由脚本决定淘汰策略；
- `lua_package_path` 决定 `require` 的搜索路径；
- 每个请求的 Lua 执行仍在工作线程内，CPU 密集型脚本会直接吃掉网关吞吐。

三类预算的规划建议：

| 资源 | 典型值 | 估算方法 |
|---|---|---|
| WASM 单请求内存 | 64k~4m | 插件线性内存上限；同时并发数 × 上限是峰值上界 |
| WASM 单请求 fuel | 10 万~1000 万 | 在 `-t` 后压测；`fuel_exhausted` 非零说明预算太小或插件有死循环 |
| 响应过滤器缓冲 | 最大响应体 | 启用 header/body filter 后每请求按响应体大小占用；静态文件上限 8 MiB |
| proxy_cache | keys_zone 大小 | 128 B/条目 + 响应体；按热点数据量规划 |
| Still ONLine | zone 大小 | 按每个 location 一份最后副本 × 响应体大小估算 |

CPU 密集的鉴权/签名建议放在后端；网关内适合做轻量头处理、路由改写和拒绝。

---

## 12. 可观测性

### 12.1 暴露指标

ONRouter 不自动占用 `/metrics`，需要显式声明，并建议加访问控制：

```nginx
server {
    listen 127.0.0.1:8080;

    location = /metrics {
        allow 127.0.0.1;
        deny all;
        content_by_rust metrics;
    }
}
```

Prometheus：

```yaml
scrape_configs:
  - job_name: onrouter
    metrics_path: /metrics
    static_configs:
      - targets: ["10.0.0.10:8080"]
```

常用指标族：

| 指标 | 用途 |
|---|---|
| `onrouter_uptime_seconds` | 进程存活 |
| `onrouter_connections_accepted` / `_active` / `_capacity` | 连接水位 |
| `onrouter_http_requests_total` / `onrouter_http_responses_total` | 请求量与状态码分布 |
| `onrouter_cache_requests_total{status}` | MISS/HIT/EXPIRED/STALE/BYPASS |
| `onrouter_proxy_cache_disk_{entries,bytes,value_bytes,capacity_bytes,pending_jobs,pending_bytes}` | 各区冷层的体量与排队情况（没开 `disk=on` 时整族不输出） |
| `onrouter_proxy_cache_disk_operations_total{zone,op}` | `spill`/`spill_skipped`/`cold_hit`/`promote`/`evict`/`expire`/`corrupt`/`cold_error`/`never_read`/`warm_recovered` |
| `onrouter_upstream_*` | 节点可选性（`server_available`）、主动检查、失败、懒探测、熔断 |
| `onrouter_proxy_split_*` | 灰度落点与改投账本 |
| `onrouter_wasm_*` | 插件调用、失败、fuel 耗尽、拒绝 |
| `onrouter_tls_handshake_failures_total` | TLS 握手失败 |
| `onrouter_limit_rejections_total` | 限流/限连拒绝 |
| `onrouter_access_log_dropped_total` | 日志丢弃（磁盘告警） |
| `onrouter_still_online_*` | 副本区条目/字节/待恢复任务 |
| `onrouter_dict_disk_{entries,bytes,value_bytes,capacity_bytes,pending_jobs,pending_bytes}` | `lua_shared_dict … disk=<目录>` 各区的冷层体量与写盘排队（没配 disk= 的区不输出） |
| `onrouter_dict_disk_operations_total{dict,op}` | 共享字典冷层的 `spill`/`cold_hit`/`promote`/`evict`/`expire`/`corrupt`/`cold_error` 等逐操作计数 |
| `onrouter_stream_udp_{datagrams,bytes,forwarded,responses}_total` | 四层 UDP 的进/出账：收到多少数据报、转发多少、后端回了多少 |
| `onrouter_stream_udp_sessions_total` / `_sessions_active` | 会话累计与当前活跃（一条会话=一个 fd，长期不回落就是 `proxy_timeout` 配长了） |
| `onrouter_stream_udp_dropped_total{role}` | 丢包原因：`no_permit`（连接额度耗尽）/`queue_full`（会话队列满）/`send_failed`（后端发送失败）/`session_cap`（撞上 `udp_max_sessions`） |

建议告警：

- 5xx 比例突增；
- `upstream_server_available == 0` 持续超过一个 `fail_timeout` / `lazy_rejoin` 周期；
- `upstream_server_healthy == 0` 持续超过一个主动探测周期（仅配置了 `health_check` 时）；
- `circuit_state == 2` 持续；
- `wasm_errors_total` / `fuel_exhausted_total` 增长；
- `wasm_denied_total` 快速增长（可能是鉴权策略误伤或攻击）；
- `connections_active / capacity > 0.8`；
- `access_log_dropped_total` 增长。

### 12.2 启动日志

进程启动时会打印：

- 监听地址与 server 列表；
- worker 线程数与亲和性计划；
- upstream 的 `least_time`/韧性摘要；
- 灰度分流、WASM 插件、学习表、调度窗口的逐条说明；
- `/metrics` 提示。

把启动日志收进日志平台；线上事故里“配置改过但没生效”通常能在启动横幅与 `-t` 告警之间对上。

---

## 13. 性能与稳定性验证

### 13.1 本机压测口径（1.0.2）

仓库内提供：

```bash
# 单元测试
cargo test --workspace

# 特性 E2E（真实端口 + 真实后端）
python tools/canary_e2e.py        # 22 项
python tools/wasm_e2e.py         # 23 项
python tools/resilience_e2e.py   # 17 项
python tools/affinity_e2e.py     # 7 项
python tools/proxy_split_e2e.py  # 76 项
python tools/proxy_disk_e2e.py   # 39 项（响应缓存磁盘冷层）
python tools/proxy_cache_e2e.py  # 21 项（含 proxy_cache_revalidate 的 R1–R8）
python tools/set_if_e2e.py       # 34 项（含 server 级 REWRITE 的 S16–S23）
python tools/limit_key_e2e.py    # 35 项（限流按头/Cookie/参数分桶；全部同 IP，换键必换桶）
python tools/expires_e2e.py      # 42 项（expires 各写法在静态/反代/缓存/Lua/流式/return 上的落头，含 4 条 -t 否决）
python tools/herd_e2e.py         # 18 项（惊群：热点 key 到期、锁、冷层过期、同键 200 并发限流）

# 业务形状（不是指令清单，判的是业务底线）
python tools/course_selection_e2e.py --students 2400 --conc 240   # 选课开放：不超卖、源站报名数==网关放行数
python tools/flash_sale_e2e.py                                   # 大促/闪购（36 项）
python tools/game_udp_e2e.py                                     # 游戏服务器 UDP（31 项）
python tools/quic_business_e2e.py                                # 同一站点 over h1/h2/h3 的跨传输一致性（41 项）
python tools/production_shape_e2e.py                               # 800 文件静态站 + WASM + Lua 同进程（529 项）
python tools/https_matrix_e2e.py                                # 多域名单端口 TLS：证书按 SNI、站点按 Host（76 项，含 default_server 写在最后的 18449 组）
python tools/random_scenarios_e2e.py --iters 20                 # 随机拓扑对撞（每轮换一份配置：端口聚合/别名/正则/rewrite/L4 SNI），20 轮 4122 项

# 教程示例本身的核对（文档里那几行配置照抄能不能得到同样结果）
python tools/tutorial_limit_check.py                             # §12 的 17 项（含 rate/burst/队列实测值）

# 稳定性压测：默认 20 分钟，混合反代/缓存/WASM/Lua/静态流量；发布口径跑 21 分钟
cargo build --release -p onrouter-server --bin onrouter
python tools/soak_test.py --minutes 21
```

TLS 套件的证书夹具由 `tools/selfsigned.py` 现造（每套件一个目录，入口先 `ensure()`）。
约定来自一次只在 CI 复现的红：`production_shape` 的配置读的是别套件的 `certs_random/`，
那个目录在 `.gitignore` 里，干净检出根本不存在，本机却因为跑过 `random_scenarios` 而一直藏着
一份。两条约束写在 `selfsigned.py` 里：`openssl req -x509` 默认给自签证书打 `CA:TRUE`，
rustls 会拒绝把它当末端证书（`CaUsedAsEndEntity`），而 h3 客户端正是拿这张证书当自己的受信根；
SAN 必须包含连接用的名字，QUIC 强制校验。


`soak_test.py` 的结论口径：

- 预热期（默认前 5 分钟）不计入趋势，让缓存、线程池、分配器达到稳态；
- 采 Windows `PrivateUsage` / Linux `RssAnon` 作为私有内存；
- 预热后私有内存增长超过 48 MiB **且** 回归斜率超过 1 MiB/min，判为疑似泄漏；
- 增长率超过 72 MiB，或结束值超过基线 2 倍且增长超过 32 MiB，判为失败；
- 请求失败率超过 0.2%（且至少 50 个）或请求量过低，也判失败；
- 报告写入 `target/soak_report.json`、`target/soak_samples.csv`、`target/soak_metrics_end.txt`。

本机 21 分钟运行的实测记录见 `target/soak_console.log`（随本次发布生成）。不同硬件/后端下
吞吐不同，看趋势而不是看绝对值。

1.0.0 发布前实测（Windows，18 逻辑核，24 短连接 + 4 keep-alive worker）：

| 指标 | 数值 |
|---|---|
| 结论 | **PASS**（`failures` 为空） |
| 实际时长 / 平均吞吐 | 20.92 min / 2064.7 req/s |
| 请求总数 / 回源请求 | 2,591,305 / 1,963,093 |
| 私有内存 | 20.11 MiB → 21.97 MiB（+1.86 MiB，峰值 22.15 MiB） |
| 私有内存斜率 | +0.067 MiB/min（阈值 1.0，预热后 192 个样本） |
| RSS | 28.52 MiB → 29.98 MiB |

同配置的首次 21 分钟运行（保留为 `target/soak_report_run1.json`）同样 PASS：
2,787,193 请求、0 失败、私有内存 17.89 → 20.08 MiB（+2.19 MiB，斜率 +0.163 MiB/min）。
两次运行的涨幅都在噪声量级，且没有随请求量单调上涨，可以排除持续泄漏。

1.0.1 加了响应缓存磁盘冷层，压测口径跟着改：`conf/soak.conf` 现在带一个
`keys_zone=soakcold:1k disk=on`（8 条内存容量）配 256 个循环键的 `/cold` 路径——
原来的 4m 区装得下 512 个键、根本不会淘汰，"压测通过"对新代码不构成证据。这一轮：

| 指标 | 数值 |
|---|---|
| 结论 | **PASS**（`failures` 为空） |
| 实际时长 / 平均吞吐 | 20.92 min / 1778.1 req/s |
| 请求总数 / 失败 / 回源 | 2,231,814 / **0** / 1,696,741 |
| 私有内存 | 18.58 MiB → 19.29 MiB（+0.71 MiB，峰值 21.07 MiB） |
| 私有内存斜率 | +0.021 MiB/min（阈值 1.0，预热后 192 个样本） |
| RSS | 26.08 MiB → 27.85 MiB |
| 冷层账目（结束时） | 落盘 81,723 / 冷命中 80,986 / 提升 80,986 / 索引 256 条 |
| 冷层异常账目 | `spill_skipped` 0、`corrupt` 0、`cold_error` 0、`never_read` 0、`pending_jobs` 0 |

1.0.2 的这一轮（同一口径、同一份 `conf/soak.conf`，跑在发布二进制上）：

| 指标 | 数值 |
|---|---|
| 结论 | **PASS**（`failures` 为空） |
| 实际时长 / 平均吞吐 | 20.92 min / 1812.8 req/s（24 短连接 + 4 keep-alive worker） |
| 请求总数 / 失败 / 回源 | 2,275,361 / **0** / 1,728,933 |
| 私有内存 | 20.47 MiB → 20.96 MiB（**+0.49 MiB**，峰值 22.33 MiB） |
| 私有内存斜率 | +0.055 MiB/min（阈值 1.0，预热后 192 个样本） |
| RSS | 27.77 MiB → 29.20 MiB |
| 冷层账目（结束时） | 落盘 83,363 / 冷命中 82,632 / 提升 82,632；`corrupt` 0、`never_read` 0、`pending_jobs` 0 |

顺带修掉一个会把冷层账目弄脏的压测器缺陷：`soak_test.py` 过去只清 `logs/soak_cache`，
而配置里还有 `logs/soak_cold disk=on`——上一轮留下的 256 个冷层文件会在启动扫描时被记成
`corrupt`，让"异常账目全零"这条证据失真。现在清理目录是从配置里读 `proxy_cache_path` 得到的，
这一轮 `corrupt=0` 才是真意义上的干净。

冷层的落盘量与冷命中量近乎一比一、且 `never_read=0`，说明写下去的都是真被读回来的对象，
不是"往磁盘倾倒垃圾"；`pending_jobs` 收尾归零说明异步写线程没被拖在后面。
这一轮跑的是 1.0.1 的全部改动（冷层 + `proxy_cache_revalidate` + server 级 REWRITE），产物：
`target/soak_report_v101.json`、`target/soak_metrics_end_v101.txt`；冷层单独验证的那一轮（只有冷层）
保留为 `target/soak_report_v101_coldtier.json`，两条曲线一致（+1.07 MiB 与 +0.71 MiB，都在噪声量级）。
全量回归 `python run_regression.py reg_101_roll.txt` → `TOTAL 86 scripts, nonzero=1`：那一条非零是
`smoke_suite.py`（退出码 1，日志里 28/28 通过——脚本自己的退出码判定与断言结果不一致），
在 1.0.2 的同一条上它是 `EXIT 0`，1.0.1 当时到底是断言之外的什么问题没有留下证据，
所以这里记成"当时那条不为零"而不是"全绿"。

1.0.2 的发布闸门跑在最终二进制上：`python run_regression.py reg_102_ship.txt` →
`TOTAL 94 scripts, nonzero=0`（比 1.0.1 多出 `expires`、`limit_key`、`herd`、`game_udp`、
`course_selection`、`flash_sale`、`production_shape`、`quic_business` 这八条业务形状套件；
那时 `random_scenarios_e2e` 还按旧 §13.1 的理由记在 `SKIP` 里）。

**v1.0.2 之后的一批**（兜底证书跟 `default_server`、TLS 夹具自给）把回归重新数过：
`random_scenarios_e2e` 回到 roll 里，套件数 **95**。它的 TLS 预言机原先把"证书按 SNI"与
"站点按 Host/:authority"记成同一件事，而且探针根本没把 SNI 发出去（`HTTPSConnection("127.0.0.1")`
把 IP 当了 SNI），于是证书指纹成片红——红的是夹具，报出来的却是"网关选错站/发错证书"。
三条一起修（预言机按 SNI 单算、探针显式发 SNI、网关兜底证书跟默认 server），
20 轮随机拓扑 4122/4122。`https_matrix` 由 71 条涨到 76 条，多出来的正是"`default_server`
写在最后一个块"那组——只有它能把两种实现分开。

### 13.2 上线前压测建议

1. 用生产同规格机器与同版本二进制；
2. 先跑 5 分钟基线，再逐步加并发到目标 QPS 的 1.5 倍；
3. 观察 `connections_active`、P99、5xx、`wasm_fuel_exhausted_total`；
4. 跑至少 20 分钟，确认私有内存曲线在预热后走平；
5. 做故障演练：杀一台后端、杀全部后端、恢复后端，核对 `lazy_rejoin`/熔断指标与客户端错误率；
6. 做配置回滚演练：改坏配置 → `-t` 失败 → 热重载保留旧配置 → 恢复。

---

## 14. 安全要点

- **TLS**：证书与私钥路径必须可被进程读取；私钥权限 0600。证书原地续期会被热重载检测。
- **管理面**：`/metrics`、`/status` 等 content handler 必须加 `allow/deny` 或只监听内网地址。
- **配置与插件**：配置与 `.wasm` 文件的可写权限等同于网关代码执行权限；不要让业务用户可写。
- **前置代理信任**：使用 `front_proxy` 的 `ip_header`/`proto_header` 时，只有直连对端落在
  `trust`/`set_real_ip_from` 网段内才会采信；否则客户端可伪造 `X-Forwarded-For` 绕过 ACL/限流。
- **Still ONLine**：默认不读写带凭证的请求；不要为了“登录页也能降级”而打开
  `still_online_allow_credentials`，除非你明确接受共享副本被同一用户读到。
- **代理环境变量**：进程启动时会忽略 `HTTP_PROXY`/`ALL_PROXY`，避免后端连接被系统代理劫持。
- **运行用户**：使用非 root 用户；绑定 80/443 可用 `setcap cap_net_bind_service=+ep` 或前置
  LB 转发到高位端口。

---

## 15. 故障排查

| 现象 | 优先检查 | 处理 |
|---|---|---|
| 配置通过但行为没变 | `-t` 的“告警 N 条” | 指令可能拼错或被忽略；按告警逐条修 |
| 启动即退出 | `-t` 退出码、`error_log` | 监听端口占用、证书不可读、引用不存在 |
| 502 | `onrouter_upstream_requests_total{result="failure"}` | 后端连不上、响应非法、或所有节点都在摘除期；看 `healthy` 与熔断状态 |
| 504 | `proxy_read_timeout`/后端日志 | 后端慢；不要用增大超时掩盖容量问题。口径见 7.1：**等满超时才是 504**，同一现象返回 502 说明卡在连接层而不是慢 |
| 浏览器报"证书与域名不符" | `-t` 输出的 `TLS -> […(default)]`、各块的 `ssl_certificate` | 见 5.5：SNI 匹配不上时出示的是该地址**默认 server** 的证书。要么给这个域名补一个带自己证书的站点，要么让 `default_server` 那个块配上通配/兜底证书 |
| 灰度不生效 | `proxy_split_targets_total`、`$proxy_split` 头 | 条件顺序、cookie 名、percent、default |
| 灰度整池挂掉仍 502 | `proxy_split_failover` | 默认 on 会改投；写 off 的实验本来就不串台 |
| 缓存一直 MISS | 上游 `Cache-Control`/`Set-Cookie`、方法、key | 见第 9.1 节排查顺序 |
| WASM 请求 500 | `wasm_errors_total`、`fuel_exhausted_total` | 插件 trap/预算不足；看 `-t` 导出校验 |
| 亲和性没生效 | 启动日志“绑定 CPU 核心” | 容器 cpuset、macOS、掩码越界 |
| 改了 `listen` 不生效 | 热重载只替换路由 | 重启进程 |
| Windows 改配置不生效 | 没有 `reload` 指令 | 加 `reload 2s;` 或重启 |
| 内存缓慢上涨 | `soak_test.py` 报告、缓存/过滤器体量 | 区分缓存填充与泄漏；看私有内存斜率 |
| 日志缺失 | `access_log_dropped_total`、磁盘权限 | 扩容/修复权限；日志目录必须可写 |

收集现场：

```bash
onrouter -V
onrouter -t -c conf/onrouter.conf > /tmp/onrouter-t.txt 2>&1
curl -s http://127.0.0.1:8080/metrics > /tmp/onrouter-metrics.txt
tail -n 200 conf/logs/error.log
```

---

## 16. 升级、回滚与发布检查

### 16.1 从旧版本升上来要做什么

1. 备份当前二进制、配置、证书与插件；
2. 用新二进制对**旧配置**跑 `-t`，确认告警与退出码；
3. 先在灰度实例启动新版本，接入少量流量；
4. 核对启动横幅、`/metrics`、错误日志与核心接口；
5. 全量替换：停旧进程 → 起新进程；有 LB 时先摘流再停，避免连接被重置；
6. 回滚：换回旧二进制 + 旧配置，`-t` 后启动。

1.0.x 各版新增的配置都是**可选**的：`worker_threads`/`worker_cpu_affinity`、`lazy_rejoin`、
`circuit_breaker`、`canary`、`wasm_plugin`、`expires`、`limit_req_queue`、`stream` 里的
`udp`/`proxy_responses`/`udp_max_sessions` 等，不写就不改变原有行为。真正会变的是**校验变严**：
`proxy_split_failover` 与灰度变量、`limit_*_zone` 的 key、`expires` 的取值写错时现在会在 `-t`
阶段失败并点名，而不是线上 500 或静默放行。升级时用新二进制对**旧配置**跑一次 `-t`，
逐条读告警，就是这一版的全部迁移成本。

### 16.2 发布前检查表

- [ ] `cargo audit`（发布闸门之一，不进每次 push 的 CI：一条无关的传递性 unmaintained 公告不该
      拦住一次生产修复，但**必须在打标签之前**把结果写进 `docs/SECURITY_AUDIT.md`——
      是"受影响、已升级"还是"结构性不受影响（例如运行时无 JIT）"，都要落成一句可核对的话）；
- [ ] `cargo test --workspace` 全绿；
- [ ] `cargo clippy --workspace --all-targets` 无 error；
- [ ] 全量回归 `python run_regression.py <本次发布名>.txt` 记录零非零退出（`run_regression.py`
      顶部的 `SKIP` 集是**唯一**允许"不参与"的地方，往里加一条必须同时写清为什么它的红绿
      不构成证据；当前 `SKIP` 为空）；
- [ ] CI 的三个 E2E 步骤在 Linux 上全绿：功能契约（11 条：canary、wasm、resilience、affinity、
      proxy_split、proxy_disk、limit_key、expires、herd、security_matrix、https_matrix）、业务形状
      （选课/静态站+WASM+Lua/游戏 UDP 共 3 条）、跨传输一致性（`orr-h3check` 探针 + `quic_business` 1 条），
      共 15 条；
- [ ] 21 分钟 soak 通过，私有内存预热后走平；
- [ ] 发布包内二进制的 `-V` 与 `Cargo.toml` 版本一致；
- [ ] 用发布包里的二进制跑 `-t` 与一次真实请求；
- [ ] 备份旧版本，准备回滚命令；
- [ ] 通知值守同学本次变更点与观测指标。

### 16.3 打包

```powershell
# Windows：生成 target\dist\archives\onrouter-v1.0.2-x86_64-pc-windows-msvc.zip
powershell -ExecutionPolicy Bypass -File .\build-release.ps1 build
python tools\release_verify.py
```

```bash
# Linux/macOS：脚本会按本机平台构建并打包
bash build-release.sh
```

GitHub Actions 的 `release.yml` 在推送 `v*` 标签时构建各平台产物并创建 Release；`ci.yml`
在每次 push/PR 跑单元测试与 E2E，`workflow_dispatch` 可额外触发 soak。

正式发布前请人工确认版本号、变更说明与产物哈希；签名/推送标签属于对外操作，需由发布负责人执行。
