# ONRouter 1.0 操作手册

适用版本：**1.0.0**（2026-10-21）
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

1.0 的发布包是“开箱可跑”的完整目录，不只是两个可执行文件：

| 路径 | 用途 |
|---|---|
| `onrouter` / `onrouter.exe` | 网关主程序 |
| `orr-gencert` / `orr-gencert.exe` | 生成自签名证书（测试/内网用） |
| `conf/*.conf` | 示例配置（含 `tutorial_hello.conf`、`tutorial_full.conf`） |
| `conf/wasm/`、`conf/wasm_static/` 等 | WASM 插件与 E2E/教学用静态资源 |
| `lua/`、`public/` | 示例 Lua 脚本与静态站点 |
| `certs/` | 打包时新生成的自签名证书对，供 `conf/onrouter.conf` 的 8443 TLS 演示直接使用 |
| `docs/OPERATIONS.md`、`docs/TUTORIAL.md` | 操作手册与使用教程 |
| `README.md` | 项目说明 |

`certs/` 里的私钥不进入 git，每次打包由 `orr-gencert` 现生成；它只用于开箱验证，
生产环境请按第 5 节替换为自己的证书。`logs/`、`cache/` 等运行时状态**不会**打进包内，
首次启动前需保证对应目录可写。

```bash
# Linux / macOS
tar xzf onrouter-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
cd onrouter-v1.0.0-x86_64-unknown-linux-gnu
install -m 0755 onrouter orr-gencert /usr/local/bin/
onrouter -V
onrouter -t -c conf/onrouter.conf

# Windows PowerShell
Expand-Archive onrouter-v1.0.0-x86_64-pc-windows-msvc.zip -DestinationPath C:\onrouter
cd C:\onrouter
.\onrouter.exe -V
.\onrouter.exe -t -c conf\onrouter.conf
```

解压后目录本身就是推荐布局（`onrouter` 与 `conf/`、`lua/`、`public/` 同级），
直接 `onrouter -c conf/onrouter.conf` 即可启动，教程见 `docs/TUTORIAL.md`。

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
- `wasm_plugin auth conf/wasm/auth.wat;` 应写成 `wasm_plugin auth wasm/auth.wat;`（相对 `conf/`）；
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
- `proxy_cache_path` 的 `keys_zone` 容量、`still_online_zone` 预算（已有条目立即按新上限裁剪）；
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
| `client_header_timeout` / `client_body_timeout` | 读请求头/体的空闲超时 | — |
| `shutdown_grace <t>;` | 优雅停机排空上限 | 30s |
| `reload <t>;` | 配置/证书轮询间隔 | 仅信号 |
| `server_tokens on/off;` | 是否暴露版本 | — |
| `tcp_nodelay on/off;` | TCP_NODELAY | — |
| `accept_backlog <n>;` | listen backlog | — |
| `gzip ...` | 响应压缩 | 关闭 |
| `proxy_cache_path <path> keys_zone=<name>:<size>;` | 内存缓存区 | — |
| `still_online_zone <name> <size>;` | 最后已知好副本区 | — |

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

`max_fails`/`fail_timeout` 是被动健康检查：连接失败/超时累计到阈值后摘除节点，`fail_timeout`
内不再选它。`down` 是人工下线，不参与探测。

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
proxy_cache_path logs/cache keys_zone=pages:64m;   # 仅内存，path 不落盘

location /api/ {
    proxy_cache pages;
    proxy_cache_valid 200 30s;
    proxy_cache_lock on;
    proxy_cache_use_stale error timeout updating http_502 http_503;
    proxy_pass http://app;
}
```

- 区容量按 **128 B/条目** 估算；`64m` ≈ 52 万条（键+元数据，响应体另计）。容量不够时按 LRU
  淘汰，`keys_zone` 过小会表现为命中率上不去而不是报错。
- 缓存完全在内存，进程重启即清空；`proxy_cache_path` 的路径不会写盘，不要把本地磁盘当缓存盘。
- 新鲜度优先取上游 `Cache-Control`/`Expires`；上游没给提示才用 `proxy_cache_valid`。带
  `Set-Cookie` 的响应默认不缓存。
- `proxy_cache_lock` 合并同键并发回源；对热点 key 的缓存击穿很有效。
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
| `onrouter_upstream_*` | 节点可选性（`server_available`）、主动检查、失败、懒探测、熔断 |
| `onrouter_proxy_split_*` | 灰度落点与改投账本 |
| `onrouter_wasm_*` | 插件调用、失败、fuel 耗尽、拒绝 |
| `onrouter_tls_handshake_failures_total` | TLS 握手失败 |
| `onrouter_limit_rejections_total` | 限流/限连拒绝 |
| `onrouter_access_log_dropped_total` | 日志丢弃（磁盘告警） |
| `onrouter_still_online_*` | 副本区条目/字节/待恢复任务 |

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

### 13.1 本机 1.0.0 压测口径

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

# 稳定性压测：默认 20 分钟，混合反代/缓存/WASM/Lua/静态流量
cargo build --release -p onrouter-server --bin onrouter
python tools/soak_test.py --minutes 20
```

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
| 502 | `onrouter_upstream_requests_total{result="failure"}` | 后端不可达/超时；看 `healthy` 与熔断状态 |
| 504 | `proxy_read_timeout`/后端日志 | 后端慢；不要用增大超时掩盖容量问题 |
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

## 16. 升级、回滚与 1.0.0 发布检查

### 16.1 从 0.8.x 升到 1.0.0

1. 备份当前二进制、配置、证书与插件；
2. 用新二进制对**旧配置**跑 `-t`，确认告警与退出码；
3. 先在灰度实例启动新版本，接入少量流量；
4. 核对启动横幅、`/metrics`、错误日志与核心接口；
5. 全量替换：停旧进程 → 起新进程；有 LB 时先摘流再停，避免连接被重置；
6. 回滚：换回旧二进制 + 旧配置，`-t` 后启动。

1.0.0 新增的配置都是**可选**的：`worker_threads`/`worker_cpu_affinity`、`lazy_rejoin`、
`circuit_breaker`、`canary`、`wasm_plugin` 等不写就不改变原有行为。唯一需要注意的是
`proxy_split_failover` 与灰度变量的 `-t` 校验更严格：写错的灰度配置现在会在检查阶段失败，
而不是线上 500。

### 16.2 发布前检查表

- [ ] `cargo test --workspace` 全绿；
- [ ] `cargo clippy --workspace --all-targets` 无 error；
- [ ] 五项 E2E 全绿（canary/wasm/resilience/affinity/proxy_split）；
- [ ] 20 分钟 soak 通过，私有内存预热后走平；
- [ ] 发布包内二进制的 `-V` 与 `Cargo.toml` 版本一致；
- [ ] 用发布包里的二进制跑 `-t` 与一次真实请求；
- [ ] 备份旧版本，准备回滚命令；
- [ ] 通知值守同学本次变更点与观测指标。

### 16.3 打包

```powershell
# Windows：生成 target\dist\archives\onrouter-v1.0.0-x86_64-pc-windows-msvc.zip
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
