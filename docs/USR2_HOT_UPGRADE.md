# USR2 热升级：可行性分析与落地设计

> 状态：**未实现**。本机为 Windows（无 USR2、无 WSL/Docker、未安装 Linux 构建目标），
> 无法对 Unix 进程/FD 继承做任何真实验证，因此没有把不可测试的 `cfg(unix)` 代码合入。
> 本文给出差距、两条可选方案、改动清单与可执行的 Linux 验证计划。

## 1. nginx 的 USR2 做了什么

nginx 是 master/worker 多进程模型，监听 socket 由 master 持有：

1. master 收到 `USR2`，把 `nginx.pid` 改名为 `nginx.pid.oldbin`；
2. master `exec` 新的 nginx 二进制（新 master 通过环境变量 `NGINX` 继承监听 FD）；
3. 新 master 用继承的 FD 起新 worker，与旧 worker **同时 accept**；
4. 新版本稳定后，向旧 master 发 `WINCH`（旧 worker 停止 accept、处理完存量后退出）；
5. 旧 master 收到 `QUIT` 退出。任一步失败可回滚到旧 master。

关键点不是信号本身，而是 **监听 FD 的所有权可以跨进程传递**，且存在一个
master 进程负责编排。

## 2. ONRouter 现状与阻塞点

| 能力 | 现状 |
|---|---|
| 监听 socket | 由单个进程内的 tokio 任务持有（`server::bind_listener` + accept loop） |
| 进程模型 | 单进程、多线程（16 个 Lua VM / 18 个 worker 线程），无 master/worker 拆分 |
| 配置热重载 | ✅ 已支持：`SIGHUP` 或 `reload <interval>;` 原子替换路由表，监听不重绑 |
| 优雅停机 | ✅ `SIGTERM/SIGINT` + `shutdown_grace`，存量连接排空后退出 |
| Windows | 无 `SIGUSR2`；`WSADuplicateSocket` 语义与 Unix FD 继承不同，无法按同一套代码实现 |

因此“在现有进程里加一个 SIGUSR2 分支”不够：新二进制必须拿到**同一组监听 FD**
（或通过 `SO_REUSEPORT` 重新绑定），旧进程还必须停止 accept 并排空。
这需要跨进程的所有权移交，属于架构级改动。

## 3. 方案 A：SO_REUSEPORT 新旧并行（推荐，改动较小）

适用于当前单进程模型，Linux 3.9+ / macOS 支持，Windows 不支持。

### 流程

```
旧进程 (pid P1, 持有监听)                新进程 (pid P2)
  │ SIGUSR2                                 │
  ├─ spawn 自身 exe, 继承环境变量 ──────────▶│ 启动，绑定相同端口
  │   ONROUTER_UPGRADE=1                    │ (SO_REUSEPORT 允许同 UID 多绑定)
  │   ONROUTER_READY_FD=<pipe write fd>     ├─ 全部监听 bind 成功
  │                                         ├─ 写 readiness 管道
  ├─ 读到 ready                             │
  ├─ 停止 accept（关闭监听/退出 accept 循环）│ 继续 accept（内核在两组 socket 间分流）
  ├─ 等待在途请求 ≤ shutdown_grace          │
  └─ 退出，释放旧监听                        └─ 成为唯一服务进程
```

### 必要改动

1. **监听标志**（`crates/onrouter-server/src/server.rs::bind_listener`）
   - Unix 下在 `bind()` 前设置 `SO_REUSEPORT`（`socket2::Socket::set_reuse_port`）；
   - Windows 保持现状。注意：`SO_REUSEPORT` 必须在**所有**绑定同一端口的进程上设置，
     所以旧进程从第一次启动起就要带上该标志（不能只在升级时加）。
2. **信号**（`crates/onrouter-server/src/main.rs::spawn_signal_handlers`）
   - 增加 `SignalKind::user_defined2()`；收到后调用升级协调器，而不是停机。
3. **升级协调器**（新模块 `upgrade.rs`，`cfg(unix)`）
   - `Command::new(current_exe)` 带上原 `-c` 参数与 `ONROUTER_UPGRADE=1`；
   - 建 pipe，把写端 FD 通过环境变量交给子进程（`pre_exec` 清 CLOEXEC）；
   - 等待 ready 或子进程退出：子进程先退出 → 保持旧进程服务（自动回滚）；
   - ready 后触发“停止 accept”，复用现有 `watch` 停机信号做请求排空；
   - `pid` 文件交接：新进程写自己的 pid，旧进程退出时不得删除新 pid 文件。
4. **accept 循环的“只停 accept、不停连接”**（`server.rs`）
   - 现有 `watch<bool>` 是整进程停机语义；需要额外的 `stop_accepting` 通知，
     让监听任务退出但连接任务继续，直到排空。
5. **失败处理**
   - 新进程 bind 失败（无 `SO_REUSEPORT`、端口被非合作进程占用）→ 写错误到管道并退出，
     旧进程记录告警继续服务；
   - 升级中再次收到 USR2 → 忽略并告警。

### 局限

- 升级窗口内新旧进程同时 serve，旧进程上的长连接/keepalive 会继续工作到排空；
- 不允许跨 UID 升级；容器内需要 `net.ipv4.ip_unprivileged_port_start` 等权限；
- 内核在 reuseport 组内的分流不保证均匀（对存量短连接影响可忽略）；
- 仅 Unix 可用；Windows 仍需“停-起”窗口（可用负载均衡器蓝绿规避）。

## 4. 方案 B：nginx 式 master/worker + FD 继承（彻底，但改动大）

1. 引入 master 进程：只负责 bind、spawn worker、信号编排；
2. worker 通过 `SCM_RIGHTS` 或 `exec` 继承的 FD 创建 `TcpListener`（`from_raw_fd`）；
3. USR2 时 master `exec` 新二进制并传递 FD 列表（如 `ONROUTER_FDS=3:0.0.0.0:8080,...`）；
4. 旧 master 保留旧 worker，按 WINCH/QUIT 逐步退出，失败可回滚。

优点是与 nginx 语义、运维脚本完全一致；缺点是要重写生命周期、pid、日志、
共享字典（跨进程共享内存）等，工作量以周计，且同样只能在 Unix 上验证。

## 5. 验证计划（Linux）

在拿到 Linux 主机/CI 后，按以下门槛验收（缺一不可）：

```bash
# 1) 构建
cargo build --release -p onrouter-server --bin onrouter

# 2) 起服务，持续压测（记录每个请求的结果）
seq 1 200000 | xargs -P 16 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:8080/bench/hello > /tmp/upgrade_codes.txt &
LOAD=$!

# 3) 用新二进制替换磁盘上的可执行文件（模拟升级）
cp target/release/onrouter /tmp/onrouter.new
kill -USR2 "$(cat conf/logs/onrouter.pid)"

# 4) 等 2s，确认：新 pid 存活、旧 pid 退出、无 5xx/连接错误
sleep 2
kill -0 "$(cat conf/logs/onrouter.pid)"
grep -Ev '^200$' /tmp/upgrade_codes.txt | wc -l    # 期望 0
wait $LOAD
```

附加用例：

- 新二进制启动失败（如配置错误/bind 失败）→ 旧进程仍返回 200，日志有回滚告警；
- 升级期间保持 100 条 keepalive 长连接，升级后旧连接上的请求仍成功；
- 连续两次 USR2 不产生孤儿进程；`ps` 中只有一个服务进程；
- 回滚：升级后发 `SIGHUP` 加载新配置失败，旧路由表仍生效（现有能力）。

## 6. 结论

- **可行性**：方案 A 可行，预计 1–2 天实现 + Linux 验证；方案 B 需要多进程重构，1–2 周。
- **当前决定**：先不写无法验证的 Unix 代码；在 Linux CI 可用后按方案 A 落地。
- **运维注意**：当前版本**没有注册 SIGUSR2**，不要发送该信号——Unix 的默认动作是
  **终止进程**。二进制升级请使用滚动重启/前置负载均衡。
- **近期替代**：滚动重启 + 前置负载均衡（或 DNS 权重切换）可获得可接受的发布窗口；
  配置/脚本层面的变更继续用已支持的 `SIGHUP` 热重载，无需重启。
