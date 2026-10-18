# Linux A/B 基线（ONRouter vs OpenResty）

> 状态：**未采集**。当前机器是 Windows，未安装 WSL/Docker，Rust 只装了
> `x86_64-pc-windows-msvc` 目标，无法运行 Linux 侧压测。
> 仓库已提供可复现脚本：`tools/linux_ab.sh`（渲染 `tools/openresty_bench.conf.tmpl`
> 到临时前缀，不写系统目录）。

## 为什么必须在 Linux 上重跑

Windows 版 nginx 只有 `select()` 事件模型且 worker 数受限，ONRouter 则是 tokio
多线程 + 16 个 Lua VM。因此 Windows 上的对比只能回答“两个 Windows 构建谁更快”，
不能代表生产环境（Linux epoll）的差距。`bench_ab.py` 的输出里也打印了同样的口径提示。

## 运行方法

```bash
# 依赖：Linux、cargo、python3、OpenResty（lua-nginx-module 已内置）
sudo apt install -y python3 build-essential   # 示例
# 安装 OpenResty：https://openresty.org/en/linux-packages.html

tools/linux_ab.sh
# 自定义：
SWEEP=1,4,8,16 REQUESTS=30000 tools/linux_ab.sh
OPENRESTY_NGINX=/usr/local/openresty/nginx/sbin/nginx tools/linux_ab.sh
```

脚本行为：

1. `cargo build --release -p onrouter-server --bin onrouter`；
2. 把 OpenResty 配置模板渲染到 `.bench_openresty/conf/bench.conf`；
3. 用 `OPENRESTY_DIR=.bench_openresty` 启动 OpenResty（`-p` 临时前缀）；
4. 跑 `bench_ab.py --sweep ... --json bench_linux_ab.json`；
5. 退出时 `nginx -s quit` 清理。

## 采集要求（否则数据不可比）

- 机器空闲（无其它压测/编译/容器），CPU 频率策略固定（`cpupower frequency-set -g performance`）；
- 至少重复 3 次，取每个 `(端点, 并发)` 的中位数，并记录极差；
- 先看 `client_ceiling_rps`：若某一侧 rps 接近天花板，增加压测进程/换第二台客户端；
- ONRouter 与 OpenResty 使用同一份 `public/index.html`、同一段 Lua 源码、同一组
  Python 后端（`bench_ab.py` 已保证）；
- 只覆盖 keep-alive GET；TLS、POST、大 body、HTTP/2 需另跑对应 E2E/压测。

## JSON 结构

```json
{
  "levels": [1, 4, 8, 16],
  "client_ceiling_rps": 12345.6,
  "data": {
    "orr|Lua content_by_lua|1": [rps, p50_ms, p99_ms, errors],
    "or|Lua content_by_lua|1":  [rps, p50_ms, p99_ms, errors]
  }
}
```

## Windows 参考数据（仅供本机回归，不作为 Linux 基线）

2026-10-18，Windows 10.0.26300，16 逻辑核，`python bench_ab.py --sweep 1,4 --requests 12000`
（`bench_win_ab.json`）：

| 端点 | 并发 | ONRouter | OpenResty | ORR/OR |
|---|---:|---:|---:|---:|
| 静态 index.html | 1 | 3595/s | 2863/s | 1.26x |
| 静态 index.html | 4 | 8025/s | 3614/s | 2.22x |
| Lua content_by_lua | 1 | 6309/s | 7111/s | 0.89x |
| Lua content_by_lua | 4 | 15197/s | 19850/s | 0.77x |
| Lua shared.DICT incr | 1 | 6445/s | 7778/s | 0.83x |
| Lua shared.DICT incr | 4 | 15091/s | 20784/s | 0.73x |
| Lua *_file | 1 | 6295/s | 7907/s | 0.80x |
| Lua *_file | 4 | 15733/s | 22109/s | 0.71x |
| 反代 upstream | 1 | 3411/s | 96/s* | 35.7x* |
| 反代 upstream | 4 | 8041/s | 2721/s | 2.96x |

\* OpenResty/Windows 在 c=1 反代行出现 96 req/s、14.4 ms 的异常值，疑似
Windows 版 nginx 的 upstream/事件模型问题；该行必须用 Linux 数据替代，不能据此得出
“反代快 35 倍”的结论。

## 验收标准

- `bench_linux_ab.json` 入库（或附在 release 说明），含 3 次运行与中位数；
- 记录内核版本、CPU 型号/核数、OpenResty 版本、ONRouter commit；
- 报告中同时给出客户端天花板与两侧 rps 上限，明确是否存在客户端受限。
