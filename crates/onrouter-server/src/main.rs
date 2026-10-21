//! ONRouter — 用 Rust 从零实现的 OpenResty / Nginx 风格网关服务器。
//!
//! 功能对照（逐项翻译自 Nginx / OpenResty）：
//! | Nginx / OpenResty            | ONRouter (Rust)                              |
//! |------------------------------|---------------------------------------------|
//! | master/worker 事件循环        | tokio 多线程运行时 + 连接额度信号量           |
//! | nginx.conf                   | 自研 Nginx 风格配置解析器                     |
//! | upstream + 负载均衡           | upstream.rs（加权 rr / least_conn / ip_hash） |
//! | proxy_pass 反向代理           | proxy.rs（hyper 连接池，响应流式转发）        |
//! | rewrite / return             | engine.rs（regex + last/break/redirect）      |
//! | location = / ~ / 前缀         | router.rs（nginx 匹配优先级）                 |
//! | listen ssl / http2 / SNI     | certs.rs（多证书 SNI + ALPN + TLS 版本控制）  |
//! | ngx_lua 脚本层               | lua_engine.rs（mlua，ngx.* API）              |
//! | error_log / access_log       | log.rs / access_log.rs（分级 + 滚动 + 有界队列）|
//! | limit_req / limit_conn       | limit.rs（分片令牌桶 + RAII 并发额度）        |
//! | worker_connections / 超时     | settings.rs + server.rs                       |
//! | quit / reopen_logs 信号      | SIGTERM/SIGINT 优雅停机，SIGHUP/SIGUSR1 重开日志 |
//!
//! 用法：`onrouter [-t] [-V] [path/to/onrouter.conf]`

mod access;
mod access_log;
mod affinity;
mod certs;
mod compress;
mod disk_cache;
mod dns;
mod engine;
mod front_proxy;
mod governor;
mod learning;
mod limit;
mod log;
mod lua_engine;
mod lua_resty;
mod metrics;
mod proxy;
mod proxy_cache;
mod proxy_tls;
mod realip;
mod resp_rewrite;
mod router;
mod schedule;
mod server;
mod settings;
mod shared_dict;
mod sockpool;
mod still_online;
mod stream;
mod tls;
mod upstream;
mod vip;
mod wasm;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use onrouter_config::Config;
use tokio::sync::watch;

use engine::HandlerRegistry;
use lua_engine::LuaEngine;
use proxy::ProxyEngine;
use router::Router;
use settings::Settings;
use upstream::UpstreamPool;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("config error: {0}")]
    Config(#[from] onrouter_config::ConfigError),
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("{0}")]
    Other(String),
}

/// 相对路径基于配置文件所在目录解析
pub fn resolve_path(p: &str, base_dir: &PathBuf) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

struct Args {
    conf: PathBuf,
    /// -t：只校验配置（含证书），不启动服务
    test: bool,
    /// -p <dir>：nginx 前缀目录（conf/日志/pid 的相对路径基准），nginx-tests 兼容
    prefix: Option<PathBuf>,
    /// -g "<directive; ...>"：命令行全局指令，合并进配置根部（可重复）
    globals: Vec<String>,
}

const USAGE: &str = "\
onrouter —— Rust 版 Nginx/OpenResty 风格网关

用法: onrouter [选项] [配置文件]

  -c <file>      指定配置文件（默认 conf/onrouter.conf）
  -p <dir>       前缀目录，配置内相对路径以此为基准（nginx 兼容）
  -g <directives> 命令行全局指令，如 -g 'pid run.pid; error_log err.log warn;'
  -e <file>      错误日志覆盖（接受并忽略，error_log 由 -g/conf 控制）
  -t             测试配置是否有效（含证书与限流引用），不启动
  -V             显示版本
  -h, --help     显示本帮助
";

fn parse_args() -> Result<Args, String> {
    let mut conf: Option<PathBuf> = None;
    let mut test = false;
    let mut prefix: Option<PathBuf> = None;
    let mut globals: Vec<String> = Vec::new();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-t" | "--test" => test = true,
            "-V" | "--version" => {
                println!("ONRouter/{} (Rust, OpenResty-compatible)", VERSION);
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-c" | "--conf" => {
                let Some(p) = argv.get(i + 1) else {
                    return Err("-c 需要一个文件路径".to_string());
                };
                conf = Some(PathBuf::from(p));
                i += 1;
            }
            "-p" | "--prefix" => {
                let Some(p) = argv.get(i + 1) else {
                    return Err("-p 需要一个目录路径".to_string());
                };
                prefix = Some(PathBuf::from(p));
                i += 1;
            }
            "-g" => {
                let Some(g) = argv.get(i + 1) else {
                    return Err("-g 需要一个指令串".to_string());
                };
                globals.push(g.clone());
                i += 1;
            }
            // Test::Nginx 固定传 `-e error.log`；错误日志目标由 conf/-g 的 error_log 决定
            "-e" => {
                if argv.get(i + 1).is_none() {
                    return Err("-e 需要一个文件路径".to_string());
                }
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("未知选项 '{other}'（-h 查看用法）"));
                }
                if conf.is_some() {
                    return Err(format!("多余的参数 '{other}'"));
                }
                conf = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }
    Ok(Args {
        conf: conf.unwrap_or_else(|| PathBuf::from("conf/onrouter.conf")),
        test,
        prefix,
        globals,
    })
}

/// `-g 'a b; c d;'` 解析成指令并插到配置根部最前面（与 conf 同级指令冲突时命令行优先，
/// 与 nginx 行为一致：-g 的值覆盖配置文件里的同名全局指令）
fn merge_globals(config: &mut Config, globals: &[String]) -> Result<(), String> {
    if globals.is_empty() {
        return Ok(());
    }
    let text = globals.join(" ");
    let extra = Config::parse(&text).map_err(|e| format!("-g 指令解析失败: {e}"))?;
    let mut block = extra.root.block;
    block.append(&mut config.root.block);
    config.root.block = block;
    Ok(())
}

fn main() {
    // 网关直连后端，忽略系统代理环境变量（否则 hyper-util 会把 upstream 请求
    // 发给 HTTP_PROXY，后端可达性完全取决于代理工具）
    for k in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::remove_var(k);
    }

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[onrouter] {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let conf_path = if let Some(pfx) = &args.prefix {
        let raw = &args.conf;
        if raw.is_absolute() {
            raw.clone()
        } else {
            pfx.join(raw)
        }
    } else {
        args.conf.clone()
    };
    let base_dir = match &args.prefix {
        Some(pfx) => pfx.clone(),
        None => conf_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    };

    let mut config = match Config::load(&conf_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[onrouter] 配置加载失败 {conf_path:?}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = merge_globals(&mut config, &args.globals) {
        eprintln!("[onrouter] {e}");
        std::process::exit(1);
    }

    // 日志器要最先初始化：之后所有模块的告警都走 error_log 而不是 stderr
    let _err_log = log::init(&config, &base_dir);

    let (settings, setting_warnings) = Settings::from_config(&config);
    // 告警副本同时留给 `-t` 直接打印：日志器是异步队列，-t 在 writer 线程排空前就 exit(0)，
    // 只看 error_log 会把"配置里有指令被忽略"这件事整个丢掉
    let mut startup_warnings: Vec<String> = Vec::new();
    for w in setting_warnings {
        log_warn!("{w}");
        startup_warnings.push(w);
    }

    // worker 线程数与 CPU 亲和性计划在 `-t` 之前算好：掩码越界这类告警必须在配置
    // 测试阶段就能看到，而不是等进程真的起来才出现在 error_log 里。
    let workers = settings
        .worker_threads
        .unwrap_or_else(affinity::cpu_count)
        .max(1);
    let affinity_plan = settings.worker_cpu_affinity.as_ref().map(|spec| {
        let (plan, warnings) = affinity::AffinityPlan::build(spec, workers);
        for w in warnings {
            log_warn!("{w}");
            startup_warnings.push(w);
        }
        log_info!("{}", plan.describe());
        plan
    });
    let limits = Arc::new(limit::Limits::parse_all(&config));
    for w in &limits.warnings {
        log_warn!("{w}");
        startup_warnings.push(w.clone());
    }
    // 缓存学习：默认整条链路关着，只有 `learning on;` + 声明了学习区才会改变任何行为
    let learning = Arc::new(learning::Learning::parse_all(&config));
    for w in &learning.warnings {
        log_warn!("{w}");
        startup_warnings.push(w.clone());
    }
    // 队列：`limit_req_queue` 把"超限即拒"改成"有界排队"，`limit_req_learning` 再让排队
    // 上界跟着 key 的突发形状走。启动与热重载共用这一条入口，两条路径不会分叉。
    for note in limits.apply_queue(&config, &learning) {
        log_warn!("队列: {note}");
        startup_warnings.push(note);
    }
    // 信誉：`vip_learning` 学出来的重要客户只改两处行为——排队上界与缓存驻留加权。
    // 申领排在缓存、队列之后：预算紧张时先让路的就是这份"锦上添花"。
    for note in limits.apply_vip(&learning) {
        log_warn!("信誉: {note}");
        startup_warnings.push(note);
    }

    // Scheduled windows: the table is built once at startup; afterwards the runner recomputes at each due
    // point and a hot reload only swaps definitions in place. An unreadable window table must abort startup
    // here: a mistyped "open daily at 09:00" must not turn into "going live with half a window table".
    let schedule = Arc::new(match schedule::Scheduler::parse_all(&config) {
        Ok(s) => s,
        Err(e) => {
            log_error!("invalid scheduled window configuration: {e}");
            eprintln!("[onrouter] invalid scheduled window configuration: {e}");
            std::process::exit(1);
        }
    });
    // The summary prints the computed next trigger time in each window's own timezone: the operator uses it to
    // check whether the gateway's clock and the host clock read the same time -- the most common accident with
    // calendar-style configuration is host clock drift.
    for line in schedule.describe(schedule::now_ms()) {
        log_info!("{line}");
    }

    // Cache governor: sleep/boost phases driven by observed traffic. Parse failure aborts
    // startup the way the schedule table does — a governor that half-read its thresholds
    // would flap the cache layer instead of serving it.
    let governor = Arc::new(match governor::parse_governor(&config) {
        Ok((c, ws)) => {
            for w in ws {
                log_warn!("{w}");
                startup_warnings.push(w);
            }
            governor::Governor::new(c)
        }
        Err(e) => {
            log_error!("invalid cache_governor configuration: {e}");
            eprintln!("[onrouter] invalid cache_governor configuration: {e}");
            std::process::exit(1);
        }
    });
    if governor.enabled() {
        log_info!("{}", governor.describe());
    }

    let router = match Router::build(&config, &base_dir) {
        Ok(r) => r,
        Err(e) => {
            log_error!("路由构建失败: {e}");
            eprintln!("[onrouter] 路由构建失败: {e}");
            std::process::exit(1);
        }
    };
    for w in &router.warnings {
        log_warn!("{w}");
        startup_warnings.push(w.clone());
    }

    let pid_path = config
        .find("pid")
        .and_then(|d| d.arg(0))
        .map(|p| resolve_path(p, &base_dir));

    if args.test {
        std::process::exit(
            match check(
                &router,
                &settings,
                &limits,
                &learning,
                &schedule,
                &config,
                &startup_warnings,
            ) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("[onrouter] {e}");
                    1
                }
            },
        );
    }

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder
        .worker_threads(workers)
        .thread_name("onrouter-worker")
        .enable_all();
    if let Some(plan) = affinity_plan {
        runtime_builder.on_thread_start(plan.into_thread_start_hook());
    }
    let runtime = runtime_builder.build().expect("tokio 运行时创建失败");

    if let Err(e) = runtime.block_on(run(
        config,
        router,
        settings,
        limits,
        Arc::clone(&learning),
        schedule,
        governor,
        base_dir,
        conf_path,
        workers,
        pid_path,
    )) {
        log_error!("启动失败: {e}");
        eprintln!("[onrouter] 启动失败: {e}");
        std::process::exit(1);
    }
}

/// `-t`：把运行期会踩的坑提前踩一遍（证书、限流引用、监听地址）
/// 预算的人类可读口径（副本区按字节配额，与 proxy_cache 的条数预算不同）。
fn human_bytes(n: usize) -> String {
    const MIB: usize = 1024 * 1024;
    if n >= MIB && n % MIB == 0 {
        format!("{} MiB", n / MIB)
    } else if n >= 1024 && n % 1024 == 0 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}

fn check(
    router: &Router,
    settings: &Settings,
    limits: &limit::Limits,
    learning: &learning::Learning,
    schedule: &schedule::Scheduler,
    config: &Config,
    warnings: &[String],
) -> Result<(), String> {
    if router.listeners.is_empty() {
        return Err("配置中没有任何 listen 指令".to_string());
    }
    for l in &router.listeners {
        if let Some(opts) = &l.tls {
            certs::validate(&opts.specs)?;
        }
    }
    for line in router.describe_listeners() {
        println!("  监听 {line}");
    }
    for st in &router.stream {
        if st.udp {
            println!(
                "  监听 udp://{}（proxy_responses={}，空闲回收 {:?}）",
                st.listen, st.proxy_responses, st.proxy_timeout
            );
        }
    }
    println!(
        "  worker_connections={} keepalive_requests={} shutdown_grace={:?}",
        settings.worker_connections, settings.keepalive_requests, settings.shutdown_grace
    );
    let workers = settings
        .worker_threads
        .unwrap_or_else(affinity::cpu_count)
        .max(1);
    let plan_line = settings.worker_cpu_affinity.as_ref().map(|spec| {
        let (plan, _) = affinity::AffinityPlan::build(spec, workers);
        format!("；亲和性：{}", plan.per_thread())
    });
    println!(
        "  worker_threads={}（逻辑核 {}）worker_cpu_affinity={}{}",
        workers,
        affinity::cpu_count(),
        settings
            .worker_cpu_affinity
            .as_ref()
            .map(|a| a.describe())
            .unwrap_or_else(|| "off".to_string()),
        plan_line.unwrap_or_default()
    );
    if !router.still_zones.is_empty() {
        let mut items: Vec<_> = router.still_zones.iter().collect();
        items.sort();
        // 列出区名与预算：确认顶层 still_online_zone 真的进了路由表，而不是只写了个名字
        println!(
            "  Still ONLine 副本区 {}",
            items
                .iter()
                .map(|(n, b)| format!("{n}={}", human_bytes(**b)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // 限流队列：只在写了 limit_req_queue 时产生输出，老配置的 -t 结果保持原样
    let queue = limits.queue_summary();
    if !queue.is_empty() {
        println!("  限流队列 {}", queue.join(" | "));
    }
    // 学习：同样只在真开着时打印——运维要能在 -t 就看到"这张表要占多少内存"，
    // 而不是等启动日志里才发现预算不够、某区退回不学。
    for line in learning.describe() {
        println!("  {line}");
    }
    // 前置代理：把"声明了哪几家、各靠什么头识别、有几段授权网段"打在 -t 里。
    // 这套配置最坏的失效是厂商网段过期后静默退回按节点 IP 计数，得让它在检查阶段就看得见。
    let fps = front_proxy::snapshot();
    if !fps.is_empty() {
        println!("  前置代理识别 {}", front_proxy::describe(&fps));
    }
    // Scheduled windows: -t prints the open/closed state and the next trigger computed from this
    // configuration. The likeliest accident with calendar-style configuration is a wrong host clock or
    // timezone convention, and that only becomes visible once you lay out the computed wall clock.
    for line in schedule.describe(schedule::now_ms()) {
        println!("  {line}");
    }
    // Cache governor: -t lays out the parsed phase machine. It also flags the one
    // configuration that silently cannot do what it says -- deep sleep requested
    // with no `disk=` zone for the demotion pass to write into.
    match governor::parse_governor(config) {
        Ok((c, warns)) => {
            for w in warns {
                println!("  Warning {w}");
            }
            if c.enabled() {
                println!("  {}", governor::describe_conf(&c));
                if c.mode == governor::GovernorMode::Auto
                    && c.tier == governor::SleepTier::Deep
                    // 深睡的动作是"把内存里的东西下沉到冷层"。共享字典的 `disk=` 与
                    // proxy_cache 的 `disk=on` 都算，两边一个都没有才是真的没东西可沉。
                    && shared_dict::config_disk_zone_count(config) == 0
                    && proxy_cache::ProxyCache::config_disk_zone_count(config) == 0
                {
                    println!(
                        "  Warning cache_governor_tier deep but no lua_shared_dict declares disk=: \
                         deep sleep has nothing to demote and only the light actions will run"
                    );
                }
            }
        }
        Err(e) => return Err(e),
    }
    // upstream 段：以前只有真正启动时才解析，于是出现过"-t 通过、启动才炸"。
    // 自适应选点的冲突（ip_hash + least_time、单节点池）必须在这一步就看得见。
    let pool = UpstreamPool::parse_all(config).map_err(|e| e.to_string())?;
    for w in &pool.warnings {
        println!("  告警 {w}");
    }
    let mut names: Vec<&String> = pool.map.keys().collect();
    names.sort();
    for name in names {
        if let Some(up) = pool.get(name) {
            if let Some(line) = up.least_time_desc() {
                println!("  {line}");
            }
            if let Some(line) = up.resilience_desc() {
                println!("  {line}");
            }
        }
    }
    // 业务分流（proxy_pass http://$变量）逐条自述：声明的比例、粘性键、改投策略。
    // 这行是"-t 通过不代表比例按你想的走"的那道补票：把网关读出来的那张表打出来。
    for line in &router.split_routes {
        println!("  {line}");
    }
    // WASM 插件：-t 把编译成功的模块、指令预算、内存上限和导出函数列出来。模块在构建路由时
    // 就已完成校验与编译，这里看到的就是线上将要执行的那一份。
    for line in crate::wasm::describe() {
        println!("  {line}");
    }
    // proxy_cache 冷层：配置里写了 disk=on 才有行。目录、上限、门槛都在这一行说清楚，
    // 因为"这个区的缓存会不会跨重启"从配置上看不出来。-t 不创建目录，只复述配置。
    for line in proxy_cache::ProxyCache::describe_disk(&router.cache_disk) {
        println!("  {line}");
    }
    if !warnings.is_empty() {
        // 逐条打印：这些行就是"配置里有指令没生效"，只给个数量等于没给
        println!("  告警 {} 条：", warnings.len());
        for w in warnings {
            println!("    - {w}");
        }
    }
    println!("配置测试通过。");
    Ok(())
}

async fn run(
    config: Config,
    router: Router,
    settings: Settings,
    limits: Arc<limit::Limits>,
    learning: Arc<learning::Learning>,
    schedule: Arc<schedule::Scheduler>,
    governor: Arc<governor::Governor>,
    base_dir: PathBuf,
    conf_path: PathBuf,
    workers: usize,
    pid_path: Option<PathBuf>,
) -> Result<(), AppError> {
    let conf_display = conf_path.display().to_string();
    let pool = UpstreamPool::parse_all(&config)?;
    for w in &pool.warnings {
        log_warn!("{w}");
    }
    let pool = Arc::new(pool);
    let handlers = Arc::new(HandlerRegistry::with_builtins());
    let lua = LuaEngine::new(&config, &base_dir)?;
    // init_worker_by_lua*：调度器已随 VM 池启动，此处逐 VM 执行（对标每 worker 一次）
    lua.run_init_workers().await?;
    let lua = Arc::new(lua);
    let proxy = match dns::DnsResolver::from_config(&config) {
        Some(r) => {
            println!(
                "[onrouter] 异步 DNS 解析器就绪：nameserver {:?}",
                r.nameservers()
            );
            Arc::new(ProxyEngine::new(Arc::clone(&pool)).with_resolver(r))
        }
        None => Arc::new(ProxyEngine::new(Arc::clone(&pool))),
    };
    let proxy_cache =
        proxy_cache::ProxyCache::with_capacities(router.cache_zones.clone(), Arc::clone(&learning));
    // proxy_cache 的磁盘冷层：`router.cache_disk` 里没有区 = 不创建任何目录，落盘与冷读两条
    // 路径全程短路。打开失败就直接失败——`disk=on` 许的是"这份缓存要落盘"。
    let proxy_disks = proxy_cache::ProxyCache::open_disk_zones(&router.cache_disk)?;
    if !proxy_disks.is_empty() {
        disk_cache::register_proxy_zones(
            proxy_disks
                .iter()
                .map(|(n, s)| (n.clone(), s.clone()))
                .collect(),
        );
    }
    proxy_cache.attach_disks(proxy_disks);
    let still_online = still_online::StillOnline::with_budgets(router.still_zones.clone());
    let access_log = access_log::AccessLog::new(&config, &base_dir);

    let listener_specs = router.listeners.clone();
    let cert_files = crate::tls::cert_files(&router.listeners);
    // 分流自述要在 router 移入 state 之后再打印，所以先把这几行留下
    let split_lines = router.split_routes.clone();
    let stream_specs: Vec<Arc<router::StreamServer>> =
        router.stream.clone().into_iter().map(Arc::new).collect();
    if listener_specs.is_empty() && stream_specs.is_empty() {
        return Err(AppError::Other("配置中没有任何 listen 指令".into()));
    }

    let state = Arc::new(server::AppState {
        router: std::sync::RwLock::new(Arc::new(router)),
        handlers,
        lua,
        proxy,
        proxy_cache,
        still_online: Arc::clone(&still_online),
        access_log: Arc::clone(&access_log),
        settings: settings.clone(),
        limits: Arc::clone(&limits),
        schedule: Arc::clone(&schedule),
        governor: Arc::clone(&governor),
        permits: server::permits_for(&settings),
        tls_registry: crate::tls::TlsRegistry::new(),
        cert_files: std::sync::RwLock::new(cert_files),
    });

    // 子请求（ngx.location.capture）晚绑定：LuaEngine 早于 AppState 构造，这里回填其运行句柄
    state.lua.bind_app_state(&state);

    // 运行时指标单例：记录 worker_connections 容量与进程启动时刻，供 /metrics 渲染
    crate::metrics::global(settings.worker_connections);
    // upstream 每节点连接数/健康/成败计数：注册的是运行中的 Arc，渲染时直接读原子量
    crate::metrics::register_upstreams(&pool);
    // Still ONLine 副本层计数：实例进程内唯一（热重载只套用新预算），注册一次即可
    crate::metrics::register_still_online(&still_online);
    // 缓存学习账目：同样注册一次，重载只换配置不换实例
    crate::metrics::register_proxy_cache(&state.proxy_cache);
    // 限流队列：`Limits` 实例进程内唯一，热重载只原地换策略，计数不清零
    crate::metrics::register_limits(&limits);
    // Scheduled windows: registered once the same way; the number of requests denied with 403 during a closed
    // window must show up on /metrics, otherwise "the gate is working" and "this route has no gate at all"
    // look exactly alike.
    crate::metrics::register_schedule(&schedule);
    // Cache governor: same registration discipline — one instance, reload swaps config in place
    crate::metrics::register_governor(&governor);

    // 先全部绑定再开始服务：端口冲突要在启动阶段就失败，而不是半启动状态
    let mut bound = Vec::with_capacity(listener_specs.len());
    for l in &listener_specs {
        match server::bind_listener(l, settings.accept_backlog) {
            Ok(tcp) => bound.push((l.clone(), tcp)),
            Err(e) => {
                // 已经绑定成功的先关掉（随进程退出释放），错误信息里带上是哪一个
                return Err(e);
            }
        }
    }
    // 四层 stream 监听：合成一个纯 TCP Listener（无 TLS/h2/quic），同样先绑定再服务。
    let mut bound_stream: Vec<(Arc<router::StreamServer>, tokio::net::TcpListener)> = Vec::new();
    let mut bound_udp: Vec<(Arc<router::StreamServer>, Arc<tokio::net::UdpSocket>)> = Vec::new();
    for s in &stream_specs {
        // UDP 入口走另一条通路：绑一个数据报 socket，不建 TCP 监听器
        if s.udp {
            let sock = tokio::net::UdpSocket::bind(s.listen)
                .await
                .map_err(|e| AppError::Other(format!("stream udp 监听 {} 绑定失败: {e}", s.listen)))
                .map(Arc::new)?;
            bound_udp.push((Arc::clone(s), sock));
            continue;
        }
        let l = router::Listener {
            addr: s.listen,
            tls: None,
            ssl_cert_scripts: Vec::new(),
            http2: false,
            quic: false,
            backlog: None,
            ipv6only: None,
        };
        match server::bind_listener(&l, settings.accept_backlog) {
            Ok(tcp) => bound_stream.push((Arc::clone(s), tcp)),
            Err(e) => return Err(e),
        }
    }

    let (tx, rx) = watch::channel(false);

    // 全部端口绑定成功后再落 pid 文件：Test::Nginx 用 waitforfile(nginx.pid) 判定启动完成
    if let Some(pp) = &pid_path {
        if let Some(dir) = pp.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(pp, format!("{}\n", std::process::id())) {
            log_warn!("写 pid 文件 {pp:?} 失败: {e}");
        }
    }

    // 后台维护：清理限流状态表里的闲置 key（防状态表随客户端数量膨胀）、
    // 清扫 DICT 冷层（过期/`inactive` 回收 + 容量逐出 + 账目自愈）。
    // 节拍跟缓存治理器的相位走：sleep 把这一轮拉长十倍（轻档休眠的全部收益），
    // 并按 `should_skip_sweep` 整轮跳过昂贵的冷层目录扫描——跳过必计数，绝不静默。
    let maintain = {
        let limits = Arc::clone(&limits);
        let access_log = Arc::clone(&state.access_log);
        let governor = Arc::clone(&governor);
        tokio::spawn(async move {
            let mut reported = 0u64;
            loop {
                tokio::time::sleep(governor.sweep_interval()).await;
                let n = limits.purge_idle_all(10 * 60 * 1000);
                if n > 0 {
                    log_debug!("清理限流状态表 {n} 个闲置 key");
                }
                // 清扫要走文件系统，放到阻塞线程池，别占着 worker
                if !governor.should_skip_sweep() {
                    match tokio::task::spawn_blocking(disk_cache::sweep_all).await {
                        Ok(0) | Err(_) => {}
                        Ok(n) => log_debug!("磁盘冷层清扫回收 {n} 个条目"),
                    }
                }
                let d = access_log.dropped_count();
                if d > reported {
                    reported = d;
                    log_error!("access_log 队列不足，累计丢弃 {d} 条（考虑调大容量或日志盘吞吐）");
                }
            }
        })
    };

    // Cache governor task: advances the phase machine on a 500ms tick and executes
    // the side effects a phase entry owns. Spawned only when the feature is on —
    // with `cache_governor off` (the default) neither this task nor the request
    // hook exists. A later `off -> observe/auto` hot reload starts it lazily.
    if governor.enabled() {
        spawn_governor_task(Arc::clone(&governor), Arc::clone(&state.proxy_cache));
    }

    // 主动健康检查：配了 health_check 的 upstream 各起一个后台探测任务
    let health = pool.spawn_health_checks(rx.clone());

    // 配置热重载：SIGHUP（unix）或 `reload <interval>` 轮询触发，原子替换路由表而不动
    // 已绑定监听（无 accept 空窗）。任务常驻，未配 reload 时也支持 SIGHUP。
    let reload_notify = Arc::new(tokio::sync::Notify::new());
    let reload = {
        let state = Arc::clone(&state);
        let conf_path = conf_path.clone();
        let base_dir = base_dir.clone();
        let listeners = listener_specs.clone();
        let notify = Arc::clone(&reload_notify);
        let poll = settings.reload;
        spawn_reload_task(
            state,
            conf_path,
            base_dir,
            listeners,
            poll,
            notify,
            rx.clone(),
        )
    };

    let signals = spawn_signal_handlers(tx.clone(), reload_notify.clone());

    // Scheduled window runner: when no window is declared **this task does not exist at all** (the zero-footprint requirement of defaulting to off).
    let schedule_runner = spawn_schedule_task(Arc::clone(&state));

    let mut tasks = tokio::task::JoinSet::new();
    for (l, tcp) in bound {
        let state = Arc::clone(&state);
        // QUIC/HTTP/3：同一 addr 再挂一个 UDP 端点（h3），TCP 侧照常提供 h1/h2（供 Alt-Svc 回退）
        if l.quic {
            tokio::spawn(server::serve_quic(
                Arc::clone(&state),
                l.clone(),
                rx.clone(),
            ));
        }
        tasks.spawn(server::serve(state, l, tcp, rx.clone()));
    }
    // 四层 stream 隧道：与 HTTP 共用停机信号与 worker_connections 额度。
    for (s, udp_sock) in bound_udp {
        tasks.spawn(stream::serve_udp(
            Arc::clone(&state),
            Arc::clone(&pool),
            s,
            udp_sock,
            rx.clone(),
        ));
    }
    for (s, tcp) in bound_stream {
        tasks.spawn(stream::serve_stream(
            Arc::clone(&state),
            Arc::clone(&pool),
            s,
            tcp,
            rx.clone(),
        ));
    }

    // Still ONLine 后台重取：脏表里到期的 key 用匿名 GET 换回新鲜内容（副本层自己在
    // 请求路径上回放，重取只负责"恢复后重试"，所以没配副本区时这个循环基本是空转）。
    tokio::spawn(server::still_online_refresh_loop(
        Arc::clone(&state),
        rx.clone(),
    ));

    println!(
        "[onrouter] 启动完成：{} 个监听（含 {} 个 stream），{workers} 个 worker 线程，配置 {conf_display}",
        listener_specs.len() + stream_specs.len(),
        stream_specs.len()
    );
    for line in state.routing().describe_listeners() {
        log_info!("监听 {line}");
    }
    for line in limits.describe() {
        log_info!("生效 {line}");
    }
    for line in learning.describe() {
        log_info!("生效 {line}");
    }
    log_info!(
        "worker_connections={}，Lua VM={}，upstream={:?}",
        settings.worker_connections,
        state.lua.vm_count(),
        pool.map.keys().collect::<Vec<_>>()
    );
    // 自适应选点只在开了 observe/on 时出声；启动就把档位和账目指标名写进日志，
    // 运营者不必事后猜"这个池到底有没有在测"。
    {
        let mut names: Vec<&String> = pool.map.keys().collect();
        names.sort();
        for name in names {
            if let Some(up) = pool.get(name) {
                if let Some(line) = up.least_time_desc() {
                    log_info!("{line}；账目见 /metrics 的 onrouter_upstream_least_time_total 与 onrouter_upstream_server_ewma_seconds");
                }
                if let Some(line) = up.resilience_desc() {
                    log_info!("{line}；状态见 /metrics 的 onrouter_upstream_circuit_state / onrouter_upstream_lazy_probes_total");
                }
            }
        }
    }
    // 业务分流在启动横幅里自述一次：这配置把哪条 location 按什么比例分成哪几路、
    // 选中路全挂时怎么办。计数指标名一起写出来，运营者不用事后猜"到底有没有在分"。
    for line in &split_lines {
        log_info!(
            "{line}；落点比例见 /metrics 的 onrouter_proxy_split_targets_total，\
             结局计数见 onrouter_proxy_split_total"
        );
    }
    for line in crate::wasm::describe() {
        log_info!(
            "{line}；调用/错误/fuel 见 /metrics 的 onrouter_wasm_invocations_total、\
             onrouter_wasm_errors_total、onrouter_wasm_fuel_exhausted_total"
        );
    }
    let so_rows = still_online.zone_rows();
    if !so_rows.is_empty() {
        log_info!(
            "Still ONLine 副本区：{}（只存 GET 2xx、无 Set-Cookie、且上游没声明私有（Cache-Control 不缓存 / Vary 按身份分变体）的响应，凭证请求一律不写；回放带 X-Still-Online: stale，计数见 /metrics 的 onrouter_still_online_*）",
            so_rows
                .iter()
                .map(|(n, _, _, b)| format!("{n}={}", human_bytes(*b)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if disk_cache::enabled() {
        let cold = disk_cache::snapshot();
        log_info!(
            "DICT 磁盘冷层：{} 个区已启用（{}），落盘/冷命中见 /metrics 的 onrouter_dict_disk_*",
            cold.len(),
            cold.iter()
                .map(|(n, s)| format!("{n}: {:?}", s.config().root))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if disk_cache::proxy_enabled() {
        let cold = disk_cache::proxy_snapshot();
        log_info!(
            "proxy_cache 磁盘冷层：{} 个区已启用（{}）；被内存挤出去的新鲜响应会落盘，冷命中额外带 X-Cache-Tier: disk，账目见 /metrics 的 onrouter_proxy_cache_disk_*",
            cold.len(),
            cold
                .iter()
                .map(|(n, s)| format!("{n}: {:?}", s.config().root))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let fps = front_proxy::snapshot();
    if !fps.is_empty() {
        log_info!(
            "前置代理识别：{}；命中/采用/挡下计数见 /metrics 的 onrouter_front_proxy_total，\
             头部取值一律要先过对端验证",
            front_proxy::describe(&fps)
        );
    }

    // 所有 accept 循环在停机信号后置位并排空在途连接，这里等它们自然结束
    while tasks.join_next().await.is_some() {}
    maintain.abort();
    reload.abort();
    if let Some(s) = schedule_runner {
        s.abort();
    }
    for h in health {
        h.abort();
    }
    if let Some(s) = signals {
        s.abort();
    }
    log_info!("已退出");
    drop(state);
    // 冷层：把排队的落盘/删除写完再退，否则重启后扫目录会少一批数据
    if tokio::task::spawn_blocking(disk_cache::flush_all_pending)
        .await
        .is_err()
    {
        log_warn!("磁盘冷层排空任务异常结束（尽力而为，冷层丢数据只影响命中率）");
    }
    // 冲刷并回收两个日志线程：优雅退出不该丢访问日志/诊断日志
    access_log::shutdown();
    log::shutdown();
    Ok(())
}

/// 停机信号：unix 用 SIGTERM/SIGINT 优雅停机，SIGHUP 热重载配置（+ 重开日志），SIGUSR1 重开日志；windows 用 Ctrl+C
fn spawn_signal_handlers(
    tx: watch::Sender<bool>,
    reload: Arc<tokio::sync::Notify>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(unix)]
    {
        Some(tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM 注册失败");
            let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT 注册失败");
            let mut hangup = signal(SignalKind::hangup()).expect("SIGHUP 注册失败");
            let mut user1 = signal(SignalKind::user_defined1()).expect("SIGUSR1 注册失败");
            loop {
                tokio::select! {
                    _ = terminate.recv() => {
                        lua_engine::mark_worker_exiting();
                        log_info!("收到 SIGTERM，开始优雅停机");
                        break;
                    }
                    _ = interrupt.recv() => {
                        lua_engine::mark_worker_exiting();
                        log_info!("收到 SIGINT，开始优雅停机");
                        break;
                    }
                    // nginx: SIGHUP = 重载配置（这里同时重开日志）；SIGUSR1 = 仅重开日志
                    _ = hangup.recv() => {
                        log::reopen();
                        access_log::reopen();
                        log_info!("收到 SIGHUP：重开日志并热重载配置");
                        reload.notify_one();
                    }
                    _ = user1.recv() => {
                        log::reopen();
                        access_log::reopen();
                        log_info!("收到 SIGUSR1：日志已重新打开");
                    }
                }
            }
            let _ = tx.send(true);
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = reload; // Windows 无信号式重载；用 conf 的 `reload <interval>;` 轮询
        Some(tokio::spawn(async move {
            // CTRL_BREAK_EVENT 是 Windows 上可从外部（服务管理器/taskkill 之外的
            // GenerateConsoleCtrlEvent）投递的优雅停机事件，和 Ctrl+C 同语义处理。
            use tokio::signal::windows::{ctrl_break, ctrl_c};
            let mut interrupt = ctrl_c().expect("Ctrl+C 注册失败");
            let mut brk = ctrl_break().expect("Ctrl+Break 注册失败");
            let how = tokio::select! {
                _ = interrupt.recv() => "Ctrl+C",
                _ = brk.recv() => "Ctrl+Break",
            };
            lua_engine::mark_worker_exiting();
            log_info!("收到 {how}，开始优雅停机");
            let _ = tx.send(true);
            // 二次中断立即退出
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = brk.recv() => {}
            }
            log_warn!("再次收到中断信号，强制退出");
            std::process::exit(1);
        }))
    }
}

/// Cache governor runner: a 500ms tick that advances the phase machine and
/// executes the side effect each phase entry owns.
///
/// Author: yxpil
///
/// Exactly one task may own the phase machine (`mark_task_started`). It is
/// spawned at startup only when the feature is on — the default `off` leaves no
/// resident task at all — and lazily on an `off -> observe/auto` hot reload.
/// Turning it off via reload keeps the task alive but idle: `advance` answers
/// `None` in off mode, so nothing is measured, decided or acted on.
fn spawn_governor_task(g: Arc<governor::Governor>, pc: Arc<proxy_cache::ProxyCache>) {
    if !g.mark_task_started() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some((from, to, cause, action)) = g.advance(schedule::now_ms() as u64) else {
                continue;
            };
            let cause_txt = match cause {
                governor::Cause::Load => "load",
                governor::Cause::Predicted => "predicted",
            };
            log_info!(
                "governor: phase {} -> {} ({cause_txt}); routes and cadence follow immediately",
                from.as_str(),
                to.as_str()
            );
            match action {
                governor::Action::EnterSleep => {
                    let deep = g.conf.read().unwrap_or_else(|e| e.into_inner()).tier
                        == governor::SleepTier::Deep;
                    if deep {
                        // Bounded per pass: sleep may last all weekend, and one
                        // mega-pass would hold zone locks while the disk writer
                        // queues. Repeated passes make the same progress.
                        for _ in 0..4 {
                            // Dict entries go through note_demotion (counters +
                            // pre-warm ring in one step). proxy_cache entries are
                            // evictions of reconstructible data — counters only.
                            let records = shared_dict::governor_demote_all(64);
                            let dict_n = records.len();
                            for (zone, key, bytes) in records {
                                g.note_demotion(zone, key, true, bytes);
                            }
                            let (en, eb) = pc.governor_evict_pass(64);
                            g.counters.demoted.fetch_add(en as u64, Ordering::Relaxed);
                            g.counters.demoted_bytes.fetch_add(eb, Ordering::Relaxed);
                            if dict_n == 0 && en == 0 {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                governor::Action::EnterBoost => {
                    // Pre-warm what deep sleep pushed out: single batch per boost
                    // entry, cold tier only, bounded by the demotion ring itself.
                    for k in g.take_prewarm_batch(64) {
                        if let Some(zone) = shared_dict::governor_zone(&k.zone) {
                            if zone.governor_prewarm(&k.key) {
                                g.counters.prewarmed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                governor::Action::EnterNormal => {}
            }
        }
    });
}

/// Scheduled window runner: **one** task, sleeping until the next natural minute boundary and, on waking,
/// recomputing every window.
///
/// Author: yxpil
///
/// Why it sleeps by the minute rather than precisely until the earliest next fire: cron's resolution is the
/// minute anyway, and "sleeping until next_fire" would turn a single clock jump or a single late wake-up into
/// "the whole window was missed". Recomputing by the minute decides at most one second late and keeps a single
/// code path -- the state is always derived from the calendar, never from "whether I remember it being open or
/// closed last time".
///
/// When the table is empty (no schedule_window written at all) **this task is not created**: defaulting to off
/// must leave no resident overhead.
fn spawn_schedule_task(state: Arc<server::AppState>) -> Option<tokio::task::JoinHandle<()>> {
    if state.schedule.is_empty() {
        return None;
    }
    log_info!(
        "scheduled window runner started: {} windows, recomputed at every minute boundary; state flips are recorded in error_log, and the current values are on /metrics under onrouter_schedule_*",
        state.schedule.len()
    );
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(next_minute_wait()).await;
            let now = schedule::now_ms();
            for ch in state.schedule.advance(now) {
                // Only say something when the state **really** changed: coming due does not imply a flip (see next_trigger_at in schedule.rs).
                log_info!(
                    "schedule: window '{}' at {} switched to {}; routes referencing it take effect immediately (gate state on /metrics: onrouter_schedule_open, denied count: onrouter_schedule_denied_total)",
                    ch.name,
                    state.schedule.wall(&ch.name, ch.at_ms),
                    if ch.open { "open" } else { "closed" }
                );
            }
        }
    }))
}

/// How long until the next natural minute boundary. Adds 20ms to clear the boundary, so we never sit in the
/// last millisecond of the previous minute, compute the new state as the old one, then decide the other way on
/// the next wake-up (evaluating twice within the same minute must give the same result).
fn next_minute_wait() -> Duration {
    let now = schedule::now_ms();
    let to_next = 60_000 - now.rem_euclid(60_000);
    Duration::from_millis((to_next.max(1) + 20) as u64)
}

/// 配置热重载后台任务：监听 SIGHUP 通知与（可选）`reload <interval>` 轮询；
/// 检测到主配置文件 mtime 变化即重建路由表并原子替换（Router::rebuild_routing_with_specs 复用
/// 已绑定的监听集合，绝不 rebind socket → 无 accept 空窗）。构建失败则保留旧路由并记日志。
/// 同时监视证书/私钥文件的大小与 mtime：证书原地续期（不动 conf）也会触发 TLS 接受器刷新。
///
/// 顺带承担 `*.lua` 脚本文件的定期自检：请求路径只查内存缓存、从不 stat，
/// 文件是否变过由这里的节拍统一检查（未配 `reload` 时自检照样跑，间隔 1s）。
fn spawn_reload_task(
    state: Arc<server::AppState>,
    conf_path: PathBuf,
    base_dir: PathBuf,
    listeners: Vec<router::Listener>,
    poll: Option<Duration>,
    notify: Arc<tokio::sync::Notify>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // 未配 reload 时只等 SIGHUP；给轮询兜一个长间隔，SIGHUP 仍能即时唤醒
        let poll = poll.unwrap_or_else(|| Duration::from_secs(3600));
        let mut tick = tokio::time::interval(poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut lua_tick = tokio::time::interval(lua_engine::LUA_FILE_CHECK_INTERVAL);
        lua_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last = conf_mtime(&conf_path);
        let mut last_certs = cert_stamp(&state.cert_files());
        loop {
            let from_signal = tokio::select! {
                _ = notify.notified() => true,
                _ = tick.tick() => false,
                _ = lua_tick.tick() => {
                    check_lua_files();
                    continue;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow_and_update() {
                        break;
                    }
                    continue;
                }
            };
            // 轮询触发：配置或任一证书/私钥文件变了才重建；SIGHUP 触发时无条件尝试。
            // 证书监视让自动续期（只替换证书文件、不写 conf）也能生效。
            if !from_signal
                && conf_mtime(&conf_path) == last
                && cert_stamp(&state.cert_files()) == last_certs
            {
                continue;
            }
            check_lua_files();
            do_reload(&state, &conf_path, &base_dir, &listeners);
            last = conf_mtime(&conf_path);
            last_certs = cert_stamp(&state.cert_files());
        }
    })
}

/// 定期自检 Lua 脚本文件：mtime 变了的重读进缓存，下一个请求即编译新版本。
fn check_lua_files() {
    for p in lua_engine::recheck_cached_files() {
        log_info!(
            "定期自检：Lua 脚本有变更，缓存已更新（重读或失效） {}",
            p.display()
        );
    }
}

fn conf_mtime(path: &PathBuf) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// 证书/私钥文件指纹：(路径, 大小, mtime)。任一文件被替换或续期都会变化。
fn cert_stamp(paths: &[PathBuf]) -> Vec<(PathBuf, u64, Option<std::time::SystemTime>)> {
    paths
        .iter()
        .map(|p| {
            let meta = std::fs::metadata(p).ok();
            (
                p.clone(),
                meta.as_ref().map(|m| m.len()).unwrap_or(0),
                meta.and_then(|m| m.modified().ok()),
            )
        })
        .collect()
}

/// 真正执行一次重载：重新读盘 → 仅重建路由（保留监听）→ 成功则原子替换，失败保留旧配置。
fn do_reload(
    state: &Arc<server::AppState>,
    conf_path: &PathBuf,
    base_dir: &PathBuf,
    listeners: &[router::Listener],
) {
    match onrouter_config::Config::load(conf_path) {
        Err(e) => log_error!("热重载失败：配置解析出错，保持旧配置继续服务: {e}"),
        Ok(cfg) => match router::Router::rebuild_routing_with_specs(&cfg, base_dir, listeners) {
            Err(e) => log_error!("热重载失败：路由构建出错，保持旧配置继续服务: {e}"),
            Ok((new_router, fresh_listeners)) => {
                let warnings = new_router.warnings.clone();
                // proxy_cache 冷层先打开、后换路由：打不开就整次重载作废并保留旧配置，
                // 否则会出现"路由是新的、磁盘层还是旧的（或没有）"这种对不上账的状态。
                // 新配置里没写 disk=on 时这里传入空表 = 摘掉全部冷层并排空旧队列。
                let proxy_disks =
                    match proxy_cache::ProxyCache::open_disk_zones(&new_router.cache_disk) {
                        Ok(d) => d,
                        Err(e) => {
                            log_error!("热重载失败：{e}，保持旧配置继续服务");
                            return;
                        }
                    };
                disk_cache::register_proxy_zones(
                    proxy_disks
                        .iter()
                        .map(|(n, s)| (n.clone(), s.clone()))
                        .collect(),
                );
                state.proxy_cache.attach_disks(proxy_disks);
                state.swap_router(new_router);
                // 缓存学习：账本跨重载延续（见 learning::Budget），这里只换配置并逐区对齐
                let learning = learning::Learning::parse_all(&cfg);
                for w in &learning.warnings {
                    log_warn!("热重载告警: {w}");
                }
                for line in learning.describe() {
                    log_info!("热重载生效 {line}");
                }
                for note in state.proxy_cache.apply_learning(learning) {
                    log_warn!("缓存学习: {note}");
                }
                // 队列套用放在缓存之后：两者共用同一本进程级账本，而账本只有 apply_learning
                // 做过"旧账延续"，队列必须用那份套用完的配置申领/退回，否则预算会被重复申领。
                let live = state.proxy_cache.learning_cfg();
                for note in state.limits.apply_queue(&cfg, &live) {
                    log_warn!("热重载队列: {note}");
                }
                for note in state.limits.apply_vip(&live) {
                    log_warn!("热重载信誉: {note}");
                }
                // Scheduled windows: window instances are never swapped within the process (the routes
                // referencing them must keep resolving by name), so here we only swap the definitions in place
                // and **recompute the current state** from the new configuration -- the state is a pure function
                // of the calendar, so recomputing is correct, and it needs no "remember whether it was open or
                // closed last time" persistence.
                for note in state.schedule.apply(&cfg, schedule::now_ms()) {
                    log_warn!("scheduled window reload: {note}");
                }
                for line in state.schedule.describe(schedule::now_ms()) {
                    log_info!("after hot reload, {line}");
                }
                // Cache governor: a reload swaps only the configuration — the window,
                // the phase and the learned profile are observations and stay put.
                // A rejected definition keeps the running one (a bad threshold pair
                // must not take the cache layer down mid-flight), unlike startup,
                // where the same error aborts.
                match governor::parse_governor(&cfg) {
                    Ok((c, ws)) => {
                        state.governor.apply(c);
                        for w in ws {
                            log_warn!("cache_governor reload: {w}");
                        }
                        if state.governor.enabled() {
                            spawn_governor_task(
                                Arc::clone(&state.governor),
                                Arc::clone(&state.proxy_cache),
                            );
                            log_info!("{}", state.governor.describe());
                        } else {
                            log_info!(
                                "cache_governor off: phase machine stays idle, window and profile stop being fed"
                            );
                        }
                    }
                    Err(e) => log_error!(
                        "cache_governor reload rejected, keeping the running configuration: {e}"
                    ),
                }
                // upstream 池（连同 least_time 的 EWMA）挂在启动时构建的 Arc 上，热重载不替换它。
                // 这里照样按新配置打一行档位并说明"要重启"，否则运维会以为 SIGHUP 就切了档。
                if let Ok(p) = UpstreamPool::parse_all(&cfg) {
                    for w in &p.warnings {
                        log_warn!("热重载告警: {w}");
                    }
                    for up in p.map.values() {
                        if let Some(line) = up.least_time_desc() {
                            log_info!("热重载 {line}（upstream 池不热替换，档位改动要重启才生效）");
                        }
                        if let Some(line) = up.resilience_desc() {
                            log_info!("热重载 {line}（upstream 池不热替换，熔断/惰性重加入改动要重启才生效）");
                        }
                    }
                }
                // 证书 / ssl_protocols / ssl_certificate_by_lua 脚本按新配置原地刷新；
                // 监听 socket 不动，新连接下一次握手即用新证书
                state.tls_registry.reload(
                    &fresh_listeners,
                    Arc::clone(&state.lua),
                    server::MAX_CONCURRENT_STREAMS,
                );
                state.set_cert_files(crate::tls::cert_files(&fresh_listeners));
                for w in warnings {
                    log_warn!("热重载告警: {w}");
                }
                log_info!("热重载完成：路由表与 TLS 配置已原子替换（监听未变动，无停机）");
            }
        },
    }
}
