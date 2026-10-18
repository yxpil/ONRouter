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

mod access_log;
mod access;
mod certs;
mod compress;
mod dns;
mod engine;
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
mod server;
mod settings;
mod shared_dict;
mod sockpool;
mod stream;
mod tls;
mod upstream;

use std::path::PathBuf;
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
    for w in setting_warnings {
        log_warn!("{w}");
    }
    let limits = Arc::new(limit::Limits::parse_all(&config));
    for w in &limits.warnings {
        log_warn!("{w}");
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
    }

    let pid_path = config
        .find("pid")
        .and_then(|d| d.arg(0))
        .map(|p| resolve_path(p, &base_dir));

    if args.test {
        std::process::exit(match check(&router, &settings) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("[onrouter] {e}");
                1
            }
        });
    }

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("onrouter-worker")
        .enable_all()
        .build()
        .expect("tokio 运行时创建失败");

    if let Err(e) = runtime.block_on(run(
        config,
        router,
        settings,
        limits,
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
fn check(router: &Router, settings: &Settings) -> Result<(), String> {
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
    println!(
        "  worker_connections={} keepalive_requests={} shutdown_grace={:?}",
        settings.worker_connections, settings.keepalive_requests, settings.shutdown_grace
    );
    if !router.warnings.is_empty() {
        println!("  （有 {} 条告警，见 error_log）", router.warnings.len());
    }
    println!("配置测试通过。");
    Ok(())
}

async fn run(
    config: Config,
    router: Router,
    settings: Settings,
    limits: Arc<limit::Limits>,
    base_dir: PathBuf,
    conf_path: PathBuf,
    workers: usize,
    pid_path: Option<PathBuf>,
) -> Result<(), AppError> {
    let conf_display = conf_path.display().to_string();
    let pool = UpstreamPool::parse_all(&config)?;
    let pool = Arc::new(pool);
    let handlers = Arc::new(HandlerRegistry::with_builtins());
    let lua = Arc::new(LuaEngine::new(&config, &base_dir)?);
    let proxy = match dns::DnsResolver::from_config(&config) {
        Some(r) => {
            println!("[onrouter] 异步 DNS 解析器就绪：nameserver {:?}", r.nameservers());
            Arc::new(ProxyEngine::new(Arc::clone(&pool)).with_resolver(r))
        }
        None => Arc::new(ProxyEngine::new(Arc::clone(&pool))),
    };
    let proxy_cache = proxy_cache::ProxyCache::new();
    let access_log = access_log::AccessLog::new(&config, &base_dir);

    let listener_specs = router.listeners.clone();
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
        access_log: Arc::clone(&access_log),
        settings: settings.clone(),
        limits: Arc::clone(&limits),
        permits: server::permits_for(&settings),
    });

    // 子请求（ngx.location.capture）晚绑定：LuaEngine 早于 AppState 构造，这里回填其运行句柄
    state.lua.bind_app_state(&state);

    // 运行时指标单例：记录 worker_connections 容量与进程启动时刻，供 /metrics 渲染
    crate::metrics::global(settings.worker_connections);

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
    for s in &stream_specs {
        let l = router::Listener {
            addr: s.listen,
            tls: None,
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

    // 后台维护：清理限流状态表里的闲置 key（防状态表随客户端数量膨胀）
    let maintain = {
        let limits = Arc::clone(&limits);
        let access_log = Arc::clone(&state.access_log);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut reported = 0u64;
            loop {
                ticker.tick().await;
                let n = limits.purge_idle_all(10 * 60 * 1000);
                if n > 0 {
                    log_debug!("清理限流状态表 {n} 个闲置 key");
                }
                let d = access_log.dropped_count();
                if d > reported {
                    reported = d;
                    log_error!("access_log 队列不足，累计丢弃 {d} 条（考虑调大容量或日志盘吞吐）");
                }
            }
        })
    };

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
        spawn_reload_task(state, conf_path, base_dir, listeners, poll, notify, rx.clone())
    };

    let signals = spawn_signal_handlers(tx.clone(), reload_notify.clone());

    let mut tasks = tokio::task::JoinSet::new();
    for (l, tcp) in bound {
        let state = Arc::clone(&state);
        // QUIC/HTTP/3：同一 addr 再挂一个 UDP 端点（h3），TCP 侧照常提供 h1/h2（供 Alt-Svc 回退）
        if l.quic {
            tokio::spawn(server::serve_quic(Arc::clone(&state), l.clone(), rx.clone()));
        }
        tasks.spawn(server::serve(state, l, tcp, rx.clone()));
    }
    // 四层 stream 隧道：与 HTTP 共用停机信号，接受同一个 shutdown watch。
    for (s, tcp) in bound_stream {
        tasks.spawn(stream::serve_stream(Arc::clone(&pool), s, tcp, rx.clone()));
    }

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
    log_info!(
        "worker_connections={}，Lua VM={}，upstream={:?}",
        settings.worker_connections,
        state.lua.vm_count(),
        pool.map.keys().collect::<Vec<_>>()
    );

    // 所有 accept 循环在停机信号后置位并排空在途连接，这里等它们自然结束
    while tasks.join_next().await.is_some() {}
    maintain.abort();
    reload.abort();
    for h in health {
        h.abort();
    }
    if let Some(s) = signals {
        s.abort();
    }
    log_info!("已退出");
    drop(state);
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
                    _ = terminate.recv() => { log_info!("收到 SIGTERM，开始优雅停机"); break; }
                    _ = interrupt.recv() => { log_info!("收到 SIGINT，开始优雅停机"); break; }
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
            let _ = tokio::signal::ctrl_c().await;
            log_info!("收到 Ctrl+C，开始优雅停机");
            let _ = tx.send(true);
            // 二次 Ctrl+C 立即退出
            let _ = tokio::signal::ctrl_c().await;
            log_warn!("再次收到中断信号，强制退出");
            std::process::exit(1);
        }))
    }
}

/// 配置热重载后台任务：监听 SIGHUP 通知与（可选）`reload <interval>` 轮询；
/// 检测到主配置文件 mtime 变化即重建路由表并原子替换（Router::rebuild_routing 复用
/// 已绑定的监听集合，绝不 rebind socket → 无 accept 空窗）。构建失败则保留旧路由并记日志。
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
        let mut last = conf_mtime(&conf_path);
        loop {
            let from_signal = tokio::select! {
                _ = notify.notified() => true,
                _ = tick.tick() => false,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow_and_update() {
                        break;
                    }
                    continue;
                }
            };
            // 轮询触发时以 mtime 变化为准；SIGHUP 触发时无条件尝试
            if !from_signal && conf_mtime(&conf_path) == last {
                continue;
            }
            do_reload(&state, &conf_path, &base_dir, &listeners);
            last = conf_mtime(&conf_path);
        }
    })
}

fn conf_mtime(path: &PathBuf) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
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
        Ok(cfg) => match router::Router::rebuild_routing(&cfg, base_dir, listeners) {
            Err(e) => log_error!("热重载失败：路由构建出错，保持旧配置继续服务: {e}"),
            Ok(new_router) => {
                let warnings = new_router.warnings.clone();
                state.swap_router(new_router);
                for w in warnings {
                    log_warn!("热重载告警: {w}");
                }
                log_info!("热重载完成：路由表已原子替换（监听未变动，无停机）");
            }
        },
    }
}
