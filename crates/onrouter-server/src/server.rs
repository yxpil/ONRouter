//! 连接层 + 请求管线（对标 Nginx 的 accept/读写事件 + 11 个 HTTP 阶段）。
//!
//! 连接层职责：
//!   - 按配置地址绑定监听（backlog / ipv6only），一条 listen = 一个 accept 循环
//!   - 并发连接上限（worker_connections）+ 快速拒绝
//!   - TLS：多证书 SNI、ALPN 协商 h2/http1.1、握手超时
//!   - 读头超时、keep-alive 空闲与请求数上限、优雅停机
//!   - panic 隔离（单个请求崩溃不能带倒整个进程）
//!
//! 请求管线（阶段顺序与 nginx 一致）：
//!   POST_READ(校验/取 vhost) → FIND_CONFIG(location) → REWRITE(rewrite/last)
//!   → PREACCESS(limit_req) → ACCESS(limit_conn / *_by_*) → TRY_FILES/CONTENT
//!   → LOG(响应体生命周期结束时落访问日志)

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use futures_util::{FutureExt, StreamExt};
use http_body_util::{BodyExt, BodyStream, Empty, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_TYPE, SERVER, VARY};
use hyper::server::conn::{http1, http2};
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit};

use crate::access_log::{AccessLog, LogRecord};
use crate::compress::{accepts_gzip, GzipBody};
use crate::engine::{self, HandlerRegistry, Phase, RequestCtx, StreamEvent, StreamSink};
use crate::lua_engine::LuaEngine;
use crate::proxy::{ProxyBody, ProxyEngine, ProxyOpts, ProxyTimeouts};
use crate::proxy_cache::CacheHit;
use crate::router::{self, Location, Router, Server};
use crate::settings::Settings;
use crate::tls::{self, TlsAcceptor};
use crate::{log_debug, log_error, log_info, log_warn, AppError};

fn http_version_f64(v: Version) -> f64 {
    match v {
        Version::HTTP_09 => 0.9,
        Version::HTTP_10 => 1.0,
        Version::HTTP_11 => 1.1,
        Version::HTTP_2 => 2.0,
        Version::HTTP_3 => 3.0,
        _ => 1.1,
    }
}

/// 请求起始时间（epoch 秒）
fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 响应体错误类型：hyper::Error 无公开构造器，代理层无法在响应体中途表达
/// “上游读超时”这类自定义错误，因此统一擦除成盒装错误（hyper/h3 都接受该类型）。
pub type RespBody = BoxBody<Bytes, crate::proxy::BoxError>;
pub type BoxResponse = Response<RespBody>;
use http_body_util::combinators::BoxBody;

/// 所有响应统一携带的品牌头（对标 nginx 的 Server 头）
pub const SERVER_HEADER: &str = concat!("ONRouter/", env!("CARGO_PKG_VERSION"));

/// location 匹配/内部重定向的最大跳数（nginx NGX_HTTP_MAX_URI_CHANGES = 10）
const MAX_URI_CHANGES: usize = 10;
/// 单个请求最多允许的头数量；头块总大小超 MAX_HEADER_BYTES → 431
const MAX_REQUEST_HEADERS: usize = 100;
/// nginx large_client_header_buffers 的额度：超了先由我们自己判定，才能给出 414/431 的区分
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// 交给 hyper 的解析硬上限：留出余量，越界的请求行/URI 才能进到我们的判定里换成正确状态码
/// （若这里就等于 MAX_HEADER_BYTES，20KB 的请求行会被解析器一口 431 掉，丢掉 414 语义）
const PARSE_CEILING_BYTES: usize = 64 * 1024;
/// 请求行（URI）长度上限，nginx 同样是 8K
const MAX_URI_BYTES: usize = 8 * 1024;
/// HTTP/2 并发流上限（nginx http2_max_concurrent_streams 默认 128）
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 128;
/// 流式响应的通道容量（帧数）。慢客户端只能让脚本多缓冲，不会丢数据。
const STREAM_CHANNEL_CAPACITY: usize = 64;

pub struct AppState {
    /// 路由表放在热交换的 RwLock<Arc<Router>> 里：热重载任务只换这个 Arc，
    /// 每个请求开头取一次快照（Arc clone），在途请求继续用旧快照跑完 → 零停机。
    pub router: std::sync::RwLock<Arc<Router>>,
    pub handlers: Arc<HandlerRegistry>,
    pub lua: Arc<LuaEngine>,
    pub proxy: Arc<ProxyEngine>,
    pub proxy_cache: Arc<crate::proxy_cache::ProxyCache>,
    /// Still ONLine 的"最后已知良好响应"副本区（与 proxy_cache 完全独立）
    pub still_online: Arc<crate::still_online::StillOnline>,
    pub access_log: Arc<AccessLog>,
    pub settings: Settings,
    pub limits: Arc<crate::limit::Limits>,
    /// Scheduled access window table (`schedule_window` + `schedule_access`). When no window is declared this
    /// is an empty table; on the request path only routes whose `schedule_gate` is None skip this lookup at all.
    pub schedule: Arc<crate::schedule::Scheduler>,
    /// Cache governor (`cache_governor`): traffic-phase machine for the cache layers.
    /// Off by default; the only request-path touchpoint is one atomic add when enabled.
    pub governor: Arc<crate::governor::Governor>,
    /// 全局并发连接额度（worker_connections）
    pub permits: Arc<tokio::sync::Semaphore>,
    /// 运行期 TLS 接受器 / QUIC endpoint 注册表：热重载时原地刷新证书与协议配置
    pub tls_registry: crate::tls::TlsRegistry,
    /// 当前生效的证书/私钥文件清单（去重）：重载任务据此监视 mtime/大小变化，
    /// 让证书原地续期即便不动配置文件也能触发刷新。
    pub cert_files: std::sync::RwLock<Vec<std::path::PathBuf>>,
}

impl AppState {
    /// 取当前路由表快照：热重载只替换其中的 Arc，这里读锁极短（仅克隆 Arc），
    /// 绝不跨越 await 持锁。在途请求持有旧快照即可跑完，实现零停机。
    pub fn routing(&self) -> Arc<Router> {
        self.router
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 热重载：原子替换路由表（写锁只覆盖一次 Arc 赋值）。
    pub fn swap_router(&self, next: Router) {
        // 新的 proxy_cache_path keys_zone 容量随配置生效（已有 zone 立即裁剪）
        self.proxy_cache.apply_capacities(&next.cache_zones);
        // 副本区的字节预算同理；条目超限立刻按 LRU 裁掉
        self.still_online.apply_budgets(&next.still_zones);
        let mut w = self
            .router
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *w = Arc::new(next);
    }

    /// 当前证书/私钥文件清单快照（重载任务用于监视文件变化）。
    pub fn cert_files(&self) -> Vec<std::path::PathBuf> {
        self.cert_files
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// 热重载成功后更新证书文件清单（新配置可能换路径）。
    pub fn set_cert_files(&self, files: Vec<std::path::PathBuf>) {
        *self.cert_files.write().unwrap_or_else(|p| p.into_inner()) = files;
    }
}

/// 一条连接的可共享元信息（TLS/SNI 决定 scheme，vhost 匹配决定用哪个地址）
pub struct ConnMeta {
    /// 该连接所属监听端点的配置地址（vhost 分组键）
    pub listener: SocketAddr,
    pub peer: Option<SocketAddr>,
    pub scheme: &'static str,
    /// 是否 HTTP/1.x（keep-alive 上限用 `Connection: close` 实现；h2 用 GOAWAY）
    pub http1: bool,
    /// 本端点若同时开了 QUIC，则给出要广播的 `Alt-Svc` 头值（如 `h3=":18443"; ma=3600`），
    /// 让真实浏览器/客户端在拿到 h1/h2 响应后发现可用的 HTTP/3。无 QUIC 时为 None。
    pub alt_svc: Option<String>,
    /// 本连接已处理的请求数（每个连接独享一份计数）
    pub requests: Arc<AtomicU64>,
}

pub fn full_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into())
        .map_err(|never| -> crate::proxy::BoxError { match never {} })
        .boxed()
}

fn empty_body() -> RespBody {
    Empty::new()
        .map_err(|never| -> crate::proxy::BoxError { match never {} })
        .boxed()
}

// ==================== 监听与 accept 循环 ====================

/// 按配置地址创建监听 socket（backlog、ipv6only、SO_REUSEADDR）
pub fn bind_listener(
    l: &crate::router::Listener,
    default_backlog: u32,
) -> Result<TcpListener, AppError> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let addr = l.addr;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| AppError::Other(format!("创建监听 socket 失败 {addr}: {e}")))?;
    // 重启时尽快复用处于 TIME_WAIT 的端口（Windows 上 SO_REUSEADDR 语义是"可抢占"，不能用）
    #[cfg(not(windows))]
    if let Err(e) = socket.set_reuse_address(true) {
        log_warn!("{addr} 设置 SO_REUSEADDR 失败: {e}");
    }
    if addr.is_ipv6() {
        if let Some(v6only) = l.ipv6only {
            socket
                .set_only_v6(v6only)
                .map_err(|e| AppError::Other(format!("{addr} 设置 ipv6only 失败: {e}")))?;
        }
    }
    socket
        .set_nonblocking(true)
        .map_err(|e| AppError::Other(format!("{addr} 设置非阻塞失败: {e}")))?;
    let sa: SockAddr = addr.into();
    socket.bind(&sa).map_err(|e| {
        AppError::Other(format!(
            "绑定 {addr} 失败: {e}（端口已被占用，或需要管理员/root 权限绑定 <1024 端口）"
        ))
    })?;
    let backlog = l.backlog.unwrap_or(default_backlog);
    socket
        .listen(backlog as i32)
        .map_err(|e| AppError::Other(format!("{addr} listen(backlog={backlog}) 失败: {e}")))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| AppError::Other(format!("{addr} 交给 tokio 失败: {e}")))
}

/// 一个监听端点的 accept 循环；`shutdown` 置位后停止接收并优雅排空在途连接
pub async fn serve(
    state: Arc<AppState>,
    listener: crate::router::Listener,
    tcp: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = listener.addr;
    let tls: Option<TlsAcceptor> = match &listener.tls {
        Some(opts) => {
            match tls::make_acceptor(opts, &listener.ssl_cert_scripts, Arc::clone(&state.lua)) {
                Ok(acc) => {
                    let names: Vec<String> =
                        opts.specs.iter().flat_map(|s| s.names.clone()).collect();
                    let protos = format!("{:?}", opts.protocols.normalized().enabled);
                    log_info!(
                        "{addr} TLS 就绪（协议 {protos}，ALPN {:?}，证书名 {names:?}）",
                        if opts.http2 {
                            "h2,http/1.1"
                        } else {
                            "http/1.1"
                        }
                    );
                    Some(acc)
                }
                Err(e) => {
                    // 证书有问题就不能"降级成明文"继续服务——那会让 https 的调用方拿到意外结果
                    log_error!("{addr} TLS 配置无效: {e}，该监听退出");
                    return;
                }
            }
        }
        None => None,
    };
    let scheme = if tls.is_some() { "https" } else { "http" };
    if let Some(acc) = &tls {
        // 登记到运行期注册表：accept 循环每连接取最新句柄，SIGHUP/轮询重载可原地换证书
        state.tls_registry.register_tcp(addr, acc.clone());
    }
    let is_tls = tls.is_some();
    // QUIC 端点在 TCP 响应上广播 Alt-Svc，让客户端发现同端口的 HTTP/3（h3 只在 https 上合法）
    let alt_svc: Option<String> = if listener.quic && tls.is_some() {
        Some(format!("h3=\":{}\"; ma=3600", addr.port()))
    } else {
        None
    };
    log_info!(
        "监听 {scheme}://{addr}（backlog={})",
        listener.backlog.unwrap_or(state.settings.accept_backlog)
    );

    let mut tasks = tokio::task::JoinSet::new();
    let mut backoff = Duration::from_millis(1);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            r = tcp.accept() => r,
            // 顺手回收已完成的连接任务：JoinSet 只有 join 后才释放，
            // 否则高流量下每个连接的任务内存会累积到进程退出
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        match accepted {
            Ok((stream, peer)) => {
                backoff = Duration::from_millis(1);
                crate::metrics::get().on_accept();
                // 每连接取一次当前接受器：重载后新连接立即用新证书，在途握手不被打断
                let current_tls = if is_tls {
                    state.tls_registry.tcp(addr).or_else(|| tls.clone())
                } else {
                    None
                };
                spawn_connection(
                    &mut tasks,
                    Arc::clone(&state),
                    stream,
                    peer,
                    addr,
                    current_tls,
                    listener.http2,
                    alt_svc.clone(),
                    shutdown.clone(),
                );
            }
            Err(e) => {
                // fd 耗尽 / 监听队列异常：指数退避，避免刷错误日志把 CPU 打满
                log_warn!("{addr} accept 失败: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => break,
                }
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
        }
    }

    // 先关闭监听 socket 再排空：grace 期间到达的新连接应立即被拒绝，
    // 而不是在 backlog 里排到进程退出才被重置（nginx 的 listen close 语义）。
    drop(tcp);
    drain_connections(&mut tasks, state.settings.shutdown_grace, addr).await;
}

/// 停机时在 grace 期内等在途连接自然结束，超时后强制断开（nginx 的 graceful shutdown 语义）。
/// HTTP/1.1、HTTP/2、HTTP/3 与 L4 stream 共用同一套排空逻辑。
pub(crate) async fn drain_connections(
    tasks: &mut tokio::task::JoinSet<()>,
    grace: Duration,
    addr: SocketAddr,
) {
    if tasks.is_empty() {
        return;
    }
    log_info!(
        "{addr} 停止接收，等待 {} 条在途连接结束（最多 {grace:?}）",
        tasks.len()
    );
    let started = Instant::now();
    while !tasks.is_empty() {
        let remaining = grace.saturating_sub(started.elapsed());
        tokio::select! {
            _ = tasks.join_next() => {}
            _ = tokio::time::sleep(remaining) => {
                if !tasks.is_empty() {
                    log_warn!("{addr} 优雅停机超时 {grace:?}，强制断开 {} 条连接", tasks.len());
                    tasks.abort_all();
                }
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn spawn_connection(
    tasks: &mut tokio::task::JoinSet<()>,
    state: Arc<AppState>,
    stream: TcpStream,
    peer: SocketAddr,
    listener: SocketAddr,
    tls: Option<TlsAcceptor>,
    enable_h2c: bool,
    alt_svc: Option<String>,
    shutdown: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        // 连接额度：拿不到就快速拒绝，而不是排队（保护后端与自身 fd）
        let permit: Option<OwnedSemaphorePermit> = state.permits.clone().try_acquire_owned().ok();
        if permit.is_none() {
            match &tls {
                // 明文：回一个 503 让客户端知道是过载而不是网络故障；TLS：直接关闭（握手都还没做）
                None => reject_overloaded(stream).await,
                Some(_) => drop(stream),
            }
            log_debug!("连接数已达 worker_connections，拒绝 {peer}");
            return;
        }
        let _permit = permit.expect("checked above");
        let _active = crate::metrics::ActiveConnGuard::new(crate::metrics::get());
        let _ = stream.set_nodelay(state.settings.tcp_nodelay);
        match tls {
            None => {
                // 明文且监听开了 http2：嗅探 HTTP/2 客户端连接前导（prior-knowledge h2c），
                // 命中就按 h2c 服务，否则回落到 HTTP/1.1（peek 不消费字节，h1 仍能完整读请求行）
                let h2c = if enable_h2c {
                    sniff_h2c_preface(&stream).await
                } else {
                    false
                };
                let meta = Arc::new(ConnMeta {
                    listener,
                    peer: Some(peer),
                    scheme: "http",
                    http1: !h2c,
                    alt_svc,
                    requests: Arc::new(AtomicU64::new(0)),
                });
                drive(state, TokioIo::new(stream), meta, shutdown).await;
            }
            Some(acceptor) => {
                let handshake = tokio::time::timeout(
                    state.settings.tls_handshake_timeout,
                    acceptor.accept(stream),
                );
                let (tls_stream, h2) = match handshake.await {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(e)) => {
                        crate::metrics::get().on_tls_handshake_failure();
                        // nginx 对握手失败也是在 error 日志里点名对端：这通常意味着对端
                        // 只提供了我们不协商的曲线/密码套件，只有失败现场能看出来。
                        crate::log_warn!("TLS 握手失败 {peer}: {e}");
                        return;
                    }
                    Err(_) => {
                        crate::metrics::get().on_tls_handshake_failure();
                        crate::log_warn!(
                            "TLS 握手超时（{:.0?}）{peer}",
                            state.settings.tls_handshake_timeout
                        );
                        return;
                    }
                };
                // ALPN（或后端类型）决定这条连接走 h2 还是 h1：rustls 看 ALPN，原生 legacy 恒为 h1
                let meta = Arc::new(ConnMeta {
                    listener,
                    peer: Some(peer),
                    scheme: "https",
                    http1: !h2,
                    alt_svc,
                    requests: Arc::new(AtomicU64::new(0)),
                });
                drive(state, TokioIo::new(tls_stream), meta, shutdown).await;
            }
        }
    });
}

/// 嗅探明文连接是否以 HTTP/2 客户端连接前导（24 字节 magic）开头 → prior-knowledge h2c。
/// 用 `peek`（MSG_PEEK，不消费字节）：h2c 命中后 hyper 仍会读到完整前导；未命中则原样交给 h1。
/// 分多次 peek 累积（TCP 可能分包），拿到 24 字节或读不到新字节即止，全程带短超时防挂起。
async fn sniff_h2c_preface(stream: &TcpStream) -> bool {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut buf = [0u8; 24];
    let mut filled = 0usize;
    for _ in 0..32 {
        let res =
            tokio::time::timeout(Duration::from_millis(100), stream.peek(&mut buf[filled..])).await;
        match res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                filled += n;
                if filled >= 24 {
                    break;
                }
            }
            _ => break, // 超时或出错：当作非 h2c，回落 h1（后续 h1 读会正常处理或超时）
        }
    }
    filled >= 24 && &buf[..] == PREFACE
}

/// 过载快速拒绝：写一个 503 并关闭
async fn reject_overloaded(mut stream: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = b"service busy\r\n";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nserver: {SERVER_HEADER}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut buf = Vec::with_capacity(resp.len() + body.len());
    buf.extend_from_slice(resp.as_bytes());
    buf.extend_from_slice(body);
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&buf)).await;
    let _ = stream.shutdown().await;
    // 请求还在内核接收缓冲里没被读过，立即 close 会发 RST，把刚写出的 503 冲掉。
    // 半关闭后给客户端几十毫秒排空（正常客户端读到 503 即关闭，不会真的等满）。
    let mut sink = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_millis(50), async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// 一条连接的读写循环：按 ALPN/明文选择 h1 或 h2，并在停机信号到来时优雅收尾
async fn drive<I>(
    state: Arc<AppState>,
    io: TokioIo<I>,
    meta: Arc<ConnMeta>,
    shutdown: watch::Receiver<bool>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = Gateway {
        state: Arc::clone(&state),
        meta: Arc::clone(&meta),
    };
    let timer = TokioTimer::new();
    if meta.http1 {
        let mut builder = http1::Builder::new();
        builder
            .timer(timer)
            // hyper 的读头超时同时覆盖"慢速发头"与 keep-alive 空闲等待
            .header_read_timeout(state.settings.client_header_timeout)
            .max_headers(MAX_REQUEST_HEADERS)
            .max_header_size(PARSE_CEILING_BYTES)
            .ignore_invalid_headers(false)
            .title_case_headers(false)
            .writev(true);
        let conn = builder.serve_connection(io, service).with_upgrades();
        serve_conn(conn, shutdown, |c| c.graceful_shutdown()).await;
    } else {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(timer)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .adaptive_window(true)
            .keep_alive_interval(Some(state.settings.keepalive_timeout))
            .keep_alive_timeout(state.settings.client_body_timeout);
        let conn = builder.serve_connection(io, service);
        serve_conn(conn, shutdown, |c| c.graceful_shutdown()).await;
    }
}

/// 驱动一条连接直到结束；停机信号触发 `graceful` 后继续 poll 直到在途请求写完
async fn serve_conn<F, G>(conn: F, mut shutdown: watch::Receiver<bool>, graceful: G)
where
    F: Future<Output = Result<(), hyper::Error>>,
    G: Fn(Pin<&mut F>),
{
    let mut conn = Box::pin(conn);
    loop {
        tokio::select! {
            r = conn.as_mut() => {
                if let Err(e) = r {
                    // 客户端提前断开/畸形请求属于常态，落在 debug 级别避免日志被打满
                    log_debug!("连接结束: {e}");
                }
                break;
            }
            changed = shutdown.changed() => {
                // 只有真正进入停机状态才收尾，避免 receiver 被关闭时误触发
                if changed.is_ok() && *shutdown.borrow_and_update() {
                    graceful(conn.as_mut());
                }
            }
        }
    }
}

// ==================== Service：每请求一次 ====================

pub struct Gateway {
    pub state: Arc<AppState>,
    pub meta: Arc<ConnMeta>,
}

/// 请求句柄被丢弃（客户端断开、连接被取消）时补一条访问日志
struct EmitGuard {
    rec: Arc<LogRecord>,
    log: Arc<AccessLog>,
}

impl Drop for EmitGuard {
    fn drop(&mut self) {
        self.log.finish(&self.rec);
    }
}

impl Service<Request<Incoming>> for Gateway {
    type Response = BoxResponse;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<BoxResponse, Infallible>> + Send + 'static>>;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let meta = Arc::clone(&self.meta);
        let remote = meta
            .peer
            .map(|p| p.ip().to_string())
            .unwrap_or_else(|| "-".into());
        let rec = state.access_log.record(
            remote,
            req.method().as_str().to_string(),
            request_target(req.uri(), req.version()),
            proto_name(req.version()).to_string(),
            header_of(&req, "referer").unwrap_or_else(|| "-".into()),
            header_of(&req, "user-agent").unwrap_or_else(|| "-".into()),
        );

        // keep-alive 请求数上限（nginx keepalive_requests）：第 N 条之后主动关闭连接。
        // h2 不能用 Connection 头，交由 keep_alive_interval / 停机时的 GOAWAY 处理。
        let seq = meta.requests.fetch_add(1, Ordering::Relaxed) + 1;
        crate::metrics::get().on_request();
        // Cache governor: one fetch_add into the 32-slot window per request while
        // the feature is on. With `cache_governor off` (the default) this branch
        // is never taken and the request path is unchanged.
        if state.governor.enabled() {
            state.governor.note_request(unix_now() as u64);
        }
        let must_close = meta.http1 && seq >= state.settings.keepalive_requests as u64;

        // gzip 判定要在 `req` 被 move 进 handle_request 之前取走请求头的 Accept-Encoding。
        let accept_encoding = header_of(&req, "accept-encoding").unwrap_or_default();

        Box::pin(async move {
            let _guard = EmitGuard {
                rec: Arc::clone(&rec),
                log: Arc::clone(&state.access_log),
            };
            // HTTP/1.1 的 Upgrade（WebSocket）只能在 hyper 连接上接管原始 socket；其余请求
            // （含 HTTP/2）以及 HTTP/3 都走同一个传输无关核心 handle_request，请求体先擦成 BoxBody。
            let handled = if crate::proxy::is_upgrade_request(req.headers()) {
                std::panic::AssertUnwindSafe(handle_upgrade(
                    Arc::clone(&state),
                    Arc::clone(&meta),
                    Arc::clone(&rec),
                    &mut req,
                ))
                .catch_unwind()
                .await
            } else {
                let breq =
                    req.map(|b| b.map_err(|e| Box::new(e) as crate::proxy::BoxError).boxed());
                std::panic::AssertUnwindSafe(handle_request(
                    Arc::clone(&state),
                    Arc::clone(&meta),
                    Arc::clone(&rec),
                    breq,
                ))
                .catch_unwind()
                .await
            };
            let resp = match handled {
                Ok(r) => r,
                Err(p) => {
                    log_error!("请求处理 panic（已隔离，返回 500）: {}", panic_text(&p));
                    error_page(StatusCode::INTERNAL_SERVER_ERROR)
                }
            };
            let mut resp = finalize(&state, &rec, resp, must_close, &accept_encoding);
            // Alt-Svc 广播 HTTP/3 可用性（仅 h1/h2 over TLS；h3 上再广播 h3 无意义）
            if let Some(av) = &meta.alt_svc {
                if let Ok(v) = HeaderValue::from_str(av) {
                    resp.headers_mut().insert("alt-svc", v);
                }
            }
            Ok(resp)
        })
    }
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "未知 panic".to_string()
    }
}

/// 统一收尾：状态码记账、Server 头策略、过载关闭、gzip 压缩、响应体字节计数 + 落日志
fn finalize(
    state: &AppState,
    rec: &Arc<LogRecord>,
    resp: BoxResponse,
    must_close: bool,
    accept_encoding: &str,
) -> BoxResponse {
    rec.set_status(resp.status().as_u16());
    crate::metrics::get().record_status(resp.status().as_u16());
    let (mut parts, body) = resp.into_parts();
    if state.settings.server_tokens {
        if !parts.headers.contains_key(SERVER) {
            if let Ok(v) = HeaderValue::from_str(SERVER_HEADER) {
                parts.headers.insert(SERVER, v);
            }
        }
    } else {
        parts.headers.remove(SERVER);
    }
    if must_close {
        parts
            .headers
            .insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
    }
    let head = rec.method == "HEAD";

    // 已知线上字节长度：优先取显式 Content-Length，否则从 body 的 exact size_hint 推断。
    // 静态文件走 Full 体，Content-Length 由 hyper 在实际编码时才补上，此时 headers 里还没有，
    // 若不查 size_hint 就会把定长小文件误判成流式、绕过 gzip_min_length。
    let wire_len = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .or_else(|| body.size_hint().exact().map(|n| n as usize));

    // gzip 判定（对标 nginx：gzip on + 命中 gzip_types + 长度阈值 + 客户端接受）：
    // 仅在开启、2xx 成功、非 HEAD、体本身未带 Content-Encoding、客户端 Accept-Encoding 接受 gzip、
    // Content-Type 命中可压缩类型、且（已知长度时）不小于 gzip_min_length 时压缩。
    // 流式/未知长度的响应尽力压缩（nginx 亦按缓冲后的实际长度衡量，这里宁多不少）。
    let do_gzip = state.settings.gzip.enabled
        && !head
        && parts.status.is_success()
        && !parts.headers.contains_key(CONTENT_ENCODING)
        && accepts_gzip(accept_encoding)
        && parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| state.settings.gzip.eligible_content_type(ct))
        && match wire_len {
            Some(n) => n >= state.settings.gzip.min_length,
            None => true,
        };

    let body = if rec.mark_wrapped() {
        body
    } else {
        // GzipBody 必须包在 LoggedBody 之内，才能让访问日志的 bytes_sent 反映真实压缩后的线上字节。
        let base: RespBody = if do_gzip {
            // 压缩改变了字节数：移除 Content-Length（交由传输层分帧），标注 Content-Encoding: gzip，
            // 并按 nginx 追加 Vary: Accept-Encoding。
            parts.headers.remove(CONTENT_LENGTH);
            parts
                .headers
                .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            append_vary(&mut parts.headers);
            GzipBody::new(body, state.settings.gzip.comp_level).boxed()
        } else {
            body
        };
        LoggedBody {
            inner: base,
            rec: Arc::clone(rec),
            log: Arc::clone(&state.access_log),
            count: !head,
        }
        .boxed()
    };
    Response::from_parts(parts, body)
}

/// 追加 `Vary: Accept-Encoding`，保留既有的 Vary 值且不重复（nginx 压缩响应必带 Vary）。
fn append_vary(headers: &mut hyper::HeaderMap) {
    match headers.get_mut(VARY) {
        Some(existing) => {
            let already = existing
                .to_str()
                .map(|s| {
                    s.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
                })
                .unwrap_or(false);
            if already {
                return;
            }
            let merged = match existing.to_str() {
                Ok(s) => format!("{}, Accept-Encoding", s),
                Err(_) => "Accept-Encoding".to_string(),
            };
            if let Ok(nv) = HeaderValue::from_str(&merged) {
                *existing = nv;
            }
        }
        None => {
            headers.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
        }
    }
}

/// 包一层响应体：累计真实写出的字节数，并在响应体生命周期结束时落访问日志
struct LoggedBody {
    inner: RespBody,
    rec: Arc<LogRecord>,
    log: Arc<AccessLog>,
    count: bool,
}

impl Body for LoggedBody {
    type Data = Bytes;
    type Error = crate::proxy::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        // SAFETY: `inner` 是一个自创建起就被结构固定的 Pin<Box<..>>，这里只把它重新借成
        // Pin<&mut _> 交给 poll_frame，从不把字段移出 LoggedBody，不违反 pin 契约。
        let this = unsafe { self.get_unchecked_mut() };
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if this.count {
                    if let Some(bytes) = frame.data_ref().map(|d| d.len()) {
                        this.rec.add_bytes(bytes);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        self.rec.emit(&self.log);
    }
}

// ==================== 请求处理 ====================

/// 传输无关的请求核心：入参请求体已被擦除成 `ProxyReqBody`（BoxBody<Bytes, BoxError>），
/// 因此 HTTP/1.1、HTTP/2（hyper `Incoming`）与 HTTP/3（h3 请求流）都能喂进同一套阶段管线
/// （vhost/location/rewrite/access/try_files/content/proxy/lua）。返回的 `BoxResponse` 由各自
/// 传输层负责把 `RespBody` 落成线上字节。
/// vhost 匹配要用的主机名。HTTP/1.x 在 `Host` 头里；HTTP/2 **没有 Host 头**，主机在
/// `:authority` 伪头上，hyper 把它放进 URI 的 authority。只读 `Host` 的后果不是报错而是
/// 静默串站：h2 上每个请求的 host 都是 None，于是永远落到 default_server（没配 default 时
/// 全体落到 vhost 列表第一个）。绝对形式请求行（`GET http://host/ HTTP/1.1`）走同一条兜底。
/// h2/h3 的请求体没有 `Content-Length`，也没有 `Transfer-Encoding: chunked`——字节就在
/// DATA 帧里，流的 END_STREAM 标志就是体的结束。所以"这两个头有没有"在 h2/h3 上完全不能
/// 用来判断"要不要读体"：实测过一个 64 KB 的 POST，`ctx.req_body` 是空的，源站收到的
/// 请求连 Content-Length 都没有，等于**API 的写操作在 h2/h3 上被静默清空**，而 h1 一切正常。
/// 对分帧协议一律按"可能带体"处理：没有 DATA 帧时读到的就是空字节，代价只有一次轮询。
fn body_rides_on_framing(version: http::Version) -> bool {
    matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3)
}

fn request_host(headers: &hyper::HeaderMap, uri: &hyper::Uri) -> Option<String> {
    if let Some(h) = headers
        .get(HOST_NAME)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return Some(h.to_string());
    }
    uri.authority().map(|a| a.as_str().to_string())
}

/// `$request_uri` 的取值。h1 就是请求行里的原始 target（origin-form 与绝对形式都原样保留）；
/// h2/h3 没有请求行，hyper 会把 `:scheme`/`:authority` 一起重建成绝对 `Uri`，直接
/// `to_string()` 会让 `$request_uri` 变成 `https://host/path`，插进
/// `return 302 https://main$request_uri` 就拼出两个 URL 相连。分帧协议上它只能是
/// `:path`（RFC 9113 §8.3.1），含原始 query，不解码。
fn request_target(uri: &hyper::Uri, version: http::Version) -> String {
    if matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3) {
        match uri.query() {
            Some(q) => format!("{}?{}", uri.path(), q),
            None => uri.path().to_string(),
        }
    } else {
        uri.to_string()
    }
}

async fn handle_request(
    state: Arc<AppState>,
    meta: Arc<ConnMeta>,
    rec: Arc<LogRecord>,
    req: Request<crate::proxy::ProxyReqBody>,
) -> BoxResponse {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let version = parts.version;
    let uri = parts.uri.clone();
    let headers = &parts.headers;

    // ---- POST_READ：畸形/越权请求直接在入口拒绝（对齐 nginx 的 400/414/501）----
    if !is_supported_method(&method) {
        return error_page(StatusCode::NOT_IMPLEMENTED);
    }
    let raw_path = uri.path().to_string();
    if raw_path.len() > MAX_URI_BYTES || uri.query().map(|q| q.len()).unwrap_or(0) > MAX_URI_BYTES {
        return error_page(StatusCode::URI_TOO_LONG);
    }
    // 头块总额：hyper 的解析上限留了余量（见 PARSE_CEILING_BYTES），这里按 nginx 的额度自己判，
    // 才能把"URI 太长"和"头太多"分开告诉客户端
    let head_bytes = headers.iter().fold(0usize, |acc, (k, v)| {
        acc + k.as_str().len() + v.as_bytes().len() + 4
    });
    if head_bytes > MAX_HEADER_BYTES {
        return error_page(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    if version == Version::HTTP_11 && headers.get(HOST_NAME).is_none() {
        return error_page(StatusCode::BAD_REQUEST);
    }
    // RFC 9112 §6.1：一个请求**只能有一条** Host。多条时 nginx 回 400；以前我们悄悄取第一条，
    // 而第一条常常是客户端库自动加的 `127.0.0.1:端口`（显式写的那条在后面）——于是请求落到
    // 该端口的默认站点：一个"看起来完全正常"的跨站点内容路由错误。宁可拒掉，不猜。
    let host_lines = headers.get_all(HOST_NAME).iter().count();
    if host_lines > 1 {
        log_warn!("请求带 {host_lines} 条 Host 头，按 RFC 9112 拒绝（400）");
        return error_page(StatusCode::BAD_REQUEST);
    }
    // Transfer-Encoding：只接受纯 chunked；CL+TE 并存是请求走私的经典形态，一律拒绝
    let te = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .map(|v| v.to_str().unwrap_or("").trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let chunked = te.iter().any(|v| v == "chunked");
    if !te.is_empty() && (!chunked || te.len() != 1 || te.iter().any(|v| v != "chunked")) {
        return error_page(StatusCode::BAD_REQUEST);
    }
    let cl_values: Vec<&HeaderValue> = headers.get_all(CONTENT_LENGTH).iter().collect();
    if cl_values.len() > 1 {
        return error_page(StatusCode::BAD_REQUEST);
    }
    // CL 与 TE 并存：RFC 9112 §6.1 允许收件方"要么 400，要么 TE 优先并忽略 CL"。
    // hyper 走的是后者（解析时就地删掉 CL，只留 chunked），所以我们看不到那两个头同时存在；
    // 这 3 行是给 hyper 语义变化兜底的后盾，不让歧义悄悄变成走私面。
    if chunked && !cl_values.is_empty() {
        return error_page(StatusCode::BAD_REQUEST);
    }
    if let Some(v) = cl_values.first() {
        if v.to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_none()
        {
            return error_page(StatusCode::BAD_REQUEST);
        }
    }

    // 匹配 location 之前先做 URL 解码 + dot-segment 归一化：
    // 匹配与静态文件解析用解码后的路径，转发/日志仍用原始 URI（nginx 的 r->uri / r->unparsed_uri 之分）
    let path = match decode_and_normalize(&raw_path) {
        Some(p) => p,
        None => return error_page(StatusCode::BAD_REQUEST),
    };
    let host = request_host(&headers, &uri);
    let router = state.routing();
    let server = match router.match_server(meta.listener, host.as_deref()) {
        Some(s) => Arc::clone(s),
        None => return error_page(StatusCode::NOT_FOUND),
    };

    let mut ctx = RequestCtx {
        method: method.as_str().to_string(),
        path,
        query: uri.query().unwrap_or("").to_string(),
        uri: request_target(&uri, version),
        host,
        remote_addr: rec.remote(),
        remote_port: meta.peer.map(|p| p.port()).unwrap_or(0),
        server_port: meta.listener.port(),
        req_headers: header_pairs(headers),
        resp_headers: Vec::new(),
        rewritten_path: None,
        status: 200,
        body: None,
        stream: None,
        done: false,
        internal_redirect: false,
        req_body: Bytes::new(),
        exec_depth: 0,
        redirect: None,
        scheme: meta.scheme.to_string(),
        internal_request: false,
        filter_chunk: None,
        filter_eof: false,
        listener: Some(meta.listener),
        capture_depth: 0,
        balancer_peer: None,
        balancer_timeouts: None,
        balancer_more_failures: None,
        balancer_recreate_request: false,
        upstream_addr: String::new(),
        upstream_status: 0,
        proxy_split: String::new(),
        proxy_split_served: String::new(),
        upstream_header_time: 0.0,
        ssl: None,
        start_time: unix_now(),
        http_version: http_version_f64(version),
        body_builder: None,
        eof_sent: false,
        cache_status: String::new(),
        still_online: String::new(),
        front_proxy: String::new(),
        front_proxy_country: String::new(),
        front_proxy_host: String::new(),
        front_proxy_verified: false,
        realip_remote_addr: meta.peer.map(|p| p.ip().to_string()).unwrap_or_default(),
        set_vars: Vec::new(),
        rewrite_return: None,
    };

    // ---- realip / limit_conn（Upgrade 与普通请求共用同一实现）----
    apply_realip(&server, &mut ctx, meta.peer);
    apply_front_proxy(&server, &mut ctx, meta.peer);
    // 访问日志与 $remote_addr 保持一致：日志记录的是 realip 之后的客户端地址
    rec.set_remote(ctx.remote_addr.clone());
    // ---- 请求体：默认边读边限长缓冲；`proxy_request_buffering off` 的 proxy location 走流式转发 ----
    // location 先匹配一次：limit_conn 允许写在 location 里，请求体上限也有 location 级覆盖。
    let loc0 = Router::match_location(&server, ctx.effective_path());
    let conn_guards = match acquire_conn_guards(&state, &server, loc0, &ctx) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    let limit = loc0
        .and_then(|l| l.client_max_body_size)
        .or(server.client_max_body_size);
    let has_body = chunked || cl_values.first().is_some() || body_rides_on_framing(version);
    // 流式条件：命中带 proxy_pass 且 buffering=off 的 location，且确实带请求体
    let stream_body = has_body
        && loc0
            .map(|l| l.proxy_pass.is_some() && !l.proxy_request_buffering)
            .unwrap_or(false);
    let inbound = if stream_body {
        // 流式路径同样受 client_body_timeout 约束（在 StreamBodyGuard 里逐帧计时）
        let idle_body = state.settings.client_body_timeout;
        // 分块无法预先限长；声明了 Content-Length 时先做 upfront 拒绝，
        // 其余（chunked / 谎报长度）在转发途中由 BodyLimitBody 边数边限。
        if let Some(max) = limit {
            if let Some(declared) = cl_values
                .first()
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                if declared > max {
                    return close_now(error_page(StatusCode::PAYLOAD_TOO_LARGE));
                }
            }
        }
        let body = match limit {
            Some(max) if max != u64::MAX => StreamBodyGuard::new(body, max, idle_body).boxed(),
            _ => StreamBodyGuard::new(body, u64::MAX, idle_body).boxed(),
        };
        ProxyBody::Streaming(Some(body))
    } else {
        let body_bytes = if has_body {
            match read_body(body, limit, state.settings.client_body_timeout).await {
                Ok(b) => b,
                Err(BodyFail::TooLarge) => {
                    // 体没读完就返回：必须断开，否则残留字节会被当成下一个请求
                    return close_now(error_page(StatusCode::PAYLOAD_TOO_LARGE));
                }
                Err(BodyFail::Timeout) => {
                    return close_now(error_page(StatusCode::REQUEST_TIMEOUT))
                }
                Err(BodyFail::Io) => return close_now(error_page(StatusCode::BAD_REQUEST)),
            }
        } else {
            Bytes::new()
        };
        ctx.req_body = body_bytes.clone();
        ProxyBody::Buffered(Some(body_bytes))
    };

    let mut scope = RequestScope {
        guards: conn_guards,
        streamed: false,
        allow_stream: true,
    };
    let resp = process(&state, &mut ctx, &server, inbound, &mut scope).await;
    // 访问日志的 $upstream_*：处理结束（含换节点重试）后回填。
    // 流式响应的 ctx 已移交后台任务，此处读不到，日志按无上游记录。
    if !scope.streamed {
        rec.set_upstream(
            ctx.upstream_addr.clone(),
            ctx.upstream_status,
            ctx.upstream_header_time,
        );
    }
    // ---- LOG 阶段：log_by_lua / log_by_rust（响应已成形）。脚本在 ctx 的副本上运行，
    // 其 ngx.say 等写入落到副本、不回灌已发送的 resp；失败只记日志，不改变响应。----
    // 流式响应把这段收尾转交给了后台的 Lua 任务（此时 ctx 已不属于本函数）。
    if !scope.streamed {
        if let Some(loc) = Router::match_location(&server, ctx.effective_path()) {
            let has_log = loc.lua_phases.iter().any(|(p, _, _)| *p == Phase::Log)
                || loc.rust_phases.iter().any(|(p, _)| *p == Phase::Log);
            if has_log {
                ctx.status = resp.status().as_u16();
                run_log_phase(&state, &mut ctx, loc).await;
            }
        }
    }
    // conn_guards 到这里才释放：整个请求处理期间都占着并发额度
    // （流式请求的额度在后台任务末尾释放，覆盖脚本实际在跑的时长）
    drop(scope);
    resp
}

/// 运行 LOG 阶段。rust 处理器直接用 &mut ctx；lua 在 ctx 的克隆上跑，避免影响已发送响应。
async fn run_log_phase(state: &Arc<AppState>, ctx: &mut RequestCtx, loc: &Location) {
    for (p, spec) in &loc.rust_phases {
        if *p != Phase::Log {
            continue;
        }
        if let Err(e) = state.handlers.run_phase(Phase::Log, spec, ctx).await {
            log_error!("log_by_rust '{}' 失败: {e}", spec.name);
        }
    }
    for (p, name, src) in &loc.lua_phases {
        if *p != Phase::Log {
            continue;
        }
        let shared = Arc::new(Mutex::new(ctx.clone()));
        if let Err(e) = state.lua.run_phase(name, src, Arc::clone(&shared)).await {
            log_error!("{name} 执行失败: {e}");
        }
    }
}

/// content_by_lua 的流式启动结果。
enum StreamStart {
    /// 头已成形、脚本转到后台继续跑，响应立即可发
    Streamed(BoxResponse),
    /// 脚本在首次输出前就结束了：ctx 已交回，继续走原有的缓冲路径
    Completed(Option<AppError>),
}

/// 尝试流式运行 content_by_lua：
/// - 首次 ngx.flush（或缓冲越过阈值）时，用此刻的 status/响应头立刻回响应；
/// - 脚本跑完都没 flush → 取回 ctx，让调用方继续走缓冲路径（行为与之前完全一致）；
/// - 出错同样交回 ctx，由调用方按 500 收尾。
async fn start_streaming_content(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &Arc<Server>,
    loc: &Location,
    name: &str,
    src: &crate::lua_engine::LuaSource,
    scope: &mut RequestScope,
) -> StreamStart {
    let (tx, mut rx) = tokio::sync::mpsc::channel(STREAM_CHANNEL_CAPACITY);
    // 流式响应在首次 flush 时头就定型，之后 ctx 被移交给后台 Lua 任务无法再求值：
    // 此刻就把 add_header 的变量展开好带进 StreamSink。
    let extra = router::effective_add_headers(Some(loc), server)
        .into_iter()
        .map(|(k, v)| (k.clone(), crate::proxy::interpolate_vars(v, ctx)))
        .collect();
    ctx.stream = Some(StreamSink::new(tx, extra));
    let shared = Arc::new(Mutex::new(std::mem::take(ctx)));
    let engine = Arc::clone(&state.lua);
    let shared_for_lua = Arc::clone(&shared);
    let name_owned = name.to_string();
    let src_owned = src.clone();
    let mut lua_fut = Box::pin(async move {
        engine
            .run_phase(&name_owned, &src_owned, shared_for_lua)
            .await
    });

    // biased：脚本 flush 后立刻返回时通道里已有 Head，优先按流式收尾，避免
    // 缓冲路径拿到的是已被 flush 搬空的 body。
    let mut finished: Option<Result<(), AppError>> = None;
    let head = tokio::select! {
        biased;
        ev = rx.recv() => match ev {
            Some(StreamEvent::Head { status, headers }) => Some((status, headers)),
            _ => None,
        },
        res = &mut lua_fut => {
            finished = Some(res);
            match rx.try_recv() {
                Ok(StreamEvent::Head { status, headers }) => Some((status, headers)),
                _ => None,
            }
        }
    };

    let Some((status, mut headers)) = head else {
        let mut final_ctx = take_ctx(shared);
        final_ctx.stream = None;
        *ctx = final_ctx;
        return StreamStart::Completed(finished.and_then(|r| r.err()));
    };

    let guards = std::mem::take(&mut scope.guards);
    scope.streamed = true;
    let bg_state = Arc::clone(state);
    let bg_server = Arc::clone(server);
    match finished {
        // Lua 已结束，只剩补发剩余字节/log 阶段
        Some(run) => {
            tokio::spawn(async move {
                finish_streamed(bg_state, bg_server, shared, run, status, guards).await;
            });
        }
        None => {
            tokio::spawn(async move {
                let run = lua_fut.await;
                finish_streamed(bg_state, bg_server, shared, run, status, guards).await;
            });
        }
    }
    // 流式的头在 Head 帧就定型了，expires 在这里补上（与缓冲路径同一份判定）
    headers.extend(expires_pairs(Some(loc), server, status));
    StreamStart::Streamed(stream_response(status, headers, rx))
}

/// 流式响应转到后台后的收尾：补发剩余字节 → 结束响应体 → LOG 阶段 → 释放 limit_conn。
async fn finish_streamed(
    state: Arc<AppState>,
    server: Arc<Server>,
    shared: Arc<Mutex<RequestCtx>>,
    run: Result<(), AppError>,
    status: u16,
    guards: Vec<crate::limit::ConnGuard>,
) {
    let mut ctx = take_ctx(shared);
    // 先关流再跑 LOG 阶段：log_by_lua 再慢也不拖住客户端最后一个字节。
    ctx.drain_and_end_stream().await;
    ctx.status = status;
    if let Err(e) = run {
        log_error!("content_by_lua（已开始流式输出）收尾失败: {e}");
    }
    if let Some(loc) = Router::match_location(&server, ctx.effective_path()) {
        let has_log = loc.lua_phases.iter().any(|(p, _, _)| *p == Phase::Log)
            || loc.rust_phases.iter().any(|(p, _)| *p == Phase::Log);
        if has_log {
            run_log_phase(&state, &mut ctx, loc).await;
        }
    }
    drop(guards);
}

/// 从 Lua 任务的共享句柄取回 ctx（锁中毒也照常取，不让请求崩掉）。
fn take_ctx(shared: Arc<Mutex<RequestCtx>>) -> RequestCtx {
    match Arc::try_unwrap(shared) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}

/// 把流式帧通道包成 hyper 响应体。Head 帧在启动阶段已被消费，这里只转发 Data。
fn stream_response(
    status: u16,
    headers: Vec<(String, String)>,
    rx: tokio::sync::mpsc::Receiver<StreamEvent>,
) -> BoxResponse {
    let body_stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Some(StreamEvent::Data(data)) => {
                    return Some((Ok::<_, crate::proxy::BoxError>(Frame::data(data)), rx));
                }
                Some(StreamEvent::Head { .. }) => continue,
                Some(StreamEvent::End) | None => return None,
            }
        }
    });
    let body: RespBody = BodyExt::boxed(http_body_util::StreamBody::new(body_stream));
    let mut builder =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));
    {
        let hm = builder.headers_mut().unwrap();
        for (k, v) in headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
    }
    builder
        .body(body)
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 有界 + 超时的请求体读取（chunked 与定长都适用）
enum BodyFail {
    TooLarge,
    Timeout,
    Io,
}

async fn read_body(
    body: crate::proxy::ProxyReqBody,
    limit: Option<u64>,
    timeout: Duration,
) -> Result<Bytes, BodyFail> {
    let mut stream = BodyStream::new(body);
    let mut out: Vec<u8> = Vec::new();
    while let Some(frame) = tokio::time::timeout(timeout, stream.next())
        .await
        .map_err(|_| BodyFail::Timeout)?
    {
        match frame {
            Ok(f) => {
                if let Some(data) = f.into_data().ok() {
                    if let Some(max) = limit {
                        if out.len() as u64 + data.len() as u64 > max {
                            return Err(BodyFail::TooLarge);
                        }
                    }
                    out.extend_from_slice(&data);
                }
            }
            Err(_) => return Err(BodyFail::Io),
        }
    }
    Ok(Bytes::from(out))
}

/// `sub_filter` 处理磁盘文件时的缓冲上限：超过则跳过改写、原样流式发送。
/// nginx 的 sub_filter 是流式过滤器（只保留匹配长度的尾巴窗口），代价小；
/// 我们按整段替换实现，必须给它一个硬上限，否则一个指令 + 一个大文件 = 内存放大。
const SUB_FILTER_MAX_BUFFER: u64 = 8 << 20;

/// 只读取文件的 `[start, start+len)` 窗口，而不是整份文件。
/// 旧实现对任意 len 都 `fs::read` 全文件——range 截断与大响应体都会多读多占。
async fn read_file_window(
    path: &std::path::Path,
    start: u64,
    len: u64,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(path).await?;
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(len).read_to_end(&mut buf).await?;
    Ok(buf)
}

/// 流式请求体的字节上限：chunked 没有 Content-Length 可预检，只能边转发边计数。
/// 超限时以 body 错误中断，上游连接随之中断（不会把超出的字节继续塞给后端）。
const STREAM_BODY_LIMIT_ERR: &str = "client_max_body_size exceeded (streamed request body)";
/// 流式请求体的空闲超时：nginx 的 `client_body_timeout` 是"两次读之间"的间隔上限，
/// 缓冲式路径由 read_body 的 per-frame timeout 实现；`proxy_request_buffering off`
/// 绕过 read_body，必须在 body 适配器里补上同一条超时，否则一个慢客户端可以
/// 发一个 chunk 后永久挂住——连接额度、上游连接一起被钉住（慢速拒绝服务）。
const STREAM_BODY_TIMEOUT_ERR: &str = "client_body_timeout exceeded (streamed request body)";

struct StreamBodyGuard {
    inner: crate::proxy::ProxyReqBody,
    max: u64,
    seen: u64,
    /// None = 关闭（`client_body_timeout 0`）
    idle: Option<Duration>,
    /// 用 `Pin<Box<Sleep>>` 持有定时器：本结构体因此保持 `Unpin`，
    /// 可以用 `get_mut()` 而不是 `unsafe get_unchecked_mut()`。
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl StreamBodyGuard {
    fn new(inner: crate::proxy::ProxyReqBody, max: u64, idle: Duration) -> Self {
        let idle = if idle.is_zero() { None } else { Some(idle) };
        let timer = idle.map(|d| Box::pin(tokio::time::sleep(d)));
        StreamBodyGuard {
            inner,
            max,
            seen: 0,
            idle,
            timer,
        }
    }

    /// 收到数据后重新计时（nginx 语义：超时只约束相邻两次读，不是总时长）
    fn rearm(&mut self) {
        if let Some(d) = self.idle {
            self.timer = Some(Box::pin(tokio::time::sleep(d)));
        }
    }
}

impl Body for StreamBodyGuard {
    type Data = Bytes;
    type Error = crate::proxy::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(t) = this.timer.as_mut() {
            if t.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Some(Err(STREAM_BODY_TIMEOUT_ERR.into())));
            }
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let got_data = frame.data_ref().is_some();
                if let Some(data) = frame.data_ref() {
                    this.seen = this.seen.saturating_add(data.len() as u64);
                    if this.seen > this.max {
                        return Poll::Ready(Some(Err(STREAM_BODY_LIMIT_ERR.into())));
                    }
                }
                if got_data {
                    this.rearm();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// 判断 Lua 是否改写过请求体。`Bytes` 不可变，改写只能换一个新分配：
/// 指针与长度都相同即可跳过逐字节比较；指针不同时仍按内容判断，
/// 避免"脚本写了内容相同的新字节"被误当成改写。
fn same_body(a: &Bytes, b: &Bytes) -> bool {
    a.len() == b.len() && (a.as_ptr() == b.as_ptr() || &a[..] == &b[..])
}

/// 子请求（`ngx.location.capture`）的捕获结果：状态码 + 响应头 + 完整响应体。
pub struct CaptureResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 子请求最大嵌套深度（对标 nginx 的子请求计数上限，防 capture 递归成环）。
const MAX_CAPTURE_DEPTH: u8 = 10;

/// 运行一个内部子请求：在与父请求相同的 vhost 下，对 `uri` 跑完整请求管线
/// （rewrite → access → content：静态/return/proxy/嵌套 Lua 皆可），收集响应体返回。
/// 由 Lua 的 capture op 任务在 tokio 任务里调用（父协程此刻已 yield、不持 VM 锁）。
pub async fn run_capture(
    state: &Arc<AppState>,
    parent: &RequestCtx,
    uri: &str,
    method: &str,
    body: &[u8],
) -> Result<CaptureResult, String> {
    if parent.capture_depth >= MAX_CAPTURE_DEPTH {
        return Err("subrequest capture depth limit exceeded".to_string());
    }
    let listener = parent
        .listener
        .ok_or_else(|| "subrequest: parent has no listener".to_string())?;
    // 拆出 path/query 并归一化（与主请求入口一致：解码 + dot-segment 消除）
    let (raw_path, query) = match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (uri.to_string(), String::new()),
    };
    let path =
        decode_and_normalize(&raw_path).ok_or_else(|| "subrequest: invalid uri".to_string())?;
    let router = state.routing();
    let server = router
        .match_server(listener, parent.host.as_deref())
        .map(Arc::clone)
        .ok_or_else(|| "subrequest: no matching server".to_string())?;

    // 子请求 ctx：继承父请求的连接画像（host/remote/scheme/listener），但用独立的
    // path/query/uri/method；内部请求标记为真（可命中 internal location），无请求体。
    let mut ctx = RequestCtx {
        method: method.to_string(),
        path,
        query,
        uri: uri.to_string(),
        host: parent.host.clone(),
        remote_addr: parent.remote_addr.clone(),
        remote_port: parent.remote_port,
        server_port: parent.server_port,
        req_headers: parent.req_headers.clone(),
        resp_headers: Vec::new(),
        rewritten_path: None,
        status: 200,
        body: None,
        stream: None,
        done: false,
        internal_redirect: false,
        req_body: Bytes::copy_from_slice(body),
        exec_depth: 0,
        redirect: None,
        scheme: parent.scheme.clone(),
        internal_request: true,
        filter_chunk: None,
        filter_eof: false,
        listener: Some(listener),
        capture_depth: parent.capture_depth + 1,
        balancer_peer: None,
        balancer_timeouts: None,
        balancer_more_failures: None,
        balancer_recreate_request: false,
        upstream_addr: String::new(),
        upstream_status: 0,
        proxy_split: String::new(),
        proxy_split_served: String::new(),
        upstream_header_time: 0.0,
        ssl: None,
        start_time: unix_now(),
        http_version: parent.http_version,
        body_builder: None,
        eof_sent: false,
        cache_status: String::new(),
        still_online: String::new(),
        // 子请求继承父请求的前置代理画像：同一个连接、同一批请求头，重新判定只会得出同样结论
        front_proxy: parent.front_proxy.clone(),
        front_proxy_country: parent.front_proxy_country.clone(),
        front_proxy_host: parent.front_proxy_host.clone(),
        front_proxy_verified: parent.front_proxy_verified,
        realip_remote_addr: parent.realip_remote_addr.clone(),
        set_vars: Vec::new(),
        rewrite_return: None,
    };
    if !body.is_empty() {
        ctx.req_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        ctx.req_headers
            .push(("content-length".to_string(), body.len().to_string()));
    }

    let mut scope = RequestScope {
        guards: Vec::new(),
        streamed: false,
        allow_stream: false,
    };
    let capture_body = if body.is_empty() {
        ProxyBody::Buffered(None)
    } else {
        ProxyBody::Buffered(Some(Bytes::copy_from_slice(body)))
    };
    let resp = process(state, &mut ctx, &server, capture_body, &mut scope).await;
    let (parts, body) = resp.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|e| format!("subrequest body collect failed: {e}"))?
        .to_bytes();
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    Ok(CaptureResult {
        status: parts.status.as_u16(),
        headers,
        body: collected.to_vec(),
    })
}

/// 请求生命周期资源。流式响应一旦开头，Lua 收尾、LOG 阶段与 limit_conn 额度的
/// 释放都要延后到响应体结束，故由 process 就地转交（streamed=true 时 guards 被移走）。
struct RequestScope {
    guards: Vec<crate::limit::ConnGuard>,
    streamed: bool,
    /// 子请求（ngx.location.capture）要把响应体收集完整，必须走缓冲路径
    allow_stream: bool,
}

/// REWRITE → PREACCESS → ACCESS 的共用入口（普通请求与 WebSocket Upgrade 都走这里，
/// 避免 Upgrade 绕过 allow/deny、auth_basic、限流和 Lua access 阶段）。
/// 返回最终命中的 location；拒绝/跳转/结束请求以 Err(response) 返回。
async fn run_ingress<'a>(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &'a Arc<Server>,
) -> Result<&'a Location, BoxResponse> {
    let mut last_loc: Option<&'a Location> = None;
    // 0) server 级 REWRITE（nginx 的 SERVER-rewrite 相位：在 location 匹配之前）。
    //    这一步的 `set`/`rewrite` 会改变后面的路径与变量，所以必须在匹配之前跑；
    //    `return` 也在这一层就出结果——`server { return 301 https://$host$request_uri; }`
    //    这种"只做跳转的 vhost"本来就没有可匹配的 location。
    //    与 location 级的刻意差异见 engine.rs：location 级 `return` 仍排在访问控制之后。
    if !server.rewrite_steps.is_empty() || server.ret.is_some() {
        // 条件里的 return 也算"这一步有东西要做"，所以上面的判据不能只看裸 return
        ctx.rewrite_return = None;
        engine::apply_rewrite_steps(ctx, &server.rewrite_steps);
        if let Some((code, target)) = ctx.redirect.take() {
            return Err(redirect_response(code, &target));
        }
        // server 级 rewrite 的 last/break 结果只是"路径变了"，直接带进 location 查找；
        // 不占用环检测的额度，否则一条 server 级 rewrite 就吃掉一跳
        ctx.internal_redirect = false;
        // `if (...) { return ...; }` 记在 ctx.rewrite_return 上，裸 `return` 记在 server.ret 上。
        // 两者都算"本相位终止"，条件里的那个优先：它只有在条件成立时才存在，而同时写了
        // 裸 return 的配置本来就是退化的（nginx 里裸 return 之后的指令永远到不了）。
        let ret = ctx.rewrite_return.take().or_else(|| server.ret.clone());
        if let Some(ret) = &ret {
            engine::apply_return(ctx, ret);
            if let Some((code, target)) = ctx.redirect.take() {
                return Err(redirect_response(code, &target));
            }
            return Err(finish_response(ctx, server, last_loc));
        }
    }
    // 停在"还在跳转"状态跑满 10 跳 = 配置成环（nginx: rewrite or internal redirection cycle → 500）
    let mut cycle = false;
    for _ in 0..MAX_URI_CHANGES {
        cycle = true;
        let loc = Router::match_location(server, ctx.effective_path());
        last_loc = loc;
        let Some(loc) = loc else {
            cycle = false;
            break;
        };

        // internal 只允许内部重定向命中（nginx：外部请求访问 internal location → 404）
        if loc.internal && !ctx.internal_request {
            ctx.status = 404;
            return Err(error_page(StatusCode::NOT_FOUND));
        }

        // 1) REWRITE 阶段指令：rewrite / set / if，按配置书写顺序混排执行
        // 记下的 return 属于"本 location 的这一段序列"，重新匹配 location 时必须作废
        ctx.rewrite_return = None;
        if !loc.rewrite_steps.is_empty() {
            engine::apply_rewrite_steps(ctx, &loc.rewrite_steps);
            if let Some((code, target)) = ctx.redirect.take() {
                return Err(redirect_response(code, &target));
            }
            if ctx.internal_redirect {
                ctx.internal_redirect = false;
                ctx.internal_request = true;
                continue;
            }
        }
        // 2) rewrite_by_rust / rewrite_by_lua
        if run_phases(state, ctx, loc, Phase::Rewrite, server).await {
            // 阶段脚本报错必须就此收口：继续往下跑会让"检查没跑成"变成"检查通过"
            return Err(error_response(ctx, server, last_loc, 500).await);
        }
        if let Some((code, target)) = ctx.redirect.take() {
            return Err(redirect_response(code, &target));
        }
        if ctx.done {
            return Err(finish_response(ctx, server, last_loc));
        }
        if ctx.internal_redirect {
            ctx.internal_redirect = false;
            ctx.internal_request = true;
            ctx.exec_depth = ctx.exec_depth.saturating_add(1);
            continue;
        }
        // 3) PREACCESS：limit_req
        if let Some(resp) = check_limit_req(state, ctx, loc).await {
            return Err(resp);
        }
        // 3.5) ACCESS：内置 allow/deny（IP）+ auth_basic（basic auth），先于 access_by_*
        if let Some(resp) = check_access_and_auth(state, ctx, loc, server).await {
            return Err(resp);
        }
        // 4) ACCESS：access_by_rust / access_by_lua
        if run_phases(state, ctx, loc, Phase::Access, server).await {
            // 同上：access 检查脚本加载失败或运行报错 = 拒绝，绝不放行到 content/proxy
            return Err(error_response(ctx, server, last_loc, 500).await);
        }
        if let Some((code, target)) = ctx.redirect.take() {
            return Err(redirect_response(code, &target));
        }
        if ctx.done {
            return Err(finish_response(ctx, server, last_loc));
        }
        if ctx.internal_redirect {
            ctx.internal_redirect = false;
            ctx.internal_request = true;
            ctx.exec_depth = ctx.exec_depth.saturating_add(1);
            continue;
        }

        // return 指令在这里生效：裸 `return` 与 `if` 块里记下的 return 走同一处，
        // 都在 limit_req / allow-deny / auth_basic / access_by_* 之后。nginx 把 return 归
        // rewrite 阶段（先于访问控制），ONRouter 刻意不同：条件 return 不许绕过访问控制。
        let ret = ctx.rewrite_return.clone().or_else(|| loc.ret.clone());
        if let Some(ret) = &ret {
            engine::apply_return(ctx, ret);
            if let Some((code, target)) = ctx.redirect.take() {
                return Err(redirect_response(code, &target));
            }
            return Err(finish_response(ctx, server, Some(loc)));
        }
        return Ok(loc);
    }
    if cycle {
        log_error!(
            "内部重定向成环：'{}' 已跳满 {MAX_URI_CHANGES} 次（检查 rewrite ... last / ngx.exec）",
            ctx.effective_path()
        );
        return Err(error_response(ctx, server, last_loc, 500).await);
    }
    ctx.status = 404;
    Err(error_page(StatusCode::NOT_FOUND))
}

async fn process(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &Arc<Server>,
    body: ProxyBody,
    scope: &mut RequestScope,
) -> BoxResponse {
    let loc = match run_ingress(state, ctx, server).await {
        Ok(loc) => loc,
        Err(resp) => return resp,
    };

    // ---- CONTENT ----
    if let Some(target) = &loc.proxy_pass {
        // proxy_pass 主机位是变量（业务分流）时按请求插值。字面量目标恒走借用这条路：
        // 一个字符都不扫、一次分配都不做，配了分流与否不该让别人的 proxy_pass 变贵。
        let target: std::borrow::Cow<'_, str> = if target.contains('$') {
            crate::proxy::interpolate_vars(target, ctx).into()
        } else {
            target.as_str().into()
        };
        // "比例选中了哪一路"在插值完成的那一刻就定了，所以分流也要写进 ctx：缓存命中时
        // 请求根本没交给节点（`$proxy_split_served` 保持空串），但运营者仍要能看出这条
        // 响应属于哪一路业务。没配分流的 location 一个字符都不扫。
        if loc.route_split.is_some() {
            ctx.proxy_split = crate::proxy::split_target(&target).0.to_string();
        }
        // BALANCER：balancer_by_lua 在转发前运行，Lua 可经 ngx.balancer 选定上游节点/超时
        if run_phases(state, ctx, loc, Phase::Balancer, server).await {
            return error_response(ctx, server, Some(loc), 500).await;
        }
        let headers = router::effective_proxy_headers(loc, server);
        let opts = ProxyOpts {
            set_headers: &headers,
            timeouts: ProxyTimeouts {
                connect: loc.proxy_connect_timeout,
                send: loc.proxy_send_timeout,
                read: loc.proxy_read_timeout,
            },
            next_upstream: &loc.proxy_next_upstream,
            next_upstream_tries: loc.proxy_next_upstream_tries,
            next_upstream_timeout: loc.proxy_next_upstream_timeout,
            tls: &loc.proxy_tls,
            split: loc.route_split.as_ref(),
            split_failover: loc.split_failover.clone(),
            var_targets: loc.var_targets.as_ref(),
        };

        // ---- proxy_cache：仅幂等方法 + 缓冲请求体时参与缓存（流式体无法回放）----
        let caching_zone = loc.proxy_cache.clone();
        let cacheable_method = caching_zone.is_some()
            && loc
                .proxy_cache_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&ctx.method))
            && matches!(body, ProxyBody::Buffered(_));
        let cache_target = if cacheable_method {
            caching_zone
                .clone()
                .map(|zone| (zone, build_cache_key(&loc.proxy_cache_key, ctx, &target)))
        } else {
            None
        };
        // nginx 语义：表达式展开后非空且不为 "0" 即触发
        let bypass = cache_target.is_some() && cache_expr_truthy(&loc.proxy_cache_bypass, ctx);
        let no_cache = cache_target.is_some() && cache_expr_truthy(&loc.proxy_no_cache, ctx);
        let lookup = match (&cache_target, bypass) {
            (Some((zone, key)), false) => {
                let (hit, cached, count, from_disk) = state.proxy_cache.lookup(zone, key);
                Some((zone.clone(), key.clone(), hit, cached, count, from_disk))
            }
            _ => None,
        };
        if let Some((_, _, CacheHit::Hit, Some(resp), _, from_disk)) = &lookup {
            ctx.cache_status = "HIT".to_string();
            let resp = if *from_disk {
                // 磁盘冷层供的命中：状态词仍是 HIT（nginx 的 `$upstream_cache_status` 词表里
                // 没有"磁盘命中"这一档，客户端与 CDN 的判断逻辑不该被我们改宽度），
                // 层级另用一个 ONRouter 自己的头说出来。
                let mut marked = (**resp).clone();
                marked
                    .headers
                    .push(("x-cache-tier".to_string(), "disk".to_string()));
                Arc::new(marked)
            } else {
                Arc::clone(resp)
            };
            return serve_from_cache(resp, loc, server, "HIT", ctx);
        }
        // 过期条目在 stale 滞留期内仍可被 use_stale 回放
        let stale_response = match &lookup {
            Some((_, _, CacheHit::Expired, Some(resp), _, _)) => Some(Arc::clone(resp)),
            _ => None,
        };
        let status_tag = if bypass || (caching_zone.is_some() && cache_target.is_none()) {
            "BYPASS"
        } else {
            match &lookup {
                Some((_, _, CacheHit::Expired, _, _, _)) => "EXPIRED",
                Some((_, _, CacheHit::Miss, _, _, _)) => "MISS",
                _ => "",
            }
        };
        // `$upstream_cache_status`：只有真正参与了缓存的请求才有值。POST 这类非幂等方法、
        // 流式请求体、以及没配 proxy_cache 的 location 都是空串（nginx 同义：没有缓存中的响应
        // 就没有状态），add_header 因此发成一个空值头而不是字面量。
        ctx.cache_status = if cache_target.is_none() {
            String::new()
        } else {
            status_tag.to_string()
        };

        // proxy_cache_lock：同 key 并发 MISS 只放一个请求回源；等待者拿到锁后二次查缓存。
        // `updating` + stale：刷新进行中时直接回放过期内容，避免所有并发请求一起等。
        let mut lock_guard: Option<tokio::sync::OwnedMutexGuard<()>> = None;
        if loc.proxy_cache_lock && !bypass && !no_cache {
            if let Some((zone, key)) = &cache_target {
                let lock = state.proxy_cache.cache_lock(zone, key);
                let mut acquired = None;
                if stale_response.is_some()
                    && use_stale_allows(&loc.proxy_cache_use_stale, "updating")
                {
                    match lock.clone().try_lock_owned() {
                        Ok(g) => acquired = Some(g),
                        Err(_) => {
                            log_debug!("proxy_cache updating: {key} 刷新进行中，回放 stale");
                            ctx.cache_status = "STALE".to_string();
                            return serve_from_cache(
                                Arc::clone(stale_response.as_ref().unwrap()),
                                loc,
                                server,
                                "STALE",
                                ctx,
                            );
                        }
                    }
                }
                if acquired.is_none() {
                    acquired =
                        match tokio::time::timeout(loc.proxy_cache_lock_timeout, lock.lock_owned())
                            .await
                        {
                            Ok(g) => Some(g),
                            Err(_) => {
                                log_warn!(
                                    "proxy_cache_lock 等待超时（{}s），直接回源：{key}",
                                    loc.proxy_cache_lock_timeout.as_secs_f64()
                                );
                                None
                            }
                        };
                }
                if acquired.is_some() {
                    let (hit, cached, from_disk) = state.proxy_cache.peek(zone, key);
                    if hit == CacheHit::Hit {
                        if let Some(resp) = cached {
                            ctx.cache_status = "HIT".to_string();
                            let resp = if from_disk {
                                let mut marked = (*resp).clone();
                                marked
                                    .headers
                                    .push(("x-cache-tier".to_string(), "disk".to_string()));
                                Arc::new(marked)
                            } else {
                                resp
                            };
                            return serve_from_cache(resp, loc, server, "HIT", ctx);
                        }
                    }
                }
                lock_guard = acquired;
            }
        }
        let _lock_guard = lock_guard;

        // min_uses 计数：bypass 请求不做 lookup，但仍要计入“第 N 次才写缓存”
        let use_count = match &lookup {
            Some((_, _, _, _, c, _)) => *c,
            None => match &cache_target {
                Some((zone, key)) => state.proxy_cache.note_use(zone, key),
                None => 0,
            },
        };

        // Lua 的 set_body_data / init_body…finish_body / discard_body 改写的是 ctx.req_body：
        // 转发时以它为准（对标 OpenResty：proxy_pass 发送的是被脚本替换后的请求体）。
        // Bytes 不可变：指针+长度相同即可断定未被改写，省掉每请求一次 memcmp。
        let body = match body {
            ProxyBody::Buffered(Some(ref b)) if !same_body(&ctx.req_body, b) => {
                ProxyBody::Buffered(Some(ctx.req_body.clone()))
            }
            ProxyBody::Buffered(None) if !ctx.req_body.is_empty() => {
                ProxyBody::Buffered(Some(ctx.req_body.clone()))
            }
            other => other,
        };

        // ---- Still ONLine：最后已知良好响应副本（与 proxy_cache 相互独立）----
        // 只有 GET + 缓冲请求体参与：POST 这类"动作"绝不能由别的请求的副本顶替，
        // 流式上传转发到一半失败时后端已经收到过数据，回放副本只会掩盖问题。
        let so_target = match (&loc.still_online, &body) {
            (Some(zone), ProxyBody::Buffered(_)) if ctx.method.eq_ignore_ascii_case("GET") => {
                Some((
                    zone.clone(),
                    build_cache_key(&loc.proxy_cache_key, ctx, &target),
                ))
            }
            _ => None,
        };
        // 凭证闸门（硬规则 3）：请求带 Cookie/Authorization 时**永不**写入副本区；
        // 默认也不回放，`still_online_allow_credentials on` 只放开"读"这一半。
        let so_creds = crate::still_online::request_has_credentials(&ctx.req_headers);
        let so_read = so_target.is_some()
            && (!so_creds || loc.still_online_allow_credentials)
            // proxy_cache_bypass 写明的请求同样不读副本：运维既然要求"绕开缓存"，
            // 副本也是缓存。
            && !cache_expr_truthy(&loc.proxy_cache_bypass, ctx);
        let so_write = so_target.is_some()
            && !so_creds
            && !ctx.internal_request
            && !cache_expr_truthy(&loc.proxy_no_cache, ctx);
        if so_creds && so_target.is_some() {
            state.still_online.note_credential_reject();
        }

        // ---- proxy_cache_revalidate：过期条目先问一次"还是这份吗" ----
        // 带出去的是**缓存里那份**的校验器，并且先把客户端自带的 If-* 摘掉：客户端的
        // If-* 说的是它自己的副本，混在一次条件请求里会把"我们的副本没变"误当成
        // "你的副本没变"而错发 304。没有 ETag/Last-Modified 就没什么可问的，走普通回源。
        let mut revalidate_from: Option<Arc<crate::proxy_cache::CachedResponse>> = None;
        if cache_target.is_some() && loc.proxy_cache_revalidate {
            if let Some(stale) = &stale_response {
                let validators = crate::proxy_cache::revalidation_validators(&stale.headers);
                if !validators.is_empty() {
                    ctx.req_headers.retain(|(k, _)| {
                        !k.eq_ignore_ascii_case("if-none-match")
                            && !k.eq_ignore_ascii_case("if-modified-since")
                            && !k.eq_ignore_ascii_case("if-unmodified-since")
                            && !k.eq_ignore_ascii_case("if-range")
                    });
                    for (k, v) in validators {
                        ctx.req_headers.push((k, v));
                    }
                    revalidate_from = Some(Arc::clone(stale));
                }
            }
        }

        return match state
            .proxy
            .forward(ctx, &target, &loc.pattern, &opts, body)
            .await
        {
            Ok(upstream_resp) => {
                // use_stale http_xxx：上游返回这些状态码时回放过期内容（不覆盖缓存）
                let upstream_status = upstream_resp.status().as_u16();
                // 我们的条件请求拿到 304：对象没变，发存下来的那份，有效期按 304 的头重算。
                // 这一步必须在 use_stale/http_xxx 之前——304 不是失败，是一次成功的确认。
                if let Some(stored) = &revalidate_from {
                    if upstream_status == 304 {
                        // cache_target 一定是 Some：revalidate_from 只在那条路径上才会被赋值
                        let (zone, key) = cache_target.clone().unwrap();
                        return serve_revalidated(
                            state,
                            loc,
                            server,
                            ctx,
                            stored,
                            (&zone, &key),
                            upstream_resp.headers(),
                        )
                        .await;
                    }
                }
                if let Some(stale) = &stale_response {
                    let token = format!("http_{upstream_status}");
                    if use_stale_allows(&loc.proxy_cache_use_stale, &token) {
                        log_warn!(
                            "proxy_cache use_stale {token}：回放过期响应 {}",
                            ctx.effective_path()
                        );
                        ctx.cache_status = "STALE".to_string();
                        return serve_from_cache(Arc::clone(stale), loc, server, "STALE", ctx);
                    }
                }
                // Still ONLine：上游还活着但回了 5xx —— 后端崩溃最常见的形态。
                // 有副本就顶住这次请求（5xx 本身永远进不了副本区）。
                if upstream_status >= 500 && so_read {
                    if let Some((zone, key)) = &so_target {
                        if let Some(resp) = serve_still_online(state, loc, server, ctx, zone, key) {
                            log_warn!(
                                "Still ONLine：上游返回 {upstream_status}，回放副本 {zone} {}",
                                ctx.effective_path()
                            );
                            return resp;
                        }
                    }
                }
                // 未启用缓存：若声明了 header_filter_by_lua/body_filter_by_lua/sub_filter，则缓冲代理
                // 响应并运行过滤器（对齐 nginx：响应过滤器对代理响应同样生效，代价是关闭流式）；
                // 否则保持既有流式转发路径。
                if cache_target.is_none() {
                    let hf = loc.lua_phases.iter().find(|(p, n, _)| {
                        *p == Phase::Content && n.starts_with("header_filter_by_lua")
                    });
                    let bf = loc.lua_phases.iter().find(|(p, n, _)| {
                        *p == Phase::Content && n.starts_with("body_filter_by_lua")
                    });
                    if hf.is_none()
                        && bf.is_none()
                        && !has_wasm_filter(loc)
                        && loc.sub_filter.is_none()
                    {
                        if so_target.is_none() {
                            return convert_upstream_response(upstream_resp, loc, server, ctx);
                        }
                        // 要留副本就必须缓冲整份响应（与 sub_filter/body_filter 同一个取舍）
                        let buffered = match buffer_upstream(upstream_resp).await {
                            Ok(v) => v,
                            Err(e) => {
                                log_error!("代理响应体收集失败: {e}");
                                return error_response(
                                    ctx,
                                    server,
                                    Some(loc),
                                    crate::proxy::upstream_error_status(&e.to_string()),
                                )
                                .await;
                            }
                        };
                        let (status, hdrs, body) = buffered;
                        if so_write {
                            if let Some((zone, key)) = &so_target {
                                store_still_online(
                                    state, loc, ctx, zone, key, status, &hdrs, &body,
                                );
                            }
                        }
                        return build_buffered_response(
                            status, &hdrs, body, loc, server, "", false, ctx,
                        );
                    }
                    // 过滤器需要整体缓冲：收集状态/头/体灌入 ctx 供 Lua 读写
                    let (parts, ibody) = upstream_resp.into_parts();
                    ctx.status = parts.status.as_u16();
                    ctx.resp_headers = Vec::new();
                    for (k, v) in parts.headers.iter() {
                        if is_hop_by_hop(k.as_str()) {
                            continue;
                        }
                        ctx.resp_headers
                            .push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
                    }
                    let collected = match ibody.collect().await {
                        Ok(c) => c.to_bytes(),
                        Err(e) => {
                            log_error!("代理响应体收集失败: {e}");
                            return error_response(
                                ctx,
                                server,
                                Some(loc),
                                crate::proxy::upstream_error_status(&e.to_string()),
                            )
                            .await;
                        }
                    };
                    ctx.body = Some(collected.to_vec());
                    // HEADER FILTER：可改写 ngx.status / ngx.header.*（写回 ctx.status / resp_headers）
                    if let Some((_, name, src)) = hf {
                        if run_lua(state, ctx, name, src).await {
                            log_error!("header_filter_by_lua(代理) 执行失败");
                        }
                    }
                    // BODY FILTER：ngx.arg[1]=响应体块、ngx.arg[2]=eof
                    if let Some((_, name, src)) = bf {
                        ctx.filter_chunk = ctx.body.clone();
                        ctx.filter_eof = true;
                        if run_lua(state, ctx, name, src).await {
                            log_error!("body_filter_by_lua(代理) 执行失败");
                            ctx.status = 500;
                            ctx.body = None;
                        } else if let Some(nc) = ctx.filter_chunk.take() {
                            ctx.body = Some(nc);
                        }
                    }
                    if run_wasm_filters(loc, ctx, true) {
                        return error_response(ctx, server, Some(loc), 500).await;
                    }
                    let body_bytes = bytes::Bytes::from(ctx.body.take().unwrap_or_default());
                    let hdrs = ctx.resp_headers.clone();
                    return build_buffered_response(
                        ctx.status, &hdrs, body_bytes, loc, server, "", false, ctx,
                    );
                }
                let (zone, key) = cache_target.clone().unwrap();
                let status = upstream_status;
                let (parts, ibody) = upstream_resp.into_parts();
                let collected = match ibody.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(e) => {
                        log_error!("代理响应体收集失败: {e}");
                        return error_response(
                            ctx,
                            server,
                            Some(loc),
                            crate::proxy::upstream_error_status(&e.to_string()),
                        )
                        .await;
                    }
                };
                // 存可回放的头：剔除 hop-by-hop 与 content-length（回发时按 body 重算）
                let hdrs: Vec<(String, String)> = parts
                    .headers
                    .iter()
                    .filter(|(k, _)| {
                        !is_hop_by_hop(k.as_str())
                            && k.as_str().to_ascii_lowercase() != "content-length"
                    })
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                // `proxy_ignore_headers`：被点名的头不再参与"能不能缓存、缓存多久"的判定，
                // 但它们仍然照原样存下来、透传给客户端（nginx 是"停止处理"，不是"删除"）。
                let counts = |name: &str| {
                    crate::proxy_cache::header_counts_for_cache(name, &loc.proxy_ignore_headers)
                };
                let has_set_cookie = hdrs
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie") && counts(k));
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let decided: Vec<(String, String)> =
                    hdrs.iter().filter(|(k, _)| counts(k)).cloned().collect();
                let ttl = crate::proxy_cache::effective_ttl(
                    &loc.proxy_cache_valid,
                    status,
                    &decided,
                    now_unix,
                );
                let cacheable = ttl.is_some()
                    && !has_set_cookie
                    && !no_cache
                    // HEAD 只读不写：HEAD 响应无 body，写入会让同 key 的 GET 命中空体
                    // （nginx 用 proxy_cache_convert_head 规避，这里直接不写）
                    && !ctx.method.eq_ignore_ascii_case("HEAD")
                    && use_count >= loc.proxy_cache_min_uses;
                let body = bytes::Bytes::from(collected.to_vec());
                if cacheable {
                    // 替学出来的重要客户写入时做驻留加权：对象在频率草图里更"热"，
                    // 因此下一轮扫库流量来了，被挤掉的是别的条目。见 `vip_learning`。
                    state.proxy_cache.store_as(
                        &zone,
                        &key,
                        crate::proxy_cache::CachedResponse {
                            status,
                            headers: hdrs.clone(),
                            body: Arc::new(body.clone()),
                        },
                        ttl.unwrap(),
                        state.limits.is_vip(&ctx.remote_addr),
                    );
                }
                // 副本区独立写入：proxy_cache 因为 TTL/HEAD/min_uses 不收这条也没关系
                if so_write {
                    if let Some((so_zone, so_key)) = &so_target {
                        store_still_online(state, loc, ctx, so_zone, so_key, status, &hdrs, &body);
                    }
                }
                // 配了 WASM 响应过滤器：缓存里存上游原件，发给客户端的那份过过滤器。
                // 先存后滤是刻意的——否则同一条响应每命中一次就被改写一次，缓存会漂移。
                let (out_status, out_headers, out_body) = if has_wasm_filter(loc) {
                    ctx.status = status;
                    ctx.resp_headers = hdrs;
                    ctx.body = Some(body.to_vec());
                    if run_wasm_filters(loc, ctx, true) {
                        return error_response(ctx, server, Some(loc), 500).await;
                    }
                    (
                        ctx.status,
                        std::mem::take(&mut ctx.resp_headers),
                        Bytes::from(ctx.body.take().unwrap_or_default()),
                    )
                } else {
                    (status, hdrs, body)
                };
                build_buffered_response(
                    out_status,
                    &out_headers,
                    out_body,
                    loc,
                    server,
                    if cacheable { status_tag } else { "BYPASS" },
                    !status_tag.is_empty(),
                    ctx,
                )
            }
            Err(e) => {
                // use_stale error/timeout：回源失败时回放过期内容（缓存不可用时网关仍可用）
                if let Some(stale) = &stale_response {
                    if use_stale_allows(&loc.proxy_cache_use_stale, "error")
                        || use_stale_allows(&loc.proxy_cache_use_stale, "timeout")
                    {
                        log_warn!(
                            "proxy_cache use_stale：回源失败回放过期响应 {}{}: {e}",
                            target,
                            ctx.effective_path()
                        );
                        ctx.cache_status = "STALE".to_string();
                        return serve_from_cache(Arc::clone(stale), loc, server, "STALE", ctx);
                    }
                }
                log_error!("代理失败 {}{}: {e}", target, ctx.effective_path());
                // 流式请求体超限是客户端的问题，按 413 回（其余转发失败按上游语义分 504/502）
                if e.contains(STREAM_BODY_LIMIT_ERR) {
                    return error_response(ctx, server, Some(loc), 413).await;
                }
                // 流式上传卡住同样是客户端问题：nginx 对 client_body_timeout 回 408
                if e.contains(STREAM_BODY_TIMEOUT_ERR) {
                    return error_response(ctx, server, Some(loc), 408).await;
                }
                // Still ONLine：后端连不上/超时——这才是"崩了"的主形态。有副本就顶住，
                // 并把该 key 挂进脏表等恢复后重取；没有副本仍按上游失败的原始语义回
                // （超时 504、连不上/坏响应 502，不编造内容）。
                if so_read {
                    if let Some((zone, key)) = &so_target {
                        if let Some(resp) = serve_still_online(state, loc, server, ctx, zone, key) {
                            log_warn!(
                                "Still ONLine：回源失败，回放副本 {zone} {target}{}: {e}",
                                ctx.effective_path()
                            );
                            return resp;
                        }
                    }
                }
                let code = crate::proxy::upstream_error_status(&e);
                error_response(ctx, server, Some(loc), code).await
            }
        };
    }

    if let Some((_, name, src)) = loc.lua_phases.iter().find(|(p, _, _)| *p == Phase::Content) {
        // header/body filter 与 sub_filter 需要完整响应体才能处理，命中它们时不流式。
        let streamable = scope.allow_stream
            && loc.sub_filter.is_none()
            && !has_wasm_filter(loc)
            && !loc.lua_phases.iter().any(|(p, n, _)| {
                *p == Phase::Content
                    && (n.starts_with("header_filter_by_lua")
                        || n.starts_with("body_filter_by_lua"))
            });
        let failed = if streamable {
            match start_streaming_content(state, ctx, server, loc, name, src, scope).await {
                StreamStart::Streamed(resp) => return resp,
                StreamStart::Completed(err) => match err {
                    Some(e) => {
                        log_error!("{name} 执行失败: {e}");
                        true
                    }
                    None => false,
                },
            }
        } else {
            run_lua(state, ctx, name, src).await
        };
        // 脚本没跑成就是 5xx：这里不能按 ctx 里残留的 200 收尾，否则"缺文件"会变成"空 200"
        if failed {
            return error_response(ctx, server, Some(loc), 500).await;
        }
        if let Some((code, target)) = ctx.redirect.take() {
            return redirect_response(code, &target);
        }
        if ctx.internal_redirect && ctx.exec_depth < MAX_URI_CHANGES as u8 {
            ctx.internal_redirect = false;
            ctx.internal_request = true;
            ctx.exec_depth += 1;
            return Box::pin(process(state, ctx, server, body, scope)).await;
        }
        // 脚本没产出任何响应体也没 exit：继续按静态兜底（对标 content_by_lua 未命中的常见写法）
        if !ctx.done && ctx.body.as_ref().map(|b| b.is_empty()).unwrap_or(true) {
            return serve_static_flow(state, ctx, server, loc, body, scope).await;
        }

        // 执行 header_filter_by_lua（如果存在，用于修改响应头）
        if let Some((_, hfilter_name, hfilter_src)) = loc.lua_phases.iter().find(|(p, n, _)| {
            *p == Phase::Content
                && (n == "header_filter_by_lua" || n == "header_filter_by_lua_file")
        }) {
            if run_lua(state, ctx, hfilter_name, hfilter_src).await {
                log_error!("header_filter_by_lua 执行失败");
            }
        }

        // 执行 body_filter_by_lua（如果存在）
        if let Some((_, filter_name, filter_src)) = loc.lua_phases.iter().find(|(p, n, _)| {
            *p == Phase::Content && (n == "body_filter_by_lua" || n == "body_filter_by_lua_file")
        }) {
            if let Some(response_body) = ctx.body.clone() {
                // 设置 filter 参数
                ctx.filter_chunk = Some(response_body);
                ctx.filter_eof = true;

                // 执行过滤器
                if run_lua(state, ctx, filter_name, filter_src).await {
                    log_error!("body_filter_by_lua 执行失败");
                    ctx.status = 500;
                    ctx.body = None;
                    return finish_response(ctx, server, Some(loc));
                }

                // 读取修改后的 chunk
                if let Some(modified_chunk) = ctx.filter_chunk.take() {
                    ctx.body = Some(modified_chunk);
                }
            }
        }

        if run_wasm_filters(loc, ctx, true) {
            return error_response(ctx, server, Some(loc), 500).await;
        }

        return finish_response(ctx, server, Some(loc));
    }

    if let Some((_, spec)) = loc.rust_phases.iter().find(|(p, _)| *p == Phase::Content) {
        if let Err(e) = state.handlers.run_phase(Phase::Content, spec, ctx).await {
            log_error!("content_by_rust 失败: {e}");
            return error_response(ctx, server, Some(loc), 500).await;
        }
        if run_wasm_filters(loc, ctx, true) {
            return error_response(ctx, server, Some(loc), 500).await;
        }
        return finish_response(ctx, server, Some(loc));
    }

    serve_static_flow(state, ctx, server, loc, body, scope).await
}

/// 执行某个阶段的 rust + lua 处理器；返回 true 表示出错（已置 ctx.status=500/done）。
/// 调用方必须在 true 时立即收口：继续往下走等于把"检查没跑成"当成"检查通过"。
async fn run_phases(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    loc: &Location,
    phase: Phase,
    server: &Arc<Server>,
) -> bool {
    for (p, spec) in &loc.rust_phases {
        if *p != phase || ctx.done {
            continue;
        }
        if let Err(e) = state.handlers.run_phase(phase, spec, ctx).await {
            log_error!("{phase:?} 阶段处理器 '{}' 失败: {e}", spec.name);
            ctx.status = 500;
            ctx.done = true;
            return true;
        }
    }
    for (p, name, src) in &loc.lua_phases {
        if *p != phase || ctx.done {
            continue;
        }
        if run_lua(state, ctx, name, src).await {
            return true;
        }
    }
    // WASM 插件目前只接 access 阶段（响应过滤器在响应生成后单独跑）。与 Lua 共用
    // ctx：插件改过的请求头会随转发送给后端，插件生成的响应走 ctx.done 收口。
    if phase == Phase::Access {
        for (p, plugin) in &loc.wasm_phases {
            if *p != crate::wasm::WasmPhase::Access || ctx.done {
                continue;
            }
            if let Err(e) = crate::wasm::access(plugin, ctx) {
                log_error!("{e}");
                ctx.status = 500;
                ctx.done = true;
                return true;
            }
        }
    }
    let _ = server;
    false
}

/// 运行一段 Lua；返回 true 表示出错。
/// ctx 通过 Arc<Mutex> 交给 Lua 线程：锁中毒（Lua 里 panic）不能带崩整个站，取回内部值继续。
async fn run_lua(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    name: &str,
    src: &crate::lua_engine::LuaSource,
) -> bool {
    let shared = Arc::new(Mutex::new(std::mem::take(ctx)));
    let r = state.lua.run_phase(name, src, Arc::clone(&shared)).await;
    // 取回 ctx：中毒锁也照常取（宁可带着略过的状态返回，也不要 panic）
    *ctx = take_ctx(shared);
    if let Err(e) = r {
        log_error!("{name} 执行失败: {e}");
        ctx.status = 500;
        ctx.done = true;
        return true;
    }
    false
}

fn has_wasm_filter(loc: &Location) -> bool {
    loc.wasm_phases.iter().any(|(p, _)| {
        matches!(
            p,
            crate::wasm::WasmPhase::HeaderFilter | crate::wasm::WasmPhase::BodyFilter
        )
    })
}

/// 运行 location 上声明的 WASM 响应过滤器（先全部 header_filter，再全部 body_filter）。
/// 返回 true 表示失败：必须就此收口成 5xx。过滤器是"看过了才放行"的关口，
/// 插件 trap 或耗尽 fuel 时把原响应原样发出去，等于让一个安全检查静默失效。
fn run_wasm_filters(loc: &Location, ctx: &mut RequestCtx, with_body: bool) -> bool {
    for (phase, plugin) in &loc.wasm_phases {
        let wanted = match phase {
            crate::wasm::WasmPhase::HeaderFilter => true,
            crate::wasm::WasmPhase::BodyFilter => with_body,
            crate::wasm::WasmPhase::Access => false,
        };
        if !wanted {
            continue;
        }
        if let Err(e) = crate::wasm::filter(plugin, *phase, ctx) {
            log_error!("{e}");
            ctx.status = 500;
            ctx.body = None;
            ctx.done = true;
            return true;
        }
    }
    false
}

/// limit_req：命中返回 429（带 Retry-After），未命中返回 None。
///
/// 区里没写 `limit_req_queue` 时行为与从前逐字节一致（超限即拒，等价 nginx `nodelay`）。
/// 写了之后，超限的请求改为"占住一个有界队列名额 + 预留这一格令牌 → 等到令牌成熟 → 放行"：
/// 令牌在判定时就记成欠账，所以醒来不会被别人抢走，也不需要在原地反复重试。
/// 客户端在这段等待里断开，future 被丢弃、名额随之归还，队列不会被幽灵排队占死。
/// 写了 `vip_learning` 时，这里的每种判定结果都会记进进程级信誉表（放行加分、429 扣分），
/// 信誉再反过来决定这个 key 的排队上界与缓存驻留加权——它不参与"能不能放行"。
async fn check_limit_req(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    loc: &Location,
) -> Option<BoxResponse> {
    let vip = state.limits.vip();
    for rule in &loc.limit_req {
        let Some(zone) = state.limits.req_zone(&rule.zone) else {
            continue;
        };
        // key 按区声明的模板算：$remote_addr 是快路径，$cookie_sid/$http_x/$arg_ 走插值。
        // 这一维上没值的请求不参与本区计数（nginx 同义），否则匿名流量会共用一个桶。
        let Some(key) = crate::limit::zone_key(&zone.key_var, ctx) else {
            log_debug!(
                "limit_req '{}' 无 key（{} 展开为空），本区不限流",
                rule.zone,
                zone.key_var
            );
            continue;
        };
        let retry_after = match zone.admit(&key, rule.burst, vip.as_ref()) {
            crate::limit::Admit::Pass => continue,
            crate::limit::Admit::Reject { retry_after_secs } => retry_after_secs,
            crate::limit::Admit::Queued { wait_ms, permit } => {
                log_debug!("limit_req '{}' 排队 {wait_ms}ms: {key}", rule.zone);
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                // 名额用完立刻归还；预留的令牌不退（见 limit::Admit::Queued）
                drop(permit);
                continue;
            }
        };
        log_debug!("limit_req '{}' 命中: {key}", rule.zone);
        crate::metrics::get().on_limit_req_rejected();
        ctx.status = state.limits.req_status;
        let mut resp = status_page(state.limits.req_status);
        set_header(&mut resp, "retry-after", &retry_after.to_string());
        return Some(resp);
    }
    None
}

// ==================== ACCESS：内置 allow/deny + auth_basic ====================

/// realip：直连对端为可信代理时，用 real_ip_header 覆盖 $remote_addr。
/// 必须早于 limit_conn / limit_req / geo / auth，令这些环节都基于真实客户端 IP。
fn apply_realip(server: &Server, ctx: &mut RequestCtx, peer: Option<std::net::SocketAddr>) {
    if !server.real_ip.enabled() {
        return;
    }
    if let Some(peer) = peer {
        if let Some(real) = server.real_ip.apply(peer.ip(), &ctx.req_headers) {
            log_debug!(
                "realip：{} → {}（源自 ${}",
                peer,
                real,
                server.real_ip.header
            );
            ctx.remote_addr = real;
        }
    }
}

/// front_proxy：认出直连对端属于哪家前置代理（CDN / LB），并在 egress 模式下按该 profile
/// 声明的头链还原真实客户端地址，附带来源侧协议、可见域名与国家。
///
/// 位置紧贴在 `apply_realip` 之后、`rec.set_remote` / limit_conn / allow-deny / VIP /
/// location 匹配之前，所以改写一次就全链路一致；判定是**每请求一次**而非每连接一次，
/// CDN 那种长连接复用不会把上一个请求的结论带过来（这也是"复用"这一项的实际含义）。
///
/// 采信闸门在 `front_proxy::decide` 内部：直连对端不在 `profile.trust ∪ set_real_ip_from`
/// 里时，地址、协议、Host、国家一个都不采用；`detect` 模式则只识别、不改写任何东西。
fn apply_front_proxy(server: &Server, ctx: &mut RequestCtx, peer: Option<std::net::SocketAddr>) {
    use crate::front_proxy as fp;
    if !server.front_proxy.enabled() {
        return;
    }
    let realip = fp::RealIpState {
        enabled: server.real_ip.enabled(),
        header: &server.real_ip.header,
        trusted: &server.real_ip.trusted,
        recursive: server.real_ip.recursive,
    };
    let d = fp::decide(
        &server.front_proxy,
        &ctx.req_headers,
        peer.map(|p| p.ip()),
        &realip,
    );
    let Some(name) = d.profile else {
        return;
    };
    ctx.front_proxy = name;
    ctx.front_proxy_verified = d.verified;
    if let Some(ip) = d.real_ip {
        log_debug!(
            "front_proxy '{}'：{} → {ip}（源自 {}）",
            ctx.front_proxy,
            ctx.remote_addr,
            d.ip_source.unwrap_or_default()
        );
        ctx.remote_addr = ip;
    }
    // 协议取自前置代理，只影响 $scheme/$https 与发给后端的 X-Forwarded-Proto：
    // CDN  terminates TLS 而回源走 http 时，源站据此才不会生成 http:// 的降级跳转。
    if let Some(s) = d.scheme {
        ctx.scheme = s;
    }
    if let Some(h) = d.host {
        ctx.front_proxy_host = h;
    }
    if let Some(c) = d.country {
        ctx.front_proxy_country = c;
    }
}

/// limit_conn：在 ACCESS 之前按区声明的 key（客户端地址或请求期变量）占用并发额度；
/// 超限返回 nginx 风格错误页。key 在这一维上没值的请求不计数，与 limit_req 同一口径。
///
/// `loc` 是按**改写前的原始 URI** 匹配出来的那一级：额度必须在读请求体之前就占住，
/// 而 REWRITE 要到 `run_ingress` 里才跑。nginx 在 PREACCESS 相位判定，那时改写已经发生，
/// 所以"用 rewrite 把流量搬进另一个带不同 limit_conn 的 location"这一种配置上两边不同——
/// 绝大多数配置没有这种改写，写了 limit_conn 的那一级就是请求实际落到的那一级。
fn acquire_conn_guards(
    state: &AppState,
    server: &Server,
    loc: Option<&Location>,
    ctx: &RequestCtx,
) -> Result<Vec<crate::limit::ConnGuard>, BoxResponse> {
    let mut guards = Vec::new();
    for rule in router::effective_limit_conn(loc, server) {
        let Some(zone) = state.limits.conn_zone(&rule.zone) else {
            continue;
        };
        let Some(key) = crate::limit::zone_key(&zone.key_var, ctx) else {
            continue;
        };
        match zone.try_acquire(&key, rule.number) {
            Some(g) => guards.push(g),
            None => {
                log_debug!("limit_conn '{}' 命中: {key}", rule.zone);
                crate::metrics::get().on_limit_conn_rejected();
                return Err(close_now(status_page(state.limits.conn_status)));
            }
        }
    }
    Ok(guards)
}

/// ACCESS 阶段内置访问控制：先 IP（allow/deny），then the schedule gate (schedule_access)，最后
/// HTTP Basic（auth_basic），都在 access_by_* 之前执行（与 nginx 内置模块的注册顺序一致）。
/// 命中拒绝则返回统一错误页。
async fn check_access_and_auth(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    loc: &Location,
    server: &Arc<Server>,
) -> Option<BoxResponse> {
    // ---- IP allow/deny：location 有自身规则则用之，否则继承 server ----
    let rules = if !loc.access_rules.is_empty() {
        &loc.access_rules
    } else {
        &server.access_rules
    };
    if !rules.is_empty() {
        // 地址解析不了必须拒绝（fail closed）：allow/deny 是访问控制，
        // 把"读不到对端 IP"当成"没有规则"等于给绕过者开门。
        match ctx.remote_addr.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                if !crate::access::check_access(rules, ip) {
                    log_debug!("allow/deny 拒绝 {}", ctx.remote_addr);
                    ctx.status = 403;
                    return Some(status_page(403));
                }
            }
            Err(_) => {
                log_error!(
                    "allow/deny 无法解析对端地址 {}，按拒绝处理",
                    ctx.remote_addr
                );
                ctx.status = 403;
                return Some(status_page(403));
            }
        }
    }

    // ---- schedule gate: when the location writes none it inherits the server (the same inheritance path as auth_basic) ----
    // Placed after allow/deny: the IP whitelist is therefore the operator's natural escape hatch during a
    // closed window, and a deny still takes priority over "it happens to be open right now".
    let gate = loc
        .schedule_gate
        .as_deref()
        .or(server.schedule_gate.as_deref());
    if let Some(name) = gate {
        // The state is only an atomic bit: the decision path takes no lock, reads no timezone, touches no calendar.
        if !state.schedule.is_open(name) {
            state.schedule.on_denied(name);
            log_debug!(
                "schedule_access '{name}' window closed, rejecting {}",
                ctx.remote_addr
            );
            ctx.status = 403;
            return Some(status_page(403));
        }
    }

    // ---- auth_basic：realm 三态（None 继承 / "off" 关闭 / 其它启用）----
    let realm = loc
        .auth_basic_realm
        .as_deref()
        .or(server.auth_basic_realm.as_deref());
    let realm = match realm {
        Some(r) if r != "off" => r,
        _ => return None,
    };
    // 启用 auth_basic 却没有口令文件同样 fail closed：没有可校验的凭据源，
    // 任何请求（包括无 Authorization 的）都拿不到 200。nginx 在此情形返回 500，
    // 我们用 401 质询 + error_log，既不泄露内容、又能让客户端提示输入口令。
    let file = match loc
        .auth_basic_user_file
        .as_ref()
        .or(server.auth_basic_user_file.as_ref())
    {
        Some(f) => f,
        None => {
            log_error!("auth_basic 已启用但未配置 auth_basic_user_file，按未授权处理");
            ctx.status = 401;
            return Some(basic_challenge(realm));
        }
    };

    // 校验 Authorization（缺失/格式错/不匹配一律 401，附带 WWW-Authenticate）。
    // 文件读取与口令校验（md5crypt 是 1000 轮 MD5）一起丢进阻塞池：
    // 放在请求任务上会占住 async worker，几个慢校验就能拖垮整条 accept 链。
    let header = ctx.header("authorization").map(str::to_string);
    let path = file.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::access::load_htpasswd(&path)
            .map(|users| crate::access::check_auth_header(header.as_deref(), &users))
    })
    .await
    .ok()
    .flatten();
    let outcome = match outcome {
        Some(o) => o,
        None => {
            // 文件读不到：等同认证失败，但仍要给出 401 质询（与 nginx 行为一致）
            log_error!("auth_basic_user_file 无法读取: {}", file.display());
            ctx.status = 401;
            return Some(basic_challenge(realm));
        }
    };
    match outcome {
        crate::access::AuthOutcome::Ok(user) => {
            log_debug!("auth_basic 通过: {user}");
            None
        }
        _ => {
            ctx.status = 401;
            Some(basic_challenge(realm))
        }
    }
}

/// 401 质询：统一错误页 + `WWW-Authenticate: Basic realm="..."`（realm 里的反斜杠/引号转义）。
fn basic_challenge(realm: &str) -> BoxResponse {
    let escaped = realm.replace('\\', "\\\\").replace('"', "\\\"");
    let mut resp = status_page(401);
    set_header(
        &mut resp,
        "www-authenticate",
        &format!("Basic realm=\"{escaped}\""),
    );
    resp
}

// ==================== 静态文件（try_files / index / autoindex / alias / 条件请求）====================

/// 文件校验元数据：由 (mtime, size) 派生，支撑 304 / 206 / 416
#[derive(Debug, Clone)]
struct FileMeta {
    /// nginx 风格强校验位：`"<mtime 十六进制>-<size 十六进制>"`
    etag: String,
    /// IMF-fixdate（HTTP 的 Last-Modified 只有秒级精度）
    last_modified: String,
    mtime: u64,
    size: u64,
}

async fn serve_static_flow(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &Arc<Server>,
    loc: &Location,
    body: ProxyBody,
    scope: &mut RequestScope,
) -> BoxResponse {
    let Some(snap) = static_snapshot(ctx, server, loc) else {
        return error_response(ctx, server, Some(loc), 404).await;
    };
    let hit = tokio::task::spawn_blocking(move || resolve_snap(&snap))
        .await
        .unwrap_or(StaticHit::NotFound);
    match hit {
        StaticHit::File {
            code,
            mime,
            body: source,
            meta,
            window,
        } => {
            // window 命中时同一份文件要改写成 206
            let status = match (code, window) {
                (200, Some(_)) => StatusCode::PARTIAL_CONTENT,
                (c, _) => StatusCode::from_u16(c).unwrap_or(StatusCode::OK),
            };
            // sub_filter：仅对完整体（非 Range 切片）且 MIME 命中时改写；Range/206 不改（对齐 nginx：
            // 无法在字节区间上安全替换）。命中过滤器时大文件也必须整份读入内存。
            let filter = loc.sub_filter.as_ref().filter(|c| {
                window.is_none()
                    && !c.filters.is_empty()
                    && crate::engine::sub_filter_applies(Some(mime.as_str()), &c.types)
            });
            let source = match source {
                FileSource::Memory(content) => FileSource::Memory(match filter {
                    Some(conf) => Bytes::from(crate::engine::apply_sub_filter(
                        Some(conf),
                        Some(mime.as_str()),
                        content.to_vec(),
                    )),
                    None => content,
                }),
                FileSource::Disk { path, start, len } => match filter {
                    // 超过缓冲上限的响应体不改写，原样零拷贝流式发送。
                    // sub_filter 需要看到整段内容才能替换，全量缓冲等于把
                    // "文件大小 × 并发数"的内存压在请求任务上；宁可漏改写一个
                    // 大文件，也不能让一条 `sub_filter` 指令变成内存放大开关。
                    Some(_) if len > SUB_FILTER_MAX_BUFFER => {
                        log_warn!(
                            "sub_filter 跳过 {}: 响应体 {len} 字节超过缓冲上限 {} MiB，按原样发送",
                            path.display(),
                            SUB_FILTER_MAX_BUFFER >> 20
                        );
                        FileSource::Disk { path, start, len }
                    }
                    Some(_) => match read_file_window(&path, start, len).await {
                        Ok(win) => FileSource::Memory(Bytes::from(
                            crate::engine::apply_sub_filter(filter, Some(mime.as_str()), win),
                        )),
                        Err(e) => {
                            log_warn!("静态文件读取失败 {}: {e}", path.display());
                            return error_response(ctx, server, Some(loc), 404).await;
                        }
                    },
                    None => FileSource::Disk { path, start, len },
                },
            };
            let total = meta.as_ref().map(|m| m.size).unwrap_or(match &source {
                FileSource::Memory(b) => b.len() as u64,
                FileSource::Disk { len, .. } => *len,
            });
            // WASM 响应过滤器：静态响应也要过（nginx 的 header/body filter 对静态文件同样生效）。
            // 需要整份体，小文件/内存体直接改；超过缓冲上限的磁盘文件按原样发送（与 sub_filter
            // 同一取舍：宁可漏一次改写，也不让一条过滤器指令变成内存放大开关）。
            if has_wasm_filter(loc) {
                let buffered = match &source {
                    FileSource::Memory(b) => Some(b.clone()),
                    FileSource::Disk { path, start, len } if *len <= SUB_FILTER_MAX_BUFFER => {
                        match read_file_window(path, *start, *len).await {
                            Ok(win) => Some(Bytes::from(win)),
                            Err(e) => {
                                log_warn!("静态文件读取失败 {}: {e}", path.display());
                                return error_response(ctx, server, Some(loc), 404).await;
                            }
                        }
                    }
                    FileSource::Disk { path, len, .. } => {
                        log_warn!(
                            "WASM 响应过滤器跳过 {}: 响应体 {len} 字节超过缓冲上限 {} MiB，按原样发送",
                            path.display(),
                            SUB_FILTER_MAX_BUFFER >> 20
                        );
                        None
                    }
                };
                if let Some(content) = buffered {
                    let mut headers: Vec<(String, String)> = vec![
                        ("content-type".to_string(), mime.clone()),
                        ("server".to_string(), SERVER_HEADER.to_string()),
                    ];
                    if let Some(m) = &meta {
                        headers.push(("etag".to_string(), m.etag.clone()));
                        headers.push(("last-modified".to_string(), m.last_modified.clone()));
                        headers.push(("accept-ranges".to_string(), "bytes".to_string()));
                    }
                    if let Some((start, end)) = window {
                        headers.push((
                            "content-range".to_string(),
                            format!("bytes {start}-{end}/{total}"),
                        ));
                    }
                    ctx.status = status.as_u16();
                    ctx.resp_headers = headers;
                    ctx.body = Some(if ctx.method == "HEAD" {
                        Vec::new()
                    } else {
                        content.to_vec()
                    });
                    if run_wasm_filters(loc, ctx, true) {
                        return error_response(ctx, server, Some(loc), 500).await;
                    }
                    let resp_status = ctx.status;
                    let hdrs = std::mem::take(&mut ctx.resp_headers);
                    let body = Bytes::from(ctx.body.take().unwrap_or_default());
                    return build_buffered_response(
                        resp_status,
                        &hdrs,
                        body,
                        loc,
                        server,
                        "",
                        false,
                        ctx,
                    );
                }
            }
            let body_len = match &source {
                FileSource::Memory(b) => b.len() as u64,
                FileSource::Disk { len, .. } => *len,
            };
            let mut builder = Response::builder()
                .status(status)
                .header("content-type", mime)
                .header("server", SERVER_HEADER)
                // 流式体没有可推断的长度，显式声明让定长分帧与 HEAD 语义和 buffered 路径一致
                .header(hyper::header::CONTENT_LENGTH, body_len.to_string());
            if let Some(m) = &meta {
                builder = builder
                    .header("etag", m.etag.as_str())
                    .header("last-modified", m.last_modified.as_str())
                    .header("accept-ranges", "bytes");
            }
            if let Some((start, end)) = window {
                builder = builder.header("content-range", format!("bytes {start}-{end}/{total}"));
            }
            // HEAD 不发体：大文件连打开都不必，头部元数据已足够
            let body = if ctx.method == "HEAD" {
                empty_body()
            } else {
                match source {
                    FileSource::Memory(content) => full_body(content),
                    FileSource::Disk { path, start, len } => {
                        match DiskBody::open(&path, start, len).await {
                            Some(b) => b,
                            None => {
                                log_warn!("静态文件打开失败 {}", path.display());
                                return error_response(ctx, server, Some(loc), 404).await;
                            }
                        }
                    }
                }
            };
            let mut resp = builder
                .body(body)
                .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR));
            apply_add_headers(&mut resp, loc, server, ctx);
            resp
        }
        // 304 只带校验头，没有响应体（Content-Type/Content-Length 由协议层省掉）
        StaticHit::NotModified(m) => {
            let mut resp = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("server", SERVER_HEADER)
                .header("etag", m.etag.as_str())
                .header("last-modified", m.last_modified.as_str())
                .header("accept-ranges", "bytes")
                .body(empty_body())
                .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR));
            apply_add_headers(&mut resp, loc, server, ctx);
            resp
        }
        StaticHit::RangeUnsatisfiable(m) => {
            let resp = Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("server", SERVER_HEADER)
                .header("content-range", format!("bytes */{}", m.size))
                .header("etag", m.etag.as_str())
                .header("last-modified", m.last_modified.as_str())
                .body(empty_body())
                .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR));
            resp
        }
        StaticHit::Redirect(target) => redirect_response(301, &target),
        StaticHit::InternalRedirect(last) => {
            if ctx.exec_depth < MAX_URI_CHANGES as u8 {
                ctx.rewritten_path = Some(last);
                ctx.exec_depth += 1;
                ctx.internal_request = true;
                return Box::pin(process(state, ctx, server, body, scope)).await;
            }
            error_response(ctx, server, Some(loc), 404).await
        }
        StaticHit::NotFound => error_response(ctx, server, Some(loc), 404).await,
        StaticHit::Forbidden => error_response(ctx, server, Some(loc), 403).await,
    }
}

#[derive(Debug)]
enum StaticHit {
    /// window = Some((起, 止))：按 Range 命中的闭区间，响应改 206；meta = None 表示动态生成的内容（无校验位）
    File {
        code: u16,
        mime: String,
        body: FileSource,
        meta: Option<FileMeta>,
        window: Option<(u64, u64)>,
    },
    /// 条件请求命中：304 Not Modified
    NotModified(FileMeta),
    /// Range 越界：416 + `Content-Range: bytes */size`
    RangeUnsatisfiable(FileMeta),
    /// 目录存在但 URI 缺尾斜杠：301
    Redirect(String),
    /// try_files 兜底：内部重定向目标
    InternalRedirect(String),
    NotFound,
    Forbidden,
}

/// 静态文件的取体方式：小文件/动态生成走内存；大文件与 Range 只记录磁盘区间，
/// 响应阶段按 64KiB 分块流式读出，不把整份文件驻留内存。
#[derive(Debug)]
enum FileSource {
    /// `Bytes` 让缓存命中与 Range 切片都只做引用计数，不再整份复制
    Memory(Bytes),
    Disk {
        path: PathBuf,
        start: u64,
        len: u64,
    },
}

const DISK_CHUNK: usize = 64 * 1024;

/// 从磁盘流式读响应体：每次 poll_frame 只读一块，文件句柄随体结束关闭。
struct DiskBody {
    file: Option<tokio::fs::File>,
    remaining: u64,
    buf: Vec<u8>,
    pending: Option<
        Pin<
            Box<
                dyn Future<Output = (tokio::fs::File, Vec<u8>, std::io::Result<usize>)>
                    + Send
                    + Sync
                    + 'static,
            >,
        >,
    >,
}

impl DiskBody {
    async fn open(path: &std::path::Path, start: u64, len: u64) -> Option<RespBody> {
        if len == 0 {
            return Some(empty_body());
        }
        use tokio::io::AsyncSeekExt;
        let mut file = tokio::fs::File::open(path).await.ok()?;
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await.ok()?;
        }
        Some(
            DiskBody {
                file: Some(file),
                remaining: len,
                buf: Vec::with_capacity(DISK_CHUNK.min(len as usize)),
                pending: None,
            }
            .boxed(),
        )
    }
}

impl Body for DiskBody {
    type Data = Bytes;
    type Error = crate::proxy::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if let Some(mut fut) = this.pending.take() {
                match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        this.pending = Some(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready((file, buf, res)) => {
                        this.file = Some(file);
                        match res {
                            Ok(0) => {
                                // stat 之后文件被截断：提前结束，避免继续发不存在的字节
                                log_warn!("静态文件提前 EOF（剩余 {} 字节未读）", this.remaining);
                                this.remaining = 0;
                                return Poll::Ready(None);
                            }
                            Ok(n) => {
                                this.remaining -= n as u64;
                                let out = Bytes::copy_from_slice(&buf[..n]);
                                this.buf = buf;
                                if this.remaining == 0 {
                                    this.file = None;
                                }
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                            Err(e) => {
                                this.remaining = 0;
                                this.file = None;
                                return Poll::Ready(Some(Err(Box::new(e))));
                            }
                        }
                    }
                }
            }
            if this.remaining == 0 {
                this.file = None;
                return Poll::Ready(None);
            }
            let want = this.remaining.min(DISK_CHUNK as u64) as usize;
            let Some(file) = this.file.take() else {
                this.remaining = 0;
                return Poll::Ready(None);
            };
            let mut buf = std::mem::take(&mut this.buf);
            buf.resize(want, 0);
            this.pending = Some(Box::pin(async move {
                use tokio::io::AsyncReadExt;
                let mut file = file;
                let r = file.read(&mut buf[..want]).await;
                (file, buf, r)
            }));
            // 建好读任务后立即回到循环顶部 poll 一次，少一次不必要的 task 唤醒
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining)
    }
}

/// 静态解析快照：把 ctx/server/location 的相关数据抽成 owned 结构，整体丢进 spawn_blocking
/// （文件系统调用不能留在 async worker 线程上，否则一个慢盘就能卡住该核全部请求）
struct StaticSnap {
    base: PathBuf,
    is_alias: bool,
    pattern: String,
    path: String,
    query: String,
    index: Vec<String>,
    autoindex: bool,
    try_files: Option<Vec<String>>,
    /// 只有安全方法参与条件请求与 Range（POST 之类不该收到 304/206）
    negotiable: bool,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
    if_range: Option<String>,
    range: Option<String>,
}

fn static_snapshot(ctx: &RequestCtx, server: &Server, loc: &Location) -> Option<StaticSnap> {
    let (base, is_alias) = if let Some(alias) = &loc.alias {
        (alias.clone(), true)
    } else if let Some(root) = loc.root.as_ref().or(server.root.as_ref()) {
        (root.clone(), false)
    } else {
        return None;
    };
    Some(StaticSnap {
        base,
        is_alias,
        pattern: loc.pattern.clone(),
        path: ctx.effective_path().to_string(),
        query: ctx.query.clone(),
        index: loc.index.clone().unwrap_or_else(|| server.index.clone()),
        autoindex: loc.autoindex || server.autoindex,
        try_files: loc.try_files.clone(),
        negotiable: matches!(ctx.method.as_str(), "GET" | "HEAD"),
        if_none_match: ctx.header("if-none-match").map(str::to_string),
        if_modified_since: ctx.header("if-modified-since").map(str::to_string),
        if_range: ctx.header("if-range").map(str::to_string),
        range: ctx.header("range").map(str::to_string),
    })
}

impl StaticSnap {
    /// nginx 语义：alias 剥掉 location 前缀，root 追加完整 URI
    fn base_rel(&self, path: &str) -> (PathBuf, String) {
        if self.is_alias {
            let rel = path.strip_prefix(&self.pattern).unwrap_or(path);
            (self.base.clone(), rel.trim_start_matches('/').to_string())
        } else {
            (self.base.clone(), path.trim_start_matches('/').to_string())
        }
    }
}

fn resolve_snap(snap: &StaticSnap) -> StaticHit {
    if let Some(tf) = &snap.try_files {
        for cand in &tf[..tf.len() - 1] {
            let p = cand.replace("$uri", &snap.path);
            match resolve_one(snap, &p) {
                StaticHit::NotFound | StaticHit::Forbidden => continue,
                h => return h,
            }
        }
        let last = tf
            .last()
            .map(|s| s.replace("$uri", &snap.path))
            .unwrap_or_default();
        return if last.starts_with('/') {
            StaticHit::InternalRedirect(last)
        } else {
            StaticHit::NotFound
        };
    }
    resolve_one(snap, &snap.path)
}

fn resolve_one(snap: &StaticSnap, path: &str) -> StaticHit {
    // 隐藏文件策略先于一切磁盘访问：点开头的内容（.git/.env/.htpasswd/备份点文件）不外泄，
    // 用 404 而不是 403 —— 403 等于告诉探测者"这东西存在"
    if hidden_hit(path) {
        log_debug!("拒绝隐藏文件：{path}");
        return StaticHit::NotFound;
    }
    let (base, rel) = snap.base_rel(path);
    let file_path = base.join(&rel);
    if rel.is_empty() || file_path.is_dir() {
        if !path.ends_with('/') {
            let q = if snap.query.is_empty() {
                String::new()
            } else {
                format!("?{}", snap.query)
            };
            return StaticHit::Redirect(format!("{path}/{q}"));
        }
        for name in &snap.index {
            let cand = file_path.join(name);
            if cand.is_file() {
                return file_hit(&cand, 200, snap);
            }
        }
        if snap.autoindex {
            if let Some(html) = autoindex_html(&file_path, path) {
                return StaticHit::File {
                    code: 200,
                    mime: "text/html; charset=utf-8".to_string(),
                    body: FileSource::Memory(Bytes::from(html.into_bytes())),
                    // 目录列表是动态生成的，没有稳定的校验位，也不支持 Range
                    meta: None,
                    window: None,
                };
            }
        }
        return StaticHit::Forbidden;
    }
    if file_path.is_file() {
        file_hit(&file_path, 200, snap)
    } else {
        StaticHit::NotFound
    }
}

/// URI 路径里是否有点开头的段。`.well-known`（ACME/LDAP/security.txt 约定目录）放行。
fn hidden_hit(path: &str) -> bool {
    path.split('/')
        .any(|seg| seg.starts_with('.') && seg != ".well-known" && seg != "." && seg != "..")
}

/// 静态文件内存缓存：小文件整体驻留内存，命中后零磁盘读；以 (mtime, size) 做失效校验
const FILE_CACHE_MAX_FILE: u64 = 1024 * 1024;
const FILE_CACHE_MAX_ENTRIES: usize = 512;

type FileCacheInner = HashMap<PathBuf, (u64, u64, Bytes)>;
static FILE_CACHE: std::sync::OnceLock<RwLock<FileCacheInner>> = std::sync::OnceLock::new();
use std::sync::RwLock;

fn file_cache() -> &'static RwLock<FileCacheInner> {
    FILE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 读全量并回填缓存；命中返回整份文件体（`Bytes` 克隆只增引用计数）
fn read_cached(path: &std::path::Path, mtime: u64, size: u64) -> Option<Bytes> {
    if let Ok(cache) = file_cache().read() {
        if let Some((m, sz, body)) = cache.get(path) {
            if *m == mtime && *sz == size {
                return Some(body.clone());
            }
        }
    }
    let body = Bytes::from(std::fs::read(path).ok()?);
    if let Ok(mut cache) = file_cache().write() {
        if cache.len() >= FILE_CACHE_MAX_ENTRIES {
            cache.clear(); // 简单淘汰：满即清空，热文件下一轮自动回填
        }
        cache.insert(path.to_path_buf(), (mtime, size, body.clone()));
    }
    Some(body)
}

fn file_hit(path: &std::path::Path, code: u16, snap: &StaticSnap) -> StaticHit {
    let Ok(meta) = std::fs::metadata(path) else {
        return StaticHit::NotFound;
    };
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fm = FileMeta {
        etag: etag_of(mtime, size),
        last_modified: http_date(mtime),
        mtime,
        size,
    };

    // 1) 条件请求：命中就一个字节都不用读
    if code == 200 && snap.negotiable && not_modified(snap, &fm) {
        return StaticHit::NotModified(fm);
    }

    // 2) Range：只在 GET/HEAD 且 If-Range（若带来）与当前版本一致时生效
    let window = if code == 200 && snap.negotiable {
        match snap.range.as_deref() {
            Some(hdr) if if_range_matches(snap.if_range.as_deref(), &fm) => {
                match parse_range(hdr, size) {
                    RangeReq::Window(s, e) => Some((s, e)),
                    RangeReq::Unsatisfiable => return StaticHit::RangeUnsatisfiable(fm),
                    RangeReq::Ignored => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };

    // 3) 取体：小文件走内存缓存（命中即零磁盘读）；大文件与未缓存文件只记录磁盘区间，
    //    由 serve_static_flow 流式读出——不再把整份大文件读进内存
    let cached = if size <= FILE_CACHE_MAX_FILE {
        read_cached(path, mtime, size)
    } else {
        None
    };
    let body = match (window, cached) {
        // Bytes::slice 只做引用计数，Range 切片不再复制缓存内容
        (Some((s, e)), Some(all)) => FileSource::Memory(all.slice(s as usize..=e as usize)),
        (Some((s, e)), None) => FileSource::Disk {
            path: path.to_path_buf(),
            start: s,
            len: e - s + 1,
        },
        (None, Some(all)) => FileSource::Memory(all),
        (None, None) => FileSource::Disk {
            path: path.to_path_buf(),
            start: 0,
            len: size,
        },
    };
    StaticHit::File {
        code,
        mime: mime_of(path).to_string(),
        body,
        meta: Some(fm),
        window,
    }
}

enum RangeReq {
    /// 语法不合 / 多段 / 带 If-Range 不匹配：按 nginx 语义忽略 Range，回整份 200
    Ignored,
    /// 闭区间 [start, end]
    Window(u64, u64),
    Unsatisfiable,
}

/// 只支持单段 Range：`bytes=200-499`、`bytes=200-`、`bytes=-499`（后缀长度）。
/// 多段范围（`bytes=0-1,3-4`）不返回 multipart，而是整体忽略——nginx 在 multi_ranges off 时同样如此。
fn parse_range(hdr: &str, size: u64) -> RangeReq {
    let Some(spec) = hdr.trim().strip_prefix("bytes=") else {
        return RangeReq::Ignored;
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(',') {
        return RangeReq::Ignored;
    }
    let (lo, hi) = match spec.split_once('-') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => return RangeReq::Ignored,
    };
    match (lo.parse::<u64>(), hi.parse::<u64>()) {
        (Ok(a), Ok(b)) => {
            if a > b {
                return RangeReq::Ignored;
            }
            if a >= size {
                return RangeReq::Unsatisfiable;
            }
            RangeReq::Window(a, b.min(size - 1))
        }
        // bytes=200-
        (Ok(a), Err(_)) => {
            if a >= size {
                return RangeReq::Unsatisfiable;
            }
            RangeReq::Window(a, size.saturating_sub(1))
        }
        // bytes=-500（最后 500 字节）
        (Err(_), Ok(n)) => {
            if n == 0 || size == 0 {
                return RangeReq::Unsatisfiable;
            }
            RangeReq::Window(size - n.min(size), size - 1)
        }
        _ => RangeReq::Ignored,
    }
}

/// If-Range：带校验位时必须与我们发出的一致，带日期时必须与 Last-Modified 同秒，否则回整份 200
fn if_range_matches(hdr: Option<&str>, fm: &FileMeta) -> bool {
    let Some(v) = hdr.map(str::trim) else {
        return true;
    };
    if v.is_empty() {
        return false;
    }
    if v.starts_with('"') || v.starts_with("W/") {
        v == fm.etag || strip_weak(v) == strip_weak(&fm.etag)
    } else {
        parse_http_date(v).is_some_and(|d| d == fm.mtime)
    }
}

/// RFC 9110 §13.2.2：If-None-Match 优先于 If-Modified-Since（后者只在没有校验位可比时才看）
fn not_modified(snap: &StaticSnap, fm: &FileMeta) -> bool {
    if let Some(inm) = &snap.if_none_match {
        return etag_list_matches(inm, &fm.etag);
    }
    if let Some(ims) = &snap.if_modified_since {
        if let Some(since) = parse_http_date(ims) {
            // HTTP 日期只有秒精度，mtime <= 条件时间即视为未修改（nginx 同）
            return fm.mtime <= since;
        }
    }
    false
}

/// `If-None-Match: "a", W/"b", *`
fn etag_list_matches(header: &str, ours: &str) -> bool {
    let ours = strip_weak(ours);
    header.split(',').any(|raw| {
        let t = raw.trim();
        !t.is_empty() && (t == "*" || strip_weak(t) == ours)
    })
}

fn strip_weak(tag: &str) -> &str {
    tag.strip_prefix("W/")
        .or_else(|| tag.strip_prefix("w/"))
        .unwrap_or(tag)
}

/// nginx 的 ETag 形式：`"<mtime 十六进制>-<size 十六进制>"`（强校验位）
fn etag_of(mtime: u64, size: u64) -> String {
    format!("\"{mtime:x}-{size:x}\"")
}

/// IMF-fixdate：`Mon, 13 Oct 2026 08:09:10 GMT`
fn http_date(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

/// 解析 HTTP 日期：主流是 RFC 7231 的 IMF-fixdate，老客户端仍会发 RFC 850 / asctime
fn parse_http_date(s: &str) -> Option<u64> {
    use chrono::{TimeZone, Utc};
    let s = s.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(dt.timestamp().max(0) as u64);
    }
    for fmt in [
        "%a, %d-%b-%y %H:%M:%S %Z",
        "%a %b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%S%:z",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&dt).timestamp().max(0) as u64);
        }
    }
    None
}

use chrono::NaiveDateTime;

/// autoindex：nginx 风格目录列表页（文件名必须转义，否则恶意文件名可注入脚本）
fn autoindex_html(dir: &std::path::Path, uri: &str) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for e in std::fs::read_dir(dir).ok()? {
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        // 与 hidden_hit 同一套策略：列表里出现 .git/.env 就等于把"这里有敏感文件"说出去了
        if hidden_hit(&format!("/{name}")) {
            continue;
        }
        let slash = if e.path().is_dir() { "/" } else { "" };
        let disp = html_escape(&format!("{name}{slash}"));
        // Directory-listing hrefs must be re-encoded or names with spaces/non-ASCII are
        // unclickable; the pchar set keeps characters like `@` exactly as the client sent them
        let href = crate::engine::encode_path_segment(&name) + slash;
        entries.push(format!("<a href=\"{href}\">{disp}</a>"));
    }
    entries.sort();
    Some(format!(
        "<html>\r\n<head><title>Index of {}</title></head>\r\n<body>\r\n<h1>Index of {}</h1><hr><pre><a href=\"../\">../</a>\r\n{}</pre><hr><center>{}</center>\r\n</body>\r\n</html>\r\n",
        html_escape(uri),
        html_escape(uri),
        entries.join("\r\n"),
        SERVER_HEADER
    ))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

// ==================== 响应构造 ====================

/// 对上游响应头应用 proxy_redirect（Location/Refresh）与 proxy_cookie_domain/path（Set-Cookie）改写。
/// 两条代理响应缝（流式 convert_upstream_response 与缓冲 build_buffered_response）共用。
fn apply_proxied_header_rewrites(hm: &mut hyper::HeaderMap, loc: &Location) {
    use crate::resp_rewrite as rw;
    // proxy_redirect：Location / Refresh（各取当前值，命中第一条规则即改写）。
    if !loc.proxy_redirect.off && !loc.proxy_redirect.rules.is_empty() {
        for name in ["location", "refresh"] {
            let hn = HeaderName::from_static(name);
            let cur = hm
                .get(&hn)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if let Some(cur) = cur {
                if let Some(new) = rw::apply_redirect(&loc.proxy_redirect.rules, &cur) {
                    if let Ok(val) = HeaderValue::from_str(&new) {
                        hm.insert(hn, val);
                    }
                }
            }
        }
    }
    // proxy_cookie_domain / proxy_cookie_path：Set-Cookie（保留多条）。
    let do_domain = !loc.proxy_cookie_domain.off && !loc.proxy_cookie_domain.rules.is_empty();
    let do_path = !loc.proxy_cookie_path.off && !loc.proxy_cookie_path.rules.is_empty();
    if do_domain || do_path {
        let hn = HeaderName::from_static("set-cookie");
        let olds: Vec<String> = hm
            .get_all(&hn)
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        if !olds.is_empty() {
            hm.remove(&hn);
            for old in olds {
                let mut v = old;
                if do_domain {
                    v = rw::rewrite_cookie_attr(&v, &loc.proxy_cookie_domain, "domain");
                }
                if do_path {
                    v = rw::rewrite_cookie_attr(&v, &loc.proxy_cookie_path, "path");
                }
                if let Ok(val) = HeaderValue::from_str(&v) {
                    hm.append(hn.clone(), val);
                }
            }
        }
    }
}

fn convert_upstream_response(
    resp: Response<crate::proxy::UpstreamBody>,
    loc: &Location,
    server: &Server,
    ctx: &RequestCtx,
) -> BoxResponse {
    let (mut parts, body) = resp.into_parts();
    let mut builder = Response::builder().status(parts.status);
    {
        let hm = builder.headers_mut().unwrap();
        if let Ok(v) = HeaderValue::from_str(SERVER_HEADER) {
            hm.insert(SERVER, v);
        }
        // drain() 只在每个 key 的第一个值上带出 HeaderName，重复值以 None 续传——需承接上一名，
        // 否则会丢弃多值头（如多条 Set-Cookie）。
        let mut last_name: Option<HeaderName> = None;
        for (k, v) in parts.headers.drain() {
            let name = match k {
                Some(n) => {
                    last_name = Some(n.clone());
                    n
                }
                None => match last_name.clone() {
                    Some(n) => n,
                    None => continue,
                },
            };
            if is_hop_by_hop(name.as_str()) {
                continue;
            }
            if name.as_str() == "set-cookie" {
                hm.append(name, v);
            } else {
                hm.insert(name, v);
            }
        }
        push_add_headers(hm, Some(loc), server, ctx);
        push_expires(hm, Some(loc), server, parts.status.as_u16());
        apply_proxied_header_rewrites(hm, loc);
    }
    builder
        .body(body.boxed())
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 缓存键：`$proxy_host` 由 proxy_pass 的 authority 供值，其余交给变量插值。
/// 默认模板 `$scheme$proxy_host$request_uri` 对齐 nginx。
fn build_cache_key(template: &str, ctx: &RequestCtx, target: &str) -> String {
    let rest = target
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let proxy_host = match rest.split_once('/') {
        Some((h, _)) => h,
        None => rest,
    };
    crate::proxy::interpolate_vars_with(template, ctx, |name| {
        (name == "proxy_host").then(|| proxy_host.to_string())
    })
}

/// nginx 的 bypass/no_cache 条件：任一表达式展开后非空且不为 "0" 即成立。
fn cache_expr_truthy(exprs: &[String], ctx: &RequestCtx) -> bool {
    exprs.iter().any(|e| {
        let v = crate::proxy::interpolate_vars(e, ctx);
        !v.is_empty() && v != "0"
    })
}

fn use_stale_allows(tokens: &[String], token: &str) -> bool {
    tokens.iter().any(|t| t == token)
}

/// 把上游响应整体缓冲成 `(状态, 可回放头, 体)`：剔除 hop-by-hop 与 Content-Length
/// （回发时按体长重算）。Still ONLine 要留副本就必须看到完整响应体。
async fn buffer_upstream(
    resp: Response<crate::proxy::UpstreamBody>,
) -> Result<(u16, Vec<(String, String)>, Bytes), String> {
    let (parts, ibody) = resp.into_parts();
    let collected = match ibody.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return Err(e.to_string()),
    };
    let hdrs: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(k, _)| {
            !is_hop_by_hop(k.as_str()) && !k.as_str().eq_ignore_ascii_case("content-length")
        })
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    Ok((parts.status.as_u16(), hdrs, collected))
}

/// 写入副本（准入闸门 1：只收 2xx、只收上游没发 `Set-Cookie` 的响应，
/// 且响应本身没声明"这份内容是这个访客专属的"（硬规则 4）；
/// 调用方已保证请求不带 Cookie/Authorization，且不是子请求）。
/// 存成功意味着这条 key 刚刚拿到过新鲜内容，顺手撤销后台的待重取标记。
fn store_still_online(
    state: &AppState,
    loc: &Location,
    ctx: &RequestCtx,
    zone: &str,
    key: &str,
    status: u16,
    headers: &[(String, String)],
    body: &Bytes,
) {
    if !(200..300).contains(&status) {
        return;
    }
    if crate::still_online::response_has_set_cookie(headers) {
        // 会话签发响应天然是"这个人专属"的，进副本区就等于把登录态发给下一个客户端
        state.still_online.note_credential_reject();
        return;
    }
    if let Some(reason) = crate::still_online::response_forbids_copy(headers) {
        // 没带凭证头不等于公开：上游用 Cache-Control/Vary 说过"按访客分过变体"，
        // 而副本 key 里没有身份，存下来就会把第一个访客的正文回放给所有人。
        state.still_online.note_private_reject();
        log_debug!("still_online 拒绝收录 {key}：{reason}");
        return;
    }
    let snap = crate::still_online::Snapshot {
        resp: Arc::new(crate::proxy_cache::CachedResponse {
            status,
            headers: headers.to_vec(),
            body: Arc::new(body.clone()),
        }),
        stored_at: std::time::SystemTime::now(),
        listener: ctx.listener,
        host: ctx.host.clone(),
        scheme: ctx.scheme.clone(),
        // 存原始请求行：后台重取要照它重新走一遍路由（rewrite 步骤也得重跑）
        uri: ctx.uri.clone(),
    };
    if state
        .still_online
        .store(zone, key, snap, loc.still_online_max_body)
    {
        // 存进去的就是新鲜内容：后台那条待重取标记可以撤了
        state.still_online.clear_dirty(zone, key);
    }
}

/// 回放副本（准入闸门 2：`Set-Cookie` 一律剥掉，永不随副本下发）。
/// 同时把该 key 挂进脏表，交给后台在健康恢复后单飞重取。
fn serve_still_online(
    state: &AppState,
    loc: &Location,
    server: &Server,
    ctx: &mut RequestCtx,
    zone: &str,
    key: &str,
) -> Option<BoxResponse> {
    let snap = state
        .still_online
        .lookup(zone, key, loc.still_online_max_age)?;
    let policy = crate::still_online::RetryPolicy {
        base: loc.still_online_retry,
        max: loc.still_online_retry_max,
        deadline: loc.still_online_retry_deadline,
    };
    state.still_online.mark_dirty(zone, key, &snap, &policy);
    let age = snap.age().as_secs();
    let headers = crate::still_online::strip_for_replay(&snap.resp.headers);
    ctx.still_online = "STALE".to_string();
    // 回放同样是一条发往客户端的正常响应：配了 WASM 过滤器就要过。
    // 过滤的是回放副本，脏表里的原件不动（下次重取仍以源站为准）。
    let (status, body, headers) = if has_wasm_filter(loc) {
        ctx.status = snap.resp.status;
        ctx.resp_headers = headers;
        ctx.body = Some((*snap.resp.body).to_vec());
        if run_wasm_filters(loc, ctx, true) {
            return Some(error_page(StatusCode::INTERNAL_SERVER_ERROR));
        }
        (
            ctx.status,
            Bytes::from(ctx.body.take().unwrap_or_default()),
            std::mem::take(&mut ctx.resp_headers),
        )
    } else {
        (snap.resp.status, (*snap.resp.body).clone(), headers)
    };
    let mut resp = build_buffered_response(status, &headers, body, loc, server, "", false, ctx);
    {
        let hm = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str("stale") {
            hm.insert(HeaderName::from_static("x-still-online"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&age.to_string()) {
            hm.insert(HeaderName::from_static("age"), v);
        }
    }
    Some(resp)
}

/// Still ONLine 后台重取循环：把脏表里到期的 key 用**匿名 GET** 重新走一遍正常请求路径。
///
/// * 单飞由脏表本身保证——`due_jobs` 取走即出表，同一 key 不可能有两个并发重取；
/// * 重取请求走 `process()`，所以 location 匹配、rewrite、限流、allow/deny 与 auth_basic
///   对它一视同仁，且成功时副本由写入闸门自动更新（不再需要第二套写入逻辑）；
/// * 响应带 `X-Still-Online` 说明这次"成功"其实是我们自己的旧副本（后端还没回来），按失败退避；
/// * 逐个串行处理：后端刚恢复时不再制造并发洪峰。
pub async fn still_online_refresh_loop(state: Arc<AppState>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => {}
            _ = tick.tick() => {}
        }
        if *stop.borrow_and_update() {
            return;
        }
        if state.still_online.dirty_len() == 0 {
            continue;
        }
        for job in state.still_online.due_jobs(Instant::now()) {
            if refresh_copy(&state, &job).await {
                log_info!("Still ONLine：副本 {} {} 已换成新鲜内容", job.zone, job.key);
                state.still_online.note_refreshed(&job.zone, &job.key);
            } else {
                state.still_online.requeue(job);
            }
        }
    }
}

/// 合成一次匿名重取请求；返回是否真的换到了新鲜内容。
/// 请求头只带 Host：既够虚拟主机匹配，也保证凭证闸门把它认成匿名请求
/// （副本层因此永远拿不到任何 Cookie/Authorization）。
async fn refresh_copy(state: &Arc<AppState>, job: &crate::still_online::RefreshJob) -> bool {
    let Some(listener) = job.listener else {
        return false;
    };
    let router = state.routing();
    let Some(server) = router
        .match_server(listener, job.host.as_deref())
        .map(Arc::clone)
    else {
        // 热重载后这个监听/虚拟主机已经不在了：副本继续服务到 max_age，但无法重建请求
        log_debug!(
            "Still ONLine：重取无法定位虚拟主机（{} {:?}）",
            listener,
            job.host
        );
        return false;
    };
    let Ok(uri) = job.uri.parse::<hyper::Uri>() else {
        return false;
    };
    let Some(path) = decode_and_normalize(uri.path()) else {
        return false;
    };
    let mut ctx = RequestCtx {
        method: "GET".to_string(),
        path,
        query: uri.query().unwrap_or("").to_string(),
        // 用原始请求行重建：cache key 模板里的 $request_uri 必须和当初一致
        uri: job.uri.clone(),
        host: job.host.clone(),
        // 网关自己发起的请求：源地址取本监听族的回环，便于按 IP 审计
        remote_addr: if listener.ip().is_ipv4() {
            "127.0.0.1".to_string()
        } else {
            "::1".to_string()
        },
        remote_port: 0,
        server_port: listener.port(),
        req_headers: vec![(
            "host".to_string(),
            job.host.clone().unwrap_or_else(|| "unknown".to_string()),
        )],
        resp_headers: Vec::new(),
        rewritten_path: None,
        status: 200,
        body: None,
        stream: None,
        done: false,
        internal_redirect: false,
        req_body: Bytes::new(),
        exec_depth: 0,
        redirect: None,
        scheme: job.scheme.clone(),
        // 不是内部请求：`internal;` 的 location 本就不该被对外回源，副本也只服务外部可见 URL
        internal_request: false,
        filter_chunk: None,
        filter_eof: false,
        listener: Some(listener),
        capture_depth: 0,
        balancer_peer: None,
        balancer_timeouts: None,
        balancer_more_failures: None,
        balancer_recreate_request: false,
        upstream_addr: String::new(),
        upstream_status: 0,
        proxy_split: String::new(),
        proxy_split_served: String::new(),
        upstream_header_time: 0.0,
        ssl: None,
        start_time: unix_now(),
        http_version: 1.1,
        body_builder: None,
        eof_sent: false,
        cache_status: String::new(),
        still_online: String::new(),
        // 重取由网关自己发起：没有前置代理，也没有"改写前的对端"可审计
        front_proxy: String::new(),
        front_proxy_country: String::new(),
        front_proxy_host: String::new(),
        front_proxy_verified: false,
        realip_remote_addr: String::new(),
        set_vars: Vec::new(),
        rewrite_return: None,
    };
    let mut scope = RequestScope {
        guards: Vec::new(),
        streamed: false,
        allow_stream: false,
    };
    let resp = process(
        state,
        &mut ctx,
        &server,
        ProxyBody::Buffered(None),
        &mut scope,
    )
    .await;
    let replayed = resp.headers().contains_key("x-still-online");
    let ok = resp.status().is_success();
    drop(resp);
    ok && !replayed
}

/// 命中缓存：用存储的状态/头/体重建响应，带上 X-Cache-Status 与 add_header。
/// 配了 WASM 响应过滤器时，命中同样要过一遍——缓存只该省掉回源，不该省掉关口。
fn serve_from_cache(
    resp: Arc<crate::proxy_cache::CachedResponse>,
    loc: &Location,
    server: &Server,
    status_tag: &str,
    ctx: &mut RequestCtx,
) -> BoxResponse {
    let (mut status, mut headers, mut body) =
        (resp.status, resp.headers.clone(), (*resp.body).clone());
    if has_wasm_filter(loc) {
        ctx.status = status;
        ctx.resp_headers = headers;
        ctx.body = Some(body.to_vec());
        if run_wasm_filters(loc, ctx, true) {
            return error_page(StatusCode::INTERNAL_SERVER_ERROR);
        }
        status = ctx.status;
        headers = std::mem::take(&mut ctx.resp_headers);
        body = Bytes::from(ctx.body.take().unwrap_or_default());
    }
    build_buffered_response(status, &headers, body, loc, server, status_tag, true, ctx)
}

/// `proxy_cache_revalidate` 拿到 304 后的收口：状态与 body 用缓存里那份，**头按 304 刷新**，
/// 有效期重算后写回缓存，响应带 `X-Cache-Status: REVALIDATED`。
///
/// 上游答 304 时不附带 body，所以这里绝不能去"收集响应体"——那会得到一个空体并把
/// 好端端的缓存条目覆盖成空响应（nginx 用同一套 if/else 规避，这里用独立的收口函数）。
async fn serve_revalidated(
    state: &Arc<AppState>,
    loc: &Location,
    server: &Server,
    ctx: &mut RequestCtx,
    stored: &Arc<crate::proxy_cache::CachedResponse>,
    zone_key: (&str, &str),
    fresh: &hyper::HeaderMap,
) -> BoxResponse {
    let (zone, key) = zone_key;
    let counts =
        |name: &str| crate::proxy_cache::header_counts_for_cache(name, &loc.proxy_ignore_headers);
    let mut fresh_h: Vec<(String, String)> = Vec::new();
    for (k, v) in fresh.iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        fresh_h.push((name.to_string(), v.to_str().unwrap_or("").to_string()));
    }
    let merged = crate::proxy_cache::merge_revalidated(&stored.headers, &fresh_h);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // 有效期的口径与普通写入一致：先看上游这次说了什么（Cache-Control/Expires），
    // 上游什么都没说才回落到 `proxy_cache_valid` 里 200 的那条（304 描述的是同一个对象）。
    let decided: Vec<(String, String)> =
        merged.iter().filter(|(k, _)| counts(k)).cloned().collect();
    let ttl = crate::proxy_cache::effective_ttl(&loc.proxy_cache_valid, 200, &decided, now_unix);
    if let Some(ttl) = ttl {
        state.proxy_cache.store_as(
            &zone,
            &key,
            crate::proxy_cache::CachedResponse {
                status: stored.status,
                headers: merged.clone(),
                body: Arc::clone(&stored.body),
            },
            ttl,
            state.limits.is_vip(&ctx.remote_addr),
        );
    }
    ctx.cache_status = "REVALIDATED".to_string();
    let resp = Arc::new(crate::proxy_cache::CachedResponse {
        status: stored.status,
        headers: merged,
        body: Arc::clone(&stored.body),
    });
    serve_from_cache(resp, loc, server, "REVALIDATED", ctx)
}

/// 由缓冲好的状态/头/字节构造最终响应；`with_status_tag` 为真时附带 `X-Cache-Status`。
fn build_buffered_response(
    status: u16,
    headers: &[(String, String)],
    body: Bytes,
    loc: &Location,
    server: &Server,
    status_tag: &str,
    with_status_tag: bool,
    ctx: &RequestCtx,
) -> BoxResponse {
    let mut builder =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));
    {
        let hm = builder.headers_mut().unwrap();
        if let Ok(v) = HeaderValue::from_str(SERVER_HEADER) {
            hm.insert(SERVER, v);
        }
        for (k, v) in headers {
            if is_hop_by_hop(k) || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                // Set-Cookie 允许多条共存（append 而非 insert，避免折叠重复头）。
                if name.as_str() == "set-cookie" {
                    hm.append(name, val);
                } else {
                    hm.insert(name, val);
                }
            }
        }
        push_add_headers(hm, Some(loc), server, ctx);
        push_expires(hm, Some(loc), server, status);
        if with_status_tag {
            crate::metrics::get().record_cache_status(status_tag);
            if let Ok(val) = HeaderValue::from_str(status_tag) {
                hm.insert(HeaderName::from_static("x-cache-status"), val);
            }
            // RFC 9209：本机作为源站，把自己那层缓存判定报给前置代理，让它能量化"回源有多少
            // 是真活、多少是命中"。只在 egress 且直连对端验证过时才报——没验证就等于不知道
            // 对面是不是声明的那家，报出去只会污染它的观测。
            if server.front_proxy.mode == crate::front_proxy::FrontProxyMode::Egress
                && ctx.front_proxy_verified
            {
                let prev = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("cache-status"))
                    .map(|(_, v)| v.as_str());
                let ours = crate::front_proxy::cache_status_field(status_tag);
                if let Ok(val) =
                    HeaderValue::from_str(&crate::front_proxy::append_cache_status(prev, &ours))
                {
                    hm.insert(HeaderName::from_static("cache-status"), val);
                }
            }
        }
        apply_proxied_header_rewrites(hm, loc);
    }
    // sub_filter 输出过滤器：改写缓冲好的响应体（Content-Length 之后按新体重算）。
    let body = if loc.sub_filter.is_some() {
        let ct = crate::engine::header_lookup_content_type(headers);
        let replaced =
            crate::engine::apply_sub_filter(loc.sub_filter.as_ref(), ct.as_deref(), body.to_vec());
        Bytes::from(replaced)
    } else {
        body
    };
    let len = body.len();
    let resp = builder.body(full_body(body));
    match resp {
        Ok(mut r) => {
            if let Ok(v) = HeaderValue::from_str(&len.to_string()) {
                r.headers_mut().insert(CONTENT_LENGTH, v);
            }
            r
        }
        Err(_) => error_page(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Lua / Rust 处理器产出的响应：resp_headers + add_header + Server 头
fn finish_response(ctx: &RequestCtx, server: &Server, loc: Option<&Location>) -> BoxResponse {
    let status = StatusCode::from_u16(ctx.status).unwrap_or(StatusCode::OK);
    // sub_filter 输出过滤器（content_by_lua / return 产出的响应体）。
    let body = match loc.and_then(|l| l.sub_filter.as_ref()) {
        Some(_) => {
            let ct = crate::engine::header_lookup_content_type(&ctx.resp_headers);
            crate::engine::apply_sub_filter(
                loc.and_then(|l| l.sub_filter.as_ref()),
                ct.as_deref(),
                ctx.body.clone().unwrap_or_default(),
            )
        }
        None => ctx.body.clone().unwrap_or_default(),
    };
    let mut builder = Response::builder().status(status);
    {
        let hm = builder.headers_mut().unwrap();
        for (k, v) in &ctx.resp_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                // resp_headers 里的同名多行（如多条 Set-Cookie）必须 append 保留
                if hm.contains_key(&name) {
                    hm.append(name, val);
                } else {
                    hm.insert(name, val);
                }
            }
        }
        push_add_headers(hm, loc, server, ctx);
        push_expires(hm, loc, server, ctx.status);
        if !hm.contains_key(hyper::header::CONTENT_TYPE) && !body.is_empty() {
            hm.insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
    }
    builder
        .body(full_body(body))
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

fn redirect_response(code: u16, target: &str) -> BoxResponse {
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND))
        .header("location", target)
        .header("server", SERVER_HEADER)
        .body(full_body(String::new()))
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 按 error_page 指令返回自定义错误页；目标文件不存在则退回内置默认页。
/// 读文件放进 spawn_blocking：错误路径同样不能阻塞 async worker。
async fn error_response(
    ctx: &mut RequestCtx,
    server: &Server,
    loc: Option<&Location>,
    code: u16,
) -> BoxResponse {
    ctx.status = code;
    let target = loc
        .and_then(|l| l.error_pages.get(&code))
        .or_else(|| server.error_pages.get(&code))
        .cloned();
    let base = loc
        .and_then(|l| l.root.as_ref().or(l.alias.as_ref()))
        .or(server.root.as_ref())
        .cloned();
    let file = match (target, base) {
        (Some(t), Some(base)) => {
            let f = base.join(t.trim_start_matches('/'));
            Some(f)
        }
        _ => None,
    };
    if let Some(file) = file {
        let read = tokio::task::spawn_blocking(move || {
            if file.is_file() {
                Some((
                    mime_of(&file).to_string(),
                    std::fs::read(&file).unwrap_or_default(),
                ))
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten();
        if let Some((mime, content)) = read {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            return Response::builder()
                .status(status)
                .header("content-type", mime)
                .header("server", SERVER_HEADER)
                .body(full_body(content))
                .unwrap_or_else(|_| error_page(status));
        }
    }
    error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

fn status_page(code: u16) -> BoxResponse {
    error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 显式要求关闭连接：用于请求体没读完就必须回错的场景（413/408）
fn close_now(mut resp: BoxResponse) -> BoxResponse {
    resp.headers_mut()
        .insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

fn set_header(resp: &mut BoxResponse, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
        resp.headers_mut().insert(n, v);
    }
}

/// add_header 对静态响应同样生效（这里覆盖的都是 2xx/3xx：nginx 的 add_header 默认不加到 4xx/5xx）
fn apply_add_headers(resp: &mut BoxResponse, loc: &Location, server: &Server, ctx: &RequestCtx) {
    let status = resp.status().as_u16();
    let hm = resp.headers_mut();
    push_add_headers(hm, Some(loc), server, ctx);
    push_expires(hm, Some(loc), server, status);
}

/// `expires` 在这一响上该落的头。与 add_header 共用同一批漏斗点，覆盖范围因此一致：
/// 静态、代理回源、缓存命中、buffered/Lua 流式都走得到；`off`/本级没写 = 空表 = 一字不动。
fn expires_pairs(loc: Option<&Location>, server: &Server, status: u16) -> Vec<(String, String)> {
    let Some(exp) = router::effective_expires(loc, server) else {
        return Vec::new();
    };
    exp.headers_for(status, unix_now() as i64)
}

/// 把 `expires` 的头写进 HeaderMap（后写覆盖：与 nginx 的 header filter 一样，
/// 网关的过期策略说了算，源站那份同名字段被替换掉）。
fn push_expires(hm: &mut hyper::HeaderMap, loc: Option<&Location>, server: &Server, status: u16) {
    for (k, v) in expires_pairs(loc, server, status) {
        if let (Ok(name), Ok(val)) = (
            HeaderName::try_from(k.as_str()),
            HeaderValue::try_from(v.as_str()),
        ) {
            hm.insert(name, val);
        }
    }
}

/// nginx 的 add_header：`Parameter value can contain variables.`
/// 每个响应按当前请求做一次变量展开；取值失败的头仍然加（nginx 的 headers filter 不因空值跳过），
/// 缺失的 `$arg_/$cookie_/$http_` 之类就是空串——这正是 `$upstream_cache_status` 在非缓存方法下
/// 该表现成空串的原因。
fn push_add_headers(
    hm: &mut hyper::HeaderMap,
    loc: Option<&Location>,
    server: &Server,
    ctx: &RequestCtx,
) {
    for (k, v) in router::effective_add_headers(loc, server) {
        let val = crate::proxy::interpolate_vars(v, ctx);
        if let (Ok(name), Ok(hv)) = (
            HeaderName::try_from(k.as_str()),
            HeaderValue::try_from(val.as_str()),
        ) {
            hm.insert(name, hv);
        }
    }
}

/// nginx/OpenResty 风格默认错误页
/// Upgrade 请求的完整处理：路由 → 与后端完成 101 握手 → 返回 101 响应 →
/// 把客户端连接交给 hyper 的升级机制，spawn 一条双向 TCP 管道。
async fn handle_upgrade(
    state: Arc<AppState>,
    meta: Arc<ConnMeta>,
    rec: Arc<LogRecord>,
    req: &mut Request<Incoming>,
) -> BoxResponse {
    let host = request_host(req.headers(), req.uri());
    let router = state.routing();
    let server = match router.match_server(meta.listener, host.as_deref()) {
        Some(s) => Arc::clone(s),
        None => return error_page(StatusCode::NOT_FOUND),
    };
    let path = match decode_and_normalize(req.uri().path()) {
        Some(p) => p,
        None => return error_page(StatusCode::BAD_REQUEST),
    };
    let mut ctx = RequestCtx {
        method: req.method().as_str().to_string(),
        path,
        query: req.uri().query().unwrap_or("").to_string(),
        uri: req.uri().to_string(),
        host,
        remote_addr: rec.remote(),
        remote_port: meta.peer.map(|p| p.port()).unwrap_or(0),
        server_port: meta.listener.port(),
        req_headers: header_pairs(req.headers()),
        resp_headers: Vec::new(),
        rewritten_path: None,
        status: 101,
        body: None,
        stream: None,
        done: false,
        internal_redirect: false,
        req_body: Bytes::new(),
        exec_depth: 0,
        redirect: None,
        scheme: meta.scheme.to_string(),
        internal_request: false,
        filter_chunk: None,
        filter_eof: false,
        listener: Some(meta.listener),
        capture_depth: 0,
        balancer_peer: None,
        balancer_timeouts: None,
        balancer_more_failures: None,
        balancer_recreate_request: false,
        upstream_addr: String::new(),
        upstream_status: 0,
        proxy_split: String::new(),
        proxy_split_served: String::new(),
        upstream_header_time: 0.0,
        ssl: None,
        start_time: unix_now(),
        http_version: http_version_f64(req.version()),
        body_builder: None,
        eof_sent: false,
        cache_status: String::new(),
        still_online: String::new(),
        front_proxy: String::new(),
        front_proxy_country: String::new(),
        front_proxy_host: String::new(),
        front_proxy_verified: false,
        realip_remote_addr: meta.peer.map(|p| p.ip().to_string()).unwrap_or_default(),
        set_vars: Vec::new(),
        rewrite_return: None,
    };
    // Upgrade 不再是旁路：realip / limit_conn / rewrite / limit_req / allow-deny / auth /
    // access_by_lua 全部与普通请求一致，之后才允许进入 101 切换。
    apply_realip(&server, &mut ctx, meta.peer);
    apply_front_proxy(&server, &mut ctx, meta.peer);
    rec.set_remote(ctx.remote_addr.clone());
    let loc0 = Router::match_location(&server, ctx.effective_path());
    let conn_guards = match acquire_conn_guards(&state, &server, loc0, &ctx) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    let location = match run_ingress(&state, &mut ctx, &server).await {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let Some(target) = &location.proxy_pass else {
        return error_page(StatusCode::BAD_REQUEST);
    };
    // Upgrade 与 forward 同语义：proxy_pass 主机位是变量时按请求插值，
    // 业务分流同样作用于 WebSocket 隧道（字面量目标恒走借用，不额外分配）。
    let proxy_pass: std::borrow::Cow<'_, str> = if target.contains('$') {
        crate::proxy::interpolate_vars(target, &ctx).into()
    } else {
        target.as_str().into()
    };

    // Upgrade 与普通转发同语义：balancer_by_lua 先选点，set_timeouts 覆盖本跳超时
    if run_phases(&state, &mut ctx, &location, Phase::Balancer, &server).await {
        return error_response(&mut ctx, &server, Some(&location), 500).await;
    }

    let timeouts = ProxyTimeouts {
        connect: location.proxy_connect_timeout,
        send: location.proxy_send_timeout,
        read: location.proxy_read_timeout,
    };
    let set_headers_ref: Vec<(&str, &str)> = location
        .proxy_set_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let opts = ProxyOpts {
        set_headers: &set_headers_ref,
        timeouts,
        next_upstream: &location.proxy_next_upstream,
        next_upstream_tries: location.proxy_next_upstream_tries,
        next_upstream_timeout: location.proxy_next_upstream_timeout,
        tls: &location.proxy_tls,
        split: location.route_split.as_ref(),
        split_failover: location.split_failover.clone(),
        var_targets: location.var_targets.as_ref(),
    };

    let tunnel = match state.proxy.upgrade(&mut ctx, &proxy_pass, &opts).await {
        Ok(t) => t,
        Err(e) => {
            log_warn!("WebSocket 升级失败: {}", e);
            rec.set_upstream(
                ctx.upstream_addr.clone(),
                ctx.upstream_status,
                ctx.upstream_header_time,
            );
            let code = crate::proxy::upstream_error_status(&e);
            return error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY));
        }
    };
    rec.set_upstream(
        ctx.upstream_addr.clone(),
        ctx.upstream_status,
        ctx.upstream_header_time,
    );

    // 后端 101 头原样转发（Sec-WebSocket-Accept 由后端计算，不能自造）
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in &tunnel.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = match builder.body(full_body(Vec::<u8>::new())) {
        Ok(r) => r,
        Err(e) => {
            log_warn!("101 响应构造失败: {}", e);
            return error_page(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // 在 Request 上登记升级交接；响应写出后 hyper 把客户端裸流交给我们
    let on = hyper::upgrade::on(&mut *req);
    // upstream 并发额度覆盖整条隧道：随 pump 任务结束（任一方向断开/空闲超时）才释放
    let upstream_guard = tunnel.guard;
    let backend = PrefixedTcp::new(tunnel.prefix, tunnel.stream);
    // 空闲超时对齐 nginx 的 proxy_read_timeout（0 = 不限）；balancer set_timeouts 覆盖首跳后
    // 同样约束整条隧道。同时用内联 join 而不是嵌套 spawn，保证连接任务被 abort 时两个方向一起结束。
    let idle = ctx
        .balancer_timeouts
        .map(|t| Duration::from_millis(t.2))
        .unwrap_or(location.proxy_read_timeout);
    tokio::spawn(async move {
        let _conn_guards = conn_guards; // limit_conn 的额度覆盖整条 WebSocket 生命周期
        let _upstream_guard = upstream_guard; // upstream max_conns 同理
        match on.await {
            Ok(upgraded) => {
                // Upgraded 实现 hyper 自带 IO trait，用 TokioIo 桥到 tokio traits
                let client = hyper_util::rt::TokioIo::new(upgraded);
                let (mut cr, mut cw) = tokio::io::split(client);
                let (mut br, mut bw) = tokio::io::split(backend);
                tokio::join!(
                    async {
                        crate::stream::pump(&mut br, &mut cw, idle).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut cw).await;
                    },
                    async {
                        crate::stream::pump(&mut cr, &mut bw, idle).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut bw).await;
                    }
                );
            }
            Err(e) => log_warn!("upgrade 交接失败: {}", e),
        }
    });
    resp
}

/// 先吐出一段缓存字节、再透传后端流的读包装：
/// 后端可能在 101 头之后立刻抢跑发了 WS 帧，这些前导字节不能丢。
/// `inner` 是 `ProxyStream`（明文 TCP 或 wss/https 后端的 TLS 流）。
struct PrefixedTcp {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: crate::proxy_tls::ProxyStream,
}

impl PrefixedTcp {
    fn new(prefix: Vec<u8>, inner: crate::proxy_tls::ProxyStream) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl tokio::io::AsyncRead for PrefixedTcp {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let data = this.prefix.get_ref();
        let pos = this.prefix.position() as usize;
        if pos < data.len() && buf.remaining() > 0 {
            let n = buf.remaining().min(data.len() - pos);
            let dst = buf.initialize_unfilled_to(n);
            dst.copy_from_slice(&data[pos..pos + n]);
            buf.advance(n);
            this.prefix.set_position((pos + n) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedTcp {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn error_page(status: StatusCode) -> BoxResponse {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!(
        "<html>\n<head><title>{code} {reason}</title></head>\n<body>\n<center><h1>{code} {reason}</h1></center>\n<hr><center>{SERVER_HEADER}</center>\n</body>\n</html>\n"
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", SERVER_HEADER)
        .body(full_body(body))
        .unwrap_or_else(|_| {
            // 连状态码都不合法时（理论不可达）退回 500 的裸响应
            Response::new(empty_body())
        })
}

fn mime_of(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" | "lua" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

// ==================== 工具 ====================

use hyper::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
const HOST_NAME: HeaderName = HeaderName::from_static("host");

fn proto_name(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

fn header_of(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

fn is_supported_method(m: &Method) -> bool {
    matches!(
        m.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

/// 路径解码 + 归一化（RFC 3986）：
/// - `%XX` 百分号解码（不把 '+' 当空格：那是表单编码的规则，不适用于路径）
/// - `\` 视作 `/`（Windows 文件系统把反斜杠当分隔符，不处理会绕过穿越检测）
/// - 消除 `.` / `..`；`..` 越出根 → 拒绝
/// - 解码后含 NUL 或控制字符 → 拒绝
fn decode_and_normalize(raw: &str) -> Option<String> {
    if raw.contains('\0') {
        return None;
    }
    let mut decoded: Vec<u8> = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                let b = u8::from_str_radix(hex, 16).ok()?;
                // 编码过的分隔符与控制字符同样危险（%2e%2e%2f、%00 之类）
                if b == b'/' || b < 0x20 || b == 0x7f {
                    return None;
                }
                decoded.push(b);
                i += 3;
            }
            b'%' => return None, // 截断的 % 转义
            c => {
                decoded.push(c);
                i += 1;
            }
        }
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    if decoded.chars().any(|c| (c as u32) < 0x20 || c == '\0') {
        return None;
    }
    let unified = decoded.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    for seg in unified.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segs.pop().is_none() {
                    return None;
                }
            }
            _ => segs.push(seg),
        }
    }
    let mut out = String::with_capacity(unified.len() + 1);
    out.push('/');
    out.push_str(&segs.join("/"));
    // 保留尾部斜杠：目录语义（index / 301 补斜杠）依赖它
    if unified.ends_with('/') && !out.ends_with('/') {
        out.push('/');
    }
    Some(out)
}

/// 供 main 使用的连接额度表
pub fn permits_for(settings: &Settings) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(
        settings.worker_connections.max(1),
    ))
}

// ==================== HTTP/3（QUIC/UDP）服务 ====================

/// 为一个 `listen ... quic` 端点绑定 QUIC/UDP 并按 HTTP/3 接受连接。
///
/// 复用与 TCP 监听完全相同的请求核心（`handle_request`）：h3 请求体先擦成 `ProxyReqBody`，
/// 响应体仍是传输无关的 `RespBody`，因此 vhost/location/rewrite/access/proxy/lua 全部阶段
/// 在 HTTP/1.1、HTTP/2、HTTP/3 上行为一致。证书走 `tls::make_quic_server_config`
/// （锁 TLS1.3、ALPN=h3、多证书 SNI；与热重载共用同一构造路径）。
///
/// 已知边界：WebSocket/Upgrade 隧道只在 hyper（HTTP/1.1 over TCP）上接管原始 socket，
/// HTTP/3 不支持 Upgrade；热重载沿用共享的 `RwLock<Arc<Router>>`，无需重新绑定 UDP。
pub async fn serve_quic(
    state: Arc<AppState>,
    listener: crate::router::Listener,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = listener.addr;
    let server_cfg = match &listener.tls {
        Some(opts) => match crate::tls::make_quic_server_config(opts, MAX_CONCURRENT_STREAMS) {
            Ok(c) => c,
            Err(e) => {
                log_error!("{addr} QUIC TLS 配置无效: {e}，该监听退出");
                return;
            }
        },
        None => {
            log_error!("{addr} quic 监听缺少 TLS 证书（quic 隐含 ssl），该监听退出");
            return;
        }
    };
    let endpoint = match quinn::Endpoint::server(server_cfg, addr) {
        Ok(e) => e,
        Err(e) => {
            log_error!("{addr} 绑定 QUIC/UDP 失败: {e}，该监听退出");
            return;
        }
    };
    state.tls_registry.register_quic(addr, endpoint.clone());
    log_info!("监听 https://{addr}（QUIC/HTTP/3，ALPN h3）");

    let mut tasks = tokio::task::JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        let incoming = tokio::select! {
            _ = shutdown.changed() => break,
            inc = endpoint.accept() => inc,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let Some(incoming) = incoming else {
            break; // endpoint 已关闭
        };
        let peer = incoming.remote_address();
        match incoming.accept() {
            Ok(connecting) => {
                let state = Arc::clone(&state);
                tasks.spawn(async move {
                    let conn = match connecting.await {
                        Ok(c) => c,
                        Err(e) => {
                            crate::metrics::get().on_tls_handshake_failure();
                            crate::log_warn!("QUIC 握手失败 {peer}: {e}");
                            return;
                        }
                    };
                    serve_h3_connection(state, conn, addr).await;
                });
            }
            Err(e) => log_debug!("QUIC incoming 接受失败 {peer}: {e}"),
        }
    }
    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    drain_connections(&mut tasks, state.settings.shutdown_grace, addr).await;
    endpoint.wait_idle().await;
}

/// 单条 QUIC 连接：建立 h3 server 连接，循环 accept 请求流并各自成任务，
/// 使慢请求不会阻塞后续请求（与 h2 的多路复用语义一致）。
async fn serve_h3_connection(state: Arc<AppState>, conn: quinn::Connection, listener: SocketAddr) {
    let peer = conn.remote_address();
    let _permit = match state.permits.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            conn.close(quinn::VarInt::from_u32(0), b"overloaded");
            log_debug!("连接数已达 worker_connections，拒绝 QUIC {peer}");
            return;
        }
    };
    let _active = crate::metrics::ActiveConnGuard::new(crate::metrics::get());

    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::builder().build(h3_conn).await {
            Ok(c) => c,
            Err(e) => {
                log_debug!("HTTP/3 连接建立失败 {peer}: {e:?}");
                return;
            }
        };

    let requests = Arc::new(AtomicU64::new(0));
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                crate::metrics::get().on_request();
                let meta = Arc::new(ConnMeta {
                    listener,
                    peer: Some(peer),
                    scheme: "https",
                    http1: false,
                    alt_svc: None,
                    requests: Arc::clone(&requests),
                });
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(state, meta, resolver).await {
                        log_debug!("HTTP/3 请求结束: {e:?}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                log_debug!("HTTP/3 accept 出错 {peer}: {e:?}");
                break;
            }
        }
    }
    // 连接收尾：优雅发 GOAWAY，等在途请求自然结束（客户端已断开则忽略错误）
    let _ = h3_conn.shutdown(0).await;
}

/// 单个 h3 请求：解析请求头/体 → 走传输无关核心 → 逐帧写回响应。
async fn handle_h3_request(
    state: Arc<AppState>,
    meta: Arc<ConnMeta>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (req, stream) = resolver.resolve_request().await?;
    let (parts, ()) = req.into_parts();
    let (mut send, recv) = stream.split();

    // 请求体：recv_data 逐帧适配成 ProxyReqBody，交给核心里的 read_body 做限长/超时
    let body_stream = futures_util::stream::unfold(recv, |mut rs| async move {
        match rs.recv_data().await {
            Ok(Some(mut buf)) => {
                let data = buf.copy_to_bytes(buf.remaining());
                Some((Ok::<_, crate::proxy::BoxError>(Frame::data(data)), rs))
            }
            Ok(None) => None,
            Err(e) => Some((
                Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "h3 recv error: {e:?}"
                ))),
                rs,
            )),
        }
    });
    let body: crate::proxy::ProxyReqBody =
        BoxBody::new(http_body_util::StreamBody::new(body_stream));

    let remote = meta
        .peer
        .map(|p| p.ip().to_string())
        .unwrap_or_else(|| "-".into());
    let header_str = |name: &str| -> String {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string()
    };
    let accept_encoding = parts
        .headers
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let rec = state.access_log.record(
        remote,
        parts.method.as_str().to_string(),
        request_target(&parts.uri, parts.version),
        proto_name(parts.version).to_string(),
        header_str("referer"),
        header_str("user-agent"),
    );

    let breq = Request::from_parts(parts, body);
    let handled = std::panic::AssertUnwindSafe(handle_request(
        Arc::clone(&state),
        Arc::clone(&meta),
        Arc::clone(&rec),
        breq,
    ))
    .catch_unwind()
    .await;
    let resp = match handled {
        Ok(r) => r,
        Err(p) => {
            log_error!(
                "HTTP/3 请求处理 panic（已隔离，返回 500）: {}",
                panic_text(&p)
            );
            error_page(StatusCode::INTERNAL_SERVER_ERROR)
        }
    };
    // finalize 记账状态码 / Server 头 / gzip / 访问日志字节计数；must_close=false（h3 无 Connection:close）
    let resp = finalize(&state, &rec, resp, false, &accept_encoding);

    let (mut resp_parts, mut resp_body) = resp.into_parts();
    // HTTP/3 禁止逐跳头（RFC 9114 §4.2）：这些是 TCP 层的概念，QUIC 连接上没有对应语义
    let hop_by_hop = [
        hyper::header::CONNECTION,
        hyper::header::TRANSFER_ENCODING,
        hyper::header::UPGRADE,
        HeaderName::from_static("keep-alive"),
    ];
    for h in hop_by_hop {
        resp_parts.headers.remove(h);
    }
    send.send_response(Response::from_parts(resp_parts, ()))
        .await?;
    while let Some(frame) = resp_body.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    if !data.is_empty() {
                        send.send_data(data).await?;
                    }
                }
            }
            Err(_) => break,
        }
    }
    send.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_for(base: PathBuf, path: &str) -> StaticSnap {
        StaticSnap {
            base,
            is_alias: false,
            pattern: "/".to_string(),
            path: path.to_string(),
            query: String::new(),
            index: vec!["index.html".to_string()],
            autoindex: false,
            try_files: None,
            negotiable: true,
            if_none_match: None,
            if_modified_since: None,
            if_range: None,
            range: None,
        }
    }

    /// 每个用例一个独立临时目录，避免静态缓存与用例互相污染
    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "onrouter-static-{}-{}-{}",
            tag,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn request_uri_on_h2_is_path_and_query_not_absolute() {
        let abs: hyper::Uri = "https://yxp.hk/redir?x=1".parse().unwrap();
        assert_eq!(request_target(&abs, Version::HTTP_2), "/redir?x=1");
        assert_eq!(request_target(&abs, Version::HTTP_3), "/redir?x=1");
        // h1 的绝对形式请求行原样进 $request_uri（与 nginx 一致）
        assert_eq!(
            request_target(&abs, Version::HTTP_11),
            "https://yxp.hk/redir?x=1"
        );
        let origin: hyper::Uri = "/redir?x=1".parse().unwrap();
        assert_eq!(request_target(&origin, Version::HTTP_11), "/redir?x=1");
    }

    #[test]
    fn etag_and_last_modified_come_from_mtime_and_size() {
        let dir = tmp_dir("etag");
        std::fs::write(dir.join("a.txt"), b"hello world").unwrap();
        let snap = snap_for(dir.clone(), "/a.txt");
        let hit = resolve_snap(&snap);
        let StaticHit::File {
            meta: Some(m),
            body: FileSource::Memory(body),
            ..
        } = hit
        else {
            panic!("应为文件命中，实际 {hit:?}");
        };
        assert_eq!(m.size, 11);
        assert_eq!(m.etag, etag_of(m.mtime, 11));
        assert_eq!(&body[..], b"hello world");
        // 同 (mtime,size) 必须得到同一个 ETag：这是 304 判定的前提
        assert_eq!(m.etag, etag_of(m.mtime, 11));
        assert!(m.last_modified.ends_with("GMT"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn if_none_match_hits_304() {
        let dir = tmp_dir("inm");
        std::fs::write(dir.join("a.txt"), b"hello world").unwrap();
        let mut snap = snap_for(dir.clone(), "/a.txt");
        let StaticHit::File { meta: Some(m), .. } = resolve_snap(&snap) else {
            panic!("先取到 ETag");
        };
        // 原样带上服务器发出的 ETag
        snap.if_none_match = Some(m.etag.clone());
        assert!(matches!(resolve_snap(&snap), StaticHit::NotModified(mm) if mm.etag == m.etag));
        // 弱校验位与多值列表同样算命中（RFC 9110 对 If-None-Match 用弱比较）
        snap.if_none_match = Some(format!("W/{}, \"other\"", m.etag));
        assert!(matches!(resolve_snap(&snap), StaticHit::NotModified(_)));
        // 星号表示"任何版本"
        snap.if_none_match = Some("*".to_string());
        assert!(matches!(resolve_snap(&snap), StaticHit::NotModified(_)));
        // 不匹配就照常 200
        snap.if_none_match = Some("\"deadbeef-0\"".to_string());
        assert!(matches!(resolve_snap(&snap), StaticHit::File { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn if_modified_since_is_secondary_to_etag() {
        let dir = tmp_dir("ims");
        std::fs::write(dir.join("a.txt"), b"hello world").unwrap();
        let mut snap = snap_for(dir.clone(), "/a.txt");
        let StaticHit::File { meta: Some(m), .. } = resolve_snap(&snap) else {
            panic!("先取到 mtime");
        };
        // 条件时间 >= 文件 mtime：未修改
        snap.if_modified_since = Some(http_date(m.mtime + 5));
        assert!(matches!(resolve_snap(&snap), StaticHit::NotModified(_)));
        // 条件时间早于 mtime：修改过，正常返回
        snap.if_modified_since = Some(http_date(m.mtime.saturating_sub(5)));
        assert!(matches!(resolve_snap(&snap), StaticHit::File { .. }));
        // 非法日期：忽略条件头，不能误判成 304
        snap.if_modified_since = Some("not-a-date".to_string());
        assert!(matches!(resolve_snap(&snap), StaticHit::File { .. }));
        // 两者同时存在时 If-None-Match 优先（哪怕 IMS 说没修改）
        snap.if_modified_since = Some(http_date(m.mtime + 5));
        snap.if_none_match = Some("\"stale-etag\"".to_string());
        assert!(matches!(resolve_snap(&snap), StaticHit::File { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_slices_the_body() {
        let dir = tmp_dir("range");
        std::fs::write(dir.join("a.txt"), b"0123456789").unwrap();
        let cases = [
            ("bytes=0-4", Some((0u64, 4u64)), b"01234".as_slice()),
            ("bytes=3-", Some((3, 9)), b"3456789".as_slice()),
            ("bytes=-3", Some((7, 9)), b"789".as_slice()),
            // 超出末尾的结束值截到文件尾（RFC 9110 §14.1.1）
            ("bytes=5-99", Some((5, 9)), b"56789".as_slice()),
            // 多段与非法语法：按 nginx 语义忽略 Range，回整份 200
            ("bytes=0-1,4-5", None, b"0123456789".as_slice()),
            ("items=0-1", None, b"0123456789".as_slice()),
            ("bytes=abc-def", None, b"0123456789".as_slice()),
        ];
        for (hdr, window, want) in cases {
            let mut snap = snap_for(dir.clone(), "/a.txt");
            snap.range = Some(hdr.to_string());
            let hit = resolve_snap(&snap);
            let StaticHit::File {
                body: FileSource::Memory(body),
                window: got,
                ..
            } = hit
            else {
                panic!("{hdr} 应命中文件");
            };
            assert_eq!(got, window, "{hdr} 的区间");
            assert_eq!(body, want, "{hdr} 的内容");
        }
        // 起点越界 → 416
        let mut snap = snap_for(dir.clone(), "/a.txt");
        snap.range = Some("bytes=100-120".to_string());
        assert!(matches!(
            resolve_snap(&snap),
            StaticHit::RangeUnsatisfiable(_)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn if_range_mismatch_falls_back_to_whole_file() {
        let dir = tmp_dir("ifrange");
        std::fs::write(dir.join("a.txt"), b"0123456789").unwrap();
        let mut snap = snap_for(dir.clone(), "/a.txt");
        snap.range = Some("bytes=0-3".to_string());
        let StaticHit::File { meta: Some(m), .. } = resolve_snap(&snap) else {
            panic!("先取到 ETag");
        };
        // 客户端缓存的校验位已过期：不能给 206，给整份 200
        snap.if_range = Some("\"deadbeef-99\"".to_string());
        let StaticHit::File {
            body: FileSource::Memory(body),
            window,
            ..
        } = resolve_snap(&snap)
        else {
            panic!("应命中文件");
        };
        assert_eq!(window, None);
        assert_eq!(&body[..], b"0123456789");
        // 校验位一致时 Range 生效
        snap.if_range = Some(m.etag.clone());
        let StaticHit::File {
            window,
            body: FileSource::Memory(body),
            ..
        } = resolve_snap(&snap)
        else {
            panic!("应命中文件");
        };
        assert_eq!(window, Some((0, 3)));
        assert_eq!(&body[..], b"0123");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_safe_methods_skip_negotiation() {
        let dir = tmp_dir("post");
        std::fs::write(dir.join("a.txt"), b"hello world").unwrap();
        let mut snap = snap_for(dir.clone(), "/a.txt");
        let StaticHit::File { meta: Some(m), .. } = resolve_snap(&snap) else {
            panic!("先取到 ETag");
        };
        // POST 参与静态兜底时不该收到 304/206
        snap.negotiable = false;
        snap.if_none_match = Some(m.etag.clone());
        snap.range = Some("bytes=0-2".to_string());
        let StaticHit::File {
            body: FileSource::Memory(body),
            window,
            ..
        } = resolve_snap(&snap)
        else {
            panic!("应命中文件");
        };
        assert_eq!(window, None);
        assert_eq!(&body[..], b"hello world");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hidden_files_are_not_served() {
        assert!(hidden_hit("/.env"));
        assert!(hidden_hit("/app/.git/config"));
        assert!(hidden_hit("/backup/.bashrc.bak"));
        assert!(!hidden_hit("/.well-known/acme-challenge/token"));
        assert!(!hidden_hit("/index.html"));
        assert!(!hidden_hit("/"));

        let dir = tmp_dir("hidden");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/config"), b"[core]-secret").unwrap();
        std::fs::write(dir.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(dir.join("visible.txt"), b"ok").unwrap();
        assert!(matches!(
            resolve_snap(&snap_for(dir.clone(), "/.env")),
            StaticHit::NotFound
        ));
        assert!(matches!(
            resolve_snap(&snap_for(dir.clone(), "/.git/config")),
            StaticHit::NotFound
        ));
        // 同一目录下的普通文件不受影响
        let StaticHit::File {
            body: FileSource::Memory(body),
            ..
        } = resolve_snap(&snap_for(dir.clone(), "/visible.txt"))
        else {
            panic!("普通文件应照常服务");
        };
        assert_eq!(&body[..], b"ok");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_parsing_edges() {
        assert!(matches!(
            parse_range("bytes=0-0", 10),
            RangeReq::Window(0, 0)
        ));
        assert!(matches!(
            parse_range("bytes=-0", 10),
            RangeReq::Unsatisfiable
        ));
        assert!(matches!(
            parse_range("bytes=0-", 0),
            RangeReq::Unsatisfiable
        ));
        assert!(matches!(parse_range("bytes=-5", 3), RangeReq::Window(0, 2)));
        assert!(matches!(parse_range("bytes=4-2", 10), RangeReq::Ignored));
        assert!(matches!(parse_range("bytes = 0-1", 10), RangeReq::Ignored));
        assert!(matches!(
            parse_range("bytes=0-1,2-3", 10),
            RangeReq::Ignored
        ));
    }

    #[test]
    fn http_dates_round_trip() {
        let s = http_date(1_760_000_000);
        assert!(s.ends_with("GMT"), "{s}");
        assert_eq!(parse_http_date(&s), Some(1_760_000_000));
        // 老式 RFC 850 与 Netscape 格式也得认
        assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
        assert!(parse_http_date("November 6, 1994 8:49:37 AM").is_none());
        assert!(parse_http_date("").is_none());
    }

    #[tokio::test]
    async fn large_files_and_ranges_stream_from_disk() {
        let dir = tmp_dir("diskstream");
        let data: Vec<u8> = (0..(FILE_CACHE_MAX_FILE as usize + 4096))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(dir.join("big.bin"), &data).unwrap();

        // 超过缓存阈值 → 不整份入内存，只登记磁盘区间
        let hit = resolve_snap(&snap_for(dir.clone(), "/big.bin"));
        let StaticHit::File {
            body: FileSource::Disk { start, len, .. },
            window: None,
            ..
        } = hit
        else {
            panic!("大文件应走磁盘流式：{hit:?}");
        };
        assert_eq!((start, len), (0, data.len() as u64));

        // Range 同理，且流式读出的字节与源文件一致（含端点）
        let mut snap = snap_for(dir.clone(), "/big.bin");
        let lo = FILE_CACHE_MAX_FILE + 17;
        snap.range = Some(format!("bytes={lo}-{}", lo + 99));
        let hit = resolve_snap(&snap);
        let StaticHit::File {
            body: FileSource::Disk { start, len, .. },
            window,
            ..
        } = hit
        else {
            panic!("大文件 Range 应走磁盘流式：{hit:?}");
        };
        assert_eq!(window, Some((lo, lo + 99)));
        assert_eq!((start, len), (lo, 100));
        let mut body = DiskBody::open(&dir.join("big.bin"), start, len)
            .await
            .expect("打开磁盘体");
        let mut got = Vec::new();
        while let Some(frame) = body.frame().await {
            got.extend_from_slice(frame.unwrap().data_ref().unwrap());
        }
        assert_eq!(got, &data[lo as usize..(lo + 100) as usize]);

        // 文件被截断/删除后打开失败 → 调用方回 404，而不是挂起或发出空体
        assert!(DiskBody::open(&dir.join("missing.bin"), 0, 10)
            .await
            .is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bypass_and_no_cache_predicates_follow_nginx_truthiness() {
        let mut c = RequestCtx::default();
        c.query = "a=1&b=0&c=&d=x".into();
        // 多值：任一表达式成立即成立
        assert!(cache_expr_truthy(&["$arg_b".into(), "$arg_a".into()], &c));
        assert!(cache_expr_truthy(
            &["$arg_a".into(), "$arg_nope".into()],
            &c
        ));
        // 空值、"0"、缺失变量都不成立（"0" 在 nginx 里明确是假）
        assert!(!cache_expr_truthy(&["$arg_c".into()], &c));
        assert!(!cache_expr_truthy(&["$arg_b".into()], &c));
        assert!(!cache_expr_truthy(
            &["$arg_nope".into(), "$http_x_nope".into()],
            &c
        ));
        // 字面量与模板
        assert!(cache_expr_truthy(&["always".into()], &c));
        assert!(cache_expr_truthy(&["prefix-$arg_d".into()], &c));
        // 没配指令 = 空列表 = 永不成立
        assert!(!cache_expr_truthy(&[], &c));
    }
}
