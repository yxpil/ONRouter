//! 反向代理：对标 Nginx 的 `proxy_pass`。
//!
//! - 支持 `proxy_pass http://upstream_name`（走 upstream 负载均衡）
//! - 支持 `proxy_pass http://host:port`（直连）
//! - 支持 `proxy_set_header` 覆盖/新增转发头（含 $remote_addr/$host/$scheme/$server_port/
//!   $proxy_add_x_forwarded_for 插值）
//! - `proxy_connect_timeout` 控制连接超时，`proxy_read_timeout` 控制等待响应头
//!   以及响应体两次相邻读取之间的空闲超时
//! - `proxy_next_upstream error timeout ...` 决定是否换节点重试
//!
//! 与 nginx 的差异（有意为之，避免踩坑）：
//! - 默认先把请求体缓冲完整再转发（Lua/限流/体大小检查都需要完整体）；
//!   `proxy_request_buffering off` 的 proxy location 改为边收边转发（流式，见 `ProxyBody::Streaming`），
//!   此时 Lua 读不到请求体、且无法换节点重试（字节一旦发给后端就不能回放），与 nginx 语义一致。
//! - 转发时的 `Content-Length`：缓冲路径按真实字节数重算（客户端谎报长度时不透传畸形）；
//!   流式路径由 hyper 依据转发体的 `size_hint` 重新决定成帧。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, UPGRADE};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_service::Service as _;

use crate::engine::RequestCtx;
use crate::engine::SplitRole;
use crate::proxy_tls::{ProxyConnector, ProxyStream, TlsPolicy};
use crate::router::SplitFailover;
use crate::upstream::{KeepaliveOpts, UpstreamGuard, UpstreamPool};
use crate::{log_info, log_warn};

/// 转发请求体统一擦除成 BoxBody：缓冲路径塞 `Full<Bytes>`，流式路径塞客户端的 `Incoming`，
/// 二者共用同一套连接池客户端（`Client` 的请求体类型是编译期固定的）。
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type ProxyReqBody = BoxBody<Bytes, BoxError>;
type HyperClient = Client<ProxyConnector, ProxyReqBody>;

fn full_boxed(b: Bytes) -> ProxyReqBody {
    Full::new(b).map_err(|e| match e {}).boxed()
}

/// 转发给后端的请求体来源。
/// - `Buffered`：整体已在内存里，可按 Content-Length 精确重发，因此允许换节点重试
/// - `Streaming`：把客户端的请求体（已从具体传输层擦除成 `ProxyReqBody`）管道给后端，
///   边收边发、内存 O(1)；字节一旦被后端消费就无法回放，故流式路径不参与换节点重试
///   （对齐 nginx `proxy_request_buffering off`）。
///   擦除后同一套代理逻辑既能吃 hyper 的 `Incoming`（HTTP/1.1、h2），也能吃 h3 的请求体流。
pub enum ProxyBody {
    Buffered(Option<Bytes>),
    Streaming(Option<ProxyReqBody>),
}

/// 请求体发送完成的信号。hyper 把最后一帧交给连接任务（或体一开始就为空）时置位；
/// `proxy_read_timeout` 只在请求发完之后才会计时 —— 上传阶段由 `proxy_send_timeout`
/// 按单次写操作兜底，两者不能互相冒充（nginx 语义）。
struct BodySent {
    inner: ProxyReqBody,
    done: Option<tokio::sync::watch::Sender<bool>>,
}

impl BodySent {
    fn signal(&mut self) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(true);
        }
    }
}

impl Body for BodySent {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        let finished = match &polled {
            Poll::Ready(None) => true,
            Poll::Ready(Some(Ok(_))) => this.inner.is_end_stream(),
            _ => false,
        };
        if finished {
            this.signal();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 等请求体发完后再等响应头，最多 `read`（0 = 不限）。
async fn read_deadline(done: &mut tokio::sync::watch::Receiver<bool>, read: Duration) {
    while !*done.borrow_and_update() {
        if done.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
    if read.is_zero() {
        std::future::pending::<()>().await;
    } else {
        tokio::time::sleep(read).await;
    }
}

/// 上游响应体包装：把 `proxy_read_timeout` 应用到**每一次体读取**（nginx 的语义是
/// 两次相邻读之间的空闲上限，而非整个响应体的总时长），并在体结束时结算 upstream guard。
///
/// guard 生命周期从“拿到响应头”延伸到“体读完/失败”：`max_conns` 并发计数覆盖整个响应，
/// 慢流式响应不会被提前漏计。中途超时/断连记一次节点失败并丢弃 `Incoming`，
/// hyper 不会把未读完的上游连接放回池（超时连接因此不会再被后续请求复用）。
/// 客户端主动断开时体被 drop：只释放计数，不把责任算到后端头上。
pub struct UpstreamBody {
    inner: Incoming,
    read: Duration,
    guard: Option<UpstreamGuard>,
    backend: String,
    /// 空闲读计时器：每收到一帧就 reset，避免每帧重新分配
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    settled: bool,
}

impl UpstreamBody {
    pub fn new(
        inner: Incoming,
        read: Duration,
        guard: Option<UpstreamGuard>,
        backend: String,
    ) -> Self {
        UpstreamBody {
            inner,
            read,
            guard,
            backend,
            timer: None,
            settled: false,
        }
    }

    /// 体结束/失败时结算一次（重复调用无副作用），同时释放并发计数。
    fn settle(&mut self, ok: bool) {
        if self.settled {
            return;
        }
        self.settled = true;
        if let Some(g) = self.guard.take() {
            if ok {
                g.note_success();
            } else {
                g.note_failure();
            }
        }
    }
}

impl std::fmt::Debug for UpstreamBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamBody")
            .field("backend", &self.backend)
            .field("read", &self.read)
            .field("settled", &self.settled)
            .finish()
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        // SAFETY: inner/timer 都是自持字段，从不移出结构体（与 GzipBody 相同的模式）
        let this = unsafe { self.get_unchecked_mut() };
        if this.settled {
            return Poll::Ready(None);
        }
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let deadline = tokio::time::Instant::now() + this.read;
                match &mut this.timer {
                    Some(t) => t.as_mut().reset(deadline),
                    None => this.timer = Some(Box::pin(tokio::time::sleep(this.read))),
                }
                // Content-Length 体在最后一帧时，传输层按长度即可判定结束，未必再 poll 一次 None；
                // 在这里补一次成功结算，避免这类响应的被动健康与成功指标永远不计。
                if this.inner.is_end_stream() {
                    this.settle(true);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.settle(false);
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => {
                this.settle(true);
                Poll::Ready(None)
            }
            Poll::Pending => {
                let read = this.read;
                let timer = this
                    .timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(read)));
                match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        crate::log_warn!(
                            "上游响应体读取超时 ({:?})，终止转发: {}",
                            read,
                            this.backend
                        );
                        this.settle(false);
                        Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("upstream body read timeout ({read:?})"),
                        )))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    /// 只有真正耗尽后才报告结束：空体也要先 poll 一次，guard 才能记上成功。
    fn is_end_stream(&self) -> bool {
        self.settled
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 每个代理 location 的超时（连接级 + 写空闲级 + 读响应头级）
#[derive(Debug, Clone, Copy)]
pub struct ProxyTimeouts {
    pub connect: Duration,
    /// `proxy_send_timeout`：两次写操作之间的最大空闲，0 = 不限制
    pub send: Duration,
    pub read: Duration,
}

/// `forward` 的可选参数包（避免 6 个位置参数互相混淆）
pub struct ProxyOpts<'a> {
    /// 已按 server/location 合并好的 proxy_set_header
    pub set_headers: &'a [(&'a str, &'a str)],
    pub timeouts: ProxyTimeouts,
    /// `proxy_next_upstream` 的取值列表
    pub next_upstream: &'a [String],
    /// `proxy_next_upstream_tries`：0 = 只受节点数限制
    pub next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout`：0 = 不限制换节点总耗时
    pub next_upstream_timeout: Duration,
    /// `proxy_ssl_*` 解析出的 https/wss 后端 TLS 策略
    pub tls: &'a TlsPolicy,
    /// `proxy_pass http://$变量` 分流（构建期已解析）；None = 目标写死
    pub split: Option<&'a crate::router::RouteSplit>,
    /// `proxy_split_failover`：本意那一路全挂时改投还是原样失败
    pub split_failover: SplitFailover,
    /// 主机位是**非分流**变量（`set`/`map`/`geo`/请求可控变量）时，允许真正去连的落点集合。
    /// None = 目标写死或由 `split_clients` 枚举，这一层不查表。见 `Router::declared_targets`。
    pub var_targets: Option<&'a Arc<std::collections::HashSet<String>>>,
}

/// 分流改投的候选顺序：本意那一路永远排第一，后面按 `proxy_split_failover` 决定留不留退路。
///
/// 候选只在"请求还没交给任何后端节点"这个时刻逐个尝试 —— 这是这套语义的安全边界：
/// 一旦请求发给了某个节点，成败就归 `proxy_next_upstream` 与 `error_page` 管，绝不跨路
/// 重投，否则一个 POST 会被写进两个业务版本。没有分流时只有一个候选，与目标写死的
/// 今天行为逐字一致。
fn split_candidates(
    chosen: &str,
    split: Option<&crate::router::RouteSplit>,
    failover: &SplitFailover,
) -> Vec<String> {
    let Some(sp) = split else {
        return vec![chosen.to_string()];
    };
    let mut out = vec![chosen.to_string()];
    match failover {
        SplitFailover::Off => {}
        SplitFailover::On => out.extend(sp.fallback_order(chosen)),
        SplitFailover::Target(t) => out.push(t.clone()),
    }
    out
}

/// 落点候选是否"自带落点"：IP 字面量，或写了显式端口。
/// 裸名字（`v2`）不算 —— 它要么是具名 upstream 池，要么就该报错，绝不能悄悄交给 DNS 猜：
/// 一条通配 A 记录就能把这一路的流量变成另一路的，而分流的落点必须是配置能逐个枚举出来的。
pub(crate) fn is_direct_host(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok() || s.contains(':')
}

/// `http(s)://<主机位>[/路径]` 拆成（主机位, 路径）。
///
/// "这一路叫什么"就是主机位那一段：转发侧拿它选池，缓存侧拿它写 `$proxy_split`。
/// 两侧共用这一个拆法，同一条分流不可能被理解成两个落点。
pub(crate) fn split_target(target: &str) -> (&str, Option<&str>) {
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    match rest.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    }
}

/// 一个落点候选解析出的结果：可连接的后端地址 + 它所属的池（组内换节点重试用）。
struct BackendPick {
    backend: String,
    guard: Option<UpstreamGuard>,
    keepalive: KeepaliveOpts,
    max_attempts: usize,
    tried: Vec<usize>,
    pool: Option<String>,
}

/// 每个监听进程一个共享连接池客户端；连接池按 (connect 超时, keepalive 参数, TLS 策略指纹) 分组
pub struct ProxyEngine {
    pool: Arc<UpstreamPool>,
    clients: Mutex<HashMap<(u64, u64, u64, u64, u64), HyperClient>>,
    /// 异步 DNS 解析器（配置了 `resolver` 时非空）；转发/Upgrade 前用它把域名换成 IP。
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl ProxyEngine {
    pub fn new(pool: Arc<UpstreamPool>) -> Self {
        ProxyEngine {
            pool,
            clients: Mutex::new(HashMap::new()),
            resolver: None,
        }
    }

    /// 挂上异步 DNS 解析器（配置了 `resolver` 指令时）；未挂则转发走默认 getaddrinfo。
    pub fn with_resolver(mut self, resolver: Arc<crate::dns::DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// 把一个落点候选换成可连接的后端：具名 upstream 池优先（负载均衡 + 被动健康检查），
    /// 其次 host:port / IP 直连。
    ///
    /// `strict` = 这个候选来自分流。严格模式下裸名字查不到池就是错误（`no split branch`），
    /// 不交给 DNS 猜；目标写死的老路径 strict=false，行为与今天完全一致。
    fn pick_backend(&self, cand: &str, remote: &str, strict: bool) -> Result<BackendPick, String> {
        if cand.is_empty() {
            return Err("empty split branch（分桶选中的目标是空串）".to_string());
        }
        if let Some(up) = self.pool.get(cand) {
            // 分流的判据比 acquire 更严：整池都在 fail_timeout 摘除期内就算"这一路没人可服务"，
            // 允许按 proxy_split_failover 改投（普通 proxy_pass 不走这里，行为不变）
            if strict && !up.split_has_live_server() {
                return Err(format!("no live upstreams: {cand}（全部节点在摘除期内）"));
            }
            let keepalive = up.keepalive;
            let max_attempts = up.server_count().max(1).min(8);
            return match up.acquire(remote, &[]) {
                Some(g) => {
                    let tried = vec![g.idx()];
                    let addr = (*g).clone();
                    Ok(BackendPick {
                        backend: addr,
                        guard: Some(g),
                        keepalive,
                        max_attempts,
                        tried,
                        pool: Some(cand.to_string()),
                    })
                }
                // 对齐 nginx：全组没有可选节点时是 502 + "no live upstreams"，
                // 不是把请求硬塞给已经摘除的节点
                None => Err(format!("no live upstreams: {cand}")),
            };
        }
        if strict && !is_direct_host(cand) {
            return Err(format!(
                "no split branch: {cand}（既不是已声明的 upstream 池，也没写显式端口；\
                 分流的目标必须是池名或 host:port，不能靠 DNS 猜）"
            ));
        }
        Ok(BackendPick {
            backend: cand.to_string(),
            guard: None,
            keepalive: KeepaliveOpts::default(),
            max_attempts: 2,
            tried: Vec::new(),
            pool: None,
        })
    }

    /// 若挂了 resolver 且目标主机是域名（非 IP 字面量），把它解析成 "IP:port" 作为连接目标，
    /// 从而让 hyper 跳过阻塞式 getaddrinfo；解析失败即返回错误（对齐 nginx：解析不出来 → 502）。
    /// 未挂 resolver 时原样返回，保持既有行为。
    async fn connect_target(&self, backend: &str) -> Result<String, String> {
        let resolver = match &self.resolver {
            Some(r) => r,
            None => return Ok(backend.to_string()),
        };
        // 拆 host:port（IPv6 字面量带方括号）
        let (host, port) = split_host_port(backend);
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Ok(backend.to_string());
        }
        let addrs = resolver.resolve(host).await?;
        let ip = addrs
            .into_iter()
            .next()
            .ok_or_else(|| format!("DNS 无可用地址: {host}"))?;
        Ok(crate::dns::authority_with_port(ip, port))
    }

    /// 同一 (connect 超时 + keepalive 配置 + TLS 策略指纹) 复用同一个客户端（= 同一套连接池）。
    /// `is_https` 决定是否构建 rustls 客户端配置（http 目标走 0 指纹、共享明文池）。
    fn client(
        &self,
        connect: Duration,
        send: Duration,
        ka: KeepaliveOpts,
        tls: &TlsPolicy,
        is_https: bool,
    ) -> Result<HyperClient, String> {
        // 缓存键：用 u64 哨兵值编码 Option（usize::MAX / u64::MAX 表示"未设，走默认"）。
        // 第四位是 TLS 策略指纹，防止某 location 的 `proxy_ssl_verify off` 复用到别的 location；
        // send 超时随连接器走，也必须参与分池。
        let key = (
            connect.as_millis() as u64,
            send.as_millis() as u64,
            ka.max_idle.unwrap_or(usize::MAX) as u64,
            ka.idle_timeout
                .map(|d| d.as_millis() as u64)
                .unwrap_or(u64::MAX),
            if is_https { tls.fingerprint() } else { 0 },
        );
        let mut map = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = map.get(&key) {
            return Ok(c.clone());
        }
        let tls_cfg = if is_https {
            Some(tls.build_client_config()?)
        } else {
            None
        };
        let connector = ProxyConnector::new(connect, send, tls_cfg, tls);
        let mut builder = Client::builder(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if let Some(n) = ka.max_idle {
            builder.pool_max_idle_per_host(n);
        }
        if let Some(t) = ka.idle_timeout {
            builder.pool_idle_timeout(Some(t));
        }
        let client = builder.build(connector);
        map.insert(key, client.clone());
        Ok(client)
    }

    /// 执行反代。`target` 是 proxy_pass 的值（http:// 后面的部分），
    /// 与 upstream 名匹配时走负载均衡，否则当作 host:port 直连。
    pub async fn forward(
        &self,
        ctx: &mut RequestCtx,
        target: &str,
        loc_prefix: &str,
        opts: &ProxyOpts<'_>,
        mut body: ProxyBody,
    ) -> Result<Response<UpstreamBody>, String> {
        let is_https = target.starts_with("https://");
        // 解析目标：http(s)://host[:port][/path]
        // 带路径时替换 location 前缀（对标 nginx proxy_pass 的 URI 语义）
        let (host, path) = split_target(target);
        let host_part = host.to_string();
        let uri_part = path.map(|p| format!("/{p}"));
        // 主机位是**非分流**变量时：客户端不能决定网关连到哪里。插值出来的落点必须是
        // 配置里列得出来的那批（构建期算好，所有 location 共享一份），否则一个 socket 都不开。
        // 没挂白名单的两类路径 —— 目标写死、目标由 split_clients 枚举 —— 连这次查表都不做。
        if let (None, Some(allow)) = (opts.split, opts.var_targets) {
            if !allow.contains(host_part.as_str()) {
                return Err(format!(
                    "undeclared proxy_pass target: {host_part}（主机位是变量，但 '{host_part}' 不是 \
                     配置里列得出来的落点：已声明的 upstream 池 / 写死的 proxy_pass 主机 / \
                     split_clients 分支 / proxy_split_failover 目标。请求已拒绝，未回源）"
                ));
            }
        }
        // 分流归属：balancer_by_lua 显式选点时完全不介入（选节点归 Lua 管）。
        let routing = opts
            .split
            .filter(|_| ctx.balancer_peer.is_none())
            .map(|sp| (sp, host_part.clone()));
        let chosen: Option<&str> = routing.as_ref().map(|(_, c)| c.as_str());
        // 落点账本（分流才有；登记超限时是 None —— 分流照走，只是不统计）
        let stats = routing.as_ref().and_then(|(sp, _)| sp.stats.clone());
        if let Some(c) = chosen {
            ctx.proxy_split = c.to_string();
            if c.is_empty() {
                if let Some(st) = &stats {
                    st.note(SplitRole::Empty);
                }
            }
        }
        let mut pick: Option<BackendPick> = None;
        let mut pick_err = String::new();
        if let Some((bh, bp)) = ctx.balancer_peer.clone() {
            pick = Some(BackendPick {
                backend: format!("{bh}:{bp}"),
                guard: None,
                keepalive: KeepaliveOpts::default(),
                max_attempts: 1,
                tried: Vec::new(),
                pool: None,
            });
        } else {
            // 逐个候选试到"能给出一个后端地址"为止 —— 跨路改投只发生在这个时刻。
            let candidates = split_candidates(&host_part, opts.split, &opts.split_failover);
            for cand in candidates.iter() {
                let outcome = match self.pick_backend(cand, &ctx.remote_addr, chosen.is_some()) {
                    // 分流分支的域名先探一次解析：探不通 = 这一路现在没人可服务，按策略改投，
                    // 而不是把 502 直接砸回客户端。没配 resolver 时不探（域名交给系统解析，
                    // 失败即 502 且不改投）；https 也不探（SNI/证书校验必须保留 DNS 名）。
                    Ok(p) if chosen.is_some() && !is_https && self.resolver.is_some() => {
                        match self.connect_target(&p.backend).await {
                            Ok(_) => Ok(p),
                            Err(e) => Err(format!("unresolvable '{cand}': {e}")),
                        }
                    }
                    other => other,
                };
                match outcome {
                    Ok(p) => {
                        ctx.proxy_split_served = cand.clone();
                        if let Some(st) = &stats {
                            st.note_served(cand);
                            st.note(if Some(cand.as_str()) == chosen {
                                SplitRole::Routed
                            } else {
                                SplitRole::Bled
                            });
                        }
                        pick = Some(p);
                        break;
                    }
                    Err(e) => {
                        if let Some(st) = &stats {
                            st.note(SplitRole::Down);
                        }
                        if candidates.len() > 1 {
                            log_warn!("分流改投：'{cand}' 无人可服务（{e}），按 proxy_split_failover 试下一路");
                        }
                        // 回给客户端的那条留本意那一路的错误：运维要查的是"分到的那一路为什么没人"
                        if pick_err.is_empty() {
                            pick_err = e;
                        }
                    }
                }
            }
        }
        let Some(p) = pick else {
            return Err(pick_err);
        };
        // upstream 负载均衡：guard 存活期间连接计数 +1，并用于健康检查上报
        let mut guard_holder = p.guard;
        let mut backend = p.backend;
        // 命中 named upstream 时套用其 keepalive 调优；直连目标走默认（hyper 池默认）。
        let keepalive = p.keepalive;
        let mut max_attempts = p.max_attempts;
        let mut tried = p.tried;
        // 组内换节点重试只在本意那一路的池里换，绝不跨到别的业务版本
        let pool_name = p.pool;
        // 健康上报：模块级函数避免闭包借用与 async 冲突
        fn note(guard_holder: &Option<UpstreamGuard>, ok: bool) {
            if let Some(g) = guard_holder {
                if ok {
                    g.note_success();
                } else {
                    g.note_failure();
                }
            }
        }

        let out_path = match uri_part {
            Some(repl) => rewrite_proxy_path(ctx.effective_path(), loc_prefix, &repl),
            None => ctx.effective_path().to_string(),
        };
        let query = if ctx.query.is_empty() {
            String::new()
        } else {
            format!("?{}", ctx.query)
        };

        // 转发请求头：复制后按 proxy_set_header 覆盖（构建一次，重试时 clone）
        let mut headers = HeaderMap::new();
        for (k, v) in &ctx.req_headers {
            if is_hop_by_hop(k)
                || k.eq_ignore_ascii_case("content-length")
                || k.eq_ignore_ascii_case("expect")
            {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_bytes()),
                HeaderValue::try_from(v.as_str()),
            ) {
                headers.append(name, val);
            }
        }
        for (k, v) in opts.set_headers {
            let name = hyper::header::HeaderName::try_from(*k)
                .map_err(|e| format!("非法的 proxy_set_header 名 {k}: {e}"))?;
            let val = interpolate_vars(v, ctx);
            headers.insert(name, HeaderValue::try_from(val).map_err(|e| e.to_string())?);
        }
        if !headers.contains_key(HOST) {
            // nginx 默认把 Host 改写成后端主机名；ONRouter 保留客户端 Host（后端虚拟主机更常用），
            // 需要 nginx 行为时显式写 `proxy_set_header Host <后端名>;`
            if let Some(h) = &ctx.host {
                headers.insert(HOST, HeaderValue::try_from(h.as_str()).unwrap());
            }
        }

        // 请求体来源决定转发方式：
        // - Buffered：整体已在内存，Content-Length 按真实字节数重算（客户端谎报长度时不把畸形透传给后端）
        // - Streaming：把客户端 Incoming 直接管道给后端，不重算长度，由 hyper 依据 body 的 size_hint
        //   决定 Content-Length（原始定长）或分块传输（原始 chunked）
        let streamed = matches!(body, ProxyBody::Streaming(_));
        if let ProxyBody::Buffered(Some(b)) = &body {
            // 空体也补 CL：脚本 discard_body / 构造空体后，后端应看到明确的 Content-Length: 0
            let had_cl = ctx
                .req_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
            if !ctx.is_bodyless_method() && (!b.is_empty() || had_cl) {
                if let Ok(v) = HeaderValue::try_from(b.len().to_string()) {
                    headers.insert(CONTENT_LENGTH, v);
                }
            }
        }
        // 流式请求体一旦被后端消费就无法回放，禁止换节点重试（对齐 nginx buffering off）
        if streamed {
            max_attempts = 1;
        }

        // proxy_next_upstream：token 语义对齐 nginx（error/timeout/invalid_header/http_XXX/non_idempotent/off）
        let next = opts.next_upstream;
        let next_off = next.iter().any(|v| v == "off");
        let on_error = !next_off && next.iter().any(|v| v == "error");
        let on_timeout = !next_off && next.iter().any(|v| v == "timeout");
        let on_invalid_header = !next_off && next.iter().any(|v| v == "invalid_header");
        let allow_non_idempotent = !next_off && next.iter().any(|v| v == "non_idempotent");
        let retry_statuses: Vec<u16> = if next_off {
            Vec::new()
        } else {
            next.iter()
                .filter_map(|v| v.strip_prefix("http_").and_then(|s| s.parse::<u16>().ok()))
                .collect()
        };
        let idempotent = is_idempotent(&ctx.method);
        let method_retryable = idempotent || allow_non_idempotent;
        if opts.next_upstream_tries > 0 {
            max_attempts = max_attempts.min(opts.next_upstream_tries as usize);
        }
        // 换节点总时间预算（nginx `proxy_next_upstream_timeout`，0 = 不限制）
        let retry_deadline = (!opts.next_upstream_timeout.is_zero())
            .then(|| std::time::Instant::now() + opts.next_upstream_timeout);

        // balancer_by_lua set_timeouts 覆盖 location 的连接/写/读超时
        let eff_connect = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.0))
            .unwrap_or(opts.timeouts.connect);
        let eff_send = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.1))
            .unwrap_or(opts.timeouts.send);
        let eff_read = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.2))
            .unwrap_or(opts.timeouts.read);
        let mut last_err = String::new();
        for attempt in 0..max_attempts {
            if attempt > 0 {
                if retry_deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                    break;
                }
                if let Some(up) = pool_name.as_ref().and_then(|n| self.pool.get(n)) {
                    match up.acquire(&ctx.remote_addr, &tried) {
                        Some(g) => {
                            tried.push(g.idx());
                            backend = (*g).clone();
                            guard_holder = Some(g);
                        }
                        // 可选节点已经都试过一轮，不再继续换
                        None => break,
                    }
                }
                log_warn!(
                    "upstream {} 换节点重试: {backend}",
                    pool_name.as_deref().unwrap_or(&host_part)
                );
            }
            // https 后端保留主机名（SNI/证书校验需要 DNS 名），不做 resolver→IP 改写；
            // http 后端若配了 resolver 则把域名换成 IP 以跳过阻塞式 getaddrinfo。
            let connect_host = if is_https {
                backend.clone()
            } else {
                self.connect_target(&backend).await?
            };
            let scheme = if is_https { "https" } else { "http" };
            let uri = format!("{scheme}://{connect_host}{}{query}", encode_path(&out_path),);
            // 每次尝试重建请求体：缓冲体可回放（clone Bytes），流式体只能取用一次
            let req_body: ProxyReqBody = match &mut body {
                ProxyBody::Buffered(b) => full_boxed(b.as_ref().cloned().unwrap_or_default()),
                ProxyBody::Streaming(inc) => inc.take().expect("streaming body 仅用于单次尝试"),
            };
            let (sent_tx, mut sent_rx) = tokio::sync::watch::channel(false);
            let mut req_body = BodySent {
                inner: req_body,
                done: Some(sent_tx),
            };
            if req_body.is_end_stream() {
                req_body.signal();
            }
            let req_body: ProxyReqBody = req_body.boxed();
            let mut req = Request::builder()
                .method(ctx.method.as_str())
                .uri(&uri)
                .version(hyper::Version::HTTP_11)
                .body(req_body)
                .map_err(|e| e.to_string())?;
            *req.headers_mut() = headers.clone();

            let client = self.client(eff_connect, eff_send, keepalive, opts.tls, is_https)?;
            // 记录本次尝试选定的后端（供 $upstream_addr，重试时覆盖为最后尝试的节点）
            ctx.upstream_addr = backend.clone();
            // 连接+上传由 connect/send 超时管；read 超时从请求体发完起算，仅等响应头，
            // 响应头之后每帧再各自计时（UpstreamBody）。
            let t0 = std::time::Instant::now();
            let outcome = tokio::select! {
                r = client.request(req) => Ok(r),
                _ = read_deadline(&mut sent_rx, eff_read) => Err(()),
            };
            match outcome {
                Ok(Ok(r)) => {
                    let status = r.status().as_u16();
                    // http_XXX：状态码本身就是换节点条件；丢弃未读 body 即关闭该后端连接。
                    // 预算耗尽/次数用尽时把最后一个上游响应原样返回（nginx 不会改写成 502）。
                    let within_budget =
                        retry_deadline.map_or(true, |d| std::time::Instant::now() < d);
                    let matched_fail_status =
                        !retry_statuses.is_empty() && retry_statuses.contains(&status);
                    if matched_fail_status
                        && method_retryable
                        && attempt + 1 < max_attempts
                        && within_budget
                    {
                        // 真的换节点了，这一次尝试才算"失败尝试"：nginx 只在 upstream_next 里
                        // 打 NGX_PEER_FAILED，而 403/404 走的是 NGX_PEER_NEXT，不计。
                        // 缺了这一步，"只会回 503 的后端"永远摘不掉：max_fails 数不到它。
                        if !matches!(status, 403 | 404) {
                            note(&guard_holder, false);
                        }
                        guard_holder = None;
                        ctx.upstream_status = status;
                        last_err =
                            format!("后端返回 {status}，按 proxy_next_upstream 换节点: {backend}");
                        log_warn!("{last_err}");
                        drop(r);
                        continue;
                    }
                    // 响应头已到：guard 随响应体继续存活，读完/失败后才结算
                    let (parts, incoming) = r.into_parts();
                    ctx.upstream_status = parts.status.as_u16();
                    let header_dt = t0.elapsed().as_secs_f64();
                    ctx.upstream_header_time = header_dt;
                    // 自适应选点的唯一样本来源：成功拿到响应头的请求才入账（口径同 nginx least_time header）
                    if let Some(g) = &guard_holder {
                        g.note_latency(header_dt);
                    }
                    // 到这里就是"命中了 http_XXX 但这次不换节点"（最后一台/预算用尽/非幂等）。
                    // nginx 此时把上游响应原样回给客户端，并且**不**记失败尝试——失败只随真正的
                    // upstream_next 发生。这里保持一致，不去"顺手摘掉"最后一台。
                    return Ok(Response::from_parts(
                        parts,
                        UpstreamBody::new(incoming, eff_read, guard_holder.take(), backend.clone()),
                    ));
                }
                Ok(Err(e)) => {
                    note(&guard_holder, false);
                    guard_holder = None;
                    ctx.upstream_status = 0;
                    let root = error_root(&e);
                    last_err = format!("代理请求失败 {backend}: {e} | 根因: {root}");
                    // 连接阶段失败时请求还没发出去，非幂等方法也可安全换节点；
                    // 已发出的请求则要求幂等方法或显式 non_idempotent。
                    let not_sent = looks_like_connect_error(&root);
                    let header_bad = on_invalid_header && looks_like_invalid_header(&root);
                    let retry = (on_error && (method_retryable || not_sent))
                        || (header_bad && method_retryable);
                    if retry && attempt + 1 < max_attempts {
                        continue;
                    }
                    return Err(last_err);
                }
                Err(_) => {
                    note(&guard_holder, false);
                    guard_holder = None;
                    ctx.upstream_status = 0;
                    last_err = format!("proxy_read_timeout ({:?}) 超时: {backend}", eff_read);
                    if method_retryable && on_timeout && attempt + 1 < max_attempts {
                        continue;
                    }
                    return Err(last_err);
                }
            }
        }
        Err(last_err)
    }
}

/// `proxy_pass` 带 URI 部分时的转发路径：把匹配到的 location 前缀整段换成 URI 部分，
/// 余下的原样接上。nginx 这里是**纯字符串替换**——既不补斜杠也不删斜杠，余下部分可以为空。
/// 单独成函数是因为"请求路径正好等于前缀"这一条曾经被补成 `/api/hot/`：后端把同一个资源
/// 看成两条路由（框架的精确路由表就是这样），缓存键也跟着分叉。
fn rewrite_proxy_path(effective: &str, loc_prefix: &str, repl: &str) -> String {
    match effective.strip_prefix(loc_prefix) {
        Some(rel) => format!("{repl}{rel}"),
        None => effective.to_string(),
    }
}

/// 路径按段重新做百分号编码后转发：
/// location 匹配用的是解码后的路径，而 URI 语法不允许空格/控制字符/裸 UTF-8 字节，
/// 直接把解码结果拼进转发 URI 会让后端收到非法请求行（含中文文件名、带空格的路径必现）。
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(crate::lua_engine::escape_uri)
        .collect::<Vec<_>>()
        .join("/")
}

/// Upgrade（WebSocket 隧道）的请求行必须转发客户端**原始的、未解码**的 request target。
/// 用解码后的路径拼接会让 `%23` 变成裸 `#`（后端把它当片段截断 URI）、`%2f` 变成 `/`、
/// `%2541` 之类二次编码也被顺手解掉一层——前后端对"这是哪个资源"的认知就此分叉，
/// 而 location 匹配、allow/deny、auth_basic、limit_req 全部是按前端认知做的，
/// 于是这些防护可以被一条构造的编码 URI 绕开。nginx 在这条路径上原样透传，我们也照做。
/// 返回 `None` 表示不能原样透传（rewrite 改写出的解码态路径、`*` 或绝对形式），调用方回退到编码路径。
fn raw_upgrade_target(ctx: &RequestCtx) -> Option<String> {
    if ctx.rewritten_path.is_some() {
        return None;
    }
    let uri = ctx.uri.as_str();
    if !uri.starts_with('/') || uri.contains(['\r', '\n', '\0']) {
        return None;
    }
    Some(uri.to_string())
}

/// nginx：非幂等请求（有副作用的）默认不参与 next_upstream 重试
fn is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "HEAD"
            | "OPTIONS"
            | "TRACE"
            | "PROPFIND"
            | "COPY"
            | "MOVE"
            | "MKCOL"
            | "LOCK"
            | "UNLOCK"
            | "SEARCH"
    )
}

/// 把 "host:port" / "host" / "[::1]:port" / "::1" 拆成 (host, port)；缺省端口 80。
fn split_host_port(s: &str) -> (&str, u16) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ip, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(80);
            return (ip, port);
        }
        return (s, 80);
    }
    // 恰有一个冒号才当端口；多个冒号说明是裸 IPv6 字面量（无端口）
    match s.rsplit_once(':') {
        Some((h, p)) => {
            if h.contains(':') {
                (s, 80)
            } else {
                (h, p.parse::<u16>().unwrap_or(80))
            }
        }
        None => (s, 80),
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

/// 展开错误源链，便于诊断
fn error_root(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    loop {
        match cur.source() {
            Some(s) => cur = s,
            None => return cur.to_string(),
        }
    }
}

/// 连接阶段错误：此时请求一个字节都还没发给后端，换节点不会造成副作用。
fn looks_like_connect_error(root: &str) -> bool {
    let s = root.to_ascii_lowercase();
    s.contains("connect") || s.contains("dns") || s.contains("refused")
}

/// 上游超时（连不上之外的"等了太久"）。
fn looks_like_upstream_timeout(err: &str) -> bool {
    let s = err.to_ascii_lowercase();
    s.contains("超时") || s.contains("timed out") || s.contains("timeout")
}

/// 回源失败该给客户端哪个状态码。
///
/// nginx 把"后端慢"和"后端坏"分成两个码：等满 `proxy_*_timeout` 是 504，连不上/响应非法
/// 才是 502。这个区分不是好看：告警规则、`error_page 504`、以及"该扩容还是该查进程"的
/// 判断都建立在它上面；并进 502 会让一台只是慢的后端看起来像一台挂掉的后端。
/// hyper 把错误折叠成字符串，所以按本文件在回源路径上写出的根因文本判定。
pub fn upstream_error_status(err: &str) -> u16 {
    if looks_like_upstream_timeout(err) {
        504
    } else {
        502
    }
}

/// hyper 把所有协议错误折叠成字符串，只能按根因文本近似识别"响应头非法"
/// （invalid HTTP status-code / invalid HTTP header / invalid content-length 等）。
fn looks_like_invalid_header(root: &str) -> bool {
    let s = root.to_ascii_lowercase();
    s.contains("invalid") || s.contains("parse")
}

/// 配置值里的内置变量插值（proxy_set_header 与 rust handler 共用）
pub fn interpolate_vars(template: &str, ctx: &RequestCtx) -> String {
    interpolate_vars_with(template, ctx, |_| None)
}

/// 同 `interpolate_vars`，但调用方可以注入只在本处成立的变量（cache key 的 `$proxy_host`）。
/// 词法只扫描**原模板**，替换结果不参与分词：否则 `$scheme$proxy_host` 先换成
/// `$scheme127.0.0.1:80` 后，贪婪词法会把 `$scheme` 读成 `$scheme127`，键里留下一截
/// 永远展开不了的字面量。
pub(crate) fn interpolate_vars_with(
    template: &str,
    ctx: &RequestCtx,
    extra: impl Fn(&str) -> Option<String>,
) -> String {
    if !template.contains('$') {
        return template.to_string();
    }
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            let ch = template[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let rest = &template[i + 1..];
        // ${name} 与 $name 两种写法；$1 是正则捕获组，不当作变量
        let (name, consumed) = if let Some(after) = rest.strip_prefix('{') {
            match after.find('}') {
                Some(end)
                    if end > 0
                        && after[..end]
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
                {
                    (&after[..end], end + 3)
                }
                _ => {
                    out.push('$');
                    i += 1;
                    continue;
                }
            }
        } else {
            let len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if len == 0 {
                out.push('$');
                i += 1;
                continue;
            }
            (&rest[..len], 1 + len)
        };
        if name.as_bytes()[0].is_ascii_digit() {
            out.push_str(&template[i..i + consumed]);
            i += consumed;
            continue;
        }
        // 单遍替换：替换结果里的 `$` 不会被再次展开（用户数据里的 $arg_x 不该二次求值）。
        let value = extra(name).or_else(|| crate::engine::resolve_var(ctx, name, 0));
        match value {
            Some(v) => out.push_str(&v),
            // nginx 认识的变量名此刻没有值 → 空串：`$arg_x`/`$cookie_x`/`$http_x` 这类前缀
            // 派生名、`$sent_http_x`/`$upstream_http_x`，以及 `builtin_var` 匹配不到的固定名
            // （例如明文请求下的 `$ssl_server_name`）。这决定了
            // `proxy_cache_bypass $arg_nocache $http_pragma;` 的判真：没带的头必须是"空"，
            // 否则表达式永远为真，缓存形同关闭。
            None if crate::engine::is_derived_var_name(name)
                || crate::engine::is_static_var_name(name) => {}
            // 名字根本不像 nginx 变量（拼错、或 `set` 之外的自定义名）：保留字面量。
            // nginx 在解析期就 emerg "unknown \"x\" variable" 拒绝启动，我们没有全量变量
            // 白名单，静默变空串会把配置错误藏起来；留字面量在响应里一眼能看见。
            None => out.push_str(&template[i..i + consumed]),
        }
        i += consumed;
    }
    out
}

/// 检测是否为 WebSocket/Upgrade 请求（对标 nginx 的 map $http_upgrade $connection_upgrade）
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    // Connection 头必须包含 "upgrade"
    let has_upgrade_conn = headers.get_all(CONNECTION).iter().any(|v| {
        v.to_str()
            .ok()
            .map(|s| s.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
    });

    // Upgrade 头存在（通常是 "websocket"，但也可以是其他协议）
    let has_upgrade_header = headers.contains_key(UPGRADE);

    has_upgrade_conn && has_upgrade_header
}

/// 升级隧道的交付物：已与后端完成 101 握手的流（明文 TCP 或 wss/https 后端上的 TLS 流）
pub struct UpgradeTunnel {
    pub stream: ProxyStream,
    /// 后端 101 响应的头（原样转发给客户端，含 Sec-WebSocket-Accept）
    pub headers: Vec<(String, String)>,
    /// 后端在 101 头之后立即发出的字节（WS 帧可能已到达），交给隧道先行读出
    pub prefix: Vec<u8>,
    /// upstream 并发额度：隧道的整个生命周期内都必须持有，
    /// 否则 `max_conns` 统计不到 WebSocket 这类长连接（由 server 层随隧道任务释放）。
    pub guard: Option<UpstreamGuard>,
}

impl ProxyEngine {
    /// WebSocket/Upgrade 隧道代理（对标 nginx 的 proxy + $connection_upgrade）：
    /// 1. 向后端直发带 Upgrade 头的 HTTP/1.1 请求（raw，不经 hyper 客户端池）
    /// 2. 校验后端返回 101，收集其响应头与抢跑字节
    /// 3. 由 server 层把客户端流与返回的 backend 流做双向管道
    pub async fn upgrade(
        &self,
        ctx: &mut RequestCtx,
        target: &str,
        opts: &ProxyOpts<'_>,
    ) -> Result<UpgradeTunnel, String> {
        // ws://、http:// 走明文；wss://、https:// 走 rustls-over-TCP（复用代理连接器）
        let is_tls = target.starts_with("https://") || target.starts_with("wss://");
        let rest = target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");
        let (host_part, _uri_part) = match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), Some(format!("/{p}"))),
            None => (rest.to_string(), None),
        };
        // 与 forward() 同一道闸门：Upgrade 也是"网关朝一个落点开 socket"，
        // 客户端能控制主机位变量时照样只允许配置里列得出来的落点。
        if let (None, Some(allow)) = (opts.split, opts.var_targets) {
            if !allow.contains(host_part.as_str()) {
                return Err(format!(
                    "undeclared proxy_pass target: {host_part}（主机位是变量，但 '{host_part}' 不是 \
                     配置里列得出来的落点：已声明的 upstream 池 / 写死的 proxy_pass 主机 / \
                     split_clients 分支 / proxy_split_failover 目标。请求已拒绝，未回源）"
                ));
            }
        }
        // balancer_by_lua 选点优先；否则逐个分流候选试到"能给出一个后端地址"为止，
        // 最后按 host:port 直连。跨路改投同样只发生在"还没把 Upgrade 发给任何节点"的时刻。
        let mut guard_holder: Option<UpstreamGuard> = None;
        let routing = opts
            .split
            .filter(|_| ctx.balancer_peer.is_none())
            .map(|sp| (sp, host_part.clone()));
        let chosen: Option<&str> = routing.as_ref().map(|(_, c)| c.as_str());
        let stats = routing.as_ref().and_then(|(sp, _)| sp.stats.clone());
        if let Some(c) = chosen {
            ctx.proxy_split = c.to_string();
            if c.is_empty() {
                if let Some(st) = &stats {
                    st.note(SplitRole::Empty);
                }
            }
        }
        let backend_addr = match ctx.balancer_peer.clone() {
            Some((bh, bp)) => format!("{bh}:{bp}"),
            None => {
                let candidates = split_candidates(&host_part, opts.split, &opts.split_failover);
                let mut hit: Option<BackendPick> = None;
                let mut err = String::new();
                for cand in candidates.iter() {
                    let p = match self.pick_backend(cand, &ctx.remote_addr, chosen.is_some()) {
                        Ok(p) => p,
                        Err(e) => {
                            if let Some(st) = &stats {
                                st.note(SplitRole::Down);
                            }
                            if candidates.len() > 1 {
                                log_warn!("WebSocket 分流改投：'{cand}' 无人可服务（{e}），按 proxy_split_failover 试下一路");
                            }
                            if err.is_empty() {
                                err = e;
                            }
                            continue;
                        }
                    };
                    // 与 forward 同口径：分流分支的域名解析不出来 = 这一路没人可服务，按策略改投。
                    if chosen.is_some() && !is_tls && self.resolver.is_some() {
                        if let Err(e) = self.connect_target(&p.backend).await {
                            let e = format!("unresolvable '{cand}': {e}");
                            if let Some(st) = &stats {
                                st.note(SplitRole::Down);
                            }
                            if candidates.len() > 1 {
                                log_warn!("WebSocket 分流改投：{e}");
                            }
                            if err.is_empty() {
                                err = e;
                            }
                            continue;
                        }
                    }
                    ctx.proxy_split_served = cand.clone();
                    if let Some(st) = &stats {
                        st.note_served(cand);
                        st.note(if Some(cand.as_str()) == chosen {
                            SplitRole::Routed
                        } else {
                            SplitRole::Bled
                        });
                    }
                    hit = Some(p);
                    break;
                }
                let Some(p) = hit else {
                    return Err(err);
                };
                guard_holder = p.guard;
                p.backend
            }
        };
        // 访问日志的 $upstream_addr：即使在后续建连/握手阶段失败也要留下尝试目标
        ctx.upstream_addr = backend_addr.clone();
        let (host, port) = match backend_addr.split_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| format!("非法端口: {p}"))?,
            ),
            None => (backend_addr.clone(), if is_tls { 443 } else { 80 }),
        };
        // 明文：有 resolver 且是域名时先异步解析成 IP 再连（HOST 头仍用原始名）；
        // TLS：保留主机名（rustls 需要 DNS 名作 SNI/证书校验），不做 resolver→IP 改写。
        let connect_host = if is_tls {
            host.clone()
        } else {
            match &self.resolver {
                Some(r) if host.parse::<std::net::IpAddr>().is_err() => {
                    let addrs = r.resolve(&host).await?;
                    let ip = addrs
                        .into_iter()
                        .next()
                        .ok_or_else(|| format!("DNS 无可用地址: {host}"))?;
                    match ip {
                        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                        std::net::IpAddr::V4(v4) => v4.to_string(),
                    }
                }
                _ => host.clone(),
            }
        };

        let eff_connect = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.0))
            .unwrap_or(opts.timeouts.connect);
        let eff_send = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.1))
            .unwrap_or(opts.timeouts.send);
        let eff_read = ctx
            .balancer_timeouts
            .map(|t| std::time::Duration::from_millis(t.2))
            .unwrap_or(opts.timeouts.read);
        let tls_cfg = if is_tls {
            Some(opts.tls.build_client_config()?)
        } else {
            None
        };
        let mut connector = ProxyConnector::new(eff_connect, eff_send, tls_cfg, opts.tls);
        let scheme = if is_tls { "https" } else { "http" };
        let dst: Uri = format!("{scheme}://{connect_host}:{port}")
            .parse()
            .map_err(|e| format!("非法后端地址 {connect_host}:{port}: {e}"))?;
        // 建连 + 发送升级请求 + 等到 101 响应头，计入 $upstream_header_time
        let t0 = std::time::Instant::now();
        let mut backend_stream = match connector.call(dst).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(g) = &guard_holder {
                    g.note_failure();
                }
                return Err(format!("连接后端失败 {backend_addr}: {e}"));
            }
        };

        // 构建升级请求头
        let mut req_headers = HeaderMap::new();
        for (k, v) in &ctx.req_headers {
            if is_hop_by_hop(k)
                || k.eq_ignore_ascii_case("content-length")
                || k.eq_ignore_ascii_case("expect")
            {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_bytes()),
                HeaderValue::try_from(v.as_str()),
            ) {
                req_headers.append(name, val);
            }
        }
        req_headers.insert(
            HOST,
            HeaderValue::try_from(ctx.host.as_deref().unwrap_or(&host))
                .map_err(|e| e.to_string())?,
        );
        req_headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Some(upgrade) = ctx.header("upgrade") {
            req_headers.insert(
                UPGRADE,
                HeaderValue::try_from(upgrade).map_err(|e| e.to_string())?,
            );
        }
        for (k, v) in opts.set_headers {
            let name = hyper::header::HeaderName::try_from(*k)
                .map_err(|e| format!("非法的 proxy_set_header 名 {k}: {e}"))?;
            let val = interpolate_vars(v, ctx);
            req_headers.insert(name, HeaderValue::try_from(val).map_err(|e| e.to_string())?);
        }

        let request_line = match raw_upgrade_target(ctx) {
            // 原始 URI 已含 query，不再拼接
            Some(target) => format!("{} {} HTTP/1.1\r\n", ctx.method, target),
            None => format!(
                "{} {}{}{} HTTP/1.1\r\n",
                ctx.method,
                encode_path(ctx.effective_path()),
                if ctx.query.is_empty() { "" } else { "?" },
                ctx.query
            ),
        };
        let mut request_buf = request_line.into_bytes();
        for (name, value) in &req_headers {
            request_buf.extend_from_slice(
                format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes(),
            );
        }
        request_buf.extend_from_slice(b"\r\n");

        if let Err(e) = backend_stream.write_all(&request_buf).await {
            if let Some(g) = &guard_holder {
                g.note_failure();
            }
            return Err(format!("发送升级请求失败: {e}"));
        }

        // 读后端响应头：循环直到 \r\n\r\n（本地包可能拆分），上限 64KB
        let mut resp_buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = match tokio::time::timeout(eff_read, backend_stream.read(&mut chunk)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    if let Some(g) = &guard_holder {
                        g.note_failure();
                    }
                    return Err(format!("读取后端响应失败: {e}"));
                }
                Err(_) => {
                    if let Some(g) = &guard_holder {
                        g.note_failure();
                    }
                    return Err(format!("等待后端 101 超时: {backend_addr}"));
                }
            };
            if n == 0 {
                if let Some(g) = &guard_holder {
                    g.note_failure();
                }
                return Err("后端在建连前关闭（非 101）".to_string());
            }
            resp_buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if resp_buf.len() > 64 * 1024 {
                if let Some(g) = &guard_holder {
                    g.note_failure();
                }
                return Err("后端 101 响应头过大".to_string());
            }
        };

        let head_str = String::from_utf8_lossy(&resp_buf[..head_end]).to_string();
        let mut lines = head_str.split("\r\n");
        let first_line = lines.next().unwrap_or("");
        let status_code = if first_line.len() >= 12
            && (first_line.starts_with("HTTP/1.1 ") || first_line.starts_with("HTTP/1.0 "))
        {
            first_line[9..12].parse::<u16>().unwrap_or(0)
        } else {
            0
        };
        if status_code != 101 {
            if let Some(g) = &guard_holder {
                g.note_failure();
            }
            return Err(format!("后端未返回 101，而是 {status_code}"));
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let prefix = resp_buf[head_end..].to_vec();

        // 101 已建立：本次尝试算成功，但并发额度随隧道继续持有
        ctx.upstream_status = 101;
        ctx.upstream_header_time = t0.elapsed().as_secs_f64();
        if let Some(g) = &guard_holder {
            g.note_success();
        }
        log_info!(
            "WebSocket/Upgrade 隧道已建联: {} -> {}",
            ctx.remote_addr,
            backend_addr
        );
        Ok(UpgradeTunnel {
            stream: backend_stream,
            headers,
            prefix,
            guard: guard_holder.take(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::RequestCtx;

    /// nginx 的 proxy_pass URI 语义是纯字符串替换。逐条钉住，特别是"请求正好等于前缀"
    /// 与"前缀不带斜杠而剩余带斜杠"这两种最容易悄悄改变后端所见路径的写法。
    #[test]
    fn proxy_pass_uri_replacement_is_pure_string_replacement() {
        assert_eq!(
            rewrite_proxy_path("/api/hot", "/api/hot", "/api/hot"),
            "/api/hot"
        );
        assert_eq!(
            rewrite_proxy_path("/api/hot", "/api/hot", "/v1/hot"),
            "/v1/hot"
        );
        assert_eq!(
            rewrite_proxy_path("/api/hot/detail", "/api/hot", "/v1/hot"),
            "/v1/hot/detail"
        );
        // 经典写法：location /api/ + proxy_pass http://app/
        assert_eq!(rewrite_proxy_path("/api/hello", "/api/", "/"), "/hello");
        assert_eq!(rewrite_proxy_path("/api/", "/api/", "/"), "/");
        // 前缀不带尾斜杠、proxy_pass 的 URI 带尾斜杠、剩余部分又带斜杠：nginx 就是
        // "directive 的 URI + 去掉 location 前缀后的剩余"（ngx_http_proxy_module.c 里
        // loc_len = ngx_min(plcf->location.len, r->uri.len)），**不去重斜杠**，
        // 所以这条会得到 `/v1//x` —— 这是 nginx 的真实输出，也是文档劝人以斜杠结尾的原因。
        assert_eq!(rewrite_proxy_path("/api/x", "/api", "/v1/"), "/v1//x");
        assert_eq!(rewrite_proxy_path("/api/x", "/api/", "/v1/"), "/v1/x");
        // 前缀匹配到 /apix 这种"半个词"的剩余部分：nginx 直接拼，不补斜杠（这是它的既有
        // 语义，也是"proxy_pass 的 location 请以斜杠结尾"那条告诫的来源）
        assert_eq!(rewrite_proxy_path("/apix", "/api", "/v1"), "/v1x");
        // 精确匹配的 location
        assert_eq!(rewrite_proxy_path("/x", "/x", "/y"), "/y");
        // rewrite 改写过路径、与前缀对不上时：原样转发，不猜
        assert_eq!(rewrite_proxy_path("/other", "/api", "/v1"), "/other");
    }

    /// nginx 把"后端慢"和"后端坏"分成 504 与 502。告警规则、`error_page 504` 与
    /// "该扩容还是该查进程"都建立在这个区分上，所以两类根因都要钉住。
    #[test]
    fn upstream_timeout_maps_to_504_and_broken_upstream_to_502() {
        for e in [
            "proxy_read_timeout (1s) 超时: 127.0.0.1:18631",
            "等待后端 101 超时: 127.0.0.1:18631",
            "代理请求失败 127.0.0.1:1 | 根因: operation timed out",
        ] {
            assert_eq!(upstream_error_status(e), 504, "超时应当是 504：{e}");
        }
        for e in [
            "连接后端失败 127.0.0.1:1: 由于目标计算机积极拒绝，无法连接。",
            "no live upstreams: app（全部节点在摘除期内）",
            "unresolvable 'svc.invalid': dns",
            "后端未返回 101，而是 400",
        ] {
            assert_eq!(upstream_error_status(e), 502, "连不上/坏响应仍是 502：{e}");
        }
        // 拒绝连接里出现的 "Connection refused" 不该被误判成超时
        assert_eq!(
            upstream_error_status(
                "代理请求失败 127.0.0.1:1 | 根因: Connection refused (os error 10061)"
            ),
            502
        );
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            method: "GET".to_string(),
            path: "/api/x".to_string(),
            query: "a=1".to_string(),
            uri: "/api/x?a=1".to_string(),
            host: Some("www.example.com".to_string()),
            remote_addr: "10.0.0.9".to_string(),
            remote_port: 54321,
            server_port: 8080,
            req_headers: vec![
                ("user-agent".to_string(), "curl/8".to_string()),
                ("x-forwarded-for".to_string(), "1.1.1.1".to_string()),
            ],
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
            scheme: "https".to_string(),
            internal_request: false,
            filter_chunk: None,
            filter_eof: false,
            listener: None,
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
            start_time: 0.0,
            http_version: 1.1,
            body_builder: None,
            eof_sent: false,
            cache_status: String::new(),
            still_online: String::new(),
            front_proxy: String::new(),
            front_proxy_country: String::new(),
            front_proxy_host: String::new(),
            front_proxy_verified: false,
            realip_remote_addr: String::new(),
            set_vars: Vec::new(),
            rewrite_return: None,
        }
    }

    #[test]
    fn interpolates_core_variables() {
        let c = ctx();
        assert_eq!(
            interpolate_vars("$scheme://$host:$server_port$uri?$args", &c),
            "https://www.example.com:8080/api/x?a=1"
        );
        assert_eq!(
            interpolate_vars("$remote_addr:$remote_port", &c),
            "10.0.0.9:54321"
        );
        assert_eq!(
            interpolate_vars("$proxy_add_x_forwarded_for", &c),
            "1.1.1.1, 10.0.0.9"
        );
    }

    #[test]
    fn expands_http_header_vars() {
        let c = ctx();
        assert_eq!(
            interpolate_vars("[$http_user_agent|$http_missing]", &c),
            "[curl/8|]"
        );
        // 变量名里下划线代表连字符
        assert_eq!(interpolate_vars("$http_x_forwarded_for", &c), "1.1.1.1");
    }

    #[test]
    fn expands_arg_cookie_braced_and_avoids_double_expansion() {
        let mut c = ctx();
        c.query = "a=1&nocache=%31".to_string();
        c.req_headers
            .push(("cookie".to_string(), "sid=abc".to_string()));
        assert_eq!(interpolate_vars("$arg_nocache|$arg_missing", &c), "1|");
        assert_eq!(interpolate_vars("$cookie_sid|$cookie_nope", &c), "abc|");
        assert_eq!(
            interpolate_vars("${host}:${server_port}", &c),
            "www.example.com:8080"
        );
        // 替换结果里的 $ 不再二次求值（否则用户数据可影响 cache key / 头值）
        c.uri = "/x?q=$arg_a".to_string();
        assert_eq!(interpolate_vars("$request_uri", &c), "/x?q=$arg_a");
    }

    #[test]
    fn known_but_valueless_var_expands_empty_unknown_stays_literal() {
        let c = ctx();
        // nginx 认识的名字但这次没值 → 空串（$upstream_cache_status 在非缓存请求上就是空）
        assert_eq!(
            interpolate_vars("[$upstream_cache_status|$arg_no]", &c),
            "[|]"
        );
        // 根本不像 nginx 变量的名字（拼错、或 set 之外的自定义名）保留字面量，
        // 让配置错误在响应头里看得见，而不是静默变成空值
        assert_eq!(interpolate_vars("$hstop", &c), "$hstop");
        assert_eq!(
            interpolate_vars("$upstream_cache_statusx", &c),
            "$upstream_cache_statusx"
        );
        // $host 去端口、$http_host 原样：两条路径共用 builtin_var 这一个事实源
        let mut c2 = ctx();
        c2.host = Some("example.test:8080".into());
        c2.req_headers
            .push(("host".into(), "example.test:8080".into()));
        assert_eq!(
            interpolate_vars("$host|$http_host", &c2),
            "example.test|example.test:8080"
        );
    }

    #[test]
    fn injected_var_does_not_break_lexical_boundaries() {
        let c = ctx();
        let key = |tmpl: &str| {
            interpolate_vars_with(tmpl, &c, |n| {
                (n == "proxy_host").then(|| "127.0.0.1:18271".to_string())
            })
        };
        // 注入的值以数字开头：词法只扫原模板，否则 `$scheme` 会被贪婪读成 `$scheme127`
        // 这个不存在的名字，键里留下一截永远展开不了的字面量
        assert_eq!(
            key("$scheme$proxy_host$request_uri"),
            "https127.0.0.1:18271/api/x?a=1"
        );
        assert_eq!(key("${proxy_host}$uri"), "127.0.0.1:18271/api/x");
        // 注入只覆盖同名变量，其余仍走常规解析
        assert_eq!(
            key("$scheme $host $proxy_host"),
            "https www.example.com 127.0.0.1:18271"
        );
    }

    #[test]
    fn forwarded_path_is_reencoded_per_segment() {
        // 解码后的中文/空格必须重新编码，否则后端拿到非法请求行
        assert_eq!(
            encode_path("/a b/中文.html"),
            "/a%20b/%E4%B8%AD%E6%96%87.html"
        );
        // 原本就是转义形式的 '%' 不能二次误解
        assert_eq!(encode_path("/100%25/"), "/100%2525/");
        assert_eq!(encode_path("/"), "/");
    }

    #[test]
    fn upgrade_target_forwards_raw_undecoded_uri() {
        let mut c = ctx();
        // 解码后的 path 会把 %23 变成裸 '#'（后端按片段截断）、%3f 变成第二个 '?'：
        // 网关与后端认到的资源不同，前置的 location/allow-deny/限流就能被绕过。
        c.uri = "/ws%23frag?x=1%3fy=2".to_string();
        c.path = "/ws#frag".to_string();
        c.query = "x=1%3fy=2".to_string();
        assert_eq!(
            raw_upgrade_target(&c).as_deref(),
            Some("/ws%23frag?x=1%3fy=2")
        );
        // rewrite 改写出来的是解码态路径，只能重新编码；绝对形式/`*` 同理
        c.rewritten_path = Some("/rewritten".to_string());
        assert_eq!(raw_upgrade_target(&c), None);
        c.rewritten_path = None;
        c.uri = "*".to_string();
        assert_eq!(raw_upgrade_target(&c), None);
        c.uri = "/a\r\nX: 1".to_string();
        assert_eq!(raw_upgrade_target(&c), None);
    }

    #[test]
    fn only_idempotent_methods_retry() {
        assert!(is_idempotent("GET"));
        assert!(is_idempotent("HEAD"));
        assert!(!is_idempotent("POST"));
        assert!(!is_idempotent("PATCH"));
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        for h in ["connection", "Transfer-Encoding", "Upgrade", "keep-alive"] {
            assert!(is_hop_by_hop(h), "{h}");
        }
        assert!(!is_hop_by_hop("x-request-id"));
    }

    #[test]
    fn clients_are_shared_per_connect_timeout() {
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let k = KeepaliveOpts::default();
        let tls = TlsPolicy::default();
        let a = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            k,
            &tls,
            false,
        );
        let b = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            k,
            &tls,
            false,
        );
        let c = e.client(
            Duration::from_secs(7),
            Duration::from_secs(60),
            k,
            &tls,
            false,
        );
        let _ = (&a, &b, &c);
        let n = e.clients.lock().unwrap().len();
        assert_eq!(n, 2, "两个不同的 connect 超时应有两个客户端池");
    }

    #[test]
    fn keepalive_config_splits_pools() {
        // 相同 connect 超时但不同 keepalive 配置应各自独立成套池；同配置复用同一套。
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let tls = TlsPolicy::default();
        let base = KeepaliveOpts::default();
        let capped = KeepaliveOpts {
            max_idle: Some(8),
            idle_timeout: None,
        };
        let timed = KeepaliveOpts {
            max_idle: None,
            idle_timeout: Some(Duration::from_secs(5)),
        };
        let _ = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            base,
            &tls,
            false,
        );
        let _ = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            base,
            &tls,
            false,
        ); // 同键 → 命中缓存，不新增
        let _ = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            capped,
            &tls,
            false,
        );
        let _ = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            timed,
            &tls,
            false,
        );
        assert_eq!(
            e.clients.lock().unwrap().len(),
            3,
            "keepalive 不同的三个配置应各建一套池"
        );
    }

    #[test]
    fn tls_policy_splits_pools_even_with_same_timeouts() {
        // 相同 connect/keepalive 但不同 TLS 策略：必须分池，否则某 location 的
        // `proxy_ssl_verify off` 会污染另一 location 的连接器（安全隐患）。
        // 用 verify off 的两种变体，保证都能成功构建（verify on 无 CA 会直接报错不入池）。
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let k = KeepaliveOpts::default();
        let a = TlsPolicy {
            verify: false,
            server_name: Some("a.example".to_string()),
            ..Default::default()
        };
        let b = TlsPolicy {
            verify: false,
            server_name: Some("b.example".to_string()),
            ..Default::default()
        };
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &a, true);
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &b, true);
        // 同策略再来一次 → 命中缓存，不新增
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &a, true);
        // http 目标忽略 TLS 指纹（第四键恒 0），与上面两个 https 池都不同键
        let _ = e.client(
            Duration::from_secs(3),
            Duration::from_secs(60),
            k,
            &a,
            false,
        );
        assert_eq!(e.clients.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn https_backend_needs_trusted_cert_when_verify_on() {
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let mut c = ctx();
        // 纯 Rust 离线构建未链接系统根库：verify on 且无 CA 束应给出明确错误，
        // 而非静默连上或裸 TLS 失败。
        let tls = TlsPolicy {
            verify: true,
            ..Default::default()
        };
        let opts = ProxyOpts {
            set_headers: &[],
            timeouts: ProxyTimeouts {
                connect: Duration::from_secs(1),
                send: Duration::from_secs(1),
                read: Duration::from_secs(1),
            },
            next_upstream: &[],
            next_upstream_tries: 0,
            split: None,
            split_failover: SplitFailover::On,
            var_targets: None,
            next_upstream_timeout: Duration::ZERO,
            tls: &tls,
        };
        let err = e
            .forward(
                &mut c,
                "https://example.com",
                "/api",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await
            .unwrap_err();
        assert!(err.contains("proxy_ssl_trusted_certificate"), "{err}");
    }

    #[tokio::test]
    async fn forward_records_upstream_metrics_on_failure() {
        // 直连一个无监听端口 → forward 返回 Err，但 ctx 仍记录被试后端与 status=0，
        // 供 $upstream_addr / log_by_lua 观察（对照 nginx：失败也会记 upstream_addr）。
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let mut c = ctx();
        let tls = TlsPolicy {
            verify: false,
            ..Default::default()
        };
        let opts = ProxyOpts {
            set_headers: &[],
            timeouts: ProxyTimeouts {
                connect: Duration::from_millis(300),
                send: Duration::from_millis(300),
                read: Duration::from_millis(300),
            },
            next_upstream: &[],
            next_upstream_tries: 0,
            split: None,
            split_failover: SplitFailover::On,
            var_targets: None,
            next_upstream_timeout: Duration::ZERO,
            tls: &tls,
        };
        let r = e
            .forward(
                &mut c,
                "http://127.0.0.1:1",
                "/api",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await;
        assert!(r.is_err(), "无监听端口应转发失败");
        assert_eq!(c.upstream_addr, "127.0.0.1:1");
        assert_eq!(c.upstream_status, 0);
    }

    /// 主机位是**非分流**变量时，白名单外的落点连一次 socket 都不许开 —— 客户端可控的
    /// 变量（`$http_x_target` / `$arg_host` / `$cookie_route`）不能把网关变成任意地址的连接器。
    /// 带对照组：同一个引擎、同一份 opts，挂进集合的落点照常回源 —— 否则"没连上"
    /// 可能只是测试自己写错了，而不是闸门生效。
    #[tokio::test]
    async fn variable_host_outside_allowlist_never_connects() {
        let reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (canary, canary_hits) = counted_backend(reply).await;
        let (declared, declared_hits) = counted_backend(reply).await;
        let e = ProxyEngine::new(Arc::new(UpstreamPool::default()));
        let tls = TlsPolicy::default();
        let allow = Arc::new(
            [declared.clone()]
                .into_iter()
                .collect::<std::collections::HashSet<String>>(),
        );
        let mut opts = test_opts(&tls, None, SplitFailover::On);
        opts.var_targets = Some(&allow);

        let err = e
            .forward(
                &mut ctx(),
                &format!("http://{canary}"),
                "/x",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await
            .unwrap_err();
        assert!(err.contains("undeclared proxy_pass target"), "{err}");
        assert_eq!(
            canary_hits.load(Relaxed),
            0,
            "白名单外的落点一次连接都不该发起"
        );

        let mut c2 = ctx();
        let ok = e
            .forward(
                &mut c2,
                &format!("http://{declared}"),
                "/x",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await;
        assert!(ok.is_ok(), "挂进集合的落点不该被拦：{:?}", ok.err());
        assert_eq!(declared_hits.load(Relaxed), 1);
    }

    #[test]
    fn tls_policy_build_client_config() {
        // verify off：AcceptAll danger verifier，可直接构建
        let off = TlsPolicy {
            verify: false,
            ..Default::default()
        };
        assert!(off.build_client_config().is_ok());
        // verify on 且无 trusted cert：明确报错（离线未链接系统根库）
        let on = TlsPolicy::default();
        assert!(on
            .build_client_config()
            .unwrap_err()
            .contains("proxy_ssl_trusted_certificate"));
        // 不同策略的指纹必须不同，避免连接池串味
        assert_ne!(off.fingerprint(), on.fingerprint());
    }

    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    /// 固定应答的假后端 + 命中计数：分流不能只看返回码，必须证明请求有没有真的落到这一路
    async fn counted_backend(reply: &'static str) -> (String, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                h.fetch_add(1, Relaxed);
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        (addr, hits)
    }

    /// 曾经监听、已经关掉的端口：connect 直接被拒
    async fn dead_port() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap().to_string();
        drop(l);
        a
    }

    fn pool_of(spec: &str) -> Arc<UpstreamPool> {
        Arc::new(
            UpstreamPool::parse_all(&onrouter_config::Config::parse(spec).expect("配置应能解析"))
                .expect("upstream 应能构建"),
        )
    }

    fn route(dest: &str, branches: &[&str]) -> crate::router::RouteSplit {
        let targets: Vec<String> = branches.iter().map(|s| s.to_string()).collect();
        crate::router::RouteSplit {
            dest: dest.to_string(),
            key: "\"${remote_addr}\"".to_string(),
            branches: targets
                .iter()
                .enumerate()
                .map(|(i, t)| (if i == 0 { 100.0 } else { 0.0 }, t.clone()))
                .collect(),
            star: None,
            stats: crate::engine::register_split_route(dest, &targets),
            summary: None,
        }
    }

    #[test]
    fn split_candidate_order_follows_failover_policy() {
        let sp = route("t_cand", &["v1", "v2", "v3"]);
        // 默认 on：本意那一路排第一，其余按声明顺序补上来
        assert_eq!(
            split_candidates("v2", Some(&sp), &SplitFailover::On),
            vec!["v2", "v1", "v3"]
        );
        // off：只有一个候选，绝不改投
        assert_eq!(
            split_candidates("v2", Some(&sp), &SplitFailover::Off),
            vec!["v2"]
        );
        // 显式目标：只有它，其余分支一律不碰
        assert_eq!(
            split_candidates("v2", Some(&sp), &SplitFailover::Target("v3".into())),
            vec!["v2", "v3"]
        );
        // 没有分流（目标写死）：一个候选，与今天的行为逐字一致
        assert_eq!(
            split_candidates("backend", None, &SplitFailover::On),
            vec!["backend"]
        );
    }

    #[test]
    fn split_branch_must_be_enumerable_never_guessed_from_dns() {
        let e = ProxyEngine::new(Arc::new(UpstreamPool::default()));
        // 严格模式（分流分支）：裸名字查不到池就是错误，绝不悄悄交给 DNS
        let err = match e.pick_backend("v9", "10.0.0.9", true) {
            Err(e) => e,
            Ok(_) => panic!("裸名字的分支不该被交给 DNS 猜"),
        };
        assert!(err.contains("no split branch"), "实际: {err}");
        assert!(
            e.pick_backend("v9", "10.0.0.9", false).is_ok(),
            "目标写死时保持今天的直连语义"
        );
        // 自带落点的写法在严格模式下照样允许
        assert!(e.pick_backend("127.0.0.1:8080", "10.0.0.9", true).is_ok());
        assert!(
            e.pick_backend("10.0.0.5", "10.0.0.9", true).is_ok(),
            "IP 字面量不经 DNS"
        );
        let empty = match e.pick_backend("", "10.0.0.9", true) {
            Err(e) => e,
            Ok(_) => panic!("空分支不可能有落点"),
        };
        assert!(empty.contains("empty"), "实际: {empty}");
        // 具名池命中：返回池里的节点并带上池名（组内换节点重试用）
        let up = pool_of("upstream gray { server 127.0.0.1:8081; server 127.0.0.1:8082; }");
        let e2 = ProxyEngine::new(up);
        let p = match e2.pick_backend("gray", "10.0.0.9", true) {
            Ok(p) => p,
            Err(e) => panic!("池内应有节点: {e}"),
        };
        assert!(["127.0.0.1:8081", "127.0.0.1:8082"].contains(&p.backend.as_str()));
        assert_eq!(p.pool.as_deref(), Some("gray"));
        assert_eq!(
            p.tried.len(),
            1,
            "首个节点要计入 tried，否则换节点会重复选同一台"
        );
    }

    #[tokio::test]
    async fn bleeding_only_happens_when_the_chosen_branch_has_no_backend() {
        let (b_addr, b_hits) =
            counted_backend("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let dead = dead_port().await;
        let pool = pool_of(&format!(
            "upstream a {{ server {dead}; }} upstream b {{ server {b_addr}; }}"
        ));
        let e = ProxyEngine::new(pool);
        let sp = route("t_bleed", &["a", "b"]);
        let stats = sp.stats.clone().expect("账本应已登记");
        let tls = TlsPolicy::default();
        let opts = test_opts(&tls, Some(&sp), SplitFailover::On);
        // 第一次：a 池里还有"可选节点"，请求发出去后被拒 —— 这不是改投时刻，原样失败
        let mut c1 = ctx();
        let r1 = e
            .forward(
                &mut c1,
                "http://a",
                "/api",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await;
        assert!(r1.is_err(), "本意那路拒接时应原样失败");
        assert_eq!(c1.proxy_split, "a");
        // 请求已经交给了 a 的节点（只是那台拒接）：这不算改投，served 记 a
        assert_eq!(c1.proxy_split_served, "a");
        assert_eq!(b_hits.load(Relaxed), 0, "a 还有节点时绝不能落到 b");
        assert_eq!(stats.served("a"), 1);
        assert_eq!(stats.role(SplitRole::Routed), 1);
        assert_eq!(stats.role(SplitRole::Bled), 0);
        assert_eq!(
            stats.role(SplitRole::Down),
            0,
            "a 当时还有可选节点，不是'没人可服务'"
        );
        // 第二次：被动健康检查已把 a 摘除 —— 这才是"这一路没人可服务"，允许改投
        let mut c2 = ctx();
        let r2 = e
            .forward(
                &mut c2,
                "http://a",
                "/api",
                &opts,
                ProxyBody::Buffered(None),
            )
            .await;
        assert!(r2.is_ok(), "a 全摘后应按 proxy_split_failover 改投到 b");
        assert_eq!(c2.proxy_split, "a", "$proxy_split 记的是按比例选中的那一路");
        assert_eq!(
            c2.proxy_split_served, "b",
            "实际服务的是改投后的那一路，两者不同才说明串过台"
        );
        assert_eq!(b_hits.load(Relaxed), 1);
        assert_eq!(stats.served("b"), 1);
        assert_eq!(stats.role(SplitRole::Down), 1);
        assert_eq!(stats.role(SplitRole::Bled), 1);
        assert_eq!(
            stats.role(SplitRole::Routed),
            1,
            "改投那次记 bled，不重复记 routed"
        );
    }

    #[tokio::test]
    async fn failover_off_keeps_the_failure_in_its_own_branch() {
        let (b_addr, b_hits) =
            counted_backend("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let dead = dead_port().await;
        let pool = pool_of(&format!(
            "upstream a {{ server {dead}; }} upstream b {{ server {b_addr}; }}"
        ));
        let e = ProxyEngine::new(pool);
        let sp = route("t_off", &["a", "b"]);
        let stats = sp.stats.clone().expect("账本应已登记");
        let tls = TlsPolicy::default();
        let opts = test_opts(&tls, Some(&sp), SplitFailover::Off);
        // 先让 a 的节点拒接一次，把它摘除
        let mut c0 = ctx();
        assert!(e
            .forward(
                &mut c0,
                "http://a",
                "/api",
                &opts,
                ProxyBody::Buffered(None)
            )
            .await
            .is_err());
        assert_eq!(
            c0.proxy_split_served, "a",
            "请求确实交给了 a 的节点，只是那台拒接"
        );
        // 摘除之后再请求：off 模式下"这一路没人可服务"也不改投，原样失败
        for _ in 0..2 {
            let mut c = ctx();
            let r = e
                .forward(&mut c, "http://a", "/api", &opts, ProxyBody::Buffered(None))
                .await;
            assert!(r.is_err(), "不串台：这一路的失败原样回给客户端");
            assert_eq!(c.proxy_split, "a");
            assert_eq!(
                c.proxy_split_served, "",
                "一个节点都没交给，就不该有'实际服务的那一路'"
            );
        }
        assert_eq!(b_hits.load(Relaxed), 0, "off 模式下 b 一次都不该被碰到");
        assert_eq!(stats.role(SplitRole::Bled), 0);
        assert_eq!(stats.served("b"), 0);
        assert!(
            stats.role(SplitRole::Down) >= 1,
            "摘除后的那一路要留下'没人可服务'的账"
        );
    }

    #[tokio::test]
    async fn a_5xx_response_never_re_routes_to_another_branch() {
        // 这条是整套语义的安全边界：后端已经收到过请求，成败归 proxy_next_upstream / error_page，
        // 绝不能跨路重投 —— 否则一个 POST 会被写进两个业务版本。
        let (a_addr, a_hits) =
            counted_backend("HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .await;
        let (b_addr, b_hits) =
            counted_backend("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let pool = pool_of(&format!(
            "upstream a {{ server {a_addr}; }} upstream b {{ server {b_addr}; }}"
        ));
        let e = ProxyEngine::new(pool);
        let sp = route("t_5xx", &["a", "b"]);
        let stats = sp.stats.clone().expect("账本应已登记");
        let tls = TlsPolicy::default();
        let opts = test_opts(&tls, Some(&sp), SplitFailover::On);
        let mut c = ctx();
        let r = e
            .forward(&mut c, "http://a", "/api", &opts, ProxyBody::Buffered(None))
            .await
            .expect("5xx 是后端的答复，不是没人可服务");
        assert_eq!(r.status().as_u16(), 500);
        assert_eq!(c.proxy_split, "a");
        assert_eq!(c.proxy_split_served, "a");
        assert_eq!(a_hits.load(Relaxed), 1);
        assert_eq!(b_hits.load(Relaxed), 0, "后端 5xx 绝不能改投到别的业务版本");
        assert_eq!(stats.role(SplitRole::Bled), 0);
        assert_eq!(stats.role(SplitRole::Routed), 1);
    }

    fn test_opts<'a>(
        tls: &'a TlsPolicy,
        split: Option<&'a crate::router::RouteSplit>,
        failover: SplitFailover,
    ) -> ProxyOpts<'a> {
        ProxyOpts {
            set_headers: &[],
            timeouts: ProxyTimeouts {
                connect: Duration::from_millis(300),
                send: Duration::from_millis(300),
                read: Duration::from_millis(300),
            },
            next_upstream: &[],
            next_upstream_tries: 0,
            next_upstream_timeout: Duration::ZERO,
            tls,
            split,
            split_failover: failover,
            var_targets: None,
        }
    }
}
