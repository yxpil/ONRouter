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
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderValue, CONTENT_LENGTH, HOST, CONNECTION, UPGRADE};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use http::Uri;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_service::Service as _;

use crate::engine::RequestCtx;
use crate::proxy_tls::{ProxyConnector, ProxyStream, TlsPolicy};
use crate::upstream::{KeepaliveOpts, UpstreamGuard, UpstreamPool};
use crate::{log_warn, log_info};

/// 转发请求体统一擦除成 BoxBody：缓冲路径塞 `Full<Bytes>`，流式路径塞客户端的 `Incoming`，
/// 二者共用同一套连接池客户端（`Client` 的请求体类型是编译期固定的）。
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type ProxyReqBody = BoxBody<Bytes, BoxError>;
type HyperClient = Client<ProxyConnector, ProxyReqBody>;

fn full_boxed(b: Bytes) -> ProxyReqBody {
    Full::new(b)
        .map_err(|e| match e {})
        .boxed()
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
            ka.idle_timeout.map(|d| d.as_millis() as u64).unwrap_or(u64::MAX),
            if is_https { tls.fingerprint() } else { 0 },
        );
        let mut map = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = map.get(&key) {
            return Ok(c.clone());
        }
        let tls_cfg = if is_https { Some(tls.build_client_config()?) } else { None };
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
        let rest = target
            .strip_prefix("https://")
            .or_else(|| target.strip_prefix("http://"))
            .unwrap_or(target);
        let (host_part, uri_part) = match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), Some(format!("/{p}"))),
            None => (rest.to_string(), None),
        };
        // upstream 负载均衡：guard 存活期间连接计数 +1，并用于健康检查上报
        let mut guard_holder: Option<UpstreamGuard> = None;
        let mut tried: Vec<usize> = Vec::new();
        let mut max_attempts = 2;
        // 命具 named upstream 时套用其 keepalive 调优；直连目标走默认（hyper 池默认）。
        let mut keepalive = KeepaliveOpts::default();
        let backend = if let Some((bh, bp)) = ctx.balancer_peer.clone() {
            // balancer_by_lua 显式选定节点：绕开 upstream 负载均衡，直连该 host:port。
            // 单跳转发（Lua 已在对端选择逻辑里自行处理节点，不在这里做组内 failover）。
            max_attempts = 1;
            format!("{bh}:{bp}")
        } else if let Some(up) = self.pool.get(&host_part) {
            max_attempts = up.server_count().max(1).min(8);
            keepalive = up.keepalive;
            match up.acquire(&ctx.remote_addr, &tried) {
                Some(g) => {
                    tried.push(g.idx());
                    let addr = (*g).clone();
                    guard_holder = Some(g);
                    addr
                }
                // 对齐 nginx：全组没有可选节点时是 502 + "no live upstreams"，
                // 不是把请求硬塞给已经摘除的节点
                None => return Err(format!("no live upstreams: {host_part}")),
            }
        } else {
            host_part.clone()
        };
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
            Some(repl) => {
                let rel = match ctx.effective_path().strip_prefix(loc_prefix) {
                    Some(r) => r,
                    None => ctx.effective_path(),
                };
                let rel = if rel.is_empty() { "/" } else { rel };
                let base = repl.trim_end_matches('/');
                if rel.starts_with('/') {
                    format!("{base}{rel}")
                } else {
                    format!("{base}/{rel}")
                }
            }
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
            if is_hop_by_hop(k) || k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("expect")
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

        let mut backend = backend;
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
                if let Some(up) = self.pool.get(&host_part) {
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
                log_warn!("upstream {host_part} 换节点重试: {backend}");
            }
            // https 后端保留主机名（SNI/证书校验需要 DNS 名），不做 resolver→IP 改写；
            // http 后端若配了 resolver 则把域名换成 IP 以跳过阻塞式 getaddrinfo。
            let connect_host = if is_https {
                backend.clone()
            } else {
                self.connect_target(&backend).await?
            };
            let scheme = if is_https { "https" } else { "http" };
            let uri = format!(
                "{scheme}://{connect_host}{}{query}",
                encode_path(&out_path),
            );
            // 每次尝试重建请求体：缓冲体可回放（clone Bytes），流式体只能取用一次
            let req_body: ProxyReqBody = match &mut body {
                ProxyBody::Buffered(b) => full_boxed(b.as_ref().cloned().unwrap_or_default()),
                ProxyBody::Streaming(inc) => {
                    inc.take().expect("streaming body 仅用于单次尝试")
                }
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
                    if !retry_statuses.is_empty()
                        && method_retryable
                        && retry_statuses.contains(&status)
                        && attempt + 1 < max_attempts
                        && within_budget
                    {
                        guard_holder = None;
                        ctx.upstream_status = status;
                        last_err = format!(
                            "后端返回 {status}，按 proxy_next_upstream 换节点: {backend}"
                        );
                        log_warn!("{last_err}");
                        drop(r);
                        continue;
                    }
                    // 响应头已到：guard 随响应体继续存活，读完/失败后才结算
                    let (parts, incoming) = r.into_parts();
                    ctx.upstream_status = parts.status.as_u16();
                    ctx.upstream_header_time = t0.elapsed().as_secs_f64();
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
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PROPFIND" | "COPY" | "MOVE" | "MKCOL" | "LOCK"
            | "UNLOCK" | "SEARCH"
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
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization"
            | "te" | "trailer" | "transfer-encoding" | "upgrade"
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

/// hyper 把所有协议错误折叠成字符串，只能按根因文本近似识别"响应头非法"
/// （invalid HTTP status-code / invalid HTTP header / invalid content-length 等）。
fn looks_like_invalid_header(root: &str) -> bool {
    let s = root.to_ascii_lowercase();
    s.contains("invalid") || s.contains("parse")
}

/// 配置值里的内置变量插值（proxy_set_header 与 rust handler 共用）
pub fn interpolate_vars(template: &str, ctx: &RequestCtx) -> String {
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
        let value = match name {
            // 与既有语义保持一致：无 Host 头时回落 "unknown"
            "host" => Some(ctx.host.clone().unwrap_or_else(|| "unknown".to_string())),
            _ => crate::engine::resolve_var(ctx, name, 0),
        };
        match value {
            Some(v) => out.push_str(&v),
            // nginx 中缺失的 http/arg/cookie 变量展开为空串
            None if name.starts_with("http_")
                || name.starts_with("sent_http_")
                || name.starts_with("arg_")
                || name.starts_with("cookie_") => {}
            None => out.push_str(&template[i..i + consumed]),
        }
        i += consumed;
    }
    out
}

/// 检测是否为 WebSocket/Upgrade 请求（对标 nginx 的 map $http_upgrade $connection_upgrade）
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    // Connection 头必须包含 "upgrade"
    let has_upgrade_conn = headers
        .get_all(CONNECTION)
        .iter()
        .any(|v| v.to_str().ok().map(|s| s.to_ascii_lowercase().contains("upgrade")).unwrap_or(false));
    
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
        // balancer_by_lua 选点优先；否则 upstream 名走负载均衡 + 被动健康检查，最后按 host:port 直连
        let mut guard_holder: Option<UpstreamGuard> = None;
        let backend_addr = if let Some((bh, bp)) = ctx.balancer_peer.clone() {
            format!("{bh}:{bp}")
        } else if let Some(up) = self.pool.get(&host_part) {
            match up.acquire(&ctx.remote_addr, &[]) {
                Some(g) => {
                    let addr = (*g).clone();
                    guard_holder = Some(g);
                    addr
                }
                None => return Err(format!("no live upstreams: {host_part}")),
            }
        } else {
            host_part.clone()
        };
        // 访问日志的 $upstream_addr：即使在后续建连/握手阶段失败也要留下尝试目标
        ctx.upstream_addr = backend_addr.clone();
        let (host, port) = match backend_addr.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| format!("非法端口: {p}"))?),
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
        let tls_cfg = if is_tls { Some(opts.tls.build_client_config()?) } else { None };
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
            if is_hop_by_hop(k) || k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("expect") {
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
            HeaderValue::try_from(ctx.host.as_deref().unwrap_or(&host)).map_err(|e| e.to_string())?,
        );
        req_headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Some(upgrade) = ctx.header("upgrade") {
            req_headers.insert(UPGRADE, HeaderValue::try_from(upgrade).map_err(|e| e.to_string())?);
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
            request_buf.extend_from_slice(format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes());
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
        let status_code = if first_line.len() >= 12 && (first_line.starts_with("HTTP/1.1 ") || first_line.starts_with("HTTP/1.0 ")) {
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
        log_info!("WebSocket/Upgrade 隧道已建联: {} -> {}", ctx.remote_addr, backend_addr);
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
            upstream_header_time: 0.0,
            ssl: None,
            start_time: 0.0,
            http_version: 1.1,
            body_builder: None,
            eof_sent: false,
        }
    }

    #[test]
    fn interpolates_core_variables() {
        let c = ctx();
        assert_eq!(
            interpolate_vars("$scheme://$host:$server_port$uri?$args", &c),
            "https://www.example.com:8080/api/x?a=1"
        );
        assert_eq!(interpolate_vars("$remote_addr:$remote_port", &c), "10.0.0.9:54321");
        assert_eq!(
            interpolate_vars("$proxy_add_x_forwarded_for", &c),
            "1.1.1.1, 10.0.0.9"
        );
    }

    #[test]
    fn expands_http_header_vars() {
        let c = ctx();
        assert_eq!(interpolate_vars("[$http_user_agent|$http_missing]", &c), "[curl/8|]");
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
    fn forwarded_path_is_reencoded_per_segment() {
        // 解码后的中文/空格必须重新编码，否则后端拿到非法请求行
        assert_eq!(encode_path("/a b/中文.html"), "/a%20b/%E4%B8%AD%E6%96%87.html");
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
        assert_eq!(raw_upgrade_target(&c).as_deref(), Some("/ws%23frag?x=1%3fy=2"));
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
        let a = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &tls, false);
        let b = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &tls, false);
        let c = e.client(Duration::from_secs(7), Duration::from_secs(60), k, &tls, false);
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
        let capped = KeepaliveOpts { max_idle: Some(8), idle_timeout: None };
        let timed = KeepaliveOpts { max_idle: None, idle_timeout: Some(Duration::from_secs(5)) };
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), base, &tls, false);
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), base, &tls, false); // 同键 → 命中缓存，不新增
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), capped, &tls, false);
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), timed, &tls, false);
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
        let _ = e.client(Duration::from_secs(3), Duration::from_secs(60), k, &a, false);
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
            next_upstream_timeout: Duration::ZERO,
            tls: &tls,
        };
        let err = e
            .forward(&mut c, "https://example.com", "/api", &opts, ProxyBody::Buffered(None))
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
            next_upstream_timeout: Duration::ZERO,
            tls: &tls,
        };
        let r = e
            .forward(&mut c, "http://127.0.0.1:1", "/api", &opts, ProxyBody::Buffered(None))
            .await;
        assert!(r.is_err(), "无监听端口应转发失败");
        assert_eq!(c.upstream_addr, "127.0.0.1:1");
        assert_eq!(c.upstream_status, 0);
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
        assert!(on.build_client_config().unwrap_err().contains("proxy_ssl_trusted_certificate"));
        // 不同策略的指纹必须不同，避免连接池串味
        assert_ne!(off.fingerprint(), on.fingerprint());
    }
}
