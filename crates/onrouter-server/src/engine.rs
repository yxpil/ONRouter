//! 引擎：rewrite/return 规则执行 + Rust 原生处理器注册表（对标 OpenResty 的 *_by_lua，但全部 Rust 编译期实现）。
//!
//! 配置指令：
//! ```text
//! rewrite ^/old/(.*)$ /new/$1 last;
//! return 301 http://example.com;
//! content_by_rust hello;          # 调用注册的 Rust 处理器
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::sync::mpsc;

use onrouter_config::Directive;

use crate::log_warn;
use crate::AppError;

/// 流式响应的帧：Head 只在最前面出现一次，之后都是 Data，End 表示脚本收尾、
/// 响应体到此为止（不依赖发送端全部 drop，便于 log 阶段继续持有 ctx）。
#[derive(Debug)]
pub enum StreamEvent {
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Data(Bytes),
    End,
}

/// content_by_lua 的流式输出口（ngx.flush 或输出越过阈值后启用）。
/// 发送端是有界通道：脚本同步调用 ngx.flush 时 try_send，通道满则把字节留在
/// ctx.body 里等下次；脚本结束后由后台任务 await 补发剩余数据，保证不丢字节。
#[derive(Debug, Clone)]
pub struct StreamSink {
    pub tx: mpsc::Sender<StreamEvent>,
    /// Head 快照要合并的 add_header（location 覆盖 server）
    pub extra_headers: Vec<(String, String)>,
    head_sent: bool,
}

impl StreamSink {
    pub fn new(tx: mpsc::Sender<StreamEvent>, extra_headers: Vec<(String, String)>) -> Self {
        Self {
            tx,
            extra_headers,
            head_sent: false,
        }
    }
}

/// 自动冲刷阈值：ngx.say/print 的缓冲超过它就先发一帧，避免脚本忘写 ngx.flush
/// 时整段响应都等脚本跑完（对齐 nginx 输出缓冲上限的直觉）。
pub const STREAM_AUTO_FLUSH_BYTES: usize = 64 * 1024;

// ---------- 请求上下文（贯穿 rewrite -> access -> content） ----------

/// ssl_certificate_by_lua 阶段的握手状态：SNI、脚本选出的证书/私钥、是否清空或中止。
/// 只在握手期间挂在 ctx 上（普通请求为 None），ngx.ssl.* 通过它读写。
#[derive(Debug, Clone, Default)]
pub struct SslState {
    pub server_name: Option<String>,
    pub cert_chain: Option<Vec<Vec<u8>>>,
    pub priv_key: Option<Vec<u8>>,
    /// 脚本调用 clear_certs() 后置位：未再设置新证书则握手失败（与 OpenResty 一致）
    pub cleared: bool,
    /// 脚本 ngx.exit(负数错误码) 中止握手
    pub aborted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    pub method: String,
    /// 解码并归一化后的路径（用于 location 匹配与静态文件解析）
    pub path: String,
    pub query: String,
    /// 客户端发来的原始 URI（含 query，未解码）——日志与 $request_uri 用它
    pub uri: String,
    pub host: Option<String>,
    pub remote_addr: String,
    /// 客户端端口（`$remote_port`）
    pub remote_port: u16,
    /// 本服务监听端口（`$server_port`）
    pub server_port: u16,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    /// 处理过程中可能被 rewrite 修改后的路径
    pub rewritten_path: Option<String>,
    pub status: u16,
    /// 生成式响应体（return / rust handler 产出）
    pub body: Option<Vec<u8>>,
    /// 流式输出口：只有 content_by_lua 且无 header/body filter 时才装上
    pub stream: Option<StreamSink>,
    pub done: bool,
    /// rewrite ... last 触发的内部重定向
    pub internal_redirect: bool,
    /// 请求体（当前缓冲式读取；供 Lua 读取与代理转发）
    /// 用 Bytes 而不是 Vec：入口克隆/LOG 阶段克隆 ctx 都是 O(1)，且 Bytes 不可变，
    /// 代理前可用"指针相同"快速判定 Lua 没有改写，无需每次请求再 memcmp 一遍。
    pub req_body: Bytes,
    /// ngx.exec 内部重定向深度
    pub exec_depth: u8,
    /// rewrite ... redirect/permanent 触发的外部重定向
    pub redirect: Option<(u16, String)>,
    /// 客户端侧协议（http/https）；由连接的 TLS 状态决定，用于 X-Forwarded-Proto
    pub scheme: String,
    /// 本次请求是否为内部重定向产物（`internal;` location 只放行这类请求）
    pub internal_request: bool,
    /// body_filter_by_lua 参数：ngx.arg[1]=chunk, ngx.arg[2]=eof
    pub filter_chunk: Option<Vec<u8>>,
    pub filter_eof: bool,
    /// 本请求所属监听端点地址；子请求（ngx.location.capture）据此重新匹配 vhost
    pub listener: Option<SocketAddr>,
    /// 子请求嵌套深度（ngx.location.capture 的循环/超深防护）
    pub capture_depth: u8,
    /// balancer_by_lua：Lua 选定的上游节点 (host, port)；非空时转发绕开 upstream 负载均衡直连此节点
    pub balancer_peer: Option<(String, u16)>,
    /// balancer_by_lua set_timeouts：连接/发送/读取超时（毫秒），非空时覆盖 location 的 proxy_*_timeout
    pub balancer_timeouts: Option<(u64, u64, u64)>,
    /// balancer_by_lua set_more_failures：{failures, return_code, escalate}，记录供健康上报参考
    pub balancer_more_failures: Option<(u32, u32, bool)>,
    /// balancer_by_lua recreate_request(true)：本次转发是否重建发往后端的请求
    pub balancer_recreate_request: bool,
    /// 代理转发实际选定的后端 host:port（供 $upstream_addr / log_by_lua 读取）
    pub upstream_addr: String,
    /// 代理转发收到的后端响应状态码（0 = 未取得；供 $upstream_status）
    pub upstream_status: u16,
    /// 后端"连接+发送+等到响应头"的耗时秒数（供 $upstream_header_time / $upstream_response_time）
    pub upstream_header_time: f64,
    /// SSL 握手阶段状态；仅 ssl_certificate_by_lua 执行期间为 Some
    pub ssl: Option<SslState>,
    /// 请求到达时间（epoch 秒），供 `ngx.req.start_time()` / `$request_time`
    pub start_time: f64,
    /// HTTP 版本（1.0 / 1.1 / 2.0 / 3.0），供 `ngx.req.http_version()`
    pub http_version: f64,
    /// `ngx.req.init_body` / `append_body` 的构造缓冲；`finish_body` 提交到 req_body
    pub body_builder: Option<Vec<u8>>,
    /// `ngx.eof()` 已结束响应：后续 `ngx.print/say` 输出丢弃
    pub eof_sent: bool,
    /// `$upstream_cache_status`：本次请求的 proxy_cache 结果（HIT/MISS/EXPIRED/BYPASS/STALE）。
    /// 请求根本没参与缓存（非幂等方法、未配 zone、流式请求体）时是空串，与 nginx 一致。
    pub cache_status: String,
    /// `$still_online`：本次响应是否由 Still ONLine 副本顶替（回放时为 `STALE`）。
    /// 没配副本区、或本次正常回源成功时是空串——与 `$upstream_cache_status` 同理。
    pub still_online: String,
    /// `$proxy_split`：按比例**选中**的那一路（split_clients 落桶的结果）。
    /// 没走变量分流时是空串。
    pub proxy_split: String,
    /// `$proxy_split_served`：**请求被交给**哪一路（在解析出后端节点时记账）。与 `$proxy_split`
    /// 不同就说明发生了跨路改投（`proxy_split_failover`），业务归因要按这个字段；
    /// 一个节点都没选中（整池在摘除期、目标不存在）时是空串。
    pub proxy_split_served: String,
    /// `front_proxy` 命中的 profile 名；空串 = 没认出前置代理（CDN /  LB）。
    /// 识别本身不代表信任，信任看 `$front_proxy_verified`。
    pub front_proxy: String,
    /// 前置代理给出的客户端国家码；只有直连对端验证过才会有值。
    pub front_proxy_country: String,
    /// 前置代理给出的对外可见域名（`X-Forwarded-Host` 一类头）；同样只有验证过才采信。
    /// 刻意不回写 `ctx.host`：那个字段参与虚拟主机匹配、日志与缓存键，
    /// 要用它拼 URL 或转发给后端请在配置里显式写 `$front_proxy_host`。
    pub front_proxy_host: String,
    /// 直连 TCP 对端是否落在 `profile.trust ∪ set_real_ip_from` 内。
    /// 这是所有头部取值的准入闸门：闸门没过，地址/协议/Host/国家一个都不采信。
    pub front_proxy_verified: bool,
    /// 未被任何模块改写过的真实 TCP 对端地址（nginx `$realip_remote_addr` 同名）。
    /// 审计用：拿它和 `$remote_addr` 一比就能看出"头部声称的地址"与"实际连上来的"差多少。
    pub realip_remote_addr: String,
    /// `set $name value;` 写入的请求级变量，后写覆盖先写。
    /// 解析顺序在 map/geo/builtin 之前：nginx 里 `set` 注册的是独立变量，与它们不可能重名。
    pub set_vars: Vec<(String, String)>,
    /// `if (cond) { return ...; }` 命中后暂存的 return。
    /// ONRouter 刻意**不**在 REWRITE 阶段立即结束请求，而是和裸 `return` 在同一处执行
    /// （ACCESS 之后）：条件 return 因此不可能绕过 allow/deny 与 auth_basic。
    /// 这是与 nginx 的已知差异（nginx 里 return 属于 rewrite 阶段，先于访问控制）。
    pub rewrite_return: Option<ReturnAction>,
}

impl RequestCtx {
    pub fn effective_path(&self) -> &str {
        self.rewritten_path.as_deref().unwrap_or(&self.path)
    }

    /// Lua 的 ngx.say/ngx.print 输出入口：流式模式下越过阈值自动推一帧。
    pub fn lua_output(&mut self, bytes: &[u8]) {
        if self.eof_sent {
            return;
        }
        self.body
            .get_or_insert_with(Vec::new)
            .extend_from_slice(bytes);
        if self.stream.is_some()
            && self
                .body
                .as_ref()
                .is_some_and(|b| b.len() >= STREAM_AUTO_FLUSH_BYTES)
        {
            self.flush_stream();
        }
    }

    /// 把已缓冲的输出推给流式通道；首帧先推 Head 快照（状态 + 头 + add_header）。
    /// 返回 true 表示缓冲已清空。通道满时数据留在 body 里，下次再推。
    pub fn flush_stream(&mut self) -> bool {
        if self.stream.is_none() {
            return false;
        }
        if !self.stream.as_ref().is_some_and(|s| s.head_sent) {
            let status = self.status;
            let mut headers = self.resp_headers.clone();
            if let Some(sink) = &self.stream {
                for (k, v) in &sink.extra_headers {
                    if !headers.iter().any(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
                        headers.push((k.clone(), v.clone()));
                    }
                }
            }
            if !(100..200).contains(&status)
                && status != 204
                && status != 304
                && !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                headers.push(("content-type".into(), "text/plain; charset=utf-8".into()));
            }
            let sent = self
                .stream
                .as_ref()
                .is_some_and(|s| s.tx.try_send(StreamEvent::Head { status, headers }).is_ok());
            if !sent {
                return false;
            }
            if let Some(s) = self.stream.as_mut() {
                s.head_sent = true;
            }
        }
        let Some(body) = self.body.take() else {
            return true;
        };
        if body.is_empty() {
            return true;
        }
        let frame = StreamEvent::Data(Bytes::from(body));
        match self.stream.as_ref().unwrap().tx.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(StreamEvent::Data(b))) => {
                self.body = Some(b.to_vec());
                false
            }
            Err(_) => {
                self.stream = None;
                false
            }
        }
    }

    /// 响应头是否已经发给客户端（`ngx.headers_sent`）
    pub fn headers_sent(&self) -> bool {
        self.stream.as_ref().is_some_and(|s| s.head_sent)
    }

    /// ngx.eof()：结束输出流。已发送响应头时立即推完剩余字节并结束流；
    /// 通道拥塞时保留 stream，交给脚本结束后的 drain_and_end_stream 补发。
    pub fn eof_stream(&mut self) {
        self.eof_sent = true;
        if self.stream.is_none() {
            return;
        }
        if self.flush_stream() {
            if let Some(sink) = &self.stream {
                let _ = sink.tx.try_send(StreamEvent::End);
            }
            self.stream = None;
        }
    }

    /// 脚本结束后的收尾：把通道满时退回缓冲的剩余字节 await 补发完，再发 End。
    /// 只有已经开始流式输出的请求会走到这里。
    pub async fn drain_and_end_stream(&mut self) {
        let Some(sink) = self.stream.take() else {
            return;
        };
        if let Some(body) = self.body.take() {
            for chunk in body.chunks(STREAM_AUTO_FLUSH_BYTES) {
                if sink
                    .tx
                    .send(StreamEvent::Data(Bytes::copy_from_slice(chunk)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        let _ = sink.tx.send(StreamEvent::End).await;
    }

    /// 定时器/后台任务用的游离上下文：不属于任何请求，ngx.say 等写入落到这里被丢弃
    /// （对标 OpenResty 的 fake request client）
    pub fn detached() -> RequestCtx {
        RequestCtx {
            method: "GET".to_string(),
            path: "@timer".to_string(),
            query: String::new(),
            uri: "@timer".to_string(),
            host: None,
            remote_addr: "0.0.0.0".to_string(),
            remote_port: 0,
            server_port: 0,
            req_headers: Vec::new(),
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
            scheme: "http".to_string(),
            internal_request: true,
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
            start_time: unix_now(),
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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// 语义上不带请求体的方法（转发时不给它们补 Content-Length）
    pub fn is_bodyless_method(&self) -> bool {
        matches!(self.method.as_str(), "GET" | "HEAD")
    }

    pub fn set_resp_header(&mut self, name: &str, value: &str) {
        let key = name.to_lowercase();
        self.resp_headers.retain(|(k, _)| k.to_lowercase() != key);
        self.resp_headers.push((key, value.to_string()));
    }

    pub fn say(&mut self, text: &str) {
        self.body
            .get_or_insert_with(Vec::new)
            .extend_from_slice(text.as_bytes());
    }
}

// ---------- nginx `map` 派生变量 ----------

/// 一个 `map` 分支。`literal=Some(s)` 为精确串匹配（含 `""` 空串）；
/// `literal=None` 时用预编译 `regex` 匹配源变量值。
#[derive(Debug, Clone)]
pub struct MapCase {
    pub literal: Option<String>,
    pub regex: Option<regex::Regex>,
    pub result: String,
}

/// 顶层 `map $source $dest { ... }`：`$dest` 的值由 `$source` 逐分支匹配得出。
#[derive(Debug, Clone)]
pub struct MapDef {
    /// 目标变量名（不含 `$`）
    pub dest: String,
    /// 源变量名（不含 `$`）
    pub source: String,
    /// 无分支命中时的默认值；`None` 表示默认空串
    pub default: Option<String>,
    pub cases: Vec<MapCase>,
}

/// map/geo/split 的派生定义按 Arc 存放：热路径每次解析变量时只克隆一个引用，
/// 不再把整张规则表（含编译好的正则）复制一遍。
static MAPS: std::sync::OnceLock<std::sync::RwLock<Vec<Arc<MapDef>>>> = std::sync::OnceLock::new();

fn map_store() -> &'static std::sync::RwLock<Vec<Arc<MapDef>>> {
    MAPS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// 由 Router::build 在每次（含热重载）构建路由表时调用，原子替换整张 map 表。
pub fn install_maps(defs: Vec<MapDef>) {
    *map_store().write().unwrap() = defs.into_iter().map(Arc::new).collect();
}

/// 当前时间（epoch 秒，含小数）。
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// nginx `$host` 是**不带端口**的请求主机名（要端口用 `$http_host` 或 `$server_port`）。
/// Host 头本身常带 `:port`，所以这里剥掉；IPv6 字面量取 `]` 之前的部分。
fn nginx_host_value(h: &str) -> String {
    if let Some(end) = h.rfind(']') {
        return h[..=end].to_string();
    }
    // 只剥"名字:十进制端口"，免得把无括号的 IPv6 字面量截成空串
    if let Some((name, port)) = h.split_once(':') {
        if !name.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return name.to_string();
        }
    }
    h.to_string()
}

/// 内置 nginx 变量读取（`$uri` / `$http_*` / `$sent_http_*` / `$status` 等）。
/// 这是 ngx.var 与 map 源解析共享的唯一事实源。
pub fn builtin_var(ctx: &RequestCtx, name: &str) -> Option<String> {
    if let Some(hdr) = name.strip_prefix("http_") {
        let want = hdr.replace('_', "-");
        return ctx
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&want))
            .map(|(_, v)| v.clone());
    }
    if let Some(hdr) = name.strip_prefix("sent_http_") {
        let want = hdr.replace('_', "-");
        return ctx
            .resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&want))
            .map(|(_, v)| v.clone());
    }
    if let Some(arg) = name.strip_prefix("arg_") {
        return query_arg(ctx, arg);
    }
    if let Some(cookie) = name.strip_prefix("cookie_") {
        return cookie_value(ctx, cookie);
    }
    match name {
        "remote_addr" => Some(ctx.remote_addr.clone()),
        // nginx 的 $binary_remote_addr 是 4/16 字节裸地址，只适合当键、不适合当头值。
        // 这里返回文本形式：作为 proxy_set_header 的值它本来就是这个用途，
        // 作为限流 key 的一部分，文本与裸字节的一一映射等价（见 limit::addr_var）。
        "binary_remote_addr" => Some(ctx.remote_addr.clone()),
        "remote_port" => Some(ctx.remote_port.to_string()),
        "server_port" => Some(ctx.server_port.to_string()),
        "scheme" => Some(ctx.scheme.clone()),
        "request_method" | "method" => Some(ctx.method.clone()),
        "request_uri" => Some(ctx.uri.clone()),
        "uri" => Some(ctx.effective_path().to_string()),
        "args" | "query_string" => Some(ctx.query.clone()),
        "is_args" => Some(if ctx.query.is_empty() {
            String::new()
        } else {
            "?".to_string()
        }),
        // $host 去端口（要原始头用 $http_host）；无 Host 头时沿用既有的 "unknown" 回落，
        // 让 Lua、add_header、cache key 三条路径共用同一个答案
        "host" => Some(
            ctx.host
                .as_deref()
                .map(nginx_host_value)
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        // 仅 SSL 握手阶段的 ctx 持有 SNI；普通请求未把连接的 SNI 带进 ctx（返回空）
        "ssl_server_name" => ctx.ssl.as_ref().and_then(|s| s.server_name.clone()),
        "status" => Some(ctx.status.to_string()),
        "body_bytes_sent" => Some(ctx.body.as_ref().map(|b| b.len()).unwrap_or(0).to_string()),
        "content_type" => ctx
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone()),
        "request_length" => Some(
            (ctx.uri.len()
                + ctx
                    .req_headers
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 4)
                    .sum::<usize>())
            .to_string(),
        ),
        "content_length" => ctx
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.clone()),
        "request_body" => Some(String::from_utf8_lossy(&ctx.req_body).into_owned()),
        "request_time" => Some(format!("{:.3}", (unix_now() - ctx.start_time).max(0.0))),
        "msec" => Some(format!("{:.3}", unix_now())),
        "time_local" => Some(
            chrono::Local::now()
                .format("%d/%b/%Y:%H:%M:%S %z")
                .to_string(),
        ),
        "time_iso8601" => Some(
            chrono::Local::now()
                .format("%Y-%m-%dT%H:%M:%S%:z")
                .to_string(),
        ),
        "https" => Some(
            if ctx.scheme.eq_ignore_ascii_case("https") {
                "on"
            } else {
                ""
            }
            .to_string(),
        ),
        "server_addr" => ctx.listener.map(|a| a.ip().to_string()),
        "proxy_add_x_forwarded_for" => Some(match ctx.header("x-forwarded-for") {
            Some(prior) if !prior.trim().is_empty() => format!("{prior}, {}", ctx.remote_addr),
            _ => ctx.remote_addr.clone(),
        }),
        "hostname" => std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .ok(),
        "upstream_addr" => Some(ctx.upstream_addr.clone()),
        "upstream_status" => Some(ctx.upstream_status.to_string()),
        "upstream_header_time" | "upstream_response_time" => {
            Some(format!("{:.3}", ctx.upstream_header_time))
        }
        "upstream_cache_status" => Some(ctx.cache_status.clone()),
        "still_online" => Some(ctx.still_online.clone()),
        "proxy_split" => Some(ctx.proxy_split.clone()),
        "proxy_split_served" => Some(ctx.proxy_split_served.clone()),
        "front_proxy" => Some(ctx.front_proxy.clone()),
        "front_proxy_country" => Some(ctx.front_proxy_country.clone()),
        "front_proxy_host" => Some(ctx.front_proxy_host.clone()),
        "front_proxy_verified" => Some(if ctx.front_proxy_verified {
            "1".to_string()
        } else {
            String::new()
        }),
        "realip_remote_addr" => Some(ctx.realip_remote_addr.clone()),
        _ => None,
    }
}

/// `builtin_var` 里能匹配到的固定变量名（不含 `http_`/`arg_` 这类前缀派生名）。
/// 供变量展开判断"这个名字 nginx 认不认识"用；新增 builtin 变量时必须同步这里，
/// `static_var_names_are_known` 单测会把每个名字拿去实际解析做交叉检查。
const STATIC_VAR_NAMES: &[&str] = &[
    "remote_addr",
    "binary_remote_addr",
    "remote_port",
    "server_port",
    "server_addr",
    "scheme",
    "request_method",
    "method",
    "request_uri",
    "uri",
    "args",
    "query_string",
    "is_args",
    "host",
    "ssl_server_name",
    "status",
    "body_bytes_sent",
    "content_type",
    "content_length",
    "request_length",
    "request_body",
    "request_time",
    "msec",
    "time_local",
    "time_iso8601",
    "https",
    "hostname",
    "proxy_add_x_forwarded_for",
    "upstream_addr",
    "upstream_status",
    "upstream_header_time",
    "upstream_response_time",
    "upstream_cache_status",
    "still_online",
    "proxy_split",
    "proxy_split_served",
    "front_proxy",
    "front_proxy_country",
    "front_proxy_host",
    "front_proxy_verified",
    "realip_remote_addr",
];

/// 名字是不是 nginx 的前缀派生变量（`$http_x`/`$arg_x`/`$cookie_x`/`$sent_http_x`/
/// `$upstream_http_x`/`$upstream_cookie_x`）：这类变量"没有值"是正常状态，展开为空串。
pub fn is_derived_var_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "http_",
        "sent_http_",
        "arg_",
        "cookie_",
        "upstream_http_",
        "upstream_cookie_",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// 名字是不是 nginx 认识的固定变量（值可能取不到，但名字本身合法）。
pub fn is_static_var_name(name: &str) -> bool {
    STATIC_VAR_NAMES.contains(&name)
}

/// 从 query 串里取一个参数（百分号解码，`+` 视为空格）；重复参数取第一个。
fn query_arg(ctx: &RequestCtx, name: &str) -> Option<String> {
    ctx.query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

/// 从 Cookie 请求头里取一个 cookie 值（键名大小写敏感，与 nginx `$cookie_<name>` 一致）。
fn cookie_value(ctx: &RequestCtx, name: &str) -> Option<String> {
    let raw = ctx.header("cookie")?;
    raw.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then(|| v.trim().to_string())
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解析变量 `$name`：优先内置 map 目标，其次 geo 目标，最后内置变量表。
/// map/geo 的源变量可再次经本函数递归解析（`depth` 防环）。`None` 表示未定义。
pub fn resolve_var(ctx: &RequestCtx, name: &str, depth: u8) -> Option<String> {
    if depth > 8 {
        return None;
    }
    // `set $x ...;` 写的请求级变量优先：后写覆盖先写，且它不该被同名 map 顶掉
    if let Some((_, v)) = ctx.set_vars.iter().rev().find(|(k, _)| k == name) {
        return Some(v.clone());
    }
    let def = {
        let store = map_store().read().unwrap();
        store.iter().find(|d| d.dest == name).cloned()
    };
    if let Some(def) = def {
        let src = builtin_var(ctx, &def.source)
            .or_else(|| resolve_var(ctx, &def.source, depth + 1))
            .unwrap_or_default();
        return Some(match_map(&def, &src));
    }
    if let Some(g) = resolve_geo(ctx, name, depth) {
        return Some(g);
    }
    if let Some(s) = resolve_split(ctx, name, depth) {
        return Some(s);
    }
    if let Some(c) = resolve_canary(ctx, name, depth) {
        return Some(c);
    }
    builtin_var(ctx, name)
}

/// 纯匹配：给定已解析的源值，按 nginx 语义返回目标值（先全部精确匹配，再按序试正则，
/// 最后 default）。与全局 map 表解耦，便于单测。
pub fn match_map(def: &MapDef, src: &str) -> String {
    for c in &def.cases {
        if let Some(lit) = &c.literal {
            if lit == src {
                return c.result.clone();
            }
        }
    }
    for c in &def.cases {
        if c.literal.is_none() {
            if let Some(re) = &c.regex {
                if let Some(caps) = re.captures(src) {
                    // 结果里的 $0..$9 / ${name} 引用捕获组（对齐 ngx map）
                    return expand_map_result(&c.result, re, &caps);
                }
            }
        }
    }
    def.default.clone().unwrap_or_default()
}

/// 把 map 结果串里的 `$0`..`$9`、`${name}` 替换为对应捕获组；未命中的组替换为空串。
/// `$$` 不是 nginx 语法，这里不特殊处理。
fn expand_map_result(result: &str, re: &regex::Regex, caps: &regex::Captures) -> String {
    if !result.contains('$') {
        return result.to_string();
    }
    let bytes = result.as_bytes();
    let mut out = String::with_capacity(result.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            let ch = result[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let rest = &result[i + 1..];
        // ${name}
        if let Some(after_brace) = rest.strip_prefix('{') {
            if let Some(end) = after_brace.find('}') {
                let name = &after_brace[..end];
                let val = re
                    .capture_names()
                    .zip(caps.iter())
                    .find(|(n, _)| n.as_deref() == Some(name))
                    .and_then(|(_, m)| m)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                out.push_str(&val);
                i += 2 + end + 1;
                continue;
            }
        }
        // $0..$9
        let digit_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_len > 0 {
            let idx: usize = rest[..digit_len].parse().unwrap_or(0);
            let val = caps
                .get(idx)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            out.push_str(&val);
            i += 1 + digit_len;
        } else {
            out.push('$');
            i += 1;
        }
    }
    out
}

/// 便捷入口：顶层变量解析（depth=0）。
pub fn resolve_variable(ctx: &RequestCtx, name: &str) -> Option<String> {
    resolve_var(ctx, name, 0)
}

// ---------- nginx `geo` 派生变量（按客户端 IP 最长前缀匹配） ----------

/// 一条 geo 网络规则：`ip/prefix`（v4 前缀≤32、v6≤128；省略 `/` 时 v4=/32、v6=/128）。
#[derive(Debug, Clone)]
pub struct GeoRule {
    pub ip: std::net::IpAddr,
    pub prefix: u8,
    pub result: String,
}

/// 顶层 `geo [$source] $dest { ... }`：`$dest` 由源变量里的 IP 做最长前缀匹配得出。
/// 缺省源为 `$remote_addr`。构建时规则按前缀长度降序排列，首个命中即最具体匹配。
#[derive(Debug, Clone)]
pub struct GeoDef {
    pub dest: String,
    pub source: String,
    pub default: Option<String>,
    pub rules: Vec<GeoRule>,
}

static GEOS: std::sync::OnceLock<std::sync::RwLock<Vec<Arc<GeoDef>>>> = std::sync::OnceLock::new();

fn geo_store() -> &'static std::sync::RwLock<Vec<Arc<GeoDef>>> {
    GEOS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// 由 Router::build 在每次构建路由表时原子替换（与 map 一样热重载安全）。
pub fn install_geos(defs: Vec<GeoDef>) {
    *geo_store().write().unwrap() = defs.into_iter().map(Arc::new).collect();
}

/// `target` 是否落在 `rule` 的网络内。族不同直接判否（v4 目标只匹配 v4 规则，反之亦然）。
pub fn geo_rule_matches(target: &std::net::IpAddr, rule: &GeoRule) -> bool {
    match (target, &rule.ip) {
        (std::net::IpAddr::V4(t), std::net::IpAddr::V4(r)) => {
            let (tv, rv) = (u32::from(*t), u32::from(*r));
            let p = rule.prefix.min(32);
            let mask = if p == 0 { 0 } else { !0u32 << (32 - p) };
            (tv & mask) == (rv & mask)
        }
        (std::net::IpAddr::V6(t), std::net::IpAddr::V6(r)) => {
            let (tv, rv) = (u128::from(*t), u128::from(*r));
            let p = rule.prefix.min(128);
            let mask = if p == 0 { 0u128 } else { !0u128 << (128 - p) };
            (tv & mask) == (rv & mask)
        }
        _ => false,
    }
}

/// 纯匹配：给定已解析的源 IP，按（已排序的）规则返回首个命中的结果，否则 default。
pub fn match_geo(def: &GeoDef, ip: &std::net::IpAddr) -> String {
    for r in &def.rules {
        if geo_rule_matches(ip, r) {
            return r.result.clone();
        }
    }
    def.default.clone().unwrap_or_default()
}

/// 解析变量 `$name`（geo 版）：若 name 是某个 geo 的目标，则读源变量、解析成 IP、
/// 最长前缀匹配；否则返回 None（交由 map / 内置变量处理）。
fn resolve_geo(ctx: &RequestCtx, name: &str, depth: u8) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let def = {
        let store = geo_store().read().unwrap();
        store.iter().find(|d| d.dest == name).cloned()
    };
    let def = def?;
    let src_raw = builtin_var(ctx, &def.source)
        .or_else(|| resolve_var(ctx, &def.source, depth + 1))
        .unwrap_or_default();
    let ip = src_raw.trim().parse::<std::net::IpAddr>().ok()?;
    Some(match_geo(&def, &ip))
}

// ---------- nginx `split_clients` 派生变量（按键模板哈希做加权分流） ----------

/// 一个加权分桶：`percent` 为百分比权重（可含小数，如 0.5 表示 0.5%）。
#[derive(Debug, Clone)]
pub struct SplitBucket {
    pub percent: f64,
    pub result: String,
}

/// 顶层 `split_clients <key_template> $dest { ... }`：`$dest` 由 `<key_template>`
/// 插值后经 MurmurHash2 取模落桶决定；`*` 桶承接剩余百分比。
#[derive(Debug, Clone)]
pub struct SplitDef {
    pub dest: String,
    /// 键模板，如 `"${remote_addr}${http_user_agent}"`（含变量引用，运行时插值）
    pub key: String,
    /// 显式百分比桶（按声明顺序累加）
    pub buckets: Vec<SplitBucket>,
    /// `*` 兜底桶结果；`None` 表示无兜底，落空返回空串
    pub star: Option<String>,
}

static SPLITS: std::sync::OnceLock<std::sync::RwLock<Vec<Arc<SplitDef>>>> =
    std::sync::OnceLock::new();

fn split_store() -> &'static std::sync::RwLock<Vec<Arc<SplitDef>>> {
    SPLITS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// 由 Router::build 在每次构建路由表时原子替换（与 map/geo 一样热重载安全）。
pub fn install_splits(defs: Vec<SplitDef>) {
    *split_store().write().unwrap() = defs.into_iter().map(Arc::new).collect();
}

/// nginx `ngx_murmur_hash2` 的等价实现（32 位，MurmurHash2，小端读入）。
/// 纯函数，便于单测比对已知向量。
pub fn murmur_hash2(data: &[u8]) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let len = data.len();
    let mut h: u32 = (len as u32) ^ 0x9dc0_3ac8;
    let mut i = 0;
    while i + 4 <= len {
        let mut k = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M);
        h ^= k;
        i += 4;
    }
    match len - i {
        3 => {
            h ^= (data[i + 2] as u32) << 16;
            h ^= (data[i + 1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        2 => {
            h ^= (data[i + 1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        1 => {
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        _ => {}
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

/// 由键字符串得到落在 `[0, 10000)` 的桶坐标（百分数 × 100，支持两位小数权重）。
pub fn split_id(key: &str) -> u32 {
    murmur_hash2(key.as_bytes()) % 10000
}

/// 纯落桶：按声明顺序累加权重（换算到 id 单位），首个 `id < 累计上界` 命中；
/// 都不中则返回 `*` 兜底，无兜底返回空串。与全局表解耦，便于单测。
pub fn pick_split_bucket(def: &SplitDef, id: u32) -> String {
    let mut sum: f64 = 0.0;
    for b in &def.buckets {
        sum += b.percent * 100.0;
        if (id as f64) < sum {
            return b.result.clone();
        }
    }
    def.star.clone().unwrap_or_default()
}

/// 展开键模板里的变量引用：`${name}` 与 `$name` 两种形式；未定义变量按空串处理。
fn expand_split_key(ctx: &RequestCtx, template: &str, depth: u8) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            let ch = template[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let rest = &template[i + 1..];
        // ${name}
        if let Some(after_brace) = rest.strip_prefix('{') {
            if let Some(end) = after_brace.find('}') {
                let name = &after_brace[..end];
                let val = resolve_var(ctx, name, depth).unwrap_or_default();
                out.push_str(&val);
                i += 2 + end + 1;
                continue;
            }
        }
        // $name：变量名为 [A-Za-z0-9_] 序列
        let name_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        if name_len > 0 {
            let val = resolve_var(ctx, &rest[..name_len], depth).unwrap_or_default();
            out.push_str(&val);
            i += 1 + name_len;
        } else {
            out.push('$');
            i += 1;
        }
    }
    out
}

/// 解析变量 `$name`（split_clients 版）：若 name 是某个 split 的目标，则插值键模板、
/// 取哈希落桶；否则返回 None（交由内置变量处理）。
fn resolve_split(ctx: &RequestCtx, name: &str, depth: u8) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let def = {
        let store = split_store().read().unwrap();
        store.iter().find(|d| d.dest == name).cloned()
    };
    let def = def?;
    let key = expand_split_key(ctx, &def.key, depth + 1);
    let id = split_id(&key);
    Some(pick_split_bucket(&def, id))
}

/// 按目标变量名查 split 定义（构建路由表时用来把 `proxy_pass http://$x` 接到比例上）。
/// 必须在 `install_splits` 之后调用，否则看到的是上一份配置。
pub fn split_def(dest: &str) -> Option<Arc<SplitDef>> {
    split_store()
        .read()
        .unwrap()
        .iter()
        .find(|d| d.dest == dest)
        .cloned()
}

/// 配置里每一条 split_clients 写过的落点值（每一路 + `*`），供路由表构建"能列出来的落点"集合。
pub fn split_branch_values() -> Vec<String> {
    let store = split_store().read().unwrap();
    let mut out = Vec::new();
    for d in store.iter() {
        out.extend(d.buckets.iter().map(|b| b.result.clone()));
        out.extend(d.star.clone());
    }
    out
}

// ---------- 灰度发布（canary）：按请求特征选择版本 ----------

/// 一条灰度条件。全部来自请求本身（Cookie / Header / query / User-Agent / OS），
/// 不回源、不写请求，只决定 `$canary` 展开成哪个版本。
#[derive(Debug, Clone)]
pub enum CanaryWhen {
    /// `cookie <name> <target>`（存在且非空）或 `cookie <name>=<value> <target>`（精确）
    Cookie { name: String, value: Option<String> },
    /// `header <name> ...`，头名大小写不敏感
    Header { name: String, value: Option<String> },
    /// `arg <name> ...`，query 参数名大小写敏感（与 `$arg_*` 一致）
    Arg { name: String, value: Option<String> },
    /// `ua ~ <re> <target>` / `ua ~* <re> <target>`
    UserAgent {
        regex: regex::Regex,
        pattern: String,
        case_insensitive: bool,
    },
    /// `os windows|macos|linux|android|ios|other <target>`
    Os(CanaryOs),
}

/// 灰度规则认的操作系统族。识别顺序在 [`detect_os`] 里固定：iOS 先于 macOS、
/// Android 先于 Linux —— 这两组 UA 都同时含有后者的标记，顺序错了会把 iPhone
/// 判成 Mac、把 Android 判成 Linux。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryOs {
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
    Other,
}

impl CanaryOs {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" => Some(CanaryOs::Windows),
            "macos" | "mac" | "osx" | "macosx" => Some(CanaryOs::Macos),
            "linux" => Some(CanaryOs::Linux),
            "android" => Some(CanaryOs::Android),
            "ios" | "iphone" | "ipad" => Some(CanaryOs::Ios),
            "other" | "unknown" => Some(CanaryOs::Other),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CanaryOs::Windows => "windows",
            CanaryOs::Macos => "macos",
            CanaryOs::Linux => "linux",
            CanaryOs::Android => "android",
            CanaryOs::Ios => "ios",
            CanaryOs::Other => "other",
        }
    }
}

/// 从 User-Agent 判操作系统族。标记顺序即语义的一部分（见 [`CanaryOs`]）。
pub fn detect_os(ua: &str) -> CanaryOs {
    let ua = ua.to_ascii_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        CanaryOs::Ios
    } else if ua.contains("android") {
        CanaryOs::Android
    } else if ua.contains("windows") {
        CanaryOs::Windows
    } else if ua.contains("macintosh") || ua.contains("mac os x") {
        CanaryOs::Macos
    } else if ua.contains("linux") || ua.contains("cros") {
        CanaryOs::Linux
    } else {
        CanaryOs::Other
    }
}

fn ua_of<'a>(ctx: &'a RequestCtx) -> &'a str {
    ctx.header("user-agent").unwrap_or("")
}

/// 条件值匹配：`want=None` 表示"存在且非空"，`Some(v)` 表示精确相等。
/// 空值不算"存在"——`Cookie: release=` 是浏览器清掉标记后的常见残留，
/// 把它当成灰度命中会让用户永远回不到默认版本。
fn canary_value_matches(actual: Option<String>, want: &Option<String>) -> bool {
    match (actual, want) {
        (None, _) => false,
        (Some(v), None) => !v.is_empty(),
        (Some(v), Some(w)) => v == *w,
    }
}

impl CanaryWhen {
    pub fn matches(&self, ctx: &RequestCtx) -> bool {
        match self {
            CanaryWhen::Cookie { name, value } => {
                canary_value_matches(cookie_value(ctx, name), value)
            }
            CanaryWhen::Header { name, value } => {
                canary_value_matches(ctx.header(name).map(str::to_string), value)
            }
            CanaryWhen::Arg { name, value } => canary_value_matches(query_arg(ctx, name), value),
            CanaryWhen::UserAgent { regex, .. } => regex.is_match(ua_of(ctx)),
            CanaryWhen::Os(os) => detect_os(ua_of(ctx)) == *os,
        }
    }

    /// `-t` / 启动横幅里的条件自述；与配置写法尽量同形，运维一眼能对上。
    pub fn label(&self) -> String {
        match self {
            CanaryWhen::Cookie { name, value } => match value {
                Some(v) => format!("cookie {name}={v}"),
                None => format!("cookie {name}"),
            },
            CanaryWhen::Header { name, value } => match value {
                Some(v) => format!("header {name}={v}"),
                None => format!("header {name}"),
            },
            CanaryWhen::Arg { name, value } => match value {
                Some(v) => format!("arg {name}={v}"),
                None => format!("arg {name}"),
            },
            CanaryWhen::UserAgent {
                pattern,
                case_insensitive,
                ..
            } => format!(
                "ua {} {pattern}",
                if *case_insensitive { "~*" } else { "~" }
            ),
            CanaryWhen::Os(os) => format!("os {}", os.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CanaryRule {
    pub when: CanaryWhen,
    pub target: String,
}

/// 顶层 `canary $dest [key] { ... }`：按声明顺序取第一条命中的规则；
/// 都不命中时用 `percent` 对粘性键做哈希分桶；最后落到 `default`。
#[derive(Debug, Clone)]
pub struct CanaryDef {
    pub dest: String,
    pub rules: Vec<CanaryRule>,
    pub buckets: Vec<SplitBucket>,
    /// 百分比档的粘性键模板（缺省 `${remote_addr}`）
    pub key: String,
    /// 必填：没有任何条件/百分比命中时的版本，也是灰度回退的终点
    pub default: String,
}

impl CanaryDef {
    /// `-t` / 启动横幅里的一行规则自述（不含 location）。
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .rules
            .iter()
            .map(|r| format!("{}→{}", r.when.label(), r.target))
            .collect();
        parts.extend(
            self.buckets
                .iter()
                .map(|b| format!("{}%→{}", trim_percent(b.percent), b.result)),
        );
        parts.push(format!("default→{}", self.default));
        format!("[{}]", parts.join(" "))
    }
}

fn trim_percent(p: f64) -> String {
    let s = format!("{p:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

static CANARIES: std::sync::OnceLock<std::sync::RwLock<Vec<Arc<CanaryDef>>>> =
    std::sync::OnceLock::new();
/// 没配 canary 时（绝大多数部署）让 `resolve_var` 只付一次原子读，
/// 不读锁、不扫表 —— 变量解析在每请求热路径上被调用很多次。
static CANARY_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn canary_store() -> &'static std::sync::RwLock<Vec<Arc<CanaryDef>>> {
    CANARIES.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// 由 Router::build 在每次构建路由表时原子替换（与 map/geo/split 一样热重载安全）。
pub fn install_canaries(defs: Vec<CanaryDef>) {
    CANARY_ACTIVE.store(!defs.is_empty(), std::sync::atomic::Ordering::Release);
    *canary_store().write().unwrap() = defs.into_iter().map(Arc::new).collect();
}

/// 按目标变量名查灰度定义（构建路由表时用来把 `proxy_pass http://$x` 接上候选表）。
pub fn canary_def(dest: &str) -> Option<Arc<CanaryDef>> {
    if !CANARY_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    canary_store()
        .read()
        .unwrap()
        .iter()
        .find(|d| d.dest == dest)
        .cloned()
}

/// 配置里每一条 canary 写过的版本值（规则 + 百分比 + default），
/// 供路由表构建"能列出来的落点"集合（与 `split_branch_values` 同责）。
pub fn canary_target_values() -> Vec<String> {
    if !CANARY_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return Vec::new();
    }
    let store = canary_store().read().unwrap();
    let mut out = Vec::new();
    for d in store.iter() {
        out.extend(d.rules.iter().map(|r| r.target.clone()));
        out.extend(d.buckets.iter().map(|b| b.result.clone()));
        out.push(d.default.clone());
    }
    out
}

fn resolve_canary(ctx: &RequestCtx, name: &str, depth: u8) -> Option<String> {
    let def = canary_def(name)?;
    Some(match_canary(&def, ctx, depth + 1))
}

/// 纯规则求值：条件按声明顺序第一条命中；否则百分比哈希分桶；最后 default。
/// 与全局表解耦，便于单测直接喂任意规则组合（并发单测里全局表会被互相覆盖）。
fn match_canary(def: &CanaryDef, ctx: &RequestCtx, depth: u8) -> String {
    for r in &def.rules {
        if r.when.matches(ctx) {
            return r.target.clone();
        }
    }
    if !def.buckets.is_empty() {
        let key = expand_split_key(ctx, &def.key, depth);
        let id = split_id(&key);
        let mut sum = 0.0;
        for b in &def.buckets {
            sum += b.percent * 100.0;
            if (id as f64) < sum {
                return b.result.clone();
            }
        }
    }
    def.default.clone()
}

// ---------- 分流落点统计（split_clients 的结果被 proxy_pass 当路由目标时） ----------

/// 一次分流请求的四种结局之一。基数因此有上界，不会随流量长成无界标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitRole {
    /// 本意那一路当时有可选节点，请求交给了它（记在解析出落点的那一刻，
    /// 不代表后端返回了 2xx —— 成败归 proxy_next_upstream 与访问日志管）
    Routed,
    /// 本意那一路没人可服务，按 `proxy_split_failover` 改投到了别的分支
    Bled,
    /// 某个分支被选中时**整池没有可选节点**（摘除期、主动探测判死、`down`、并发额度打满；
    /// 按候选尝试计数，可以大于请求数）
    Down,
    /// 落桶结果是空串（分桶值写了空串或没有 `*` 兜底）
    Empty,
}

impl SplitRole {
    pub const ALL: [SplitRole; 4] = [
        SplitRole::Routed,
        SplitRole::Bled,
        SplitRole::Down,
        SplitRole::Empty,
    ];
    pub fn label(self) -> &'static str {
        match self {
            SplitRole::Routed => "routed",
            SplitRole::Bled => "bled",
            SplitRole::Down => "down",
            SplitRole::Empty => "empty",
        }
    }
    fn idx(self) -> usize {
        self as usize
    }
}

/// 一个 split 变量（按目标变量名归属）的分流账本。
///
/// 刻意挂在**进程级注册表**上而不是路由表上：路由表每次热重载都整份重建，
/// 账本若跟着重建，运维在发布窗口里看到的曲线就会莫名归零。名字相同的
/// 第二次注册返回同一个 `Arc`，因此重载不丢历史。
#[derive(Debug)]
pub struct SplitRouteStats {
    pub dest: String,
    /// 声明顺序的分支值，供指标与 `-t` 打印
    pub branches: Vec<String>,
    index: HashMap<String, usize>,
    served: Vec<AtomicU64>,
    roles: [AtomicU64; 4],
}

impl SplitRouteStats {
    fn new(dest: &str, branches: &[String]) -> Self {
        let index = branches
            .iter()
            .enumerate()
            .map(|(i, b)| (b.clone(), i))
            .collect();
        SplitRouteStats {
            dest: dest.to_string(),
            branches: branches.to_vec(),
            index,
            served: branches.iter().map(|_| AtomicU64::new(0)).collect(),
            roles: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// 请求被交给这一路的计数（在解析出落点时记账，不看后端成败）
    pub fn note_served(&self, branch: &str) {
        if let Some(&i) = self.index.get(branch) {
            self.served[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn note(&self, role: SplitRole) {
        self.roles[role.idx()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn role(&self, role: SplitRole) -> u64 {
        self.roles[role.idx()].load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn served(&self, branch: &str) -> u64 {
        self.index
            .get(branch)
            .map(|&i| self.served[i].load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }
}

static SPLIT_STATS: std::sync::OnceLock<std::sync::RwLock<HashMap<String, Arc<SplitRouteStats>>>> =
    std::sync::OnceLock::new();

/// 登记上限：分流条目来自配置文件本身，这个数只是防止有人把它写成无界表。
const MAX_SPLIT_ROUTES: usize = 64;
/// 单个 split 的分支上限，同上。
const MAX_SPLIT_BRANCHES: usize = 64;

fn split_stats_store() -> &'static std::sync::RwLock<HashMap<String, Arc<SplitRouteStats>>> {
    SPLIT_STATS.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// 构建路由表时登记一条分流（幂等：同名返回既有账本）。
/// 超限或分支为空时返回 None —— 分流照走，只是不再计数，并告警一次。
pub fn register_split_route(dest: &str, branches: &[String]) -> Option<Arc<SplitRouteStats>> {
    let mut store = split_stats_store().write().unwrap();
    if let Some(existing) = store.get(dest) {
        return Some(existing.clone());
    }
    if branches.len() > MAX_SPLIT_BRANCHES {
        log_warn!(
            "split_clients {dest} 分支数 {} 超过登记上限 {}，本次不再统计落点比例",
            branches.len(),
            MAX_SPLIT_BRANCHES
        );
        return None;
    }
    if store.len() >= MAX_SPLIT_ROUTES {
        log_warn!(
            "分流账本已满（{} 条），split_clients {dest} 不再统计落点比例",
            MAX_SPLIT_ROUTES
        );
        return None;
    }
    let stats = Arc::new(SplitRouteStats::new(dest, branches));
    store.insert(dest.to_string(), Arc::clone(&stats));
    Some(stats)
}

/// 指标渲染与 E2E 读取用：按名字排序的完整快照。
pub fn split_stats_snapshot() -> Vec<Arc<SplitRouteStats>> {
    let mut v: Vec<_> = split_stats_store()
        .read()
        .unwrap()
        .iter()
        .map(|(_, s)| Arc::clone(s))
        .collect();
    v.sort_by(|a, b| a.dest.cmp(&b.dest));
    v
}

// ---------- nginx `sub_filter`（响应体文本替换输出过滤器） ----------

/// 一条 sub_filter 匹配目标：字面串或（不）区分大小写的正则。
#[derive(Debug, Clone)]
pub enum SubPattern {
    Literal(String),
    Regex(regex::Regex),
}

/// `sub_filter <match> <replacement>;` 一条规则。替换串中的 `&` 代表本次匹配到的原文，
/// `\&`/`\\` 为转义（对齐 ngx_http_sub_filter_module 的转义语义）。
#[derive(Debug, Clone)]
pub struct SubFilter {
    pub pattern: SubPattern,
    pub replacement: String,
}

/// location 级 sub_filter 配置：规则 + 是否只替换首个（默认 true）+ 生效的响应类型。
#[derive(Debug, Clone)]
pub struct SubFilterConf {
    pub filters: Vec<SubFilter>,
    pub once: bool,
    /// 生效 MIME 列表（默认 `["text/html"]`）；含 `*`/`all` 表示对任意类型生效。
    pub types: Vec<String>,
}

/// 响应 Content-Type 是否落在 sub_filter_types 内（取 `;` 前的 MIME，大小写不敏感，
/// 支持 `text/*` 通配子类型）。
pub fn sub_filter_applies(content_type: Option<&str>, types: &[String]) -> bool {
    if types
        .iter()
        .any(|t| t == "*" || t.eq_ignore_ascii_case("all"))
    {
        return true;
    }
    let ct = match content_type {
        Some(c) => c,
        None => return false,
    };
    let mime = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    types.iter().any(|t| {
        let tl = t.to_ascii_lowercase();
        match tl.split_once('/') {
            Some((base, "*")) => mime
                .split_once('/')
                .map(|(b, _)| b == base)
                .unwrap_or(false),
            _ => tl == mime,
        }
    })
}

/// 把替换模板里的 `&`（本次匹配原文）与反斜杠转义展开成实际写入内容。
fn expand_sub_replacement(template: &str, matched: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n) => out.push(n),
                None => out.push('\\'),
            }
        } else if c == '&' {
            out.push_str(matched);
        } else {
            out.push(c);
        }
    }
    out
}

/// 字面串替换：命中即写入替换串并从匹配之后继续（不会重扫替换结果），`once` 时只替换第一处。
fn replace_sub_literal(body: &str, needle: &str, repl: &str, once: bool) -> String {
    if needle.is_empty() {
        return body.to_string();
    }
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        match rest.find(needle) {
            Some(pos) => {
                out.push_str(&rest[..pos]);
                out.push_str(&expand_sub_replacement(
                    repl,
                    &rest[pos..pos + needle.len()],
                ));
                rest = &rest[pos + needle.len()..];
                if once {
                    out.push_str(rest);
                    break;
                }
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// 正则替换：逐个非重叠匹配替换（同样展开 `&`），`once` 时只替换第一处。
fn replace_sub_regex(body: &str, re: &regex::Regex, repl: &str, once: bool) -> String {
    let mut out = String::with_capacity(body.len());
    let mut last = 0;
    for m in re.find_iter(body) {
        out.push_str(&body[last..m.start()]);
        out.push_str(&expand_sub_replacement(repl, m.as_str()));
        last = m.end();
        if once {
            break;
        }
    }
    out.push_str(&body[last..]);
    out
}

/// 单条规则应用到整串。
fn apply_one_sub(body: &str, f: &SubFilter, once: bool) -> String {
    match &f.pattern {
        SubPattern::Literal(n) => replace_sub_literal(body, n, &f.replacement, once),
        SubPattern::Regex(re) => replace_sub_regex(body, re, &f.replacement, once),
    }
}

/// 输出过滤器主入口：按声明顺序依次对响应体应用每条规则（前一条的结果作为后一条输入）。
/// 仅在 `conf` 有规则且响应类型命中 `types` 时改写；非 UTF-8 体（二进制）原样返回。
/// 返回新字节（内容长度由调用方按新体重算 Content-Length）。
pub fn apply_sub_filter(
    conf: Option<&SubFilterConf>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Vec<u8> {
    let conf = match conf {
        Some(c) if !c.filters.is_empty() => c,
        _ => return body,
    };
    if !sub_filter_applies(content_type, &conf.types) {
        return body;
    }
    let text = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return body,
    };
    let mut cur = text.to_string();
    for f in &conf.filters {
        cur = apply_one_sub(&cur, f, conf.once);
    }
    cur.into_bytes()
}

/// 从 `(name,value)` 响应头切片里取 content-type（大小写不敏感）。
pub fn header_lookup_content_type(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
}

// ---------- rewrite / return ----------

#[derive(Debug, Clone)]
pub enum RewriteFlag {
    /// 重新匹配 location
    Last,
    /// 停在本 location，继续后续处理
    Break,
    /// 302 外部重定向
    Redirect,
    /// 301 外部重定向
    Permanent,
}

#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub pattern: regex::Regex,
    pub replacement: String,
    pub flag: RewriteFlag,
}

/// REWRITE 阶段的一条步骤。nginx 把 `rewrite`/`set`/`if` 都排在 rewrite 阶段，
/// **按配置书写顺序**执行，所以这里是一个有序的枚举列表而不是三张表。
#[derive(Debug, Clone)]
pub enum RewriteStep {
    /// `rewrite regex replacement [flag];`
    Rewrite(RewriteRule),
    /// `set $name value;`：value 做一次变量展开后写入请求级变量
    Set { name: String, value: String },
    /// `if (cond) { return ...; }`：命中时记下 return 并停止后续步骤，实际执行在 ACCESS 之后
    Return(ReturnAction),
    /// `if (cond) { ... }`：条件成立才依次执行内层步骤（内层允许 rewrite/set/return）
    If {
        cond: IfCond,
        then: Vec<RewriteStep>,
    },
}

/// `if` 的条件：左值一定是变量（nginx 的语法要求），右值是字面量或变量模板。
#[derive(Debug, Clone)]
pub struct IfCond {
    pub lhs: String,
    pub op: CondOp,
    /// 仅 `=`/`!=` 使用；其余比较为 None。
    pub rhs: Option<String>,
}

/// nginx `if` 支持的比较。文件类测试（`-f`/`-d`/`-e`…）不在此列，解析期就告警拒绝。
#[derive(Debug, Clone)]
pub enum CondOp {
    /// 非空即真（`if ($x)`）
    NonEmpty,
    /// 空即真（`if (!$x)`）
    Empty,
    Eq,
    Ne,
    /// `~`：区分大小写的部分匹配
    Regex(regex::Regex),
    /// `~*`：忽略大小写的部分匹配
    IRegex(regex::Regex),
    NotRegex(regex::Regex),
    NotIRegex(regex::Regex),
}

/// `if` 条件求值。注意与 `proxy_cache_bypass` 那类谓词不同：nginx 的 `if` 只看"空/非空"，
/// 字符串 "0" 在这里算真。
pub fn eval_if_cond(cond: &IfCond, ctx: &RequestCtx) -> bool {
    let lhs = crate::proxy::interpolate_vars(&cond.lhs, ctx);
    match &cond.op {
        CondOp::NonEmpty => !lhs.is_empty(),
        CondOp::Empty => lhs.is_empty(),
        CondOp::Eq => cond_rhs(cond, ctx).is_some_and(|r| lhs == r),
        CondOp::Ne => cond_rhs(cond, ctx).map_or(true, |r| lhs != r),
        CondOp::Regex(re) | CondOp::NotRegex(re) => {
            re.is_match(&lhs) != matches!(&cond.op, CondOp::NotRegex(_))
        }
        CondOp::IRegex(re) | CondOp::NotIRegex(re) => {
            re.is_match(&lhs) != matches!(&cond.op, CondOp::NotIRegex(_))
        }
    }
}

fn cond_rhs(cond: &IfCond, ctx: &RequestCtx) -> Option<String> {
    cond.rhs
        .as_deref()
        .map(|r| crate::proxy::interpolate_vars(r, ctx))
}

/// return 指令：状态码 + 可选文本/URL
#[derive(Debug, Clone)]
pub struct ReturnAction {
    pub code: u16,
    pub text: Option<String>,
}

/// 按书写顺序执行 REWRITE 阶段步骤；返回 `ctx.done`（需要立即结束请求处理）。
/// `last`/`break` 的内部跳转语义由调用方（server.rs）通过 `ctx.internal_redirect` 处理。
pub fn apply_rewrite_steps(ctx: &mut RequestCtx, steps: &[RewriteStep]) -> bool {
    let _ = apply_steps(ctx, steps, 0);
    ctx.done
}

/// 一条步骤执行后 rewrite 阶段是否就此收束。nginx 的 rewrite 模块命中 `last`/`break`
/// 后立即停止本 location 的 rewrite 处理（包括后面书写的 set/return/if），所以不能简单
/// 地"返回 false 继续下一条"。
#[derive(Debug, PartialEq, Eq)]
enum StepFlow {
    Continue,
    /// 停止后续步骤：last/break/return/redirect 都走这里
    Stop,
}

fn apply_steps(ctx: &mut RequestCtx, steps: &[RewriteStep], depth: u8) -> StepFlow {
    for step in steps {
        match step {
            RewriteStep::Rewrite(rule) => {
                let path = ctx.effective_path().to_string();
                let Some(caps) = rule.pattern.captures(&path) else {
                    continue;
                };
                let mut replaced = rule.replacement.clone();
                // $1..$9 反向引用
                for i in (1..10).rev() {
                    let cap = caps.get(i).map(|m| m.as_str()).unwrap_or("").to_string();
                    replaced = replaced.replace(&format!("${i}"), &cap);
                }
                match rule.flag {
                    RewriteFlag::Redirect | RewriteFlag::Permanent => {
                        let code = if matches!(rule.flag, RewriteFlag::Permanent) {
                            301
                        } else {
                            302
                        };
                        let target = if replaced.starts_with("http") {
                            replaced
                        } else {
                            format!(
                                "http://{}{}",
                                ctx.host.as_deref().unwrap_or("localhost"),
                                replaced
                            )
                        };
                        ctx.redirect = Some((code, target));
                        ctx.done = true;
                        return StepFlow::Stop;
                    }
                    RewriteFlag::Last => {
                        ctx.rewritten_path = Some(replaced);
                        ctx.internal_redirect = true;
                        return StepFlow::Stop;
                    }
                    RewriteFlag::Break => {
                        ctx.rewritten_path = Some(replaced);
                        return StepFlow::Stop;
                    }
                }
            }
            RewriteStep::Set { name, value } => {
                let replaced = crate::proxy::interpolate_vars(value, ctx);
                if let Some(existing) = ctx.set_vars.iter_mut().find(|(k, _)| k == name) {
                    existing.1 = replaced;
                } else {
                    ctx.set_vars.push((name.clone(), replaced));
                }
            }
            RewriteStep::Return(ret) => {
                // 记下但不在这里结束请求：见 RequestCtx::rewrite_return 的注释
                ctx.rewrite_return = Some(ret.clone());
                return StepFlow::Stop;
            }
            RewriteStep::If { cond, then } => {
                // nginx 不支持 if 嵌套；解析期已拒绝，这里 depth 只是防御性上限
                if depth < 4
                    && eval_if_cond(cond, ctx)
                    && apply_steps(ctx, then, depth + 1) == StepFlow::Stop
                {
                    return StepFlow::Stop;
                }
            }
        }
    }
    StepFlow::Continue
}

pub fn apply_return(ctx: &mut RequestCtx, ret: &ReturnAction) {
    ctx.status = ret.code;
    // nginx 从 1.4.0 起在 `return` 的文本与 URL 里展开变量。ONRouter 过去把模板原样发出去，
    // 于是 `return 301 https://$host$request_uri;`（整站跳转最常见的那一行）会把字面量
    // "$host" 塞进 Location。展开用 rewrite/proxy 同一把插值器，未知变量名保持原样。
    let text = ret
        .text
        .as_ref()
        .map(|t| crate::proxy::interpolate_vars(t, ctx));
    // return 301/302 <url>：URL 放入 Location（对标 nginx）
    if matches!(ret.code, 301 | 302 | 303 | 307 | 308) {
        if let Some(url) = &text {
            ctx.set_resp_header("location", url);
            ctx.body = None;
            ctx.done = true;
            return;
        }
    }
    ctx.body = text.map(|t| t.into_bytes());
    ctx.done = true;
}

// ---------- Rust 原生处理器（对标 ngx Lua 模块，编译进二进制） ----------

pub type NativeHandler = Arc<
    dyn for<'a> Fn(&'a mut RequestCtx, &'a [String]) -> BoxFuture<'a, Result<(), String>>
        + Send
        + Sync,
>;

#[derive(Default, Clone)]
pub struct HandlerRegistry {
    map: HashMap<String, NativeHandler>,
}

/// 阶段归属（对应 nginx 的处理阶段）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Rewrite,
    Access,
    /// BALANCER：balancer_by_lua，在 proxy_pass 转发前运行，由 Lua 选定上游节点
    Balancer,
    Content,
    /// LOG：响应完成后运行（log_by_lua / log_by_rust），其输出被丢弃、不影响已发送的响应
    Log,
}

impl Phase {
    pub fn directive_names() -> &'static [&'static str] {
        &[
            "rewrite_by_rust",
            "access_by_rust",
            "content_by_rust",
            "log_by_rust",
        ]
    }

    pub fn from_directive(name: &str) -> Option<Phase> {
        match name {
            "rewrite_by_rust" => Some(Phase::Rewrite),
            "access_by_rust" => Some(Phase::Access),
            "content_by_rust" => Some(Phase::Content),
            "log_by_rust" => Some(Phase::Log),
            _ => None,
        }
    }
}

/// 处理器规格：来自配置 `content_by_rust name arg1 arg2`
#[derive(Debug, Clone)]
pub struct HandlerSpec {
    pub name: String,
    pub args: Vec<String>,
}

impl HandlerRegistry {
    pub fn with_builtins() -> Self {
        let mut reg = HandlerRegistry::default();

        // echo：输出文本（含变量插值）
        reg.register("echo", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                let text = args.join(" ");
                ctx.say(&crate::proxy::interpolate_vars(&text, ctx));
                Ok(())
            })
        });

        // time：模拟慢接口（sleep 后输出 JSON），演示异步不阻塞
        reg.register("time", |ctx: &mut RequestCtx, _args: &[String]| {
            Box::pin(async move {
                let start = std::time::Instant::now();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                ctx.set_resp_header("content-type", "application/json");
                ctx.say(&format!(
                    "{{\"now\": \"{}\", \"elapsed_ms\": {:.2}}}",
                    now,
                    start.elapsed().as_secs_f64() * 1000.0
                ));
                Ok(())
            })
        });

        // auth：access 阶段 token 鉴权，auth <期望token>
        reg.register("auth", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                let expect = args.first().map(|s| s.as_str()).unwrap_or("");
                match ctx.header("x-token") {
                    Some(t) if t == expect => Ok(()),
                    Some(_) => {
                        ctx.status = 403;
                        ctx.say("forbidden: bad token");
                        ctx.done = true;
                        Ok(())
                    }
                    None => {
                        ctx.status = 401;
                        ctx.say("unauthorized: missing x-token header");
                        ctx.done = true;
                        Ok(())
                    }
                }
            })
        });

        // status：直接返回指定状态码与文本
        reg.register("status", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                ctx.status = args.first().and_then(|s| s.parse().ok()).unwrap_or(200);
                if let Some(text) = args.get(1) {
                    ctx.say(&crate::proxy::interpolate_vars(text, ctx));
                }
                Ok(())
            })
        });

        // info：打印请求画像（调试用）
        reg.register("info", |ctx: &mut RequestCtx, _args: &[String]| {
            Box::pin(async move {
                ctx.set_resp_header("content-type", "text/plain; charset=utf-8");
                ctx.say(&format!(
                    "method={}\npath={}\nquery={}\nremote={}\nhost={:?}\nheaders={:?}",
                    ctx.method, ctx.path, ctx.query, ctx.remote_addr, ctx.host, ctx.req_headers
                ));
                Ok(())
            })
        });

        // metrics：渲染 Prometheus 文本（对标 stub_status 的运行时指标）。数据源是进程级
        // metrics 单例，连接层在 accept/请求/状态码处写入，此处只读。
        reg.register("metrics", |ctx: &mut RequestCtx, _args: &[String]| {
            Box::pin(async move {
                ctx.set_resp_header("content-type", "text/plain; version=0.0.4; charset=utf-8");
                ctx.say(&crate::metrics::get().render());
                Ok(())
            })
        });

        reg
    }

    pub fn register<F>(&mut self, name: &str, h: F)
    where
        F: for<'a> Fn(&'a mut RequestCtx, &'a [String]) -> BoxFuture<'a, Result<(), String>>
            + Send
            + Sync
            + 'static,
    {
        self.map.insert(name.to_string(), Arc::new(h));
    }

    pub fn get(&self, name: &str) -> Option<&NativeHandler> {
        self.map.get(name)
    }

    /// 执行一个 rust 阶段
    pub async fn run_phase(
        &self,
        phase: Phase,
        spec: &HandlerSpec,
        ctx: &mut RequestCtx,
    ) -> Result<(), AppError> {
        let h = self.get(&spec.name).ok_or_else(|| {
            AppError::Other(format!(
                "{phase:?} 阶段找不到处理器 '{spec_name}'（未注册）",
                spec_name = spec.name
            ))
        })?;
        h(ctx, &spec.args).await.map_err(AppError::Other)
    }
}

/// 从配置指令构造 HandlerSpec
pub fn spec_from_directive(d: &Directive) -> Option<HandlerSpec> {
    let name = d.arg(0)?;
    Some(HandlerSpec {
        name: name.to_string(),
        args: d.args[1..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(pat: &str) -> regex::Regex {
        regex::Regex::new(pat).unwrap()
    }
    fn re_ci(pat: &str) -> regex::Regex {
        regex::RegexBuilder::new(pat)
            .case_insensitive(true)
            .build()
            .unwrap()
    }
    fn lit(pattern: &str, result: &str) -> MapCase {
        MapCase {
            literal: Some(pattern.to_string()),
            regex: None,
            result: result.to_string(),
        }
    }
    fn rx(pattern: regex::Regex, result: &str) -> MapCase {
        MapCase {
            literal: None,
            regex: Some(pattern),
            result: result.to_string(),
        }
    }

    #[test]
    fn match_map_exact_then_default() {
        let def = MapDef {
            dest: "kind".into(),
            source: "x".into(),
            default: Some("other".into()),
            cases: vec![lit("mobile", "phone"), lit("desktop", "pc")],
        };
        assert_eq!(match_map(&def, "mobile"), "phone");
        assert_eq!(match_map(&def, "desktop"), "pc");
        assert_eq!(match_map(&def, "tablet"), "other");
        // 空串精确匹配（nginx `''` 分支）
        let def2 = MapDef {
            dest: "conn".into(),
            source: "upgrade".into(),
            default: Some("upgrade".into()),
            cases: vec![lit("", "close")],
        };
        assert_eq!(match_map(&def2, ""), "close");
        assert_eq!(match_map(&def2, "websocket"), "upgrade");
    }

    #[test]
    fn match_map_regex_ci_and_case_sensitive() {
        let def = MapDef {
            dest: "t".into(),
            source: "s".into(),
            default: None,
            cases: vec![rx(re_ci("^bot$"), "crawler"), rx(re("^admin"), "staff")],
        };
        assert_eq!(match_map(&def, "BOT"), "crawler");
        assert_eq!(match_map(&def, "admin-x"), "staff");
        // 区分大小写的正则：ADMIN 不匹配 ^admin
        assert_eq!(match_map(&def, "ADMIN"), "");
    }

    #[test]
    fn match_map_exact_beats_regex_regardless_of_order() {
        // 即便正则在前，nginx 语义仍先取精确匹配
        let def = MapDef {
            dest: "d".into(),
            source: "s".into(),
            default: Some("def".into()),
            cases: vec![rx(re("^foo"), "regex-hit"), lit("foobar", "exact-hit")],
        };
        assert_eq!(match_map(&def, "foobar"), "exact-hit");
        assert_eq!(match_map(&def, "foozzz"), "regex-hit");
    }

    #[test]
    fn match_map_capture_references_in_result() {
        let def = MapDef {
            dest: "d".into(),
            source: "s".into(),
            default: None,
            cases: vec![
                rx(re("^/api/([a-z]+)/(\\d+)$"), "$2@$1"),
                rx(re("^(?<verb>[A-Z]+)"), "verb-${verb}"),
            ],
        };
        assert_eq!(match_map(&def, "/api/users/42"), "42@users");
        assert_eq!(match_map(&def, "GET"), "verb-GET");
        assert_eq!(match_map(&def, "nope"), "");
    }

    #[test]
    fn resolve_variable_reads_builtin_vars() {
        let mut ctx = RequestCtx::default();
        ctx.scheme = "https".into();
        ctx.remote_addr = "203.0.113.9".into();
        ctx.req_headers
            .push(("x-client".to_string(), "android-13".to_string()));
        // 内置变量走 builtin_var（未安装任何 map/geo 时 resolve_variable 等价于 builtin_var）
        assert_eq!(resolve_variable(&ctx, "scheme").as_deref(), Some("https"));
        assert_eq!(
            resolve_variable(&ctx, "remote_addr").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            resolve_variable(&ctx, "http_x_client").as_deref(),
            Some("android-13")
        );
        // 未定义变量返回 None
        assert_eq!(resolve_variable(&ctx, "no_such_var"), None);
    }

    #[test]
    fn geo_exact_host_and_network_match() {
        let def = GeoDef {
            dest: "country".into(),
            source: "remote_addr".into(),
            default: Some("ZZ".into()),
            rules: vec![
                GeoRule {
                    ip: "127.0.0.1".parse().unwrap(),
                    prefix: 32,
                    result: "local".into(),
                },
                GeoRule {
                    ip: "10.1.0.0".parse().unwrap(),
                    prefix: 16,
                    result: "private".into(),
                },
            ],
        };
        assert_eq!(match_geo(&def, &"127.0.0.1".parse().unwrap()), "local");
        assert_eq!(match_geo(&def, &"10.1.99.7".parse().unwrap()), "private");
        assert_eq!(match_geo(&def, &"8.8.8.8".parse().unwrap()), "ZZ");
        // /32 主机不匹配到 127.0.0.2
        assert_eq!(match_geo(&def, &"127.0.0.2".parse().unwrap()), "ZZ");
    }

    #[test]
    fn geo_longest_prefix_wins() {
        // 声明顺序刻意「宽在前」，排序后应最具体优先
        let mut rules = vec![
            GeoRule {
                ip: "10.0.0.0".parse().unwrap(),
                prefix: 8,
                result: "wide".into(),
            },
            GeoRule {
                ip: "10.1.0.0".parse().unwrap(),
                prefix: 16,
                result: "mid".into(),
            },
            GeoRule {
                ip: "10.1.2.0".parse().unwrap(),
                prefix: 24,
                result: "narrow".into(),
            },
        ];
        rules.sort_by(|a, b| b.prefix.cmp(&a.prefix));
        let def = GeoDef {
            dest: "d".into(),
            source: "remote_addr".into(),
            default: None,
            rules,
        };
        assert_eq!(match_geo(&def, &"10.1.2.5".parse().unwrap()), "narrow");
        assert_eq!(match_geo(&def, &"10.1.9.5".parse().unwrap()), "mid");
        assert_eq!(match_geo(&def, &"10.9.9.9".parse().unwrap()), "wide");
    }

    #[test]
    fn murmur_hash2_is_deterministic_and_bounded() {
        // 同输入同输出；split_id 落在 [0,10000)
        let a = murmur_hash2(b"${remote_addr}127.0.0.1");
        let b = murmur_hash2(b"${remote_addr}127.0.0.1");
        assert_eq!(a, b);
        assert_ne!(murmur_hash2(b"alpha"), murmur_hash2(b"beta"));
        for k in [
            "",
            "x",
            "127.0.0.1Chrome",
            "a-long-key-that-spans-several-4-byte-blocks",
        ] {
            let id = split_id(k);
            assert!(id < 10000, "split_id({k}) = {id} 越界");
        }
    }

    #[test]
    fn split_ledger_is_idempotent_and_bounded() {
        // 同名第二次登记返回同一本账：热重载会重建整份路由表，账本若跟着重建，
        // 运维在发布窗口里看到的落点曲线就会莫名归零。
        let a = register_split_route("t_ledger", &["x".into(), "y".into()]).expect("应能登记");
        let b = register_split_route("t_ledger", &["x".into(), "y".into()]).expect("应能登记");
        assert!(Arc::ptr_eq(&a, &b), "重复登记必须复用同一本账");
        a.note_served("x");
        a.note(SplitRole::Routed);
        assert_eq!(a.served("x"), 1);
        assert_eq!(a.role(SplitRole::Routed), 1);
        assert_eq!(
            a.served("nope"),
            0,
            "未声明的分支不进账：指标标签的基数必须有上界"
        );
        // 分支数超过登记上限：分流照走，只是不再统计，绝不无界增长
        let too_many: Vec<String> = (0..=MAX_SPLIT_BRANCHES).map(|i| format!("b{i}")).collect();
        assert!(
            register_split_route("t_ledger_big", &too_many).is_none(),
            "超限的 split 必须拒绝登记而不是无限扩建账本"
        );
    }

    #[test]
    fn pick_split_bucket_accumulates_and_star_catches_rest() {
        let def = SplitDef {
            dest: "v".into(),
            key: "${remote_addr}".into(),
            buckets: vec![
                SplitBucket {
                    percent: 0.5,
                    result: "a".into(),
                },
                SplitBucket {
                    percent: 50.0,
                    result: "b".into(),
                },
            ],
            star: Some("rest".into()),
        };
        // 0.5% → id<50；50% → 累计到 5050；其余走 *
        assert_eq!(pick_split_bucket(&def, 0), "a");
        assert_eq!(pick_split_bucket(&def, 49), "a");
        assert_eq!(pick_split_bucket(&def, 50), "b");
        assert_eq!(pick_split_bucket(&def, 5049), "b");
        assert_eq!(pick_split_bucket(&def, 5050), "rest");
        assert_eq!(pick_split_bucket(&def, 9999), "rest");
        // 无 * 时落空返回空串
        let no_star = SplitDef {
            dest: "v".into(),
            key: String::new(),
            buckets: def.buckets.clone(),
            star: None,
        };
        assert_eq!(pick_split_bucket(&no_star, 6000), "");
    }

    #[test]
    fn zero_percent_branch_is_never_selected_by_the_ratio() {
        // `0%` 那一路只当改投落点：无论它声明在前还是在后，10000 个桶坐标里一个都不属于它。
        // 这条断言是 `proxy_split_failover http://<0% 分支>` 那个报错文案的前提 —— 文案让用户
        // 把退路写成 0%，如果比例还能选中它，"只当落点"就是假话。
        for (i, def) in [
            SplitDef {
                dest: "z".into(),
                key: String::new(),
                buckets: vec![
                    SplitBucket {
                        percent: 0.0,
                        result: "fallback_only".into(),
                    },
                    SplitBucket {
                        percent: 70.0,
                        result: "a".into(),
                    },
                ],
                star: Some("b".into()),
            },
            SplitDef {
                dest: "z".into(),
                key: String::new(),
                buckets: vec![
                    SplitBucket {
                        percent: 70.0,
                        result: "a".into(),
                    },
                    SplitBucket {
                        percent: 0.0,
                        result: "fallback_only".into(),
                    },
                ],
                star: Some("b".into()),
            },
        ]
        .iter()
        .enumerate()
        {
            let mut hit_fallback_only = 0;
            for id in 0..10000u32 {
                if pick_split_bucket(def, id) == "fallback_only" {
                    hit_fallback_only += 1;
                }
            }
            assert_eq!(hit_fallback_only, 0, "第 {i} 份：0% 分支被比例选中了");
            // 其余两路照旧各占其位：0% 不消耗任何桶坐标
            assert_eq!(pick_split_bucket(def, 0), "a");
            assert_eq!(pick_split_bucket(def, 6999), "a");
            assert_eq!(pick_split_bucket(def, 7000), "b");
        }
    }

    #[test]
    fn expand_split_key_resolves_builtin_vars() {
        let mut ctx = RequestCtx::default();
        ctx.remote_addr = "203.0.113.7".into();
        ctx.req_headers
            .push(("user-agent".to_string(), "curl/8".to_string()));
        // ${var} 与 $var 两种写法都插值；未定义变量按空串
        assert_eq!(
            expand_split_key(&ctx, "${remote_addr}${http_user_agent}", 0),
            "203.0.113.7curl/8"
        );
        assert_eq!(
            expand_split_key(&ctx, "$remote_addr-$no_such", 0),
            "203.0.113.7-"
        );
    }

    // ---- canary：灰度条件与求值 ----

    #[test]
    fn return_expands_variables_in_body_and_redirect_url() {
        let mut ctx = RequestCtx::default();
        ctx.host = Some("www.example.com".to_string());
        ctx.set_vars
            .push(("reason".to_string(), "maintenance".to_string()));
        // 200 + 文本：变量必须展开（nginx 1.4.0 起的行为）；认不出的名字保持字面量
        apply_return(
            &mut ctx,
            &ReturnAction {
                code: 200,
                text: Some("server-blocked:$reason,$nosuchvar".to_string()),
            },
        );
        assert_eq!(ctx.status, 200);
        assert_eq!(
            String::from_utf8(ctx.body.clone().unwrap()).unwrap(),
            "server-blocked:maintenance,$nosuchvar"
        );
        assert!(ctx.done);
        // 301 + URL：Location 拿到展开后的地址，body 必须为空（重定向无 body）
        let mut ctx2 = RequestCtx::default();
        ctx2.host = Some("www.example.com".to_string());
        apply_return(
            &mut ctx2,
            &ReturnAction {
                code: 301,
                text: Some("https://$host/redirect".to_string()),
            },
        );
        let loc = ctx2
            .resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .expect("301 必须带 Location");
        assert_eq!(
            loc, "https://www.example.com/redirect",
            "URL 里的变量要展开"
        );
        assert!(ctx2.body.is_none(), "重定向响应不该带 body");
        // 301 不带文本时不该凭空造一个 Location
        let mut ctx3 = RequestCtx::default();
        apply_return(
            &mut ctx3,
            &ReturnAction {
                code: 301,
                text: None,
            },
        );
        assert!(!ctx3
            .resp_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("location")));
    }

    fn canary_ctx() -> RequestCtx {
        let mut ctx = RequestCtx::default();
        ctx.remote_addr = "203.0.113.7".into();
        ctx.query = "ver=beta&debug=1".into();
        ctx.req_headers
            .push(("cookie".into(), "sid=abc; release=beta".into()));
        ctx.req_headers
            .push(("x-client-channel".into(), "CANARY".into()));
        ctx
    }

    #[test]
    fn canary_conditions_read_cookie_header_arg_and_ua() {
        let ctx = canary_ctx();
        // cookie：精确值 / 存在且非空
        let cookie = |v: Option<&str>| CanaryWhen::Cookie {
            name: "release".into(),
            value: v.map(str::to_string),
        };
        assert!(cookie(Some("beta")).matches(&ctx));
        assert!(!cookie(Some("stable")).matches(&ctx));
        assert!(cookie(None).matches(&ctx), "存在即命中");
        // 空 cookie 是浏览器清标记后的残留，不算命中
        let mut empty = canary_ctx();
        empty.req_headers[0].1 = "release=".into();
        assert!(!cookie(None).matches(&empty));
        assert!(!cookie(Some("beta")).matches(&empty));

        // header 名大小写不敏感，值大小写敏感
        let hdr = |v: Option<&str>| CanaryWhen::Header {
            name: "X-Client-Channel".into(),
            value: v.map(str::to_string),
        };
        assert!(hdr(Some("CANARY")).matches(&ctx));
        assert!(!hdr(Some("canary")).matches(&ctx));
        assert!(hdr(None).matches(&ctx));

        // query 参数（百分号解码由既有 query_arg 负责）
        let arg = |v: Option<&str>| CanaryWhen::Arg {
            name: "ver".into(),
            value: v.map(str::to_string),
        };
        assert!(arg(Some("beta")).matches(&ctx));
        assert!(!arg(Some("stable")).matches(&ctx));
        assert!(arg(None).matches(&ctx));

        // UA 正则：区分大小写与不区分两档
        let ua = |pat: &str, ci: bool| CanaryWhen::UserAgent {
            regex: regex::RegexBuilder::new(pat)
                .case_insensitive(ci)
                .build()
                .unwrap(),
            pattern: pat.to_string(),
            case_insensitive: ci,
        };
        let mut mic = canary_ctx();
        mic.req_headers
            .push(("user-agent".into(), "Mozilla/5.0 Firefox/129.0".into()));
        assert!(ua("firefox", true).matches(&mic));
        assert!(!ua("firefox", false).matches(&mic));
        assert!(ua("Firefox/[0-9]+", false).matches(&mic));

        // os 条件复用同一份 UA 判据
        let mut ios = canary_ctx();
        ios.req_headers.push((
            "user-agent".into(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)".into(),
        ));
        assert!(CanaryWhen::Os(CanaryOs::Ios).matches(&ios));
        assert!(!CanaryWhen::Os(CanaryOs::Macos).matches(&ios));
    }

    #[test]
    fn detect_os_orders_ios_before_macos_and_android_before_linux() {
        // 两组 UA 都同时含后者标记：顺序错了就会把 iPhone 判成 Mac、Android 判成 Linux
        assert_eq!(
            detect_os("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
            CanaryOs::Ios
        );
        assert_eq!(
            detect_os("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
            CanaryOs::Macos
        );
        assert_eq!(
            detect_os("Mozilla/5.0 (Linux; Android 13; Pixel 7)"),
            CanaryOs::Android
        );
        assert_eq!(
            detect_os("Mozilla/5.0 (X11; Linux x86_64)"),
            CanaryOs::Linux
        );
        assert_eq!(
            detect_os("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            CanaryOs::Windows
        );
        assert_eq!(detect_os("curl/8.4.0"), CanaryOs::Other);
        // 配置别名与回显一致
        assert_eq!(CanaryOs::parse("WIN"), Some(CanaryOs::Windows));
        assert_eq!(CanaryOs::parse("osx"), Some(CanaryOs::Macos));
        assert_eq!(CanaryOs::parse("plan9"), None);
        assert_eq!(CanaryOs::Ios.as_str(), "ios");
    }

    #[test]
    fn match_canary_prefers_first_rule_then_percent_then_default() {
        let rule = |target: &str| CanaryRule {
            when: CanaryWhen::Cookie {
                name: "release".into(),
                value: Some("beta".into()),
            },
            target: target.into(),
        };
        let def = CanaryDef {
            dest: "release".into(),
            rules: vec![rule("rule-hit")],
            // 100% 桶：只要规则没命中就必然落到这里，用来证明"规则优先于百分比"
            buckets: vec![SplitBucket {
                percent: 100.0,
                result: "percent".into(),
            }],
            key: "${remote_addr}".into(),
            default: "stable".into(),
        };
        assert_eq!(match_canary(&def, &canary_ctx(), 0), "rule-hit");
        let mut plain = canary_ctx();
        plain.req_headers[0].1 = "sid=abc".into();
        assert_eq!(
            match_canary(&def, &plain, 0),
            "percent",
            "规则未命中时先走百分比，而不是直接掉到 default"
        );

        // 没有百分比档时落到 default
        let no_pct = CanaryDef {
            dest: "release".into(),
            rules: vec![rule("rule-hit")],
            buckets: Vec::new(),
            key: "${remote_addr}".into(),
            default: "stable".into(),
        };
        assert_eq!(match_canary(&no_pct, &plain, 0), "stable");
    }

    #[test]
    fn canary_percent_is_sticky_per_key_and_covers_both_sides() {
        let def = CanaryDef {
            dest: "release".into(),
            rules: Vec::new(),
            buckets: vec![
                SplitBucket {
                    percent: 50.0,
                    result: "a".into(),
                },
                SplitBucket {
                    percent: 50.0,
                    result: "b".into(),
                },
            ],
            key: "${cookie_sid}".into(),
            default: "stable".into(),
        };
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            let mut ctx = RequestCtx::default();
            ctx.req_headers
                .push(("cookie".into(), format!("sid=user-{i}")));
            let first = match_canary(&def, &ctx, 0);
            // 同一用户重复访问必须稳定落在同一版本（粘性键的全部意义）
            assert_eq!(first, match_canary(&def, &ctx, 0));
            seen.insert(first);
        }
        assert_eq!(
            seen,
            ["a".to_string(), "b".to_string()].into_iter().collect(),
            "50/50 分桶应覆盖两边，实际 {seen:?}"
        );
    }

    #[test]
    fn canary_summary_lists_rules_percent_and_default() {
        let def = CanaryDef {
            dest: "release".into(),
            rules: vec![CanaryRule {
                when: CanaryWhen::Os(CanaryOs::Ios),
                target: "beta".into(),
            }],
            buckets: vec![SplitBucket {
                percent: 0.5,
                result: "beta".into(),
            }],
            key: "${cookie_sid}".into(),
            default: "stable".into(),
        };
        let s = def.summary();
        assert!(s.contains("os ios→beta"), "{s}");
        assert!(s.contains("0.5%→beta"), "{s}");
        assert!(s.contains("default→stable"), "{s}");
        // 粘性键由外层 location 描述统一追加一次，summary 里再写会重复
        assert!(!s.contains("粘性键"), "{s}");
    }

    #[test]
    fn sub_filter_literal_replaces_all_or_once() {
        let conf = SubFilterConf {
            filters: vec![SubFilter {
                pattern: SubPattern::Literal("foo".into()),
                replacement: "bar".into(),
            }],
            once: false,
            types: vec!["text/html".into()],
        };
        let out = apply_sub_filter(
            Some(&conf),
            Some("text/html; charset=utf-8"),
            b"a foo b foo c".to_vec(),
        );
        assert_eq!(std::str::from_utf8(&out).unwrap(), "a bar b bar c");
        // once=只替换第一处
        let once = SubFilterConf {
            once: true,
            ..conf.clone()
        };
        let out = apply_sub_filter(Some(&once), Some("text/html"), b"a foo b foo c".to_vec());
        assert_eq!(std::str::from_utf8(&out).unwrap(), "a bar b foo c");
    }

    #[test]
    fn sub_filter_amp_expands_to_matched_text_and_gates_by_type() {
        // `&` = 匹配原文；类型不匹配 text/html 时不改写
        let conf = SubFilterConf {
            filters: vec![SubFilter {
                pattern: SubPattern::Literal("cat".into()),
                replacement: "[&]".into(),
            }],
            once: false,
            types: vec!["text/html".into()],
        };
        let out = apply_sub_filter(Some(&conf), Some("text/html"), b"the cat sat".to_vec());
        assert_eq!(std::str::from_utf8(&out).unwrap(), "the [cat] sat");
        let out2 = apply_sub_filter(
            Some(&conf),
            Some("application/json"),
            b"the cat sat".to_vec(),
        );
        assert_eq!(&out2, b"the cat sat");
    }

    #[test]
    fn sub_filter_regex_ci_and_wildcard_type() {
        let conf = SubFilterConf {
            filters: vec![SubFilter {
                pattern: SubPattern::Regex(
                    regex::RegexBuilder::new("he[l]{2,}o")
                        .case_insensitive(true)
                        .build()
                        .unwrap(),
                ),
                replacement: "HI".into(),
            }],
            once: false,
            types: vec!["text/*".into()],
        };
        let out = apply_sub_filter(Some(&conf), Some("text/plain"), b"Hello hELLo hlo".to_vec());
        assert_eq!(std::str::from_utf8(&out).unwrap(), "HI HI hlo");
    }

    #[test]
    fn sub_filter_sequential_rules_chain_and_binary_untouched() {
        // 规则按序：第二条作用于第一条的结果
        let conf = SubFilterConf {
            filters: vec![
                SubFilter {
                    pattern: SubPattern::Literal("a".into()),
                    replacement: "b".into(),
                },
                SubFilter {
                    pattern: SubPattern::Literal("b".into()),
                    replacement: "c".into(),
                },
            ],
            once: false,
            types: vec!["*".into()],
        };
        let out = apply_sub_filter(Some(&conf), Some("text/html"), b"aaa".to_vec());
        assert_eq!(std::str::from_utf8(&out).unwrap(), "ccc");
        // 非 UTF-8 字节（二进制）原样返回
        let bin = vec![0xff_u8, 0xfe, 0x00, b'a'];
        let out = apply_sub_filter(Some(&conf), Some("text/html"), bin.clone());
        assert_eq!(out, bin);
    }

    #[test]
    fn geo_ipv6_and_cross_family_never_match() {
        let def = GeoDef {
            dest: "d".into(),
            source: "s".into(),
            default: Some("none".into()),
            rules: vec![
                GeoRule {
                    ip: "2001:db8::".parse().unwrap(),
                    prefix: 32,
                    result: "doc".into(),
                },
                GeoRule {
                    ip: "::1".parse().unwrap(),
                    prefix: 128,
                    result: "loopback".into(),
                },
            ],
        };
        assert_eq!(match_geo(&def, &"2001:db8:abcd::1".parse().unwrap()), "doc");
        assert_eq!(match_geo(&def, &"::1".parse().unwrap()), "loopback");
        // IPv4 目标绝不匹配 IPv6 规则
        assert_eq!(match_geo(&def, &"8.8.8.8".parse().unwrap()), "none");
    }

    #[test]
    fn geo_prefix_zero_matches_all_of_family() {
        let def = GeoDef {
            dest: "d".into(),
            source: "s".into(),
            default: Some("other".into()),
            rules: vec![GeoRule {
                ip: "0.0.0.0".parse().unwrap(),
                prefix: 0,
                result: "any-v4".into(),
            }],
        };
        assert_eq!(match_geo(&def, &"1.2.3.4".parse().unwrap()), "any-v4");
        // v6 不匹配 v4 的 /0
        assert_eq!(match_geo(&def, &"::1".parse().unwrap()), "other");
    }

    /// STATIC_VAR_NAMES 是"名字合法但这次取不到值"的白名单（add_header/proxy_cache_key
    /// 靠它决定展开成空串还是保留字面量）。漏同步的后果很隐蔽，所以每个名字实际取一次。
    #[test]
    fn static_var_names_are_known() {
        let mut ctx = RequestCtx::default();
        ctx.host = Some("example.test".into());
        ctx.listener = Some("127.0.0.1:8080".parse().unwrap());
        ctx.req_headers = vec![
            ("content-type".into(), "text/plain".into()),
            ("content-length".into(), "3".into()),
        ];
        ctx.ssl = Some(SslState {
            server_name: Some("tls.example.test".into()),
            ..Default::default()
        });
        for name in STATIC_VAR_NAMES {
            // $hostname 读环境变量，CI 机器上可能两个都没有
            if *name == "hostname" {
                continue;
            }
            assert!(
                builtin_var(&ctx, name).is_some(),
                "'{name}' 列在 STATIC_VAR_NAMES 里，但 builtin_var 返回 None（两边没同步）"
            );
            assert!(is_static_var_name(name));
        }
        // 反面：既不在名单也不该被 builtin 认出来的名字必须保持"未知"
        assert!(builtin_var(&ctx, "definitely_not_a_variable").is_none());
        assert!(!is_static_var_name("definitely_not_a_variable"));
        assert!(!is_derived_var_name("definitely_not_a_variable"));
        // 前缀派生名：没有值也属于合法变量
        for d in [
            "http_x_no_such",
            "arg_no_such",
            "cookie_no_such",
            "sent_http_no_such",
        ] {
            assert!(is_derived_var_name(d), "{d} 应识别为派生变量");
            assert!(builtin_var(&ctx, d).is_none());
        }
    }

    #[test]
    fn host_var_drops_the_port_like_nginx() {
        let mut ctx = RequestCtx::default();
        ctx.req_headers = vec![("host".into(), "example.test:8080".into())];
        ctx.host = Some("example.test:8080".into());
        // $host 去端口；$http_host 保留原始头值
        assert_eq!(builtin_var(&ctx, "host").as_deref(), Some("example.test"));
        assert_eq!(
            builtin_var(&ctx, "http_host").as_deref(),
            Some("example.test:8080")
        );
        // 无端口 / IPv6（带括号与不带括号）都不能被截坏
        for (raw, want) in [
            ("example.test", "example.test"),
            ("[::1]:8080", "[::1]"),
            ("[2001:db8::1]", "[2001:db8::1]"),
            ("::1", "::1"),
            ("host:notaport", "host:notaport"),
        ] {
            ctx.host = Some(raw.into());
            assert_eq!(
                builtin_var(&ctx, "host").as_deref(),
                Some(want),
                "raw={raw}"
            );
        }
    }

    fn set_step(name: &str, value: &str) -> RewriteStep {
        RewriteStep::Set {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn set_writes_request_var_and_last_write_wins() {
        let mut ctx = RequestCtx::default();
        ctx.path = "/a/b".into();
        ctx.query = "n=7".into();
        let steps = vec![
            set_step("tag", "first"),
            set_step("tag", "second-$arg_n"),
            set_step("tail", "$uri-end"),
        ];
        assert!(!apply_rewrite_steps(&mut ctx, &steps));
        assert_eq!(resolve_variable(&ctx, "tag").as_deref(), Some("second-7"));
        // value 只展开一次：变量值里出现的 $ 不会被二次展开
        assert_eq!(ctx.set_vars.len(), 2);
        // 未参与 set 的变量仍走 builtin 通道
        assert_eq!(resolve_variable(&ctx, "uri").as_deref(), Some("/a/b"));
    }

    #[test]
    fn set_can_shadow_a_builtin_name_for_this_request() {
        let mut ctx = RequestCtx::default();
        ctx.uri = "/orig?q=1".into();
        ctx.path = "/orig".into();
        apply_rewrite_steps(&mut ctx, &[set_step("request_uri", "/fake")]);
        assert_eq!(
            resolve_variable(&ctx, "request_uri").as_deref(),
            Some("/fake")
        );
    }

    #[test]
    fn if_conds_follow_nginx_truthiness_and_string_rules() {
        let mut ctx = RequestCtx::default();
        ctx.uri = "/x".into();
        ctx.query = "a=0".into();
        ctx.req_headers = vec![("user-agent".into(), "Mozilla/5.0 MSIE".into())];
        let cond = |lhs: &str, op: CondOp, rhs: Option<&str>| IfCond {
            lhs: lhs.into(),
            op,
            rhs: rhs.map(|s| s.to_string()),
        };
        // 空/非空：nginx 只看变量是否有值，字符串 "0" 算真
        assert!(eval_if_cond(&cond("$arg_a", CondOp::NonEmpty, None), &ctx));
        assert!(!eval_if_cond(
            &cond("$arg_missing", CondOp::NonEmpty, None),
            &ctx
        ));
        assert!(eval_if_cond(
            &cond("$arg_missing", CondOp::Empty, None),
            &ctx
        ));
        // = / !=：右值本身也是模板
        assert!(eval_if_cond(&cond("$arg_a", CondOp::Eq, Some("0")), &ctx));
        assert!(eval_if_cond(
            &cond("$scheme", CondOp::Ne, Some("$arg_a")),
            &ctx
        ));
        // `= ""` 是 nginx 里"这个头/Cookie 没带"的标准写法，空右值要能活到求值阶段
        assert!(eval_if_cond(
            &cond("$http_x_key", CondOp::Eq, Some("")),
            &ctx
        ));
        assert!(!eval_if_cond(
            &cond("$http_user_agent", CondOp::Eq, Some("")),
            &ctx
        ));
        assert!(eval_if_cond(
            &cond("$http_user_agent", CondOp::Ne, Some("")),
            &ctx
        ));
        // ~ 区分大小写、~* 忽略、!~ / !~* 取反
        assert!(eval_if_cond(
            &cond("$http_user_agent", CondOp::Regex(re("MSIE")), None),
            &ctx
        ));
        assert!(!eval_if_cond(
            &cond("$http_user_agent", CondOp::Regex(re("msie")), None),
            &ctx
        ));
        assert!(eval_if_cond(
            &cond("$http_user_agent", CondOp::IRegex(re_ci("msie")), None),
            &ctx
        ));
        assert!(eval_if_cond(
            &cond("$http_user_agent", CondOp::NotRegex(re("msie")), None),
            &ctx
        ));
        assert!(!eval_if_cond(
            &cond("$http_user_agent", CondOp::NotIRegex(re_ci("MSIE")), None),
            &ctx
        ));
    }

    #[test]
    fn if_gates_inner_set_then_return() {
        let mut ctx = RequestCtx::default();
        ctx.query = "debug=1".into();
        let steps = vec![RewriteStep::If {
            cond: IfCond {
                lhs: "$arg_debug".into(),
                op: CondOp::NonEmpty,
                rhs: None,
            },
            then: vec![
                set_step("why", "debug-on"),
                RewriteStep::Return(ReturnAction {
                    code: 403,
                    text: Some("no".into()),
                }),
            ],
        }];
        // return 只被"记下"：ONRouter 让它和裸 return 一样在 ACCESS 之后执行，
        // 所以这里既不是 done，也不改 status
        assert!(!apply_rewrite_steps(&mut ctx, &steps));
        assert!(!ctx.done);
        assert_eq!(ctx.status, 0);
        assert_eq!(ctx.rewrite_return.as_ref().map(|r| r.code), Some(403));
        // 内层 set 在 return 之前已生效（顺序语义）
        assert_eq!(resolve_variable(&ctx, "why").as_deref(), Some("debug-on"));

        // 条件不成立时整块跳过
        let mut ctx2 = RequestCtx::default();
        ctx2.query = "debug=".into();
        assert!(!apply_rewrite_steps(&mut ctx2, &steps));
        assert!(ctx2.rewrite_return.is_none());
        assert_eq!(resolve_variable(&ctx2, "why"), None);
    }

    #[test]
    fn recorded_return_stops_the_rest_of_the_sequence() {
        let mut ctx = RequestCtx::default();
        ctx.query = "go=1".into();
        let steps = vec![
            RewriteStep::If {
                cond: IfCond {
                    lhs: "$arg_go".into(),
                    op: CondOp::NonEmpty,
                    rhs: None,
                },
                then: vec![RewriteStep::Return(ReturnAction {
                    code: 429,
                    text: None,
                })],
            },
            // if 命中后不该再执行：后面的 rewrite 不生效
            RewriteStep::Rewrite(RewriteRule {
                pattern: re("^/x$"),
                replacement: "/y".into(),
                flag: RewriteFlag::Break,
            }),
        ];
        apply_rewrite_steps(&mut ctx, &steps);
        assert_eq!(ctx.rewritten_path, None);
        assert_eq!(ctx.rewrite_return.as_ref().map(|r| r.code), Some(429));
    }

    #[test]
    fn rewrite_last_inside_if_stops_the_step_list() {
        let mut ctx = RequestCtx::default();
        ctx.path = "/old".into();
        ctx.query = "go=1".into();
        let steps = vec![
            RewriteStep::If {
                cond: IfCond {
                    lhs: "$arg_go".into(),
                    op: CondOp::NonEmpty,
                    rhs: None,
                },
                then: vec![RewriteStep::Rewrite(RewriteRule {
                    pattern: re("^/old$"),
                    replacement: "/new".into(),
                    flag: RewriteFlag::Last,
                })],
            },
            // last 之后不该再执行：$tag 保持未定义
            set_step("tag", "after"),
        ];
        assert!(!apply_rewrite_steps(&mut ctx, &steps));
        assert_eq!(ctx.rewritten_path.as_deref(), Some("/new"));
        assert!(ctx.internal_redirect);
        assert_eq!(resolve_variable(&ctx, "tag"), None);
    }
}
