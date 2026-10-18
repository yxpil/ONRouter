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
use std::sync::Arc;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::sync::mpsc;

use onrouter_config::Directive;

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
        self.body.get_or_insert_with(Vec::new).extend_from_slice(bytes);
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
            upstream_header_time: 0.0,
            ssl: None,
            start_time: unix_now(),
            http_version: 1.1,
            body_builder: None,
            eof_sent: false,
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
        "remote_port" => Some(ctx.remote_port.to_string()),
        "server_port" => Some(ctx.server_port.to_string()),
        "scheme" => Some(ctx.scheme.clone()),
        "request_method" | "method" => Some(ctx.method.clone()),
        "request_uri" => Some(ctx.uri.clone()),
        "uri" => Some(ctx.effective_path().to_string()),
        "args" | "query_string" => Some(ctx.query.clone()),
        "is_args" => Some(if ctx.query.is_empty() { String::new() } else { "?".to_string() }),
        "host" => ctx.host.clone(),
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
                + ctx.req_headers.iter().map(|(k, v)| k.len() + v.len() + 4).sum::<usize>())
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
        "time_local" => Some(chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z").to_string()),
        "time_iso8601" => Some(chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string()),
        "https" => Some(if ctx.scheme.eq_ignore_ascii_case("https") { "on" } else { "" }.to_string()),
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
        _ => None,
    }
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
            let val = caps.get(idx).map(|m| m.as_str().to_string()).unwrap_or_default();
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
    if types.iter().any(|t| t == "*" || t.eq_ignore_ascii_case("all")) {
        return true;
    }
    let ct = match content_type {
        Some(c) => c,
        None => return false,
    };
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    types.iter().any(|t| {
        let tl = t.to_ascii_lowercase();
        match tl.split_once('/') {
            Some((base, "*")) => mime.split_once('/').map(|(b, _)| b == base).unwrap_or(false),
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
                out.push_str(&expand_sub_replacement(repl, &rest[pos..pos + needle.len()]));
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

/// return 指令：状态码 + 可选文本/URL
#[derive(Debug, Clone)]
pub struct ReturnAction {
    pub code: u16,
    pub text: Option<String>,
}

/// 对 ctx 依次应用 rewrite 规则；返回是否需要停止处理
pub fn apply_rewrites(ctx: &mut RequestCtx, rules: &[RewriteRule]) -> bool {
    for rule in rules {
        let path = ctx.effective_path().to_string();
        if let Some(caps) = rule.pattern.captures(&path) {
            let mut replaced = rule.replacement.clone();
            // $1..$9 反向引用
            for i in (1..10).rev() {
                let cap = caps
                    .get(i)
                    .map(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                replaced = replaced.replace(&format!("${i}"), &cap);
            }
            match rule.flag {
                RewriteFlag::Redirect | RewriteFlag::Permanent => {
                    let code = if matches!(rule.flag, RewriteFlag::Permanent) { 301 } else { 302 };
                    let target = if replaced.starts_with("http") {
                        replaced
                    } else {
                        format!("http://{}{}", ctx.host.as_deref().unwrap_or("localhost"), replaced)
                    };
                    ctx.redirect = Some((code, target));
                    ctx.done = true;
                    return true;
                }
                RewriteFlag::Last => {
                    ctx.rewritten_path = Some(replaced);
                    ctx.internal_redirect = true;
                    return true;
                }
                RewriteFlag::Break => {
                    ctx.rewritten_path = Some(replaced);
                    return true;
                }
            }
        }
    }
    false
}

pub fn apply_return(ctx: &mut RequestCtx, ret: &ReturnAction) {
    ctx.status = ret.code;
    // return 301/302 <url>：URL 放入 Location（对标 nginx）
    if matches!(ret.code, 301 | 302 | 303 | 307 | 308) {
        if let Some(url) = &ret.text {
            ctx.set_resp_header("location", url);
            ctx.body = None;
            ctx.done = true;
            return;
        }
    }
    ctx.body = ret.text.clone().map(|t| t.into_bytes());
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
        &["rewrite_by_rust", "access_by_rust", "content_by_rust", "log_by_rust"]
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
                ctx.status = args
                    .first()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200);
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
        h(ctx, &spec.args)
            .await
            .map_err(AppError::Other)
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
        regex::RegexBuilder::new(pat).case_insensitive(true).build().unwrap()
    }
    fn lit(pattern: &str, result: &str) -> MapCase {
        MapCase { literal: Some(pattern.to_string()), regex: None, result: result.to_string() }
    }
    fn rx(pattern: regex::Regex, result: &str) -> MapCase {
        MapCase { literal: None, regex: Some(pattern), result: result.to_string() }
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
            cases: vec![rx(re("^/api/([a-z]+)/(\\d+)$"), "$2@$1"),
                        rx(re("^(?<verb>[A-Z]+)"), "verb-${verb}")],
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
        ctx.req_headers.push(("x-client".to_string(), "android-13".to_string()));
        // 内置变量走 builtin_var（未安装任何 map/geo 时 resolve_variable 等价于 builtin_var）
        assert_eq!(resolve_variable(&ctx, "scheme").as_deref(), Some("https"));
        assert_eq!(resolve_variable(&ctx, "remote_addr").as_deref(), Some("203.0.113.9"));
        assert_eq!(resolve_variable(&ctx, "http_x_client").as_deref(), Some("android-13"));
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
                GeoRule { ip: "127.0.0.1".parse().unwrap(), prefix: 32, result: "local".into() },
                GeoRule { ip: "10.1.0.0".parse().unwrap(), prefix: 16, result: "private".into() },
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
            GeoRule { ip: "10.0.0.0".parse().unwrap(), prefix: 8, result: "wide".into() },
            GeoRule { ip: "10.1.0.0".parse().unwrap(), prefix: 16, result: "mid".into() },
            GeoRule { ip: "10.1.2.0".parse().unwrap(), prefix: 24, result: "narrow".into() },
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
        for k in ["", "x", "127.0.0.1Chrome", "a-long-key-that-spans-several-4-byte-blocks"] {
            let id = split_id(k);
            assert!(id < 10000, "split_id({k}) = {id} 越界");
        }
    }

    #[test]
    fn pick_split_bucket_accumulates_and_star_catches_rest() {
        let def = SplitDef {
            dest: "v".into(),
            key: "${remote_addr}".into(),
            buckets: vec![
                SplitBucket { percent: 0.5, result: "a".into() },
                SplitBucket { percent: 50.0, result: "b".into() },
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
        let no_star = SplitDef { dest: "v".into(), key: String::new(), buckets: def.buckets.clone(), star: None };
        assert_eq!(pick_split_bucket(&no_star, 6000), "");
    }

    #[test]
    fn expand_split_key_resolves_builtin_vars() {
        let mut ctx = RequestCtx::default();
        ctx.remote_addr = "203.0.113.7".into();
        ctx.req_headers.push(("user-agent".to_string(), "curl/8".to_string()));
        // ${var} 与 $var 两种写法都插值；未定义变量按空串
        assert_eq!(
            expand_split_key(&ctx, "${remote_addr}${http_user_agent}", 0),
            "203.0.113.7curl/8"
        );
        assert_eq!(expand_split_key(&ctx, "$remote_addr-$no_such", 0), "203.0.113.7-");
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
        let out = apply_sub_filter(Some(&conf), Some("text/html; charset=utf-8"), b"a foo b foo c".to_vec());
        assert_eq!(std::str::from_utf8(&out).unwrap(), "a bar b bar c");
        // once=只替换第一处
        let once = SubFilterConf { once: true, ..conf.clone() };
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
        let out2 = apply_sub_filter(Some(&conf), Some("application/json"), b"the cat sat".to_vec());
        assert_eq!(&out2, b"the cat sat");
    }

    #[test]
    fn sub_filter_regex_ci_and_wildcard_type() {
        let conf = SubFilterConf {
            filters: vec![SubFilter {
                pattern: SubPattern::Regex(
                    regex::RegexBuilder::new("he[l]{2,}o").case_insensitive(true).build().unwrap(),
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
                SubFilter { pattern: SubPattern::Literal("a".into()), replacement: "b".into() },
                SubFilter { pattern: SubPattern::Literal("b".into()), replacement: "c".into() },
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
                GeoRule { ip: "2001:db8::".parse().unwrap(), prefix: 32, result: "doc".into() },
                GeoRule { ip: "::1".parse().unwrap(), prefix: 128, result: "loopback".into() },
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
            rules: vec![GeoRule { ip: "0.0.0.0".parse().unwrap(), prefix: 0, result: "any-v4".into() }],
        };
        assert_eq!(match_geo(&def, &"1.2.3.4".parse().unwrap()), "any-v4");
        // v6 不匹配 v4 的 /0
        assert_eq!(match_geo(&def, &"::1".parse().unwrap()), "other");
    }
}