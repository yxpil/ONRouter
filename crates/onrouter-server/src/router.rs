//! 请求路由与配置模型：监听端点 / server 块 / location 匹配（nginx 语义）。
//!
//! location 匹配算法（与 nginx 一致）：
//!   1. `= /exact` 精确匹配命中 → 直接使用
//!   2. 记录最长前缀匹配；若该前缀带 `^~` → 直接使用（跳过正则）
//!   3. 否则按配置顺序找第一个命中的正则（`~` 或 `~*`）→ 使用
//!   4. 都没有 → 用第 2 步的最长前缀
//!
//! server 匹配：先按**实际监听地址**（ip:port）取该端点的 vhost 集合，
//! 再按 Host 匹配：精确名 > 通配符（`*.example.com` / `example.*`）> `default_server` > 第一个。
//!
//! `listen` 支持的形态：
//! ```text
//! listen 8080;                       # 0.0.0.0:8080（与 nginx 一致）
//! listen 127.0.0.1:8080;             # 指定地址
//! listen [::]:8080;                  # IPv6
//! listen 8443 ssl http2;             # TLS + ALPN h2
//! listen 8443 ssl default_server;    # 该端点的默认 vhost
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use onrouter_config::{Config, Directive};

use crate::certs::{CertSpec, SessionCache, SessionOptions, TlsOptions, TlsProtocols, TlsVersion};
use crate::engine::{
    CondOp, GeoDef, GeoRule, HandlerSpec, IfCond, MapCase, MapDef, Phase, ReturnAction,
    RewriteFlag, RewriteRule, RewriteStep, SplitBucket, SplitDef,
};
use crate::limit::{ConnRule, ReqRule};
use crate::lua_engine::LuaSource;
use crate::proxy_tls::TlsPolicy;
use crate::AppError;

// ---------- location 匹配 ----------

#[derive(Debug, Clone)]
pub enum LocationKind {
    /// `location = /exact`
    Exact(String),
    /// `location /prefix`（`^~`：命中即赢过正则）
    Prefix { path: String, caret: bool },
    /// `location ~ regex`
    Regex(regex::Regex),
    /// `location ~* regex`
    RegexI(regex::Regex),
}

impl LocationKind {
    fn parse(modifier: Option<&str>, pattern: &str) -> Result<Self, AppError> {
        Ok(match modifier {
            Some("=") => LocationKind::Exact(pattern.to_string()),
            Some("^~") => LocationKind::Prefix {
                path: pattern.to_string(),
                caret: true,
            },
            Some("~") => LocationKind::Regex(regex::Regex::new(pattern)
                .map_err(|e| AppError::Other(format!("location 正则错误 {pattern}: {e}")))?),
            Some("~*") => LocationKind::RegexI(
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| AppError::Other(format!("location 正则错误 {pattern}: {e}")))?,
            ),
            None => LocationKind::Prefix {
                path: pattern.to_string(),
                caret: false,
            },
            Some(other) => {
                return Err(AppError::Other(format!(
                    "暂不支持的 location 修饰符 '{other}'（支持 = / ^~ / ~ / ~*）"
                )))
            }
        })
    }

    fn prefix_path(&self) -> Option<&str> {
        match self {
            LocationKind::Prefix { path, .. } => Some(path),
            _ => None,
        }
    }

    fn is_caret(&self) -> bool {
        matches!(self, LocationKind::Prefix { caret: true, .. })
    }

    fn is_regex(&self) -> bool {
        matches!(self, LocationKind::Regex(_) | LocationKind::RegexI(_))
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub kind: LocationKind,
    /// 原始 pattern（日志/调试/alias 前缀剥离/proxy URI 替换）
    pub pattern: String,
    /// REWRITE 阶段步骤：`rewrite`/`set`/`if` 按书写顺序混排（nginx 同款语义）
    pub rewrite_steps: Vec<RewriteStep>,
    pub ret: Option<ReturnAction>,
    pub proxy_pass: Option<String>,
    pub proxy_set_headers: Vec<(String, String)>,
    pub proxy_read_timeout: std::time::Duration,
    pub proxy_connect_timeout: std::time::Duration,
    pub proxy_send_timeout: std::time::Duration,
    /// `proxy_next_upstream off | error | timeout | invalid_header | non_idempotent | http_XXX`
    /// （默认 error,timeout）
    pub proxy_next_upstream: Vec<String>,
    /// `proxy_next_upstream_tries`：最多尝试节点数（0 = 跟随 upstream 节点数）
    pub proxy_next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout`：换节点总时间预算（0 = 不限制）
    pub proxy_next_upstream_timeout: std::time::Duration,
    /// `proxy_request_buffering on|off`（默认 on）。off 且该 location 有 proxy_pass 时，
    /// 请求体边收边转发给后端，网关不再整体缓冲（nginx 语义）。
    pub proxy_request_buffering: bool,
    pub rust_phases: Vec<(Phase, HandlerSpec)>,
    pub lua_phases: Vec<(Phase, String, LuaSource)>,
    pub root: Option<PathBuf>,
    pub alias: Option<PathBuf>,
    pub index: Option<Vec<String>>,
    pub try_files: Option<Vec<String>>,
    pub autoindex: bool,
    pub error_pages: HashMap<u16, String>,
    pub add_headers: Vec<(String, String)>,
    /// PREACCESS 阶段限流
    pub limit_req: Vec<ReqRule>,
    /// `internal;` 只允许内部重定向访问
    pub internal: bool,
    /// `client_max_body_size` 的 location 级覆盖
    pub client_max_body_size: Option<u64>,
    /// ACCESS 阶段 IP 白/黑名单（allow/deny，有序，第一条命中生效，无命中默认放行）
    pub access_rules: Vec<crate::access::AccessRule>,
    /// `auth_basic "realm";`；None = 未启用。字面量 `off`/空串视为关闭。
    pub auth_basic_realm: Option<String>,
    /// `auth_basic_user_file <path>;` 解析后的绝对路径
    pub auth_basic_user_file: Option<PathBuf>,
    /// `proxy_cache <zone>|off;`：Some(zone) 启用命名缓存区，None 关闭
    pub proxy_cache: Option<String>,
    /// `proxy_cache_key <模板>;`，默认 `$scheme$proxy_host$request_uri`
    pub proxy_cache_key: String,
    /// `proxy_cache_methods`（默认 GET HEAD）
    pub proxy_cache_methods: Vec<String>,
    /// `proxy_cache_valid` 拆分后的 (状态码集合, ttl)；空表示仅按上游 Cache 头
    pub proxy_cache_valid: Vec<(Vec<String>, std::time::Duration)>,
    /// `proxy_cache_min_uses N`（默认 1）：同一 key 第 N 次起才写入
    pub proxy_cache_min_uses: u32,
    /// `proxy_cache_lock on|off`：同一 key 并发未命中时只放一个请求回源
    pub proxy_cache_lock: bool,
    /// `proxy_cache_lock_timeout`（默认 5s）：等锁超时后自己回源
    pub proxy_cache_lock_timeout: std::time::Duration,
    /// `proxy_cache_use_stale`：回源失败/指定状态码/刷新中时回放过期条目
    pub proxy_cache_use_stale: Vec<String>,
    /// `proxy_cache_bypass`：任一表达式展开为非空且非 "0" 时不读缓存
    pub proxy_cache_bypass: Vec<String>,
    /// `proxy_no_cache`：任一表达式展开为非空且非 "0" 时不写缓存
    pub proxy_no_cache: Vec<String>,
    /// `proxy_ignore_headers`：这些上游响应头（小写）不参与缓存判定（TTL 与 Set-Cookie 门槛），
    /// 但仍然原样透传给客户端——nginx 语义是"停止处理"这些头，不是删除它们。
    pub proxy_ignore_headers: Vec<String>,
    /// `still_online <区>|off;`：后端故障时回放的"最后已知良好响应"副本区（None=关闭）。
    /// 与 `proxy_cache` 完全独立：自己的容量、保留期与逐出，互不影响。
    pub still_online: Option<String>,
    /// `still_online_max_age`（默认 7d）：副本存放超过这个时长就不再回放（就地删除）。
    pub still_online_max_age: std::time::Duration,
    /// `still_online_max_body`（默认 1m）：单条副本的响应体上限，超过直接不收。
    pub still_online_max_body: usize,
    /// `still_online_retry`（默认 5s）：脏 key 首次重取的退避，之后每次翻倍。
    pub still_online_retry: std::time::Duration,
    /// `still_online_retry_max`（默认 300s）：退避翻倍后的封顶。
    pub still_online_retry_max: std::time::Duration,
    /// `still_online_retry_deadline`（默认 30m）：从首次失败起算，超过就放弃自动重取。
    pub still_online_retry_deadline: std::time::Duration,
    /// `still_online_allow_credentials on`：只放开"带 Cookie/Authorization 的请求也能读副本"。
    /// 写入门槛与回放时的 Set-Cookie 剥离是硬规则，不受本开关影响。
    pub still_online_allow_credentials: bool,
    /// `proxy_ssl_*`：https/wss 后端的客户端 TLS 策略
    pub proxy_tls: TlsPolicy,
    /// `sub_filter ...`：响应体文本替换输出过滤器（None=未启用）
    pub sub_filter: Option<crate::engine::SubFilterConf>,
    /// `proxy_redirect ...`：改写上游 `Location`/`Refresh` 响应头
    pub proxy_redirect: crate::resp_rewrite::ProxyRedirect,
    /// `proxy_cookie_domain ...`：改写 `Set-Cookie` 的 `domain=` 属性
    pub proxy_cookie_domain: crate::resp_rewrite::CookieRewrite,
    /// `proxy_cookie_path ...`：改写 `Set-Cookie` 的 `path=` 属性
    pub proxy_cookie_path: crate::resp_rewrite::CookieRewrite,
}

#[derive(Debug, Clone)]
pub struct Server {
    /// `server_name` 的首个值，用于日志与告警
    pub server_name: String,
    pub server_names: Vec<String>,
    /// `listen ... default_server`：Host 匹配不上时的兜底 vhost
    pub is_default_server: bool,
    pub locations: Vec<Location>,
    pub root: Option<PathBuf>,
    pub index: Vec<String>,
    pub autoindex: bool,
    pub error_pages: HashMap<u16, String>,
    pub client_max_body_size: Option<u64>,
    pub add_headers: Vec<(String, String)>,
    /// server 级 proxy_set_header，作为 location 的默认值
    pub proxy_set_headers: Vec<(String, String)>,
    /// server 级并发限制
    pub limit_conn: Vec<ConnRule>,
    /// server 级 ACCESS IP 规则：location 无自身规则时继承（nginx 语义）
    pub access_rules: Vec<crate::access::AccessRule>,
    pub auth_basic_realm: Option<String>,
    pub auth_basic_user_file: Option<PathBuf>,
    /// `real_ip_header` / `set_real_ip_from` / `real_ip_recursive`（server 级，对标 nginx http/server）
    pub real_ip: crate::realip::RealIpConf,
    /// 前置代理/CDN 感知（`front_proxy_mode` / `front_proxy_auto_trust` + 顶层 profile 表）
    pub front_proxy: crate::front_proxy::FrontProxyConf,
}

/// 一个 server 块的 `ssl_certificate_by_lua*`：握手阶段按 SNI 选中并执行。
/// `names` 是该 server 的 server_name 集合，空表示兜底（无 SNI 命中时使用）。
#[derive(Debug, Clone)]
pub struct SslCertScript {
    pub names: Vec<String>,
    /// 原始指令名（ssl_certificate_by_lua / _file），日志与错误信息用
    pub directive: String,
    pub source: LuaSource,
}

/// 一个真实监听端点
#[derive(Debug, Clone)]
pub struct Listener {
    pub addr: SocketAddr,
    pub tls: Option<TlsOptions>,
    /// 该监听上各 server 的握手脚本（按配置顺序；空 = 不启用）
    pub ssl_cert_scripts: Vec<SslCertScript>,
    /// 明文监听是否接受 h2c（prior-knowledge）；TLS 监听的 h2 由 tls.http2 决定
    pub http2: bool,
    /// `listen ... quic`：该端点用 QUIC/HTTP/3 服务（UDP），隐含 tls=Some。
    /// 同一 addr 的 TCP 监听照常存在；QUIC 端点在 server.rs 里另起 UDP accept 循环。
    pub quic: bool,
    /// `listen ... backlog=N`；None 用全局 accept_backlog
    pub backlog: Option<u32>,
    /// `listen [::]:80 ipv6only=off` 等；None = 默认（仅 IPv6）
    pub ipv6only: Option<bool>,
}

/// `stream{}` 里一条 SNI 路由：命中 pattern（精确或 `*.suffix` 通配）→ 转发到 target。
#[derive(Debug, Clone)]
pub struct SniMatch {
    pub pattern: String,
    pub target: String,
}

/// 顶层 `stream{ server{...} }` 解析出的一条四层监听配置（由 stream.rs 在运行时消费）。
#[derive(Debug, Clone)]
pub struct StreamServer {
    pub listen: SocketAddr,
    pub ssl_preread: bool,
    pub sni_matches: Vec<SniMatch>,
    /// `proxy_pass` 的默认目标（命名 upstream 或 host:port）；也是 SNI 未命中的回落。
    pub default_target: Option<String>,
    pub connect_timeout: std::time::Duration,
    /// 空闲超时（任一方向无活动超过它即断开；0=不限）。
    pub proxy_timeout: std::time::Duration,
    /// 窥探 ClientHello 的读超时。
    pub pread_timeout: std::time::Duration,
}

impl Default for StreamServer {
    fn default() -> Self {
        use std::time::Duration;
        StreamServer {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            ssl_preread: false,
            sni_matches: Vec::new(),
            default_target: None,
            connect_timeout: Duration::from_secs(60),
            proxy_timeout: Duration::from_secs(600),
            pread_timeout: Duration::from_secs(30),
        }
    }
}

/// 某监听地址上的一组虚拟主机；`servers[0]` 是默认 vhost
#[derive(Debug)]
pub struct AddrGroup {
    pub servers: Vec<Arc<Server>>,
}

#[derive(Debug)]
pub struct Router {
    pub groups: HashMap<SocketAddr, AddrGroup>,
    pub listeners: Vec<Listener>,
    pub warnings: Vec<String>,
    /// 顶层 `stream{}` 解析出的四层监听配置（HTTP 路由之外，由 stream.rs 独立服务）。
    pub stream: Vec<StreamServer>,
    /// 顶层 `proxy_cache_path ... keys_zone=name:size` 换算出的每区条目上限
    pub cache_zones: HashMap<String, usize>,
    /// 顶层 `still_online_zone <名称> <容量>;` 换算出的每区**字节**预算。
    /// 副本存的是完整响应体，条数上限约束不了内存，所以这里按字节计。
    pub still_zones: HashMap<String, usize>,
}

/// 一个 server 块里除 listen 之外的所有配置模板
struct ServerTemplate {
    server_name: String,
    server_names: Vec<String>,
    locations: Vec<Location>,
    root: Option<PathBuf>,
    index: Vec<String>,
    autoindex: bool,
    error_pages: HashMap<u16, String>,
    client_max_body_size: Option<u64>,
    add_headers: Vec<(String, String)>,
    proxy_set_headers: Vec<(String, String)>,
    proxy_connect_timeout: std::time::Duration,
    proxy_read_timeout: std::time::Duration,
    proxy_send_timeout: std::time::Duration,
    proxy_next_upstream: Vec<String>,
    proxy_next_upstream_tries: u32,
    proxy_next_upstream_timeout: std::time::Duration,
    proxy_request_buffering: bool,
    proxy_cache: Option<String>,
    proxy_cache_key: String,
    proxy_cache_methods: Vec<String>,
    proxy_cache_valid: Vec<(Vec<String>, std::time::Duration)>,
    proxy_cache_min_uses: u32,
    proxy_cache_lock: bool,
    proxy_cache_lock_timeout: std::time::Duration,
    proxy_cache_use_stale: Vec<String>,
    proxy_cache_bypass: Vec<String>,
    proxy_no_cache: Vec<String>,
    proxy_ignore_headers: Vec<String>,
    still_online: Option<String>,
    still_online_max_age: std::time::Duration,
    still_online_max_body: usize,
    still_online_retry: std::time::Duration,
    still_online_retry_max: std::time::Duration,
    still_online_retry_deadline: std::time::Duration,
    still_online_allow_credentials: bool,
    proxy_tls: TlsPolicy,
    limit_conn: Vec<ConnRule>,
    access_rules: Vec<crate::access::AccessRule>,
    auth_basic_realm: Option<String>,
    auth_basic_user_file: Option<PathBuf>,
    real_ip: crate::realip::RealIpConf,
    front_proxy: crate::front_proxy::FrontProxyConf,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
    ssl_cert_script: Option<SslCertScript>,
    protocols: TlsProtocols,
    http2: bool,
}

#[derive(Debug, Clone, Default)]
struct ListenFlags {
    ssl: bool,
    http2: bool,
    quic: bool,
    default_server: bool,
    backlog: Option<u32>,
    ipv6only: Option<bool>,
}

/// 解析 `listen` 的第一个参数为 SocketAddr
pub fn parse_listen_addr(arg: &str) -> Option<SocketAddr> {
    let a = arg.trim();
    if a.is_empty() {
        return None;
    }
    if let Ok(p) = a.parse::<u16>() {
        return Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, p)));
    }
    if let Some(rest) = a.strip_prefix("*:") {
        let p = rest.parse::<u16>().ok()?;
        return Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, p)));
    }
    a.parse::<SocketAddr>().ok().or_else(|| {
        // `1.2.3.4 8080` 之类的分隔写法不支持；给个明确错误提示
        None
    })
}

fn parse_listen(directive: &Directive) -> Result<(SocketAddr, ListenFlags), AppError> {
    let arg = directive
        .arg(0)
        .ok_or_else(|| AppError::Other("listen 缺少地址/端口".into()))?;
    let addr = parse_listen_addr(arg).ok_or_else(|| {
        AppError::Other(format!(
            "listen 参数无法解析: '{arg}'（支持 8080 / 127.0.0.1:8080 / [::]:8080 / *:8080）"
        ))
    })?;
    let mut f = ListenFlags::default();
    for a in directive.args.iter().skip(1) {
        match a.as_str() {
            "ssl" => f.ssl = true,
            "http2" => f.http2 = true,
            // QUIC 传输强制 TLS1.3（RFC 9001），`quic` 隐含 `ssl`：证书缺失时报错同 ssl 路径
            "quic" => {
                f.quic = true;
                f.ssl = true;
            }
            "default_server" => f.default_server = true,
            other => {
                if let Some(v) = other.strip_prefix("backlog=") {
                    f.backlog = Some(v.parse().map_err(|_| {
                        AppError::Other(format!("listen backlog 取值非法: {other}"))
                    })?);
                } else if let Some(v) = other.strip_prefix("ipv6only=") {
                    f.ipv6only = Some(match v {
                        "on" => true,
                        "off" => false,
                        _ => {
                            return Err(AppError::Other(format!(
                                "listen ipv6only 只接受 on/off，收到 '{v}'"
                            )))
                        }
                    });
                } else {
                    // reuseport/proxy_protocol/setfib 等尚未实现，明确报错而不是静默忽略
                    return Err(AppError::Other(format!(
                        "listen 暂不支持参数 '{other}'（已支持 ssl / http2 / quic / default_server / backlog=N / ipv6only=on|off）"
                    )));
                }
            }
        }
    }
    Ok((addr, f))
}

/// 解析 error_page 指令组：`error_page 404 403 /x.html;`
fn parse_error_pages(d: &Directive) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for ep in collect_error_pages(d) {
        let args: Vec<&str> = ep.args.iter().map(String::as_str).collect();
        let Some(target) = args.iter().rev().find(|a| a.starts_with('/')) else {
            continue;
        };
        for a in &args {
            if let Ok(code) = a.parse::<u16>() {
                map.insert(code, target.to_string());
            }
        }
    }
    map
}

/// error_page 可能出现在块里（server 块）也可能被 include 展开到别处，统一收集
fn collect_error_pages(d: &Directive) -> Vec<&Directive> {
    d.block.iter().filter(|x| x.name == "error_page").collect()
}

/// front_proxy 块里的头部名：与 `real_ip_header` 共用规范化（`$http_x_real_ip` / `X_Real_IP` /
/// `X-Real-IP` 都归一成 `x-real-ip`），但这里额外要求结果非空且只含合法字段名字符——
/// 这个名字接下来要拿去逐个比对请求头，带空格或控制字符的配置必须是错误而不是"查不到"。
fn front_header_name(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    let norm = crate::realip::normalize_header_name(s);
    let ok = !norm.is_empty()
        && norm.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    ok.then_some(norm)
}

/// 解析 nginx 大小后缀：1m / 10k / 1g / 纯字节
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix(['k', 'K']) {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix(['m', 'M']) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix(['g', 'G']) {
        (n, 1024 * 1024 * 1024u64)
    } else {
        (s, 1u64)
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// nginx 时间值：带 ms 精度，0 表示不限（由调用方解释）。
fn parse_time(v: &str, default: std::time::Duration) -> std::time::Duration {
    crate::settings::parse_duration(v).unwrap_or(default)
}

/// nginx 的 proxy_next_upstream 取值；http_XXX 任意三位状态码，其余未知 token 告警忽略。
fn validate_next_upstream(args: &[String], warnings: &mut Vec<String>) {
    for a in args {
        let known = matches!(
            a.as_str(),
            "off" | "error" | "timeout" | "invalid_header" | "non_idempotent"
        ) || a
            .strip_prefix("http_")
            .and_then(|s| s.parse::<u16>().ok())
            .is_some();
        if !known {
            warnings.push(format!("proxy_next_upstream 未识别的取值 '{a}'（已忽略）"));
        }
    }
}

/// `client_max_body_size`：0 在 nginx 里表示"不限制"，这里翻成 u64::MAX 以便覆盖继承值。
fn parse_body_limit(v: &str) -> Option<u64> {
    parse_size(v).map(|n| if n == 0 { u64::MAX } else { n })
}

fn parse_on_off(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" => Some(true),
        "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// REWRITE 阶段有序步骤：`rewrite`/`set`/`if` 按配置书写顺序混排（nginx 的 rewrite 模块
/// 就是这个语义，三种指令互相影响顺序）。location 级专用；server 级暂不参与匹配前阶段。
fn parse_rewrite_steps(
    d: &Directive,
    warnings: &mut Vec<String>,
) -> Result<Vec<RewriteStep>, AppError> {
    let mut out = Vec::new();
    for c in &d.block {
        match c.name.as_str() {
            "rewrite" => out.push(RewriteStep::Rewrite(parse_rewrite_rule(c, warnings)?)),
            "set" => out.push(parse_set(c)?),
            "if" => {
                let cond = parse_if_cond(c)?;
                let mut then = Vec::new();
                for g in &c.block {
                    match g.name.as_str() {
                        "rewrite" => then.push(RewriteStep::Rewrite(parse_rewrite_rule(g, warnings)?)),
                        "set" => then.push(parse_set(g)?),
                        "return" => then.push(RewriteStep::Return(parse_return(g)?)),
                        "if" => {
                            return Err(AppError::Other(format!(
                                "第 {} 行 if 不支持嵌套（nginx 同样禁止）",
                                g.line
                            )))
                        }
                        other => {
                            return Err(AppError::Other(format!(
                                "第 {} 行 if 块内只允许 rewrite/set/return，出现 '{other}'",
                                g.line
                            )))
                        }
                    }
                }
                out.push(RewriteStep::If { cond, then });
            }
            _ => {}
        }
    }
    Ok(out)
}

fn parse_rewrite_rule(r: &Directive, warnings: &mut Vec<String>) -> Result<RewriteRule, AppError> {
    let pattern = r
        .arg(0)
        .ok_or_else(|| AppError::Other(format!("第 {} 行 rewrite 缺少 pattern", r.line)))?;
    let replacement = r
        .arg(1)
        .ok_or_else(|| AppError::Other(format!("第 {} 行 rewrite 缺少 replacement", r.line)))?;
    let flag = match r.arg(2) {
        Some("last") => RewriteFlag::Last,
        Some("break") => RewriteFlag::Break,
        Some("redirect") => RewriteFlag::Redirect,
        Some("permanent") => RewriteFlag::Permanent,
        None => RewriteFlag::Last,
        Some(other) => {
            warnings.push(format!(
                "rewrite 标志 '{other}'（第 {} 行）不支持，按 last 处理",
                r.line
            ));
            RewriteFlag::Last
        }
    };
    Ok(RewriteRule {
        pattern: regex::Regex::new(pattern)
            .map_err(|e| AppError::Other(format!("rewrite 正则错误 {pattern}: {e}")))?,
        replacement: replacement.to_string(),
        flag,
    })
}

/// `set $name value;`：value 可以带变量，运行期展开一次。
fn parse_set(d: &Directive) -> Result<RewriteStep, AppError> {
    let raw = d
        .arg(0)
        .ok_or_else(|| AppError::Other(format!("第 {} 行 set 缺少 $变量名", d.line)))?;
    let name = raw.strip_prefix('$').ok_or_else(|| {
        AppError::Other(format!("第 {} 行 set 的目标必须是 $变量，写成 '{raw}'", d.line))
    })?;
    if name.is_empty()
        || name.as_bytes()[0].is_ascii_digit()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(AppError::Other(format!(
            "第 {} 行 set 的变量名 '{raw}' 非法（只允许字母、数字、下划线，且不能以数字开头）",
            d.line
        )));
    }
    if d.args.len() < 2 {
        return Err(AppError::Other(format!(
            "第 {} 行 set ${name} 缺少值（nginx 要求两个参数）",
            d.line
        )));
    }
    Ok(RewriteStep::Set {
        name: name.to_string(),
        value: d.args[1..].join(" "),
    })
}

/// nginx 的 `if` 用括号包住条件，但词法器不把 `()` 当分隔符，所以要手工剥掉。
/// 引号里的内容不会被并进括号 token（`"a")` 会拆成 Quoted("a") + Word(")")），因此安全。
fn strip_if_parens(args: &[String]) -> Vec<String> {
    let mut v: Vec<String> = args.to_vec();
    if let Some(first) = v.first_mut() {
        *first = first.trim_start_matches('(').to_string();
    }
    if let Some(last) = v.last_mut() {
        *last = last.trim_end_matches(')').to_string();
    }
    v.retain(|s| !s.is_empty());
    v
}

fn parse_if_cond(d: &Directive) -> Result<IfCond, AppError> {
    if d.block.is_empty() {
        return Err(AppError::Other(format!(
            "第 {} 行 if 需要 `{{ ... }}` 块（nginx 的 if 只能包指令块）",
            d.line
        )));
    }
    let toks = strip_if_parens(&d.args);
    let Some(first) = toks.first() else {
        return Err(AppError::Other(format!(
            "第 {} 行 if 缺少条件变量",
            d.line
        )));
    };
    if first.starts_with('-') || first.starts_with("!-") {
        return Err(AppError::Other(format!(
            "第 {} 行 if 的文件测试（-f/-d/-e/-x 及 !-f 等）ONRouter 不支持；请用 try_files 或 Lua 的 io.open",
            d.line
        )));
    }
    let (neg, lhs) = match first.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, first.as_str()),
    };
    if !lhs.starts_with('$') {
        return Err(AppError::Other(format!(
            "第 {} 行 if 的左值必须是变量，写成 '{first}'",
            d.line
        )));
    }
    let Some(op) = toks.get(1) else {
        return Ok(IfCond {
            lhs: lhs.to_string(),
            op: if neg { CondOp::Empty } else { CondOp::NonEmpty },
            rhs: None,
        });
    };
    if neg {
        return Err(AppError::Other(format!(
            "第 {} 行 if 的 '!' 只能单独判断变量真假，或对正则取反（!~ / !~*）",
            d.line
        )));
    }
    let rhs_text = if toks.len() > 2 {
        Some(toks[2..].join(" "))
    } else {
        None
    };
    // 空右值一律拒绝：nginx 里 `if ($x = )` 是语法错误，而不是"和空串比"
    let rhs = rhs_text.as_deref().ok_or_else(|| {
        AppError::Other(format!("第 {} 行 if 的比较 '{op}' 缺少右值", d.line))
    })?;
    let build = |pat: &str, ci: bool| -> Result<regex::Regex, AppError> {
        regex::RegexBuilder::new(pat)
            .case_insensitive(ci)
            .build()
            .map_err(|e| AppError::Other(format!("第 {} 行 if 正则错误 {pat}: {e}", d.line)))
    };
    let literal = rhs.to_string();
    let op = match op.as_str() {
        "=" => CondOp::Eq,
        "!=" => CondOp::Ne,
        "~" => CondOp::Regex(build(rhs, false)?),
        "~*" => CondOp::IRegex(build(rhs, true)?),
        "!~" => CondOp::NotRegex(build(rhs, false)?),
        "!~*" => CondOp::NotIRegex(build(rhs, true)?),
        other => {
            return Err(AppError::Other(format!(
                "第 {} 行 if 不支持的比较符 '{other}'（可用：= != ~ ~* !~ !~*）",
                d.line
            )))
        }
    };
    Ok(IfCond {
        lhs: lhs.to_string(),
        op,
        rhs: match toks[1].as_str() {
            "=" | "!=" => Some(literal),
            _ => None,
        },
    })
}

/// `return code [text];` / `return url;`（后者按 302）
fn parse_return(d: &Directive) -> Result<ReturnAction, AppError> {
    match d.arg(0).and_then(|s| s.parse::<u16>().ok()) {
        Some(code) => Ok(ReturnAction {
            code,
            text: d.arg(1).map(|s| s.to_string()),
        }),
        None => match d.arg(0) {
            Some(url) => Ok(ReturnAction {
                code: 302,
                text: Some(url.to_string()),
            }),
            None => Err(AppError::Other(format!(
                "第 {} 行 return 缺少参数",
                d.line
            ))),
        },
    }
}

/// 解析顶层 `ssl_session_cache`：
///   off | none | builtin[:条数] | shared:名称:容量
/// nginx 允许 builtin 与 shared 并存；这里只保留最后一个并告警（单后端不做复合缓存）。
fn parse_session_cache(config: &Config, warnings: &mut Vec<String>) -> SessionCache {
    let mut result = SessionCache::default();
    for d in config
        .root
        .block
        .iter()
        .filter(|d| d.name == "ssl_session_cache")
    {
        if d.args.is_empty() {
            warnings.push(format!(
                "第 {} 行 ssl_session_cache 缺少参数（off/builtin[:n]/shared:name:size）",
                d.line
            ));
            continue;
        }
        let mut chosen = 0usize;
        for tok in &d.args {
            let lower = tok.to_ascii_lowercase();
            let parsed = if lower == "off" || lower == "none" {
                Some(SessionCache::Off)
            } else if lower == "builtin" {
                Some(SessionCache::Builtin(256))
            } else if let Some(n) = lower.strip_prefix("builtin:") {
                match n.parse::<usize>() {
                    Ok(v) if v > 0 => Some(SessionCache::Builtin(v)),
                    _ => {
                        warnings.push(format!(
                            "第 {} 行 ssl_session_cache builtin 条数非法 '{tok}'，按 256 处理",
                            d.line
                        ));
                        Some(SessionCache::Builtin(256))
                    }
                }
            } else if lower.starts_with("shared:") {
                let rest = &tok["shared:".len()..];
                match rest.rsplit_once(':') {
                    Some((name, size)) if !name.is_empty() => match parse_size(size) {
                        Some(bytes) if bytes > 0 => Some(SessionCache::Shared {
                            name: name.to_string(),
                            // nginx 的容量单位是字节；rustls 按会话条数计，按每会话约 512B 折算
                            capacity: ((bytes / 512).clamp(64, 1_000_000)) as usize,
                        }),
                        _ => {
                            warnings.push(format!(
                                "第 {} 行 ssl_session_cache 容量非法 '{size}'（应如 10m）",
                                d.line
                            ));
                            None
                        }
                    },
                    _ => {
                        warnings.push(format!(
                            "第 {} 行 ssl_session_cache 格式应为 shared:名称:容量（收到 '{tok}'）",
                            d.line
                        ));
                        None
                    }
                }
            } else {
                warnings.push(format!(
                    "第 {} 行 ssl_session_cache 无法识别 '{tok}'（支持 off/builtin[:n]/shared:name:size）",
                    d.line
                ));
                None
            };
            if let Some(p) = parsed {
                if chosen > 0 {
                    warnings.push(format!(
                        "第 {} 行 ssl_session_cache 配置了多种模式，ONRouter 只采用最后一个",
                        d.line
                    ));
                }
                result = p;
                chosen += 1;
            }
        }
    }
    result
}

/// 顶层 `ssl_session_tickets on|off`（nginx 默认 on）。
fn parse_session_tickets(config: &Config, warnings: &mut Vec<String>) -> bool {
    let mut on = true;
    for d in config
        .root
        .block
        .iter()
        .filter(|d| d.name == "ssl_session_tickets")
    {
        match d.arg(0).and_then(|v| parse_on_off(v)) {
            Some(v) => on = v,
            None => warnings.push(format!(
                "第 {} 行 ssl_session_tickets 只接受 on/off（收到 '{}'），保持 {}",
                d.line,
                d.arg(0).unwrap_or(""),
                if on { "on" } else { "off" }
            )),
        }
    }
    on
}

/// 组装本进程所有 TLS 监听共用的会话设施。
/// tickets 开 → 整个进程一份 ticket 密钥（跨端口可无状态恢复）；
/// shared → 整个进程一份内存缓存，而非每个监听各建一份。
fn parse_session_options(config: &Config, warnings: &mut Vec<String>) -> SessionOptions {
    let cache = parse_session_cache(config, warnings);
    let tickets = parse_session_tickets(config, warnings);
    let shared_store = match &cache {
        SessionCache::Shared { capacity, .. } => {
            let store: std::sync::Arc<dyn rustls::server::StoresServerSessions> =
                rustls::server::ServerSessionMemoryCache::new((*capacity).max(1));
            Some(store)
        }
        _ => None,
    };
    let ticketer = if tickets {
        match rustls::crypto::ring::Ticketer::new() {
            Ok(t) => Some(t),
            Err(e) => {
                warnings.push(format!(
                    "TLS ticketer 初始化失败（{e}），回退到有状态会话缓存"
                ));
                None
            }
        }
    } else {
        None
    };
    SessionOptions {
        cache,
        tickets,
        shared_store,
        ticketer,
    }
}

/// 解析 `proxy_ssl_*`：把 https/wss 后端的客户端 TLS 策略就地应用到 `policy`。
/// server 与 location 级共用；未写的指令保持传入值（location 缺省继承 server 级）。
/// - `proxy_ssl_verify on|off`（默认 on）：off → 不校验后端证书（自签/内网）
/// - `proxy_ssl_server_name on|off`（默认 on）：本实现下 rustls 客户端总会发 SNI，故仅作记录
/// - `proxy_ssl_name <host>`：覆盖 SNI/校验主机名（默认取 proxy_pass 的 host）
/// - `proxy_ssl_trusted_certificate <path>`：PEM CA 束（verify on 时必需；相对 conf 目录解析）
fn parse_proxy_ssl_directives(
    d: &Directive,
    base_dir: &PathBuf,
    warnings: &mut Vec<String>,
    policy: &mut TlsPolicy,
) {
    if let Some(v) = d.find("proxy_ssl_verify").and_then(|x| x.arg(0)) {
        match parse_on_off(v) {
            Some(b) => policy.verify = b,
            None => warnings.push(format!(
                "proxy_ssl_verify 只接受 on/off（收到 '{v}'），保持 {}",
                if policy.verify { "on" } else { "off" }
            )),
        }
    }
    if let Some(v) = d.find("proxy_ssl_server_name").and_then(|x| x.arg(0)) {
        match parse_on_off(v) {
            Some(b) => policy.send_sni = b,
            None => warnings.push(format!(
                "proxy_ssl_server_name 只接受 on/off（收到 '{v}'），保持 {}",
                if policy.send_sni { "on" } else { "off" }
            )),
        }
    }
    if let Some(v) = d.find("proxy_ssl_name").and_then(|x| x.arg(0)) {
        policy.server_name = Some(v.to_string());
    }
    if let Some(v) = d.find("proxy_ssl_trusted_certificate").and_then(|x| x.arg(0)) {
        let p = crate::resolve_path(v, base_dir);
        policy.trusted_cert = Some(p.to_string_lossy().into_owned());
    }
    if let Some(v) = d.find("proxy_ssl_certificate").and_then(|x| x.arg(0)) {
        let p = crate::resolve_path(v, base_dir);
        policy.client_cert = Some(p.to_string_lossy().into_owned());
    }
    if let Some(v) = d.find("proxy_ssl_certificate_key").and_then(|x| x.arg(0)) {
        let p = crate::resolve_path(v, base_dir);
        policy.client_key = Some(p.to_string_lossy().into_owned());
    }
}

/// `proxy_cache*` 指令的解析产物：字段用 Option 表示"本块是否显式指定"，
/// 以便 location 缺省时继承 server 级（nginx 的 location 可覆盖 http/server 值）。
struct CacheSettings {
    /// None=未写；Some(None)=写了 `off`；Some(Some(zone))=写了区名
    zone: Option<Option<String>>,
    key: Option<String>,
    methods: Option<Vec<String>>,
    valid: Vec<(Vec<String>, std::time::Duration)>,
    has_valid: bool,
    min_uses: Option<u32>,
    lock: Option<bool>,
    lock_timeout: Option<std::time::Duration>,
    use_stale: Option<Vec<String>>,
    bypass: Option<Vec<String>>,
    no_cache: Option<Vec<String>>,
    ignore_headers: Option<Vec<String>>,
}

/// nginx `proxy_ignore_headers` 能忽略的响应头（官方文档列出的九个，小写比较）。
/// ONRouter 里只有 Cache-Control/Expires/Set-Cookie 真正参与缓存判定：X-Accel-* 与 Vary
/// 本来就没有对应的处理路径，接受这些词只是让 nginx 配置能原样搬过来。
const IGNOREABLE_HEADERS: &[&str] = &[
    "cache-control",
    "expires",
    "set-cookie",
    "vary",
    "x-accel-expires",
    "x-accel-redirect",
    "x-accel-limit-rate",
    "x-accel-buffering",
    "x-accel-charset",
];

fn parse_cache_directives(d: &Directive, warnings: &mut Vec<String>) -> CacheSettings {
    let mut cs = CacheSettings {
        zone: None,
        key: None,
        methods: None,
        valid: Vec::new(),
        has_valid: false,
        min_uses: None,
        lock: None,
        lock_timeout: None,
        use_stale: None,
        bypass: None,
        no_cache: None,
        ignore_headers: None,
    };
    if let Some(v) = d.find("proxy_cache").and_then(|x| x.arg(0)) {
        cs.zone = Some(if v.eq_ignore_ascii_case("off") {
            None
        } else {
            Some(v.to_string())
        });
    }
    if let Some(v) = d.find("proxy_cache_key").and_then(|x| x.arg(0)) {
        cs.key = Some(v.to_string());
    }
    if let Some(m) = d.find("proxy_cache_methods") {
        if !m.args.is_empty() {
            cs.methods = Some(m.args.iter().map(|a| a.to_ascii_uppercase()).collect());
        }
    }
    // proxy_cache_valid 可多行：`proxy_cache_valid 200 302 10m;` / `proxy_cache_valid any 1m;`
    for vd in d.block.iter().filter(|x| x.name == "proxy_cache_valid") {
        if vd.args.len() < 2 {
            warnings.push(format!(
                "第 {} 行 proxy_cache_valid 需要 `<码...> <时长>`，已忽略",
                vd.line
            ));
            continue;
        }
        let (time_arg, code_args) = vd.args.split_last().unwrap();
        match crate::settings::parse_duration(time_arg) {
            Some(dur) => cs.valid.push((code_args.to_vec(), dur)),
            None => warnings.push(format!(
                "第 {} 行 proxy_cache_valid 时长非法 '{time_arg}'，已忽略",
                vd.line
            )),
        }
        cs.has_valid = true;
    }
    if let Some(v) = d.find("proxy_cache_min_uses").and_then(|x| x.arg(0)) {
        match v.parse::<u32>() {
            Ok(n) if n >= 1 => cs.min_uses = Some(n),
            _ => warnings.push(format!("proxy_cache_min_uses 需为 ≥1 整数，已忽略 '{v}'")),
        }
    }
    if let Some(v) = d.find("proxy_cache_lock").and_then(|x| x.arg(0)) {
        match parse_on_off(v) {
            Some(b) => cs.lock = Some(b),
            None => warnings.push(format!("proxy_cache_lock 只接受 on/off（收到 '{v}'），保持 off")),
        }
    }
    if let Some(v) = d.find("proxy_cache_lock_timeout").and_then(|x| x.arg(0)) {
        match crate::settings::parse_duration(v) {
            Some(dur) => cs.lock_timeout = Some(dur),
            None => warnings.push(format!(
                "proxy_cache_lock_timeout 时长非法 '{v}'，保持 5s"
            )),
        }
    }
    if let Some(u) = d.find("proxy_cache_use_stale") {
        let mut tokens: Vec<String> = Vec::new();
        for a in &u.args {
            let t = a.to_ascii_lowercase();
            let valid = matches!(
                t.as_str(),
                "off" | "error"
                    | "timeout"
                    | "updating"
                    | "invalid_header"
                    | "http_403"
                    | "http_404"
                    | "http_429"
                    | "http_500"
                    | "http_501"
                    | "http_502"
                    | "http_503"
                    | "http_504"
                    | "http_505"
            );
            if valid {
                tokens.push(t);
            } else {
                warnings.push(format!(
                    "第 {} 行 proxy_cache_use_stale 不支持 '{a}'，已忽略",
                    u.line
                ));
            }
        }
        // nginx：`off` 与其他值混写时只有 off 生效
        if tokens.iter().any(|t| t == "off") {
            tokens.clear();
        }
        cs.use_stale = Some(tokens);
    }
    if let Some(b) = d.find("proxy_cache_bypass") {
        cs.bypass = Some(b.args.clone());
    }
    if let Some(n) = d.find("proxy_no_cache") {
        cs.no_cache = Some(n.args.clone());
    }
    if let Some(i) = d.find("proxy_ignore_headers") {
        let mut names = Vec::new();
        for a in &i.args {
            let low = a.to_ascii_lowercase();
            if IGNOREABLE_HEADERS.contains(&low.as_str()) {
                if !names.contains(&low) {
                    names.push(low);
                }
            } else {
                warnings.push(format!(
                    "proxy_ignore_headers: 无法忽略 \"{a}\"（nginx 只认 {}），该词已丢弃",
                    IGNOREABLE_HEADERS.join("、")
                ));
            }
        }
        cs.ignore_headers = Some(names);
    }
    cs
}

/// still_online 的默认保留期与单条上限；写在这里便于 `-t` 输出与文档口径一致。
pub const STILL_ONLINE_DEFAULT_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(7 * 24 * 3600);
pub const STILL_ONLINE_DEFAULT_MAX_BODY: usize = 1024 * 1024;

/// `still_online*` 指令产物：None 表示本块没写，location 缺省时继承 server 级。
struct StillOnlineSettings {
    /// None=未写；Some(None)=写了 `off`；Some(Some(zone))=写了区名
    zone: Option<Option<String>>,
    max_age: Option<std::time::Duration>,
    max_body: Option<usize>,
    retry: Option<std::time::Duration>,
    retry_max: Option<std::time::Duration>,
    retry_deadline: Option<std::time::Duration>,
    allow_credentials: Option<bool>,
}

fn parse_still_online_directives(
    d: &Directive,
    warnings: &mut Vec<String>,
    inherited_zone: bool,
) -> StillOnlineSettings {
    let mut s = StillOnlineSettings {
        zone: None,
        max_age: None,
        max_body: None,
        retry: None,
        retry_max: None,
        retry_deadline: None,
        allow_credentials: None,
    };
    if let Some(v) = d.find("still_online").and_then(|x| x.arg(0)) {
        s.zone = Some(if v == "off" { None } else { Some(v.to_string()) });
    }
    if let Some(v) = d.find("still_online_max_age").and_then(|x| x.arg(0)) {
        match crate::settings::parse_duration(v) {
            Some(dur) => s.max_age = Some(dur),
            None => warnings.push(format!(
                "still_online_max_age 时长非法 '{v}'，保持 {}",
                STILL_ONLINE_DEFAULT_MAX_AGE.as_secs()
            )),
        }
    }
    if let Some(v) = d.find("still_online_max_body").and_then(|x| x.arg(0)) {
        match parse_size(v) {
            Some(n) if n > 0 => s.max_body = Some(n as usize),
            _ => warnings.push(format!(
                "still_online_max_body 需为 >0 的大小（如 512k/2m），已忽略 '{v}'"
            )),
        }
    }
    for (name, slot) in [
        ("still_online_retry", &mut s.retry),
        ("still_online_retry_max", &mut s.retry_max),
        ("still_online_retry_deadline", &mut s.retry_deadline),
    ] {
        if let Some(v) = d.find(name).and_then(|x| x.arg(0)) {
            match crate::settings::parse_duration(v) {
                Some(dur) => *slot = Some(dur),
                None => warnings.push(format!("{name} 时长非法 '{v}'，已忽略")),
            }
        }
    }
    if let Some(v) = d
        .find("still_online_allow_credentials")
        .and_then(|x| x.arg(0))
    {
        match parse_on_off(v) {
            Some(b) => s.allow_credentials = Some(b),
            None => warnings.push(format!(
                "still_online_allow_credentials 只接受 on/off（收到 '{v}'），保持 off"
            )),
        }
    }
    // 本块最终是否真的有区：写了 zone（且不是 off）＞ 从 server 级继承
    let zone_here = s
        .zone
        .clone()
        .map(|z| z.is_some())
        .unwrap_or(inherited_zone);
    if !zone_here && d.block.iter().any(|c| c.name.starts_with("still_online_")) {
        // 没开区却写了子参数：整组不会生效，必须留痕而不是静默
        warnings.push(format!(
            "第 {} 行块内的 still_online_* 参数不会生效（缺少 still_online <区> 指令，或它写成了 off）",
            d.line
        ));
    }
    s
}

impl Router {
    pub fn build(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        Self::build_with_listeners(config, base_dir, None).map(|(r, _)| r)
    }

    /// 热重载：复用进程已绑定的监听集合，只按新配置重建 vhost/location 路由表。
    /// reload 期间从不触碰 listen socket（无 accept 空窗），因此新增/改动的
    /// server/location 对新请求立即生效；配置里新引入的监听地址不会被绑定（需重启）。
    ///
    /// 额外返回**新配置解析出的监听参数**（证书路径、协议集合、ssl_certificate_by_lua
    /// 脚本），供 TLS 层原地刷新证书。Router.listeners 仍保留已绑定集合，不重新 bind。
    pub fn rebuild_routing_with_specs(
        config: &Config,
        base_dir: &PathBuf,
        listeners: &[Listener],
    ) -> Result<(Self, Vec<Listener>), AppError> {
        Self::build_with_listeners(config, base_dir, Some(listeners.to_vec()))
    }

    /// 解析顶层 `map $source $dest { ... }` 块为 MapDef 列表。
    /// 分支语法：`default <val>;`、`<literal> <val>;`、`~<regex> <val>;`、`~*<regex> <val>;`。
    fn parse_maps(config: &Config, warnings: &mut Vec<String>) -> Result<Vec<MapDef>, AppError> {
        let mut defs = Vec::new();
        for d in config.root.block.iter().filter(|d| d.name == "map") {
            let source = d.arg(0).ok_or_else(|| {
                AppError::Other(format!("map（第 {} 行）缺少源变量", d.line))
            })?;
            let dest = d
                .arg(1)
                .ok_or_else(|| AppError::Other(format!("map {source}（第 {} 行）缺少目标变量", d.line)))?;
            let source = source.trim_start_matches('$').to_string();
            let dest = dest.trim_start_matches('$').to_string();
            if dest.is_empty() || source.is_empty() {
                return Err(AppError::Other(format!("map 需要源与目标两个变量（第 {} 行）", d.line)));
            }
            let mut default: Option<String> = None;
            let mut cases: Vec<MapCase> = Vec::new();
            for c in &d.block {
                let result = c.args.first().cloned().unwrap_or_default();
                if c.name == "default" {
                    default = Some(result);
                    continue;
                }
                if let Some(pat) = c.name.strip_prefix("~*") {
                    let re = regex::RegexBuilder::new(pat)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| AppError::Other(format!("map {dest} 正则错误 {pat}: {e}")))?;
                    cases.push(MapCase { literal: None, regex: Some(re), result });
                } else if let Some(pat) = c.name.strip_prefix('~') {
                    let re = regex::Regex::new(pat)
                        .map_err(|e| AppError::Other(format!("map {dest} 正则错误 {pat}: {e}")))?;
                    cases.push(MapCase { literal: None, regex: Some(re), result });
                } else {
                    // 精确串匹配（含 `=` 前缀的显式精确写法与空串 `""`）
                    let lit = c.name.strip_prefix('=').unwrap_or(&c.name).to_string();
                    cases.push(MapCase { literal: Some(lit), regex: None, result });
                }
            }
            if !default.is_some() && cases.is_empty() {
                warnings.push(format!("map {source} → {dest}（第 {} 行）没有任何分支，目标恒为空串", d.line));
            }
            defs.push(MapDef { dest, source, default, cases });
        }
        Ok(defs)
    }

    /// 解析顶层 `geo [$source] $dest { ... }` 块为 GeoDef 列表。
    /// 分支语法：`default <val>;`、`<ip>/<prefix> <val>;`、`<ip> <val>;`。
    /// 规则按前缀长度降序排列，令最长前缀（最具体）优先命中（对齐 ngx_geo）。
    fn parse_geos(config: &Config, warnings: &mut Vec<String>) -> Result<Vec<GeoDef>, AppError> {
        let mut defs = Vec::new();
        for d in config.root.block.iter().filter(|d| d.name == "geo") {
            let (source_raw, dest_raw) = match d.args.len() {
                1 => ("$remote_addr".to_string(), d.args[0].clone()),
                2 => (d.args[0].clone(), d.args[1].clone()),
                _ => {
                    return Err(AppError::Other(format!(
                        "geo 需要 1 或 2 个变量参数（第 {} 行）",
                        d.line
                    )))
                }
            };
            let source = source_raw.trim_start_matches('$').to_string();
            let dest = dest_raw.trim_start_matches('$').to_string();
            if dest.is_empty() || source.is_empty() {
                return Err(AppError::Other(format!("geo 目标/源变量为空（第 {} 行）", d.line)));
            }
            let mut default: Option<String> = None;
            let mut rules: Vec<GeoRule> = Vec::new();
            for c in &d.block {
                let result = c.args.first().cloned().unwrap_or_default();
                if c.name == "default" {
                    default = Some(result);
                    continue;
                }
                // 解析 `<ip>[/<prefix>]`
                let (addr_str, prefix_str) = match c.name.split_once('/') {
                    Some((a, p)) => (a, Some(p)),
                    None => (c.name.as_str(), None),
                };
                let ip: std::net::IpAddr = addr_str.parse().map_err(|_| {
                    AppError::Other(format!("geo {dest} 非法 IP '{addr_str}'（第 {} 行）", c.line))
                })?;
                let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
                let prefix: u8 = match prefix_str {
                    Some(p) => p.parse().map_err(|_| {
                        AppError::Other(format!("geo {dest} 非法前缀 '{p}'（第 {} 行）", c.line))
                    })?,
                    None => width,
                };
                if prefix > width {
                    return Err(AppError::Other(format!(
                        "geo {dest} 前缀 /{prefix} 超出 {width} 位上限（第 {} 行）",
                        c.line
                    )));
                }
                rules.push(GeoRule { ip, prefix, result });
            }
            // 最长前缀优先；前缀相同保持声明顺序（稳定排序）
            rules.sort_by(|a, b| b.prefix.cmp(&a.prefix));
            if default.is_none() && rules.is_empty() {
                warnings.push(format!("geo {source} → {dest}（第 {} 行）没有任何规则，目标恒为空串", d.line));
            }
            defs.push(GeoDef { dest, source, default, rules });
        }
        Ok(defs)
    }

    /// 解析顶层 `front_proxy <名字> { ... }` 块为 profile 表。
    ///
    /// 这里刻意不认任何厂商：块里声明的只有两件事——"这一家用哪些头证明它是它"（`probe`）、
    /// "对端落在哪些网段时它说的话可以信"（`trust`），以及各角色的头名（`ip_header` /
    /// `country_header` / `proto_header` / `host_header`）。厂商改名或换网段是改配置，不是改代码。
    fn parse_front_proxies(
        config: &Config,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<std::sync::Arc<crate::front_proxy::FrontProfile>>, AppError> {
        use crate::front_proxy::{FrontProfile, Probe};
        const INNER: &[&str] =
            &["probe", "ip_header", "country_header", "proto_header", "host_header", "trust"];
        let mut out: Vec<std::sync::Arc<FrontProfile>> = Vec::new();
        for d in config.root.block.iter().filter(|d| d.name == "front_proxy") {
            let name = d
                .arg(0)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::Other(format!(
                        "第 {} 行 front_proxy 缺少名字（front_proxy <名字> {{ … }}）",
                        d.line
                    ))
                })?;
            if out.iter().any(|p| p.name.eq_ignore_ascii_case(&name)) {
                return Err(AppError::Other(format!(
                    "第 {} 行 front_proxy '{name}' 重复声明：同名 profile 会让指标与告警分不出是哪一家",
                    d.line
                )));
            }
            Self::warn_unknown(d, INNER, "front_proxy", warnings);
            let mut p = FrontProfile {
                name: name.clone(),
                probes: Vec::new(),
                ip_headers: Vec::new(),
                country_header: None,
                proto_header: None,
                host_header: None,
                trust: Vec::new(),
                counters: Default::default(),
            };
            for c in d.block.iter().filter(|x| x.name == "probe") {
                let header = front_header_name(c.arg(0)).ok_or_else(|| {
                    AppError::Other(format!(
                        "第 {} 行 probe 缺少合法的头部名（只允许字母数字与 -_）",
                        c.line
                    ))
                })?;
                let substr = match (c.arg(1), c.arg(2)) {
                    (Some(op), Some(v)) if op.trim() == "~" => Some(v.to_ascii_lowercase()),
                    (Some(op), _) => {
                        return Err(AppError::Other(format!(
                            "第 {} 行 probe '{header}' 的第二参数只接受 '~ <值包含的子串>'（收到 '{op}'）",
                            c.line
                        )))
                    }
                    (None, Some(v)) => {
                        return Err(AppError::Other(format!(
                            "第 {} 行 probe '{header}' 的取值 '{v}' 缺少 '~' 前缀",
                            c.line
                        )))
                    }
                    (None, None) => None,
                };
                if p.probes.iter().any(|e| e.header == header) {
                    return Err(AppError::Other(format!(
                        "第 {} 行 front_proxy '{name}' 对 '{header}' 声明了两个探针，AND 语义下前一个永远无效",
                        c.line
                    )));
                }
                p.probes.push(Probe { header, substr });
            }
            for c in d.block.iter().filter(|x| x.name == "ip_header") {
                let header = front_header_name(c.arg(0)).ok_or_else(|| {
                    AppError::Other(format!(
                        "第 {} 行 ip_header 缺少合法的头部名（只允许字母数字与 -_）",
                        c.line
                    ))
                })?;
                if p.ip_headers.iter().any(|h| h == &header) {
                    warnings.push(format!(
                        "第 {} 行 front_proxy '{name}' 的 ip_header '{header}' 重复，按链只算一次",
                        c.line
                    ));
                    continue;
                }
                p.ip_headers.push(header);
            }
            for (directive, slot) in
                [("country_header", 0usize), ("proto_header", 1), ("host_header", 2)]
            {
                let hits: Vec<&Directive> =
                    d.block.iter().filter(|x| x.name == directive).collect();
                let Some(first) = hits.first() else { continue };
                let header = front_header_name(first.arg(0)).ok_or_else(|| {
                    AppError::Other(format!(
                        "第 {} 行 {directive} 缺少合法的头部名（只允许字母数字与 -_）",
                        first.line
                    ))
                })?;
                if hits.len() > 1 {
                    warnings.push(format!(
                        "第 {} 行 front_proxy '{name}' 写了 {} 条 {directive}，只有第一条生效",
                        d.line,
                        hits.len()
                    ));
                }
                match slot {
                    0 => p.country_header = Some(header),
                    1 => p.proto_header = Some(header),
                    _ => p.host_header = Some(header),
                }
            }
            for c in d.block.iter().filter(|x| x.name == "trust") {
                for a in &c.args {
                    match crate::realip::parse_trusted_net(a) {
                        Some(n) => p.trust.push(n),
                        None => {
                            return Err(AppError::Other(format!(
                                "第 {} 行 front_proxy '{name}' 的 trust '{a}' 不是合法地址/网段。\
                                 这里不能用告警放过：网段写错变成空集，等于整个来源验证失效（退回按节点地址计数），\
                                 而配置里看起来却像配好了",
                                c.line
                            )))
                        }
                    }
                }
            }
            if p.probes.is_empty() {
                warnings.push(format!(
                    "front_proxy '{name}'（第 {} 行）没有任何 probe：无法识别，这条 profile 永远命中不了，\
                     请至少写一条 probe <厂商专有头>",
                    d.line
                ));
            }
            if p.ip_headers.is_empty() {
                warnings.push(format!(
                    "front_proxy '{name}'（第 {} 行）没有 ip_header：egress 模式下取不到真实客户端地址，\
                     只能用于识别与协议/Host 还原",
                    d.line
                ));
            }
            out.push(std::sync::Arc::new(p));
        }
        Ok(out)
    }

    /// 解析顶层 `split_clients <key> $dest { ... }` 块为 SplitDef 列表。
    /// 分支语法：`<percent>% <result>;` 与 `* <result>;`（兜底桶）。
    /// 权重按声明顺序累加落桶（对齐 ngx_split_clients）。
    fn parse_splits(config: &Config, warnings: &mut Vec<String>) -> Result<Vec<SplitDef>, AppError> {
        let mut defs = Vec::new();
        for d in config.root.block.iter().filter(|d| d.name == "split_clients") {
            let key = d
                .arg(0)
                .ok_or_else(|| {
                    AppError::Other(format!(
                        "split_clients（第 {} 行）缺少键模板",
                        d.line
                    ))
                })?
                .to_string();
            let dest_raw = d.arg(1).ok_or_else(|| {
                AppError::Other(format!(
                    "split_clients {key}（第 {} 行）缺少目标变量",
                    d.line
                ))
            })?;
            let dest = dest_raw.trim_start_matches('$').to_string();
            if dest.is_empty() {
                return Err(AppError::Other(format!(
                    "split_clients 目标变量为空（第 {} 行）",
                    d.line
                )));
            }
            let mut buckets: Vec<SplitBucket> = Vec::new();
            let mut star: Option<String> = None;
            let mut sum: f64 = 0.0;
            for c in &d.block {
                let result = c.args.first().cloned().unwrap_or_default();
                if c.name == "*" {
                    star = Some(result);
                    continue;
                }
                // c.name 形如 "0.5%" 或 "2%"
                let pct_str = c.name.trim_end_matches('%');
                let percent: f64 = pct_str.parse().map_err(|_| {
                    AppError::Other(format!(
                        "split_clients {dest} 非法权重 '{}'（第 {} 行）",
                        c.name, c.line
                    ))
                })?;
                if percent <= 0.0 {
                    return Err(AppError::Other(format!(
                        "split_clients {dest} 权重须为正数（第 {} 行）",
                        c.line
                    )));
                }
                sum += percent;
                buckets.push(SplitBucket { percent, result });
            }
            if star.is_none() && buckets.is_empty() {
                warnings.push(format!(
                    "split_clients {key} → {dest}（第 {} 行）没有任何分桶，目标恒为空串",
                    d.line
                ));
            }
            if sum > 100.0001 {
                warnings.push(format!(
                    "split_clients {dest}（第 {} 行）权重合计 {:.3}% 超过 100%，超出部分永不命中",
                    d.line,
                    sum
                ));
            }
            defs.push(SplitDef { dest, key, buckets, star });
        }
        Ok(defs)
    }

    fn build_with_listeners(
        config: &Config,
        base_dir: &PathBuf,
        listener_override: Option<Vec<Listener>>,
    ) -> Result<(Self, Vec<Listener>), AppError> {
        let mut warnings: Vec<String> = Vec::new();
        Self::warn_unknown_top_level(config, &mut warnings);
        // TLS 会话恢复策略是进程级的：所有监听共享同一份缓存/ticket 密钥
        let session = parse_session_options(config, &mut warnings);
        // addr -> servers
        let mut groups: HashMap<SocketAddr, Vec<Arc<Server>>> = HashMap::new();
        // addr -> 默认 vhost 下标标记
        let mut defaults: HashMap<SocketAddr, usize> = HashMap::new();
        // addr -> TLS 证书集合
        let mut tls_specs: HashMap<SocketAddr, Vec<CertSpec>> = HashMap::new();
        // addr -> ssl_certificate_by_lua 脚本（按 server 块配置顺序）
        let mut tls_scripts: HashMap<SocketAddr, Vec<SslCertScript>> = HashMap::new();
        // addr -> (是否 ssl, 是否 http2, 最低 TLS 版本)
        struct Endpoint {
            ssl: bool,
            http2: bool,
            quic: bool,
            protocols: TlsProtocols,
            backlog: Option<u32>,
            ipv6only: Option<bool>,
        }
        let mut endpoints: HashMap<SocketAddr, Endpoint> = HashMap::new();
        // 配置里 listen 首次出现的顺序（HashMap 遍历顺序不定，监听顺序必须可复现）
        let mut order: Vec<SocketAddr> = Vec::new();
        let mut plain_conflicts: Vec<SocketAddr> = Vec::new();

        // 顶层 `map` 指令：解析后原子替换全局 map 表（build 与 rebuild 都经过这里，热重载安全）
        let maps = Self::parse_maps(config, &mut warnings)?;
        crate::engine::install_maps(maps);

        // 顶层 `geo` 指令：同理，按 IP 最长前缀匹配的派生变量表
        let geos = Self::parse_geos(config, &mut warnings)?;
        crate::engine::install_geos(geos);

        // 顶层 `front_proxy` 块：前置代理 profile 表（识别证据 + 授权网段），同理原子替换，热重载安全
        let front_profiles =
            std::sync::Arc::new(Self::parse_front_proxies(config, &mut warnings)?);
        crate::front_proxy::install(front_profiles.as_ref().clone());
        let mut front_proxy_used = false;

        // 顶层 `split_clients` 指令：按键模板哈希加权分流的派生变量表
        let splits = Self::parse_splits(config, &mut warnings)?;
        crate::engine::install_splits(splits);

        let limits_declared: Vec<String> = config
            .root
            .block
            .iter()
            .filter(|d| d.name == "limit_req_zone" || d.name == "limit_conn_zone")
            .filter_map(|d| d.args.iter().find_map(|a| a.strip_prefix("zone="))
                .map(|z| z.split(':').next().unwrap_or(z).to_string()))
            .collect();

        // 限流区的 key 决定"按什么计数"。本实现只会按客户端地址计数：写成别的变量
        // （$http_x_api_key、$uri…）时请求路径根本不展开它，配置看着生效、实际按 IP 限——
        // 这种"写了但那一维不存在"是静默的放行失败，`-t` 必须直接否决（审计 S11）。
        for d in config
            .root
            .block
            .iter()
            .filter(|d| matches!(d.name.as_str(), "limit_req_zone" | "limit_conn_zone"))
        {
            if let Some(var) = crate::limit::zone_key_var(d) {
                if !crate::limit::addr_var(&var) {
                    return Err(AppError::Other(format!(
                        "第 {} 行 {} 的 key '{var}' 不支持：限流区只支持 $remote_addr / $binary_remote_addr（按客户端地址计数）。这个变量在请求路径上不会展开，写下去只会变成按 IP 限流，请改用地址或删除本区域",
                        d.line, d.name
                    )));
                }
            }
        }

        // 队列/学习指令引用未声明的 limit_req 区 = 这条配置一行都不会生效。
        // 按 location 级 limit_req 的先例硬失败：写错区名不该只是日志里飘过一行告警。
        for d in config
            .root
            .block
            .iter()
            .filter(|d| matches!(d.name.as_str(), "limit_req_queue" | "limit_req_learning"))
        {
            if let Some(z) = d.arg(0).filter(|s| !s.is_empty()) {
                if !limits_declared.iter().any(|n| n == z) {
                    return Err(AppError::Other(format!(
                        "第 {} 行 {} 引用了未声明的区域 '{z}'（先写 limit_req_zone）",
                        d.line, d.name
                    )));
                }
            }
        }

        for d in config.servers() {
            Self::warn_unknown(
                d,
                &["listen", "server_name", "root", "index", "autoindex", "try_files",
                   "error_page", "client_max_body_size", "return", "rewrite", "set", "if", "add_header",
                   "proxy_pass", "proxy_set_header", "proxy_read_timeout", "proxy_connect_timeout",
                   "proxy_send_timeout", "proxy_next_upstream", "proxy_next_upstream_tries",
                   "proxy_next_upstream_timeout", "proxy_request_buffering", "limit_conn", "http2",
                   "proxy_cache", "proxy_cache_key", "proxy_cache_methods", "proxy_cache_valid", "proxy_cache_min_uses",
                   "proxy_cache_lock", "proxy_cache_lock_timeout", "proxy_cache_use_stale",
                   "proxy_cache_bypass", "proxy_no_cache", "proxy_ignore_headers",
                   "still_online", "still_online_max_age", "still_online_max_body",
                   "still_online_retry", "still_online_retry_max",
                   "still_online_retry_deadline", "still_online_allow_credentials",
                   "proxy_ssl_verify", "proxy_ssl_server_name", "proxy_ssl_name", "proxy_ssl_trusted_certificate",
                   "proxy_ssl_certificate", "proxy_ssl_certificate_key",
                   "ssl_certificate", "ssl_certificate_key", "ssl_min_version", "ssl_protocols",
                   "ssl_certificate_by_lua", "ssl_certificate_by_lua_file",
                   "location", "content_by_lua", "content_by_lua_file", "access_by_lua",
                   "access_by_lua_file", "rewrite_by_lua", "rewrite_by_lua_file",
                   "header_filter_by_lua", "header_filter_by_lua_file",
                   "body_filter_by_lua", "body_filter_by_lua_file",
                   "log_by_lua", "log_by_lua_file",
                   "content_by_rust", "access_by_rust", "rewrite_by_rust", "log_by_rust",
                   "allow", "deny", "auth_basic", "auth_basic_user_file",
                   "set_real_ip_from", "real_ip_header", "real_ip_recursive",
                   "front_proxy_mode", "front_proxy_auto_trust"],
                "server",
                &mut warnings,
            );
            // 这四条都属于 nginx 的 REWRITE 阶段，ONRouter 只在 location 里跑该阶段。
            // 写在 server 级过去是"静默失效"（`server { return 403; }` 照样放行），
            // 现在必须留痕。
            for c in d
                .block
                .iter()
                .filter(|c| matches!(c.name.as_str(), "return" | "rewrite" | "set" | "if"))
            {
                warnings.push(format!(
                    "server 块第 {} 行：'{}' 暂不支持 server 级（REWRITE 阶段只在 location 内执行），该指令已被忽略",
                    c.line, c.name
                ));
            }

            let tmpl =
                Self::build_template(d, base_dir, &limits_declared, &front_profiles, &mut warnings)?;
            if tmpl.front_proxy.enabled() {
                front_proxy_used = true;
            }

            let mut listens: Vec<(SocketAddr, ListenFlags)> = Vec::new();
            for l in d.block.iter().filter(|x| x.name == "listen") {
                listens.push(parse_listen(l)?);
            }
            if listens.is_empty() {
                listens.push((
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 8080)),
                    ListenFlags::default(),
                ));
                warnings.push(format!(
                    "server '{}'（第 {} 行）没有 listen 指令，默认监听 0.0.0.0:8080",
                    tmpl.server_name, d.line
                ));
            }

            for (addr, flags) in listens {
                if !order.contains(&addr) {
                    order.push(addr);
                }
                let ep = endpoints.entry(addr).or_insert(Endpoint {
                    ssl: false,
                    http2: false,
                    quic: false,
                    protocols: tmpl.protocols.clone(),
                    backlog: None,
                    ipv6only: None,
                });
                if flags.backlog.is_some() {
                    ep.backlog = flags.backlog;
                }
                if flags.ipv6only.is_some() {
                    ep.ipv6only = flags.ipv6only;
                }
                if flags.ssl {
                    if ep.ssl {
                        // 同一地址已有 ssl server，确保证书齐全
                    }
                    ep.ssl = true;
                    let cert = tmpl
                        .ssl_cert
                        .clone()
                        .ok_or_else(|| AppError::Other(format!(
                            "{addr} 声明了 listen ssl，但 server '{}' 缺少 ssl_certificate",
                            tmpl.server_name
                        )))?;
                    let key = tmpl.ssl_key.clone().ok_or_else(|| AppError::Other(format!(
                        "{addr} 声明了 listen ssl，但 server '{}' 缺少 ssl_certificate_key",
                        tmpl.server_name
                    )))?;
                    tls_specs.entry(addr).or_default().push(CertSpec {
                        names: tmpl.server_names.clone(),
                        cert,
                        key,
                    });
                    if let Some(mut script) = tmpl.ssl_cert_script.clone() {
                        script.names = tmpl.server_names.clone();
                        tls_scripts.entry(addr).or_default().push(script);
                    }
                } else if ep.ssl {
                    if let Some(mut script) = tmpl.ssl_cert_script.clone() {
                        script.names = tmpl.server_names.clone();
                        tls_scripts.entry(addr).or_default().push(script);
                    }
                    // 该端点已被其他 server 要求 TLS：这个 vhost 复用同一监听 socket，
                    // 只能走 HTTPS（与 nginx 行为一致：同一地址不能同时有明文与 TLS）
                    plain_conflicts.push(addr);
                }
                ep.http2 |= flags.http2 || tmpl.http2;
                ep.quic |= flags.quic;
                // 同一 socket 上多个 server 的 ssl_protocols 取并集
                ep.protocols.union_with(&tmpl.protocols);

                let server = Server {
                    server_name: tmpl.server_name.clone(),
                    server_names: tmpl.server_names.clone(),
                    is_default_server: flags.default_server,
                    locations: tmpl.locations.clone(),
                    root: tmpl.root.clone(),
                    index: tmpl.index.clone(),
                    autoindex: tmpl.autoindex,
                    error_pages: tmpl.error_pages.clone(),
                    client_max_body_size: tmpl.client_max_body_size,
                    add_headers: tmpl.add_headers.clone(),
                    proxy_set_headers: tmpl.proxy_set_headers.clone(),
                    limit_conn: tmpl.limit_conn.clone(),
                    access_rules: tmpl.access_rules.clone(),
                    auth_basic_realm: tmpl.auth_basic_realm.clone(),
                    auth_basic_user_file: tmpl.auth_basic_user_file.clone(),
                    real_ip: tmpl.real_ip.clone(),
                    front_proxy: tmpl.front_proxy.clone(),
                };
                let list = groups.entry(addr).or_default();
                if flags.default_server {
                    if defaults.contains_key(&addr) {
                        return Err(AppError::Other(format!(
                            "{addr} 上配置了多个 default_server，只能有一个"
                        )));
                    }
                    defaults.insert(addr, list.len());
                }
                list.push(Arc::new(server));
            }
        }

        // 按配置顺序组装监听端点
        let mut listeners = Vec::new();
        for addr in order {
            let ep = endpoints.get(&addr);
            let tls = ep.filter(|e| e.ssl).map(|e| TlsOptions {
                specs: tls_specs.remove(&addr).unwrap_or_default(),
                http2: e.http2,
                protocols: e.protocols.clone(),
                session: session.clone(),
            });
            if ep.map(|e| e.ssl).unwrap_or(false) && tls.as_ref().map(|t| t.specs.is_empty()).unwrap_or(true) {
                return Err(AppError::Other(format!("{addr} 需要 TLS 但没有加载到证书")));
            }
            listeners.push(Listener {
                addr,
                tls,
                ssl_cert_scripts: tls_scripts.remove(&addr).unwrap_or_default(),
                http2: ep.map(|e| e.http2).unwrap_or(false),
                quic: ep.map(|e| e.quic).unwrap_or(false),
                backlog: ep.and_then(|e| e.backlog),
                ipv6only: ep.and_then(|e| e.ipv6only),
            });
        }

        // 默认 vhost 放到下标 0
        for (addr, idx) in &defaults {
            if let Some(list) = groups.get_mut(addr) {
                if *idx < list.len() && *idx != 0 {
                    list.swap(0, *idx);
                }
            }
        }
        // 没有显式 default_server 时，把"名字最少/第一个"的放前面（nginx：配置顺序第一个）
        let out_groups: HashMap<SocketAddr, AddrGroup> = groups
            .into_iter()
            .map(|(a, servers)| (a, AddrGroup { servers }))
            .collect();

        if !plain_conflicts.is_empty() {
            warnings.push(format!(
                "端点 {plain_conflicts:?} 同时被声明为明文与 TLS 监听，统一按 HTTPS 提供服务"
            ));
        }
        // 副本区必须先于引用检查就绪
        let still_zones = Self::parse_still_zones(config, &mut warnings);

        let stream = Self::parse_streams(config, &mut warnings)?;
        let cache_zones = Self::parse_cache_zones(config, &mut warnings);
        // 缓存学习引用未声明的 keys_zone：这行学习配置一行都不会生效（apply_learning 只遍历已存在的区）。
        // 与队列学习、副本区同一先例——写错区名硬失败，不该只在日志里飘过一行。
        for d in config
            .root
            .block
            .iter()
            .filter(|d| d.name == "proxy_cache_learning")
        {
            if let Some(z) = d.arg(0).filter(|s| !s.is_empty()) {
                if !cache_zones.contains_key(z) {
                    return Err(AppError::Other(format!(
                        "第 {} 行 proxy_cache_learning 引用了未声明的缓存区 '{z}'（需要顶层 proxy_cache_path … keys_zone={z}:<容量>;）",
                        d.line
                    )));
                }
            }
        }
        // 引用了未声明的副本区 = 这条 still_online 完全不会生效，按 limit_req 的先例硬失败
        for (addr, group) in &out_groups {
            for srv in &group.servers {
                for loc in &srv.locations {
                    if let Some(zone) = &loc.still_online {
                        if !still_zones.contains_key(zone) {
                            return Err(AppError::Other(format!(
                                "{addr} 的 location '{}' 引用了未声明的副本区 '{zone}'（需要顶层 still_online_zone {zone} <容量>;）",
                                loc.pattern
                            )));
                        }
                    }
                }
            }
        }

        // 信誉表拿"来源地址"当身份，而 realip 让这个地址有一部分是客户端自报的。
        // 不是漏洞（信誉只改排队上界与缓存驻留，永远不参与放行判定），但信任根必须让运维
        // 看见，所以这里给一条告警而非硬失败——`-t` 仍然通过（审计 S12 的信任根暴露）。
        if config.root.block.iter().any(|d| d.name == "vip_learning") {
            for group in out_groups.values() {
                for srv in &group.servers {
                    if !srv.real_ip.trusted.is_empty() {
                        warnings.push(format!(
                            "虚拟主机 '{}' 同时开了 set_real_ip_from 与 vip_learning：信誉按来源地址记分，\
                             而 realip 让这个地址来自客户端自报的头——能伪造它的地址就能攒成重要客户\
                             （只影响排队上界与缓存驻留，不影响是否放行）。set_real_ip_from 请只写自己可信的回环/反代段",
                            srv.server_name
                        ));
                        break;
                    }
                }
            }
        }

        // front_proxy 的两条暴露：声明了却没启用（配置读起来像"已经知道外面是 CDN 了"，其实一行没跑），
        // 以及 auto_trust 把授权根从 set_real_ip_from 挪进了 profile 自己（网段写错/过期时的表现不同）。
        if !front_profiles.is_empty() && !front_proxy_used {
            warnings.push(format!(
                "顶层声明了 {} 个 front_proxy profile（{}），但没有任何 vhost 开启 front_proxy_mode：\
                 现在只是解析过、没跑过。要在某个 server 里写 front_proxy_mode detect;（只识别）\
                 或 egress;（按真实客户端计数并做出口优化）",
                front_profiles.len(),
                crate::front_proxy::describe(&front_profiles)
            ));
        }
        for group in out_groups.values() {
            for srv in &group.servers {
                if srv.front_proxy.mode == crate::front_proxy::FrontProxyMode::Egress
                    && srv.front_proxy.auto_trust
                {
                    warnings.push(format!(
                        "虚拟主机 '{}' 开了 front_proxy_auto_trust：profile 自己声明的 trust 网段成为改写 \
                         $remote_addr 的授权根（不再只有 set_real_ip_from 一处）。网段过期时的表现是认不出来源、\
                         退回按节点地址计数，比写错 set_real_ip_from 更难发现，请核对厂商当前公布的边缘网段",
                        srv.server_name
                    ));
                }
            }
        }

        let config_listeners = listeners;
        Ok((
            Router {
                groups: out_groups,
                listeners: listener_override.unwrap_or_else(|| config_listeners.clone()),
                warnings,
                stream,
                cache_zones,
                still_zones,
            },
            config_listeners,
        ))
    }

    /// 顶层 `proxy_cache_path <path> ... keys_zone=<name>:<size> ...;`
    /// ONRouter 只有内存缓存，path/levels/max_size 不会落盘；keys_zone 的 size 用于
    /// 换算每区条目上限（nginx 文档 1 MB ≈ 8000 key，这里按约 128 B/条估算）。
    fn parse_cache_zones(config: &Config, warnings: &mut Vec<String>) -> HashMap<String, usize> {
        let mut out = HashMap::new();
        for d in config
            .root
            .block
            .iter()
            .filter(|d| d.name == "proxy_cache_path")
        {
            let Some(kz) = d
                .args
                .iter()
                .find_map(|a| a.strip_prefix("keys_zone="))
            else {
                warnings.push(format!(
                    "顶层第 {} 行 proxy_cache_path 缺少 keys_zone=<名称>:<容量>，已忽略",
                    d.line
                ));
                continue;
            };
            let (name, size) = kz.split_once(':').unwrap_or((kz, ""));
            let Some(bytes) = parse_size(size).filter(|b| *b > 0) else {
                warnings.push(format!(
                    "顶层第 {} 行 proxy_cache_path keys_zone 容量非法 '{size}'，已忽略",
                    d.line
                ));
                continue;
            };
            if name.is_empty() {
                warnings.push(format!(
                    "顶层第 {} 行 proxy_cache_path keys_zone 缺少名称，已忽略",
                    d.line
                ));
                continue;
            }
            // 128 B/条 → 1 MB ≈ 8192 条；下限 8 条便于测试/极小配置
            let capacity = ((bytes / 128) as usize).max(8);
            out.insert(name.to_string(), capacity);
        }
        out
    }

    /// 顶层 `still_online_zone <名称> <容量>;`：容量直接按**字节**作为该区预算
    /// （与 `proxy_cache_path keys_zone` 的条数换算不同——副本装的是完整响应体）。
    fn parse_still_zones(config: &Config, warnings: &mut Vec<String>) -> HashMap<String, usize> {
        let mut out = HashMap::new();
        for d in config
            .root
            .block
            .iter()
            .filter(|d| d.name == "still_online_zone")
        {
            let (Some(name), Some(size)) = (d.arg(0), d.arg(1)) else {
                warnings.push(format!(
                    "顶层第 {} 行 still_online_zone 需要 `<名称> <容量>`（如 still_online_zone lkg 16m;），已忽略",
                    d.line
                ));
                continue;
            };
            if d.args.len() > 2 {
                warnings.push(format!(
                    "顶层第 {} 行 still_online_zone 多余参数 {:?} 已忽略",
                    d.line,
                    &d.args[2..]
                ));
            }
            let Some(bytes) = parse_size(size).filter(|b| *b > 0) else {
                warnings.push(format!(
                    "顶层第 {} 行 still_online_zone 容量非法 '{size}'，已忽略",
                    d.line
                ));
                continue;
            };
            // 预算至少能放下一条默认上限（1 MB）的副本，否则该区永远写不进去
            let budget = (bytes as usize).max(STILL_ONLINE_DEFAULT_MAX_BODY);
            if (bytes as usize) < budget {
                warnings.push(format!(
                    "顶层第 {} 行 still_online_zone '{name}' 容量 {bytes} B 小于单条副本上限 {} B，已抬到该值",
                    d.line, STILL_ONLINE_DEFAULT_MAX_BODY
                ));
            }
            out.insert(name.to_string(), budget);
        }
        out
    }

    /// 解析顶层 `stream { server { listen …; proxy_pass …; [ssl_preread on;] [sni_match …;] } }`。
    /// 每个 stream server 的每条 listen 生成一个 `StreamServer`（四层，独立于 HTTP 路由）。
    fn parse_streams(config: &Config, warnings: &mut Vec<String>) -> Result<Vec<StreamServer>, AppError> {
        let mut out = Vec::new();
        for sd in config.root.block.iter().filter(|d| d.name == "stream") {
            for srv in sd.block.iter().filter(|x| x.name == "server") {
                Self::warn_unknown(
                    srv,
                    &["listen", "ssl_preread", "proxy_pass", "sni_match",
                       "proxy_connect_timeout", "proxy_timeout", "preread_timeout"],
                    "stream server",
                    warnings,
                );
                let mut base = StreamServer::default();
                for v in srv.block.iter().filter(|x| x.name == "ssl_preread").take(1) {
                    match v.arg(0).and_then(parse_on_off) {
                        Some(b) => base.ssl_preread = b,
                        None => warnings.push(format!(
                            "ssl_preread 需要 on|off，已忽略 '{:?}'（第 {} 行）",
                            v.arg(0), v.line
                        )),
                    }
                }
                base.default_target = srv
                    .block
                    .iter()
                    .find(|x| x.name == "proxy_pass")
                    .and_then(|x| x.arg(0))
                    .map(|s| s.trim_matches('"').to_string());
                for m in srv.block.iter().filter(|x| x.name == "sni_match") {
                    match (m.arg(0), m.arg(1)) {
                        (Some(p), Some(t)) => base
                            .sni_matches
                            .push(SniMatch { pattern: p.trim_matches('"').to_string(), target: t.trim_matches('"').to_string() }),
                        _ => warnings.push(format!(
                            "sni_match 需要 <name> <target> 两个参数（第 {} 行）",
                            m.line
                        )),
                    }
                }
                for (name, slot) in [
                    ("proxy_connect_timeout", &mut base.connect_timeout),
                    ("proxy_timeout", &mut base.proxy_timeout),
                    ("preread_timeout", &mut base.pread_timeout),
                ] {
                    if let Some(v) = srv.block.iter().find(|x| x.name == name).and_then(|x| x.arg(0)) {
                        match crate::settings::parse_duration(v) {
                            Some(d) => *slot = d,
                            None => warnings.push(format!("{name} 时间值无法解析 '{v}'（已忽略）")),
                        }
                    }
                }
                let mut listens: Vec<SocketAddr> = Vec::new();
                for l in srv.block.iter().filter(|x| x.name == "listen") {
                    let (addr, _flags) = parse_listen(l)?;
                    listens.push(addr);
                }
                if listens.is_empty() {
                    return Err(AppError::Other(format!(
                        "stream server（第 {} 行）没有 listen 指令",
                        srv.line
                    )));
                }
                for addr in listens {
                    let mut s = base.clone();
                    s.listen = addr;
                    if s.default_target.is_none() && s.sni_matches.is_empty() {
                        return Err(AppError::Other(format!(
                            "stream {addr}（第 {} 行）既无 proxy_pass 也无 sni_match，无转发目标",
                            srv.line
                        )));
                    }
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    /// 未知指令告警：拼错的指令静默失效是网关最难排查的一类故障
    fn warn_unknown(
        d: &Directive,
        known: &[&str],
        ctx: &str,
        warnings: &mut Vec<String>,
    ) {
        for child in &d.block {
            if child.name == "location" {
                continue;
            }
            if !known.contains(&child.name.as_str()) {
                warnings.push(format!(
                    "{ctx} 块第 {} 行：未知指令 '{name}'（已忽略，请检查拼写或是否尚未支持）",
                    child.line,
                    name = child.name
                ));
            }
        }
    }

    /// 顶层未知指令告警。迁移 nginx.conf 时最常见的问题是"写了但没生效"，
    /// 因此未识别的顶层指令必须在启动/重载日志里显式出现。
    fn warn_unknown_top_level(config: &Config, warnings: &mut Vec<String>) {
        const KNOWN: &[&str] = &[
            "server", "stream", "upstream",
            "map", "geo", "split_clients",
            "limit_req_zone", "limit_conn_zone", "limit_req_status", "limit_conn_status",
            "lua_shared_dict", "init_by_lua", "init_by_lua_file",
            "init_worker_by_lua", "init_worker_by_lua_file", "lua_package_path",
            "lua_slice_instructions",
            "error_log", "error_log_max_size", "error_log_keep",
            "access_log", "access_log_max_size", "access_log_keep",
            "resolver", "resolver_timeout", "pid",
            "worker_connections", "client_header_timeout", "client_body_timeout",
            "keepalive_timeout", "tls_handshake_timeout", "shutdown_grace",
            "keepalive_requests", "server_tokens", "tcp_nodelay", "accept_backlog",
            "gzip", "gzip_min_length", "gzip_comp_level", "gzip_types", "reload",
            "ssl_session_cache", "ssl_session_tickets", "proxy_cache_path",
            "still_online_zone",
            "learning", "learning_memory_budget", "proxy_cache_learning",
            "limit_req_queue", "limit_req_learning", "vip_learning",
            "front_proxy",
        ];
        for d in &config.root.block {
            match d.name.as_str() {
                "worker_processes" => warnings.push(format!(
                    "顶层第 {} 行：worker_processes 已忽略（ONRouter 为单进程多线程模型，\
                     工作线程数固定为 CPU 核数）",
                    d.line
                )),
                "log_format" => warnings.push(format!(
                    "顶层第 {} 行：log_format 已忽略（access_log 固定使用内置 combined 格式，\
                     暂不支持自定义格式）",
                    d.line
                )),
                name if KNOWN.contains(&name) => {}
                name => warnings.push(format!(
                    "顶层第 {} 行：未知指令 '{name}'（已忽略，请检查拼写或是否尚未支持）",
                    d.line
                )),
            }
        }
    }

    fn build_template(
        d: &Directive,
        base_dir: &PathBuf,
        limits: &[String],
        front_profiles: &std::sync::Arc<Vec<std::sync::Arc<crate::front_proxy::FrontProfile>>>,
        warnings: &mut Vec<String>,
    ) -> Result<ServerTemplate, AppError> {
        let mut tmpl = ServerTemplate {
            server_name: "localhost".to_string(),
            server_names: vec!["localhost".to_string()],
            locations: Vec::new(),
            root: None,
            index: vec!["index.html".to_string()],
            autoindex: false,
            error_pages: HashMap::new(),
            client_max_body_size: Some(1024 * 1024),
            add_headers: Vec::new(),
            proxy_set_headers: Vec::new(),
            proxy_connect_timeout: std::time::Duration::from_secs(3),
            proxy_read_timeout: std::time::Duration::from_secs(60),
            proxy_send_timeout: std::time::Duration::from_secs(60),
            proxy_next_upstream: vec!["error".to_string(), "timeout".to_string()],
            proxy_next_upstream_tries: 0,
            proxy_next_upstream_timeout: std::time::Duration::ZERO,
            proxy_request_buffering: true,
            proxy_cache: None,
            proxy_cache_key: "$scheme$proxy_host$request_uri".to_string(),
            proxy_cache_methods: vec!["GET".to_string(), "HEAD".to_string()],
            proxy_cache_valid: Vec::new(),
            proxy_cache_min_uses: 1,
            proxy_cache_lock: false,
            proxy_cache_lock_timeout: std::time::Duration::from_secs(5),
            proxy_cache_use_stale: Vec::new(),
            proxy_cache_bypass: Vec::new(),
            proxy_no_cache: Vec::new(),
            proxy_ignore_headers: Vec::new(),
            still_online: None,
            still_online_max_age: STILL_ONLINE_DEFAULT_MAX_AGE,
            still_online_max_body: STILL_ONLINE_DEFAULT_MAX_BODY,
            still_online_retry: std::time::Duration::from_secs(5),
            still_online_retry_max: std::time::Duration::from_secs(300),
            still_online_retry_deadline: std::time::Duration::from_secs(1800),
            still_online_allow_credentials: false,
            proxy_tls: TlsPolicy::default(),
            limit_conn: Vec::new(),
            access_rules: Vec::new(),
            auth_basic_realm: None,
            auth_basic_user_file: None,
            real_ip: crate::realip::RealIpConf::default(),
            front_proxy: crate::front_proxy::FrontProxyConf::default(),
            ssl_cert: None,
            ssl_key: None,
            ssl_cert_script: None,
            protocols: TlsProtocols::default(),
            http2: false,
        };
        if let Some(sn) = d.find("server_name") {
            let names: Vec<String> = sn
                .args
                .iter()
                .filter(|n| !n.eq_ignore_ascii_case("default_server"))
                .cloned()
                .collect();
            if !names.is_empty() {
                tmpl.server_names = names.clone();
                tmpl.server_name = names[0].clone();
            }
        }
        if let Some(root) = d.find("root").and_then(|x| x.arg(0)) {
            tmpl.root = Some(crate::resolve_path(root, base_dir));
        }
        if let Some(ix) = d.find("index") {
            let names: Vec<String> = ix.args.clone();
            if !names.is_empty() {
                tmpl.index = names;
            }
        }
        if let Some(ai) = d.find("autoindex") {
            tmpl.autoindex = ai.arg(0) == Some("on");
        }
        if let Some(v) = d
            .find("client_max_body_size")
            .and_then(|x| x.arg(0))
            .and_then(parse_body_limit)
        {
            tmpl.client_max_body_size = Some(v);
        }
        if let Some(cert) = d.find("ssl_certificate").and_then(|x| x.arg(0)) {
            tmpl.ssl_cert = Some(crate::resolve_path(cert, base_dir));
        }
        if let Some(key) = d.find("ssl_certificate_key").and_then(|x| x.arg(0)) {
            tmpl.ssl_key = Some(crate::resolve_path(key, base_dir));
        }
        for name in ["ssl_certificate_by_lua", "ssl_certificate_by_lua_file"] {
            if let Some(dir) = d.find(name) {
                if let Some(src) = LuaSource::from_directive(dir, base_dir) {
                    tmpl.ssl_cert_script = Some(SslCertScript {
                        names: Vec::new(), // 落到监听时按 server_name 填
                        directive: name.to_string(),
                        source: src,
                    });
                    break;
                }
            }
        }
        // ssl_min_version：等价于"该版本及以上全部启用"（向后兼容别名）。
        if let Some(v) = d.find("ssl_min_version").and_then(|x| x.arg(0)) {
            match TlsVersion::from_nginx_token(v) {
                Some(ver) => tmpl.protocols = TlsProtocols::from_min(ver),
                None => warnings.push(format!(
                    "ssl_min_version 不支持 '{v}'（可用 TLSv1/TLSv1.1/TLSv1.2/TLSv1.3），按 TLS1.2"
                )),
            }
        }
        // ssl_protocols：显式启用集合（nginx 语义），出现即以它为准，覆盖 ssl_min_version。
        if let Some(p) = d.find("ssl_protocols") {
            let mut set = TlsProtocols { enabled: Vec::new() };
            for tok in &p.args {
                match TlsVersion::from_nginx_token(tok) {
                    Some(ver) => set.set(ver),
                    None => {
                        let lk = tok.to_ascii_lowercase();
                        if lk == "sslv3" || lk == "ssl" {
                            warnings.push(format!(
                                "ssl_protocols 忽略 '{tok}'：SSLv3 已废弃且无任何后端支持"
                            ));
                        } else {
                            warnings.push(format!("ssl_protocols 无法识别的协议 '{tok}'"));
                        }
                    }
                }
            }
            if set.enabled.is_empty() {
                warnings.push("ssl_protocols 未列出任何可用协议，回落默认 TLSv1.2 TLSv1.3".to_string());
            } else {
                tmpl.protocols = set;
            }
        }
        if let Some(v) = d.find("http2").and_then(|x| x.arg(0)) {
            tmpl.http2 = v == "on" || v == "1.3.0" || v == "true";
        }
        for h in d.block.iter().filter(|x| x.name == "proxy_set_header") {
            if let (Some(k), Some(v)) = (h.arg(0), h.arg(1)) {
                tmpl.proxy_set_headers.push((k.to_string(), v.to_string()));
            }
        }
        for (name, slot) in [
            ("proxy_connect_timeout", &mut tmpl.proxy_connect_timeout),
            ("proxy_read_timeout", &mut tmpl.proxy_read_timeout),
            ("proxy_send_timeout", &mut tmpl.proxy_send_timeout),
        ] {
            if let Some(v) = d.find(name).and_then(|x| x.arg(0)) {
                *slot = parse_time(v, *slot);
            }
        }
        if let Some(nu) = d.find("proxy_next_upstream") {
            validate_next_upstream(&nu.args, warnings);
            tmpl.proxy_next_upstream = nu.args.clone();
        }
        if let Some(v) = d.find("proxy_next_upstream_tries").and_then(|x| x.arg(0)) {
            match v.parse::<u32>() {
                Ok(n) => tmpl.proxy_next_upstream_tries = n,
                Err(_) => warnings.push(format!(
                    "proxy_next_upstream_tries 需要非负整数（收到 '{v}'），保持 {}",
                    tmpl.proxy_next_upstream_tries
                )),
            }
        }
        if let Some(v) = d.find("proxy_next_upstream_timeout").and_then(|x| x.arg(0)) {
            match crate::settings::parse_duration(v) {
                Some(t) => tmpl.proxy_next_upstream_timeout = t,
                None => warnings.push(format!(
                    "proxy_next_upstream_timeout 无法解析 '{v}'，保持 {:?}",
                    tmpl.proxy_next_upstream_timeout
                )),
            }
        }
        if let Some(v) = d.find("proxy_request_buffering").and_then(|x| x.arg(0)) {
            match parse_on_off(v) {
                Some(b) => tmpl.proxy_request_buffering = b,
                None => warnings.push(format!(
                    "proxy_request_buffering 只接受 on/off（收到 '{v}'），保持 on"
                )),
            }
        }
        parse_proxy_ssl_directives(d, base_dir, warnings, &mut tmpl.proxy_tls);
        let cs = parse_cache_directives(d, warnings);
        if let Some(z) = cs.zone {
            tmpl.proxy_cache = z;
        }
        if cs.key.is_some() {
            tmpl.proxy_cache_key = cs.key.unwrap();
        }
        if cs.methods.is_some() {
            tmpl.proxy_cache_methods = cs.methods.unwrap();
        }
        if cs.has_valid {
            tmpl.proxy_cache_valid = cs.valid;
        }
        if cs.min_uses.is_some() {
            tmpl.proxy_cache_min_uses = cs.min_uses.unwrap();
        }
        if let Some(b) = cs.lock {
            tmpl.proxy_cache_lock = b;
        }
        if let Some(t) = cs.lock_timeout {
            tmpl.proxy_cache_lock_timeout = t;
        }
        if let Some(s) = cs.use_stale {
            tmpl.proxy_cache_use_stale = s;
        }
        if let Some(b) = cs.bypass {
            tmpl.proxy_cache_bypass = b;
        }
        if let Some(n) = cs.no_cache {
            tmpl.proxy_no_cache = n;
        }
        if let Some(i) = cs.ignore_headers {
            tmpl.proxy_ignore_headers = i;
        }
        let so = parse_still_online_directives(d, warnings, false);
        if let Some(z) = so.zone {
            tmpl.still_online = z;
        }
        if so.max_age.is_some() {
            tmpl.still_online_max_age = so.max_age.unwrap();
        }
        if so.max_body.is_some() {
            tmpl.still_online_max_body = so.max_body.unwrap();
        }
        if so.retry.is_some() {
            tmpl.still_online_retry = so.retry.unwrap();
        }
        if so.retry_max.is_some() {
            tmpl.still_online_retry_max = so.retry_max.unwrap();
        }
        if so.retry_deadline.is_some() {
            tmpl.still_online_retry_deadline = so.retry_deadline.unwrap();
        }
        if so.allow_credentials.is_some() {
            tmpl.still_online_allow_credentials = so.allow_credentials.unwrap();
        }
        for c in d.block.iter().filter(|x| x.name == "limit_conn") {
            match crate::limit::parse_conn_rule(c) {
                Some(rule) => {
                    if !limits.contains(&rule.zone) {
                        return Err(AppError::Other(format!(
                            "第 {} 行 limit_conn 引用了未声明的区域 '{}'",
                            c.line, rule.zone
                        )));
                    }
                    tmpl.limit_conn.push(rule);
                }
                None => {
                    return Err(AppError::Other(format!(
                        "第 {} 行 limit_conn 需要 `<zone> <number>`",
                        c.line
                    )))
                }
            }
        }
        tmpl.error_pages = parse_error_pages(d);
        tmpl.add_headers = parse_add_headers(d);
        let (a_rules, a_realm, a_file) =
            parse_access_directives(d, base_dir, "server", warnings)?;
        tmpl.access_rules = a_rules;
        tmpl.auth_basic_realm = a_realm;
        tmpl.auth_basic_user_file = a_file;

        // realip 模块：set_real_ip_from（可重复）/ real_ip_header / real_ip_recursive
        {
            let mut ri = crate::realip::RealIpConf::default();
            for h in d.block.iter().filter(|x| x.name == "real_ip_header").take(1) {
                if let Some(v) = h.arg(0) {
                    ri.header = crate::realip::normalize_header_name(v);
                }
            }
            for c in d.block.iter().filter(|x| x.name == "set_real_ip_from") {
                for a in &c.args {
                    match crate::realip::parse_trusted_net(a) {
                        Some(n) => ri.trusted.push(n),
                        None => warnings.push(format!(
                            "第 {} 行 set_real_ip_from 无法识别的地址/网段 '{a}'（已忽略）",
                            c.line
                        )),
                    }
                }
            }
            for r in d.block.iter().filter(|x| x.name == "real_ip_recursive").take(1) {
                match r.arg(0) {
                    Some("on") => ri.recursive = true,
                    Some("off") => ri.recursive = false,
                    other => warnings.push(format!(
                        "第 {} 行 real_ip_recursive 只接受 on/off（收到 {:?}），保持 {}",
                        r.line,
                        other,
                        if ri.recursive { "on" } else { "off" }
                    )),
                }
            }
            tmpl.real_ip = ri;
        }

        // front_proxy：顶层声明 profile（识别证据 + 授权网段），server 级决定用不用、用到什么程度。
        {
            use crate::front_proxy::FrontProxyMode;
            let mut fp = crate::front_proxy::FrontProxyConf {
                profiles: std::sync::Arc::clone(front_profiles),
                ..Default::default()
            };
            let mode_hits: Vec<&Directive> =
                d.block.iter().filter(|x| x.name == "front_proxy_mode").collect();
            if mode_hits.len() > 1 {
                warnings.push(format!(
                    "第 {} 行写了 {} 条 front_proxy_mode，只有第一条生效：这一档决定要不要改写取值，\
                     重复写容易留下一条自己都不记得的行",
                    d.line,
                    mode_hits.len()
                ));
            }
            if let Some(m) = mode_hits.first() {
                let raw = m.arg(0).map(|s| s.trim().to_ascii_lowercase());
                fp.mode = match raw.as_deref() {
                    Some("off") => FrontProxyMode::Off,
                    Some("detect") => FrontProxyMode::Detect,
                    Some("egress") => FrontProxyMode::Egress,
                    other => {
                        // 写错一档 = 这台 vhost 的前置代理感知整台静默关闭，与 S11 同一类，直接否决
                        return Err(AppError::Other(format!(
                            "第 {} 行 front_proxy_mode 只接受 off / detect / egress（收到 {:?}）",
                            m.line, other
                        )));
                    }
                };
            }
            let at_hits: Vec<&Directive> = d
                .block
                .iter()
                .filter(|x| x.name == "front_proxy_auto_trust")
                .collect();
            if at_hits.len() > 1 {
                warnings.push(format!(
                    "第 {} 行写了 {} 条 front_proxy_auto_trust，只有第一条生效",
                    d.line,
                    at_hits.len()
                ));
            }
            if let Some(a) = at_hits.first() {
                fp.auto_trust = match a.arg(0) {
                    Some("on") => true,
                    Some("off") => false,
                    other => {
                        return Err(AppError::Other(format!(
                            "第 {} 行 front_proxy_auto_trust 只接受 on/off（收到 {:?}）：\
                             这一档决定 profile 自己声明的网段能不能授权改写 $remote_addr，不能猜",
                            a.line, other
                        )))
                    }
                };
            }
            if fp.mode != FrontProxyMode::Off && fp.profiles.is_empty() {
                return Err(AppError::Other(format!(
                    "第 {} 行 front_proxy_mode '{}' 已开启，但顶层没有任何 front_proxy 块可匹配",
                    d.line,
                    fp.mode.as_str()
                )));
            }
            if fp.mode == FrontProxyMode::Egress {
                let has_root = !tmpl.real_ip.trusted.is_empty()
                    || fp.profiles.iter().any(|p| !p.trust.is_empty());
                if !has_root {
                    return Err(AppError::Other(format!(
                        "第 {} 行 front_proxy_mode egress 不会生效：一个可信网段都没有，来源无法验证，\
                         于是所有厂商头都按\"客户端自己发的\"处理。请给 profile 写 trust <网段>，\
                         或写 set_real_ip_from（两者安全前提相同：只信对端落在段内的请求带来的头）",
                        d.line
                    )));
                }
            }
            if fp.auto_trust && fp.mode != FrontProxyMode::Egress {
                // 与 S11 同一类失效：这一行读起来像"profile 的网段已经在授权改写地址"，
                // 而 detect/off 档下地址取值根本不会发生。做灰度时要一起改，别留一行空转的行。
                return Err(AppError::Other(format!(
                    "第 {} 行 front_proxy_auto_trust on 在本 vhost 永远不生效：front_proxy_mode 是 '{}'，\
                     不改写 $remote_addr。要真按真实客户端计数就写成 egress；只想先观察就删掉这条（保留识别）",
                    d.line,
                    fp.mode.as_str()
                )));
            }
            if fp.auto_trust && fp.profiles.iter().all(|p| p.trust.is_empty()) {
                warnings.push(format!(
                    "第 {} 行 front_proxy_auto_trust on 目前是空转：没有任何 profile 写了 trust 网段，\
                     改写授权仍然只来自 set_real_ip_from",
                    d.line
                ));
            }
            tmpl.front_proxy = fp;
        }

        for loc in d.block.iter().filter(|x| x.name == "location") {
            tmpl.locations
                .push(Self::build_location(loc, base_dir, &tmpl, limits, warnings)?);
        }
        Ok(tmpl)
    }

    fn build_location(
        d: &Directive,
        base_dir: &PathBuf,
        tmpl: &ServerTemplate,
        limits: &[String],
        warnings: &mut Vec<String>,
    ) -> Result<Location, AppError> {
        let (modifier, pattern) = match (d.arg(0), d.arg(1)) {
            (Some(m), Some(p)) if ["=", "^~", "~", "~*"].contains(&m) => (Some(m), p),
            (Some(p), _) => (None, p),
            _ => return Err(AppError::Other("location 缺少 pattern".into())),
        };
        let mut loc = Location {
            kind: LocationKind::parse(modifier, pattern)?,
            pattern: pattern.to_string(),
            rewrite_steps: Vec::new(),
            ret: None,
            proxy_pass: None,
            proxy_set_headers: Vec::new(),
            proxy_read_timeout: tmpl.proxy_read_timeout,
            proxy_connect_timeout: tmpl.proxy_connect_timeout,
            proxy_send_timeout: tmpl.proxy_send_timeout,
            proxy_next_upstream: tmpl.proxy_next_upstream.clone(),
            proxy_next_upstream_tries: tmpl.proxy_next_upstream_tries,
            proxy_next_upstream_timeout: tmpl.proxy_next_upstream_timeout,
            proxy_request_buffering: tmpl.proxy_request_buffering,
            proxy_cache: tmpl.proxy_cache.clone(),
            proxy_cache_key: tmpl.proxy_cache_key.clone(),
            proxy_cache_methods: tmpl.proxy_cache_methods.clone(),
            proxy_cache_valid: tmpl.proxy_cache_valid.clone(),
            proxy_cache_min_uses: tmpl.proxy_cache_min_uses,
            proxy_cache_lock: tmpl.proxy_cache_lock,
            proxy_cache_lock_timeout: tmpl.proxy_cache_lock_timeout,
            proxy_cache_use_stale: tmpl.proxy_cache_use_stale.clone(),
            proxy_cache_bypass: tmpl.proxy_cache_bypass.clone(),
            proxy_no_cache: tmpl.proxy_no_cache.clone(),
            proxy_ignore_headers: tmpl.proxy_ignore_headers.clone(),
            still_online: tmpl.still_online.clone(),
            still_online_max_age: tmpl.still_online_max_age,
            still_online_max_body: tmpl.still_online_max_body,
            still_online_retry: tmpl.still_online_retry,
            still_online_retry_max: tmpl.still_online_retry_max,
            still_online_retry_deadline: tmpl.still_online_retry_deadline,
            still_online_allow_credentials: tmpl.still_online_allow_credentials,
            proxy_tls: tmpl.proxy_tls.clone(),
            rust_phases: Vec::new(),
            lua_phases: Vec::new(),
            root: None,
            alias: None,
            index: None,
            try_files: None,
            autoindex: false,
            error_pages: HashMap::new(),
            add_headers: parse_add_headers(d),
            limit_req: Vec::new(),
            internal: false,
            client_max_body_size: None,
            access_rules: Vec::new(),
            auth_basic_realm: None,
            auth_basic_user_file: None,
            sub_filter: None,
            proxy_redirect: crate::resp_rewrite::ProxyRedirect::default(),
            proxy_cookie_domain: crate::resp_rewrite::CookieRewrite::default(),
            proxy_cookie_path: crate::resp_rewrite::CookieRewrite::default(),
        };
        Self::warn_unknown(
            d,
            &["rewrite", "set", "if", "return", "proxy_pass", "proxy_set_header", "proxy_read_timeout",
               "proxy_connect_timeout", "proxy_send_timeout", "proxy_next_upstream",
               "proxy_next_upstream_tries", "proxy_next_upstream_timeout",
               "proxy_request_buffering",
               "proxy_cache", "proxy_cache_key", "proxy_cache_methods", "proxy_cache_valid", "proxy_cache_min_uses",
               "proxy_cache_lock", "proxy_cache_lock_timeout", "proxy_cache_use_stale",
               "proxy_cache_bypass", "proxy_no_cache", "proxy_ignore_headers",
               "still_online", "still_online_max_age", "still_online_max_body",
               "still_online_retry", "still_online_retry_max",
               "still_online_retry_deadline", "still_online_allow_credentials",
               "proxy_ssl_verify", "proxy_ssl_server_name", "proxy_ssl_name", "proxy_ssl_trusted_certificate",
                   "proxy_ssl_certificate", "proxy_ssl_certificate_key",
               "root",
               "alias", "index", "try_files", "autoindex", "error_page", "add_header",
               "limit_req", "internal", "client_max_body_size", "content_by_lua",
               "content_by_lua_file", "access_by_lua", "access_by_lua_file", "rewrite_by_lua",
               "rewrite_by_lua_file", "header_filter_by_lua", "header_filter_by_lua_file",
               "body_filter_by_lua", "body_filter_by_lua_file",
               "log_by_lua", "log_by_lua_file",
               "balancer_by_lua", "balancer_by_lua_file",
               "content_by_rust", "access_by_rust", "rewrite_by_rust", "log_by_rust",
               "allow", "deny", "auth_basic", "auth_basic_user_file",
               "sub_filter", "sub_filter_once", "sub_filter_types",
               "proxy_redirect", "proxy_cookie_domain", "proxy_cookie_path"],
            &format!("location '{}'", loc.pattern),
            warnings,
        );
        if let Some(v) = d.find("root").and_then(|x| x.arg(0)) {
            loc.root = Some(crate::resolve_path(v, base_dir));
        }
        if let Some(v) = d.find("alias").and_then(|x| x.arg(0)) {
            loc.alias = Some(crate::resolve_path(v, base_dir));
        }
        if let Some(ix) = d.find("index") {
            if !ix.args.is_empty() {
                loc.index = Some(ix.args.clone());
            }
        }
        if let Some(tf) = d.find("try_files") {
            if tf.args.len() >= 2 {
                loc.try_files = Some(tf.args.clone());
            } else {
                return Err(AppError::Other(format!(
                    "第 {} 行 try_files 至少需要一个文件和一个兜底项",
                    tf.line
                )));
            }
        }
        if let Some(ai) = d.find("autoindex") {
            loc.autoindex = ai.arg(0) == Some("on");
        }
        if d.find("internal").is_some() {
            loc.internal = true;
        }
        if let Some(v) = d
            .find("client_max_body_size")
            .and_then(|x| x.arg(0))
            .and_then(parse_body_limit)
        {
            loc.client_max_body_size = Some(v);
        }
        let (rules, realm, user_file) =
            parse_access_directives(d, base_dir, &format!("location '{}'", loc.pattern), warnings)?;
        loc.access_rules = rules;
        loc.auth_basic_realm = realm;
        loc.auth_basic_user_file = user_file;
        loc.error_pages = parse_error_pages(d);
        // sub_filter：收集多条规则 + once + types，有任一规则才启用
        {
            use crate::engine::{SubFilter, SubFilterConf, SubPattern};
            let mut filters: Vec<SubFilter> = Vec::new();
            for sf in d.block.iter().filter(|x| x.name == "sub_filter") {
                let (m, r) = match (sf.arg(0), sf.arg(1)) {
                    (Some(m), Some(r)) => (m.to_string(), r.to_string()),
                    _ => {
                        return Err(AppError::Other(format!(
                            "sub_filter 需要匹配串与替换串两个参数（第 {} 行）",
                            sf.line
                        )))
                    }
                };
                let pattern = if let Some(pat) = m.strip_prefix("~*") {
                    let re = regex::RegexBuilder::new(pat)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| AppError::Other(format!("sub_filter 正则错误 {pat}: {e}")))?;
                    SubPattern::Regex(re)
                } else if let Some(pat) = m.strip_prefix('~') {
                    let re = regex::Regex::new(pat)
                        .map_err(|e| AppError::Other(format!("sub_filter 正则错误 {pat}: {e}")))?;
                    SubPattern::Regex(re)
                } else {
                    SubPattern::Literal(m)
                };
                filters.push(SubFilter { pattern, replacement: r });
            }
            if !filters.is_empty() {
                let once = match d
                    .find("sub_filter_once")
                    .and_then(|x| x.arg(0))
                    .and_then(parse_on_off)
                {
                    Some(b) => b,
                    None => true, // nginx 默认 on
                };
                let types = match d.find("sub_filter_types") {
                    Some(t) if !t.args.is_empty() => t.args.clone(),
                    _ => vec!["text/html".to_string()], // nginx 默认 text/html
                };
                loc.sub_filter = Some(SubFilterConf { filters, once, types });
            }
        }
        if let Some(pp) = d.find("proxy_pass").and_then(|x| x.arg(0)) {
            loc.proxy_pass = Some(pp.to_string());
        }
        // proxy_redirect：off | default | <redirect> <replacement>（可重复）。
        // 有意偏离 nginx：未显式声明时不改写 Location（nginx 默认会隐式 default），
        // 以免破坏既有代理测试；需要默认行为时写 `proxy_redirect default;`。
        {
            use crate::resp_rewrite::{MatchPattern, ProxyRedirect, RedirectRule};
            let mut pr = ProxyRedirect::default();
            for rd in d.block.iter().filter(|x| x.name == "proxy_redirect") {
                match rd.arg(0).map(|s| s.to_string()).as_deref() {
                    Some("off") => {
                        pr.off = true;
                        pr.rules.clear();
                    }
                    Some("default") => {
                        if let Some(pp) = loc.proxy_pass.as_deref() {
                            match crate::resp_rewrite::default_redirect_rule(pp, &loc.pattern) {
                                Some(r) => pr.rules.push(r),
                                None => warnings.push(format!(
                                    "proxy_redirect default 无法从 proxy_pass 推断（第 {} 行）",
                                    rd.line
                                )),
                            }
                        } else {
                            warnings.push(format!(
                                "proxy_redirect default 需要 proxy_pass（第 {} 行）",
                                rd.line
                            ));
                        }
                    }
                    Some(redirect) => {
                        let replacement = match rd.arg(1) {
                            Some(v) => v.to_string(),
                            None => {
                                warnings.push(format!(
                                    "proxy_redirect 需要 <redirect> <replacement> 两个参数（第 {} 行）",
                                    rd.line
                                ));
                                continue;
                            }
                        };
                        match MatchPattern::from_token(redirect) {
                            Some(m) => pr.rules.push(RedirectRule { m, replacement }),
                            None => warnings.push(format!(
                                "proxy_redirect 正则错误 {redirect}（第 {} 行）",
                                rd.line
                            )),
                        }
                    }
                    None => warnings.push(format!("proxy_redirect 缺少参数（第 {} 行）", rd.line)),
                }
            }
            loc.proxy_redirect = pr;
        }
        // proxy_cookie_domain / proxy_cookie_path：off | <old> <new>（new 为字面量 none 即删除）（可重复）。
        for (name, slot) in [
            ("proxy_cookie_domain", &mut loc.proxy_cookie_domain),
            ("proxy_cookie_path", &mut loc.proxy_cookie_path),
        ] {
            let mut cr = crate::resp_rewrite::CookieRewrite::default();
            for cd in d.block.iter().filter(|x| x.name == name) {
                match cd.arg(0).map(|s| s.to_string()).as_deref() {
                    Some("off") => {
                        cr.off = true;
                        cr.rules.clear();
                    }
                    Some(old) => {
                        let new = match cd.arg(1) {
                            Some(v) => v.to_string(),
                            None => {
                                warnings.push(format!(
                                    "{name} 需要 <old> <new> 两个参数（第 {} 行）",
                                    cd.line
                                ));
                                continue;
                            }
                        };
                        match crate::resp_rewrite::MatchPattern::from_token(old) {
                            Some(m) => {
                                let remove = new.eq_ignore_ascii_case("none");
                                cr.rules.push(crate::resp_rewrite::CookieAttrRule {
                                    m,
                                    replacement: new,
                                    remove,
                                });
                            }
                            None => warnings.push(format!(
                                "{name} 正则错误 {old}（第 {} 行）",
                                cd.line
                            )),
                        }
                    }
                    None => warnings.push(format!("{name} 缺少参数（第 {} 行）", cd.line)),
                }
            }
            *slot = cr;
        }
        for h in d.block.iter().filter(|x| x.name == "proxy_set_header") {
            if let (Some(k), Some(v)) = (h.arg(0), h.arg(1)) {
                loc.proxy_set_headers.push((k.to_string(), v.to_string()));
            }
        }
        for (name, slot) in [
            ("proxy_connect_timeout", &mut loc.proxy_connect_timeout),
            ("proxy_read_timeout", &mut loc.proxy_read_timeout),
            ("proxy_send_timeout", &mut loc.proxy_send_timeout),
        ] {
            if let Some(v) = d.find(name).and_then(|x| x.arg(0)) {
                *slot = parse_time(v, *slot);
            }
        }
        if let Some(nu) = d.find("proxy_next_upstream") {
            validate_next_upstream(&nu.args, warnings);
            loc.proxy_next_upstream = nu.args.clone();
        }
        if let Some(v) = d.find("proxy_next_upstream_tries").and_then(|x| x.arg(0)) {
            match v.parse::<u32>() {
                Ok(n) => loc.proxy_next_upstream_tries = n,
                Err(_) => warnings.push(format!(
                    "proxy_next_upstream_tries 需要非负整数（收到 '{v}'），保持 {}",
                    loc.proxy_next_upstream_tries
                )),
            }
        }
        if let Some(v) = d.find("proxy_next_upstream_timeout").and_then(|x| x.arg(0)) {
            match crate::settings::parse_duration(v) {
                Some(t) => loc.proxy_next_upstream_timeout = t,
                None => warnings.push(format!(
                    "proxy_next_upstream_timeout 无法解析 '{v}'，保持 {:?}",
                    loc.proxy_next_upstream_timeout
                )),
            }
        }
        if let Some(v) = d.find("proxy_request_buffering").and_then(|x| x.arg(0)) {
            match parse_on_off(v) {
                Some(b) => loc.proxy_request_buffering = b,
                None => warnings.push(format!(
                    "proxy_request_buffering 只接受 on/off（收到 '{v}'），保持 {}",
                    if loc.proxy_request_buffering { "on" } else { "off" }
                )),
            }
        }
        parse_proxy_ssl_directives(d, base_dir, warnings, &mut loc.proxy_tls);
        let lcs = parse_cache_directives(d, warnings);
        if let Some(z) = lcs.zone {
            loc.proxy_cache = z;
        }
        if lcs.key.is_some() {
            loc.proxy_cache_key = lcs.key.unwrap();
        }
        if lcs.methods.is_some() {
            loc.proxy_cache_methods = lcs.methods.unwrap();
        }
        if lcs.has_valid {
            loc.proxy_cache_valid = lcs.valid;
        }
        if lcs.min_uses.is_some() {
            loc.proxy_cache_min_uses = lcs.min_uses.unwrap();
        }
        if let Some(b) = lcs.lock {
            loc.proxy_cache_lock = b;
        }
        if let Some(t) = lcs.lock_timeout {
            loc.proxy_cache_lock_timeout = t;
        }
        if let Some(s) = lcs.use_stale {
            loc.proxy_cache_use_stale = s;
        }
        if let Some(b) = lcs.bypass {
            loc.proxy_cache_bypass = b;
        }
        if let Some(n) = lcs.no_cache {
            loc.proxy_no_cache = n;
        }
        if let Some(i) = lcs.ignore_headers {
            loc.proxy_ignore_headers = i;
        }
        let sos = parse_still_online_directives(d, warnings, loc.still_online.is_some());
        if let Some(z) = sos.zone {
            loc.still_online = z;
        }
        if sos.max_age.is_some() {
            loc.still_online_max_age = sos.max_age.unwrap();
        }
        if sos.max_body.is_some() {
            loc.still_online_max_body = sos.max_body.unwrap();
        }
        if sos.retry.is_some() {
            loc.still_online_retry = sos.retry.unwrap();
        }
        if sos.retry_max.is_some() {
            loc.still_online_retry_max = sos.retry_max.unwrap();
        }
        if sos.retry_deadline.is_some() {
            loc.still_online_retry_deadline = sos.retry_deadline.unwrap();
        }
        if sos.allow_credentials.is_some() {
            loc.still_online_allow_credentials = sos.allow_credentials.unwrap();
        }
        for r in d.block.iter().filter(|x| x.name == "limit_req") {
            match crate::limit::parse_req_rule(r) {
                Some(rule) => {
                    if !limits.contains(&rule.zone) {
                        return Err(AppError::Other(format!(
                            "location '{}' 第 {} 行 limit_req 引用了未声明的区域 '{}'",
                            loc.pattern, r.line, rule.zone
                        )));
                    }
                    loc.limit_req.push(rule);
                }
                None => {
                    return Err(AppError::Other(format!(
                        "第 {} 行 limit_req 需要 `zone=<name> [burst=n]`",
                        r.line
                    )))
                }
            }
        }
        loc.rewrite_steps = parse_rewrite_steps(d, warnings)?;
        if let Some(ret) = d.find("return") {
            loc.ret = Some(parse_return(ret)?);
        }
        for name in Phase::directive_names() {
            if let Some(dir) = d.find(name) {
                let phase = Phase::from_directive(name).unwrap();
                if let Some(spec) = crate::engine::spec_from_directive(dir) {
                    loc.rust_phases.push((phase, spec));
                }
            }
        }
        for name in [
            "rewrite_by_lua",
            "rewrite_by_lua_file",
            "access_by_lua",
            "access_by_lua_file",
            "content_by_lua",
            "content_by_lua_file",
            "header_filter_by_lua",
            "header_filter_by_lua_file",
            "body_filter_by_lua",
            "body_filter_by_lua_file",
            "log_by_lua",
            "log_by_lua_file",
            "balancer_by_lua",
            "balancer_by_lua_file",
        ] {
            if let Some(dir) = d.find(name) {
                let phase = match name.split('_').next().unwrap() {
                    "rewrite" => Phase::Rewrite,
                    "access" => Phase::Access,
                    "log" => Phase::Log,
                    "balancer" => Phase::Balancer,
                    _ => Phase::Content,
                };
                if let Some(src) = LuaSource::from_directive(dir, base_dir) {
                    loc.lua_phases.push((phase, name.to_string(), src));
                }
            }
        }
        Ok(loc)
    }

    /// 按真实监听地址 + Host 选 server（nginx ngx_http_find_virtual_server 的顺序）：
    /// 精确名 > `*.example.com`（最长）> `example.*`（最长）> default_server > 配置顺序第一个
    pub fn match_server(&self, local: SocketAddr, host: Option<&str>) -> Option<&Arc<Server>> {
        let group = self
            .groups
            .get(&local)
            // 兜底：同一端口其他地址绑定时共享 vhost 集合（例如 0.0.0.0 与 127.0.0.1 混配）。
            // HashMap 迭代顺序不稳定，必须显式排序：优先同协议族的未指定地址
            // （0.0.0.0 / [::]），其余按 SocketAddr 字典序取最小，保证同一请求永远落到同一个 vhost。
            .or_else(|| {
                self.groups
                    .keys()
                    .filter(|a| a.port() == local.port())
                    .min_by_key(|a| {
                        let unspecified = a.ip().is_unspecified() && a.is_ipv4() == local.is_ipv4();
                        (!unspecified, **a)
                    })
                    .and_then(|a| self.groups.get(a))
            })?;
        let servers = &group.servers;
        if let Some(h) = host.map(strip_port).filter(|h| !h.is_empty()) {
            if let Some(s) = servers
                .iter()
                .find(|s| s.server_names.iter().any(|n| n.eq_ignore_ascii_case(h)))
            {
                return Some(s);
            }
            if let Some(s) = best_wildcard(servers, h, true) {
                return Some(s);
            }
            if let Some(s) = best_wildcard(servers, h, false) {
                return Some(s);
            }
        }
        servers
            .iter()
            .find(|s| s.is_default_server)
            .or(servers.first())
    }

    /// 启动/`-t` 用：每个监听端点上的 vhost 概况（运维只需看日志就知道 Host 会落到哪）
    pub fn describe_listeners(&self) -> Vec<String> {
        let mut out = Vec::new();
        for l in &self.listeners {
            let tls = match &l.tls {
                Some(_) => " TLS",
                None => "",
            };
            let names = self.groups.get(&l.addr).map_or(String::new(), |g| {
                g.servers
                    .iter()
                    .map(|s| {
                        if s.is_default_server {
                            format!("{}(default)", s.server_name)
                        } else {
                            s.server_name.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            out.push(format!("{}{tls} -> [{names}]", l.addr));
        }
        out
    }

    /// 选择 location（nginx 算法）
    pub fn match_location<'s>(server: &'s Server, path: &str) -> Option<&'s Location> {
        if let Some(l) = server.locations.iter().find(|l| {
            matches!(&l.kind, LocationKind::Exact(p) if p == path)
        }) {
            return Some(l);
        }
        let mut best_prefix: Option<(&Location, usize)> = None;
        for l in &server.locations {
            if let Some(p) = l.kind.prefix_path() {
                if path.starts_with(p) && best_prefix.map_or(true, |(_, len)| p.len() > len) {
                    best_prefix = Some((l, p.len()));
                }
            }
        }
        if let Some((l, _)) = best_prefix {
            if l.kind.is_caret() {
                return Some(l);
            }
        }
        for l in &server.locations {
            if !l.kind.is_regex() {
                continue;
            }
            let hit = match &l.kind {
                LocationKind::Regex(re) | LocationKind::RegexI(re) => re.is_match(path),
                _ => false,
            };
            if hit {
                return Some(l);
            }
        }
        best_prefix.map(|(l, _)| l)
    }
}

fn strip_port(host: &str) -> &str {
    if let Some((h, _)) = host.rsplit_once(']') {
        return h;
    }
    host.split(':').next().unwrap_or(host)
}

/// server_name 通配符：`*.example.com` / `example.*`
fn wildcard_match(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    if let Some(suf) = p.strip_prefix("*.") {
        h.ends_with(&format!(".{suf}"))
    } else if let Some(pre) = p.strip_suffix(".*") {
        h.starts_with(&format!("{pre}."))
    } else {
        false
    }
}

/// 通配符 vhost 里取最长匹配者：`prefix_form=true` 看 `*.example.com`，false 看 `example.*`
fn best_wildcard<'a>(
    servers: &'a [Arc<Server>],
    host: &str,
    prefix_form: bool,
) -> Option<&'a Arc<Server>> {
    let mut best: Option<(usize, &'a Arc<Server>)> = None;
    for s in servers {
        for n in &s.server_names {
            let form_ok = if prefix_form {
                n.starts_with("*.")
            } else {
                n.ends_with(".*")
            };
            if !form_ok || !wildcard_match(n, host) {
                continue;
            }
            if best.map_or(true, |(len, _)| n.len() > len) {
                best = Some((n.len(), s));
            }
        }
    }
    best.map(|(_, s)| s)
}

/// location 级 add_header 为空时回退到 server 级（nginx：location 一旦有 add_header 就完全覆盖 server 级）
pub fn effective_add_headers<'a>(
    loc: Option<&'a Location>,
    server: &'a Server,
) -> Vec<&'a (String, String)> {
    let mut out: Vec<&(String, String)> = Vec::new();
    if let Some(l) = loc {
        if !l.add_headers.is_empty() {
            out.extend(l.add_headers.iter());
            return out;
        }
    }
    out.extend(server.add_headers.iter());
    out
}

fn parse_add_headers(d: &Directive) -> Vec<(String, String)> {
    d.block
        .iter()
        .filter(|x| x.name == "add_header")
        .filter_map(|h| Some((h.arg(0)?.to_string(), h.arg(1)?.to_string())))
        .collect()
}

/// 解析 ACCESS 阶段指令：有序的 `allow`/`deny`，以及 `auth_basic`/`auth_basic_user_file`。
/// location 与 server 级共用。非法地址报错（与 nginx 启动期校验一致）；realm 的字面量
/// `off` 或空串视为关闭。
fn parse_access_directives(
    d: &Directive,
    base_dir: &PathBuf,
    where_name: &str,
    warnings: &mut Vec<String>,
) -> Result<(Vec<crate::access::AccessRule>, Option<String>, Option<PathBuf>), AppError> {
    let mut rules = Vec::new();
    // 保持 allow/deny 出现的相对顺序：遍历 block，按 name 分派
    for x in d.block.iter().filter(|x| x.name == "allow" || x.name == "deny") {
        let allow = x.name == "allow";
        if x.args.is_empty() {
            warnings.push(format!("{where_name} 第 {} 行 {} 缺少地址参数，忽略", x.line, x.name));
            continue;
        }
        let refs: Vec<&str> = x.args.iter().map(|s| s.as_str()).collect();
        match crate::access::parse_allow_arg(allow, &refs) {
            Some(rule) => rules.push(rule),
            None => {
                return Err(AppError::Other(format!(
                    "{where_name} 第 {} 行 {} 的地址无法解析（需 IPv4/IPv6/CIDR/all，收到 {:?}）",
                    x.line,
                    x.name,
                    x.args
                )))
            }
        }
    }

    // realm 三态：None=本层未设置（继承上层），Some("off")=显式关闭，Some(其它)=启用
    let realm = d
        .find("auth_basic")
        .and_then(|a| a.arg(0))
        .map(|s| {
            let t = s.trim();
            if t.is_empty() || t.eq_ignore_ascii_case("off") {
                "off".to_string()
            } else {
                t.to_string()
            }
        });
    let user_file = d
        .find("auth_basic_user_file")
        .and_then(|a| a.arg(0))
        .map(|p| crate::resolve_path(p, base_dir));

    if realm.as_deref().is_some_and(|v| v != "off") && user_file.is_none() {
        warnings.push(format!("{where_name} 配置了 auth_basic 却没有 auth_basic_user_file，认证将始终失败"));
    }
    Ok((rules, realm, user_file))
}

/// `proxy_set_header` 合并：server 级为默认，location 级同名覆盖
pub fn effective_proxy_headers<'a>(
    loc: &'a Location,
    server: &'a Server,
) -> Vec<(&'a str, &'a str)> {
    let mut out: Vec<(&str, &str)> = server
        .proxy_set_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for (k, v) in &loc.proxy_set_headers {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            *slot = (k.as_str(), v.as_str());
        } else {
            out.push((k.as_str(), v.as_str()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(s: &str) -> Config {
        Config::parse(s).unwrap()
    }

    fn build(s: &str) -> Router {
        Router::build(&cfg(s), &PathBuf::from(".")).unwrap()
    }

    /// S11：限流区的 key 写了运行期根本不展开的变量，配置"看着生效"、实际按 IP 限。
    /// 这类静默的按预期失败放行不许只留一行告警：`-t` 直接否决，且点名那个 key。
    #[test]
    fn non_address_limit_zone_key_is_a_hard_error() {
        for (dir, bad) in [
            ("limit_req_zone", "$http_x_api_key"),
            ("limit_req_zone", "$uri"),
            ("limit_conn_zone", "$server_name"),
        ] {
            let e = Router::build(
                &cfg(&format!("{dir} {bad} zone=k:1m rate=10r/s;")),
                &PathBuf::from("."),
            )
            .expect_err("{bad} 不是客户端地址，这份配置该被否决");
            let msg = e.to_string();
            assert!(msg.contains(bad) && msg.contains("只支持"), "{msg}");
        }
        // 对照组：两个地址写法照常通过
        build("limit_req_zone $binary_remote_addr zone=k:1m rate=10r/s;");
        build("limit_req_zone $remote_addr zone=k:1m rate=10r/s;");
    }

    /// S12 的信任根暴露：realip 与信誉表同时出现时 `-t` 要说清楚（但照常通过——
    /// 信誉只改排队上界与缓存驻留，不是放行判定，写在一起是常见拓扑而不是错误）。
    #[test]
    fn realip_plus_vip_learning_warns_about_the_trust_root() {
        let both = r#"
            vip_learning table=8k min=10 decay=30s;
            server {
                listen 127.0.0.1:18199;
                real_ip_header X-Forwarded-For;
                set_real_ip_from 127.0.0.0/8;
                location / { return 200 ok; }
            }
        "#;
        let r = Router::build(&cfg(both), &PathBuf::from(".")).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("set_real_ip_from") && w.contains("信誉")),
            "{:?}",
            r.warnings
        );
        // 只开 realip、不学信誉：不该有这条告警
        let only_realip = r#"
            server {
                listen 127.0.0.1:18200;
                real_ip_header X-Forwarded-For;
                set_real_ip_from 127.0.0.0/8;
                location / { return 200 ok; }
            }
        "#;
        let r2 = Router::build(&cfg(only_realip), &PathBuf::from(".")).unwrap();
        assert!(
            !r2.warnings.iter().any(|w| w.contains("信誉")),
            "{:?}",
            r2.warnings
        );
    }

    #[test]
    fn session_cache_directive_forms() {
        let mut w = Vec::new();
        assert_eq!(
            parse_session_cache(&cfg("ssl_session_cache off;"), &mut w),
            SessionCache::Off
        );
        assert_eq!(
            parse_session_cache(&cfg("ssl_session_cache none;"), &mut w),
            SessionCache::Off
        );
        assert_eq!(
            parse_session_cache(&cfg("ssl_session_cache builtin:1000;"), &mut w),
            SessionCache::Builtin(1000)
        );
        assert_eq!(
            parse_session_cache(&cfg("ssl_session_cache shared:SSL:10m;"), &mut w),
            SessionCache::Shared {
                name: "SSL".into(),
                capacity: 20480
            }
        );
        assert!(w.is_empty(), "{w:?}");

        // nginx 允许 builtin 与 shared 并存；这里取最后一个并告警
        let mut w = Vec::new();
        assert_eq!(
            parse_session_cache(&cfg("ssl_session_cache builtin:100 shared:SSL:1m;"), &mut w),
            SessionCache::Shared {
                name: "SSL".into(),
                capacity: 2048
            }
        );
        assert_eq!(w.len(), 1, "{w:?}");

        let mut w = Vec::new();
        let _ = parse_session_cache(&cfg("ssl_session_cache shared:SSL:banana;"), &mut w);
        assert!(!w.is_empty());
    }

    #[test]
    fn session_options_share_ticketer_and_store() {
        let mut w = Vec::new();
        assert!(parse_session_tickets(&cfg("ssl_session_tickets on;"), &mut w));
        let mut w = Vec::new();
        assert!(!parse_session_tickets(&cfg("ssl_session_tickets off;"), &mut w));

        let opts = parse_session_options(
            &cfg("ssl_session_cache shared:SSL:1m; ssl_session_tickets on;"),
            &mut w,
        );
        assert!(w.is_empty(), "{w:?}");
        assert!(opts.tickets);
        assert!(opts.ticketer.is_some());
        assert!(opts.shared_store.is_some());
        assert!(matches!(
            opts.cache,
            SessionCache::Shared { ref name, capacity: 2048 } if name == "SSL"
        ));

        let off = parse_session_options(
            &cfg("ssl_session_cache off; ssl_session_tickets off;"),
            &mut w,
        );
        assert!(!off.tickets);
        assert!(off.ticketer.is_none());
        assert!(off.shared_store.is_none());
    }

    #[test]
    fn cache_lock_stale_bypass_directives_parse() {
        let r = build(
            r#"
            proxy_cache_path /tmp/c levels=1:2 keys_zone=pages:16m max_size=1g;
            server {
                listen 127.0.0.1:18196;
                location / {
                    proxy_pass http://127.0.0.1:1;
                    proxy_cache pages;
                    proxy_cache_valid 200 1m;
                    proxy_cache_min_uses 2;
                    proxy_cache_lock on;
                    proxy_cache_lock_timeout 250ms;
                    proxy_cache_use_stale error timeout http_502 updating;
                    proxy_cache_bypass $cookie_nocache $arg_nocache;
                    proxy_no_cache $arg_nocache;
                }
            }
            "#,
        );
        let loc = &r.groups[&"127.0.0.1:18196".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0]
            .locations[0];
        assert!(loc.proxy_cache_lock);
        assert_eq!(
            loc.proxy_cache_lock_timeout,
            std::time::Duration::from_millis(250)
        );
        assert_eq!(
            loc.proxy_cache_use_stale,
            vec!["error", "timeout", "http_502", "updating"]
        );
        assert_eq!(loc.proxy_cache_bypass, vec!["$cookie_nocache", "$arg_nocache"]);
        assert_eq!(loc.proxy_no_cache, vec!["$arg_nocache"]);
        assert_eq!(loc.proxy_cache_min_uses, 2);
        // 16m keys_zone → 16*1024*1024/128 = 131072 条
        assert_eq!(r.cache_zones.get("pages"), Some(&131072));
        assert!(
            !r.warnings.iter().any(|w| w.contains("proxy_cache_path")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn cache_use_stale_off_and_invalid_tokens() {
        let conf = r#"
            server {
                listen 127.0.0.1:18196;
                location /bad {
                    proxy_cache_use_stale error garbage;
                }
                location /off {
                    proxy_cache_use_stale off;
                }
                location /mixed {
                    proxy_cache_use_stale error off;
                }
            }
        "#;
        let r = build(conf);
        let srv = &r.groups[&"127.0.0.1:18196".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0];
        assert_eq!(srv.locations[0].proxy_cache_use_stale, vec!["error"]);
        assert!(
            srv.locations[1].proxy_cache_use_stale.is_empty(),
            "off 应清空 stale 集合"
        );
        assert!(
            srv.locations[2].proxy_cache_use_stale.is_empty(),
            "off 与其他值混写时只有 off 生效"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("garbage")),
            "未知 token 应告警: {:?}",
            r.warnings
        );
    }

    #[test]
    fn proxy_cache_path_without_keys_zone_warns() {
        let mut w = Vec::new();
        let zones = Router::parse_cache_zones(&cfg("proxy_cache_path /tmp/c;"), &mut w);
        assert!(zones.is_empty());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn top_level_unknown_and_ignored_directives_warn() {
        let conf = r#"
            worker_processes auto;
            log_format main '$remote_addr - $request';
            totally_unknown_directive x;
            gzip on;
            server { listen 127.0.0.1:18195; location / { return 200 ok; } }
        "#;
        let r = build(conf);
        let joined = r.warnings.join("\n");
        assert!(joined.contains("worker_processes 已忽略"), "{joined}");
        assert!(joined.contains("log_format 已忽略"), "{joined}");
        assert!(
            joined.contains("未知指令 'totally_unknown_directive'"),
            "{joined}"
        );
        // 已知顶层指令不应产生告警
        assert!(!joined.contains("未知指令 'gzip'"), "{joined}");
        assert!(!joined.contains("未知指令 'server'"), "{joined}");
    }

    #[test]
    fn parse_maps_all_forms() {
        let conf = r#"
            map $http_x_src $dst {
                default      fallback;
                exact1       hit1;
                ""           empty_hit;
                ~^/reg       reg_hit;
                ~*CI$        ci_hit;
            }
            server { listen 127.0.0.1:18199; location / { return 200 x; } }
        "#;
        let mut warns = Vec::new();
        let defs = Router::parse_maps(&cfg(conf), &mut warns).unwrap();
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert_eq!(d.source, "http_x_src");
        assert_eq!(d.dest, "dst");
        assert_eq!(d.default.as_deref(), Some("fallback"));
        // 精确（含空串）+ 正则 + 大小写不敏感正则共 4 个分支
        assert_eq!(d.cases.len(), 4);
        assert!(d.cases.iter().any(|c| c.literal.as_deref() == Some("exact1")));
        assert!(d.cases.iter().any(|c| c.literal.as_deref() == Some("")));
        assert!(d.cases.iter().any(|c| c.regex.as_ref().is_some_and(|r| r.as_str() == "^/reg")));
        assert!(d.cases.iter().any(|c| c.regex.as_ref().is_some_and(|r| r.as_str() == "CI$")));
    }

    #[test]
    fn build_with_maps_rejects_bad_regex() {
        let conf = r#"
            map $host $x { default y; ~[  bad; }
            server { listen 127.0.0.1:18198; location / { return 200 z; } }
        "#;
        assert!(Router::build(&cfg(conf), &PathBuf::from(".")).is_err());
    }

    #[test]
    fn parse_geos_sorts_longest_prefix_first() {
        let conf = r#"
            geo $client_net {
                default      external;
                10.0.0.0/8   wide;
                10.1.0.0/16  mid;
                127.0.0.1    loopback;
                2001:db8::/32 doc;
            }
            server { listen 127.0.0.1:18197; location / { return 200 g; } }
        "#;
        let mut warns = Vec::new();
        let defs = Router::parse_geos(&cfg(conf), &mut warns).unwrap();
        assert_eq!(defs.len(), 1);
        let g = &defs[0];
        // 单参数形式：源默认 remote_addr，目标 $client_net
        assert_eq!(g.source, "remote_addr");
        assert_eq!(g.dest, "client_net");
        assert_eq!(g.default.as_deref(), Some("external"));
        // 无斜杠主机 → 满位前缀（v4/32, v6/128 保持声明值）
        assert_eq!(g.rules.len(), 4);
        // 按前缀降序：/32(127.0.0.1) 与 /32(2001:db8) 先于 /16 先于 /8
        let prefixes: Vec<u8> = g.rules.iter().map(|r| r.prefix).collect();
        assert_eq!(prefixes, vec![32, 32, 16, 8]);
        assert!(g.rules.iter().any(|r| r.ip.to_string() == "127.0.0.1" && r.result == "loopback"));
        assert!(g.rules.iter().any(|r| r.ip.to_string() == "2001:db8::"));
    }

    #[test]
    fn parse_geos_rejects_bad_ip_and_prefix() {
        let bad_ip = "geo $g { default x; not-an-ip v; } server{listen 18196;}";
        assert!(Router::parse_geos(&cfg(bad_ip), &mut Vec::new()).is_err());
        let bad_prefix = "geo $g { default x; 10.0.0.0/33 v; } server{listen 18196;}";
        assert!(Router::parse_geos(&cfg(bad_prefix), &mut Vec::new()).is_err());
    }

    #[test]
    fn parse_sub_filter_directives() {
        let conf = r#"
            server {
                listen 127.0.0.1:18193;
                location / {
                    sub_filter "foo" "bar";
                    sub_filter ~*^h/el+lo$ "hi";
                    sub_filter_once off;
                    sub_filter_types text/html application/json;
                    return 200 ok;
                }
            }
        "#;
        let r = build(conf);
        let loc = &r.groups[&"127.0.0.1:18193".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0]
            .locations[0];
        let sf = loc.sub_filter.as_ref().expect("sub_filter 应启用");
        assert!(!sf.once, "sub_filter_once off 应被解析");
        assert_eq!(sf.types, vec!["text/html".to_string(), "application/json".to_string()]);
        assert_eq!(sf.filters.len(), 2);
        assert!(matches!(
            &sf.filters[0].pattern,
            crate::engine::SubPattern::Literal(s) if s == "foo"
        ));
        assert!(matches!(
            &sf.filters[1].pattern,
            crate::engine::SubPattern::Regex(_)
        ));
        assert_eq!(sf.filters[1].replacement, "hi");
    }

    #[test]
    fn parse_proxy_redirect_and_cookie_directives() {
        let conf = r#"
            server {
                listen 127.0.0.1:18194;
                location /api/ {
                    proxy_pass http://10.0.0.5:8080;
                    proxy_redirect default;
                    proxy_redirect http://backend.internal:8080 http://public.example;
                    proxy_redirect ~^http://x:[0-9]+/(.*)$ https://pub/$1;
                    proxy_cookie_domain backend.internal public.example;
                    proxy_cookie_domain .old none;
                    proxy_cookie_path /app /gateway;
                    proxy_cookie_path off;
                }
            }
        "#;
        let r = build(conf);
        let loc = &r.groups[&"127.0.0.1:18194".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0]
            .locations[0];
        // proxy_redirect：default 合成 + 字面量 + 正则，共 3 条；未 off
        assert!(!loc.proxy_redirect.off);
        assert_eq!(loc.proxy_redirect.rules.len(), 3);
        assert!(matches!(
            &loc.proxy_redirect.rules[0].m,
            crate::resp_rewrite::MatchPattern::Literal(s) if s == "http://10.0.0.5:8080"
        ));
        assert_eq!(loc.proxy_redirect.rules[0].replacement, "/api/");
        assert_eq!(loc.proxy_redirect.rules[1].replacement, "http://public.example");
        assert!(matches!(&loc.proxy_redirect.rules[2].m, crate::resp_rewrite::MatchPattern::Regex(_)));
        // default 合成产出相对 Location
        assert_eq!(
            crate::resp_rewrite::apply_redirect(&loc.proxy_redirect.rules, "http://10.0.0.5:8080/login").as_deref(),
            Some("/api/login")
        );
        // proxy_cookie_domain：两条规则，第二条 none → remove
        assert!(!loc.proxy_cookie_domain.off);
        assert_eq!(loc.proxy_cookie_domain.rules.len(), 2);
        assert!(!loc.proxy_cookie_domain.rules[0].remove);
        assert!(loc.proxy_cookie_domain.rules[1].remove);
        // proxy_cookie_path：先一条规则后被 off 清空
        assert!(loc.proxy_cookie_path.off);
        assert!(loc.proxy_cookie_path.rules.is_empty());
    }

    #[test]
    fn proxy_redirect_absent_is_pass_through() {
        // 未声明 proxy_redirect → 不改写（有意偏离 nginx 隐式 default）。
        let conf = r#"
            server { listen 127.0.0.1:18195; location /api/ { proxy_pass http://10.0.0.5:8080; } }
        "#;
        let r = build(conf);
        let loc = &r.groups[&"127.0.0.1:18195".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0]
            .locations[0];
        assert!(loc.proxy_redirect.rules.is_empty());
        assert!(!loc.proxy_redirect.off);
        assert!(loc.proxy_cookie_domain.rules.is_empty() && loc.proxy_cookie_path.rules.is_empty());
    }

    #[test]
    fn parse_real_ip_directives_into_server() {
        let conf = r#"
            server {
                listen 127.0.0.1:18196;
                real_ip_header X-Forwarded-For;
                set_real_ip_from 127.0.0.0/8;
                set_real_ip_from 10.0.0.1;
                real_ip_recursive on;
                location / { return 200 ok; }
            }
        "#;
        let r = build(conf);
        let srv = &r.groups[&"127.0.0.1:18196".parse::<std::net::SocketAddr>().unwrap()].servers[0];
        assert_eq!(srv.real_ip.header, "x-forwarded-for", "real_ip_header 规范化为小写");
        assert!(srv.real_ip.recursive, "real_ip_recursive on");
        assert_eq!(srv.real_ip.trusted.len(), 2, "两条 set_real_ip_from 累加");
        assert_eq!(srv.real_ip.trusted[0].prefix, 8);
        assert_eq!(srv.real_ip.trusted[1].prefix, 32, "裸地址按满前缀");
        assert!(srv.real_ip.enabled());
    }

    #[test]
    fn real_ip_off_by_default_and_bad_net_warns() {
        let conf = r#"
            server { listen 127.0.0.1:18197; set_real_ip_from not-an-ip; location / { return 200 ok; } }
        "#;
        let r = build(conf);
        let srv = &r.groups[&"127.0.0.1:18197".parse::<std::net::SocketAddr>().unwrap()].servers[0];
        assert!(!srv.real_ip.enabled(), "非法网段被忽略 → 模块关闭");
        assert!(!srv.real_ip.recursive, "默认 recursive off");
        assert_eq!(srv.real_ip.header, "x-real-ip", "默认头部 x-real-ip");
        assert!(r.warnings.iter().any(|w| w.contains("set_real_ip_from")));
    }

    #[test]
    fn sub_filter_defaults_once_and_html_and_rejects_bad_regex() {
        // 未写 once/types：默认 once=true、types=["text/html"]
        let conf = r#"
            server { listen 127.0.0.1:18192; location / { sub_filter a b; return 200 ok; } }
        "#;
        let r = build(conf);
        let loc = &r.groups[&"127.0.0.1:18192".parse::<std::net::SocketAddr>().unwrap()]
            .servers[0]
            .locations[0];
        let sf = loc.sub_filter.as_ref().unwrap();
        assert!(sf.once);
        assert_eq!(sf.types, vec!["text/html".to_string()]);
        // 非法正则应报错
        let bad = r#"
            server { listen 127.0.0.1:18191; location / { sub_filter ~"[" x; return 200 ok; } }
        "#;
        assert!(Router::build(&cfg(bad), &PathBuf::from(".")).is_err());
    }

    #[test]
    fn parse_splits_buckets_star_and_error() {
        let conf = r#"
            split_clients "${remote_addr}${http_user_agent}" $variant {
                0.5%         ".2g";
                2%           "test";
                *            "none";
            }
            server { listen 127.0.0.1:18195; location / { return 200 s; } }
        "#;
        let mut warns = Vec::new();
        let defs = Router::parse_splits(&cfg(conf), &mut warns).unwrap();
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert_eq!(d.dest, "variant");
        // 键模板保留变量引用原样，运行时才插值
        assert_eq!(d.key, "${remote_addr}${http_user_agent}");
        assert_eq!(d.star.as_deref(), Some("none"));
        assert_eq!(d.buckets.len(), 2);
        assert!((d.buckets[0].percent - 0.5).abs() < 1e-9 && d.buckets[0].result == ".2g");
        assert!((d.buckets[1].percent - 2.0).abs() < 1e-9 && d.buckets[1].result == "test");

        // 非法权重（非数字）应报错
        let bad = r#"
            split_clients $host $v { abc% x; }
            server { listen 127.0.0.1:18194; location / { return 200 y; } }
        "#;
        assert!(Router::parse_splits(&cfg(bad), &mut Vec::new()).is_err());
    }

    const TWO_HOSTS: &str = r#"
        server {
            listen 127.0.0.1:18080;
            server_name a.example.com;
            location = /x { return 200 "a"; }
        }
        server {
            listen 127.0.0.1:18080;
            server_name b.example.com;
            location = /x { return 200 "b"; }
        }
        server {
            listen 127.0.0.1:18081 default_server;
            server_name c.example.com;
            location = /x { return 200 "c"; }
        }
    "#;

    #[test]
    fn routes_by_actual_listen_address_not_just_port() {
        let r = build(TWO_HOSTS);
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:18081".parse().unwrap();
        assert_eq!(
            r.match_server(a, Some("b.example.com")).unwrap().server_name,
            "b.example.com"
        );
        assert_eq!(
            r.match_server(b, Some("b.example.com")).unwrap().server_name,
            "c.example.com",
            "另一个监听地址上的 vhost 不应串到这里"
        );
    }

    #[test]
    fn host_with_port_still_matches() {
        let r = build(TWO_HOSTS);
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(
            r.match_server(a, Some("a.example.com:18080")).unwrap().server_name,
            "a.example.com"
        );
    }

    #[test]
    fn wildcard_vhost_prefers_exact_then_longest_wildcard_then_default() {
        let r = build(
            r#"server { listen 127.0.0.1:18087; server_name www.*; location / { return 200 suffix; } }
               server { listen 127.0.0.1:18087; server_name *.a.example.com; location / { return 200 short; } }
               server { listen 127.0.0.1:18087; server_name hit.example.com; location / { return 200 exact; } }
               server { listen 127.0.0.1:18087 default_server; server_name fallback; location / { return 200 default; } }"#,
        );
        let addr: SocketAddr = "127.0.0.1:18087".parse().unwrap();
        let pick =
            |h: &str| r.match_server(addr, Some(h)).unwrap().server_name.to_string();
        // 1. 精确名赢过所有通配
        assert_eq!(pick("hit.example.com"), "hit.example.com");
        // 2. 前缀通配命中
        assert_eq!(pick("q.a.example.com"), "*.a.example.com");
        // 3. 后缀通配命中
        assert_eq!(pick("www.long.io"), "www.*");
        // 4. 通配只匹配子域：*.a.example.com 不命中 a.example.com
        assert_eq!(pick("a.example.com"), "fallback");
        // 5. 都不匹配时走 default_server（不是配置顺序第一个）
        assert_eq!(pick("nothing.here"), "fallback");
        // 6. 大小写无关；没有 Host 头也走 default_server
        assert_eq!(pick("HIT.EXAMPLE.COM"), "hit.example.com");
        assert_eq!(r.match_server(addr, None).unwrap().server_name, "fallback");
    }

    #[test]
    fn same_port_vhost_fallback_is_deterministic() {
        // 未绑定的本机地址触发同端口兜底：优先同协议族的未指定地址（0.0.0.0），
        // 不受 HashMap 迭代顺序影响。
        let r = build(
            r#"server { listen 127.0.0.1:18088; server_name loop; }
               server { listen 0.0.0.0:18088; server_name wild; }"#,
        );
        for _ in 0..16 {
            let s = r
                .match_server("192.0.2.10:18088".parse().unwrap(), None)
                .unwrap();
            assert_eq!(s.server_name, "wild");
        }
        // 没有未指定地址时按 SocketAddr 字典序取最小，结果同样稳定。
        let r = build(
            r#"server { listen 127.0.0.2:18089; server_name two; }
               server { listen 127.0.0.1:18089; server_name one; }"#,
        );
        for _ in 0..16 {
            let s = r
                .match_server("192.0.2.11:18089".parse().unwrap(), None)
                .unwrap();
            assert_eq!(s.server_name, "one");
        }
    }

    #[test]
    fn unknown_directive_is_warned_not_silently_dropped() {
        let r = build(
            r#"server { listen 127.0.0.1:18099; server_name w; prxoy_pass http://127.0.0.1:1; }"#,
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("prxoy_pass")),
            "实际告警: {:?}",
            r.warnings
        );
    }

    #[test]
    fn rejects_unknown_listen_parameter() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080 spdy; }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("spdy"));
    }

    #[test]
    fn listen_backlog_and_ipv6only_flags_reach_the_listener() {
        let r = build("server { listen 18080 backlog=2048 ipv6only=off; }");
        let l = &r.listeners[0];
        assert_eq!(l.backlog, Some(2048));
        assert_eq!(l.ipv6only, Some(false));
        assert_eq!(l.addr, "0.0.0.0:18080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn listeners_follow_config_order() {
        let r = build(
            "server { listen 18082; } server { listen 18081; } server { listen 18083; }",
        );
        let ports: Vec<u16> = r.listeners.iter().map(|l| l.addr.port()).collect();
        assert_eq!(ports, vec![18082, 18081, 18083]);
    }

    #[test]
    fn multiple_listen_lines_share_one_server_block() {
        let r = build("server { listen 18084; listen 18085; server_name m; }");
        let ports: Vec<u16> = r.listeners.iter().map(|l| l.addr.port()).collect();
        assert!(ports.contains(&18084) && ports.contains(&18085));
        // 同一个 server 块要出现在两个监听端点的 vhost 集合里
        for port in [18084u16, 18085] {
            let s = r
                .match_server(format!("127.0.0.1:{port}").parse().unwrap(), Some("m"))
                .unwrap_or_else(|| panic!("{port} 上没有 vhost"));
            assert_eq!(s.server_name, "m");
        }
    }

    #[test]
    fn two_default_servers_on_one_endpoint_is_fatal() {
        let err = Router::build(
            &cfg(
                "server { listen 127.0.0.1:18080 default_server; } server { listen 127.0.0.1:18080 default_server; }",
            ),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("default_server"));
    }

    #[test]
    fn listen_forms() {
        assert_eq!(
            parse_listen_addr("8080").unwrap(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("[::]:8080").unwrap(),
            "[::]:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(parse_listen_addr("nonsense"), None);
    }

    #[test]
    fn location_priority_matches_nginx() {
        let r = build(
            r#"server { listen 127.0.0.1:18080;
                 location / { return 200 root; }
                 location = /a/b/c/d { return 200 exact; }
                 location /a/ { return 200 prefix; }
                 location ^~ /a/b/ { return 200 caret; }
                 location ~ ^/a/b/c { return 200 regex1; }
                 location ~ ^/a/o { return 200 regex2; }
               }"#,
        );
        let s = r
            .match_server("127.0.0.1:18080".parse().unwrap(), None)
            .unwrap()
            .clone();
        let pick = |p: &str| Router::match_location(&s, p).unwrap().pattern.clone();
        // 精确匹配优先于一切（这里同时命中 ^~ 前缀与正则）
        assert_eq!(pick("/a/b/c/d"), "/a/b/c/d");
        // ^~ 前缀命中后不再检查正则（nginx：`^~` 只在"它是最长前缀"时抑制正则）
        assert_eq!(pick("/a/b/c/x"), "/a/b/");
        // 最长前缀不是 ^~ 时，按配置顺序取第一个命中的正则
        assert_eq!(pick("/a/other"), "^/a/o");
        assert_eq!(pick("/a/xyz"), "/a/");
        assert_eq!(pick("/zzz"), "/");
    }

    #[test]
    fn server_level_proxy_headers_merge_with_location() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_set_header X-A 1; proxy_set_header X-B 1;
                 location /p/ { proxy_pass http://127.0.0.1:1; proxy_set_header X-B 2; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        let loc = Router::match_location(&s, "/p/x").unwrap();
        let merged = effective_proxy_headers(loc, &s);
        assert!(merged.contains(&("X-A", "1")));
        assert!(merged.contains(&("X-B", "2")));
        assert!(!merged.contains(&("X-B", "1")));
    }

    #[test]
    fn proxy_request_buffering_defaults_on_and_inherits_overrides() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_request_buffering off;
                 location /inherited { proxy_pass http://127.0.0.1:1; }
                 location /forced-on  { proxy_pass http://127.0.0.1:1; proxy_request_buffering on; } }
            server { listen 127.0.0.1:18081; location / { proxy_pass http://127.0.0.1:1; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        // server 级 off 被 location 继承
        assert!(!Router::match_location(&s, "/inherited").unwrap().proxy_request_buffering);
        // location 级 on 覆盖 server 级 off
        assert!(Router::match_location(&s, "/forced-on").unwrap().proxy_request_buffering);
        // 未声明时默认 on（nginx 一致）
        let s2 = r.match_server("127.0.0.1:18081".parse().unwrap(), None).unwrap().clone();
        assert!(Router::match_location(&s2, "/").unwrap().proxy_request_buffering);
    }

    #[test]
    fn proxy_request_buffering_rejects_bad_value_keeps_default() {
        let r = build(
            "server { listen 127.0.0.1:18080; proxy_request_buffering maybe; location / { proxy_pass http://127.0.0.1:1; } }",
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        assert!(Router::match_location(&s, "/").unwrap().proxy_request_buffering, "非法取值应回落默认 on");
        assert!(r.warnings.iter().any(|w| w.contains("proxy_request_buffering")), "{:?}", r.warnings);
    }

    #[test]
    fn proxy_ssl_directives_parse_and_inherit() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_ssl_verify off;
                 proxy_ssl_name from-server;
                 location /inherited { proxy_pass https://127.0.0.1:1; }
                 location /override { proxy_pass https://127.0.0.1:1;
                     proxy_ssl_verify on; proxy_ssl_name from-loc; } }
            server { listen 127.0.0.1:18081; location / { proxy_pass http://127.0.0.1:1; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        // server 级 off + name 被 location 继承
        let inh = Router::match_location(&s, "/inherited").unwrap();
        assert!(!inh.proxy_tls.verify);
        assert_eq!(inh.proxy_tls.server_name.as_deref(), Some("from-server"));
        // location 级覆盖 server 级
        let ovr = Router::match_location(&s, "/override").unwrap();
        assert!(ovr.proxy_tls.verify);
        assert_eq!(ovr.proxy_tls.server_name.as_deref(), Some("from-loc"));
        // 未声明时默认 verify on、发 SNI、无覆盖名/无 trusted cert
        let s2 = r.match_server("127.0.0.1:18081".parse().unwrap(), None).unwrap().clone();
        let dflt = Router::match_location(&s2, "/").unwrap();
        assert!(dflt.proxy_tls.verify);
        assert!(dflt.proxy_tls.send_sni);
        assert_eq!(dflt.proxy_tls.server_name, None);
        assert_eq!(dflt.proxy_tls.trusted_cert, None);
    }

    #[test]
    fn proxy_ssl_rejects_bad_verify_value_keeps_default() {
        let r = build(
            "server { listen 127.0.0.1:18080; proxy_ssl_verify maybe; location / { proxy_pass https://127.0.0.1:1; } }",
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        assert!(
            Router::match_location(&s, "/").unwrap().proxy_tls.verify,
            "非法取值应回落默认 verify on"
        );
        assert!(r.warnings.iter().any(|w| w.contains("proxy_ssl_verify")), "{:?}", r.warnings);
    }

    #[test]
    fn limit_req_must_reference_declared_zone() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080; location / { limit_req zone=nope; } }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("未声明的区域"));
    }

    #[test]
    fn add_header_location_overrides_server() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; add_header X-S 1;
                 location /a { add_header X-L 1; }
                 location /b { return 200 x; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        let loc_a = Router::match_location(&s, "/a").unwrap();
        assert_eq!(effective_add_headers(Some(loc_a), &s).len(), 1);
        let loc_b = Router::match_location(&s, "/b").unwrap();
        assert_eq!(effective_add_headers(Some(loc_b), &s).len(), 1);
    }

    #[test]
    fn client_max_body_size_default_is_one_megabyte_and_zero_means_unlimited() {
        let r = build(
            "server { listen 127.0.0.1:18080;
                location / { }
                location /big { client_max_body_size 0; }
            }",
        );
        let s = r
            .match_server("127.0.0.1:18080".parse().unwrap(), None)
            .unwrap()
            .clone();
        assert_eq!(s.client_max_body_size, Some(1024 * 1024), "nginx 默认 1m");
        assert_eq!(
            Router::match_location(&s, "/small").unwrap().client_max_body_size,
            None,
            "location 未显式配置时继承 server"
        );
        assert_eq!(
            Router::match_location(&s, "/big").unwrap().client_max_body_size,
            Some(u64::MAX),
            "0 = 不限制，需覆盖继承的 1m"
        );

        let r2 = build("server { listen 127.0.0.1:18081; client_max_body_size 0; location / { } }");
        let s2 = r2
            .match_server("127.0.0.1:18081".parse().unwrap(), None)
            .unwrap()
            .clone();
        assert_eq!(s2.client_max_body_size, Some(u64::MAX), "server 级 0 同样不限制");
    }

    #[test]
    fn try_files_needs_fallback() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080; location / { try_files $uri; } }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("try_files"));
    }

    #[test]
    fn ssl_listen_without_cert_is_fatal() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18443 ssl; server_name x; }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("ssl_certificate"));
    }

    #[test]
    fn quic_listen_implies_ssl_and_marks_the_listener() {
        let r = build(
            r#"server {
                listen 127.0.0.1:18443 quic;
                server_name x;
                ssl_certificate c.pem;
                ssl_certificate_key k.pem;
            }"#,
        );
        let l = &r.listeners[0];
        assert!(l.quic, "listen quic 应把 Listener.quic 置为 true");
        assert!(l.tls.is_some(), "quic 隐含 ssl：必须带 TLS 配置");
        // quic 但不带 http2（h2 走 TCP，h3 走 QUIC）
        assert!(!l.http2);
    }

    #[test]
    fn ssl_protocols_parses_explicit_set() {
        let tls_of = |conf: &str| {
            let r = build(conf);
            r.listeners[0].tls.as_ref().unwrap().protocols.clone()
        };

        // 显式单版本集合：可裁剪掉另一版本
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_protocols TLSv1.2; }"#)
                .enabled,
            vec![TlsVersion::Tls12]
        );
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_protocols TLSv1.3; }"#)
                .enabled,
            vec![TlsVersion::Tls13]
        );
        // 四个都写：升序去重，含旧版本
        let all = tls_of(
            r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem;
                 ssl_protocols TLSv1.3 TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; }"#,
        );
        assert_eq!(
            all.enabled,
            vec![TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13]
        );
        assert!(all.wants_legacy());

        // 默认（不写任何 TLS 协议指令）= TLS1.2 + TLS1.3
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; }"#)
                .enabled,
            vec![TlsVersion::Tls12, TlsVersion::Tls13]
        );

        // ssl_min_version 别名仍生效：min=TLSv1.3 → 只剩 1.3
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_min_version TLSv1.3; }"#)
                .enabled,
            vec![TlsVersion::Tls13]
        );

        // 同一 socket 上两个 server 的 ssl_protocols 取并集
        let merged = tls_of(
            r#"server { listen 127.0.0.1:18443 ssl; server_name a; ssl_certificate c.pem;
                     ssl_certificate_key k.pem; ssl_protocols TLSv1.2; }
               server { listen 127.0.0.1:18443 ssl; server_name b; ssl_certificate c.pem;
                     ssl_certificate_key k.pem; ssl_protocols TLSv1.3; }"#,
        );
        assert_eq!(merged.enabled, vec![TlsVersion::Tls12, TlsVersion::Tls13]);
    }

    #[test]
    fn default_server_goes_first() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; server_name first; }
               server { listen 127.0.0.1:18080 default_server; server_name chosen; }"#,
        );
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(r.match_server(a, Some("unknown.com")).unwrap().server_name, "chosen");
        assert_eq!(r.match_server(a, None).unwrap().server_name, "chosen");
    }

    #[test]
    fn rebuild_routing_updates_locations_but_keeps_bound_listeners() {
        let base = r#"
            server {
                listen 127.0.0.1:18090;
                server_name reload.test;
                location = /x { return 200 "old"; }
            }
        "#;
        let r0 = build(base);
        // 模拟进程实际绑定的监听集合（reload 期间不得改变）
        let bound = r0.listeners.clone();

        let updated = r#"
            server {
                listen 127.0.0.1:18090;
                server_name reload.test;
                location = /x { return 200 "new"; }
                location = /added { return 200 "added"; }
            }
        "#;
        let (r1, fresh1) =
            Router::rebuild_routing_with_specs(&cfg(updated), &PathBuf::from("."), &bound)
                .unwrap();

        let a: SocketAddr = "127.0.0.1:18090".parse().unwrap();
        // 路由表更新：新增的 location 现在能命中，正文也换成新值
        let srv = r1.match_server(a, Some("reload.test")).unwrap();
        let loc = Router::match_location(srv, "/added").unwrap();
        assert!(loc.ret.as_ref().and_then(|r| r.text.as_ref()).is_some_and(|b| b.contains("added")));
        let loc_x = Router::match_location(srv, "/x").unwrap();
        assert!(loc_x.ret.as_ref().and_then(|r| r.text.as_ref()).is_some_and(|b| b.contains("new")));

        // 监听集合原样保留（即便新配置里没提这个地址，也不新增/删除 socket）
        let addrs = |ls: &[Listener]| ls.iter().map(|l| l.addr).collect::<Vec<_>>();
        assert_eq!(addrs(&r1.listeners), addrs(&bound));
        // 但新配置解析出的监听参数要单独交出来，供 TLS 证书/协议原地刷新
        assert_eq!(addrs(&fresh1), addrs(&bound));

        // 新配置引入了一个**未绑定**的监听地址：rebuild_routing 不应把它加进来
        let with_new_port = r#"
            server { listen 127.0.0.1:18090; location = /x { return 200 "a"; } }
            server { listen 127.0.0.1:18099; location = /x { return 200 "b"; } }
        "#;
        let (r2, fresh2) =
            Router::rebuild_routing_with_specs(&cfg(with_new_port), &PathBuf::from("."), &bound)
                .unwrap();
        assert_eq!(addrs(&r2.listeners), addrs(&bound), "热重载不绑定新监听地址（需重启）");
        assert_eq!(
            fresh2.len(),
            2,
            "新配置解析结果应包含 18090 与 18099，用于判断哪些监听可刷新、哪些需重启"
        );
        // 已绑定的 18090 仍能正常路由
        assert!(r2.match_server(a, None).is_some());
    }

    fn steps_of(r: &Router, port: u16, path: &str) -> Vec<RewriteStep> {
        let s = r
            .match_server(format!("127.0.0.1:{port}").parse().unwrap(), None)
            .unwrap()
            .clone();
        Router::match_location(&s, path).unwrap().rewrite_steps.clone()
    }

    fn step_kind(st: &RewriteStep) -> &'static str {
        match st {
            RewriteStep::Rewrite(_) => "rewrite",
            RewriteStep::Set { .. } => "set",
            RewriteStep::Return(_) => "return",
            RewriteStep::If { .. } => "if",
        }
    }

    #[test]
    fn rewrite_set_if_keep_the_written_order() {
        let r = build(
            r#"server { listen 127.0.0.1:18077;
                 location /o {
                     set $tag one;
                     rewrite ^/o/x$ /o/y break;
                     if ($arg_go) { set $tag two; }
                     set $tail end;
                 }
               }"#,
        );
        let steps = steps_of(&r, 18077, "/o/x");
        assert_eq!(
            steps.iter().map(step_kind).collect::<Vec<_>>(),
            vec!["set", "rewrite", "if", "set"]
        );
        // set 的多参数值按空格拼回模板
        match &steps[0] {
            RewriteStep::Set { name, value } => {
                assert_eq!(name, "tag");
                assert_eq!(value, "one");
            }
            other => panic!("期望 set，实际 {other:?}"),
        }
        assert!(
            r.warnings.iter().all(|w| !w.contains("'set'") && !w.contains("'if'")),
            "set/if 不该再被当成未知指令：{:?}",
            r.warnings
        );
    }

    #[test]
    fn if_forms_parse_into_conditions() {
        let r = build(
            r#"server { listen 127.0.0.1:18076;
                 location /a { if ($arg_x) { set $h 1; } }
                 location /b { if (!$arg_x) { set $h 1; } }
                 location /c { if ($scheme = "http") { set $h 1; } }
                 location /d { if ($host != localhost) { set $h 1; } }
                 location /e { if ($http_user_agent ~ MSIE) { set $h 1; } }
                 location /f { if ($http_user_agent ~* "msie 6") { set $h 1; } }
                 location /g { if ($request_uri !~ ^/pub) { set $h 1; } }
               }"#,
        );
        let cond = |p: &str| match &steps_of(&r, 18076, p)[0] {
            RewriteStep::If { cond, then } => {
                assert_eq!(then.len(), 1, "{p} 的内层步骤");
                cond.clone()
            }
            other => panic!("{p}: 期望 if，实际 {other:?}"),
        };
        let c = cond("/a");
        assert_eq!(c.lhs, "$arg_x");
        assert!(matches!(c.op, CondOp::NonEmpty));
        let c = cond("/b");
        assert_eq!(c.lhs, "$arg_x");
        assert!(matches!(c.op, CondOp::Empty));
        let c = cond("/c");
        assert!(matches!(c.op, CondOp::Eq));
        assert_eq!(c.rhs.as_deref(), Some("http"));
        let c = cond("/d");
        assert!(matches!(c.op, CondOp::Ne));
        assert_eq!(c.rhs.as_deref(), Some("localhost"));
        let c = cond("/e");
        assert_eq!(c.rhs, None, "正则的比较值存在 CondOp 里，不重复放 rhs");
        match &c.op {
            CondOp::Regex(re) => assert_eq!(re.as_str(), "MSIE"),
            other => panic!("期望 Regex，实际 {other:?}"),
        }
        match &cond("/f").op {
            CondOp::IRegex(re) => {
                assert_eq!(re.as_str(), "msie 6");
                assert!(re.is_match("MSIE 6"), "~* 必须忽略大小写");
            }
            other => panic!("期望 IRegex，实际 {other:?}"),
        }
        match &cond("/g").op {
            CondOp::NotRegex(re) => assert_eq!(re.as_str(), "^/pub"),
            other => panic!("期望 NotRegex，实际 {other:?}"),
        }
    }

    #[test]
    fn if_and_set_reject_unsupported_forms_at_parse_time() {
        const HEAD: &str = "server { listen 127.0.0.1:18075; location / { ";
        for tail in [
            "if (-f $request_filename) { return 404; } }",
            "if (!-d $x) { return 404; } }",
            "if ($a) { if ($b) { return 404; } } }",
            "if ($a > 1) { return 404; } }",
            "if ($a) return 404; }",
            "if (1 = $a) { return 404; } }",
            "if ($a =) { return 404; } }",
            "if () { return 404; } }",
            "set plain 1; }",
            "set $1a 1; }",
            "set $ok; }",
            "if ($a) { proxy_pass http://127.0.0.1:1; } }",
        ] {
            let conf = format!("{HEAD}{tail} }}");
            assert!(
                Router::build(&cfg(&conf), &PathBuf::from(".")).is_err(),
                "应当拒绝：{tail}"
            );
        }
    }

    #[test]
    fn server_level_rewrite_directives_warn_instead_of_failing_open() {
        let r = build(
            r#"server { listen 127.0.0.1:18074; return 403 "no";
                 location / { return 200 ok; } }"#,
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("'return'") && w.contains("已被忽略")),
            "server 级 return 必须告警：{:?}",
            r.warnings
        );
    }

    /// 取 127.0.0.1:<port> 上第一个 vhost 的第 n 个 location。
    fn loc_at(r: &Router, port: u16, n: usize) -> &Location {
        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        &r.groups[&addr].servers[0].locations[n]
    }

    #[test]
    fn still_online_zone_budget_is_bytes_not_entries() {
        let mut w = Vec::new();
        let zones = Router::parse_still_zones(&cfg("still_online_zone lkg 16m;"), &mut w);
        assert_eq!(zones.get("lkg"), Some(&(16 * 1024 * 1024)));
        assert!(w.is_empty(), "{w:?}");

        // 参数缺失 / 容量非法：只忽略并留痕，不硬失败
        let mut w = Vec::new();
        assert!(Router::parse_still_zones(&cfg("still_online_zone lkg;"), &mut w).is_empty());
        assert!(w.iter().any(|x| x.contains("<名称> <容量>")), "{w:?}");
        let mut w = Vec::new();
        assert!(
            Router::parse_still_zones(&cfg("still_online_zone lkg banana;"), &mut w).is_empty()
        );
        assert!(w.iter().any(|x| x.contains("容量非法")), "{w:?}");
    }

    #[test]
    fn still_online_zone_smaller_than_one_entry_is_clamped() {
        let mut w = Vec::new();
        let zones = Router::parse_still_zones(&cfg("still_online_zone lkg 64k;"), &mut w);
        // 预算低于单条上限（1 MB）时这条副本永远写不进去，所以抬到 1 MB 并告警
        assert_eq!(zones.get("lkg"), Some(&STILL_ONLINE_DEFAULT_MAX_BODY));
        assert!(w.iter().any(|x| x.contains("已抬到该值")), "{w:?}");
    }

    #[test]
    fn still_online_directives_defaults_and_overrides() {
        let conf = r#"
            still_online_zone lkg 32m;
            server {
                listen 127.0.0.1:18081;
                location /a { proxy_pass http://127.0.0.1:1; }
                location /b {
                    still_online lkg;
                    still_online_max_age 30m;
                    still_online_max_body 256k;
                    still_online_retry 2s;
                    still_online_retry_max 1m;
                    still_online_retry_deadline 2h;
                    still_online_allow_credentials on;
                    proxy_pass http://127.0.0.1:1;
                }
            }
        "#;
        let r = build(conf);
        assert_eq!(r.still_zones.get("lkg"), Some(&(32 * 1024 * 1024)));

        let a = loc_at(&r, 18081, 0);
        assert_eq!(a.still_online, None, "没写 still_online 的 location 默认关闭");
        assert_eq!(a.still_online_max_age, STILL_ONLINE_DEFAULT_MAX_AGE);
        assert_eq!(a.still_online_max_body, STILL_ONLINE_DEFAULT_MAX_BODY);
        assert_eq!(a.still_online_retry, std::time::Duration::from_secs(5));
        assert_eq!(a.still_online_retry_max, std::time::Duration::from_secs(300));
        assert_eq!(
            a.still_online_retry_deadline,
            std::time::Duration::from_secs(1800)
        );
        assert!(!a.still_online_allow_credentials, "凭证闸门默认关，且只能显式 on 打开");

        let b = loc_at(&r, 18081, 1);
        assert_eq!(b.still_online.as_deref(), Some("lkg"));
        assert_eq!(b.still_online_max_age, std::time::Duration::from_secs(1800));
        assert_eq!(b.still_online_max_body, 256 * 1024);
        assert_eq!(b.still_online_retry, std::time::Duration::from_secs(2));
        assert_eq!(b.still_online_retry_max, std::time::Duration::from_secs(60));
        assert_eq!(
            b.still_online_retry_deadline,
            std::time::Duration::from_secs(7200)
        );
        assert!(b.still_online_allow_credentials);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    #[test]
    fn still_online_inherits_from_server_and_off_stops_the_chain() {
        let conf = r#"
            still_online_zone lkg 32m;
            server {
                listen 127.0.0.1:18082;
                still_online lkg;
                still_online_max_age 1h;
                location /inherit { proxy_pass http://127.0.0.1:1; }
                location /explicit { still_online lkg; still_online_max_age 5m; proxy_pass http://127.0.0.1:1; }
                location /off { still_online off; proxy_pass http://127.0.0.1:1; }
            }
        "#;
        let r = build(conf);
        let a = loc_at(&r, 18082, 0);
        assert_eq!(a.still_online.as_deref(), Some("lkg"), "server 级开区，location 继承");
        assert_eq!(a.still_online_max_age, std::time::Duration::from_secs(3600));

        let b = loc_at(&r, 18082, 1);
        assert_eq!(b.still_online_max_age, std::time::Duration::from_secs(300));

        let c = loc_at(&r, 18082, 2);
        assert_eq!(c.still_online, None, "off 必须能单点关掉继承来的副本区");
        assert!(r.warnings.is_empty(), "继承区里写子参数不该告警：{:?}", r.warnings);
    }

    #[test]
    fn still_online_undeclared_zone_is_a_hard_error() {
        let conf = r#"
            server {
                listen 127.0.0.1:18083;
                location / { still_online lkg; proxy_pass http://127.0.0.1:1; }
            }
        "#;
        let err = Router::build(&cfg(conf), &PathBuf::from(".")).unwrap_err();
        assert!(
            err.to_string().contains("未声明的副本区"),
            "引用没声明的区应当硬失败：{err}"
        );
    }

    #[test]
    fn proxy_cache_learning_undeclared_zone_is_a_hard_error() {
        // apply_learning 只遍历已经存在的区：区名写错，这行学习配置一行都不会生效，
        // 所以按队列学习/副本区的先例硬失败，而不是让运维去 /metrics 里猜。
        let err = Router::build(
            &cfg(
                r#"
                proxy_cache_path /tmp/c keys_zone=pages:16m;
                proxy_cache_learning ghost sketch=8k;
                server { listen 127.0.0.1:18086; location / { proxy_pass http://127.0.0.1:1; } }
            "#,
            ),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("未声明的缓存区"),
            "引用没声明的缓存区应当硬失败：{err}"
        );
        let r = build(
            r#"
                proxy_cache_path /tmp/c keys_zone=pages:16m;
                proxy_cache_learning pages sketch=8k;
                server { listen 127.0.0.1:18086; location / { proxy_pass http://127.0.0.1:1; } }
            "#,
        );
        assert!(
            r.warnings.iter().all(|w| !w.contains("proxy_cache_learning")),
            "区名写对不该有意见：{:?}",
            r.warnings
        );
    }

    #[test]
    fn still_online_orphan_params_and_bad_values_warn() {
        // 没开区却写了子参数：整组不生效，必须留痕
        let r = build(
            r#"server { listen 127.0.0.1:18084;
                 location / { still_online_max_age 1h; proxy_pass http://127.0.0.1:1; } }"#,
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("不会生效")),
            "{:?}",
            r.warnings
        );

        // 非法值各自回落到默认并告警，不影响启动
        let r = build(
            r#"still_online_zone lkg 32m;
               server { listen 127.0.0.1:18085;
                 location / {
                     still_online lkg;
                     still_online_max_age banana;
                     still_online_max_body 0;
                     still_online_allow_credentials maybe;
                     proxy_pass http://127.0.0.1:1;
                 } }"#,
        );
        let loc = loc_at(&r, 18085, 0);
        assert_eq!(loc.still_online_max_age, STILL_ONLINE_DEFAULT_MAX_AGE);
        assert_eq!(loc.still_online_max_body, STILL_ONLINE_DEFAULT_MAX_BODY);
        assert!(!loc.still_online_allow_credentials);
        for needle in ["时长非法", "still_online_max_body", "只接受 on/off"] {
            assert!(
                r.warnings.iter().any(|w| w.contains(needle)),
                "缺少 {needle} 告警：{:?}",
                r.warnings
            );
        }
    }

    /// front_proxy 的 `-t` 口径：会静默失效的写法直接否决，只影响可观测性的留痕。
    /// 与 S11 同源的一条判断标准——"配置读起来像生效了、运行期一行不跑"必须是错误。
    #[test]
    fn front_proxy_config_validation() {
        use crate::front_proxy::FrontProxyMode;
        let good = r#"
            front_proxy edge_a {
                probe x-front-id;
                probe Via ~ edge-sub;
                ip_header x-real-client;
                ip_header x-forwarded-for;
                country_header x-front-country;
                trust 192.0.2.0/24;
            }
            server {
                listen 127.0.0.1:18260;
                front_proxy_mode egress;
                location / { return 200 ok; }
            }
        "#;
        let r = Router::build(&cfg(good), &PathBuf::from(".")).unwrap();
        let addr: SocketAddr = "127.0.0.1:18260".parse().unwrap();
        let srv = &r.groups[&addr].servers[0];
        assert_eq!(srv.front_proxy.mode, FrontProxyMode::Egress);
        assert!(!srv.front_proxy.auto_trust);
        let p = &srv.front_proxy.profiles[0];
        assert_eq!(p.probes.len(), 2);
        assert_eq!(p.probes[1].substr.as_deref(), Some("edge-sub"));
        assert_eq!(p.ip_headers, vec!["x-real-client".to_string(), "x-forwarded-for".to_string()]);
        assert_eq!(p.trust.len(), 1);
        assert_eq!(p.country_header.as_deref(), Some("x-front-country"));

        // 网段写错必须否决：放过就等于来源验证静默失效，而配置看起来像配好了
        let bad_net = "front_proxy edge_b { probe x; trust 192.0.2.0/33; }
                       server { listen 127.0.0.1:18261; front_proxy_mode detect; }";
        let e = Router::build(&cfg(bad_net), &PathBuf::from(".")).expect_err("前缀 33 该否决");
        assert!(e.to_string().contains("192.0.2.0/33"), "{e}");

        // 模式值拼错 = 这台 vhost 的感知整台关闭，同样否决
        let bad_mode = "front_proxy edge_c { probe x; trust 10.0.0.0/8; }
                        server { listen 127.0.0.1:18261; front_proxy_mode egres; }";
        let e = Router::build(&cfg(bad_mode), &PathBuf::from(".")).expect_err("拼错的模式值该否决");
        assert!(e.to_string().contains("egres"), "{e}");

        // 一个可信网段都没有的 egress：出口优化一条都不会生效
        let no_root = "front_proxy edge_d { probe x; ip_header y; }
                       server { listen 127.0.0.1:18261; front_proxy_mode egress; }";
        let e = Router::build(&cfg(no_root), &PathBuf::from(".")).expect_err("无授权根的 egress 是空转");
        assert!(e.to_string().contains("不会生效"), "{e}");

        // auto_trust 写在非 egress 档上：读起来像"已经在按 profile 的网段改地址"，运行时一行不跑
        let idle_trust = "front_proxy edge_i { probe x; ip_header y; trust 10.0.0.0/8; }
                          server { listen 127.0.0.1:18261; front_proxy_mode detect; front_proxy_auto_trust on; }";
        let e = Router::build(&cfg(idle_trust), &PathBuf::from(".")).expect_err("detect 档下的 auto_trust 是空转");
        let msg = e.to_string();
        assert!(msg.contains("永远不生效") && msg.contains("detect"), "{e}");

        // 同一档写两遍：只有第一条生效，留痕而不是静默丢弃
        let twice = r#"
            front_proxy edge_j { probe x; ip_header y; trust 10.0.0.0/8; }
            server {
                listen 127.0.0.1:18264;
                front_proxy_mode detect;
                front_proxy_mode egress;
            }
        "#;
        let r = Router::build(&cfg(twice), &PathBuf::from(".")).unwrap();
        let addr3: SocketAddr = "127.0.0.1:18264".parse().unwrap();
        assert_eq!(r.groups[&addr3].servers[0].front_proxy.mode, FrontProxyMode::Detect);
        assert!(
            r.warnings.iter().any(|w| w.contains("front_proxy_mode") && w.contains("只有第一条生效")),
            "{:?}",
            r.warnings
        );

        // 开了模式却没有 profile 可匹配
        let orphan = "server { listen 127.0.0.1:18261; front_proxy_mode detect; }";
        assert!(Router::build(&cfg(orphan), &PathBuf::from(".")).is_err());

        // 同名 profile 重复：指标与告警会分不出说的是哪一家
        let dup = "front_proxy edge_e { probe x; trust 10.0.0.0/8; }
                   front_proxy edge_E { probe y; trust 10.0.0.0/8; }
                   server { listen 127.0.0.1:18261; front_proxy_mode detect; }";
        let e = Router::build(&cfg(dup), &PathBuf::from(".")).expect_err("同名（不分大小写）该否决");
        assert!(e.to_string().contains("重复声明"), "{e}");

        // 三条只留痕的：没有探针、没有 ip_header、声明了却没有任何 vhost 启用
        let quiet = r#"
            front_proxy edge_f { ip_header x; trust 10.0.0.0/8; }
            front_proxy edge_g { probe x; country_header y; }
            server { listen 127.0.0.1:18263; }
        "#;
        let r = Router::build(&cfg(quiet), &PathBuf::from(".")).unwrap();
        let w = r.warnings.join("\n");
        for needle in ["永远命中不了", "没有 ip_header", "只是解析过、没跑过"] {
            assert!(w.contains(needle), "缺少 {needle} 告警：{w}");
        }

        // auto_trust 开在 egress 上：授权根从 set_real_ip_from 挪进 profile 自己，必须点名 vhost 留痕
        let auto = r#"
            front_proxy edge_h { probe x; ip_header y; trust 198.51.100.0/24; }
            server {
                listen 127.0.0.1:18262;
                server_name origin.example;
                front_proxy_mode egress;
                front_proxy_auto_trust on;
            }
        "#;
        let r = Router::build(&cfg(auto), &PathBuf::from(".")).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("origin.example") && w.contains("auto_trust")),
            "{:?}",
            r.warnings
        );
        let addr2: SocketAddr = "127.0.0.1:18262".parse().unwrap();
        assert!(r.groups[&addr2].servers[0].front_proxy.auto_trust);
    }
}
