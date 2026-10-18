//! 运行时指标（对标 nginx `stub_status` + 常见 Prometheus 网关指标）。
//!
//! 全局单例：连接层写入（accept / 活跃连接 gauge / 请求数 / 状态码分类），
//! `content_by_rust metrics` 处理器读取并渲染为 Prometheus 文本格式。
//! 之所以用进程级单例而非挂在请求上下文上，是因为原生处理器签名拿不到 `AppState`。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

#[derive(Default)]
pub struct Metrics {
    pub(crate) accepted: AtomicU64,
    pub(crate) active: AtomicU64,
    pub(crate) handled: AtomicU64,
    pub(crate) http_2xx: AtomicU64,
    pub(crate) http_3xx: AtomicU64,
    pub(crate) http_4xx: AtomicU64,
    pub(crate) http_5xx: AtomicU64,
    /// proxy_cache 结果（按 X-Cache-Status 语义归类）
    pub(crate) cache_hit: AtomicU64,
    pub(crate) cache_miss: AtomicU64,
    pub(crate) cache_expired: AtomicU64,
    pub(crate) cache_bypass: AtomicU64,
    pub(crate) cache_stale: AtomicU64,
    /// 入站 TLS/QUIC 握手失败（含超时）
    pub(crate) tls_handshake_failures: AtomicU64,
    pub(crate) limit_req_rejected: AtomicU64,
    pub(crate) limit_conn_rejected: AtomicU64,
    /// access_log 队列满被丢弃的条数
    pub(crate) access_log_dropped: AtomicU64,
    /// Lua 阶段首段在请求任务内直接跑完的次数（低并发快速路径命中）
    pub(crate) lua_inline: AtomicU64,
    /// Lua 阶段首段让出后把挂起协程移交调度器的次数
    pub(crate) lua_adopted: AtomicU64,
    /// VM 锁忙、整个阶段交给调度器执行的次数
    pub(crate) lua_scheduled: AtomicU64,
    /// worker_connections 上限（渲染 onrouter_connections_capacity）
    pub(crate) capacity: AtomicU64,
    start: OnceLock<Instant>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// upstream 节点句柄：注册一次（启动时），渲染时直接读节点原子量，不产生额外同步。
/// 热重载只重建路由表、复用在跑的 UpstreamPool，所以这份快照不会过期。
static UPSTREAMS: OnceLock<Vec<Arc<crate::upstream::Upstream>>> = OnceLock::new();

/// 登记全部 upstream，供 `/metrics` 渲染每节点连接数/健康/成败计数。
pub fn register_upstreams(pool: &crate::upstream::UpstreamPool) {
    let mut ups: Vec<_> = pool.map.values().cloned().collect();
    ups.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = UPSTREAMS.set(ups);
}

/// 取得全局指标单例（首次调用时按 capacity 初始化容量与启动时刻）。
pub fn global(worker_connections: usize) -> &'static Metrics {
    let m = METRICS.get_or_init(Metrics::default);
    m.capacity.store(worker_connections as u64, Ordering::Relaxed);
    m.start.get_or_init(Instant::now);
    m
}

/// 只读取得单例（不改动容量/启动时刻）——供原生指标处理器等无 AppState 的地方使用。
pub fn get() -> &'static Metrics {
    let m = METRICS.get_or_init(Metrics::default);
    m.start.get_or_init(Instant::now);
    m
}

impl Metrics {
    #[inline]
    pub fn on_accept(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_conn_open(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_conn_close(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_request(&self) {
        self.handled.fetch_add(1, Ordering::Relaxed);
    }
    /// 按响应状态码归类计数（finalize 里调用）。
    pub fn record_status(&self, status: u16) {
        let c = match status {
            200..=299 => &self.http_2xx,
            300..=399 => &self.http_3xx,
            400..=499 => &self.http_4xx,
            500..=599 => &self.http_5xx,
            _ => return,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// proxy_cache 命中分类计数；标签取 X-Cache-Status 的取值（大小写敏感）。
    pub fn record_cache_status(&self, status: &str) {
        let c = match status {
            "HIT" => &self.cache_hit,
            "MISS" => &self.cache_miss,
            "EXPIRED" => &self.cache_expired,
            "BYPASS" => &self.cache_bypass,
            "STALE" => &self.cache_stale,
            _ => return,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_tls_handshake_failure(&self) {
        self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_limit_req_rejected(&self) {
        self.limit_req_rejected.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_limit_conn_rejected(&self) {
        self.limit_conn_rejected.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_access_log_dropped(&self) {
        self.access_log_dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn on_lua_inline(&self) {
        self.lua_inline.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_lua_adopted(&self) {
        self.lua_adopted.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn on_lua_scheduled(&self) {
        self.lua_scheduled.fetch_add(1, Ordering::Relaxed);
    }

    /// 渲染 Prometheus 文本暴露格式。
    pub fn render(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let uptime = self.start.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let cap = g(&self.capacity);
        let mut s = String::with_capacity(1024);
        s.push_str("# HELP onrouter_uptime_seconds Process uptime in seconds.\n");
        s.push_str("# TYPE onrouter_uptime_seconds counter\n");
        s.push_str(&format!("onrouter_uptime_seconds {uptime}\n"));
        s.push_str("# HELP onrouter_connections_accepted Total accepted TCP connections.\n");
        s.push_str("# TYPE onrouter_connections_accepted counter\n");
        s.push_str(&format!("onrouter_connections_accepted {}\n", g(&self.accepted)));
        s.push_str("# HELP onrouter_connections_active Current open connections (gauge).\n");
        s.push_str("# TYPE onrouter_connections_active gauge\n");
        s.push_str(&format!("onrouter_connections_active {}\n", g(&self.active)));
        s.push_str("# HELP onrouter_connections_capacity worker_connections limit.\n");
        s.push_str("# TYPE onrouter_connections_capacity gauge\n");
        s.push_str(&format!("onrouter_connections_capacity {cap}\n"));
        s.push_str("# HELP onrouter_http_requests_total Total HTTP requests handled.\n");
        s.push_str("# TYPE onrouter_http_requests_total counter\n");
        s.push_str(&format!("onrouter_http_requests_total {}\n", g(&self.handled)));
        s.push_str("# HELP onrouter_http_responses_total Response count by status class.\n");
        s.push_str("# TYPE onrouter_http_responses_total counter\n");
        for (class, cell) in [
            ("2xx", &self.http_2xx),
            ("3xx", &self.http_3xx),
            ("4xx", &self.http_4xx),
            ("5xx", &self.http_5xx),
        ] {
            s.push_str(&format!("onrouter_http_responses_total{{class=\"{class}\"}} {}\n", g(cell)));
        }
        s.push_str("# HELP onrouter_cache_requests_total proxy_cache outcomes by X-Cache-Status.\n");
        s.push_str("# TYPE onrouter_cache_requests_total counter\n");
        for (status, cell) in [
            ("hit", &self.cache_hit),
            ("miss", &self.cache_miss),
            ("expired", &self.cache_expired),
            ("bypass", &self.cache_bypass),
            ("stale", &self.cache_stale),
        ] {
            s.push_str(&format!(
                "onrouter_cache_requests_total{{status=\"{status}\"}} {}\n",
                g(cell)
            ));
        }
        s.push_str("# HELP onrouter_tls_handshake_failures_total Inbound TLS/QUIC handshake failures (including timeouts).\n");
        s.push_str("# TYPE onrouter_tls_handshake_failures_total counter\n");
        s.push_str(&format!(
            "onrouter_tls_handshake_failures_total {}\n",
            g(&self.tls_handshake_failures)
        ));
        s.push_str("# HELP onrouter_limit_rejections_total Requests rejected by limit_req/limit_conn.\n");
        s.push_str("# TYPE onrouter_limit_rejections_total counter\n");
        s.push_str(&format!(
            "onrouter_limit_rejections_total{{type=\"req\"}} {}\n",
            g(&self.limit_req_rejected)
        ));
        s.push_str(&format!(
            "onrouter_limit_rejections_total{{type=\"conn\"}} {}\n",
            g(&self.limit_conn_rejected)
        ));
        s.push_str("# HELP onrouter_access_log_dropped_total Access log lines dropped because the write queue was full.\n");
        s.push_str("# TYPE onrouter_access_log_dropped_total counter\n");
        s.push_str(&format!(
            "onrouter_access_log_dropped_total {}\n",
            g(&self.access_log_dropped)
        ));
        if let Some(ups) = UPSTREAMS.get() {
            s.push_str("# HELP onrouter_upstream_server_connections In-flight connections per upstream server.\n");
            s.push_str("# TYPE onrouter_upstream_server_connections gauge\n");
            for up in ups {
                for srv in &up.servers {
                    s.push_str(&format!(
                        "onrouter_upstream_server_connections{{upstream=\"{}\",server=\"{}\"}} {}\n",
                        label(&up.name),
                        label(&srv.addr),
                        srv.conns.load(Ordering::Relaxed)
                    ));
                }
            }
            s.push_str("# HELP onrouter_upstream_server_healthy Active health-check verdict per upstream server (1 = healthy).\n");
            s.push_str("# TYPE onrouter_upstream_server_healthy gauge\n");
            for up in ups {
                for srv in &up.servers {
                    s.push_str(&format!(
                        "onrouter_upstream_server_healthy{{upstream=\"{}\",server=\"{}\"}} {}\n",
                        label(&up.name),
                        label(&srv.addr),
                        u8::from(!srv.manually_down && srv.healthy.load(Ordering::Relaxed))
                    ));
                }
            }
            s.push_str("# HELP onrouter_upstream_requests_total Upstream request outcomes reported by the proxy.\n");
            s.push_str("# TYPE onrouter_upstream_requests_total counter\n");
            for up in ups {
                for srv in &up.servers {
                    s.push_str(&format!(
                        "onrouter_upstream_requests_total{{upstream=\"{}\",server=\"{}\",result=\"success\"}} {}\n",
                        label(&up.name),
                        label(&srv.addr),
                        srv.success_count()
                    ));
                    s.push_str(&format!(
                        "onrouter_upstream_requests_total{{upstream=\"{}\",server=\"{}\",result=\"failure\"}} {}\n",
                        label(&up.name),
                        label(&srv.addr),
                        srv.failure_count()
                    ));
                }
            }
        }
        s.push_str("# HELP onrouter_lua_phase_inline_total Lua phases that ran their first segment inline in the request task.\n");
        s.push_str("# TYPE onrouter_lua_phase_inline_total counter\n");
        s.push_str(&format!("onrouter_lua_phase_inline_total {}\n", g(&self.lua_inline)));
        s.push_str("# HELP onrouter_lua_phase_adopted_total Lua phases handed to the scheduler after yielding in the request task.\n");
        s.push_str("# TYPE onrouter_lua_phase_adopted_total counter\n");
        s.push_str(&format!("onrouter_lua_phase_adopted_total {}\n", g(&self.lua_adopted)));
        s.push_str("# HELP onrouter_lua_phase_scheduled_total Lua phases submitted to the scheduler without the fast path.\n");
        s.push_str("# TYPE onrouter_lua_phase_scheduled_total counter\n");
        s.push_str(&format!("onrouter_lua_phase_scheduled_total {}\n", g(&self.lua_scheduled)));
        s
    }
}

/// Prometheus 标签值转义：配置里的 upstream/节点名可以含引号或反斜杠。
fn label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// 活跃连接 RAII 守卫：new 时 +1，drop 时 -1（连接任务结束时自动回落）。
pub struct ActiveConnGuard(&'static Metrics);

impl ActiveConnGuard {
    pub fn new(m: &'static Metrics) -> Self {
        m.on_conn_open();
        Self(m)
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.0.on_conn_close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_status_buckets_by_class() {
        let m = Metrics::default();
        m.record_status(200);
        m.record_status(204);
        m.record_status(301);
        m.record_status(404);
        m.record_status(503);
        m.record_status(500);
        assert_eq!(m.http_2xx.load(Ordering::Relaxed), 2);
        assert_eq!(m.http_3xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.http_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.http_5xx.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn render_contains_all_metric_families() {
        let m = Metrics::default();
        m.capacity.store(1024, Ordering::Relaxed);
        m.start.get_or_init(Instant::now);
        m.on_accept();
        m.on_request();
        m.record_status(200);
        m.record_cache_status("HIT");
        m.record_cache_status("MISS");
        m.record_cache_status("BYPASS");
        m.record_cache_status("SKIP");
        m.on_tls_handshake_failure();
        m.on_limit_req_rejected();
        m.on_limit_conn_rejected();
        m.on_access_log_dropped();
        m.on_lua_inline();
        m.on_lua_adopted();
        m.on_lua_scheduled();
        let text = m.render();
        for needle in [
            "onrouter_connections_accepted 1",
            "onrouter_http_requests_total 1",
            "onrouter_connections_capacity 1024",
            "class=\"2xx\"",
            "onrouter_cache_requests_total{status=\"hit\"} 1",
            "onrouter_cache_requests_total{status=\"miss\"} 1",
            "onrouter_cache_requests_total{status=\"expired\"} 0",
            "onrouter_cache_requests_total{status=\"bypass\"} 1",
            "onrouter_cache_requests_total{status=\"stale\"} 0",
            "onrouter_tls_handshake_failures_total 1",
            "onrouter_limit_rejections_total{type=\"req\"} 1",
            "onrouter_limit_rejections_total{type=\"conn\"} 1",
            "onrouter_access_log_dropped_total 1",
            "onrouter_lua_phase_inline_total 1",
            "onrouter_lua_phase_adopted_total 1",
            "onrouter_lua_phase_scheduled_total 1",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
    }

    #[test]
    fn renders_registered_upstream_servers() {
        let cfg = onrouter_config::Config::parse(
            "upstream metrics_u { server 127.0.0.1:9001 weight=2; server 127.0.0.1:9002 backup down; }",
        )
        .unwrap();
        let pool = crate::upstream::UpstreamPool::parse_all(&cfg).unwrap();
        register_upstreams(&pool);
        let m = Metrics::default();
        m.start.get_or_init(Instant::now);
        let text = m.render();
        for needle in [
            "onrouter_upstream_server_connections{upstream=\"metrics_u\",server=\"127.0.0.1:9001\"} 0",
            "onrouter_upstream_server_healthy{upstream=\"metrics_u\",server=\"127.0.0.1:9001\"} 1",
            "onrouter_upstream_requests_total{upstream=\"metrics_u\",server=\"127.0.0.1:9001\",result=\"success\"} 0",
            "onrouter_upstream_requests_total{upstream=\"metrics_u\",server=\"127.0.0.1:9001\",result=\"failure\"} 0",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
    }
}
