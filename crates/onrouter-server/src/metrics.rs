//! 运行时指标（对标 nginx `stub_status` + 常见 Prometheus 网关指标）。
//!
//! 全局单例：连接层写入（accept / 活跃连接 gauge / 请求数 / 状态码分类），
//! `content_by_rust metrics` 处理器读取并渲染为 Prometheus 文本格式。
//! 之所以用进程级单例而非挂在请求上下文上，是因为原生处理器签名拿不到 `AppState`。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
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
    /// worker_connections 上限（渲染 onrouter_connections_capacity）
    pub(crate) capacity: AtomicU64,
    start: OnceLock<Instant>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

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
        s
    }
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
        let text = m.render();
        for needle in [
            "onrouter_connections_accepted 1",
            "onrouter_http_requests_total 1",
            "onrouter_connections_capacity 1024",
            "class=\"2xx\"",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
    }
}
