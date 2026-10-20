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

/// Still ONLine 副本层句柄：与 upstream 一样注册一次即可——热重载只套用新预算，
/// 实例本身在进程内不换，所以计数不会因为重载而清零。
static STILL_ONLINE: OnceLock<Arc<crate::still_online::StillOnline>> = OnceLock::new();

/// 登记副本层，供 `/metrics` 渲染副本读写/重取/拒绝凭证/逐出计数与每区占用。
pub fn register_still_online(so: &Arc<crate::still_online::StillOnline>) {
    let _ = STILL_ONLINE.set(Arc::clone(so));
}

/// 缓存学习：与副本层同理，`ProxyCache` 实例进程内唯一（热重载只套用新配置），
/// 注册一次即可，账目不会因重载而清零。
static PROXY_CACHE: OnceLock<Arc<crate::proxy_cache::ProxyCache>> = OnceLock::new();

/// 登记缓存层，供 `/metrics` 渲染学习预算与逐区的准入拒绝/冷位驱逐计数。
pub fn register_proxy_cache(pc: &Arc<crate::proxy_cache::ProxyCache>) {
    let _ = PROXY_CACHE.set(Arc::clone(pc));
}

/// 限流器句柄：`Limits` 与缓存层同理，进程内唯一（热重载只原地套用新队列策略，
/// 区实例不换），所以注册一次即可，队列计数不会因重载而清零。
static LIMITS: OnceLock<Arc<crate::limit::Limits>> = OnceLock::new();

/// 登记限流器，供 `/metrics` 渲染逐区的队列深度/等待/命中与学习表占用。
pub fn register_limits(l: &Arc<crate::limit::Limits>) {
    let _ = LIMITS.set(Arc::clone(l));
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
        if let Some(so) = STILL_ONLINE.get() {
            s.push_str("# HELP onrouter_still_online_total Still ONLine last-known-good copy events by kind. rejected_credential = 带凭证/Set-Cookie 被挡；rejected_private = 上游声明私有或 Vary 按身份分变体被挡。\n");
            s.push_str("# TYPE onrouter_still_online_total counter\n");
            for (kind, cell) in [
                ("stored", &so.stored_total),
                ("served", &so.served_total),
                ("refreshed", &so.refreshed_total),
                ("refresh_failed", &so.refresh_failed_total),
                ("rejected_credential", &so.rejected_credential_total),
                ("rejected_private", &so.rejected_private_total),
                ("evicted", &so.evicted_total),
            ] {
                s.push_str(&format!(
                    "onrouter_still_online_total{{kind=\"{kind}\"}} {}\n",
                    g(cell)
                ));
            }
            s.push_str("# HELP onrouter_still_online_pending_jobs Keys waiting for a background re-fetch (gauge).\n");
            s.push_str("# TYPE onrouter_still_online_pending_jobs gauge\n");
            s.push_str(&format!(
                "onrouter_still_online_pending_jobs {}\n",
                so.dirty_len()
            ));
            s.push_str("# HELP onrouter_still_online_zone_entries Cached responses held per zone (gauge).\n");
            s.push_str("# TYPE onrouter_still_online_zone_entries gauge\n");
            s.push_str("# HELP onrouter_still_online_zone_bytes Bytes held per zone: role=\"used\" 实际占用，role=\"budget\" 配置预算.\n");
            s.push_str("# TYPE onrouter_still_online_zone_bytes gauge\n");
            for (name, entries, used, budget) in so.zone_rows() {
                let zone = label(&name);
                s.push_str(&format!(
                    "onrouter_still_online_zone_entries{{zone=\"{zone}\"}} {entries}\n"
                ));
                s.push_str(&format!(
                    "onrouter_still_online_zone_bytes{{zone=\"{zone}\",role=\"used\"}} {used}\n"
                ));
                s.push_str(&format!(
                    "onrouter_still_online_zone_bytes{{zone=\"{zone}\",role=\"budget\"}} {budget}\n"
                ));
            }
        }
        // front_proxy：按 profile 逐行展开；一个都没声明时连 HELP/TYPE 都不出，
        // 免得没开功能的实例上挂着一堆恒为 0 的序列。
        let fps = crate::front_proxy::snapshot();
        if !fps.is_empty() {
            s.push_str("# HELP onrouter_front_proxy_total Front-proxy (CDN/LB) profile accounting. role=\"matched\" 探针命中；ip_applied / ip_blocked 真实客户端地址的采用与被挡（blocked = 对端验证没过，或 front_proxy_auto_trust 未开）；origin_applied / origin_blocked 协议与 Host 等来源元数据；country_applied 国家码采用次数。计数随 profile 表存活，热重载后从 0 重新计数（与 nginx reload 后的 stub_status 同一语义）.\n");
            s.push_str("# TYPE onrouter_front_proxy_total counter\n");
            for p in fps {
                let name = label(&p.name);
                let c = &p.counters;
                for (role, cell) in [
                    ("matched", &c.matched),
                    ("ip_applied", &c.ip_applied),
                    ("ip_blocked", &c.ip_blocked),
                    ("origin_applied", &c.origin_applied),
                    ("origin_blocked", &c.origin_blocked),
                    ("country_applied", &c.country_applied),
                ] {
                    s.push_str(&format!(
                        "onrouter_front_proxy_total{{profile=\"{name}\",role=\"{role}\"}} {}\n",
                        g(cell)
                    ));
                }
            }
        }
        if let Some(pc) = PROXY_CACHE.get() {
            let (enabled, used, budget, denied) = pc.learning_summary();
            s.push_str("# HELP onrouter_learning_enabled Learning master switch for cache admission, queue burst shapes and client reputation (1 = on, 0 = off).\n");
            s.push_str("# TYPE onrouter_learning_enabled gauge\n");
            s.push_str(&format!(
                "onrouter_learning_enabled {}\n",
                if enabled { 1 } else { 0 }
            ));
            s.push_str("# HELP onrouter_learning_memory_bytes Learning memory footprint; role=\"used\" is the ledger total, role=\"budget\" the configured ceiling.\n");
            s.push_str("# TYPE onrouter_learning_memory_bytes gauge\n");
            s.push_str(&format!(
                "onrouter_learning_memory_bytes{{role=\"used\"}} {used}\n"
            ));
            s.push_str(&format!(
                "onrouter_learning_memory_bytes{{role=\"budget\"}} {budget}\n"
            ));
            s.push_str("# HELP onrouter_learning_budget_denied_total Learning allocations refused because the shared budget was exhausted (cache sketches fall back to plain LRU, queues to the configured depth, reputation to no VIP learning).\n");
            s.push_str("# TYPE onrouter_learning_budget_denied_total counter\n");
            s.push_str(&format!("onrouter_learning_budget_denied_total {denied}\n"));
            s.push_str("# HELP onrouter_cache_learning_sketch_bytes Sketch bytes held per proxy_cache zone; 0 means the zone is declared but not learning.\n");
            s.push_str("# TYPE onrouter_cache_learning_sketch_bytes gauge\n");
            s.push_str("# HELP onrouter_cache_learning_aging_total Whole-table halving (aging) cycles executed per zone sketch.\n");
            s.push_str("# TYPE onrouter_cache_learning_aging_total counter\n");
            s.push_str("# HELP onrouter_cache_learning_events_total Per-zone cache learning decisions; role=\"admission_rejected\" cold objects refused entry, role=\"evicted_cold\" objects displaced by a hotter newcomer, role=\"retained\" writes given the VIP retention boost.\n");
            s.push_str("# TYPE onrouter_cache_learning_events_total counter\n");
            for row in pc.learning_rows() {
                let zone = label(&row.zone);
                s.push_str(&format!(
                    "onrouter_cache_learning_sketch_bytes{{zone=\"{zone}\"}} {}\n",
                    row.sketch_bytes
                ));
                s.push_str(&format!(
                    "onrouter_cache_learning_aging_total{{zone=\"{zone}\"}} {}\n",
                    row.ages
                ));
                s.push_str(&format!(
                    "onrouter_cache_learning_events_total{{zone=\"{zone}\",role=\"admission_rejected\"}} {}\n",
                    row.admission_rejected
                ));
                s.push_str(&format!(
                    "onrouter_cache_learning_events_total{{zone=\"{zone}\",role=\"evicted_cold\"}} {}\n",
                    row.evicted_cold
                ));
                s.push_str(&format!(
                    "onrouter_cache_learning_events_total{{zone=\"{zone}\",role=\"retained\"}} {}\n",
                    row.retained
                ));
            }
        }
        if let Some(lim) = LIMITS.get() {
            s.push_str("# HELP onrouter_queue_depth Per-key queue depth bounds; kind=\"min\"/\"max\" are configured, kind=\"learned\" is the largest burst length the zone has learned so far (0 = nothing learned).\n");
            s.push_str("# TYPE onrouter_queue_depth gauge\n");
            s.push_str("# HELP onrouter_queue_max_delay_ms Configured ceiling on how long a single queued request may wait.\n");
            s.push_str("# TYPE onrouter_queue_max_delay_ms gauge\n");
            s.push_str("# HELP onrouter_queue_occupied Requests held in the bounded queue; kind=\"now\" sampled at scrape, kind=\"max\" the high-water mark.\n");
            s.push_str("# TYPE onrouter_queue_occupied gauge\n");
            s.push_str("# HELP onrouter_queue_events_total Queue outcomes; role=\"queued\" took a slot in the bounded queue (the wait itself is reported by onrouter_queue_wait_ms_total), role=\"rejected_full\" queue depth reached, role=\"rejected_slow\" projected wait over budget.\n");
            s.push_str("# TYPE onrouter_queue_events_total counter\n");
            s.push_str("# HELP onrouter_queue_wait_ms_total Milliseconds requests spent queued (divide by role=\"queued\" events for the average wait).\n");
            s.push_str("# TYPE onrouter_queue_wait_ms_total counter\n");
            s.push_str("# HELP onrouter_queue_depth_adjust_total Times a finished burst rewrote that key's learned queue depth — the evidence that depth is actually adapting.\n");
            s.push_str("# TYPE onrouter_queue_depth_adjust_total counter\n");
            s.push_str("# HELP onrouter_queue_table_bytes Burst-shape table bytes held per limit_req zone; 0 means learning is off or the budget refused it.\n");
            s.push_str("# TYPE onrouter_queue_table_bytes gauge\n");
            s.push_str("# HELP onrouter_queue_table_slots Slots of the fixed-size burst-shape table; kind=\"used\" populated, kind=\"total\" fixed capacity.\n");
            s.push_str("# TYPE onrouter_queue_table_slots gauge\n");
            for (name, q) in lim.queue_rows() {
                let zone = label(&name);
                let (dmin, dmax, delay) = match q.policy {
                    Some(p) => (p.depth_min as u64, p.depth_max as u64, p.max_delay_ms),
                    None => (0, 0, 0),
                };
                s.push_str(&format!(
                    "onrouter_queue_depth{{zone=\"{zone}\",kind=\"min\"}} {dmin}\n"
                ));
                s.push_str(&format!(
                    "onrouter_queue_depth{{zone=\"{zone}\",kind=\"max\"}} {dmax}\n"
                ));
                s.push_str(&format!(
                    "onrouter_queue_depth{{zone=\"{zone}\",kind=\"learned\"}} {}\n",
                    q.learned_max
                ));
                s.push_str(&format!(
                    "onrouter_queue_max_delay_ms{{zone=\"{zone}\"}} {delay}\n"
                ));
                s.push_str(&format!(
                    "onrouter_queue_occupied{{zone=\"{zone}\",kind=\"now\"}} {}\n",
                    q.occupied
                ));
                s.push_str(&format!(
                    "onrouter_queue_occupied{{zone=\"{zone}\",kind=\"max\"}} {}\n",
                    q.occupied_max
                ));
                for (role, v) in [
                    ("queued", q.queued),
                    ("rejected_full", q.rejected_full),
                    ("rejected_slow", q.rejected_slow),
                ] {
                    s.push_str(&format!(
                        "onrouter_queue_events_total{{zone=\"{zone}\",role=\"{role}\"}} {v}\n"
                    ));
                }
                s.push_str(&format!(
                    "onrouter_queue_wait_ms_total{{zone=\"{zone}\"}} {}\n",
                    q.wait_ms_total
                ));
                s.push_str(&format!(
                    "onrouter_queue_depth_adjust_total{{zone=\"{zone}\"}} {}\n",
                    q.depth_adjust
                ));
                s.push_str(&format!(
                    "onrouter_queue_table_bytes{{zone=\"{zone}\"}} {}\n",
                    q.table_bytes
                ));
                s.push_str(&format!(
                    "onrouter_queue_table_slots{{zone=\"{zone}\",kind=\"used\"}} {}\n",
                    q.table_slots
                ));
                s.push_str(&format!(
                    "onrouter_queue_table_slots{{zone=\"{zone}\",kind=\"total\"}} {}\n",
                    q.table_slots_total
                ));
            }
            // 信誉表：只有真建起来了才渲染（与队列同一口径——没在学的东西不占面板）
            if let Some(v) = lim.vip_snapshot() {
                s.push_str("# HELP onrouter_vip_table_bytes Reputation table bytes (fixed size, direct-mapped; 12 B per key).\n");
                s.push_str("# TYPE onrouter_vip_table_bytes gauge\n");
                s.push_str(&format!("onrouter_vip_table_bytes {}\n", v.table_bytes));
                s.push_str("# HELP onrouter_vip_slots Reputation table slots; kind=\"used\" populated, kind=\"total\" fixed capacity.\n");
                s.push_str("# TYPE onrouter_vip_slots gauge\n");
                s.push_str(&format!(
                    "onrouter_vip_slots{{kind=\"used\"}} {}\n",
                    v.slots_used
                ));
                s.push_str(&format!(
                    "onrouter_vip_slots{{kind=\"total\"}} {}\n",
                    v.slots_total
                ));
                s.push_str("# HELP onrouter_vip_score Client reputation scores; kind=\"threshold\" is the configured promotion bar, kind=\"max\" the highest score currently held.\n");
                s.push_str("# TYPE onrouter_vip_score gauge\n");
                s.push_str(&format!("onrouter_vip_score{{kind=\"threshold\"}} {}\n", v.min));
                s.push_str(&format!("onrouter_vip_score{{kind=\"max\"}} {}\n", v.max_score));
                s.push_str("# HELP onrouter_vip_clients Clients currently at or above the promotion threshold.\n");
                s.push_str("# TYPE onrouter_vip_clients gauge\n");
                s.push_str(&format!("onrouter_vip_clients {}\n", v.vip_count));
                s.push_str("# HELP onrouter_vip_decay_ms Silence that costs one reputation point.\n");
                s.push_str("# TYPE onrouter_vip_decay_ms gauge\n");
                s.push_str(&format!("onrouter_vip_decay_ms {}\n", v.decay_ms));
                s.push_str("# HELP onrouter_vip_events_total Rate-limit outcomes fed into reputation; role=\"passed\" within rate (earns credit), role=\"queued\" needed the queue (neutral), role=\"rejected\" hit the limit (costs credit), role=\"promoted\"/\"demoted\" crossed the threshold either way, role=\"collision\" a new key lost the slot to a still-scored incumbent (reputation is never stolen by collision).\n");
                s.push_str("# TYPE onrouter_vip_events_total counter\n");
                for (role, n) in [
                    ("passed", v.passed),
                    ("queued", v.queued),
                    ("rejected", v.rejected),
                    ("promoted", v.promoted),
                    ("demoted", v.demoted),
                    ("collision", v.collision),
                ] {
                    s.push_str(&format!(
                        "onrouter_vip_events_total{{role=\"{role}\"}} {n}\n"
                    ));
                }
            }
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
            // 自适应选点（least_time）：只给真的开了 observe/on 的 upstream 出账目，
            // 默认 off 时一行都不多——指标行数也是"功能关掉就没有代价"的证据之一。
            let lt_on: Vec<_> = ups
                .iter()
                .filter(|u| !matches!(u.least_time, crate::upstream::LeastTime::Off))
                .collect();
            if !lt_on.is_empty() {
                s.push_str("# HELP onrouter_upstream_least_time_mode Adaptive upstream selection tier (0=off 1=observe 2=on).\n");
                s.push_str("# TYPE onrouter_upstream_least_time_mode gauge\n");
                s.push_str("# HELP onrouter_upstream_server_ewma_seconds Latest time-decayed EWMA of the upstream header time observed by the gateway; 0 = never sampled. A stale value is re-probed rather than trusted (see least_time_total role=\"cold\").\n");
                s.push_str("# TYPE onrouter_upstream_server_ewma_seconds gauge\n");
                s.push_str("# HELP onrouter_upstream_least_time_total Adaptive selection accounting: sampled=latency samples taken, picked=choices made by the score, would_differ=observe-only (would have picked elsewhere), cold=exploratory pick of a server whose latency is unknown (never sampled, or estimate older than 4x least_time_window).\n");
                s.push_str("# TYPE onrouter_upstream_least_time_total counter\n");
                for up in lt_on {
                    let mode = match up.least_time {
                        crate::upstream::LeastTime::Off => 0,
                        crate::upstream::LeastTime::Observe => 1,
                        crate::upstream::LeastTime::On => 2,
                    };
                    s.push_str(&format!(
                        "onrouter_upstream_least_time_mode{{upstream=\"{}\"}} {mode}\n",
                        label(&up.name)
                    ));
                    for srv in &up.servers {
                        s.push_str(&format!(
                            "onrouter_upstream_server_ewma_seconds{{upstream=\"{}\",server=\"{}\"}} {:.6}\n",
                            label(&up.name),
                            label(&srv.addr),
                            srv.ewma_seconds()
                        ));
                    }
                    let (sampled, picked, would_differ, cold) = up.least_time_counters();
                    for (role, v) in [
                        ("sampled", sampled),
                        ("picked", picked),
                        ("would_differ", would_differ),
                        ("cold", cold),
                    ] {
                        s.push_str(&format!(
                            "onrouter_upstream_least_time_total{{upstream=\"{}\",role=\"{role}\"}} {v}\n",
                            label(&up.name)
                        ));
                    }
                }
            }
        }
        // 业务分流（proxy_pass http://$变量）：targets 是"这一路实际服务了多少请求"，
        // 拿它除以总数就是运维要核对的那张比例表；total 的 role 说明每一路是怎么被处置的。
        // 没配分流时这里一行都不出（账本按 split 名建立，只有分流真的被解析过才有条目）。
        let splits = crate::engine::split_stats_snapshot();
        if !splits.is_empty() {
            s.push_str("# HELP onrouter_proxy_split_targets_total Requests forwarded to each declared branch of a split route (counted when the gateway hands the request to a node of that branch, before the outcome is known; divide by the branch total to check the observed ratio against the declared one).\n");
            s.push_str("# TYPE onrouter_proxy_split_targets_total counter\n");
            s.push_str("# HELP onrouter_proxy_split_total Split outcome accounting: routed=forwarded to the branch the ratio chose, bled=forwarded to another branch after proxy_split_failover, down=a chosen branch had no selectable node at resolution time (counted per candidate attempt, can exceed the request count), empty=the bucket resolved to an empty target. A backend 5xx never re-routes, so it changes none of these.\n");
            s.push_str("# TYPE onrouter_proxy_split_total counter\n");
            for st in splits {
                for branch in &st.branches {
                    s.push_str(&format!(
                        "onrouter_proxy_split_targets_total{{split=\"{}\",target=\"{}\"}} {}\n",
                        label(&st.dest),
                        label(branch),
                        st.served(branch)
                    ));
                }
                for role in crate::engine::SplitRole::ALL {
                    s.push_str(&format!(
                        "onrouter_proxy_split_total{{split=\"{}\",role=\"{}\"}} {}\n",
                        label(&st.dest),
                        role.label(),
                        st.role(role)
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
        // ngx.shared.DICT 磁盘冷层：运维要看分层到底有没有在转（落盘/冷命中/提升）
        push_dict_zones(&mut s, &crate::disk_cache::snapshot());
        s
    }
}

/// Prometheus 标签值转义：配置里的 upstream/节点名可以含引号或反斜杠。
fn label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// ngx.shared.DICT 磁盘冷层指标。只在真的开了 `disk=` 的区才输出——
/// 没开磁盘层的部署里，这些 0 值序列只是噪音。
fn push_dict_zones(s: &mut String, zones: &[(String, crate::disk_cache::DiskStore)]) {
    if zones.is_empty() {
        return;
    }
    s.push_str("# HELP onrouter_dict_disk_entries Cold tier entries currently indexed on disk.\n");
    s.push_str("# TYPE onrouter_dict_disk_entries gauge\n");
    for (name, z) in zones {
        let n = label(name);
        s.push_str(&format!("onrouter_dict_disk_entries{{dict=\"{n}\"}} {}\n", z.entries()));
    }
    s.push_str("# HELP onrouter_dict_disk_bytes Bytes occupied by committed cold tier entries (headers included).\n");
    s.push_str("# TYPE onrouter_dict_disk_bytes gauge\n");
    for (name, z) in zones {
        s.push_str(&format!(
            "onrouter_dict_disk_bytes{{dict=\"{}\"}} {}\n",
            label(name),
            z.bytes_used()
        ));
    }
    s.push_str("# HELP onrouter_dict_disk_value_bytes Value bytes of live cold entries, excluding headers.\n");
    s.push_str("# TYPE onrouter_dict_disk_value_bytes gauge\n");
    for (name, z) in zones {
        s.push_str(&format!(
            "onrouter_dict_disk_value_bytes{{dict=\"{}\"}} {}\n",
            label(name),
            z.value_bytes()
        ));
    }
    s.push_str("# HELP onrouter_dict_disk_capacity_bytes disk= max_bytes quota for the cold tier.\n");
    s.push_str("# TYPE onrouter_dict_disk_capacity_bytes gauge\n");
    for (name, z) in zones {
        s.push_str(&format!(
            "onrouter_dict_disk_capacity_bytes{{dict=\"{}\"}} {}\n",
            label(name),
            z.config().max_bytes
        ));
    }
    s.push_str("# HELP onrouter_dict_disk_pending_jobs Spill/trim jobs queued but not yet performed by the writer thread.\n");
    s.push_str("# TYPE onrouter_dict_disk_pending_jobs gauge\n");
    for (name, z) in zones {
        let n = label(name);
        let st = z.stats();
        s.push_str(&format!(
            "onrouter_dict_disk_pending_jobs{{dict=\"{n}\"}} {}\n",
            st.pending_jobs.load(Ordering::Relaxed)
        ));
    }
    s.push_str("# HELP onrouter_dict_disk_pending_bytes Bytes queued but not yet on disk.\n");
    s.push_str("# TYPE onrouter_dict_disk_pending_bytes gauge\n");
    for (name, z) in zones {
        s.push_str(&format!(
            "onrouter_dict_disk_pending_bytes{{dict=\"{}\"}} {}\n",
            label(name),
            z.stats().pending_bytes.load(Ordering::Relaxed)
        ));
    }
    s.push_str("# HELP onrouter_dict_disk_operations_total Cold tier operations by kind.\n");
    s.push_str("# TYPE onrouter_dict_disk_operations_total counter\n");
    for (name, z) in zones {
        let n = label(name);
        let st = z.stats();
        for (op, cell) in [
            ("spill", &st.spilled),
            ("spill_skipped", &st.spill_skipped),
            ("cold_hit", &st.cold_hit),
            ("promote", &st.promoted),
            ("evict", &st.evicted),
            ("expire", &st.expired_removed),
            ("corrupt", &st.corrupt),
            ("cold_error", &st.cold_error),
            ("never_read", &st.never_read),
            ("warm_recovered", &st.warm_recovered),
        ] {
            s.push_str(&format!(
                "onrouter_dict_disk_operations_total{{dict=\"{n}\",op=\"{op}\"}} {}\n",
                cell.load(Ordering::Relaxed)
            ));
        }
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

    #[test]
    fn dict_cold_tier_metrics_render_per_zone() {
        // 直接把本地 store 喂给渲染函数，不碰全局注册表——disk_cache 那边的注册表测试
        // 会与之竞争，用全局 snapshot 渲染会偶发失败。
        let dir = std::env::temp_dir().join(format!(
            "onrouter-metrics-disk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = crate::disk_cache::DiskConfig {
            root: dir.clone(),
            spill_after: 0.0,
            ..Default::default()
        };
        let store = crate::disk_cache::DiskStore::open(cfg, None).unwrap();
        assert!(store.spill("k", b"hello", None, 4.0));
        store.flush_pending();
        let mut text = String::new();
        push_dict_zones(&mut text, &[("api cache".to_string(), store.clone())]);
        for needle in [
            "onrouter_dict_disk_entries{dict=\"api cache\"} 1",
            "onrouter_dict_disk_value_bytes{dict=\"api cache\"} 5",
            "onrouter_dict_disk_operations_total{dict=\"api cache\",op=\"spill\"} 1",
            "onrouter_dict_disk_operations_total{dict=\"api cache\",op=\"promote\"} 0",
            "onrouter_dict_disk_pending_jobs{dict=\"api cache\"} 0",
            "# TYPE onrouter_dict_disk_capacity_bytes gauge",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
        assert!(
            !text.contains("onrouter_dict_disk_bytes{dict=\"api cache\"} 0\n"),
            "已落盘的区不该报 0 字节：\n{text}"
        );
        // 没开 disk= 的部署里，这一族完全不应出现
        let mut none = String::new();
        push_dict_zones(&mut none, &[]);
        assert!(none.is_empty(), "无冷层时不该输出任何指标，实际：{none}");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
