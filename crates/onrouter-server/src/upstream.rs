//! upstream 模块：对标 Nginx 的 `upstream` 块。
//!
//! ```text
//! upstream backend {
//!     server 127.0.0.1:9001 weight=2 max_fails=3 fail_timeout=10s;
//!     server 127.0.0.1:9002 backup;
//!     server 127.0.0.1:9003 down;
//!     server 127.0.0.1:9004 max_conns=10;
//!     least_conn;      # 可选：round-robin(默认) / least_conn / ip_hash
//!     health_check interval=5s fails=3 rises=2 uri=/status timeout=2s;
//! }
//! ```
//!
//! - 负载均衡：平滑加权轮询（默认，nginx 的 SWRR）/ least_conn / ip_hash
//! - 被动健康检查：满 max_fails 次就把 effective_weight 降一档并进入 fail_timeout 摘除期，
//!   到期后惰性恢复。权重归零的节点仍会被偶尔选中 —— 这就是 nginx 的自愈通道
//! - 主动健康检查：后台探测 TCP 连通性（或 `uri=` 的 HTTP 状态），fails/rises 双阈值翻转
//! - 节点属性：`backup`（主组没有可用节点才接流量）、`down`（永久摘除）、`max_conns`（并发额度）
//! - 全部节点不可选时 acquire 返回 None，代理层据此给 502（对齐 nginx "no live upstreams"）

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onrouter_config::Directive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{log_error, log_info, log_warn};
use crate::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalance {
    RoundRobin,
    LeastConn,
    IpHash,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `health_check` 指令（nginx Plus 同名指令的子集 + uri/timeout）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    pub interval: Duration,
    pub timeout: Duration,
    /// 连续失败多少次判定不健康
    pub fails: usize,
    /// 连续成功多少次恢复健康
    pub rises: usize,
    /// None = 只做 TCP 连接；Some = HTTP GET 并要求 2xx/3xx
    pub uri: Option<String>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        HealthCheck {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            fails: 3,
            rises: 1,
            uri: None,
        }
    }
}

/// 上游 keep-alive 连接池调优（对标 nginx 的 `keepalive N` / `keepalive_timeout`）。
/// 两者都用 `Option`：None 表示沿用 hyper 客户端池的默认值（不显式设上限/超时），
/// 只有配置里出现对应指令时才收紧。代理层把它并入连接池客户端的缓存键，
/// 使不同 keepalive 配置的上游各得一套独立池。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepaliveOpts {
    /// `keepalive N`：每个后端主机在池中保留的空闲连接上限
    pub max_idle: Option<usize>,
    /// `keepalive_timeout X`：空闲连接被回收前最多保活多久
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug)]
pub struct UpstreamServer {
    pub addr: String,
    pub weight: usize,
    pub max_fails: usize,
    /// 摘除时长（秒）
    pub fail_timeout: f64,
    /// 备份机：主组全部不可用后才参与
    pub backup: bool,
    /// 配置里手工标死（`down`）：永不参与，也不主动探测
    pub manually_down: bool,
    /// 并发额度，0 = 不限
    pub max_conns: usize,
    pub conns: AtomicUsize,
    /// 主动健康检查结论；未配置探测时恒为 true
    pub healthy: AtomicBool,
    /// 代理层上报的请求结果（指标用；是否触发摘除由 fails 单独判定）
    successes: AtomicU64,
    failures: AtomicU64,
    fails: AtomicUsize,
    /// 被动摘除截止时间（epoch 毫秒；0 = 可用）
    down_until: AtomicU64,
    probe_fails: AtomicUsize,
    probe_rises: AtomicUsize,
    /// SWRR 状态：只在持有 `Upstream::schedule` 锁时写（acquire 路径）
    current_weight: AtomicIsize,
    effective_weight: AtomicIsize,
}

impl UpstreamServer {
    fn new(addr: String, weight: usize, max_fails: usize, fail_timeout: f64) -> Self {
        UpstreamServer {
            addr,
            weight,
            max_fails,
            fail_timeout,
            backup: false,
            manually_down: false,
            max_conns: 0,
            conns: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            fails: AtomicUsize::new(0),
            down_until: AtomicU64::new(0),
            probe_fails: AtomicUsize::new(0),
            probe_rises: AtomicUsize::new(0),
            current_weight: AtomicIsize::new(0),
            effective_weight: AtomicIsize::new(weight as isize),
        }
    }

    fn effective(&self) -> isize {
        self.effective_weight.load(Ordering::Relaxed)
    }

    /// 被动摘除窗口到期后恢复权重：nginx 用定时器做，这里惰性检查，效果等价且省一个定时器
    fn restore_if_expired(&self, now: u64) {
        let until = self.down_until.load(Ordering::Relaxed);
        if until != 0 && now >= until {
            self.down_until.store(0, Ordering::Relaxed);
            self.fails.store(0, Ordering::Relaxed);
            self.effective_weight
                .store(self.weight as isize, Ordering::Relaxed);
        }
    }

    fn conns_available(&self) -> bool {
        self.max_conns == 0 || self.conns.load(Ordering::Relaxed) < self.max_conns
    }

    /// 可选节点：没被标死、主动探测通过、并发额度未满
    fn selectable(&self) -> bool {
        !self.manually_down && self.healthy.load(Ordering::Relaxed) && self.conns_available()
    }

    /// 满 max_fails 次：有效权重降一档（最低 0）并进入摘除期。
    /// 权重降到 0 不等于永久摘除——fail_timeout 到期后靠真实流量试探恢复。
    fn note_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n < self.max_fails.max(1) {
            return;
        }
        self.fails.store(0, Ordering::Relaxed);
        let next = (self.effective() - self.weight as isize).max(0);
        self.effective_weight.store(next, Ordering::Relaxed);
        self.down_until
            .store(now_millis() + (self.fail_timeout * 1000.0) as u64, Ordering::Relaxed);
        log_warn!(
            "upstream 节点 {} 连续失败 {n} 次，降权至 {next}，摘除 {:.0}s",
            self.addr,
            self.fail_timeout
        );
    }

    fn note_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        self.fails.store(0, Ordering::Relaxed);
        self.down_until.store(0, Ordering::Relaxed);
        self.effective_weight
            .store(self.weight as isize, Ordering::Relaxed);
    }

    /// 代理层上报的累计成功/失败数（指标渲染用）
    pub fn success_count(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// 主动探测结果落账：fails/rises 双阈值，只在状态翻转时打日志（避免每轮刷屏）
    fn apply_probe(&self, hc: &HealthCheck, ok: bool) {
        if ok {
            self.probe_fails.store(0, Ordering::Relaxed);
            let r = self.probe_rises.fetch_add(1, Ordering::Relaxed) + 1;
            if !self.healthy.load(Ordering::Relaxed) && r >= hc.rises.max(1) {
                self.healthy.store(true, Ordering::Relaxed);
                self.probe_rises.store(0, Ordering::Relaxed);
                log_info!("主动健康检查：{} 恢复", self.addr);
            }
        } else {
            self.probe_rises.store(0, Ordering::Relaxed);
            let f = self.probe_fails.fetch_add(1, Ordering::Relaxed) + 1;
            if self.healthy.load(Ordering::Relaxed) && f >= hc.fails.max(1) {
                self.healthy.store(false, Ordering::Relaxed);
                self.probe_fails.store(0, Ordering::Relaxed);
                log_error!("主动健康检查：{} 连续失败 {f} 次，摘除", self.addr);
            }
        }
    }
}

#[derive(Debug)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub lb: LoadBalance,
    pub health_check: Option<HealthCheck>,
    /// keep-alive 连接池调优（`keepalive` / `keepalive_timeout`）
    pub keepalive: KeepaliveOpts,
    /// 调度锁：nginx 每个请求取一次 peer 锁，这里不做无锁近似，
    /// 否则并发请求会把 SWRR 的 current_weight 写成乱账
    schedule: Mutex<()>,
}

impl Upstream {
    /// 选一个后端并把连接数 +1（guard drop 时 -1）。
    /// `tried` = 本次请求已试过的下标（换节点重试时回填）；主组被试完/全不可用时自动切 backup 组，
    /// 与 nginx 的 `rrp->failed` 后换 peer set 的行为一致。两组都没有可选节点时返回 None。
    pub fn acquire(self: &Arc<Self>, client_ip: &str, tried: &[usize]) -> Option<UpstreamGuard> {
        let _sched = self.schedule.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_millis();
        for s in &self.servers {
            s.restore_if_expired(now);
        }

        let mut group = self.candidates(false, tried);
        if group.is_empty() {
            group = self.candidates(true, tried);
        }
        if group.is_empty() {
            return None;
        }
        // 摘除期内的节点权重已归零：只要还有正权重节点就不给它流量；
        // 全组都是零时保留原组，让流量去试探最早失败的节点（否则一旦全摘除就再也起不来）。
        // 原地 retain 而不是再 collect 一个 Vec：取节点在每请求热路径上，省一次分配。
        if group.iter().any(|i| self.servers[*i].effective() > 0) {
            group.retain(|i| self.servers[*i].effective() > 0);
        }

        let idx = match self.lb {
            LoadBalance::RoundRobin => self.pick_swrr(&group),
            LoadBalance::LeastConn => self.pick_least_conn(&group),
            LoadBalance::IpHash => self.pick_ip_hash(client_ip, &group),
        };
        self.servers[idx].conns.fetch_add(1, Ordering::Relaxed);
        Some(UpstreamGuard {
            upstream: Arc::clone(self),
            idx,
        })
    }

    fn candidates(&self, backup_group: bool, tried: &[usize]) -> Vec<usize> {
        (0..self.servers.len())
            .filter(|i| self.servers[*i].backup == backup_group)
            .filter(|i| !tried.contains(i))
            .filter(|i| self.servers[*i].selectable())
            .collect()
    }

    /// nginx 平滑加权轮询：每轮 `current += effective`，取最大者后 `current -= total`。
    /// weight=5/1/1 的一轮是 a a b a c a a，之后状态回到全零 —— 分布均匀且不需要历史。
    fn pick_swrr(&self, candidates: &[usize]) -> usize {
        let mut total: isize = 0;
        let mut best = candidates[0];
        for &i in candidates {
            let s = &self.servers[i];
            let eff = s.effective();
            total += eff;
            s.current_weight.fetch_add(eff, Ordering::Relaxed);
            if s.current_weight.load(Ordering::Relaxed)
                > self.servers[best].current_weight.load(Ordering::Relaxed)
            {
                best = i;
            }
        }
        self.servers[best]
            .current_weight
            .fetch_sub(total, Ordering::Relaxed);
        best
    }

    fn pick_least_conn(&self, candidates: &[usize]) -> usize {
        let mut best = candidates[0];
        let mut best_metric = f64::INFINITY;
        for &i in candidates {
            let s = &self.servers[i];
            let metric = s.conns.load(Ordering::Relaxed) as f64 / s.weight.max(1) as f64;
            if metric < best_metric {
                best_metric = metric;
                best = i;
            }
        }
        best
    }

    fn pick_ip_hash(&self, client_ip: &str, candidates: &[usize]) -> usize {
        let mut h: u64 = 5381;
        for b in client_ip.bytes() {
            h = h.wrapping_mul(33) ^ b as u64;
        }
        let total: usize = candidates.iter().map(|&i| self.servers[i].weight).sum();
        let mut target = (h as usize) % total.max(1);
        for &i in candidates {
            if target < self.servers[i].weight {
                return i;
            }
            target -= self.servers[i].weight;
        }
        candidates[0]
    }

    /// 代理层上报健康结果。只写节点自身的原子量，不碰 SWRR 的 current_weight，
    /// 因此无需调度锁——锁只保护 acquire 的选点轨迹。
    pub fn report(&self, idx: usize, ok: bool) {
        let Some(s) = self.servers.get(idx) else {
            return;
        };
        if ok {
            s.note_success();
        } else {
            s.note_failure();
        }
    }

    /// 节点数：代理层用它决定换节点重试的上限
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// 启动主动健康检查后台任务；`down` 节点跳过，停机信号置位后退出。
    /// 一个 upstream 一个任务，任务内串行探测（节点规模到几百再考虑并发）。
    pub fn spawn_health_check(
        self: &Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let hc = self.health_check.clone()?;
        let up = Arc::clone(self);
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(hc.interval) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
                for s in &up.servers {
                    if s.manually_down {
                        continue;
                    }
                    let ok = probe(&s.addr, &hc).await;
                    s.apply_probe(&hc, ok);
                }
            }
        }))
    }
}

/// 一次探测：TCP 必须连通；配了 `uri=` 还要在同一连接上读完状态行并要求 2xx/3xx
async fn probe(addr: &str, hc: &HealthCheck) -> bool {
    let connected =
        tokio::time::timeout(hc.timeout, tokio::net::TcpStream::connect(addr)).await;
    let Ok(Ok(stream)) = connected else {
        return false;
    };
    match hc.uri.as_deref() {
        None => true,
        Some(uri) => {
            tokio::time::timeout(hc.timeout, http_probe(stream, addr, uri))
                .await
                .unwrap_or(false)
        }
    }
}

async fn http_probe(mut stream: tokio::net::TcpStream, addr: &str, uri: &str) -> bool {
    let req = format!("GET {uri} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; 512];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n >= 12 => n,
        _ => return false,
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    // 状态行是 "HTTP/1.1 <code> <reason>"：状态码在版本 token 之后
    let Some(code) = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
    else {
        return false;
    };
    (200..400).contains(&code)
}

/// 连接租约：drop 时连接数 -1；代理层用 note_success/note_failure 上报健康
pub struct UpstreamGuard {
    upstream: Arc<Upstream>,
    idx: usize,
}

impl UpstreamGuard {
    pub fn note_success(&self) {
        self.upstream.report(self.idx, true);
    }

    pub fn note_failure(&self) {
        self.upstream.report(self.idx, false);
    }

    /// 已试过的节点下标：代理换节点重试时回填给 acquire
    pub fn idx(&self) -> usize {
        self.idx
    }
}

impl std::ops::Deref for UpstreamGuard {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.upstream.servers[self.idx].addr
    }
}

impl Drop for UpstreamGuard {
    fn drop(&mut self) {
        self.upstream.servers[self.idx]
            .conns
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct UpstreamPool {
    pub map: HashMap<String, Arc<Upstream>>,
}

impl UpstreamPool {
    pub fn parse_all(config: &onrouter_config::Config) -> Result<Self, AppError> {
        let mut map = HashMap::new();
        for d in config.root.block.iter().filter(|d| d.name == "upstream") {
            let up = Self::parse_upstream(d)?;
            map.insert(up.name.clone(), Arc::new(up));
        }
        Ok(UpstreamPool { map })
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Upstream>> {
        self.map.get(name)
    }

    /// 起后台探测任务，返回的 handle 由调用方在退出时 abort
    pub fn spawn_health_checks(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        self.map
            .values()
            .filter_map(|u| u.spawn_health_check(shutdown.clone()))
            .collect()
    }

    fn parse_upstream(d: &Directive) -> Result<Upstream, AppError> {
        let name = d
            .arg(0)
            .ok_or_else(|| AppError::Other("upstream 缺少名称".into()))?
            .to_string();
        let mut servers = Vec::new();
        let mut lb = LoadBalance::RoundRobin;
        let mut health_check = None;
        let mut keepalive = KeepaliveOpts::default();
        for child in &d.block {
            match child.name.as_str() {
                "keepalive" => {
                    let v = child.arg(0).ok_or_else(|| {
                        AppError::Other(format!("upstream {name}: keepalive 需要一个正整数参数"))
                    })?;
                    keepalive.max_idle =
                        Some(strict_positive(v, &name, "keepalive")?);
                }
                "keepalive_timeout" => {
                    let v = child.arg(0).ok_or_else(|| {
                        AppError::Other(format!("upstream {name}: keepalive_timeout 需要一个时长参数"))
                    })?;
                    keepalive.idle_timeout = Some(parse_duration(v).ok_or_else(|| {
                        AppError::Other(format!("upstream {name}: keepalive_timeout={v} 非法"))
                    })?);
                }
                "server" => {
                    let addr = child
                        .arg(0)
                        .ok_or_else(|| AppError::Other(format!("upstream {name} 的 server 缺少地址")))?
                        .to_string();
                    let mut weight = 1usize;
                    let mut max_fails = 1usize;
                    let mut fail_timeout = 10.0f64;
                    let mut backup = false;
                    let mut down = false;
                    let mut max_conns = 0usize;
                    for a in &child.args[1..] {
                        let (k, v) = match a.split_once('=') {
                            Some((k, v)) => (k, Some(v)),
                            None => (a.as_str(), None),
                        };
                        match (k, v) {
                            ("weight", Some(v)) => {
                                weight = strict_positive(v, &name, "weight")?;
                                if weight > 256 {
                                    return Err(AppError::Other(format!(
                                        "upstream {name}: weight 不能超过 256（收到 {v}）"
                                    )));
                                }
                            }
                            ("max_fails", Some(v)) => max_fails = strict_positive(v, &name, "max_fails")?,
                            ("fail_timeout", Some(v)) => {
                                fail_timeout = parse_seconds(v)
                                    .filter(|x| *x > 0.0)
                                    .ok_or_else(|| {
                                        AppError::Other(format!(
                                            "upstream {name}: fail_timeout={v} 非法"
                                        ))
                                    })?
                            }
                            ("max_conns", Some(v)) => max_conns = strict_positive(v, &name, "max_conns")?,
                            ("backup", None) => backup = true,
                            ("down", None) => down = true,
                            _ => {
                                return Err(AppError::Other(format!(
                                    "upstream {name}: server 不认识的参数 {a}"
                                )))
                            }
                        }
                    }
                    let mut s = UpstreamServer::new(addr, weight, max_fails, fail_timeout);
                    s.backup = backup;
                    s.manually_down = down;
                    s.max_conns = max_conns;
                    servers.push(s);
                }
                "least_conn" => lb = LoadBalance::LeastConn,
                "ip_hash" => lb = LoadBalance::IpHash,
                "health_check" => health_check = Some(parse_health_check(child, &name)?),
                _ => {
                    return Err(AppError::Other(format!(
                        "upstream {name} 里有不支持的指令 {}",
                        child.name
                    )))
                }
            }
        }
        if servers.is_empty() {
            return Err(AppError::Other(format!("upstream {name} 没有任何 server")));
        }
        if servers.iter().all(|s| s.manually_down) {
            return Err(AppError::Other(format!(
                "upstream {name} 的所有 server 都是 down"
            )));
        }
        if !servers.iter().any(|s| !s.backup) {
            return Err(AppError::Other(format!(
                "upstream {name} 没有主组节点：全是 backup"
            )));
        }
        if matches!(lb, LoadBalance::IpHash) && servers.iter().any(|s| s.backup) {
            return Err(AppError::Other(format!(
                "upstream {name}: ip_hash 不能和 backup 同时使用"
            )));
        }
        Ok(Upstream {
            name,
            servers,
            lb,
            health_check,
            keepalive,
            schedule: Mutex::new(()),
        })
    }
}

fn strict_positive(v: &str, up: &str, key: &str) -> Result<usize, AppError> {
    v.trim()
        .parse::<usize>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            AppError::Other(format!(
                "upstream {up}: {key}={v} 必须是正整数"
            ))
        })
}

/// 接受 `10s` / `10` / `500ms` / `1m`
fn parse_seconds(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.trim().parse::<f64>().ok().map(|v| v / 1000.0);
    }
    if let Some(m) = s.strip_suffix('m') {
        return m.trim().parse::<f64>().ok().map(|v| v * 60.0);
    }
    if let Some(sec) = s.strip_suffix('s') {
        return sec.trim().parse::<f64>().ok();
    }
    s.parse::<f64>().ok()
}

fn parse_duration(s: &str) -> Option<Duration> {
    parse_seconds(s)
        .filter(|v| *v > 0.0)
        .map(Duration::from_secs_f64)
}

fn parse_health_check(d: &Directive, up_name: &str) -> Result<HealthCheck, AppError> {
    let mut hc = HealthCheck::default();
    // Directive.args 不含指令名本身
    for a in &d.args {
        let (k, v) = a.split_once('=').ok_or_else(|| {
            AppError::Other(format!(
                "upstream {up_name}: health_check 参数 {a} 不是 key=value"
            ))
        })?;
        match (k, v) {
            ("interval", v) => {
                hc.interval = parse_duration(v).ok_or_else(|| {
                    AppError::Other(format!("upstream {up_name}: interval={v} 非法"))
                })?
            }
            ("timeout", v) => {
                hc.timeout = parse_duration(v).ok_or_else(|| {
                    AppError::Other(format!("upstream {up_name}: timeout={v} 非法"))
                })?
            }
            ("fails", v) => {
                hc.fails = v.trim().parse::<usize>().ok().filter(|n| *n > 0).ok_or_else(|| {
                    AppError::Other(format!("upstream {up_name}: fails={v} 必须是正整数"))
                })?
            }
            ("rises", v) => {
                hc.rises = v.trim().parse::<usize>().ok().filter(|n| *n > 0).ok_or_else(|| {
                    AppError::Other(format!("upstream {up_name}: rises={v} 必须是正整数"))
                })?
            }
            ("uri", v) => {
                if !v.starts_with('/') {
                    return Err(AppError::Other(format!(
                        "upstream {up_name}: health_check uri 必须以 / 开头，收到 {v}"
                    )));
                }
                hc.uri = Some(v.to_string());
            }
            (k, v) => {
                return Err(AppError::Other(format!(
                    "upstream {up_name}: health_check 不支持的参数 {k}={v}"
                )))
            }
        }
    }
    Ok(hc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(conf: &str) -> Result<UpstreamPool, AppError> {
        let cfg = onrouter_config::Config::parse(&format!("upstream u {{ {conf} }}"))
            .expect("配置应能解析");
        UpstreamPool::parse_all(&cfg)
    }

    fn upstream(conf: &str) -> Arc<Upstream> {
        Arc::clone(pool(conf).unwrap().get("u").unwrap())
    }

    /// 一次选完就立刻释放连接租约，否则 max_conns/least_conn 的计数会串扰
    fn pick_release(up: &Arc<Upstream>) -> String {
        let g = up.acquire("10.0.0.1", &[]).expect("应有可用节点");
        let addr = (*g).clone();
        drop(g);
        addr
    }

    #[test]
    fn swrr_reproduces_nginx_weighted_sequence() {
        // weight=5/1/1：SWRR 的轨迹是 a a b a c a a，一轮之后 current_weight 全部归零
        let up = upstream(
            "server a weight=5; server b weight=1; server c weight=1; ",
        );
        let seq: Vec<String> = (0..7).map(|_| pick_release(&up)).collect();
        assert_eq!(
            seq,
            vec!["a", "a", "b", "a", "c", "a", "a"],
            "SWRR 序列不符: {seq:?}"
        );
        // 状态回到零点：下一轮分布完全一致，不会随时间漂移
        let seq2: Vec<String> = (0..7).map(|_| pick_release(&up)).collect();
        assert_eq!(seq2, seq);
        // 等权重的两台必须严格交替
        let up = upstream("server a; server b; ");
        let alt: Vec<String> = (0..6).map(|_| pick_release(&up)).collect();
        assert_eq!(alt, vec!["a", "b", "a", "b", "a", "b"], "等权重应交替: {alt:?}");
    }

    /// 强制选中某个下标的节点（把它以外的都标成已试过），用来精确制造失败
    fn fail_on(up: &Arc<Upstream>, idx: usize) {
        let tried: Vec<usize> = (0..up.servers.len()).filter(|i| *i != idx).collect();
        let g = up.acquire("10.0.0.1", &tried).expect("该节点应仍可选");
        assert_eq!(g.idx(), idx);
        g.note_failure();
        drop(g);
    }

    #[test]
    fn passive_failure_excludes_node_then_recovers() {
        let up = upstream("server a max_fails=2 fail_timeout=0.05s; server b; ");
        // 第 1 次失败没到阈值，权重不动
        fail_on(&up, 0);
        assert_eq!(up.servers[0].effective(), 1, "未到 max_fails 不该降权");
        // 第 2 次到阈值：进入摘除期，这段时间只会选到 b
        fail_on(&up, 0);
        assert_eq!(up.servers[0].effective(), 0, "到阈值应把有效权重降为零");
        for _ in 0..5 {
            assert_eq!(pick_release(&up), "b");
        }
        // fail_timeout 到期后 a 带着完整权重回来
        std::thread::sleep(Duration::from_millis(80));
        let seen: Vec<String> = (0..4).map(|_| pick_release(&up)).collect();
        assert!(seen.contains(&"a".to_string()), "摘除期过后 a 应重新参与: {seen:?}");
    }

    #[test]
    fn success_restores_weight_without_waiting_for_timeout() {
        let up = upstream("server a max_fails=1 fail_timeout=60s; server b; ");
        fail_on(&up, 0);
        // 60s 的摘除期还没到，只应该选到 b
        for _ in 0..4 {
            assert_eq!(pick_release(&up), "b");
        }
        // 一次成功就完全恢复（nginx 的 free_round_robin_peer 语义）
        up.report(0, true);
        assert_eq!(up.servers[0].effective(), 1);
        let seen: Vec<String> = (0..4).map(|_| pick_release(&up)).collect();
        assert!(seen.contains(&"a".to_string()), "成功后应立刻恢复: {seen:?}");
    }

    #[test]
    fn backup_only_serves_when_primary_group_empty() {
        let up = upstream("server p1; server p2; server bk backup; ");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            seen.insert(pick_release(&up));
        }
        assert!(!seen.contains("bk"), "主组活着不该碰 backup: {seen:?}");
        assert_eq!(seen, set_of(["p1", "p2"]));

        // 主组全部标死 -> 切 backup
        let up = upstream("server p1 down; server p2 down; server bk backup; ");
        assert_eq!(pick_release(&up), "bk");
    }

    fn set_of<'a, I: IntoIterator<Item = &'a str>>(xs: I) -> std::collections::HashSet<String> {
        xs.into_iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn down_node_is_never_picked_and_exhaustion_yields_none() {
        let up = upstream("server a down; server b; ");
        for _ in 0..6 {
            assert_eq!(pick_release(&up), "b");
        }
        // 唯一的可用节点已在本轮试过 -> 没有可选节点（代理层据此出 502）
        assert!(up.acquire("10.0.0.1", &[1]).is_none());
    }

    #[test]
    fn max_conns_gates_and_releases() {
        let up = upstream("server a max_conns=1; server b; ");
        let a = up.acquire("10.0.0.1", &[1]).unwrap();
        assert_eq!(&*a, "a");
        // a 的唯一额度被占满：此后只可能选到 b
        for _ in 0..4 {
            let g = up.acquire("10.0.0.1", &[]).unwrap();
            assert_eq!(&*g, "b", "额度满的节点不该再被选中");
            drop(g);
        }
        drop(a);
        // 租约释放后 a 回来
        let seen: Vec<String> = (0..4).map(|_| pick_release(&up)).collect();
        assert!(seen.contains(&"a".to_string()), "释放额度后应重新参与: {seen:?}");
        // 主组额度满但还有 backup：换节点重试应切到备组，而不是 502
        let up = upstream("server a max_conns=1; server b backup; ");
        let held = up.acquire("10.0.0.1", &[]).unwrap();
        assert_eq!(&*held, "a");
        let fallback = up.acquire("10.0.0.1", &[0]).expect("主组没额度时应落到 backup");
        assert_eq!(&*fallback, "b");
        drop((held, fallback));
        // 两组都没有可选节点才返回 None
        let up = upstream("server a max_conns=1; ");
        let held = up.acquire("10.0.0.1", &[]).unwrap();
        assert!(up.acquire("10.0.0.1", &[0]).is_none(), "唯一节点已试过应无可选");
        assert!(up.acquire("10.0.0.1", &[]).is_none(), "唯一节点额度已满，不该硬塞");
        drop(held);
        assert_eq!(
            up.acquire("10.0.0.1", &[]).map(|g| (*g).clone()),
            Some("a".to_string()),
            "额度释放后应恢复可选"
        );
    }

    #[test]
    fn least_conn_and_ip_hash_respect_selection() {
        let up = upstream("least_conn; server a weight=1; server b; ");
        let g1 = up.acquire("10.0.0.1", &[]).unwrap();
        let g2 = up.acquire("10.0.0.1", &[]).unwrap();
        assert_ne!(&*g1, &*g2, "least_conn 应把并发摊到两个节点");
        drop((g1, g2));

        let up = upstream("ip_hash; server a; server b; server c; ");
        let one = pick_release(&up);
        for _ in 0..5 {
            assert_eq!(pick_release(&up), one, "同一客户端 IP 应稳定命中同一节点");
        }
    }

    #[test]
    fn active_probe_flips_health_on_thresholds() {
        let up = upstream("server a; ");
        let s = &up.servers[0];
        let hc = HealthCheck {
            fails: 2,
            rises: 3,
            ..Default::default()
        };
        s.apply_probe(&hc, false);
        assert!(s.healthy.load(Ordering::Relaxed), "未达阈值不该摘");
        s.apply_probe(&hc, false);
        assert!(!s.healthy.load(Ordering::Relaxed), "连续 2 次失败应摘除");
        // 中途一次失败要重新计数
        s.apply_probe(&hc, true);
        s.apply_probe(&hc, true);
        s.apply_probe(&hc, false);
        s.apply_probe(&hc, true);
        s.apply_probe(&hc, true);
        assert!(!s.healthy.load(Ordering::Relaxed), "成功计数被失败打断，未达 rises 不该恢复");
        s.apply_probe(&hc, true);
        assert!(s.healthy.load(Ordering::Relaxed), "连续 3 次成功应恢复");
        assert!(up.acquire("10.0.0.1", &[]).is_some());
        s.apply_probe(&hc, false);
        s.apply_probe(&hc, false);
        assert!(up.acquire("10.0.0.1", &[]).is_none(), "探测失败期间不该有可选节点");
    }

    #[tokio::test]
    async fn probe_checks_tcp_connectivity_and_http_status() {
        let serving = fake_backend("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let broken = fake_backend("HTTP/1.0 503 Service Unavailable\r\n\r\n").await;
        // 曾经监听、已经关掉的端口：connect 直接被拒
        let dead = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap().to_string();
            drop(l);
            a
        };
        let tcp_only = HealthCheck {
            timeout: Duration::from_secs(2),
            uri: None,
            ..Default::default()
        };
        let with_uri = HealthCheck {
            timeout: Duration::from_secs(2),
            uri: Some("/status".into()),
            ..Default::default()
        };
        assert!(probe(&serving, &tcp_only).await);
        assert!(probe(&serving, &with_uri).await, "2xx 应判健康");
        assert!(!probe(&broken, &with_uri).await, "5xx 应判不健康");
        assert!(!probe(&dead, &tcp_only).await, "拒接的端口应判不健康");
    }

    /// 起一个固定应答的假后端，返回它的地址
    async fn fake_backend(reply: &'static str) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 128];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        addr
    }

    #[test]
    fn config_parses_all_node_attributes() {
        let up = upstream(
            "server a weight=3 max_fails=4 fail_timeout=30s; \
             server b backup max_conns=50; server c down; \
             health_check interval=2s fails=5 rises=4 uri=/status timeout=500ms; ",
        );
        assert_eq!(up.servers[0].weight, 3);
        assert_eq!(up.servers[0].max_fails, 4);
        assert_eq!(up.servers[0].fail_timeout, 30.0);
        assert!(up.servers[1].backup);
        assert_eq!(up.servers[1].max_conns, 50);
        assert!(up.servers[2].manually_down);
        assert_eq!(
            up.health_check,
            Some(HealthCheck {
                interval: Duration::from_secs(2),
                timeout: Duration::from_millis(500),
                fails: 5,
                rises: 4,
                uri: Some("/status".into()),
            })
        );
    }

    #[test]
    fn config_parses_keepalive_knobs() {
        let up = upstream("server a; keepalive 16; keepalive_timeout 30s; ");
        assert_eq!(up.keepalive.max_idle, Some(16));
        assert_eq!(up.keepalive.idle_timeout, Some(Duration::from_secs(30)));
        // 缺省 = None（沿用 hyper 客户端池默认，不显式设上限/超时）
        let up2 = upstream("server a; ");
        assert_eq!(up2.keepalive.max_idle, None);
        assert_eq!(up2.keepalive.idle_timeout, None);
        // 非法值必须报错，而不是猜一个默认
        assert!(pool("server a; keepalive; ").is_err(), "keepalive 缺参数应拒绝");
        assert!(pool("server a; keepalive 0; ").is_err(), "keepalive 必须正整数");
        assert!(pool("server a; keepalive abc; ").is_err());
        assert!(
            pool("server a; keepalive_timeout abc; ").is_err(),
            "keepalive_timeout 非法时长应拒绝"
        );
    }

    #[test]
    fn config_rejects_nonsense_instead_of_guessing() {
        for conf in [
            "server a weight=0; ",
            "server a weight=300; ",
            "server a weight=abc; ",
            "server a fail_timeout=abc; ",
            "server a max_conns=0; ",
            "server a bogus=1; ",
            "server a mystery; ",
            "server a down; server b down; ",
            "server a backup; ",
            "ip_hash; server a; server b backup; ",
            "server a; health_check uri=status; ",
            "server a; health_check bogus=1; ",
            "server a; fair; ",
        ] {
            assert!(
                pool(conf).is_err(),
                "应当拒绝这份配置: {conf}"
            );
        }
        assert!(pool("server a; health_check; ").is_ok(), "health_check 允许无参");
    }
}
