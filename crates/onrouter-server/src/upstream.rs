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

/// `least_time off|observe|on` —— 自适应选点的三档。
///
/// 分成三档是本项目对"先量后改"的固定要求（和 `front_proxy_mode` 的 off/detect/egress 同构）：
/// * [`LeastTime::Off`]（默认）：一个原子量都不写，选点路径与没有这段代码时逐字节一致。
/// * [`LeastTime::Observe`]：照常按配置的方法选点，但**开始记账**——记录每个后端的响应时间 EWMA，
///   并统计"如果按自适应打分选，会和实际选点不同"的次数。运营者据此先看清证据再决定开 `on`。
/// * [`LeastTime::On`]：用 P2C + EWMA 打分选点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeastTime {
    Off,
    Observe,
    On,
}

/// EWMA 的样本上限：再慢的响应也不该把某个节点的记忆拉爆（超时/失败根本不入账，见 `note_latency`）。
const MAX_SAMPLE_SECONDS: f64 = 30.0;
/// 打分里的时延下限，防止"极快后端"把乘积压成 0 从而永远赢。
const MIN_LATENCY_SECONDS: f64 = 1e-6;
/// 记忆有效期 = `least_time_window` 的几倍。**必须有**：观测只在"这个节点被选中"时发生，
/// 于是一个被误判为慢、从此拿不到流量的后端，它的旧估计永远不会被新样本改写 —— 纯靠时延打分就会
/// 把它永久饿死。超过这个时长没样本，就当作"不知道它现在多快"，重新纳入探索（见 `known_ewma`）。
const LT_EXPIRE_MULT: f64 = 4.0;

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
    /// 观测到的响应头时间 EWMA，存 f64 秒的位（`AtomicU64`）。**0 是"还没有样本"的哨兵**，
    /// 不是"耗时 0 秒"——真实的响应头不可能在 0 秒内到达。见 [`Upstream::note_latency`]。
    ewma_bits: AtomicU64,
    /// 上一个样本的 epoch 毫秒：EWMA 按**时间**衰减，不是按样本数。
    /// 高 QPS 下每个样本只推进很小一步（窗口内平均）；流量停了一阵再来时，α 已经趋近 1，
    /// 第一个新样本几乎完全改写旧值——于是一次长暂停之后的旧记忆自然淡出，
    /// 不会让十分钟前的慢样本永远压着现在很快的节点。
    ewma_last_ms: AtomicU64,
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
            ewma_bits: AtomicU64::new(0),
            ewma_last_ms: AtomicU64::new(0),
        }
    }

    /// 当前 EWMA 估计（秒）。`0.0` = 还没有样本（哨兵，见 `ewma_bits`）。
    /// 内部存的是**纳秒**：`note_latency` 写入时钳到最小 1ns，这样"有样本但极快"
    /// 永远不会撞上空闲哨兵 `0`。
    pub fn ewma_seconds(&self) -> f64 {
        let bits = self.ewma_bits.load(Ordering::Acquire);
        if bits == 0 {
            0.0
        } else {
            f64::from_bits(bits) / 1e9
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
    /// `least_time off|observe|on`
    pub least_time: LeastTime,
    /// EWMA 的时间窗口（秒）：`least_time_window`，默认 5s
    pub lt_window: f64,
    /// P2C 的两个候选从这个非加密 PRNG 抽（splitmix64）。选点不需要密码学随机，
    /// 但需要**便宜**：一个原子 fetch_add 就够，不能每请求分配。
    rng: AtomicU64,
    /// 自适应打分的账目（`role` 标签见 metrics 渲染）
    lt_sampled: AtomicU64,
    lt_picked: AtomicU64,
    lt_would_differ: AtomicU64,
    lt_cold_pick: AtomicU64,
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

        let mut idx = match self.lb {
            LoadBalance::RoundRobin => self.pick_swrr(&group),
            LoadBalance::LeastConn => self.pick_least_conn(&group),
            LoadBalance::IpHash => self.pick_ip_hash(client_ip, &group),
        };
        match self.least_time {
            LeastTime::Off => {}
            // 证据期：选点结果**必须**与 off 一致，只多算一次假想打分并记差分。
            // 假想打分是纯读的（不碰 current_weight），所以不会污染上面已经走完了的 SWRR 轨迹。
            LeastTime::Observe => {
                if self.pick_least_time(&group) != idx {
                    self.lt_would_differ.fetch_add(1, Ordering::Relaxed);
                }
            }
            LeastTime::On => {
                if group.len() > 1 {
                    self.lt_picked.fetch_add(1, Ordering::Relaxed);
                    idx = self.pick_least_time(&group);
                }
            }
        }
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

    /// 分流改投的判据："这一路现在还有没有不在摘除期内的可选节点"。
    ///
    /// 为什么不能直接用 `acquire` 返回 None：`acquire` 的兜底是全零权重也留一台去试探
    /// （否则一旦全摘就再也起不来），所以被动摘除几乎不会让它返回 None。业务分流的语义
    /// 正好相反 —— 整池都在 `fail_timeout` 摘除期内，对这一路来说就是"没人可服务"，
    /// 必须允许改投。这里先走一遍 `restore_if_expired` 再判，摘除期一到就自动回到
    /// "有人可服务"，不会把某一路永久判死。只给分流用，普通 `proxy_pass` 不受影响。
    pub fn split_has_live_server(&self) -> bool {
        let _sched = self.schedule.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_millis();
        for s in &self.servers {
            s.restore_if_expired(now);
        }
        let live = |backup: bool| {
            (0..self.servers.len())
                .filter(|i| self.servers[*i].backup == backup)
                .filter(|i| self.servers[*i].selectable())
                .any(|i| self.servers[i].effective() > 0)
        };
        // 与 acquire 同两级：主组没人可服务时 backup 组仍然算"有人"
        live(false) || live(true)
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

    /// 抽 `[0, n)` 内的一个下标。splitmix64 的 finalizer，状态只是一个原子加法，
    /// 所以热路径上零分配、零锁。
    fn rnd_below(&self, n: usize) -> usize {
        let mut z = self
            .rng
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) as usize) % n
    }

    /// 自适应打分：**P2C**（抽两个候选，取分低者），不是全体取最小。
    ///
    /// 为什么不 argmin：只按"谁现在最快就全投给谁"会造成 herd —— 大家瞬间涌向那个 momentarily
    /// 最快的后端，把它压成最慢的，然后流量整体甩到下一个，来回振荡。P2C 每请求只看两个候选，
    /// 加上分数里的在途项 `conns/weight`，被压的节点会自己涨分退让，这正是
    /// Google 那套 P2C+EWMA（Vigier）的稳态来源。代价是单次选点可能不是全局最优，
    /// 但整体延迟显著更稳，也不会把任何一个后端饿死。
    fn pick_least_time(&self, candidates: &[usize]) -> usize {
        if candidates.len() < 2 {
            return candidates[0];
        }
        let a = self.rnd_below(candidates.len());
        let mut b = self.rnd_below(candidates.len());
        // 两个候选必须不同，否则等于退化成单次抽样。组内 >= 2 时最多几次就散开。
        let mut spins = 0;
        while b == a {
            b = self.rnd_below(candidates.len());
            spins += 1;
            if spins > 64 {
                b = (a + 1) % candidates.len();
                break;
            }
        }
        let (ia, ib) = (candidates[a], candidates[b]);
        let (sa, sb) = (self.score(ia), self.score(ib));
        // 选中了一个"当前不知道多快"的节点而另一个知道：这是一次探索，单独计数，
        // 用来证明新后端/变快的后端确实会被打到流量（而不是被有历史的节点永久压住）。
        let unknown = |i: usize| self.known_ewma(i).is_none();
        if sa <= sb {
            if unknown(ia) && !unknown(ib) {
                self.lt_cold_pick.fetch_add(1, Ordering::Relaxed);
            }
            ia
        } else {
            if unknown(ib) && !unknown(ia) {
                self.lt_cold_pick.fetch_add(1, Ordering::Relaxed);
            }
            ib
        }
    }

    /// 分数 = (**在途 + 1**) × 观测时延，即"这个请求大概还要多久才能被这个后端做完"的估计。
    /// 为什么是 `+1` 而不是裸 `在途 × 时延`：空闲池里在途是 0，裸乘积会把所有节点都算成 0 分并列，
    /// 于是"谁反应快选谁"在低并发下完全不生效——而那正是这条规则最该起作用的时候。
    /// **不知道时延的节点返回负分**（从没样本、或样本已过期，见 [`Self::known_ewma`]），
    /// 于是永远排在接受过流量的节点前面，直到它拿到自己的新样本 —— 冷启动与"变快的后端重新证明自己"
    /// 都靠这一条规则完成，不需要额外的试跑机制。
    /// 两个都不知道时按在途少者优先（分数是 -1/(inflight+1)，越闲越负）。
    fn score(&self, i: usize) -> f64 {
        let s = &self.servers[i];
        let inflight = s.conns.load(Ordering::Relaxed) as f64 / s.weight.max(1) as f64;
        match self.known_ewma(i) {
            None => -1.0 / (inflight + 1.0),
            Some(e) => (inflight + 1.0) * e.max(MIN_LATENCY_SECONDS),
        }
    }

    /// 这个节点**当前可用**的时延估计（秒）。`None` = "不知道"：从来没有样本，
    /// 或者最后一个样本距今已超过 `LT_EXPIRE_MULT × least_time_window`。
    ///
    /// 过期这一条不是保守，是这套打分法能成立的前提：观测只发生在被选中之后，
    /// 一个被旧的高估计挤出去的节点若不重新探索，就再也没有机会说明自己已经变快了。
    fn known_ewma(&self, i: usize) -> Option<f64> {
        let s = &self.servers[i];
        let bits = s.ewma_bits.load(Ordering::Acquire);
        if bits == 0 {
            return None;
        }
        if self.ewma_age_seconds(s) > self.lt_window * LT_EXPIRE_MULT {
            return None;
        }
        Some(f64::from_bits(bits) / 1e9)
    }

    fn ewma_age_seconds(&self, s: &UpstreamServer) -> f64 {
        let last = s.ewma_last_ms.load(Ordering::Acquire);
        now_millis().saturating_sub(last) as f64 / 1000.0
    }

    /// 代理层在**收到响应头**时回填一次观测时延（nginx `least_time header` 的同款口径）。
    ///
    /// 三件事决定了它不会被脏数据带偏：
    /// * `off` 档直接返回 —— 默认关掉时一个原子量都不写，路径与没有这段代码时一致。
    /// * 只有成功拿到响应头的请求才调用它；连接失败/读超时**不入账**（那种"耗时"是超时阈值，
    ///   不是后端的真实快慢），它们的降权由既有的 `note_failure`/`fail_timeout` 负责。
    /// * 样本先钳到 [`MAX_SAMPLE_SECONDS`]，再按**时间**衰减：`α = 1 - e^(-Δt/τ)`，τ = `least_time_window`。
    ///   于是收敛时间只跟墙上时钟有关（约一个 τ 就淡掉 63%），跟 QPS 无关：高 QPS 下每样本只推进
    ///   一小步（等效窗口内平均，不会因最近一个抖动就整体甩流量），低 QPS 下 Δt 本身就大，追得上变化。
    ///   nginx 那一系（Plus 的 `least_time`）按**响应数**平滑：系数固定、与样本何时到达无关，于是
    ///   记忆时长跟着 QPS 变 —— 1k QPS 下等于只记最近几个响应（全是噪声），0.1 QPS 下等于把几十秒
    ///   前的观测当现状。这里刻意换成按**时间**衰减，并把窗口做成可配的（见 `known_ewma` 的过期）。
    ///   （对比只到**性质**为止：`least_time` 不在开源 nginx 里，本仓库也没有它的源码可以核实，
    ///   所以不引用它的具体系数。）
    pub fn note_latency(&self, idx: usize, seconds: f64) {
        if matches!(self.least_time, LeastTime::Off) {
            return;
        }
        let Some(s) = self.servers.get(idx) else {
            return;
        };
        let sample = seconds.clamp(0.0, MAX_SAMPLE_SECONDS) * 1e9;
        self.lt_sampled.fetch_add(1, Ordering::Relaxed);
        let mut cur = s.ewma_bits.load(Ordering::Acquire);
        loop {
            let now = now_millis();
            let last = s.ewma_last_ms.load(Ordering::Acquire);
            let dt = now.saturating_sub(last).min(3_600_000) as f64 / 1000.0;
            let tau = self.lt_window.max(0.001);
            // 从来没有样本，或旧样本已经过期（见 LT_EXPIRE_MULT）：直接采用新观测，不带历史。
            let alpha = if cur == 0 || dt > tau * LT_EXPIRE_MULT {
                1.0
            } else {
                1.0 - (-dt / tau).exp()
            };
            let old = if cur == 0 { 0.0 } else { f64::from_bits(cur) };
            let next = old + (sample - old) * alpha;
            let next_bits = next.max(1.0).to_bits();
            match s.ewma_bits.compare_exchange_weak(
                cur,
                next_bits,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                // `ewma_last_ms` 与 `ewma_bits` 是两次独立写：并发更新里最坏是把衰减算早/晚
                // 一个样本的时间，不会让某个节点被永久误判（CAS 重试本身以最新 bits 为准）。
                Ok(_) => {
                    s.ewma_last_ms.store(now, Ordering::Release);
                    return;
                }
                Err(seen) => cur = seen,
            }
        }
    }

    /// 自适应选点的账目：`(入样, 由分数选点, observe 档本会改判, 冷启动探索)`。
    pub fn least_time_counters(&self) -> (u64, u64, u64, u64) {
        (
            self.lt_sampled.load(Ordering::Relaxed),
            self.lt_picked.load(Ordering::Relaxed),
            self.lt_would_differ.load(Ordering::Relaxed),
            self.lt_cold_pick.load(Ordering::Relaxed),
        )
    }

    /// `-t` 与启动/重载日志用的一行描述；关闭时返回 None（不打扰）。
    pub fn least_time_desc(&self) -> Option<String> {
        match self.least_time {
            LeastTime::Off => None,
            m => Some(format!(
                "upstream '{}'：least_time {}，{} 个节点，EWMA 窗口 {:.1}s（超过 {:.0}倍窗口没有样本就重新探测）",
                self.name,
                match m {
                    LeastTime::Observe => "observe（只测量，选点不变）",
                    LeastTime::On => "on（按 P2C+EWMA 选点）",
                    LeastTime::Off => unreachable!(),
                },
                self.servers.len(),
                self.lt_window,
                LT_EXPIRE_MULT
            )),
        }
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

    /// 收到响应头时回填观测时延（自适应选点唯一接受的样本来源）
    pub fn note_latency(&self, seconds: f64) {
        self.upstream.note_latency(self.idx, seconds);
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
    /// 配置能过、但运营者该知道"这里没有可比对象"一类事实。与 limits/learning 的 warnings 同一套路：
    /// `-t` 直接打印（日志器是异步队列，-t 不等排空），启动路径再 log_warn 一次落 error log。
    pub warnings: Vec<String>,
}

impl UpstreamPool {
    pub fn parse_all(config: &onrouter_config::Config) -> Result<Self, AppError> {
        let mut map = HashMap::new();
        let mut warnings = Vec::new();
        for d in config.root.block.iter().filter(|d| d.name == "upstream") {
            let up = Self::parse_upstream(d)?;
            if !matches!(up.least_time, LeastTime::Off)
                && up
                    .servers
                    .iter()
                    .filter(|s| !s.backup && !s.manually_down)
                    .count()
                    < 2
            {
                warnings.push(format!(
                    "upstream '{}': 主组只有一个可选节点，least_time={} 无从比较，不会改变任何行为",
                    up.name,
                    least_time_name(up.least_time)
                ));
            }
            map.insert(up.name.clone(), Arc::new(up));
        }
        Ok(UpstreamPool { map, warnings })
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
        let mut least_time = LeastTime::Off;
        let mut lt_window = 5.0f64;
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
                "least_time" => {
                    let v = child.arg(0).ok_or_else(|| {
                        AppError::Other(format!(
                            "upstream {name}: least_time 需要 off|observe|on 之一"
                        ))
                    })?;
                    least_time = match v.trim().to_ascii_lowercase().as_str() {
                        "off" => LeastTime::Off,
                        "observe" => LeastTime::Observe,
                        "on" => LeastTime::On,
                        // 写成 detect 是把 front_proxy_mode 的词表串档了：明确指出来，
                        // 而不是给一句"不认识"让人去猜哪个功能说错了。
                        "detect" => {
                            return Err(AppError::Other(format!(
                                "upstream {name}: least_time 的中间档叫 observe（detect 是 front_proxy_mode 的词）"
                            )))
                        }
                        _ => {
                            return Err(AppError::Other(format!(
                                "upstream {name}: least_time {v} 不认识（可用 off|observe|on）"
                            )))
                        }
                    };
                }
                "least_time_window" => {
                    let v = child.arg(0).ok_or_else(|| {
                        AppError::Other(format!(
                            "upstream {name}: least_time_window 需要一个时长参数"
                        ))
                    })?;
                    let secs = parse_seconds(v)
                        .filter(|x| *x > 0.0 && *x <= 3600.0)
                        .ok_or_else(|| {
                            AppError::Other(format!(
                                "upstream {name}: least_time_window {v} 非法（需在 0..3600s 之间）"
                            ))
                        })?;
                    lt_window = secs;
                }
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
        if matches!(lb, LoadBalance::IpHash) && !matches!(least_time, LeastTime::Off) {
            // 与 front_proxy 的"声明了却无效即报错"同一条规矩：ip_hash 的选点由客户端 IP 决定，
            // 自适应分数拿不到否决权，写在这里只会让运营者以为流量会跟着时延走。
            return Err(AppError::Other(format!(
                "upstream {name}: ip_hash 已经决定了选点，least_time={} 不会参与，请二选一",
                least_time_name(least_time)
            )));
        }
        let mut seed = now_millis() << 1;
        for b in name.as_bytes() {
            seed = seed.wrapping_mul(131) ^ *b as u64;
        }
        Ok(Upstream {
            name,
            servers,
            lb,
            health_check,
            keepalive,
            least_time,
            lt_window,
            rng: AtomicU64::new(seed),
            lt_sampled: AtomicU64::new(0),
            lt_picked: AtomicU64::new(0),
            lt_would_differ: AtomicU64::new(0),
            lt_cold_pick: AtomicU64::new(0),
            schedule: Mutex::new(()),
        })
    }
}

fn least_time_name(m: LeastTime) -> &'static str {
    match m {
        LeastTime::Off => "off",
        LeastTime::Observe => "observe",
        LeastTime::On => "on",
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
    fn split_sees_a_removed_pool_as_empty_while_acquire_still_probes() {
        // 单节点池被动摘除后：acquire 仍会给一台零权重节点去试探（不能让池永远起不来），
        // 但分流的判据必须是"这一路没人可服务"—— 否则 proxy_split_failover 永远不会生效。
        let up = upstream("server a; ");
        assert!(up.split_has_live_server(), "新池默认有人可服务");
        let g = up.acquire("10.0.0.1", &[]).expect("应有可用节点");
        g.note_failure(); // max_fails 默认 1：一次失败就进摘除期
        assert!(
            up.acquire("10.0.0.1", &[]).is_some(),
            "兜底：全零权重也要留一台试探，否则池永远回不来"
        );
        assert!(
            !up.split_has_live_server(),
            "分流判据：整池都在摘除期内 = 这一路没人可服务"
        );
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
            "least_time detect; server a; server b; ",
            "least_time fastest; server a; server b; ",
            "least_time on; ip_hash; server a; server b; ",
            "least_time observe; ip_hash; server a; server b; ",
            "least_time_window 0s; least_time on; server a; server b; ",
            "least_time_window 2h; least_time on; server a; server b; ",
            "least_time_window abc; least_time on; server a; server b; ",
            "least_time; server a; server b; ",
            "least_time_window; least_time on; server a; server b; ",
        ] {
            assert!(
                pool(conf).is_err(),
                "应当拒绝这份配置: {conf}"
            );
        }
        assert!(pool("server a; health_check; ").is_ok(), "health_check 允许无参");
        // least_time 与 least_conn/rr 都能搭；单节点池只告警（没有可比的对象，不是错误）
        assert!(pool("least_time on; least_conn; server a; server b; ").is_ok());
        assert!(pool("least_time on; server a; ").is_ok(), "单节点池应告警而非报错");
    }

    // ---- least_time：自适应上游选择 ----

    #[test]
    fn off_tier_touches_nothing() {
        // 默认档：不写 EWMA、不写计数器，选点轨迹与这段代码不存在时一致
        let up = upstream("server a; server b; ");
        up.note_latency(0, 0.012);
        assert_eq!(up.servers[0].ewma_seconds(), 0.0, "off 档不该记住任何时延");
        assert_eq!(up.least_time_counters(), (0, 0, 0, 0));
        let seq: Vec<String> = (0..6).map(|_| pick_release(&up)).collect();
        assert_eq!(seq, vec!["a", "b", "a", "b", "a", "b"], "off 档仍是纯 SWRR: {seq:?}");
        assert!(up.least_time_desc().is_none(), "off 档不该出现在 -t 输出里");
    }

    #[test]
    fn unmeasured_node_is_explored_then_latency_decides() {
        let up = upstream("least_time on; server a; server b; ");
        // a 有历史而且很快，b 一个样本都没有：冷启动必须由 b 拿到流量
        up.note_latency(0, 0.001);
        for _ in 0..20 {
            assert_eq!(pick_release(&up), "b", "没有样本的节点必须先被探测");
        }
        assert!(up.least_time_counters().3 > 0, "冷启动探索要单独计数");
        // b 有了自己的（更慢的）样本之后，快的一方才接管
        up.note_latency(1, 0.050);
        for _ in 0..20 {
            assert_eq!(pick_release(&up), "a", "两个都有样本时该选快的");
        }
    }

    #[test]
    fn stale_estimate_does_not_starve_a_node() {
        // 观测只在"被选中"之后发生：如果旧估计永不过期，一个曾经慢、后来变快的后端
        // 会因为拿不到流量而永远无法澄清自己。过期 = 重新当作"不知道"，纳入探索。
        let up = upstream("least_time on; least_time_window 0.001s; server a; server b; ");
        up.note_latency(0, 0.002);
        up.note_latency(1, 0.001);
        assert_eq!(pick_release(&up), "b", "两个都有样本时按快慢选");
        std::thread::sleep(std::time::Duration::from_millis(8));
        // 只给 b 续上新样本，a 的记忆就此越过有效期
        up.note_latency(1, 0.001);
        assert_eq!(up.known_ewma(0), None, "超过 4×窗口的样本应判为不知道");
        assert!(up.known_ewma(1).is_some());
        assert_eq!(pick_release(&up), "a", "过期的旧估计不该把 a 永久压在后面");
        assert!(up.least_time_counters().3 > 0, "重新探测要计入 cold");
    }

    #[test]
    fn busy_fast_node_yields_to_idle_slow_node() {
        // P2C 不自家 herd 的关键：快但已被压满的节点要让给慢而空闲的节点
        let up = upstream("least_time on; server a; server b; ");
        up.note_latency(0, 0.001);
        up.note_latency(1, 0.010);
        // 先证明空闲时确实选快的
        assert_eq!(pick_release(&up), "a");
        // 用 tried 把流量钉在 a 上，占住 12 条在途不放
        let held: Vec<UpstreamGuard> = (0..12)
            .map(|_| {
                let tried: Vec<usize> = (0..up.servers.len()).filter(|i| *i != 0).collect();
                up.acquire("10.0.0.1", &tried).expect("a 应仍可选")
            })
            .collect();
        assert_eq!(up.servers[0].conns.load(Ordering::Relaxed), 12);
        for _ in 0..10 {
            assert_eq!(pick_release(&up), "b", "在途把快节点压成排队时该让路");
        }
        drop(held);
        assert_eq!(pick_release(&up), "a", "在途清空后快节点重新赢回");
    }

    #[test]
    fn observe_tier_never_changes_selection() {
        // 证据期的硬保证：同一份配置，observe 的选点轨迹必须与 off 逐次一致
        let off = upstream("server a weight=5; server b weight=1; server c weight=1; ");
        let obs = upstream(
            "least_time observe; server a weight=5; server b weight=1; server c weight=1; ",
        );
        // 故意造出一份"按分数选会想改判"的历史
        obs.note_latency(1, 0.001);
        obs.note_latency(2, 0.002);
        let a: Vec<String> = (0..21).map(|_| pick_release(&off)).collect();
        let b: Vec<String> = (0..21).map(|_| pick_release(&obs)).collect();
        assert_eq!(a, b, "observe 档的选点必须与 off 完全一致: off={a:?} obs={b:?}");
        let (sampled, picked, would_differ, _cold) = obs.least_time_counters();
        assert_eq!(sampled, 2, "observe 档照常入样");
        assert_eq!(picked, 0, "observe 档不能由分数选点");
        assert!(would_differ > 0, "本会改判的次数就是证据期的产出");
        assert_eq!(off.least_time_counters(), (0, 0, 0, 0), "off 档一个计数都不写");
    }

    #[test]
    fn latency_sample_is_clamped_and_keeps_the_no_sample_sentinel() {
        let up = upstream("least_time on; server a; server b; ");
        up.note_latency(0, 3600.0);
        assert!(
            (up.servers[0].ewma_seconds() - MAX_SAMPLE_SECONDS).abs() < 1e-9,
            "荒谬的长样本应被钳到上限，实际 {:?}",
            up.servers[0].ewma_seconds()
        );
        up.note_latency(1, 0.0);
        assert!(up.servers[1].ewma_seconds() > 0.0, "0 秒样本不能撞成\"没有样本\"");
    }

    #[test]
    fn failures_do_not_write_latency() {
        // 失败/超时的"耗时"是阈值不是后端的快慢：只走 note_failure/fail_timeout 降权
        let up = upstream("least_time on; server a max_fails=1 fail_timeout=60s; server b; ");
        let tried: Vec<usize> = (0..up.servers.len()).filter(|i| *i != 0).collect();
        let g = up.acquire("10.0.0.1", &tried).expect("a 应仍可选");
        g.note_failure();
        drop(g);
        assert_eq!(up.servers[0].ewma_seconds(), 0.0, "失败不该留下时延样本");
        assert_eq!(up.least_time_counters().0, 0, "失败不该计入 sampled");
        assert_eq!(up.servers[0].failure_count(), 1);
    }

    #[test]
    fn adaptive_tier_and_window_are_described() {
        let up = upstream("least_time on; least_time_window 30s; server a; server b; ");
        assert_eq!(up.lt_window, 30.0);
        let d = up.least_time_desc().expect("on 档应有描述");
        assert!(d.contains("on（按 P2C+EWMA 选点）"), "描述应说清档位: {d}");
        assert!(d.contains("30.0s"), "描述应带上窗口: {d}");
        let o = upstream("least_time observe; server a; server b; ");
        assert!(o.least_time_desc().unwrap().contains("只测量，选点不变"));
        // 单节点池：告警进 warnings 列表（-t 直接打印，启动再落一次 error log），不是错误
        let single = pool("least_time on; server a; ").unwrap();
        assert!(
            single.warnings.iter().any(|w| w.contains("只有一个可选节点")),
            "单节点池应有告警: {:?}",
            single.warnings
        );
        assert!(
            pool("least_time on; server a; server b; ").unwrap().warnings.is_empty(),
            "有可比对象时不该出声"
        );
    }
}
