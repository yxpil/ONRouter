//! 请求速率与并发限制（对标 nginx `limit_req` / `limit_conn`）。
//!
//! ```text
//! limit_req_zone  $remote_addr  zone=allr:10m  rate=50r/s  burst=100;
//! limit_conn_zone $remote_addr  zone=allc:10m;
//! limit_req_status  429;
//! limit_conn_status 503;
//!
//! server {
//!     location /api/ { limit_req zone=allr burst=200; }
//!     location /     { limit_conn allc 64; }
//! }
//! ```
//!
//! 实现要点：
//! - `limit_req` 默认是令牌桶语义的**拒绝式**实现（等价 nginx `nodelay`：不做延迟排队，超限直接回状态码）。
//! - 写了 `limit_req_queue <zone>;` 之后，超限的请求改为"最多排队 depth 个、每个最多等 max_delay"，
//!   排不下或等不起仍然按原状态码拒绝——队列是**有界**的，不存在无界缓冲。
//! - 再写 `limit_req_learning <zone>;`（且 `learning on;`）时，排队深度与等待预算按 key 学出来的
//!   突发形状自动调，只在你给的 `[min, max]` 区间内动：刚结束一股正常突发的 key 多排几个，
//!   长度越过洪水线（`depth × 4`）的持续突发一律退回下界——奖励偶发突发、惩罚持续洪水。
//!   学到的只是"这个 key 上次一口气来了多少个"这份近似记忆，一张定长表，占进程级学习预算。
//! - 判定发生在 PREACCESS 位置（access 鉴权之前），与 nginx 阶段顺序一致。
//! - 状态表按 key 哈希分 32 片，各片独立锁；每片容量上限 + 插入序淘汰，
//!   防止攻击者用海量 key 把限流表本身变成内存 DoS（自研限流最容易漏的一点）。
//! - 时间基准用单调毫秒，NTP 校时回拨不会导致额度暴涨。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use onrouter_config::{Config, Directive};

const SHARDS: usize = 32;
/// 单片最多跟踪多少 key
const PER_SHARD_CAPACITY: usize = 16384;

fn base_ms() -> u64 {
    static BASE: OnceLock<u64> = OnceLock::new();
    *BASE.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}

/// 进程启动以来的单调毫秒
fn now_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now.saturating_sub(base_ms()) as i64
}

fn shard_of(key: &str) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

#[derive(Debug)]
struct ReqState {
    /// 可用令牌（1.0 = 允许一个请求）。排队时允许记成**负数**：那是已经预留出去的令牌，
    /// 补回来之前谁都别想插队——预留是"排上队就一定等得到"的唯一保证。
    tokens: f64,
    updated_ms: i64,
    /// 该 key 当前占用的队列名额数。
    /// 排队计数必须**精确**（它是有界队列的安全边界），所以放在限流原表里，
    /// 而不是放进那份"够用就行"的突发表；代价只是每 key 4 字节。
    queued: u32,
}

#[derive(Debug, Default)]
struct ReqShard {
    map: HashMap<String, ReqState>,
    order: VecDeque<String>,
}

// ==================== 队列：有界排队 + 突发形状学习 ====================

/// `limit_req_queue <zone> [depth=N] [depth_min=N] [max_delay=T];`
///
/// `depth` 是运维给的**天花板**（每 key 最多同时排队多少个请求），不是目标值：
/// 开学习时实际深度会在 `[depth_min, depth]` 里按这个 key 的真实突发长度调。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueuePolicy {
    pub depth_min: u32,
    pub depth_max: u32,
    pub max_delay_ms: u64,
}

impl Default for QueuePolicy {
    fn default() -> Self {
        QueuePolicy {
            depth_min: 1,
            depth_max: DEFAULT_QUEUE_DEPTH,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
        }
    }
}

const DEFAULT_QUEUE_DEPTH: u32 = 10;
const DEFAULT_MAX_DELAY_MS: u64 = 5_000;
/// 排队深度硬顶：再多就是拿网关内存换虚假的通过率。
const MAX_QUEUE_DEPTH: u32 = 4096;

/// `admit` 的结果。`Queued` 带着一个 RAII 名额：请求结束（含客户端断开）即归还。
#[derive(Debug)]
pub enum Admit {
    /// 有令牌，立即放行
    Pass,
    /// 已占住一个队列名额**并预留了令牌**：等满 `wait_ms` 就直接放行，不用再抢一次令牌。
    /// 名额必须随请求结束归还（drop），但预留的令牌不退——客户端中途断开只会少服务一个，
    /// 欠账由令牌自然补回，绝不会白送给别人。
    Queued { wait_ms: u64, permit: QueuePermit },
    /// 排队排不下/等不起：`retry_after_secs` 为建议等待时长
    Reject { retry_after_secs: u64 },
}

/// 队列名额的租约。客户端在排队期间断开时 future 被丢弃，名额随之归还——
/// 这是有界队列不会被"幽灵排队"占死的唯一保证。
#[derive(Debug)]
pub struct QueuePermit {
    zone: Arc<ReqZone>,
    key: String,
}

impl Drop for QueuePermit {
    fn drop(&mut self) {
        self.zone.dec_queued(&self.key);
    }
}

/// 一个 key 的突发形状记忆（定长直接映射表的一格）。
#[derive(Debug, Clone, Copy)]
struct BurstSlot {
    /// key 哈希（0 保留为"空槽"）
    tag: u32,
    /// 上次到达时间的单调毫秒低 32 位（约 49 天回绕一次，用 wrapping 差值算间隔）
    last_ms: u32,
    /// 当前这股突发的长度
    run: u16,
    /// 上一个**已完成**突发的长度；0 = 还没学到东西
    held: u16,
}

/// 按 key 记"一口气来了多少个"的定长表。
///
/// 为什么不是 HashMap：队列学习要记得下每个 key 的突发形状，用哈希表就是又开一张
/// 随 key 数量线性增长的表——那正是限流表自己被当成 DoS 向量的老问题。
/// 直接映射 + tag 校验：撞槽只是顶掉别人的记忆，最坏退回深度下界，
/// 绝不影响放行判定（判定只认令牌桶和精确的 `queued` 计数）。
#[derive(Debug)]
pub struct BurstTable {
    slots: Vec<BurstSlot>,
    /// 判定"还在同一股突发里"的最大间隔：超过它就算这股突发结束了
    gap_cap_ms: u32,
    /// 申领时夹取到的请求量：热重载比较"大小有没有变"用（`bytes()` 是按槽取整的实占）
    wanted: usize,
}

impl BurstTable {
    fn new(bytes: usize, gap_cap_ms: u32) -> Self {
        let per = std::mem::size_of::<BurstSlot>();
        let slots = (bytes / per).max(16);
        BurstTable {
            slots: vec![
                BurstSlot {
                    tag: 0,
                    last_ms: 0,
                    run: 0,
                    held: 0,
                };
                slots
            ],
            gap_cap_ms,
            wanted: bytes,
        }
    }

    fn want_bytes(&self) -> usize {
        self.wanted
    }

    fn bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<BurstSlot>()
    }

    /// 观测到一次到达，返回（该 key 学到的突发长度，是否改写了学到的深度）。
    ///
    /// 学到的量刻意取"上一股**已经结束**的突发"的长度：`flood_at` 是这股突发的容忍上限
    /// （运维给的天花板 × 4）。长度越过它就判定为持续洪水、把记忆清零——
    /// 只靠"突发不结束"是罚不到洪水的，因为一股够长的突发本身就会被当成形状记住。
    /// 于是这套规则奖励偶发突发、惩罚持续洪水，且无论学到什么都不会超过 `depth` 天花板。
    fn observe(&mut self, key: &str, now_ms: i64, flood_at: u16) -> (u16, bool) {
        // tag 取非零：哈希出 0 时抬到 1，避免与"空槽"混淆
        let tag = crate::engine::murmur_hash2(key.as_bytes()).max(1);
        let now32 = now_ms.max(0) as u32;
        let n = self.slots.len();
        let s = &mut self.slots[(tag as usize) % n];
        if s.tag != tag {
            *s = BurstSlot {
                tag,
                last_ms: now32,
                run: 1,
                held: 0,
            };
            return (0, false);
        }
        let gap = now32.wrapping_sub(s.last_ms);
        let before = s.held;
        s.last_ms = now32;
        if gap > self.gap_cap_ms {
            // 这股结束了：只有"像正常突发"的长度才值得记；
            // 越过洪水线的长度按洪水处理，结束时也清零——
            // 否则"攻满一分钟再停手"就能把攻击长度换成下一股的深队列。
            s.held = if s.run >= flood_at { 0 } else { s.run };
            s.run = 1;
        } else {
            s.run = s.run.saturating_add(1);
            if s.run >= flood_at {
                // 到现在还没结束，且长度已超过可容忍的突发：按洪水处理，记忆归零
                s.held = 0;
            }
        }
        let adjusted = s.held != before;
        (s.held, adjusted)
    }

    /// 指标快照：（已用槽数，总槽数，当前学到的最大突发长度）。
    fn snapshot(&self) -> (u32, u32, u16) {
        let mut used = 0u32;
        let mut max_held = 0u16;
        for s in &self.slots {
            if s.tag != 0 {
                used += 1;
                max_held = max_held.max(s.held);
            }
        }
        (used, self.slots.len() as u32, max_held)
    }
}

/// 队列判定的内部结论（`Wait` 表示已在本次持锁期间占住一个名额）
#[derive(Debug)]
enum Decision {
    Pass,
    /// 已排队：需等待的毫秒数
    Wait(u64),
    /// 拒绝：(补回一个令牌的时长, 原因)
    Reject(u64, RejectWhy),
}

#[derive(Debug, Clone, Copy)]
enum RejectWhy {
    /// 本区没开队列
    NoQueue,
    /// 队列已满
    Depth,
    /// 排上了也要等过预算：不如立刻回 429，别占着连接干等
    Delay,
}

/// 本请求适用的排队上界（可能来自学习，也可能就是配置天花板）
#[derive(Debug, Clone, Copy)]
struct QueueEff {
    depth: u32,
    delay_ms: u64,
}

#[derive(Debug)]
pub struct ReqZone {
    pub name: String,
    pub rate_per_sec: f64,
    /// zone 级默认 burst
    pub burst: f64,
    /// 限流依据的变量；目前只支持按客户端地址计数
    pub key_var: String,
    shards: Vec<Mutex<ReqShard>>,
    /// `limit_req_queue` 声明的排队策略；None = 本区保持"超限即拒"。
    /// 用 `Mutex<Option<_>>` 是为了热重载能原地改：限流区实例进程内唯一，
    /// 表里的在世状态（令牌、排队数）不能因为改配置而清零。
    policy: Mutex<Option<QueuePolicy>>,
    /// 按 key 学突发形状的定长表；None = 不学（未声明、或预算领不到）
    table: Mutex<Option<BurstTable>>,
    q: QueueCounters,
}

/// 队列运行计数（`/metrics` 逐区渲染）。全部 relaxed：这些是给运维看形状的数字，
/// 不是用来做判定或结算的，判定一律在分片锁内完成。
#[derive(Debug, Default)]
struct QueueCounters {
    /// 拿到过队列名额的请求数。注意口径：本区只知道"排上了"，
    /// 醒来后是否真抢到令牌由调用方判定，所以这里不叫"放行数"。
    queued: AtomicU64,
    /// 因队列已满被拒
    rejected_full: AtomicU64,
    /// 因"等不起"（预计等待超预算）被拒
    rejected_slow: AtomicU64,
    /// 排队累计等待毫秒数（与 queued 相除得平均排队时长）
    wait_ms_total: AtomicU64,
    /// 学到的突发深度被改写的次数（"自动调 queue 深度"发生过的证据）
    depth_adjust: AtomicU64,
    /// 同时排队数的历史峰值
    occupied_max: AtomicU32,
}

impl ReqZone {
    fn new(name: &str, rate_per_sec: f64, burst: f64, key_var: &str) -> Arc<Self> {
        Arc::new(ReqZone {
            name: name.to_string(),
            rate_per_sec,
            burst,
            key_var: key_var.to_string(),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(ReqShard::default()))
                .collect(),
            policy: Mutex::new(None),
            table: Mutex::new(None),
            q: QueueCounters::default(),
        })
    }

    /// 一个令牌的补足时长（毫秒，向上取整，至少 1ms）
    fn token_period_ms(&self) -> u64 {
        (1000.0 / self.rate_per_sec.max(1e-9)).ceil().max(1.0) as u64
    }

    fn policy(&self) -> Option<QueuePolicy> {
        let g = self.policy.lock().unwrap_or_else(|e| e.into_inner());
        match &*g {
            Some(p) => Some(*p),
            None => None,
        }
    }

    /// 突发表实际占用（0 = 本区没在学）。
    fn table_bytes(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|t| t.bytes())
            .unwrap_or(0)
    }

    /// "还在同一股突发里"的判定间隔：取两个补令牌周期，夹到 [20ms, 1s]。
    /// 下界防止高速区把持续洪水当成一股突发，上界防止低速区把相隔几秒的两个请求连成一股。
    fn gap_cap_ms(&self) -> u32 {
        ((2.0 * self.token_period_ms() as f64).ceil() as u32).clamp(20, 1_000)
    }

    /// 一个 key 的突发形状观测；None = 本区没在学（没声明，或预算领不到）
    fn observe_burst(&self, key: &str, flood_at: u16) -> Option<u16> {
        let now = now_ms();
        let mut g = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let t = g.as_mut()?;
        let (held, adjusted) = t.observe(key, now, flood_at);
        if adjusted {
            self.q.depth_adjust.fetch_add(1, Ordering::Relaxed);
        }
        Some(held)
    }

    /// 判定这个 key 此刻适用的排队上界。
    /// 没开学习时恒等于配置天花板；开了学习时取"上一股已结束的突发有多长"，
    /// 并夹在 `[depth_min, depth_max]` 内——运维给的区间是硬边界，学习只在里面动。
    /// 学到的重要客户（VIP）直接用到天花板：突发学习存在的前提是"这个 key 我们不认识"，
    /// 而信誉已经回答了这个问题。注意这只改变"排几个"，不改变速率——排上队的请求
    /// 仍然按同一速率发放令牌，所以给可信客户放宽队列不会多放出一个请求。
    /// 等待预算只认运维给的 `max_delay`：排队时已经预留了令牌，
    /// 排上队就一定等得到，不需要再按"深度 × 周期"猜一遍位置。
    fn effective(&self, p: QueuePolicy, key: &str, vip: Option<&Arc<crate::vip::Vip>>) -> QueueEff {
        let static_eff = || QueueEff {
            depth: p.depth_max,
            delay_ms: p.max_delay_ms,
        };
        // 洪水判定点：天花板 × 4。够不到这个长度的都算正常突发；够到了就不再给记忆
        let flood_at = ((p.depth_max as usize).saturating_mul(4))
            .min(MAX_QUEUE_DEPTH as usize)
            .max(2) as u16;
        let trusted = vip.is_some_and(|v| v.is_vip(key));
        let Some(held) = self.observe_burst(key, flood_at) else {
            return static_eff();
        };
        if trusted {
            return QueueEff {
                depth: p.depth_max,
                delay_ms: p.max_delay_ms,
            };
        }
        // 还没学到东西（首股突发）时用下界：宁可先拒一半，也不给陌生 key 一上来就发深队列
        let depth = if held == 0 {
            p.depth_min.max(1)
        } else {
            (held as u32).clamp(p.depth_min.max(1), p.depth_max)
        };
        QueueEff {
            depth,
            delay_ms: p.max_delay_ms,
        }
    }

    /// 限流判定的唯一入口。`eff = None` 时与旧的 `check()` 逐行等价（超限即拒）。
    fn decide(&self, key: &str, burst_override: Option<f64>, eff: Option<QueueEff>) -> Decision {
        let burst = burst_override.unwrap_or(self.burst).max(0.0);
        let capacity = burst + 1.0;
        let refill_per_ms = self.rate_per_sec / 1000.0;
        let now = now_ms();
        let mut shard = self.shards[shard_of(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (deficit_ms, queued) = match shard.map.get_mut(key) {
            Some(st) => {
                st.tokens =
                    (st.tokens + (now - st.updated_ms).max(0) as f64 * refill_per_ms).min(capacity);
                st.updated_ms = now;
                if st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    (None, st.queued)
                } else {
                    // 保留原来的截断口径：`limit_req_queue` 不写时 Retry-After 一字不变
                    let wait_ms = ((1.0 - st.tokens) / refill_per_ms.max(1e-9)) as u64;
                    (Some(wait_ms), st.queued)
                }
            }
            None => {
                if shard.map.len() >= PER_SHARD_CAPACITY {
                    if let Some(old) = shard.order.pop_front() {
                        shard.map.remove(&old);
                    }
                }
                shard.map.insert(
                    key.to_string(),
                    ReqState {
                        tokens: capacity - 1.0,
                        updated_ms: now,
                        queued: 0,
                    },
                );
                shard.order.push_back(key.to_string());
                (None, 0)
            }
        };
        let Some(deficit) = deficit_ms else {
            return Decision::Pass;
        };
        // 超限：先看排队上界（可能来自学习），排不下或等不起就照原样拒绝
        let Some(eff) = eff else {
            return Decision::Reject(deficit, RejectWhy::NoQueue);
        };
        if queued >= eff.depth {
            return Decision::Reject(deficit, RejectWhy::Depth);
        }
        if deficit > eff.delay_ms {
            return Decision::Reject(deficit, RejectWhy::Delay);
        }
        if let Some(st) = shard.map.get_mut(key) {
            // 排队就把这一格的令牌**预留**掉（令牌数记成欠账）。这样醒来时不需要再抢一次：
            // 晚到的请求只会因此排得更久、或者干脆被拒，绝不会抢走已排队者的令牌。
            // 不预留的写法在真实并发下会把排上队的请求挤成"等完了再吃 429"，
            // 比 nginx 的 delay 模式更差，也让速率变得不可预测。
            st.tokens -= 1.0;
            st.queued += 1;
            self.q.occupied_max.fetch_max(st.queued, Ordering::Relaxed);
        }
        Decision::Wait(deficit)
    }

    /// 默认路径：超限直接拒（等价 nginx `nodelay`）。返回 Some(建议 Retry-After 秒数)。
    pub fn check(&self, key: &str, burst_override: Option<f64>) -> Option<u64> {
        match self.decide(key, burst_override, None) {
            Decision::Pass => None,
            Decision::Reject(deficit, _) => Some(ms_to_secs(deficit)),
            // eff=None 时 decide 不会进这条；真进了也放行，绝不吞请求
            Decision::Wait(_) => None,
        }
    }

    /// 带排队的判定：本区没配 `limit_req_queue` 时结果与 `check()` 完全一致。
    /// `vip` 给出进程级信誉表：判定的**结果**（放行/排队/拒绝）会记进它，
    /// 而它只在两处影响行为——本 key 的排队上界、以及缓存写入的驻留加权。
    /// 一次请求若命中多条 `limit_req`，每个区各记一次：加分与扣分同样成倍，方向不变。
    pub fn admit(
        self: &Arc<Self>,
        key: &str,
        burst_override: Option<f64>,
        vip: Option<&Arc<crate::vip::Vip>>,
    ) -> Admit {
        let admit = self.admit_inner(key, burst_override, vip);
        if let Some(v) = vip {
            let outcome = match &admit {
                Admit::Pass => crate::vip::Outcome::Passed,
                Admit::Queued { .. } => crate::vip::Outcome::Queued,
                Admit::Reject { .. } => crate::vip::Outcome::Rejected,
            };
            v.note(key, outcome, now_ms());
        }
        admit
    }

    fn admit_inner(
        self: &Arc<Self>,
        key: &str,
        burst_override: Option<f64>,
        vip: Option<&Arc<crate::vip::Vip>>,
    ) -> Admit {
        let Some(p) = self.policy() else {
            return match self.check(key, burst_override) {
                None => Admit::Pass,
                Some(secs) => Admit::Reject {
                    retry_after_secs: secs,
                },
            };
        };
        let eff = self.effective(p, key, vip);
        match self.decide(key, burst_override, Some(eff)) {
            Decision::Pass => Admit::Pass,
            Decision::Wait(wait_ms) => {
                self.q.wait_ms_total.fetch_add(wait_ms, Ordering::Relaxed);
                self.q.queued.fetch_add(1, Ordering::Relaxed);
                Admit::Queued {
                    wait_ms,
                    permit: QueuePermit {
                        zone: Arc::clone(self),
                        key: key.to_string(),
                    },
                }
            }
            Decision::Reject(deficit, why) => {
                let c = match why {
                    RejectWhy::NoQueue | RejectWhy::Depth => &self.q.rejected_full,
                    RejectWhy::Delay => &self.q.rejected_slow,
                };
                c.fetch_add(1, Ordering::Relaxed);
                Admit::Reject {
                    retry_after_secs: ms_to_secs(deficit),
                }
            }
        }
    }

    fn dec_queued(&self, key: &str) {
        let mut shard = self.shards[shard_of(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(st) = shard.map.get_mut(key) {
            st.queued = st.queued.saturating_sub(1);
        }
    }

    /// 清理长期闲置 key（后台定时调用，防表膨胀）。
    /// map 与 order 都一次 retain 完成：旧实现逐 key `position + remove`，大表时是 O(n²)。
    /// 还在排队的 key 一律不删：删掉等于把它的令牌重置成满桶，白送额度。
    pub fn purge_idle(&self, idle_ms: i64) -> usize {
        let now = now_ms();
        let mut removed = 0usize;
        for s in &self.shards {
            let mut shard = s.lock().unwrap_or_else(|e| e.into_inner());
            let shard = &mut *shard;
            let (map, order) = (&mut shard.map, &mut shard.order);
            let before = map.len();
            map.retain(|_, st| st.queued > 0 || now - st.updated_ms <= idle_ms);
            removed += before - map.len();
            if map.len() != before {
                order.retain(|k| map.contains_key(k));
            }
        }
        removed
    }

    /// 队列概况（`-t` 摘要与 `/metrics` 用）
    pub fn queue_snapshot(&self) -> QueueSnapshot {
        let occupied = self
            .shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .map
                    .values()
                    .map(|st| st.queued as u64)
                    .sum::<u64>()
            })
            .sum();
        let (table_bytes, slots, slots_total, learned_max) = match self
            .table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(t) => {
                let (used, total, held) = t.snapshot();
                (t.bytes(), used, total, held)
            }
            None => (0, 0, 0, 0),
        };
        QueueSnapshot {
            policy: self.policy(),
            occupied,
            occupied_max: self.q.occupied_max.load(Ordering::Relaxed) as u64,
            queued: self.q.queued.load(Ordering::Relaxed),
            rejected_full: self.q.rejected_full.load(Ordering::Relaxed),
            rejected_slow: self.q.rejected_slow.load(Ordering::Relaxed),
            wait_ms_total: self.q.wait_ms_total.load(Ordering::Relaxed),
            depth_adjust: self.q.depth_adjust.load(Ordering::Relaxed),
            table_bytes,
            table_slots: slots,
            table_slots_total: slots_total,
            learned_max,
        }
    }
}

/// 一区的队列快照（渲染指标与日志用；不含判定路径的任何状态）
#[derive(Debug)]
pub struct QueueSnapshot {
    pub policy: Option<QueuePolicy>,
    /// 此刻全区正在排队的请求数（抓取时逐片求和，不是判定依据）
    pub occupied: u64,
    pub occupied_max: u64,
    pub queued: u64,
    pub rejected_full: u64,
    pub rejected_slow: u64,
    pub wait_ms_total: u64,
    pub depth_adjust: u64,
    pub table_bytes: usize,
    pub table_slots: u32,
    pub table_slots_total: u32,
    pub learned_max: u16,
}

fn ms_to_secs(ms: u64) -> u64 {
    ms.div_ceil(1000).max(1)
}

/// 套用单区的突发表申领/退回。四条路径都必须在**同一把表锁**里完成，
/// 否则并发的 admit 可能读到"旧表已归还账本、新表还没建"的中间态。
fn sync_burst_table(
    zone: &Arc<ReqZone>,
    name: &str,
    want: Option<usize>,
    learning: &crate::learning::Learning,
    notes: &mut Vec<String>,
) {
    let mut g = zone.table.lock().unwrap_or_else(|e| e.into_inner());
    match (g.as_ref(), want) {
        (None, None) => {}
        (Some(_), None) => {
            let held = g.as_ref().map(|t| t.bytes()).unwrap_or(0);
            learning.release_bytes(held);
            *g = None;
            notes.push(format!(
                "队列学习：区 '{name}' 已停止学习，归还 {held} B，排队上界退回配置值"
            ));
        }
        (Some(cur), Some(w)) => {
            let clamped = learning.clamp_queue_bytes(w);
            if cur.want_bytes() == clamped {
                return; // 尺寸没变：保住已学到的形状，别因为重载把记忆抹平
            }
            let held = cur.bytes();
            learning.release_bytes(held);
            *g = None;
            notes.push(format!(
                "队列学习：区 '{name}' 的突发表从 {held} B 改为 {clamped} B，已学到的形状随之清空"
            ));
        }
        (None, Some(_)) => {}
    }
    if g.is_some() {
        return; // 尺寸未变，或上面已退回
    }
    let Some(clamped) = want.map(|w| learning.clamp_queue_bytes(w)) else {
        return;
    };
    let Some(granted) = learning.claim_bytes(clamped, crate::learning::MAX_QUEUE_BYTES) else {
        notes.push(format!(
            "队列学习：区 '{name}' 需要 {clamped} B，预算不足（累计拒绝 {} 次申领），该区退回配置固定上界",
            learning.denied()
        ));
        return;
    };
    let t = BurstTable::new(granted, zone.gap_cap_ms());
    // 表按槽取整，实占可能小于申领数：把差额还回账本，别让预算只涨不跌
    let diff = granted.saturating_sub(t.bytes());
    if diff > 0 {
        learning.release_bytes(diff);
    }
    *g = Some(t);
}

/// `learning_memory_budget` 被调小时，队列侧也要如实收敛：按表从大到小放，
/// 放到守住上限为止。缓存草图在 `ProxyCache::apply_learning` 里先让位，
/// 所以这里的收敛只处理"放掉全部草图仍不够"的剩余部分。
fn trim_tables_to_budget(
    limits: &Limits,
    learning: &crate::learning::Learning,
    notes: &mut Vec<String>,
) {
    let total = learning.budget.total();
    if learning.used() <= total {
        return;
    }
    let mut owned: Vec<(usize, String)> = limits
        .req_zones
        .iter()
        .filter(|(_, z)| z.table_bytes() > 0)
        .map(|(n, z)| (z.table_bytes(), n.clone()))
        .collect();
    owned.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (bytes, name) in owned {
        if learning.used() <= total {
            break;
        }
        let Some(zone) = limits.req_zones.get(&name) else {
            continue;
        };
        let mut g = zone.table.lock().unwrap_or_else(|e| e.into_inner());
        let held = g.as_ref().map(|t| t.bytes()).unwrap_or(0);
        *g = None;
        learning.release_bytes(held);
        notes.push(format!(
            "队列学习：learning_memory_budget 已降到 {total} B，放掉区 '{name}' 的 {bytes} B 突发表以守住上限，该区退回配置固定上界"
        ));
    }
}

/// 解析顶层 `limit_req_queue <zone> [depth=N] [depth_min=N] [max_delay=T];`
fn parse_queue_policies(config: &Config, notes: &mut Vec<String>) -> HashMap<String, QueuePolicy> {
    let mut out = HashMap::new();
    for d in config
        .root
        .block
        .iter()
        .filter(|d| d.name == "limit_req_queue")
    {
        let Some(zone) = d.arg(0).filter(|s| !s.is_empty()) else {
            notes.push(format!(
                "limit_req_queue（第 {} 行）缺少区名，已忽略",
                d.line
            ));
            continue;
        };
        let mut p = QueuePolicy::default();
        for a in &d.args {
            if let Some(v) = a.strip_prefix("depth=") {
                match v.parse::<u32>() {
                    Ok(n) => p.depth_max = n,
                    Err(_) => notes.push(format!(
                        "limit_req_queue {zone}（第 {} 行）depth='{v}' 不是整数，改用默认 {}",
                        d.line, DEFAULT_QUEUE_DEPTH
                    )),
                }
            } else if let Some(v) = a.strip_prefix("depth_min=") {
                match v.parse::<u32>() {
                    Ok(n) => p.depth_min = n,
                    Err(_) => notes.push(format!(
                        "limit_req_queue {zone}（第 {} 行）depth_min='{v}' 不是整数，改用默认 1",
                        d.line
                    )),
                }
            } else if let Some(v) = a.strip_prefix("max_delay=") {
                match crate::settings::parse_duration(v) {
                    Some(t) => p.max_delay_ms = t.as_millis() as u64,
                    None => notes.push(format!(
                        "limit_req_queue {zone}（第 {} 行）max_delay='{v}' 时间非法（需形如 500ms / 2s），改用默认 {}ms",
                        d.line, DEFAULT_MAX_DELAY_MS
                    )),
                }
            } else if !a.starts_with(zone) {
                notes.push(format!(
                    "limit_req_queue {zone}（第 {} 行）不认识的参数 '{a}'（可用：depth / depth_min / max_delay），已忽略",
                    d.line
                ));
            }
        }
        if p.depth_max > MAX_QUEUE_DEPTH {
            notes.push(format!(
                "limit_req_queue {zone}（第 {} 行）depth={} 超过硬顶 {MAX_QUEUE_DEPTH}，已夹到硬顶",
                d.line, p.depth_max
            ));
            p.depth_max = MAX_QUEUE_DEPTH;
        }
        if p.depth_min > p.depth_max {
            notes.push(format!(
                "limit_req_queue {zone}（第 {} 行）depth_min={} 大于 depth={}，下界已按上界处理",
                d.line, p.depth_min, p.depth_max
            ));
            p.depth_min = p.depth_max;
        }
        if p.depth_max == 0 {
            notes.push(format!(
                "limit_req_queue {zone}（第 {} 行）depth=0 等于不排队，本区保持超限即拒",
                d.line
            ));
        }
        out.insert(zone.to_string(), p);
    }
    out
}

#[derive(Debug, Default)]
struct ConnShard {
    map: HashMap<String, u32>,
}

pub struct ConnZone {
    pub name: String,
    pub key_var: String,
    shards: Vec<Mutex<ConnShard>>,
}

impl ConnZone {
    fn new(name: &str, key_var: &str) -> Arc<Self> {
        Arc::new(ConnZone {
            name: name.to_string(),
            key_var: key_var.to_string(),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(ConnShard::default()))
                .collect(),
        })
    }

    /// 占用一个并发额度；超限返回 None。成功返回 RAII，drop 时释放。
    pub fn try_acquire(self: &Arc<Self>, key: &str, number: u32) -> Option<ConnGuard> {
        let mut shard = self.shards[shard_of(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let n = shard.map.get(key).copied().unwrap_or(0);
        if n >= number {
            return None;
        }
        if !shard.map.contains_key(key) && shard.map.len() >= PER_SHARD_CAPACITY {
            // 状态表满：优先淘汰已归零的 key；无可淘汰项时按 nginx 的 shm 耗尽语义拒绝新连接
            match shard
                .map
                .iter()
                .find(|(_, v)| **v == 0)
                .map(|(k, _)| k.clone())
            {
                Some(old) => {
                    shard.map.remove(&old);
                }
                None => return None,
            }
        }
        shard.map.insert(key.to_string(), n + 1);
        Some(ConnGuard {
            zone: Arc::clone(self),
            key: key.to_string(),
        })
    }

    fn release(&self, key: &str) {
        let mut shard = self.shards[shard_of(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match shard.map.get_mut(key) {
            Some(n) if *n > 1 => *n -= 1,
            Some(_) => {
                shard.map.remove(key);
            }
            None => {}
        }
    }

    /// 清理没有任何在途连接的 key（只统计活跃数，空闲 key 可安全移除）
    fn purge_idle(&self, _idle_ms: i64) -> usize {
        let mut removed = 0usize;
        for s in &self.shards {
            let mut shard = s.lock().unwrap_or_else(|e| e.into_inner());
            let before = shard.map.len();
            shard.map.retain(|_, n| *n > 0);
            removed += before - shard.map.len();
        }
        removed
    }
}

pub struct ConnGuard {
    zone: Arc<ConnZone>,
    key: String,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.zone.release(&self.key);
    }
}

/// location 级 `limit_req zone=name [burst=n] [nodelay]`
#[derive(Debug, Clone)]
pub struct ReqRule {
    pub zone: String,
    pub burst: Option<f64>,
}

/// `limit_conn name number;`
#[derive(Debug, Clone)]
pub struct ConnRule {
    pub zone: String,
    pub number: u32,
}

#[derive(Default)]
pub struct Limits {
    req_zones: HashMap<String, Arc<ReqZone>>,
    conn_zones: HashMap<String, Arc<ConnZone>>,
    pub req_status: u16,
    pub conn_status: u16,
    pub warnings: Vec<String>,
    /// 进程级信誉表（`vip_learning`）：所有区共用同一张，因为信誉看的是客户端而不是区。
    /// 用 Mutex 是为了热重载原地换：判定路径只克隆一个 Arc，不进请求路径的锁竞争。
    vip: Mutex<Option<Arc<crate::vip::Vip>>>,
}

/// key 完全由客户端地址构成：请求路径上不必插值（见 server::limit_key）
pub fn addr_var(v: &str) -> bool {
    matches!(v, "$remote_addr" | "$binary_remote_addr")
}

/// 限流判定时刻（preaccess/ACCESS，读请求头之后、回源之前）就有值的固定变量。
/// 这是 nginx 变量全集里"能给请求归组"的那一部分：地址、连接与监听、请求行、Host/SNI。
const REQUEST_PHASE_VARS: &[&str] = &[
    "remote_addr",
    "binary_remote_addr",
    "realip_remote_addr",
    "remote_port",
    "server_addr",
    "server_port",
    "scheme",
    "https",
    "request_method",
    "method",
    "request_uri",
    "uri",
    "args",
    "query_string",
    "is_args",
    "host",
    "ssl_server_name",
    "content_type",
    "content_length",
    "request_length",
    "hostname",
    "proxy_add_x_forwarded_for",
    "front_proxy",
    "front_proxy_country",
    "front_proxy_host",
    "front_proxy_verified",
];

/// 这些前缀派生的变量在判定时刻必然取不到值：它们描述的是**响应**或**后端**。
/// 写进 key 的话每个请求都展开成空串，整区流量并成一个桶——比"按 IP 限"更安静的失效。
const RESPONSE_PHASE_PREFIXES: &[&str] = &[
    "sent_http_",
    "upstream_http_",
    "upstream_cookie_",
    "upstream_",
];

/// 逐段检查一条 zone key 模板，第一处取不到值的变量给出点名与原因。
/// nginx 的 key 是 complex value，所以 `$cookie_sid$remote_addr` 这种复合写法要逐段判；
/// 段名取 `$` 之后的 `[A-Za-z0-9_]` 前缀，与变量插值的词法一致（`$1` 是捕获组字面量，跳过）。
///
/// 支持的维度：客户端地址、请求头（`$http_*`）、Cookie（`$cookie_*`）、URL 参数（`$arg_*`）、
/// 以及 `REQUEST_PHASE_VARS` 里的请求期变量。
/// 明确否决的：响应期/后端变量、`$request_body`（判定时刻体还没读完，恒为空）、
/// 本实现没有的变量（`$server_name`、`$geoip_*`…），以及 `set` 出来的请求级变量——
/// nginx 允许它当 key，但我们的限流跑在 REWRITE 之前，那时 set 还没执行；
/// 与其让它静默变成"所有请求共用一个空桶"，不如在 `-t` 就拒绝。
pub fn check_key_var(var: &str) -> Result<(), String> {
    let segs = key_segs(var);
    for name in &segs {
        let dollar = format!("${name}");
        if name == "request_body" {
            return Err(format!(
                "'{dollar}' 在限流判定时刻请求体还没读完，当 key 会把整区流量并成一个空桶"
            ));
        }
        if REQUEST_PHASE_VARS.contains(&name.as_str()) {
            continue;
        }
        if RESPONSE_PHASE_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return Err(format!(
                "'{dollar}' 是响应期/后端变量，限流判定（ACCESS 之前）取不到值，当 key 会把整区流量并成一个空桶"
            ));
        }
        if name.starts_with("http_") || name.starts_with("cookie_") || name.starts_with("arg_") {
            continue;
        }
        return Err(format!(
            "'{dollar}' 在限流判定时刻展开不出值。支持的 key：$remote_addr / $binary_remote_addr、\
             $http_<头>、$cookie_<名>、$arg_<参数>、$uri/$request_uri/$host/$scheme/$request_method \
             等请求期变量（可拼接，如 $cookie_sid$remote_addr）；set 出来的变量不能作为 key，\
             请直接用它右边的来源变量"
        ));
    }
    // 一个变量都没有的模板（`$1abc` 这类捕获组字面量、纯文本）会原样保留，于是每个请求
    // 都落进同一个"常量键"桶：整区变成一条全局限流。这同样是静默失效，一起否决。
    if segs.is_empty() {
        return Err(format!(
            "'{var}' 里没有任何展开得出值的变量（`$1` 这类正则捕获组不算）：这样写会让所有请求共用同一个键"
        ));
    }
    Ok(())
}

/// 取出模板里所有 `$name` / `${name}` 形式的变量名（跳过 `$1` 这类数字捕获组）
fn key_segs(var: &str) -> Vec<String> {
    let bytes = var.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if bytes.get(j) == Some(&b'{') {
            j += 1;
        }
        let start = j;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
            j += 1;
        }
        if start != j && !bytes[start].is_ascii_digit() {
            out.push(var[start..j].to_string());
        }
        i = j.max(i + 1);
    }
    out
}

/// 本请求在这个 key 模板下的计数 key。
///
/// 返回 `None` = 这一维上这个请求没有值（没带那个头/Cookie/参数）。nginx 的语义是
/// **key 为空的请求不受本区限流**，调用方要跳过判定；绝不能把它们并到一个空 key 的桶里，
/// 那等于给整个区加了一道隐藏的总闸，还会把"匿名流量"和真流量混在一起算突发。
///
/// 地址写法走快路径：不插值、每请求零分配，这也是绝大多数配置的形态。
pub fn zone_key(var: &str, ctx: &crate::engine::RequestCtx) -> Option<String> {
    if addr_var(var) {
        return Some(ctx.remote_addr.clone());
    }
    let key = crate::proxy::interpolate_vars(var, ctx);
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// 从一条 `limit_*_zone` 指令里取出 key 变量（与 `parse_req_zone` 同一口径）。/// `-t` 用它把"写了个运行期根本不展开的变量"直接否决掉（见 router 的 `check_zone_keys`）。
pub fn zone_key_var(d: &Directive) -> Option<String> {
    var_of(&d.args)
}

impl Limits {
    pub fn parse_all(config: &Config) -> Self {
        let mut l = Limits {
            req_status: 429,
            conn_status: 503,
            ..Default::default()
        };
        for d in &config.root.block {
            match d.name.as_str() {
                "limit_req_zone" => match parse_req_zone(d) {
                    Some((var, name, rate, burst)) => {
                        // key 变量是不是地址，`-t` 已经否决过了（router::check_zone_keys）。
                        // 这里不再重复判定，避免"运行期悄悄改按 IP 限"与"`-t` 放行"两说。
                        l.req_zones
                            .insert(name.clone(), ReqZone::new(&name, rate, burst, &var));
                    }
                    None => l.warnings.push(format!(
                        "limit_req_zone（第 {} 行）缺少变量、zone= 或 rate=",
                        d.line
                    )),
                },
                "limit_conn_zone" => match parse_conn_zone(d) {
                    Some((var, name)) => {
                        l.conn_zones
                            .insert(name.clone(), ConnZone::new(&name, &var));
                    }
                    None => l.warnings.push(format!(
                        "limit_conn_zone（第 {} 行）缺少变量或 zone=",
                        d.line
                    )),
                },
                "limit_req_status" => {
                    if let Some(v) = d.arg(0).and_then(|s| s.parse::<u16>().ok()) {
                        l.req_status = v;
                    }
                }
                "limit_conn_status" => {
                    if let Some(v) = d.arg(0).and_then(|s| s.parse::<u16>().ok()) {
                        l.conn_status = v;
                    }
                }
                _ => {}
            }
        }
        l
    }

    pub fn req_zone(&self, name: &str) -> Option<&Arc<ReqZone>> {
        self.req_zones.get(name)
    }

    pub fn conn_zone(&self, name: &str) -> Option<&Arc<ConnZone>> {
        self.conn_zones.get(name)
    }

    // ==================== 队列：配置套用（启动与热重载走同一条路） ====================

    /// 套用 `limit_req_queue` / `limit_req_learning`。返回的是**降级说明**而不是错误：
    /// 队列领不到学习预算、或配置引用了尚未建立的限流区，都只让那条配置退回原样
    /// （超限即拒 / 需要重启），绝不能让网关因此拒绝服务。
    ///
    /// 为什么热重载只改策略而不重建区：`limit_req_zone` 的区实例在进程内唯一，
    /// 表里的在世状态（令牌余量、正在排队的请求）一清零，客户端就会看到
    /// "每次重载都白送一轮额度"。新增的区仍然要重启，这里如实说明。
    pub fn apply_queue(
        &self,
        config: &Config,
        learning: &crate::learning::Learning,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let declared = parse_queue_policies(config, &mut notes);
        for (name, zone) in &self.req_zones {
            let want = declared.get(name).copied();
            let mut g = zone.policy.lock().unwrap_or_else(|e| e.into_inner());
            *g = want;
            drop(g);
            // 学习表只在"本区真的会排队"时申领：没开队列的区永远走不到 admit 的学习分支，
            // 给它一张表等于白占进程级预算。
            let bytes = if want.is_some() {
                learning.zone_wants_queue_learning(name)
            } else {
                None
            };
            sync_burst_table(zone, name, bytes, learning, &mut notes);
        }
        for name in declared.keys() {
            if !self.req_zones.contains_key(name) {
                notes.push(format!(
                    "limit_req_queue '{name}' 没有对应的 limit_req_zone（或该区是本次重载新增的），此配置需重启生效"
                ));
            }
        }
        // 队列侧声明了学习、但本区没开队列：这条声明永远不会被读到，说清楚比静默忽略好
        for name in learning.queue_zones.keys() {
            if !declared.contains_key(name) {
                notes.push(format!(
                    "limit_req_learning '{name}' 需要同一区先写 limit_req_queue，否则无队列可学（已忽略）"
                ));
            }
        }
        trim_tables_to_budget(self, learning, &mut notes);
        notes
    }

    // ==================== 信誉：进程级一张表（队列优先级 + 缓存驻留） ====================

    /// 套用 `vip_learning`：建表 / 换表 / 放表。返回的是**降级说明**而不是错误。
    ///
    /// 申领顺序刻意为 缓存草图 → 突发表 → 信誉表：预算不够时越靠后的越先让路，
    /// 因为信誉只是"锦上添花"（少给一点优先级、少驻留一会儿），而令牌与队列计数是正确性状态。
    pub fn apply_vip(&self, learning: &crate::learning::Learning) -> Vec<String> {
        let mut notes = Vec::new();
        let want = learning.vip_cfg();
        let mut g = self.vip.lock().unwrap_or_else(|e| e.into_inner());
        // 配置没变就别重建：重建会把在世信誉清零，等于每次重载都把所有客户重新当陌生人
        if matches!((g.as_ref(), want), (Some(v), Some(w)) if v.cfg() == w)
            || (g.is_none() && want.is_none())
        {
            return notes;
        }
        if let Some(old) = g.take() {
            let b = old.claimed_bytes();
            learning.release_bytes(b);
            notes.push(format!(
                "信誉学习：配置或预算已变，放掉旧信誉表 {b} B（在世信誉随之清零）"
            ));
        }
        let Some(cfg) = want else {
            return notes;
        };
        if self.req_zones.is_empty() {
            // 没申领过就不归还：信誉的观察源是限流判定，一个区都没有时这条配置永远不会生效
            notes.push(
                "vip_learning：没有任何 limit_req_zone，判定结果无从观测，信誉学不起来".to_string(),
            );
            return notes;
        }
        match crate::vip::Vip::new(cfg, learning) {
            Some(v) => {
                let bytes = v.bytes();
                *g = Some(Arc::new(v));
                notes.push(format!(
                    "信誉学习：已建 {bytes} B 表（{} 个槽位），分数 >= {} 算重要客户；静默 {}ms 掉 1 分、每次 429 扣 {}",
                    bytes / crate::vip::SLOT_BYTES,
                    cfg.min,
                    cfg.decay_ms,
                    crate::vip::STRIKE
                ));
            }
            None => notes.push(format!(
                "vip_learning：预算 {} B 已被缓存与队列用完，信誉表没建起来（本次不学重要客户）",
                learning.budget.total()
            )),
        }
        notes
    }

    /// 当前信誉表（请求路径用：判定要写、缓存写入要读）。
    pub fn vip(&self) -> Option<Arc<crate::vip::Vip>> {
        self.vip.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 这个客户端现在算不算重要客户（没建表 = 一律不算）。
    pub fn is_vip(&self, key: &str) -> bool {
        self.vip().is_some_and(|v| v.is_vip(key))
    }

    pub fn vip_snapshot(&self) -> Option<crate::vip::VipSnapshot> {
        self.vip().map(|v| v.snapshot())
    }

    /// 逐区队列概况（`/metrics` 渲染；按区名排序，保证每次抓取可比对）
    pub fn queue_rows(&self) -> Vec<(String, QueueSnapshot)> {
        let mut rows: Vec<(String, QueueSnapshot)> = self
            .req_zones
            .iter()
            .map(|(n, z)| (n.clone(), z.queue_snapshot()))
            .filter(|(_, s)| s.policy.is_some() || s.table_bytes > 0)
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// 只列开了队列的区（`-t` 摘要用）：没写 `limit_req_queue` 时一行都不产生，
    /// 免得把老配置的 `-t` 输出搅变。
    pub fn queue_summary(&self) -> Vec<String> {
        self.queue_rows()
            .into_iter()
            .filter_map(|(n, s)| {
                let p = s.policy?;
                Some(format!(
                    "zone={n} depth={}..{} max_delay={}ms 学习={} B",
                    p.depth_min, p.depth_max, p.max_delay_ms, s.table_bytes
                ))
            })
            .collect()
    }

    /// 启动时打印的区域概况（运维只看日志就要知道限流到底生效了什么）
    pub fn describe(&self) -> Vec<String> {
        // 按区名排序：日志与 -t 摘要必须逐次可比对
        let mut reqs: Vec<&Arc<ReqZone>> = self.req_zones.values().collect();
        reqs.sort_by(|a, b| a.name.cmp(&b.name));
        let mut out: Vec<String> = reqs
            .iter()
            .map(|z| {
                let mut line = format!(
                    "limit_req zone={} rate={:.1}r/s burst={:.0} key={}",
                    z.name, z.rate_per_sec, z.burst, z.key_var
                );
                if let Some(p) = z.policy() {
                    let t = z.table_bytes();
                    line.push_str(&format!(
                        "，队列 depth={}..{} max_delay={}ms 学习={}",
                        p.depth_min,
                        p.depth_max,
                        p.max_delay_ms,
                        if t > 0 {
                            format!("{t} B")
                        } else {
                            "off".to_string()
                        }
                    ));
                }
                line
            })
            .collect();
        let mut conns: Vec<&Arc<ConnZone>> = self.conn_zones.values().collect();
        conns.sort_by(|a, b| a.name.cmp(&b.name));
        out.extend(
            conns
                .iter()
                .map(|z| format!("limit_conn zone={} key={}", z.name, z.key_var)),
        );
        out
    }

    /// 清理所有区域里的闲置 key（后台定时任务调用，防止状态表随客户端数量无限增长）
    pub fn purge_idle_all(&self, idle_ms: i64) -> usize {
        self.req_zones
            .values()
            .map(|z| z.purge_idle(idle_ms))
            .sum::<usize>()
            + self
                .conn_zones
                .values()
                .map(|z| z.purge_idle(idle_ms))
                .sum::<usize>()
    }
}

fn zone_name_of(arg: &str) -> Option<String> {
    let z = arg.strip_prefix("zone=")?;
    Some(z.split(':').next()?.to_string())
}

/// 变量参数：nginx 写 `$remote_addr` 或 `$binary_remote_addr`（词法器不认 `$`，这里靠首字符判断）
fn var_of(args: &[String]) -> Option<String> {
    args.iter().find(|a| a.starts_with('$')).cloned()
}

fn parse_req_zone(d: &Directive) -> Option<(String, String, f64, f64)> {
    let var = var_of(&d.args)?;
    let mut name = None;
    let mut rate = None;
    let mut burst = 0.0;
    for a in &d.args {
        if a.starts_with("zone=") {
            name = zone_name_of(a);
        } else if let Some(r) = a.strip_prefix("rate=") {
            rate = parse_rate(r);
        } else if let Some(b) = a.strip_prefix("burst=") {
            burst = b.parse().unwrap_or(0.0);
        }
    }
    Some((var, name?, rate?, burst))
}

fn parse_conn_zone(d: &Directive) -> Option<(String, String)> {
    let var = var_of(&d.args)?;
    Some((var, d.args.iter().find_map(|a| zone_name_of(a))?))
}

/// `50r/s` / `300r/m` / `2r/h` / `10`
fn parse_rate(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("r/s") {
        n.parse::<f64>().ok()
    } else if let Some(n) = s.strip_suffix("r/m") {
        n.parse::<f64>().ok().map(|v| v / 60.0)
    } else if let Some(n) = s.strip_suffix("r/h") {
        n.parse::<f64>().ok().map(|v| v / 3600.0)
    } else {
        s.parse::<f64>().ok()
    }
}

/// 解析 location 内的 `limit_req zone=name [burst=n] [nodelay]`
pub fn parse_req_rule(d: &Directive) -> Option<ReqRule> {
    let zone = d.args.iter().find_map(|a| zone_name_of(a))?;
    let burst = d
        .args
        .iter()
        .find_map(|a| a.strip_prefix("burst="))
        .and_then(|v| v.parse::<f64>().ok());
    Some(ReqRule { zone, burst })
}

/// 解析 `limit_conn name number;`
pub fn parse_conn_rule(d: &Directive) -> Option<ConnRule> {
    let zone = d.arg(0)?.to_string();
    let number = d.arg(1)?.parse::<u32>().ok()?;
    Some(ConnRule { zone, number })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_after_burst_is_consumed() {
        // 速率取 1r/s：测试并行跑满 CPU 时几次调用的间隔也远小于 1s，
        // 不会像 1000r/s 那样在几毫秒里补出新令牌而偶发误判。
        let z = ReqZone::new("t", 1.0, 3.0, "$remote_addr");
        for _ in 0..4 {
            assert!(z.check("1.2.3.4", None).is_none());
        }
        assert!(z.check("1.2.3.4", None).is_some(), "burst+1 之后应拒绝");
        assert!(z.check("5.6.7.8", None).is_none(), "不同 key 互不影响");
        // 规则级 burst 覆盖
        let z2 = ReqZone::new("t2", 1.0, 0.0, "$remote_addr");
        assert!(z2.check("k", Some(5.0)).is_none());
        assert!(
            z2.check("k", Some(0.0)).is_none(),
            "覆盖为 0 时首个请求仍可放行"
        );
    }

    #[test]
    fn tokens_refill_over_time() {
        // 2 r/s = 每 500ms 补一个令牌：判断用的时间尺度比调度抖动大两个数量级。
        // 这里不能用高速率（原来写的是 1000r/s）：那等于要求"两次背靠背的 check"落在同一个
        // 毫秒内——本机全过，Linux CI 上跑满 CPU 时中间那条"应拒绝"会被补回来的令牌翻成放行，
        // 红的是测试对调度抖动敏感，不是补牌逻辑。
        let z = ReqZone::new("t", 2.0, 0.0, "$remote_addr");
        assert!(z.check("k", None).is_none(), "首个请求放行");
        assert!(z.check("k", None).is_some(), "桶空时应拒绝");
        std::thread::sleep(std::time::Duration::from_millis(650));
        assert!(z.check("k", None).is_none(), "按速率补回令牌后应再次放行");
    }

    #[test]
    fn conn_guard_acquires_and_releases() {
        let z = ConnZone::new("c", "$remote_addr");
        let a = z.try_acquire("ip", 2).expect("1");
        let b = z.try_acquire("ip", 2).expect("2");
        assert!(z.try_acquire("ip", 2).is_none(), "并发 2 已满");
        drop(a);
        assert!(z.try_acquire("ip", 2).is_some(), "释放后应可再取");
        drop(b);
        assert!(z.try_acquire("other", 1).is_some());
    }

    #[test]
    fn keys_spread_across_shards() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..500 {
            seen.insert(shard_of(&format!("10.0.0.{i}")));
        }
        assert!(seen.len() > 20, "key 应分散到多片，实际片数 {}", seen.len());
    }

    #[test]
    fn parses_rate_forms() {
        assert_eq!(parse_rate("50r/s"), Some(50.0));
        assert!((parse_rate("300r/m").unwrap() - 5.0).abs() < 1e-9);
        assert_eq!(parse_rate("x"), None);
    }

    #[test]
    fn parses_zone_and_rules() {
        let cfg = Config::parse(
            "limit_req_zone $remote_addr zone=allr:10m rate=600r/m burst=20;
             limit_conn_zone $binary_remote_addr zone=allc:10m;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let desc = l.describe();
        assert_eq!(desc.len(), 2, "一个 limit_req 区 + 一个 limit_conn 区");
        assert!(
            desc.iter().any(|s| s.contains("zone=allr")
                && s.contains("rate=10.0r/s")
                && s.contains("burst=20")
                && s.contains("key=$remote_addr")),
            "describe: {desc:?}"
        );
        assert!(desc
            .iter()
            .any(|s| s.contains("zone=allc") && s.contains("key=$binary_remote_addr")));
        let z = l.req_zone("allr").unwrap();
        assert!((z.rate_per_sec - 10.0).abs() < 1e-9);
        assert_eq!(z.burst, 20.0);
        assert!(l.conn_zone("allc").is_some());
        assert!(l.req_zone("nope").is_none(), "未声明的 zone 不应凭空出现");
    }

    #[test]
    fn purge_idle_removes_stale_keys() {
        let z = ReqZone::new("t", 10.0, 0.0, "$remote_addr");
        z.check("a", None);
        z.check("b", None);
        // 全部视为已闲置
        assert_eq!(z.purge_idle(-1), 2);
        assert!(z.purge_idle(1_000_000) == 0);
    }

    /// "是不是地址"只有一处判定：地址走快路径，其余按 key 模板插值。
    /// `-t` 用 check_key_var 逐段否决"判定时刻取不到值"的写法，
    /// 运行期不再有"记着别的变量、实际按 IP 限"这种两说。
    #[test]
    fn key_templates_are_checked_per_segment() {
        assert!(addr_var("$remote_addr"));
        assert!(addr_var("$binary_remote_addr"));
        for good in [
            "$remote_addr",
            "$binary_remote_addr",
            "$http_x_api_key",
            "$cookie_sid",
            "$arg_token",
            "$cookie_sid$remote_addr",
            "${http_x_stu}-${uri}",
            "$uri",
            "$host",
            "$server_port",
            "$request_method",
        ] {
            assert!(
                check_key_var(good).is_ok(),
                "{good} 是请求期就有值的变量，不该被否决：{:?}",
                check_key_var(good)
            );
        }
        for bad in [
            "$status",
            "$upstream_addr",
            "$sent_http_x_cache",
            "$upstream_http_age",
            "$request_body",
            "$server_name",
            "$geoip_country_code",
            "$not_a_var",
        ] {
            assert!(
                check_key_var(bad).is_err(),
                "{bad} 在判定时刻取不到值，该被否决"
            );
        }
        // 复合模板逐段判：坏一段就整体否决，并且要点名那一段
        let e = check_key_var("$cookie_sid$status").unwrap_err();
        assert!(e.contains("$status"), "{e}");
        // 一个变量都没有的模板（`$1abc` 这类捕获组字面量）会原样保留，
        // 于是每个请求共用同一个常量键桶 = 整区变成一条全局限流，同样要否决
        let e = check_key_var("$1abc").unwrap_err();
        assert!(e.contains("没有任何展开得出值的变量"), "{e}");
        assert!(check_key_var("static").is_err(), "纯文本键同样并成一个桶");
    }

    /// key 在这一维上没有值 = 这个请求不参与本区计数（nginx 同义）。
    /// 把它们并到一个空 key 的桶里等于给全区加一道看不见的总闸，
    /// 还会把匿名流量学成"同一个大客户"。
    #[test]
    fn zone_key_scopes_counting_to_the_declared_dimension() {
        let mut ctx = crate::engine::RequestCtx::default();
        ctx.remote_addr = "10.1.2.3".into();
        ctx.req_headers = vec![
            ("x-student".into(), "20210001".into()),
            ("cookie".into(), "sid=abc; theme=dark".into()),
        ];
        ctx.query = "token=t9".into();
        assert_eq!(zone_key("$remote_addr", &ctx).as_deref(), Some("10.1.2.3"));
        assert_eq!(
            zone_key("$binary_remote_addr", &ctx).as_deref(),
            Some("10.1.2.3")
        );
        assert_eq!(
            zone_key("$http_x_student", &ctx).as_deref(),
            Some("20210001")
        );
        assert_eq!(zone_key("$cookie_sid", &ctx).as_deref(), Some("abc"));
        assert_eq!(zone_key("$arg_token", &ctx).as_deref(), Some("t9"));
        assert_eq!(
            zone_key("$cookie_sid$remote_addr", &ctx).as_deref(),
            Some("abc10.1.2.3"),
            "拼接写法按整模板插值"
        );
        assert_eq!(
            zone_key("$http_x_missing", &ctx),
            None,
            "没带头的请求不该被计数"
        );
        assert_eq!(zone_key("$cookie_nope", &ctx), None);
        // 地址永远有值：非地址维度才可能返回 None
        let empty_ctx = crate::engine::RequestCtx::default();
        assert!(zone_key("$remote_addr", &empty_ctx).is_some());
        assert_eq!(zone_key("$http_x_student", &empty_ctx), None);
    }

    #[test]
    fn conn_zone_rejects_when_shard_exhausted() {
        let z = ConnZone::new("c", "$remote_addr");
        // 超过单片容量后，已归零的 key 可被复用而不是无限增长
        for i in 0..(PER_SHARD_CAPACITY + 10) {
            let g = z.try_acquire(&format!("k{i}"), 1);
            assert!(g.is_some(), "key {i} 应能获取额度");
            drop(g);
        }
        assert!(z.try_acquire("late", 1).is_some());
    }

    #[test]
    fn purge_idle_all_covers_every_zone() {
        let cfg = Config::parse(
            "limit_req_zone $remote_addr zone=a:1m rate=1r/s;
             limit_conn_zone $remote_addr zone=b:1m;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        l.req_zone("a").unwrap().check("1.1.1.1", None);
        assert!(l.purge_idle_all(-1) >= 1);
    }

    // ==================== 队列：有界排队 + 突发形状学习 ====================

    /// 学习规则本身：记的是"上一股已经结束的突发有多长"，用固定时间戳喂出来。
    #[test]
    fn burst_table_remembers_finished_bursts_only() {
        let mut t = BurstTable::new(16 * 1024, 100);
        // 一股 10 个、彼此间隔 50ms（都 < gap_cap，且远未到洪水线 64）：还没结束，不该给出任何深度
        for i in 0..10u32 {
            let (held, adjusted) = t.observe("k", 1_000 + i as i64 * 50, 64);
            assert_eq!(held, 0, "突发进行中就给深度，等于奖励持续压顶");
            assert!(!adjusted);
        }
        // 停了 300ms（> gap_cap）再来一个：上一股结束，长度 10 成为下次的上界
        assert_eq!(
            t.observe("k", 1_750, 64),
            (10, true),
            "学到的量要能计入调整次数"
        );
        // 第二股进行中：仍沿用上一股的结论，不会中途改写
        assert_eq!(t.observe("k", 1_800, 64), (10, false));
        assert_eq!(t.observe("k", 1_850, 64), (10, false));
        // 第二股结束：长度只有 3，学到的量跟着真实形状往下走，不是只涨不跌
        assert_eq!(t.observe("k", 2_300, 64), (3, true));
        // 陌生 key 一无所知；撞槽只会顶掉别人的记忆，不会给出假深度
        assert_eq!(t.observe("fresh", 2_300, 64), (0, false));
        let (used, total, max) = t.snapshot();
        assert_eq!(total, (16 * 1024 / std::mem::size_of::<BurstSlot>()) as u32);
        assert_eq!(used, 2);
        assert_eq!(max, 3);
    }

    /// 持续洪水拿不到深队列：一股长到越过洪水线的突发，会把已学到的深度清零。
    /// 这是"奖励偶发突发、惩罚持续洪水"的另一半，也是队列不会被攻击当缓冲用的依据。
    #[test]
    fn a_sustained_flood_is_not_rewarded_with_a_deep_queue() {
        let mut t = BurstTable::new(16 * 1024, 1_000);
        // 先记下一股正常长度的突发（5 个，仍在洪水线 8 之内）
        for i in 0..5 {
            assert_eq!(
                t.observe("bursty", i as i64 * 10, 8).0,
                0,
                "突发没结束前不给深度"
            );
        }
        assert_eq!(t.observe("bursty", 5_000, 8), (5, true), "结束后学到 5");
        // 另一路持续洪水：越过洪水线（8）之后，深度立刻回到无记忆状态
        for i in 0..8 {
            assert_eq!(
                t.observe("flood", 10_000 + i as i64 * 10, 8).0,
                0,
                "洪水第 {i} 个请求就不该有深队列"
            );
        }
        for i in 0..20 {
            assert_eq!(
                t.observe("flood", 10_200 + i as i64 * 10, 8).0,
                0,
                "洪水持续期间一直是下界"
            );
        }
        // 洪水收手后隔很久再来一个：也不该把这么长一股记成"正常突发"，
        // 否则"攻满一分钟再停手"就能换来下一股的深队列
        assert_eq!(
            t.observe("flood", 30_000, 8),
            (0, false),
            "洪水结束时同样清零"
        );
        // 两路互不干扰：突发那路记住的仍是它自己的形状
        assert_eq!(
            t.observe("bursty", 20_000, 8),
            (1, true),
            "距上次已远超 gap_cap，这股只有 1 个"
        );
        assert_eq!(t.snapshot().2, 1, "表里只留突发那路的结论");
    }

    /// 没写 `limit_req_queue` 时，`admit()` 必须与旧的 `check()` 完全同构：
    /// 只拒、不排队，且 Retry-After 逐字节不变。
    #[test]
    fn admit_without_a_queue_policy_matches_check() {
        let z = ReqZone::new("t", 1.0, 2.0, "$remote_addr");
        for _ in 0..3 {
            assert!(
                matches!(z.admit("k", None, None), Admit::Pass),
                "burst+1 内应放行"
            );
        }
        let a = z.admit("k", None, None);
        let Admit::Reject { retry_after_secs } = a else {
            panic!("未开队列时不应排队，得到 {a:?}");
        };
        assert_eq!(retry_after_secs, z.check("k", None).unwrap());
        // 队列计数只在"真的可能排队"的区累加：没开队列的区一律为 0，
        // 超限拒绝仍按老路径计入访问日志与通用限流指标。
        let s = z.queue_snapshot();
        assert_eq!(
            (s.queued, s.rejected_full, s.rejected_slow, s.occupied),
            (0, 0, 0, 0)
        );
    }

    /// 队列是有界的：排到 depth 就拒，名额随请求结束归还。
    #[test]
    fn queue_is_bounded_and_returns_its_slots() {
        let cfg = Config::parse(
            "limit_req_zone $remote_addr zone=q:1m rate=1r/s;
             limit_req_queue q depth=2 depth_min=2 max_delay=5s;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let learn = crate::learning::Learning::parse_all(&cfg);
        assert!(l.apply_queue(&cfg, &learn).is_empty());
        let z = l.req_zone("q").unwrap();
        assert!(matches!(z.admit("k", None, None), Admit::Pass));
        let mut held = vec![z.admit("k", None, None), z.admit("k", None, None)];
        for a in &held {
            assert!(matches!(a, Admit::Queued { .. }), "depth=2 应排下两个");
        }
        assert!(
            matches!(z.admit("k", None, None), Admit::Reject { .. }),
            "第三个排不下就该拒"
        );
        assert_eq!(z.queue_snapshot().occupied, 2);
        drop(held.pop().unwrap());
        assert!(
            matches!(z.admit("k", None, None), Admit::Queued { .. }),
            "归还名额后应可再排"
        );
        drop(held);
        assert_eq!(z.queue_snapshot().occupied, 0);
        // 别的 key 不受影响：令牌与队列都按 key 独立
        assert!(matches!(z.admit("other", None, None), Admit::Pass));
    }

    /// 学到的形状要真的进到放行判定里：陌生 key 只给下界，刚结束一股突发的 key 多排几个。
    #[test]
    fn learned_burst_depth_reaches_the_admission_decision() {
        let cfg = Config::parse(
            "learning on; learning_memory_budget 64k;
             limit_req_zone $remote_addr zone=q:1m rate=20r/s;
             limit_req_queue q depth=50 depth_min=1;
             limit_req_learning q table=8k;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let learn = crate::learning::Learning::parse_all(&cfg);
        assert!(l.apply_queue(&cfg, &learn).is_empty());
        let z = l.req_zone("q").unwrap();
        assert!(z.queue_snapshot().table_bytes > 0, "突发表应已申领");

        // 陌生 key：什么也没学到，只给 depth_min 一个名额
        assert!(matches!(z.admit("1.1.1.1", None, None), Admit::Pass));
        let _slot = z.admit("1.1.1.1", None, None);
        assert!(matches!(_slot, Admit::Queued { .. }));
        assert!(
            matches!(z.admit("1.1.1.1", None, None), Admit::Reject { .. }),
            "下界 1 时第二个就该拒"
        );

        // 学过的 key：先攒一股 4 个的突发（多出的两个被拒，但同样被计入形状），
        // 再停一段超过 gap_cap 的时间让这股突发结束
        let mut keep = Vec::new();
        for _ in 0..4 {
            let a = z.admit("2.2.2.2", None, None);
            if let Admit::Queued { permit, .. } = a {
                keep.push(permit);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        // 结束后第一个请求会补满令牌桶：先把它吃掉，再数这一股能给几个队列名额
        let _ = z.admit("2.2.2.2", None, None);
        let mut slots = 0usize;
        while let Admit::Queued { permit, .. } = z.admit("2.2.2.2", None, None) {
            keep.push(permit);
            slots += 1;
        }
        assert!(
            slots >= 2,
            "刚结束一股 4 个的突发，排队上界应高于下界，实得 {slots}"
        );
        let s = z.queue_snapshot();
        assert!(s.depth_adjust > 0, "深度改写过就要留下计数");
        assert!(s.learned_max >= 2, "表里要存得住学到的长度");
    }

    /// 信誉要真的能换成队列优先级：突发学习把两个 key 都教成"长度 1"之后，
    /// 有信誉的那个仍然拿满运维给的天花板，没信誉的只有一个名额。
    /// 同时确认信誉不豁免行为惩罚——VIP 冲进来同样被拒、同样掉级。
    #[test]
    fn vip_reputation_reaches_the_queue_depth() {
        let cfg = Config::parse(
            "learning on; learning_memory_budget 64k;
             limit_req_zone $remote_addr zone=q:1m rate=20r/s;
             limit_req_queue q depth=8 depth_min=1 max_delay=2s;
             limit_req_learning q table=8k;
             vip_learning table=8k min=4 decay=1m;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let learn = crate::learning::Learning::parse_all(&cfg);
        assert!(l.apply_queue(&cfg, &learn).is_empty());
        let notes = l.apply_vip(&learn);
        assert!(
            notes.iter().any(|n| n.contains("信誉学习：已建")),
            "{notes:?}"
        );
        let v = l.vip().expect("apply_vip 应建好信誉表");
        let z = l.req_zone("q").unwrap();
        // 两次 reload 之间配置没变就不该重建表：重建等于把所有在世信誉清零
        assert!(
            l.apply_vip(&learn).is_empty(),
            "配置未变时热重载要复用同一张表"
        );
        assert!(Arc::ptr_eq(&l.vip().unwrap(), &v));

        // 陌生 key：只有 depth_min 一个名额
        let mut cold = Vec::new();
        assert!(matches!(z.admit("1.1.1.1", None, Some(&v)), Admit::Pass));
        while let Admit::Queued { permit, .. } = z.admit("1.1.1.1", None, Some(&v)) {
            cold.push(permit);
        }
        assert_eq!(cold.len(), 1, "没信誉的冷 key 只该拿到 depth_min");
        assert_eq!(v.score("1.1.1.1"), 0, "一次 429 就把它打回零点");

        // 攒够信誉的 key：第一股突发就直接用 depth_max
        let now = now_ms();
        for _ in 0..4 {
            v.note("9.9.9.9", crate::vip::Outcome::Passed, now);
        }
        assert!(l.is_vip("9.9.9.9"), "达到 min 就算重要客户");
        let mut hot = Vec::new();
        let mut rejected = false;
        loop {
            match z.admit("9.9.9.9", None, Some(&v)) {
                Admit::Queued { permit, .. } => hot.push(permit),
                Admit::Reject { .. } => rejected = true,
                Admit::Pass => {}
            }
            if rejected {
                break;
            }
        }
        assert_eq!(
            hot.len(),
            8,
            "VIP 首股应拿到 depth_max 个名额，实得 {}",
            hot.len()
        );
        assert_eq!(v.score("9.9.9.9"), 0, "洪水那一下 429 的扣分照收");
        assert!(!l.is_vip("9.9.9.9"), "被拒过就不该还挂着 VIP");
        assert_eq!(l.vip_snapshot().unwrap().demoted, 1, "掉级要留计数");

        // 更要紧的一半：突发学习已经把 key 教成"长度 1"之后，信誉仍要盖过这个学到的下界。
        // 稀疏流量（间隔 > gap_cap=100ms）让两个 key 都只学到长度 1，差别于是只可能来自信誉。
        let (plain_key, trusted_key) = ("7.7.7.1", "7.7.7.2");
        for key in [plain_key, trusted_key] {
            for _ in 0..2 {
                assert!(matches!(z.admit(key, None, Some(&v)), Admit::Pass), "{key}");
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
        assert_eq!(z.queue_snapshot().learned_max, 1, "稀疏流量只该学到长度 1");
        assert_eq!(v.score(plain_key), 2, "两次放行不到 min");
        for _ in 0..2 {
            v.note(trusted_key, crate::vip::Outcome::Passed, now_ms());
        }
        assert!(l.is_vip(trusted_key));
        std::thread::sleep(std::time::Duration::from_millis(150));
        // 把一股突发打到被拒为止，数这期间占住的队列名额
        for (key, want) in [(plain_key, 1usize), (trusted_key, 8usize)] {
            let mut keep = Vec::new();
            loop {
                match z.admit(key, None, Some(&v)) {
                    Admit::Queued { permit, .. } => keep.push(permit),
                    Admit::Reject { .. } => break,
                    Admit::Pass => {}
                }
            }
            assert_eq!(
                keep.len(),
                want,
                "{key} 学到的突发长度是 1：非 VIP 只拿到 1 个名额，VIP 要拿满天花板"
            );
        }
    }

    /// 队列的近似记忆必须记在进程级账本上：申领、归还、以及"没在学"时不占预算。
    #[test]
    fn queue_learning_claims_and_returns_the_process_ledger() {
        let cfg = Config::parse(
            "learning on; learning_memory_budget 64k;
             limit_req_zone $remote_addr zone=q:1m rate=1r/s;
             limit_req_queue q depth=5;
             limit_req_learning q table=8k;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let learn = crate::learning::Learning::parse_all(&cfg);
        let z = l.req_zone("q").unwrap();
        assert!(l.apply_queue(&cfg, &learn).is_empty());
        let bytes = z.queue_snapshot().table_bytes;
        assert!(
            bytes > 0 && bytes <= 8 * 1024,
            "表按申领量建，实占 {bytes} B"
        );
        assert_eq!(learn.used(), bytes, "账本要如实记着这张表");

        // 重载后本区不再学习（这里用"账本沿用、区换成别的名字"模拟）：表要还得干干净净
        let shrunk_cfg = Config::parse(
            "learning on; learning_memory_budget 64k; limit_req_learning other table=8k;",
        )
        .unwrap();
        let mut shrunk = crate::learning::Learning::parse_all(&shrunk_cfg);
        shrunk.reuse_ledger(&learn.budget);
        let notes = l.apply_queue(&cfg, &shrunk);
        assert!(notes.iter().any(|n| n.contains("停止学习")), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("limit_req_queue")),
            "声明了学习却没开队列要说明白：{notes:?}"
        );
        assert_eq!(z.queue_snapshot().table_bytes, 0);
        assert_eq!(learn.used(), 0, "预算不能只涨不跌");
    }

    /// 预算领不到只降级、不致命：队列照用配置天花板，只是不再按 key 调深度。
    #[test]
    fn an_unaffordable_burst_table_degrades_to_the_static_depth() {
        let cfg = Config::parse(
            "learning on; learning_memory_budget 8k;
             limit_req_zone $remote_addr zone=q:1m rate=1r/s;
             limit_req_queue q depth=5;
             limit_req_learning q table=1m;",
        )
        .unwrap();
        let l = Limits::parse_all(&cfg);
        let learn = crate::learning::Learning::parse_all(&cfg);
        let notes = l.apply_queue(&cfg, &learn);
        assert!(notes.iter().any(|n| n.contains("预算不足")), "{notes:?}");
        let z = l.req_zone("q").unwrap();
        assert_eq!(z.queue_snapshot().table_bytes, 0, "领不到就不该占内存");
        assert_eq!(learn.used(), 0);
        assert!(matches!(z.admit("k", None, None), Admit::Pass));
        assert!(
            matches!(z.admit("k", None, None), Admit::Queued { .. }),
            "队列本身仍可用"
        );
    }

    #[test]
    fn parses_queue_policies_and_clamps_absurd_values() {
        let cfg = Config::parse(
            "limit_req_zone $remote_addr zone=q:1m rate=1r/s;
             limit_req_queue q depth=99999 depth_min=3 max_delay=2s;",
        )
        .unwrap();
        let mut notes = Vec::new();
        let mut p = parse_queue_policies(&cfg, &mut notes);
        let p = p.remove("q").expect("解析出 q 区");
        assert_eq!(p.depth_max, MAX_QUEUE_DEPTH, "depth 要夹到硬顶");
        assert_eq!(p.depth_min, 3);
        assert_eq!(p.max_delay_ms, 2000);
        assert!(notes.iter().any(|n| n.contains("硬顶")), "{notes:?}");

        // 下界大于上界：按上界处理，而不是把区间反过来
        let bad = Config::parse("limit_req_queue q depth=2 depth_min=9;").unwrap();
        let mut notes = Vec::new();
        let p = parse_queue_policies(&bad, &mut notes).remove("q").unwrap();
        assert_eq!((p.depth_min, p.depth_max), (2, 2));
        assert!(notes.iter().any(|n| n.contains("大于")), "{notes:?}");

        // 不认识的参数与非法时间：告警但仍给出可用策略
        let odd = Config::parse("limit_req_queue q max_delay=abc nonsense=1;").unwrap();
        let mut notes = Vec::new();
        let p = parse_queue_policies(&odd, &mut notes).remove("q").unwrap();
        assert_eq!(p.max_delay_ms, DEFAULT_MAX_DELAY_MS);
        assert!(notes.iter().any(|n| n.contains("nonsense")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("时间非法")), "{notes:?}");
    }

    #[test]
    fn queue_config_for_a_missing_zone_or_a_missing_queue_is_reported_not_fatal() {
        // 引用了不存在的限流区：只说明"需重启"，绝不拒绝启动
        let cfg = Config::parse("limit_req_queue ghost depth=5;").unwrap();
        let l = Limits::parse_all(&cfg);
        let notes = l.apply_queue(&cfg, &crate::learning::Learning::default());
        assert!(
            notes
                .iter()
                .any(|n| n.contains("ghost") && n.contains("重启")),
            "{notes:?}"
        );
        // 只声明了队列、没声明学习：不占任何预算
        let cfg2 = Config::parse(
            "limit_req_zone $remote_addr zone=q:1m rate=1r/s; limit_req_queue q depth=5;",
        )
        .unwrap();
        let l2 = Limits::parse_all(&cfg2);
        let learn = crate::learning::Learning::parse_all(&cfg2);
        assert!(l2.apply_queue(&cfg2, &learn).is_empty());
        assert_eq!(l2.req_zone("q").unwrap().queue_snapshot().table_bytes, 0);
        assert_eq!(learn.used(), 0);
        // -t 摘要只列开了队列的区，没写 limit_req_queue 时一行都不产生
        assert!(
            l2.queue_summary().is_empty()
                || l2.queue_summary().iter().all(|s| s.contains("zone=q"))
        );
        let empty = Limits::parse_all(
            &Config::parse("limit_req_zone $remote_addr zone=a:1m rate=1r/s;").unwrap(),
        );
        assert!(empty.queue_summary().is_empty(), "没开队列不该出现在摘要里");
    }
}
