//! 学习基建：极小内存的频率草图 + 全局字节预算。
//!
//! 这一层只负责"用固定大小的内存估计一件事发生得多频繁"，不做任何决策：
//! 决策在 `proxy_cache`（准入/驱逐）与 `limit`（队列深度）里做，两处共用同一张草图。
//!
//! 为什么是 4-bit count-min sketch（TinyLFU 的核心结构）而不是"每 key 一个计数器"：
//!   * 每 key 存计数就是又开一张无界哈希表，攻击者拿海量一次性 key 扫一遍就能把它撑爆，
//!     而这恰好是缓存学习最容易被滥用的地方；
//!   * 草图的大小与 key 数量**无关**：`bytes` 定死，计数器 4 bit 一个（一字节两个），
//!     4 行取最小值估计，只有"低估"没有"高估"；
//!   * 老化用整体减半（TinyLFU 的 reset）：写满一轮预算后所有计数器右移一位，
//!     老热点自然衰减、新热点能爬上来，不需要任何 per-key 时间戳。
//!
//! 哈希用 `engine::murmur_hash2`（确定性、无随机种子）：同一次进程启动内，同一 key
//! 的估计值是可复现的，便于 E2E 断言与排障。代价是草图下标可预测——但草图只影响
//! "缓存谁/排队多深"，不影响鉴权或放行，可预测不构成绕过面。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use onrouter_config::{Config, Directive};

/// nginx 风格的大小字面量（`512k` / `1m` / 纯字节数），复用 router 里那一份解析。
fn parse_size(s: &str) -> Option<usize> {
    crate::router::parse_size(s).map(|v| v as usize)
}

/// 草图行数：4 行是 TinyLFU 的取值，行越多误增越少但每次操作的哈希次数越多。
pub const ROWS: usize = 4;
/// 单个计数器的饱和值：4 bit。
pub const MAX_CTR: u8 = 15;
/// 一张草图至少这么多字节，再小就没必要学了（碰撞噪声压过信号）。
pub const MIN_SKETCH_BYTES: usize = 8 * 1024;

/// 4-bit 计数器的 count-min sketch，带周期性减半老化。
pub struct Sketch {
    /// 每行计数器个数（草图总计数器 = ROWS * cols）
    cols: usize,
    /// 打包存储：每字节两个 4-bit 计数器，低半字节是偶数下标
    ctr: Vec<u8>,
    /// 自上次减半以来累计的写入次数
    adds: usize,
    /// 累计写入多少次后减半（= 总计数器数，即平均每格被写过一次）
    reset_at: usize,
    /// 减半过多少次（老化轮次，指标与单测用）
    ages: u64,
}

impl Sketch {
    /// 按字节预算建图。`bytes` 会被向上取整到"每行计数器数为偶数"以保证半字节对齐，
    /// 并夹到 [`MIN_SKETCH_BYTES`] 以上。
    pub fn new(bytes: usize) -> Self {
        let bytes = bytes.max(MIN_SKETCH_BYTES);
        // 一字节两个计数器 → 总计数器数 = bytes * 2
        let total = bytes * 2;
        let cols = (total / ROWS).max(2);
        let ctr = vec![0u8; (cols * ROWS + 1) / 2];
        let reset_at = cols * ROWS;
        Sketch {
            cols,
            ctr,
            adds: 0,
            reset_at,
            ages: 0,
        }
    }

    #[inline]
    fn slot(&self, row: usize, idx: usize) -> (usize, bool) {
        let global = row * self.cols + idx;
        (global / 2, global % 2 == 1)
    }

    #[inline]
    fn get_slot(&self, row: usize, idx: usize) -> u8 {
        let (b, hi) = self.slot(row, idx);
        if hi {
            self.ctr[b] >> 4
        } else {
            self.ctr[b] & 0x0f
        }
    }

    #[inline]
    fn set_slot(&mut self, row: usize, idx: usize, v: u8) {
        let (b, hi) = self.slot(row, idx);
        if hi {
            self.ctr[b] = (self.ctr[b] & 0x0f) | ((v & 0x0f) << 4);
        } else {
            self.ctr[b] = (self.ctr[b] & 0xf0) | (v & 0x0f);
        }
    }

    /// 第 `row` 行里 `key` 的列下标。行之间用不同的盐，避免同一批 key 在所有行撞同一列。
    fn col(&self, row: usize, key: &[u8]) -> usize {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&(row as u32).to_le_bytes());
        let h = crate::engine::murmur_hash2(key) ^ crate::engine::murmur_hash2(&buf);
        (h as usize) % self.cols
    }

    /// 观测到一次 `key`：4 行各 +1（饱和于 15），并推进老化轮次。
    pub fn note(&mut self, key: &str) {
        self.note_weighted(key, 1);
    }
    /// 加权观测：`w` 次累加（VIP 驻留加权用它，权重由配置给死，不来自客户端可控的信号）。
    /// 饱和后继续加不再改变估计值，但仍计入老化轮次——否则扫库流量能让草图永不减半。
    pub fn note_weighted(&mut self, key: &str, w: u8) {
        let w = w.max(1);
        for _ in 0..w {
            let kb = key.as_bytes();
            for row in 0..ROWS {
                let idx = self.col(row, kb);
                let v = self.get_slot(row, idx);
                if v < MAX_CTR {
                    self.set_slot(row, idx, v + 1);
                }
            }
            self.adds += 1;
        }
        if self.adds >= self.reset_at {
            self.age();
        }
    }

    /// `key` 的估计频次（0..=15）：4 行取最小值。
    pub fn estimate(&self, key: &str) -> u8 {
        let kb = key.as_bytes();
        let mut m = MAX_CTR;
        for row in 0..ROWS {
            let idx = self.col(row, kb);
            m = m.min(self.get_slot(row, idx));
        }
        m
    }

    /// 全体减半（向下取整）：老热点平滑衰减，等价 TinyLFU 的 reset。
    pub fn age(&mut self) {
        for b in self.ctr.iter_mut() {
            let lo = (*b & 0x0f) >> 1;
            let hi = (*b >> 4) >> 1;
            *b = lo | (hi << 4);
        }
        self.adds = 0;
        self.ages = self.ages.wrapping_add(1);
    }

    /// 实际占用字节（含打包数组本体，草图是定长的，没有随 key 增长的附属结构）。
    pub fn bytes(&self) -> usize {
        self.ctr.len()
    }

    pub fn ages(&self) -> u64 {
        self.ages
    }
}

/// 全局学习内存预算的账房：草图按字节申领，领不到就退化成"不学习"。
///
/// 为什么要有账房而不是让每个区自己 `new(bytes)`：学习结构是**随配置区数量线性增长**的，
/// 12 个缓存区各要 512 KiB 就是 6 MiB，而"极小内存"必须是进程级承诺。申领失败是
/// 常态化的降级路径（该区行为回到纯 LRU），不是错误。
///
/// 账本必须**跨热重载延续**：重载会重新 parse 出一个全新的 `Learning`，如果账本也换新的，
/// 同一批已在世的草图就会在新账本上被重复申领一遍，预算在多次重载后悄悄失效。
/// 所以这里用 `Arc` 持有，并把上限做成可调整的（`set_total`）。
/// 有意不实现 `Default`：默认上限 0 等于"静默不学习"，是最难排查的一种配置错误。
pub struct Budget {
    total: AtomicUsize,
    used: AtomicUsize,
    denied: AtomicUsize,
}

impl Budget {
    pub fn new(total: usize) -> Self {
        Budget {
            total: AtomicUsize::new(total),
            used: AtomicUsize::new(0),
            denied: AtomicUsize::new(0),
        }
    }

    /// 调整上限（配置改了）。把上限调小不会主动驱逐：超额部分由调用方
    /// （`ProxyCache::apply_learning`）如实收敛并在日志里说明。
    pub fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
    }

    /// 申领 `n` 字节：够则累加并返回 true，不够则记一次拒绝并返回 false。
    pub fn claim(&self, n: usize) -> bool {
        let total = self.total.load(Ordering::Relaxed);
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_add(n);
            if next > total {
                self.denied.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            match self.used.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }

    /// 归还（热重载后区变少/草图缩小时调用，避免只涨不跌）。
    pub fn release(&self, n: usize) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            match self.used.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(c) => cur = c,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    pub fn denied(&self) -> usize {
        self.denied.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

/// 学习三件套的进程级配置与账目（`learning on;` 打开，默认关闭）。
pub struct Learning {
    /// 总开关：off 时所有学习路径都短路，行为与没有这套代码时逐字节一致
    pub enabled: bool,
    /// 进程级账本。`Arc`：见 [`Budget`] 的说明，热重载必须沿用同一本账。
    pub budget: Arc<Budget>,
    /// 每个学习区默认申领的草图字节数（`proxy_cache_learning <zone> sketch=<size>` 覆盖）
    pub sketch_bytes: usize,
    /// 解析期收集的配置告警（`-t` 与启动日志如实打印）
    pub warnings: Vec<String>,
    /// 声明要学习的 proxy_cache 区：区名 → 指定的草图字节（None = 用 `sketch_bytes` 默认）
    pub learn_zones: HashMap<String, Option<usize>>,
    /// 声明要学突发形状的 limit_req 区：区名 → 突发表字节（None = 用 `queue_table_bytes` 默认）。
    /// 队列的**正确性**状态（每 key 排队数）在原有限流表里，不受本字段控制；
    /// 这里申领的只是"这个 key 上次一口气来了多少个"这份**近似**记忆。
    pub queue_zones: HashMap<String, Option<usize>>,
    /// 每个队列学习区默认申领的突发表字节数
    pub queue_table_bytes: usize,
    /// 信誉表配置（进程级一张）：None = 没写 `vip_learning`，不学重要客户。
    /// 它不挂在某个区上：信誉看的是"这个客户端"，而队列与缓存都要用同一份判断。
    pub vip: Option<crate::vip::VipConfig>,
}

impl Default for Learning {
    fn default() -> Self {
        Learning {
            enabled: false,
            budget: Arc::new(Budget::new(DEFAULT_BUDGET)),
            sketch_bytes: DEFAULT_SKETCH_BYTES,
            warnings: Vec::new(),
            learn_zones: HashMap::new(),
            queue_zones: HashMap::new(),
            queue_table_bytes: DEFAULT_QUEUE_BYTES,
            vip: None,
        }
    }
}

/// 默认全局预算：1 MiB——够放两张 512 KiB 的草图（每张 2 MiB 计数器槽位）。
pub const DEFAULT_BUDGET: usize = 1024 * 1024;
/// 硬顶：再多就不是"极小内存"了，配置超出即夹到此处并告警。
pub const MAX_BUDGET: usize = 16 * 1024 * 1024;
/// 单区草图默认大小。
pub const DEFAULT_SKETCH_BYTES: usize = 256 * 1024;
/// 单区草图硬顶（防止一个区把预算吃光）。
pub const MAX_SKETCH_BYTES: usize = 4 * 1024 * 1024;
/// 单区队列突发表默认大小：64 KiB ≈ 5400 个 key 的突发形状记忆。
/// 比缓存草图小一个量级是刻意的——队列学习只需要"这个 key 上次一口气来了多少个"，
/// 一个 key 12 字节足够，而缓存准入需要给每个 URL 留频次。
pub const DEFAULT_QUEUE_BYTES: usize = 64 * 1024;
/// 单区队列突发表硬顶。
pub const MAX_QUEUE_BYTES: usize = 1024 * 1024;
/// 信誉表默认大小：64 KiB ≈ 5400 个客户端（每 key 12 字节）。
pub const DEFAULT_VIP_BYTES: usize = 64 * 1024;
/// 信誉表硬顶：整进程只有一张，再多就超出"极小内存"的承诺。
pub const MAX_VIP_BYTES: usize = 1024 * 1024;

impl Learning {
    /// 为某个缓存区申领一张草图：总开关关闭、或预算领不到时返回 None
    /// （调用方据此回到纯 LRU，并把"该区没在学"如实反映到指标里）。
    ///
    /// "申领量超过全局预算"这种配置错误不在这里报——它在解析期就能看出来，
    /// 由 `-t` 如实打印告警；运行期只做降级，不产生新的告警路径。
    pub fn sketch_for(&self, zone: &str, want_bytes: Option<usize>) -> Option<Sketch> {
        let want = self.claim_bytes(want_bytes.unwrap_or(self.sketch_bytes), MAX_SKETCH_BYTES)?;
        let s = Sketch::new(want);
        // Sketch::new 会向上夹到 MIN_SKETCH_BYTES，实际占用可能与申领数不同：把差额还回去
        let diff = want.saturating_sub(s.bytes());
        if diff > 0 {
            self.budget.release(diff);
        }
        let _ = zone;
        Some(s)
    }

    /// 从进程级账本申领 `want` 字节（先夹到 `[MIN_SKETCH_BYTES, cap]`）。
    /// 领不到返回 None——调用方据此退回"不学习"，而不是 panic 或撑破预算。
    ///
    /// 缓存草图与队列突发表共用这一个入口：预算是**进程级**承诺，两类结构必须在
    /// 同一本账上排队，而不是各拿一个"看起来很小"的默认值互相挤兑。
    pub fn claim_bytes(&self, want: usize, cap: usize) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        let want = want.clamp(MIN_SKETCH_BYTES, cap);
        if self.budget.claim(want) {
            Some(want)
        } else {
            None
        }
    }

    /// 归还申领的字节（热重载后区变少/表缩小时调用，避免只涨不跌）。
    pub fn release_bytes(&self, n: usize) {
        self.budget.release(n);
    }

    /// 队列突发表申领量的取值区间夹取。与 [`Self::claim_bytes`] 同一口径，
    /// 供热重载判断"大小没变就别重建表"时比较用。
    pub fn clamp_queue_bytes(&self, want: usize) -> usize {
        want.clamp(MIN_SKETCH_BYTES, MAX_QUEUE_BYTES)
    }

    /// 该区是否参与学习（返回实际应申领的草图字节；None = 不学）。
    /// 声明了区但没写 `sketch=` 时用全局默认值——"没写大小"和"没声明区"是两回事。
    pub fn zone_wants_learning(&self, zone: &str) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        self.learn_zones.get(zone).map(|s| s.unwrap_or(self.sketch_bytes))
    }

    /// 该 limit_req 区是否要学突发形状（返回应申领的表字节；None = 不学）。
    pub fn zone_wants_queue_learning(&self, zone: &str) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        self.queue_zones
            .get(zone)
            .map(|b| b.unwrap_or(self.queue_table_bytes))
    }

    /// 热重载：把**旧账本**移植进新配置，上限换成新配置声明的值。
    ///
    /// 不做这件事的后果是静默的：新账本从 0 开始记，已在世的草图被重复申领一遍，
    /// 于是 `learning_memory_budget` 在多次重载后会悄悄失效（实际占用 = 上限 × 重载次数）。
    pub fn reuse_ledger(&mut self, prev: &Arc<Budget>) {
        prev.set_total(self.budget.total());
        self.budget = Arc::clone(prev);
    }

    /// 学习占用统计（指标与 `-t` 摘要用）。
    pub fn used(&self) -> usize {
        self.budget.used()
    }

    /// 因为预算不够而没能建图/扩图的次数。
    pub fn denied(&self) -> usize {
        self.budget.denied()
    }

    /// 启动/重载日志与 `-t` 摘要：把"到底在学什么"打印出来。
    /// 未启用时返回空——默认关闭是常态，不该每次启动都往日志里塞一行废话。
    pub fn describe(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.learn_zones.len() + self.queue_zones.len() + 1);
        out.push(format!(
            "learning 已启用：预算 {} B（已用 {} B），单区默认草图 {} B / 突发表 {} B",
            self.budget.total(),
            self.budget.used(),
            self.sketch_bytes,
            self.queue_table_bytes
        ));
        let mut cache: Vec<&String> = self.learn_zones.keys().collect();
        cache.sort();
        for z in cache {
            let want = self.zone_wants_learning(z).unwrap_or_default();
            out.push(format!("proxy_cache_learning zone={z} sketch={want} B"));
        }
        let mut queue: Vec<&String> = self.queue_zones.keys().collect();
        queue.sort();
        for z in queue {
            let want = self.zone_wants_queue_learning(z).unwrap_or_default();
            out.push(format!("limit_req_learning zone={z} table={want} B"));
        }
        if let Some(v) = self.vip_cfg() {
            out.push(format!(
                "vip_learning 信誉表 table={} B 晋升门槛 min={}/255 静默 {}ms 掉 1 分",
                v.table_bytes, v.min, v.decay_ms
            ));
        }
        out
    }

    /// 解析学习相关的顶层指令。只认识这几条；一条都不写时 `enabled=false`，
    /// 所有学习路径短路，行为与没有这套代码时逐字节一致。
    ///
    /// ```text
    /// learning                     on;
    /// learning_memory_budget       1m;
    /// proxy_cache_learning <zone> [sketch=<size>];
    /// limit_req_learning   <zone> [table=<size>];
    /// vip_learning        [table=<size>] [min=N] [decay=30s];
    /// ```
    pub fn parse_all(config: &Config) -> Self {
        let mut l = Learning::default();
        for d in &config.root.block {
            match d.name.as_str() {
                "learning" => match d.arg(0) {
                    Some("on") => l.enabled = true,
                    Some("off") => l.enabled = false,
                    Some(v) => {
                        l.warnings.push(format!(
                            "learning（第 {} 行）只接受 on/off，收到 '{v}'，按 off 处理",
                            d.line
                        ))
                    }
                    None => l.warnings.push(format!(
                        "learning（第 {} 行）缺少 on/off 参数，按 off 处理",
                        d.line
                    )),
                },
                "learning_memory_budget" => match d.arg(0).and_then(parse_size) {
                    Some(b) => {
                        let clamped = b.clamp(MIN_SKETCH_BYTES, MAX_BUDGET);
                        if clamped != b {
                            l.warnings.push(format!(
                                "learning_memory_budget（第 {} 行）{b} B 超出可用范围，已夹到 {} B",
                                d.line, clamped
                            ));
                        }
                        l.budget = Arc::new(Budget::new(clamped));
                    }
                    None => l.warnings.push(format!(
                        "learning_memory_budget（第 {} 行）大小非法（需形如 512k / 1m），已忽略并用默认 {} B",
                        d.line, DEFAULT_BUDGET
                    )),
                },
                "proxy_cache_learning" => {
                    if let Some((zone, sketch)) =
                        parse_learning_zone(d, "proxy_cache_learning", "sketch", &mut l.warnings)
                    {
                        if sketch.is_some() && sketch.unwrap_or_default() > l.budget.total() {
                            l.warnings.push(format!(
                                "proxy_cache_learning {zone}（第 {} 行）申领 {} B 大于全局预算 {} B，该区不会学习（回到纯 LRU）",
                                d.line,
                                sketch.unwrap_or_default(),
                                l.budget.total()
                            ));
                        }
                        l.learn_zones.insert(zone, sketch);
                    }
                }
                "limit_req_learning" => {
                    if let Some((zone, table)) =
                        parse_learning_zone(d, "limit_req_learning", "table", &mut l.warnings)
                    {
                        l.queue_zones.insert(zone, table);
                    }
                }
                "vip_learning" => {
                    let (cfg, notes) = crate::vip::parse_vip_directive(d);
                    l.warnings.extend(notes);
                    if l.vip.is_some() {
                        l.warnings.push(format!(
                            "vip_learning（第 {} 行）声明了多次，以最后一次为准",
                            d.line
                        ));
                    }
                    l.vip = Some(cfg);
                }
                _ => {}
            }
        }
        // 没有声明任何学习对象时，开总开关也没有东西可学——照实关掉，免得日志谎称"已启用"
        if l.learn_zones.is_empty() && l.queue_zones.is_empty() && l.vip.is_none() {
            l.enabled = false;
        }
        l
    }

    /// 信誉表配置：`learning off` 时返回 None（与其余学习路径同一开关）。
    pub fn vip_cfg(&self) -> Option<crate::vip::VipConfig> {
        if self.enabled {
            self.vip
        } else {
            None
        }
    }
}

/// `proxy_cache_learning <zone> [sketch=<size>]` 与 `limit_req_learning <zone> [table=<size>]`
/// 的参数形状一样，只有大小关键字不同，因此共用一份解析与告警措辞。
fn parse_learning_zone(
    d: &Directive,
    directive: &str,
    keyword: &str,
    warnings: &mut Vec<String>,
) -> Option<(String, Option<usize>)> {
    let Some(zone) = d.arg(0).filter(|s| !s.is_empty()) else {
        warnings.push(format!(
            "{directive}（第 {} 行）缺少区名，已忽略",
            d.line
        ));
        return None;
    };
    let raw = d.args.iter().find_map(|a| a.strip_prefix(&format!("{keyword}=")));
    let size = raw.and_then(parse_size);
    if raw.is_some() && size.is_none() {
        warnings.push(format!(
            "{directive} {zone}（第 {} 行）{keyword}='{}' 大小非法，改用默认值",
            d.line,
            raw.unwrap_or("")
        ));
    }
    if let Some(s) = size {
        let cap = if keyword == "sketch" {
            MAX_SKETCH_BYTES
        } else {
            MAX_QUEUE_BYTES
        };
        if s > cap {
            warnings.push(format!(
                "{directive} {zone}（第 {} 行）{keyword} 超过单区硬顶 {} B，已夹到硬顶",
                d.line, cap
            ));
        }
    }
    Some((zone.to_string(), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sketch_is_bounded_by_bytes_not_key_count() {
        // "极小内存"的承诺是结构性的：喂一百万个不同 key，占用一个字都不能变
        let mut s = Sketch::new(MIN_SKETCH_BYTES);
        let base = s.bytes();
        for i in 0..1_000_000u64 {
            s.note(&format!("key-{i}"));
            if s.bytes() != base {
                panic!("草图随 key 数增长");
            }
        }
        assert_eq!(s.bytes(), MIN_SKETCH_BYTES);
        assert!(s.ages() > 0, "写满一轮必须发生减半");
    }

    #[test]
    fn hot_key_outranks_one_shot_keys() {
        // 缓存准入要解决的正是这个场景：一个热对象 vs 海量一次性扫描 key
        let mut s = Sketch::new(64 * 1024);
        for _ in 0..20 {
            s.note("/hot");
        }
        for i in 0..50_000 {
            s.note(&format!("/scan/{i}"));
        }
        assert!(
            s.estimate("/hot") > s.estimate("/scan/7"),
            "热 key {} 应高于扫描 key {}",
            s.estimate("/hot"),
            s.estimate("/scan/7")
        );
    }

    #[test]
    fn counters_saturate_at_four_bits() {
        let mut s = Sketch::new(MIN_SKETCH_BYTES);
        for _ in 0..500 {
            s.note("/x");
        }
        assert_eq!(s.estimate("/x"), MAX_CTR, "4-bit 饱和");
    }

    #[test]
    fn estimate_never_overcounts_unseen_key_absent() {
        // count-min 只有"低估"没有"高估"：没见过的 key 估出来只能 <= 真值
        let mut s = Sketch::new(MIN_SKETCH_BYTES);
        for _ in 0..50 {
            s.note("/a");
        }
        assert!(s.estimate("/never-seen") <= s.estimate("/a"));
    }

    #[test]
    fn halving_decays_old_hotness() {
        let mut s = Sketch::new(MIN_SKETCH_BYTES);
        for _ in 0..50 {
            s.note("/old");
        }
        assert_eq!(s.estimate("/old"), MAX_CTR);
        s.age();
        s.age();
        assert!(s.estimate("/old") < MAX_CTR, "减半后必须衰减");
        s.age();
        s.age();
        s.age();
        s.age();
        s.age();
        assert_eq!(s.estimate("/old"), 0, "反复减半归零");
    }

    #[test]
    fn saturated_writes_still_advance_aging() {
        // 关键反滥用点：饱和后继续写也要推进老化，否则扫库流量让草图永不衰减
        let mut s = Sketch::new(MIN_SKETCH_BYTES);
        for _ in 0..(s.reset_at + 1) {
            s.note("/saturated");
        }
        assert!(s.ages() >= 1);
        assert!(s.estimate("/saturated") < MAX_CTR, "减半后不再是饱和值");
    }

    #[test]
    fn weighted_note_lifts_estimate() {
        let mut s = Sketch::new(64 * 1024);
        for _ in 0..4 {
            s.note_weighted("/vip-object", 3);
        }
        for _ in 0..4 {
            s.note("/plain-object");
        }
        assert!(s.estimate("/vip-object") >= s.estimate("/plain-object"));
    }

    #[test]
    fn estimate_is_deterministic_for_same_key() {
        let a = || {
            let mut s = Sketch::new(16 * 1024);
            s.note("/same");
            s
        };
        assert_eq!(a().estimate("/same"), a().estimate("/same"));
        assert_eq!(a().estimate("/other"), a().estimate("/other"));
    }

    #[test]
    fn budget_claims_and_denies() {
        let b = Budget::new(1000);
        assert!(b.claim(600));
        assert_eq!(b.used(), 600);
        assert!(!b.claim(500), "超出预算必须拒绝");
        assert_eq!(b.denied(), 1);
        assert_eq!(b.used(), 600, "被拒的申领不能占用额度");
        b.release(600);
        assert!(b.claim(1000));
        assert_eq!(b.used(), 1000);
    }

    #[test]
    fn learning_off_never_allocates() {
        let l = Learning::default();
        assert!(!l.enabled);
        assert!(l.sketch_for("c1", None).is_none());
        assert_eq!(l.budget.used(), 0);
    }

    #[test]
    fn learning_reserves_exact_sketch_bytes() {
        let l = Learning {
            enabled: true,
            budget: Arc::new(Budget::new(1024 * 1024)),
            sketch_bytes: 128 * 1024,
            ..Default::default()
        };
        let s = l.sketch_for("c1", None).expect("应有草图");
        assert_eq!(s.bytes(), 128 * 1024);
        assert_eq!(l.budget.used(), 128 * 1024, "申领数必须与实际占用一致");
        // 第二张领到剩下 896 KiB 中的 128 KiB，账目累加
        let _ = l.sketch_for("c2", None).expect("第二张");
        assert_eq!(l.budget.used(), 256 * 1024);
    }

    #[test]
    fn learning_degrades_gracefully_when_budget_exhausted() {
        let l = Learning {
            enabled: true,
            budget: Arc::new(Budget::new(MIN_SKETCH_BYTES * 2)),
            sketch_bytes: MIN_SKETCH_BYTES,
            ..Default::default()
        };
        assert!(l.sketch_for("a", None).is_some());
        assert!(l.sketch_for("b", None).is_some());
        // 第三个区领不到：返回 None 让调用方回到纯 LRU，而不是 panic 或超预算
        assert!(l.sketch_for("c", None).is_none());
        assert_eq!(l.budget.used(), MIN_SKETCH_BYTES * 2);
    }

    #[test]
    fn oversized_request_degrades_without_consuming_budget() {
        let l = Learning {
            enabled: true,
            budget: Arc::new(Budget::new(64 * 1024)),
            sketch_bytes: 64 * 1024,
            ..Default::default()
        };
        // 单区申领量 > 全局预算：运行期不学习也不告警（那是解析期 -t 的事），但要记一次拒绝
        assert!(l.sketch_for("big", Some(MAX_SKETCH_BYTES)).is_none());
        assert_eq!(l.denied(), 1);
        assert_eq!(l.budget.used(), 0, "被拒的申领不得占用预算");
    }

    fn cfg(text: &str) -> onrouter_config::Config {
        onrouter_config::Config::parse(text).expect("配置应能解析")
    }

    #[test]
    fn parse_defaults_are_off() {
        let l = Learning::parse_all(&cfg("events { worker_connections 1024; }"));
        assert!(!l.enabled);
        assert!(l.learn_zones.is_empty());
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        assert_eq!(l.budget.total(), DEFAULT_BUDGET);
        assert_eq!(l.sketch_bytes, DEFAULT_SKETCH_BYTES);
    }

    #[test]
    fn describe_lists_declared_zones() {
        let l = Learning::parse_all(&cfg(
            "learning on;
             learning_memory_budget 1m;
             proxy_cache_learning b sketch=512k;
             proxy_cache_learning a;",
        ));
        let d = l.describe();
        assert_eq!(d.len(), 3, "一行总览 + 两个区，实际 {d:?}");
        assert!(d[0].contains("预算 1048576 B"), "{}", d[0]);
        // 区名排序输出：日志与 -t 摘要必须逐次可比对
        assert!(d[1].contains("zone=a") && d[2].contains("zone=b"), "{d:?}");
        assert!(d[1].contains(&DEFAULT_SKETCH_BYTES.to_string()), "未写 sketch 用默认");
        assert!(d[2].contains("524288"), "写了 sketch 用声明值");
        assert!(Learning::default().describe().is_empty(), "默认关闭不占日志");
    }

    /// 账本跨重载延续是硬要求：新配置若换一本新账，在世草图会被重复申领，
    /// `learning_memory_budget` 就只是个摆设。
    #[test]
    fn reuse_ledger_keeps_claims_across_reload() {
        let prev = Learning::parse_all(&cfg(
            "learning on; learning_memory_budget 512k; proxy_cache_learning a; proxy_cache_learning b;",
        ));
        // 模拟运行期：两个区各申领了一张默认草图
        let _a = prev.sketch_for("a", None).expect("a");
        let _b = prev.sketch_for("b", None).expect("b");
        let used = prev.used();
        assert_eq!(used, DEFAULT_SKETCH_BYTES * 2);

        // 重载：解析出的新 Learning 自带一本新账，reuse_ledger 必须换回旧账并套用新上限
        let mut next = Learning::parse_all(&cfg(
            "learning on; learning_memory_budget 1m; proxy_cache_learning a; proxy_cache_learning b;",
        ));
        assert_eq!(next.used(), 0, "解析期不该有任何占用");
        let ledger = Arc::clone(&prev.budget);
        next.reuse_ledger(&ledger);
        assert_eq!(next.used(), used, "旧账本上的在世申领必须照常计入");
        assert_eq!(next.budget.total(), 1024 * 1024, "上限换成新配置声明的值");
        // 剩余额度按"已用 512k、上限 1m"算：再申领一张默认草图应成功
        assert!(next.sketch_for("c", None).is_some());
        assert_eq!(next.used(), used + DEFAULT_SKETCH_BYTES);
        assert!(Arc::ptr_eq(&next.budget, &ledger), "同一个账本，不是副本");
    }

    #[test]
    fn parse_enables_declared_learning_zones() {
        let l = Learning::parse_all(&cfg(
            "learning on;
             learning_memory_budget 2m;
             proxy_cache_learning c1;
             proxy_cache_learning c2 sketch=512k;",
        ));
        assert!(l.enabled);
        assert_eq!(l.budget.total(), 2 * 1024 * 1024);
        assert_eq!(l.zone_wants_learning("c1"), Some(DEFAULT_SKETCH_BYTES));
        assert_eq!(l.zone_wants_learning("c2"), Some(512 * 1024));
        assert_eq!(l.zone_wants_learning("nope"), None);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }

    #[test]
    fn learning_on_without_zones_stays_off() {
        // 没有声明任何学习区就"开总开关"：日志不得谎称已启用
        let l = Learning::parse_all(&cfg("learning on;"));
        assert!(!l.enabled, "{:?}", l.learn_zones);
    }

    #[test]
    fn parse_warns_on_bad_forms_but_still_learns() {
        let l = Learning::parse_all(&cfg(
            "learning maybe;
             learning on;
             learning_memory_budget banana;
             proxy_cache_learning c1 sketch=also-banana;
             proxy_cache_learning;",
        ));
        // `learning maybe` 非法按 off，后面的 `learning on` 仍生效（后写覆盖，与 nginx 一致）
        assert!(l.enabled);
        assert_eq!(l.budget.total(), DEFAULT_BUDGET, "非法预算回落默认");
        assert_eq!(l.zone_wants_learning("c1"), Some(DEFAULT_SKETCH_BYTES));
        for (needle, why) in [
            ("只接受 on/off", "learning 取值非法"),
            ("大小非法", "预算大小非法"),
            ("sketch='also-banana'", "sketch 非法"),
            ("缺少区名", "空区名"),
        ] {
            assert!(
                l.warnings.iter().any(|w| w.contains(needle)),
                "{why} 应有告警，实际 {:?}",
                l.warnings
            );
        }
    }

    #[test]
    fn parse_clamps_oversized_sketch_and_warns() {
        let l = Learning::parse_all(&cfg(
            "learning on;
             learning_memory_budget 1m;
             proxy_cache_learning big sketch=32m;",
        ));
        assert!(
            l.warnings.iter().any(|w| w.contains("单区硬顶")),
            "{:?}",
            l.warnings
        );
        assert!(
            l.warnings.iter().any(|w| w.contains("不会学习")),
            "申领 > 全局预算必须如实告警，实际 {:?}",
            l.warnings
        );
        // 运行期确实建不出图：返回 None 而不是撑破预算
        assert!(l.sketch_for("big", l.zone_wants_learning("big")).is_none());
        assert_eq!(l.budget.used(), 0);
    }

    #[test]
    fn budget_clamped_to_hard_ceiling() {
        let l = Learning::parse_all(&cfg("learning on; proxy_cache_learning z; learning_memory_budget 64m;"));
        assert_eq!(l.budget.total(), MAX_BUDGET, "超过硬顶要夹住");
        assert!(l.warnings.iter().any(|w| w.contains("超出可用范围")), "{:?}", l.warnings);
    }
}
