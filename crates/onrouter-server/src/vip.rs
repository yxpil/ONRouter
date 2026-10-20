//! 重要客户信誉（`vip_learning`）：用**已经算出来的限流判定结果**给每个客户端打一个信誉分，
//! 再把分数只用在两个地方——队列优先级与缓存驻留。
//!
//! 为什么不做成"VIP 名单"：名单是配置，不是学习。这里要的是**从流量里长出来**的判断：
//! 谁长期按速率老实请求，谁的分数就涨；谁把限流打出大量 429，谁的分数就掉。
//! 于是"重要客户"的定义是行为给的，不是 IP 段给的，运维也不需要预先知道谁会来。
//!
//! 内存：一张定长、直接映射的表（每 key 12 字节）。撞槽时**新来的认输**，不顶掉老住户
//! 攒下的分数（否则一个请求就能拆掉别人的信誉，见 `note`）；新 key 最坏是学不到分——
//! 而信誉**永远不是放行判定的一部分**，令牌桶与队列计数才是，所以顶多退回"非 VIP"。
//! 申领走进程级学习账本（[`crate::learning::Budget`]），领不到就整张表不存在，行为与没写本指令一致。
//!
//! 落点只有两个（刻意不做别的）：
//! - 队列：VIP key 跳过"陌生 key 先给下界"的冷启动惩罚，第一股突发就用满 `depth` 天花板。
//! - 缓存：VIP 请求写入的对象在频率草图里加权计数，因此更难被一次性流量挤掉（驻留）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::learning::Learning;

/// 一个 key 的信誉槽。`last_ms` 是进程启动以来的单调毫秒（与限流表同一时基）。
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// 非零 tag：哈希出 0 时抬到 1，避免与空槽混淆
    tag: u32,
    last_ms: u32,
    score: u8,
}

pub const SLOT_BYTES: usize = std::mem::size_of::<Slot>();

/// 单次"被拒绝"扣掉的信誉。取 8 是为了让一轮攻击（几十次 429）足以把任何分数打到 0，
/// 而偶发的一两次超限不至于立刻掉级。
pub const STRIKE: u8 = 8;
/// 一次"没超限、正常放行"加的分。
const CREDIT: u8 = 1;
/// 信誉分上限：只是计数器宽度，不代表"255 分比 24 分更重要"。
pub const MAX_SCORE: u8 = 255;

/// `vip_learning` 解析后的配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VipConfig {
    /// 表字节数（申领时还会夹到硬顶）
    pub table_bytes: usize,
    /// 晋升门槛：分数达到它才算 VIP
    pub min: u8,
    /// 静默多久掉 1 分（毫秒）：不再回来的客户会自动退级
    pub decay_ms: u64,
}

impl Default for VipConfig {
    fn default() -> Self {
        VipConfig {
            table_bytes: crate::learning::DEFAULT_VIP_BYTES,
            min: 24,
            decay_ms: 30_000,
        }
    }
}

/// 一次限流判定的结果——信誉只看这个，不看业务含义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 令牌够用，直接放行（唯一加分的结果）
    Passed,
    /// 排上了队：它已经超速了，不算功劳也不算过错
    Queued,
    /// 被拒：超限的证据，扣分
    Rejected,
}

/// 进程级信誉表。
pub struct Vip {
    cfg: VipConfig,
    slots: Mutex<Vec<Slot>>,
    /// 实际申领到的字节（归还账本时用，必须与申领值一致）
    claimed: usize,
    ev_passed: AtomicU64,
    ev_queued: AtomicU64,
    ev_rejected: AtomicU64,
    ev_promoted: AtomicU64,
    ev_demoted: AtomicU64,
    /// 撞槽让路次数：有人想记录信誉，但槽里住着一个还有分的别人
    ev_collision: AtomicU64,
}

impl std::fmt::Debug for Vip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vip").field("cfg", &self.cfg).finish()
    }
}

fn tag_of(key: &str) -> u32 {
    crate::engine::murmur_hash2(key.as_bytes()).max(1)
}

impl Vip {
    /// 按配置建表并向进程级账本申领。领不到返回 None（= 本区不学信誉）。
    pub fn new(cfg: VipConfig, learning: &Learning) -> Option<Self> {
        // 申领值至少是一个最小草图，所以槽数下限永远用不上
        let granted = learning.claim_bytes(cfg.table_bytes, crate::learning::MAX_VIP_BYTES)?;
        let slots = granted / SLOT_BYTES;
        let held = slots * SLOT_BYTES;
        // 表按槽取整，实占可能小于申领数：把差额还回账本，别让预算只涨不跌
        if held < granted {
            learning.release_bytes(granted - held);
        }
        Some(Vip {
            // cfg 里保留的是"运维要的大小"：热重载靠它判断尺寸没变、不该重建表
            cfg,
            slots: Mutex::new(vec![
                Slot {
                    tag: 0,
                    last_ms: 0,
                    score: 0,
                };
                slots
            ]),
            claimed: held,
            ev_passed: AtomicU64::new(0),
            ev_queued: AtomicU64::new(0),
            ev_rejected: AtomicU64::new(0),
            ev_promoted: AtomicU64::new(0),
            ev_demoted: AtomicU64::new(0),
            ev_collision: AtomicU64::new(0),
        })
    }

    pub fn cfg(&self) -> VipConfig {
        self.cfg
    }

    /// 实占字节（按槽取整）：申领时就把取整差额还了回去，所以与 `claimed` 相等。
    pub fn bytes(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            * SLOT_BYTES
    }

    /// 申领给账本的字节：归还必须用这个数，否则账会越还越乱。
    pub fn claimed_bytes(&self) -> usize {
        self.claimed
    }

    /// 记一次限流判定结果。`now_ms` 由调用方给（单测要把时间捏在手里）。
    ///
    /// 撞槽的处理是刻意的"**新来的吃亏，老住户不动**"：直接映射表里谁能顶掉谁，
    /// 就等于谁能清零谁的信誉。攻击者只要挑一个与某 VIP 同槽的地址发一个请求，
    /// 就能把攒了很久的分数打回 0 并让它掉级（本轮审计 S12）。反过来让新 key 认输，
    /// 最坏只是这个 key 学不到信誉（= 非 VIP，行为与本指令未开启一致），不伤害任何人。
    /// 老住户彻底静默到 0 分之后，槽位照常可以易主，表不会被历史住户占死。
    pub fn note(&self, key: &str, outcome: Outcome, now_ms: i64) {
        let tag = tag_of(key);
        let now32 = now_ms.max(0) as u32;
        match outcome {
            Outcome::Passed => self.ev_passed.fetch_add(1, Ordering::Relaxed),
            Outcome::Queued => self.ev_queued.fetch_add(1, Ordering::Relaxed),
            Outcome::Rejected => self.ev_rejected.fetch_add(1, Ordering::Relaxed),
        };
        let mut g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let n = g.len();
        let s = &mut g[(tag as usize) % n];
        if s.tag != tag {
            if s.tag != 0 {
                // 老住户按已经静默的时长折算当前分数；还有分就不许顶
                let gap = now32.wrapping_sub(s.last_ms) as u64;
                let rested = s.score.saturating_sub((gap / self.cfg.decay_ms.max(1)) as u8);
                if rested > 0 {
                    self.ev_collision.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
            // 空槽，或住户已经衰减到 0 分：新 key 正常入住，本次结果照常计入
            *s = Slot {
                tag,
                last_ms: now32,
                score: 0,
            };
        }
        let gap = now32.wrapping_sub(s.last_ms) as u64;
        s.last_ms = now32;
        // 静默衰减：按"隔了多少个 decay_ms"扣分，不靠后台线程扫表
        let decay = (gap / self.cfg.decay_ms.max(1)) as u8;
        let before = s.score;
        let mut score = before.saturating_sub(decay);
        score = match outcome {
            Outcome::Passed => score.saturating_add(CREDIT).min(MAX_SCORE),
            Outcome::Queued => score,
            Outcome::Rejected => score.saturating_sub(STRIKE),
        };
        s.score = score;
        let min = self.cfg.min;
        if before < min && score >= min {
            self.ev_promoted.fetch_add(1, Ordering::Relaxed);
        } else if before >= min && score < min {
            self.ev_demoted.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 这个 key 现在算不算重要客户。空槽 / 撞槽（tag 不符）一律算"不算"。
    pub fn is_vip(&self, key: &str) -> bool {
        let tag = tag_of(key);
        let g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let s = &g[(tag as usize) % g.len()];
        s.tag == tag && s.score >= self.cfg.min
    }

    /// 当前分数（单测用；不 VIP 也如实给出）。看板走 `snapshot()` 的聚合值。
    #[cfg(test)]
    pub fn score(&self, key: &str) -> u8 {
        let tag = tag_of(key);
        let g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let s = &g[(tag as usize) % g.len()];
        if s.tag == tag {
            s.score
        } else {
            0
        }
    }

    pub fn snapshot(&self) -> VipSnapshot {
        let g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let min = self.cfg.min;
        let mut used = 0usize;
        let mut vip_count = 0usize;
        let mut max_score = 0u8;
        for s in g.iter() {
            if s.tag != 0 {
                used += 1;
                if s.score >= min {
                    vip_count += 1;
                }
                max_score = max_score.max(s.score);
            }
        }
        VipSnapshot {
            min,
            decay_ms: self.cfg.decay_ms,
            table_bytes: g.len() * SLOT_BYTES,
            slots_used: used,
            slots_total: g.len(),
            vip_count,
            max_score,
            passed: self.ev_passed.load(Ordering::Relaxed),
            queued: self.ev_queued.load(Ordering::Relaxed),
            rejected: self.ev_rejected.load(Ordering::Relaxed),
            promoted: self.ev_promoted.load(Ordering::Relaxed),
            demoted: self.ev_demoted.load(Ordering::Relaxed),
            collision: self.ev_collision.load(Ordering::Relaxed),
        }
    }
}

/// `/metrics` 渲染用的一次快照。
#[derive(Debug, Clone, Copy)]
pub struct VipSnapshot {
    pub min: u8,
    pub decay_ms: u64,
    pub table_bytes: usize,
    pub slots_used: usize,
    pub slots_total: usize,
    pub vip_count: usize,
    pub max_score: u8,
    pub passed: u64,
    pub queued: u64,
    pub rejected: u64,
    pub promoted: u64,
    pub demoted: u64,
    /// 撞槽让路次数（新 key 想把信誉记到一个还有分的老住户槽位上，被拒）
    pub collision: u64,
}

/// 解析 `vip_learning [table=<size>] [min=<1..=255>] [decay=<duration>];`。
/// 参数写错不拒绝整个配置：逐条告警并改用默认值（与 `limit_req_queue` 同一口径）。
pub fn parse_vip_directive(d: &onrouter_config::Directive) -> (VipConfig, Vec<String>) {
    let mut cfg = VipConfig::default();
    let mut notes = Vec::new();
    // Directive 的 args 不含指令名本身
    for a in &d.args {
        if let Some(v) = a.strip_prefix("table=") {
            match crate::router::parse_size(v) {
                Some(n) if (n as usize) >= crate::learning::MIN_SKETCH_BYTES => {
                    cfg.table_bytes = n as usize;
                }
                Some(_) => notes.push(format!(
                    "vip_learning（第 {} 行）table='{v}' 小于 {} B，信誉表小到没有意义，改用默认 {} B",
                    d.line,
                    crate::learning::MIN_SKETCH_BYTES,
                    crate::learning::DEFAULT_VIP_BYTES
                )),
                None => notes.push(format!(
                    "vip_learning（第 {} 行）table='{v}' 不是长度写法（如 64k），已忽略",
                    d.line
                )),
            }
        } else if let Some(v) = a.strip_prefix("min=") {
            match v.parse::<u64>() {
                Ok(n) if (1..=MAX_SCORE as u64).contains(&n) => cfg.min = n as u8,
                Ok(n) => notes.push(format!(
                    "vip_learning（第 {} 行）min='{v}' 超出 1..{MAX_SCORE}（实际 {n}），改用默认 {}",
                    d.line, cfg.min
                )),
                Err(_) => notes.push(format!(
                    "vip_learning（第 {} 行）min='{v}' 不是整数，改用默认 {}",
                    d.line, cfg.min
                )),
            }
        } else if let Some(v) = a.strip_prefix("decay=") {
            match crate::settings::parse_duration(v) {
                Some(t) if t.as_millis() >= 1000 => cfg.decay_ms = t.as_millis() as u64,
                Some(t) => notes.push(format!(
                    "vip_learning（第 {} 行）decay='{v}'（{}ms）短于 1s：衰减会把信誉当噪声抹平，改用默认 {}ms",
                    d.line,
                    t.as_millis(),
                    cfg.decay_ms
                )),
                None => notes.push(format!(
                    "vip_learning（第 {} 行）decay='{v}' 不是时长写法（需形如 30s / 2m），改用默认 {}ms",
                    d.line, cfg.decay_ms
                )),
            }
        } else {
            notes.push(format!(
                "vip_learning（第 {} 行）不认识的参数 '{a}'（可用：table / min / decay），已忽略",
                d.line
            ));
        }
    }
    (cfg, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::Budget;
    use std::sync::Arc;

    fn vip(min: u8, decay_ms: u64) -> Arc<Vip> {
        let learning = Learning {
            enabled: true,
            budget: Arc::new(Budget::new(4 * crate::learning::MAX_VIP_BYTES)),
            ..Default::default()
        };
        let cfg = VipConfig {
            table_bytes: crate::learning::MIN_SKETCH_BYTES,
            min,
            decay_ms,
        };
        Arc::new(Vip::new(cfg, &learning).expect("预算够用，表该建起来"))
    }

    #[test]
    fn polite_traffic_is_promoted_and_flood_is_not() {
        let v = vip(8, 60_000);
        // 每 100ms 一个请求：都没超限，8 次后晋升
        for i in 0..8u64 {
            v.note("1.2.3.4", Outcome::Passed, (i * 100) as i64);
            assert_eq!(v.is_vip("1.2.3.4"), i >= 7, "第 {i} 次后的分数 {}", v.score("1.2.3.4"));
        }
        assert_eq!(v.snapshot().promoted, 1);
        // 攻击者同样打 8 个：一次都没加分，全是拒绝
        let a = vip(8, 60_000);
        for i in 0..8u64 {
            a.note("9.9.9.9", Outcome::Rejected, (i * 10) as i64);
        }
        assert_eq!(a.score("9.9.9.9"), 0);
        assert!(!a.is_vip("9.9.9.9"));
    }

    #[test]
    fn a_vip_that_starts_flooding_loses_the_status() {
        let v = vip(8, 60_000);
        for i in 0..20u64 {
            v.note("k", Outcome::Passed, (i * 100) as i64);
        }
        assert!(v.is_vip("k"));
        // 一轮洪水：每次拒绝扣 8，2 次就跌破门槛
        v.note("k", Outcome::Rejected, 3_000);
        v.note("k", Outcome::Rejected, 3_010);
        assert!(!v.is_vip("k"), "分数 {}", v.score("k"));
        assert_eq!(v.snapshot().demoted, 1);
    }

    #[test]
    fn queueing_neither_earns_nor_costs_reputation() {
        let v = vip(4, 60_000);
        for i in 0..10u64 {
            v.note("k", Outcome::Queued, (i * 100) as i64);
        }
        assert_eq!(v.score("k"), 0);
    }

    #[test]
    fn silence_decays_the_score() {
        let v = vip(4, 1_000);
        for i in 0..6u64 {
            v.note("k", Outcome::Passed, (i * 10) as i64);
        }
        assert_eq!(v.score("k"), 6);
        // 距上一次通过（t=50）静默整 5s 后再来一个：先扣 5 分，再加 1 分
        v.note("k", Outcome::Passed, 5_050);
        assert_eq!(v.score("k"), 2);
    }

    /// 找一个与 `key` 抢同一个槽的另一个 key（直接映射：tag % n 相同即可）。
    fn collides_with(v: &Arc<Vip>, key: &str) -> Option<String> {
        let n = v.slots.lock().unwrap().len();
        let want = (tag_of(key) as usize) % n;
        (0..1_000_000u32)
            .map(|i| format!("x{i}"))
            .find(|k| (tag_of(k) as usize) % n == want && tag_of(k) != tag_of(key))
    }

    /// S12：撞槽**不许**清零别人的信誉。否则任何人挑一个与某 VIP 同槽的地址发一个请求，
    /// 就能把攒了很久的分数打回 0、让它当场掉级——信誉表就此变成一个免费的去 VIP 开关。
    #[test]
    fn a_collision_never_wipes_an_incumbent_vip() {
        let v = vip(2, 10_000);
        v.note("a", Outcome::Passed, 0);
        v.note("a", Outcome::Passed, 10);
        assert!(v.is_vip("a"));
        let Some(other) = collides_with(&v, "a") else {
            // 找不到撞槽的 key：这条测试的前提不成立
            return;
        };
        v.note(&other, Outcome::Rejected, 20);
        assert_eq!(v.score("a"), 2, "老住户的分数一格不许动");
        assert!(v.is_vip("a"), "一个陌生地址的一个请求不该拆掉 VIP");
        assert_eq!(v.score(&other), 0, "认输的是新来的，也不给它编分数");
        assert_eq!(v.snapshot().collision, 1, "让路要留计数，看板才看得出表太挤");
    }

    /// 老住户彻底静默到 0 分之后，槽位照常可以易主——表不会被历史住户占死。
    #[test]
    fn a_fully_decayed_incumbent_relinquishes_the_slot() {
        let v = vip(2, 1_000);
        v.note("a", Outcome::Passed, 0);
        v.note("a", Outcome::Passed, 10);
        assert!(v.is_vip("a"), "两分正好够门槛 {}", v.score("a"));
        let Some(other) = collides_with(&v, "a") else {
            return;
        };
        // 2 分要静默 2s 才掉光；隔 5s 再来，槽位已经是无主的
        v.note(&other, Outcome::Passed, 5_000);
        assert_eq!(v.score(&other), 1, "新住户正常入住并开始攒分");
        assert_eq!(v.snapshot().collision, 0, "衰减到位的槽位不算让路");
    }

    #[test]
    fn table_claims_and_releases_follow_the_ledger() {
        let budget = Arc::new(Budget::new(crate::learning::DEFAULT_VIP_BYTES));
        let learning = Learning {
            enabled: true,
            budget: Arc::clone(&budget),
            ..Default::default()
        };
        let v = Vip::new(VipConfig::default(), &learning).expect("默认表正好占满预算");
        assert_eq!(budget.used(), v.claimed_bytes());
        assert_eq!(v.bytes(), v.claimed_bytes(), "按槽取整的差额要还给账本：记的就是实占");
        learning.release_bytes(v.claimed_bytes());
        assert_eq!(budget.used(), 0);
        // 预算不够时不建表：调用方据此把"没学信誉"如实反映到看板上
        let tight = Learning {
            enabled: true,
            budget: Arc::new(Budget::new(crate::learning::MIN_SKETCH_BYTES - 1)),
            ..Default::default()
        };
        assert!(Vip::new(VipConfig::default(), &tight).is_none());
    }

    /// 指令解析吃的是真实配置树：`args` 不含指令名，逐个参数都要读到，
    /// 写错的参数只告警并退回默认值，不能让整份配置失效。
    #[test]
    fn directive_parses_every_parameter_and_warns_instead_of_failing() {
        let cfg = onrouter_config::Config::parse(
            "learning on; vip_learning table=16k min=9 decay=2m;",
        )
        .unwrap();
        let l = Learning::parse_all(&cfg);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let v = l.vip_cfg().expect("声明了就要解析出来");
        assert_eq!(
            (v.table_bytes, v.min, v.decay_ms),
            (16 * 1024, 9, 120_000),
            "table/min/decay 三个参数都要真的生效"
        );

        let bad = onrouter_config::Config::parse(
            "learning on; vip_learning table=8 decay=500ms min=900 nope=1;",
        )
        .unwrap();
        let l = Learning::parse_all(&bad);
        assert_eq!(l.warnings.len(), 4, "{:?}", l.warnings);
        let def = VipConfig::default();
        let v = l.vip_cfg().unwrap();
        assert_eq!(
            (v.table_bytes, v.min, v.decay_ms),
            (def.table_bytes, def.min, def.decay_ms),
            "每个坏参数都只该让自己退回默认值"
        );
        // 没写 vip_learning 时完全不学信誉：一条行为变化都不许有
        let none = Learning::parse_all(&onrouter_config::Config::parse("learning on;").unwrap());
        assert!(none.vip_cfg().is_none());
    }
}
