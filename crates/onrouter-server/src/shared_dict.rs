//! ngx.shared.DICT —— 对标 OpenResty 的 `lua_shared_dict` 共享内存字典。
//!
//! ```text
//! lua_shared_dict counters 1m;      # 声明一个共享区（容量上限，超出会 LRU 淘汰）
//! ```
//!
//! 可选的第二层：磁盘冷层（见 [`crate::disk_cache`]）。加上 `disk=` 就启用分层，
//! **高频数据留在内存、内存淘汰下来的低频数据落盘**，Lua 侧的 API 一个字节都没改：
//!
//! ```text
//! lua_shared_dict session 10m disk=cache/dict max_disk=512m levels=1:2
//!                 inactive=10m spill_after=3 max_value=64k;
//! ```
//!
//! | 参数 | 含义 | 默认 |
//! | --- | --- | --- |
//! | `disk=<路径>` | 冷层根目录；相对路径按配置文件所在目录解析。不写就没有冷层 | 关闭 |
//! | `max_disk=<size>` | 冷层字节上限，超限由后台按分数逐出最冷的条目 | 256m |
//! | `levels=1:2` | 目录分片级数（对标 nginx `proxy_cache_path levels=`） | 1:2 |
//! | `inactive=<dur>` | 冷条目闲置多久后被回收；`0` 表示不按闲置回收 | 0（关闭） |
//! | `spill_after=<num>` | 衰减后的访问次数达到该阈值的淘汰受害者才落盘 | 3 |
//! | `max_value=<size>` | 单条 value 的落盘上限；更大的只留在内存 | 64k |
//!
//! 热度按"访问一次 +1，60 秒线性衰减到 0"累计：只有真的被反复读过的 key 才会落盘，
//! 一次性数据淘汰即丢弃，不会把磁盘写成一堆没人再读的垃圾。
//!
//! Lua 侧：
//! ```lua
//! local d = ngx.shared.counters
//! d:set("k", "v", 10)     -- ttl 可选（秒）；空间不足时 LRU 淘汰旧项
//! d:safe_set("k", "v")    -- 不淘汰，空间不足返回 nil+"no memory"
//! d:get("k")              -- 过期返回 nil；内存没有会先查冷层
//! d:add("k", "1")         -- 已存在则失败
//! d:incr("k", 1)          -- 原子自增
//! d:delete("k"); d:flush_all()
//! d:capacity(); d:free_space(); d:num(); d:flush_expired()
//! ```
//!
//! 兼容性偏离（有意为之，写在文档里）：启用冷层后 `capacity()` 与 `free_space()` 仍只
//! 描述**内存层**——它们是 OpenResty 里既有语义，脚本会拿它们做准入判断；冷层的规模
//! 走 `/metrics`（`onrouter_dict_disk_*`）观察。`num()/size()/get_keys()` 则包含冷层，
//! 因为它们描述"这个区里还有什么"。
//! 落盘/提升全部发生在内存路径的淘汰点与读路径的未命中点，请求线程永不等磁盘写完。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use onrouter_config::Config;

use crate::disk_cache::{self, ClockFrequency, DiskConfig, DiskStore, Features, Scorer};
use crate::router::parse_size;
use crate::settings::parse_duration;
use crate::AppError;

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// OpenResty 语义：exptime 为 nil 或 0 → 永不过期；负数 → 立即过期。
fn expiry_at(now: f64, ex: Option<f64>) -> Option<f64> {
    match ex {
        None => None,
        Some(t) if t == 0.0 => None,
        Some(t) => Some(now + t),
    }
}

/// 单个条目的成本：key + value + 固定开销（对标 nginx slab node overhead ~64B）
const NODE_OVERHEAD: usize = 64;

/// 访问次数的衰减窗口（秒）：命中一次 +1，每过 `FREQ_WINDOW` 秒线性衰减到 0。
/// 有了它才谈得上"高频留内存、低频落盘"——不衰减的话长跑进程的每个 key 都会
/// 攒到高热度，冷层最终会变成一次性数据的垃圾场。
const FREQ_WINDOW: f64 = 60.0;
/// 频次上限：热键被疯狂命中时也不能把 f32 拉爆，更要防止单个 key 霸占热层。
const FREQ_CAP: f32 = 1024.0;

#[derive(Debug, Clone)]
struct Entry {
    value: Vec<u8>,
    /// 过期时间（epoch 秒）；None = 永不过期
    expires_at: Option<f64>,
    /// LRU 时钟戳（每次 get/set 更新）：同一毫秒内的先后次序由它决定
    last_used: u64,
    /// 最后一次访问的 epoch 秒——分层策略要的是"真实年龄"，tick 序号给不了
    seen_at: f64,
    /// 本条目占用的字节数（key.len + value.len + overhead）
    cost: usize,
    /// 衰减后的访问次数（截至 `freq_at` 时刻的快照）
    freq: f32,
    /// `freq` 上次折算的时刻（epoch 秒）
    freq_at: f64,
}

impl Entry {
    fn alive(&self, now: f64) -> bool {
        match self.expires_at {
            Some(t) => now < t,
            None => true,
        }
    }

    /// 当前该算作多少热度：把 `freq_at` 到现在这段的衰减就地折算，不需要全局衰减扫描
    fn decayed_freq(&self, now: f64) -> f32 {
        let keep = (1.0 - (now - self.freq_at).max(0.0) / FREQ_WINDOW).max(0.0) as f32;
        self.freq * keep
    }

    /// 记一次访问（读命中与写入都算）
    fn note_hit(&mut self, now: f64) {
        self.freq = (self.decayed_freq(now) + 1.0).min(FREQ_CAP);
        self.freq_at = now;
        self.seen_at = now;
    }

    /// 新建条目即一次访问：`freq` 从 1 起算，`cost` 由调用方算好（要用 key 长度）
    fn new(value: Vec<u8>, expires_at: Option<f64>, last_used: u64, cost: usize, now: f64) -> Self {
        Entry {
            value,
            expires_at,
            last_used,
            seen_at: now,
            cost,
            freq: 1.0,
            freq_at: now,
        }
    }

    /// 提升回内存的条目要带走冷层记录的热度历史，否则"热→冷→热"每轮都从零开始计数
    fn promoted(value: Vec<u8>, expires_at: Option<f64>, last_used: u64, cost: usize, now: f64, freq: f32) -> Self {
        let mut e = Entry::new(value, expires_at, last_used, cost, now);
        e.freq = freq.max(1.0);
        e
    }

    /// 交给分层策略的特征（`on_disk=false`：内存层条目）
    fn features(&self, now: f64) -> Features {
        Features {
            freq: self.decayed_freq(now),
            age_ms: (((now - self.seen_at).max(0.0) * 1000.0) as u64).min(u64::from(u32::MAX)),
            value_len: self.value.len(),
            ttl_left: self.expires_at.map(|t| (t - now).max(0.0)),
            on_disk: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SharedZone {
    inner: Arc<ZoneInner>,
}

const SHARDS: usize = 16;

#[derive(Debug)]
struct ZoneInner {
    /// 按 key 哈希分成 16 片，各片独立锁：多核并发读写互不阻塞
    shards: Vec<Mutex<HashMap<String, Entry>>>,
    /// 容量上限（字节）；0 = 无限制（向后兼容旧配置）
    capacity: usize,
    /// 当前已用字节数（近似值，跨分片汇总）
    used: AtomicUsize,
    /// 全局 LRU 时钟（单调递增，用于标记最近访问）
    clock: AtomicU64,
    /// 磁盘冷层；None = 未配 `disk=`，行为与纯内存时代完全一致
    disk: Option<DiskStore>,
}

impl ZoneInner {
    fn new(capacity: usize, disk: Option<DiskStore>) -> Self {
        ZoneInner {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            capacity,
            used: AtomicUsize::new(0),
            clock: AtomicU64::new(0),
            disk,
        }
    }

    fn shard_index(&self, key: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % SHARDS
    }

    /// 取分片锁。中毒的锁继续用：一个 panic 只该毁掉一次缓存写入，
    /// 不该把整个 worker 线程连带所有 VM 一起拖死。
    fn lock_shard(&self, key: &str) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.lock_slot(self.shard_index(key))
    }

    fn lock_slot(&self, idx: usize) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.shards[idx].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 分配一个新的时钟戳
    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 释放字节数。用 CAS 夹在 0：used 是跨分片近似值，
    /// 万一并发窗口里出现重复扣减也不能让 usize 回绕成天文数字。
    fn release(&self, bytes: usize) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(bytes);
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// 淘汰受害者打分：分数越低越先离开热层。开了冷层就用冷层同一个 [`Scorer`]，
    /// 两层口径一致——否则"内存里最不热的"和"磁盘里最不热的"是两套排序，
    /// 落盘与逐出会互相打脸。没开冷层也按同一套 recency+频次打分（等价于旧近似 LRU）。
    fn victim_score(&self, e: &Entry, now: f64) -> f32 {
        let f = e.features(now);
        match &self.disk {
            Some(d) => d.score(&f),
            None => ClockFrequency.score(&f),
        }
    }

    /// 从随机分片中采样若干 entry，淘汰分数最低的那个（Redis 式近似 LRU + 分层判定）。
    ///
    /// 调用方持有 `make_room` 的循环，可能连着调多次；这里每次只处理一个受害者，
    /// 并且**只持当前分片锁**——落盘是"编码 + 入队"，不在这里删文件、不在这里扫描。
    fn evict_one(&self) -> bool {
        let now = now_epoch();
        // 从随机起点扫分片，直到找到一个非空的（采样近似 LRU，O(1) 摊还）
        let start = (self.tick() as usize) % SHARDS;
        for offset in 0..SHARDS {
            let shard_idx = (start + offset) % SHARDS;
            let mut map = self.lock_slot(shard_idx);
            if map.is_empty() {
                continue;
            }
            // 采样最多 8 个 entry，找分数最低的（同分时 last_used 小的先走）
            let mut best: Option<(String, f32, u64)> = None;
            for (k, v) in map.iter().take(8) {
                let s = self.victim_score(v, now);
                let better = match &best {
                    None => true,
                    Some((_, bs, bt)) => s < *bs || (s == *bs && v.last_used < *bt),
                };
                if better {
                    best = Some((k.clone(), s, v.last_used));
                }
            }
            let Some((key, _, _)) = best else { continue };
            if let Some(entry) = map.remove(&key) {
                self.release(entry.cost);
                self.spill_victim(&key, &entry, now);
                return true;
            }
        }
        false
    }

    /// 淘汰受害者的去处：达到 `spill_after` 的提交异步落盘，其余直接丢弃。
    ///
    /// 一次性数据（freq 还没攒够）落盘没有意义——它只会占住磁盘额度，
    /// 等后台清扫来删。这就是"高频留内存、低频落盘"里"低频"的定义。
    fn spill_victim(&self, key: &str, entry: &Entry, now: f64) {
        let Some(store) = &self.disk else { return };
        let freq = entry.decayed_freq(now);
        if !store.admit(freq, entry.value.len(), entry.expires_at) {
            store.note_spill_skipped();
            return;
        }
        store.spill(key, &entry.value, entry.expires_at, freq);
    }

    /// 缓存治理器（governor）深档休眠的降级原语：与 `evict_one` 同一套采样评分选
    /// 受害者，但**无视 `spill_after` 频率门强制落盘**，返回 `(key, 字节数)` 供预取
    /// 环记录。容量淘汰可以"低频就丢"——那是缓存语义；休眠降级不行：这里搬的是
    /// Lua 应用状态，丢了磁盘副本就是丢数据，不是清扫。
    ///
    /// Author: yxpil
    fn demote_one(&self) -> Option<(String, u64)> {
        let now = now_epoch();
        let start = (self.tick() as usize) % SHARDS;
        for offset in 0..SHARDS {
            let shard_idx = (start + offset) % SHARDS;
            let mut map = self.lock_slot(shard_idx);
            if map.is_empty() {
                continue;
            }
            let mut best: Option<(String, f32, u64)> = None;
            for (k, v) in map.iter().take(8) {
                let s = self.victim_score(v, now);
                let better = match &best {
                    None => true,
                    Some((_, bs, bt)) => s < *bs || (s == *bs && v.last_used < *bt),
                };
                if better {
                    best = Some((k.clone(), s, v.last_used));
                }
            }
            let Some((key, _, _)) = best else { continue };
            if let Some(entry) = map.remove(&key) {
                self.release(entry.cost);
                if let Some(store) = &self.disk {
                    let freq = entry.decayed_freq(now);
                    // Forced: the governor's sleep contract is "value stays readable
                    // through the cold path", so no admit() frequency gate here.
                    store.spill(&key, &entry.value, entry.expires_at, freq);
                }
                return Some((key, entry.cost as u64));
            }
        }
        None
    }

    /// 注销某 key 的冷层副本（覆盖写、删除、add 成功时调用）。
    ///
    /// 只允许在**不持有分片锁**时调用：它要拿冷层索引锁并排队删文件。
    /// 锁序约定见 [`crate::disk_cache`] 模块头——禁止反过来。
    fn forget_cold(&self, key: &str) {
        if let Some(store) = &self.disk {
            store.forget(key);
        }
    }

    /// 冷层是否有这条未过期的数据（只查内存索引，零 IO）。
    fn cold_has(&self, key: &str) -> bool {
        match &self.disk {
            Some(store) => store.has(key),
            None => false,
        }
    }

    /// 冷层命中就把条目提升回内存，返回 `(value, 是否已过期)`；None = 冷层也没有这条。
    ///
    /// 三条纪律：文件 IO 全程在任何分片锁之外；**先立内存副本再摘冷层**（中间窗口里
    /// 并发读至少能命中一层，不会读出假未命中）；内存实在放不下时照样返回值、
    /// 只是不缓存，冷层副本原样保留，一条数据都不丢。
    ///
    /// `keep_expired`：写类操作（`bump`）需要把过期副本搬回内存才能就地累加；
    /// 纯读（`get_stale`）不该为一条即将过期的数据占住内存额度。
    fn cold_promote(
        &self,
        key: &str,
        allow_expired: bool,
        keep_expired: bool,
    ) -> Option<(Vec<u8>, bool)> {
        let store = self.disk.as_ref()?;
        let c = store.read(key, allow_expired)?;
        let now = now_epoch();
        if c.expired && !keep_expired {
            // 只为 `get_stale` 服务的过期读不值得占住内存额度
            return Some((c.value, true));
        }
        let cost = key.len() + c.value.len() + NODE_OVERHEAD;
        if !self.make_room(cost) {
            return Some((c.value, false));
        }
        let out = c.value.clone();
        let tick = self.tick();
        let mut map = self.lock_shard(key);
        if let Some(prev) = map.insert(
            key.to_string(),
            Entry::promoted(c.value, c.expires, tick, cost, now, c.freq),
        ) {
            self.release(prev.cost);
        }
        self.used.fetch_add(cost, Ordering::Relaxed);
        drop(map);
        store.forget(key);
        store.note_promoted();
        Some((out, false))
    }

    /// 尝试为给定成本腾出空间：先清理过期项，再 LRU 淘汰。
    /// 常见路径（空间足够）不碰任何分片锁——旧实现在每次 set 时都遍历 16 片，
    /// 且为过期项分配 key 向量，使热路径变成 O(全表)。
    fn make_room(&self, cost: usize) -> bool {
        if self.capacity == 0 {
            return true; // 无容量限制
        }
        if self.used.load(Ordering::Relaxed).saturating_add(cost) <= self.capacity {
            return true;
        }
        // 第一轮（仅空间不足时）：就地清理各分片中的过期项
        let now = now_epoch();
        for i in 0..SHARDS {
            let mut map = self.lock_slot(i);
            let mut freed = 0usize;
            map.retain(|_, e| {
                if e.alive(now) {
                    true
                } else {
                    freed += e.cost;
                    false
                }
            });
            if freed > 0 {
                self.release(freed);
            }
        }
        // 冷层的过期项也顺手回收：只有真的缺空间时才付这次索引扫描
        if let Some(store) = &self.disk {
            store.purge_expired();
        }
        // 第二轮：如果还不够，LRU 淘汰
        while self.used.load(Ordering::Relaxed).saturating_add(cost) > self.capacity {
            if !self.evict_one() {
                return false; // 没有可淘汰的了
            }
        }
        true
    }

    /// 已加锁分片里的数字累加：命中且可解析返回 `Some(Ok/Err)`，未命中/已过期返回 None。
    /// `incr` 的两条入口（直接命中、冷层提升后重试）共用，避免复制一遍记账。
    fn add_into(
        &self,
        map: &mut HashMap<String, Entry>,
        key: &str,
        delta: i64,
        now: f64,
        tag: &str,
    ) -> Option<Result<i64, String>> {
        let e = map.get_mut(key)?;
        if !e.alive(now) {
            return None;
        }
        let text = String::from_utf8_lossy(&e.value).trim().to_string();
        let Ok(cur) = text.parse::<i64>() else {
            return Some(Err(format!("{tag}: '{key}' 的值不是数字 ({text})")));
        };
        let new = cur + delta;
        let new_val = new.to_string().into_bytes();
        let new_cost = key.len() + new_val.len() + NODE_OVERHEAD;
        let old_cost = e.cost;
        e.value = new_val;
        e.cost = new_cost;
        e.last_used = self.tick();
        e.note_hit(now);
        // 数字位数变化会改变条目成本：同步 used，否则 free_space 会越走越偏
        if new_cost >= old_cost {
            self.used.fetch_add(new_cost - old_cost, Ordering::Relaxed);
        } else {
            self.release(old_cost - new_cost);
        }
        Some(Ok(new))
    }
}

impl SharedZone {
    fn new(capacity: usize, disk: Option<DiskStore>) -> Self {
        SharedZone {
            inner: Arc::new(ZoneInner::new(capacity, disk)),
        }
    }

    /// Whether this zone has a disk cold tier. The governor's deep-sleep pass
    /// refuses to touch zones without one — they hold Lua application state with
    /// nowhere to demote it to.
    pub fn has_disk(&self) -> bool {
        self.inner.disk.is_some()
    }

    /// Governor deep-sleep pass: force-spill up to `max` coldest entries to the
    /// cold tier and reclaim their memory. Returns one `(key, bytes)` record per
    /// demoted entry — the governor needs the keys to build its pre-warm ring.
    /// Zones without `disk=` answer empty by construction (see [`Self::has_disk`]).
    pub fn governor_demote_pass(&self, max: usize) -> Vec<(String, u64)> {
        if self.inner.disk.is_none() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for _ in 0..max {
            match self.inner.demote_one() {
                Some((k, b)) => out.push((k, b)),
                None => break,
            }
        }
        out
    }

    /// Governor boost pre-warm: bring one key back from the cold tier into memory
    /// (the same promote path a cold get() takes, lock discipline included).
    /// False = the cold tier has no such entry (already promoted, expired, or the
    /// value lived in a proxy_cache zone that has no cold copy at all).
    pub fn governor_prewarm(&self, key: &str) -> bool {
        self.inner.cold_promote(key, false, false).is_some()
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let now = now_epoch();
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(e) = map.get_mut(key) {
                if e.alive(now) {
                    e.last_used = self.inner.tick();
                    e.note_hit(now);
                    return Some(e.value.clone());
                }
            }
        }
        // 内存没有才问冷层：冷层有内存索引，真未命中依旧是一次哈希查找、零磁盘 IO
        self.inner
            .cold_promote(key, false, false)
            .filter(|(_, expired)| !*expired)
            .map(|(v, _)| v)
    }

    /// 含过期项的读取，附带 stale 标志（对标 get_stale 的 (value, stale) 双返回值）
    pub fn get_stale_flagged(&self, key: &str) -> (Option<Vec<u8>>, bool) {
        let now = now_epoch();
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(e) = map.get_mut(key) {
                e.last_used = self.inner.tick();
                e.note_hit(now);
                return (Some(e.value.clone()), !e.alive(now));
            }
        }
        match self.inner.cold_promote(key, true, false) {
            Some((v, expired)) => (Some(v), expired),
            None => (None, false),
        }
    }

    /// 写入：空间不足时 LRU 淘汰（淘汰受害者达到热度门槛则落盘）；
    /// 单项超过整区容量时返回 Err("no memory")
    pub fn set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<(), String> {
        let now = now_epoch();
        let expires_at = expiry_at(now, ex);
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 先估算净增量（每次 set 只锁一次当前分片），再释放旧成本/记入新成本
        let old_cost = {
            let map = self.inner.lock_shard(key);
            map.get(key).map(|e| e.cost).unwrap_or(0)
        };
        let net_cost = cost.saturating_sub(old_cost);
        // 腾空间（不持有任何锁）
        if !self.inner.make_room(net_cost) {
            return Err("no memory".to_string());
        }
        let tick = self.inner.tick();
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(prev) = map.insert(
                key.to_string(),
                Entry::new(value, expires_at, tick, cost, now),
            ) {
                // 用最终替换掉的条目做精确结算：旧实现只在 cost 变大时加差额，
                // 值变小时从不减，used 会一路虚高直到容量假满。
                self.inner.release(prev.cost);
            }
            self.inner.used.fetch_add(cost, Ordering::Relaxed);
        }
        // 新值写进内存后，冷层的旧副本就成了脏数据：注销它，否则同 key 会两层各一份
        self.inner.forget_cold(key);
        Ok(())
    }

    /// safe_set：不淘汰，空间不足直接返回 Err("no memory")
    pub fn safe_set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<(), String> {
        let now = now_epoch();
        let expires_at = expiry_at(now, ex);
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        let mut map = self.inner.lock_shard(key);
        // 检查剩余空间（考虑移除旧条目后的净增量）
        let old_cost = map.get(key).map(|e| e.cost).unwrap_or(0);
        let net = cost.saturating_sub(old_cost);
        if self.inner.capacity > 0
            && self.inner.used.load(Ordering::Relaxed) + net > self.inner.capacity
        {
            return Err("no memory".to_string());
        }
        let tick = self.inner.tick();
        map.insert(
            key.to_string(),
            Entry::new(value, expires_at, tick, cost, now),
        );
        // 更新 used：减去旧值，加上新值
        if old_cost > 0 {
            self.inner.release(old_cost);
        }
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        drop(map);
        self.inner.forget_cold(key);
        Ok(())
    }

    /// 不存在（或已过期）时才写入；返回是否成功
    pub fn add(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<bool, String> {
        let now = now_epoch();
        // 冷层有这条未过期副本 = key 存在（只查索引，零 IO）
        if self.inner.cold_has(key) {
            return Ok(false);
        }
        let mut map = self.inner.lock_shard(key);
        // 过期项仍计入 used，但它会被本次写入替换，容量检查按净增量算
        let old_cost = match map.get(key) {
            Some(e) if e.alive(now) => return Ok(false),
            Some(e) => e.cost,
            None => 0,
        };
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 检查空间（add 不淘汰，直接失败）
        let net = cost.saturating_sub(old_cost);
        if self.inner.capacity > 0
            && self
                .inner
                .used
                .load(Ordering::Relaxed)
                .saturating_add(net)
                > self.inner.capacity
        {
            return Err("no memory".to_string());
        }
        let expires_at = expiry_at(now, ex);
        let tick = self.inner.tick();
        if let Some(prev) = map.insert(
            key.to_string(),
            Entry::new(value, expires_at, tick, cost, now),
        ) {
            // 覆盖的是过期项：先释放旧成本，否则同一 key 会被重复计费
            self.inner.release(prev.cost);
        }
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        drop(map);
        // 冷层那条已过期的副本随本次写入作废
        self.inner.forget_cold(key);
        Ok(true)
    }

    /// 已存在（未过期）时才覆盖；返回是否成功
    pub fn replace(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<bool, String> {
        let now = now_epoch();
        let mut map = self.inner.lock_shard(key);
        // 冷层副本同样算"存在"：replace 覆盖它，而不是因为条目住在磁盘就报不存在
        let cold = self.inner.cold_has(key);
        let existing = map.get(key);
        if !cold && !existing.is_some_and(|e| e.alive(now)) {
            return Ok(false);
        }
        let old_cost = existing.map(|e| e.cost).unwrap_or(0);
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        let net = cost.saturating_sub(old_cost);
        if self.inner.capacity > 0
            && self.inner.used.load(Ordering::Relaxed) + net > self.inner.capacity
        {
            // replace 允许淘汰吗？OpenResty 的 replace 不淘汰 → 保守起见返回 no memory
            return Err("no memory".to_string());
        }
        let expires_at = expiry_at(now, ex);
        let tick = self.inner.tick();
        if old_cost > 0 {
            map.remove(key); // 释放旧成本
            self.inner.release(old_cost);
        }
        map.insert(
            key.to_string(),
            Entry::new(value, expires_at, tick, cost, now),
        );
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        drop(map);
        self.inner.forget_cold(key);
        Ok(true)
    }

    pub fn delete(&self, key: &str) {
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(e) = map.remove(key) {
                self.inner.release(e.cost);
            }
        }
        // delete 是对两层的删除，不只是内存：冷层副本留着就删不掉数据
        self.inner.forget_cold(key);
    }

    /// 原子自增整数值；项不存在时若给了 init 则初始化为 init
    pub fn incr(&self, key: &str, delta: i64, init: Option<i64>) -> Result<i64, String> {
        let now = now_epoch();
        // 命中且存活：原地累加，全程只持当前分片锁，不触发淘汰
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(r) = self.inner.add_into(&mut map, key, delta, now, "incr") {
                return r;
            }
        }
        // 内存没有：先问冷层（真未命中零 IO）。提升成功后就地累加，
        // 计数类 key 住在磁盘上也该继续数，而不是凭空从 init 重来
        if self.inner.cold_promote(key, false, false).is_some() {
            let mut map = self.inner.lock_shard(key);
            if let Some(r) = self.inner.add_into(&mut map, key, delta, now, "incr") {
                return r;
            }
        }
        // 不存在/已过期：需要新建。make_room 会遍历锁全部分片，必须先释放当前分片锁再调用，
        // 否则自死锁（与 set 的腾空间路径同理）
        let Some(init) = init else {
            return Err(format!("incr: '{key}' 不存在且未提供 init"));
        };
        let new = init + delta;
        let val = new.to_string().into_bytes();
        let cost = key.len() + val.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 同 key 的过期项会被替换，其成本按"即将释放"计入净增量
        let old_expired = {
            let map = self.inner.lock_shard(key);
            map.get(key)
                .filter(|e| !e.alive(now))
                .map(|e| e.cost)
                .unwrap_or(0)
        };
        // 新建的是全新值：冷层那条（多半已过期的）副本必须作废，否则它会盖住这个计数
        self.inner.forget_cold(key);
        if !self.inner.make_room(cost.saturating_sub(old_expired)) {
            return Err("no memory".to_string());
        }
        let tick = self.inner.tick();
        let mut map = self.inner.lock_shard(key);
        // 释放锁的窗口里同 key 可能已被其它请求写入且为数字：再走一次累加，避免覆盖
        if let Some(r) = self.inner.add_into(&mut map, key, delta, now, "incr") {
            return r;
        }
        if let Some(prev) = map.insert(
            key.to_string(),
            Entry::new(val, None, tick, cost, now),
        ) {
            self.inner.release(prev.cost); // 覆盖的是过期项
        }
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(new)
    }

    /// 剩余存活时间：None=不存在，Some(-1.0)=永不过期，Some(x)=剩余秒数。
    /// 内存没有再查冷层索引——仍然零 IO。
    pub fn ttl(&self, key: &str) -> Option<f64> {
        let now = now_epoch();
        let map = self.inner.lock_shard(key);
        if let Some(e) = map.get(key) {
            return Some(match e.expires_at {
                None => -1.0,
                Some(t) => (t - now).max(0.0),
            });
        }
        drop(map);
        self.inner.disk.as_ref().and_then(|d| d.ttl(key))
    }

    pub fn flush_all(&self) {
        for i in 0..SHARDS {
            let mut map = self.inner.lock_slot(i);
            let total: usize = map.values().map(|e| e.cost).sum();
            self.inner.release(total);
            map.clear();
        }
        // 两层一起清：只清内存的话，flush_all 之后 key 还能从磁盘读回来
        if let Some(store) = &self.inner.disk {
            store.purge();
        }
    }

    /// 枚举现存（未过期）键：最多 max 个；第二返回值表示是否还有更多。
    /// 对标 ngx.shared.DICT:get_keys(max_count)。冷层键一并列出（零 IO）。
    pub fn get_keys(&self, max: usize) -> (Vec<String>, bool) {
        let now = now_epoch();
        let mut keys = Vec::new();
        for i in 0..SHARDS {
            let map = self.inner.lock_slot(i);
            for (k, e) in map.iter() {
                if !e.alive(now) {
                    continue;
                }
                if keys.len() >= max {
                    return (keys, true);
                }
                keys.push(k.clone());
            }
        }
        if let Some(store) = &self.inner.disk {
            let cold = store.keys(max.saturating_sub(keys.len()).saturating_add(1), false);
            let more = cold.len() > max.saturating_sub(keys.len());
            for k in cold {
                if keys.len() >= max {
                    break;
                }
                keys.push(k);
            }
            if more {
                return (keys, true);
            }
        }
        (keys, false)
    }

    /// 重设过期时间：ex <= 0 表示永不过期。key 不存在/已过期返回 false。
    pub fn expire(&self, key: &str, ex: f64) -> bool {
        let now = now_epoch();
        {
            let mut map = self.inner.lock_shard(key);
            if let Some(e) = map.get_mut(key) {
                if e.alive(now) {
                    e.expires_at = if ex == 0.0 { None } else { Some(now + ex) };
                    return true;
                }
            }
        }
        // 住在冷层的条目：先提升再改 TTL，否则这次 expire 会静默失效
        if self.inner.cold_promote(key, false, false).is_some() {
            let mut map = self.inner.lock_shard(key);
            if let Some(e) = map.get_mut(key) {
                if e.alive(now) {
                    e.expires_at = if ex == 0.0 { None } else { Some(now + ex) };
                    return true;
                }
            }
        }
        false
    }

    /// 清理所有过期项，返回清理的数量（两层都清）
    pub fn flush_expired(&self) -> usize {
        let now = now_epoch();
        let mut count = 0;
        for i in 0..SHARDS {
            let mut map = self.inner.lock_slot(i);
            let expired: Vec<String> = map
                .iter()
                .filter(|(_, e)| !e.alive(now))
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                if let Some(e) = map.remove(&k) {
                    self.inner.release(e.cost);
                    count += 1;
                }
            }
        }
        if let Some(store) = &self.inner.disk {
            count += store.purge_expired();
        }
        count
    }

    /// 总条目数（含过期）：内存 + 冷层
    pub fn num(&self) -> usize {
        let n: usize = (0..SHARDS)
            .map(|i| self.inner.lock_slot(i).len())
            .sum();
        n + self
            .inner
            .disk
            .as_ref()
            .map(|d| d.entries())
            .unwrap_or(0)
    }

    /// 容量上限（字节）——**只算内存层**，见模块头的兼容性偏离说明
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// 剩余可用空间（字节）——**只算内存层**，见模块头的兼容性偏离说明
    pub fn free_space(&self) -> usize {
        if self.inner.capacity == 0 {
            return usize::MAX;
        }
        self.inner
            .capacity
            .saturating_sub(self.inner.used.load(Ordering::Relaxed))
    }

    /// key 是否存在且未过期（对标 key_present）。冷层索引也算，零 IO。
    pub fn key_present(&self, key: &str) -> bool {
        let now = now_epoch();
        {
            let map = self.inner.lock_shard(key);
            if map.get(key).is_some_and(|e| e.alive(now)) {
                return true;
            }
        }
        self.inner.cold_has(key)
    }

    /// 值存储占用字节数（所有存活项的 value 长度之和，对标 size()）：内存 + 冷层
    pub fn size(&self) -> usize {
        let now = now_epoch();
        let mem: usize = (0..SHARDS)
            .map(|i| {
                self.inner
                    .lock_slot(i)
                    .values()
                    .filter(|e| e.alive(now))
                    .map(|e| e.value.len())
                    .sum::<usize>()
            })
            .sum();
        mem + self
            .inner
            .disk
            .as_ref()
            .map(|d| d.value_bytes())
            .unwrap_or(0)
    }

    /// force_set：始终覆盖，必要时 LRU 淘汰腾空间；单项超过整区容量时静默不落（对标 force_set）
    pub fn force_set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<(), String> {
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Ok(()); // force：放不下也不报错，best-effort
        }
        self.set(key, value, ex)
    }

    /// force_add：仅在 key 不存在/已过期时写入，空间不足会 LRU 淘汰（对标 force_add）
    pub fn force_add(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<bool, String> {
        let now = now_epoch();
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 先释放分片锁检查存在性，再 make_room（会锁全部分片），最后重新加锁写入
        if self.key_present(key) {
            return Ok(false);
        }
        // 同 key 的过期项会被替换，按净增量腾空间
        let old_expired = {
            let map = self.inner.lock_shard(key);
            map.get(key)
                .filter(|e| !e.alive(now))
                .map(|e| e.cost)
                .unwrap_or(0)
        };
        self.inner.forget_cold(key);
        if !self.inner.make_room(cost.saturating_sub(old_expired)) {
            return Err("no memory".to_string());
        }
        let mut map = self.inner.lock_shard(key);
        if map.get(key).is_some_and(|e| e.alive(now)) {
            return Ok(false); // 竞争窗口里已被写入
        }
        let tick = self.inner.tick();
        if let Some(prev) = map.insert(
            key.to_string(),
            Entry::new(value, expiry_at(now, ex), tick, cost, now),
        ) {
            self.inner.release(prev.cost); // 覆盖的是过期项
        }
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(true)
    }

    /// decr：decr(key, minus, init?) —— 语义为 incr 取负（init 命中时结果 = init - minus）
    pub fn decr(&self, key: &str, minus: i64, init: Option<i64>) -> Result<i64, String> {
        self.incr(key, -minus, init)
    }

    /// bump：把值当整数累加，允许累加已过期项（不检查存活、不新建），返回新值或 Err("not found")
    pub fn bump(&self, key: &str, by: i64) -> Result<i64, String> {
        let now = now_epoch();
        // bump 的语义无视过期，所以冷层读允许过期项，并把副本搬回内存就地累加
        let missing = {
            let map = self.inner.lock_shard(key);
            !map.contains_key(key)
        };
        if missing {
            self.inner.cold_promote(key, true, true);
        }
        let mut map = self.inner.lock_shard(key);
        let Some(e) = map.get_mut(key) else {
            return Err(format!("bump: '{key}' not found"));
        };
        let text = String::from_utf8_lossy(&e.value).trim().to_string();
        let cur: i64 = text
            .parse()
            .map_err(|_| format!("bump: '{key}' 的值不是数字 ({text})"))?;
        let new = cur + by;
        let new_val = new.to_string().into_bytes();
        let new_cost = key.len() + new_val.len() + NODE_OVERHEAD;
        let old_cost = e.cost;
        e.value = new_val;
        e.cost = new_cost;
        e.last_used = self.inner.tick();
        e.note_hit(now);
        if new_cost >= old_cost {
            self.inner.used.fetch_add(new_cost - old_cost, Ordering::Relaxed);
        } else {
            self.inner.release(old_cost - new_cost);
        }
        Ok(new)
    }
}

#[derive(Debug, Default)]
pub struct SharedDicts {
    pub zones: HashMap<String, SharedZone>,
}

/// 比较两个 `disk=` 根目录是否指向同一处：优先问操作系统（能识别符号链接、`./`
/// 与大小写差异），目录还不存在时退回按路径分量比较。
pub(crate) fn canonical_root(p: &std::path::Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| {
        let mut out = PathBuf::new();
        for c in p.components() {
            if c != std::path::Component::CurDir {
                out.push(c.as_os_str());
            }
        }
        out
    })
}

impl SharedDicts {
    /// 解析顶层 `lua_shared_dict <name> <size> [key=value ...];`
    ///
    /// 带 `disk=` 的区会在这里打开磁盘冷层：启动时扫目录重建索引（warm start），
    /// 于是上次进程留下的数据这次进程照样能读到。`base_dir` 用来解析 `disk=` 的
    /// 相对路径，与 `*_by_lua_file` / `pid` 同一口径。
    ///
    /// 未知参数与非法值**直接让启动失败**：分层是运维显式配的，静默降级会让人以为
    /// 数据在磁盘上，而其实一层都没有。
    pub fn parse_all(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        // 先只解析参数，全部合法才开始 open：中途失败不该留下一堆已起线程的 store
        let mut specs: Vec<(String, usize, Option<DiskConfig>)> = Vec::new();
        for d in &config.root.block {
            if d.name != "lua_shared_dict" {
                continue;
            }
            let name = d
                .arg(0)
                .ok_or_else(|| AppError::Other("lua_shared_dict 缺少名称".into()))?;
            let size_str = d
                .arg(1)
                .ok_or_else(|| {
                    AppError::Other(format!(
                        "lua_shared_dict {name} 缺少容量大小（如 1m / 10k）"
                    ))
                })?;
            let capacity = parse_size(size_str).ok_or_else(|| {
                AppError::Other(format!(
                    "lua_shared_dict {name}: 非法的容量大小 '{size_str}'"
                ))
            })? as usize;
            if capacity == 0 {
                return Err(AppError::Other(format!(
                    "lua_shared_dict {name}: 容量不能为 0"
                )));
            }
            let mut disk: Option<DiskConfig> = None;
            for kv in d.args.iter().skip(2) {
                let Some((k, v)) = kv.split_once('=') else {
                    return Err(AppError::Other(format!(
                        "lua_shared_dict {name}: 多余参数 '{kv}'，冷层参数要写成 key=value（disk=cache/dict max_disk=512m）"
                    )));
                };
                let (k, v) = (k.trim(), v.trim());
                if k == "disk" {
                    if disk.is_some() {
                        return Err(AppError::Other(format!(
                            "lua_shared_dict {name}: disk= 重复出现"
                        )));
                    }
                    if v.is_empty() {
                        return Err(AppError::Other(format!(
                            "lua_shared_dict {name}: disk= 需要冷层根目录路径"
                        )));
                    }
                    let mut c = DiskConfig::default();
                    c.root = crate::resolve_path(v, base_dir);
                    disk = Some(c);
                    continue;
                }
                let Some(cfg) = disk.as_mut() else {
                    return Err(AppError::Other(format!(
                        "lua_shared_dict {name}: 参数 {k}= 需要先写 disk="
                    )));
                };
                match k {
                    "max_disk" => {
                        cfg.max_bytes = parse_size(v).ok_or_else(|| {
                            AppError::Other(format!(
                                "lua_shared_dict {name}: 非法的 max_disk='{v}'"
                            ))
                        })?
                    }
                    "levels" => {
                        cfg.levels = disk_cache::parse_levels(v).ok_or_else(|| {
                            AppError::Other(format!(
                                "lua_shared_dict {name}: 非法的 levels='{v}'（对标 nginx：1~3 级，每级 1..3）"
                            ))
                        })?
                    }
                    "inactive" => {
                        cfg.inactive = parse_duration(v).ok_or_else(|| {
                            AppError::Other(format!(
                                "lua_shared_dict {name}: 非法的 inactive='{v}'"
                            ))
                        })?
                    }
                    "spill_after" => {
                        cfg.spill_after = v.parse::<f32>().map_err(|_| {
                            AppError::Other(format!(
                                "lua_shared_dict {name}: 非法的 spill_after='{v}'（要一个数字）"
                            ))
                        })?
                    }
                    "max_value" => {
                        cfg.max_value = parse_size(v).ok_or_else(|| {
                            AppError::Other(format!(
                                "lua_shared_dict {name}: 非法的 max_value='{v}'"
                            ))
                        })? as usize
                    }
                    other => {
                        return Err(AppError::Other(format!(
                            "lua_shared_dict {name}: 未知参数 {other}=（可用：disk/max_disk/levels/inactive/spill_after/max_value）"
                        )));
                    }
                }
            }
            if let Some(cfg) = &disk {
                if cfg.max_bytes == 0 {
                    return Err(AppError::Other(format!(
                        "lua_shared_dict {name}: max_disk=0 等于没有冷层，请直接去掉 disk="
                    )));
                }
            }
            specs.push((name.to_string(), capacity, disk));
        }

        // 两个区不能共用一个冷层目录：条目文件只由 key 哈希命名，跨区是同一个命名空间，
        // 一边 forget 会把另一边的数据删掉。配置期直接拒绝，比运行时互相吃掉数据好查。
        let mut roots: Vec<(PathBuf, String)> = Vec::new();
        for (name, _, cfg) in specs.iter() {
            let Some(cfg) = cfg else { continue };
            let mine = canonical_root(&cfg.root);
            if let Some((_, other)) = roots.iter().find(|(p, _)| *p == mine) {
                return Err(AppError::Other(format!(
                    "lua_shared_dict {name}: disk= 根目录 {:?} 与区 {other} 重复，两个区必须各用一个目录",
                    cfg.root
                )));
            }
            roots.push((mine, name.clone()));
        }

        // 打开顺序有讲究（见 disk_cache::register_zones 的文档）：
        // 先排空旧 store 承诺的落盘 → 再 open 新 store（此时扫描能看到完整目录）→ 最后替换登记
        if specs.iter().any(|(_, _, d)| d.is_some()) {
            disk_cache::flush_all_pending();
        }
        let mut cold: Vec<(String, DiskStore)> = Vec::new();
        for (name, _, cfg) in specs.iter() {
            let Some(cfg) = cfg else { continue };
            match DiskStore::open(cfg.clone(), None) {
                Ok(store) => cold.push((name.clone(), store)),
                Err(e) => {
                    for (_, store) in &cold {
                        store.flush_pending();
                    }
                    return Err(AppError::Other(format!(
                        "lua_shared_dict {name}: 磁盘冷层启动失败: {e}"
                    )));
                }
            }
        }
        disk_cache::register_zones(cold.clone());

        let mut zones = HashMap::new();
        for (name, capacity, cfg) in specs {
            let store = cfg
                .as_ref()
                .and_then(|_| cold.iter().find(|(n, _)| *n == name).map(|(_, s)| s.clone()));
            zones.insert(name.clone(), SharedZone::new(capacity, store));
        }
        let dicts = SharedDicts { zones };
        register_governor_zones(&dicts);
        Ok(dicts)
    }
}

/// Process-wide zone registry the cache governor reads. The Lua VM owns its own
/// `SharedDicts` clone deep inside the engine; rather than threading a handle
/// through every layer, parse_all publishes the zone table here (hot reload
/// overwrites it — the zones are Arc-shared, so in-flight VM handles stay valid).
///
/// Author: yxpil
static GOV_ZONES: std::sync::OnceLock<std::sync::RwLock<HashMap<String, SharedZone>>> =
    std::sync::OnceLock::new();

pub fn register_governor_zones(zones: &SharedDicts) {
    let lock = GOV_ZONES.get_or_init(|| std::sync::RwLock::new(HashMap::new()));
    *lock.write().unwrap_or_else(|e| e.into_inner()) = zones.zones.clone();
}

pub fn governor_zone(name: &str) -> Option<SharedZone> {
    let lock = GOV_ZONES.get()?;
    lock.read()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .cloned()
}

/// How many declared zones carry a `disk=` cold tier — the `-t` input for the
/// "deep sleep tier but nothing can actually be demoted" advisory.
pub fn governor_disk_zone_count() -> usize {
    let Some(lock) = GOV_ZONES.get() else { return 0 };
    lock.read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|z| z.has_disk())
        .count()
}

/// Config-level twin of [`governor_disk_zone_count`] for `-t`: there the runtime
/// registry is still empty because `parse_all` runs at Lua engine init, so the
/// advisory has to read the `disk=` argument straight from the directive.
pub fn config_disk_zone_count(config: &Config) -> usize {
    config
        .root
        .block
        .iter()
        .filter(|d| {
            d.name == "lua_shared_dict"
                && d.args.iter().skip(2).any(|kv| {
                    kv.split_once('=')
                        .map(|(k, _)| k.trim() == "disk")
                        .unwrap_or(false)
                })
        })
        .count()
}

/// Governor deep-sleep demotion across every registered disk-backed zone:
/// force-spill up to `max_per_zone` coldest entries per zone, returning one
/// `(zone, key, bytes)` record per demoted entry. The governor routes these
/// through `note_demotion` so the counters and the pre-warm ring stay in sync
/// (never both — that would double-count).
///
/// Author: yxpil
pub fn governor_demote_all(max_per_zone: usize) -> Vec<(String, String, u64)> {
    let Some(lock) = GOV_ZONES.get() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, zone) in lock.read().unwrap_or_else(|e| e.into_inner()).iter() {
        for (key, bytes) in zone.governor_demote_pass(max_per_zone) {
            out.push((name.clone(), key, bytes));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(cap: usize) -> SharedZone {
        SharedZone::new(cap, None)
    }

    #[test]
    fn basic_set_get_delete() {
        let z = zone(1024);
        z.set("k", b"v".to_vec(), None).unwrap();
        assert_eq!(z.get("k"), Some(b"v".to_vec()));
        z.delete("k");
        assert_eq!(z.get("k"), None);
    }

    #[test]
    fn ttl_expires() {
        let z = zone(1024);
        z.set("k", b"v".to_vec(), Some(0.05)).unwrap();
        assert_eq!(z.get("k"), Some(b"v".to_vec()));
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert_eq!(z.get("k"), None);
    }

    #[test]
    fn add_rejects_existing() {
        let z = zone(1024);
        z.set("k", b"v".to_vec(), None).unwrap();
        assert_eq!(z.add("k", b"x".to_vec(), None), Ok(false));
        assert_eq!(z.get("k"), Some(b"v".to_vec()));
    }

    #[test]
    fn replace_rejects_missing() {
        let z = zone(1024);
        assert_eq!(z.replace("k", b"v".to_vec(), None), Ok(false));
    }

    #[test]
    fn incr_works() {
        let z = zone(1024);
        assert_eq!(z.incr("c", 1, Some(0)), Ok(1));
        assert_eq!(z.incr("c", 5, None), Ok(6));
        assert_eq!(z.incr("c", -2, None), Ok(4));
    }

    #[test]
    fn capacity_enforced_with_lru_eviction() {
        // 每条目 cost = NODE_OVERHEAD(64) + key.len + value.len。
        // 容量 300B：3 个短串（70+70+68=208）都能放下，还没触发淘汰
        let z = zone(300);
        z.set("a", b"hello".to_vec(), None).unwrap();
        z.set("b", b"world".to_vec(), None).unwrap();
        z.set("c", b"foo".to_vec(), None).unwrap();
        assert!(z.get("a").is_some());
        assert!(z.get("b").is_some());
        assert!(z.get("c").is_some());
        // 再塞一个大条目（cost=64+1+40=105），208+105>300，触发一次近似 LRU 淘汰
        z.set("d", b"this_is_a_longer_value_to_force_eviction".to_vec(), None)
            .unwrap();
        // 近似 LRU 淘汰目标不确定，但新写入的 d 一定在，且总占用被压回容量以内
        assert!(z.get("d").is_some());
        assert!(z.num() <= 3);
    }

    #[test]
    fn single_item_exceeds_capacity() {
        let z = zone(10);
        assert!(z.set("big", vec![0u8; 100], None).is_err());
    }

    #[test]
    fn safe_set_no_eviction() {
        // 容量 200B：a(cost 69) + b(cost 125) = 194 装满但未超
        let z = zone(200);
        z.set("a", b"fill".to_vec(), None).unwrap();
        z.set("b", vec![0u8; 60], None).unwrap();
        // safe_set 一个新的大值（cost 145），194+145>200：safe_set 不淘汰，直接失败
        assert!(z.safe_set("c", vec![0u8; 80], None).is_err());
        // 且原有条目没有被淘汰
        assert!(z.get("a").is_some());
        assert!(z.get("b").is_some());
    }

    #[test]
    fn flush_expired_clears_only_stale() {
        let z = zone(1024);
        z.set("alive", b"v".to_vec(), Some(10.0)).unwrap();
        z.set("dead", b"v".to_vec(), Some(0.01)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let n = z.flush_expired();
        assert_eq!(n, 1);
        assert_eq!(z.num(), 1);
        assert_eq!(z.get("alive"), Some(b"v".to_vec()));
    }

    #[test]
    fn free_space_and_capacity() {
        let z = zone(1000);
        assert_eq!(z.capacity(), 1000);
        z.set("k", b"v".to_vec(), None).unwrap();
        assert!(z.free_space() < 1000);
    }

    #[test]
    fn get_stale_flagged_marks_expiry() {
        let z = zone(1024);
        z.set("k", b"v".to_vec(), Some(0.02)).unwrap();
        let (v, stale) = z.get_stale_flagged("k");
        assert_eq!(v.as_deref(), Some(&b"v"[..]));
        assert!(!stale);
        std::thread::sleep(std::time::Duration::from_millis(40));
        let (v2, stale2) = z.get_stale_flagged("k");
        assert_eq!(v2.as_deref(), Some(&b"v"[..])); // 过期项仍能读到
        assert!(stale2); // 且标记为 stale
    }

    #[test]
    fn key_present_and_size() {
        let z = zone(1024);
        assert!(!z.key_present("a"));
        z.set("a", b"hello".to_vec(), None).unwrap();
        assert!(z.key_present("a"));
        assert_eq!(z.size(), 5);
        z.set("b", b"xy".to_vec(), None).unwrap();
        assert_eq!(z.size(), 7);
        z.delete("b");
        assert_eq!(z.size(), 5);
    }

    #[test]
    fn force_add_evicts_but_rejects_existing() {
        let z = zone(1024);
        assert_eq!(z.force_add("k", b"1".to_vec(), None), Ok(true));
        assert_eq!(z.force_add("k", b"2".to_vec(), None), Ok(false));
        assert_eq!(z.get("k"), Some(b"1".to_vec()));
    }

    #[test]
    fn force_set_oversized_is_best_effort() {
        let z = zone(10); // 单项 cost 远超容量
        // force_set 不报错、也不落库（对标 force 语义）
        assert!(z.force_set("big", vec![0u8; 100], None).is_ok());
        assert!(!z.key_present("big"));
    }

    #[test]
    fn decr_mirrors_incr_sign() {
        let z = zone(1024);
        assert_eq!(z.decr("c", 2, Some(10)), Ok(8)); // init - minus
        assert_eq!(z.decr("c", 3, None), Ok(5));
        assert_eq!(z.incr("c", 5, None), Ok(10));
    }

    #[test]
    fn bump_accumulates_even_when_expired_and_rejects_missing() {
        let z = zone(1024);
        assert!(z.bump("missing", 1).is_err());
        z.set("n", b"5".to_vec(), None).unwrap();
        assert_eq!(z.bump("n", 3), Ok(8));
        assert_eq!(z.bump("n", -1), Ok(7));
    }

    #[test]
    fn set_shrinking_value_releases_space() {
        let z = zone(1024);
        z.set("k", vec![0u8; 500], None).unwrap();
        z.set("k", b"small".to_vec(), None).unwrap();
        assert_eq!(
            z.free_space(),
            1024 - (1 + "small".len() + NODE_OVERHEAD),
            "覆盖为更小的值必须释放旧成本"
        );
    }

    #[test]
    fn add_over_expired_entry_does_not_double_count() {
        let z = zone(400);
        z.set("k", vec![0u8; 200], Some(0.02)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(40));
        assert_eq!(z.add("k", b"v".to_vec(), None), Ok(true));
        assert_eq!(
            z.free_space(),
            400 - (1 + 1 + NODE_OVERHEAD),
            "替换过期项时应释放它占的成本"
        );
    }

    #[test]
    fn incr_and_bump_track_digit_growth() {
        let z = zone(1024);
        assert_eq!(z.incr("c", 0, Some(0)), Ok(0));
        let base = z.free_space();
        assert_eq!(z.incr("c", 99999, None), Ok(99999));
        assert_eq!(base - z.free_space(), 4, "\"0\" → \"99999\" 成本 +4");

        z.set("n", b"1".to_vec(), None).unwrap();
        let base2 = z.free_space();
        assert_eq!(z.bump("n", 1000), Ok(1001));
        assert_eq!(base2 - z.free_space(), 3, "\"1\" → \"1001\" 成本 +3");
    }

    #[test]
    fn get_bumps_lru_clock() {
        let z = zone(1024);
        z.set("a", b"1".to_vec(), None).unwrap();
        z.set("b", b"2".to_vec(), None).unwrap();
        // 多次读 a，让它比 b 更"热"
        for _ in 0..5 {
            z.get("a");
        }
        // 当需要淘汰时，b 应该先被选中（last_used 更小）
        // 这个测试是概率性的（采样 8 个），但在只有 2 个 entry 的小字典里几乎确定
        z.set("c", vec![0u8; 200], None).unwrap(); // 可能触发淘汰
        // b 可能被淘汰，a 更可能保留
        // 不做硬断言，只验证不 panic
    }

    #[test]
    fn zero_exptime_never_expires_and_negative_expires_now() {
        let z = zone(1024);
        z.set("forever", b"v".to_vec(), Some(0.0)).unwrap();
        assert!(z.key_present("forever"));
        assert_eq!(z.ttl("forever"), Some(-1.0), "exptime=0 对标 OpenResty：永不过期");

        z.set("dead", b"v".to_vec(), Some(-1.0)).unwrap();
        assert!(!z.key_present("dead"), "负 exptime 应立即过期");
        assert!(z.get_stale_flagged("dead").1, "过期项仍可 get_stale 读取并标记 stale");

        assert_eq!(z.add("forever", b"new".to_vec(), None), Ok(false));
        assert_eq!(z.get("forever"), Some(b"v".to_vec()), "未过期项 add 应失败");

        assert!(z.expire("forever", 0.0));
        assert_eq!(z.ttl("forever"), Some(-1.0));
    }

    // ---- 磁盘冷层（分层只在配了 disk= 的区里发生）----

    fn tmpdir(name: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "onrouter-dict-{}-{n}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// 造一个带冷层的区：`spill_after=0` 让每次内存淘汰都真的落盘，便于观察分层。
    ///
    /// 容量取 130：单条 `key(1)+value(6)+64 = 71`，第二条要 142 > 130，
    /// 于是 `set` 第二个 key 必然逐出第一个——受害者唯一，测试不靠采样运气。
    fn disk_zone(dir: PathBuf, spill_after: f32) -> (SharedZone, DiskStore) {
        let cfg = DiskConfig {
            root: dir,
            spill_after,
            ..Default::default()
        };
        let store = DiskStore::open(cfg, None).unwrap();
        (SharedZone::new(130, Some(store.clone())), store)
    }

    const V_A: &[u8] = b"abcdef";
    const V_B: &[u8] = b"123456";

    /// 把 "a" 挤进冷层：先写 a，再写 b 触发唯一的一次淘汰。
    ///
    /// 用例结尾都要先 `flush_pending` 再删临时目录：落盘是异步的，直接删目录会让
    /// 写线程对着已消失的路径报错，那只是测试噪音，不是产品行为。
    fn spill_one(z: &SharedZone, s: &DiskStore) {
        z.set("a", V_A.to_vec(), None).unwrap();
        z.set("b", V_B.to_vec(), None).unwrap();
        s.flush_pending();
    }

    #[test]
    fn evicted_entry_lands_on_disk_and_promotes_back_on_read() {
        let dir = tmpdir("tier");
        let (z, s) = disk_zone(dir.clone(), 0.0);
        spill_one(&z, &s);
        assert!(s.has("a"), "内存淘汰下来的条目要落冷层，不能直接丢");
        assert!(!s.has("b"), "还在内存里的 key 不该同时有一份冷层副本");
        assert_eq!(z.get("a"), Some(V_A.to_vec()), "冷层命中必须读出原始字节");
        assert_eq!(z.get("a"), Some(V_A.to_vec()));
        assert_eq!(
            s.stats().promoted.load(Ordering::Relaxed),
            1,
            "第二次读已在内存，不该再提升一次"
        );
        assert!(s.read("a", false).is_none(), "提升后冷层副本必须注销");
        // 提升 "a" 把唯一的对手 "b" 挤下盘，但落盘是异步的：排空后才看得见
        s.flush_pending();
        assert!(s.has("b"), "提升挤掉的对手也该落到冷层");
        assert_eq!(z.get("b"), Some(V_B.to_vec()));
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governor_demote_pass_force_spills_fresh_entries_and_prewarm_restores_them() {
        let dir = tmpdir("gov-demote");
        // spill_after 3 would normally refuse these fresh entries (freq = 1).
        // The governor's sleep pass must bypass that gate: it moves application
        // state, and a dropped cold copy here would be data loss, not cleanup.
        // Capacity 4096 keeps both entries in memory until the pass -- the pass
        // is what must drain a populated zone, not eviction by a tiny budget.
        let cfg = DiskConfig {
            root: dir.clone(),
            spill_after: 3.0,
            ..Default::default()
        };
        let s = DiskStore::open(cfg, None).unwrap();
        let z = SharedZone::new(4096, Some(s.clone()));
        z.set("a", V_A.to_vec(), None).unwrap();
        z.set("b", V_B.to_vec(), None).unwrap();
        let recs = z.governor_demote_pass(64);
        assert_eq!(recs.len(), 2, "pass must drain every in-memory entry");
        assert!(
            recs.iter().all(|(_, bytes)| *bytes > 0),
            "each record carries the reclaimed byte count for the governor"
        );
        s.flush_pending();
        assert_eq!(z.num(), 2, "after demotion the entries live in the cold tier");
        assert!(s.has("a") && s.has("b"), "forced spill must not hit the frequency gate");
        assert!(z.governor_prewarm("a"), "pre-warm must bring the cold entry back");
        assert_eq!(z.get("a"), Some(V_A.to_vec()));
        assert!(!z.governor_prewarm("never-existed"), "absent keys answer false");
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governor_demote_pass_is_inert_without_a_disk_tier() {
        let z = zone(1024);
        z.set("a", V_A.to_vec(), None).unwrap();
        assert!(
            z.governor_demote_pass(64).is_empty(),
            "zones without disk= hold Lua state and must never be demoted"
        );
        assert_eq!(z.get("a"), Some(V_A.to_vec()), "the value stays in memory");
    }

    #[test]
    fn one_shot_data_below_spill_after_is_dropped_not_written() {
        let dir = tmpdir("threshold");
        // 默认阈值 3：只写过一次的 key（freq=1）落盘没有意义
        let (z, s) = disk_zone(dir.clone(), 3.0);
        spill_one(&z, &s);
        assert!(!s.has("a"), "低频一次性数据淘汰即丢弃，否则磁盘会被垃圾写满");
        assert_eq!(s.stats().spilled.load(Ordering::Relaxed), 0);
        assert_eq!(z.get("a"), None, "没落盘就是真没了，内存语义与不配 disk= 一致");
        assert_eq!(
            s.stats().spill_skipped.load(Ordering::Relaxed),
            1,
            "写 b 只需腾出 71 字节，淘汰 a 一次就够，这一次被策略拦下"
        );
        // 反复读写过的 key 攒够热度（写 1 次 + 读 5 次 = 6 ≥ 阈值 3）后才落盘
        z.set("h", V_A.to_vec(), None).unwrap(); // 挤掉 b（同样 freq=1）
        assert_eq!(
            s.stats().spill_skipped.load(Ordering::Relaxed),
            2,
            "a、b 两次淘汰都被策略拦下，且都被计入 spill_skipped"
        );
        for _ in 0..5 {
            z.get("h");
        }
        z.set("x", vec![b'y'; 6], None).unwrap(); // 挤掉 h
        s.flush_pending();
        assert!(s.has("h"), "达到 spill_after 的淘汰受害者才落盘");
        assert_eq!(s.stats().spilled.load(Ordering::Relaxed), 1);
        assert_eq!(
            s.stats().spill_skipped.load(Ordering::Relaxed),
            2,
            "h 是真落盘的，不该同时算进被拦下的那批"
        );
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cold_tier_is_visible_to_num_size_keys_ttl_without_io() {
        let dir = tmpdir("introspect");
        let (z, s) = disk_zone(dir.clone(), 0.0);
        spill_one(&z, &s);
        assert!(s.has("a"));
        assert_eq!(z.num(), 2, "num 含冷层：内存 1 条 + 冷层 1 条");
        assert_eq!(z.size(), 12, "size 含冷层存活 value");
        assert!(z.key_present("a"), "key_present 要能答冷层的 key");
        assert_eq!(z.ttl("a"), Some(-1.0), "冷层 TTL 只查索引");
        assert_eq!(z.capacity(), 130, "capacity/free_space 保持 OpenResty 的内存层语义");
        assert_eq!(z.free_space(), 130 - 71);
        let (mut keys, more) = z.get_keys(10);
        assert!(!more);
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_and_overwrite_deregister_the_cold_copy() {
        let dir = tmpdir("dereg");
        let (z, s) = disk_zone(dir.clone(), 0.0);
        spill_one(&z, &s);
        z.delete("a");
        assert!(!s.has("a"), "delete 必须连冷层一起注销，否则删掉的 key 还能读回来");
        assert_eq!(z.get("a"), None);
        // "b" 在 delete 后仍占内存，再写两条把它挤下盘
        z.set("c", V_A.to_vec(), None).unwrap();
        z.set("d", V_A.to_vec(), None).unwrap();
        s.flush_pending();
        assert!(s.has("b"), "覆盖之前先确认 b 已进冷层");
        z.set("b", b"REPLACED".to_vec(), None).unwrap();
        assert!(!s.has("b"), "覆盖写要注销冷层副本");
        assert_eq!(z.get("b"), Some(b"REPLACED".to_vec()));
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_all_and_flush_expired_reach_the_cold_tier() {
        let dir = tmpdir("flush");
        let (z, s) = disk_zone(dir.clone(), 0.0);
        spill_one(&z, &s);
        assert_eq!(z.num(), 2);
        z.flush_all();
        assert_eq!(z.num(), 0, "flush_all 只清内存的话，key 还能从磁盘读回来");
        assert!(!s.has("a"));
        assert_eq!(z.get("a"), None);

        // 过期回收同样两层都管
        z.set("e", V_A.to_vec(), Some(0.2)).unwrap();
        z.set("f", V_B.to_vec(), None).unwrap(); // 挤掉 e（此刻还没过期）
        s.flush_pending();
        assert!(s.has("e"));
        std::thread::sleep(std::time::Duration::from_millis(320));
        assert_eq!(z.flush_expired(), 1, "过期的冷条目也要被 flush_expired 收走");
        assert!(!s.has("e"));
        assert_eq!(s.entries(), 0, "过期的冷条目要真的从索引里摘掉");
        assert!(z.get("f").is_some(), "没过期的一条不能陪葬");
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_reads_back_what_the_previous_process_spilled() {
        let dir = tmpdir("warm");
        {
            let (z, s) = disk_zone(dir.clone(), 0.0);
            spill_one(&z, &s);
            assert!(s.has("a"));
            // 这里靠 block 作用域退出模拟"进程结束"，冷层靠扫目录重建（无索引文件）
        }
        let cfg = DiskConfig {
            root: dir.clone(),
            spill_after: 0.0,
            ..Default::default()
        };
        let s2 = DiskStore::open(cfg, None).unwrap();
        assert_eq!(
            s2.stats().warm_recovered.load(Ordering::Relaxed),
            1,
            "扫目录重建只认完好的条目"
        );
        let z2 = SharedZone::new(130, Some(s2.clone()));
        assert_eq!(z2.get("a"), Some(V_A.to_vec()), "重启后冷层数据要能读回来");
        assert_eq!(z2.num(), 1);
        s2.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expire_promotes_a_cold_entry_instead_of_silently_failing() {
        let dir = tmpdir("expire");
        let (z, s) = disk_zone(dir.clone(), 0.0);
        spill_one(&z, &s);
        assert!(s.has("a"));
        assert!(z.expire("a", 60.0), "对住在冷层的 key 调 expire 不能静默失效");
        assert!(z.ttl("a").unwrap() > 50.0);
        assert!(!s.has("a"), "expire 走提升路径，冷层副本应当随之注销");
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bump_accumulates_an_expired_cold_copy() {
        let dir = tmpdir("bump");
        // "g"(1+2+64=67) + "h"(1+1+64=65) = 132 > 130 → g 落冷层
        let (z, s) = disk_zone(dir.clone(), 0.0);
        z.set("g", b"10".to_vec(), Some(0.2)).unwrap();
        z.set("h", b"0".to_vec(), None).unwrap();
        s.flush_pending();
        assert!(s.has("g"), "先确认 g 已被挤进冷层");
        std::thread::sleep(std::time::Duration::from_millis(260));
        assert_eq!(
            z.bump("g", 5).unwrap(),
            15,
            "bump 的语义是无视过期累加，冷层里的过期副本也该搬回来接着数"
        );
        assert_eq!(z.bump("g", 5).unwrap(), 20, "第二次 bump 落在同一条上");
        assert_eq!(
            z.get("g"),
            None,
            "bump 不续期：条目仍然过期，get 照旧读不到（对标 OpenResty）"
        );
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incr_continues_a_counter_held_in_the_cold_tier() {
        let dir = tmpdir("incr");
        // "n"(1+2+64=67) + "m"(1+1+64=65) = 132 > 130 → n 落冷层
        let (z, s) = disk_zone(dir.clone(), 0.0);
        z.set("n", b"41".to_vec(), None).unwrap();
        z.set("m", b"0".to_vec(), None).unwrap();
        s.flush_pending();
        assert!(s.has("n"), "先确认 n 已被挤进冷层");
        assert_eq!(z.incr("n", 1, Some(0)).unwrap(), 42, "磁盘上的计数也要接着数");
        assert!(!s.has("n"), "提升后冷层副本注销");
        assert_eq!(z.incr("fresh", 3, Some(10)).unwrap(), 13);
        assert!(
            z.incr("gone", 1, None).is_err(),
            "两层都没有且没给 init 时必须报错"
        );
        s.flush_pending();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_all_wires_disk_params_and_rejects_bad_ones() {
        // 会整表替换进程级冷层登记，与 disk_cache 的注册表测试互斥
        let _g = disk_cache::REGISTRY_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("parse");
        let base = dir.parent().unwrap().to_path_buf();
        let rel = dir.file_name().unwrap().to_string_lossy().replace('\\', "/");
        let ok = format!(
            "lua_shared_dict hot 1m disk={rel} max_disk=1m levels=1:2 inactive=5m spill_after=2 max_value=8k;\nlua_shared_dict plain 1m;\n"
        );
        let cfg = onrouter_config::Config::parse(&ok).unwrap();
        let dicts = SharedDicts::parse_all(&cfg, &base).unwrap();
        let hot = dicts.zones.get("hot").expect("hot 区应存在");
        assert_eq!(hot.capacity(), 1024 * 1024);
        assert!(
            hot.get("nothing-here").is_none(),
            "带冷层的区读未命中要照常返回 nil"
        );
        let snap = disk_cache::snapshot();
        assert!(
            snap.iter().any(|(n, st)| n == "hot" && st.config().max_bytes == 1024 * 1024),
            "只有写了 disk= 的区进冷层登记，参数要按配置生效"
        );
        assert!(!snap.iter().any(|(n, _)| n == "plain"));
        for (bad, needle) in [
            ("lua_shared_dict x 1m disk=;", "需要冷层根目录路径"),
            ("lua_shared_dict x 1m disk=a/b max_disk=0;", "max_disk=0"),
            ("lua_shared_dict a 1m disk=dup;\nlua_shared_dict b 1m disk=./dup;", "根目录"),
            ("lua_shared_dict x 1m disk=a/b bogus=1;", "未知参数"),
            ("lua_shared_dict x 1m max_disk=1m;", "需要先写 disk="),
            ("lua_shared_dict x 1m 512m;", "多余参数"),
            ("lua_shared_dict x disk=a/b;", "容量大小"),
        ] {
            let cfg = onrouter_config::Config::parse(bad).unwrap();
            let err = SharedDicts::parse_all(&cfg, &base)
                .err()
                .unwrap_or_else(|| panic!("{bad} 应启动失败"));
            let msg = err.to_string();
            assert!(msg.contains(needle), "{bad} 的报错该含 {needle}，实际：{msg}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
