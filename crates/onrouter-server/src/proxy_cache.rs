//! `proxy_cache`：反向代理响应缓存（对标 nginx ngx_http_proxy_cache_module）。
//!
//! 纯内存实现（不做磁盘持久化；`proxy_cache_path` 只取 `keys_zone` 容量用于 LRU，
//! 不建共享内存段），语义对齐 nginx 的常用子集：
//!   * `proxy_cache <zone>|off;`     —— 命中且未过期直接返回缓存，不再打后端
//!   * `proxy_cache_key <模板>;`      —— 默认 `$scheme$proxy_host$request_uri`
//!   * `proxy_cache_valid [码...] <时长>;` —— 哪些状态码缓存多久；`any` 兜底
//!   * `proxy_cache_methods GET HEAD;`—— 只缓存幂等方法
//!   * `proxy_cache_min_uses N;`      —— 同一 key 至少第 N 次请求才写入（默认 1）
//!   * `proxy_cache_lock on` + `proxy_cache_lock_timeout` —— 同 key 并发 MISS 只回源一次
//!   * `proxy_cache_use_stale error|timeout|updating|http_xxx` —— 失败/刷新中回放过期内容
//!   * `proxy_cache_bypass` / `proxy_no_cache` —— 按表达式跳过读取 / 跳过写入
//!   * `proxy_cache_path ... keys_zone=<名>:<容量>` —— 容量按 128 B/条换算，LRU 淘汰
//! 未写 `proxy_cache_valid` 时回落到上游的 `Cache-Control: max-age` / `Expires`；都没有则不缓存。
//!
//! 过期条目在内存里额外滞留 `STALE_GRACE`，供 `use_stale` 回放；之后由写入计数触发的
//! 清理逻辑释放（容量本身由 LRU 上限兜底）。
//! 有意未实现（README 已标注）：revalidation（If-None-Match 回源校验）、`purge`、Vary、
//! `proxy_cache_lock_age`、磁盘持久化。缓存响应统一带
//! `X-Cache-Status: HIT|MISS|EXPIRED|BYPASS|STALE` 头，便于外部验证。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

/// 一份可回放的缓存响应（body 已在内存，可被多个并发请求共享）。
pub struct CachedResponse {
    pub status: u16,
    /// 已剔除 hop-by-hop 与 Content-Length 的头（回发时按 body 长度重算 Content-Length）
    pub headers: Vec<(String, String)>,
    pub body: Arc<Bytes>,
}

struct Slot {
    resp: Arc<CachedResponse>,
    expires: Instant,
    /// 过期后仍保留到此时刻：期间可被 `proxy_cache_use_stale` 回放，
    /// 超过后由清理逻辑移除（内存缓存没有磁盘回退，必须给出明确的滞留上限）。
    stale_until: Instant,
    /// LRU 序号（每个 zone 内单调递增）
    tick: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHit {
    /// 命中且新鲜
    Hit,
    /// 命中但已过期（stale 滞留期内可被 `use_stale` 回放；否则回源重取）
    Expired,
    /// 无缓存条目
    Miss,
}

/// `/metrics` 逐区渲染的一行学习账目（区名已排序，保证两次抓取可比对）。
#[derive(Debug, Clone)]
pub struct LearningRow {
    pub zone: String,
    /// 本区申领到的草图字节；0 = 没在学
    pub sketch_bytes: usize,
    pub ages: u64,
    pub admission_rejected: u64,
    pub evicted_cold: u64,
    /// 替 VIP 写过并做过驻留加权的次数
    pub retained: u64,
}

struct Zone {
    entries: HashMap<String, Slot>,
    /// tick → key，用于 O(log n) 找出最久未使用的条目
    lru: BTreeMap<u64, String>,
    /// 每个 key 被请求过多少次（用于 min_uses）
    uses: HashMap<String, u32>,
    tick: u64,
    capacity: usize,
    stores: u64,
    /// 缓存学习：该区申领到的频率草图（None = 不学习，驱逐退回纯 LRU）。
    /// 大小与 key 数量无关，见 `learning.rs`。
    sketch: Option<crate::learning::Sketch>,
    /// 被准入闸门挡下的写入次数（对象太冷，不值得占位）
    admission_rejected: u64,
    /// 因为"比最老窗口里的邻居更冷"而被抢位驱逐的条目数
    evicted_cold: u64,
    /// 因请求者是 VIP 而做过驻留加权的写入次数
    retained: u64,
    /// 预算不足以给本区建图：只在**下一次重载**时重试，不在每个请求里重复申领
    /// （否则 `budget_denied` 会变成"每请求 +1"的噪声指标，白跑一串原子 CAS）。
    sketch_refused: bool,
}

impl Zone {
    fn new(capacity: usize) -> Self {
        Zone {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            uses: HashMap::new(),
            tick: 0,
            capacity,
            stores: 0,
            sketch: None,
            admission_rejected: 0,
            evicted_cold: 0,
            retained: 0,
            sketch_refused: false,
        }
    }

    /// 摘掉一个条目（同时从 LRU 索引里删掉）。
    fn remove(&mut self, key: &str) -> Option<Slot> {
        let s = self.entries.remove(key);
        if let Some(s) = &s {
            self.lru.remove(&s.tick);
        }
        s
    }

    /// 学习：在**最老的 `SCAN_WINDOW` 个**条目里找估计频率最低的一个（同频则取更老的）。
    ///
    /// 只扫常数个候选，所以选受害者的代价与容量无关——这正是 TinyLFU 本体的做法：
    /// 频率只用来"挑谁出局"，不用来给全表排序。
    fn coldest_in_window(&self) -> Option<(String, u8)> {
        let sk = self.sketch.as_ref()?;
        let mut best: Option<(u8, u64, &str)> = None;
        for (tick, key) in self.lru.iter().take(SCAN_WINDOW) {
            let f = sk.estimate(key);
            let replace = match best {
                None => true,
                Some((bf, bt, _)) => f < bf || (f == bf && *tick < bt),
            };
            if replace {
                best = Some((f, *tick, key.as_str()));
            }
        }
        best.map(|(f, _, key)| (key.to_string(), f))
    }
}

/// 学习驱逐时扫描的最老候选个数。8 个是 TinyLFU/SLRU 文献里常见的窗口，
/// 够躲开"刚进来一次的路过 key"，又把每次驱逐的额外开销钉在常数上。
const SCAN_WINDOW: usize = 8;

pub const DEFAULT_MAX_ENTRIES_PER_ZONE: usize = 4096;

/// 过期条目在内存中额外滞留的时长（供 use_stale 回放）；内存缓存没有磁盘层，
/// 超过后必须真正释放，否则被淘汰策略遗忘的 key 会永久占内存。
const STALE_GRACE: Duration = Duration::from_secs(3600);

pub struct ProxyCache {
    zones: Mutex<HashMap<String, Zone>>,
    /// `proxy_cache_path ... keys_zone=name:size` 换算出的每区条目上限
    capacities: Mutex<HashMap<String, usize>>,
    /// `proxy_cache_lock` 的每 key 异步互斥量：同 key 并发 MISS 只放一个请求回源
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// 缓存学习的配置与全局字节预算（默认关闭 → 所有学习路径短路）
    learning: Mutex<Arc<crate::learning::Learning>>,
}

impl ProxyCache {
    #[cfg(test)]
    fn new() -> Arc<Self> {
        Self::with_capacities(HashMap::new(), Arc::new(crate::learning::Learning::default()))
    }

    #[cfg(test)]
    /// 只给单测用：带学习的构造。
    fn learning(caps: HashMap<String, usize>, l: Arc<crate::learning::Learning>) -> Arc<Self> {
        Self::with_capacities(caps, l)
    }

    pub fn with_capacities(
        capacities: HashMap<String, usize>,
        learning: Arc<crate::learning::Learning>,
    ) -> Arc<Self> {
        Arc::new(ProxyCache {
            zones: Mutex::new(HashMap::new()),
            capacities: Mutex::new(capacities),
            locks: Mutex::new(HashMap::new()),
            learning: Mutex::new(learning),
        })
    }

    /// 当前生效的学习配置快照（取锁极短：只克隆 Arc）。
    /// 公开给热重载：队列侧与缓存侧共用**同一本进程级账本**，
    /// 而账本只在 `apply_learning` 里做过"旧账延续"，所以队列必须拿这份套用完的快照，
    /// 不能拿刚解析出来的那份（它带着一本从 0 开始记的新账）。
    pub fn learning_cfg(&self) -> Arc<crate::learning::Learning> {
        self.learning
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 热重载换上新的学习配置：逐区对齐——
    /// 新声明的区建图、被撤销的区放图并归还预算、大小变化的区**重建**草图
    /// （定长结构无法原地缩放，重建等于学习状态清零，这一点在 README 里如实写明）。
    ///
    /// 返回需要打进日志的说明（预算调小导致的强制放图、申领不到的区）；调用方负责打印，
    /// 这样本模块不依赖日志宏，单测也能断言降级确实发生。
    pub fn apply_learning(&self, mut next: crate::learning::Learning) -> Vec<String> {
        let mut notes = Vec::new();
        {
            let prev = self.learning_cfg();
            next.reuse_ledger(&prev.budget);
        }
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        for (name, z) in zones.iter_mut() {
            // 配置换了，允许本区重新申领一次（上次重载留下的"领不到"标记不作数）
            z.sketch_refused = false;
            let want = next.zone_wants_learning(name);
            match (z.sketch.is_some(), want) {
                (false, None) => {}
                (true, None) => {
                    let freed = z.sketch.take().map(|s| s.bytes()).unwrap_or(0);
                    next.budget.release(freed);
                }
                (_, Some(bytes)) => {
                    let current = z.sketch.as_ref().map(|s| s.bytes());
                    if current == Some(bytes) {
                        continue;
                    }
                    if let Some(old) = z.sketch.take() {
                        next.budget.release(old.bytes());
                    }
                    z.sketch = next.sketch_for(name, Some(bytes));
                    if z.sketch.is_none() {
                        z.sketch_refused = true;
                        notes.push(format!(
                            "缓存学习：区 '{name}' 需要 {bytes} B，预算不足（累计拒绝 {} 次申领），该区退回纯 LRU",
                            next.budget.denied()
                        ));
                    }
                }
            }
        }
        // 预算被调小：按"最大的草图先让位"收敛，直到账目不超过上限。
        // 宁可比配置多留一会儿，也不能让进程超出承诺的内存上限。
        let total = next.budget.total();
        if next.budget.used() > total {
            let mut biggest: Vec<(usize, String)> = zones
                .iter()
                .filter_map(|(n, z)| z.sketch.as_ref().map(|s| (s.bytes(), n.clone())))
                .collect();
            // 先让最大的草图放位：一次释放最多，收敛步数最少
            biggest.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            for (bytes, name) in biggest {
                if next.budget.used() <= total {
                    break;
                }
                if let Some(z) = zones.get_mut(&name) {
                    if z.sketch.take().is_some() {
                        next.budget.release(bytes);
                        // 标记为"本轮不再重试"：否则每个请求都会申领→失败→把拒绝计数刷成噪声
                        z.sketch_refused = true;
                        notes.push(format!(
                            "缓存学习：learning_memory_budget 已降到 {} B，放掉区 '{name}' 的 {} B 草图以守住上限，该区退回纯 LRU",
                            total, bytes
                        ));
                    }
                }
            }
        }
        drop(zones);
        *self.learning.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(next);
        notes
    }

    /// 按需给区挂上草图（第一次真正用到这个区时）。已挂过/不该学则原样返回。
    /// 返回是否处于学习状态，供调用方决定是否记账。
    ///
    /// 预算领不到只在**首次**尝试时发生：之后 `sketch_refused` 挡住重试，
    /// 免得每个请求都跑一次申领-失败并把 `budget_denied` 刷成无意义的天文数字。
    /// 想重试请改配置触发重载（那里会清掉标记）。
    fn ensure_sketch(&self, name: &str, z: &mut Zone) -> bool {
        if z.sketch.is_some() {
            return true;
        }
        if z.sketch_refused {
            return false;
        }
        let l = self.learning_cfg();
        let Some(bytes) = l.zone_wants_learning(name) else {
            return false;
        };
        z.sketch = l.sketch_for(name, Some(bytes));
        if z.sketch.is_none() {
            z.sketch_refused = true;
        }
        z.sketch.is_some()
    }

    /// 热重载时应用新的 keys_zone 容量：已有 zone 立即按新上限裁剪。
    pub fn apply_capacities(&self, capacities: &HashMap<String, usize>) {
        {
            let mut caps = self.capacities.lock().unwrap_or_else(|e| e.into_inner());
            *caps = capacities.clone();
        }
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        for (name, z) in zones.iter_mut() {
            z.capacity = capacities
                .get(name)
                .copied()
                .unwrap_or(DEFAULT_MAX_ENTRIES_PER_ZONE);
            Self::trim(z);
        }
    }

    fn capacity_for(&self, zone: &str) -> usize {
        self.capacities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(zone)
            .copied()
            .unwrap_or(DEFAULT_MAX_ENTRIES_PER_ZONE)
    }

    /// 查缓存并把该 key 的请求计数 +1（返回自增后的计数，用于 min_uses 判定）。
    /// 对 zone/key 做一次加锁即可完成「查 + 计数 + 刷新 LRU」，避免多次加锁间的竞态。
    pub fn lookup(&self, zone: &str, key: &str) -> (CacheHit, Option<Arc<CachedResponse>>, u32) {
        self.lookup_impl(zone, key, true)
    }

    /// 拿到 proxy_cache_lock 之后的二次检查：命中的话直接返回，且不重复累计 min_uses。
    pub fn peek(&self, zone: &str, key: &str) -> (CacheHit, Option<Arc<CachedResponse>>) {
        let (hit, resp, _) = self.lookup_impl(zone, key, false);
        (hit, resp)
    }

    fn lookup_impl(
        &self,
        zone: &str,
        key: &str,
        count_use: bool,
    ) -> (CacheHit, Option<Arc<CachedResponse>>, u32) {
        let now = Instant::now();
        let capacity = self.capacity_for(zone);
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = g
            .entry(zone.to_string())
            .or_insert_with(|| Zone::new(capacity));
        z.capacity = capacity;
        // 学习：先记账再判定——草图里的"这个 key 被访问过几次"是准入与驱逐的唯一依据，
        // 而它必须在写决策之前就是最新的（命中/过期/未命中都要算一次访问）。
        if self.ensure_sketch(zone, z) {
            if let Some(sk) = z.sketch.as_mut() {
                sk.note(key);
            }
        }
        let count = if count_use {
            let c = z.uses.entry(key.to_string()).or_insert(0);
            *c = c.saturating_add(1);
            *c
        } else {
            z.uses.get(key).copied().unwrap_or(0)
        };

        enum Kind {
            Fresh(Arc<CachedResponse>),
            Stale(Arc<CachedResponse>),
            Dead,
        }
        let kind = match z.entries.get(key) {
            Some(s) if s.expires > now => Kind::Fresh(s.resp.clone()),
            Some(s) if s.stale_until > now => Kind::Stale(s.resp.clone()),
            Some(_) => Kind::Dead,
            None => return (CacheHit::Miss, None, count),
        };
        match kind {
            Kind::Fresh(resp) => {
                Self::touch(z, key);
                (CacheHit::Hit, Some(resp), count)
            }
            Kind::Stale(resp) => {
                Self::touch(z, key);
                (CacheHit::Expired, Some(resp), count)
            }
            Kind::Dead => {
                if let Some(s) = z.entries.remove(key) {
                    z.lru.remove(&s.tick);
                }
                (CacheHit::Miss, None, count)
            }
        }
    }

    fn touch(z: &mut Zone, key: &str) {
        z.tick = z.tick.wrapping_add(1);
        let tick = z.tick;
        if let Some(s) = z.entries.get_mut(key) {
            z.lru.remove(&s.tick);
            s.tick = tick;
        }
        z.lru.insert(tick, key.to_string());
    }

    /// 仅累计 min_uses 计数（命中被 bypass 的请求仍需计数，才能与 nginx 的
    /// “第 N 次请求起写入缓存”语义一致）。
    pub fn note_use(&self, zone: &str, key: &str) -> u32 {
        let capacity = self.capacity_for(zone);
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = g
            .entry(zone.to_string())
            .or_insert_with(|| Zone::new(capacity));
        let c = z.uses.entry(key.to_string()).or_insert(0);
        *c = c.saturating_add(1);
        *c
    }

    /// 写入/覆盖一条缓存。ttl=0 视为不缓存。
    /// 转发路径按 `store_as()` 传 VIP 驻留标志，所以这个无 VIP 语义的入口只有测试在用。
    #[cfg(test)]
    pub fn store(&self, zone: &str, key: &str, resp: CachedResponse, ttl: Duration) {
        self.store_as(zone, key, resp, ttl, false);
    }

    /// VIP 驻留加权：一次额外计数的权重。刻意取小（草图上限 15）——
    /// 一次加权要敌得过几轮扫库噪声，但也不该让一个 VIP 的请求把整区钉死。
    pub const RETAIN_BOOST: u8 = 4;

    /// 与 `store()` 相同，但 `retain_vip` 表示这次写入是替一个学出来的重要客户做的：
    /// 对象在频率草图里加权计数，因此在后续准入/驱逐里更难被一次性流量挤掉。
    /// 加权只发生在**准入判定之后**，所以它买到的是"驻留"，不是"插队"。
    pub fn store_as(
        &self,
        zone: &str,
        key: &str,
        resp: CachedResponse,
        ttl: Duration,
        retain_vip: bool,
    ) {
        self.store_with_grace(zone, key, resp, ttl, STALE_GRACE, retain_vip);
    }

    fn store_with_grace(
        &self,
        zone: &str,
        key: &str,
        resp: CachedResponse,
        ttl: Duration,
        grace: Duration,
        retain_vip: bool,
    ) {
        if ttl.is_zero() {
            return;
        }
        let capacity = self.capacity_for(zone);
        let now = Instant::now();
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = g
            .entry(zone.to_string())
            .or_insert_with(|| Zone::new(capacity));
        z.capacity = capacity;
        // 学习：容量已满、且这是个**新** key（覆盖旧条目永远照写），先过准入闸门。
        // 判据只有一个：它在草图里的访问频次，够不够格挤掉最老窗口里最冷的那位。
        // 一次性 URL / 扫库流量因此进不了缓存，而 TTL 到期后的正常刷新不受影响。
        if self.ensure_sketch(zone, z)
            && !z.entries.contains_key(key)
            && z.entries.len() >= z.capacity
        {
            let cand = z.sketch.as_ref().map(|s| s.estimate(key)).unwrap_or(0);
            if let Some((victim, vf)) = z.coldest_in_window() {
                if vf >= cand {
                    // 不比现有最冷条目更热：这次响应只是路过，不给它腾地方
                    z.admission_rejected += 1;
                    return;
                }
                if z.remove(&victim).is_some() {
                    z.evicted_cold += 1;
                }
            }
        }
        z.remove(key);
        z.tick = z.tick.wrapping_add(1);
        let tick = z.tick;
        z.entries.insert(
            key.to_string(),
            Slot {
                resp: Arc::new(resp),
                expires: now + ttl,
                stale_until: now + ttl + grace,
                tick,
            },
        );
        z.lru.insert(tick, key.to_string());
        z.stores = z.stores.wrapping_add(1);
        // VIP 驻留：写进去之后才加权，因此它影响的是"这个对象往后多难被挤掉"，
        // 不影响本次写入能不能进得来（准入仍只看它自己的历史频次）。
        if retain_vip {
            if let Some(sk) = z.sketch.as_mut() {
                sk.note_weighted(key, Self::RETAIN_BOOST);
            }
            z.retained += 1;
        }
        if z.stores % 128 == 0 {
            Self::cleanup(z, now);
        }
        Self::trim(z);
    }

    /// 淘汰到容量上限：未学习时是纯 LRU（取最久未使用），学习开启时从最老窗口里
    /// 挑估计频率最低的那个——被访问得更勤的条目（包括 VIP 加权过的）更容易留下来。
    fn trim(z: &mut Zone) {
        while z.entries.len() > z.capacity {
            if z.sketch.is_some() {
                if let Some((victim, _)) = z.coldest_in_window() {
                    if z.remove(&victim).is_some() {
                        z.evicted_cold += 1;
                    }
                    continue;
                }
            }
            let Some((_, key)) = z.lru.pop_first() else {
                break;
            };
            z.entries.remove(&key);
        }
    }

    /// 清理超过 stale 滞留期的条目，并压缩无人再查询的 min_uses 计数。
    fn cleanup(z: &mut Zone, now: Instant) {
        let dead: Vec<(String, u64)> = z
            .entries
            .iter()
            .filter(|(_, s)| s.stale_until <= now)
            .map(|(k, s)| (k.clone(), s.tick))
            .collect();
        for (key, tick) in dead {
            z.entries.remove(&key);
            z.lru.remove(&tick);
        }
        let limit = z.capacity.saturating_mul(4).max(64);
        if z.uses.len() > limit {
            let entries = &z.entries;
            z.uses.retain(|k, _| entries.contains_key(k));
        }
    }

    /// 取得某个 key 的回源锁（Arc 便于跨 await 持有；空闲锁会在表过大时回收）。
    pub fn cache_lock(&self, zone: &str, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut g = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= 4096 {
            g.retain(|_, v| Arc::strong_count(v) > 1);
        }
        g.entry(format!("{zone}\u{0}{key}"))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// 主动失效一个 key（proxy_cache off/配置变更时可用），返回是否删除。
    #[allow(dead_code)]
    pub fn invalidate(&self, zone: &str, key: &str) -> bool {
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(z) = g.get_mut(zone) {
            z.uses.remove(key);
            if let Some(s) = z.entries.remove(key) {
                z.lru.remove(&s.tick);
                return true;
            }
        }
        false
    }

    /// `/metrics` 用：逐区的学习状态。没在学的区也要列出来（草图 0 字节），
    /// 运维看面板时才能发现"配了区却没学到"。
    pub fn learning_rows(&self) -> Vec<LearningRow> {
        let g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows: Vec<LearningRow> = g
            .iter()
            .map(|(name, z)| {
                let (bytes, ages) = z
                    .sketch
                    .as_ref()
                    .map(|s| (s.bytes(), s.ages()))
                    .unwrap_or((0, 0));
                LearningRow {
                    zone: name.clone(),
                    sketch_bytes: bytes,
                    ages,
                    admission_rejected: z.admission_rejected,
                    evicted_cold: z.evicted_cold,
                    retained: z.retained,
                }
            })
            .collect();
        rows.sort_by(|a, b| a.zone.cmp(&b.zone));
        rows
    }

    /// 全局学习账目：(是否启用, 已申领字节, 预算上限, 累计申领被拒次数)。
    pub fn learning_summary(&self) -> (bool, usize, usize, usize) {
        let l = self.learning_cfg();
        (l.enabled, l.used(), l.budget.total(), l.denied())
    }

    #[cfg(test)]
    fn len(&self, zone: &str) -> usize {
        self.zones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(zone)
            .map(|z| z.entries.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn force_expire(&self, zone: &str, key: &str, stale_for: Duration) {
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(z) = g.get_mut(zone) {
            if let Some(s) = z.entries.get_mut(key) {
                let now = Instant::now();
                s.expires = now;
                s.stale_until = now + stale_for;
            }
        }
    }
}

/// 从 `proxy_cache_valid` 规则里挑出匹配状态码的 TTL；`any` 作为兜底。
/// 规则形如 [("200", dur), ("301 302", dur), ("any", dur)]，已在 router 里按码拆分。
pub fn ttl_from_valid(valid: &[(Vec<String>, Duration)], status: u16) -> Option<Duration> {
    let s = status.to_string();
    let mut any: Option<Duration> = None;
    for (codes, dur) in valid {
        if codes.iter().any(|c| c == "any") {
            if any.is_none() {
                any = Some(*dur);
            }
            continue;
        }
        if codes.iter().any(|c| c == &s) {
            return Some(*dur);
        }
    }
    any
}

/// 上游显式缓存指示的三态。nginx 语义：响应自带的 Cache-Control/Expires 优先于
/// `proxy_cache_valid`；显式 `no-store/no-cache/private/max-age=0` 则拒绝缓存。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamDirective {
    /// 上游明确要求不缓存
    Forbid,
    /// 上游给出有效期
    Expire(Duration),
    /// 上游没有任何缓存提示
    NoHint,
}

/// 解析上游 `Cache-Control`/`Expires`。`Forbid` 覆盖一切；有 `max-age`/`Expires` 按其时长；
/// 都没有返回 `NoHint`（交由 `proxy_cache_valid` 决定）。
pub fn upstream_directive(headers: &[(String, String)], now_unix: i64) -> UpstreamDirective {
    let mut max_age: Option<i64> = None;
    let mut forbid = false;
    let mut expires: Option<i64> = None;
    let mut hinted = false;
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if kl == "cache-control" {
            hinted = true;
            for part in v.split(',') {
                let p = part.trim().to_ascii_lowercase();
                if p == "no-store" || p == "no-cache" || p == "private" || p == "max-age=0" {
                    forbid = true;
                } else if let Some(n) = p.strip_prefix("max-age=") {
                    if let Ok(sec) = n.trim().parse::<i64>() {
                        max_age = Some(sec);
                    }
                }
            }
        } else if kl == "expires" {
            if let Some(t) = parse_http_date(v) {
                expires = Some(t);
                hinted = true;
            }
        }
    }
    if forbid {
        return UpstreamDirective::Forbid;
    }
    if let Some(sec) = max_age {
        return UpstreamDirective::Expire(Duration::from_secs(sec.max(0) as u64));
    }
    if let Some(exp) = expires {
        let delta = exp - now_unix;
        return UpstreamDirective::Expire(Duration::from_secs(delta.max(0) as u64));
    }
    let _ = hinted;
    UpstreamDirective::NoHint
}

/// `proxy_ignore_headers` 的判定视图：被点名（小写存储）的响应头不再参与
/// "能不能缓存 / 缓存多久"。注意这只影响判定——存下来与回发给客户端的头仍是原始集合，
/// nginx 的语义是"停止处理该头"，不是"删除该头"。
pub fn header_counts_for_cache(name: &str, ignore: &[String]) -> bool {
    !ignore
        .iter()
        .any(|t| t.eq_ignore_ascii_case(name))
}

/// 结合上游指示与 `proxy_cache_valid` 得到最终 TTL；None = 不缓存。
/// 优先级：上游显式指示（含 Forbid）> proxy_cache_valid > 不缓存。
pub fn effective_ttl(
    valid: &[(Vec<String>, Duration)],
    status: u16,
    headers: &[(String, String)],
    now_unix: i64,
) -> Option<Duration> {
    match upstream_directive(headers, now_unix) {
        UpstreamDirective::Forbid => None,
        UpstreamDirective::Expire(d) => Some(d),
        UpstreamDirective::NoHint => ttl_from_valid(valid, status).filter(|d| !d.is_zero()),
    }
}

/// 极简 HTTP-date 解析（IMF-fixdate: `Wed, 21 Oct 2015 07:28:00 GMT`）→ Unix 秒。
/// 解析失败返回 None。仅覆盖标准格式，够用。
fn parse_http_date(v: &str) -> Option<i64> {
    let v = v.trim();
    // 去掉星期
    let (_, rest) = v.split_once(", ")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: i64 = parts[0].parse().ok()?;
    let month = match parts[1].to_ascii_lowercase().as_str() {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4, "may" => 5, "jun" => 6,
        "jul" => 7, "aug" => 8, "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[2].parse().ok()?;
    // 时间 HH:MM:SS
    let t: Vec<i64> = parts[3].split(':').filter_map(|x| x.parse().ok()).collect();
    let (h, mi, sec) = (t.first().copied().unwrap_or(0), t.get(1).copied().unwrap_or(0), t.get(2).copied().unwrap_or(0));
    // days-from-civil (Howard Hinnant) 计算公历日序，再换 Unix 秒
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: Arc::new(Bytes::from_static(b"hi")),
        }
    }

    /// `proxy_ignore_headers` 只作用于判定：被点名的头从判定集合里剔除，
    /// 上游的 no-store / 过期头因此不再阻止缓存。
    #[test]
    fn ignore_headers_only_affects_the_decision_view() {
        let valid = vec![(vec!["200".to_string()], Duration::from_secs(60))];
        let hdrs = vec![
            ("cache-control".to_string(), "no-store".to_string()),
            ("set-cookie".to_string(), "sid=1".to_string()),
        ];
        let counts = |ignore: &[String]| {
            hdrs.iter()
                .filter(|(k, _)| header_counts_for_cache(k, ignore))
                .cloned()
                .collect::<Vec<_>>()
        };
        // 不忽略：上游明说 no-store → 不缓存
        assert_eq!(effective_ttl(&valid, 200, &counts(&[]), 0), None);
        // 忽略 cache-control：判定集合里没有该头 → 回落到 proxy_cache_valid
        let ignore = vec!["cache-control".to_string()];
        assert_eq!(
            effective_ttl(&valid, 200, &counts(&ignore), 0),
            Some(Duration::from_secs(60))
        );
        // 忽略项大小写不敏感（配置里已统一小写，这里防回归）
        assert!(!header_counts_for_cache("set-cookie", &["Set-Cookie".to_string()]));
        assert!(!header_counts_for_cache("Set-Cookie", &["set-cookie".to_string()]));
        // 未被点名的头一律保留
        assert!(header_counts_for_cache("expires", &["cache-control".to_string()]));
    }

    #[test]
    fn miss_then_hit_then_expire() {
        let c = ProxyCache::new();
        let (hit, _, count) = c.lookup("z", "k");
        assert_eq!(hit, CacheHit::Miss);
        assert_eq!(count, 1);
        c.store("z", "k", entry(), Duration::from_secs(60));
        let (hit, resp, _) = c.lookup("z", "k");
        assert_eq!(hit, CacheHit::Hit);
        assert_eq!(&resp.unwrap().body[..], b"hi");
    }

    #[test]
    fn expired_reports_expired() {
        let c = ProxyCache::new();
        c.store("z", "k", entry(), Duration::from_secs(60));
        // 手工把过期时间挪到过去
        {
            let mut g = c.zones.lock().unwrap();
            let z = g.get_mut("z").unwrap();
            z.entries.get_mut("k").unwrap().expires = Instant::now() - Duration::from_secs(1);
        }
        let (hit, _, _) = c.lookup("z", "k");
        assert_eq!(hit, CacheHit::Expired);
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let c = ProxyCache::new();
        c.store("z", "k", entry(), Duration::ZERO);
        assert_eq!(c.len("z"), 0);
    }

    #[test]
    fn use_count_increments() {
        let c = ProxyCache::new();
        for i in 1..=3 {
            let (_, _, count) = c.lookup("z", "k");
            assert_eq!(count, i);
        }
    }

    #[test]
    fn ttl_specific_over_any() {
        let valid = vec![
            (vec!["any".to_string()], Duration::from_secs(1)),
            (vec!["200".to_string()], Duration::from_secs(10)),
        ];
        assert_eq!(ttl_from_valid(&valid, 200), Some(Duration::from_secs(10)));
        assert_eq!(ttl_from_valid(&valid, 404), Some(Duration::from_secs(1)));
    }

    #[test]
    fn upstream_directive_parses_cache_control() {
        let hs = vec![("Cache-Control".to_string(), "public, max-age=120".to_string())];
        assert_eq!(
            upstream_directive(&hs, 0),
            UpstreamDirective::Expire(Duration::from_secs(120))
        );
        for bad in ["no-store", "no-cache", "private", "max-age=0"] {
            let hs = vec![("Cache-Control".to_string(), bad.to_string())];
            assert_eq!(upstream_directive(&hs, 0), UpstreamDirective::Forbid, "{bad}");
        }
        let hs = vec![("Content-Type".to_string(), "text/plain".to_string())];
        assert_eq!(upstream_directive(&hs, 0), UpstreamDirective::NoHint);
    }

    #[test]
    fn effective_ttl_prefers_upstream_over_valid() {
        let valid = vec![(vec!["200".to_string()], Duration::from_secs(60))];
        // 上游 no-store 覆盖 proxy_cache_valid → 不缓存
        let hs = vec![("Cache-Control".to_string(), "no-store".to_string())];
        assert_eq!(effective_ttl(&valid, 200, &hs, 0), None);
        // 上游 max-age 覆盖 valid
        let hs = vec![("Cache-Control".to_string(), "max-age=5".to_string())];
        assert_eq!(effective_ttl(&valid, 200, &hs, 0), Some(Duration::from_secs(5)));
        // 上游无提示 → 回落到 valid
        let hs = vec![("Content-Type".to_string(), "text/plain".to_string())];
        assert_eq!(effective_ttl(&valid, 200, &hs, 0), Some(Duration::from_secs(60)));
        // 上游无提示且无匹配 valid → 不缓存
        assert_eq!(effective_ttl(&[], 500, &hs, 0), None);
    }

    #[test]
    fn ttl_from_expires_header_future() {
        // Wed, 21 Oct 2015 07:28:00 GMT == 1445412480；now 取 30 秒前 → Expire(30s)
        let hs = vec![("Expires".to_string(), "Wed, 21 Oct 2015 07:28:00 GMT".to_string())];
        let d = upstream_directive(&hs, 1_445_412_450);
        assert_eq!(d, UpstreamDirective::Expire(Duration::from_secs(30)));
    }

    #[test]
    fn invalidate_removes() {
        let c = ProxyCache::new();
        c.store("z", "k", entry(), Duration::from_secs(60));
        assert!(c.invalidate("z", "k"));
        assert!(!c.invalidate("z", "k"));
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(crate::learning::Learning::default()),
        );
        c.store("z", "a", entry(), Duration::from_secs(60));
        c.store("z", "b", entry(), Duration::from_secs(60));
        // 访问 a，使 b 成为最久未使用
        assert_eq!(c.lookup("z", "a").0, CacheHit::Hit);
        c.store("z", "c", entry(), Duration::from_secs(60));
        assert_eq!(c.len("z"), 2);
        assert_eq!(c.peek("z", "a").0, CacheHit::Hit);
        assert_eq!(c.peek("z", "b").0, CacheHit::Miss);
        assert_eq!(c.peek("z", "c").0, CacheHit::Hit);
    }

    /// 建一套"只有指定区参与学习"的配置（草图取最小尺寸，定长且够单测用）
    fn learning_of(zones: &[(&str, usize)], budget: usize) -> crate::learning::Learning {
        let mut learn_zones = HashMap::new();
        for (name, bytes) in zones {
            learn_zones.insert(name.to_string(), Some(*bytes));
        }
        crate::learning::Learning {
            enabled: true,
            budget: std::sync::Arc::new(crate::learning::Budget::new(budget)),
            sketch_bytes: crate::learning::MIN_SKETCH_BYTES,
            warnings: Vec::new(),
            learn_zones,
            queue_zones: HashMap::new(),
            queue_table_bytes: crate::learning::DEFAULT_QUEUE_BYTES,
            vip: None,
        }
    }

    const SK: usize = crate::learning::MIN_SKETCH_BYTES;

    /// 缓存学习要解决的核心场景：容量已满时，海量一次性 key 不该把热对象挤出去。
    #[test]
    fn learning_refuses_cold_newcomers_in_a_full_zone() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(learning_of(&[("z", SK)], SK * 4)),
        );
        // 先各访问 5 次攒热度（未命中也记频率），再写入 → 占满容量
        for _ in 0..5 {
            c.lookup("z", "a");
            c.lookup("z", "b");
        }
        c.store("z", "a", entry(), Duration::from_secs(60));
        c.store("z", "b", entry(), Duration::from_secs(60));
        for i in 0..50 {
            c.store("z", &format!("scan-{i}"), entry(), Duration::from_secs(60));
        }
        assert_eq!(c.len("z"), 2, "冷 key 不得把热条目挤出去");
        assert_eq!(c.peek("z", "a").0, CacheHit::Hit);
        assert_eq!(c.peek("z", "b").0, CacheHit::Hit);
        let row = &c.learning_rows()[0];
        assert_eq!(row.zone, "z");
        assert_eq!(row.sketch_bytes, SK, "该区应确实持有草图");
        assert!(row.admission_rejected >= 50, "准入拒绝要逐次计数，实际 {}", row.admission_rejected);
        assert_eq!(row.evicted_cold, 0, "拒绝不是驱逐，没腾过位置");
    }

    /// 准入的另一半：比在场最冷条目更热的新 key 应当进得来，并记下一次冷位驱逐。
    #[test]
    fn learning_admits_a_hotter_newcomer() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(learning_of(&[("z", SK)], SK * 4)),
        );
        for _ in 0..3 {
            c.lookup("z", "a");
        }
        c.store("z", "a", entry(), Duration::from_secs(60));
        c.store("z", "b", entry(), Duration::from_secs(60));
        for _ in 0..12 {
            c.lookup("z", "hot");
        }
        c.store("z", "hot", entry(), Duration::from_secs(60));
        assert_eq!(c.len("z"), 2);
        assert_eq!(c.peek("z", "hot").0, CacheHit::Hit, "更热的新 key 应准入");
        assert_eq!(c.peek("z", "b").0, CacheHit::Miss, "b 一次没被访问过，该它出局");
        assert_eq!(c.peek("z", "a").0, CacheHit::Hit);
        let row = &c.learning_rows()[0];
        assert_eq!(row.evicted_cold, 1, "抢位驱逐计数");
    }

    /// VIP 驻留加权的价值要用同一份流量做对照才看得出来：差别只在那次写入多算了 4 分权重，
    /// 于是热对象守得住。另一头，加权发生在准入**之后**，所以信誉换不到插队。
    #[test]
    fn vip_retention_keeps_objects_without_skipping_admission() {
        let build = |retain: bool| {
            let c = ProxyCache::learning(
                HashMap::from([("z".to_string(), 2)]),
                Arc::new(learning_of(&[("z", SK)], SK * 4)),
            );
            for _ in 0..8 {
                c.lookup("z", "hot");
            }
            c.store("z", "hot", entry(), Duration::from_secs(60));
            for _ in 0..2 {
                c.lookup("z", "v");
            }
            c.store_as("z", "v", entry(), Duration::from_secs(60), retain);
            // 一个比 v 热、比 hot 冷的新 key：不加权时它正好换掉 v
            for _ in 0..4 {
                c.lookup("z", "n");
            }
            c.store("z", "n", entry(), Duration::from_secs(60));
            c
        };

        let kept = build(true);
        let r = &kept.learning_rows()[0];
        assert_eq!(
            kept.peek("z", "v").0,
            CacheHit::Hit,
            "加权过的对象该扛住这次换位"
        );
        assert_eq!(r.evicted_cold, 0, "加权后没人够格出局");
        assert_eq!(r.retained, 1, "驻留加权要计数");

        // 同样的流量、不加权：v 就是全区最冷的那个，照常被换掉
        let plain = build(false);
        let r = &plain.learning_rows()[0];
        assert_eq!(
            plain.peek("z", "v").0,
            CacheHit::Miss,
            "对照组里 v 该出局，否则这条测试什么都没证明"
        );
        assert_eq!(plain.peek("z", "n").0, CacheHit::Hit);
        assert_eq!(r.evicted_cold, 1);
        assert_eq!(r.retained, 0);

        // 不插队：从没被访问过的 key 即便由 VIP 写入，也照样过不了准入
        let cold = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(learning_of(&[("z", SK)], SK * 4)),
        );
        for _ in 0..5 {
            cold.lookup("z", "a");
            cold.lookup("z", "b");
        }
        cold.store("z", "a", entry(), Duration::from_secs(60));
        cold.store("z", "b", entry(), Duration::from_secs(60));
        cold.store_as("z", "vip-new", entry(), Duration::from_secs(60), true);
        assert_eq!(
            cold.peek("z", "vip-new").0,
            CacheHit::Miss,
            "信誉不该换成插队"
        );
        let r = &cold.learning_rows()[0];
        assert_eq!(r.admission_rejected, 1);
        assert_eq!(r.retained, 0, "没写进去就不该记一次驻留");
    }

    /// 覆盖写（TTL 到期后的正常刷新）不受准入影响：否则热对象会永远刷不新。
    #[test]
    fn learning_still_refreshes_an_existing_key_when_full() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(learning_of(&[("z", SK)], SK * 4)),
        );
        c.store("z", "a", entry(), Duration::from_secs(60));
        c.store("z", "b", entry(), Duration::from_secs(60));
        for i in 0..20 {
            c.store("z", "a", entry(), Duration::from_secs(60 + i));
        }
        assert_eq!(c.len("z"), 2);
        assert_eq!(c.peek("z", "a").0, CacheHit::Hit);
        assert_eq!(c.learning_rows()[0].admission_rejected, 0, "覆盖写不该被准入拦下");
    }

    /// 关掉学习时不得有任何副作用：不建图、不计数、也不占用预算。
    #[test]
    fn learning_off_is_inert() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 2)]),
            Arc::new(crate::learning::Learning::default()),
        );
        for _ in 0..5 {
            c.lookup("z", "a");
        }
        c.store("z", "a", entry(), Duration::from_secs(60));
        for i in 0..10 {
            c.store("z", &format!("k{i}"), entry(), Duration::from_secs(60));
        }
        let row = &c.learning_rows()[0];
        assert_eq!((row.sketch_bytes, row.ages, row.admission_rejected, row.evicted_cold), (0, 0, 0, 0), "未学习区不得建图/计数");
        let (enabled, used, budget, denied) = c.learning_summary();
        assert!(!enabled);
        assert_eq!((used, budget, denied), (0, crate::learning::DEFAULT_BUDGET, 0));
        // 行为回到纯 LRU：最新写入的两条留下，a 早被淘汰
        assert_eq!(c.peek("z", "a").0, CacheHit::Miss);
    }

    /// 热重载：开→关→开 同一区，账本必须一字节不剩地归还，否则预算会被重载吃光。
    #[test]
    fn apply_learning_returns_bytes_on_disable() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 4)]),
            Arc::new(crate::learning::Learning::default()),
        );
        c.store("z", "a", entry(), Duration::from_secs(60));
        let notes = c.apply_learning(learning_of(&[("z", SK)], SK * 2));
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(c.learning_summary().1, SK, "启用后应记账 {} B", SK);
        assert_eq!(c.learning_rows()[0].sketch_bytes, SK);
        c.apply_learning(crate::learning::Learning::default());
        assert_eq!(c.learning_summary().1, 0, "关闭后必须全额归还");
        assert_eq!(c.learning_rows()[0].sketch_bytes, 0);
        // 再打开：同一个账本还能申领得动（重复申领 = 预算泄漏的表征）
        for _ in 0..2 {
            c.apply_learning(learning_of(&[("z", SK)], SK * 2));
            assert_eq!(c.learning_summary().1, SK);
        }
    }

    /// 预算调小时按"最大的草图先让位"收敛，绝不能让实际占用超出配置承诺的上限。
    #[test]
    fn apply_learning_shrink_releases_largest_first() {
        let caps = HashMap::from([("big".to_string(), 4usize), ("small".to_string(), 4usize)]);
        let c = ProxyCache::learning(caps, Arc::new(crate::learning::Learning::default()));
        c.store("big", "x", entry(), Duration::from_secs(60));
        c.store("small", "y", entry(), Duration::from_secs(60));
        c.apply_learning(learning_of(&[("big", SK * 2), ("small", SK)], SK * 3));
        assert_eq!(c.learning_summary().1, SK * 3);
        let notes = c.apply_learning(learning_of(&[("big", SK * 2), ("small", SK)], SK * 2));
        assert_eq!(c.learning_summary().1, SK, "占用必须收敛到新上限以内");
        assert!(
            notes.iter().any(|n| n.contains("big") && n.contains("放掉")),
            "应说明放掉的是哪个区，实际 {notes:?}"
        );
        let rows = c.learning_rows();
        assert_eq!(rows.iter().find(|r| r.zone == "big").unwrap().sketch_bytes, 0);
        assert_eq!(rows.iter().find(|r| r.zone == "small").unwrap().sketch_bytes, SK);
    }

    /// 申领不到的区要如实报告，并且**不在每个请求里重试**（否则拒绝计数会变成噪声）。
    #[test]
    fn apply_learning_reports_and_stops_retrying_a_refused_zone() {
        let c = ProxyCache::learning(
            HashMap::from([("z".to_string(), 4)]),
            Arc::new(crate::learning::Learning::default()),
        );
        c.store("z", "a", entry(), Duration::from_secs(60));
        let notes = c.apply_learning(learning_of(&[("z", SK)], SK / 2));
        assert!(
            notes.iter().any(|n| n.contains("预算不足")),
            "{notes:?}"
        );
        assert_eq!(c.learning_rows()[0].sketch_bytes, 0);
        for i in 0..100 {
            c.lookup("z", &format!("k{i}"));
        }
        assert_eq!(c.learning_summary().3, 1, "拒绝只该记一次，实际 {}", c.learning_summary().3);
    }

    #[test]
    fn apply_capacities_trims_existing_zone() {
        let c = ProxyCache::new();
        for i in 0..10 {
            c.store("z", &format!("k{i}"), entry(), Duration::from_secs(60));
        }
        c.apply_capacities(&HashMap::from([("z".to_string(), 3)]));
        assert_eq!(c.len("z"), 3);
    }

    #[test]
    fn stale_entry_survives_expiry_then_is_removed() {
        let c = ProxyCache::new();
        c.store("z", "k", entry(), Duration::from_secs(60));
        c.force_expire("z", "k", Duration::from_secs(30));
        let (hit, resp, _) = c.lookup("z", "k");
        assert_eq!(hit, CacheHit::Expired);
        assert_eq!(&resp.unwrap().body[..], b"hi");
        // 超过 stale 滞留期 → 真正删除，避免内存永久占用
        c.force_expire("z", "k", Duration::ZERO);
        assert_eq!(c.lookup("z", "k").0, CacheHit::Miss);
        assert_eq!(c.len("z"), 0);
    }

    #[tokio::test]
    async fn same_key_lock_is_exclusive() {
        let c = ProxyCache::new();
        let l1 = c.cache_lock("z", "k");
        let l2 = c.cache_lock("z", "k");
        assert!(Arc::ptr_eq(&l1, &l2), "同 key 必须拿到同一把锁");
        let guard = l1.clone().lock_owned().await;
        assert!(l1.clone().try_lock_owned().is_err(), "leader 持锁期间 waiter 必须等待");
        drop(guard);
        assert!(l2.try_lock_owned().is_ok());
        // 不同 key 互不影响
        assert!(!Arc::ptr_eq(&c.cache_lock("z", "k2"), &l1));
    }
}
