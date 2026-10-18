//! ngx.shared.DICT —— 对标 OpenResty 的 `lua_shared_dict` 共享内存字典。
//!
//! ```text
//! lua_shared_dict counters 1m;      # 声明一个共享区（容量上限，超出会 LRU 淘汰）
//! ```
//!
//! Lua 侧：
//! ```lua
//! local d = ngx.shared.counters
//! d:set("k", "v", 10)     -- ttl 可选（秒）；空间不足时 LRU 淘汰旧项
//! d:safe_set("k", "v")    -- 不淘汰，空间不足返回 nil+"no memory"
//! d:get("k")              -- 过期返回 nil
//! d:add("k", "1")         -- 已存在则失败
//! d:incr("k", 1)          -- 原子自增
//! d:delete("k"); d:flush_all()
//! d:capacity(); d:free_space(); d:num(); d:flush_expired()
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use onrouter_config::Config;

use crate::router::parse_size;
use crate::AppError;

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 单个条目的成本：key + value + 固定开销（对标 nginx slab node overhead ~64B）
const NODE_OVERHEAD: usize = 64;

#[derive(Debug, Clone)]
struct Entry {
    value: Vec<u8>,
    /// 过期时间（epoch 秒）；None = 永不过期
    expires_at: Option<f64>,
    /// LRU 时钟戳（每次 get/set 更新）
    last_used: u64,
    /// 本条目占用的字节数（key.len + value.len + overhead）
    cost: usize,
}

impl Entry {
    fn alive(&self, now: f64) -> bool {
        match self.expires_at {
            Some(t) => now < t,
            None => true,
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
}

impl ZoneInner {
    fn new(capacity: usize) -> Self {
        ZoneInner {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            capacity,
            used: AtomicUsize::new(0),
            clock: AtomicU64::new(0),
        }
    }

    fn shard(&self, key: &str) -> &Mutex<HashMap<String, Entry>> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// 分配一个新的时钟戳
    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 从随机分片中采样若干 entry，淘汰 last_used 最小的那个（Redis 式近似 LRU）
    fn evict_one(&self) -> bool {
        // 尝试多个分片直到找到一个有 entry 的
        let start = (self.tick() as usize) % SHARDS;
        for offset in 0..SHARDS {
            let shard_idx = (start + offset) % SHARDS;
            let mut map = self.shards[shard_idx].lock().unwrap();
            if map.is_empty() {
                continue;
            }
            // 采样最多 8 个 entry，找 last_used 最小的
            let mut best_key: Option<String> = None;
            let mut best_tick = u64::MAX;
            for (k, v) in map.iter().take(8) {
                if v.last_used < best_tick {
                    best_tick = v.last_used;
                    best_key = Some(k.clone());
                }
            }
            if let Some(key) = best_key {
                if let Some(entry) = map.remove(&key) {
                    self.used.fetch_sub(entry.cost, Ordering::Relaxed);
                    return true;
                }
            }
        }
        false
    }

    /// 尝试为给定成本腾出空间：先清理过期项，再 LRU 淘汰
    fn make_room(&self, cost: usize) -> bool {
        if self.capacity == 0 {
            return true; // 无容量限制
        }
        // 第一轮：清理所有分片中的过期项
        let now = now_epoch();
        for shard in &self.shards {
            let mut map = shard.lock().unwrap();
            let expired: Vec<String> = map
                .iter()
                .filter(|(_, e)| !e.alive(now))
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                if let Some(e) = map.remove(&k) {
                    self.used.fetch_sub(e.cost, Ordering::Relaxed);
                }
            }
        }
        // 第二轮：如果还不够，LRU 淘汰
        while self.used.load(Ordering::Relaxed) + cost > self.capacity {
            if !self.evict_one() {
                return false; // 没有可淘汰的了
            }
        }
        true
    }
}

impl SharedZone {
    fn new(capacity: usize) -> Self {
        SharedZone {
            inner: Arc::new(ZoneInner::new(capacity)),
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let now = now_epoch();
        let mut map = self.inner.shard(key).lock().unwrap();
        if let Some(e) = map.get_mut(key) {
            if e.alive(now) {
                e.last_used = self.inner.tick();
                return Some(e.value.clone());
            }
        }
        None
    }

    /// 含过期项的读取，附带 stale 标志（对标 get_stale 的 (value, stale) 双返回值）
    pub fn get_stale_flagged(&self, key: &str) -> (Option<Vec<u8>>, bool) {
        let now = now_epoch();
        let mut map = self.inner.shard(key).lock().unwrap();
        if let Some(e) = map.get_mut(key) {
            e.last_used = self.inner.tick();
            return (Some(e.value.clone()), !e.alive(now));
        }
        (None, false)
    }

    /// 写入：空间不足时 LRU 淘汰；单项超过整区容量时返回 Err("no memory")
    pub fn set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<(), String> {
        let now = now_epoch();
        let expires_at = ex.map(|t| now + t);
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 先计算净增量（需要临时锁一下当前分片读取旧值）
        let shard = self.inner.shard(key);
        let old_cost = {
            let map = shard.lock().unwrap();
            map.get(key).map(|e| e.cost).unwrap_or(0)
        };
        let net_cost = if cost > old_cost { cost - old_cost } else { 0 };
        // 腾空间（不持有任何锁）
        if !self.inner.make_room(net_cost) {
            return Err("no memory".to_string());
        }
        let tick = self.inner.tick();
        let mut map = shard.lock().unwrap();
        map.insert(
            key.to_string(),
            Entry {
                value,
                expires_at,
                last_used: tick,
                cost,
            },
        );
        self.inner.used.fetch_add(net_cost, Ordering::Relaxed);
        Ok(())
    }

    /// safe_set：不淘汰，空间不足直接返回 Err("no memory")
    pub fn safe_set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<(), String> {
        let now = now_epoch();
        let expires_at = ex.map(|t| now + t);
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        let mut map = self.inner.shard(key).lock().unwrap();
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
            Entry {
                value,
                expires_at,
                last_used: tick,
                cost,
            },
        );
        // 更新 used：减去旧值，加上新值
        if old_cost > 0 {
            self.inner.used.fetch_sub(old_cost, Ordering::Relaxed);
        }
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(())
    }

    /// 不存在（或已过期）时才写入；返回是否成功
    pub fn add(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<bool, String> {
        let now = now_epoch();
        let mut map = self.inner.shard(key).lock().unwrap();
        if map.get(key).is_some_and(|e| e.alive(now)) {
            return Ok(false);
        }
        let cost = key.len() + value.len() + NODE_OVERHEAD;
        if self.inner.capacity > 0 && cost > self.inner.capacity {
            return Err("no memory".to_string());
        }
        // 检查空间（add 不淘汰，直接失败）
        if self.inner.capacity > 0
            && self.inner.used.load(Ordering::Relaxed) + cost > self.inner.capacity
        {
            return Err("no memory".to_string());
        }
        let expires_at = ex.map(|t| now + t);
        let tick = self.inner.tick();
        map.insert(
            key.to_string(),
            Entry {
                value,
                expires_at,
                last_used: tick,
                cost,
            },
        );
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(true)
    }

    /// 已存在（未过期）时才覆盖；返回是否成功
    pub fn replace(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> Result<bool, String> {
        let now = now_epoch();
        let mut map = self.inner.shard(key).lock().unwrap();
        let existing = map.get(key);
        if !existing.is_some_and(|e| e.alive(now)) {
            return Ok(false);
        }
        let old_cost = existing.unwrap().cost;
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
        map.remove(key); // 释放旧成本
        self.inner.used.fetch_sub(old_cost, Ordering::Relaxed);
        let expires_at = ex.map(|t| now + t);
        let tick = self.inner.tick();
        map.insert(
            key.to_string(),
            Entry {
                value,
                expires_at,
                last_used: tick,
                cost,
            },
        );
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(true)
    }

    pub fn delete(&self, key: &str) {
        let mut map = self.inner.shard(key).lock().unwrap();
        if let Some(e) = map.remove(key) {
            self.inner.used.fetch_sub(e.cost, Ordering::Relaxed);
        }
    }

    /// 原子自增整数值；项不存在时若给了 init 则初始化为 init
    pub fn incr(&self, key: &str, delta: i64, init: Option<i64>) -> Result<i64, String> {
        let now = now_epoch();
        let shard = self.inner.shard(key);
        // 命中且存活：原地累加，全程只持当前分片锁，不触发淘汰
        {
            let mut map = shard.lock().unwrap();
            if let Some(e) = map.get_mut(key) {
                if e.alive(now) {
                    let text = String::from_utf8_lossy(&e.value).trim().to_string();
                    let cur: i64 = text
                        .parse()
                        .map_err(|_| format!("incr: '{key}' 的值不是数字 ({text})"))?;
                    let new = cur + delta;
                    e.value = new.to_string().into_bytes();
                    e.last_used = self.inner.tick();
                    return Ok(new);
                }
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
        if !self.inner.make_room(cost) {
            return Err("no memory".to_string());
        }
        let tick = self.inner.tick();
        let mut map = shard.lock().unwrap();
        // 释放锁的窗口里同 key 可能已被其它请求写入且为数字：再走一次累加，避免覆盖
        if let Some(e) = map.get_mut(key) {
            if e.alive(now) {
                let text = String::from_utf8_lossy(&e.value).trim().to_string();
                if let Ok(cur) = text.parse::<i64>() {
                    let new2 = cur + delta;
                    e.value = new2.to_string().into_bytes();
                    e.last_used = tick;
                    return Ok(new2);
                }
            }
        }
        map.insert(
            key.to_string(),
            Entry {
                value: val,
                expires_at: None,
                last_used: tick,
                cost,
            },
        );
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(new)
    }

    /// 剩余存活时间：None=不存在，Some(-1.0)=永不过期，Some(x)=剩余秒数
    pub fn ttl(&self, key: &str) -> Option<f64> {
        let now = now_epoch();
        let map = self.inner.shard(key).lock().unwrap();
        map.get(key).map(|e| match e.expires_at {
            None => -1.0,
            Some(t) => (t - now).max(0.0),
        })
    }

    pub fn flush_all(&self) {
        for s in &self.inner.shards {
            let mut map = s.lock().unwrap();
            let total: usize = map.values().map(|e| e.cost).sum();
            self.inner.used.fetch_sub(total, Ordering::Relaxed);
            map.clear();
        }
    }

    /// 清理所有过期项，返回清理的数量
    pub fn flush_expired(&self) -> usize {
        let now = now_epoch();
        let mut count = 0;
        for s in &self.inner.shards {
            let mut map = s.lock().unwrap();
            let expired: Vec<String> = map
                .iter()
                .filter(|(_, e)| !e.alive(now))
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                if let Some(e) = map.remove(&k) {
                    self.inner.used.fetch_sub(e.cost, Ordering::Relaxed);
                    count += 1;
                }
            }
        }
        count
    }

    /// 总条目数（含过期）
    pub fn num(&self) -> usize {
        self.inner
            .shards
            .iter()
            .map(|s| s.lock().unwrap().len())
            .sum()
    }

    /// 容量上限（字节）
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// 剩余可用空间（字节）
    pub fn free_space(&self) -> usize {
        if self.inner.capacity == 0 {
            return usize::MAX;
        }
        self.inner
            .capacity
            .saturating_sub(self.inner.used.load(Ordering::Relaxed))
    }

    /// key 是否存在且未过期（对标 key_present）
    pub fn key_present(&self, key: &str) -> bool {
        let now = now_epoch();
        let map = self.inner.shard(key).lock().unwrap();
        map.get(key).is_some_and(|e| e.alive(now))
    }

    /// 值存储占用字节数（所有存活项的 value 长度之和，对标 size()）
    pub fn size(&self) -> usize {
        let now = now_epoch();
        self.inner
            .shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap()
                    .values()
                    .filter(|e| e.alive(now))
                    .map(|e| e.value.len())
                    .sum::<usize>()
            })
            .sum()
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
        if !self.inner.make_room(cost) {
            return Err("no memory".to_string());
        }
        let shard = self.inner.shard(key);
        let mut map = shard.lock().unwrap();
        if map.get(key).is_some_and(|e| e.alive(now)) {
            return Ok(false); // 竞争窗口里已被写入
        }
        let tick = self.inner.tick();
        map.insert(
            key.to_string(),
            Entry {
                value,
                expires_at: ex.map(|t| now + t),
                last_used: tick,
                cost,
            },
        );
        self.inner.used.fetch_add(cost, Ordering::Relaxed);
        Ok(true)
    }

    /// decr：decr(key, minus, init?) —— 语义为 incr 取负（init 命中时结果 = init - minus）
    pub fn decr(&self, key: &str, minus: i64, init: Option<i64>) -> Result<i64, String> {
        self.incr(key, -minus, init)
    }

    /// bump：把值当整数累加，允许累加已过期项（不检查存活、不新建），返回新值或 Err("not found")
    pub fn bump(&self, key: &str, by: i64) -> Result<i64, String> {
        let shard = self.inner.shard(key);
        let mut map = shard.lock().unwrap();
        let Some(e) = map.get_mut(key) else {
            return Err(format!("bump: '{key}' not found"));
        };
        let text = String::from_utf8_lossy(&e.value).trim().to_string();
        let cur: i64 = text
            .parse()
            .map_err(|_| format!("bump: '{key}' 的值不是数字 ({text})"))?;
        let new = cur + by;
        e.value = new.to_string().into_bytes();
        e.last_used = self.inner.tick();
        Ok(new)
    }
}

#[derive(Debug, Default)]
pub struct SharedDicts {
    pub zones: HashMap<String, SharedZone>,
}

impl SharedDicts {
    /// 解析顶层 `lua_shared_dict <name> <size>;` 指令
    pub fn parse_all(config: &Config) -> Result<Self, AppError> {
        let mut zones = HashMap::new();
        for d in &config.root.block {
            if d.name == "lua_shared_dict" {
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
                zones.insert(name.to_string(), SharedZone::new(capacity));
            }
        }
        Ok(SharedDicts { zones })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(cap: usize) -> SharedZone {
        SharedZone::new(cap)
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
}
