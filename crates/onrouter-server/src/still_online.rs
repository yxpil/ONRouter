//! Still ONLine：后端不可用时继续对外服务"最后一次成功响应"的副本层。
//!
//! 与 `proxy_cache` 完全隔离：独立的区、独立的容量预算、独立的保留期，
//! 不会被 proxy_cache 的 LRU/`proxy_cache_valid` 判定挤掉或提前过期。
//! 只在 `proxy_pass` 路径上工作（静态文件与 Lua content 不依赖后端，谈不上"后端崩了"）。
//!
//! 三条**没有开关**的凭证硬规则（用户明确要求：不许因为兜底而让登录态被串用）：
//!   1. 上游响应里带 `Set-Cookie` 的一律不进副本区——会话签发响应天然是"这个人专属"的；
//!   2. 回放副本时一律剥掉 `Set-Cookie`——即便历史条目里存在也绝不发给下一个客户端；
//!   3. 请求自带 `Cookie`/`Authorization` 时**不写入**副本区；默认也**不回放**给它
//!      （`still_online_allow_credentials on;` 只放开"读"，写入门槛不松）。
//! 后台恢复重试发的是匿名 GET（不携带任何 Cookie/Authorization），所以后端拿到的是
//! 一个公开可取的同一 URL；需要登录才能取到的内容本来就不入门槛 3 之外的写入路径。
//!
//! 第 4 条同样没有开关，管的是"上游自己说这份内容是这个访客专属的"（`response_forbids_copy`）：
//!   4. 响应带 `Cache-Control: private / no-store / no-cache / max-age=0`、有效期为 0，
//!      或 `Vary` 点名了 `Accept-Encoding` 之外的头 → 不进副本区。
//!      副本 key 默认不含身份，也没有第二个地方能把它认回来，所以只要上游分过变体就不能存。
//!
//! 容量按**字节预算**计（区别于 `keys_zone` 的条数换算）：副本存的是完整响应体，
//! 条数上限无法约束内存。超预算按 LRU 逐出；单条超过 `still_online_max_body` 直接不收。
//!
//! 恢复重试：回源失败时把该 key 挂进脏表，由后台任务在健康恢复后单飞重取，
//! 指数退避（`retry` → 每次翻倍 → `retry_max`），超过 `retry_deadline` 放弃（副本本身还在）。

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::proxy_cache::CachedResponse;

/// 一条副本：可回放的响应 + 重建匿名回源请求所需的连接画像（不含任何凭证）。
#[derive(Clone)]
pub struct Snapshot {
    pub resp: Arc<CachedResponse>,
    /// 写入时刻，用于 `still_online_max_age` 判定与 `Age` 头
    pub stored_at: SystemTime,
    /// 重放这条副本时"当时是哪个监听、哪个 vhost、哪个 URI"——后台重试照此重建请求
    pub listener: Option<SocketAddr>,
    pub host: Option<String>,
    pub scheme: String,
    pub uri: String,
}

impl Snapshot {
    /// 副本已存放多久（供 `Age` 与保留期判定）。
    pub fn age(&self) -> Duration {
        self.stored_at
            .elapsed()
            .unwrap_or(Duration::from_secs(u64::MAX / 2))
    }
}

/// 脏表里的一条待重取任务。
#[derive(Clone)]
pub struct RefreshJob {
    pub zone: String,
    pub key: String,
    pub listener: Option<SocketAddr>,
    pub host: Option<String>,
    pub scheme: String,
    pub uri: String,
    pub attempts: u32,
    pub next_at: Instant,
    pub first_failed_at: Instant,
    /// 挂进脏表时所在 location 的退避节奏：重取失败后照它继续翻倍，
    /// 不必（也无法）在后台重新查回那份配置。
    pub policy: RetryPolicy,
}

struct Slot {
    snap: Arc<Snapshot>,
    bytes: usize,
    tick: u64,
}

struct Zone {
    entries: HashMap<String, Slot>,
    /// tick → key，用于 O(log n) 找最久未使用条目
    lru: BTreeMap<u64, String>,
    tick: u64,
    /// `still_online_zone <名> <容量>` 换算出的字节预算
    budget: usize,
    used: usize,
}

impl Zone {
    fn new(budget: usize) -> Self {
        Zone {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
            budget,
            used: 0,
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(slot) = self.entries.get_mut(key) {
            self.lru.remove(&slot.tick);
            self.tick += 1;
            slot.tick = self.tick;
            self.lru.insert(self.tick, key.to_string());
        }
    }

    /// 逐出到 `need` 字节能放进来；返回逐出条数。
    fn evict_to_fit(&mut self, need: usize) -> usize {
        let mut evicted = 0;
        // 预算是硬上限：即便单条小于预算，也要给后面的条目留空间的可能，
        // 所以只保证 used + need <= budget；否则从最久未使用开始清。
        while self.used.saturating_add(need) > self.budget {
            let Some((tick, key)) = self.lru.iter().next().map(|(t, k)| (*t, k.clone())) else {
                break;
            };
            self.lru.remove(&tick);
            if let Some(slot) = self.entries.remove(&key) {
                self.used = self.used.saturating_sub(slot.bytes);
                evicted += 1;
            }
        }
        evicted
    }
}

/// 单个脏 key 的退避节奏由调用方（location 配置）给出，避免全局写死。
#[derive(Clone, Copy)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max: Duration,
    pub deadline: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            base: Duration::from_secs(5),
            max: Duration::from_secs(300),
            deadline: Duration::from_secs(1800),
        }
    }
}

impl RetryPolicy {
    /// 第 n 次失败后的等待：base 逐次翻倍，封顶 max。
    fn backoff(&self, attempts: u32) -> Duration {
        let factor = attempts.saturating_sub(1).min(16);
        self.base.saturating_mul(1u32 << factor).min(self.max)
    }
}

/// 副本区 + 脏表 + 计数器。挂进 `AppState`，请求路径只做一次加锁的 map 查找。
pub struct StillOnline {
    zones: Mutex<HashMap<String, Zone>>,
    budgets: Mutex<HashMap<String, usize>>,
    dirty: Mutex<HashMap<(String, String), RefreshJob>>,
    /// 脏表容量上限：后端彻底没了时，脏表会随请求数线性膨胀，必须有界。
    dirty_cap: usize,
    pub stored_total: AtomicU64,
    pub served_total: AtomicU64,
    pub refreshed_total: AtomicU64,
    pub refresh_failed_total: AtomicU64,
    /// 因凭证硬规则被拒绝的次数（写入门槛 3 / 响应带 Set-Cookie 门槛 1）
    pub rejected_credential_total: AtomicU64,
    /// 因"这份内容不属于公众"（硬规则 4：Cache-Control 不缓存 / Vary 按身份分变体）被拒绝的次数
    pub rejected_private_total: AtomicU64,
    pub evicted_total: AtomicU64,
}

impl StillOnline {
    pub fn with_budgets(budgets: HashMap<String, usize>) -> Arc<Self> {
        let dirty_cap = (budgets.values().sum::<usize>() / 4096)
            .clamp(1024, 65536)
            .max(1024);
        Arc::new(StillOnline {
            zones: Mutex::new(HashMap::new()),
            budgets: Mutex::new(budgets),
            dirty: Mutex::new(HashMap::new()),
            dirty_cap,
            stored_total: AtomicU64::new(0),
            served_total: AtomicU64::new(0),
            refreshed_total: AtomicU64::new(0),
            refresh_failed_total: AtomicU64::new(0),
            rejected_credential_total: AtomicU64::new(0),
            rejected_private_total: AtomicU64::new(0),
            evicted_total: AtomicU64::new(0),
        })
    }

    fn bump(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    /// 热重载：套用新的字节预算并立刻裁剪超限条目。
    pub fn apply_budgets(&self, budgets: &HashMap<String, usize>) {
        {
            let mut b = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
            *b = budgets.clone();
        }
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        // 配置里被删掉的区：再也不会被任何 location 引用，留着只是占内存
        zones.retain(|name, _| budgets.contains_key(name));
        for (name, z) in zones.iter_mut() {
            if let Some(&budget) = budgets.get(name) {
                z.budget = budget;
                // 逐出到"当前用量已不超预算"：need=0 即把 used 压回 budget 以下
                let evicted = z.evict_to_fit(0);
                Self::bump(&self.evicted_total, evicted as u64);
            }
        }
        drop(zones);
        // 脏表里指向已删除区的任务不再有去处：直接摘掉，省得后台空转一整个 deadline
        self.dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id, _| budgets.contains_key(&id.0));
    }

    /// 写入/覆盖一条副本。返回 false = 区未定义、超过单条上限，或放不下。
    pub fn store(&self, zone: &str, key: &str, snap: Snapshot, max_body: usize) -> bool {
        let bytes = snap.resp.body.len();
        if bytes > max_body {
            return false;
        }
        let budget = {
            let b = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
            b.get(zone).copied()
        };
        let Some(budget) = budget else { return false };
        let slot_bytes = bytes.saturating_add(key.len()).saturating_add(128);
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = zones
            .entry(zone.to_string())
            .or_insert_with(|| Zone::new(budget));
        z.budget = budget;
        // 覆盖旧条目先退账，避免重复计数
        if let Some(old) = z.entries.get(key) {
            z.used = z.used.saturating_sub(old.bytes);
        }
        let evicted = z.evict_to_fit(slot_bytes);
        Self::bump(&self.evicted_total, evicted as u64);
        // 单条就超预算：放不进去，明确失败（不静默吞掉）
        if slot_bytes > z.budget {
            return false;
        }
        z.tick += 1;
        let tick = z.tick;
        z.lru.insert(tick, key.to_string());
        z.entries.insert(
            key.to_string(),
            Slot {
                snap: Arc::new(snap),
                bytes: slot_bytes,
                tick,
            },
        );
        z.used = z.used.saturating_add(slot_bytes);
        Self::bump(&self.stored_total, 1);
        true
    }

    /// 取回不超过 `max_age` 的副本；超龄条目就地删除（内存里的东西留着只是风险）。
    pub fn lookup(&self, zone: &str, key: &str, max_age: Duration) -> Option<Arc<Snapshot>> {
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = zones.get_mut(zone)?;
        let stale = match z.entries.get(key) {
            Some(slot) if slot.snap.age() > max_age => true,
            Some(_) => false,
            None => return None,
        };
        if stale {
            if let Some(slot) = z.entries.remove(key) {
                z.lru.remove(&slot.tick);
                z.used = z.used.saturating_sub(slot.bytes);
            }
            return None;
        }
        z.touch(key);
        let snap = Arc::clone(&z.entries.get(key)?.snap);
        Self::bump(&self.served_total, 1);
        Some(snap)
    }

    /// `/metrics` 用：按区名排序的 (名称, 条目数, 占用字节, 字节预算)。
    /// 已声明但还没写过条目的区也要出现（budget 来自配置），否则"配了但没用上"看不出来。
    pub fn zone_rows(&self) -> Vec<(String, usize, usize, usize)> {
        let zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let budgets = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<&String> = zones.keys().chain(budgets.keys()).collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(|n| {
                let (entries, used) = zones.get(n).map(|z| (z.entries.len(), z.used)).unwrap_or((0, 0));
                let budget = budgets.get(n).copied().unwrap_or(0);
                (n.clone(), entries, used, budget)
            })
            .collect()
    }

    pub fn note_credential_reject(&self) {
        Self::bump(&self.rejected_credential_total, 1);
    }

    /// 硬规则 4 命中一次（私有/按身份分变体的响应被挡在副本区外）。
    pub fn note_private_reject(&self) {
        Self::bump(&self.rejected_private_total, 1);
    }

    /// 回源失败：挂进脏表。已有任务时保持它的退避节奏（不被并发请求重置成"立刻重试"）。
    pub fn mark_dirty(&self, zone: &str, key: &str, snap: &Snapshot, policy: &RetryPolicy) {
        let id = (zone.to_string(), key.to_string());
        let mut dirty = self.dirty.lock().unwrap_or_else(|e| e.into_inner());
        if dirty.contains_key(&id) {
            return;
        }
        if dirty.len() >= self.dirty_cap {
            // 表满了就不再收：副本仍在服务，只是恢复后不会自动重取这一条。
            // 溢出计数并入 refresh_failed（同一家族：没换成新鲜内容）。
            Self::bump(&self.refresh_failed_total, 1);
            return;
        }
        let now = Instant::now();
        dirty.insert(
            id,
            RefreshJob {
                zone: zone.to_string(),
                key: key.to_string(),
                listener: snap.listener,
                host: snap.host.clone(),
                scheme: snap.scheme.clone(),
                uri: snap.uri.clone(),
                attempts: 0,
                next_at: now + policy.backoff(1),
                first_failed_at: now,
                policy: *policy,
            },
        );
    }

    pub fn dirty_len(&self) -> usize {
        self.dirty.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 到期的任务取出并从脏表摘除（由后台任务逐个重取；重取失败再 `requeue`）。
    pub fn due_jobs(&self, now: Instant) -> Vec<RefreshJob> {
        let mut dirty = self.dirty.lock().unwrap_or_else(|e| e.into_inner());
        let due: Vec<RefreshJob> = dirty
            .values()
            .filter(|j| j.next_at <= now)
            .cloned()
            .collect();
        for j in &due {
            dirty.remove(&(j.zone.clone(), j.key.clone()));
        }
        due
    }

    /// 重取成功：清脏标记（副本已被 `store` 覆盖，下次服务的是新鲜内容）。
    pub fn note_refreshed(&self, zone: &str, key: &str) {
        Self::bump(&self.refreshed_total, 1);
        self.dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(zone.to_string(), key.to_string()));
    }

    /// 真实流量刚刚成功取到了新鲜内容：撤销这条待重取标记（不算一次后台重取，
    /// 所以不动 `refreshed_total`）。返回是否真的摘掉了一项。
    pub fn clear_dirty(&self, zone: &str, key: &str) -> bool {
        self.dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(zone.to_string(), key.to_string()))
            .is_some()
    }

    /// 重取失败：按任务自带的退避节奏重新入表；超过 deadline 就放弃（副本继续服务到 max_age）。
    pub fn requeue(&self, job: RefreshJob) {
        let now = Instant::now();
        let attempts = job.attempts.saturating_add(1);
        Self::bump(&self.refresh_failed_total, 1);
        if now.duration_since(job.first_failed_at) > job.policy.deadline {
            return;
        }
        let wait = job.policy.backoff(attempts);
        let mut dirty = self.dirty.lock().unwrap_or_else(|e| e.into_inner());
        dirty.insert(
            (job.zone.clone(), job.key.clone()),
            RefreshJob {
                attempts,
                next_at: now + wait,
                ..job
            },
        );
    }
}

/// 回放副本时要从响应头里剔除的名字：hop-by-hop 由调用方处理，这里只管凭证面。
/// `Set-Cookie` 是硬规则 2：**永不**随副本下发。
pub fn strip_for_replay(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("set-cookie"))
        .cloned()
        .collect()
}

/// 请求侧凭证头检测（硬规则 3）。用 ASCII 大小写无关比较，不复制头值。
pub fn request_has_credentials(req_headers: &[(String, String)]) -> bool {
    req_headers.iter().any(|(k, _)| {
        k.eq_ignore_ascii_case("cookie") || k.eq_ignore_ascii_case("authorization")
    })
}

/// 响应侧凭证头检测（硬规则 1）。
pub fn response_has_set_cookie(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
}

/// 响应侧"这份内容不属于公众"检测（硬规则 4）。返回拒绝原因。
///
/// 为什么需要它：副本区的 key 默认 `$scheme$proxy_host$request_uri`，**不含任何身份**，
/// 回放时也不看请求带了什么——上游只要说过 `Cache-Control: private`（或 no-store/no-cache/
/// max-age=0），就是在声明"这个响应是按当前这个访客生成的"，进副本区等于故障期把 A 的
/// 正文回放给 B。与 `proxy_cache` 的 `effective_ttl` 用同一个 `upstream_directive` 判定，
/// 两处语义不许分叉。
///
/// `Vary` 同理但更隐蔽：只要它点名了 `Accept-Encoding` 之外的头（Cookie、X-Api-Key、
/// 任何自定义鉴权头），说明上游按那个头分过变体，而我们的 key 里没有它——存下的永远是
/// 第一个到达客户端的那一份。
pub fn response_forbids_copy(headers: &[(String, String)]) -> Option<&'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match crate::proxy_cache::upstream_directive(headers, now) {
        crate::proxy_cache::UpstreamDirective::Forbid => {
            return Some("上游声明该响应不缓存（private / no-store / no-cache / max-age=0）")
        }
        crate::proxy_cache::UpstreamDirective::Expire(d) if d.is_zero() => {
            return Some("上游给的有效期为 0，存进去立刻就是过期内容")
        }
        crate::proxy_cache::UpstreamDirective::Expire(_)
        | crate::proxy_cache::UpstreamDirective::NoHint => {}
    }
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("vary") {
            continue;
        }
        for part in v.split(',') {
            let p = part.trim();
            if !p.is_empty() && !p.eq_ignore_ascii_case("accept-encoding") {
                return Some("Vary 按副本 key 之外的头分变体");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn budgets(entries: &[(&str, usize)]) -> HashMap<String, usize> {
        entries
            .iter()
            .map(|(n, b)| (n.to_string(), *b))
            .collect()
    }

    fn snap(body: &str, uri: &str) -> Snapshot {
        Snapshot {
            resp: Arc::new(CachedResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/html".into())],
                body: Arc::new(Bytes::from(body.to_string())),
            }),
            stored_at: SystemTime::now(),
            listener: Some("127.0.0.1:18080".parse().unwrap()),
            host: Some("site.local".into()),
            scheme: "http".into(),
            uri: uri.into(),
        }
    }

    fn store_all(cache: &Arc<StillOnline>, zone: &str, body: &str, uri: &str) -> bool {
        let key = format!("{uri}");
        cache.store(zone, &key, snap(body, uri), usize::MAX)
    }

    /// 单条目计费口径（与 `store` 内部一致：body + key + 128 固定开销）。
    /// 测试用它算预算，别把长度写死成字面量。
    fn unit(body_len: usize, key: &str) -> usize {
        body_len + key.len() + 128
    }

    /// 测试用的区诊断口径（走 `zone_rows`，不额外开生产接口）。
    fn stats(c: &StillOnline, zone: &str) -> (usize, usize) {
        c.zone_rows()
            .into_iter()
            .find(|row| row.0 == zone)
            .map(|row| (row.1, row.2))
            .unwrap_or((0, 0))
    }

    #[test]
    fn backoff_doubles_and_caps_at_max() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff(0), Duration::from_secs(5));
        assert_eq!(p.backoff(1), Duration::from_secs(5));
        assert_eq!(p.backoff(2), Duration::from_secs(10));
        assert_eq!(p.backoff(4), Duration::from_secs(40));
        // 封顶后不再指数增长
        assert_eq!(p.backoff(30), Duration::from_secs(300));
    }

    #[test]
    fn stores_and_lookups_within_max_age() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 4096)]));
        assert!(store_all(&c, "pages", "hello", "/a"));
        let s = c
            .lookup("pages", "/a", Duration::from_secs(60))
            .expect("应命中副本");
        assert_eq!(&s.resp.body[..], b"hello");
        assert_eq!(s.host.as_deref(), Some("site.local"));
        assert_eq!(c.stored_total.load(Ordering::Relaxed), 1);
        assert_eq!(c.served_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn undefined_zone_is_a_hard_store_failure() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 4096)]));
        assert!(!store_all(&c, "nope", "x", "/a"));
    }

    #[test]
    fn oversized_entry_is_skipped_not_truncated() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 4096)]));
        assert!(!c.store("pages", "/big", snap("1234567890", "/big"), 5));
        assert_eq!(stats(&c, "pages").0, 0);
    }

    #[test]
    fn byte_budget_evicts_least_recently_used() {
        // 预算刚好容两条，第三条挤掉最久未用的（计费口径见 unit）
        let unit = unit(64, "/k1");
        let c = StillOnline::with_budgets(budgets(&[("pages", 2 * unit)]));
        assert!(store_all(&c, "pages", "a".repeat(64).as_str(), "/k1"));
        assert!(store_all(&c, "pages", "b".repeat(64).as_str(), "/k2"));
        // 读一次 k1，使 k2 成为最久未使用
        let _ = c.lookup("pages", "/k1", Duration::from_secs(60));
        assert!(store_all(&c, "pages", "c".repeat(64).as_str(), "/k3"));
        assert!(c.lookup("pages", "/k1", Duration::from_secs(60)).is_some());
        assert!(c.lookup("pages", "/k3", Duration::from_secs(60)).is_some());
        assert!(c.lookup("pages", "/k2", Duration::from_secs(60)).is_none());
        assert!(c.evicted_total.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn entry_bigger_than_budget_never_lands() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 256)]));
        assert!(!store_all(&c, "pages", &"x".repeat(4000), "/big"));
        assert_eq!(stats(&c, "pages"), (0, 0));
    }

    #[test]
    fn over_age_entry_is_dropped_on_read() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 4096)]));
        assert!(store_all(&c, "pages", "x", "/a"));
        // 直接把写入时刻调到过去
        {
            let mut zs = c.zones.lock().unwrap();
            let z = zs.get_mut("pages").unwrap();
            let slot = z.entries.get_mut("/a").unwrap();
            let mut s = (*slot.snap).clone();
            s.stored_at = SystemTime::now() - Duration::from_secs(3600);
            slot.snap = Arc::new(s);
        }
        assert!(c.lookup("pages", "/a", Duration::from_secs(60)).is_none());
        assert_eq!(stats(&c, "pages").0, 0);
    }

    #[test]
    fn replay_strip_removes_set_cookie_only() {
        let hs = vec![
            ("Content-Type".into(), "text/html".into()),
            ("Set-Cookie".into(), "sid=steal; Path=/".into()),
            ("set-cookie".into(), "sid2=steal2".into()),
        ];
        let out = strip_for_replay(&hs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "Content-Type");
    }

    #[test]
    fn credential_detection_is_case_insensitive_and_value_free() {
        assert!(request_has_credentials(&[("Cookie".into(), "sid=1".into())]));
        assert!(request_has_credentials(&[(
            "authorization".into(),
            "Bearer x".into()
        )]));
        assert!(!request_has_credentials(&[("accept".into(), "*/*".into())]));
        assert!(response_has_set_cookie(&[("SET-COOKIE".into(), "a=1".into())]));
        assert!(!response_has_set_cookie(&[("cookie".into(), "a=1".into())]));
    }

    #[test]
    fn private_or_identity_varied_responses_never_enter_the_copy_zone() {
        for bad in [
            vec![("Cache-Control".into(), "private".into())],
            vec![("cache-control".into(), "private, max-age=300".into())],
            vec![("Cache-Control".into(), "no-store".into())],
            vec![("Cache-Control".into(), "public, max-age=0".into())],
            vec![("Vary".into(), "Cookie".into())],
            vec![("Vary".into(), "Accept-Encoding, X-Api-Key".into())],
            vec![("Vary".into(), "*".into())],
        ] {
            assert!(
                response_forbids_copy(&bad).is_some(),
                "必须拒绝：{bad:?}"
            );
        }
    }

    #[test]
    fn public_and_unhinted_responses_still_qualify() {
        // 公开可取的静态响应是副本层的主场，别把功能阉掉
        for ok in [
            vec![],
            vec![("Cache-Control".into(), "public, max-age=60".into())],
            // 压缩协商是副本能安全承载的唯一变体维度（头与体原样带走）
            vec![
                ("Cache-Control".into(), "public, max-age=60".into()),
                ("Vary".into(), "accept-encoding".into()),
                ("Content-Encoding".into(), "gzip".into()),
            ],
            vec![("Content-Type".into(), "text/html".into())],
        ] {
            assert_eq!(response_forbids_copy(&ok), None, "应当可存：{ok:?}");
        }
    }

    #[test]
    fn dirty_queue_backs_off_and_stops_rescheduling_immediately() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 65536)]));
        store_all(&c, "pages", "x", "/a");
        let policy = RetryPolicy::default();
        let s = c.lookup("pages", "/a", Duration::from_secs(60)).unwrap();
        c.mark_dirty("pages", "/a", &s, &policy);
        // 并发失败不许把下次重试拉回"立刻"
        c.mark_dirty("pages", "/a", &s, &policy);
        assert_eq!(c.dirty_len(), 1);
        let marked_at = Instant::now();
        assert!(
            c.due_jobs(marked_at).is_empty(),
            "第一次重试要等一个 base 退避"
        );
        let jobs = c.due_jobs(marked_at + policy.base * 2);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].uri, "/a");
        // 重取失败后重新入表：下次仍在未来，且带上了 attempt 计数
        c.requeue(jobs[0].clone());
        let after_first = Instant::now();
        assert!(
            c.due_jobs(after_first).is_empty(),
            "失败后必须退避，不能立刻重试"
        );
        let second = c.due_jobs(after_first + policy.base * 2);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 1, "attempt 随退避递增");
        assert_eq!(c.dirty_len(), 0, "取走即出表");
    }

    #[test]
    fn requeue_gives_up_after_deadline() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 65536)]));
        store_all(&c, "pages", "x", "/a");
        let s = c.lookup("pages", "/a", Duration::from_secs(60)).unwrap();
        let policy = RetryPolicy {
            base: Duration::from_millis(1),
            max: Duration::from_millis(1),
            deadline: Duration::from_millis(1),
        };
        c.mark_dirty("pages", "/a", &s, &policy);
        std::thread::sleep(Duration::from_millis(5));
        let jobs = c.due_jobs(Instant::now());
        assert_eq!(jobs.len(), 1);
        c.requeue(jobs[0].clone());
        assert_eq!(c.dirty_len(), 0, "超过 deadline 不再重取");
        assert!(c.refresh_failed_total.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn refreshed_clears_the_dirty_entry() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 65536)]));
        store_all(&c, "pages", "x", "/a");
        let s = c.lookup("pages", "/a", Duration::from_secs(60)).unwrap();
        c.mark_dirty("pages", "/a", &s, &RetryPolicy::default());
        c.note_refreshed("pages", "/a");
        assert_eq!(c.dirty_len(), 0);
        assert_eq!(c.refreshed_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dirty_queue_is_bounded_so_a_dead_backend_cannot_grow_it() {
        // 每区 4096 B 预算 → dirty_cap 取到下限 1024；灌 1024+ 条看是否停在容量内
        let c = StillOnline::with_budgets(budgets(&[("pages", 4096)]));
        let cap = c.dirty_cap;
        let policy = RetryPolicy::default();
        let s = snap("x", "/seed");
        for i in 0..(cap + 64) {
            c.mark_dirty("pages", &format!("/k{i}"), &s, &policy);
        }
        assert_eq!(c.dirty_len(), cap, "脏表必须有界");
    }

    #[test]
    fn apply_budgets_trims_live_zone() {
        let unit = unit(64, "/k1");
        let c = StillOnline::with_budgets(budgets(&[("pages", 2 * unit)]));
        store_all(&c, "pages", &"a".repeat(64), "/k1");
        store_all(&c, "pages", &"b".repeat(64), "/k2");
        assert_eq!(stats(&c, "pages").0, 2);
        c.apply_budgets(&budgets(&[("pages", unit)]));
        assert_eq!(stats(&c, "pages").0, 1);
    }

    #[test]
    fn zone_rows_lists_declared_but_empty_zones() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 65536), ("empty", 4096)]));
        store_all(&c, "pages", "x", "/a");
        let rows = c.zone_rows();
        assert_eq!(rows.len(), 2, "声明过但还没写过条目的区也要出现在指标里");
        let pages = rows.iter().find(|r| r.0 == "pages").unwrap();
        assert_eq!((pages.1, pages.2, pages.3), (1, unit(1, "/a"), 65536));
        let empty = rows.iter().find(|r| r.0 == "empty").unwrap();
        assert_eq!((empty.1, empty.2), (0, 0));
        assert_eq!(empty.3, 4096);
    }

    #[test]
    fn apply_budgets_drops_removed_zone_and_its_pending_jobs() {
        let c = StillOnline::with_budgets(budgets(&[("pages", 65536)]));
        store_all(&c, "pages", "x", "/a");
        let s = c.lookup("pages", "/a", Duration::from_secs(60)).unwrap();
        c.mark_dirty("pages", "/a", &s, &RetryPolicy::default());
        // 配置里删掉这个区（热重载）：副本与待重取任务都要跟着消失
        c.apply_budgets(&budgets(&[]));
        assert_eq!(stats(&c, "pages"), (0, 0));
        assert_eq!(c.dirty_len(), 0);
    }
}
