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
//! - `limit_req` 为令牌桶语义的**拒绝式**实现（等价 nginx `nodelay`：不做延迟排队，超限直接回状态码）。
//! - 判定发生在 PREACCESS 位置（access 鉴权之前），与 nginx 阶段顺序一致。
//! - 状态表按 key 哈希分 32 片，各片独立锁；每片容量上限 + 插入序淘汰，
//!   防止攻击者用海量 key 把限流表本身变成内存 DoS（自研限流最容易漏的一点）。
//! - 时间基准用单调毫秒，NTP 校时回拨不会导致额度暴涨。

use std::collections::{HashMap, VecDeque};
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
    /// 可用令牌（1.0 = 允许一个请求）
    tokens: f64,
    updated_ms: i64,
}

#[derive(Debug, Default)]
struct ReqShard {
    map: HashMap<String, ReqState>,
    order: VecDeque<String>,
}

pub struct ReqZone {
    pub name: String,
    pub rate_per_sec: f64,
    /// zone 级默认 burst
    pub burst: f64,
    /// 限流依据的变量；目前只支持按客户端地址计数
    pub key_var: String,
    shards: Vec<Mutex<ReqShard>>,
}

impl ReqZone {
    fn new(name: &str, rate_per_sec: f64, burst: f64, key_var: &str) -> Arc<Self> {
        Arc::new(ReqZone {
            name: name.to_string(),
            rate_per_sec,
            burst,
            key_var: key_var.to_string(),
            shards: (0..SHARDS).map(|_| Mutex::new(ReqShard::default())).collect(),
        })
    }

    /// 放行返回 None；拒绝返回 Some(建议 Retry-After 秒数)
    pub fn check(&self, key: &str, burst_override: Option<f64>) -> Option<u64> {
        let burst = burst_override.unwrap_or(self.burst).max(0.0);
        let capacity = burst + 1.0;
        let refill_per_ms = self.rate_per_sec / 1000.0;
        let now = now_ms();
        let mut shard = self.shards[shard_of(key)].lock().unwrap_or_else(|e| e.into_inner());

        if let Some(st) = shard.map.get_mut(key) {
            st.tokens = (st.tokens + (now - st.updated_ms).max(0) as f64 * refill_per_ms).min(capacity);
            st.updated_ms = now;
            if st.tokens >= 1.0 {
                st.tokens -= 1.0;
                None
            } else {
                let wait_ms = ((1.0 - st.tokens) / refill_per_ms.max(1e-9)) as u64;
                Some(wait_ms.div_ceil(1000).max(1))
            }
        } else {
            if shard.map.len() >= PER_SHARD_CAPACITY {
                if let Some(old) = shard.order.pop_front() {
                    shard.map.remove(&old);
                }
            }
            shard.map.insert(
                key.to_string(),
                ReqState { tokens: capacity - 1.0, updated_ms: now },
            );
            shard.order.push_back(key.to_string());
            None
        }
    }

    /// 清理长期闲置 key（后台定时调用，防表膨胀）。
    /// map 与 order 都一次 retain 完成：旧实现逐 key `position + remove`，大表时是 O(n²)。
    pub fn purge_idle(&self, idle_ms: i64) -> usize {
        let now = now_ms();
        let mut removed = 0usize;
        for s in &self.shards {
            let mut shard = s.lock().unwrap_or_else(|e| e.into_inner());
            let shard = &mut *shard;
            let (map, order) = (&mut shard.map, &mut shard.order);
            let before = map.len();
            map.retain(|_, st| now - st.updated_ms <= idle_ms);
            removed += before - map.len();
            if map.len() != before {
                order.retain(|k| map.contains_key(k));
            }
        }
        removed
    }
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
            shards: (0..SHARDS).map(|_| Mutex::new(ConnShard::default())).collect(),
        })
    }

    /// 占用一个并发额度；超限返回 None。成功返回 RAII，drop 时释放。
    pub fn try_acquire(self: &Arc<Self>, key: &str, number: u32) -> Option<ConnGuard> {
        let mut shard = self.shards[shard_of(key)].lock().unwrap_or_else(|e| e.into_inner());
        let n = shard.map.get(key).copied().unwrap_or(0);
        if n >= number {
            return None;
        }
        if !shard.map.contains_key(key) && shard.map.len() >= PER_SHARD_CAPACITY {
            // 状态表满：优先淘汰已归零的 key；无可淘汰项时按 nginx 的 shm 耗尽语义拒绝新连接
            match shard.map.iter().find(|(_, v)| **v == 0).map(|(k, _)| k.clone()) {
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
        let mut shard = self.shards[shard_of(key)].lock().unwrap_or_else(|e| e.into_inner());
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
}

/// 目前限流只支持按客户端地址计数（其余变量需要 nginx 的 shared 变量体系）
fn addr_var(v: &str) -> bool {
    matches!(v, "$remote_addr" | "$binary_remote_addr")
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
                        if !addr_var(&var) {
                            l.warnings.push(format!(
                                "limit_req_zone '{name}' 的 key '{var}' 暂不支持（仅 $remote_addr / $binary_remote_addr），该区域按客户端地址限流"
                            ));
                        }
                        l.req_zones
                            .insert(name.clone(), ReqZone::new(&name, rate, burst, &var));
                    }
                    None => l
                        .warnings
                        .push(format!("limit_req_zone（第 {} 行）缺少变量、zone= 或 rate=", d.line)),
                },
                "limit_conn_zone" => match parse_conn_zone(d) {
                    Some((var, name)) => {
                        if !addr_var(&var) {
                            l.warnings.push(format!(
                                "limit_conn_zone '{name}' 的 key '{var}' 暂不支持（仅 $remote_addr / $binary_remote_addr），该区域按客户端地址限流"
                            ));
                        }
                        l.conn_zones
                            .insert(name.clone(), ConnZone::new(&name, &var));
                    }
                    None => l
                        .warnings
                        .push(format!("limit_conn_zone（第 {} 行）缺少变量或 zone=", d.line)),
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

    /// 启动时打印的区域概况（运维只看日志就要知道限流到底生效了什么）
    pub fn describe(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .req_zones
            .values()
            .map(|z| {
                format!(
                    "limit_req zone={} rate={:.1}r/s burst={:.0} key={}",
                    z.name, z.rate_per_sec, z.burst, z.key_var
                )
            })
            .collect();
        out.extend(self.conn_zones.values().map(|z| {
            format!("limit_conn zone={} key={}", z.name, z.key_var)
        }));
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
        assert!(z2.check("k", Some(0.0)).is_none(), "覆盖为 0 时首个请求仍可放行");
    }

    #[test]
    fn tokens_refill_over_time() {
        let z = ReqZone::new("t", 1000.0, 0.0, "$remote_addr");
        assert!(z.check("k", None).is_none());
        assert!(z.check("k", None).is_some());
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(z.check("k", None).is_none(), "1000r/s 下 10ms 应补回令牌");
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
            desc.iter().any(|s| s.contains("zone=allr") && s.contains("rate=10.0r/s")
                && s.contains("burst=20") && s.contains("key=$remote_addr")),
            "describe: {desc:?}"
        );
        assert!(desc.iter().any(|s| s.contains("zone=allc") && s.contains("key=$binary_remote_addr")));
        let z = l.req_zone("allr").unwrap();
        assert!((z.rate_per_sec - 10.0).abs() < 1e-9);
        assert_eq!(z.burst, 20.0);
        assert!(l.conn_zone("allc").is_some());
        assert!(l.req_zone("nope").is_none(), "未声明的 zone 不应凭空出现");
    }

    #[test]
    fn purge_idle_removes_stale_keys() {        let z = ReqZone::new("t", 10.0, 0.0, "$remote_addr");
        z.check("a", None);
        z.check("b", None);
        // 全部视为已闲置
        assert_eq!(z.purge_idle(-1), 2);
        assert!(z.purge_idle(1_000_000) == 0);
    }

    #[test]
    fn unsupported_key_variable_warns_but_still_limits() {
        let cfg = Config::parse("limit_req_zone $uri zone=u:1m rate=1r/s;").unwrap();
        let l = Limits::parse_all(&cfg);
        assert!(l.warnings.iter().any(|w| w.contains("$uri")), "{:?}", l.warnings);
        assert!(l.req_zone("u").unwrap().check("/", None).is_none());
        assert!(l.req_zone("u").unwrap().check("/", None).is_some());
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
}
