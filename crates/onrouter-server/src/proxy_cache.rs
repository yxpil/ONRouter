//! `proxy_cache`：反向代理响应缓存（对标 nginx ngx_http_proxy_cache_module）。
//!
//! 纯内存实现（不做磁盘持久化，也不做 keys_zone 的共享内存段），语义对齐 nginx 的常用子集：
//!   * `proxy_cache <zone>|off;`     —— 命中且未过期直接返回缓存，不再打后端
//!   * `proxy_cache_key <模板>;`      —— 默认 `$scheme$proxy_host$request_uri`
//!   * `proxy_cache_valid [码...] <时长>;` —— 哪些状态码缓存多久；`any` 兜底
//!   * `proxy_cache_methods GET HEAD;`—— 只缓存幂等方法
//!   * `proxy_cache_min_uses N;`      —— 同一 key 至少第 N 次请求才写入（默认 1）
//! 未写 `proxy_cache_valid` 时回落到上游的 `Cache-Control: max-age` / `Expires`；都没有则不缓存。
//!
//! 有意未实现（README 已标注）：`proxy_cache_use_stale`、revalidation（If-None-Match 回源校验）、
//! `purge`、`$upstream_cache_status` 之外的 STALE 语义、磁盘 keys_zone。缓存响应统一带
//! `X-Cache-Status: HIT|MISS|BYPASS|EXPIRED` 头，便于外部验证。

use std::collections::HashMap;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHit {
    /// 命中且新鲜
    Hit,
    /// 命中但已过期（当前无 use_stale，会回源重取 → 记为 MISS）
    Expired,
    /// 无缓存条目
    Miss,
}

#[derive(Default)]
struct Zone {
    entries: HashMap<String, Slot>,
    /// 每个 key 被请求过多少次（用于 min_uses）
    uses: HashMap<String, u32>,
}

/// 每区上限，超过按插入序粗淘汰（够用即可，不追求 LRU 精度）。
const MAX_ENTRIES_PER_ZONE: usize = 4096;

pub struct ProxyCache {
    zones: Mutex<HashMap<String, Zone>>,
}

impl ProxyCache {
    pub fn new() -> Arc<Self> {
        Arc::new(ProxyCache {
            zones: Mutex::new(HashMap::new()),
        })
    }

    /// 查缓存并把该 key 的请求计数 +1（返回自增后的计数，用于 min_uses 判定）。
    /// 对 zone/key 做一次加锁即可完成「查 + 计数」，避免两次加锁间的竞态。
    pub fn lookup(&self, zone: &str, key: &str) -> (CacheHit, Option<Arc<CachedResponse>>, u32) {
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = g.entry(zone.to_string()).or_default();
        let count = {
            let c = z.uses.entry(key.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        match z.entries.get(key) {
            Some(s) if s.expires > Instant::now() => (CacheHit::Hit, Some(s.resp.clone()), count),
            Some(s) => (CacheHit::Expired, Some(s.resp.clone()), count),
            None => (CacheHit::Miss, None, count),
        }
    }

    /// 写入/覆盖一条缓存。ttl<=0 视为不缓存。
    pub fn store(&self, zone: &str, key: &str, resp: CachedResponse, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let z = g.entry(zone.to_string()).or_default();
        if z.entries.len() >= MAX_ENTRIES_PER_ZONE && !z.entries.contains_key(key) {
            // 粗淘汰：清掉最早一半（HashMap 无序，这里近似即可）
            let drop_n = z.entries.len() / 2;
            let keys: Vec<String> = z.entries.keys().take(drop_n).cloned().collect();
            for k in keys {
                z.entries.remove(&k);
            }
        }
        z.entries.insert(
            key.to_string(),
            Slot {
                resp: Arc::new(resp),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// 主动失效一个 key（proxy_cache off/配置变更时可用），返回是否删除。
    #[allow(dead_code)]
    pub fn invalidate(&self, zone: &str, key: &str) -> bool {
        let mut g = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(z) = g.get_mut(zone) {
            z.uses.remove(key);
            return z.entries.remove(key).is_some();
        }
        false
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
}
