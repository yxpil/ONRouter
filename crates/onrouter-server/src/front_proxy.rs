//! front_proxy：厂商无关的"我前面还有一层代理/CDN"感知，以及知道这件事之后的出口模式。
//!
//! 为什么单独一个模块，而不是把厂商名单写进代码：
//!
//! * **判定逻辑里不出现任何厂商名。** 每家前置代理叫什么、用哪个头带真实客户端地址、哪个头带国家/原始协议/
//!   原始 Host、它的边缘网段是哪些，全部由配置里的 `front_proxy <名字> { ... }` 块声明。厂商会改头名、
//!   会轮换网段，写死进代码就是一颗会过期的地雷；而且没有理由为某一家定制行为——差异都是"头名不同"而已。
//!   （本注释里出现的厂商名只是**出处引用**，不在任何代码路径上；release 二进制里搜不到这些名字。
//!   可直接抄的真实声明见 `conf/front_proxy_examples.conf`。）
//! * **识别归识别，信任归网段。** 探针（`probe`）命中只说明"这条请求像是从某家前置代理来的"，它**永远不是**
//!   改写 `$remote_addr` 的授权。授权只有一个来源：直连对端落在声明过的网段里。这条没有开关，因为任何一家的
//!   IP 头都是普通请求头，客户端想发就发——Fastly 文档写明它只在头缺失时补 `Fastly-Client-IP`（收到就不动，
//!   于是可伪造），Cloudflare 说的是客户端自带同名头会被它覆盖（覆盖只发生在经过它的那条路上），AWS 甚至说
//!   光看 IP 段不够、要靠自定义头。三家口径不同，结论相同：头部取值必须有网段做前提。
//!
//! 三档模式：
//!   * `off`（默认）：只解析、不查询，请求路径零开销。
//!   * `detect`：识别并命名（`$front_proxy`、`/metrics`、访问日志），给出不一致告警，**不改任何行为**。
//!   * `egress`：出口模式——地址、协议/Host、国家都按 profile 采用（各自都要过网段闸门），并输出 RFC 9209
//!     `Cache-Status`，让前面那层 CDN 能衡量源站做了多少活。
//!
//! 与 nginx 的关系：nginx 只有 `ngx_http_realip_module` 这一个头，且必须管理员先说清"信哪个头、信哪些网段"。
//! 这里做的是同一个安全前提下的一层泛化：把"一个头"变成"一条按 profile 排好的头链"，把"每次只能配一台"
//! 变成"多份声明 + 运行时按证据择优"。`set_real_ip_from` / `real_ip_header` / `real_ip_recursive` 的语义
//! 完全不变，也仍然是唯一的默认授权根（见 [`decide`]）。

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::{log_debug, log_warn};
use crate::realip::{net_matches, parse_ip_chain, TrustedNet};

/// `front_proxy_mode`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontProxyMode {
    Off,
    Detect,
    Egress,
}

impl FrontProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            FrontProxyMode::Off => "off",
            FrontProxyMode::Detect => "detect",
            FrontProxyMode::Egress => "egress",
        }
    }
}

/// 一条指纹探针：头必须出现；带 `substr` 时值还要（大小写不敏感）包含它。
#[derive(Debug, Clone)]
pub struct Probe {
    pub header: String,
    pub substr: Option<String>,
}

/// 一个 `front_proxy <name> { ... }` 块解析后的产物。计数器是内部可变项，供 `/metrics` 按 profile 展开。
#[derive(Debug)]
pub struct FrontProfile {
    pub name: String,
    pub probes: Vec<Probe>,
    /// 真实客户端地址的候选头，按声明顺序优先。
    pub ip_headers: Vec<String>,
    pub country_header: Option<String>,
    pub proto_header: Option<String>,
    pub host_header: Option<String>,
    /// 本家的边缘网段。为空 ⇒ 本 profile 永远无法自证来源。
    pub trust: Vec<TrustedNet>,
    pub counters: ProfileCounters,
}

#[derive(Debug, Default)]
pub struct ProfileCounters {
    pub matched: AtomicU64,
    pub ip_applied: AtomicU64,
    pub ip_blocked: AtomicU64,
    pub origin_applied: AtomicU64,
    pub origin_blocked: AtomicU64,
    pub country_applied: AtomicU64,
    /// 首次"命中却被闸门挡下"时置位，保证告警只打一条而不是每个请求一条。
    pub warned: AtomicBool,
}

/// 挂在 Server 上的解析产物（与 `Server.real_ip` 同级：server 级开关 + 全局 profile 表）。
#[derive(Debug, Clone)]
pub struct FrontProxyConf {
    pub mode: FrontProxyMode,
    /// `front_proxy_auto_trust on;`：允许 profile 自己声明的网段成为改写 `$remote_addr` 的授权根。
    /// 关闭（默认）时，profile 只用于识别与建议，地址改写仍完全归 `set_real_ip_from` + `real_ip_header`。
    pub auto_trust: bool,
    pub profiles: Arc<Vec<Arc<FrontProfile>>>,
}

impl Default for FrontProxyConf {
    fn default() -> Self {
        FrontProxyConf {
            mode: FrontProxyMode::Off,
            auto_trust: false,
            profiles: Arc::new(Vec::new()),
        }
    }
}

impl FrontProxyConf {
    pub fn enabled(&self) -> bool {
        self.mode != FrontProxyMode::Off && !self.profiles.is_empty()
    }
}

// ==================== 全局 profile 表（供指标与横幅按名字展开） ====================

fn registry() -> &'static Mutex<Vec<Arc<FrontProfile>>> {
    static REG: OnceLock<Mutex<Vec<Arc<FrontProfile>>>> = OnceLock::new();
    REG.get_or_init(Default::default)
}

/// 配置装载时原子替换 profile 表（`Router::build` 与热重载都经过这里）。
pub fn install(profiles: Vec<Arc<FrontProfile>>) {
    let mut g = registry().lock().unwrap_or_else(|e| e.into_inner());
    *g = profiles;
}

pub fn snapshot() -> Vec<Arc<FrontProfile>> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

// ==================== 头部取值（各家的"格式方言"在这里收敛） ====================

fn header_value<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 百分号解码。前置代理会把地址/位置类头的取值按 RFC 3986 §1.2 百分号编码（CloudFront 的文档就这么写），
/// 于是 `2001%3Adb8%3A%3A1` 这种形状要能解；不含 `%` 时直接原样返回。只做能解就解、解不动就返回原值，绝不 panic。
pub fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &bytes[i + 1..i + 3];
            if let Some(b) = std::str::from_utf8(hex)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // 解码后可能不再是合法 UTF-8（客户端乱填），此时退回原值
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// 把一个头的值切成地址链。先走 realip 的解析（裸 IP、`[v6]:port`、`v4:port`、逗号链都覆盖），
/// 解不出再补一种形状：IPv6 被 URL 编码后解码成 `2001:db8::1:46532`，端口与地址都成了冒号分隔，
/// 只有"尾段是纯数字且前段是合法地址"时才敢剥掉端口。
fn chain_of(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .flat_map(|tok| {
            let t = tok.trim();
            let mut got = parse_ip_chain(t);
            if got.is_empty() {
                if let Some((head, port)) = t.rsplit_once(':') {
                    if !port.is_empty()
                        && port.chars().all(|c| c.is_ascii_digit())
                        && port.len() <= 5
                    {
                        if let Ok(ip) = head.parse::<IpAddr>() {
                            got.push(ip);
                        }
                    }
                }
            }
            got
        })
        .collect()
}

/// 从一个"带真实客户端 IP"的头值里取地址。支持三种已知形状，全部走同一套解析：
/// 裸 IP、`a, b, c` 逗号链（XFF）、`ip:port` / `[v6]:port`（CloudFront-Viewer-Address 形状）。
/// 语义与 realip 一致：`recursive` 关取最右，开则从右往左跳过仍可信的地址。
pub fn ip_from_value(value: &str, skip_nets: &[TrustedNet], recursive: bool) -> Option<IpAddr> {
    let value = percent_decode(value.trim());
    let chain = chain_of(&value);
    if chain.is_empty() {
        return None;
    }
    if !recursive {
        return chain.last().copied();
    }
    let is_trusted = |ip: &IpAddr| skip_nets.iter().any(|n| net_matches(ip, n));
    chain.iter().rev().find(|ip| !is_trusted(ip)).or(chain.first()).copied()
}

/// 从协议头里取原始 scheme。形状至少三种：`https`、`https, http`（多级追加）、
/// `{"scheme":"https","ssl_protocol":"TLSv1.3"}`（JSON）。取不到 http/https 就当没有。
pub fn scheme_from_value(value: &str) -> Option<String> {
    let v = value.trim();
    if v.starts_with('{') {
        // 只认 "scheme" 这一个键，不做完整 JSON 解析（值里可能带任意空白与相邻键）
        let key = "\"scheme\"";
        let at = v.find(key)? + key.len();
        let rest = v[at..].find(':')?;
        let after = &v[at + rest + 1..].trim_start()[..];
        let begin = after.find('"')? + 1;
        let end = begin + after[begin..].find('"')?;
        return normalize_scheme(&after[begin..end]);
    }
    // 逗号链：最左一级是客户端与最外层 CDN 之间用的协议
    for part in v.split(',') {
        if let Some(s) = normalize_scheme(part) {
            return Some(s);
        }
    }
    None
}

fn normalize_scheme(raw: &str) -> Option<String> {
    let t = raw.trim().to_ascii_lowercase();
    match t.as_str() {
        "https" | "on" | "ssl" | "1" => Some("https".to_string()),
        "http" | "off" | "0" => Some("http".to_string()),
        _ => None,
    }
}

/// 国家/地区码头：只接受两个字母，其余一律当作没有（这个值会进日志与变量，不能原样透传）。
pub fn country_from_value(value: &str) -> Option<String> {
    let t = value.trim();
    if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(t.to_ascii_uppercase())
    } else {
        None
    }
}

/// Host 头：去掉端口、拒绝空值与任何控制字符（它会被拼进生成的 Location 与缓存 key）。
pub fn host_from_value(value: &str) -> Option<String> {
    let t = value.trim().split(',').next().unwrap_or("").trim();
    let t = t.rsplit_once(':').map(|(h, _)| h).unwrap_or(t);
    if t.is_empty()
        || t.len() > 253
        || !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

// ==================== 匹配与决策 ====================

pub struct Candidate<'a> {
    pub profile: &'a FrontProfile,
    /// 直连对端是否落在"profile 自己的网段 ∪ set_real_ip_from"里。这是唯一的授权前提。
    pub verified: bool,
}

/// 按证据择优：先看对端能否验证（伪造者进不了网段），再看探针条数（越多越特异），同分先声明者胜。
pub fn match_profile<'a>(
    profiles: &'a [Arc<FrontProfile>],
    headers: &[(String, String)],
    peer: Option<IpAddr>,
    extra_nets: &[TrustedNet],
) -> Option<Candidate<'a>> {
    let mut best: Option<((u8, usize), Candidate<'a>)> = None;
    for p in profiles.iter() {
        if p.probes.is_empty() {
            continue; // 没有探针的 profile 不参与匹配（否则等于"所有请求都算这家"）
        }
        let hits = p
            .probes
            .iter()
            .filter(|pr| match header_value(headers, &pr.header) {
                Some(v) => match &pr.substr {
                    Some(s) => v.to_ascii_lowercase().contains(&s.to_ascii_lowercase()),
                    None => true,
                },
                None => false,
            })
            .count();
        if hits != p.probes.len() {
            continue; // AND 语义：所有探针都要命中
        }
        let verified = peer
            .map(|ip| {
                p.trust.iter().any(|n| net_matches(&ip, n))
                    || extra_nets.iter().any(|n| net_matches(&ip, n))
            })
            .unwrap_or(false);
        let rank = (verified as u8, hits);
        // 严格大于：平级不替换，于是先声明的 profile 胜出
        if best.as_ref().map(|(r, _)| &rank > r).unwrap_or(true) {
            best = Some((rank, Candidate { profile: p, verified }));
        }
    }
    best.map(|(_, cand)| cand)
}

/// realip 现状，用来判断 profile 的建议与管理员的配置是否说的是同一个头。
pub struct RealIpState<'a> {
    pub enabled: bool,
    pub header: &'a str,
    pub trusted: &'a [TrustedNet],
    pub recursive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// profile 命中但没有网段可验证：头是客户端自己发的，一个都不许采信。
    Unverified,
    /// `front_proxy_auto_trust` 未开：识别到了，但授权仍只认 `real_ip_header`，于是只建议不改写。
    AutoTrustOff,
    /// 开了 auto_trust 也验证了来源，但头链里没有一个给出可用地址（都没出现，或值不是 IP）。
    NoUsableIp,
}

impl Blocked {
    pub fn as_str(self) -> &'static str {
        match self {
            Blocked::Unverified => "对端不在任何声明过的网段里（来源无法验证）",
            Blocked::AutoTrustOff => "front_proxy_auto_trust 未开（识别归识别，信任要配置）",
            Blocked::NoUsableIp => "ip_header 链里没有任何一个头给出可用地址",
        }
    }
}

/// 一个请求的出口模式决策结果。字段都是"该写进 ctx 的值"，写与不写由 server.rs 决定。
#[derive(Default)]
pub struct Decision {
    pub profile: Option<String>,
    pub verified: bool,
    pub real_ip: Option<String>,
    pub ip_source: Option<String>,
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub country: Option<String>,
    pub blocked: Option<Blocked>,
}

/// 纯决策函数：输入请求头 + 直连对端 + realip 现状，输出该采用什么、为什么没采用。
///
/// 硬规则（无开关）：**任何头部取值（地址、协议、Host、国家）都要求直连对端落在
/// `profile.trust ∪ set_real_ip_from` 内**。`auto_trust` 只决定"profile 自己的网段能否授权改写
/// `$remote_addr`"，不能绕过对端验证。
pub fn decide(
    conf: &FrontProxyConf,
    headers: &[(String, String)],
    peer: Option<IpAddr>,
    realip: &RealIpState<'_>,
) -> Decision {
    let mut d = Decision::default();
    if !conf.enabled() {
        return d;
    }
    let cand = match match_profile(&conf.profiles, headers, peer, realip.trusted) {
        Some(c) => c,
        None => return d,
    };
    let p = cand.profile;
    d.profile = Some(p.name.clone());
    d.verified = cand.verified;
    p.counters.matched.fetch_add(1, Ordering::Relaxed);

    if conf.mode == FrontProxyMode::Detect {
        return d;
    }

    // ---- 真实客户端地址 ----
    if let Some((ip, from)) = pick_ip(conf, p, headers, cand.verified, realip, &mut d) {
        d.real_ip = Some(ip.to_string());
        d.ip_source = Some(from);
    }

    // ---- 来源侧的协议 / Host / 国家：同样要过验证闸门 ----
    if cand.verified {
        if let Some(h) = &p.proto_header {
            if let Some(s) = header_value(headers, h).and_then(scheme_from_value) {
                d.scheme = Some(s);
                p.counters.origin_applied.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(h) = &p.host_header {
            if let Some(sv) = header_value(headers, h).and_then(host_from_value) {
                d.host = Some(sv);
            }
        }
        if let Some(h) = &p.country_header {
            if let Some(c) = header_value(headers, h).and_then(country_from_value) {
                d.country = Some(c);
                p.counters.country_applied.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else if p.proto_header.is_some() || p.host_header.is_some() {
        d.blocked.get_or_insert(Blocked::Unverified);
        p.counters.origin_blocked.fetch_add(1, Ordering::Relaxed);
    }

    advise(p, &d);
    d
}

/// 地址链选择。返回 `(地址, 来源头名)`；被挡下时把原因写进 `d.blocked` 并计数。
fn pick_ip(
    conf: &FrontProxyConf,
    p: &FrontProfile,
    headers: &[(String, String)],
    verified: bool,
    realip: &RealIpState<'_>,
    d: &mut Decision,
) -> Option<(IpAddr, String)> {
    if !conf.auto_trust {
        // 默认档：profile 不碰地址。但要说清"你以为在按真客户端限流，其实按的是节点地址"。
        // 只有当 real_ip_header 根本不在本 profile 认可的头链里时才算不一致——
        // 在里面就说明两处配置说的是同一个来源，地址已经由 realip 正确落地。
        let agrees = realip.enabled
            && p.ip_headers.iter().any(|h| h.eq_ignore_ascii_case(realip.header));
        if !p.ip_headers.is_empty() && !agrees {
            d.blocked.get_or_insert(Blocked::AutoTrustOff);
            p.counters.ip_blocked.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    if !verified {
        d.blocked = Some(Blocked::Unverified);
        p.counters.ip_blocked.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let skip = nets_for(p, realip);
    for h in &p.ip_headers {
        if let Some(v) = header_value(headers, h) {
            if let Some(ip) = ip_from_value(v, &skip, realip.recursive) {
                p.counters.ip_applied.fetch_add(1, Ordering::Relaxed);
                if realip.enabled && !h.eq_ignore_ascii_case(realip.header) {
                    log_debug!(
                        "front_proxy '{}'：地址取自 {h}，而 real_ip_header 是 {}，后者优先级只在 auto_trust 下生效",
                        p.name,
                        realip.header
                    );
                }
                return Some((ip, h.clone()));
            }
        }
    }
    d.blocked.get_or_insert(Blocked::NoUsableIp);
    p.counters.ip_blocked.fetch_add(1, Ordering::Relaxed);
    None
}

/// 递归剔除时要跳过的地址集合 = 本 profile 的网段 ∪ 管理员声明的 set_real_ip_from。
/// 顺带解决"链里最后一跳是我自己另一台代理"导致的取错值。
fn nets_for(p: &FrontProfile, realip: &RealIpState<'_>) -> Vec<TrustedNet> {
    let mut v: Vec<TrustedNet> = p.trust.to_vec();
    for n in realip.trusted {
        if !v.iter().any(|x| x.net == n.net && x.prefix == n.prefix) {
            v.push(*n);
        }
    }
    v
}

/// 首次命中却被挡下时打一条可执行的告警（同一个 profile 只打一次，避免刷屏）。
pub fn advise(p: &FrontProfile, d: &Decision) {
    let Some(reason) = d.blocked else { return };
    if p.counters.warned.swap(true, Ordering::Relaxed) {
        return;
    }
    log_warn!(
        "front_proxy '{}' 命中但来源判定没走通：{}。本 profile 的 ip_header 链=[{}]，trust 网段 {} 条。\
         要让 ONRouter 按真实客户端计数，要么把这些网段写进 set_real_ip_from，要么显式开 \
         front_proxy_auto_trust on;（前者更安全：网段过期只会退回按节点地址计数，不会退回到可伪造）",
        p.name,
        reason.as_str(),
        if p.ip_headers.is_empty() { "（未声明）".to_string() } else { p.ip_headers.join(" → ") },
        p.trust.len()
    );
}

/// RFC 9209 `Cache-Status` 里本节点那一条。ONRouter 作为源站把自己那层缓存判定报给前置 CDN，
/// 让它能衡量"回源有多少是真活、多少是命中"。detail 用规范的小写集合；认不出的状态就只报节点名。
pub fn cache_status_field(state: &str) -> String {
    let detail = match state.trim().to_ascii_uppercase().as_str() {
        "HIT" => Some("hit"),
        "MISS" => Some("miss"),
        "STALE" => Some("stale"),
        "BYPASS" => Some("bypass"),
        "REVALIDATED" | "EXPIRED" => Some("proxy-revalidated"),
        _ => None,
    };
    match detail {
        Some(d) => format!("onrouter; detail={d}"),
        None => "onrouter".to_string(),
    }
}

/// 上游若已带 `Cache-Status`，它的条目在前（离源站更近），本节点追加在后；已经出现过就不重复。
pub fn append_cache_status(existing: Option<&str>, ours: &str) -> String {
    match existing {
        None | Some("") => ours.to_string(),
        Some(prev) if prev.contains("onrouter") => prev.to_string(),
        Some(prev) => format!("{prev}, {ours}"),
    }
}

/// 启动横幅用的一句话：声明了几家、各自靠什么识别、地址链是什么。
pub fn describe(profiles: &[Arc<FrontProfile>]) -> String {
    if profiles.is_empty() {
        return "未声明任何 front_proxy（front_proxy_mode 保持 off）".to_string();
    }
    profiles
        .iter()
        .map(|p| {
            format!(
                "'{}'（探针 {} 个、ip_header 链 [{}]、trust 网段 {} 条）",
                p.name,
                p.probes.len(),
                p.ip_headers.join(" → "),
                p.trust.len()
            )
        })
        .collect::<Vec<_>>()
        .join("；")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realip::parse_trusted_net;

    fn net(s: &str) -> TrustedNet {
        parse_trusted_net(s).unwrap()
    }
    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn hdr(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    fn profile(name: &str) -> FrontProfile {
        FrontProfile {
            name: name.to_string(),
            probes: vec![Probe { header: "x-front-id".into(), substr: None }],
            ip_headers: vec!["x-real-client".into(), "x-forwarded-for".into()],
            country_header: Some("x-front-country".into()),
            proto_header: Some("x-front-visitor".into()),
            host_header: Some("x-forwarded-host".into()),
            trust: vec![],
            counters: ProfileCounters::default(),
        }
    }

    fn conf(profiles: Vec<FrontProfile>, mode: FrontProxyMode, auto_trust: bool) -> FrontProxyConf {
        FrontProxyConf {
            mode,
            auto_trust,
            profiles: Arc::new(profiles.into_iter().map(Arc::new).collect()),
        }
    }

    fn realip_off() -> RealIpState<'static> {
        RealIpState { enabled: false, header: "x-real-ip", trusted: &[], recursive: false }
    }

    fn req() -> Vec<(String, String)> {
        vec![
            hdr("X-Front-Id", "abc123"),
            hdr("X-Real-Client", "203.0.113.9"),
            hdr("X-Forwarded-For", "198.51.100.7, 203.0.113.9"),
            hdr("X-Front-Country", "cn"),
            hdr("X-Front-Visitor", "{\"scheme\":\"https\",\"ssl_protocol\":\"TLSv1.3\"}"),
            hdr("X-Forwarded-Host", "www.example.org:443"),
        ]
    }

    #[test]
    fn probe_hit_without_a_trusted_peer_grants_nothing() {
        // 客户端自己伪造全套厂商头：一个字段都不许采信
        let c = conf(vec![profile("edge")], FrontProxyMode::Egress, true);
        let d = decide(&c, &req(), Some(v4("8.8.8.8")), &realip_off());
        assert_eq!(d.profile.as_deref(), Some("edge"), "识别本身不要求可信");
        assert!(!d.verified);
        assert_eq!(d.real_ip, None);
        assert_eq!(d.scheme, None, "协议头没采信，否则会生成 http:// 的跳转降级");
        assert_eq!(d.host, None);
        assert_eq!(d.country, None);
        assert_eq!(d.blocked, Some(Blocked::Unverified));
    }

    #[test]
    fn auto_trust_off_means_recognition_only() {
        let mut p = profile("edge");
        p.trust = vec![net("192.0.2.0/24")];
        let c = conf(vec![p], FrontProxyMode::Egress, false);
        let d = decide(&c, &req(), Some(v4("192.0.2.5")), &realip_off());
        assert!(d.verified);
        assert_eq!(d.real_ip, None, "默认档不许改地址");
        assert_eq!(d.blocked, Some(Blocked::AutoTrustOff));
        // 协议与 Host 属于"来源侧元数据"，网段验证过就可以采用
        assert_eq!(d.scheme.as_deref(), Some("https"));
        assert_eq!(d.host.as_deref(), Some("www.example.org"));
        assert_eq!(d.country.as_deref(), Some("CN"));
    }

    #[test]
    fn auto_trust_on_follows_the_header_chain_in_order() {
        let mut p = profile("edge");
        p.trust = vec![net("192.0.2.0/24")];
        let c = conf(vec![p], FrontProxyMode::Egress, true);
        let d = decide(&c, &req(), Some(v4("192.0.2.5")), &realip_off());
        assert_eq!(d.real_ip.as_deref(), Some("203.0.113.9"), "首选头优先");
        assert_eq!(d.ip_source.as_deref(), Some("x-real-client"));
    }

    #[test]
    fn chain_falls_through_when_the_first_header_is_junk() {
        let mut p = profile("edge");
        p.trust = vec![net("192.0.2.0/24")];
        let mut r = req();
        r[1] = hdr("X-Real-Client", "not-an-ip");
        let c = conf(vec![p], FrontProxyMode::Egress, true);
        let d = decide(&c, &r, Some(v4("192.0.2.5")), &realip_off());
        assert_eq!(d.real_ip.as_deref(), Some("203.0.113.9"), "按链落到下一个候选头");
        assert_eq!(d.ip_source.as_deref(), Some("x-forwarded-for"));
    }

    #[test]
    fn recursive_skips_addresses_inside_the_declared_ranges() {
        let mut p = profile("edge");
        p.trust = vec![net("192.0.2.0/24"), net("198.51.100.0/24")];
        let c = conf(vec![p], FrontProxyMode::Egress, true);
        let mut ri = realip_off();
        ri.recursive = true;
        // 链里 198.51.100.7 也属于本 profile 网段（另一层代理），真实客户端是 203.0.113.9；
        // 首选头没有值，走 XFF 时必须跳过可信跳。
        let r = vec![hdr("X-Front-Id", "1"), hdr("X-Real-Client", ""), hdr("X-Forwarded-For", "203.0.113.9, 198.51.100.7")];
        let d = decide(&c, &r, Some(v4("192.0.2.5")), &ri);
        assert_eq!(d.real_ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn set_real_ip_from_alone_is_enough_to_verify_origin_metadata() {
        // 管理员只写了 set_real_ip_from，profile 没写 trust：网段验证仍成立（授权根是他自己给的）
        let c = conf(vec![profile("edge")], FrontProxyMode::Egress, false);
        static NETS: std::sync::OnceLock<Vec<TrustedNet>> = std::sync::OnceLock::new();
        let nets = NETS.get_or_init(|| vec![net("192.0.2.0/24")]);
        let ri = RealIpState { enabled: true, header: "x-forwarded-for", trusted: nets, recursive: false };
        let d = decide(&c, &req(), Some(v4("192.0.2.9")), &ri);
        assert!(d.verified);
        assert_eq!(d.scheme.as_deref(), Some("https"));
        // real_ip_header 已经是 profile 首选链里的头之一 ⇒ 不存在"两处说两种话"
        assert_eq!(d.blocked, None);
    }

    #[test]
    fn profiles_are_compared_by_evidence_not_declaration_order() {
        let mut generic = profile("generic");
        generic.probes = vec![Probe { header: "x-front-id".into(), substr: None }];
        generic.trust = vec![net("198.51.100.0/24")]; // 对端不在此段
        let mut specific = profile("specific");
        specific.probes = vec![
            Probe { header: "x-front-id".into(), substr: None },
            Probe { header: "x-front-country".into(), substr: Some("cn".into()) },
        ];
        // 只有 1 个探针，但对端在它的网段里 ⇒ 证据更强，胜过 2 探针却验证不了的
        specific.trust = vec![net("192.0.2.0/24")];
        let c = conf(vec![generic, specific], FrontProxyMode::Detect, false);
        let d = decide(&c, &req(), Some(v4("192.0.2.1")), &realip_off());
        assert_eq!(d.profile.as_deref(), Some("specific"));
        let d2 = decide(&c, &req(), Some(v4("198.51.100.1")), &realip_off());
        assert_eq!(d2.profile.as_deref(), Some("generic"));
    }

    #[test]
    fn value_dialects_all_parse() {
        // 裸 IP / 逗号链 / ip:port / URL 编码 IPv6
        assert_eq!(ip_from_value("203.0.113.9", &[], false), Some(v4("203.0.113.9")));
        assert_eq!(ip_from_value("198.51.100.7:46532", &[], false), Some(v4("198.51.100.7")));
        // 整段 URL 编码的 IPv6 + 端口：解码后 9 段不是合法地址，只有"尾段纯数字且前段合法"才剥端口
        assert_eq!(
            ip_from_value("2001%3A0db8%3A0%3A0%3A0%3A0%3A0%3A1%3A46532", &[], false)
                .map(|i| i.to_string()),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(ip_from_value("", &[], false), None);
        assert_eq!(ip_from_value("unknown, unknown", &[], false), None);
        // 协议三种形状
        assert_eq!(scheme_from_value("https").as_deref(), Some("https"));
        assert_eq!(scheme_from_value("https, http").as_deref(), Some("https"));
        assert_eq!(
            scheme_from_value(r#"{"scheme":"https","ssl_protocol":"TLSv1.3"}"#).as_deref(),
            Some("https")
        );
        assert_eq!(scheme_from_value("{\"scheme\":\"\"}"), None);
        assert_eq!(scheme_from_value("javascript:alert(1)"), None);
        // 国家与 Host 的取值边界
        assert_eq!(country_from_value("cn").as_deref(), Some("CN"));
        assert_eq!(country_from_value("CN;evil"), None);
        assert_eq!(country_from_value(""), None);
        assert_eq!(host_from_value("WWW.Example.ORG:443").as_deref(), Some("www.example.org"));
        assert_eq!(host_from_value("a\r\nSet-Cookie: x=1"), None);
        assert_eq!(host_from_value(""), None);
        assert_eq!(percent_decode("2001%3Adb8"), "2001:db8");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
    }

    #[test]
    fn cache_status_line_follows_rfc_9209_and_appends() {
        assert_eq!(cache_status_field("HIT"), "onrouter; detail=hit");
        assert_eq!(cache_status_field("STALE"), "onrouter; detail=stale");
        assert_eq!(cache_status_field("revalidated"), "onrouter; detail=proxy-revalidated");
        // 认不出的状态只报节点名，不编造 detail
        assert_eq!(cache_status_field(""), "onrouter");
        assert_eq!(cache_status_field("WTF"), "onrouter");
        assert_eq!(append_cache_status(None, "onrouter; detail=hit"), "onrouter; detail=hit");
        assert_eq!(
            append_cache_status(Some("fastly; detail=miss"), "onrouter; detail=hit"),
            "fastly; detail=miss, onrouter; detail=hit"
        );
        // 同一条链上经过两次（自己的上游也是本机）不重复记账
        assert_eq!(
            append_cache_status(Some("onrouter; detail=hit"), "onrouter; detail=miss"),
            "onrouter; detail=hit"
        );
    }

    #[test]
    fn describe_lists_the_declared_evidence() {
        let mut p = profile("edge");
        p.ip_headers = vec!["x-real-client".into(), "x-forwarded-for".into()];
        p.trust = vec![net("192.0.2.0/24")];
        let s = describe(&[Arc::new(p)]);
        assert!(s.contains("'edge'"), "{s}");
        assert!(s.contains("x-real-client → x-forwarded-for"), "{s}");
        assert!(s.contains("trust 网段 1 条"), "{s}");
        assert!(describe(&[]).contains("front_proxy_mode 保持 off"));
    }

    #[test]
    fn off_mode_does_not_even_look_at_headers() {
        let c = conf(vec![profile("edge")], FrontProxyMode::Off, true);
        let d = decide(&c, &req(), Some(v4("192.0.2.5")), &realip_off());
        assert_eq!(d.profile, None);
        assert!(!c.enabled());
        // 空表也等于关闭
        let empty = conf(vec![], FrontProxyMode::Egress, true);
        assert!(!empty.enabled());
    }

    #[test]
    fn probe_with_no_substring_and_empty_probe_list() {
        // 没有探针的 profile 不参与匹配：否则它对所有请求都命中
        let mut p = profile("no-probe");
        p.probes.clear();
        let c = conf(vec![p], FrontProxyMode::Detect, true);
        assert_eq!(decide(&c, &req(), Some(v4("192.0.2.5")), &realip_off()).profile, None);
        // substr 不匹配 ⇒ 整个 profile 不命中
        let mut q = profile("with-sub");
        q.probes = vec![Probe { header: "x-front-id".into(), substr: Some("zzz".into()) }];
        let cq = conf(vec![q], FrontProxyMode::Detect, true);
        assert_eq!(decide(&cq, &req(), Some(v4("192.0.2.5")), &realip_off()).profile, None);
    }
}
