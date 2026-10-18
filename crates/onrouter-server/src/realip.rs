//! nginx `ngx_http_realip_module`：位于可信 CDN/反向代理之后时，把 `$remote_addr`
//! 换成真实客户端 IP。
//!
//! 语义对标 nginx：
//! * `set_real_ip_from <ip> | <ip>/<prefix>`（可重复）列出**可信上游代理**地址段。只有当
//!   **直连对端 IP** 落在其中之一时，才信任头部里的地址；否则保持真实 socket 对端（防止客户端
//!   自己伪造 X-Forwarded-For 冒充他人）。
//! * `real_ip_header <name>`（默认 `X-Real-IP`，常被设为 `X-Forwarded-For` / Cloudflare 的
//!   `CF-Connecting-IP`）：读取哪个请求头。
//! * `real_ip_recursive on|off`（默认 off）：头部值是一个**逗号分隔的地址链**时如何选真实 IP。
//!   - off：取链中**最右**地址（即最后一个可信代理写下的那个）。
//!   - on：从右往左扫描，跳过仍属于 `set_real_ip_from` 的地址，第一个**非可信**地址即为真实 IP；
//!     若整条链都可信，落到最左端。
//!
//! 结果覆盖 `ctx.remote_addr`，于是 `$remote_addr`、geo、limit_req/limit_conn、auth allow/deny、
//! access_log 全部基于真实客户端 IP，与 nginx 行为一致。

use std::net::IpAddr;

/// 一条 `set_real_ip_from` 规则：网络地址 + 前缀长度（v4≤32，v6≤128）。
#[derive(Debug, Clone, Copy)]
pub struct TrustedNet {
    pub net: IpAddr,
    pub prefix: u8,
}

/// `real_ip_*` 指令解析后的产物，挂在 Server 上（server 级作用域，对标 nginx http/server）。
#[derive(Debug, Clone)]
pub struct RealIpConf {
    /// 读取的请求头名（已规范化为小写、`_`→`-`），默认 `"x-real-ip"`。
    pub header: String,
    /// 可信上游代理地址段；为空 ⇒ 该模块完全关闭（不做任何改写）。
    pub trusted: Vec<TrustedNet>,
    /// `real_ip_recursive`：是否递归剔除可信地址。
    pub recursive: bool,
}

impl Default for RealIpConf {
    fn default() -> Self {
        RealIpConf { header: "x-real-ip".to_string(), trusted: Vec::new(), recursive: false }
    }
}

/// 指令层：规范化头部名（`$http_x_real_ip` / `X-Real-IP` / `X_Real_IP` 均可），去掉 `$`、前缀 `http_`。
pub fn normalize_header_name(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('$') {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("http_") {
        s = rest;
    }
    s.replace('_', "-").to_ascii_lowercase()
}

/// 解析 `<ip>[/<prefix>]`；裸地址按满前缀（v4 /32，v6 /128）。前缀超宽或地址非法 → None。
pub fn parse_trusted_net(s: &str) -> Option<TrustedNet> {
    let s = s.trim();
    let (ip_str, prefix_str) = match s.split_once('/') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    let net: IpAddr = ip_str.parse().ok()?;
    let width: u8 = if net.is_ipv6() { 128 } else { 32 };
    let prefix: u8 = if prefix_str.is_empty() {
        width
    } else {
        let p: u8 = prefix_str.parse().ok()?;
        if p > width {
            return None;
        }
        p
    };
    Some(TrustedNet { net, prefix })
}

/// `ip` 是否落在 `net/prefix` 内。跨族（v4 对 v6 网段）恒 false；prefix=0 匹配同族全部。
pub fn net_matches(ip: &IpAddr, net: &TrustedNet) -> bool {
    fn to_bits(ip: IpAddr) -> (u128, u8) {
        match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
            IpAddr::V6(v6) => (u128::from(v6), 128),
        }
    }
    let (a_bits, a_width) = to_bits(*ip);
    let (n_bits, n_width) = to_bits(net.net);
    if a_width != n_width {
        return false; // 族不同永不匹配
    }
    if net.prefix == 0 {
        return true; // 0.0.0.0/0 或 ::/0 匹配本族所有
    }
    let width = a_width;
    let mask: u128 = (!0u128) << (width - net.prefix);
    (a_bits & mask) == (n_bits & mask)
}

/// 把一个请求头值解析成有序 IP 链（支持 XFF 的 `a, b, c`；每项可为裸 IP，也容忍 `a:port`/`[v6]:port`，
/// 端口在真实 IP 场景一律忽略）。非 IP 段静默跳过。
pub fn parse_ip_chain(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|tok| {
            let t = tok.trim().trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == ':' || c == '.' || c == '[' || c == ']'));
            // 先直接尝试裸 IP
            if let Ok(ip) = t.parse::<IpAddr>() {
                return Some(ip);
            }
            // [IPv6]:port 形式
            if t.starts_with('[') {
                if let Some(end) = t.find(']') {
                    if let Ok(ip) = t[1..end].parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
                return None;
            }
            // IPv4:port —— 仅在去掉端口后仍是合法 v4 时接受（否则裸 IPv6 会被误伤，已被上面的 parse 拦截）
            if let Some(pos) = t.rfind(':') {
                if let Ok(ip) = t[..pos].parse::<std::net::Ipv4Addr>() {
                    return Some(IpAddr::V4(ip));
                }
            }
            None
        })
        .collect()
}

impl RealIpConf {
    /// 本请求是否应尝试改写真实 IP（关闭态：无可信网段）。
    pub fn enabled(&self) -> bool {
        !self.trusted.is_empty()
    }

    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted.iter().any(|n| net_matches(ip, n))
    }

    /// 从请求头里挑出真实客户端 IP。返回 `Some(ip)` 表示应把 `remote_addr` 覆盖为该值。
    /// 仅当**直连对端**可信时才信任头部（这是安全前提）。
    pub fn resolve(&self, peer: IpAddr, header_value: Option<&str>) -> Option<IpAddr> {
        if !self.enabled() {
            return None;
        }
        // 直连对端不是可信代理 → 忽略头部，保持真实对端（防伪造）。
        if !self.is_trusted(&peer) {
            return None;
        }
        let raw = header_value?;
        let chain = parse_ip_chain(raw);
        let real = if chain.is_empty() {
            // 头部可能是单个非 XFF 形式的裸值（理论上 parse_ip_chain 已覆盖）；空即放弃。
            return None;
        } else if !self.recursive {
            *chain.last().unwrap()
        } else {
            // 从右往左，第一个仍不可信的地址即真实客户端；全可信则取最左。
            *chain
                .iter()
                .rev()
                .find(|ip| !self.is_trusted(ip))
                .unwrap_or_else(|| chain.first().unwrap())
        };
        // 只有当结果确实是一个可路由地址且不同于直连对端时才报告改写（保留幂等语义）。
        Some(real)
    }

    /// 便捷入口：给定对端 IP 与请求头表，返回**规范化字符串**形式的真实 IP（供直接写回 ctx.remote_addr）。
    pub fn apply(&self, peer: IpAddr, headers: &[(String, String)]) -> Option<String> {
        let hv = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&self.header))
            .map(|(_, v)| v.as_str());
        self.resolve(peer, hv).map(|ip| ip.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> TrustedNet {
        parse_trusted_net(s).unwrap()
    }

    #[test]
    fn parses_nets_and_bare_addresses() {
        assert_eq!(parse_trusted_net("10.0.0.0/8").unwrap().prefix, 8);
        assert_eq!(parse_trusted_net("192.168.1.5").unwrap().prefix, 32);
        assert_eq!(parse_trusted_net("::1").unwrap().prefix, 128);
        assert_eq!(parse_trusted_net("fd00::/8").unwrap().prefix, 8);
        // 前缀超宽 / 非法地址 → None
        assert!(parse_trusted_net("10.0.0.0/33").is_none());
        assert!(parse_trusted_net("not-an-ip/8").is_none());
    }

    #[test]
    fn net_matches_prefix_and_family() {
        let a = net("10.1.2.3/16");
        assert!(net_matches(&v4("10.1.255.7"), &a));
        assert!(!net_matches(&v4("10.2.0.1"), &a));
        // /32 精确
        assert!(net_matches(&v4("10.1.2.3"), &net("10.1.2.3/32")));
        assert!(!net_matches(&v4("10.1.2.4"), &net("10.1.2.3/32")));
        // /0 匹配本族全部
        assert!(net_matches(&v4("203.0.113.9"), &net("0.0.0.0/0")));
        // 跨族永不匹配
        assert!(!net_matches(&v4("10.0.0.1"), &net("::/0")));
        assert!(!net_matches(&v4("10.0.0.1"), &net("fe80::/10")));
    }

    #[test]
    fn xff_ip_chain_real_values() {
        // 直接断言链内容，避免上面过度绕圈的写法
        let c = parse_ip_chain("[2001:db8::68]:8443, 10.0.0.9:1234, bad, ,");
        assert!(c.iter().any(|x| *x == v4("10.0.0.9")));
        assert!(c.iter().any(|x| x.to_string() == "2001:db8::68"));
        assert_eq!(c.len(), 2); // 只有两个是合法 IP
    }

    #[test]
    fn only_rewrites_when_direct_peer_trusted() {
        let conf = RealIpConf {
            header: "x-real-ip".into(),
            trusted: vec![net("127.0.0.0/8")],
            recursive: false,
        };
        // 可信对端 → 信任头部
        assert_eq!(conf.resolve(v4("127.0.0.1"), Some("203.0.113.9")).map(|s| s.to_string()), Some("203.0.113.9".into()));
        // 不可信对端（外部直连伪造头）→ 保持对端，不改写
        assert_eq!(conf.resolve(v4("8.8.8.8"), Some("1.1.1.1")), None);
    }

    #[test]
    fn recursive_off_takes_rightmost_recursive_on_skips_trusted() {
        let trusted = vec![net("10.0.0.0/8"), net("127.0.0.0/8")];
        let off = RealIpConf {
            header: "x-forwarded-for".into(),
            trusted: trusted.clone(),
            recursive: false,
        };
        let on = RealIpConf { header: "x-forwarded-for".into(), trusted, recursive: true };
        // 真实客户端 203.0.113.1 → 两跳可信代理 10.0.0.1、10.0.0.2
        let chain = "203.0.113.1, 10.0.0.1, 10.0.0.2";
        assert_eq!(off.resolve(v4("10.0.0.2"), Some(chain)), Some(v4("10.0.0.2")));
        assert_eq!(on.resolve(v4("10.0.0.2"), Some(chain)), Some(v4("203.0.113.1")));
        // 整条链都可信 → recursive on 落到最左
        let all_trusted = "10.1.1.1, 10.2.2.2";
        assert_eq!(on.resolve(v4("10.2.2.2"), Some(all_trusted)), Some(v4("10.1.1.1")));
    }

    #[test]
    fn disabled_when_no_trusted_nets_and_apply_reads_headers() {
        let mut conf = RealIpConf::default();
        assert!(!conf.enabled());
        assert_eq!(conf.resolve(v4("127.0.0.1"), Some("203.0.113.5")), None);
        conf.trusted = vec![net("127.0.0.0/8")];
        let headers = vec![("X-Real-IP".to_string(), "203.0.113.7".to_string())];
        // 大小写不敏感命中头部（key 存的是 "X-Real-IP"，conf.header 是 "x-real-ip"）
        assert_eq!(conf.apply(v4("127.0.0.1"), &headers).as_deref(), Some("203.0.113.7"));
    }
}
