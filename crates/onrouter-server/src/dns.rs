//! 异步 DNS 存根解析器：对标 nginx 的 `resolver` 指令 + `resolver_timeout`。
//!
//! nginx 默认在 worker 里用 getaddrinfo（同步、阻塞）解析 proxy_pass 的域名；
//! 配了 `resolver` 后改用非阻塞的异步解析，配合 `valid=` 缓存，避免解析卡住事件循环。
//!
//! ONRouter 采用同样的思路：这里实现一个纯 Rust 的 UDP DNS 存根解析器（A/AAAA，
//! 标准 RFC1035 报文，支持压缩指针），带 TTL 缓存；proxy 转发与 Upgrade 隧道在
//! 连接后端前用它把域名换成 IP 字面量，从而绕过阻塞式 getaddrinfo。
//!
//! 支持的配置指令：
//! ```text
//! resolver 127.0.0.1:5553 valid=30s timeout=5s;
//! resolver_timeout 5s;   # 等价于 resolver 的 timeout=
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::settings::parse_duration;

/// DNS 报文类型：仅用到 A(1) 与 AAAA(28)。
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// 一轮解析最多遍历 nameserver 列表两遍：第一遍全是瞬时错误（超时/收发/报文异常）
/// 且没拿到地址时再给一次机会；NXDOMAIN 等权威否定不做无谓重查。
const DNS_QUERY_ROUNDS: usize = 2;

/// 解析器配置（来自 `resolver` 指令）。
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// 上游 DNS 服务器地址（可配多个，逐个尝试）。
    pub nameservers: Vec<SocketAddr>,
    /// 结果缓存有效期；nginx `valid=` 默认 10s。这里用它覆盖报文 TTL。
    pub valid: Duration,
    /// 单次查询超时；nginx `resolver_timeout` 默认 5s。
    pub timeout: Duration,
    /// 是否解析 AAAA（IPv6）；nginx `ipv6=on` 默认开。
    pub ipv6: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            nameservers: Vec::new(),
            valid: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            ipv6: true,
        }
    }
}

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

/// 进程级共享的异步解析器 + TTL 缓存。
pub struct DnsResolver {
    config: ResolverConfig,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// 多 A/AAAA 记录的轮询游标（按域名）。proxy 侧只取解析结果的首地址，
    /// 不轮换的话第二条及之后的记录永远用不上。
    rotation: Mutex<HashMap<String, usize>>,
    /// 自增查询 ID（简单取 16 位回绕）。
    next_id: Mutex<u16>,
}

impl DnsResolver {
    /// 从配置读取 `resolver` 指令；没有该指令（或名字服务器非法）时返回 None，
    /// proxy 继续走默认 getaddrinfo 路径（保持无 resolver 配置时的既有行为）。
    pub fn from_config(config: &onrouter_config::Config) -> Option<Arc<DnsResolver>> {
        let d = config.find("resolver")?;
        let mut cfg = ResolverConfig::default();
        for arg in &d.args {
            let a = arg.trim();
            if a.is_empty() {
                continue;
            }
            if let Some(rest) = a.strip_prefix("valid=") {
                if let Some(v) = parse_duration(rest) {
                    cfg.valid = v;
                }
                continue;
            }
            if let Some(rest) = a.strip_prefix("timeout=") {
                if let Some(v) = parse_duration(rest) {
                    cfg.timeout = v;
                }
                continue;
            }
            if let Some(rest) = a.strip_prefix("ipv6=") {
                cfg.ipv6 = matches!(rest.trim(), "on" | "true" | "yes" | "1");
                continue;
            }
            // 其余参数按名字服务器地址解析；`[::1]:53` 之类的 IPv6 需带端口或用默认 53
            if let Some(sa) = parse_nameserver(a) {
                cfg.nameservers.push(sa);
            }
        }
        if cfg.nameservers.is_empty() {
            return None;
        }
        // 兼容 `resolver_timeout 5s;` 独立指令（nginx 里 timeout 也能单独写）
        if let Some(v) = config
            .find("resolver_timeout")
            .and_then(|t| t.arg(0))
            .and_then(parse_duration)
        {
            cfg.timeout = v;
        }
        Some(Arc::new(DnsResolver {
            config: cfg,
            cache: Mutex::new(HashMap::new()),
            rotation: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
        }))
    }

    /// 供启动日志展示已配置的名字服务器。
    pub fn nameservers(&self) -> &[SocketAddr] {
        &self.config.nameservers
    }

    fn take_id(&self) -> u16 {
        let mut g = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        *g
    }

    /// 解析主机名为 IP 列表。IP 字面量直接返回（不发 DNS 查询），命中且未过期的缓存即时返回。
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        // 缓存查找（含负缓存：空结果也缓存，避免反复查询不存在的域名）
        if let Some(addrs) = self.cached(host) {
            return if addrs.is_empty() {
                Err(format!("DNS 无记录: {host}（缓存）"))
            } else {
                Ok(self.rotate(host, addrs))
            };
        }

        let mut addrs: Vec<IpAddr> = Vec::new();
        let mut last_err = String::new();
        for _round in 0..DNS_QUERY_ROUNDS {
            // 本轮是否出现过瞬时错误；全是"无记录"时说明是权威否定，不必再查一遍
            let mut had_error = false;
            for ns in self.config.nameservers.iter().copied() {
                // 先查 A（IPv4 优先，与 nginx ipv6=off / 常见 vhost 场景一致）
                match self.query_one(ns, host, TYPE_A).await {
                    Ok(a) => addrs.extend(a),
                    Err(e) => {
                        had_error = true;
                        last_err = e;
                    }
                }
                if addrs.is_empty() && self.config.ipv6 {
                    match self.query_one(ns, host, TYPE_AAAA).await {
                        Ok(a) => addrs.extend(a),
                        Err(e) => {
                            had_error = true;
                            last_err = e;
                        }
                    }
                }
                if !addrs.is_empty() {
                    break;
                }
            }
            if !addrs.is_empty() || !had_error {
                break;
            }
            // 所有 nameserver 都瞬时失败且无地址：进入下一轮重查
        }

        self.store(host, addrs.clone());
        if addrs.is_empty() {
            Err(if last_err.is_empty() {
                format!("DNS 解析失败: {host}")
            } else {
                last_err
            })
        } else {
            Ok(self.rotate(host, addrs))
        }
    }

    /// 按域名轮换多地址顺序：消费方都取首地址，轮换后连续请求会分摊到各条 A/AAAA 记录。
    fn rotate(&self, host: &str, mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        let len = addrs.len();
        if len > 1 {
            let mut g = self.rotation.lock().unwrap_or_else(|e| e.into_inner());
            let idx = g.entry(host.to_string()).or_insert(0);
            addrs.rotate_left(*idx % len);
            *idx = idx.wrapping_add(1);
        }
        addrs
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let e = g.get(host)?;
        if e.expires > Instant::now() {
            Some(e.addrs.clone())
        } else {
            None
        }
    }

    fn store(&self, host: &str, addrs: Vec<IpAddr>) {
        let mut g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(
            host.to_string(),
            CacheEntry {
                addrs,
                expires: Instant::now() + self.config.valid,
            },
        );
    }

    /// 向单个名字服务器发一条查询并解析应答。
    async fn query_one(
        &self,
        ns: SocketAddr,
        host: &str,
        qtype: u16,
    ) -> Result<Vec<IpAddr>, String> {
        let id = self.take_id();
        let query = build_query(id, host, qtype);
        let bind = if ns.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("DNS socket 绑定失败: {e}"))?;
        socket
            .connect(ns)
            .await
            .map_err(|e| format!("连接 DNS 服务器 {ns} 失败: {e}"))?;
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(self.config.timeout, async {
            socket.send(&query).await?;
            socket.recv(&mut buf).await
        })
        .await
        .map_err(|_| format!("DNS 查询超时（{:?}）: {host}", self.config.timeout))?
        .map_err(|e| format!("DNS 收发失败: {e}"))?;
        parse_response(&buf[..n], id, host, qtype)
    }
}

/// 把 "127.0.0.1" / "127.0.0.1:53" / "[::1]:53" 解析成 SocketAddr，默认端口 53。
fn parse_nameserver(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    // 纯 IP（无端口）→ 补 53
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    // 带方括号但端口缺省，如 "[::1]"
    let trimmed = s.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

/// 构造一条标准查询报文：ID + 递归期望(0x0100) + 1 条 question。
fn build_query(id: u16, host: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + host.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    write_name(&mut msg, host);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg
}

/// 把域名按 label 编码（每段长度前缀，末尾 0）。不做压缩（查询里禁止指针）。
fn write_name(msg: &mut Vec<u8>, host: &str) {
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > 63 {
            // 单 label 超 63 字节非法；截断保证报文不畸形
            msg.push(63);
            msg.extend_from_slice(&bytes[..63]);
        } else {
            msg.push(bytes.len() as u8);
            msg.extend_from_slice(bytes);
        }
    }
    msg.push(0);
}

/// 从报文 offset 处读取一个域名（跟随压缩指针），返回 (name, 名称之后的真实 offset)。
/// 返回的 offset 始终是"顶层"位置（遇到指针即停止跟随，不改变真实游标由调用方控制）。
fn read_name(msg: &[u8], offset: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut i = offset;
    let mut jumped = false;
    let mut end = offset;
    let mut hops = 0;
    loop {
        if i >= msg.len() {
            return Err("DNS 报文 name 越界".into());
        }
        let len = msg[i] as usize;
        if len == 0 {
            if !jumped {
                end = i + 1;
            }
            break;
        }
        // 压缩指针：高 2 位为 11
        if len & 0xC0 == 0xC0 {
            if i + 1 >= msg.len() {
                return Err("DNS 压缩指针越界".into());
            }
            if !jumped {
                end = i + 2;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | msg[i + 1] as usize;
            hops += 1;
            if hops > 128 {
                return Err("DNS 压缩指针循环".into());
            }
            i = ptr;
            jumped = true;
            continue;
        }
        let start = i + 1;
        let stop = start + len;
        if stop > msg.len() {
            return Err("DNS label 越界".into());
        }
        labels.push(String::from_utf8_lossy(&msg[start..stop]).to_string());
        i = stop;
    }
    Ok((labels.join("."), end))
}

/// 解析应答，抽取匹配 qtype 的记录地址。校验事务 ID、QR 位与 RCODE。
fn parse_response(
    msg: &[u8],
    want_id: u16,
    host: &str,
    _qtype: u16,
) -> Result<Vec<IpAddr>, String> {
    if msg.len() < 12 {
        return Err("DNS 应答太短".into());
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if id != want_id {
        return Err(format!("DNS 事务 ID 不匹配（期望 {want_id}，收到 {id}）"));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qr = flags & 0x8000 == 0x8000;
    if !qr {
        return Err("DNS 报文不是应答".into());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // NXDOMAIN(3) 等：视为无记录而非硬错误，交由上层负缓存
        return Ok(Vec::new());
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    // 跳过 question 段
    let mut i = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, i)?;
        i = next + 4; // QTYPE + QCLASS
        if i > msg.len() {
            return Err("DNS question 段越界".into());
        }
    }

    let want = host.trim_end_matches('.').to_ascii_lowercase();
    let mut addrs = Vec::new();
    for _ in 0..an {
        let (name, next) = read_name(msg, i)?;
        i = next;
        if i + 10 > msg.len() {
            return Err("DNS RR 头越界".into());
        }
        let rtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        let rdata = i + 10;
        if rdata + rdlen > msg.len() {
            return Err("DNS RDATA 越界".into());
        }
        let name_matches = name.trim_end_matches('.').to_ascii_lowercase() == want;
        if name_matches && rtype == TYPE_A && rdlen == 4 {
            addrs.push(IpAddr::V4(Ipv4Addr::new(
                msg[rdata],
                msg[rdata + 1],
                msg[rdata + 2],
                msg[rdata + 3],
            )));
        } else if name_matches && rtype == TYPE_AAAA && rdlen == 16 {
            let mut o = [0u8; 16];
            o.copy_from_slice(&msg[rdata..rdata + 16]);
            addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
        }
        i = rdata + rdlen;
    }
    Ok(addrs)
}

/// 把解析出的 IP + 端口拼成 URI authority / connect 目标；IPv6 加方括号。
pub fn authority_with_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query(host: &str, qtype: u16) -> (u16, Vec<u8>) {
        let id = 0xABCD;
        (id, build_query(id, host, qtype))
    }

    /// 手工构造一条 A 记录应答，验证解析器（含压缩指针）。
    fn a_answer(id: u16, host: &str, ip: [u8; 4], use_pointer: bool) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1 RD=1 RA=1, NOERROR
        msg.extend_from_slice(&1u16.to_be_bytes()); // QD=1
        msg.extend_from_slice(&1u16.to_be_bytes()); // AN=1
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        // question
        write_name(&mut msg, host);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        // answer
        if use_pointer {
            // 压缩指针指向 question 名字起点（offset 12）
            let ptr = 12u16;
            msg.push(0xC0 | ((ptr >> 8) as u8 & 0x3F));
            msg.push((ptr & 0xFF) as u8);
        } else {
            write_name(&mut msg, host);
        }
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
        msg.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        msg.extend_from_slice(&ip);
        msg
    }

    #[test]
    fn build_query_shape() {
        let (_, q) = sample_query("www.example.com", TYPE_A);
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(q[5], 1); // QDCOUNT = 1
                             // 末尾四个字节：label 结束 \0 + QTYPE(0,1) + QCLASS(0,1)
        assert_eq!(&q[q.len() - 5..], &[0x00, 0x00, 0x01, 0x00, 0x01][..]);
    }

    #[test]
    fn parse_a_answer_plain_name() {
        let (id, _) = sample_query("test.invalid", TYPE_A);
        let ans = a_answer(id, "test.invalid", [127, 0, 0, 1], false);
        let addrs = parse_response(&ans, id, "test.invalid", TYPE_A).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn parse_a_answer_compressed() {
        let (id, _) = sample_query("a.b.c", TYPE_A);
        let ans = a_answer(id, "a.b.c", [10, 0, 0, 5], true);
        let addrs = parse_response(&ans, id, "a.b.c", TYPE_A).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);
    }

    #[test]
    fn parse_rejects_wrong_id() {
        let (id, _) = sample_query("x.io", TYPE_A);
        let ans = a_answer(id, "x.io", [1, 1, 1, 1], false);
        assert!(parse_response(&ans, 0x9999, "x.io", TYPE_A).is_err());
    }

    #[test]
    fn nxdomain_returns_empty() {
        let (id, _) = sample_query("gone.io", TYPE_A);
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x8183u16.to_be_bytes()); // QR=1, RCODE=3 (NXDOMAIN)
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        write_name(&mut msg, "gone.io");
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        let addrs = parse_response(&msg, id, "gone.io", TYPE_A).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn ip_literal_short_circuits() {
        let r = DnsResolver {
            config: ResolverConfig::default(),
            cache: Mutex::new(HashMap::new()),
            rotation: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
        };
        let addrs = tokio_test(&r, "127.0.0.1");
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn rotates_across_cached_addresses() {
        let host = "multi.invalid";
        let mut cache = HashMap::new();
        cache.insert(
            host.to_string(),
            CacheEntry {
                addrs: vec![
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                ],
                expires: Instant::now() + Duration::from_secs(60),
            },
        );
        let r = DnsResolver {
            config: ResolverConfig::default(),
            cache: Mutex::new(cache),
            rotation: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let firsts: Vec<IpAddr> = (0..4)
            .map(|_| *rt.block_on(r.resolve(host)).unwrap().first().unwrap())
            .collect();
        assert_eq!(
            firsts,
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ]
        );
    }

    #[test]
    fn retries_after_transient_timeout() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sock = rt.block_on(async { tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap() });
        let ns = sock.local_addr().unwrap();
        let answered = Arc::new(AtomicUsize::new(0));
        let answered_srv = answered.clone();
        rt.spawn(async move {
            let mut buf = [0u8; 4096];
            let mut a_seen = 0usize;
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                if n < 17 {
                    continue;
                }
                let qid = u16::from_be_bytes([buf[0], buf[1]]);
                let Ok((_, qend)) = read_name(&buf[..n], 12) else {
                    continue;
                };
                let qtype = u16::from_be_bytes([buf[qend], buf[qend + 1]]);
                let question = buf[12..qend + 4].to_vec();
                let mut msg = Vec::new();
                msg.extend_from_slice(&qid.to_be_bytes());
                if qtype == TYPE_A {
                    a_seen += 1;
                    if a_seen == 1 {
                        // 丢弃首条 A 查询，制造一次超时
                        continue;
                    }
                    answered_srv.fetch_add(1, Ordering::Relaxed);
                    msg.extend_from_slice(&0x8180u16.to_be_bytes());
                    msg.extend_from_slice(&1u16.to_be_bytes()); // QD
                    msg.extend_from_slice(&1u16.to_be_bytes()); // AN
                    msg.extend_from_slice(&0u16.to_be_bytes());
                    msg.extend_from_slice(&0u16.to_be_bytes());
                    msg.extend_from_slice(&question);
                    // 指针指向 question 名，A 127.0.0.9
                    msg.extend_from_slice(&[
                        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 30, 0, 4, 127, 0, 0, 9,
                    ]);
                } else {
                    // AAAA 回 NXDOMAIN：让首轮以"超时 + 无记录"结束
                    msg.extend_from_slice(&0x8183u16.to_be_bytes());
                    msg.extend_from_slice(&1u16.to_be_bytes());
                    msg.extend_from_slice(&0u16.to_be_bytes());
                    msg.extend_from_slice(&0u16.to_be_bytes());
                    msg.extend_from_slice(&0u16.to_be_bytes());
                    msg.extend_from_slice(&question);
                }
                let _ = sock.send_to(&msg, peer).await;
            }
        });

        let r = DnsResolver {
            config: ResolverConfig {
                nameservers: vec![ns],
                valid: Duration::from_secs(10),
                timeout: Duration::from_millis(150),
                ipv6: true,
            },
            cache: Mutex::new(HashMap::new()),
            rotation: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
        };
        let addrs = rt.block_on(r.resolve("retry.invalid")).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))]);
        assert_eq!(answered.load(Ordering::Relaxed), 1);
    }

    fn tokio_test(r: &DnsResolver, host: &str) -> Vec<IpAddr> {
        // IP 字面量路径不触碰网络，可在无 runtime 依赖下用 block_on 手工驱动
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(r.resolve(host)).unwrap()
    }

    #[test]
    fn authority_formatting() {
        assert_eq!(
            authority_with_port(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080),
            "1.2.3.4:8080"
        );
        assert_eq!(
            authority_with_port(IpAddr::V6("::1".parse().unwrap()), 80),
            "[::1]:80"
        );
    }

    #[test]
    fn nameserver_parsing() {
        assert_eq!(
            parse_nameserver("8.8.8.8"),
            Some("8.8.8.8:53".parse().unwrap())
        );
        assert_eq!(
            parse_nameserver("127.0.0.1:5553"),
            Some("127.0.0.1:5553".parse().unwrap())
        );
        assert_eq!(
            parse_nameserver("[::1]:53"),
            Some("[::1]:53".parse().unwrap())
        );
        assert_eq!(parse_nameserver("::1"), Some("[::1]:53".parse().unwrap()));
        assert_eq!(parse_nameserver("not-an-ip"), None);
    }

    #[test]
    fn resolver_from_config_requires_nameserver() {
        let cfg = onrouter_config::Config::parse("").unwrap();
        assert!(DnsResolver::from_config(&cfg).is_none());
        let cfg = onrouter_config::Config::parse("resolver 127.0.0.1:5553 valid=30s;").unwrap();
        let r = DnsResolver::from_config(&cfg).unwrap();
        assert_eq!(r.config.nameservers.len(), 1);
        assert_eq!(r.config.valid, Duration::from_secs(30));
    }
}
