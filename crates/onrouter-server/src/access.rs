//! 访问控制：IP 白/黑名单（`allow`/`deny`，对标 ngx_http_access_module）+ HTTP 基本认证
//! （`auth_basic` / `auth_basic_user_file`，对标 ngx_http_auth_basic_module）。
//!
//! 两者都在 ACCESS 阶段执行，先 IP 后 basic auth，再轮到 access_by_lua/rust（与 nginx 一致，
//! 内置 access/auth 模块的 handler 早于 ngx_lua 注册）。
//!
//! htpasswd 口令散列支持四种存储形态，全部自实现、不引第三方密码学 crate（纯 Rust、交叉编译友好）：
//! - 明文 `user:pass`
//! - `{SHA}base64(sha1(pass))`（Netscape 格式）
//! - `$1$<salt>$<hash>`（MD5-crypt，glibc）
//! - `$apr1$<salt>$<hash>`（Apache 变体 MD5-crypt）
//! crypt(3) 的 DES 与 bcrypt（`$2y$`）暂不支持，见 README roadmap。

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;
use std::time::SystemTime;

// ==================== htpasswd 文件缓存 ====================

/// 进程级 htpasswd 缓存：按路径缓存解析结果，文件 mtime 变化时重载（对标 nginx open_file_cache
/// 的被动失效）。读不到文件或解析失败返回 `None`，调用方按“认证失败”处理。
static HTPASSWD_CACHE: OnceLock<Mutex<HashMap<PathBuf, (SystemTime, Htpasswd)>>> = OnceLock::new();

pub fn load_htpasswd(path: &Path) -> Option<Htpasswd> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let cache = HTPASSWD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // 中毒的锁：拿内部数据继续（缓存非关键状态）
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((t, users)) = map.get(path) {
        if *t == mtime {
            return Some(users.clone());
        }
    }
    let text = std::fs::read_to_string(path).ok()?;
    let users = Htpasswd::parse(&text);
    map.insert(path.to_path_buf(), (mtime, users.clone()));
    Some(users)
}

// ==================== IP allow/deny ====================

/// 一条 CIDR 规则：`addr` 为网络地址，`bits` 为前缀长度（v4 最大 32、v6 最大 128）。
#[derive(Debug, Clone, PartialEq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub bits: u8,
}

impl IpNet {
    /// 解析 `allow`/`deny` 的地址参数：裸 IP（等价 /32 或 /128）、CIDR、或 `all`（Any）。
    /// 返回 `None` 表示无法解析。`all` 用 `IpNet { addr: 0.0.0.0, bits: 0 }` 之外的显式约定：
    /// 这里单独用 `parse_allow_arg` 处理，`all` 不经过本函数。
    fn parse(s: &str) -> Option<IpNet> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        match s.split_once('/') {
            Some((ip, bits)) => {
                let addr: IpAddr = ip.parse().ok()?;
                let bits: u8 = bits.parse().ok()?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if bits > max {
                    return None;
                }
                Some(IpNet { addr, bits })
            }
            None => {
                let addr: IpAddr = s.parse().ok()?;
                let bits = if addr.is_ipv4() { 32 } else { 128 };
                Some(IpNet { addr, bits })
            }
        }
    }

    /// 把地址按前缀长度截断成网络地址（掩码高位保留），避免非零主机位导致漏配。
    fn masked_bytes(addr: IpAddr) -> [u8; 16] {
        match addr {
            IpAddr::V4(v4) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&v4.octets());
                b
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    /// `IpNet::all_v4()` / `all_v6()`：匹配对应协议族的任意地址。
    fn any_for(family_v4: bool) -> IpNet {
        if family_v4 {
            IpNet { addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), bits: 0 }
        } else {
            IpNet { addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), bits: 0 }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // v4/v6 混配时不匹配（nginx 的 allow all 会同时下发 v4/v6 规则，见 collect）
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let a = IpNet::masked_bytes(self.addr);
        let b = IpNet::masked_bytes(ip);
        let mut remaining = self.bits;
        let mut i = 0usize;
        while i < 16 && remaining > 0 {
            let take = if remaining >= 8 { 8 } else { remaining };
            let mask = if take == 8 { 0xFFu8 } else { (0xFFu8 << (8 - take)) & 0xFF };
            if (a[i] & mask) != (b[i] & mask) {
                return false;
            }
            remaining = remaining.saturating_sub(8);
            i += 1;
        }
        true
    }
}

/// 一条有序规则：allow=true 命中放行、false 命中拒绝。`allow all`/`deny all` 展开为
/// v4 + v6 两条 Any 规则，这样 `deny all` 能拦住 IPv4 客户端（本机测试多为 127.0.0.1）。
#[derive(Debug, Clone)]
pub struct AccessRule {
    pub allow: bool,
    pub nets: Vec<IpNet>,
}

impl AccessRule {
    fn matches(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

/// 解析一条 `allow`/`deny` 指令的地址参数列表（可 `allow 10.0.0.0/8 192.168.1.5;` 多值）。
/// 返回 `None` 表示参数里有非法地址。
pub fn parse_allow_arg(allow: bool, args: &[&str]) -> Option<AccessRule> {
    let mut nets = Vec::new();
    for a in args {
        let a = a.trim();
        if a == "all" {
            nets.push(IpNet::any_for(true));
            nets.push(IpNet::any_for(false));
        } else if a == "localhost" {
            // 与 nginx 略有差异：nginx 的 localhost 走 DNS；这里固定回环，测试/单机够用
            nets.push(IpNet::parse("127.0.0.1/8")?);
            nets.push(IpNet::parse("::1/128")?);
        } else {
            nets.push(IpNet::parse(a)?);
        }
    }
    if nets.is_empty() {
        return None;
    }
    Some(AccessRule { allow, nets })
}

/// nginx ngx_http_access_module 语义：自上而下第一条匹配的规则决定放行/拒绝；
/// 没有任何规则匹配时默认放行。
pub fn check_access(rules: &[AccessRule], ip: IpAddr) -> bool {
    for r in rules {
        if r.matches(ip) {
            return r.allow;
        }
    }
    true
}

// ==================== HTTP Basic Auth ====================

/// 校验 Authorization 头是否为 `Basic <base64(user:pass)>` 且口令匹配。
/// 返回 Some(user) 表示通过，None 表示缺失/格式错/不匹配。
pub fn check_auth_header(header: Option<&str>, users: &Htpasswd) -> AuthOutcome {
    let header = match header {
        Some(h) => h,
        None => return AuthOutcome::Missing,
    };
    let rest = match header.strip_prefix("Basic ") {
        Some(r) => r,
        None => return AuthOutcome::BadFormat,
    };
    let decoded = match b64_decode(rest.trim()) {
        Some(d) => d,
        None => return AuthOutcome::BadFormat,
    };
    let text = match String::from_utf8(decoded) {
        Ok(t) => t,
        Err(_) => return AuthOutcome::BadFormat,
    };
    // user 不能含冒号：按第一个冒号切分（与 nginx 一致）
    let (user, pass) = match text.split_once(':') {
        Some(up) => up,
        None => return AuthOutcome::BadFormat,
    };
    if user.is_empty() {
        return AuthOutcome::BadFormat;
    }
    if users.verify(user, pass) {
        AuthOutcome::Ok(user.to_string())
    } else {
        AuthOutcome::Denied
    }
}

pub enum AuthOutcome {
    Ok(String),
    Missing,
    BadFormat,
    Denied,
}

/// 已解析的 htpasswd 用户表。
#[derive(Debug, Default, Clone)]
pub struct Htpasswd {
    entries: Vec<(String, String)>, // (user, stored-hash)
}

impl Htpasswd {
    /// 解析 htpasswd 文本：`user:hash`，忽略空行与 `#` 注释；同名用户以最后一条为准。
    pub fn parse(text: &str) -> Htpasswd {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((user, hash)) = line.split_once(':') {
                // 覆盖同名旧条目
                if let Some(pos) = entries.iter().position(|(u, _)| u == user) {
                    entries[pos].1 = hash.to_string();
                } else {
                    entries.push((user.to_string(), hash.to_string()));
                }
            }
        }
        Htpasswd { entries }
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        for (u, stored) in &self.entries {
            if u == user {
                return verify_password(stored, password);
            }
        }
        false
    }

    #[cfg(test)]
    pub fn users(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(u, _)| u.as_str())
    }
}

/// 按存储形态分派校验。比较一律走常量时间，避免按字符早退的时间侧信道。
pub fn verify_password(stored: &str, password: &str) -> bool {
    if let Some(b64) = stored.strip_prefix("{SHA}") {
        let want = match b64_decode(b64) {
            Some(v) => v,
            None => return false,
        };
        let got = sha1(password.as_bytes());
        return ct_eq(&want, &got);
    }
    if stored.starts_with("$1$") || stored.starts_with("$apr1$") {
        return verify_md5crypt(stored, password);
    }
    // 明文（含 crypt-DES / bcrypt 前缀我们不支持时，退化成整串比较会误判为不匹配，安全）
    ct_eq(stored.as_bytes(), password.as_bytes())
}

/// 解析 `$<magic>$<salt>$<hash>` 并重新计算比对。
fn verify_md5crypt(stored: &str, password: &str) -> bool {
    // 去掉起始 '$'
    let body = stored.strip_prefix('$').unwrap_or(stored);
    // 形如 `1$salt$hash` 或 `apr1$salt$hash`
    let (id, rest) = match body.split_once('$') {
        Some(pair) => pair,
        None => return false,
    };
    let (salt, hash) = match rest.split_once('$') {
        Some(pair) => pair,
        None => return false,
    };
    let magic = format!("${id}$");
    let recomputed = md5crypt(password.as_bytes(), salt.as_bytes(), &magic);
    match recomputed {
        Some(full) => {
            // full 形如 `$id$salt$hash`，只比对 hash 段
            match full.rsplit_once('$') {
                Some((_, h)) => ct_eq(h.as_bytes(), hash.as_bytes()),
                None => false,
            }
        }
        None => false,
    }
}

// ==================== 常量时间比较 ====================

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // 长度不同一定不相等；长度本身不泄露口令内容，仍可早退
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ==================== base64（标准字母表，容忍填充/换行）====================

const B64_ALPHA: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    // 建反查表
    let mut rev = [-1i16; 256];
    for (i, &c) in B64_ALPHA.iter().enumerate() {
        rev[c as usize] = i as i16;
    }
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        // 跳过 base64 里常见的换行/空白
        if byte == b'\n' || byte == b'\r' || byte == b' ' || byte == b'\t' {
            continue;
        }
        let val = rev[byte as usize];
        if val < 0 {
            return None;
        }
        acc = (acc << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHA[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHA[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHA[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}


// ==================== SHA-1（RFC 3121）====================

fn sha1(msg: &[u8]) -> Vec<u8> {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (msg.len() as u64) * 8;

    // padding：消息 + 0x80 + 若干 0 + 64-bit 大端长度，总长为 64 的倍数
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&ml.to_be_bytes());

    for block in data.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = Vec::with_capacity(20);
    for x in h {
        out.extend_from_slice(&x.to_be_bytes());
    }
    out
}

// ==================== MD5（RFC 1321）====================

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// 计算一段（可多次 update 的）MD5 摘要。为 md5_crypt 需要增量喂入不同字节，
/// 这里用一个累积 buffer 的简单实现（口令/盐都很短，性能无所谓）。
struct Md5 {
    buf: Vec<u8>,
}

impl Md5 {
    fn new() -> Md5 {
        Md5 { buf: Vec::new() }
    }
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn finalize(self) -> [u8; 16] {
        md5_digest(&self.buf)
    }
}

fn md5_digest(msg: &[u8]) -> [u8; 16] {
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let ml = (msg.len() as u64) * 8;

    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&ml.to_le_bytes());

    for block in data.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_S[i]));
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

// ==================== MD5-crypt（Poul-Henning Kamp 算法，$1$ / $apr1$）====================

/// 返回完整串 `$<id>$<salt>$<hash>`。salt 取前 8 字节（与 crypt 规范一致）。
pub fn md5crypt(password: &[u8], salt: &[u8], magic: &str) -> Option<String> {
    // magic 形如 "$1$" 或 "$apr1$"
    let salt = &salt[..salt.len().min(8)];

    // ctx A：password + magic + salt
    let mut a = Md5::new();
    a.update(password);
    a.update(magic.as_bytes());
    a.update(salt);

    // ctx B：password + salt + password
    let mut b = Md5::new();
    b.update(password);
    b.update(salt);
    b.update(password);
    let db = b.finalize();

    // 把 B 的摘要按 password 长度喂进 A
    let n = password.len();
    let mut remaining = n;
    while remaining > 16 {
        a.update(&db);
        remaining -= 16;
    }
    a.update(&db[..remaining]);

    // 逐位：奇→0x00，偶→password[0]
    let mut i = n;
    while i > 0 {
        if i & 1 == 1 {
            a.update(&[0u8]);
        } else {
            a.update(&password[0..1]);
        }
        i >>= 1;
    }
    let mut da = a.finalize();

    // 1000 轮混淆（apr1 与 $1$ 的这一段完全相同，只是初始 magic 不同）
    for j in 0..1000 {
        let mut c = Md5::new();
        if j & 1 == 1 {
            c.update(password);
        } else {
            c.update(&da);
        }
        if j % 3 != 0 {
            c.update(salt);
        }
        if j % 7 != 0 {
            c.update(password);
        }
        if j & 1 == 1 {
            c.update(&da);
        } else {
            c.update(password);
        }
        da = c.finalize();
    }

    // 定长编码：自定义字母表 + 固定字节置换
    const ITER64: &[u8; 64] =
        b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut hash = String::new();
    let append24 = |hash: &mut String, a: u8, b: u8, c: u8, count: usize| {
        let w = ((a as u32) << 16) | ((b as u32) << 8) | (c as u32);
        // md5-crypt 的 base64 段按「低位 6 bit 在前」取出（与标准 base64 的高位在前相反）
        for k in 0..count {
            hash.push(ITER64[((w >> (6 * k)) & 0x3F) as usize] as char);
        }
    };
    append24(&mut hash, da[0], da[6], da[12], 4);
    append24(&mut hash, da[1], da[7], da[13], 4);
    append24(&mut hash, da[2], da[8], da[14], 4);
    append24(&mut hash, da[3], da[9], da[15], 4);
    append24(&mut hash, da[4], da[10], da[5], 4);
    append24(&mut hash, 0, 0, da[11], 2);

    Some(format!("{}{}${}", magic, std::str::from_utf8(salt).ok()?, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipnet_matches_cidr_and_family() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.1.2.3".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        // v4 规则不匹配 v6 地址
        assert!(!net.contains("::1".parse().unwrap()));
        // 主机位非零时仍按网络地址截断
        let net2 = IpNet::parse("192.168.1.7/24").unwrap();
        assert!(net2.contains("192.168.1.200".parse().unwrap()));
        assert!(!net2.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn access_first_match_wins_default_allow() {
        let rules = vec![
            AccessRule { allow: true, nets: vec![IpNet::parse("127.0.0.1/32").unwrap()] },
            AccessRule { allow: false, nets: vec![IpNet::any_for(true), IpNet::any_for(false)] },
        ];
        assert!(check_access(&rules, "127.0.0.1".parse().unwrap()));
        assert!(!check_access(&rules, "8.8.8.8".parse().unwrap()));
        // 无规则 → 默认放行
        assert!(check_access(&[], "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn allow_deny_all_blocks_ipv4() {
        let rule = parse_allow_arg(false, &["all"]).unwrap();
        assert!(rule.matches("127.0.0.1".parse().unwrap()));
        assert!(rule.matches("::1".parse().unwrap()));
    }

    #[test]
    fn sha1_known_vector() {
        // RFC 3121: sha1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let got = sha1(b"abc");
        let expect =
            hex::decode_bytes("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(got, expect);
    }

    #[test]
    fn md5_known_vector() {
        // RFC 1321: md5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let got = md5_digest(b"abc");
        assert_eq!(hex::decode_bytes("900150983cd24fb0d6963f7d28e17f72"), got);
    }

    #[test]
    fn md5crypt_matches_openssl() {
        // openssl passwd -1 -salt abcdef12 secret
        assert_eq!(
            md5crypt(b"secret", b"abcdef12", "$1$").unwrap(),
            "$1$abcdef12$toTUGmcmirn3PFj.vEnTe1"
        );
        // openssl passwd -apr1 -salt abcdef12 secret
        assert_eq!(
            md5crypt(b"secret", b"abcdef12", "$apr1$").unwrap(),
            "$apr1$abcdef12$OApeybNqWgw1NMEqIdbvf1"
        );
    }

    #[test]
    fn verify_password_all_formats() {
        assert!(verify_password("secret", "secret"));
        assert!(!verify_password("secret", "wrong"));
        // {SHA} base64(sha1("secret")) —— 与 openssl/python 生成的一致
        assert!(verify_password("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "secret"));
        assert!(!verify_password("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "wrong"));
        // md5crypt
        assert!(verify_password("$1$abcdef12$toTUGmcmirn3PFj.vEnTe1", "secret"));
        assert!(verify_password("$apr1$abcdef12$OApeybNqWgw1NMEqIdbvf1", "secret"));
        assert!(!verify_password("$apr1$abcdef12$OApeybNqWgw1NMEqIdbvf1", "wrong"));
    }

    #[test]
    fn htpasswd_parse_and_verify() {
        let text = "# comment line\nalice:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\n\nbob:$apr1$abcdef12$OApeybNqWgw1NMEqIdbvf1\n";
        let h = Htpasswd::parse(text);
        assert!(h.verify("alice", "secret"));
        assert!(h.verify("bob", "secret"));
        assert!(!h.verify("bob", "nope"));
        assert!(!h.verify("carol", "secret"));
        let users: Vec<_> = h.users().collect();
        assert_eq!(users, vec!["alice", "bob"]);
    }

    #[test]
    fn base64_roundtrip_and_basic_header() {
        assert_eq!(b64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");
        assert_eq!(b64_decode("YWxpY2U6c2VjcmV0").unwrap(), b"alice:secret");
        let h = Htpasswd::parse("alice:secret");
        match check_auth_header(Some("Basic YWxpY2U6c2VjcmV0"), &h) {
            AuthOutcome::Ok(u) => assert_eq!(u, "alice"),
            _ => panic!("expected Ok"),
        }
        assert!(matches!(check_auth_header(None, &h), AuthOutcome::Missing));
        assert!(matches!(
            check_auth_header(Some("Basic !!!!"), &h),
            AuthOutcome::BadFormat
        ));
        assert!(matches!(
            check_auth_header(Some("Basic YWxpY2U6d3Jvcmc="), &h),
            AuthOutcome::Denied
        ));
    }

    // 轻量 hex（仅测试用）
    mod hex {
        pub fn decode_bytes(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
    }
}
