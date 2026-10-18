//! L4（传输层）反向代理：对标 Nginx 的 `stream{}` 模块 + `ssl_preread`。
//!
//! 与 HTTP 层（server.rs）完全不同的一条通路：不解析、不终止 TLS、不理解应用协议，
//! 只在 TCP 字节层把客户端连接"接线"到某个后端。可选 `ssl_preread`：在不解密的前提下，
//! 窥探连接开头的 TLS ClientHello，从中取出 SNI（server_name 扩展），据此把连接路由到
//! 不同后端——这正是四层 SNI 负载均衡的标准做法。
//!
//! 语义要点（对齐 nginx）：
//! * `proxy_pass <upstream-name> | <host:port>;` —— 转发目标，可命名 upstream（复用 L7 的
//!   负载均衡/健康检查池）或直接给地址。
//! * `ssl_preread on|off;` —— 是否窥探 SNI。off 时直接连到 `proxy_pass` 默认目标。
//! * `sni_match <name> <target>;`（可重复，ONRouter 扩展的显式 SNI 路由）—— name 为精确主机名
//!   或 `*.example.com` 通配（只匹配一级标签）；命中则路由到 target，未命中回落 `proxy_pass`。
//! * 窥探是 best-effort：不是 TLS / 读不完整 / 没有 SNI 时，仍按默认目标接线，并把已经读到的
//!   字节原样补给后端（字节透明，绝不吃掉握手数据）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::router::StreamServer;
use crate::upstream::UpstreamPool;
use crate::{log_debug, log_error, log_info, log_warn};

/// 窥探 ClientHello 的最大缓冲（16KB 足够容纳带大量扩展的握手第一条记录）。
const PREREAD_CAP: usize = 16 * 1024;

/// 从一段（可能只是 ClientHello 前缀的）字节里解析 SNI；任何不规范都返回 None。
///
/// TLS 记录头：type(1)=0x16 + version(2) + length(2)。记录体是握手消息：
/// type(1)=0x01 + length(3) + legacy_version(2) + random(32) + session_id(1+..) +
/// cipher_suites(2+..) + compression(1+..) + extensions(2+..)，逐个扩展找 server_name(0x0000)。
pub fn parse_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    let body_end = 5usize.checked_add(rec_len)?;
    if buf.len() < body_end {
        return None; // 记录还没读全
    }
    let hs = &buf[5..body_end];
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut p = 4usize; // 跳过 type(1)+length(3)
    p += 2 + 32; // legacy_version + random
    if hs.len() < p + 1 {
        return None;
    }
    let sid_len = hs[p] as usize;
    p += 1 + sid_len;
    if hs.len() < p + 2 {
        return None;
    }
    let cs_len = ((hs[p] as usize) << 8) | (hs[p + 1] as usize);
    p += 2 + cs_len;
    if hs.len() < p + 1 {
        return None;
    }
    let cm_len = hs[p] as usize;
    p += 1 + cm_len;
    if hs.len() < p + 2 {
        return None;
    }
    let ext_total = ((hs[p] as usize) << 8) | (hs[p + 1] as usize);
    p += 2;
    let ext_end = p.checked_add(ext_total)?;
    if hs.len() < ext_end {
        return None;
    }
    let ext = &hs[p..ext_end];
    let mut e = 0;
    while e + 4 <= ext.len() {
        let etype = ((ext[e] as u16) << 8) | ext[e + 1] as u16;
        let elen = ((ext[e + 2] as usize) << 8) | ext[e + 3] as usize;
        let data_start = e + 4;
        let data_end = data_start.checked_add(elen)?;
        if data_end > ext.len() {
            break;
        }
        if etype == 0x0000 {
            let sn = &ext[data_start..data_end];
            if sn.len() < 2 {
                break;
            }
            let list_len = ((sn[0] as usize) << 8) | sn[1] as usize;
            let list_end = (2 + list_len).min(sn.len());
            let mut l = 2;
            while l + 3 <= list_end {
                let name_type = sn[l];
                let name_len = ((sn[l + 1] as usize) << 8) | sn[l + 2] as usize;
                l += 3;
                if l + name_len > sn.len() {
                    break;
                }
                if name_type == 0x00 {
                    return String::from_utf8(sn[l..l + name_len].to_vec())
                        .ok()
                        .map(|s| s.to_ascii_lowercase());
                }
                l += name_len;
            }
            break;
        }
        e = data_start + elen;
    }
    None
}

/// SNI 匹配：精确（大小写不敏感）或 `*.suffix` 通配（匹配恰好一级子域，如 `*.e.com`
/// 命中 `a.e.com` 但不命中 `e.com` 也不命中 `x.y.e.com`）。
pub fn sni_pattern_matches(pattern: &str, sni: &str) -> bool {
    let sni = sni.to_ascii_lowercase();
    let pat = pattern.to_ascii_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        match sni.strip_suffix(&format!(".{suffix}")) {
            Some(prefix) => !prefix.is_empty() && !prefix.contains('.'),
            None => false,
        }
    } else {
        sni == pat
    }
}

/// 依序取第一条命中的 SNI 路由目标。
pub fn pick_sni_target(srv: &StreamServer, sni: Option<&str>) -> Option<String> {
    let name = sni?;
    for m in &srv.sni_matches {
        if sni_pattern_matches(&m.pattern, name) {
            return Some(m.target.clone());
        }
    }
    None
}

/// 把 proxy_pass 目标解析成一个可 connect 的 "host:port" 串：
/// 命中命名 upstream 则按池选一个节点，否则当作字面地址原样返回。
fn resolve_target(pool: &UpstreamPool, spec: &str, client_ip: &str) -> Option<String> {
    if let Some(up) = pool.get(spec) {
        let guard = up.acquire(client_ip, &[])?;
        // UpstreamGuard Deref<Target=String> 到节点 addr
        return Some((*guard).clone());
    }
    Some(spec.to_string())
}

/// 四层监听 accept 循环（结构与 server.rs::serve 对齐：优雅停机、accept 退避、JoinSet 排空）。
pub async fn serve_stream(
    pool: Arc<UpstreamPool>,
    srv: Arc<StreamServer>,
    tcp: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = srv.listen;
    log_info!(
        "stream 监听 tcp://{addr}（preread={}，{} 条 SNI 路由）",
        srv.ssl_preread,
        srv.sni_matches.len()
    );
    let mut tasks = tokio::task::JoinSet::new();
    let mut backoff = Duration::from_millis(1);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            r = tcp.accept() => r,
        };
        match accepted {
            Ok((stream, peer)) => {
                backoff = Duration::from_millis(1);
                let pool = Arc::clone(&pool);
                let srv = Arc::clone(&srv);
                tasks.spawn(async move {
                    handle_connection(pool, srv, stream, peer).await;
                });
            }
            Err(e) => {
                log_warn!("stream {addr} accept 失败: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => break,
                }
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
        }
    }
    // 停机：给在途隧道一个短暂排空窗口后强制结束
    let grace = Duration::from_millis(200);
    let started = std::time::Instant::now();
    while !tasks.is_empty() && started.elapsed() < grace {
        tokio::select! {
            _ = tasks.join_next() => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// 单条连接：窥探（可选）→ 选目标 → 连接后端 → 字节双向接力。
async fn handle_connection(
    pool: Arc<UpstreamPool>,
    srv: Arc<StreamServer>,
    mut client: TcpStream,
    peer: SocketAddr,
) {
    let client_ip = peer.ip().to_string();
    let mut prefix: Vec<u8> = Vec::new();
    let target: Option<String>;

    if srv.ssl_preread {
        prefix = pread_prefix(&mut client, srv.pread_timeout).await;
        let sni = parse_client_hello_sni(&prefix);
        target = pick_sni_target(&srv, sni.as_deref()).or_else(|| srv.default_target.clone());
        if let Some(n) = &sni {
            log_debug!("stream preread SNI={n} from {peer}");
        }
    } else {
        target = srv.default_target.clone();
    }

    let target = match target {
        Some(t) => t,
        None => {
            log_warn!("stream {} 连接 {peer} 无可用目标（未配 proxy_pass 且 SNI 未命中）", srv.listen);
            return;
        }
    };
    let spec = match resolve_target(&pool, &target, &client_ip) {
        Some(s) => s,
        None => {
            log_warn!("stream 目标 {target} 无可用后端节点（no live upstreams）");
            return;
        }
    };
    let mut backend = match connect_with_timeout(&spec, srv.connect_timeout).await {
        Ok(b) => b,
        Err(e) => {
            log_error!("stream 连接后端 {spec} 失败: {e}");
            return;
        }
    };

    // 把已窥探的字节原样补给后端，保证字节透明（ClientHello 一个都不能少）。
    if !prefix.is_empty() && backend.write_all(&prefix).await.is_err() {
        return;
    }
    relay(client, backend, srv.proxy_timeout).await;
}

/// 窥探开头字节：读到一条完整 TLS 记录或封顶/超时为止；非 TLS 也返回已读到的内容。
async fn pread_prefix(client: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let read_fut = async {
        loop {
            if buf.len() >= PREREAD_CAP {
                break;
            }
            if buf.len() >= 5 {
                let rec_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
                if buf.len() >= 5 + rec_len {
                    break;
                }
            }
            match client.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
    };
    let _ = tokio::time::timeout(timeout, read_fut).await;
    buf
}

/// 带超时的后端连接。spec 为 "host:port"。
async fn connect_with_timeout(spec: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    if timeout.is_zero() {
        return TcpStream::connect(spec).await;
    }
    match tokio::time::timeout(timeout, TcpStream::connect(spec)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("连接后端 {spec} 超时 {timeout:?}"),
        )),
    }
}

/// 双向接力：两个方向各一个任务，任一方向读空闲超过 idle（0=不限）或 EOF/错误即结束。
async fn relay(client: TcpStream, backend: TcpStream, idle: Duration) {
    let (mut cr, mut cw) = client.into_split();
    let (mut br, mut bw) = backend.into_split();
    let to_client = tokio::spawn(async move {
        pump(&mut br, &mut cw, idle).await;
        let _ = cw.shutdown().await;
    });
    let to_backend = tokio::spawn(async move {
        pump(&mut cr, &mut bw, idle).await;
        let _ = bw.shutdown().await;
    });
    let _ = tokio::join!(to_client, to_backend);
}

/// 单向泵：read→write 直到 EOF/错误/空闲超时。
async fn pump<R, W>(r: &mut R, w: &mut W, idle: Duration)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = if idle.is_zero() {
            match r.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            }
        } else {
            match tokio::time::timeout(idle, r.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => break,
            }
        };
        if n == 0 {
            break;
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        let _ = w.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 手工构造一个含 SNI 的最小合法 TLS ClientHello，用于验证解析器。
    fn client_hello(host: &str) -> Vec<u8> {
        let mut hs_body: Vec<u8> = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // legacy version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id len = 0
        hs_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len2 + one suite
        hs_body.extend_from_slice(&[0x01, 0x00]); // compression: len1 + 0x00
        let host_bytes = host.as_bytes();
        let mut sn_entry: Vec<u8> = Vec::new();
        sn_entry.push(0x00); // host_name
        sn_entry.push((host_bytes.len() >> 8) as u8);
        sn_entry.push(host_bytes.len() as u8);
        sn_entry.extend_from_slice(host_bytes);
        let list_len = sn_entry.len();
        let mut ext_data: Vec<u8> = Vec::new();
        ext_data.push((list_len >> 8) as u8);
        ext_data.push(list_len as u8);
        ext_data.extend_from_slice(&sn_entry);
        let ext_len = ext_data.len();
        let mut exts: Vec<u8> = Vec::new();
        exts.extend_from_slice(&[0x00, 0x00]); // type server_name
        exts.push((ext_len >> 8) as u8);
        exts.push(ext_len as u8);
        exts.extend_from_slice(&ext_data);
        let ext_total = exts.len();
        hs_body.push((ext_total >> 8) as u8);
        hs_body.push(ext_total as u8);
        hs_body.extend_from_slice(&exts);

        let hs_len = hs_body.len();
        let mut record: Vec<u8> = Vec::new();
        record.push(0x01); // client_hello
        record.push((hs_len >> 16) as u8);
        record.push((hs_len >> 8) as u8);
        record.push(hs_len as u8);
        record.extend_from_slice(&hs_body);

        let rec_len = record.len();
        let mut out: Vec<u8> = Vec::new();
        out.push(0x16); // handshake
        out.extend_from_slice(&[0x03, 0x01]); // version
        out.push((rec_len >> 8) as u8);
        out.push(rec_len as u8);
        out.extend_from_slice(&record);
        out
    }

    #[test]
    fn parses_sni_from_client_hello() {
        assert_eq!(
            parse_client_hello_sni(&client_hello("a.example.com")).as_deref(),
            Some("a.example.com")
        );
        // 大小写归一
        assert_eq!(
            parse_client_hello_sni(&client_hello("MIXED.Example")).as_deref(),
            Some("mixed.example")
        );
    }

    #[test]
    fn no_sni_and_garbage_return_none() {
        assert_eq!(parse_client_hello_sni(&[0x17, 0x03, 0x03, 0x00, 0x10]), None);
        assert_eq!(parse_client_hello_sni(&[]), None);
        let mut not_hello = client_hello("x");
        not_hello[5] = 0x02; // 握手类型改成 server_hello
        assert_eq!(parse_client_hello_sni(&not_hello), None);
    }

    #[test]
    fn truncated_client_hello_returns_none() {
        let mut hello = client_hello("a.example");
        hello.truncate(hello.len() - 1); // 少一字节，记录不完整
        assert!(parse_client_hello_sni(&hello).is_none());
    }

    #[test]
    fn sni_matcher_exact_and_wildcard() {
        assert!(sni_pattern_matches("a.example.com", "A.EXAMPLE.COM"));
        assert!(!sni_pattern_matches("a.example.com", "b.example.com"));
        assert!(sni_pattern_matches("*.example.com", "a.example.com"));
        assert!(sni_pattern_matches("*.example.com", "b.example.com"));
        assert!(!sni_pattern_matches("*.example.com", "example.com"));
        assert!(!sni_pattern_matches("*.example.com", "x.y.example.com"));
    }

    #[test]
    fn pick_sni_target_first_match_wins_and_none_falls_back() {
        let mut srv = StreamServer::default();
        srv.sni_matches = vec![
            crate::router::SniMatch { pattern: "*.example.com".into(), target: "up_a".into() },
            crate::router::SniMatch { pattern: "a.example.com".into(), target: "up_b".into() },
        ];
        assert_eq!(pick_sni_target(&srv, Some("a.example.com")).as_deref(), Some("up_a"));
        assert_eq!(pick_sni_target(&srv, Some("other.net")).as_deref(), None);
        assert_eq!(pick_sni_target(&srv, None).as_deref(), None);
    }
}
