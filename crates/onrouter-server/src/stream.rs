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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::router::StreamServer;
use crate::upstream::{UpstreamGuard, UpstreamPool};
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
/// 返回的 guard 必须由调用方持有到隧道结束，`max_conns` 的额度才覆盖整条连接。
fn resolve_target(
    pool: &UpstreamPool,
    spec: &str,
    client_ip: &str,
) -> Option<(String, Option<UpstreamGuard>)> {
    if let Some(up) = pool.get(spec) {
        let guard = up.acquire(client_ip, &[])?;
        // UpstreamGuard Deref<Target=String> 到节点 addr
        let addr = (*guard).clone();
        return Some((addr, Some(guard)));
    }
    Some((spec.to_string(), None))
}

/// 四层监听 accept 循环（结构与 server.rs::serve 对齐：worker_connections 额度、
/// 活跃连接指标、优雅停机、accept 退避、JoinSet 排空）。
pub async fn serve_stream(
    state: Arc<crate::server::AppState>,
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
            // 回收已完成的隧道任务，避免长跑进程里 JoinSet 只增不减
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        match accepted {
            Ok((stream, peer)) => {
                backoff = Duration::from_millis(1);
                crate::metrics::get().on_accept();
                let pool = Arc::clone(&pool);
                let state = Arc::clone(&state);
                let srv = Arc::clone(&srv);
                tasks.spawn(async move {
                    // 与 HTTP 共用 worker_connections 额度：拿不到就立刻断开，不排队、不耗 fd
                    let Ok(_permit) = state.permits.clone().try_acquire_owned() else {
                        log_debug!(
                            "stream {} 连接数已达 worker_connections，拒绝 {peer}",
                            srv.listen
                        );
                        return;
                    };
                    let _active = crate::metrics::ActiveConnGuard::new(crate::metrics::get());
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
    // 与 HTTP 同语义：先关监听（新连接立即被拒），再在 shutdown_grace 内等隧道自然结束
    drop(tcp);
    crate::server::drain_connections(&mut tasks, state.settings.shutdown_grace, addr).await;
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
            log_warn!(
                "stream {} 连接 {peer} 无可用目标（未配 proxy_pass 且 SNI 未命中）",
                srv.listen
            );
            return;
        }
    };
    let (spec, upstream_guard) = match resolve_target(&pool, &target, &client_ip) {
        Some(s) => s,
        None => {
            log_warn!("stream 目标 {target} 无可用后端节点（no live upstreams）");
            return;
        }
    };
    let mut backend = match connect_with_timeout(&spec, srv.connect_timeout).await {
        Ok(b) => {
            // 连接成功即视为节点存活（被动健康检查）；隧道期间的 max_conns 由 guard 持有
            if let Some(g) = &upstream_guard {
                g.note_success();
            }
            b
        }
        Err(e) => {
            if let Some(g) = &upstream_guard {
                g.note_failure();
            }
            log_error!("stream 连接后端 {spec} 失败: {e}");
            return;
        }
    };

    // 把已窥探的字节原样补给后端，保证字节透明（ClientHello 一个都不能少）。
    if !prefix.is_empty() && backend.write_all(&prefix).await.is_err() {
        return;
    }
    relay(client, backend, srv.proxy_timeout).await;
    // guard 在这里释放：upstream 的 conns 计数覆盖整条隧道，而不是只覆盖 connect
    drop(upstream_guard);
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

/// 双向接力：两个方向在同一任务内并发（join），任一方向读空闲超过 idle（0=不限）
/// 或 EOF/错误即结束本方向。不用 `tokio::spawn`：外层连接任务被停机 abort 时，
/// 两个方向会一起被取消，不会留下持有半条 socket 的孤儿任务。
async fn relay(client: TcpStream, backend: TcpStream, idle: Duration) {
    let (mut cr, mut cw) = client.into_split();
    let (mut br, mut bw) = backend.into_split();
    let to_client = async {
        pump(&mut br, &mut cw, idle).await;
        // 后端 EOF：向客户端发 FIN，让对端知道响应结束
        let _ = cw.shutdown().await;
    };
    let to_backend = async {
        pump(&mut cr, &mut bw, idle).await;
        let _ = bw.shutdown().await;
    };
    tokio::join!(to_client, to_backend);
}

/// 单向泵：read→write 直到 EOF/错误/空闲超时（WebSocket 隧道也复用）。
pub(crate) async fn pump<R, W>(r: &mut R, w: &mut W, idle: Duration)
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

// ==================== 四层 UDP（数据报代理） ====================
//
// 与 TCP 隧道完全不同的一条通路：没有连接、没有"读完再写"，只有"一个客户端 4 元组
// 对应一条到后端的通道"。游戏 / 语音 / 实时状态同步这类业务全靠这个形状，而它的难点
// 不在转发一个包，在几万到几十万小包下的那几个边界：
//
// * **回包必须回到发起它的那个客户端**。会话按 (客户端 IP, 端口) 归位，并且每会话一条
//   `connect` 到后端的 socket——连好之后内核只把那个源发来的报文交给我们，别人伪造的
//   回包进不来。把 A 的位置/血量/房间状态发给 B 不是"体验差"，是跨用户数据泄漏。
// * **会话必须有生命周期**。没有回收就没有 UDP 代理：源地址可以伪造，洪水会让会话表
//   无限增长。`proxy_timeout` 就是这条边（nginx 同义：空闲多久就丢掉这个"伪连接"）。
//   会话数还与 `worker_connections` 共用同一个额度——一个会话就是一条 socket、一个 fd。
//   额度用尽时**丢包并计数**，而不是把进程拖到 EMFILE。
// * `proxy_responses 0` 是"只管发、不等回包"（心跳、状态上报）。这种形态不该建会话、
//   不该占 fd，所以在主循环里直接 `send_to`，一个任务都不开。
// * 队列满时丢包，不排队到内存里。对 UDP 来说丢一个包是协议允许的结果。

/// 单个数据报的上限（UDP 规范值）
const MAX_DATAGRAM: usize = 65535;

/// 每个会话的入向队列长度；满了直接丢并计数
const SESSION_QUEUE: usize = 256;

/// 会话表大到这个数就顺手清一次"任务已结束但表里还在"的条目
const SESSION_SWEEP_TRIGGER: usize = 4096;

/// UDP 侧的运行计数（`/metrics` 渲染；没开 UDP 监听时一个指标都不出，
/// 免得把 `off` 这个配置状态渲染成一堆零，让人以为有个空闲的 UDP 入口）
#[derive(Debug, Default)]
pub struct UdpCounters {
    datagrams_in: AtomicU64,
    bytes_in: AtomicU64,
    forwarded: AtomicU64,
    responses: AtomicU64,
    sessions_total: AtomicU64,
    sessions_live: AtomicI64,
    drop_no_permit: AtomicU64,
    drop_session_cap: AtomicU64,
    drop_queue_full: AtomicU64,
    drop_send_failed: AtomicU64,
}

/// 会话表条目的入向端
type SessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;

pub struct UdpStats {
    pub datagrams_in: u64,
    pub bytes_in: u64,
    pub forwarded: u64,
    pub responses: u64,
    pub sessions_total: u64,
    pub sessions_live: i64,
    pub drop_no_permit: u64,
    pub drop_session_cap: u64,
    pub drop_queue_full: u64,
    pub drop_send_failed: u64,
}

static UDP: OnceLock<UdpCounters> = OnceLock::new();

fn udp() -> &'static UdpCounters {
    UDP.get_or_init(UdpCounters::default)
}

pub fn udp_snapshot() -> Option<UdpStats> {
    let c = UDP.get()?;
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    Some(UdpStats {
        datagrams_in: g(&c.datagrams_in),
        bytes_in: g(&c.bytes_in),
        forwarded: g(&c.forwarded),
        responses: g(&c.responses),
        sessions_total: g(&c.sessions_total),
        sessions_live: c.sessions_live.load(Ordering::Relaxed),
        drop_no_permit: g(&c.drop_no_permit),
        drop_session_cap: g(&c.drop_session_cap),
        drop_queue_full: g(&c.drop_queue_full),
        drop_send_failed: g(&c.drop_send_failed),
    })
}

/// 一个数据报入口的服务循环：收 → 按客户端 4 元组归位 → 转给会话任务（或不等回包时直接发出）。
pub async fn serve_udp(
    state: Arc<crate::server::AppState>,
    pool: Arc<UpstreamPool>,
    srv: Arc<StreamServer>,
    sock: Arc<UdpSocket>,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = srv.listen;
    let idle = srv.proxy_timeout;
    let fire_and_forget = srv.proxy_responses == 0;
    udp(); // 把计数表立起来：/metrics 由此决定渲染这一族
    log_info!(
        "stream 监听 udp://{addr}（proxy_responses={}，空闲回收 {idle:?}，{}）",
        srv.proxy_responses,
        if fire_and_forget {
            "不等回包"
        } else {
            "双向"
        }
    );

    // 不等回包时共用的出向 socket；双向模式下每个会话自己 connect
    let egress: Option<Arc<UdpSocket>> = if fire_and_forget {
        Some(Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| log_error!("stream udp://{addr} 出向 socket 失败: {e}"))
                .ok()
                .expect("绑定出向 socket"),
        ))
    } else {
        None
    };

    let mut sessions: HashMap<SocketAddr, SessionTx> = HashMap::new();
    // 本条监听的在世会话数（与 `udp_max_sessions` 比）：会话由任务自己收尾，所以是原子计数
    let live_sessions: Arc<std::sync::atomic::AtomicUsize> =
        Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cap = srv.udp_max_sessions;
    if cap == 0 && !state.routing().listeners.is_empty() {
        log_warn!(
            "stream udp://{addr} 没有设 udp_max_sessions：源地址可伪造的 UDP 洪水会吃光              worker_connections，把七层与其它四层服务一起饿死（nginx 没有这个旋钮，这里给一个）。             想要上限就写 udp_max_sessions <n>;"
        );
    }
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut sweep_logged = false;

    loop {
        let (n, peer) = tokio::select! {
            _ = shutdown.changed() => break,
            r = sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    log_warn!("stream udp://{addr} 收包失败: {e}");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            }
        };
        let count = udp();
        count.datagrams_in.fetch_add(1, Ordering::Relaxed);
        count.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        let data = &buf[..n];
        let target_spec = match srv.default_target.as_deref() {
            Some(t) => t,
            None => {
                log_warn!("stream udp://{addr} 没有 proxy_pass 目标，丢包");
                continue;
            }
        };
        let client_ip = peer.ip().to_string();

        if fire_and_forget {
            // 不建会话、不占 fd：选一个节点直接发出去
            let Some((spec, _guard)) = resolve_target(&pool, target_spec, &client_ip) else {
                count.drop_no_permit.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let Some(dest) = resolve_backend(&spec).await else {
                log_warn!("stream udp://{addr} 后端 {spec} 无法解析，丢包");
                count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            match egress.as_ref().unwrap().send_to(data, dest).await {
                Ok(m) if m == n => {
                    count.forwarded.fetch_add(1, Ordering::Relaxed);
                }
                Ok(m) => {
                    log_warn!("stream udp://{addr} 数据报被截断（发出 {m}/{n} 字节），丢包");
                    count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    log_debug!("stream udp://{addr} 发后端 {dest} 失败: {e}");
                    count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            continue;
        }

        // 双向：已有会话就直接投递；投递失败说明那头已经收摊，顺手把条目摘掉
        if let Some(tx) = sessions.get(&peer).cloned() {
            if tx.is_closed() {
                sessions.remove(&peer);
            } else {
                match tx.try_send(data.to_vec()) {
                    Ok(()) => continue,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        count.drop_queue_full.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        sessions.remove(&peer);
                    }
                }
            }
        }

        if sessions.len() >= SESSION_SWEEP_TRIGGER {
            let before = sessions.len();
            sessions.retain(|_, tx| !tx.is_closed());
            if !sweep_logged {
                log_warn!(
                    "stream udp://{addr} 会话表到达 {before} 条，回收了 {} 条已结束的空位",
                    before - sessions.len()
                );
                sweep_logged = true;
            }
        }

        // 每监听点的会话上限：先挡在这一层，别让一条吵闹的 UDP 服务把进程额度吃光
        if cap > 0 && live_sessions.load(Ordering::Relaxed) >= cap {
            count.drop_session_cap.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // 会话=一条 socket=一个 fd，所以与 HTTP/stream 共用 worker_connections 额度
        let Ok(permit) = state.permits.clone().try_acquire_owned() else {
            count.drop_no_permit.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some((spec, guard)) = resolve_target(&pool, target_spec, &client_ip) else {
            count.drop_no_permit.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(backend) = resolve_backend(&spec).await else {
            log_warn!("stream udp://{addr} 后端 {spec} 无法解析，丢包");
            count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
        sessions.insert(peer, tx);
        live_sessions.fetch_add(1, Ordering::Relaxed);
        count.sessions_total.fetch_add(1, Ordering::Relaxed);
        count.sessions_live.fetch_add(1, Ordering::Relaxed);
        let first = data.to_vec();
        tokio::spawn(udp_session(
            Arc::clone(&sock),
            Arc::clone(&srv),
            peer,
            backend,
            rx,
            first,
            guard,
            permit,
            Arc::clone(&live_sessions),
            shutdown.clone(),
        ));
    }

    // 停机：把会话条目全摘掉，各任务的 rx 随之关闭并自行收尾
    sessions.clear();
    log_info!("stream udp://{addr} 已停止");
}

/// 把一个后端写法（`ip:port`，或带域名的字面量）落成一个可发的地址。
async fn resolve_backend(spec: &str) -> Option<SocketAddr> {
    if let Ok(a) = spec.parse::<SocketAddr>() {
        return Some(a);
    }
    let mut addrs = tokio::net::lookup_host(spec).await.ok()?;
    addrs.next()
}

/// 一个客户端会话：一条 connect 到后端的 socket + 双向搬运 + 空闲回收。
///
/// `permit`/`guard` 必须随会话存活：前者是 worker_connections 额度（会话=一个 fd），
/// 后者是 upstream 的并发计数（`max_conns`）。它们在函数返回时才释放。
async fn udp_session(
    gw: Arc<UdpSocket>,
    srv: Arc<StreamServer>,
    peer: SocketAddr,
    backend: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    first: Vec<u8>,
    _guard: Option<UpstreamGuard>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    live_sessions: Arc<std::sync::atomic::AtomicUsize>,
    mut shutdown: watch::Receiver<bool>,
) {
    let count = udp();
    // 先 bind 再 connect：connect 之后内核只把**这个后端**发来的报文交给我们，
    // 于是"把 A 的状态发给 B"这条路径在操作系统层面就不存在
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            log_warn!("stream udp 会话 {peer} 建 socket 失败: {e}");
            live_sessions.fetch_sub(1, Ordering::Relaxed);
            count.sessions_live.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };
    if let Err(e) = sock.connect(backend).await {
        log_warn!("stream udp 会话 {peer} → {backend} 连接失败: {e}");
        live_sessions.fetch_sub(1, Ordering::Relaxed);
        count.sessions_live.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    let idle = srv.proxy_timeout;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    // 第一个包已经在主循环里收到，先把它发出去，别再等 rx
    let mut pending: Option<Vec<u8>> = Some(first);

    loop {
        // 空闲上限每轮重算：任何一次收发都算"还活着"
        let deadline = if idle.is_zero() {
            tokio::time::Instant::now() + Duration::from_secs(365 * 24 * 3600)
        } else {
            tokio::time::Instant::now() + idle
        };
        let out = {
            let pending = &mut pending;
            let rx = &mut rx;
            async move {
                match pending.take() {
                    Some(d) => Some(d),
                    None => rx.recv().await,
                }
            }
        };
        tokio::select! {
            biased;
            maybe = out => {
                let Some(data) = maybe else {
                    // rx 关闭（主循环停机或会话被摘掉）
                    break;
                };
                let n = data.len();
                match sock.send(&data).await {
                    Ok(m) if m == n => { count.forwarded.fetch_add(1, Ordering::Relaxed); }
                    Ok(m) => {
                        log_warn!("stream udp 会话 {peer}：数据报被截断（{m}/{n} 字节）");
                        count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        log_debug!("stream udp 会话 {peer} → {backend} 发送失败: {e}");
                        count.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            r = sock.recv(&mut buf) => match r {
                Ok(n) => {
                    // 回包只可能来自这个后端（socket 已 connect），因此这里不存在
                    // "把别人的状态发给这位客户端"的路径
                    count.responses.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = gw.send_to(&buf[..n], peer).await {
                        log_debug!("stream udp 回包给 {peer} 失败: {e}");
                    }
                }
                Err(e) => {
                    log_debug!("stream udp 会话 {peer} 收后端失败: {e}");
                    break;
                }
            },
            _ = tokio::time::sleep_until(deadline), if !idle.is_zero() => {
                log_debug!("stream udp 会话 {peer} 空闲超过 {idle:?}，回收");
                break;
            }
            _ = shutdown.changed() => break,
        }
    }
    live_sessions.fetch_sub(1, Ordering::Relaxed);
    count.sessions_live.fetch_sub(1, Ordering::Relaxed);
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
        assert_eq!(
            parse_client_hello_sni(&[0x17, 0x03, 0x03, 0x00, 0x10]),
            None
        );
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
            crate::router::SniMatch {
                pattern: "*.example.com".into(),
                target: "up_a".into(),
            },
            crate::router::SniMatch {
                pattern: "a.example.com".into(),
                target: "up_b".into(),
            },
        ];
        assert_eq!(
            pick_sni_target(&srv, Some("a.example.com")).as_deref(),
            Some("up_a")
        );
        assert_eq!(pick_sni_target(&srv, Some("other.net")).as_deref(), None);
        assert_eq!(pick_sni_target(&srv, None).as_deref(), None);
    }
}
