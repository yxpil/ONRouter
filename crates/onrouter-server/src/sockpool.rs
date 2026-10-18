// ngx.socket.tcp cosocket 连接池（对标 OpenResty 的 lua_socket_pool）。
//
// 语义：`sock:setkeepalive(timeout?, pool_size?)` 把一条已连接、且无在途收发的 TCP 连接
// （连同 receive 残留缓冲）按 `host:port` 键放回进程级空闲池；后续 `sock:connect(host, port)`
// 优先从池里复用一条未超时的连接，避免重复三次握手。池按 key 维护 FIFO，超过 pool_size 时
// 淘汰最旧空闲项（被丢弃的连接随 TcpStream drop 而关闭）。
//
// 锁约定：临界区只做 HashMap/VecDeque 的增删与 move，**绝不跨 await 持锁**，因此用轻量的
// std::sync::Mutex 即可，无需 tokio 异步互斥。

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// 池中的一条空闲连接：保留底层流与 receive 的残留字节，复用时原样带回。
struct IdleConn {
    stream: TcpStream,
    buf: Vec<u8>,
    /// 绝对到期时刻；取用时晚于此刻的连接视为失效并丢弃。
    deadline: Instant,
}

/// 默认单 key 池上限（对标 `lua_socket_pool_size` 的默认 30）。
const DEFAULT_POOL_SIZE: usize = 30;

fn pool() -> &'static Mutex<HashMap<String, VecDeque<IdleConn>>> {
    static POOL: OnceLock<Mutex<HashMap<String, VecDeque<IdleConn>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 放回一条空闲连接。`idle` 为空闲保有时长；`pool_size` 为该 key 的容量上限（0 用默认）。
/// 超容量时淘汰最旧项。放入前先确保连接已半关闭读方向无残留语义问题——这里只 move，不触碰 fd。
pub fn put(key: String, stream: TcpStream, buf: Vec<u8>, idle: Duration, pool_size: usize) {
    let cap = if pool_size == 0 {
        DEFAULT_POOL_SIZE
    } else {
        pool_size
    };
    let mut g = match pool().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let q = g.entry(key).or_default();
    q.push_back(IdleConn {
        stream,
        buf,
        deadline: Instant::now() + idle,
    });
    // 超容量：丢弃最旧（其 TcpStream 随 drop 关闭）。
    while q.len() > cap {
        q.pop_front();
    }
}

/// 取出一条可用连接：跳过并丢弃已到期项，返回首个未超时的 (stream, 残留 buf)。
pub fn take(key: &str) -> Option<(TcpStream, Vec<u8>)> {
    let mut g = match pool().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    let q = match g.get_mut(key) {
        Some(q) => q,
        None => return None,
    };
    while let Some(entry) = q.pop_front() {
        if entry.deadline > now {
            if q.is_empty() {
                g.remove(key);
            }
            return Some((entry.stream, entry.buf));
        }
        // 已超时：drop entry（连接随之关闭），继续找下一条。
    }
    g.remove(key);
    None
}

/// 某 key 当前空闲连接数（含未到期；主要供测试与观测）。
#[allow(dead_code)]
pub fn idle_count(key: &str) -> usize {
    let g = match pool().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.get(key).map(|q| q.len()).unwrap_or(0)
}

/// 清空整个池（主要供测试隔离）。
#[cfg(test)]
pub fn clear() {
    let mut g = match pool().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn localhost_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn put_then_take_roundtrip_preserves_buf() {
        clear();
        let (client, _server) = localhost_pair().await;
        let key = "127.0.0.1:9".to_string();
        put(key.clone(), client, vec![1, 2, 3], Duration::from_secs(60), 0);
        assert_eq!(idle_count(&key), 1);
        let (s, buf) = take(&key).expect("应复用刚放入的连接");
        assert_eq!(buf, vec![1, 2, 3]);
        assert!(s.peer_addr().is_ok());
        // 取空后 key 被回收。
        assert_eq!(idle_count(&key), 0);
        assert!(take(&key).is_none());
    }

    #[tokio::test]
    async fn expired_entries_are_dropped() {
        clear();
        let (client, _server) = localhost_pair().await;
        let key = "127.0.0.1:8".to_string();
        // 负 idle：立即到期。
        put(key.clone(), client, vec![7], Duration::ZERO, 0);
        // deadline = now + 0；take 时 now >= deadline → 判定过期丢弃。
        assert!(take(&key).is_none());
        assert_eq!(idle_count(&key), 0);
    }

    #[tokio::test]
    async fn pool_size_evicts_oldest_fifo() {
        clear();
        let key = "127.0.0.1:7".to_string();
        let mut conns = Vec::new();
        for _ in 0..4 {
            conns.push(localhost_pair().await.0);
        }
        for (i, c) in conns.into_iter().enumerate() {
            // 用不同残留标记顺序，cap=2 只留最近两条。
            put(key.clone(), c, vec![i as u8], Duration::from_secs(60), 2);
        }
        assert_eq!(idle_count(&key), 2);
        let (_, buf1) = take(&key).unwrap();
        let (_, buf2) = take(&key).unwrap();
        assert_eq!(buf1, vec![2]);
        assert_eq!(buf2, vec![3]);
    }
}
