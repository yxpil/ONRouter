//! 磁盘冷层 —— `ngx.shared.DICT` 的第二层存储。
//!
//! 分层定位：**内存是热层，磁盘是冷层，一个 key 在任一时刻只属于其中一层**。
//! 冷命中即"提升"（数据搬回内存，冷层副本随之注销）；内存压力下的淘汰受害者若访问
//! 频次达到 `spill_after` 就"落盘"，否则直接丢弃。Lua 侧看到的仍然是一个
//! `ngx.shared.DICT`，API 面一个字节都没改，分层完全由配置指令开启：
//!
//! ```text
//! lua_shared_dict session 10m disk=cache/dict max_disk=512m levels=1:2
//!                 spill_after=3 max_value=64k inactive=10m;
//! ```
//!
//! 条目文件布局（对标 nginx `proxy_cache_path levels=`，但条目自描述、不需要索引文件）：
//! ```text
//! <root>/<hex[0..l0]>/<hex[0..l0+l1]>/<16位hex>.bin
//! ```
//! 路径**只由 key 哈希的十六进制字符拼出**，key 原文永不进入路径——所以 `../../`、
//! 反斜杠、NUL、任意 Unicode 的 key 都不可能把写入挪到 root 之外。key 存在条目体内，
//! 扫描重建以体内为准，读回时再比对一次（哈希撞名可检出并丢弃）。
//!
//! 头部 32 字节 + key + value：
//! ```text
//!  0.. 4  magic "ORDK"   4 version   5 flags(bit0=有 expires)   6..8 保留
//!  8..12  key_len(u32)  12..16 val_len(u32)  16..24 expires(f64)
//! 24..28  freq(f32)     28..32 crc32(key || value)
//! ```
//!
//! 四条硬纪律（下面的结构都是被它们逼出来的）：
//!   * **落盘全异步**：文件只由每个 store 的一个写线程创建/替换/删除（temp+rename）。
//!     请求线程只做"编码 + 入队"，绝不在请求路径上写磁盘。排队期间的数据属于"还没落地
//!     的那一代"：`forget` 用 per-key 墓碑拦迟到的旧值，`purge`（`flush_all`）推进全区
//!     代际计数，把 flush 之前入队的整批落盘作废——否则被 flush 掉的 key 会在几毫秒后
//!     自己复活，重启扫目录还能把它们读回来。
//!   * **真未命中零 IO**：冷层有内存索引，key 不在索引里就只是又一次哈希表未命中，
//!     不会 open 任何文件。只有真正的冷命中才付一次小文件读的代价——与项目里
//!     `require()` / `content_by_lua_file` 早已存在的同步读盘同一量级。
//!   * **容量判定与逐出分离**（对标 nginx：`max_size` 由后台 cache manager 清理）：
//!     落盘路径只做"满了就不落"的 O(1) 判定，逐出全部发生在后台清扫里。淘汰受害者是
//!     持着分片锁被丢弃的，那里绝不能做 O(n) 扫描或磁盘删除。
//!   * **坏数据一律丢弃并计数**：截断、magic/版本不符、CRC 不符、key 不符、长度字段撒谎
//!     都按未命中处理并异步删除该文件；长度一律按上限校验，绝不用它做无界分配；绝不 panic。
//!
//! 锁序约定：允许"持内存分片锁 → 拿冷层索引锁"，**禁止**"持冷层索引锁 → 拿分片锁"。
//! 分片锁内只允许两类索引接触：[`DiskStore::spill`]（原子量判定 + 编码 + 入队，不拿索引锁）
//! 与 [`DiskStore::forget`]（摘索引 + 排队删除，纳秒级）。冷读的索引锁在文件 IO 之前就释放，
//! 提升时的分片锁则完全不依赖索引锁，因此不存在环。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{log_debug, log_error, log_info, log_warn};

const MAGIC: [u8; 4] = *b"ORDK";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 32;
const FLAG_EXPIRES: u8 = 1 << 0;

/// 默认单条落盘上限：冷层只收"小而下落不明"的数据，一次冷读必然是一个小文件的顺序读，
/// 代价可预期；大对象留在内存层或干脆不缓存。
pub const DEFAULT_MAX_VALUE: usize = 64 * 1024;
/// 写了 `disk=` 但没写 `max_disk=` 时的冷层容量上限。
pub const DEFAULT_MAX_DISK: u64 = 256 * 1024 * 1024;
/// 排队未落盘任务的字节上限。宁可丢弃这次落盘，也不让磁盘反压到请求线程。
const PENDING_BYTES_CAP: u64 = 32 * 1024 * 1024;
/// 排队未落盘任务的条数上限。
const PENDING_JOBS_CAP: u64 = 8192;
/// 已删除/覆盖 key 的墓碑保留时长。期间同 key 更早的异步落盘任务会被丢弃，
/// 否则"淘汰已入队 → 新值覆盖 → 迟到的旧落盘"会把旧值复活成一条冷条目。
const TOMBSTONE_TTL: Duration = Duration::from_secs(120);
/// 墓碑表规模上限：异常流量下宁可提前回收墓碑，也不能让它无界增长。
const TOMBSTONE_CAP: usize = 65536;
/// 写线程空闲多久检查一次"自己是否已无人引用"。
const WRITER_IDLE: Duration = Duration::from_secs(1);
/// `flush_pending` 的有界等待：冷层是尽力而为的下一层，停机不该为它无限挂住。
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// 一轮清扫最多逐出多少条，避免脏账或畸形目录树把维护任务占死。
const TRIM_BATCH: usize = 10_000;

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 冷层用的同一个时钟，暴露给 DICT 之外的调用方（`proxy_cache` 落盘时要算绝对到期时刻）。
/// 自己调 `SystemTime` 会引入第二套口径，条目 TTL 与索引记账就对不上了。
pub fn epoch_now() -> f64 {
    now_epoch()
}

/// 跨进程稳定的 key 哈希，用于目录分片与文件名。
///
/// 不能用 `DefaultHasher`/`RandomState`：冷层路径必须能在进程重启后由同一个 key 重新
/// 推导出来，而那两类哈希不保证跨进程一致（`RandomState` 还带随机种子）。
/// 这里用 FNV-1a 64 再加一轮末位混淆：无依赖、无种子、结果确定。
pub fn key_hash(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 29;
    h
}

/// `levels=1:2` 解析（对标 nginx）：每个分量 1..=3，最多 3 级，总长 ≤ 12（必须给
/// 文件名留出十六进制位）。非法返回 None —— 配置期直接报错，不静默降级。
pub fn parse_levels(spec: &str) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for part in spec.split(':') {
        let n: usize = part.trim().parse().ok()?;
        if !(1..=3).contains(&n) {
            return None;
        }
        out.push(n);
    }
    if out.is_empty() || out.len() > 3 || out.iter().sum::<usize>() > 12 {
        return None;
    }
    Some(out)
}

/// 由 key 推导条目文件路径。root 之外不可能被到达：路径分量只可能是 `[0-9a-f]*`。
pub fn entry_path(root: &Path, levels: &[usize], key: &str) -> PathBuf {
    let hex = format!("{:016x}", key_hash(key));
    let mut p = PathBuf::from(root);
    let mut off = 0usize;
    for l in levels {
        off = (off + l).min(hex.len());
        p.push(&hex[..off]);
    }
    p.push(format!("{hex}.bin"));
    p
}

/// 冷层容量与保留策略，全部来自 `lua_shared_dict` 的参数。
#[derive(Debug, Clone)]
pub struct DiskConfig {
    pub root: PathBuf,
    /// 冷层字节上限；超限由后台清扫按分数逐出最冷的条目。0 = 禁用落盘。
    pub max_bytes: u64,
    pub levels: Vec<usize>,
    /// 超过这么久没被访问的冷条目由清扫回收；0 = 不按活跃度回收（只受 TTL 与容量约束）
    pub inactive: Duration,
    /// 衰减访问次数达到该阈值的内存淘汰受害者才落盘（"低频落盘"的阈值）
    pub spill_after: f32,
    /// 单条 value 的落盘上限
    pub max_value: usize,
}

impl Default for DiskConfig {
    fn default() -> Self {
        DiskConfig {
            root: PathBuf::from("cache/dict"),
            max_bytes: DEFAULT_MAX_DISK,
            levels: vec![1, 2],
            inactive: Duration::ZERO,
            spill_after: 3.0,
            max_value: DEFAULT_MAX_VALUE,
        }
    }
}

/// 冷热判定特征。学习型策略（后续可能接入的 <5MB 小模型）只需要读这几个字段，
/// 不需要理解分层机制本身——这就是留给策略的接缝。
///
/// 基线 [`ClockFrequency`] 只用到 `freq` 与 `age_ms`；其余字段是接缝的一部分，
/// 现在没人读不代表该删——删了就得在下一个策略落地时重新设计一遍签名。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Features {
    /// 衰减后的访问次数
    pub freq: f32,
    /// 距上次访问过了多少毫秒
    pub age_ms: u64,
    pub value_len: usize,
    /// 剩余存活秒数；None = 永不过期
    pub ttl_left: Option<f64>,
    /// 该条目当前位于冷层（用于冷层内部逐出排序）
    pub on_disk: bool,
}

/// 分层策略接缝：分数越低越先离开热层、越先被冷层丢弃。
///
/// 实现者必须遵守的约定（写死在这里）：
///   * 纯函数、无 IO、无阻塞、单次调用预算微秒级——它跑在淘汰与逐出路径上。
///   * 返回 NaN/Inf 会被调用侧视为"策略坏了"并回落到 [`ClockFrequency`]，所以坏掉的
///     策略只会让分层退回确定性基线，不会丢数据、不会卡请求。
pub trait Scorer: Send + Sync + std::fmt::Debug {
    fn score(&self, f: &Features) -> f32;
}

/// 确定性基线：recency（1/(1+age 秒)）+ 频次对数项。
/// 所有条目频次相同时排序退化为与旧的近似 LRU 完全一致，因此默认行为不变。
#[derive(Debug, Default, Clone, Copy)]
pub struct ClockFrequency;

impl Scorer for ClockFrequency {
    fn score(&self, f: &Features) -> f32 {
        let age_s = (f.age_ms as f64 / 1000.0).max(0.0) as f32;
        let recency = 1.0 / (1.0 + age_s);
        let hot = (1.0 + f.freq.max(0.0)).ln();
        recency + 0.25 * hot
    }
}

/// 冷层计数：供 `/metrics` 与运维判断"分层到底有没有在转"。
#[derive(Debug, Default)]
pub struct DiskStats {
    /// 已提交的落盘任务数（含随后被墓碑拦截的）
    pub spilled: AtomicU64,
    /// 落盘被跳过：超 max_value / 已过期 / 冷层或队列已满 / 写线程不可用
    pub spill_skipped: AtomicU64,
    pub cold_hit: AtomicU64,
    /// 提升到内存层的冷条目数（= 分层真正生效的次数）
    pub promoted: AtomicU64,
    pub cold_error: AtomicU64,
    pub corrupt: AtomicU64,
    pub expired_removed: AtomicU64,
    pub evicted: AtomicU64,
    /// 落盘成功后从未被读过就被清掉的条目（冷层里有死数据的信号）
    pub never_read: AtomicU64,
    /// 已落盘条目占的字节（含头部）
    pub bytes: AtomicU64,
    pub entries: AtomicU64,
    /// 排队未落盘的字节/条数（运维看落盘是否滞后）
    pub pending_bytes: AtomicU64,
    pub pending_jobs: AtomicU64,
    /// 启动扫描重建恢复出来的条目数
    pub warm_recovered: AtomicU64,
}

impl DiskStats {
    #[inline]
    fn bump(&self, c: &AtomicU64) -> u64 {
        c.fetch_add(1, Ordering::Relaxed) + 1
    }
    #[inline]
    fn add(&self, c: &AtomicU64, n: u64) {
        if n > 0 {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }
    #[inline]
    fn sub(&self, c: &AtomicU64, n: u64) {
        let mut cur = c.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            match c.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// 冷层内存索引里的一条（不含 value，value 在文件里）。
struct ColdSlot {
    path: PathBuf,
    val_len: u32,
    /// 条目文件字节数（含头）
    bytes: u64,
    expires: Option<f64>,
    freq: f32,
    /// 最后一次被读/写的时间戳（`inactive` 回收与冷层逐出排序用）
    last_used: f64,
    /// 入册时的全局序号，用于丢弃迟到的异步落盘
    seq: u64,
    /// 落盘后是否被读过（`never_read` 判定）
    read: bool,
}

impl ColdSlot {
    fn alive(&self, now: f64) -> bool {
        match self.expires {
            Some(t) => now < t,
            None => true,
        }
    }
}

struct Tombstone {
    seq: u64,
    at: Instant,
}

#[derive(Default)]
struct Index {
    slots: HashMap<String, ColdSlot>,
    /// 已删除/覆盖的 key → 删除时的序号；见模块头"迟到的旧落盘"说明
    tomb: HashMap<String, Tombstone>,
}

enum Job {
    /// 已编码好的条目字节；写线程负责 temp+rename 与索引登记。
    /// `epoch` 是入队时的"代"：`purge()`（flush_all）推进一代，比它旧的下盘直接丢弃。
    Write {
        key: String,
        seq: u64,
        epoch: u64,
        bytes: Vec<u8>,
    },
    Remove {
        path: PathBuf,
    },
    /// 腾出 `need` 字节的额度：由写线程逐出最冷的条目（请求线程绝不做 O(n) 逐出）
    Trim {
        need: u64,
    },
    /// 屏障：此前入队的所有任务都处理完才应答（FIFO 保证）
    Barrier(std::sync::mpsc::Sender<bool>),
}

struct Inner {
    cfg: Arc<DiskConfig>,
    index: Arc<Mutex<Index>>,
    stats: Arc<DiskStats>,
    seq: AtomicU64,
    /// 全区级"代"号：`purge()`（`flush_all`）推进一代。排队中的落盘任务带着入队时的
    /// 代，落地下盘时代已变 → 丢弃。没有它，"淘汰已入队 → flush_all 摘空索引 → 迟到的
    /// 落盘登记索引"会让一条本该被 flush 掉的数据复活，重启扫目录还能把它读回来。
    epoch: Arc<AtomicU64>,
    /// 策略接缝：默认 [`ClockFrequency`]
    scorer: Arc<dyn Scorer>,
    tx: Mutex<Option<std::sync::mpsc::Sender<Job>>>,
    /// 写线程是否还活着（起线程失败时置 false，落盘自动降级为丢弃）
    alive: std::sync::atomic::AtomicBool,
    /// 是否已有一次腾额度任务在排队：合并高频的"满了"判定，避免队列被 Trim 灌满
    trim_queued: Arc<std::sync::atomic::AtomicBool>,
    /// 上次为"落盘队列打满"告警的epoch 秒。持续告警会把日志刷满，反而看不见别的。
    spill_full_warn_at: AtomicU64,
}

/// 可克隆的磁盘冷层句柄：同一区的 16 个分片、16 个 VM 共享同一个 store。
#[derive(Clone)]
pub struct DiskStore {
    inner: Arc<Inner>,
}

/// 只打运维关心的量：日志/断言里出现 store 时不该把索引整个倒出来。
impl std::fmt::Debug for DiskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskStore")
            .field("root", &self.inner.cfg.root)
            .field("max_bytes", &self.inner.cfg.max_bytes)
            .field("entries", &self.inner.stats.entries.load(Ordering::Relaxed))
            .field("bytes", &self.inner.stats.bytes.load(Ordering::Relaxed))
            .finish()
    }
}

/// 一次冷读拿到的完整条目。
pub struct ColdValue {
    pub value: Vec<u8>,
    pub expires: Option<f64>,
    /// 落盘时记录的衰减频次；提升回内存后接着累加，热度历史不因搬迁而清零
    pub freq: f32,
    /// 冷层里这条已过期（对标 `get_stale` 的 stale 标志）
    pub expired: bool,
}

impl DiskStore {
    /// 打开（或创建）冷层。启动时扫目录重建索引（warm start），坏条目丢弃并计数。
    pub fn open(cfg: DiskConfig, scorer: Option<Arc<dyn Scorer>>) -> Result<Self, String> {
        std::fs::create_dir_all(&cfg.root)
            .map_err(|e| format!("创建磁盘冷层目录 {:?} 失败: {e}", cfg.root))?;
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let inner = Arc::new(Inner {
            cfg: Arc::new(cfg),
            index: Arc::new(Mutex::new(Index::default())),
            stats: Arc::new(DiskStats::default()),
            seq: AtomicU64::new(0),
            epoch: Arc::new(AtomicU64::new(0)),
            scorer: scorer.unwrap_or_else(|| Arc::new(ClockFrequency)),
            tx: Mutex::new(Some(tx)),
            alive: std::sync::atomic::AtomicBool::new(true),
            trim_queued: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            spill_full_warn_at: AtomicU64::new(0),
        });
        let store = DiskStore { inner };
        let recovered = store.scan_rebuild()?;
        store
            .inner
            .stats
            .warm_recovered
            .store(recovered as u64, Ordering::Relaxed);
        if recovered > 0 {
            log_info!(
                "磁盘冷层 {:?}：扫描重建恢复 {recovered} 条 / {} 字节",
                store.inner.cfg.root,
                store.bytes_used()
            );
        }
        store.spawn_writer(rx);
        Ok(store)
    }

    pub fn config(&self) -> &Arc<DiskConfig> {
        &self.inner.cfg
    }

    pub fn stats(&self) -> &Arc<DiskStats> {
        &self.inner.stats
    }

    /// 内存淘汰受害者该不该落盘（"低频落盘"的判定门）。
    ///
    /// 学习型策略要替换的就是这个门 + [`Scorer`]；签名里只出现特征值，不出现任何分层
    /// 内部结构，模型可以独立演进。
    pub fn admit(&self, freq: f32, value_len: usize, expires: Option<f64>) -> bool {
        let cfg = &self.inner.cfg;
        cfg.max_bytes > 0
            && value_len <= cfg.max_value
            && freq >= cfg.spill_after
            && expires.map_or(true, |t| now_epoch() < t)
    }

    /// 按当前策略给一个特征打分（NaN 兜底到基线）。内存层选淘汰受害者时也走这里，
    /// 保证两层的排序口径一致。
    pub fn score(&self, f: &Features) -> f32 {
        let v = self.inner.scorer.score(f);
        if v.is_finite() {
            v
        } else {
            ClockFrequency.score(f)
        }
    }

    /// 该 key 是否在冷层且未过期（只查索引，零 IO）。
    pub fn has(&self, key: &str) -> bool {
        let now = now_epoch();
        let idx = self.lock();
        idx.slots.get(key).is_some_and(|s| s.alive(now))
    }

    /// 冷层剩余 TTL（只查索引，零 IO）：None=不在冷层，Some(-1)=永不过期，
    /// Some(0)=在索引里但已过期（过期项仍可被 `get_stale` 读到，与内存层一致）。
    pub fn ttl(&self, key: &str) -> Option<f64> {
        let now = now_epoch();
        let idx = self.lock();
        idx.slots
            .get(key)
            .map(|s| s.expires.map(|t| (t - now).max(0.0)).unwrap_or(-1.0))
    }

    /// 冷读。`allow_expired=true` 对标 `get_stale`（过期条目仍返回，由调用方标记 stale）。
    ///
    /// 这是本模块唯一发生在请求线程上的磁盘 IO，且只在真正的冷命中时发生。
    pub fn read(&self, key: &str, allow_expired: bool) -> Option<ColdValue> {
        let now = now_epoch();
        let path = {
            let mut idx = self.lock_mut();
            let s = idx.slots.get_mut(key)?;
            if !allow_expired && !s.alive(now) {
                return None;
            }
            s.last_used = now;
            s.read = true;
            s.path.clone()
        };
        match self.read_file(&path, key) {
            Ok(Some(e)) => {
                self.inner.stats.bump(&self.inner.stats.cold_hit);
                Some(ColdValue {
                    value: e.value,
                    expires: e.expires,
                    freq: e.freq,
                    expired: e.expires.is_some_and(|t| now >= t),
                })
            }
            Ok(None) => {
                // 文件已不在：索引是脏的，注销它，后续读退化成零 IO 的未命中
                self.drop_slot(key);
                let n = self.inner.stats.bump(&self.inner.stats.cold_error);
                if n % 64 == 1 {
                    log_warn!("磁盘冷层：{path:?} 已不存在（累计 {n} 次），索引已注销");
                }
                None
            }
            Err(ReadError::Corrupt) => {
                let n = self.inner.stats.bump(&self.inner.stats.corrupt);
                if n % 64 == 1 {
                    log_error!("磁盘冷层：条目 {path:?} 校验失败（累计 {n} 次），已丢弃");
                }
                self.drop_slot(key);
                self.send_remove(path);
                None
            }
            Err(ReadError::Io(e)) => {
                let n = self.inner.stats.bump(&self.inner.stats.cold_error);
                if n % 64 == 1 {
                    log_error!("磁盘冷层：读取 {path:?} 失败（累计 {n} 次）: {e}");
                }
                None
            }
        }
    }

    /// 提交一次异步落盘。返回 false 表示按策略/容量/队列决定不落（调用方直接丢弃条目）。
    ///
    /// 唯一调用点是内存层近似 LRU 选中淘汰受害者之后，**此时持有分片锁**，所以这里只做
    /// 原子量检查 + 编码 + 入队：不拿索引锁、不做 O(n) 逐出、不碰文件系统。
    pub fn spill(&self, key: &str, value: &[u8], expires: Option<f64>, freq: f32) -> bool {
        let st = &self.inner.stats;
        let cost = (HEADER_LEN + key.len() + value.len()) as u64;
        let skip = || {
            st.bump(&st.spill_skipped);
            false
        };
        if !self.inner.alive.load(Ordering::Relaxed) {
            return skip();
        }
        if self.inner.cfg.max_bytes == 0 || cost > self.inner.cfg.max_bytes {
            return skip();
        }
        // max_value 在这里也兜一道：[`admit`] 是策略门，这里是守门员——
        // 调用方（内存淘汰路径）万一漏判，也不能让一条超大 value 把磁盘层撑爆
        if value.len() > self.inner.cfg.max_value {
            return skip();
        }
        if expires.is_some_and(|t| now_epoch() >= t) {
            return skip();
        }
        // 满了就拒掉这一次，并把"腾地方"派给写线程（见模块头"容量判定与逐出分离"）。
        // 不做同步逐出：这里持有内存分片锁，O(n) 扫描 + 删文件会把淘汰路径变成阻塞操作。
        let on_disk = st.bytes.load(Ordering::Relaxed);
        let pending = st.pending_bytes.load(Ordering::Relaxed);
        if on_disk.saturating_add(pending).saturating_add(cost) > self.inner.cfg.max_bytes {
            self.inner.schedule_trim(cost);
            return skip();
        }
        if pending + cost > PENDING_BYTES_CAP
            || st.pending_jobs.load(Ordering::Relaxed) >= PENDING_JOBS_CAP
        {
            self.warn_spill_full(pending);
            return skip();
        }
        st.pending_bytes.fetch_add(cost, Ordering::Relaxed);
        st.pending_jobs.fetch_add(1, Ordering::Relaxed);
        let job = Job::Write {
            key: key.to_string(),
            seq: self.inner.next_seq(),
            epoch: self.inner.epoch.load(Ordering::Relaxed),
            bytes: encode(key, value, expires, freq),
        };
        if self.inner.send(job) {
            st.bump(&st.spilled);
            true
        } else {
            st.sub(&st.pending_bytes, cost);
            st.sub(&st.pending_jobs, 1);
            skip()
        }
    }

    /// 注销冷层副本并异步删文件（提升、覆盖写、删除时调用）。
    ///
    /// 顺序固定为"先摘索引 + 立墓碑，后删文件"：并发读要么看到索引并读到完整文件，
    /// 要么看不到索引直接未命中，绝不会拿着一个已删除的路径去 open。
    pub fn forget(&self, key: &str) {
        let seq = self.inner.next_seq();
        let removed = {
            let mut idx = self.lock_mut();
            idx.tomb.insert(
                key.to_string(),
                Tombstone {
                    seq,
                    at: Instant::now(),
                },
            );
            if idx.tomb.len() > TOMBSTONE_CAP {
                let half = TOMBSTONE_TTL / 2;
                idx.tomb.retain(|_, t| t.at.elapsed() < half);
            }
            idx.slots.remove(key)
        };
        if let Some(s) = removed {
            self.inner.unaccount(s.bytes);
            if !s.read {
                self.inner.stats.bump(&self.inner.stats.never_read);
            }
            self.send_remove(s.path);
        }
    }

    /// 登记一次"冷条目已提升回内存"（由 `SharedZone` 调用，指标口径统一）。
    pub fn note_promoted(&self) {
        self.inner.stats.bump(&self.inner.stats.promoted);
    }

    /// 登记一次"策略决定不落盘"（热度不够 / 太大 / 已过期）。
    /// 运维要看的就是这个数：分层没在转通常是阈值配得太高，而不是磁盘坏了。
    pub fn note_spill_skipped(&self) {
        self.inner.stats.bump(&self.inner.stats.spill_skipped);
    }

    /// 落盘队列打满：磁盘跟不上内存淘汰的速度。60 秒最多告警一次——持续刷日志只会
    /// 把别的东西淹掉，而这次落盘本来就是尽力而为。
    fn warn_spill_full(&self, pending: u64) {
        let now = now_epoch() as u64;
        let last = self.inner.spill_full_warn_at.swap(now, Ordering::Relaxed);
        if now.saturating_sub(last) >= 60 {
            log_warn!(
                "磁盘冷层 {:?}：落盘队列已满（排队 {pending} 字节 / {} 个任务），本次落盘丢弃；冷层是尽力而为，不影响正确性",
                self.inner.cfg.root,
                self.inner.stats.pending_jobs.load(Ordering::Relaxed)
            );
        }
    }

    /// 清空整个冷层（对标 `flush_all`）：一次性摘掉索引，文件交给写线程删。
    /// 锁内只做摘取与记账，不做任何文件 IO。
    pub fn purge(&self) -> usize {
        let paths = {
            let mut idx = self.lock_mut();
            // 先推进代：此刻还在队列里的落盘任务属于被 flush 掉的那一代，落地即丢弃。
            // 只靠墓碑做不到这件事——这些 key 还没进过索引，墓碑无从登记。
            self.inner.epoch.fetch_add(1, Ordering::Relaxed);
            let mut out: Vec<PathBuf> = Vec::with_capacity(idx.slots.len());
            let mut bytes = 0u64;
            let mut never = 0u64;
            for (_, s) in std::mem::take(&mut idx.slots) {
                bytes += s.bytes;
                if !s.read {
                    never += 1;
                }
                out.push(s.path);
            }
            self.inner.unaccount(bytes);
            self.inner.stats.entries.store(0, Ordering::Relaxed);
            self.inner.stats.add(&self.inner.stats.never_read, never);
            out
        };
        let n = paths.len();
        for p in paths {
            self.send_remove(p);
        }
        n
    }

    /// 只清过期项（对标 `flush_expired`），返回清理条数。
    pub fn purge_expired(&self) -> usize {
        let now = now_epoch();
        let paths = {
            let mut idx = self.lock_mut();
            let dead: Vec<String> = idx
                .slots
                .iter()
                .filter(|(_, s)| !s.alive(now))
                .map(|(k, _)| k.clone())
                .collect();
            let mut out: Vec<PathBuf> = Vec::with_capacity(dead.len());
            for k in dead {
                if let Some(s) = idx.slots.remove(&k) {
                    self.inner.unaccount(s.bytes);
                    self.inner.stats.sub(&self.inner.stats.entries, 1);
                    if !s.read {
                        self.inner.stats.bump(&self.inner.stats.never_read);
                    }
                    out.push(s.path);
                }
            }
            out
        };
        let n = paths.len();
        self.inner
            .stats
            .add(&self.inner.stats.expired_removed, n as u64);
        for p in paths {
            self.send_remove(p);
        }
        n
    }

    /// 存活冷条目的 value 字节合计（对标 `DICT:size` 的冷层部分，零 IO）。
    pub fn value_bytes(&self) -> usize {
        let now = now_epoch();
        let idx = self.lock();
        idx.slots
            .values()
            .filter(|s| s.alive(now))
            .map(|s| s.val_len as usize)
            .sum()
    }

    /// 冷层 key 列表（`get_keys` 用），零 IO。
    pub fn keys(&self, max: usize, include_expired: bool) -> Vec<String> {
        let now = now_epoch();
        let idx = self.lock();
        idx.slots
            .iter()
            .filter(|(_, s)| include_expired || s.alive(now))
            .take(max)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn entries(&self) -> usize {
        self.lock().slots.len()
    }

    pub fn bytes_used(&self) -> u64 {
        self.inner.stats.bytes.load(Ordering::Relaxed)
    }

    /// 等写线程把排队中的落盘做完（优雅停机、热重载替换、单测里的"已可见"同步点）。
    pub fn flush_pending(&self) {
        let Some(tx) = self
            .inner
            .tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return;
        };
        let (done, wait) = std::sync::mpsc::channel();
        if tx.send(Job::Barrier(done)).is_err() {
            return;
        }
        match wait.recv_timeout(FLUSH_TIMEOUT) {
            Ok(_) => {}
            Err(_) => {
                let n = self.inner.stats.pending_jobs.load(Ordering::Relaxed);
                if n > 0 {
                    log_warn!(
                        "磁盘冷层：排空超时，仍有 {n} 个落盘任务未完成（冷层尽力而为，不影响正确性）"
                    );
                }
            }
        }
    }

    /// 后台清扫：过期回收 → `inactive` 回收 → `max_disk` 逐出 → 墓碑回收 → 账目自愈。
    /// 返回本轮移除的条目数（日志用）。
    pub fn sweep(&self) -> usize {
        let now = now_epoch();
        let inactive = self.inner.cfg.inactive;
        let mut removed_files: Vec<PathBuf> = Vec::new();
        let expired_n;
        let mut idle_n = 0u64;
        {
            let mut idx = self.lock_mut();
            let dead: Vec<String> = idx
                .slots
                .iter()
                .filter(|(_, s)| !s.alive(now))
                .map(|(k, _)| k.clone())
                .collect();
            expired_n = dead.len() as u64;
            for k in dead {
                if let Some(s) = idx.slots.remove(&k) {
                    self.inner.unaccount(s.bytes);
                    if !s.read {
                        self.inner.stats.bump(&self.inner.stats.never_read);
                    }
                    removed_files.push(s.path);
                }
            }
            if inactive != Duration::ZERO {
                let idle: Vec<String> = idx
                    .slots
                    .iter()
                    .filter(|(_, s)| now - s.last_used >= inactive.as_secs_f64())
                    .map(|(k, _)| k.clone())
                    .collect();
                idle_n = idle.len() as u64;
                for k in idle {
                    if let Some(s) = idx.slots.remove(&k) {
                        self.inner.unaccount(s.bytes);
                        if !s.read {
                            self.inner.stats.bump(&self.inner.stats.never_read);
                        }
                        removed_files.push(s.path);
                    }
                }
            }
            idx.tomb.retain(|_, t| t.at.elapsed() < TOMBSTONE_TTL);
            // 账目自愈：以索引为准重算，任何异常路径留下的偏差在这里归零
            let sum: u64 = idx.slots.values().map(|s| s.bytes).sum();
            self.inner.stats.bytes.store(sum, Ordering::Relaxed);
            self.inner
                .stats
                .entries
                .store(idx.slots.len() as u64, Ordering::Relaxed);
        }
        self.inner
            .stats
            .add(&self.inner.stats.expired_removed, expired_n);
        self.inner.stats.add(&self.inner.stats.evicted, idle_n);
        for p in removed_files {
            self.send_remove(p);
        }
        let trimmed = self.trim_to(self.inner.cfg.max_bytes);
        let n = (expired_n + idle_n + trimmed) as usize;
        if n > 0 {
            log_debug!("磁盘冷层 {:?}：清扫回收 {n} 条", self.inner.cfg.root);
        }
        n
    }

    /// 把冷层压回 `limit` 以内（只在后台跑，可以慢慢扫）。
    fn trim_to(&self, limit: u64) -> u64 {
        let mut removed = 0usize;
        while self.bytes_used() > limit {
            let Some((path, bytes, read)) = self.coldest() else {
                // 索引已空但计数没归零：以索引为准修正，避免账目永久虚高
                self.inner.stats.bytes.store(0, Ordering::Relaxed);
                self.inner.stats.entries.store(0, Ordering::Relaxed);
                break;
            };
            self.inner.unaccount(bytes);
            if !read {
                self.inner.stats.bump(&self.inner.stats.never_read);
            }
            self.send_remove(path);
            removed += 1;
            if removed >= TRIM_BATCH {
                break; // 单轮上限：极端脏账也不占住维护任务，下一轮继续
            }
        }
        if removed > 0 {
            self.inner
                .stats
                .add(&self.inner.stats.evicted, removed as u64);
        }
        removed as u64
    }

    fn coldest(&self) -> Option<(PathBuf, u64, bool)> {
        pop_coldest(&self.inner.index, &self.inner.scorer)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        self.inner.index.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn lock_mut(&self) -> std::sync::MutexGuard<'_, Index> {
        self.inner.index.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 只摘索引（文件留给调用方处理）；返回被摘掉的字节数。
    fn drop_slot(&self, key: &str) -> Option<u64> {
        let s = { self.lock_mut().slots.remove(key) }?;
        self.inner.unaccount(s.bytes);
        if !s.read {
            self.inner.stats.bump(&self.inner.stats.never_read);
        }
        Some(s.bytes)
    }

    /// 删除文件：优先交给写线程；写线程不可用时就地删（宁可让清扫多占一点时间，
    /// 也不能留下永远没人删的孤儿文件）。
    fn send_remove(&self, path: PathBuf) {
        if !self.inner.send(Job::Remove { path: path.clone() }) {
            let _ = std::fs::remove_file(&path);
        }
    }

    /// 写线程唯一入口：把已承诺的落盘任务做完。
    fn run_job(
        job: Job,
        index: &Mutex<Index>,
        stats: &Arc<DiskStats>,
        cfg: &Arc<DiskConfig>,
        scorer: &Arc<dyn Scorer>,
        trim_flag: &std::sync::atomic::AtomicBool,
        epoch: &AtomicU64,
    ) {
        match job {
            Job::Write {
                key,
                seq,
                epoch: gen,
                bytes,
            } => apply_write(index, stats, cfg, key, seq, gen, epoch, bytes),
            Job::Trim { need } => {
                run_trim(index, stats, cfg, scorer, need);
                // 先干完再解锁：期间新的"满了"判定会继续复用这个已排队的任务
                trim_flag.store(false, Ordering::Relaxed);
            }
            Job::Remove { path } => {
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        log_debug!("磁盘冷层：删 {path:?} 失败: {e}");
                    }
                }
            }
            Job::Barrier(done) => {
                // 队列是 FIFO，能收到这个任务就说明此前的活儿都干完了
                let _ = done.send(true);
            }
        }
    }

    /// 每个 store 一个写线程：本模块唯一的磁盘写入者。
    ///
    /// 线程只持 `Weak<Inner>` 作为"是否还有人用这个 store"的判据，但落盘所需的
    /// `index/stats/cfg` 是强引用克隆——所以即便 `Arc<Inner>` 已被释放（热重载替换、
    /// 停机），队列里排队的任务仍会写完，不会把已经答应的冷数据丢掉。
    fn spawn_writer(&self, rx: std::sync::mpsc::Receiver<Job>) {
        let weak = Arc::downgrade(&self.inner);
        let index = Arc::clone(&self.inner.index);
        let stats = Arc::clone(&self.inner.stats);
        let cfg = Arc::clone(&self.inner.cfg);
        let scorer = Arc::clone(&self.inner.scorer);
        let trim_flag = Arc::clone(&self.inner.trim_queued);
        let epoch = Arc::clone(&self.inner.epoch);
        let name = cfg
            .root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "dict".into());
        let spawned = std::thread::Builder::new()
            .name(format!("dict-disk-{name}"))
            .spawn(move || {
                loop {
                    let job = match rx.recv_timeout(WRITER_IDLE) {
                        Ok(j) => j,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if weak.upgrade().is_none() {
                                break;
                            }
                            continue;
                        }
                        // 所有 Sender 已随 Inner 释放：收尾队列里剩下的再退出
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    Self::run_job(job, &index, &stats, &cfg, &scorer, &trim_flag, &epoch);
                }
                // 退出前排空队列：已经答应写盘的条目不该因为 store 被替换而凭空消失
                for j in rx.try_iter() {
                    Self::run_job(j, &index, &stats, &cfg, &scorer, &trim_flag, &epoch);
                }
            });
        match spawned {
            Ok(_) => {}
            Err(e) => {
                // 没有线程 = 没有磁盘层：索引永远空，读语义仍然正确，落盘自动降级为丢弃
                log_error!("磁盘冷层：写线程启动失败: {e}，本次运行禁用落盘");
                *self.inner.tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
                self.inner.alive.store(false, Ordering::Relaxed);
            }
        }
    }

    /// 启动扫描重建（按既定决策：不维护索引文件，目录本身就是索引）。
    fn scan_rebuild(&self) -> Result<usize, String> {
        let root = self.inner.cfg.root.clone();
        let levels = self.inner.cfg.levels.clone();
        let mut stack = vec![root.clone()];
        let mut files: Vec<PathBuf> = Vec::new();
        let mut tmp_left = 0usize;
        let mut visited = 0usize;
        while let Some(dir) = stack.pop() {
            visited += 1;
            if visited > 100_000 {
                log_warn!("磁盘冷层：{root:?} 目录数异常（>100000），剩余部分本次不扫描");
                break;
            }
            let rd = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) => {
                    log_warn!("磁盘冷层：扫描 {dir:?} 失败: {e}");
                    continue;
                }
            };
            for de in rd.flatten() {
                let p = de.path();
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                // 用 symlink_metadata：冷层的目录树只许待在自己的 root 里。
                // 跟着链接走会扫到目录外面去，顺手还把别人的 .tmp 当遗留残骸删掉（S10）。
                let md = match std::fs::symlink_metadata(&p) {
                    Ok(md) => md,
                    Err(_) => continue,
                };
                if md.is_dir() {
                    stack.push(p);
                } else if md.is_file() && ext == "bin" {
                    files.push(p);
                } else if ext == "tmp" {
                    // 上次中断遗留的临时文件：与任何有效条目无关，直接删
                    // （unlink 只摘名字：即便这个 .tmp 是别人种的链接，也不碰链接指向的内容）
                    let _ = std::fs::remove_file(&p);
                    tmp_left += 1;
                }
            }
        }
        if tmp_left > 0 {
            log_info!("磁盘冷层：清理上次中断遗留的 {tmp_left} 个 .tmp 文件");
        }
        let now = now_epoch();
        let cap = self.inner.cfg.max_bytes;
        let len_cap = HEADER_LEN + 4 * self.inner.cfg.max_value;
        let mut recovered = 0usize;
        let mut dropped = 0usize;
        let mut bytes = 0u64;
        {
            let mut idx = self.lock_mut();
            idx.tomb.clear();
            for path in files {
                let entry = match read_path_at(&path, len_cap) {
                    Ok(Some(e)) => e,
                    // 损坏/截断/长度撒谎：删掉，别让坏文件一直占目录
                    _ => {
                        let _ = std::fs::remove_file(&path);
                        dropped += 1;
                        continue;
                    }
                };
                // 路径必须与 key 的哈希一致：不一致说明文件被手工挪动过，丢弃以免歧义
                let expect = entry_path(&root, &levels, &entry.key);
                if expect != path || idx.slots.contains_key(&entry.key) {
                    let _ = std::fs::remove_file(&path);
                    dropped += 1;
                    continue;
                }
                if entry.expires.is_some_and(|t| now >= t) {
                    let _ = std::fs::remove_file(&path);
                    dropped += 1;
                    continue;
                }
                if cap > 0 && bytes + entry.bytes > cap {
                    // 启动就超额：先按文件名顺序收，超出上限的直接删（运行期清扫会继续压）
                    let _ = std::fs::remove_file(&path);
                    dropped += 1;
                    continue;
                }
                bytes += entry.bytes;
                recovered += 1;
                idx.slots.insert(
                    entry.key,
                    ColdSlot {
                        path,
                        val_len: entry.val_len,
                        bytes: entry.bytes,
                        expires: entry.expires,
                        freq: entry.freq,
                        last_used: now,
                        seq: 0,
                        read: false,
                    },
                );
            }
            self.inner.stats.bytes.store(bytes, Ordering::Relaxed);
            self.inner
                .stats
                .entries
                .store(idx.slots.len() as u64, Ordering::Relaxed);
        }
        self.inner
            .stats
            .add(&self.inner.stats.corrupt, dropped as u64);
        if dropped > 0 {
            log_warn!("磁盘冷层：扫描 {root:?} 丢弃 {dropped} 个无效/超额条目文件");
        }
        Ok(recovered)
    }

    fn read_file(&self, path: &Path, expect_key: &str) -> Result<Option<FileEntry>, ReadError> {
        let cap = HEADER_LEN + 4 * self.inner.cfg.max_value;
        match read_path_at(path, cap)? {
            None => Ok(None),
            // 64 位哈希撞名或文件张冠李戴：宁可当没缓存
            Some(e) if e.key == expect_key => Ok(Some(e)),
            Some(_) => Err(ReadError::Corrupt),
        }
    }
}

impl Inner {
    #[inline]
    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 索引里少了一条：释放它占的字节额度与条目计数。
    fn unaccount(&self, bytes: u64) {
        self.stats.sub(&self.stats.bytes, bytes);
        self.stats.sub(&self.stats.entries, 1);
    }

    /// 安排一次后台腾额度（同一次里多次请求会合并成一个任务）。
    fn schedule_trim(&self, need: u64) {
        if self.trim_queued.swap(true, Ordering::Relaxed) {
            return;
        }
        if !self.send(Job::Trim { need }) {
            self.trim_queued.store(false, Ordering::Relaxed);
        }
    }

    fn send(&self, job: Job) -> bool {
        let tx = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        match &*tx {
            Some(s) => s.send(job).is_ok(),
            None => false,
        }
    }
}

struct FileEntry {
    key: String,
    value: Vec<u8>,
    val_len: u32,
    bytes: u64,
    expires: Option<f64>,
    freq: f32,
}

/// 同步读一个条目文件并全量校验（扫描重建与冷读两条路径共用）。
/// `len_cap` 是"头 + key + value"的字节上限：长度字段一律不可信，超限直接判损坏。
fn read_path_at(path: &Path, len_cap: usize) -> Result<Option<FileEntry>, ReadError> {
    // 只读普通文件：冷层的目录树按我们的规则命名，一个符号链接/目录/junction 就不是条目。
    // 不挡的话"往缓存根里塞一个指向别处的链接"就能让网关替人读任意文件（S10 的读侧）。
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_file() => {}
        Ok(_) => return Err(ReadError::Corrupt),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ReadError::Io(e)),
    }
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if f.metadata().map(|m| m.len() as usize).unwrap_or(usize::MAX) > len_cap {
        return Err(ReadError::Corrupt);
    }
    let mut head = [0u8; HEADER_LEN];
    f.read_exact(&mut head).map_err(map_io)?;
    let h = decode_header(&head)?;
    // 只读声明长度对应的字节：文件尾部有垃圾不影响可用字节，也不放大内存占用
    let mut key = vec![0u8; h.key_len];
    let mut value = vec![0u8; h.val_len];
    f.read_exact(&mut key).map_err(map_io)?;
    f.read_exact(&mut value).map_err(map_io)?;
    if crc32(&key, &value) != h.crc {
        return Err(ReadError::Corrupt);
    }
    let key = String::from_utf8(key).map_err(|_| ReadError::Corrupt)?;
    let cost = (HEADER_LEN + key.len() + value.len()) as u64;
    Ok(Some(FileEntry {
        key,
        val_len: h.val_len as u32,
        bytes: cost,
        expires: h.expires,
        freq: h.freq,
        value,
    }))
}

struct HeaderParts {
    key_len: usize,
    val_len: usize,
    expires: Option<f64>,
    freq: f32,
    crc: u32,
}

fn decode_header(head: &[u8; HEADER_LEN]) -> Result<HeaderParts, ReadError> {
    if head[0..4] != MAGIC || head[4] != VERSION {
        return Err(ReadError::Corrupt);
    }
    // 保留位不校验：未来复用这些位时旧文件仍可读
    let key_len = u32::from_le_bytes(head[8..12].try_into().unwrap()) as usize;
    let val_len = u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize;
    let cap = 4 * DEFAULT_MAX_VALUE;
    if key_len == 0 || key_len > cap || val_len > cap {
        return Err(ReadError::Corrupt);
    }
    let has_exp = head[5] & FLAG_EXPIRES != 0;
    let bits = u64::from_le_bytes(head[16..24].try_into().unwrap());
    let expires = if has_exp {
        let t = f64::from_bits(bits);
        if !t.is_finite() {
            return Err(ReadError::Corrupt);
        }
        Some(t)
    } else {
        None
    };
    let freq = f32::from_le_bytes(head[24..28].try_into().unwrap());
    let crc = u32::from_le_bytes(head[28..32].try_into().unwrap());
    Ok(HeaderParts {
        key_len,
        val_len,
        expires,
        // freq 只参与分层排序，不参与正确性判定：脏值收敛到 0
        freq: if freq.is_finite() && freq >= 0.0 {
            freq.min(1e6)
        } else {
            0.0
        },
        crc,
    })
}

/// 32 字节头 + key + value。
pub fn encode(key: &str, value: &[u8], expires: Option<f64>, freq: f32) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + key.len() + value.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(if expires.is_some() { FLAG_EXPIRES } else { 0 });
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(&expires.unwrap_or(0.0).to_bits().to_le_bytes());
    out.extend_from_slice(&freq.max(0.0).to_le_bytes());
    out.extend_from_slice(&crc32(key.as_bytes(), value).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(value);
    out
}

/// 从完整字节串解析头部（写线程登记索引用，省一次文件读）。
fn decode_header_array(bytes: &[u8]) -> Option<HeaderParts> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let head: [u8; HEADER_LEN] = bytes[..HEADER_LEN].try_into().ok()?;
    decode_header(&head).ok()
}

/// CRC-32（IEEE 多项式，与 zlib 同）：只用于判定"条目自洽"，不是密码学校验。
fn crc32(key: &[u8], value: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, v) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *v = c;
        }
        t
    });
    let mut crc = !0u32;
    for b in key.iter().chain(value.iter()) {
        crc = table[((crc as u8) ^ b) as usize] ^ (crc >> 8);
    }
    !crc
}

fn map_io(e: std::io::Error) -> ReadError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        ReadError::Corrupt
    } else {
        ReadError::Io(e)
    }
}

enum ReadError {
    Corrupt,
    Io(std::io::Error),
}

/// temp + rename 原子替换：读者永远只会看到完整的新条目或完整的旧条目。
/// 临时文件后缀带 pid，避免异常配置下同 root 的多进程互相踩临时文件。
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        // 必须"这次创建"这个临时名，不能跟随已存在的路径：条目名是可以从外部预测的
        // （FNV-1a + 固定分层），File::create 会顺着别人预埋的硬链接写过去，
        // 于是"占住临时名"变成借用网关权限截断并重写任意文件（S10）。
        // create_new 存在即失败；撞名只会是上次崩溃留下的残骸，unlink 掉重来——
        // unlink 只删名字，绝不动别人的内容。
        let mut f = match open_exclusive(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&tmp)?;
                open_exclusive(&tmp)?
            }
            Err(e) => return Err(e),
        };
        f.write_all(bytes)?;
        f.flush()?;
        // 不做逐条 fsync：缓存层要的是吞吐。崩溃时刚排队的冷数据丢了可接受
        // （内存层本来也没了），但"要么完整要么没有"必须靠 rename 保证。
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn open_exclusive(p: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
}

/// 取走当前分数最低（最冷）的一条。后台路径专用：O(n) 扫描，只在写线程/清扫里跑。
fn pop_coldest(index: &Mutex<Index>, scorer: &Arc<dyn Scorer>) -> Option<(PathBuf, u64, bool)> {
    let mut idx = index.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_epoch();
    let pick = idx
        .slots
        .iter()
        .min_by(|(_, a), (_, b)| score_slot(scorer, a, now).total_cmp(&score_slot(scorer, b, now)))
        .map(|(k, s)| (k.clone(), s.path.clone(), s.bytes, s.read))?;
    let (key, path, bytes, read) = pick;
    idx.slots.remove(&key)?;
    Some((path, bytes, read))
}

fn score_slot(scorer: &Arc<dyn Scorer>, s: &ColdSlot, now: f64) -> f32 {
    let f = Features {
        freq: s.freq,
        age_ms: (((now - s.last_used).max(0.0) * 1000.0) as u64).min(u64::from(u32::MAX)),
        value_len: s.val_len as usize,
        ttl_left: s.expires.map(|t| (t - now).max(0.0)),
        on_disk: true,
    };
    let v = scorer.score(&f);
    if v.is_finite() {
        v
    } else {
        // 策略坏了不连累缓存：回落确定性基线
        ClockFrequency.score(&f)
    }
}

/// 为一次落盘腾出 `need` 字节：逐出最冷的条目，直到 `已落盘 + 排队中 + need <= max_disk`。
/// 跑在写线程上，所以这里的 O(n) 扫描与删文件都不占用请求路径。
fn run_trim(
    index: &Mutex<Index>,
    stats: &Arc<DiskStats>,
    cfg: &Arc<DiskConfig>,
    scorer: &Arc<dyn Scorer>,
    need: u64,
) {
    let limit = cfg.max_bytes;
    if limit == 0 {
        return;
    }
    let mut evicted = 0u64;
    loop {
        let on_disk = stats.bytes.load(Ordering::Relaxed);
        let pending = stats.pending_bytes.load(Ordering::Relaxed);
        if on_disk.saturating_add(pending).saturating_add(need) <= limit {
            break;
        }
        let Some((path, bytes, read)) = pop_coldest(index, scorer) else {
            break; // 空了：额度让给排队中的任务，剩下的由落盘判定自己拒
        };
        stats.sub(&stats.bytes, bytes);
        stats.sub(&stats.entries, 1);
        if !read {
            stats.bump(&stats.never_read);
        }
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log_debug!("磁盘冷层：逐出时删 {path:?} 失败: {e}");
            }
        }
        evicted += 1;
        if evicted >= TRIM_BATCH as u64 {
            break;
        }
    }
    stats.add(&stats.evicted, evicted);
}

/// 写线程处理一个落盘任务：temp+rename → 校验 → 登记索引。
/// `index/stats/cfg` 是强引用克隆，因此即便 `Arc<Inner>` 已释放（热重载替换、
/// 停机），队列里排队的任务仍能写完，不会把已经答应的冷数据丢掉。
fn apply_write(
    index: &Mutex<Index>,
    stats: &Arc<DiskStats>,
    cfg: &Arc<DiskConfig>,
    key: String,
    seq: u64,
    gen: u64,
    epoch: &AtomicU64,
    bytes: Vec<u8>,
) {
    stats.sub(&stats.pending_bytes, bytes.len() as u64);
    stats.sub(&stats.pending_jobs, 1);
    let cost = bytes.len() as u64;
    // 代已推进（flush_all 过）：这条快照属于被清掉的那一代，不许复活成冷条目
    if epoch.load(Ordering::Relaxed) != gen {
        return;
    }
    // 墓碑/更新拦截：这条快照比最近一次删除更旧、或索引里已经有更新版本 → 丢弃，
    // 否则冷层会复活一个已被新值取代的旧条目
    let stale = {
        let idx = index.lock().unwrap_or_else(|e| e.into_inner());
        idx.tomb.get(&key).is_some_and(|t| t.seq >= seq)
            || idx.slots.get(&key).is_some_and(|s| s.seq > seq)
    };
    if stale {
        return;
    }
    let Some(h) = decode_header_array(&bytes) else {
        log_error!("磁盘冷层：待写条目 {key} 头部自相矛盾，已丢弃");
        return;
    };
    let path = entry_path(&cfg.root, &cfg.levels, &key);
    if let Err(e) = atomic_write(&path, &bytes) {
        log_error!("磁盘冷层：写 {path:?} 失败: {e}");
        return;
    }
    let mut idx = index.lock().unwrap_or_else(|e| e.into_inner());
    if idx.tomb.get(&key).is_some_and(|t| t.seq >= seq) || epoch.load(Ordering::Relaxed) != gen {
        // 写文件的窗口里该 key 被删了、或整区被 flush 了：删掉刚写的文件，不登记索引
        drop(idx);
        let _ = std::fs::remove_file(&path);
        return;
    }
    let prev = idx.slots.insert(
        key,
        ColdSlot {
            path,
            val_len: h.val_len as u32,
            bytes: cost,
            expires: h.expires,
            freq: h.freq,
            last_used: now_epoch(),
            seq,
            read: false,
        },
    );
    // 计价：同 key 覆盖要先退掉旧条目的额度，否则 bytes 会随覆盖次数虚高
    if let Some(prev) = prev {
        stats.sub(&stats.bytes, prev.bytes);
    } else {
        stats.add(&stats.entries, 1);
    }
    stats.add(&stats.bytes, cost);
}

/// 进程内所有启用磁盘层的区，按名字登记；热重载整表替换。
///
/// 放全局而不挂 AppState：`SharedDicts` 由 `LuaEngine` 持有，而维护任务与 `/metrics`
/// 渲染两处都要访问，且热重载会重建 `LuaEngine`——全局快照是唯一不会过期的挂点。
static REGISTRY: OnceLock<Mutex<Vec<(String, DiskStore)>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<(String, DiskStore)>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// 测试专用互斥：登记是进程级全局且整表替换，任何"注册了再断言快照"的用例
/// 都会互相把对方的区挤掉（`shared_dict::parse_all` 也会登记）。跨模块的这类
/// 用例先取这把锁。
#[cfg(test)]
pub(crate) static REGISTRY_TEST_GUARD: Mutex<()> = Mutex::new(());

/// 用新的区集合替换登记，并排空被替换掉的旧 store 的落盘队列。
///
/// 热重载的正确调用顺序是：先 [`flush_all_pending`]（旧 store 承诺的落盘先落盘），
/// 再 `open` 新 store（此时扫描能看到完整目录），最后调用本函数替换登记。
pub fn register_zones(zones: Vec<(String, DiskStore)>) {
    let old = {
        let mut r = registry().lock().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *r, zones)
    };
    for (_, store) in &old {
        store.flush_pending();
    }
}

/// 全部启用磁盘层的区的 (名字, 句柄) 快照。
pub fn snapshot() -> Vec<(String, DiskStore)> {
    registry().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// 后台维护入口：清扫每个区，返回本轮回收条数。
pub fn sweep_all() -> usize {
    snapshot()
        .into_iter()
        .chain(proxy_snapshot())
        .map(|(_, store)| store.sweep())
        .sum()
}

/// 停机前把排队中的落盘写完（有界等待）。
pub fn flush_all_pending() {
    for (_, store) in snapshot().into_iter().chain(proxy_snapshot()) {
        store.flush_pending();
    }
}

pub fn enabled() -> bool {
    !registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty()
}

/// `proxy_cache` 的冷层登记表，与 DICT 那张分开。
///
/// 分开的理由只有一条：两家的 `/metrics` 家族不同名
/// （`onrouter_dict_disk_*` / `onrouter_proxy_cache_disk_*`），合成一张表就会把响应缓存
/// 的落盘账记到共享字典头上。维护任务与停机排空则同时覆盖两张表。
static PROXY_REGISTRY: OnceLock<Mutex<Vec<(String, DiskStore)>>> = OnceLock::new();

fn proxy_registry() -> &'static Mutex<Vec<(String, DiskStore)>> {
    PROXY_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// 替换 `proxy_cache` 的冷层登记，并排空被替换掉的旧 store（热重载与启动同一条路径）。
pub fn register_proxy_zones(zones: Vec<(String, DiskStore)>) {
    let old = {
        let mut r = proxy_registry().lock().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *r, zones)
    };
    for (_, store) in &old {
        store.flush_pending();
    }
}

pub fn proxy_snapshot() -> Vec<(String, DiskStore)> {
    proxy_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn proxy_enabled() -> bool {
    !proxy_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("onrouter-disk-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn cfg(dir: PathBuf) -> DiskConfig {
        DiskConfig {
            root: dir,
            ..Default::default()
        }
    }

    fn open(dir: PathBuf) -> DiskStore {
        DiskStore::open(cfg(dir), None).unwrap()
    }

    /// 落盘并等它真的可见（单测里的同步点）
    fn spill_sync(s: &DiskStore, key: &str, val: impl AsRef<[u8]>, freq: f32) -> bool {
        let ok = s.spill(key, val.as_ref(), None, freq);
        s.flush_pending();
        ok
    }

    /// S10：条目名与临时名都能从外部算出来（FNV-1a + 固定分层 + pid 后缀是进程内公开的）。
    /// 所以"提前在那个名字上建一个硬链接"绝不能变成借网关的权限改写链接指向的文件：
    /// 临时名必须这次创建，撞名只允许 unlink 重建（unlink 不动内容）。
    #[test]
    fn atomic_write_never_writes_through_a_pre_existing_temp_name() {
        let dir = tmpdir("tempclash");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("entry.bin");
        let tmp = dir.join(format!("entry.{}.tmp", std::process::id()));
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"IMPORTANT-NOT-CACHE-DATA").unwrap();
        if std::fs::hard_link(&victim, &tmp).is_err() {
            // 这台机器（或这个卷）不支持硬链接：攻击前提造不出来，只能不测
            return;
        }
        atomic_write(&target, b"a-cache-entry").unwrap();
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"IMPORTANT-NOT-CACHE-DATA",
            "别人文件的内容一格都不许被我们改写"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"a-cache-entry",
            "条目照常原子落地"
        );
        assert!(!tmp.exists(), "用完的临时名不该留下");
    }

    /// 扫描重建不许跟着链接走出冷层 root（跟着目录链接跑，还会顺手删掉别人的 .tmp）。
    #[test]
    fn scan_does_not_follow_a_link_out_of_the_cache_root() {
        let dir = tmpdir("linkwalk");
        let outside = tmpdir("linkwalk-outside");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.tmp.tmp"), b"not-yours").unwrap();
        std::fs::write(outside.join("keep.bin"), b"not-yours-either").unwrap();
        let linked = {
            #[cfg(windows)]
            {
                std::os::windows::fs::symlink_dir(&outside, dir.join("link")).is_ok()
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&outside, dir.join("link")).is_ok()
            }
            #[cfg(not(any(windows, unix)))]
            {
                false
            }
        };
        if !linked {
            // 建不了目录链接（Windows 无符号链接权限是常态）：攻击前提造不出来，只能不测
            return;
        }
        let store = open(dir.clone());
        let n = store.scan_rebuild().unwrap_or_default();
        assert_eq!(n, 0, "链接外面的东西不是本区的条目，一条都不该收");
        assert!(
            outside.join("keep.tmp.tmp").exists(),
            "外面的 .tmp 不该被当成我们的遗留残骸删掉"
        );
    }

    fn walk_bins(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for de in rd.flatten() {
                    let p = de.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.extension().and_then(|e| e.to_str()) == Some("bin") {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    /// 绕过落盘路径直接往索引/文件系统塞一条，用于测读路径与清扫
    fn plant(s: &DiskStore, key: &str, value: &[u8], expires: Option<f64>, freq: f32) -> PathBuf {
        let path = entry_path(&s.config().root, &s.config().levels, key);
        atomic_write(&path, &encode(key, value, expires, freq)).unwrap();
        let bytes = (HEADER_LEN + key.len() + value.len()) as u64;
        s.lock_mut().slots.insert(
            key.to_string(),
            ColdSlot {
                path: path.clone(),
                val_len: value.len() as u32,
                bytes,
                expires,
                freq,
                last_used: now_epoch(),
                seq: 0,
                read: false,
            },
        );
        s.inner.stats.bytes.fetch_add(bytes, Ordering::Relaxed);
        s.inner.stats.entries.fetch_add(1, Ordering::Relaxed);
        path
    }

    #[test]
    fn roundtrip_preserves_value_ttl_and_freq() {
        let dir = tmpdir("roundtrip");
        let s = open(dir.clone());
        assert!(spill_sync(&s, "user:42", "hello-disk", 5.0));
        assert!(s.has("user:42"));
        let v = s.read("user:42", false).expect("冷读应命中");
        assert_eq!(v.value, b"hello-disk");
        assert_eq!(v.freq, 5.0, "热度历史要随条目一起落盘");
        assert_eq!(v.expires, None);
        assert!(!v.expired);
        assert_eq!(s.entries(), 1);
        // 计费口径 = 文件本身的大小（头部 + key + value）
        assert_eq!(
            s.bytes_used(),
            encode("user:42", b"hello-disk", None, 5.0).len() as u64
        );
        s.forget("user:42");
        s.flush_pending();
        assert!(!s.has("user:42"));
        assert!(
            walk_bins(&dir).is_empty(),
            "forget 必须真删文件，不能只删索引"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_cold_entry_follows_get_vs_get_stale_split() {
        let dir = tmpdir("expired");
        let s = open(dir.clone());
        // 过期条目不允许落盘（admit 与 spill 两道都拒）
        assert!(!s.admit(9.0, 4, Some(now_epoch() - 1.0)));
        assert!(!s.spill("k", b"v", Some(now_epoch() - 1.0), 9.0));
        // 直接塞一条已过期的，验证读路径语义与内存层一致
        let past = now_epoch() - 5.0;
        plant(&s, "k", b"v", Some(past), 9.0);
        assert_eq!(s.ttl("k"), Some(0.0));
        assert!(!s.has("k"), "过期条目不算存在");
        assert!(s.read("k", false).is_none(), "get 语义不可读过期的冷条目");
        let stale = s.read("k", true).expect("get_stale 语义应读到");
        assert!(stale.expired);
        assert_eq!(stale.value, b"v");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_is_derived_only_from_hash_so_keys_cannot_escape() {
        let root = PathBuf::from("base");
        for key in [
            "../../../../etc/passwd",
            "..\\..\\windows\\system32",
            "\0\0\0",
            "🚀/../x",
            "",
            "%2e%2e%2f",
        ] {
            let p = entry_path(&root, &[1, 2], key);
            let rel = p
                .strip_prefix(&root)
                .unwrap_or_else(|_| panic!("key {key:?} 越界: {p:?}"));
            let comps: Vec<_> = rel.components().collect();
            let (dirs, file) = comps.split_at(comps.len() - 1);
            for c in dirs {
                let std::path::Component::Normal(s) = c else {
                    panic!("key {key:?} 生成了非普通分量: {rel:?}");
                };
                assert!(
                    s.to_string_lossy().chars().all(|ch| ch.is_ascii_hexdigit()),
                    "key {key:?} 的目录分量 {s:?} 含非十六进制字符"
                );
            }
            // 文件名固定 16 位十六进制 + .bin：key 的任何字节都不会进路径
            let std::path::Component::Normal(name) = file[0] else {
                panic!("key {key:?} 的文件名不是普通分量: {rel:?}");
            };
            let name = name.to_string_lossy().to_string();
            let Some((hex, ext)) = name.split_once('.') else {
                panic!("文件名 {name} 没有扩展名");
            };
            assert_eq!(ext, "bin", "文件名 {name} 扩展名不是 bin");
            assert_eq!(hex.len(), 16, "文件名 {name} 的哈希段长度不是 16");
            assert!(
                hex.chars().all(|ch| ch.is_ascii_hexdigit()),
                "文件名 {name} 含非十六进制字符"
            );
        }
        // 同一个 key 的路径必须跨进程稳定（这是"扫目录重建"能工作的前提）
        assert_eq!(
            entry_path(&root, &[1, 2], "session:abc"),
            entry_path(&root, &[1, 2], "session:abc")
        );
    }

    #[test]
    fn corrupt_and_truncated_files_are_dropped_not_panicked() {
        let dir = tmpdir("corrupt");
        let s = open(dir.clone());
        let levels = s.config().levels.clone();
        let put = |name: &str, bytes: Vec<u8>| {
            let p = entry_path(&dir, &levels, name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, bytes).unwrap();
            p
        };
        put("good", encode("good", b"payload", None, 4.0));
        let mut trunc = encode("trunc", b"payload", None, 4.0);
        trunc.truncate(trunc.len() - 4);
        put("trunc", trunc);
        let mut flip = encode("flip", b"payload", None, 4.0);
        let n = flip.len() - 1;
        flip[n] ^= 0xff;
        put("flip", flip);
        put("junk", b"not-an-entry-at-all-but-long-enough".to_vec());
        let mut liar = encode("liar", b"x", None, 1.0);
        liar[12..16].copy_from_slice(&(400_000u32).to_le_bytes());
        put("liar", liar);
        // 文件在但内容属于另一个 key（哈希撞名的极端情形）
        put("mismatch", encode("other-key", b"payload", None, 4.0));

        let fresh = DiskStore::open(cfg(dir.clone()), None).unwrap();
        assert_eq!(
            fresh.stats().warm_recovered.load(Ordering::Relaxed),
            1,
            "只应恢复 good"
        );
        assert!(fresh.has("good"));
        for k in ["trunc", "flip", "junk", "liar", "mismatch"] {
            assert!(!fresh.has(k), "{k} 不应被当成有效冷条目");
            assert!(
                !entry_path(&dir, &levels, k).exists(),
                "{k} 的坏文件应被删除"
            );
        }
        assert!(fresh.stats().corrupt.load(Ordering::Relaxed) >= 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rebuilds_index_from_directory_scan() {
        let dir = tmpdir("restart");
        {
            let s = open(dir.clone());
            for i in 0..25 {
                spill_sync(&s, &format!("k{i}"), &format!("v{i}"), 7.0);
            }
            assert_eq!(s.entries(), 25);
        }
        // 模拟重启：同目录再开一个 store，不依赖任何索引文件
        let s2 = DiskStore::open(cfg(dir.clone()), None).unwrap();
        assert_eq!(s2.entries(), 25);
        assert_eq!(s2.stats().warm_recovered.load(Ordering::Relaxed), 25);
        let v = s2.read("k7", false).expect("重启后应能读到冷数据");
        assert_eq!(v.value, b"v7");
        assert_eq!(v.freq, 7.0);
        // 遗留的 .tmp 会被扫掉
        let stray = entry_path(&dir, &s2.config().levels, "k1").with_extension("12345.tmp");
        std::fs::write(&stray, b"partial").unwrap();
        let s3 = DiskStore::open(cfg(dir.clone()), None).unwrap();
        assert_eq!(s3.entries(), 25);
        assert!(!stray.exists(), "上次中断的临时文件不该留下");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_disk_is_enforced_by_the_background_sweep() {
        let dir = tmpdir("maxdisk");
        let mut c = cfg(dir.clone());
        // 一条 = 32 + 3 + 40 = 75 字节，"third" 的 key 长一点是 77；上限 160 放得下两条、装不下第三条
        c.max_bytes = 160;
        c.spill_after = 0.0;
        let s = DiskStore::open(c, None).unwrap();
        spill_sync(&s, "old", &"a".repeat(40), 0.5);
        spill_sync(&s, "new", &"b".repeat(40), 9.0);
        assert_eq!(s.entries(), 2);
        // 第三条装不下：落盘路径只做判定，直接拒（不在这里逐出），但会派一个后台腾额度任务
        assert!(
            !s.spill("third", "c".repeat(40).as_bytes(), None, 9.0),
            "满仓时不该在请求路径腾地方"
        );
        assert_eq!(s.stats().spill_skipped.load(Ordering::Relaxed) > 0, true);
        s.flush_pending();
        assert!(!s.has("old"), "后台 Trim 应已逐出分数最低的条目");
        assert!(s.has("new"), "后台 Trim 只逐出最冷的，高频条目要留下");
        assert!(s.stats().evicted.load(Ordering::Relaxed) > 0);
        // 清扫按分数逐出最冷的，然后第三条才落得进去
        s.sweep();
        assert!(s.bytes_used() <= s.config().max_bytes);
        assert!(s.spill("third", "c".repeat(40).as_bytes(), None, 9.0));
        s.flush_pending();
        assert!(s.has("new"), "高频次条目应留下");
        assert!(s.has("third"));
        assert!(!s.has("old"), "最冷的该先走");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tombstone_blocks_a_late_spill_of_the_previous_value() {
        let dir = tmpdir("tomb");
        let s = open(dir.clone());
        // 旧值已入队但还没落盘（模拟"淘汰受害者正在排队"）
        assert!(s.spill("k", b"OLD-VALUE", None, 5.0));
        // 随后新值覆盖：内存路径会先 forget 冷层副本 → 立墓碑
        s.forget("k");
        s.flush_pending();
        assert!(!s.has("k"), "迟到的旧落盘必须被墓碑拦截，否则旧值会复活");
        assert_eq!(s.read("k", false).map(|v| v.value), None);
        assert!(walk_bins(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn purge_drops_spills_queued_before_the_flush() {
        let dir = tmpdir("epoch");
        let s = open(dir.clone());
        // 排队中的落盘（模拟"淘汰受害者正在等写线程"）
        assert!(s.spill("a", b"A-VALUE", None, 5.0));
        // flush_all 落到冷层：索引被摘空，但 "a" 从没进过索引，墓碑无从登记
        assert_eq!(s.purge(), 0);
        s.flush_pending();
        assert!(
            !s.has("a"),
            "flush_all 之后迟到的落盘不许把数据复活成冷条目"
        );
        assert_eq!(s.read("a", false).map(|v| v.value), None);
        assert!(
            walk_bins(&dir).is_empty(),
            "被 flush 掉的那一代不许留下文件"
        );
        assert_eq!(s.entries(), 0, "扫目录重建也读不到它（重启即消失）");
        // 新一代照常落盘
        spill_sync(&s, "b", b"B-VALUE", 5.0);
        assert!(s.has("b"), "flush 只作废它之前的那批排队任务");
        assert_eq!(
            s.read("b", false).map(|v| v.value),
            Some(b"B-VALUE".to_vec())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_reclaims_expired_and_zeroes_the_ledger() {
        let dir = tmpdir("sweep");
        let s = open(dir.clone());
        let path = plant(&s, "dying", b"x", Some(now_epoch() + 0.02), 4.0);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(s.sweep(), 1);
        assert_eq!(s.stats().expired_removed.load(Ordering::Relaxed), 1);
        s.flush_pending();
        assert!(!path.exists(), "清扫要真删文件");
        assert_eq!(s.bytes_used(), 0, "账目要归零");
        assert_eq!(s.entries(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inactive_reclaims_idle_entries() {
        let dir = tmpdir("inactive");
        let mut c = cfg(dir.clone());
        c.inactive = Duration::from_millis(20);
        c.spill_after = 0.0;
        let s = DiskStore::open(c, None).unwrap();
        spill_sync(&s, "idle", b"v", 4.0);
        assert!(s.has("idle"));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(s.sweep(), 1);
        assert!(!s.has("idle"));
        // inactive=0 时永不按活跃度回收
        let mut c2 = cfg(tmpdir("inactive-off"));
        c2.spill_after = 0.0;
        let s2 = DiskStore::open(c2, None).unwrap();
        spill_sync(&s2, "keep", b"v", 4.0);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(s2.sweep(), 0, "没配 inactive 不该回收未过期条目");
        assert!(s2.has("keep"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(s2.config().root.clone());
    }

    #[test]
    fn oversized_values_are_never_spilled() {
        let dir = tmpdir("oversize");
        let mut c = cfg(dir.clone());
        c.max_value = 16;
        c.spill_after = 0.0;
        let s = DiskStore::open(c, None).unwrap();
        assert!(!s.admit(9.0, 17, None), "超过 max_value 的条目不该落盘");
        assert!(!s.spill("big", &vec![b'x'; 17], None, 9.0));
        s.flush_pending();
        assert_eq!(s.entries(), 0);
        assert!(s.spill("small", b"12345678", None, 9.0));
        s.flush_pending();
        assert!(s.has("small"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn levels_spec_parses_like_nginx() {
        assert_eq!(parse_levels("1"), Some(vec![1]));
        assert_eq!(parse_levels("1:2"), Some(vec![1, 2]));
        assert_eq!(parse_levels("1:1:1"), Some(vec![1, 1, 1]));
        assert_eq!(parse_levels("1:2:3:1"), None, "最多 3 级");
        assert_eq!(parse_levels("0"), None);
        assert_eq!(parse_levels("4"), None);
        assert_eq!(parse_levels("6:6:6"), None, "十六进制位要用超了");
        assert_eq!(parse_levels("x"), None);
        assert_eq!(parse_levels(""), None);
    }

    #[test]
    fn concurrent_spill_read_delete_keep_the_ledger_consistent() {
        let dir = tmpdir("concurrent");
        let mut c = cfg(dir.clone());
        c.max_bytes = u64::MAX / 4;
        c.spill_after = 0.0;
        let s = DiskStore::open(c, None).unwrap();
        let mut handles = Vec::new();
        for t in 0..8 {
            let s = s.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..60 {
                    let k = format!("t{t}k{i}");
                    s.spill(&k, k.as_bytes(), None, 3.0);
                    let _ = s.read(&k, false);
                    if i % 5 == 0 {
                        s.forget(&k);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        s.flush_pending();
        s.sweep(); // 清扫会把账目重算成以索引为准
        let idx_bytes: u64 = s.lock().slots.values().map(|x| x.bytes).sum();
        assert_eq!(
            s.bytes_used(),
            idx_bytes,
            "并发读写删之后账目必须与索引一致"
        );
        assert_eq!(
            s.stats().pending_jobs.load(Ordering::Relaxed),
            0,
            "排空后不该有残留计价"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scorer_returning_nan_falls_back_to_the_deterministic_baseline() {
        #[derive(Debug)]
        struct Broken;
        impl Scorer for Broken {
            fn score(&self, _f: &Features) -> f32 {
                f32::NAN
            }
        }
        let dir = tmpdir("scorer");
        let mut c = cfg(dir.clone());
        c.spill_after = 0.0;
        let s = DiskStore::open(c, Some(Arc::new(Broken))).unwrap();
        let f = Features {
            freq: 3.0,
            age_ms: 1000,
            value_len: 8,
            ttl_left: None,
            on_disk: false,
        };
        assert!(s.score(&f).is_finite(), "坏策略必须被兜底成有限值");
        assert_eq!(s.score(&f), ClockFrequency.score(&f), "兜底就是基线分数");
        assert!(s.spill("a", b"1", None, 1.0));
        s.flush_pending();
        assert!(s.has("a"), "策略坏了也要照常落盘");
        // 冷层逐出排序同样走兜底，不应 panic
        s.trim_to(0);
        assert_eq!(s.entries(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_all_and_registry_snapshot_survive_hot_replace() {
        let _g = REGISTRY_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("registry");
        let s = open(dir.clone());
        spill_sync(&s, "zone-key", b"v", 9.0);
        register_zones(vec![("zone".to_string(), s.clone())]);
        assert!(enabled());
        // 只认自己的区：注册表是进程级全局，别的用例可能同时登记了区，
        // sweep_all/flush_all_pending 会一并处理它们，所以不能断言快照总数。
        assert!(
            snapshot()
                .iter()
                .any(|(n, st)| n == "zone" && st.config().root == dir),
            "登记后快照里必须有本区"
        );
        assert_eq!(sweep_all(), 0, "健康条目不该被清扫掉");
        assert!(s.has("zone-key"), "清扫之后仍要能按 key 定位到条目");
        flush_all_pending();
        // 替换成空集合时旧 store 会先排空落盘队列，冷数据不丢
        register_zones(Vec::new());
        assert!(!snapshot().iter().any(|(n, _)| n == "zone"));
        let s2 = DiskStore::open(cfg(dir.clone()), None).unwrap();
        assert!(s2.has("zone-key"), "替换登记不该丢已承诺的落盘");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
