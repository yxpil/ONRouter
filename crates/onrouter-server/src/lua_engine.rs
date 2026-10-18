//! Lua 引擎：OpenResty 的 LuaJIT + ngx.* 在 Rust 侧的对应物。
//!
//! - VM：mlua (Lua 5.4)，按 CPU 核心组建 VM 池（每核心一个，对标 OpenResty 每 worker 一个 VM）。
//!   每个 VM 由一个专属调度器任务持有锁，以「同步 resume 一段、段间释放锁」的协程方式并发
//!   多条在途请求（对标 OpenResty 单 worker 内的 C10K）：请求脚本在 ngx.sleep 与 cosocket op 处
//!   coroutine.yield 让出，让出期间同 VM 的其它请求继续推进，锁在步与步之间释放以便
//!   ngx.timer 回调与 tokio 睡眠定时器取得进展。
//! - 非阻塞 I/O：ngx.sleep 与 ngx.socket.tcp() cosocket（connect/send/receive）都走同一套
//!   「协程让出 + 调度器带结果 resume」机制——op 在 tokio 任务里跑，不持 VM 锁，完成后把
//!   唤醒值 (op_id, [结果…]) 投回调度器，coroutine.yield 因此拿到返回值，实现单 VM 上的真并发。
//! - 阶段：rewrite_by_lua / access_by_lua / content_by_lua / header_filter_by_lua /
//!   body_filter_by_lua / log_by_lua（LOG 阶段在响应成形后于 ctx 副本上运行，输出不回灌响应）
//! - API：ngx.say/print/status/exit/header/req.*/ctx/sleep/socket.tcp/time/log/
//!   shared.DICT/redirect/exec/re.*/encode_base64/decode_base64/
//!   escape_uri/unescape_uri/decode_args/encode_args/config/OK/ERROR/ERR/WARN/INFO…/HTTP_*
//!   —— 语义对齐 ngx_lua
//! - 请求状态放在 `Arc<Mutex<RequestCtx>>`，脚本通过 userdata 句柄读写；每次同步 resume
//!   前按协程挂回各自的 __ctx / ngx.ctx（每请求一张表，跨让出保持），阶段结束后由 Rust 侧
//!   继续接管同一个 ctx

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use mlua::prelude::*;
use mlua::{AnyUserData, Function, RegistryKey, Thread, ThreadStatus, Variadic};
use std::pin::Pin;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio::sync::{mpsc, oneshot};

use onrouter_config::Config;

use crate::engine::RequestCtx;
use crate::shared_dict::SharedDicts;
use crate::{resolve_path, AppError};

/// 进程级退出标志：收到 SIGTERM/SIGINT（或 Windows Ctrl-C）后置位，
/// 供 `ngx.worker.exiting()` 在脚本里感知优雅停机。
static WORKER_EXITING: AtomicBool = AtomicBool::new(false);

/// 信号处理器调用：标记 worker 进入退出流程
pub fn mark_worker_exiting() {
    WORKER_EXITING.store(true, Ordering::SeqCst);
}

/// 进程是否正在退出
pub fn worker_exiting() -> bool {
    WORKER_EXITING.load(Ordering::SeqCst)
}

/// 请求句柄 userdata：Lua 里所有 ngx.* 都通过它操作当前请求
#[derive(Clone)]
struct CtxHandle(Arc<Mutex<RequestCtx>>);


impl LuaUserData for CtxHandle {}

/// ngx.req.socket() 返回的请求体读取器。请求体在进入内容阶段前已整体缓冲，
/// 这里是对内存缓冲的顺序读取；游标由 socket 对象与 receiveuntil 迭代器共享。
struct ReqSocket {
    cursor: Arc<Mutex<ReqSocketCursor>>,
}

#[derive(Default)]
struct ReqSocketCursor {
    pos: usize,
    closed: bool,
}

/// 从当前协程的 registry 里取请求 ctx（与 install_api 内的 get_ctx 同源）。
fn current_ctx(lua: &Lua) -> LuaResult<Arc<Mutex<RequestCtx>>> {
    let ud: AnyUserData = lua.named_registry_value("__ctx")?;
    let h = ud.borrow::<CtxHandle>()?;
    Ok(Arc::clone(&h.0))
}

/// ngx.ssl.parse_pem_cert 的返回值：一条或多条 DER 证书（链）
struct SslCertChain(Vec<Vec<u8>>);

impl LuaUserData for SslCertChain {}

/// ngx.ssl.parse_pem_priv_key 的返回值：DER 私钥（格式由 set_cert_and_key 时探测）
struct SslPrivKey(Vec<u8>);

impl LuaUserData for SslPrivKey {}

fn ssl_cert_from_value(v: &LuaValue) -> Result<Vec<Vec<u8>>, String> {
    match v {
        LuaValue::String(s) => Ok(vec![s.as_bytes().to_vec()]),
        LuaValue::UserData(u) => u
            .borrow::<SslCertChain>()
            .map(|c| c.0.clone())
            .map_err(|e| format!("证书参数不是 parse_pem_cert() 的返回值: {e}")),
        _ => Err("证书必须是 DER 字符串或 parse_pem_cert() 的返回值".to_string()),
    }
}

fn ssl_key_from_value(v: &LuaValue) -> Result<Vec<u8>, String> {
    match v {
        LuaValue::String(s) => Ok(s.as_bytes().to_vec()),
        LuaValue::UserData(u) => u
            .borrow::<SslPrivKey>()
            .map(|k| k.0.clone())
            .map_err(|e| format!("私钥参数不是 parse_pem_priv_key() 的返回值: {e}")),
        _ => Err("私钥必须是 DER 字符串或 parse_pem_priv_key() 的返回值".to_string()),
    }
}

impl LuaUserData for ReqSocket {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // receive([size]) -> data | nil, err。读到体尾返回 nil, "closed"（对齐 OpenResty）。
        methods.add_method("receive", |lua, this, size: Option<usize>| {
            let shared = current_ctx(lua)?;
            let ctx = shared.lock().unwrap();
            let mut cur = this.cursor.lock().unwrap();
            if cur.closed || cur.pos >= ctx.req_body.len() {
                return Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("closed")?),
                ));
            }
            let remaining = ctx.req_body.len() - cur.pos;
            let n = size.unwrap_or(remaining).min(remaining);
            let data = lua.create_string(&ctx.req_body[cur.pos..cur.pos + n])?;
            cur.pos += n;
            Ok((LuaValue::String(data), LuaValue::Nil))
        });

        // receiveuntil(delim [, opts]) -> iterator；opts.inclusive=false 时丢弃分隔符。
        // 分隔符在体尾之前找不到时消费剩余数据并返回 nil, "closed"。
        methods.add_method(
            "receiveuntil",
            |lua, this, (delim, opts): (LuaString, Option<LuaTable>)| {
                let delim = delim.as_bytes().to_vec();
                if delim.is_empty() {
                    return Err(mlua::Error::external(
                        "receiveuntil: delimiter must not be empty",
                    ));
                }
                let inclusive = opts
                    .as_ref()
                    .and_then(|t| t.get::<Option<bool>>("inclusive").ok().flatten())
                    .unwrap_or(true);
                let cursor = Arc::clone(&this.cursor);
                let iter = lua.create_function(move |lua, ()| {
                    let shared = current_ctx(lua)?;
                    let ctx = shared.lock().unwrap();
                    let mut cur = cursor.lock().unwrap();
                    if cur.closed || cur.pos >= ctx.req_body.len() {
                        return Ok((
                            LuaValue::Nil,
                            LuaValue::String(lua.create_string("closed")?),
                        ));
                    }
                    let rest = &ctx.req_body[cur.pos..];
                    match find_subslice(rest, &delim) {
                        Some(idx) => {
                            let end = cur.pos + idx + delim.len();
                            let data_end = if inclusive { end } else { cur.pos + idx };
                            let chunk = lua.create_string(&ctx.req_body[cur.pos..data_end])?;
                            cur.pos = end;
                            Ok((LuaValue::String(chunk), LuaValue::Nil))
                        }
                        None => {
                            cur.pos = ctx.req_body.len();
                            Ok((
                                LuaValue::Nil,
                                LuaValue::String(lua.create_string("closed")?),
                            ))
                        }
                    }
                })?;
                Ok(iter)
            },
        );

        // 请求体已在内存，超时设置无实际作用；保留接口以兼容现有脚本。
        methods.add_method("settimeout", |_, _, _ms: u64| Ok(()));
        methods.add_method(
            "settimeouts",
            |_, _, (_c, _s, _r): (Option<u64>, Option<u64>, Option<u64>)| Ok(()),
        );
        methods.add_method("close", |_, this, ()| {
            this.cursor.lock().unwrap().closed = true;
            Ok(1)
        });
        methods.add_method("getreusedtimes", |_, _, ()| Ok(0i64));
    }
}

/// 阶段脚本来源：内联代码（content_by_lua "code"）或文件（content_by_lua_file "path"）
#[derive(Debug, Clone)]
pub enum LuaSource {
    Inline(Arc<str>),
    File(PathBuf),
}

/// Lua 脚本文件全局缓存：内容只在首次请求时读盘，此后请求路径**零 syscall**；
/// 失效完全交给后台定期自检（main.rs 的 reload 任务调用 recheck_cached_files）。
struct CachedLua {
    content: Arc<str>,
    mtime: std::time::SystemTime,
}

/// 后台自检的节拍：每 1 秒 stat 一遍已缓存的 .lua，mtime 变了才重读并换掉内容。
/// 与主配置自己的 `reload <interval>;` 轮询解耦：.lua 自检常开，编辑后最多 1 秒生效。
pub const LUA_FILE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

static FILE_CACHE: std::sync::OnceLock<std::sync::RwLock<HashMap<PathBuf, CachedLua>>> =
    std::sync::OnceLock::new();

// ngx.re 的进程级正则缓存（对齐 ngx.re 的 o/预编译缓存语义）：opt() 把编译结果存入，
// 返回一个 __orr_re 句柄；match 家族可用句柄复用，避免热路径反复编译。
static RE_CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<regex::Regex>>> =
    std::sync::OnceLock::new();

fn regex_cache() -> &'static std::sync::Mutex<Vec<regex::Regex>> {
    RE_CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}
fn regex_from_cache(i: usize) -> LuaResult<regex::Regex> {
    regex_cache()
        .lock()
        .unwrap()
        .get(i)
        .cloned()
        .ok_or_else(|| mlua::Error::external("ngx.re: 无效的预编译句柄"))
}
fn regex_to_cache(r: regex::Regex) -> usize {
    let mut c = regex_cache().lock().unwrap();
    c.push(r);
    c.len() - 1
}

/// 不带 opt() 句柄的 ngx.re 调用的透明编译缓存：pattern -> 按 i/s/m 标志位分槽。
/// OpenResty 的 `o` 是显式缓存；这里对反复出现的同一模式也缓存（限量、溢出整表清空），
/// 避免热路径每个请求重新编译正则。命中路径只做一次 HashMap 借用查询，不再分配 pattern。
static RE_COMPILED: std::sync::OnceLock<
    std::sync::Mutex<HashMap<String, [Option<regex::Regex>; 8]>>,
> = std::sync::OnceLock::new();
const RE_COMPILED_MAX: usize = 256;

fn re_compiled() -> &'static std::sync::Mutex<HashMap<String, [Option<regex::Regex>; 8]>> {
    RE_COMPILED.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn re_flag_bits(flags: Option<&str>) -> usize {
    let mut bits = 0;
    if let Some(f) = flags {
        if f.contains('i') {
            bits |= 1;
        }
        if f.contains('s') {
            bits |= 2;
        }
        if f.contains('m') {
            bits |= 4;
        }
    }
    bits
}

fn build_regex_uncached(pattern: &str, flags: Option<&str>) -> LuaResult<regex::Regex> {
    let mut builder = regex::RegexBuilder::new(pattern);
    if let Some(f) = flags {
        // 对齐 PCRE/OpenResty 常用标志：i 忽略大小写、s 单行(. 匹配换行)、m 多行(^$ 逐行)
        if f.contains('i') {
            builder.case_insensitive(true);
        }
        if f.contains('s') {
            builder.dot_matches_new_line(true);
        }
        if f.contains('m') {
            builder.multi_line(true);
        }
    }
    builder.build().map_err(mlua::Error::external)
}

/// ngx.re 的编译入口：同一 (pattern, i/s/m) 只编译一次。
fn build_regex_cached(pattern: &str, flags: Option<&str>) -> LuaResult<regex::Regex> {
    let bits = re_flag_bits(flags);
    {
        let cache = re_compiled().lock().unwrap();
        if let Some(slots) = cache.get(pattern) {
            if let Some(re) = &slots[bits] {
                return Ok(re.clone());
            }
        }
    }
    let built = build_regex_uncached(pattern, flags)?;
    let mut cache = re_compiled().lock().unwrap();
    if cache.len() >= RE_COMPILED_MAX && !cache.contains_key(pattern) {
        cache.clear();
    }
    let slots = cache
        .entry(pattern.to_string())
        .or_insert_with(|| std::array::from_fn(|_| None));
    slots[bits] = Some(built.clone());
    Ok(built)
}

/// 请求路径取脚本内容：命中即返回，零 syscall；未命中才读盘一次并登记，
/// 之后文件的变更全部由后台 `recheck_cached_files` 发现。
fn load_file_cached(p: &PathBuf) -> Result<Arc<str>, AppError> {
    let cache = FILE_CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()));
    if let Some(cached) = cache.read().unwrap().get(p) {
        return Ok(Arc::clone(&cached.content));
    }
    let (content, mtime) = read_lua_file(p)?;
    cache
        .write()
        .unwrap()
        .insert(p.clone(), CachedLua { content: Arc::clone(&content), mtime });
    Ok(content)
}

fn read_lua_file(p: &PathBuf) -> Result<(Arc<str>, std::time::SystemTime), AppError> {
    let s: Arc<str> = std::fs::read_to_string(p)
        .map_err(|e| AppError::Other(format!("读取 Lua 文件失败 {}: {e}", p.display())))?
        .into();
    let mtime = std::fs::metadata(p)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    Ok((s, mtime))
}

/// 定期自检：stat 一遍已缓存的 .lua，mtime 变了才重读；文件消失则移出缓存。
/// 返回本轮真正发生变更的文件，供调用方记日志。请求路径不会走到这里。
pub fn recheck_cached_files() -> Vec<PathBuf> {
    let cache = FILE_CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()));
    let snap: Vec<(PathBuf, std::time::SystemTime)> = cache
        .read()
        .unwrap()
        .iter()
        .map(|(p, c)| (p.clone(), c.mtime))
        .collect();
    let mut changed = Vec::new();
    for (p, old_mtime) in snap {
        let Ok(meta) = std::fs::metadata(&p) else {
            cache.write().unwrap().remove(&p);
            changed.push(p);
            continue;
        };
        if meta.modified().ok() == Some(old_mtime) {
            continue;
        }
        // 读失败（例如编辑器刚 truncate）则保留旧内容，下一轮再试：
        // 半成品文件不该把正在服务的请求打成 500。
        if let Ok((content, mtime)) = read_lua_file(&p) {
            cache
                .write()
                .unwrap()
                .insert(p.clone(), CachedLua { content, mtime });
            changed.push(p);
        }
    }
    changed
}

impl LuaSource {
    pub fn load(&self) -> Result<Arc<str>, AppError> {
        match self {
            LuaSource::Inline(s) => Ok(Arc::clone(s)),
            LuaSource::File(p) => load_file_cached(p),
        }
    }

    pub fn from_directive(d: &onrouter_config::Directive, base_dir: &PathBuf) -> Option<LuaSource> {
        let arg = d.arg(0)?;
        Some(if d.name.ends_with("_file") {
            LuaSource::File(resolve_path(arg, base_dir))
        } else {
            LuaSource::Inline(Arc::from(arg.to_string()))
        })
    }
}

/// cosocket 的统一流：明文 TCP，或 `sock:tlshandshake` 之后的 rustls 客户端 TLS-over-TCP。
/// 与 `proxy_tls::ProxyStream` 同构，但不需要 hyper 的 `Connection`/`rt` 桥接。
/// Tls 变体用 `Box` 保证 `Unpin`（`Pin::new(s.as_mut())` 要求内层 Unpin）。
pub enum CosStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for CosStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CosStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            CosStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for CosStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            CosStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            CosStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CosStream::Plain(s) => Pin::new(s).poll_flush(cx),
            CosStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CosStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            CosStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// TCP cosocket 句柄（对标 ngx.socket.tcp 的底层对象）。
///
/// I/O 在 tokio 任务里执行，**不持 Lua VM 锁**：`_start_*` 立即 spawn 一个 op 任务并返回 op id，
/// Lua 侧 `coroutine.yield(op_id)` 让出；op 完成后把结果作为唤醒值投回调度器，调度器再带结果
/// resume 本协程（即 `coroutine.yield` 的返回值）。同一 socket 上的 op 由调用协程串行发起，
/// `stream` 的 tokio 互斥锁只是与调度器/其它 VM 任务隔离的防护。
pub struct Cosocket {
    stream: Arc<tokio::sync::Mutex<Option<CosStream>>>,
    buf: Arc<tokio::sync::Mutex<Vec<u8>>>,
    timeout_ms: Arc<std::sync::atomic::AtomicU64>,
    /// setsize 上限（字节）；0 表示不限制。超限时 receive 报错而非继续缓冲。
    size_cap: Arc<std::sync::atomic::AtomicUsize>,
    /// 当前连接的对端 (host, port)，供 setkeepalive 回池与 reconnect 复用。
    peer: Arc<std::sync::Mutex<Option<(String, u16)>>>,
    /// 当前连接是否来自 keepalive 池（`getreusedtimes()`：1=复用，0=新建）
    reused: Arc<AtomicUsize>,
    op_counter: Arc<AtomicU64>,
    ev_tx: mpsc::UnboundedSender<(u64, Vec<ResumeVal>)>,
}

/// receive 模式（在同步阶段从 LuaValue 解析，交给 async 任务拥有）。
enum RecvPat {
    Line,
    All,
    Exact(usize),
}

impl Cosocket {
    fn new(ev_tx: mpsc::UnboundedSender<(u64, Vec<ResumeVal>)>, op_counter: Arc<AtomicU64>) -> Self {
        Cosocket {
            stream: Arc::new(tokio::sync::Mutex::new(None)),
            buf: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            timeout_ms: Arc::new(std::sync::atomic::AtomicU64::new(5000)),
            size_cap: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            peer: Arc::new(std::sync::Mutex::new(None)),
            reused: Arc::new(AtomicUsize::new(0)),
            op_counter,
            ev_tx,
        }
    }
}

/// 睡眠/op 的超时时长；0 表示不超时（给一个足够大的上限）。
fn op_timeout(dur_ms: u64) -> std::time::Duration {
    if dur_ms == 0 {
        std::time::Duration::from_secs(3600)
    } else {
        std::time::Duration::from_millis(dur_ms)
    }
}

/// 从已缓冲字节 + 流的增量读中取出一个 receive 请求的数据；内部按 (Line/All/Exact) 处理，
/// 读满/EOF/出错即返回。持有 buf 的 tokio 锁跨 await（Send 安全）。
async fn recv_into(
    s: &mut CosStream,
    buf: &mut Vec<u8>,
    pat: &RecvPat,
    cap: usize,
) -> Vec<ResumeVal> {
    use ResumeVal::*;
    let nil_closed = |left: Vec<u8>| vec![Nil, Str("closed".into()), Bytes(left)];
    let exceeds = || vec![Nil, Str("exceeds the max allowed size".into())];
    if cap > 0 {
        if let RecvPat::Exact(n) = pat {
            if *n > cap {
                return exceeds();
            }
        }
    }
    match pat {
        RecvPat::Line => loop {
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = buf.drain(..=pos).collect();
                line.pop(); // 去掉 '\n'
                if line.last() == Some(&b'\r') {
                    line.pop(); // 去掉 CRLF 的 '\r'
                }
                return vec![Bytes(line)];
            }
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) => return nil_closed(buf.clone()),
                Ok(n) => {
                    if cap > 0 && buf.len() + n > cap {
                        return exceeds();
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => return vec![Nil, Str(format!("recv error: {e}"))],
            }
        },
        RecvPat::Exact(n) => {
            if *n == 0 {
                return vec![Bytes(Vec::new())];
            }
            loop {
                if buf.len() >= *n {
                    let data: Vec<u8> = buf.drain(..*n).collect();
                    return vec![Bytes(data)];
                }
                let mut tmp = [0u8; 4096];
                match s.read(&mut tmp).await {
                    Ok(0) => return nil_closed(buf.clone()),
                    Ok(k) => {
                        if cap > 0 && buf.len() + k > cap {
                            return exceeds();
                        }
                        buf.extend_from_slice(&tmp[..k]);
                    }
                    Err(e) => return vec![Nil, Str(format!("recv error: {e}"))],
                }
            }
        }
        RecvPat::All => loop {
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) => return vec![Bytes(std::mem::take(buf))],
                Ok(k) => {
                    if cap > 0 && buf.len() + k > cap {
                        return exceeds();
                    }
                    tmp[..k].iter().for_each(|&b| buf.push(b));
                }
                Err(e) => return vec![Nil, Str(format!("recv error: {e}"))],
            }
        },
    }
}

/// 在 buf 中查找子序列 needle，返回首个匹配下标。
fn find_subslice(buf: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if buf.len() < needle.len() {
        return None;
    }
    buf.windows(needle.len()).position(|w| w == needle)
}

/// receiveany(min, max)：读到至少 min 字节即返回（上限 max，默认 4096），返回可用数据。
async fn recv_any_into(
    s: &mut CosStream,
    buf: &mut Vec<u8>,
    min: usize,
    max: usize,
    cap: usize,
) -> Vec<ResumeVal> {
    use ResumeVal::*;
    let max = if max == 0 { 4096 } else { max };
    if cap > 0 && min > cap {
        return vec![Nil, Str("exceeds the max allowed size".into())];
    }
    loop {
        if buf.len() >= min {
            let take = buf.len().min(max);
            let data: Vec<u8> = buf.drain(..take).collect();
            return vec![Bytes(data)];
        }
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp).await {
            Ok(0) => {
                if buf.is_empty() {
                    return vec![Nil, Str("closed".into())];
                }
                let data: Vec<u8> = buf.drain(..).collect();
                return vec![Bytes(data)];
            }
            Ok(n) => {
                if cap > 0 && buf.len() + n > cap {
                    return vec![Nil, Str("exceeds the max allowed size".into())];
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => return vec![Nil, Str(format!("recv error: {e}"))],
        }
    }
}

/// receiveuntil(delim)：读到 delim 为止，返回 delim 之前的数据并消费 delim；found=true。
/// EOF 且未找到 delim：返回已缓冲数据，found=false。
async fn recv_until_into(s: &mut CosStream, buf: &mut Vec<u8>, delim: &[u8]) -> Vec<ResumeVal> {
    use ResumeVal::*;
    if delim.is_empty() {
        return vec![Bytes(Vec::new()), Bool(true)];
    }
    loop {
        if let Some(pos) = find_subslice(buf, delim) {
            let chunk: Vec<u8> = buf.drain(..pos).collect();
            buf.drain(..delim.len()); // 消费分隔符本身
            return vec![Bytes(chunk), Bool(true)];
        }
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp).await {
            Ok(0) => {
                let rem: Vec<u8> = buf.drain(..).collect();
                return vec![Bytes(rem), Bool(false)];
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return vec![Nil, Str(format!("recv error: {e}"))],
        }
    }
}

impl LuaUserData for Cosocket {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // _start_connect(host, port) -> op id；成功唤醒值 [1]，失败 [nil, err]
        // 优先复用 keepalive 池里同 host:port 的未超时空闲连接（对标 OpenResty setkeepalive 复用）。
        methods.add_method("_start_connect", |lua, this, (host, port): (String, LuaValue)| {
            let port = to_u16(lua, &port)?;
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let stream = Arc::clone(&this.stream);
            let buf = Arc::clone(&this.buf);
            let peer = Arc::clone(&this.peer);
            let reused = Arc::clone(&this.reused);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            let key = format!("{host}:{port}");
            if let Some((s, leftover)) = crate::sockpool::take(&key) {
                // 命中池：接管已连接流与其残留缓冲，记录 peer，无需握手。
                reused.store(1, Ordering::Relaxed);
                let payload = vec![
                    ResumeVal::Int(1),
                    ResumeVal::Str("reused".into()),
                ];
                tokio::spawn(async move {
                    *stream.lock().await = Some(CosStream::Plain(s));
                    *buf.lock().await = leftover;
                    if let Ok(mut p) = peer.lock() {
                        *p = Some((host, port));
                    }
                    let _ = ev.send((id, payload));
                });
                return Ok(id);
            }
            reused.store(0, Ordering::Relaxed);
            let host2 = host.clone();
            tokio::spawn(async move {
                let payload = match tokio::time::timeout(dur, TcpStream::connect((host.as_str(), port))).await {
                    Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                    Ok(Err(e)) => vec![ResumeVal::Nil, ResumeVal::Str(format!("connect failed: {e}"))],
                    Ok(Ok(s)) => {
                        *stream.lock().await = Some(CosStream::Plain(s));
                        if let Ok(mut p) = peer.lock() {
                            *p = Some((host2, port));
                        }
                        vec![ResumeVal::Int(1)]
                    }
                };
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _start_send(data) -> op id；成功 [bytes]，失败 [nil, err]
        methods.add_method("_start_send", |lua, this, data: LuaString| {
            let _ = lua;
            let bytes = data.as_bytes().to_vec();
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let stream = Arc::clone(&this.stream);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            tokio::spawn(async move {
                let mut g = stream.lock().await;
                let payload = match g.as_mut() {
                    None => vec![ResumeVal::Nil, ResumeVal::Str("closed".into())],
                    Some(s) => match tokio::time::timeout(dur, s.write_all(&bytes)).await {
                        Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                        Ok(Err(e)) => vec![ResumeVal::Nil, ResumeVal::Str(format!("send error: {e}"))],
                        Ok(Ok(())) => vec![ResumeVal::Int(bytes.len() as i64)],
                    },
                };
                drop(g);
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _start_receive(pattern) -> op id；pattern: "*l"|nil / "*a" / 整数 n
        methods.add_method("_start_receive", |lua, this, pattern: LuaValue| {
            let pat = parse_recv_pat(lua, &pattern)?;
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let stream = Arc::clone(&this.stream);
            let buf = Arc::clone(&this.buf);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            let cap = this.size_cap.load(Ordering::Relaxed);
            tokio::spawn(async move {
                let mut sg = stream.lock().await;
                let s = match sg.as_mut() {
                    None => {
                        let _ = ev.send((id, vec![ResumeVal::Nil, ResumeVal::Str("closed".into())]));
                        return;
                    }
                    Some(s) => s,
                };
                let mut bg = buf.lock().await;
                let payload = match tokio::time::timeout(dur, recv_into(s, &mut bg, &pat, cap)).await {
                    Ok(p) => p,
                    Err(_) => {
                        // 超时：把已缓冲部分作为 partial 回传
                        let partial = bg.clone();
                        vec![
                            ResumeVal::Nil,
                            ResumeVal::Str("timeout".into()),
                            ResumeVal::Bytes(partial),
                        ]
                    }
                };
                drop(bg);
                drop(sg);
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _close() -> 1（同步：此刻无在途 op，tokio try_lock 可成功）
        methods.add_method("_close", |_lua, this, ()| {
            if let Ok(mut g) = this.stream.try_lock() {
                *g = None;
            } else {
                let stream = Arc::clone(&this.stream);
                tokio::spawn(async move {
                    *stream.lock().await = None;
                });
            }
            if let Ok(mut b) = this.buf.try_lock() {
                b.clear();
            }
            Ok(1u64)
        });

        // _settimeout(ms) -> 1
        methods.add_method("_settimeout", |_lua, this, ms: u64| {
            this.timeout_ms.store(ms, Ordering::Relaxed);
            Ok(1u64)
        });

        // _setsize(bytes) -> 1：设定接收缓冲上限，超限的 receive 报错而非无限缓冲。
        methods.add_method("_setsize", |_lua, this, bytes: usize| {
            this.size_cap.store(bytes, Ordering::Relaxed);
            Ok(1u64)
        });

        // _getreusedtimes() -> 0|1：当前连接是否来自 keepalive 池
        methods.add_method("_getreusedtimes", |_lua, this, ()| {
            Ok(this.reused.load(Ordering::Relaxed) as i64)
        });

        // _start_receiveany(min, max?) -> op id；成功 [data]，失败 [nil, err, partial]
        methods.add_method(
            "_start_receiveany",
            |lua, this, (min, max): (LuaValue, LuaValue)| {
                let min = to_usize(lua, &min)?.max(1);
                let max = to_usize_opt(lua, &max);
                let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
                let ev = this.ev_tx.clone();
                let stream = Arc::clone(&this.stream);
                let buf = Arc::clone(&this.buf);
                let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
                let cap = this.size_cap.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut sg = stream.lock().await;
                    let s = match sg.as_mut() {
                        None => {
                            let _ =
                                ev.send((id, vec![ResumeVal::Nil, ResumeVal::Str("closed".into())]));
                            return;
                        }
                        Some(s) => s,
                    };
                    let mut bg = buf.lock().await;
                    let payload =
                        match tokio::time::timeout(dur, recv_any_into(s, &mut bg, min, max, cap))
                            .await
                        {
                            Ok(p) => p,
                            Err(_) => {
                                let partial = bg.clone();
                                vec![
                                    ResumeVal::Nil,
                                    ResumeVal::Str("timeout".into()),
                                    ResumeVal::Bytes(partial),
                                ]
                            }
                        };
                    drop(bg);
                    drop(sg);
                    let _ = ev.send((id, payload));
                });
                Ok(id)
            },
        );

        // _start_receive_until(delim) -> op id；成功 [data, found(bool)]，失败 [nil, err]
        methods.add_method("_start_receive_until", |_lua, this, delim: LuaString| {
            let needle = delim.as_bytes().to_vec();
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let stream = Arc::clone(&this.stream);
            let buf = Arc::clone(&this.buf);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            tokio::spawn(async move {
                let mut sg = stream.lock().await;
                let s = match sg.as_mut() {
                    None => {
                        let _ =
                            ev.send((id, vec![ResumeVal::Nil, ResumeVal::Str("closed".into())]));
                        return;
                    }
                    Some(s) => s,
                };
                let mut bg = buf.lock().await;
                let payload = match tokio::time::timeout(dur, recv_until_into(s, &mut bg, &needle))
                    .await
                {
                    Ok(p) => p,
                    Err(_) => {
                        let partial = bg.clone();
                        vec![
                            ResumeVal::Nil,
                            ResumeVal::Str("timeout".into()),
                            ResumeVal::Bytes(partial),
                        ]
                    }
                };
                drop(bg);
                drop(sg);
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _start_shutdown(read?, write?) -> op id；成功 [1]，失败 [nil, err]
        // 对标 OpenResty：这是会让出的 cosocket op。write 方向做真正的优雅写关闭（对端收到 EOF）。
        methods.add_method(
            "_start_shutdown",
            |_lua, this, (rd, wr): (Option<bool>, Option<bool>)| {
                let read = rd.unwrap_or(true);
                let write = wr.unwrap_or(true);
                let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
                let ev = this.ev_tx.clone();
                let stream = Arc::clone(&this.stream);
                // 仅读方向关闭：tokio 公开 API 无法在不拆流的前提下半关读，明确拒绝。
                if !write && read {
                    tokio::spawn(async move {
                        let _ = ev.send((
                            id,
                            vec![
                                ResumeVal::Nil,
                                ResumeVal::Str("read-half shutdown unsupported".into()),
                            ],
                        ));
                    });
                    return Ok(id);
                }
                // both / write-only：优雅关闭写方向（flush + FIN）。
                tokio::spawn(async move {
                    let mut sg = stream.lock().await;
                    let payload = match sg.as_mut() {
                        None => vec![ResumeVal::Nil, ResumeVal::Str("closed".into())],
                        Some(s) => match s.shutdown().await {
                            Ok(()) => vec![ResumeVal::Int(1)],
                            Err(e) => vec![ResumeVal::Nil, ResumeVal::Str(format!("shutdown: {e}"))],
                        },
                    };
                    drop(sg);
                    let _ = ev.send((id, payload));
                });
                Ok(id)
            },
        );

        // _setkeepalive(timeout_sec?, pool_size?) -> ok, err（同步：把空闲连接回池）
        methods.add_method(
            "_setkeepalive",
            |lua, this, (timeout, pool_size): (Option<f64>, Option<usize>)| {
                let key = match this.peer.lock() {
                    Ok(g) => match g.as_ref() {
                        Some((h, p)) => format!("{h}:{p}"),
                        None => {
                            return Ok((
                                LuaValue::Nil,
                                LuaValue::String(lua.create_string("closed")?),
                            ))
                        }
                    },
                    Err(p) => p.into_inner().as_ref().map(|(h, p)| format!("{h}:{p}")).unwrap_or_default(),
                };
                if key.is_empty() {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("closed")?),
                    ));
                }
                let idle_ms = ((timeout.unwrap_or(60.0) * 1000.0) as u64).max(1);
                let s = match this.stream.try_lock() {
                    Ok(mut g) => match g.take() {
                        Some(CosStream::Plain(s)) => s,
                        Some(CosStream::Tls(_)) => {
                            return Ok((
                                LuaValue::Nil,
                                LuaValue::String(lua.create_string("tls connections are not pooled")?),
                            ))
                        }
                        None => {
                            return Ok((
                                LuaValue::Nil,
                                LuaValue::String(lua.create_string("closed")?),
                            ))
                        }
                    },
                    Err(_) => {
                        return Ok((
                            LuaValue::Nil,
                            LuaValue::String(lua.create_string("busy: pending operation")?),
                        ))
                    }
                };
                let leftover = match this.buf.try_lock() {
                    Ok(mut b) => std::mem::take(&mut *b),
                    Err(_) => {
                        // 无法取 buf：丢弃连接（随 s drop 关闭），报忙。
                        return Ok((
                            LuaValue::Nil,
                            LuaValue::String(lua.create_string("busy: pending operation")?),
                        ));
                    }
                };
                if !leftover.is_empty() {
                    // OpenResty 拒绝保有待读数据的连接；连接随 s drop 关闭。
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("pool supports not keeping pending read data")?),
                    ));
                }
                crate::sockpool::put(
                    key,
                    s,
                    Vec::new(),
                    std::time::Duration::from_millis(idle_ms),
                    pool_size.unwrap_or(0),
                );
                Ok((LuaValue::Integer(1), LuaValue::Nil))
            },
        );

        // _start_tlshandshake(sni?, verify?, ca_path?) -> id；成功 [1]，失败 [nil, err]
        // 把当前明文 TCP 流升级为 rustls 客户端 TLS 流（对标 sock:tlshandshake）。默认不校验证书；
        // verify=true 需给 ca 指向 PEM 根束（纯 Rust 离线，未链接系统根库）。
        methods.add_method(
            "_start_tlshandshake",
            |_lua, this, (sni, verify, ca): (Option<String>, Option<bool>, Option<String>)| {
                let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
                let ev = this.ev_tx.clone();
                let stream = Arc::clone(&this.stream);
                let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
                // 默认 SNI：取已记录的 peer 主机名。
                let sni = sni.or_else(|| {
                    this.peer.lock().ok().and_then(|p| p.as_ref().map(|(h, _)| h.clone()))
                });
                let verify = verify.unwrap_or(false);
                let ca_present = ca.clone();
                tokio::spawn(async move {
                    let mut sg = stream.lock().await;
                    let tcp = match sg.take() {
                        Some(CosStream::Plain(t)) => t,
                        Some(CosStream::Tls(_)) => {
                            let _ = ev.send((
                                id,
                                vec![ResumeVal::Nil, ResumeVal::Str("already tls".into())],
                            ));
                            return;
                        }
                        None => {
                            let _ = ev.send((
                                id,
                                vec![ResumeVal::Nil, ResumeVal::Str("closed".into())],
                            ));
                            return;
                        }
                    };
                    let host = match sni.clone() {
                        Some(h) => h,
                        None => {
                            let _ = ev.send((
                                id,
                                vec![ResumeVal::Nil, ResumeVal::Str("no server name for SNI".into())],
                            ));
                            return;
                        }
                    };
                    let cfg_res = if verify {
                        match ca_present.as_deref() {
                            Some(path) => crate::proxy_tls::verify_client_config(path)
                                .map_err(|e| e),
                            None => Err("verify=true 需要 ca 证书束路径".to_string()),
                        }
                    } else {
                        Ok(crate::proxy_tls::insecure_client_config())
                    };
                    let cfg = match cfg_res {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = ev.send((id, vec![ResumeVal::Nil, ResumeVal::Str(e)]));
                            return;
                        }
                    };
                    let name = match ServerName::try_from(host.clone()) {
                        Ok(n) => n.to_owned(),
                        Err(e) => {
                            let _ = ev.send((
                                id,
                                vec![
                                    ResumeVal::Nil,
                                    ResumeVal::Str(format!("非法 SNI 主机名 {host}: {e}")),
                                ],
                            ));
                            return;
                        }
                    };
                    let connector = TlsConnector::from(cfg);
                    let fut = async {
                        let s = connector.connect(name, tcp).await?;
                        Ok::<_, std::io::Error>(s)
                    };
                    let payload = match tokio::time::timeout(dur, fut).await {
                        Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                        Ok(Err(e)) => {
                            vec![ResumeVal::Nil, ResumeVal::Str(format!("tls handshake failed: {e}"))]
                        }
                        Ok(Ok(tls)) => {
                            *sg = Some(CosStream::Tls(Box::new(tls)));
                            vec![ResumeVal::Int(1)]
                        }
                    };
                    let _ = ev.send((id, payload));
                });
                Ok(id)
            },
        );
    }
}

/// UDP cosocket 句柄（对标 ngx.socket.udp）。数据报语义：setpeername 后 send/receive
/// 走「已连接 UDP」（底层 send/recv 只与该对端收发）。同样经调度器让出，不持 VM 锁。
pub struct UdpCosocket {
    sock: Arc<tokio::sync::Mutex<Option<UdpSocket>>>,
    timeout_ms: Arc<AtomicU64>,
    op_counter: Arc<AtomicU64>,
    ev_tx: mpsc::UnboundedSender<(u64, Vec<ResumeVal>)>,
}

impl UdpCosocket {
    fn new(ev_tx: mpsc::UnboundedSender<(u64, Vec<ResumeVal>)>, op_counter: Arc<AtomicU64>) -> Self {
        UdpCosocket {
            sock: Arc::new(tokio::sync::Mutex::new(None)),
            timeout_ms: Arc::new(AtomicU64::new(5000)),
            op_counter,
            ev_tx,
        }
    }
}

impl LuaUserData for UdpCosocket {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // _start_setpeername(host, port) -> id；成功 [1]，失败 [nil, err]
        methods.add_method(
            "_start_setpeername",
            |lua, this, (host, port): (String, LuaValue)| {
                let port = to_u16(lua, &port)?;
                let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
                let ev = this.ev_tx.clone();
                let sock = Arc::clone(&this.sock);
                let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
                tokio::spawn(async move {
                    let payload = match tokio::time::timeout(dur, async {
                        let s = UdpSocket::bind("0.0.0.0:0").await?;
                        s.connect((host.as_str(), port)).await?;
                        Ok::<_, std::io::Error>(s)
                    })
                    .await
                    {
                        Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                        Ok(Err(e)) => vec![ResumeVal::Nil, ResumeVal::Str(format!("setpeername failed: {e}"))],
                        Ok(Ok(s)) => {
                            *sock.lock().await = Some(s);
                            vec![ResumeVal::Int(1)]
                        }
                    };
                    let _ = ev.send((id, payload));
                });
                Ok(id)
            },
        );

        // _start_send(data) -> id；成功 [bytes]，失败 [nil, err]
        methods.add_method("_start_send", |lua, this, data: LuaString| {
            let _ = lua;
            let bytes = data.as_bytes().to_vec();
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let sock = Arc::clone(&this.sock);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            tokio::spawn(async move {
                let mut g = sock.lock().await;
                let payload = match g.as_mut() {
                    None => vec![ResumeVal::Nil, ResumeVal::Str("closed".into())],
                    Some(s) => match tokio::time::timeout(dur, s.send(&bytes)).await {
                        Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                        Ok(Err(e)) => vec![ResumeVal::Nil, ResumeVal::Str(format!("send error: {e}"))],
                        Ok(Ok(n)) => vec![ResumeVal::Int(n as i64)],
                    },
                };
                drop(g);
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _start_receive(max) -> id；成功 [data]，失败 [nil, err]（一次收一个数据报）
        methods.add_method("_start_receive", |lua, this, max: LuaValue| {
            let mut max = to_usize_opt(lua, &max);
            if max == 0 {
                max = 8192;
            }
            let id = this.op_counter.fetch_add(1, Ordering::Relaxed);
            let ev = this.ev_tx.clone();
            let sock = Arc::clone(&this.sock);
            let dur = op_timeout(this.timeout_ms.load(Ordering::Relaxed));
            tokio::spawn(async move {
                let mut g = sock.lock().await;
                let payload = match g.as_mut() {
                    None => vec![ResumeVal::Nil, ResumeVal::Str("closed".into())],
                    Some(s) => {
                        let mut v = vec![0u8; max];
                        match tokio::time::timeout(dur, s.recv(&mut v)).await {
                            Err(_) => vec![ResumeVal::Nil, ResumeVal::Str("timeout".into())],
                            Ok(Err(e)) => vec![ResumeVal::Nil, ResumeVal::Str(format!("recv error: {e}"))],
                            Ok(Ok(n)) => vec![ResumeVal::Bytes(v[..n].to_vec())],
                        }
                    }
                };
                drop(g);
                let _ = ev.send((id, payload));
            });
            Ok(id)
        });

        // _close() -> 1（同步）
        methods.add_method("_close", |_lua, this, ()| {
            if let Ok(mut g) = this.sock.try_lock() {
                *g = None;
            } else {
                let sock = Arc::clone(&this.sock);
                tokio::spawn(async move {
                    *sock.lock().await = None;
                });
            }
            Ok(1u64)
        });

        // _settimeout(ms) -> 1
        methods.add_method("_settimeout", |_lua, this, ms: u64| {
            this.timeout_ms.store(ms, Ordering::Relaxed);
            Ok(1u64)
        });
    }
}

/// 把 Lua 侧的端口值（整数/数字/字符串）转成 u16。
fn to_u16(_lua: &Lua, v: &LuaValue) -> LuaResult<u16> {
    let n = match v {
        LuaValue::Integer(i) => *i,
        LuaValue::Number(f) => *f as i64,
        LuaValue::String(s) => s
            .to_string_lossy()
            .parse::<i64>()
            .map_err(|_| LuaError::runtime("invalid port"))?,
        _ => return Err(LuaError::runtime("invalid port type")),
    };
    if !(1..=65535).contains(&n) {
        return Err(LuaError::runtime("port out of range"));
    }
    Ok(n as u16)
}

/// 把 Lua 侧的整数/数字/字符串值转成 usize（必需参数）。
fn to_usize(_lua: &Lua, v: &LuaValue) -> LuaResult<usize> {
    let n = match v {
        LuaValue::Integer(i) => *i,
        LuaValue::Number(f) => *f as i64,
        LuaValue::String(s) => s
            .to_string_lossy()
            .parse::<i64>()
            .map_err(|_| LuaError::runtime("invalid number"))?,
        _ => return Err(LuaError::runtime("invalid number type")),
    };
    if n < 0 {
        return Err(LuaError::runtime("negative size"));
    }
    Ok(n as usize)
}

/// 可选 usize 参数：nil/缺失视作 0（由调用方决定默认）。
fn to_usize_opt(_lua: &Lua, v: &LuaValue) -> usize {
    match v {
        LuaValue::Integer(i) if *i > 0 => *i as usize,
        LuaValue::Number(f) if *f >= 1.0 => *f as usize,
        LuaValue::String(s) => s.to_string_lossy().parse::<usize>().unwrap_or(0),
        _ => 0,
    }
}

/// 解析 receive pattern。
fn parse_recv_pat(_lua: &Lua, v: &LuaValue) -> LuaResult<RecvPat> {
    Ok(match v {
        LuaValue::Nil => RecvPat::Line,
        LuaValue::Integer(n) if *n > 0 => RecvPat::Exact(*n as usize),
        LuaValue::Number(f) if *f >= 1.0 => RecvPat::Exact(*f as usize),
        LuaValue::String(s) => {
            let t = s.to_string_lossy().to_lowercase();
            match t.as_str() {
                "*a" | "*all" | "all" => RecvPat::All,
                "*l" | "l" | "line" => RecvPat::Line,
                other => {
                    // 也接受纯数字字符串
                    match other.parse::<usize>() {
                        Ok(n) if n > 0 => RecvPat::Exact(n),
                        _ => RecvPat::Line,
                    }
                }
            }
        }
        _ => RecvPat::Line,
    })
}

type VM = tokio::sync::Mutex<Lua>;

/// 对标 lua_max_pending_timers / lua_max_running_timers 的默认值
const MAX_PENDING_TIMERS: isize = 1024;
const MAX_RUNNING_TIMERS: isize = 4096;

/// 一次请求阶段作业：由 run_phase 提交给所属 VM 的调度器协程执行。
/// 调度器把 code 编译进一个新 Lua 协程（thread），与其它在途请求在同一 VM 上
/// 交错 resume；协程 Finished 时通过 reply 回传结果（保持 run_phase 原契约）。
enum Job {
    Start {
        co_id: u64,
        phase_name: String,
        code: Arc<str>,
        ctx: Arc<Mutex<RequestCtx>>,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    /// 快速路径首段已在连接任务里跑过并让出：把挂起的协程连同 registry 句柄移交给调度器，
    /// 由它登记等待（op 结果可能已在线路上）并在事件到达后恢复。
    Adopt {
        co_id: u64,
        phase_name: String,
        ctx: Arc<Mutex<RequestCtx>>,
        thread_key: RegistryKey,
        ctx_table_key: RegistryKey,
        op_id: u64,
        reply: oneshot::Sender<Result<(), AppError>>,
    },
    /// 定时器回调：与请求协程一样由调度器 resume，因此回调里可以使用 ngx.sleep /
    /// cosocket / ngx.location.capture / ngx.thread.*（走同一套 yield-op 唤醒机制）。
    /// 线程与游离 ctx 表已在 tokio 定时器任务里持 VM 锁建好。
    Timer {
        co_id: u64,
        thread_key: RegistryKey,
        ctx_table_key: RegistryKey,
        ctx: Arc<Mutex<RequestCtx>>,
        done: oneshot::Sender<Result<bool, String>>,
    },
}

/// VM 槽位：提交作业的发端（run_phase 用）+ 每 VM 的协程 id 计数。
/// VM 本体由调度器任务持有强引用（引擎存活期间调度器不退出），Weak<VM> 供 ngx.timer 回调加锁。
/// co_counter 同时用于 Job 主协程 id 与 ngx.thread 子协程 id（同一命名空间，杜绝 states 键冲突）。
struct VmSlot {
    job_tx: mpsc::UnboundedSender<Job>,
    co_counter: Arc<AtomicU64>,
    /// 快速路径入口：VM 锁空闲时由当前请求任务直接持锁执行首段（省掉两次任务跳转）
    vm: Arc<VM>,
    /// 每 VM 一份编译缓存：调度器与快速路径共用，避免两条路径各编译一次
    chunks: Arc<std::sync::Mutex<ChunkCache>>,
    /// ngx.thread.spawn 的跨锁信箱：快速路径结束时要清掉本请求未启动的子线程
    sched_ctl: SharedCtl,
}

/// 调度器在协程让出后、重新 resume 时回传给协程的值（纯 Rust，跨 await 安全）。
/// 由完成事件的发端（睡眠 / cosocket op 任务）填充，scheduler 在 resume 前转成 LuaValue。
#[derive(Clone)]
enum ResumeVal {
    Nil,
    #[allow(dead_code)] // 预留给未来返回布尔的 op（如 setkeepalive）
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    /// 子请求（ngx.location.capture）结果：让出恢复时转成 {status=,body=,header=} 表
    SubReq {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
}

/// 每 VM 一份的已编译代码块缓存：阶段名 -> 源码 -> registry 里的函数原型句柄。
/// 对标 OpenResty 的 `lua_code_cache on`：一段源码只在该 VM 里编译一次，之后每个请求只做
/// 一次 registry 取回 + `create_thread`。编译一个 chunk 是 10µs 量级，与整条 content_by_lua
/// 请求路径同量级，每请求重编译会让 Lua 端点慢于 OpenResty（实测 c=1 时 0.74x）。
/// 用 RegistryKey 而非 Function：mlua 的 Function/Table 是 `!Send`，必须靠 registry 句柄跨 await。
/// 键取自配置里的 LuaSource，稳态下条目数就等于指令数。定期自检改写脚本内容会新增一个源码键，
/// 旧版本靠下面的桶上限淘汰（每阶段最多这么多份不同源码），不会无界增长。
type ChunkCache = HashMap<String, HashMap<Arc<str>, RegistryKey>>;

/// 单个阶段桶允许共存的不同源码份数：正常配置远达不到，只有反复编辑脚本才会触发淘汰。
const CHUNK_CACHE_MAX_PER_PHASE: usize = 16;

/// 调度器内部：一个在途协程的 Rust 侧状态。
/// thread_key / ctx_table_key 指向 registry 里持有的 mlua 句柄（Send 安全，跨 await 存活）。
struct CoState {
    thread_key: RegistryKey,
    ctx_table_key: RegistryKey,
    ctx: Arc<Mutex<RequestCtx>>,
    reply: oneshot::Sender<Result<(), AppError>>,
    /// 本次让出对应的唤醒参数（睡眠为空；cosocket op 携带结果）。resume 前消费并清空。
    wake_args: Vec<ResumeVal>,
    /// 该协程所属阶段名（rewrite/access/content/header_filter/body_filter/log/timer…）。
    /// resume 前回挂到 registry 的 `__phase`，供 ngx.get_phase() 读取（对标 ngx_lua）。
    phase: String,
    // ---------- ngx.thread.* 轻量级线程（light thread）----------
    /// true=由 ngx.thread.spawn 派生的子协程（不拥有请求 reply）；false=Job 主协程。
    is_child: bool,
    /// 所属请求（顶层 Job）的 co id；主协程等于自身，子协程等于派生它的那个请求。用于共享 ctx 与收尾回收。
    owner: u64,
    /// 若为 Some(tid)，本次 resume 用 Lua 侧 `__thread_sink[tid]` 的打包结果作唤醒值喂回
    /// （ngx.thread.wait 命中已完成线程时经调度器投递）。resume 前消费并清空。
    wake_tid: Option<u64>,
    /// 定时器回调：完成后把 `Ok(return_false)` / `Err(错误)` 回执给发起任务的 tokio 定时器，
    /// 由它决定 `ngx.timer.every` 是否继续下一轮并维护 running 计数。普通请求为 None。
    timer_done: Option<oneshot::Sender<Result<bool, String>>>,
}

/// ngx.thread.* 的跨锁信箱：请求协程内的 spawn/wait/kill 原语把「意图」写在这里，
/// 由所属 VM 的调度器在持锁一步内消费（登记子协程、挂起/即时唤醒 wait、杀掉线程）。
/// 用 std Mutex，临界区极短、绝不跨 await；加锁顺序恒为「先 VM 锁、后 ctl」。
pub(crate) struct SchedCtl {
    spawns: Vec<SpawnReq>,
    waits: Vec<WaitReq>,
    kills: Vec<u64>,
}

/// 一次 spawn 的登记：tid=新子协程 id，owner=所属请求 co id，thread_key=已建好的协程句柄。
struct SpawnReq {
    tid: u64,
    owner: u64,
    thread_key: RegistryKey,
}

/// 一次 wait 的登记：op=父协程 yield 出的等待 op id，tids=被等待的线程（任一完成即返回）。
struct WaitReq {
    op: u64,
    tids: Vec<u64>,
}

type SharedCtl = Arc<std::sync::Mutex<SchedCtl>>;

/// 快速路径首段的执行结果
enum InlineOutcome {
    Finished,
    Yielded {
        op_id: u64,
        thread_key: RegistryKey,
        ctx_table_key: RegistryKey,
    },
}

/// 请求已结束但 ngx.thread.spawn 的子协程还没被调度器登记：直接丢弃（对标请求结束即回收）。
fn drop_unstarted_spawns(ctl: &SharedCtl, owner: u64) {
    let mut c = ctl.lock().unwrap();
    c.spawns.retain(|s| s.owner != owner);
}

/// 登记一次协程让出：等待 op 完成事件；若等的是 ngx.thread.wait 且目标已结束则立即唤醒。
/// 调度器恢复路径与 Adopt（快速路径移交）路径共用，保证两边的等待语义一致。
fn park_yielded(
    co_id: u64,
    sid: u64,
    states: &mut HashMap<u64, CoState>,
    pending: &mut VecDeque<u64>,
    waiting: &mut HashMap<u64, u64>,
    ctl: &SharedCtl,
    done: &HashSet<u64>,
    tid_waitop: &mut HashMap<u64, u64>,
    wait_group: &mut HashMap<u64, Vec<u64>>,
) {
    if sid == THREAD_YIELD_MARK {
        // ngx.thread.yield：主动让出，本轮重排再跑
        pending.push_back(co_id);
        return;
    }
    let waited = {
        let mut c = ctl.lock().unwrap();
        match c.waits.iter().position(|w| w.op == sid) {
            Some(i) => Some(c.waits.remove(i).tids),
            None => None,
        }
    };
    match waited {
        Some(tids) => {
            if let Some(hit) = tids.iter().find(|t| done.contains(t)).copied() {
                if let Some(st) = states.get_mut(&co_id) {
                    st.wake_tid = Some(hit);
                }
                pending.push_back(co_id);
            } else {
                waiting.insert(sid, co_id);
                for t in &tids {
                    tid_waitop.insert(*t, sid);
                }
                wait_group.insert(sid, tids);
            }
        }
        None => {
            // 普通 sleep / cosocket / 子请求让出
            waiting.insert(sid, co_id);
        }
    }
}

/// ngx.thread.yield() 让出后「重排再跑」的哨兵 op id（对应 Lua 整数 i64::MAX）：
/// 调度器认出它即把本协程重新入队，不登记 waiting（真实 op id 从 1 递增，永达不到此值）。
const THREAD_YIELD_MARK: u64 = i64::MAX as u64;

pub struct LuaEngine {
    /// Lua VM 池：每 CPU 核心一个独立 VM，VM 之间完全并行；
    /// 每个 VM 内部由调度器以协程方式并发多条在途请求（对标 OpenResty 每 worker 一个 VM）。
    vms: Vec<Arc<VmSlot>>,
    /// 轮询游标（无锁）
    counter: AtomicUsize,
    /// 子请求用的 AppState 晚绑定槽：LuaEngine 在 AppState 之前构造，故捕获
    /// Weak<AppState> 只能在 main 建好 state 后回填（见 `bind_app_state`）。
    subreq_slot: SubreqSlot,
    /// init_worker_by_lua*：调度器就绪后由 `run_init_workers()` 在每个 VM 各执行一次
    worker_inits: Vec<(String, LuaSource)>,
}

/// 子请求晚句柄：安装 API 时各 VM 捕获其克隆，运行期升级成 `Arc<AppState>` 跑 run_capture。
pub type SubreqSlot = Arc<std::sync::OnceLock<Weak<crate::server::AppState>>>;

// ---------- 编解码工具（无第三方依赖的 base64 / percent-encoding） ----------

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(B64_ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && c != b'\r' && c != b'\n').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - i * 6);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn is_uri_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// 对标 ngx.escape_uri：只保留字母数字与 -._~，其余全部 %XX（含 '/'）
pub fn escape_uri(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if is_uri_unreserved(c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// 对标 ngx.unescape_uri：%XX 解码 + '+' 还原为空格
pub fn unescape_uri(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(c) => {
                        out.push(c);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 对标 ngx.decode_args："a=1&b=two&flag" -> {a="1", b="two", flag=true}
fn decode_args(query: &str) -> Vec<(String, LuaArgValue)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => out.push((unescape_uri(k), LuaArgValue::Str(unescape_uri(v)))),
            None => out.push((unescape_uri(pair), LuaArgValue::Flag)),
        }
    }
    out
}

// ---------- ngx.* 摘要 / CRC / 时间（ring 纯 Rust，复用依赖图中已有的 ring） ----------

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// MD5 摘要核心（纯 Rust，教科书 RFC1321；ring 不提供 MD5，故自实现）。
fn md5_bytes(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] =
        std::array::from_fn(|i| (2f64.powi(32) * ((i as f64 + 1.0).sin().abs())) as u32);

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x6745_2301u32, 0xefcd_ab89u32, 0x98ba_dcfeu32, 0x1032_5476u32);

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (mut f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// ngx.md5(str) —— 十六进制小写摘要
fn md5_hex(data: &[u8]) -> String {
    hex_lower(&md5_bytes(data))
}

/// ngx.md5_bin(str) —— 原始 16 字节
fn md5_bin(data: &[u8]) -> Vec<u8> {
    md5_bytes(data).to_vec()
}

/// ngx.sha1_bin(str) —— 原始 20 字节（OpenResty 语义）
fn sha1_bin(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec()
}

/// SHA-256 原始 32 字节摘要（resty.string.sha256_hex 的底层）。
fn sha256_bin(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// ngx.hmac_sha1(key, str) —— 原始 20 字节 HMAC
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// CRC32（IEEE 802.3 反向多项式 0xEDB88320），与 nginx/OpenResty 的 crc32 逐位一致。
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut tab = [0u32; 256];
        for (i, e) in tab.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        tab
    });
    let mut crc = !0u32;
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// ngx.cookie_time(ts) —— Netscape cookie 时间串 "%a, %d-%b-%Y %H:%M:%S GMT"
fn cookie_time(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%a, %d-%b-%Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01-Jan-1970 00:00:00 GMT".to_string())
}

/// ngx.http_time(ts) —— IMF (RFC1123) 时间串 "Wdy, DD Mon YYYY HH:MM:SS GMT"
fn http_time(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

/// ngx.parse_http_time(str) —— 解析 IMF 时间回 unix 秒；失败返回 None（OpenResty 语义）
fn parse_http_time(s: &str) -> Option<i64> {
    use chrono::{DateTime, Utc};
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc).timestamp());
    }
    chrono::NaiveDateTime::parse_from_str(s, "%a, %d %b %Y %H:%M:%S GMT")
        .ok()
        .map(|n| n.and_utc().timestamp())
}

/// 改写/构造请求体后同步 Content-Length；Transfer-Encoding 与之冲突，一并移除。
fn set_request_content_length(ctx: &mut crate::engine::RequestCtx, len: usize) {
    ctx.req_headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")
    });
    ctx.req_headers
        .push(("content-length".to_string(), len.to_string()));
}


/// 参数值：字符串或布尔标志
pub enum LuaArgValue {
    Str(String),
    Flag,
}

fn push_args_table(lua: &Lua, args: Vec<(String, LuaArgValue)>) -> LuaResult<LuaTable> {
    let t = lua.create_table()?;
    for (k, v) in args {
        match v {
            LuaArgValue::Str(s) => t.raw_set(k, s)?,
            LuaArgValue::Flag => t.raw_set(k, true)?,
        }
    }
    Ok(t)
}

/// OpenResty lua_package_path 的占位符语义：`$prefix`/`${prefix}` 替换为前缀目录，
/// `;;` 替换为 `;` + Lua 默认路径（`;;` 的两个分号分别充当分隔与占位）；
/// 未写 `;;` 时默认路径被整体替换。
fn expand_package_path(raw: &str, default: &str, prefix: &str) -> String {
    let s = raw.replace("${prefix}", prefix).replace("$prefix", prefix);
    let mut expanded = s.replace(";;", &format!(";{default};"));
    if s.starts_with(";;") {
        expanded = expanded.trim_start_matches(';').to_string();
    }
    if s.ends_with(";;") {
        expanded = expanded.trim_end_matches(';').to_string();
    }
    expanded
}

impl LuaEngine {
    /// VM 实例数（启动日志用）
    pub fn vm_count(&self) -> usize {
        self.vms.len()
    }

    pub fn new(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        let dicts = SharedDicts::parse_all(config)?;

        // init_by_lua / init_by_lua_file：收集脚本（每个 VM 各执行一次，对标每 worker 一次 init）
        let mut inits: Vec<(String, String)> = Vec::new();
        for name in ["init_by_lua", "init_by_lua_file"] {
            if let Some(d) = config.find(name) {
                let Some(arg) = d.arg(0) else { continue };
                let code = if name.ends_with("_file") {
                    std::fs::read_to_string(resolve_path(arg, base_dir))
                        .map_err(|e| AppError::Other(format!("读取 {arg}: {e}")))?
                } else {
                    arg.to_string()
                };
                inits.push((name.to_string(), code));
            }
        }

        // init_worker_by_lua*：不在 new 里同步执行——脚本里的 ngx.sleep / ngx.timer.at /
        // cosocket 都依赖 VM 调度器，必须等调度器任务起来后由 run_init_workers() 提交。
        let mut worker_inits: Vec<(String, LuaSource)> = Vec::new();
        for name in ["init_worker_by_lua", "init_worker_by_lua_file"] {
            if let Some(d) = config.find(name) {
                if let Some(src) = LuaSource::from_directive(d, base_dir) {
                    // _file 在启动阶段就读一次：路径错误直接让启动失败，而不是静默跳过
                    src.load()?;
                    worker_inits.push((name.to_string(), src));
                }
            }
        }

        // lua_package_path：可多次出现，按声明顺序用 ';' 拼接；`$prefix` 与 `;;` 在应用时展开
        let raw_package_path = {
            let mut vals: Vec<String> = Vec::new();
            for d in &config.root.block {
                if d.name == "lua_package_path" {
                    if let Some(a) = d.arg(0) {
                        vals.push(a.to_string());
                    }
                }
            }
            (!vals.is_empty()).then(|| vals.join(";"))
        };

        // VM 数量 = CPU 核心数（1~16 封顶）
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 16);
        // 进程级定时器计数（对标 lua_max_pending/running_timers 的每 worker 计数）
        let timer_pending = Arc::new(AtomicIsize::new(0));
        let timer_running = Arc::new(AtomicIsize::new(0));
        let subreq_slot: SubreqSlot = Arc::new(std::sync::OnceLock::new());
        let mut vms: Vec<Arc<VmSlot>> = Vec::with_capacity(n);
        let mut applied_path: Option<String> = None;
        for _ in 0..n {
            let vm = Arc::new(VM::new(Lua::new()));
            let vm_ref = Arc::downgrade(&vm);
            // 每 VM 一套作业/事件通道：调度器任务独占 VM 锁，run_phase 通过 job_tx 提交
            // 事件 = (op id, 回传给协程的唤醒值)：睡眠投空 vec，cosocket op 投结果
            let (job_tx, job_rx) = mpsc::unbounded_channel::<Job>();
            let (ev_tx, ev_rx) = mpsc::unbounded_channel::<(u64, Vec<ResumeVal>)>();
            let op_counter = Arc::new(AtomicU64::new(1));
            // co_counter：Job 主协程与 ngx.thread 子协程共用同一 id 命名空间（states 键唯一）。
            // sched_ctl：请求协程内的 spawn/wait/kill 原语 ↔ 调度器的跨锁信箱。
            let co_counter = Arc::new(AtomicU64::new(1));
            let sched_ctl: SharedCtl = Arc::new(std::sync::Mutex::new(SchedCtl {
                spawns: Vec::new(),
                waits: Vec::new(),
                kills: Vec::new(),
            }));
            {
                let mut guard = vm.try_lock()
                    .map_err(|_| AppError::Other("Lua VM 启动时被占用".to_string()))?;
                Self::install_api(
                    &mut guard,
                    &dicts,
                    &vm_ref,
                    &timer_pending,
                    &timer_running,
                    &ev_tx,
                    &op_counter,
                    &subreq_slot,
                    &co_counter,
                    &sched_ctl,
                    &job_tx,
                )?;
                crate::lua_resty::install_modules(&guard)
                    .map_err(|e| AppError::Other(format!("注册 resty.* 模块失败: {e}")))?;
                if let Some(raw) = &raw_package_path {
                    let applied = Self::set_package_path(&guard, raw, base_dir)?;
                    if applied_path.is_none() {
                        applied_path = Some(applied);
                    }
                }
                for (name, code) in &inits {
                    guard.load(code).set_name(name).exec()?;
                }
            }
            // ev_tx 的存活副本此刻已冻结进 ngx.sleep 的 Rust 闭包里；调度器只持有 ev_rx
            // 调度器任务持有 VM 的强引用：引擎存活期间 job_tx 不 drop，调度器不退出，VM 随之存活
            let chunks: Arc<std::sync::Mutex<ChunkCache>> =
                Arc::new(std::sync::Mutex::new(HashMap::new()));
            tokio::spawn(Self::run_scheduler(
                vm.clone(),
                job_rx,
                ev_rx,
                Arc::clone(&sched_ctl),
                Arc::clone(&chunks),
            ));
            vms.push(Arc::new(VmSlot {
                job_tx,
                co_counter,
                vm,
                chunks,
                sched_ctl,
            }));
        }
        for (name, _) in &inits {
            println!("[onrouter] 已执行 {name}（x{n} VM）");
        }
        if let Some(path) = &applied_path {
            println!("[onrouter] lua_package_path 已应用（package.path）：{path}");
        }
        if !worker_inits.is_empty() {
            let names: Vec<&str> = worker_inits.iter().map(|(n, _)| n.as_str()).collect();
            println!(
                "[onrouter] init_worker 脚本待执行：{}（调度器就绪后每 VM 一次）",
                names.join(", ")
            );
        }
        println!(
            "[onrouter] Lua VM 池就绪：{n} 个实例（每核心一个，VM 内协程并发多条在途请求）"
        );
        Ok(LuaEngine {
            vms,
            counter: AtomicUsize::new(0),
            subreq_slot,
            worker_inits,
        })
    }

    /// 晚绑定 AppState：main 构造好 `Arc<AppState>` 后调用一次，把 Weak 句柄填进子请求槽。
    /// 之前 capture 调用会安全地返回 status=0（LuaEngine 不可能在 state 就绪前收到请求）。
    pub fn bind_app_state(&self, state: &Arc<crate::server::AppState>) {
        let _ = self.subreq_slot.set(Arc::downgrade(state));
    }

    /// 应用 lua_package_path：`$prefix`/`${prefix}` 展开为配置基准目录，
    /// `;;` 展开为 Lua 默认路径（与 OpenResty 一致：写了 `;;` 才保留默认搜索路径）。
    fn set_package_path(lua: &Lua, raw: &str, base_dir: &PathBuf) -> Result<String, AppError> {
        let package: LuaTable = lua.globals().get("package")?;
        let default: String = package.get("path")?;
        let expanded = expand_package_path(raw, &default, &base_dir.to_string_lossy());
        package.set("path", expanded.as_str())?;
        Ok(expanded)
    }

    /// 在每个 VM 上各执行一次 init_worker_by_lua*（对标 OpenResty 每个 worker 执行一次）。
    /// 必须等调度器任务启动后调用：脚本里的 ngx.sleep / cosocket / ngx.timer.at 依赖它。
    pub async fn run_init_workers(&self) -> Result<(), AppError> {
        for (name, src) in &self.worker_inits {
            let code = src.load()?;
            for (idx, slot) in self.vms.iter().enumerate() {
                Self::run_on_slot(
                    slot,
                    name,
                    Arc::clone(&code),
                    Arc::new(Mutex::new(RequestCtx::detached())),
                )
                .await
                .map_err(|e| {
                    AppError::Other(format!("{name} 在第 {} 个 VM 执行失败: {e}", idx + 1))
                })?;
            }
            println!(
                "[onrouter] 已执行 {name}（x{} VM，每 VM 一次）",
                self.vms.len()
            );
        }
        Ok(())
    }

    fn install_api(
        lua: &Lua,
        dicts: &SharedDicts,
        vm_ref: &Weak<VM>,
        timer_pending: &Arc<AtomicIsize>,
        timer_running: &Arc<AtomicIsize>,
        ev_tx: &mpsc::UnboundedSender<(u64, Vec<ResumeVal>)>,
        op_counter: &Arc<AtomicU64>,
        subreq_slot: &SubreqSlot,
        co_counter: &Arc<AtomicU64>,
        sched_ctl: &SharedCtl,
        job_tx: &mpsc::UnboundedSender<Job>,
    ) -> Result<(), AppError> {
        let get_ctx = |lua: &Lua| -> LuaResult<CtxHandle> {
            let ud: AnyUserData = lua.named_registry_value("__ctx")?;
            let h = ud.borrow::<CtxHandle>()?;
            Ok(h.clone())
        };

        let ngx = lua.create_table()?;

        // ngx.say(...) / ngx.print(...) —— 追加响应体（say 换行，print 不换）。
        // 多个参数之间不加分隔、按序直拼，与 OpenResty 一致（早期实现插了空格，
        // 同一句脚本会比 OpenResty 多出 n-1 个字节）。
        for (fname, newline) in [("say", true), ("print", false)] {
            let f = lua.create_function(move |lua, args: Variadic<LuaValue>| {
                let h = get_ctx(lua)?;
                let mut ctx = h.0.lock().unwrap();
                for v in args.iter() {
                    let text: Vec<u8> = match v {
                        LuaValue::String(s) => s.as_bytes().to_vec(),
                        LuaValue::Integer(n) => n.to_string().into_bytes(),
                        LuaValue::Number(n) => n.to_string().into_bytes(),
                        LuaValue::Boolean(b) => {
                            if *b { b"true".to_vec() } else { b"false".to_vec() }
                        }
                        LuaValue::Nil => b"nil".to_vec(),
                        other => format!("{other:?}").into_bytes(),
                    };
                    ctx.lua_output(&text);
                }
                if newline {
                    ctx.lua_output(b"\n");
                }
                Ok(())
            })?;
            ngx.set(fname, f)?;
        }

        // ngx.flush([wait]) —— 把已缓冲的响应体推给客户端。流式模式下立刻发头/发数据；
        // 缓冲模式（未启用流式，或处在 rewrite/access/log 等阶段）退化为 no-op，
        // 返回值恒为 1（OpenResty 的 wait 语义是等内核写出去，本实现队列化即返回）。
        let flush = lua.create_function(move |lua, _wait: Option<bool>| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if ctx.stream.is_some() {
                let _ = ctx.flush_stream();
            }
            Ok(1)
        })?;
        ngx.set("flush", flush)?;

        // ngx.send_headers() —— 立即发送响应头（流式模式下首帧 Head；缓冲模式退化为
        // 标记性 no-op，脚本结束时统一发送）。恒返回 1，对齐 OpenResty 的成功语义。
        let send_headers = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if ctx.stream.is_some() {
                let _ = ctx.flush_stream();
            }
            Ok(1)
        })?;
        ngx.set("send_headers", send_headers)?;

        // ngx.eof() —— 结束响应输出：之后的 ngx.print/say 全部丢弃，流式响应立即收尾。
        let eof = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().eof_stream();
            Ok(1)
        })?;
        ngx.set("eof", eof)?;

        // ngx.log(level, msg...) —— 映射到 error_log 分级日志
        let log = lua.create_function(|_lua, args: Variadic<LuaValue>| {
            if args.is_empty() {
                return Ok(());
            }
            // 第一个参数是级别（字符串或整数），其余是消息
            let (level, start_idx) = match &args[0] {
                LuaValue::String(s) => {
                    let lvl_str = s.to_string_lossy().to_lowercase();
                    let lvl = match lvl_str.as_str() {
                        "emerg" | "alert" | "crit" => crate::log::Level::Crit,
                        "error" => crate::log::Level::Error,
                        "warn" => crate::log::Level::Warn,
                        "notice" => crate::log::Level::Notice,
                        "info" => crate::log::Level::Info,
                        "debug" => crate::log::Level::Debug,
                        _ => crate::log::Level::Info, // 未知级别默认 info
                    };
                    (lvl, 1)
                }
                LuaValue::Integer(n) => {
                    // 数字级别：对齐 OpenResty ngx.STDERR/EMERG/.../DEBUG 常量取值
                    let lvl = match *n {
                        -1 => crate::log::Level::Debug, // STDERR：当作最详细级落盘
                        0..=2 => crate::log::Level::Crit, // EMERG/ALERT/CRIT
                        3 => crate::log::Level::Error,  // ERROR
                        4 => crate::log::Level::Warn,   // WARN
                        5 => crate::log::Level::Notice, // NOTICE
                        6 => crate::log::Level::Info,   // INFO
                        _ => crate::log::Level::Debug,  // DEBUG 及以上
                    };
                    (lvl, 1)
                }
                _ => (crate::log::Level::Info, 0), // 没有级别参数，从第一条开始
            };
            
            let msg = args[start_idx..]
                .iter()
                .map(|v| match v {
                    LuaValue::String(s) => s.to_string_lossy().to_string(),
                    LuaValue::Integer(n) => n.to_string(),
                    LuaValue::Number(n) => format!("{}", n),
                    LuaValue::Nil => "nil".to_string(),
                    LuaValue::Boolean(true) => "true".to_string(),
                    LuaValue::Boolean(false) => "false".to_string(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(" ");
            
            crate::log::with_log(level, msg);
            Ok(())
        })?;
        ngx.set("log", log)?;

        // ngx.exit(status) —— 结束请求。负数（如 ngx.ERROR）在 SSL 握手阶段表示中止握手。
        let exit = lua.create_function(move |lua, code: Option<i64>| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if let Some(c) = code {
                if c < 0 {
                    if let Some(ssl) = ctx.ssl.as_mut() {
                        ssl.aborted = true;
                    }
                } else if c <= u16::MAX as i64 {
                    ctx.status = c as u16;
                }
            }
            ctx.done = true;
            Ok(())
        })?;
        ngx.set("exit", exit)?;

        // ngx.redirect(uri, status?) —— 外部重定向（默认 302）
        let redirect = lua.create_function(move |lua, (uri, code): (String, Option<u16>)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.redirect = Some((code.unwrap_or(302), uri));
            ctx.done = true;
            Ok(())
        })?;
        ngx.set("redirect", redirect)?;

        // ngx.exec(uri) —— 内部重定向（跳转内部 location，客户端无感）
        let exec = lua.create_function(move |lua, uri: String| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.rewritten_path = Some(uri);
            ctx.internal_redirect = true;
            Ok(())
        })?;
        ngx.set("exec", exec)?;

        // ngx.sleep(secs) —— 让出当前请求协程，不阻塞 VM（单位与 OpenResty 对齐：秒，可带小数）：
        // _onrouter_sleep_start 用 tokio 定时器计时，把完成事件投回所属 VM 调度器并返回 sleep id；
        // Lua 侧随即 coroutine.yield(id) 挂起，调度器收到该 id 的事件后再 resume 本协程。
        {
            let ev_tx = ev_tx.clone();
            let counter = Arc::clone(op_counter);
            let sleep_start = lua.create_function(move |_lua, secs: f64| {
                let id = counter.fetch_add(1, Ordering::Relaxed);
                let ev_tx = ev_tx.clone();
                let dur = std::time::Duration::from_secs_f64(secs.max(0.0));
                tokio::spawn(async move {
                    tokio::time::sleep(dur).await;
                    let _ = ev_tx.send((id, Vec::new()));
                });
                Ok(id)
            })?;
            lua.globals().set("_onrouter_sleep_start", sleep_start)?;
        }
        let sleep_wrapper: LuaFunction = lua
            .load(
                r#"
                return function(ms)
                    if not (coroutine.isyieldable and coroutine.isyieldable()) then
                        error("ngx.sleep must run inside a coroutine (not usable in this context)", 0)
                    end
                    local id = _onrouter_sleep_start(ms)
                    return coroutine.yield(id)
                end
                "#,
            )
            .eval()?;
        ngx.set("sleep", sleep_wrapper)?;

        // ngx.timer —— 官方表 API：at / every / running_count / pending_count
        // 回调派发器：把 premature 作为首参、原样转发用户变参（对标 OpenResty 调用约定）
        let dispatch: LuaFunction = lua
            .load("return function(f, premature, args) return f(premature, table.unpack(args, 1, args.n or 0)) end")
            .eval()?;
        lua.set_named_registry_value("__timer_dispatch", dispatch)?;
        // 定时器回调必须作为纯 Lua 闭包进协程：Lua 5.4 不允许 yield 跨 C 调用边界，
        // 若在 Rust 帧里 call 用户回调，回调里的 ngx.sleep/cosocket 会直接报错。
        let make_runner: LuaFunction = lua
            .load(
                "return function(dispatch, cb, args) return function() return dispatch(cb, false, args) end end",
            )
            .eval()?;
        lua.set_named_registry_value("__timer_make_runner", make_runner)?;

        let timer = lua.create_table()?;

        // ngx.timer.at(delay_sec, callback, ...) -> ok, err
        // 语义对齐 lua-nginx-module t/106-timer.t：秒（可浮点）、premature 首参、
        // 变参转发、失败返回 (nil, err)、回调跑在调度器托管的协程里（可用 yield 类 API）
        {
            let vm_ref = vm_ref.clone();
            let pending = Arc::clone(timer_pending);
            let running = Arc::clone(timer_running);
            let co_counter = Arc::clone(co_counter);
            let job_tx = job_tx.clone();
            let timer_at = lua.create_function(move |lua_ctx, (delay, callback, args): (LuaValue, LuaValue, Variadic<LuaValue>)| {
                let delay_secs = match &delay {
                    LuaValue::Number(n) => *n as f64,
                    LuaValue::Integer(n) => *n as f64,
                    _ => return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid delay")?))),
                };
                if !delay_secs.is_finite() || delay_secs < 0.0 {
                    return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid delay")?)));
                }
                let cb = match callback {
                    LuaValue::Function(f) => f,
                    _ => return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid callback type")?))),
                };
                if pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_TIMERS {
                    pending.fetch_sub(1, Ordering::SeqCst);
                    return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("too many pending timers")?)));
                }
                // 用户变参在注册时冻结进表（跨 await/线程后无法再借用当前栈）
                let args_table = lua_ctx.create_table()?;
                let mut n = 0;
                for v in args {
                    n += 1;
                    args_table.raw_set(n, v)?;
                }
                args_table.raw_set("n", n)?;
                // 注册时绑定成无参 Lua 闭包，触发后由调度器建成协程 resume
                let runner_key = match Self::bind_timer_runner(lua_ctx, cb, args_table) {
                    Ok(k) => k,
                    Err(e) => {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        return Err(e);
                    }
                };
                let base_ctx = Self::timer_ctx_base(lua_ctx);

                let vm_ref = vm_ref.clone();
                let pending = Arc::clone(&pending);
                let running = Arc::clone(&running);
                let co_counter = Arc::clone(&co_counter);
                let job_tx = job_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs)).await;
                    let Some(vm) = vm_ref.upgrade() else {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        return;
                    };
                    pending.fetch_sub(1, Ordering::SeqCst);
                    if running.fetch_add(1, Ordering::SeqCst) >= MAX_RUNNING_TIMERS {
                        running.fetch_sub(1, Ordering::SeqCst);
                        eprintln!("[timer] too many running timers");
                        let guard = vm.lock().await;
                        let _ = guard.remove_registry_value(runner_key);
                        return;
                    }
                    // 回调协程与请求协程同权：ngx.sleep / cosocket / subrequest / ngx.thread.*
                    // 都走调度器的 yield-op 唤醒机制；__ctx 由调度器挂上游离 ctx。
                    let res = Self::dispatch_timer_job(
                        &vm,
                        &runner_key,
                        &base_ctx,
                        &co_counter,
                        &job_tx,
                    )
                    .await;
                    if let Err(e) = &res {
                        eprintln!("[timer] 回调执行失败: {e}");
                    }
                    let guard = vm.lock().await;
                    let _ = guard.remove_registry_value(runner_key);
                    drop(guard);
                    running.fetch_sub(1, Ordering::SeqCst);
                });
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?;
            timer.set("at", timer_at)?;
        }

        // ngx.timer.every(interval_sec, callback, ...) -> ok, err
        // 语义对齐 t/152-timer-every.t：interval<=0 报 invalid interval、
        // 回调显式返回 false 时停止（v0.10.6 行为）
        {
            let vm_ref = vm_ref.clone();
            let pending = Arc::clone(timer_pending);
            let running = Arc::clone(timer_running);
            let co_counter = Arc::clone(co_counter);
            let job_tx = job_tx.clone();
            let timer_every = lua.create_function(move |lua_ctx, (interval, callback, args): (LuaValue, LuaValue, Variadic<LuaValue>)| {
                let interval_secs = match &interval {
                    LuaValue::Number(n) => *n as f64,
                    LuaValue::Integer(n) => *n as f64,
                    _ => return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid interval")?))),
                };
                if !interval_secs.is_finite() || interval_secs <= 0.0 {
                    return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid interval")?)));
                }
                let cb = match callback {
                    LuaValue::Function(f) => f,
                    _ => return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid callback type")?))),
                };
                if pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_TIMERS {
                    pending.fetch_sub(1, Ordering::SeqCst);
                    return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("too many pending timers")?)));
                }
                let args_table = lua_ctx.create_table()?;
                let mut n = 0;
                for v in args {
                    n += 1;
                    args_table.raw_set(n, v)?;
                }
                args_table.raw_set("n", n)?;
                let runner_key = match Self::bind_timer_runner(lua_ctx, cb, args_table) {
                    Ok(k) => k,
                    Err(e) => {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        return Err(e);
                    }
                };
                let base_ctx = Self::timer_ctx_base(lua_ctx);

                let vm_ref = vm_ref.clone();
                let pending = Arc::clone(&pending);
                let running = Arc::clone(&running);
                let co_counter = Arc::clone(&co_counter);
                let job_tx = job_tx.clone();
                tokio::spawn(async move {
                    let duration = std::time::Duration::from_secs_f64(interval_secs);
                    loop {
                        tokio::time::sleep(duration).await;
                        let Some(vm) = vm_ref.upgrade() else {
                            pending.fetch_sub(1, Ordering::SeqCst);
                            break;
                        };
                        // 对标 TEST 4「开始运行时立刻登记下一发」：pending 保持 +1
                        pending.fetch_sub(1, Ordering::SeqCst);
                        if running.fetch_add(1, Ordering::SeqCst) >= MAX_RUNNING_TIMERS {
                            running.fetch_sub(1, Ordering::SeqCst);
                            eprintln!("[timer] too many running timers");
                            let guard = vm.lock().await;
                            let _ = guard.remove_registry_value(runner_key);
                            break;
                        }
                        let res = Self::dispatch_timer_job(
                        &vm,
                        &runner_key,
                        &base_ctx,
                        &co_counter,
                        &job_tx,
                    )
                    .await;
                        let stop = match res {
                            Err(e) => {
                                eprintln!("[timer] 周期回调执行失败: {e}");
                                true
                            }
                            // 回调显式 return false -> 终止周期定时器
                            Ok(true) => true,
                            Ok(false) => false,
                        };
                        running.fetch_sub(1, Ordering::SeqCst);
                        if stop {
                            let guard = vm.lock().await;
                            let _ = guard.remove_registry_value(runner_key);
                            break;
                        }
                        pending.fetch_add(1, Ordering::SeqCst);
                    }
                });
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?;
            timer.set("every", timer_every)?;
        }

        // ngx.timer.running_count() / pending_count()
        {
            let running = Arc::clone(timer_running);
            let pending = Arc::clone(timer_pending);
            timer.set("running_count", lua.create_function(move |_, ()| Ok(running.load(Ordering::SeqCst)))?)?;
            timer.set("pending_count", lua.create_function(move |_, ()| Ok(pending.load(Ordering::SeqCst)))?)?;
        }
        ngx.set("timer", timer)?;

        // ngx.time() / ngx.now()
        let time = lua.create_function(|_, ()| Ok(chrono::Utc::now().timestamp()))?;
        ngx.set("time", time)?;
        let now = lua.create_function(|_, ()| Ok(chrono::Utc::now().timestamp_millis() as f64 / 1000.0))?;
        ngx.set("now", now)?;

        // ngx.header —— 响应头（ngx.header["X"] = "v"；读请求头用 ngx.req）
        let header = lua.create_table()?;
        let header_set = lua.create_function(move |lua, (name, value): (String, Option<LuaValue>)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let key = name.to_lowercase();
            ctx.resp_headers.retain(|(k, _)| k.to_lowercase() != key);
            match value {
                Some(LuaValue::String(s)) => {
                    ctx.resp_headers.push((key, s.to_string_lossy().to_string()));
                }
                Some(LuaValue::Integer(n)) => ctx.resp_headers.push((key, n.to_string())),
                Some(LuaValue::Table(t)) => {
                    // 表值 = 同名多行（典型：多条 Set-Cookie）
                    for v in t.sequence_values::<LuaValue>() {
                        let v = v?;
                        let bs = lua_value_to_bytes(&v).unwrap_or_default();
                        ctx.resp_headers
                            .push((key.clone(), String::from_utf8_lossy(&bs).into_owned()));
                    }
                }
                _ => {} // nil = 删除
            }
            Ok(())
        })?;
        header.set("set", header_set)?;

        // ngx.header 元表：让 `ngx.header["X"] = v` / `local v = ngx.header["X"]` 直接读写
        // 响应头（对标 ngx_lua）——赋值路由进 ctx.resp_headers，读取按大小写不敏感回查。
        let header_mt = lua.create_table()?;
        let header_newindex = lua.create_function(move |lua, (_t, name, value): (LuaTable, String, LuaValue)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let key = name.to_lowercase();
            ctx.resp_headers.retain(|(k, _)| k.to_lowercase() != key);
            match value {
                LuaValue::String(s) => ctx.resp_headers.push((key, s.to_string_lossy().to_string())),
                LuaValue::Integer(n) => ctx.resp_headers.push((key, n.to_string())),
                LuaValue::Number(n) => ctx.resp_headers.push((key, n.to_string())),
                LuaValue::Boolean(b) => ctx.resp_headers.push((key, b.to_string())),
                LuaValue::Nil => {} // nil = 删除
                LuaValue::Table(t) => {
                    // 表值 = 同名多行（典型：多条 Set-Cookie）
                    for v in t.sequence_values::<LuaValue>() {
                        let bs = lua_value_to_bytes(&v?).unwrap_or_default();
                        ctx.resp_headers
                            .push((key.clone(), String::from_utf8_lossy(&bs).into_owned()));
                    }
                }
                other => {
                    let bs = lua_value_to_bytes(&other).unwrap_or_default();
                    ctx.resp_headers.push((key, String::from_utf8_lossy(&bs).into_owned()));
                }
            }
            Ok(())
        })?;
        let header_index = lua.create_function(move |lua, (_t, name): (LuaTable, String)| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let key = name.to_lowercase();
            let vals: Vec<&String> = ctx
                .resp_headers
                .iter()
                .filter(|(k, _)| k.to_lowercase() == key)
                .map(|(_, v)| v)
                .collect();
            match vals.len() {
                0 => Ok(LuaValue::Nil),
                1 => Ok(LuaValue::String(lua.create_string(vals[0].as_str())?)),
                // 多行同名头读取为表（OpenResty 语义）
                _ => {
                    let t = lua.create_table()?;
                    for (i, v) in vals.iter().enumerate() {
                        t.raw_set(i + 1, lua.create_string(v.as_str())?)?;
                    }
                    Ok(LuaValue::Table(t))
                }
            }
        })?;
        header_mt.set("__newindex", header_newindex)?;
        header_mt.set("__index", header_index)?;
        header.set_metatable(Some(header_mt));

        ngx.set("header", header)?;

        // ngx.arg —— body_filter_by_lua 参数访问（ngx.arg[1]=chunk, ngx.arg[2]=eof）
        let arg = lua.create_table()?;
        let arg_get = lua.create_function(move |lua, (_, idx): (LuaTable, usize)| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            match idx {
                1 => {
                    // 返回 chunk（Vec<u8> 转 Lua string）
                    if let Some(ref chunk) = ctx.filter_chunk {
                        Ok(LuaValue::String(lua.create_string(chunk)?))
                    } else {
                        Ok(LuaValue::Nil)
                    }
                }
                2 => {
                    // 返回 eof 标志
                    Ok(LuaValue::Boolean(ctx.filter_eof))
                }
                _ => Ok(LuaValue::Nil),
            }
        })?;
        let arg_set = lua.create_function(move |lua, (_, idx, value): (LuaTable, usize, LuaValue)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            match idx {
                1 => {
                    // 设置修改后的 chunk
                    match value {
                        LuaValue::String(s) => {
                            ctx.filter_chunk = Some(s.as_bytes().to_vec());
                        }
                        LuaValue::Nil => {
                            ctx.filter_chunk = None;
                        }
                        _ => {}
                    }
                }
                2 => {
                    // eof 只读，不允许修改
                    eprintln!("[lua] ngx.arg[2] (eof) is read-only");
                }
                _ => {}
            }
            Ok(())
        })?;
        let mt = lua.create_table()?;
        mt.set("__index", arg_get)?;
        mt.set("__newindex", arg_set)?;
        arg.set_metatable(Some(mt));
        ngx.set("arg", arg)?;

        // ngx.socket.tcp() —— 真·非阻塞 cosocket：底层 op 在 tokio 任务里跑，Lua 方法通过
        // coroutine.yield(op_id) 让出（不持 VM 锁），op 完成后调度器带结果 resume 协程。
        // Rust 侧只提供「不 yield 的启动原语」（Cosocket 的 _start_* / _close / _settimeout 方法），
        // 公开的 connect/send/receive 语义（含让出）用一小段 Lua 包在 metatable 上。
        let socket = lua.create_table()?;
        {
            let ev_tx = ev_tx.clone();
            let op_counter = Arc::clone(op_counter);
            let sock_new = lua.create_function(move |lua, ()| {
                let cs = Cosocket::new(ev_tx.clone(), Arc::clone(&op_counter));
                Ok(lua.create_userdata(cs)?)
            })?;
            lua.globals().set("_onrouter_sock_new", sock_new)?;
        }
        {
            let ev_tx = ev_tx.clone();
            let op_counter = Arc::clone(op_counter);
            let udp_new = lua.create_function(move |lua, ()| {
                let us = UdpCosocket::new(ev_tx.clone(), Arc::clone(&op_counter));
                Ok(lua.create_userdata(us)?)
            })?;
            lua.globals().set("_onrouter_udp_new", udp_new)?;
        }
        let cosocket_mod: LuaFunction = lua
            .load(
                r#"
                return function(socket_tbl)
                    local mt = { __index = {} }
                    local M = mt.__index
                    function M:connect(host, port)
                        self._host, self._port = host, port
                        local id = self._h:_start_connect(host, port)
                        return coroutine.yield(id)
                    end
                    function M:send(data)
                        local id = self._h:_start_send(data)
                        return coroutine.yield(id)
                    end
                    function M:receive(pattern)
                        local id = self._h:_start_receive(pattern)
                        return coroutine.yield(id)
                    end
                    function M:receiveany(min, max)
                        local id = self._h:_start_receiveany(min, max or 0)
                        return coroutine.yield(id)
                    end
                    function M:receiveuntil(delim)
                        local sock = self
                        local done = false
                        local function it()
                            if done then return nil end
                            local id = sock._h:_start_receive_until(delim)
                            local data, found = coroutine.yield(id)
                            if data == nil then
                                done = true
                                sock._h:_close()
                                return nil, found
                            end
                            done = true
                            sock._h:_close()
                            if found then return data end
                            return data, "closed"
                        end
                        return it
                    end
                    function M:close() return self._h:_close() end
                    function M:settimeout(ms) return self._h:_settimeout(ms) end
                    function M:setsize(n) return self._h:_setsize(n) end
                    function M:shutdown(read, write)
                        local id = self._h:_start_shutdown(read, write)
                        return coroutine.yield(id)
                    end
                    function M:setkeepalive(timeout, pool_size)
                        return self._h:_setkeepalive(timeout, pool_size)
                    end
                    function M:tlshandshake(opts)
                        opts = opts or {}
                        local id = self._h:_start_tlshandshake(opts.server_name, opts.verify, opts.ca)
                        return coroutine.yield(id)
                    end
                    -- 新版命名 sslhandshake 是 tlshandshake 的别名
                    M.sslhandshake = M.tlshandshake
                    function M:getreusedtimes() return self._h:_getreusedtimes() end
                    function M:reconnect()
                        if not self._host then return nil, "no peer" end
                        self:close()
                        local ok, err = self:connect(self._host, self._port)
                        return ok, err
                    end
                    function M:getstats() return { bytes_received = 0, bytes_sent = 0 } end
                    socket_tbl.tcp = function()
                        return setmetatable({ _h = _onrouter_sock_new() }, mt)
                    end
                    local umt = { __index = {} }
                    local U = umt.__index
                    function U:setpeername(host, port)
                        local id = self._h:_start_setpeername(host, port)
                        return coroutine.yield(id)
                    end
                    function U:send(data)
                        local id = self._h:_start_send(data)
                        return coroutine.yield(id)
                    end
                    function U:receive(max)
                        local id = self._h:_start_receive(max or 0)
                        return coroutine.yield(id)
                    end
                    function U:close() return self._h:_close() end
                    function U:settimeout(ms) return self._h:_settimeout(ms) end
                    socket_tbl.udp = function()
                        return setmetatable({ _h = _onrouter_udp_new() }, umt)
                    end
                    return true
                end
                "#,
            )
            .eval()?;
        cosocket_mod.call::<()>(socket.clone())?;
        ngx.set("socket", socket)?;

        // ngx.location.capture(uri, opts?) —— 内部子请求（对标 OpenResty）。
        // Rust 侧只提供「不 yield 的启动原语」_onrouter_capture_start：读父 ctx、spawn
        // 一个跑完整管线的 tokio 任务（经晚绑定的 AppState），把结果作为 SubReq 唤醒值投回
        // 调度器；Lua 侧 coroutine.yield(op_id) 让出（不持 VM 锁），恢复时拿到 {status,body,header} 表。
        {
            let ev_tx = ev_tx.clone();
            let counter = Arc::clone(op_counter);
            let slot = Arc::clone(subreq_slot);
            let capture_start = lua.create_function(move |lua, (uri, method, body): (String, String, Option<LuaString>)| {
                let h = get_ctx(lua)?;
                let parent = h.0.lock().unwrap().clone();
                let id = counter.fetch_add(1, Ordering::Relaxed);
                let ev = ev_tx.clone();
                let slot = Arc::clone(&slot);
                let body = body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
                tokio::spawn(async move {
                    let payload = match slot.get().and_then(|w| w.upgrade()) {
                        None => vec![ResumeVal::Nil, ResumeVal::Str("subrequests unavailable".into())],
                        Some(state) => {
                            match crate::server::run_capture(&state, &parent, &uri, &method, &body).await {
                                Ok(r) => vec![ResumeVal::SubReq {
                                    status: r.status,
                                    headers: r.headers,
                                    body: r.body,
                                }],
                                Err(e) => vec![ResumeVal::Nil, ResumeVal::Str(e)],
                            }
                        }
                    };
                    let _ = ev.send((id, payload));
                });
                Ok(id)
            })?;
            lua.globals().set("_onrouter_capture_start", capture_start)?;
        }
        let location_mod: LuaFunction = lua
            .load(
                r#"
                return function()
                    local function capture(uri, opts)
                        opts = opts or {}
                        local method = "GET"
                        if opts.method then method = tostring(opts.method) end
                        local target = uri
                        if opts.args ~= nil then
                            local args = opts.args
                            if type(args) == "table" then args = ngx.encode_args(args) end
                            args = tostring(args)
                            if args ~= "" then
                                local base = uri:match("^[^?]*") or uri
                                target = base .. "?" .. args
                            end
                        end
                        local body = opts.body
                        if body ~= nil then body = tostring(body) end
                        local res = coroutine.yield(_onrouter_capture_start(target, method, body))
                        if res == nil then
                            return { status = 0, body = nil, header = {} }
                        end
                        return res
                    end
                    -- capture_multi：每个子请求跑在独立 light thread 上，真正并发；
                    -- 返回值的顺序与输入一致（对标 OpenResty 的 capture_multi）。
                    local function capture_multi(specs)
                        local threads = {}
                        local results = {}
                        for i = 1, #specs do
                            local spec = specs[i]
                            local uri, opts
                            if type(spec) == "table" then
                                uri, opts = spec[1], spec[2]
                            else
                                uri = spec
                            end
                            if uri == nil then
                                results[i] = { status = 0, body = nil, header = {} }
                            else
                                threads[i] = ngx.thread.spawn(capture, uri, opts)
                            end
                        end
                        for i = 1, #specs do
                            if threads[i] then
                                local ok, res = ngx.thread.wait(threads[i])
                                if ok then
                                    results[i] = res
                                else
                                    results[i] = { status = 0, body = nil, header = {} }
                                end
                            end
                        end
                        return table.unpack(results, 1, #specs)
                    end
                    return { capture = capture, capture_multi = capture_multi }
                end
                "#,
            )
            .eval()?;
        let location_tbl: LuaTable = location_mod.call(())?;
        ngx.set("location", location_tbl)?;

        // ---------- ngx.thread.* —— 轻量级线程（light thread），同 VM 真并发 ----------
        // spawn/wait/yield/kill 与请求协程共用调度器：子协程是 states 里的一等协程，
        // 因此能和其它请求/子线程交错跑 cosocket/ngx.sleep；结果经 Lua 侧 `__thread_sink`
        // 表打包，由调度器在「线程完成 / wait 命中」时喂回等待方协程（对标 ngx_lua）。
        // 结果表 sink[tid] = table.pack(ok, ret...)，ok=false 时为 table.pack(false, err)。
        lua.globals().set("__thread_sink", lua.create_table()?)?;
        let define_body: LuaFunction = lua
            .load(
                r#"return function()
                    _G.__thread_body = function(func, args, tid)
                        return function()
                            local r = table.pack(pcall(func, table.unpack(args, 1, args.n)))
                            local sink = _G.__thread_sink
                            if r[1] then
                                sink[tid] = table.pack(true, table.unpack(r, 2, r.n))
                            else
                                sink[tid] = table.pack(false, r[2])
                            end
                        end
                    end
                end"#,
            )
            .eval()?;
        define_body.call::<()>(())?;

        // _onrouter_thread_spawn(func, packed_args) -> tid：建子协程 + 登记信箱。
        {
            let ctl = Arc::clone(sched_ctl);
            let counter = Arc::clone(co_counter);
            let spawn = lua.create_function(move |lua_ctx, (func, args): (LuaFunction, LuaTable)| {
                let owner = lua_ctx
                    .named_registry_value::<i64>("__cur_owner")
                    .map(|v| v as u64)
                    .unwrap_or(0);
                if owner == 0 {
                    return Err(mlua::Error::external(
                        "ngx.thread.spawn 只能在请求协程内调用（无所属请求）",
                    ));
                }
                let tid = counter.fetch_add(1, Ordering::Relaxed);
                let body: LuaFunction = lua_ctx
                    .globals()
                    .get::<LuaFunction>("__thread_body")?
                    .call((func, args, tid as i64))?;
                let co = lua_ctx.create_thread(body)?;
                let thread_key = lua_ctx.create_registry_value(co)?;
                ctl.lock().unwrap().spawns.push(SpawnReq {
                    tid,
                    owner,
                    thread_key,
                });
                Ok(tid as i64)
            })?;
            lua.globals().set("_onrouter_thread_spawn", spawn)?;
        }
        // _onrouter_thread_wait(tids) -> op：登记等待意图，返回让出用的 op id。
        {
            let ctl = Arc::clone(sched_ctl);
            let counter = Arc::clone(op_counter);
            let wait = lua.create_function(move |_lua, tids: LuaTable| {
                let mut v = Vec::new();
                let mut i = 1i64;
                loop {
                    match tids.raw_get::<i64>(i) {
                        Ok(n) => {
                            v.push(n as u64);
                            i += 1;
                        }
                        Err(_) => break,
                    }
                }
                if v.is_empty() {
                    return Err(mlua::Error::external("ngx.thread.wait 需要一个线程参数"));
                }
                let op = counter.fetch_add(1, Ordering::Relaxed);
                ctl.lock().unwrap().waits.push(WaitReq { op, tids: v });
                Ok(op as i64)
            })?;
            lua.globals().set("_onrouter_thread_wait", wait)?;
        }
        // _onrouter_thread_yield() -> 哨兵 op id：让出重排（不阻塞、不等待）。
        {
            let y = lua.create_function(|_lua, ()| Ok(THREAD_YIELD_MARK as i64))?;
            lua.globals().set("_onrouter_thread_yield", y)?;
        }
        // _onrouter_thread_kill(tid) -> true：请求杀子线程，由调度器在下一步回收。
        {
            let ctl = Arc::clone(sched_ctl);
            let kill = lua.create_function(move |_lua, tid: i64| {
                ctl.lock().unwrap().kills.push(tid as u64);
                Ok(true)
            })?;
            lua.globals().set("_onrouter_thread_kill", kill)?;
        }

        let thread_mod: LuaFunction = lua
            .load(
                r#"
                return function()
                    local t = {}
                    -- spawn：把用户函数与变参打包，交 Rust 建子协程并登记；返回线程对象。
                    function t.spawn(func, ...)
                        assert(type(func) == 'function', "bad spawn argument type")
                        local args = table.pack(...)
                        local tid = _onrouter_thread_spawn(func, args)
                        return { _thread_tid = tid }
                    end
                    -- wait：任一给定线程先完成即返回 ok, ret...；让出等调度器投递 sink。
                    function t.wait(...)
                        local ts = table.pack(...)
                        local tids = {}
                        for i = 1, ts.n do
                            local th = ts[i]
                            if type(th) ~= 'table' or not th._thread_tid then
                                return nil, "not a light thread object"
                            end
                            tids[i] = th._thread_tid
                        end
                        return coroutine.yield(_onrouter_thread_wait(tids))
                    end
                    -- yield：主动让出，让同 VM 的其它协程获得一次调度。
                    function t.yield()
                        return coroutine.yield(_onrouter_thread_yield())
                    end
                    -- kill：中止指定线程（已结束的线程为 no-op）。
                    function t.kill(thread)
                        if type(thread) ~= 'table' or not thread._thread_tid then
                            return nil, "not a light thread object"
                        end
                        _onrouter_thread_kill(thread._thread_tid)
                        return true
                    end
                    return t
                end
                "#,
            )
            .eval()?;
        let thread_tbl: LuaTable = thread_mod.call(())?;
        ngx.set("thread", thread_tbl)?;

        // ngx.on_abort(f) —— 登记中断回调。API 兼容：接受并暂存到本请求 ctx；
        // 实际「客户端断开」触发尚未接入服务器层连接存活探测（见 README roadmap）。
        {
            let on_abort = lua.create_function(move |lua_ctx, f: LuaValue| {
                if !matches!(f, LuaValue::Function(_)) {
                    return Ok((LuaValue::Nil, LuaValue::String(lua_ctx.create_string("invalid callback type")?)));
                }
                let ct = match lua_ctx.globals().get::<LuaTable>("ngx")?.raw_get("ctx")? {
                    LuaValue::Table(t) => t,
                    _ => lua_ctx.create_table()?,
                };
                ct.raw_set("__on_abort", f)?;
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?;
            ngx.set("on_abort", on_abort)?;
        }

        // ngx.req.* —— 请求信息
        let req = lua.create_table()?;
        for (fname, field) in [
            ("get_method", "method"),
            ("get_path", "path"),
            ("get_query", "query"),
        ] {
            let f = lua.create_function(move |lua, ()| {
                let h = get_ctx(lua)?;
                let ctx = h.0.lock().unwrap();
                let v = match field {
                    "method" => ctx.method.clone(),
                    "path" => ctx.effective_path().to_string(),
                    _ => ctx.query.clone(),
                };
                Ok(LuaValue::String(lua.create_string(v)?))
            })?;
            req.set(fname, f)?;
        }
        let get_headers = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let t = lua.create_table()?;
            for (k, v) in &ctx.req_headers {
                t.raw_set(k.as_str(), v.as_str())?;
            }
            Ok(LuaValue::Table(t))
        })?;
        req.set("get_headers", get_headers)?;

        // ngx.req.set_header(name, value) —— 改写入站请求头（转发时随 ctx.req_headers 带给后端）。
        //   value=nil 删除该头；value 为表则按序写多值（对齐 OpenResty）。name 归一化为小写。
        // ngx.req.set_raw_header 保留原始名；clear_header 删除。
        fn format_number(n: f64) -> String {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", n as i64)
            } else {
                n.to_string()
            }
        }

        fn hdr_to_str(lua: &mlua::Lua, v: &LuaValue) -> Option<String> {
            match v {
                LuaValue::Nil => None,
                LuaValue::String(s) => Some(String::from_utf8_lossy(&s.as_bytes()).into_owned()),
                LuaValue::Integer(n) => Some(n.to_string()),
                LuaValue::Number(n) => Some(format_number(*n)),
                LuaValue::Boolean(b) => Some((if *b { "true" } else { "false" }).to_string()),
                LuaValue::Table(t) => {
                    // 表值：取其数组部分，逐项转字符串
                    let mut out = String::new();
                    for i in 1..=t.raw_len() {
                        if let Ok(item) = t.raw_get::<LuaValue>(i) {
                            if let Some(s) = hdr_to_str(lua, &item) {
                                if !out.is_empty() {
                                    out.push(',');
                                }
                                out.push_str(&s);
                            }
                        }
                    }
                    Some(out)
                }
                _ => None,
            }
        }

        fn apply_header(
            ctx: &mut crate::engine::RequestCtx,
            name: &str,
            value: Option<String>,
            vals: Option<Vec<String>>,
        ) {
            ctx.req_headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            if let Some(list) = vals {
                for v in list {
                    ctx.req_headers.push((name.to_string(), v));
                }
            } else if let Some(v) = value {
                ctx.req_headers.push((name.to_string(), v));
            }
        }

        let set_header = lua.create_function(move |lua, (name, value): (String, LuaValue)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let name = name.to_lowercase();
            match &value {
                LuaValue::Nil => apply_header(&mut ctx, &name, None, None),
                LuaValue::Table(t) => {
                    let mut list = Vec::new();
                    for i in 1..=t.raw_len() {
                        if let Ok(item) = t.raw_get::<LuaValue>(i) {
                            if let Some(s) = hdr_to_str(lua, &item) {
                                list.push(s);
                            }
                        }
                    }
                    apply_header(&mut ctx, &name, None, Some(list));
                }
                other => {
                    if let Some(s) = hdr_to_str(lua, other) {
                        apply_header(&mut ctx, &name, Some(s), None);
                    }
                }
            }
            Ok(true)
        })?;
        req.set("set_header", set_header)?;

        let set_raw_header = lua.create_function(move |lua, (name, value): (String, LuaValue)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            match &value {
                LuaValue::Nil => apply_header(&mut ctx, &name, None, None),
                LuaValue::Table(t) => {
                    let mut list = Vec::new();
                    for i in 1..=t.raw_len() {
                        if let Ok(item) = t.raw_get::<LuaValue>(i) {
                            if let Some(s) = hdr_to_str(lua, &item) {
                                list.push(s);
                            }
                        }
                    }
                    apply_header(&mut ctx, &name, None, Some(list));
                }
                other => {
                    if let Some(s) = hdr_to_str(lua, other) {
                        apply_header(&mut ctx, &name, Some(s), None);
                    }
                }
            }
            Ok(true)
        })?;
        req.set("set_raw_header", set_raw_header)?;

        let clear_header = lua.create_function(move |lua, name: String| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.req_headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
            Ok(true)
        })?;
        req.set("clear_header", clear_header)?;

        // ngx.req.get_uri_args() —— 查询串解析为表
        let get_uri_args = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let query = h.0.lock().unwrap().query.clone();
            Ok(LuaValue::Table(push_args_table(lua, decode_args(&query))?))
        })?;
        req.set("get_uri_args", get_uri_args)?;

        // ngx.req.set_uri(path) —— 重写请求路径（不含 query）
        let set_uri = lua.create_function(move |lua, path: String| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().rewritten_path = Some(path);
            Ok(())
        })?;
        req.set("set_uri", set_uri)?;

        // ngx.req.set_uri_args(args) —— 覆盖 query（字符串或表）
        let set_uri_args = lua.create_function(move |lua, args: LuaValue| {
            let h = get_ctx(lua)?;
            let q = match args {
                LuaValue::String(s) => s.to_string_lossy().to_string(),
                LuaValue::Table(t) => {
                    let mut parts = Vec::new();
                    for pair in t.pairs::<LuaValue, LuaValue>() {
                        let (k, v) = pair?;
                        let key: String = match k {
                            LuaValue::String(s) => s.to_string_lossy().to_string(),
                            other => format!("{other:?}"),
                        };
                        match v {
                            LuaValue::Nil => parts.push(escape_uri(&key)),
                            LuaValue::Boolean(true) => parts.push(escape_uri(&key)),
                            other => {
                                let val: String = match other {
                                    LuaValue::String(s) => s.to_string_lossy().to_string(),
                                    LuaValue::Integer(n) => n.to_string(),
                                    LuaValue::Number(n) => n.to_string(),
                                    _ => format!("{other:?}"),
                                };
                                parts.push(format!("{}={}", escape_uri(&key), escape_uri(&val)));
                            }
                        }
                    }
                    parts.join("&")
                }
                _ => return Err(mlua::Error::external("set_uri_args: 参数必须是字符串或表")),
            };
            h.0.lock().unwrap().query = q;
            Ok(())
        })?;
        req.set("set_uri_args", set_uri_args)?;

        // ngx.req.get_body_data() —— 请求体（已由 server 层缓冲）
        let get_body = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            if ctx.req_body.is_empty() {
                Ok(LuaValue::Nil)
            } else {
                Ok(LuaValue::String(lua.create_string(&ctx.req_body)?))
            }
        })?;
        req.set("get_body_data", get_body)?;

        // ngx.req.read_body() —— 请求体已由服务层缓冲，保留为幂等兼容占位
        let read_body = lua.create_function(|_, ()| Ok(LuaValue::Nil))?;
        req.set("read_body", read_body)?;

        // ngx.req.socket([raw]) —— 请求体读取器。请求体已整体缓冲在 ctx.req_body，
        // 这里提供顺序读取视图（receive/receiveuntil/settimeout/close）；
        // 与上游流式转发（proxy_request_buffering off）互斥，那种场景下体不在内存。
        let req_socket = lua.create_function(move |lua, _raw: Option<bool>| {
            let cursor = Arc::new(Mutex::new(ReqSocketCursor::default()));
            let ud = lua.create_userdata(ReqSocket { cursor })?;
            Ok((LuaValue::UserData(ud), LuaValue::Nil))
        })?;
        req.set("socket", req_socket)?;
        // ngx.req.get_body_file() —— 本实现请求体常驻内存，恒返回 nil（对标 in-memory 情形）
        let get_body_file = lua.create_function(|_, ()| Ok(LuaValue::Nil))?;
        req.set("get_body_file", get_body_file)?;
        // ngx.req.set_body_data(data) —— 用新体覆盖请求体（供 rewrite/exec 后转发）
        let set_body_data = lua.create_function(move |lua, data: LuaString| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.req_body = Bytes::copy_from_slice(&data.as_bytes());
            let len = ctx.req_body.len();
            set_request_content_length(&mut ctx, len);
            Ok(LuaValue::Nil)
        })?;
        req.set("set_body_data", set_body_data)?;
        // ngx.req.discard_body() —— 丢弃请求体
        let discard_body = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.req_body = Bytes::new();
            ctx.body_builder = None;
            set_request_content_length(&mut ctx, 0);
            Ok(LuaValue::Nil)
        })?;
        req.set("discard_body", discard_body)?;
        // ngx.req.start_time() —— 请求到达时间（epoch 秒）
        let start_time = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let t = h.0.lock().unwrap().start_time;
            Ok(t)
        })?;
        req.set("start_time", start_time)?;
        // ngx.req.http_version() —— 1.0 / 1.1 / 2.0 / 3.0
        let http_version = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let v = h.0.lock().unwrap().http_version;
            Ok(v)
        })?;
        req.set("http_version", http_version)?;
        // ngx.req.is_internal() —— 是否内部请求（ngx.exec / capture 产物）
        let is_internal = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let v = h.0.lock().unwrap().internal_request;
            Ok(v)
        })?;
        req.set("is_internal", is_internal)?;
        // ngx.req.init_body / append_body / finish_body —— 构造请求体（对标 ngx_lua）
        let init_body = lua.create_function(move |lua, size: Option<usize>| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().body_builder = Some(Vec::with_capacity(size.unwrap_or(0)));
            Ok(LuaValue::Nil)
        })?;
        req.set("init_body", init_body)?;
        let append_body = lua.create_function(move |lua, data: LuaString| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            match ctx.body_builder.as_mut() {
                Some(buf) => {
                    buf.extend_from_slice(&data.as_bytes());
                    Ok((LuaValue::Nil, LuaValue::Nil))
                }
                None => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("request body not initialized")?),
                )),
            }
        })?;
        req.set("append_body", append_body)?;
        let finish_body = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if let Some(buf) = ctx.body_builder.take() {
                let len = buf.len();
                ctx.req_body = Bytes::from(buf);
                set_request_content_length(&mut ctx, len);
            }
            Ok(LuaValue::Nil)
        })?;
        req.set("finish_body", finish_body)?;
        // ngx.req.set_method(method)
        let set_method = lua.create_function(move |lua, m: String| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().method = m;
            Ok(LuaValue::Nil)
        })?;
        req.set("set_method", set_method)?;
        // ngx.req.get_post_args() —— application/x-www-form-urlencoded 请求体解析为表
        let get_post_args = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let body = h.0.lock().unwrap().req_body.clone();
            let q = String::from_utf8_lossy(&body).into_owned();
            Ok(LuaValue::Table(push_args_table(lua, decode_args(&q))?))
        })?;
        req.set("get_post_args", get_post_args)?;
        // ngx.req.raw_header([full]) —— 重建请求首部文本；full=true 追加空行与请求体
        let raw_header = lua.create_function(move |lua, full: Option<bool>| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let mut s = format!("{} {} HTTP/1.1\r\n", ctx.method, ctx.uri);
            for (k, v) in &ctx.req_headers {
                s.push_str(&format!("{k}: {v}\r\n"));
            }
            s.push_str("\r\n");
            if full.unwrap_or(false) {
                if let Ok(bs) = lua.create_string(&ctx.req_body[..]) {
                    s.push_str(&bs.to_string_lossy());
                }
            }
            Ok(LuaValue::String(lua.create_string(s)?))
        })?;
        req.set("raw_header", raw_header)?;

        ngx.set("req", req)?;

        // ngx.resp.get_headers() —— 响应头表
        let resp = lua.create_table()?;
        let resp_headers = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let t = lua.create_table()?;
            for (k, v) in &ctx.resp_headers {
                t.raw_set(k.as_str(), v.as_str())?;
            }
            Ok(LuaValue::Table(t))
        })?;
        resp.set("get_headers", resp_headers)?;
        ngx.set("resp", resp)?;

        // ngx.re.* —— 正则（桥接 Rust regex crate；对标 PCRE 的常用子集）
        let re = lua.create_table()?;

        fn build_regex(pattern: &str, flags: Option<String>) -> LuaResult<regex::Regex> {
            let mut builder = regex::RegexBuilder::new(pattern);
            if let Some(f) = flags {
                // 对齐 PCRE/OpenResty 常用标志：i 忽略大小写、s 单行(. 匹配换行)、m 多行(^$ 逐行)
                if f.contains('i') {
                    builder.case_insensitive(true);
                }
                if f.contains('s') {
                    builder.dot_matches_new_line(true);
                }
                if f.contains('m') {
                    builder.multi_line(true);
                }
            }
            builder.build().map_err(mlua::Error::external)
        }

        // 把一次 captures 结果转成 OpenResty 的 cap 表：cap[0]=整体、cap[N]=第 N 组、cap.name=命名组
        fn caps_to_table(lua: &mlua::Lua, re: &regex::Regex, caps: &regex::Captures) -> LuaResult<LuaTable> {
            let t = lua.create_table()?;
            for i in 0..caps.len() {
                if let Some(m) = caps.get(i) {
                    t.raw_set(i as i64, m.as_str())?;
                }
            }
            for (i, name) in re.capture_names().enumerate() {
                if i == 0 {
                    continue;
                }
                if let Some(nm) = name {
                    if let Some(m) = caps.get(i) {
                        t.raw_set(nm, m.as_str())?;
                    }
                }
            }
            Ok(t)
        }

        // 解析正则入参：字符串 pattern（配合 options 标志）或 opt() 预编译句柄。
        // Pattern 只借用 Lua 字符串，命中编译缓存时不再为模式分配 String。
        enum ReArg {
            Pattern(LuaString),
            Cached(usize),
            /// 非字符串/句柄入参：沿用旧行为，按空模式处理
            Empty,
        }
        fn parse_re_arg(v: &LuaValue) -> ReArg {
            match v {
                LuaValue::String(s) => ReArg::Pattern(s.clone()),
                LuaValue::Table(t) => {
                    if let Ok(idx) = t.raw_get::<i64>("__orr_re") {
                        ReArg::Cached(idx as usize)
                    } else {
                        ReArg::Empty
                    }
                }
                _ => ReArg::Empty,
            }
        }
        fn build_from_arg(arg: ReArg, options: Option<String>) -> LuaResult<regex::Regex> {
            match arg {
                ReArg::Cached(i) => regex_from_cache(i),
                ReArg::Pattern(p) => build_regex_cached(&p.to_string_lossy(), options.as_deref()),
                ReArg::Empty => build_regex_cached("", options.as_deref()),
            }
        }

        // ngx.re.match(s, pattern, flags?) -> {cap1, cap2, ...} | nil
        let re_match = lua.create_function(move |lua, (s, pattern, flags): (String, String, Option<String>)| {
            let re = build_regex_cached(&pattern, flags.as_deref())?;
            let Some(caps) = re.captures(&s) else {
                return Ok(LuaValue::Nil);
            };
            let t = lua.create_table()?;
            // 对齐 OpenResty：cap[0] 是整体匹配，捕获组从 1 开始
            for i in 0..caps.len() {
                if let Some(m) = caps.get(i) {
                    t.raw_set(i as i64, m.as_str())?;
                }
            }
            Ok(LuaValue::Table(t))
        })?;
        re.set("match", re_match)?;

        // ngx.re.find(s, pattern, flags?) -> from, to（1-based；无匹配返回 nil）
        let re_find = lua.create_function(move |_, (s, pattern, flags): (String, String, Option<String>)| {
            let re = build_regex_cached(&pattern, flags.as_deref())?;
            match re.find(&s) {
                Some(m) => Ok((Some(m.start() as i64 + 1), Some(m.end() as i64))),
                None => Ok((None, None)),
            }
        })?;
        re.set("find", re_find)?;

        // ngx.re.opt(regex, options?) -> 预编译句柄（表 {__orr_re=idx}），可回传给其它 ngx.re.*
        let re_opt = lua.create_function(move |lua, (pattern, options): (String, Option<String>)| {
            let built = build_regex(&pattern, options)?;
            let idx = regex_to_cache(built);
            let t = lua.create_table()?;
            t.raw_set("__orr_re", idx as i64)?;
            Ok(LuaValue::Table(t))
        })?;
        re.set("opt", re_opt)?;

        // ngx.re.gmatch(subject, regex, options?) -> iterator；每次调用返回一个 cap 表，耗尽返回 nil
        let re_gmatch = lua.create_function(move |lua, (subject, regex_arg, options): (String, LuaValue, Option<String>)| {
            let built = build_from_arg(parse_re_arg(&regex_arg), options)?;
            let state = std::sync::Arc::new(std::sync::Mutex::new((built, subject, 0usize)));
            let it = lua.create_function(move |lua, ()| {
                let mut st = state.lock().unwrap();
                let (re, subj, pos) = &mut *st;
                let tail = &subj[*pos..];
                match re.captures(tail) {
                    Some(caps) => {
                        let m = caps.get(0).unwrap();
                        let adv = m.end();
                        *pos += adv;
                        if adv == 0 {
                            // 零宽匹配：前进一格避免在同一位置死循环
                            *pos = (*pos + 1).min(subj.len());
                        }
                        let t = caps_to_table(lua, re, &caps)?;
                        drop(st);
                        Ok(LuaValue::Table(t))
                    }
                    None => Ok(LuaValue::Nil),
                }
            })?;
            Ok(LuaValue::Function(it))
        })?;
        re.set("gmatch", re_gmatch)?;

        // sub/gsub 共用：all=false 只替换首个；replace 可为字符串或回调函数
        fn repl_to_str(v: &LuaValue) -> String {
            match v {
                LuaValue::String(s) => String::from_utf8_lossy(&s.as_bytes()).into_owned(),
                LuaValue::Integer(n) => n.to_string(),
                LuaValue::Number(n) => {
                    if n.fract() == 0.0 && n.abs() < 1e15 {
                        format!("{}", *n as i64)
                    } else {
                        n.to_string()
                    }
                }
                LuaValue::Nil => String::new(),
                _ => String::new(),
            }
        }
        fn do_sub(
            lua: &mlua::Lua,
            subject: &str,
            regex_arg: &LuaValue,
            replace: &LuaValue,
            options: Option<String>,
            all: bool,
        ) -> LuaResult<(String, i64)> {
            let re = build_from_arg(parse_re_arg(regex_arg), options)?;
            match replace {
                LuaValue::Function(f) => {
                    let mut out = String::new();
                    let mut last = 0usize;
                    let mut count: i64 = 0;
                    for caps in re.captures_iter(subject) {
                        let m = caps.get(0).unwrap();
                        out.push_str(&subject[last..m.start()]);
                        let t = caps_to_table(lua, &re, &caps)?;
                        let r: LuaValue = f.call(t)?;
                        out.push_str(&repl_to_str(&r));
                        last = m.end();
                        count += 1;
                        if !all {
                            break;
                        }
                    }
                    out.push_str(&subject[last..]);
                    Ok((out, count))
                }
                other => {
                    let rep = repl_to_str(other);
                    let n = re.find_iter(subject).count();
                    let limit = if all { usize::MAX } else { 1 };
                    let new = re.replacen(subject, limit, rep.as_str()).into_owned();
                    let cnt = if all { n as i64 } else { if n > 0 { 1 } else { 0 } };
                    Ok((new, cnt))
                }
            }
        }

        // ngx.re.sub(subject, regex, replace, options?) -> new_subject, n
        let re_sub = lua.create_function(move |lua, (subject, regex_arg, replace, options): (String, LuaValue, LuaValue, Option<String>)| {
            let (s, n) = do_sub(lua, &subject, &regex_arg, &replace, options, false)?;
            Ok((s, n))
        })?;
        re.set("sub", re_sub)?;

        // ngx.re.gsub(subject, regex, replace, options?) -> new_subject, n
        let re_gsub = lua.create_function(move |lua, (subject, regex_arg, replace, options): (String, LuaValue, LuaValue, Option<String>)| {
            let (s, n) = do_sub(lua, &subject, &regex_arg, &replace, options, true)?;
            Ok((s, n))
        })?;
        re.set("gsub", re_gsub)?;
        ngx.set("re", re)?;

        // ngx.shared.DICT —— lua_shared_dict 声明的共享区
        let shared = lua.create_table()?;
        for (name, zone) in &dicts.zones {
            shared.raw_set(name.as_str(), zone.clone())?;
        }
        ngx.set("shared", shared)?;

        // ngx.encode_base64 / decode_base64
        let b64e = lua.create_function(|lua, s: LuaString| {
            let bytes = s.as_bytes().to_vec();
            let encoded = b64_encode(&bytes);
            Ok(LuaValue::String(lua.create_string(encoded)?))
        })?;
        ngx.set("encode_base64", b64e)?;
        let b64d = lua.create_function(|lua, s: LuaString| {
            match b64_decode(&s.to_string_lossy()) {
                Some(b) => Ok(LuaValue::String(lua.create_string(&b)?)),
                None => Err(mlua::Error::external("decode_base64: 非法输入")),
            }
        })?;
        ngx.set("decode_base64", b64d)?;

        // ngx.escape_uri / unescape_uri
        let eu = lua.create_function(|_, s: LuaString| Ok(escape_uri(&s.to_string_lossy())))?;
        ngx.set("escape_uri", eu)?;
        let uu = lua.create_function(|_, s: LuaString| Ok(unescape_uri(&s.to_string_lossy())))?;
        ngx.set("unescape_uri", uu)?;

        // ngx.decode_args / encode_args
        let da = lua.create_function(move |lua, s: LuaString| {
            let q = s.to_string_lossy().to_string();
            Ok(LuaValue::Table(push_args_table(lua, decode_args(&q))?))
        })?;
        ngx.set("decode_args", da)?;
        let ea = lua.create_function(|_, t: LuaTable| {
            let mut parts = Vec::new();
            for pair in t.pairs::<LuaValue, LuaValue>() {
                let (k, v) = pair?;
                let key: String = match k {
                    LuaValue::String(s) => s.to_string_lossy().to_string(),
                    other => format!("{other:?}"),
                };
                match v {
                    LuaValue::Nil => parts.push(escape_uri(&key)),
                    LuaValue::Boolean(true) => parts.push(escape_uri(&key)),
                    other => {
                        let val: String = match other {
                            LuaValue::String(s) => s.to_string_lossy().to_string(),
                            LuaValue::Integer(n) => n.to_string(),
                            LuaValue::Number(n) => n.to_string(),
                            _ => continue,
                        };
                        parts.push(format!("{}={}", escape_uri(&key), escape_uri(&val)));
                    }
                }
            }
            Ok(parts.join("&"))
        })?;
        ngx.set("encode_args", ea)?;

        // ---------- ngx.* 摘要 / CRC / 时间 ----------
        // ngx.md5(str[, binary]) —— 默认十六进制小写；第二参 true 返回原始 16 字节
        let md5 = lua.create_function(|lua, (s, bin): (LuaString, Option<bool>)| {
            let bytes = s.as_bytes().to_vec();
            if bin.unwrap_or(false) {
                Ok(LuaValue::String(lua.create_string(md5_bin(&bytes))?))
            } else {
                Ok(LuaValue::String(lua.create_string(md5_hex(&bytes))?))
            }
        })?;
        ngx.set("md5", md5)?;
        let md5_bin_f = lua.create_function(|lua, s: LuaString| {
            let bytes = s.as_bytes().to_vec();
            Ok(LuaValue::String(lua.create_string(md5_bin(&bytes))?))
        })?;
        ngx.set("md5_bin", md5_bin_f)?;
        // ngx.sha1_bin(str[, hex]) —— 默认原始 20 字节；第二参 true 返回十六进制
        let sha1_bin_f = lua.create_function(|lua, (s, hex): (LuaString, Option<bool>)| {
            let raw = sha1_bin(&s.as_bytes().to_vec());
            if hex.unwrap_or(false) {
                Ok(LuaValue::String(lua.create_string(hex_lower(&raw))?))
            } else {
                Ok(LuaValue::String(lua.create_string(raw)?))
            }
        })?;
        ngx.set("sha1_bin", sha1_bin_f)?;
        // ngx.sha256_bin(str[, hex]) —— 默认原始 32 字节；第二参 true 返回十六进制
        let sha256_bin_f = lua.create_function(|lua, (s, hex): (LuaString, Option<bool>)| {
            let raw = sha256_bin(&s.as_bytes().to_vec());
            if hex.unwrap_or(false) {
                Ok(LuaValue::String(lua.create_string(hex_lower(&raw))?))
            } else {
                Ok(LuaValue::String(lua.create_string(raw)?))
            }
        })?;
        ngx.set("sha256_bin", sha256_bin_f)?;
        // ngx.hmac_sha1(secret, str) —— 原始 20 字节 HMAC-SHA1（OpenResty 语义）
        let hmac = lua.create_function(|lua, (key, data): (LuaString, LuaString)| {
            let mac = hmac_sha1(&key.as_bytes().to_vec(), &data.as_bytes().to_vec());
            Ok(LuaValue::String(lua.create_string(mac)?))
        })?;
        ngx.set("hmac_sha1", hmac)?;
        // ngx.crc32_short / crc32_long —— 同一 CRC32（历史命名，结果一致），无符号整数
        let crc = lua.create_function(|_, s: LuaString| Ok(crc32(&s.as_bytes().to_vec()) as i64))?;
        ngx.set("crc32_short", crc.clone())?;
        ngx.set("crc32_long", crc)?;
        // ngx.cookie_time(ts) / ngx.http_time(ts)
        let ctime = lua.create_function(|_, ts: i64| Ok(cookie_time(ts)))?;
        ngx.set("cookie_time", ctime)?;
        let htime = lua.create_function(|_, ts: i64| Ok(http_time(ts)))?;
        ngx.set("http_time", htime)?;
        // ngx.parse_http_time(str) —— 成功返回 unix 秒，失败返回 nil
        let ptime = lua.create_function(|_, s: LuaString| {
            Ok(match parse_http_time(&s.to_string_lossy()) {
                Some(ts) => LuaValue::Integer(ts),
                None => LuaValue::Nil,
            })
        })?;
        ngx.set("parse_http_time", ptime)?;
        // ngx.today() —— "YYYY-MM-DD"（本地日，UTC 对齐 nginx 语义）
        let today = lua.create_function(|_, ()| {
            Ok(chrono::Utc::now().format("%Y-%m-%d").to_string())
        })?;
        ngx.set("today", today)?;
        // ngx.update_time() —— 刷新缓存时间。本实现每次实时取钟，故为无副作用的兼容占位。
        let update_time = lua.create_function(|_, ()| Ok(LuaValue::Nil))?;
        ngx.set("update_time", update_time)?;
        // ngx.get_phase() —— 返回当前阶段名（rewrite/access/content/header_filter/body_filter/log…）
        let get_phase = lua.create_function(|lua, ()| {
            match lua.named_registry_value::<String>("__phase") {
                Ok(p) => Ok(LuaValue::String(lua.create_string(p)?)),
                Err(_) => Ok(LuaValue::Nil),
            }
        })?;
        ngx.set("get_phase", get_phase)?;

        // ngx.worker.* —— 单进程反应器：pid 真实，worker id 恒 0，count 恒 1；
        // exiting() 由进程信号处理器置位，pids() 只含当前进程。
        let worker = lua.create_table()?;
        worker.set("pid", lua.create_function(|_, ()| Ok(std::process::id() as i64))?)?;
        worker.set("id", lua.create_function(|_, ()| Ok(0i64))?)?;
        worker.set("count", lua.create_function(|_, ()| Ok(1i64))?)?;
        worker.set(
            "exiting",
            lua.create_function(|_, ()| Ok(worker_exiting()))?,
        )?;
        worker.set(
            "pids",
            lua.create_function(|lua, ()| {
                let t = lua.create_table()?;
                t.raw_set(1, std::process::id() as i64)?;
                Ok(t)
            })?,
        )?;
        ngx.set("worker", worker)?;

        // ngx.config —— 版本信息（服务器品牌：ONRouter）
        let config_tbl = lua.create_table()?;
        config_tbl.set("server", "ONRouter")?;
        config_tbl.set("server_version", env!("CARGO_PKG_VERSION"))?;
        config_tbl.set("nginx_version", "1.27.0-compatible")?;
        config_tbl.set("ngx_lua_version", "0.10.28-compatible")?;
        config_tbl.set("onrouter_version", env!("CARGO_PKG_VERSION"))?;
        config_tbl.set("subsystem", "http")?;
        config_tbl.set("no_debug", true)?;
        // ngx.config.prefix() —— 返回工作目录（对标 nginx `-p` 前缀）
        config_tbl.set(
            "prefix",
            lua.create_function(|_, ()| {
                Ok(std::env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "./".to_string()))
            })?,
        )?;
        ngx.set("config", config_tbl)?;

        // ngx.status —— 通过 metatable 支持读写：ngx.status = 201 / 读取 ngx.status
        let status_get = lua.create_function(move |_lua, ()| {
            let h = get_ctx(_lua)?;
            let v = h.0.lock().unwrap().status as i64;
            Ok(LuaValue::Integer(v))
        })?;
        let status_set = lua.create_function(move |lua, code: u16| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().status = code;
            Ok(())
        })?;
        ngx.set("_get_status", status_get)?;
        ngx.set("_set_status", status_set)?;
        let mt = lua.create_table()?;
        let idx = lua.create_function(move |_lua, (t, key): (LuaTable, String)| {
            match key.as_str() {
                "status" => {
                    let f: LuaFunction = t.raw_get("_get_status")?;
                    f.call(())
                }
                "is_subrequest" => {
                    // 子请求（ngx.location.capture）派生：capture_depth>0 或内部请求标志
                    let ud: AnyUserData = _lua.named_registry_value("__ctx")?;
                    let h = ud.borrow::<CtxHandle>()?;
                    let ctx = h.0.lock().unwrap();
                    Ok(LuaValue::Boolean(ctx.capture_depth > 0))
                }
                "headers_sent" => {
                    let ud: AnyUserData = _lua.named_registry_value("__ctx")?;
                    let h = ud.borrow::<CtxHandle>()?;
                    let sent = h.0.lock().unwrap().headers_sent();
                    Ok(LuaValue::Boolean(sent))
                }
                _ => Ok(LuaValue::Nil),
            }
        })?;
        let newidx = lua.create_function(move |_lua, (t, key, value): (LuaTable, String, LuaValue)| {
            if key == "status" {
                let code = value.as_integer().unwrap_or(200) as u16;
                let f: LuaFunction = t.raw_get("_set_status")?;
                f.call::<()>(code)?;
            } else {
                t.raw_set(key, value)?;
            }
            Ok(())
        })?;
        mt.set("__index", idx)?;
        mt.set("__newindex", newidx)?;
        ngx.set_metatable(Some(mt));

        // ngx.ctx —— 每请求共享表
        let ctx_new = lua.create_function(|lua, ()| Ok(LuaValue::Table(lua.create_table()?)))?;
        ngx.set("ctx", ctx_new)?;

        ngx.raw_set("version", env!("CARGO_PKG_VERSION"))?;

        // ngx.balancer —— balancer_by_lua 阶段用于 Lua 选定上游节点（对齐 OpenResty 的 ngx.balancer）。
        // 成功返回 true，失败返回 (nil, err)。set_current_peer 选定的节点会绕开 upstream 负载均衡直连。
        let balancer = lua.create_table()?;
        // balancer.set_current_peer(host, port)
        balancer.set(
            "set_current_peer",
            lua.create_function(move |lua, (host, port): (String, u16)| {
                if host.is_empty() {
                    return Ok((LuaValue::Nil, LuaValue::String(lua.create_string("invalid 'host'")?)));
                }
                let h = get_ctx(lua)?;
                h.0.lock().unwrap().balancer_peer = Some((host, port));
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?,
        )?;
        // balancer.get_current_peer() -> host, port（未设置时返回 nil）
        balancer.set(
            "get_current_peer",
            lua.create_function(move |lua, ()| {
                let h = get_ctx(lua)?;
                let peer = h.0.lock().unwrap().balancer_peer.clone();
                match peer {
                    Some((host, port)) => Ok((
                        LuaValue::String(lua.create_string(&host)?),
                        LuaValue::Integer(port as i64),
                    )),
                    None => Ok((LuaValue::Nil, LuaValue::Nil)),
                }
            })?,
        )?;
        // balancer.set_timeouts(connect_ms, send_ms, read_ms)
        balancer.set(
            "set_timeouts",
            lua.create_function(move |lua, (connect, send, read): (i64, i64, i64)| {
                if connect < 0 || send < 0 || read < 0 {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("timeout should be a valid number")?),
                    ));
                }
                let h = get_ctx(lua)?;
                h.0.lock().unwrap().balancer_timeouts =
                    Some((connect as u64, send as u64, read as u64));
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?,
        )?;
        // balancer.set_more_failures({failures=?, return_code=?, escalate=?})
        balancer.set(
            "set_more_failures",
            lua.create_function(move |lua, opts: LuaTable| {
                let failures: i64 = opts.raw_get("failures").unwrap_or(0);
                let return_code: i64 = opts.raw_get("return_code").unwrap_or(-1);
                let escalate: bool = opts.raw_get("escalate").unwrap_or(false);
                if failures < 1 {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("invalid 'failures' field")?),
                    ));
                }
                if return_code < 0 {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("invalid 'return_code' field")?),
                    ));
                }
                let h = get_ctx(lua)?;
                h.0.lock().unwrap().balancer_more_failures =
                    Some((failures as u32, return_code as u32, escalate));
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?,
        )?;
        // balancer.recreate_request([boolean]) —— 默认 true；本次转发是否重建发往后端的请求
        balancer.set(
            "recreate_request",
            lua.create_function(move |lua, flag: Option<bool>| {
                let h = get_ctx(lua)?;
                h.0.lock().unwrap().balancer_recreate_request = flag.unwrap_or(true);
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            })?,
        )?;
        ngx.set("balancer", balancer)?;

        // ngx.var —— nginx 变量的 Lua 只读访问（OpenResty ngx.var 表）。全部以字符串返回，
        // 未定义的变量返回 nil（对齐 ngx_lua）。$uri / $args / $status 可写。
        // 读取统一走 engine::resolve_variable：内置变量表 + 由 `map` 指令派生的自定义变量。
        let var = lua.create_table()?;
        let var_mt = lua.create_table()?;
        let var_index = lua.create_function(move |lua, (_t, name): (LuaTable, String)| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let val: Option<String> = crate::engine::resolve_variable(&ctx, &name);
            Ok(match val {
                Some(v) => LuaValue::String(lua.create_string(v)?),
                None => LuaValue::Nil,
            })
        })?;
        let var_newindex = lua.create_function(move |lua, (_t, (name, value)): (LuaTable, (String, LuaValue))| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            // LuaString → owned String（避免 BorrowedStr 生命周期问题）
            let as_str = |v: &LuaValue| -> Option<String> {
                match v {
                    LuaValue::String(s) => Some(String::from_utf8_lossy(&s.as_bytes()).into_owned()),
                    _ => None,
                }
            };
            match name.as_str() {
                "uri" => {
                    if let Some(p) = as_str(&value) {
                        ctx.rewritten_path = Some(if p.starts_with('/') { p } else { format!("/{p}") });
                    }
                }
                "args" => {
                    match &value {
                        LuaValue::Nil => ctx.query = String::new(),
                        _ => {
                            if let Some(q) = as_str(&value) {
                                ctx.query = q;
                            }
                        }
                    }
                }
                "status" => {
                    if let Some(n) = value.as_integer() {
                        ctx.status = n as u16;
                    } else if let Some(s) = as_str(&value) {
                        if let Ok(n) = s.parse::<u16>() {
                            ctx.status = n;
                        }
                    }
                }
                // 其它 nginx 变量在本实现里只读；对齐"不可写变量被忽略"的最保守语义
                _ => {}
            }
            Ok(())
        })?;
        var_mt.set("__index", var_index)?;
        var_mt.set("__newindex", var_newindex)?;
        var.set_metatable(Some(var_mt));
        ngx.set("var", var)?;

        // ngx.* 常量 —— 日志级别（OpenResty 取值）+ 控制值 + 常用 HTTP 状态码
        for (name, val) in [
            ("STDERR", -1i64), ("EMERG", 0), ("ALERT", 1), ("CRIT", 2), ("ERR", 3),
            ("WARN", 4), ("NOTICE", 5), ("INFO", 6), ("DEBUG", 7),
            ("OK", 0i64), ("ERROR", -1i64),
        ] {
            ngx.raw_set(name, val)?;
        }
        for (name, code) in [
            ("HTTP_OK", 200u16), ("HTTP_CREATED", 201), ("HTTP_ACCEPTED", 202),
            ("HTTP_NO_CONTENT", 204), ("HTTP_MOVED_PERMANENTLY", 301), ("HTTP_MOVED_TEMPORARILY", 302),
            ("HTTP_NOT_MODIFIED", 304), ("HTTP_BAD_REQUEST", 400), ("HTTP_UNAUTHORIZED", 401),
            ("HTTP_FORBIDDEN", 403), ("HTTP_NOT_FOUND", 404), ("HTTP_REQUEST_TIMEOUT", 408),
            ("HTTP_CONFLICT", 409), ("HTTP_UNPROCESSABLE_ENTITY", 422), ("HTTP_TOO_MANY_REQUESTS", 429),
            ("HTTP_INTERNAL_SERVER_ERROR", 500), ("HTTP_BAD_GATEWAY", 502), ("HTTP_SERVICE_UNAVAILABLE", 503),
            ("HTTP_GATEWAY_TIMEOUT", 504),
        ] {
            ngx.raw_set(name, code)?;
        }

        // ---------- ngx.ssl（ssl_certificate_by_lua 专用） ----------
        // `require "ngx.ssl"` 走 package.loaded，语义与 OpenResty 的同名模块一致：
        // 只在 SSL 握手阶段可用；证书/私钥均为 DER，PEM 由 parse_pem_* 转换。
        let ssl = lua.create_table()?;
        {
            let f = lua.create_function(move |lua, ()| {
                let h = get_ctx(lua)?;
                let ctx = h.0.lock().unwrap();
                Ok(match ctx.ssl.as_ref().and_then(|s| s.server_name.clone()) {
                    Some(n) => LuaValue::String(lua.create_string(n)?),
                    None => LuaValue::Nil,
                })
            })?;
            ssl.set("server_name", f)?;
        }

        let parse_pem_cert = lua.create_function(move |lua, pem: LuaString| {
            let mut reader = std::io::BufReader::new(std::io::Cursor::new(pem.as_bytes()));
            match rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() {
                Ok(certs) if !certs.is_empty() => {
                    let chain: Vec<Vec<u8>> = certs.iter().map(|c| c.as_ref().to_vec()).collect();
                    let ud = lua.create_userdata(SslCertChain(chain))?;
                    Ok((LuaValue::UserData(ud), LuaValue::Nil))
                }
                Ok(_) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("PEM 中没有证书")?),
                )),
                Err(e) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string(format!("解析 PEM 证书失败: {e}"))?),
                )),
            }
        })?;
        ssl.set("parse_pem_cert", parse_pem_cert)?;

        let parse_pem_priv_key = lua.create_function(move |lua, pem: LuaString| {
            let mut reader = std::io::BufReader::new(std::io::Cursor::new(pem.as_bytes()));
            match rustls_pemfile::private_key(&mut reader) {
                Ok(Some(key)) => {
                    let ud = lua.create_userdata(SslPrivKey(key.secret_der().to_vec()))?;
                    Ok((LuaValue::UserData(ud), LuaValue::Nil))
                }
                Ok(None) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("PEM 中没有私钥")?),
                )),
                Err(e) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string(format!("解析 PEM 私钥失败: {e}"))?),
                )),
            }
        })?;
        ssl.set("parse_pem_priv_key", parse_pem_priv_key)?;

        let cert_pem_to_der = lua.create_function(move |lua, pem: LuaString| {
            let mut reader = std::io::BufReader::new(std::io::Cursor::new(pem.as_bytes()));
            match rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() {
                Ok(certs) => {
                    let mut der = Vec::new();
                    for c in certs {
                        der.extend_from_slice(c.as_ref());
                    }
                    Ok((LuaValue::String(lua.create_string(der)?), LuaValue::Nil))
                }
                Err(e) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string(format!("解析 PEM 证书失败: {e}"))?),
                )),
            }
        })?;
        ssl.set("cert_pem_to_der", cert_pem_to_der)?;

        let priv_key_pem_to_der = lua.create_function(move |lua, pem: LuaString| {
            let mut reader = std::io::BufReader::new(std::io::Cursor::new(pem.as_bytes()));
            match rustls_pemfile::private_key(&mut reader) {
                Ok(Some(key)) => Ok((
                    LuaValue::String(lua.create_string(key.secret_der())?),
                    LuaValue::Nil,
                )),
                Ok(None) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("PEM 中没有私钥")?),
                )),
                Err(e) => Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string(format!("解析 PEM 私钥失败: {e}"))?),
                )),
            }
        })?;
        ssl.set("priv_key_pem_to_der", priv_key_pem_to_der)?;

        // set_cert_and_key(cert, key) / set_cert(chain) / set_priv_key(key)
        let set_pair = lua.create_function(
            move |lua, (cert, key): (LuaValue, LuaValue)| {
                let chain = match ssl_cert_from_value(&cert) {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?)))
                    }
                };
                let key = match ssl_key_from_value(&key) {
                    Ok(k) => k,
                    Err(e) => {
                        return Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?)))
                    }
                };
                if let Err(e) = crate::certs::certified_key_from_der(chain.clone(), key.clone()) {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string(format!("证书/私钥无效: {e}"))?),
                    ));
                }
                let h = get_ctx(lua)?;
                let mut ctx = h.0.lock().unwrap();
                let Some(ssl) = ctx.ssl.as_mut() else {
                    return Ok((
                        LuaValue::Nil,
                        LuaValue::String(lua.create_string("不在 SSL 握手阶段")?),
                    ));
                };
                ssl.cert_chain = Some(chain);
                ssl.priv_key = Some(key);
                ssl.cleared = false;
                Ok((LuaValue::Boolean(true), LuaValue::Nil))
            },
        )?;
        ssl.set("set_cert_and_key", set_pair)?;

        // 旧 API：set_cert 与 set_priv_key 分开调用，握手侧成对取用并统一校验
        let set_cert = lua.create_function(move |lua, cert: LuaValue| {
            let chain = match ssl_cert_from_value(&cert) {
                Ok(c) => c,
                Err(e) => return Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
            };
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let Some(ssl) = ctx.ssl.as_mut() else {
                return Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("不在 SSL 握手阶段")?),
                ));
            };
            ssl.cert_chain = Some(chain);
            ssl.cleared = false;
            Ok((LuaValue::Boolean(true), LuaValue::Nil))
        })?;
        ssl.set("set_cert", set_cert)?;

        let set_priv_key = lua.create_function(move |lua, key: LuaValue| {
            let key_der = match ssl_key_from_value(&key) {
                Ok(k) => k,
                Err(e) => return Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
            };
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let Some(ssl) = ctx.ssl.as_mut() else {
                return Ok((
                    LuaValue::Nil,
                    LuaValue::String(lua.create_string("不在 SSL 握手阶段")?),
                ));
            };
            ssl.priv_key = Some(key_der);
            ssl.cleared = false;
            Ok((LuaValue::Boolean(true), LuaValue::Nil))
        })?;
        ssl.set("set_priv_key", set_priv_key)?;

        let clear_certs = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if let Some(ssl) = ctx.ssl.as_mut() {
                ssl.cert_chain = None;
                ssl.priv_key = None;
                ssl.cleared = true;
            }
            Ok(true)
        })?;
        ssl.set("clear_certs", clear_certs)?;

        let package: LuaTable = lua.globals().get("package")?;
        let loaded: LuaTable = package.get("loaded")?;
        loaded.set("ngx.ssl", ssl)?;

        lua.globals().set("ngx", ngx)?;

        Ok(())
    }

    /// 执行一个请求阶段脚本：轮询选一个 VM，把脚本作为协程作业提交给该 VM 的调度器，
    /// 等待该协程跑到 Finished（期间与同 VM 的其它在途请求交错执行）。ctx 改完带回去。
    pub async fn run_phase(
        &self,
        phase_name: &str,
        src: &LuaSource,
        ctx: Arc<Mutex<RequestCtx>>,
    ) -> Result<(), AppError> {
        let code = src.load()?;
        // 无锁轮询选 VM：VM 之间完全并行，VM 之内由调度器以协程方式并发
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.vms.len();
        Self::run_on_slot(&self.vms[idx], phase_name, code, ctx).await
    }

    /// 把定时器的 (dispatch, cb, args) 绑成无参纯 Lua 闭包（存入 registry），
    /// 让回调在协程里执行时没有 Rust 帧挡在中间，yield 才能穿透到调度器。
    fn bind_timer_runner(lua: &Lua, cb: Function, args_table: LuaTable) -> LuaResult<RegistryKey> {
        let dispatch: LuaFunction = lua.named_registry_value("__timer_dispatch")?;
        let make_runner: LuaFunction = lua.named_registry_value("__timer_make_runner")?;
        let runner: Function = make_runner.call((dispatch, cb, args_table))?;
        lua.create_registry_value(runner)
    }

    /// 定时器游离 ctx 的连接画像：继承注册时的 listener/host/scheme 等，让回调里的
    /// ngx.location.capture 仍能按原 server 的路由表解析；请求态字段保持 detached。
    fn timer_ctx_base(lua: &Lua) -> RequestCtx {
        let mut base = RequestCtx::detached();
        let Ok(ud) = lua.named_registry_value::<AnyUserData>("__ctx") else {
            return base;
        };
        let Ok(h) = ud.borrow::<CtxHandle>() else {
            return base;
        };
        let cur = h.0.lock().unwrap();
        base.listener = cur.listener;
        base.host.clone_from(&cur.host);
        base.scheme.clone_from(&cur.scheme);
        base.remote_addr.clone_from(&cur.remote_addr);
        base.remote_port = cur.remote_port;
        base.server_port = cur.server_port;
        base.http_version = cur.http_version;
        base
    }

    /// 定时器触发：在所属 VM 上建好回调协程，作为 Job 交给调度器 resume，并等它跑完。
    /// 返回 Ok(回调是否显式 return false)——供 ngx.timer.every 判定是否续期。
    async fn dispatch_timer_job(
        vm: &Arc<VM>,
        runner_key: &RegistryKey,
        base_ctx: &RequestCtx,
        co_counter: &Arc<AtomicU64>,
        job_tx: &mpsc::UnboundedSender<Job>,
    ) -> Result<bool, String> {
        let (thread_key, ctx_table_key) = {
            let guard = vm.lock().await;
            let built = (|| -> LuaResult<(RegistryKey, RegistryKey)> {
                let runner: Function = guard.registry_value(runner_key)?;
                let thread = guard.create_thread(runner)?;
                let thread_key = guard.create_registry_value(thread)?;
                let ctx_table = guard.create_table()?;
                let ctx_table_key = guard.create_registry_value(ctx_table)?;
                Ok((thread_key, ctx_table_key))
            })();
            match built {
                Ok(keys) => keys,
                Err(e) => return Err(format!("定时器回调协程创建失败: {e}")),
            }
        };
        let (done, rx) = oneshot::channel();
        let job = Job::Timer {
            co_id: co_counter.fetch_add(1, Ordering::Relaxed),
            thread_key,
            ctx_table_key,
            ctx: Arc::new(Mutex::new(base_ctx.clone())),
            done,
        };
        if let Err(e) = job_tx.send(job) {
            if let Job::Timer {
                thread_key,
                ctx_table_key,
                ..
            } = e.0
            {
                let guard = vm.lock().await;
                let _ = guard.remove_registry_value(thread_key);
                let _ = guard.remove_registry_value(ctx_table_key);
            }
            return Err("Lua 调度器已停止".into());
        }
        match rx.await {
            Ok(res) => res,
            Err(_) => Err("Lua 调度器在定时器回调完成前退出".into()),
        }
    }

    /// 把一段脚本作为作业提交给指定 VM 的调度器并等待完成（请求阶段与 init_worker 共用）。
    ///
    /// 低并发快速路径：VM 锁空闲时由当前任务持锁把首段直接跑掉——
    /// 无让出的脚本（多数 Lua 阶段）完全不经过调度器任务，省掉「连接任务 → 调度器 → 回话」
    /// 两次任务跳转；一旦脚本让出（sleep/cosocket/subrequest/thread.wait），把挂起的协程
    /// Adopt 给调度器，后续恢复与其它请求一样由调度器统一驱动。
    async fn run_on_slot(
        slot: &Arc<VmSlot>,
        phase_name: &str,
        code: Arc<str>,
        ctx: Arc<Mutex<RequestCtx>>,
    ) -> Result<(), AppError> {
        let co_id = slot.co_counter.fetch_add(1, Ordering::Relaxed);
        if let Ok(guard) = slot.vm.try_lock() {
            let outcome = Self::run_inline_segment(
                &guard,
                &slot.chunks,
                &slot.sched_ctl,
                co_id,
                phase_name,
                &code,
                &ctx,
            );
            drop(guard);
            match outcome? {
                InlineOutcome::Finished => {
                    crate::metrics::get().on_lua_inline();
                    return Ok(());
                }
                InlineOutcome::Yielded {
                    op_id,
                    thread_key,
                    ctx_table_key,
                } => {
                    crate::metrics::get().on_lua_adopted();
                    let (tx, rx) = oneshot::channel();
                    slot.job_tx
                        .send(Job::Adopt {
                            co_id,
                            phase_name: phase_name.to_string(),
                            ctx,
                            thread_key,
                            ctx_table_key,
                            op_id,
                            reply: tx,
                        })
                        .map_err(|_| AppError::Other("Lua 调度器已停止".into()))?;
                    return match rx.await {
                        Ok(res) => res,
                        Err(_) => Err(AppError::Other("Lua 调度器在请求完成前退出".into())),
                    };
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        crate::metrics::get().on_lua_scheduled();
        let job = Job::Start {
            co_id,
            phase_name: phase_name.to_string(),
            code,
            ctx,
            reply: tx,
        };
        slot.job_tx
            .send(job)
            .map_err(|_| AppError::Other("Lua 调度器已停止".into()))?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(AppError::Other("Lua 调度器在请求完成前退出".into())),
        }
    }

    /// 快速路径：在 VM 锁内同步建协程 + resume 首段。
    /// Finished 时自行清理（未启动的 spawn 一并丢弃）；让出时把 registry 句柄交还调用方移交调度器。
    fn run_inline_segment(
        lua: &Lua,
        chunks: &Arc<std::sync::Mutex<ChunkCache>>,
        ctl: &SharedCtl,
        co_id: u64,
        phase_name: &str,
        code: &Arc<str>,
        ctx: &Arc<Mutex<RequestCtx>>,
    ) -> Result<InlineOutcome, AppError> {
        let (thread_key, ctx_table_key) = {
            let mut cache = chunks.lock().unwrap();
            Self::co_spawn(lua, &mut cache, phase_name, code)?
        };
        let run = (|| -> Result<LuaValue, AppError> {
            let ngx: LuaTable = lua.globals().get("ngx")?;
            let ctx_table: LuaTable = lua.registry_value(&ctx_table_key)?;
            lua.set_named_registry_value("__ctx", CtxHandle(Arc::clone(ctx)))?;
            lua.set_named_registry_value("__phase", phase_name.to_string())?;
            lua.set_named_registry_value("__cur_co", co_id as i64)?;
            lua.set_named_registry_value("__cur_owner", co_id as i64)?;
            ngx.raw_set("ctx", ctx_table)?;
            let thread: Thread = lua.registry_value(&thread_key)?;
            thread.resume::<LuaValue>(()).map_err(AppError::from)
        })();
        match run {
            Err(e) => {
                let _ = lua.remove_registry_value(thread_key);
                let _ = lua.remove_registry_value(ctx_table_key);
                drop_unstarted_spawns(ctl, co_id);
                Err(e)
            }
            Ok(yielded) => {
                // resume 成功返回后协程要么已结束、要么停在受支持的让出点
                let thread: Thread = lua.registry_value(&thread_key)?;
                match thread.status() {
                    ThreadStatus::Finished => {
                        let _ = lua.remove_registry_value(thread_key);
                        let _ = lua.remove_registry_value(ctx_table_key);
                        // 请求脚本没让出就结束：spawn 出的子线程尚未启动，随请求一起丢弃
                        drop_unstarted_spawns(ctl, co_id);
                        Ok(InlineOutcome::Finished)
                    }
                    ThreadStatus::Resumable => match op_id_of(&yielded) {
                        Some(op_id) => Ok(InlineOutcome::Yielded {
                            op_id,
                            thread_key,
                            ctx_table_key,
                        }),
                        None => {
                            let _ = lua.remove_registry_value(thread_key);
                            let _ = lua.remove_registry_value(ctx_table_key);
                            drop_unstarted_spawns(ctl, co_id);
                            Err(AppError::Other(
                                "attempt to yield from outside a supported operation".into(),
                            ))
                        }
                    },
                    // 同步 resume 不可能停在 Running；Error 表示协程异常终止
                    ThreadStatus::Error | ThreadStatus::Running => {
                        let _ = lua.remove_registry_value(thread_key);
                        let _ = lua.remove_registry_value(ctx_table_key);
                        drop_unstarted_spawns(ctl, co_id);
                        Err(AppError::Other("coroutine aborted".into()))
                    }
                }
            }
        }
    }

    /// 为新请求建一个协程，并把协程句柄与「本请求专属」的 ngx.ctx 表各自存入 registry
    /// （返回可跨 await 存活的 RegistryKey）。脚本源码走 `chunks` 缓存，只在首次出现时编译。
    fn co_spawn(
        lua: &Lua,
        chunks: &mut ChunkCache,
        phase_name: &str,
        code: &Arc<str>,
    ) -> LuaResult<(RegistryKey, RegistryKey)> {
        // 命中路径不分配：先 get_mut，只有首次见到这个阶段的脚本才付出 String 键的分配
        if !chunks.contains_key(phase_name) {
            chunks.insert(phase_name.to_string(), HashMap::new());
        }
        let by_code = chunks
            .get_mut(phase_name)
            .expect("刚插入的阶段桶一定存在");
        let f = match by_code.get(code.as_ref()) {
            Some(key) => lua.registry_value::<Function>(key)?,
            None => {
                let compiled: Function = lua.load(code.as_ref()).set_name(phase_name).into_function()?;
                let key = lua.create_registry_value(compiled.clone())?;
                // 自检重载过的脚本会以「另一个源码键」留在这个桶里；桶满就整桶清空
                // （RegistryKey drop 即 lua_unref，Lua 侧引用同步释放），避免长期攒出泄漏。
                if by_code.len() >= CHUNK_CACHE_MAX_PER_PHASE {
                    by_code.clear();
                }
                by_code.insert(Arc::clone(code), key);
                compiled
            }
        };
        let co = lua.create_thread(f)?;
        let thread_key = lua.create_registry_value(co)?;
        let ctx_table = lua.create_table()?;
        let ctx_table_key = lua.create_registry_value(ctx_table)?;
        Ok((thread_key, ctx_table_key))
    }

    /// VM 调度器：单任务独占该 VM 的锁，以「持锁同步 resume 一段、段间释放锁」的方式并发多条协程。
    /// 释放锁的窗口内，直接 vm.lock() 的 ngx.timer 与 tokio 睡眠定时器得以推进；协程只在 ngx.sleep
    /// 处 coroutine.yield 让出（yielded 值即睡眠 id）。
    async fn run_scheduler(
        vm: Arc<VM>,
        mut job_rx: mpsc::UnboundedReceiver<Job>,
        mut ev_rx: mpsc::UnboundedReceiver<(u64, Vec<ResumeVal>)>,
        ctl: SharedCtl,
        chunks: Arc<std::sync::Mutex<ChunkCache>>,
    ) {
        let mut states: HashMap<u64, CoState> = HashMap::new();
        let mut ready: VecDeque<u64> = VecDeque::new();
        let mut waiting: HashMap<u64, u64> = HashMap::new(); // op id -> 协程 id
        // 挂起等待时被 select 取走的作业/事件先暂存，下一步统一步骤内处理（避免丢事件）
        let mut inbox: VecDeque<Job> = VecDeque::new();
        let mut wake_evs: VecDeque<(u64, Vec<ResumeVal>)> = VecDeque::new();
        // ---------- ngx.thread.* 簿记 ----------
        let mut done: HashSet<u64> = HashSet::new(); // 已完成线程（结果在 __thread_sink[tid]）
        let mut tid_waitop: HashMap<u64, u64> = HashMap::new(); // tid -> parked 的 wait op
        let mut wait_group: HashMap<u64, Vec<u64>> = HashMap::new(); // wait op -> 被等待 tids
        let mut owner_children: HashMap<u64, Vec<u64>> = HashMap::new(); // owner req -> 子线程 tids

        loop {
            // ==================== 持锁一步 ====================
            {
                let guard = vm.lock().await;
                let lua = &*guard;
                let ngx: LuaTable = match lua.globals().get("ngx") {
                    Ok(t) => t,
                    Err(_) => break, // VM 状态异常，退出
                };

                // 1) 收下新作业：编译进协程并入队 ready；Adopt 作业接管快速路径移交的挂起协程
                let mut jobs: Vec<Job> = Vec::new();
                jobs.extend(inbox.drain(..));
                while let Ok(j) = job_rx.try_recv() {
                    jobs.push(j);
                }
                let mut adopted: Vec<(u64, u64)> = Vec::new();
                for job in jobs {
                    match job {
                        Job::Start { co_id, phase_name, code, ctx, reply } => {
                            let spawned = {
                                let mut cache = chunks.lock().unwrap();
                                Self::co_spawn(lua, &mut cache, &phase_name, &code)
                            };
                            match spawned {
                                Ok((thread_key, ctx_table_key)) => {
                                    states.insert(
                                        co_id,
                                        CoState {
                                            thread_key,
                                            ctx_table_key,
                                            ctx,
                                            reply,
                                            wake_args: Vec::new(),
                                            phase: phase_name,
                                            is_child: false,
                                            owner: co_id,
                                            wake_tid: None,
                                            timer_done: None,
                                        },
                                    );
                                    ready.push_back(co_id);
                                }
                                Err(e) => {
                                    eprintln!("[onrouter] {phase_name} 脚本编译失败: {e}");
                                    let _ = reply.send(Err(AppError::Lua(e)));
                                }
                            }
                        }
                        Job::Adopt {
                            co_id,
                            phase_name,
                            ctx,
                            thread_key,
                            ctx_table_key,
                            op_id,
                            reply,
                        } => {
                            states.insert(
                                co_id,
                                CoState {
                                    thread_key,
                                    ctx_table_key,
                                    ctx,
                                    reply,
                                    wake_args: Vec::new(),
                                    phase: phase_name,
                                    is_child: false,
                                    owner: co_id,
                                    wake_tid: None,
                                    timer_done: None,
                                },
                            );
                            adopted.push((co_id, op_id));
                        }
                        Job::Timer {
                            co_id,
                            thread_key,
                            ctx_table_key,
                            ctx,
                            done,
                        } => {
                            let (dummy_tx, _dummy_rx) = oneshot::channel();
                            states.insert(
                                co_id,
                                CoState {
                                    thread_key,
                                    ctx_table_key,
                                    ctx,
                                    reply: dummy_tx,
                                    wake_args: Vec::new(),
                                    phase: "timer".to_string(),
                                    is_child: false,
                                    owner: co_id,
                                    wake_tid: None,
                                    timer_done: Some(done),
                                },
                            );
                            ready.push_back(co_id);
                        }
                    }
                }

                // 1b) 收下 spawn 请求：为每个子协程建 CoState，共享 owner 的 ctx/Arc/阶段并入队 ready。
                let spawns = std::mem::take(&mut ctl.lock().unwrap().spawns);
                for SpawnReq { tid, owner, thread_key } in spawns {
                    let prepared = states.get(&owner).map(|p| {
                        (
                            Arc::clone(&p.ctx),
                            p.phase.clone(),
                            lua.registry_value::<LuaTable>(&p.ctx_table_key),
                        )
                    });
                    let (ctx, phase, table_res) = match prepared {
                        Some(x) => x,
                        None => {
                            let _ = lua.remove_registry_value(thread_key);
                            continue;
                        }
                    };
                    let ctx_table_key = match table_res.and_then(|ct| lua.create_registry_value(ct)) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("[onrouter] thread 共享 ctx 失败: {e}");
                            let _ = lua.remove_registry_value(thread_key);
                            continue;
                        }
                    };
                    let (dummy_tx, _dummy_rx) = oneshot::channel();
                    states.insert(
                        tid,
                        CoState {
                            thread_key,
                            ctx_table_key,
                            ctx,
                            reply: dummy_tx,
                            wake_args: Vec::new(),
                            phase,
                            is_child: true,
                            owner,
                            wake_tid: None,
                            timer_done: None,
                        },
                    );
                    owner_children.entry(owner).or_default().push(tid);
                    ready.push_back(tid);
                }

                // 1c) 收下 kill 请求：中止仍在跑的线程，记 false 结果并投递等待方。
                let kills = std::mem::take(&mut ctl.lock().unwrap().kills);
                for tid in kills {
                    if !states.contains_key(&tid) {
                        continue; // 已结束/未知：no-op
                    }
                    let _ = sink_set_err(lua, tid, "thread killed");
                    done.insert(tid);
                    remove_child_state(lua, &mut states, &mut waiting, tid);
                    deliver_thread(
                        &mut tid_waitop,
                        &mut waiting,
                        &mut wait_group,
                        &mut states,
                        &mut ready,
                        tid,
                    );
                }

                // 1d) 快速路径移交的挂起协程：登记让出等待。必须放在事件处理之前——op 的
                //     完成事件可能先于 Adopt 作业到达，若此时 waiting 里没有映射，事件会被丢弃。
                for (co_id, op_id) in adopted {
                    park_yielded(
                        co_id,
                        op_id,
                        &mut states,
                        &mut ready,
                        &mut waiting,
                        &ctl,
                        &done,
                        &mut tid_waitop,
                        &mut wait_group,
                    );
                }

                // 2) 收下完成事件（睡眠或 cosocket op）：把对应协程从 waiting 移回 ready，
                //    并携带该 op 的唤醒值（睡眠为空 vec，cosocket 为结果），供 resume 回传。
                let mut evs: Vec<(u64, Vec<ResumeVal>)> = Vec::new();
                evs.extend(wake_evs.drain(..));
                while let Ok(e) = ev_rx.try_recv() {
                    evs.push(e);
                }
                for (sid, payload) in evs {
                    if let Some(co_id) = waiting.remove(&sid) {
                        if let Some(st) = states.get_mut(&co_id) {
                            st.wake_args = payload;
                        }
                        ready.push_back(co_id);
                    }
                }

                // 3) 本轮就绪协程各同步 resume 一次（公平轮转）。
                //    请求协程与 ngx.thread.spawn 出的子协程共用此循环：子协程是一等 states
                //    成员，可交错跑 cosocket/ngx.sleep；完成时把 __thread_sink[tid] 投递给 parked 等待方。
                let mut pending = std::mem::take(&mut ready);
                while let Some(co_id) = pending.pop_front() {
                    // 借用 st 仅用于挂上下文 + 取句柄 + 取出唤醒参数/tid；随后立即结束借用
                    let (thread, wake_args, wake_tid, is_child, owner) =
                        match states.get_mut(&co_id) {
                            None => continue,
                            Some(st) => {
                                let _ = lua.set_named_registry_value(
                                    "__ctx",
                                    CtxHandle(Arc::clone(&st.ctx)),
                                );
                                let _ = lua.set_named_registry_value("__phase", st.phase.clone());
                                // spawn 需据此把子线程挂到正确的所属请求上
                                let _ =
                                    lua.set_named_registry_value("__cur_co", co_id as i64);
                                let _ = lua
                                    .set_named_registry_value("__cur_owner", st.owner as i64);
                                if let Ok(ct) = lua.registry_value::<LuaTable>(&st.ctx_table_key) {
                                    let _ = ngx.raw_set("ctx", ct);
                                }
                                let wa = std::mem::take(&mut st.wake_args);
                                let wt = st.wake_tid.take();
                                (
                                    lua.registry_value::<Thread>(&st.thread_key),
                                    wa,
                                    wt,
                                    st.is_child,
                                    st.owner,
                                )
                            }
                        }; // states 借用到此结束
                    let thread = match thread {
                        Ok(t) => t,
                        Err(e) => {
                            if is_child {
                                thread_complete(
                                    lua, &mut states, &mut waiting, &mut done, &mut tid_waitop,
                                    &mut wait_group, &mut ready, co_id,
                                    Some(&e.to_string()),
                                );
                            } else {
                                finish(lua, &mut states, &mut waiting, co_id, Err(AppError::Lua(e)));
                                reap_children(
                                    lua, &mut states, owner, &mut owner_children, &mut done,
                                    &mut tid_waitop, &mut wait_group, &mut waiting,
                                );
                            }
                            continue;
                        }
                    };

                    // 喂回协程本轮恢复值：wait 命中用 sink[tid] 打包结果，否则用 op 唤醒参数
                    let resume_result = (|| -> LuaResult<LuaValue> {
                        if let Some(tid) = wake_tid {
                            let vals = sink_values(lua, tid)?;
                            return thread.resume::<LuaValue>(mlua::MultiValue::from_vec(vals));
                        }
                        if wake_args.is_empty() {
                            thread.resume::<LuaValue>(())
                        } else {
                            let mut vals: Vec<LuaValue> = Vec::with_capacity(wake_args.len());
                            for rv in wake_args {
                                vals.push(resume_val_to_lua(lua, rv)?);
                            }
                            thread.resume::<LuaValue>(mlua::MultiValue::from_vec(vals))
                        }
                    })();

                    match resume_result {
                        Err(e) => {
                            eprintln!("[onrouter] 脚本错误: {e}");
                            if is_child {
                                thread_complete(
                                    lua, &mut states, &mut waiting, &mut done, &mut tid_waitop,
                                    &mut wait_group, &mut ready, co_id, Some(&e.to_string()),
                                );
                            } else {
                                finish(lua, &mut states, &mut waiting, co_id, Err(AppError::Lua(e)));
                                reap_children(
                                    lua, &mut states, owner, &mut owner_children, &mut done,
                                    &mut tid_waitop, &mut wait_group, &mut waiting,
                                );
                            }
                        }
                        Ok(yielded) => match thread.status() {
                            ThreadStatus::Finished => {
                                if is_child {
                                    // 子协程体在返回前已把结果写入 __thread_sink[tid]
                                    thread_complete(
                                        lua, &mut states, &mut waiting, &mut done, &mut tid_waitop,
                                        &mut wait_group, &mut ready, co_id, None,
                                    );
                                } else if states
                                    .get(&co_id)
                                    .map_or(false, |st| st.timer_done.is_some())
                                {
                                    // 定时器回调：返回值 false 表示 ngx.timer.every 停止续期
                                    let stop = matches!(yielded, LuaValue::Boolean(false));
                                    finish_timer(lua, &mut states, &mut waiting, co_id, Ok(stop));
                                    reap_children(
                                        lua, &mut states, owner, &mut owner_children, &mut done,
                                        &mut tid_waitop, &mut wait_group, &mut waiting,
                                    );
                                } else {
                                    finish(lua, &mut states, &mut waiting, co_id, Ok(()));
                                    reap_children(
                                        lua, &mut states, owner, &mut owner_children, &mut done,
                                        &mut tid_waitop, &mut wait_group, &mut waiting,
                                    );
                                }
                            }
                            ThreadStatus::Resumable => match op_id_of(&yielded) {
                                Some(sid) => park_yielded(
                                    co_id,
                                    sid,
                                    &mut states,
                                    &mut pending,
                                    &mut waiting,
                                    &ctl,
                                    &done,
                                    &mut tid_waitop,
                                    &mut wait_group,
                                ),
                                None => {
                                    // 非受支持让出（yield 出的不是 op id）：无法唤醒，按错误回传避免悬挂
                                    eprintln!("[onrouter] 协程 yield 了非 op id 值，无法恢复");
                                    let msg = AppError::Other(
                                        "attempt to yield from outside a supported operation".into(),
                                    );
                                    if is_child {
                                        let m = msg.to_string();
                                        thread_complete(
                                            lua, &mut states, &mut waiting, &mut done,
                                            &mut tid_waitop, &mut wait_group, &mut ready, co_id,
                                            Some(&m),
                                        );
                                    } else {
                                        finish(lua, &mut states, &mut waiting, co_id, Err(msg));
                                        reap_children(
                                            lua, &mut states, owner, &mut owner_children,
                                            &mut done, &mut tid_waitop, &mut wait_group,
                                            &mut waiting,
                                        );
                                    }
                                }
                            },
                            ThreadStatus::Error => {
                                if is_child {
                                    thread_complete(
                                        lua, &mut states, &mut waiting, &mut done, &mut tid_waitop,
                                        &mut wait_group, &mut ready, co_id,
                                        Some("coroutine error"),
                                    );
                                } else {
                                    finish(
                                        lua, &mut states, &mut waiting, co_id,
                                        Err(AppError::Other("coroutine error".into())),
                                    );
                                    reap_children(
                                        lua, &mut states, owner, &mut owner_children, &mut done,
                                        &mut tid_waitop, &mut wait_group, &mut waiting,
                                    );
                                }
                            }
                            // 不应出现（同步 resume 不会停在 Running）；保守放回本轮继续
                            ThreadStatus::Running => pending.push_back(co_id),
                        },
                    }
                }
                ready.append(&mut pending);
            } // ==================== 释放锁 ====================

            // ctl 信箱在本步 resume 中途可能收到 spawn/wait/kill（子线程登记、等待、杀掉），
            // 此时即便 ready 暂空也必须再跑一步处理，否则会误入 select 永久阻塞（父 parked、子未跑）。
            let ctl_busy = {
                let c = ctl.lock().unwrap();
                !(c.spawns.is_empty() && c.waits.is_empty() && c.kills.is_empty())
            };
            // 有就绪工作或有 ctl 待办：让出执行权给 runtime（timer/事件），随即再跑一步
            // 两者皆空：挂起等作业或完成事件
            if ready.is_empty() && !ctl_busy {
                tokio::select! {
                    j = job_rx.recv() => match j {
                        Some(job) => inbox.push_back(job),
                        None => break, // 所有 job_tx 已 drop（引擎关闭）
                    },
                    e = ev_rx.recv() => {
                        if let Some(ev) = e { wake_evs.push_back(ev); }
                    },
                }
            } else {
                tokio::task::yield_now().await;
            }
        }

        // 退出：把仍在途的协程全部回传错误，避免 run_phase 永久等待
        let lua_guard = vm.lock().await;
        for (_, st) in std::mem::take(&mut states) {
            let _ = lua_guard.remove_registry_value(st.thread_key);
            let _ = lua_guard.remove_registry_value(st.ctx_table_key);
            drop(st.ctx);
            if let Some(tx) = st.timer_done {
                let _ = tx.send(Err("Lua 调度器已停止".into()));
            } else {
                let _ = st.reply.send(Err(AppError::Other("Lua 调度器已停止".into())));
            }
        }
        drop(lua_guard);
    }
}

/// 结束一个协程：出栈 states、释放其 registry 句柄、尽早 drop 请求 ctx 引用，再回传结果。
/// 定时器协程把结果改投给 timer_done（发起任务的 tokio 定时器），普通请求/子线程走 reply。
fn finish(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    waiting: &mut HashMap<u64, u64>,
    co_id: u64,
    result: Result<(), AppError>,
) {
    if let Some((timer_done, reply)) = take_finished_state(lua, states, waiting, co_id) {
        if let Some(tx) = timer_done {
            let _ = tx.send(result.map(|_| false).map_err(|e| e.to_string()));
        } else {
            let _ = reply.send(result);
        }
    }
}

/// 定时器回调正常结束：把「是否 return false」回执给定时器任务。
fn finish_timer(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    waiting: &mut HashMap<u64, u64>,
    co_id: u64,
    result: Result<bool, String>,
) {
    if let Some((timer_done, reply)) = take_finished_state(lua, states, waiting, co_id) {
        if let Some(tx) = timer_done {
            let _ = tx.send(result);
        } else {
            let _ = reply.send(result.map(|_| ()).map_err(AppError::Other));
        }
    }
}

type FinishSenders = (
    Option<oneshot::Sender<Result<bool, String>>>,
    oneshot::Sender<Result<(), AppError>>,
);

fn take_finished_state(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    waiting: &mut HashMap<u64, u64>,
    co_id: u64,
) -> Option<FinishSenders> {
    let st = states.remove(&co_id)?;
    // 清理可能残留的 waiting 映射（此协程已结束）
    waiting.retain(|_, v| *v != co_id);
    let _ = lua.remove_registry_value(st.thread_key);
    let _ = lua.remove_registry_value(st.ctx_table_key);
    drop(st.ctx);
    Some((st.timer_done, st.reply))
}

/// 回收一个已结束的 ngx.thread 子协程：只清理其 registry 句柄与 waiting 残留，
/// 不发送 reply（子协程持有的是 dummy oneshot，真实收尾在等待方/所属请求）。
fn remove_child_state(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    waiting: &mut HashMap<u64, u64>,
    tid: u64,
) {
    if let Some(st) = states.remove(&tid) {
        waiting.retain(|_, v| *v != tid);
        let _ = lua.remove_registry_value(st.thread_key);
        let _ = lua.remove_registry_value(st.ctx_table_key);
        drop(st.ctx);
    }
}

/// 读取 Lua 侧 `__thread_sink[tid]`（`table.pack(ok, ret...)`）的打包值，供等待方本轮 resume 喂回。
fn sink_values(lua: &Lua, tid: u64) -> LuaResult<Vec<LuaValue>> {
    let sink: LuaTable = lua.globals().get("__thread_sink")?;
    let packed: LuaTable = match sink.raw_get(tid as i64) {
        Ok(t) => t,
        Err(_) => return Ok(vec![LuaValue::Boolean(false), LuaValue::Nil]),
    };
    let n: i64 = packed.raw_get("n").unwrap_or(0);
    let mut out = Vec::with_capacity(n.max(0) as usize);
    for i in 1..=n {
        match packed.raw_get::<LuaValue>(i) {
            Ok(v) => out.push(v),
            Err(_) => break,
        }
    }
    // 消费后清槽，避免同一 tid 结果被重复投递
    let _ = sink.raw_set(tid as i64, LuaValue::Nil);
    Ok(out)
}

/// 把 `__thread_sink[tid]` 写成 (false, err)：kill 或子协程异常退出时的失败结果。
fn sink_set_err(lua: &Lua, tid: u64, msg: &str) -> LuaResult<()> {
    let sink: LuaTable = lua.globals().get("__thread_sink")?;
    let packed = lua.create_table()?;
    packed.raw_set("n", 2)?;
    packed.raw_set(1, false)?;
    packed.raw_set(2, msg)?;
    sink.raw_set(tid as i64, packed)
}

/// 一个线程完成/失败后投递：若有某等待方正 parked 在该 tid 上，唤醒其首个等待协程并清理同组簿记。
fn deliver_thread(
    tid_waitop: &mut HashMap<u64, u64>,
    waiting: &mut HashMap<u64, u64>,
    wait_group: &mut HashMap<u64, Vec<u64>>,
    states: &mut HashMap<u64, CoState>,
    ready: &mut VecDeque<u64>,
    tid: u64,
) {
    let op = match tid_waitop.remove(&tid) {
        Some(op) => op,
        None => return, // 无人等待此线程
    };
    let parent = match waiting.remove(&op) {
        Some(p) => p,
        None => return, // 等待方已不在 parked 状态
    };
    // 同一次 wait 的其它线程不再需要跟踪（任一完成即已交付）
    if let Some(group) = wait_group.remove(&op) {
        for t in group {
            tid_waitop.remove(&t);
        }
    }
    if let Some(st) = states.get_mut(&parent) {
        st.wake_tid = Some(tid);
        ready.push_back(parent);
    }
}

/// 子协程收尾统一入口：正常完成时其结果已写入 sink；异常/被杀时补写失败结果。
/// 记入 done、清理状态、投递给 parked 等待方。
fn thread_complete(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    waiting: &mut HashMap<u64, u64>,
    done: &mut HashSet<u64>,
    tid_waitop: &mut HashMap<u64, u64>,
    wait_group: &mut HashMap<u64, Vec<u64>>,
    ready: &mut VecDeque<u64>,
    tid: u64,
    err: Option<&str>,
) {
    if let Some(m) = err {
        let _ = sink_set_err(lua, tid, m);
    }
    done.insert(tid);
    remove_child_state(lua, states, waiting, tid);
    deliver_thread(tid_waitop, waiting, wait_group, states, ready, tid);
}

/// 所属请求结束（正常/出错）时回收其仍在途的子线程：直接移除状态并清簿记
/// （对标 ngx_lua：请求终止会杀掉其所有 light thread；结果已无人接收）。
fn reap_children(
    lua: &Lua,
    states: &mut HashMap<u64, CoState>,
    owner: u64,
    owner_children: &mut HashMap<u64, Vec<u64>>,
    done: &mut HashSet<u64>,
    tid_waitop: &mut HashMap<u64, u64>,
    wait_group: &mut HashMap<u64, Vec<u64>>,
    waiting: &mut HashMap<u64, u64>,
) {
    let tids = match owner_children.remove(&owner) {
        Some(t) => t,
        None => return,
    };
    for tid in tids {
        if states.contains_key(&tid) {
            remove_child_state(lua, states, waiting, tid);
        }
        done.remove(&tid);
        if let Some(op) = tid_waitop.remove(&tid) {
            if let Some(group) = wait_group.remove(&op) {
                for t in group {
                    tid_waitop.remove(&t);
                }
            }
        }
    }
}

/// 从协程 yield 出的值里取 op id（睡眠 / cosocket 让出时均以整型 op id yield）。
fn op_id_of(v: &LuaValue) -> Option<u64> {
    match v {
        LuaValue::Integer(i) => u64::try_from(*i).ok(),
        LuaValue::Number(n) => u64::try_from(*n as i64).ok(),
        _ => None,
    }
}

/// 把 Rust 侧的唤醒值转成 LuaValue（在 VM 锁内、resume 之前调用）。
fn resume_val_to_lua(lua: &Lua, v: ResumeVal) -> LuaResult<LuaValue> {
    Ok(match v {
        ResumeVal::Nil => LuaValue::Nil,
        ResumeVal::Bool(b) => LuaValue::Boolean(b),
        ResumeVal::Int(i) => LuaValue::Integer(i),
        ResumeVal::Str(s) => LuaValue::String(lua.create_string(s)?),
        ResumeVal::Bytes(b) => LuaValue::String(lua.create_string(&b)?),
        ResumeVal::SubReq {
            status,
            headers,
            body,
        } => {
            let t = lua.create_table()?;
            t.set("status", status as i64)?;
            t.set("body", lua.create_string(&body)?)?;
            let ht = lua.create_table()?;
            for (k, val) in headers {
                ht.set(k, val)?;
            }
            t.set("header", ht)?;
            LuaValue::Table(t)
        }
    })
}

// ---------- SharedZone 的 Lua 绑定（ngx.shared.<name>） ----------

impl LuaUserData for crate::shared_dict::SharedZone {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // d:get(key) -> string | nil
        methods.add_method("get", |lua, this, key: String| {
            Ok(this
                .get(&key)
                .map(|b| LuaValue::String(lua.create_string(&b).unwrap())))
        });
        // d:get_stale(key) -> value, stale（含过期项；第二返回值标记是否已过期，对标 ngx_lua）
        methods.add_method("get_stale", |lua, this, key: String| {
            let (val, stale) = this.get_stale_flagged(&key);
            let v = match val {
                Some(b) => LuaValue::String(lua.create_string(&b)?),
                None => LuaValue::Nil,
            };
            Ok((v, LuaValue::Boolean(stale)))
        });
        // d:set(key, value, ex?) -> true | nil, "no memory"
        methods.add_method(
            "set",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持（仅 string/number/boolean）"))?;
                match this.set(&key, bytes, ex) {
                    Ok(()) => Ok((LuaValue::Boolean(true), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:safe_set(key, value, ex?) -> true | nil, "no memory"
        methods.add_method(
            "safe_set",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                match this.safe_set(&key, bytes, ex) {
                    Ok(()) => Ok((LuaValue::Boolean(true), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:add(key, value, ex?) -> true | false | nil, "no memory"
        methods.add_method(
            "add",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                match this.add(&key, bytes, ex) {
                    Ok(ok) => Ok((LuaValue::Boolean(ok), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:replace(key, value, ex?) -> true | false | nil, "no memory"
        methods.add_method(
            "replace",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                match this.replace(&key, bytes, ex) {
                    Ok(ok) => Ok((LuaValue::Boolean(ok), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:delete(key)
        methods.add_method("delete", |_, this, key: String| {
            this.delete(&key);
            Ok(())
        });
        // d:incr(key, delta, init?) -> new_value | nil, err
        methods.add_method(
            "incr",
            |lua, this, (key, delta, init): (String, i64, Option<i64>)| {
                match this.incr(&key, delta, init) {
                    Ok(v) => Ok((LuaValue::Integer(v), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:ttl(key) -> 剩余秒数 | -1（永不过期）| nil（不存在）
        methods.add_method("ttl", |_, this, key: String| Ok(this.ttl(&key)));
        // d:flush_all()
        methods.add_method("flush_all", |_, this, ()| {
            this.flush_all();
            Ok(())
        });
        // d:flush_expired() -> 清理的条目数
        methods.add_method("flush_expired", |_, this, ()| Ok(this.flush_expired()));
        // d:num() -> 总条目数
        methods.add_method("num", |_, this, ()| Ok(this.num()));
        // d:capacity() -> 容量上限（字节）
        methods.add_method("capacity", |_, this, ()| Ok(this.capacity()));
        // d:free_space() -> 剩余可用空间（字节）
        methods.add_method("free_space", |_, this, ()| Ok(this.free_space()));

        // ---------- Batch 2：补齐 OpenResty ngx.shared.DICT 方法面 ----------
        // d:get_plus(key) -> value, flags（ONRouter 存无类型字节，flags 恒 0=string）
        methods.add_method("get_plus", |lua, this, key: String| {
            let v = match this.get(&key) {
                Some(b) => LuaValue::String(lua.create_string(&b)?),
                None => LuaValue::Nil,
            };
            Ok((v, LuaValue::Integer(0)))
        });
        // d:get2(key) -> (value | nil, need_mask, stale, flags, expire)
        methods.add_method("get2", |lua, this, key: String| {
            let (val, stale) = this.get_stale_flagged(&key);
            let ttl = this.ttl(&key).unwrap_or(-1.0);
            let v = match val {
                Some(b) => LuaValue::String(lua.create_string(&b)?),
                None => LuaValue::Nil,
            };
            Ok((
                v,
                LuaValue::Boolean(false), // need_mask
                LuaValue::Boolean(stale),
                LuaValue::Integer(0), // flags：无类型存储
                LuaValue::Number(ttl),
            ))
        });
        // d:size() -> 存活值字节总和
        methods.add_method("size", |_, this, ()| Ok(this.size()));
        // d:len() -> 总条目数（对标 OpenResty len，等价 num）
        methods.add_method("len", |_, this, ()| Ok(this.num()));
        // d:key_present(key) -> boolean
        methods.add_method("key_present", |_, this, key: String| Ok(this.key_present(&key)));
        // d:force_set(key, value, ex?) -> true | nil, "no memory"（始终覆盖，必要时 LRU 淘汰）
        methods.add_method(
            "force_set",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持（仅 string/number/boolean）"))?;
                match this.force_set(&key, bytes, ex) {
                    Ok(()) => Ok((LuaValue::Boolean(true), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:force_add(key, value, ex?) -> true | false | nil, "no memory"
        methods.add_method(
            "force_add",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                match this.force_add(&key, bytes, ex) {
                    Ok(ok) => Ok((LuaValue::Boolean(ok), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:decr(key, minus, init?) -> new_value | nil, err
        methods.add_method(
            "decr",
            |lua, this, (key, minus, init): (String, i64, Option<i64>)| {
                match this.decr(&key, minus, init) {
                    Ok(v) => Ok((LuaValue::Integer(v), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:bump(key, inc?) -> new_value | nil, err（允许累加已过期项，不新建）
        methods.add_method("bump", |lua, this, (key, inc): (String, Option<i64>)| {
            match this.bump(&key, inc.unwrap_or(1)) {
                Ok(v) => Ok((LuaValue::Integer(v), LuaValue::Nil)),
                Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
            }
        });
        // d:set_auto(key, value, expiry?, flags?) —— 无类型存储，flags 被接受但忽略
        methods.add_method(
            "set_auto",
            |lua, this, (key, value, expiry, _flags): (String, LuaValue, Option<f64>, Option<i64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                match this.set(&key, bytes, expiry) {
                    Ok(()) => Ok((LuaValue::Boolean(true), LuaValue::Nil)),
                    Err(e) => Ok((LuaValue::Nil, LuaValue::String(lua.create_string(e)?))),
                }
            },
        );
        // d:get_keys(max?) -> keys, more（默认 1024，与 OpenResty 一致）
        methods.add_method("get_keys", |lua, this, max: Option<usize>| {
            let (keys, more) = this.get_keys(max.unwrap_or(1024));
            let t = lua.create_table()?;
            for (i, k) in keys.iter().enumerate() {
                t.raw_set(i + 1, lua.create_string(k)?)?;
            }
            Ok((t, LuaValue::Boolean(more)))
        });
        // d:expire(key, exptime) -> true | false（key 不存在/已过期）
        methods.add_method("expire", |_, this, (key, ex): (String, f64)| {
            Ok(this.expire(&key, ex))
        });
    }
}

fn lua_value_to_bytes(v: &LuaValue) -> Option<Vec<u8>> {
    match v {
        LuaValue::String(s) => Some(s.as_bytes().to_vec()),
        LuaValue::Integer(n) => Some(n.to_string().into_bytes()),
        LuaValue::Number(n) => Some(n.to_string().into_bytes()),
        LuaValue::Boolean(true) => Some(b"true".to_vec()),
        LuaValue::Boolean(false) => Some(b"false".to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 定死 `*_file` 的契约：请求路径只查内存、绝不 stat；发现变更的是后台自检。
    /// 断言都按本测试的文件过滤，避免与并行用例共用全局 FILE_CACHE 时互相干扰。
    #[test]
    fn lua_file_cache_only_refreshed_by_self_check() {
        let dir = std::env::temp_dir().join(format!("onrouter-luawatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("watch.lua");
        let touched = |changed: &[PathBuf]| changed.iter().any(|x| x == &p);

        std::fs::write(&p, "v1").unwrap();
        assert_eq!(&*load_file_cached(&p).unwrap(), "v1");

        // 留足时间让 mtime 一定变化（NTFS 时间戳粒度约 10ms）
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&p, "v2").unwrap();
        assert_eq!(
            &*load_file_cached(&p).unwrap(),
            "v1",
            "请求路径不应 stat，编辑后仍返回缓存内容"
        );

        assert!(touched(&recheck_cached_files()), "自检应发现该文件变更");
        assert_eq!(&*load_file_cached(&p).unwrap(), "v2");
        assert!(!touched(&recheck_cached_files()), "内容未再变化时自检应为空操作");

        std::fs::remove_file(&p).unwrap();
        assert!(touched(&recheck_cached_files()), "文件消失应清掉缓存条目");
        assert!(load_file_cached(&p).is_err(), "缓存已失效且文件不存在 -> 读取报错");
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        // 跨分块填充（>55 字节，触发第二轮补零到 %64==56）
        assert_eq!(
            md5_hex(b"hello world this is a longer message to cross one 64-byte block boundary"),
            hex_lower(&md5_bytes(
                b"hello world this is a longer message to cross one 64-byte block boundary"
            ))
        );
        assert_eq!(md5_bin(b"abc").len(), 16);
        assert_eq!(md5_bin(b"abc"), md5_bytes(b"abc").to_vec());
    }

    #[test]
    fn sha1_bin_matches_known_digest() {
        assert_eq!(
            hex_lower(&sha1_bin(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(sha1_bin(b"abc").len(), 20);
    }

    #[test]
    fn sha256_bin_matches_known_digest() {
        // FIPS 180-4 测试向量
        assert_eq!(
            hex_lower(&sha256_bin(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_lower(&sha256_bin(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_bin(b"abc").len(), 32);
    }

    #[test]
    fn hmac_sha1_matches_rfc2202() {
        assert_eq!(
            hex_lower(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn crc32_matches_std_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn time_formatting_and_parsing() {
        assert_eq!(http_time(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(cookie_time(0), "Thu, 01-Jan-1970 00:00:00 GMT");
        // 往返：格式化后再解析回同一 unix 秒
        let ts = 1_700_000_000i64;
        let s = http_time(ts);
        assert_eq!(parse_http_time(&s), Some(ts));
        assert_eq!(parse_http_time("not-a-date"), None);
    }

    // 轻量级线程结果投递核心：__thread_body 把 func 的 pcall 结果打包进 __thread_sink[tid]。
    // 成功 → (true, ret...)；抛错 → (false, err)。调度器据此喂回等待方。
    #[test]
    fn thread_body_packs_success_and_error() {
        let lua = mlua::Lua::new();
        lua.globals().set("__thread_sink", lua.create_table().unwrap()).unwrap();
        let define: mlua::Function = lua
            .load(
                r#"return function()
                    _G.__thread_body = function(func, args, tid)
                        return function()
                            local r = table.pack(pcall(func, table.unpack(args, 1, args.n)))
                            local sink = _G.__thread_sink
                            if r[1] then
                                sink[tid] = table.pack(true, table.unpack(r, 2, r.n))
                            else
                                sink[tid] = table.pack(false, r[2])
                            end
                        end
                    end
                end"#,
            )
            .eval()
            .unwrap();
        define.call::<()>(()).unwrap();

        // 成功：返回两个值
        let body: mlua::Function = lua
            .globals()
            .get::<mlua::Function>("__thread_body")
            .unwrap()
            .call((
                lua.load("return 'a', 7").into_function().unwrap(),
                {
                    let args = lua.create_table().unwrap();
                    args.raw_set("n", 0).unwrap();
                    args
                },
                1i64,
            ))
            .unwrap();
        body.call::<()>(()).unwrap();
        let sink: mlua::Table = lua.globals().get("__thread_sink").unwrap();
        let packed: mlua::Table = sink.raw_get(1i64).unwrap();
        let n: i64 = packed.raw_get("n").unwrap();
        assert_eq!(n, 3); // true, 'a', 7
        assert_eq!(packed.raw_get::<bool>(1).unwrap(), true);
        assert_eq!(packed.raw_get::<String>(2).unwrap(), "a");
        assert_eq!(packed.raw_get::<i64>(3).unwrap(), 7);

        // 失败：func 抛错
        let body2: mlua::Function = lua
            .globals()
            .get::<mlua::Function>("__thread_body")
            .unwrap()
            .call((
                lua.load("error('boom')").into_function().unwrap(),
                {
                    let args = lua.create_table().unwrap();
                    args.raw_set("n", 0).unwrap();
                    args
                },
                2i64,
            ))
            .unwrap();
        body2.call::<()>(()).unwrap();
        let packed2: mlua::Table = sink.raw_get(2i64).unwrap();
        assert_eq!(packed2.raw_get::<bool>(1).unwrap(), false);
        assert!(packed2.raw_get::<String>(2).unwrap().contains("boom"));
    }

    // ngx.thread 模块面：工厂返回含 spawn/wait/yield/kill 的表。
    #[test]
    fn thread_module_exposes_api() {
        let lua = mlua::Lua::new();
        // 桩：真实 _onrouter_thread_* 在请求期由 install_api 注入，此处仅需工厂闭包可成功构造表。
        let factory: mlua::Function = lua
            .load(
                r#"return function()
                    local t = {}
                    function t.spawn(func, ...) return { _thread_tid = 0 } end
                    function t.wait(...) return nil end
                    function t.yield() return nil end
                    function t.kill(thread) return true end
                    return t
                end"#,
            )
            .eval()
            .unwrap();
        let t: mlua::Table = factory.call(()).unwrap();
        for name in ["spawn", "wait", "yield", "kill"] {
            assert!(matches!(
                t.raw_get::<mlua::Value>(name).unwrap(),
                mlua::Value::Function(_)
            ), "missing ngx.thread.{name}");
        }
    }

    // 低并发快速路径：空闲 VM 在连接任务里内联跑首段；脚本让出后由 Adopt 移交给调度器，
    // 与走 Job 队列的请求混跑也必须全部完成且不丢唤醒（sleep + ngx.thread 都覆盖）。
    #[tokio::test]
    async fn fast_path_inline_and_adopt_mix_with_scheduler_jobs() {
        let cfg = Config::parse("lua_shared_dict t 1m;").unwrap();
        let engine = Arc::new(LuaEngine::new(&cfg, &std::path::PathBuf::from(".")).unwrap());
        let src = LuaSource::Inline(Arc::from(
            r#"
            ngx.shared.t:incr("entered", 1, 0)
            ngx.sleep(0.005)
            local th = ngx.thread.spawn(function()
                ngx.sleep(0.002)
                return "child-ok"
            end)
            local ok, v = ngx.thread.wait(th)
            assert(ok and v == "child-ok", "thread.wait 结果异常")
            ngx.shared.t:incr("done", 1, 0)
        "#,
        ));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..48 {
            let engine = Arc::clone(&engine);
            let src = src.clone();
            set.spawn(async move {
                engine
                    .run_phase(
                        "content_by_lua",
                        &src,
                        Arc::new(Mutex::new(RequestCtx::default())),
                    )
                    .await
            });
        }
        while let Some(r) = set.join_next().await {
            r.expect("任务 panic").expect("Lua 阶段失败");
        }
        let probe: Arc<str> = Arc::from(
            r#"
            assert(tonumber(ngx.shared.t:get("entered")) == 48, "entered=" .. tostring(ngx.shared.t:get("entered")))
            assert(tonumber(ngx.shared.t:get("done")) == 48, "done=" .. tostring(ngx.shared.t:get("done")))
        "#,
        );
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(probe),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("并发快速路径结果校验失败");
    }

    // lua_package_path 占位符：`;;` 保留默认路径，不写则整体替换；`$prefix` 两写法等价。
    #[test]
    fn package_path_expansion_matches_openresty_semantics() {
        assert_eq!(
            expand_package_path("$prefix/lua/?.lua;;", "D1;D2", "/srv/app"),
            "/srv/app/lua/?.lua;D1;D2"
        );
        assert_eq!(
            expand_package_path("${prefix}/lua/?.lua", "D1;D2", "/srv/app"),
            "/srv/app/lua/?.lua"
        );
        assert_eq!(expand_package_path(";;", "D1", "P"), "D1");
    }

    // init_worker_by_lua_block：每个 VM 各执行一次；lua_package_path 让 require 从磁盘加载；
    // init_by_lua 先于 init_worker；脚本里的 ngx.timer.at 真正触发。
    #[tokio::test]
    async fn init_worker_runs_per_vm_with_lua_package_path() {
        let dir = std::env::temp_dir().join(format!("onrouter-initw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("helper.lua"), "return { value = 'loaded-from-disk' }").unwrap();
        let dir_slash = dir.to_string_lossy().replace('\\', "/");
        let conf = format!(
            r#"
            lua_shared_dict t 1m;
            lua_package_path "{dir_slash}/?.lua;;";
            init_by_lua_block {{ ngx.shared.t:set("init", "by-init") }}
            init_worker_by_lua_block {{
                assert(ngx.shared.t:get("init") == "by-init", "init_by_lua 必须先执行")
                local h = require("helper")
                ngx.shared.t:set("worker_mod", h.value)
                ngx.shared.t:incr("worker_runs", 1, 0)
                local ok = ngx.timer.at(0, function(premature)
                    ngx.shared.t:set("timer", premature and "premature" or "fired")
                end)
                assert(ok, "ngx.timer.at 注册失败")
            }}
        "#
        );
        let cfg = Config::parse(&conf).unwrap();
        let engine = LuaEngine::new(&cfg, &dir).unwrap();
        engine.run_init_workers().await.unwrap();
        // 定时器在调度器里异步触发，给它一个窗口
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let n = engine.vm_count();
        let probe: Arc<str> = Arc::from(format!(
            r#"
            local t = ngx.shared.t
            assert(t:get("init") == "by-init", "init_by_lua 未执行")
            assert(t:get("worker_mod") == "loaded-from-disk", "require(helper) 未从 lua_package_path 加载")
            assert(tonumber(t:get("worker_runs")) == {n}, "init_worker 应每个 VM 执行一次，实际 " .. tostring(t:get("worker_runs")))
            assert(package.path:find("{dir_slash}/?.lua", 1, true), "package.path 未包含配置目录")
            assert(t:get("timer") == "fired", "init_worker 里注册的 timer 未触发")
        "#
        ));
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(probe),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("init_worker 结果校验失败");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // 定时器回调由调度器按协程执行：回调里的 ngx.sleep / ngx.thread.spawn+wait /
    // 嵌套 ngx.timer.at 都可用；ngx.timer.every 回调 return false 后不再续期。
    #[tokio::test]
    async fn timer_callback_runs_as_coroutine_and_every_stops_on_false() {
        let cfg = Config::parse("lua_shared_dict t 1m;").unwrap();
        let engine = LuaEngine::new(&cfg, &std::path::PathBuf::from(".")).unwrap();
        let src: Arc<str> = Arc::from(
            r#"
            assert(ngx.timer.at(0.01, function(premature, tag)
                assert(premature == false, "premature 应为 false")
                assert(ngx.get_phase() == "timer", "phase=" .. tostring(ngx.get_phase()))
                ngx.sleep(0.02)
                ngx.shared.t:set("slept", tag)
                local th = ngx.thread.spawn(function()
                    ngx.sleep(0.01)
                    return "child-timer"
                end)
                local ok, v = ngx.thread.wait(th)
                assert(ok and v == "child-timer", "定时器内 thread.wait 结果异常")
                ngx.shared.t:set("thread", v)
                assert(ngx.timer.at(0.01, function()
                    ngx.sleep(0.01)
                    ngx.shared.t:set("nested", "ok")
                end))
            end, "arg0"))

            assert(ngx.timer.every(0.02, function()
                ngx.sleep(0.005)
                local n = (tonumber(ngx.shared.t:get("every_n")) or 0) + 1
                ngx.shared.t:set("every_n", n)
                if n >= 2 then return false end
            end))
        "#,
        );
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(src),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("注册定时器失败");

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let probe: Arc<str> = Arc::from(
            r#"
            local t = ngx.shared.t
            assert(t:get("slept") == "arg0", "回调里的 ngx.sleep 未生效")
            assert(t:get("thread") == "child-timer", "回调里的 ngx.thread 未生效")
            assert(t:get("nested") == "ok", "回调里注册的嵌套 timer 未触发")
            assert(tonumber(t:get("every_n")) == 2, "every 次数异常: " .. tostring(t:get("every_n")))
            t:set("every_seen", tostring(t:get("every_n")))
        "#,
        );
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(probe),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("定时器协程结果校验失败");

        // return false 之后不得再续期
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(Arc::from(
                    r#"assert(ngx.shared.t:get("every_seen") == tostring(ngx.shared.t:get("every_n")), "every 未在 return false 后停止")"#,
                )),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("every 停止校验失败");
    }

    // init_worker_by_lua_file：从配置文件解析出的 _file 形式同样每 VM 执行一次；
    // 文件缺失时启动阶段即失败（而不是静默跳过）。
    #[tokio::test]
    async fn init_worker_file_runs_and_missing_file_fails_startup() {
        let dir = std::env::temp_dir().join(format!("onrouter-initwf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("worker.lua");
        std::fs::write(&script, r#"ngx.shared.t:set("from_file", "yes")"#).unwrap();
        let script_slash = script.to_string_lossy().replace('\\', "/");
        let conf = format!(
            "lua_shared_dict t 1m;\ninit_worker_by_lua_file \"{script_slash}\";\n"
        );
        let cfg = Config::parse(&conf).unwrap();
        let engine = LuaEngine::new(&cfg, &dir).unwrap();
        engine.run_init_workers().await.unwrap();
        engine
            .run_phase(
                "content_by_lua",
                &LuaSource::Inline(Arc::from(
                    r#"assert(ngx.shared.t:get("from_file") == "yes", "init_worker_by_lua_file 未执行")"#,
                )),
                Arc::new(Mutex::new(RequestCtx::default())),
            )
            .await
            .expect("_file 形式 init_worker 未生效");

        let bad = Config::parse("init_worker_by_lua_file \"definitely-not-exist.lua\";").unwrap();
        assert!(LuaEngine::new(&bad, &dir).is_err(), "缺失的 init_worker 文件应在启动时报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // balancer_by_lua 端到端（引擎级）：Lua 里 ngx.balancer 的选择结果应落到 RequestCtx，
    // 供 proxy::forward 绕开 upstream 负载均衡直连该节点。
    #[tokio::test]
    async fn balancer_lua_phase_stashes_peer_on_ctx() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let ctx = Arc::new(Mutex::new(RequestCtx::default()));
        let code: Arc<str> = r#"
            local b = ngx.balancer
            assert(b.set_current_peer('10.1.2.3', 8080))
            assert(b.set_timeouts(1000, 2000, 3000))
            assert(b.set_more_failures({failures = 2, return_code = 502}))
            assert(b.recreate_request(false))
            local host, port = b.get_current_peer()
            assert(host == '10.1.2.3' and port == 8080)
            -- 空 host 应返回 nil,err
            local ok, err = b.set_current_peer('', 80)
            assert(ok == nil and err)
        "#
        .into();
        let src = LuaSource::Inline(code);
        engine
            .run_phase("balancer_by_lua", &src, Arc::clone(&ctx))
            .await
            .expect("balancer phase 执行失败");
        let c = ctx.lock().unwrap();
        assert_eq!(c.balancer_peer, Some(("10.1.2.3".to_string(), 8080)));
        assert_eq!(c.balancer_timeouts, Some((1000, 2000, 3000)));
        assert_eq!(c.balancer_more_failures, Some((2, 502, false)));
        assert!(!c.balancer_recreate_request);
    }

    // ngx.var —— 读取当前请求的 nginx 变量；未定义返回 nil；$uri 可写。
    #[tokio::test]
    async fn ngx_var_reads_and_writes() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let mut ctx = RequestCtx::default();
        ctx.method = "POST".into();
        ctx.path = "/a b".into();
        ctx.uri = "/a%20b?x=1".into();
        ctx.query = "x=1".into();
        ctx.host = Some("h.example".into());
        ctx.remote_addr = "1.2.3.4".into();
        ctx.remote_port = 5555;
        ctx.scheme = "https".into();
        ctx.req_headers.push(("user-agent".into(), "curl/8".into()));
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            ngx.say('uri=' .. ngx.var.uri)
            ngx.say('request_uri=' .. ngx.var.request_uri)
            ngx.say('method=' .. ngx.var.request_method)
            ngx.say('args=' .. ngx.var.args)
            ngx.say('is_args=' .. ngx.var.is_args)
            ngx.say('host=' .. ngx.var.host)
            ngx.say('ua=' .. ngx.var.http_user_agent)
            ngx.say('remote=' .. ngx.var.remote_addr .. ':' .. ngx.var.remote_port)
            ngx.say('scheme=' .. ngx.var.scheme)
            ngx.say('missing=' .. tostring(ngx.var.no_such_var))
            -- 写 $uri 后应立刻可读回
            ngx.var.uri = '/new'
            ngx.say('rewritten=' .. ngx.var.uri)
            -- 写 $status
            ngx.var.status = 201
            ngx.say('status=' .. tostring(ngx.var.status))
        "#
        .into();
        engine
            .run_phase("content_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("ngx.var content phase 执行失败");
        let c = shared.lock().unwrap();
        let body = String::from_utf8_lossy(c.body.as_deref().unwrap_or(&[])).to_string();
        assert!(body.contains("uri=/a b"), "{body}");
        assert!(body.contains("request_uri=/a%20b?x=1"), "{body}");
        assert!(body.contains("method=POST"), "{body}");
        assert!(body.contains("args=x=1"), "{body}");
        assert!(body.contains("is_args=?"), "{body}");
        assert!(body.contains("host=h.example"), "{body}");
        assert!(body.contains("ua=curl/8"), "{body}");
        assert!(body.contains("remote=1.2.3.4:5555"), "{body}");
        assert!(body.contains("scheme=https"), "{body}");
        assert!(body.contains("missing=nil"), "{body}");
        assert!(body.contains("rewritten=/new"), "{body}");
        assert!(body.contains("status=201"), "{body}");
        // 写回 ctx：$uri 改写落 rewritten_path，$status 落 status
        assert_eq!(c.rewritten_path.as_deref(), Some("/new"));
        assert_eq!(c.status, 201);
    }

    // ngx.re.gmatch/sub/gsub + 回调替换 + opt 预编译句柄
    #[tokio::test]
    async fn ngx_re_gmatch_sub_gsub_opt() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let shared = Arc::new(Mutex::new(RequestCtx::default()));
        let code: Arc<str> = r#"
            local it = ngx.re.gmatch("a1b2c3", "([a-z])([0-9])")
            local acc = ""
            while true do
                local m = it()
                if not m then break end
                acc = acc .. m[1] .. m[2] .. ","
            end
            ngx.say('gmatch=' .. acc)
            local s1, n1 = ngx.re.sub("hello world foo", "[a-z]+", "X")
            ngx.say('sub=' .. s1 .. '/' .. n1)
            local s2, n2 = ngx.re.gsub("a-b-c", "-", "_")
            ngx.say('gsub=' .. s2 .. '/' .. n2)
            local s3, n3 = ngx.re.gsub("x1y2", "[0-9]", function(m) return "[" .. m[0] .. "]" end)
            ngx.say('cb=' .. s3 .. '/' .. n3)
            local h = ngx.re.opt("[a-z]+")
            local s4, n4 = ngx.re.gsub("abc1def", h, "*")
            ngx.say('opt=' .. s4 .. '/' .. n4)
        "#
        .into();
        engine
            .run_phase("content_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("ngx.re content phase 执行失败");
        let body = String::from_utf8_lossy(shared.lock().unwrap().body.as_deref().unwrap_or(&[])).to_string();
        assert!(body.contains("gmatch=a1,b2,c3,"), "{body}");
        assert!(body.contains("sub=X world foo/1"), "{body}");
        assert!(body.contains("gsub=a_b_c/2"), "{body}");
        assert!(body.contains("cb=x[1]y[2]/2"), "{body}");
        assert!(body.contains("opt=*1*/2"), "{body}");
    }

    // ngx.req.set_header / set_raw_header / clear_header 改写入站头（转发时带给后端）
    #[tokio::test]
    async fn ngx_req_set_and_clear_header() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let mut ctx = RequestCtx::default();
        ctx.req_headers.push(("user-agent".into(), "curl/8".into()));
        ctx.req_headers.push(("x-del".into(), "bye".into()));
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            ngx.req.set_header("X-Foo", "bar")
            ngx.req.set_header("x-multi", {"a", "b"})
            ngx.req.set_header("X-Del", nil)
            ngx.req.clear_header("user-agent")
            ngx.req.set_raw_header("X-Raw-Name", "kept")
        "#
        .into();
        engine
            .run_phase("content_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("ngx.req header phase 执行失败");
        let c = shared.lock().unwrap();
        let find = |k: &str| c.req_headers.iter().filter(|(n, _)| n == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();
        assert_eq!(find("x-foo"), vec!["bar"], "set_header 归一化小写名");
        assert_eq!(find("x-multi"), vec!["a", "b"], "表值按序写多值");
        assert!(find("x-del").is_empty(), "value=nil 应删除该头");
        assert!(find("user-agent").is_empty(), "clear_header 删除");
        assert_eq!(find("X-Raw-Name"), vec!["kept"], "set_raw_header 保留原始名");
    }

    // ngx.req.socket：对已缓冲请求体的顺序读取（receive/receiveuntil/close）
    #[tokio::test]
    async fn ngx_req_socket_reads_buffered_body() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let mut ctx = RequestCtx::default();
        ctx.req_body = Bytes::from_static(b"part1\r\n\r\npart2-tail");
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            local sock = ngx.req.socket()
            local a = sock:receive(5)
            local b = sock:receiveuntil("\r\n\r\n")()
            local c = sock:receive(4)
            local rest = sock:receive()
            local d, err = sock:receive(1)
            ngx.say('a=' .. a)
            ngx.say('b=' .. b)
            ngx.say('c=' .. c)
            ngx.say('rest=' .. rest)
            ngx.say('d=' .. tostring(d) .. ' err=' .. tostring(err))
        "#
        .into();
        engine
            .run_phase("content_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("req.socket phase 执行失败");
        let body =
            String::from_utf8_lossy(shared.lock().unwrap().body.as_deref().unwrap_or(&[])).to_string();
        assert!(body.contains("a=part1"), "{body}");
        assert!(body.contains("b=\r\n\r\n"), "{body}");
        assert!(body.contains("c=part"), "{body}");
        assert!(body.contains("rest=2-tail"), "{body}");
        assert!(body.contains("d=nil err=closed"), "{body}");
    }

    // ngx.flush：立即发 Head + 已缓冲数据；脚本结束后剩余输出由服务层补发
    #[tokio::test]
    async fn ngx_flush_emits_head_and_buffered_body() {
        use crate::engine::{StreamEvent, StreamSink};
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = RequestCtx::default();
        ctx.status = 201;
        ctx.stream = Some(StreamSink::new(
            tx,
            vec![("x-extra".to_string(), "1".to_string())],
        ));
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            ngx.header["X-Test"] = "yes"
            ngx.say("first")
            assert(ngx.flush() == 1)
            ngx.say("second")
        "#
        .into();
        engine
            .run_phase("content_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("flush phase 执行失败");

        match rx.try_recv().expect("脚本结束前应已收到 Head") {
            StreamEvent::Head { status, headers } => {
                assert_eq!(status, 201);
                assert!(headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("x-test") && v == "yes"));
                assert!(headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("x-extra") && v == "1"));
                assert!(headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type")));
            }
            other => panic!("首帧应为 Head: {other:?}"),
        }
        match rx.try_recv().expect("flush 应已发出数据帧") {
            StreamEvent::Data(b) => assert_eq!(&b[..], b"first\n"),
            other => panic!("第二帧应为 Data: {other:?}"),
        }

        // VM 的 registry 还会短暂持有最后一次 resume 的 ctx 句柄，故按服务层的
        // take_ctx 语义克隆一份来收尾（End 帧保证响应体一定终止）。
        let mut ctx = shared.lock().unwrap().clone();
        assert_eq!(ctx.body.as_deref(), Some(&b"second\n"[..]));
        ctx.drain_and_end_stream().await;
        match rx.recv().await.expect("补发帧") {
            StreamEvent::Data(b) => assert_eq!(&b[..], b"second\n"),
            other => panic!("补发帧应为 Data: {other:?}"),
        }
        assert!(matches!(rx.recv().await, Some(StreamEvent::End)));
    }

    // ngx.ssl：握手阶段读 SNI、解析 PEM、设置证书/私钥；ngx.exit(ngx.ERROR) 标记中止
    #[tokio::test]
    async fn ngx_ssl_sets_cert_and_reads_sni() {
        use crate::engine::SslState;
        let pair = rcgen::generate_simple_self_signed(vec!["a.test".into()]).unwrap();
        let cert_pem = pair.cert.pem();
        let key_pem = pair.key_pair.serialize_pem();
        let cfg = Config::parse("").unwrap();
        let engine = LuaEngine::new(&cfg, &std::path::PathBuf::from(".")).unwrap();

        let mut ctx = RequestCtx::default();
        ctx.ssl = Some(SslState {
            server_name: Some("A.Test".into()),
            ..SslState::default()
        });
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = format!(
            r#"
            local ssl = require "ngx.ssl"
            local sni = ssl.server_name()
            local cert = assert(ssl.parse_pem_cert([==[{cert_pem}]==]))
            local key = assert(ssl.parse_pem_priv_key([==[{key_pem}]==]))
            local ok, err = ssl.set_cert_and_key(cert, key)
            ngx.say(sni .. '|' .. tostring(ok) .. '|' .. tostring(err))
            "#
        )
        .into();
        engine
            .run_phase("ssl_certificate", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("ssl phase 执行失败");
        {
            let ctx = shared.lock().unwrap();
            let ssl = ctx.ssl.as_ref().expect("ssl 状态应保留");
            assert_eq!(ssl.server_name.as_deref(), Some("A.Test"));
            assert_eq!(ssl.cert_chain.as_ref().map(|c| c.len()), Some(1));
            assert!(ssl.priv_key.is_some());
            assert!(!ssl.aborted);
            let body = String::from_utf8_lossy(ctx.body.as_deref().unwrap_or(&[]));
            assert!(body.contains("A.Test|true|nil"), "{body}");
        }

        // ngx.exit(ngx.ERROR)：不报 Lua 错误，但把握手标记为中止
        let mut ctx = RequestCtx::default();
        ctx.ssl = Some(SslState::default());
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = "ngx.exit(ngx.ERROR)".into();
        engine
            .run_phase("ssl_certificate", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("ngx.exit(ngx.ERROR) 不应抛 Lua 错误");
        assert!(shared.lock().unwrap().ssl.as_ref().unwrap().aborted);
    }

    // body_filter_by_lua 原语：ngx.arg[1] 读改响应体块、ngx.arg[2] 读 eof —— 代理路径过滤器复用之
    #[tokio::test]
    async fn body_filter_lua_transforms_chunk() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let mut ctx = RequestCtx::default();
        ctx.filter_chunk = Some(b"hello world".to_vec());
        ctx.filter_eof = true;
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            local c = ngx.arg[1]
            local eof = ngx.arg[2]
            if eof then
                ngx.arg[1] = c:upper() .. '!'
            end
        "#
        .into();
        engine
            .run_phase("body_filter_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("body_filter phase 执行失败");
        let c = shared.lock().unwrap();
        assert_eq!(c.filter_chunk.as_deref(), Some(b"HELLO WORLD!".as_slice()));
    }

    // header_filter_by_lua 原语：ngx.status 写回 ctx.status、ngx.header.* 写回 resp_headers（含 nil 删除）
    #[tokio::test]
    async fn header_filter_lua_sets_status_and_headers() {
        let cfg = Config::parse("").unwrap();
        let base = std::path::PathBuf::from(".");
        let engine = LuaEngine::new(&cfg, &base).unwrap();
        let mut ctx = RequestCtx::default();
        ctx.status = 200;
        ctx.resp_headers.push(("content-type".into(), "text/plain".into()));
        let shared = Arc::new(Mutex::new(ctx));
        let code: Arc<str> = r#"
            ngx.status = 203
            ngx.header["X-Filtered"] = "yes"
            ngx.header["content-type"] = nil
        "#
        .into();
        engine
            .run_phase("header_filter_by_lua", &LuaSource::Inline(code), Arc::clone(&shared))
            .await
            .expect("header_filter phase 执行失败");
        let c = shared.lock().unwrap();
        assert_eq!(c.status, 203);
        assert!(c.resp_headers.iter().any(|(k, v)| k == "x-filtered" && v == "yes"), "{:?}", c.resp_headers);
        assert!(!c.resp_headers.iter().any(|(k, _)| k == "content-type"), "{:?}", c.resp_headers);
    }
}
