//! access_log：Nginx combined 格式 + `$request_time` + `$upstream_addr`/`$upstream_status`/
//! `$upstream_header_time`。
//!
//! ```text
//! $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//!  "$http_referer" "$http_user_agent" $request_time "$upstream_addr" $upstream_status $upstream_header_time
//! ```
//!
//! 工程要点（对照 nginx 的差异都写在注释里）：
//! - `$body_bytes_sent` 必须是**真正写回客户端的响应体字节数**，不是耗时也不是请求体大小。
//!   因此每个响应体都被 `LoggedBody` 包一层计数器，日志在响应体生命周期结束时才落，
//!   流式代理（大文件、慢客户端）也能记到准确值。
//! - 写入走专用后台线程 + **有界**通道：队列满时丢弃并计数，绝不阻塞 worker
//!   （无界通道在日志盘慢时会把内存吃穿）。
//! - 文件按大小滚动，`reopen()` 兼容外部 logrotate。

use crossbeam_channel::{bounded, Sender, TrySendError};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use onrouter_config::Config;

use crate::log::FileWriter;
use crate::router::parse_size;

const QUEUE_CAPACITY: usize = 32768;
const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;
/// 单字段最长记录多少字节（超长 UA/URI 不应撑爆日志）
const FIELD_MAX: usize = 2000;

enum Cmd {
    Line(String),
    /// SIGUSR1/SIGHUP 后重新打开日志文件（仅 unix）
    #[cfg(unix)]
    Reopen,
    Shutdown,
}

pub struct AccessLog {
    tx: Option<Sender<Cmd>>,
    /// 后台写线程：shutdown() 发信号后 join，保证退出前日志落盘
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    dropped: Arc<AtomicU64>,
    /// 交互终端下同时回显，便于开发（stdout 是管道时不打印，避免写满阻塞 worker）
    echo: bool,
}

static INSTANCE: OnceLock<Arc<AccessLog>> = OnceLock::new();

/// 本请求最终命中的上游（换节点重试后为最后一次尝试）。
struct UpstreamLog {
    addr: String,
    status: u16,
    header_time: f64,
}

/// 一条请求的记账信息；响应体结束时通过 `emit` 落日志
pub struct LogRecord {
    pub started: Instant,
    /// realip 在请求入口之后才改写客户端地址，日志要记录改写后的 `$remote_addr`，
    /// 故此处用可写单元格而非只读 String（请求内先被读取用于初始化 ctx）。
    remote: std::sync::RwLock<String>,
    /// 处理结束前回填一次；之后 emit 只读，用 OnceLock 免掉每请求的锁开销。
    upstream: OnceLock<UpstreamLog>,
    pub method: String,
    pub uri: String,
    pub proto: String,
    pub referer: String,
    pub user_agent: String,
    status: AtomicU16,
    bytes_sent: AtomicU64,
    /// 响应体已交给写出层（此时只能等它 drop 时再落日志）
    wrapped: AtomicBool,
    emitted: AtomicBool,
}

impl LogRecord {
    fn new(
        remote: String,
        method: String,
        uri: String,
        proto: String,
        referer: String,
        user_agent: String,
    ) -> Arc<Self> {
        Arc::new(LogRecord {
            started: Instant::now(),
            remote: std::sync::RwLock::new(remote),
            upstream: OnceLock::new(),
            method,
            uri,
            proto,
            referer,
            user_agent,
            status: AtomicU16::new(0),
            bytes_sent: AtomicU64::new(0),
            wrapped: AtomicBool::new(false),
            emitted: AtomicBool::new(false),
        })
    }

    /// 当前记录的客户端地址（realip 改写后为真实客户端 IP）
    pub fn remote(&self) -> String {
        self.remote
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// realip 生效后同步访问日志的 `$remote_addr`。
    pub fn set_remote(&self, remote: String) {
        *self.remote.write().unwrap_or_else(|p| p.into_inner()) = remote;
    }

    /// 记录本请求最终命中的上游；无上游（静态文件/缓存命中）时保持未设置。
    pub fn set_upstream(&self, addr: String, status: u16, header_time: f64) {
        if addr.is_empty() {
            return;
        }
        let _ = self.upstream.set(UpstreamLog {
            addr,
            status,
            header_time,
        });
    }

    pub fn set_status(&self, status: u16) {
        self.status.store(status, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, n: usize) {
        self.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// 标记"响应体已交给 hyper"，此后由 body 的 Drop 负责落日志
    pub fn mark_wrapped(&self) -> bool {
        self.wrapped.swap(true, Ordering::AcqRel)
    }

    /// 落一条日志；重复调用只生效一次
    pub fn emit(&self, log: &AccessLog) {
        if self.emitted.swap(true, Ordering::AcqRel) {
            return;
        }
        log.write(self.line());
    }

    /// 组装一行 combined + request_time + upstream 三元组。
    fn line(&self) -> String {
        // 状态码为 0 说明响应还没生成就断了：nginx 用 499 记这类客户端提前关闭
        let status = match self.status.load(Ordering::Relaxed) {
            0 => 499,
            s => s,
        };
        let secs = self.started.elapsed().as_secs_f64();
        let time = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        let (up_addr, up_status, up_time) = match self.upstream.get() {
            Some(u) if u.status != 0 => (
                format!("\"{}\"", field(&u.addr)),
                u.status.to_string(),
                format!("{:.3}", u.header_time),
            ),
            Some(u) => (
                format!("\"{}\"", field(&u.addr)),
                "-".to_string(),
                "-".to_string(),
            ),
            None => ("-".to_string(), "-".to_string(), "-".to_string()),
        };
        format!(
            "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\" {:.3} {} {} {}",
            field(&self.remote()),
            time,
            field(&self.method),
            field(&self.uri),
            self.proto,
            status,
            self.bytes_sent(),
            field(&self.referer),
            field(&self.user_agent),
            secs,
            up_addr,
            up_status,
            up_time
        )
    }
}

/// 日志字段转义：引号与控制字符会破坏可解析的 combined 格式（也是日志注入的入口）
fn field(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(FIELD_MAX));
    for c in s.chars().take(FIELD_MAX) {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

impl AccessLog {
    pub fn new(config: &Config, base_dir: &PathBuf) -> Arc<Self> {
        let decl = config.find("access_log");
        let path_arg = decl.and_then(|d| d.arg(0));
        let disabled = matches!(path_arg, Some("off") | None);
        let path = path_arg
            .filter(|p| *p != "off")
            .map(|p| crate::resolve_path(p, base_dir));

        let max_size = config
            .find("access_log_max_size")
            .and_then(|d| d.arg(0))
            .and_then(parse_size)
            .unwrap_or(DEFAULT_MAX_SIZE);
        let keep = config
            .find("access_log_keep")
            .and_then(|d| d.arg(0))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);

        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = bounded::<Cmd>(QUEUE_CAPACITY);

        let file = if disabled {
            None
        } else {
            match path.clone() {
                Some(p) => match FileWriter::open(&p, max_size, keep) {
                    Some(w) => Some(w),
                    None => {
                        // 打不开就退回回显：宁可刷屏也不要静默丢掉全部访问日志
                        let _ = writeln!(
                            std::io::stderr(),
                            "[onrouter] access_log 无法写入 {}，改为回显 stdout",
                            p.display()
                        );
                        None
                    }
                },
                None => None,
            }
        };

        // 没有文件可写时才回显；stdout 是管道/重定向时不打印（管道写满会阻塞全部 worker）
        let echo = file.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout());

        let mut worker = None;
        if let Some(f) = file {
            let d2 = Arc::clone(&dropped);
            worker = std::thread::Builder::new()
                .name("onrouter-access-log".into())
                .spawn(move || {
                    let mut writer = f;
                    let mut reported = 0u64;
                    loop {
                        let first = match rx.recv() {
                            Ok(c) => c,
                            Err(_) => break,
                        };
                        let mut batch = vec![first];
                        while let Ok(more) = rx.try_recv() {
                            batch.push(more);
                        }
                        let d = d2.load(Ordering::Relaxed);
                        if d > reported {
                            reported = d;
                            let _ = writeln!(
                                std::io::stderr(),
                                "[onrouter] access_log 队列已满，累计丢弃 {d} 条"
                            );
                        }
                        let mut shutdown = false;
                        for cmd in batch {
                            match cmd {
                                Cmd::Shutdown => shutdown = true,
                                #[cfg(unix)]
                                Cmd::Reopen => writer.reopen(),
                                Cmd::Line(line) => writer.line(&line),
                            }
                            if shutdown {
                                break;
                            }
                        }
                        if shutdown {
                            while let Ok(Cmd::Line(line)) = rx.try_recv() {
                                writer.line(&line);
                            }
                            writer.flush();
                            return;
                        }
                        writer.flush();
                    }
                    writer.flush();
                })
                .ok();
        }

        // 只有真的起了写线程才保留通道；否则文件打不开，投递只会堆到队列满
        let log = Arc::new(AccessLog {
            tx: (!disabled && worker.is_some()).then_some(tx),
            worker: Mutex::new(worker),
            dropped,
            echo,
        });
        // reopen() 通过单例找到写入通道（同一个 Arc，同一套计数）
        let _ = INSTANCE.set(Arc::clone(&log));
        log
    }

    fn write(&self, line: String) {
        if self.echo {
            println!("[access] {line}");
        }
        if let Some(tx) = &self.tx {
            if let Err(TrySendError::Full(_)) = tx.try_send(Cmd::Line(line)) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                crate::metrics::get().on_access_log_dropped();
            }
        }
    }

    /// 为一条新请求建立记账（在连接层刚解析出请求行时就创建，异常路径也能留痕）
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        remote: String,
        method: String,
        uri: String,
        proto: String,
        referer: String,
        user_agent: String,
    ) -> Arc<LogRecord> {
        LogRecord::new(remote, method, uri, proto, referer, user_agent)
    }

    /// 处理结束时若响应体从未被写出（连接被取消等），补一条日志
    pub fn finish(&self, rec: &LogRecord) {
        if !rec.wrapped.load(Ordering::Acquire) {
            rec.emit(self);
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// logrotate 之后通知重新打开访问日志（SIGUSR1/SIGHUP，仅 unix）
#[cfg(unix)]
pub fn reopen() {
    if let Some(log) = INSTANCE.get() {
        if let Some(tx) = &log.tx {
            let _ = tx.try_send(Cmd::Reopen);
        }
    }
}

/// 停机：冲刷并等待后台写线程结束
pub fn shutdown() {
    let Some(log) = INSTANCE.get() else { return };
    if let Some(tx) = &log.tx {
        let _ = tx.try_send(Cmd::Shutdown);
    }
    if let Some(handle) = log.worker.lock().unwrap().take() {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_and_control_chars() {
        assert_eq!(field("a\"b"), "a\\\"b");
        assert_eq!(field("x\ny"), "x\\ny");
        assert_eq!(field("bad\x01char"), "bad?char");
        let long = field(&"z".repeat(FIELD_MAX + 500));
        assert_eq!(long.len(), FIELD_MAX);
    }

    #[test]
    fn emit_is_idempotent_and_marks_missing_status_as_499() {
        let log = AccessLog {
            tx: None,
            worker: Mutex::new(None),
            dropped: Arc::new(AtomicU64::new(0)),
            echo: false,
        };
        let rec = log.record(
            "1.2.3.4".into(),
            "GET".into(),
            "/x".into(),
            "HTTP/1.1".into(),
            "-".into(),
            "curl".into(),
        );
        rec.add_bytes(1234);
        assert_eq!(rec.bytes_sent(), 1234);
        rec.set_upstream("127.0.0.1:9000".into(), 200, 0.012);
        let line = rec.line();
        assert!(line.contains("\"127.0.0.1:9000\" 200 0.012"), "{line}");
        rec.emit(&log);
        rec.emit(&log); // 第二次必须被吞掉
        assert!(!rec.mark_wrapped(), "首次 mark 应返回 false");
    }

    #[test]
    fn line_marks_missing_upstream_with_dashes() {
        let log = AccessLog {
            tx: None,
            worker: Mutex::new(None),
            dropped: Arc::new(AtomicU64::new(0)),
            echo: false,
        };
        let rec = log.record(
            "1.2.3.4".into(),
            "GET".into(),
            "/static.css".into(),
            "HTTP/1.1".into(),
            "-".into(),
            "curl".into(),
        );
        rec.set_status(200);
        let line = rec.line();
        assert!(
            line.ends_with(" - - -"),
            "无上游时末尾应为三个占位符: {line}"
        );
    }
}
