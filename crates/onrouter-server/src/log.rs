//! error_log：分级错误日志（对标 nginx `error_log <path> [level];`）。
//!
//! 设计要点：
//! - 请求热路径只做一次有界通道投递，不阻塞在文件 IO 上；队列满时丢弃并计数
//!   （原先所有诊断直接 `eprintln!` 到 stderr，stderr 是管道且写满时会卡住 worker）。
//! - 单写线程负责时间戳、按级别落盘、按大小滚动、Warn 以上回显 stderr。
//! - `reopen()` 支持外部 logrotate。

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use crossbeam_channel::{bounded, Sender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};

use onrouter_config::Config;

use crate::resolve_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info,
    Notice,
    Warn,
    Error,
    Crit,
    /// 关闭日志
    Off,
}

impl Level {
    fn parse(s: &str) -> Option<Level> {
        Some(match s.to_ascii_lowercase().as_str() {
            "debug" => Level::Debug,
            "info" => Level::Info,
            "notice" => Level::Notice,
            "warn" | "warning" => Level::Warn,
            "error" | "err" => Level::Error,
            "crit" | "alert" | "emerg" => Level::Crit,
            "off" | "none" => Level::Off,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Notice => "notice",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::Crit => "crit",
            Level::Off => "off",
        }
    }
}

enum Cmd {
    Line(Level, String),
    /// logrotate / SIGUSR1：外部移走文件后重新打开（windows 无信号，按大小滚动即可）
    #[cfg(unix)]
    Reopen,
    Shutdown,
}

const QUEUE_CAPACITY: usize = 65536;
const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;

pub struct ErrorLog {
    tx: Option<Sender<Cmd>>,
    /// 后台写线程：shutdown() 发信号后 join，保证退出前队列落盘
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    level: Level,
    dropped: Arc<AtomicU64>,
}

static LOG: OnceLock<Arc<ErrorLog>> = OnceLock::new();

/// 落盘文件句柄 + 滚动策略（access_log 也复用同一套滚动逻辑）
pub struct FileWriter {
    path: PathBuf,
    file: BufWriter<std::fs::File>,
    bytes: u64,
    max_size: u64,
    keep: usize,
}

impl FileWriter {
    pub fn open(path: &PathBuf, max_size: u64, keep: usize) -> Option<Self> {
        let file = open_append(path)?;
        let bytes = file.get_ref().metadata().map(|m| m.len()).unwrap_or(0);
        Some(FileWriter { path: path.clone(), file, bytes, max_size, keep })
    }

    pub fn line(&mut self, line: &str) {
        if writeln!(self.file, "{line}").is_err() {
            return;
        }
        self.bytes += line.len() as u64 + 1;
        if self.bytes < self.max_size {
            return;
        }
        // 滚动：先拿到占位句柄，把当前句柄彻底关掉，才能改名（Windows 上打开中的文件无法 rename）
        let Some(null) = empty_writer() else {
            let _ = writeln!(std::io::stderr(), "[onrouter] 无法滚动日志，继续写入原文件");
            return;
        };
        let _ = self.file.flush();
        drop(std::mem::replace(&mut self.file, null));
        shift_files(&self.path, self.keep);
        if let Some(mut fresh) = FileWriter::open(&self.path, self.max_size, self.keep) {
            std::mem::swap(self, &mut fresh);
        }
    }

    pub fn flush(&mut self) {
        let _ = self.file.flush();
    }

    /// logrotate 之后换回真实路径（unix 信号触发；windows 靠按大小滚动）
    #[cfg(unix)]
    pub fn reopen(&mut self) {
        let Some(null) = empty_writer() else { return };
        drop(std::mem::replace(&mut self.file, null));
        if let Some(mut fresh) = FileWriter::open(&self.path, self.max_size, self.keep) {
            std::mem::swap(self, &mut fresh);
        }
    }
}

/// 占位用的 /dev/null 式 writer（滚动瞬间句柄必须先移走才能改名）
fn empty_writer() -> Option<BufWriter<std::fs::File>> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("onrouter-log-placeholder.tmp"))
        .ok()
        .map(BufWriter::new)
}

fn open_append(p: &Path) -> Option<BufWriter<std::fs::File>> {
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match OpenOptions::new().create(true).append(true).open(p) {
        Ok(f) => Some(BufWriter::new(f)),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "[onrouter] error_log 打开失败 {}: {e}", p.display());
            None
        }
    }
}

/// file.log -> file.log.1 -> ... 保留 keep 份
fn shift_files(path: &Path, keep: usize) {
    if keep == 0 {
        return;
    }
    let numbered = |i: usize| format!("{}.{}", path.display(), i);
    let _ = std::fs::remove_file(numbered(keep));
    for i in (1..keep).rev() {
        let _ = std::fs::rename(numbered(i), numbered(i + 1));
    }
    let _ = std::fs::rename(path, numbered(1));
}

pub fn init(config: &Config, base_dir: &PathBuf) -> Arc<ErrorLog> {
    let d = config.find("error_log");
    let arg0 = d.and_then(|x| x.arg(0));
    let path = arg0
        .filter(|p| *p != "stderr" && *p != "off")
        .map(|p| resolve_path(p, base_dir));
    let level = d
        .and_then(|x| x.arg(1))
        .and_then(Level::parse)
        .unwrap_or(Level::Info);
    let max_size = config
        .find("error_log_max_size")
        .and_then(|x| x.arg(0))
        .and_then(crate::router::parse_size)
        .unwrap_or(DEFAULT_MAX_SIZE);
    let keep = config
        .find("error_log_keep")
        .and_then(|x| x.arg(0))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5);

    let dropped = Arc::new(AtomicU64::new(0));
    let (tx, rx) = bounded::<Cmd>(QUEUE_CAPACITY);
    let mut worker = None;
    if let Some(file_path) = path.clone() {
        let mut writer = FileWriter::open(&file_path, max_size, keep);
        let d2 = Arc::clone(&dropped);
        worker = std::thread::Builder::new()
            .name("onrouter-error-log".into())
            .spawn(move || {
                let mut reported = 0u64;
                loop {
                    let first = match rx.recv() {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let mut batch: Vec<Cmd> = vec![first];
                    while let Ok(more) = rx.try_recv() {
                        batch.push(more);
                    }
                    let d = d2.load(Ordering::Relaxed);
                    if d > reported {
                        reported = d;
                        let _ = writeln!(
                            std::io::stderr(),
                            "[onrouter] error_log 队列已满，累计丢弃 {d} 条"
                        );
                    }
                    let mut shutdown = false;
                    for cmd in batch {
                        match cmd {
                            Cmd::Shutdown => shutdown = true,
                            #[cfg(unix)]
                            Cmd::Reopen => {
                                if let Some(w) = writer.as_mut() {
                                    w.reopen();
                                }
                            }
                            Cmd::Line(lvl, msg) => write_line(writer.as_mut(), lvl, &msg),
                        }
                        if shutdown {
                            break;
                        }
                    }
                    if shutdown {
                        // 停机前把队列里剩下的行写完：优雅退出不该丢诊断信息
                        while let Ok(Cmd::Line(lvl, msg)) = rx.try_recv() {
                            write_line(writer.as_mut(), lvl, &msg);
                        }
                        if let Some(w) = writer.as_mut() {
                            w.flush();
                        }
                        return;
                    }
                    if let Some(w) = writer.as_mut() {
                        w.flush();
                    }
                }
            })
            .ok();
    }

    let log = Arc::new(ErrorLog {
        // 没有写线程时不留通道：否则队列会静默堆满
        tx: (path.is_some() && worker.is_some()).then_some(tx),
        worker: Mutex::new(worker),
        level,
        dropped,
    });
    let _ = LOG.set(Arc::clone(&log));
    log
}

fn write_line(writer: Option<&mut FileWriter>, lvl: Level, msg: &str) {
    let line = format!(
        "{} [{}] {}",
        chrono::Local::now().format("%Y/%m/%d %H:%M:%S"),
        lvl.as_str(),
        msg
    );
    if lvl >= Level::Warn {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
    if let Some(w) = writer {
        w.line(&line);
    }
}

/// logrotate 风格：外部移走文件后通知重新打开（SIGUSR1/SIGHUP，仅 unix）
#[cfg(unix)]
pub fn reopen() {
    if let Some(log) = LOG.get() {
        if let Some(tx) = &log.tx {
            let _ = tx.try_send(Cmd::Reopen);
        }
    }
}

/// 停机：冲刷并等待后台写线程结束
pub fn shutdown() {
    let Some(log) = LOG.get() else { return };
    if let Some(tx) = &log.tx {
        let _ = tx.try_send(Cmd::Shutdown);
    }
    if let Some(handle) = log.worker.lock().unwrap().take() {
        let _ = handle.join();
    }
}

impl ErrorLog {
    /// 该级别是否会落盘（Off 或低于配置阈值都不落）
    fn enabled(&self, level: Level) -> bool {
        self.level != Level::Off && level >= self.level
    }

    pub fn log(&self, level: Level, msg: impl Into<String>) {
        if !self.enabled(level) {
            return;
        }
        let msg = msg.into();
        match &self.tx {
            Some(tx) => {
                if let Err(TrySendError::Full(Cmd::Line(l, m))) = tx.try_send(Cmd::Line(level, msg))
                {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    if l >= Level::Warn {
                        let _ = writeln!(std::io::stderr(), "[onrouter/{}] {m}", l.as_str());
                    }
                }
            }
            None => {
                if level >= Level::Warn {
                    let _ = writeln!(std::io::stderr(), "[onrouter/{}] {msg}", level.as_str());
                }
            }
        }
    }
}

pub fn with_log(level: Level, msg: String) {
    match LOG.get() {
        Some(log) => log.log(level, msg),
        None => {
            if level >= Level::Warn {
                let _ = writeln!(std::io::stderr(), "[onrouter/{}] {msg}", level.as_str());
            }
        }
    }
}

/// 这条级别现在会落盘吗？给宏做**前置**判定用。
///
/// 为什么要在调用点判：`format!(...)` 是实参，展开后无条件执行 —— 生产阈值 warn 下，
/// 每个请求一路 `log_debug!` 都要付一次字符串构造与堆分配，消息最后又被扔掉。
/// 请求路径上的诊断因此变成了真实性价成本（front_proxy 的 egress 档首次压测就被这项吃走）。
pub fn enabled(level: Level) -> bool {
    match LOG.get() {
        Some(log) => log.enabled(level),
        // 未初始化时 with_log 只把 warn 以上打到 stderr，判定必须与它一致
        None => level >= Level::Warn,
    }
}

// 四档宏都先判级别再 format —— 见 [`enabled`]。
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Error) {
            $crate::log::with_log($crate::log::Level::Error, format!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Warn) {
            $crate::log::with_log($crate::log::Level::Warn, format!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Info) {
            $crate::log::with_log($crate::log::Level::Info, format!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Debug) {
            $crate::log::with_log($crate::log::Level::Debug, format!($($arg)*))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(Level::Error > Level::Warn);
        assert!(Level::Crit > Level::Error);
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("bogus"), None);
    }

    #[test]
    fn filters_below_level() {
        let log = ErrorLog {
            tx: None,
            worker: Mutex::new(None),
            level: Level::Error,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        assert!(!log.enabled(Level::Warn), "warn 低于 error 阈值应被过滤");
        assert!(log.enabled(Level::Error));
        assert!(log.enabled(Level::Crit));
        log.log(Level::Info, "should be dropped silently".to_string());

        let off = ErrorLog {
            tx: None,
            worker: Mutex::new(None),
            level: Level::Off,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        assert!(!off.enabled(Level::Crit), "off 级别不产生任何日志");
    }

    /// 消息构造次数计数：用来证明"级别没过时 format! 根本没执行"。
    static FORMATTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    struct Counted;
    impl std::fmt::Display for Counted {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            FORMATTED.fetch_add(1, Ordering::SeqCst);
            write!(f, "counted")
        }
    }

    #[test]
    fn below_threshold_message_is_never_built() {
        // 单测进程不调用 log::init ⇒ LOG 未落地 ⇒ 只有 warn 以上才会走 stderr
        assert!(!enabled(Level::Debug) && !enabled(Level::Info));
        assert!(enabled(Level::Warn) && enabled(Level::Error));
        log_debug!("{Counted}");
        log_info!("{Counted}");
        assert_eq!(
            FORMATTED.load(Ordering::SeqCst),
            0,
            "低于阈值的诊断日志不该构造消息 —— 请求路径上每一次 format! 都是实打实的堆分配"
        );
    }
}
